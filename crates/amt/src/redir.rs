//! The shared front of AMT's redirection protocol on port 16994: start a
//! session of one kind ("SOL " or "IDER") and authenticate it.
//!
//! The framing follows Intel's redirection protocol as MeshCommander/MeshCentral
//! implement it: `StartRedirectionSession`, then authentication with HTTP-style
//! digest carried in binary frames (auth type 4, with cnonce and qop; `amtterm`
//! only knows the plain-password type 1, which AMT 12 refuses). Integers in the
//! frames are little-endian.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};

use crate::digest::{DigestInput, cnonce};
use crate::error::{Error, Result};
use crate::wsman::Endpoint;

pub const DEFAULT_PORT: u16 = 16994;
const AUTH_URI: &str = "/RedirectionService";

/// A redirection session kind: the start frame's flag byte and 4-byte name.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Kind {
    flags: u8,
    name: [u8; 4],
}

pub(crate) const SOL: Kind = Kind {
    flags: 0,
    name: *b"SOL ",
};
pub(crate) const IDER: Kind = Kind {
    flags: 0,
    name: *b"IDER",
};
/// KVM over the redirection port; the start frame carries flag 0x01.
pub(crate) const KVMR: Kind = Kind {
    flags: 1,
    name: *b"KVMR",
};

mod msg {
    pub const START_SESSION: u8 = 0x10;
    pub const START_SESSION_REPLY: u8 = 0x11;
    pub const AUTHENTICATE: u8 = 0x13;
    pub const AUTHENTICATE_REPLY: u8 = 0x14;
}

mod auth {
    pub const QUERY: u8 = 0;
    pub const PASSWORD: u8 = 1;
    pub const DIGEST: u8 = 4;
}

/// The sending half of a redirection connection, with its sequence counter.
pub(crate) struct Writer {
    pub half: OwnedWriteHalf,
    seq: u32,
}

impl Writer {
    pub fn next_seq(&mut self) -> u32 {
        let s = self.seq;
        self.seq = self.seq.wrapping_add(1);
        s
    }

    pub async fn send(&mut self, frame: &[u8]) -> Result<()> {
        self.half.write_all(frame).await?;
        Ok(())
    }
}

/// Connects, starts a `kind` session and authenticates it. On return the
/// session-specific protocol (SOL settings, IDER open) begins.
pub(crate) async fn open(
    ep: &Endpoint,
    port: u16,
    kind: Kind,
    timeout: Duration,
) -> Result<(OwnedReadHalf, Writer)> {
    let stream = tokio::time::timeout(timeout, TcpStream::connect((ep.host.as_str(), port)))
        .await
        .map_err(|_| Error::Timeout("connecting to the redirection port"))??;
    stream.set_nodelay(true)?;
    let (mut rd, wr) = stream.into_split();
    let mut w = Writer { half: wr, seq: 0 };
    tokio::time::timeout(timeout, start_and_authenticate(&mut rd, &mut w, ep, kind))
        .await
        .map_err(|_| Error::Timeout("redirection handshake"))??;
    Ok((rd, w))
}

async fn start_and_authenticate(
    rd: &mut OwnedReadHalf,
    w: &mut Writer,
    ep: &Endpoint,
    kind: Kind,
) -> Result<()> {
    // 1. StartRedirectionSession(kind).
    let mut start = vec![msg::START_SESSION, kind.flags, 0, 0];
    start.extend_from_slice(&kind.name);
    w.send(&start).await?;
    let head = read_exact(rd, 13).await?;
    expect_type(&head, msg::START_SESSION_REPLY)?;
    if head[1] != 0 {
        return Err(Error::Protocol(format!(
            "StartRedirectionSession refused (status {}); is the redirection listener open and the feature enabled?",
            head[1]
        )));
    }
    let oem = head[12] as usize;
    if oem > 0 {
        read_exact(rd, oem).await?;
    }

    // 2. Ask which authentication types AMT accepts.
    w.send(&[msg::AUTHENTICATE, 0, 0, 0, auth::QUERY, 0, 0, 0, 0])
        .await?;
    let (_, _, supported) = read_auth_reply(rd).await?;

    if supported.contains(&auth::DIGEST) {
        // 3a. Digest: an empty request draws the challenge (realm, nonce, qop).
        let user = ep.user.as_bytes();
        let uri = AUTH_URI.as_bytes();
        let mut f = vec![msg::AUTHENTICATE, 0, 0, 0, auth::DIGEST];
        f.extend_from_slice(&((user.len() + uri.len() + 8) as u32).to_le_bytes());
        push_str(&mut f, user);
        f.extend_from_slice(&[0, 0]); // realm, nonce
        push_str(&mut f, uri);
        f.extend_from_slice(&[0, 0, 0, 0]); // cnonce, nc, response, qop
        w.send(&f).await?;
        let (status, kind, data) = read_auth_reply(rd).await?;
        if status != 1 || kind != auth::DIGEST {
            return Err(Error::RedirectionAuth(status));
        }
        let (realm, nonce, qop) = parse_challenge(&data)?;

        let cn = cnonce();
        let nc = "00000002";
        let resp = DigestInput {
            user: &ep.user,
            realm: &realm,
            password: &ep.password,
            method: "POST",
            uri: AUTH_URI,
            nonce: &nonce,
            nc,
            cnonce: &cn,
            qop: &qop,
        }
        .response();
        let fields: [&[u8]; 8] = [
            user,
            realm.as_bytes(),
            nonce.as_bytes(),
            uri,
            cn.as_bytes(),
            nc.as_bytes(),
            resp.as_bytes(),
            qop.as_bytes(),
        ];
        let len: usize = fields.iter().map(|f| f.len() + 1).sum();
        let mut f = vec![msg::AUTHENTICATE, 0, 0, 0, auth::DIGEST];
        f.extend_from_slice(&(len as u32).to_le_bytes());
        for field in fields {
            push_str(&mut f, field);
        }
        w.send(&f).await?;
    } else if supported.contains(&auth::PASSWORD) {
        // 3b. Only for old firmware that offers nothing better, and only when
        // asked for: an offer without digest may be a downgrade on the path.
        if !ep.allow_plaintext_auth {
            return Err(Error::PlaintextAuthRefused);
        }
        tracing::warn!(
            host = %ep.host,
            "redirection: device offers only plaintext authentication; sending the password in clear"
        );
        let (user, pass) = (ep.user.as_bytes(), ep.password.as_bytes());
        let mut f = vec![msg::AUTHENTICATE, 0, 0, 0, auth::PASSWORD];
        f.extend_from_slice(&((user.len() + pass.len() + 2) as u32).to_le_bytes());
        push_str(&mut f, user);
        push_str(&mut f, pass);
        w.send(&f).await?;
    } else {
        return Err(Error::Protocol(format!(
            "no supported authentication type offered: {supported:?}"
        )));
    }
    let (status, _, _) = read_auth_reply(rd).await?;
    if status != 0 {
        return Err(Error::RedirectionAuth(status));
    }
    Ok(())
}

/// Reads an AuthenticateSessionReply: (status, auth type, auth data).
async fn read_auth_reply(rd: &mut OwnedReadHalf) -> Result<(u8, u8, Vec<u8>)> {
    let h = read_exact(rd, 9).await?;
    expect_type(&h, msg::AUTHENTICATE_REPLY)?;
    let len = u32::from_le_bytes([h[5], h[6], h[7], h[8]]) as usize;
    if len > 4096 {
        return Err(Error::Protocol(format!("auth reply of {len} bytes")));
    }
    Ok((h[1], h[4], read_exact(rd, len).await?))
}

/// Realm, nonce and qop: three length-prefixed strings.
fn parse_challenge(data: &[u8]) -> Result<(String, String, String)> {
    let mut at = 0;
    let mut next = || -> Result<String> {
        let len = *data
            .get(at)
            .ok_or_else(|| Error::Protocol("short digest challenge".into()))?
            as usize;
        let s = data
            .get(at + 1..at + 1 + len)
            .ok_or_else(|| Error::Protocol("short digest challenge".into()))?;
        at += 1 + len;
        Ok(String::from_utf8_lossy(s).into_owned())
    };
    let realm = next()?;
    let nonce = next()?;
    let qop = next()?;
    Ok((realm, nonce, qop))
}

fn push_str(f: &mut Vec<u8>, s: &[u8]) {
    f.push(s.len() as u8);
    f.extend_from_slice(s);
}

pub(crate) fn expect_type(frame: &[u8], want: u8) -> Result<()> {
    if frame.first() == Some(&want) {
        Ok(())
    } else {
        Err(Error::Protocol(format!(
            "expected message 0x{want:02X}, got 0x{:02X}",
            frame.first().copied().unwrap_or(0)
        )))
    }
}

pub(crate) async fn read_exact(rd: &mut OwnedReadHalf, n: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; n];
    rd.read_exact(&mut buf).await?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_challenge() {
        let mut d = vec![5];
        d.extend_from_slice(b"realm");
        d.push(3);
        d.extend_from_slice(b"abc");
        d.push(4);
        d.extend_from_slice(b"auth");
        let (r, n, q) = parse_challenge(&d).unwrap();
        assert_eq!(
            (r.as_str(), n.as_str(), q.as_str()),
            ("realm", "abc", "auth")
        );
        assert!(parse_challenge(&d[..6]).is_err());
    }
}
