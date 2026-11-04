//! Serial-over-LAN through the AMT redirection protocol on port 16994.
//!
//! The framing follows Intel's redirection protocol as MeshCommander implements
//! it (`amt-redir`): a `StartRedirectionSession` naming "SOL ", authentication
//! with HTTP-style digest carried in binary frames (auth type 4, with cnonce and
//! qop; `amtterm` only knows the plain-password type 1, which AMT 12 refuses),
//! then SOL settings and a stream of data/keep-alive frames. All integers are
//! little-endian.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::{Mutex, Notify};
use tokio::task::JoinHandle;

use crate::digest::{DigestInput, cnonce};
use crate::error::{Error, Result};
use crate::wsman::Endpoint;

pub const DEFAULT_PORT: u16 = 16994;
const AUTH_URI: &str = "/RedirectionService";
/// Bytes kept for `read`. Older output is dropped first.
const BUFFER_LIMIT: usize = 256 * 1024;

mod msg {
    pub const START_SESSION: u8 = 0x10;
    pub const START_SESSION_REPLY: u8 = 0x11;
    pub const AUTHENTICATE: u8 = 0x13;
    pub const AUTHENTICATE_REPLY: u8 = 0x14;
    pub const SOL_SETTINGS: u8 = 0x20;
    pub const SOL_SETTINGS_REPLY: u8 = 0x21;
    pub const SOL_CONTROL: u8 = 0x27;
    pub const SOL_DATA_TO_HOST: u8 = 0x28;
    pub const SOL_CONTROL_FROM_HOST: u8 = 0x29;
    pub const SOL_DATA_FROM_HOST: u8 = 0x2A;
    pub const KEEP_ALIVE: u8 = 0x2B;
}

mod auth {
    pub const QUERY: u8 = 0;
    pub const PASSWORD: u8 = 1;
    pub const DIGEST: u8 = 4;
}

/// Output received from the host, shared with the reader task.
#[derive(Default)]
struct Inbox {
    data: Vec<u8>,
    closed: Option<String>,
}

/// An open SOL session. Dropping it closes the connection.
pub struct SolSession {
    writer: Arc<Mutex<Writer>>,
    inbox: Arc<Mutex<Inbox>>,
    arrived: Arc<Notify>,
    reader: JoinHandle<()>,
    keepalive: JoinHandle<()>,
}

struct Writer {
    half: OwnedWriteHalf,
    seq: u32,
}

impl Writer {
    fn next_seq(&mut self) -> u32 {
        let s = self.seq;
        self.seq = self.seq.wrapping_add(1);
        s
    }

    async fn send(&mut self, frame: &[u8]) -> Result<()> {
        self.half.write_all(frame).await?;
        Ok(())
    }
}

impl SolSession {
    /// Connects, authenticates and starts SOL. On a device in client control
    /// mode, user consent must have been granted first or AMT ends the session.
    pub async fn open(ep: &Endpoint, port: u16, timeout: Duration) -> Result<Self> {
        let stream = tokio::time::timeout(timeout, TcpStream::connect((ep.host.as_str(), port)))
            .await
            .map_err(|_| Error::Timeout("connecting to the redirection port"))??;
        stream.set_nodelay(true)?;
        let (mut rd, wr) = stream.into_split();
        let mut w = Writer { half: wr, seq: 0 };

        tokio::time::timeout(timeout, handshake(&mut rd, &mut w, ep))
            .await
            .map_err(|_| Error::Timeout("SOL handshake"))??;

        let writer = Arc::new(Mutex::new(w));
        let inbox = Arc::new(Mutex::new(Inbox::default()));
        let arrived = Arc::new(Notify::new());
        let reader = tokio::spawn(read_loop(rd, inbox.clone(), arrived.clone()));
        let keepalive = tokio::spawn(keepalive_loop(writer.clone()));
        tracing::info!(host = %ep.host, "SOL session open");
        Ok(Self {
            writer,
            inbox,
            arrived,
            reader,
            keepalive,
        })
    }

    /// Sends bytes to the host's serial port (what you would type).
    pub async fn send(&self, data: &[u8]) -> Result<()> {
        if let Some(reason) = self.inbox.lock().await.closed.clone() {
            return Err(Error::Protocol(format!("session closed: {reason}")));
        }
        let mut w = self.writer.lock().await;
        // One frame carries at most u16::MAX bytes; AMT's buffer is far smaller.
        for chunk in data.chunks(1000) {
            let seq = w.next_seq();
            let mut f = vec![msg::SOL_DATA_TO_HOST, 0, 0, 0];
            f.extend_from_slice(&seq.to_le_bytes());
            f.extend_from_slice(&(chunk.len() as u16).to_le_bytes());
            f.extend_from_slice(chunk);
            w.send(&f).await?;
        }
        Ok(())
    }

    /// Takes everything received so far, waiting up to `wait` for the first
    /// byte if nothing is buffered yet, then `settle` for output to stop.
    pub async fn read(&self, wait: Duration, settle: Duration) -> Result<Vec<u8>> {
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            let notified = self.arrived.notified();
            {
                let inbox = self.inbox.lock().await;
                if !inbox.data.is_empty() || inbox.closed.is_some() {
                    break;
                }
            }
            if tokio::time::timeout_at(deadline, notified).await.is_err() {
                break;
            }
        }
        // Let a burst finish (a screen redraw arrives as many frames).
        loop {
            let notified = self.arrived.notified();
            if tokio::time::timeout(settle, notified).await.is_err() {
                break;
            }
        }
        let mut inbox = self.inbox.lock().await;
        let out = std::mem::take(&mut inbox.data);
        if out.is_empty()
            && let Some(reason) = &inbox.closed
        {
            return Err(Error::Protocol(format!("session closed: {reason}")));
        }
        Ok(out)
    }

    pub async fn is_closed(&self) -> Option<String> {
        self.inbox.lock().await.closed.clone()
    }

    pub async fn close(self) {
        self.keepalive.abort();
        let _ = self.writer.lock().await.half.shutdown().await;
        self.reader.abort();
    }
}

impl Drop for SolSession {
    fn drop(&mut self) {
        self.keepalive.abort();
        self.reader.abort();
    }
}

async fn handshake(rd: &mut OwnedReadHalf, w: &mut Writer, ep: &Endpoint) -> Result<()> {
    // 1. StartRedirectionSession("SOL ").
    w.send(&[msg::START_SESSION, 0, 0, 0, b'S', b'O', b'L', b' '])
        .await?;
    let head = read_exact(rd, 13).await?;
    expect_type(&head, msg::START_SESSION_REPLY)?;
    if head[1] != 0 {
        return Err(Error::Protocol(format!(
            "StartRedirectionSession refused (status {})",
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
        // 3b. Only for old firmware that offers nothing better.
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

    // 4. SOL settings: max TX buffer, TX timeout, TX overflow timeout, RX
    //    timeout, RX flush timeout, heartbeat (ms), then 4 reserved bytes.
    let seq = w.next_seq();
    let mut f = vec![msg::SOL_SETTINGS, 0, 0, 0];
    f.extend_from_slice(&seq.to_le_bytes());
    for v in [10_000u16, 100, 0, 10_000, 100, 0] {
        f.extend_from_slice(&v.to_le_bytes());
    }
    f.extend_from_slice(&[0, 0, 0, 0]);
    w.send(&f).await?;
    let reply = read_exact(rd, 23).await?;
    expect_type(&reply, msg::SOL_SETTINGS_REPLY)?;
    if reply[1] != 0 {
        return Err(Error::Protocol(format!(
            "SOL settings refused (status {}); is user consent granted?",
            reply[1]
        )));
    }

    // 5. Control: assert RTS/DTR (0x1B) so the host sees a connected terminal.
    let seq = w.next_seq();
    let mut f = vec![msg::SOL_CONTROL, 0, 0, 0];
    f.extend_from_slice(&seq.to_le_bytes());
    f.extend_from_slice(&[0, 0, 0x1B, 0, 0, 0]);
    w.send(&f).await?;
    Ok(())
}

async fn read_loop(mut rd: OwnedReadHalf, inbox: Arc<Mutex<Inbox>>, arrived: Arc<Notify>) {
    let reason = loop {
        match read_frame(&mut rd).await {
            Ok(Frame::Data(bytes)) => {
                let mut ib = inbox.lock().await;
                ib.data.extend_from_slice(&bytes);
                if ib.data.len() > BUFFER_LIMIT {
                    let excess = ib.data.len() - BUFFER_LIMIT;
                    ib.data.drain(..excess);
                }
                drop(ib);
                arrived.notify_waiters();
            }
            Ok(Frame::Ignored) => {}
            Err(e) => break e.to_string(),
        }
    };
    tracing::info!(%reason, "SOL session ended");
    inbox.lock().await.closed = Some(reason);
    arrived.notify_waiters();
}

async fn keepalive_loop(writer: Arc<Mutex<Writer>>) {
    let mut tick = tokio::time::interval(Duration::from_secs(2));
    tick.tick().await;
    loop {
        tick.tick().await;
        let mut w = writer.lock().await;
        let seq = w.next_seq();
        let mut f = vec![msg::KEEP_ALIVE, 0, 0, 0];
        f.extend_from_slice(&seq.to_le_bytes());
        if w.send(&f).await.is_err() {
            break;
        }
    }
}

enum Frame {
    Data(Vec<u8>),
    Ignored,
}

async fn read_frame(rd: &mut OwnedReadHalf) -> Result<Frame> {
    let mut t = [0u8; 1];
    let n = rd.read(&mut t).await?;
    if n == 0 {
        return Err(Error::Protocol("connection closed by AMT".into()));
    }
    match t[0] {
        msg::SOL_DATA_FROM_HOST => {
            let h = read_exact(rd, 9).await?;
            let len = u16::from_le_bytes([h[7], h[8]]) as usize;
            Ok(Frame::Data(read_exact(rd, len).await?))
        }
        msg::KEEP_ALIVE => {
            read_exact(rd, 7).await?;
            Ok(Frame::Ignored)
        }
        msg::SOL_CONTROL_FROM_HOST => {
            read_exact(rd, 9).await?;
            Ok(Frame::Ignored)
        }
        other => Err(Error::Protocol(format!(
            "unexpected message type 0x{other:02X}"
        ))),
    }
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

fn expect_type(frame: &[u8], want: u8) -> Result<()> {
    if frame.first() == Some(&want) {
        Ok(())
    } else {
        Err(Error::Protocol(format!(
            "expected message 0x{want:02X}, got 0x{:02X}",
            frame.first().copied().unwrap_or(0)
        )))
    }
}

async fn read_exact(rd: &mut OwnedReadHalf, n: usize) -> Result<Vec<u8>> {
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
