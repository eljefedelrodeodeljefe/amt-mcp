//! A scripted fake of the AMT redirection service, for tests.
//!
//! It speaks the server side of the SOL handshake (session start, digest
//! authentication, SOL settings), verifies the client's digest against its own
//! password, echoes host-bound data back with a prefix, and records what it saw.

use std::net::SocketAddr;
use std::sync::Arc;

use md5::{Digest, Md5};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

pub const REALM: &str = "Digest:FAKEREALM0000000000000000000000";
pub const NONCE: &str = "fakenonce==";

/// What the fake observed, for assertions.
#[derive(Debug, Default, Clone)]
pub struct Seen {
    pub authenticated: bool,
    pub settings_received: bool,
    pub typed: Vec<u8>,
    pub keepalives: usize,
}

pub struct FakeRedirection {
    pub addr: SocketAddr,
    pub seen: Arc<Mutex<Seen>>,
}

impl FakeRedirection {
    /// Starts a fake accepting one session, authenticating `user`/`password`.
    /// It greets with `banner` once SOL is up.
    pub async fn start(user: &str, password: &str, banner: &str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let seen = Arc::new(Mutex::new(Seen::default()));
        let (user, password, banner) = (user.to_string(), password.to_string(), banner.to_string());
        let s = seen.clone();
        tokio::spawn(async move {
            if let Ok((sock, _)) = listener.accept().await {
                let _ = serve(sock, &user, &password, &banner, s).await;
            }
        });
        Self { addr, seen }
    }
}

fn md5_hex(s: &str) -> String {
    hex::encode(Md5::digest(s.as_bytes()))
}

async fn read_n(sock: &mut TcpStream, n: usize) -> std::io::Result<Vec<u8>> {
    let mut b = vec![0; n];
    sock.read_exact(&mut b).await?;
    Ok(b)
}

fn strings(data: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut at = 0;
    while at < data.len() {
        let len = data[at] as usize;
        let end = (at + 1 + len).min(data.len());
        out.push(String::from_utf8_lossy(&data[at + 1..end]).into_owned());
        at = end;
    }
    out
}

fn auth_reply(status: u8, kind: u8, data: &[u8]) -> Vec<u8> {
    let mut f = vec![0x14, status, 0, 0, kind];
    f.extend_from_slice(&(data.len() as u32).to_le_bytes());
    f.extend_from_slice(data);
    f
}

fn data_frame(bytes: &[u8]) -> Vec<u8> {
    let mut f = vec![0x2A, 0, 0, 0, 0, 0, 0, 0];
    f.extend_from_slice(&(bytes.len() as u16).to_le_bytes());
    f.extend_from_slice(bytes);
    f
}

async fn serve(
    mut sock: TcpStream,
    user: &str,
    password: &str,
    banner: &str,
    seen: Arc<Mutex<Seen>>,
) -> std::io::Result<()> {
    // StartRedirectionSession("SOL ") -> reply with no OEM data.
    let start = read_n(&mut sock, 8).await?;
    assert_eq!(&start[..], &[0x10, 0, 0, 0, b'S', b'O', b'L', b' ']);
    sock.write_all(&[0x11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
        .await?;

    loop {
        let h = read_n(&mut sock, 9).await?;
        assert_eq!(h[0], 0x13, "expected AuthenticateSession");
        let len = u32::from_le_bytes([h[5], h[6], h[7], h[8]]) as usize;
        let data = read_n(&mut sock, len).await?;
        match h[4] {
            0 => sock.write_all(&auth_reply(0, 0, &[1, 4])).await?,
            4 => {
                let f = strings(&data);
                // [user, realm, nonce, uri, cnonce, nc, response, qop]
                if f.get(1).is_none_or(|r| r.is_empty()) {
                    let mut c = vec![REALM.len() as u8];
                    c.extend_from_slice(REALM.as_bytes());
                    c.push(NONCE.len() as u8);
                    c.extend_from_slice(NONCE.as_bytes());
                    c.push(4);
                    c.extend_from_slice(b"auth");
                    sock.write_all(&auth_reply(1, 4, &c)).await?;
                    continue;
                }
                let ha1 = md5_hex(&format!("{user}:{REALM}:{password}"));
                let ha2 = md5_hex(&format!("POST:{}", f[3]));
                let want = md5_hex(&format!("{ha1}:{NONCE}:{}:{}:{}:{ha2}", f[5], f[4], f[7]));
                let ok = f[0] == user && f[6] == want;
                sock.write_all(&auth_reply(if ok { 0 } else { 2 }, 4, &[]))
                    .await?;
                if !ok {
                    return Ok(());
                }
                seen.lock().await.authenticated = true;
                break;
            }
            other => panic!("fake does not speak auth type {other}"),
        }
    }

    // SOL settings (4 + 4 seq + 12 + 4 = 24 bytes) -> 23-byte reply.
    let s = read_n(&mut sock, 24).await?;
    assert_eq!(s[0], 0x20);
    seen.lock().await.settings_received = true;
    let mut reply = vec![0x21, 0];
    reply.resize(23, 0);
    sock.write_all(&reply).await?;
    // Control (0x27): 4 + 4 seq + 6.
    let c = read_n(&mut sock, 14).await?;
    assert_eq!(c[0], 0x27);

    sock.write_all(&data_frame(banner.as_bytes())).await?;
    loop {
        let mut t = [0u8; 1];
        if sock.read(&mut t).await? == 0 {
            return Ok(());
        }
        match t[0] {
            0x28 => {
                let h = read_n(&mut sock, 9).await?;
                let len = u16::from_le_bytes([h[7], h[8]]) as usize;
                let bytes = read_n(&mut sock, len).await?;
                seen.lock().await.typed.extend_from_slice(&bytes);
                let mut echo = b"echo:".to_vec();
                echo.extend_from_slice(&bytes);
                sock.write_all(&data_frame(&echo)).await?;
            }
            0x2B => {
                read_n(&mut sock, 7).await?;
                seen.lock().await.keepalives += 1;
            }
            other => panic!("fake got unexpected message 0x{other:02X}"),
        }
    }
}
