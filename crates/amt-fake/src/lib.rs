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
    pub kind: Vec<u8>,
    pub authenticated: bool,
    /// IDE-R: the feature toggle the client sent (0x01 + start bits).
    pub ider_toggle: Option<u32>,
    /// IDE-R: last block address and block size from READ CAPACITY.
    pub ider_capacity: Option<(u32, u32)>,
    /// IDE-R: bytes returned for the READ(10) the fake issued.
    pub ider_read: Vec<u8>,
    pub settings_received: bool,
    pub typed: Vec<u8>,
    pub keepalives: usize,
    /// The password a client sent in clear (auth type 1), if any.
    pub plaintext_password: Option<String>,
}

pub struct FakeRedirection {
    pub addr: SocketAddr,
    pub seen: Arc<Mutex<Seen>>,
}

/// Which authentication types the fake offers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Offer {
    Digest,
    /// Only type 1, the password in clear: old firmware, or a downgrade by
    /// someone on the path.
    PlaintextOnly,
}

impl FakeRedirection {
    /// Starts a fake accepting one session, authenticating `user`/`password`.
    /// It greets with `banner` once SOL is up.
    pub async fn start(user: &str, password: &str, banner: &str) -> Self {
        Self::start_kind(user, password, banner, false, Offer::Digest).await
    }

    /// A SOL fake that offers only plaintext authentication (type 1).
    pub async fn start_plaintext_only(user: &str, password: &str, banner: &str) -> Self {
        Self::start_kind(user, password, banner, false, Offer::PlaintextOnly).await
    }

    /// An IDE-R fake: after authentication it opens the session, then issues
    /// READ CAPACITY and a READ(10) of `read_blocks` blocks from block 1.
    pub async fn start_ider(user: &str, password: &str) -> Self {
        Self::start_kind(user, password, "", true, Offer::Digest).await
    }

    async fn start_kind(
        user: &str,
        password: &str,
        banner: &str,
        ider: bool,
        offer: Offer,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let seen = Arc::new(Mutex::new(Seen::default()));
        let (user, password, banner) = (user.to_string(), password.to_string(), banner.to_string());
        let s = seen.clone();
        tokio::spawn(async move {
            if let Ok((sock, _)) = listener.accept().await {
                let _ = if ider {
                    serve_ider(sock, &user, &password, s).await
                } else {
                    serve(sock, &user, &password, &banner, offer, s).await
                };
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

/// Session start and digest authentication. Returns false if the client
/// failed to authenticate (the fake then ends the connection).
async fn start_and_auth(
    sock: &mut TcpStream,
    user: &str,
    password: &str,
    offer: Offer,
    seen: &Arc<Mutex<Seen>>,
) -> std::io::Result<bool> {
    // StartRedirectionSession(kind) -> reply with no OEM data.
    let start = read_n(sock, 8).await?;
    assert_eq!(&start[..4], &[0x10, 0, 0, 0]);
    seen.lock().await.kind = start[4..].to_vec();
    sock.write_all(&[0x11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
        .await?;

    loop {
        let h = read_n(sock, 9).await?;
        assert_eq!(h[0], 0x13, "expected AuthenticateSession");
        let len = u32::from_le_bytes([h[5], h[6], h[7], h[8]]) as usize;
        let data = read_n(sock, len).await?;
        match h[4] {
            0 => {
                let types: &[u8] = match offer {
                    Offer::Digest => &[1, 4],
                    Offer::PlaintextOnly => &[1],
                };
                sock.write_all(&auth_reply(0, 0, types)).await?
            }
            1 => {
                let f = strings(&data);
                let ok = f.first().map(String::as_str) == Some(user)
                    && f.get(1).map(String::as_str) == Some(password);
                seen.lock().await.plaintext_password = f.get(1).cloned();
                sock.write_all(&auth_reply(if ok { 0 } else { 2 }, 1, &[]))
                    .await?;
                if ok {
                    seen.lock().await.authenticated = true;
                }
                return Ok(ok);
            }
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
                if ok {
                    seen.lock().await.authenticated = true;
                }
                return Ok(ok);
            }
            other => panic!("fake does not speak auth type {other}"),
        }
    }
}

async fn serve(
    mut sock: TcpStream,
    user: &str,
    password: &str,
    banner: &str,
    offer: Offer,
    seen: Arc<Mutex<Seen>>,
) -> std::io::Result<()> {
    if !start_and_auth(&mut sock, user, password, offer, &seen).await? {
        return Ok(());
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

fn ider_frame(id: u8, seq: u32, data: &[u8]) -> Vec<u8> {
    let mut f = vec![id, 0, 0, 0];
    f.extend_from_slice(&seq.to_le_bytes());
    f.extend_from_slice(data);
    f
}

/// A COMMAND WRITTEN frame for the CD-ROM device carrying `cdb`.
fn ider_command(seq: u32, cdb: [u8; 12]) -> Vec<u8> {
    // Frame bytes 8..16 are registers (device flags at 14), 16..28 the CDB.
    let mut d = vec![0u8; 8];
    d[6] = 0x10; // device flags: slave (CD-ROM)
    d.extend_from_slice(&cdb);
    ider_frame(0x50, seq, &d)
}

/// Reads client frames until a DATA TO HOST (0x54) with the completed flag,
/// returning the concatenated payloads.
async fn ider_collect(sock: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let h = read_n(sock, 8).await?;
        assert_eq!(h[0], 0x54, "expected DATA TO HOST, got 0x{:02X}", h[0]);
        let regs = read_n(sock, 26).await?;
        let len = u16::from_le_bytes([regs[1], regs[2]]) as usize;
        out.extend_from_slice(&read_n(sock, len).await?);
        if h[3] & 2 != 0 {
            return Ok(out);
        }
    }
}

async fn serve_ider(
    mut sock: TcpStream,
    user: &str,
    password: &str,
    seen: Arc<Mutex<Seen>>,
) -> std::io::Result<()> {
    if !start_and_auth(&mut sock, user, password, Offer::Digest, &seen).await? {
        return Ok(());
    }
    // OPEN_SESSION from the client: header + 10 bytes of parameters.
    let open = read_n(&mut sock, 18).await?;
    assert_eq!(open[0], 0x40);
    // Reply: version 1.0, read/write buffer 4096, protocol 0, no OEM data.
    let mut reply = vec![0u8; 22];
    reply[0] = 1;
    reply[8..10].copy_from_slice(&4096u16.to_le_bytes());
    reply[10..12].copy_from_slice(&4096u16.to_le_bytes());
    let mut seq = 0;
    sock.write_all(&ider_frame(0x41, seq, &reply)).await?;
    seq += 1;
    // The client enables the device: DisableEnableFeatures(REGS_TOGGLE, value).
    let toggle = read_n(&mut sock, 13).await?;
    assert_eq!((toggle[0], toggle[8]), (0x48, 3));
    seen.lock().await.ider_toggle = Some(u32::from_le_bytes([
        toggle[9], toggle[10], toggle[11], toggle[12],
    ]));

    // READ CAPACITY.
    sock.write_all(&ider_command(seq, [0x25, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]))
        .await?;
    seq += 1;
    let cap = ider_collect(&mut sock).await?;
    seen.lock().await.ider_capacity = Some((
        u32::from_be_bytes([cap[0], cap[1], cap[2], cap[3]]),
        u32::from_be_bytes([cap[4], cap[5], cap[6], cap[7]]),
    ));

    // READ(10) of 2 blocks from LBA 1: 4096 bytes, one chunk at this buffer size.
    sock.write_all(&ider_command(seq, [0x28, 0, 0, 0, 0, 1, 0, 0, 2, 0, 0, 0]))
        .await?;
    let data = ider_collect(&mut sock).await?;
    seen.lock().await.ider_read = data;
    // Keep the connection open until the client goes away.
    let mut rest = [0u8; 64];
    while sock.read(&mut rest).await? > 0 {}
    Ok(())
}

/// What [`FakeWsman`] does with one request it has read in full.
#[derive(Debug, Clone)]
pub enum WsmanStep {
    /// Answers 200 with this SOAP body.
    Respond(String),
    /// Closes the connection without answering, as a device that executed the
    /// request and then reset would.
    Drop,
    /// Never answers, holding the connection open: the client times out.
    Hang,
}

/// A scripted fake of AMT's WS-Man HTTP endpoint (no digest challenge). It
/// reads each request in full, records its body, then follows the next step of
/// the script; past the end of the script it answers with an empty body.
pub struct FakeWsman {
    pub addr: SocketAddr,
    /// The body of every request received, in order.
    pub requests: Arc<Mutex<Vec<String>>>,
}

impl FakeWsman {
    pub async fn start(script: Vec<WsmanStep>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let script = Arc::new(Mutex::new(std::collections::VecDeque::from(script)));
        let seen = requests.clone();
        tokio::spawn(async move {
            while let Ok((sock, _)) = listener.accept().await {
                let (seen, script) = (seen.clone(), script.clone());
                tokio::spawn(async move {
                    let _ = serve_wsman(sock, seen, script).await;
                });
            }
        });
        Self { addr, requests }
    }

    /// How many requests reached the fake.
    pub async fn count(&self) -> usize {
        self.requests.lock().await.len()
    }
}

async fn serve_wsman(
    mut sock: TcpStream,
    seen: Arc<Mutex<Vec<String>>>,
    script: Arc<Mutex<std::collections::VecDeque<WsmanStep>>>,
) -> std::io::Result<()> {
    let mut buf = Vec::new();
    loop {
        // Headers, then a Content-Length body.
        let head_end = loop {
            if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break i + 4;
            }
            let mut chunk = [0u8; 4096];
            let n = sock.read(&mut chunk).await?;
            if n == 0 {
                return Ok(());
            }
            buf.extend_from_slice(&chunk[..n]);
        };
        let head = String::from_utf8_lossy(&buf[..head_end]).to_ascii_lowercase();
        let len: usize = head
            .lines()
            .find_map(|l| l.strip_prefix("content-length:"))
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(0);
        while buf.len() < head_end + len {
            let mut chunk = [0u8; 4096];
            let n = sock.read(&mut chunk).await?;
            if n == 0 {
                return Ok(());
            }
            buf.extend_from_slice(&chunk[..n]);
        }
        let body = String::from_utf8_lossy(&buf[head_end..head_end + len]).into_owned();
        buf.drain(..head_end + len);
        seen.lock().await.push(body);
        let step = script.lock().await.pop_front();
        match step {
            Some(WsmanStep::Drop) => return Ok(()),
            Some(WsmanStep::Hang) => {
                std::future::pending::<()>().await;
            }
            Some(WsmanStep::Respond(body)) => write_soap(&mut sock, &body).await?,
            None => write_soap(&mut sock, "").await?,
        }
    }
}

async fn write_soap(sock: &mut TcpStream, body: &str) -> std::io::Result<()> {
    let resp = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/soap+xml;charset=UTF-8\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    sock.write_all(resp.as_bytes()).await
}
