//! Serial-over-LAN through the AMT redirection protocol on port 16994: after
//! the shared session start and digest authentication (`redir`), SOL settings
//! and a stream of data/keep-alive frames. All integers are little-endian.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::OwnedReadHalf;
use tokio::sync::{Mutex, Notify};
use tokio::task::JoinHandle;

use crate::error::{Error, Result};
use crate::redir::{self, Writer, expect_type, read_exact};
use crate::wsman::Endpoint;

pub use crate::redir::DEFAULT_PORT;
/// Bytes kept for `read`. Older output is dropped first.
const BUFFER_LIMIT: usize = 256 * 1024;

mod msg {
    pub const SOL_SETTINGS: u8 = 0x20;
    pub const SOL_SETTINGS_REPLY: u8 = 0x21;
    pub const SOL_CONTROL: u8 = 0x27;
    pub const SOL_DATA_TO_HOST: u8 = 0x28;
    pub const SOL_CONTROL_FROM_HOST: u8 = 0x29;
    pub const SOL_DATA_FROM_HOST: u8 = 0x2A;
    pub const KEEP_ALIVE: u8 = 0x2B;
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

impl SolSession {
    /// Connects, authenticates and starts SOL. On a device in client control
    /// mode, user consent must have been granted first or AMT ends the session.
    pub async fn open(ep: &Endpoint, port: u16, timeout: Duration) -> Result<Self> {
        let (mut rd, mut w) = redir::open(ep, port, redir::SOL, timeout).await?;
        tokio::time::timeout(timeout, sol_setup(&mut rd, &mut w))
            .await
            .map_err(|_| Error::Timeout("SOL setup"))??;

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

async fn sol_setup(rd: &mut OwnedReadHalf, w: &mut Writer) -> Result<()> {
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
