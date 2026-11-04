//! IDE redirection: serve a local ISO image to the device as a CD-ROM drive,
//! so it can boot an installer or rescue system with no physical media.
//!
//! After the shared redirection start and digest authentication (`redir`,
//! session kind "IDER"), AMT sends ATAPI commands written by the host's BIOS
//! or OS and expects register/data frames back. The command set and the
//! response frames follow Intel's protocol as MeshCentral's
//! `amt-ider-module.js` implements it (Apache-2.0). Only the CD-ROM device is
//! served, read-only; the floppy device always reports no medium.
//!
//! Frame header: command id, 2 reserved bytes, attributes, sequence (u32 LE).

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::AsyncReadExt;
use tokio::net::tcp::OwnedReadHalf;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

use crate::error::{Error, Result};
use crate::redir::{self, Writer};
use crate::wsman::Endpoint;

const CD_BLOCK: u64 = 2048;
const DEV_FLOPPY: u8 = 0xA0;
const DEV_CD: u8 = 0xB0;

/// When AMT should switch the host's boot over to the IDE-R device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum IderStart {
    /// At the next reboot (pair with a reset or cycle).
    OnReboot,
    /// After the OS shuts down gracefully.
    Graceful,
    /// Immediately: the drive appears to the running host.
    Now,
}

impl IderStart {
    fn bits(self) -> u32 {
        match self {
            Self::OnReboot => 0x08,
            Self::Graceful => 0x10,
            Self::Now => 0x18,
        }
    }
}

/// What an IDE-R session has done so far.
#[derive(Debug, Clone, Default, Serialize)]
pub struct IderStatus {
    pub image_bytes: u64,
    /// AMT reports the IDE-R device as enabled towards the host.
    pub enabled: bool,
    pub commands: u64,
    pub blocks_read: u64,
    pub bytes_sent: u64,
    pub last_command: Option<String>,
    pub resets: u32,
    pub closed: Option<String>,
}

/// A running IDE-R session. Dropping it ends the session.
pub struct IderSession {
    task: JoinHandle<()>,
    status: Arc<Mutex<IderStatus>>,
}

impl IderSession {
    /// Opens IDE-R and starts serving `iso` as the CD-ROM. On a device in
    /// client control mode, user consent must be granted first.
    pub async fn open(
        ep: &Endpoint,
        port: u16,
        iso: &Path,
        start: IderStart,
        timeout: Duration,
    ) -> Result<Self> {
        let file = File::open(iso)
            .map_err(|e| Error::InvalidArgument(format!("cannot open {}: {e}", iso.display())))?;
        let size = file.metadata()?.len();
        if size == 0 || size % CD_BLOCK != 0 {
            return Err(Error::InvalidArgument(format!(
                "{} is not a CD image: its size is not a multiple of 2048 bytes",
                iso.display()
            )));
        }
        let (rd, w) = redir::open(ep, port, redir::IDER, timeout).await?;
        let status = Arc::new(Mutex::new(IderStatus {
            image_bytes: size,
            ..Default::default()
        }));
        let mut s = Server {
            w,
            media: Some(Media { file, size }),
            cd_ready: false,
            read_buffer: 8192,
            start,
            status: status.clone(),
        };
        let st = status.clone();
        let task = tokio::spawn(async move {
            let reason = match s.run(rd).await {
                Ok(()) => "closed by AMT".to_string(),
                Err(e) => e.to_string(),
            };
            tracing::info!(%reason, "IDE-R session ended");
            st.lock().await.closed = Some(reason);
        });
        tracing::info!(host = %ep.host, image = %iso.display(), "IDE-R session open");
        Ok(Self { task, status })
    }

    pub async fn status(&self) -> IderStatus {
        self.status.lock().await.clone()
    }

    pub async fn close(self) {
        self.task.abort();
    }
}

impl Drop for IderSession {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct Media {
    file: File,
    size: u64,
}

struct Server {
    w: Writer,
    media: Option<Media>,
    cd_ready: bool,
    read_buffer: usize,
    start: IderStart,
    status: Arc<Mutex<IderStatus>>,
}

impl Server {
    async fn run(&mut self, mut rd: OwnedReadHalf) -> Result<()> {
        // OPEN_SESSION: rx timeout 30 s, tx timeout 0, heartbeat 20 s, version 1.
        let mut open = Vec::new();
        open.extend_from_slice(&30_000u16.to_le_bytes());
        open.extend_from_slice(&0u16.to_le_bytes());
        open.extend_from_slice(&20_000u16.to_le_bytes());
        open.extend_from_slice(&1u32.to_le_bytes());
        self.command(0x40, &open, false, false).await?;

        let mut acc: Vec<u8> = Vec::new();
        let mut in_seq: u32 = 0;
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            let n = rd.read(&mut buf).await?;
            if n == 0 {
                return Ok(());
            }
            acc.extend_from_slice(&buf[..n]);
            while let Some(len) = self.frame(&acc).await? {
                let seq = u32::from_le_bytes([acc[4], acc[5], acc[6], acc[7]]);
                if seq != in_seq {
                    return Err(Error::Protocol(format!(
                        "IDE-R frame out of sequence: got {seq}, expected {in_seq}"
                    )));
                }
                in_seq = in_seq.wrapping_add(1);
                acc.drain(..len);
            }
        }
    }

    /// Handles one complete frame at the front of `acc` and returns its length,
    /// or `None` if more bytes are needed.
    async fn frame(&mut self, acc: &[u8]) -> Result<Option<usize>> {
        if acc.len() < 8 {
            return Ok(None);
        }
        Ok(Some(match acc[0] {
            0x41 => {
                // OPEN_SESSION reply.
                if acc.len() < 30 || acc.len() < 30 + acc[29] as usize {
                    return Ok(None);
                }
                let read_buffer = u16::from_le_bytes([acc[16], acc[17]]) as usize;
                if acc[21] != 0 || read_buffer == 0 || read_buffer > 8192 {
                    return Err(Error::Protocol(format!(
                        "unexpected IDE-R parameters (protocol {}, read buffer {read_buffer})",
                        acc[21]
                    )));
                }
                self.read_buffer = read_buffer;
                self.enable().await?;
                30 + acc[29] as usize
            }
            0x43 => return Err(Error::Protocol("IDE-R session closed by AMT".into())),
            0x44 => {
                self.command(0x45, &[], false, false).await?; // ping -> pong
                8
            }
            0x45 | 0x4B => 8, // pong, heartbeat
            0x46 => {
                if acc.len() < 9 {
                    return Ok(None);
                }
                self.status.lock().await.resets += 1;
                self.command(0x47, &[], false, false).await?; // reset acknowledged
                9
            }
            0x49 => {
                if acc.len() < 13 {
                    return Ok(None);
                }
                let value = u32::from_le_bytes([acc[9], acc[10], acc[11], acc[12]]);
                match acc[8] {
                    1 if value & 1 != 0 => self.enable().await?,
                    2 => self.status.lock().await.enabled = value & 2 != 0,
                    3 => {
                        if value != 1 {
                            tracing::warn!(value, "IDE-R register toggle failed");
                        }
                        self.status.lock().await.enabled = value == 1;
                    }
                    _ => {}
                }
                13
            }
            0x4A => {
                if acc.len() < 11 {
                    return Ok(None);
                }
                tracing::warn!(code = acc[8], "IDE-R error reported by AMT");
                11
            }
            0x50 => {
                if acc.len() < 28 {
                    return Ok(None);
                }
                let flags = acc[14];
                let dev = if flags & 0x10 != 0 {
                    DEV_CD
                } else {
                    DEV_FLOPPY
                };
                let mut cdb = [0u8; 12];
                cdb.copy_from_slice(&acc[16..28]);
                self.scsi(dev, &cdb, acc[9] & 1 == 1, flags).await?;
                28
            }
            0x53 => {
                // Data the host wrote: refuse, the media is read-only.
                if acc.len() < 14 {
                    return Ok(None);
                }
                let len = u16::from_le_bytes([acc[9], acc[10]]) as usize;
                if acc.len() < 14 + len {
                    return Ok(None);
                }
                self.end_sense(DEV_FLOPPY, 0x07, 0x27, 0x00).await?;
                14 + len
            }
            other => {
                return Err(Error::Protocol(format!(
                    "unknown IDE-R command 0x{other:02X}"
                )));
            }
        }))
    }

    async fn enable(&mut self) -> Result<()> {
        // DisableEnableFeatures, REGS_TOGGLE: enable + when to switch over.
        let mut d = vec![3u8];
        d.extend_from_slice(&(0x01 + self.start.bits()).to_le_bytes());
        self.command(0x48, &d, false, false).await
    }

    async fn command(&mut self, id: u8, data: &[u8], completed: bool, dma: bool) -> Result<()> {
        let mut attributes = if id > 50 && completed { 2 } else { 0 };
        if dma {
            attributes += 1;
        }
        let seq = self.w.next_seq();
        let mut f = vec![id, 0, 0, attributes];
        f.extend_from_slice(&seq.to_le_bytes());
        f.extend_from_slice(data);
        self.w.send(&f).await?;
        self.status.lock().await.bytes_sent += f.len() as u64;
        Ok(())
    }

    /// Command completed with good status.
    async fn end_ok(&mut self, dev: u8) -> Result<()> {
        let mut d = vec![0u8; 12];
        d.extend_from_slice(&[0xC5, 0, 3, 0, 0, 0, dev, 0x50, 0, 0, 0]);
        self.command(0x51, &d, true, false).await
    }

    /// Command failed with sense key / ASC / ASCQ.
    async fn end_sense(&mut self, dev: u8, sense: u8, asc: u8, ascq: u8) -> Result<()> {
        let mut d = vec![0u8; 12];
        d.extend_from_slice(&[0x87, sense << 4, 3, 0, 0, 0, dev, 0x51, sense, asc, ascq]);
        self.command(0x51, &d, true, false).await
    }

    async fn data_to_host(&mut self, dev: u8, last: bool, data: &[u8], dma: bool) -> Result<()> {
        let len = data.len();
        let dmalen = if dma { 0 } else { len };
        let mut d = vec![
            0,
            (len & 0xff) as u8,
            (len >> 8) as u8,
            0,
            if dma { 0xB4 } else { 0xB5 },
            0,
            2,
            0,
            (dmalen & 0xff) as u8,
            (dmalen >> 8) as u8,
            dev,
            0x58,
        ];
        if last {
            d.extend_from_slice(&[0x85, 0, 3, 0, 0, 0, dev, 0x50, 0, 0, 0, 0, 0, 0]);
        } else {
            d.extend_from_slice(&[0; 14]);
        }
        d.extend_from_slice(data);
        self.command(0x54, &d, last, dma).await
    }

    fn cd_blocks(&self) -> u64 {
        self.media.as_ref().map(|m| m.size / CD_BLOCK).unwrap_or(0)
    }

    async fn scsi(&mut self, dev: u8, cdb: &[u8; 12], dma: bool, flags: u8) -> Result<()> {
        {
            let mut st = self.status.lock().await;
            st.commands += 1;
            st.last_command = Some(format!("0x{:02X} dev 0x{dev:02X}", cdb[0]));
        }
        let cd = dev == DEV_CD;
        let has_media = cd && self.media.is_some();
        match cdb[0] {
            // TEST UNIT READY: report the first one as "medium changed", like a
            // drive that just had a disc inserted, then ready.
            0x00 => {
                if has_media && !self.cd_ready {
                    self.cd_ready = true;
                }
                self.end_ok(dev).await
            }
            // READ(6)
            0x08 => {
                let lba = (((cdb[1] & 0x1f) as u64) << 16) | ((cdb[2] as u64) << 8) | cdb[3] as u64;
                let len = if cdb[4] == 0 { 256 } else { cdb[4] as u64 };
                self.read_blocks(dev, lba, len, dma).await
            }
            // WRITE(6), WRITE(10), WRITE AND VERIFY: read-only media.
            0x0A | 0x2A | 0x2E => self.end_sense(dev, 0x07, 0x27, 0x00).await,
            // MODE SENSE(6), all pages.
            0x1A if cdb[2] == 0x3F && cdb[3] == 0 => {
                if !has_media {
                    return self.end_sense(dev, 0x02, 0x3A, 0x00).await;
                }
                self.data_to_host(dev, true, &[0, 0x05, 0x80, 0], dma).await
            }
            0x1A => self.end_sense(dev, 0x05, 0x24, 0x00).await,
            // START STOP UNIT, PREVENT ALLOW MEDIUM REMOVAL
            0x1B | 0x1E => self.end_ok(dev).await,
            // READ FORMAT CAPACITIES (floppy only)
            0x23 => self.end_sense(dev, 0x05, 0x24, 0x00).await,
            // READ CAPACITY: last block address and block size.
            0x25 => {
                if !has_media {
                    return self.end_sense(dev, 0x02, 0x3A, 0x00).await;
                }
                let last = (self.cd_blocks() - 1) as u32;
                let mut d = last.to_be_bytes().to_vec();
                d.extend_from_slice(&(CD_BLOCK as u32).to_be_bytes());
                self.data_to_host(flags, true, &d, dma).await
            }
            // READ(10)
            0x28 => {
                let lba = u32::from_be_bytes([cdb[2], cdb[3], cdb[4], cdb[5]]) as u64;
                let len = u16::from_be_bytes([cdb[7], cdb[8]]) as u64;
                self.read_blocks(dev, lba, len, dma).await
            }
            // READ TOC: one data track.
            0x43 => {
                if !cd {
                    return self.end_sense(dev, 0x05, 0x20, 0x00).await;
                }
                let msf = cdb[1] & 0x02 != 0;
                let mut format = cdb[2] & 0x07;
                if format == 0 {
                    format = cdb[9] >> 6;
                }
                let d: &[u8] = match (format, msf) {
                    (1, _) => &[
                        0x00, 0x0A, 0x01, 0x01, 0x00, 0x14, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
                    ],
                    (_, true) => &[
                        0x00, 0x12, 0x01, 0x01, 0x00, 0x14, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00,
                        0x00, 0x14, 0xAA, 0x00, 0x00, 0x00, 0x34, 0x13,
                    ],
                    _ => &[
                        0x00, 0x12, 0x01, 0x01, 0x00, 0x14, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x14, 0xAA, 0x00, 0x00, 0x00, 0x00, 0x00,
                    ],
                };
                self.data_to_host(dev, true, d, dma).await
            }
            // GET CONFIGURATION
            0x46 => {
                let sendall = cdb[1] != 2;
                let first = u16::from_be_bytes([cdb[2], cdb[3]]);
                let buflen = u16::from_be_bytes([cdb[7], cdb[8]]) as usize;
                let d = get_configuration(sendall, first, buflen);
                self.data_to_host(dev, true, &d, dma).await
            }
            // GET EVENT STATUS NOTIFICATION (media class)
            0x4A => {
                if cdb[1] != 0x01 && cdb[4] != 0x10 {
                    return self.end_sense(dev, 0x05, 0x26, 0x01).await;
                }
                let present = if has_media { 0x02 } else { 0x00 };
                self.data_to_host(dev, true, &[0x00, present, 0x80, 0x00], dma)
                    .await
            }
            // READ DISC INFORMATION / MODE SELECT(10): not supported.
            0x51 | 0x55 => self.end_sense(dev, 0x05, 0x20, 0x00).await,
            // MODE SENSE(10)
            0x5A => {
                let page = cdb[2] & 0x3F;
                match mode_sense_10(cd, page) {
                    Some(d) => self.data_to_host(dev, true, d, dma).await,
                    None => self.end_sense(dev, 0x05, 0x20, 0x00).await,
                }
            }
            // GET PERFORMANCE
            0xAC => {
                self.data_to_host(
                    dev,
                    true,
                    &[0x00, 0x00, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00],
                    dma,
                )
                .await
            }
            _ => self.end_sense(dev, 0x05, 0x20, 0x00).await,
        }
    }

    async fn read_blocks(&mut self, dev: u8, lba: u64, len: u64, dma: bool) -> Result<()> {
        if dev != DEV_CD || self.media.is_none() {
            return self.end_sense(dev, 0x02, 0x3A, 0x00).await;
        }
        if lba + len > self.cd_blocks() {
            return self.end_sense(dev, 0x05, 0x21, 0x00).await;
        }
        if len == 0 {
            return self.end_ok(dev).await;
        }
        let mut offset = lba * CD_BLOCK;
        let mut remaining = (len * CD_BLOCK) as usize;
        let chunk = self.read_buffer;
        let mut buf = vec![0u8; chunk];
        while remaining > 0 {
            let n = remaining.min(chunk);
            {
                let media = self.media.as_mut().expect("checked above");
                media.file.seek(SeekFrom::Start(offset))?;
                media.file.read_exact(&mut buf[..n])?;
            }
            remaining -= n;
            offset += n as u64;
            let data = buf[..n].to_vec();
            self.data_to_host(dev, remaining == 0, &data, dma).await?;
        }
        self.status.lock().await.blocks_read += len;
        Ok(())
    }
}

fn get_configuration(sendall: bool, first: u16, buflen: usize) -> Vec<u8> {
    const PROFILE_LIST: &[u8] = &[0x00, 0x00, 0x03, 0x04, 0x00, 0x08, 0x01, 0x00];
    const CORE: &[u8] = &[0x00, 0x01, 0x03, 0x04, 0x00, 0x00, 0x00, 0x02];
    const MORPHING: &[u8] = &[0x00, 0x02, 0x03, 0x04, 0x00, 0x00, 0x00, 0x00];
    const REMOVABLE: &[u8] = &[0x00, 0x03, 0x03, 0x04, 0x29, 0x00, 0x00, 0x02];
    const RANDOM: &[u8] = &[
        0x00, 0x10, 0x01, 0x08, 0x00, 0x00, 0x08, 0x00, 0x00, 0x01, 0x00, 0x00,
    ];
    const READ: &[u8] = &[0x00, 0x1E, 0x03, 0x00];
    const POWER: &[u8] = &[0x01, 0x00, 0x03, 0x00];
    const TIMEOUT: &[u8] = &[0x01, 0x05, 0x03, 0x00];
    if buflen == 0 {
        let mut d = 0x3Cu32.to_be_bytes().to_vec();
        d.extend_from_slice(&8u32.to_be_bytes());
        return d;
    }
    // As the reference implementation: the last matching feature wins.
    let features: [(u16, &[u8]); 7] = [
        (0x01, CORE),
        (0x02, MORPHING),
        (0x03, REMOVABLE),
        (0x10, RANDOM),
        (0x1E, READ),
        (0x100, POWER),
        (0x105, TIMEOUT),
    ];
    let mut r: Option<&[u8]> = if first == 0 { Some(PROFILE_LIST) } else { None };
    for (code, feature) in features {
        if first == code || (sendall && first < code) {
            r = Some(feature);
        }
    }
    let mut d = 8u32.to_be_bytes().to_vec();
    match r {
        Some(f) => {
            d.extend_from_slice(&((f.len() + 4) as u32).to_be_bytes());
            d.extend_from_slice(f);
        }
        None => d.extend_from_slice(&4u32.to_be_bytes()),
    }
    d.truncate(buflen);
    d
}

fn mode_sense_10(cd: bool, page: u8) -> Option<&'static [u8]> {
    const CD_ERROR_RECOVERY: &[u8] = &[
        0x00, 0x0E, 0x01, 0x80, 0x00, 0x00, 0x00, 0x00, 0x01, 0x06, 0x00, 0xFF, 0x00, 0x00, 0x00,
        0x00,
    ];
    const CD_3F: &[u8] = &[
        0x00, 0x28, 0x01, 0x80, 0x00, 0x00, 0x00, 0x00, 0x01, 0x06, 0x00, 0xFF, 0x00, 0x00, 0x00,
        0x00, 0x2A, 0x18, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    const CD_1A: &[u8] = &[
        0x00, 0x12, 0x01, 0x80, 0x00, 0x00, 0x00, 0x00, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    const CD_1D: &[u8] = &[
        0x00, 0x12, 0x01, 0x80, 0x00, 0x00, 0x00, 0x00, 0x1D, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    const CD_2A: &[u8] = &[
        0x00, 0x20, 0x01, 0x80, 0x00, 0x00, 0x00, 0x00, 0x2A, 0x18, 0x00, 0x00, 0x00, 0x00, 0x20,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    ];
    if !cd {
        return None;
    }
    match page {
        0x01 => Some(CD_ERROR_RECOVERY),
        0x3F => Some(CD_3F),
        0x1A => Some(CD_1A),
        0x1D => Some(CD_1D),
        0x2A => Some(CD_2A),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configuration_header_and_truncation() {
        let d = get_configuration(true, 0, 64);
        assert_eq!(&d[..4], &8u32.to_be_bytes());
        // With sendall from 0, the reference picks the last feature (timeout).
        assert_eq!(&d[8..], &[0x01, 0x05, 0x03, 0x00]);
        assert_eq!(get_configuration(true, 0, 6).len(), 6);
        assert_eq!(
            get_configuration(false, 0x1E, 64)[8..],
            [0x00, 0x1E, 0x03, 0x00]
        );
    }

    #[test]
    fn start_bits() {
        assert_eq!(IderStart::OnReboot.bits() + 1, 0x09);
        assert_eq!(IderStart::Now.bits() + 1, 0x19);
    }

    #[test]
    fn mode_sense_pages() {
        assert!(mode_sense_10(true, 0x2A).is_some());
        assert!(mode_sense_10(false, 0x2A).is_none());
        assert!(mode_sense_10(true, 0x05).is_none());
    }
}
