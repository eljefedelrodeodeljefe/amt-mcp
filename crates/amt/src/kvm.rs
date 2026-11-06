//! KVM: enable it over WS-Man, then speak RFB to take screenshots and send
//! keys. This sees what the display shows, including BIOS setup and boot
//! loaders.
//!
//! Updates arrive as ZRLE (AMT's "RLE") or Raw in AMT's native pixel format
//! and are converted to PNG. AMT's KVM framebuffer is limited to about 9.2 MB
//! (bytes per pixel x width x height): 3840x2160 at 16 bits is over it.
//!
//! Two transports: inside an AMT redirection session (port 16994, session
//! "KVMR", digest-authenticated, RFB security None) — the path Intel's own
//! tools use — or the standard VNC port 5900 with an RFB password. Both work;
//! the redirection path needs no RFB password and no open port 5900.
//!
//! AMT ends the session on the first update request unless the client offers
//! ZRLE (with Raw) and asks for the whole screen in one request, as Intel's
//! own client does.

use std::time::Duration;

use des::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};
use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::device::{Device, declare_prefix};
use crate::error::{Error, Result};
use crate::redir::{self, expect_type, read_exact};
use crate::wsman::Endpoint;
use crate::wsman::{self, CIM, IPS, field_u32};
use crate::zrle::{self, Zrle};

pub const VNC_PORT: u16 = 5900;

/// The largest framebuffer accepted from the device, in its native pixel
/// format (bytes per pixel x width x height). AMT's own limit is about 9.2 MB;
/// this leaves headroom while keeping a hostile ServerInit or DesktopSize from
/// sizing a multi-gigabyte allocation.
pub const MAX_FRAMEBUFFER_BYTES: usize = 16 << 20;

/// Refuses a framebuffer of `w` x `h` pixels at `bpp` bytes each over
/// [`MAX_FRAMEBUFFER_BYTES`].
fn check_framebuffer(w: usize, h: usize, bpp: usize) -> Result<()> {
    let bytes = w.saturating_mul(h).saturating_mul(bpp);
    if bytes > MAX_FRAMEBUFFER_BYTES {
        return Err(Error::Protocol(format!(
            "KVM framebuffer {w}x{h} at {bpp} bytes per pixel is {bytes} bytes, over the limit of {MAX_FRAMEBUFFER_BYTES}"
        )));
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize)]
pub struct KvmState {
    /// CIM_KVMRedirectionSAP EnabledState: 2 enabled, 3 disabled, 6 enabled but offline.
    pub sap_enabled_state: u32,
    pub port_5900_enabled: bool,
    pub enabled_by_mebx: bool,
}

impl Device {
    pub async fn kvm_state(&self) -> Result<KvmState> {
        let sap = self
            .client()
            .get(&format!("{CIM}CIM_KVMRedirectionSAP"))
            .await?;
        let kvm = self.kvm().await?;
        Ok(KvmState {
            sap_enabled_state: field_u32(&sap, "EnabledState")?,
            port_5900_enabled: kvm.port_5900_enabled,
            enabled_by_mebx: kvm.enabled_by_mebx,
        })
    }

    /// Opens the VNC port with `rfb_password` and enables the KVM service.
    /// The RFB password must be exactly 8 characters with upper, lower, digit
    /// and a symbol.
    pub async fn enable_kvm(&self, rfb_password: &str) -> Result<KvmState> {
        check_rfb_password(rfb_password)?;
        let uri = format!("{IPS}IPS_KVMRedirectionSettingData");
        let xml = self.client().get(&uri).await?;
        let inst = wsman::element(&xml, "IPS_KVMRedirectionSettingData")
            .ok_or(Error::MissingField("IPS_KVMRedirectionSettingData"))?;
        let inst = wsman::replace_field(&inst, "Is5900PortEnabled", "true");
        let inst = wsman::replace_field(&inst, "RFBPassword", rfb_password);
        let inst = declare_prefix(&inst, &uri);
        self.client().put(&uri, &inst).await?;
        self.kvm_sap_state(2).await?;
        self.kvm_state().await
    }

    /// Enables the KVM service only, leaving the VNC port as it is. Enough for
    /// KVM over the redirection port (`KvmSession::open_redirection`).
    pub async fn enable_kvm_service(&self) -> Result<KvmState> {
        self.kvm_sap_state(2).await?;
        self.kvm_state().await
    }

    /// Closes the VNC port and disables the KVM service.
    pub async fn disable_kvm(&self) -> Result<KvmState> {
        let uri = format!("{IPS}IPS_KVMRedirectionSettingData");
        let xml = self.client().get(&uri).await?;
        let inst = wsman::element(&xml, "IPS_KVMRedirectionSettingData")
            .ok_or(Error::MissingField("IPS_KVMRedirectionSettingData"))?;
        let inst = wsman::replace_field(&inst, "Is5900PortEnabled", "false");
        let inst = declare_prefix(&inst, &uri);
        self.client().put(&uri, &inst).await?;
        self.kvm_sap_state(3).await?;
        self.kvm_state().await
    }

    async fn kvm_sap_state(&self, requested: u32) -> Result<()> {
        let xml = self
            .client()
            .call(
                &format!("{CIM}CIM_KVMRedirectionSAP"),
                "RequestStateChange",
                &[],
                &format!("<p:RequestedState>{requested}</p:RequestedState>"),
            )
            .await?;
        match field_u32(&xml, "ReturnValue")? {
            0 => Ok(()),
            code => Err(Error::ReturnValue {
                method: "CIM_KVMRedirectionSAP.RequestStateChange",
                code,
                meaning: None,
            }),
        }
    }
}

pub(crate) fn check_rfb_password(p: &str) -> Result<()> {
    let ok = p.len() == 8
        && p.bytes().any(|b| b.is_ascii_uppercase())
        && p.bytes().any(|b| b.is_ascii_lowercase())
        && p.bytes().any(|b| b.is_ascii_digit())
        && p.bytes().any(|b| b.is_ascii_punctuation());
    if ok {
        Ok(())
    } else {
        Err(Error::InvalidArgument(
            "RFB password: exactly 8 characters with upper, lower, digit and a symbol".into(),
        ))
    }
}

/// The RFB pixel format in effect.
#[derive(Debug, Clone, Copy)]
struct PixelFormat {
    bpp: u8,
    big_endian: bool,
    true_colour: bool,
    max: [u16; 3],
    shift: [u8; 3],
}

impl PixelFormat {
    /// Parses the 16-byte RFB PIXEL_FORMAT. Refuses what RFB does not allow
    /// (bits per pixel other than 8, 16 or 32) and true-colour shifts that
    /// point past the pixel, which would otherwise overflow `v >> shift`.
    fn parse(b: &[u8]) -> Result<Self> {
        let f = Self {
            bpp: b[0],
            big_endian: b[2] != 0,
            true_colour: b[3] != 0,
            max: [
                u16::from_be_bytes([b[4], b[5]]),
                u16::from_be_bytes([b[6], b[7]]),
                u16::from_be_bytes([b[8], b[9]]),
            ],
            shift: [b[10], b[11], b[12]],
        };
        if !matches!(f.bpp, 8 | 16 | 32) {
            return Err(Error::Protocol(format!(
                "RFB pixel format with {} bits per pixel; only 8, 16 or 32 are valid",
                f.bpp
            )));
        }
        if f.true_colour && f.shift.iter().any(|&s| s >= f.bpp) {
            return Err(Error::Protocol(format!(
                "RFB pixel format shifts {:?} reach past a {}-bit pixel",
                f.shift, f.bpp
            )));
        }
        Ok(f)
    }

    fn bytes_per_pixel(&self) -> usize {
        (self.bpp as usize).div_ceil(8)
    }

    fn rgb(&self, px: &[u8], palette: &[[u8; 3]]) -> [u8; 3] {
        let v = match (px.len(), self.big_endian) {
            (1, _) => px[0] as u32,
            (2, false) => u16::from_le_bytes([px[0], px[1]]) as u32,
            (2, true) => u16::from_be_bytes([px[0], px[1]]) as u32,
            (4, false) => u32::from_le_bytes([px[0], px[1], px[2], px[3]]),
            (4, true) => u32::from_be_bytes([px[0], px[1], px[2], px[3]]),
            _ => 0,
        };
        if !self.true_colour {
            return palette.get(v as usize).copied().unwrap_or([0, 0, 0]);
        }
        let mut out = [0u8; 3];
        for ((o, &max), &shift) in out.iter_mut().zip(&self.max).zip(&self.shift) {
            let max = max.max(1) as u32;
            *o = (((v >> shift) & max) * 255 / max) as u8;
        }
        out
    }
}

/// An RFB connection to the device's screen.
pub struct KvmSession {
    stream: TcpStream,
    width: u16,
    height: u16,
    format: PixelFormat,
    palette: Vec<[u8; 3]>,
    zrle: Zrle,
    timeout: Duration,
}

/// How the RFB session authenticates.
enum Security<'a> {
    /// VNC authentication with the RFB password (port 5900).
    Vnc(&'a str),
    /// None: the redirection layer already authenticated the session.
    None,
}

impl KvmSession {
    /// KVM inside an AMT redirection session (port 16994, session "KVMR"),
    /// authenticated with the AMT account's digest credentials — the path
    /// Intel's own tools use. Needs no RFB password and no port 5900. In client
    /// control mode, user consent must be granted first.
    pub async fn open_redirection(ep: &Endpoint, port: u16, timeout: Duration) -> Result<Self> {
        let (mut rd, mut w) = redir::open(ep, port, redir::KVMR, timeout).await?;
        w.send(&[0x40, 0, 0, 0, 0, 0, 0, 0]).await?;
        let reply = tokio::time::timeout(timeout, read_exact(&mut rd, 8))
            .await
            .map_err(|_| Error::Timeout("KVM redirection start"))??;
        expect_type(&reply, 0x41)?;
        let stream = rd
            .reunite(w.half)
            .map_err(|_| Error::Protocol("KVM socket halves did not match".into()))?;
        Self::rfb(stream, Security::None, &ep.host, timeout).await
    }

    /// KVM on the standard VNC port, authenticated with the RFB password.
    pub async fn open(
        host: &str,
        port: u16,
        rfb_password: &str,
        timeout: Duration,
    ) -> Result<Self> {
        let s = tokio::time::timeout(timeout, TcpStream::connect((host, port)))
            .await
            .map_err(|_| Error::Timeout("connecting to the KVM port"))??;
        s.set_nodelay(true)?;
        Self::rfb(s, Security::Vnc(rfb_password), host, timeout).await
    }

    async fn rfb(
        mut s: TcpStream,
        security: Security<'_>,
        host: &str,
        timeout: Duration,
    ) -> Result<Self> {
        tokio::time::timeout(timeout, async {
            let mut ver = [0u8; 12];
            s.read_exact(&mut ver).await?;
            let (major, minor) = parse_rfb_version(&ver).ok_or_else(|| {
                Error::Protocol(format!("not an RFB server: {:?}", String::from_utf8_lossy(&ver)))
            })?;
            // AMT announces "RFB 004.000"; like common viewers, speak 3.8 to it.
            let use_minor = match (major, minor) {
                (3, m) if m >= 8 => 8,
                (3, 7) => 7,
                (3, _) => 3,
                _ => 8,
            };
            s.write_all(format!("RFB 003.{use_minor:03}\n").as_bytes()).await?;
            let want: u8 = match security {
                Security::Vnc(_) => 2,
                Security::None => 1,
            };
            if use_minor == 3 {
                let t = s.read_u32().await?;
                if t != want as u32 {
                    return Err(Error::Protocol(format!("RFB security type {t}, expected {want}")));
                }
            } else {
                let n = s.read_u8().await? as usize;
                if n == 0 {
                    return Err(Error::Protocol(read_reason(&mut s).await));
                }
                let mut types = vec![0u8; n];
                s.read_exact(&mut types).await?;
                if !types.contains(&want) {
                    return Err(Error::Protocol(format!(
                        "RFB security type {want} not offered: {types:?}"
                    )));
                }
                s.write_u8(want).await?;
            }
            if let Security::Vnc(password) = security {
                let mut challenge = [0u8; 16];
                s.read_exact(&mut challenge).await?;
                s.write_all(&vnc_response(password, &challenge)).await?;
            }
            // RFB 3.8 sends a SecurityResult for every type, None included.
            if (use_minor >= 8 || want == 2) && s.read_u32().await? != 0 {
                let reason = if use_minor >= 8 {
                    read_reason(&mut s).await
                } else {
                    "authentication failed".into()
                };
                return Err(Error::Protocol(format!(
                    "KVM login refused: {reason}. Check the credentials and that user consent is granted"
                )));
            }
            s.write_u8(1).await?; // ClientInit: shared
            Ok(())
        })
        .await
        .map_err(|_| Error::Timeout("RFB handshake"))??;

        let mut init = [0u8; 24];
        tokio::time::timeout(timeout, s.read_exact(&mut init))
            .await
            .map_err(|_| Error::Timeout("RFB ServerInit"))??;
        let width = u16::from_be_bytes([init[0], init[1]]);
        let height = u16::from_be_bytes([init[2], init[3]]);
        // Keep AMT's native pixel format (16-bit RGB565 on AMT 12): AMT does
        // not accept every SetPixelFormat a client might ask for.
        let format = PixelFormat::parse(&init[4..20])?;
        check_framebuffer(width as usize, height as usize, format.bytes_per_pixel())?;
        let name_len = u32::from_be_bytes([init[20], init[21], init[22], init[23]]) as usize;
        let mut name = vec![0u8; name_len.min(4096)];
        s.read_exact(&mut name).await?;
        // SetEncodings as Intel's own client sends them: ZRLE (AMT's "RLE"),
        // Raw (AMT refuses a list without it) and DesktopSize (-223). AMT ends
        // the session on the first update request if ZRLE is not offered.
        let mut enc = vec![2u8, 0, 0, 3];
        for e in [16i32, 0, -223] {
            enc.extend_from_slice(&e.to_be_bytes());
        }
        s.write_all(&enc).await?;
        tracing::info!(host, width, height, bpp = format.bpp, "KVM session open");
        Ok(Self {
            stream: s,
            width,
            height,
            format,
            palette: vec![[0, 0, 0]; 256],
            zrle: Zrle::new(),
            timeout,
        })
    }

    pub fn size(&self) -> (u16, u16) {
        (self.width, self.height)
    }

    /// A full-screen framebuffer, PNG-encoded.
    pub async fn screenshot(&mut self) -> Result<Vec<u8>> {
        // A DesktopSize rectangle mid-capture means the mode changed: start over
        // once at the new size.
        let (rgb, w, h) = match self.capture().await? {
            Some(frame) => frame,
            None => self
                .capture()
                .await?
                .ok_or_else(|| Error::Protocol("display size keeps changing".into()))?,
        };
        let mut png_bytes = Vec::new();
        {
            let mut enc = png::Encoder::new(&mut png_bytes, w as u32, h as u32);
            enc.set_color(png::ColorType::Rgb);
            enc.set_depth(png::BitDepth::Eight);
            let mut writer = enc
                .write_header()
                .map_err(|e| Error::Protocol(format!("PNG: {e}")))?;
            writer
                .write_image_data(&rgb)
                .map_err(|e| Error::Protocol(format!("PNG: {e}")))?;
        }
        Ok(png_bytes)
    }

    /// Reads the whole screen with one full, non-incremental request, as
    /// Intel's client does (AMT ends the session on partial-region requests).
    /// `None` if the size changed meanwhile.
    async fn capture(&mut self) -> Result<Option<(Vec<u8>, usize, usize)>> {
        let (w, h) = (self.width as usize, self.height as usize);
        let mut rgb = vec![0u8; w * h * 3];
        self.request(0, self.height).await?;
        let timeout = self.timeout;
        let resized =
            match tokio::time::timeout(timeout * 3, self.read_update(&mut rgb, w, h)).await {
                Err(_) => return Err(Error::Timeout("KVM framebuffer")),
                Ok(Err(Error::Io(e))) if e.kind() == std::io::ErrorKind::ConnectionReset => {
                    return Err(Error::Protocol(
                        "AMT reset the KVM connection on a framebuffer request".into(),
                    ));
                }
                Ok(r) => r?,
            };
        if resized {
            return Ok(None);
        }
        Ok(Some((rgb, w, h)))
    }

    async fn request(&mut self, y: u16, height: u16) -> Result<()> {
        let mut req = vec![3u8, 0, 0, 0];
        req.extend_from_slice(&y.to_be_bytes());
        req.extend_from_slice(&self.width.to_be_bytes());
        req.extend_from_slice(&height.to_be_bytes());
        self.stream.write_all(&req).await?;
        Ok(())
    }

    /// Reads server messages until one FramebufferUpdate has been applied.
    async fn read_update(&mut self, rgb: &mut [u8], w: usize, h: usize) -> Result<bool> {
        loop {
            match self.stream.read_u8().await? {
                0 => {
                    let mut hdr = [0u8; 3];
                    self.stream.read_exact(&mut hdr).await?;
                    let rects = u16::from_be_bytes([hdr[1], hdr[2]]);
                    let mut resized = false;
                    for _ in 0..rects {
                        resized |= self.read_rect(rgb, w, h).await?;
                    }
                    return Ok(resized);
                }
                1 => self.read_colour_map().await?,
                2 => {}
                3 => {
                    let mut hdr = [0u8; 7];
                    self.stream.read_exact(&mut hdr).await?;
                    let len = u32::from_be_bytes([hdr[3], hdr[4], hdr[5], hdr[6]]) as usize;
                    let mut skip = vec![0u8; len.min(1 << 20)];
                    self.stream.read_exact(&mut skip).await?;
                }
                other => return Err(Error::Protocol(format!("unexpected RFB message {other}"))),
            }
        }
    }

    /// Applies one rectangle; true if it was a DesktopSize change.
    async fn read_rect(&mut self, rgb: &mut [u8], w: usize, h: usize) -> Result<bool> {
        let mut r = [0u8; 12];
        self.stream.read_exact(&mut r).await?;
        let (x, y) = (
            u16::from_be_bytes([r[0], r[1]]) as usize,
            u16::from_be_bytes([r[2], r[3]]) as usize,
        );
        let (rw, rh) = (
            u16::from_be_bytes([r[4], r[5]]) as usize,
            u16::from_be_bytes([r[6], r[7]]) as usize,
        );
        let enc = i32::from_be_bytes([r[8], r[9], r[10], r[11]]);
        if enc == -223 {
            check_framebuffer(rw, rh, self.format.bytes_per_pixel())?;
            self.width = rw as u16;
            self.height = rh as u16;
            return Ok(true);
        }
        // Every rectangle lies inside the framebuffer, which bounds what it
        // can make us allocate and decode.
        if x + rw > w || y + rh > h {
            return Err(Error::Protocol(format!(
                "RFB rectangle {rw}x{rh} at ({x},{y}) lies outside the {w}x{h} framebuffer"
            )));
        }
        if enc == 16 {
            let len = self.stream.read_u32().await? as usize;
            if len > 64 << 20 {
                return Err(Error::Protocol(format!("ZRLE rectangle of {len} bytes")));
            }
            let mut packed = vec![0u8; len];
            self.stream.read_exact(&mut packed).await?;
            let tiles = self.zrle.inflate(&packed, zrle::max_tile_bytes(rw, rh))?;
            let (format, palette) = (self.format, &self.palette);
            zrle::decode_tiles(&tiles, rw, rh, |cx, cy, v| {
                let (px, py) = (x + cx, y + cy);
                if px < w && py < h {
                    let o = (py * w + px) * 3;
                    rgb[o..o + 3].copy_from_slice(&format.rgb(&v.to_le_bytes(), palette));
                }
            })?;
            return Ok(false);
        }
        if enc != 0 {
            return Err(Error::Protocol(format!("unrequested RFB encoding {enc}")));
        }
        let bpp = self.format.bytes_per_pixel();
        let mut data = vec![0u8; rw * rh * bpp];
        self.stream.read_exact(&mut data).await?;
        for row in 0..rh {
            for col in 0..rw {
                let (px, py) = (x + col, y + row);
                if px >= w || py >= h {
                    continue;
                }
                let i = (row * rw + col) * bpp;
                let c = self.format.rgb(&data[i..i + bpp], &self.palette);
                let o = (py * w + px) * 3;
                rgb[o..o + 3].copy_from_slice(&c);
            }
        }
        Ok(false)
    }

    async fn read_colour_map(&mut self) -> Result<()> {
        let mut hdr = [0u8; 5];
        self.stream.read_exact(&mut hdr).await?;
        let first = u16::from_be_bytes([hdr[1], hdr[2]]) as usize;
        let n = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
        let mut d = vec![0u8; n * 6];
        self.stream.read_exact(&mut d).await?;
        for i in 0..n {
            let c = &d[i * 6..i * 6 + 6];
            if let Some(slot) = self.palette.get_mut(first + i) {
                *slot = [c[0], c[2], c[4]];
            }
        }
        Ok(())
    }

    /// Presses and releases each key in turn.
    pub async fn keys(&mut self, keysyms: &[u32]) -> Result<()> {
        for &k in keysyms {
            for down in [1u8, 0] {
                let mut m = vec![4u8, down, 0, 0];
                m.extend_from_slice(&k.to_be_bytes());
                self.stream.write_all(&m).await?;
            }
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
        Ok(())
    }

    pub async fn close(mut self) {
        let _ = self.stream.shutdown().await;
    }
}

/// `RFB xxx.yyy\n` → (major, minor).
fn parse_rfb_version(v: &[u8; 12]) -> Option<(u32, u32)> {
    if !v.starts_with(b"RFB ") || v[7] != b'.' || v[11] != b'\n' {
        return None;
    }
    let major = std::str::from_utf8(&v[4..7]).ok()?.parse().ok()?;
    let minor = std::str::from_utf8(&v[8..11]).ok()?.parse().ok()?;
    Some((major, minor))
}

async fn read_reason(s: &mut TcpStream) -> String {
    let Ok(len) = s.read_u32().await else {
        return "connection refused".into();
    };
    let mut b = vec![0u8; (len as usize).min(1024)];
    if s.read_exact(&mut b).await.is_err() {
        return "connection refused".into();
    }
    String::from_utf8_lossy(&b).into_owned()
}

/// VNC authentication: DES-encrypt the challenge with the password (8 bytes,
/// zero-padded) as key, each key byte bit-reversed.
fn vnc_response(password: &str, challenge: &[u8; 16]) -> [u8; 16] {
    let mut key = [0u8; 8];
    for (k, b) in key.iter_mut().zip(password.bytes()) {
        *k = b.reverse_bits();
    }
    let cipher = des::Des::new(GenericArray::from_slice(&key));
    let mut out = *challenge;
    for block in out.chunks_mut(8) {
        cipher.encrypt_block(GenericArray::from_mut_slice(block));
    }
    out
}

/// Keysyms for text plus named keys written as `{enter}`, `{esc}`, `{f2}`,
/// `{up}`, `{down}`, `{left}`, `{right}`, `{tab}`, `{backspace}`, `{delete}`,
/// `{home}`, `{end}`, `{pgup}`, `{pgdn}`, `{f1}`…`{f12}`, `{space}`.
pub fn keysyms(text: &str) -> Result<Vec<u32>> {
    let mut out = Vec::new();
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '{' {
            let mut name = String::new();
            for n in chars.by_ref() {
                if n == '}' {
                    break;
                }
                name.push(n);
            }
            out.push(named_key(&name.to_ascii_lowercase())?);
        } else if c == '\n' {
            out.push(0xFF0D);
        } else if (' '..='~').contains(&c) {
            out.push(c as u32);
        } else {
            return Err(Error::InvalidArgument(format!(
                "cannot type {c:?}; use printable ASCII or {{named}} keys"
            )));
        }
    }
    Ok(out)
}

fn named_key(name: &str) -> Result<u32> {
    Ok(match name {
        "enter" | "return" => 0xFF0D,
        "esc" | "escape" => 0xFF1B,
        "tab" => 0xFF09,
        "backspace" => 0xFF08,
        "delete" | "del" => 0xFFFF,
        "home" => 0xFF50,
        "left" => 0xFF51,
        "up" => 0xFF52,
        "right" => 0xFF53,
        "down" => 0xFF54,
        "pgup" | "pageup" => 0xFF55,
        "pgdn" | "pagedown" => 0xFF56,
        "end" => 0xFF57,
        "space" => 0x0020,
        f if f.starts_with('f') && f.len() <= 3 => {
            let n: u32 = f[1..]
                .parse()
                .map_err(|_| Error::InvalidArgument(format!("unknown key {{{name}}}")))?;
            if !(1..=12).contains(&n) {
                return Err(Error::InvalidArgument(format!("unknown key {{{name}}}")));
            }
            0xFFBE + n - 1
        }
        _ => return Err(Error::InvalidArgument(format!("unknown key {{{name}}}"))),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A pixel format block for ServerInit: bpp, depth, big endian, true
    /// colour, maxima and shifts.
    fn pixel_format(bpp: u8, max: [u16; 3], shift: [u8; 3]) -> [u8; 16] {
        let mut f = [0u8; 16];
        f[0] = bpp;
        f[1] = bpp.min(24);
        f[3] = 1;
        for i in 0..3 {
            f[4 + 2 * i..6 + 2 * i].copy_from_slice(&max[i].to_be_bytes());
            f[10 + i] = shift[i];
        }
        f
    }

    const RGB565: ([u16; 3], [u8; 3]) = ([31, 63, 31], [11, 5, 0]);

    /// A fake RFB 3.8 server (security None) that sends ServerInit with
    /// `width` x `height` and `format`, then `after` once the client's first
    /// FramebufferUpdateRequest has arrived.
    async fn fake_rfb(
        width: u16,
        height: u16,
        format: [u8; 16],
        after: Vec<u8>,
    ) -> Result<KvmSession> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.expect("accept");
            s.write_all(b"RFB 003.008\n").await.unwrap();
            let mut buf = [0u8; 12];
            s.read_exact(&mut buf).await.unwrap();
            s.write_all(&[1, 1]).await.unwrap(); // one type: None
            s.read_u8().await.unwrap();
            s.write_u32(0).await.unwrap(); // SecurityResult OK
            s.read_u8().await.unwrap(); // ClientInit
            let mut init = Vec::new();
            init.extend_from_slice(&width.to_be_bytes());
            init.extend_from_slice(&height.to_be_bytes());
            init.extend_from_slice(&format);
            init.extend_from_slice(&0u32.to_be_bytes());
            if s.write_all(&init).await.is_err() {
                return;
            }
            // SetEncodings (4 + 3 x 4), then FramebufferUpdateRequest (10).
            let mut rest = [0u8; 16 + 10];
            if s.read_exact(&mut rest).await.is_err() {
                return;
            }
            let _ = s.write_all(&after).await;
            let mut sink = [0u8; 64];
            while matches!(s.read(&mut sink).await, Ok(n) if n > 0) {}
        });
        let s = TcpStream::connect(addr).await?;
        KvmSession::rfb(s, Security::None, "fake", Duration::from_secs(2)).await
    }

    /// A FramebufferUpdate with one rectangle header.
    fn update(x: u16, y: u16, w: u16, h: u16, enc: i32) -> Vec<u8> {
        let mut m = vec![0u8, 0, 0, 1];
        for v in [x, y, w, h] {
            m.extend_from_slice(&v.to_be_bytes());
        }
        m.extend_from_slice(&enc.to_be_bytes());
        m
    }

    #[tokio::test]
    async fn oversized_server_init_is_refused() {
        let (max, shift) = RGB565;
        let r = fake_rfb(u16::MAX, u16::MAX, pixel_format(16, max, shift), vec![]).await;
        let err = r.err().expect("a 65535x65535 framebuffer must be refused");
        assert!(err.to_string().contains("over the limit"), "{err}");
    }

    #[tokio::test]
    async fn raw_rectangle_outside_the_framebuffer_is_refused() {
        let (max, shift) = RGB565;
        let mut kvm = fake_rfb(
            4,
            4,
            pixel_format(16, max, shift),
            update(0, 0, u16::MAX, u16::MAX, 0),
        )
        .await
        .expect("open");
        let err = kvm.screenshot().await.expect_err("refused");
        assert!(err.to_string().contains("outside"), "{err}");
    }

    #[tokio::test]
    async fn zrle_rectangle_outside_the_framebuffer_is_refused() {
        let (max, shift) = RGB565;
        let mut after = update(2, 2, 4, 4, 16);
        after.extend_from_slice(&0u32.to_be_bytes());
        let mut kvm = fake_rfb(4, 4, pixel_format(16, max, shift), after)
            .await
            .expect("open");
        let err = kvm.screenshot().await.expect_err("refused");
        assert!(err.to_string().contains("outside"), "{err}");
    }

    #[tokio::test]
    async fn oversized_desktop_size_is_refused() {
        let (max, shift) = RGB565;
        let mut kvm = fake_rfb(
            4,
            4,
            pixel_format(16, max, shift),
            update(0, 0, u16::MAX, u16::MAX, -223),
        )
        .await
        .expect("open");
        let err = kvm.screenshot().await.expect_err("refused");
        assert!(err.to_string().contains("over the limit"), "{err}");
    }

    #[tokio::test]
    async fn pixel_shift_past_the_pixel_is_refused() {
        // A shift of 40 would panic in `v >> shift` on the first pixel.
        let mut after = update(0, 0, 1, 1, 0);
        after.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]);
        let r = fake_rfb(1, 1, pixel_format(32, [255; 3], [40, 8, 0]), after).await;
        let mut kvm = match r {
            Err(e) => {
                assert!(e.to_string().contains("pixel format"), "{e}");
                return;
            }
            Ok(kvm) => kvm,
        };
        let res = kvm.screenshot().await;
        panic!(
            "pixel format with shift 40 accepted: {:?}",
            res.map(|p| p.len())
        );
    }

    #[test]
    fn pixel_format_rules() {
        let (max, shift) = RGB565;
        assert!(PixelFormat::parse(&pixel_format(16, max, shift)).is_ok());
        assert!(PixelFormat::parse(&pixel_format(32, [255; 3], [16, 8, 0])).is_ok());
        assert!(PixelFormat::parse(&pixel_format(16, max, [16, 5, 0])).is_err());
        assert!(PixelFormat::parse(&pixel_format(32, [255; 3], [32, 8, 0])).is_err());
        assert!(PixelFormat::parse(&pixel_format(24, [255; 3], [16, 8, 0])).is_err());
        assert!(PixelFormat::parse(&pixel_format(0, max, shift)).is_err());
        // Palette formats carry no shifts to check.
        let mut indexed = pixel_format(8, [0; 3], [200, 200, 200]);
        indexed[3] = 0;
        assert!(PixelFormat::parse(&indexed).is_ok());
    }

    #[test]
    fn vnc_response_is_des_ecb() {
        // DES in ECB mode: equal challenge blocks give equal response blocks.
        let r = vnc_response("password", &[0u8; 16]);
        assert_eq!(&r[..8], &r[8..]);
        assert_ne!(r, [0u8; 16]);
    }

    #[test]
    fn keysyms_parse_text_and_names() {
        assert_eq!(keysyms("a{enter}").unwrap(), vec![0x61, 0xFF0D]);
        assert_eq!(keysyms("{F2}{down}").unwrap(), vec![0xFFBF, 0xFF54]);
        assert!(keysyms("{nope}").is_err());
        assert!(keysyms("é").is_err());
    }

    #[test]
    fn pixel_conversion_565() {
        let pf = PixelFormat {
            bpp: 16,
            big_endian: false,
            true_colour: true,
            max: [31, 63, 31],
            shift: [11, 5, 0],
        };
        assert_eq!(pf.rgb(&0xF800u16.to_le_bytes(), &[]), [255, 0, 0]);
        assert_eq!(pf.rgb(&0x07E0u16.to_le_bytes(), &[]), [0, 255, 0]);
    }

    #[test]
    fn rfb_versions() {
        assert_eq!(parse_rfb_version(b"RFB 004.000\n"), Some((4, 0)));
        assert_eq!(parse_rfb_version(b"RFB 003.008\n"), Some((3, 8)));
        assert_eq!(parse_rfb_version(b"HTTP/1.1 200"), None);
    }

    #[test]
    fn rfb_password_rules() {
        assert!(check_rfb_password("Ab1!Cd2@").is_ok());
        assert!(check_rfb_password("short1!A").is_ok());
        assert!(check_rfb_password("Ab1!Cd2").is_err());
        assert!(check_rfb_password("abcdefgh").is_err());
    }
}
