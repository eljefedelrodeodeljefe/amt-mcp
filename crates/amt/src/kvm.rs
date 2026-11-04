//! KVM through AMT's standard VNC port (5900): enable it over WS-Man with an
//! RFB password, then speak plain RFB to take screenshots and send keys. This
//! sees what the display shows, including BIOS setup and boot loaders.
//!
//! Only the Raw encoding is requested, so a full-screen update is large but
//! needs no decoder; frames are converted from 16-bit RGB565 to PNG.
//!
//! Known limit: on AMT 12 with a 3840x2160 display, login and ServerInit
//! succeed but AMT resets the connection on the first framebuffer request,
//! even for a small region. AMT's KVM capture has a maximum resolution; use a
//! lower display/console resolution (e.g. the `video=` kernel parameter).

use std::time::Duration;

use des::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};
use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::device::{Device, declare_prefix};
use crate::error::{Error, Result};
use crate::wsman::{self, CIM, IPS, field_u32};

pub const VNC_PORT: u16 = 5900;

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
    fn parse(b: &[u8]) -> Self {
        Self {
            bpp: b[0],
            big_endian: b[2] != 0,
            true_colour: b[3] != 0,
            max: [
                u16::from_be_bytes([b[4], b[5]]),
                u16::from_be_bytes([b[6], b[7]]),
                u16::from_be_bytes([b[8], b[9]]),
            ],
            shift: [b[10], b[11], b[12]],
        }
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
    timeout: Duration,
}

impl KvmSession {
    /// Connects to 5900 and authenticates with the RFB password. In client
    /// control mode, user consent must be granted first.
    pub async fn open(
        host: &str,
        port: u16,
        rfb_password: &str,
        timeout: Duration,
    ) -> Result<Self> {
        let mut s = tokio::time::timeout(timeout, TcpStream::connect((host, port)))
            .await
            .map_err(|_| Error::Timeout("connecting to the KVM port"))??;
        s.set_nodelay(true)?;
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

            if use_minor == 3 {
                let t = s.read_u32().await?;
                if t != 2 {
                    return Err(Error::Protocol(format!("RFB security type {t}, expected VNC auth")));
                }
            } else {
                let n = s.read_u8().await? as usize;
                if n == 0 {
                    return Err(Error::Protocol(read_reason(&mut s).await));
                }
                let mut types = vec![0u8; n];
                s.read_exact(&mut types).await?;
                if !types.contains(&2) {
                    return Err(Error::Protocol(format!("no VNC authentication offered: {types:?}")));
                }
                s.write_u8(2).await?;
            }
            let mut challenge = [0u8; 16];
            s.read_exact(&mut challenge).await?;
            s.write_all(&vnc_response(rfb_password, &challenge)).await?;
            if s.read_u32().await? != 0 {
                let reason = if use_minor >= 8 {
                    read_reason(&mut s).await
                } else {
                    "authentication failed".into()
                };
                return Err(Error::Protocol(format!(
                    "KVM login refused: {reason}. Check the RFB password and that user consent is granted"
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
        let native = PixelFormat::parse(&init[4..20]);
        let name_len = u32::from_be_bytes([init[20], init[21], init[22], init[23]]) as usize;
        let mut name = vec![0u8; name_len.min(4096)];
        s.read_exact(&mut name).await?;
        // SetPixelFormat: 16-bit RGB565 little-endian, the depth AMT's KVM
        // serves reliably (MeshCommander uses the same).
        let format = PixelFormat {
            bpp: 16,
            big_endian: false,
            true_colour: true,
            max: [31, 63, 31],
            shift: [11, 5, 0],
        };
        let mut spf = vec![0u8, 0, 0, 0, 16, 16, 0, 1];
        for m in format.max {
            spf.extend_from_slice(&m.to_be_bytes());
        }
        spf.extend_from_slice(&[11, 5, 0, 0, 0, 0]);
        s.write_all(&spf).await?;
        // SetEncodings: Raw only.
        s.write_all(&[2, 0, 0, 1, 0, 0, 0, 0]).await?;
        tracing::info!(
            host,
            width,
            height,
            native_bpp = native.bpp,
            "KVM session open"
        );
        Ok(Self {
            stream: s,
            width,
            height,
            format,
            palette: vec![[0, 0, 0]; 256],
            timeout,
        })
    }

    pub fn size(&self) -> (u16, u16) {
        (self.width, self.height)
    }

    /// A full-screen framebuffer, PNG-encoded. Requested in horizontal bands
    /// so no single update is larger than a few megabytes.
    pub async fn screenshot(&mut self) -> Result<Vec<u8>> {
        let (w, h) = (self.width as usize, self.height as usize);
        let mut rgb = vec![0u8; w * h * 3];
        let band = (2_000_000 / (w.max(1) * 2)).clamp(16, h.max(16)) as u16;
        let mut y = 0u16;
        while y < self.height {
            let bh = band.min(self.height - y);
            self.request(y, bh).await?;
            let timeout = self.timeout;
            match tokio::time::timeout(timeout * 2, self.read_update(&mut rgb, w, h)).await {
                Err(_) => return Err(Error::Timeout("KVM framebuffer")),
                Ok(Err(Error::Io(e))) if e.kind() == std::io::ErrorKind::ConnectionReset => {
                    let (w, h) = (self.width, self.height);
                    return Err(Error::Protocol(format!(
                        "AMT reset the KVM connection on a framebuffer request ({w}x{h}). {}",
                        "AMT's KVM capture has a resolution limit; try a lower display resolution"
                    )));
                }
                Ok(r) => r?,
            }
            y += bh;
        }
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

    async fn request(&mut self, y: u16, height: u16) -> Result<()> {
        let mut req = vec![3u8, 0, 0, 0];
        req.extend_from_slice(&y.to_be_bytes());
        req.extend_from_slice(&self.width.to_be_bytes());
        req.extend_from_slice(&height.to_be_bytes());
        self.stream.write_all(&req).await?;
        Ok(())
    }

    /// Reads server messages until one FramebufferUpdate has been applied.
    async fn read_update(&mut self, rgb: &mut [u8], w: usize, h: usize) -> Result<()> {
        loop {
            match self.stream.read_u8().await? {
                0 => {
                    let mut hdr = [0u8; 3];
                    self.stream.read_exact(&mut hdr).await?;
                    let rects = u16::from_be_bytes([hdr[1], hdr[2]]);
                    for _ in 0..rects {
                        self.read_rect(rgb, w, h).await?;
                    }
                    return Ok(());
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

    async fn read_rect(&mut self, rgb: &mut [u8], w: usize, h: usize) -> Result<()> {
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
        Ok(())
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
