//! ZRLE (RFB encoding 16), which AMT's KVM calls RLE: 64x64 tiles inside one
//! raw-deflate stream that lasts for the whole connection.

use flate2::{Decompress, FlushDecompress};

use crate::error::{Error, Result};

pub(crate) struct Zrle {
    /// Created on the first compressed rectangle, once its header tells
    /// whether the stream is zlib-wrapped or raw deflate.
    inflate: Option<Decompress>,
}

impl Zrle {
    pub fn new() -> Self {
        Self { inflate: None }
    }

    /// One rectangle's payload as its tile stream, at most `limit` bytes (see
    /// [`max_tile_bytes`]): more is refused rather than inflated, so a small
    /// payload cannot expand without bound. A rectangle may be a single
    /// uncompressed deflate block (`00`, LEN, NLEN, data), which AMT sends
    /// outside the compressed stream; MeshCommander takes those as they are.
    pub fn inflate(&mut self, data: &[u8], limit: usize) -> Result<Vec<u8>> {
        let too_large = || {
            Error::Protocol(format!(
                "ZRLE rectangle inflates past {limit} bytes, more than its tiles can hold"
            ))
        };
        if data.len() > 5 && data[0] == 0 {
            let len = u16::from_le_bytes([data[1], data[2]]) as usize;
            let nlen = u16::from_le_bytes([data[3], data[4]]);
            if len == data.len() - 5 && nlen == !(len as u16) {
                if len > limit {
                    return Err(too_large());
                }
                return Ok(data[5..].to_vec());
            }
        }
        let z = self.inflate.get_or_insert_with(|| {
            let zlib_header = data.len() >= 2
                && data[0] & 0x0F == 8
                && u16::from_be_bytes([data[0], data[1]]).is_multiple_of(31);
            Decompress::new(zlib_header)
        });
        let mut out = Vec::with_capacity((data.len() * 8 + 1024).min(limit + 1));
        let mut input = data;
        loop {
            if out.len() > limit {
                return Err(too_large());
            }
            if out.capacity() - out.len() < 64 * 1024 {
                // Exact, so capacity never runs more than one step past `limit`.
                out.reserve_exact((256 * 1024).min(limit + 1 - out.len()));
            }
            let (in0, out0) = (z.total_in(), z.total_out());
            z.decompress_vec(input, &mut out, FlushDecompress::Sync)
                .map_err(|e| {
                    Error::Protocol(format!(
                        "ZRLE inflate: {e} (rect of {} bytes starting {:02x?})",
                        data.len(),
                        &data[..data.len().min(8)]
                    ))
                })?;
            let used = (z.total_in() - in0) as usize;
            let produced = z.total_out() - out0;
            input = &input[used..];
            if out.len() > limit {
                return Err(too_large());
            }
            if input.is_empty() && out.capacity() > out.len() {
                return Ok(out);
            }
            if used == 0 && produced == 0 {
                return Ok(out);
            }
        }
    }
}

/// The most tile-stream bytes a `w` x `h` rectangle of 16-bit pixels can need:
/// three bytes a pixel (plain RLE with every run of one), plus each 64x64
/// tile's subencoding byte and a palette of up to 127 colours.
pub(crate) fn max_tile_bytes(w: usize, h: usize) -> usize {
    let tiles = w.div_ceil(64) * h.div_ceil(64);
    w * h * 3 + tiles * (1 + 127 * 2)
}

/// Decodes a ZRLE tile stream for a `w` x `h` rectangle of 16-bit pixels,
/// calling `put(x, y, pixel)` for each pixel (coordinates within the rect).
pub(crate) fn decode_tiles(
    data: &[u8],
    w: usize,
    h: usize,
    mut put: impl FnMut(usize, usize, u16),
) -> Result<()> {
    let mut p = 0usize;
    let short = || Error::Protocol("ZRLE tile data ended early".into());
    let byte = |p: &mut usize| -> Result<u8> {
        let b = *data.get(*p).ok_or_else(short)?;
        *p += 1;
        Ok(b)
    };
    let pixel = |p: &mut usize| -> Result<u16> {
        let b = data.get(*p..*p + 2).ok_or_else(short)?;
        *p += 2;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    };
    let run = |p: &mut usize| -> Result<usize> {
        let mut len = 1usize;
        loop {
            let b = byte(p)?;
            len += b as usize;
            if b != 255 {
                return Ok(len);
            }
        }
    };

    for ty in (0..h).step_by(64) {
        for tx in (0..w).step_by(64) {
            let (tw, th) = ((w - tx).min(64), (h - ty).min(64));
            let n = tw * th;
            let mut set = |i: usize, v: u16| put(tx + i % tw, ty + i / tw, v);
            let sub = byte(&mut p)?;
            match sub {
                0 => {
                    for i in 0..n {
                        let v = pixel(&mut p)?;
                        set(i, v);
                    }
                }
                1 => {
                    let v = pixel(&mut p)?;
                    for i in 0..n {
                        set(i, v);
                    }
                }
                2..=16 => {
                    let palette: Vec<u16> =
                        (0..sub).map(|_| pixel(&mut p)).collect::<Result<_>>()?;
                    let bits = match sub {
                        2 => 1,
                        3..=4 => 2,
                        _ => 4,
                    };
                    for row in 0..th {
                        let mut acc = 0u8;
                        let mut left = 0;
                        for col in 0..tw {
                            if left == 0 {
                                acc = byte(&mut p)?;
                                left = 8;
                            }
                            left -= bits;
                            let idx = ((acc >> left) & ((1 << bits) - 1)) as usize;
                            let v = *palette.get(idx).ok_or_else(short)?;
                            set(row * tw + col, v);
                        }
                    }
                }
                128 => {
                    let mut i = 0;
                    while i < n {
                        let v = pixel(&mut p)?;
                        let len = run(&mut p)?;
                        for _ in 0..len.min(n - i) {
                            set(i, v);
                            i += 1;
                        }
                    }
                }
                130..=255 => {
                    let palette: Vec<u16> = (0..sub - 128)
                        .map(|_| pixel(&mut p))
                        .collect::<Result<_>>()?;
                    let mut i = 0;
                    while i < n {
                        let b = byte(&mut p)?;
                        let v = *palette.get((b & 0x7F) as usize).ok_or_else(short)?;
                        let len = if b & 0x80 != 0 { run(&mut p)? } else { 1 };
                        for _ in 0..len.min(n - i) {
                            set(i, v);
                            i += 1;
                        }
                    }
                }
                other => {
                    return Err(Error::Protocol(format!(
                        "ZRLE subencoding {other} is reserved"
                    )));
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{Compress, Compression, FlushCompress};

    fn render(data: &[u8], w: usize, h: usize) -> Vec<u16> {
        let mut out = vec![0u16; w * h];
        decode_tiles(data, w, h, |x, y, v| out[y * w + x] = v).unwrap();
        out
    }

    #[test]
    fn solid_raw_palette_and_rle_tiles() {
        // 2x2 solid
        assert_eq!(render(&[1, 0x34, 0x12], 2, 2), vec![0x1234; 4]);
        // 2x1 raw
        assert_eq!(render(&[0, 1, 0, 2, 0], 2, 1), vec![1, 2]);
        // 4x1 packed palette of 2 (1 bit/pixel): pattern 1,0,1,1 = 0b1011_0000
        assert_eq!(
            render(&[2, 0xAA, 0x00, 0xBB, 0x00, 0b1011_0000], 4, 1),
            vec![0xBB, 0xAA, 0xBB, 0xBB]
        );
        // plain RLE: 3x1 of one pixel, run length byte 2 => 3
        assert_eq!(render(&[128, 0x05, 0x00, 2], 3, 1), vec![5, 5, 5]);
        // palette RLE with 2 colours: index 0 once, index 1 run of 2
        assert_eq!(render(&[130, 7, 0, 9, 0, 0, 0x81, 1], 3, 1), vec![7, 9, 9]);
        assert!(decode_tiles(&[0, 1], 2, 1, |_, _, _| {}).is_err());
    }

    #[test]
    fn multiple_tiles_cover_the_rect() {
        // 65x1: two tiles (64 + 1), both solid.
        let out = render(&[1, 1, 0, 1, 2, 0], 65, 1);
        assert!(out[..64].iter().all(|&v| v == 1));
        assert_eq!(out[64], 2);
    }

    #[test]
    fn stored_block_is_taken_as_is() {
        let mut z = Zrle::new();
        let payload = [1u8, 2, 3];
        let mut block = vec![0, 3, 0, 0xFC, 0xFF];
        block.extend_from_slice(&payload);
        assert_eq!(z.inflate(&block, 1024).unwrap(), payload);
    }

    #[test]
    fn zlib_wrapped_stream_is_detected() {
        let mut c = Compress::new(Compression::default(), true);
        let mut z = Zrle::new();
        let mut buf = Vec::with_capacity(256);
        c.compress_vec(b"zlib wrapped tiles", &mut buf, FlushCompress::Sync)
            .unwrap();
        assert_eq!(z.inflate(&buf, 1024).unwrap(), b"zlib wrapped tiles");
    }

    #[test]
    fn decompression_bomb_is_refused() {
        // 64 MiB of zeros deflate to a few tens of kilobytes.
        let mut c = Compress::new(Compression::best(), false);
        let zeros = vec![0u8; 64 << 20];
        let mut buf = Vec::with_capacity(1 << 20);
        c.compress_vec(&zeros, &mut buf, FlushCompress::Sync)
            .unwrap();
        assert!(buf.len() < 1 << 20);
        let limit = max_tile_bytes(64, 64);
        let err = Zrle::new().inflate(&buf, limit).expect_err("refused");
        assert!(err.to_string().contains("inflates past"), "{err}");
    }

    #[test]
    fn stored_block_over_the_limit_is_refused() {
        let mut block = vec![0, 3, 0, 0xFC, 0xFF];
        block.extend_from_slice(&[1, 2, 3]);
        assert!(Zrle::new().inflate(&block, 2).is_err());
    }

    #[test]
    fn output_exactly_at_the_limit_is_accepted() {
        let mut c = Compress::new(Compression::default(), false);
        let mut buf = Vec::with_capacity(256);
        c.compress_vec(b"12345678", &mut buf, FlushCompress::Sync)
            .unwrap();
        assert_eq!(Zrle::new().inflate(&buf, 8).unwrap(), b"12345678");
    }

    #[test]
    fn inflate_keeps_the_stream_across_rects() {
        let mut c = Compress::new(Compression::default(), false);
        let mut z = Zrle::new();
        for chunk in [b"first tile data".as_slice(), b"second, same stream"] {
            let mut buf = Vec::with_capacity(256);
            c.compress_vec(chunk, &mut buf, FlushCompress::Sync)
                .unwrap();
            assert_eq!(z.inflate(&buf, 1024).unwrap(), chunk);
        }
    }
}
