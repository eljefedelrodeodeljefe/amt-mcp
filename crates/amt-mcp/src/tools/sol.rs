use std::time::Duration;

use amt::SolSession;
use serde_json::{Value, json};

use crate::params::{SolReadParams, SolSendParams};

pub async fn read(sol: &SolSession, p: &SolReadParams) -> anyhow::Result<Value> {
    let wait = Duration::from_millis(p.wait_ms.unwrap_or(2000).min(30_000));
    let settle = Duration::from_millis(p.settle_ms.unwrap_or(300).min(5_000));
    let bytes = sol.read(wait, settle).await?;
    let text = String::from_utf8_lossy(&bytes);
    let text = if p.strip_ansi.unwrap_or(true) {
        strip_ansi(&text)
    } else {
        text.into_owned()
    };
    Ok(json!({ "bytes": bytes.len(), "output": text }))
}

pub async fn send(sol: &SolSession, p: &SolSendParams) -> anyhow::Result<Value> {
    let mut data = if p.escapes.unwrap_or(false) {
        unescape(&p.text)?
    } else {
        p.text.as_bytes().to_vec()
    };
    if p.enter.unwrap_or(true) {
        data.push(b'\r');
    }
    sol.send(&data).await?;
    Ok(json!({ "sent_bytes": data.len() }))
}

/// Removes CSI (`ESC [ … final`), OSC (`ESC ] … BEL/ST`) and two-byte escapes,
/// plus carriage returns and other C0 controls except newline and tab.
pub fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut it = s.chars().peekable();
    while let Some(c) = it.next() {
        match c {
            '\u{1b}' => match it.next() {
                Some('[') => {
                    for c in it.by_ref() {
                        if ('@'..='~').contains(&c) {
                            break;
                        }
                    }
                }
                Some(']') => {
                    while let Some(c) = it.next() {
                        if c == '\u{07}' {
                            break;
                        }
                        if c == '\u{1b}' && it.peek() == Some(&'\\') {
                            it.next();
                            break;
                        }
                    }
                }
                _ => {}
            },
            '\n' | '\t' => out.push(c),
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    out
}

fn unescape(s: &str) -> anyhow::Result<Vec<u8>> {
    let mut out = Vec::new();
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' && i + 1 < b.len() {
            i += 1;
            match b[i] {
                b'r' => out.push(b'\r'),
                b'n' => out.push(b'\n'),
                b't' => out.push(b'\t'),
                b'e' => out.push(0x1b),
                b'\\' => out.push(b'\\'),
                b'x' => {
                    let hex = s
                        .get(i + 1..i + 3)
                        .ok_or_else(|| anyhow::anyhow!("\\x needs two hex digits"))?;
                    out.push(u8::from_str_radix(hex, 16)?);
                    i += 2;
                }
                other => anyhow::bail!("unknown escape \\{}", other as char),
            }
        } else {
            out.push(b[i]);
        }
        i += 1;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_terminal_noise() {
        let raw = "\u{1b}[2J\u{1b}[1;1HUbuntu 26.04\r\nlogin: \u{1b}]0;title\u{07}";
        assert_eq!(strip_ansi(raw), "Ubuntu 26.04\nlogin: ");
    }

    #[test]
    fn unescapes_keys() {
        assert_eq!(
            unescape(r"\e[A\x03\\").unwrap(),
            vec![0x1b, b'[', b'A', 3, b'\\']
        );
        assert!(unescape(r"\q").is_err());
        assert!(unescape(r"\x4").is_err());
    }
}
