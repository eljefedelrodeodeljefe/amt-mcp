//! HTTP digest authentication (RFC 7616 with MD5, `qop=auth`), as Intel AMT
//! speaks it on 16992. Also used by the redirection protocol, which carries the
//! same digest inside its own binary frames.

use md5::{Digest, Md5};

pub(crate) fn md5_hex(input: &str) -> String {
    hex::encode(Md5::digest(input.as_bytes()))
}

/// A fresh 32-hex-digit client nonce.
pub(crate) fn cnonce() -> String {
    hex::encode(rand::random::<[u8; 16]>())
}

/// Inputs to one digest computation.
pub(crate) struct DigestInput<'a> {
    pub user: &'a str,
    pub realm: &'a str,
    pub password: &'a str,
    pub method: &'a str,
    pub uri: &'a str,
    pub nonce: &'a str,
    pub nc: &'a str,
    pub cnonce: &'a str,
    pub qop: &'a str,
}

impl DigestInput<'_> {
    /// The digest `response` value for `qop=auth`.
    pub fn response(&self) -> String {
        let ha1 = md5_hex(&format!("{}:{}:{}", self.user, self.realm, self.password));
        let ha2 = md5_hex(&format!("{}:{}", self.method, self.uri));
        md5_hex(&format!(
            "{ha1}:{}:{}:{}:{}:{ha2}",
            self.nonce, self.nc, self.cnonce, self.qop
        ))
    }
}

/// A parsed `WWW-Authenticate: Digest …` challenge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Challenge {
    pub realm: String,
    pub nonce: String,
    pub qop: Option<String>,
    pub opaque: Option<String>,
}

impl Challenge {
    pub fn parse(header: &str) -> Option<Self> {
        let rest = header.trim().strip_prefix("Digest")?.trim();
        let mut realm = None;
        let mut nonce = None;
        let mut qop = None;
        let mut opaque = None;
        for part in split_params(rest) {
            let Some((k, v)) = part.split_once('=') else {
                continue;
            };
            let v = v.trim().trim_matches('"').to_string();
            match k.trim().to_ascii_lowercase().as_str() {
                "realm" => realm = Some(v),
                "nonce" => nonce = Some(v),
                "qop" => qop = Some(v),
                "opaque" => opaque = Some(v),
                _ => {}
            }
        }
        Some(Self {
            realm: realm?,
            nonce: nonce?,
            qop,
            opaque,
        })
    }

    /// The `Authorization` header answering this challenge.
    pub fn authorization(&self, user: &str, password: &str, method: &str, uri: &str) -> String {
        let cnonce = cnonce();
        let nc = "00000001";
        // AMT offers "auth" or "auth,auth-int"; only "auth" is implemented.
        let qop = "auth";
        let resp = DigestInput {
            user,
            realm: &self.realm,
            password,
            method,
            uri,
            nonce: &self.nonce,
            nc,
            cnonce: &cnonce,
            qop,
        }
        .response();
        let realm = &self.realm;
        let nonce = &self.nonce;
        let mut h = format!(
            "Digest username=\"{user}\", realm=\"{realm}\", nonce=\"{nonce}\", uri=\"{uri}\", "
        );
        h.push_str(&format!(
            "response=\"{resp}\", qop={qop}, nc={nc}, cnonce=\"{cnonce}\""
        ));
        if let Some(o) = &self.opaque {
            h.push_str(&format!(", opaque=\"{o}\""));
        }
        h
    }
}

/// Splits `a="x, y", b=z` at the commas outside quotes.
fn split_params(s: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut quoted = false;
    for (i, c) in s.char_indices() {
        match c {
            '"' => quoted = !quoted,
            ',' if !quoted => {
                out.push(&s[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    out.push(&s[start..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_amt_challenge() {
        let c = Challenge::parse(
            r#"Digest realm="Digest:A3829B3827DE4D33D4449B366831FD01", nonce="Xa3e8F8AAAAAAAAAAAAAAAA==",stale="false",qop="auth""#,
        )
        .unwrap();
        assert_eq!(c.realm, "Digest:A3829B3827DE4D33D4449B366831FD01");
        assert_eq!(c.nonce, "Xa3e8F8AAAAAAAAAAAAAAAA==");
        assert_eq!(c.qop.as_deref(), Some("auth"));
        assert_eq!(c.opaque, None);
    }

    #[test]
    fn rfc2617_example() {
        // RFC 2617 section 3.5.
        let r = DigestInput {
            user: "Mufasa",
            realm: "testrealm@host.com",
            password: "Circle Of Life",
            method: "GET",
            uri: "/dir/index.html",
            nonce: "dcd98b7102dd2f0e8b11d0f600bfb0c093",
            nc: "00000001",
            cnonce: "0a4f113b",
            qop: "auth",
        }
        .response();
        assert_eq!(r, "6629fae49393a05397450978507c4ef1");
    }

    #[test]
    fn rejects_basic() {
        assert!(Challenge::parse(r#"Basic realm="x""#).is_none());
    }
}
