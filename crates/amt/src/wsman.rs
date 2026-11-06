//! WS-Management over HTTP digest on port 16992 — the request/response half of
//! Intel AMT. Envelopes are built as strings and responses read with
//! [`field`]: AMT's XML is flat enough that a full XML stack buys nothing.

use std::sync::Mutex;
use std::time::Duration;

use regex::Regex;
use reqwest::StatusCode;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, WWW_AUTHENTICATE};

use crate::digest::Challenge;
use crate::error::{Error, Result};

pub const DEFAULT_PORT: u16 = 16992;
const PATH: &str = "/wsman";

/// Resource URI prefixes, as the AMT SDK spells them.
pub const CIM: &str = "http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/";
pub const AMT: &str = "http://intel.com/wbem/wscim/1/amt-schema/1/";
pub const IPS: &str = "http://intel.com/wbem/wscim/1/ips-schema/1/";

const ACTION_GET: &str = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Get";
const ACTION_PUT: &str = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Put";

/// Where and how to reach one AMT device.
#[derive(Debug, Clone)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub password: String,
    pub timeout: Duration,
    /// Accept redirection authentication type 1, which sends the password in
    /// clear over TCP 16994, when the device offers nothing better. Off by
    /// default: anyone on the path can strip digest from the offer to force it.
    pub allow_plaintext_auth: bool,
}

impl Endpoint {
    pub fn new(
        host: impl Into<String>,
        user: impl Into<String>,
        password: impl Into<String>,
    ) -> Self {
        Self {
            host: host.into(),
            port: DEFAULT_PORT,
            user: user.into(),
            password: password.into(),
            timeout: Duration::from_secs(15),
            allow_plaintext_auth: false,
        }
    }
}

/// Whether a WS-Man call changes the device, which decides whether it may be
/// resent after a transport error ([`Client::send`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Call {
    /// Reads only (Get, Enumerate, Pull, read-only methods): safe to resend.
    Read,
    /// Changes state (Put, Delete, most methods): resent only if the request
    /// certainly never left this machine.
    Write,
}

/// A WS-Man client for one device. Cheap to share: requests are independent.
pub struct Client {
    ep: Endpoint,
    http: reqwest::Client,
    /// The last digest challenge, reused until AMT rejects it (nonces stay valid
    /// for a while), saving the 401 round trip on most calls.
    challenge: Mutex<Option<Challenge>>,
    /// One request in flight per device: AMT's embedded web server handles very
    /// few concurrent connections and drops the rest.
    gate: tokio::sync::Mutex<()>,
}

impl Client {
    pub fn new(ep: Endpoint) -> Result<Self> {
        let http = reqwest::Client::builder().timeout(ep.timeout).build()?;
        Ok(Self {
            ep,
            http,
            challenge: Mutex::new(None),
            gate: tokio::sync::Mutex::new(()),
        })
    }

    pub fn endpoint(&self) -> &Endpoint {
        &self.ep
    }

    fn url(&self) -> String {
        format!("http://{}:{}{PATH}", self.ep.host, self.ep.port)
    }

    /// Sends one envelope and returns the response body, answering the digest
    /// challenge if AMT asks for one.
    ///
    /// `kind` decides whether a transport failure may be answered by sending
    /// again. A request that failed to connect never left and is always
    /// resent once. Any later failure (reset, connection closed before the
    /// response, timeout) may come after AMT executed the request, so only a
    /// [`Call::Read`] is resent then. reqwest files both under
    /// `is_request()`; only `is_connect()` proves nothing was sent. An idle
    /// keep-alive that AMT closed before the request was written is retried
    /// by hyper's pool on its own.
    pub async fn send(&self, envelope: &str, kind: Call) -> Result<String> {
        let _turn = self.gate.lock().await;
        match self.exchange(envelope).await {
            Err(Error::Http(e)) if e.is_connect() || (kind == Call::Read && e.is_request()) => {
                tracing::debug!(error = %e, ?kind, "retrying WS-Man request");
                self.exchange(envelope).await
            }
            other => other,
        }
    }

    async fn exchange(&self, envelope: &str) -> Result<String> {
        let cached = self.challenge.lock().expect("challenge lock").clone();
        if let Some(ch) = cached {
            let resp = self.post(envelope, Some(&ch)).await?;
            if resp.status() != StatusCode::UNAUTHORIZED {
                return Self::body(resp).await;
            }
            // Stale nonce: fall through and take the fresh challenge.
            let fresh = Self::challenge_of(&resp)?;
            *self.challenge.lock().expect("challenge lock") = Some(fresh.clone());
            return Self::body(self.post(envelope, Some(&fresh)).await?).await;
        }
        let first = self.post(envelope, None).await?;
        if first.status() != StatusCode::UNAUTHORIZED {
            return Self::body(first).await;
        }
        let ch = Self::challenge_of(&first)?;
        *self.challenge.lock().expect("challenge lock") = Some(ch.clone());
        Self::body(self.post(envelope, Some(&ch)).await?).await
    }

    async fn post(&self, envelope: &str, ch: Option<&Challenge>) -> Result<reqwest::Response> {
        let mut req = self
            .http
            .post(self.url())
            .header(CONTENT_TYPE, "application/soap+xml;charset=UTF-8")
            .body(envelope.to_string());
        if let Some(ch) = ch {
            req = req.header(
                AUTHORIZATION,
                ch.authorization(&self.ep.user, &self.ep.password, "POST", PATH),
            );
        }
        Ok(req.send().await?)
    }

    fn challenge_of(resp: &reqwest::Response) -> Result<Challenge> {
        let status = resp.status().as_u16();
        resp.headers()
            .get_all(WWW_AUTHENTICATE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .find_map(Challenge::parse)
            .ok_or(Error::NoChallenge { status })
    }

    async fn body(resp: reqwest::Response) -> Result<String> {
        let status = resp.status();
        let text = resp.text().await?;
        if status == StatusCode::UNAUTHORIZED {
            return Err(Error::Unauthorized {
                status: status.as_u16(),
            });
        }
        if let Some(reason) = fault_reason(&text) {
            return Err(Error::Fault(reason));
        }
        if !status.is_success() {
            return Err(Error::HttpStatus {
                status: status.as_u16(),
                body: text.chars().take(300).collect(),
            });
        }
        Ok(text)
    }

    /// `Get` on a singleton resource.
    pub async fn get(&self, resource_uri: &str) -> Result<String> {
        self.send(&envelope(ACTION_GET, resource_uri, "", ""), Call::Read)
            .await
    }

    /// `Put` of a whole instance. `instance_xml` is the body element, which must
    /// declare its own namespace prefix.
    pub async fn put(&self, resource_uri: &str, instance_xml: &str) -> Result<String> {
        self.send(
            &envelope(ACTION_PUT, resource_uri, "", instance_xml),
            Call::Write,
        )
        .await
    }

    /// Invokes `method` on `resource_uri` (action `{resource_uri}/{method}`).
    /// `selectors` is a pre-built `<w:SelectorSet>` or empty, `input` the
    /// contents of `<p:{method}_INPUT>`. Treated as a [`Call::Write`]: use
    /// [`Client::invoke_read`] for methods that only read.
    pub async fn invoke(
        &self,
        resource_uri: &str,
        method: &str,
        selectors: &str,
        input: &str,
    ) -> Result<String> {
        self.invoke_as(resource_uri, method, selectors, input, Call::Write)
            .await
    }

    /// [`Client::invoke`] for a method that only reads (`GetRecords`,
    /// `GetLowAccuracyTimeSynch`), which may be resent after a dropped
    /// connection.
    pub async fn invoke_read(
        &self,
        resource_uri: &str,
        method: &str,
        selectors: &str,
        input: &str,
    ) -> Result<String> {
        self.invoke_as(resource_uri, method, selectors, input, Call::Read)
            .await
    }

    async fn invoke_as(
        &self,
        resource_uri: &str,
        method: &str,
        selectors: &str,
        input: &str,
        kind: Call,
    ) -> Result<String> {
        let body =
            format!("<p:{method}_INPUT xmlns:p=\"{resource_uri}\">{input}</p:{method}_INPUT>");
        self.send(
            &envelope(
                &format!("{resource_uri}/{method}"),
                resource_uri,
                selectors,
                &body,
            ),
            kind,
        )
        .await
    }

    /// Enumerates every instance of `resource_uri` (WS-Enumeration with
    /// optimized enumeration, then `Pull` until end of sequence) and returns
    /// each instance element, tags included.
    pub async fn enumerate(&self, resource_uri: &str) -> Result<Vec<String>> {
        let class = resource_uri.rsplit('/').next().unwrap_or(resource_uri);
        let body = format!(
            "<n:Enumerate xmlns:n=\"{ENUMERATION}\"><w:OptimizeEnumeration/>\
<w:MaxElements>{MAX_ELEMENTS}</w:MaxElements></n:Enumerate>"
        );
        let mut xml = self
            .send(
                &envelope(&format!("{ENUMERATION}/Enumerate"), resource_uri, "", &body),
                Call::Read,
            )
            .await?;
        let mut out = Vec::new();
        // A safety bound: AMT's largest tables (event log) hold a few hundred.
        for _ in 0..64 {
            out.extend(elements(&xml, class));
            if xml.contains("EndOfSequence") {
                return Ok(out);
            }
            let Some(ctx) = field(&xml, "EnumerationContext") else {
                return Ok(out);
            };
            let body = format!(
                "<n:Pull xmlns:n=\"{ENUMERATION}\"><n:EnumerationContext>{ctx}</n:EnumerationContext>\
<n:MaxElements>{MAX_ELEMENTS}</n:MaxElements></n:Pull>"
            );
            xml = self
                .send(
                    &envelope(&format!("{ENUMERATION}/Pull"), resource_uri, "", &body),
                    Call::Read,
                )
                .await?;
        }
        Ok(out)
    }
}

impl Client {
    /// `Get` on one instance of a multi-instance class.
    pub async fn get_with(&self, resource_uri: &str, selectors: &[(&str, &str)]) -> Result<String> {
        self.send(
            &envelope(ACTION_GET, resource_uri, &selector_set(selectors), ""),
            Call::Read,
        )
        .await
    }

    /// `Delete` of one instance.
    pub async fn delete(&self, resource_uri: &str, selectors: &[(&str, &str)]) -> Result<String> {
        self.send(
            &envelope(ACTION_DELETE, resource_uri, &selector_set(selectors), ""),
            Call::Write,
        )
        .await
    }

    /// `Put` of one instance of a multi-instance class.
    pub async fn put_with(
        &self,
        resource_uri: &str,
        selectors: &[(&str, &str)],
        instance_xml: &str,
    ) -> Result<String> {
        self.send(
            &envelope(
                ACTION_PUT,
                resource_uri,
                &selector_set(selectors),
                instance_xml,
            ),
            Call::Write,
        )
        .await
    }

    /// [`Client::invoke`] with selectors given as pairs (a [`Call::Write`]).
    pub async fn call(
        &self,
        resource_uri: &str,
        method: &str,
        selectors: &[(&str, &str)],
        input: &str,
    ) -> Result<String> {
        self.invoke(resource_uri, method, &selector_set(selectors), input)
            .await
    }

    /// [`Client::invoke_read`] with selectors given as pairs.
    pub async fn call_read(
        &self,
        resource_uri: &str,
        method: &str,
        selectors: &[(&str, &str)],
        input: &str,
    ) -> Result<String> {
        self.invoke_read(resource_uri, method, &selector_set(selectors), input)
            .await
    }
}

const ACTION_DELETE: &str = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete";

/// A `<w:SelectorSet>`, or nothing for no selectors.
pub fn selector_set(selectors: &[(&str, &str)]) -> String {
    if selectors.is_empty() {
        return String::new();
    }
    let inner: String = selectors
        .iter()
        .map(|(k, v)| format!("<w:Selector Name=\"{k}\">{}</w:Selector>", escape(v)))
        .collect();
    format!("<w:SelectorSet>{inner}</w:SelectorSet>")
}

/// An endpoint reference to an instance, as method parameters take them. The
/// caller wraps it in the parameter element (`<p:Source>…</p:Source>`).
pub fn reference(resource_uri: &str, selectors: &[(&str, &str)]) -> String {
    format!(
        "<a:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address>\
<a:ReferenceParameters><w:ResourceURI>{resource_uri}</w:ResourceURI>{}</a:ReferenceParameters>",
        selector_set(selectors)
    )
}

/// XML-escapes text for a parameter value.
pub fn xml_text(s: &str) -> String {
    escape(s)
}

const ENUMERATION: &str = "http://schemas.xmlsoap.org/ws/2004/09/enumeration";
const MAX_ELEMENTS: u32 = 100;

/// Every element called `name` (prefix-agnostic), tags included.
pub fn elements(xml: &str, name: &str) -> Vec<String> {
    let re = Regex::new(&format!(
        r"(?s)<((?:[\w-]+:)?{n})(?:\s[^>]*)?>.*?</(?:[\w-]+:)?{n}>",
        n = regex::escape(name)
    ))
    .expect("elements regex");
    re.find_iter(xml).map(|m| m.as_str().to_string()).collect()
}

/// The texts of every element called `name` (prefix-agnostic).
pub fn fields(xml: &str, name: &str) -> Vec<String> {
    let re = Regex::new(&format!(
        r"<(?:[\w-]+:)?{}(?:\s[^>]*)?>([^<]*)</",
        regex::escape(name)
    ))
    .expect("fields regex");
    re.captures_iter(xml).map(|c| unescape(&c[1])).collect()
}

/// A SOAP envelope for AMT.
pub fn envelope(action: &str, resource_uri: &str, selectors: &str, body: &str) -> String {
    let id: u32 = rand::random();
    format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\
<Envelope xmlns=\"http://www.w3.org/2003/05/soap-envelope\" \
xmlns:a=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" \
xmlns:w=\"http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd\">\
<Header><a:Action>{action}</a:Action><a:To>/wsman</a:To>\
<w:ResourceURI>{resource_uri}</w:ResourceURI><a:MessageID>{id}</a:MessageID>\
<a:ReplyTo><a:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address></a:ReplyTo>\
<w:OperationTimeout>PT60S</w:OperationTimeout>{selectors}</Header><Body>{body}</Body></Envelope>"
    )
}

/// A `<w:SelectorSet>` with one `Name` selector.
pub fn name_selector(name: &str) -> String {
    format!(
        "<w:SelectorSet><w:Selector Name=\"Name\">{}</w:Selector></w:SelectorSet>",
        escape(name)
    )
}

/// The text of the first element called `name`, whatever its namespace prefix.
pub fn field(xml: &str, name: &str) -> Option<String> {
    let re = Regex::new(&format!(
        r"<(?:[\w-]+:)?{}(?:\s[^>]*)?>([^<]*)</",
        regex::escape(name)
    ))
    .expect("field regex");
    re.captures(xml).map(|c| unescape(&c[1]))
}

/// The whole first element called `name` (prefix-agnostic), tags included.
pub fn element(xml: &str, name: &str) -> Option<String> {
    let re = Regex::new(&format!(
        r"(?s)<((?:[\w-]+:)?{n})(?:\s[^>]*)?>.*?</(?:[\w-]+:)?{n}>",
        n = regex::escape(name)
    ))
    .expect("element regex");
    re.find(xml).map(|m| m.as_str().to_string())
}

/// `field` parsed as a number.
pub fn field_u32(xml: &str, name: &'static str) -> Result<u32> {
    field(xml, name)
        .ok_or(Error::MissingField(name))?
        .trim()
        .parse()
        .map_err(|_| Error::MissingField(name))
}

/// Replaces the text of the first `name` element inside `xml`.
pub fn replace_field(xml: &str, name: &str, value: &str) -> String {
    let re = Regex::new(&format!(
        r"(<(?:[\w-]+:)?{}(?:\s[^>]*)?>)[^<]*(</)",
        regex::escape(name)
    ))
    .expect("replace regex");
    re.replace(xml, |c: &regex::Captures| {
        format!("{}{}{}", &c[1], escape(value), &c[2])
    })
    .into_owned()
}

fn fault_reason(xml: &str) -> Option<String> {
    if !xml.contains(":Fault>") && !xml.contains("<Fault>") {
        return None;
    }
    let text = field(xml, "Text").unwrap_or_default();
    let sub = field(xml, "Value").unwrap_or_default();
    Some(format!("{text} {sub}").trim().to_string())
}

fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn unescape(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

#[cfg(test)]
mod tests {
    use super::*;

    const REDIR: &str = r#"<a:Body><g:AMT_RedirectionService><g:CreationClassName>AMT_RedirectionService</g:CreationClassName><g:EnabledState>32771</g:EnabledState><g:ListenerEnabled>false</g:ListenerEnabled></g:AMT_RedirectionService></a:Body>"#;

    #[test]
    fn reads_fields_with_any_prefix() {
        assert_eq!(field(REDIR, "EnabledState").as_deref(), Some("32771"));
        assert_eq!(field(REDIR, "ListenerEnabled").as_deref(), Some("false"));
        assert_eq!(field_u32(REDIR, "EnabledState").unwrap(), 32771);
        assert!(field(REDIR, "Nope").is_none());
    }

    #[test]
    fn does_not_match_prefix_of_longer_name() {
        let xml = "<g:EnabledStateX>1</g:EnabledStateX><g:EnabledState>2</g:EnabledState>";
        assert_eq!(field(xml, "EnabledState").as_deref(), Some("2"));
    }

    #[test]
    fn extracts_and_edits_instance() {
        let inst = element(REDIR, "AMT_RedirectionService").unwrap();
        assert!(inst.starts_with("<g:AMT_RedirectionService>"));
        assert!(inst.ends_with("</g:AMT_RedirectionService>"));
        let edited = replace_field(&inst, "ListenerEnabled", "true");
        assert_eq!(field(&edited, "ListenerEnabled").as_deref(), Some("true"));
        assert_eq!(field(&edited, "EnabledState").as_deref(), Some("32771"));
    }

    #[test]
    fn detects_fault() {
        let xml = r#"<a:Body><a:Fault><a:Code><a:Value>a:Sender</a:Value></a:Code><a:Reason><a:Text xml:lang="en-US">The specified resource is not supported.</a:Text></a:Reason></a:Fault></a:Body>"#;
        assert_eq!(
            fault_reason(xml).as_deref(),
            Some("The specified resource is not supported. a:Sender")
        );
        assert!(fault_reason(REDIR).is_none());
    }

    #[test]
    fn envelope_carries_action_and_resource() {
        let e = envelope(ACTION_GET, "urn:x", "", "");
        assert!(
            e.contains("<a:Action>http://schemas.xmlsoap.org/ws/2004/09/transfer/Get</a:Action>")
        );
        assert!(e.contains("<w:ResourceURI>urn:x</w:ResourceURI>"));
    }
}
