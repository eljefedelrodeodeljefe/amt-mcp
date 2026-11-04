use thiserror::Error;

/// Everything the `amt` library can fail with.
#[derive(Debug, Error)]
pub enum Error {
    #[error("HTTP transport to AMT failed: {0}")]
    Http(#[from] reqwest::Error),

    #[error("TCP connection to AMT failed: {0}")]
    Io(#[from] std::io::Error),

    #[error("AMT rejected the credentials (HTTP {status})")]
    Unauthorized { status: u16 },

    #[error("AMT answered HTTP {status} without a digest challenge")]
    NoChallenge { status: u16 },

    #[error("AMT returned HTTP {status}: {body}")]
    HttpStatus { status: u16, body: String },

    #[error("AMT returned a WS-Man fault: {0}")]
    Fault(String),

    #[error("AMT response is missing `{0}`")]
    MissingField(&'static str),

    #[error("AMT method {method} returned ReturnValue {code}{}", meaning.map(|m| format!(" ({m})")).unwrap_or_default())]
    ReturnValue {
        method: &'static str,
        code: u32,
        meaning: Option<&'static str>,
    },

    #[error("redirection protocol error: {0}")]
    Protocol(String),

    #[error("redirection session authentication failed (status {0})")]
    RedirectionAuth(u8),

    #[error("timed out waiting for AMT: {0}")]
    Timeout(&'static str),

    #[error("invalid argument: {0}")]
    InvalidArgument(String),
}

pub type Result<T> = std::result::Result<T, Error>;
