//! A password held in memory: never shown by `Debug`, zeroed on drop.

use std::fmt;

use zeroize::Zeroize;

/// A password or other credential. `Debug` prints `***`; the bytes are
/// zeroed when it is dropped. Read it with [`Secret::expose`] at the one
/// place it is sent.
#[derive(Clone, Default)]
pub struct Secret(String);

impl Secret {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    /// The secret itself, for the code that sends it.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl From<String> for Secret {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for Secret {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("***")
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_is_redacted() {
        let s = Secret::from("hunter2!X");
        assert_eq!(format!("{s:?}"), "***");
        assert_eq!(format!("{:?}", Some(s.clone())), "Some(***)");
        assert_eq!(s.expose(), "hunter2!X");
    }
}
