//! Environment parsing. Strict: a value that is not understood is a startup
//! error naming the variable, never a silent default.

use amt::Secret;
use anyhow::Context;

/// Parses a boolean setting: `true`/`false`, `1`/`0`, `yes`/`no`, any case.
pub fn parse_bool(name: &str, value: &str) -> anyhow::Result<bool> {
    match value.to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" => Ok(true),
        "false" | "0" | "no" => Ok(false),
        _ => anyhow::bail!("{name} must be true or false (also 1/0, yes/no), not {value:?}"),
    }
}

/// A boolean environment variable, `default` when it is not set.
pub fn bool_env(name: &str, default: bool) -> anyhow::Result<bool> {
    match std::env::var(name) {
        Ok(v) => parse_bool(name, &v),
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(std::env::VarError::NotUnicode(_)) => anyhow::bail!("{name} is not valid UTF-8"),
    }
}

/// A password from a file, without its trailing newline, held as a
/// [`Secret`] from the moment it is read.
pub fn read_secret(path: &str, what: &str) -> anyhow::Result<Secret> {
    let mut s = std::fs::read_to_string(path).with_context(|| format!("reading {what} {path}"))?;
    let len = s.trim_end_matches(['\r', '\n']).len();
    s.truncate(len);
    Ok(Secret::from(s))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_file_loses_its_newline_and_hides_in_debug() {
        let path = std::env::temp_dir().join(format!("amt-mcp-secret-{}", std::process::id()));
        std::fs::write(&path, "hunter2!X\r\n").unwrap();
        let s = read_secret(path.to_str().unwrap(), "test").unwrap();
        std::fs::remove_file(&path).unwrap();
        assert_eq!(s.expose(), "hunter2!X");
        assert_eq!(format!("{s:?}"), "***");
    }

    #[test]
    fn booleans_in_any_case() {
        for v in ["true", "TRUE", "True", "1", "yes", "YES"] {
            assert!(parse_bool("AMT_ALLOW_WRITES", v).unwrap(), "{v}");
        }
        for v in ["false", "FALSE", "0", "no", "No"] {
            assert!(!parse_bool("AMT_ALLOW_WRITES", v).unwrap(), "{v}");
        }
    }

    #[test]
    fn anything_else_is_an_error_naming_the_variable() {
        for v in ["on", "off", "y", "enabled", "", " true", "2"] {
            let err = parse_bool("AMT_ALLOW_WRITES", v).expect_err(v);
            assert!(err.to_string().contains("AMT_ALLOW_WRITES"), "{err}");
        }
    }
}
