//! Environment parsing. Strict: a value that is not understood is a startup
//! error naming the variable, never a silent default.

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

#[cfg(test)]
mod tests {
    use super::*;

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
