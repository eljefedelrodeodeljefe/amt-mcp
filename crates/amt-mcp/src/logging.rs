//! Diagnostics on stderr: the filter, and one line per write tool.

use std::fmt::Display;

use tracing::level_filters::LevelFilter;
use tracing_subscriber::EnvFilter;

/// The log filter: `rust_log` (RUST_LOG) if given, otherwise info, so the
/// write-tool lines below are on by default.
pub fn filter(rust_log: Option<&str>) -> EnvFilter {
    EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .parse_lossy(rust_log.unwrap_or_default())
}

/// One info line for a write tool: the tool, what was asked (never a
/// password, consent code or typed text) and how it ended.
pub fn write_tool<T, E: Display>(tool: &'static str, detail: &str, res: &Result<T, E>) {
    match res {
        Ok(_) => tracing::info!(tool, detail, outcome = "ok", "write tool"),
        Err(e) => tracing::info!(tool, detail, outcome = "error", error = %e, "write tool"),
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::sync::{Arc, Mutex};

    use super::*;

    #[derive(Clone, Default)]
    struct Captured(Arc<Mutex<Vec<u8>>>);

    impl Write for Captured {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn defaults_to_info() {
        assert_eq!(filter(None).max_level_hint(), Some(LevelFilter::INFO));
        assert_eq!(filter(Some("")).max_level_hint(), Some(LevelFilter::INFO));
        assert_eq!(
            filter(Some("debug")).max_level_hint(),
            Some(LevelFilter::DEBUG)
        );
    }

    #[test]
    fn write_tool_lines_show_at_the_default_level() {
        let out = Captured::default();
        let sink = out.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_env_filter(filter(None))
            .with_writer(move || sink.clone())
            .with_ansi(false)
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            write_tool("power", "reset", &Ok::<(), String>(()));
            write_tool("consent_submit", "", &Err::<(), _>("code rejected"));
        });
        let text = String::from_utf8(out.0.lock().unwrap().clone()).unwrap();
        assert!(
            text.contains("tool=\"power\"") || text.contains("tool=power"),
            "{text}"
        );
        assert!(
            text.contains("outcome=\"ok\"") || text.contains("outcome=ok"),
            "{text}"
        );
        assert!(text.contains("code rejected"), "{text}");
        assert_eq!(text.lines().count(), 2, "{text}");
    }
}
