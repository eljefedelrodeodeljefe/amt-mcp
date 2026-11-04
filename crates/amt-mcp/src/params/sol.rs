use schemars::JsonSchema;
use serde::Deserialize;

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SolReadParams {
    #[schemars(
        description = "Milliseconds to wait for the first output if none is buffered (default 2000, max 30000)"
    )]
    pub wait_ms: Option<u64>,
    #[schemars(description = "Milliseconds of silence that end a burst of output (default 300)")]
    pub settle_ms: Option<u64>,
    #[schemars(description = "Remove ANSI escape sequences from the output (default true)")]
    pub strip_ansi: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SolSendParams {
    #[schemars(description = "Text to type on the serial console")]
    pub text: String,
    #[schemars(description = "Append a carriage return, i.e. press Enter (default true)")]
    pub enter: Option<bool>,
    #[schemars(
        description = "Interpret escapes in text: \\r, \\n, \\t, \\e (ESC), \\xNN. Use for arrow keys or Ctrl sequences, e.g. \\e[A is Up (default false)"
    )]
    pub escapes: Option<bool>,
}
