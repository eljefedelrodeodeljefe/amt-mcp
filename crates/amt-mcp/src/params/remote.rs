use schemars::JsonSchema;
use serde::Deserialize;

#[derive(Debug, Deserialize, JsonSchema)]
pub struct KvmEnableParams {
    #[schemars(
        description = "Path to a file on the MCP server's machine holding the RFB (VNC) password: exactly 8 characters with upper, lower, digit and a symbol. Never passed through the conversation"
    )]
    pub rfb_password_file: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct KvmKeysParams {
    #[schemars(
        description = "Text to type. Named keys in braces: {enter} {esc} {tab} {backspace} {delete} {up} {down} {left} {right} {home} {end} {pgup} {pgdn} {space} {f1}..{f12}"
    )]
    pub keys: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct IderStartParams {
    #[schemars(
        description = "Path to an ISO image on the MCP server's machine, served read-only as a CD-ROM"
    )]
    pub iso_path: String,
    #[schemars(
        description = "When the device switches to the IDE-R drive: on_reboot (default; pair with set_next_boot ider_cd and power reset), graceful, now"
    )]
    pub start: Option<amt::IderStart>,
}
