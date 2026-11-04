use schemars::JsonSchema;
use serde::Deserialize;

#[derive(Debug, Deserialize, JsonSchema)]
pub struct KvmEnableParams {
    #[schemars(
        description = "Only for the VNC transport (port 5900): path to a file on the MCP server's machine holding the RFB password, exactly 8 characters with upper, lower, digit and a symbol. Omit to enable just the KVM service, which is all the default redirection transport needs"
    )]
    pub rfb_password_file: Option<String>,
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
