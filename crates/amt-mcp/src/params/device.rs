use amt::PowerAction;
use schemars::JsonSchema;
use serde::Deserialize;

#[derive(Debug, Deserialize, JsonSchema)]
pub struct PowerParams {
    #[schemars(
        description = "on: power on a machine that is off. off: immediate power off, the OS is not asked. cycle: power off then on. reset: hard reset without removing power. graceful_off / graceful_reset: ask the OS to shut down or restart cleanly (needs Intel's in-band agent in the OS)"
    )]
    pub action: PowerAction,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ConsentCodeParams {
    #[schemars(
        description = "The 6-digit code shown on the device's own display after consent_request"
    )]
    pub code: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct LogParams {
    #[schemars(description = "Return only the newest N records (default 50)")]
    pub limit: Option<usize>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct AddAlarmParams {
    #[schemars(description = "Alarm name: 1-32 letters, digits, '-' or '_'")]
    pub name: String,
    #[schemars(
        description = "First wake time, UTC ISO 8601 such as 2026-01-01T06:00:00Z, before 2038"
    )]
    pub start: String,
    #[schemars(
        description = "Repeat interval as an ISO 8601 duration (P1D daily, PT12H twice a day); omit for a one-off"
    )]
    pub interval: Option<String>,
    #[schemars(
        description = "Delete the alarm after it fires (default true; ignored by AMT for repeating alarms)"
    )]
    pub delete_on_completion: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct AlarmNameParams {
    #[schemars(description = "Alarm name as list_alarms reports it")]
    pub name: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct AddAccountParams {
    #[schemars(description = "Account name: 1-16 letters, digits, '-' or '_'")]
    pub user: String,
    #[schemars(
        description = "Path to a file on the MCP server's machine holding the new account's password (8-32 chars, upper, lower, digit, symbol). The password is never passed through the conversation"
    )]
    pub password_file: String,
    #[schemars(
        description = "Realms to grant. Omit for a read-only monitoring account (hardware_asset, general_info, event_log_reader)"
    )]
    pub realms: Option<Vec<amt::Realm>>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct AccountHandleParams {
    #[schemars(description = "Account handle as list_accounts reports it")]
    pub handle: u32,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct NextBootParams {
    #[schemars(
        description = "default (clear any override), bios_setup, pxe, hard_drive, cd_dvd, ider_cd, ider_floppy"
    )]
    pub target: amt::BootTarget,
    #[schemars(
        description = "Redirect the BIOS console to Serial-over-LAN for that boot (default false)"
    )]
    pub sol: Option<bool>,
}
