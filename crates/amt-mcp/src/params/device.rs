use amt::PowerAction;
use schemars::JsonSchema;
use serde::Deserialize;

#[derive(Debug, Deserialize, JsonSchema)]
pub struct PowerParams {
    #[schemars(
        description = "on: power on a machine that is off. off: immediate power off, the OS is not asked. cycle: power off then on. reset: hard reset without removing power"
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
