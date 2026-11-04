use amt::{Device, PowerAction};
use serde_json::{Value, json};

pub async fn status(dev: &Device) -> anyhow::Result<Value> {
    Ok(serde_json::to_value(dev.status().await?)?)
}

pub async fn power(dev: &Device, action: PowerAction) -> anyhow::Result<Value> {
    let before = dev.power_state().await?;
    tracing::info!(?action, ?before, "power action");
    dev.power(action).await?;
    Ok(json!({ "action": action, "accepted": true, "power_state_before": before }))
}

pub async fn consent_request(dev: &Device) -> anyhow::Result<Value> {
    dev.consent_start().await?;
    Ok(json!({
        "requested": true,
        "consent_state": dev.consent_state().await?,
        "next": "read the 6-digit code from the device's display and call consent_submit"
    }))
}

pub async fn consent_submit(dev: &Device, code: &str) -> anyhow::Result<Value> {
    dev.consent_submit(code).await?;
    Ok(json!({ "accepted": true, "consent_state": dev.consent_state().await? }))
}

pub async fn consent_cancel(dev: &Device) -> anyhow::Result<Value> {
    dev.consent_cancel().await?;
    Ok(json!({ "cancelled": true, "consent_state": dev.consent_state().await? }))
}

pub async fn enable_sol_listener(dev: &Device) -> anyhow::Result<Value> {
    Ok(serde_json::to_value(
        dev.enable_redirection_listener().await?,
    )?)
}
