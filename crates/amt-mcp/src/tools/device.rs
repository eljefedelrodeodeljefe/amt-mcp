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

pub async fn inventory(dev: &Device) -> anyhow::Result<Value> {
    Ok(serde_json::to_value(dev.inventory().await?)?)
}

pub async fn network(dev: &Device) -> anyhow::Result<Value> {
    Ok(json!({
        "general": dev.general_settings().await?,
        "ports": dev.ethernet_ports().await?,
    }))
}

pub async fn clock(dev: &Device) -> anyhow::Result<Value> {
    Ok(serde_json::to_value(dev.clock().await?)?)
}

pub async fn sync_clock(dev: &Device) -> anyhow::Result<Value> {
    Ok(serde_json::to_value(dev.sync_clock().await?)?)
}

fn newest<T: serde::Serialize>(mut v: Vec<T>, limit: Option<usize>) -> anyhow::Result<Value> {
    let total = v.len();
    let keep = limit.unwrap_or(50);
    if v.len() > keep {
        v.drain(..v.len() - keep);
    }
    Ok(json!({ "total": total, "records": v }))
}

pub async fn event_log(dev: &Device, limit: Option<usize>) -> anyhow::Result<Value> {
    newest(dev.event_log().await?, limit)
}

pub async fn audit_log(dev: &Device, limit: Option<usize>) -> anyhow::Result<Value> {
    newest(dev.audit_log().await?, limit)
}

pub async fn alarms(dev: &Device) -> anyhow::Result<Value> {
    Ok(json!({ "alarms": dev.alarms().await? }))
}

pub async fn add_alarm(dev: &Device, p: &crate::params::AddAlarmParams) -> anyhow::Result<Value> {
    dev.add_alarm(
        &p.name,
        &p.start,
        p.interval.as_deref(),
        p.delete_on_completion.unwrap_or(true),
    )
    .await?;
    alarms(dev).await
}

pub async fn delete_alarm(dev: &Device, name: &str) -> anyhow::Result<Value> {
    dev.delete_alarm(name).await?;
    alarms(dev).await
}

pub async fn accounts(dev: &Device) -> anyhow::Result<Value> {
    Ok(json!({ "accounts": dev.accounts().await? }))
}

pub async fn add_account(
    dev: &Device,
    p: &crate::params::AddAccountParams,
) -> anyhow::Result<Value> {
    let password = crate::config::read_secret(&p.password_file, "password_file")?;
    let realms = p
        .realms
        .clone()
        .unwrap_or_else(|| amt::READ_ONLY_REALMS.to_vec());
    let handle = dev.add_account(&p.user, password.expose(), &realms).await?;
    Ok(json!({ "handle": handle, "user": p.user, "realms": realms }))
}

pub async fn remove_account(dev: &Device, handle: u32) -> anyhow::Result<Value> {
    dev.remove_account(handle).await?;
    accounts(dev).await
}

pub async fn boot_options(dev: &Device) -> anyhow::Result<Value> {
    Ok(json!({
        "capabilities": dev.boot_capabilities().await?,
        "next_boot": dev.boot_settings().await?,
    }))
}

pub async fn set_next_boot(
    dev: &Device,
    p: &crate::params::NextBootParams,
) -> anyhow::Result<Value> {
    match dev.set_next_boot(p.target, p.sol.unwrap_or(false)).await {
        Ok(s) => Ok(json!({ "next_boot": s, "next": "use power (on, reset or cycle) to boot it" })),
        Err(amt::Error::Fault(f)) if f.contains("not authorized") => Err(anyhow::anyhow!(
            "AMT refused the boot override ({f}). In client control mode with consent policy 'all', forced boot sources need user consent: consent_request, consent_submit, then retry"
        )),
        Err(e) => Err(e.into()),
    }
}
