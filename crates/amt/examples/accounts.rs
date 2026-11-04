//! Account check: adds a read-only account (unless it exists), then shows what
//! it can and cannot do.
//!
//! AMT_HOST=… AMT_PASSWORD_FILE=<admin> AMT_NEW_USER=… AMT_NEW_PASSWORD_FILE=… \
//!   cargo run -p amt --example accounts

use amt::{Client, Device, Endpoint, READ_ONLY_REALMS};

fn read(var: &str) -> Result<String, Box<dyn std::error::Error>> {
    Ok(std::fs::read_to_string(std::env::var(var)?)?
        .trim_end_matches(['\r', '\n'])
        .to_string())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let host = std::env::var("AMT_HOST")?;
    let user = std::env::var("AMT_NEW_USER")?;
    let admin = Device::new(Client::new(Endpoint::new(
        &host,
        "admin",
        read("AMT_PASSWORD_FILE")?,
    ))?);
    if !admin.accounts().await?.iter().any(|a| a.user == user) {
        let h = admin
            .add_account(&user, &read("AMT_NEW_PASSWORD_FILE")?, &READ_ONLY_REALMS)
            .await?;
        println!("added {user} with handle {h}");
    }
    println!("accounts: {:?}", admin.accounts().await?);

    let ro = Device::new(Client::new(Endpoint::new(
        &host,
        &user,
        read("AMT_NEW_PASSWORD_FILE")?,
    ))?);
    println!(
        "as {user}: inventory -> {}",
        ro.inventory()
            .await
            .map(|i| format!("ok, bios {:?}", i.bios.version))
            .unwrap_or_else(|e| format!("refused: {e}"))
    );
    println!(
        "as {user}: event_log -> {}",
        ro.event_log()
            .await
            .map(|l| format!("ok, {} records", l.len()))
            .unwrap_or_else(|e| format!("refused: {e}"))
    );
    println!(
        "as {user}: power_state -> {}",
        ro.power_state()
            .await
            .map(|p| format!("ok, {p:?}"))
            .unwrap_or_else(|e| format!("refused: {e}"))
    );
    println!(
        "as {user}: audit_log -> {}",
        ro.audit_log()
            .await
            .map(|l| format!("ok, {} records", l.len()))
            .unwrap_or_else(|e| format!("refused: {e}"))
    );
    println!(
        "as {user}: sync_clock (a write) -> {}",
        ro.sync_clock()
            .await
            .map(|c| format!("ALLOWED, {c:?}"))
            .unwrap_or_else(|e| format!("refused: {e}"))
    );
    println!(
        "as {user}: consent_state -> {}",
        ro.consent_state()
            .await
            .map(|c| format!("ok, {c:?}"))
            .unwrap_or_else(|e| format!("refused: {e}"))
    );
    Ok(())
}
