//! Non-disruptive write checks against a live device. Each step is undone:
//! the clock is synced, a far-future alarm is added and deleted, and a boot
//! override is set and cleared again without any power action.

use amt::{BootTarget, Client, Device, Endpoint};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let host = std::env::var("AMT_HOST")?;
    let password = std::fs::read_to_string(std::env::var("AMT_PASSWORD_FILE")?)?
        .trim_end_matches(['\r', '\n'])
        .to_string();
    let d = Device::new(Client::new(Endpoint::new(host, "admin", password))?);

    for leftover in ["t1", "t2"] {
        let _ = d.delete_alarm(leftover).await;
    }
    println!("sync_clock: {:?}", d.sync_clock().await?);

    d.add_alarm("writes-check", "2030-01-01T00:00:00Z", Some("P1D"), true)
        .await?;
    println!("alarms after add: {:?}", d.alarms().await?);
    d.delete_alarm("writes-check").await?;
    println!("alarms after delete: {:?}", d.alarms().await?);

    for (target, sol) in [
        (BootTarget::Default, false),
        (BootTarget::Pxe, false),
        (BootTarget::HardDrive, false),
        (BootTarget::BiosSetup, false),
        (BootTarget::BiosSetup, true),
    ] {
        match d.set_next_boot(target, sol).await {
            Ok(s) => println!("set {target:?} sol={sol}: {s:?}"),
            Err(e) => println!("set {target:?} sol={sol}: FAILED {e}"),
        }
    }
    println!(
        "cleared: {:?}",
        d.set_next_boot(BootTarget::Default, false).await?
    );
    println!("consent: {:?}", d.consent_state().await?);
    Ok(())
}
