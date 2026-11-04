//! Runs every read-only call against a live device and prints the results.
//! Nothing is changed on the device.

use amt::{Client, Device, Endpoint};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let host = std::env::var("AMT_HOST")?;
    let password = std::fs::read_to_string(std::env::var("AMT_PASSWORD_FILE")?)?
        .trim_end_matches(['\r', '\n'])
        .to_string();
    let d = Device::new(Client::new(Endpoint::new(host, "admin", password))?);
    macro_rules! show {
        ($name:literal, $e:expr) => {
            match $e.await {
                Ok(v) => println!("== {}\n{:#?}", $name, v),
                Err(e) => println!("== {} FAILED: {e}", $name),
            }
        };
    }
    show!("inventory", d.inventory());
    show!("general_settings", d.general_settings());
    show!("ethernet_ports", d.ethernet_ports());
    show!("clock", d.clock());
    show!("boot_capabilities", d.boot_capabilities());
    show!("boot_settings", d.boot_settings());
    show!("alarms", d.alarms());
    show!("accounts", d.accounts());
    show!("event_log", d.event_log());
    show!("audit_log", d.audit_log());
    Ok(())
}
