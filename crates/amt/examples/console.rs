//! Live SOL check. Two steps, because the consent code is only on the device's display:
//!
//!   console request          shows the code on the device
//!   console open <code>      submits it, opens SOL, presses Enter, prints the output
//!
//! AMT_HOST=<host> AMT_PASSWORD_FILE=<file> cargo run -p amt --example console -- request

use std::time::Duration;

use amt::{Client, Device, Endpoint, SolSession};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let host = std::env::var("AMT_HOST")?;
    let password = std::fs::read_to_string(std::env::var("AMT_PASSWORD_FILE")?)?
        .trim_end_matches(['\r', '\n'])
        .to_string();
    let ep = Endpoint::new(host, "admin", password);
    let dev = Device::new(Client::new(ep.clone())?);
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("request") => {
            dev.consent_start().await?;
            println!("consent state: {:?}", dev.consent_state().await?);
        }
        Some("open") => {
            if let Some(code) = args.get(1) {
                dev.consent_submit(code).await?;
            }
            println!("consent state: {:?}", dev.consent_state().await?);
            let sol =
                SolSession::open(&ep, amt::sol::DEFAULT_PORT, Duration::from_secs(20)).await?;
            println!("SOL open");
            sol.send(b"\r").await?;
            let out = sol
                .read(Duration::from_secs(5), Duration::from_millis(800))
                .await?;
            println!(
                "--- {} bytes ---\n{}",
                out.len(),
                String::from_utf8_lossy(&out)
            );
            sol.close().await;
        }
        _ => eprintln!("usage: console request | console open [code]"),
    }
    Ok(())
}
