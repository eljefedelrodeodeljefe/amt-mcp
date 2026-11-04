//! Read-only probe of a live AMT device: prints `Device::status()` as JSON.
//!
//! AMT_HOST=<host> AMT_PASSWORD_FILE=<file> cargo run -p amt --example probe

use amt::{Client, Device, Endpoint};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let host = std::env::var("AMT_HOST")?;
    let user = std::env::var("AMT_USER").unwrap_or_else(|_| "admin".into());
    let password = std::fs::read_to_string(std::env::var("AMT_PASSWORD_FILE")?)?
        .trim_end_matches(['\r', '\n'])
        .to_string();
    let dev = Device::new(Client::new(Endpoint::new(host, user, password))?);
    let status = dev.status().await?;
    println!("{status:#?}");
    Ok(())
}
