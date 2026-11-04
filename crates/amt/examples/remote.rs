//! Live check of the consent-gated features, in two steps because the consent
//! code is only shown on the device's display:
//!
//!   remote request
//!   remote run <code> <rfb-password-file> <screenshot.png> <cd-image> <seconds>
//!   remote kvm <rfb-password-file> <screenshot.png>   (consent already granted)
//!   remote kvmr <screenshot.png> [code]             (KVM over the redirection port)
//!
//! `run` submits the code, sets and clears a PXE boot override, enables KVM and
//! saves a screenshot, then serves <cd-image> over IDE-R with start=now for
//! <seconds> so the running host can read it, and prints the session status.

use std::time::Duration;

use amt::{BootTarget, Client, Device, Endpoint, IderSession, IderStart, KvmSession};

fn secret(path: &str) -> Result<String, Box<dyn std::error::Error>> {
    Ok(std::fs::read_to_string(path)?
        .trim_end_matches(['\r', '\n'])
        .to_string())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let host = std::env::var("AMT_HOST")?;
    let ep = Endpoint::new(
        &host,
        "admin",
        secret(&std::env::var("AMT_PASSWORD_FILE")?)?,
    );
    let d = Device::new(Client::new(ep.clone())?);
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("request") => {
            d.consent_start().await?;
            println!("consent: {:?}", d.consent_state().await?);
        }
        Some("run") if args.len() == 6 => {
            d.consent_submit(&args[1]).await?;
            println!("consent: {:?}", d.consent_state().await?);

            match d.set_next_boot(BootTarget::Pxe, false).await {
                Ok(s) => println!("boot override pxe: {s:?}"),
                Err(e) => println!("boot override pxe: FAILED {e}"),
            }
            println!(
                "boot override cleared: {:?}",
                d.set_next_boot(BootTarget::Default, false).await?
            );

            let rfb = secret(&args[2])?;
            match d.enable_kvm(&rfb).await {
                Ok(k) => println!("kvm enabled: {k:?}"),
                Err(e) => println!("kvm enable: FAILED {e}"),
            }
            match KvmSession::open(&host, amt::kvm::VNC_PORT, &rfb, Duration::from_secs(20)).await {
                Ok(mut k) => {
                    println!("kvm session: {:?}", k.size());
                    match k.screenshot().await {
                        Ok(png) => {
                            std::fs::write(&args[3], &png)?;
                            println!("screenshot: {} bytes -> {}", png.len(), args[3]);
                        }
                        Err(e) => println!("screenshot: FAILED {e}"),
                    }
                    k.close().await;
                }
                Err(e) => println!("kvm session: FAILED {e}"),
            }

            match IderSession::open(
                &ep,
                amt::sol::DEFAULT_PORT,
                std::path::Path::new(&args[4]),
                IderStart::Now,
                Duration::from_secs(20),
            )
            .await
            {
                Ok(s) => {
                    let secs: u64 = args[5].parse()?;
                    for i in 0..secs {
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        if i % 5 == 4 {
                            println!("ider t+{}s: {:?}", i + 1, s.status().await);
                        }
                    }
                    println!("ider final: {:?}", s.status().await);
                    s.close().await;
                }
                Err(e) => println!("ider: FAILED {e}"),
            }
            println!("consent at end: {:?}", d.consent_state().await?);
        }
        Some("kvmr") if args.len() >= 2 => {
            if let Some(code) = args.get(2) {
                d.consent_submit(code).await?;
            }
            println!("consent: {:?}", d.consent_state().await?);
            let mut k =
                KvmSession::open_redirection(&ep, amt::sol::DEFAULT_PORT, Duration::from_secs(20))
                    .await?;
            println!("kvm (redirection) session: {:?}", k.size());
            let png = k.screenshot().await?;
            std::fs::write(&args[1], &png)?;
            println!(
                "screenshot: {} bytes -> {} at {:?}",
                png.len(),
                args[1],
                k.size()
            );
            k.close().await;
        }
        Some("kvm") if args.len() == 3 => {
            println!("consent: {:?}", d.consent_state().await?);
            let mut k = KvmSession::open(
                &host,
                amt::kvm::VNC_PORT,
                &secret(&args[1])?,
                Duration::from_secs(20),
            )
            .await?;
            println!("kvm session: {:?}", k.size());
            let png = k.screenshot().await?;
            std::fs::write(&args[2], &png)?;
            println!("screenshot: {} bytes -> {}", png.len(), args[2]);
            k.close().await;
        }
        _ => eprintln!(
            "usage: remote request | remote run <code> <rfb-file> <png> <cd-image> <seconds> | remote kvm <rfb-file> <png>"
        ),
    }
    Ok(())
}
