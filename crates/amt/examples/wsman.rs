//! Raw WS-Man reads against a live device, for checking a class before a tool uses it.
//!
//!   wsman get <resource-uri>
//!   wsman enum <resource-uri>
//!   wsman call <resource-uri> <method> <selector-name>=<value> <input-xml>
//!
//! Short class names are expanded: `CIM_Processor`, `AMT_MessageLog`, `IPS_OptInService`.

use amt::{Client, Endpoint, wsman};

fn uri(class: &str) -> String {
    if class.contains("://") {
        return class.to_string();
    }
    let base = match class.split('_').next() {
        Some("CIM") => wsman::CIM,
        Some("AMT") => wsman::AMT,
        _ => wsman::IPS,
    };
    format!("{base}{class}")
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let host = std::env::var("AMT_HOST")?;
    let password = std::fs::read_to_string(std::env::var("AMT_PASSWORD_FILE")?)?
        .trim_end_matches(['\r', '\n'])
        .to_string();
    let c = Client::new(Endpoint::new(host, "admin", password))?;
    let args: Vec<String> = std::env::args().skip(1).collect();
    match (args.first().map(String::as_str), args.get(1)) {
        (Some("get"), Some(class)) => println!("{}", c.get(&uri(class)).await?),
        (Some("enum"), Some(class)) => {
            for item in c.enumerate(&uri(class)).await? {
                println!("{item}\n");
            }
        }
        (Some("call"), Some(class)) if args.len() == 5 => {
            let (k, v) = args[3]
                .split_once('=')
                .ok_or("selector must be name=value")?;
            println!(
                "{}",
                c.call(&uri(class), &args[2], &[(k, v)], &args[4]).await?
            );
        }
        _ => eprintln!("usage: wsman get|enum <class> | call <class> <method> <sel>=<val> <input>"),
    }
    Ok(())
}
