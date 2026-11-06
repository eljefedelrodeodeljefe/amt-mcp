use anyhow::Result;
use rmcp::{ServiceExt, transport::stdio};

mod config;
mod error;
mod guides;
mod logging;
mod params;
mod server;
mod tools;

#[tokio::main]
async fn main() -> Result<()> {
    // Log to stderr — stdout is reserved for MCP JSON-RPC messages.
    tracing_subscriber::fmt()
        .with_env_filter(logging::filter(std::env::var("RUST_LOG").ok().as_deref()))
        .with_writer(std::io::stderr)
        .init();

    let server = server::AmtServer::from_env()?;
    tracing::info!("amt-mcp starting");

    let svc = server.serve(stdio()).await?;
    svc.waiting().await?;

    Ok(())
}
