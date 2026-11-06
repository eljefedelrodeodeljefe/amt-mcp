use anyhow::Result;
use rmcp::{ServiceExt, transport::stdio};
use tracing_subscriber::EnvFilter;

mod config;
mod error;
mod guides;
mod params;
mod server;
mod tools;

#[tokio::main]
async fn main() -> Result<()> {
    // Log to stderr — stdout is reserved for MCP JSON-RPC messages.
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    let server = server::AmtServer::from_env()?;
    tracing::info!("amt-mcp starting");

    let svc = server.serve(stdio()).await?;
    svc.waiting().await?;

    Ok(())
}
