//! Intel AMT client: WS-Man over HTTP digest (power, user consent, redirection
//! settings) and the redirection protocol for Serial-over-LAN.
//!
//! No MCP types live here; the library stands on its own.

pub mod device;
mod digest;
pub mod error;
pub mod sol;
pub mod wsman;

pub use device::{
    ConsentPolicy, ConsentState, ControlMode, Device, Kvm, PowerAction, PowerState, Redirection,
    Status,
};
pub use error::{Error, Result};
pub use sol::SolSession;
pub use wsman::{Client, Endpoint};
