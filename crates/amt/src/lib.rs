//! Intel AMT client: WS-Man over HTTP digest (power, user consent, redirection
//! settings) and the redirection protocol for Serial-over-LAN.
//!
//! No MCP types live here; the library stands on its own.

pub mod accounts;
pub mod alarm;
pub mod boot;
pub mod device;
mod digest;
pub mod error;
pub mod ider;
pub mod inventory;
pub mod kvm;
pub mod logs;
pub mod network;
mod redir;
pub mod secret;
pub mod sol;
pub mod wsman;
mod zrle;

pub use accounts::{Account, READ_ONLY_REALMS, Realm};
pub use alarm::Alarm;
pub use boot::{BootCapabilities, BootSettings, BootTarget};
pub use device::{
    ConsentPolicy, ConsentState, ControlMode, Device, Kvm, PowerAction, PowerState, Redirection,
    Status,
};
pub use error::{Error, Result};
pub use ider::{IderSession, IderStart, IderStatus};
pub use inventory::{GeneralSettings, Inventory};
pub use kvm::{KvmSession, KvmState};
pub use logs::{AuditRecord, Event};
pub use network::{Clock, EthernetPort};
pub use secret::Secret;
pub use sol::SolSession;
pub use wsman::{Client, Endpoint};
