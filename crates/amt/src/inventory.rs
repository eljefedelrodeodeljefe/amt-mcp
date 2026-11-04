//! Hardware inventory as AMT reports it out of band: BIOS, chassis, CPUs,
//! memory and the AMT firmware version. Works with the host OS down.

use serde::Serialize;

use crate::device::Device;
use crate::error::Result;
use crate::wsman::{AMT, CIM, field, fields};

#[derive(Debug, Clone, Serialize)]
pub struct Inventory {
    pub bios: Bios,
    pub chassis: Chassis,
    pub processors: Vec<Processor>,
    pub memory: Vec<Memory>,
    pub memory_total_bytes: u64,
    pub amt_version: Option<String>,
    pub amt_build: Option<String>,
    pub platform_guid: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Bios {
    pub manufacturer: Option<String>,
    pub version: Option<String>,
    pub release_date: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Chassis {
    pub manufacturer: Option<String>,
    pub model: Option<String>,
    pub version: Option<String>,
    pub serial_number: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Processor {
    pub device_id: Option<String>,
    pub family: Option<u32>,
    pub stepping: Option<String>,
    pub current_clock_mhz: Option<u32>,
    pub max_clock_mhz: Option<u32>,
    /// CIM `CPUStatus`: 1 = enabled.
    pub status: Option<u32>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Memory {
    pub bank: Option<String>,
    pub capacity_bytes: Option<u64>,
    pub speed_mhz: Option<u32>,
    pub manufacturer: Option<String>,
    pub part_number: Option<String>,
    pub serial_number: Option<String>,
}

fn opt(xml: &str, name: &str) -> Option<String> {
    field(xml, name)
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

fn num<T: std::str::FromStr>(xml: &str, name: &str) -> Option<T> {
    opt(xml, name).and_then(|v| v.parse().ok())
}

impl Device {
    pub async fn inventory(&self) -> Result<Inventory> {
        let c = self.client();
        let bios = c.get(&format!("{CIM}CIM_BIOSElement")).await?;
        let chassis = c.get(&format!("{CIM}CIM_Chassis")).await?;
        let package = c.get(&format!("{CIM}CIM_ComputerSystemPackage")).await?;
        let cpus = c.enumerate(&format!("{CIM}CIM_Processor")).await?;
        let dimms = c.enumerate(&format!("{CIM}CIM_PhysicalMemory")).await?;
        let software = c.enumerate(&format!("{CIM}CIM_SoftwareIdentity")).await?;

        let memory: Vec<Memory> = dimms
            .iter()
            .map(|d| Memory {
                bank: opt(d, "BankLabel"),
                capacity_bytes: num(d, "Capacity"),
                speed_mhz: num::<u32>(d, "ConfiguredMemoryClockSpeed")
                    .or_else(|| num(d, "Speed"))
                    .filter(|s| *s > 0),
                manufacturer: opt(d, "Manufacturer"),
                part_number: opt(d, "PartNumber"),
                serial_number: opt(d, "SerialNumber"),
            })
            .collect();
        let version_of = |id: &str| {
            software
                .iter()
                .find(|s| field(s, "InstanceID").as_deref() == Some(id))
                .and_then(|s| opt(s, "VersionString"))
        };
        Ok(Inventory {
            bios: Bios {
                manufacturer: opt(&bios, "Manufacturer"),
                version: opt(&bios, "Version"),
                release_date: field(&bios, "ReleaseDate")
                    .and_then(|_| fields(&bios, "Datetime").into_iter().next())
                    .filter(|d| !d.is_empty()),
            },
            chassis: Chassis {
                manufacturer: opt(&chassis, "Manufacturer"),
                model: opt(&chassis, "Model"),
                version: opt(&chassis, "Version"),
                serial_number: opt(&chassis, "SerialNumber"),
            },
            processors: cpus
                .iter()
                .map(|p| Processor {
                    device_id: opt(p, "DeviceID"),
                    family: num(p, "Family"),
                    stepping: opt(p, "Stepping"),
                    current_clock_mhz: num(p, "CurrentClockSpeed"),
                    max_clock_mhz: num(p, "MaxClockSpeed"),
                    status: num(p, "CPUStatus"),
                })
                .collect(),
            memory_total_bytes: memory.iter().filter_map(|m| m.capacity_bytes).sum(),
            memory,
            amt_version: version_of("AMT"),
            amt_build: version_of("Build Number"),
            platform_guid: opt(&package, "PlatformGUID"),
        })
    }

    /// AMT's own idea of the host: FQDN, digest realm, whether it answers ping.
    pub async fn general_settings(&self) -> Result<GeneralSettings> {
        let x = self
            .client()
            .get(&format!("{AMT}AMT_GeneralSettings"))
            .await?;
        Ok(GeneralSettings {
            host_name: opt(&x, "HostName"),
            domain_name: opt(&x, "DomainName"),
            host_os_fqdn: opt(&x, "HostOSFQDN"),
            digest_realm: opt(&x, "DigestRealm"),
            network_enabled: opt(&x, "AMTNetworkEnabled").as_deref() == Some("1"),
            ping_response_enabled: opt(&x, "PingResponseEnabled").as_deref() == Some("true"),
            shared_fqdn: opt(&x, "SharedFQDN").as_deref() == Some("true"),
        })
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct GeneralSettings {
    pub host_name: Option<String>,
    pub domain_name: Option<String>,
    pub host_os_fqdn: Option<String>,
    pub digest_realm: Option<String>,
    pub network_enabled: bool,
    pub ping_response_enabled: bool,
    pub shared_fqdn: bool,
}
