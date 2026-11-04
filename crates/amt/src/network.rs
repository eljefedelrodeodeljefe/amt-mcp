//! AMT's network settings (read-only here: a wrong write can cut AMT off the
//! network) and its clock, which can be read and synchronised.

use serde::Serialize;

use crate::device::Device;
use crate::error::{Error, Result};
use crate::wsman::{AMT, field, field_u32};

#[derive(Debug, Clone, Serialize)]
pub struct EthernetPort {
    pub instance_id: Option<String>,
    pub mac_address: Option<String>,
    pub link_up: bool,
    pub dhcp_enabled: bool,
    pub ip_address: Option<String>,
    pub subnet_mask: Option<String>,
    pub default_gateway: Option<String>,
    pub primary_dns: Option<String>,
    /// AMT uses the host's MAC.
    pub shared_mac: bool,
    /// AMT shares the host's DHCP address (ports 16992–16995 are intercepted on it).
    pub shared_dynamic_ip: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct Clock {
    /// AMT's clock, Unix seconds.
    pub amt_unix: u64,
    /// This machine's clock at the time of the read.
    pub local_unix: u64,
    /// `amt - local`; positive means AMT runs ahead.
    pub offset_seconds: i64,
}

fn opt(xml: &str, name: &str) -> Option<String> {
    field(xml, name)
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

const TIME: &str = "AMT_TimeSynchronizationService";

impl Device {
    pub async fn ethernet_ports(&self) -> Result<Vec<EthernetPort>> {
        let ports = self
            .client()
            .enumerate(&format!("{AMT}AMT_EthernetPortSettings"))
            .await?;
        Ok(ports
            .iter()
            .map(|p| EthernetPort {
                instance_id: opt(p, "InstanceID"),
                mac_address: opt(p, "MACAddress"),
                link_up: opt(p, "LinkIsUp").as_deref() == Some("true"),
                dhcp_enabled: opt(p, "DHCPEnabled").as_deref() == Some("true"),
                ip_address: opt(p, "IPAddress"),
                subnet_mask: opt(p, "SubnetMask"),
                default_gateway: opt(p, "DefaultGateway"),
                primary_dns: opt(p, "PrimaryDNS"),
                shared_mac: opt(p, "SharedMAC").as_deref() == Some("true"),
                shared_dynamic_ip: opt(p, "SharedDynamicIP").as_deref() == Some("true"),
            })
            .collect())
    }

    /// Reads AMT's clock (`GetLowAccuracyTimeSynch`).
    pub async fn clock(&self) -> Result<Clock> {
        let xml = self
            .client()
            .call(&format!("{AMT}{TIME}"), "GetLowAccuracyTimeSynch", &[], "")
            .await?;
        if field_u32(&xml, "ReturnValue")? != 0 {
            return Err(Error::ReturnValue {
                method: "GetLowAccuracyTimeSynch",
                code: field_u32(&xml, "ReturnValue")?,
                meaning: None,
            });
        }
        let amt = field_u32(&xml, "Ta0")? as u64;
        let local = now_unix();
        Ok(Clock {
            amt_unix: amt,
            local_unix: local,
            offset_seconds: amt as i64 - local as i64,
        })
    }

    /// Sets AMT's clock to this machine's (`SetHighAccuracyTimeSynch`, the
    /// two-step exchange the SDK prescribes: Ta0 from AMT, then Tm1/Tm2 local).
    pub async fn sync_clock(&self) -> Result<Clock> {
        let uri = format!("{AMT}{TIME}");
        let xml = self
            .client()
            .call(&uri, "GetLowAccuracyTimeSynch", &[], "")
            .await?;
        let ta0 = field_u32(&xml, "Ta0")?;
        let tm = now_unix();
        let xml = self
            .client()
            .call(
                &uri,
                "SetHighAccuracyTimeSynch",
                &[],
                &format!("<p:Ta0>{ta0}</p:Ta0><p:Tm1>{tm}</p:Tm1><p:Tm2>{tm}</p:Tm2>"),
            )
            .await?;
        match field_u32(&xml, "ReturnValue")? {
            0 => self.clock().await,
            code => Err(Error::ReturnValue {
                method: "SetHighAccuracyTimeSynch",
                code,
                meaning: None,
            }),
        }
    }
}
