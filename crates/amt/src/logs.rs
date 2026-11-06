//! The two logs AMT keeps: the platform event log (`AMT_MessageLog`, BIOS and
//! boot progress, firmware errors, watchdog) and the audit log (`AMT_AuditLog`,
//! who used AMT and how: power actions, redirection, consent, ACL changes).

use serde::Serialize;

use crate::device::Device;
use crate::error::{Error, Result};
use crate::wsman::{AMT, field, field_u32, fields};

const MESSAGE_LOG: &str = "Intel(r) AMT:MessageLog 1";
const AUDIT_LOG: &str = "Intel(r) AMT:Audit Log";

#[derive(Debug, Clone, Serialize)]
pub struct Event {
    /// Unix seconds, as AMT recorded them (AMT's clock, see `clock`).
    pub time_unix: u32,
    pub sensor_type: u8,
    pub event_type: u8,
    pub offset: u8,
    pub severity: u8,
    pub entity: &'static str,
    pub description: String,
    pub raw_data: [u8; 8],
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditRecord {
    pub time_unix: u32,
    pub application: String,
    pub event: String,
    pub app_id: u16,
    pub event_id: u16,
    /// Digest user name, "local" or "kvm-default-port".
    pub initiator: String,
    pub source_address: Option<String>,
}

impl Device {
    /// The platform event log, oldest first.
    pub async fn event_log(&self) -> Result<Vec<Event>> {
        let uri = format!("{AMT}AMT_MessageLog");
        let sel = [("Name", MESSAGE_LOG)];
        let xml = self
            .client()
            .call_read(&uri, "PositionToFirstRecord", &sel, "")
            .await?;
        let mut id =
            field(&xml, "IterationIdentifier").ok_or(Error::MissingField("IterationIdentifier"))?;
        let mut out = Vec::new();
        for _ in 0..16 {
            let xml = self
                .client()
                .call_read(
                    &uri,
                    "GetRecords",
                    &sel,
                    &format!(
                        "<p:IterationIdentifier>{id}</p:IterationIdentifier><p:MaxReadRecords>390</p:MaxReadRecords>"
                    ),
                )
                .await?;
            for rec in fields(&xml, "RecordArray") {
                if let Some(e) = decode_event(&base64_decode(&rec)) {
                    out.push(e);
                }
            }
            if field(&xml, "NoMoreRecords").as_deref() != Some("false") {
                break;
            }
            id = field(&xml, "IterationIdentifier")
                .ok_or(Error::MissingField("IterationIdentifier"))?;
        }
        Ok(out)
    }

    /// The audit log, oldest first.
    pub async fn audit_log(&self) -> Result<Vec<AuditRecord>> {
        let uri = format!("{AMT}AMT_AuditLog");
        let sel = [("Name", AUDIT_LOG)];
        let mut out = Vec::new();
        let mut start = 1u32;
        for _ in 0..64 {
            let xml = self
                .client()
                .call_read(
                    &uri,
                    "ReadRecords",
                    &sel,
                    &format!("<p:StartIndex>{start}</p:StartIndex>"),
                )
                .await?;
            let total = field_u32(&xml, "TotalRecordCount").unwrap_or(0);
            let got = field_u32(&xml, "RecordsReturned").unwrap_or(0);
            for rec in fields(&xml, "EventRecords") {
                if let Some(r) = decode_audit(&base64_decode(&rec)) {
                    out.push(r);
                }
            }
            // `got` comes from the device: a count that would run the index
            // past u32 ends the paging instead of overflowing.
            match start.checked_add(got) {
                Some(next) if got != 0 && next <= total => start = next,
                _ => break,
            }
        }
        Ok(out)
    }
}

fn base64_decode(s: &str) -> Vec<u8> {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    let mut acc = 0u32;
    let mut bits = 0;
    for c in s.bytes() {
        let Some(v) = T.iter().position(|&t| t == c) else {
            continue;
        };
        acc = (acc << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    out
}

fn decode_event(e: &[u8]) -> Option<Event> {
    if e.len() < 21 {
        return None;
    }
    let mut data = [0u8; 8];
    data.copy_from_slice(&e[13..21]);
    let (sensor, offset) = (e[5], e[7]);
    Some(Event {
        time_unix: u32::from_le_bytes([e[0], e[1], e[2], e[3]]),
        sensor_type: sensor,
        event_type: e[6],
        offset,
        severity: e[9],
        entity: entity_name(e[11]),
        description: event_description(sensor, offset, &data),
        raw_data: data,
    })
}

fn entity_name(e: u8) -> &'static str {
    match e {
        0 => "unspecified",
        3 => "processor",
        7 => "system board",
        8 => "memory module",
        11 => "add-in card",
        19 => "power supply",
        23 => "system chassis",
        34 => "BIOS",
        35 => "operating system",
        37 => "Intel AMT",
        38 => "Intel ME",
        _ => "other",
    }
}

const FIRMWARE_PROGRESS: [&str; 26] = [
    "unspecified",
    "memory initialization",
    "hard-disk initialization and test",
    "secondary processor initialization",
    "user authentication",
    "user-initiated system setup",
    "USB resource configuration",
    "PCI resource configuration",
    "option ROM initialization",
    "video initialization",
    "cache initialization",
    "SMBus initialization",
    "keyboard controller initialization",
    "embedded/management controller initialization",
    "docking station attachment",
    "enabling docking station",
    "docking station ejection",
    "disabling docking station",
    "calling operating system wake-up vector",
    "starting operating system boot process",
    "baseboard initialization",
    "reserved",
    "floppy initialization",
    "keyboard test",
    "pointing device test",
    "primary processor initialization",
];

const FIRMWARE_ERROR: [&str; 14] = [
    "unspecified",
    "no system memory installed",
    "no usable system memory",
    "unrecoverable hard-disk/ATAPI/IDE device failure",
    "unrecoverable system-board failure",
    "unrecoverable diskette subsystem failure",
    "unrecoverable hard-disk controller failure",
    "unrecoverable keyboard failure",
    "removable boot media not found",
    "unrecoverable video controller failure",
    "no video device detected",
    "BIOS ROM corruption detected",
    "CPU voltage mismatch",
    "CPU speed matching failure",
];

fn event_description(sensor: u8, offset: u8, data: &[u8; 8]) -> String {
    match sensor {
        15 if data[0] == 235 => "firmware event with invalid data".into(),
        15 if offset == 0 => format!(
            "firmware error: {}",
            FIRMWARE_ERROR.get(data[1] as usize).unwrap_or(&"unknown")
        ),
        15 => format!(
            "firmware progress: {}",
            FIRMWARE_PROGRESS
                .get(data[1] as usize)
                .unwrap_or(&"unknown")
        ),
        5 => "chassis intrusion".into(),
        6 => "platform security violation".into(),
        18 => "system event".into(),
        30 => "no bootable media".into(),
        32 => "operating system lockup or power interrupt".into(),
        35 => "system boot failure".into(),
        37 => "system firmware started".into(),
        other => format!("sensor type {other}, offset {offset}"),
    }
}

fn decode_audit(r: &[u8]) -> Option<AuditRecord> {
    if r.len() < 5 {
        return None;
    }
    let app = u16::from_be_bytes([r[0], r[1]]);
    let ev = u16::from_be_bytes([r[2], r[3]]);
    let mut p = 5usize;
    let initiator = match r[4] {
        0 => {
            let len = *r.get(p)? as usize;
            let name = String::from_utf8_lossy(r.get(p + 1..p + 1 + len)?).into_owned();
            p += 1 + len;
            name
        }
        1 => {
            // Kerberos: domain-length-prefixed SID; skip it.
            let len = *r.get(p + 4)? as usize;
            p += 5 + len;
            "kerberos".into()
        }
        2 => "local".into(),
        3 => "kvm-default-port".into(),
        other => format!("initiator type {other}"),
    };
    let time = u32::from_be_bytes(r.get(p..p + 4)?.try_into().ok()?);
    p += 4;
    let source_address = r.get(p + 1).and_then(|&len| {
        r.get(p + 2..p + 2 + len as usize)
            .map(|a| {
                String::from_utf8_lossy(a)
                    .trim_end_matches('\0')
                    .to_string()
            })
            .filter(|a| !a.is_empty())
    });
    let (application, event) = audit_names(app, ev);
    Some(AuditRecord {
        time_unix: time,
        application,
        event,
        app_id: app,
        event_id: ev,
        initiator,
        source_address,
    })
}

/// Names for the common audit applications and events (AMT SDK "Audit Log
/// Events"); anything else is reported by number.
fn audit_names(app: u16, ev: u16) -> (String, String) {
    let (a, e): (&str, Option<&str>) = match app {
        16 => (
            "security admin",
            match ev {
                0 => Some("provisioning started"),
                1 => Some("provisioning completed"),
                2 => Some("ACL entry added"),
                3 => Some("ACL entry modified"),
                4 => Some("ACL entry removed"),
                5 => Some("ACL access with invalid credentials"),
                7 => Some("TLS state changed"),
                17 => Some("unprovisioning started"),
                _ => None,
            },
        ),
        17 => (
            "remote control",
            match ev {
                0 => Some("remote power up"),
                1 => Some("remote power down"),
                2 => Some("remote power cycle"),
                3 => Some("remote reset"),
                _ => None,
            },
        ),
        18 => (
            "redirection",
            match ev {
                0 => Some("IDE-R session opened"),
                1 => Some("IDE-R session closed"),
                2 => Some("IDE-R enabled"),
                3 => Some("IDE-R disabled"),
                4 => Some("SOL session opened"),
                5 => Some("SOL session closed"),
                6 => Some("SOL enabled"),
                7 => Some("SOL disabled"),
                8 => Some("KVM session started"),
                9 => Some("KVM session ended"),
                10 => Some("KVM enabled"),
                11 => Some("KVM disabled"),
                12 => Some("VNC password failed 3 times"),
                _ => None,
            },
        ),
        19 => ("firmware update", None),
        20 => ("security audit log", None),
        21 => (
            "network time",
            if ev == 0 { Some("time set") } else { None },
        ),
        22 => ("network administration", None),
        23 => ("storage administration", None),
        24 => ("event manager", None),
        26 => ("agent presence", None),
        29 => (
            "KVM",
            match ev {
                0 => Some("KVM enabled"),
                1 => Some("KVM disabled"),
                2 => Some("KVM password changed"),
                3 => Some("KVM consent succeeded"),
                4 => Some("KVM consent failed"),
                _ => None,
            },
        ),
        30 => (
            "user opt-in",
            match ev {
                0 => Some("opt-in policy changed"),
                1 => Some("consent code sent"),
                2 => Some("start opt-in blocked"),
                _ => None,
            },
        ),
        33 => ("watchdog", None),
        _ => ("unknown", None),
    };
    let app_name = if a == "unknown" {
        format!("application {app}")
    } else {
        a.to_string()
    };
    (
        app_name,
        e.map(str::to_string)
            .unwrap_or_else(|| format!("event {ev}")),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_roundtrip_of_known_bytes() {
        assert_eq!(base64_decode("AAEC/w=="), vec![0, 1, 2, 255]);
    }

    #[test]
    fn decodes_firmware_progress_event() {
        let mut e = vec![
            0x10, 0x20, 0x30, 0x40, 0x01, 15, 0x6F, 2, 0x68, 0x08, 0, 34, 0,
        ];
        e.extend_from_slice(&[0xC0, 9, 0, 0, 0, 0, 0, 0]);
        let ev = decode_event(&e).unwrap();
        assert_eq!(ev.time_unix, 0x4030_2010);
        assert_eq!(ev.entity, "BIOS");
        assert_eq!(ev.description, "firmware progress: video initialization");
        assert!(decode_event(&e[..20]).is_none());
    }

    #[test]
    fn decodes_digest_audit_record() {
        let mut r = vec![0, 17, 0, 2, 0, 5];
        r.extend_from_slice(b"admin");
        r.extend_from_slice(&0x6000_0000u32.to_be_bytes());
        r.extend_from_slice(&[0, 9]);
        r.extend_from_slice(b"192.0.2.1");
        r.push(0);
        let a = decode_audit(&r).unwrap();
        assert_eq!(a.application, "remote control");
        assert_eq!(a.event, "remote power cycle");
        assert_eq!(a.initiator, "admin");
        assert_eq!(a.time_unix, 0x6000_0000);
        assert_eq!(a.source_address.as_deref(), Some("192.0.2.1"));
    }
}
