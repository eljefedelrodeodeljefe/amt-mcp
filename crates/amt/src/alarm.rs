//! Scheduled wake: AMT powers the machine on at a set time, optionally
//! repeating (`AMT_AlarmClockService`, `IPS_AlarmClockOccurrence`).

use serde::Serialize;

use crate::device::Device;
use crate::error::{Error, Result};
use crate::wsman::{AMT, IPS, field, field_u32, fields, xml_text};

const SERVICE: &str = "Intel(r) AMT Alarm Clock Service";
const COMMON: &str = "http://schemas.dmtf.org/wbem/wscim/1/common";

#[derive(Debug, Clone, Serialize)]
pub struct Alarm {
    pub name: String,
    /// ISO 8601, as AMT stores it (UTC).
    pub start_time: Option<String>,
    /// ISO 8601 duration, e.g. `P1D`; absent for a one-off alarm.
    pub interval: Option<String>,
    pub delete_on_completion: bool,
}

impl Device {
    pub async fn alarms(&self) -> Result<Vec<Alarm>> {
        let items = self
            .client()
            .enumerate(&format!("{IPS}IPS_AlarmClockOccurrence"))
            .await?;
        Ok(items
            .iter()
            .map(|a| Alarm {
                name: field(a, "InstanceID").unwrap_or_default(),
                start_time: fields(a, "Datetime").into_iter().next(),
                interval: fields(a, "Interval")
                    .into_iter()
                    .rev()
                    .find(|v| v.starts_with('P')),
                delete_on_completion: field(a, "DeleteOnCompletion").as_deref() == Some("true"),
            })
            .collect())
    }

    /// Adds a wake alarm. `start` is UTC ISO 8601 (`2026-01-01T06:00:00Z`),
    /// `interval` an ISO 8601 duration (`P1D`, `PT12H`) or `None` for once.
    pub async fn add_alarm(
        &self,
        name: &str,
        start: &str,
        interval: Option<&str>,
        delete_on_completion: bool,
    ) -> Result<()> {
        validate_name(name)?;
        if !is_utc_datetime(start) {
            return Err(Error::InvalidArgument(
                "start must be UTC ISO 8601, e.g. 2026-01-01T06:00:00Z".into(),
            ));
        }
        // AMT keeps time as 32-bit Unix seconds and rejects later dates as
        // invalid XML.
        if start[..4] > *"2037" {
            return Err(Error::InvalidArgument(
                "start must be before 2038 (AMT's clock is 32-bit Unix time)".into(),
            ));
        }
        if let Some(i) = interval
            && !(i.starts_with('P') && i.len() > 1 && i.bytes().all(|b| b.is_ascii_alphanumeric()))
        {
            return Err(Error::InvalidArgument(
                "interval must be an ISO 8601 duration such as P1D or PT12H".into(),
            ));
        }
        let occ = format!("{IPS}IPS_AlarmClockOccurrence");
        let interval_xml = interval
            .map(|i| format!("<s:Interval><d:Interval>{i}</d:Interval></s:Interval>"))
            .unwrap_or_default();
        let input = format!(
            "<p:AlarmTemplate xmlns:s=\"{occ}\" xmlns:d=\"{COMMON}\">\
<s:InstanceID>{n}</s:InstanceID><s:ElementName>{n}</s:ElementName>\
<s:StartTime><d:Datetime>{start}</d:Datetime></s:StartTime>{interval_xml}\
<s:DeleteOnCompletion>{delete_on_completion}</s:DeleteOnCompletion></p:AlarmTemplate>",
            n = xml_text(name)
        );
        let xml = self
            .client()
            .call(
                &format!("{AMT}AMT_AlarmClockService"),
                "AddAlarm",
                &[("Name", SERVICE)],
                &input,
            )
            .await?;
        match field_u32(&xml, "ReturnValue")? {
            0 => Ok(()),
            code => Err(Error::ReturnValue {
                method: "AddAlarm",
                code,
                meaning: match code {
                    1 => Some("alarm clock table full or invalid parameters"),
                    2 => Some("duplicate name"),
                    _ => None,
                },
            }),
        }
    }

    pub async fn delete_alarm(&self, name: &str) -> Result<()> {
        self.client()
            .delete(
                &format!("{IPS}IPS_AlarmClockOccurrence"),
                &[("InstanceID", name)],
            )
            .await
            .map(|_| ())
    }
}

fn validate_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 32
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(Error::InvalidArgument(
            "alarm name: 1-32 characters of letters, digits, '-' or '_'".into(),
        ));
    }
    Ok(())
}

fn is_utc_datetime(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 20
        && b[19] == b'Z'
        && b[4] == b'-'
        && b[7] == b'-'
        && b[10] == b'T'
        && b[13] == b':'
        && b[16] == b':'
        && [0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18]
            .iter()
            .all(|&i| b[i].is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_inputs() {
        assert!(is_utc_datetime("2026-01-01T06:00:00Z"));
        assert!(!is_utc_datetime("2026-01-01 06:00:00"));
        assert!(!is_utc_datetime("2026-01-01T06:00:00+01:00"));
        assert!(validate_name("nightly-wake").is_ok());
        assert!(validate_name("bad name").is_err());
        assert!(validate_name("").is_err());
    }
}
