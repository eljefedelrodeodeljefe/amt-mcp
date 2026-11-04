//! Typed operations on one AMT device, each one a WS-Man call verified on AMT 12
//! hardware in client control mode.

use serde::Serialize;

use crate::error::{Error, Result};
use crate::wsman::{self, AMT, CIM, Client, IPS, field, field_u32};

/// `CIM_AssociatedPowerManagementService.PowerState`, as AMT reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PowerState {
    On,
    SleepLight,
    SleepDeep,
    Hibernate,
    OffSoft,
    OffHard,
    Other(u32),
}

impl From<u32> for PowerState {
    fn from(v: u32) -> Self {
        match v {
            2 => Self::On,
            3 => Self::SleepLight,
            4 => Self::SleepDeep,
            7 => Self::Hibernate,
            8 => Self::OffSoft,
            6 => Self::OffHard,
            other => Self::Other(other),
        }
    }
}

/// A power action, sent as `CIM_PowerManagementService.RequestPowerStateChange`.
/// These are the out-of-band actions: none of them asks the OS first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, Serialize)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum PowerAction {
    /// Power on a machine that is off (state 2).
    On,
    /// Immediate power off (state 8, CIM "Off - Soft"). AMT does not ask the OS,
    /// so to the machine this is like holding the power button.
    Off,
    /// Power off then on again (state 5, "Power Cycle (Off Soft)").
    Cycle,
    /// Hard reset without removing power (state 10, "Master Bus Reset").
    Reset,
}

impl PowerAction {
    pub fn cim_value(self) -> u32 {
        match self {
            Self::On => 2,
            Self::Off => 8,
            Self::Cycle => 5,
            Self::Reset => 10,
        }
    }
}

/// `IPS_HostBasedSetupService.CurrentControlMode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlMode {
    NotProvisioned,
    /// Client control mode: user consent is mandatory for redirection.
    Client,
    /// Admin control mode: consent policy is configurable.
    Admin,
    Other(u32),
}

impl From<u32> for ControlMode {
    fn from(v: u32) -> Self {
        match v {
            0 => Self::NotProvisioned,
            1 => Self::Client,
            2 => Self::Admin,
            other => Self::Other(other),
        }
    }
}

/// `IPS_OptInService.OptInState`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsentState {
    /// No consent in progress.
    NotStarted,
    /// A code was requested but is not on screen yet.
    Requested,
    /// The code is on the device's screen.
    Displayed,
    /// The right code was entered; redirection may start.
    Received,
    /// A redirection session is running under this consent.
    InSession,
    Other(u32),
}

impl From<u32> for ConsentState {
    fn from(v: u32) -> Self {
        match v {
            0 => Self::NotStarted,
            1 => Self::Requested,
            2 => Self::Displayed,
            3 => Self::Received,
            4 => Self::InSession,
            other => Self::Other(other),
        }
    }
}

/// What a session needs consent for, from `OptInRequired` (a bit mask).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConsentPolicy {
    pub raw: u32,
    /// Human-readable: "none", "kvm" or "all".
    pub required_for: &'static str,
    /// Whether this control mode may change the policy.
    pub modifiable: bool,
}

/// Everything `get_status` reports.
#[derive(Debug, Clone, Serialize)]
pub struct Status {
    pub power_state: PowerState,
    pub control_mode: ControlMode,
    pub consent_state: ConsentState,
    pub consent_policy: ConsentPolicy,
    pub redirection: Redirection,
    pub kvm: Kvm,
}

#[derive(Debug, Clone, Serialize)]
pub struct Redirection {
    pub sol_enabled: bool,
    pub ider_enabled: bool,
    /// Whether the 16994/16995 listener accepts sessions at all.
    pub listener_enabled: bool,
    pub raw_enabled_state: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct Kvm {
    pub enabled_by_mebx: bool,
    pub port_5900_enabled: bool,
    pub session_timeout_minutes: Option<u32>,
}

/// One AMT device.
pub struct Device {
    client: Client,
}

const POWER_SERVICE: &str = "Intel(r) AMT Power Management Service";

impl Device {
    pub fn new(client: Client) -> Self {
        Self { client }
    }

    pub fn client(&self) -> &Client {
        &self.client
    }

    pub async fn power_state(&self) -> Result<PowerState> {
        let xml = self
            .client
            .get(&format!("{CIM}CIM_AssociatedPowerManagementService"))
            .await?;
        Ok(field_u32(&xml, "PowerState")?.into())
    }

    /// Sends a power action. Out-of-band and immediate: the OS is not asked.
    pub async fn power(&self, action: PowerAction) -> Result<()> {
        let uri = format!("{CIM}CIM_PowerManagementService");
        let input = format!(
            "<p:PowerState>{}</p:PowerState><p:ManagedElement>\
<a:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address>\
<a:ReferenceParameters><w:ResourceURI>{CIM}CIM_ComputerSystem</w:ResourceURI>\
<w:SelectorSet><w:Selector Name=\"CreationClassName\">CIM_ComputerSystem</w:Selector>\
<w:Selector Name=\"Name\">ManagedSystem</w:Selector></w:SelectorSet></a:ReferenceParameters>\
</p:ManagedElement>",
            action.cim_value()
        );
        let xml = self
            .client
            .invoke(
                &uri,
                "RequestPowerStateChange",
                &wsman::name_selector(POWER_SERVICE),
                &input,
            )
            .await?;
        check_return("RequestPowerStateChange", &xml, power_meaning)
    }

    pub async fn control_mode(&self) -> Result<ControlMode> {
        let xml = self
            .client
            .get(&format!("{IPS}IPS_HostBasedSetupService"))
            .await?;
        Ok(field_u32(&xml, "CurrentControlMode")?.into())
    }

    async fn opt_in(&self) -> Result<String> {
        self.client.get(&format!("{IPS}IPS_OptInService")).await
    }

    pub async fn consent_state(&self) -> Result<ConsentState> {
        Ok(field_u32(&self.opt_in().await?, "OptInState")?.into())
    }

    /// Asks AMT to show a 6-digit consent code on the device's display.
    pub async fn consent_start(&self) -> Result<()> {
        let xml = self
            .client
            .invoke(&format!("{IPS}IPS_OptInService"), "StartOptIn", "", "")
            .await?;
        check_return("StartOptIn", &xml, consent_meaning)
    }

    /// Submits the code read off the device's display.
    pub async fn consent_submit(&self, code: &str) -> Result<()> {
        if code.len() != 6 || !code.bytes().all(|b| b.is_ascii_digit()) {
            return Err(Error::InvalidArgument(
                "the consent code is the 6 digits shown on the device's display".into(),
            ));
        }
        let xml = self
            .client
            .invoke(
                &format!("{IPS}IPS_OptInService"),
                "SendOptInCode",
                "",
                &format!("<p:OptInCode>{code}</p:OptInCode>"),
            )
            .await?;
        check_return("SendOptInCode", &xml, consent_meaning)
    }

    /// Withdraws a pending or granted consent.
    pub async fn consent_cancel(&self) -> Result<()> {
        let xml = self
            .client
            .invoke(&format!("{IPS}IPS_OptInService"), "CancelOptIn", "", "")
            .await?;
        check_return("CancelOptIn", &xml, consent_meaning)
    }

    pub async fn redirection(&self) -> Result<Redirection> {
        let xml = self
            .client
            .get(&format!("{AMT}AMT_RedirectionService"))
            .await?;
        let raw = field_u32(&xml, "EnabledState")?;
        Ok(Redirection {
            // 32768 = both off, 32769 = IDER, 32770 = SOL, 32771 = both.
            ider_enabled: raw & 1 == 1 && raw >= 32768,
            sol_enabled: raw & 2 == 2 && raw >= 32768,
            listener_enabled: field(&xml, "ListenerEnabled").as_deref() == Some("true"),
            raw_enabled_state: raw,
        })
    }

    /// Opens the 16994 redirection listener, which SOL and IDE-R need. The
    /// features themselves must already be enabled (`rpc configure amtfeatures`
    /// or MEBx); this flips only `ListenerEnabled`.
    pub async fn enable_redirection_listener(&self) -> Result<Redirection> {
        let uri = format!("{AMT}AMT_RedirectionService");
        let xml = self.client.get(&uri).await?;
        let inst = wsman::element(&xml, "AMT_RedirectionService")
            .ok_or(Error::MissingField("AMT_RedirectionService"))?;
        let inst = wsman::replace_field(&inst, "ListenerEnabled", "true");
        // The instance from a Get relies on the envelope's namespace declaration;
        // a Put body must carry its own.
        let inst = declare_prefix(&inst, &uri);
        self.client.put(&uri, &inst).await?;
        self.redirection().await
    }

    pub async fn kvm(&self) -> Result<Kvm> {
        let xml = self
            .client
            .get(&format!("{IPS}IPS_KVMRedirectionSettingData"))
            .await?;
        Ok(Kvm {
            enabled_by_mebx: field(&xml, "EnabledByMEBx").as_deref() == Some("true"),
            port_5900_enabled: field(&xml, "Is5900PortEnabled").as_deref() == Some("true"),
            session_timeout_minutes: field(&xml, "SessionTimeout").and_then(|v| v.parse().ok()),
        })
    }

    pub async fn status(&self) -> Result<Status> {
        let opt_in = self.opt_in().await?;
        let raw = field_u32(&opt_in, "OptInRequired")?;
        Ok(Status {
            power_state: self.power_state().await?,
            control_mode: self.control_mode().await?,
            consent_state: field_u32(&opt_in, "OptInState")?.into(),
            consent_policy: ConsentPolicy {
                raw,
                required_for: match raw {
                    0 => "none",
                    1 => "kvm",
                    _ => "all",
                },
                modifiable: field(&opt_in, "CanModifyOptInPolicy").as_deref() == Some("1")
                    || field(&opt_in, "CanModifyOptInPolicy").as_deref() == Some("true"),
            },
            redirection: self.redirection().await?,
            kvm: self.kvm().await?,
        })
    }
}

/// Adds `xmlns:{prefix}="{uri}"` to the root tag of `inst` if it is missing.
fn declare_prefix(inst: &str, uri: &str) -> String {
    let Some(end) = inst.find('>') else {
        return inst.to_string();
    };
    let tag = &inst[1..end];
    let Some((prefix, _)) = tag
        .split_whitespace()
        .next()
        .and_then(|n| n.split_once(':'))
    else {
        return inst.to_string();
    };
    if tag.contains(&format!("xmlns:{prefix}=")) {
        return inst.to_string();
    }
    format!("<{tag} xmlns:{prefix}=\"{uri}\"{}", &inst[end..])
}

fn check_return(
    method: &'static str,
    xml: &str,
    meaning: fn(u32) -> Option<&'static str>,
) -> Result<()> {
    match field_u32(xml, "ReturnValue")? {
        0 => Ok(()),
        code => Err(Error::ReturnValue {
            method,
            code,
            meaning: meaning(code),
        }),
    }
}

fn power_meaning(code: u32) -> Option<&'static str> {
    match code {
        1 => Some("not supported"),
        2 => Some("unknown or unspecified error"),
        3 => Some("cannot complete within timeout"),
        4 => Some("failed"),
        5 => Some("invalid parameter"),
        6 => Some("in use"),
        _ => None,
    }
}

fn consent_meaning(code: u32) -> Option<&'static str> {
    match code {
        1 => Some("internal error"),
        2 => Some("invalid state for this request"),
        3 => Some("blocked"),
        2066 => Some("unsupported or wrong consent code"),
        2082 => Some("consent code expired; request a new one"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn declares_missing_prefix() {
        let inst = "<g:AMT_RedirectionService><g:X>1</g:X></g:AMT_RedirectionService>";
        assert_eq!(
            declare_prefix(inst, "urn:r"),
            "<g:AMT_RedirectionService xmlns:g=\"urn:r\"><g:X>1</g:X></g:AMT_RedirectionService>"
        );
        let already = "<g:A xmlns:g=\"urn:r\"></g:A>";
        assert_eq!(declare_prefix(already, "urn:r"), already);
    }

    #[test]
    fn maps_states() {
        assert_eq!(PowerState::from(2), PowerState::On);
        assert_eq!(PowerState::from(8), PowerState::OffSoft);
        assert_eq!(ControlMode::from(1), ControlMode::Client);
        assert_eq!(ConsentState::from(3), ConsentState::Received);
        assert_eq!(PowerAction::Cycle.cim_value(), 5);
    }

    #[test]
    fn return_value_errors_carry_meaning() {
        let xml = "<g:ReturnValue>2066</g:ReturnValue>";
        let e = check_return("SendOptInCode", xml, consent_meaning).unwrap_err();
        assert!(e.to_string().contains("2066"));
        assert!(e.to_string().contains("wrong consent code"));
        assert!(check_return("X", "<g:ReturnValue>0</g:ReturnValue>", consent_meaning).is_ok());
    }
}
