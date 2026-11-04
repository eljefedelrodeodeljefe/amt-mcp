//! One-time boot control: the next boot goes to BIOS setup, PXE, the hard
//! drive, an optical drive or an IDE-R image, optionally with the BIOS
//! console redirected to SOL. AMT clears the setting after that boot.
//!
//! The sequence is the SDK's: `Put` AMT_BootSettingData, then
//! `CIM_BootService.SetBootConfigRole`, then `CIM_BootConfigSetting.ChangeBootOrder`.
//! The power action that makes it happen is separate (`Device::power`).

use serde::{Deserialize, Serialize};

use crate::device::Device;
use crate::error::{Error, Result};
use crate::wsman::{self, AMT, CIM, field, field_u32};

const BOOT_CONFIG: &str = "Intel(r) AMT: Boot Configuration 0";
const BOOT_SERVICE: &str = "Intel(r) AMT Boot Service";

/// Where the next boot goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum BootTarget {
    /// Normal boot order; clears any pending override.
    Default,
    /// Enter BIOS setup.
    BiosSetup,
    /// Network boot.
    Pxe,
    /// Local hard drive, skipping other devices.
    HardDrive,
    /// Local CD/DVD drive.
    CdDvd,
    /// The IDE-R image as a CD-ROM (needs an IDE-R session to serve it).
    IderCd,
    /// The IDE-R image as a floppy.
    IderFloppy,
}

impl BootTarget {
    fn source(self) -> Option<&'static str> {
        match self {
            Self::Pxe => Some("Intel(r) AMT: Force PXE Boot"),
            Self::HardDrive => Some("Intel(r) AMT: Force Hard-drive Boot"),
            Self::CdDvd => Some("Intel(r) AMT: Force CD/DVD Boot"),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct BootCapabilities {
    pub bios_setup: bool,
    pub pxe: bool,
    pub hard_drive: bool,
    pub cd_dvd: bool,
    pub ider: bool,
    pub sol: bool,
    pub keyboard_lock: bool,
    pub bios_secure_boot: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct BootSettings {
    pub bios_setup: bool,
    pub use_sol: bool,
    pub use_ider: bool,
    /// 0 floppy, 1 CD-ROM.
    pub ider_boot_device: u32,
    pub options_cleared: bool,
}

fn flag(xml: &str, name: &str) -> bool {
    field(xml, name).as_deref() == Some("true")
}

impl Device {
    pub async fn boot_capabilities(&self) -> Result<BootCapabilities> {
        let x = self
            .client()
            .get(&format!("{AMT}AMT_BootCapabilities"))
            .await?;
        Ok(BootCapabilities {
            bios_setup: flag(&x, "BIOSSetup"),
            pxe: flag(&x, "ForcePXEBoot"),
            hard_drive: flag(&x, "ForceHardDriveBoot"),
            cd_dvd: flag(&x, "ForceCDorDVDBoot"),
            ider: flag(&x, "IDER"),
            sol: flag(&x, "SOL"),
            keyboard_lock: flag(&x, "KeyboardLock"),
            bios_secure_boot: flag(&x, "BIOSSecureBoot"),
        })
    }

    pub async fn boot_settings(&self) -> Result<BootSettings> {
        let x = self
            .client()
            .get(&format!("{AMT}AMT_BootSettingData"))
            .await?;
        Ok(BootSettings {
            bios_setup: flag(&x, "BIOSSetup"),
            use_sol: flag(&x, "UseSOL"),
            use_ider: flag(&x, "UseIDER"),
            ider_boot_device: field_u32(&x, "IDERBootDevice").unwrap_or(0),
            options_cleared: flag(&x, "OptionsCleared"),
        })
    }

    /// Sets where the *next* boot goes. `sol` redirects the BIOS console to
    /// Serial-over-LAN for that boot. Does not reboot: follow with `power`.
    pub async fn set_next_boot(&self, target: BootTarget, sol: bool) -> Result<BootSettings> {
        let caps = self.boot_capabilities().await?;
        let supported = match target {
            BootTarget::Default => true,
            BootTarget::BiosSetup => caps.bios_setup,
            BootTarget::Pxe => caps.pxe,
            BootTarget::HardDrive => caps.hard_drive,
            BootTarget::CdDvd => caps.cd_dvd,
            BootTarget::IderCd | BootTarget::IderFloppy => caps.ider,
        };
        if !supported || (sol && !caps.sol) {
            return Err(Error::InvalidArgument(format!(
                "this device does not support boot target {target:?}{}",
                if sol { " with SOL" } else { "" }
            )));
        }

        // 1. Boot setting data.
        let uri = format!("{AMT}AMT_BootSettingData");
        let xml = self.client().get(&uri).await?;
        let inst = wsman::element(&xml, "AMT_BootSettingData")
            .ok_or(Error::MissingField("AMT_BootSettingData"))?;
        let ider = matches!(target, BootTarget::IderCd | BootTarget::IderFloppy);
        let mut inst = strip_read_only(&inst);
        for (name, value) in [
            ("BIOSSetup", (target == BootTarget::BiosSetup).to_string()),
            ("BIOSPause", "false".into()),
            ("UseSOL", sol.to_string()),
            ("UseIDER", ider.to_string()),
            (
                "IDERBootDevice",
                if target == BootTarget::IderCd {
                    "1"
                } else {
                    "0"
                }
                .into(),
            ),
            ("BootMediaIndex", "0".into()),
            ("UseSafeMode", "false".into()),
            ("ReflashBIOS", "false".into()),
            ("ConfigurationDataReset", "false".into()),
            ("FirmwareVerbosity", "0".into()),
            ("LockKeyboard", "false".into()),
            ("LockPowerButton", "false".into()),
            ("LockResetButton", "false".into()),
            ("LockSleepButton", "false".into()),
            ("UserPasswordBypass", "false".into()),
            ("SecureErase", "false".into()),
        ] {
            inst = wsman::replace_field(&inst, name, &value);
        }
        let inst = crate::device::declare_prefix(&inst, &uri);
        self.client().put(&uri, &inst).await?;

        // 2. Make the AMT boot configuration the one used next time.
        let role = format!(
            "<p:BootConfigSetting>{}</p:BootConfigSetting><p:Role>1</p:Role>",
            wsman::reference(
                &format!("{CIM}CIM_BootConfigSetting"),
                &[("InstanceID", BOOT_CONFIG)]
            )
        );
        let xml = self
            .client()
            .call(
                &format!("{CIM}CIM_BootService"),
                "SetBootConfigRole",
                &[("Name", BOOT_SERVICE)],
                &role,
            )
            .await?;
        check("SetBootConfigRole", &xml)?;

        // 3. Boot order: one forced device, or none.
        let order = target
            .source()
            .map(|id| {
                format!(
                    "<p:Source>{}</p:Source>",
                    wsman::reference(
                        &format!("{CIM}CIM_BootSourceSetting"),
                        &[("InstanceID", id)]
                    )
                )
            })
            .unwrap_or_default();
        let xml = self
            .client()
            .call(
                &format!("{CIM}CIM_BootConfigSetting"),
                "ChangeBootOrder",
                &[("InstanceID", BOOT_CONFIG)],
                &order,
            )
            .await?;
        check("ChangeBootOrder", &xml)?;
        self.boot_settings().await
    }
}

/// Fields a Put must not carry back: they are reported by AMT, not settable.
fn strip_read_only(inst: &str) -> String {
    let mut s = inst.to_string();
    for name in [
        "BIOSLastStatus",
        "OptionsCleared",
        "UEFIBootParametersArray",
        "UEFIBootNumberOfParams",
    ] {
        let re = regex::Regex::new(&format!(
            r"<(?:[\w-]+:)?{n}(?:\s[^>]*)?>[^<]*</(?:[\w-]+:)?{n}>|<(?:[\w-]+:)?{n}(?:\s[^>]*)?/>",
            n = name
        ))
        .expect("strip regex");
        s = re.replace_all(&s, "").into_owned();
    }
    s
}

fn check(method: &'static str, xml: &str) -> Result<()> {
    match field_u32(xml, "ReturnValue")? {
        0 => Ok(()),
        code => Err(Error::ReturnValue {
            method,
            code,
            meaning: None,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_reported_fields() {
        let inst = "<g:AMT_BootSettingData><g:BIOSLastStatus>2</g:BIOSLastStatus><g:BIOSLastStatus>0</g:BIOSLastStatus><g:BIOSSetup>false</g:BIOSSetup><g:OptionsCleared>true</g:OptionsCleared></g:AMT_BootSettingData>";
        assert_eq!(
            strip_read_only(inst),
            "<g:AMT_BootSettingData><g:BIOSSetup>false</g:BIOSSetup></g:AMT_BootSettingData>"
        );
    }

    #[test]
    fn forced_sources() {
        assert!(BootTarget::BiosSetup.source().is_none());
        assert_eq!(
            BootTarget::Pxe.source(),
            Some("Intel(r) AMT: Force PXE Boot")
        );
    }
}
