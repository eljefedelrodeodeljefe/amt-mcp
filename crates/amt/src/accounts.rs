//! AMT user accounts (`AMT_AuthorizationService` ACL entries): list, add a
//! digest user limited to chosen realms, remove. The built-in `admin` account
//! is not an ACL entry and cannot be removed here.

use md5::{Digest, Md5};
use serde::{Deserialize, Serialize};

use crate::device::Device;
use crate::error::{Error, Result};
use crate::wsman::{AMT, field, field_u32, fields, xml_text};

const SERVICE: &str = "Intel(r) AMT Authorization Service";

/// AMT realms: what an account may do. Names follow the AMT SDK.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum Realm {
    /// SOL, IDE-R and KVM sessions.
    Redirection,
    /// Full administration.
    PtAdministration,
    /// Inventory reads.
    HardwareAsset,
    /// Power control and boot options.
    RemoteControl,
    Storage,
    EventManager,
    StorageAdmin,
    AgentPresenceLocal,
    AgentPresenceRemote,
    CircuitBreaker,
    NetworkTime,
    /// General settings and status reads.
    GeneralInfo,
    EndpointAccessControl,
    EndpointAccessControlAdmin,
    /// Read the platform event log.
    EventLogReader,
    /// Read and manage the audit log.
    AuditLog,
    /// Managing other accounts.
    AclRealm,
    Other(u32),
}

impl Realm {
    pub fn value(self) -> u32 {
        match self {
            Self::Redirection => 2,
            Self::PtAdministration => 3,
            Self::HardwareAsset => 4,
            Self::RemoteControl => 5,
            Self::Storage => 6,
            Self::EventManager => 7,
            Self::StorageAdmin => 8,
            Self::AgentPresenceLocal => 9,
            Self::AgentPresenceRemote => 10,
            Self::CircuitBreaker => 11,
            Self::NetworkTime => 12,
            Self::GeneralInfo => 13,
            Self::EndpointAccessControl => 17,
            Self::EndpointAccessControlAdmin => 18,
            Self::EventLogReader => 19,
            Self::AuditLog => 20,
            Self::AclRealm => 21,
            Self::Other(v) => v,
        }
    }

    pub fn from_value(v: u32) -> Self {
        match v {
            2 => Self::Redirection,
            3 => Self::PtAdministration,
            4 => Self::HardwareAsset,
            5 => Self::RemoteControl,
            6 => Self::Storage,
            7 => Self::EventManager,
            8 => Self::StorageAdmin,
            9 => Self::AgentPresenceLocal,
            10 => Self::AgentPresenceRemote,
            11 => Self::CircuitBreaker,
            12 => Self::NetworkTime,
            13 => Self::GeneralInfo,
            17 => Self::EndpointAccessControl,
            18 => Self::EndpointAccessControlAdmin,
            19 => Self::EventLogReader,
            20 => Self::AuditLog,
            21 => Self::AclRealm,
            other => Self::Other(other),
        }
    }
}

/// The realms of a read-only monitoring account.
pub const READ_ONLY_REALMS: [Realm; 3] = [
    Realm::HardwareAsset,
    Realm::GeneralInfo,
    Realm::EventLogReader,
];

#[derive(Debug, Clone, Serialize)]
pub struct Account {
    pub handle: u32,
    pub user: String,
    /// 0 local only, 1 network only, 2 both.
    pub access: u32,
    pub realms: Vec<Realm>,
    /// AMT's own internal accounts (`$$…`). Not removable.
    pub system: bool,
}

impl Device {
    pub async fn accounts(&self) -> Result<Vec<Account>> {
        let uri = format!("{AMT}AMT_AuthorizationService");
        let sel = [("Name", SERVICE)];
        let xml = self
            .client()
            .call_read(
                &uri,
                "EnumerateUserAclEntries",
                &sel,
                "<p:StartIndex>1</p:StartIndex>",
            )
            .await?;
        let mut out = Vec::new();
        for h in fields(&xml, "Handles") {
            let Ok(handle) = h.trim().parse::<u32>() else {
                continue;
            };
            let e = self
                .client()
                .call_read(
                    &uri,
                    "GetUserAclEntryEx",
                    &sel,
                    &format!("<p:Handle>{handle}</p:Handle>"),
                )
                .await?;
            let user = field(&e, "DigestUsername").unwrap_or_default();
            out.push(Account {
                handle,
                system: user.starts_with("$$"),
                user,
                access: field_u32(&e, "AccessPermission").unwrap_or(1),
                realms: fields(&e, "Realms")
                    .iter()
                    .filter_map(|r| r.trim().parse().ok())
                    .map(Realm::from_value)
                    .collect(),
            });
        }
        Ok(out)
    }

    /// Adds a network digest account limited to `realms`. AMT requires a strong
    /// password (8–32 characters, upper, lower, digit, symbol).
    pub async fn add_account(&self, user: &str, password: &str, realms: &[Realm]) -> Result<u32> {
        if user.is_empty()
            || user.len() > 16
            || !user
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            return Err(Error::InvalidArgument(
                "user: 1-16 characters of letters, digits, '-' or '_'".into(),
            ));
        }
        if realms.is_empty() {
            return Err(Error::InvalidArgument("give at least one realm".into()));
        }
        check_password(password)?;
        let realm = self
            .general_settings()
            .await?
            .digest_realm
            .ok_or(Error::MissingField("DigestRealm"))?;
        // AMT stores HA1 = MD5(user:realm:password), base64-encoded raw bytes.
        let ha1 = Md5::digest(format!("{user}:{realm}:{password}").as_bytes());
        let realms_xml: String = realms
            .iter()
            .map(|r| format!("<p:Realms>{}</p:Realms>", r.value()))
            .collect();
        let input = format!(
            "<p:DigestUsername>{}</p:DigestUsername><p:DigestPassword>{}</p:DigestPassword>\
<p:AccessPermission>1</p:AccessPermission>{realms_xml}",
            xml_text(user),
            base64_encode(&ha1)
        );
        let xml = self
            .client()
            .call(
                &format!("{AMT}AMT_AuthorizationService"),
                "AddUserAclEntryEx",
                &[("Name", SERVICE)],
                &input,
            )
            .await?;
        match field_u32(&xml, "ReturnValue")? {
            0 => field_u32(&xml, "Handle"),
            code => Err(Error::ReturnValue {
                method: "AddUserAclEntryEx",
                code,
                meaning: acl_meaning(code),
            }),
        }
    }

    pub async fn remove_account(&self, handle: u32) -> Result<()> {
        if self
            .accounts()
            .await?
            .iter()
            .any(|a| a.handle == handle && a.system)
        {
            return Err(Error::InvalidArgument(
                "that is one of AMT's internal accounts and must not be removed".into(),
            ));
        }
        let xml = self
            .client()
            .call(
                &format!("{AMT}AMT_AuthorizationService"),
                "RemoveUserAclEntry",
                &[("Name", SERVICE)],
                &format!("<p:Handle>{handle}</p:Handle>"),
            )
            .await?;
        match field_u32(&xml, "ReturnValue")? {
            0 => Ok(()),
            code => Err(Error::ReturnValue {
                method: "RemoveUserAclEntry",
                code,
                meaning: acl_meaning(code),
            }),
        }
    }
}

fn acl_meaning(code: u32) -> Option<&'static str> {
    match code {
        2054 => Some("invalid user name"),
        2058 => Some("maximum number of users reached"),
        2065 => Some("user name already in use"),
        2075 => Some("non-unique or invalid realm"),
        2076 => Some("password does not meet AMT's strength rules"),
        _ => None,
    }
}

pub(crate) fn check_password(p: &str) -> Result<()> {
    let ok = (8..=32).contains(&p.len())
        && p.bytes().any(|b| b.is_ascii_uppercase())
        && p.bytes().any(|b| b.is_ascii_lowercase())
        && p.bytes().any(|b| b.is_ascii_digit())
        && p.bytes().any(|b| b.is_ascii_punctuation() && b != b'_')
        && !p.bytes().any(|b| matches!(b, b'"' | b',' | b':'));
    if ok {
        Ok(())
    } else {
        Err(Error::InvalidArgument(
            "password: 8-32 characters with upper, lower, digit and a symbol (not _ \" , :)".into(),
        ))
    }
}

pub(crate) fn base64_encode(b: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in b.chunks(3) {
        let n = chunk.iter().fold(0u32, |acc, &x| (acc << 8) | x as u32) << (8 * (3 - chunk.len()));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(T[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_rfc4648() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"a"), "YQ==");
        assert_eq!(base64_encode(b"ab"), "YWI=");
        assert_eq!(base64_encode(b"abc"), "YWJj");
        assert_eq!(base64_encode(b"abcdef"), "YWJjZGVm");
    }

    #[test]
    fn password_rules() {
        assert!(check_password("Strong!Pass9").is_ok());
        assert!(check_password("weakpass").is_err());
        assert!(check_password("NoSymbol99").is_err());
        assert!(check_password("Under_Score9").is_err());
        assert!(check_password("Has:Colon9").is_err());
    }

    #[test]
    fn realm_values_roundtrip() {
        for r in READ_ONLY_REALMS {
            assert_eq!(Realm::from_value(r.value()), r);
        }
    }
}
