use std::time::Duration;

use amt::{Client, Device, Endpoint, SolSession};
use anyhow::Context;
use rmcp::{
    ServerHandler,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{CallToolResult, Content, ErrorCode, ErrorData, ServerCapabilities, ServerInfo},
    tool, tool_handler, tool_router,
};
use serde_json::Value;
use tokio::sync::Mutex;

use crate::error::tool_error;
use crate::params::*;
use crate::tools;

pub struct AmtServer {
    tool_router: ToolRouter<Self>,
    device: Device,
    /// Least-privilege account for read tools, if configured
    /// (AMT_READ_USER + AMT_READ_PASSWORD_FILE). Falls back to `device`.
    reader: Option<Device>,
    sol_port: u16,
    timeout: Duration,
    writes_enabled: bool,
    /// At most one SOL session per process; AMT allows one per device anyway.
    sol: Mutex<Option<SolSession>>,
}

impl AmtServer {
    pub fn from_env() -> anyhow::Result<Self> {
        let host = std::env::var("AMT_HOST").context("AMT_HOST not set")?;
        let user = std::env::var("AMT_USER").unwrap_or_else(|_| "admin".into());
        let password = match (
            std::env::var("AMT_PASSWORD_FILE"),
            std::env::var("AMT_PASSWORD"),
        ) {
            (Ok(path), _) => std::fs::read_to_string(&path)
                .with_context(|| format!("reading AMT_PASSWORD_FILE {path}"))?
                .trim_end_matches(['\r', '\n'])
                .to_string(),
            (Err(_), Ok(p)) => p,
            _ => anyhow::bail!("set AMT_PASSWORD_FILE (preferred) or AMT_PASSWORD"),
        };
        let timeout_ms: u64 = std::env::var("AMT_TIMEOUT_MS")
            .unwrap_or_else(|_| "15000".into())
            .parse()
            .context("AMT_TIMEOUT_MS must be a whole number of milliseconds")?;
        let port = env_port("AMT_PORT", amt::wsman::DEFAULT_PORT)?;
        let sol_port = env_port("AMT_SOL_PORT", amt::sol::DEFAULT_PORT)?;
        let writes_enabled = std::env::var("AMT_ALLOW_WRITES")
            .map(|v| matches!(v.as_str(), "true" | "1" | "yes"))
            .unwrap_or(false);

        let mut ep = Endpoint::new(host.clone(), user, password);
        ep.port = port;
        ep.timeout = Duration::from_millis(timeout_ms);
        let timeout = ep.timeout;
        let reader = match (
            std::env::var("AMT_READ_USER"),
            std::env::var("AMT_READ_PASSWORD_FILE"),
        ) {
            (Ok(u), Ok(path)) => {
                let p = std::fs::read_to_string(&path)
                    .with_context(|| format!("reading AMT_READ_PASSWORD_FILE {path}"))?
                    .trim_end_matches(['\r', '\n'])
                    .to_string();
                let mut r = Endpoint::new(host, u, p);
                r.port = port;
                r.timeout = timeout;
                Some(Device::new(Client::new(r)?))
            }
            (Err(_), Err(_)) => None,
            _ => anyhow::bail!("AMT_READ_USER and AMT_READ_PASSWORD_FILE must be set together"),
        };
        Ok(Self {
            tool_router: Self::tool_router(),
            device: Device::new(Client::new(ep)?),
            reader,
            sol_port,
            timeout,
            writes_enabled,
            sol: Mutex::new(None),
        })
    }

    /// The device handle for read-only tools.
    fn reads(&self) -> &Device {
        self.reader.as_ref().unwrap_or(&self.device)
    }

    fn ok(value: &Value) -> CallToolResult {
        CallToolResult::success(vec![Content::text(
            serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string()),
        )])
    }

    fn guard_write(&self) -> Result<(), ErrorData> {
        if self.writes_enabled {
            Ok(())
        } else {
            Err(ErrorData::new(
                ErrorCode::INVALID_REQUEST,
                "write operations are disabled — set AMT_ALLOW_WRITES=true to enable",
                None,
            ))
        }
    }

    fn no_session() -> ErrorData {
        ErrorData::new(
            ErrorCode::INVALID_REQUEST,
            "no SOL session open — call sol_open first",
            None,
        )
    }
}

#[tool_router]
impl AmtServer {
    // ── Reads ─────────────────────────────────────────────────────────────────

    #[tool(
        description = "Get the device's power state (CIM_AssociatedPowerManagementService), control mode (IPS_HostBasedSetupService), user-consent state and policy (IPS_OptInService), redirection (AMT_RedirectionService: SOL, IDE-R, listener) and KVM settings (IPS_KVMRedirectionSettingData)"
    )]
    async fn get_status(&self) -> Result<CallToolResult, ErrorData> {
        let data = tools::device::status(self.reads())
            .await
            .map_err(tool_error)?;
        Ok(Self::ok(&data))
    }

    #[tool(
        description = "Hardware inventory read out of band: BIOS (CIM_BIOSElement), chassis model and serial (CIM_Chassis), CPUs (CIM_Processor), memory modules (CIM_PhysicalMemory), AMT firmware version (CIM_SoftwareIdentity). Works with the OS down"
    )]
    async fn get_inventory(&self) -> Result<CallToolResult, ErrorData> {
        let data = tools::device::inventory(self.reads())
            .await
            .map_err(tool_error)?;
        Ok(Self::ok(&data))
    }

    #[tool(
        description = "AMT network view: host name, digest realm, ping response (AMT_GeneralSettings) and per-port MAC, link, DHCP, address and whether AMT shares the host's MAC/IP (AMT_EthernetPortSettings). Read-only"
    )]
    async fn get_network(&self) -> Result<CallToolResult, ErrorData> {
        let data = tools::device::network(self.reads())
            .await
            .map_err(tool_error)?;
        Ok(Self::ok(&data))
    }

    #[tool(
        description = "AMT's clock against this machine's (AMT_TimeSynchronizationService.GetLowAccuracyTimeSynch). Event and audit log times use AMT's clock"
    )]
    async fn get_clock(&self) -> Result<CallToolResult, ErrorData> {
        let data = tools::device::clock(self.reads())
            .await
            .map_err(tool_error)?;
        Ok(Self::ok(&data))
    }

    #[tool(
        description = "Platform event log (AMT_MessageLog.GetRecords): BIOS/POST progress, firmware errors, boot failures, watchdog, newest last. Times are AMT-clock Unix seconds"
    )]
    async fn get_event_log(
        &self,
        Parameters(p): Parameters<LogParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let data = tools::device::event_log(self.reads(), p.limit)
            .await
            .map_err(tool_error)?;
        Ok(Self::ok(&data))
    }

    #[tool(
        description = "Audit log (AMT_AuditLog.ReadRecords): who used AMT and how — power actions, SOL/IDE-R/KVM sessions, consent codes, account and TLS changes — with the initiating user and address, newest last"
    )]
    async fn get_audit_log(
        &self,
        Parameters(p): Parameters<LogParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let data = tools::device::audit_log(self.reads(), p.limit)
            .await
            .map_err(tool_error)?;
        Ok(Self::ok(&data))
    }

    #[tool(description = "Scheduled wake alarms (IPS_AlarmClockOccurrence)")]
    async fn list_alarms(&self) -> Result<CallToolResult, ErrorData> {
        let data = tools::device::alarms(self.reads())
            .await
            .map_err(tool_error)?;
        Ok(Self::ok(&data))
    }

    #[tool(
        description = "AMT user accounts besides the built-in admin, with their realms (AMT_AuthorizationService.EnumerateUserAclEntries / GetUserAclEntryEx)"
    )]
    async fn list_accounts(&self) -> Result<CallToolResult, ErrorData> {
        let data = tools::device::accounts(self.reads())
            .await
            .map_err(tool_error)?;
        Ok(Self::ok(&data))
    }

    #[tool(
        description = "Boot capabilities (AMT_BootCapabilities: BIOS setup, PXE, hard drive, CD/DVD, IDE-R, SOL) and the pending one-time boot override (AMT_BootSettingData)"
    )]
    async fn get_boot_options(&self) -> Result<CallToolResult, ErrorData> {
        let data = tools::device::boot_options(self.reads())
            .await
            .map_err(tool_error)?;
        Ok(Self::ok(&data))
    }

    // ── Clock, alarms, accounts ───────────────────────────────────────────────

    #[tool(
        description = "Set AMT's clock to this machine's (AMT_TimeSynchronizationService.SetHighAccuracyTimeSynch)"
    )]
    async fn sync_clock(&self) -> Result<CallToolResult, ErrorData> {
        self.guard_write()?;
        let data = tools::device::sync_clock(&self.device)
            .await
            .map_err(tool_error)?;
        Ok(Self::ok(&data))
    }

    #[tool(
        description = "Schedule a wake: AMT powers the machine on at a UTC time, once or repeating (AMT_AlarmClockService.AddAlarm). Confirm with the user first"
    )]
    async fn add_alarm(
        &self,
        Parameters(p): Parameters<AddAlarmParams>,
    ) -> Result<CallToolResult, ErrorData> {
        self.guard_write()?;
        let data = tools::device::add_alarm(&self.device, &p)
            .await
            .map_err(tool_error)?;
        Ok(Self::ok(&data))
    }

    #[tool(description = "Delete a scheduled wake alarm (IPS_AlarmClockOccurrence Delete)")]
    async fn delete_alarm(
        &self,
        Parameters(p): Parameters<AlarmNameParams>,
    ) -> Result<CallToolResult, ErrorData> {
        self.guard_write()?;
        let data = tools::device::delete_alarm(&self.device, &p.name)
            .await
            .map_err(tool_error)?;
        Ok(Self::ok(&data))
    }

    #[tool(
        description = "Add an AMT digest account limited to the given realms (AMT_AuthorizationService.AddUserAclEntryEx). Omit realms for a read-only monitoring account. The password is read from password_file, never passed in the conversation"
    )]
    async fn add_account(
        &self,
        Parameters(p): Parameters<AddAccountParams>,
    ) -> Result<CallToolResult, ErrorData> {
        self.guard_write()?;
        let data = tools::device::add_account(&self.device, &p)
            .await
            .map_err(tool_error)?;
        Ok(Self::ok(&data))
    }

    #[tool(
        description = "Remove an AMT account by handle (AMT_AuthorizationService.RemoveUserAclEntry)"
    )]
    async fn remove_account(
        &self,
        Parameters(p): Parameters<AccountHandleParams>,
    ) -> Result<CallToolResult, ErrorData> {
        self.guard_write()?;
        let data = tools::device::remove_account(&self.device, p.handle)
            .await
            .map_err(tool_error)?;
        Ok(Self::ok(&data))
    }

    // ── Boot ──────────────────────────────────────────────────────────────────

    #[tool(
        description = "Set a one-time boot override: bios_setup, pxe, hard_drive, cd_dvd, ider_cd, ider_floppy, or default to clear it; sol=true redirects the BIOS console to SOL (AMT_BootSettingData Put, CIM_BootService.SetBootConfigRole, CIM_BootConfigSetting.ChangeBootOrder). Does not reboot — follow with power. In client control mode, forced sources need user consent first"
    )]
    async fn set_next_boot(
        &self,
        Parameters(p): Parameters<NextBootParams>,
    ) -> Result<CallToolResult, ErrorData> {
        self.guard_write()?;
        let data = tools::device::set_next_boot(&self.device, &p)
            .await
            .map_err(tool_error)?;
        Ok(Self::ok(&data))
    }

    // ── Power ─────────────────────────────────────────────────────────────────

    #[tool(
        description = "Out-of-band power action (CIM_PowerManagementService.RequestPowerStateChange): on, off, cycle, reset (immediate, the OS is not asked) or graceful_off, graceful_reset (the OS is asked to shut down; needs Intel's in-band agent in the OS, refused otherwise). Needs no user consent. Read get_status and confirm with the user first"
    )]
    async fn power(
        &self,
        Parameters(p): Parameters<PowerParams>,
    ) -> Result<CallToolResult, ErrorData> {
        self.guard_write()?;
        let data = tools::device::power(&self.device, p.action)
            .await
            .map_err(tool_error)?;
        Ok(Self::ok(&data))
    }

    // ── User consent ──────────────────────────────────────────────────────────

    #[tool(
        description = "Ask AMT to show a 6-digit user-consent code on the device's own display (IPS_OptInService.StartOptIn). Required before SOL, IDE-R or KVM when the consent policy is not 'none'. Someone at the device must read the code"
    )]
    async fn consent_request(&self) -> Result<CallToolResult, ErrorData> {
        self.guard_write()?;
        let data = tools::device::consent_request(&self.device)
            .await
            .map_err(tool_error)?;
        Ok(Self::ok(&data))
    }

    #[tool(
        description = "Submit the 6-digit code read off the device's display (IPS_OptInService.SendOptInCode). The code expires about two minutes after it appears"
    )]
    async fn consent_submit(
        &self,
        Parameters(p): Parameters<ConsentCodeParams>,
    ) -> Result<CallToolResult, ErrorData> {
        self.guard_write()?;
        let data = tools::device::consent_submit(&self.device, &p.code)
            .await
            .map_err(tool_error)?;
        Ok(Self::ok(&data))
    }

    #[tool(
        description = "Withdraw a pending or granted user consent (IPS_OptInService.CancelOptIn)"
    )]
    async fn consent_cancel(&self) -> Result<CallToolResult, ErrorData> {
        self.guard_write()?;
        let data = tools::device::consent_cancel(&self.device)
            .await
            .map_err(tool_error)?;
        Ok(Self::ok(&data))
    }

    // ── Serial-over-LAN ───────────────────────────────────────────────────────

    #[tool(
        description = "Open the redirection listener on 16994 that SOL and IDE-R need (AMT_RedirectionService ListenerEnabled=true). SOL itself must already be enabled in the device's AMT features"
    )]
    async fn enable_sol_listener(&self) -> Result<CallToolResult, ErrorData> {
        self.guard_write()?;
        let data = tools::device::enable_sol_listener(&self.device)
            .await
            .map_err(tool_error)?;
        Ok(Self::ok(&data))
    }

    #[tool(
        description = "Open a Serial-over-LAN console session (redirection protocol on 16994, digest authentication). Grant user consent first if the policy requires it. Output is buffered until sol_read"
    )]
    async fn sol_open(&self) -> Result<CallToolResult, ErrorData> {
        self.guard_write()?;
        let mut slot = self.sol.lock().await;
        if let Some(s) = slot.as_ref()
            && s.is_closed().await.is_none()
        {
            return Ok(Self::ok(
                &serde_json::json!({ "open": true, "reused": true }),
            ));
        }
        let session =
            SolSession::open(self.device.client().endpoint(), self.sol_port, self.timeout)
                .await
                .map_err(|e| tool_error(e.into()))?;
        *slot = Some(session);
        Ok(Self::ok(
            &serde_json::json!({ "open": true, "reused": false }),
        ))
    }

    #[tool(
        description = "Read what the serial console printed since the last read. Waits up to wait_ms for output, then until it has been quiet for settle_ms"
    )]
    async fn sol_read(
        &self,
        Parameters(p): Parameters<SolReadParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let slot = self.sol.lock().await;
        let s = slot.as_ref().ok_or_else(Self::no_session)?;
        let data = tools::sol::read(s, &p).await.map_err(tool_error)?;
        Ok(Self::ok(&data))
    }

    #[tool(
        description = "Type on the serial console. Appends Enter unless enter=false; set escapes=true for control keys (\\e[A is Up, \\x03 is Ctrl-C). Follow with sol_read to see the result"
    )]
    async fn sol_send(
        &self,
        Parameters(p): Parameters<SolSendParams>,
    ) -> Result<CallToolResult, ErrorData> {
        self.guard_write()?;
        let slot = self.sol.lock().await;
        let s = slot.as_ref().ok_or_else(Self::no_session)?;
        let data = tools::sol::send(s, &p).await.map_err(tool_error)?;
        Ok(Self::ok(&data))
    }

    #[tool(description = "Close the Serial-over-LAN session")]
    async fn sol_close(&self) -> Result<CallToolResult, ErrorData> {
        let session = self.sol.lock().await.take();
        let was_open = session.is_some();
        if let Some(s) = session {
            s.close().await;
        }
        Ok(Self::ok(&serde_json::json!({ "closed": was_open })))
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for AmtServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_instructions(INSTRUCTIONS)
    }
}

const INSTRUCTIONS: &str = concat!(
    "Intel AMT out-of-band management over WS-Man (HTTP digest, port 16992) and the ",
    "redirection protocol (Serial-over-LAN, port 16994). Configure with AMT_HOST and ",
    "AMT_PASSWORD_FILE (or AMT_PASSWORD). Optional: AMT_USER (default admin), AMT_PORT, ",
    "AMT_SOL_PORT, AMT_TIMEOUT_MS (default 15000), AMT_READ_USER + AMT_READ_PASSWORD_FILE ",
    "(a least-privilege account used for read tools), AMT_ALLOW_WRITES (default false — must ",
    "be 'true' for power, consent and console tools). ",
    "Power actions are immediate and bypass the OS. In client control mode every SOL, ",
    "IDE-R or KVM session needs a 6-digit consent code that only someone at the device's ",
    "display can read: call consent_request, ask the user for the code, then ",
    "consent_submit, then sol_open.",
);

fn env_port(key: &str, default: u16) -> anyhow::Result<u16> {
    match std::env::var(key) {
        Ok(p) => p
            .parse()
            .with_context(|| format!("{key} must be a valid port number")),
        Err(_) => Ok(default),
    }
}
