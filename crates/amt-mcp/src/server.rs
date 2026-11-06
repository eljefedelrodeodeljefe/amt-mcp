use std::time::Duration;

use amt::{Client, Device, Endpoint, IderSession, KvmSession, Secret, SolSession};
use anyhow::Context;
use base64::Engine;
use rmcp::{
    RoleServer, ServerHandler,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{
        AnnotateAble, CallToolResult, Content, ErrorCode, ErrorData, ListResourcesResult,
        PaginatedRequestParams, RawResource, ReadResourceRequestParams, ReadResourceResult,
        ResourceContents, ServerCapabilities, ServerInfo,
    },
    service::RequestContext,
    tool, tool_handler, tool_router,
};
use serde_json::Value;
use tokio::sync::Mutex;

use crate::config::{self, read_secret};
use crate::error::tool_error;
use crate::guides;
use crate::logging;
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
    kvm: Mutex<Option<KvmSession>>,
    /// KVM over the redirection port (default) or the VNC port 5900.
    kvm_over_vnc: bool,
    /// The RFB password set by kvm_enable, or read from AMT_RFB_PASSWORD_FILE.
    rfb_password: Mutex<Option<Secret>>,
    ider: Mutex<Option<IderSession>>,
}

impl AmtServer {
    pub fn from_env() -> anyhow::Result<Self> {
        let host = std::env::var("AMT_HOST").context("AMT_HOST not set")?;
        let user = std::env::var("AMT_USER").unwrap_or_else(|_| "admin".into());
        let password = match (
            std::env::var("AMT_PASSWORD_FILE"),
            std::env::var("AMT_PASSWORD"),
        ) {
            (Ok(path), _) => read_secret(&path, "AMT_PASSWORD_FILE")?,
            (Err(_), Ok(p)) => Secret::from(p),
            _ => anyhow::bail!("set AMT_PASSWORD_FILE (preferred) or AMT_PASSWORD"),
        };
        let timeout_ms: u64 = std::env::var("AMT_TIMEOUT_MS")
            .unwrap_or_else(|_| "15000".into())
            .parse()
            .context("AMT_TIMEOUT_MS must be a whole number of milliseconds")?;
        let port = env_port("AMT_PORT", amt::wsman::DEFAULT_PORT)?;
        let sol_port = env_port("AMT_SOL_PORT", amt::sol::DEFAULT_PORT)?;
        let writes_enabled = config::bool_env("AMT_ALLOW_WRITES", false)?;

        let mut ep = Endpoint::new(host.clone(), user, password);
        ep.port = port;
        ep.allow_plaintext_auth = config::bool_env("AMT_ALLOW_PLAINTEXT_AUTH", false)?;
        if ep.allow_plaintext_auth {
            tracing::warn!(
                "AMT_ALLOW_PLAINTEXT_AUTH is set: a device that offers only plaintext redirection auth gets the admin password in clear"
            );
        }
        ep.timeout = Duration::from_millis(timeout_ms);
        let timeout = ep.timeout;
        let reader = match (
            std::env::var("AMT_READ_USER"),
            std::env::var("AMT_READ_PASSWORD_FILE"),
        ) {
            (Ok(u), Ok(path)) => {
                let p = read_secret(&path, "AMT_READ_PASSWORD_FILE")?;
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
            kvm: Mutex::new(None),
            kvm_over_vnc: match std::env::var("AMT_KVM_TRANSPORT").as_deref() {
                Ok("vnc") => true,
                Ok("redirection") | Err(_) => false,
                Ok(other) => {
                    anyhow::bail!("AMT_KVM_TRANSPORT must be redirection or vnc, not {other}")
                }
            },
            rfb_password: Mutex::new(match std::env::var("AMT_RFB_PASSWORD_FILE") {
                Ok(path) => Some(read_secret(&path, "AMT_RFB_PASSWORD_FILE")?),
                Err(_) => None,
            }),
            ider: Mutex::new(None),
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

    /// The KVM session, opened on first use over the configured transport.
    async fn kvm_session(
        &self,
    ) -> Result<tokio::sync::MutexGuard<'_, Option<KvmSession>>, ErrorData> {
        let mut slot = self.kvm.lock().await;
        if slot.is_none() {
            let ep = self.device.client().endpoint();
            let session = if self.kvm_over_vnc {
                let pw = self.rfb_password.lock().await.clone().ok_or_else(|| {
                    ErrorData::new(
                        ErrorCode::INVALID_REQUEST,
                        "no RFB password known — call kvm_enable with rfb_password_file or set AMT_RFB_PASSWORD_FILE",
                        None,
                    )
                })?;
                KvmSession::open(&ep.host, amt::kvm::VNC_PORT, pw.expose(), self.timeout).await
            } else {
                KvmSession::open_redirection(ep, self.sol_port, self.timeout).await
            }
            .map_err(|e| tool_error(e.into()))?;
            *slot = Some(session);
        }
        Ok(slot)
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
        let res = tools::device::sync_clock(&self.device).await;
        logging::write_tool("sync_clock", "", &res);
        let data = res.map_err(tool_error)?;
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
        let res = tools::device::add_alarm(&self.device, &p).await;
        logging::write_tool(
            "add_alarm",
            &format!("name={} start={}", p.name, p.start),
            &res,
        );
        let data = res.map_err(tool_error)?;
        Ok(Self::ok(&data))
    }

    #[tool(description = "Delete a scheduled wake alarm (IPS_AlarmClockOccurrence Delete)")]
    async fn delete_alarm(
        &self,
        Parameters(p): Parameters<AlarmNameParams>,
    ) -> Result<CallToolResult, ErrorData> {
        self.guard_write()?;
        let res = tools::device::delete_alarm(&self.device, &p.name).await;
        logging::write_tool("delete_alarm", &format!("name={}", p.name), &res);
        let data = res.map_err(tool_error)?;
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
        let res = tools::device::add_account(&self.device, &p).await;
        logging::write_tool(
            "add_account",
            &format!("user={} realms={:?}", p.user, p.realms),
            &res,
        );
        let data = res.map_err(tool_error)?;
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
        let res = tools::device::remove_account(&self.device, p.handle).await;
        logging::write_tool("remove_account", &format!("handle={}", p.handle), &res);
        let data = res.map_err(tool_error)?;
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
        let res = tools::device::set_next_boot(&self.device, &p).await;
        logging::write_tool(
            "set_next_boot",
            &format!("target={:?} sol={:?}", p.target, p.sol),
            &res,
        );
        let data = res.map_err(tool_error)?;
        Ok(Self::ok(&data))
    }

    #[tool(
        description = "List the operator guides (setup, security, recipes, troubleshooting). Read them before provisioning, before exposing AMT on a network, or when a step fails; they mark the steps that need a person at the device"
    )]
    async fn list_guides(&self) -> Result<CallToolResult, ErrorData> {
        let list: Vec<Value> = guides::GUIDES
            .iter()
            .map(|g| serde_json::json!({ "name": g.name, "title": g.title, "description": g.description }))
            .collect();
        Ok(Self::ok(&serde_json::json!({ "guides": list })))
    }

    #[tool(description = "Read one operator guide in full (markdown)")]
    async fn get_guide(
        &self,
        Parameters(p): Parameters<GuideParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let g = guides::find(&p.name).ok_or_else(|| {
            ErrorData::new(
                ErrorCode::INVALID_PARAMS,
                format!("no guide {:?}; see list_guides", p.name),
                None,
            )
        })?;
        Ok(CallToolResult::success(vec![Content::text(g.text)]))
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
        let res = tools::device::power(&self.device, p.action).await;
        logging::write_tool("power", &format!("action={:?}", p.action), &res);
        let data = res.map_err(tool_error)?;
        Ok(Self::ok(&data))
    }

    // ── User consent ──────────────────────────────────────────────────────────

    #[tool(
        description = "Ask AMT to show a 6-digit user-consent code on the device's own display (IPS_OptInService.StartOptIn). Required before SOL, IDE-R or KVM when the consent policy is not 'none'. Someone at the device must read the code"
    )]
    async fn consent_request(&self) -> Result<CallToolResult, ErrorData> {
        self.guard_write()?;
        let res = tools::device::consent_request(&self.device).await;
        logging::write_tool("consent_request", "", &res);
        let data = res.map_err(tool_error)?;
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
        let res = tools::device::consent_submit(&self.device, &p.code).await;
        logging::write_tool("consent_submit", "", &res);
        let data = res.map_err(tool_error)?;
        Ok(Self::ok(&data))
    }

    #[tool(
        description = "Withdraw a pending or granted user consent (IPS_OptInService.CancelOptIn)"
    )]
    async fn consent_cancel(&self) -> Result<CallToolResult, ErrorData> {
        self.guard_write()?;
        let res = tools::device::consent_cancel(&self.device).await;
        logging::write_tool("consent_cancel", "", &res);
        let data = res.map_err(tool_error)?;
        Ok(Self::ok(&data))
    }

    // ── Serial-over-LAN ───────────────────────────────────────────────────────

    #[tool(
        description = "Open the redirection listener on 16994 that SOL and IDE-R need (AMT_RedirectionService ListenerEnabled=true). SOL itself must already be enabled in the device's AMT features"
    )]
    async fn enable_sol_listener(&self) -> Result<CallToolResult, ErrorData> {
        self.guard_write()?;
        let res = tools::device::enable_sol_listener(&self.device).await;
        logging::write_tool("enable_sol_listener", "", &res);
        let data = res.map_err(tool_error)?;
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
        let res =
            SolSession::open(self.device.client().endpoint(), self.sol_port, self.timeout).await;
        logging::write_tool("sol_open", "", &res);
        let session = res.map_err(|e| tool_error(e.into()))?;
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

    // ── KVM ───────────────────────────────────────────────────────────────────

    #[tool(
        description = "Enable the KVM service (CIM_KVMRedirectionSAP.RequestStateChange 2). With rfb_password_file it also opens the standard VNC port 5900 with that RFB password (IPS_KVMRedirectionSettingData Is5900PortEnabled/RFBPassword), needed only for AMT_KVM_TRANSPORT=vnc"
    )]
    async fn kvm_enable(
        &self,
        Parameters(p): Parameters<KvmEnableParams>,
    ) -> Result<CallToolResult, ErrorData> {
        self.guard_write()?;
        let state = match &p.rfb_password_file {
            Some(path) => {
                let pw = read_secret(path, "rfb_password_file").map_err(tool_error)?;
                let res = self.device.enable_kvm(pw.expose()).await;
                logging::write_tool("kvm_enable", "port_5900=true", &res);
                let state = res.map_err(|e| tool_error(e.into()))?;
                *self.rfb_password.lock().await = Some(pw);
                state
            }
            None => {
                let res = self.device.enable_kvm_service().await;
                logging::write_tool("kvm_enable", "port_5900=unchanged", &res);
                res.map_err(|e| tool_error(e.into()))?
            }
        };
        Ok(Self::ok(&serde_json::to_value(state).unwrap_or_default()))
    }

    #[tool(
        description = "Close the VNC port and disable the KVM service (CIM_KVMRedirectionSAP.RequestStateChange 3)"
    )]
    async fn kvm_disable(&self) -> Result<CallToolResult, ErrorData> {
        self.guard_write()?;
        if let Some(k) = self.kvm.lock().await.take() {
            k.close().await;
        }
        let res = self.device.disable_kvm().await;
        logging::write_tool("kvm_disable", "", &res);
        let state = res.map_err(|e| tool_error(e.into()))?;
        Ok(Self::ok(&serde_json::to_value(state).unwrap_or_default()))
    }

    #[tool(
        description = "Screenshot of the device's display over KVM, returned as a PNG image: BIOS setup, boot loader, installer or desktop. Uses KVM inside a redirection session on 16994 (default) or the VNC port (AMT_KVM_TRANSPORT=vnc). Opens the session on first use. In client control mode grant user consent first. AMT's KVM framebuffer is limited to about 9.2 MB (3840x2160 is too large)"
    )]
    async fn kvm_screenshot(&self) -> Result<CallToolResult, ErrorData> {
        self.guard_write()?;
        let mut slot = self.kvm_session().await?;
        let kvm = slot.as_mut().ok_or_else(Self::no_session)?;
        match kvm.screenshot().await {
            Ok(png) => {
                let (w, h) = kvm.size();
                Ok(CallToolResult::success(vec![
                    Content::image(
                        base64::engine::general_purpose::STANDARD.encode(&png),
                        "image/png",
                    ),
                    Content::text(format!("{w}x{h}")),
                ]))
            }
            Err(e) => {
                *slot = None;
                Err(tool_error(e.into()))
            }
        }
    }

    #[tool(
        description = "Type on the device's keyboard over KVM. Text plus named keys in braces, e.g. \"{f1}\" to enter BIOS setup or \"root{enter}\". Follow with kvm_screenshot"
    )]
    async fn kvm_send_keys(
        &self,
        Parameters(p): Parameters<KvmKeysParams>,
    ) -> Result<CallToolResult, ErrorData> {
        self.guard_write()?;
        let keys = amt::kvm::keysyms(&p.keys).map_err(|e| tool_error(e.into()))?;
        let mut slot = self.kvm_session().await?;
        let kvm = slot.as_mut().ok_or_else(Self::no_session)?;
        if let Err(e) = kvm.keys(&keys).await {
            *slot = None;
            return Err(tool_error(e.into()));
        }
        Ok(Self::ok(&serde_json::json!({ "keys_sent": keys.len() })))
    }

    #[tool(description = "Close the KVM session (the VNC port stays enabled)")]
    async fn kvm_close(&self) -> Result<CallToolResult, ErrorData> {
        let was_open = match self.kvm.lock().await.take() {
            Some(k) => {
                k.close().await;
                true
            }
            None => false,
        };
        Ok(Self::ok(&serde_json::json!({ "closed": was_open })))
    }

    // ── IDE-R ─────────────────────────────────────────────────────────────────

    #[tool(
        description = "Serve a local ISO to the device as a CD-ROM over IDE redirection (redirection protocol, session IDER). Typical boot: consent_request/consent_submit, ider_start (on_reboot), set_next_boot ider_cd, power reset. The session keeps running until ider_stop"
    )]
    async fn ider_start(
        &self,
        Parameters(p): Parameters<IderStartParams>,
    ) -> Result<CallToolResult, ErrorData> {
        self.guard_write()?;
        let mut slot = self.ider.lock().await;
        if let Some(s) = slot.as_ref()
            && s.status().await.closed.is_none()
        {
            return Err(ErrorData::new(
                ErrorCode::INVALID_REQUEST,
                "an IDE-R session is already running — ider_stop first",
                None,
            ));
        }
        let start = p.start.unwrap_or(amt::IderStart::OnReboot);
        let res = IderSession::open(
            self.device.client().endpoint(),
            self.sol_port,
            std::path::Path::new(&p.iso_path),
            start,
            self.timeout,
        )
        .await;
        logging::write_tool(
            "ider_start",
            &format!("iso={} start={start:?}", p.iso_path),
            &res,
        );
        let session = res.map_err(|e| tool_error(e.into()))?;
        let status = session.status().await;
        *slot = Some(session);
        Ok(Self::ok(&serde_json::to_value(status).unwrap_or_default()))
    }

    #[tool(
        description = "IDE-R session progress: whether AMT enabled the drive, commands handled, blocks read, resets, and why it closed"
    )]
    async fn ider_status(&self) -> Result<CallToolResult, ErrorData> {
        let slot = self.ider.lock().await;
        let s = slot.as_ref().ok_or_else(|| {
            ErrorData::new(
                ErrorCode::INVALID_REQUEST,
                "no IDE-R session — call ider_start first",
                None,
            )
        })?;
        Ok(Self::ok(
            &serde_json::to_value(s.status().await).unwrap_or_default(),
        ))
    }

    #[tool(description = "End the IDE-R session; the device loses the CD-ROM")]
    async fn ider_stop(&self) -> Result<CallToolResult, ErrorData> {
        let was_open = match self.ider.lock().await.take() {
            Some(s) => {
                s.close().await;
                true
            }
            None => false,
        };
        Ok(Self::ok(&serde_json::json!({ "stopped": was_open })))
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for AmtServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(
            ServerCapabilities::builder()
                .enable_tools()
                .enable_resources()
                .build(),
        )
        .with_instructions(INSTRUCTIONS)
    }

    async fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, ErrorData> {
        let resources = guides::GUIDES
            .iter()
            .map(|g| {
                RawResource::new(format!("{}{}", guides::URI_PREFIX, g.name), g.name)
                    .with_title(g.title)
                    .with_description(g.description)
                    .with_mime_type("text/markdown")
                    .no_annotation()
            })
            .collect();
        Ok(ListResourcesResult::with_all_items(resources))
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResult, ErrorData> {
        let g = guides::find(&request.uri).ok_or_else(|| {
            ErrorData::new(
                ErrorCode::INVALID_PARAMS,
                format!("no resource {}", request.uri),
                None,
            )
        })?;
        Ok(ReadResourceResult::new(vec![
            ResourceContents::TextResourceContents {
                uri: request.uri,
                mime_type: Some("text/markdown".into()),
                text: g.text.to_string(),
                meta: None,
            },
        ]))
    }
}

const INSTRUCTIONS: &str = concat!(
    "Intel AMT out-of-band management over WS-Man (HTTP digest, port 16992) and the ",
    "redirection protocol (Serial-over-LAN, port 16994). Configure with AMT_HOST and ",
    "AMT_PASSWORD_FILE (or AMT_PASSWORD). Optional: AMT_USER (default admin), AMT_PORT, ",
    "AMT_SOL_PORT, AMT_TIMEOUT_MS (default 15000), AMT_READ_USER + AMT_READ_PASSWORD_FILE ",
    "(a least-privilege account used for read tools), AMT_KVM_TRANSPORT (redirection or vnc), AMT_RFB_PASSWORD_FILE (KVM over vnc), AMT_ALLOW_PLAINTEXT_AUTH (default false; lets SOL, IDE-R and KVM fall back to sending the password in clear when a device offers no digest), AMT_ALLOW_WRITES (default false — must ",
    "be 'true' for power, consent and console tools; true/false, 1/0 or yes/no, anything else ",
    "stops the server). ",
    "Power actions are immediate and bypass the OS. In client control mode every SOL, ",
    "IDE-R or KVM session needs a 6-digit consent code that only someone at the device's ",
    "display can read: call consent_request, ask the user for the code, then ",
    "consent_submit, then sol_open. ",
    "Operator guides (setup incl. steps that need a human, security, recipes, troubleshooting): ",
    "list_guides / get_guide, also as resources amt://guide/<name>.",
);

fn env_port(key: &str, default: u16) -> anyhow::Result<u16> {
    match std::env::var(key) {
        Ok(p) => p
            .parse()
            .with_context(|| format!("{key} must be a valid port number")),
        Err(_) => Ok(default),
    }
}
