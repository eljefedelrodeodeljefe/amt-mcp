# amt-mcp

An [MCP](https://modelcontextprotocol.io) server for **Intel AMT** (vPro) out-of-band
management over AMT's own protocols: power control, user consent, Serial-over-LAN, KVM,
IDE-R remote disk, boot overrides, logs, scheduled wake and accounts. No MPS, MeshCentral
or agent on the target is needed.

Version 0.2.0 <!-- x-release-please-version -->

## Tools

Write tools (✓) are refused unless `AMT_ALLOW_WRITES=true`.

| Area | Tool | Writes | What it does |
| --- | --- | :---: | --- |
| Status | `get_status` | | Power state, control mode, consent, SOL/IDE-R/listener and KVM settings |
| | `get_inventory` | | BIOS, chassis model/serial, CPUs, memory, AMT version (also with the OS down) |
| | `get_network` | | AMT's host name, digest realm, per-port MAC, link, DHCP, address |
| | `get_event_log` | | Platform events: BIOS/POST progress, firmware errors, boot failures |
| | `get_audit_log` | | Who used AMT: power actions, SOL/IDE-R/KVM sessions, consent, accounts |
| Power | `power` | ✓ | `on`, `off`, `cycle`, `reset` (immediate); `graceful_off`, `graceful_reset` (need Intel's OS agent) |
| | `get_boot_options` | | Boot capabilities and the pending one-time override |
| | `set_next_boot` | ✓ | Next boot: `bios_setup`, `pxe`, `hard_drive`, `cd_dvd`, `ider_cd`, `ider_floppy`, `default`; optional BIOS console on SOL |
| Consent | `consent_request` | ✓ | Shows a 6-digit code on the device's display |
| | `consent_submit` | ✓ | Submits the code read off the display |
| | `consent_cancel` | ✓ | Withdraws consent |
| Console | `enable_sol_listener` | ✓ | Opens the 16994 redirection listener |
| | `sol_open` / `sol_close` | ✓ / | Serial-over-LAN session |
| | `sol_read` | | Console output since the last read (ANSI stripped by default) |
| | `sol_send` | ✓ | Types on the console; `escapes=true` for control keys |
| KVM | `kvm_enable` / `kvm_disable` | ✓ | KVM service on/off; optionally VNC port 5900 with an RFB password |
| | `kvm_screenshot` | ✓ | The display as a PNG image |
| | `kvm_send_keys` | ✓ | Text and named keys (`{f2}`, `{enter}`, …) |
| | `kvm_close` | | Ends the KVM session |
| Remote disk | `ider_start` | ✓ | Serves a local ISO as the device's CD-ROM (IDE-R) |
| | `ider_status` / `ider_stop` | | Progress; end the session |
| Clock & wake | `get_clock` / `sync_clock` | / ✓ | AMT's clock against this machine's; set it |
| | `list_alarms` / `add_alarm` / `delete_alarm` | / ✓ / ✓ | Scheduled power-on, once or repeating |
| Accounts | `list_accounts` | | AMT accounts and their realms |
| | `add_account` / `remove_account` | ✓ | Digest accounts limited to realms (read-only by default) |
| Guides | `list_guides` / `get_guide` | | Operator guides, also as resources `amt://guide/<name>` |

## Configuration

| Variable | Default | |
| --- | --- | --- |
| `AMT_HOST` | — | Device address (AMT shares the host OS's IP in DHCP mode) |
| `AMT_PASSWORD_FILE` | — | File holding the AMT admin password. Passwords are read only from files; a set `AMT_PASSWORD` stops the server |
| `AMT_USER` | `admin` | |
| `AMT_PORT` | `16992` | WS-Man (HTTP digest) |
| `AMT_SOL_PORT` | `16994` | Redirection protocol |
| `AMT_TIMEOUT_MS` | `15000` | |
| `AMT_READ_USER` + `AMT_READ_PASSWORD_FILE` | — | A least-privilege account for read tools |
| `AMT_KVM_TRANSPORT` | `redirection` | KVM inside a redirection session on 16994, or `vnc` for port 5900 |
| `AMT_RFB_PASSWORD_FILE` | — | RFB password, only for `AMT_KVM_TRANSPORT=vnc` |
| `AMT_ALLOW_WRITES` | `false` | Must be `true` for anything that changes state |
| `AMT_ALLOW_PLAINTEXT_AUTH` | `false` | Let redirection (SOL, IDE-R, KVM) send the password in clear when a device offers no digest |

Boolean variables take `true`/`false`, `1`/`0` or `yes`/`no` in any case. Anything else
(`on`, an empty value) stops the server at startup with an error naming the variable.

```json
{
  "mcpServers": {
    "amt": {
      "command": "amt-mcp",
      "env": {
        "AMT_HOST": "192.0.2.10",
        "AMT_PASSWORD_FILE": "/home/you/.config/amt-password",
        "AMT_ALLOW_WRITES": "true"
      }
    }
  }
}
```

## Requirements on the device

- AMT provisioned. Client control mode (e.g. via Intel's `rpc activate -local -ccm`) is
  enough; admin control mode additionally allows turning user consent off.
- For SOL: the SOL feature enabled, the redirection listener open (`enable_sol_listener`),
  and a getty on the AMT SOL serial port (`8086:a363` on recent chipsets shows up as a
  `ttyS*`).

## Guides

The server carries operator guides as MCP resources (`amt://guide/<name>`) and through
`list_guides`/`get_guide`: [setup](docs/guides/setup.md) (including the steps that need a
person at the device), [security](docs/guides/security.md), [recipes](docs/guides/recipes.md)
and [troubleshooting](docs/guides/troubleshooting.md).

## User consent needs a person at the device

In client control mode AMT requires consent for every SOL, IDE-R and KVM session and
for forced boot sources, and the policy cannot be changed. The code appears **only on
the device's own display**, so someone has to be there to read it:

1. `consent_request`
2. read the code at the device, then `consent_submit`
3. `sol_open`, `sol_send`, `sol_read`

Power actions, reads and clearing a boot override need no consent.

## Known limits

- KVM: AMT's KVM framebuffer is limited to about 9.2 MB (bytes per pixel x width x
  height). At 16 bits per pixel, 3840x2160 is over it; 1920x1080 works.
- `add_alarm`: start times must be before 2038 (AMT's clock is 32-bit).

## Security

- Plain-HTTP AMT (16992/16994) carries digest-protected credentials but unencrypted
  traffic. Expose these ports only to management hosts.
- Redirection sessions use digest only. A device that offers just plaintext
  authentication (old firmware, or someone on the path stripping digest from the
  offer) is refused unless `AMT_ALLOW_PLAINTEXT_AUTH=true`.
- `power` is equivalent to the physical power button. Confirm before using it.

## Development

```bash
cargo test --all
AMT_HOST=… AMT_PASSWORD_FILE=… cargo run -p amt --example probe     # read-only status
AMT_HOST=… AMT_PASSWORD_FILE=… cargo run -p amt --example console -- request
AMT_HOST=… AMT_PASSWORD_FILE=… cargo run -p amt --example console -- open <code>
AMT_HOST=… AMT_PASSWORD_FILE=… cargo run -p amt --example reads      # every read call
AMT_HOST=… AMT_PASSWORD_FILE=… cargo run -p amt --example writes     # reversible writes
AMT_HOST=… AMT_PASSWORD_FILE=… cargo run -p amt --example wsman -- get CIM_Chassis
```

## License

MIT
