# amt-mcp

An [MCP](https://modelcontextprotocol.io) server for **Intel AMT** (vPro) out-of-band
management: power control, user consent, and a Serial-over-LAN console, over AMT's own
protocols. No MPS, MeshCentral or agent on the target is needed.

Version 0.1.0 <!-- x-release-please-version -->

## Tools

| Tool | Writes | What it does |
|------|:------:|--------------|
| `get_status` | | Power state, control mode, consent state and policy, SOL/IDE-R/listener and KVM settings |
| `power` | ✓ | `on`, `off`, `cycle` or `reset` — immediate, the OS is not asked |
| `consent_request` | ✓ | Shows a 6-digit consent code on the device's display |
| `consent_submit` | ✓ | Submits the code read off the display |
| `consent_cancel` | ✓ | Withdraws consent |
| `enable_sol_listener` | ✓ | Opens the 16994 redirection listener SOL needs |
| `sol_open` | ✓ | Opens a Serial-over-LAN session |
| `sol_read` | | Returns console output since the last read (ANSI stripped by default) |
| `sol_send` | ✓ | Types on the console; `escapes=true` for control keys |
| `sol_close` | | Ends the session |

Write tools are refused unless `AMT_ALLOW_WRITES=true`.

## Configuration

| Variable | Default | |
|----------|---------|--|
| `AMT_HOST` | — | Device address (AMT shares the host OS's IP in DHCP mode) |
| `AMT_PASSWORD_FILE` | — | File holding the AMT admin password (preferred) |
| `AMT_PASSWORD` | — | The password itself, if no file is given |
| `AMT_USER` | `admin` | |
| `AMT_PORT` | `16992` | WS-Man (HTTP digest) |
| `AMT_SOL_PORT` | `16994` | Redirection protocol |
| `AMT_TIMEOUT_MS` | `15000` | |
| `AMT_ALLOW_WRITES` | `false` | Must be `true` for anything that changes state |

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

## User consent

In client control mode AMT requires consent for every SOL, IDE-R and KVM session, and
the policy cannot be changed. The code appears **only on the device's own display**, so
someone has to be there to read it:

1. `consent_request`
2. read the code at the device, then `consent_submit`
3. `sol_open`, `sol_send`, `sol_read`

Power actions need no consent.

## Security

- Plain-HTTP AMT (16992/16994) carries digest-protected credentials but unencrypted
  traffic. Expose these ports only to management hosts.
- `power` is equivalent to the physical power button. Confirm before using it.

## Development

```bash
cargo test --all
AMT_HOST=… AMT_PASSWORD_FILE=… cargo run -p amt --example probe     # read-only status
AMT_HOST=… AMT_PASSWORD_FILE=… cargo run -p amt --example console -- request
AMT_HOST=… AMT_PASSWORD_FILE=… cargo run -p amt --example console -- open <code>
```

## License

MIT
