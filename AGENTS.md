# AGENTS.md — conventions for `amt-mcp`

Ported from `rigol-mcp` so muscle memory transfers between the two.

## Branching and commits

`main` is the sole long-lived branch. Feature work branches off `main` and returns via
pull request.

Branch prefixes, kebab-case: `feat/`, `fix/`, `bugfix/`, `docs/`, `chore/`, `refactor/`.

Conventional commits drive release-please. `feat:` bumps minor, `fix:` and `perf:` bump
patch, `feat!:` or a `BREAKING CHANGE:` footer bumps major. `chore:`, `ci:`, `test:`,
`docs:` and `refactor:` do not affect the version. One logical change per commit.

## Layout

```text
crates/amt/            library — no MCP types cross into here
  src/wsman.rs         WS-Man envelopes over HTTP digest, field extraction
  src/digest.rs        digest auth (HTTP header and redirection-frame variants)
  src/device.rs        typed operations: power, control mode, consent, redirection, KVM
  src/sol.rs           redirection protocol: SOL handshake, data, keep-alive
  src/error.rs         typed errors
  examples/probe.rs    read-only status of a live device
  examples/console.rs  live consent + SOL check
crates/amt-mcp/        binary
  src/server.rs        MCP adapter — #[tool] stubs only, no logic
  src/tools/           pure logic, returns anyhow::Result<Value>
  src/params/          Deserialize + JsonSchema structs
  src/error.rs         maps failures onto MCP error codes
crates/amt-fake/       test-only fake of the redirection service (unpublished)
```

The seam between `amt` and `amt-mcp` is load-bearing: the library must stay usable
without an MCP runtime.

## Adding a tool

1. A parameter struct in `crates/amt-mcp/src/params/{domain}.rs`, deriving `Deserialize`
   and `JsonSchema`, with `#[schemars(description = "…")]` on each field.
2. Pure logic in `crates/amt-mcp/src/tools/{domain}.rs` returning `anyhow::Result<Value>`.
3. A `#[tool(description = "…")]` stub in `server.rs` that calls `self.guard_write()?`
   first if it changes anything on the device.

Tool descriptions name the AMT SDK class and method (`IPS_OptInService.StartOptIn`).
New WS-Man calls and redirection messages are checked one at a time on real hardware with
the examples before a tool depends on them. Tests run against `amt-fake`.

## Safety rules

- Power actions are out-of-band and immediate. Never make any other tool trigger one as a
  side effect, and keep `power` behind `guard_write`.
- Never add anything that brute-forces consent codes or passwords. AMT locks out after
  failed attempts.
- Never weaken the consent flow: no tool may set the consent policy to `none` without a
  dedicated, separately gated operation.
- Read `get_status` before proposing a write, and confirm with the user before `power`.
- **No deployment details in this repo**: no hostnames, IPs, device models or serials,
  or names of the projects this is used in. Examples use documentation addresses
  (`192.0.2.0/24`).

## Gates

All commits must pass `prek run --all-files`:

- `cargo fmt`
- `cargo clippy --all-targets -- -D warnings` — **`#[allow]` escapes are refused**; fix the
  lint instead
- `cargo test --all`
- `typos`, TOML/YAML validation, markdownlint

## Runtime

stdout is the MCP protocol channel. All diagnostics go to stderr via `tracing`. Anything
printed to stdout corrupts the JSON-RPC stream.
