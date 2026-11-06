# Changelog

## [0.3.0](https://github.com/eljefedelrodeodeljefe/amt-mcp/compare/v0.2.0...v0.3.0) (2026-11-06)


### ⚠ BREAKING CHANGES

* **mcp:** AMT_PASSWORD is no longer read, and setting it stops the server at startup. Put the password in a file (mode 600) and set AMT_PASSWORD_FILE.
* **amt:** amt::Endpoint::password is an amt::Secret instead of a String. Read it with `.expose()`; build one with `Secret::from`.
* **redir:** amt::Endpoint has a new public field, allow_plaintext_auth, so struct literals must set it (Endpoint::new defaults it to false). amt::Error has a new variant, PlaintextAuthRefused. Devices that offer only plaintext auth stop working until the opt-in is set.
* **wsman:** amt::Client::send takes a second argument, a wsman::Call. invoke and call are treated as writes; read-only methods should use invoke_read / call_read to keep the retry.

### Bug Fixes

* **amt:** keep passwords out of Debug output ([f1c6863](https://github.com/eljefedelrodeodeljefe/amt-mcp/commit/f1c6863c78fccdedf6f4a8df6ec59108db4fe416))
* device-safety fixes (no double sends, bounded device input, no plaintext downgrade, redacted secrets) ([ccb9ad2](https://github.com/eljefedelrodeodeljefe/amt-mcp/commit/ccb9ad2d0f64c8f44dcdd7ca0bbb561b06595f0e))
* **kvm:** bound framebuffer, rectangle and ZRLE sizes from the device ([9e1af03](https://github.com/eljefedelrodeodeljefe/amt-mcp/commit/9e1af03132093b7d96e863d0bb42748c68e21263))
* **kvm:** refuse RFB pixel formats that would overflow a shift ([c7ba263](https://github.com/eljefedelrodeodeljefe/amt-mcp/commit/c7ba263d78669f17733ee16f3194b22915318321))
* **logs:** checked arithmetic on audit-log paging ([3a90eaf](https://github.com/eljefedelrodeodeljefe/amt-mcp/commit/3a90eaf279a2a0b06204f982ef4d1c21ecb5917a))
* **mcp:** log at info by default and one line per write tool ([ce08012](https://github.com/eljefedelrodeodeljefe/amt-mcp/commit/ce080125d266c9b319a1fb962532a5e57f1fc719))
* **mcp:** read the admin password only from AMT_PASSWORD_FILE ([45361e9](https://github.com/eljefedelrodeodeljefe/amt-mcp/commit/45361e9820202e57337f71fb5322435f0b9abc67))
* **mcp:** strict boolean environment parsing ([de429b9](https://github.com/eljefedelrodeodeljefe/amt-mcp/commit/de429b92bfcee83a85736d487816db2b5ad8d605))
* **redir:** refuse plaintext redirection auth unless opted in ([3c75fcd](https://github.com/eljefedelrodeodeljefe/amt-mcp/commit/3c75fcd4cfe48f140337d10a0f3226978aa86865))
* **wsman:** never resend a mutating call that may have reached AMT ([edfb7db](https://github.com/eljefedelrodeodeljefe/amt-mcp/commit/edfb7db03f07235015dc691204cbb8480faa6de8))


### Documentation

* **agents:** expect with a reason instead of allow; device-safety rules ([3dbe121](https://github.com/eljefedelrodeodeljefe/amt-mcp/commit/3dbe121b84c8b382e09fb1854a80b4ab988e0ea5))
* prose sweep of README, AGENTS.md and operator guides ([cbeceed](https://github.com/eljefedelrodeodeljefe/amt-mcp/commit/cbeceed3a35dbf09ea09c8d65f70449c37c5556b))
* prose sweep of README, AGENTS.md and operator guides ([871be6f](https://github.com/eljefedelrodeodeljefe/amt-mcp/commit/871be6f2e1c409ee95ef2f754616c414609919c1))

## [0.2.0](https://github.com/eljefedelrodeodeljefe/amt-mcp/compare/v0.1.0...v0.2.0) (2026-11-04)


### Features

* Intel AMT MCP server — power, user consent and Serial-over-LAN ([564eee6](https://github.com/eljefedelrodeodeljefe/amt-mcp/commit/564eee6ed5f6223c53a9bfbdbb0771ef26ecb38b))
* inventory, logs, network and clock, wake alarms, accounts, boot control, graceful power ([940208e](https://github.com/eljefedelrodeodeljefe/amt-mcp/commit/940208e7f7e14fee8ac30f54df999c1dfbbcb3a6))
* KVM over the VNC port and IDE-R (serve an ISO as a CD-ROM) ([ae19ca2](https://github.com/eljefedelrodeodeljefe/amt-mcp/commit/ae19ca2c6b1f7dfed8fd386230f949f6414e5e01))
* operator guides as MCP resources and list_guides/get_guide ([137acdc](https://github.com/eljefedelrodeodeljefe/amt-mcp/commit/137acdc66e62be14264acae5b5c0e8dc281bba87))


### Bug Fixes

* **kvm:** screenshots work — ZRLE, whole-screen requests, KVM over the redirection port ([59c6eea](https://github.com/eljefedelrodeodeljefe/amt-mcp/commit/59c6eea9ac5c93ff46317d9bf2e7efc40f1159b8))
