# Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| `rpc activate`/`configure` hangs, `Execution timeout after 20s` | No LMS on Linux; the ME's local transport stalls | **Human:** full AC drain (unplug ≥ 30 s), retry. Kill a hung `rpc` with `pkill -x rpc` (not `-f`, which can match the shell running it) |
| MEBx "Error applying new password" | Password rules or a stuck ME | Include a symbol; avoid `"` `,` `:`; MEBx uses the US layout. **Human:** AC drain, retry |
| `amtterm`: "session authentication failed" | It only knows plain-password auth; AMT 12+ wants digest | Use `sol_open` here |
| `set_next_boot` refused, "not authorized" | Client control mode: forced boot sources need consent | Consent first; clearing with `default` works without |
| `add_alarm`: "XML content is not valid" | Start time after 2037 (AMT's clock is 32-bit) | Use an earlier date |
| Tool calls fail intermittently in parallel | AMT's web server handles very few connections | This server serializes requests per device; for other clients, do the same |
| `kvm_screenshot`: AMT resets the connection | Display resolution above AMT's KVM capture limit (seen at 3840x2160 on AMT 12) | Lower the display or console resolution (e.g. `video=1920x1080` on the kernel command line) |
| `sol_open`: StartRedirectionSession refused | Listener closed or SOL disabled | `enable_sol_listener`; `get_status` → `redirection` |
| Nothing answers on 16992 | AMT not provisioned, network access not activated, or filtered | `rpc amtinfo` on the host; check `get_network` from a reachable host |
| `ping` answers while the host is rebooting | AMT answers ping on the shared IP | Use `get_status` (power state) or the host's own services instead |
| `graceful_off`/`graceful_reset` refused | They need Intel's in-band agent in the OS | Use `off`/`reset`, or shut down from the OS |
