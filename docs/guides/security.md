# Security

AMT is a second computer inside the host with network access, power control and,
when enabled, keyboard, screen and disk access. Treat its ports like a BMC's.

## A host firewall does not protect the AMT ports

| Port | What |
| --- | --- |
| 16992 | WS-Man over HTTP (digest auth): everything this server does |
| 16993 | WS-Man over TLS (closed until TLS is configured) |
| 16994 | Redirection: SOL, IDE-R (plain) |
| 16995 | Redirection over TLS |
| 623 | AMT's other management protocol endpoint |
| 5900 | KVM over standard VNC, when enabled |

- Allow these **only from management hosts**. AMT shares the host's IP in DHCP mode,
  so a firewall on the host does not protect them: AMT answers before the OS sees the
  packets. Filter on the switch or router.
- AMT cannot use a tagged VLAN in this mode: put the whole switch port in the
  management VLAN, or filter by the host's MAC.
- An overlay network on the host (VPN, mesh) does not reach AMT. Reach it from a jump
  host on the same segment.

## Credentials

- Keep the AMT, RFB and account passwords in files (mode 600) and pass the paths
  (`AMT_PASSWORD_FILE`, `AMT_READ_PASSWORD_FILE`, `rfb_password_file`,
  `password_file`). This server never takes a password as a tool argument.
- Use a read-only account for monitoring (`add_account` with no realms).
- Plain HTTP (16992) protects credentials with digest auth, but the traffic itself is
  unencrypted. Prefer TLS (16993/16995) where the network is not trusted.
- Redirection (16994) authenticates with digest. If a device offers only the
  plaintext type, the session is refused: the password would cross the network in
  clear, and anyone on the path can force that by editing the offer. Set
  `AMT_ALLOW_PLAINTEXT_AUTH=true` only for old firmware on a trusted segment; the
  server logs a warning when it is set.

## In client control mode, root on the host can deprovision AMT

- In client control mode, root on the host can deprovision AMT. If untrusted code
  runs as root (CI jobs with Docker, for example), it can turn remote management off,
  but it cannot use AMT to take over the machine without the AMT password.
- Admin control mode prevents that (deprovisioning needs the AMT admin password) and
  allows turning consent off. Only turn
  consent off when the network exposure above is locked down.

## Old ME firmware has network-reachable vulnerabilities

- Several severe AMT vulnerabilities were network-reachable through 16992–16995. Keep
  ME firmware current. Some vendors ship ME firmware only as a Windows updater, and
  the BIOS package does not include it. **Human:** may need a Windows PE stick.
- If the firmware cannot be updated, the port filtering above is the mitigation.

## Hygiene

- Disable KVM (`kvm_disable`) when not in use: it gives full keyboard and screen control
  of the host.
- KVM over the redirection port needs no VNC port: leave 5900 closed unless a plain
  VNC client must connect.
- Review the audit log (`get_audit_log`): power actions, SOL/IDE-R/KVM sessions,
  consent codes and account changes, with the initiating user and address.
- `power` is the physical power button. Confirm before using it.
