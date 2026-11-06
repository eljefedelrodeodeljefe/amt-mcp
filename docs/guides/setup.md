# Setup: getting a device manageable

Steps marked **Human** need someone at the device or in its firmware setup.
Everything else this server or an SSH session on the host can do.

## 1. Prerequisites

- A vPro platform with AMT: a vPro CPU and the Intel I219-LM (or similar) onboard
  NIC. AMT is only reachable through that port.
- **Human:** AMT enabled in the BIOS (often *Advanced → Intel Manageability*). Some
  firmware then opens MEBx at every boot until AMT is provisioned.
- The host OS sees the ME: `/dev/mei0` exists. `fwupdmgr get-devices` shows the ME
  firmware version and whether AMT is *unprovisioned*.

## 2. Choose a control mode

| | Client control mode (CCM) | Admin control mode (ACM) |
| --- | --- | --- |
| How | From the host OS, no reboot: Intel `rpc activate -local -ccm` | **Human:** MEBx (Ctrl+P at power-on) manual setup, or a provisioning certificate |
| Power control | No consent needed | No consent needed |
| SOL, IDE-R, KVM, forced boot | 6-digit consent code on the device's display, every session | Consent policy can be `none` |
| Undo | Root on the host can deprovision | Needs the AMT admin password |

CCM is enough for power control and works without anyone at the device. For an
unattended console, or a host that runs untrusted code as root, use ACM.

## 3. Provision (CCM, from the host)

1. Install Intel's `rpc-go` from its official releases and check the published SHA256.
2. `rpc amtinfo` should report `pre-provisioning state`.
3. `rpc activate -local -ccm -password <strong password>`.
   - Without Intel's LMS on Linux, `rpc` talks to the ME directly ("local transport").
     If it stalls with `Execution timeout after 20s`, see the troubleshooting guide:
     **Human:** a full AC drain (unplug ≥ 30 s) usually fixes it.
4. `rpc amtinfo` reports `activated in client control mode`.

The AMT password has 8–32 characters with upper, lower, digit and a symbol, and none of
`"` `,` `:`. Keep it in a file (mode 600) and point `AMT_PASSWORD_FILE` at it, and keep it
out of any repository.

**Human (MEBx only):** MEBx always uses the US keyboard layout. Choose a password
whose characters are in the same place on the local layout.

## 4. Enable redirection features

- SOL and IDE-R: `rpc configure amtfeatures -sol -ider -kvm -password …` (may stall
  like activation; it often enables the features before stalling).
- Open the redirection listener: `enable_sol_listener`.
- KVM: `kvm_enable`. That is all the default transport (KVM inside a redirection
  session on 16994) needs. Only for `AMT_KVM_TRANSPORT=vnc` pass an RFB password file
  (8 characters, no more and no fewer, with upper, lower, digit and symbol), which also opens port 5900.
- Keep the display at or below AMT's KVM framebuffer limit (~9.2 MB: 1920x1080 at 16
  bits fits, 3840x2160 exceeds it), e.g. with `video=1920x1080` on the kernel command line.
- Check with `get_status` and `get_boot_options`.

## 5. Host side for a serial console

AMT's SOL appears as a PCI serial port (`8086:a363` on recent chipsets, a `ttyS*`
in Linux; check `/sys/class/tty/ttyS*/device`). See the recipes guide, "Serial
console on the host".

## 6. Least privilege

Create a read-only account (`add_account` without realms) and run read tools with
it: `AMT_READ_USER` + `AMT_READ_PASSWORD_FILE`. Writes keep using the admin account.
