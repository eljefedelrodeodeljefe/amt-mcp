# Recipes

Steps marked **Human** need someone at the device. A "Consent" step is the consent flow
in client control mode with consent policy `all`: run `consent_request`, ask the person at the
device for the 6-digit code shown on its display, then `consent_submit`. The code
expires after about two minutes.

## Recover a hung host

1. `get_status`: power state. `get_event_log`: last firmware events.
2. Confirm with the user, then `power` `reset` (hard reset) or `cycle`.
3. Watch it come back: `get_event_log` shows firmware progress; once the OS is up the
   host answers on its own services again.

No consent needed.

## Watch the boot or log in on the serial console

1. Consent.
2. `sol_open`, then `sol_read` repeatedly; `sol_send` types (`escapes=true` for keys).
3. `sol_close` when done.

For boot messages and GRUB on the console, the host must be set up first (below).

## Serial console on the host (Linux)

Find the AMT SOL port: the `ttyS*` whose device is the AMT SOL PCI function
(`8086:a363` on recent chipsets). Then, e.g. for `ttyS4` at I/O `0x30A0`:

```text
# /etc/default/grub.d/90-amt-sol.cfg
GRUB_CMDLINE_LINUX="$GRUB_CMDLINE_LINUX console=tty0 console=ttyS4,115200n8"
GRUB_TERMINAL="console serial"
GRUB_SERIAL_COMMAND="serial --port=0x30A0 --speed=115200 --word=8 --parity=no --stop=1"
GRUB_TIMEOUT_STYLE=menu
GRUB_TIMEOUT=5
```

`update-grub`, then `systemctl enable --now serial-getty@ttyS4`. The kernel console
takes effect at the next boot.

## Boot into BIOS setup

1. Consent (forced boot sources need it in client control mode).
2. `set_next_boot` `bios_setup` (`sol=true` to redirect the BIOS console to SOL, if
   the BIOS supports it).
3. `power` `reset` (or `on` if off).
4. With `sol=true`: `sol_open` and read the BIOS menus. Otherwise `kvm_enable` once,
   then `kvm_screenshot` and `kvm_send_keys`.

## Reinstall from an ISO with no physical media

1. Consent.
2. `ider_start` with the ISO path (`start=on_reboot`).
3. `set_next_boot` `ider_cd`.
4. Confirm with the user, then `power` `reset`.
5. Follow the installer on `sol_read` (if it uses the serial console) or
   `kvm_screenshot`. `ider_status` shows blocks served.
6. `ider_stop` once the installer no longer needs the CD.

To check IDE-R without rebooting, run `ider_start` with `start=now`; the running host
sees a new "Intel Virtual CD".

## Scheduled wake

`add_alarm` with a UTC start before 2038 and an optional repeat (`P1D`). Pair with the
firmware's "After Power Loss = Power On" so the host also returns after a power cut.

## Who used AMT, and when

`get_audit_log`: power actions, SOL/IDE-R/KVM sessions, consent codes, account
changes, with user and source address. Times are AMT's clock: `get_clock`, and
`sync_clock` if it drifted.
