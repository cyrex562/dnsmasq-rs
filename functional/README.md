# DHCP Functional Test Harness

Runs `dnsmasq-rs` as the DHCP server inside a real OpenWrt x86_64 QEMU VM and exercises it with
real DHCP client tools running in lightweight Linux network namespaces on the host. Design:
`docs/superpowers/specs/2026-08-22-dhcp-functional-test-harness-design.md`.

This is a manual, opt-in harness — unlike `parity/`, it is not wired into `harness/gate.sh`.
VM boot time (no KVM acceleration is assumed) and the one-time host network setup below make it
too slow/heavy for the autonomous port harness's per-issue gate.

## One-time host setup

Before running any scenario, once per working session (or once ever, if you don't reboot):

```bash
sudo ./functional/setup-host.sh
```

This creates a Linux bridge (`dnsmasq-fnbr0`), one persistent TAP device for the router VM's
LAN interface (chowned to you, so later steps don't need `sudo`), and four network namespaces
(`fn-client-0` through `fn-client-3`) with veth pairs already wired into the bridge. It's
idempotent — safe to run again if you're not sure it already ran.

When you're done working and want to remove all of that:

```bash
sudo ./functional/teardown-host.sh
```

### Optional: passwordless `ip netns exec`

`functional/run.sh` (added in a later issue) needs one privileged operation per DHCP client run
— `ip netns exec fn-client-N <command>` — which will prompt for your `sudo` password each time
unless you install the scoped, opt-in sudoers rule in
`functional/dnsmasq-rs-functional.sudoers.example`. See that file for install instructions. This
step is entirely optional; without it, the harness still works, just with a password prompt per
client invocation.

## Router VM image

Once per host (or whenever `dnsmasq-rs` itself changes and you want the image to pick up the
new binary):

```bash
sudo ./functional/images/build-router-image.sh
```

This fetches (and checksum-verifies) a pinned OpenWrt x86_64 image into `functional/.cache/`
(gitignored) if not already cached, cross-compiles `dnsmasq-rs` for
`x86_64-unknown-linux-musl`, and customizes a copy of the base image via `guestfish`: installs
the binary, disables OpenWrt's own `dnsmasq`, and installs a custom `/etc/init.d/dnsmasq-rs`
service (classic `rc.common`, not `procd` — see the design doc's "Router VM image" section for
why). Needs `sudo` because `guestfish`'s helper VM needs to read the host's `0600 root:root`
kernel image; the resulting `functional/.cache/router.img` is chowned back to you afterward.

## Status

- [x] One-time host network setup (`setup-host.sh` / `teardown-host.sh`) — this file.
- [x] Router VM image (fetch OpenWrt, cross-compile + inject `dnsmasq-rs`) — issue #135.
- [ ] Scenario runner + `basic-lease` smoke-test scenario — issue #136.
- [ ] Remaining v1 scenarios + ISC `dhclient` client type — issue #137.
