# DHCP Functional Test Harness

Runs `dnsmasq-rs` as the DHCP server inside a real OpenWrt x86_64 QEMU VM and exercises it with
real DHCP clients, each running inside its own small Alpine Linux QEMU VM. Design:
`docs/superpowers/specs/2026-08-22-dhcp-functional-test-harness-design.md` (overall harness) and
`docs/superpowers/specs/2026-08-23-dhcp-harness-vm-client-design.md` (VM-based client).

This is a manual, opt-in harness — unlike `parity/`, it is not wired into `harness/gate.sh`.
VM boot time (no KVM acceleration is assumed) and the one-time host network setup below make it
too slow/heavy for the autonomous port harness's per-issue gate.

## One-time host setup

Before running any scenario, once per working session (or once ever, if you don't reboot):

```bash
sudo ./functional/setup-host.sh
```

This creates a Linux bridge (`dnsmasq-fnbr0`) and one persistent TAP device for the router VM's
LAN interface (chowned to you, so later steps don't need `sudo`). It's idempotent — safe to run
again if you're not sure it already ran. Client VMs each get their own ephemeral TAP, created
and destroyed per run — there's no more one-time client setup.

When you're done working and want to remove all of that:

```bash
sudo ./functional/teardown-host.sh
```

### Optional: passwordless TAP create/delete

`functional/lib/client.sh` needs one privileged operation per client VM run — creating and
destroying its ephemeral TAP device, executed through the narrow `functional/lib/tap-ctl.sh`
wrapper, since this host's `sudo` (`sudo-rs`) rejects any wildcard in a sudoers command spec, so
the `fnvm*` scoping lives in the wrapper script itself rather than the sudoers rule — which will
prompt for your `sudo` password each time unless you install the scoped, opt-in sudoers rule in
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

## Client VM image

Once per host (or whenever the client's DHCP behavior needs to change):

```bash
sudo ./functional/images/build-client-image.sh
```

This fetches (and checksum-verifies) a pinned Alpine x86_64 cloud image into `functional/.cache/`
(gitignored) if not already cached, and customizes a copy via `guestfish`: disables the image's
own default-runlevel services (`networking`, `sshd`, `chronyd`, the `tiny-cloud-*` agent — none
of which this harness needs, and `networking` would otherwise race the harness's own DHCP
client run), and installs one custom OpenRC service that brings up `eth0`, runs `udhcpc` once,
reports the result, and powers off. Needs `sudo` for the same `guestfish`-needs-the-host-kernel
reason `build-router-image.sh` does. One image serves every scenario and every client — nothing
scenario-specific is baked in; only the VM's MAC address varies per run.

## Running a scenario

Once all three one-time steps above are done:

```bash
./functional/run.sh basic-lease
```

This boots the router VM with a per-run scratch disk carrying the scenario's `dnsmasq.conf`,
waits for `dnsmasq-rs` to report ready, then boots one small Alpine VM per `client-N.conf`,
each running a single DHCP transaction and reporting the result back over its own scratch disk,
checked against that file's `EXPECT_*` values. See the design docs' "Scenario format and client
execution" sections for the full field reference. `run.sh` needs no `sudo` of its own beyond the
`tap-ctl.sh` calls covered above.

## Scenarios (v1)

| Scenario | What it proves |
|---|---|
| `basic-lease` | Plain `dhcp-range`: a client gets a pool address plus router/DNS/lease-time. |
| `static-reservation` | `dhcp-host=<mac>,<ip>` (a reserved address *outside* the pool range): the matching MAC gets exactly that address, not a pool one. |
| `client-options` | `dhcp-option` for domain-name and NTP server: the client actually receives them, not just the fixed fact set `basic-lease` covers. |
| `mac-blocklist-nak` | `dhcp-host=<mac>,ignore`: the matching MAC gets no reply at all. Named to match the design doc's v1 list, but the verified, correct expected outcome is `EXPECT_RESULT=timeout`, not an explicit NAK — `ignore` is a silent drop in both dnsmasq-rs and upstream (see `tasks.md`). Verified this isn't a silent-pass trap: removing the `dhcp-host` line makes the scenario fail as expected (the client gets a real lease instead). |

All four run with `CLIENT_TOOL=alpine-vm` — v1's only client tool (see below).

### Client tools

v1 ships with one client tool, `alpine-vm`: a small Alpine Linux VM per client run, booting a
customized image (see "Client VM image" above), attached to the shared bridge via its own
ephemeral TAP device. This replaced an earlier namespace-based `busybox-udhcpc` client entirely
(issue #141) — new, test-only software (a second client tool, originally planned as ISC
`dhclient`) belongs in a container or VM, not installed onto the host's own package database,
and a VM-based client was the harness's own already-stated future direction ("namespace clients
now, VM clients later").

## Status

- [x] One-time host network setup (`setup-host.sh` / `teardown-host.sh`) — this file.
- [x] Router VM image (fetch OpenWrt, cross-compile + inject `dnsmasq-rs`) — issue #135.
- [x] Scenario runner + `basic-lease` smoke-test scenario — issue #136.
- [x] Remaining v1 scenarios (`static-reservation`, `client-options`, `mac-blocklist-nak`) —
      issue #137.
- [x] VM-based client (`alpine-vm`, replacing the namespace-based `busybox-udhcpc`) — issue #141.
