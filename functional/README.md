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

`functional/run.sh` needs one privileged operation per DHCP client run — executed through the
narrow `functional/lib/netns-exec.sh` wrapper, since this host's `sudo` (`sudo-rs`) rejects any
wildcard in a sudoers command spec, so the `fn-client-*` scoping lives in the wrapper script
itself rather than the sudoers rule — which will prompt for your `sudo` password each time unless
you install the scoped, opt-in sudoers rule in `functional/dnsmasq-rs-functional.sudoers.example`.
See that file for install instructions. This step is entirely optional; without it, the harness
still works, just with a password prompt per client invocation.

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

## Running a scenario

Once both one-time steps above are done:

```bash
./functional/run.sh basic-lease
```

This boots the router VM with a per-run scratch disk carrying the scenario's `dnsmasq.conf`,
waits for `dnsmasq-rs` to report ready, then runs each `client-N.conf`'s DHCP client against it
and checks the result against that file's `EXPECT_*` values. See the design doc's "Scenario
format and client execution" section for the full field reference. `run.sh` needs no `sudo` of
its own beyond the `netns-exec.sh` calls covered above.

## Scenarios (v1)

| Scenario | What it proves |
|---|---|
| `basic-lease` | Plain `dhcp-range`: a client gets a pool address plus router/DNS/lease-time. |
| `static-reservation` | `dhcp-host=<mac>,<ip>` (a reserved address *outside* the pool range): the matching MAC gets exactly that address, not a pool one. |
| `client-options` | `dhcp-option` for domain-name and NTP server: the client actually receives them, not just the fixed fact set `basic-lease` covers. |
| `mac-blocklist-nak` | `dhcp-host=<mac>,ignore`: the matching MAC gets no reply at all. Named to match the design doc's v1 list, but the verified, correct expected outcome is `EXPECT_RESULT=timeout`, not an explicit NAK — `ignore` is a silent drop in both dnsmasq-rs and upstream (see `tasks.md`). Verified this isn't a silent-pass trap: removing the `dhcp-host` line makes the scenario fail as expected (the client gets a real lease instead). |

All four run with `CLIENT_TOOL=busybox-udhcpc` — v1's only client tool (see below).

### Client tools

v1 ships with `busybox-udhcpc` only, running inside the `fn-client-N` namespaces
`setup-host.sh` creates. A second client tool was originally planned as ISC `dhclient` running
the same way, but installing a new package onto the host just to support this harness didn't
sit right once it came time to implement it (issue #137) — namespaces are fine, but new
test-only software belongs in a container or VM, not the host's own package database. The
alternatives for running `dhclient` in a container joined to an existing namespace were more
fragile than just building a real second client VM, which the original design already
anticipated ("namespace clients now, VM clients later"). That's tracked as its own issue
(#141 — Alpine base image, Packer/Vagrant-built) rather than folded into `busybox-udhcpc`'s
existing namespace-based path.

## Status

- [x] One-time host network setup (`setup-host.sh` / `teardown-host.sh`) — this file.
- [x] Router VM image (fetch OpenWrt, cross-compile + inject `dnsmasq-rs`) — issue #135.
- [x] Scenario runner + `basic-lease` smoke-test scenario — issue #136.
- [x] Remaining v1 scenarios (`static-reservation`, `client-options`, `mac-blocklist-nak`) —
      issue #137. ISC `dhclient` support was dropped from this issue's scope — see "Client
      tools" above and issue #141.
