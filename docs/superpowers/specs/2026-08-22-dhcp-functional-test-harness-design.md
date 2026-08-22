# DHCP Functional Test Harness — Design

**Issue:** #118 — "start the creation of a test suite where dnsmasq-rs running on a
representative router VM via QEMU acts as a DHCP server to various DHCP clients and
exercises elements of its functionality in various scenarios."

## Problem

`parity/` (the existing Docker-based harness) is explicitly DNS-only and cannot cover DHCP:
containers don't easily get real L2 broadcast semantics or the `NET_ADMIN`/`NET_RAW`
capabilities dnsmasq's DHCP path needs, and `parity/README.md`'s own "Next Expansion Points"
names a VM-backed lane as the way to close that gap. This spec is that lane: a harness where
`dnsmasq-rs` runs inside a real router-like environment and real DHCP client software talks to
it over a real (virtual) network, so DHCP behavior gets the same "run it for real and see what
breaks" treatment `parity/`'s expansion (issue #124) already gave DNS.

## Environment constraints (verified, not assumed)

- QEMU (`qemu-system-x86_64`, `qemu-img`) is installed; network access for downloading a base
  image works.
- `/dev/kvm` exists but is **not** accessible to the invoking user (root/`kvm`-group only, no
  ACL grant) — VMs run under software emulation (TCG) unless that changes. The harness must not
  assume hardware acceleration.
- `guestfish` and `qemu-nbd` are installed (offline image customization without needing
  `virt-customize`). QEMU supports `virtio-9p` host-directory passthrough. `expect` is not
  installed. `busybox` (providing `udhcpc`) is installed; ISC `dhclient` is not (one-time `apt`
  install).
- Creating network namespaces, moving interfaces between namespaces, and creating bridges/TAPs
  all require `CAP_NET_ADMIN` (root) on this kernel/config — there is no way to make the *whole*
  harness unprivileged without changing the client-topology decision below.

## Decisions

1. **Clients are Linux network namespaces running real client binaries now; VM clients are a
   documented future phase**, not built here. Each client gets a namespace + veth pair on a
   shared bridge, running a real DHCP client tool — real L2 broadcast/timing behavior, cheap to
   spin up many of, no per-client OS image or boot cost. The client-invocation interface
   (a `client-N.conf` file naming a tool + expectations, resolved to an actual command by
   `run.sh`) is deliberately generic so a later phase can add a VM-backed client type without
   reworking scenario format or comparison logic.
2. **The router VM runs a real OpenWrt x86_64 image**, not a generic Debian/Alpine box or a
   from-scratch Buildroot image. OpenWrt is the most common real-world dnsmasq deployment
   target; running the port inside it is the highest-fidelity "representative router"
   available without building a custom distribution.
3. **Manual-only invocation**, not wired into `harness/gate.sh`. VM boot time (worse without
   KVM) and the one-time host network setup this needs make it too slow/heavy for the
   autonomous port harness's per-issue gate; it lives in `functional/` and is run by hand, the
   same relationship `parity/run-suite.sh` has to `harness/gate.sh --parity`.
4. **Unprivileged by default; `sudo` isolated to a documented one-time setup step.** A
   `sudo ./functional/setup-host.sh` run once (idempotent, safe to re-run) creates the bridge,
   persistent TAP, and per-client namespaces/veths. Every repeated `./functional/run.sh
   <scenario>` invocation after that needs no privilege except one narrow, isolatable
   `ip netns exec` call per client (optionally passwordless via a scoped, opt-in
   `/etc/sudoers.d/` rule this repo ships but does not install automatically).

## Architecture

```
functional/
  setup-host.sh          # one-time, sudo: bridge + persistent TAP + client netns/veth
  teardown-host.sh        # reverses setup-host.sh
  run.sh                  # ./functional/run.sh <scenario>  (no sudo except netns-exec)
  images/
    fetch-openwrt.sh      # downloads + pins an OpenWrt x86_64 release into .cache/ (gitignored)
    build-router-image.sh # guestfish offline customization (see below)
  scenarios/
    basic-lease/
      dnsmasq.conf
      client-1.conf
    static-reservation/
      dnsmasq.conf
      client-1.conf
    client-options/
      dnsmasq.conf
      client-1.conf
    mac-blocklist-nak/
      dnsmasq.conf
      client-1.conf
  lib/                    # shared shell helpers: wait-for-vm, parse-lease, netns helpers
```

### One-time host setup (`setup-host.sh` / `teardown-host.sh`)

Creates (idempotently): a Linux bridge (`dnsmasq-fnbr0`); one persistent TAP device for the
router VM's single LAN-side interface (where `dnsmasq-rs` listens — the VM has no WAN interface
at all, since every v1 scenario is purely LAN-side DHCP and there is nothing for a WAN link to
do), chowned to the invoking user so QEMU can attach without `sudo`; four network namespace +
veth pairs (`fn-client-0` through `fn-client-3` — enough for v1's sequential, single-client-at-
a-time scenarios with headroom for near-term additions, cheap to raise later), with each
bridge-side veth end already attached. `teardown-host.sh` reverses all of it. Neither script is
invoked automatically by `run.sh` — the shared network state is meant to persist across many
`run.sh` invocations within a working session, torn down explicitly when the user is done.

### Router VM image (`images/`)

`fetch-openwrt.sh` downloads one pinned OpenWrt x86_64 `generic-ext4-combined` image into
`functional/.cache/` (gitignored — images don't belong in git, matching the reasoning that kept
the 44GB `target/` build directory out of Docker context in the parity harness).
`build-router-image.sh` customizes that base image **once**, offline, via `guestfish` (no boot
needed):

- Installs the cross-compiled `dnsmasq-rs` binary (musl target, matching OpenWrt's libc) at
  `/usr/sbin/dnsmasq-rs`.
- Disables OpenWrt's own `dnsmasq` init script so the two don't fight over ports 53/67.
- Adds a custom init script that mounts a `virtio-9p` share (mount tag `scenario`) at
  `/mnt/scenario` and execs `dnsmasq-rs --conf-file=/mnt/scenario/dnsmasq.conf`.
- Ensures the `9p`/`virtio` kernel modules needed for that mount are present.

One customized image is reused across every scenario. `run.sh` boots QEMU with
`-virtfs local,path=functional/scenarios/<name>,mount_tag=scenario,security_model=none`
pointing at that scenario's own directory, so each scenario supplies its own `dnsmasq.conf`
without any image rebuild — adding a scenario is adding a directory, not a build step, and
iterating on one reboots the VM rather than re-customizing a disk.

**Readiness detection:** the init script writes a marker file (`/mnt/scenario/.ready`) to the
9p share once `dnsmasq-rs` is listening. `run.sh` polls for that file's appearance from the
host side — this works identically regardless of boot speed (TCG vs. hypothetical future KVM),
and avoids `expect`-scripting the serial console (not installed, and brittle across OpenWrt
versions).

### Scenario format and client execution

Each scenario is a directory with a real `dnsmasq.conf` (injected via the 9p share, not baked
into the image) and one `client-N.conf` per client, a shell-sourceable `KEY=value` file:

```
CLIENT_TOOL=busybox-udhcpc     # busybox-udhcpc | isc-dhclient  (v1 set)
CLIENT_MAC=52:54:00:12:34:56    # optional; auto-generated per run if omitted
EXPECT_RESULT=lease             # lease | nak | timeout
EXPECT_IP_RANGE=192.168.50.100-192.168.50.150
EXPECT_ROUTER=192.168.50.1
EXPECT_DNS=192.168.50.1
EXPECT_LEASE_TIME=3600
```

For each client file, `run.sh` assigns a pre-provisioned namespace slot and execs the named
tool inside it (`busybox udhcpc` with a small lease-dump hook script; ISC `dhclient` reading
back `dhclient.leases`), capturing the resulting facts — assigned IP, router/DNS options, lease
time, or an explicit NAK/timeout. A comparison step checks those facts against the scenario's
`EXPECT_*` values and reports pass/fail per assertion, the same "normalize actual vs. expected,
report every mismatch" shape `parity_probe` already uses for DNS, applied to lease facts
instead of DNS packets.

v1 supports exactly two client tools (`busybox-udhcpc`, ISC `dhclient` — genuinely different
retry/option-request behavior) and runs a scenario's clients **sequentially**, not
concurrently. Concurrent multi-client scenarios (pool exhaustion) are real future work, not v1,
because of the extra care needed around ordering and timing.

### Error handling

- Missing one-time setup (bridge/namespaces absent) → a clear "run `setup-host.sh` first"
  message, not a confusing low-level QEMU/netns error.
- VM boot timeout (readiness marker never appears within a bounded window) → explicit failure
  with the VM's captured console output printed for debugging, mirroring
  `parity/run-suite.sh`'s "print container logs on failure" pattern.
- Client timeout when `EXPECT_RESULT=lease` → a distinct "no lease obtained" failure, never
  conflated with a wrong-value mismatch.
- `run.sh` traps on exit to reliably kill its own QEMU process and clear only its own per-run
  state (lease files, PID files) — it never tears down the shared bridge/namespaces
  `setup-host.sh` created; those persist across runs within a session by design.

## Initial (v1) scenario set

Deliberately small, matching "start the creation of":

1. **`basic-lease`** — plain `dhcp-range`, one client, asserts IP-in-range + router + DNS +
   lease time. The smoke test proving the whole pipeline works end to end.
2. **`static-reservation`** — `dhcp-host=<mac>,<ip>`; the client with that MAC must get exactly
   that IP, not a pool address.
3. **`client-options`** — a `dhcp-option` config (domain-name + NTP server), asserts the client
   actually received them.
4. **`mac-blocklist-nak`** — a config that should refuse a specific MAC, asserting
   `EXPECT_RESULT=nak`/`timeout` — proving the harness can check negative outcomes, not just
   happy-path leases.

## Explicitly out of scope for this iteration (tracked as future work)

- VM-backed (non-namespace) clients, for real non-Linux client OS behavior.
- `systemd-networkd` as a third client tool.
- Concurrent/parallel multi-client scenarios (pool exhaustion, contention).
- Lease renewal/rebinding timing scenarios (need a running VM held open across a lease
  lifetime, not just a single DISCOVER→ACK round trip).
- DHCPDECLINE/conflict-detection scenarios.
- Vendor-class / relay-agent scenarios.
- Wiring this harness into `harness/gate.sh` or any CI-gated path.

## Verification plan

Same standard this session has applied to every other change: after implementation, actually
boot the router VM, actually run each v1 scenario's real client against real `dnsmasq-rs`, and
confirm the harness reports the correct pass/fail for both positive and negative scenarios —
not just that the scripts run without a shell error. `mac-blocklist-nak` in particular exists
to prove the harness doesn't just default to "pass" when nothing happens.
