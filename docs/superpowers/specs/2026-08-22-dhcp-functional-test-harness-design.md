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
  `virt-customize`) — though `guestfish` itself needs `sudo` on this host (see below).
  The chosen OpenWrt image has `virtio_blk`/`virtio_net` compiled directly into its kernel but
  **no 9p support at all** (confirmed by inspecting `modules.builtin` — see "Router VM image"),
  which changed the original config-injection plan; `mtools` (`mformat`/`mcopy`) is installed
  for unprivileged vfat image creation. `expect` is not installed. `busybox` (providing
  `udhcpc`) is installed — v1's only client tool runs entirely on tooling already present, no
  host package installs needed (see "Scenario format and client execution" for why a second,
  ISC-`dhclient`-based tool was dropped from v1's scope).
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
4. **Unprivileged by default; `sudo` isolated to documented one-time setup steps.** A
   `sudo ./functional/setup-host.sh` run once (idempotent, safe to re-run) creates the bridge,
   persistent TAP, and per-client namespaces/veths. A one-time
   `sudo ./functional/images/build-router-image.sh` similarly needs `sudo` — confirmed while
   implementing this: `guestfish`'s supermin helper VM needs to read the host's kernel image,
   which is `0600 root:root` on this system, the same class of constraint as the network setup.
   Every repeated `./functional/run.sh <scenario>` invocation after both one-time steps needs no
   privilege except one narrow, isolatable `ip netns exec` call per client (optionally
   passwordless via a scoped, opt-in `/etc/sudoers.d/` rule this repo ships but does not install
   automatically).

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

`fetch-openwrt.sh` downloads one pinned OpenWrt x86_64 `generic-ext4-combined` image
(OpenWrt 25.12.5, checksum-verified) into `functional/.cache/` (gitignored — images don't
belong in git, matching the reasoning that kept the 44GB `target/` build directory out of
Docker context in the parity harness). `build-router-image.sh` customizes that base image
**once**, offline, via `guestfish` (no boot needed — but confirmed to require `sudo` on this
host: `guestfish`'s supermin helper VM needs to read the host kernel image to build its own
appliance, and this system's kernel images are `0600 root:root`, the same class of constraint
that makes `setup-host.sh` need `sudo`):

- Installs the cross-compiled `dnsmasq-rs` binary (`x86_64-unknown-linux-musl` target — a
  static-pie musl binary carries its own libc, so it doesn't need to match OpenWrt's musl
  version exactly) at `/usr/sbin/dnsmasq-rs`.
- Disables OpenWrt's own `dnsmasq` init script so the two don't fight over ports 53/67.
- Adds a custom init script (`/etc/init.d/dnsmasq-rs`) that waits for a second virtio-block
  device to appear, mounts its (vfat) filesystem **read-write** at `/mnt/scenario`, backgrounds
  `dnsmasq-rs --conf-file=/mnt/scenario/dnsmasq.conf` redirecting its output to
  `/mnt/scenario/dnsmasq-rs.log`, and once `pidof dnsmasq-rs` confirms it's running, touches
  `/mnt/scenario/.ready` on that same disk.

**Config injection — revised from the original virtio-9p plan.** Inspecting the actual
downloaded image (`sda2` is the rootfs; confirmed via `guestfish`) showed `virtio_blk`/
`virtio_net` compiled directly into the kernel (`modules.builtin`), but **no 9p support at
all** — neither built in nor as a loadable module, and no way to add one offline without a
full kernel rebuild. `run.sh` instead builds a small per-run scratch disk: an `mtools`-formatted
vfat image (`mformat`/`mcopy` — unprivileged, no loop-mount needed) containing just the
scenario's `dnsmasq.conf`, attached as QEMU's second `virtio-blk` drive. One customized router
image is still reused across every scenario; only the scratch disk (built fresh per run, in
seconds) carries scenario-specific content, so adding a scenario is still "add a directory,"
not an image rebuild.

**Readiness detection — revised twice from the original `.ready`-marker plan, before landing
back on a `.ready` marker.** The first revision made the scratch disk config-injection-only and
tried polling the guest's serial console (`-serial file:<path>`) for `dnsmasq-rs`'s own startup
log line instead, since a read-only disk gives the guest no way to signal back. That in turn
was superseded once it became clear the console approach would need a *read-write* channel
anyway to be robust (a config that hangs rather than errors gives no console line to poll for
either way). The scratch disk was made read-write and the guest now writes both a `.ready`
marker and a full `dnsmasq-rs.log` back onto it — `run.sh` polls for `.ready`'s appearance from
the host via `mtools` (`mdir`), and `dnsmasq-rs.log` is available for post-run debugging without
needing console access at all.

**Init mechanism — classic `rc.common`, not `procd`.** The init script deliberately does not
use `USE_PROCD=1`/`procd_open_instance` despite that being OpenWrt's modern convention (and
what the stock `/etc/init.d/dnsmasq` uses). Empirically, `procd_open_instance` /
`procd_set_param command ...` / `procd_close_instance` all completed without error but the
resulting instance never actually started `dnsmasq-rs` — confirmed via `pidof` polling, and by
proving the identical command works when instead launched as a plain backgrounded shell job
from the same script. Rather than chase procd's silent failure further, the script uses the
older `start()`/`stop()` `rc.common` convention, which the dispatcher still fully supports.
The trade-off is losing procd's auto-respawn-on-crash — acceptable for a test harness, where a
mid-scenario crash should surface as a test failure rather than be silently respawned away.

### Scenario format and client execution

Each scenario is a directory with a real `dnsmasq.conf` (injected via the per-run scratch
virtio-blk disk, not baked into the image) and one `client-N.conf` per client, a
shell-sourceable `KEY=value` file:

```
CLIENT_TOOL=busybox-udhcpc     # busybox-udhcpc (v1 set — see below)
CLIENT_MAC=52:54:00:12:34:56    # optional; auto-generated per run if omitted
EXPECT_RESULT=lease             # lease | nak | timeout
EXPECT_IP=192.168.50.120         # optional exact-match (static reservations)
EXPECT_IP_RANGE=192.168.50.100-192.168.50.150
EXPECT_ROUTER=192.168.50.1
EXPECT_DNS=192.168.50.1
EXPECT_LEASE_TIME=3600
EXPECT_DOMAIN=example.test      # optional
EXPECT_NTP=192.168.50.1          # optional
```

For each client file, `run.sh` assigns a pre-provisioned namespace slot and execs the named
tool inside it (`busybox udhcpc` with a small lease-dump hook script), capturing the resulting
facts — assigned IP, router/DNS/domain/NTP options, lease time, or an explicit NAK/timeout. A
comparison step checks those facts against the scenario's `EXPECT_*` values and reports
pass/fail per assertion, the same "normalize actual vs. expected, report every mismatch" shape
`parity_probe` already uses for DNS, applied to lease facts instead of DNS packets.

**v1 client tools — revised from the original two-tool plan.** The original plan called for a
second client tool, ISC `dhclient`, running inside the same `fn-client-N` namespaces
`busybox-udhcpc` uses. Implementing it (Issue #137) surfaced a real design question: `dhclient`
isn't installed on this class of host, and installing new packages onto the host's own root
filesystem just to support a test harness runs against how this project wants to treat host
state. The alternatives considered — a Docker container bind-mounted onto an existing `ip
netns`-created namespace's `/proc/<pid>/ns/net`, or extracting a static `dhclient` binary from a
container build — were both more fragile than this design's own stated direction for a second
client type: a real VM. That became Issue #141 (Alpine base image, Packer/Vagrant-built, a
one-time build a developer runs once these test machines are mature), tracked separately since
it's a new subsystem (its own image pipeline, networking, and result-capture convention), not a
same-day extension of the namespace-based runner. v1 ships with exactly one client tool,
`busybox-udhcpc`, running in the existing namespaces.

Scenarios still run a scenario's clients **sequentially**, not concurrently — concurrent
multi-client scenarios (pool exhaustion) are real future work, not v1, because of the extra
care needed around ordering and timing.

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
