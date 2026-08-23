# DHCP Functional Harness: VM-Based Client Design

Part of the DHCP functional test harness (Issue #118; see
`docs/superpowers/specs/2026-08-22-dhcp-functional-test-harness-design.md` for the harness's
overall architecture, which this spec assumes and extends). Tracked as Issue #141.

## Motivation

The harness's v1 client execution ran `busybox udhcpc` inside lightweight Linux network
namespaces (`fn-client-0` through `fn-client-3`, created by `setup-host.sh`) on the host. Issue
#137 originally planned a second client tool, ISC `dhclient`, running the same way. Implementing
it surfaced a real objection: `dhclient` isn't installed on this class of host, and installing a
new package onto the host's own root filesystem just to support a test harness doesn't fit how
this project wants to treat host state — new, test-only software belongs in a container or VM,
not the host's package database.

The alternatives considered for `dhclient` specifically — a Docker container bind-mounted onto
an existing `ip netns`-created namespace's `/proc/<pid>/ns/net`, or extracting a static binary
from a container build — were both more fragile than the harness's own already-stated direction
for a second client type ("namespace clients now, VM clients later"). Rather than bolt VM
support on as a second option alongside namespaces, this spec replaces the namespace-based
client entirely with a small QEMU VM booting a customized Alpine Linux image. Every client
becomes a VM; namespaces, their setup/teardown, and the sudo wrapper built for them are removed.

This spec covers exactly enough to reproduce the harness's existing v1 test coverage (the four
scenarios already built: `basic-lease`, `static-reservation`, `client-options`,
`mac-blocklist-nak`) on the new mechanism. Compatibility testing, edge cases, and additional
client tools are explicitly out of scope, deferred to future work once this baseline is proven.

## Environment constraints

- Same host as the rest of the harness: no `/dev/kvm` access for this user, so client VMs run
  under TCG (software emulation) like the router VM. Alpine's minimal footprint should still
  boot markedly faster than the OpenWrt router image did.
- This host's `sudo` is `sudo-rs` (Ubuntu's Rust reimplementation), which rejects any wildcard
  character in a sudoers command argument — the same constraint `functional/lib/netns-exec.sh`
  was built to work around for namespace exec, and which the new TAP-lifecycle wrapper (below)
  needs to work around the same way.
- `guestfish` needs `sudo` on this host (the same `0600 root:root` host kernel image constraint
  documented in the harness's main spec) — the client image build inherits this, exactly like
  `build-router-image.sh` does.
- Alpine publishes pre-installed "nocloud" cloud images (qcow2) per release — no installer/ISO
  boot required to customize them, the same property that made OpenWrt's
  `generic-ext4-combined` image guestfish-friendly for the router.

## Architecture

### Topology

The router side is unchanged: the persistent bridge `dnsmasq-fnbr0` and TAP `dnsmasq-fntap0`
from `setup-host.sh` still exist and still work exactly as before. Each client VM attaches to
the same bridge via its own **ephemeral** TAP device — created immediately before that client
runs and destroyed immediately after, rather than a namespace/veth pair created once by
`setup-host.sh` and left standing. This means `setup-host.sh` shrinks to just the bridge and
router TAP; there is no more per-client one-time setup at all.

Creating and destroying a TAP needs `CAP_NET_ADMIN` (root), so this needs its own narrow sudo
entry point, `functional/lib/tap-ctl.sh` — the same shape as the now-removed `netns-exec.sh`:
a fixed script path granted with no argument list in the sudoers file (sudo-rs rejects
wildcards outright, and a bare command path already matches any arguments per standard
sudoers(5) semantics), with the actual scoping — only TAP names matching `fn-vmclient-*` — done
inside the script itself. It supports two operations:

```
tap-ctl.sh create <name>   # ip tuntap add dev <name> mode tap user <invoking user>; attach to the bridge; bring up
tap-ctl.sh delete <name>   # ip link delete <name>
```

### Client VM image

`functional/images/fetch-alpine.sh` mirrors `fetch-openwrt.sh`: downloads and
checksum-verifies one pinned Alpine release's official nocloud cloud image (qcow2) into
`functional/.cache/` (gitignored).

`functional/images/build-client-image.sh` mirrors `build-router-image.sh`, but does less —
there's no binary to cross-compile and inject; Alpine's own BusyBox already provides `udhcpc`.
It customizes a copy of the fetched image via `guestfish` (needs `sudo` for the same host-kernel
reason `build-router-image.sh` does):

- Uploads `functional/images/client-dhcp-test.init` (an OpenRC init script) to
  `/etc/init.d/dhcp-test-client` and enables it in the default runlevel.
- Uploads `functional/images/client-udhcpc-handler.sh` (a guest-side port of the harness's
  existing `functional/lib/udhcpc-handler.sh` — same event-handler contract, same
  `RESULT=`/`ACTUAL_*` output format) to `/usr/local/sbin/dhcp-test-handler.sh`.

One customized client image serves every scenario and every client slot — nothing scenario- or
client-specific gets baked in. The only thing that varies per client is its MAC address, set at
QEMU launch time (`-device virtio-net-pci,...,mac=<addr>`), not injected into the image or a
scratch disk.

The init script's job at boot:

```
1. Wait for the scratch disk (a second virtio-blk device) to appear, mount it read-write
   (same convention as the router: config in, results out, over the same disk).
2. Bring up eth0.
3. Run: udhcpc -i eth0 -n -q -f -t 8 -T 3 -s /usr/local/sbin/dhcp-test-handler.sh
   (same retry budget already tuned for this harness's namespace-based client — see
   functional/lib/client.sh's existing comment on why 8x3s).
4. The handler script (invoked by udhcpc, exactly like the host-side version was invoked by
   udhcpc in the namespace) writes RESULT=lease|nak|timeout plus ACTUAL_IP/ACTUAL_ROUTER/
   ACTUAL_DNS/ACTUAL_LEASE/ACTUAL_DOMAIN/ACTUAL_NTP to the scratch disk, exactly as it does
   today.
5. Touch .done on the scratch disk; sync.
6. poweroff.
```

No scenario-specific config is needed inside the VM: the client's only job is "run a DHCP
client once and report what happened," identical across every scenario. Scenario-specific
behavior (what the client's MAC is, what a correct outcome looks like) lives entirely on the
host side, in `client-N.conf` and the comparison logic — unchanged from today.

### Execution flow

`functional/lib/client.sh`'s `run_and_check_client` keeps its existing signature and its
existing comparison logic (`EXPECT_*` vs. `ACTUAL_*`) completely unchanged — only how the
`RESULT`/`ACTUAL_*` facts get produced changes. The namespace-based `run_busybox_udhcpc` is
replaced by a VM-based equivalent:

```
1. Generate a unique ephemeral TAP name (e.g. fn-vmclient-<random>).
2. sudo tap-ctl.sh create <name>
3. Build an empty scratch disk (generalizing lib/scratch-disk.sh, which today always copies in
   a dnsmasq.conf — the client doesn't need one).
4. Copy the cached client image to a per-run working copy (Alpine will write to its own disk
   during boot — logs, /tmp — so, like the router, this can't be the shared cached image).
5. Boot: -netdev tap,ifname=<name>,... -device virtio-net-pci,netdev=...,mac=<CLIENT_MAC>
   -drive file=<working copy> -drive file=<scratch disk> -serial file:<console log> ...
6. Poll the scratch disk for .done (bounded timeout; expected well under the router's 180s
   given Alpine's minimal footprint).
7. On timeout: print the VM's console log, same diagnostic pattern the router path already
   uses on its own readiness timeout.
8. On success: read RESULT/ACTUAL_* off the scratch disk via mtools, same as today.
9. Always: stop the VM process, delete the ephemeral TAP (sudo tap-ctl.sh delete <name>), and
   remove the scratch disk / working copy — even on failure.
```

`CLIENT_TOOL` stays in the `client-N.conf` format (kept rather than dropped, even though v1 has
exactly one implementation) and its value becomes `alpine-vm`, replacing `busybox-udhcpc` across
all four existing scenario files.

## What gets removed

- `setup-host.sh` / `teardown-host.sh`: all `fn-client-0..3` namespace/veth creation and
  teardown. Only the bridge and router TAP remain.
- `functional/lib/netns-exec.sh`: deleted.
- `functional/dnsmasq-rs-functional.sudoers.example`: rewritten to grant `tap-ctl.sh` instead
  of `netns-exec.sh`.
- `functional/lib/udhcpc-handler.sh`: its logic moves into the client image as
  `functional/images/client-udhcpc-handler.sh` — it's guest content now (uploaded via
  `guestfish`, like `dnsmasq-rs.init` is for the router), not host-invoked tooling.
- `functional/README.md`: the "Optional: passwordless `ip netns exec`" section becomes about
  `tap-ctl.sh`; the one-time-setup section drops the namespace description; a new "Client VM
  image" section (mirroring "Router VM image") documents `fetch-alpine.sh` /
  `build-client-image.sh`.

## Error handling

- TAP name collision or creation failure → clear error from `tap-ctl.sh`, surfaced by
  `client.sh`, not a confusing low-level QEMU error.
- Client VM boot/run timeout (`.done` never appears) → explicit failure with the VM's console
  output printed, the same "print logs on failure" pattern the router path and `parity/`
  already use.
- Cleanup (VM process, ephemeral TAP, scratch disk, working image copy) always runs, even on
  failure — via the same `trap`-based approach `run.sh` already uses for the router VM, extended
  to cover the per-client VM resources too.

## Testing / acceptance criteria

This replaces the client execution mechanism entirely, so the bar is a full regression pass,
not incremental coverage:

- All four existing scenarios (`basic-lease`, `static-reservation`, `client-options`,
  `mac-blocklist-nak`) pass against the new VM-based client with identical `EXPECT_*` values —
  no scenario file's expectations should need to change, only `CLIENT_TOOL`.
- `mac-blocklist-nak`'s negative control (removing the `dhcp-host=...,ignore` line makes the
  scenario fail) is re-verified under the new mechanism, matching how it was originally verified
  for the namespace-based client.
- Running `run.sh` twice in a row leaves no leftover QEMU processes, TAPs, or work directories —
  the same criterion the harness's namespace-based version was already held to.
