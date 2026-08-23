# DHCP Harness VM-Based Client Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the DHCP functional test harness's namespace-based `busybox-udhcpc` client with a small QEMU-booted Alpine Linux VM per client, so every DHCP client run happens in a real VM instead of a Linux network namespace.

**Architecture:** Each client VM attaches to the harness's existing shared bridge (`dnsmasq-fnbr0`) via its own ephemeral TAP device (created and destroyed per client run, unlike the router's persistent one), booting a pre-customized Alpine image whose one job is: bring up `eth0`, run `udhcpc` once, write the result to a virtio-blk scratch disk, then power off. `functional/lib/client.sh`'s existing `EXPECT_*`/`ACTUAL_*` comparison logic is untouched — only how the `ACTUAL_*` facts get produced changes.

**Tech Stack:** Bash, QEMU/TCG, `guestfish`, `mtools`, Alpine Linux 3.24.1 (generic tiny-cloud image), OpenRC, BusyBox `udhcpc`.

**Spec:** `docs/superpowers/specs/2026-08-23-dhcp-harness-vm-client-design.md` (assumes the harness's overall architecture from `docs/superpowers/specs/2026-08-22-dhcp-functional-test-harness-design.md`).

## Global Constraints

- This host's `sudo` is `sudo-rs`, which rejects any wildcard character in a sudoers command argument. Every new privileged entry point needs its own fixed-path wrapper script with scoping done inside the script, exactly like `functional/lib/netns-exec.sh` already does — never a wildcard in the sudoers file itself.
- `guestfish` needs `sudo` on this host (the base image customization steps run as root) because its supermin helper VM must read the host kernel image, which is `0600 root:root`.
- No `/dev/kvm` access for this user — all VMs run under TCG (software emulation). Don't assume hardware acceleration anywhere.
- Pin exact image versions and checksums — never fetch "latest". The Alpine image for this plan is pinned to:
  - URL: `https://dl-cdn.alpinelinux.org/alpine/v3.24/releases/cloud/generic_alpine-3.24.1-x86_64-bios-tiny-r0.qcow2`
  - SHA-512: `c245c259397defd353095ee4416a1e4cffdb68aa57e5c8bb1bf06f019322c4f72eca9b1c6372e1ee1432bd4fa83669863e28f13817915387b743ea3782e3327e`
  - Verified layout (via read-only `guestfish` inspection): single ext4 filesystem on `/dev/sda` (no separate boot partition, unlike the OpenWrt router image's `sda1`/`sda2` split). `/etc/runlevels/default` contains `chronyd`, `networking`, `sshd`, `tiny-cloud-early`, `tiny-cloud-final`, `tiny-cloud-main`. `/sbin/udhcpc` is a symlink into BusyBox.
- This plan touches no Rust source — every task is shell scripts, one guest-side OpenRC init script, and config/doc updates. Still run `cargo test --all-features` before any commit as a sanity check that nothing else regressed (it should report the same pass count throughout).
- Testing real behavior (booting VMs, running `guestfish`, privileged `ip`/`tuntap` commands) needs `sudo`, which this environment's agent session cannot supply interactively. Every task that needs a privileged command run has the executor ask the human operator to run it and paste the output, then verify the result independently via unprivileged reads — the same workflow already established for the router VM image work. Do not skip real verification in favor of "should work" reasoning.

---

### Task 1: Fetch and verify the Alpine client base image

**Files:**
- Create: `functional/images/fetch-alpine.sh`

**Interfaces:**
- Produces: `functional/images/fetch-alpine.sh`, an executable script with no arguments that prints the absolute path to the verified image on its last line of stdout, exactly mirroring `functional/images/fetch-openwrt.sh`'s contract (Task 4 and `build-client-image.sh`, written in a later task, both rely on this).

- [ ] **Step 1: Write `fetch-alpine.sh`**

```bash
#!/usr/bin/env bash
set -euo pipefail

# Downloads and verifies the pinned Alpine x86_64 cloud image the functional
# harness's client VMs boot. Safe to re-run: skips the download if the
# image already exists.
#
# The image lives under functional/.cache/ (gitignored) — it does not
# belong in git, the same reasoning fetch-openwrt.sh documents for the
# router image.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CACHE_DIR="$ROOT_DIR/functional/.cache"

ALPINE_VERSION=3.24.1
ALPINE_BRANCH=v3.24
IMAGE_BASENAME="generic_alpine-${ALPINE_VERSION}-x86_64-bios-tiny-r0.qcow2"
IMAGE_URL="https://dl-cdn.alpinelinux.org/alpine/${ALPINE_BRANCH}/releases/cloud/${IMAGE_BASENAME}"
# From https://dl-cdn.alpinelinux.org/alpine/v3.24/releases/cloud/generic_alpine-3.24.1-x86_64-bios-tiny-r0.qcow2.sha512
# -- pinned so a tampered or corrupted download is caught rather than
# silently used.
EXPECTED_SHA512=c245c259397defd353095ee4416a1e4cffdb68aa57e5c8bb1bf06f019322c4f72eca9b1c6372e1ee1432bd4fa83669863e28f13817915387b743ea3782e3327e

log() { echo "==> $*"; }

mkdir -p "$CACHE_DIR"
cd "$CACHE_DIR"

IMG_PATH="$CACHE_DIR/$IMAGE_BASENAME"

if [[ -f "$IMG_PATH" ]]; then
  log "already have $IMAGE_BASENAME, skipping download"
  echo "$IMG_PATH"
  exit 0
fi

log "downloading $IMAGE_BASENAME (Alpine $ALPINE_VERSION)"
curl -fL --progress-bar -o "$IMG_PATH" "$IMAGE_URL"

log "verifying checksum"
ACTUAL_SHA512=$(sha512sum "$IMG_PATH" | cut -d' ' -f1)
if [[ "$ACTUAL_SHA512" != "$EXPECTED_SHA512" ]]; then
  echo "checksum mismatch for $IMG_PATH:" >&2
  echo "  expected: $EXPECTED_SHA512" >&2
  echo "  actual:   $ACTUAL_SHA512" >&2
  rm -f "$IMG_PATH"
  exit 1
fi

log "fetched $IMG_PATH"
echo "$IMG_PATH"
```

- [ ] **Step 2: Make it executable and check syntax**

```bash
chmod +x functional/images/fetch-alpine.sh
bash -n functional/images/fetch-alpine.sh
```

Expected: no output (syntax OK).

- [ ] **Step 3: Run it for real (unprivileged — no sudo needed)**

```bash
./functional/images/fetch-alpine.sh
```

Expected: downloads the image, verifies the checksum, and prints the absolute path to `functional/.cache/generic_alpine-3.24.1-x86_64-bios-tiny-r0.qcow2` as the last line.

- [ ] **Step 4: Run it again to confirm the skip-if-cached path**

```bash
./functional/images/fetch-alpine.sh
```

Expected: prints `==> already have generic_alpine-3.24.1-x86_64-bios-tiny-r0.qcow2, skipping download` and the same path, with no download.

- [ ] **Step 5: Commit**

```bash
git add functional/images/fetch-alpine.sh
git commit -m "functional: fetch the pinned Alpine client VM base image"
```

---

### Task 2: TAP lifecycle sudo wrapper

**Files:**
- Create: `functional/lib/tap-ctl.sh`
- Modify: `functional/dnsmasq-rs-functional.sudoers.example`

**Interfaces:**
- Consumes: `$BRIDGE` (must match `functional/lib/common.sh`'s `BRIDGE=dnsmasq-fnbr0` constant — this script does not source `common.sh`, since it runs under `sudo` as a standalone entry point exactly like `netns-exec.sh` does; keep the value in sync manually, same as that file already requires).
- Produces: `functional/lib/tap-ctl.sh create <name>` and `functional/lib/tap-ctl.sh delete <name>`, where `<name>` must match `fn-vmclient-*` or the script refuses and exits 1. `create` makes the TAP, attaches it to the bridge, and brings it up, owned by the invoking (`SUDO_USER`) user. Task 5's `client.sh` calls this via `sudo`.

- [ ] **Step 1: Write `tap-ctl.sh`**

```bash
#!/usr/bin/env bash
set -euo pipefail

# Narrow sudo entry point for functional/lib/client.sh: creates/destroys the
# ephemeral TAP device each client VM attaches to the shared bridge with.
# Granted passwordless sudo via
# functional/dnsmasq-rs-functional.sudoers.example, which grants this exact
# absolute path with no argument list in the sudoers spec -- this host's
# sudo (sudo-rs) rejects any wildcard character in a command argument
# outright, so the fn-vmclient-* scoping below is what actually constrains
# this, not the sudoers grant syntax. Same pattern netns-exec.sh already
# uses for namespace names.

# Must match functional/lib/common.sh's $BRIDGE.
BRIDGE=dnsmasq-fnbr0

op="${1:-}"
name="${2:-}"

case "$name" in
  fn-vmclient-*) ;;
  *)
    echo "tap-ctl.sh: refusing non fn-vmclient-* TAP name: '$name'" >&2
    exit 1
    ;;
esac

case "$op" in
  create)
    ip tuntap add dev "$name" mode tap user "${SUDO_USER:-$(id -un)}"
    ip link set "$name" master "$BRIDGE"
    ip link set "$name" up
    ;;
  delete)
    ip link delete "$name" 2>/dev/null || true
    ;;
  *)
    echo "tap-ctl.sh: usage: tap-ctl.sh create|delete <fn-vmclient-name>" >&2
    exit 1
    ;;
esac
```

- [ ] **Step 2: Make it executable and check syntax**

```bash
chmod +x functional/lib/tap-ctl.sh
bash -n functional/lib/tap-ctl.sh
```

Expected: no output.

- [ ] **Step 3: Rewrite the sudoers example to grant this instead of `netns-exec.sh`**

Replace the entire contents of `functional/dnsmasq-rs-functional.sudoers.example` with:

```
# Optional: install this to let `functional/lib/client.sh` create/destroy
# the ephemeral TAP devices client VMs attach to the shared bridge with,
# without a sudo password prompt on every run. Not required — without it,
# tap-ctl.sh calls will just prompt for your password each time.
#
# Install:
#   1. Replace YOUR_USERNAME below with your actual username (`whoami`).
#   2. Replace /home/YOUR_USERNAME/Projects/dnsmasq-rs below with this
#      repo's actual absolute path.
#   3. sudo cp functional/dnsmasq-rs-functional.sudoers.example \
#        /etc/sudoers.d/dnsmasq-rs-functional
#   4. sudo chmod 0440 /etc/sudoers.d/dnsmasq-rs-functional
#   5. sudo visudo -c   # verify the file parses before trusting it
#
# Scope: only functional/lib/tap-ctl.sh, a narrow wrapper that itself
# refuses any TAP name not matching fn-vmclient-* — nothing broader. This
# grants the wrapper script itself, not `ip tuntap`/`ip link` directly with
# a wildcard: this host's sudo (sudo-rs, Ubuntu's Rust reimplementation)
# rejects any wildcard character ("*", "?", "[]") in a command argument
# outright ("wildcards are not allowed in command arguments"), so the
# fn-vmclient-* scoping has to live in the wrapper script instead of the
# sudoers file. A bare command path with no argument list (as below) still
# matches any arguments, per standard sudoers(5) semantics — that part is
# not a wildcard and sudo-rs does support it.
YOUR_USERNAME ALL=(root) NOPASSWD: /home/YOUR_USERNAME/Projects/dnsmasq-rs/functional/lib/tap-ctl.sh
```

- [ ] **Step 4: Ask the human operator to (re)install the sudoers rule and verify TAP create/delete work**

Ask them to run, replacing `YOUR_USERNAME`/path if needed (they'll already have a similar rule installed from the earlier `netns-exec.sh` work — this replaces it):

```bash
sudo cp functional/dnsmasq-rs-functional.sudoers.example /etc/sudoers.d/dnsmasq-rs-functional
sudo sed -i 's/YOUR_USERNAME/'"$(whoami)"'/g' /etc/sudoers.d/dnsmasq-rs-functional
sudo chmod 0440 /etc/sudoers.d/dnsmasq-rs-functional
sudo visudo -c
```

Then, without any further sudo prompt, verify directly:

```bash
sudo -n /home/YOUR_USERNAME/Projects/dnsmasq-rs/functional/lib/tap-ctl.sh create fn-vmclient-test
ip link show fn-vmclient-test
sudo -n /home/YOUR_USERNAME/Projects/dnsmasq-rs/functional/lib/tap-ctl.sh delete fn-vmclient-test
ip link show fn-vmclient-test
```

Expected: `visudo -c` reports the file parsed OK; the first `ip link show` shows the TAP attached to `dnsmasq-fnbr0` and up; the second `ip link show` fails with "does not exist" (deleted). Also verify the safety check independently:

```bash
sudo -n /home/YOUR_USERNAME/Projects/dnsmasq-rs/functional/lib/tap-ctl.sh create not-fn-vmclient-prefixed
```

Expected: `tap-ctl.sh: refusing non fn-vmclient-* TAP name: 'not-fn-vmclient-prefixed'`, exit 1, no TAP created.

- [ ] **Step 5: Commit**

```bash
git add functional/lib/tap-ctl.sh functional/dnsmasq-rs-functional.sudoers.example
git commit -m "functional: add tap-ctl.sh sudo wrapper for ephemeral client TAPs"
```

---

### Task 3: Generalize `lib/vm.sh`/`lib/scratch-disk.sh`, update `run.sh`'s call sites

**Files:**
- Modify: `functional/lib/vm.sh`
- Modify: `functional/lib/scratch-disk.sh`
- Modify: `functional/run.sh`

**Interfaces:**
- Produces (renamed/generalized from the router-only originals, for Task 5's client VM path to consume):
  - `start_vm(tap, mem_mb, image, scratch_disk, console_log, qemu_log, mac)` — `mac` may be an empty string, in which case no `mac=` is added to the `-device` line and QEMU picks one. Returns the QEMU PID on stdout, same as `start_router_vm` did.
  - `wait_for_marker(scratch_disk, timeout_s, marker_grep_pattern)` — generalized from `wait_for_vm_ready`, which only ever checked for `.ready`.
  - `stop_vm(pid)` — renamed from `stop_router_vm`, unchanged behavior.
  - `print_vm_diagnostics(console_log, scratch_disk, extra_file)` — `extra_file` may be an empty string, in which case the "extra file" dump is skipped. Previously hardcoded to `dnsmasq-rs.log`.
  - `build_empty_scratch_disk(out_img)` — new, alongside the existing `build_scenario_disk`.

- [ ] **Step 1: Rewrite `functional/lib/vm.sh`**

```bash
#!/usr/bin/env bash
# QEMU VM lifecycle helpers for functional/run.sh and functional/lib/client.sh.
# Shared between the router VM (persistent TAP, `-m 512`) and per-client VMs
# (ephemeral TAP, `-m 256`) — not executable on its own.

start_vm() {
  local tap="$1" mem_mb="$2" image="$3" scratch_disk="$4" console_log="$5" qemu_log="$6" mac="$7"
  local device_arg="virtio-net-pci,netdev=lan0"
  [[ -n "$mac" ]] && device_arg="${device_arg},mac=${mac}"
  qemu-system-x86_64 \
    -m "$mem_mb" \
    -netdev tap,id=lan0,ifname="$tap",script=no,downscript=no \
    -device "$device_arg" \
    -drive file="$image",if=virtio,format=raw \
    -drive file="$scratch_disk",if=virtio,format=raw \
    -serial file:"$console_log" \
    -monitor none -display none -no-reboot \
    >"$qemu_log" 2>&1 &
  echo $!
}

# Polls the scratch disk (unprivileged, via mtools) for a marker file the
# guest's init script writes once it's done — ".ready" for the router
# (still serving), ".done" for a client VM (finished and about to power
# off).
wait_for_marker() {
  local scratch_disk="$1" timeout_s="$2" marker="$3"
  local waited=0
  while (( waited < timeout_s )); do
    if mdir -i "$scratch_disk" :: 2>/dev/null | grep -qi "$marker"; then
      return 0
    fi
    sleep 2
    waited=$((waited + 2))
  done
  return 1
}

stop_vm() {
  local pid="$1"
  [[ -z "$pid" ]] && return 0
  kill "$pid" 2>/dev/null || return 0
  local waited=0
  while kill -0 "$pid" 2>/dev/null && (( waited < 10 )); do
    sleep 1
    waited=$((waited + 1))
  done
  kill -9 "$pid" 2>/dev/null || true
}

print_vm_diagnostics() {
  local console_log="$1" scratch_disk="$2" extra_file="${3:-}"
  echo "--- VM console log (tail -60) ---"
  tail -n 60 "$console_log" 2>/dev/null || echo "(no console log captured)"
  if [[ -n "$extra_file" ]]; then
    echo "--- $extra_file from scratch disk (if present) ---"
    mtype -i "$scratch_disk" "::$extra_file" 2>/dev/null || echo "($extra_file not present on scratch disk)"
  fi
}
```

- [ ] **Step 2: Add `build_empty_scratch_disk` to `functional/lib/scratch-disk.sh`**

Append this function to the end of the existing file (leave `build_scenario_disk` untouched):

```bash

# A client VM needs no per-scenario config injected — only a blank,
# formatted disk to write its result back onto.
build_empty_scratch_disk() {
  local out_img="$1"
  dd if=/dev/zero of="$out_img" bs=1M count=8 status=none
  mformat -i "$out_img" -v SCRATCH ::
}
```

- [ ] **Step 3: Update `functional/run.sh`'s call sites to the renamed/generalized functions**

In `functional/run.sh`, change:

```bash
VM_PID=""
cleanup() {
  stop_router_vm "$VM_PID"
  rm -rf "$WORK_DIR"
}
```

to:

```bash
VM_PID=""
cleanup() {
  stop_vm "$VM_PID"
  rm -rf "$WORK_DIR"
}
```

Change:

```bash
log "booting router VM"
VM_PID="$(start_router_vm "$ROUTER_RUN_IMG" "$SCENARIO_DISK" "$CONSOLE_LOG" "$QEMU_LOG")"

log "waiting for dnsmasq-rs to become ready (timeout 180s)"
if ! wait_for_vm_ready "$SCENARIO_DISK" 180; then
  err "VM did not become ready within 180s"
  print_vm_diagnostics "$CONSOLE_LOG" "$SCENARIO_DISK"
  exit 1
fi
```

to:

```bash
log "booting router VM"
VM_PID="$(start_vm "$TAP" 512 "$ROUTER_RUN_IMG" "$SCENARIO_DISK" "$CONSOLE_LOG" "$QEMU_LOG" "")"

log "waiting for dnsmasq-rs to become ready (timeout 180s)"
if ! wait_for_marker "$SCENARIO_DISK" 180 '\.ready'; then
  err "VM did not become ready within 180s"
  print_vm_diagnostics "$CONSOLE_LOG" "$SCENARIO_DISK" "dnsmasq-rs.log"
  exit 1
fi
```

Also update the top-of-file comment block (it currently says `# Needs no sudo of its own except the \`ip netns exec\` calls inside # lib/client.sh ...`) to:

```bash
# Needs no sudo of its own except the tap-ctl.sh calls inside lib/client.sh
# (optionally passwordless — see
# functional/dnsmasq-rs-functional.sudoers.example).
```

- [ ] **Step 4: Syntax-check everything touched**

```bash
bash -n functional/lib/vm.sh
bash -n functional/lib/scratch-disk.sh
bash -n functional/run.sh
```

Expected: no output.

- [ ] **Step 5: Regression-test the router path (client execution is untouched in this task — still namespace-based)**

```bash
./functional/run.sh basic-lease
```

Expected: `==> basic-lease: 1 passed, 0 failed`, exit 0 — identical to before this task, proving the `vm.sh` rename didn't break the router VM boot/readiness path.

- [ ] **Step 6: Commit**

```bash
git add functional/lib/vm.sh functional/lib/scratch-disk.sh functional/run.sh
git commit -m "functional: generalize lib/vm.sh for shared router/client VM use"
```

---

### Task 4: Guest-side client files and `build-client-image.sh`

**Files:**
- Create: `functional/images/client-udhcpc-handler.sh`
- Create: `functional/images/client-dhcp-test.init`
- Create: `functional/images/build-client-image.sh`

**Interfaces:**
- Consumes: `functional/images/fetch-alpine.sh` (Task 1).
- Produces: `functional/.cache/client.img` — a raw-format, bootable Alpine image with `dhcp-test-client` as the only enabled default-runlevel service. Task 5's `client.sh` copies this per-run, exactly as `run.sh` already does with `router.img`.

- [ ] **Step 1: Write `client-udhcpc-handler.sh`** (a verbatim copy of the existing `functional/lib/udhcpc-handler.sh` — same event contract, now guest-side content instead of host-invoked tooling)

```sh
#!/bin/sh
# busybox udhcpc event handler for the DHCP functional test harness's
# VM-based client. Invoked by udhcpc itself as: $0 deconfig|bound|renew|nak|leasefail
# udhcpc exports lease facts (ip, router, dns, lease, ...) as environment
# variables for bound/renew. This normalizes them into a shell-sourceable
# RESULT file that functional/lib/client.sh reads back off the scratch
# disk. Guest-side counterpart of the harness's original namespace-based
# handler script — same output format, uploaded into the client VM image
# by build-client-image.sh instead of invoked directly on the host.

[ -n "$RESULT_FILE" ] || exit 0

case "$1" in
	bound|renew)
		# router/dns can carry multiple space-separated addresses; take
		# the first, both because that's what a real client primarily
		# acts on and because an unquoted multi-word value would corrupt
		# this file's own shell-assignment syntax when client.sh sources
		# it back (`FOO=a b` runs "b" as a command with FOO=a in its
		# environment, leaving the caller's FOO unset).
		{
			echo "RESULT=lease"
			echo "ACTUAL_IP=$ip"
			echo "ACTUAL_ROUTER=${router%% *}"
			echo "ACTUAL_DNS=${dns%% *}"
			echo "ACTUAL_LEASE=$lease"
			echo "ACTUAL_DOMAIN=$domain"
			echo "ACTUAL_NTP=${ntpsrv%% *}"
		} > "$RESULT_FILE"
		;;
	nak)
		echo "RESULT=nak" > "$RESULT_FILE"
		;;
	leasefail)
		echo "RESULT=timeout" > "$RESULT_FILE"
		;;
esac
```

- [ ] **Step 2: Write `client-dhcp-test.init`** (an OpenRC init script)

```sh
#!/sbin/openrc-run
# One-shot DHCP client for the DHCP functional test harness's VM-based
# client (see
# docs/superpowers/specs/2026-08-23-dhcp-harness-vm-client-design.md). Not
# a long-running service: brings up eth0, runs udhcpc once, writes the
# result to the scratch disk functional/lib/client.sh attached, then
# powers off. build-client-image.sh disables this image's own default
# networking/tiny-cloud services so nothing else touches eth0 or delays
# boot looking for a cloud-init datasource that doesn't exist here.

description="One-shot DHCP client run for the dnsmasq-rs functional test harness"

find_scratch_disk() {
	local i=0
	while [ $i -lt 30 ]; do
		if [ -b /dev/vdb1 ]; then
			echo /dev/vdb1
			return 0
		elif [ -b /dev/vdb ]; then
			echo /dev/vdb
			return 0
		fi
		sleep 1
		i=$((i + 1))
	done
	return 1
}

start() {
	ebegin "$description"

	local dev
	dev="$(find_scratch_disk)" || {
		eend 1 "scratch disk never appeared"
		poweroff
		return 1
	}

	mkdir -p /mnt/scratch
	mount -t vfat "$dev" /mnt/scratch

	ip link set eth0 up

	RESULT_FILE=/mnt/scratch/result \
		udhcpc -i eth0 -n -q -f -t 8 -T 3 \
			-O domain -O ntpsrv \
			-s /usr/local/sbin/dhcp-test-handler.sh \
		>/mnt/scratch/udhcpc.log 2>&1

	touch /mnt/scratch/.done
	sync

	eend 0
	poweroff
}
```

- [ ] **Step 3: Write `build-client-image.sh`**

```bash
#!/usr/bin/env bash
set -euo pipefail

# Customizes the fetched Alpine base image into the client VM image
# functional/lib/client.sh boots: disables the image's own default-runlevel
# services (networking, tiny-cloud-*, sshd, chronyd -- none of which this
# harness needs, and "networking" would otherwise race our own manual
# udhcpc run on eth0) and installs one custom OpenRC service that runs a
# single DHCP transaction and reports the result (see
# docs/superpowers/specs/2026-08-23-dhcp-harness-vm-client-design.md).
#
# Requires sudo: guestfish's supermin helper VM needs to read the host
# kernel image, the same reason build-router-image.sh needs it.
#
# Safe to re-run: always rebuilds functional/.cache/client.img fresh from
# the pristine base image fetch-alpine.sh downloaded.

if [[ $EUID -ne 0 ]]; then
  echo "build-client-image.sh must be run with sudo (guestfish needs to read the host kernel)." >&2
  exit 1
fi

REAL_USER="${SUDO_USER:-$(id -un)}"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CACHE_DIR="$ROOT_DIR/functional/.cache"
CLIENT_IMG="$CACHE_DIR/client.img"

log() { echo "==> $*"; }

log "fetching base image (no-op if already cached)"
BASE_IMG="$(sudo -u "$REAL_USER" "$ROOT_DIR/functional/images/fetch-alpine.sh" | tail -1)"

log "copying base image to $CLIENT_IMG for customization"
cp -f "$BASE_IMG" "$CLIENT_IMG"

# The image has a single ext4 filesystem directly on sda (no partition
# table, unlike OpenWrt's sda1/sda2 router image) -- confirmed by
# inspecting the Alpine 3.24.1 generic_alpine-*-bios-tiny-r0 image via
# `guestfish --ro ... list-filesystems`.
log "customizing $CLIENT_IMG via guestfish"
guestfish -a "$CLIENT_IMG" -m /dev/sda <<GUESTFISH
upload $ROOT_DIR/functional/images/client-dhcp-test.init /etc/init.d/dhcp-test-client
chmod 0755 /etc/init.d/dhcp-test-client

upload $ROOT_DIR/functional/images/client-udhcpc-handler.sh /usr/local/sbin/dhcp-test-handler.sh
chmod 0755 /usr/local/sbin/dhcp-test-handler.sh

# Disable every default-runlevel service this image ships with: "networking"
# would bring up its own DHCP client on eth0 and race our own; the
# tiny-cloud-* services would otherwise spend boot time looking for a
# cloud-init datasource that doesn't exist here; sshd/chronyd aren't needed
# for a single DHCP transaction. This is the offline equivalent of
# \`rc-update del <service> default\` for each.
rm-f /etc/runlevels/default/networking
rm-f /etc/runlevels/default/tiny-cloud-early
rm-f /etc/runlevels/default/tiny-cloud-final
rm-f /etc/runlevels/default/tiny-cloud-main
rm-f /etc/runlevels/default/sshd
rm-f /etc/runlevels/default/chronyd

ln-sf ../init.d/dhcp-test-client /etc/runlevels/default/dhcp-test-client
GUESTFISH

# The base image is qcow2; guestfish edits it in place without changing
# its format. Convert to raw so vm.sh's shared start_vm (used by both the
# router and every client VM) can assume every image drive is
# format=raw, matching the OpenWrt router image's native format.
log "converting to raw format for QEMU boot"
qemu-img convert -O raw "$CLIENT_IMG" "$CLIENT_IMG.raw"
mv -f "$CLIENT_IMG.raw" "$CLIENT_IMG"

chown "$REAL_USER" "$CLIENT_IMG"

log "built $CLIENT_IMG"
echo "$CLIENT_IMG"
```

- [ ] **Step 4: Make scripts executable, syntax-check**

```bash
chmod +x functional/images/build-client-image.sh
sh -n functional/images/client-udhcpc-handler.sh
bash -n functional/images/build-client-image.sh
```

`client-dhcp-test.init` has no direct syntax-check equivalent (it's an OpenRC script, not a standalone executable on the host) — it gets validated by actually booting the image in Task 5.

Expected: no output from either check.

- [ ] **Step 5: Ask the human operator to build the image**

```bash
sudo ./functional/images/build-client-image.sh
```

Expected: completes without error, ends with `==> built /home/.../functional/.cache/client.img` and the path.

- [ ] **Step 6: Independently verify the customization via read-only `guestfish` inspection**

Ask the human operator to run and paste the output:

```bash
sudo guestfish --ro -a functional/.cache/client.img -i <<'EOF'
is-file /etc/init.d/dhcp-test-client
is-file /usr/local/sbin/dhcp-test-handler.sh
is-symlink /etc/runlevels/default/dhcp-test-client
ls /etc/runlevels/default
EOF
```

Expected: first three lines `true`; the `ls` output lists exactly `dhcp-test-client` (none of `networking`/`sshd`/`chronyd`/`tiny-cloud-*` remain).

Also confirm the raw-format conversion succeeded:

```bash
file functional/.cache/client.img
```

Expected: reports a raw disk image (e.g. `DOS/MBR boot sector` or similar — NOT "QEMU QCOW2 Image").

- [ ] **Step 7: Commit**

```bash
git add functional/images/client-udhcpc-handler.sh functional/images/client-dhcp-test.init functional/images/build-client-image.sh
git commit -m "functional: add Alpine client VM image build (guest init + handler)"
```

---

### Task 5: `client.sh` VM-based execution path

**Files:**
- Modify: `functional/lib/client.sh`
- Modify: `functional/run.sh`

**Interfaces:**
- Consumes: `start_vm`, `wait_for_marker`, `stop_vm`, `print_vm_diagnostics` (Task 3), `build_empty_scratch_disk` (Task 3), `functional/lib/tap-ctl.sh` (Task 2), `$CACHE_DIR/client.img` (Task 4).
- Produces: `run_and_check_client(conf_file, label)` — signature changes from the current `run_and_check_client(conf_file, ns, label)`: the `ns` (namespace) parameter is gone, since clients are no longer namespace slots. `run.sh`'s client loop (this task) is the only caller and gets updated to match.

- [ ] **Step 1: Replace `run_busybox_udhcpc` with `run_alpine_vm_client` in `functional/lib/client.sh`**

Delete this whole function:

```bash
# Brings up $ns's eth0 with $mac, runs busybox udhcpc against it, and writes
# a normalized RESULT=lease|nak|timeout (plus ACTUAL_* facts on lease) to
# $result_file via lib/udhcpc-handler.sh — see that script for why router/
# dns/ntp are reduced to their first address and why the file must stay
# single-word-per-line.
run_busybox_udhcpc() {
  local ns="$1" mac="$2" result_file="$3"
  local netns_exec="$LIB_DIR/netns-exec.sh"

  sudo "$netns_exec" "$ns" ip link set eth0 down
  sudo "$netns_exec" "$ns" ip link set eth0 address "$mac"
  sudo "$netns_exec" "$ns" ip link set eth0 up

  # -t 8 -T 3 gives ~24s of discover retries (the 45s wrapper below leaves
  # headroom for the request/ack round trip after an offer arrives): the
  # veth flap above drops carrier on the host-side bridge port too, and
  # how long it takes to return to forwarding varies with how loaded the
  # host is running the (unaccelerated, TCG) router VM alongside
  # everything else — a fixed short guard delay was tried and still
  # flaked under load. Retrying across a longer window is the standard
  # way DHCP clients absorb this instead of guessing a fixed delay.
  #
  # -O domain -O ntpsrv: busybox only requests a baseline option set by
  # default: client-options scenarios need these explicitly requested to
  # get them back at all.
  timeout 45 sudo "$netns_exec" "$ns" \
    env RESULT_FILE="$result_file" \
    busybox udhcpc -i eth0 -n -q -f -t 8 -T 3 \
      -O domain -O ntpsrv \
      -s "$LIB_DIR/udhcpc-handler.sh" \
    >/dev/null 2>&1 || true
}
```

Replace it with:

```bash
# Boots a small Alpine VM (functional/.cache/client.img, built by
# functional/images/build-client-image.sh) attached to the shared bridge
# via a fresh ephemeral TAP, waits for it to run its one-shot DHCP client
# and report results, and writes the same RESULT=/ACTUAL_* shape to
# $result_file that the namespace-based busybox-udhcpc path used to —
# comparison logic in run_and_check_client never needs to know the
# difference. See
# docs/superpowers/specs/2026-08-23-dhcp-harness-vm-client-design.md.
run_alpine_vm_client() {
  local mac="$1" result_file="$2"
  local tap_ctl="$LIB_DIR/tap-ctl.sh"
  local tap_name="fn-vmclient-$$-$RANDOM"

  sudo "$tap_ctl" create "$tap_name"

  local work_dir client_img scratch_disk console_log qemu_log
  work_dir="$(mktemp -d)"
  client_img="$work_dir/client.img"
  scratch_disk="$work_dir/scratch.img"
  console_log="$work_dir/console.log"
  qemu_log="$work_dir/qemu.log"

  build_empty_scratch_disk "$scratch_disk"
  cp -f "$CACHE_DIR/client.img" "$client_img"

  local vm_pid
  vm_pid="$(start_vm "$tap_name" 256 "$client_img" "$scratch_disk" "$console_log" "$qemu_log" "$mac")"

  if wait_for_marker "$scratch_disk" 60 '\.done'; then
    mtype -i "$scratch_disk" ::result > "$result_file" 2>/dev/null || true
  else
    echo "client VM did not finish within 60s" >&2
    print_vm_diagnostics "$console_log" "$scratch_disk" ""
  fi

  stop_vm "$vm_pid"
  sudo "$tap_ctl" delete "$tap_name"
  rm -rf "$work_dir"
}
```

- [ ] **Step 2: Update `run_and_check_client`'s signature and dispatch**

Change:

```bash
run_and_check_client() {
  local conf_file="$1" ns="$2" label="$3"
```

to:

```bash
run_and_check_client() {
  local conf_file="$1" label="$2"
```

Change:

```bash
  case "$CLIENT_TOOL" in
    busybox-udhcpc)
      run_busybox_udhcpc "$ns" "$CLIENT_MAC" "$result_file"
      ;;
    *)
      echo "FAIL $label: unsupported CLIENT_TOOL '$CLIENT_TOOL' (v1 supports busybox-udhcpc only — see issue #141 for a VM-based second client type)"
      rm -rf "$result_dir"
      return 1
      ;;
  esac
```

to:

```bash
  case "$CLIENT_TOOL" in
    alpine-vm)
      run_alpine_vm_client "$CLIENT_MAC" "$result_file"
      ;;
    *)
      echo "FAIL $label: unsupported CLIENT_TOOL '$CLIENT_TOOL' (v1 supports alpine-vm only)"
      rm -rf "$result_dir"
      return 1
      ;;
  esac
```

Leave every other line of `run_and_check_client` (the `EXPECT_*`/`ACTUAL_*` comparison block) exactly as-is.

- [ ] **Step 3: Update `functional/run.sh`'s client loop**

Change:

```bash
PASS_COUNT=0
FAIL_COUNT=0
for conf_file in "$SCENARIO_DIR"/client-*.conf; do
  [[ -e "$conf_file" ]] || continue
  label="$(basename "$conf_file" .conf)"
  idx="${label#client-}"
  ns="fn-client-$idx"
  log "running client $label against namespace $ns"
  if run_and_check_client "$conf_file" "$ns" "$label"; then
    PASS_COUNT=$((PASS_COUNT + 1))
  else
    FAIL_COUNT=$((FAIL_COUNT + 1))
  fi
done
```

to:

```bash
PASS_COUNT=0
FAIL_COUNT=0
for conf_file in "$SCENARIO_DIR"/client-*.conf; do
  [[ -e "$conf_file" ]] || continue
  label="$(basename "$conf_file" .conf)"
  log "running client $label"
  if run_and_check_client "$conf_file" "$label"; then
    PASS_COUNT=$((PASS_COUNT + 1))
  else
    FAIL_COUNT=$((FAIL_COUNT + 1))
  fi
done
```

- [ ] **Step 4: Also require the client image, alongside the router image**

In `functional/lib/common.sh`, add a new function right after `require_router_image`:

```bash
require_client_image() {
  if [[ ! -f "$CACHE_DIR/client.img" ]]; then
    err "client image not built — run: sudo ./functional/images/build-client-image.sh"
    exit 1
  fi
}
```

In `functional/run.sh`, change:

```bash
require_host_setup
require_router_image
```

to:

```bash
require_host_setup
require_router_image
require_client_image
```

- [ ] **Step 5: Syntax-check everything touched**

```bash
bash -n functional/lib/client.sh
bash -n functional/lib/common.sh
bash -n functional/run.sh
```

Expected: no output.

- [ ] **Step 6: First real end-to-end test — `basic-lease` still references `CLIENT_TOOL=busybox-udhcpc` at this point, so temporarily point it at the new mechanism to prove it end-to-end before Task 6's permanent scenario-file rewrite**

Ask the human operator to run:

```bash
sed -i 's/CLIENT_TOOL=busybox-udhcpc/CLIENT_TOOL=alpine-vm/' functional/scenarios/basic-lease/client-0.conf
./functional/run.sh basic-lease
git checkout functional/scenarios/basic-lease/client-0.conf
```

Expected: `==> basic-lease: 1 passed, 0 failed`, exit 0. If it fails, use `print_vm_diagnostics`'s console-log dump (printed automatically on a `wait_for_marker` timeout) to diagnose — this is a genuinely new boot path (first real boot of the Alpine image), so budget time for iteration exactly like the router image needed in earlier issues (procd, `SO_BROADCAST`, `IP_PKTINFO` were all found this way). The final `git checkout` reverts the temporary edit — Task 6 makes the permanent version of this change across all four scenario files.

- [ ] **Step 7: Commit**

```bash
git add functional/lib/client.sh functional/lib/common.sh functional/run.sh
git commit -m "functional: run DHCP clients as Alpine VMs instead of namespaces"
```

---

### Task 6: Scenario config updates, dead-code removal, docs

**Files:**
- Modify: `functional/scenarios/basic-lease/client-0.conf`
- Modify: `functional/scenarios/static-reservation/client-0.conf`
- Modify: `functional/scenarios/client-options/client-0.conf`
- Modify: `functional/scenarios/mac-blocklist-nak/client-0.conf`
- Modify: `functional/setup-host.sh`
- Modify: `functional/teardown-host.sh`
- Delete: `functional/lib/netns-exec.sh`
- Delete: `functional/lib/udhcpc-handler.sh` (superseded by `functional/images/client-udhcpc-handler.sh` from Task 4)
- Modify: `functional/README.md`

**Interfaces:**
- Consumes: everything from Tasks 1-5. This task removes the last references to the retired namespace-based mechanism and updates all four scenario files to the new `CLIENT_TOOL` value.

- [ ] **Step 1: Update `CLIENT_TOOL` in all four scenario files**

In each of `functional/scenarios/{basic-lease,static-reservation,client-options,mac-blocklist-nak}/client-0.conf`, change the line `CLIENT_TOOL=busybox-udhcpc` to `CLIENT_TOOL=alpine-vm`. (`mac-blocklist-nak/client-0.conf` has a comment block above it — leave the comment as-is, only change the `CLIENT_TOOL=` line itself.)

- [ ] **Step 2: Trim `functional/setup-host.sh` to just the bridge and router TAP**

Replace the whole file with:

```bash
#!/usr/bin/env bash
set -euo pipefail

# One-time (idempotent) host network setup for the DHCP functional test
# harness. Requires sudo — creating the bridge and TAP needs CAP_NET_ADMIN.
# See docs/superpowers/specs/2026-08-22-dhcp-functional-test-harness-design.md
# for the full design and rationale.
#
# Creates:
#   - a Linux bridge (dnsmasq-fnbr0) — the shared L2 segment the router VM
#     and every client VM's ephemeral TAP attach to.
#   - one persistent TAP device (dnsmasq-fntap0) for the router VM's LAN
#     interface, chowned to the invoking (non-root) user so a later,
#     unprivileged `qemu-system-x86_64` can attach to it directly.
#
# Client VMs each get their own ephemeral TAP, created and destroyed per run
# by functional/lib/tap-ctl.sh (see
# docs/superpowers/specs/2026-08-23-dhcp-harness-vm-client-design.md) — there
# is no more one-time client setup here.
#
# Safe to re-run: every step checks whether its target already exists first.

if [[ $EUID -ne 0 ]]; then
  echo "setup-host.sh must be run with sudo (it creates the bridge/TAP)." >&2
  exit 1
fi

# The user who invoked sudo -- the TAP device is chowned to them so a later,
# unprivileged `qemu-system-x86_64` can open it directly.
REAL_USER="${SUDO_USER:-$(id -un)}"

BRIDGE=dnsmasq-fnbr0
TAP=dnsmasq-fntap0

log() { echo "==> $*"; }

if ! ip link show "$BRIDGE" &>/dev/null; then
  log "creating bridge $BRIDGE"
  ip link add name "$BRIDGE" type bridge
  ip link set "$BRIDGE" up
else
  log "bridge $BRIDGE already exists"
fi

if ! ip link show "$TAP" &>/dev/null; then
  log "creating TAP $TAP for the router VM, owned by $REAL_USER"
  ip tuntap add dev "$TAP" mode tap user "$REAL_USER"
  ip link set "$TAP" master "$BRIDGE"
  ip link set "$TAP" up
else
  log "TAP $TAP already exists"
fi

log "setup complete: bridge=$BRIDGE tap=$TAP"
```

- [ ] **Step 3: Trim `functional/teardown-host.sh` to match**

Replace the whole file with:

```bash
#!/usr/bin/env bash
set -uo pipefail
# Deliberately not `set -e`: teardown should attempt every step even if an
# earlier one fails, so a partial or double-run teardown doesn't abort
# halfway with unrelated state left behind.

# Reverses setup-host.sh. Requires sudo, same reason as setup-host.sh.

if [[ $EUID -ne 0 ]]; then
  echo "teardown-host.sh must be run with sudo." >&2
  exit 1
fi

BRIDGE=dnsmasq-fnbr0
TAP=dnsmasq-fntap0

log() { echo "==> $*"; }

if ip link show "$TAP" &>/dev/null; then
  log "removing TAP $TAP"
  ip link del "$TAP" || true
fi

if ip link show "$BRIDGE" &>/dev/null; then
  log "removing bridge $BRIDGE"
  ip link del "$BRIDGE" || true
fi

log "teardown complete"
```

- [ ] **Step 4: Delete the retired namespace-exec wrapper and host-side handler script**

```bash
git rm functional/lib/netns-exec.sh functional/lib/udhcpc-handler.sh
```

- [ ] **Step 5: Confirm nothing else still references the retired mechanism**

```bash
grep -rn "netns-exec\|busybox-udhcpc\|fn-client-" functional/ docs/superpowers/specs/2026-08-22-dhcp-functional-test-harness-design.md
```

Expected: no matches (the `mac-blocklist-nak/client-0.conf` comment references neither string, so it's unaffected). If the main harness spec doc (`2026-08-22-...`) has references to `fn-client-*` namespaces or `busybox-udhcpc` as the only v1 tool, update them to reflect the VM-based client — cross-reference `2026-08-23-dhcp-harness-vm-client-design.md` rather than duplicating its content.

- [ ] **Step 6: Rewrite `functional/README.md`**

Replace the `## One-time host setup` section's namespace description (currently: `"...and four network namespaces (fn-client-0 through fn-client-3) with veth pairs already wired into the bridge."`) with:

```
This creates a Linux bridge (`dnsmasq-fnbr0`) and one persistent TAP device for the router VM's
LAN interface (chowned to you, so later steps don't need `sudo`). It's idempotent — safe to run
again if you're not sure it already ran. Client VMs each get their own ephemeral TAP, created
and destroyed per run — there's no more one-time client setup.
```

Replace the `### Optional: passwordless \`ip netns exec\`` section with:

```
### Optional: passwordless TAP create/delete

`functional/lib/client.sh` needs one privileged operation per client VM run — creating and
destroying its ephemeral TAP device, executed through the narrow `functional/lib/tap-ctl.sh`
wrapper, since this host's `sudo` (`sudo-rs`) rejects any wildcard in a sudoers command spec, so
the `fn-vmclient-*` scoping lives in the wrapper script itself rather than the sudoers rule —
which will prompt for your `sudo` password each time unless you install the scoped, opt-in
sudoers rule in `functional/dnsmasq-rs-functional.sudoers.example`. See that file for install
instructions. This step is entirely optional; without it, the harness still works, just with a
password prompt per client invocation.
```

Add a new section after `## Router VM image`, before `## Running a scenario`:

```
## Client VM image

Once per host (or whenever the client's DHCP behavior needs to change):

\`\`\`bash
sudo ./functional/images/build-client-image.sh
\`\`\`

This fetches (and checksum-verifies) a pinned Alpine x86_64 cloud image into `functional/.cache/`
(gitignored) if not already cached, and customizes a copy via `guestfish`: disables the image's
own default-runlevel services (`networking`, `sshd`, `chronyd`, the `tiny-cloud-*` agent — none
of which this harness needs, and `networking` would otherwise race the harness's own DHCP
client run), and installs one custom OpenRC service that brings up `eth0`, runs `udhcpc` once,
reports the result, and powers off. Needs `sudo` for the same `guestfish`-needs-the-host-kernel
reason `build-router-image.sh` does. One image serves every scenario and every client — nothing
scenario-specific is baked in; only the VM's MAC address varies per run.
```

Update the `## Scenarios (v1)` section's closing line (currently `All four run with \`CLIENT_TOOL=busybox-udhcpc\` — v1's only client tool (see below).`) to:

```
All four run with `CLIENT_TOOL=alpine-vm` — v1's only client tool (see below).
```

Replace the entire `### Client tools` section with:

```
### Client tools

v1 ships with one client tool, `alpine-vm`: a small Alpine Linux VM per client run, booting a
customized image (see "Client VM image" above), attached to the shared bridge via its own
ephemeral TAP device rather than a network namespace. This replaced the original namespace-based
`busybox-udhcpc` client entirely (issue #141) — new, test-only software (a second client tool,
originally planned as ISC `dhclient`) belongs in a container or VM, not installed onto the host's
own package database, and a VM-based client was the harness's own already-stated future direction
("namespace clients now, VM clients later").
```

- [ ] **Step 7: Syntax-check the modified scripts**

```bash
bash -n functional/setup-host.sh
bash -n functional/teardown-host.sh
```

Expected: no output.

- [ ] **Step 8: Ask the human operator to tear down and recreate host state with the trimmed scripts, then regression-test**

```bash
sudo ./functional/teardown-host.sh
sudo ./functional/setup-host.sh
ip netns list
```

Expected: `ip netns list` shows nothing (no more `fn-client-*` namespaces — teardown removed the old ones and setup no longer creates new ones).

```bash
./functional/run.sh basic-lease
```

Expected: `==> basic-lease: 1 passed, 0 failed`, exit 0 — this is the permanent version of Task 5 Step 6's temporary test, now using the committed scenario file (not a `sed`-then-revert).

- [ ] **Step 9: Commit**

```bash
git add functional/scenarios functional/setup-host.sh functional/teardown-host.sh functional/README.md
git commit -m "functional: switch scenarios to alpine-vm, retire namespace client setup"
```

---

### Task 7: Full regression pass (acceptance gate)

**Files:** none (verification only).

**Interfaces:** none — this task only runs the harness and confirms behavior.

- [ ] **Step 1: Run all four scenarios**

```bash
for s in basic-lease static-reservation client-options mac-blocklist-nak; do
  echo "=== $s ==="
  ./functional/run.sh "$s"
  echo "EXIT: $?"
done
```

Expected: every scenario reports `1 passed, 0 failed` and `EXIT: 0`.

- [ ] **Step 2: Re-verify `mac-blocklist-nak`'s negative control under the new mechanism**

```bash
cp functional/scenarios/mac-blocklist-nak/dnsmasq.conf /tmp/mac-blocklist-dnsmasq.conf.bak
grep -v 'dhcp-host=52:54:00:de:ad:00,ignore' functional/scenarios/mac-blocklist-nak/dnsmasq.conf > /tmp/mac-blocklist-dnsmasq.conf.new
mv /tmp/mac-blocklist-dnsmasq.conf.new functional/scenarios/mac-blocklist-nak/dnsmasq.conf
./functional/run.sh mac-blocklist-nak
echo "EXIT: $?"
mv /tmp/mac-blocklist-dnsmasq.conf.bak functional/scenarios/mac-blocklist-nak/dnsmasq.conf
./functional/run.sh mac-blocklist-nak
echo "EXIT: $?"
```

Expected: the first run (blocklist removed) reports `FAIL client-0: expected result 'timeout', got 'lease'` and `EXIT: 1`; the second run (config restored) reports `1 passed, 0 failed` and `EXIT: 0`.

- [ ] **Step 3: Confirm running the harness twice leaves no leftover state**

```bash
./functional/run.sh basic-lease
./functional/run.sh basic-lease
ps aux | grep qemu-system | grep -v grep || echo "no leftover qemu processes"
ip link show | grep fn-vmclient || echo "no leftover client TAPs"
ip link show | grep fn-vmclient-h 2>/dev/null; true
ls /tmp/dnsmasq-rs-functional.* 2>&1 || echo "no leftover work dirs"
```

Expected: `no leftover qemu processes`, `no leftover client TAPs`, `no leftover work dirs`.

- [ ] **Step 4: Full Rust test suite sanity check (no Rust source changed this plan, but confirm nothing else regressed)**

```bash
cargo test --all-features 2>&1 | grep -E "^test result|FAILED|error\["
```

Expected: same pass counts as before this plan started, 0 failures.

- [ ] **Step 5: Update `functional/README.md`'s status checklist**

Change:

```
- [x] Remaining v1 scenarios (`static-reservation`, `client-options`, `mac-blocklist-nak`) —
      issue #137. ISC `dhclient` support was dropped from this issue's scope — see "Client
      tools" above and issue #141.
```

to:

```
- [x] Remaining v1 scenarios (`static-reservation`, `client-options`, `mac-blocklist-nak`) —
      issue #137.
- [x] VM-based client (`alpine-vm`, replacing the namespace-based `busybox-udhcpc`) — issue #141.
```

- [ ] **Step 6: Commit**

```bash
git add functional/README.md
git commit -m "functional: VM-based client harness complete (issue #141)"
```
