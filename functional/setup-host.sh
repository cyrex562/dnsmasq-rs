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
