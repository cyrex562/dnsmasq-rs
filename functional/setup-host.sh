#!/usr/bin/env bash
set -euo pipefail

# One-time (idempotent) host network setup for the DHCP functional test
# harness. Requires sudo — creating bridges, TAPs, and network namespaces all
# need CAP_NET_ADMIN. See docs/superpowers/specs/2026-08-22-dhcp-functional-
# test-harness-design.md for the full design and rationale.
#
# Creates:
#   - a Linux bridge (dnsmasq-fnbr0) — the shared L2 segment the router VM
#     and every client namespace attach to.
#   - one persistent TAP device (dnsmasq-fntap0) for the router VM's LAN
#     interface, chowned to the invoking (non-root) user so a later,
#     unprivileged `qemu-system-x86_64` can attach to it directly.
#   - four network namespaces (fn-client-0..fn-client-3), each with a veth
#     pair already wired into the bridge, for lightweight DHCP client
#     scenarios (functional/run.sh execs client tools inside these via
#     `ip netns exec` — the one privileged operation run.sh itself needs).
#
# Safe to re-run: every step checks whether its target already exists first.
# This is a presence check only, not a full self-heal — if a namespace exists
# but its veth wiring was left half-done by an interrupted previous run, this
# script will not notice; run teardown-host.sh first if you suspect that.

if [[ $EUID -ne 0 ]]; then
  echo "setup-host.sh must be run with sudo (it creates bridges/TAPs/namespaces)." >&2
  exit 1
fi

# The user who invoked sudo -- the TAP device is chowned to them so a later,
# unprivileged `qemu-system-x86_64` can open it directly.
REAL_USER="${SUDO_USER:-$(id -un)}"

BRIDGE=dnsmasq-fnbr0
TAP=dnsmasq-fntap0
NUM_CLIENTS=4

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

for i in $(seq 0 $((NUM_CLIENTS - 1))); do
  NS="fn-client-$i"
  VETH_HOST="fnveth${i}h"
  VETH_NS="fnveth${i}n"

  if ip netns list 2>/dev/null | grep -qw "$NS"; then
    log "namespace $NS already exists"
    continue
  fi

  log "creating namespace $NS with veth pair"
  ip netns add "$NS"
  ip link add "$VETH_HOST" type veth peer name "$VETH_NS"
  ip link set "$VETH_HOST" master "$BRIDGE"
  ip link set "$VETH_HOST" up
  ip link set "$VETH_NS" netns "$NS"
  ip netns exec "$NS" ip link set lo up
  ip netns exec "$NS" ip link set "$VETH_NS" name eth0
  ip netns exec "$NS" ip link set eth0 up
done

log "setup complete: bridge=$BRIDGE tap=$TAP clients=fn-client-0..$((NUM_CLIENTS - 1))"
