#!/usr/bin/env bash
set -uo pipefail
# Deliberately not `set -e`: teardown should attempt every step even if an
# earlier one fails (e.g. a namespace already gone), so a partial or
# double-run teardown doesn't abort halfway with unrelated state left behind.

# Reverses setup-host.sh. Requires sudo, same reason as setup-host.sh.

if [[ $EUID -ne 0 ]]; then
  echo "teardown-host.sh must be run with sudo." >&2
  exit 1
fi

BRIDGE=dnsmasq-fnbr0
TAP=dnsmasq-fntap0
NUM_CLIENTS=4

log() { echo "==> $*"; }

for i in $(seq 0 $((NUM_CLIENTS - 1))); do
  NS="fn-client-$i"
  if ip netns list 2>/dev/null | grep -qw "$NS"; then
    log "removing namespace $NS"
    # Deleting the namespace also destroys its eth0, which — being one end of
    # a veth pair — takes the host-side fnveth<i>h peer with it. No separate
    # veth cleanup step is needed.
    ip netns del "$NS" || true
  fi
done

if ip link show "$TAP" &>/dev/null; then
  log "removing TAP $TAP"
  ip link del "$TAP" || true
fi

if ip link show "$BRIDGE" &>/dev/null; then
  log "removing bridge $BRIDGE"
  ip link del "$BRIDGE" || true
fi

log "teardown complete"
