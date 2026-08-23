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
