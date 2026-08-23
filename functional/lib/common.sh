#!/usr/bin/env bash
# Shared paths, constants, and small helpers sourced by functional/run.sh.
# Not executable on its own.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CACHE_DIR="$ROOT_DIR/functional/.cache"
LIB_DIR="$ROOT_DIR/functional/lib"

# Must match functional/setup-host.sh's names exactly.
BRIDGE=dnsmasq-fnbr0
TAP=dnsmasq-fntap0

log() { echo "==> $*"; }
err() { echo "ERROR: $*" >&2; }

require_host_setup() {
  if ! ip link show "$BRIDGE" &>/dev/null; then
    err "host network not set up — run: sudo ./functional/setup-host.sh"
    exit 1
  fi
}

require_router_image() {
  if [[ ! -f "$CACHE_DIR/router.img" ]]; then
    err "router image not built — run: sudo ./functional/images/build-router-image.sh"
    exit 1
  fi
}

require_client_image() {
  if [[ ! -f "$CACHE_DIR/client.img" ]]; then
    err "client image not built — run: sudo ./functional/images/build-client-image.sh"
    exit 1
  fi
}
