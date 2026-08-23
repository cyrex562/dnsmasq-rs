#!/usr/bin/env bash
set -euo pipefail

# Narrow sudo entry point for functional/lib/client.sh: creates/destroys the
# ephemeral TAP device each client VM attaches to the shared bridge with.
# Granted passwordless sudo via
# functional/dnsmasq-rs-functional.sudoers.example, which grants this exact
# absolute path with no argument list in the sudoers spec -- this host's
# sudo (sudo-rs) rejects any wildcard character in a command argument
# outright, so the fnvm*-prefix scoping below is what actually constrains
# this, not the sudoers grant syntax. Same pattern netns-exec.sh already
# uses for namespace names.

# Must match functional/lib/common.sh's $BRIDGE.
BRIDGE=dnsmasq-fnbr0

op="${1:-}"
name="${2:-}"

# Prefix is short (4 chars, not "fn-vmclient-") because Linux interface
# names are capped at IFNAMSIZ-1 = 15 usable characters -- confirmed the
# hard way ("dev" not a valid ifname) with the longer prefix first tried.
case "$name" in
  fnvm*) ;;
  *)
    echo "tap-ctl.sh: refusing non fnvm*-prefixed TAP name: '$name'" >&2
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
    echo "tap-ctl.sh: usage: tap-ctl.sh create|delete <fnvm-name>" >&2
    exit 1
    ;;
esac
