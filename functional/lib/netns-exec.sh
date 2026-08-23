#!/usr/bin/env bash
set -euo pipefail

# Narrow sudo entry point for functional/run.sh: execs a command inside one
# of the harness's fn-client-* namespaces. Granted passwordless sudo via
# functional/dnsmasq-rs-functional.sudoers.example, which grants this exact
# absolute path with no argument list in the sudoers spec -- this host's
# sudo (sudo-rs) rejects any wildcard character in a command argument
# outright, so per-namespace/command wildcarding can't live in the sudoers
# file at all. The fn-client-* check below is what actually constrains
# this to the harness's own namespaces.

ns="${1:-}"
shift || true

case "$ns" in
  fn-client-*) ;;
  *)
    echo "netns-exec.sh: refusing non fn-client-* namespace: '$ns'" >&2
    exit 1
    ;;
esac

exec /usr/sbin/ip netns exec "$ns" "$@"
