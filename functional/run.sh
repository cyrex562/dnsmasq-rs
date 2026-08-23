#!/usr/bin/env bash
set -euo pipefail

# Runs one DHCP functional scenario: boots the router VM (image from
# build-router-image.sh, TAP/bridge from setup-host.sh), attaches a
# per-run scratch disk carrying the scenario's dnsmasq.conf, waits for
# dnsmasq-rs to report ready, then runs each client-N.conf's DHCP client
# against it and checks the result against its EXPECT_* values. See
# docs/superpowers/specs/2026-08-22-dhcp-functional-test-harness-design.md.
#
# Needs no sudo of its own except the `ip netns exec` calls inside
# lib/client.sh (optionally passwordless — see
# functional/dnsmasq-rs-functional.sudoers.example).

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"
# shellcheck source=lib/scratch-disk.sh
source "$SCRIPT_DIR/lib/scratch-disk.sh"
# shellcheck source=lib/vm.sh
source "$SCRIPT_DIR/lib/vm.sh"
# shellcheck source=lib/client.sh
source "$SCRIPT_DIR/lib/client.sh"

usage() {
  echo "usage: $0 <scenario-name>" >&2
  exit 1
}

[[ $# -eq 1 ]] || usage
SCENARIO="$1"
SCENARIO_DIR="$ROOT_DIR/functional/scenarios/$SCENARIO"

[[ -d "$SCENARIO_DIR" ]] || { err "no such scenario: $SCENARIO_DIR"; exit 1; }
[[ -f "$SCENARIO_DIR/dnsmasq.conf" ]] || { err "$SCENARIO_DIR is missing dnsmasq.conf"; exit 1; }

require_host_setup
require_router_image

WORK_DIR="$(mktemp -d /tmp/dnsmasq-rs-functional.XXXXXX)"
ROUTER_RUN_IMG="$WORK_DIR/router.img"
SCENARIO_DISK="$WORK_DIR/scenario.img"
CONSOLE_LOG="$WORK_DIR/console.log"
QEMU_LOG="$WORK_DIR/qemu.log"

VM_PID=""
cleanup() {
  stop_router_vm "$VM_PID"
  rm -rf "$WORK_DIR"
}
trap cleanup EXIT

log "building scenario scratch disk"
build_scenario_disk "$SCENARIO_DIR" "$SCENARIO_DISK"

log "copying router image for this run"
cp -f "$CACHE_DIR/router.img" "$ROUTER_RUN_IMG"

log "booting router VM"
VM_PID="$(start_router_vm "$ROUTER_RUN_IMG" "$SCENARIO_DISK" "$CONSOLE_LOG" "$QEMU_LOG")"

log "waiting for dnsmasq-rs to become ready (timeout 180s)"
if ! wait_for_vm_ready "$SCENARIO_DISK" 180; then
  err "VM did not become ready within 180s"
  print_vm_diagnostics "$CONSOLE_LOG" "$SCENARIO_DISK"
  exit 1
fi
log "dnsmasq-rs is ready"

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

echo "==> $SCENARIO: $PASS_COUNT passed, $FAIL_COUNT failed"
[[ "$FAIL_COUNT" -eq 0 ]]
