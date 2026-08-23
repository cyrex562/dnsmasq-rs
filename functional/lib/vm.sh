#!/usr/bin/env bash
# QEMU router-VM lifecycle helpers for functional/run.sh. Needs $TAP from
# lib/common.sh. Not executable on its own.

start_router_vm() {
  local router_img="$1" scenario_disk="$2" console_log="$3" qemu_log="$4"
  qemu-system-x86_64 \
    -m 512 \
    -netdev tap,id=lan0,ifname="$TAP",script=no,downscript=no \
    -device virtio-net-pci,netdev=lan0 \
    -drive file="$router_img",if=virtio,format=raw \
    -drive file="$scenario_disk",if=virtio,format=raw \
    -serial file:"$console_log" \
    -monitor none -display none -no-reboot \
    >"$qemu_log" 2>&1 &
  echo $!
}

# Polls the scratch disk (unprivileged, via mtools) for the .ready marker
# the guest's init script writes once dnsmasq-rs is confirmed running.
wait_for_vm_ready() {
  local scenario_disk="$1" timeout_s="$2"
  local waited=0
  while (( waited < timeout_s )); do
    if mdir -i "$scenario_disk" :: 2>/dev/null | grep -qi '\.ready'; then
      return 0
    fi
    sleep 2
    waited=$((waited + 2))
  done
  return 1
}

stop_router_vm() {
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
  local console_log="$1" scenario_disk="$2"
  echo "--- VM console log (tail -60) ---"
  tail -n 60 "$console_log" 2>/dev/null || echo "(no console log captured)"
  echo "--- dnsmasq-rs.log from scenario disk (if present) ---"
  mtype -i "$scenario_disk" ::dnsmasq-rs.log 2>/dev/null || echo "(dnsmasq-rs.log not present on scenario disk)"
}
