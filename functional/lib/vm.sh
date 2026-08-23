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
