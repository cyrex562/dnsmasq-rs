#!/usr/bin/env bash
# Per-run scenario scratch disk: the router VM's second virtio-blk drive,
# carrying the scenario's dnsmasq.conf in and (once mounted read-write by
# the guest's init script) dnsmasq-rs.log/.ready back out. See
# docs/superpowers/specs/2026-08-22-dhcp-functional-test-harness-design.md,
# "Router VM image" section, for why this replaced the original virtio-9p
# plan. Not executable on its own.

build_scenario_disk() {
  local scenario_dir="$1" out_img="$2"
  dd if=/dev/zero of="$out_img" bs=1M count=8 status=none
  mformat -i "$out_img" -v SCENARIO ::
  mcopy -i "$out_img" "$scenario_dir/dnsmasq.conf" ::dnsmasq.conf
}
