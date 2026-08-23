#!/usr/bin/env bash
# DHCP client execution and EXPECT_* checking for functional/run.sh. Needs
# $LIB_DIR from lib/common.sh. Not executable on its own.

gen_client_mac() {
  printf '52:54:00:%02x:%02x:%02x\n' $((RANDOM % 256)) $((RANDOM % 256)) $((RANDOM % 256))
}

ip_to_int() {
  local a b c d
  IFS=. read -r a b c d <<<"$1"
  echo $(( (a << 24) + (b << 16) + (c << 8) + d ))
}

ip_in_range() {
  local ip="$1" range="$2" lo hi
  lo="${range%-*}"
  hi="${range#*-}"
  local ip_i lo_i hi_i
  ip_i=$(ip_to_int "$ip")
  lo_i=$(ip_to_int "$lo")
  hi_i=$(ip_to_int "$hi")
  (( ip_i >= lo_i && ip_i <= hi_i ))
}

# Boots a small Alpine VM (functional/.cache/client.img, built by
# functional/images/build-client-image.sh) attached to the shared bridge
# via a fresh ephemeral TAP, waits for it to run its one-shot DHCP client
# and report results, and writes the same RESULT=/ACTUAL_* shape to
# $result_file that the namespace-based busybox-udhcpc path used to —
# comparison logic in run_and_check_client never needs to know the
# difference. See
# docs/superpowers/specs/2026-08-23-dhcp-harness-vm-client-design.md.
run_alpine_vm_client() {
  local mac="$1" result_file="$2"
  local tap_ctl="$LIB_DIR/tap-ctl.sh"
  # Linux interface names are capped at 15 usable characters (IFNAMSIZ-1):
  # "fnvm" + 4 hex digits from $$ + 4 hex digits from $RANDOM = 12 chars,
  # comfortably under the limit and still unique enough for sequential runs.
  local tap_name
  tap_name="fnvm$(printf '%04x' $(( $$ % 65536 )))$(printf '%04x' "$RANDOM")"

  sudo "$tap_ctl" create "$tap_name"

  local work_dir client_img scratch_disk console_log qemu_log
  work_dir="$(mktemp -d)"
  client_img="$work_dir/client.img"
  scratch_disk="$work_dir/scratch.img"
  console_log="$work_dir/console.log"
  qemu_log="$work_dir/qemu.log"

  build_empty_scratch_disk "$scratch_disk"
  cp -f "$CACHE_DIR/client.img" "$client_img"

  local vm_pid
  vm_pid="$(start_vm "$tap_name" 256 "$client_img" "$scratch_disk" "$console_log" "$qemu_log" "$mac")"

  if wait_for_marker "$scratch_disk" 60 '\.done'; then
    mtype -i "$scratch_disk" ::result > "$result_file" 2>/dev/null || true
  else
    echo "client VM did not finish within 60s" >&2
    print_vm_diagnostics "$console_log" "$scratch_disk" ""
  fi

  stop_vm "$vm_pid"
  sudo "$tap_ctl" delete "$tap_name"
  rm -rf "$work_dir"
}

# Runs the client tool named in $1 (a client-N.conf) inside namespace $2,
# labeled $3 for output, and checks the result against the conf's
# EXPECT_* values. Prints one line per mismatch plus a final PASS/FAIL
# line; returns 0 only if every assertion held.
run_and_check_client() {
  local conf_file="$1" label="$2"
  local CLIENT_TOOL="" CLIENT_MAC="" EXPECT_RESULT="" EXPECT_IP="" EXPECT_IP_RANGE=""
  local EXPECT_ROUTER="" EXPECT_DNS="" EXPECT_LEASE_TIME="" EXPECT_DOMAIN="" EXPECT_NTP=""
  # shellcheck source=/dev/null
  source "$conf_file"

  [[ -n "$CLIENT_MAC" ]] || CLIENT_MAC="$(gen_client_mac)"

  # A private (mode 700) subdirectory, not a bare /tmp file: the handler
  # runs as root (via sudo), and the kernel's fs.protected_regular
  # hardening (default on since ~5.x) refuses to let root open-for-write
  # a file it doesn't own inside a world-writable sticky directory like
  # /tmp itself, regardless of capabilities — confirmed via strace
  # (EACCES on the openat) when this was a bare `mktemp` file directly
  # under /tmp. A private subdirectory isn't world-writable, so the
  # protection never triggers.
  local result_dir result_file
  result_dir="$(mktemp -d)"
  result_file="$result_dir/result"

  case "$CLIENT_TOOL" in
    alpine-vm)
      run_alpine_vm_client "$CLIENT_MAC" "$result_file"
      ;;
    *)
      echo "FAIL $label: unsupported CLIENT_TOOL '$CLIENT_TOOL' (v1 supports alpine-vm only)"
      rm -rf "$result_dir"
      return 1
      ;;
  esac

  local RESULT="timeout" ACTUAL_IP="" ACTUAL_ROUTER="" ACTUAL_DNS="" ACTUAL_LEASE=""
  local ACTUAL_DOMAIN="" ACTUAL_NTP=""
  if [[ -f "$result_file" ]]; then
    # shellcheck source=/dev/null
    source "$result_file"
  fi
  rm -rf "$result_dir"

  local ok=1
  if [[ "$RESULT" != "$EXPECT_RESULT" ]]; then
    echo "FAIL $label: expected result '$EXPECT_RESULT', got '$RESULT'"
    ok=0
  fi

  if [[ "$EXPECT_RESULT" == "lease" && "$RESULT" == "lease" ]]; then
    if [[ -n "$EXPECT_IP" && "$ACTUAL_IP" != "$EXPECT_IP" ]]; then
      echo "FAIL $label: IP expected '$EXPECT_IP' got '$ACTUAL_IP'"
      ok=0
    fi
    if [[ -n "$EXPECT_IP_RANGE" ]] && ! ip_in_range "$ACTUAL_IP" "$EXPECT_IP_RANGE"; then
      echo "FAIL $label: IP '$ACTUAL_IP' not in expected range $EXPECT_IP_RANGE"
      ok=0
    fi
    if [[ -n "$EXPECT_ROUTER" && "$ACTUAL_ROUTER" != "$EXPECT_ROUTER" ]]; then
      echo "FAIL $label: router expected '$EXPECT_ROUTER' got '$ACTUAL_ROUTER'"
      ok=0
    fi
    if [[ -n "$EXPECT_DNS" && "$ACTUAL_DNS" != "$EXPECT_DNS" ]]; then
      echo "FAIL $label: dns expected '$EXPECT_DNS' got '$ACTUAL_DNS'"
      ok=0
    fi
    if [[ -n "$EXPECT_LEASE_TIME" && "$ACTUAL_LEASE" != "$EXPECT_LEASE_TIME" ]]; then
      echo "FAIL $label: lease time expected '$EXPECT_LEASE_TIME' got '$ACTUAL_LEASE'"
      ok=0
    fi
    if [[ -n "$EXPECT_DOMAIN" && "$ACTUAL_DOMAIN" != "$EXPECT_DOMAIN" ]]; then
      echo "FAIL $label: domain expected '$EXPECT_DOMAIN' got '$ACTUAL_DOMAIN'"
      ok=0
    fi
    if [[ -n "$EXPECT_NTP" && "$ACTUAL_NTP" != "$EXPECT_NTP" ]]; then
      echo "FAIL $label: ntp server expected '$EXPECT_NTP' got '$ACTUAL_NTP'"
      ok=0
    fi
  fi

  if [[ "$ok" == "1" ]]; then
    echo "PASS $label"
    return 0
  fi
  return 1
}
