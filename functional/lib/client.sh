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

# Runs the client tool named in $1 (a client-N.conf) inside namespace $2,
# labeled $3 for output, and checks the result against the conf's
# EXPECT_* values. Prints one line per mismatch plus a final PASS/FAIL
# line; returns 0 only if every assertion held.
run_and_check_client() {
  local conf_file="$1" ns="$2" label="$3"
  local CLIENT_TOOL="" CLIENT_MAC="" EXPECT_RESULT="" EXPECT_IP_RANGE=""
  local EXPECT_ROUTER="" EXPECT_DNS="" EXPECT_LEASE_TIME=""
  # shellcheck source=/dev/null
  source "$conf_file"

  if [[ "$CLIENT_TOOL" != "busybox-udhcpc" ]]; then
    echo "FAIL $label: unsupported CLIENT_TOOL '$CLIENT_TOOL' (v1 supports busybox-udhcpc only)"
    return 1
  fi

  [[ -n "$CLIENT_MAC" ]] || CLIENT_MAC="$(gen_client_mac)"

  local netns_exec="$LIB_DIR/netns-exec.sh"
  sudo "$netns_exec" "$ns" ip link set eth0 down
  sudo "$netns_exec" "$ns" ip link set eth0 address "$CLIENT_MAC"
  sudo "$netns_exec" "$ns" ip link set eth0 up

  # A private (mode 700) subdirectory, not a bare /tmp file: the handler
  # script writes this as root (via sudo), and the kernel's
  # fs.protected_regular hardening (default on since ~5.x) refuses to let
  # root open-for-write a file it doesn't own inside a world-writable
  # sticky directory like /tmp itself, regardless of capabilities —
  # confirmed via strace (EACCES on the openat) when this was a bare
  # `mktemp` file directly under /tmp. A private subdirectory isn't
  # world-writable, so the protection never triggers.
  local result_dir result_file
  result_dir="$(mktemp -d)"
  result_file="$result_dir/result"

  # -t 8 -T 3 gives ~24s of discover retries (the 45s wrapper below leaves
  # headroom for the request/ack round trip after an offer arrives): the
  # veth flap above drops carrier on the host-side bridge port too, and
  # how long it takes to return to forwarding varies with how loaded the
  # host is running the (unaccelerated, TCG) router VM alongside
  # everything else — a fixed short guard delay was tried and still
  # flaked under load. Retrying across a longer window is the standard
  # way DHCP clients absorb this instead of guessing a fixed delay.
  timeout 45 sudo "$netns_exec" "$ns" \
    env RESULT_FILE="$result_file" \
    busybox udhcpc -i eth0 -n -q -f -t 8 -T 3 \
      -s "$LIB_DIR/udhcpc-handler.sh" \
    >/dev/null 2>&1 || true

  local RESULT="timeout" ACTUAL_IP="" ACTUAL_ROUTER="" ACTUAL_DNS="" ACTUAL_LEASE=""
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
  fi

  if [[ "$ok" == "1" ]]; then
    echo "PASS $label"
    return 0
  fi
  return 1
}
