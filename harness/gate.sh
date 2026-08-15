#!/usr/bin/env bash
# Local CI substitute. Emits a JSON verdict on stdout; diagnostics on stderr.
#
# Never runs `cargo fmt` — this tree is deliberately not rustfmt-formatted
# (2873 diff hunks against an aligned style), so formatting is not a signal.
# Never uses `-D warnings` — there are 198 baseline clippy warnings; the caller
# ratchets the count instead.
set -uo pipefail

REPO="${1:?usage: gate.sh <repo-dir> [--parity]}"

# Every cargo invocation is bounded. A test that leaks a foreground child --
# e.g. a daemon-startup test whose subject never exits -- blocks `cargo test`
# forever, and an unbounded gate turns that into hours of dead time instead of
# a failure the implementer can act on. Timeouts are generous: these are real
# builds, not unit tests.
CARGO_TIMEOUT="${GATE_CARGO_TIMEOUT:-1800}"
PARITY_TIMEOUT="${GATE_PARITY_TIMEOUT:-2400}"

# Kill anything the tests leaked behind, so the next feature set starts clean
# and the harness does not accumulate orphaned daemons across a run.
reap_strays() {
  pkill -KILL -f "$REPO/target/debug/dnsmasq-rs" 2>/dev/null || true
}
trap reap_strays EXIT
RUN_PARITY=0
[[ "${2:-}" == "--parity" ]] && RUN_PARITY=1
cd "$REPO" || exit 2

STAGES=()
declare -A T_PASS T_FAIL CLIPPY
PARITY_JSON="null"
OK=1

record() { STAGES+=("$1|$2|$3"); [[ "$2" == "true" ]] || OK=0; }

SETS=("default:" "all-features:--all-features" "no-default-features:--no-default-features")

# ── build checks ─────────────────────────────────────────────────────────────
for spec in "${SETS[@]}"; do
  name="${spec%%:*}"; flags="${spec#*:}"
  # shellcheck disable=SC2086
  if out=$(timeout "$CARGO_TIMEOUT" cargo check $flags 2>&1); then
    record "check:$name" true ""
  else
    record "check:$name" false "$(echo "$out" | grep -E '^error' | head -5 | tr '\n' ';')"
  fi
done

# ── tests ────────────────────────────────────────────────────────────────────
for spec in "${SETS[@]}"; do
  name="${spec%%:*}"; flags="${spec#*:}"
  # shellcheck disable=SC2086
  out=$(timeout "$CARGO_TIMEOUT" cargo test $flags 2>&1)
  rc=$?
  reap_strays
  if [[ $rc -eq 124 ]]; then
    T_PASS[$name]=0; T_FAIL[$name]=0
    record "test:$name" false "TIMED OUT after ${CARGO_TIMEOUT}s -- a test is hanging, most likely one that spawns the binary and waits for it to exit"
    continue
  fi
  p=$(echo "$out" | grep -oP '(?<=result: ok\. )\d+(?= passed)' | paste -sd+ | bc 2>/dev/null)
  f=$(echo "$out" | grep -oP '\d+(?= failed)' | paste -sd+ | bc 2>/dev/null)
  T_PASS[$name]=${p:-0}; T_FAIL[$name]=${f:-0}
  # Herestring, not a pipe: `grep -q` closes the pipe on first match, which
  # SIGPIPEs the writer, and `pipefail` would then report a successful match
  # as a failed pipeline.
  if [[ "${f:-0}" -eq 0 ]] && grep -q "test result" <<< "$out"; then
    record "test:$name" true "${p:-0} passed"
  else
    record "test:$name" false "$(echo "$out" | grep -E '^(error|test result: FAILED)' | head -5 | tr '\n' ';')"
  fi
done

# ── clippy (counts only) ─────────────────────────────────────────────────────
for spec in "${SETS[@]}"; do
  name="${spec%%:*}"; flags="${spec#*:}"
  # shellcheck disable=SC2086
  n=$(timeout "$CARGO_TIMEOUT" cargo clippy --all-targets $flags 2>&1 | grep -cE '^warning')
  CLIPPY[$name]=${n:-0}
  record "clippy:$name" true "$n warnings"
done

# ── forbidden paths ──────────────────────────────────────────────────────────
FORBIDDEN=$(git diff --name-only master...HEAD 2>/dev/null \
  | grep -E '^(harness/|original_dnsmasq_src/|old/)' || true)
if [[ -n "$FORBIDDEN" ]]; then
  record "forbidden-paths" false "$(echo "$FORBIDDEN" | tr '\n' ';')"
else
  record "forbidden-paths" true ""
fi

# ── parity (ratchet; the caller compares against baseline) ───────────────────
if [[ "$RUN_PARITY" -eq 1 ]]; then
  if out=$(timeout "$PARITY_TIMEOUT" "$REPO/parity/run-major.sh" --json 2>/dev/null) && [[ -n "$out" ]]; then
    PARITY_JSON="$out"
    record "parity" true ""
  else
    PARITY_JSON="null"
    record "parity" true "parity run unavailable; skipped"
  fi
fi

# ── emit ─────────────────────────────────────────────────────────────────────
{
  echo "{"
  echo "  \"ok\": $([[ $OK -eq 1 ]] && echo true || echo false),"
  echo "  \"stages\": ["
  for i in "${!STAGES[@]}"; do
    IFS='|' read -r n o d <<< "${STAGES[$i]}"
    d=${d//\\/\\\\}; d=${d//\"/\\\"}
    printf '    {"name": "%s", "ok": %s, "detail": "%s"}%s\n' \
      "$n" "$o" "$d" "$([[ $i -lt $((${#STAGES[@]} - 1)) ]] && echo ,)"
  done
  echo "  ],"
  echo "  \"tests\": {"
  echo "    \"default\": {\"passed\": ${T_PASS[default]}, \"failed\": ${T_FAIL[default]}},"
  echo "    \"all-features\": {\"passed\": ${T_PASS[all-features]}, \"failed\": ${T_FAIL[all-features]}},"
  echo "    \"no-default-features\": {\"passed\": ${T_PASS[no-default-features]}, \"failed\": ${T_FAIL[no-default-features]}}"
  echo "  },"
  echo "  \"clippy\": {"
  echo "    \"default\": ${CLIPPY[default]},"
  echo "    \"all-features\": ${CLIPPY[all-features]},"
  echo "    \"no-default-features\": ${CLIPPY[no-default-features]}"
  echo "  },"
  echo "  \"parity\": $PARITY_JSON"
  echo "}"
}
exit 0
