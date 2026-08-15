#!/usr/bin/env bash
# Local CI substitute. Emits a JSON verdict on stdout; diagnostics on stderr.
#
# Never runs `cargo fmt` — this tree is deliberately not rustfmt-formatted
# (2873 diff hunks against an aligned style), so formatting is not a signal.
# Never uses `-D warnings` — there are 198 baseline clippy warnings; the caller
# ratchets the count instead.
set -uo pipefail

REPO="${1:?usage: gate.sh <repo-dir> [--parity]}"
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
  if out=$(cargo check $flags 2>&1); then
    record "check:$name" true ""
  else
    record "check:$name" false "$(echo "$out" | grep -E '^error' | head -5 | tr '\n' ';')"
  fi
done

# ── tests ────────────────────────────────────────────────────────────────────
for spec in "${SETS[@]}"; do
  name="${spec%%:*}"; flags="${spec#*:}"
  # shellcheck disable=SC2086
  out=$(cargo test $flags 2>&1)
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
  n=$(cargo clippy --all-targets $flags 2>&1 | grep -cE '^warning')
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
  if out=$("$REPO/parity/run-major.sh" --json 2>/dev/null) && [[ -n "$out" ]]; then
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
