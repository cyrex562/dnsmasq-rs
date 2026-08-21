#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="$ROOT_DIR/parity/compose.major.yaml"
FIXTURE="${FIXTURE:-basic}"
UPSTREAM_PORT="${UPSTREAM_PORT:-2053}"
CANDIDATE_PORT="${CANDIDATE_PORT:-3053}"
# 3s was not enough after a cold container build: upstream had not finished
# starting, so every case failed as "upstream query failed" and the run looked
# like a total parity failure rather than a not-ready one.
PARITY_STARTUP_WAIT_SECS="${PARITY_STARTUP_WAIT_SECS:-10}"

# In --json mode stdout carries ONLY the probe's JSON document, so every
# progress message goes to stderr. The harness gate parses stdout directly.
JSON_MODE=0
[[ "${1:-}" == "--json" ]] && JSON_MODE=1

say() {
  if [[ "$JSON_MODE" -eq 1 ]]; then
    echo "$@" >&2
  else
    echo "$@"
  fi
}

cleanup() {
  if [[ "${KEEP_CONTAINERS:-0}" == "1" ]]; then
    return
  fi
  # --rmi local removes the images this compose file built (not anything
  # pulled/tagged elsewhere on the host). Left unbounded across many harness
  # cycles, these plus their build-cache layers grew to ~2.5TB and filled the
  # disk — this teardown, plus the age-bounded builder prune below, keeps that
  # from recurring without nuking cache useful for back-to-back runs.
  docker compose -f "$COMPOSE_FILE" down --remove-orphans --rmi local --volumes >/dev/null 2>&1 || true
  docker builder prune -f --filter "until=24h" >/dev/null 2>&1 || true
}

trap cleanup EXIT

cd "$ROOT_DIR"

say "==> building parity containers"
if [[ "$JSON_MODE" -eq 1 ]]; then
  docker compose -f "$COMPOSE_FILE" build upstream rust >&2
else
  docker compose -f "$COMPOSE_FILE" build upstream rust
fi

say "==> starting upstream and candidate services"
docker compose -f "$COMPOSE_FILE" up -d upstream rust >&2

say "==> waiting ${PARITY_STARTUP_WAIT_SECS}s for services to start"
sleep "$PARITY_STARTUP_WAIT_SECS"

QUERY_FILE="$ROOT_DIR/parity/fixtures/dns/${FIXTURE}/queries.txt"

say "==> probing DNS parity using fixture '${FIXTURE}'"

if [[ "$JSON_MODE" -eq 1 ]]; then
  # --json always exits 0; the caller compares the per-case results against
  # its recorded baseline rather than treating any mismatch as fatal.
  cargo run --quiet --bin parity_probe -- \
    --queries "$QUERY_FILE" \
    --upstream "127.0.0.1:${UPSTREAM_PORT}" \
    --candidate "127.0.0.1:${CANDIDATE_PORT}" \
    --json 2>/dev/null
  say "==> parity probe complete for fixture '${FIXTURE}'"
  exit 0
fi

if ! cargo run --quiet --bin parity_probe -- \
  --queries "$QUERY_FILE" \
  --upstream "127.0.0.1:${UPSTREAM_PORT}" \
  --candidate "127.0.0.1:${CANDIDATE_PORT}"; then
  echo
  echo "==> parity probe failed; container logs follow"
  docker compose -f "$COMPOSE_FILE" logs upstream rust || true
  exit 1
fi

echo "==> DNS parity probe passed for fixture '${FIXTURE}'"
