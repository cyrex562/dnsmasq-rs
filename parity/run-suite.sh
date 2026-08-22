#!/usr/bin/env bash
set -euo pipefail

# Runs every fixture under parity/fixtures/dns/ against both daemons and
# reports a pass/fail summary. Builds the two images once and reuses them
# across fixtures (only the mounted config path/command args change), unlike
# looping run-major.sh which would rebuild per fixture for no benefit.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="$ROOT_DIR/parity/compose.major.yaml"
FIXTURES_DIR="$ROOT_DIR/parity/fixtures/dns"
UPSTREAM_PORT="${UPSTREAM_PORT:-2053}"
CANDIDATE_PORT="${CANDIDATE_PORT:-3053}"
PARITY_STARTUP_WAIT_SECS="${PARITY_STARTUP_WAIT_SECS:-10}"

cleanup() {
  if [[ "${KEEP_CONTAINERS:-0}" == "1" ]]; then
    return
  fi
  # See run-major.sh's cleanup() for why --rmi local/--volumes and the
  # age-bounded builder prune are both here: left unbounded across many
  # runs, build-cache layers grow enough to fill the disk.
  docker compose -f "$COMPOSE_FILE" down --remove-orphans --rmi local --volumes >/dev/null 2>&1 || true
  docker builder prune -f --filter "until=24h" >/dev/null 2>&1 || true
}
trap cleanup EXIT

cd "$ROOT_DIR"

mapfile -t FIXTURES < <(find "$FIXTURES_DIR" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | sort)

if [[ ${#FIXTURES[@]} -eq 0 ]]; then
  echo "no fixtures found under $FIXTURES_DIR" >&2
  exit 1
fi

echo "==> building parity containers (shared across ${#FIXTURES[@]} fixtures: ${FIXTURES[*]})"
docker compose -f "$COMPOSE_FILE" build upstream rust

PASSED=()
FAILED=()

for fx in "${FIXTURES[@]}"; do
  echo
  echo "==> [$fx] starting services"
  FIXTURE="$fx" docker compose -f "$COMPOSE_FILE" up -d --force-recreate upstream rust

  echo "==> [$fx] waiting ${PARITY_STARTUP_WAIT_SECS}s for services to start"
  sleep "$PARITY_STARTUP_WAIT_SECS"

  QUERY_FILE="$FIXTURES_DIR/$fx/queries.txt"
  echo "==> [$fx] probing"
  if cargo run --quiet --bin parity_probe -- \
    --queries "$QUERY_FILE" \
    --upstream "127.0.0.1:${UPSTREAM_PORT}" \
    --candidate "127.0.0.1:${CANDIDATE_PORT}"; then
    echo "==> [$fx] PASS"
    PASSED+=("$fx")
  else
    echo "==> [$fx] FAIL"
    FAILED+=("$fx")
    echo "----> [$fx] container logs"
    docker compose -f "$COMPOSE_FILE" logs upstream rust || true
  fi
done

echo
echo "==================== parity suite summary ===================="
echo "passed (${#PASSED[@]}/${#FIXTURES[@]}): ${PASSED[*]:-none}"
if [[ ${#FAILED[@]} -gt 0 ]]; then
  echo "failed (${#FAILED[@]}/${#FIXTURES[@]}): ${FAILED[*]}"
  exit 1
fi
echo "all fixtures passed"
