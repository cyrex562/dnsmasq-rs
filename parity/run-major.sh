#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="$ROOT_DIR/parity/compose.major.yaml"
FIXTURE="${FIXTURE:-basic}"
UPSTREAM_PORT="${UPSTREAM_PORT:-2053}"
CANDIDATE_PORT="${CANDIDATE_PORT:-3053}"
PARITY_STARTUP_WAIT_SECS="${PARITY_STARTUP_WAIT_SECS:-3}"

cleanup() {
  if [[ "${KEEP_CONTAINERS:-0}" == "1" ]]; then
    return
  fi
  docker compose -f "$COMPOSE_FILE" down --remove-orphans >/dev/null 2>&1 || true
}

trap cleanup EXIT

cd "$ROOT_DIR"

echo "==> building parity containers"
docker compose -f "$COMPOSE_FILE" build upstream rust

echo "==> starting upstream and candidate services"
docker compose -f "$COMPOSE_FILE" up -d upstream rust

echo "==> waiting ${PARITY_STARTUP_WAIT_SECS}s for services to start"
sleep "$PARITY_STARTUP_WAIT_SECS"

QUERY_FILE="$ROOT_DIR/parity/fixtures/dns/${FIXTURE}/queries.txt"

echo "==> probing DNS parity using fixture '${FIXTURE}'"
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
