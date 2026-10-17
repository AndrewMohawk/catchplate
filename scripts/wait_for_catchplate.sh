#!/usr/bin/env bash
set -euo pipefail

BASE="${BASE:-http://localhost:${CATCHPLATE_CONTROL_PLANE_HOST_PORT:-3000}}"
RETRIES="${CATCHPLATE_WAIT_RETRIES:-60}"

for _ in $(seq 1 "$RETRIES"); do
  if curl -fsS "$BASE/healthz" >/dev/null 2>&1; then
    exit 0
  fi
  sleep 1
done

echo "Catchplate did not become healthy at $BASE" >&2
exit 1
