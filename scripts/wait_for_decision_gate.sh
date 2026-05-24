#!/usr/bin/env bash
set -euo pipefail

BASE="${DECISION_GATE_BASE:-http://localhost:9090}"
RETRIES="${SERVERWARE_WAIT_RETRIES:-60}"

for _ in $(seq 1 "$RETRIES"); do
  if curl -fsS "$BASE/healthz" >/dev/null 2>&1; then
    exit 0
  fi
  sleep 1
done

echo "Serverware decision gate did not become healthy at $BASE" >&2
exit 1
