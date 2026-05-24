#!/usr/bin/env bash
set -euo pipefail

BASE="${BASE:-http://localhost:3000}"
RETRIES="${SERVERWARE_WAIT_RETRIES:-60}"

for _ in $(seq 1 "$RETRIES"); do
  if curl -fsS "$BASE/healthz" >/dev/null 2>&1; then
    exit 0
  fi
  sleep 1
done

echo "Serverware did not become healthy at $BASE" >&2
exit 1
