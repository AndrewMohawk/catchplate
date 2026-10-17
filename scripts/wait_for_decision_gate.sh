#!/usr/bin/env bash
set -euo pipefail

BASE="${DECISION_GATE_BASE:-http://localhost:9090}"
RETRIES="${CATCHPLATE_WAIT_RETRIES:-60}"

for _ in $(seq 1 "$RETRIES"); do
  if curl -fsS "$BASE/healthz" 2>/dev/null | python3 -c '
import json
import sys

health = json.load(sys.stdin)
if health.get("ok") is not True or health.get("credential_generations_ready") is not True:
    raise SystemExit(1)
' >/dev/null 2>&1; then
    exit 0
  fi
  sleep 1
done

echo "Catchplate decision gate did not become healthy with credential generations ready at $BASE" >&2
exit 1
