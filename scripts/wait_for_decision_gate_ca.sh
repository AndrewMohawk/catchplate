#!/usr/bin/env bash
set -euo pipefail

RETRIES="${CATCHPLATE_WAIT_RETRIES:-60}"

for _ in $(seq 1 "$RETRIES"); do
  if docker compose exec -T catchplate sh -c 'test -s /data/decision-gate-ca-cert.pem && test -s /data/decision-gate-ca-key.pem' >/dev/null 2>&1; then
    exit 0
  fi
  sleep 1
done

echo "decision-gate CA handoff files did not become available under /data" >&2
exit 1
