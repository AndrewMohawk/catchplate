#!/usr/bin/env bash
set -euo pipefail

RETRIES="${SERVERWARE_WAIT_RETRIES:-60}"

for _ in $(seq 1 "$RETRIES"); do
  if docker compose exec -T demo-upstream sh -c 'test -s /data/demo-upstream/ca.pem && test -s /data/demo-upstream/cert.pem' >/dev/null 2>&1; then
    exit 0
  fi
  sleep 1
done

echo "demo upstream CA and leaf certificates did not become available under /data/demo-upstream" >&2
exit 1
