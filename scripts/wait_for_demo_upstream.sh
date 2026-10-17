#!/usr/bin/env bash
set -euo pipefail

RETRIES="${CATCHPLATE_WAIT_RETRIES:-60}"

for _ in $(seq 1 "$RETRIES"); do
  if docker compose exec -T demo-upstream python -c '
import ssl
import urllib.request

with urllib.request.urlopen(
    "https://127.0.0.1:8443/_test/request-count?method=GET&path=%2Fecho",
    context=ssl._create_unverified_context(),
    timeout=2,
) as response:
    assert response.status == 200
' >/dev/null 2>&1; then
    exit 0
  fi
  sleep 1
done

echo "demo upstream HTTPS endpoint did not become ready" >&2
exit 1
