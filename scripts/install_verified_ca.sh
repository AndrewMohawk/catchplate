#!/usr/bin/env bash
set -euo pipefail

TMP_DIR="${TMP_DIR:-.tmp}"
CA_OUT="${SERVERWARE_CA_OUT:-$TMP_DIR/serverware-ca.pem}"
VERIFY_OUT="${SERVERWARE_VERIFY_OUT:-$TMP_DIR/attestation-verify.json}"
ADMIN_TOKEN="${SERVERWARE_ADMIN_TOKEN:-dev-admin-token}"
SERVICE="${SERVERWARE_COMPOSE_SERVICE:-serverware}"
VERIFY_BASE="${SERVERWARE_VERIFY_BASE:-http://localhost:3000}"
CONTAINER_CA_OUT="${SERVERWARE_CONTAINER_CA_OUT:-/tmp/serverware-verified-ca.pem}"
RETRIES="${SERVERWARE_CA_VERIFY_RETRIES:-60}"

mkdir -p "$TMP_DIR" "$(dirname "$CA_OUT")" "$(dirname "$VERIFY_OUT")"

verify_tmp="$TMP_DIR/attestation-verify.tmp.json"
verify_err="$TMP_DIR/attestation-verify.err"

for _ in $(seq 1 "$RETRIES"); do
  verify_cmd=(
    docker compose exec -T "$SERVICE"
    python scripts/verify_attestation.py
    --base "$VERIFY_BASE"
    --admin-token "$ADMIN_TOKEN"
    --ca-out "$CONTAINER_CA_OUT"
  )
  if [[ -n "${SERVERWARE_EXPECTED_POLICY_KEY_HASH:-}" ]]; then
    verify_cmd+=(--expected-policy-key-hash "$SERVERWARE_EXPECTED_POLICY_KEY_HASH")
  fi
  if [[ -n "${SERVERWARE_EXPECTED_ROLLBACK_EPOCH:-}" ]]; then
    verify_cmd+=(--expected-rollback-epoch "$SERVERWARE_EXPECTED_ROLLBACK_EPOCH")
  fi

  if "${verify_cmd[@]}" > "$verify_tmp" 2> "$verify_err"; then
    docker compose exec -T "$SERVICE" cat "$CONTAINER_CA_OUT" > "$CA_OUT"
    chmod 600 "$CA_OUT"
    python3 - "$verify_tmp" "$CA_OUT" > "$VERIFY_OUT" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    data = json.load(handle)
data["host_ca_out"] = sys.argv[2]
print(json.dumps(data, indent=2, sort_keys=True))
PY
    cat "$VERIFY_OUT"
    exit 0
  fi
  sleep 1
done

cat "$verify_err" >&2
exit 1
