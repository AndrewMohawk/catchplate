#!/usr/bin/env bash
set -euo pipefail

BASE="${BASE:-http://localhost:3000}"
PROXY="${PROXY:-http://localhost:8080}"
GATE="${DECISION_GATE_BASE:-http://localhost:9091}"
TMP_DIR="${TMP_DIR:-.tmp}"
CA_FILE="$TMP_DIR/serverware-ca.pem"
ADMIN_HEADER=(-H "X-Serverware-Admin-Token: ${SERVERWARE_ADMIN_TOKEN:-dev-admin-token}")
AGENT_HEADER=(-H "X-Serverware-Agent: demo-agent")
AGENT_PROXY_HEADER=(--proxy-header "X-Serverware-Agent: demo-agent")

mkdir -p "$TMP_DIR"

SERVERWARE_CA_OUT="$CA_FILE" \
SERVERWARE_VERIFY_OUT="$TMP_DIR/decision-gate-approval-attestation.json" \
  ./scripts/install_verified_ca.sh >/dev/null
curl -fsS "${ADMIN_HEADER[@]}" -X POST "$BASE/api/dev/webauthn/credential" > "$TMP_DIR/decision-gate-webauthn-dev-credential.json"
curl -fsS "${ADMIN_HEADER[@]}" "$BASE/api/grants/status" > "$TMP_DIR/decision-gate-grant-store-status-before.json"
python3 - "$TMP_DIR/decision-gate-grant-store-status-before.json" <<'PY'
import json
import sys
status = json.load(open(sys.argv[1]))
assert status["backend"] == "postgres", status
assert status["ha"] is True, status
assert status["transactional_consume"] == "select_for_update_skip_locked", status
PY

run_version="1.2.$(date +%s)"
npm_body="{\"name\":\"demo-package\",\"version\":\"$run_version\",\"tarball_integrity\":\"sha512-demo\"}"
npm_url="https://demo-upstream:8443/npm/demo-package"
approval_code="$(curl -sS -o "$TMP_DIR/decision-gate-approval-required.json" -w "%{http_code}" \
  -X PUT --data "$npm_body" -H "Content-Type: application/json" \
  --proxy "$PROXY" "${AGENT_PROXY_HEADER[@]}" --cacert "$CA_FILE" "${AGENT_HEADER[@]}" "$npm_url")"
if [[ "$approval_code" != "428" ]]; then
  echo "expected npm publish to require approval with 428, got $approval_code" >&2
  cat "$TMP_DIR/decision-gate-approval-required.json" >&2
  exit 1
fi

approval_id="$(python3 - "$TMP_DIR/decision-gate-approval-required.json" <<'PY'
import json
import sys
print(json.load(open(sys.argv[1]))["approval_id"])
PY
)"

curl -fsS "${ADMIN_HEADER[@]}" -X POST "$BASE/api/approvals/$approval_id/webauthn/options" > "$TMP_DIR/decision-gate-approval-options.json"
challenge="$(python3 - "$TMP_DIR/decision-gate-approval-options.json" <<'PY'
import json
import sys
data = json.load(open(sys.argv[1]))
print(data["publicKey"]["challenge"])
PY
)"
curl -fsS "${ADMIN_HEADER[@]}" -H "Content-Type: application/json" -X POST \
  --data "{\"challenge\":\"$challenge\"}" \
  "$BASE/api/dev/webauthn/assertion" > "$TMP_DIR/decision-gate-approval-assertion.json"
python3 - "$TMP_DIR/decision-gate-approval-assertion.json" "$TMP_DIR/decision-gate-approval-approve.json" <<'PY'
import json
import sys
json.dump({"assertion": json.load(open(sys.argv[1]))}, open(sys.argv[2], "w"))
PY
curl -fsS "${ADMIN_HEADER[@]}" -H "Content-Type: application/json" -X POST \
  --data @"$TMP_DIR/decision-gate-approval-approve.json" \
  "$BASE/api/approvals/$approval_id/approve?ttl_seconds=30" > "$TMP_DIR/decision-gate-approval-approved.json"

python3 - "$TMP_DIR/decision-gate-approval-approved.json" "$GATE" "$npm_body" <<'PY'
import json
import os
import sys
import urllib.request

approved = json.load(open(sys.argv[1]))
gate = sys.argv[2].rstrip("/")
body = sys.argv[3]
management_token = os.environ.get("SERVERWARE_DATA_PLANE_AUDIT_TOKEN", "").strip() or "dev-data-plane-audit-token"
publish = approved.get("data_plane_grant_publish") or {}
assert publish.get("enabled") is True, approved
assert publish.get("ok") is True, approved
assert (publish.get("response") or {}).get("grant_id") == f"approval:{approved['id']}", approved

decision_payload = {
    "clientIp": approved["canonical_request"]["client_ip"],
    "method": "PUT",
    "url": "https://demo-upstream:8443/npm/demo-package",
    "headers": {"X-Serverware-Agent": "demo-agent", "Content-Type": "application/json"},
    "body": body,
    "credentialMetadata": {approved["credential_id"]: {"x_app_id": "demo-x-app"}},
}

def post(path, payload):
    req = urllib.request.Request(
        f"{gate}{path}",
        data=json.dumps(payload, separators=(",", ":"), sort_keys=True).encode(),
        headers={
            "Content-Type": "application/json",
            "X-Serverware-Data-Plane-Token": management_token,
        },
    )
    with urllib.request.urlopen(req, timeout=10) as response:
        return json.loads(response.read())

first = post("/v1/decide", decision_payload)
assert first["action"] == "allow", first
assert first["jit"]["grant_consumed"] is True, first
assert first["jit"]["grant_id"], first
assert first["jit"]["approval_id"] == approved["id"], first
assert first["jit"]["grant_store"] == "shared", first
assert first["injection"]["credential_ref"] == approved["credential_id"], first

second = post("/v1/decide", decision_payload)
assert second["action"] == "jit_required", second
assert second["jit"]["grant_consumed"] is False, second
assert second["jit"]["grant_store"] == "shared", second
print(json.dumps({"ok": True, "approval_id": approved["id"], "grant_id": first["jit"]["grant_id"], "grant_store": first["jit"]["grant_store"]}, sort_keys=True))
PY

curl -fsS "${ADMIN_HEADER[@]}" "$BASE/api/grants/status" > "$TMP_DIR/decision-gate-grant-store-status-after.json"
python3 - "$TMP_DIR/decision-gate-grant-store-status-after.json" <<'PY'
import json
import sys
status = json.load(open(sys.argv[1]))
assert status["backend"] == "postgres", status
assert status["grants"]["consumed_grants"] >= 1, status
assert status["consumptions"]["consumptions"] >= 1, status
assert status["consumptions"]["pending_audit"] == 0, status
print(json.dumps({"ok": True, "grant_store_backend": "postgres", "pending_audit": 0}, sort_keys=True))
PY
