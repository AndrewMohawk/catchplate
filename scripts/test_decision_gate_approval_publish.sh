#!/usr/bin/env bash
set -euo pipefail

BASE="${BASE:-http://localhost:3000}"
PROXY="${PROXY:-http://localhost:8080}"
GATE="${DECISION_GATE_BASE:-http://localhost:9091}"
GATE_HOST="${DECISION_GATE_HOST:-127.0.0.1}"
GATE_PORT="${DECISION_GATE_PORT:-9090}"
TMP_DIR="${TMP_DIR:-.tmp}"
CA_FILE="$TMP_DIR/catchplate-ca.pem"
ADMIN_HEADER=(-H "X-Catchplate-Admin-Token: ${CATCHPLATE_ADMIN_TOKEN:-dev-admin-token}")
AGENT_HEADER=(-H "X-Catchplate-Agent: demo-agent")
AGENT_PROXY_HEADER=(--proxy-header "X-Catchplate-Agent: demo-agent")

mkdir -p "$TMP_DIR"

POLICY_RESTORE_NEEDED=0

restore_demo_policy() {
  docker compose exec -T catchplate python - <<'PY'
import os
import time

from catchplate.config import POLICY_BUNDLE_PATH
from catchplate.db import get_policy_high_water
from catchplate.policy_bundle import demo_policy_bundle, write_policy_bundle

bundle = demo_policy_bundle("cred-demo-bearer")
high_water = get_policy_high_water()
if high_water:
    bundle["metadata"]["sequence"] = int(high_water["sequence"]) + 1
    bundle["metadata"]["rollbackEpoch"] = max(
        int(bundle["metadata"].get("rollbackEpoch", 0)),
        int(high_water["rollback_epoch"]),
    )
snapshot = write_policy_bundle(bundle, enforce_high_water=True)
now = time.time()
os.utime(POLICY_BUNDLE_PATH, (now, now))
print(snapshot.hash)
PY
}

wait_for_policy_hash() {
  python3 - "$GATE" "$1" <<'PY'
import json
import sys
import time
import urllib.request

gate = sys.argv[1].rstrip("/")
expected_hash = sys.argv[2]
deadline = time.time() + 15
health = {}
while time.time() < deadline:
    with urllib.request.urlopen(f"{gate}/healthz", timeout=10) as response:
        health = json.loads(response.read())
    if health.get("policy_hash") == expected_hash and health.get("credential_generations_ready") is True:
        break
    time.sleep(0.25)
else:
    raise AssertionError(f"decision gate did not load restored policy and credential generations: {health}")
PY
}

cleanup_policy() {
  local original_status=$?
  local cleanup_status=0
  local restored_policy_hash=""
  trap - EXIT
  if [[ "$POLICY_RESTORE_NEEDED" == "1" ]]; then
    POLICY_RESTORE_NEEDED=0
    set +e
    restored_policy_hash="$(restore_demo_policy)"
    cleanup_status=$?
    if [[ "$cleanup_status" == "0" ]]; then
      wait_for_policy_hash "$restored_policy_hash"
      cleanup_status=$?
    fi
    set -e
    if [[ "$cleanup_status" != "0" ]]; then
      echo "failed to restore demo policy during cleanup" >&2
      if [[ "$original_status" == "0" ]]; then
        original_status=$cleanup_status
      fi
    fi
  fi
  exit "$original_status"
}

trap cleanup_policy EXIT

CATCHPLATE_CA_OUT="$CA_FILE" \
CATCHPLATE_VERIFY_OUT="$TMP_DIR/decision-gate-approval-attestation.json" \
  ./scripts/install_verified_ca.sh >/dev/null
curl -fsS "${ADMIN_HEADER[@]}" -X POST "$BASE/api/dev/webauthn/credential" > "$TMP_DIR/decision-gate-webauthn-dev-credential.json"
curl -fsS "${ADMIN_HEADER[@]}" "$BASE/api/grants/status" > "$TMP_DIR/decision-gate-grant-store-status-before.json"
python3 - "$TMP_DIR/decision-gate-grant-store-status-before.json" <<'PY'
import json
import sys
status = json.load(open(sys.argv[1]))
assert status["backend"] == "postgres", status
assert status["ha"] is True, status
assert status["transactional_consume"] == "select_for_update_bounded_wait", status
assert status["consumptions"]["pending_audit"] == 0, status
PY

POLICY_RESTORE_NEEDED=1
jit_rate_policy_hash="$(docker compose exec -T catchplate python - <<'PY'
import os
import time

from catchplate.config import POLICY_BUNDLE_PATH
from catchplate.db import get_policy_high_water
from catchplate.policy_bundle import demo_policy_bundle, write_policy_bundle

bundle = demo_policy_bundle("cred-demo-bearer")
high_water = get_policy_high_water()
if high_water:
    bundle["metadata"]["sequence"] = int(high_water["sequence"]) + 1
    bundle["metadata"]["rollbackEpoch"] = max(
        int(bundle["metadata"].get("rollbackEpoch", 0)),
        int(high_water["rollback_epoch"]),
    )
route = next(item for item in bundle["routes"] if item["id"] == "demo.npm.publish.jit")
route["constraints"].append(
    {
        "id": "npm-jit-rate-atomicity",
        "type": "rateLimit",
        "description": "Exercise quota commit before one-use JIT grant consumption.",
        "max": 1,
        "windowSeconds": 2,
        "store": "shared",
        "key": {
            "scope": ["principal", "credential", "credentialVersion", "route", "operation"],
            "operationFields": ["packageName", "packageVersion"],
        },
    }
)
snapshot = write_policy_bundle(bundle, enforce_high_water=True)
now = time.time()
os.utime(POLICY_BUNDLE_PATH, (now, now))
print(snapshot.hash)
PY
)"

python3 - "$GATE" "$jit_rate_policy_hash" <<'PY'
import json
import sys
import time
import urllib.request

gate = sys.argv[1].rstrip("/")
expected_hash = sys.argv[2]
deadline = time.time() + 15
while time.time() < deadline:
    with urllib.request.urlopen(f"{gate}/healthz", timeout=10) as response:
        health = json.loads(response.read())
    if health.get("policy_hash") == expected_hash and health.get("credential_generations_ready") is True:
        break
    time.sleep(0.25)
else:
    raise AssertionError(f"decision gate did not load JIT rate-limit test policy: {health}")
PY

run_version="1.2.$(date +%s)"
npm_body="$(python3 - "$run_version" <<'PY'
import base64
import hashlib
import json
import sys

version = sys.argv[1]
tarball = f"catchplate npm publish fixture {version}\n".encode("ascii")
integrity = "sha512-" + base64.b64encode(hashlib.sha512(tarball).digest()).decode("ascii")
print(
    json.dumps(
        {
            "name": "demo-package",
            "dist-tags": {"latest": version},
            "tarball_integrity": integrity,
            "versions": {
                version: {
                    "name": "demo-package",
                    "version": version,
                    "_integrity": integrity,
                    "dist": {"integrity": integrity},
                }
            },
            "_attachments": {
                f"demo-package-{version}.tgz": {
                    "content_type": "application/octet-stream",
                    "data": base64.b64encode(tarball).decode("ascii"),
                    "length": len(tarball),
                }
            },
        },
        separators=(",", ":"),
        sort_keys=True,
    )
)
PY
)"
npm_url="https://demo-upstream:8443/npm/demo-package"
python3 - "$GATE" "$npm_body" "$TMP_DIR/decision-gate-approval-required.json" "$TMP_DIR/decision-gate-approval-request.raw" "$GATE_HOST" "$GATE_PORT" <<'PY'
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import urllib.request

gate = sys.argv[1].rstrip("/")
body = sys.argv[2]
output_path = sys.argv[3]
raw_request_path = Path(sys.argv[4])
gate_host = sys.argv[5]
gate_port = int(sys.argv[6])
management_token = os.environ.get("CATCHPLATE_DATA_PLANE_MANAGEMENT_TOKEN", "").strip() or "dev-rust-management-token"


def post(url, payload, token):
    request = urllib.request.Request(
        url,
        data=json.dumps(payload, separators=(",", ":"), sort_keys=True).encode(),
        headers={"Content-Type": "application/json", "X-Catchplate-Data-Plane-Token": token},
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.loads(response.read())


def mutation_store():
    query = """
    SELECT json_build_object(
      'attempts', (SELECT COUNT(*) FROM release_authorization_attempts),
      'quota', (SELECT COALESCE(SUM(count), 0) FROM rate_limit_counters WHERE route_id = 'demo.npm.publish.jit'),
      'approvals', (SELECT COUNT(*) FROM approval_requests),
      'grants', (SELECT COUNT(*) FROM approval_grants)
    )
    """
    raw = subprocess.check_output(
        ["docker", "compose", "exec", "-T", "grant-store", "psql", "-U", "catchplate", "-d", "catchplate", "-Atq", "-c", query],
        text=True,
    )
    return json.loads(raw)


def forward(raw: bytes):
    with socket.create_connection((gate_host, gate_port), timeout=10) as sock:
        sock.sendall(raw)
        response = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
    head, _, response_body = response.partition(b"\r\n\r\n")
    return int(head.split(b" ", 2)[1]), json.loads(response_body)


def preview_client_ip():
    override = os.environ.get("CATCHPLATE_TEST_PROXY_CLIENT_IP", "").strip()
    if override:
        return override
    container_id = subprocess.check_output(
        ["docker", "compose", "ps", "-q", "decision-gate-rs"],
        text=True,
    ).strip()
    if not container_id:
        return "127.0.0.1"
    inspection = json.loads(
        subprocess.check_output(["docker", "inspect", container_id], text=True)
    )[0]
    for network in inspection.get("NetworkSettings", {}).get("Networks", {}).values():
        gateway = str(network.get("Gateway") or "").strip()
        if gateway:
            return gateway
    return "127.0.0.1"


payload = {
    "clientIp": preview_client_ip(),
    "method": "PUT",
    "url": "https://demo-upstream:8443/npm/demo-package",
    "headers": {"X-Catchplate-Agent": "demo-agent", "Content-Type": "application/json"},
    "body": body,
    "preview": True,
}
body_bytes = body.encode()
raw_request = (
    "PUT https://demo-upstream:8443/npm/demo-package HTTP/1.1\r\n"
    "Host: demo-upstream:8443\r\n"
    "X-Catchplate-Agent: demo-agent\r\n"
    "Content-Type: application/json\r\n"
    f"Content-Length: {len(body_bytes)}\r\n"
    "Connection: close\r\n\r\n"
).encode() + body_bytes
raw_request_path.write_bytes(raw_request)
before = mutation_store()
preview = post(f"{gate}/v1/decide", payload, management_token)
assert preview["action"] == "jit_required", preview
assert preview["preview"] is True and preview["allowed"] is False, preview
assert preview["authorizes_forwarding"] is False, preview
assert preview["injection"] is None, preview
assert preview["approval_id"] is None, preview
assert mutation_store() == before, (before, mutation_store())

before_actual = mutation_store()
status, approval = forward(raw_request)
assert status == 428, approval
assert approval["action"] == "jit_required" and approval["allowed"] is False, approval
assert approval["approval_id"], approval
assert approval["approval_status"] == "pending", approval
assert approval["approval_created"] is True, approval
assert approval["expires_at"], approval
assert 1 <= approval["retry_after_seconds"] <= 3600, approval
assert approval["payload"]["approval_id"] == approval["approval_id"], approval
assert approval["payload"]["approval_status"] == approval["approval_status"], approval
assert approval["payload"]["expires_at"] == approval["expires_at"], approval
assert approval["payload"]["retry_after_seconds"] == approval["retry_after_seconds"], approval
assert approval["request_digest"] == preview["request_digest"], (preview, approval)
assert approval["operation_digest"] == preview["operation_digest"], (preview, approval)
after_actual = mutation_store()
assert after_actual["attempts"] == before_actual["attempts"], (before_actual, after_actual)
assert after_actual["quota"] == before_actual["quota"], (before_actual, after_actual)
assert after_actual["grants"] == before_actual["grants"], (before_actual, after_actual)
assert after_actual["approvals"] == before_actual["approvals"] + 1, (before_actual, after_actual)
approval["_test_client_ip"] = payload["clientIp"]
approval["_test_raw_request_sha256"] = "sha256:" + hashlib.sha256(
    raw_request
).hexdigest()
json.dump(approval, open(output_path, "w", encoding="utf-8"))
PY

approval_id="$(python3 - "$TMP_DIR/decision-gate-approval-required.json" <<'PY'
import json
import sys
print(json.load(open(sys.argv[1]))["approval_id"])
PY
)"

curl -fsS "${ADMIN_HEADER[@]}" "$BASE/api/approvals/$approval_id/review" > "$TMP_DIR/decision-gate-approval-review.json"
python3 - "$TMP_DIR/decision-gate-approval-review.json" "$TMP_DIR/decision-gate-approval-required.json" "$TMP_DIR/decision-gate-approval-review-request.json" <<'PY'
import json
import sys
review = json.load(open(sys.argv[1]))
required = json.load(open(sys.argv[2]))
assert review["id"] == required["approval_id"], (review, required)
assert review["status"] == required["approval_status"] == "pending", (review, required)
assert review["expires_at"] == required["expires_at"], (review, required)
assert review["review_digest"].startswith("sha256:"), review
assert review["review_receipt"]["id"], review
json.dump({"reviewReceiptId": review["review_receipt"]["id"]}, open(sys.argv[3], "w"))
PY
curl -fsS "${ADMIN_HEADER[@]}" -H "Content-Type: application/json" -X POST \
  --data @"$TMP_DIR/decision-gate-approval-review-request.json" \
  "$BASE/api/approvals/$approval_id/webauthn/options" > "$TMP_DIR/decision-gate-approval-options.json"
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
python3 - "$TMP_DIR/decision-gate-approval-assertion.json" "$TMP_DIR/decision-gate-approval-review.json" "$TMP_DIR/decision-gate-approval-approve.json" <<'PY'
import json
import sys
review = json.load(open(sys.argv[2]))
json.dump(
    {
        "assertion": json.load(open(sys.argv[1])),
        "reviewReceiptId": review["review_receipt"]["id"],
    },
    open(sys.argv[3], "w"),
)
PY
curl -fsS "${ADMIN_HEADER[@]}" -H "Content-Type: application/json" -X POST \
  --data @"$TMP_DIR/decision-gate-approval-approve.json" \
  "$BASE/api/approvals/$approval_id/approve?ttl_seconds=30" > "$TMP_DIR/decision-gate-approval-approved.json"

python3 - "$TMP_DIR/decision-gate-approval-approved.json" "$TMP_DIR/decision-gate-approval-required.json" "$TMP_DIR/decision-gate-approval-request.raw" "$GATE" "$BASE" "$npm_body" "$GATE_HOST" "$GATE_PORT" <<'PY'
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import urllib.request

approved = json.load(open(sys.argv[1]))
required = json.load(open(sys.argv[2]))
raw_request = Path(sys.argv[3]).read_bytes()
gate = sys.argv[4].rstrip("/")
base = sys.argv[5].rstrip("/")
body = sys.argv[6]
gate_host = sys.argv[7]
gate_port = int(sys.argv[8])
management_token = os.environ.get("CATCHPLATE_DATA_PLANE_MANAGEMENT_TOKEN", "").strip() or "dev-rust-management-token"
rate_limit_token = os.environ.get("CATCHPLATE_DATA_PLANE_RATE_LIMIT_CONSUME_TOKEN", "").strip() or "dev-rate-limit-consume-token"
publish = approved.get("data_plane_grant_publish") or {}
assert approved["id"] == required["approval_id"], (approved, required)
assert approved["request_digest"] == required["request_digest"], (approved, required)
assert approved["operation_digest"] == required["operation_digest"], (approved, required)
assert "sha256:" + hashlib.sha256(raw_request).hexdigest() == required[
    "_test_raw_request_sha256"
], required
assert publish == {"enabled": True, "ok": True, "error": None}, approved

decision_payload = {
    "clientIp": required["_test_client_ip"],
    "method": "PUT",
    "url": "https://demo-upstream:8443/npm/demo-package",
    "headers": {
        "X-Catchplate-Agent": "demo-agent",
        "Content-Type": "application/json",
    },
    "body": body,
    "credentialMetadata": {approved["credential_id"]: {"x_app_id": "demo-x-app"}},
}


def post(path, payload):
    req = urllib.request.Request(
        f"{gate}{path}",
        data=json.dumps(payload, separators=(",", ":"), sort_keys=True).encode(),
        headers={
            "Content-Type": "application/json",
            "X-Catchplate-Data-Plane-Token": management_token,
        },
    )
    with urllib.request.urlopen(req, timeout=10) as response:
        return json.loads(response.read())


def control_post(path, payload, token):
    req = urllib.request.Request(
        f"{base}{path}",
        data=json.dumps(payload, separators=(",", ":"), sort_keys=True).encode(),
        headers={
            "Content-Type": "application/json",
            "X-Catchplate-Data-Plane-Token": token,
        },
    )
    with urllib.request.urlopen(req, timeout=10) as response:
        return json.loads(response.read())


def forward() -> tuple[int, dict]:
    with socket.create_connection((gate_host, gate_port), timeout=10) as sock:
        sock.sendall(raw_request)
        response = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
    head, _, response_body = response.partition(b"\r\n\r\n")
    return int(head.split(b" ", 2)[1]), json.loads(response_body)


def release_store() -> dict:
    grant_id = f"approval:{approved['id']}"
    query = f"""
    SELECT json_build_object(
      'attempts', (SELECT COUNT(*) FROM release_authorization_attempts WHERE route_id = 'demo.npm.publish.jit'),
      'forwarded', (SELECT COUNT(*) FROM release_authorization_attempts WHERE route_id = 'demo.npm.publish.jit' AND state = 'committed' AND completion_outcome = 'forwarded'),
      'nonterminal', (SELECT COUNT(*) FROM release_authorization_attempts WHERE route_id = 'demo.npm.publish.jit' AND state IN ('reserved', 'dispatching')),
      'uncorrelated', (SELECT COUNT(*) FROM release_authorization_attempts WHERE route_id = 'demo.npm.publish.jit' AND attempt_id <> flow_id),
      'credential_issuances', (
        SELECT COUNT(*)
        FROM release_authorization_credential_issuances AS issuance
        INNER JOIN release_authorization_attempts AS attempt
          ON attempt.attempt_id = issuance.attempt_id
        WHERE attempt.route_id = 'demo.npm.publish.jit'
      ),
      'quota_count', (SELECT COALESCE(SUM(count), 0) FROM rate_limit_counters WHERE route_id = 'demo.npm.publish.jit'),
      'approvals', (SELECT COUNT(*) FROM approval_requests WHERE route_id = 'demo.npm.publish.jit'),
      'grant_state', (SELECT state FROM approval_grants WHERE id = '{grant_id}'),
      'grant_uses', (SELECT uses_remaining FROM approval_grants WHERE id = '{grant_id}'),
      'grant_reservation', (SELECT reserved_attempt_id FROM approval_grants WHERE id = '{grant_id}')
    )
    """
    raw = subprocess.check_output(
        ["docker", "compose", "exec", "-T", "grant-store", "psql", "-U", "catchplate", "-d", "catchplate", "-Atq", "-c", query],
        text=True,
    )
    return json.loads(raw)


operation = required["operation"]
rate_material = {
    "constraint": "npm-jit-rate-atomicity",
    "principal": approved["principal_id"],
    "credential": approved["credential_id"],
    "credentialVersion": approved["credential_version"],
    "route": approved["route_id"],
    "operation": operation["operation"],
    "operation.packageName": operation["packageName"],
    "operation.packageVersion": operation["packageVersion"],
}
counter_key = "sha256:" + hashlib.sha256(
    json.dumps(rate_material, separators=(",", ":"), sort_keys=True).encode()
).hexdigest()
exhausted = control_post(
    "/api/data-plane/rate-limits/consume",
    {
        "counterKey": counter_key,
        "principalId": approved["principal_id"],
        "routeId": approved["route_id"],
        "credentialRef": approved["credential_id"],
        "credentialVersion": approved["credential_version"],
        "policyHash": approved["policy_hash"],
        "constraintId": "npm-jit-rate-atomicity",
        "operation": operation["operation"],
        "operationContext": operation,
        "max": 1,
        "windowSeconds": 2,
        "consume": True,
    },
    rate_limit_token,
)
assert exhausted["allowed"] is True and exhausted["remaining"] == 0, exhausted

before_preview = release_store()
rate_denied = post("/v1/decide", decision_payload)
assert rate_denied["action"] == "jit_required", rate_denied
assert rate_denied["preview"] is True and rate_denied["allowed"] is False, rate_denied
assert rate_denied["injection"] is None, rate_denied
assert release_store() == before_preview, (before_preview, release_store())

before_denial = release_store()
status, denied = forward()
assert status == 403, denied
assert denied["payload"]["error"] == "credential_rate_limit_exceeded", denied
assert denied["payload"]["store"] == "shared", denied
assert release_store() == before_denial, (before_denial, release_store())

time.sleep(2.2)
before_forward = release_store()
status, first = forward()
assert status == 200, first
after_forward = release_store()
assert after_forward["attempts"] == before_forward["attempts"] + 1, (before_forward, after_forward)
assert after_forward["forwarded"] == before_forward["forwarded"] + 1, (before_forward, after_forward)
assert after_forward["nonterminal"] == before_forward["nonterminal"], (before_forward, after_forward)
assert after_forward["uncorrelated"] == before_forward["uncorrelated"], (before_forward, after_forward)
assert after_forward["credential_issuances"] == before_forward["credential_issuances"] + 1, (before_forward, after_forward)
assert after_forward["grant_state"] == "consumed", after_forward
assert after_forward["grant_uses"] == 0, after_forward
assert after_forward["grant_reservation"] is None, after_forward

time.sleep(2.2)
before_reuse = release_store()
status, second = forward()
assert status == 428, second
assert second["action"] == "jit_required", second
assert second["approval_id"] != approved["id"], second
assert second["approval_status"] == "pending", second
assert second["approval_created"] is True, second
assert second["expires_at"], second
assert 1 <= second["retry_after_seconds"] <= 3600, second
after_reuse = release_store()
assert after_reuse["approvals"] == before_reuse["approvals"] + 1, (before_reuse, after_reuse)
for key in before_reuse.keys() - {"approvals"}:
    assert after_reuse[key] == before_reuse[key], (key, before_reuse, after_reuse)

status, reused = forward()
assert status == 428, reused
assert reused["approval_id"] == second["approval_id"], (second, reused)
assert reused["approval_status"] == "pending", reused
assert reused["approval_created"] is False, reused
assert release_store() == after_reuse, (after_reuse, release_store())
print(json.dumps({
    "ok": True,
    "approval_id": approved["id"],
    "grant_id": f"approval:{approved['id']}",
    "grant_store": "atomic_release_authorization",
    "quota_denial_preserved_grant": True,
}, sort_keys=True))
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
