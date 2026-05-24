#!/usr/bin/env bash
set -euo pipefail

BASE="${BASE:-http://localhost:3000}"
PROXY="${PROXY:-http://localhost:8080}"
TMP_DIR="${TMP_DIR:-.tmp}"
CA_FILE="$TMP_DIR/serverware-ca.pem"
AGENT_HEADER=(-H "X-Serverware-Agent: demo-agent")
ADMIN_HEADER=(-H "X-Serverware-Admin-Token: ${SERVERWARE_ADMIN_TOKEN:-dev-admin-token}")

mkdir -p "$TMP_DIR"

for _ in $(seq 1 60); do
  if curl -fs "$BASE/healthz" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

unauth_code="$(curl -sS -o "$TMP_DIR/bootstrap-unauth.json" -w "%{http_code}" "$BASE/api/bootstrap")"
if [[ "$unauth_code" != "401" ]]; then
  echo "expected unauthenticated bootstrap to fail with 401, got $unauth_code" >&2
  cat "$TMP_DIR/bootstrap-unauth.json" >&2
  exit 1
fi

ca_unauth_code="$(curl -sS -o "$TMP_DIR/ca-unauth.json" -w "%{http_code}" "$BASE/ca.pem")"
if [[ "$ca_unauth_code" != "401" ]]; then
  echo "expected unauthenticated CA download to fail with 401, got $ca_unauth_code" >&2
  cat "$TMP_DIR/ca-unauth.json" >&2
  exit 1
fi

curl -fsS "${ADMIN_HEADER[@]}" -X POST "$BASE/api/demo/seed" > "$TMP_DIR/seed.json"
curl -fsS "${ADMIN_HEADER[@]}" -X POST "$BASE/api/dev/webauthn/credential" > "$TMP_DIR/webauthn-dev-credential.json"
curl -fsS "${ADMIN_HEADER[@]}" "$BASE/api/bootstrap" > "$TMP_DIR/bootstrap.json"
python3 - "$TMP_DIR/bootstrap.json" "$TMP_DIR/credential-version-before-rotation.txt" <<'PY'
import json, sys
data = json.load(open(sys.argv[1]))
assert data["admin_auth_required"] is True, data
assert data["policy_hash"], data
assert data["policy_signature"].startswith("ed25519:"), data
assert data["policy_signing_key_id"].startswith("sha256:"), data
credential = next(item for item in data["credentials"] if item["id"] == "cred-demo-bearer")
assert "secret" not in credential, credential
assert isinstance(credential["credential_version"], int) and credential["credential_version"] >= 1, credential
assert credential["secret_kek_id"].startswith("attested-dev-kek:"), credential
assert credential["secret_updated_at"], credential
open(sys.argv[2], "w").write(str(credential["credential_version"]))
PY

curl -fsS "$BASE/attestation?nonce=e2e" > "$TMP_DIR/attestation.json"
python3 - "$TMP_DIR/attestation.json" <<'PY'
import json, sys
data = json.load(open(sys.argv[1]))
assert data["policy_bundle_digest"], data
assert data["policy_bundle_signature"].startswith("ed25519:"), data
assert data["policy_signing_key_id"].startswith("sha256:"), data
assert data["data_plane_binary_digest"].startswith("sha256:"), data
assert data["quote"]["claims"]["data_plane_binary_digest"] == data["data_plane_binary_digest"], data
assert "BEGIN PUBLIC KEY" in data["policy_signing_public_key_pem"], data
assert data["nonce"] == "e2e", data
PY

SERVERWARE_CA_OUT="$CA_FILE" \
SERVERWARE_VERIFY_OUT="$TMP_DIR/attestation-verify.json" \
  ./scripts/install_verified_ca.sh >/dev/null
python3 - "$TMP_DIR/attestation-verify.json" "$CA_FILE" <<'PY'
import json, sys
data = json.load(open(sys.argv[1]))
assert data["ok"] is True, data
assert data["policy_hash"].startswith("sha256:"), data
assert data["policy_signing_key_id"].startswith("sha256:"), data
assert data["ca_intermediate_spki_sha256"].startswith("sha256:"), data
assert data["data_plane_binary_digest"].startswith("sha256:"), data
assert data["ca_out"] == "/tmp/serverware-verified-ca.pem", data
assert data["host_ca_out"] == sys.argv[2], data
PY

if [[ ! -s "$CA_FILE" ]]; then
  echo "verified CA file was not installed" >&2
  exit 1
fi

unknown_code="$(curl -sS -o "$TMP_DIR/unknown-route.json" -w "%{http_code}" --proxy "$PROXY" --cacert "$CA_FILE" "${AGENT_HEADER[@]}" \
  "https://demo-upstream:8443/unknown")"
if [[ "$unknown_code" != "403" ]]; then
  echo "expected unknown route to fail with 403, got $unknown_code" >&2
  cat "$TMP_DIR/unknown-route.json" >&2
  exit 1
fi

curl -fsS --proxy "$PROXY" --cacert "$CA_FILE" "${AGENT_HEADER[@]}" \
  "https://demo-upstream:8443/echo" > "$TMP_DIR/echo.json"
python3 - "$TMP_DIR/echo.json" <<'PY'
import hashlib, json, sys
data = json.load(open(sys.argv[1]))
assert data["authorization_present"] is True, data
assert data["authorization_scheme"] == "Bearer", data
assert data["authorization_sha256"] == "sha256:" + hashlib.sha256(b"Bearer demo-token-from-vault").hexdigest(), data
for key in ("authorization", "serverware_agent", "proxy_authorization", "cookie", "x_api_key"):
    assert key not in data, data
PY

curl -fsS --proxy "$PROXY" --cacert "$CA_FILE" "${AGENT_HEADER[@]}" \
  "https://demo-upstream:8443/gmail/v1/users/me/messages?q=from%3Asecurity%40example.com&maxResults=500" \
  > "$TMP_DIR/gmail-list.json"
python3 - "$TMP_DIR/gmail-list.json" <<'PY'
import json, sys
data = json.load(open(sys.argv[1]))
assert set(data) == {"messages"}, data
for item in data["messages"]:
    assert item["serverwareAgeProof"] == "validated", item
    assert int(item["internalDate"]) > 1776900000000, item
    assert item["threadId"].startswith("thread-"), item
    assert item["payload"]["headers"][0]["name"] == "From", item
    assert "body" not in item["payload"], item
    for key in ("authorization", "proxy_authorization", "serverware_agent", "cookie", "query", "raw", "secretDebug", "serverDebugSecret"):
        assert key not in item, item
PY

curl -fsS --proxy "$PROXY" --cacert "$CA_FILE" "${AGENT_HEADER[@]}" \
  "https://demo-upstream:8443/gmail/v1/users/me/messages?q=newer_than%3A3650d&maxResults=500" \
  > "$TMP_DIR/gmail-weak-query.json"
python3 - "$TMP_DIR/gmail-weak-query.json" <<'PY'
import json, sys
data = json.load(open(sys.argv[1]))
assert set(data) == {"messages"}, data
assert all(item["serverwareAgeProof"] == "validated" for item in data["messages"]), data
assert all("raw" not in item and "body" not in item["payload"] for item in data["messages"]), data
PY

curl -fsS --proxy "$PROXY" --cacert "$CA_FILE" "${AGENT_HEADER[@]}" \
  "https://demo-upstream:8443/gmail/v1/users/me/messages?q=from%3Asecurity%40example.com&omitInternalDate=1" \
  > "$TMP_DIR/gmail-pending-list.json"
python3 - "$TMP_DIR/gmail-pending-list.json" <<'PY'
import json, sys
data = json.load(open(sys.argv[1]))
assert set(data) == {"messages", "serverwarePendingAgeProof"}, data
assert data["serverwarePendingAgeProof"] == ["pending-message-1", "pending-message-2"], data
for item in data["messages"]:
    assert item["serverwareAgeProof"] == "pending", item
    assert "internalDate" not in item, item
    assert item["payload"]["headers"][0]["name"] == "From", item
    assert "body" not in item["payload"], item
    for key in ("authorization", "proxy_authorization", "serverware_agent", "cookie", "query", "raw", "secretDebug", "serverDebugSecret"):
        assert key not in item, item
PY

pending_get_code="$(curl -sS -o "$TMP_DIR/gmail-pending-get-block.json" -w "%{http_code}" --proxy "$PROXY" --cacert "$CA_FILE" "${AGENT_HEADER[@]}" \
  "https://demo-upstream:8443/gmail/v1/users/me/messages/pending-message-1")"
if [[ "$pending_get_code" != "403" ]]; then
  echo "expected Gmail ID without age proof to fail with 403, got $pending_get_code" >&2
  cat "$TMP_DIR/gmail-pending-get-block.json" >&2
  exit 1
fi

curl -fsS --proxy "$PROXY" --cacert "$CA_FILE" "${AGENT_HEADER[@]}" \
  "https://demo-upstream:8443/gmail/v1/users/me/messages/recent-message-1" \
  > "$TMP_DIR/gmail-get.json"
python3 - "$TMP_DIR/gmail-get.json" <<'PY'
import json, sys
data = json.load(open(sys.argv[1]))
assert data["id"] == "recent-message-1", data
assert data["threadId"] == "thread-recent-message-1", data
assert data["payload"]["headers"][0]["name"] == "From", data
assert "body" not in data["payload"], data
for key in ("authorization", "proxy_authorization", "serverware_agent", "cookie", "query", "path", "method", "raw", "secretDebug", "serverDebugSecret"):
    assert key not in data, data
PY

old_code="$(curl -sS -o "$TMP_DIR/gmail-old-block.json" -w "%{http_code}" --proxy "$PROXY" --cacert "$CA_FILE" "${AGENT_HEADER[@]}" \
  "https://demo-upstream:8443/gmail/v1/users/me/messages/old-message-1")"
if [[ "$old_code" != "403" ]]; then
  echo "expected old gmail direct read to fail with 403, got $old_code" >&2
  cat "$TMP_DIR/gmail-old-block.json" >&2
  exit 1
fi

curl -fsS --proxy "$PROXY" --cacert "$CA_FILE" "${AGENT_HEADER[@]}" \
  "https://demo-upstream:8443/2/tweets" > "$TMP_DIR/x-read.json"
python3 - "$TMP_DIR/x-read.json" <<'PY'
import hashlib, json, sys
data = json.load(open(sys.argv[1]))
assert data["authorization_present"] is True, data
assert data["authorization_scheme"] == "Bearer", data
assert data["authorization_sha256"] == "sha256:" + hashlib.sha256(b"Bearer demo-token-from-vault").hexdigest(), data
assert "authorization" not in data, data
assert data["data"][0]["id"] == "tweet-1", data
assert data["data"][0]["text"] == "demo", data
PY

x_write_code="$(curl -sS -o "$TMP_DIR/x-write-block.json" -w "%{http_code}" -X POST --proxy "$PROXY" --cacert "$CA_FILE" "${AGENT_HEADER[@]}" \
  "https://demo-upstream:8443/2/tweets")"
if [[ "$x_write_code" != "403" ]]; then
  echo "expected X write to fail with 403, got $x_write_code" >&2
  cat "$TMP_DIR/x-write-block.json" >&2
  exit 1
fi

x_unknown_read_code="$(curl -sS -o "$TMP_DIR/x-unknown-read-block.json" -w "%{http_code}" --proxy "$PROXY" --cacert "$CA_FILE" "${AGENT_HEADER[@]}" \
  "https://demo-upstream:8443/2/users")"
if [[ "$x_unknown_read_code" != "403" ]]; then
  echo "expected unconfigured X read operation to fail with 403, got $x_unknown_read_code" >&2
  cat "$TMP_DIR/x-unknown-read-block.json" >&2
  exit 1
fi

npm_body='{"name":"demo-package","version":"1.2.3","tarball_integrity":"sha512-demo"}'
npm_url="https://demo-upstream:8443/npm/demo-package"
bad_npm_body='{"name":"demo-package","version":"1.2.3"}'
bad_npm_code="$(curl -sS -o "$TMP_DIR/npm-missing-fields-block.json" -w "%{http_code}" -X PUT --data "$bad_npm_body" -H "Content-Type: application/json" --proxy "$PROXY" --cacert "$CA_FILE" "${AGENT_HEADER[@]}" \
  "$npm_url")"
if [[ "$bad_npm_code" != "403" ]]; then
  echo "expected npm publish missing integrity to fail with 403, got $bad_npm_code" >&2
  cat "$TMP_DIR/npm-missing-fields-block.json" >&2
  exit 1
fi
approval_code="$(curl -sS -o "$TMP_DIR/approval-block.json" -w "%{http_code}" -X PUT --data "$npm_body" -H "Content-Type: application/json" --proxy "$PROXY" --cacert "$CA_FILE" "${AGENT_HEADER[@]}" \
  "$npm_url")"
if [[ "$approval_code" != "428" ]]; then
  echo "expected approval request to fail with 428, got $approval_code" >&2
  cat "$TMP_DIR/approval-block.json" >&2
  exit 1
fi

approval_id="$(python3 - "$TMP_DIR/approval-block.json" <<'PY'
import json, sys
print(json.load(open(sys.argv[1]))["approval_id"])
PY
)"
approval_without_webauthn_code="$(curl -sS -o "$TMP_DIR/approval-no-webauthn.json" -w "%{http_code}" "${ADMIN_HEADER[@]}" -X POST "$BASE/api/approvals/$approval_id/approve?ttl_seconds=30")"
if [[ "$approval_without_webauthn_code" != "412" ]]; then
  echo "expected approval without WebAuthn to fail with 412, got $approval_without_webauthn_code" >&2
  cat "$TMP_DIR/approval-no-webauthn.json" >&2
  exit 1
fi

curl -fsS "${ADMIN_HEADER[@]}" -X POST "$BASE/api/approvals/$approval_id/webauthn/options" > "$TMP_DIR/approval-webauthn-options.json"
challenge="$(python3 - "$TMP_DIR/approval-webauthn-options.json" <<'PY'
import json, sys
data = json.load(open(sys.argv[1]))
payload = data["serverware"]["payload"]
assert isinstance(payload["credential_version"], int) and payload["credential_version"] >= 1, data
assert payload["approval_expires_at"], data
assert payload["grant_ttl_seconds"] == 30, data
assert payload["grant_max_uses"] == 1, data
assert payload["consume_mode"] == "forwardStart", data
assert payload["redacted_display_digest"].startswith("sha256:"), data
print(data["publicKey"]["challenge"])
PY
)"
curl -fsS "${ADMIN_HEADER[@]}" -H "Content-Type: application/json" -X POST \
  --data "{\"challenge\":\"$challenge\"}" \
  "$BASE/api/dev/webauthn/assertion" > "$TMP_DIR/approval-webauthn-assertion.json"
python3 - "$TMP_DIR/approval-webauthn-assertion.json" "$TMP_DIR/approval-webauthn-approve.json" <<'PY'
import json, sys
assertion = json.load(open(sys.argv[1]))
json.dump({"assertion": assertion}, open(sys.argv[2], "w"))
PY
curl -fsS "${ADMIN_HEADER[@]}" -H "Content-Type: application/json" -X POST \
  --data @"$TMP_DIR/approval-webauthn-approve.json" \
  "$BASE/api/approvals/$approval_id/approve?ttl_seconds=30" > "$TMP_DIR/approval-approved.json"
python3 - "$TMP_DIR/approval-approved.json" <<'PY'
import json, sys
data = json.load(open(sys.argv[1]))
assert data["approved_by"] == "user:demo", data
assert data["approval_authn"]["method"] == "webauthn", data
assert data["approval_authn"]["authenticator_class"] == "dev", data
assert data["approval_challenge_id"], data
assert data["credential_id"] == "cred-demo-bearer", data
assert isinstance(data["credential_version"], int) and data["credential_version"] >= 1, data
assert data["canonical_request"]["credential_ref"] == "cred-demo-bearer", data
assert data["canonical_request"]["credential_version"] == str(data["credential_version"]), data
PY
repeat_approval_code="$(curl -sS -o "$TMP_DIR/approval-repeat-block.json" -w "%{http_code}" "${ADMIN_HEADER[@]}" -H "Content-Type: application/json" -X POST \
  --data @"$TMP_DIR/approval-webauthn-approve.json" \
  "$BASE/api/approvals/$approval_id/approve?ttl_seconds=30")"
if [[ "$repeat_approval_code" != "409" ]]; then
  echo "expected repeated approval to fail with 409, got $repeat_approval_code" >&2
  cat "$TMP_DIR/approval-repeat-block.json" >&2
  exit 1
fi
curl -fsS -X PUT --data "$npm_body" -H "Content-Type: application/json" --proxy "$PROXY" --cacert "$CA_FILE" "${AGENT_HEADER[@]}" \
  "$npm_url" > "$TMP_DIR/approval-pass.json"
python3 - "$TMP_DIR/approval-pass.json" <<'PY'
import hashlib, json, sys
data = json.load(open(sys.argv[1]))
assert data["authorization_present"] is True, data
assert data["authorization_scheme"] == "Bearer", data
assert data["authorization_sha256"] == "sha256:" + hashlib.sha256(b"Bearer demo-token-from-vault").hexdigest(), data
assert "authorization" not in data, data
assert data["published"] is True, data
PY

reuse_code="$(curl -sS -o "$TMP_DIR/approval-reuse-block.json" -w "%{http_code}" -X PUT --data "$npm_body" -H "Content-Type: application/json" --proxy "$PROXY" --cacert "$CA_FILE" "${AGENT_HEADER[@]}" \
  "$npm_url")"
if [[ "$reuse_code" != "428" ]]; then
  echo "expected consumed JIT grant to require a fresh approval, got $reuse_code" >&2
  cat "$TMP_DIR/approval-reuse-block.json" >&2
  exit 1
fi

curl -fsS "${ADMIN_HEADER[@]}" -H "Content-Type: application/json" -X PUT \
  --data '{"secret":"rotated-token-from-vault","metadata":{"x_app_id":"demo-x-app"}}' \
  "$BASE/api/credentials/cred-demo-bearer" > "$TMP_DIR/credential-rotated.json"
python3 - "$TMP_DIR/credential-rotated.json" "$TMP_DIR/credential-version-before-rotation.txt" <<'PY'
import json, sys
data = json.load(open(sys.argv[1]))
previous = int(open(sys.argv[2]).read())
assert data["credential_version"] > previous, data
assert data["metadata"]["x_app_id"] == "demo-x-app", data
PY

rotated_seen=0
for _ in $(seq 1 30); do
  curl -fsS --proxy "$PROXY" --cacert "$CA_FILE" "${AGENT_HEADER[@]}" \
    "https://demo-upstream:8443/echo" > "$TMP_DIR/echo-rotated.json"
  if python3 - "$TMP_DIR/echo-rotated.json" <<'PY'
import hashlib, json, sys
data = json.load(open(sys.argv[1]))
expected = "sha256:" + hashlib.sha256(b"Bearer rotated-token-from-vault").hexdigest()
raise SystemExit(0 if data.get("authorization_sha256") == expected and "authorization" not in data else 1)
PY
  then
    rotated_seen=1
    break
  fi
  sleep 0.2
done
if [[ "$rotated_seen" != "1" ]]; then
  echo "expected proxy subprocess to observe broker-published credential generation before lease TTL" >&2
  cat "$TMP_DIR/echo-rotated.json" >&2
  exit 1
fi

curl -fsS "${ADMIN_HEADER[@]}" "$BASE/api/runtime/metrics" > "$TMP_DIR/runtime-metrics.json"
python3 - "$TMP_DIR/runtime-metrics.json" <<'PY'
import json, sys
data = json.load(open(sys.argv[1]))
assert data["credential_generation_count"] >= 1, data
assert data["credential_generation_updates"] >= 1, data
PY

curl -fsS "${ADMIN_HEADER[@]}" "$BASE/api/audit/verify" > "$TMP_DIR/audit-verify.json"
python3 - "$TMP_DIR/audit-verify.json" <<'PY'
import json, sys
data = json.load(open(sys.argv[1]))
assert data["ok"] is True, data
assert data["count"] > 0, data
assert data["head"].startswith("sha256:"), data
PY
curl -fsS "${ADMIN_HEADER[@]}" "$BASE/api/audit?limit=250" > "$TMP_DIR/audit-events.json"
python3 - "$TMP_DIR/audit-events.json" <<'PY'
import json, sys
events = json.load(open(sys.argv[1]))
proxy_events = [item["event"] for item in events if item["event_type"] == "proxy.request_decision"]
grant_events = [item["event"] for item in events if item["event_type"] == "jit.grant.consumed"]
assert any(
    event.get("route_id") == "demo.npm.publish.jit"
    and event.get("credential_id") == "cred-demo-bearer"
    and isinstance(event.get("credential_version"), int)
    and event.get("request_digest", "").startswith("sha256:")
    and event.get("operation_digest", "").startswith("sha256:")
    for event in proxy_events
), proxy_events[:5]
assert any(
    event.get("route_id") == "demo.npm.publish.jit"
    and event.get("credential_id") == "cred-demo-bearer"
    and event.get("consume_result") == "consumed"
    and event.get("approval_request_id")
    and event.get("flow_id")
    for event in grant_events
), grant_events[:5]
PY

echo "serverware e2e passed"
