#!/usr/bin/env bash
set -euo pipefail

TMP_DIR="${TMP_DIR:-.tmp}"
mkdir -p "$TMP_DIR"
collector_key="$TMP_DIR/dev-proof-collector-key.pem"
collector_public_der="$TMP_DIR/dev-proof-collector-public.der"
rm -f \
  "$TMP_DIR/dev-proxy-response-proof.json" \
  "$TMP_DIR/dev-proxy-response-proof-summary.json" \
  "$collector_key" \
  "$collector_public_der"
openssl genpkey -algorithm ED25519 -out "$collector_key" >/dev/null 2>&1
chmod 0600 "$collector_key"
openssl pkey -in "$collector_key" -pubout -outform DER -out "$collector_public_der"

docker compose run --rm --no-deps \
  --user "$(id -u):$(id -g)" \
  -v "$PWD/$TMP_DIR:/proof" \
  --entrypoint /usr/local/bin/serverware-proof-client \
  decision-gate-rs \
  --proxy decision-gate-rs:9090 \
  --url https://demo-upstream:8443/echo \
  --ca /data/decision-gate-ca-cert.pem \
  --out /proof/dev-proxy-response-proof.json \
  --collector-key /proof/dev-proof-collector-key.pem \
  --proxy-header "X-Serverware-Agent: demo-agent" \
  --header "X-Serverware-Agent: demo-agent" \
  > "$TMP_DIR/dev-proxy-response-proof-summary.json"

python3 - \
  "$TMP_DIR/dev-proxy-response-proof.json" \
  "$TMP_DIR/dev-proxy-response-proof-summary.json" \
  "$collector_public_der" <<'PY'
import hashlib
import base64
import json
import sys
from cryptography.hazmat.primitives import serialization

proof_path, summary_path, collector_public_der_path = sys.argv[1:]
with open(proof_path, "rb") as handle:
    proof_bytes = handle.read()
proof = json.loads(proof_bytes)
with open(summary_path, "r", encoding="utf-8") as handle:
    summary = json.load(handle)
with open(collector_public_der_path, "rb") as handle:
    collector_public_der = handle.read()

assert summary["ok"] is True, summary
assert summary["response_status"] == 200, summary
assert summary["proof_sha256"] == "sha256:" + hashlib.sha256(proof_bytes).hexdigest(), summary
assert proof["apiVersion"] == "serverware.proxyResponseProof/v2", proof
assert proof["kind"] == "ServerwareProxyResponseProof", proof
capture = proof["external_capture"]
statement = proof["server_statement"]
assert capture["apiVersion"] == "serverware.proxyResponseCapture/v1", capture
assert capture["environment"] == "development", capture
assert capture["collection_mode"] == "external-client-capture", capture
for field in ("client_nonce", "client_request_digest", "request_digest", "operation_digest", "response", "tls_channel_binding"):
    assert capture[field] == statement[field], (field, capture[field], statement[field])
canonical_client_request = json.dumps(
    capture["client_request"], sort_keys=True, separators=(",", ":"), ensure_ascii=True
).encode()
assert capture["client_request"]["apiVersion"] == "serverware.clientProofRequest/v1", capture
assert capture["client_request_digest"] == "sha256:" + hashlib.sha256(canonical_client_request).hexdigest(), capture
assert summary["client_request_digest"] == capture["client_request_digest"], summary
assert "server_statement_sha256" not in proof, proof
collector_signature = proof["collector_signature"]
assert collector_signature["algorithm"] == "Ed25519", collector_signature
collector_key_id = "sha256:" + hashlib.sha256(collector_public_der).hexdigest()
assert collector_signature["key_id"] == collector_key_id, collector_signature
assert summary["collector_key_id"] == collector_key_id, summary
assert collector_signature["signature"].startswith("ed25519:"), collector_signature
canonical_capture = json.dumps(capture, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
collector_public_key = serialization.load_pem_public_key(collector_signature["public_key_pem"].encode("ascii"))
collector_public_key.verify(
    base64.urlsafe_b64decode(collector_signature["signature"].removeprefix("ed25519:") + "=="),
    canonical_capture,
)
server_signature = proof["server_signature"]
assert server_signature["algorithm"] == "Ed25519", proof
canonical_statement = json.dumps(statement, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
server_public_key = serialization.load_pem_public_key(server_signature["public_key_pem"].encode("ascii"))
server_public_der = server_public_key.public_bytes(
    serialization.Encoding.DER,
    serialization.PublicFormat.SubjectPublicKeyInfo,
)
assert server_signature["key_id"] == "sha256:" + hashlib.sha256(server_public_der).hexdigest(), server_signature
server_public_key.verify(
    base64.urlsafe_b64decode(server_signature["signature"].removeprefix("ed25519:") + "=="),
    canonical_statement,
)
assert proof["vendor_tee"]["platform"] == "none-dev", proof
assert proof["vendor_tee"]["provider"] == "development-fixture", proof
assert "body" not in capture["response"], capture
tls_peer = capture["tls_peer"]
assert tls_peer["spiffe_id"].startswith("spiffe://"), tls_peer
assert tls_peer["spiffe_id"] == statement["server_instance"]["id"], (tls_peer, statement)
assert tls_peer["spiffe_id"] == summary["server_instance_id"], (tls_peer, summary)
assert tls_peer["leaf_certificate_sha256"] == summary["tls_peer_leaf_certificate_sha256"], (tls_peer, summary)
selected_headers = capture["response"]["selected_headers"]
required_headers = {
    "content-length",
    "x-serverware-client-request-digest",
    "x-serverware-policy-hash",
    "x-serverware-request-digest",
    "x-serverware-operation-digest",
    "x-serverware-response-body-sha256",
}
assert required_headers <= set(selected_headers), selected_headers
assert set(selected_headers) <= required_headers | {"content-type"}, selected_headers
assert selected_headers["x-serverware-client-request-digest"] == capture["client_request_digest"], selected_headers
assert selected_headers["x-serverware-request-digest"] == capture["request_digest"], selected_headers
assert selected_headers["x-serverware-operation-digest"] == capture["operation_digest"], selected_headers
assert selected_headers["x-serverware-response-body-sha256"] == capture["response"]["body_digest"], selected_headers
claims = proof["vendor_tee"]["trusted_verifier"]["statement"]["attested_claims"]
expected_claims = {
    "server_statement_sha256": capture["server_statement_sha256"],
    "server_statement_api_version": statement["apiVersion"],
    "issued_at_unix": statement["issued_at_unix"],
    "client_nonce_sha256": "sha256:" + hashlib.sha256(base64.urlsafe_b64decode(capture["client_nonce"] + "==")).hexdigest(),
    "client_request_digest": statement["client_request_digest"],
    "request_digest": statement["request_digest"],
    "operation_digest": statement["operation_digest"],
    "response_status": statement["response"]["status"],
    "selected_response_headers_digest": statement["response"]["selected_headers_digest"],
    "response_body_digest": statement["response"]["body_digest"],
    "policy_digest": statement["policy_digest"],
    "runtime_manifest_digest": statement["runtime_manifest_digest"],
    "data_plane_binary_digest": statement["data_plane_binary_digest"],
    "release_digest": statement["release_digest"],
    "server_instance_id": statement["server_instance"]["id"],
    "server_instance_identity_digest": statement["server_instance"]["identity_digest"],
    "tls_channel_binding_type": statement["tls_channel_binding"]["type"],
    "tls_channel_binding_sha256": "sha256:" + hashlib.sha256(
        json.dumps(statement["tls_channel_binding"], sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    ).hexdigest(),
    "response_signing_key_id": server_signature["key_id"],
}
assert claims == expected_claims, (claims, expected_claims)
PY

nonce="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
status="$(curl -sS -o "$TMP_DIR/response-proof-unsafe.json" -w '%{http_code}' \
  --max-time 10 \
  --proxy http://localhost:9090 \
  --proxy-header "X-Serverware-Agent: demo-agent" \
  --cacert "$TMP_DIR/serverware-ca.pem" \
  -H "X-Serverware-Agent: demo-agent" \
  -H "X-Serverware-Proof-Nonce: $nonce" \
  -X POST \
  https://demo-upstream:8443/echo)"
python3 - "$status" "$TMP_DIR/response-proof-unsafe.json" <<'PY'
import json
import sys

status = int(sys.argv[1])
with open(sys.argv[2], "r", encoding="utf-8") as handle:
    payload = json.load(handle)
assert status == 400, (status, payload)
assert payload == {"error": "response_proof_requires_safe_method"}, payload
PY

printf '%s\n' '{"ok":true,"response_proof_capture":"pass"}'
