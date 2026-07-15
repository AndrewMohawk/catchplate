#!/usr/bin/env bash
set -euo pipefail

TMP_DIR="${TMP_DIR:-.tmp}"
mkdir -p "$TMP_DIR"
collector_key="$TMP_DIR/dev-proof-collector-key.pem"
collector_public_der="$TMP_DIR/dev-proof-collector-public.der"
stream_dir="$TMP_DIR/stream-proof"
stream_proof="$stream_dir/dev-streaming-proxy-response-proof.json"
stream_body="$stream_dir/dev-streaming-body.bin"
stream_summary="$TMP_DIR/dev-streaming-proof-summary.json"
mkdir -p "$stream_dir"
chmod 0700 "$stream_dir"
rm -f \
  "$TMP_DIR/dev-proxy-response-proof.json" \
  "$TMP_DIR/dev-proxy-response-proof-summary.json" \
  "$stream_proof" \
  "$stream_body" \
  "$stream_summary" \
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
  --expected-principal-id agent:demo \
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


def decode_base64url(value):
    assert isinstance(value, str) and "=" not in value, value
    decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    assert base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") == value, value
    return decoded


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
assert proof["apiVersion"] == "serverware.proxyResponseProof/v3", proof
assert proof["kind"] == "ServerwareProxyResponseProof", proof
capture = proof["external_capture"]
statement = proof["server_statement"]
assert capture["apiVersion"] == "serverware.proxyResponseCapture/v2", capture
assert capture["environment"] == "development", capture
assert capture["collection_mode"] == "external-client-capture", capture
for field in (
    "client_nonce",
    "client_request_digest",
    "principal_id",
    "route_id",
    "request_digest",
    "operation_digest",
    "release_authority",
    "control_plane_authorization_receipt",
    "upstream_response",
    "response",
    "tls_channel_binding",
):
    assert capture[field] == statement[field], (field, capture[field], statement[field])
assert statement["apiVersion"] == "serverware.proxyResponseStatement/v2", statement
release_authority = capture["release_authority"]
assert set(release_authority) == {
    "authority_mode",
    "grant_id",
    "approval_id",
    "credential_ref",
    "credential_version",
    "request_digest",
    "operation_digest",
    "attempt_id",
    "consumption_identity_digest",
    "authorization_state_at_upstream_dispatch",
    "authorization_state_observed_at_epoch_ms",
    "reservation_expires_at_epoch_ms",
    "dispatch_expires_at_epoch_ms",
}, release_authority
assert release_authority["authority_mode"] == "atomic", release_authority
assert (release_authority["grant_id"] is None) == (release_authority["approval_id"] is None), release_authority
assert (release_authority["credential_ref"] is None) == (release_authority["credential_version"] == 0), release_authority
assert release_authority["request_digest"] == capture["request_digest"], release_authority
assert release_authority["operation_digest"] == capture["operation_digest"], release_authority
assert release_authority["attempt_id"].startswith("sha256:") and len(release_authority["attempt_id"]) == 71, release_authority
assert release_authority["consumption_identity_digest"].startswith("sha256:") and len(release_authority["consumption_identity_digest"]) == 71, release_authority
assert release_authority["authorization_state_at_upstream_dispatch"] == "dispatching", release_authority
observed_at = release_authority["authorization_state_observed_at_epoch_ms"]
reservation_expires_at = release_authority["reservation_expires_at_epoch_ms"]
dispatch_expires_at = release_authority["dispatch_expires_at_epoch_ms"]
assert isinstance(observed_at, int) and 0 < observed_at <= statement["issued_at_unix"] * 1000 + 999, release_authority
assert isinstance(reservation_expires_at, int) and observed_at < reservation_expires_at, release_authority
assert isinstance(dispatch_expires_at, int) and observed_at < dispatch_expires_at, release_authority
assert "completion_outcome" not in release_authority, release_authority
assert summary["release_authority"] == release_authority, summary
receipt = capture["control_plane_authorization_receipt"]
assert set(receipt) == {
    "apiVersion",
    "kind",
    "principal_id",
    "route_id",
    "release_authority",
    "request",
    "response",
}, receipt
assert receipt["apiVersion"] == "serverware.controlPlaneAuthorizationReceipt/v1", receipt
assert receipt["kind"] == "ControlPlaneAuthorizationReceipt", receipt
assert receipt["principal_id"] == capture["principal_id"], receipt
assert receipt["route_id"] == capture["route_id"], receipt
assert receipt["release_authority"] == release_authority, receipt
receipt_request = receipt["request"]
assert set(receipt_request) == {"method", "path", "query", "nonce", "body_b64", "body_sha256"}, receipt_request
assert receipt_request["method"] == "POST", receipt_request
assert receipt_request["path"] == "/api/data-plane/release-authorizations/dispatch", receipt_request
assert receipt_request["query"] == "", receipt_request
assert len(decode_base64url(receipt_request["nonce"])) == 32, receipt_request
receipt_request_body = decode_base64url(receipt_request["body_b64"])
assert receipt_request["body_sha256"] == "sha256:" + hashlib.sha256(receipt_request_body).hexdigest(), receipt_request
assert receipt_request_body == json.dumps(
    json.loads(receipt_request_body), sort_keys=True, separators=(",", ":"), ensure_ascii=True
).encode(), receipt_request
dispatch_request = json.loads(receipt_request_body)
assert dispatch_request == {
    "apiVersion": "serverware.releaseAuthorizationDispatch/v1",
    "attemptId": release_authority["attempt_id"],
    "bindingDigest": release_authority["consumption_identity_digest"],
}, dispatch_request
receipt_response = receipt["response"]
assert set(receipt_response) == {
    "status",
    "body_b64",
    "body_sha256",
    "response_signing_key_id",
    "statement_b64",
    "statement_sha256",
    "signature",
}, receipt_response
assert receipt_response["status"] == 200, receipt_response
receipt_response_body = decode_base64url(receipt_response["body_b64"])
assert receipt_response["body_sha256"] == "sha256:" + hashlib.sha256(receipt_response_body).hexdigest(), receipt_response
dispatch_response = json.loads(receipt_response_body)
assert dispatch_response["apiVersion"] == "serverware.releaseAuthorization/v1", dispatch_response
assert dispatch_response["ok"] is True and dispatch_response["authorized"] is True, dispatch_response
assert dispatch_response["state"] == dispatch_response["reason"] == "dispatching", dispatch_response
assert dispatch_response["attemptId"] == release_authority["attempt_id"], dispatch_response
assert dispatch_response["bindingDigest"] == release_authority["consumption_identity_digest"], dispatch_response
assert dispatch_response["grantId"] == release_authority["grant_id"], dispatch_response
assert dispatch_response["approvalRequestId"] == release_authority["approval_id"], dispatch_response
assert dispatch_response["dispatchStartedAtEpochMs"] == observed_at, dispatch_response
assert dispatch_response["dispatchExpiresAtEpochMs"] == dispatch_expires_at, dispatch_response
assert dispatch_response["reservationExpiresAtEpochMs"] == reservation_expires_at, dispatch_response
assert dispatch_response["completionOutcome"] is None, dispatch_response
receipt_statement_bytes = decode_base64url(receipt_response["statement_b64"])
assert receipt_response["statement_sha256"] == "sha256:" + hashlib.sha256(receipt_statement_bytes).hexdigest(), receipt_response
assert receipt_statement_bytes == json.dumps(
    json.loads(receipt_statement_bytes), sort_keys=True, separators=(",", ":"), ensure_ascii=True
).encode(), receipt_response
receipt_statement = json.loads(receipt_statement_bytes)
assert receipt_statement["version"] == "serverware.responseSignature/v1", receipt_statement
assert receipt_statement["request"] == {
    "method": receipt_request["method"],
    "path": receipt_request["path"],
    "query": receipt_request["query"],
}, receipt_statement
assert receipt_statement["nonce"] == receipt_request["nonce"], receipt_statement
assert receipt_statement["status_code"] == receipt_response["status"], receipt_statement
assert receipt_statement["body_sha256"] == receipt_response["body_sha256"], receipt_statement
assert receipt_statement["response_signing_key_id"] == receipt_response["response_signing_key_id"], receipt_statement
assert observed_at <= receipt_statement["issued_at_ms"] < dispatch_expires_at, receipt_statement
assert receipt_statement["issued_at_ms"] < reservation_expires_at, receipt_statement
assert receipt_response["signature"].startswith("ed25519:"), receipt_response
assert len(decode_base64url(receipt_response["signature"].removeprefix("ed25519:"))) == 64, receipt_response
upstream_response = capture["upstream_response"]
assert set(upstream_response) == {
    "status",
    "selected_raw_policy_headers_b64",
    "body_digest",
    "canonical_digest",
}, upstream_response
assert upstream_response["status"] == capture["response"]["status"] == summary["response_status"], upstream_response
assert upstream_response["body_digest"].startswith("sha256:") and len(upstream_response["body_digest"]) == 71, upstream_response
raw_headers = upstream_response["selected_raw_policy_headers_b64"]
required_raw_headers = {"content-encoding", "content-length", "content-type"}
allowed_raw_headers = required_raw_headers | {
    "cache-control",
    "content-language",
    "etag",
    "last-modified",
    "retry-after",
    "www-authenticate",
}
assert required_raw_headers <= set(raw_headers) <= allowed_raw_headers, raw_headers
for name, values in raw_headers.items():
    assert isinstance(values, list) and len(values) <= 128, (name, values)
    for value in values:
        assert "=" not in value, (name, value)
        decoded = decode_base64url(value)
        assert len(decoded) <= 8192, (name, len(decoded))
canonical_upstream = {
    "status": upstream_response["status"],
    "selected_raw_policy_headers_b64": raw_headers,
    "body_digest": upstream_response["body_digest"],
}
assert upstream_response["canonical_digest"] == "sha256:" + hashlib.sha256(
    json.dumps(canonical_upstream, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
).hexdigest(), upstream_response
assert "client_request" not in capture, capture
canonical_client_request = json.dumps(
    {
        "apiVersion": "serverware.clientProofRequest/v1",
        "method": "GET",
        "scheme": "https",
        "authority": "demo-upstream:8443",
        "path": "/echo",
        "query": [],
        "headers": {},
        "body_sha256": "sha256:" + hashlib.sha256(b"").hexdigest(),
    },
    sort_keys=True,
    separators=(",", ":"),
    ensure_ascii=True,
).encode()
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
    "principal_id": statement["principal_id"],
    "route_id": statement["route_id"],
    "request_digest": statement["request_digest"],
    "operation_digest": statement["operation_digest"],
    "release_authority": statement["release_authority"],
    "control_plane_authorization_receipt_sha256": "sha256:" + hashlib.sha256(
        json.dumps(
            statement["control_plane_authorization_receipt"],
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode()
    ).hexdigest(),
    "upstream_response": statement["upstream_response"],
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

docker compose run --rm --no-deps \
  --user "$(id -u):$(id -g)" \
  -v "$PWD/$TMP_DIR:/proof" \
  --entrypoint /usr/local/bin/serverware-proof-client \
  decision-gate-rs \
  --stream \
  --proxy decision-gate-rs:9090 \
  --url 'https://demo-upstream:8443/stream-bytes?chunks=2&chunkSize=16' \
  --ca /data/decision-gate-ca-cert.pem \
  --out /proof/stream-proof/dev-streaming-proxy-response-proof.json \
  --body-out /proof/stream-proof/dev-streaming-body.bin \
  --collector-key /proof/dev-proof-collector-key.pem \
  --expected-principal-id agent:demo \
  --proxy-header "X-Serverware-Agent: demo-agent" \
  --header "X-Serverware-Agent: demo-agent" \
  --max-stream-bytes 1048576 \
  > "$stream_summary"

docker compose run --rm --no-deps -T \
  -v "$PWD/$TMP_DIR:/proof:ro" \
  -v "$PWD/schemas:/proof-schemas:ro" \
  --entrypoint python \
  serverware - \
  /proof/stream-proof/dev-streaming-proxy-response-proof.json \
  /proof-schemas/streaming-response-proof.v1.schema.json <<'PY'
import json
import sys

import jsonschema

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    proof = json.load(handle)
with open(sys.argv[2], "r", encoding="utf-8") as handle:
    schema = json.load(handle)
jsonschema.Draft202012Validator.check_schema(schema)
jsonschema.validate(proof, schema)
PY

python3 - "$stream_proof" "$stream_body" "$stream_summary" <<'PY'
import hashlib
import json
import sys

proof_path, body_path, summary_path = sys.argv[1:]
with open(proof_path, "rb") as handle:
    proof_bytes = handle.read()
proof = json.loads(proof_bytes)
with open(body_path, "rb") as handle:
    body = handle.read()
with open(summary_path, "r", encoding="utf-8") as handle:
    summary = json.load(handle)

assert summary["ok"] is True and summary["stream_verified"] is True, summary
assert summary["proof_sha256"] == "sha256:" + hashlib.sha256(proof_bytes).hexdigest(), summary
assert summary["body_bytes"] == len(body) == 32, summary
assert summary["body_sha256"] == "sha256:" + hashlib.sha256(body).hexdigest(), summary
assert proof["apiVersion"] == "serverware.streamingProxyResponseProof/v1", proof
assert proof["kind"] == "ServerwareStreamingProxyResponseProof", proof
capture = proof["external_capture"]
statement = proof["streaming_response_statement"]
assert capture["apiVersion"] == "serverware.streamingProxyResponseCapture/v1", capture
assert statement["apiVersion"] == "serverware.streamingResponseStatement/v1", statement
assert "client_request" not in capture, capture
assert "authorization_binding" not in capture, capture
binding_commitment = capture["authorization_binding_commitment"]
assert binding_commitment == statement["authorization_binding_validation"]["binding_commitment"], binding_commitment
assert "operation_context" not in binding_commitment, binding_commitment
assert binding_commitment["operation_context_digest"].startswith("sha256:"), binding_commitment
canonical_client_request = json.dumps(
    {
        "apiVersion": "serverware.streamingClientProofRequest/v1",
        "method": "GET",
        "scheme": "https",
        "authority": "demo-upstream:8443",
        "path": "/stream-bytes",
        "query": [["chunkSize", "16"], ["chunks", "2"]],
        "headers": {},
        "body_sha256": "sha256:" + hashlib.sha256(b"").hexdigest(),
    },
    sort_keys=True,
    separators=(",", ":"),
    ensure_ascii=True,
).encode()
assert capture["client_request_digest"] == "sha256:" + hashlib.sha256(canonical_client_request).hexdigest(), capture
for field in (
    "client_nonce",
    "client_request_digest",
    "principal_id",
    "route_id",
    "request_digest",
    "operation_digest",
    "release_authority",
    "control_plane_authorization_receipt",
    "control_plane_authorization_receipt_sha256",
    "upstream_response",
    "released_response",
    "tls_channel_binding",
):
    assert capture[field] == statement[field], (field, capture[field], statement[field])
authority = capture["release_authority"]
assert authority["authority_mode"] == "atomic", authority
assert authority["authorization_state_at_upstream_dispatch"] == "dispatching", authority
assert authority["credential_ref"] is None and authority["credential_version"] == 0, authority
assert authority["grant_id"] is None and authority["approval_id"] is None, authority
released = capture["released_response"]
assert released["completion"] == "normal-eof", released
assert released["framing"] == "http1.1-chunked-trailers", released
assert released["body_bytes"] == len(body), released
assert released["body_digest"] == summary["body_sha256"], released
assert released["trailer_names"] == [
    "X-Serverware-Stream-Proof-B64",
    "X-Serverware-Stream-Proof-SHA256",
], released
assert released["selected_wire_headers"] == {
    "connection": "close",
    "content-type": "application/octet-stream",
    "trailer": "X-Serverware-Stream-Proof-B64, X-Serverware-Stream-Proof-SHA256",
    "transfer-encoding": "chunked",
}, released
upstream = capture["upstream_response"]
assert upstream["body_bytes"] == len(body), upstream
assert upstream["body_digest"] == summary["body_sha256"], upstream
assert capture["tls_channel_binding"]["exporter_label"] == "EXPORTER-Serverware-Proxy-Stream-v1", capture
assert statement["server_instance"]["id"] == summary["server_instance_id"], statement
assert proof["vendor_tee"]["platform"] == "none-dev", proof
assert proof["vendor_tee"]["provider"] == "development-fixture", proof
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

printf '%s\n' '{"buffered_response_proof_capture":"pass","ok":true,"streaming_response_proof_capture":"pass"}'
