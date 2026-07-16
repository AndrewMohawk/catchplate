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
structured_stream_dir="$TMP_DIR/structured-stream-proofs"
mkdir -p "$stream_dir"
mkdir -p "$structured_stream_dir"
chmod 0700 "$stream_dir"
chmod 0700 "$structured_stream_dir"
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
assert receipt_statement["version"] == "serverware.responseSignature/v2", receipt_statement
assert receipt_statement["request"] == {
    "method": receipt_request["method"],
    "path": receipt_request["path"],
    "query_sha256": "sha256:" + hashlib.sha256(receipt_request["query"].encode()).hexdigest(),
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

structured_stream_modes=(jsonl json-array json-sse json-nested form csv)
for stream_mode in "${structured_stream_modes[@]}"; do
  mode_dir="$structured_stream_dir/$stream_mode"
  mkdir -p "$mode_dir"
  chmod 0700 "$mode_dir"
  rm -f "$mode_dir/proof.json" "$mode_dir/body.bin" "$mode_dir/summary.json"
  docker compose run --rm --no-deps \
    --user "$(id -u):$(id -g)" \
    -v "$PWD/$TMP_DIR:/proof" \
    --entrypoint /usr/local/bin/serverware-proof-client \
    decision-gate-rs \
    --stream \
    --proxy decision-gate-rs:9090 \
    --url "https://demo-upstream:8443/proof-stream/$stream_mode" \
    --ca /data/decision-gate-ca-cert.pem \
    --out "/proof/structured-stream-proofs/$stream_mode/proof.json" \
    --body-out "/proof/structured-stream-proofs/$stream_mode/body.bin" \
    --collector-key /proof/dev-proof-collector-key.pem \
    --expected-principal-id agent:demo \
    --proxy-header "X-Serverware-Agent: demo-agent" \
    --header "X-Serverware-Agent: demo-agent" \
    --max-stream-bytes 1048576 \
    > "$mode_dir/summary.json"
done

docker compose run --rm --no-deps -T \
  -v "$PWD/$structured_stream_dir:/proof:ro" \
  -v "$PWD/schemas:/proof-schemas:ro" \
  --entrypoint python \
  serverware - \
  /proof \
  /proof-schemas/streaming-response-proof.v1.schema.json <<'PY'
import json
import pathlib
import sys

import jsonschema

proof_root = pathlib.Path(sys.argv[1])
with open(sys.argv[2], "r", encoding="utf-8") as handle:
    schema = json.load(handle)
jsonschema.Draft202012Validator.check_schema(schema)
proof_paths = sorted(proof_root.glob("*/proof.json"))
assert len(proof_paths) == 6, proof_paths
for proof_path in proof_paths:
    with proof_path.open("r", encoding="utf-8") as handle:
        jsonschema.validate(json.load(handle), schema)
PY

python3 - "$structured_stream_dir" <<'PY'
import csv
import hashlib
import io
import json
import pathlib
import sys
from urllib.parse import parse_qs


root = pathlib.Path(sys.argv[1])
expected = {
    "jsonl": ("demo.proof.stream.jsonl", "application/x-ndjson"),
    "json-array": ("demo.proof.stream.json-array", "application/json"),
    "json-sse": ("demo.proof.stream.json-sse", "text/event-stream"),
    "json-nested": ("demo.proof.stream.json-nested", "application/json"),
    "form": ("demo.proof.stream.form", "application/x-www-form-urlencoded"),
    "csv": ("demo.proof.stream.csv", "text/csv"),
}
expected_items = [
    {"index": 0, "kept": "alpha", "nested": {"safe": "one"}, "sawSecret": True},
    {"index": 1, "kept": "beta", "nested": {"safe": "two"}, "sawSecret": True},
]
expected_raw = {
    "jsonl": (
        b'{"index":0,"kept":"alpha","nested":{"safe":"one","secret":"hidden"},"sawSecret":true,"upstreamSecret":"hidden"}\n'
        b'{"index":1,"kept":"beta","nested":{"safe":"two","secret":"hidden"},"sawSecret":true,"upstreamSecret":"hidden"}\n'
    ),
    "json-array": (
        b'[{"index":0,"kept":"alpha","nested":{"safe":"one","secret":"hidden"},"sawSecret":true,"upstreamSecret":"hidden"},'
        b'{"index":1,"kept":"beta","nested":{"safe":"two","secret":"hidden"},"sawSecret":true,"upstreamSecret":"hidden"}]'
    ),
    "json-sse": (
        b'event: hidden\nid: hidden-0\ndata: {"index":0,"kept":"alpha","nested":{"safe":"one","secret":"hidden"},"sawSecret":true,"upstreamSecret":"hidden"}\n\n'
        b'event: hidden\nid: hidden-1\ndata: {"index":1,"kept":"beta","nested":{"safe":"two","secret":"hidden"},"sawSecret":true,"upstreamSecret":"hidden"}\n\n'
        b"data: [DONE]\n\n"
    ),
    "json-nested": (
        b'{"requestId":"proof-request","profile":{"email":"operator@example.test","settings":{"theme":"dark","token":"hidden"},"secret":"hidden"},'
        b'"items":[{"id":"one","details":{"safe":"kept","secret":"hidden"},"secret":"hidden"}],'
        b'"audit":{"trace":"proof-trace","privateToken":"hidden"},"sawSecret":true,"upstreamSecret":"hidden"}'
    ),
    "form": b"kept=alpha&safe=one&sawSecret=true&hidden=hidden&upstreamSecret=hidden",
    "csv": (
        b"id,public,safe_note,sawSecret,hidden,upstreamSecret\n"
        b"one,alpha,kept,true,hidden,hidden\n"
        b"two,beta,kept-too,true,hidden,hidden\n"
    ),
}


def assert_no_forbidden_keys(value):
    if isinstance(value, dict):
        forbidden = {
            "secret",
            "token",
            "privatetoken",
            "upstreamsecret",
            "echoedsecret",
            "authorization_sha256",
        }
        assert not (forbidden & {str(key).lower() for key in value}), value
        for item in value.values():
            assert_no_forbidden_keys(item)
    elif isinstance(value, list):
        for item in value:
            assert_no_forbidden_keys(item)


for mode, (route_id, content_type) in expected.items():
    mode_dir = root / mode
    proof_bytes = (mode_dir / "proof.json").read_bytes()
    body = (mode_dir / "body.bin").read_bytes()
    summary = json.loads((mode_dir / "summary.json").read_text(encoding="utf-8"))
    proof = json.loads(proof_bytes)
    capture = proof["external_capture"]
    statement = proof["streaming_response_statement"]
    upstream = capture["upstream_response"]
    released = capture["released_response"]
    assert summary["ok"] is True and summary["stream_verified"] is True, summary
    assert summary["proof_sha256"] == "sha256:" + hashlib.sha256(proof_bytes).hexdigest(), summary
    assert summary["body_sha256"] == "sha256:" + hashlib.sha256(body).hexdigest(), summary
    assert summary["body_bytes"] == len(body) > 0, summary
    assert proof["apiVersion"] == "serverware.streamingProxyResponseProof/v1", proof
    assert proof["kind"] == "ServerwareStreamingProxyResponseProof", proof
    assert proof["vendor_tee"]["platform"] == "none-dev", proof
    assert proof["vendor_tee"]["provider"] == "development-fixture", proof
    assert capture["principal_id"] == statement["principal_id"] == "agent:demo", (mode, capture)
    assert capture["route_id"] == statement["route_id"] == route_id, (mode, capture)
    assert capture["client_request_digest"] == statement["client_request_digest"], mode
    assert capture["released_response"] == statement["released_response"], mode
    assert capture["upstream_response"] == statement["upstream_response"], mode
    raw_body = expected_raw[mode]
    assert upstream["body_bytes"] == len(raw_body), (mode, upstream)
    assert upstream["body_digest"] == "sha256:" + hashlib.sha256(raw_body).hexdigest(), (mode, upstream)
    assert upstream["body_digest"] != released["body_digest"], (mode, upstream, released)
    assert released["completion"] == "normal-eof", (mode, released)
    assert released["framing"] == "http1.1-chunked-trailers", (mode, released)
    assert released["body_bytes"] == len(body), (mode, released)
    assert released["body_digest"] == summary["body_sha256"], (mode, released)
    assert released["trailer_names"] == [
        "X-Serverware-Stream-Proof-B64",
        "X-Serverware-Stream-Proof-SHA256",
    ], (mode, released)
    released_content_type = released["selected_wire_headers"]["content-type"]
    assert released_content_type.split(";", 1)[0].strip().lower() == content_type, (mode, released)
    assert capture["release_authority"]["credential_ref"] is None, (mode, capture)
    assert capture["release_authority"]["credential_version"] == 0, (mode, capture)
    assert capture["tls_channel_binding"]["exporter_label"] == "EXPORTER-Serverware-Proxy-Stream-v1", capture
    assert b"hidden" not in body, (mode, body)

    if mode == "jsonl":
        value = [json.loads(line) for line in body.splitlines() if line]
        assert value == expected_items, value
    elif mode == "json-array":
        value = json.loads(body)
        assert value == expected_items, value
    elif mode == "json-sse":
        data = []
        for line in body.decode("utf-8").splitlines():
            if line.startswith("data: ") and line != "data: [DONE]":
                data.append(json.loads(line[6:]))
        value = data
        assert value == expected_items, (body, value)
        assert body.rstrip().endswith(b"data: [DONE]"), body
    elif mode == "json-nested":
        value = json.loads(body)
        assert value == {
            "audit": {"trace": "proof-trace"},
            "items": [{"details": {"safe": "kept"}, "id": "one"}],
            "profile": {
                "email": "operator@example.test",
                "settings": {"theme": "dark"},
            },
            "requestId": "proof-request",
            "sawSecret": True,
        }, value
    elif mode == "form":
        value = parse_qs(body.decode("utf-8"), keep_blank_values=True)
        assert value == {"kept": ["alpha"], "safe": ["one"], "sawSecret": ["true"]}, value
    else:
        value = list(csv.DictReader(io.StringIO(body.decode("utf-8"))))
        assert value == [
            {"id": "one", "public": "alpha", "safe_note": "kept", "sawSecret": "true"},
            {"id": "two", "public": "beta", "safe_note": "kept-too", "sawSecret": "true"},
        ], value
    assert_no_forbidden_keys(value)
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

printf '%s\n' '{"buffered_response_proof_capture":"pass","ok":true,"streaming_response_proof_capture":"pass","structured_streaming_connect_proofs":6}'
