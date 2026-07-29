#!/usr/bin/env bash
set -euo pipefail

tmp_root="$(python3 - "${TMP_DIR:-.tmp}" <<'PY'
import pathlib
import sys

print(pathlib.Path(sys.argv[1]).resolve())
PY
)"
observation_container_suffix="$$-$(openssl rand -hex 6)"
TMP_DIR="$tmp_root/response-proof-capture-$observation_container_suffix"
gate_proxy_url="${SERVERWARE_RESPONSE_PROOF_PROXY_URL:-http://localhost:9090}"
mkdir -p "$TMP_DIR"
verified_ca_source="${SERVERWARE_CA_FILE:-$tmp_root/serverware-ca.pem}"
if [[ ! -f "$verified_ca_source" ]]; then
  echo "verified Serverware CA is missing at $verified_ca_source" >&2
  exit 1
fi
cp "$verified_ca_source" "$TMP_DIR/serverware-ca.pem"
chmod 0600 "$TMP_DIR/serverware-ca.pem"
collector_key="$TMP_DIR/dev-proof-collector-key.pem"
collector_public_der="$TMP_DIR/dev-proof-collector-public.der"
stream_dir="$TMP_DIR/stream-proof"
stream_proof="$stream_dir/dev-streaming-proxy-response-proof.json"
stream_body="$stream_dir/dev-streaming-body.bin"
stream_summary="$TMP_DIR/dev-streaming-proof-summary.json"
structured_stream_dir="$TMP_DIR/structured-stream-proofs"
observation_dir="$TMP_DIR/response-observation-proofs"
observation_post_dir="$observation_dir/post-success"
observation_deny_dir="$observation_dir/local-denial"
observation_upstream_error_dir="$observation_dir/upstream-error"
observation_validation_dir="$observation_dir/validation-block"
observation_limit_dir="$observation_dir/body-limit-retry"
observation_outage_dir="$observation_dir/attestation-outage"
observation_replay_first_dir="$observation_dir/replay-first"
observation_replay_second_dir="$observation_dir/replay-second"
observation_generic_dir="$observation_dir/generic-unverified"
mkdir -p "$stream_dir"
mkdir -p "$structured_stream_dir"
mkdir -p \
  "$observation_post_dir" \
  "$observation_deny_dir" \
  "$observation_upstream_error_dir" \
  "$observation_validation_dir" \
  "$observation_limit_dir" \
  "$observation_outage_dir" \
  "$observation_replay_first_dir" \
  "$observation_replay_second_dir" \
  "$observation_generic_dir"
chmod 0700 "$stream_dir"
chmod 0700 "$structured_stream_dir"
chmod 0700 "$observation_dir" "$observation_dir"/*
rm -f \
  "$TMP_DIR/dev-proxy-response-proof.json" \
  "$TMP_DIR/dev-proxy-response-proof-summary.json" \
  "$stream_proof" \
  "$stream_body" \
  "$stream_summary" \
  "$collector_key" \
  "$collector_public_der"
observation_outage_gate="serverware-observation-outage-$observation_container_suffix"
observation_custody="serverware-observation-custody-$observation_container_suffix"
observation_custody_gate="serverware-observation-custody-gate-$observation_container_suffix"
observation_custody_socket_volume="serverware-observation-socket-$observation_container_suffix"
observation_custody_state_volume="serverware-observation-state-$observation_container_suffix"
observation_containers=()
observation_volumes=()

cleanup_observation_containers() {
  if [[ "${#observation_containers[@]}" -gt 0 ]]; then
    docker rm -f "${observation_containers[@]}" >/dev/null 2>&1 || true
  fi
  if [[ "${#observation_volumes[@]}" -gt 0 ]]; then
    docker volume rm -f "${observation_volumes[@]}" >/dev/null 2>&1 || true
  fi
  chmod -R u+rwX "$TMP_DIR" >/dev/null 2>&1 || true
  rm -rf "$TMP_DIR"
}

trap cleanup_observation_containers EXIT

wait_for_observation_gate() {
  local container_name="$1"
  for _ in $(seq 1 100); do
    if docker inspect --format '{{.State.Running}}' "$container_name" 2>/dev/null | grep -qx true \
      && docker compose exec -T serverware python - "$container_name" <<'PY' >/dev/null 2>&1
import socket
import sys

with socket.create_connection((sys.argv[1], 9090), timeout=0.25):
    pass
PY
    then
      return 0
    fi
    sleep 0.1
  done
  docker logs "$container_name" >&2 || true
  echo "observation gate $container_name did not become ready" >&2
  return 1
}

demo_request_count() {
  local method="$1"
  local path="$2"
  local run_id="${3:-}"
  docker compose exec -T demo-upstream python - "$method" "$path" "$run_id" <<'PY'
import json
import ssl
import sys
import urllib.parse
import urllib.request

parameters = {"method": sys.argv[1], "path": sys.argv[2]}
if sys.argv[3]:
    parameters["run_id"] = sys.argv[3]
query = urllib.parse.urlencode(parameters)
with urllib.request.urlopen(
    "https://127.0.0.1:8443/_test/request-count?" + query,
    context=ssl._create_unverified_context(),
    timeout=5,
) as response:
    print(json.load(response)["count"])
PY
}

new_observation_nonce() {
  docker compose exec -T serverware python - <<'PY'
import base64
import os
import struct
import time

nonce = struct.pack(">I", int(time.time()) + 300) + os.urandom(28)
print(base64.urlsafe_b64encode(nonce).rstrip(b"=").decode("ascii"))
PY
}

openssl genpkey -algorithm ED25519 -out "$collector_key" >/dev/null 2>&1
chmod 0600 "$collector_key"
openssl pkey -in "$collector_key" -pubout -outform DER -out "$collector_public_der"

docker compose run --rm --no-deps \
  --user "$(id -u):$(id -g)" \
  -v "$TMP_DIR:/proof" \
  --entrypoint /usr/local/bin/serverware-proof-client \
  decision-gate-rs \
  --proxy decision-gate-rs:9090 \
  --url https://demo-upstream:8443/echo \
  --ca /proof/serverware-ca.pem \
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
    "response_headers",
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
assert receipt_statement["version"] == "serverware.responseSignature/v3", receipt_statement
assert receipt_statement["request"] == {
    "method": receipt_request["method"],
    "path": receipt_request["path"],
    "query_sha256": "sha256:" + hashlib.sha256(receipt_request["query"].encode()).hexdigest(),
}, receipt_statement
assert receipt_statement["nonce"] == receipt_request["nonce"], receipt_statement
assert receipt_statement["status_code"] == receipt_response["status"], receipt_statement
assert receipt_statement["body_sha256"] == receipt_response["body_sha256"], receipt_statement
receipt_response_headers = receipt_response["response_headers"]
receipt_response_headers_bytes = json.dumps(
    receipt_response_headers, sort_keys=True, separators=(",", ":"), ensure_ascii=True
).encode()
assert receipt_statement["response_headers_sha256"] == (
    "sha256:" + hashlib.sha256(receipt_response_headers_bytes).hexdigest()
), receipt_statement
assert receipt_statement["response_header_count"] == len(receipt_response_headers), receipt_statement
assert all(
    item["name"] == item["name"].lower()
    and not item["name"].startswith("x-serverware-response-")
    for item in receipt_response_headers
), receipt_response_headers
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
  -v "$TMP_DIR:/proof" \
  --entrypoint /usr/local/bin/serverware-proof-client \
  decision-gate-rs \
  --stream \
  --proxy decision-gate-rs:9090 \
  --url 'https://demo-upstream:8443/stream-bytes?chunks=2&chunkSize=16' \
  --ca /proof/serverware-ca.pem \
  --out /proof/stream-proof/dev-streaming-proxy-response-proof.json \
  --body-out /proof/stream-proof/dev-streaming-body.bin \
  --collector-key /proof/dev-proof-collector-key.pem \
  --expected-principal-id agent:demo \
  --proxy-header "X-Serverware-Agent: demo-agent" \
  --header "X-Serverware-Agent: demo-agent" \
  --max-stream-bytes 1048576 \
  > "$stream_summary"

docker compose run --rm --no-deps -T \
  --user "$(id -u):$(id -g)" \
  -v "$TMP_DIR:/proof:ro" \
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
    -v "$TMP_DIR:/proof" \
    --entrypoint /usr/local/bin/serverware-proof-client \
    decision-gate-rs \
    --stream \
    --proxy decision-gate-rs:9090 \
    --url "https://demo-upstream:8443/proof-stream/$stream_mode" \
    --ca /proof/serverware-ca.pem \
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
  --user "$(id -u):$(id -g)" \
  -v "$structured_stream_dir:/proof:ro" \
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

printf '%s' '{"audit_marker":"serverware-observation-post"}' > "$observation_post_dir/request.bin"
chmod 0600 "$observation_post_dir/request.bin"

docker compose run --rm --no-deps \
  --user "$(id -u):$(id -g)" \
  -v "$TMP_DIR:/proof" \
  --entrypoint /usr/local/bin/serverware-proof-client \
  decision-gate-rs \
  --observation \
  --method POST \
  --proxy decision-gate-rs:9090 \
  --url https://demo-upstream:8443/echo \
  --ca /proof/serverware-ca.pem \
  --out /proof/response-observation-proofs/post-success/proof.json \
  --body-out /proof/response-observation-proofs/post-success/body.bin \
  --request-body /proof/response-observation-proofs/post-success/request.bin \
  --collector-key /proof/dev-proof-collector-key.pem \
  --expected-principal-id agent:demo \
  --proxy-header "X-Serverware-Agent: demo-agent" \
  --header "X-Serverware-Agent: demo-agent" \
  --header "Content-Type: application/json" \
  > "$observation_post_dir/summary.json"

denied_run_id="denied-$observation_container_suffix"
denied_count_before="$(demo_request_count DELETE /echo "$denied_run_id")"
docker compose run --rm --no-deps \
  --user "$(id -u):$(id -g)" \
  -v "$TMP_DIR:/proof" \
  --entrypoint /usr/local/bin/serverware-proof-client \
  decision-gate-rs \
  --observation \
  --method DELETE \
  --proxy decision-gate-rs:9090 \
  --url https://demo-upstream:8443/echo \
  --ca /proof/serverware-ca.pem \
  --out /proof/response-observation-proofs/local-denial/proof.json \
  --body-out /proof/response-observation-proofs/local-denial/body.bin \
  --collector-key /proof/dev-proof-collector-key.pem \
  --expected-principal-id agent:demo \
  --proxy-header "X-Serverware-Agent: demo-agent" \
  --header "X-Serverware-Agent: demo-agent" \
  --header "User-Agent: serverware-test-run/$denied_run_id" \
  > "$observation_deny_dir/summary.json"
denied_count_after="$(demo_request_count DELETE /echo "$denied_run_id")"

docker compose run --rm --no-deps \
  --user "$(id -u):$(id -g)" \
  -v "$TMP_DIR:/proof" \
  --entrypoint /usr/local/bin/serverware-proof-client \
  decision-gate-rs \
  --observation \
  --proxy decision-gate-rs:9090 \
  --url 'https://demo-upstream:8443/echo?reflectCredential=1' \
  --ca /proof/serverware-ca.pem \
  --out /proof/response-observation-proofs/validation-block/proof.json \
  --body-out /proof/response-observation-proofs/validation-block/body.bin \
  --collector-key /proof/dev-proof-collector-key.pem \
  --expected-principal-id agent:demo \
  --proxy-header "X-Serverware-Agent: demo-agent" \
  --header "X-Serverware-Agent: demo-agent" \
  > "$observation_validation_dir/summary.json"

docker compose run --rm --no-deps \
  --user "$(id -u):$(id -g)" \
  -v "$TMP_DIR:/proof" \
  --entrypoint /usr/local/bin/serverware-proof-client \
  decision-gate-rs \
  --observation \
  --proxy decision-gate-rs:9090 \
  --url https://demo-upstream:8443/2/tweets/search/recent \
  --ca /proof/serverware-ca.pem \
  --out /proof/response-observation-proofs/upstream-error/proof.json \
  --body-out /proof/response-observation-proofs/upstream-error/body.bin \
  --collector-key /proof/dev-proof-collector-key.pem \
  --expected-principal-id agent:demo \
  --proxy-header "X-Serverware-Agent: demo-agent" \
  --header "X-Serverware-Agent: demo-agent" \
  > "$observation_upstream_error_dir/summary.json"

if docker compose run --rm --no-deps \
  --user "$(id -u):$(id -g)" \
  -v "$TMP_DIR:/proof" \
  --entrypoint /usr/local/bin/serverware-proof-client \
  decision-gate-rs \
  --observation \
  --proxy decision-gate-rs:9090 \
  --url https://demo-upstream:8443/echo \
  --ca /proof/serverware-ca.pem \
  --out /proof/response-observation-proofs/body-limit-retry/proof.json \
  --body-out /proof/response-observation-proofs/body-limit-retry/body.bin \
  --max-observation-body-bytes 1 \
  --collector-key /proof/dev-proof-collector-key.pem \
  --expected-principal-id agent:demo \
  --proxy-header "X-Serverware-Agent: demo-agent" \
  --header "X-Serverware-Agent: demo-agent" \
  > "$observation_limit_dir/failed.stdout.json" \
  2> "$observation_limit_dir/failed.stderr.json"; then
  echo "observation collector unexpectedly accepted a body above its configured limit" >&2
  exit 1
fi
python3 - "$observation_limit_dir" <<'PY'
import json
import pathlib
import re
import sys

directory = pathlib.Path(sys.argv[1])
assert not (directory / "proof.json").exists(), list(directory.iterdir())
assert not (directory / "body.bin").exists(), list(directory.iterdir())
stderr_lines = [
    line for line in (directory / "failed.stderr.json").read_text(encoding="utf-8").splitlines()
    if line.strip()
]
assert stderr_lines, stderr_lines
assert all(
    re.fullmatch(r"Container [A-Za-z0-9_.-]+ (Creating|Created)", line.strip())
    for line in stderr_lines[:-1]
), stderr_lines
error = json.loads(stderr_lines[-1])
assert error == {
    "ok": False,
    "error": "observation decoded body exceeds --max-observation-body-bytes 1",
}, error
PY
docker compose run --rm --no-deps \
  --user "$(id -u):$(id -g)" \
  -v "$TMP_DIR:/proof" \
  --entrypoint /usr/local/bin/serverware-proof-client \
  decision-gate-rs \
  --observation \
  --proxy decision-gate-rs:9090 \
  --url https://demo-upstream:8443/echo \
  --ca /proof/serverware-ca.pem \
  --out /proof/response-observation-proofs/body-limit-retry/proof.json \
  --body-out /proof/response-observation-proofs/body-limit-retry/body.bin \
  --max-observation-body-bytes 16777216 \
  --collector-key /proof/dev-proof-collector-key.pem \
  --expected-principal-id agent:demo \
  --proxy-header "X-Serverware-Agent: demo-agent" \
  --header "X-Serverware-Agent: demo-agent" \
  > "$observation_limit_dir/summary.json"

docker compose run --rm --no-deps -T \
  --user "$(id -u):$(id -g)" \
  -v "$observation_dir:/proof:ro" \
  -v "$PWD/schemas:/proof-schemas:ro" \
  --entrypoint python \
  serverware - \
  /proof \
  /proof-schemas/response-observation-proof.v1.schema.json <<'PY'
import json
import pathlib
import re
import sys

import jsonschema

root = pathlib.Path(sys.argv[1])
with open(sys.argv[2], "r", encoding="utf-8") as handle:
    schema = json.load(handle)
jsonschema.Draft202012Validator.check_schema(schema)
proofs = sorted(root.glob("*/proof.json"))
assert len(proofs) == 5, proofs
for proof_path in proofs:
    with proof_path.open("r", encoding="utf-8") as handle:
        jsonschema.validate(json.load(handle), schema)
PY

python3 - \
  "$observation_post_dir" \
  "$observation_deny_dir" \
  "$observation_upstream_error_dir" \
  "$observation_validation_dir" \
  "$denied_count_before" \
  "$denied_count_after" <<'PY'
import hashlib
import json
import pathlib
import sys


def load_case(path_text):
    path = pathlib.Path(path_text)
    proof_bytes = (path / "proof.json").read_bytes()
    body = (path / "body.bin").read_bytes()
    summary = json.loads((path / "summary.json").read_text(encoding="utf-8"))
    proof = json.loads(proof_bytes)
    statement = proof["runtime_proof"]["server_statement"]
    assert summary["ok"] is True and summary["observation_verified"] is True, summary
    assert summary["proof_sha256"] == "sha256:" + hashlib.sha256(proof_bytes).hexdigest(), summary
    assert summary["body_sha256"] == "sha256:" + hashlib.sha256(body).hexdigest(), summary
    assert summary["body_bytes"] == len(body), summary
    assert proof["apiVersion"] == "serverware.responseObservationProof/v1", proof
    assert proof["kind"] == "ServerwareResponseObservationProof", proof
    assert proof["runtime_proof"]["apiVersion"] == "serverware.responseObservationRuntimeProof/v1", proof
    assert proof["runtime_proof"]["kind"] == "ServerwareResponseObservationRuntimeProof", proof
    assert proof["runtime_proof"]["vendor_tee"]["provider"] == "development-fixture", proof
    assert statement["request"]["body_observation"] == "complete-buffered", statement
    assert statement["request"]["aggregate_digest"] == summary["request_aggregate_digest"], summary
    assert statement["emitted_response"] == proof["response"], proof
    assert proof["response"]["body_digest"] == summary["body_sha256"], proof
    assert proof["response"]["body_bytes"] == len(body), proof
    assert statement["observation_authority"] == {
        "source": "gate-authored",
        "upstream_truth": "not-independently-observed",
        "downstream_delivery": "not-claimed",
    }, statement
    assert proof["collector"]["algorithm"] == "Ed25519", proof
    return proof, statement, body


post_proof, post, post_body = load_case(sys.argv[1])
request_body = (pathlib.Path(sys.argv[1]) / "request.bin").read_bytes()
assert post["request"]["method"] == "POST", post
assert post["request"]["body_digest"] == "sha256:" + hashlib.sha256(request_body).hexdigest(), post
assert post["request"]["body_bytes"] == len(request_body), post
assert post["policy"]["decision_state"] == "allowed", post
assert post["principal_id"] == "agent:demo" and post["route_id"] == "demo.echo", post
assert post["credential"]["state"] == "injected", post
assert post["credential"]["binding_digest"].startswith("sha256:"), post
assert post["authorization"]["state"] == "completed-forwarded", post
assert post["authorization"]["binding_digest"].startswith("sha256:"), post
assert post["authorization"]["release_authority"]["credential_ref"] == "cred-demo-bearer", post
assert post["authorization"]["control_plane_authorization_receipt"] is not None, post
assert post["authorization"]["control_plane_authorization_receipt_sha256"].startswith("sha256:"), post
assert post["response_path"] == "complete-upstream-response-released", post
assert post["upstream_attempt"] == "complete", post
assert post["upstream_observation"]["status"] == 200, post
assert post["upstream_observation"]["body_state"] == "complete", post
post_payload = json.loads(post_body)
assert post_payload["method"] == "POST" and post_payload["path"] == "/echo", post_payload
assert post_payload["authorization_present"] is True, post_payload
assert post_payload["authorization_scheme"] == "Bearer", post_payload
assert post_payload["credential_marker"] in {"initial", "rotated"}, post_payload

_, denied, denied_body = load_case(sys.argv[2])
assert denied["policy"]["decision_state"] == "denied", denied
assert denied["response_path"] == "local-reject-no-upstream-attempt", denied
assert denied["upstream_attempt"] == "not-started", denied
assert denied["upstream_observation"] is None, denied
assert denied["credential"] == {"state": "not-evaluated", "binding_digest": None}, denied
assert denied["authorization"]["state"] == "denied", denied
denied_payload = json.loads(denied_body)
assert denied_payload["action"] == "deny" and denied_payload["allowed"] is False, denied_payload
assert denied_payload["status_code"] == 403, denied_payload
assert denied_payload["payload"] == {"error": "unknown_route_denied"}, denied_payload
assert int(sys.argv[5]) == int(sys.argv[6]), (
    "locally denied observation reached the upstream",
    sys.argv[5],
    sys.argv[6],
)

_, upstream_error, upstream_error_body = load_case(sys.argv[3])
assert upstream_error["policy"]["decision_state"] == "allowed", upstream_error
assert upstream_error["route_id"] == "demo.x.search.recent", upstream_error
assert upstream_error["response_path"] == "post-dispatch-local-failure", upstream_error
assert upstream_error["upstream_attempt"] == "headers-observed-body-incomplete", upstream_error
assert upstream_error["upstream_observation"]["status"] == 404, upstream_error
assert upstream_error["upstream_observation"]["body_state"] == "unread", upstream_error
assert upstream_error["upstream_observation"]["body_bytes"] is None, upstream_error
assert upstream_error["upstream_observation"]["body_digest"] is None, upstream_error
assert json.loads(upstream_error_body)["error"] == "response_error_policy_missing", upstream_error_body

_, validation, validation_body = load_case(sys.argv[4])
assert validation["policy"]["decision_state"] == "allowed", validation
assert validation["route_id"] == "demo.echo", validation
assert validation["response_path"] == "complete-upstream-response-blocked", validation
assert validation["upstream_attempt"] == "complete", validation
assert validation["upstream_observation"]["status"] == 200, validation
assert validation["upstream_observation"]["body_state"] == "complete", validation
assert validation["upstream_observation"]["body_bytes"] > 0, validation
assert validation["upstream_observation"]["body_digest"].startswith("sha256:"), validation
assert validation["upstream_observation"]["body_digest"] != validation["emitted_response"]["body_digest"], validation
assert json.loads(validation_body) == {"error": "response_credential_reflection"}, validation_body
PY

generic_nonce="$(new_observation_nonce)"
curl -sS --http1.1 --raw --noproxy '' \
  --max-time 10 \
  --proxy "$gate_proxy_url" \
  --proxy-header "X-Serverware-Agent: demo-agent" \
  --cacert "$TMP_DIR/serverware-ca.pem" \
  -H "X-Serverware-Agent: demo-agent" \
  -H "X-Serverware-Observation-Nonce: $generic_nonce" \
  -D "$observation_generic_dir/headers.txt" \
  -o "$observation_generic_dir/wire.bin" \
  https://demo-upstream:8443/not-allowed-generic-observation

python3 - "$observation_generic_dir" <<'PY'
import base64
import hashlib
import json
import pathlib
import re
import sys

directory = pathlib.Path(sys.argv[1])
headers = (directory / "headers.txt").read_bytes().lower()
wire = (directory / "wire.bin").read_bytes()
assert b"transfer-encoding: chunked\r\n" in headers, headers
assert b"connection: close\r\n" in headers, headers
assert b"content-length:" not in headers, headers
assert (
    b"trailer: x-serverware-observation-proof-b64, x-serverware-observation-proof-sha256\r\n"
    in headers
), headers
match = re.fullmatch(
    rb"([0-9a-f]+)\r\n(.*)\r\n0\r\n"
    rb"x-serverware-observation-proof-b64: ([A-Za-z0-9_-]+)\r\n"
    rb"x-serverware-observation-proof-sha256: (sha256:[0-9a-f]{64})\r\n\r\n",
    wire,
    re.DOTALL | re.IGNORECASE,
)
assert match is not None, wire[-512:]
assert int(match.group(1), 16) == len(match.group(2)), (match.group(1), len(match.group(2)))
runtime_proof_bytes = base64.urlsafe_b64decode(match.group(3) + b"=" * (-len(match.group(3)) % 4))
assert match.group(4).decode("ascii").lower() == (
    "sha256:" + hashlib.sha256(runtime_proof_bytes).hexdigest()
), match.group(4)
runtime_proof = json.loads(runtime_proof_bytes)
assert runtime_proof["apiVersion"] == "serverware.responseObservationRuntimeProof/v1", runtime_proof
assert runtime_proof["kind"] == "ServerwareResponseObservationRuntimeProof", runtime_proof
assert "collector" not in runtime_proof, runtime_proof
assert not (directory / "proof.json").exists(), list(directory.iterdir())
assert not (directory / "body.bin").exists(), list(directory.iterdir())
assert {path.name for path in directory.iterdir()} == {"headers.txt", "wire.bin"}, list(directory.iterdir())
PY

outage_container_id="$(docker compose run -d --no-deps \
  --name "$observation_outage_gate" \
  -e SERVERWARE_DATA_PLANE_RESPONSE_PROOF_ATTESTATION_COMMAND=/bin/false \
  decision-gate-rs)"
observation_containers+=("$outage_container_id")
wait_for_observation_gate "$observation_outage_gate"
if docker compose run --rm --no-deps \
  --user "$(id -u):$(id -g)" \
  -v "$TMP_DIR:/proof" \
  --entrypoint /usr/local/bin/serverware-proof-client \
  decision-gate-rs \
  --observation \
  --proxy "$observation_outage_gate:9090" \
  --url https://demo-upstream:8443/not-allowed-attestation-outage \
  --ca /proof/serverware-ca.pem \
  --out /proof/response-observation-proofs/attestation-outage/proof.json \
  --body-out /proof/response-observation-proofs/attestation-outage/body.bin \
  --collector-key /proof/dev-proof-collector-key.pem \
  --expected-principal-id agent:demo \
  --proxy-header "X-Serverware-Agent: demo-agent" \
  --header "X-Serverware-Agent: demo-agent" \
  > "$observation_outage_dir/stdout.json" \
  2> "$observation_outage_dir/stderr.json"; then
  echo "observation collector unexpectedly accepted an attestation outage" >&2
  exit 1
fi
python3 - "$observation_outage_dir" <<'PY'
import json
import pathlib
import re
import sys

directory = pathlib.Path(sys.argv[1])
assert not (directory / "proof.json").exists(), list(directory.iterdir())
assert not (directory / "body.bin").exists(), list(directory.iterdir())
assert (directory / "stdout.json").read_bytes() == b"", list(directory.iterdir())
assert {path.name for path in directory.iterdir()} == {"stdout.json", "stderr.json"}, list(directory.iterdir())
stderr_lines = [
    line for line in (directory / "stderr.json").read_text(encoding="utf-8").splitlines()
    if line.strip()
]
assert stderr_lines, stderr_lines
assert all(
    re.fullmatch(r"Container [A-Za-z0-9_.-]+ (Creating|Created)", line.strip())
    for line in stderr_lines[:-1]
), stderr_lines
error = json.loads(stderr_lines[-1])
assert error == {
    "ok": False,
    "error": "observation collection failed before the response head",
}, error
PY

custody_compose=(docker compose --profile custody -f docker-compose.yml -f docker-compose.custody.yml)
observation_volumes+=("$observation_custody_socket_volume")
docker volume create "$observation_custody_socket_volume" >/dev/null
observation_volumes+=("$observation_custody_state_volume")
docker volume create "$observation_custody_state_volume" >/dev/null
custody_container_id="$("${custody_compose[@]}" run -d --no-deps \
  --name "$observation_custody" \
  -v "$observation_custody_socket_volume:/run/serverware-custody" \
  -v "$observation_custody_state_volume:/var/lib/serverware-custody" \
  custody-runtime)"
observation_containers+=("$custody_container_id")
for _ in $(seq 1 100); do
  if docker exec "$custody_container_id" test -S /run/serverware-custody/custody.sock 2>/dev/null; then
    break
  fi
  sleep 0.1
done
docker exec "$custody_container_id" test -S /run/serverware-custody/custody.sock
custody_gate_container_id="$("${custody_compose[@]}" run -d --no-deps \
  --name "$observation_custody_gate" \
  -v "$observation_custody_socket_volume:/run/serverware-custody:ro" \
  decision-gate-rs)"
observation_containers+=("$custody_gate_container_id")
custody_image_id="$(docker inspect --format '{{.Image}}' "$custody_container_id")"
custody_gate_image_id="$(docker inspect --format '{{.Image}}' "$custody_gate_container_id")"
if [[ -z "$custody_image_id" || "$custody_image_id" != "$custody_gate_image_id" ]]; then
  echo "observation custody and decision gate did not use the same immutable image ID" >&2
  exit 1
fi
wait_for_observation_gate "$observation_custody_gate"

replay_nonce="$(new_observation_nonce)"
replay_run_id="replay-$observation_container_suffix"
replay_count_before="$(demo_request_count GET /echo "$replay_run_id")"
docker compose run --rm --no-deps \
  --user "$(id -u):$(id -g)" \
  -v "$TMP_DIR:/proof" \
  --entrypoint /usr/local/bin/serverware-proof-client \
  decision-gate-rs \
  --observation \
  --nonce "$replay_nonce" \
  --proxy "$observation_custody_gate:9090" \
  --url https://demo-upstream:8443/echo \
  --ca /proof/serverware-ca.pem \
  --out /proof/response-observation-proofs/replay-first/proof.json \
  --body-out /proof/response-observation-proofs/replay-first/body.bin \
  --collector-key /proof/dev-proof-collector-key.pem \
  --expected-principal-id agent:demo \
  --proxy-header "X-Serverware-Agent: demo-agent" \
  --header "X-Serverware-Agent: demo-agent" \
  --header "User-Agent: serverware-test-run/$replay_run_id" \
  > "$observation_replay_first_dir/summary.json"

replay_count_after_first="$(demo_request_count GET /echo "$replay_run_id")"
docker stop "$observation_custody_gate" >/dev/null
docker restart "$custody_container_id" >/dev/null
for _ in $(seq 1 100); do
  if docker exec "$custody_container_id" test -S /run/serverware-custody/custody.sock 2>/dev/null; then
    break
  fi
  sleep 0.1
done
docker exec "$custody_container_id" test -S /run/serverware-custody/custody.sock
docker start "$observation_custody_gate" >/dev/null
wait_for_observation_gate "$observation_custody_gate"

if docker compose run --rm --no-deps \
  --user "$(id -u):$(id -g)" \
  -v "$TMP_DIR:/proof" \
  --entrypoint /usr/local/bin/serverware-proof-client \
  decision-gate-rs \
  --observation \
  --nonce "$replay_nonce" \
  --proxy "$observation_custody_gate:9090" \
  --url https://demo-upstream:8443/echo \
  --ca /proof/serverware-ca.pem \
  --out /proof/response-observation-proofs/replay-second/proof.json \
  --body-out /proof/response-observation-proofs/replay-second/body.bin \
  --collector-key /proof/dev-proof-collector-key.pem \
  --expected-principal-id agent:demo \
  --proxy-header "X-Serverware-Agent: demo-agent" \
  --header "X-Serverware-Agent: demo-agent" \
  --header "User-Agent: serverware-test-run/$replay_run_id" \
  > "$observation_replay_second_dir/stdout.json" \
  2> "$observation_replay_second_dir/stderr.json"; then
  echo "custody-backed observation replay unexpectedly produced a verified artifact" >&2
  exit 1
fi
replay_count_after="$(demo_request_count GET /echo "$replay_run_id")"
python3 - \
  "$observation_replay_first_dir" \
  "$observation_replay_second_dir" \
  "$replay_count_before" \
  "$replay_count_after_first" \
  "$replay_count_after" <<'PY'
import hashlib
import json
import pathlib
import re
import sys

first = pathlib.Path(sys.argv[1])
second = pathlib.Path(sys.argv[2])
first_proof = json.loads((first / "proof.json").read_text(encoding="utf-8"))
first_body = (first / "body.bin").read_bytes()
first_summary = json.loads((first / "summary.json").read_text(encoding="utf-8"))
assert first_summary["ok"] is True and first_summary["observation_verified"] is True, first_summary
assert first_proof["runtime_proof"]["server_statement"]["upstream_attempt"] == "complete", first_proof
assert first_proof["response"]["body_digest"] == "sha256:" + hashlib.sha256(first_body).hexdigest(), first_proof

assert not (second / "proof.json").exists(), list(second.iterdir())
assert not (second / "body.bin").exists(), list(second.iterdir())
assert (second / "stdout.json").read_bytes() == b"", list(second.iterdir())
assert {path.name for path in second.iterdir()} == {"stdout.json", "stderr.json"}, list(second.iterdir())
stderr_lines = [
    line for line in (second / "stderr.json").read_text(encoding="utf-8").splitlines()
    if line.strip()
]
assert stderr_lines, stderr_lines
assert all(
    re.fullmatch(r"Container [A-Za-z0-9_.-]+ (Creating|Created)", line.strip())
    for line in stderr_lines[:-1]
), stderr_lines
error = json.loads(stderr_lines[-1])
assert error == {
    "ok": False,
    "error": "observation request rejected before proof: HTTP 409 response_observation_nonce_rejected",
}, error
before, after_first, after_replay = map(int, sys.argv[3:6])
assert after_first == before + 1, (
    "first custody-backed observation did not make exactly one upstream attempt",
    before,
    after_first,
)
assert after_replay == after_first, (
    "replayed observation nonce reached the upstream after durable custody restart",
    after_first,
    after_replay,
)
PY

docker compose run --rm --no-deps -T \
  --user "$(id -u):$(id -g)" \
  -v "$observation_replay_first_dir:/proof:ro" \
  -v "$PWD/schemas:/proof-schemas:ro" \
  --entrypoint python \
  serverware - \
  /proof/proof.json \
  /proof-schemas/response-observation-proof.v1.schema.json <<'PY'
import json
import sys

import jsonschema

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    proof = json.load(handle)
with open(sys.argv[2], "r", encoding="utf-8") as handle:
    schema = json.load(handle)
jsonschema.validate(proof, schema)
PY

nonce="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
status="$(curl -sS -o "$TMP_DIR/response-proof-unsafe.json" -w '%{http_code}' \
  --max-time 10 \
  --proxy "$gate_proxy_url" \
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

printf '%s\n' '{"buffered_response_proof_capture":"pass","observation_proof_capture":"pass","observation_proof_cases":8,"ok":true,"streaming_response_proof_capture":"pass","structured_streaming_connect_proofs":6}'
