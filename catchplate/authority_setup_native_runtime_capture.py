"""Original buffered capture admission under independently selected scope.

The collector authenticates its actual HTTP/TLS observation. Original role-4
Nitro evidence and control-plane dispatch signatures are verified here again.
Neither collector output nor this local projection grants action authority.
"""
import hashlib

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from scripts import verify_nitro_tee as nitro
from catchplate import authority_setup_native_runtime as p
from catchplate import authority_setup_native_runtime_policy as policy
from catchplate import authority_setup_native_runtime_receipt as r

STATEMENT_FIELDS = frozenset({"apiVersion", "issued_at_unix", "client_nonce", "principal_id", "route_id", "request_digest", "operation_digest",
    "runtime_manifest_digest", "data_plane_binary_digest", "release_digest", "server_instance", "tls_channel_binding", "client_request_digest",
    "release_authority", "control_plane_authorization_receipt", "upstream_response", "policy_digest", "response"})
CAPTURE_FIELDS = frozenset({"apiVersion", "environment", "collection_mode", "captured_at_unix", "client_nonce", "client_request_digest",
    "principal_id", "route_id", "request_digest", "operation_digest", "release_authority", "control_plane_authorization_receipt",
    "upstream_response", "response", "tls_channel_binding", "tls_peer", "server_statement_sha256", "classification", "okForAction", "runtime_proof_sha256"})


def _quote(proof, statement, expected, roots, now):
    evidence = r.exact(proof["native_attestation"], {"apiVersion", "attestationDocumentB64", "responseProofPublicKey"})
    p.require(evidence["apiVersion"] == "catchplate.nativeResponseProofKeyEvidence/v1")
    raw_key = r.b64(evidence["responseProofPublicKey"], 32, 32)
    key = Ed25519PublicKey.from_public_bytes(raw_key)
    pem = key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii")
    p.require(policy.ca.key_id(key) == expected["keyId"] and raw_key != bytes(32))
    signed_bytes = r.utf8(statement)
    r.signature(proof["server_signature"], signed_bytes, pem)
    signature = r.b64(proof["server_signature"]["signature"][8:], 64, 64)
    nonce = r.b64(statement["client_nonce"], 32, 32)
    challenge = hashlib.sha256(b"catchplate/native-response-attestation-challenge/v1\0" + bytes([len(nonce)]) + nonce
        + hashlib.sha256(signed_bytes).digest() + signature).digest()
    binding = hashlib.sha256(b"catchplate/native-proof-custody-boot/v1\0" + r.b64(expected["bootId"], 32, 32)
        + bytes.fromhex(expected["keyId"][7:]) + bytes.fromhex(expected["controlPlaneResponseSigningKeyId"][7:])).digest()
    user_data = b"catchplate/enclave-runtime-key-binding/v1\0\x04" + b"".join(bytes.fromhex(expected[field][7:])
        for field in ("releaseRecordSha256", "policyHash", "configurationSha256", "caCertificateSha256", "caPublicKeySpkiSha256"))
    user_data += hashlib.sha256(raw_key).digest() + binding
    document = r.b64(evidence["attestationDocumentB64"], 12288, 1)
    trust, crls, certs = policy.native._trust({**roots, "apiVersion": policy.native.TRUST_SCHEMA})
    payload, issued, _, _, _ = nitro._verify_nitro_document_common(document, claims=None,
        expected_user_data_bytes=user_data, challenge=challenge, expected_pcrs=expected["expectedPcrs"], expected_eif=expected["expectedEif"],
        roots=trust, crls=crls, certificate_profile=certs, expected_module_id=expected["expectedModuleId"],
        now=now // 1_000_000_000, max_age=expected["maxAgeSeconds"], future_skew=expected["futureSkewSeconds"], native_profile=True)
    p.require(type(payload["public_key"]) is bytes and payload["public_key"] == raw_key)
    return {"apiVersion": "catchplate.nativeResponseAttestationVerification/v2", "ok": True, "debug": False,
        "resultScope": "local-signature-and-native-quote-only", "okForAction": False, "statementApiVersion": statement["apiVersion"],
        "serverStatementSha256": p.sha256(signed_bytes), "signatureSha256": p.sha256(signature), "clientNonce": statement["client_nonce"],
        "quoteChallenge": p.enrollment.encoded(challenge), "bootId": expected["bootId"], "keyId": expected["keyId"],
        "controlPlaneResponseSigningKeyId": expected["controlPlaneResponseSigningKeyId"], "policyHash": expected["policyHash"],
        "dataPlaneBinaryDigest": expected["expectedBinaryDigest"], "requestBindingSha256": "sha256:" + binding.hex(),
        "attestationDocumentSha256": p.sha256(document), "issuedAtUnix": issued, "statementIssuedAtUnix": statement["issued_at_unix"]}


def verify(raw, attempt, scope, roots, now):
    artifact = r.exact(r.document(raw, p.MAX_CAPTURE), {"apiVersion", "kind", "resultScope", "okForAction", "environment", "captureMode",
        "external_capture", "runtime_proof", "native_verification", "collector_signature"})
    p.require(artifact["apiVersion"] == "catchplate.nativeResponseCapture/v2" and artifact["kind"] == "CatchplateNativeResponseCapture"
        and artifact["resultScope"] == "local-capture-and-native-quote-only" and artifact["okForAction"] is False
        and artifact["environment"] == "native-unadmitted" and artifact["captureMode"] == "buffered"
        and attempt["issuedAtEpochNs"] <= now < attempt["expiresAtEpochNs"] <= scope["expiresAtEpochNs"])
    r.signature(artifact["collector_signature"], r.utf8({key: value for key, value in artifact.items() if key != "collector_signature"}),
        scope["collectorPublicKeyPem"], capture=True)
    proof = r.exact(artifact["runtime_proof"], {"apiVersion", "kind", "server_statement", "server_statement_sha256", "server_signature", "native_attestation"})
    p.require(proof["apiVersion"] == "catchplate.nativeResponseRuntimeProof/v2" and proof["kind"] == "CatchplateNativeResponseRuntimeProof"
        and len(r.utf8(proof)) <= 128 * 1024)
    statement = r.exact(proof["server_statement"], STATEMENT_FIELDS)
    p.require(statement["apiVersion"] == "catchplate.nativeProxyResponseStatement/v1")
    expected = scope["nativeAssignment"]
    for field, value in {"client_nonce": attempt["nonce"], "principal_id": attempt["principalId"], "route_id": attempt["routeId"],
            "client_request_digest": attempt["clientRequestSha256"], "policy_digest": attempt["policyHash"],
            "data_plane_binary_digest": expected["expectedBinaryDigest"], "release_digest": scope["responseProvenanceSha256"],
            "runtime_manifest_digest": scope["responseRuntimeManifestSha256"]}.items():
        p.require(statement[field] == value)
    for field in ("request_digest", "operation_digest", "runtime_manifest_digest"):
        p.digest(statement[field])
    statement_sha = p.sha256(r.utf8(statement)); p.require(proof["server_statement_sha256"] == statement_sha)
    observed = r.exact(artifact["external_capture"], CAPTURE_FIELDS)
    p.require(observed["apiVersion"] == "catchplate.proxyResponseCapture/v2" and observed["environment"] == "native-unadmitted"
        and observed["classification"] == "client-capture-verified" and observed["okForAction"] is False
        and observed["collection_mode"] == "external-client-capture" and observed["server_statement_sha256"] == statement_sha
        and observed["runtime_proof_sha256"] == p.sha256(r.utf8(proof)))
    for field in ("client_nonce", "client_request_digest", "principal_id", "route_id", "request_digest", "operation_digest",
            "release_authority", "control_plane_authorization_receipt", "upstream_response", "response", "tls_channel_binding"):
        p.require(observed[field] == statement[field])
    peer = r.exact(observed["tls_peer"], {"spiffe_id", "leaf_certificate_sha256"})
    p.digest(peer["leaf_certificate_sha256"])
    p.require(peer["spiffe_id"] == scope["serverInstanceId"] and statement["server_instance"] == {
        "id": scope["serverInstanceId"], "identity_digest": p.sha256(scope["serverInstanceId"].encode("utf-8"))})
    tls = r.exact(statement["tls_channel_binding"], {"type", "value"}); p.require(tls["type"] == "tls-exporter"); r.b64(tls["value"], 32, 32)
    issued, captured = r.uint(statement["issued_at_unix"], 1), r.uint(observed["captured_at_unix"], 1)
    # Seconds are intervals, not invented subsecond sampling. Require the entire
    # recorded interval to lie inside this one original protected attempt.
    p.require(attempt["issuedAtEpochNs"] <= issued * 1_000_000_000 <= captured * 1_000_000_000
        and (captured + 1) * 1_000_000_000 <= now < attempt["expiresAtEpochNs"]
        and now - issued * 1_000_000_000 <= expected["maxAgeSeconds"] * 1_000_000_000)
    response = r.exact(statement["response"], {"status", "selected_headers", "selected_headers_digest", "body_digest"})
    r.uint(response["status"], 200, 299); p.digest(response["body_digest"])
    headers = response["selected_headers"]
    required = {"content-length", "x-catchplate-client-request-digest", "x-catchplate-policy-hash", "x-catchplate-request-digest",
        "x-catchplate-operation-digest", "x-catchplate-response-body-sha256"}
    p.require(type(headers) is dict and required <= set(headers) <= required | {"content-type"}
        and all(type(value) is str and len(value) <= 4096 for value in headers.values()))
    length = headers["content-length"]
    p.require(length.isascii() and length.isdecimal() and len(length) <= 20 and 0 <= int(length) <= 2**63 - 1
        and str(int(length)) == length)
    if "content-type" in headers:
        p.enrollment.setup.text(headers["content-type"], 4096)
    for header, field in (("x-catchplate-client-request-digest", "client_request_digest"), ("x-catchplate-policy-hash", "policy_digest"),
            ("x-catchplate-request-digest", "request_digest"), ("x-catchplate-operation-digest", "operation_digest")):
        p.require(headers[header] == statement[field])
    p.require(headers["x-catchplate-response-body-sha256"] == response["body_digest"]
        and response["selected_headers_digest"] == p.sha256(r.utf8(headers)))
    upstream = r.exact(statement["upstream_response"], {"status", "selected_raw_policy_headers_b64", "body_digest", "canonical_digest"})
    p.require(type(upstream["status"]) is int and upstream["status"] == response["status"])
    p.digest(upstream["body_digest"])
    selected = upstream["selected_raw_policy_headers_b64"]
    p.require(type(selected) is dict and {"content-encoding", "content-length", "content-type"} <= set(selected)
        <= {"cache-control", "content-encoding", "content-language", "content-length", "content-type", "etag", "last-modified", "retry-after", "www-authenticate"})
    for values in selected.values():
        p.require(type(values) is list and len(values) <= 128)
        for value in values:
            r.b64(value, 8192)
    p.require(upstream["canonical_digest"] == p.sha256(r.utf8({name: value for name, value in upstream.items() if name != "canonical_digest"})))
    r.verify(statement, scope, attempt, now)
    verification = _quote(proof, statement, expected, roots, now)
    p.require(type(verification["issuedAtUnix"]) is int
        and attempt["issuedAtEpochNs"] <= verification["issuedAtUnix"] * 1_000_000_000
        and (verification["issuedAtUnix"] + 1) * 1_000_000_000 < attempt["expiresAtEpochNs"]
        and p.canonical(verification) == p.canonical(artifact["native_verification"]))
    return projection(raw, attempt)


def projection(raw, attempt):
    """Data projection only; effect caller is the independently verified kernel."""
    artifact = r.document(raw, p.MAX_CAPTURE)
    proof, verification = artifact["runtime_proof"], artifact["native_verification"]
    statement = proof["server_statement"]
    return {"apiVersion": "catchplate.setupNativeRuntimeEvidence/v1", "resultScope": "trusted-collector-and-native-signatures-only",
        "okForAction": False, "nativeHostVerified": False, "enrollmentComplete": False, "proxyReady": False,
        "attemptSha256": p.sha256(p.canonical(attempt)), "captureSha256": p.sha256(raw), "serverStatementSha256": p.sha256(r.utf8(statement)),
        "requestSha256": statement["request_digest"], "operationSha256": statement["operation_digest"],
        "dispatchReceiptSha256": p.sha256(r.utf8(statement["control_plane_authorization_receipt"])), "responseBodySha256": statement["response"]["body_digest"],
        "responseStatus": statement["response"]["status"], "collectorKeyId": artifact["collector_signature"]["key_id"],
        "nativeKeyId": proof["server_signature"]["key_id"], "attestationDocumentSha256": verification["attestationDocumentSha256"]}
