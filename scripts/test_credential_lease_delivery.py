#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import shlex
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from fastapi import HTTPException, Request
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from serverware.response_identity import response_headers_binding  # noqa: E402

ADMIN_TOKEN = "credential-lease-test-admin-token"
DATA_PLANE_TOKEN = "credential-lease-test-data-plane-token"
DATA_PLANE_BINARY_DIGEST = "sha256:" + "7" * 64
CREDENTIAL_ID = "cred-demo-bearer"
PRINCIPAL_ID = "agent:demo"
ROUTE_ID = "demo.echo"
CREDENTIAL_SECRET = "demo-token-from-vault"
INITIAL_METADATA = {
    "expires_at_epoch_ms": 4_102_444_800_000,
    "managed": True,
    "provider_id": "demo",
    "provider_subject": "demo-service-account",
    "secret_class": "bearerToken",
    "x_app_id": "demo-x-app",
}
UPDATED_METADATA = {
    "managed": True,
    "provider_id": "demo",
    "provider_subject": "demo-service-account",
    "secret_class": "bearerToken",
    "x_app_id": "demo-x-app-v2",
}
LEASE_PATH = "/api/data-plane/credential-leases"
RESPONSE_SIGNATURE_HEADERS = {
    "x-serverware-response-key-id",
    "x-serverware-response-body-sha256",
    "x-serverware-response-statement-sha256",
    "x-serverware-response-statement-b64",
    "x-serverware-response-signature",
}
AAD_FIELDS = (
    "apiVersion",
    "algorithm",
    "recipientKeyId",
    "recipientNonce",
    "policyHash",
    "dataPlaneBinaryDigest",
    "principalId",
    "routeId",
    "credentialId",
    "issuedAtEpochMs",
    "expiresAtEpochMs",
)
V4_AAD_FIELDS = (
    "apiVersion",
    "algorithm",
    "purpose",
    "requestBindingSha256",
    "requestAuthoritySha256",
    "recipientKeyId",
    "recipientNonce",
    "policyHash",
    "dataPlaneBinaryDigest",
    "principalId",
    "routeId",
    "credentialId",
    "issuedAtEpochMs",
    "expiresAtEpochMs",
)
ENCRYPTED_FIELDS = (
    "serverEphemeralPublicKey",
    "aeadNonce",
    "ciphertext",
    "ciphertextSha256",
)
DUPLICATED_BINDINGS = (
    "recipientKeyId",
    "recipientNonce",
    "policyHash",
    "dataPlaneBinaryDigest",
    "principalId",
    "routeId",
    "credentialId",
    "issuedAtEpochMs",
    "expiresAtEpochMs",
)


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def b64e(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def b64d(value: str) -> bytes:
    if "=" in value:
        raise AssertionError("expected unpadded base64url")
    decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if b64e(decoded) != value:
        raise AssertionError("base64url value is not canonical")
    return decoded


def sha256_prefixed(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def recipient_attestation_verifier() -> None:
    try:
        for name in (
            "SERVERWARE_ADMIN_TOKEN",
            "SERVERWARE_DATA_PLANE_CREDENTIAL_LEASE_TOKEN",
            "SERVERWARE_DATA_PLANE_AUDIT_TOKEN",
            "SERVERWARE_DATA_PLANE_GRANT_CONSUME_TOKEN",
            "SERVERWARE_DATA_PLANE_RATE_LIMIT_CONSUME_TOKEN",
            "SERVERWARE_DATA_PLANE_MANAGEMENT_TOKEN",
            "SERVERWARE_METADATA_STORE_POSTGRES_DSN",
        ):
            if os.getenv(name):
                raise ValueError(f"verifier inherited sensitive environment variable {name}")
        request = json.load(sys.stdin)
        evidence = request["recipientAttestation"]
        if evidence.get("format") != "serverware.testRecipientAttestation/v1":
            raise ValueError("unexpected recipient attestation format")
        for field in (
            "purpose",
            "requestBindingSha256",
            "recipientKeyId",
            "recipientNonce",
            "policyHash",
            "dataPlaneBinaryDigest",
            "principalId",
            "routeId",
            "credentialId",
        ):
            if evidence.get(field) != request.get(field):
                raise ValueError(f"recipient attestation {field} mismatch")
        request_authority_sha256 = request.get("requestAuthoritySha256")
        if request_authority_sha256 is None:
            if "requestAuthoritySha256" in evidence:
                raise ValueError(
                    "legacy recipient attestation carried request authority"
                )
        elif evidence.get("requestAuthoritySha256") != request_authority_sha256:
            raise ValueError(
                "recipient attestation requestAuthoritySha256 mismatch"
            )
        counter_path = evidence.get("testVerifierCounterPath")
        if counter_path:
            with open(counter_path, "a", encoding="ascii") as counter:
                counter.write("verified\n")
        response = {
            "ok": True,
            "debug": False,
            "purpose": request["purpose"],
            "requestBindingSha256": request["requestBindingSha256"],
            "recipientKeyId": request["recipientKeyId"],
            "recipientNonce": request["recipientNonce"],
            "policyHash": request["policyHash"],
            "dataPlaneBinaryDigest": request["dataPlaneBinaryDigest"],
            "principalId": request["principalId"],
            "routeId": request["routeId"],
            "credentialId": request["credentialId"],
        }
        if request_authority_sha256 is not None:
            response["requestAuthoritySha256"] = request_authority_sha256
        if evidence.get("testLargeVerifierOutput") is True:
            response["padding"] = "x" * (64 * 1024)
        print(
            json.dumps(response, sort_keys=True)
        )
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1) from exc


def master_key_unseal_fixture() -> None:
    request = json.load(sys.stdin)
    key = b"0123456789abcdef0123456789abcdef"
    if len(key) != 32:
        raise AssertionError("master-key fixture must be exactly 32 bytes")
    print(
        json.dumps(
            {
                "apiVersion": "serverware.unsealedMaterial/v1",
                "kind": "UnsealedMaterial",
                "ok": True,
                "material": "broker-kek",
                "requestDigest": request["requestDigest"],
                "releaseHandle": request["releaseHandle"],
                "keyB64": b64e(key),
                "provider": "test-in-memory-unseal",
                "attestationDocumentSha256": "sha256:" + "a" * 64,
                "recipientPublicKeySha256": "sha256:" + "b" * 64,
                "kmsKeyId": "test-kms-key",
            },
            sort_keys=True,
        )
    )


@dataclass(frozen=True)
class AppResponse:
    status_code: int
    headers: dict[str, str]
    raw_headers: tuple[tuple[bytes, bytes], ...]
    body: bytes

    def json(self) -> Any:
        return json.loads(self.body)


async def _asgi_request(
    app: Any,
    method: str,
    target: str,
    *,
    payload: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
) -> AppResponse:
    parsed = urlsplit(target)
    body = b"" if payload is None else canonical_json_bytes(payload)
    request_headers = {
        "host": "testserver",
        "content-length": str(len(body)),
        **({"content-type": "application/json"} if payload is not None else {}),
        **(headers or {}),
    }
    scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": method.upper(),
        "scheme": "http",
        "path": parsed.path,
        "raw_path": parsed.path.encode("ascii"),
        "query_string": parsed.query.encode("ascii"),
        "root_path": "",
        "headers": [(key.lower().encode("ascii"), value.encode("latin-1")) for key, value in request_headers.items()],
        "client": ("127.0.0.1", 12345),
        "server": ("testserver", 80),
    }
    request_sent = False
    status_code: int | None = None
    response_headers: dict[str, str] = {}
    response_raw_headers: list[tuple[bytes, bytes]] = []
    response_body = bytearray()

    async def receive() -> dict[str, Any]:
        nonlocal request_sent
        if request_sent:
            return {"type": "http.disconnect"}
        request_sent = True
        return {"type": "http.request", "body": body, "more_body": False}

    async def send(message: dict[str, Any]) -> None:
        nonlocal status_code
        if message["type"] == "http.response.start":
            status_code = int(message["status"])
            response_raw_headers.extend(
                (bytes(key), bytes(value))
                for key, value in message.get("headers", [])
            )
            response_headers.update(
                (key.decode("latin-1").lower(), value.decode("latin-1"))
                for key, value in message.get("headers", [])
            )
        elif message["type"] == "http.response.body":
            response_body.extend(message.get("body", b""))

    await app(scope, receive, send)
    if status_code is None:
        raise AssertionError("ASGI application did not start a response")
    return AppResponse(
        status_code,
        response_headers,
        tuple(response_raw_headers),
        bytes(response_body),
    )


def app_request(
    app: Any,
    method: str,
    target: str,
    *,
    payload: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
) -> AppResponse:
    return asyncio.run(_asgi_request(app, method, target, payload=payload, headers=headers))


def verify_response_signature(
    response: AppResponse,
    *,
    public_key: Ed25519PublicKey,
    key_id: str,
    method: str,
    target: str,
    response_nonce: str,
    policy_hash: str,
) -> dict[str, Any]:
    missing = RESPONSE_SIGNATURE_HEADERS.difference(response.headers)
    if missing:
        raise AssertionError(f"signed response headers are missing: {sorted(missing)}")

    parsed = urlsplit(target)
    statement_bytes = b64d(response.headers["x-serverware-response-statement-b64"])
    statement = json.loads(statement_bytes)
    if canonical_json_bytes(statement) != statement_bytes:
        raise AssertionError("response signature statement is not canonical JSON")
    if response.headers["x-serverware-response-key-id"] != key_id:
        raise AssertionError("response key header does not match the attested key")
    if statement.get("response_signing_key_id") != key_id:
        raise AssertionError("response statement does not bind the attested key")
    if response.headers["x-serverware-response-body-sha256"] != sha256_prefixed(response.body):
        raise AssertionError("response body digest header mismatch")
    if statement.get("body_sha256") != sha256_prefixed(response.body):
        raise AssertionError("response statement body digest mismatch")
    if response.headers["x-serverware-response-statement-sha256"] != sha256_prefixed(statement_bytes):
        raise AssertionError("response statement digest header mismatch")
    if statement.get("version") != "serverware.responseSignature/v3":
        raise AssertionError(f"unexpected response signature version: {statement}")
    authenticated_headers = [
        (name, value)
        for name, value in response.raw_headers
        if not name.lower().startswith(b"x-serverware-response-")
    ]
    headers_digest, header_count = response_headers_binding(
        authenticated_headers
    )
    if (
        statement.get("response_headers_sha256") != headers_digest
        or statement.get("response_header_count") != header_count
    ):
        raise AssertionError(
            "response statement header binding mismatch"
        )
    if statement.get("request") != {
        "method": method.upper(),
        "path": parsed.path,
        "query_sha256": sha256_prefixed(parsed.query.encode("utf-8")),
    }:
        raise AssertionError(f"response statement request binding mismatch: {statement}")
    if statement.get("status_code") != response.status_code:
        raise AssertionError(f"response statement status mismatch: {statement}")
    if statement.get("nonce") != response_nonce:
        raise AssertionError(f"response statement nonce mismatch: {statement}")
    if (statement.get("context") or {}).get("policy_bundle_digest") != policy_hash:
        raise AssertionError(f"response statement policy binding mismatch: {statement}")

    signature = response.headers["x-serverware-response-signature"]
    if not signature.startswith("ed25519:"):
        raise AssertionError("response signature does not use Ed25519")
    public_key.verify(b64d(signature.split(":", 1)[1]), statement_bytes)
    return statement


def recipient_nonce(label: str) -> bytes:
    nonce = hashlib.sha256(f"serverware:credential-lease-test:{label}".encode("ascii")).digest()
    if len(nonce) != 32:
        raise AssertionError("recipient nonce must be 32 bytes")
    return nonce


def recipient_attestation(
    key_id: str,
    nonce: str,
    policy_hash: str,
    binary_digest: str,
    purpose: str,
    request_binding_sha256: str,
    request_authority_sha256: str | None,
) -> dict[str, str]:
    evidence = {
        "format": "serverware.testRecipientAttestation/v1",
        "purpose": purpose,
        "requestBindingSha256": request_binding_sha256,
        "recipientKeyId": key_id,
        "recipientNonce": nonce,
        "policyHash": policy_hash,
        "dataPlaneBinaryDigest": binary_digest,
        "principalId": PRINCIPAL_ID,
        "routeId": ROUTE_ID,
        "credentialId": CREDENTIAL_ID,
    }
    if request_authority_sha256 is not None:
        evidence["requestAuthoritySha256"] = request_authority_sha256
    return evidence


def credential_lease_request_binding(payload: dict[str, Any]) -> str:
    return sha256_prefixed(
        canonical_json_bytes(
            {
                "apiVersion": payload["apiVersion"],
                "purpose": payload["purpose"],
                "principalId": payload["principalId"],
                "routeId": payload["routeId"],
                "credentialId": payload["credentialId"],
                "expectedCredentialVersion": payload["expectedCredentialVersion"],
                "expectedMetadataSha256": payload["expectedMetadataSha256"],
                "requestAuthority": payload.get("requestAuthority"),
                "releaseAuthorization": payload.get("releaseAuthorization"),
                "recipientKeyId": payload["recipientKeyId"],
                "recipientNonce": payload["recipientNonce"],
                "policyHash": payload["policyHash"],
                "dataPlaneBinaryDigest": payload["dataPlaneBinaryDigest"],
                "maxTtlSeconds": payload["maxTtlSeconds"],
            }
        )
    )


def credential_metadata_sha256(metadata: dict[str, Any]) -> str:
    return sha256_prefixed(canonical_json_bytes(metadata))


def credential_request_authority(
    *,
    attempt_id: str,
    reservation_id: str,
    binding_digest: str,
    request_digest: str,
    operation_digest: str,
    operation_context: dict[str, Any],
    reservation_expires_at_epoch_ms: int,
) -> dict[str, Any]:
    return {
        "apiVersion": "serverware.credentialLeaseRequestAuthority/v1",
        "attemptId": attempt_id,
        "reservationId": reservation_id,
        "bindingDigest": binding_digest,
        "requestDigest": request_digest,
        "operationDigest": operation_digest,
        "operationContext": operation_context,
        "reservationExpiresAtEpochMs": reservation_expires_at_epoch_ms,
    }


def lease_payload(
    public_key_raw: bytes,
    policy_hash: str,
    label: str,
    *,
    purpose: str = "generationMetadata",
    expected_credential_version: int | None = None,
    expected_metadata_sha256: str | None = None,
    request_authority: dict[str, Any] | None = None,
    release_authorization: dict[str, Any] | None = None,
) -> dict[str, Any]:
    key_id = sha256_prefixed(public_key_raw)
    nonce = recipient_nonce(label)
    payload = {
        "apiVersion": (
            "serverware.credentialLeaseRequest/v4"
            if request_authority is not None
            else "serverware.credentialLeaseRequest/v3"
        ),
        "purpose": purpose,
        "principalId": PRINCIPAL_ID,
        "routeId": ROUTE_ID,
        "credentialId": CREDENTIAL_ID,
        "expectedCredentialVersion": expected_credential_version,
        "expectedMetadataSha256": expected_metadata_sha256,
        "recipientPublicKey": b64e(public_key_raw),
        "recipientKeyId": key_id,
        "recipientNonce": b64e(nonce),
        "policyHash": policy_hash,
        "dataPlaneBinaryDigest": DATA_PLANE_BINARY_DIGEST,
        "maxTtlSeconds": 5,
    }
    if request_authority is not None:
        payload["requestAuthority"] = request_authority
        payload["releaseAuthorization"] = release_authorization
    request_binding_sha256 = credential_lease_request_binding(payload)
    request_authority_sha256 = (
        sha256_prefixed(canonical_json_bytes(request_authority))
        if request_authority is not None
        else None
    )
    payload["recipientAttestation"] = recipient_attestation(
        key_id,
        b64e(nonce),
        policy_hash,
        DATA_PLANE_BINARY_DIGEST,
        purpose,
        request_binding_sha256,
        request_authority_sha256,
    )
    return payload


def decrypt_lease(
    envelope: dict[str, Any],
    *,
    recipient_private_key: X25519PrivateKey,
    recipient_nonce_raw: bytes,
    request_payload: dict[str, Any],
) -> dict[str, Any]:
    request_bound = (
        request_payload["apiVersion"]
        == "serverware.credentialLeaseRequest/v4"
    )
    aad_fields = V4_AAD_FIELDS if request_bound else AAD_FIELDS
    expected_fields = set(aad_fields).union(ENCRYPTED_FIELDS)
    if set(envelope) != expected_fields:
        raise AssertionError(f"credential lease envelope fields changed: {sorted(envelope)}")
    expected_envelope_version = (
        "serverware.credentialLeaseEnvelope/v3"
        if request_bound
        else "serverware.credentialLeaseEnvelope/v2"
    )
    if envelope["apiVersion"] != expected_envelope_version:
        raise AssertionError(f"unexpected credential lease envelope version: {envelope}")
    if envelope["algorithm"] != "X25519-HKDF-SHA256-AES-256-GCM":
        raise AssertionError(f"unexpected credential lease algorithm: {envelope}")
    lease_ttl_ms = envelope["expiresAtEpochMs"] - envelope["issuedAtEpochMs"]
    if not 0 < lease_ttl_ms <= 5_000:
        raise AssertionError(f"credential lease TTL was not bounded to five seconds: {envelope}")

    aad = {field: envelope[field] for field in aad_fields}
    aad_bytes = canonical_json_bytes(aad)
    server_public_key_raw = b64d(envelope["serverEphemeralPublicKey"])
    aead_nonce = b64d(envelope["aeadNonce"])
    ciphertext = b64d(envelope["ciphertext"])
    if len(server_public_key_raw) != 32 or len(aead_nonce) != 12:
        raise AssertionError("credential lease envelope contains invalid key or nonce lengths")
    if envelope["ciphertextSha256"] != sha256_prefixed(ciphertext):
        raise AssertionError("credential lease ciphertext digest mismatch")

    shared_secret = recipient_private_key.exchange(X25519PublicKey.from_public_bytes(server_public_key_raw))
    envelope_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=recipient_nonce_raw,
        info=b"serverware:credential-lease-envelope:v2\0" + hashlib.sha256(aad_bytes).digest(),
    ).derive(shared_secret)
    plaintext_bytes = AESGCM(envelope_key).decrypt(aead_nonce, ciphertext, aad_bytes)
    plaintext = json.loads(plaintext_bytes)
    if canonical_json_bytes(plaintext) != plaintext_bytes:
        raise AssertionError("credential lease plaintext is not canonical JSON")
    expected_set_version = (
        "serverware.credentialLeaseSet/v4"
        if request_bound
        else "serverware.credentialLeaseSet/v3"
    )
    if plaintext.get("apiVersion") != expected_set_version:
        raise AssertionError(f"unexpected credential lease plaintext version: {plaintext}")
    expected_plaintext_fields = {
        "apiVersion",
        "purpose",
        "requestBindingSha256",
        "releaseAuthorization",
        *DUPLICATED_BINDINGS,
        "credentials",
    }
    if request_bound:
        expected_plaintext_fields.update(
            {
                "requestAuthority",
                "requestAuthoritySha256",
            }
        )
    if set(plaintext) != expected_plaintext_fields:
        raise AssertionError(f"credential lease plaintext fields changed: {sorted(plaintext)}")
    if plaintext["purpose"] != request_payload["purpose"]:
        raise AssertionError(f"credential lease purpose substitution: {plaintext}")
    if plaintext["requestBindingSha256"] != credential_lease_request_binding(request_payload):
        raise AssertionError(f"credential lease request binding mismatch: {plaintext}")
    if not request_bound and plaintext["releaseAuthorization"] is not None:
        raise AssertionError(
            f"legacy credential lease carried release authority: {plaintext}"
        )
    if request_bound:
        request_authority_sha256 = sha256_prefixed(
            canonical_json_bytes(request_payload["requestAuthority"])
        )
        if (
            plaintext["requestAuthority"] != request_payload["requestAuthority"]
            or plaintext["requestAuthoritySha256"] != request_authority_sha256
            or envelope["requestAuthoritySha256"] != request_authority_sha256
            or plaintext["releaseAuthorization"]
            != request_payload["releaseAuthorization"]
        ):
            raise AssertionError(
                f"credential lease v4 authority binding mismatch: {plaintext}"
            )
        if (
            plaintext["expiresAtEpochMs"]
            > request_payload["requestAuthority"][
                "reservationExpiresAtEpochMs"
            ]
        ):
            raise AssertionError(
                "credential lease v4 outlived its request authority"
            )
    for field in DUPLICATED_BINDINGS:
        if plaintext.get(field) != envelope.get(field):
            raise AssertionError(f"credential lease duplicated binding mismatch for {field}: {plaintext}")
    credentials = plaintext.get("credentials")
    if not isinstance(credentials, list) or len(credentials) != 1:
        raise AssertionError(f"credential lease must contain one credential: {plaintext}")
    expected_entry_fields = {
        "credentialId",
        "credentialVersion",
        "metadataSha256",
        "metadata",
    }
    if request_payload["purpose"] == "dispatchSecret":
        expected_entry_fields.add("secret")
    if set(credentials[0]) != expected_entry_fields:
        raise AssertionError(f"credential lease material shape mismatch: {plaintext}")
    if credentials[0]["metadataSha256"] != credential_metadata_sha256(
        credentials[0]["metadata"]
    ):
        raise AssertionError(f"credential lease metadata digest mismatch: {plaintext}")
    return plaintext


def assert_status(response: AppResponse, expected: int, label: str, detail: str | None = None) -> None:
    if response.status_code != expected:
        raise AssertionError(f"{label} returned {response.status_code}: {response.body.decode(errors='replace')}")
    if detail is not None and detail not in json.dumps(response.json(), sort_keys=True):
        raise AssertionError(f"{label} failed for the wrong reason: {response.json()}")


def assert_python_v4_golden(app_module: Any) -> None:
    attempt_id = "sha256:" + "1" * 64
    binding_digest = "sha256:" + "2" * 64
    reservation_id = sha256_prefixed(
        canonical_json_bytes(
            {
                "apiVersion": "serverware.releaseReservationIdentity/v1",
                "attemptId": attempt_id,
                "bindingDigest": binding_digest,
            }
        )
    )
    authority = credential_request_authority(
        attempt_id=attempt_id,
        reservation_id=reservation_id,
        binding_digest=binding_digest,
        request_digest="sha256:" + "3" * 64,
        operation_digest="sha256:" + "4" * 64,
        operation_context={
            "account": "acct:golden",
            "operation": "gmail.message.get",
        },
        reservation_expires_at_epoch_ms=4_102_444_800_000,
    )
    expected_authority_json = (
        b'{"apiVersion":"serverware.credentialLeaseRequestAuthority/v1",'
        b'"attemptId":"' + attempt_id.encode("ascii") + b'",'
        b'"bindingDigest":"' + binding_digest.encode("ascii") + b'",'
        b'"operationContext":{"account":"acct:golden",'
        b'"operation":"gmail.message.get"},'
        b'"operationDigest":"sha256:' + b"4" * 64 + b'",'
        b'"requestDigest":"sha256:' + b"3" * 64 + b'",'
        b'"reservationExpiresAtEpochMs":4102444800000,'
        b'"reservationId":"' + reservation_id.encode("ascii") + b'"}'
    )
    if canonical_json_bytes(authority) != expected_authority_json:
        raise AssertionError(
            "credential lease v4 golden authority bytes drifted"
        )
    payload = {
        "apiVersion": "serverware.credentialLeaseRequest/v4",
        "purpose": "dispatchSecret",
        "principalId": "agent:golden",
        "routeId": "gmail.messages",
        "credentialId": "credential:golden",
        "expectedCredentialVersion": 7,
        "expectedMetadataSha256": "sha256:" + "5" * 64,
        "requestAuthority": authority,
        "releaseAuthorization": None,
        "recipientPublicKey": "A" * 43,
        "recipientKeyId": "sha256:" + "6" * 64,
        "recipientNonce": "B" * 43,
        "policyHash": "sha256:" + "7" * 64,
        "dataPlaneBinaryDigest": "sha256:" + "8" * 64,
        "maxTtlSeconds": 5,
    }
    model = app_module.CredentialLeaseRequest.model_validate(payload)
    authority_sha256 = sha256_prefixed(canonical_json_bytes(authority))
    expected_request_binding_json = (
        b'{"apiVersion":"serverware.credentialLeaseRequest/v4",'
        b'"credentialId":"credential:golden",'
        b'"dataPlaneBinaryDigest":"sha256:' + b"8" * 64 + b'",'
        b'"expectedCredentialVersion":7,'
        b'"expectedMetadataSha256":"sha256:' + b"5" * 64 + b'",'
        b'"maxTtlSeconds":5,'
        b'"policyHash":"sha256:' + b"7" * 64 + b'",'
        b'"principalId":"agent:golden",'
        b'"purpose":"dispatchSecret",'
        b'"recipientKeyId":"sha256:' + b"6" * 64 + b'",'
        b'"recipientNonce":"' + b"B" * 43 + b'",'
        b'"releaseAuthorization":null,'
        b'"requestAuthority":' + expected_authority_json + b','
        b'"routeId":"gmail.messages"}'
    )
    request_binding_sha256 = sha256_prefixed(
        expected_request_binding_json
    )
    if (
        app_module._credential_lease_request_authority_sha256(
            model.request_authority
        )
        != authority_sha256
        or app_module._credential_lease_request_binding_sha256(model)
        != request_binding_sha256
        or credential_lease_request_binding(payload)
        != request_binding_sha256
    ):
        raise AssertionError(
            "Python credential lease v4 golden digest fixture drifted"
        )
    aad = {
        "apiVersion": "serverware.credentialLeaseEnvelope/v3",
        "algorithm": "X25519-HKDF-SHA256-AES-256-GCM",
        "purpose": "dispatchSecret",
        "requestBindingSha256": request_binding_sha256,
        "requestAuthoritySha256": authority_sha256,
        "recipientKeyId": payload["recipientKeyId"],
        "recipientNonce": payload["recipientNonce"],
        "policyHash": payload["policyHash"],
        "dataPlaneBinaryDigest": payload["dataPlaneBinaryDigest"],
        "principalId": payload["principalId"],
        "routeId": payload["routeId"],
        "credentialId": payload["credentialId"],
        "issuedAtEpochMs": 4_102_444_795_000,
        "expiresAtEpochMs": 4_102_444_800_000,
    }
    expected_aad_json = (
        b'{"algorithm":"X25519-HKDF-SHA256-AES-256-GCM",'
        b'"apiVersion":"serverware.credentialLeaseEnvelope/v3",'
        b'"credentialId":"credential:golden",'
        b'"dataPlaneBinaryDigest":"sha256:' + b"8" * 64 + b'",'
        b'"expiresAtEpochMs":4102444800000,'
        b'"issuedAtEpochMs":4102444795000,'
        b'"policyHash":"sha256:' + b"7" * 64 + b'",'
        b'"principalId":"agent:golden",'
        b'"purpose":"dispatchSecret",'
        b'"recipientKeyId":"sha256:' + b"6" * 64 + b'",'
        b'"recipientNonce":"' + b"B" * 43 + b'",'
        b'"requestAuthoritySha256":"' + authority_sha256.encode("ascii") + b'",'
        b'"requestBindingSha256":"' + request_binding_sha256.encode("ascii") + b'",'
        b'"routeId":"gmail.messages"}'
    )
    if (
        tuple(aad) != V4_AAD_FIELDS
        or canonical_json_bytes(aad) != expected_aad_json
    ):
        raise AssertionError(
            "credential lease v4 golden AAD bytes drifted"
        )
    hkdf_info = (
        b"serverware:credential-lease-envelope:v2\0"
        + hashlib.sha256(expected_aad_json).digest()
    )
    if (
        not hkdf_info.startswith(
            b"serverware:credential-lease-envelope:v2\0"
        )
        or len(hkdf_info) != 72
    ):
        raise AssertionError("credential lease v4 HKDF domain drifted")


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        data_dir = Path(tmp)
        verifier_command = shlex.join(
            [sys.executable, str(Path(__file__).resolve()), "--recipient-attestation-verifier"]
        )
        os.environ.update(
            {
                "SERVERWARE_DATA_DIR": tmp,
                "SERVERWARE_ADMIN_TOKEN": ADMIN_TOKEN,
                "SERVERWARE_DATA_PLANE_INSTANCE_ID": "spiffe://test.serverware/decision-gate/credential-lease",
                "SERVERWARE_DATA_PLANE_CREDENTIAL_LEASE_TOKEN": DATA_PLANE_TOKEN,
                "SERVERWARE_DEV_AUTHENTICATOR": "1",
                "SERVERWARE_EXPECTED_DATA_PLANE_BINARY_DIGEST": DATA_PLANE_BINARY_DIGEST,
                "SERVERWARE_DATA_PLANE_LEASE_RECIPIENT_ATTESTATION_REQUIRED": "1",
                "SERVERWARE_DATA_PLANE_LEASE_RECIPIENT_VERIFY_COMMAND": verifier_command,
                "SERVERWARE_KEY_RELEASE_REQUIRED": "1",
                "SERVERWARE_KEY_RELEASE_REQUIRE_DATA_PLANE_DIGEST": "1",
                "SERVERWARE_SECRET_LEASE_TTL_SECONDS": "5",
                "SERVERWARE_METADATA_STORE_BACKEND": "sqlite",
                "SERVERWARE_AUDIT_STORE_BACKEND": "sqlite",
                "SERVERWARE_GRANT_STORE_BACKEND": "sqlite",
                "SERVERWARE_AUDIT_ANCHOR_URL": "",
                "SERVERWARE_DECISION_GATE_BASE": "",
                "SERVERWARE_RELEASE_PROVENANCE": str(data_dir / "release-provenance.json"),
                "SERVERWARE_IMAGE_SIGNATURES": str(data_dir / "image-signatures.json"),
            }
        )
        for name in (
            "SERVERWARE_MASTER_KEY",
            "SERVERWARE_METADATA_STORE_POSTGRES_DSN",
            "SERVERWARE_AUDIT_STORE_POSTGRES_DSN",
            "SERVERWARE_GRANT_STORE_POSTGRES_DSN",
        ):
            os.environ.pop(name, None)

        from serverware import app as app_module
        from serverware import db, key_release, policy_bundle, runtime
        from serverware.auth import AdminIdentity
        from serverware.attestation import runtime_manifest, verify_attestation_quote
        from serverware.ca_material import ensure_mitm_ca_material
        from serverware.constraints import shared_durable_budget_claims

        assert_python_v4_golden(app_module)
        binding_metadata = app_module._credential_lease_public_metadata(
            {
                "secret": "credential-value-not-in-metadata",
                "metadata": {
                    "provider": "npm",
                    "provider_subject": "npm-account-123",
                    "account_subject": "npm-account-123",
                    "secret_class": "automationToken",
                    "token_class": "automationToken",
                    "oauth_client_id": "public-client-id",
                    "client_id": "public-client-id",
                    "provider_identity_verified": True,
                    "refresh_token": "must-not-cross-the-lease-boundary",
                },
            }
        )
        if binding_metadata != {
            "account_subject": "npm-account-123",
            "client_id": "public-client-id",
            "oauth_client_id": "public-client-id",
            "provider": "npm",
            "provider_identity_verified": True,
            "provider_subject": "npm-account-123",
            "secret_class": "automationToken",
            "token_class": "automationToken",
        }:
            raise AssertionError(
                f"credential lease binding metadata contract drifted: {binding_metadata}"
            )
        exact_static_policy = policy_bundle.CredentialPolicy(
            id="credential:binding-test",
            provider="generic",
            provider_subject="account:binding-test",
            injection={"type": "bearer"},
        )
        try:
            app_module._assert_credential_policy_binding(
                {
                    "kind": "bearer",
                    "metadata": {
                        "provider": "npm",
                        "provider_subject": "account:binding-test",
                        "secret_class": "automationToken",
                    },
                },
                exact_static_policy,
            )
        except HTTPException as exc:
            if exc.status_code != 409 or "provider" not in str(exc.detail):
                raise AssertionError(
                    f"generic provider mismatch failed incorrectly: {exc}"
                ) from exc
        else:
            raise AssertionError("generic signed provider acted as a wildcard")
        scoped_static_policy = policy_bundle.CredentialPolicy(
            id="credential:scope-test",
            provider="npm",
            provider_subject="account:binding-test",
            scopes=("package.publish",),
            injection={"type": "bearer"},
        )
        try:
            app_module._assert_credential_policy_binding(
                {
                    "kind": "bearer",
                    "metadata": {
                        "provider": "npm",
                        "provider_subject": "account:binding-test",
                        "secret_class": "automationToken",
                    },
                },
                scoped_static_policy,
            )
        except HTTPException as exc:
            if exc.status_code != 409 or "scopes" not in str(exc.detail):
                raise AssertionError(
                    f"static scope mismatch failed incorrectly: {exc}"
                ) from exc
        else:
            raise AssertionError("static credential scope drift was accepted")
        try:
            app_module._credential_metadata_scopes(
                {
                    "scopes": ["package.publish"],
                    "scope": "package.read",
                }
            )
        except HTTPException as exc:
            if exc.status_code != 409 or "contradictory" not in str(exc.detail):
                raise AssertionError(
                    f"scope alias contradiction failed incorrectly: {exc}"
                ) from exc
        else:
            raise AssertionError("contradictory scope aliases were accepted")
        ensure_mitm_ca_material()
        db.init_db()
        original_replay_max = db.CREDENTIAL_LEASE_REPLAY_MAX_ENTRIES
        db.CREDENTIAL_LEASE_REPLAY_MAX_ENTRIES = 2
        try:
            replay_now = 1_000_000
            if db.reserve_credential_lease_nonce("key-a", "nonce-a", now_epoch_ms=replay_now) is not None:
                raise AssertionError("first replay reservation failed")
            if db.reserve_credential_lease_nonce("key-a", "nonce-a", now_epoch_ms=replay_now) != "replay":
                raise AssertionError("duplicate replay reservation was accepted")
            if db.reserve_credential_lease_nonce("key-b", "nonce-b", now_epoch_ms=replay_now) is not None:
                raise AssertionError("second replay reservation failed")
            if db.reserve_credential_lease_nonce("key-c", "nonce-c", now_epoch_ms=replay_now) != "capacity":
                raise AssertionError("bounded replay store exceeded capacity")
            after_retention = replay_now + db._CREDENTIAL_LEASE_REPLAY_RETENTION_MS + 1
            if db.reserve_credential_lease_nonce("key-c", "nonce-c", now_epoch_ms=after_retention) is not None:
                raise AssertionError("expired replay reservations did not release capacity")
            with db.connect() as replay_conn:
                stored = replay_conn.execute(
                    "SELECT nonce_count FROM credential_lease_replay_state WHERE scope = ?",
                    ("global",),
                ).fetchone()
                actual = replay_conn.execute(
                    "SELECT COUNT(*) AS count FROM credential_lease_nonces"
                ).fetchone()
                if int(stored["nonce_count"]) != int(actual["count"]):
                    raise AssertionError(f"replay counter drifted from stored nonces: {dict(stored)} {dict(actual)}")
                replay_conn.execute("DELETE FROM credential_lease_nonces")
                replay_conn.execute("DELETE FROM credential_lease_replay_state")
        finally:
            db.CREDENTIAL_LEASE_REPLAY_MAX_ENTRIES = original_replay_max
        if runtime_manifest().get("credential_lease_protocol") != "serverware.credentialLeaseEnvelope/v2":
            raise AssertionError("attested credential lease protocol drifted from envelope v2")

        original_registration_release_channel = app_module.RELEASE_CHANNEL
        original_bootstrap_token = app_module.WEBAUTHN_BOOTSTRAP_TOKEN
        app_module.RELEASE_CHANNEL = "prod"
        app_module.WEBAUTHN_BOOTSTRAP_TOKEN = "test-webauthn-bootstrap-token-at-least-32-characters"
        registration_identity = AdminIdentity(
            user_id="user:bootstrap-test",
            roles=frozenset({"admin"}),
            auth_method="test",
        )
        try:
            try:
                app_module.webauthn_register_options(
                    app_module.WebAuthnRegistrationStart(label="YubiKey", bootstrapToken="wrong-token"),
                    registration_identity,
                )
            except HTTPException as exc:
                if exc.status_code != 403 or "bootstrap token" not in str(exc.detail):
                    raise AssertionError(f"first WebAuthn enrollment failed incorrectly: {exc}") from exc
            else:
                raise AssertionError("first production WebAuthn enrollment accepted an invalid bootstrap token")
            enrollment_options = app_module.webauthn_register_options(
                app_module.WebAuthnRegistrationStart(
                    label="YubiKey",
                    bootstrapToken=app_module.WEBAUTHN_BOOTSTRAP_TOKEN,
                ),
                registration_identity,
            )
            if (enrollment_options.get("serverware") or {}).get("authorizationMode") != "bootstrap-token":
                raise AssertionError(f"first WebAuthn enrollment was not bootstrap-bound: {enrollment_options}")
        finally:
            app_module.RELEASE_CHANNEL = original_registration_release_channel
            app_module.WEBAUTHN_BOOTSTRAP_TOKEN = original_bootstrap_token

        oversized_control_plane_request = app_request(
            app_module.app,
            "POST",
            "/api/credentials",
            payload={"padding": "x" * (2 * 1024 * 1024)},
            headers={
                "X-Serverware-Admin-Token": ADMIN_TOKEN,
                "X-Serverware-Response-Nonce": "oversized-control-plane-request",
            },
        )
        assert_status(
            oversized_control_plane_request,
            413,
            "aggregate control-plane request limit",
            "exceeds 2 MiB",
        )

        original_release_channel = app_module.RELEASE_CHANNEL
        original_attestation_required = app_module.DATA_PLANE_LEASE_RECIPIENT_ATTESTATION_REQUIRED
        original_verifier_command = app_module.DATA_PLANE_LEASE_RECIPIENT_VERIFY_COMMAND
        app_module.RELEASE_CHANNEL = "prod"
        app_module.DATA_PLANE_LEASE_RECIPIENT_ATTESTATION_REQUIRED = False
        app_module.DATA_PLANE_LEASE_RECIPIENT_VERIFY_COMMAND = ""
        try:
            app_module._verify_credential_lease_recipient_attestation(
                None,
                purpose="generationMetadata",
                request_binding_sha256="sha256:" + "0" * 64,
                request_authority_sha256=None,
                recipient_key_id="sha256:" + "1" * 64,
                recipient_nonce=b64e(recipient_nonce("production-misconfiguration")),
                policy_hash_value="sha256:" + "2" * 64,
                data_plane_binary_digest=DATA_PLANE_BINARY_DIGEST,
                principal_id=PRINCIPAL_ID,
                route_id=ROUTE_ID,
                credential_id=CREDENTIAL_ID,
            )
        except HTTPException as exc:
            if exc.status_code != 503 or "not configured fail-closed" not in str(exc.detail):
                raise AssertionError(f"production attestation misconfiguration failed incorrectly: {exc}") from exc
        else:
            raise AssertionError("production recipient attestation misconfiguration was accepted")
        finally:
            app_module.RELEASE_CHANNEL = original_release_channel
            app_module.DATA_PLANE_LEASE_RECIPIENT_ATTESTATION_REQUIRED = original_attestation_required
            app_module.DATA_PLANE_LEASE_RECIPIENT_VERIFY_COMMAND = original_verifier_command

        for metadata_key in (
            "client_secret",
            "clientSecret",
            "client.secret",
            "oauthAccessToken",
            "refresh-token",
            "token",
        ):
            try:
                db.create_credential(
                    f"secret-bearing-metadata-{metadata_key}",
                    "bearer",
                    "safe-secret-field",
                    {metadata_key: "must-not-be-plaintext-metadata"},
                )
            except ValueError as exc:
                if "secret material" not in str(exc):
                    raise AssertionError(f"secret-bearing metadata failed incorrectly: {exc}") from exc
            else:
                raise AssertionError(f"secret-bearing credential metadata key was accepted: {metadata_key}")

        original_dev_authenticator = app_module.DEV_AUTHENTICATOR_ENABLED
        app_module.DEV_AUTHENTICATOR_ENABLED = False
        try:
            app_module.seed_demo()
        except HTTPException as exc:
            if exc.status_code != 404:
                raise AssertionError(f"production demo seed failed incorrectly: {exc}") from exc
        else:
            raise AssertionError("demo seed endpoint was available without the development authenticator")
        finally:
            app_module.DEV_AUTHENTICATOR_ENABLED = original_dev_authenticator

        snapshot_before_seed = policy_bundle.get_policy_snapshot()
        sequence_before_seed = (
            int(snapshot_before_seed.raw["metadata"]["sequence"])
            if snapshot_before_seed is not None
            else 0
        )
        seed_nonce = "credential-lease-seed-response"
        seed_response = app_request(
            app_module.app,
            "POST",
            "/api/demo/seed",
            headers={
                "X-Serverware-Admin-Token": ADMIN_TOKEN,
                "X-Serverware-Response-Nonce": seed_nonce,
            },
        )
        assert_status(seed_response, 200, "demo seed")
        if CREDENTIAL_SECRET.encode("ascii") in seed_response.body:
            raise AssertionError("demo seed response exposed the plaintext credential")
        seed_payload = json.loads(seed_response.body)
        streaming_routes = [
            route for route in seed_payload["routes"] if route["id"].endswith(".stream")
        ]
        if not streaming_routes or any(
            route.get("credential_id") is not None or route.get("injection")
            for route in streaming_routes
        ):
            raise AssertionError("streaming demo routes retained a credential assignment")
        policy_bundle.POLICY_BUNDLE_PATH.unlink()
        policy_bundle._SNAPSHOT_CACHE = None
        restart_seed_nonce = "credential-lease-restart-seed-response"
        restarted_seed = app_request(
            app_module.app,
            "POST",
            "/api/demo/seed",
            headers={
                "X-Serverware-Admin-Token": ADMIN_TOKEN,
                "X-Serverware-Response-Nonce": restart_seed_nonce,
            },
        )
        assert_status(restarted_seed, 200, "demo seed after policy-file loss")
        restarted_seed_payload = json.loads(restarted_seed.body)
        if restarted_seed_payload["policy_sequence"] <= seed_payload["policy_sequence"]:
            raise AssertionError("demo seed did not advance persisted policy high-water after restart")
        key_release_status = key_release.status()
        if key_release_status.get("enabled") is not True or "broker-kek" not in (
            key_release_status.get("materials") or {}
        ):
            raise AssertionError(f"broker key release gate was not enforced: {key_release_status}")

        concurrent = db.create_credential("concurrent-rotation", "bearer", "version-one", {"purpose": "test"})
        barrier = threading.Barrier(3)

        def rotate_concurrently(secret: str) -> dict[str, Any] | None:
            barrier.wait()
            return db.update_credential(concurrent["id"], {"secret": secret})

        with ThreadPoolExecutor(max_workers=2) as pool:
            rotations = [
                pool.submit(rotate_concurrently, "version-two-a"),
                pool.submit(rotate_concurrently, "version-two-b"),
            ]
            barrier.wait()
            rotated = [future.result(timeout=15) for future in rotations]
        versions = sorted(int(item["credential_version"]) for item in rotated if item is not None)
        if versions != [2, 3]:
            raise AssertionError(f"concurrent credential rotations reused a version: {rotated}")
        db.delete_credential(concurrent["id"])

        lease_locked = db.create_credential("lease-lock", "bearer", "lease-version-one", {"purpose": "test"})
        snapshot_acquired = threading.Event()
        release_snapshot = threading.Event()
        mutation_started = threading.Event()
        mutation_completed = threading.Event()

        def hold_lease_snapshot() -> tuple[int, str]:
            with db.credential_lease_snapshot(lease_locked["id"]) as leased:
                if leased is None:
                    raise AssertionError("lease snapshot did not find its credential")
                snapshot_acquired.set()
                if not release_snapshot.wait(10):
                    raise AssertionError("lease snapshot release timed out")
                return int(leased["credential_version"]), str(leased["secret"])

        def rotate_after_snapshot() -> dict[str, Any] | None:
            mutation_started.set()
            try:
                return db.update_credential(lease_locked["id"], {"secret": "lease-version-two"})
            finally:
                mutation_completed.set()

        with ThreadPoolExecutor(max_workers=2) as pool:
            snapshot_future = pool.submit(hold_lease_snapshot)
            if not snapshot_acquired.wait(10):
                raise AssertionError("lease snapshot was not acquired")
            mutation_future = pool.submit(rotate_after_snapshot)
            if not mutation_started.wait(10):
                raise AssertionError("credential rotation did not start")
            if mutation_completed.wait(0.25):
                raise AssertionError("credential rotation crossed an active lease snapshot")
            release_snapshot.set()
            leased_version, leased_secret = snapshot_future.result(timeout=15)
            rotated_after_lease = mutation_future.result(timeout=15)
        if (leased_version, leased_secret) != (1, "lease-version-one"):
            raise AssertionError("lease snapshot did not preserve one immutable credential generation")
        if rotated_after_lease is None or int(rotated_after_lease["credential_version"]) != 2:
            raise AssertionError(f"post-lease rotation did not advance the generation: {rotated_after_lease}")
        db.delete_credential(lease_locked["id"])

        seeded = restarted_seed.json()
        snapshot = policy_bundle.get_policy_snapshot()
        if snapshot is None or seeded.get("policy_hash") != snapshot.hash:
            raise AssertionError(f"demo seed did not activate its signed policy: {seeded}")
        seeded_sequence = int(snapshot.raw["metadata"]["sequence"])
        if seeded_sequence <= sequence_before_seed or seeded.get("policy_sequence") != seeded_sequence:
            raise AssertionError(
                f"demo seed did not monotonically advance and report the policy sequence: {seeded}"
            )
        signed_policy = json.loads((data_dir / "policy-bundle.json").read_text(encoding="utf-8"))
        if not signed_policy.get("metadata", {}).get("signature") or not signed_policy["metadata"].get("signingKeyId"):
            raise AssertionError("demo policy was not signed")
        compiled = policy_bundle.compile_policy_bundle(signed_policy, verify_signature=True, validate_schema=True)
        if compiled.hash != snapshot.hash:
            raise AssertionError("signed demo policy did not compile to the active policy hash")

        attestation_nonce = "credential-lease-response-key"
        attestation_target = f"/attestation?nonce={attestation_nonce}"
        attestation_response = app_request(
            app_module.app,
            "GET",
            attestation_target,
            headers={"X-Serverware-Response-Nonce": attestation_nonce},
        )
        assert_status(attestation_response, 200, "attestation")
        attestation = attestation_response.json()
        claims = verify_attestation_quote(attestation)
        response_key_pem = attestation["response_signing_public_key_pem"].encode("ascii")
        loaded_key = serialization.load_pem_public_key(response_key_pem)
        if not isinstance(loaded_key, Ed25519PublicKey):
            raise AssertionError("attested response signing key is not Ed25519")
        response_public_key = loaded_key
        response_key_der = response_public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        response_key_id = sha256_prefixed(response_key_der)
        if response_key_id != attestation.get("response_signing_key_id"):
            raise AssertionError("attested response signing key ID does not match its public key")
        if claims.get("response_signing_key_id") != response_key_id:
            raise AssertionError("attestation quote does not bind the response signing key")
        if claims.get("policy_bundle_digest") != snapshot.hash:
            raise AssertionError("attestation quote does not bind the active signed policy")
        if claims.get("data_plane_binary_digest") != DATA_PLANE_BINARY_DIGEST:
            raise AssertionError("attestation quote does not bind the expected data-plane binary")

        verify_response_signature(
            attestation_response,
            public_key=response_public_key,
            key_id=response_key_id,
            method="GET",
            target=attestation_target,
            response_nonce=attestation_nonce,
            policy_hash=snapshot.hash,
        )
        verify_response_signature(
            restarted_seed,
            public_key=response_public_key,
            key_id=response_key_id,
            method="POST",
            target="/api/demo/seed",
            response_nonce=restart_seed_nonce,
            policy_hash=snapshot.hash,
        )

        recipient_private_key = X25519PrivateKey.generate()
        recipient_public_key_raw = recipient_private_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        if len(recipient_public_key_raw) != 32:
            raise AssertionError("generated X25519 recipient public key is not 32 bytes")

        lease_responses: list[AppResponse] = []

        def post_lease(
            payload: dict[str, Any],
            label: str,
            *,
            token: str = DATA_PLANE_TOKEN,
        ) -> AppResponse:
            response_nonce = f"credential-lease-response:{label}"
            response = app_request(
                app_module.app,
                "POST",
                LEASE_PATH,
                payload=payload,
                headers={
                    "X-Serverware-Data-Plane-Token": token,
                    "X-Serverware-Response-Nonce": response_nonce,
                },
            )
            verify_response_signature(
                response,
                public_key=response_public_key,
                key_id=response_key_id,
                method="POST",
                target=LEASE_PATH,
                response_nonce=response_nonce,
                policy_hash=snapshot.hash,
            )
            if CREDENTIAL_SECRET.encode("ascii") in response.body:
                raise AssertionError(f"{label} response exposed the plaintext credential")
            lease_responses.append(response)
            return response

        initial_payload = lease_payload(recipient_public_key_raw, snapshot.hash, "initial")
        if (
            initial_payload["apiVersion"]
            != "serverware.credentialLeaseRequest/v3"
            or "requestAuthority" in initial_payload
            or "releaseAuthorization" in initial_payload
            or "requestAuthoritySha256"
            in initial_payload["recipientAttestation"]
        ):
            raise AssertionError(
                "generationMetadata did not omit both authority fields"
            )
        verifier_counter = data_dir / "recipient-verifier-count.txt"
        initial_payload["recipientAttestation"]["testVerifierCounterPath"] = str(verifier_counter)
        original_credential_for_lease = app_module._credential_for_lease
        original_credential_lease_snapshot = db.credential_lease_snapshot
        original_load_master_key = db.load_master_key
        original_decrypt_secret_envelope = db.decrypt_secret_envelope

        def reject_generation_refresh(_credential_id: str) -> dict[str, Any] | None:
            raise AssertionError("generation metadata entered the credential refresh path")

        def reject_generation_secret_snapshot(_credential_id: str) -> Any:
            raise AssertionError("generation metadata entered the secret snapshot path")

        def reject_generation_master_key_load() -> bytes:
            raise AssertionError("generation metadata loaded the credential master key")

        def reject_generation_decrypt(_row: Any) -> str:
            raise AssertionError("generation metadata decrypted credential material")

        app_module._credential_for_lease = reject_generation_refresh
        db.credential_lease_snapshot = reject_generation_secret_snapshot
        db.load_master_key = reject_generation_master_key_load
        db.decrypt_secret_envelope = reject_generation_decrypt
        try:
            initial_response = post_lease(initial_payload, "initial")
        finally:
            app_module._credential_for_lease = original_credential_for_lease
            db.credential_lease_snapshot = original_credential_lease_snapshot
            db.load_master_key = original_load_master_key
            db.decrypt_secret_envelope = original_decrypt_secret_envelope
        assert_status(initial_response, 200, "initial credential lease")
        initial_plaintext = decrypt_lease(
            initial_response.json(),
            recipient_private_key=recipient_private_key,
            recipient_nonce_raw=recipient_nonce("initial"),
            request_payload=initial_payload,
        )
        initial_metadata_sha256 = credential_metadata_sha256(INITIAL_METADATA)
        expected_initial_generation = {
            "credentialId": CREDENTIAL_ID,
            "credentialVersion": 1,
            "metadataSha256": initial_metadata_sha256,
            "metadata": INITIAL_METADATA,
        }
        if initial_plaintext["credentials"] != [expected_initial_generation]:
            raise AssertionError(f"initial credential lease contents are incorrect: {initial_plaintext}")
        if CREDENTIAL_SECRET in canonical_json_bytes(initial_plaintext).decode("utf-8"):
            raise AssertionError("generation metadata plaintext contains credential secret material")
        if "fingerprint" in canonical_json_bytes(initial_plaintext).decode("utf-8").lower():
            raise AssertionError("generation metadata plaintext contains a secret fingerprint")

        dispatch_payload = lease_payload(
            recipient_public_key_raw,
            snapshot.hash,
            "initial-dispatch",
            purpose="dispatchSecret",
            expected_credential_version=1,
            expected_metadata_sha256=initial_metadata_sha256,
        )
        if (
            dispatch_payload["apiVersion"]
            != "serverware.credentialLeaseRequest/v3"
            or "requestAuthority" in dispatch_payload
            or "releaseAuthorization" in dispatch_payload
        ):
            raise AssertionError(
                "legacy uncontrolled dispatch did not omit authority fields"
            )
        dispatch_calls = 0
        injection_binding_calls = 0
        route_binding_calls = 0
        original_assert_injection_binding = (
            app_module._assert_credential_injection_binding
        )
        original_assert_route_binding = app_module._assert_route_credential_binding

        def count_dispatch_refresh(credential_id: str) -> dict[str, Any] | None:
            nonlocal dispatch_calls
            dispatch_calls += 1
            return original_credential_for_lease(credential_id)

        def count_injection_binding(
            credential: dict[str, Any], credential_policy: Any
        ) -> None:
            nonlocal injection_binding_calls
            injection_binding_calls += 1
            original_assert_injection_binding(credential, credential_policy)

        def count_route_binding(
            route: Any,
            credential: dict[str, Any],
            credential_policy: Any,
        ) -> None:
            nonlocal route_binding_calls
            route_binding_calls += 1
            original_assert_route_binding(route, credential, credential_policy)

        app_module._credential_for_lease = count_dispatch_refresh
        app_module._assert_credential_injection_binding = count_injection_binding
        app_module._assert_route_credential_binding = count_route_binding
        try:
            dispatch_response = post_lease(dispatch_payload, "initial-dispatch")
        finally:
            app_module._credential_for_lease = original_credential_for_lease
            app_module._assert_credential_injection_binding = (
                original_assert_injection_binding
            )
            app_module._assert_route_credential_binding = original_assert_route_binding
        assert_status(dispatch_response, 200, "initial dispatch credential lease")
        dispatch_plaintext = decrypt_lease(
            dispatch_response.json(),
            recipient_private_key=recipient_private_key,
            recipient_nonce_raw=recipient_nonce("initial-dispatch"),
            request_payload=dispatch_payload,
        )
        expected_initial_secret = {
            **expected_initial_generation,
            "secret": CREDENTIAL_SECRET,
        }
        if dispatch_plaintext["credentials"] != [expected_initial_secret]:
            raise AssertionError(
                f"initial dispatch credential lease contents are incorrect: {dispatch_plaintext}"
            )
        if dispatch_calls != 1:
            raise AssertionError(f"dispatch secret refresh path called {dispatch_calls} times")
        if injection_binding_calls != 2:
            raise AssertionError(
                "dispatch secret lease did not revalidate injection binding before "
                f"and inside the immutable snapshot: {injection_binding_calls}"
            )
        if route_binding_calls != 2:
            raise AssertionError(
                "dispatch secret lease did not revalidate exact route binding before "
                f"and inside the immutable snapshot: {route_binding_calls}"
            )

        original_active_route_by_id = app_module._active_route_by_id
        original_atomic_release_enabled = (
            app_module.ATOMIC_RELEASE_AUTHORIZATION_ENABLED
        )
        base_route = original_active_route_by_id(ROUTE_ID, snapshot=snapshot)
        atomic_route = replace(
            base_route,
            jit={"required": False},
            constraints=(
                *base_route.constraints,
                {
                    "id": "credential-lease-atomic-fixture",
                    "type": "rateLimit",
                    "phase": "request",
                    "store": "shared",
                    "max": 1,
                    "windowSeconds": 60,
                    "key": {"scope": ["route", "operation"]},
                },
            ),
        )
        atomic_attempt_id = "sha256:" + "d" * 64
        atomic_request_digest = "sha256:" + "e" * 64
        atomic_operation_digest = "sha256:" + "f" * 64
        atomic_quota = {
            "counter_key": "sha256:" + "1" * 64,
            "constraint_id": "credential-lease-atomic-fixture",
            "operation": "demo.echo",
            "window_kind": "fixed",
            "window_seconds": 60,
            "max_count": 1,
        }
        atomic_expected = runtime.expected_release_authorization_identity(
            attempt_id=atomic_attempt_id,
            flow_id=atomic_attempt_id,
            principal_id=PRINCIPAL_ID,
            route_id=ROUTE_ID,
            credential_ref=CREDENTIAL_ID,
            credential_version=1,
            policy_hash=snapshot.hash,
            request_digest=atomic_request_digest,
            operation_digest=atomic_operation_digest,
            operation_context={"operation": "demo.echo"},
            shared_quotas=[atomic_quota],
            require_jit_grant=False,
        )
        atomic_reserved = runtime._normalized_direct_release_authorization_response(
            db.reserve_release_authorization(
                attempt_id=atomic_attempt_id,
                flow_id=atomic_attempt_id,
                principal_id=PRINCIPAL_ID,
                route_id=ROUTE_ID,
                credential_id=CREDENTIAL_ID,
                credential_version=1,
                policy_hash=snapshot.hash,
                request_digest=atomic_request_digest,
                operation_digest=atomic_operation_digest,
                operation_context={"operation": "demo.echo"},
                shared_quotas=[atomic_quota],
                require_jit_grant=False,
                reservation_ttl_seconds=60,
                actor_id="spiffe://test.serverware/decision-gate/credential-lease",
            )
        )
        runtime.validate_reserve_release_authorization_response(
            atomic_reserved,
            attempt_id=atomic_attempt_id,
            require_jit_grant=False,
            expected_binding_digest=atomic_expected.binding_digest,
            expected_shared_quotas=[atomic_quota],
        )
        atomic_release_authorization = (
            runtime.credential_lease_release_authorization(
                atomic_expected,
                atomic_reserved,
            )
        )
        if atomic_release_authorization is None:
            raise AssertionError(
                "non-JIT shared quota did not produce credential release authority"
            )
        atomic_request_authority = runtime.credential_lease_request_authority(
            atomic_expected,
            atomic_reserved,
            operation_context={"operation": "demo.echo"},
            controlled=True,
        )
        if atomic_request_authority is None:
            raise AssertionError(
                "non-JIT shared quota did not produce request authority"
            )
        if (
            runtime.credential_lease_request_authority(
                atomic_expected,
                atomic_reserved,
                operation_context={"operation": "demo.echo"},
                controlled=False,
            )
            is not None
        ):
            raise AssertionError(
                "uncontrolled credential dispatch unexpectedly gained request authority"
            )
        atomic_payload = lease_payload(
            recipient_public_key_raw,
            snapshot.hash,
            "atomic-dispatch",
            purpose="dispatchSecret",
            expected_credential_version=1,
            expected_metadata_sha256=initial_metadata_sha256,
            request_authority=atomic_request_authority,
            release_authorization=atomic_release_authorization,
        )
        if atomic_payload["recipientAttestation"].get(
            "requestAuthoritySha256"
        ) != sha256_prefixed(
            canonical_json_bytes(atomic_request_authority)
        ):
            raise AssertionError(
                "credential lease v4 recipient attestation lost request authority"
            )
        app_module._active_route_by_id = (
            lambda route_id, *, snapshot=None: (
                atomic_route
                if route_id == ROUTE_ID
                else original_active_route_by_id(route_id, snapshot=snapshot)
            )
        )
        app_module.ATOMIC_RELEASE_AUTHORIZATION_ENABLED = True
        try:
            atomic_response = post_lease(
                atomic_payload, "atomic-dispatch"
            )
            assert_status(
                atomic_response,
                200,
                "non-JIT atomic dispatch credential lease",
            )
            atomic_plaintext = decrypt_lease(
                atomic_response.json(),
                recipient_private_key=recipient_private_key,
                recipient_nonce_raw=recipient_nonce("atomic-dispatch"),
                request_payload=atomic_payload,
            )
            if atomic_plaintext["credentials"] != [expected_initial_secret]:
                raise AssertionError(
                    "non-JIT atomic dispatch returned wrong credential material"
                )
            replay_payload = lease_payload(
                recipient_public_key_raw,
                snapshot.hash,
                "atomic-dispatch-replay",
                purpose="dispatchSecret",
                expected_credential_version=1,
                expected_metadata_sha256=initial_metadata_sha256,
                request_authority=atomic_request_authority,
                release_authorization=atomic_release_authorization,
            )
            assert_status(
                post_lease(replay_payload, "atomic-dispatch-replay"),
                409,
                "non-JIT atomic dispatch replay",
                "already issued credential material",
            )
        finally:
            app_module.ATOMIC_RELEASE_AUTHORIZATION_ENABLED = (
                original_atomic_release_enabled
            )
            app_module._active_route_by_id = original_active_route_by_id

        gmail_traversal_constraint = {
            "id": "credential-lease-gmail-traversal-fixture",
            "type": "traversalBudget",
            "store": "shared",
            "maxPages": 2,
            "reservationMode": "atomicReserveCommitRelease",
            "onOverflow": "deny",
            "requestSource": "query",
            "requestField": "pageToken",
            "responseField": "nextPageToken",
            "operations": ["gmail.message.list"],
            "key": {
                "scope": [
                    "principal",
                    "route",
                    "credential",
                    "credentialVersion",
                    "operation",
                ]
            },
        }
        gmail_route = replace(
            base_route,
            jit={"required": False},
            constraints=(gmail_traversal_constraint,),
        )
        gmail_get_attempt_id = "sha256:" + "5" * 64
        gmail_get_request_digest = "sha256:" + "6" * 64
        gmail_get_operation_digest = "sha256:" + "7" * 64
        gmail_get_operation = {"operation": "gmail.message.get"}
        gmail_get_expected = runtime.expected_release_authorization_identity(
            attempt_id=gmail_get_attempt_id,
            flow_id=gmail_get_attempt_id,
            principal_id=PRINCIPAL_ID,
            route_id=ROUTE_ID,
            credential_ref=CREDENTIAL_ID,
            credential_version=1,
            policy_hash=snapshot.hash,
            request_digest=gmail_get_request_digest,
            operation_digest=gmail_get_operation_digest,
            operation_context=gmail_get_operation,
            shared_quotas=[],
            require_jit_grant=False,
        )
        gmail_get_reserved = (
            runtime._normalized_direct_release_authorization_response(
                db.reserve_release_authorization(
                    attempt_id=gmail_get_attempt_id,
                    flow_id=gmail_get_attempt_id,
                    principal_id=PRINCIPAL_ID,
                    route_id=ROUTE_ID,
                    credential_id=CREDENTIAL_ID,
                    credential_version=1,
                    policy_hash=snapshot.hash,
                    request_digest=gmail_get_request_digest,
                    operation_digest=gmail_get_operation_digest,
                    operation_context=gmail_get_operation,
                    shared_quotas=[],
                    require_jit_grant=False,
                    reservation_ttl_seconds=60,
                    actor_id=(
                        "spiffe://test.serverware/decision-gate/"
                        "credential-lease"
                    ),
                )
            )
        )
        runtime.validate_reserve_release_authorization_response(
            gmail_get_reserved,
            attempt_id=gmail_get_attempt_id,
            require_jit_grant=False,
            expected_binding_digest=gmail_get_expected.binding_digest,
            expected_shared_quotas=[],
        )
        gmail_get_authority = credential_request_authority(
            attempt_id=gmail_get_attempt_id,
            reservation_id=db.release_reservation_id(
                gmail_get_attempt_id,
                gmail_get_expected.binding_digest,
            ),
            binding_digest=gmail_get_expected.binding_digest,
            request_digest=gmail_get_request_digest,
            operation_digest=gmail_get_operation_digest,
            operation_context=gmail_get_operation,
            reservation_expires_at_epoch_ms=gmail_get_reserved[
                "reservation_expires_at_epoch_ms"
            ],
        )

        def gmail_get_payload(
            label: str,
            *,
            authority: dict[str, Any] | None = None,
            release: dict[str, Any] | None = None,
        ) -> dict[str, Any]:
            return lease_payload(
                recipient_public_key_raw,
                snapshot.hash,
                label,
                purpose="dispatchSecret",
                expected_credential_version=1,
                expected_metadata_sha256=initial_metadata_sha256,
                request_authority=(
                    gmail_get_authority
                    if authority is None
                    else authority
                ),
                release_authorization=release,
            )

        app_module._active_route_by_id = (
            lambda route_id, *, snapshot=None: (
                gmail_route
                if route_id == ROUTE_ID
                else original_active_route_by_id(
                    route_id,
                    snapshot=snapshot,
                )
            )
        )
        app_module.ATOMIC_RELEASE_AUTHORIZATION_ENABLED = True
        try:
            legacy_controlled = lease_payload(
                recipient_public_key_raw,
                snapshot.hash,
                "gmail-get-legacy-v3",
                purpose="dispatchSecret",
                expected_credential_version=1,
                expected_metadata_sha256=initial_metadata_sha256,
            )
            assert_status(
                post_lease(legacy_controlled, "gmail-get-legacy-v3"),
                409,
                "legacy v3 controlled route",
                "operation-bound credential lease v4",
            )

            omitted_authority = gmail_get_payload(
                "gmail-get-omitted-authority"
            )
            omitted_authority.pop("requestAuthority")
            assert_status(
                post_lease(
                    omitted_authority,
                    "gmail-get-omitted-authority",
                ),
                422,
                "v4 omitted request authority",
                "requires exact requestAuthority",
            )
            omitted_release = gmail_get_payload(
                "gmail-get-omitted-release"
            )
            omitted_release.pop("releaseAuthorization")
            assert_status(
                post_lease(
                    omitted_release,
                    "gmail-get-omitted-release",
                ),
                422,
                "v4 omitted nullable release field",
                "requires exact requestAuthority",
            )

            substituted_authorities = []
            substituted_attempt = {
                **gmail_get_authority,
                "attemptId": "sha256:" + "8" * 64,
            }
            substituted_attempt["reservationId"] = db.release_reservation_id(
                substituted_attempt["attemptId"],
                substituted_attempt["bindingDigest"],
            )
            substituted_authorities.append(
                ("attempt", substituted_attempt)
            )
            substituted_binding = {
                **gmail_get_authority,
                "bindingDigest": "sha256:" + "9" * 64,
            }
            substituted_binding["reservationId"] = db.release_reservation_id(
                substituted_binding["attemptId"],
                substituted_binding["bindingDigest"],
            )
            substituted_authorities.extend(
                [
                    ("binding", substituted_binding),
                    (
                        "request-digest",
                        {
                            **gmail_get_authority,
                            "requestDigest": "sha256:" + "a" * 64,
                        },
                    ),
                    (
                        "operation-digest",
                        {
                            **gmail_get_authority,
                            "operationDigest": "sha256:" + "b" * 64,
                        },
                    ),
                    (
                        "operation",
                        {
                            **gmail_get_authority,
                            "operationContext": {
                                "operation": "gmail.message.list"
                            },
                        },
                    ),
                    (
                        "expiry",
                        {
                            **gmail_get_authority,
                            "reservationExpiresAtEpochMs": 1,
                        },
                    ),
                ]
            )
            for label, substituted_authority in substituted_authorities:
                substituted_payload = gmail_get_payload(
                    f"gmail-get-substituted-{label}",
                    authority=substituted_authority,
                )
                if (
                    credential_lease_request_binding(substituted_payload)
                    == credential_lease_request_binding(
                        gmail_get_payload(
                            f"gmail-get-binding-baseline-{label}"
                        )
                    )
                    or sha256_prefixed(
                        canonical_json_bytes(substituted_authority)
                    )
                    == sha256_prefixed(
                        canonical_json_bytes(gmail_get_authority)
                    )
                ):
                    raise AssertionError(
                        "request authority substitution did not isolate "
                        f"credential lease identity: {label}"
                    )
                assert_status(
                    post_lease(
                        substituted_payload,
                        f"gmail-get-substituted-{label}",
                    ),
                    409,
                    f"v4 substituted {label}",
                )

            crossed_release = gmail_get_payload(
                "gmail-get-crossed-release",
                release=atomic_release_authorization,
            )
            assert_status(
                post_lease(
                    crossed_release,
                    "gmail-get-crossed-release",
                ),
                409,
                "decision-bound crossed release authority",
                "must omit durable release authorization",
            )

            gmail_list_attempt_id = "sha256:" + "c" * 64
            gmail_list_request_digest = "sha256:" + "d" * 64
            gmail_list_operation_digest = "sha256:" + "e" * 64
            gmail_list_operation = {"operation": "gmail.message.list"}
            gmail_list_expected = (
                runtime.expected_release_authorization_identity(
                    attempt_id=gmail_list_attempt_id,
                    flow_id=gmail_list_attempt_id,
                    principal_id=PRINCIPAL_ID,
                    route_id=ROUTE_ID,
                    credential_ref=CREDENTIAL_ID,
                    credential_version=1,
                    policy_hash=snapshot.hash,
                    request_digest=gmail_list_request_digest,
                    operation_digest=gmail_list_operation_digest,
                    operation_context=gmail_list_operation,
                    shared_quotas=[],
                    require_jit_grant=False,
                )
            )
            gmail_list_reserved = (
                runtime._normalized_direct_release_authorization_response(
                    db.reserve_release_authorization(
                        attempt_id=gmail_list_attempt_id,
                        flow_id=gmail_list_attempt_id,
                        principal_id=PRINCIPAL_ID,
                        route_id=ROUTE_ID,
                        credential_id=CREDENTIAL_ID,
                        credential_version=1,
                        policy_hash=snapshot.hash,
                        request_digest=gmail_list_request_digest,
                        operation_digest=gmail_list_operation_digest,
                        operation_context=gmail_list_operation,
                        shared_quotas=[],
                        require_jit_grant=False,
                        reservation_ttl_seconds=60,
                        actor_id=(
                            "spiffe://test.serverware/decision-gate/"
                            "credential-lease"
                        ),
                    )
                )
            )
            gmail_list_authority = credential_request_authority(
                attempt_id=gmail_list_attempt_id,
                reservation_id=db.release_reservation_id(
                    gmail_list_attempt_id,
                    gmail_list_expected.binding_digest,
                ),
                binding_digest=gmail_list_expected.binding_digest,
                request_digest=gmail_list_request_digest,
                operation_digest=gmail_list_operation_digest,
                operation_context=gmail_list_operation,
                reservation_expires_at_epoch_ms=gmail_list_reserved[
                    "reservation_expires_at_epoch_ms"
                ],
            )
            gmail_list_v1_payload = lease_payload(
                recipient_public_key_raw,
                snapshot.hash,
                "gmail-list-v1-denied",
                purpose="dispatchSecret",
                expected_credential_version=1,
                expected_metadata_sha256=initial_metadata_sha256,
                request_authority=gmail_list_authority,
                release_authorization=None,
            )
            assert_status(
                post_lease(
                    gmail_list_v1_payload,
                    "gmail-list-v1-denied",
                ),
                409,
                "Gmail list without v2 durable authority",
                "lacks exact durable release authority",
            )

            gmail_get_payload_value = gmail_get_payload(
                "gmail-get-decision-bound"
            )
            gmail_get_response = post_lease(
                gmail_get_payload_value,
                "gmail-get-decision-bound",
            )
            assert_status(
                gmail_get_response,
                200,
                "Gmail get decision-bound credential lease",
            )
            gmail_get_plaintext = decrypt_lease(
                gmail_get_response.json(),
                recipient_private_key=recipient_private_key,
                recipient_nonce_raw=recipient_nonce(
                    "gmail-get-decision-bound"
                ),
                request_payload=gmail_get_payload_value,
            )
            if (
                gmail_get_plaintext["releaseAuthorization"] is not None
                or gmail_get_plaintext["requestAuthority"]
                != gmail_get_authority
                or gmail_get_plaintext["credentials"]
                != [expected_initial_secret]
            ):
                raise AssertionError(
                    "Gmail get decision-bound lease lost its exact authority"
                )
        finally:
            app_module.ATOMIC_RELEASE_AUTHORIZATION_ENABLED = (
                original_atomic_release_enabled
            )
            app_module._active_route_by_id = original_active_route_by_id

        durable_constraint = {
            "id": "credential-lease-durable-fixture",
            "type": "slidingWindowLimit",
            "store": "shared",
            "windowSeconds": 60,
            "windowSemantics": "sliding",
            "measure": "operationCount",
            "reservationMode": "atomicReserveCommitRelease",
            "onOverflow": "deny",
            "max": 2,
            "key": {
                "scope": [
                    "principal",
                    "route",
                    "credential",
                    "credentialVersion",
                    "operation",
                ]
            },
        }
        durable_route = replace(
            base_route,
            jit={"required": False},
            constraints=(durable_constraint,),
        )
        durable_attempt_id = "sha256:" + "2" * 64
        durable_request_digest = "sha256:" + "3" * 64
        durable_operation_digest = "sha256:" + "4" * 64
        durable_actor = (
            "spiffe://test.serverware/decision-gate/credential-lease"
        )
        durable_claims = shared_durable_budget_claims(
            durable_route,
            principal_id=PRINCIPAL_ID,
            credential_ref=CREDENTIAL_ID,
            credential_version=1,
            policy_hash=snapshot.hash,
            operation_fields={"operation": "demo.echo"},
        )
        durable_claim_digest = sha256_prefixed(
            canonical_json_bytes(durable_claims)
        )
        durable_reserved = db.reserve_release_authorization_v2(
            attempt_id=durable_attempt_id,
            flow_id=durable_attempt_id,
            principal_id=PRINCIPAL_ID,
            route_id=ROUTE_ID,
            credential_id=CREDENTIAL_ID,
            credential_version=1,
            policy_hash=snapshot.hash,
            request_digest=durable_request_digest,
            operation_digest=durable_operation_digest,
            operation_context={"operation": "demo.echo"},
            shared_quotas=[],
            require_jit_grant=False,
            reservation_ttl_seconds=60,
            durable_policy_binding={
                "actorId": durable_actor,
                "claimDigest": durable_claim_digest,
                "claims": durable_claims,
            },
            actor_id=durable_actor,
        )
        durable_state = durable_reserved["durable_policy"]
        durable_release_authorization = {
            "apiVersion": (
                "serverware.credentialLeaseReleaseAuthorization/v2"
            ),
            "kind": "atomicReservation",
            "state": "reserved",
            "attemptId": durable_attempt_id,
            "reservationId": db.release_reservation_id(
                durable_attempt_id,
                durable_reserved["binding_digest"],
            ),
            "bindingDigest": durable_reserved["binding_digest"],
            "principalId": PRINCIPAL_ID,
            "routeId": ROUTE_ID,
            "credentialId": CREDENTIAL_ID,
            "credentialVersion": 1,
            "policyHash": snapshot.hash,
            "requestDigest": durable_request_digest,
            "operationDigest": durable_operation_digest,
            "quotaClaims": [],
            "durablePolicy": {
                "reservationId": durable_state["reservation_id"],
                "actorId": durable_state["actor_id"],
                "claimDigest": durable_state["claim_digest"],
                "reservationDeadlineAtEpochMs": durable_state[
                    "reservation_deadline_at_epoch_ms"
                ],
                "releaseBindingDigest": durable_reserved[
                    "binding_digest"
                ],
            },
            "grantId": None,
            "approvalRequestId": None,
            "reservationExpiresAtEpochMs": durable_reserved[
                "reservation_expires_at_epoch_ms"
            ],
        }
        durable_request_authority = credential_request_authority(
            attempt_id=durable_release_authorization["attemptId"],
            reservation_id=durable_release_authorization["reservationId"],
            binding_digest=durable_release_authorization["bindingDigest"],
            request_digest=durable_release_authorization["requestDigest"],
            operation_digest=durable_release_authorization[
                "operationDigest"
            ],
            operation_context={"operation": "demo.echo"},
            reservation_expires_at_epoch_ms=durable_release_authorization[
                "reservationExpiresAtEpochMs"
            ],
        )
        durable_payload = lease_payload(
            recipient_public_key_raw,
            snapshot.hash,
            "durable-dispatch",
            purpose="dispatchSecret",
            expected_credential_version=1,
            expected_metadata_sha256=initial_metadata_sha256,
            request_authority=durable_request_authority,
            release_authorization=durable_release_authorization,
        )
        app_module.CredentialLeaseRequest.model_validate(
            durable_payload
        )
        for mixed_release in (
            {
                **durable_release_authorization,
                "apiVersion": (
                    "serverware.credentialLeaseReleaseAuthorization/v1"
                ),
            },
            {
                **atomic_release_authorization,
                "durablePolicy": None,
            },
            {
                **durable_release_authorization,
                "attemptId": "legacy-attempt-id",
            },
            {
                **durable_release_authorization,
                "reservationId": "sha256:" + "9" * 64,
            },
            {
                **durable_release_authorization,
                "credentialVersion": "1",
            },
        ):
            mixed_payload = lease_payload(
                recipient_public_key_raw,
                snapshot.hash,
                "durable-mixed",
                purpose="dispatchSecret",
                expected_credential_version=1,
                expected_metadata_sha256=initial_metadata_sha256,
                request_authority=durable_request_authority,
                release_authorization=mixed_release,
            )
            try:
                app_module.CredentialLeaseRequest.model_validate(
                    mixed_payload
                )
            except Exception:
                pass
            else:
                raise AssertionError(
                    "credential lease accepted mixed v1/v2 durable authority"
                )
        app_module._active_route_by_id = (
            lambda route_id, *, snapshot=None: (
                durable_route
                if route_id == ROUTE_ID
                else original_active_route_by_id(
                    route_id,
                    snapshot=snapshot,
                )
            )
        )
        app_module.ATOMIC_RELEASE_AUTHORIZATION_ENABLED = True
        try:
            durable_response = post_lease(
                durable_payload,
                "durable-dispatch",
            )
            assert_status(
                durable_response,
                200,
                "durable v2 credential lease",
            )
            durable_plaintext = decrypt_lease(
                durable_response.json(),
                recipient_private_key=recipient_private_key,
                recipient_nonce_raw=recipient_nonce(
                    "durable-dispatch"
                ),
                request_payload=durable_payload,
            )
            if durable_plaintext["credentials"] != [
                expected_initial_secret
            ]:
                raise AssertionError(
                    "durable v2 credential lease returned wrong material"
                )
        finally:
            app_module.ATOMIC_RELEASE_AUTHORIZATION_ENABLED = (
                original_atomic_release_enabled
            )
            app_module._active_route_by_id = (
                original_active_route_by_id
            )

        jit_attempt_id = "sha256:" + "f" * 64
        jit_binding_digest = "sha256:" + "a" * 64
        jit_request_digest = "sha256:" + "b" * 64
        jit_operation_digest = "sha256:" + "c" * 64
        jit_expires_at_epoch_ms = int(time.time() * 1000) + 4_500
        jit_request_authority = credential_request_authority(
            attempt_id=jit_attempt_id,
            reservation_id=db.release_reservation_id(
                jit_attempt_id,
                jit_binding_digest,
            ),
            binding_digest=jit_binding_digest,
            request_digest=jit_request_digest,
            operation_digest=jit_operation_digest,
            operation_context={"operation": "demo.echo"},
            reservation_expires_at_epoch_ms=jit_expires_at_epoch_ms,
        )
        jit_release_authorization = {
            "apiVersion": "serverware.credentialLeaseReleaseAuthorization/v1",
            "kind": "jitGrant",
            "state": "reserved",
            "attemptId": jit_attempt_id,
            "reservationId": jit_request_authority["reservationId"],
            "bindingDigest": jit_binding_digest,
            "principalId": PRINCIPAL_ID,
            "routeId": ROUTE_ID,
            "credentialId": CREDENTIAL_ID,
            "credentialVersion": 1,
            "policyHash": snapshot.hash,
            "requestDigest": jit_request_digest,
            "operationDigest": jit_operation_digest,
            "quotaClaims": [],
            "grantId": "grant:credential-lease-ordering",
            "approvalRequestId": "approval:credential-lease-ordering",
            "reservationExpiresAtEpochMs": jit_expires_at_epoch_ms,
        }
        jit_payload = lease_payload(
            recipient_public_key_raw,
            snapshot.hash,
            "jit-dispatch-ordering",
            purpose="dispatchSecret",
            expected_credential_version=1,
            expected_metadata_sha256=initial_metadata_sha256,
            request_authority=jit_request_authority,
            release_authorization=jit_release_authorization,
        )
        original_active_route_by_id = app_module._active_route_by_id
        original_assert_release = (
            app_module._assert_credential_lease_release_authorization
        )
        original_claim_release = (
            app_module._claim_credential_lease_release_authorization
        )
        ordering: list[str] = []

        def jit_route(route_id: str, *, snapshot: Any = None) -> Any:
            route = original_active_route_by_id(route_id, snapshot=snapshot)
            return replace(
                route,
                jit={
                    "required": True,
                    "approvers": {"users": ["user:test-approver"]},
                    "authentication": {"method": "webauthn"},
                },
            )

        def accept_release(payload: Any, *, route: Any) -> dict[str, Any]:
            del route
            assert payload.request_authority is not None
            assert payload.release_authorization is not None
            request_authority_wire = payload.request_authority.model_dump(
                by_alias=True,
                exclude_unset=True,
            )
            return {
                "controlled": True,
                "issuanceKind": "jitGrant",
                "requestAuthority": request_authority_wire,
                "requestAuthoritySha256": sha256_prefixed(
                    canonical_json_bytes(request_authority_wire)
                ),
                "releaseAuthorization": (
                    payload.release_authorization.model_dump(
                        by_alias=True,
                        exclude_unset=True,
                    )
                ),
                "authoritySnapshot": {"state": "reserved"},
            }

        def claim_release(
            payload: Any,
            *,
            route: Any,
            dispatch_authority: dict[str, Any],
            request_binding_sha256: str,
            recipient_nonce_sha256: str,
        ) -> dict[str, Any]:
            del route
            ordering.append("claim")
            assert payload.request_authority is not None
            authority = dispatch_authority["requestAuthority"]
            return {
                "release_kind": dispatch_authority["issuanceKind"],
                "attempt_id": authority["attemptId"],
                "reservation_id": authority["reservationId"],
                "binding_digest": authority["bindingDigest"],
                "request_digest": authority["requestDigest"],
                "operation_digest": authority["operationDigest"],
                "request_binding_sha256": request_binding_sha256,
                "request_authority_sha256": dispatch_authority[
                    "requestAuthoritySha256"
                ],
                "recipient_key_id": payload.recipient_key_id,
                "recipient_nonce_sha256": recipient_nonce_sha256,
                "reservation_expires_at_epoch_ms": authority[
                    "reservationExpiresAtEpochMs"
                ],
                "claimed_at_epoch_ms": int(time.time() * 1000),
            }

        def refresh_after_claim(credential_id: str) -> dict[str, Any] | None:
            if ordering != ["claim"]:
                raise AssertionError(
                    f"credential refresh preceded atomic JIT issuance claim: {ordering}"
                )
            ordering.append("refresh")
            return original_credential_for_lease(credential_id)

        app_module._active_route_by_id = jit_route
        app_module._assert_credential_lease_release_authorization = accept_release
        app_module._claim_credential_lease_release_authorization = claim_release
        app_module._credential_for_lease = refresh_after_claim
        try:
            jit_response = post_lease(jit_payload, "jit-dispatch-ordering")
        finally:
            app_module._active_route_by_id = original_active_route_by_id
            app_module._assert_credential_lease_release_authorization = (
                original_assert_release
            )
            app_module._claim_credential_lease_release_authorization = (
                original_claim_release
            )
            app_module._credential_for_lease = original_credential_for_lease
        assert_status(jit_response, 200, "JIT dispatch ordering lease")
        if ordering != ["claim", "refresh"]:
            raise AssertionError(f"unexpected JIT credential issuance ordering: {ordering}")
        jit_plaintext = decrypt_lease(
            jit_response.json(),
            recipient_private_key=recipient_private_key,
            recipient_nonce_raw=recipient_nonce("jit-dispatch-ordering"),
            request_payload=jit_payload,
        )
        if (
            jit_plaintext["expiresAtEpochMs"]
            > jit_release_authorization["reservationExpiresAtEpochMs"]
        ):
            raise AssertionError(
                "JIT credential lease outlived its release reservation"
            )

        encryption_entered = threading.Event()
        allow_encryption = threading.Event()
        endpoint_mutation_started = threading.Event()
        endpoint_mutation_completed = threading.Event()
        original_encrypt_lease = app_module.encrypt_credential_lease_envelope

        def blocked_encrypt_lease(**kwargs: Any) -> dict[str, str]:
            encryption_entered.set()
            if not allow_encryption.wait(10):
                raise AssertionError("credential lease encryption release timed out")
            return original_encrypt_lease(**kwargs)

        def rename_during_encryption() -> dict[str, Any] | None:
            endpoint_mutation_started.set()
            try:
                return db.update_credential(CREDENTIAL_ID, {"name": "Demo bearer token after lease"})
            finally:
                endpoint_mutation_completed.set()

        app_module.encrypt_credential_lease_envelope = blocked_encrypt_lease
        try:
            with ThreadPoolExecutor(max_workers=2) as pool:
                endpoint_lease_future = pool.submit(
                    post_lease,
                    lease_payload(recipient_public_key_raw, snapshot.hash, "endpoint-lock"),
                    "endpoint-lock",
                )
                if not encryption_entered.wait(10):
                    raise AssertionError("lease endpoint did not enter envelope encryption")
                endpoint_mutation_future = pool.submit(rename_during_encryption)
                if not endpoint_mutation_started.wait(10):
                    raise AssertionError("endpoint credential mutation did not start")
                if endpoint_mutation_completed.wait(0.25):
                    raise AssertionError("credential mutation completed while lease encryption held the snapshot")
                allow_encryption.set()
                endpoint_locked_response = endpoint_lease_future.result(timeout=15)
                renamed_after_encryption = endpoint_mutation_future.result(timeout=15)
        finally:
            allow_encryption.set()
            app_module.encrypt_credential_lease_envelope = original_encrypt_lease
        assert_status(endpoint_locked_response, 200, "endpoint lease snapshot")
        endpoint_locked_plaintext = decrypt_lease(
            endpoint_locked_response.json(),
            recipient_private_key=recipient_private_key,
            recipient_nonce_raw=recipient_nonce("endpoint-lock"),
            request_payload=lease_payload(
                recipient_public_key_raw, snapshot.hash, "endpoint-lock"
            ),
        )
        if endpoint_locked_plaintext["credentials"] != [expected_initial_generation]:
            raise AssertionError("endpoint lease did not encrypt one immutable credential generation")
        if renamed_after_encryption is None or renamed_after_encryption["name"] != "Demo bearer token after lease":
            raise AssertionError("credential mutation did not complete after lease encryption released")
        db.update_credential(CREDENTIAL_ID, {"name": "Demo bearer token"})

        second_recipient_private_key = X25519PrivateKey.generate()
        second_recipient_public_key_raw = second_recipient_private_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        second_recipient_payload = lease_payload(
            second_recipient_public_key_raw,
            snapshot.hash,
            "second-recipient",
        )
        second_recipient_response = post_lease(second_recipient_payload, "second-recipient")
        assert_status(second_recipient_response, 200, "second recipient credential lease")
        second_recipient_plaintext = decrypt_lease(
            second_recipient_response.json(),
            recipient_private_key=second_recipient_private_key,
            recipient_nonce_raw=recipient_nonce("second-recipient"),
            request_payload=second_recipient_payload,
        )
        if second_recipient_plaintext["credentials"] != [expected_initial_generation]:
            raise AssertionError(f"second recipient lease contents are incorrect: {second_recipient_plaintext}")
        with db.connect() as replay_conn:
            reserved_before_rejections = int(
                replay_conn.execute("SELECT COUNT(*) AS count FROM credential_lease_nonces").fetchone()["count"]
            )

        rejection_cases: list[tuple[str, dict[str, Any], int, str, str]] = []
        rejection_cases.append(("replay", initial_payload, 409, "already been used", DATA_PLANE_TOKEN))
        rejection_cases.append(
            (
                "wrong token",
                lease_payload(recipient_public_key_raw, snapshot.hash, "wrong-token"),
                401,
                "data-plane authentication required",
                "wrong-token",
            )
        )
        wrong_policy = lease_payload(recipient_public_key_raw, snapshot.hash, "wrong-policy")
        wrong_policy["policyHash"] = "sha256:" + "1" * 64
        rejection_cases.append(("wrong policy hash", wrong_policy, 409, "policy hash is not active", DATA_PLANE_TOKEN))
        wrong_binary = lease_payload(recipient_public_key_raw, snapshot.hash, "wrong-binary")
        wrong_binary["dataPlaneBinaryDigest"] = "sha256:" + "2" * 64
        rejection_cases.append(("wrong binary digest", wrong_binary, 409, "binary digest", DATA_PLANE_TOKEN))
        wrong_principal = lease_payload(recipient_public_key_raw, snapshot.hash, "wrong-principal")
        wrong_principal["principalId"] = "agent:not-assigned"
        wrong_principal["recipientAttestation"]["principalId"] = "agent:not-assigned"
        rejection_cases.append(("wrong principal", wrong_principal, 409, "not assigned", DATA_PLANE_TOKEN))
        wrong_key_id = lease_payload(recipient_public_key_raw, snapshot.hash, "wrong-key-id")
        wrong_key_id["recipientKeyId"] = "sha256:" + "3" * 64
        rejection_cases.append(("wrong recipient key id", wrong_key_id, 400, "does not match", DATA_PLANE_TOKEN))
        malformed_key = lease_payload(recipient_public_key_raw, snapshot.hash, "malformed-key")
        malformed_key["recipientPublicKey"] = "not+base64url"
        rejection_cases.append(("malformed recipient key", malformed_key, 400, "recipientPublicKey", DATA_PLANE_TOKEN))
        malformed_nonce = lease_payload(recipient_public_key_raw, snapshot.hash, "malformed-nonce")
        malformed_nonce["recipientNonce"] = b64e(b"n" * 31)
        rejection_cases.append(("malformed recipient nonce", malformed_nonce, 400, "recipientNonce", DATA_PLANE_TOKEN))
        noncanonical_nonce = lease_payload(recipient_public_key_raw, snapshot.hash, "noncanonical-nonce")
        canonical_nonce = noncanonical_nonce["recipientNonce"]
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        canonical_index = alphabet.index(canonical_nonce[-1])
        noncanonical_nonce["recipientNonce"] = canonical_nonce[:-1] + alphabet[canonical_index ^ 1]
        noncanonical_nonce["recipientAttestation"]["recipientNonce"] = noncanonical_nonce["recipientNonce"]
        rejection_cases.append(
            (
                "noncanonical recipient nonce",
                noncanonical_nonce,
                400,
                "canonical base64url",
                DATA_PLANE_TOKEN,
            )
        )
        stale_attestation = lease_payload(recipient_public_key_raw, snapshot.hash, "stale-attestation")
        stale_attestation["recipientAttestation"]["recipientNonce"] = b64e(recipient_nonce("old-evidence"))
        rejection_cases.append(
            (
                "stale recipient attestation",
                stale_attestation,
                403,
                "attestation verification failed",
                DATA_PLANE_TOKEN,
            )
        )
        unknown_field = lease_payload(recipient_public_key_raw, snapshot.hash, "unknown-field")
        unknown_field["unknownField"] = "must-fail-closed"
        rejection_cases.append(("unknown extra field", unknown_field, 422, "extra_forbidden", DATA_PLANE_TOKEN))
        missing_purpose = lease_payload(
            recipient_public_key_raw, snapshot.hash, "missing-purpose"
        )
        missing_purpose.pop("purpose")
        rejection_cases.append(
            ("missing purpose", missing_purpose, 422, "Field required", DATA_PLANE_TOKEN)
        )
        missing_release_mode = lease_payload(
            recipient_public_key_raw,
            snapshot.hash,
            "missing-release-mode",
            purpose="dispatchSecret",
            expected_credential_version=1,
            expected_metadata_sha256=initial_metadata_sha256,
            request_authority=gmail_get_authority,
            release_authorization=None,
        )
        missing_release_mode.pop("releaseAuthorization")
        rejection_cases.append(
            (
                "missing release mode",
                missing_release_mode,
                422,
                "requires exact requestAuthority",
                DATA_PLANE_TOKEN,
            )
        )
        generation_with_dispatch_bindings = lease_payload(
            recipient_public_key_raw,
            snapshot.hash,
            "generation-mode-substitution",
            expected_credential_version=1,
            expected_metadata_sha256=initial_metadata_sha256,
        )
        rejection_cases.append(
            (
                "generation mode substitution",
                generation_with_dispatch_bindings,
                422,
                "must not include dispatch bindings",
                DATA_PLANE_TOKEN,
            )
        )
        dispatch_without_generation = lease_payload(
            recipient_public_key_raw,
            snapshot.hash,
            "dispatch-without-generation",
            purpose="dispatchSecret",
        )
        rejection_cases.append(
            (
                "dispatch missing generation",
                dispatch_without_generation,
                422,
                "require expected credential metadata bindings",
                DATA_PLANE_TOKEN,
            )
        )
        excessive_ttl = lease_payload(
            recipient_public_key_raw, snapshot.hash, "excessive-ttl"
        )
        excessive_ttl["maxTtlSeconds"] = 6
        rejection_cases.append(
            (
                "credential lease TTL above cap",
                excessive_ttl,
                422,
                "less than or equal to 5",
                DATA_PLANE_TOKEN,
            )
        )
        oversized_attestation = lease_payload(recipient_public_key_raw, snapshot.hash, "oversized-attestation")
        oversized_attestation["recipientAttestation"] = {"evidence": "x" * (64 * 1024)}
        rejection_cases.append(
            (
                "oversized recipient attestation",
                oversized_attestation,
                422,
                "recipient attestation exceeds 64 KiB",
                DATA_PLANE_TOKEN,
            )
        )
        oversized_transport = lease_payload(recipient_public_key_raw, snapshot.hash, "oversized-transport")
        oversized_transport["recipientAttestation"]["transportPadding"] = "x" * (96 * 1024)
        rejection_cases.append(
            (
                "oversized credential lease request",
                oversized_transport,
                413,
                "request exceeds 96 KiB",
                DATA_PLANE_TOKEN,
            )
        )
        oversized_verifier_output = lease_payload(
            recipient_public_key_raw,
            snapshot.hash,
            "oversized-verifier-output",
        )
        oversized_verifier_output["recipientAttestation"]["testLargeVerifierOutput"] = True
        rejection_cases.append(
            (
                "oversized verifier output",
                oversized_verifier_output,
                503,
                "verifier output exceeds 64 KiB",
                DATA_PLANE_TOKEN,
            )
        )

        for label, payload, status_code, detail, token in rejection_cases:
            rejected = post_lease(payload, label.replace(" ", "-"), token=token)
            assert_status(rejected, status_code, label, detail)
        if verifier_counter.read_text(encoding="ascii").splitlines() != ["verified"]:
            raise AssertionError("a replay invoked the recipient attestation verifier again")
        with db.connect() as replay_conn:
            reserved_after_rejections = replay_conn.execute(
                "SELECT COUNT(*) AS count FROM credential_lease_nonces"
            ).fetchone()
        if int(reserved_after_rejections["count"]) != reserved_before_rejections:
            raise AssertionError(
                "invalid recipient attestations consumed replay capacity: "
                f"before={reserved_before_rejections} after={dict(reserved_after_rejections)}"
            )
        replay_after_lease_expiry = db.reserve_credential_lease_nonce(
            initial_payload["recipientKeyId"],
            sha256_prefixed(recipient_nonce("initial")),
            now_epoch_ms=initial_response.json()["expiresAtEpochMs"] + 1,
        )
        if replay_after_lease_expiry != "replay":
            raise AssertionError("recipient nonce tombstone expired with the five-second lease")

        original_plaintext_max = app_module._CREDENTIAL_LEASE_PLAINTEXT_MAX_BYTES
        app_module._CREDENTIAL_LEASE_PLAINTEXT_MAX_BYTES = 1
        try:
            oversized_plaintext = post_lease(
                lease_payload(recipient_public_key_raw, snapshot.hash, "oversized-plaintext"),
                "oversized-plaintext",
            )
            assert_status(oversized_plaintext, 503, "oversized credential lease plaintext", "exceeds 4 MiB")
        finally:
            app_module._CREDENTIAL_LEASE_PLAINTEXT_MAX_BYTES = original_plaintext_max

        original_response_max = app_module._CREDENTIAL_LEASE_RESPONSE_MAX_BYTES
        app_module._CREDENTIAL_LEASE_RESPONSE_MAX_BYTES = 1
        try:
            oversized_response = post_lease(
                lease_payload(recipient_public_key_raw, snapshot.hash, "oversized-response"),
                "oversized-response",
            )
            assert_status(oversized_response, 503, "oversized credential lease response", "exceeds 8 MiB")
        finally:
            app_module._CREDENTIAL_LEASE_RESPONSE_MAX_BYTES = original_response_max

        audit_failure_private_key = X25519PrivateKey.generate()
        audit_failure_public_key = audit_failure_private_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        original_record_audit_event = db.record_audit_event

        def fail_issuance_audit(event_type: str, *args: Any, **kwargs: Any) -> Any:
            if event_type == "data_plane.credential_lease.issued":
                raise RuntimeError("simulated audit-store outage")
            return original_record_audit_event(event_type, *args, **kwargs)

        db.record_audit_event = fail_issuance_audit
        try:
            audit_failure_response = post_lease(
                lease_payload(audit_failure_public_key, snapshot.hash, "audit-failure"),
                "audit-failure",
            )
            assert_status(
                audit_failure_response,
                503,
                "credential lease issuance audit failure",
                "audit is unavailable",
            )
        finally:
            db.record_audit_event = original_record_audit_event
        audit_recovery_response = post_lease(
            lease_payload(audit_failure_public_key, snapshot.hash, "audit-recovery"),
            "audit-recovery",
        )
        assert_status(audit_recovery_response, 200, "credential lease issuance audit recovery")

        wrong_provider_metadata = {**INITIAL_METADATA, "provider_id": "other-provider"}
        db.update_credential(CREDENTIAL_ID, {"metadata": wrong_provider_metadata})
        runtime.invalidate_secret_leases(CREDENTIAL_ID)
        wrong_provider_response = post_lease(
            lease_payload(recipient_public_key_raw, snapshot.hash, "wrong-stored-provider"),
            "wrong-stored-provider",
        )
        assert_status(
            wrong_provider_response,
            409,
            "stored provider outside signed policy",
            "provider does not match",
        )

        excessive_scope_metadata = {**INITIAL_METADATA, "scopes": ["demo", "admin.everything"]}
        db.update_credential(CREDENTIAL_ID, {"metadata": excessive_scope_metadata})
        runtime.invalidate_secret_leases(CREDENTIAL_ID)
        excessive_scope_response = post_lease(
            lease_payload(recipient_public_key_raw, snapshot.hash, "excessive-stored-scope"),
            "excessive-stored-scope",
        )
        assert_status(
            excessive_scope_response,
            409,
            "stored scope outside signed policy",
            "scopes exceed",
        )
        duplicate_scope_metadata = {**INITIAL_METADATA, "scopes": ["demo", "demo"]}
        db.update_credential(CREDENTIAL_ID, {"metadata": duplicate_scope_metadata})
        runtime.invalidate_secret_leases(CREDENTIAL_ID)
        duplicate_scope_response = post_lease(
            lease_payload(recipient_public_key_raw, snapshot.hash, "duplicate-stored-scope"),
            "duplicate-stored-scope",
        )
        assert_status(
            duplicate_scope_response,
            503,
            "duplicate stored scopes",
            "contains duplicates",
        )
        db.update_credential(CREDENTIAL_ID, {"metadata": INITIAL_METADATA})
        runtime.invalidate_secret_leases(CREDENTIAL_ID)

        policy_race_payload = lease_payload(recipient_public_key_raw, snapshot.hash, "policy-race")
        changed_snapshot = replace(snapshot, hash="sha256:" + "4" * 64)
        original_get_policy_snapshot = app_module.get_policy_snapshot
        policy_reads = 0

        def changing_policy_snapshot() -> Any:
            nonlocal policy_reads
            policy_reads += 1
            return snapshot if policy_reads == 1 else changed_snapshot

        app_module.get_policy_snapshot = changing_policy_snapshot
        try:
            try:
                app_module.data_plane_credential_leases(
                    request=Request({
                        "type": "http", "method": "POST",
                        "path": "/api/data-plane/credential-leases",
                        "query_string": b"", "headers": [],
                    }),
                    payload=app_module.CredentialLeaseRequest.model_validate(policy_race_payload),
                )
            except HTTPException as exc:
                if exc.status_code != 409 or "policy hash is not active" not in str(exc.detail):
                    raise AssertionError(f"mid-lease policy change failed incorrectly: {exc}") from exc
            else:
                raise AssertionError("a policy change during credential lease authorization was accepted")
        finally:
            app_module.get_policy_snapshot = original_get_policy_snapshot

        before_update = db.get_credential(CREDENTIAL_ID)
        if before_update is None:
            raise AssertionError("seeded credential is missing before metadata update")
        updated = db.update_credential(CREDENTIAL_ID, {"metadata": UPDATED_METADATA})
        if updated is None or int(updated["credential_version"]) != int(before_update["credential_version"]) + 1:
            raise AssertionError(f"metadata-only update did not increment credential version: {updated}")
        runtime.invalidate_secret_leases(CREDENTIAL_ID)

        updated_payload = lease_payload(recipient_public_key_raw, snapshot.hash, "metadata-update")
        updated_response = post_lease(updated_payload, "metadata-update")
        assert_status(updated_response, 200, "post-update credential lease")
        updated_plaintext = decrypt_lease(
            updated_response.json(),
            recipient_private_key=recipient_private_key,
            recipient_nonce_raw=recipient_nonce("metadata-update"),
            request_payload=updated_payload,
        )
        expected_updated_generation = {
            **expected_initial_generation,
            "credentialVersion": updated["credential_version"],
            "metadataSha256": credential_metadata_sha256(UPDATED_METADATA),
            "metadata": UPDATED_METADATA,
        }
        if updated_plaintext["credentials"] != [expected_updated_generation]:
            raise AssertionError(f"updated credential lease contents are incorrect: {updated_plaintext}")

        if not db.delete_credential(CREDENTIAL_ID):
            raise AssertionError("seeded credential deletion failed")
        runtime.invalidate_secret_leases(CREDENTIAL_ID)
        deleted_payload = lease_payload(recipient_public_key_raw, snapshot.hash, "deleted")
        deleted_response = post_lease(deleted_payload, "deleted")
        assert_status(
            deleted_response,
            404,
            "post-delete credential lease",
            "credential became unavailable",
        )
        recreated = db.upsert_credential_with_id(
            CREDENTIAL_ID,
            "Demo Bearer",
            "bearer",
            "recreated-demo-token",
            INITIAL_METADATA,
        )
        if int(recreated["credential_version"]) <= int(updated["credential_version"]):
            raise AssertionError(f"credential version rolled back after delete and recreate: {recreated}")
        db.delete_credential(CREDENTIAL_ID)
        runtime.invalidate_secret_leases(CREDENTIAL_ID)

        from serverware import crypto

        original_release_channel = crypto.RELEASE_CHANNEL
        original_unseal_command = crypto.MASTER_KEY_UNSEAL_COMMAND
        original_env_master_key = os.environ.get("SERVERWARE_MASTER_KEY")
        crypto.RELEASE_CHANNEL = "prod"
        crypto.MASTER_KEY_UNSEAL_COMMAND = (
            f"{shlex.quote(sys.executable)} {shlex.quote(str(Path(__file__).resolve()))} --master-key-unseal-fixture"
        )
        fake_release = {
            "key_release_provider": "external-command",
            "external_release": {"release_handle": "sha256:" + "c" * 64},
        }
        try:
            unsealed = crypto._unseal_master_key(fake_release)
            if unsealed != b"0123456789abcdef0123456789abcdef":
                raise AssertionError("production unseal command did not return the expected in-memory broker KEK")
            os.environ["SERVERWARE_MASTER_KEY"] = "11" * 32
            crypto.load_master_key.cache_clear()
            try:
                crypto.load_master_key()
            except ValueError as exc:
                if "forbidden in production" not in str(exc):
                    raise AssertionError(f"production environment master key failed incorrectly: {exc}") from exc
            else:
                raise AssertionError("production accepted SERVERWARE_MASTER_KEY")
            os.environ.pop("SERVERWARE_MASTER_KEY", None)
            crypto.load_master_key.cache_clear()
            try:
                crypto.load_master_key()
            except ValueError as exc:
                if "persistent plaintext master key" not in str(exc):
                    raise AssertionError(f"production disk master key failed incorrectly: {exc}") from exc
            else:
                raise AssertionError("production accepted a persistent plaintext master key")
        finally:
            crypto.RELEASE_CHANNEL = original_release_channel
            crypto.MASTER_KEY_UNSEAL_COMMAND = original_unseal_command
            if original_env_master_key is None:
                os.environ.pop("SERVERWARE_MASTER_KEY", None)
            else:
                os.environ["SERVERWARE_MASTER_KEY"] = original_env_master_key
            crypto.load_master_key.cache_clear()

        audit_nonce = "credential-lease-audit-response"
        audit_target = "/api/audit?limit=500"
        audit_response = app_request(
            app_module.app,
            "GET",
            audit_target,
            headers={
                "X-Serverware-Admin-Token": ADMIN_TOKEN,
                "X-Serverware-Response-Nonce": audit_nonce,
            },
        )
        assert_status(audit_response, 200, "credential lease audit output")
        verify_response_signature(
            audit_response,
            public_key=response_public_key,
            key_id=response_key_id,
            method="GET",
            target=audit_target,
            response_nonce=audit_nonce,
            policy_hash=snapshot.hash,
        )
        if CREDENTIAL_SECRET.encode("ascii") in audit_response.body:
            raise AssertionError("audit API output exposed the plaintext credential")
        lease_audits = [
            item
            for item in audit_response.json()
            if str(item.get("event_type", "")).startswith("data_plane.credential_lease.")
        ]
        issued_audits = [item for item in lease_audits if item["event_type"].endswith(".issued")]
        rejected_audits = [item for item in lease_audits if item["event_type"].endswith(".rejected")]
        if not issued_audits or not rejected_audits:
            raise AssertionError(f"credential lease audit outcomes are incomplete: {lease_audits}")
        if any(item["event"]["credential_count"] != 1 for item in issued_audits):
            raise AssertionError(f"credential lease audit counts are incorrect: {issued_audits}")
        issued_purposes = {item["event"].get("purpose") for item in issued_audits}
        if issued_purposes != {"generationMetadata", "dispatchSecret"}:
            raise AssertionError(
                f"credential lease audit purposes are incomplete: {issued_audits}"
            )
        dispatch_audits = [
            item
            for item in issued_audits
            if item["event"].get("purpose") == "dispatchSecret"
        ]
        if not any(
            item["event"].get("expected_credential_version") == 1
            and item["event"].get("expected_metadata_sha256")
            == initial_metadata_sha256
            for item in dispatch_audits
        ):
            raise AssertionError(
                f"dispatch audit omitted exact generation bindings: {dispatch_audits}"
            )
        for item in lease_audits:
            event = item["event"]
            if item.get("actor_id") != "spiffe://test.serverware/decision-gate/credential-lease":
                raise AssertionError(f"credential lease audit actor was not server-derived: {item}")
            if "recipient_nonce" in event or not str(event.get("recipient_nonce_sha256", "")).startswith("sha256:"):
                raise AssertionError(f"credential lease audit did not hash the recipient nonce: {item}")
            if event.get("purpose") not in {"generationMetadata", "dispatchSecret"}:
                raise AssertionError(f"credential lease audit omitted its purpose: {item}")

        legacy_plaintext_files = [
            path
            for path in data_dir.rglob("*")
            if path.is_file() and path.name in {"credential-generations.json", "credential-leases.json"}
        ]
        if legacy_plaintext_files:
            raise AssertionError(f"legacy plaintext credential files were created: {legacy_plaintext_files}")
        for path in data_dir.rglob("*"):
            if path.is_file() and CREDENTIAL_SECRET.encode("ascii") in path.read_bytes():
                raise AssertionError(f"plaintext credential was persisted in {path}")
        if any(CREDENTIAL_SECRET.encode("ascii") in response.body for response in lease_responses):
            raise AssertionError("a credential lease HTTP response exposed plaintext secret material")

        print(
            json.dumps(
                {
                    "credential_lease_delivery": "pass",
                    "issued_audits": len(issued_audits),
                    "rejected_audits": len(rejected_audits),
                    "response_signatures": "attested-ed25519",
                    "key_release_required": True,
                    "recipient_attestation_required": True,
                    "ok": True,
                },
                sort_keys=True,
            )
        )


if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] == "--recipient-attestation-verifier":
        recipient_attestation_verifier()
    elif len(sys.argv) == 2 and sys.argv[1] == "--master-key-unseal-fixture":
        master_key_unseal_fixture()
    else:
        main()
