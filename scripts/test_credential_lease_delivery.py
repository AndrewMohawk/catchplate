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
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from fastapi import HTTPException
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

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
    "scopes": ["demo"],
    "x_app_id": "demo-x-app",
}
UPDATED_METADATA = {
    "managed": True,
    "provider_id": "demo",
    "scopes": ["demo"],
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
            "SERVERWARE_DATA_PLANE_AUDIT_TOKEN",
            "SERVERWARE_METADATA_STORE_POSTGRES_DSN",
        ):
            if os.getenv(name):
                raise ValueError(f"verifier inherited sensitive environment variable {name}")
        request = json.load(sys.stdin)
        evidence = request["recipientAttestation"]
        if evidence.get("format") != "serverware.testRecipientAttestation/v1":
            raise ValueError("unexpected recipient attestation format")
        for field in (
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
        counter_path = evidence.get("testVerifierCounterPath")
        if counter_path:
            with open(counter_path, "a", encoding="ascii") as counter:
                counter.write("verified\n")
        response = {
            "ok": True,
            "debug": False,
            "recipientKeyId": request["recipientKeyId"],
            "recipientNonce": request["recipientNonce"],
            "policyHash": request["policyHash"],
            "dataPlaneBinaryDigest": request["dataPlaneBinaryDigest"],
            "principalId": request["principalId"],
            "routeId": request["routeId"],
            "credentialId": request["credentialId"],
        }
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
            response_headers.update(
                (key.decode("latin-1").lower(), value.decode("latin-1"))
                for key, value in message.get("headers", [])
            )
        elif message["type"] == "http.response.body":
            response_body.extend(message.get("body", b""))

    await app(scope, receive, send)
    if status_code is None:
        raise AssertionError("ASGI application did not start a response")
    return AppResponse(status_code, response_headers, bytes(response_body))


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
    if statement.get("version") != "serverware.responseSignature/v1":
        raise AssertionError(f"unexpected response signature version: {statement}")
    if statement.get("request") != {
        "method": method.upper(),
        "path": parsed.path,
        "query": parsed.query,
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
) -> dict[str, str]:
    return {
        "format": "serverware.testRecipientAttestation/v1",
        "recipientKeyId": key_id,
        "recipientNonce": nonce,
        "policyHash": policy_hash,
        "dataPlaneBinaryDigest": binary_digest,
        "principalId": PRINCIPAL_ID,
        "routeId": ROUTE_ID,
        "credentialId": CREDENTIAL_ID,
    }


def lease_payload(public_key_raw: bytes, policy_hash: str, label: str) -> dict[str, Any]:
    key_id = sha256_prefixed(public_key_raw)
    nonce = recipient_nonce(label)
    return {
        "apiVersion": "serverware.credentialLeaseRequest/v2",
        "principalId": PRINCIPAL_ID,
        "routeId": ROUTE_ID,
        "credentialId": CREDENTIAL_ID,
        "recipientPublicKey": b64e(public_key_raw),
        "recipientKeyId": key_id,
        "recipientNonce": b64e(nonce),
        "policyHash": policy_hash,
        "dataPlaneBinaryDigest": DATA_PLANE_BINARY_DIGEST,
        "maxTtlSeconds": 5,
        "recipientAttestation": recipient_attestation(
            key_id,
            b64e(nonce),
            policy_hash,
            DATA_PLANE_BINARY_DIGEST,
        ),
    }


def decrypt_lease(
    envelope: dict[str, Any],
    *,
    recipient_private_key: X25519PrivateKey,
    recipient_nonce_raw: bytes,
) -> dict[str, Any]:
    expected_fields = set(AAD_FIELDS).union(ENCRYPTED_FIELDS)
    if set(envelope) != expected_fields:
        raise AssertionError(f"credential lease envelope fields changed: {sorted(envelope)}")
    if envelope["apiVersion"] != "serverware.credentialLeaseEnvelope/v2":
        raise AssertionError(f"unexpected credential lease envelope version: {envelope}")
    if envelope["algorithm"] != "X25519-HKDF-SHA256-AES-256-GCM":
        raise AssertionError(f"unexpected credential lease algorithm: {envelope}")
    if envelope["expiresAtEpochMs"] - envelope["issuedAtEpochMs"] != 5_000:
        raise AssertionError(f"credential lease TTL was not bounded to five seconds: {envelope}")

    aad = {field: envelope[field] for field in AAD_FIELDS}
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
    if plaintext.get("apiVersion") != "serverware.credentialLeaseSet/v2":
        raise AssertionError(f"unexpected credential lease plaintext version: {plaintext}")
    if set(plaintext) != {"apiVersion", *DUPLICATED_BINDINGS, "credentials"}:
        raise AssertionError(f"credential lease plaintext fields changed: {sorted(plaintext)}")
    for field in DUPLICATED_BINDINGS:
        if plaintext.get(field) != envelope.get(field):
            raise AssertionError(f"credential lease duplicated binding mismatch for {field}: {plaintext}")
    return plaintext


def assert_status(response: AppResponse, expected: int, label: str, detail: str | None = None) -> None:
    if response.status_code != expected:
        raise AssertionError(f"{label} returned {response.status_code}: {response.body.decode(errors='replace')}")
    if detail is not None and detail not in json.dumps(response.json(), sort_keys=True):
        raise AssertionError(f"{label} failed for the wrong reason: {response.json()}")


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
                "SERVERWARE_DATA_PLANE_AUDIT_TOKEN": DATA_PLANE_TOKEN,
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

        ensure_mitm_ca_material()
        db.init_db()
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
        verifier_counter = data_dir / "recipient-verifier-count.txt"
        initial_payload["recipientAttestation"]["testVerifierCounterPath"] = str(verifier_counter)
        initial_response = post_lease(initial_payload, "initial")
        assert_status(initial_response, 200, "initial credential lease")
        initial_plaintext = decrypt_lease(
            initial_response.json(),
            recipient_private_key=recipient_private_key,
            recipient_nonce_raw=recipient_nonce("initial"),
        )
        expected_initial_credential = {
            "credentialId": CREDENTIAL_ID,
            "credentialVersion": 1,
            "secret": CREDENTIAL_SECRET,
            "metadata": INITIAL_METADATA,
        }
        if initial_plaintext["credentials"] != [expected_initial_credential]:
            raise AssertionError(f"initial credential lease contents are incorrect: {initial_plaintext}")

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
        )
        if endpoint_locked_plaintext["credentials"] != [expected_initial_credential]:
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
        )
        if second_recipient_plaintext["credentials"] != [expected_initial_credential]:
            raise AssertionError(f"second recipient lease contents are incorrect: {second_recipient_plaintext}")

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
                    app_module.CredentialLeaseRequest.model_validate(policy_race_payload)
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
        )
        expected_updated_credential = {
            **expected_initial_credential,
            "credentialVersion": updated["credential_version"],
            "metadata": UPDATED_METADATA,
        }
        if updated_plaintext["credentials"] != [expected_updated_credential]:
            raise AssertionError(f"updated credential lease contents are incorrect: {updated_plaintext}")

        if not db.delete_credential(CREDENTIAL_ID):
            raise AssertionError("seeded credential deletion failed")
        runtime.invalidate_secret_leases(CREDENTIAL_ID)
        deleted_payload = lease_payload(recipient_public_key_raw, snapshot.hash, "deleted")
        deleted_response = post_lease(deleted_payload, "deleted")
        assert_status(deleted_response, 404, "post-delete credential lease", "credential is unavailable")
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
        if len(issued_audits) != 4 or len(rejected_audits) != 16:
            raise AssertionError(f"credential lease audit outcomes are incomplete: {lease_audits}")
        if sorted(item["event"]["credential_count"] for item in issued_audits) != [1, 1, 1, 1]:
            raise AssertionError(f"credential lease audit counts are incorrect: {issued_audits}")
        for item in lease_audits:
            event = item["event"]
            if "recipient_nonce" in event or not str(event.get("recipient_nonce_sha256", "")).startswith("sha256:"):
                raise AssertionError(f"credential lease audit did not hash the recipient nonce: {item}")

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
