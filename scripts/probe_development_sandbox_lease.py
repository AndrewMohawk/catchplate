#!/usr/bin/env python3
"""Bounded live synthetic-only lease probe; prints flags, never material.

Run inside the dedicated sandbox container. This does not activate a profile,
seed policy, start services, contact upstreams, or touch a production endpoint.
The live API creates two ordinary synthetic nonce reservations/audit events.
"""
from __future__ import annotations

import hashlib
import http.client
import json
import os
from pathlib import Path
import sys
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.test_credential_lease_delivery import (  # noqa: E402
    CREDENTIAL_SECRET, b64e, canonical_json_bytes, decrypt_lease,
)


class ProbeFailure(Exception):
    """Only fixed, non-sensitive labels may leave the probe."""


def require(condition: bool, label: str) -> None:
    if not condition:
        raise ProbeFailure(label)


def request(method: str, path: str, payload=None, token: str | None = None):
    # An unconfigurable loopback destination prevents credentials escaping.
    connection = http.client.HTTPConnection("127.0.0.1", 3000, timeout=10)
    try:
        headers = {"Content-Type": "application/json"}
        if token is not None:
            headers["X-Catchplate-Data-Plane-Token"] = token
        body = None if payload is None else canonical_json_bytes(payload)
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        raw = response.read(8 * 1024 * 1024 + 1)
        require(len(raw) <= 8 * 1024 * 1024, "response-size")
        require(CREDENTIAL_SECRET.encode() not in raw, "plaintext-on-wire")
        return response.status, json.loads(raw)
    finally:
        connection.close()


def main() -> None:
    require(os.environ.get("CATCHPLATE_DEVELOPMENT_SANDBOX") == "1", "not-sandbox")
    require(os.environ.get("CATCHPLATE_RELEASE_CHANNEL") == "dev", "not-dev")
    require(os.environ.get("CATCHPLATE_DATA_DIR") == "/data", "unexpected-data-root")
    status, report = request("GET", "/api/sandbox/status")
    require(status == 200 and report.get("syntheticOnly") is True
            and report.get("productionReady") is False
            and report.get("hardwareVerified") is False, "inactive-synthetic-profile")
    marker = json.loads(Path("/data/.catchplate-development-sandbox.json").read_text())
    require(marker == {"schema": "catchplate.developmentSandbox/v1", "syntheticOnly": True},
            "invalid-sandbox-marker")
    from catchplate.demo_seed_policy import require_demo_semantics
    from catchplate.policy_bundle import policy_hash
    policy = json.loads(Path("/data/policy-bundle.json").read_text())
    require_demo_semantics(policy)
    bundle_hash = policy_hash(policy)
    binary_digest = os.environ["CATCHPLATE_EXPECTED_DATA_PLANE_BINARY_DIGEST"]
    token_path = Path(os.environ["CATCHPLATE_DATA_PLANE_CREDENTIAL_LEASE_TOKEN_FILE"])
    require(token_path == Path("/run/secrets/catchplate/credential-lease.token"), "unexpected-token-path")
    token = token_path.read_text().strip()
    private_key = X25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    key_id = "sha256:" + hashlib.sha256(public_key).hexdigest()
    metadata = None
    for purpose in ("generationMetadata", "dispatchSecret"):
        nonce = os.urandom(32)
        payload = {
            "apiVersion": "catchplate.credentialLeaseRequest/v3", "purpose": purpose,
            "principalId": "agent:demo", "routeId": "demo.echo", "credentialId": "cred-demo-bearer",
            "expectedCredentialVersion": None if metadata is None else metadata["credentialVersion"],
            "expectedMetadataSha256": None if metadata is None else metadata["metadataSha256"],
            "recipientPublicKey": b64e(public_key), "recipientKeyId": key_id,
            "recipientNonce": b64e(nonce), "policyHash": bundle_hash,
            "dataPlaneBinaryDigest": binary_digest, "maxTtlSeconds": 5,
        }
        started = time.monotonic()
        status, envelope = request("POST", "/api/data-plane/credential-leases", payload, token)
        lease_elapsed_ms = round((time.monotonic() - started) * 1000)
        if status != 200:
            # Never print server messages, bodies, envelopes or exception text.
            raise ProbeFailure(purpose + "-http-" + str(status))
        plaintext = decrypt_lease(envelope, recipient_private_key=private_key,
                                  recipient_nonce_raw=nonce, request_payload=payload)
        entry = plaintext["credentials"][0]
        require(entry["credentialId"] == "cred-demo-bearer", "unexpected-credential")
        if purpose == "generationMetadata":
            require("secret" not in entry, "metadata-contained-secret")
            metadata = entry
        else:
            require(entry["secret"] == CREDENTIAL_SECRET, "synthetic-secret-mismatch")
        started = time.monotonic()
        replay_status, rejection = request("POST", "/api/data-plane/credential-leases", payload, token)
        replay_elapsed_ms = round((time.monotonic() - started) * 1000)
        require(replay_status == 409 and rejection.get("detail") == "recipient nonce has already been used",
                purpose + "-replay-not-rejected")
        print(json.dumps({"phase": purpose, "httpStatus": status,
                          "encryptedRoundtrip": True, "bindingsVerified": True,
                          "replayStatus": replay_status, "syntheticOnly": True,
                          "leaseElapsedMs": lease_elapsed_ms,
                          "replayElapsedMs": replay_elapsed_ms}), flush=True)


if __name__ == "__main__":
    try:
        main()
    except ProbeFailure as exc:
        print(json.dumps({"ok": False, "errorLabel": str(exc)}), flush=True)
        raise SystemExit(1) from None
    except Exception as exc:
        print(json.dumps({"ok": False, "errorType": type(exc).__name__}), flush=True)
        raise SystemExit(1) from None
