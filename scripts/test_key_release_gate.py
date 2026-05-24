#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from typing import Any


BASE = os.getenv("BASE", "http://localhost:3000").rstrip("/")
ADMIN_TOKEN = os.getenv("SERVERWARE_ADMIN_TOKEN", "dev-admin-token")


def request_json(path: str, *, payload: dict[str, Any] | None = None, token: str | None = ADMIN_TOKEN) -> tuple[int, dict[str, Any]]:
    data = None if payload is None else json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    headers = {}
    if token:
        headers["X-Serverware-Admin-Token"] = token
    if payload is not None:
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(f"{BASE}{path}", data=data, headers=headers, method="GET" if payload is None else "POST")
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def main() -> None:
    code, attestation = request_json("/attestation?nonce=key-release-test", token=None)
    if code != 200:
        raise SystemExit(f"attestation failed: {code} {attestation}")
    quote = attestation.get("quote") or {}
    claims = quote.get("claims") or {}
    if quote.get("provider") != "dev-signed-quote":
        raise SystemExit(f"unexpected quote provider: {quote}")
    for field in ("runtime_manifest_digest", "policy_bundle_digest", "ca_intermediate_spki_sha256", "data_plane_binary_digest", "rollback_epoch"):
        if claims.get(field) != attestation.get(field):
            raise SystemExit(f"quote claim {field} does not match attestation: {attestation}")

    valid_payload = {
        "expectedPolicyHash": attestation["policy_bundle_digest"],
        "expectedCaSpki": attestation["ca_intermediate_spki_sha256"],
        "expectedRollbackEpoch": attestation["rollback_epoch"],
        "expectedReleaseChannel": attestation["release_channel"],
    }
    if attestation.get("data_plane_binary_digest"):
        valid_payload["expectedDataPlaneBinaryDigest"] = attestation["data_plane_binary_digest"]
    for material in ("broker-kek", "decision-gate-ca"):
        code, valid = request_json("/api/key-release/verify", payload={**valid_payload, "material": material})
        if code != 200 or valid.get("ok") is not True:
            raise SystemExit(f"valid key-release verification failed for {material}: {code} {valid}")

    deadline = time.monotonic() + 20
    status: dict[str, Any] = {}
    while time.monotonic() < deadline:
        code, status = request_json("/api/key-release/status")
        if code == 200:
            materials = status.get("materials") or {}
            if "broker-kek" in materials and "decision-gate-ca" in materials:
                break
        time.sleep(0.25)
    else:
        raise SystemExit(f"key release materials were not published: {status}")

    materials = status["materials"]
    for material in ("broker-kek", "decision-gate-ca"):
        record = materials[material]
        if record.get("policy_bundle_digest") != attestation.get("policy_bundle_digest"):
            raise SystemExit(f"{material} policy digest mismatch: {record}")
        if record.get("ca_intermediate_spki_sha256") != attestation.get("ca_intermediate_spki_sha256"):
            raise SystemExit(f"{material} CA SPKI mismatch: {record}")
        if record.get("data_plane_binary_digest") != attestation.get("data_plane_binary_digest"):
            raise SystemExit(f"{material} data-plane binary digest mismatch: {record}")
        if record.get("rollback_epoch") != attestation.get("rollback_epoch"):
            raise SystemExit(f"{material} rollback epoch mismatch: {record}")
        if not str(record.get("quote_digest", "")).startswith("sha256:"):
            raise SystemExit(f"{material} missing quote digest: {record}")

    code, valid = request_json("/api/key-release/verify", payload={**valid_payload, "material": "broker-kek"})
    if code != 200 or valid.get("ok") is not True:
        raise SystemExit(f"valid key-release verification failed: {code} {valid}")

    code, denied = request_json(
        "/api/key-release/verify",
        payload={**valid_payload, "material": "broker-kek", "expectedPolicyHash": "sha256:" + "0" * 64},
    )
    if code != 409 or "policy digest mismatch" not in str(denied):
        raise SystemExit(f"wrong policy hash was not denied: {code} {denied}")

    code, denied = request_json(
        "/api/key-release/verify",
        payload={**valid_payload, "material": "broker-kek", "expectedRollbackEpoch": int(attestation["rollback_epoch"]) + 1000},
    )
    if code != 409 or "rollback epoch" not in str(denied):
        raise SystemExit(f"stale rollback expectation was not denied: {code} {denied}")

    if attestation.get("data_plane_binary_digest"):
        code, denied = request_json(
            "/api/key-release/verify",
            payload={**valid_payload, "material": "decision-gate-ca", "expectedDataPlaneBinaryDigest": "sha256:" + "1" * 64},
        )
        if code != 409 or "data-plane binary digest mismatch" not in str(denied):
            raise SystemExit(f"wrong data-plane binary digest was not denied: {code} {denied}")

    code, unauth = request_json("/api/key-release/status", token=None)
    if code != 401:
        raise SystemExit(f"unauthenticated key-release status should be denied: {code} {unauth}")

    print(
        json.dumps(
            {
                "ok": True,
                "key_release": "pass",
                "materials": sorted(materials),
                "policy_hash": attestation["policy_bundle_digest"],
                "ca_intermediate_spki_sha256": attestation["ca_intermediate_spki_sha256"],
                "data_plane_binary_digest": attestation.get("data_plane_binary_digest"),
                "rollback_epoch": attestation["rollback_epoch"],
                "quote_provider": quote["provider"],
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
