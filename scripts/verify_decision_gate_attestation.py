#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import secrets
import sys
import time
import urllib.request
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from serverware.http_client import request_bytes


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def sha256_prefixed(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def require_positive_int(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise ValueError(f"{label} must be a positive integer")
    return value


def verify_policy_high_water(
    *,
    attestation: dict[str, Any],
    manifest: dict[str, Any],
    control_attestation: dict[str, Any],
    control_claims: dict[str, Any],
    policy: dict[str, Any],
    require_persisted: bool,
) -> tuple[int, int]:
    metadata = policy.get("metadata") or {}
    if not isinstance(metadata, dict):
        raise ValueError("control-plane policy metadata is invalid")
    policy_id = metadata.get("id")
    if not isinstance(policy_id, str) or not policy_id:
        raise ValueError("control-plane policy id is missing")
    sequence = require_positive_int(metadata.get("sequence"), "control-plane policy sequence")
    rollback_epoch = require_positive_int(
        metadata.get("rollbackEpoch"), "control-plane policy rollback epoch"
    )
    policy_hash = policy.get("policy_hash")

    database_high_water = policy.get("high_water")
    if not isinstance(database_high_water, dict) or set(database_high_water) != {
        "policy_id",
        "sequence",
        "rollback_epoch",
        "policy_hash",
        "updated_at",
    }:
        raise ValueError("control-plane policy endpoint high-water record is invalid")
    expected_database_high_water = {
        "policy_id": policy_id,
        "sequence": sequence,
        "rollback_epoch": rollback_epoch,
        "policy_hash": policy_hash,
    }
    if any(database_high_water.get(key) != value for key, value in expected_database_high_water.items()):
        raise ValueError("control-plane database high-water does not bind the active policy")
    if not isinstance(database_high_water.get("updated_at"), str) or not database_high_water["updated_at"]:
        raise ValueError("control-plane database high-water is missing updated_at")

    control_high_water = control_attestation.get("policy_high_water")
    if not isinstance(control_high_water, dict) or set(control_high_water) != {
        "store",
        "policyId",
        "sequence",
        "rollbackEpoch",
        "policyHash",
        "updatedAt",
    }:
        raise ValueError("control-plane attestation high-water record is invalid")
    expected_control_high_water = {
        "policyId": policy_id,
        "sequence": sequence,
        "rollbackEpoch": rollback_epoch,
        "policyHash": policy_hash,
        "updatedAt": database_high_water["updated_at"],
    }
    if any(control_high_water.get(key) != value for key, value in expected_control_high_water.items()):
        raise ValueError("control-plane attestation high-water does not match the database record")
    if control_high_water.get("store") not in {"sqlite", "postgres"}:
        raise ValueError("control-plane attestation high-water store is unsupported")
    control_high_water_digest = sha256_prefixed(canonical_json(control_high_water).encode("utf-8"))
    if control_attestation.get("policy_high_water_digest") != control_high_water_digest:
        raise ValueError("control-plane attestation high-water digest mismatch")
    for field, expected in (
        ("policy_sequence", sequence),
        ("rollback_epoch", rollback_epoch),
        ("policy_high_water_digest", control_high_water_digest),
    ):
        if control_attestation.get(field) != expected or control_claims.get(field) != expected:
            raise ValueError(f"control-plane quote {field} claim mismatch")

    gate_high_water = attestation.get("policy_high_water")
    if not isinstance(gate_high_water, dict) or set(gate_high_water) != {
        "api_version",
        "policy_id",
        "sequence",
        "rollback_epoch",
        "policy_hash",
    }:
        raise ValueError("decision gate policy high-water record is invalid")
    expected_gate_high_water = {
        "api_version": "serverware.policyHighWater/v1",
        "policy_id": policy_id,
        "sequence": sequence,
        "rollback_epoch": rollback_epoch,
        "policy_hash": policy_hash,
    }
    if gate_high_water != expected_gate_high_water:
        raise ValueError("decision gate policy high-water does not bind the active policy")
    for field, expected in (
        ("policy_id", policy_id),
        ("policy_sequence", sequence),
        ("policy_rollback_epoch", rollback_epoch),
        ("policy_high_water", gate_high_water),
    ):
        if attestation.get(field) != expected or manifest.get(field) != expected:
            raise ValueError(f"decision gate {field} attestation mismatch")
    persisted = attestation.get("policy_high_water_persisted")
    if not isinstance(persisted, bool) or manifest.get("policy_high_water_persisted") is not persisted:
        raise ValueError("decision gate high-water persistence claim mismatch")
    if require_persisted and not persisted:
        raise ValueError("decision gate policy high-water must be persisted")
    return sequence, rollback_epoch


def request_json(url: str, admin_token: str | None = None) -> dict[str, Any]:
    headers = {}
    if admin_token:
        headers["X-Serverware-Admin-Token"] = admin_token
    request = urllib.request.Request(url, headers=headers)
    return json.loads(request_bytes(request, timeout=10, max_bytes=8 * 1024 * 1024).body)


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify the Rust decision-gate dev attestation.")
    parser.add_argument("--gate", default="http://localhost:9090")
    parser.add_argument("--serverware", default="http://localhost:3000")
    parser.add_argument("--admin-token", default="dev-admin-token")
    parser.add_argument("--expected-binary-digest")
    parser.add_argument("--require-persisted-high-water", action="store_true")
    args = parser.parse_args()

    gate = args.gate.rstrip("/")
    serverware = args.serverware.rstrip("/")
    deadline = time.monotonic() + 15
    while True:
        nonce = secrets.token_urlsafe(24)
        attestation = request_json(f"{gate}/attestation?nonce={nonce}")
        health = request_json(f"{gate}/healthz")
        policy = request_json(f"{serverware}/api/policy", args.admin_token)
        control_attestation = request_json(f"{serverware}/attestation?nonce={nonce}-control")
        policy_hash = policy.get("policy_hash")
        manifest = attestation.get("runtime_manifest")
        observed_hashes = {
            attestation.get("policy_bundle_digest"),
            health.get("policy_hash"),
            manifest.get("policy_hash") if isinstance(manifest, dict) else None,
            control_attestation.get("policy_bundle_digest"),
            policy_hash,
        }
        if None not in observed_hashes and len(observed_hashes) == 1:
            break
        if time.monotonic() >= deadline:
            raise ValueError(f"decision gate policy did not converge across attested reads: {sorted(map(str, observed_hashes))}")
        time.sleep(0.25)

    if attestation.get("nonce") != nonce:
        raise ValueError("decision gate attestation nonce mismatch")
    if control_attestation.get("nonce") != f"{nonce}-control":
        raise ValueError("control-plane attestation nonce mismatch")
    manifest = attestation.get("runtime_manifest")
    if not isinstance(manifest, dict):
        raise ValueError("decision gate attestation missing runtime_manifest")
    expected_manifest_digest = sha256_prefixed(canonical_json(manifest).encode("utf-8"))
    if attestation.get("runtime_manifest_digest") != expected_manifest_digest:
        raise ValueError("decision gate runtime_manifest_digest mismatch")
    binary_digest = attestation.get("data_plane_binary_digest")
    if not isinstance(binary_digest, str) or not binary_digest.startswith("sha256:"):
        raise ValueError("decision gate missing binary digest")
    if manifest.get("binary_digest") != binary_digest:
        raise ValueError("decision gate manifest binary digest mismatch")
    if health.get("data_plane_binary_digest") != binary_digest:
        raise ValueError("decision gate health binary digest mismatch")
    if args.expected_binary_digest and args.expected_binary_digest != binary_digest:
        raise ValueError("decision gate binary digest does not match expected digest")
    control_binary_digest = control_attestation.get("data_plane_binary_digest")
    if control_binary_digest and control_binary_digest != binary_digest:
        raise ValueError("control-plane data-plane binary digest does not match running decision gate")
    control_quote = control_attestation.get("quote") or {}
    control_claims = control_quote.get("claims") or {}
    if not isinstance(control_claims, dict):
        raise ValueError("control-plane quote claims are missing")
    if control_claims.get("data_plane_binary_digest") != control_binary_digest:
        raise ValueError("control-plane quote data-plane binary digest claim mismatch")
    control_image_signatures = control_attestation.get("image_signatures_digest")
    gate_image_signatures = attestation.get("image_signatures_digest")
    if control_image_signatures != gate_image_signatures:
        raise ValueError("control-plane and decision gate image signatures digest mismatch")
    if control_claims.get("image_signatures_digest") != control_image_signatures:
        raise ValueError("control-plane quote image signatures digest claim mismatch")

    signing_key_id = (policy.get("metadata") or {}).get("signingKeyId")
    if attestation.get("policy_bundle_digest") != policy_hash:
        raise ValueError("decision gate policy hash does not match control plane")
    if manifest.get("policy_hash") != policy_hash or health.get("policy_hash") != policy_hash:
        raise ValueError("decision gate policy hash is inconsistent")
    if attestation.get("policy_signing_key_id") != signing_key_id:
        raise ValueError("decision gate policy signing key does not match control plane")
    if manifest.get("policy_signing_key_id") != signing_key_id:
        raise ValueError("decision gate manifest policy signing key mismatch")
    policy_sequence, rollback_epoch = verify_policy_high_water(
        attestation=attestation,
        manifest=manifest,
        control_attestation=control_attestation,
        control_claims=control_claims,
        policy=policy,
        require_persisted=args.require_persisted_high_water,
    )

    hot_path = manifest.get("hot_path") or {}
    if hot_path.get("sqlite_calls") != 0 or hot_path.get("filesystem_calls") != 0:
        raise ValueError("decision gate hot path must report zero SQLite/filesystem calls")
    if (
        manifest.get("jit_grant_store") != "atomic_release_authorization"
        or health.get("jit_grant_store") != "atomic_release_authorization"
        or manifest.get("release_authorization_mode") != "reserve_dispatch_complete"
    ):
        raise ValueError("decision gate must attest the atomic reserve/dispatch/complete release authority")
    release_authorization = health.get("release_authorization") or {}
    if release_authorization.get("enabled") is not True or release_authorization.get("mode") != "reserve_dispatch_complete":
        raise ValueError("decision gate health must report the atomic release authorization lifecycle")

    print(
        json.dumps(
            {
                "ok": True,
                "data_plane_binary_digest": binary_digest,
                "policy_hash": policy_hash,
                "policy_sequence": policy_sequence,
                "rollback_epoch": rollback_epoch,
                "policy_high_water_persisted": attestation.get("policy_high_water_persisted"),
                "policy_signing_key_id": signing_key_id,
                "tee_platform": attestation.get("tee_platform"),
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
