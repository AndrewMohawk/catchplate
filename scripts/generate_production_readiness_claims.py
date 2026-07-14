#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import ssl
import sys
import time
import urllib.error
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from verify_attestation import (
    canonical_json,
    policy_hash,
    spki_hash_from_public_key_pem,
    verify_policy_signature,
    verify_quote,
    verify_runtime_digest,
)
from serverware.http_client import request_bytes


REQUIRED_MATERIALS = {"broker-kek", "decision-gate-ca"}
REQUIRED_DIGEST_FIELDS = (
    "runtime_manifest_digest",
    "policy_bundle_digest",
    "policy_high_water_digest",
    "ca_intermediate_spki_sha256",
    "data_plane_binary_digest",
    "provenance_digest",
    "image_signatures_digest",
    "source_tree_digest",
    "response_signing_key_id",
)
OPTIONAL_COPY_FIELDS = (
    "policy_signing_key_id",
    "service_tls_spki_sha256",
    "key_release_required",
    "key_release_allow_debug",
    "sealing_public_key_id",
)


def sha256_prefixed(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def request_json(url: str, admin_token: str | None = None, *, ca_bundle: str | None = None) -> dict[str, Any]:
    headers = {"X-Serverware-Admin-Token": admin_token} if admin_token else {}
    request = urllib.request.Request(url, headers=headers)
    context = ssl.create_default_context(cafile=ca_bundle) if ca_bundle else None
    return json.loads(
        request_bytes(request, timeout=10, max_bytes=8 * 1024 * 1024, context=context).body
    )


def require_sha256_claim(claims: dict[str, Any], field: str) -> None:
    value = claims.get(field)
    if not isinstance(value, str) or not value.startswith("sha256:") or len(value) != 71:
        raise ValueError(f"claim {field} must be a sha256: digest")
    try:
        bytes.fromhex(value.removeprefix("sha256:"))
    except ValueError as exc:
        raise ValueError(f"claim {field} must be a sha256: digest") from exc


def extract_quote_claims(attestation: dict[str, Any]) -> dict[str, Any]:
    quote = attestation.get("quote")
    if not isinstance(quote, dict):
        raise ValueError("attestation is missing quote")
    claims = quote.get("claims")
    if not isinstance(claims, dict):
        raise ValueError("attestation quote is missing claims")
    return json.loads(json.dumps(claims))


def verify_policy_binding(attestation: dict[str, Any], policy_status: dict[str, Any]) -> None:
    public_key_pem = attestation.get("policy_signing_public_key_pem")
    if not isinstance(public_key_pem, str):
        raise ValueError("attestation missing policy signing public key")
    key_hash = spki_hash_from_public_key_pem(public_key_pem)
    if attestation.get("policy_signing_key_id") != key_hash:
        raise ValueError("policy signing key hash does not match public key")
    bundle = policy_status.get("bundle")
    if not isinstance(bundle, dict):
        raise ValueError("policy endpoint did not return a signed bundle")
    verify_policy_signature(bundle, public_key_pem)
    computed_policy_hash = policy_hash(bundle)
    if computed_policy_hash != policy_status.get("policy_hash"):
        raise ValueError("policy endpoint hash mismatch")
    if computed_policy_hash != attestation.get("policy_bundle_digest"):
        raise ValueError("attestation policy digest mismatch")
    if (bundle.get("metadata") or {}).get("signature") != attestation.get("policy_bundle_signature"):
        raise ValueError("attestation policy signature mismatch")
    metadata = bundle.get("metadata") or {}
    sequence = metadata.get("sequence")
    rollback_epoch = metadata.get("rollbackEpoch")
    policy_id = metadata.get("id")
    if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 1:
        raise ValueError("policy sequence must be a positive integer")
    if not isinstance(rollback_epoch, int) or isinstance(rollback_epoch, bool) or rollback_epoch < 1:
        raise ValueError("policy rollback epoch must be a positive integer")
    database_high_water = policy_status.get("high_water")
    expected_database_high_water = {
        "policy_id": policy_id,
        "sequence": sequence,
        "rollback_epoch": rollback_epoch,
        "policy_hash": computed_policy_hash,
    }
    if not isinstance(database_high_water, dict) or set(database_high_water) != {
        "policy_id",
        "sequence",
        "rollback_epoch",
        "policy_hash",
        "updated_at",
    } or any(
        database_high_water.get(key) != value for key, value in expected_database_high_water.items()
    ):
        raise ValueError("policy endpoint high-water does not bind the signed bundle")
    if not isinstance(database_high_water.get("updated_at"), str) or not database_high_water["updated_at"]:
        raise ValueError("policy endpoint high-water is missing updated_at")
    attested_high_water = attestation.get("policy_high_water")
    expected_attested_high_water = {
        "policyId": policy_id,
        "sequence": sequence,
        "rollbackEpoch": rollback_epoch,
        "policyHash": computed_policy_hash,
        "updatedAt": database_high_water["updated_at"],
    }
    if not isinstance(attested_high_water, dict) or set(attested_high_water) != {
        "store",
        "policyId",
        "sequence",
        "rollbackEpoch",
        "policyHash",
        "updatedAt",
    } or any(
        attested_high_water.get(key) != value for key, value in expected_attested_high_water.items()
    ):
        raise ValueError("attestation high-water does not bind the signed bundle")
    if attested_high_water.get("store") not in {"sqlite", "postgres"}:
        raise ValueError("attestation high-water store is unsupported")
    high_water_digest = sha256_prefixed(canonical_json(attested_high_water).encode("utf-8"))
    if attestation.get("policy_high_water_digest") != high_water_digest:
        raise ValueError("attestation policy high-water digest mismatch")
    if attestation.get("policy_sequence") != sequence or attestation.get("rollback_epoch") != rollback_epoch:
        raise ValueError("attestation policy monotonic metadata mismatch")


def readiness_claims_from_attestation(
    attestation: dict[str, Any],
    policy_status: dict[str, Any] | None,
    *,
    nonce: str,
    tee_verify_command: str | None = None,
    allow_debug_claims: bool = False,
) -> dict[str, Any]:
    verify_runtime_digest(attestation)
    verify_quote(attestation, tee_verify_command)
    if policy_status is not None:
        verify_policy_binding(attestation, policy_status)

    source_claims = extract_quote_claims(attestation)
    claims = {field: source_claims.get(field) for field in REQUIRED_DIGEST_FIELDS}
    for field in OPTIONAL_COPY_FIELDS:
        if field in source_claims:
            claims[field] = source_claims.get(field)
    claims["nonce"] = nonce
    claims["policy_sequence"] = source_claims.get("policy_sequence")
    claims["rollback_epoch"] = source_claims.get("rollback_epoch")
    claims["release_channel"] = source_claims.get("release_channel")
    claims["materials"] = source_claims.get("materials")
    claims["debug"] = bool(source_claims.get("debug"))

    for field in REQUIRED_DIGEST_FIELDS:
        require_sha256_claim(claims, field)
        if claims.get(field) != attestation.get(field):
            raise ValueError(f"claim {field} does not match attestation")
    if not isinstance(claims.get("rollback_epoch"), int):
        raise ValueError("claim rollback_epoch must be an integer")
    if not isinstance(claims.get("policy_sequence"), int) or isinstance(claims["policy_sequence"], bool) or claims["policy_sequence"] < 1:
        raise ValueError("claim policy_sequence must be a positive integer")
    if claims["policy_sequence"] != attestation.get("policy_sequence"):
        raise ValueError("claim policy_sequence does not match attestation")
    if not isinstance(claims.get("release_channel"), str) or not claims.get("release_channel"):
        raise ValueError("claim release_channel is required")
    materials = {str(item) for item in (claims.get("materials") or []) if isinstance(item, str)}
    if materials != REQUIRED_MATERIALS:
        raise ValueError("claims must authorize exactly broker-kek and decision-gate-ca")
    if claims.get("debug") and not allow_debug_claims:
        raise ValueError("production readiness claims must not be debug claims")
    if not allow_debug_claims:
        require_sha256_claim(claims, "service_tls_spki_sha256")
        if claims["service_tls_spki_sha256"] != attestation.get("service_tls_spki_sha256"):
            raise ValueError("claim service_tls_spki_sha256 does not match attestation")
    return claims


def write_claims(path: Path, claims: dict[str, Any]) -> str:
    payload = (json.dumps(claims, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode("utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    os.chmod(path, 0o600)
    return sha256_prefixed(payload)


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate a verified claims file for production Nitro/KMS readiness probes.")
    parser.add_argument("--base", default="http://localhost:3000", help="Serverware control-plane base URL")
    parser.add_argument("--ca-bundle", default=None, help="CA bundle for the production control-plane TLS service")
    parser.add_argument("--admin-token", default=os.getenv("SERVERWARE_ADMIN_TOKEN"), help="admin token for policy verification")
    parser.add_argument("--nonce", default=None)
    parser.add_argument("--out", default=None)
    parser.add_argument("--tee-verify-command", default=os.getenv("SERVERWARE_TEE_QUOTE_VERIFY_COMMAND"))
    parser.add_argument("--skip-policy-verify", action="store_true")
    parser.add_argument("--allow-debug-claims", action="store_true")
    args = parser.parse_args()

    if not args.skip_policy_verify and not args.admin_token:
        raise SystemExit("--admin-token or SERVERWARE_ADMIN_TOKEN is required unless --skip-policy-verify is used")
    if args.skip_policy_verify and not args.allow_debug_claims:
        raise ValueError("production readiness claims may not skip signed policy and high-water verification")

    nonce = args.nonce or f"production-readiness-claims-{int(time.time())}"
    base = args.base.rstrip("/")
    if not args.allow_debug_claims and not base.startswith("https://"):
        raise ValueError("production readiness claims require an HTTPS control-plane base URL")
    if not args.allow_debug_claims and not args.ca_bundle:
        raise ValueError("production readiness claims require --ca-bundle")
    attestation = request_json(f"{base}/attestation?nonce={nonce}", ca_bundle=args.ca_bundle)
    if attestation.get("nonce") != nonce:
        raise ValueError("attestation nonce mismatch")
    policy_status = None
    if not args.skip_policy_verify:
        policy_status = request_json(f"{base}/api/policy", args.admin_token, ca_bundle=args.ca_bundle)
    claims = readiness_claims_from_attestation(
        attestation,
        policy_status,
        nonce=nonce,
        tee_verify_command=args.tee_verify_command,
        allow_debug_claims=args.allow_debug_claims,
    )

    if args.out:
        output_path = Path(args.out)
        claims_sha256 = write_claims(output_path, claims)
        print(
            json.dumps(
                {
                    "ok": True,
                    "claims_path": str(output_path),
                    "claims_sha256": claims_sha256,
                    "policy_bundle_digest": claims["policy_bundle_digest"],
                    "release_channel": claims["release_channel"],
                    "rollback_epoch": claims["rollback_epoch"],
                    "materials": claims["materials"],
                },
                sort_keys=True,
            )
        )
    else:
        print(json.dumps(claims, indent=2, sort_keys=True, ensure_ascii=True))


if __name__ == "__main__":
    try:
        main()
    except (urllib.error.URLError, ValueError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, sort_keys=True))
        raise SystemExit(1) from exc
