#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import time
import urllib.error
from pathlib import Path
from typing import Any

from verify_attestation import (
    canonical_json,
    policy_hash,
    request_json,
    spki_hash_from_public_key_pem,
    verify_policy_signature,
    verify_quote,
    verify_runtime_digest,
)


REQUIRED_MATERIALS = {"broker-kek", "decision-gate-ca"}
REQUIRED_DIGEST_FIELDS = (
    "runtime_manifest_digest",
    "policy_bundle_digest",
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
    if not isinstance(claims.get("release_channel"), str) or not claims.get("release_channel"):
        raise ValueError("claim release_channel is required")
    materials = {str(item) for item in (claims.get("materials") or []) if isinstance(item, str)}
    if materials != REQUIRED_MATERIALS:
        raise ValueError("claims must authorize exactly broker-kek and decision-gate-ca")
    if claims.get("debug") and not allow_debug_claims:
        raise ValueError("production readiness claims must not be debug claims")
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
    parser.add_argument("--admin-token", default=os.getenv("SERVERWARE_ADMIN_TOKEN"), help="admin token for policy verification")
    parser.add_argument("--nonce", default=None)
    parser.add_argument("--out", default=None)
    parser.add_argument("--tee-verify-command", default=os.getenv("SERVERWARE_TEE_QUOTE_VERIFY_COMMAND"))
    parser.add_argument("--skip-policy-verify", action="store_true")
    parser.add_argument("--allow-debug-claims", action="store_true")
    args = parser.parse_args()

    if not args.skip_policy_verify and not args.admin_token:
        raise SystemExit("--admin-token or SERVERWARE_ADMIN_TOKEN is required unless --skip-policy-verify is used")

    nonce = args.nonce or f"production-readiness-claims-{int(time.time())}"
    base = args.base.rstrip("/")
    attestation = request_json(f"{base}/attestation?nonce={nonce}")
    if attestation.get("nonce") != nonce:
        raise ValueError("attestation nonce mismatch")
    policy_status = None
    if not args.skip_policy_verify:
        policy_status = request_json(f"{base}/api/policy", args.admin_token)
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
