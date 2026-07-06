#!/usr/bin/env python3
from __future__ import annotations

import base64
import copy
import json
import tempfile
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import generate_production_readiness_claims as generator
from verify_attestation import canonical_json, policy_hash


def b64e(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def sha256_prefixed(value: bytes) -> str:
    import hashlib

    return "sha256:" + hashlib.sha256(value).hexdigest()


def key_info(key: Ed25519PrivateKey) -> dict[str, str]:
    public_key = key.public_key()
    pem = public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return {"pem": pem, "spki_sha256": sha256_prefixed(der)}


def signature_payload(bundle: dict[str, Any]) -> dict[str, Any]:
    copied = copy.deepcopy(bundle)
    copied.setdefault("metadata", {}).pop("signature", None)
    return copied


def sign_policy_bundle(bundle: dict[str, Any], key: Ed25519PrivateKey) -> dict[str, Any]:
    signed = copy.deepcopy(bundle)
    signed.setdefault("metadata", {})["signature"] = "ed25519:" + b64e(
        key.sign(canonical_json(signature_payload(signed)).encode("utf-8"))
    )
    return signed


def sign_quote(quote: dict[str, Any], key: Ed25519PrivateKey) -> dict[str, Any]:
    signed = copy.deepcopy(quote)
    unsigned = copy.deepcopy(signed)
    unsigned.pop("signature", None)
    signed["signature"] = "ed25519:" + b64e(key.sign(canonical_json(unsigned).encode("utf-8")))
    return signed


def fixture(debug: bool = False, materials: list[str] | None = None) -> tuple[dict[str, Any], dict[str, Any]]:
    policy_key = Ed25519PrivateKey.generate()
    policy_info = key_info(policy_key)
    bundle = sign_policy_bundle(
        {
            "apiVersion": "serverware.policy/v1",
            "kind": "PolicyBundle",
            "metadata": {
                "id": "readiness-test",
                "sequence": 1,
                "rollbackEpoch": 7,
                "signingKeyId": policy_info["spki_sha256"],
            },
            "defaults": {"action": "deny"},
            "routes": [],
        },
        policy_key,
    )
    bundle_hash = policy_hash(bundle)
    manifest = {
        "mode": "tee",
        "tee_quote_provider": "aws-nitro-enclaves",
        "tee_platform": "aws-nitro",
        "release_channel": "prod",
        "policy_signing_key_id": policy_info["spki_sha256"],
    }
    runtime_digest = sha256_prefixed(repr(sorted(manifest.items())).encode("utf-8"))
    claims = {
        "nonce": "attestation-nonce",
        "runtime_manifest_digest": runtime_digest,
        "policy_bundle_digest": bundle_hash,
        "policy_signing_key_id": policy_info["spki_sha256"],
        "ca_intermediate_spki_sha256": "sha256:" + "c" * 64,
        "data_plane_binary_digest": "sha256:" + "d" * 64,
        "service_tls_spki_sha256": None,
        "rollback_epoch": 7,
        "release_channel": "prod",
        "provenance_digest": "sha256:" + "e" * 64,
        "image_signatures_digest": "sha256:" + "f" * 64,
        "source_tree_digest": "sha256:" + "1" * 64,
        "response_signing_key_id": "sha256:" + "2" * 64,
        "materials": materials or ["broker-kek", "decision-gate-ca"],
        "debug": debug,
        "key_release_required": True,
        "key_release_allow_debug": False,
        "sealing_public_key_id": "sha256:" + "3" * 64,
    }
    quote_key = Ed25519PrivateKey.generate()
    quote_info = key_info(quote_key)
    quote = sign_quote(
        {
            "version": 1,
            "provider": "dev-signed-quote",
            "tee_platform": "none-dev",
            "issued_at_ms": 1779698000000,
            "debug": debug,
            "quote_signing_key_id": quote_info["spki_sha256"],
            "quote_signing_public_key_pem": quote_info["pem"],
            "claims": claims,
        },
        quote_key,
    )
    attestation = {
        "tee_platform": "none-dev",
        "quote": quote,
        "runtime_manifest": manifest,
        "runtime_manifest_digest": runtime_digest,
        "policy_bundle_digest": bundle_hash,
        "policy_bundle_signature": bundle["metadata"]["signature"],
        "policy_signing_key_id": policy_info["spki_sha256"],
        "policy_signing_public_key_pem": policy_info["pem"],
        "ca_intermediate_spki_sha256": claims["ca_intermediate_spki_sha256"],
        "data_plane_binary_digest": claims["data_plane_binary_digest"],
        "service_tls_spki_sha256": None,
        "rollback_epoch": claims["rollback_epoch"],
        "release_channel": claims["release_channel"],
        "provenance_digest": claims["provenance_digest"],
        "image_signatures_digest": claims["image_signatures_digest"],
        "source_tree_digest": claims["source_tree_digest"],
        "response_signing_key_id": claims["response_signing_key_id"],
        "nonce": "attestation-nonce",
    }
    return attestation, {"bundle": bundle, "policy_hash": bundle_hash}


def expect_failure(attestation: dict[str, Any], policy_status: dict[str, Any] | None, expected: str) -> None:
    try:
        generator.readiness_claims_from_attestation(attestation, policy_status, nonce="readiness-nonce")
    except ValueError as exc:
        if expected not in str(exc):
            raise AssertionError(f"wrong failure, expected {expected!r}: {exc}") from exc
    else:
        raise AssertionError(f"claims generation unexpectedly accepted invalid input for {expected!r}")


def main() -> None:
    attestation, policy_status = fixture()
    claims = generator.readiness_claims_from_attestation(attestation, policy_status, nonce="readiness-nonce")
    if claims["nonce"] != "readiness-nonce":
        raise AssertionError(f"claims did not use the readiness nonce: {claims}")
    if claims["policy_bundle_digest"] != attestation["policy_bundle_digest"]:
        raise AssertionError(f"claims did not bind the attested policy digest: {claims}")
    if set(claims["materials"]) != {"broker-kek", "decision-gate-ca"}:
        raise AssertionError(f"claims did not preserve authorized release materials: {claims}")
    if claims["debug"] is not False:
        raise AssertionError(f"production claims should not be debug: {claims}")

    with tempfile.TemporaryDirectory() as tmp_raw:
        output = Path(tmp_raw) / "claims.json"
        digest = generator.write_claims(output, claims)
        written = json.loads(output.read_text(encoding="utf-8"))
        if written != claims or not digest.startswith("sha256:"):
            raise AssertionError("claims writer did not persist the expected JSON")

    debug_attestation, debug_policy = fixture(debug=True)
    expect_failure(debug_attestation, debug_policy, "debug claims")
    allowed_debug = generator.readiness_claims_from_attestation(
        debug_attestation,
        debug_policy,
        nonce="debug-readiness",
        allow_debug_claims=True,
    )
    if allowed_debug["debug"] is not True:
        raise AssertionError(f"debug opt-in did not preserve debug claim: {allowed_debug}")

    missing_material_attestation, missing_material_policy = fixture(materials=["broker-kek"])
    expect_failure(missing_material_attestation, missing_material_policy, "exactly broker-kek and decision-gate-ca")

    extra_material_attestation, extra_material_policy = fixture(materials=["broker-kek", "decision-gate-ca", "debug-material"])
    expect_failure(extra_material_attestation, extra_material_policy, "exactly broker-kek and decision-gate-ca")

    bad_policy = copy.deepcopy(policy_status)
    bad_policy["policy_hash"] = "sha256:" + "0" * 64
    expect_failure(attestation, bad_policy, "policy endpoint hash mismatch")

    tampered_attestation = copy.deepcopy(attestation)
    tampered_attestation["source_tree_digest"] = "sha256:" + "9" * 64
    expect_failure(tampered_attestation, policy_status, "source_tree_digest")

    print(json.dumps({"ok": True, "production_readiness_claims": "pass"}, sort_keys=True))


if __name__ == "__main__":
    main()
