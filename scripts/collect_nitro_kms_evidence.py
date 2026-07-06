#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import shlex
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
REQUIRED_MATERIALS = ("broker-kek", "decision-gate-ca")
AUTHORIZED_MATERIALS = set(REQUIRED_MATERIALS)
SAFE_CLAIM_FIELDS = (
    "nonce",
    "runtime_manifest_digest",
    "policy_bundle_digest",
    "ca_intermediate_spki_sha256",
    "data_plane_binary_digest",
    "rollback_epoch",
    "release_channel",
    "provenance_digest",
    "image_signatures_digest",
    "source_tree_digest",
    "response_signing_key_id",
    "materials",
    "debug",
)
SECRET_FIELD_NAMES = {
    "plaintext",
    "secret",
    "password",
    "private_key",
    "private_key_pem",
    "raw_material",
    "material_value",
    "unwrapped_key",
    "decrypted_key",
}


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_prefixed(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def sha256_prefixed_json(value: Any) -> str:
    return sha256_prefixed(canonical_json(value).encode("utf-8"))


def b64d(value: str, label: str = "base64url value") -> bytes:
    try:
        return base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except Exception as exc:
        raise RuntimeError(f"{label} is invalid base64url") from exc


def env_bool(env: dict[str, str], name: str, default: bool = False) -> bool:
    raw = env.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def command_words(raw: str) -> list[str]:
    try:
        return shlex.split(raw)
    except ValueError:
        return []


def command_mentions(raw: str, *needles: str) -> bool:
    lowered = " ".join(command_words(raw)).lower()
    return any(needle.lower() in lowered for needle in needles)


def load_claims(env: dict[str, str], claims_file: str | None, nonce: str | None) -> dict[str, Any]:
    if claims_file:
        parsed = json.loads(Path(claims_file).read_text(encoding="utf-8"))
    else:
        raw = env.get("SERVERWARE_PRODUCTION_READINESS_CLAIMS_JSON", "").strip()
        if not raw:
            raise RuntimeError("claims require --claims-file or SERVERWARE_PRODUCTION_READINESS_CLAIMS_JSON")
        parsed = json.loads(raw)
    if not isinstance(parsed, dict):
        raise RuntimeError("claims must be a JSON object")
    claims = json.loads(json.dumps(parsed))
    claims["nonce"] = nonce or f"nitro-kms-evidence-{int(time.time())}"
    return claims


def assert_no_secret_fields(value: Any, path: str = "$") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            key_name = str(key).lower()
            if key_name in SECRET_FIELD_NAMES:
                raise RuntimeError(f"refusing to include secret-like response field {path}.{key}")
            assert_no_secret_fields(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            assert_no_secret_fields(child, f"{path}[{index}]")


def validate_live_config(env: dict[str, str], *, allow_fixtures_for_test: bool) -> None:
    attestation_command = env.get("SERVERWARE_NITRO_ATTESTATION_COMMAND", "").strip()
    kms_command = env.get("SERVERWARE_NITRO_KMS_RELEASE_COMMAND", "").strip()
    if not attestation_command:
        raise RuntimeError("SERVERWARE_NITRO_ATTESTATION_COMMAND must be configured")
    if not kms_command:
        raise RuntimeError("SERVERWARE_NITRO_KMS_RELEASE_COMMAND must be configured")
    if not env_bool(env, "SERVERWARE_NITRO_REQUIRE_KMS_COMMAND"):
        raise RuntimeError("SERVERWARE_NITRO_REQUIRE_KMS_COMMAND must be enabled")
    if allow_fixtures_for_test:
        return
    if env_bool(env, "SERVERWARE_NITRO_FIXTURE"):
        raise RuntimeError("live Nitro evidence must not use SERVERWARE_NITRO_FIXTURE")
    if env.get("SERVERWARE_NITRO_ATTESTATION_DOCUMENT") or env.get("SERVERWARE_NITRO_ATTESTATION_DOCUMENT_B64"):
        raise RuntimeError("live Nitro evidence must use a fresh attestation command, not a static document")
    if command_mentions(attestation_command, "fixture", "nitro_attestation_fixture.py"):
        raise RuntimeError("live Nitro evidence must not use the attestation fixture helper")
    if command_mentions(kms_command, "fixture", "nitro_kms_fixture.py"):
        raise RuntimeError("live Nitro evidence must not use the KMS fixture helper")


def run_provider(mode: str, payload: dict[str, Any], env: dict[str, str]) -> dict[str, Any]:
    result = subprocess.run(
        [sys.executable, "scripts/aws_nitro_tee_provider.py", mode],
        cwd=ROOT,
        env=env,
        input=(canonical_json(payload) + "\n").encode("utf-8"),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=180,
        check=False,
    )
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace") or result.stdout.decode("utf-8", errors="replace")
        raise RuntimeError(f"aws_nitro_tee_provider.py {mode} failed with exit {result.returncode}: {detail.strip()}")
    parsed = json.loads(result.stdout.decode("utf-8"))
    if not isinstance(parsed, dict):
        raise RuntimeError(f"aws_nitro_tee_provider.py {mode} returned non-object JSON")
    assert_no_secret_fields(parsed)
    return parsed


def expected_from_claims(claims: dict[str, Any]) -> dict[str, Any]:
    return {
        "policy_bundle_digest": claims.get("policy_bundle_digest"),
        "ca_intermediate_spki_sha256": claims.get("ca_intermediate_spki_sha256"),
        "rollback_epoch": claims.get("rollback_epoch"),
        "release_channel": claims.get("release_channel"),
        "provenance_digest": claims.get("provenance_digest"),
        "source_tree_digest": claims.get("source_tree_digest"),
        "response_signing_key_id": claims.get("response_signing_key_id"),
        "data_plane_binary_digest": claims.get("data_plane_binary_digest"),
    }


def requested_materials(claims: dict[str, Any], materials: list[str] | None) -> list[str]:
    requested = materials or list(REQUIRED_MATERIALS)
    if not requested:
        raise RuntimeError("at least one material is required")
    unauthorized_requested = sorted(set(requested) - AUTHORIZED_MATERIALS)
    if unauthorized_requested:
        raise RuntimeError(f"unauthorized requested materials: {', '.join(unauthorized_requested)}")
    authorized = {str(item) for item in (claims.get("materials") or []) if isinstance(item, str)}
    unexpected_authorized = sorted(authorized - AUTHORIZED_MATERIALS)
    if unexpected_authorized:
        raise RuntimeError(f"claims authorize unauthorized materials: {', '.join(unexpected_authorized)}")
    missing = [material for material in requested if material not in authorized]
    if missing:
        raise RuntimeError(f"claims do not authorize requested materials: {', '.join(missing)}")
    return requested


def redacted_claims(claims: dict[str, Any]) -> dict[str, Any]:
    safe = {field: claims.get(field) for field in SAFE_CLAIM_FIELDS if field in claims}
    omitted = sorted(set(claims) - set(safe))
    return {
        "sha256": sha256_prefixed_json(claims),
        "fields": safe,
        "omitted_fields": omitted,
    }


def redacted_key_provider(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    allowed = {"type", "key_id", "key_arn", "arn", "kid", "hsm_cluster", "partition", "slot", "label"}
    return {key: value.get(key) for key in sorted(allowed) if value.get(key) is not None}


def redacted_kms_release(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    result: dict[str, Any] = {
        "ok": value.get("ok"),
        "provider": value.get("provider"),
        "material": value.get("material"),
        "request_digest": value.get("request_digest"),
        "release_handle": value.get("release_handle"),
        "ciphertext_blob_sha256": value.get("ciphertext_blob_sha256"),
        "encryption_context_sha256": value.get("encryption_context_sha256"),
        "material_handle": value.get("material_handle"),
        "recipient_ciphertext_sha256": value.get("recipient_ciphertext_sha256"),
        "attestation_document_sha256": value.get("attestation_document_sha256"),
        "key_provider": redacted_key_provider(value.get("key_provider")),
        "audit": value.get("audit") if isinstance(value.get("audit"), dict) else None,
    }
    if isinstance(value.get("signature"), str):
        result["signature_sha256"] = sha256_prefixed(value["signature"].encode("utf-8"))
    if isinstance(value.get("public_key_pem"), str):
        result["public_key_sha256"] = sha256_prefixed(value["public_key_pem"].encode("utf-8"))
    included = {
        "ok",
        "provider",
        "material",
        "request_digest",
        "release_handle",
        "ciphertext_blob_sha256",
        "encryption_context_sha256",
        "material_handle",
        "recipient_ciphertext_sha256",
        "attestation_document_sha256",
        "key_provider",
        "audit",
        "signature",
        "public_key_pem",
    }
    result["omitted_fields"] = sorted(set(value) - included)
    return {key: child for key, child in result.items() if child is not None}


def redacted_release(value: dict[str, Any]) -> dict[str, Any]:
    return {
        "ok": value.get("ok"),
        "provider": value.get("provider"),
        "material": value.get("material"),
        "release_handle": value.get("release_handle"),
        "kms_command_configured": value.get("kms_command_configured"),
        "kms_command_required": value.get("kms_command_required"),
        "kms_request_digest": value.get("kms_request_digest"),
        "kms_release": redacted_kms_release(value.get("kms_release")),
    }


def redacted_tee(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    fields = (
        "provider",
        "tee_platform",
        "verified",
        "debug",
        "module_id",
        "timestamp",
        "digest",
        "pcrs",
        "certificate_sha256",
        "root_sha256",
        "user_data_sha256",
        "raw_attestation_document_sha256",
    )
    return {field: value.get(field) for field in fields if value.get(field) is not None}


def collect_evidence(
    claims: dict[str, Any],
    env: dict[str, str],
    *,
    materials: list[str] | None = None,
    allow_fixtures_for_test: bool = False,
) -> dict[str, Any]:
    validate_live_config(env, allow_fixtures_for_test=allow_fixtures_for_test)
    material_names = requested_materials(claims, materials)
    quote = run_provider("quote", {"claims": claims}, env)
    verified = run_provider("verify", {"quote": quote}, env)
    verified_claims = verified.get("claims") or {}
    tee = verified_claims.get("tee") or {}
    if not isinstance(verified_claims, dict) or not isinstance(tee, dict) or tee.get("verified") is not True:
        raise RuntimeError(f"Nitro quote did not verify: {verified}")

    expected = expected_from_claims(claims)
    releases = [
        redacted_release(
            run_provider(
                "release",
                {"material": material, "claims": verified_claims, "expected": expected},
                env,
            )
        )
        for material in material_names
    ]

    raw_b64 = quote.get("raw_attestation_document_b64")
    raw_attestation = b64d(raw_b64, "Nitro quote raw_attestation_document_b64") if isinstance(raw_b64, str) and raw_b64 else b""
    attestation_command = env.get("SERVERWARE_NITRO_ATTESTATION_COMMAND", "").strip()
    kms_command = env.get("SERVERWARE_NITRO_KMS_RELEASE_COMMAND", "").strip()
    expected_pcrs = env.get("SERVERWARE_NITRO_EXPECTED_PCRS", "").strip()
    evidence = {
        "apiVersion": "serverware.nitroKmsEvidence/v1",
        "kind": "NitroKmsEvidence",
        "ok": True,
        "generated_at_unix": int(time.time()),
        "provider": verified.get("provider"),
        "tee_platform": verified.get("tee_platform"),
        "claims": redacted_claims(claims),
        "quote": {
            "provider": quote.get("provider"),
            "tee_platform": quote.get("tee_platform"),
            "issued_at_ms": quote.get("issued_at_ms"),
            "debug": quote.get("debug"),
            "raw_attestation_document_sha256": sha256_prefixed(raw_attestation),
            "raw_attestation_document_bytes": len(raw_attestation),
        },
        "nitro": redacted_tee(tee),
        "release_materials": releases,
        "config": {
            "attestation_command_sha256": sha256_prefixed(attestation_command.encode("utf-8")),
            "kms_release_command_sha256": sha256_prefixed(kms_command.encode("utf-8")),
            "expected_pcrs_sha256": sha256_prefixed(expected_pcrs.encode("utf-8")) if expected_pcrs else None,
            "kms_command_required": env_bool(env, "SERVERWARE_NITRO_REQUIRE_KMS_COMMAND"),
            "fixtures_allowed_for_test": allow_fixtures_for_test,
        },
        "redaction": {
            "raw_attestation_document_b64": "omitted",
            "kms_public_key_pem": "sha256-only",
            "kms_signature": "sha256-only",
            "plaintext_material": "rejected",
        },
    }
    return evidence


def write_evidence(path: Path, evidence: dict[str, Any]) -> str:
    payload = (json.dumps(evidence, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode("utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    return sha256_prefixed(payload)


def main() -> None:
    parser = argparse.ArgumentParser(description="Collect redacted live Nitro attestation and KMS/HSM release evidence.")
    parser.add_argument("--claims-file", default=None)
    parser.add_argument("--material", action="append", dest="materials", help="Material to prove; defaults to broker-kek and decision-gate-ca.")
    parser.add_argument("--nonce", default=None)
    parser.add_argument("--out", default=None)
    parser.add_argument("--allow-fixtures-for-test", action="store_true")
    args = parser.parse_args()

    env = dict(os.environ)
    try:
        claims = load_claims(env, args.claims_file, args.nonce)
        evidence = collect_evidence(
            claims,
            env,
            materials=args.materials,
            allow_fixtures_for_test=args.allow_fixtures_for_test,
        )
        if args.out:
            output_path = Path(args.out)
            evidence_sha256 = write_evidence(output_path, evidence)
            print(canonical_json({"ok": True, "evidence_path": str(output_path), "evidence_sha256": evidence_sha256}))
        else:
            print(canonical_json(evidence))
    except Exception as exc:
        failure = {
            "apiVersion": "serverware.nitroKmsEvidence/v1",
            "kind": "NitroKmsEvidence",
            "ok": False,
            "error": str(exc),
            "generated_at_unix": int(time.time()),
        }
        if args.out:
            output_path = Path(args.out)
            evidence_sha256 = write_evidence(output_path, failure)
            failure["evidence_path"] = str(output_path)
            failure["evidence_sha256"] = evidence_sha256
        print(canonical_json(failure))
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
