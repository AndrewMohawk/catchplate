#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import platform
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

import build_production_images
import merge_production_images_env
import run_production_readiness


REQUIRED_READINESS_CHECKS = {
    "no-dev-fixtures",
    "control-plane-auth",
    "nitro",
    "attested-credential-delivery",
    "cosign-sigstore",
    "external-transparency",
    "apparmor",
    "shared-stores",
    "agent-egress",
    "production-images-no-shell",
}
REQUIRED_MATERIALS = {"broker-kek", "decision-gate-ca"}
REQUIRED_STORES = {"metadata", "grant", "audit"}
TEST_ONLY_BYPASS_ENV = "SERVERWARE_TEST_ONLY_ALLOW_PREFLIGHT_BYPASS"
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
IMAGE_REF_RE = re.compile(r"^(?P<repo>[^@,\s]+)@(?P<digest>sha256:[0-9a-f]{64})$")
BASE64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")
PROXY_PROOF_MAX_AGE_LIMIT_SECONDS = 900
PROXY_PROOF_FUTURE_SKEW_SECONDS = 30
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


def sha256_prefixed_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def sha256_prefixed_json(value: Any) -> str:
    return sha256_prefixed_bytes(canonical_json(value).encode("utf-8"))


def hash_to_bytes(value: str) -> bytes:
    require(SHA256_RE.fullmatch(value) is not None, "Merkle hash must be a sha256-prefixed digest")
    return bytes.fromhex(value.split(":", 1)[1])


def node_hash(left: str, right: str) -> str:
    return sha256_prefixed_bytes(b"\x01" + hash_to_bytes(left) + hash_to_bytes(right))


def transparency_leaf_payload(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "anchor_id": item.get("anchor_id"),
        "sequence": item.get("sequence"),
        "received_at": item.get("received_at"),
        "record": item.get("record"),
        "record_digest": item.get("record_digest"),
    }


def transparency_leaf_hash(item: dict[str, Any]) -> str:
    return sha256_prefixed_bytes(b"\x00" + canonical_json(transparency_leaf_payload(item)).encode("utf-8"))


def verify_merkle_inclusion(leaf: str, proof: list[Any], root: str) -> bool:
    cursor = leaf
    for step in proof:
        if not isinstance(step, dict):
            return False
        side = step.get("side")
        sibling = step.get("hash")
        if not isinstance(sibling, str) or SHA256_RE.fullmatch(sibling) is None:
            return False
        if side == "left":
            cursor = node_hash(sibling, cursor)
        elif side == "right":
            cursor = node_hash(cursor, sibling)
        else:
            return False
    return cursor == root


def b64d(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def release_public_key_id(public_key_pem: str) -> str:
    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode("ascii"))
        der = public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    except Exception as exc:
        raise ValueError("release signing public key is invalid") from exc
    return sha256_prefixed_bytes(der)


def verify_ed25519(public_key_pem: str, signature: str, payload: bytes, label: str) -> None:
    if not signature.startswith("ed25519:"):
        raise ValueError(f"{label} signature is not ed25519")
    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode("ascii"))
        public_key.verify(b64d(signature.split(":", 1)[1]), payload)
    except Exception as exc:
        raise ValueError(f"{label} signature verification failed") from exc


def verify_external_checkpoint_receipt(
    checkpoint: dict[str, Any],
    *,
    expected_fields: dict[str, Any],
    label: str,
) -> dict[str, Any]:
    require(checkpoint.get("ok") is True, f"{label} external transparency checkpoint did not pass")
    provider = checkpoint.get("provider")
    require(isinstance(provider, str) and provider, f"{label} external transparency checkpoint did not bind provider")
    log_id = require_sha256(checkpoint.get("log_id"), f"{label} external transparency log id")
    receipt = checkpoint.get("receipt") if isinstance(checkpoint.get("receipt"), dict) else {}
    require(receipt.get("kind") == "ed25519-signed-checkpoint", f"{label} external transparency receipt is not ed25519-signed")
    payload = receipt.get("payload") if isinstance(receipt.get("payload"), dict) else {}
    require(payload, f"{label} external transparency receipt is missing payload")
    public_key_pem = receipt.get("public_key_pem")
    signature = receipt.get("signature")
    require(isinstance(public_key_pem, str) and public_key_pem, f"{label} external transparency receipt is missing public key")
    require(isinstance(signature, str) and signature, f"{label} external transparency receipt is missing signature")
    require(
        release_public_key_id(public_key_pem) == log_id,
        f"{label} external transparency receipt public key does not match log id",
    )
    require(payload.get("provider") == provider, f"{label} external transparency receipt provider mismatch")
    require(payload.get("log_id") == log_id, f"{label} external transparency receipt log mismatch")
    for field, expected in expected_fields.items():
        require(payload.get(field) == expected, f"{label} external transparency receipt {field} mismatch")
    verify_ed25519(public_key_pem, signature, canonical_json(payload).encode("utf-8"), f"{label} external transparency receipt")
    return {"provider": provider, "log_id": log_id, "external_sequence": checkpoint.get("external_sequence")}


def verify_signed_tree_head(sth: dict[str, Any], *, root: str, tree_size: int, label: str) -> None:
    require(sth.get("version") == "serverware.transparencyLog/v1", f"{label} signed tree head version mismatch")
    require(sth.get("tree_head_hash") == root, f"{label} signed tree head root mismatch")
    require(sth.get("tree_size") == tree_size, f"{label} signed tree head size mismatch")
    public_key_pem = sth.get("public_key_pem")
    signature = sth.get("signature")
    require(isinstance(public_key_pem, str) and public_key_pem, f"{label} signed tree head is missing public key")
    require(isinstance(signature, str) and signature, f"{label} signed tree head is missing signature")
    require(sth.get("log_id") == release_public_key_id(public_key_pem), f"{label} signed tree head log id mismatch")
    payload = dict(sth)
    payload.pop("signature", None)
    payload.pop("public_key_pem", None)
    verify_ed25519(public_key_pem, signature, canonical_json(payload).encode("utf-8"), f"{label} signed tree head")


def reject_duplicate_json_object_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    parsed: dict[str, Any] = {}
    for key, value in pairs:
        if key in parsed:
            raise ValueError(f"duplicate JSON object key: {key}")
        parsed[key] = value
    return parsed


def load_json(path: Path, label: str) -> dict[str, Any]:
    if not path.exists():
        raise ValueError(f"{label} artifact does not exist: {path}")
    parsed = json.loads(
        path.read_text(encoding="utf-8"),
        object_pairs_hook=reject_duplicate_json_object_keys,
    )
    if not isinstance(parsed, dict):
        raise ValueError(f"{label} artifact must be a JSON object: {path}")
    return parsed


def file_digest(path: Path) -> str:
    return sha256_prefixed_bytes(path.read_bytes())


def semantic_result_digest(document: dict[str, Any]) -> str:
    payload = dict(document)
    payload.pop("result_path", None)
    payload.pop("result_sha256", None)
    return sha256_prefixed_json(payload)


def kms_ciphertext_blob(config: dict[str, Any], material: str) -> bytes:
    path = config.get("ciphertext_blob_path") or config.get("ciphertextBlobPath")
    if isinstance(path, str) and path:
        blob_path = Path(path)
        require(blob_path.is_file(), f"current KMS material {material} ciphertext blob path is not a file")
        return blob_path.read_bytes()
    raw = config.get("ciphertext_blob_b64") or config.get("ciphertextBlobB64")
    require(isinstance(raw, str) and raw, f"current KMS material {material} is missing ciphertext blob")
    try:
        return base64.b64decode(raw + "=" * (-len(raw) % 4), validate=True)
    except Exception as exc:
        raise ValueError(f"current KMS material {material} ciphertext blob is invalid base64") from exc


def current_kms_material_bindings(path: Path) -> dict[str, dict[str, str]]:
    parsed = load_json(path, "current KMS materials")
    assert_no_secret_fields(parsed)
    require(isinstance(parsed, dict), "current KMS materials file must be a JSON object")
    material_names = set(parsed)
    missing = sorted(REQUIRED_MATERIALS - material_names)
    unexpected = sorted(material_names - REQUIRED_MATERIALS)
    require(not missing, f"current KMS materials file is missing required materials: {missing}")
    require(not unexpected, f"current KMS materials file contains unauthorized materials: {unexpected}")
    bindings: dict[str, dict[str, str]] = {}
    for material in sorted(REQUIRED_MATERIALS):
        config = parsed.get(material)
        require(isinstance(config, dict), f"current KMS materials file is missing {material}")
        key_id = config.get("key_id") or config.get("keyId") or config.get("kms_key_id")
        require(isinstance(key_id, str) and key_id, f"current KMS material {material} is missing key id")
        context = config.get("encryption_context") or config.get("encryptionContext") or {}
        require(isinstance(context, dict), f"current KMS material {material} encryption context must be an object")
        bindings[material] = {
            "key_id_sha256": sha256_prefixed_bytes(key_id.encode("utf-8")),
            "ciphertext_blob_sha256": sha256_prefixed_bytes(kms_ciphertext_blob(config, material)),
            "encryption_context_sha256": sha256_prefixed_json(context),
        }
    return bindings


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def require_sha256(value: Any, label: str) -> str:
    require(isinstance(value, str) and SHA256_RE.fullmatch(value), f"{label} must be a sha256-prefixed digest")
    return str(value)


def require_image_ref(value: Any, label: str) -> tuple[str, str]:
    require(isinstance(value, str), f"{label} must be a digest-pinned image ref")
    match = IMAGE_REF_RE.fullmatch(str(value))
    require(match is not None, f"{label} must be repo@sha256:<64 hex>")
    return str(value), match.group("digest")


def sigstore_tlog_entries(bundle: dict[str, Any]) -> list[dict[str, Any]]:
    verification = bundle.get("verificationMaterial") or bundle.get("verification_material") or {}
    candidates = [
        verification.get("tlogEntries") if isinstance(verification, dict) else None,
        verification.get("transparencyLogEntries") if isinstance(verification, dict) else None,
        verification.get("transparencyLog") if isinstance(verification, dict) else None,
        bundle.get("tlogEntries"),
    ]
    for candidate in candidates:
        if isinstance(candidate, list):
            return [item for item in candidate if isinstance(item, dict)]
        if isinstance(candidate, dict):
            return [candidate]
    return []


def sigstore_log_id(entry: dict[str, Any]) -> Any:
    value = entry.get("log_id") or entry.get("logID") or entry.get("logId")
    if isinstance(value, dict):
        return value.get("keyId") or value.get("key_id")
    return value


def verify_sigstore_bundle_binding(
    sigstore: dict[str, Any],
    *,
    expected_statement_digest: str,
    expected_signature: str,
    expected_rekor_log_id: str,
    label: str,
) -> None:
    bundle = sigstore.get("bundle") if isinstance(sigstore.get("bundle"), dict) else {}
    require(bundle, f"{label} Sigstore proof is missing bundle")
    message_signature = bundle.get("messageSignature") if isinstance(bundle.get("messageSignature"), dict) else {}
    if not message_signature:
        message_signature = bundle.get("message_signature") if isinstance(bundle.get("message_signature"), dict) else {}
    require(message_signature, f"{label} Sigstore bundle is missing message signature")
    message_digest = message_signature.get("messageDigest") if isinstance(message_signature.get("messageDigest"), dict) else {}
    if not message_digest:
        message_digest = message_signature.get("message_digest") if isinstance(message_signature.get("message_digest"), dict) else {}
    require(str(message_digest.get("algorithm", "")).lower() == "sha256", f"{label} Sigstore bundle digest algorithm mismatch")
    require(
        message_digest.get("digest") == expected_statement_digest.split(":", 1)[1],
        f"{label} Sigstore bundle digest mismatch",
    )
    require(message_signature.get("signature") == expected_signature, f"{label} Sigstore bundle signature mismatch")

    transparency = sigstore.get("transparency") if isinstance(sigstore.get("transparency"), dict) else {}
    entries = sigstore_tlog_entries(bundle)
    require(entries, f"{label} Sigstore bundle is missing transparency log entry")
    entry = entries[0]
    require(sigstore_log_id(entry) == expected_rekor_log_id, f"{label} Sigstore bundle Rekor log mismatch")
    require(sigstore_log_id(entry) == transparency.get("log_id"), f"{label} Sigstore bundle/top-level log mismatch")
    for top_key, entry_keys in (
        ("entry_uuid", ("entry_uuid", "entryUUID", "uuid")),
        ("integrated_time", ("integrated_time", "integratedTime")),
        ("log_index", ("log_index", "logIndex")),
    ):
        top_value = transparency.get(top_key)
        entry_value = next((entry.get(key) for key in entry_keys if entry.get(key) is not None), None)
        require(entry_value == top_value, f"{label} Sigstore bundle/top-level {top_key} mismatch")
    entry_inclusion = entry.get("inclusion_proof") or entry.get("inclusionProof")
    require(entry_inclusion == transparency.get("inclusion_proof"), f"{label} Sigstore bundle/top-level inclusion proof mismatch")


def assert_no_secret_fields(value: Any, path: str = "$") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if str(key).lower() in SECRET_FIELD_NAMES:
                raise ValueError(f"completion artifact contains secret-like field {path}.{key}")
            assert_no_secret_fields(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            assert_no_secret_fields(child, f"{path}[{index}]")


def release_materials(
    evidence: dict[str, Any],
    label: str,
    *,
    nitro_attestation_sha256: str,
) -> dict[str, dict[str, str]]:
    seen: dict[str, dict[str, str]] = {}
    for item in evidence.get("release_materials") or []:
        if not isinstance(item, dict):
            continue
        material = item.get("material")
        require(isinstance(material, str) and material, f"{label} release material entry is missing material")
        require(material not in seen, f"{label} has duplicate release material: {material}")
        kms_request_digest = require_sha256(
            item.get("kms_request_digest"),
            f"{label} material {material} KMS request digest",
        )
        kms = item.get("kms_release") if isinstance(item.get("kms_release"), dict) else {}
        require(kms.get("ok") is True, f"{label} material {material} does not include an ok KMS release")
        require(
            kms.get("request_digest") == kms_request_digest,
            f"{label} material {material} KMS request digest mismatch",
        )
        recipient_ciphertext_sha256 = require_sha256(
            kms.get("recipient_ciphertext_sha256"),
            f"{label} material {material} recipient ciphertext digest",
        )
        require(
            kms.get("material_handle") == recipient_ciphertext_sha256,
            f"{label} material {material} material handle does not match recipient ciphertext digest",
        )
        attestation_document_sha256 = require_sha256(
            kms.get("attestation_document_sha256"),
            f"{label} material {material} KMS Recipient attestation digest",
        )
        require(
            attestation_document_sha256 == nitro_attestation_sha256,
            f"{label} material {material} KMS release attestation digest does not match Nitro evidence",
        )
        key_provider = kms.get("key_provider") if isinstance(kms.get("key_provider"), dict) else {}
        key_id = key_provider.get("key_id")
        require(isinstance(key_id, str) and key_id, f"{label} material {material} does not bind a KMS/HSM key id")
        audit = kms.get("audit") if isinstance(kms.get("audit"), dict) else {}
        ciphertext_blob_sha256 = kms.get("ciphertext_blob_sha256") or audit.get("ciphertext_blob_sha256")
        encryption_context_sha256 = kms.get("encryption_context_sha256") or audit.get("encryption_context_sha256")
        seen[material] = {
            "material": material,
            "key_id_sha256": sha256_prefixed_bytes(key_id.encode("utf-8")),
            "kms_request_digest": kms_request_digest,
            "recipient_ciphertext_sha256": recipient_ciphertext_sha256,
            "attestation_document_sha256": attestation_document_sha256,
            "ciphertext_blob_sha256": require_sha256(
                ciphertext_blob_sha256,
                f"{label} material {material} input ciphertext digest",
            ),
            "encryption_context_sha256": require_sha256(
                encryption_context_sha256,
                f"{label} material {material} encryption context digest",
            ),
        }
    return seen


def verify_nitro_evidence(evidence: dict[str, Any], label: str) -> dict[str, Any]:
    assert_no_secret_fields(evidence)
    require(evidence.get("apiVersion") == "serverware.nitroKmsEvidence/v1", f"{label} has wrong apiVersion")
    require(evidence.get("ok") is True, f"{label} is not ok")
    require(evidence.get("provider") == "aws-nitro-enclaves", f"{label} does not prove AWS Nitro")
    require(evidence.get("tee_platform") == "aws-nitro", f"{label} does not prove aws-nitro platform")
    nitro = evidence.get("nitro") if isinstance(evidence.get("nitro"), dict) else {}
    require(nitro.get("verified") is True, f"{label} Nitro metadata is not verified")
    require(nitro.get("debug") is False, f"{label} Nitro metadata is debug")
    raw_attestation_document_sha256 = require_sha256(
        nitro.get("raw_attestation_document_sha256"),
        f"{label} raw attestation digest",
    )
    materials = release_materials(
        evidence,
        label,
        nitro_attestation_sha256=raw_attestation_document_sha256,
    )
    require(REQUIRED_MATERIALS.issubset(materials), f"{label} does not prove all required materials")
    redaction = evidence.get("redaction") if isinstance(evidence.get("redaction"), dict) else {}
    require(redaction.get("plaintext_material") == "rejected", f"{label} does not document plaintext material rejection")
    config = evidence.get("config") if isinstance(evidence.get("config"), dict) else {}
    require(config.get("kms_command_required") is True, f"{label} did not require the KMS/HSM release command")
    require(config.get("fixtures_allowed_for_test") is not True, f"{label} was collected with fixtures allowed")
    command_hashes = {
        "attestation_command_sha256": require_sha256(
            config.get("attestation_command_sha256"),
            f"{label} attestation command digest",
        ),
        "kms_release_command_sha256": require_sha256(
            config.get("kms_release_command_sha256"),
            f"{label} KMS release command digest",
        ),
    }
    claims = evidence.get("claims") if isinstance(evidence.get("claims"), dict) else {}
    claim_fields = claims.get("fields") if isinstance(claims.get("fields"), dict) else {}
    attested_runtime = {
        "policy_digest": require_sha256(
            claim_fields.get("policy_bundle_digest"),
            f"{label} attested policy bundle digest",
        ),
        "policy_sequence": claim_fields.get("policy_sequence"),
        "policy_high_water_digest": require_sha256(
            claim_fields.get("policy_high_water_digest"),
            f"{label} attested policy high-water digest",
        ),
        "runtime_manifest_digest": require_sha256(
            claim_fields.get("runtime_manifest_digest"),
            f"{label} attested runtime manifest digest",
        ),
        "data_plane_binary_digest": require_sha256(
            claim_fields.get("data_plane_binary_digest"),
            f"{label} attested data-plane binary digest",
        ),
        "provenance_digest": require_sha256(
            claim_fields.get("provenance_digest"),
            f"{label} attested release provenance digest",
        ),
        "source_tree_digest": require_sha256(
            claim_fields.get("source_tree_digest"),
            f"{label} attested source tree digest",
        ),
        "response_signing_key_id": require_sha256(
            claim_fields.get("response_signing_key_id"),
            f"{label} attested response signing key id",
        ),
    }
    require(claim_fields.get("debug") is False, f"{label} attested runtime claims are debug")
    require(
        isinstance(attested_runtime["policy_sequence"], int)
        and not isinstance(attested_runtime["policy_sequence"], bool)
        and attested_runtime["policy_sequence"] > 0,
        f"{label} attested policy sequence is invalid",
    )
    require(
        isinstance(claim_fields.get("release_channel"), str) and bool(claim_fields.get("release_channel")),
        f"{label} attested runtime claims omit release channel",
    )
    return {
        "provider": evidence.get("provider"),
        "tee_platform": evidence.get("tee_platform"),
        "materials": sorted(REQUIRED_MATERIALS),
        "material_key_ids": {material: materials[material]["key_id_sha256"] for material in sorted(REQUIRED_MATERIALS)},
        "material_bindings": {
            material: {
                "key_id_sha256": materials[material]["key_id_sha256"],
                "ciphertext_blob_sha256": materials[material]["ciphertext_blob_sha256"],
                "encryption_context_sha256": materials[material]["encryption_context_sha256"],
            }
            for material in sorted(REQUIRED_MATERIALS)
        },
        "material_release_receipts": {
            material: {
                "kms_request_digest": materials[material]["kms_request_digest"],
                "recipient_ciphertext_sha256": materials[material]["recipient_ciphertext_sha256"],
                "attestation_document_sha256": materials[material]["attestation_document_sha256"],
            }
            for material in sorted(REQUIRED_MATERIALS)
        },
        "command_hashes": command_hashes,
        "raw_attestation_document_sha256": raw_attestation_document_sha256,
        "attested_runtime": attested_runtime,
    }


def verify_readiness(readiness: dict[str, Any]) -> dict[str, Any]:
    assert_no_secret_fields(readiness)
    require(readiness.get("ok") is True, "production readiness is not ok")
    require(readiness.get("production_readiness") == "pass", "production readiness did not pass")
    require(readiness.get("mode") == "live", "production readiness must be a live-mode result")
    checks = set(readiness.get("checks") or [])
    require(REQUIRED_READINESS_CHECKS.issubset(checks), "production readiness omitted required checks")
    environment = verify_readiness_environment(readiness.get("environment"), "production readiness")
    live = readiness.get("live")
    require(isinstance(live, dict), "production readiness is missing live probe results")

    sigstore = live.get("sigstore") if isinstance(live.get("sigstore"), dict) else {}
    require(sigstore.get("ok") is True, "live Sigstore probe did not pass")
    require_sha256(sigstore.get("key_id"), "live Sigstore key id")
    require_sha256(sigstore.get("transparency_log_id"), "live Sigstore/Rekor log id")

    transparency = live.get("external_transparency") if isinstance(live.get("external_transparency"), dict) else {}
    require(transparency.get("ok") is True, "live external transparency probe did not pass")
    require(bool(transparency.get("provider")), "live external transparency probe did not bind provider")
    require_sha256(transparency.get("log_id"), "live external transparency log id")

    stores = live.get("shared_stores") if isinstance(live.get("shared_stores"), dict) else {}
    require(stores.get("ok") is True, "live shared-store probe did not pass")
    store_results = stores.get("stores") if isinstance(stores.get("stores"), dict) else {}
    require(REQUIRED_STORES.issubset(set(store_results)), "live shared-store probe omitted required stores")
    for label in REQUIRED_STORES:
        result = store_results.get(label) if isinstance(store_results.get(label), dict) else {}
        require(result.get("ok") is True, f"live {label} store probe did not pass")
        require(bool(result.get("tables")), f"live {label} store probe did not list required tables")

    nitro_summary = verify_nitro_evidence(live.get("nitro") if isinstance(live.get("nitro"), dict) else {}, "readiness Nitro evidence")

    images = live.get("production_images_no_shell") if isinstance(live.get("production_images_no_shell"), dict) else {}
    require(images.get("ok") is True, "production image no-shell probe did not pass")
    require(bool(images.get("images")), "production image no-shell probe did not list images")
    production_image_digests: list[str] = []
    for image in images.get("images") or []:
        require(isinstance(image, str) and "@sha256:" in image, f"production image was not digest-pinned: {image}")
        production_image_digests.append("sha256:" + image.rsplit("@sha256:", 1)[1])

    apparmor = live.get("apparmor") if isinstance(live.get("apparmor"), dict) else {}
    require(apparmor.get("ok") is True, "AppArmor live probe did not pass")

    return {
        "checks": sorted(checks),
        "environment": environment,
        "sigstore_key_id": sigstore.get("key_id"),
        "rekor_log_id": sigstore.get("transparency_log_id"),
        "external_transparency_provider": transparency.get("provider"),
        "external_transparency_log_id": transparency.get("log_id"),
        "nitro": nitro_summary,
        "production_images": images.get("images"),
        "production_image_digests": sorted(production_image_digests),
    }


def verify_readiness_environment(value: Any, label: str) -> dict[str, Any]:
    require(isinstance(value, dict), f"{label} is missing redacted environment evidence")
    require(value.get("secret_values_redacted") is True, f"{label} environment evidence is not redacted")
    env_keys = value.get("env_keys")
    require(isinstance(env_keys, list), f"{label} environment keys must be a list")
    require("SERVERWARE_PRODUCTION_IMAGES" in env_keys, f"{label} environment did not include production images")
    production_readiness_env_sha256 = require_sha256(
        value.get("production_readiness_env_sha256"),
        f"{label} production readiness env digest",
    )
    production_images_env_sha256 = require_sha256(
        value.get("production_images_env_sha256"),
        f"{label} production images env digest",
    )
    return {
        "env_keys": sorted(str(key) for key in env_keys),
        "production_readiness_env_sha256": production_readiness_env_sha256,
        "production_images_env_sha256": production_images_env_sha256,
        "secret_values_redacted": True,
    }


def verify_production_config_result(config: dict[str, Any], preflight_summary: dict[str, Any]) -> dict[str, Any]:
    assert_no_secret_fields(config)
    require(config.get("ok") is True, "production config gate artifact is not ok")
    require(config.get("production_readiness") == "pass", "production config gate artifact did not pass")
    require(config.get("mode") == "config", "production config gate artifact must be config mode")
    checks = set(config.get("checks") or [])
    require(REQUIRED_READINESS_CHECKS.issubset(checks), "production config gate artifact omitted required checks")
    require(config.get("live") is None, "production config gate artifact must not contain live probe results")
    environment = verify_readiness_environment(config.get("environment"), "production config gate")
    require(
        environment["production_readiness_env_sha256"] == preflight_summary["production_readiness_env_sha256"],
        "production config gate env digest does not match production host preflight",
    )
    require(
        environment["production_images_env_sha256"] == preflight_summary["production_images_env_sha256"],
        "production config gate image env digest does not match production host preflight",
    )
    semantic_sha256 = semantic_result_digest(config)
    require(
        semantic_sha256 == preflight_summary["production_config_semantic_sha256"],
        "production config gate artifact does not match production host preflight config gate",
    )
    return {
        "mode": "config",
        "checks": sorted(checks),
        "environment": environment,
        "semantic_sha256": semantic_sha256,
        "preflight_config_bound": True,
    }


def external_checkpoint_binding(
    transparency: dict[str, Any],
    *,
    anchor_key: str,
    expected_provider: str,
    expected_log_id: str,
    label: str,
) -> dict[str, Any]:
    anchor_response = transparency.get(anchor_key) if isinstance(transparency.get(anchor_key), dict) else {}
    anchors = anchor_response.get("anchors") if isinstance(anchor_response.get("anchors"), list) else []
    checkpoints = [
        item.get("external_checkpoint")
        for item in anchors
        if isinstance(item, dict) and isinstance(item.get("external_checkpoint"), dict)
    ]
    require(checkpoints, f"{label} transparency anchor is missing external checkpoint evidence")
    checkpoint = checkpoints[0]
    require(checkpoint.get("ok") is True, f"{label} external transparency checkpoint did not pass")
    provider = checkpoint.get("provider")
    log_id = require_sha256(checkpoint.get("log_id"), f"{label} external transparency log id")
    require(provider == expected_provider, f"{label} external transparency provider does not match live readiness")
    require(log_id == expected_log_id, f"{label} external transparency log does not match live readiness")
    return verify_external_checkpoint_receipt(
        checkpoint,
        expected_fields={"provider": provider, "log_id": log_id},
        label=label,
    )


def transparency_record_binding(
    transparency: dict[str, Any],
    *,
    anchor_key: str,
    inclusion_key: str,
    expected_type: str,
    expected_fields: dict[str, Any],
    label: str,
) -> dict[str, Any]:
    record = transparency.get("record") if isinstance(transparency.get("record"), dict) else {}
    require(record, f"{label} transparency record is missing")
    require(record.get("type") == expected_type, f"{label} transparency record type mismatch")
    for key, expected in expected_fields.items():
        require(record.get(key) == expected, f"{label} transparency record {key} mismatch")
    record_digest = sha256_prefixed_json(record)

    inclusion = transparency.get(inclusion_key) if isinstance(transparency.get(inclusion_key), dict) else {}
    require(inclusion.get("verified") is True, f"{label} transparency inclusion proof was not verified")
    require(inclusion.get("record_digest") == record_digest, f"{label} transparency inclusion record digest mismatch")
    item = inclusion.get("item") if isinstance(inclusion.get("item"), dict) else {}
    require(item.get("record") == record, f"{label} transparency inclusion returned the wrong record")
    require(item.get("record_digest") == record_digest, f"{label} transparency inclusion item digest mismatch")
    expected_leaf_hash = transparency_leaf_hash(item)
    require(item.get("leaf_hash") == expected_leaf_hash, f"{label} transparency inclusion leaf payload mismatch")
    require(inclusion.get("leaf_hash") == expected_leaf_hash, f"{label} transparency inclusion leaf hash mismatch")
    tree_size = inclusion.get("tree_size")
    require(isinstance(tree_size, int) and tree_size >= 1, f"{label} transparency tree size is invalid")
    tree_head_hash = require_sha256(inclusion.get("tree_head_hash"), f"{label} transparency tree head")
    proof = inclusion.get("proof")
    require(isinstance(proof, list), f"{label} transparency inclusion proof must be a list")
    require(verify_merkle_inclusion(expected_leaf_hash, proof, tree_head_hash), f"{label} transparency Merkle inclusion proof did not verify")
    signed_tree_head = inclusion.get("signed_tree_head") if isinstance(inclusion.get("signed_tree_head"), dict) else {}
    verify_signed_tree_head(signed_tree_head, root=tree_head_hash, tree_size=tree_size, label=label)

    anchor_response = transparency.get(anchor_key) if isinstance(transparency.get(anchor_key), dict) else {}
    anchors = anchor_response.get("anchors") if isinstance(anchor_response.get("anchors"), list) else []
    matching_anchor = next(
        (item for item in anchors if isinstance(item, dict) and item.get("record_digest") == record_digest),
        None,
    )
    require(matching_anchor is not None, f"{label} transparency anchor response did not bind record digest")
    require(matching_anchor.get("leaf_hash") == expected_leaf_hash, f"{label} transparency anchor leaf hash mismatch")
    require(matching_anchor.get("tree_head_hash") == tree_head_hash, f"{label} transparency anchor tree head mismatch")
    require(matching_anchor.get("tree_size") == tree_size, f"{label} transparency anchor tree size mismatch")
    anchor_sth = matching_anchor.get("signed_tree_head") if isinstance(matching_anchor.get("signed_tree_head"), dict) else {}
    require(anchor_sth == signed_tree_head, f"{label} transparency anchor signed tree head mismatch")
    checkpoint = matching_anchor.get("external_checkpoint") if isinstance(matching_anchor.get("external_checkpoint"), dict) else {}
    verify_external_checkpoint_receipt(
        checkpoint,
        expected_fields={
            "record_digest": record_digest,
            "leaf_hash": expected_leaf_hash,
            "tree_head_hash": tree_head_hash,
            "tree_size": tree_size,
        },
        label=label,
    )
    return {"record_digest": record_digest, "leaf_hash": expected_leaf_hash, "tree_head_hash": tree_head_hash}


def verify_release_provenance(
    summary: dict[str, Any],
    document: dict[str, Any],
    expected_external_provider: str,
    expected_external_log_id: str,
) -> dict[str, Any]:
    require(summary.get("ok") is True and summary.get("release_provenance") == "pass", "release provenance summary did not pass")
    require(summary.get("anchored") is True, "release provenance was not anchored")
    require(summary.get("inclusion_verified") is True, "release provenance inclusion proof was not verified")
    provenance = document.get("provenance")
    require(isinstance(provenance, dict), "release provenance document is missing provenance")
    require(
        provenance.get("source") == "serverware-digest-pinned-production-release",
        "release provenance was not generated in digest-pinned production mode",
    )
    digest = require_sha256(document.get("provenance_digest"), "release provenance digest")
    require(summary.get("provenance_digest") == digest, "release provenance summary digest mismatch")
    require(sha256_prefixed_json(provenance) == digest, "release provenance payload digest mismatch")
    signature = document.get("signature")
    public_key_pem = document.get("release_signing_public_key_pem")
    require(isinstance(signature, str) and signature, "release provenance document is missing signature")
    require(isinstance(public_key_pem, str) and public_key_pem, "release provenance document is missing signing public key")
    release_signing_key_id = require_sha256(document.get("release_signing_key_id"), "release signing key id")
    require(summary.get("release_signing_key_id") == release_signing_key_id, "release provenance summary signing key mismatch")
    require(
        release_public_key_id(public_key_pem) == release_signing_key_id,
        "release provenance signing key id does not match public key",
    )
    verify_ed25519(public_key_pem, signature, canonical_json(provenance).encode("utf-8"), "release provenance")
    transparency = document.get("transparency") if isinstance(document.get("transparency"), dict) else {}
    inclusion_proof = transparency.get("inclusion_proof") if isinstance(transparency.get("inclusion_proof"), dict) else {}
    anchor_response = transparency.get("anchor_response") if isinstance(transparency.get("anchor_response"), dict) else {}
    require(
        transparency.get("inclusion_verified") is True or bool(inclusion_proof) or anchor_response.get("accepted"),
        "release provenance document is missing verified transparency inclusion evidence",
    )
    release_record = transparency_record_binding(
        transparency,
        anchor_key="anchor_response",
        inclusion_key="inclusion_proof",
        expected_type="release.provenance.v1",
        expected_fields={
            "provenance_digest": digest,
            "signature": signature,
            "release_signing_key_id": release_signing_key_id,
        },
        label="release provenance",
    )
    external_transparency = external_checkpoint_binding(
        transparency,
        anchor_key="anchor_response",
        expected_provider=expected_external_provider,
        expected_log_id=expected_external_log_id,
        label="release provenance",
    )
    source_tree = provenance.get("source_tree") if isinstance(provenance.get("source_tree"), dict) else {}
    compose_config_sha256 = require_sha256(
        provenance.get("compose_config_sha256"),
        "release provenance compose config digest",
    )
    compose = provenance.get("compose") if isinstance(provenance.get("compose"), dict) else {}
    require(
        compose.get("sha256") == compose_config_sha256,
        "release provenance Compose summary digest does not match its rendered config digest",
    )
    require(
        Path(str(compose.get("file") or "")).name == "docker-compose.production.yml",
        "release provenance did not bind docker-compose.production.yml",
    )
    sbom = provenance.get("sbom") if isinstance(provenance.get("sbom"), dict) else {}
    cyclonedx = sbom.get("cyclonedx") if isinstance(sbom.get("cyclonedx"), dict) else {}
    sbom_components = cyclonedx.get("components")
    require(isinstance(sbom_components, int) and sbom_components > 0, "release provenance CycloneDX SBOM component count is invalid")
    return {
        "provenance_digest": digest,
        "release_signing_key_id": release_signing_key_id,
        "transparency_mode": summary.get("transparency_mode"),
        "external_transparency": external_transparency,
        "transparency_record_digest": release_record["record_digest"],
        "source_tree_digest": require_sha256(source_tree.get("digest"), "release provenance source tree digest"),
        "compose_config_sha256": compose_config_sha256,
        "sbom_cyclonedx_sha256": require_sha256(cyclonedx.get("sha256"), "release provenance CycloneDX SBOM digest"),
        "sbom_cyclonedx_components": sbom_components,
    }


def verify_production_image_build(build: dict[str, Any], source_tree_digest: str) -> dict[str, Any]:
    assert_no_secret_fields(build)
    require(build.get("ok") is True, "production image build artifact is not ok")
    no_shell = build.get("no_shell") if isinstance(build.get("no_shell"), dict) else {}
    require(no_shell.get("ok") is True, "production image build artifact did not pass no-shell verification")
    metadata = build.get("metadata") if isinstance(build.get("metadata"), dict) else {}
    build_source_tree_digest = require_sha256(metadata.get("source_tree_digest"), "production image build source tree digest")
    require(
        build_source_tree_digest == source_tree_digest,
        "production image build source tree digest does not match release provenance",
    )
    images = build.get("images")
    require(isinstance(images, list) and images, "production image build artifact has no images")
    normalized = []
    seen_services: set[str] = set()
    for image in images:
        require(isinstance(image, dict), "production image build entry must be an object")
        service = image.get("service")
        require(isinstance(service, str) and service, "production image build entry is missing service")
        require(service not in seen_services, f"duplicate production image build service: {service}")
        seen_services.add(service)
        binary_digest = None
        if service == "serverware-decision-gate":
            binary_digest = require_sha256(
                image.get("binary_digest"),
                "serverware-decision-gate production image binary digest",
            )
        normalized.append(
            {
                "service": service,
                "image_id": require_sha256(image.get("image_id"), f"{service} image_id"),
                "dockerfile": image.get("dockerfile"),
                "tag": image.get("tag"),
                **({"binary_digest": binary_digest} if binary_digest else {}),
            }
        )
    require(
        "serverware-decision-gate" in seen_services,
        "production image build artifact is missing the decision gate",
    )
    return {
        "source_tree_digest": build_source_tree_digest,
        "images": normalized,
        "no_shell": "pass",
    }


def verify_published_images(
    published: dict[str, Any],
    build_summary: dict[str, Any],
    readiness_image_refs: list[str],
) -> dict[str, Any]:
    assert_no_secret_fields(published)
    require(published.get("ok") is True, "production images published artifact is not ok")
    build_by_service = {item["service"]: item for item in build_summary["images"]}
    remote_no_shell = published.get("remote_no_shell")
    require(
        isinstance(remote_no_shell, dict) and remote_no_shell.get("ok") is True,
        "published production images did not pass remote no-shell verification",
    )
    expected_refs = sorted(readiness_image_refs)
    images = published.get("images")
    require(isinstance(images, list) and images, "production images published artifact has no images")
    published_refs: list[str] = []
    published_digests: list[str] = []
    published_services: list[str] = []
    for image in images:
        require(isinstance(image, dict), "published image entry must be an object")
        service = image.get("service")
        require(isinstance(service, str) and service, "published image entry is missing service")
        local_image_id = require_sha256(image.get("local_image_id"), f"{service} published local image id")
        require(service in build_by_service, f"published image service is not in current build artifact: {service}")
        require(
            local_image_id == build_by_service[service]["image_id"],
            "published production images do not match current no-shell build",
        )
        require_sha256(image.get("remote_image_id"), f"{service} published remote image id")
        if service == "serverware-decision-gate":
            require(
                require_sha256(image.get("binary_digest"), "published decision-gate binary digest")
                == build_by_service[service]["binary_digest"],
                "published decision-gate executable does not match the measured build executable",
            )
        repo_digest, digest = require_image_ref(image.get("repo_digest"), f"{service} published repo digest")
        published_refs.append(repo_digest)
        published_digests.append(digest)
        published_services.append(service)
    require(
        sorted(published_services) == sorted(build_by_service),
        "published production image services do not match current build artifact",
    )
    require(sorted(published_refs) == expected_refs, "published production image refs do not match live readiness images")
    env_value = published.get("env") if isinstance(published.get("env"), dict) else {}
    if env_value.get("SERVERWARE_PRODUCTION_IMAGES"):
        require(
            sorted(item.strip() for item in str(env_value["SERVERWARE_PRODUCTION_IMAGES"]).split(",") if item.strip())
            == expected_refs,
            "published artifact env value does not match live readiness images",
        )
    return {
        "services": sorted(published_services),
        "repo_digests": sorted(published_refs),
        "image_digests": sorted(published_digests),
        "source_build_file": published.get("source_build_file"),
    }


def normalized_image_signature_payload(document: dict[str, Any]) -> dict[str, Any]:
    copied = json.loads(json.dumps(document))
    copied.pop("image_signature_bundle_digest", None)
    copied.pop("bundle_signature", None)
    metadata = copied.get("metadata")
    if isinstance(metadata, dict):
        metadata.pop("signature", None)
        metadata.pop("transparency", None)
        metadata.pop("bundleSigstore", None)
    return copied


def verify_image_signatures(
    summary: dict[str, Any],
    document: dict[str, Any],
    provenance: dict[str, Any],
    expected_image_digests: list[str],
    expected_image_refs: list[str],
    expected_sigstore_key_id: str,
    expected_rekor_log_id: str,
    expected_external_provider: str,
    expected_external_log_id: str,
) -> dict[str, Any]:
    provenance_digest = str(provenance["provenance_digest"])
    require(summary.get("ok") is True and summary.get("image_signatures") == "pass", "image signatures summary did not pass")
    require(summary.get("image_signature_provider") == "sigstore-command", "image signatures did not use sigstore-command")
    require(summary.get("inclusion_verified") is True, "image signature bundle inclusion proof was not verified")
    require(summary.get("provenance_digest") == provenance_digest, "image signatures summary provenance digest mismatch")
    release_signing_key_id = require_sha256(provenance.get("release_signing_key_id"), "release signing key id")
    require(summary.get("release_signing_key_id") == release_signing_key_id, "image signatures summary release signing key mismatch")
    image_signing_key_id = require_sha256(summary.get("image_signing_key_id"), "image signing key id")
    require(image_signing_key_id == expected_sigstore_key_id, "image signing key does not match live Sigstore key")
    digest = require_sha256(document.get("image_signature_bundle_digest"), "image signature bundle digest")
    require(summary.get("image_signature_bundle_digest") == digest, "image signature summary digest mismatch")
    normalized_payload = normalized_image_signature_payload(document)
    require(sha256_prefixed_json(normalized_payload) == digest, "image signature bundle payload digest mismatch")
    require(document.get("apiVersion") == "serverware.imageSignatures/v1", "image signature bundle has wrong apiVersion")
    images = document.get("images")
    require(isinstance(images, list) and images, "image signature bundle has no images")
    require(summary.get("images") == len(images), "image signature summary image count mismatch")
    signed_image_digests: list[str] = []
    signed_image_map: dict[str, str] = {}
    signed_repo_digests: list[str] = []
    transparency_log_ids: list[str] = []
    metadata = document.get("metadata") if isinstance(document.get("metadata"), dict) else {}
    require(metadata.get("provenanceDigest") == provenance_digest, "image signature metadata provenance digest mismatch")
    require(metadata.get("releaseSigningKeyId") == release_signing_key_id, "image signature metadata release signing key mismatch")
    require(metadata.get("sourceTreeDigest") == provenance["source_tree_digest"], "image signature metadata source tree digest mismatch")
    require(metadata.get("composeConfigSha256") == provenance["compose_config_sha256"], "image signature metadata compose config digest mismatch")
    require(metadata.get("sbomCyclonedxSha256") == provenance["sbom_cyclonedx_sha256"], "image signature metadata SBOM digest mismatch")
    require(metadata.get("sigstoreTransparencyRequired") is True, "image signature metadata does not require transparency")
    bundle_sigstore = document.get("bundle_signature") if isinstance(document.get("bundle_signature"), dict) else {}
    metadata_bundle_sigstore = metadata.get("bundleSigstore") if isinstance(metadata.get("bundleSigstore"), dict) else {}
    require(bundle_sigstore, "image signature bundle is missing Sigstore signature")
    require(metadata_bundle_sigstore == bundle_sigstore, "image signature metadata bundle Sigstore proof mismatch")
    require(bundle_sigstore.get("ok") is True, "image signature bundle Sigstore proof did not pass")
    require(bool(bundle_sigstore.get("signature")), "image signature bundle Sigstore proof is missing signature")
    require(metadata.get("signature") == bundle_sigstore.get("signature"), "image signature metadata signature mismatch")
    require(bundle_sigstore.get("statement_digest") == digest, "image signature bundle Sigstore statement digest mismatch")
    bundle_key_provider = bundle_sigstore.get("key_provider") if isinstance(bundle_sigstore.get("key_provider"), dict) else {}
    require(bundle_key_provider.get("key_id") == image_signing_key_id, "image signature bundle Sigstore signing key mismatch")
    bundle_sigstore_transparency = bundle_sigstore.get("transparency") if isinstance(bundle_sigstore.get("transparency"), dict) else {}
    bundle_rekor_log_id = require_sha256(bundle_sigstore_transparency.get("log_id"), "image signature bundle transparency log id")
    require(bundle_rekor_log_id == expected_rekor_log_id, "image signature bundle transparency log does not match live Rekor log")
    require(bool(bundle_sigstore_transparency.get("inclusion_proof")), "image signature bundle has no transparency inclusion proof")
    verify_sigstore_bundle_binding(
        bundle_sigstore,
        expected_statement_digest=digest,
        expected_signature=str(bundle_sigstore.get("signature")),
        expected_rekor_log_id=expected_rekor_log_id,
        label="image signature bundle",
    )
    transparency_log_ids.append(bundle_rekor_log_id)
    metadata_transparency = metadata.get("transparency") if isinstance(metadata.get("transparency"), dict) else {}
    external_transparency = external_checkpoint_binding(
        metadata_transparency,
        anchor_key="anchorResponse",
        expected_provider=expected_external_provider,
        expected_log_id=expected_external_log_id,
        label="image signature bundle",
    )
    for image in images:
        require(isinstance(image, dict), "image signature entry must be an object")
        service = image.get("service")
        require(isinstance(service, str) and service, "image signature entry is missing service")
        image_id = require_sha256(image.get("image_id"), f"image {image.get('service')} digest")
        signed_image_digests.append(image_id)
        signed_image_map[service] = image_id
        sigstore = image.get("sigstore") if isinstance(image.get("sigstore"), dict) else {}
        require(sigstore.get("ok") is True, f"image {image.get('service')} Sigstore proof did not pass")
        require(bool(sigstore.get("signature")), f"image {image.get('service')} Sigstore proof is missing signature")
        require(image.get("signature") == sigstore.get("signature"), f"image {image.get('service')} Sigstore signature mismatch")
        transparency = sigstore.get("transparency") if isinstance(sigstore.get("transparency"), dict) else {}
        log_id = require_sha256(transparency.get("log_id"), f"image {image.get('service')} transparency log id")
        require(log_id == expected_rekor_log_id, f"image {image.get('service')} transparency log does not match live Rekor log")
        transparency_log_ids.append(log_id)
        require(bool(transparency.get("inclusion_proof")), f"image {image.get('service')} has no transparency inclusion proof")
        statement = image.get("statement") if isinstance(image.get("statement"), dict) else {}
        statement_digest = sha256_prefixed_json(statement)
        require(image.get("statement_digest") == statement_digest, f"image {image.get('service')} statement digest mismatch")
        require(sigstore.get("statement_digest") == statement_digest, f"image {image.get('service')} Sigstore statement digest mismatch")
        verify_sigstore_bundle_binding(
            sigstore,
            expected_statement_digest=statement_digest,
            expected_signature=str(sigstore.get("signature")),
            expected_rekor_log_id=expected_rekor_log_id,
            label=f"image {image.get('service')}",
        )
        key_provider = sigstore.get("key_provider") if isinstance(sigstore.get("key_provider"), dict) else {}
        require(key_provider.get("key_id") == image_signing_key_id, f"image {image.get('service')} Sigstore signing key mismatch")
        subject = statement.get("subject") if isinstance(statement.get("subject"), list) else []
        require(any((item.get("digest") or {}).get("sha256") == image_id.split(":", 1)[1] for item in subject if isinstance(item, dict)), f"image {image.get('service')} statement subject digest mismatch")
        predicate = statement.get("predicate") if isinstance(statement.get("predicate"), dict) else {}
        require(predicate.get("provenance_digest") == provenance_digest, f"image {image.get('service')} statement provenance mismatch")
        require(predicate.get("release_signing_key_id") == release_signing_key_id, f"image {image.get('service')} statement release signing key mismatch")
        require(predicate.get("image_id") == image_id, f"image {image.get('service')} statement image digest mismatch")
        require(predicate.get("source_tree_digest") == provenance["source_tree_digest"], f"image {image.get('service')} statement source tree digest mismatch")
        require(predicate.get("compose_config_sha256") == provenance["compose_config_sha256"], f"image {image.get('service')} statement compose config digest mismatch")
        require(predicate.get("sbom_cyclonedx_sha256") == provenance["sbom_cyclonedx_sha256"], f"image {image.get('service')} statement SBOM digest mismatch")
        require(predicate.get("sbom_cyclonedx_components") == provenance["sbom_cyclonedx_components"], f"image {image.get('service')} statement SBOM component count mismatch")
        for repo_digest in predicate.get("repo_digests") or []:
            ref, _digest = require_image_ref(repo_digest, f"image {image.get('service')} statement repo digest")
            signed_repo_digests.append(ref)
    image_record = transparency_record_binding(
        metadata_transparency,
        anchor_key="anchorResponse",
        inclusion_key="inclusionProof",
        expected_type="release.image_signatures.v1",
        expected_fields={
            "provenance_digest": provenance_digest,
            "image_signature_bundle_digest": digest,
            "image_signing_key_id": image_signing_key_id,
            "image_signature_provider": "sigstore-command",
            "release_signing_key_id": release_signing_key_id,
            "signature": metadata.get("signature"),
            "images": signed_image_map,
        },
        label="image signature bundle",
    )
    require(
        sorted(signed_image_digests) == sorted(expected_image_digests),
        "image signature bundle does not cover exactly the digest-pinned production images from readiness",
    )
    require(
        sorted(signed_repo_digests) == sorted(expected_image_refs),
        "image signature bundle does not cover exactly the published production image refs from readiness",
    )
    return {
        "image_signature_bundle_digest": digest,
        "image_signing_key_id": image_signing_key_id,
        "transparency_log_ids": sorted(set(transparency_log_ids)),
        "external_transparency": external_transparency,
        "transparency_record_digest": image_record["record_digest"],
        "images": len(images),
        "signed_image_digests": sorted(signed_image_digests),
        "signed_repo_digests": sorted(signed_repo_digests),
    }


def verify_benchmark(
    bench: dict[str, Any],
    p99_limit_ms: float,
    expected_binary_digest: str,
) -> dict[str, Any]:
    require(bench.get("candidate") == "rust-decision-gate", "benchmark did not run against rust-decision-gate")
    binary_digest = require_sha256(bench.get("data_plane_binary_digest"), "benchmark data-plane binary digest")
    require(
        binary_digest == expected_binary_digest,
        "benchmark data-plane binary digest does not match production key-release measurement",
    )
    policy_hash = require_sha256(bench.get("policy_hash"), "benchmark policy hash")
    runtime_manifest_digest = require_sha256(bench.get("runtime_manifest_digest"), "benchmark runtime manifest digest")
    nonce_before = bench.get("attestation_nonce_before")
    nonce_after = bench.get("attestation_nonce_after")
    require(isinstance(nonce_before, str) and bool(nonce_before), "benchmark is missing its initial attestation nonce")
    require(isinstance(nonce_after, str) and bool(nonce_after), "benchmark is missing its final attestation nonce")
    require(nonce_before != nonce_after, "benchmark attestation nonces must be distinct")
    requests = int(bench.get("requests") or 0)
    require(requests >= 100, "benchmark request count is too small")
    p99 = float(bench.get("p99_ms"))
    require(p99 <= p99_limit_ms, f"benchmark p99 {p99} ms exceeds {p99_limit_ms} ms")
    return {
        "candidate": bench.get("candidate"),
        "requests": requests,
        "p50_ms": bench.get("p50_ms"),
        "p95_ms": bench.get("p95_ms"),
        "p99_ms": p99,
        "limit_ms": p99_limit_ms,
        "data_plane_binary_digest": binary_digest,
        "policy_hash": policy_hash,
        "runtime_manifest_digest": runtime_manifest_digest,
        "attestation_nonce_bound": True,
    }


def verify_nitro_binding(
    readiness_summary: dict[str, Any],
    nitro_summary: dict[str, Any],
    preflight_summary: dict[str, Any],
) -> dict[str, Any]:
    readiness_nitro = readiness_summary["nitro"]
    require(
        readiness_nitro["raw_attestation_document_sha256"] == nitro_summary["raw_attestation_document_sha256"],
        "standalone Nitro/KMS evidence does not match live readiness attestation",
    )
    require(
        readiness_nitro["materials"] == nitro_summary["materials"],
        "standalone Nitro/KMS evidence materials do not match live readiness",
    )
    require(
        readiness_nitro["material_key_ids"] == nitro_summary["material_key_ids"],
        "standalone Nitro/KMS evidence KMS key IDs do not match live readiness",
    )
    require(
        readiness_nitro["material_bindings"] == nitro_summary["material_bindings"],
        "standalone Nitro/KMS evidence KMS material bindings do not match live readiness",
    )
    require(
        readiness_nitro["material_release_receipts"] == nitro_summary["material_release_receipts"],
        "standalone Nitro/KMS evidence KMS release receipts do not match live readiness",
    )
    require(
        readiness_nitro["command_hashes"] == nitro_summary["command_hashes"],
        "standalone Nitro/KMS evidence command hashes do not match live readiness",
    )
    require(
        readiness_nitro["attested_runtime"] == nitro_summary["attested_runtime"],
        "standalone Nitro/KMS evidence runtime claims do not match live readiness",
    )
    require(
        nitro_summary["material_key_ids"] == preflight_summary["kms_material_key_ids"],
        "standalone Nitro/KMS evidence KMS key IDs do not match production host preflight KMS materials",
    )
    require(
        nitro_summary["material_bindings"] == preflight_summary["kms_material_bindings"],
        "standalone Nitro/KMS evidence KMS material bindings do not match production host preflight KMS materials",
    )
    return {
        "raw_attestation_document_sha256": nitro_summary["raw_attestation_document_sha256"],
        "materials": nitro_summary["materials"],
        "material_key_ids": nitro_summary["material_key_ids"],
        "material_bindings": nitro_summary["material_bindings"],
        "material_release_receipts": nitro_summary["material_release_receipts"],
        "command_hashes": nitro_summary["command_hashes"],
        "attested_runtime": nitro_summary["attested_runtime"],
        "readiness_bound": True,
        "commands_bound": True,
        "preflight_kms_materials_bound": True,
    }


def nested(value: dict[str, Any], *keys: str) -> Any:
    current: Any = value
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def require_preflight_file_digest(preflight: dict[str, Any], paths: dict[str, Path], artifact: str, *keys: str) -> None:
    expected = nested(preflight, "checks", "release_artifacts", *keys)
    require(
        expected == file_digest(paths[artifact]),
        f"production host preflight {artifact} digest does not match current artifact",
    )


def verify_production_host_preflight(
    preflight: dict[str, Any],
    paths: dict[str, Path],
    readiness_summary: dict[str, Any],
) -> dict[str, Any]:
    assert_no_secret_fields(preflight)
    require(preflight.get("apiVersion") == "serverware.productionHostPreflight/v1", "production host preflight has wrong apiVersion")
    require(preflight.get("ok") is True, "production host preflight is not ok")
    require(not preflight.get("failures"), "production host preflight includes failures")
    checks = preflight.get("checks") if isinstance(preflight.get("checks"), dict) else {}
    host = checks.get("host") if isinstance(checks.get("host"), dict) else {}
    require(host.get("ok") is True, "production host preflight host check did not pass")
    require(host.get("skipped") is not True, "production host preflight skipped host checks")
    require(host.get("linux") is True, "production host preflight did not prove Linux")
    require(host.get("nitro_nsm_device") is True, "production host preflight did not prove /dev/nsm")
    require(host.get("apparmor_sysfs") is True, "production host preflight did not prove AppArmor sysfs")

    runtime_trust = checks.get("runtime_trust_materials") if isinstance(checks.get("runtime_trust_materials"), dict) else {}
    require(runtime_trust.get("ok") is True, "production host preflight runtime trust material check did not pass")
    require(runtime_trust.get("skipped") is not True, "production host preflight skipped runtime trust material checks")
    require(
        sorted(runtime_trust.get("tls_files") or []) == ["ca.pem", "serverware.crt", "serverware.key"],
        "production host preflight did not validate every control-plane TLS file",
    )
    require(
        sorted(runtime_trust.get("helper_files") or [])
        == [
            "control-plane-attestation-verify",
            "lease-recipient-attest",
            "lease-recipient-verify",
            "nsm-attest",
            "nsm-unseal",
            "response-proof-attest",
        ],
        "production host preflight did not validate every attestation helper",
    )
    require(
        sorted(runtime_trust.get("anchor_tls_files") or []) == ["audit-anchor.crt", "audit-anchor.key"],
        "production host preflight did not validate every audit-anchor TLS file",
    )
    require(
        len(runtime_trust.get("proof_files") or []) == 4,
        "production host preflight did not validate every response-proof trust file",
    )
    require(
        runtime_trust.get("proof_collector_files") == ["serverware-proof-client"],
        "production host preflight did not validate the response-proof collector executable",
    )
    require(
        runtime_trust.get("proof_collector_private_key_mode") == "0o600",
        "production host preflight did not enforce response-proof collector private-key mode 0600",
    )
    require_sha256(runtime_trust.get("proof_collector_key_id"), "production host preflight collector key id")
    require_sha256(runtime_trust.get("proof_verifier_key_id"), "production host preflight verifier key id")

    production_env = checks.get("production_env") if isinstance(checks.get("production_env"), dict) else {}
    require(production_env.get("ok") is True, "production host preflight production env check did not pass")
    production_env_file = production_env.get("file") if isinstance(production_env.get("file"), dict) else {}
    require(
        production_env_file.get("sha256") == file_digest(paths["production_readiness_env"]),
        "production host preflight production env digest does not match current production readiness env",
    )
    config_gate = production_env.get("config_gate") if isinstance(production_env.get("config_gate"), dict) else {}
    require(config_gate.get("skipped") is not True, "production host preflight skipped the config gate")
    require(config_gate.get("ok") is True, "production host preflight config gate did not pass")
    preflight_config_file = config_gate.get("file") if isinstance(config_gate.get("file"), dict) else {}
    preflight_config_path = Path(str(config_gate.get("out") or preflight_config_file.get("path") or ""))
    require(preflight_config_path.is_file(), "production host preflight config gate artifact is missing")
    require(
        preflight_config_file.get("sha256") == file_digest(preflight_config_path),
        "production host preflight config gate digest does not match current preflight config artifact",
    )
    require(
        config_gate.get("result_sha256") == preflight_config_file.get("sha256"),
        "production host preflight config gate result digest mismatch",
    )
    preflight_config = load_json(preflight_config_path, "production host preflight config gate")
    preflight_config_semantic_sha256 = semantic_result_digest(preflight_config)
    require(
        config_gate.get("semantic_sha256") == preflight_config_semantic_sha256,
        "production host preflight config gate semantic digest mismatch",
    )

    images_env = checks.get("production_images_env") if isinstance(checks.get("production_images_env"), dict) else {}
    require(images_env.get("ok") is True and images_env.get("status") == "valid", "production host preflight image env check did not pass")
    images_env_file = images_env.get("file") if isinstance(images_env.get("file"), dict) else {}
    require(
        images_env_file.get("sha256") == file_digest(paths["production_images_env"]),
        "production host preflight production images env digest does not match current production images env",
    )
    require(
        sorted(images_env.get("image_digests") or []) == sorted(readiness_summary["production_image_digests"]),
        "production host preflight image env digests do not match readiness",
    )
    env_refs = sorted(item.get("ref") for item in images_env.get("images") or [] if isinstance(item, dict))
    require(env_refs == sorted(readiness_summary["production_images"]), "production host preflight image env refs do not match readiness")

    env_merge = checks.get("production_images_env_merge") if isinstance(checks.get("production_images_env_merge"), dict) else {}
    require(env_merge.get("ok") is True, "production host preflight image env merge check did not pass")
    production_compose = checks.get("production_compose") if isinstance(checks.get("production_compose"), dict) else {}
    require(production_compose.get("ok") is True, "production host preflight Compose check did not pass")
    require(production_compose.get("skipped") is not True, "production host preflight skipped the Compose check")
    production_compose_sha256 = require_sha256(
        production_compose.get("sha256"),
        "production host preflight Compose digest",
    )

    artifacts = checks.get("release_artifacts") if isinstance(checks.get("release_artifacts"), dict) else {}
    require(artifacts.get("ok") is True, "production host preflight release artifact check did not pass")
    require_preflight_file_digest(preflight, paths, "production_images_build", "production_images", "file", "sha256")
    require_preflight_file_digest(preflight, paths, "production_images_published", "production_images_published", "file", "sha256")
    require_preflight_file_digest(preflight, paths, "release_provenance_summary", "release_provenance", "file", "sha256")
    require_preflight_file_digest(preflight, paths, "release_provenance", "release_provenance_document", "sha256")
    require_preflight_file_digest(preflight, paths, "image_signatures_summary", "image_signatures_summary", "file", "sha256")
    require_preflight_file_digest(preflight, paths, "image_signatures", "image_signatures", "file", "sha256")
    require_preflight_file_digest(preflight, paths, "bench", "bench", "file", "sha256")
    artifact_mounts = checks.get("release_artifact_mounts") if isinstance(checks.get("release_artifact_mounts"), dict) else {}
    require(artifact_mounts.get("ok") is True, "production host preflight release artifact mount check did not pass")
    mounted_artifacts = artifact_mounts.get("artifacts") if isinstance(artifact_mounts.get("artifacts"), list) else []
    require(len(mounted_artifacts) == 2, "production host preflight did not validate both release artifact mounts")
    for item in mounted_artifacts:
        require(isinstance(item, dict), "production host preflight release artifact mount entry must be an object")
        require(item.get("matches_approved_artifact") is True, "production release artifact mount did not match approved bytes")
    benchmark = artifacts.get("bench") if isinstance(artifacts.get("bench"), dict) else {}
    benchmark_binary_digest = require_sha256(
        benchmark.get("data_plane_binary_digest"),
        "production host preflight benchmark binary digest",
    )
    signatures = artifacts.get("image_signatures") if isinstance(artifacts.get("image_signatures"), dict) else {}
    require(signatures.get("covers_published_production_images") is True, "production host preflight did not prove published image digest coverage")
    require(signatures.get("covers_published_production_image_refs") is True, "production host preflight did not prove published image ref coverage")

    kms = checks.get("kms_materials") if isinstance(checks.get("kms_materials"), dict) else {}
    require(kms.get("ok") is True, "production host preflight KMS materials check did not pass")
    require(kms.get("secret_values_redacted") is True, "production host preflight KMS materials did not redact secret values")
    kms_file = kms.get("file") if isinstance(kms.get("file"), dict) else {}
    require(
        kms_file.get("sha256") == file_digest(paths["kms_materials"]),
        "production host preflight KMS materials digest does not match current KMS materials file",
    )
    kms_material_key_ids: dict[str, str] = {}
    kms_material_bindings: dict[str, dict[str, str]] = {}
    for item in kms.get("materials") or []:
        require(isinstance(item, dict), "production host preflight KMS material entry must be an object")
        material = item.get("material")
        require(isinstance(material, str) and material, "production host preflight KMS material entry is missing material")
        require(material not in kms_material_key_ids, f"production host preflight has duplicate KMS material: {material}")
        kms_material_key_ids[material] = require_sha256(
            item.get("key_id_sha256"),
            f"production host preflight {material} KMS key id digest",
        )
        kms_material_bindings[material] = {
            "key_id_sha256": kms_material_key_ids[material],
            "ciphertext_blob_sha256": require_sha256(
                item.get("ciphertext_blob_sha256"),
                f"production host preflight {material} KMS ciphertext digest",
            ),
            "encryption_context_sha256": require_sha256(
                item.get("encryption_context_sha256"),
                f"production host preflight {material} KMS encryption context digest",
            ),
        }
    materials = sorted(kms_material_key_ids)
    require(sorted(REQUIRED_MATERIALS) == materials, "production host preflight did not validate all required KMS materials")
    current_bindings = current_kms_material_bindings(paths["kms_materials"])
    require(
        kms_material_bindings == current_bindings,
        "production host preflight KMS material bindings do not match current KMS materials file",
    )
    return {
        "host": {
            "system": host.get("system"),
            "machine": host.get("machine"),
            "linux": host.get("linux"),
            "nitro_nsm_device": host.get("nitro_nsm_device"),
            "apparmor_sysfs": host.get("apparmor_sysfs"),
        },
        "runtime_trust_materials": {
            "tls_files": sorted(runtime_trust.get("tls_files") or []),
            "anchor_tls_files": sorted(runtime_trust.get("anchor_tls_files") or []),
            "helper_files": sorted(runtime_trust.get("helper_files") or []),
            "proof_files": sorted(runtime_trust.get("proof_files") or []),
            "proof_collector_files": sorted(runtime_trust.get("proof_collector_files") or []),
            "proof_collector_private_key_mode": runtime_trust.get("proof_collector_private_key_mode"),
            "proof_collector_key_id": runtime_trust.get("proof_collector_key_id"),
            "proof_verifier_key_id": runtime_trust.get("proof_verifier_key_id"),
            "private_key_mode": runtime_trust.get("private_key_mode"),
            "certificate_not_after": runtime_trust.get("certificate_not_after"),
        },
        "production_env_keys": production_env.get("env_keys") or [],
        "production_readiness_env_sha256": production_env_file.get("sha256"),
        "production_images_env_sha256": images_env_file.get("sha256"),
        "production_config_sha256": preflight_config_file.get("sha256"),
        "production_config_semantic_sha256": preflight_config_semantic_sha256,
        "production_compose_sha256": production_compose_sha256,
        "release_artifact_mounts": mounted_artifacts,
        "production_image_refs": sorted(readiness_summary["production_images"]),
        "benchmark_binary_digest": benchmark_binary_digest,
        "kms_materials": sorted(REQUIRED_MATERIALS),
        "kms_material_key_ids": {material: kms_material_key_ids[material] for material in sorted(REQUIRED_MATERIALS)},
        "kms_material_bindings": {
            material: kms_material_bindings[material]
            for material in sorted(REQUIRED_MATERIALS)
        },
        "kms_materials_file_sha256": kms_file.get("sha256"),
    }


def verify_current_completion_host(preflight_summary: dict[str, Any], *, skip_current_host_check: bool) -> dict[str, Any]:
    current = {
        "system": platform.system(),
        "machine": platform.machine(),
        "linux": platform.system() == "Linux",
        "nitro_nsm_device": Path("/dev/nsm").exists(),
        "apparmor_sysfs": Path("/sys/module/apparmor").exists(),
    }
    if skip_current_host_check:
        require(
            os.environ.get(TEST_ONLY_BYPASS_ENV) == "1",
            f"--skip-current-host-check is test-only; set {TEST_ONLY_BYPASS_ENV}=1 in fixture tests",
        )
        return {**current, "skipped": True, "preflight_bound": False}
    for key, message in (
        ("linux", "current completion host must be Linux"),
        ("nitro_nsm_device", "current completion host must expose /dev/nsm"),
        ("apparmor_sysfs", "current completion host must expose AppArmor sysfs"),
    ):
        require(current[key] is True, message)
    for key in ("system", "machine", "linux", "nitro_nsm_device", "apparmor_sysfs"):
        require(
            current[key] == preflight_summary["host"].get(key),
            f"current completion host {key} does not match production host preflight",
        )
    return {**current, "skipped": False, "preflight_bound": True}


def verify_current_production_env_binding(
    paths: dict[str, Path],
    readiness_summary: dict[str, Any],
    preflight_summary: dict[str, Any],
    config_summary: dict[str, Any],
) -> dict[str, Any]:
    try:
        production_env = run_production_readiness.load_env_file(paths["production_readiness_env"])
    except Exception as exc:
        raise ValueError(f"current production readiness env is invalid: {exc}") from exc
    try:
        images_value = merge_production_images_env.load_images_fragment(paths["production_images_env"])
        images = merge_production_images_env.validate_production_images(images_value)
    except Exception as exc:
        raise ValueError(f"current production images env is invalid: {exc}") from exc

    configured_images = production_env.get(merge_production_images_env.KEY)
    require(
        configured_images == images_value,
        "production readiness env SERVERWARE_PRODUCTION_IMAGES does not match production images env",
    )
    refs = sorted(image["ref"] for image in images)
    digests = sorted(image["digest"] for image in images)
    require(
        refs == sorted(readiness_summary["production_images"]),
        "current production images env refs do not match readiness",
    )
    require(
        digests == sorted(readiness_summary["production_image_digests"]),
        "current production images env digests do not match readiness",
    )
    require(
        refs == sorted(preflight_summary["production_image_refs"]),
        "current production images env refs do not match production host preflight",
    )
    require(
        sorted(production_env) == sorted(preflight_summary["production_env_keys"]),
        "current production readiness env keys do not match production host preflight",
    )
    expected_binary_digest = require_sha256(
        production_env.get("SERVERWARE_EXPECTED_DATA_PLANE_BINARY_DIGEST"),
        "production readiness expected data-plane binary digest",
    )
    require(
        expected_binary_digest == preflight_summary["benchmark_binary_digest"],
        "production readiness expected data-plane binary digest does not match production host preflight benchmark",
    )
    expected_server_instance_id = production_env.get("SERVERWARE_DATA_PLANE_INSTANCE_ID", "")
    require(
        expected_server_instance_id.startswith("spiffe://")
        and len(expected_server_instance_id) > len("spiffe://"),
        "production readiness env does not pin a data-plane SPIFFE instance",
    )
    expected_collector_key_id = require_sha256(
        production_env.get("SERVERWARE_PROXY_PROOF_COLLECTOR_KEY_ID"),
        "production readiness response-proof collector key id",
    )
    expected_verifier_key_id = require_sha256(
        production_env.get("SERVERWARE_PROXY_PROOF_VERIFIER_KEY_ID"),
        "production readiness response-proof verifier key id",
    )
    runtime_trust = preflight_summary["runtime_trust_materials"]
    require(
        runtime_trust.get("proof_collector_key_id") == expected_collector_key_id,
        "production readiness response-proof collector key id does not match production host preflight",
    )
    require(
        runtime_trust.get("proof_verifier_key_id") == expected_verifier_key_id,
        "production readiness response-proof verifier key id does not match production host preflight",
    )
    production_readiness_env_sha256 = file_digest(paths["production_readiness_env"])
    production_images_env_sha256 = file_digest(paths["production_images_env"])
    require(
        production_readiness_env_sha256 == preflight_summary["production_readiness_env_sha256"],
        "current production readiness env digest does not match production host preflight",
    )
    require(
        production_images_env_sha256 == preflight_summary["production_images_env_sha256"],
        "current production images env digest does not match production host preflight",
    )
    for summary_label, summary in (
        ("production readiness", readiness_summary),
        ("production config gate", config_summary),
    ):
        environment = summary["environment"]
        require(
            environment["production_readiness_env_sha256"] == production_readiness_env_sha256,
            f"{summary_label} env digest does not match current production readiness env",
        )
        require(
            environment["production_images_env_sha256"] == production_images_env_sha256,
            f"{summary_label} image env digest does not match current production images env",
        )
    return {
        "production_readiness_env_sha256": production_readiness_env_sha256,
        "production_images_env_sha256": production_images_env_sha256,
        "production_env_keys": sorted(production_env),
        "production_images_key": merge_production_images_env.KEY,
        "production_images_key_bound": True,
        "preflight_env_files_bound": True,
        "production_image_refs": refs,
        "production_image_digests": digests,
        "expected_data_plane_binary_digest": expected_binary_digest,
        "expected_server_instance_id": expected_server_instance_id,
        "expected_proxy_collector_key_id": expected_collector_key_id,
        "expected_proxy_verifier_key_id": expected_verifier_key_id,
    }


def verify_running_production_containers(
    *,
    env_file: Path,
    compose_file: Path,
    production_image_refs: list[str],
    source_tree_digest: str,
    skip_current_host_check: bool,
) -> dict[str, Any]:
    if skip_current_host_check:
        return {"ok": True, "skipped": True, "containers": []}
    production_env = run_production_readiness.load_env_file(env_file)
    by_name = {
        ref.split("@", 1)[0].rsplit("/", 1)[-1]: ref
        for ref in production_image_refs
    }
    expected = {
        "serverware": by_name["control"],
        "audit-anchor": by_name["control"],
        "decision-gate-rs": by_name["decision-gate"],
    }

    def docker(command: list[str]) -> str:
        result = subprocess.run(
            command,
            cwd=Path(__file__).resolve().parent.parent,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            text=True,
        )
        if result.returncode != 0:
            detail = result.stderr.strip() or result.stdout.strip()
            raise ValueError(f"{' '.join(command)} failed with exit {result.returncode}: {detail}")
        return result.stdout.strip()

    base = ["docker", "compose", "--env-file", str(env_file), "-f", str(compose_file)]
    containers: list[dict[str, Any]] = []
    artifact_sources = {
        "/run/serverware/release/release-provenance.json": production_env["SERVERWARE_RELEASE_PROVENANCE_FILE"],
        "/run/serverware/release/image-signatures.json": production_env["SERVERWARE_IMAGE_SIGNATURES_FILE"],
    }
    for service, expected_ref in expected.items():
        container_id = docker([*base, "ps", "-q", service])
        require(bool(container_id) and "\n" not in container_id, f"production Compose service {service} is not uniquely running")
        container = json.loads(docker(["docker", "inspect", container_id]))[0]
        require((container.get("State") or {}).get("Status") == "running", f"production service {service} is not running")
        require((container.get("Config") or {}).get("Image") == expected_ref, f"production service {service} was not created from its digest-pinned image ref")
        host_config = container.get("HostConfig") if isinstance(container.get("HostConfig"), dict) else {}
        require(host_config.get("ReadonlyRootfs") is True, f"production service {service} does not have a read-only root filesystem")
        require("ALL" in (host_config.get("CapDrop") or []), f"production service {service} does not drop all capabilities")
        require(
            any(str(item).startswith("no-new-privileges") for item in host_config.get("SecurityOpt") or []),
            f"production service {service} does not enforce no-new-privileges",
        )
        image_id = require_sha256(container.get("Image"), f"production service {service} image id")
        image = json.loads(docker(["docker", "image", "inspect", image_id]))[0]
        require(expected_ref in (image.get("RepoDigests") or []), f"production service {service} local image does not retain the approved registry digest")
        labels = ((image.get("Config") or {}).get("Labels")) or {}
        require(
            labels.get("dev.serverware.source_tree_digest") == source_tree_digest,
            f"production service {service} image source-tree label does not match release provenance",
        )
        if service in {"serverware", "decision-gate-rs"}:
            mounts = container.get("Mounts") or []
            for destination, source in artifact_sources.items():
                require(
                    any(
                        isinstance(item, dict)
                        and item.get("Destination") == destination
                        and item.get("Source") == source
                        and item.get("RW") is False
                        for item in mounts
                    ),
                    f"production service {service} does not use the approved read-only {destination} mount",
                )
        containers.append(
            {
                "service": service,
                "container_id": container_id,
                "image_id": image_id,
                "image_ref": expected_ref,
                "source_tree_digest": source_tree_digest,
                "read_only_rootfs": True,
                "capabilities_dropped": "ALL",
                "release_artifacts_read_only": service in {"serverware", "decision-gate-rs"},
            }
        )
    return {"ok": True, "skipped": False, "compose_file": str(compose_file), "containers": containers}


def ed25519_public_key_der(public_key_pem: str, label: str) -> bytes:
    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode("ascii"))
    except Exception as exc:
        raise ValueError(f"{label} public key is invalid") from exc
    require(isinstance(public_key, Ed25519PublicKey), f"{label} public key is not Ed25519")
    return public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def ed25519_public_key_id(public_key_pem: str, label: str) -> str:
    return sha256_prefixed_bytes(ed25519_public_key_der(public_key_pem, label))


def require_base64url_bytes(value: Any, label: str, *, minimum_bytes: int) -> bytes:
    require(isinstance(value, str) and bool(value), f"{label} is required")
    require(BASE64URL_RE.fullmatch(value) is not None, f"{label} must be unpadded base64url")
    try:
        decoded = b64d(value)
    except Exception as exc:
        raise ValueError(f"{label} is invalid base64url") from exc
    require(len(decoded) >= minimum_bytes, f"{label} must contain at least {minimum_bytes} bytes")
    require(base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=") == value, f"{label} is not canonical base64url")
    return decoded


def require_unix_time(value: Any, label: str) -> int:
    require(isinstance(value, int) and not isinstance(value, bool), f"{label} must be an integer Unix timestamp")
    require(value > 0, f"{label} must be positive")
    return value


def require_production_identifier(value: Any, label: str) -> str:
    require(isinstance(value, str) and bool(value.strip()), f"{label} is required")
    normalized = value.strip().lower()
    require(
        normalized not in {"none", "none-dev", "dev", "development", "fixture", "self-reported"}
        and not normalized.startswith("dev-")
        and "fixture" not in normalized
        and "self-report" not in normalized,
        f"{label} is not a production identifier",
    )
    return value.strip()


def require_exact_object_fields(value: dict[str, Any], expected_fields: set[str], label: str) -> None:
    actual_fields = set(value)
    missing = sorted(expected_fields - actual_fields)
    unexpected = sorted(actual_fields - expected_fields)
    require(
        not missing and not unexpected,
        f"{label} fields do not match the contract; missing={missing}, unexpected={unexpected}",
    )


def verify_production_proxy_response_proof(
    document: dict[str, Any],
    *,
    trusted_verifier_public_key_pem: str,
    trusted_collector_public_key_pem: str,
    expected_server_instance_id: str,
    expected_client_nonce: str,
    expected_request_digest: str,
    expected_operation_digest: str,
    expected_tls_channel_binding: str,
    expected_policy_digest: str,
    expected_runtime_manifest_digest: str,
    expected_binary_digest: str,
    expected_release_digest: str,
    expected_response_signing_key_id: str,
    expected_tee_platform: str,
    expected_quote_provider: str,
    max_age_seconds: int,
) -> dict[str, Any]:
    assert_no_secret_fields(document)
    require(
        1 <= max_age_seconds <= PROXY_PROOF_MAX_AGE_LIMIT_SECONDS,
        f"proxy proof max age must be between 1 and {PROXY_PROOF_MAX_AGE_LIMIT_SECONDS} seconds",
    )
    require(document.get("apiVersion") == "serverware.proxyResponseProof/v2", "proxy response proof has wrong apiVersion")
    require(document.get("kind") == "ServerwareProxyResponseProof", "proxy response proof has wrong kind")
    require_exact_object_fields(
        document,
        {
            "apiVersion",
            "kind",
            "external_capture",
            "collector_signature",
            "server_statement",
            "server_signature",
            "vendor_tee",
        },
        "proxy response proof",
    )

    require(
        isinstance(expected_server_instance_id, str)
        and expected_server_instance_id.startswith("spiffe://")
        and len(expected_server_instance_id) > len("spiffe://"),
        "expected proxy server instance identity must be a SPIFFE ID",
    )

    expected_nonce_bytes = require_base64url_bytes(
        expected_client_nonce,
        "expected proxy proof client nonce",
        minimum_bytes=32,
    )
    require_sha256(expected_request_digest, "expected proxy request digest")
    require_sha256(expected_operation_digest, "expected proxy operation digest")
    expected_bindings = {
        "policy_digest": require_sha256(expected_policy_digest, "expected proxy policy digest"),
        "runtime_manifest_digest": require_sha256(
            expected_runtime_manifest_digest,
            "expected proxy runtime manifest digest",
        ),
        "data_plane_binary_digest": require_sha256(expected_binary_digest, "expected proxy data-plane binary digest"),
        "release_digest": require_sha256(expected_release_digest, "expected proxy release digest"),
    }
    expected_tls_bytes = require_base64url_bytes(
        expected_tls_channel_binding,
        "expected proxy TLS channel binding",
        minimum_bytes=32,
    )

    external_capture = document.get("external_capture") if isinstance(document.get("external_capture"), dict) else {}
    require(
        external_capture.get("apiVersion") == "serverware.proxyResponseCapture/v1",
        "proxy response external capture has wrong apiVersion",
    )
    require_exact_object_fields(
        external_capture,
        {
            "apiVersion",
            "environment",
            "collection_mode",
            "captured_at_unix",
            "client_nonce",
            "client_request",
            "client_request_digest",
            "request_digest",
            "operation_digest",
            "response",
            "tls_channel_binding",
            "tls_peer",
            "server_statement_sha256",
        },
        "proxy response external capture",
    )
    require(external_capture.get("environment") == "production", "proxy response external capture is not production evidence")
    require(
        external_capture.get("collection_mode") == "external-client-capture",
        "proxy response external capture is absent, dev, or self-reported",
    )
    captured_at = require_unix_time(
        external_capture.get("captured_at_unix"),
        "proxy response external capture time",
    )
    now = int(time.time())
    require(
        captured_at <= now + PROXY_PROOF_FUTURE_SKEW_SECONDS,
        "proxy response external capture time is in the future",
    )
    require(now - captured_at <= max_age_seconds, "proxy response external capture is stale")

    nonce = external_capture.get("client_nonce")
    nonce_bytes = require_base64url_bytes(nonce, "proxy response external capture client nonce", minimum_bytes=32)
    require(
        nonce == expected_client_nonce and nonce_bytes == expected_nonce_bytes,
        "proxy response external capture client nonce mismatch",
    )
    client_request = (
        external_capture.get("client_request")
        if isinstance(external_capture.get("client_request"), dict)
        else {}
    )
    require_exact_object_fields(
        client_request,
        {"apiVersion", "method", "scheme", "authority", "path", "query", "headers", "body_sha256"},
        "proxy response external client request",
    )
    require(
        client_request.get("apiVersion") == "serverware.clientProofRequest/v1",
        "proxy response external client request has wrong apiVersion",
    )
    require(client_request.get("method") in {"GET", "HEAD"}, "proxy response proof request method is not safe")
    require(client_request.get("scheme") == "https", "proxy response proof request scheme is not HTTPS")
    require(
        isinstance(client_request.get("authority"), str)
        and bool(client_request["authority"])
        and client_request["authority"] == client_request["authority"].lower()
        and not client_request["authority"].endswith("."),
        "proxy response proof request authority is not canonical",
    )
    require(
        isinstance(client_request.get("path"), str) and client_request["path"].startswith("/"),
        "proxy response proof request path is not canonical",
    )
    client_query = client_request.get("query")
    require(
        isinstance(client_query, list)
        and all(
            isinstance(pair, list)
            and len(pair) == 2
            and all(isinstance(value, str) for value in pair)
            for pair in client_query
        )
        and client_query == sorted(client_query),
        "proxy response proof request query is not a sorted string-pair list",
    )
    client_headers = client_request.get("headers")
    reserved_client_headers = {
        "authorization",
        "connection",
        "content-length",
        "host",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "proxy-connection",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "x-serverware-agent",
        "x-serverware-data-plane-token",
        "x-serverware-proof-nonce",
    }
    require(
        isinstance(client_headers, dict)
        and all(
            isinstance(name, str)
            and re.fullmatch(r"[a-z0-9][a-z0-9-]*", name) is not None
            and name not in reserved_client_headers
            and isinstance(value, str)
            and value == value.strip()
            and "\r" not in value
            and "\n" not in value
            for name, value in client_headers.items()
        ),
        "proxy response proof request headers are not canonical and sanitized",
    )
    require(
        client_request.get("body_sha256") == sha256_prefixed_bytes(b""),
        "proxy response proof request did not bind an empty body",
    )
    client_request_digest = require_sha256(
        external_capture.get("client_request_digest"),
        "proxy response external client request digest",
    )
    require(
        client_request_digest == sha256_prefixed_json(client_request),
        "proxy response external client request digest mismatch",
    )
    request_digest = require_sha256(
        external_capture.get("request_digest"),
        "proxy response external capture canonical request digest",
    )
    operation_digest = require_sha256(
        external_capture.get("operation_digest"),
        "proxy response external capture operation digest",
    )
    require(request_digest == expected_request_digest, "proxy response external capture canonical request digest mismatch")
    require(operation_digest == expected_operation_digest, "proxy response external capture operation digest mismatch")

    response = external_capture.get("response") if isinstance(external_capture.get("response"), dict) else {}
    require_exact_object_fields(
        response,
        {"status", "selected_headers", "selected_headers_digest", "body_digest"},
        "proxy response external capture response",
    )
    status = response.get("status")
    require(isinstance(status, int) and not isinstance(status, bool), "proxy response external capture status must be an integer")
    require(200 <= status < 300, "proxy response external capture did not bind a successful production response status")
    selected_headers = response.get("selected_headers")
    require(
        isinstance(selected_headers, dict) and bool(selected_headers),
        "proxy response external capture is missing selected response headers",
    )
    require(len(selected_headers) <= 64, "proxy response external capture selected too many response headers")
    for name, value in selected_headers.items():
        require(
            isinstance(name, str) and re.fullmatch(r"[a-z0-9][a-z0-9-]*", name) is not None,
            "proxy response external capture header names must be canonical lowercase HTTP field names",
        )
        require(
            isinstance(value, str) and "\r" not in value and "\n" not in value,
            f"proxy response external capture header {name} is invalid",
        )
    selected_headers_digest = require_sha256(
        response.get("selected_headers_digest"),
        "proxy response external capture selected response headers digest",
    )
    require(
        selected_headers_digest == sha256_prefixed_json(selected_headers),
        "proxy response external capture selected response headers digest mismatch",
    )
    body_digest = require_sha256(response.get("body_digest"), "proxy response external capture emitted body digest")
    required_selected_headers = {
        "content-length",
        "x-serverware-client-request-digest",
        "x-serverware-policy-hash",
        "x-serverware-request-digest",
        "x-serverware-operation-digest",
        "x-serverware-response-body-sha256",
    }
    selected_header_names = set(selected_headers)
    missing_selected_headers = sorted(required_selected_headers - selected_header_names)
    unexpected_selected_headers = sorted(
        selected_header_names - required_selected_headers - {"content-type"}
    )
    require(
        not missing_selected_headers,
        f"proxy response external capture is missing required selected response headers: {missing_selected_headers}",
    )
    require(
        not unexpected_selected_headers,
        f"proxy response external capture has unexpected selected response headers: {unexpected_selected_headers}",
    )
    require(
        re.fullmatch(r"0|[1-9][0-9]*", selected_headers["content-length"]) is not None,
        "proxy response external capture content-length header is not canonical",
    )
    require(
        selected_headers["x-serverware-client-request-digest"] == client_request_digest,
        "proxy response external client request digest header mismatch",
    )
    require(
        selected_headers["x-serverware-request-digest"] == request_digest,
        "proxy response external capture request digest header mismatch",
    )
    require(
        selected_headers["x-serverware-operation-digest"] == operation_digest,
        "proxy response external capture operation digest header mismatch",
    )
    require(
        selected_headers["x-serverware-response-body-sha256"] == body_digest,
        "proxy response external capture body digest header mismatch",
    )

    tls_channel_binding = (
        external_capture.get("tls_channel_binding")
        if isinstance(external_capture.get("tls_channel_binding"), dict)
        else {}
    )
    require_exact_object_fields(
        tls_channel_binding,
        {"type", "value"},
        "proxy response external capture TLS channel binding",
    )
    require(
        tls_channel_binding.get("type") == "tls-exporter",
        "proxy response external capture did not use a TLS exporter channel binding",
    )
    tls_value = tls_channel_binding.get("value")
    tls_bytes = require_base64url_bytes(
        tls_value,
        "proxy response external capture TLS channel binding",
        minimum_bytes=32,
    )
    require(
        tls_value == expected_tls_channel_binding and tls_bytes == expected_tls_bytes,
        "proxy response external capture TLS channel binding mismatch",
    )

    tls_peer = external_capture.get("tls_peer") if isinstance(external_capture.get("tls_peer"), dict) else {}
    require_exact_object_fields(
        tls_peer,
        {"spiffe_id", "leaf_certificate_sha256"},
        "proxy response external capture TLS peer",
    )
    tls_peer_spiffe_id = tls_peer.get("spiffe_id")
    require(
        isinstance(tls_peer_spiffe_id, str)
        and tls_peer_spiffe_id.startswith("spiffe://")
        and len(tls_peer_spiffe_id) > len("spiffe://"),
        "proxy response external capture TLS peer identity must be a SPIFFE ID",
    )
    require(
        tls_peer_spiffe_id == expected_server_instance_id,
        "proxy response external capture TLS peer SPIFFE ID does not match expected server instance",
    )
    tls_peer_leaf_certificate_digest = require_sha256(
        tls_peer.get("leaf_certificate_sha256"),
        "proxy response external capture TLS peer leaf certificate digest",
    )

    collector_signature = (
        document.get("collector_signature") if isinstance(document.get("collector_signature"), dict) else {}
    )
    require_exact_object_fields(
        collector_signature,
        {"algorithm", "key_id", "public_key_pem", "signature"},
        "proxy response collector signature",
    )
    require(
        collector_signature.get("algorithm") == "Ed25519",
        "proxy response collector signature algorithm is not Ed25519",
    )
    collector_public_key_pem = collector_signature.get("public_key_pem")
    collector_signature_value = collector_signature.get("signature")
    require(
        isinstance(collector_public_key_pem, str) and collector_public_key_pem,
        "proxy response external capture is missing its collector public key",
    )
    require(
        isinstance(collector_signature_value, str) and collector_signature_value,
        "proxy response external capture is missing its collector signature",
    )
    collector_public_key_der = ed25519_public_key_der(
        collector_public_key_pem,
        "proxy response external capture collector",
    )
    trusted_collector_public_key_der = ed25519_public_key_der(
        trusted_collector_public_key_pem,
        "trusted proxy response collector",
    )
    require(
        collector_public_key_der == trusted_collector_public_key_der,
        "proxy response collector signing key does not match the configured trust root",
    )
    collector_signing_key_id = sha256_prefixed_bytes(collector_public_key_der)
    require(
        collector_signature.get("key_id") == collector_signing_key_id,
        "proxy response collector signing key id mismatch",
    )
    verify_ed25519(
        collector_public_key_pem,
        collector_signature_value,
        canonical_json(external_capture).encode("utf-8"),
        "proxy response external capture collector",
    )

    server_statement = document.get("server_statement") if isinstance(document.get("server_statement"), dict) else {}
    require(
        server_statement.get("apiVersion") == "serverware.proxyResponseStatement/v1",
        "proxy response server statement has wrong apiVersion",
    )
    require_exact_object_fields(
        server_statement,
        {
            "apiVersion",
            "issued_at_unix",
            "client_nonce",
            "client_request_digest",
            "request_digest",
            "operation_digest",
            "response",
            "tls_channel_binding",
            "policy_digest",
            "runtime_manifest_digest",
            "data_plane_binary_digest",
            "release_digest",
            "server_instance",
        },
        "proxy response server statement",
    )
    issued_at = require_unix_time(
        server_statement.get("issued_at_unix"),
        "proxy response server statement issue time",
    )
    require(
        issued_at <= now + PROXY_PROOF_FUTURE_SKEW_SECONDS,
        "proxy response server statement issue time is in the future",
    )
    require(now - issued_at <= max_age_seconds, "proxy response server statement is stale")
    require(
        issued_at <= captured_at + PROXY_PROOF_FUTURE_SKEW_SECONDS,
        "proxy response server statement was issued after the external capture",
    )

    server_statement_digest = require_sha256(
        external_capture.get("server_statement_sha256"),
        "proxy response external capture server statement digest",
    )
    require(
        server_statement_digest == sha256_prefixed_json(server_statement),
        "proxy response external capture server statement digest mismatch",
    )

    server_signature = document.get("server_signature") if isinstance(document.get("server_signature"), dict) else {}
    require_exact_object_fields(
        server_signature,
        {"algorithm", "key_id", "public_key_pem", "signature"},
        "proxy response server signature",
    )
    require(server_signature.get("algorithm") == "Ed25519", "proxy response server signature algorithm is not Ed25519")
    response_public_key_pem = server_signature.get("public_key_pem")
    server_signature_value = server_signature.get("signature")
    require(
        isinstance(response_public_key_pem, str) and response_public_key_pem,
        "proxy response server statement is missing its signing public key",
    )
    require(
        isinstance(server_signature_value, str) and server_signature_value,
        "proxy response server statement is missing its signature",
    )
    response_signing_key_id = ed25519_public_key_id(response_public_key_pem, "proxy response server statement")
    require(
        server_signature.get("key_id") == response_signing_key_id,
        "proxy response server statement signing key id mismatch",
    )
    require(
        response_signing_key_id == require_sha256(
            expected_response_signing_key_id,
            "expected proxy response signing key id",
        ),
        "proxy response signing key does not match the fresh attested runtime",
    )
    verify_ed25519(
        response_public_key_pem,
        server_signature_value,
        canonical_json(server_statement).encode("utf-8"),
        "proxy response server statement",
    )

    statement_nonce = server_statement.get("client_nonce")
    require_base64url_bytes(statement_nonce, "proxy response server statement client nonce", minimum_bytes=32)
    require(
        statement_nonce == nonce,
        "proxy response external capture client_nonce does not match server statement",
    )
    statement_request_digest = require_sha256(
        server_statement.get("request_digest"),
        "proxy response server statement canonical request digest",
    )
    require(
        statement_request_digest == request_digest,
        "proxy response external capture request_digest does not match server statement",
    )
    require(
        require_sha256(
            server_statement.get("client_request_digest"),
            "proxy response server statement client request digest",
        )
        == client_request_digest,
        "proxy response external client request digest does not match server statement",
    )
    statement_operation_digest = require_sha256(
        server_statement.get("operation_digest"),
        "proxy response server statement operation digest",
    )
    require(
        statement_operation_digest == operation_digest,
        "proxy response external capture operation_digest does not match server statement",
    )

    statement_response = (
        server_statement.get("response") if isinstance(server_statement.get("response"), dict) else {}
    )
    require_exact_object_fields(
        statement_response,
        {"status", "selected_headers", "selected_headers_digest", "body_digest"},
        "proxy response server statement response",
    )
    require(
        statement_response == response,
        "proxy response external capture response does not match server statement",
    )
    statement_tls_channel_binding = (
        server_statement.get("tls_channel_binding")
        if isinstance(server_statement.get("tls_channel_binding"), dict)
        else {}
    )
    require_exact_object_fields(
        statement_tls_channel_binding,
        {"type", "value"},
        "proxy response server statement TLS channel binding",
    )
    require(
        statement_tls_channel_binding == tls_channel_binding,
        "proxy response external capture tls_channel_binding does not match server statement",
    )

    bindings = {
        "policy_digest": require_sha256(
            server_statement.get("policy_digest"),
            "proxy response server statement policy digest",
        ),
        "runtime_manifest_digest": require_sha256(
            server_statement.get("runtime_manifest_digest"),
            "proxy response server statement runtime manifest digest",
        ),
        "data_plane_binary_digest": require_sha256(
            server_statement.get("data_plane_binary_digest"),
            "proxy response server statement data-plane binary digest",
        ),
        "release_digest": require_sha256(
            server_statement.get("release_digest"),
            "proxy response server statement release digest",
        ),
    }
    for field, expected in expected_bindings.items():
        require(bindings[field] == expected, f"proxy response server statement {field.replace('_', ' ')} mismatch")
    require(
        selected_headers["x-serverware-policy-hash"] == bindings["policy_digest"],
        "proxy response external capture policy hash header mismatch",
    )

    server_instance = (
        server_statement.get("server_instance")
        if isinstance(server_statement.get("server_instance"), dict)
        else {}
    )
    require_exact_object_fields(server_instance, {"id", "identity_digest"}, "proxy response server instance")
    server_instance_id = server_instance.get("id")
    require(
        isinstance(server_instance_id, str) and server_instance_id.startswith("spiffe://") and len(server_instance_id) > len("spiffe://"),
        "proxy response server statement server instance identity must be a SPIFFE ID",
    )
    require(
        server_instance_id == expected_server_instance_id,
        "proxy response server statement server instance does not match expected SPIFFE ID",
    )
    require(
        server_instance_id == tls_peer_spiffe_id,
        "proxy response server statement server instance does not match external capture TLS peer SPIFFE ID",
    )
    server_instance_identity_digest = require_sha256(
        server_instance.get("identity_digest"),
        "proxy response server statement server instance identity digest",
    )
    require(
        server_instance_identity_digest == sha256_prefixed_bytes(server_instance_id.encode("utf-8")),
        "proxy response server statement server instance identity digest mismatch",
    )

    vendor_tee = document.get("vendor_tee") if isinstance(document.get("vendor_tee"), dict) else {}
    tee_platform = require_production_identifier(vendor_tee.get("platform"), "proxy response vendor TEE platform")
    quote_provider = require_production_identifier(vendor_tee.get("provider"), "proxy response vendor quote provider")
    require(tee_platform == expected_tee_platform, "proxy response vendor TEE platform does not match release attestation")
    require(quote_provider == expected_quote_provider, "proxy response vendor quote provider does not match release attestation")
    quote = vendor_tee.get("quote") if isinstance(vendor_tee.get("quote"), dict) else {}
    require(bool(quote), "proxy response proof is missing a non-null vendor TEE quote")
    require_production_identifier(quote.get("format"), "proxy response vendor quote format")
    require_base64url_bytes(quote.get("body_b64"), "proxy response vendor quote body", minimum_bytes=64)
    vendor_quote_digest = require_sha256(vendor_tee.get("quote_sha256"), "proxy response vendor quote digest")
    require(vendor_quote_digest == sha256_prefixed_json(quote), "proxy response vendor quote digest mismatch")

    trusted_verifier_key_id = ed25519_public_key_id(
        trusted_verifier_public_key_pem,
        "trusted proxy proof vendor verifier",
    )
    trusted_verifier = (
        vendor_tee.get("trusted_verifier") if isinstance(vendor_tee.get("trusted_verifier"), dict) else {}
    )
    require(
        trusted_verifier.get("apiVersion") == "serverware.vendorTeeVerification/v1",
        "proxy response vendor verifier result has wrong apiVersion",
    )
    require(
        trusted_verifier.get("kind") == "ServerwareVendorTeeVerification",
        "proxy response vendor verifier result has wrong kind",
    )
    verifier_statement = (
        trusted_verifier.get("statement") if isinstance(trusted_verifier.get("statement"), dict) else {}
    )
    verifier_signature = trusted_verifier.get("signature")
    require(bool(verifier_statement), "proxy response proof is missing a trusted vendor verifier statement")
    require(isinstance(verifier_signature, str) and verifier_signature, "proxy response proof is missing a trusted vendor verifier signature")
    require(
        verifier_statement.get("verifier_key_id") == trusted_verifier_key_id,
        "proxy response vendor verifier key is not the configured trust root",
    )
    verify_ed25519(
        trusted_verifier_public_key_pem,
        verifier_signature,
        canonical_json(verifier_statement).encode("utf-8"),
        "proxy response trusted vendor verifier",
    )
    require(verifier_statement.get("outcome") == "verified", "proxy response vendor TEE verification outcome is not verified")
    require(verifier_statement.get("environment") == "production", "proxy response vendor TEE verification is not production")
    require(
        verifier_statement.get("trust_basis") == "vendor-root-certificate-chain",
        "proxy response vendor TEE verifier did not use a vendor trust root",
    )
    require(verifier_statement.get("vendor_quote_verified") is True, "proxy response vendor quote was not verified")
    require(verifier_statement.get("certificate_chain_verified") is True, "proxy response vendor certificate chain was not verified")
    require(verifier_statement.get("revocation_checked") is True, "proxy response vendor quote revocation status was not checked")
    require(verifier_statement.get("debug") is False, "proxy response vendor TEE verification accepted debug mode")
    verified_at = require_unix_time(verifier_statement.get("verified_at_unix"), "proxy response vendor verification time")
    expires_at = require_unix_time(verifier_statement.get("expires_at_unix"), "proxy response vendor verification expiry")
    require(verified_at <= now + PROXY_PROOF_FUTURE_SKEW_SECONDS, "proxy response vendor verification time is in the future")
    require(now - verified_at <= max_age_seconds, "proxy response trusted vendor verifier receipt is stale")
    require(expires_at > verified_at, "proxy response vendor verifier validity window is invalid")
    require(expires_at >= now, "proxy response trusted vendor verifier receipt is expired")
    require(
        expires_at - verified_at <= PROXY_PROOF_MAX_AGE_LIMIT_SECONDS,
        "proxy response vendor verifier validity window is too long",
    )
    require(verifier_statement.get("tee_platform") == tee_platform, "proxy response vendor verifier TEE platform mismatch")
    require(verifier_statement.get("quote_provider") == quote_provider, "proxy response vendor verifier quote provider mismatch")
    require(
        verifier_statement.get("vendor_quote_sha256") == vendor_quote_digest,
        "proxy response vendor verifier quote digest mismatch",
    )
    require(
        "proof_evidence_sha256" not in verifier_statement,
        "proxy response vendor verifier used the legacy proof evidence digest binding",
    )
    require(
        verifier_statement.get("server_statement_sha256") == server_statement_digest,
        "proxy response vendor verifier server statement digest mismatch",
    )
    require(
        verifier_statement.get("response_signing_key_id") == response_signing_key_id,
        "proxy response vendor verifier did not bind the response signing key",
    )

    attested_claims = (
        verifier_statement.get("attested_claims")
        if isinstance(verifier_statement.get("attested_claims"), dict)
        else {}
    )
    expected_attested_claims: dict[str, Any] = {
        "server_statement_sha256": server_statement_digest,
        "server_statement_api_version": server_statement["apiVersion"],
        "issued_at_unix": issued_at,
        "client_nonce_sha256": sha256_prefixed_bytes(nonce_bytes),
        "client_request_digest": client_request_digest,
        "request_digest": request_digest,
        "operation_digest": operation_digest,
        "response_status": status,
        "selected_response_headers_digest": selected_headers_digest,
        "response_body_digest": body_digest,
        **bindings,
        "server_instance_id": server_instance_id,
        "server_instance_identity_digest": server_instance_identity_digest,
        "tls_channel_binding_type": tls_channel_binding["type"],
        "tls_channel_binding_sha256": sha256_prefixed_json(tls_channel_binding),
        "response_signing_key_id": response_signing_key_id,
    }
    for field, expected in expected_attested_claims.items():
        require(attested_claims.get(field) == expected, f"proxy response vendor TEE attested claim {field} mismatch")
    require(
        set(attested_claims) == set(expected_attested_claims),
        "proxy response vendor TEE attested claims do not exactly match the server statement",
    )

    return {
        "apiVersion": document.get("apiVersion"),
        "server_statement_sha256": server_statement_digest,
        "captured_at_unix": captured_at,
        "issued_at_unix": issued_at,
        "client_request_digest": client_request_digest,
        "request_digest": request_digest,
        "operation_digest": operation_digest,
        "status": status,
        "selected_response_headers_digest": selected_headers_digest,
        "emitted_body_digest": body_digest,
        **bindings,
        "server_instance_id": server_instance_id,
        "server_instance_identity_digest": server_instance_identity_digest,
        "tls_channel_binding_sha256": sha256_prefixed_json(tls_channel_binding),
        "tls_peer_spiffe_id": tls_peer_spiffe_id,
        "tls_peer_leaf_certificate_sha256": tls_peer_leaf_certificate_digest,
        "collector_signing_key_id": collector_signing_key_id,
        "response_signing_key_id": response_signing_key_id,
        "vendor_tee_platform": tee_platform,
        "vendor_quote_provider": quote_provider,
        "vendor_quote_sha256": vendor_quote_digest,
        "trusted_verifier_key_id": trusted_verifier_key_id,
        "vendor_quote_verified": True,
        "trusted_verifier_outcome": "verified",
        "collector_signature_verified": True,
        "server_statement_signature_verified": True,
        "fresh_client_nonce_bound": True,
        "authenticated_external_client_capture_bound": True,
        "release_artifacts_bound": True,
    }


def write_output(path: Path, proof: dict[str, Any]) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = (json.dumps(proof, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode("utf-8")
    path.write_bytes(payload)
    return sha256_prefixed_bytes(payload)


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify the Serverware final release-completion artifact set.")
    parser.add_argument("--production-readiness", default=".tmp/production-readiness.json")
    parser.add_argument("--production-readiness-config", default=".tmp/production-readiness-config.json")
    parser.add_argument("--production-readiness-env", default="ops/production-readiness.env")
    parser.add_argument("--compose-file", default="docker-compose.production.yml")
    parser.add_argument("--production-host-preflight", default=".tmp/production-host-preflight.json")
    parser.add_argument("--nitro-evidence", default=".tmp/nitro-kms-evidence.json")
    parser.add_argument("--production-images-build", default=".tmp/production-images-build.json")
    parser.add_argument("--production-images-env", default=".tmp/production-images.env")
    parser.add_argument("--production-images-published", default=".tmp/production-images-published.json")
    parser.add_argument("--release-provenance-summary", default=".tmp/release-provenance-summary.json")
    parser.add_argument("--release-provenance", default=".tmp/release-provenance.json")
    parser.add_argument("--image-signatures-summary", default=".tmp/image-signatures-summary.json")
    parser.add_argument("--image-signatures", default=".tmp/image-signatures.json")
    parser.add_argument("--bench", default=".tmp/decision-gate-rs-bench.json")
    parser.add_argument("--kms-materials", default="/etc/serverware/kms-materials.json")
    parser.add_argument("--proxy-response-proof", default=None)
    parser.add_argument("--proxy-proof-verifier-public-key", default=None)
    parser.add_argument("--proxy-collector-public-key", default=None)
    parser.add_argument("--proxy-server-instance-id", default=None)
    parser.add_argument("--proxy-client-nonce", default=None)
    parser.add_argument("--proxy-request-digest", default=None)
    parser.add_argument("--proxy-operation-digest", default=None)
    parser.add_argument("--proxy-tls-channel-binding", default=None)
    parser.add_argument("--proxy-proof-max-age-seconds", type=int, default=300)
    parser.add_argument("--p99-limit-ms", type=float, default=20.0)
    parser.add_argument("--out", default=None)
    parser.add_argument("--skip-current-host-check", action="store_true", help="Test-only bypass for synthetic fixture completion tests.")
    args = parser.parse_args()

    require(bool(args.proxy_response_proof), "production completion requires --proxy-response-proof")
    require(
        bool(args.proxy_proof_verifier_public_key),
        "production completion requires --proxy-proof-verifier-public-key",
    )
    require(
        bool(args.proxy_collector_public_key),
        "production completion requires --proxy-collector-public-key",
    )
    require(bool(args.proxy_server_instance_id), "production completion requires --proxy-server-instance-id")
    require(bool(args.proxy_client_nonce), "production completion requires --proxy-client-nonce")
    require(bool(args.proxy_request_digest), "production completion requires --proxy-request-digest")
    require(bool(args.proxy_operation_digest), "production completion requires --proxy-operation-digest")
    require(bool(args.proxy_tls_channel_binding), "production completion requires --proxy-tls-channel-binding")

    paths = {
        "production_readiness": Path(args.production_readiness),
        "production_readiness_config": Path(args.production_readiness_config),
        "production_readiness_env": Path(args.production_readiness_env),
        "production_host_preflight": Path(args.production_host_preflight),
        "nitro_evidence": Path(args.nitro_evidence),
        "production_images_build": Path(args.production_images_build),
        "production_images_env": Path(args.production_images_env),
        "production_images_published": Path(args.production_images_published),
        "release_provenance_summary": Path(args.release_provenance_summary),
        "release_provenance": Path(args.release_provenance),
        "image_signatures_summary": Path(args.image_signatures_summary),
        "image_signatures": Path(args.image_signatures),
        "bench": Path(args.bench),
        "kms_materials": Path(args.kms_materials),
        "proxy_response_proof": Path(args.proxy_response_proof),
        "proxy_proof_verifier_public_key": Path(args.proxy_proof_verifier_public_key),
        "proxy_collector_public_key": Path(args.proxy_collector_public_key),
    }

    readiness = load_json(paths["production_readiness"], "production readiness")
    production_readiness_config = load_json(paths["production_readiness_config"], "production readiness config")
    production_host_preflight = load_json(paths["production_host_preflight"], "production host preflight")
    nitro_evidence = load_json(paths["nitro_evidence"], "Nitro/KMS evidence")
    production_images_build = load_json(paths["production_images_build"], "production images build")
    production_images_published = load_json(paths["production_images_published"], "production images published")
    provenance_summary = load_json(paths["release_provenance_summary"], "release provenance summary")
    provenance_document = load_json(paths["release_provenance"], "release provenance")
    image_summary = load_json(paths["image_signatures_summary"], "image signatures summary")
    image_document = load_json(paths["image_signatures"], "image signatures")
    bench = load_json(paths["bench"], "decision-gate benchmark")
    proxy_response_proof = load_json(paths["proxy_response_proof"], "production proxy response proof")
    trusted_proxy_verifier_public_key_pem = paths["proxy_proof_verifier_public_key"].read_text(encoding="ascii")
    trusted_proxy_collector_public_key_pem = paths["proxy_collector_public_key"].read_text(encoding="ascii")

    readiness_summary = verify_readiness(readiness)
    preflight_summary = verify_production_host_preflight(production_host_preflight, paths, readiness_summary)
    current_host_summary = verify_current_completion_host(
        preflight_summary,
        skip_current_host_check=args.skip_current_host_check,
    )
    production_config_summary = verify_production_config_result(production_readiness_config, preflight_summary)
    production_env_binding = verify_current_production_env_binding(
        paths,
        readiness_summary,
        preflight_summary,
        production_config_summary,
    )
    nitro_summary = verify_nitro_evidence(nitro_evidence, "standalone Nitro/KMS evidence")
    nitro_binding = verify_nitro_binding(readiness_summary, nitro_summary, preflight_summary)
    provenance_summary_out = verify_release_provenance(
        provenance_summary,
        provenance_document,
        str(readiness_summary["external_transparency_provider"]),
        str(readiness_summary["external_transparency_log_id"]),
    )
    require(
        preflight_summary["production_compose_sha256"] == provenance_summary_out["compose_config_sha256"],
        "production host rendered Compose digest does not match signed release provenance",
    )
    provenance_summary_out["production_host_compose_bound"] = True
    current_source_tree_digest = build_production_images.source_tree_digest()
    require(
        provenance_summary_out["source_tree_digest"] == current_source_tree_digest,
        "release provenance source tree digest does not match current source tree",
    )
    provenance_summary_out["current_source_tree_digest"] = current_source_tree_digest
    provenance_summary_out["current_source_tree_bound"] = True
    running_containers = verify_running_production_containers(
        env_file=paths["production_readiness_env"],
        compose_file=Path(args.compose_file),
        production_image_refs=list(readiness_summary["production_images"]),
        source_tree_digest=current_source_tree_digest,
        skip_current_host_check=args.skip_current_host_check,
    )
    production_images_build_summary = verify_production_image_build(
        production_images_build,
        str(provenance_summary_out["source_tree_digest"]),
    )
    production_images_published_summary = verify_published_images(
        production_images_published,
        production_images_build_summary,
        list(readiness_summary["production_images"]),
    )
    image_summary_out = verify_image_signatures(
        image_summary,
        image_document,
        provenance_summary_out,
        list(readiness_summary["production_image_digests"]),
        list(readiness_summary["production_images"]),
        str(readiness_summary["sigstore_key_id"]),
        str(readiness_summary["rekor_log_id"]),
        str(readiness_summary["external_transparency_provider"]),
        str(readiness_summary["external_transparency_log_id"]),
    )
    benchmark_summary = verify_benchmark(
        bench,
        args.p99_limit_ms,
        str(production_env_binding["expected_data_plane_binary_digest"]),
    )
    production_gate_binary = next(
        (
            item.get("binary_digest")
            for item in production_images_build_summary["images"]
            if item.get("service") == "serverware-decision-gate"
        ),
        None,
    )
    require(
        production_gate_binary == benchmark_summary["data_plane_binary_digest"],
        "benchmark data-plane binary digest does not match the production image binary",
    )
    benchmark_summary["production_image_binary_bound"] = True
    require(
        args.proxy_server_instance_id == production_env_binding["expected_server_instance_id"],
        "proxy response expected server instance does not match the signed production environment",
    )
    attested_runtime = readiness_summary["nitro"]["attested_runtime"]
    require(
        attested_runtime["data_plane_binary_digest"] == production_gate_binary,
        "fresh Nitro-attested data-plane binary digest does not match the production image",
    )
    require(
        attested_runtime["provenance_digest"] == provenance_summary_out["provenance_digest"],
        "fresh Nitro-attested release digest does not match signed release provenance",
    )
    require(
        attested_runtime["source_tree_digest"] == provenance_summary_out["source_tree_digest"],
        "fresh Nitro-attested source tree digest does not match signed release provenance",
    )
    proxy_response_summary = verify_production_proxy_response_proof(
        proxy_response_proof,
        trusted_verifier_public_key_pem=trusted_proxy_verifier_public_key_pem,
        trusted_collector_public_key_pem=trusted_proxy_collector_public_key_pem,
        expected_server_instance_id=str(args.proxy_server_instance_id),
        expected_client_nonce=str(args.proxy_client_nonce),
        expected_request_digest=str(args.proxy_request_digest),
        expected_operation_digest=str(args.proxy_operation_digest),
        expected_tls_channel_binding=str(args.proxy_tls_channel_binding),
        expected_policy_digest=str(attested_runtime["policy_digest"]),
        expected_runtime_manifest_digest=str(attested_runtime["runtime_manifest_digest"]),
        expected_binary_digest=str(attested_runtime["data_plane_binary_digest"]),
        expected_release_digest=str(attested_runtime["provenance_digest"]),
        expected_response_signing_key_id=str(attested_runtime["response_signing_key_id"]),
        expected_tee_platform=str(nitro_summary["tee_platform"]),
        expected_quote_provider=str(nitro_summary["provider"]),
        max_age_seconds=args.proxy_proof_max_age_seconds,
    )
    require(
        proxy_response_summary["collector_signing_key_id"]
        == production_env_binding["expected_proxy_collector_key_id"],
        "proxy response collector key does not match the signed production environment pin",
    )
    require(
        proxy_response_summary["trusted_verifier_key_id"]
        == production_env_binding["expected_proxy_verifier_key_id"],
        "proxy response vendor verifier key does not match the signed production environment pin",
    )

    proof = {
        "apiVersion": "serverware.completionProof/v2",
        "kind": "ServerwareCompletionProof",
        "ok": True,
        "generated_at_unix": int(time.time()),
        "artifacts": {label: {"path": str(path), "sha256": file_digest(path)} for label, path in paths.items()},
        "production_readiness": readiness_summary,
        "production_readiness_config": production_config_summary,
        "current_completion_host": current_host_summary,
        "production_env_binding": production_env_binding,
        "running_production_containers": running_containers,
        "production_host_preflight": preflight_summary,
        "nitro_kms_evidence": nitro_summary,
        "nitro_evidence_binding": nitro_binding,
        "production_images_build": production_images_build_summary,
        "production_images_published": production_images_published_summary,
        "release_provenance": provenance_summary_out,
        "image_signatures": image_summary_out,
        "benchmark": benchmark_summary,
        "production_proxy_response_proof": proxy_response_summary,
    }
    if args.out:
        proof["proof_path"] = args.out
        proof["proof_sha256"] = write_output(Path(args.out), proof)
    print(canonical_json(proof))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(canonical_json({"ok": False, "error": str(exc)}), file=sys.stderr)
        raise SystemExit(1) from exc
