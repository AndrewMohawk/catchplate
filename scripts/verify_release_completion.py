#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import platform
import re
import sys
import time
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization

import build_production_images
import merge_production_images_env
import run_production_readiness


REQUIRED_READINESS_CHECKS = {
    "no-dev-fixtures",
    "control-plane-auth",
    "nitro",
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


def load_json(path: Path, label: str) -> dict[str, Any]:
    if not path.exists():
        raise ValueError(f"{label} artifact does not exist: {path}")
    parsed = json.loads(path.read_text(encoding="utf-8"))
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
        "compose_config_sha256": require_sha256(provenance.get("compose_config_sha256"), "release provenance compose config digest"),
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
        normalized.append(
            {
                "service": service,
                "image_id": require_sha256(image.get("image_id"), f"{service} image_id"),
                "dockerfile": image.get("dockerfile"),
                "tag": image.get("tag"),
            }
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
    build_by_service = {item["service"]: item["image_id"] for item in build_summary["images"]}
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
            local_image_id == build_by_service[service],
            "published production images do not match current no-shell build",
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


def verify_benchmark(bench: dict[str, Any], p99_limit_ms: float) -> dict[str, Any]:
    require(bench.get("candidate") == "rust-decision-gate", "benchmark did not run against rust-decision-gate")
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

    artifacts = checks.get("release_artifacts") if isinstance(checks.get("release_artifacts"), dict) else {}
    require(artifacts.get("ok") is True, "production host preflight release artifact check did not pass")
    require_preflight_file_digest(preflight, paths, "production_images_build", "production_images", "file", "sha256")
    require_preflight_file_digest(preflight, paths, "production_images_published", "production_images_published", "file", "sha256")
    require_preflight_file_digest(preflight, paths, "release_provenance_summary", "release_provenance", "file", "sha256")
    require_preflight_file_digest(preflight, paths, "release_provenance", "release_provenance_document", "sha256")
    require_preflight_file_digest(preflight, paths, "image_signatures_summary", "image_signatures_summary", "file", "sha256")
    require_preflight_file_digest(preflight, paths, "image_signatures", "image_signatures", "file", "sha256")
    require_preflight_file_digest(preflight, paths, "bench", "bench", "file", "sha256")
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
        "production_env_keys": production_env.get("env_keys") or [],
        "production_readiness_env_sha256": production_env_file.get("sha256"),
        "production_images_env_sha256": images_env_file.get("sha256"),
        "production_config_sha256": preflight_config_file.get("sha256"),
        "production_config_semantic_sha256": preflight_config_semantic_sha256,
        "production_image_refs": sorted(readiness_summary["production_images"]),
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
    parser.add_argument("--p99-limit-ms", type=float, default=20.0)
    parser.add_argument("--out", default=None)
    parser.add_argument("--skip-current-host-check", action="store_true", help="Test-only bypass for synthetic fixture completion tests.")
    args = parser.parse_args()

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
    current_source_tree_digest = build_production_images.source_tree_digest()
    require(
        provenance_summary_out["source_tree_digest"] == current_source_tree_digest,
        "release provenance source tree digest does not match current source tree",
    )
    provenance_summary_out["current_source_tree_digest"] = current_source_tree_digest
    provenance_summary_out["current_source_tree_bound"] = True
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
    benchmark_summary = verify_benchmark(bench, args.p99_limit_ms)

    proof = {
        "apiVersion": "serverware.completionProof/v1",
        "kind": "ServerwareCompletionProof",
        "ok": True,
        "generated_at_unix": int(time.time()),
        "artifacts": {label: {"path": str(path), "sha256": file_digest(path)} for label, path in paths.items()},
        "production_readiness": readiness_summary,
        "production_readiness_config": production_config_summary,
        "current_completion_host": current_host_summary,
        "production_env_binding": production_env_binding,
        "production_host_preflight": preflight_summary,
        "nitro_kms_evidence": nitro_summary,
        "nitro_evidence_binding": nitro_binding,
        "production_images_build": production_images_build_summary,
        "production_images_published": production_images_published_summary,
        "release_provenance": provenance_summary_out,
        "image_signatures": image_summary_out,
        "benchmark": benchmark_summary,
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
