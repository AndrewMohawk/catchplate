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

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import build_production_images  # noqa: E402
import merge_production_images_env  # noqa: E402
import publish_production_images  # noqa: E402
import run_production_readiness  # noqa: E402
import verify_release_completion as completion  # noqa: E402

SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
BENCH_P99_TARGET_MS = 20.0
EXPECTED_TRANSPARENCY_PROVIDER_ENV_KEY = "SERVERWARE_TRANSPARENCY_EXPECTED_PROVIDER"
EXPECTED_TRANSPARENCY_LOG_ID_ENV_KEY = "SERVERWARE_TRANSPARENCY_EXPECTED_LOG_ID"
EXPECTED_SIGSTORE_KEY_ID_ENV_KEY = "SERVERWARE_COSIGN_KEY_ID"
EXPECTED_REKOR_LOG_ID_ENV_KEY = "SERVERWARE_COSIGN_EXPECTED_REKOR_LOG_ID"


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_prefixed_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def sha256_prefixed_json(value: Any) -> str:
    return sha256_prefixed_bytes(canonical_json(value).encode("utf-8"))


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


def load_json(path: Path, label: str) -> dict[str, Any]:
    if not path.exists():
        raise ValueError(f"{label} does not exist: {path}")
    parsed = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(parsed, dict):
        raise ValueError(f"{label} must be a JSON object: {path}")
    return parsed


def file_summary(path: Path, label: str) -> dict[str, Any]:
    if not path.exists():
        return {"label": label, "path": str(path), "exists": False}
    data = path.read_bytes()
    return {
        "label": label,
        "path": str(path),
        "exists": True,
        "bytes": len(data),
        "sha256": sha256_prefixed_bytes(data),
    }


def require_sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise ValueError(f"{label} must be sha256:<64 hex>")
    return value


def _release_trust_root(
    configured: dict[str, str],
    setting_name: str,
    label: str,
) -> tuple[str, str]:
    selected = configured.get(setting_name, "").strip()
    if not selected:
        raise ValueError(f"production readiness env is missing {setting_name}")
    snapshot = completion.snapshot_regular_file(
        Path(selected),
        label,
        max_bytes=completion.FINAL_TRUST_ROOT_MAX_BYTES,
    )
    public_key_pem = completion.snapshot_text(snapshot, label, encoding="ascii").strip()
    return public_key_pem, release_public_key_id(public_key_pem)


def release_trust_from_config(configured: dict[str, str]) -> dict[str, str]:
    provider = configured.get(completion.EXTERNAL_CHECKPOINT_PROVIDER_ENV_KEY, "").strip()
    expected_provider = configured.get(EXPECTED_TRANSPARENCY_PROVIDER_ENV_KEY, "").strip()
    if not provider or provider != expected_provider:
        raise ValueError(
            "SERVERWARE_EXTERNAL_CHECKPOINT_PROVIDER must match "
            "SERVERWARE_TRANSPARENCY_EXPECTED_PROVIDER"
        )
    expected_external_log_id = require_sha256(
        configured.get(EXPECTED_TRANSPARENCY_LOG_ID_ENV_KEY),
        EXPECTED_TRANSPARENCY_LOG_ID_ENV_KEY,
    )
    expected_sigstore_key_id = require_sha256(
        configured.get(EXPECTED_SIGSTORE_KEY_ID_ENV_KEY),
        EXPECTED_SIGSTORE_KEY_ID_ENV_KEY,
    )
    expected_rekor_log_id = require_sha256(
        configured.get(EXPECTED_REKOR_LOG_ID_ENV_KEY),
        EXPECTED_REKOR_LOG_ID_ENV_KEY,
    )
    release_pem, release_id = _release_trust_root(
        configured,
        completion.RELEASE_PROVENANCE_TRUST_ROOT_ENV_KEY,
        "release provenance trust root",
    )
    sigstore_pem, sigstore_id = _release_trust_root(
        configured,
        completion.SIGSTORE_TRUST_ROOT_ENV_KEY,
        "Sigstore trust root",
    )
    rekor_pem, rekor_id = _release_trust_root(
        configured,
        completion.REKOR_TRUST_ROOT_ENV_KEY,
        "Rekor trust root",
    )
    external_pem, external_id = _release_trust_root(
        configured,
        completion.EXTERNAL_CHECKPOINT_TRUST_ROOT_ENV_KEY,
        "external checkpoint trust root",
    )
    if sigstore_id != expected_sigstore_key_id:
        raise ValueError("Sigstore trust root does not match SERVERWARE_COSIGN_KEY_ID")
    if rekor_id != expected_rekor_log_id:
        raise ValueError("Rekor trust root does not match SERVERWARE_COSIGN_EXPECTED_REKOR_LOG_ID")
    if external_id != expected_external_log_id:
        raise ValueError(
            "external checkpoint trust root does not match "
            "SERVERWARE_TRANSPARENCY_EXPECTED_LOG_ID"
        )
    role_ids = {release_id, sigstore_id, rekor_id, external_id}
    if len(role_ids) != 4:
        raise ValueError("production release trust roles must use distinct public keys")
    for setting_name, expected_id_name, label in (
        (
            completion.FINAL_HARDWARE_TRUST_ROOT_ENV_KEY,
            completion.FINAL_HARDWARE_TRUST_ROOT_ID_ENV_KEY,
            "hardware assurance trust root",
        ),
        (
            completion.FINAL_CHALLENGE_AUTHORITY_TRUST_ROOT_ENV_KEY,
            completion.FINAL_CHALLENGE_AUTHORITY_TRUST_ROOT_ID_ENV_KEY,
            "final challenge authority trust root",
        ),
    ):
        if not configured.get(setting_name, "").strip():
            continue
        _, key_id = _release_trust_root(configured, setting_name, label)
        expected_key_id = require_sha256(configured.get(expected_id_name), expected_id_name)
        if key_id != expected_key_id:
            raise ValueError(f"{label} does not match {expected_id_name}")
        if key_id in role_ids:
            raise ValueError(f"{label} must not reuse a production release trust key")
        role_ids.add(key_id)
    return {
        "release_public_key_pem": release_pem,
        "release_key_id": release_id,
        "sigstore_public_key_pem": sigstore_pem,
        "sigstore_key_id": sigstore_id,
        "rekor_public_key_pem": rekor_pem,
        "rekor_log_id": rekor_id,
        "external_public_key_pem": external_pem,
        "external_provider": expected_provider,
        "external_log_id": external_id,
    }


def verify_production_images_build(path: Path, *, check_current_tree: bool) -> dict[str, Any]:
    build = load_json(path, "production images build artifact")
    if build.get("ok") is not True:
        raise ValueError("production images build artifact is not ok")
    no_shell = build.get("no_shell") if isinstance(build.get("no_shell"), dict) else {}
    if no_shell.get("ok") is not True:
        raise ValueError("production images build artifact did not pass no-shell verification")
    metadata = build.get("metadata") if isinstance(build.get("metadata"), dict) else {}
    source_tree_digest = require_sha256(metadata.get("source_tree_digest"), "production image source tree digest")
    current_source_tree_digest = build_production_images.source_tree_digest()
    if check_current_tree and source_tree_digest != current_source_tree_digest:
        raise ValueError(
            "production image build artifact is stale: "
            f"artifact source_tree_digest={source_tree_digest} current_source_tree_digest={current_source_tree_digest}"
        )
    images = build.get("images")
    if not isinstance(images, list) or not images:
        raise ValueError("production images build artifact has no images")
    normalized_images = []
    for image in images:
        if not isinstance(image, dict):
            raise ValueError(f"production image entry must be an object: {image!r}")
        service = str(image.get("service") or "")
        if not service:
            raise ValueError("production image entry is missing service")
        image_id = require_sha256(image.get("image_id"), f"{service} image_id")
        binary_digest = None
        launcher_binary_digest = None
        if service == "serverware-decision-gate":
            binary_digest = require_sha256(
                image.get("binary_digest"),
                "serverware-decision-gate production image binary digest",
            )
            launcher_binary_digest = require_sha256(
                image.get("launcher_binary_digest"),
                "serverware production launcher binary digest",
            )
        normalized_images.append(
            {
                "service": service,
                "dockerfile": image.get("dockerfile"),
                "image_id": image_id,
                "tag": image.get("tag"),
                **({"binary_digest": binary_digest} if binary_digest else {}),
                **(
                    {"launcher_binary_digest": launcher_binary_digest}
                    if launcher_binary_digest
                    else {}
                ),
            }
        )
    return {
        "path": str(path),
        "file": file_summary(path, "production-images-build"),
        "source_tree_digest": source_tree_digest,
        "current_source_tree_digest": current_source_tree_digest,
        "images": normalized_images,
        "no_shell": "pass",
    }


def verify_bench(path: Path) -> dict[str, Any]:
    bench = load_json(path, "decision gate benchmark")
    if bench.get("candidate") != "rust-decision-gate":
        raise ValueError("decision gate benchmark did not run the Rust candidate")
    binary_digest = require_sha256(bench.get("data_plane_binary_digest"), "decision gate benchmark binary digest")
    policy_hash = require_sha256(bench.get("policy_hash"), "decision gate benchmark policy hash")
    runtime_manifest_digest = require_sha256(
        bench.get("runtime_manifest_digest"),
        "decision gate benchmark runtime manifest digest",
    )
    nonce_before = bench.get("attestation_nonce_before")
    nonce_after = bench.get("attestation_nonce_after")
    if not isinstance(nonce_before, str) or not nonce_before or not isinstance(nonce_after, str) or not nonce_after:
        raise ValueError("decision gate benchmark is missing nonce-bound attestation evidence")
    if nonce_before == nonce_after:
        raise ValueError("decision gate benchmark must use distinct before/after attestation nonces")
    p99 = bench.get("p99_ms")
    if not isinstance(p99, int | float):
        raise ValueError("decision gate benchmark is missing numeric p99_ms")
    if float(p99) >= BENCH_P99_TARGET_MS:
        raise ValueError(f"decision gate p99_ms {p99} exceeds target {BENCH_P99_TARGET_MS}")
    return {
        "path": str(path),
        "file": file_summary(path, "decision-gate-bench"),
        "candidate": bench.get("candidate"),
        "requests": bench.get("requests"),
        "warmup": bench.get("warmup"),
        "p50_ms": bench.get("p50_ms"),
        "p95_ms": bench.get("p95_ms"),
        "p99_ms": p99,
        "data_plane_binary_digest": binary_digest,
        "policy_hash": policy_hash,
        "runtime_manifest_digest": runtime_manifest_digest,
        "attestation_nonce_bound": True,
        "target_p99_ms": BENCH_P99_TARGET_MS,
    }


def verify_summary(path: Path, *, label: str, pass_key: str, digest_key: str) -> dict[str, Any]:
    summary = load_json(path, label)
    if summary.get("ok") is not True or summary.get(pass_key) != "pass":
        raise ValueError(f"{label} did not pass")
    if summary.get("inclusion_verified") is not True:
        raise ValueError(f"{label} does not have verified transparency inclusion")
    return {
        "path": str(path),
        "file": file_summary(path, label),
        "digest": require_sha256(summary.get(digest_key), f"{label} digest"),
        "transparency_mode": summary.get("transparency_mode"),
    }


def verify_external_transparency_checkpoint(
    transparency: dict[str, Any],
    *,
    anchor_key: str,
    trust: dict[str, str],
    expected_checkpoint_sha256: str,
    label: str,
) -> dict[str, Any]:
    return completion.external_checkpoint_binding(
        transparency,
        anchor_key=anchor_key,
        expected_provider=trust["external_provider"],
        expected_log_id=trust["external_log_id"],
        trusted_public_key_pem=trust["external_public_key_pem"],
        expected_checkpoint_sha256=expected_checkpoint_sha256,
        label=label,
    )


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


def verify_release_provenance_document(
    document_path: Path,
    *,
    summary_digest: str,
    expected_source_tree_digest: str,
    expected_launcher_binary_digest: str,
    trust: dict[str, str],
) -> dict[str, Any]:
    document = load_json(document_path, "release provenance document")
    provenance = document.get("provenance")
    if not isinstance(provenance, dict):
        raise ValueError("release provenance document is missing provenance")
    document_digest = require_sha256(document.get("provenance_digest"), "release provenance document digest")
    if sha256_prefixed_json(provenance) != document_digest:
        raise ValueError("release provenance document payload digest mismatch")
    if summary_digest != document_digest:
        raise ValueError("release provenance summary digest does not match document digest")
    source_tree = provenance.get("source_tree") if isinstance(provenance.get("source_tree"), dict) else {}
    source_tree_digest = require_sha256(source_tree.get("digest"), "release provenance source tree digest")
    if provenance.get("source") != "serverware-digest-pinned-production-release":
        raise ValueError("release provenance was not generated in digest-pinned production mode")
    compose_config_sha256 = require_sha256(
        provenance.get("compose_config_sha256"),
        "release provenance compose config digest",
    )
    compose = provenance.get("compose") if isinstance(provenance.get("compose"), dict) else {}
    if compose.get("sha256") != compose_config_sha256:
        raise ValueError("release provenance Compose summary digest does not match its rendered config digest")
    if Path(str(compose.get("file") or "")).name != "docker-compose.production.yml":
        raise ValueError("release provenance did not bind docker-compose.production.yml")
    sbom = provenance.get("sbom") if isinstance(provenance.get("sbom"), dict) else {}
    cyclonedx = sbom.get("cyclonedx") if isinstance(sbom.get("cyclonedx"), dict) else {}
    sbom_components = cyclonedx.get("components")
    if not isinstance(sbom_components, int) or sbom_components <= 0:
        raise ValueError("release provenance CycloneDX SBOM component count is invalid")
    if source_tree_digest != expected_source_tree_digest:
        raise ValueError(
            "release provenance source tree digest does not match production image build: "
            f"provenance={source_tree_digest} production_images={expected_source_tree_digest}"
        )
    images = provenance.get("images") if isinstance(provenance.get("images"), dict) else {}
    decision_gate = (
        images.get("serverware-decision-gate")
        if isinstance(images.get("serverware-decision-gate"), dict)
        else {}
    )
    launcher_binary_digest = require_sha256(
        decision_gate.get("launcher_binary_digest"),
        "release provenance production launcher binary digest",
    )
    if launcher_binary_digest != expected_launcher_binary_digest:
        raise ValueError(
            "release provenance production launcher digest does not match the measured production build"
        )
    signature = document.get("signature")
    public_key_pem = document.get("release_signing_public_key_pem")
    if not isinstance(signature, str) or not signature or not isinstance(public_key_pem, str) or not public_key_pem:
        raise ValueError("release provenance document is missing signature metadata")
    release_signing_key_id = require_sha256(document.get("release_signing_key_id"), "release signing key id")
    if release_signing_key_id != trust["release_key_id"]:
        raise ValueError("release provenance signer does not match the independently trusted release key")
    if release_public_key_id(public_key_pem) != trust["release_key_id"]:
        raise ValueError("release provenance embedded signing key is not the independently trusted release key")
    verify_ed25519(
        trust["release_public_key_pem"],
        signature,
        canonical_json(provenance).encode("utf-8"),
        "release provenance",
    )
    transparency = document.get("transparency") if isinstance(document.get("transparency"), dict) else {}
    release_record = completion.transparency_record_binding(
        transparency,
        anchor_key="anchor_response",
        inclusion_key="inclusion_proof",
        expected_type="release.provenance.v1",
        expected_fields={
            "provenance_digest": document_digest,
            "signature": signature,
            "release_signing_key_id": release_signing_key_id,
            "production_launcher_binary_digest": launcher_binary_digest,
        },
        expected_external_provider=trust["external_provider"],
        expected_external_log_id=trust["external_log_id"],
        trusted_external_public_key_pem=trust["external_public_key_pem"],
        label="release provenance",
    )
    external_transparency = verify_external_transparency_checkpoint(
        transparency,
        anchor_key="anchor_response",
        trust=trust,
        expected_checkpoint_sha256=release_record["external_checkpoint"]["checkpoint_sha256"],
        label="release provenance",
    )
    return {
        **file_summary(document_path, "release-provenance"),
        "provenance_digest": document_digest,
        "source_tree_digest": source_tree_digest,
        "compose_config_sha256": compose_config_sha256,
        "sbom_cyclonedx_sha256": require_sha256(cyclonedx.get("sha256"), "release provenance CycloneDX SBOM digest"),
        "sbom_cyclonedx_components": sbom_components,
        "release_signing_key_id": release_signing_key_id,
        "production_launcher_binary_digest": launcher_binary_digest,
        "external_transparency": external_transparency,
        "transparency_record_digest": release_record["record_digest"],
    }


def image_signature_scope(
    document_path: Path,
    production_image_ids: list[str],
    *,
    summary_digest: str,
    expected_provenance_digest: str,
    expected_published_image_digests: list[str] | None = None,
    expected_published_image_refs: list[str] | None = None,
    expected_release_bindings: dict[str, Any] | None = None,
    trust: dict[str, str],
) -> dict[str, Any]:
    document = load_json(document_path, "image signatures document")
    document_digest = require_sha256(document.get("image_signature_bundle_digest"), "image signature document digest")
    if sha256_prefixed_json(normalized_image_signature_payload(document)) != document_digest:
        raise ValueError("image signature document payload digest mismatch")
    if summary_digest != document_digest:
        raise ValueError("image signature summary digest does not match document digest")
    metadata = document.get("metadata") if isinstance(document.get("metadata"), dict) else {}
    metadata_provenance_digest = metadata.get("provenanceDigest")
    if metadata_provenance_digest is not None and metadata_provenance_digest != expected_provenance_digest:
        raise ValueError(
            "image signature metadata provenance digest does not match release provenance: "
            f"image_signatures={metadata_provenance_digest} release_provenance={expected_provenance_digest}"
        )
    if metadata.get("signatureProvider") != "sigstore-command":
        raise ValueError("image signatures did not use sigstore-command")
    if metadata.get("sigstoreTransparencyRequired") is not True:
        raise ValueError("image signatures do not require Sigstore transparency")
    image_signing_key_id = require_sha256(metadata.get("imageSigningKeyId"), "image signature signing key id")
    if image_signing_key_id != trust["sigstore_key_id"]:
        raise ValueError("image signing key does not match the independently trusted Sigstore key")
    bundle_sigstore = document.get("bundle_signature") if isinstance(document.get("bundle_signature"), dict) else {}
    metadata_bundle_sigstore = metadata.get("bundleSigstore") if isinstance(metadata.get("bundleSigstore"), dict) else {}
    if not bundle_sigstore or metadata_bundle_sigstore != bundle_sigstore:
        raise ValueError("image signature metadata bundle Sigstore proof mismatch")
    if bundle_sigstore.get("ok") is not True:
        raise ValueError("image signature bundle Sigstore proof did not pass")
    if not bundle_sigstore.get("signature") or metadata.get("signature") != bundle_sigstore.get("signature"):
        raise ValueError("image signature bundle signature mismatch")
    if bundle_sigstore.get("statement_digest") != document_digest:
        raise ValueError("image signature bundle Sigstore statement digest mismatch")
    bundle_key_provider = bundle_sigstore.get("key_provider") if isinstance(bundle_sigstore.get("key_provider"), dict) else {}
    if bundle_key_provider.get("key_id") != image_signing_key_id:
        raise ValueError("image signature bundle Sigstore signing key mismatch")
    bundle_transparency = bundle_sigstore.get("transparency") if isinstance(bundle_sigstore.get("transparency"), dict) else {}
    bundle_rekor_log_id = require_sha256(bundle_transparency.get("log_id"), "image signature bundle transparency log id")
    if bundle_rekor_log_id != trust["rekor_log_id"]:
        raise ValueError("image signature bundle transparency log does not match the independently trusted Rekor log")
    transparency_log_ids = [bundle_rekor_log_id]
    if not bundle_transparency.get("inclusion_proof"):
        raise ValueError("image signature bundle has no transparency inclusion proof")
    completion.verify_sigstore_bundle_binding(
        bundle_sigstore,
        expected_statement=normalized_image_signature_payload(document),
        expected_statement_digest=document_digest,
        expected_signature=str(bundle_sigstore.get("signature")),
        trusted_signing_public_key_pem=trust["sigstore_public_key_pem"],
        expected_signing_key_id=trust["sigstore_key_id"],
        expected_rekor_log_id=trust["rekor_log_id"],
        trusted_rekor_public_key_pem=trust["rekor_public_key_pem"],
        label="image signature bundle",
    )
    if expected_release_bindings:
        expected_metadata = {
            "releaseSigningKeyId": expected_release_bindings["release_signing_key_id"],
            "sourceTreeDigest": expected_release_bindings["source_tree_digest"],
            "composeConfigSha256": expected_release_bindings["compose_config_sha256"],
            "sbomCyclonedxSha256": expected_release_bindings["sbom_cyclonedx_sha256"],
        }
        for key, expected in expected_metadata.items():
            if metadata.get(key) != expected:
                raise ValueError(f"image signature metadata {key} does not match release provenance")
    images = document.get("images")
    if not isinstance(images, list) or not images:
        raise ValueError("image signatures document has no images")
    signed_ids = []
    signed_refs = []
    signed_image_map: dict[str, str] = {}
    for item in images:
        if not isinstance(item, dict):
            raise ValueError("image signature entry must be an object")
        service = str(item.get("service") or "")
        if not service:
            raise ValueError("image signature entry is missing service")
        image_id = item.get("image_id")
        image_id = require_sha256(image_id, f"image {service} digest")
        signed_ids.append(image_id)
        signed_image_map[service] = image_id
        statement = item.get("statement") if isinstance(item.get("statement"), dict) else {}
        statement_digest = sha256_prefixed_json(statement)
        if item.get("statement_digest") != statement_digest:
            raise ValueError(f"image signature statement digest mismatch for {service}")
        sigstore = item.get("sigstore") if isinstance(item.get("sigstore"), dict) else {}
        if sigstore.get("ok") is not True:
            raise ValueError(f"image {service} Sigstore proof did not pass")
        if not sigstore.get("signature") or item.get("signature") != sigstore.get("signature"):
            raise ValueError(f"image {service} Sigstore signature mismatch")
        if sigstore.get("statement_digest") != statement_digest:
            raise ValueError(f"image {service} Sigstore statement digest mismatch")
        key_provider = sigstore.get("key_provider") if isinstance(sigstore.get("key_provider"), dict) else {}
        if key_provider.get("key_id") != image_signing_key_id:
            raise ValueError(f"image {service} Sigstore signing key mismatch")
        sigstore_transparency = sigstore.get("transparency") if isinstance(sigstore.get("transparency"), dict) else {}
        log_id = require_sha256(sigstore_transparency.get("log_id"), f"image {service} transparency log id")
        if log_id != trust["rekor_log_id"]:
            raise ValueError(f"image {service} transparency log does not match the independently trusted Rekor log")
        transparency_log_ids.append(log_id)
        if not sigstore_transparency.get("inclusion_proof"):
            raise ValueError(f"image {service} has no transparency inclusion proof")
        completion.verify_sigstore_bundle_binding(
            sigstore,
            expected_statement=statement,
            expected_statement_digest=statement_digest,
            expected_signature=str(sigstore.get("signature")),
            trusted_signing_public_key_pem=trust["sigstore_public_key_pem"],
            expected_signing_key_id=trust["sigstore_key_id"],
            expected_rekor_log_id=trust["rekor_log_id"],
            trusted_rekor_public_key_pem=trust["rekor_public_key_pem"],
            label=f"image {service}",
        )
        predicate = statement.get("predicate") if isinstance(statement.get("predicate"), dict) else {}
        if expected_release_bindings:
            expected_predicate = {
                "release_signing_key_id": expected_release_bindings["release_signing_key_id"],
                "source_tree_digest": expected_release_bindings["source_tree_digest"],
                "compose_config_sha256": expected_release_bindings["compose_config_sha256"],
                "sbom_cyclonedx_sha256": expected_release_bindings["sbom_cyclonedx_sha256"],
                "sbom_cyclonedx_components": expected_release_bindings["sbom_cyclonedx_components"],
            }
            if predicate.get("image_id") not in (None, image_id):
                raise ValueError(f"image signature statement image digest mismatch for {item.get('service')}")
            for key, expected in expected_predicate.items():
                if predicate.get(key) != expected:
                    raise ValueError(f"image signature statement {key} does not match release provenance for {item.get('service')}")
        for ref in predicate.get("repo_digests") or []:
            if isinstance(ref, str):
                signed_refs.append(ref)
    metadata_transparency = metadata.get("transparency") if isinstance(metadata.get("transparency"), dict) else {}
    image_record = completion.transparency_record_binding(
        metadata_transparency,
        anchor_key="anchorResponse",
        inclusion_key="inclusionProof",
        expected_type="release.image_signatures.v1",
        expected_fields={
            "provenance_digest": expected_provenance_digest,
            "image_signature_bundle_digest": document_digest,
            "image_signing_key_id": image_signing_key_id,
            "image_signature_provider": "sigstore-command",
            "release_signing_key_id": expected_release_bindings["release_signing_key_id"] if expected_release_bindings else metadata.get("releaseSigningKeyId"),
            "signature": metadata.get("signature"),
            "images": signed_image_map,
        },
        expected_external_provider=trust["external_provider"],
        expected_external_log_id=trust["external_log_id"],
        trusted_external_public_key_pem=trust["external_public_key_pem"],
        label="image signature bundle",
    )
    external_transparency = verify_external_transparency_checkpoint(
        metadata_transparency,
        anchor_key="anchorResponse",
        trust=trust,
        expected_checkpoint_sha256=image_record["external_checkpoint"]["checkpoint_sha256"],
        label="image signature bundle",
    )
    production_ids = sorted(production_image_ids)
    signed_ids_sorted = sorted(signed_ids)
    covers_local_production_ids = signed_ids_sorted == production_ids
    expected_published_ids = sorted(expected_published_image_digests or [])
    covers_published_production_images = signed_ids_sorted == expected_published_ids if expected_published_ids else None
    expected_published_refs = sorted(expected_published_image_refs or [])
    covers_published_production_image_refs = sorted(signed_refs) == expected_published_refs if expected_published_refs else None
    if covers_published_production_images is True:
        note = "signature bundle covers published production digest refs"
    elif expected_published_ids:
        note = "signature bundle must be regenerated with make sign-production-images after registry publish"
    elif covers_local_production_ids:
        note = "signature bundle covers current local production image IDs"
    else:
        note = "production digest refs must be signed after registry publish"
    return {
        "path": str(document_path),
        "file": file_summary(document_path, "image-signatures"),
        "image_signature_bundle_digest": document_digest,
        "provenance_digest": metadata_provenance_digest,
        "signed_image_ids": signed_ids_sorted,
        "signed_repo_digests": sorted(signed_refs),
        "image_signing_key_id": image_signing_key_id,
        "transparency_log_ids": sorted(set(transparency_log_ids)),
        "external_transparency": external_transparency,
        "transparency_record_digest": image_record["record_digest"],
        "covers_local_production_image_ids": covers_local_production_ids,
        "expected_published_image_digests": expected_published_ids,
        "expected_published_image_refs": expected_published_refs,
        "covers_published_production_images": covers_published_production_images,
        "covers_published_production_image_refs": covers_published_production_image_refs,
        "note": note,
    }


def production_images_env_status(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {
            "path": str(path),
            "status": "missing",
            "images": [],
            "image_digests": [],
            "secret_values_redacted": True,
        }
    try:
        raw = merge_production_images_env.load_images_fragment(path)
        images = merge_production_images_env.validate_production_images(raw)
    except Exception as exc:
        return {
            "path": str(path),
            "status": "invalid",
            "error": str(exc),
            "images": [],
            "image_digests": [],
            "secret_values_redacted": True,
        }
    return {
        "path": str(path),
        "status": "valid",
        "images": images,
        "image_digests": sorted(item["digest"] for item in images),
        "secret_values_redacted": True,
    }


def env_status(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {
            "path": str(path),
            "status": "missing",
            "env_keys": [],
            "secret_values_redacted": True,
        }
    try:
        loaded = run_production_readiness.load_env_file(path)
    except Exception as exc:
        return {
            "path": str(path),
            "status": "invalid",
            "error": str(exc),
            "env_keys": [],
            "secret_values_redacted": True,
        }
    return {
        "path": str(path),
        "status": "valid",
        "env_keys": sorted(loaded),
        "secret_values_redacted": True,
    }


def host_status() -> dict[str, Any]:
    system = platform.system()
    return {
        "system": system,
        "machine": platform.machine(),
        "linux": system == "Linux",
        "nitro_nsm_device": Path("/dev/nsm").exists(),
        "apparmor_sysfs": Path("/sys/module/apparmor").exists(),
    }


def production_commands(
    *,
    registry_prefix: str | None,
    tag: str,
    build: dict[str, Any],
    env_file: Path,
    kms_spec: Path,
    kms_out: Path,
) -> dict[str, Any]:
    source_tree_digest = str((build.get("metadata") or {}).get("source_tree_digest") or "")
    require_sha256(source_tree_digest, "production image source tree digest")
    release_root = f"/opt/serverware/releases/{source_tree_digest.replace(':', '-', 1)}"
    commands = [
        ["make", "build-production-images"],
        [
            "make",
            "decision-gate-bench-evidence",
            "DECISION_GATE_BENCH_FILE=.tmp/decision-gate-rs-bench.json",
        ],
    ]
    publish_plan: list[dict[str, Any]] = []
    if registry_prefix:
        publish_plan = publish_production_images.command_plan(build, registry_prefix=registry_prefix, tag=tag)
        commands.append(
            [
                "make",
                "publish-production-images",
                f"PRODUCTION_IMAGE_REGISTRY_PREFIX={registry_prefix}",
                f"PRODUCTION_IMAGE_TAG={tag}",
            ]
        )
    commands.extend(
        [
            [
                "make",
                "merge-production-images-env",
                "PRODUCTION_IMAGES_ENV_OUT=.tmp/production-images.env",
                f"PRODUCTION_READINESS_ENV={env_file}",
            ],
            ["make", "build-production-launcher"],
            [
                "make",
                "production-release-provenance",
                "RELEASE_PROVENANCE_SUMMARY_FILE=.tmp/release-provenance-summary.json",
                "RELEASE_PROVENANCE_FILE=.tmp/release-provenance.json",
                "PRODUCTION_IMAGES_ENV_OUT=.tmp/production-images.env",
                f"PRODUCTION_READINESS_ENV={env_file}",
            ],
            [
                "make",
                "sign-production-images",
                "PRODUCTION_IMAGES_ENV_OUT=.tmp/production-images.env",
                f"PRODUCTION_READINESS_ENV={env_file}",
                "IMAGE_SIGNATURES_SUMMARY_FILE=.tmp/image-signatures-summary.json",
                "IMAGE_SIGNATURES_FILE=.tmp/image-signatures.json",
            ],
            [
                "make",
                "prepare-aws-kms-materials",
                f"AWS_KMS_MATERIALS_SPEC={kms_spec}",
                f"AWS_KMS_MATERIALS_OUT={kms_out}",
            ],
            ["make", "deploy-production"],
            ["make", "install-production-launcher"],
            [
                "make",
                "generate-production-launch-manifest",
                f"PRODUCTION_RELEASE_ROOT={release_root}",
                f"PRODUCTION_SOURCE_TREE_DIGEST={source_tree_digest}",
            ],
            ["make", "run-production-readiness-final"],
        ]
    )
    one_shot = ["make", "production-release-proof"]
    if registry_prefix:
        one_shot.extend([f"PRODUCTION_IMAGE_REGISTRY_PREFIX={registry_prefix}", f"PRODUCTION_IMAGE_TAG={tag}"])
    one_shot.extend(
        [
            f"PRODUCTION_READINESS_ENV={env_file}",
            f"AWS_KMS_MATERIALS_SPEC={kms_spec}",
            f"AWS_KMS_MATERIALS_OUT={kms_out}",
            f"PRODUCTION_RELEASE_ROOT={release_root}",
            f"PRODUCTION_SOURCE_TREE_DIGEST={source_tree_digest}",
        ]
    )
    return {
        "registry_prefix": registry_prefix,
        "tag": tag,
        "one_shot_command": one_shot,
        "publish_plan": publish_plan,
        "commands": commands,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate a redacted production handoff manifest from local Serverware release evidence.")
    parser.add_argument("--production-images-build", default=".tmp/production-images-build.json")
    parser.add_argument("--release-provenance-summary", default=".tmp/release-provenance-summary.json")
    parser.add_argument("--release-provenance", default=".tmp/release-provenance.json")
    parser.add_argument("--image-signatures-summary", default=".tmp/image-signatures-summary.json")
    parser.add_argument("--image-signatures", default=".tmp/image-signatures.json")
    parser.add_argument("--bench", default=".tmp/decision-gate-rs-bench.json")
    parser.add_argument("--production-images-env", default=".tmp/production-images.env")
    parser.add_argument("--env-file", default="ops/production-readiness.env")
    parser.add_argument("--env-template", default="ops/production-readiness.env.example")
    parser.add_argument("--kms-materials-spec", default="ops/aws-kms-materials.spec.json")
    parser.add_argument("--kms-materials-out", default="/etc/serverware/kms-materials.json")
    parser.add_argument("--registry-prefix", default=os.getenv("PRODUCTION_IMAGE_REGISTRY_PREFIX", ""))
    parser.add_argument("--tag", default=os.getenv("PRODUCTION_IMAGE_TAG", "production-candidate"))
    parser.add_argument("--out", default=".tmp/production-handoff.json")
    parser.add_argument("--skip-current-tree-check", action="store_true")
    args = parser.parse_args()

    try:
        env_path = Path(args.env_file)
        configured = run_production_readiness.load_env_file(env_path)
        release_trust = release_trust_from_config(configured)
        env = env_status(env_path)
        build_path = Path(args.production_images_build)
        build_raw = load_json(build_path, "production images build artifact")
        production_images = verify_production_images_build(build_path, check_current_tree=not args.skip_current_tree_check)
        image_ids = [item["image_id"] for item in production_images["images"]]
        bench = verify_bench(Path(args.bench))
        production_gate_binary = next(
            (
                item.get("binary_digest")
                for item in production_images["images"]
                if item.get("service") == "serverware-decision-gate"
            ),
            None,
        )
        if production_gate_binary != bench["data_plane_binary_digest"]:
            raise ValueError("decision-gate benchmark binary digest does not match the production image binary")
        release_provenance = verify_summary(
            Path(args.release_provenance_summary),
            label="release provenance summary",
            pass_key="release_provenance",
            digest_key="provenance_digest",
        )
        production_launcher_binary_digest = next(
            (
                item.get("launcher_binary_digest")
                for item in production_images["images"]
                if item.get("service") == "serverware-decision-gate"
            ),
            None,
        )
        production_launcher_binary_digest = require_sha256(
            production_launcher_binary_digest,
            "production image launcher binary digest",
        )
        image_signatures_summary = verify_summary(
            Path(args.image_signatures_summary),
            label="image signatures summary",
            pass_key="image_signatures",
            digest_key="image_signature_bundle_digest",
        )
        release_provenance_document = verify_release_provenance_document(
            Path(args.release_provenance),
            summary_digest=release_provenance["digest"],
            expected_source_tree_digest=production_images["source_tree_digest"],
            expected_launcher_binary_digest=production_launcher_binary_digest,
            trust=release_trust,
        )
        published_images_env = production_images_env_status(Path(args.production_images_env))
        signatures = image_signature_scope(
            Path(args.image_signatures),
            image_ids,
            summary_digest=image_signatures_summary["digest"],
            expected_provenance_digest=release_provenance["digest"],
            expected_published_image_digests=published_images_env["image_digests"],
            expected_published_image_refs=[item["ref"] for item in published_images_env["images"]],
            expected_release_bindings=release_provenance_document,
            trust=release_trust,
        )
        host = host_status()
        registry_prefix = args.registry_prefix.strip() or None
        commands = production_commands(
            registry_prefix=registry_prefix,
            tag=args.tag,
            build=build_raw,
            env_file=Path(args.env_file),
            kms_spec=Path(args.kms_materials_spec),
            kms_out=Path(args.kms_materials_out),
        )
        remaining = []
        if not registry_prefix:
            remaining.append("set PRODUCTION_IMAGE_REGISTRY_PREFIX and publish digest-pinned production images")
        if env["status"] != "valid":
            remaining.append("create a non-placeholder ops/production-readiness.env on the production host")
        if not host["linux"] or not host["nitro_nsm_device"] or not host["apparmor_sysfs"]:
            remaining.append("run final readiness on a Linux Nitro host with /dev/nsm and AppArmor")
        if published_images_env["status"] != "valid":
            remaining.append("publish production images to create .tmp/production-images.env, then run make sign-production-images")
        elif signatures["covers_published_production_images"] is not True:
            remaining.append("run make sign-production-images with .tmp/production-images.env after registry publish")
        remaining.append(
            "install the immutable release tree and run make production-release-proof so systemd produces the final completion proof"
        )
        result = {
            "apiVersion": "serverware.productionHandoff/v1",
            "kind": "ProductionHandoff",
            "ok": True,
            "generated_at_unix": int(time.time()),
            "completion_state": "pending-production-host",
            "local_evidence": {
                "production_images": production_images,
                "bench": bench,
                "release_provenance": release_provenance,
                "release_provenance_document": release_provenance_document,
                "image_signatures_summary": image_signatures_summary,
                "image_signatures": signatures,
            },
            "production_images_env": published_images_env,
            "production_env": env,
            "env_template": file_summary(Path(args.env_template), "production-readiness-env-template"),
            "host": host,
            "production_commands": commands,
            "remaining": remaining,
            "secret_values_redacted": True,
        }
        output_path = Path(args.out)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(canonical_json(result))
    except Exception as exc:
        print(canonical_json({"ok": False, "error": str(exc)}), file=sys.stderr)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
