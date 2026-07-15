#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import errno
import fcntl
import hashlib
import hmac
import importlib
import io
import json
import math
import os
import platform
import re
import secrets
import stat
import subprocess
import sys
import tempfile
import tarfile
import time
import types
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

import build_production_images
import merge_production_images_env
import production_release_input_preflight
import run_production_readiness
import verify_production_policy_identity
from serverware.policy_bundle import PolicySnapshot, compile_policy_bundle


_MEASURED_PREFLIGHT_MODULE: types.ModuleType | None = None
_MEASURED_PREFLIGHT_MODULE_SHA256: str | None = None


def load_production_host_preflight_module(
    production_env: dict[str, str],
    *,
    final: bool,
    after_open: Any | None = None,
) -> types.ModuleType:
    global _MEASURED_PREFLIGHT_MODULE, _MEASURED_PREFLIGHT_MODULE_SHA256
    if not final:
        return importlib.import_module("production_host_preflight")
    setting = run_production_readiness.PRODUCTION_HOST_PREFLIGHT_SCRIPT_SHA256_ENV
    expected_digest = production_env.get(setting)
    if not isinstance(expected_digest, str) or run_production_readiness.SHA256_RE.fullmatch(
        expected_digest
    ) is None:
        raise ValueError(f"{setting} must be sha256:<64 lowercase hex>")
    if (
        _MEASURED_PREFLIGHT_MODULE is not None
        and _MEASURED_PREFLIGHT_MODULE_SHA256 == expected_digest
    ):
        return _MEASURED_PREFLIGHT_MODULE
    path = (Path(__file__).resolve().parent / "production_host_preflight.py").resolve()
    measured = run_production_readiness.open_measured_script(path, expected_digest, setting)
    try:
        if after_open is not None:
            after_open(measured)
        os.lseek(measured.fd, 0, os.SEEK_SET)
        data = run_production_readiness.read_fd_bytes(
            measured.fd,
            measured.metadata,
            "measured production host preflight module",
            max_bytes=run_production_readiness.MAX_EXECUTABLE_BYTES,
        )
        module_name = "_serverware_measured_production_host_preflight"
        module = types.ModuleType(module_name)
        module.__file__ = str(path)
        module.__package__ = None
        sys.modules[module_name] = module
        try:
            exec(compile(data, str(path), "exec"), module.__dict__, module.__dict__)
        except Exception:
            sys.modules.pop(module_name, None)
            raise
    finally:
        measured.close()
    _MEASURED_PREFLIGHT_MODULE = module
    _MEASURED_PREFLIGHT_MODULE_SHA256 = expected_digest
    return module


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
SHA384_RE = re.compile(r"^sha384:[0-9a-f]{96}$")
IMAGE_REF_RE = re.compile(r"^(?P<repo>[^@,\s]+)@(?P<digest>sha256:[0-9a-f]{64})$")
BASE64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")
PROXY_PROOF_MAX_AGE_LIMIT_SECONDS = 900
PROXY_PROOF_FUTURE_SKEW_SECONDS = 30
CONTROL_PLANE_AUTHORIZATION_RECEIPT_API_VERSION = "serverware.controlPlaneAuthorizationReceipt/v1"
CONTROL_PLANE_RESPONSE_SIGNATURE_API_VERSION = "serverware.responseSignature/v1"
CONTROL_PLANE_DISPATCH_PATH = "/api/data-plane/release-authorizations/dispatch"
HARDWARE_PROOF_API_VERSION = "serverware.hardwareAssurance/v1"
HARDWARE_PROOF_MAX_AGE_SECONDS = 900
HARDWARE_PROOF_FUTURE_SKEW_SECONDS = 30
EIF_BUILD_MANIFEST_API_VERSION = "serverware.eifBuildManifest/v1"
FINAL_CHALLENGE_LEDGER_API_VERSION = "serverware.finalChallengeLedger/v1"
FINAL_CHALLENGE_LEDGER_MAX_ENTRIES = 4096
FINAL_CHALLENGE_RECEIPT_API_VERSION = "serverware.finalChallengeReceipt/v1"
FINAL_CHALLENGE_RECEIPT_MAX_AGE_SECONDS = 900
FINAL_COMPLETION_IDENTITY_API_VERSION = "serverware.finalCompletionIdentity/v1"
FINAL_MODE_ENV_KEY = "SERVERWARE_COMPLETION_VERIFICATION_MODE"
FINAL_HARDWARE_ASSURANCE_ENV_KEY = "SERVERWARE_HARDWARE_ASSURANCE"
FINAL_HARDWARE_TRUST_ROOT_ENV_KEY = "SERVERWARE_HARDWARE_ASSURANCE_TRUSTED_PUBLIC_KEY"
FINAL_HARDWARE_TRUST_ROOT_ID_ENV_KEY = "SERVERWARE_HARDWARE_ASSURANCE_TRUSTED_PUBLIC_KEY_ID"
FINAL_HARDWARE_CHALLENGE_NONCE_ENV_KEY = "SERVERWARE_HARDWARE_ASSURANCE_EXPECTED_CHALLENGE_NONCE"
FINAL_HARDWARE_CHALLENGE_DIGEST_ENV_KEY = "SERVERWARE_HARDWARE_ASSURANCE_EXPECTED_CHALLENGE_NONCE_SHA256"
FINAL_CHALLENGE_RECEIPT_ENV_KEY = "SERVERWARE_FINAL_CHALLENGE_RECEIPT"
FINAL_CHALLENGE_AUTHORITY_TRUST_ROOT_ENV_KEY = "SERVERWARE_FINAL_CHALLENGE_AUTHORITY_PUBLIC_KEY"
FINAL_CHALLENGE_AUTHORITY_TRUST_ROOT_ID_ENV_KEY = "SERVERWARE_FINAL_CHALLENGE_AUTHORITY_PUBLIC_KEY_ID"
FINAL_CHALLENGE_AUTHORITY_PROVIDER_ENV_KEY = "SERVERWARE_FINAL_CHALLENGE_AUTHORITY_PROVIDER"
RELEASE_PROVENANCE_TRUST_ROOT_ENV_KEY = "SERVERWARE_RELEASE_PROVENANCE_TRUSTED_PUBLIC_KEY"
SIGSTORE_TRUST_ROOT_ENV_KEY = "SERVERWARE_SIGSTORE_TRUSTED_PUBLIC_KEY"
REKOR_TRUST_ROOT_ENV_KEY = "SERVERWARE_REKOR_TRUSTED_PUBLIC_KEY"
EXTERNAL_CHECKPOINT_TRUST_ROOT_ENV_KEY = "SERVERWARE_EXTERNAL_CHECKPOINT_TRUSTED_PUBLIC_KEY"
EXTERNAL_CHECKPOINT_PROVIDER_ENV_KEY = "SERVERWARE_EXTERNAL_CHECKPOINT_PROVIDER"
CONTROL_PLANE_RESPONSE_SIGNING_KEY_ENV_KEY = (
    "SERVERWARE_CONTROL_PLANE_RESPONSE_SIGNING_PUBLIC_KEY"
)
CONTROL_PLANE_RESPONSE_SIGNING_KEY_ID_ENV_KEY = (
    "SERVERWARE_CONTROL_PLANE_RESPONSE_SIGNING_PUBLIC_KEY_ID"
)
PROXY_PRINCIPAL_ENV_KEY = "SERVERWARE_PROXY_PROOF_PRINCIPAL_ID"
RELEASE_IDENTITY_FIELDS = {
    "source_tree_digest",
    "provenance_digest",
    "runtime_manifest_digest",
    "data_plane_binary_digest",
    "production_image_digests",
    "production_image_refs",
    "production_images_build_sha256",
    "production_images_published_sha256",
    "image_signature_bundle_digest",
}
CURRENT_HOST_IDENTITY_SCHEME = "serverware.currentCompletionHostIdentity/v1"
CURRENT_HOST_IDENTITY_MAX_OBSERVATION_AGE_SECONDS = 60
CURRENT_HOST_MACHINE_ID_PATH = Path("/etc/machine-id")
CURRENT_HOST_PRODUCT_UUID_PATH = Path("/sys/devices/virtual/dmi/id/product_uuid")
CURRENT_HOST_BOOT_ID_PATH = Path("/proc/sys/kernel/random/boot_id")
MACHINE_ID_RE = re.compile(r"^[0-9a-f]{32}$")
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
FINAL_HARDWARE_EVIDENCE = (
    "independently signed verifier statement",
    "fresh signed current-host identity commitment",
    "EIF image measurement and build-manifest evidence",
    "PCR0/PCR1/PCR2 measurements",
    "enclave CID and parent-CID evidence",
    "authenticated vsock handshake evidence",
    "KMS Recipient enclave key-custody evidence",
    "evidence that parent processes never held plaintext key material",
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
FINAL_EVIDENCE_MAX_BYTES = 4 * 1024 * 1024
FINAL_TRUST_ROOT_MAX_BYTES = 64 * 1024
POLICY_BUNDLE_MAX_BYTES = 8 * 1024 * 1024
COMPLETION_INPUT_MAX_BYTES = 64 * 1024 * 1024
ENV_INPUT_MAX_BYTES = 8 * 1024 * 1024
COMPOSE_INPUT_MAX_BYTES = 16 * 1024 * 1024
PROXY_EXPECTED_DIGEST_ENV_KEYS = {
    "proxy_client_request_digest": "SERVERWARE_PROXY_EXPECTED_CLIENT_REQUEST_DIGEST",
    "proxy_request_digest": "SERVERWARE_PROXY_EXPECTED_REQUEST_DIGEST",
    "proxy_operation_digest": "SERVERWARE_PROXY_EXPECTED_OPERATION_DIGEST",
}
PROXY_PROOF_MAX_AGE_ENV_KEY = "SERVERWARE_PROXY_PROOF_MAX_AGE_SECONDS"
COMPLETION_P99_LIMIT_ENV_KEY = "SERVERWARE_COMPLETION_P99_LIMIT_MS"
DOCKER_EXECUTABLE_ENV_KEY = run_production_readiness.PRODUCTION_DOCKER_EXECUTABLE_ENV
DOCKER_COMPOSE_PLUGIN_EXECUTABLE_ENV_KEY = (
    run_production_readiness.DOCKER_COMPOSE_PLUGIN_EXECUTABLE_ENV
)
DOCKER_COMPOSE_PLUGIN_SHA256_ENV_KEY = run_production_readiness.DOCKER_COMPOSE_PLUGIN_SHA256_ENV
DOCKER_UNIX_SOCKET_ENV_KEY = run_production_readiness.DOCKER_UNIX_SOCKET_ENV
DOCKER_DAEMON_ID_ENV_KEY = run_production_readiness.DOCKER_DAEMON_ID_ENV
PREFLIGHT_MAX_AGE_ENV_KEY = run_production_readiness.PRODUCTION_HOST_PREFLIGHT_MAX_AGE_ENV
PREFLIGHT_SIGNING_PUBLIC_KEY_ENV_KEY = (
    run_production_readiness.PRODUCTION_HOST_PREFLIGHT_SIGNING_PUBLIC_KEY_ENV
)
PREFLIGHT_SIGNING_KEY_ID_ENV_KEY = (
    run_production_readiness.PRODUCTION_HOST_PREFLIGHT_SIGNING_KEY_ID_ENV
)


@dataclass(frozen=True)
class FileSnapshot:
    path: Path
    data: bytes
    sha256: str
    metadata: os.stat_result


class InputSnapshots:
    def __init__(self) -> None:
        self.by_key: dict[str, FileSnapshot] = {}
        self._by_path: dict[str, FileSnapshot] = {}

    def capture(self, key: str, path: Path, label: str, *, max_bytes: int) -> FileSnapshot:
        absolute = os.path.abspath(os.fspath(path))
        snapshot = self._by_path.get(absolute)
        if snapshot is None:
            snapshot = snapshot_regular_file(path, label, max_bytes=max_bytes)
            self._by_path[absolute] = snapshot
        else:
            require(len(snapshot.data) <= max_bytes, f"{label} exceeds the {max_bytes}-byte size limit")
        self.by_key[key] = snapshot
        return snapshot

    def capture_many(
        self,
        paths: dict[str, Path],
        limits: dict[str, tuple[str, int]],
    ) -> dict[str, FileSnapshot]:
        grouped: dict[str, list[tuple[str, Path, str, int]]] = {}
        for key, path in paths.items():
            label, max_bytes = limits[key]
            grouped.setdefault(os.path.abspath(os.fspath(path)), []).append(
                (key, path, label, max_bytes)
            )
        for entries in grouped.values():
            strictest = min(entry[3] for entry in entries)
            snapshot = self.capture(entries[0][0], entries[0][1], entries[0][2], max_bytes=strictest)
            for key, _path, label, max_bytes in entries:
                require(len(snapshot.data) <= max_bytes, f"{label} exceeds the {max_bytes}-byte size limit")
                self.by_key[key] = snapshot
        return self.by_key


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


def decode_canonical_base64url(value: Any, label: str) -> bytes:
    require(
        isinstance(value, str) and bool(value) and BASE64URL_RE.fullmatch(value) is not None,
        f"{label} is not canonical unpadded base64url",
    )
    require(len(value) % 4 != 1, f"{label} is not canonical unpadded base64url")
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except Exception as exc:
        raise ValueError(f"{label} is not canonical unpadded base64url") from exc
    require(
        base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") == value,
        f"{label} is not canonical unpadded base64url",
    )
    return decoded


def b64d(value: str) -> bytes:
    return decode_canonical_base64url(value, "base64url value")


def decode_ed25519_signature(value: Any, label: str) -> bytes:
    require(isinstance(value, str) and bool(value), f"{label} is missing")
    encoded = value.split(":", 1)[1] if value.startswith("ed25519:") else value
    decoded = decode_canonical_base64url(encoded, label)
    require(len(decoded) == 64, f"{label} must decode to exactly 64 bytes")
    return decoded


def decode_signature(value: Any, label: str) -> bytes:
    require(isinstance(value, str) and value, f"{label} is missing")
    encoded = value.split(":", 1)[1] if value.startswith("ed25519:") else value
    try:
        return base64.b64decode(encoded + "=" * (-len(encoded) % 4), altchars=b"-_", validate=True)
    except Exception as exc:
        raise ValueError(f"{label} is invalid base64") from exc


def decode_sha256_value(value: Any, label: str) -> bytes:
    require(isinstance(value, str) and value, f"{label} is missing")
    candidate = value.split(":", 1)[1] if value.startswith("sha256:") else value
    if re.fullmatch(r"[0-9a-fA-F]{64}", candidate):
        return bytes.fromhex(candidate)
    try:
        decoded = base64.b64decode(candidate + "=" * (-len(candidate) % 4), altchars=b"-_", validate=True)
    except Exception as exc:
        raise ValueError(f"{label} is not a SHA-256 value") from exc
    require(len(decoded) == hashlib.sha256().digest_size, f"{label} is not 32 bytes")
    return decoded


def normalized_sha256_value(value: Any, label: str) -> str:
    return "sha256:" + decode_sha256_value(value, label).hex()


def verify_public_key_signature(public_key_pem: str, signature: str, payload: bytes, label: str) -> None:
    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode("ascii"))
        if isinstance(public_key, Ed25519PublicKey):
            signature_bytes = decode_ed25519_signature(signature, f"{label} signature")
            public_key.verify(signature_bytes, payload)
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            signature_bytes = decode_signature(signature, f"{label} signature")
            if isinstance(public_key.curve, ec.SECP256R1):
                digest_algorithm = hashes.SHA256()
            elif isinstance(public_key.curve, ec.SECP384R1):
                digest_algorithm = hashes.SHA384()
            elif isinstance(public_key.curve, ec.SECP521R1):
                digest_algorithm = hashes.SHA512()
            else:
                raise ValueError(f"{label} uses an unsupported elliptic curve")
            public_key.verify(signature_bytes, payload, ec.ECDSA(digest_algorithm))
        elif isinstance(public_key, rsa.RSAPublicKey):
            signature_bytes = decode_signature(signature, f"{label} signature")
            public_key.verify(signature_bytes, payload, padding.PKCS1v15(), hashes.SHA256())
        else:
            raise ValueError(f"{label} uses an unsupported public key type")
    except InvalidSignature as exc:
        raise ValueError(f"{label} signature verification failed") from exc
    except ValueError:
        raise
    except Exception as exc:
        raise ValueError(f"{label} signature verification failed") from exc


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
        require(isinstance(public_key, Ed25519PublicKey), f"{label} public key is not Ed25519")
        public_key.verify(
            decode_ed25519_signature(signature, f"{label} signature"),
            payload,
        )
    except ValueError:
        raise
    except Exception as exc:
        raise ValueError(f"{label} signature verification failed") from exc


def decode_base64(value: Any, label: str) -> bytes:
    require(isinstance(value, str) and value, f"{label} is missing")
    try:
        return base64.b64decode(value + "=" * (-len(value) % 4), validate=True)
    except Exception as exc:
        raise ValueError(f"{label} is invalid base64") from exc


def verify_external_checkpoint_receipt(
    checkpoint: dict[str, Any],
    *,
    expected_provider: str,
    expected_log_id: str,
    trusted_public_key_pem: str,
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
    trusted_log_id = release_public_key_id(trusted_public_key_pem)
    require(trusted_log_id == expected_log_id, f"{label} trusted external transparency key id mismatch")
    require(
        release_public_key_id(public_key_pem) == trusted_log_id,
        f"{label} external transparency receipt public key is not the independently trusted log key",
    )
    require(provider == expected_provider, f"{label} external transparency provider is not the trusted provider")
    require(log_id == expected_log_id, f"{label} external transparency log is not the trusted log")
    require(payload.get("provider") == provider, f"{label} external transparency receipt provider mismatch")
    require(payload.get("log_id") == log_id, f"{label} external transparency receipt log mismatch")
    for field, expected in expected_fields.items():
        require(payload.get(field) == expected, f"{label} external transparency receipt {field} mismatch")
    verify_ed25519(
        trusted_public_key_pem,
        signature,
        canonical_json(payload).encode("utf-8"),
        f"{label} external transparency receipt",
    )
    return {
        "provider": provider,
        "log_id": log_id,
        "external_sequence": checkpoint.get("external_sequence"),
        "checkpoint_sha256": sha256_prefixed_json(checkpoint),
        "receipt_payload_sha256": sha256_prefixed_json(payload),
    }


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


def snapshot_regular_file(path: Path, label: str, *, max_bytes: int) -> FileSnapshot:
    require(max_bytes > 0, f"{label} snapshot size limit is invalid")
    require(hasattr(os, "O_NOFOLLOW"), f"{label} cannot be opened safely on this platform")
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise ValueError(f"{label} must not be a symlink: {path}") from exc
        raise ValueError(f"{label} could not be opened without following symlinks: {path}") from exc
    try:
        opened_metadata = os.fstat(descriptor)
        require(stat.S_ISREG(opened_metadata.st_mode), f"{label} must be a regular file: {path}")
        require(opened_metadata.st_size <= max_bytes, f"{label} exceeds the {max_bytes}-byte size limit")
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        require(data, f"{label} must not be empty")
        require(len(data) <= max_bytes, f"{label} exceeds the {max_bytes}-byte size limit")
        completed_metadata = os.fstat(descriptor)
        require(
            (
                completed_metadata.st_dev,
                completed_metadata.st_ino,
                completed_metadata.st_size,
                completed_metadata.st_mtime_ns,
                completed_metadata.st_ctime_ns,
            )
            == (
                opened_metadata.st_dev,
                opened_metadata.st_ino,
                opened_metadata.st_size,
                opened_metadata.st_mtime_ns,
                opened_metadata.st_ctime_ns,
            )
            and len(data) == opened_metadata.st_size,
            f"{label} changed while its byte snapshot was being captured",
        )
    finally:
        os.close(descriptor)
    return FileSnapshot(
        path=path,
        data=data,
        sha256=sha256_prefixed_bytes(data),
        metadata=opened_metadata,
    )


def snapshot_text(snapshot: FileSnapshot, label: str, *, encoding: str) -> str:
    try:
        return snapshot.data.decode(encoding)
    except UnicodeDecodeError as exc:
        raise ValueError(f"{label} is not valid {encoding} text: {snapshot.path}") from exc


def snapshot_final_verification_files(
    paths: dict[str, Path],
    *,
    include_hardware_assurance: bool,
    include_final_receipt: bool,
    include_proxy_security: bool = False,
    include_policy: bool = False,
) -> dict[str, FileSnapshot]:
    requested: list[tuple[str, str, int]] = []
    if include_proxy_security:
        requested.extend(
            [
                (
                    "proxy_response_proof",
                    "production proxy response proof",
                    FINAL_EVIDENCE_MAX_BYTES,
                ),
                (
                    "proxy_collector_public_key",
                    "proxy response collector trust root",
                    FINAL_TRUST_ROOT_MAX_BYTES,
                ),
                (
                    "proxy_proof_verifier_public_key",
                    "proxy proof vendor verifier trust root",
                    FINAL_TRUST_ROOT_MAX_BYTES,
                ),
                (
                    "control_plane_response_signing_public_key",
                    "control-plane response signing trust root",
                    FINAL_TRUST_ROOT_MAX_BYTES,
                ),
            ]
        )
    if include_policy:
        requested.extend(
            [
                ("policy_bundle", "signed production policy bundle", POLICY_BUNDLE_MAX_BYTES),
                (
                    "policy_trusted_public_key",
                    "production policy signing trust root",
                    FINAL_TRUST_ROOT_MAX_BYTES,
                ),
            ]
        )
    if include_hardware_assurance:
        requested.extend(
            [
                ("hardware_assurance", "hardware assurance", FINAL_EVIDENCE_MAX_BYTES),
                (
                    "hardware_assurance_trusted_public_key",
                    "hardware assurance trust root",
                    FINAL_TRUST_ROOT_MAX_BYTES,
                ),
            ]
        )
    if include_final_receipt:
        requested.extend(
            [
                ("final_challenge_receipt", "final challenge receipt", FINAL_EVIDENCE_MAX_BYTES),
                (
                    "final_challenge_authority_public_key",
                    "final challenge authority trust root",
                    FINAL_TRUST_ROOT_MAX_BYTES,
                ),
            ]
        )
    grouped: dict[str, list[tuple[str, str, int, Path]]] = {}
    for key, label, max_bytes in requested:
        path = paths[key]
        grouped.setdefault(os.path.abspath(os.fspath(path)), []).append(
            (key, label, max_bytes, path)
        )
    snapshots: dict[str, FileSnapshot] = {}
    for entries in grouped.values():
        strictest_limit = min(entry[2] for entry in entries)
        snapshot = snapshot_regular_file(
            entries[0][3],
            entries[0][1],
            max_bytes=strictest_limit,
        )
        for key, _label, _max_bytes, _path in entries:
            snapshots[key] = snapshot
    return snapshots


def load_json_bytes(data: bytes, path: Path, label: str) -> dict[str, Any]:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"{label} artifact is not valid UTF-8: {path}") from exc
    parsed = json.loads(text, object_pairs_hook=reject_duplicate_json_object_keys)
    if not isinstance(parsed, dict):
        raise ValueError(f"{label} artifact must be a JSON object: {path}")
    return parsed


def load_json_snapshot(snapshot: FileSnapshot, label: str) -> dict[str, Any]:
    return load_json_bytes(snapshot.data, snapshot.path, label)


def load_production_env_snapshot(snapshot: FileSnapshot) -> dict[str, str]:
    text = snapshot_text(snapshot, "production readiness env", encoding="utf-8")
    loaded: dict[str, str] = {}
    for lineno, raw in enumerate(text.splitlines(), start=1):
        parsed = run_production_readiness.parse_env_assignment(raw, lineno)
        if parsed is None:
            continue
        key, value = parsed
        require(key not in loaded, f"production readiness env line {lineno} duplicates {key}")
        require(
            run_production_readiness.PLACEHOLDER_RE.search(value) is None,
            f"production readiness env line {lineno} contains a placeholder value",
        )
        require(
            run_production_readiness.EXAMPLE_DOMAIN_RE.search(value) is None,
            f"production readiness env line {lineno} contains an example placeholder domain",
        )
        loaded[key] = value
    require(bool(loaded), "production readiness env is empty")
    return loaded


def load_images_env_snapshot(snapshot: FileSnapshot) -> tuple[str, list[dict[str, str]]]:
    text = snapshot_text(snapshot, "production images env", encoding="utf-8")
    loaded: dict[str, str] = {}
    for lineno, raw in enumerate(text.splitlines(), start=1):
        parsed = run_production_readiness.parse_env_assignment(raw, lineno)
        if parsed is None:
            continue
        key, value = parsed
        require(key not in loaded, f"production images env line {lineno} duplicates {key}")
        loaded[key] = value
    require(
        sorted(loaded) == [merge_production_images_env.KEY],
        f"production images env must contain only {merge_production_images_env.KEY}",
    )
    value = loaded[merge_production_images_env.KEY]
    return value, merge_production_images_env.validate_production_images(value)


def materialize_snapshots(
    snapshots: dict[str, FileSnapshot],
    keys: tuple[str, ...],
) -> tuple[tempfile.TemporaryDirectory[str], dict[str, Path]]:
    temporary = tempfile.TemporaryDirectory(prefix="serverware-completion-inputs-")
    directory = Path(temporary.name)
    os.chmod(directory, 0o700)
    paths: dict[str, Path] = {}
    for index, key in enumerate(keys):
        destination = directory / f"{index:02d}-{key}"
        descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(descriptor, "wb", closefd=False) as handle:
                handle.write(snapshots[key].data)
                handle.flush()
                os.fsync(handle.fileno())
        finally:
            os.close(descriptor)
        paths[key] = destination
    return temporary, paths


def semantic_result_digest(document: dict[str, Any]) -> str:
    payload = dict(document)
    payload.pop("result_path", None)
    payload.pop("result_sha256", None)
    return sha256_prefixed_json(payload)


def kms_ciphertext_blob(
    config: dict[str, Any],
    material: str,
    snapshots: InputSnapshots,
) -> bytes:
    path = config.get("ciphertext_blob_path") or config.get("ciphertextBlobPath")
    if isinstance(path, str) and path:
        snapshot = snapshots.capture(
            f"kms_ciphertext_{material}",
            Path(path),
            f"current KMS material {material} ciphertext blob",
            max_bytes=COMPLETION_INPUT_MAX_BYTES,
        )
        return snapshot.data
    raw = config.get("ciphertext_blob_b64") or config.get("ciphertextBlobB64")
    require(isinstance(raw, str) and raw, f"current KMS material {material} is missing ciphertext blob")
    try:
        return base64.b64decode(raw + "=" * (-len(raw) % 4), validate=True)
    except Exception as exc:
        raise ValueError(f"current KMS material {material} ciphertext blob is invalid base64") from exc


def current_kms_material_bindings(
    snapshot: FileSnapshot,
    snapshots: InputSnapshots,
) -> dict[str, dict[str, str]]:
    parsed = load_json_snapshot(snapshot, "current KMS materials")
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
            "ciphertext_blob_sha256": sha256_prefixed_bytes(
                kms_ciphertext_blob(config, material, snapshots)
            ),
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


def parse_nonnegative_int64(value: Any, label: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{label} is invalid")
    if isinstance(value, int):
        parsed = value
    elif isinstance(value, str) and re.fullmatch(r"0|[1-9][0-9]*", value):
        parsed = int(value)
    else:
        raise ValueError(f"{label} is invalid")
    require(0 <= parsed <= 2**63 - 1, f"{label} is outside int64 range")
    return parsed


def verify_sigstore_checkpoint(
    *,
    proof: dict[str, Any],
    expected_tree_size: int,
    expected_root_hash: bytes,
    trusted_rekor_public_key_pem: str,
    label: str,
) -> None:
    checkpoint = proof.get("checkpoint") if isinstance(proof.get("checkpoint"), dict) else {}
    envelope = checkpoint.get("envelope")
    require(isinstance(envelope, str) and envelope, f"{label} Sigstore checkpoint envelope is missing")
    try:
        signed_text, signature_block = envelope.split("\n\n", 1)
    except ValueError as exc:
        raise ValueError(f"{label} Sigstore checkpoint envelope is malformed") from exc
    checkpoint_lines = signed_text.splitlines()
    require(len(checkpoint_lines) == 3, f"{label} Sigstore checkpoint body is malformed")
    origin, tree_size_value, root_hash_value = checkpoint_lines
    checkpoint_tree_size = parse_nonnegative_int64(tree_size_value, f"{label} checkpoint tree size")
    checkpoint_root_hash = decode_sha256_value(root_hash_value, f"{label} checkpoint root hash")
    require(checkpoint_tree_size == expected_tree_size, f"{label} checkpoint tree size mismatch")
    require(checkpoint_root_hash == expected_root_hash, f"{label} checkpoint root hash mismatch")
    signature_lines = [line for line in signature_block.splitlines() if line]
    require(len(signature_lines) == 1, f"{label} Sigstore checkpoint signature block is invalid")
    prefix = "\u2014 "
    require(signature_lines[0].startswith(prefix), f"{label} Sigstore checkpoint signature marker is invalid")
    try:
        signer_name, encoded_signature = signature_lines[0][len(prefix) :].rsplit(" ", 1)
    except ValueError as exc:
        raise ValueError(f"{label} Sigstore checkpoint signature line is malformed") from exc
    require(origin.startswith(signer_name + " "), f"{label} Sigstore checkpoint signer name mismatch")
    signature_with_key_hint = decode_signature(encoded_signature, f"{label} checkpoint note signature")
    require(
        len(signature_with_key_hint) > 4,
        f"{label} Sigstore checkpoint note signature is too short",
    )
    verify_public_key_signature(
        trusted_rekor_public_key_pem,
        base64.b64encode(signature_with_key_hint[4:]).decode("ascii"),
        (signed_text + "\n").encode("utf-8"),
        f"{label} Sigstore checkpoint",
    )


def verify_sigstore_merkle_inclusion(
    *,
    leaf_hash: bytes,
    proof: dict[str, Any],
    label: str,
) -> None:
    tree_size_value = proof.get("treeSize") if proof.get("treeSize") is not None else proof.get("tree_size")
    log_index_value = proof.get("logIndex") if proof.get("logIndex") is not None else proof.get("log_index")
    root_hash = proof.get("rootHash") if proof.get("rootHash") is not None else proof.get("root_hash")
    hashes = proof.get("hashes")
    tree_size = parse_nonnegative_int64(tree_size_value, f"{label} Sigstore inclusion tree size")
    log_index = parse_nonnegative_int64(log_index_value, f"{label} Sigstore inclusion log index")
    require(tree_size >= 1, f"{label} Sigstore inclusion tree size is invalid")
    require(
        0 <= log_index < tree_size,
        f"{label} Sigstore inclusion log index is invalid",
    )
    root = decode_sha256_value(root_hash, f"{label} Sigstore inclusion root")
    require(isinstance(hashes, list), f"{label} Sigstore inclusion hashes must be a list")
    cursor = leaf_hash
    index = log_index
    last = tree_size - 1
    for position, sibling_value in enumerate(hashes):
        require(last != 0, f"{label} Sigstore inclusion proof has extra hashes")
        sibling = decode_sha256_value(sibling_value, f"{label} Sigstore inclusion hash {position}")
        if index & 1 or index == last:
            cursor = hashlib.sha256(b"\x01" + sibling + cursor).digest()
            while index and not index & 1:
                index >>= 1
                last >>= 1
        else:
            cursor = hashlib.sha256(b"\x01" + cursor + sibling).digest()
        index >>= 1
        last >>= 1
    require(last == 0 and cursor == root, f"{label} Sigstore Merkle inclusion proof did not verify")


def verify_sigstore_bundle_binding(
    sigstore: dict[str, Any],
    *,
    expected_statement: dict[str, Any],
    expected_statement_digest: str,
    expected_signature: str,
    trusted_signing_public_key_pem: str,
    expected_signing_key_id: str,
    expected_rekor_log_id: str,
    trusted_rekor_public_key_pem: str,
    label: str,
) -> None:
    trusted_signing_key_id = release_public_key_id(trusted_signing_public_key_pem)
    trusted_rekor_log_id = release_public_key_id(trusted_rekor_public_key_pem)
    require(
        trusted_signing_key_id == expected_signing_key_id,
        f"{label} independently trusted Sigstore key id mismatch",
    )
    require(
        trusted_rekor_log_id == expected_rekor_log_id,
        f"{label} independently trusted Rekor key id mismatch",
    )
    require(
        sha256_prefixed_json(expected_statement) == expected_statement_digest,
        f"{label} expected statement digest mismatch",
    )
    signing_public_key = serialization.load_pem_public_key(
        trusted_signing_public_key_pem.encode("ascii")
    )
    require(
        not isinstance(signing_public_key, Ed25519PublicKey),
        f"{label} transparent Ed25519/Ed25519ph signatures are not supported by this verifier",
    )
    statement_bytes = canonical_json(expected_statement).encode("utf-8")
    bundle = sigstore.get("bundle") if isinstance(sigstore.get("bundle"), dict) else {}
    require(bundle, f"{label} Sigstore proof is missing bundle")
    message_signature = bundle.get("messageSignature") if isinstance(bundle.get("messageSignature"), dict) else {}
    if not message_signature:
        message_signature = bundle.get("message_signature") if isinstance(bundle.get("message_signature"), dict) else {}
    require(message_signature, f"{label} Sigstore bundle is missing message signature")
    message_digest = message_signature.get("messageDigest") if isinstance(message_signature.get("messageDigest"), dict) else {}
    if not message_digest:
        message_digest = message_signature.get("message_digest") if isinstance(message_signature.get("message_digest"), dict) else {}
    digest_algorithm = str(message_digest.get("algorithm", "")).lower().replace("-", "_")
    require(digest_algorithm in {"sha256", "sha2_256"}, f"{label} Sigstore bundle digest algorithm mismatch")
    require(
        decode_sha256_value(message_digest.get("digest"), f"{label} Sigstore bundle digest")
        == hash_to_bytes(expected_statement_digest),
        f"{label} Sigstore bundle digest mismatch",
    )
    require(message_signature.get("signature") == expected_signature, f"{label} Sigstore bundle signature mismatch")
    verify_public_key_signature(
        trusted_signing_public_key_pem,
        expected_signature,
        statement_bytes,
        f"{label} Sigstore message",
    )

    verification_material = (
        bundle.get("verificationMaterial")
        if isinstance(bundle.get("verificationMaterial"), dict)
        else bundle.get("verification_material")
        if isinstance(bundle.get("verification_material"), dict)
        else {}
    )
    public_key = verification_material.get("publicKey") if isinstance(verification_material.get("publicKey"), dict) else {}
    if not public_key:
        public_key = verification_material.get("public_key") if isinstance(verification_material.get("public_key"), dict) else {}
    public_key_hint = public_key.get("hint")
    require(
        normalized_sha256_value(public_key_hint, f"{label} Sigstore bundle public-key hint")
        == expected_signing_key_id,
        f"{label} Sigstore bundle public-key hint mismatch",
    )

    transparency = sigstore.get("transparency") if isinstance(sigstore.get("transparency"), dict) else {}
    entries = sigstore_tlog_entries(bundle)
    require(entries, f"{label} Sigstore bundle is missing transparency log entry")
    entry = entries[0]
    entry_log_id = sigstore_log_id(entry)
    normalized_entry_log_id = normalized_sha256_value(entry_log_id, f"{label} Sigstore bundle Rekor log id")
    require(normalized_entry_log_id == expected_rekor_log_id, f"{label} Sigstore bundle Rekor log mismatch")
    require(
        normalized_entry_log_id
        == normalized_sha256_value(transparency.get("log_id"), f"{label} top-level Rekor log id"),
        f"{label} Sigstore bundle/top-level log mismatch",
    )
    require(
        isinstance(transparency.get("entry_uuid"), str) and transparency.get("entry_uuid"),
        f"{label} top-level transparency entry correlation id is missing",
    )
    for top_key, entry_keys in (
        ("integrated_time", ("integrated_time", "integratedTime")),
        ("log_index", ("log_index", "logIndex")),
    ):
        top_value = parse_nonnegative_int64(transparency.get(top_key), f"{label} top-level {top_key}")
        entry_raw = next((entry.get(key) for key in entry_keys if entry.get(key) is not None), None)
        entry_value = parse_nonnegative_int64(entry_raw, f"{label} bundle {top_key}")
        require(entry_value == top_value, f"{label} Sigstore bundle/top-level {top_key} mismatch")
    entry_inclusion = entry.get("inclusion_proof") or entry.get("inclusionProof")
    require(entry_inclusion == transparency.get("inclusion_proof"), f"{label} Sigstore bundle/top-level inclusion proof mismatch")
    require(isinstance(entry_inclusion, dict), f"{label} Sigstore bundle inclusion proof is missing")

    canonicalized_body_value = entry.get("canonicalizedBody") or entry.get("canonicalized_body")
    canonicalized_body = decode_base64(canonicalized_body_value, f"{label} Sigstore canonicalized body")
    try:
        body = json.loads(canonicalized_body, object_pairs_hook=reject_duplicate_json_object_keys)
    except Exception as exc:
        raise ValueError(f"{label} Sigstore canonicalized body is invalid JSON") from exc
    require(isinstance(body, dict), f"{label} Sigstore canonicalized body must be an object")
    spec = body.get("spec") if isinstance(body.get("spec"), dict) else {}
    data = spec.get("data") if isinstance(spec.get("data"), dict) else {}
    body_hash = data.get("hash") if isinstance(data.get("hash"), dict) else {}
    body_signature = spec.get("signature") if isinstance(spec.get("signature"), dict) else {}
    require(str(body_hash.get("algorithm", "")).lower() == "sha256", f"{label} Rekor body digest algorithm mismatch")
    require(
        body_hash.get("value") == expected_statement_digest.split(":", 1)[1],
        f"{label} Rekor body statement digest mismatch",
    )
    require(body_signature.get("content") == expected_signature, f"{label} Rekor body signature mismatch")
    body_public_key = body_signature.get("publicKey") if isinstance(body_signature.get("publicKey"), dict) else {}
    encoded_body_public_key = body_public_key.get("content")
    decoded_body_public_key = decode_base64(encoded_body_public_key, f"{label} Rekor body public key")
    try:
        body_public_key_pem = decoded_body_public_key.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError(f"{label} Rekor body public key is not ASCII PEM") from exc
    require(
        release_public_key_id(body_public_key_pem) == expected_signing_key_id,
        f"{label} Rekor body key is not the independently trusted Sigstore key",
    )

    integrated_time = parse_nonnegative_int64(
        entry.get("integratedTime") if entry.get("integratedTime") is not None else entry.get("integrated_time"),
        f"{label} Rekor integrated time",
    )
    log_index = parse_nonnegative_int64(
        entry.get("logIndex") if entry.get("logIndex") is not None else entry.get("log_index"),
        f"{label} Rekor log index",
    )
    inclusion_promise = entry.get("inclusionPromise") if isinstance(entry.get("inclusionPromise"), dict) else {}
    if not inclusion_promise:
        inclusion_promise = entry.get("inclusion_promise") if isinstance(entry.get("inclusion_promise"), dict) else {}
    signed_entry_timestamp = inclusion_promise.get("signedEntryTimestamp") or inclusion_promise.get(
        "signed_entry_timestamp"
    )
    set_payload = {
        "body": canonicalized_body_value,
        "integratedTime": integrated_time,
        "logID": decode_sha256_value(entry_log_id, f"{label} Rekor log id").hex(),
        "logIndex": log_index,
    }
    require(isinstance(signed_entry_timestamp, str) and signed_entry_timestamp, f"{label} Rekor signed entry timestamp is missing")
    verify_public_key_signature(
        trusted_rekor_public_key_pem,
        signed_entry_timestamp,
        canonical_json(set_payload).encode("utf-8"),
        f"{label} Rekor signed entry timestamp",
    )
    verify_sigstore_merkle_inclusion(
        leaf_hash=hashlib.sha256(b"\x00" + canonicalized_body).digest(),
        proof=entry_inclusion,
        label=label,
    )
    proof_tree_size = parse_nonnegative_int64(
        entry_inclusion.get("treeSize")
        if entry_inclusion.get("treeSize") is not None
        else entry_inclusion.get("tree_size"),
        f"{label} Sigstore checkpoint tree size",
    )
    proof_root_hash = decode_sha256_value(
        entry_inclusion.get("rootHash")
        if entry_inclusion.get("rootHash") is not None
        else entry_inclusion.get("root_hash"),
        f"{label} Sigstore checkpoint root hash",
    )
    verify_sigstore_checkpoint(
        proof=entry_inclusion,
        expected_tree_size=proof_tree_size,
        expected_root_hash=proof_root_hash,
        trusted_rekor_public_key_pem=trusted_rekor_public_key_pem,
        label=label,
    )


def assert_no_secret_fields(value: Any, path: str = "$") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if str(key).lower() in SECRET_FIELD_NAMES:
                raise ValueError(f"completion artifact contains secret-like field {path}.{key}")
            assert_no_secret_fields(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            assert_no_secret_fields(child, f"{path}[{index}]")


def require_exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    missing = sorted(expected - set(value))
    unexpected = sorted(set(value) - expected)
    require(not missing, f"{label} is missing required fields: {missing}")
    require(not unexpected, f"{label} contains unexpected fields: {unexpected}")


def require_sha384(value: Any, label: str) -> str:
    require(isinstance(value, str) and SHA384_RE.fullmatch(value) is not None, f"{label} must be sha384-prefixed")
    return value


def validate_release_identity(value: Any, label: str) -> dict[str, Any]:
    require(isinstance(value, dict), f"{label} must be an object")
    require_exact_keys(value, RELEASE_IDENTITY_FIELDS, label)
    normalized = {
        "source_tree_digest": require_sha256(value.get("source_tree_digest"), f"{label} source tree digest"),
        "provenance_digest": require_sha256(value.get("provenance_digest"), f"{label} provenance digest"),
        "runtime_manifest_digest": require_sha256(
            value.get("runtime_manifest_digest"),
            f"{label} runtime manifest digest",
        ),
        "data_plane_binary_digest": require_sha256(
            value.get("data_plane_binary_digest"),
            f"{label} data-plane binary digest",
        ),
        "production_images_build_sha256": require_sha256(
            value.get("production_images_build_sha256"),
            f"{label} production image build artifact digest",
        ),
        "production_images_published_sha256": require_sha256(
            value.get("production_images_published_sha256"),
            f"{label} published image artifact digest",
        ),
        "image_signature_bundle_digest": require_sha256(
            value.get("image_signature_bundle_digest"),
            f"{label} image signature bundle digest",
        ),
    }
    image_digests = value.get("production_image_digests")
    image_refs = value.get("production_image_refs")
    require(isinstance(image_digests, list) and image_digests, f"{label} production image digests are missing")
    require(isinstance(image_refs, list) and image_refs, f"{label} production image refs are missing")
    normalized["production_image_digests"] = sorted(
        require_sha256(item, f"{label} production image digest") for item in image_digests
    )
    normalized["production_image_refs"] = sorted(
        require_image_ref(item, f"{label} production image ref")[0] for item in image_refs
    )
    require(
        len(set(normalized["production_image_digests"])) == len(normalized["production_image_digests"]),
        f"{label} contains duplicate production image digests",
    )
    require(
        len(set(normalized["production_image_refs"])) == len(normalized["production_image_refs"]),
        f"{label} contains duplicate production image refs",
    )
    return normalized


def current_host_identity_from_values(*, machine_id: str, product_uuid: str, boot_id: str) -> dict[str, str]:
    normalized_machine_id = machine_id.strip().lower()
    normalized_product_uuid = product_uuid.strip().lower()
    normalized_boot_id = boot_id.strip().lower()
    require(
        MACHINE_ID_RE.fullmatch(normalized_machine_id) is not None and set(normalized_machine_id) != {"0"},
        "current completion host machine id is invalid",
    )
    require(
        UUID_RE.fullmatch(normalized_product_uuid) is not None and set(normalized_product_uuid.replace("-", "")) != {"0"},
        "current completion host product UUID is invalid",
    )
    require(
        UUID_RE.fullmatch(normalized_boot_id) is not None and set(normalized_boot_id.replace("-", "")) != {"0"},
        "current completion host boot id is invalid",
    )

    def component_digest(label: str, value: str) -> str:
        return sha256_prefixed_bytes(
            f"{CURRENT_HOST_IDENTITY_SCHEME}:{label}\0{value}".encode("ascii")
        )

    identity = {
        "scheme": CURRENT_HOST_IDENTITY_SCHEME,
        "machine_id_sha256": component_digest("machine-id", normalized_machine_id),
        "product_uuid_sha256": component_digest("product-uuid", normalized_product_uuid),
        "boot_id_sha256": component_digest("boot-id", normalized_boot_id),
    }
    return {**identity, "identity_sha256": sha256_prefixed_json(identity)}


def read_current_host_identity() -> dict[str, str]:
    values: dict[str, str] = {}
    for key, path in (
        ("machine_id", CURRENT_HOST_MACHINE_ID_PATH),
        ("product_uuid", CURRENT_HOST_PRODUCT_UUID_PATH),
        ("boot_id", CURRENT_HOST_BOOT_ID_PATH),
    ):
        try:
            values[key] = path.read_text(encoding="ascii").strip()
        except OSError as exc:
            raise ValueError(f"current completion host identity source is unavailable: {path}") from exc
    return current_host_identity_from_values(**values)


def current_host_identity_claim(identity: dict[str, str], *, observed_at_unix: int) -> dict[str, Any]:
    require_exact_keys(
        identity,
        {"scheme", "machine_id_sha256", "product_uuid_sha256", "boot_id_sha256", "identity_sha256"},
        "current completion host identity",
    )
    payload: dict[str, Any] = {**identity, "observed_at_unix": observed_at_unix}
    return {**payload, "commitment_sha256": sha256_prefixed_json(payload)}


def verify_hardware_assurance(
    document: dict[str, Any],
    *,
    trusted_public_key_pem: str,
    expected_trusted_public_key_id: str | None,
    hardware_assurance_document_sha256: str,
    nitro_summary: dict[str, Any],
    nitro_evidence_sha256: str,
    production_host_preflight_sha256: str,
    current_host: dict[str, Any],
    expected_release_identity: dict[str, Any],
    expected_challenge_nonce: str | None = None,
    expected_challenge_nonce_sha256: str | None = None,
    now_unix: int | None = None,
) -> dict[str, Any]:
    assert_no_secret_fields(document)
    verified_expected_release_identity = validate_release_identity(
        expected_release_identity,
        "independently verified release identity",
    )
    require_exact_keys(
        document,
        {"apiVersion", "kind", "statement", "signing_key_id", "signature"},
        "hardware assurance document",
    )
    require(document.get("apiVersion") == HARDWARE_PROOF_API_VERSION, "hardware assurance apiVersion mismatch")
    require(document.get("kind") == "ServerwareHardwareAssurance", "hardware assurance kind mismatch")
    statement = document.get("statement") if isinstance(document.get("statement"), dict) else {}
    require(statement, "hardware assurance document is missing its signed statement")
    require_exact_keys(
        statement,
        {
            "verifier",
            "issued_at_unix",
            "expires_at_unix",
            "challenge_nonce",
            "current_host_identity",
            "attestation_document_sha256",
            "eif",
            "pcrs",
            "enclave",
            "key_custody",
            "no_parent_key",
            "release_bindings",
            "artifact_bindings",
        },
        "hardware assurance statement",
    )

    signing_key_id = require_sha256(document.get("signing_key_id"), "hardware assurance signing key id")
    trusted_key_id = release_public_key_id(trusted_public_key_pem)
    if expected_trusted_public_key_id is not None:
        expected_key_id = require_sha256(
            expected_trusted_public_key_id,
            "expected hardware assurance verifier public key id",
        )
        require(
            hmac.compare_digest(trusted_key_id, expected_key_id),
            "hardware assurance verifier key bytes do not match the independently configured SPKI identity",
        )
    require(signing_key_id == trusted_key_id, "hardware assurance signer does not match the separately trusted verifier key")
    signature = document.get("signature")
    require(isinstance(signature, str) and signature, "hardware assurance document is missing its signature")
    signed_statement_bytes = canonical_json(statement).encode("utf-8")
    verify_ed25519(
        trusted_public_key_pem,
        signature,
        signed_statement_bytes,
        "hardware assurance",
    )

    verifier = statement.get("verifier") if isinstance(statement.get("verifier"), dict) else {}
    require_exact_keys(verifier, {"name", "organization", "independent"}, "hardware assurance verifier identity")
    require(isinstance(verifier.get("name"), str) and bool(verifier.get("name")), "hardware assurance verifier name is missing")
    require(
        isinstance(verifier.get("organization"), str) and bool(verifier.get("organization")),
        "hardware assurance verifier organization is missing",
    )
    require(verifier.get("independent") is True, "hardware assurance was not issued by an independent verifier")

    issued_at = statement.get("issued_at_unix")
    expires_at = statement.get("expires_at_unix")
    require(isinstance(issued_at, int) and not isinstance(issued_at, bool), "hardware assurance issued_at_unix is invalid")
    require(isinstance(expires_at, int) and not isinstance(expires_at, bool), "hardware assurance expires_at_unix is invalid")
    now = int(time.time()) if now_unix is None else now_unix
    require(issued_at <= now + HARDWARE_PROOF_FUTURE_SKEW_SECONDS, "hardware assurance was issued in the future")
    require(now - issued_at <= HARDWARE_PROOF_MAX_AGE_SECONDS, "hardware assurance is stale")
    require(expires_at >= now, "hardware assurance has expired")
    require(expires_at > issued_at, "hardware assurance expiry does not follow issuance")
    require(
        expires_at - issued_at <= HARDWARE_PROOF_MAX_AGE_SECONDS,
        "hardware assurance validity window exceeds the allowed maximum",
    )

    host_identity = (
        statement.get("current_host_identity")
        if isinstance(statement.get("current_host_identity"), dict)
        else {}
    )
    require_exact_keys(
        host_identity,
        {
            "scheme",
            "machine_id_sha256",
            "product_uuid_sha256",
            "boot_id_sha256",
            "identity_sha256",
            "observed_at_unix",
            "commitment_sha256",
        },
        "hardware assurance current-host identity",
    )
    require(
        host_identity.get("scheme") == CURRENT_HOST_IDENTITY_SCHEME,
        "hardware assurance current-host identity scheme mismatch",
    )
    identity_payload = {
        "scheme": host_identity["scheme"],
        "machine_id_sha256": require_sha256(
            host_identity.get("machine_id_sha256"),
            "hardware assurance current-host machine id digest",
        ),
        "product_uuid_sha256": require_sha256(
            host_identity.get("product_uuid_sha256"),
            "hardware assurance current-host product UUID digest",
        ),
        "boot_id_sha256": require_sha256(
            host_identity.get("boot_id_sha256"),
            "hardware assurance current-host boot id digest",
        ),
    }
    identity_sha256 = require_sha256(
        host_identity.get("identity_sha256"),
        "hardware assurance current-host identity digest",
    )
    require(
        identity_sha256 == sha256_prefixed_json(identity_payload),
        "hardware assurance current-host identity digest mismatch",
    )
    observed_at = host_identity.get("observed_at_unix")
    require(
        isinstance(observed_at, int) and not isinstance(observed_at, bool),
        "hardware assurance current-host identity observation time is invalid",
    )
    require(
        observed_at <= issued_at,
        "hardware assurance current-host identity observation follows assurance issuance",
    )
    require(
        issued_at - observed_at <= CURRENT_HOST_IDENTITY_MAX_OBSERVATION_AGE_SECONDS,
        "hardware assurance current-host identity observation is stale relative to assurance issuance",
    )
    host_identity_commitment = require_sha256(
        host_identity.get("commitment_sha256"),
        "hardware assurance current-host identity commitment",
    )
    require(
        host_identity_commitment
        == sha256_prefixed_json({**identity_payload, "identity_sha256": identity_sha256, "observed_at_unix": observed_at}),
        "hardware assurance current-host identity commitment mismatch",
    )
    current_host_identity_bound = False
    if current_host.get("skipped") is not True:
        require(
            current_host.get("identity_recomputed") is True,
            "current completion host identity was not recomputed",
        )
        recomputed_identity = current_host.get("identity") if isinstance(current_host.get("identity"), dict) else {}
        require(
            recomputed_identity == {**identity_payload, "identity_sha256": identity_sha256},
            "hardware assurance current-host identity does not match current completion host",
        )
        current_host_identity_bound = True

    challenge_nonce = statement.get("challenge_nonce")
    require(
        isinstance(challenge_nonce, str) and BASE64URL_RE.fullmatch(challenge_nonce) is not None,
        "hardware assurance challenge nonce is invalid",
    )
    try:
        challenge_nonce_bytes = b64d(challenge_nonce)
    except Exception as exc:
        raise ValueError("hardware assurance challenge nonce is invalid") from exc
    require(len(challenge_nonce_bytes) >= 32, "hardware assurance challenge nonce is too short")
    supplied_expected_challenges = sum(
        value is not None
        for value in (expected_challenge_nonce, expected_challenge_nonce_sha256)
    )
    require(
        supplied_expected_challenges == 1,
        "hardware assurance verification requires exactly one caller-expected challenge nonce or nonce SHA-256",
    )
    challenge_nonce_sha256 = sha256_prefixed_bytes(challenge_nonce_bytes)
    if expected_challenge_nonce is not None:
        require(
            isinstance(expected_challenge_nonce, str)
            and BASE64URL_RE.fullmatch(expected_challenge_nonce) is not None,
            "expected hardware assurance challenge nonce is invalid",
        )
        try:
            expected_challenge_nonce_bytes = b64d(expected_challenge_nonce)
        except Exception as exc:
            raise ValueError("expected hardware assurance challenge nonce is invalid") from exc
        require(
            len(expected_challenge_nonce_bytes) >= 32,
            "expected hardware assurance challenge nonce is too short",
        )
        challenge_matches = hmac.compare_digest(
            challenge_nonce_bytes,
            expected_challenge_nonce_bytes,
        )
    else:
        expected_digest = require_sha256(
            expected_challenge_nonce_sha256,
            "expected hardware assurance challenge nonce digest",
        )
        challenge_matches = hmac.compare_digest(challenge_nonce_sha256, expected_digest)
    require(
        challenge_matches,
        "hardware assurance challenge nonce does not match the caller-expected challenge",
    )

    attestation_document_sha256 = require_sha256(
        statement.get("attestation_document_sha256"),
        "hardware assurance attestation document digest",
    )
    require(
        attestation_document_sha256 == nitro_summary["raw_attestation_document_sha256"],
        "hardware assurance does not bind the verified Nitro attestation document",
    )

    eif = statement.get("eif") if isinstance(statement.get("eif"), dict) else {}
    require_exact_keys(
        eif,
        {"image_sha384", "build_manifest", "build_manifest_sha256", "signature_verified", "evidence_sha256"},
        "hardware assurance EIF evidence",
    )
    eif_image_sha384 = require_sha384(eif.get("image_sha384"), "hardware assurance EIF image digest")
    build_manifest_sha256 = require_sha256(
        eif.get("build_manifest_sha256"),
        "hardware assurance EIF build manifest digest",
    )
    require_sha256(eif.get("evidence_sha256"), "hardware assurance EIF evidence digest")
    require(eif.get("signature_verified") is True, "hardware assurance did not verify the EIF signature")

    pcrs = statement.get("pcrs") if isinstance(statement.get("pcrs"), dict) else {}
    require_exact_keys(pcrs, {"PCR0", "PCR1", "PCR2"}, "hardware assurance PCR measurements")
    verified_pcrs = {name: require_sha384(pcrs.get(name), f"hardware assurance {name}") for name in ("PCR0", "PCR1", "PCR2")}
    require(verified_pcrs["PCR0"] == eif_image_sha384, "hardware assurance EIF image digest does not match PCR0")
    build_manifest = eif.get("build_manifest") if isinstance(eif.get("build_manifest"), dict) else {}
    require_exact_keys(
        build_manifest,
        {"apiVersion", "release_identity", "release_identity_sha256", "eif_image_sha384", "pcrs"},
        "hardware assurance EIF build manifest",
    )
    require(
        build_manifest.get("apiVersion") == EIF_BUILD_MANIFEST_API_VERSION,
        "hardware assurance EIF build manifest apiVersion mismatch",
    )
    manifest_release_identity = validate_release_identity(
        build_manifest.get("release_identity"),
        "hardware assurance EIF build manifest release identity",
    )
    require(
        manifest_release_identity == verified_expected_release_identity,
        "hardware assurance EIF build manifest does not match the independently verified source/build/release identity",
    )
    require(
        build_manifest.get("release_identity_sha256") == sha256_prefixed_json(verified_expected_release_identity),
        "hardware assurance EIF build manifest release identity digest mismatch",
    )
    require(
        build_manifest.get("eif_image_sha384") == eif_image_sha384,
        "hardware assurance EIF build manifest image measurement mismatch",
    )
    require(
        build_manifest.get("pcrs") == verified_pcrs,
        "hardware assurance EIF build manifest PCR measurements mismatch",
    )
    require(
        sha256_prefixed_json(build_manifest) == build_manifest_sha256,
        "hardware assurance EIF build manifest digest mismatch",
    )

    enclave = statement.get("enclave") if isinstance(statement.get("enclave"), dict) else {}
    require_exact_keys(
        enclave,
        {
            "cid",
            "parent_cid",
            "vsock_port",
            "cid_evidence_sha256",
            "vsock_evidence_sha256",
            "vsock_handshake_verified",
        },
        "hardware assurance enclave connectivity evidence",
    )
    cid = enclave.get("cid")
    parent_cid = enclave.get("parent_cid")
    vsock_port = enclave.get("vsock_port")
    require(isinstance(cid, int) and not isinstance(cid, bool) and 4 <= cid <= 0xFFFFFFFF, "hardware assurance enclave CID is invalid")
    require(parent_cid == 3, "hardware assurance parent CID is not the Nitro parent CID")
    require(
        isinstance(vsock_port, int) and not isinstance(vsock_port, bool) and 1 <= vsock_port <= 0xFFFFFFFF,
        "hardware assurance vsock port is invalid",
    )
    require_sha256(enclave.get("cid_evidence_sha256"), "hardware assurance CID evidence digest")
    require_sha256(enclave.get("vsock_evidence_sha256"), "hardware assurance vsock evidence digest")
    require(enclave.get("vsock_handshake_verified") is True, "hardware assurance did not verify a vsock handshake")

    key_custody = statement.get("key_custody") if isinstance(statement.get("key_custody"), dict) else {}
    require_exact_keys(
        key_custody,
        {
            "recipient_key_generated_in_enclave",
            "kms_recipient_bound",
            "plaintext_key_exported",
            "parent_process_key_access",
            "kms_recipient_bindings_sha256",
            "evidence_sha256",
        },
        "hardware assurance key-custody evidence",
    )
    require(
        key_custody.get("recipient_key_generated_in_enclave") is True,
        "hardware assurance did not prove enclave-local recipient-key generation",
    )
    require(key_custody.get("kms_recipient_bound") is True, "hardware assurance did not bind AWS KMS Recipient release")
    require(key_custody.get("plaintext_key_exported") is False, "hardware assurance permits plaintext key export")
    require(key_custody.get("parent_process_key_access") is False, "hardware assurance permits parent-process key access")
    kms_recipient_bindings_sha256 = require_sha256(
        key_custody.get("kms_recipient_bindings_sha256"),
        "hardware assurance KMS Recipient bindings digest",
    )
    require(
        kms_recipient_bindings_sha256 == sha256_prefixed_json(nitro_summary["material_release_receipts"]),
        "hardware assurance KMS Recipient bindings do not match Nitro release evidence",
    )
    require_sha256(key_custody.get("evidence_sha256"), "hardware assurance key-custody evidence digest")

    no_parent_key = statement.get("no_parent_key") if isinstance(statement.get("no_parent_key"), dict) else {}
    require_exact_keys(
        no_parent_key,
        {"verified", "parent_key_material_absent", "evidence_sha256"},
        "hardware assurance no-parent-key evidence",
    )
    require(no_parent_key.get("verified") is True, "hardware assurance no-parent-key evidence is not verified")
    require(
        no_parent_key.get("parent_key_material_absent") is True,
        "hardware assurance found key material in a parent process",
    )
    require_sha256(no_parent_key.get("evidence_sha256"), "hardware assurance no-parent-key evidence digest")

    release_bindings = statement.get("release_bindings") if isinstance(statement.get("release_bindings"), dict) else {}
    require(
        release_bindings == nitro_summary["attested_runtime"],
        "hardware assurance release bindings do not exactly match the Nitro-attested runtime",
    )
    require(
        release_bindings.get("source_tree_digest") == verified_expected_release_identity["source_tree_digest"]
        and release_bindings.get("provenance_digest") == verified_expected_release_identity["provenance_digest"]
        and release_bindings.get("runtime_manifest_digest")
        == verified_expected_release_identity["runtime_manifest_digest"]
        and release_bindings.get("data_plane_binary_digest")
        == verified_expected_release_identity["data_plane_binary_digest"],
        "hardware assurance Nitro release bindings do not match the independently verified release identity",
    )
    artifact_bindings = statement.get("artifact_bindings") if isinstance(statement.get("artifact_bindings"), dict) else {}
    require_exact_keys(
        artifact_bindings,
        {"nitro_evidence_sha256", "production_host_preflight_sha256"},
        "hardware assurance artifact bindings",
    )
    require(
        artifact_bindings.get("nitro_evidence_sha256") == nitro_evidence_sha256,
        "hardware assurance does not bind the current Nitro evidence artifact",
    )
    require(
        artifact_bindings.get("production_host_preflight_sha256") == production_host_preflight_sha256,
        "hardware assurance does not bind the current production host preflight artifact",
    )

    independent_evidence_digests = {
        eif["evidence_sha256"],
        enclave["cid_evidence_sha256"],
        enclave["vsock_evidence_sha256"],
        key_custody["evidence_sha256"],
        no_parent_key["evidence_sha256"],
    }
    require(
        len(independent_evidence_digests) == 5,
        "hardware assurance reused one evidence artifact for distinct assurance claims",
    )
    return {
        "verified": True,
        "trusted_verifier_key_id": trusted_key_id,
        "hardware_assurance_document_sha256": require_sha256(
            hardware_assurance_document_sha256,
            "hardware assurance document digest",
        ),
        "hardware_assurance_signed_statement_sha256": sha256_prefixed_bytes(
            signed_statement_bytes
        ),
        "verifier": verifier,
        "issued_at_unix": issued_at,
        "expires_at_unix": expires_at,
        "challenge_nonce_sha256": challenge_nonce_sha256,
        "expected_challenge_bound": True,
        "current_host_identity": host_identity,
        "current_host_identity_bound": current_host_identity_bound,
        "attestation_document_sha256": attestation_document_sha256,
        "eif": eif,
        "pcrs": verified_pcrs,
        "release_identity": verified_expected_release_identity,
        "release_identity_sha256": sha256_prefixed_json(verified_expected_release_identity),
        "release_measurements_bound": True,
        "enclave": enclave,
        "key_custody": key_custody,
        "no_parent_key": no_parent_key,
        "release_bindings": release_bindings,
        "artifact_bindings": artifact_bindings,
        "independent_evidence_bound": True,
    }


def completion_assurance(
    hardware_assurance: dict[str, Any] | None,
    current_host: dict[str, Any],
) -> dict[str, Any]:
    current_identity = current_host.get("identity") if isinstance(current_host.get("identity"), dict) else {}
    host_bound = (
        current_host.get("skipped") is False
        and current_host.get("preflight_bound") is True
        and current_host.get("identity_recomputed") is True
        and bool(current_identity)
    )
    if hardware_assurance is None:
        return {
            "level": "pre-enclave-readiness",
            "final_completion": False,
            "hardware_proof": False,
            "hardware_evidence_verified": False,
            "reason": "ordinary Docker, development, or /dev/nsm readiness does not prove enclave execution or key custody",
            "required_final_evidence": list(FINAL_HARDWARE_EVIDENCE),
        }
    require(hardware_assurance.get("verified") is True, "hardware assurance summary is not verified")
    require(
        hardware_assurance.get("expected_challenge_bound") is True,
        "hardware assurance summary is not bound to an externally supplied expected challenge",
    )
    require(
        hardware_assurance.get("release_measurements_bound") is True,
        "hardware assurance summary is not bound to independently verified release measurements",
    )
    if not host_bound:
        return {
            "level": "pre-enclave-readiness",
            "final_completion": False,
            "hardware_proof": False,
            "hardware_evidence_verified": True,
            "reason": "hardware evidence cannot establish final completion while the current-host binding is bypassed",
            "required_final_evidence": ["current host binding without a test-only bypass"],
        }
    hardware_identity = (
        hardware_assurance.get("current_host_identity")
        if isinstance(hardware_assurance.get("current_host_identity"), dict)
        else {}
    )
    require(
        hardware_assurance.get("current_host_identity_bound") is True
        and hardware_identity.get("identity_sha256") == current_identity.get("identity_sha256")
        and hardware_identity.get("boot_id_sha256") == current_identity.get("boot_id_sha256"),
        "hardware assurance is not bound to the recomputed current-host identity",
    )
    return {
        "level": "hardware-backed-release-completion",
        "final_completion": True,
        "hardware_proof": True,
        "hardware_evidence_verified": True,
        "reason": "fresh independently signed hardware evidence and current-host binding verified",
        "required_final_evidence": [],
    }


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
        "assurance_level": "pre-enclave-readiness",
        "hardware_proof": False,
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
    trusted_public_key_pem: str,
    expected_checkpoint_sha256: str,
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
    verified = verify_external_checkpoint_receipt(
        checkpoint,
        expected_provider=expected_provider,
        expected_log_id=expected_log_id,
        trusted_public_key_pem=trusted_public_key_pem,
        expected_fields={},
        label=label,
    )
    require(
        verified["checkpoint_sha256"] == expected_checkpoint_sha256,
        f"{label} used a different external checkpoint than the receipt binding its release record",
    )
    return verified


def transparency_record_binding(
    transparency: dict[str, Any],
    *,
    anchor_key: str,
    inclusion_key: str,
    expected_type: str,
    expected_fields: dict[str, Any],
    expected_external_provider: str,
    expected_external_log_id: str,
    trusted_external_public_key_pem: str,
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
    item_checkpoint = item.get("external_checkpoint") if isinstance(item.get("external_checkpoint"), dict) else {}
    require(item_checkpoint, f"{label} transparency inclusion item is missing its external checkpoint")
    require(
        item_checkpoint == checkpoint,
        f"{label} transparency inclusion and anchor response used different external checkpoints",
    )
    verified_checkpoint = verify_external_checkpoint_receipt(
        checkpoint,
        expected_provider=expected_external_provider,
        expected_log_id=expected_external_log_id,
        trusted_public_key_pem=trusted_external_public_key_pem,
        expected_fields={
            "record_digest": record_digest,
            "leaf_hash": expected_leaf_hash,
            "tree_head_hash": tree_head_hash,
            "tree_size": tree_size,
        },
        label=label,
    )
    return {
        "record_digest": record_digest,
        "leaf_hash": expected_leaf_hash,
        "tree_head_hash": tree_head_hash,
        "external_checkpoint": verified_checkpoint,
    }


def verify_release_provenance(
    summary: dict[str, Any],
    document: dict[str, Any],
    expected_external_provider: str,
    expected_external_log_id: str,
    trusted_release_public_key_pem: str,
    trusted_external_public_key_pem: str,
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
    trusted_release_signing_key_id = release_public_key_id(trusted_release_public_key_pem)
    require(
        release_signing_key_id == trusted_release_signing_key_id,
        "release provenance signer does not match the independently trusted release key",
    )
    require(
        release_public_key_id(public_key_pem) == trusted_release_signing_key_id,
        "release provenance embedded signing key is not the independently trusted release key",
    )
    verify_ed25519(
        trusted_release_public_key_pem,
        signature,
        canonical_json(provenance).encode("utf-8"),
        "release provenance",
    )
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
            "production_launcher_binary_digest": require_sha256(
                ((provenance.get("images") or {}).get("serverware-decision-gate") or {}).get(
                    "launcher_binary_digest"
                ),
                "release provenance production launcher binary digest",
            ),
        },
        expected_external_provider=expected_external_provider,
        expected_external_log_id=expected_external_log_id,
        trusted_external_public_key_pem=trusted_external_public_key_pem,
        label="release provenance",
    )
    external_transparency = external_checkpoint_binding(
        transparency,
        anchor_key="anchor_response",
        expected_provider=expected_external_provider,
        expected_log_id=expected_external_log_id,
        trusted_public_key_pem=trusted_external_public_key_pem,
        expected_checkpoint_sha256=release_record["external_checkpoint"]["checkpoint_sha256"],
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
    production_launcher_binary_digest = require_sha256(
        ((provenance.get("images") or {}).get("serverware-decision-gate") or {}).get(
            "launcher_binary_digest"
        ),
        "release provenance production launcher binary digest",
    )
    require(
        summary.get("production_launcher_binary_digest")
        == production_launcher_binary_digest,
        "release provenance summary production launcher digest mismatch",
    )
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
        "production_launcher_binary_digest": production_launcher_binary_digest,
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
        normalized.append(
            {
                "service": service,
                "image_id": require_sha256(image.get("image_id"), f"{service} image_id"),
                "dockerfile": image.get("dockerfile"),
                "tag": image.get("tag"),
                **({"binary_digest": binary_digest} if binary_digest else {}),
                **(
                    {"launcher_binary_digest": launcher_binary_digest}
                    if launcher_binary_digest
                    else {}
                ),
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
            require(
                require_sha256(
                    image.get("launcher_binary_digest"),
                    "published production launcher binary digest",
                )
                == build_by_service[service]["launcher_binary_digest"],
                "published production launcher does not match the measured build launcher",
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
    trusted_sigstore_public_key_pem: str,
    trusted_rekor_public_key_pem: str,
    trusted_external_public_key_pem: str,
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
    require(
        release_public_key_id(trusted_sigstore_public_key_pem) == image_signing_key_id,
        "image signing key does not match the independently trusted Sigstore key",
    )
    require(
        release_public_key_id(trusted_rekor_public_key_pem) == expected_rekor_log_id,
        "live Rekor log does not match the independently trusted Rekor key",
    )
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
        expected_statement=normalized_payload,
        expected_statement_digest=digest,
        expected_signature=str(bundle_sigstore.get("signature")),
        trusted_signing_public_key_pem=trusted_sigstore_public_key_pem,
        expected_signing_key_id=image_signing_key_id,
        expected_rekor_log_id=expected_rekor_log_id,
        trusted_rekor_public_key_pem=trusted_rekor_public_key_pem,
        label="image signature bundle",
    )
    transparency_log_ids.append(bundle_rekor_log_id)
    metadata_transparency = metadata.get("transparency") if isinstance(metadata.get("transparency"), dict) else {}
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
            expected_statement=statement,
            expected_statement_digest=statement_digest,
            expected_signature=str(sigstore.get("signature")),
            trusted_signing_public_key_pem=trusted_sigstore_public_key_pem,
            expected_signing_key_id=image_signing_key_id,
            expected_rekor_log_id=expected_rekor_log_id,
            trusted_rekor_public_key_pem=trusted_rekor_public_key_pem,
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
        expected_external_provider=expected_external_provider,
        expected_external_log_id=expected_external_log_id,
        trusted_external_public_key_pem=trusted_external_public_key_pem,
        label="image signature bundle",
    )
    external_transparency = external_checkpoint_binding(
        metadata_transparency,
        anchor_key="anchorResponse",
        expected_provider=expected_external_provider,
        expected_log_id=expected_external_log_id,
        trusted_public_key_pem=trusted_external_public_key_pem,
        expected_checkpoint_sha256=image_record["external_checkpoint"]["checkpoint_sha256"],
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


def require_preflight_file_digest(
    preflight: dict[str, Any],
    snapshots: dict[str, FileSnapshot],
    artifact: str,
    *keys: str,
) -> None:
    expected = nested(preflight, "checks", "release_artifacts", *keys)
    require(
        expected == snapshots[artifact].sha256,
        f"production host preflight {artifact} digest does not match current artifact",
    )


def verify_preflight_authenticity(
    preflight: dict[str, Any],
    *,
    trusted_public_key: FileSnapshot,
    expected_key_id: str,
    max_age_seconds: int,
) -> dict[str, Any]:
    require(1 <= max_age_seconds <= 900, "production host preflight max age is invalid")
    authenticity = preflight.get("authenticity")
    require(isinstance(authenticity, dict), "final production host preflight is unsigned")
    require_exact_keys(
        authenticity,
        {"apiVersion", "algorithm", "key_id", "payload_sha256", "signed_at_unix", "signature"},
        "production host preflight authenticity",
    )
    require(
        authenticity.get("apiVersion") == "serverware.productionHostPreflightSignature/v1"
        and authenticity.get("algorithm") == "ed25519",
        "production host preflight authenticity scheme is invalid",
    )
    key_id = require_sha256(authenticity.get("key_id"), "production host preflight signing key ID")
    require(
        hmac.compare_digest(key_id, require_sha256(expected_key_id, "expected preflight signing key ID")),
        "production host preflight signing key ID does not match the selected trust root",
    )
    public_key_pem = snapshot_text(
        trusted_public_key,
        "production host preflight signing public key",
        encoding="ascii",
    )
    require(
        hmac.compare_digest(release_public_key_id(public_key_pem), key_id),
        "production host preflight signing public key bytes do not match the expected key ID",
    )
    payload_document = dict(preflight)
    payload_document.pop("authenticity", None)
    payload = canonical_json(payload_document).encode("utf-8")
    require(
        hmac.compare_digest(
            require_sha256(authenticity.get("payload_sha256"), "production host preflight payload digest"),
            sha256_prefixed_bytes(payload),
        ),
        "production host preflight signed payload digest mismatch",
    )
    verify_ed25519(
        public_key_pem,
        str(authenticity.get("signature")),
        payload,
        "production host preflight",
    )
    now = int(time.time())
    generated_at = preflight.get("generated_at_unix")
    signed_at = authenticity.get("signed_at_unix")
    require(isinstance(generated_at, int) and generated_at > 0, "production host preflight generated_at_unix is invalid")
    require(isinstance(signed_at, int) and signed_at > 0, "production host preflight signed_at_unix is invalid")
    for timestamp, label in ((generated_at, "generated"), (signed_at, "signed")):
        require(timestamp <= now + PROXY_PROOF_FUTURE_SKEW_SECONDS, f"production host preflight was {label} in the future")
        require(now - timestamp <= max_age_seconds, f"production host preflight {label} timestamp is stale")
    require(abs(signed_at - generated_at) <= 5, "production host preflight signing time is not bound to generation")
    return {
        "verified": True,
        "key_id": key_id,
        "payload_sha256": authenticity["payload_sha256"],
        "generated_at_unix": generated_at,
        "signed_at_unix": signed_at,
        "max_age_seconds": max_age_seconds,
    }


def verify_production_host_preflight(
    preflight: dict[str, Any],
    paths: dict[str, Path],
    snapshots: InputSnapshots,
    readiness_summary: dict[str, Any],
    *,
    verification_mode: str = "readiness",
    preflight_signing_public_key: FileSnapshot | None = None,
    preflight_signing_key_id: str | None = None,
    preflight_max_age_seconds: int | None = None,
    expected_bootstrap_receipt: dict[str, Any] | None = None,
) -> dict[str, Any]:
    production_env_snapshot = load_production_env_snapshot(
        snapshots.by_key["production_readiness_env"]
    )
    preflight_module = load_production_host_preflight_module(
        production_env_snapshot,
        final=verification_mode == "final",
    )
    assert_no_secret_fields(preflight)
    require(preflight.get("apiVersion") == "serverware.productionHostPreflight/v1", "production host preflight has wrong apiVersion")
    require(preflight.get("ok") is True, "production host preflight is not ok")
    require(not preflight.get("failures"), "production host preflight includes failures")
    preflight_authenticity: dict[str, Any] | None = None
    if verification_mode == "final":
        require(preflight_signing_public_key is not None, "final completion is missing the preflight signing trust root snapshot")
        require(isinstance(preflight_signing_key_id, str), "final completion is missing the preflight signing key ID")
        require(isinstance(preflight_max_age_seconds, int), "final completion is missing the preflight freshness policy")
        preflight_authenticity = verify_preflight_authenticity(
            preflight,
            trusted_public_key=preflight_signing_public_key,
            expected_key_id=preflight_signing_key_id,
            max_age_seconds=preflight_max_age_seconds,
        )
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
    executable_digest_entries = runtime_trust.get("executable_digests")
    require(
        isinstance(executable_digest_entries, list),
        "production host preflight did not report pinned executable digests",
    )
    executable_digests: dict[str, str] = {}
    for item in executable_digest_entries:
        require(
            isinstance(item, dict)
            and set(item) == {"setting", "executable", "host_path", "sha256", "verified"},
            "production host preflight executable digest entry is invalid",
        )
        setting = item.get("setting")
        require(
            isinstance(setting, str)
            and setting in preflight_module.PINNED_EXECUTABLE_COMMAND_SETTINGS,
            "production host preflight executable digest setting is invalid",
        )
        require(
            setting not in executable_digests,
            f"production host preflight has duplicate executable digest setting: {setting}",
        )
        require(
            isinstance(item.get("executable"), str)
            and Path(str(item["executable"])).is_absolute()
            and (
                setting
                in {
                    preflight_module.PRODUCTION_PYTHON_EXECUTABLE_SETTING,
                    preflight_module.PRODUCTION_DOCKER_EXECUTABLE_SETTING,
                }
                or Path(str(item["executable"])).parent == Path("/opt/serverware/bin")
            ),
            f"production host preflight executable path is invalid for {setting}",
        )
        require(
            isinstance(item.get("host_path"), str) and bool(item["host_path"]),
            f"production host preflight host executable path is invalid for {setting}",
        )
        require(
            item.get("verified") is True,
            f"production host preflight did not verify the executable digest for {setting}",
        )
        executable_digests[setting] = require_sha256(
            item.get("sha256"),
            f"production host preflight executable digest for {setting}",
        )
    require(
        set(executable_digests)
        == preflight_module.PINNED_EXECUTABLE_COMMAND_SETTINGS,
        "production host preflight did not validate every pinned helper and collector executable",
    )
    script_digests: dict[str, str] = {}
    docker_toolchain = runtime_trust.get("docker_toolchain")
    material_digests = runtime_trust.get("material_digests")
    if verification_mode == "final":
        script_entries = runtime_trust.get("python_script_digests")
        require(isinstance(script_entries, list), "production host preflight did not report pinned Python scripts")
        for item in script_entries:
            require(
                isinstance(item, dict)
                and set(item) == {"setting", "path", "sha256", "verified"}
                and item.get("verified") is True,
                "production host preflight Python script digest entry is invalid",
            )
            setting = str(item["setting"])
            require(
                setting in set(run_production_readiness.PINNED_PYTHON_SCRIPTS.values())
                and setting not in script_digests,
                "production host preflight Python script digest setting is invalid or duplicated",
            )
            script_digests[setting] = require_sha256(
                item.get("sha256"),
                f"production host preflight Python script digest for {setting}",
            )
        require(
            set(script_digests) == set(run_production_readiness.PINNED_PYTHON_SCRIPTS.values()),
            "production host preflight did not validate every pinned Python script",
        )
        require(
            isinstance(docker_toolchain, dict)
            and docker_toolchain.get("ok") is True
            and nested(docker_toolchain, "compose_plugin", "verified") is True
            and nested(docker_toolchain, "daemon", "daemon_id_verified") is True,
            "production host preflight did not authenticate the Docker toolchain and daemon",
        )
        required_runtime_materials = {
            "control_plane_certificate",
            "control_plane_private_key",
            "control_plane_ca_bundle",
            "anchor_certificate",
            "anchor_private_key",
            "proof_ca_bundle",
            "proof_collector_private_key",
            "proof_collector_public_key",
            "proof_verifier_public_key",
            "preflight_signing_public_key",
        }
        require(
            isinstance(material_digests, dict)
            and set(material_digests) == required_runtime_materials,
            "production host preflight runtime trust digest set is incomplete",
        )
        for label, report in material_digests.items():
            require(
                isinstance(report, dict)
                and set(report)
                == {"path", "sha256", "bytes", "mode", "owner_uid", "nofollow", "secure_ancestors"}
                and report.get("nofollow") is True
                and report.get("secure_ancestors") is True,
                f"production host preflight runtime trust digest report is invalid: {label}",
            )
            require_sha256(report.get("sha256"), f"production host preflight runtime trust digest {label}")

    production_env = checks.get("production_env") if isinstance(checks.get("production_env"), dict) else {}
    require(production_env.get("ok") is True, "production host preflight production env check did not pass")
    preflight_executing_script: dict[str, Any] | None = None
    preflight_bootstrap_receipt: dict[str, Any] | None = None
    if verification_mode == "final":
        launcher_trust = (
            production_env.get("launcher_trust")
            if isinstance(production_env.get("launcher_trust"), dict)
            else {}
        )
        candidate_receipt = launcher_trust.get("bootstrap_receipt")
        require(
            isinstance(expected_bootstrap_receipt, dict)
            and isinstance(candidate_receipt, dict)
            and candidate_receipt == expected_bootstrap_receipt,
            "production host preflight is not bound to the current sealed launcher receipt",
        )
        preflight_bootstrap_receipt = candidate_receipt
        candidate = production_env.get("executing_script")
        require(
            isinstance(candidate, dict)
            and set(candidate)
            == {
                "path",
                "sha256",
                "device",
                "inode",
                "measured_from",
                "matches_pinned_path_inode",
            }
            and candidate.get("matches_pinned_path_inode") is True
            and candidate.get("sha256")
            == script_digests[
                run_production_readiness.PRODUCTION_HOST_PREFLIGHT_SCRIPT_SHA256_ENV
            ],
            "production host preflight did not bind its descriptor-executed script identity",
        )
        preflight_executing_script = candidate
    production_env_file = production_env.get("file") if isinstance(production_env.get("file"), dict) else {}
    require(
        production_env_file.get("sha256") == snapshots.by_key["production_readiness_env"].sha256,
        "production host preflight production env digest does not match current production readiness env",
    )
    config_gate = production_env.get("config_gate") if isinstance(production_env.get("config_gate"), dict) else {}
    require(config_gate.get("skipped") is not True, "production host preflight skipped the config gate")
    require(config_gate.get("ok") is True, "production host preflight config gate did not pass")
    preflight_config_file = config_gate.get("file") if isinstance(config_gate.get("file"), dict) else {}
    preflight_config_path = Path(str(config_gate.get("out") or preflight_config_file.get("path") or ""))
    preflight_config_snapshot = snapshots.capture(
        "production_host_preflight_config",
        preflight_config_path,
        "production host preflight config gate",
        max_bytes=COMPLETION_INPUT_MAX_BYTES,
    )
    require(
        preflight_config_file.get("sha256") == preflight_config_snapshot.sha256,
        "production host preflight config gate digest does not match current preflight config artifact",
    )
    require(
        config_gate.get("result_sha256") == preflight_config_file.get("sha256"),
        "production host preflight config gate result digest mismatch",
    )
    preflight_config = load_json_snapshot(
        preflight_config_snapshot,
        "production host preflight config gate",
    )
    preflight_config_semantic_sha256 = semantic_result_digest(preflight_config)
    require(
        config_gate.get("semantic_sha256") == preflight_config_semantic_sha256,
        "production host preflight config gate semantic digest mismatch",
    )

    images_env = checks.get("production_images_env") if isinstance(checks.get("production_images_env"), dict) else {}
    require(images_env.get("ok") is True and images_env.get("status") == "valid", "production host preflight image env check did not pass")
    images_env_file = images_env.get("file") if isinstance(images_env.get("file"), dict) else {}
    require(
        images_env_file.get("sha256") == snapshots.by_key["production_images_env"].sha256,
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
    compose_renderer: dict[str, Any] | None = None
    production_runtime_model: dict[str, Any] | None = None
    if verification_mode == "final":
        compose_renderer = {
            "path": production_compose.get("compose_plugin_executable"),
            "sha256": require_sha256(
                production_compose.get("compose_plugin_sha256"),
                "production host preflight Compose renderer digest",
            ),
        }
        require(
            compose_renderer["path"] == nested(docker_toolchain, "compose_plugin", "path")
            and compose_renderer["sha256"]
            == nested(docker_toolchain, "compose_plugin", "sha256"),
            "production host preflight Compose renderer differs from the measured Docker toolchain",
        )
        require(
            production_compose.get("docker_unix_socket")
            == nested(docker_toolchain, "daemon", "socket", "path")
            and production_compose.get("docker_daemon_id")
            == nested(docker_toolchain, "daemon", "daemon_id"),
            "production host preflight Compose renderer used a different Docker endpoint",
        )
        require(
            production_compose.get("docker_daemon_before")
            == production_compose.get("docker_daemon_after")
            == docker_toolchain.get("daemon"),
            "production host preflight Docker endpoint changed during Compose rendering",
        )
        require(
            production_compose.get("compose_project_name")
            == production_env_snapshot.get(
                run_production_readiness.DOCKER_COMPOSE_PROJECT_NAME_ENV
            )
            == docker_toolchain.get("compose_project_name"),
            "production host preflight Compose project name differs from the hashed production env",
        )
        candidate_runtime_model = production_compose.get("runtime_model")
        require(
            isinstance(candidate_runtime_model, dict)
            and set(candidate_runtime_model)
            == {"services", "networks", "volumes", "sha256"}
            and isinstance(candidate_runtime_model.get("services"), dict)
            and isinstance(candidate_runtime_model.get("networks"), dict)
            and isinstance(candidate_runtime_model.get("volumes"), dict)
            and set(candidate_runtime_model["services"])
            == set(run_production_readiness.FINAL_SERVICE_USERS),
            "production host preflight normalized runtime model is incomplete",
        )
        runtime_model_digest = sha256_prefixed_bytes(
            canonical_json(
                {
                    key: candidate_runtime_model[key]
                    for key in ("services", "networks", "volumes")
                }
            ).encode("utf-8")
        )
        require(
            candidate_runtime_model.get("sha256")
            == production_compose.get("runtime_model_sha256")
            == runtime_model_digest,
            "production host preflight normalized runtime model digest is invalid",
        )
        production_runtime_model = candidate_runtime_model

    artifacts = checks.get("release_artifacts") if isinstance(checks.get("release_artifacts"), dict) else {}
    require(artifacts.get("ok") is True, "production host preflight release artifact check did not pass")
    require_preflight_file_digest(preflight, snapshots.by_key, "production_images_build", "production_images", "file", "sha256")
    require_preflight_file_digest(preflight, snapshots.by_key, "production_images_published", "production_images_published", "file", "sha256")
    require_preflight_file_digest(preflight, snapshots.by_key, "release_provenance_summary", "release_provenance", "file", "sha256")
    require_preflight_file_digest(preflight, snapshots.by_key, "release_provenance", "release_provenance_document", "sha256")
    require_preflight_file_digest(preflight, snapshots.by_key, "image_signatures_summary", "image_signatures_summary", "file", "sha256")
    require_preflight_file_digest(preflight, snapshots.by_key, "image_signatures", "image_signatures", "file", "sha256")
    require_preflight_file_digest(preflight, snapshots.by_key, "bench", "bench", "file", "sha256")
    release_security = checks.get("release_security_evidence") if isinstance(checks.get("release_security_evidence"), dict) else {}
    require(release_security.get("ok") is True, "production host preflight release security evidence did not pass")
    policy_trust_roots: dict[str, Any] = {}
    if verification_mode == "final":
        candidate_trust_roots = release_security.get("trust_roots")
        require(
            isinstance(candidate_trust_roots, dict)
            and set(candidate_trust_roots)
            == {"policy_identity", "policy_activation", "reproducible_build"},
            "production host preflight policy trust-root binding set is incomplete",
        )
        role_bindings = {
            "policy_identity": (
                "policy_trusted_public_key",
                run_production_readiness.POLICY_TRUST_ROOT_ENV,
                run_production_readiness.POLICY_TRUST_ROOT_ID_ENV,
            ),
            "policy_activation": (
                "policy_activation_trusted_public_key",
                run_production_readiness.POLICY_ACTIVATION_TRUST_ROOT_ENV,
                run_production_readiness.POLICY_ACTIVATION_TRUST_ROOT_ID_ENV,
            ),
            "reproducible_build": (
                "reproducible_build_trusted_public_key",
                run_production_readiness.REPRODUCIBLE_BUILD_TRUST_ROOT_ENV,
                run_production_readiness.REPRODUCIBLE_BUILD_TRUST_ROOT_ID_ENV,
            ),
        }
        for role, (snapshot_key, path_setting, id_setting) in role_bindings.items():
            report = candidate_trust_roots.get(role)
            require(
                isinstance(report, dict)
                and report.get("verified") is True
                and report.get("path") == production_env_snapshot.get(path_setting)
                and report.get("sha256") == snapshots.by_key[snapshot_key].sha256,
                f"production host preflight {role} trust-root snapshot binding is invalid",
            )
            current_id = release_public_key_id(
                snapshot_text(snapshots.by_key[snapshot_key], f"{role} trust root", encoding="ascii")
            )
            require(
                hmac.compare_digest(
                    current_id,
                    require_sha256(
                        production_env_snapshot.get(id_setting),
                        f"production env {role} SPKI pin",
                    ),
                )
                and report.get("spki_sha256") == current_id,
                f"production host preflight {role} SPKI binding mismatch",
            )
            policy_trust_roots[role] = {
                "path": report["path"],
                "sha256": report["sha256"],
                "spki_sha256": current_id,
            }
        require(
            len({item["spki_sha256"] for item in policy_trust_roots.values()}) == 3,
            "policy identity, activation, and reproducible-build trust roots are not distinct",
        )
    policy_identity = release_security.get("policy_identity") if isinstance(release_security.get("policy_identity"), dict) else {}
    require(
        policy_identity.get("reportSha256") == snapshots.by_key["policy_identity_verification"].sha256,
        "production host preflight policy identity report digest does not match current artifact",
    )
    require(
        policy_identity.get("policyBundleSha256") == snapshots.by_key["policy_bundle"].sha256,
        "production host preflight policy bundle digest does not match current artifact",
    )
    require(
        policy_identity.get("trustedPublicKeySha256") == snapshots.by_key["policy_trusted_public_key"].sha256,
        "production host preflight policy trust root digest does not match current artifact",
    )
    activation_evidence = release_security.get("policy_activation") if isinstance(release_security.get("policy_activation"), dict) else {}
    require(
        activation_evidence.get("reportSha256") == snapshots.by_key["policy_activation_verification"].sha256,
        "production host preflight activation report digest does not match current artifact",
    )
    require(
        activation_evidence.get("signatureSha256") == snapshots.by_key["policy_activation_signature"].sha256,
        "production host preflight activation signature digest does not match current artifact",
    )
    require(
        activation_evidence.get("trustedPublicKeySha256")
        == snapshots.by_key["policy_activation_trusted_public_key"].sha256,
        "production host preflight activation trust-root digest does not match current artifact",
    )
    reproducibility_evidence = release_security.get("reproducible_builds") if isinstance(release_security.get("reproducible_builds"), dict) else {}
    require(
        reproducibility_evidence.get("reportSha256") == snapshots.by_key["reproducible_build_verification"].sha256,
        "production host preflight reproducibility report digest does not match current artifact",
    )
    require(
        reproducibility_evidence.get("signatureSha256") == snapshots.by_key["reproducible_build_signature"].sha256,
        "production host preflight reproducibility signature digest does not match current artifact",
    )
    require(
        reproducibility_evidence.get("trustedPublicKeySha256")
        == snapshots.by_key["reproducible_build_trusted_public_key"].sha256,
        "production host preflight reproducibility trust-root digest does not match current artifact",
    )
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
        kms_file.get("sha256") == snapshots.by_key["kms_materials"].sha256,
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
    current_bindings = current_kms_material_bindings(
        snapshots.by_key["kms_materials"],
        snapshots,
    )
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
            "executable_digests": executable_digests,
            "python_script_digests": script_digests,
            "docker_toolchain": docker_toolchain,
            "material_digests": material_digests,
            "private_key_mode": runtime_trust.get("private_key_mode"),
            "certificate_not_after": runtime_trust.get("certificate_not_after"),
        },
        "authenticity": preflight_authenticity,
        "bootstrap_receipt": preflight_bootstrap_receipt,
        "executing_script": preflight_executing_script,
        "production_env_keys": production_env.get("env_keys") or [],
        "production_readiness_env_sha256": production_env_file.get("sha256"),
        "production_images_env_sha256": images_env_file.get("sha256"),
        "production_config_sha256": preflight_config_file.get("sha256"),
        "production_config_semantic_sha256": preflight_config_semantic_sha256,
        "production_compose_sha256": production_compose_sha256,
        "production_compose_renderer": compose_renderer,
        "production_compose_project_name": production_compose.get(
            "compose_project_name"
        ),
        "production_runtime_model": production_runtime_model,
        "release_artifact_mounts": mounted_artifacts,
        "production_image_refs": sorted(readiness_summary["production_images"]),
        "benchmark_binary_digest": benchmark_binary_digest,
        "release_security_evidence": {
            "trust_roots": policy_trust_roots,
            "policy_identity": policy_identity,
            "policy_activation": activation_evidence,
            "reproducible_builds": reproducibility_evidence,
            "benchmarkPolicyBound": release_security.get("benchmarkPolicyBound"),
        },
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
        return {**current, "skipped": True, "preflight_bound": False, "identity_recomputed": False}
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
    return {
        **current,
        "skipped": False,
        "preflight_bound": True,
        "identity_recomputed": True,
        "identity": read_current_host_identity(),
    }


def verify_current_production_env_binding(
    paths: dict[str, Path],
    snapshots: InputSnapshots,
    readiness_summary: dict[str, Any],
    preflight_summary: dict[str, Any],
    config_summary: dict[str, Any],
    *,
    verification_mode: str = "readiness",
    release_trust_inputs: dict[str, str | None] | None = None,
    final_inputs: dict[str, str | None] | None = None,
    final_file_snapshots: dict[str, FileSnapshot] | None = None,
    proxy_digest_inputs: dict[str, str | None] | None = None,
    launcher_trust_inputs: dict[str, str | None] | None = None,
    proxy_proof_max_age_seconds: int | None = None,
    p99_limit_ms: float | None = None,
    docker_executable: str | None = None,
    docker_compose_plugin_executable: str | None = None,
    docker_unix_socket: str | None = None,
    docker_daemon_id: str | None = None,
    preflight_signing_public_key: str | None = None,
    preflight_signing_key_id: str | None = None,
    preflight_max_age_seconds: int | None = None,
    remeasure_runtime_trust: bool = True,
) -> dict[str, Any]:
    env_snapshot = snapshots.by_key["production_readiness_env"]
    launcher_trust: dict[str, Any] | None = None
    if verification_mode == "final":
        require(launcher_trust_inputs is not None, "final verification is missing launcher trust inputs")
        launcher_trust = run_production_readiness.validate_launcher_trusted_env(
            env_snapshot.path,
            env_snapshot.data,
            env_snapshot.metadata,
            expected_path=launcher_trust_inputs.get(
                run_production_readiness.LAUNCHER_TRUSTED_ENV_PATH_INPUT
            ),
            expected_sha256=launcher_trust_inputs.get(
                run_production_readiness.LAUNCHER_TRUSTED_ENV_SHA256_INPUT
            ),
        )
    try:
        production_env = load_production_env_snapshot(env_snapshot)
    except Exception as exc:
        raise ValueError(f"current production readiness env is invalid: {exc}") from exc
    require(
        not run_production_readiness.LAUNCHER_TRUST_INPUT_NAMES & set(production_env),
        "out-of-band launcher trust inputs must not be defined inside the production readiness env",
    )
    if verification_mode == "final":
        launcher_trust["startup_environment_contract"] = (
            run_production_readiness.validate_final_launcher_contract(production_env)
        )
    preflight_module = load_production_host_preflight_module(
        production_env,
        final=verification_mode == "final",
    )
    raw_max_age = production_env.get(PROXY_PROOF_MAX_AGE_ENV_KEY)
    require(isinstance(raw_max_age, str), f"production readiness env must pin {PROXY_PROOF_MAX_AGE_ENV_KEY}")
    try:
        expected_proxy_proof_max_age_seconds = int(raw_max_age)
    except ValueError as exc:
        raise ValueError(f"{PROXY_PROOF_MAX_AGE_ENV_KEY} must be an integer") from exc
    require(
        1 <= expected_proxy_proof_max_age_seconds <= PROXY_PROOF_MAX_AGE_LIMIT_SECONDS,
        f"{PROXY_PROOF_MAX_AGE_ENV_KEY} must be between 1 and {PROXY_PROOF_MAX_AGE_LIMIT_SECONDS}",
    )
    raw_p99_limit = production_env.get(COMPLETION_P99_LIMIT_ENV_KEY)
    require(isinstance(raw_p99_limit, str), f"production readiness env must pin {COMPLETION_P99_LIMIT_ENV_KEY}")
    try:
        expected_p99_limit_ms = float(raw_p99_limit)
    except ValueError as exc:
        raise ValueError(f"{COMPLETION_P99_LIMIT_ENV_KEY} must be numeric") from exc
    require(
        math.isfinite(expected_p99_limit_ms) and expected_p99_limit_ms > 0,
        f"{COMPLETION_P99_LIMIT_ENV_KEY} must be finite and positive",
    )
    expected_docker_executable = production_env.get(DOCKER_EXECUTABLE_ENV_KEY)
    require(
        isinstance(expected_docker_executable, str)
        and Path(expected_docker_executable).is_absolute(),
        f"production readiness env must pin absolute {DOCKER_EXECUTABLE_ENV_KEY}",
    )
    docker_toolchain_settings = (
        run_production_readiness.validate_docker_toolchain_settings(production_env)
        if verification_mode == "final"
        else {
            DOCKER_COMPOSE_PLUGIN_EXECUTABLE_ENV_KEY: production_env.get(
                DOCKER_COMPOSE_PLUGIN_EXECUTABLE_ENV_KEY, "readiness-unbound"
            ),
            DOCKER_COMPOSE_PLUGIN_SHA256_ENV_KEY: production_env.get(
                DOCKER_COMPOSE_PLUGIN_SHA256_ENV_KEY, "sha256:" + "0" * 64
            ),
            DOCKER_UNIX_SOCKET_ENV_KEY: production_env.get(
                DOCKER_UNIX_SOCKET_ENV_KEY, "/var/run/docker.sock"
            ),
            DOCKER_DAEMON_ID_ENV_KEY: production_env.get(
                DOCKER_DAEMON_ID_ENV_KEY, "readiness-unbound"
            ),
            run_production_readiness.DOCKER_COMPOSE_PROJECT_NAME_ENV: production_env.get(
                run_production_readiness.DOCKER_COMPOSE_PROJECT_NAME_ENV,
                "serverware-production",
            ),
        }
    )
    raw_preflight_max_age = production_env.get(PREFLIGHT_MAX_AGE_ENV_KEY)
    try:
        expected_preflight_max_age = int(raw_preflight_max_age or "300")
    except ValueError as exc:
        raise ValueError(f"{PREFLIGHT_MAX_AGE_ENV_KEY} must be an integer") from exc
    require(1 <= expected_preflight_max_age <= 900, f"{PREFLIGHT_MAX_AGE_ENV_KEY} must be between 1 and 900")
    expected_preflight_public_key = production_env.get(PREFLIGHT_SIGNING_PUBLIC_KEY_ENV_KEY)
    expected_preflight_key_id = (
        require_sha256(
            production_env.get(PREFLIGHT_SIGNING_KEY_ID_ENV_KEY),
            "production host preflight signing key ID",
        )
        if verification_mode == "final"
        else production_env.get(PREFLIGHT_SIGNING_KEY_ID_ENV_KEY, "sha256:" + "0" * 64)
    )
    if verification_mode == "final":
        require(
            proxy_proof_max_age_seconds == expected_proxy_proof_max_age_seconds,
            f"selected proxy proof max age does not exactly match {PROXY_PROOF_MAX_AGE_ENV_KEY}",
        )
        require(
            p99_limit_ms == expected_p99_limit_ms,
            f"selected p99 limit does not exactly match {COMPLETION_P99_LIMIT_ENV_KEY}",
        )
        require(
            docker_executable == expected_docker_executable,
            f"selected Docker executable does not exactly match {DOCKER_EXECUTABLE_ENV_KEY}",
        )
        for selected, setting in (
            (docker_compose_plugin_executable, DOCKER_COMPOSE_PLUGIN_EXECUTABLE_ENV_KEY),
            (docker_unix_socket, DOCKER_UNIX_SOCKET_ENV_KEY),
            (docker_daemon_id, DOCKER_DAEMON_ID_ENV_KEY),
        ):
            require(
                selected == docker_toolchain_settings[setting],
                f"selected Docker setting does not exactly match {setting}",
            )
        require(
            preflight_signing_public_key == expected_preflight_public_key,
            f"selected preflight signing public key does not exactly match {PREFLIGHT_SIGNING_PUBLIC_KEY_ENV_KEY}",
        )
        require(
            preflight_signing_key_id == expected_preflight_key_id,
            f"selected preflight signing key ID does not exactly match {PREFLIGHT_SIGNING_KEY_ID_ENV_KEY}",
        )
        require(
            preflight_max_age_seconds == expected_preflight_max_age,
            f"selected preflight max age does not exactly match {PREFLIGHT_MAX_AGE_ENV_KEY}",
        )
        measured_compose_plugin = run_production_readiness.open_measured_executable(
            Path(docker_toolchain_settings[DOCKER_COMPOSE_PLUGIN_EXECUTABLE_ENV_KEY]),
            docker_toolchain_settings[DOCKER_COMPOSE_PLUGIN_SHA256_ENV_KEY],
            DOCKER_COMPOSE_PLUGIN_EXECUTABLE_ENV_KEY,
        )
        measured_compose_plugin.close()
    try:
        images_value, images = load_images_env_snapshot(
            snapshots.by_key["production_images_env"]
        )
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
    expected_proxy_principal_id = production_env.get(PROXY_PRINCIPAL_ENV_KEY)
    require(
        isinstance(expected_proxy_principal_id, str)
        and expected_proxy_principal_id == expected_proxy_principal_id.strip()
        and 1 <= len(expected_proxy_principal_id) <= 256
        and all(character.isprintable() for character in expected_proxy_principal_id),
        "production readiness expected proxy principal ID is invalid",
    )
    expected_proxy_digests = {
        env_name: require_sha256(
            production_env.get(env_name),
            f"production readiness expected proxy digest {env_name}",
        )
        for env_name in PROXY_EXPECTED_DIGEST_ENV_KEYS.values()
    }
    if verification_mode == "final":
        require(proxy_digest_inputs is not None, "final verification is missing expected proxy digest inputs")
        for attribute, env_name in PROXY_EXPECTED_DIGEST_ENV_KEYS.items():
            require(
                proxy_digest_inputs.get(attribute) == expected_proxy_digests[env_name],
                f"selected {attribute.replace('_', ' ')} does not exactly match the hashed production readiness env",
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
    raw_executable_digest_manifest = production_env.get(
        preflight_module.ATTESTATION_EXECUTABLE_DIGEST_MANIFEST_ENV
    )
    try:
        executable_digest_manifest = json.loads(str(raw_executable_digest_manifest))
    except json.JSONDecodeError as exc:
        raise ValueError(
            "production readiness attestation executable digest manifest is invalid JSON"
        ) from exc
    require(
        isinstance(executable_digest_manifest, dict)
        and set(executable_digest_manifest)
        == preflight_module.PINNED_EXECUTABLE_COMMAND_SETTINGS,
        "production readiness attestation executable digest manifest is not closed and complete",
    )
    expected_executable_digests = {
        setting: require_sha256(
            executable_digest_manifest.get(setting),
            f"production readiness executable digest pin for {setting}",
        )
        for setting in sorted(preflight_module.PINNED_EXECUTABLE_COMMAND_SETTINGS)
    }
    require(
        runtime_trust.get("executable_digests") == expected_executable_digests,
        "production host preflight executable digests do not match the hashed production readiness env pins",
    )
    current_executable_reports, current_executable_failures = (
        preflight_module.snapshot_pinned_executables(production_env)
    )
    require(
        not current_executable_failures,
        "current pinned executable remeasurement failed: " + "; ".join(current_executable_failures),
    )
    current_executable_digests = {
        item["setting"]: item["sha256"] for item in current_executable_reports
    }
    require(
        current_executable_digests == expected_executable_digests,
        "current executable bytes do not match the hashed production readiness env pins",
    )
    current_script_digests: dict[str, str] = {}
    if verification_mode == "final":
        expected_script_pins = {
            setting: production_env.get(setting)
            for setting in run_production_readiness.PINNED_PYTHON_SCRIPTS.values()
        }
        expected_script_digests = {
            setting: require_sha256(value, f"production readiness Python script digest pin {setting}")
            for setting, value in expected_script_pins.items()
        }
        require(
            runtime_trust.get("python_script_digests") == expected_script_digests,
            "production host preflight Python script digests do not match the hashed production readiness env pins",
        )
        current_script_reports, current_script_failures = preflight_module.snapshot_pinned_python_scripts(
            production_env
        )
        require(
            not current_script_failures,
            "current pinned Python script remeasurement failed: " + "; ".join(current_script_failures),
        )
        current_script_digests = {item["setting"]: item["sha256"] for item in current_script_reports}
        require(
            current_script_digests == expected_script_digests,
            "current Python script bytes do not match the hashed production readiness env pins",
        )
        if remeasure_runtime_trust:
            current_runtime_trust, current_runtime_failures = (
                preflight_module.runtime_trust_materials_check(
                    production_env,
                    skip_host_check=False,
                )
            )
            require(
                not current_runtime_failures and current_runtime_trust.get("ok") is True,
                "current runtime trust material revalidation failed: "
                + "; ".join(current_runtime_failures),
            )
            require(
                current_runtime_trust.get("material_digests")
                == runtime_trust.get("material_digests"),
                "current TLS/audit/proof material bytes differ from the authenticated production host preflight",
            )
            require(
                current_runtime_trust.get("proof_collector_key_id")
                == runtime_trust.get("proof_collector_key_id")
                and current_runtime_trust.get("proof_verifier_key_id")
                == runtime_trust.get("proof_verifier_key_id"),
                "current proof signing identities differ from the authenticated production host preflight",
            )
            require(
                current_runtime_trust.get("docker_toolchain")
                == runtime_trust.get("docker_toolchain"),
                "current Docker toolchain/daemon binding differs from the authenticated production host preflight",
            )
        require(
            preflight_summary.get("production_compose_renderer")
            == {
                "path": docker_toolchain_settings[
                    DOCKER_COMPOSE_PLUGIN_EXECUTABLE_ENV_KEY
                ],
                "sha256": docker_toolchain_settings[
                    DOCKER_COMPOSE_PLUGIN_SHA256_ENV_KEY
                ],
            },
            "authenticated preflight Compose renderer does not match the hashed production env pin",
        )
        require(
            preflight_summary.get("production_compose_project_name")
            == docker_toolchain_settings[
                run_production_readiness.DOCKER_COMPOSE_PROJECT_NAME_ENV
            ],
            "authenticated preflight Compose project name does not match the hashed production env pin",
        )
    production_readiness_env_sha256 = snapshots.by_key["production_readiness_env"].sha256
    production_images_env_sha256 = snapshots.by_key["production_images_env"].sha256
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

    require(release_trust_inputs is not None, "release completion is missing production env trust bindings")
    for env_name, label in (
        (RELEASE_PROVENANCE_TRUST_ROOT_ENV_KEY, "release provenance trust root"),
        (SIGSTORE_TRUST_ROOT_ENV_KEY, "Sigstore trust root"),
        (REKOR_TRUST_ROOT_ENV_KEY, "Rekor trust root"),
        (EXTERNAL_CHECKPOINT_TRUST_ROOT_ENV_KEY, "external checkpoint trust root"),
        (EXTERNAL_CHECKPOINT_PROVIDER_ENV_KEY, "external checkpoint provider"),
        (
            CONTROL_PLANE_RESPONSE_SIGNING_KEY_ENV_KEY,
            "control-plane response signing trust root",
        ),
        (
            CONTROL_PLANE_RESPONSE_SIGNING_KEY_ID_ENV_KEY,
            "control-plane response signing expected SPKI identity",
        ),
        (
            run_production_readiness.POLICY_TRUST_ROOT_ENV,
            "policy identity trust root",
        ),
        (
            run_production_readiness.POLICY_TRUST_ROOT_ID_ENV,
            "policy identity expected SPKI identity",
        ),
        (
            run_production_readiness.POLICY_ACTIVATION_TRUST_ROOT_ENV,
            "policy activation trust root",
        ),
        (
            run_production_readiness.POLICY_ACTIVATION_TRUST_ROOT_ID_ENV,
            "policy activation expected SPKI identity",
        ),
        (
            run_production_readiness.REPRODUCIBLE_BUILD_TRUST_ROOT_ENV,
            "reproducible-build trust root",
        ),
        (
            run_production_readiness.REPRODUCIBLE_BUILD_TRUST_ROOT_ID_ENV,
            "reproducible-build expected SPKI identity",
        ),
    ):
        if (
            verification_mode != "final"
            and env_name
            in {
                run_production_readiness.POLICY_TRUST_ROOT_ENV,
                run_production_readiness.POLICY_TRUST_ROOT_ID_ENV,
                run_production_readiness.POLICY_ACTIVATION_TRUST_ROOT_ENV,
                run_production_readiness.POLICY_ACTIVATION_TRUST_ROOT_ID_ENV,
                run_production_readiness.REPRODUCIBLE_BUILD_TRUST_ROOT_ENV,
                run_production_readiness.REPRODUCIBLE_BUILD_TRUST_ROOT_ID_ENV,
            }
        ):
            continue
        selected = release_trust_inputs.get(env_name)
        require(isinstance(selected, str) and bool(selected), f"release completion is missing the selected {label}")
        require(
            production_env.get(env_name) == selected,
            f"selected {label} does not exactly match the hashed production readiness env",
        )
    try:
        release_provenance_trust_root_id = release_public_key_id(
            snapshot_text(snapshots.by_key["release_provenance_trusted_public_key"], "release provenance trust root", encoding="ascii")
        )
        sigstore_trust_root_id = release_public_key_id(
            snapshot_text(snapshots.by_key["sigstore_trusted_public_key"], "Sigstore trust root", encoding="ascii")
        )
        rekor_trust_root_id = release_public_key_id(
            snapshot_text(snapshots.by_key["rekor_trusted_public_key"], "Rekor trust root", encoding="ascii")
        )
        external_checkpoint_trust_root_id = release_public_key_id(
            snapshot_text(snapshots.by_key["external_checkpoint_trusted_public_key"], "external checkpoint trust root", encoding="ascii")
        )
        policy_trust_root_id = release_public_key_id(
            snapshot_text(
                snapshots.by_key["policy_trusted_public_key"],
                "policy identity trust root",
                encoding="ascii",
            )
        )
        policy_activation_trust_root_id = release_public_key_id(
            snapshot_text(
                snapshots.by_key["policy_activation_trusted_public_key"],
                "policy activation trust root",
                encoding="ascii",
            )
        )
        reproducible_build_trust_root_id = release_public_key_id(
            snapshot_text(
                snapshots.by_key["reproducible_build_trusted_public_key"],
                "reproducible-build trust root",
                encoding="ascii",
            )
        )
    except Exception as exc:
        raise ValueError(f"production readiness env release trust root is unreadable or invalid: {exc}") from exc
    require(
        final_file_snapshots is not None,
        "release completion is missing immutable control-plane response signing snapshots",
    )
    try:
        control_plane_response_signing_public_key_pem = snapshot_text(
            final_file_snapshots[
                "control_plane_response_signing_public_key"
            ],
            "control-plane response signing trust root",
            encoding="ascii",
        )
    except KeyError as exc:
        raise ValueError(
            f"release completion is missing immutable control-plane response signing trust-root snapshot: {exc}"
        ) from exc
    control_plane_response_signing_key_id = ed25519_public_key_id(
        control_plane_response_signing_public_key_pem,
        "control-plane response signing trust root",
    )
    expected_control_plane_response_signing_key_id = require_sha256(
        production_env.get(CONTROL_PLANE_RESPONSE_SIGNING_KEY_ID_ENV_KEY),
        "production readiness expected control-plane response signing SPKI identity",
    )
    require(
        hmac.compare_digest(
            control_plane_response_signing_key_id,
            expected_control_plane_response_signing_key_id,
        ),
        "control-plane response signing trust root does not match the independently configured SPKI identity",
    )
    policy_role_ids = {
        "policy_identity": policy_trust_root_id,
        "policy_activation": policy_activation_trust_root_id,
        "reproducible_build": reproducible_build_trust_root_id,
    }
    policy_role_settings = {
        "policy_identity": run_production_readiness.POLICY_TRUST_ROOT_ID_ENV,
        "policy_activation": run_production_readiness.POLICY_ACTIVATION_TRUST_ROOT_ID_ENV,
        "reproducible_build": run_production_readiness.REPRODUCIBLE_BUILD_TRUST_ROOT_ID_ENV,
    }
    for role, key_id in policy_role_ids.items():
        if verification_mode == "final":
            require(
                hmac.compare_digest(
                    key_id,
                    require_sha256(
                        production_env.get(policy_role_settings[role]),
                        f"production readiness {role} expected SPKI identity",
                    ),
                ),
                f"{role} trust-root bytes do not match the hashed production env SPKI pin",
            )
            preflight_role = nested(
                preflight_summary,
                "release_security_evidence",
                "trust_roots",
                role,
            )
            require(
                isinstance(preflight_role, dict)
                and preflight_role.get("spki_sha256") == key_id
                and preflight_role.get("sha256")
                == snapshots.by_key[
                    {
                        "policy_identity": "policy_trusted_public_key",
                        "policy_activation": "policy_activation_trusted_public_key",
                        "reproducible_build": "reproducible_build_trusted_public_key",
                    }[role]
                ].sha256,
                f"current {role} trust root differs from the authenticated preflight",
            )
    existing_release_trust_root_ids = {
        release_provenance_trust_root_id,
        sigstore_trust_root_id,
        rekor_trust_root_id,
        external_checkpoint_trust_root_id,
    }
    require(
        control_plane_response_signing_key_id
        not in existing_release_trust_root_ids,
        "control-plane responses must use an independent signing public key",
    )
    if verification_mode == "final":
        require(
            len(set(policy_role_ids.values())) == len(policy_role_ids),
            "policy identity, activation, and reproducible-build roles must use distinct public keys",
        )
    release_trust_binding = {
        "release_trust_roots_env_bound": True,
        "release_provenance_trusted_public_key_id": release_provenance_trust_root_id,
        "sigstore_trusted_public_key_id": sigstore_trust_root_id,
        "rekor_trusted_public_key_id": rekor_trust_root_id,
        "external_checkpoint_trusted_public_key_id": external_checkpoint_trust_root_id,
        "external_checkpoint_provider": production_env[EXTERNAL_CHECKPOINT_PROVIDER_ENV_KEY],
        "control_plane_response_signing_public_key_id": (
            control_plane_response_signing_key_id
        ),
        "policy_trusted_public_key_id": policy_trust_root_id,
        "policy_activation_trusted_public_key_id": policy_activation_trust_root_id,
        "reproducible_build_trusted_public_key_id": (
            reproducible_build_trust_root_id
        ),
    }

    final_trust_binding: dict[str, Any] = {
        "verification_mode": verification_mode,
        "final_trust_roots_env_bound": False,
    }
    if verification_mode == "final":
        require(final_inputs is not None, "final verification mode is missing final input bindings")
        require(
            production_env.get(FINAL_MODE_ENV_KEY) == "final",
            f"production readiness env must set {FINAL_MODE_ENV_KEY}=final for final verification",
        )
        for env_name, label in (
            (FINAL_HARDWARE_ASSURANCE_ENV_KEY, "hardware assurance evidence"),
            (FINAL_HARDWARE_TRUST_ROOT_ENV_KEY, "hardware assurance trust root"),
            (FINAL_HARDWARE_TRUST_ROOT_ID_ENV_KEY, "hardware assurance expected SPKI identity"),
            (FINAL_CHALLENGE_RECEIPT_ENV_KEY, "final challenge receipt"),
            (FINAL_CHALLENGE_AUTHORITY_TRUST_ROOT_ENV_KEY, "final challenge authority trust root"),
            (
                FINAL_CHALLENGE_AUTHORITY_TRUST_ROOT_ID_ENV_KEY,
                "final challenge authority expected SPKI identity",
            ),
            (FINAL_CHALLENGE_AUTHORITY_PROVIDER_ENV_KEY, "final challenge authority provider"),
        ):
            selected = final_inputs.get(env_name)
            require(
                isinstance(selected, str) and bool(selected),
                f"final verification is missing the selected {label}",
            )
            require(
                production_env.get(env_name) == selected,
                f"selected {label} does not exactly match the hashed production readiness env",
            )
        env_challenge_nonce = production_env.get(FINAL_HARDWARE_CHALLENGE_NONCE_ENV_KEY)
        env_challenge_digest = production_env.get(FINAL_HARDWARE_CHALLENGE_DIGEST_ENV_KEY)
        require(
            bool(env_challenge_nonce) != bool(env_challenge_digest),
            "hashed production readiness env must pin exactly one hardware assurance expected challenge nonce or digest",
        )
        selected_challenge_nonce = final_inputs.get(FINAL_HARDWARE_CHALLENGE_NONCE_ENV_KEY)
        selected_challenge_digest = final_inputs.get(FINAL_HARDWARE_CHALLENGE_DIGEST_ENV_KEY)
        require(
            bool(selected_challenge_nonce) != bool(selected_challenge_digest),
            "final verification must select exactly one hardware assurance expected challenge nonce or digest",
        )
        require(
            env_challenge_nonce == selected_challenge_nonce
            and env_challenge_digest == selected_challenge_digest,
            "selected hardware assurance expected challenge does not exactly match the hashed production readiness env",
        )
        require(final_file_snapshots is not None, "final verification is missing immutable final-file snapshots")
        try:
            hardware_trust_root_pem = snapshot_text(
                final_file_snapshots["hardware_assurance_trusted_public_key"],
                "hardware assurance trust root",
                encoding="ascii",
            )
            authority_trust_root_pem = snapshot_text(
                final_file_snapshots["final_challenge_authority_public_key"],
                "final challenge authority trust root",
                encoding="ascii",
            )
        except KeyError as exc:
            raise ValueError(f"final verification is missing immutable trust-root snapshot: {exc}") from exc
        hardware_trust_root_id = release_public_key_id(hardware_trust_root_pem)
        authority_trust_root_id = release_public_key_id(authority_trust_root_pem)
        expected_hardware_trust_root_id = require_sha256(
            production_env.get(FINAL_HARDWARE_TRUST_ROOT_ID_ENV_KEY),
            "production readiness expected hardware assurance verifier SPKI identity",
        )
        expected_authority_trust_root_id = require_sha256(
            production_env.get(FINAL_CHALLENGE_AUTHORITY_TRUST_ROOT_ID_ENV_KEY),
            "production readiness expected final challenge authority SPKI identity",
        )
        require(
            hmac.compare_digest(hardware_trust_root_id, expected_hardware_trust_root_id),
            "hardware assurance verifier key bytes do not match the independently configured SPKI identity",
        )
        require(
            hmac.compare_digest(authority_trust_root_id, expected_authority_trust_root_id),
            "final challenge authority key bytes do not match the independently configured SPKI identity",
        )
        require(
            not hmac.compare_digest(hardware_trust_root_id, authority_trust_root_id),
            "hardware assurance verifier and final challenge authority must use different public keys",
        )
        release_role_ids = {
            release_trust_binding["release_provenance_trusted_public_key_id"],
            release_trust_binding["sigstore_trusted_public_key_id"],
            release_trust_binding["rekor_trusted_public_key_id"],
            release_trust_binding["external_checkpoint_trusted_public_key_id"],
            release_trust_binding[
                "control_plane_response_signing_public_key_id"
            ],
            release_trust_binding["policy_trusted_public_key_id"],
            release_trust_binding["policy_activation_trusted_public_key_id"],
            release_trust_binding["reproducible_build_trusted_public_key_id"],
        }
        require(
            hardware_trust_root_id not in release_role_ids,
            "hardware assurance verifier must not reuse a release trust public key",
        )
        require(
            authority_trust_root_id not in release_role_ids,
            "final challenge authority must not reuse a release trust public key",
        )
        final_trust_binding = {
            "verification_mode": verification_mode,
            "final_trust_roots_env_bound": True,
            "hardware_assurance_trusted_public_key_id": hardware_trust_root_id,
            "final_challenge_authority_public_key_id": authority_trust_root_id,
            "final_challenge_authority_provider": production_env[FINAL_CHALLENGE_AUTHORITY_PROVIDER_ENV_KEY],
            "hardware_assurance_expected_challenge_selector": (
                "nonce" if env_challenge_nonce is not None else "nonce_sha256"
            ),
        }
    return {
        **release_trust_binding,
        **final_trust_binding,
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
        "expected_proxy_principal_id": expected_proxy_principal_id,
        "expected_proxy_collector_key_id": expected_collector_key_id,
        "expected_proxy_verifier_key_id": expected_verifier_key_id,
        "current_executable_digests": current_executable_digests,
        "current_python_script_digests": current_script_digests,
        "launcher_trust": launcher_trust,
        "proxy_proof_max_age_seconds": expected_proxy_proof_max_age_seconds,
        "p99_limit_ms": expected_p99_limit_ms,
        "docker_executable": expected_docker_executable,
        "docker_compose_plugin_executable": docker_toolchain_settings[
            DOCKER_COMPOSE_PLUGIN_EXECUTABLE_ENV_KEY
        ],
        "docker_compose_plugin_sha256": docker_toolchain_settings[
            DOCKER_COMPOSE_PLUGIN_SHA256_ENV_KEY
        ],
        "docker_unix_socket": docker_toolchain_settings[DOCKER_UNIX_SOCKET_ENV_KEY],
        "docker_daemon_id": docker_toolchain_settings[DOCKER_DAEMON_ID_ENV_KEY],
        "docker_compose_project_name": docker_toolchain_settings[
            run_production_readiness.DOCKER_COMPOSE_PROJECT_NAME_ENV
        ],
        "production_host_preflight_signing_public_key": expected_preflight_public_key,
        "production_host_preflight_signing_key_id": expected_preflight_key_id,
        "production_host_preflight_max_age_seconds": expected_preflight_max_age,
        **expected_proxy_digests,
    }


def verify_current_interpreter_binding(
    production_env: dict[str, str],
    executable_digests: dict[str, str],
) -> dict[str, Any]:
    setting = run_production_readiness.PRODUCTION_PYTHON_EXECUTABLE_ENV
    configured_path = production_env.get(setting)
    require(
        isinstance(configured_path, str) and Path(configured_path).is_absolute(),
        f"production readiness env must pin absolute {setting}",
    )
    expected_digest = executable_digests.get(setting)
    require(isinstance(expected_digest, str), "production Python digest pin is missing")
    measured = run_production_readiness.open_measured_executable(
        Path(configured_path),
        expected_digest,
        setting,
    )
    try:
        if sys.platform.startswith("linux"):
            descriptor = os.open("/proc/self/exe", os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
            source = "/proc/self/exe"
            try:
                current_metadata = os.fstat(descriptor)
                current_bytes = run_production_readiness.read_fd_bytes(
                    descriptor,
                    current_metadata,
                    "currently executing Python interpreter",
                    max_bytes=run_production_readiness.MAX_EXECUTABLE_BYTES,
                )
            finally:
                os.close(descriptor)
        else:
            current_path = Path(sys.executable).resolve()
            current_bytes, current_metadata = run_production_readiness.read_regular_file_once(
                current_path,
                "currently executing Python interpreter",
                max_bytes=run_production_readiness.MAX_EXECUTABLE_BYTES,
                executable=True,
            )
            source = str(current_path)
        current_digest = sha256_prefixed_bytes(current_bytes)
        require(
            hmac.compare_digest(current_digest, measured.sha256),
            "currently executing interpreter bytes do not match the production Python pin",
        )
        require(
            (current_metadata.st_dev, current_metadata.st_ino)
            == (measured.metadata.st_dev, measured.metadata.st_ino),
            "currently executing interpreter inode does not match the production Python pin",
        )
        return {
            "path": configured_path,
            "sha256": current_digest,
            "device": current_metadata.st_dev,
            "inode": current_metadata.st_ino,
            "measured_from": source,
            "matches_pinned_path_inode": True,
        }
    finally:
        measured.close()


def verify_current_script_binding(production_env: dict[str, str]) -> dict[str, Any]:
    setting = run_production_readiness.VERIFY_RELEASE_COMPLETION_SCRIPT_SHA256_ENV
    expected_digest = require_sha256(
        production_env.get(setting),
        "release completion verifier script digest pin",
    )
    raw_descriptor = os.environ.get("SERVERWARE_EXECUTING_SCRIPT_FD")
    require(
        isinstance(raw_descriptor, str) and raw_descriptor.isdigit(),
        "final verifier was not launched from a retained measured script descriptor",
    )
    descriptor = int(raw_descriptor)
    metadata = os.fstat(descriptor)
    os.lseek(descriptor, 0, os.SEEK_SET)
    data = run_production_readiness.read_fd_bytes(
        descriptor,
        metadata,
        "currently executing release completion verifier script",
        max_bytes=run_production_readiness.MAX_EXECUTABLE_BYTES,
    )
    digest = sha256_prefixed_bytes(data)
    require(
        hmac.compare_digest(digest, expected_digest),
        "currently executing release completion verifier script does not match the hashed env pin",
    )
    configured = run_production_readiness.open_measured_script(
        (Path(__file__).resolve().parent / "verify_release_completion.py"),
        expected_digest,
        setting,
    )
    try:
        require(
            (metadata.st_dev, metadata.st_ino)
            == (configured.metadata.st_dev, configured.metadata.st_ino),
            "currently executing release completion verifier script inode differs from the pinned path",
        )
    finally:
        configured.close()
    return {
        "path": str((Path(__file__).resolve().parent / "verify_release_completion.py")),
        "sha256": digest,
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "measured_from": f"/proc/self/fd/{descriptor}",
        "matches_pinned_path_inode": True,
    }


def hashed_environment_from_docker(
    value: Any,
    label: str,
) -> list[dict[str, str]]:
    require(isinstance(value, list), f"{label} environment must be a list")
    variables: dict[str, str] = {}
    for item in value:
        require(
            isinstance(item, str) and "=" in item,
            f"{label} environment entry is invalid",
        )
        name, rendered = item.split("=", 1)
        require(
            bool(name) and "=" not in name and name not in variables,
            f"{label} environment has an invalid or duplicate name",
        )
        variables[name] = sha256_prefixed_bytes(rendered.encode("utf-8"))
    return [
        {"name": name, "value_sha256": variables[name]}
        for name in sorted(variables)
    ]


def merged_expected_environment(
    image_environment: Any,
    compose_environment: Any,
    label: str,
) -> list[dict[str, str]]:
    merged = {
        item["name"]: item["value_sha256"]
        for item in hashed_environment_from_docker(
            image_environment or [], f"{label} image"
        )
    }
    require(
        isinstance(compose_environment, list),
        f"{label} signed Compose environment must be a list",
    )
    for item in compose_environment:
        require(
            isinstance(item, dict)
            and set(item) == {"name", "value_sha256"},
            f"{label} signed Compose environment entry is invalid",
        )
        merged[str(item["name"])] = require_sha256(
            item.get("value_sha256"),
            f"{label} signed Compose environment value",
        )
    return [
        {"name": name, "value_sha256": merged[name]} for name in sorted(merged)
    ]


def compose_resource_runtime_name(
    logical_name: str,
    resources: dict[str, Any],
    project_name: str,
) -> str:
    resource = resources.get(logical_name)
    require(isinstance(resource, dict), f"signed Compose resource is missing: {logical_name}")
    explicit_name = resource.get("name")
    if isinstance(explicit_name, str) and explicit_name:
        return explicit_name
    if resource.get("external") is True:
        return logical_name
    return f"{project_name}_{logical_name}"


def normalized_security_options(
    values: Any,
    *,
    project_directory: Path,
) -> list[str]:
    require(
        values is None
        or (isinstance(values, list) and all(isinstance(item, str) for item in values)),
        "container security options must be a string list",
    )
    normalized: list[str] = []
    for item in values or []:
        if item.startswith("seccomp="):
            prefix, raw_path = item.split("=", 1)
            path = Path(raw_path)
            if not path.is_absolute() and raw_path not in {"unconfined", "default"}:
                path = (project_directory / path).resolve()
                item = f"{prefix}={path}"
        normalized.append(item)
    return sorted(normalized)


def normalize_expected_ports(value: Any, label: str) -> list[dict[str, str]]:
    require(isinstance(value, list), f"{label} ports must be a list")
    normalized: list[dict[str, str]] = []
    for item in value:
        require(isinstance(item, dict), f"{label} port entry must be an object")
        target = item.get("target")
        published = item.get("published")
        require(
            isinstance(target, int) and 1 <= target <= 65535,
            f"{label} target port is invalid",
        )
        require(published is not None, f"{label} published port is required")
        normalized.append(
            {
                "target": str(target),
                "published": str(published),
                "host_ip": str(item.get("host_ip") or ""),
                "protocol": str(item.get("protocol") or "tcp"),
            }
        )
    return sorted(
        normalized,
        key=lambda item: (
            item["target"],
            item["protocol"],
            item["host_ip"],
            item["published"],
        ),
    )


def normalize_observed_ports(value: Any, label: str) -> list[dict[str, str]]:
    require(isinstance(value, dict), f"{label} port bindings must be an object")
    normalized: list[dict[str, str]] = []
    for container_port, bindings in value.items():
        require(
            isinstance(container_port, str) and "/" in container_port,
            f"{label} container port is invalid",
        )
        target, protocol = container_port.rsplit("/", 1)
        require(isinstance(bindings, list), f"{label} port bindings are invalid")
        for binding in bindings:
            require(isinstance(binding, dict), f"{label} port binding is invalid")
            normalized.append(
                {
                    "target": target,
                    "published": str(binding.get("HostPort") or ""),
                    "host_ip": str(binding.get("HostIp") or ""),
                    "protocol": protocol,
                }
            )
    return sorted(
        normalized,
        key=lambda item: (
            item["target"],
            item["protocol"],
            item["host_ip"],
            item["published"],
        ),
    )


def normalize_expected_ulimits(value: Any, label: str) -> list[dict[str, int | str]]:
    require(isinstance(value, dict), f"{label} ulimits must be an object")
    normalized: list[dict[str, int | str]] = []
    for name, limits in sorted(value.items()):
        require(isinstance(limits, dict), f"{label} ulimit {name} is invalid")
        normalized.append(
            {
                "name": name,
                "soft": int(limits.get("soft", 0)),
                "hard": int(limits.get("hard", 0)),
            }
        )
    return normalized


def normalize_observed_ulimits(value: Any, label: str) -> list[dict[str, int | str]]:
    require(isinstance(value, list), f"{label} ulimits must be a list")
    normalized = []
    for item in value:
        require(isinstance(item, dict), f"{label} ulimit entry is invalid")
        normalized.append(
            {
                "name": str(item.get("Name") or ""),
                "soft": int(item.get("Soft")),
                "hard": int(item.get("Hard")),
            }
        )
    return sorted(normalized, key=lambda item: str(item["name"]))


def normalize_expected_mounts(
    service_model: dict[str, Any],
    runtime_model: dict[str, Any],
    image_config: dict[str, Any],
    project_name: str,
) -> list[dict[str, Any]]:
    expected: list[dict[str, Any]] = []
    destinations: set[str] = set()
    for item in service_model.get("mounts") or []:
        require(isinstance(item, dict), "signed Compose mount entry is invalid")
        mount_type = item.get("type")
        target = item.get("target")
        require(
            mount_type in {"bind", "volume", "tmpfs"}
            and isinstance(target, str)
            and target.startswith("/")
            and target not in destinations,
            "signed Compose mount destination is invalid or duplicated",
        )
        destinations.add(target)
        source = str(item.get("source") or "")
        if mount_type == "volume":
            source = compose_resource_runtime_name(
                source,
                runtime_model.get("volumes") or {},
                project_name,
            )
        bind = item.get("bind") if isinstance(item.get("bind"), dict) else {}
        expected.append(
            {
                "type": mount_type,
                "source": source,
                "target": target,
                "read_only": bool(item.get("read_only", False)),
                "propagation": str(bind.get("propagation") or ("rprivate" if mount_type == "bind" else "")),
            }
        )
    image_volumes = image_config.get("Volumes") or {}
    require(isinstance(image_volumes, dict), "image volume defaults must be an object")
    for target in image_volumes:
        require(isinstance(target, str) and target.startswith("/"), "image volume destination is invalid")
        if target not in destinations:
            expected.append(
                {
                    "type": "volume",
                    "source": "<anonymous>",
                    "target": target,
                    "read_only": False,
                    "propagation": "",
                }
            )
    for item in service_model.get("tmpfs") or []:
        require(isinstance(item, dict), "signed Compose tmpfs entry is invalid")
        target = item.get("target")
        require(
            isinstance(target, str) and target.startswith("/") and target not in destinations,
            "signed Compose tmpfs destination is invalid or duplicated",
        )
        options = item.get("options") or []
        destinations.add(target)
        expected.append(
            {
                "type": "tmpfs",
                "source": "",
                "target": target,
                "read_only": "ro" in options and "rw" not in options,
                "propagation": "",
            }
        )
    return sorted(expected, key=lambda item: item["target"])


def normalize_observed_mounts(value: Any, label: str) -> list[dict[str, Any]]:
    require(isinstance(value, list), f"{label} mounts must be a list")
    normalized: list[dict[str, Any]] = []
    destinations: set[str] = set()
    for item in value:
        require(isinstance(item, dict), f"{label} mount entry is invalid")
        mount_type = item.get("Type")
        target = item.get("Destination")
        require(
            mount_type in {"bind", "volume", "tmpfs"}
            and isinstance(target, str)
            and target not in destinations,
            f"{label} mount type or destination is invalid",
        )
        destinations.add(target)
        source = item.get("Name") if mount_type == "volume" else item.get("Source")
        normalized.append(
            {
                "type": mount_type,
                "source": str(source or ""),
                "target": target,
                "read_only": item.get("RW") is not True,
                "propagation": str(item.get("Propagation") or ""),
            }
        )
    return sorted(normalized, key=lambda item: item["target"])


def mount_projections_match(
    expected: list[dict[str, Any]],
    observed: list[dict[str, Any]],
) -> bool:
    if len(expected) != len(observed):
        return False
    for expected_item, observed_item in zip(expected, observed):
        if expected_item["source"] == "<anonymous>":
            if not observed_item["source"]:
                return False
            expected_item = {**expected_item, "source": observed_item["source"]}
        if expected_item != observed_item:
            return False
    return True


def normalized_tmpfs_mapping(value: Any, label: str) -> list[dict[str, Any]]:
    require(isinstance(value, dict), f"{label} tmpfs must be an object")
    return sorted(
        (
            {
                "target": str(target),
                "options": run_production_readiness.normalize_tmpfs_options(
                    str(options).split(",")
                ),
            }
            for target, options in value.items()
        ),
        key=lambda item: item["target"],
    )


def expected_runtime_projection(
    service: str,
    service_model: dict[str, Any],
    runtime_model: dict[str, Any],
    image_config: dict[str, Any],
    *,
    project_name: str,
    project_directory: Path,
) -> dict[str, Any]:
    image_user = str(image_config.get("User") or "")
    compose_user = str(service_model.get("compose_user") or "")
    effective_user = compose_user or image_user
    require(
        effective_user == service_model.get("required_runtime_user"),
        f"production service {service} effective image/Compose user is not the fixed final user",
    )
    image_entrypoint = run_production_readiness.normalize_command_value(
        image_config.get("Entrypoint"), f"{service} image entrypoint"
    )
    image_command = run_production_readiness.normalize_command_value(
        image_config.get("Cmd"), f"{service} image command"
    )
    entrypoint = service_model.get("entrypoint")
    command = service_model.get("command")
    networks = [
        compose_resource_runtime_name(
            name,
            runtime_model.get("networks") or {},
            project_name,
        )
        for name in service_model.get("networks") or []
    ]
    host = service_model.get("host_config")
    require(isinstance(host, dict), f"production service {service} host config is invalid")
    expected_network_mode = str(host.get("network_mode") or "")
    if not expected_network_mode and networks:
        logical_networks = service_model.get("networks") or []
        primary = "default" if "default" in logical_networks else logical_networks[0]
        expected_network_mode = compose_resource_runtime_name(
            primary,
            runtime_model.get("networks") or {},
            project_name,
        )
    expected_ports = normalize_expected_ports(service_model.get("ports") or [], service)
    exposed_ports = set(str(item) for item in (image_config.get("ExposedPorts") or {}))
    exposed_ports.update(
        f"{item['target']}/{item['protocol']}" for item in expected_ports
    )
    return {
        "user": effective_user,
        "entrypoint": image_entrypoint if entrypoint is None else entrypoint,
        "command": image_command if command is None else command,
        "working_dir": str(service_model.get("working_dir") or image_config.get("WorkingDir") or ""),
        "environment": merged_expected_environment(
            image_config.get("Env") or [],
            service_model.get("environment") or [],
            service,
        ),
        "devices": service_model.get("devices") or [],
        "networks": sorted(networks),
        "mounts": normalize_expected_mounts(
            service_model, runtime_model, image_config, project_name
        ),
        "tmpfs": service_model.get("tmpfs") or [],
        "ports": expected_ports,
        "exposed_ports": sorted(exposed_ports),
        "links": service_model.get("links") or [],
        "host_config": {
            "read_only": bool(host.get("read_only")),
            "privileged": bool(host.get("privileged")),
            "publish_all_ports": False,
            "cap_add": sorted(host.get("cap_add") or []),
            "cap_drop": sorted(host.get("cap_drop") or []),
            "security_opt": normalized_security_options(
                host.get("security_opt"), project_directory=project_directory
            ),
            "pids_limit": int(host.get("pids_limit") or 0),
            "memory": int(host.get("memory") or 0),
            "init": bool(host.get("init")),
            "group_add": sorted(host.get("group_add") or []),
            "volumes_from": sorted(host.get("volumes_from") or []),
            "dns": sorted(host.get("dns") or []),
            "dns_search": sorted(host.get("dns_search") or []),
            "dns_opt": sorted(host.get("dns_opt") or []),
            "extra_hosts": sorted(host.get("extra_hosts") or []),
            "pid": str(host.get("pid") or ""),
            "ipc": str(host.get("ipc") or ""),
            "uts": str(host.get("uts") or ""),
            "network_mode": expected_network_mode,
            "userns_mode": str(host.get("userns_mode") or ""),
            "ulimits": normalize_expected_ulimits(host.get("ulimits") or {}, service),
        },
    }


def observed_runtime_projection(
    service: str,
    container: dict[str, Any],
    *,
    project_directory: Path,
) -> dict[str, Any]:
    config = container.get("Config")
    host = container.get("HostConfig")
    network_settings = container.get("NetworkSettings")
    require(isinstance(config, dict), f"production service {service} Config is invalid")
    require(isinstance(host, dict), f"production service {service} HostConfig is invalid")
    require(
        isinstance(network_settings, dict)
        and isinstance(network_settings.get("Networks"), dict),
        f"production service {service} NetworkSettings is invalid",
    )
    devices = []
    for item in host.get("Devices") or []:
        require(isinstance(item, dict), f"production service {service} device is invalid")
        devices.append(
            {
                "source": str(item.get("PathOnHost") or ""),
                "target": str(item.get("PathInContainer") or ""),
                "permissions": str(item.get("CgroupPermissions") or ""),
            }
        )
    projection = {
        "user": str(config.get("User") or ""),
        "entrypoint": run_production_readiness.normalize_command_value(
            config.get("Entrypoint"), f"{service} runtime entrypoint"
        ),
        "command": run_production_readiness.normalize_command_value(
            config.get("Cmd"), f"{service} runtime command"
        ),
        "working_dir": str(config.get("WorkingDir") or ""),
        "environment": hashed_environment_from_docker(
            config.get("Env") or [], f"{service} runtime"
        ),
        "devices": sorted(
            devices,
            key=lambda item: (item["target"], item["source"], item["permissions"]),
        ),
        "networks": sorted(network_settings["Networks"]),
        "mounts": normalize_observed_mounts(container.get("Mounts") or [], service),
        "tmpfs": normalized_tmpfs_mapping(host.get("Tmpfs") or {}, service),
        "ports": normalize_observed_ports(host.get("PortBindings") or {}, service),
        "exposed_ports": sorted((config.get("ExposedPorts") or {}).keys()),
        "links": sorted(host.get("Links") or []),
        "host_config": {
            "read_only": host.get("ReadonlyRootfs") is True,
            "privileged": host.get("Privileged") is True,
            "publish_all_ports": host.get("PublishAllPorts") is True,
            "cap_add": sorted(host.get("CapAdd") or []),
            "cap_drop": sorted(host.get("CapDrop") or []),
            "security_opt": normalized_security_options(
                host.get("SecurityOpt"), project_directory=project_directory
            ),
            "pids_limit": int(host.get("PidsLimit") or 0),
            "memory": int(host.get("Memory") or 0),
            "init": host.get("Init") is True,
            "group_add": sorted(str(item) for item in (host.get("GroupAdd") or [])),
            "volumes_from": sorted(host.get("VolumesFrom") or []),
            "dns": sorted(host.get("Dns") or []),
            "dns_search": sorted(host.get("DnsSearch") or []),
            "dns_opt": sorted(host.get("DnsOptions") or []),
            "extra_hosts": sorted(host.get("ExtraHosts") or []),
            "pid": str(host.get("PidMode") or ""),
            "ipc": str(host.get("IpcMode") or ""),
            "uts": str(host.get("UTSMode") or ""),
            "network_mode": str(host.get("NetworkMode") or ""),
            "userns_mode": str(host.get("UsernsMode") or ""),
            "ulimits": normalize_observed_ulimits(host.get("Ulimits") or [], service),
        },
    }
    return projection


def verify_runtime_projection(
    service: str,
    expected: dict[str, Any],
    observed: dict[str, Any],
) -> None:
    expected_without_mounts = {key: value for key, value in expected.items() if key != "mounts"}
    observed_without_mounts = {key: value for key, value in observed.items() if key != "mounts"}
    require(
        observed_without_mounts == expected_without_mounts,
        f"production service {service} runtime projection differs from signed Compose and pinned image defaults",
    )
    require(
        mount_projections_match(expected["mounts"], observed["mounts"]),
        f"production service {service} complete mount projection differs from signed Compose and pinned image defaults",
    )


def parse_container_copy_archive(
    archive: bytes,
    *,
    expected_sha256: str,
    expected_bytes: int,
    label: str,
) -> dict[str, Any]:
    require(
        0 < expected_bytes <= COMPLETION_INPUT_MAX_BYTES,
        f"{label} approved artifact length is invalid",
    )
    require(
        0 < len(archive) <= expected_bytes + 1024 * 1024,
        f"{label} Docker copy archive is empty or too large",
    )
    try:
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:*") as bundle:
            members = bundle.getmembers()
            require(
                len(members) == 1 and members[0].isreg(),
                f"{label} Docker copy archive must contain exactly one regular file",
            )
            member = members[0]
            require(
                member.size == expected_bytes,
                f"{label} container artifact length differs from the approved snapshot",
            )
            extracted = bundle.extractfile(member)
            require(extracted is not None, f"{label} Docker copy archive member is unreadable")
            data = extracted.read(expected_bytes + 1)
    except (tarfile.TarError, OSError) as exc:
        raise ValueError(f"{label} Docker copy archive is invalid: {exc}") from exc
    require(
        len(data) == expected_bytes,
        f"{label} Docker copy archive member length is invalid",
    )
    digest = sha256_prefixed_bytes(data)
    require(
        hmac.compare_digest(digest, require_sha256(expected_sha256, label)),
        f"{label} container-visible bytes differ from the approved snapshot",
    )
    return {
        "sha256": digest,
        "bytes": len(data),
        "tar_members": 1,
        "regular_file": True,
        "container_namespace_verified": True,
    }


def require_stable_container_generation(
    before: dict[str, Any],
    after: dict[str, Any],
) -> None:
    require(
        before == after,
        "production Compose service IDs, running StartedAt values, or runtime projections changed during inspection",
    )


def verify_running_production_containers(
    *,
    env_file: Path,
    compose_file: Path,
    production_env: dict[str, str],
    project_directory: Path,
    production_image_refs: list[str],
    source_tree_digest: str,
    runtime_model: dict[str, Any],
    artifact_expectations: dict[str, dict[str, Any]],
    compose_project_name: str,
    skip_current_host_check: bool,
    docker_executable: str,
    docker_sha256: str,
    compose_plugin_executable: str,
    compose_plugin_sha256: str,
    docker_unix_socket: str,
    docker_daemon_id: str,
    final_mode: bool,
) -> dict[str, Any]:
    if skip_current_host_check:
        return {"ok": True, "skipped": True, "containers": []}
    require(final_mode, "live production container verification requires final mode")
    require(
        runtime_model.get("sha256")
        == sha256_prefixed_bytes(
            canonical_json(
                {
                    key: runtime_model[key]
                    for key in ("services", "networks", "volumes")
                }
            ).encode("utf-8")
        ),
        "signed normalized runtime model digest is invalid",
    )
    services_model = runtime_model.get("services")
    require(
        isinstance(services_model, dict)
        and set(services_model) == set(run_production_readiness.FINAL_SERVICE_USERS),
        "signed normalized runtime model service set is incomplete",
    )
    by_name = {
        ref.split("@", 1)[0].rsplit("/", 1)[-1]: ref
        for ref in production_image_refs
    }
    expected_refs = {
        "serverware": by_name["control"],
        "audit-anchor": by_name["control"],
        "decision-gate-rs": by_name["decision-gate"],
    }

    child_env = run_production_readiness.build_final_child_environment(production_env)
    socket_path = Path(docker_unix_socket)
    docker_env = run_production_readiness.docker_subprocess_environment(
        child_env,
        socket_path,
    )
    docker_endpoint = f"unix://{socket_path}"
    daemon_before = run_production_readiness.verify_docker_daemon_identity(
        docker_executable=Path(docker_executable),
        docker_sha256=docker_sha256,
        socket_path=socket_path,
        expected_daemon_id=docker_daemon_id,
        base_env=child_env,
    )

    def measured_text(command: list[str], *, compose: bool = False) -> str:
        expected_executable = compose_plugin_executable if compose else docker_executable
        require(
            command[0] == expected_executable,
            "Docker command did not use its pinned absolute executable",
        )
        if compose:
            require(
                command[1:5]
                == ["--host", docker_endpoint, "--project-name", compose_project_name],
                "Compose command did not pin the Docker endpoint and project name",
            )
        else:
            require(
                command[1:3] == ["--host", docker_endpoint],
                "Docker command did not pin the Docker endpoint",
            )
        result = run_production_readiness.run_measured_command(
            command,
            setting=(
                run_production_readiness.DOCKER_COMPOSE_PLUGIN_EXECUTABLE_ENV
                if compose
                else run_production_readiness.PRODUCTION_DOCKER_EXECUTABLE_ENV
            ),
            expected_digest=compose_plugin_sha256 if compose else docker_sha256,
            cwd=Path(__file__).resolve().parent.parent,
            env=docker_env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            text=True,
        )
        if result.returncode != 0:
            detail = result.stderr.strip() or result.stdout.strip()
            raise ValueError(
                f"{' '.join(command)} failed with exit {result.returncode}: {detail}"
            )
        return result.stdout.strip()

    def measured_container_copy(
        container_id: str,
        destination: str,
        expected: dict[str, Any],
    ) -> dict[str, Any]:
        command = [
            docker_executable,
            "--host",
            docker_endpoint,
            "container",
            "cp",
            f"{container_id}:{destination}",
            "-",
        ]
        max_archive = int(expected["bytes"]) + 1024 * 1024
        result = run_production_readiness.run_measured_binary_command_bounded(
            command,
            setting=run_production_readiness.PRODUCTION_DOCKER_EXECUTABLE_ENV,
            expected_digest=docker_sha256,
            max_stdout_bytes=max_archive,
            cwd=Path(__file__).resolve().parent.parent,
            env=docker_env,
        )
        if result.returncode != 0:
            detail = result.stderr.decode("utf-8", errors="replace").strip()
            raise ValueError(
                f"pinned docker container cp failed with exit {result.returncode}: {detail}"
            )
        return parse_container_copy_archive(
            result.stdout,
            expected_sha256=str(expected["sha256"]),
            expected_bytes=int(expected["bytes"]),
            label=f"{container_id}:{destination}",
        )

    compose_base = [
        compose_plugin_executable,
        "--host",
        docker_endpoint,
        "--project-name",
        compose_project_name,
        "--project-directory",
        str(project_directory),
        "--env-file",
        str(env_file),
        "-f",
        str(compose_file),
    ]

    def snapshot_ids() -> dict[str, str]:
        identifiers: dict[str, str] = {}
        for service in sorted(expected_refs):
            identifier = measured_text(
                [*compose_base, "ps", "-q", service], compose=True
            )
            require(
                re.fullmatch(r"[0-9a-f]{64}", identifier) is not None,
                f"production Compose service {service} did not resolve to one full container ID",
            )
            identifiers[service] = identifier
        require(
            len(set(identifiers.values())) == len(identifiers),
            "production Compose services resolved to duplicate container IDs",
        )
        return identifiers

    def inspect_containers(identifiers: dict[str, str]) -> dict[str, dict[str, Any]]:
        raw = json.loads(
            measured_text(
                [
                    docker_executable,
                    "--host",
                    docker_endpoint,
                    "container",
                    "inspect",
                    *[identifiers[service] for service in sorted(identifiers)],
                ]
            )
        )
        require(
            isinstance(raw, list) and len(raw) == len(identifiers),
            "Docker container inspection did not return the complete service set",
        )
        by_id = {
            str(item.get("Id")): item for item in raw if isinstance(item, dict)
        }
        require(
            set(by_id) == set(identifiers.values()),
            "Docker container inspection IDs differ from the Compose snapshot",
        )
        return {service: by_id[identifier] for service, identifier in identifiers.items()}

    ids_before = snapshot_ids()
    containers_before = inspect_containers(ids_before)
    image_ids: dict[str, str] = {}
    for service, container in containers_before.items():
        require(
            (container.get("State") or {}).get("Status") == "running",
            f"production service {service} is not running",
        )
        require(
            (container.get("Config") or {}).get("Image") == expected_refs[service]
            == services_model[service].get("image"),
            f"production service {service} was not created from the signed digest-pinned image ref",
        )
        image_ids[service] = require_sha256(
            container.get("Image"), f"production service {service} image id"
        )
    raw_images = json.loads(
        measured_text(
            [
                docker_executable,
                "--host",
                docker_endpoint,
                "image",
                "inspect",
                *sorted(set(image_ids.values())),
            ]
        )
    )
    require(isinstance(raw_images, list), "Docker image inspection is invalid")
    images = {
        str(item.get("Id")): item for item in raw_images if isinstance(item, dict)
    }
    require(
        set(images) == set(image_ids.values()),
        "Docker image inspection did not return every running image",
    )

    generation_before: dict[str, Any] = {}
    container_summaries: list[dict[str, Any]] = []
    for service in sorted(expected_refs):
        container = containers_before[service]
        image_id = image_ids[service]
        image = images[image_id]
        require(
            expected_refs[service] in (image.get("RepoDigests") or []),
            f"production service {service} local image does not retain the approved registry digest",
        )
        labels = ((image.get("Config") or {}).get("Labels")) or {}
        require(
            labels.get("dev.serverware.source_tree_digest") == source_tree_digest,
            f"production service {service} image source-tree label does not match release provenance",
        )
        expected_projection = expected_runtime_projection(
            service,
            services_model[service],
            runtime_model,
            image.get("Config") or {},
            project_name=compose_project_name,
            project_directory=project_directory,
        )
        observed_projection = observed_runtime_projection(
            service, container, project_directory=project_directory
        )
        verify_runtime_projection(service, expected_projection, observed_projection)
        started_at = (container.get("State") or {}).get("StartedAt")
        require(
            isinstance(started_at, str) and bool(started_at),
            f"production service {service} running StartedAt is missing",
        )
        generation_before[service] = {
            "container_id": ids_before[service],
            "started_at": started_at,
            "image_id": image_id,
            "runtime_projection": observed_projection,
        }
        namespace_artifacts: dict[str, Any] = {}
        if service in {"serverware", "decision-gate-rs"}:
            for destination, expectation in sorted(artifact_expectations.items()):
                namespace_artifacts[destination] = measured_container_copy(
                    ids_before[service], destination, expectation
                )
        container_summaries.append(
            {
                "service": service,
                **generation_before[service],
                "image_ref": expected_refs[service],
                "source_tree_digest": source_tree_digest,
                "container_namespace_artifacts": namespace_artifacts,
            }
        )

    ids_after = snapshot_ids()
    require(
        ids_after == ids_before,
        "production Compose service ID mapping changed during runtime inspection",
    )
    containers_after = inspect_containers(ids_after)
    generation_after: dict[str, Any] = {}
    for service in sorted(expected_refs):
        container = containers_after[service]
        require(
            (container.get("State") or {}).get("Status") == "running",
            f"production service {service} stopped during runtime inspection",
        )
        require(
            require_sha256(
                container.get("Image"), f"production service {service} final image id"
            )
            == image_ids[service],
            f"production service {service} image changed during runtime inspection",
        )
        final_projection = observed_runtime_projection(
            service, container, project_directory=project_directory
        )
        verify_runtime_projection(
            service,
            expected_runtime_projection(
                service,
                services_model[service],
                runtime_model,
                images[image_ids[service]].get("Config") or {},
                project_name=compose_project_name,
                project_directory=project_directory,
            ),
            final_projection,
        )
        generation_after[service] = {
            "container_id": ids_after[service],
            "started_at": (container.get("State") or {}).get("StartedAt"),
            "image_id": image_ids[service],
            "runtime_projection": final_projection,
        }
    require_stable_container_generation(generation_before, generation_after)

    daemon_after = run_production_readiness.verify_docker_daemon_identity(
        docker_executable=Path(docker_executable),
        docker_sha256=docker_sha256,
        socket_path=socket_path,
        expected_daemon_id=docker_daemon_id,
        base_env=child_env,
    )
    run_production_readiness.require_stable_docker_daemon_binding(
        daemon_before,
        daemon_after,
    )
    return {
        "ok": True,
        "skipped": False,
        "compose_file": str(compose_file),
        "compose_project_name": compose_project_name,
        "runtime_model_sha256": runtime_model["sha256"],
        "docker_executable": docker_executable,
        "docker_sha256": docker_sha256,
        "compose_plugin_executable": compose_plugin_executable,
        "compose_plugin_sha256": compose_plugin_sha256,
        "docker_daemon_before": daemon_before,
        "docker_daemon_after": daemon_after,
        "service_generation_before": generation_before,
        "service_generation_after": generation_after,
        "containers": container_summaries,
    }


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


def verify_proxy_release_authority(
    value: Any,
    *,
    expected_request_digest: str,
    expected_operation_digest: str,
    latest_observation_at_unix: int,
) -> dict[str, Any]:
    label = "proxy response release authority"
    require(isinstance(value, dict), f"{label} must be an object")
    authority = dict(value)
    require_exact_object_fields(
        authority,
        {
            "authority_mode",
            "grant_id",
            "approval_id",
            "credential_ref",
            "credential_version",
            "request_digest",
            "operation_digest",
            "attempt_id",
            "consumption_identity_digest",
            "authorization_state_at_upstream_dispatch",
            "authorization_state_observed_at_epoch_ms",
            "reservation_expires_at_epoch_ms",
            "dispatch_expires_at_epoch_ms",
        },
        label,
    )
    require(
        authority.get("authority_mode") == "atomic",
        f"{label} did not use atomic release authorization",
    )
    grant_id = authority.get("grant_id")
    approval_id = authority.get("approval_id")
    for field, identifier in (("grant_id", grant_id), ("approval_id", approval_id)):
        require(
            identifier is None
            or (
                isinstance(identifier, str)
                and identifier == identifier.strip()
                and 1 <= len(identifier) <= 256
                and all(character.isprintable() for character in identifier)
            ),
            f"{label} {field} is invalid",
        )
    require(
        (grant_id is None and approval_id is None)
        or (isinstance(grant_id, str) and isinstance(approval_id, str)),
        f"{label} grant and approval identities are inconsistent",
    )
    credential_ref = authority.get("credential_ref")
    credential_version = authority.get("credential_version")
    require(
        credential_ref is None
        or (
            isinstance(credential_ref, str)
            and credential_ref == credential_ref.strip()
            and 1 <= len(credential_ref) <= 256
            and all(character.isprintable() for character in credential_ref)
        ),
        f"{label} credential_ref is invalid",
    )
    require(
        isinstance(credential_version, int)
        and not isinstance(credential_version, bool)
        and 0 <= credential_version <= 2**63 - 1,
        f"{label} credential_version is invalid",
    )
    require(
        (credential_ref is None and credential_version == 0)
        or (isinstance(credential_ref, str) and credential_version > 0),
        f"{label} credential identity and version are inconsistent",
    )
    request_digest = require_sha256(
        authority.get("request_digest"),
        f"{label} request digest",
    )
    operation_digest = require_sha256(
        authority.get("operation_digest"),
        f"{label} operation digest",
    )
    require(
        request_digest == expected_request_digest,
        f"{label} request digest mismatch",
    )
    require(
        operation_digest == expected_operation_digest,
        f"{label} operation digest mismatch",
    )
    require_sha256(authority.get("attempt_id"), f"{label} attempt ID")
    require_sha256(
        authority.get("consumption_identity_digest"),
        f"{label} consumption identity digest",
    )
    require(
        authority.get("authorization_state_at_upstream_dispatch") == "dispatching",
        f"{label} does not prove historical dispatch authorization",
    )
    observed_at_epoch_ms = authority.get("authorization_state_observed_at_epoch_ms")
    require(
        isinstance(observed_at_epoch_ms, int)
        and not isinstance(observed_at_epoch_ms, bool)
        and 0 < observed_at_epoch_ms <= 2**63 - 1,
        f"{label} dispatch observation timestamp is invalid",
    )
    require(
        observed_at_epoch_ms <= latest_observation_at_unix * 1000 + 999,
        f"{label} dispatch observation postdates the enclosing proof event",
    )
    reservation_expires_at_epoch_ms = authority.get("reservation_expires_at_epoch_ms")
    require(
        reservation_expires_at_epoch_ms is None
        or (
            isinstance(reservation_expires_at_epoch_ms, int)
            and not isinstance(reservation_expires_at_epoch_ms, bool)
            and 0 < reservation_expires_at_epoch_ms <= 2**63 - 1
            and observed_at_epoch_ms < reservation_expires_at_epoch_ms
        ),
        f"{label} reservation expiry is invalid",
    )
    dispatch_expires_at_epoch_ms = authority.get("dispatch_expires_at_epoch_ms")
    require(
        isinstance(dispatch_expires_at_epoch_ms, int)
        and not isinstance(dispatch_expires_at_epoch_ms, bool)
        and observed_at_epoch_ms < dispatch_expires_at_epoch_ms <= 2**63 - 1,
        f"{label} dispatch expiry is invalid",
    )
    require(
        "completion_outcome" not in authority,
        f"{label} must not claim response completion before downstream release",
    )
    return authority


def verify_control_plane_authorization_receipt(
    document: Any,
    *,
    trusted_public_key_pem: str,
    expected_trusted_public_key_id: str,
    expected_release_authority: dict[str, Any],
    expected_principal_id: str,
    expected_route_id: str,
    expected_runtime_manifest_digest: str,
    expected_policy_digest: str,
    expected_provenance_digest: str,
    expected_image_signatures_digest: str,
    expected_source_tree_digest: str,
) -> dict[str, Any]:
    label = "control-plane authorization receipt"
    require(isinstance(document, dict), f"{label} must be an object")
    assert_no_secret_fields(document)
    require_exact_object_fields(
        document,
        {
            "apiVersion",
            "kind",
            "principal_id",
            "route_id",
            "release_authority",
            "request",
            "response",
        },
        label,
    )
    require(
        document.get("apiVersion")
        == CONTROL_PLANE_AUTHORIZATION_RECEIPT_API_VERSION,
        f"{label} apiVersion mismatch",
    )
    require(
        document.get("kind") == "ControlPlaneAuthorizationReceipt",
        f"{label} kind mismatch",
    )
    require(
        document.get("principal_id") == expected_principal_id,
        f"{label} principal ID mismatch",
    )
    require(
        document.get("route_id") == expected_route_id,
        f"{label} route ID mismatch",
    )
    require(
        document.get("release_authority") == expected_release_authority,
        f"{label} release authority mismatch",
    )

    request = document.get("request")
    require(isinstance(request, dict), f"{label} request must be an object")
    require_exact_object_fields(
        request,
        {"method", "path", "query", "nonce", "body_b64", "body_sha256"},
        f"{label} request",
    )
    require(
        request.get("method") == "POST"
        and request.get("path") == CONTROL_PLANE_DISPATCH_PATH
        and request.get("query") == "",
        f"{label} request context mismatch",
    )
    request_nonce = request.get("nonce")
    request_nonce_bytes = require_base64url_bytes(
        request_nonce,
        f"{label} request nonce",
        minimum_bytes=32,
    )
    request_body_bytes = decode_canonical_base64url(
        request.get("body_b64"),
        f"{label} request body",
    )
    require(
        0 < len(request_body_bytes) <= 4 * 1024,
        f"{label} request body size is invalid",
    )
    request_body_sha256 = require_sha256(
        request.get("body_sha256"),
        f"{label} request body digest",
    )
    require(
        request_body_sha256 == sha256_prefixed_bytes(request_body_bytes),
        f"{label} request body digest mismatch",
    )
    request_body = load_json_bytes(
        request_body_bytes,
        Path("<embedded-control-plane-dispatch-request>"),
        f"{label} request body",
    )
    require(isinstance(request_body, dict), f"{label} request body must be an object")
    require_exact_object_fields(
        request_body,
        {"apiVersion", "attemptId", "bindingDigest"},
        f"{label} request body",
    )
    require(
        canonical_json(request_body).encode("utf-8") == request_body_bytes,
        f"{label} request body is not canonical JSON",
    )
    require(
        request_body
        == {
            "apiVersion": "serverware.releaseAuthorizationDispatch/v1",
            "attemptId": expected_release_authority["attempt_id"],
            "bindingDigest": expected_release_authority[
                "consumption_identity_digest"
            ],
        },
        f"{label} dispatch request body mismatch",
    )

    response = document.get("response")
    require(isinstance(response, dict), f"{label} response must be an object")
    require_exact_object_fields(
        response,
        {
            "status",
            "body_b64",
            "body_sha256",
            "response_signing_key_id",
            "statement_b64",
            "statement_sha256",
            "signature",
        },
        f"{label} response",
    )
    response_status = response.get("status")
    require(
        isinstance(response_status, int)
        and not isinstance(response_status, bool)
        and response_status == 200,
        f"{label} response status is not an exact successful dispatch status",
    )

    response_body_bytes = decode_canonical_base64url(
        response.get("body_b64"),
        f"{label} response body",
    )
    require(
        0 < len(response_body_bytes) <= 64 * 1024,
        f"{label} response body size is invalid",
    )
    response_body_sha256 = require_sha256(
        response.get("body_sha256"),
        f"{label} response body digest",
    )
    require(
        response_body_sha256 == sha256_prefixed_bytes(response_body_bytes),
        f"{label} response body digest mismatch",
    )
    response_body = load_json_bytes(
        response_body_bytes,
        Path("<embedded-control-plane-dispatch-response>"),
        f"{label} response body",
    )
    assert_no_secret_fields(response_body)
    require_exact_object_fields(
        response_body,
        {
            "apiVersion",
            "ok",
            "authorized",
            "state",
            "reason",
            "attemptId",
            "bindingDigest",
            "idempotentReplay",
            "grantId",
            "approvalRequestId",
            "reservationExpiresAtEpochMs",
            "dispatchStartedAtEpochMs",
            "dispatchExpiresAtEpochMs",
            "completionOutcome",
            "retryAfterSeconds",
            "quotas",
            "store",
        },
        f"{label} response body",
    )
    exact_dispatch_fields = {
        "apiVersion": "serverware.releaseAuthorization/v1",
        "ok": True,
        "authorized": True,
        "state": "dispatching",
        "reason": "dispatching",
        "attemptId": expected_release_authority["attempt_id"],
        "bindingDigest": expected_release_authority["consumption_identity_digest"],
        "grantId": expected_release_authority["grant_id"],
        "approvalRequestId": expected_release_authority["approval_id"],
        "reservationExpiresAtEpochMs": expected_release_authority[
            "reservation_expires_at_epoch_ms"
        ],
        "dispatchStartedAtEpochMs": expected_release_authority[
            "authorization_state_observed_at_epoch_ms"
        ],
        "dispatchExpiresAtEpochMs": expected_release_authority[
            "dispatch_expires_at_epoch_ms"
        ],
        "completionOutcome": None,
        "retryAfterSeconds": 0,
    }
    for field, expected in exact_dispatch_fields.items():
        require(
            response_body.get(field) == expected,
            f"{label} response body {field} does not match release authority",
        )
    require(
        isinstance(response_body.get("idempotentReplay"), bool),
        f"{label} response body idempotentReplay is invalid",
    )
    quotas = response_body.get("quotas")
    require(
        isinstance(quotas, list) and all(isinstance(item, dict) for item in quotas),
        f"{label} response body quotas are invalid",
    )
    quota_fields = {
        "counterKey",
        "constraintId",
        "operation",
        "windowStartEpochMs",
        "windowSeconds",
        "max",
        "count",
        "remaining",
        "reservationState",
    }
    for index, quota in enumerate(quotas):
        require_exact_object_fields(quota, quota_fields, f"{label} response body quota {index}")
    store = response_body.get("store")
    require(isinstance(store, dict), f"{label} response body store is invalid")
    require_exact_object_fields(store, {"backend", "ha"}, f"{label} response body store")
    require(
        isinstance(store.get("backend"), str)
        and bool(store["backend"])
        and store.get("ha") is True,
        f"{label} response body does not prove an HA authorization store",
    )

    dispatch_started_at_epoch_ms = response_body["dispatchStartedAtEpochMs"]
    dispatch_expires_at_epoch_ms = response_body["dispatchExpiresAtEpochMs"]
    reservation_expires_at_epoch_ms = response_body["reservationExpiresAtEpochMs"]
    for field, value in (
        ("dispatch start", dispatch_started_at_epoch_ms),
        ("dispatch expiry", dispatch_expires_at_epoch_ms),
        ("reservation expiry", reservation_expires_at_epoch_ms),
    ):
        require(
            isinstance(value, int)
            and not isinstance(value, bool)
            and 0 < value <= 2**63 - 1,
            f"{label} {field} is invalid",
        )
    require(dispatch_started_at_epoch_ms < dispatch_expires_at_epoch_ms, f"{label} dispatch window is invalid")
    require(dispatch_started_at_epoch_ms < reservation_expires_at_epoch_ms, f"{label} reservation expired before dispatch")

    response_statement_bytes = decode_canonical_base64url(
        response.get("statement_b64"),
        f"{label} response statement",
    )
    require(
        0 < len(response_statement_bytes) <= 64 * 1024,
        f"{label} response statement size is invalid",
    )
    response_statement = load_json_bytes(
        response_statement_bytes,
        Path("<embedded-control-plane-response-statement>"),
        f"{label} response statement",
    )
    require(
        canonical_json(response_statement).encode("utf-8") == response_statement_bytes,
        f"{label} response statement is not canonical JSON",
    )
    require_exact_object_fields(
        response_statement,
        {
            "version",
            "issued_at_ms",
            "request",
            "status_code",
            "body_sha256",
            "nonce",
            "response_signing_key_id",
            "context",
        },
        f"{label} response statement",
    )
    require(
        response_statement.get("version") == CONTROL_PLANE_RESPONSE_SIGNATURE_API_VERSION,
        f"{label} response statement version mismatch",
    )
    issued_at_ms = response_statement.get("issued_at_ms")
    require(
        isinstance(issued_at_ms, int)
        and not isinstance(issued_at_ms, bool)
        and 0 < issued_at_ms <= 2**63 - 1,
        f"{label} signed response issue time is invalid",
    )
    require(
        dispatch_started_at_epoch_ms <= issued_at_ms,
        f"{label} signed response predates dispatch start",
    )
    require(
        issued_at_ms < dispatch_expires_at_epoch_ms,
        f"{label} signed response was issued at or after dispatch expiry",
    )
    require(
        issued_at_ms < reservation_expires_at_epoch_ms,
        f"{label} signed response was issued at or after reservation expiry",
    )

    signed_request = response_statement.get("request")
    require(isinstance(signed_request, dict), f"{label} signed request must be an object")
    require_exact_object_fields(signed_request, {"method", "path", "query"}, f"{label} signed request")
    require(
        signed_request
        == {
            "method": request["method"],
            "path": request["path"],
            "query": request["query"],
        },
        f"{label} signed request context mismatch",
    )
    require(response_statement.get("status_code") == response_status, f"{label} signed response status mismatch")
    require(response_statement.get("body_sha256") == response_body_sha256, f"{label} signed response body digest mismatch")
    require(response_statement.get("nonce") == request_nonce, f"{label} signed response nonce mismatch")

    expected_context = {
        "runtime_manifest_digest": require_sha256(
            expected_runtime_manifest_digest,
            f"expected {label} runtime manifest digest",
        ),
        "policy_bundle_digest": require_sha256(expected_policy_digest, f"expected {label} policy digest"),
        "provenance_digest": require_sha256(expected_provenance_digest, f"expected {label} provenance digest"),
        "image_signatures_digest": require_sha256(
            expected_image_signatures_digest,
            f"expected {label} image signatures digest",
        ),
        "source_tree_digest": require_sha256(expected_source_tree_digest, f"expected {label} source tree digest"),
    }
    require(
        response_statement.get("context") == expected_context,
        f"{label} signed response attested context mismatch",
    )

    trusted_key_id = ed25519_public_key_id(
        trusted_public_key_pem,
        f"{label} trust root",
    )
    require(
        hmac.compare_digest(
            trusted_key_id,
            require_sha256(
                expected_trusted_public_key_id,
                f"expected {label} trust-root identity",
            ),
        ),
        f"{label} trust root does not match the independently configured key ID",
    )
    require(
        response.get("response_signing_key_id") == trusted_key_id,
        f"{label} is not signed by the independently trusted control-plane response key",
    )
    require(
        response_statement.get("response_signing_key_id") == trusted_key_id,
        f"{label} signed response statement key ID mismatch",
    )
    response_statement_sha256 = require_sha256(
        response.get("statement_sha256"),
        f"{label} response statement digest",
    )
    require(
        response_statement_sha256 == sha256_prefixed_bytes(response_statement_bytes),
        f"{label} response statement digest mismatch",
    )
    verify_ed25519(
        trusted_public_key_pem,
        str(response.get("signature") or ""),
        response_statement_bytes,
        label,
    )
    return {
        "apiVersion": document["apiVersion"],
        "signing_key_id": trusted_key_id,
        "principal_id": expected_principal_id,
        "route_id": expected_route_id,
        "request_nonce_sha256": sha256_prefixed_bytes(request_nonce_bytes),
        "request_body_sha256": request_body_sha256,
        "response_body_sha256": response_body_sha256,
        "response_statement_sha256": response_statement_sha256,
        "dispatch_started_at_epoch_ms": dispatch_started_at_epoch_ms,
        "dispatch_expires_at_epoch_ms": dispatch_expires_at_epoch_ms,
        "reservation_expires_at_epoch_ms": reservation_expires_at_epoch_ms,
        "issued_at_ms": issued_at_ms,
        "canonical_signature_verified": True,
        "dispatch_body_exact_match": True,
        "attested_context_exact_match": True,
        "secret_values_included": False,
    }


def verify_and_compile_policy_snapshot(
    bundle_snapshot: FileSnapshot,
    trusted_key_snapshot: FileSnapshot,
    *,
    expected_policy_digest: str,
) -> PolicySnapshot:
    bundle = load_json_snapshot(bundle_snapshot, "signed production policy bundle")
    trusted_public_key_pem = snapshot_text(
        trusted_key_snapshot,
        "production policy signing trust root",
        encoding="ascii",
    )
    trusted_key_id = ed25519_public_key_id(
        trusted_public_key_pem,
        "production policy signing trust root",
    )
    verification = verify_production_policy_identity.verify_production_policy_identity(
        bundle,
        trusted_public_key_pem,
        trusted_public_key_hash=trusted_key_id,
    )
    require(
        verification.get("ok") is True,
        "snapshotted production policy bundle failed pinned Ed25519 verification",
    )
    try:
        compiled = compile_policy_bundle(
            bundle,
            validate_schema=True,
            verify_signature=False,
        )
    except Exception as exc:
        raise ValueError(f"snapshotted production policy bundle could not be compiled: {exc}") from exc
    expected_digest = require_sha256(expected_policy_digest, "expected production policy digest")
    require(compiled.hash == expected_digest, "snapshotted production policy bundle digest mismatch")
    require(
        (verification.get("policy") or {}).get("hash") == compiled.hash,
        "compiled production policy hash differs from signature verification",
    )
    return compiled


def match_proxy_policy_route(
    policy: PolicySnapshot,
    *,
    principal_id: str,
    route_id: str,
) -> tuple[str, set[str]]:
    label = "proxy response independently matched policy route identity"
    require(
        isinstance(principal_id, str)
        and principal_id == principal_id.strip()
        and 1 <= len(principal_id) <= 256
        and all(character.isprintable() for character in principal_id),
        f"{label} principal ID is invalid",
    )
    require(principal_id in policy.principals, f"{label} principal is absent from the signed policy")
    require(
        isinstance(route_id, str)
        and route_id == route_id.strip()
        and 1 <= len(route_id) <= 256,
        f"{label} route ID is invalid",
    )
    routes = [route for route in policy.routes if route.id == route_id]
    require(len(routes) == 1, f"{label} is absent or ambiguous in the signed policy")
    route = routes[0]
    require(
        principal_id in route.principals or "*" in route.principals,
        f"{label} does not authorize the independently pinned principal",
    )
    response_profile = route.adapter_config.get("response")
    require(isinstance(response_profile, dict), f"{label} success response profile is missing")
    raw_allowed_headers = response_profile.get("allowedHeaders", [])
    require(
        isinstance(raw_allowed_headers, list)
        and all(
            isinstance(name, str)
            and name == name.lower()
            and re.fullmatch(r"[a-z0-9][a-z0-9-]*", name) is not None
            for name in raw_allowed_headers
        )
        and len(raw_allowed_headers) == len(set(raw_allowed_headers)),
        f"{label} success allowedHeaders are invalid",
    )
    return route.id, {
        "content-encoding",
        "content-length",
        "content-type",
        *raw_allowed_headers,
    }


def verify_proxy_upstream_response(
    value: Any,
    *,
    expected_status: int,
    expected_header_names: set[str],
) -> dict[str, Any]:
    label = "proxy upstream response"
    require(isinstance(value, dict), f"{label} must be an object")
    upstream = dict(value)
    require_exact_object_fields(
        upstream,
        {
            "status",
            "selected_raw_policy_headers_b64",
            "body_digest",
            "canonical_digest",
        },
        label,
    )
    status = upstream.get("status")
    require(
        isinstance(status, int)
        and not isinstance(status, bool)
        and 100 <= status <= 599,
        f"{label} status is invalid",
    )
    require(status == expected_status, f"{label} status mismatch")
    body_digest = require_sha256(upstream.get("body_digest"), f"{label} body digest")
    selected = upstream.get("selected_raw_policy_headers_b64")
    require(isinstance(selected, dict), f"{label} raw policy headers must be an object")
    require(
        set(selected) == expected_header_names,
        f"{label} raw policy header names do not exactly match the signed route success profile",
    )
    for name, values in selected.items():
        require(
            isinstance(name, str)
            and re.fullmatch(r"[a-z0-9][a-z0-9-]*", name) is not None
            and isinstance(values, list)
            and len(values) <= 128,
            f"{label} raw policy header {name!r} is invalid",
        )
        for index, encoded in enumerate(values):
            decoded = decode_canonical_base64url(
                encoded,
                f"{label} raw policy header {name}[{index}]",
            )
            require(
                len(decoded) <= 8 * 1024,
                f"{label} raw policy header {name}[{index}] is too large",
            )
    canonical_digest = require_sha256(
        upstream.get("canonical_digest"),
        f"{label} canonical digest",
    )
    require(
        canonical_digest
        == sha256_prefixed_json(
            {
                "status": status,
                "selected_raw_policy_headers_b64": selected,
                "body_digest": body_digest,
            }
        ),
        f"{label} canonical digest mismatch",
    )
    return upstream


def verify_production_proxy_response_proof(
    document: dict[str, Any],
    *,
    trusted_verifier_public_key_pem: str,
    trusted_collector_public_key_pem: str,
    trusted_control_plane_response_signing_public_key_pem: str,
    expected_control_plane_response_signing_public_key_id: str,
    policy_snapshot: PolicySnapshot,
    expected_principal_id: str,
    expected_server_instance_id: str,
    expected_client_nonce: str,
    expected_client_request_digest: str,
    expected_request_digest: str,
    expected_operation_digest: str,
    expected_tls_channel_binding: str,
    expected_policy_digest: str,
    expected_runtime_manifest_digest: str,
    expected_binary_digest: str,
    expected_release_digest: str,
    expected_image_signatures_digest: str,
    expected_source_tree_digest: str,
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
    require(document.get("apiVersion") == "serverware.proxyResponseProof/v3", "proxy response proof has wrong apiVersion")
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
    expected_client_request_digest = require_sha256(
        expected_client_request_digest,
        "expected proxy client request digest",
    )

    external_capture = document.get("external_capture") if isinstance(document.get("external_capture"), dict) else {}
    require(
        external_capture.get("apiVersion") == "serverware.proxyResponseCapture/v2",
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
            "client_request_digest",
            "principal_id",
            "route_id",
            "request_digest",
            "operation_digest",
            "release_authority",
            "control_plane_authorization_receipt",
            "upstream_response",
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
    require(
        external_capture.get("principal_id") == expected_principal_id,
        "proxy response external capture principal ID does not match the independently configured expected proxy principal",
    )
    matched_route_id, expected_raw_policy_header_names = match_proxy_policy_route(
        policy_snapshot,
        principal_id=expected_principal_id,
        route_id=external_capture.get("route_id"),
    )
    require(
        external_capture.get("route_id") == matched_route_id,
        "proxy response external capture route ID does not match the independently matched signed policy route",
    )
    client_request_digest = require_sha256(
        external_capture.get("client_request_digest"),
        "proxy response external client request digest",
    )
    require(
        client_request_digest == expected_client_request_digest,
        "proxy response external client request digest does not match the independently supplied client commitment",
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
    release_authority = verify_proxy_release_authority(
        external_capture.get("release_authority"),
        expected_request_digest=request_digest,
        expected_operation_digest=operation_digest,
        latest_observation_at_unix=captured_at,
    )

    response = external_capture.get("response") if isinstance(external_capture.get("response"), dict) else {}
    require_exact_object_fields(
        response,
        {"status", "selected_headers", "selected_headers_digest", "body_digest"},
        "proxy response external capture response",
    )
    status = response.get("status")
    require(isinstance(status, int) and not isinstance(status, bool), "proxy response external capture status must be an integer")
    require(200 <= status < 300, "proxy response external capture did not bind a successful production response status")
    upstream_response = verify_proxy_upstream_response(
        external_capture.get("upstream_response"),
        expected_status=status,
        expected_header_names=expected_raw_policy_header_names,
    )
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
        server_statement.get("apiVersion") == "serverware.proxyResponseStatement/v2",
        "proxy response server statement has wrong apiVersion",
    )
    require_exact_object_fields(
        server_statement,
        {
            "apiVersion",
            "issued_at_unix",
            "client_nonce",
            "client_request_digest",
            "principal_id",
            "route_id",
            "request_digest",
            "operation_digest",
            "release_authority",
            "control_plane_authorization_receipt",
            "upstream_response",
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
    require(
        server_statement.get("principal_id") == expected_principal_id,
        "proxy response server statement principal ID does not match the independently configured expected proxy principal",
    )
    require(
        server_statement.get("route_id") == matched_route_id,
        "proxy response server statement route ID does not match the independently matched signed policy route",
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
    statement_release_authority = verify_proxy_release_authority(
        server_statement.get("release_authority"),
        expected_request_digest=statement_request_digest,
        expected_operation_digest=statement_operation_digest,
        latest_observation_at_unix=issued_at,
    )
    require(
        statement_release_authority == release_authority,
        "proxy response external capture release authority does not match server statement",
    )
    statement_upstream_response = verify_proxy_upstream_response(
        server_statement.get("upstream_response"),
        expected_status=status,
        expected_header_names=expected_raw_policy_header_names,
    )
    require(
        statement_upstream_response == upstream_response,
        "proxy response external capture upstream response does not match server statement",
    )
    embedded_control_plane_authorization_receipt = server_statement.get(
        "control_plane_authorization_receipt"
    )
    require(
        external_capture.get("control_plane_authorization_receipt")
        == embedded_control_plane_authorization_receipt,
        "proxy response external capture control-plane authorization receipt does not match server statement",
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
        "principal_id": expected_principal_id,
        "route_id": matched_route_id,
        "request_digest": request_digest,
        "operation_digest": operation_digest,
        "release_authority": release_authority,
        "control_plane_authorization_receipt_sha256": (
            sha256_prefixed_json(embedded_control_plane_authorization_receipt)
        ),
        "upstream_response": upstream_response,
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
    control_plane_authorization = verify_control_plane_authorization_receipt(
        embedded_control_plane_authorization_receipt,
        trusted_public_key_pem=trusted_control_plane_response_signing_public_key_pem,
        expected_trusted_public_key_id=(
            expected_control_plane_response_signing_public_key_id
        ),
        expected_release_authority=release_authority,
        expected_principal_id=expected_principal_id,
        expected_route_id=matched_route_id,
        expected_runtime_manifest_digest=expected_runtime_manifest_digest,
        expected_policy_digest=expected_policy_digest,
        expected_provenance_digest=expected_release_digest,
        expected_image_signatures_digest=expected_image_signatures_digest,
        expected_source_tree_digest=expected_source_tree_digest,
    )
    control_plane_authorization_key_id = control_plane_authorization[
        "signing_key_id"
    ]
    for proof_role, proof_key_id in (
        ("external collector", collector_signing_key_id),
        ("response statement signer", response_signing_key_id),
        ("vendor TEE verifier", trusted_verifier_key_id),
    ):
        require(
            not hmac.compare_digest(
                control_plane_authorization_key_id, proof_key_id
            ),
            "control-plane response signing trust root must be independent "
            f"from the proxy proof {proof_role} key",
        )

    return {
        "apiVersion": document.get("apiVersion"),
        "server_statement_sha256": server_statement_digest,
        "captured_at_unix": captured_at,
        "issued_at_unix": issued_at,
        "client_nonce_sha256": sha256_prefixed_bytes(nonce_bytes),
        "client_request_digest": client_request_digest,
        "request_digest": request_digest,
        "operation_digest": operation_digest,
        "principal_id": expected_principal_id,
        "route_id": matched_route_id,
        "release_authority": release_authority,
        "control_plane_authorization_receipt": control_plane_authorization,
        "upstream_response": upstream_response,
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
        "release_authority_bound": True,
        "embedded_control_plane_authorization_receipt_bound": True,
        "signed_policy_route_bound": True,
        "signed_policy_response_headers_bound": True,
        "upstream_response_bound": True,
        "release_artifacts_bound": True,
    }


def completion_proof_digest_path(path: Path, generation: str) -> Path:
    require(
        re.fullmatch(r"[0-9a-f]{32}", generation) is not None,
        "completion proof checksum generation is invalid",
    )
    return path.with_name(f"{path.name}.sha256.{generation}")


def fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def verify_private_output_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    metadata = path.lstat()
    require(stat.S_ISDIR(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode), "completion proof output directory must be a non-symlink directory")
    require(metadata.st_uid == os.geteuid(), "completion proof output directory must be owned by the verifier user")
    require(not stat.S_IMODE(metadata.st_mode) & 0o022, "completion proof output directory must not be writable by group/other")


def validate_existing_private_output(path: Path, label: str) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return
    require(stat.S_ISREG(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode), f"{label} must be a regular non-symlink file")
    require(metadata.st_uid == os.geteuid(), f"{label} must be owned by the verifier user")
    require(stat.S_IMODE(metadata.st_mode) == 0o600, f"{label} must use mode 0600")


def cleanup_stale_completion_checksums(path: Path, current_generation: str, *, retain: int = 3) -> None:
    candidates: list[tuple[int, Path]] = []
    pattern = re.compile(rf"^{re.escape(path.name)}\.sha256\.([0-9a-f]{{32}})$")
    for candidate in path.parent.iterdir():
        match = pattern.fullmatch(candidate.name)
        if match is None or match.group(1) == current_generation:
            continue
        try:
            metadata = candidate.lstat()
        except FileNotFoundError:
            continue
        if (
            stat.S_ISREG(metadata.st_mode)
            and not stat.S_ISLNK(metadata.st_mode)
            and metadata.st_uid == os.geteuid()
            and stat.S_IMODE(metadata.st_mode) == 0o600
        ):
            candidates.append((metadata.st_mtime_ns, candidate))
    candidates.sort(reverse=True)
    for _mtime, candidate in candidates[max(retain - 1, 0) :]:
        candidate.unlink(missing_ok=True)
    fsync_directory(path.parent)


def write_output(
    path: Path,
    proof: dict[str, Any],
    *,
    fail_after_checksum_publish: bool = False,
) -> str:
    payload = (json.dumps(proof, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode("utf-8")
    proof_digest = sha256_prefixed_bytes(payload)
    integrity = proof.get("integrity_metadata")
    require(isinstance(integrity, dict), "completion proof is missing integrity metadata")
    generation = integrity.get("generation")
    require(isinstance(generation, str), "completion proof checksum generation is invalid")
    digest_path = completion_proof_digest_path(path, generation)
    require(
        integrity.get("detached_sha256_path") == str(digest_path),
        "completion proof checksum path does not match its generation",
    )
    digest_payload = f"{proof_digest}\n".encode("ascii")
    verify_private_output_directory(path.parent)
    lock_path = path.with_name(f".{path.name}.writer.lock")
    lock_flags = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        lock_descriptor = os.open(lock_path, lock_flags, 0o600)
    except OSError as exc:
        raise ValueError("completion proof writer lock could not be opened without following symlinks") from exc
    try:
        lock_metadata = os.fstat(lock_descriptor)
        require(stat.S_ISREG(lock_metadata.st_mode), "completion proof writer lock must be a regular file")
        require(lock_metadata.st_uid == os.geteuid(), "completion proof writer lock must be owned by the verifier user")
        require(stat.S_IMODE(lock_metadata.st_mode) == 0o600, "completion proof writer lock must use mode 0600")
        fcntl.flock(lock_descriptor, fcntl.LOCK_EX)
        validate_existing_private_output(path, "completion proof output")
        try:
            digest_path.lstat()
        except FileNotFoundError:
            pass
        else:
            raise ValueError("completion proof checksum generation already exists")
        temporary_paths: list[Path] = []
        try:
            staged: dict[Path, Path] = {}
            for destination, content in ((digest_path, digest_payload), (path, payload)):
                with tempfile.NamedTemporaryFile(
                    mode="wb",
                    dir=path.parent,
                    prefix=f".{destination.name}.",
                    delete=False,
                ) as temporary:
                    temporary_path = Path(temporary.name)
                    temporary_paths.append(temporary_path)
                    os.fchmod(temporary.fileno(), 0o600)
                    temporary.write(content)
                    temporary.flush()
                    os.fsync(temporary.fileno())
                    staged[destination] = temporary_path
            os.replace(staged[digest_path], digest_path)
            temporary_paths.remove(staged[digest_path])
            fsync_directory(path.parent)
            if fail_after_checksum_publish:
                raise RuntimeError("injected failure after checksum publication")
            os.replace(staged[path], path)
            temporary_paths.remove(staged[path])
            fsync_directory(path.parent)
            cleanup_stale_completion_checksums(path, generation)
        finally:
            for temporary_path in temporary_paths:
                temporary_path.unlink(missing_ok=True)
    finally:
        os.close(lock_descriptor)
    return proof_digest


def consume_final_challenge_once(
    ledger_path: Path,
    *,
    challenge_nonce_sha256: str,
    completion_identity_sha256: str,
    consumed_at_unix: int | None = None,
) -> dict[str, Any]:
    challenge_digest = require_sha256(challenge_nonce_sha256, "final completion challenge digest")
    completion_digest = require_sha256(completion_identity_sha256, "final completion identity digest")
    require(ledger_path.parent.is_dir(), "final challenge ledger parent directory does not exist")
    parent_stat = ledger_path.parent.stat()
    require(parent_stat.st_uid == os.geteuid(), "final challenge ledger directory must be owned by the verifier user")
    require(
        parent_stat.st_mode & (stat.S_IWGRP | stat.S_IWOTH) == 0,
        "final challenge ledger directory must not be group- or world-writable",
    )
    require(not ledger_path.is_symlink(), "final challenge ledger must not be a symlink")
    lock_path = ledger_path.with_name(ledger_path.name + ".lock")
    flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
    lock_fd = os.open(lock_path, flags, 0o600)
    temporary_path: Path | None = None
    try:
        with os.fdopen(lock_fd, "r+b", closefd=True) as lock_file:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
            if ledger_path.exists():
                ledger_fd = os.open(ledger_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
                try:
                    ledger_stat = os.fstat(ledger_fd)
                    require(stat.S_ISREG(ledger_stat.st_mode), "final challenge consumption ledger must be a regular file")
                    require(
                        ledger_stat.st_uid == os.geteuid(),
                        "final challenge consumption ledger must be owned by the verifier user",
                    )
                    require(
                        ledger_stat.st_mode & (stat.S_IRWXG | stat.S_IRWXO) == 0,
                        "final challenge consumption ledger must not grant group or world access",
                    )
                    with os.fdopen(ledger_fd, "r", encoding="utf-8", closefd=False) as ledger_file:
                        ledger = json.load(ledger_file, object_pairs_hook=reject_duplicate_json_object_keys)
                except (OSError, json.JSONDecodeError) as exc:
                    raise ValueError("final challenge consumption ledger is invalid JSON") from exc
                finally:
                    os.close(ledger_fd)
                require(isinstance(ledger, dict), "final challenge consumption ledger must be an object")
                require_exact_keys(
                    ledger,
                    {"apiVersion", "max_entries", "entries"},
                    "final challenge consumption ledger",
                )
                require(
                    ledger.get("apiVersion") == FINAL_CHALLENGE_LEDGER_API_VERSION,
                    "final challenge consumption ledger apiVersion mismatch",
                )
                require(
                    ledger.get("max_entries") == FINAL_CHALLENGE_LEDGER_MAX_ENTRIES,
                    "final challenge consumption ledger bound mismatch",
                )
                entries = ledger.get("entries")
                require(isinstance(entries, list), "final challenge consumption ledger entries must be a list")
            else:
                entries = []
            require(
                len(entries) <= FINAL_CHALLENGE_LEDGER_MAX_ENTRIES,
                "final challenge consumption ledger exceeds its configured bound",
            )
            for index, entry in enumerate(entries):
                require(isinstance(entry, dict), f"final challenge consumption ledger entry {index} must be an object")
                require_exact_keys(
                    entry,
                    {"challenge_nonce_sha256", "completion_identity_sha256", "consumed_at_unix"},
                    f"final challenge consumption ledger entry {index}",
                )
                existing_challenge = require_sha256(
                    entry.get("challenge_nonce_sha256"),
                    f"final challenge consumption ledger entry {index} challenge digest",
                )
                require(
                    not hmac.compare_digest(existing_challenge, challenge_digest),
                    "final completion challenge was already consumed",
                )
                require_sha256(
                    entry.get("completion_identity_sha256"),
                    f"final challenge consumption ledger entry {index} completion identity digest",
                )
                require(
                    isinstance(entry.get("consumed_at_unix"), int)
                    and not isinstance(entry.get("consumed_at_unix"), bool),
                    f"final challenge consumption ledger entry {index} timestamp is invalid",
                )
            require(
                len(entries) < FINAL_CHALLENGE_LEDGER_MAX_ENTRIES,
                "final challenge consumption ledger is full; rotate it explicitly before issuing another challenge",
            )
            consumed_at = int(time.time()) if consumed_at_unix is None else consumed_at_unix
            require(
                isinstance(consumed_at, int) and not isinstance(consumed_at, bool),
                "final challenge consumption time is invalid",
            )
            updated_entries = [
                *entries,
                {
                    "challenge_nonce_sha256": challenge_digest,
                    "completion_identity_sha256": completion_digest,
                    "consumed_at_unix": consumed_at,
                },
            ]
            updated_ledger = {
                "apiVersion": FINAL_CHALLENGE_LEDGER_API_VERSION,
                "max_entries": FINAL_CHALLENGE_LEDGER_MAX_ENTRIES,
                "entries": updated_entries,
            }
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=ledger_path.parent,
                prefix=f".{ledger_path.name}.",
                delete=False,
            ) as temporary:
                temporary_path = Path(temporary.name)
                os.fchmod(temporary.fileno(), 0o600)
                temporary.write(canonical_json(updated_ledger) + "\n")
                temporary.flush()
                os.fsync(temporary.fileno())
            os.replace(temporary_path, ledger_path)
            temporary_path = None
            directory_fd = os.open(ledger_path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
            return {
                "consumed": True,
                "challenge_nonce_sha256": challenge_digest,
                "completion_identity_sha256": completion_digest,
                "ledger_path": str(ledger_path),
                "ledger_entries": len(updated_entries),
                "ledger_max_entries": FINAL_CHALLENGE_LEDGER_MAX_ENTRIES,
                "ledger_trust": "verifier-owned external durable storage; host rollback resistance is supplied by that storage",
            }
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def final_completion_identity(
    hardware_assurance: dict[str, Any],
    *,
    current_host_identity_sha256: str,
    proxy_server_statement_sha256: str,
) -> dict[str, str]:
    return {
        "apiVersion": FINAL_COMPLETION_IDENTITY_API_VERSION,
        "release_identity_sha256": require_sha256(
            hardware_assurance.get("release_identity_sha256"),
            "final completion release identity digest",
        ),
        "current_host_identity_sha256": require_sha256(
            current_host_identity_sha256,
            "final completion current-host identity digest",
        ),
        "hardware_verifier_key_id": require_sha256(
            hardware_assurance.get("trusted_verifier_key_id"),
            "final completion hardware verifier key id",
        ),
        "hardware_assurance_document_sha256": require_sha256(
            hardware_assurance.get("hardware_assurance_document_sha256"),
            "final completion hardware assurance document digest",
        ),
        "hardware_assurance_signed_statement_sha256": require_sha256(
            hardware_assurance.get("hardware_assurance_signed_statement_sha256"),
            "final completion hardware assurance signed statement digest",
        ),
        "challenge_nonce_sha256": require_sha256(
            hardware_assurance.get("challenge_nonce_sha256"),
            "final completion challenge digest",
        ),
        "proxy_server_statement_sha256": require_sha256(
            proxy_server_statement_sha256,
            "final completion proxy server statement digest",
        ),
    }


def verify_final_challenge_receipt(
    document: dict[str, Any],
    *,
    trusted_public_key_pem: str,
    expected_trusted_public_key_id: str,
    final_challenge_receipt_sha256: str,
    expected_provider: str,
    expected_challenge_nonce_sha256: str,
    expected_completion_identity_sha256: str,
    expected_release_identity_sha256: str,
    expected_hardware_verifier_key_id: str,
    expected_current_host_identity_sha256: str,
    expected_proxy_server_statement_sha256: str,
    hardware_assurance_issued_at_unix: int,
    now_unix: int | None = None,
) -> dict[str, Any]:
    require_exact_keys(
        document,
        {"apiVersion", "kind", "statement", "signing_key_id", "signature"},
        "final challenge receipt",
    )
    require(
        document.get("apiVersion") == FINAL_CHALLENGE_RECEIPT_API_VERSION,
        "final challenge receipt apiVersion mismatch",
    )
    require(document.get("kind") == "FinalChallengeConsumption", "final challenge receipt kind mismatch")
    statement = document.get("statement") if isinstance(document.get("statement"), dict) else {}
    require_exact_keys(
        statement,
        {
            "authority_provider",
            "consumption_id",
            "status",
            "issued_at_unix",
            "expires_at_unix",
            "challenge_nonce_sha256",
            "completion_identity_sha256",
            "release_identity_sha256",
            "hardware_verifier_key_id",
            "current_host_identity_sha256",
            "proxy_server_statement_sha256",
        },
        "final challenge receipt statement",
    )
    provider = statement.get("authority_provider")
    consumption_id = statement.get("consumption_id")
    require(isinstance(provider, str) and 1 <= len(provider) <= 256, "final challenge authority provider is invalid")
    require(provider == expected_provider, "final challenge receipt authority provider mismatch")
    require(
        isinstance(consumption_id, str) and 1 <= len(consumption_id) <= 128,
        "final challenge receipt consumption id is invalid",
    )
    require(statement.get("status") == "consumed", "final challenge receipt did not consume the challenge")
    issued_at = statement.get("issued_at_unix")
    expires_at = statement.get("expires_at_unix")
    require(
        isinstance(issued_at, int) and not isinstance(issued_at, bool),
        "final challenge receipt issued_at_unix is invalid",
    )
    require(
        isinstance(expires_at, int) and not isinstance(expires_at, bool),
        "final challenge receipt expires_at_unix is invalid",
    )
    now = int(time.time()) if now_unix is None else now_unix
    require(issued_at <= now + HARDWARE_PROOF_FUTURE_SKEW_SECONDS, "final challenge receipt is issued in the future")
    require(expires_at > now, "final challenge receipt is expired")
    require(expires_at > issued_at, "final challenge receipt validity interval is invalid")
    require(
        expires_at - issued_at <= FINAL_CHALLENGE_RECEIPT_MAX_AGE_SECONDS,
        "final challenge receipt validity interval is too long",
    )
    require(
        issued_at >= hardware_assurance_issued_at_unix,
        "final challenge receipt predates the hardware assurance",
    )
    expected_fields = {
        "challenge_nonce_sha256": require_sha256(
            expected_challenge_nonce_sha256, "expected final challenge digest"
        ),
        "completion_identity_sha256": require_sha256(
            expected_completion_identity_sha256, "expected final completion identity digest"
        ),
        "release_identity_sha256": require_sha256(
            expected_release_identity_sha256, "expected final release identity digest"
        ),
        "hardware_verifier_key_id": require_sha256(
            expected_hardware_verifier_key_id, "expected hardware verifier key id"
        ),
        "current_host_identity_sha256": require_sha256(
            expected_current_host_identity_sha256, "expected current host identity digest"
        ),
        "proxy_server_statement_sha256": require_sha256(
            expected_proxy_server_statement_sha256, "expected proxy server statement digest"
        ),
    }
    for field, expected in expected_fields.items():
        actual = require_sha256(statement.get(field), f"final challenge receipt {field}")
        require(hmac.compare_digest(actual, expected), f"final challenge receipt {field} mismatch")
    trusted_key_id = release_public_key_id(trusted_public_key_pem)
    expected_authority_key_id = require_sha256(
        expected_trusted_public_key_id,
        "expected final challenge authority public key id",
    )
    require(
        hmac.compare_digest(trusted_key_id, expected_authority_key_id),
        "final challenge authority key bytes do not match the independently configured SPKI identity",
    )
    require(
        document.get("signing_key_id") == trusted_key_id,
        "final challenge receipt is not signed by the independently trusted authority key",
    )
    signed_statement_bytes = canonical_json(statement).encode("utf-8")
    verify_ed25519(
        trusted_public_key_pem,
        str(document.get("signature") or ""),
        signed_statement_bytes,
        "final challenge receipt",
    )
    return {
        "consumed": True,
        "authority_provider": provider,
        "authority_key_id": trusted_key_id,
        "consumption_id": consumption_id,
        "issued_at_unix": issued_at,
        "expires_at_unix": expires_at,
        "challenge_nonce_sha256": expected_fields["challenge_nonce_sha256"],
        "completion_identity_sha256": expected_fields["completion_identity_sha256"],
        "receipt_sha256": require_sha256(
            final_challenge_receipt_sha256,
            "final challenge receipt document digest",
        ),
        "receipt_signed_statement_sha256": sha256_prefixed_bytes(signed_statement_bytes),
        "trust_boundary": "off-host authority atomically consumes challenges and signs receipts",
    }


def verify_release_security_evidence(
    *,
    paths: dict[str, Path],
    production_build: dict[str, Any],
    benchmark: dict[str, Any],
    attested_runtime: dict[str, Any],
    preflight: dict[str, Any],
) -> dict[str, Any]:
    identity = verify_production_policy_identity.verify_persisted_report(
        bundle_path=paths["policy_bundle"],
        trusted_public_key_path=paths["policy_trusted_public_key"],
        report_path=paths["policy_identity_verification"],
    )
    require(identity["policyHash"] == benchmark["policy_hash"], "identity-verified policy does not match benchmark policy")
    require(identity["policyHash"] == attested_runtime["policy_digest"], "identity-verified policy does not match Nitro-attested policy")

    activation = production_release_input_preflight.verify_externally_signed_report(
        report_path=paths["policy_activation_verification"],
        signature_path=paths["policy_activation_signature"],
        trusted_public_key_path=paths["policy_activation_trusted_public_key"],
        purpose=production_release_input_preflight.ACTIVATION_PURPOSE,
        api_version=production_release_input_preflight.ACTIVATION_API_VERSION,
        kind=production_release_input_preflight.ACTIVATION_KIND,
    )
    activation_report = activation["report"]
    require(activation_report.get("production_mode") is True, "policy activation report is not production evidence")
    require(activation_report.get("environment") == "production", "policy activation environment is not production")
    require(
        activation_report.get("candidate_policy_hash") == identity["policyHash"],
        "activated candidate does not match the identity-verified policy",
    )

    reproducibility = production_release_input_preflight.verify_externally_signed_report(
        report_path=paths["reproducible_build_verification"],
        signature_path=paths["reproducible_build_signature"],
        trusted_public_key_path=paths["reproducible_build_trusted_public_key"],
        purpose=production_release_input_preflight.REPRODUCIBILITY_PURPOSE,
        api_version=production_release_input_preflight.REPRODUCIBILITY_API_VERSION,
        kind=production_release_input_preflight.REPRODUCIBILITY_KIND,
    )
    reproducibility_report = reproducibility["report"]
    require(reproducibility_report.get("reproducible") is True, "reproducible-build report did not pass")
    reproducibility_scope = reproducibility_report.get("scope")
    require(
        isinstance(reproducibility_scope, dict)
        and reproducibility_scope.get("independent_execution_proven") is True,
        "reproducible-build report did not prove two independent trusted builders",
    )
    require(
        reproducibility_report.get("source_tree_digest") == production_build["source_tree_digest"],
        "reproducible-build source digest does not match the production build",
    )
    expected_images = {
        item.get("service"): item.get("image_id")
        for item in production_build.get("images") or []
        if isinstance(item, dict)
    }
    reproduced_images = {
        item.get("service"): item.get("image_id")
        for item in reproducibility_report.get("images") or []
        if isinstance(item, dict)
    }
    require(reproduced_images == expected_images, "reproducible-build image IDs do not match the production build")
    production_gate = next(
        (item for item in production_build.get("images") or [] if item.get("service") == "serverware-decision-gate"),
        {},
    )
    reproduced_gate = next(
        (item for item in reproducibility_report.get("images") or [] if item.get("service") == "serverware-decision-gate"),
        {},
    )
    require(
        reproduced_gate.get("rust_binary_sha256") == production_gate.get("binary_digest"),
        "reproducible-build Rust binary digest does not match the production build",
    )
    production_launcher_binary_digest = require_sha256(
        production_gate.get("launcher_binary_digest"),
        "production build launcher binary digest",
    )
    require(
        reproduced_gate.get("launcher_binary_sha256")
        == production_launcher_binary_digest,
        "reproducible-build launcher binary digest does not match the production build",
    )
    preflight_security = preflight.get("release_security_evidence") or {}
    require(preflight_security.get("policy_identity") == identity, "completion policy identity differs from host preflight")
    require(
        (preflight_security.get("policy_activation") or {}).get("reportSha256") == activation["reportSha256"],
        "completion activation evidence differs from host preflight",
    )
    require(
        (preflight_security.get("reproducible_builds") or {}).get("reportSha256") == reproducibility["reportSha256"],
        "completion reproducibility evidence differs from host preflight",
    )
    return {
        "trust_roots": preflight_security.get("trust_roots") or {},
        "policy_identity": identity,
        "policy_activation": {key: value for key, value in activation.items() if key != "report"},
        "reproducible_builds": {
            **{key: value for key, value in reproducibility.items() if key != "report"},
            "scope": reproducibility_scope,
            "sourceTreeDigest": reproducibility_report.get("source_tree_digest"),
            "productionLauncherBinaryDigest": production_launcher_binary_digest,
            "productionBuildBound": True,
        },
        "benchmarkPolicyBound": True,
        "nitroAttestedPolicyBound": True,
    }


def verify_bootstrap_launcher_authorization(
    bootstrap_receipt: dict[str, Any],
    *,
    signed_provenance_digest: str,
    independently_reproduced_digest: str,
) -> dict[str, Any]:
    receipt_launcher = bootstrap_receipt.get("launcher")
    require(isinstance(receipt_launcher, dict), "sealed launcher receipt has no launcher identity")
    receipt_launcher_digest = require_sha256(
        receipt_launcher.get("sha256"),
        "sealed launcher receipt executable digest",
    )
    signed_provenance_digest = require_sha256(
        signed_provenance_digest,
        "signed provenance production launcher digest",
    )
    independently_reproduced_digest = require_sha256(
        independently_reproduced_digest,
        "independent-build production launcher digest",
    )
    require(
        receipt_launcher_digest
        == signed_provenance_digest
        == independently_reproduced_digest,
        "executed launcher digest does not match signed provenance and independent-build evidence",
    )
    expected_launcher_path = (
        "/opt/serverware/launchers/sha256-"
        + receipt_launcher_digest.removeprefix("sha256:")
        + "/serverware-production-launcher"
    )
    require(
        receipt_launcher.get("path") == expected_launcher_path,
        "executed launcher path is not content-addressed by the independently authorized digest",
    )
    return {
        "sha256": receipt_launcher_digest,
        "path": expected_launcher_path,
        "signed_provenance_bound": True,
        "independent_build_bound": True,
        "content_addressed_path_bound": True,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify Serverware release readiness and independently proven final completion.")
    parser.add_argument(
        "--verification-mode",
        choices=("readiness", "final"),
        default="readiness",
        help="Readiness never claims final completion; final fails closed unless all final evidence and one-use state pass.",
    )
    parser.add_argument("--final-challenge-receipt", default=None)
    parser.add_argument("--final-challenge-authority-public-key", default=None)
    parser.add_argument("--final-challenge-authority-public-key-id", default=None)
    parser.add_argument("--final-challenge-authority-provider", default=None)
    parser.add_argument("--production-readiness", default=".tmp/production-readiness.json")
    parser.add_argument("--production-readiness-config", default=".tmp/production-readiness-config.json")
    parser.add_argument("--production-readiness-env", default="ops/production-readiness.env")
    parser.add_argument(
        "--launcher-trusted-production-env-path",
        default=os.getenv(run_production_readiness.LAUNCHER_TRUSTED_ENV_PATH_INPUT),
    )
    parser.add_argument(
        "--launcher-trusted-production-env-sha256",
        default=os.getenv(run_production_readiness.LAUNCHER_TRUSTED_ENV_SHA256_INPUT),
    )
    parser.add_argument("--docker-executable", default=None)
    parser.add_argument("--docker-compose-plugin-executable", default=None)
    parser.add_argument("--docker-unix-socket", default=None)
    parser.add_argument("--docker-daemon-id", default=None)
    parser.add_argument("--production-host-preflight-signing-public-key", default=None)
    parser.add_argument("--production-host-preflight-signing-key-id", default=None)
    parser.add_argument("--production-host-preflight-max-age-seconds", type=int, default=None)
    parser.add_argument("--compose-file", default="docker-compose.production.yml")
    parser.add_argument("--production-host-preflight", default=".tmp/production-host-preflight.json")
    parser.add_argument("--nitro-evidence", default=".tmp/nitro-kms-evidence.json")
    parser.add_argument("--hardware-assurance", default=None)
    parser.add_argument("--hardware-assurance-trusted-public-key", default=None)
    parser.add_argument("--hardware-assurance-trusted-public-key-id", default=None)
    parser.add_argument(
        "--hardware-assurance-expected-challenge-nonce",
        default=None,
        help="Expected hardware-verifier challenge as unpadded base64url.",
    )
    parser.add_argument(
        "--hardware-assurance-expected-challenge-nonce-sha256",
        default=None,
        help="Expected hardware-verifier challenge digest as sha256:<64 lowercase hex>.",
    )
    parser.add_argument("--production-images-build", default=".tmp/production-images-build.json")
    parser.add_argument("--production-images-env", default=".tmp/production-images.env")
    parser.add_argument("--production-images-published", default=".tmp/production-images-published.json")
    parser.add_argument("--release-provenance-summary", default=".tmp/release-provenance-summary.json")
    parser.add_argument("--release-provenance", default=".tmp/release-provenance.json")
    parser.add_argument("--release-provenance-trusted-public-key", required=True)
    parser.add_argument("--image-signatures-summary", default=".tmp/image-signatures-summary.json")
    parser.add_argument("--image-signatures", default=".tmp/image-signatures.json")
    parser.add_argument("--sigstore-trusted-public-key", required=True)
    parser.add_argument("--rekor-trusted-public-key", required=True)
    parser.add_argument("--external-checkpoint-provider", required=True)
    parser.add_argument("--external-checkpoint-trusted-public-key", required=True)
    parser.add_argument("--bench", default=".tmp/decision-gate-rs-bench.json")
    parser.add_argument("--policy-bundle", required=True)
    parser.add_argument("--policy-trusted-public-key", required=True)
    parser.add_argument("--policy-trusted-public-key-id", default=None)
    parser.add_argument("--policy-identity-verification", required=True)
    parser.add_argument("--policy-activation-verification", required=True)
    parser.add_argument("--policy-activation-signature", required=True)
    parser.add_argument("--policy-activation-trusted-public-key", required=True)
    parser.add_argument("--policy-activation-trusted-public-key-id", default=None)
    parser.add_argument("--reproducible-build-verification", required=True)
    parser.add_argument("--reproducible-build-signature", required=True)
    parser.add_argument("--reproducible-build-trusted-public-key", required=True)
    parser.add_argument("--reproducible-build-trusted-public-key-id", default=None)
    parser.add_argument("--kms-materials", default="/etc/serverware/kms-materials.json")
    parser.add_argument(
        "--control-plane-response-signing-public-key",
        default=None,
    )
    parser.add_argument(
        "--control-plane-response-signing-public-key-id",
        default=None,
    )
    parser.add_argument("--proxy-response-proof", default=None)
    parser.add_argument("--proxy-proof-verifier-public-key", default=None)
    parser.add_argument("--proxy-collector-public-key", default=None)
    parser.add_argument("--proxy-server-instance-id", default=None)
    parser.add_argument("--proxy-client-nonce", default=None)
    parser.add_argument("--proxy-client-request-digest", default=None)
    parser.add_argument("--proxy-request-digest", default=None)
    parser.add_argument("--proxy-operation-digest", default=None)
    parser.add_argument("--proxy-tls-channel-binding", default=None)
    parser.add_argument("--proxy-proof-max-age-seconds", type=int, default=None)
    parser.add_argument("--p99-limit-ms", type=float, default=None)
    parser.add_argument("--out", default=None)
    parser.add_argument("--skip-current-host-check", action="store_true", help="Test-only bypass for synthetic fixture completion tests.")
    args = parser.parse_args()

    require(
        bool(args.hardware_assurance) == bool(args.hardware_assurance_trusted_public_key),
        "hardware-backed completion requires both --hardware-assurance and --hardware-assurance-trusted-public-key",
    )
    supplied_hardware_challenges = sum(
        value is not None
        for value in (
            args.hardware_assurance_expected_challenge_nonce,
            args.hardware_assurance_expected_challenge_nonce_sha256,
        )
    )
    if args.hardware_assurance:
        require(
            supplied_hardware_challenges == 1,
            "hardware-backed completion requires exactly one --hardware-assurance-expected-challenge-nonce "
            "or --hardware-assurance-expected-challenge-nonce-sha256",
        )
    else:
        require(
            supplied_hardware_challenges == 0,
            "hardware assurance expected challenge options require --hardware-assurance",
        )
    if args.verification_mode == "final":
        forbidden_environment = run_production_readiness.forbidden_process_environment_names(
            dict(os.environ)
        )
        require(
            not forbidden_environment,
            "final verifier environment contains forbidden runtime/loader injection settings: "
            + ", ".join(forbidden_environment),
        )
        require(sys.flags.isolated == 1, "final verifier Python interpreter must run in isolated mode")
        require(bool(args.docker_executable), "final verification mode requires --docker-executable")
        require(
            bool(args.docker_compose_plugin_executable),
            "final verification mode requires --docker-compose-plugin-executable",
        )
        require(bool(args.docker_unix_socket), "final verification mode requires --docker-unix-socket")
        require(bool(args.docker_daemon_id), "final verification mode requires --docker-daemon-id")
        require(
            bool(args.production_host_preflight_signing_public_key),
            "final verification mode requires --production-host-preflight-signing-public-key",
        )
        require(
            bool(args.production_host_preflight_signing_key_id),
            "final verification mode requires --production-host-preflight-signing-key-id",
        )
        require(
            isinstance(args.production_host_preflight_max_age_seconds, int),
            "final verification mode requires --production-host-preflight-max-age-seconds",
        )
        require(bool(args.hardware_assurance), "final verification mode requires hardware assurance evidence")
        require(bool(args.final_challenge_receipt), "final verification mode requires --final-challenge-receipt")
        require(
            bool(args.final_challenge_authority_public_key),
            "final verification mode requires --final-challenge-authority-public-key",
        )
        require(
            bool(args.final_challenge_authority_public_key_id),
            "final verification mode requires --final-challenge-authority-public-key-id",
        )
        require(
            bool(args.hardware_assurance_trusted_public_key_id),
            "final verification mode requires --hardware-assurance-trusted-public-key-id",
        )
        require(
            bool(args.final_challenge_authority_provider),
            "final verification mode requires --final-challenge-authority-provider",
        )
        require(not args.skip_current_host_check, "final verification mode forbids --skip-current-host-check")
        bootstrap_receipt, _ = run_production_readiness.load_sealed_bootstrap_receipt(
            required=True
        )
    else:
        bootstrap_receipt = None
        require(
            not any(
                (
                    args.final_challenge_receipt,
                    args.final_challenge_authority_public_key,
                    args.final_challenge_authority_public_key_id,
                    args.final_challenge_authority_provider,
                    args.hardware_assurance_trusted_public_key_id,
                )
            ),
            "final challenge receipt options are only valid with --verification-mode final",
        )
    require(
        bool(args.control_plane_response_signing_public_key),
        "production completion requires --control-plane-response-signing-public-key",
    )
    require(
        bool(args.control_plane_response_signing_public_key_id),
        "production completion requires --control-plane-response-signing-public-key-id",
    )
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
    require(
        bool(args.proxy_client_request_digest),
        "production completion requires --proxy-client-request-digest",
    )
    require(bool(args.proxy_request_digest), "production completion requires --proxy-request-digest")
    require(bool(args.proxy_operation_digest), "production completion requires --proxy-operation-digest")
    require(bool(args.proxy_tls_channel_binding), "production completion requires --proxy-tls-channel-binding")

    paths = {
        "production_readiness": Path(args.production_readiness),
        "production_readiness_config": Path(args.production_readiness_config),
        "production_readiness_env": Path(args.production_readiness_env),
        "production_host_preflight": Path(args.production_host_preflight),
        **(
            {
                "production_host_preflight_signing_public_key": Path(
                    args.production_host_preflight_signing_public_key
                )
            }
            if args.production_host_preflight_signing_public_key
            else {}
        ),
        "nitro_evidence": Path(args.nitro_evidence),
        "production_images_build": Path(args.production_images_build),
        "production_images_env": Path(args.production_images_env),
        "production_images_published": Path(args.production_images_published),
        "release_provenance_summary": Path(args.release_provenance_summary),
        "release_provenance": Path(args.release_provenance),
        "release_provenance_trusted_public_key": Path(args.release_provenance_trusted_public_key),
        "image_signatures_summary": Path(args.image_signatures_summary),
        "image_signatures": Path(args.image_signatures),
        "sigstore_trusted_public_key": Path(args.sigstore_trusted_public_key),
        "rekor_trusted_public_key": Path(args.rekor_trusted_public_key),
        "external_checkpoint_trusted_public_key": Path(args.external_checkpoint_trusted_public_key),
        "bench": Path(args.bench),
        "policy_bundle": Path(args.policy_bundle),
        "policy_trusted_public_key": Path(args.policy_trusted_public_key),
        "policy_identity_verification": Path(args.policy_identity_verification),
        "policy_activation_verification": Path(args.policy_activation_verification),
        "policy_activation_signature": Path(args.policy_activation_signature),
        "policy_activation_trusted_public_key": Path(args.policy_activation_trusted_public_key),
        "reproducible_build_verification": Path(args.reproducible_build_verification),
        "reproducible_build_signature": Path(args.reproducible_build_signature),
        "reproducible_build_trusted_public_key": Path(args.reproducible_build_trusted_public_key),
        "kms_materials": Path(args.kms_materials),
        "control_plane_response_signing_public_key": Path(
            args.control_plane_response_signing_public_key
        ),
        "proxy_response_proof": Path(args.proxy_response_proof),
        "proxy_proof_verifier_public_key": Path(args.proxy_proof_verifier_public_key),
        "proxy_collector_public_key": Path(args.proxy_collector_public_key),
        "compose_file": Path(args.compose_file),
    }
    if args.hardware_assurance:
        paths["hardware_assurance"] = Path(args.hardware_assurance)
        paths["hardware_assurance_trusted_public_key"] = Path(args.hardware_assurance_trusted_public_key)
    if args.verification_mode == "final":
        paths["final_challenge_receipt"] = Path(args.final_challenge_receipt)
        paths["final_challenge_authority_public_key"] = Path(args.final_challenge_authority_public_key)

    trust_root_keys = {
        "release_provenance_trusted_public_key",
        "sigstore_trusted_public_key",
        "rekor_trusted_public_key",
        "external_checkpoint_trusted_public_key",
        "policy_trusted_public_key",
        "policy_activation_trusted_public_key",
        "reproducible_build_trusted_public_key",
        "control_plane_response_signing_public_key",
        "proxy_proof_verifier_public_key",
        "proxy_collector_public_key",
        "hardware_assurance_trusted_public_key",
        "final_challenge_authority_public_key",
        "production_host_preflight_signing_public_key",
    }
    input_limits: dict[str, tuple[str, int]] = {}
    for key in paths:
        if key in trust_root_keys:
            max_bytes = FINAL_TRUST_ROOT_MAX_BYTES
        elif key == "production_readiness_env" or key == "production_images_env":
            max_bytes = ENV_INPUT_MAX_BYTES
        elif key == "compose_file":
            max_bytes = COMPOSE_INPUT_MAX_BYTES
        elif key == "policy_bundle":
            max_bytes = POLICY_BUNDLE_MAX_BYTES
        else:
            max_bytes = COMPLETION_INPUT_MAX_BYTES
        input_limits[key] = (key.replace("_", " "), max_bytes)
    input_snapshots = InputSnapshots()
    final_file_snapshots = input_snapshots.capture_many(paths, input_limits)
    stable_input_directory, stable_paths = materialize_snapshots(
        final_file_snapshots,
        tuple(paths),
    )

    readiness = load_json_snapshot(final_file_snapshots["production_readiness"], "production readiness")
    production_readiness_config = load_json_snapshot(final_file_snapshots["production_readiness_config"], "production readiness config")
    production_host_preflight = load_json_snapshot(final_file_snapshots["production_host_preflight"], "production host preflight")
    nitro_evidence = load_json_snapshot(final_file_snapshots["nitro_evidence"], "Nitro/KMS evidence")
    production_images_build = load_json_snapshot(final_file_snapshots["production_images_build"], "production images build")
    production_images_published = load_json_snapshot(final_file_snapshots["production_images_published"], "production images published")
    provenance_summary = load_json_snapshot(final_file_snapshots["release_provenance_summary"], "release provenance summary")
    provenance_document = load_json_snapshot(final_file_snapshots["release_provenance"], "release provenance")
    image_summary = load_json_snapshot(final_file_snapshots["image_signatures_summary"], "image signatures summary")
    image_document = load_json_snapshot(final_file_snapshots["image_signatures"], "image signatures")
    bench = load_json_snapshot(final_file_snapshots["bench"], "decision-gate benchmark")
    proxy_response_proof = load_json_snapshot(
        final_file_snapshots["proxy_response_proof"],
        "production proxy response proof",
    )
    trusted_control_plane_response_signing_public_key_pem = snapshot_text(
        final_file_snapshots[
            "control_plane_response_signing_public_key"
        ],
        "control-plane response signing trust root",
        encoding="ascii",
    )
    trusted_proxy_verifier_public_key_pem = snapshot_text(
        final_file_snapshots["proxy_proof_verifier_public_key"],
        "proxy proof vendor verifier trust root",
        encoding="ascii",
    )
    trusted_proxy_collector_public_key_pem = snapshot_text(
        final_file_snapshots["proxy_collector_public_key"],
        "proxy response collector trust root",
        encoding="ascii",
    )

    readiness_summary = verify_readiness(readiness)
    preflight_summary = verify_production_host_preflight(
        production_host_preflight,
        paths,
        input_snapshots,
        readiness_summary,
        verification_mode=args.verification_mode,
        preflight_signing_public_key=final_file_snapshots.get(
            "production_host_preflight_signing_public_key"
        ),
        preflight_signing_key_id=args.production_host_preflight_signing_key_id,
        preflight_max_age_seconds=args.production_host_preflight_max_age_seconds,
        expected_bootstrap_receipt=bootstrap_receipt,
    )
    current_host_summary = verify_current_completion_host(
        preflight_summary,
        skip_current_host_check=args.skip_current_host_check,
    )
    production_config_summary = verify_production_config_result(production_readiness_config, preflight_summary)
    production_env_binding = verify_current_production_env_binding(
        paths,
        input_snapshots,
        readiness_summary,
        preflight_summary,
        production_config_summary,
        verification_mode=args.verification_mode,
        release_trust_inputs={
            RELEASE_PROVENANCE_TRUST_ROOT_ENV_KEY: args.release_provenance_trusted_public_key,
            SIGSTORE_TRUST_ROOT_ENV_KEY: args.sigstore_trusted_public_key,
            REKOR_TRUST_ROOT_ENV_KEY: args.rekor_trusted_public_key,
            EXTERNAL_CHECKPOINT_TRUST_ROOT_ENV_KEY: args.external_checkpoint_trusted_public_key,
            EXTERNAL_CHECKPOINT_PROVIDER_ENV_KEY: args.external_checkpoint_provider,
            CONTROL_PLANE_RESPONSE_SIGNING_KEY_ENV_KEY: (
                args.control_plane_response_signing_public_key
            ),
            CONTROL_PLANE_RESPONSE_SIGNING_KEY_ID_ENV_KEY: (
                args.control_plane_response_signing_public_key_id
            ),
            run_production_readiness.POLICY_TRUST_ROOT_ENV: (
                args.policy_trusted_public_key
            ),
            run_production_readiness.POLICY_TRUST_ROOT_ID_ENV: (
                args.policy_trusted_public_key_id
            ),
            run_production_readiness.POLICY_ACTIVATION_TRUST_ROOT_ENV: (
                args.policy_activation_trusted_public_key
            ),
            run_production_readiness.POLICY_ACTIVATION_TRUST_ROOT_ID_ENV: (
                args.policy_activation_trusted_public_key_id
            ),
            run_production_readiness.REPRODUCIBLE_BUILD_TRUST_ROOT_ENV: (
                args.reproducible_build_trusted_public_key
            ),
            run_production_readiness.REPRODUCIBLE_BUILD_TRUST_ROOT_ID_ENV: (
                args.reproducible_build_trusted_public_key_id
            ),
        },
        final_inputs={
            FINAL_HARDWARE_ASSURANCE_ENV_KEY: args.hardware_assurance,
            FINAL_HARDWARE_TRUST_ROOT_ENV_KEY: args.hardware_assurance_trusted_public_key,
            FINAL_HARDWARE_TRUST_ROOT_ID_ENV_KEY: args.hardware_assurance_trusted_public_key_id,
            FINAL_HARDWARE_CHALLENGE_NONCE_ENV_KEY: args.hardware_assurance_expected_challenge_nonce,
            FINAL_HARDWARE_CHALLENGE_DIGEST_ENV_KEY: args.hardware_assurance_expected_challenge_nonce_sha256,
            FINAL_CHALLENGE_RECEIPT_ENV_KEY: args.final_challenge_receipt,
            FINAL_CHALLENGE_AUTHORITY_TRUST_ROOT_ENV_KEY: args.final_challenge_authority_public_key,
            FINAL_CHALLENGE_AUTHORITY_TRUST_ROOT_ID_ENV_KEY: args.final_challenge_authority_public_key_id,
            FINAL_CHALLENGE_AUTHORITY_PROVIDER_ENV_KEY: args.final_challenge_authority_provider,
        },
        final_file_snapshots=final_file_snapshots,
        proxy_digest_inputs={
            attribute: getattr(args, attribute)
            for attribute in PROXY_EXPECTED_DIGEST_ENV_KEYS
        },
        launcher_trust_inputs={
            run_production_readiness.LAUNCHER_TRUSTED_ENV_PATH_INPUT: (
                args.launcher_trusted_production_env_path
            ),
            run_production_readiness.LAUNCHER_TRUSTED_ENV_SHA256_INPUT: (
                args.launcher_trusted_production_env_sha256
            ),
        },
        proxy_proof_max_age_seconds=args.proxy_proof_max_age_seconds,
        p99_limit_ms=args.p99_limit_ms,
        docker_executable=args.docker_executable,
        docker_compose_plugin_executable=args.docker_compose_plugin_executable,
        docker_unix_socket=args.docker_unix_socket,
        docker_daemon_id=args.docker_daemon_id,
        preflight_signing_public_key=args.production_host_preflight_signing_public_key,
        preflight_signing_key_id=args.production_host_preflight_signing_key_id,
        preflight_max_age_seconds=args.production_host_preflight_max_age_seconds,
    )
    production_env = load_production_env_snapshot(
        final_file_snapshots["production_readiness_env"]
    )
    args.proxy_proof_max_age_seconds = production_env_binding[
        "proxy_proof_max_age_seconds"
    ]
    args.p99_limit_ms = production_env_binding["p99_limit_ms"]
    args.docker_executable = production_env_binding["docker_executable"]
    args.docker_compose_plugin_executable = production_env_binding[
        "docker_compose_plugin_executable"
    ]
    args.docker_unix_socket = production_env_binding["docker_unix_socket"]
    args.docker_daemon_id = production_env_binding["docker_daemon_id"]
    if args.verification_mode == "final":
        production_env_binding["executing_interpreter"] = verify_current_interpreter_binding(
            production_env,
            production_env_binding["current_executable_digests"],
        )
        production_env_binding["executing_script"] = verify_current_script_binding(
            production_env
        )
    trusted_release_public_key_pem = snapshot_text(
        final_file_snapshots["release_provenance_trusted_public_key"],
        "release provenance trust root",
        encoding="ascii",
    )
    trusted_sigstore_public_key_pem = snapshot_text(
        final_file_snapshots["sigstore_trusted_public_key"],
        "Sigstore trust root",
        encoding="ascii",
    )
    trusted_rekor_public_key_pem = snapshot_text(
        final_file_snapshots["rekor_trusted_public_key"],
        "Rekor trust root",
        encoding="ascii",
    )
    trusted_external_public_key_pem = snapshot_text(
        final_file_snapshots["external_checkpoint_trusted_public_key"],
        "external checkpoint trust root",
        encoding="ascii",
    )
    trusted_external_log_id = release_public_key_id(trusted_external_public_key_pem)
    require(
        readiness_summary["external_transparency_provider"] == args.external_checkpoint_provider,
        "live readiness external transparency provider does not match the independently expected provider",
    )
    require(
        readiness_summary["external_transparency_log_id"] == trusted_external_log_id,
        "live readiness external transparency log does not match the independently trusted key",
    )
    require(
        hmac.compare_digest(
            ed25519_public_key_id(
                trusted_control_plane_response_signing_public_key_pem,
                "control-plane response signing trust root",
            ),
            production_env_binding[
                "control_plane_response_signing_public_key_id"
            ],
        ),
        "loaded control-plane response signing trust root identity differs from the hashed production readiness env binding",
    )
    for loaded_key_pem, binding_key, label in (
        (
            trusted_release_public_key_pem,
            "release_provenance_trusted_public_key_id",
            "release provenance trust root",
        ),
        (trusted_sigstore_public_key_pem, "sigstore_trusted_public_key_id", "Sigstore trust root"),
        (trusted_rekor_public_key_pem, "rekor_trusted_public_key_id", "Rekor trust root"),
        (
            trusted_external_public_key_pem,
            "external_checkpoint_trusted_public_key_id",
            "external checkpoint trust root",
        ),
    ):
        require(
            release_public_key_id(loaded_key_pem) == production_env_binding[binding_key],
            f"loaded {label} identity differs from the hashed production readiness env binding",
        )
    nitro_summary = verify_nitro_evidence(nitro_evidence, "standalone Nitro/KMS evidence")
    nitro_binding = verify_nitro_binding(readiness_summary, nitro_summary, preflight_summary)
    hardware_assurance_summary = None
    hardware_assurance_document = None
    trusted_hardware_verifier_public_key_pem = None
    trusted_final_challenge_authority_public_key_pem = None
    if args.hardware_assurance:
        hardware_assurance_document = load_json_snapshot(
            final_file_snapshots["hardware_assurance"],
            "hardware assurance",
        )
        trusted_hardware_verifier_public_key_pem = snapshot_text(
            final_file_snapshots["hardware_assurance_trusted_public_key"],
            "hardware assurance trust root",
            encoding="ascii",
        )
        if args.verification_mode == "final":
            require(
                hmac.compare_digest(
                    release_public_key_id(trusted_hardware_verifier_public_key_pem),
                    production_env_binding["hardware_assurance_trusted_public_key_id"],
                ),
                "loaded hardware assurance trust root identity differs from the hashed production readiness env binding",
            )
    if args.verification_mode == "final":
        trusted_final_challenge_authority_public_key_pem = snapshot_text(
            final_file_snapshots["final_challenge_authority_public_key"],
            "final challenge authority trust root",
            encoding="ascii",
        )
        require(
            hmac.compare_digest(
                release_public_key_id(trusted_final_challenge_authority_public_key_pem),
                production_env_binding["final_challenge_authority_public_key_id"],
            ),
            "loaded final challenge authority trust root identity differs from the hashed production readiness env binding",
        )
    provenance_summary_out = verify_release_provenance(
        provenance_summary,
        provenance_document,
        str(readiness_summary["external_transparency_provider"]),
        str(readiness_summary["external_transparency_log_id"]),
        trusted_release_public_key_pem,
        trusted_external_public_key_pem,
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
        env_file=stable_paths["production_readiness_env"],
        compose_file=stable_paths["compose_file"],
        production_env=production_env,
        project_directory=paths["compose_file"].parent.resolve(),
        production_image_refs=list(readiness_summary["production_images"]),
        source_tree_digest=current_source_tree_digest,
        runtime_model=preflight_summary["production_runtime_model"],
        artifact_expectations={
            "/run/serverware/release/release-provenance.json": {
                "sha256": final_file_snapshots["release_provenance"].sha256,
                "bytes": len(final_file_snapshots["release_provenance"].data),
            },
            "/run/serverware/release/image-signatures.json": {
                "sha256": final_file_snapshots["image_signatures"].sha256,
                "bytes": len(final_file_snapshots["image_signatures"].data),
            },
        },
        compose_project_name=production_env_binding[
            "docker_compose_project_name"
        ],
        skip_current_host_check=args.skip_current_host_check,
        docker_executable=args.docker_executable,
        docker_sha256=production_env_binding["current_executable_digests"][
            run_production_readiness.PRODUCTION_DOCKER_EXECUTABLE_ENV
        ],
        compose_plugin_executable=args.docker_compose_plugin_executable,
        compose_plugin_sha256=production_env_binding["docker_compose_plugin_sha256"],
        docker_unix_socket=args.docker_unix_socket,
        docker_daemon_id=args.docker_daemon_id,
        final_mode=args.verification_mode == "final",
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
        trusted_sigstore_public_key_pem,
        trusted_rekor_public_key_pem,
        trusted_external_public_key_pem,
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
    verified_release_identity = validate_release_identity(
        {
            "source_tree_digest": provenance_summary_out["source_tree_digest"],
            "provenance_digest": provenance_summary_out["provenance_digest"],
            "runtime_manifest_digest": attested_runtime["runtime_manifest_digest"],
            "data_plane_binary_digest": attested_runtime["data_plane_binary_digest"],
            "production_image_digests": readiness_summary["production_image_digests"],
            "production_image_refs": readiness_summary["production_images"],
            "production_images_build_sha256": final_file_snapshots["production_images_build"].sha256,
            "production_images_published_sha256": final_file_snapshots["production_images_published"].sha256,
            "image_signature_bundle_digest": image_summary_out["image_signature_bundle_digest"],
        },
        "independently verified release identity",
    )
    if bootstrap_receipt is not None:
        require(
            bootstrap_receipt.get("sourceTreeDigest")
            == provenance_summary_out["source_tree_digest"],
            "sealed launcher receipt source tree does not match signed release provenance",
        )
    if hardware_assurance_document is not None:
        require(
            trusted_hardware_verifier_public_key_pem is not None,
            "hardware assurance trusted verifier key was not loaded",
        )
        hardware_assurance_summary = verify_hardware_assurance(
            hardware_assurance_document,
            trusted_public_key_pem=trusted_hardware_verifier_public_key_pem,
            expected_trusted_public_key_id=(
                args.hardware_assurance_trusted_public_key_id
                if args.verification_mode == "final"
                else None
            ),
            hardware_assurance_document_sha256=final_file_snapshots[
                "hardware_assurance"
            ].sha256,
            nitro_summary=nitro_summary,
            nitro_evidence_sha256=final_file_snapshots["nitro_evidence"].sha256,
            production_host_preflight_sha256=final_file_snapshots["production_host_preflight"].sha256,
            current_host=current_host_summary,
            expected_release_identity=verified_release_identity,
            expected_challenge_nonce=args.hardware_assurance_expected_challenge_nonce,
            expected_challenge_nonce_sha256=args.hardware_assurance_expected_challenge_nonce_sha256,
        )
    release_security_summary = verify_release_security_evidence(
        paths=stable_paths,
        production_build=production_images_build_summary,
        benchmark=benchmark_summary,
        attested_runtime=attested_runtime,
        preflight=preflight_summary,
    )
    if bootstrap_receipt is not None:
        launcher_authorization = verify_bootstrap_launcher_authorization(
            bootstrap_receipt,
            signed_provenance_digest=provenance_summary_out[
                "production_launcher_binary_digest"
            ],
            independently_reproduced_digest=(
                release_security_summary.get("reproducible_builds") or {}
            ).get("productionLauncherBinaryDigest"),
        )
        provenance_summary_out["executed_production_launcher"] = launcher_authorization
        release_security_summary["reproducible_builds"][
            "executedProductionLauncherBound"
        ] = True
    policy_snapshot = verify_and_compile_policy_snapshot(
        final_file_snapshots["policy_bundle"],
        final_file_snapshots["policy_trusted_public_key"],
        expected_policy_digest=str(attested_runtime["policy_digest"]),
    )
    proxy_response_summary = verify_production_proxy_response_proof(
        proxy_response_proof,
        trusted_verifier_public_key_pem=trusted_proxy_verifier_public_key_pem,
        trusted_collector_public_key_pem=trusted_proxy_collector_public_key_pem,
        trusted_control_plane_response_signing_public_key_pem=(
            trusted_control_plane_response_signing_public_key_pem
        ),
        expected_control_plane_response_signing_public_key_id=(
            args.control_plane_response_signing_public_key_id
        ),
        policy_snapshot=policy_snapshot,
        expected_principal_id=production_env_binding[
            "expected_proxy_principal_id"
        ],
        expected_server_instance_id=str(args.proxy_server_instance_id),
        expected_client_nonce=str(args.proxy_client_nonce),
        expected_client_request_digest=str(args.proxy_client_request_digest),
        expected_request_digest=str(args.proxy_request_digest),
        expected_operation_digest=str(args.proxy_operation_digest),
        expected_tls_channel_binding=str(args.proxy_tls_channel_binding),
        expected_policy_digest=str(attested_runtime["policy_digest"]),
        expected_runtime_manifest_digest=str(attested_runtime["runtime_manifest_digest"]),
        expected_binary_digest=str(attested_runtime["data_plane_binary_digest"]),
        expected_release_digest=str(attested_runtime["provenance_digest"]),
        expected_image_signatures_digest=str(
            image_summary_out["image_signature_bundle_digest"]
        ),
        expected_source_tree_digest=str(attested_runtime["source_tree_digest"]),
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
    candidate_assurance = completion_assurance(hardware_assurance_summary, current_host_summary)
    final_challenge_consumption: dict[str, Any] | None = None
    if args.verification_mode == "final":
        require(
            candidate_assurance.get("final_completion") is True,
            "final verification mode did not satisfy hardware-backed final completion requirements",
        )
        require(hardware_assurance_summary is not None, "final verification mode is missing hardware assurance summary")
        completion_identity = final_completion_identity(
            hardware_assurance_summary,
            current_host_identity_sha256=current_host_summary["identity"]["identity_sha256"],
            proxy_server_statement_sha256=proxy_response_summary["server_statement_sha256"],
        )
        completion_identity_sha256 = sha256_prefixed_json(completion_identity)
        final_challenge_consumption = verify_final_challenge_receipt(
            load_json_snapshot(
                final_file_snapshots["final_challenge_receipt"],
                "final challenge receipt",
            ),
            trusted_public_key_pem=str(trusted_final_challenge_authority_public_key_pem),
            expected_trusted_public_key_id=str(
                args.final_challenge_authority_public_key_id
            ),
            final_challenge_receipt_sha256=final_file_snapshots[
                "final_challenge_receipt"
            ].sha256,
            expected_provider=str(args.final_challenge_authority_provider),
            expected_challenge_nonce_sha256=hardware_assurance_summary["challenge_nonce_sha256"],
            expected_completion_identity_sha256=completion_identity_sha256,
            expected_release_identity_sha256=hardware_assurance_summary["release_identity_sha256"],
            expected_hardware_verifier_key_id=hardware_assurance_summary["trusted_verifier_key_id"],
            expected_current_host_identity_sha256=current_host_summary["identity"]["identity_sha256"],
            expected_proxy_server_statement_sha256=proxy_response_summary["server_statement_sha256"],
            hardware_assurance_issued_at_unix=hardware_assurance_summary["issued_at_unix"],
        )
        final_challenge_consumption["completion_identity"] = completion_identity
        assurance = candidate_assurance
    else:
        assurance = candidate_assurance
        if candidate_assurance.get("final_completion") is True:
            assurance = {
                "level": "pre-enclave-readiness",
                "final_completion": False,
                "hardware_proof": False,
                "hardware_evidence_verified": True,
                "reason": "readiness verification mode never claims or consumes final completion",
                "required_final_evidence": [
                    "rerun with --verification-mode final and an off-host challenge-authority consumption receipt"
                ],
            }

    proof = {
        "apiVersion": "serverware.completionProof/v4",
        "kind": "ServerwareCompletionProof" if assurance["final_completion"] else "ServerwarePreEnclaveReadiness",
        "ok": True,
        "verification_passed": True,
        "verification_mode": args.verification_mode,
        "result_scope": "final-completion" if assurance["final_completion"] else "readiness-only",
        "readiness_only": not assurance["final_completion"],
        "readiness_ok": True,
        "completion_status": assurance["level"],
        "release_completion": "pass" if assurance["final_completion"] else "not-final",
        "final_completion": assurance["final_completion"],
        "hardware_proof": assurance["hardware_proof"],
        "assurance_ceiling": assurance,
        "generated_at_unix": int(time.time()),
        "artifacts": {
            label: {
                "path": str(snapshot.path),
                "sha256": snapshot.sha256,
            }
            for label, snapshot in sorted(final_file_snapshots.items())
        },
        "production_readiness": readiness_summary,
        "production_readiness_config": production_config_summary,
        "current_completion_host": current_host_summary,
        "production_env_binding": production_env_binding,
        "running_production_containers": running_containers,
        "production_host_preflight": preflight_summary,
        "bootstrap_launcher": bootstrap_receipt
        if bootstrap_receipt is not None
        else {"required": False, "verified": False},
        "nitro_kms_evidence": nitro_summary,
        "nitro_evidence_binding": nitro_binding,
        "hardware_assurance_evidence": hardware_assurance_summary
        if hardware_assurance_summary is not None
        else {"provided": False, "verified": False},
        "final_challenge_consumption": final_challenge_consumption
        if final_challenge_consumption is not None
        else {"required": args.verification_mode == "final", "consumed": False},
        "production_images_build": production_images_build_summary,
        "production_images_published": production_images_published_summary,
        "release_provenance": provenance_summary_out,
        "image_signatures": image_summary_out,
        "benchmark": benchmark_summary,
        "release_security_evidence": release_security_summary,
        "production_proxy_response_proof": proxy_response_summary,
    }
    if args.out:
        proof["proof_path"] = args.out
        generation = secrets.token_hex(16)
        proof_digest_path = completion_proof_digest_path(Path(args.out), generation)
        proof["integrity_metadata"] = {
            "generation": generation,
            "detached_sha256_path": str(proof_digest_path),
            "scope": "checksum-only",
            "independently_authenticated": False,
            "authenticity_requires_external_signature_or_checkpoint": True,
        }
        proof["proof_sha256"] = write_output(Path(args.out), proof)
        proof["proof_sha256_path"] = str(proof_digest_path)
    print(canonical_json(proof))
    stable_input_directory.cleanup()


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(canonical_json({"ok": False, "error": str(exc)}), file=sys.stderr)
        raise SystemExit(1) from exc
