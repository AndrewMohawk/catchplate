#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import ipaddress
import json
import os
import platform
import re
import shlex
import stat
import subprocess
import sys
import time
import urllib.parse
from functools import partial
from pathlib import Path
from typing import Any

import collect_nitro_kms_evidence
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey


ROOT = Path(__file__).resolve().parent.parent
REQUIRED_MATERIALS = {"broker-kek", "decision-gate-ca"}
READINESS_CHECKS = [
    "no-dev-fixtures",
    "control-plane-auth",
    "oauth-providers",
    "nitro",
    "attested-credential-delivery",
    "release-completion-trust",
    "final-challenge-authority",
    "cosign-sigstore",
    "external-transparency",
    "apparmor",
    "internal-service-auth",
    "shared-stores",
    "agent-egress",
    "production-images-no-shell",
]
METADATA_TABLES = (
    "credentials",
    "pending_oauth_credentials",
    "oidc_login_states",
    "oidc_browser_sessions",
    "oauth_revocation_work",
    "routes",
    "approval_requests",
    "control_plane_approvals",
    "webauthn_credentials",
    "webauthn_challenges",
    "webauthn_recovery_ceremonies",
    "webauthn_recovery_revocations",
    "webauthn_recovery_root_state",
    "webauthn_trust_publications",
    "metadata_audit_outbox",
    "gmail_message_cache",
    "request_logs",
    "rate_limit_counters",
    "release_authorization_attempts",
    "release_authorization_quota_reservations",
    "release_authorization_events",
    "policy_high_water",
)
GRANT_TABLES = ("approval_grants", "approval_grant_consumptions")
AUDIT_TABLES = ("serverware_audit_events",)
RECOVERY_WITNESS_TABLES = (
    "serverware_recovery_authorization_claims",
    "serverware_recovery_witness_heads",
)
KMS_KEY_PREFIXES = (
    "awskms://",
    "gcpkms://",
    "azurekms://",
    "hashivault://",
    "pkcs11:",
    "kms://",
)
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
BASE64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")
INTERNAL_SERVICE_TOKEN_NAMES = (
    "SERVERWARE_DATA_PLANE_CREDENTIAL_LEASE_TOKEN",
    "SERVERWARE_DATA_PLANE_AUDIT_TOKEN",
    "SERVERWARE_DATA_PLANE_GRANT_CONSUME_TOKEN",
    "SERVERWARE_DATA_PLANE_RATE_LIMIT_CONSUME_TOKEN",
    "SERVERWARE_DATA_PLANE_RELEASE_AUTHORIZATION_TOKEN",
    "SERVERWARE_DATA_PLANE_MANAGEMENT_TOKEN",
)
MAX_OAUTH_CLIENT_SECRET_FILE_BYTES = 4096
MAX_TRUSTED_PUBLIC_KEY_FILE_BYTES = 65536
MAX_FINAL_CHALLENGE_RECEIPT_FILE_BYTES = 1048576
MAX_HARDWARE_ASSURANCE_FILE_BYTES = 1048576
CONTROL_PLANE_RUNTIME_UID = 65532
CONTROL_PLANE_RUNTIME_GID = 65532
MAX_POSIX_ID = (1 << 32) - 2
HARDWARE_PROOF_API_VERSION = "serverware.hardwareAssurance/v1"
HARDWARE_PROOF_MAX_AGE_SECONDS = 900
HARDWARE_PROOF_FUTURE_SKEW_SECONDS = 30
FINAL_CHALLENGE_RECEIPT_API_VERSION = "serverware.finalChallengeReceipt/v1"
FINAL_CHALLENGE_RECEIPT_MAX_AGE_SECONDS = 900
SETUP_TRUST_KEY_SETTINGS = (
    "SERVERWARE_SETUP_ENROLLMENT_VERIFIER_PUBLIC_KEY",
    "SERVERWARE_SETUP_HARDWARE_VERIFIER_PUBLIC_KEY",
    "SERVERWARE_SETUP_FINAL_AUTHORITY_PUBLIC_KEY",
    "SERVERWARE_WEBAUTHN_RECOVERY_ROOT_PUBLIC_KEY",
)
RELEASE_TRUST_KEY_SETTINGS = (
    "SERVERWARE_RELEASE_PROVENANCE_TRUSTED_PUBLIC_KEY",
    "SERVERWARE_SIGSTORE_TRUSTED_PUBLIC_KEY",
    "SERVERWARE_REKOR_TRUSTED_PUBLIC_KEY",
    "SERVERWARE_EXTERNAL_CHECKPOINT_TRUSTED_PUBLIC_KEY",
    "SERVERWARE_HARDWARE_ASSURANCE_TRUSTED_PUBLIC_KEY",
    "SERVERWARE_FINAL_CHALLENGE_AUTHORITY_PUBLIC_KEY",
    "SERVERWARE_POLICY_SIGNING_PUBLIC_KEY",
    "SERVERWARE_RESPONSE_SIGNING_PUBLIC_KEY",
    "SERVERWARE_WEBAUTHN_TRUST_SIGNING_PUBLIC_KEY",
    "SERVERWARE_TEE_QUOTE_SIGNING_PUBLIC_KEY",
)
REQUIRED_ONLINE_SIGNING_PUBLIC_KEYS = (
    "SERVERWARE_POLICY_SIGNING_PUBLIC_KEY",
    "SERVERWARE_RESPONSE_SIGNING_PUBLIC_KEY",
    "SERVERWARE_WEBAUTHN_TRUST_SIGNING_PUBLIC_KEY",
)
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
HARDWARE_ASSURANCE_STATEMENT_FIELDS = {
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
}
FINAL_CHALLENGE_STATEMENT_FIELDS = {
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
}


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def require_valid(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def reject_duplicate_json_object_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    parsed: dict[str, Any] = {}
    for key, value in pairs:
        if key in parsed:
            raise ValueError(f"duplicate JSON object key: {key}")
        parsed[key] = value
    return parsed


def reject_json_float(value: str) -> float:
    raise ValueError(f"floating-point JSON values are forbidden: {value}")


def reject_json_constant(value: str) -> float:
    raise ValueError(f"non-finite JSON values are forbidden: {value}")


def strict_json_object(payload: bytes, label: str) -> dict[str, Any]:
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"{label} must be valid UTF-8 JSON") from exc
    try:
        parsed = json.loads(
            text,
            object_pairs_hook=reject_duplicate_json_object_keys,
            parse_float=reject_json_float,
            parse_constant=reject_json_constant,
        )
    except (json.JSONDecodeError, ValueError) as exc:
        raise ValueError(f"{label} must be strict JSON: {exc}") from exc
    require_valid(isinstance(parsed, dict), f"{label} must be a JSON object")
    return parsed


def require_exact_keys(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    require_valid(isinstance(value, dict), f"{label} must be an object")
    missing = sorted(expected - set(value))
    unexpected = sorted(set(value) - expected)
    require_valid(not missing, f"{label} is missing required fields: {missing}")
    require_valid(not unexpected, f"{label} contains unexpected fields: {unexpected}")
    return value


def require_sha256(value: Any, label: str) -> str:
    require_valid(
        isinstance(value, str) and SHA256_RE.fullmatch(value) is not None,
        f"{label} must be a sha256-prefixed digest",
    )
    return value


def require_integer(value: Any, label: str) -> int:
    require_valid(
        isinstance(value, int) and not isinstance(value, bool),
        f"{label} must be an integer",
    )
    return value


def bounded_non_root_id(value: str) -> int:
    try:
        parsed = int(value, 10)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a decimal integer") from exc
    if not 1 <= parsed <= MAX_POSIX_ID:
        raise argparse.ArgumentTypeError(
            f"must be between 1 and {MAX_POSIX_ID}"
        )
    return parsed


def file_readable_by_identity(
    file_stat: os.stat_result,
    *,
    uid: int,
    gid: int,
) -> bool:
    mode = stat.S_IMODE(file_stat.st_mode)
    if file_stat.st_uid == uid:
        return bool(mode & stat.S_IRUSR)
    if file_stat.st_gid == gid:
        return bool(mode & stat.S_IRGRP)
    return bool(mode & stat.S_IROTH)


def decode_canonical_base64url(value: Any, label: str) -> bytes:
    require_valid(
        isinstance(value, str)
        and bool(value)
        and BASE64URL_RE.fullmatch(value) is not None
        and len(value) % 4 != 1,
        f"{label} must be canonical unpadded base64url",
    )
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except Exception as exc:
        raise ValueError(f"{label} must be canonical unpadded base64url") from exc
    require_valid(
        base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") == value,
        f"{label} must be canonical unpadded base64url",
    )
    return decoded


def decode_ed25519_signature(value: Any, label: str) -> bytes:
    require_valid(
        isinstance(value, str) and value.startswith("ed25519:"),
        f"{label} must use the ed25519 signature scheme",
    )
    decoded = decode_canonical_base64url(value.removeprefix("ed25519:"), label)
    require_valid(len(decoded) == 64, f"{label} must decode to exactly 64 bytes")
    return decoded


def verify_ed25519_statement_signature(
    public_key: Ed25519PublicKey,
    signature: Any,
    statement: dict[str, Any],
    label: str,
) -> None:
    signature_bytes = decode_ed25519_signature(signature, f"{label} signature")
    try:
        public_key.verify(signature_bytes, canonical_json(statement).encode("utf-8"))
    except InvalidSignature as exc:
        raise ValueError(f"{label} signature verification failed") from exc


def sha256_prefixed_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def sha256_prefixed_json(value: Any) -> str:
    return sha256_prefixed_bytes(canonical_json(value).encode("utf-8"))


def validate_hardware_assurance_document(
    document: dict[str, Any],
    *,
    trusted_public_key: Ed25519PublicKey,
    trusted_key_id: str,
    expected_trusted_key_id: str,
    expected_challenge_nonce: str | None,
    expected_challenge_nonce_sha256: str | None,
    now_unix: int | None = None,
) -> dict[str, Any]:
    require_exact_keys(
        document,
        {"apiVersion", "kind", "statement", "signing_key_id", "signature"},
        "hardware assurance document",
    )
    require_valid(
        document.get("apiVersion") == HARDWARE_PROOF_API_VERSION,
        f"SERVERWARE_HARDWARE_ASSURANCE must contain a {HARDWARE_PROOF_API_VERSION} document",
    )
    require_valid(
        document.get("kind") == "ServerwareHardwareAssurance",
        "hardware assurance kind must be ServerwareHardwareAssurance",
    )
    statement = require_exact_keys(
        document.get("statement"),
        HARDWARE_ASSURANCE_STATEMENT_FIELDS,
        "hardware assurance statement",
    )
    verifier = require_exact_keys(
        statement.get("verifier"),
        {"name", "organization", "independent"},
        "hardware assurance verifier identity",
    )
    require_valid(
        isinstance(verifier.get("name"), str) and bool(verifier.get("name")),
        "hardware assurance verifier name is missing",
    )
    require_valid(
        isinstance(verifier.get("organization"), str)
        and bool(verifier.get("organization")),
        "hardware assurance verifier organization is missing",
    )
    require_valid(
        verifier.get("independent") is True,
        "hardware assurance verifier must be independent",
    )
    current_host = require_exact_keys(
        statement.get("current_host_identity"),
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
    require_exact_keys(
        statement.get("pcrs"),
        {"PCR0", "PCR1", "PCR2"},
        "hardware assurance PCR measurements",
    )
    eif = require_exact_keys(
        statement.get("eif"),
        {
            "image_sha384",
            "build_manifest",
            "build_manifest_sha256",
            "signature_verified",
            "evidence_sha256",
        },
        "hardware assurance EIF evidence",
    )
    build_manifest = require_exact_keys(
        eif.get("build_manifest"),
        {
            "apiVersion",
            "release_identity",
            "release_identity_sha256",
            "eif_image_sha384",
            "pcrs",
        },
        "hardware assurance EIF build manifest",
    )
    require_exact_keys(
        build_manifest.get("release_identity"),
        RELEASE_IDENTITY_FIELDS,
        "hardware assurance EIF release identity",
    )
    require_exact_keys(
        build_manifest.get("pcrs"),
        {"PCR0", "PCR1", "PCR2"},
        "hardware assurance EIF build manifest PCR measurements",
    )
    require_exact_keys(
        statement.get("enclave"),
        {
            "cid",
            "parent_cid",
            "vsock_port",
            "cid_evidence_sha256",
            "vsock_evidence_sha256",
            "vsock_handshake_verified",
        },
        "hardware assurance enclave evidence",
    )
    require_exact_keys(
        statement.get("key_custody"),
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
    require_exact_keys(
        statement.get("no_parent_key"),
        {"verified", "parent_key_material_absent", "evidence_sha256"},
        "hardware assurance no-parent-key evidence",
    )
    require_exact_keys(
        statement.get("release_bindings"),
        {
            "policy_digest",
            "policy_sequence",
            "policy_high_water_digest",
            "runtime_manifest_digest",
            "data_plane_binary_digest",
            "provenance_digest",
            "source_tree_digest",
            "response_signing_key_id",
        },
        "hardware assurance release bindings",
    )
    require_exact_keys(
        statement.get("artifact_bindings"),
        {"nitro_evidence_sha256", "production_host_preflight_sha256"},
        "hardware assurance artifact bindings",
    )

    expected_key_id = require_sha256(
        expected_trusted_key_id,
        "SERVERWARE_HARDWARE_ASSURANCE_TRUSTED_PUBLIC_KEY_ID",
    )
    require_valid(
        hmac.compare_digest(trusted_key_id, expected_key_id),
        "hardware assurance verifier key bytes do not match SERVERWARE_HARDWARE_ASSURANCE_TRUSTED_PUBLIC_KEY_ID",
    )
    signing_key_id = require_sha256(
        document.get("signing_key_id"),
        "hardware assurance signing key id",
    )
    require_valid(
        hmac.compare_digest(signing_key_id, trusted_key_id),
        "hardware assurance signer does not match the independently trusted verifier key",
    )
    verify_ed25519_statement_signature(
        trusted_public_key,
        document.get("signature"),
        statement,
        "hardware assurance",
    )

    issued_at = require_integer(
        statement.get("issued_at_unix"), "hardware assurance issued_at_unix"
    )
    expires_at = require_integer(
        statement.get("expires_at_unix"), "hardware assurance expires_at_unix"
    )
    now = int(time.time()) if now_unix is None else now_unix
    require_valid(
        issued_at <= now + HARDWARE_PROOF_FUTURE_SKEW_SECONDS,
        "hardware assurance was issued in the future",
    )
    require_valid(
        now - issued_at <= HARDWARE_PROOF_MAX_AGE_SECONDS,
        "hardware assurance is stale",
    )
    require_valid(expires_at >= now, "hardware assurance has expired")
    require_valid(expires_at > issued_at, "hardware assurance expiry does not follow issuance")
    require_valid(
        expires_at - issued_at <= HARDWARE_PROOF_MAX_AGE_SECONDS,
        "hardware assurance validity window exceeds the allowed maximum",
    )

    challenge_nonce_bytes = decode_canonical_base64url(
        statement.get("challenge_nonce"), "hardware assurance challenge nonce"
    )
    require_valid(
        len(challenge_nonce_bytes) >= 32,
        "hardware assurance challenge nonce must contain at least 32 bytes",
    )
    require_valid(
        sum(
            bool(value)
            for value in (expected_challenge_nonce, expected_challenge_nonce_sha256)
        )
        == 1,
        "hardware assurance verification requires exactly one expected challenge",
    )
    challenge_nonce_sha256 = sha256_prefixed_bytes(challenge_nonce_bytes)
    if expected_challenge_nonce:
        expected_nonce_bytes = decode_canonical_base64url(
            expected_challenge_nonce,
            "SERVERWARE_HARDWARE_ASSURANCE_EXPECTED_CHALLENGE_NONCE",
        )
        require_valid(len(expected_nonce_bytes) >= 32, "expected hardware challenge is too short")
        challenge_matches = hmac.compare_digest(
            challenge_nonce_bytes, expected_nonce_bytes
        )
    else:
        challenge_matches = hmac.compare_digest(
            challenge_nonce_sha256,
            require_sha256(
                expected_challenge_nonce_sha256,
                "SERVERWARE_HARDWARE_ASSURANCE_EXPECTED_CHALLENGE_NONCE_SHA256",
            ),
        )
    require_valid(
        challenge_matches,
        "hardware assurance challenge nonce does not match the configured expected challenge",
    )
    return {
        "issued_at_unix": issued_at,
        "challenge_nonce_sha256": challenge_nonce_sha256,
        "release_identity_sha256": require_sha256(
            build_manifest.get("release_identity_sha256"),
            "hardware assurance release identity digest",
        ),
        "current_host_identity_sha256": require_sha256(
            current_host.get("identity_sha256"),
            "hardware assurance current-host identity digest",
        ),
        "trusted_verifier_key_id": trusted_key_id,
    }


def validate_final_challenge_receipt_document(
    document: dict[str, Any],
    *,
    trusted_public_key: Ed25519PublicKey,
    trusted_key_id: str,
    expected_trusted_key_id: str,
    expected_provider: str,
    expected_challenge_nonce_sha256: str,
    expected_hardware_verifier_key_id: str,
    hardware_assurance_summary: dict[str, Any] | None,
    now_unix: int | None = None,
) -> None:
    require_exact_keys(
        document,
        {"apiVersion", "kind", "statement", "signing_key_id", "signature"},
        "final challenge receipt",
    )
    require_valid(
        document.get("apiVersion") == FINAL_CHALLENGE_RECEIPT_API_VERSION,
        f"SERVERWARE_FINAL_CHALLENGE_RECEIPT must contain a {FINAL_CHALLENGE_RECEIPT_API_VERSION} document",
    )
    require_valid(
        document.get("kind") == "FinalChallengeConsumption",
        "final challenge receipt kind must be FinalChallengeConsumption",
    )
    statement = require_exact_keys(
        document.get("statement"),
        FINAL_CHALLENGE_STATEMENT_FIELDS,
        "final challenge receipt statement",
    )
    provider = statement.get("authority_provider")
    require_valid(
        isinstance(provider, str) and 1 <= len(provider) <= 256,
        "final challenge authority provider is invalid",
    )
    require_valid(
        hmac.compare_digest(provider, expected_provider),
        "SERVERWARE_FINAL_CHALLENGE_RECEIPT authority provider must match the configured provider",
    )
    consumption_id = statement.get("consumption_id")
    require_valid(
        isinstance(consumption_id, str) and 1 <= len(consumption_id) <= 128,
        "final challenge receipt consumption id is invalid",
    )
    require_valid(
        statement.get("status") == "consumed",
        "final challenge receipt must consume the challenge",
    )
    issued_at = require_integer(
        statement.get("issued_at_unix"), "final challenge receipt issued_at_unix"
    )
    expires_at = require_integer(
        statement.get("expires_at_unix"), "final challenge receipt expires_at_unix"
    )
    now = int(time.time()) if now_unix is None else now_unix
    require_valid(
        issued_at <= now + HARDWARE_PROOF_FUTURE_SKEW_SECONDS,
        "final challenge receipt was issued in the future",
    )
    require_valid(expires_at > now, "final challenge receipt is expired")
    require_valid(
        expires_at > issued_at,
        "final challenge receipt validity interval is invalid",
    )
    require_valid(
        expires_at - issued_at <= FINAL_CHALLENGE_RECEIPT_MAX_AGE_SECONDS,
        "final challenge receipt validity interval is too long",
    )

    expected_fields = {
        "challenge_nonce_sha256": require_sha256(
            expected_challenge_nonce_sha256,
            "expected final challenge digest",
        ),
        "hardware_verifier_key_id": require_sha256(
            expected_hardware_verifier_key_id,
            "expected hardware assurance verifier key id",
        ),
    }
    for field, expected in expected_fields.items():
        actual = require_sha256(
            statement.get(field), f"final challenge receipt {field}"
        )
        require_valid(
            hmac.compare_digest(actual, expected),
            f"final challenge receipt {field} mismatch",
        )
    for field in (
        "completion_identity_sha256",
        "release_identity_sha256",
        "current_host_identity_sha256",
        "proxy_server_statement_sha256",
    ):
        require_sha256(statement.get(field), f"final challenge receipt {field}")
    if hardware_assurance_summary is not None:
        require_valid(
            issued_at >= hardware_assurance_summary["issued_at_unix"],
            "final challenge receipt predates the hardware assurance",
        )
        for field in (
            "release_identity_sha256",
            "current_host_identity_sha256",
        ):
            require_valid(
                hmac.compare_digest(
                    statement[field], hardware_assurance_summary[field]
                ),
                f"final challenge receipt {field} does not match hardware assurance",
            )

    expected_key_id = require_sha256(
        expected_trusted_key_id,
        "SERVERWARE_FINAL_CHALLENGE_AUTHORITY_PUBLIC_KEY_ID",
    )
    require_valid(
        hmac.compare_digest(trusted_key_id, expected_key_id),
        "final challenge authority key bytes do not match SERVERWARE_FINAL_CHALLENGE_AUTHORITY_PUBLIC_KEY_ID",
    )
    signing_key_id = require_sha256(
        document.get("signing_key_id"),
        "final challenge receipt signing key id",
    )
    require_valid(
        hmac.compare_digest(signing_key_id, trusted_key_id),
        "final challenge receipt is not signed by the independently trusted authority key",
    )
    verify_ed25519_statement_signature(
        trusted_public_key,
        document.get("signature"),
        statement,
        "final challenge receipt",
    )


def redacted_environment_summary(env: dict[str, str]) -> dict[str, Any]:
    return {
        "env_keys": sorted(key for key in env if key.startswith("SERVERWARE_")),
        "production_readiness_env_path": env.get("SERVERWARE_PRODUCTION_READINESS_ENV_PATH"),
        "production_readiness_env_sha256": env.get("SERVERWARE_PRODUCTION_READINESS_ENV_SHA256"),
        "production_images_env_path": env.get("SERVERWARE_PRODUCTION_IMAGES_ENV_PATH"),
        "production_images_env_sha256": env.get("SERVERWARE_PRODUCTION_IMAGES_ENV_SHA256"),
        "secret_values_redacted": True,
    }


def env_bool(env: dict[str, str], name: str, default: bool = False) -> bool:
    raw = env.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def env_json_object(env: dict[str, str], name: str) -> dict[str, Any] | None:
    raw = env.get(name, "").strip()
    if not raw:
        return None
    parsed = json.loads(raw)
    if not isinstance(parsed, dict):
        raise ValueError(f"{name} must be a JSON object")
    return parsed


def command_words(raw: str) -> list[str]:
    try:
        return shlex.split(raw)
    except ValueError:
        return []


def command_mentions(raw: str, *needles: str) -> bool:
    lowered = " ".join(command_words(raw)).lower()
    return any(needle.lower() in lowered for needle in needles)


def placeholder_hostname(hostname: str | None) -> bool:
    if not hostname:
        return False
    lowered = hostname.rstrip(".").lower()
    return lowered == "example" or lowered.endswith(".example")


def image_ref_hostname(image: str) -> str | None:
    repo = image.split("@", 1)[0]
    if "/" not in repo:
        return None
    return repo.split("/", 1)[0]


def add(failures: list[str], condition: bool, message: str) -> None:
    if not condition:
        failures.append(message)


def service_token_is_strong(token: str) -> bool:
    return len(token.encode("utf-8")) >= 32 and len(set(token)) >= 8


def valid_pcr_policy(raw: str) -> bool:
    try:
        policy = json.loads(raw)
    except json.JSONDecodeError:
        return False
    if not isinstance(policy, dict) or not policy:
        return False
    for key, value in policy.items():
        try:
            int(key)
            decoded = bytes.fromhex(str(value).removeprefix("sha384:"))
        except Exception:
            return False
        if len(decoded) != 48:
            return False
    return True


def check_no_dev_or_fixture(env: dict[str, str], failures: list[str]) -> None:
    add(failures, not env_bool(env, "SERVERWARE_DEV_AUTHENTICATOR"), "SERVERWARE_DEV_AUTHENTICATOR must be disabled")
    release_channel = env.get("SERVERWARE_RELEASE_CHANNEL", "").strip().lower()
    add(failures, release_channel not in {"", "dev", "local", "test"}, "SERVERWARE_RELEASE_CHANNEL must be a production channel")
    public_url = env.get("SERVERWARE_PUBLIC_URL", "").strip()
    if public_url:
        parsed = urllib.parse.urlparse(public_url)
        add(failures, parsed.scheme == "https", "SERVERWARE_PUBLIC_URL must use https in production")
        add(failures, parsed.hostname not in {"localhost", "127.0.0.1", "::1"}, "SERVERWARE_PUBLIC_URL must not be localhost")
        add(failures, not placeholder_hostname(parsed.hostname), "SERVERWARE_PUBLIC_URL must not use .example placeholder domains")


def check_control_plane_security(env: dict[str, str], failures: list[str]) -> None:
    token = env.get("SERVERWARE_ADMIN_TOKEN", "").strip()
    add(failures, bool(token), "SERVERWARE_ADMIN_TOKEN must be explicitly configured for production")
    add(failures, len(token) >= 32, "SERVERWARE_ADMIN_TOKEN must be at least 32 characters")
    add(
        failures,
        token not in {"dev-admin-token", "admin", "password", "changeme", "serverware"},
        "SERVERWARE_ADMIN_TOKEN must not use a development/default value",
    )
    anchor_token = env.get("SERVERWARE_AUDIT_ANCHOR_TOKEN", "").strip()
    add(failures, len(anchor_token) >= 32, "SERVERWARE_AUDIT_ANCHOR_TOKEN must be at least 32 characters")
    add(failures, anchor_token != token, "audit-anchor token must be distinct from the admin token")
    for name in INTERNAL_SERVICE_TOKEN_NAMES:
        service_token = env.get(name, "").strip()
        if service_token:
            add(failures, anchor_token != service_token, f"audit-anchor token must be distinct from {name}")
            add(failures, token != service_token, f"admin token must be distinct from {name}")
    roles = {role.strip() for role in env.get("SERVERWARE_ADMIN_ROLES", "").split(",") if role.strip()}
    required_roles = {
        "admin",
        "approver",
        "attestation_operator",
        "attestation_reviewer",
        "auditor",
        "policy_author",
        "policy_publisher",
        "credential_owner",
    }
    add(
        failures,
        required_roles.issubset(roles),
        "SERVERWARE_ADMIN_ROLES must include the administrative, policy, credential, audit, approval, and setup attestation roles",
    )
    setup_trust_roles = (
        (
            "SERVERWARE_SETUP_ENROLLMENT_VERIFIER_PUBLIC_KEY",
            "SERVERWARE_SETUP_ENROLLMENT_VERIFIER_KEY_ID",
            "SERVERWARE_SETUP_ENROLLMENT_VERIFIER_PROVIDER",
        ),
        (
            "SERVERWARE_SETUP_HARDWARE_VERIFIER_PUBLIC_KEY",
            "SERVERWARE_SETUP_HARDWARE_VERIFIER_KEY_ID",
            "SERVERWARE_SETUP_HARDWARE_VERIFIER_PROVIDER",
        ),
        (
            "SERVERWARE_SETUP_FINAL_AUTHORITY_PUBLIC_KEY",
            "SERVERWARE_SETUP_FINAL_AUTHORITY_KEY_ID",
            "SERVERWARE_SETUP_FINAL_AUTHORITY_PROVIDER",
        ),
    )
    setup_key_ids: list[str] = []
    setup_providers: list[str] = []
    for path_name, id_name, provider_name in setup_trust_roles:
        actual_key_id = check_trusted_public_key_file(
            env, path_name, failures, require_ed25519=True
        )
        expected_key_id = env.get(id_name, "").strip()
        provider = env.get(provider_name, "").strip()
        add(
            failures,
            SHA256_RE.fullmatch(expected_key_id) is not None,
            f"{id_name} must be a lowercase SHA-256 digest",
        )
        add(
            failures,
            actual_key_id is not None
            and hmac.compare_digest(actual_key_id, expected_key_id),
            f"{path_name} SPKI identity must match {id_name}",
        )
        add(
            failures,
            re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}", provider)
            is not None,
            f"{provider_name} must be a canonical provider identifier",
        )
        if actual_key_id is not None:
            setup_key_ids.append(actual_key_id)
        if provider:
            setup_providers.append(provider)
    add(
        failures,
        len(set(setup_key_ids)) == 3,
        "setup enrollment, hardware, and final receipt roles must use distinct keys",
    )
    add(
        failures,
        len(set(setup_providers)) == 3,
        "setup enrollment, hardware, and final receipt roles must use distinct providers",
    )
    check_cross_domain_trust_key_separation(env, failures)
    try:
        setup_challenge_ttl = int(
            env.get("SERVERWARE_SETUP_ATTESTATION_CHALLENGE_TTL_SECONDS", "")
        )
    except ValueError:
        setup_challenge_ttl = 0
    add(
        failures,
        30 <= setup_challenge_ttl <= 900,
        "SERVERWARE_SETUP_ATTESTATION_CHALLENGE_TTL_SECONDS must be between 30 and 900",
    )
    add(failures, env_bool(env, "SERVERWARE_OIDC_ENABLED"), "control-plane OIDC authentication must be enabled")
    oidc_issuer = env.get("SERVERWARE_OIDC_ISSUER", "").strip()
    parsed_issuer = urllib.parse.urlparse(oidc_issuer)
    add(
        failures,
        parsed_issuer.scheme == "https" and bool(parsed_issuer.netloc),
        "SERVERWARE_OIDC_ISSUER must be an https URL",
    )
    add(
        failures,
        parsed_issuer.hostname not in {"localhost", "127.0.0.1", "::1"},
        "SERVERWARE_OIDC_ISSUER must not be localhost",
    )
    add(
        failures,
        not placeholder_hostname(parsed_issuer.hostname),
        "SERVERWARE_OIDC_ISSUER must not use .example placeholder domains",
    )
    add(failures, bool(env.get("SERVERWARE_OIDC_AUDIENCE", "").strip()), "SERVERWARE_OIDC_AUDIENCE must be configured")
    add(
        failures,
        bool(env.get("SERVERWARE_OIDC_JWKS_JSON", "").strip() or env.get("SERVERWARE_OIDC_JWKS_PATH", "").strip()),
        "SERVERWARE_OIDC_JWKS_JSON or SERVERWARE_OIDC_JWKS_PATH must be configured",
    )
    add(failures, bool(env.get("SERVERWARE_OIDC_ROLE_CLAIM", "").strip()), "SERVERWARE_OIDC_ROLE_CLAIM must be configured")
    add(
        failures,
        env_bool(env, "SERVERWARE_CONTROL_PLANE_MUTATION_WEBAUTHN_REQUIRED"),
        "high-risk control-plane mutations must require WebAuthn MFA",
    )
    add(
        failures,
        env_bool(
            env,
            "SERVERWARE_CONTROL_PLANE_MUTATION_REQUIRE_HARDWARE_ATTESTATION",
        ),
        "high-risk control-plane mutations must require hardware-attested WebAuthn",
    )
    mutation_authenticator_classes = {
        item.strip()
        for item in env.get(
            "SERVERWARE_CONTROL_PLANE_MUTATION_ALLOWED_AUTHENTICATOR_CLASSES", ""
        ).split(",")
        if item.strip()
    }
    add(
        failures,
        bool(mutation_authenticator_classes)
        and mutation_authenticator_classes.issubset({"yubikey", "hardware"}),
        "SERVERWARE_CONTROL_PLANE_MUTATION_ALLOWED_AUTHENTICATOR_CLASSES must be limited to yubikey and hardware",
    )
    add(
        failures,
        not env_bool(env, "SERVERWARE_DIRECT_CA_DOWNLOAD_ENABLED", default=True),
        "direct CA download must be disabled in production; use verifier-mediated install sessions",
    )
    try:
        ca_session_ttl = int(env.get("SERVERWARE_CA_INSTALL_SESSION_TTL_SECONDS", "0"))
    except ValueError:
        ca_session_ttl = 0
    add(
        failures,
        1 <= ca_session_ttl <= 900,
        "CA install session TTL must be configured between 1 and 900 seconds",
    )
    add(
        failures,
        env_bool(env, "SERVERWARE_CONTROL_PLANE_TWO_PERSON_REQUIRED"),
        "high-risk control-plane mutations must require two-person approval",
    )
    two_person_actions = {item.strip() for item in env.get("SERVERWARE_CONTROL_PLANE_TWO_PERSON_ACTIONS", "").split(",") if item.strip()}
    required_two_person_actions = {
        "credential.create",
        "credential.oauth.activate",
        "credential.oauth.uncertain.resolve",
        "credential.update",
        "credential.delete",
        "route.create",
        "route.update",
        "route.delete",
        "policy.publish",
        "webauthn.credential.register",
        "webauthn.credential.revoke",
        "webauthn.trust.publish",
        "rbac.role.change",
        "rbac.deprovision",
        "control_plane.token.rotate",
        "break_glass.grant",
        "setup.attestation.finalize",
    }
    add(
        failures,
        "*" in two_person_actions or required_two_person_actions.issubset(two_person_actions),
        "SERVERWARE_CONTROL_PLANE_TWO_PERSON_ACTIONS must cover credential creation, exact-account OAuth activation, uncertain OAuth issuance resolution, route, policy publish, WebAuthn enrollment, revocation, trust publication, RBAC, deprovisioning, token rotation, break-glass, and setup attestation finalization mutations",
    )
    bootstrap_token = env.get("SERVERWARE_WEBAUTHN_BOOTSTRAP_TOKEN", "")
    add(
        failures,
        len(bootstrap_token) >= 32,
        "SERVERWARE_WEBAUTHN_BOOTSTRAP_TOKEN must contain at least 32 characters",
    )
    add(
        failures,
        env_bool(env, "SERVERWARE_POLICY_PUBLISH_DRY_RUN_REQUIRED"),
        "policy publishing must require dry-run decision tests",
    )
    add(
        failures,
        env_bool(env, "SERVERWARE_POLICY_CANARY_REQUIRED"),
        "policy publishing must require canary activation before full activation",
    )
    try:
        canary_observation_seconds = int(env.get("SERVERWARE_POLICY_CANARY_MIN_OBSERVATION_SECONDS", "0"))
    except ValueError:
        canary_observation_seconds = 0
    add(
        failures,
        canary_observation_seconds > 0,
        "policy canary activation must require a positive observation window",
    )
    try:
        canary_audit_events = int(env.get("SERVERWARE_POLICY_CANARY_MIN_AUDIT_EVENTS", "0"))
    except ValueError:
        canary_audit_events = 0
    add(
        failures,
        canary_audit_events > 0,
        "policy canary activation must require audit evidence",
    )
    try:
        canary_max_denials = int(env.get("SERVERWARE_POLICY_CANARY_MAX_DENIALS", "0"))
    except ValueError:
        canary_max_denials = -1
    add(
        failures,
        canary_max_denials == 0,
        "policy canary activation must fail closed on canary denials",
    )
    origin = env.get("SERVERWARE_WEBAUTHN_ORIGIN", env.get("SERVERWARE_PUBLIC_URL", "")).strip()
    if origin:
        parsed = urllib.parse.urlparse(origin)
        add(failures, parsed.scheme == "https", "SERVERWARE_WEBAUTHN_ORIGIN must use https in production")
        add(failures, parsed.hostname not in {"localhost", "127.0.0.1", "::1"}, "SERVERWARE_WEBAUTHN_ORIGIN must not be localhost")
        add(failures, not placeholder_hostname(parsed.hostname), "SERVERWARE_WEBAUTHN_ORIGIN must not use .example placeholder domains")


def check_oauth_secret_file(env: dict[str, str], *, provider: str, setting_name: str, failures: list[str]) -> None:
    raw_path = env.get(setting_name, "").strip()
    add(failures, bool(raw_path), f"{provider} OAuth provider configuration must include {setting_name}")
    if not raw_path:
        return
    path = Path(raw_path)
    add(failures, path.is_absolute(), f"{setting_name} must be an absolute path")
    if not path.is_absolute():
        return
    try:
        file_stat = path.lstat()
    except OSError:
        failures.append(f"{setting_name} must reference a readable secret file")
        return
    mode = stat.S_IMODE(file_stat.st_mode)
    add(failures, stat.S_ISREG(file_stat.st_mode), f"{setting_name} must reference a regular, non-symlink file")
    add(failures, mode in {0o400, 0o600}, f"{setting_name} must use mode 0400 or 0600")
    add(
        failures,
        1 <= file_stat.st_size <= MAX_OAUTH_CLIENT_SECRET_FILE_BYTES,
        f"{setting_name} must contain between 1 and {MAX_OAUTH_CLIENT_SECRET_FILE_BYTES} bytes",
    )
    if not stat.S_ISREG(file_stat.st_mode) or mode not in {0o400, 0o600}:
        return
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError:
        failures.append(f"{setting_name} must reference a readable, non-symlink secret file")
        return
    try:
        opened_stat = os.fstat(descriptor)
        chunks: list[bytes] = []
        remaining = MAX_OAUTH_CLIENT_SECRET_FILE_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
    except OSError:
        failures.append(f"{setting_name} must contain readable UTF-8 secret text")
        return
    finally:
        os.close(descriptor)
    stable_file = (
        stat.S_ISREG(opened_stat.st_mode)
        and opened_stat.st_dev == file_stat.st_dev
        and opened_stat.st_ino == file_stat.st_ino
        and opened_stat.st_size == file_stat.st_size
        and stat.S_IMODE(opened_stat.st_mode) == mode
        and len(payload) == opened_stat.st_size
    )
    add(
        failures,
        stable_file and len(payload) <= MAX_OAUTH_CLIENT_SECRET_FILE_BYTES,
        f"{setting_name} changed while it was being checked",
    )
    if not stable_file:
        return
    try:
        secret = payload.decode("utf-8").rstrip("\r\n")
    except UnicodeDecodeError:
        failures.append(f"{setting_name} must contain readable UTF-8 secret text")
        return
    add(
        failures,
        bool(secret)
        and secret == secret.strip()
        and not any(character in secret for character in ("\x00", "\r", "\n")),
        f"{setting_name} must contain one non-empty secret without surrounding whitespace",
    )
    add(
        failures,
        len(secret.encode("utf-8")) >= 16 and len(set(secret)) >= 8,
        f"{setting_name} must contain a strong OAuth client secret",
    )


def read_bounded_regular_file(
    env: dict[str, str],
    setting_name: str,
    failures: list[str],
    *,
    file_label: str,
    max_bytes: int,
    allowed_modes: set[int] | None = None,
    required_read_uid: int | None = None,
    required_read_gid: int | None = None,
) -> bytes | None:
    require_valid(
        (required_read_uid is None) == (required_read_gid is None),
        "required file reader UID and GID must be configured together",
    )
    raw_path = env.get(setting_name, "").strip()
    add(failures, bool(raw_path), f"{setting_name} must be configured")
    if not raw_path:
        return None
    path = Path(raw_path)
    add(failures, path.is_absolute(), f"{setting_name} must be an absolute path")
    if not path.is_absolute():
        return None
    try:
        file_stat = path.lstat()
    except OSError:
        failures.append(f"{setting_name} must reference a readable {file_label} file")
        return None
    regular_file = stat.S_ISREG(file_stat.st_mode)
    add(failures, regular_file, f"{setting_name} must reference a regular, non-symlink {file_label} file")
    file_mode = stat.S_IMODE(file_stat.st_mode)
    mode_allowed = allowed_modes is None or file_mode in allowed_modes
    if allowed_modes is not None:
        expected_modes = " or ".join(f"{mode:04o}" for mode in sorted(allowed_modes))
        add(
            failures,
            mode_allowed,
            f"{setting_name} must use mode {expected_modes}",
        )
    bounded_file = 1 <= file_stat.st_size <= max_bytes
    add(
        failures,
        bounded_file,
        f"{setting_name} must contain between 1 and {max_bytes} bytes",
    )
    if not regular_file or not bounded_file or not mode_allowed:
        return None
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError:
        failures.append(f"{setting_name} must reference a readable, non-symlink {file_label} file")
        return None
    try:
        opened_stat = os.fstat(descriptor)
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        final_stat = os.fstat(descriptor)
    except OSError:
        failures.append(f"{setting_name} must reference a readable {file_label} file")
        return None
    finally:
        os.close(descriptor)
    stable_file = (
        stat.S_ISREG(opened_stat.st_mode)
        and opened_stat.st_dev == file_stat.st_dev
        and opened_stat.st_ino == file_stat.st_ino
        and opened_stat.st_size == file_stat.st_size
        and stat.S_IMODE(opened_stat.st_mode) == file_mode
        and opened_stat.st_uid == file_stat.st_uid
        and opened_stat.st_gid == file_stat.st_gid
        and final_stat.st_dev == opened_stat.st_dev
        and final_stat.st_ino == opened_stat.st_ino
        and final_stat.st_size == opened_stat.st_size
        and final_stat.st_mode == opened_stat.st_mode
        and final_stat.st_uid == opened_stat.st_uid
        and final_stat.st_gid == opened_stat.st_gid
        and final_stat.st_mtime_ns == opened_stat.st_mtime_ns
        and final_stat.st_ctime_ns == opened_stat.st_ctime_ns
        and len(payload) == opened_stat.st_size
    )
    add(failures, stable_file, f"{setting_name} changed while its {file_label} file was being validated")
    if not stable_file:
        return None
    if required_read_uid is not None and required_read_gid is not None:
        runtime_readable = file_readable_by_identity(
            final_stat,
            uid=required_read_uid,
            gid=required_read_gid,
        )
        add(
            failures,
            runtime_readable,
            f"{setting_name} must be readable by production control-plane "
            f"UID/GID {required_read_uid}:{required_read_gid}",
        )
        if not runtime_readable:
            return None
    return payload


def load_trusted_public_key_file(
    env: dict[str, str],
    setting_name: str,
    failures: list[str],
    *,
    require_ed25519: bool = False,
    require_ecdsa_or_rsa: bool = False,
) -> tuple[Any, str] | None:
    payload = read_bounded_regular_file(
        env,
        setting_name,
        failures,
        file_label="public-key",
        max_bytes=MAX_TRUSTED_PUBLIC_KEY_FILE_BYTES,
    )
    if payload is None:
        return None
    try:
        public_key = serialization.load_pem_public_key(payload)
        public_key_der = public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    except (TypeError, ValueError):
        failures.append(f"{setting_name} must contain a valid PEM public key")
        return None
    if require_ed25519 and not isinstance(public_key, Ed25519PublicKey):
        failures.append(f"{setting_name} must contain an Ed25519 public key")
        return None
    if require_ecdsa_or_rsa and not isinstance(
        public_key, (EllipticCurvePublicKey, RSAPublicKey)
    ):
        failures.append(f"{setting_name} must contain an ECDSA or RSA public key")
        return None
    return public_key, sha256_prefixed_bytes(public_key_der)


def check_trusted_public_key_file(
    env: dict[str, str],
    setting_name: str,
    failures: list[str],
    *,
    require_ed25519: bool = False,
    require_ecdsa_or_rsa: bool = False,
) -> str | None:
    loaded = load_trusted_public_key_file(
        env,
        setting_name,
        failures,
        require_ed25519=require_ed25519,
        require_ecdsa_or_rsa=require_ecdsa_or_rsa,
    )
    return loaded[1] if loaded is not None else None


def check_cross_domain_trust_key_separation(
    env: dict[str, str], failures: list[str]
) -> None:
    key_ids: dict[str, str] = {}
    for setting_name in REQUIRED_ONLINE_SIGNING_PUBLIC_KEYS:
        add(
            failures,
            bool(env.get(setting_name, "").strip()),
            f"{setting_name} must expose the online signing public identity for separation checks",
        )
        if env.get(setting_name, "").strip():
            key_id = check_trusted_public_key_file(
                env, setting_name, failures, require_ed25519=True
            )
            if key_id is not None:
                key_ids[setting_name] = key_id
    for setting_name in (*SETUP_TRUST_KEY_SETTINGS, *RELEASE_TRUST_KEY_SETTINGS):
        if setting_name in key_ids:
            continue
        if not env.get(setting_name, "").strip():
            continue
        ignored_failures: list[str] = []
        key_id = check_trusted_public_key_file(
            env, setting_name, ignored_failures
        )
        if key_id is not None:
            key_ids[setting_name] = key_id
    configured_setup_keys = [
        (setting_name, key_ids[setting_name])
        for setting_name in SETUP_TRUST_KEY_SETTINGS
        if setting_name in key_ids
    ]
    for index, (left_setting, left_key_id) in enumerate(configured_setup_keys):
        for right_setting, right_key_id in configured_setup_keys[index + 1 :]:
            add(
                failures,
                not hmac.compare_digest(left_key_id, right_key_id),
                "cross-domain trust key reuse is forbidden: "
                f"{left_setting} and {right_setting} must use distinct keys",
            )
    for setup_setting in SETUP_TRUST_KEY_SETTINGS:
        setup_key_id = key_ids.get(setup_setting)
        if setup_key_id is None:
            continue
        for release_setting in RELEASE_TRUST_KEY_SETTINGS:
            release_key_id = key_ids.get(release_setting)
            if release_key_id is None:
                continue
            add(
                failures,
                not hmac.compare_digest(setup_key_id, release_key_id),
                "cross-domain trust key reuse is forbidden: "
                f"{setup_setting} and {release_setting} must use distinct keys",
            )
    configured_release_keys = [
        (setting_name, key_ids[setting_name])
        for setting_name in RELEASE_TRUST_KEY_SETTINGS
        if setting_name in key_ids
    ]
    for index, (left_setting, left_key_id) in enumerate(configured_release_keys):
        for right_setting, right_key_id in configured_release_keys[index + 1 :]:
            add(
                failures,
                not hmac.compare_digest(left_key_id, right_key_id),
                "production trust key reuse is forbidden: "
                f"{left_setting} and {right_setting} must use distinct keys",
            )


def check_oauth_providers(env: dict[str, str], failures: list[str]) -> None:
    public_url = env.get("SERVERWARE_PUBLIC_URL", "").strip()
    parsed_public_url = urllib.parse.urlparse(public_url)
    public_url_is_https = parsed_public_url.scheme == "https" and bool(parsed_public_url.netloc)
    add(failures, public_url_is_https, "OAuth providers require an HTTPS SERVERWARE_PUBLIC_URL")

    try:
        state_ttl = int(env.get("SERVERWARE_OAUTH_STATE_TTL_SECONDS", ""))
    except ValueError:
        state_ttl = 0
    add(
        failures,
        60 <= state_ttl <= 900,
        "SERVERWARE_OAUTH_STATE_TTL_SECONDS must be between 60 and 900 seconds",
    )
    try:
        pending_credential_ttl = int(env.get("SERVERWARE_OAUTH_PENDING_CREDENTIAL_TTL_SECONDS", ""))
    except ValueError:
        pending_credential_ttl = 0
    add(
        failures,
        60 <= pending_credential_ttl <= 3600,
        "SERVERWARE_OAUTH_PENDING_CREDENTIAL_TTL_SECONDS must be between 60 and 3600 seconds",
    )
    try:
        pending_credential_max_count = int(
            env.get("SERVERWARE_OAUTH_PENDING_CREDENTIAL_MAX_COUNT", "")
        )
    except ValueError:
        pending_credential_max_count = 0
    add(
        failures,
        1 <= pending_credential_max_count <= 10_000,
        "SERVERWARE_OAUTH_PENDING_CREDENTIAL_MAX_COUNT must be between 1 and 10000",
    )
    setup_bounds = {
        "SERVERWARE_SETUP_SESSION_TTL_SECONDS": (300, 604_800),
        "SERVERWARE_SETUP_SESSION_MAX_ACTIVE": (1, 100_000),
        "SERVERWARE_SETUP_SESSION_MAX_RETAINED": (1, 1_000_000),
        "SERVERWARE_SETUP_SESSION_RETENTION_SECONDS": (300, 7_776_000),
        "SERVERWARE_SETUP_SESSION_EVIDENCE_MAX_BYTES": (1024, 1_048_576),
        "SERVERWARE_SETUP_SESSION_EVIDENCE_MAX_COUNT": (1, 1024),
        "SERVERWARE_SETUP_SESSION_EVENT_MAX_BYTES": (1024, 262_144),
        "SERVERWARE_SETUP_SESSION_EVENT_MAX_COUNT": (4, 4096),
        "SERVERWARE_SETUP_SESSION_AUDIT_OUTBOX_MAX_PENDING": (100, 1_000_000),
        "SERVERWARE_SETUP_SESSION_AUDIT_CLAIM_TTL_SECONDS": (5, 3600),
    }
    setup_values: dict[str, int] = {}
    for setting_name, (minimum, maximum) in setup_bounds.items():
        try:
            setup_values[setting_name] = int(env.get(setting_name, ""))
        except ValueError:
            setup_values[setting_name] = minimum - 1
        add(
            failures,
            minimum <= setup_values[setting_name] <= maximum,
            f"{setting_name} must be between {minimum} and {maximum}",
        )
    add(
        failures,
        setup_values["SERVERWARE_SETUP_SESSION_MAX_ACTIVE"]
        <= setup_values["SERVERWARE_SETUP_SESSION_MAX_RETAINED"],
        "SERVERWARE_SETUP_SESSION_MAX_RETAINED must not be below SERVERWARE_SETUP_SESSION_MAX_ACTIVE",
    )
    try:
        replay_capacity = int(env.get("SERVERWARE_CREDENTIAL_LEASE_REPLAY_MAX_ENTRIES", ""))
    except ValueError:
        replay_capacity = 0
    add(
        failures,
        10_000 <= replay_capacity <= 10_000_000,
        "SERVERWARE_CREDENTIAL_LEASE_REPLAY_MAX_ENTRIES must be between 10000 and 10000000",
    )

    plaintext_names = (
        "SERVERWARE_GOOGLE_OAUTH_CLIENT_SECRET",
        "SERVERWARE_X_OAUTH_CLIENT_SECRET",
        "SERVERWARE_TWITTER_OAUTH_CLIENT_SECRET",
        "SERVERWARE_OIDC_CLIENT_SECRET",
    )
    for setting_name in plaintext_names:
        add(
            failures,
            not env.get(setting_name, "").strip(),
            f"{setting_name} must not be set in production; use the provider client secret file",
        )

    providers = (
        (
            "Google",
            "google",
            "SERVERWARE_GOOGLE_OAUTH_CLIENT_ID",
            "SERVERWARE_GOOGLE_OAUTH_CLIENT_SECRET_FILE",
            "SERVERWARE_GOOGLE_OAUTH_REDIRECT_URI",
        ),
        (
            "X",
            "x",
            "SERVERWARE_X_OAUTH_CLIENT_ID",
            "SERVERWARE_X_OAUTH_CLIENT_SECRET_FILE",
            "SERVERWARE_X_OAUTH_REDIRECT_URI",
        ),
    )
    for provider, provider_id, client_id_name, secret_file_name, redirect_name in providers:
        add(
            failures,
            bool(env.get(client_id_name, "").strip()),
            f"{provider} OAuth provider configuration must include {client_id_name}",
        )
        check_oauth_secret_file(env, provider=provider, setting_name=secret_file_name, failures=failures)
        redirect_uri = env.get(redirect_name, "").strip()
        expected_redirect = f"{public_url.rstrip('/')}/api/oauth/callback/{provider_id}"
        parsed_redirect = urllib.parse.urlparse(redirect_uri)
        add(
            failures,
            public_url_is_https
            and parsed_redirect.scheme == "https"
            and redirect_uri == expected_redirect,
            f"{redirect_name} must be the exact HTTPS callback {expected_redirect}",
        )

    add(
        failures,
        env_bool(env, "SERVERWARE_OIDC_BROWSER_LOGIN_ENABLED"),
        "operator browser OIDC login must be enabled",
    )
    oidc_issuer = urllib.parse.urlparse(env.get("SERVERWARE_OIDC_ISSUER", "").strip())
    for name in ("SERVERWARE_OIDC_AUTHORIZATION_ENDPOINT", "SERVERWARE_OIDC_TOKEN_ENDPOINT"):
        value = env.get(name, "").strip()
        parsed = urllib.parse.urlparse(value)
        add(
            failures,
            parsed.scheme == "https"
            and bool(parsed.netloc)
            and (parsed.scheme, parsed.netloc) == (oidc_issuer.scheme, oidc_issuer.netloc),
            f"{name} must be an HTTPS endpoint on the configured OIDC issuer origin",
        )
    add(
        failures,
        bool(env.get("SERVERWARE_OIDC_CLIENT_ID", "").strip())
        and env.get("SERVERWARE_OIDC_CLIENT_ID", "").strip()
        == env.get("SERVERWARE_OIDC_AUDIENCE", "").strip(),
        "SERVERWARE_OIDC_CLIENT_ID must match SERVERWARE_OIDC_AUDIENCE",
    )
    check_oauth_secret_file(
        env,
        provider="operator OIDC",
        setting_name="SERVERWARE_OIDC_CLIENT_SECRET_FILE",
        failures=failures,
    )
    oidc_redirect = env.get("SERVERWARE_OIDC_REDIRECT_URI", "").strip()
    expected_oidc_redirect = f"{public_url.rstrip('/')}/api/auth/oidc/callback"
    add(
        failures,
        public_url_is_https and oidc_redirect == expected_oidc_redirect,
        f"SERVERWARE_OIDC_REDIRECT_URI must be the exact HTTPS callback {expected_oidc_redirect}",
    )
    oidc_scopes = [
        item.strip()
        for item in env.get("SERVERWARE_OIDC_BROWSER_SCOPES", "").split(",")
        if item.strip()
    ]
    add(
        failures,
        "openid" in oidc_scopes and len(oidc_scopes) == len(set(oidc_scopes)) <= 20,
        "SERVERWARE_OIDC_BROWSER_SCOPES must be unique, bounded, and include openid",
    )
    add(
        failures,
        env.get("SERVERWARE_OIDC_TOKEN_AUTH_METHOD", "").strip()
        in {"client_secret_basic", "client_secret_post"},
        "production browser OIDC must authenticate the token endpoint client",
    )
    try:
        oidc_login_ttl = int(env.get("SERVERWARE_OIDC_LOGIN_STATE_TTL_SECONDS", ""))
        oidc_session_ttl = int(env.get("SERVERWARE_OIDC_SESSION_TTL_SECONDS", ""))
    except ValueError:
        oidc_login_ttl = 0
        oidc_session_ttl = 0
    add(
        failures,
        60 <= oidc_login_ttl <= 900,
        "SERVERWARE_OIDC_LOGIN_STATE_TTL_SECONDS must be between 60 and 900 seconds",
    )
    add(
        failures,
        300 <= oidc_session_ttl <= 43_200,
        "SERVERWARE_OIDC_SESSION_TTL_SECONDS must be between 300 and 43200 seconds",
    )
    add(
        failures,
        env_bool(env, "SERVERWARE_OIDC_SESSION_WEBAUTHN_REQUIRED"),
        "production OIDC browser sessions must require WebAuthn binding",
    )
    try:
        oidc_session_webauthn_ttl = int(
            env.get("SERVERWARE_OIDC_SESSION_WEBAUTHN_CHALLENGE_TTL_SECONDS", "")
        )
    except ValueError:
        oidc_session_webauthn_ttl = 0
    add(
        failures,
        30 <= oidc_session_webauthn_ttl <= 300,
        "SERVERWARE_OIDC_SESSION_WEBAUTHN_CHALLENGE_TTL_SECONDS must be between 30 and 300 seconds",
    )
    try:
        oidc_session_pending_ttl = int(
            env.get("SERVERWARE_OIDC_SESSION_WEBAUTHN_PENDING_TTL_SECONDS", "")
        )
    except ValueError:
        oidc_session_pending_ttl = 0
    add(
        failures,
        60 <= oidc_session_pending_ttl <= 300,
        "SERVERWARE_OIDC_SESSION_WEBAUTHN_PENDING_TTL_SECONDS must be between 60 and 300 seconds",
    )
    add(
        failures,
        env_bool(env, "SERVERWARE_WEBAUTHN_RECOVERY_ENABLED"),
        "production must enable offline WebAuthn recovery",
    )
    recovery_key_id = check_trusted_public_key_file(
        env,
        "SERVERWARE_WEBAUTHN_RECOVERY_ROOT_PUBLIC_KEY",
        failures,
        require_ed25519=True,
    )
    expected_recovery_key_id = env.get(
        "SERVERWARE_WEBAUTHN_RECOVERY_ROOT_KEY_ID", ""
    ).strip()
    add(
        failures,
        bool(recovery_key_id)
        and SHA256_RE.fullmatch(expected_recovery_key_id) is not None
        and hmac.compare_digest(recovery_key_id or "", expected_recovery_key_id),
        "SERVERWARE_WEBAUTHN_RECOVERY_ROOT_KEY_ID must match the offline root SPKI digest",
    )
    recovery_key_path = Path(
        env.get("SERVERWARE_WEBAUTHN_RECOVERY_ROOT_PUBLIC_KEY", "")
    )
    try:
        recovery_key_mode = stat.S_IMODE(recovery_key_path.lstat().st_mode)
    except OSError:
        recovery_key_mode = 0o777
    add(
        failures,
        recovery_key_mode & 0o022 == 0,
        "SERVERWARE_WEBAUTHN_RECOVERY_ROOT_PUBLIC_KEY must not be group/world writable",
    )
    recovery_provider = env.get(
        "SERVERWARE_WEBAUTHN_RECOVERY_ROOT_PROVIDER", ""
    ).strip()
    add(
        failures,
        3 <= len(recovery_provider) <= 128
        and "replace" not in recovery_provider.lower()
        and "example" not in recovery_provider.lower(),
        "SERVERWARE_WEBAUTHN_RECOVERY_ROOT_PROVIDER must identify the offline authority",
    )
    recovery_audience = env.get("SERVERWARE_WEBAUTHN_RECOVERY_AUDIENCE", "").strip()
    parsed_recovery_audience = urllib.parse.urlparse(recovery_audience)
    add(
        failures,
        recovery_audience == public_url
        and parsed_recovery_audience.scheme == "https"
        and not placeholder_hostname(parsed_recovery_audience.hostname),
        "SERVERWARE_WEBAUTHN_RECOVERY_AUDIENCE must exactly match the production public URL",
    )
    try:
        recovery_ttl = int(env.get("SERVERWARE_WEBAUTHN_RECOVERY_TTL_SECONDS", ""))
        recovery_max_live = int(
            env.get("SERVERWARE_WEBAUTHN_RECOVERY_MAX_LIVE", "")
        )
    except ValueError:
        recovery_ttl = 0
        recovery_max_live = 0
    add(
        failures,
        30 <= recovery_ttl <= min(300, oidc_session_pending_ttl),
        "SERVERWARE_WEBAUTHN_RECOVERY_TTL_SECONDS must be between 30 seconds and the pending-session TTL",
    )
    add(
        failures,
        1 <= recovery_max_live <= 10_000,
        "SERVERWARE_WEBAUTHN_RECOVERY_MAX_LIVE must be between 1 and 10000",
    )


def check_nitro(env: dict[str, str], failures: list[str]) -> None:
    add(failures, env.get("SERVERWARE_TEE_QUOTE_PROVIDER") == "aws-nitro-enclaves", "TEE quote provider must be aws-nitro-enclaves")
    add(failures, env.get("SERVERWARE_TEE_PLATFORM") == "aws-nitro", "TEE platform must be aws-nitro")
    add(failures, not env_bool(env, "SERVERWARE_NITRO_FIXTURE"), "SERVERWARE_NITRO_FIXTURE must be disabled")
    add(failures, not env_bool(env, "SERVERWARE_NITRO_ALLOW_DEBUG"), "SERVERWARE_NITRO_ALLOW_DEBUG must be disabled")
    add(failures, not env_bool(env, "SERVERWARE_NITRO_ALLOW_DEBUG_RELEASE"), "SERVERWARE_NITRO_ALLOW_DEBUG_RELEASE must be disabled")
    attestation_command = env.get("SERVERWARE_NITRO_ATTESTATION_COMMAND", "").strip()
    add(failures, bool(attestation_command), "SERVERWARE_NITRO_ATTESTATION_COMMAND must be configured for fresh NSM documents")
    add(
        failures,
        attestation_command and not command_mentions(attestation_command, "fixture", "nitro_attestation_fixture.py"),
        "SERVERWARE_NITRO_ATTESTATION_COMMAND must not use fixture helpers",
    )
    add(
        failures,
        not env.get("SERVERWARE_NITRO_ATTESTATION_DOCUMENT") and not env.get("SERVERWARE_NITRO_ATTESTATION_DOCUMENT_B64"),
        "production Nitro readiness must use a fresh attestation command, not a static document env var",
    )
    nsm_template = env.get("SERVERWARE_NITRO_NSM_ATTEST_COMMAND_TEMPLATE", "").strip()
    add(
        failures,
        not nsm_template or not command_mentions(nsm_template, "fixture", "nitro_attestation_fixture.py"),
        "SERVERWARE_NITRO_NSM_ATTEST_COMMAND_TEMPLATE must not use fixture helpers",
    )
    add(
        failures,
        bool(env.get("SERVERWARE_NITRO_ROOT_CERT") or env.get("SERVERWARE_NITRO_ROOT_CERT_PEM")),
        "Nitro root certificate must be pinned with SERVERWARE_NITRO_ROOT_CERT[_PEM]",
    )
    add(
        failures,
        valid_pcr_policy(env.get("SERVERWARE_NITRO_EXPECTED_PCRS", "")),
        "SERVERWARE_NITRO_EXPECTED_PCRS must be a non-empty JSON PCR allowlist with 48-byte SHA384 values",
    )
    add(
        failures,
        env_bool(env, "SERVERWARE_NITRO_REQUIRE_KMS_COMMAND"),
        "SERVERWARE_NITRO_REQUIRE_KMS_COMMAND must be enabled",
    )
    kms_command = env.get("SERVERWARE_NITRO_KMS_RELEASE_COMMAND", "").strip()
    add(failures, bool(kms_command), "SERVERWARE_NITRO_KMS_RELEASE_COMMAND must be configured")
    add(
        failures,
        kms_command and not command_mentions(kms_command, "fixture", "nitro_kms_fixture.py"),
        "SERVERWARE_NITRO_KMS_RELEASE_COMMAND must not use fixture helpers",
    )
    kms_materials_file = Path(env.get("SERVERWARE_NITRO_KMS_MATERIALS_FILE", "").strip())
    add(
        failures,
        kms_materials_file.is_absolute(),
        "SERVERWARE_NITRO_KMS_MATERIALS_FILE must be an absolute host path",
    )
    materials = {
        item.strip()
        for item in env.get("SERVERWARE_NITRO_ALLOWED_MATERIALS", ",".join(sorted(REQUIRED_MATERIALS))).split(",")
        if item.strip()
    }
    add(failures, materials == REQUIRED_MATERIALS, "Nitro allowed materials must be exactly broker-kek and decision-gate-ca")


def check_attested_credential_delivery(env: dict[str, str], failures: list[str]) -> None:
    tls_dir = Path(env.get("SERVERWARE_CONTROL_PLANE_TLS_DIR", "").strip())
    anchor_tls_dir = Path(env.get("SERVERWARE_AUDIT_ANCHOR_TLS_DIR", "").strip())
    helper_dir = Path(env.get("SERVERWARE_ATTESTATION_HELPER_DIR", "").strip())
    provenance_file = Path(env.get("SERVERWARE_RELEASE_PROVENANCE_FILE", "").strip())
    signatures_file = Path(env.get("SERVERWARE_IMAGE_SIGNATURES_FILE", "").strip())
    add(failures, tls_dir.is_absolute(), "SERVERWARE_CONTROL_PLANE_TLS_DIR must be an absolute path")
    add(failures, anchor_tls_dir.is_absolute(), "SERVERWARE_AUDIT_ANCHOR_TLS_DIR must be an absolute path")
    add(failures, helper_dir.is_absolute(), "SERVERWARE_ATTESTATION_HELPER_DIR must be an absolute path")
    add(failures, provenance_file.is_absolute(), "SERVERWARE_RELEASE_PROVENANCE_FILE must be an absolute path")
    add(failures, signatures_file.is_absolute(), "SERVERWARE_IMAGE_SIGNATURES_FILE must be an absolute path")
    control_plane_base = urllib.parse.urlparse(env.get("SERVERWARE_PRODUCTION_CONTROL_PLANE_BASE", ""))
    add(
        failures,
        control_plane_base.scheme == "https" and bool(control_plane_base.hostname),
        "SERVERWARE_PRODUCTION_CONTROL_PLANE_BASE must be an HTTPS URL",
    )
    add(
        failures,
        not env_bool(env, "SERVERWARE_ALLOW_INSECURE_DEV_CREDENTIAL_LEASES"),
        "SERVERWARE_ALLOW_INSECURE_DEV_CREDENTIAL_LEASES must be disabled",
    )

    command_settings = (
        ("SERVERWARE_TEE_QUOTE_COMMAND", "TEE quote command"),
        ("SERVERWARE_TEE_QUOTE_VERIFY_COMMAND", "TEE quote verification command"),
        ("SERVERWARE_KEY_RELEASE_COMMAND", "key-release command"),
        ("SERVERWARE_MASTER_KEY_UNSEAL_COMMAND", "in-TEE broker KEK unseal command"),
        ("SERVERWARE_NITRO_NSM_UNSEAL_COMMAND_TEMPLATE", "Nitro NSM recipient unwrap command"),
        ("SERVERWARE_DATA_PLANE_RECIPIENT_ATTESTATION_COMMAND", "recipient attestation command"),
        ("SERVERWARE_DATA_PLANE_RESPONSE_PROOF_ATTESTATION_COMMAND", "response proof attestation command"),
        ("SERVERWARE_DATA_PLANE_LEASE_RECIPIENT_VERIFY_COMMAND", "recipient attestation verification command"),
        ("SERVERWARE_CONTROL_PLANE_ATTESTATION_VERIFY_COMMAND", "control-plane attestation verification command"),
    )
    for name, label in command_settings:
        command = env.get(name, "").strip()
        add(failures, bool(command), f"{name} must configure a {label}")
        add(
            failures,
            bool(command)
            and not command_mentions(
                command,
                "fixture",
                "external_tee_provider.py",
                "nitro_attestation_fixture.py",
                "nitro_kms_fixture.py",
            ),
            f"{name} must not use fixture helpers",
        )

    for name in (
        "SERVERWARE_NITRO_NSM_UNSEAL_COMMAND_TEMPLATE",
        "SERVERWARE_DATA_PLANE_RECIPIENT_ATTESTATION_COMMAND",
        "SERVERWARE_DATA_PLANE_RESPONSE_PROOF_ATTESTATION_COMMAND",
        "SERVERWARE_DATA_PLANE_LEASE_RECIPIENT_VERIFY_COMMAND",
        "SERVERWARE_CONTROL_PLANE_ATTESTATION_VERIFY_COMMAND",
    ):
        words = command_words(env.get(name, ""))
        helper_path = Path(words[0]) if words else Path()
        add(
            failures,
            bool(words) and helper_path.is_absolute() and helper_path.parent == Path("/opt/serverware/bin"),
            f"{name} must name an absolute executable under /opt/serverware/bin",
        )

    add(
        failures,
        command_words(env.get("SERVERWARE_MASTER_KEY_UNSEAL_COMMAND", ""))
        == ["/usr/bin/python3", "/app/scripts/aws_nitro_kms_unseal.py", "unseal"],
        "SERVERWARE_MASTER_KEY_UNSEAL_COMMAND must use the measured image-bundled Nitro/KMS unseal adapter",
    )
    add(
        failures,
        "{recipient_ciphertext_path}" in env.get("SERVERWARE_NITRO_NSM_UNSEAL_COMMAND_TEMPLATE", ""),
        "SERVERWARE_NITRO_NSM_UNSEAL_COMMAND_TEMPLATE must consume {recipient_ciphertext_path}",
    )

    data_plane_instance_id = env.get("SERVERWARE_DATA_PLANE_INSTANCE_ID", "").strip()
    add(
        failures,
        data_plane_instance_id.startswith("spiffe://") and len(data_plane_instance_id) > len("spiffe://"),
        "SERVERWARE_DATA_PLANE_INSTANCE_ID must be a non-empty SPIFFE ID",
    )

    collector_command = env.get("SERVERWARE_PROXY_PROOF_COLLECTOR_COMMAND", "").strip()
    collector_words = command_words(collector_command)
    collector_path = Path(collector_words[0]) if collector_words else Path()
    add(
        failures,
        len(collector_words) == 1
        and collector_path.is_absolute()
        and collector_path.parent == Path("/opt/serverware/bin"),
        "SERVERWARE_PROXY_PROOF_COLLECTOR_COMMAND must name one absolute executable under /opt/serverware/bin",
    )
    add(
        failures,
        bool(collector_words) and not command_mentions(collector_command, "fixture"),
        "SERVERWARE_PROXY_PROOF_COLLECTOR_COMMAND must not use a fixture",
    )
    proof_url = urllib.parse.urlparse(env.get("SERVERWARE_PROXY_PROOF_URL", ""))
    add(
        failures,
        proof_url.scheme == "https" and bool(proof_url.hostname) and not proof_url.username and not proof_url.password,
        "SERVERWARE_PROXY_PROOF_URL must be an HTTPS URL without userinfo",
    )
    add(failures, bool(env.get("SERVERWARE_PROXY_PROOF_ADDRESS", "").strip()), "SERVERWARE_PROXY_PROOF_ADDRESS is required")
    add(
        failures,
        bool(env.get("SERVERWARE_PROXY_PROOF_AGENT_ID", "").strip()),
        "SERVERWARE_PROXY_PROOF_AGENT_ID is required",
    )
    proof_principal_id = env.get("SERVERWARE_PROXY_PROOF_PRINCIPAL_ID", "").strip()
    add(
        failures,
        bool(proof_principal_id)
        and len(proof_principal_id) <= 256
        and not any(
            character.isspace() or not character.isprintable()
            for character in proof_principal_id
        ),
        "SERVERWARE_PROXY_PROOF_PRINCIPAL_ID must be a bounded canonical principal ID",
    )
    for name in (
        "SERVERWARE_PROXY_RESPONSE_PROOF_FILE",
        "SERVERWARE_PROXY_PROOF_CA_BUNDLE",
        "SERVERWARE_PROXY_PROOF_COLLECTOR_PRIVATE_KEY",
        "SERVERWARE_PROXY_PROOF_COLLECTOR_PUBLIC_KEY",
        "SERVERWARE_PROXY_PROOF_VERIFIER_PUBLIC_KEY",
    ):
        add(failures, Path(env.get(name, "").strip()).is_absolute(), f"{name} must be an absolute path")
    for name in (
        "SERVERWARE_PROXY_PROOF_COLLECTOR_KEY_ID",
        "SERVERWARE_PROXY_PROOF_VERIFIER_KEY_ID",
    ):
        add(
            failures,
            SHA256_RE.fullmatch(env.get(name, "").strip()) is not None,
            f"{name} must be a sha256: digest",
        )
    configured_proof_instance = env.get("SERVERWARE_PROXY_SERVER_INSTANCE_ID", data_plane_instance_id).strip()
    add(
        failures,
        configured_proof_instance == data_plane_instance_id,
        "SERVERWARE_PROXY_SERVER_INSTANCE_ID must exactly match SERVERWARE_DATA_PLANE_INSTANCE_ID",
    )
    for name in ("SERVERWARE_POLICY_MIN_SEQUENCE", "SERVERWARE_POLICY_MIN_ROLLBACK_EPOCH"):
        try:
            monotonic_floor = int(env.get(name, "0"))
        except ValueError:
            monotonic_floor = 0
        add(failures, monotonic_floor > 0, f"{name} must be a positive integer")
    for stale_name in (
        "SERVERWARE_PROXY_CLIENT_NONCE",
        "SERVERWARE_PROXY_REQUEST_DIGEST",
        "SERVERWARE_PROXY_OPERATION_DIGEST",
        "SERVERWARE_PROXY_TLS_CHANNEL_BINDING",
    ):
        add(
            failures,
            not env.get(stale_name, "").strip(),
            f"{stale_name} must not be statically configured; the readiness runner generates it",
        )

    add(failures, env_bool(env, "SERVERWARE_KEY_RELEASE_REQUIRED"), "external key release must be required")
    add(
        failures,
        not env.get("SERVERWARE_MASTER_KEY", "").strip(),
        "SERVERWARE_MASTER_KEY must not be configured in production",
    )
    add(failures, not env_bool(env, "SERVERWARE_KEY_RELEASE_ALLOW_DEBUG"), "key release must reject debug attestation")
    try:
        rollback_floor = int(env.get("SERVERWARE_KEY_RELEASE_MIN_ROLLBACK_EPOCH", "0"))
    except ValueError:
        rollback_floor = 0
    add(failures, rollback_floor >= 1, "key release must enforce a positive rollback-epoch floor")
    add(
        failures,
        env_bool(env, "SERVERWARE_KEY_RELEASE_REQUIRE_DATA_PLANE_DIGEST"),
        "key release must require the measured data-plane binary digest",
    )
    expected_digest = env.get("SERVERWARE_EXPECTED_DATA_PLANE_BINARY_DIGEST", "").strip()
    add(
        failures,
        SHA256_RE.fullmatch(expected_digest) is not None,
        "SERVERWARE_EXPECTED_DATA_PLANE_BINARY_DIGEST must be a sha256-prefixed 64-hex digest",
    )
    add(
        failures,
        env_bool(env, "SERVERWARE_DATA_PLANE_LEASE_RECIPIENT_ATTESTATION_REQUIRED"),
        "credential leases must require recipient attestation",
    )


def check_release_completion_trust(
    env: dict[str, str],
    failures: list[str],
    *,
    expected_control_plane_uid: int = CONTROL_PLANE_RUNTIME_UID,
    expected_control_plane_gid: int = CONTROL_PLANE_RUNTIME_GID,
) -> None:
    provider = env.get("SERVERWARE_EXTERNAL_CHECKPOINT_PROVIDER", "").strip()
    expected_provider = env.get("SERVERWARE_TRANSPARENCY_EXPECTED_PROVIDER", "").strip()
    add(failures, bool(provider), "SERVERWARE_EXTERNAL_CHECKPOINT_PROVIDER must be configured")
    add(
        failures,
        bool(provider) and provider == expected_provider,
        "SERVERWARE_EXTERNAL_CHECKPOINT_PROVIDER must match SERVERWARE_TRANSPARENCY_EXPECTED_PROVIDER",
    )
    key_ids = {}
    for setting_name in (
        "SERVERWARE_RELEASE_PROVENANCE_TRUSTED_PUBLIC_KEY",
        "SERVERWARE_SIGSTORE_TRUSTED_PUBLIC_KEY",
        "SERVERWARE_REKOR_TRUSTED_PUBLIC_KEY",
        "SERVERWARE_EXTERNAL_CHECKPOINT_TRUSTED_PUBLIC_KEY",
    ):
        key_ids[setting_name] = check_trusted_public_key_file(
            env,
            setting_name,
            failures,
            require_ecdsa_or_rsa=(
                setting_name == "SERVERWARE_SIGSTORE_TRUSTED_PUBLIC_KEY"
            ),
        )
    for setting_name, expected_id_name in (
        ("SERVERWARE_SIGSTORE_TRUSTED_PUBLIC_KEY", "SERVERWARE_COSIGN_KEY_ID"),
        ("SERVERWARE_REKOR_TRUSTED_PUBLIC_KEY", "SERVERWARE_COSIGN_EXPECTED_REKOR_LOG_ID"),
        ("SERVERWARE_EXTERNAL_CHECKPOINT_TRUSTED_PUBLIC_KEY", "SERVERWARE_TRANSPARENCY_EXPECTED_LOG_ID"),
    ):
        expected_key_id = env.get(expected_id_name, "").strip()
        add(
            failures,
            SHA256_RE.fullmatch(expected_key_id) is not None,
            f"{expected_id_name} must be a sha256: SPKI public-key digest",
        )
        key_id = key_ids.get(setting_name)
        add(
            failures,
            key_id is not None and key_id == expected_key_id,
            f"{setting_name} SPKI public-key digest must match {expected_id_name}",
        )
    response_key_id = check_trusted_public_key_file(
        env,
        "SERVERWARE_CONTROL_PLANE_RESPONSE_SIGNING_PUBLIC_KEY",
        failures,
        require_ed25519=True,
    )
    expected_response_key_id = env.get(
        "SERVERWARE_CONTROL_PLANE_RESPONSE_SIGNING_PUBLIC_KEY_ID",
        "",
    ).strip()
    add(
        failures,
        SHA256_RE.fullmatch(expected_response_key_id) is not None,
        "SERVERWARE_CONTROL_PLANE_RESPONSE_SIGNING_PUBLIC_KEY_ID must be a sha256: SPKI public-key digest",
    )
    add(
        failures,
        response_key_id is not None
        and hmac.compare_digest(response_key_id, expected_response_key_id),
        "SERVERWARE_CONTROL_PLANE_RESPONSE_SIGNING_PUBLIC_KEY SPKI identity must match SERVERWARE_CONTROL_PLANE_RESPONSE_SIGNING_PUBLIC_KEY_ID",
    )
    online_response_key_id = check_trusted_public_key_file(
        env,
        "SERVERWARE_RESPONSE_SIGNING_PUBLIC_KEY",
        failures,
        require_ed25519=True,
    )
    response_private_key_bytes = read_bounded_regular_file(
        env,
        "SERVERWARE_RESPONSE_SIGNING_PRIVATE_KEY_FILE",
        failures,
        file_label="response-signing private-key",
        max_bytes=MAX_TRUSTED_PUBLIC_KEY_FILE_BYTES,
        allowed_modes={0o400, 0o600},
        required_read_uid=expected_control_plane_uid,
        required_read_gid=expected_control_plane_gid,
    )
    response_private_key_id = None
    if response_private_key_bytes is not None:
        try:
            response_private_key = serialization.load_pem_private_key(
                response_private_key_bytes,
                password=None,
            )
            response_private_public_key = response_private_key.public_key()
            if not isinstance(response_private_public_key, Ed25519PublicKey):
                raise ValueError("not Ed25519")
            response_private_key_id = sha256_prefixed_bytes(
                response_private_public_key.public_bytes(
                    serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )
        except (TypeError, ValueError):
            failures.append(
                "SERVERWARE_RESPONSE_SIGNING_PRIVATE_KEY_FILE must contain an unencrypted Ed25519 PKCS#8 private key"
            )
    add(
        failures,
        response_key_id is not None
        and online_response_key_id is not None
        and hmac.compare_digest(response_key_id, online_response_key_id),
        "the release verifier control-plane response key must match the online response-signing public identity",
    )
    add(
        failures,
        response_private_key_id is not None
        and online_response_key_id is not None
        and hmac.compare_digest(response_private_key_id, online_response_key_id),
        "the provisioned response-signing private key must match the online response-signing public identity",
    )


def check_final_challenge_authority(env: dict[str, str], failures: list[str]) -> None:
    mode = env.get("SERVERWARE_COMPLETION_VERIFICATION_MODE", "readiness").strip()
    add(
        failures,
        mode in {"readiness", "final"},
        "SERVERWARE_COMPLETION_VERIFICATION_MODE must be readiness or final",
    )
    receipt_settings = (
        "SERVERWARE_FINAL_CHALLENGE_RECEIPT",
        "SERVERWARE_FINAL_CHALLENGE_AUTHORITY_PUBLIC_KEY",
        "SERVERWARE_FINAL_CHALLENGE_AUTHORITY_PUBLIC_KEY_ID",
        "SERVERWARE_FINAL_CHALLENGE_AUTHORITY_PROVIDER",
    )
    hardware_settings = (
        "SERVERWARE_HARDWARE_ASSURANCE",
        "SERVERWARE_HARDWARE_ASSURANCE_TRUSTED_PUBLIC_KEY",
        "SERVERWARE_HARDWARE_ASSURANCE_TRUSTED_PUBLIC_KEY_ID",
        "SERVERWARE_HARDWARE_ASSURANCE_EXPECTED_CHALLENGE_NONCE",
        "SERVERWARE_HARDWARE_ASSURANCE_EXPECTED_CHALLENGE_NONCE_SHA256",
    )
    configured = {
        name: env.get(name, "").strip()
        for name in (*receipt_settings, *hardware_settings)
    }
    if mode != "final":
        add(
            failures,
            not any(configured.values()),
            "final hardware and challenge authority inputs are forbidden in readiness mode",
        )
        return
    for name in (
        *receipt_settings,
        "SERVERWARE_HARDWARE_ASSURANCE",
        "SERVERWARE_HARDWARE_ASSURANCE_TRUSTED_PUBLIC_KEY",
        "SERVERWARE_HARDWARE_ASSURANCE_TRUSTED_PUBLIC_KEY_ID",
    ):
        value = configured[name]
        add(failures, bool(value), f"final verification mode requires {name}")
    expected_nonce = configured["SERVERWARE_HARDWARE_ASSURANCE_EXPECTED_CHALLENGE_NONCE"]
    expected_nonce_digest = configured[
        "SERVERWARE_HARDWARE_ASSURANCE_EXPECTED_CHALLENGE_NONCE_SHA256"
    ]
    add(
        failures,
        bool(expected_nonce) != bool(expected_nonce_digest),
        "final verification mode requires exactly one hardware assurance expected challenge nonce or digest",
    )
    if expected_nonce:
        try:
            decoded_nonce = decode_canonical_base64url(
                expected_nonce,
                "SERVERWARE_HARDWARE_ASSURANCE_EXPECTED_CHALLENGE_NONCE",
            )
        except ValueError:
            decoded_nonce = b""
        add(
            failures,
            len(decoded_nonce) >= 32,
            "SERVERWARE_HARDWARE_ASSURANCE_EXPECTED_CHALLENGE_NONCE must be unpadded base64url for at least 32 bytes",
        )
    if expected_nonce_digest:
        add(
            failures,
            SHA256_RE.fullmatch(expected_nonce_digest) is not None,
            "SERVERWARE_HARDWARE_ASSURANCE_EXPECTED_CHALLENGE_NONCE_SHA256 must be a sha256 digest",
        )
    required_values = [
        configured[name]
        for name in (
            *receipt_settings,
            "SERVERWARE_HARDWARE_ASSURANCE",
            "SERVERWARE_HARDWARE_ASSURANCE_TRUSTED_PUBLIC_KEY",
            "SERVERWARE_HARDWARE_ASSURANCE_TRUSTED_PUBLIC_KEY_ID",
        )
    ]
    if not all(required_values) or bool(expected_nonce) == bool(expected_nonce_digest):
        return
    add(
        failures,
        re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}",
            configured["SERVERWARE_FINAL_CHALLENGE_AUTHORITY_PROVIDER"],
        )
        is not None,
        "SERVERWARE_FINAL_CHALLENGE_AUTHORITY_PROVIDER must be a canonical provider identifier",
    )
    expected_hardware_key_id = configured[
        "SERVERWARE_HARDWARE_ASSURANCE_TRUSTED_PUBLIC_KEY_ID"
    ]
    expected_authority_key_id = configured[
        "SERVERWARE_FINAL_CHALLENGE_AUTHORITY_PUBLIC_KEY_ID"
    ]
    add(
        failures,
        SHA256_RE.fullmatch(expected_hardware_key_id) is not None,
        "SERVERWARE_HARDWARE_ASSURANCE_TRUSTED_PUBLIC_KEY_ID must be a sha256: SPKI public-key digest",
    )
    add(
        failures,
        SHA256_RE.fullmatch(expected_authority_key_id) is not None,
        "SERVERWARE_FINAL_CHALLENGE_AUTHORITY_PUBLIC_KEY_ID must be a sha256: SPKI public-key digest",
    )

    hardware_payload = read_bounded_regular_file(
        env,
        "SERVERWARE_HARDWARE_ASSURANCE",
        failures,
        file_label="hardware assurance",
        max_bytes=MAX_HARDWARE_ASSURANCE_FILE_BYTES,
    )
    hardware_assurance = None
    if hardware_payload is not None:
        try:
            hardware_assurance = strict_json_object(
                hardware_payload, "SERVERWARE_HARDWARE_ASSURANCE"
            )
        except ValueError as exc:
            failures.append(str(exc))
    hardware_key = load_trusted_public_key_file(
        env,
        "SERVERWARE_HARDWARE_ASSURANCE_TRUSTED_PUBLIC_KEY",
        failures,
        require_ed25519=True,
    )
    hardware_summary = None
    if hardware_key is not None:
        hardware_public_key, hardware_key_id = hardware_key
        add(
            failures,
            SHA256_RE.fullmatch(expected_hardware_key_id) is not None
            and hmac.compare_digest(hardware_key_id, expected_hardware_key_id),
            "SERVERWARE_HARDWARE_ASSURANCE_TRUSTED_PUBLIC_KEY SPKI identity must match SERVERWARE_HARDWARE_ASSURANCE_TRUSTED_PUBLIC_KEY_ID",
        )
        if hardware_assurance is not None:
            try:
                hardware_summary = validate_hardware_assurance_document(
                    hardware_assurance,
                    trusted_public_key=hardware_public_key,
                    trusted_key_id=hardware_key_id,
                    expected_trusted_key_id=expected_hardware_key_id,
                    expected_challenge_nonce=expected_nonce or None,
                    expected_challenge_nonce_sha256=expected_nonce_digest or None,
                )
            except ValueError as exc:
                failures.append(str(exc))

    receipt_payload = read_bounded_regular_file(
        env,
        "SERVERWARE_FINAL_CHALLENGE_RECEIPT",
        failures,
        file_label="final challenge receipt",
        max_bytes=MAX_FINAL_CHALLENGE_RECEIPT_FILE_BYTES,
    )
    receipt = None
    if receipt_payload is not None:
        try:
            receipt = strict_json_object(
                receipt_payload, "SERVERWARE_FINAL_CHALLENGE_RECEIPT"
            )
        except ValueError as exc:
            failures.append(str(exc))
    authority_key = load_trusted_public_key_file(
        env,
        "SERVERWARE_FINAL_CHALLENGE_AUTHORITY_PUBLIC_KEY",
        failures,
        require_ed25519=True,
    )
    if authority_key is not None:
        authority_public_key, authority_key_id = authority_key
        add(
            failures,
            SHA256_RE.fullmatch(expected_authority_key_id) is not None
            and hmac.compare_digest(authority_key_id, expected_authority_key_id),
            "SERVERWARE_FINAL_CHALLENGE_AUTHORITY_PUBLIC_KEY SPKI identity must match SERVERWARE_FINAL_CHALLENGE_AUTHORITY_PUBLIC_KEY_ID",
        )
        if receipt is not None and hardware_key is not None:
            expected_challenge_digest = expected_nonce_digest
            if expected_nonce:
                try:
                    decoded_expected_nonce = decode_canonical_base64url(
                        expected_nonce,
                        "SERVERWARE_HARDWARE_ASSURANCE_EXPECTED_CHALLENGE_NONCE",
                    )
                except ValueError:
                    decoded_expected_nonce = b""
                if decoded_expected_nonce:
                    expected_challenge_digest = sha256_prefixed_bytes(
                        decoded_expected_nonce
                    )
            if not expected_challenge_digest:
                return
            try:
                validate_final_challenge_receipt_document(
                    receipt,
                    trusted_public_key=authority_public_key,
                    trusted_key_id=authority_key_id,
                    expected_trusted_key_id=expected_authority_key_id,
                    expected_provider=configured[
                        "SERVERWARE_FINAL_CHALLENGE_AUTHORITY_PROVIDER"
                    ],
                    expected_challenge_nonce_sha256=expected_challenge_digest,
                    expected_hardware_verifier_key_id=hardware_key[1],
                    hardware_assurance_summary=hardware_summary,
                )
            except ValueError as exc:
                failures.append(str(exc))


def check_cosign(env: dict[str, str], failures: list[str]) -> None:
    add(failures, env.get("SERVERWARE_IMAGE_SIGNATURE_PROVIDER") == "sigstore-command", "image signature provider must be sigstore-command")
    sign_command = env.get("SERVERWARE_IMAGE_SIGN_COMMAND", "").strip()
    verify_command = env.get("SERVERWARE_IMAGE_VERIFY_COMMAND", "").strip()
    add(failures, bool(sign_command), "SERVERWARE_IMAGE_SIGN_COMMAND must be configured")
    add(failures, bool(verify_command), "SERVERWARE_IMAGE_VERIFY_COMMAND must be configured")
    add(
        failures,
        sign_command and not command_mentions(sign_command, "fixture", "cosign_fixture.py", "sigstore_fixture.py"),
        "SERVERWARE_IMAGE_SIGN_COMMAND must not use fixture helpers",
    )
    add(
        failures,
        verify_command and not command_mentions(verify_command, "fixture", "cosign_fixture.py", "sigstore_fixture.py"),
        "SERVERWARE_IMAGE_VERIFY_COMMAND must not use fixture helpers",
    )
    cosign_binary = env.get("SERVERWARE_COSIGN_BINARY", "cosign").strip()
    add(failures, bool(cosign_binary), "SERVERWARE_COSIGN_BINARY must be configured")
    add(
        failures,
        not command_mentions(cosign_binary, "fixture", "cosign_fixture.py"),
        "SERVERWARE_COSIGN_BINARY must not use fixture helpers",
    )
    add(failures, env_bool(env, "SERVERWARE_REQUIRE_SIGSTORE_TRANSPARENCY"), "Sigstore transparency evidence must be required")
    key_ref = env.get("SERVERWARE_COSIGN_KEY", "").strip()
    cert_identity = env.get("SERVERWARE_COSIGN_CERT_IDENTITY", "").strip()
    cert_issuer = env.get("SERVERWARE_COSIGN_CERT_OIDC_ISSUER", "").strip()
    kms_key_ok = key_ref.startswith(KMS_KEY_PREFIXES)
    add(
        failures,
        kms_key_ok,
        "cosign must use SERVERWARE_COSIGN_KEY with a KMS/HSM-backed URI",
    )
    if key_ref:
        add(failures, kms_key_ok, f"SERVERWARE_COSIGN_KEY must use a KMS/HSM-backed URI prefix: {', '.join(KMS_KEY_PREFIXES)}")
    add(
        failures,
        not cert_identity and not cert_issuer,
        "Cosign keyless/Fulcio mode is not supported by release completion; certificate identity and issuer settings must be unset",
    )
    add(
        failures,
        bool(env.get("SERVERWARE_COSIGN_KEY_ID", "").strip()),
        "SERVERWARE_COSIGN_KEY_ID must pin the stable signing public-key identity",
    )
    add(failures, bool(env.get("SERVERWARE_COSIGN_EXPECTED_REKOR_LOG_ID", "").strip()), "Sigstore/Rekor log ID must be pinned")


def expected_sigstore_key_id(env: dict[str, str]) -> str | None:
    explicit = env.get("SERVERWARE_COSIGN_KEY_ID", "").strip()
    return explicit or None


def check_transparency(env: dict[str, str], failures: list[str]) -> None:
    release_anchor = urllib.parse.urlparse(env.get("SERVERWARE_RELEASE_ANCHOR_BASE", "").strip())
    add(
        failures,
        release_anchor.scheme == "https" and bool(release_anchor.hostname),
        "SERVERWARE_RELEASE_ANCHOR_BASE must be an HTTPS URL",
    )
    add(
        failures,
        not placeholder_hostname(release_anchor.hostname),
        "SERVERWARE_RELEASE_ANCHOR_BASE must not use .example placeholder domains",
    )
    add(
        failures,
        (release_anchor.hostname or "").lower() not in {"localhost", "127.0.0.1", "::1"},
        "SERVERWARE_RELEASE_ANCHOR_BASE must not be loopback",
    )
    release_anchor_ca = env.get("SERVERWARE_RELEASE_ANCHOR_CA_BUNDLE", "").strip()
    if release_anchor_ca:
        add(
            failures,
            Path(release_anchor_ca).is_absolute(),
            "SERVERWARE_RELEASE_ANCHOR_CA_BUNDLE must be an absolute path when configured",
        )
    add(
        failures,
        env_bool(env, "SERVERWARE_TRANSPARENCY_CHECKPOINT_REQUIRED"),
        "external transparency checkpoint publication must be required",
    )
    checkpoint_command = env.get("SERVERWARE_TRANSPARENCY_CHECKPOINT_COMMAND", "").strip()
    add(failures, bool(checkpoint_command), "SERVERWARE_TRANSPARENCY_CHECKPOINT_COMMAND must be configured")
    add(
        failures,
        not command_mentions(checkpoint_command, "external_transparency_log.py"),
        "legacy local external_transparency_log.py fixture must not be used in production",
    )
    mode = env.get("SERVERWARE_TRANSPARENCY_CHECKPOINT_MODE", "").strip()
    add(failures, mode != "fixture", "SERVERWARE_TRANSPARENCY_CHECKPOINT_MODE must not be fixture in production")
    url = env.get("SERVERWARE_TRANSPARENCY_LOG_URL", "").strip()
    parsed = urllib.parse.urlparse(url)
    add(failures, parsed.scheme == "https" and bool(parsed.netloc), "SERVERWARE_TRANSPARENCY_LOG_URL must be an https URL")
    add(
        failures,
        not placeholder_hostname(parsed.hostname),
        "SERVERWARE_TRANSPARENCY_LOG_URL must not use .example placeholder domains",
    )
    add(
        failures,
        not env_bool(env, "SERVERWARE_TRANSPARENCY_ALLOW_INSECURE_HTTP"),
        "SERVERWARE_TRANSPARENCY_ALLOW_INSECURE_HTTP must be disabled",
    )
    add(failures, bool(env.get("SERVERWARE_TRANSPARENCY_EXPECTED_PROVIDER", "").strip()), "managed transparency provider must be pinned")
    add(failures, bool(env.get("SERVERWARE_TRANSPARENCY_EXPECTED_LOG_ID", "").strip()), "managed transparency log ID must be pinned")
    headers = env_json_object(env, "SERVERWARE_TRANSPARENCY_LOG_HEADERS")
    if headers:
        forbidden = {"authorization", "content-length", "host"}
        bad = sorted(key for key in headers if key.lower() in forbidden)
        add(failures, not bad, f"SERVERWARE_TRANSPARENCY_LOG_HEADERS cannot override {bad}")


def check_apparmor(env: dict[str, str], failures: list[str]) -> None:
    profile = ROOT / "security" / "apparmor" / "serverware-docker"
    override = ROOT / "docker-compose.apparmor.yml"
    add(failures, profile.exists(), "AppArmor profile file must exist")
    add(failures, override.exists(), "AppArmor Compose override must exist")
    expected_profile = env.get("SERVERWARE_APPARMOR_EXPECTED_PROFILE", "serverware-docker").strip()
    add(failures, expected_profile == "serverware-docker", "SERVERWARE_APPARMOR_EXPECTED_PROFILE must pin serverware-docker")


def check_shared_stores(env: dict[str, str], failures: list[str]) -> None:
    add(
        failures,
        not env.get("SERVERWARE_DECISION_GATE_BASE", "").strip(),
        "production must use the shared grant store instead of the gate's local management API",
    )
    add(failures, env.get("SERVERWARE_METADATA_STORE_BACKEND") == "postgres", "metadata store must be postgres")
    add(failures, bool(env.get("SERVERWARE_METADATA_STORE_POSTGRES_DSN", "").strip()), "metadata Postgres DSN must be configured")
    add(failures, env.get("SERVERWARE_GRANT_STORE_BACKEND") == "postgres", "grant store must be postgres")
    add(failures, bool(env.get("SERVERWARE_GRANT_STORE_POSTGRES_DSN", "").strip()), "grant Postgres DSN must be configured")
    metadata_dsn = env.get("SERVERWARE_METADATA_STORE_POSTGRES_DSN", "").strip()
    grant_dsn = env.get("SERVERWARE_GRANT_STORE_POSTGRES_DSN", "").strip()
    add(
        failures,
        bool(metadata_dsn) and hmac.compare_digest(metadata_dsn, grant_dsn),
        "atomic release authorization requires metadata and grant stores on the same writer DSN and schema",
    )
    add(failures, env.get("SERVERWARE_AUDIT_STORE_BACKEND") == "postgres", "audit store must be postgres")
    add(failures, bool(env.get("SERVERWARE_AUDIT_STORE_POSTGRES_DSN", "").strip()), "audit Postgres DSN must be configured")
    witness_dsn = env.get(
        "SERVERWARE_WEBAUTHN_RECOVERY_WITNESS_POSTGRES_DSN", ""
    ).strip()
    add(
        failures,
        env.get("SERVERWARE_WEBAUTHN_RECOVERY_WITNESS_BACKEND") == "postgres",
        "recovery authorization witness must use Postgres",
    )
    add(
        failures,
        bool(witness_dsn),
        "recovery authorization witness Postgres DSN must be configured",
    )
    add(
        failures,
        bool(metadata_dsn)
        and bool(witness_dsn)
        and not hmac.compare_digest(metadata_dsn, witness_dsn),
        "recovery authorization witness must not reuse the metadata DSN",
    )
    metadata_fault_domain = env.get("SERVERWARE_METADATA_STORE_FAULT_DOMAIN_ID", "").strip()
    witness_fault_domain = env.get(
        "SERVERWARE_WEBAUTHN_RECOVERY_WITNESS_FAULT_DOMAIN_ID", ""
    ).strip()
    for label, value in (
        ("metadata store", metadata_fault_domain),
        ("recovery witness", witness_fault_domain),
    ):
        add(
            failures,
            bool(value)
            and len(value) <= 256
            and value.isascii()
            and all(character.isprintable() and not character.isspace() for character in value),
            f"{label} fault-domain identity must be configured as bounded printable ASCII without whitespace",
        )
    add(
        failures,
        bool(metadata_fault_domain)
        and bool(witness_fault_domain)
        and not hmac.compare_digest(metadata_fault_domain, witness_fault_domain),
        "recovery authorization witness must use an independently provisioned fault-domain identity",
    )
    add(
        failures,
        env_bool(env, "SERVERWARE_ATOMIC_RELEASE_AUTHORIZATION_ENABLED"),
        "atomic release authorization must be enabled",
    )
    release_authorization_url = env.get(
        "SERVERWARE_CONTROL_PLANE_RELEASE_AUTHORIZATION_BASE_URL", ""
    ).strip()
    add(
        failures,
        bool(release_authorization_url),
        "atomic release authorization base URL must be configured",
    )
    if release_authorization_url:
        parsed = urllib.parse.urlparse(release_authorization_url)
        add(
            failures,
            parsed.scheme == "https" and bool(parsed.netloc),
            "atomic release authorization base URL must use https",
        )
        add(
            failures,
            parsed.path.rstrip("/")
            == "/api/data-plane/release-authorizations"
            and not parsed.username
            and not parsed.password
            and not parsed.query
            and not parsed.fragment,
            "atomic release authorization base URL must use the exact API path without embedded credentials, query, or fragment",
        )
    try:
        reservation_ttl = int(
            env.get("SERVERWARE_RELEASE_AUTHORIZATION_RESERVATION_TTL_SECONDS", "")
        )
        dispatch_ttl = int(
            env.get("SERVERWARE_RELEASE_AUTHORIZATION_DISPATCH_TTL_SECONDS", "")
        )
        reconcile_limit = int(
            env.get("SERVERWARE_RELEASE_AUTHORIZATION_RECONCILE_LIMIT", "")
        )
    except ValueError:
        reservation_ttl = dispatch_ttl = reconcile_limit = 0
    add(
        failures,
        1 <= reservation_ttl <= 300,
        "release authorization reservation TTL must be between 1 and 300 seconds",
    )
    add(
        failures,
        1 <= dispatch_ttl <= 300,
        "release authorization dispatch TTL must be between 1 and 300 seconds",
    )
    add(
        failures,
        1 <= reconcile_limit <= 500,
        "release authorization reconcile limit must be between 1 and 500",
    )


def check_internal_service_auth(env: dict[str, str], failures: list[str]) -> None:
    instance_id = env.get("SERVERWARE_DATA_PLANE_INSTANCE_ID", "").strip()
    add(
        failures,
        instance_id.startswith("spiffe://") and len(instance_id) > len("spiffe://"),
        "SERVERWARE_DATA_PLANE_INSTANCE_ID must identify the authenticated data-plane instance",
    )
    tokens = [(name, env.get(name, "").strip()) for name in INTERNAL_SERVICE_TOKEN_NAMES]
    for name, token in tokens:
        add(
            failures,
            service_token_is_strong(token),
            f"{name} must be configured with at least 32 high-entropy bytes",
        )
    for index, (left_name, left_token) in enumerate(tokens):
        for right_name, right_token in tokens[index + 1 :]:
            add(
                failures,
                not left_token or not right_token or not hmac.compare_digest(left_token, right_token),
                f"internal service credentials must be distinct: {left_name} and {right_name}",
            )


def check_agent_egress(env: dict[str, str], failures: list[str]) -> None:
    add(
        failures,
        env_bool(env, "SERVERWARE_AGENT_EGRESS_POLICY_REQUIRED"),
        "agent egress policy enforcement must be required",
    )
    mode = env.get("SERVERWARE_AGENT_EGRESS_POLICY_MODE", "").strip()
    add(
        failures,
        mode in {"kubernetes-network-policy", "iptables", "nftables", "cloud-firewall"},
        "agent egress policy mode must be kubernetes-network-policy, iptables, nftables, or cloud-firewall",
    )
    raw_cidrs = [item.strip() for item in env.get("SERVERWARE_AGENT_EGRESS_PROXY_CIDRS", "").split(",") if item.strip()]
    add(failures, bool(raw_cidrs), "agent egress proxy CIDRs must be configured")
    for cidr in raw_cidrs:
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            failures.append(f"agent egress proxy CIDR is invalid: {cidr}")
            continue
        add(failures, network.prefixlen != 0, "agent egress proxy CIDRs must not be universal routes")
    try:
        port = int(env.get("SERVERWARE_AGENT_EGRESS_PROXY_PORT", "0"))
    except ValueError:
        port = 0
    add(failures, 1 <= port <= 65535, "agent egress proxy port must be configured")
    add(
        failures,
        bool(env.get("SERVERWARE_AGENT_ENROLLMENT_REQUIRED", "").strip() or env_bool(env, "SERVERWARE_AGENT_ENROLLMENT_PACKET_REQUIRED")),
        "agent enrollment packets must be required before production credentials are enabled",
    )


def production_images(env: dict[str, str]) -> list[str]:
    return [item.strip() for item in env.get("SERVERWARE_PRODUCTION_IMAGES", "").split(",") if item.strip()]


def check_production_images(env: dict[str, str], failures: list[str]) -> None:
    add(
        failures,
        env_bool(env, "SERVERWARE_PRODUCTION_IMAGE_NO_SHELL_REQUIRED"),
        "production image no-shell verification must be required",
    )
    images = production_images(env)
    add(failures, len(images) == 2, "SERVERWARE_PRODUCTION_IMAGES must list exactly control and decision-gate image refs")
    for image in images:
        add(
            failures,
            bool(re.search(r"@sha256:[0-9a-f]{64}$", image)),
            f"production image ref must be immutable and pinned by digest: {image}",
        )
        lowered = image.lower()
        add(
            failures,
            all(marker not in lowered for marker in ("fixture", ":dev", ":local", ":test")),
            f"production image ref must not use fixture/dev/local/test markers: {image}",
        )
        add(
            failures,
            not placeholder_hostname(image_ref_hostname(image)),
            f"production image ref must not use .example placeholder registry domains: {image}",
        )
    control_image = env.get("SERVERWARE_CONTROL_PLANE_IMAGE", "").strip()
    gate_image = env.get("SERVERWARE_DECISION_GATE_IMAGE", "").strip()
    add(
        failures,
        control_image in images and control_image.rsplit("/", 1)[-1].startswith("control@sha256:"),
        "SERVERWARE_CONTROL_PLANE_IMAGE must select the digest-pinned control image",
    )
    add(
        failures,
        gate_image in images and gate_image.rsplit("/", 1)[-1].startswith("decision-gate@sha256:"),
        "SERVERWARE_DECISION_GATE_IMAGE must select the digest-pinned decision-gate image",
    )


def run_command(command: list[str], *, env: dict[str, str], input_obj: dict[str, Any] | None = None) -> dict[str, Any] | None:
    input_bytes = None
    if input_obj is not None:
        input_bytes = (canonical_json(input_obj) + "\n").encode("utf-8")
    result = subprocess.run(command, cwd=ROOT, env=env, input=input_bytes, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=180)
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace") or result.stdout.decode("utf-8", errors="replace")
        raise RuntimeError(f"{' '.join(command)} failed with exit {result.returncode}: {detail.strip()}")
    if not result.stdout.strip():
        return None
    parsed = json.loads(result.stdout.decode("utf-8"))
    if not isinstance(parsed, dict):
        raise RuntimeError(f"{' '.join(command)} returned non-object JSON")
    return parsed


def require_response_fields(response: dict[str, Any], fields: set[str], label: str) -> None:
    missing = sorted(fields - set(response))
    if missing:
        raise RuntimeError(f"{label} response missing fields: {', '.join(missing)}")


def run_sigstore_probe(env: dict[str, str]) -> dict[str, Any]:
    sign_command = command_words(env.get("SERVERWARE_IMAGE_SIGN_COMMAND", ""))
    verify_command = command_words(env.get("SERVERWARE_IMAGE_VERIFY_COMMAND", ""))
    if not sign_command:
        raise RuntimeError("SERVERWARE_IMAGE_SIGN_COMMAND must be configured for live Sigstore probe")
    if not verify_command:
        raise RuntimeError("SERVERWARE_IMAGE_VERIFY_COMMAND must be configured for live Sigstore probe")

    nonce = f"serverware-production-readiness-sigstore-{int(time.time())}"
    subject_digest = hashlib.sha256(nonce.encode("utf-8")).hexdigest()
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [
            {
                "name": "serverware-production-readiness-probe",
                "digest": {"sha256": subject_digest},
            }
        ],
        "predicateType": "https://serverware.dev/production-readiness/sigstore-probe/v1",
        "predicate": {
            "nonce": nonce,
            "releaseChannel": env.get("SERVERWARE_RELEASE_CHANNEL", ""),
            "purpose": "prove configured production Sigstore signing and verification command path",
        },
    }
    sign_request = {
        "apiVersion": "serverware.sigstoreSignRequest/v1",
        "kind": "production-readiness-probe",
        "service": "production-readiness",
        "image_id": sha256_prefixed_bytes(nonce.encode("utf-8")),
        "statement": statement,
        "statement_digest": sha256_prefixed_json(statement),
    }
    signature = run_command(sign_command, env=env, input_obj=sign_request) or {}
    if signature.get("ok") is not True:
        raise RuntimeError(f"Sigstore sign command did not return ok=true: {signature}")
    if signature.get("statement_digest") != sign_request["statement_digest"]:
        raise RuntimeError("Sigstore sign response did not bind the signed statement digest")
    key_provider = signature.get("key_provider") if isinstance(signature.get("key_provider"), dict) else {}
    expected_key_id = expected_sigstore_key_id(env)
    if expected_key_id and key_provider.get("key_id") != expected_key_id:
        raise RuntimeError("Sigstore sign response did not bind the expected key identity")
    require_transparency = env_bool(env, "SERVERWARE_REQUIRE_SIGSTORE_TRANSPARENCY")
    transparency = signature.get("transparency") or {}
    if require_transparency:
        require_response_fields(
            transparency,
            {"log_id", "entry_uuid", "integrated_time", "inclusion_proof"},
            "Sigstore transparency",
        )
    expected_log_id = env.get("SERVERWARE_COSIGN_EXPECTED_REKOR_LOG_ID", "").strip()
    if expected_log_id and transparency.get("log_id") != expected_log_id:
        raise RuntimeError("Sigstore sign response did not bind the expected Rekor log ID")

    verify_request = {
        "apiVersion": "serverware.sigstoreVerifyRequest/v1",
        "kind": sign_request["kind"],
        "service": sign_request["service"],
        "image_id": sign_request["image_id"],
        "statement": statement,
        "statement_digest": sign_request["statement_digest"],
        "signature_response": signature,
    }
    verified = run_command(verify_command, env=env, input_obj=verify_request) or {}
    if verified.get("ok") is not True:
        raise RuntimeError(f"Sigstore verify command did not return ok=true: {verified}")
    if require_transparency and verified.get("verified_transparency") is not True:
        raise RuntimeError(f"Sigstore verify command did not prove transparency: {verified}")
    if verified.get("statement_digest") != sign_request["statement_digest"]:
        raise RuntimeError("Sigstore verify response did not bind the signed statement digest")
    verify_key_provider = verified.get("key_provider") if isinstance(verified.get("key_provider"), dict) else {}
    if expected_key_id and verify_key_provider.get("key_id") != expected_key_id:
        raise RuntimeError("Sigstore verify response did not bind the expected key identity")

    return {
        "ok": True,
        "provider": signature.get("provider"),
        "key_id": key_provider.get("key_id"),
        "workload_identity": key_provider.get("workload_identity"),
        "oidc_issuer": key_provider.get("oidc_issuer"),
        "transparency_log_id": transparency.get("log_id"),
        "entry_uuid": transparency.get("entry_uuid"),
    }


def production_readiness_checkpoint(env: dict[str, str]) -> dict[str, Any]:
    nonce = f"serverware-production-readiness-transparency-{int(time.time())}"
    record = {
        "kind": "serverware.productionReadinessTransparencyProbe",
        "version": "v1",
        "nonce": nonce,
        "releaseChannel": env.get("SERVERWARE_RELEASE_CHANNEL", ""),
    }
    record_digest = sha256_prefixed_json(record)
    leaf = {"record_digest": record_digest, "nonce": nonce}
    leaf_hash = sha256_prefixed_json(leaf)
    tree_size = int(time.time())
    tree_head_hash = sha256_prefixed_json({"leaf_hash": leaf_hash, "tree_size": tree_size})
    signed_tree_head = {
        "version": "serverware.signedTreeHead/v1",
        "tree_size": tree_size,
        "tree_head_hash": tree_head_hash,
        "signature": "production-readiness-probe",
    }
    return {
        "version": "serverware.transparencyCheckpoint/v1",
        "mode": "signed-merkle-transparency-log",
        "sequence": tree_size,
        "record_digest": record_digest,
        "leaf_hash": leaf_hash,
        "tree_size": tree_size,
        "tree_head_hash": tree_head_hash,
        "signed_tree_head": signed_tree_head,
        "record": record,
    }


def run_transparency_probe(env: dict[str, str]) -> dict[str, Any]:
    checkpoint_command = command_words(env.get("SERVERWARE_TRANSPARENCY_CHECKPOINT_COMMAND", ""))
    if not checkpoint_command:
        raise RuntimeError("SERVERWARE_TRANSPARENCY_CHECKPOINT_COMMAND must be configured for live transparency probe")
    checkpoint = production_readiness_checkpoint(env)
    response = run_command(checkpoint_command, env=env, input_obj=checkpoint) or {}
    if response.get("ok") is not True:
        raise RuntimeError(f"external transparency checkpoint command did not return ok=true: {response}")
    verified = run_command(
        [sys.executable, "scripts/transparency_checkpoint.py", "verify"],
        env=env,
        input_obj={"checkpoint": checkpoint, "response": response},
    ) or {}
    if verified.get("ok") is not True:
        raise RuntimeError(f"external transparency checkpoint response did not verify: {verified}")
    return {
        "ok": True,
        "provider": verified.get("provider"),
        "log_id": verified.get("log_id"),
        "external_sequence": verified.get("external_sequence"),
        "tree_size": verified.get("tree_size"),
    }


def postgres_table_probe(label: str, dsn: str, required_tables: tuple[str, ...]) -> dict[str, Any]:
    try:
        import psycopg
        from psycopg.rows import dict_row
    except ImportError as exc:
        raise RuntimeError("live shared-store probe requires psycopg[binary]") from exc
    try:
        with psycopg.connect(dsn, connect_timeout=5, row_factory=dict_row) as conn:
            conn.read_only = True
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT current_database() AS database, current_user AS user, "
                    "COALESCE(inet_server_addr()::text, '') AS server_address, "
                    "COALESCE(inet_server_port(), 0) AS server_port, "
                    "system_identifier FROM pg_control_system()"
                )
                identity = dict(cur.fetchone() or {})
                missing: list[str] = []
                for table in required_tables:
                    cur.execute("SELECT to_regclass(%s) AS table_name", (table,))
                    row = cur.fetchone() or {}
                    if row.get("table_name") is None:
                        cur.execute("SELECT to_regclass(%s) AS table_name", (f"public.{table}",))
                        row = cur.fetchone() or {}
                    if row.get("table_name") is None:
                        missing.append(table)
        if missing:
            raise RuntimeError(f"{label} Postgres store is missing required tables: {', '.join(missing)}")
        return {
            "ok": True,
            "database": identity.get("database"),
            "user": identity.get("user"),
            "server_address": identity.get("server_address"),
            "server_port": identity.get("server_port"),
            "system_identifier": identity.get("system_identifier"),
            "tables": list(required_tables),
        }
    except Exception as exc:
        raise RuntimeError(f"{label} Postgres live probe failed: {exc}") from exc


def run_shared_store_probe(env: dict[str, str]) -> dict[str, Any]:
    metadata_dsn = env.get("SERVERWARE_METADATA_STORE_POSTGRES_DSN", "").strip()
    grant_dsn = env.get("SERVERWARE_GRANT_STORE_POSTGRES_DSN", "").strip()
    if not metadata_dsn or not grant_dsn or not hmac.compare_digest(
        metadata_dsn, grant_dsn
    ):
        raise RuntimeError(
            "metadata and grant Postgres DSNs must identify the same writer and schema"
        )
    stores = {
        "metadata": (
            env.get("SERVERWARE_METADATA_STORE_POSTGRES_DSN", "").strip(),
            METADATA_TABLES,
        ),
        "grant": (
            env.get("SERVERWARE_GRANT_STORE_POSTGRES_DSN", "").strip(),
            GRANT_TABLES,
        ),
        "audit": (
            env.get("SERVERWARE_AUDIT_STORE_POSTGRES_DSN", "").strip(),
            AUDIT_TABLES,
        ),
        "recovery_witness": (
            env.get(
                "SERVERWARE_WEBAUTHN_RECOVERY_WITNESS_POSTGRES_DSN", ""
            ).strip(),
            RECOVERY_WITNESS_TABLES,
        ),
    }
    results: dict[str, Any] = {}
    for label, (dsn, tables) in stores.items():
        if not dsn:
            raise RuntimeError(f"{label} Postgres DSN must be configured for live shared-store probe")
        results[label] = postgres_table_probe(label, dsn, tables)
    metadata_identity = (
        results["metadata"].get("server_address"),
        int(results["metadata"].get("server_port") or 0),
    )
    witness_identity = (
        results["recovery_witness"].get("server_address"),
        int(results["recovery_witness"].get("server_port") or 0),
    )
    if metadata_identity == witness_identity:
        raise RuntimeError(
            "recovery authorization witness must use a non-colocated Postgres server"
        )
    metadata_cluster = str(results["metadata"].get("system_identifier") or "")
    witness_cluster = str(results["recovery_witness"].get("system_identifier") or "")
    if not metadata_cluster or not witness_cluster:
        raise RuntimeError("Postgres system_identifier is required for recovery witness separation")
    if hmac.compare_digest(metadata_cluster, witness_cluster):
        raise RuntimeError(
            "recovery authorization witness must use an independent Postgres cluster"
        )
    return {"ok": True, "stores": results}


def live_claims(env: dict[str, str], claims_file: str | None) -> dict[str, Any]:
    if claims_file:
        parsed = json.loads(Path(claims_file).read_text(encoding="utf-8"))
    else:
        parsed = env_json_object(env, "SERVERWARE_PRODUCTION_READINESS_CLAIMS_JSON")
    if not isinstance(parsed, dict):
        raise RuntimeError("live mode requires --claims-file or SERVERWARE_PRODUCTION_READINESS_CLAIMS_JSON")
    parsed = json.loads(json.dumps(parsed))
    parsed["nonce"] = f"production-readiness-{int(time.time())}"
    return parsed


def run_live_probes(
    env: dict[str, str],
    claims_file: str | None,
    nitro_evidence_file: str | None = None,
) -> dict[str, Any]:
    probes: dict[str, Any] = {}
    probes["sigstore"] = run_sigstore_probe(env)
    probes["external_transparency"] = run_transparency_probe(env)
    probes["shared_stores"] = run_shared_store_probe(env)

    claims = live_claims(env, claims_file)
    if nitro_evidence_file:
        evidence_path = Path(nitro_evidence_file)
        evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
        if not isinstance(evidence, dict) or evidence.get("ok") is not True:
            raise RuntimeError("pre-collected Nitro/KMS evidence is absent or not ok")
        expected_claims = collect_nitro_kms_evidence.redacted_claims(claims)
        evidence_claims = evidence.get("claims") if isinstance(evidence.get("claims"), dict) else {}
        evidence_fields = dict(evidence_claims.get("fields") or {})
        expected_fields = dict(expected_claims.get("fields") or {})
        evidence_fields.pop("nonce", None)
        expected_fields.pop("nonce", None)
        if evidence_fields != expected_fields:
            raise RuntimeError("pre-collected Nitro/KMS evidence claims do not match live readiness claims")
        probes["nitro"] = evidence
    else:
        probes["nitro"] = collect_nitro_kms_evidence.collect_evidence(claims, env)

    image_args: list[str] = []
    for image in production_images(env):
        image_args.extend(["--image", image])
    if env_bool(env, "SERVERWARE_PRODUCTION_IMAGE_PULL"):
        image_args.append("--pull")
    image_scan = run_command([sys.executable, "scripts/verify_production_images_no_shell.py", *image_args], env=env)
    probes["production_images_no_shell"] = {
        "ok": True,
        "images": [item.get("image") for item in (image_scan or {}).get("results", []) if item.get("image")],
    }

    if platform.system().lower() != "linux":
        raise RuntimeError("AppArmor live probe requires a Linux Docker host")
    run_command(["./scripts/test_apparmor_runtime.sh"], env=env)
    probes["apparmor"] = {"ok": True}
    return probes


def write_result(path: str, result: dict[str, Any]) -> str:
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    payload = (json.dumps(result, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode("utf-8")
    output_path.write_bytes(payload)
    return sha256_prefixed_bytes(payload)


def emit_result(result: dict[str, Any], out_path: str | None) -> None:
    if out_path:
        result["result_path"] = out_path
        result["result_sha256"] = write_result(out_path, result)
    print(canonical_json(result))


def main() -> None:
    parser = argparse.ArgumentParser(description="Fail-closed production readiness gate for Serverware external trust dependencies.")
    parser.add_argument("--mode", choices=("config", "live"), default="config")
    parser.add_argument("--claims-file", default=None)
    parser.add_argument("--nitro-evidence-file", default=None)
    parser.add_argument(
        "--expected-control-plane-uid",
        type=bounded_non_root_id,
        default=CONTROL_PLANE_RUNTIME_UID,
        help="production control-plane UID expected to read runtime secrets",
    )
    parser.add_argument(
        "--expected-control-plane-gid",
        type=bounded_non_root_id,
        default=CONTROL_PLANE_RUNTIME_GID,
        help="production control-plane GID expected to read runtime secrets",
    )
    parser.add_argument("--out", default=None, help="write the full readiness result JSON to this path")
    args = parser.parse_args()

    env = dict(os.environ)
    failures: list[str] = []
    for check in (
        check_no_dev_or_fixture,
        check_control_plane_security,
        check_oauth_providers,
        check_nitro,
        check_attested_credential_delivery,
        partial(
            check_release_completion_trust,
            expected_control_plane_uid=args.expected_control_plane_uid,
            expected_control_plane_gid=args.expected_control_plane_gid,
        ),
        check_final_challenge_authority,
        check_cosign,
        check_transparency,
        check_apparmor,
        check_internal_service_auth,
        check_shared_stores,
        check_agent_egress,
        check_production_images,
    ):
        try:
            check(env, failures)
        except Exception as exc:
            failures.append(str(exc))
    if failures:
        emit_result(
            {
                "ok": False,
                "production_readiness": "fail",
                "mode": args.mode,
                "checks": READINESS_CHECKS,
                "environment": redacted_environment_summary(env),
                "failures": failures,
            },
            args.out,
        )
        raise SystemExit(1)

    live = None
    if args.mode == "live":
        try:
            live = run_live_probes(env, args.claims_file, args.nitro_evidence_file)
        except Exception as exc:
            emit_result(
                {
                    "ok": False,
                    "production_readiness": "fail",
                    "mode": "live",
                    "checks": READINESS_CHECKS,
                    "environment": redacted_environment_summary(env),
                    "failures": [str(exc)],
                },
                args.out,
            )
            raise SystemExit(1) from exc

    result = {
        "ok": True,
        "production_readiness": "pass",
        "mode": args.mode,
        "checks": READINESS_CHECKS,
        "environment": redacted_environment_summary(env),
        "live": live,
    }
    emit_result(result, args.out)


if __name__ == "__main__":
    main()
