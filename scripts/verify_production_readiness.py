#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import hmac
import ipaddress
import json
import os
import platform
import re
import shlex
import subprocess
import sys
import time
import urllib.parse
from pathlib import Path
from typing import Any

import collect_nitro_kms_evidence


ROOT = Path(__file__).resolve().parent.parent
REQUIRED_MATERIALS = {"broker-kek", "decision-gate-ca"}
READINESS_CHECKS = [
    "no-dev-fixtures",
    "control-plane-auth",
    "nitro",
    "attested-credential-delivery",
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
    "routes",
    "approval_requests",
    "control_plane_approvals",
    "webauthn_credentials",
    "webauthn_challenges",
    "gmail_message_cache",
    "request_logs",
    "rate_limit_counters",
    "policy_high_water",
)
GRANT_TABLES = ("approval_grants", "approval_grant_consumptions")
AUDIT_TABLES = ("serverware_audit_events",)
KMS_KEY_PREFIXES = (
    "awskms://",
    "gcpkms://",
    "azurekms://",
    "hashivault://",
    "pkcs11:",
    "kms://",
)
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
INTERNAL_SERVICE_TOKEN_NAMES = (
    "SERVERWARE_DATA_PLANE_CREDENTIAL_LEASE_TOKEN",
    "SERVERWARE_DATA_PLANE_AUDIT_TOKEN",
    "SERVERWARE_DATA_PLANE_GRANT_CONSUME_TOKEN",
    "SERVERWARE_DATA_PLANE_RATE_LIMIT_CONSUME_TOKEN",
    "SERVERWARE_DATA_PLANE_MANAGEMENT_TOKEN",
)


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_prefixed_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def sha256_prefixed_json(value: Any) -> str:
    return sha256_prefixed_bytes(canonical_json(value).encode("utf-8"))


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
    required_roles = {"admin", "approver", "auditor", "policy_author", "policy_publisher", "credential_owner"}
    add(
        failures,
        required_roles.issubset(roles),
        "SERVERWARE_ADMIN_ROLES must include admin, approver, auditor, policy_author, policy_publisher, and credential_owner",
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
        "credential.update",
        "credential.delete",
        "route.create",
        "route.update",
        "route.delete",
        "policy.publish",
        "webauthn.credential.register",
        "rbac.role.change",
        "rbac.deprovision",
        "control_plane.token.rotate",
        "break_glass.grant",
    }
    add(
        failures,
        "*" in two_person_actions or required_two_person_actions.issubset(two_person_actions),
        "SERVERWARE_CONTROL_PLANE_TWO_PERSON_ACTIONS must cover credential, route, policy publish, WebAuthn enrollment, RBAC, deprovisioning, token rotation, and break-glass mutations",
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
    keyless_ok = bool(cert_identity and cert_issuer)
    kms_key_ok = key_ref.startswith(KMS_KEY_PREFIXES)
    add(
        failures,
        keyless_ok or kms_key_ok,
        "cosign must use a KMS/HSM key ref or keyless certificate identity plus OIDC issuer",
    )
    if key_ref:
        add(failures, kms_key_ok, f"SERVERWARE_COSIGN_KEY must use a KMS/HSM-backed URI prefix: {', '.join(KMS_KEY_PREFIXES)}")
    add(failures, bool(env.get("SERVERWARE_COSIGN_KEY_ID", "").strip() or keyless_ok), "cosign key provider identity must be stable")
    add(failures, bool(env.get("SERVERWARE_COSIGN_EXPECTED_REKOR_LOG_ID", "").strip()), "Sigstore/Rekor log ID must be pinned")


def expected_sigstore_key_id(env: dict[str, str]) -> str | None:
    explicit = env.get("SERVERWARE_COSIGN_KEY_ID", "").strip()
    if explicit:
        return explicit
    key_ref = env.get("SERVERWARE_COSIGN_KEY", "").strip()
    if key_ref:
        return sha256_prefixed_bytes(key_ref.encode("utf-8"))
    cert_identity = env.get("SERVERWARE_COSIGN_CERT_IDENTITY", "").strip()
    cert_issuer = env.get("SERVERWARE_COSIGN_CERT_OIDC_ISSUER", "").strip()
    if cert_identity or cert_issuer:
        return sha256_prefixed_bytes(f"{cert_identity}|{cert_issuer}".encode("utf-8"))
    return None


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
    add(failures, env.get("SERVERWARE_AUDIT_STORE_BACKEND") == "postgres", "audit store must be postgres")
    add(failures, bool(env.get("SERVERWARE_AUDIT_STORE_POSTGRES_DSN", "").strip()), "audit Postgres DSN must be configured")
    add(
        failures,
        bool(env.get("SERVERWARE_CONTROL_PLANE_GRANT_CONSUME_URL", "").strip()),
        "shared JIT grant consume URL must be configured",
    )
    add(
        failures,
        bool(env.get("SERVERWARE_CONTROL_PLANE_RATE_LIMIT_CONSUME_URL", "").strip()),
        "shared rate-limit consume URL must be configured",
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
                cur.execute("SELECT current_database() AS database, current_user AS user")
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
            "tables": list(required_tables),
        }
    except Exception as exc:
        raise RuntimeError(f"{label} Postgres live probe failed: {exc}") from exc


def run_shared_store_probe(env: dict[str, str]) -> dict[str, Any]:
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
    }
    results: dict[str, Any] = {}
    for label, (dsn, tables) in stores.items():
        if not dsn:
            raise RuntimeError(f"{label} Postgres DSN must be configured for live shared-store probe")
        results[label] = postgres_table_probe(label, dsn, tables)
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
    parser.add_argument("--out", default=None, help="write the full readiness result JSON to this path")
    args = parser.parse_args()

    env = dict(os.environ)
    failures: list[str] = []
    for check in (
        check_no_dev_or_fixture,
        check_control_plane_security,
        check_nitro,
        check_attested_credential_delivery,
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
