from __future__ import annotations

import contextlib
import contextvars
import base64
import fcntl
import hashlib
import hmac
import json
import os
import re
import sqlite3
import time
import uuid
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path
from typing import Any

from serverware import grants
from serverware.config import (
    AUDIT_STORE_BACKEND,
    AUDIT_STORE_CONNECT_TIMEOUT_SECONDS,
    AUDIT_STORE_POSTGRES_DSN,
    CREDENTIAL_LEASE_REPLAY_MAX_ENTRIES,
    DB_PATH,
    METADATA_STORE_BACKEND,
    METADATA_STORE_CONNECT_TIMEOUT_SECONDS,
    METADATA_STORE_FAULT_DOMAIN_ID,
    METADATA_STORE_POSTGRES_DSN,
    OAUTH_PENDING_CREDENTIAL_MAX_COUNT,
    OIDC_SESSION_ACTIVATION_RETRY_TTL_SECONDS,
    RBAC_BINDINGS_PATH,
    SETUP_SESSION_AUDIT_CLAIM_TTL_SECONDS,
    SETUP_SESSION_AUDIT_OUTBOX_MAX_PENDING,
    SETUP_SESSION_EVENT_MAX_BYTES,
    SETUP_SESSION_EVENT_MAX_COUNT,
    SETUP_SESSION_EVIDENCE_MAX_BYTES,
    SETUP_SESSION_EVIDENCE_MAX_COUNT,
    SETUP_SESSION_MAX_ACTIVE,
    SETUP_SESSION_MAX_RETAINED,
    SETUP_SESSION_RETENTION_SECONDS,
    SETUP_SESSION_TTL_SECONDS,
    WEBAUTHN_CHALLENGE_GLOBAL_LIVE_MAX,
    WEBAUTHN_CHALLENGE_GLOBAL_RATE_MAX,
    WEBAUTHN_CHALLENGE_MAX_RETAINED,
    WEBAUTHN_CHALLENGE_RATE_WINDOW_SECONDS,
    WEBAUTHN_CHALLENGE_TERMINAL_RETENTION_SECONDS,
    WEBAUTHN_CHALLENGE_USER_LIVE_MAX,
    WEBAUTHN_CHALLENGE_USER_RATE_MAX,
    WEBAUTHN_RECOVERY_CREDENTIAL_HISTORY_MAX_BYTES,
    WEBAUTHN_RECOVERY_CREDENTIAL_HISTORY_MAX_COUNT,
    WEBAUTHN_RECOVERY_MAX_LIVE,
    WEBAUTHN_RECOVERY_MAX_RETAINED,
    WEBAUTHN_RECOVERY_TERMINAL_RETENTION_SECONDS,
    WEBAUTHN_RECOVERY_WITNESS_BACKEND,
    WEBAUTHN_RECOVERY_WITNESS_CONNECT_TIMEOUT_SECONDS,
    WEBAUTHN_RECOVERY_WITNESS_FAULT_DOMAIN_ID,
    WEBAUTHN_RECOVERY_WITNESS_PATH,
    WEBAUTHN_RECOVERY_WITNESS_POSTGRES_DSN,
    ensure_data_dirs,
)
from serverware.crypto import (
    BoundSecretKeyring,
    bound_secret_envelope_key_id,
    build_bound_secret_keyring,
    decrypt_bound_secret,
    decrypt_legacy_secret_with_keyring,
    decrypt_secret,
    decrypt_secret_envelope,
    encrypt_bound_secret,
    encrypt_secret,
    encrypt_secret_envelope,
    load_bound_secret_keyring,
    load_master_key,
)

_AUDIT_EVENT_JSON_WRITE_MAX_BYTES = 2 * 1024 * 1024
_AUDIT_EVENT_JSON_STORED_MAX_BYTES = 8 * 1024 * 1024
_AUDIT_VERIFY_BATCH_TARGET_BYTES = 64 * 1024 * 1024
_AUDIT_VERIFY_BATCH_SIZE = 32
_METADATA_AUDIT_OUTBOX_MAX_PENDING = 100_000
_METADATA_AUDIT_OUTBOX_CLAIM_TTL_SECONDS = 60


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso_now() -> str:
    return utcnow().isoformat()


def _metadata_utcnow(conn: Any) -> datetime:
    if isinstance(conn, PostgresMetadataConnection):
        value = conn.execute("SELECT clock_timestamp() AS now").fetchone()["now"]
    else:
        value = conn.execute(
            "SELECT strftime('%Y-%m-%dT%H:%M:%f+00:00', 'now') AS now"
        ).fetchone()["now"]
    if isinstance(value, str):
        value = datetime.fromisoformat(value)
    if not isinstance(value, datetime):
        raise MetadataStoreError("metadata database clock returned an invalid value")
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def dumps(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), sort_keys=True)


def loads(value: str | None, fallback: Any) -> Any:
    if not value:
        return fallback
    return json.loads(value)


def _approval_json_digest(payload_json: str) -> str:
    return hashlib.sha256(payload_json.encode("utf-8")).hexdigest()


def _encrypt_approval_json(payload_json: str) -> str:
    return (
        "v2:"
        + _approval_json_digest(payload_json)
        + ":"
        + encrypt_secret(payload_json)
    )


def _decrypt_approval_json(stored: str) -> str:
    if stored.startswith("v2:"):
        try:
            _, expected_digest, encrypted = stored.split(":", 2)
        except ValueError as exc:
            raise ValueError("malformed encrypted approval review payload") from exc
        payload_json = decrypt_secret(encrypted)
        if not hmac.compare_digest(
            expected_digest, _approval_json_digest(payload_json)
        ):
            raise ValueError("approval review payload digest mismatch")
        return payload_json
    if stored.startswith("v1:"):
        return decrypt_secret(stored)
    return stored


def _stored_approval_json_digest(stored: str) -> str:
    if stored.startswith("v2:"):
        try:
            _, digest, _ = stored.split(":", 2)
        except ValueError as exc:
            raise ValueError("malformed encrypted approval review payload") from exc
        if re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            raise ValueError("approval review payload digest is invalid")
        return digest
    return _approval_json_digest(_decrypt_approval_json(stored))


def _approval_url_commitment(url: str) -> str:
    return "sha256:" + hashlib.sha256(url.encode("utf-8")).hexdigest()


def _operation_digest(operation: str | None) -> str | None:
    if operation is None:
        return None
    return "sha256:" + hashlib.sha256(operation.encode("utf-8")).hexdigest()


def _operation_commitment(operation: str) -> dict[str, Any]:
    return {
        "type": "serverware.operation_commitment",
        "version": 1,
        "algorithm": "sha256",
        "digest": _operation_digest(operation),
    }


def _is_typed_operation_commitment(operation: Any) -> bool:
    return (
        isinstance(operation, dict)
        and set(operation) == {"type", "version", "algorithm", "digest"}
        and operation.get("type") == "serverware.operation_commitment"
        and operation.get("version") == 1
        and operation.get("algorithm") == "sha256"
        and isinstance(operation.get("digest"), str)
        and re.fullmatch(r"sha256:[0-9a-f]{64}", operation["digest"]) is not None
    )


def _audit_event_for_storage(
    event_type: str, event: dict[str, Any]
) -> dict[str, Any]:
    if event_type not in _RATE_LIMIT_AUDIT_EVENT_TYPES:
        return event
    operation = event.get("operation")
    if operation is None:
        return event
    if _is_typed_operation_commitment(operation):
        return event
    if not isinstance(operation, str):
        raise AuditStoreError(
            "rate-limit audit operation must be a string, typed commitment, or null"
        )
    stored = dict(event)
    stored["operation"] = _operation_commitment(operation)
    return stored


def _operation_storage_binding(
    *,
    table_kind: str,
    counter_key: str,
    attempt_id: str | None,
    storage_version: int,
    operation_digest: str,
) -> dict[str, Any]:
    return {
        "table_kind": table_kind,
        "counter_key": counter_key,
        "attempt_id": attempt_id,
        "storage_version": storage_version,
        "operation_commitment": operation_digest,
    }


def _encrypt_operation(
    operation: str | None,
    *,
    table_kind: str,
    counter_key: str,
    attempt_id: str | None,
    keyring: BoundSecretKeyring,
) -> str | None:
    if operation is None:
        return None
    digest = _operation_digest(operation)
    assert digest is not None
    return encrypt_bound_secret(
        operation,
        purpose="rate-quota-operation-recovery",
        binding=_operation_storage_binding(
            table_kind=table_kind,
            counter_key=counter_key,
            attempt_id=attempt_id,
            storage_version=_OPERATION_STORAGE_VERSION,
            operation_digest=digest,
        ),
        keyring=keyring,
    )


def _stored_operation(
    row: Any, *, table_kind: str, keyring: BoundSecretKeyring | None
) -> str | None:
    version = row["operation_storage_version"]
    if version is None:
        if row["encrypted_operation"] is not None:
            raise MetadataStoreError("legacy stored operation has unexpected ciphertext")
        return row["operation"]
    if int(version) != _OPERATION_STORAGE_VERSION:
        raise MetadataStoreError("stored operation has an unsupported storage version")
    digest = row["operation"]
    encrypted = row["encrypted_operation"]
    if digest is None and encrypted is None:
        return None
    if (
        not isinstance(digest, str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None
        or encrypted is None
    ):
        raise MetadataStoreError("stored operation commitment is incomplete")
    if keyring is None:
        raise MetadataStoreError("stored operation encryption key was not preloaded")
    attempt_id = row["attempt_id"] if table_kind == "quota_reservation" else None
    try:
        operation = decrypt_bound_secret(
            str(encrypted),
            purpose="rate-quota-operation-recovery",
            binding=_operation_storage_binding(
                table_kind=table_kind,
                counter_key=str(row["counter_key"]),
                attempt_id=str(attempt_id) if attempt_id is not None else None,
                storage_version=int(version),
                operation_digest=digest,
            ),
            keyring=keyring,
        )
    except Exception as exc:
        raise MetadataStoreError("stored operation recovery value is invalid") from exc
    calculated = _operation_digest(operation)
    if calculated is None or not hmac.compare_digest(digest, calculated):
        raise MetadataStoreError("stored operation commitment does not match recovery value")
    return operation


def _release_operation(row: Any, *, keyring: BoundSecretKeyring) -> str | None:
    return _stored_operation(row, table_kind="quota_reservation", keyring=keyring)


def _audit_hash(
    *,
    event_id: str,
    event_type: str,
    actor_type: str,
    actor_id: str | None,
    event_json: str,
    prev_event_hash: str | None,
    created_at: str,
) -> str:
    payload = dumps(
        {
            "id": event_id,
            "event_type": event_type,
            "actor_type": actor_type,
            "actor_id": actor_id,
            "event_json": event_json,
            "prev_event_hash": prev_event_hash,
            "created_at": created_at,
        }
    )
    return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _validate_audit_event_json(event_json: str) -> None:
    if len(event_json.encode("utf-8")) > _AUDIT_EVENT_JSON_WRITE_MAX_BYTES:
        raise AuditStoreError("canonical audit event exceeds 2 MiB")


def validate_audit_event(event: dict[str, Any]) -> None:
    _validate_audit_event_json(dumps(event))


def _audit_verify_batch_size(max_event_json_bytes: int) -> int:
    if max_event_json_bytes <= 0:
        return _AUDIT_VERIFY_BATCH_SIZE
    return max(
        1,
        min(
            _AUDIT_VERIFY_BATCH_SIZE,
            _AUDIT_VERIFY_BATCH_TARGET_BYTES // max_event_json_bytes,
        ),
    )


class AuditStoreError(RuntimeError):
    pass


class MetadataStoreError(RuntimeError):
    pass


class WebAuthnRecoveryError(MetadataStoreError, ValueError):
    pass


class RecoveryWitnessError(RuntimeError):
    pass


class RateLimitStoreError(RuntimeError):
    pass


class ReleaseAuthorizationError(MetadataStoreError):
    pass


class ReleaseAuthorizationConflictError(ReleaseAuthorizationError):
    pass


class _ReleaseAuthorizationDenied(Exception):
    def __init__(self, result: dict[str, Any]):
        self.result = result
        super().__init__(str(result.get("reason") or "release authorization denied"))


class _OIDCBrowserSessionActivationDenied(Exception):
    def __init__(self, result: dict[str, Any]):
        self.result = result
        super().__init__(str(result.get("reason") or "OIDC session activation denied"))


class RBACBindingStoreError(RuntimeError):
    pass


class ManagedOAuthCredentialError(ValueError):
    pass


class SetupSessionError(MetadataStoreError):
    pass


class SetupSessionNotFoundError(SetupSessionError):
    pass


class SetupSessionCapacityError(SetupSessionError):
    pass


class SetupSessionValidationError(SetupSessionError, ValueError):
    pass


class SetupSessionStaleRevisionError(SetupSessionError):
    def __init__(self, session_id: str, expected_revision: int, current_revision: int):
        self.session_id = session_id
        self.expected_revision = expected_revision
        self.current_revision = current_revision
        super().__init__(
            f"setup session {session_id} revision changed: "
            f"expected {expected_revision}, current {current_revision}"
        )


_RATE_LIMIT_AUDIT_EVENT_TYPES = frozenset(
    {"rate_limit.consumed", "rate_limit.denied"}
)
_AUDIT_STORAGE_REDACTION_MIGRATION = (
    "rate_limit_audit_chain_preserving_bound_preimage_redaction"
)
_METADATA_STORAGE_REDACTION_MIGRATION = (
    "rate_limit_metadata_bound_operation_redaction"
)
_AUDIT_BOUND_KEY_GATE_PREFIX = "audit_bound_secret_active_key:"
_METADATA_BOUND_KEY_GATE_PREFIX = "metadata_bound_secret_active_key:"
_STORAGE_REDACTION_MIGRATION_VERSION = 2
_AUDIT_STORAGE_FORMAT_VERSION = 2
_OPERATION_STORAGE_VERSION = 2
_AUDIT_LOCK_WAIT_MS = max(
    100,
    min(60_000, int(os.getenv("SERVERWARE_AUDIT_LOCK_WAIT_MS", "5000"))),
)
_AUDIT_CHAIN_LOCK_KEY = 0x5357524155444348
_AUDIT_MIGRATION_LOCK_KEY = 0x5357524155444D47
_CREDENTIAL_LEASE_REPLAY_LOCK_KEY = 0x5357524C45415345
_CREDENTIAL_LEASE_REPLAY_RETENTION_MS = 24 * 60 * 60 * 1000
_CREDENTIAL_METADATA_MAX_BYTES = 16 * 1024
_CREDENTIAL_METADATA_MAX_KEYS = 128
_CREDENTIAL_METADATA_MAX_DEPTH = 8
_CREDENTIAL_SECRET_MAX_BYTES = 1024 * 1024
_PENDING_APPROVAL_CREATION_LOCK_KEY = 0x53575250454E4447
_PENDING_OAUTH_CREATION_LOCK_KEY = 0x5357524F41555448
_OIDC_LOGIN_STATE_CREATION_LOCK_KEY = 0x5357524F49444353
_OAUTH_REVOCATION_WORK_LOCK_KEY = 0x5357524F41555257
_POLICY_HIGH_WATER_LOCK_KEY = 0x535752504F4C4943
_SETUP_SESSION_LOCK_KEY = 0x5357525345545550
_WEBAUTHN_AUTHORITY_LOCK_KEY = 0x5357525745415554
_METADATA_MIGRATION_LOCK_KEY = 0x5357524D4554414D
_METADATA_AUDIT_OUTBOX_LOCK_KEY = 0x5357524D4155444F
_PENDING_APPROVAL_MAX_COUNT = 10_000
_PENDING_APPROVAL_MAX_PAYLOAD_BYTES = 64 * 1024
_APPROVAL_REVIEW_RECEIPT_MAX_COUNT = 10_000
_OIDC_LOGIN_GLOBAL_PENDING_MAX = 2_000
_OIDC_LOGIN_SOURCE_PENDING_MAX = 20
_OIDC_LOGIN_RATE_WINDOW_SECONDS = 60
_OIDC_LOGIN_GLOBAL_RATE_MAX = 600
_OIDC_LOGIN_SOURCE_RATE_MAX = 20
_OIDC_LOGIN_RATE_BUCKET_RETENTION_SECONDS = 180
_OIDC_BROWSER_SESSION_GLOBAL_LIVE_MAX = 10_000
_OIDC_BROWSER_SESSION_USER_LIVE_MAX = 20
_OIDC_BROWSER_SESSION_ROLE_MAX_COUNT = 32
_OIDC_BROWSER_SESSION_ROLE_MAX_BYTES = 128
_OIDC_BROWSER_SESSION_ROLES_JSON_MAX_BYTES = 4 * 1024
_OIDC_BROWSER_SESSION_TTL_MIN_SECONDS = 1
_OIDC_BROWSER_SESSION_TTL_MAX_SECONDS = 24 * 60 * 60
_OIDC_BROWSER_SESSION_PENDING_TTL_MAX_SECONDS = 15 * 60
_OIDC_BROWSER_SESSION_TERMINAL_RETENTION_SECONDS = 7 * 24 * 60 * 60
_OIDC_BINDING_CHALLENGE_GLOBAL_LIVE_MAX = 10_000
_OIDC_BINDING_CHALLENGE_USER_LIVE_MAX = 4
_OIDC_BINDING_CHALLENGE_USER_RATE_MAX = 30
_OIDC_BINDING_CHALLENGE_RATE_WINDOW_SECONDS = 60
_OIDC_BINDING_CHALLENGE_TERMINAL_RETENTION_SECONDS = 10 * 60
_OAUTH_REVOCATION_BACKLOG_MAX_COUNT = max(1_000, OAUTH_PENDING_CREDENTIAL_MAX_COUNT * 4)
_OAUTH_REVOCATION_LEASE_SECONDS = 60
_OAUTH_REVOCATION_HELD_SECONDS = 10 * 60
_OAUTH_REVOCATION_RESERVED_SECONDS = 60 * 60
_oidc_login_source_context: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "serverware_oidc_login_source",
    default=None,
)
_GRANT_ATTEMPT_ID_MAX_BYTES = 256
_RELEASE_AUTHORIZATION_LOCK_WAIT_MS = 500
_RELEASE_AUTHORIZATION_ATTEMPT_ID_MAX_BYTES = 256
_RELEASE_AUTHORIZATION_BINDING_MAX_BYTES = 64 * 1024
_RELEASE_AUTHORIZATION_STATES = {
    "reserved",
    "dispatching",
    "committed",
    "cancelled",
    "committed_indeterminate",
}
_RBAC_BINDINGS_MAX_BYTES = 4 * 1024 * 1024
_VALID_RBAC_ROLES = {
    "admin",
    "approver",
    "auditor",
    "credential_owner",
    "policy_author",
    "policy_publisher",
}
_SENSITIVE_CREDENTIAL_METADATA_KEYS = {
    "access_token",
    "api_secret",
    "api_key",
    "apikey",
    "auth_token",
    "authorization",
    "bearer_token",
    "client_secret",
    "cookie",
    "credential",
    "credentials",
    "id_token",
    "password",
    "passwd",
    "private_key",
    "proxy_authorization",
    "refresh_token",
    "secret",
    "secret_key",
    "session_cookie",
    "session_token",
    "set_cookie",
    "signing_key",
    "token",
}
_SENSITIVE_CREDENTIAL_METADATA_KEYS_COMPACT = {
    "".join(character for character in key if character.isalnum())
    for key in _SENSITIVE_CREDENTIAL_METADATA_KEYS
}
_SENSITIVE_CREDENTIAL_METADATA_SUFFIXES = (
    "apikey",
    "authorization",
    "cookie",
    "credential",
    "credentials",
    "password",
    "passwd",
    "privatekey",
    "secret",
    "signingkey",
    "token",
)

_SETUP_TERMINAL_STATUSES = {"complete", "cancelled", "failed", "superseded", "expired"}
_SETUP_DIGEST_FIELDS = {
    "assignment_digest",
    "attestation_challenge_digest",
    "completion_identity_digest",
    "current_host_identity_digest",
    "enrollment_packet_digest",
    "enrollment_verifier_receipt_digest",
    "final_receipt_digest",
    "hardware_assurance_digest",
    "hardware_verification_receipt_digest",
    "oauth_state_digest",
    "policy_hash",
    "proxy_server_statement_digest",
    "release_identity_digest",
    "route_policy_digest",
    "runtime_evidence_digest",
    "trust_profile_digest",
    "verifier_nonce_hash",
}
_SETUP_TIMESTAMP_FIELDS = {
    "attestation_challenge_issued_at",
    "attestation_challenge_expires_at",
}
_SETUP_BINDING_FIELDS = {
    "assignment_digest",
    "attestation_challenge_digest",
    "attestation_challenge_expires_at",
    "attestation_challenge_issued_at",
    "attestation_challenge_value",
    "canary_id",
    "completion_identity_digest",
    "credential_id",
    "credential_version",
    "current_host_identity_digest",
    "enrollment_packet_digest",
    "enrollment_session_id",
    "enrollment_verifier_key_id",
    "enrollment_verifier_receipt_digest",
    "final_authority_key_id",
    "final_consumption_id",
    "final_receipt_digest",
    "hardware_assurance_digest",
    "hardware_verification_receipt_digest",
    "hardware_verifier_key_id",
    "oauth_pending_credential_id",
    "oauth_provider",
    "oauth_state_digest",
    "policy_hash",
    "principal_id",
    "proxy_server_statement_digest",
    "release_identity_digest",
    "route_id",
    "route_policy_digest",
    "runtime_evidence_digest",
    "template_id",
    "trust_profile_digest",
    "verifier_nonce_hash",
}
_SETUP_UNIQUE_BINDING_FIELDS = {
    "attestation_challenge_digest",
    "canary_id",
    "enrollment_session_id",
    "enrollment_verifier_receipt_digest",
    "final_consumption_id",
    "final_receipt_digest",
    "hardware_assurance_digest",
    "hardware_verification_receipt_digest",
    "oauth_pending_credential_id",
    "oauth_state_digest",
    "runtime_evidence_digest",
}
_SETUP_EVIDENCE_TRANSITIONS = {
    "record_enrollment_evidence": ("enrollment_verification", "ca_installed"),
    "record_canary_evidence": ("canary_result", "canaries_verified"),
    "record_runtime_evidence": ("runtime_verification", "runtime_verified"),
    "record_hardware_receipt": ("hardware_assurance", "hardware_verified"),
    "record_final_challenge_receipt": (
        "final_challenge_receipt",
        "completion_pending_audit",
    ),
}
_SETUP_TRANSITIONS: dict[str, dict[str, Any]] = {
    "claim": {
        "phases": None,
        "next_phase": None,
        "updates": {"current_assignee_id"},
    },
    "handoff": {
        "phases": None,
        "next_phase": None,
        "updates": {"current_assignee_id"},
    },
    "bind_oauth_flow": {
        "phases": {"created", "oauth_started"},
        "next_phase": "oauth_started",
        "updates": {"oauth_provider", "oauth_state_digest"},
    },
    "bind_pending_credential": {
        "phases": {"oauth_started", "oauth_verified"},
        "next_phase": "oauth_verified",
        "updates": {"oauth_pending_credential_id"},
    },
    "bind_credential": {
        "phases": {
            "created",
            "oauth_started",
            "oauth_verified",
            "credential_activated",
        },
        "next_phase": "credential_activated",
        "updates": {
            "assignment_digest",
            "credential_id",
            "credential_version",
            "oauth_provider",
            "principal_id",
            "route_id",
            "route_policy_digest",
            "template_id",
        },
    },
    "bind_candidate": {
        "phases": {"credential_activated", "policy_staged"},
        "next_phase": "policy_staged",
        "updates": {
            "assignment_digest",
            "canary_id",
            "policy_hash",
            "route_policy_digest",
        },
    },
    "activate_policy": {
        "phases": {"policy_staged", "policy_activated"},
        "next_phase": "policy_activated",
        "updates": {"assignment_digest", "policy_hash"},
    },
    "bind_enrollment": {
        "phases": {"policy_activated", "enrollment_issued"},
        "next_phase": "enrollment_issued",
        "updates": {
            "enrollment_packet_digest",
            "enrollment_session_id",
            "verifier_nonce_hash",
        },
    },
    "record_enrollment_evidence": {
        "phases": {"enrollment_issued", "ca_installed"},
        "next_phase": "ca_installed",
        "updates": set(),
    },
    "record_canary_evidence": {
        "phases": {"ca_installed", "canaries_verified"},
        "next_phase": "canaries_verified",
        "updates": set(),
    },
    "record_runtime_evidence": {
        "phases": {"canaries_verified", "runtime_verified"},
        "next_phase": "runtime_verified",
        "updates": set(),
    },
    "bind_attestation_challenge": {
        "phases": {"runtime_verified"},
        "next_phase": "runtime_verified",
        "updates": {
            "attestation_challenge_digest",
            "attestation_challenge_issued_at",
            "attestation_challenge_expires_at",
            "attestation_challenge_value",
        },
    },
    "record_hardware_receipt": {
        "phases": {"runtime_verified", "hardware_verified"},
        "next_phase": "hardware_verified",
        "updates": {
            "current_host_identity_digest",
            "hardware_assurance_digest",
            "hardware_verification_receipt_digest",
            "proxy_server_statement_digest",
            "release_identity_digest",
            "trust_profile_digest",
        },
    },
    "record_final_challenge_receipt": {
        "phases": {"hardware_verified"},
        "next_phase": "completion_pending_audit",
        "updates": {"completion_identity_digest", "final_consumption_id"},
    },
    "system_complete": {
        "phases": {"completion_pending_audit"},
        "next_phase": "complete",
        "updates": set(),
        "status": "complete",
    },
    "cancel": {
        "phases": None,
        "next_phase": "cancelled",
        "updates": set(),
        "status": "cancelled",
    },
    "fail": {
        "phases": None,
        "next_phase": "failed",
        "updates": set(),
        "status": "failed",
    },
    "supersede": {
        "phases": None,
        "next_phase": "superseded",
        "updates": set(),
        "status": "superseded",
    },
}


def audit_store_backend_name() -> str:
    if AUDIT_STORE_BACKEND in {"", "sqlite", "local"}:
        return "sqlite"
    if AUDIT_STORE_BACKEND in {"postgres", "postgresql"}:
        return "postgres"
    raise AuditStoreError(f"unsupported audit store backend: {AUDIT_STORE_BACKEND}")


def audit_uses_postgres() -> bool:
    return audit_store_backend_name() == "postgres"


def recovery_witness_backend_name() -> str:
    if WEBAUTHN_RECOVERY_WITNESS_BACKEND in {"sqlite", "local"}:
        return "sqlite"
    if WEBAUTHN_RECOVERY_WITNESS_BACKEND in {"postgres", "postgresql"}:
        return "postgres"
    raise RecoveryWitnessError(
        "unsupported WebAuthn recovery witness backend: "
        f"{WEBAUTHN_RECOVERY_WITNESS_BACKEND}"
    )


def recovery_witness_uses_postgres() -> bool:
    return recovery_witness_backend_name() == "postgres"


def metadata_store_backend_name() -> str:
    if METADATA_STORE_BACKEND in {"", "sqlite", "local"}:
        return "sqlite"
    if METADATA_STORE_BACKEND in {"postgres", "postgresql"}:
        return "postgres"
    raise MetadataStoreError(
        f"unsupported metadata store backend: {METADATA_STORE_BACKEND}"
    )


def metadata_uses_postgres() -> bool:
    return metadata_store_backend_name() == "postgres"


def get_rbac_role_binding(subject_id: str) -> dict[str, Any] | None:
    """Read one OIDC subject from the control plane's authoritative RBAC ledger."""
    if not subject_id or not subject_id.startswith("oidc:"):
        raise RBACBindingStoreError("RBAC subject ID is invalid")
    try:
        with RBAC_BINDINGS_PATH.open("rb") as handle:
            raw = handle.read(_RBAC_BINDINGS_MAX_BYTES + 1)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise RBACBindingStoreError("RBAC binding state is unreadable") from exc
    if len(raw) > _RBAC_BINDINGS_MAX_BYTES:
        raise RBACBindingStoreError("RBAC binding state exceeds the size limit")
    try:
        state = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RBACBindingStoreError("RBAC binding state is invalid") from exc
    if (
        not isinstance(state, dict)
        or state.get("version") != "serverware.rbacBindings/v1"
        or not isinstance(state.get("subjects"), dict)
    ):
        raise RBACBindingStoreError("RBAC binding state is invalid")
    binding = state["subjects"].get(subject_id)
    if binding is None:
        return None
    if not isinstance(binding, dict) or binding.get("subject_id") != subject_id:
        raise RBACBindingStoreError("RBAC subject binding is invalid")
    binding_status = binding.get("status")
    raw_roles = binding.get("roles")
    if binding_status not in {"active", "deprovisioned"} or not isinstance(
        raw_roles, list
    ):
        raise RBACBindingStoreError("RBAC subject binding is invalid")
    if any(
        not isinstance(role, str) or not role or role != role.strip()
        for role in raw_roles
    ):
        raise RBACBindingStoreError("RBAC subject roles are invalid")
    roles = sorted(set(raw_roles))
    if len(roles) != len(raw_roles) or set(roles) - _VALID_RBAC_ROLES:
        raise RBACBindingStoreError("RBAC subject roles are invalid")
    if (binding_status == "active" and not roles) or (
        binding_status == "deprovisioned" and roles
    ):
        raise RBACBindingStoreError("RBAC subject binding is invalid")
    return {
        "subject_id": subject_id,
        "status": binding_status,
        "roles": roles,
    }


def _audit_psycopg():
    try:
        import psycopg
        from psycopg.rows import dict_row
    except ImportError as exc:
        raise AuditStoreError("postgres audit store requires psycopg[binary]") from exc
    return psycopg, dict_row


def _metadata_psycopg():
    try:
        import psycopg
        from psycopg.rows import dict_row
    except ImportError as exc:
        raise MetadataStoreError(
            "postgres metadata store requires psycopg[binary]"
        ) from exc
    return psycopg, dict_row


def _audit_pg_connect():
    if not AUDIT_STORE_POSTGRES_DSN:
        raise AuditStoreError(
            "SERVERWARE_AUDIT_STORE_POSTGRES_DSN is required for postgres audit store"
        )
    psycopg, dict_row = _audit_psycopg()
    return psycopg.connect(
        AUDIT_STORE_POSTGRES_DSN,
        connect_timeout=AUDIT_STORE_CONNECT_TIMEOUT_SECONDS,
        row_factory=dict_row,
    )


def _postgres_audit_lock_key(conn: Any, purpose: str) -> int:
    with conn.cursor() as cur:
        identity = cur.execute(
            "SELECT current_database() AS database_name, "
            "current_schema() AS schema_name"
        ).fetchone()
    material = dumps(
        {
            "database": str(identity["database_name"]),
            "schema": str(identity["schema_name"]),
            "purpose": purpose,
        }
    ).encode("utf-8")
    return int.from_bytes(hashlib.sha256(material).digest()[:8], "big", signed=True)


def _lock_postgres_audit(conn: Any, purpose: str) -> None:
    legacy_lock_keys = {
        "chain": _AUDIT_CHAIN_LOCK_KEY,
        "migration": _AUDIT_MIGRATION_LOCK_KEY,
    }
    legacy_lock_key = legacy_lock_keys.get(purpose)
    if legacy_lock_key is None:
        raise AuditStoreError("PostgreSQL audit lock purpose is invalid")
    lock_key = _postgres_audit_lock_key(conn, purpose)
    try:
        with conn.cursor() as cur:
            cur.execute(f"SET LOCAL lock_timeout = '{_AUDIT_LOCK_WAIT_MS}ms'")
            # Rolling old writers take this fixed key exclusively. New writers use
            # shared compatibility mode, then serialize per schema on the new key.
            cur.execute(
                "SELECT pg_advisory_xact_lock_shared(%s)",
                (legacy_lock_key,),
            )
            cur.execute("SELECT pg_advisory_xact_lock(%s)", (lock_key,))
    except Exception as exc:
        if getattr(exc, "sqlstate", None) in {"55P03", "57014"}:
            raise AuditStoreError(
                "timed out acquiring compatible legacy/namespaced PostgreSQL "
                f"audit {purpose} locks"
            ) from exc
        raise


def _lock_postgres_audit_migration_tables(conn: Any) -> None:
    try:
        with conn.cursor() as cur:
            cur.execute(f"SET LOCAL lock_timeout = '{_AUDIT_LOCK_WAIT_MS}ms'")
            cur.execute(
                "LOCK TABLE serverware_audit_events IN ACCESS EXCLUSIVE MODE"
            )
    except Exception as exc:
        if getattr(exc, "sqlstate", None) in {"55P03", "57014"}:
            raise AuditStoreError(
                "timed out acquiring PostgreSQL audit migration table lock"
            ) from exc
        raise


def _lock_postgres_metadata_migration_tables(conn: Any) -> None:
    if not isinstance(conn, PostgresMetadataConnection):
        return
    try:
        conn.execute(f"SET LOCAL lock_timeout = '{_AUDIT_LOCK_WAIT_MS}ms'")
        conn.execute(
            "LOCK TABLE metadata_audit_outbox, rate_limit_counters, "
            "release_authorization_quota_reservations "
            "IN ACCESS EXCLUSIVE MODE"
        )
    except Exception as exc:
        if getattr(exc, "sqlstate", None) in {"55P03", "57014"}:
            raise MetadataStoreError(
                "timed out acquiring PostgreSQL metadata migration table locks"
            ) from exc
        raise


def _recovery_witness_pg_connect():
    if not WEBAUTHN_RECOVERY_WITNESS_POSTGRES_DSN:
        raise RecoveryWitnessError(
            "SERVERWARE_WEBAUTHN_RECOVERY_WITNESS_POSTGRES_DSN is required "
            "for the PostgreSQL recovery witness"
        )
    try:
        psycopg, dict_row = _audit_psycopg()
        return psycopg.connect(
            WEBAUTHN_RECOVERY_WITNESS_POSTGRES_DSN,
            connect_timeout=WEBAUTHN_RECOVERY_WITNESS_CONNECT_TIMEOUT_SECONDS,
            row_factory=dict_row,
        )
    except AuditStoreError as exc:
        raise RecoveryWitnessError(str(exc)) from exc
    except Exception as exc:
        raise RecoveryWitnessError("WebAuthn recovery witness is unavailable") from exc


def _recovery_witness_sqlite_connect() -> sqlite3.Connection:
    ensure_data_dirs()
    try:
        if WEBAUTHN_RECOVERY_WITNESS_PATH.resolve() == DB_PATH.resolve():
            raise RecoveryWitnessError(
                "WebAuthn recovery witness must not reuse the metadata database file"
            )
        WEBAUTHN_RECOVERY_WITNESS_PATH.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(WEBAUTHN_RECOVERY_WITNESS_PATH, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=FULL")
        return conn
    except RecoveryWitnessError:
        raise
    except OSError as exc:
        raise RecoveryWitnessError(
            "WebAuthn recovery witness file is unavailable"
        ) from exc


def _metadata_pg_connect_raw():
    if not METADATA_STORE_POSTGRES_DSN:
        raise MetadataStoreError(
            "SERVERWARE_METADATA_STORE_POSTGRES_DSN is required for postgres metadata store"
        )
    psycopg, dict_row = _metadata_psycopg()
    return psycopg.connect(
        METADATA_STORE_POSTGRES_DSN,
        connect_timeout=METADATA_STORE_CONNECT_TIMEOUT_SECONDS,
        row_factory=dict_row,
    )


def init_recovery_witness_store() -> None:
    if recovery_witness_uses_postgres():
        with _recovery_witness_pg_connect() as conn:
            with conn.transaction():
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        CREATE TABLE IF NOT EXISTS
                            serverware_recovery_authorization_claims (
                                authorization_digest TEXT PRIMARY KEY,
                                signature_digest TEXT NOT NULL UNIQUE,
                                statement_digest TEXT NOT NULL UNIQUE,
                                recovery_id TEXT NOT NULL UNIQUE,
                                ceremony_type TEXT NOT NULL,
                                user_id TEXT NOT NULL,
                                root_key_id TEXT NOT NULL,
                                root_sequence BIGINT NOT NULL,
                                claimed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
                                CHECK (root_sequence > 0),
                                CHECK (
                                    ceremony_type IN (
                                        'replacement-registration',
                                        'lost-active-key-decommission'
                                    )
                                )
                            );
                        CREATE TABLE IF NOT EXISTS
                            serverware_recovery_witness_heads (
                                root_key_id TEXT NOT NULL,
                                user_id TEXT NOT NULL,
                                last_sequence BIGINT NOT NULL,
                                updated_at TIMESTAMPTZ NOT NULL
                                    DEFAULT clock_timestamp(),
                                PRIMARY KEY (root_key_id, user_id),
                                CHECK (last_sequence > 0)
                            );
                        CREATE INDEX IF NOT EXISTS
                            serverware_recovery_claims_user_sequence
                            ON serverware_recovery_authorization_claims
                                (root_key_id, user_id, root_sequence);
                        """
                    )
        return
    with _recovery_witness_sqlite_connect() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS recovery_authorization_claims (
                authorization_digest TEXT PRIMARY KEY,
                signature_digest TEXT NOT NULL UNIQUE,
                statement_digest TEXT NOT NULL UNIQUE,
                recovery_id TEXT NOT NULL UNIQUE,
                ceremony_type TEXT NOT NULL,
                user_id TEXT NOT NULL,
                root_key_id TEXT NOT NULL,
                root_sequence INTEGER NOT NULL,
                claimed_at TEXT NOT NULL,
                CHECK (root_sequence > 0),
                CHECK (
                    ceremony_type IN (
                        'replacement-registration',
                        'lost-active-key-decommission'
                    )
                )
            );
            CREATE TABLE IF NOT EXISTS recovery_witness_heads (
                root_key_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                last_sequence INTEGER NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (root_key_id, user_id),
                CHECK (last_sequence > 0)
            );
            CREATE INDEX IF NOT EXISTS recovery_claims_user_sequence
                ON recovery_authorization_claims
                    (root_key_id, user_id, root_sequence);
            """
        )


def claim_webauthn_recovery_authorization(
    *,
    authorization_digest: str,
    signature_digest: str,
    statement_digest: str,
    recovery_id: str,
    ceremony_type: str,
    user_id: str,
    root_key_id: str,
    root_sequence: int,
) -> dict[str, Any]:
    for label, value in (
        ("authorization digest", authorization_digest),
        ("signature digest", signature_digest),
        ("statement digest", statement_digest),
        ("root key ID", root_key_id),
    ):
        if not isinstance(value, str) or re.fullmatch(
            r"sha256:[0-9a-f]{64}", value
        ) is None:
            raise RecoveryWitnessError(f"recovery witness {label} is invalid")
    if ceremony_type not in {
        "replacement-registration",
        "lost-active-key-decommission",
    }:
        raise RecoveryWitnessError("recovery witness ceremony type is invalid")
    if not isinstance(recovery_id, str) or not 1 <= len(recovery_id) <= 128:
        raise RecoveryWitnessError("recovery witness ceremony ID is invalid")
    if not isinstance(user_id, str) or not 1 <= len(user_id.encode("utf-8")) <= 512:
        raise RecoveryWitnessError("recovery witness user ID is invalid")
    if isinstance(root_sequence, bool) or not isinstance(root_sequence, int) or root_sequence < 1:
        raise RecoveryWitnessError("recovery witness root sequence is invalid")
    if recovery_witness_uses_postgres():
        try:
            with _recovery_witness_pg_connect() as conn:
                with conn.transaction():
                    head = conn.execute(
                        "SELECT last_sequence FROM serverware_recovery_witness_heads "
                        "WHERE root_key_id = %s AND user_id = %s FOR UPDATE",
                        (root_key_id, user_id),
                    ).fetchone()
                    if head is None:
                        conn.execute(
                            "INSERT INTO serverware_recovery_witness_heads "
                            "(root_key_id, user_id, last_sequence) VALUES (%s, %s, %s)",
                            (root_key_id, user_id, root_sequence),
                        )
                    elif int(head["last_sequence"]) + 1 != root_sequence:
                        raise RecoveryWitnessError(
                            "recovery witness root sequence is stale or non-monotonic"
                        )
                    else:
                        updated = conn.execute(
                            "UPDATE serverware_recovery_witness_heads "
                            "SET last_sequence = %s, updated_at = clock_timestamp() "
                            "WHERE root_key_id = %s AND user_id = %s "
                            "AND last_sequence = %s",
                            (
                                root_sequence,
                                root_key_id,
                                user_id,
                                root_sequence - 1,
                            ),
                        )
                        if updated.rowcount != 1:
                            raise RecoveryWitnessError(
                                "recovery witness root sequence claim raced"
                            )
                    row = conn.execute(
                        """
                        INSERT INTO serverware_recovery_authorization_claims (
                            authorization_digest, signature_digest,
                            statement_digest, recovery_id, ceremony_type,
                            user_id, root_key_id, root_sequence
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                        RETURNING claimed_at
                        """,
                        (
                            authorization_digest,
                            signature_digest,
                            statement_digest,
                            recovery_id,
                            ceremony_type,
                            user_id,
                            root_key_id,
                            root_sequence,
                        ),
                    ).fetchone()
        except Exception as exc:
            if getattr(exc, "sqlstate", None) == "23505":
                raise RecoveryWitnessError(
                    "recovery authorization was already claimed by the independent witness"
                ) from exc
            if isinstance(exc, RecoveryWitnessError):
                raise
            raise RecoveryWitnessError(
                "WebAuthn recovery witness claim failed closed"
            ) from exc
        return {"ok": True, "claimed_at": str(row["claimed_at"])}
    try:
        with _recovery_witness_sqlite_connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            claimed_at = conn.execute(
                "SELECT strftime('%Y-%m-%dT%H:%M:%f+00:00', 'now') AS now"
            ).fetchone()["now"]
            head = conn.execute(
                "SELECT last_sequence FROM recovery_witness_heads "
                "WHERE root_key_id = ? AND user_id = ?",
                (root_key_id, user_id),
            ).fetchone()
            if head is None:
                conn.execute(
                    "INSERT INTO recovery_witness_heads "
                    "(root_key_id, user_id, last_sequence, updated_at) "
                    "VALUES (?, ?, ?, ?)",
                    (root_key_id, user_id, root_sequence, claimed_at),
                )
            elif int(head["last_sequence"]) + 1 != root_sequence:
                raise RecoveryWitnessError(
                    "recovery witness root sequence is stale or non-monotonic"
                )
            else:
                updated = conn.execute(
                    "UPDATE recovery_witness_heads "
                    "SET last_sequence = ?, updated_at = ? "
                    "WHERE root_key_id = ? AND user_id = ? AND last_sequence = ?",
                    (
                        root_sequence,
                        claimed_at,
                        root_key_id,
                        user_id,
                        root_sequence - 1,
                    ),
                )
                if updated.rowcount != 1:
                    raise RecoveryWitnessError(
                        "recovery witness root sequence claim raced"
                    )
            conn.execute(
                """
                INSERT INTO recovery_authorization_claims (
                    authorization_digest, signature_digest, statement_digest,
                    recovery_id, ceremony_type, user_id, root_key_id,
                    root_sequence, claimed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    authorization_digest,
                    signature_digest,
                    statement_digest,
                    recovery_id,
                    ceremony_type,
                    user_id,
                    root_key_id,
                    root_sequence,
                    claimed_at,
                ),
            )
    except sqlite3.IntegrityError as exc:
        raise RecoveryWitnessError(
            "recovery authorization was already claimed by the independent witness"
        ) from exc
    except RecoveryWitnessError:
        raise
    except sqlite3.Error as exc:
        raise RecoveryWitnessError(
            "WebAuthn recovery witness claim failed closed"
        ) from exc
    return {"ok": True, "claimed_at": str(claimed_at)}


def get_webauthn_recovery_witness_sequence(
    *, root_key_id: str, user_id: str
) -> int:
    if recovery_witness_uses_postgres():
        try:
            with _recovery_witness_pg_connect() as conn:
                row = conn.execute(
                    "SELECT last_sequence FROM serverware_recovery_witness_heads "
                    "WHERE root_key_id = %s AND user_id = %s",
                    (root_key_id, user_id),
                ).fetchone()
        except Exception as exc:
            raise RecoveryWitnessError(
                "WebAuthn recovery witness head is unavailable"
            ) from exc
    else:
        try:
            with _recovery_witness_sqlite_connect() as conn:
                row = conn.execute(
                    "SELECT last_sequence FROM recovery_witness_heads "
                    "WHERE root_key_id = ? AND user_id = ?",
                    (root_key_id, user_id),
                ).fetchone()
        except sqlite3.Error as exc:
            raise RecoveryWitnessError(
                "WebAuthn recovery witness head is unavailable"
            ) from exc
    return int(row["last_sequence"]) if row else 0


def _postgres_server_identity(conn: Any) -> tuple[str, int, int]:
    row = conn.execute(
        "SELECT COALESCE(inet_server_addr()::text, '') AS address, "
        "COALESCE(inet_server_port(), 0) AS port, "
        "system_identifier FROM pg_control_system()"
    ).fetchone()
    if row is None:
        raise RecoveryWitnessError("PostgreSQL cluster identity is unavailable")
    address = str(row["address"] or "")
    port = int(row["port"] or 0)
    try:
        system_identifier = int(row["system_identifier"])
    except (KeyError, TypeError, ValueError) as exc:
        raise RecoveryWitnessError(
            "PostgreSQL cluster system_identifier is unavailable"
        ) from exc
    if system_identifier <= 0:
        raise RecoveryWitnessError(
            "PostgreSQL cluster system_identifier is unavailable"
        )
    info = getattr(conn, "info", None)
    if not address and info is not None:
        address = str(getattr(info, "host", "") or "")
    if port == 0 and info is not None:
        port = int(getattr(info, "port", 0) or 0)
    return address, port, system_identifier


def _require_fault_domain_identity(label: str, value: str) -> str:
    if (
        not value
        or len(value) > 256
        or not value.isascii()
        or any(character.isspace() or not character.isprintable() for character in value)
    ):
        raise RecoveryWitnessError(
            f"production {label} fault-domain identity is missing or invalid"
        )
    return value


def require_independent_recovery_witness(*, production: bool) -> None:
    if not production:
        init_recovery_witness_store()
        return
    if not recovery_witness_uses_postgres() or not metadata_uses_postgres():
        raise RecoveryWitnessError(
            "production recovery witness and metadata stores must use PostgreSQL"
        )
    metadata_fault_domain = _require_fault_domain_identity(
        "metadata store", METADATA_STORE_FAULT_DOMAIN_ID
    )
    witness_fault_domain = _require_fault_domain_identity(
        "recovery witness", WEBAUTHN_RECOVERY_WITNESS_FAULT_DOMAIN_ID
    )
    if hmac.compare_digest(metadata_fault_domain, witness_fault_domain):
        raise RecoveryWitnessError(
            "production recovery witness and metadata stores must use different "
            "declared fault domains"
        )
    try:
        with _metadata_pg_connect_raw() as metadata_conn:
            metadata_identity = _postgres_server_identity(metadata_conn)
        with _recovery_witness_pg_connect() as witness_conn:
            witness_identity = _postgres_server_identity(witness_conn)
    except (MetadataStoreError, RecoveryWitnessError):
        raise
    except Exception as exc:
        raise RecoveryWitnessError(
            "production recovery witness separation could not be verified"
        ) from exc
    if metadata_identity[2] == witness_identity[2]:
        raise RecoveryWitnessError(
            "production recovery witness and metadata stores must use different "
            "PostgreSQL clusters"
        )
    if metadata_identity[:2] == witness_identity[:2]:
        raise RecoveryWitnessError(
            "production recovery witness must use a non-colocated PostgreSQL server"
        )
    init_recovery_witness_store()


def _pg_sql(sql: str) -> str:
    return sql.replace("?", "%s")


def _pg_params(params: Any = None) -> Any:
    if params is None:
        return None
    if isinstance(params, list):
        return tuple(params)
    return params


class PostgresMetadataConnection:
    def __init__(self, conn: Any):
        self._conn = conn

    def __enter__(self) -> "PostgresMetadataConnection":
        self._conn.__enter__()
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> bool | None:
        return self._conn.__exit__(exc_type, exc, tb)

    @property
    def in_transaction(self) -> bool:
        return bool(getattr(self._conn.info, "transaction_status", 0))

    @property
    def raw_connection(self) -> Any:
        return self._conn

    def execute(self, sql: str, params: Any = None):
        cur = self._conn.cursor()
        if params is None:
            cur.execute(sql)
        else:
            cur.execute(_pg_sql(sql), _pg_params(params))
        return cur

    def executemany(self, sql: str, params_seq: Any) -> None:
        with self._conn.cursor() as cur:
            cur.executemany(_pg_sql(sql), [_pg_params(params) for params in params_seq])

    def executescript(self, script: str) -> None:
        with self._conn.cursor() as cur:
            cur.execute(script)


def _pending_approval_key(
    *,
    route_id: str,
    method: str,
    url: str,
    principal_id: str | None,
    credential_id: str | None,
    credential_version: int | None,
    policy_hash: str | None,
    request_digest: str | None,
    operation_digest: str | None,
    grant_ttl_seconds: int | None,
    grant_max_uses: int | None,
) -> str:
    material = dumps(
        {
            "credential_id": credential_id,
            "credential_version": credential_version,
            "grant_max_uses": grant_max_uses,
            "grant_ttl_seconds": grant_ttl_seconds,
            "method": method.upper(),
            "operation_digest": operation_digest,
            "policy_hash": policy_hash,
            "principal_id": principal_id,
            "request_digest": request_digest,
            "route_id": route_id,
            "url": url,
        }
    )
    return "sha256:" + hashlib.sha256(material.encode("utf-8")).hexdigest()


def _pending_approval_key_from_row(row: Any) -> str:
    return _pending_approval_key(
        route_id=str(row["route_id"]),
        method=str(row["method"]),
        url=str(row["url"]),
        principal_id=row["principal_id"],
        credential_id=row["credential_id"],
        credential_version=(
            int(row["credential_version"])
            if row["credential_version"] is not None
            else None
        ),
        policy_hash=row["policy_hash"],
        request_digest=row["request_digest"],
        operation_digest=row["operation_digest"],
        grant_ttl_seconds=(
            int(row["grant_ttl_seconds"])
            if row["grant_ttl_seconds"] is not None
            else None
        ),
        grant_max_uses=(
            int(row["grant_max_uses"]) if row["grant_max_uses"] is not None else None
        ),
    )


def _validate_pending_approval_payload(*values: str) -> None:
    payload_bytes = sum(len(value.encode("utf-8")) for value in values)
    if payload_bytes > _PENDING_APPROVAL_MAX_PAYLOAD_BYTES:
        raise MetadataStoreError("pending approval payload exceeds 64 KiB")


def _lock_pending_approval_creation(conn: Any) -> None:
    if isinstance(conn, PostgresMetadataConnection):
        conn.execute(
            "SELECT pg_advisory_xact_lock(?)",
            (_PENDING_APPROVAL_CREATION_LOCK_KEY,),
        )
    elif not conn.in_transaction:
        conn.execute("BEGIN IMMEDIATE")


def _lock_webauthn_authority(conn: Any) -> None:
    if isinstance(conn, PostgresMetadataConnection):
        conn.execute(
            "SELECT pg_advisory_xact_lock(?)",
            (_WEBAUTHN_AUTHORITY_LOCK_KEY,),
        )
    elif not conn.in_transaction:
        conn.execute("BEGIN IMMEDIATE")


def _expire_and_count_pending_approvals(conn: Any, now_s: str) -> int:
    conn.execute(
        "UPDATE approval_requests SET status = 'expired' "
        "WHERE status = 'pending' AND expires_at <= ?",
        (now_s,),
    )
    row = conn.execute(
        "SELECT COUNT(*) AS count FROM approval_requests "
        "WHERE status = 'pending' AND expires_at > ?",
        (now_s,),
    ).fetchone()
    return int(row["count"] if row else 0)


def _backfill_pending_approval_keys(conn: Any) -> None:
    now_s = iso_now()
    conn.execute(
        "UPDATE approval_requests SET status = 'expired' "
        "WHERE status = 'pending' AND expires_at <= ?",
        (now_s,),
    )
    rows = conn.execute(
        "SELECT * FROM approval_requests WHERE status = 'pending' "
        "ORDER BY requested_at ASC, id ASC"
    ).fetchall()
    seen: set[str] = set()
    for row in rows:
        expected_key = _pending_approval_key_from_row(row)
        current_key = row["pending_key"]
        if current_key is not None and current_key != expected_key:
            raise MetadataStoreError(
                f"pending approval has a non-deterministic immutable key: {row['id']}"
            )
        if expected_key in seen:
            conn.execute(
                "UPDATE approval_requests SET status = 'superseded', pending_key = ? "
                "WHERE id = ? AND status = 'pending'",
                (expected_key, row["id"]),
            )
            continue
        seen.add(expected_key)
        if current_key is None:
            conn.execute(
                "UPDATE approval_requests SET pending_key = ? WHERE id = ?",
                (expected_key, row["id"]),
            )


def _legacy_rate_limit_audit_event_json(
    event_type: str, event_json: str
) -> str | None:
    if event_type not in _RATE_LIMIT_AUDIT_EVENT_TYPES:
        return None
    try:
        event = loads(event_json, {})
    except (TypeError, ValueError) as exc:
        raise AuditStoreError(
            "legacy rate-limit audit event is not valid JSON"
        ) from exc
    if not isinstance(event, dict):
        raise AuditStoreError("legacy rate-limit audit event must be an object")
    stored = _audit_event_for_storage(event_type, event)
    if stored is event:
        return None
    return dumps(stored)


def _audit_json_digest(event_json: str) -> str:
    return "sha256:" + hashlib.sha256(event_json.encode("utf-8")).hexdigest()


def _row_value(row: Any, key: str, default: Any = None) -> Any:
    try:
        return row[key]
    except (IndexError, KeyError):
        return default


def _audit_preimage_binding(row: Any) -> dict[str, Any]:
    return {
        "event_id": str(row["id"]),
        "event_hash": str(row["event_hash"]),
        "storage_format_version": _AUDIT_STORAGE_FORMAT_VERSION,
    }


def _canonical_audit_event_json(
    row: Any,
    *,
    keyring: BoundSecretKeyring | None,
    allow_legacy_envelope: bool = False,
) -> str:
    visible_event_json = str(row["event_json"])
    encrypted = _row_value(row, "encrypted_canonical_event_json")
    storage_version = _row_value(row, "storage_format_version")
    if encrypted is None:
        if storage_version is not None and int(storage_version) != _AUDIT_STORAGE_FORMAT_VERSION:
            raise AuditStoreError("audit_storage_format_unsupported")
        if storage_version == _AUDIT_STORAGE_FORMAT_VERSION:
            replacement = _legacy_rate_limit_audit_event_json(
                str(row["event_type"]), visible_event_json
            )
            if replacement is not None:
                raise AuditStoreError("redacted_projection_invalid")
        return visible_event_json
    try:
        if keyring is None:
            raise AuditStoreError("audit preimage encryption key was not preloaded")
        if storage_version == _AUDIT_STORAGE_FORMAT_VERSION:
            canonical_event_json = decrypt_bound_secret(
                str(encrypted),
                purpose="audit-canonical-event-preimage",
                binding=_audit_preimage_binding(row),
                keyring=keyring,
            )
        elif allow_legacy_envelope and storage_version is None:
            canonical_event_json = decrypt_legacy_secret_with_keyring(
                str(encrypted), keyring=keyring
            )
        else:
            raise AuditStoreError("audit_storage_format_unsupported")
    except Exception as exc:
        if isinstance(exc, AuditStoreError):
            raise
        raise AuditStoreError("canonical_preimage_invalid") from exc
    redacted_event_json = _legacy_rate_limit_audit_event_json(
        str(row["event_type"]), canonical_event_json
    )
    if redacted_event_json is None:
        raise AuditStoreError("canonical_preimage_projection_invalid")
    if not hmac.compare_digest(visible_event_json, redacted_event_json):
        raise AuditStoreError("redacted_projection_mismatch")
    return canonical_event_json


def _validated_audit_row_hash(
    row: Any,
    previous_hash: str | None,
    *,
    keyring: BoundSecretKeyring | None,
    allow_legacy_envelope: bool = False,
) -> str:
    visible_event_json = str(row["event_json"])
    canonical_event_json = _canonical_audit_event_json(
        row,
        keyring=keyring,
        allow_legacy_envelope=allow_legacy_envelope,
    )
    if (
        len(visible_event_json.encode("utf-8")) > _AUDIT_EVENT_JSON_STORED_MAX_BYTES
        or len(canonical_event_json.encode("utf-8"))
        > _AUDIT_EVENT_JSON_STORED_MAX_BYTES
        or (
            row["encrypted_canonical_event_json"] is not None
            and len(str(row["encrypted_canonical_event_json"]).encode("utf-8"))
            > _AUDIT_EVENT_JSON_STORED_MAX_BYTES
        )
    ):
        raise AuditStoreError("event_size_exceeded")
    expected_hash = _audit_hash(
        event_id=row["id"],
        event_type=row["event_type"],
        actor_type=row["actor_type"],
        actor_id=row["actor_id"],
        event_json=canonical_event_json,
        prev_event_hash=row["prev_event_hash"],
        created_at=row["created_at"],
    )
    if row["prev_event_hash"] != previous_hash or row["event_hash"] != expected_hash:
        raise AuditStoreError(f"audit chain validation failed at event {row['id']}")
    return str(row["event_hash"])


def _audit_storage_redaction_marker(
    *,
    old_head_event_id: str,
    old_head_event_hash: str,
    old_event_count: int,
    affected_event_count: int,
    manifest_digest: str,
) -> dict[str, str]:
    marker_id = str(uuid.uuid4())
    marker_created_at = iso_now()
    marker_event = {
        "schema": "serverware.auditStorageRedaction/v1",
        "reason": "legacy_rate_limit_operation_plaintext_redaction",
        "old_head_event_id": old_head_event_id,
        "old_head_event_hash": old_head_event_hash,
        "old_event_count": old_event_count,
        "affected_event_count": affected_event_count,
        "manifest_schema": "serverware.auditStorageRedactionManifest/v1",
        "manifest_digest": manifest_digest,
    }
    marker_json = dumps(marker_event)
    _validate_audit_event_json(marker_json)
    marker_hash = _audit_hash(
        event_id=marker_id,
        event_type="audit.storage_redacted",
        actor_type="system",
        actor_id="audit-storage-redaction",
        event_json=marker_json,
        prev_event_hash=old_head_event_hash,
        created_at=marker_created_at,
    )
    return {
        "id": marker_id,
        "event_type": "audit.storage_redacted",
        "actor_type": "system",
        "actor_id": "audit-storage-redaction",
        "event_json": marker_json,
        "prev_event_hash": old_head_event_hash,
        "event_hash": marker_hash,
        "created_at": marker_created_at,
    }


def _store_migration_version(conn: Any, migration: str) -> int:
    row = conn.execute(
        "SELECT version FROM serverware_store_migrations WHERE migration = ?",
        (migration,),
    ).fetchone()
    return int(row["version"]) if row is not None else 0


def _migration_gate_complete(version: int, *, migration: str) -> bool:
    if version == 0:
        return False
    if version > _STORAGE_REDACTION_MIGRATION_VERSION:
        raise RuntimeError(
            f"store migration {migration} has unsupported future version {version}"
        )
    if version != _STORAGE_REDACTION_MIGRATION_VERSION:
        raise RuntimeError(
            f"store migration {migration} has unsupported version {version}"
        )
    return True


def _record_store_migration(conn: Any, migration: str) -> None:
    conn.execute(
        "INSERT INTO serverware_store_migrations (migration, version, applied_at) "
        "VALUES (?, ?, ?) ON CONFLICT (migration) DO NOTHING",
        (migration, _STORAGE_REDACTION_MIGRATION_VERSION, iso_now()),
    )
    version = _store_migration_version(conn, migration)
    if not _migration_gate_complete(version, migration=migration):
        raise RuntimeError(f"store migration {migration} gate was not committed")


def _bound_key_gate_name(prefix: str, keyring: BoundSecretKeyring) -> str:
    return prefix + keyring.active_key_id


def _bound_key_rewrap_required(
    conn: Any, *, prefix: str, keyring: BoundSecretKeyring | None
) -> bool:
    if keyring is None:
        return False
    migration = _bound_key_gate_name(prefix, keyring)
    version = _store_migration_version(conn, migration)
    return not _migration_gate_complete(version, migration=migration)


def _record_bound_key_gate(
    conn: Any, *, prefix: str, keyring: BoundSecretKeyring | None
) -> None:
    if keyring is not None:
        conn.execute(
            "DELETE FROM serverware_store_migrations WHERE migration LIKE ?",
            (prefix + "%",),
        )
        _record_store_migration(conn, _bound_key_gate_name(prefix, keyring))


def _assert_no_sqlite_destructive_audit_rewrite(conn: sqlite3.Connection) -> None:
    evidence = conn.execute(
        "SELECT id FROM audit_events WHERE event_type = 'audit.chain.superseded' LIMIT 1"
    ).fetchone()
    if evidence is not None:
        raise AuditStoreError(
            "destructive audit-chain rewrite evidence detected; restore from a "
            "pre-rewrite backup"
        )


def _validate_sqlite_audit_gate_postconditions(
    conn: sqlite3.Connection, *, keyring: BoundSecretKeyring | None
) -> None:
    trigger_count = int(
        conn.execute(
            "SELECT COUNT(*) AS count FROM sqlite_master WHERE type = 'trigger' "
            "AND name IN ('audit_storage_epoch_insert', 'audit_storage_epoch_update')"
        ).fetchone()["count"]
    )
    if trigger_count != 2:
        raise AuditStoreError("audit storage migration guard triggers are missing")
    incomplete = int(
        conn.execute(
            "SELECT COUNT(*) AS count FROM audit_events WHERE event_type IN (?, ?) "
            "AND storage_format_version IS NOT ?",
            (*tuple(sorted(_RATE_LIMIT_AUDIT_EVENT_TYPES)), _AUDIT_STORAGE_FORMAT_VERSION),
        ).fetchone()["count"]
    )
    if incomplete:
        raise AuditStoreError("audit storage migration postconditions are incomplete")
    for row in conn.execute(
        "SELECT * FROM audit_events WHERE event_type IN (?, ?)",
        tuple(sorted(_RATE_LIMIT_AUDIT_EVENT_TYPES)),
    ).fetchall():
        _canonical_audit_event_json(row, keyring=keyring)


def _active_bound_secret_keyring(
    keyring: BoundSecretKeyring,
) -> BoundSecretKeyring:
    active_key = keyring.keys.get(keyring.active_key_id)
    if active_key is None:
        raise ValueError("bound secret keyring has no active key")
    return build_bound_secret_keyring(active_key)


def _audit_preimage_requires_rewrap(
    encrypted: Any, *, keyring: BoundSecretKeyring
) -> bool:
    try:
        return not hmac.compare_digest(
            bound_secret_envelope_key_id(str(encrypted)),
            keyring.active_key_id,
        )
    except Exception as exc:
        raise AuditStoreError("canonical_preimage_invalid") from exc


def _rewrap_sqlite_audit_preimages(
    conn: sqlite3.Connection, *, keyring: BoundSecretKeyring | None
) -> None:
    rows = conn.execute("SELECT * FROM audit_events ORDER BY rowid ASC").fetchall()
    previous_hash = None
    candidates: list[tuple[str, str, str]] = []
    for row in rows:
        previous_hash = _validated_audit_row_hash(
            row, previous_hash, keyring=keyring
        )
        encrypted = _row_value(row, "encrypted_canonical_event_json")
        if encrypted is None:
            continue
        if keyring is None:
            raise AuditStoreError("audit preimage encryption key was not preloaded")
        canonical_event_json = _canonical_audit_event_json(row, keyring=keyring)
        if _audit_preimage_requires_rewrap(encrypted, keyring=keyring):
            candidates.append(
                (str(row["id"]), str(row["event_hash"]), canonical_event_json)
            )
    if not candidates:
        return
    assert keyring is not None
    active_keyring = _active_bound_secret_keyring(keyring)
    for event_id, event_hash, canonical_event_json in candidates:
        encrypted = encrypt_bound_secret(
            canonical_event_json,
            purpose="audit-canonical-event-preimage",
            binding={
                "event_id": event_id,
                "event_hash": event_hash,
                "storage_format_version": _AUDIT_STORAGE_FORMAT_VERSION,
            },
            keyring=active_keyring,
        )
        updated = conn.execute(
            "UPDATE audit_events SET encrypted_canonical_event_json = ? "
            "WHERE id = ? AND event_hash = ?",
            (encrypted, event_id, event_hash),
        )
        if updated.rowcount != 1:
            raise AuditStoreError("audit preimage rewrap candidate changed")
    previous_hash = None
    for row in conn.execute("SELECT * FROM audit_events ORDER BY rowid ASC").fetchall():
        previous_hash = _validated_audit_row_hash(
            row, previous_hash, keyring=active_keyring
        )


def _remediate_sqlite_audit_operations(
    conn: sqlite3.Connection, *, keyring: BoundSecretKeyring | None
) -> None:
    _assert_no_sqlite_destructive_audit_rewrite(conn)
    if not conn.in_transaction:
        conn.execute("BEGIN IMMEDIATE")
    version = _store_migration_version(conn, _AUDIT_STORAGE_REDACTION_MIGRATION)
    if _migration_gate_complete(version, migration=_AUDIT_STORAGE_REDACTION_MIGRATION):
        if _bound_key_rewrap_required(
            conn, prefix=_AUDIT_BOUND_KEY_GATE_PREFIX, keyring=keyring
        ):
            _rewrap_sqlite_audit_preimages(conn, keyring=keyring)
            _record_bound_key_gate(
                conn, prefix=_AUDIT_BOUND_KEY_GATE_PREFIX, keyring=keyring
            )
        _validate_sqlite_audit_gate_postconditions(conn, keyring=keyring)
        return
    _assert_no_sqlite_destructive_audit_rewrite(conn)
    version = _store_migration_version(conn, _AUDIT_STORAGE_REDACTION_MIGRATION)
    if _migration_gate_complete(version, migration=_AUDIT_STORAGE_REDACTION_MIGRATION):
        if _bound_key_rewrap_required(
            conn, prefix=_AUDIT_BOUND_KEY_GATE_PREFIX, keyring=keyring
        ):
            _rewrap_sqlite_audit_preimages(conn, keyring=keyring)
            _record_bound_key_gate(
                conn, prefix=_AUDIT_BOUND_KEY_GATE_PREFIX, keyring=keyring
            )
        _validate_sqlite_audit_gate_postconditions(conn, keyring=keyring)
        return
    max_event_json_bytes = int(
        conn.execute(
            "SELECT COALESCE(MAX(CASE WHEN visible_bytes >= encrypted_bytes "
            "THEN visible_bytes ELSE encrypted_bytes END), 0) AS max_bytes FROM ("
            "SELECT length(CAST(event_json AS BLOB)) AS visible_bytes, "
            "COALESCE(length(CAST(encrypted_canonical_event_json AS BLOB)), 0) "
            "AS encrypted_bytes FROM audit_events) AS audit_sizes"
        ).fetchone()["max_bytes"]
    )
    batch_size = _audit_verify_batch_size(max_event_json_bytes)
    candidates: list[dict[str, str]] = []
    format_updates: list[str] = []
    previous_hash = None
    old_event_count = 0
    old_head_event_id = None
    validation = conn.execute("SELECT * FROM audit_events ORDER BY rowid ASC")
    while rows := validation.fetchmany(batch_size):
        for row in rows:
            previous_hash = _validated_audit_row_hash(
                row,
                previous_hash,
                keyring=keyring,
                allow_legacy_envelope=True,
            )
            old_event_count += 1
            old_head_event_id = str(row["id"])
            if str(row["event_type"]) not in _RATE_LIMIT_AUDIT_EVENT_TYPES:
                continue
            storage_version = _row_value(row, "storage_format_version")
            if storage_version == _AUDIT_STORAGE_FORMAT_VERSION:
                continue
            original_event_json = _canonical_audit_event_json(
                row,
                keyring=keyring,
                allow_legacy_envelope=True,
            )
            redacted_event_json = _legacy_rate_limit_audit_event_json(
                str(row["event_type"]), original_event_json
            )
            if redacted_event_json is not None:
                candidates.append(
                    {
                        "id": str(row["id"]),
                        "event_hash": str(row["event_hash"]),
                        "original_event_json_digest": _audit_json_digest(
                            original_event_json
                        ),
                        "redacted_event_json_digest": _audit_json_digest(
                            redacted_event_json
                        ),
                    }
                )
            elif row["encrypted_canonical_event_json"] is not None:
                raise AuditStoreError("canonical_preimage_projection_invalid")
            else:
                format_updates.append(str(row["id"]))
    if candidates and (old_head_event_id is None or previous_hash is None):
        raise AuditStoreError("audit storage redaction found no chain head")

    manifest_digest = _audit_json_digest(dumps(candidates))
    for candidate in candidates:
        row = conn.execute(
            "SELECT * FROM audit_events WHERE id = ?", (candidate["id"],)
        ).fetchone()
        if row is None or _row_value(row, "storage_format_version") is not None:
            raise AuditStoreError("audit storage redaction candidate changed")
        if keyring is None:
            raise AuditStoreError("audit preimage encryption key was not preloaded")
        original_event_json = _canonical_audit_event_json(
            row,
            keyring=keyring,
            allow_legacy_envelope=True,
        )
        redacted_event_json = _legacy_rate_limit_audit_event_json(
            str(row["event_type"]), original_event_json
        )
        if (
            redacted_event_json is None
            or str(row["event_hash"]) != candidate["event_hash"]
            or _audit_json_digest(original_event_json)
            != candidate["original_event_json_digest"]
            or _audit_json_digest(redacted_event_json)
            != candidate["redacted_event_json_digest"]
        ):
            raise AuditStoreError("audit storage redaction candidate changed")
        encrypted_preimage = encrypt_bound_secret(
            original_event_json,
            purpose="audit-canonical-event-preimage",
            binding={
                "event_id": candidate["id"],
                "event_hash": candidate["event_hash"],
                "storage_format_version": _AUDIT_STORAGE_FORMAT_VERSION,
            },
            keyring=keyring,
        )
        if len(encrypted_preimage.encode("utf-8")) > _AUDIT_EVENT_JSON_STORED_MAX_BYTES:
            raise AuditStoreError("event_size_exceeded")
        updated = conn.execute(
            "UPDATE audit_events SET event_json = ?, "
            "encrypted_canonical_event_json = ?, storage_format_version = ? "
            "WHERE id = ? AND event_hash = ? AND storage_format_version IS NULL",
            (
                redacted_event_json,
                encrypted_preimage,
                _AUDIT_STORAGE_FORMAT_VERSION,
                candidate["id"],
                candidate["event_hash"],
            ),
        )
        if updated.rowcount != 1:
            raise AuditStoreError("audit storage redaction candidate changed")

    for event_id in format_updates:
        updated = conn.execute(
            "UPDATE audit_events SET storage_format_version = ? WHERE id = ? "
            "AND storage_format_version IS NULL",
            (_AUDIT_STORAGE_FORMAT_VERSION, event_id),
        )
        if updated.rowcount != 1:
            raise AuditStoreError("audit storage format candidate changed")
    if candidates:
        assert old_head_event_id is not None and previous_hash is not None
        marker = _audit_storage_redaction_marker(
            old_head_event_id=old_head_event_id,
            old_head_event_hash=previous_hash,
            old_event_count=old_event_count,
            affected_event_count=len(candidates),
            manifest_digest=manifest_digest,
        )
        conn.execute(
            "INSERT INTO audit_events (id, event_type, actor_type, actor_id, "
            "event_json, storage_format_version, prev_event_hash, event_hash, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                marker["id"], marker["event_type"], marker["actor_type"],
                marker["actor_id"], marker["event_json"],
                _AUDIT_STORAGE_FORMAT_VERSION, marker["prev_event_hash"],
                marker["event_hash"], marker["created_at"],
            ),
        )
    _rewrap_sqlite_audit_preimages(conn, keyring=keyring)
    _validate_sqlite_audit_gate_postconditions(conn, keyring=keyring)
    _record_store_migration(conn, _AUDIT_STORAGE_REDACTION_MIGRATION)
    _record_bound_key_gate(
        conn, prefix=_AUDIT_BOUND_KEY_GATE_PREFIX, keyring=keyring
    )


def _postgres_audit_migration_version(conn: Any) -> int:
    with conn.cursor() as cur:
        row = cur.execute(
            "SELECT version FROM serverware_store_migrations WHERE migration = %s",
            (_AUDIT_STORAGE_REDACTION_MIGRATION,),
        ).fetchone()
    return int(row["version"]) if row is not None else 0


def _postgres_bound_key_rewrap_required(
    conn: Any, *, prefix: str, keyring: BoundSecretKeyring | None
) -> bool:
    if keyring is None:
        return False
    migration = _bound_key_gate_name(prefix, keyring)
    with conn.cursor() as cur:
        row = cur.execute(
            "SELECT version FROM serverware_store_migrations WHERE migration = %s",
            (migration,),
        ).fetchone()
    version = int(row["version"]) if row is not None else 0
    return not _migration_gate_complete(version, migration=migration)


def _record_postgres_bound_key_gate(
    conn: Any, *, prefix: str, keyring: BoundSecretKeyring | None
) -> None:
    if keyring is None:
        return
    migration = _bound_key_gate_name(prefix, keyring)
    with conn.cursor() as cur:
        cur.execute(
            "DELETE FROM serverware_store_migrations WHERE migration LIKE %s",
            (prefix + "%",),
        )
        cur.execute(
            "INSERT INTO serverware_store_migrations "
            "(migration, version, applied_at) VALUES (%s, %s, %s) "
            "ON CONFLICT (migration) DO NOTHING",
            (migration, _STORAGE_REDACTION_MIGRATION_VERSION, iso_now()),
        )
        row = cur.execute(
            "SELECT version FROM serverware_store_migrations WHERE migration = %s",
            (migration,),
        ).fetchone()
    version = int(row["version"]) if row is not None else 0
    if not _migration_gate_complete(version, migration=migration):
        raise RuntimeError("audit bound-key gate was not committed")


def _record_postgres_audit_migration(conn: Any) -> None:
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO serverware_store_migrations (migration, version, applied_at) "
            "VALUES (%s, %s, %s) ON CONFLICT (migration) DO NOTHING",
            (
                _AUDIT_STORAGE_REDACTION_MIGRATION,
                _STORAGE_REDACTION_MIGRATION_VERSION,
                iso_now(),
            ),
        )
    version = _postgres_audit_migration_version(conn)
    if not _migration_gate_complete(
        version, migration=_AUDIT_STORAGE_REDACTION_MIGRATION
    ):
        raise RuntimeError("audit storage migration gate was not committed")


def _assert_no_postgres_destructive_audit_rewrite(conn: Any) -> None:
    with conn.cursor() as cur:
        evidence = cur.execute(
            "SELECT id FROM serverware_audit_events "
            "WHERE event_type = 'audit.chain.superseded' LIMIT 1"
        ).fetchone()
    if evidence is not None:
        raise AuditStoreError(
            "destructive audit-chain rewrite evidence detected; restore from a "
            "pre-rewrite backup"
        )


def _validate_postgres_audit_gate_postconditions(
    conn: Any, *, keyring: BoundSecretKeyring | None
) -> None:
    with conn.cursor() as cur:
        count = int(
            cur.execute(
                "SELECT COUNT(*)::bigint AS count FROM pg_trigger AS trigger "
                "JOIN pg_class AS relation ON relation.oid = trigger.tgrelid "
                "JOIN pg_namespace AS namespace "
                "ON namespace.oid = relation.relnamespace "
                "WHERE namespace.nspname = current_schema() "
                "AND relation.relname = 'serverware_audit_events' "
                "AND trigger.tgname = 'serverware_audit_storage_epoch_guard' "
                "AND NOT trigger.tgisinternal"
            ).fetchone()["count"]
        )
    if count != 1:
        raise AuditStoreError("audit storage migration guard trigger is missing")
    with conn.cursor() as cur:
        incomplete = int(
            cur.execute(
                "SELECT COUNT(*)::bigint AS count FROM serverware_audit_events "
                "WHERE event_type IN ('rate_limit.consumed', 'rate_limit.denied') "
                "AND storage_format_version IS DISTINCT FROM %s",
                (_AUDIT_STORAGE_FORMAT_VERSION,),
            ).fetchone()["count"]
        )
    if incomplete:
        raise AuditStoreError("audit storage migration postconditions are incomplete")
    with conn.cursor() as cur:
        rows = cur.execute(
            "SELECT id, event_type, actor_type, actor_id, event_json, "
            "encrypted_canonical_event_json, storage_format_version, prev_event_hash, "
            "event_hash, created_at FROM serverware_audit_events "
            "WHERE event_type IN ('rate_limit.consumed', 'rate_limit.denied')"
        ).fetchall()
    for row in rows:
        _canonical_audit_event_json(row, keyring=keyring)


def _rewrap_postgres_audit_preimages(
    conn: Any, *, keyring: BoundSecretKeyring | None
) -> None:
    with conn.cursor() as cur:
        rows = cur.execute(
            "SELECT id, event_type, actor_type, actor_id, event_json, "
            "encrypted_canonical_event_json, storage_format_version, "
            "prev_event_hash, event_hash, created_at "
            "FROM serverware_audit_events ORDER BY sequence ASC FOR UPDATE"
        ).fetchall()
    previous_hash = None
    candidates: list[tuple[str, str, str]] = []
    for row in rows:
        previous_hash = _validated_audit_row_hash(
            row, previous_hash, keyring=keyring
        )
        encrypted = row["encrypted_canonical_event_json"]
        if encrypted is None:
            continue
        if keyring is None:
            raise AuditStoreError("audit preimage encryption key was not preloaded")
        canonical_event_json = _canonical_audit_event_json(row, keyring=keyring)
        if _audit_preimage_requires_rewrap(encrypted, keyring=keyring):
            candidates.append(
                (str(row["id"]), str(row["event_hash"]), canonical_event_json)
            )
    if not candidates:
        return
    assert keyring is not None
    active_keyring = _active_bound_secret_keyring(keyring)
    with conn.cursor() as cur:
        for event_id, event_hash, canonical_event_json in candidates:
            encrypted = encrypt_bound_secret(
                canonical_event_json,
                purpose="audit-canonical-event-preimage",
                binding={
                    "event_id": event_id,
                    "event_hash": event_hash,
                    "storage_format_version": _AUDIT_STORAGE_FORMAT_VERSION,
                },
                keyring=active_keyring,
            )
            updated = cur.execute(
                "UPDATE serverware_audit_events "
                "SET encrypted_canonical_event_json = %s "
                "WHERE id = %s AND event_hash = %s",
                (encrypted, event_id, event_hash),
            )
            if updated.rowcount != 1:
                raise AuditStoreError("audit preimage rewrap candidate changed")
        rows = cur.execute(
            "SELECT id, event_type, actor_type, actor_id, event_json, "
            "encrypted_canonical_event_json, storage_format_version, "
            "prev_event_hash, event_hash, created_at "
            "FROM serverware_audit_events ORDER BY sequence ASC"
        ).fetchall()
    previous_hash = None
    for row in rows:
        previous_hash = _validated_audit_row_hash(
            row, previous_hash, keyring=active_keyring
        )


def _remediate_postgres_audit_operations(
    conn: Any, *, keyring: BoundSecretKeyring | None
) -> None:
    _assert_no_postgres_destructive_audit_rewrite(conn)
    with conn.cursor() as query:
        max_event_json_bytes = int(
            query.execute(
                "SELECT COALESCE(MAX(GREATEST(octet_length(event_json), "
                "COALESCE(octet_length(encrypted_canonical_event_json), 0))), 0)"
                "::bigint AS max_bytes FROM serverware_audit_events"
            ).fetchone()["max_bytes"]
        )
    batch_size = _audit_verify_batch_size(max_event_json_bytes)
    candidates: list[dict[str, str]] = []
    format_updates: list[str] = []
    previous_hash = None
    old_event_count = 0
    old_head_event_id = None
    with conn.cursor(name="serverware_audit_storage_redaction_validation") as source:
        source.execute(
            "SELECT id, event_type, actor_type, actor_id, event_json, "
            "encrypted_canonical_event_json, storage_format_version, prev_event_hash, "
            "event_hash, created_at "
            "FROM serverware_audit_events ORDER BY sequence ASC FOR UPDATE"
        )
        while rows := source.fetchmany(batch_size):
            for row in rows:
                previous_hash = _validated_audit_row_hash(
                    row,
                    previous_hash,
                    keyring=keyring,
                    allow_legacy_envelope=True,
                )
                old_event_count += 1
                old_head_event_id = str(row["id"])
                if str(row["event_type"]) not in _RATE_LIMIT_AUDIT_EVENT_TYPES:
                    continue
                if row["storage_format_version"] == _AUDIT_STORAGE_FORMAT_VERSION:
                    continue
                original_event_json = _canonical_audit_event_json(
                    row,
                    keyring=keyring,
                    allow_legacy_envelope=True,
                )
                redacted_event_json = _legacy_rate_limit_audit_event_json(
                    str(row["event_type"]), original_event_json
                )
                if redacted_event_json is not None:
                    candidates.append(
                        {
                            "id": str(row["id"]),
                            "event_hash": str(row["event_hash"]),
                            "original_event_json_digest": _audit_json_digest(
                                original_event_json
                            ),
                            "redacted_event_json_digest": _audit_json_digest(
                                redacted_event_json
                            ),
                        }
                    )
                elif row["encrypted_canonical_event_json"] is not None:
                    raise AuditStoreError("canonical_preimage_projection_invalid")
                else:
                    format_updates.append(str(row["id"]))
    if candidates and (old_head_event_id is None or previous_hash is None):
        raise AuditStoreError("audit storage redaction found no chain head")

    manifest_digest = _audit_json_digest(dumps(candidates))
    with conn.cursor() as writer:
        for candidate in candidates:
            row = writer.execute(
                "SELECT id, event_type, event_json, encrypted_canonical_event_json, "
                "storage_format_version, event_hash FROM serverware_audit_events "
                "WHERE id = %s FOR UPDATE",
                (candidate["id"],),
            ).fetchone()
            if row is None or row["storage_format_version"] is not None:
                raise AuditStoreError("audit storage redaction candidate changed")
            if keyring is None:
                raise AuditStoreError("audit preimage encryption key was not preloaded")
            original_event_json = _canonical_audit_event_json(
                row,
                keyring=keyring,
                allow_legacy_envelope=True,
            )
            redacted_event_json = _legacy_rate_limit_audit_event_json(
                str(row["event_type"]), original_event_json
            )
            if (
                redacted_event_json is None
                or str(row["event_hash"]) != candidate["event_hash"]
                or _audit_json_digest(original_event_json)
                != candidate["original_event_json_digest"]
                or _audit_json_digest(redacted_event_json)
                != candidate["redacted_event_json_digest"]
            ):
                raise AuditStoreError("audit storage redaction candidate changed")
            encrypted_preimage = encrypt_bound_secret(
                original_event_json,
                purpose="audit-canonical-event-preimage",
                binding={
                    "event_id": candidate["id"],
                    "event_hash": candidate["event_hash"],
                    "storage_format_version": _AUDIT_STORAGE_FORMAT_VERSION,
                },
                keyring=keyring,
            )
            if len(encrypted_preimage.encode("utf-8")) > _AUDIT_EVENT_JSON_STORED_MAX_BYTES:
                raise AuditStoreError("event_size_exceeded")
            updated = writer.execute(
                "UPDATE serverware_audit_events SET event_json = %s, "
                "encrypted_canonical_event_json = %s, storage_format_version = %s "
                "WHERE id = %s AND event_hash = %s AND storage_format_version IS NULL",
                (
                    redacted_event_json,
                    encrypted_preimage,
                    _AUDIT_STORAGE_FORMAT_VERSION,
                    candidate["id"],
                    candidate["event_hash"],
                ),
            )
            if updated.rowcount != 1:
                raise AuditStoreError("audit storage redaction candidate changed")
        for event_id in format_updates:
            updated = writer.execute(
                "UPDATE serverware_audit_events SET storage_format_version = %s "
                "WHERE id = %s AND storage_format_version IS NULL",
                (_AUDIT_STORAGE_FORMAT_VERSION, event_id),
            )
            if updated.rowcount != 1:
                raise AuditStoreError("audit storage format candidate changed")
        if candidates:
            assert old_head_event_id is not None and previous_hash is not None
            marker = _audit_storage_redaction_marker(
                old_head_event_id=old_head_event_id,
                old_head_event_hash=previous_hash,
                old_event_count=old_event_count,
                affected_event_count=len(candidates),
                manifest_digest=manifest_digest,
            )
            marker["storage_format_version"] = _AUDIT_STORAGE_FORMAT_VERSION
            writer.execute(
                "INSERT INTO serverware_audit_events (id, event_type, actor_type, "
                "actor_id, event_json, storage_format_version, prev_event_hash, "
                "event_hash, created_at) VALUES (%(id)s, %(event_type)s, "
                "%(actor_type)s, %(actor_id)s, %(event_json)s, "
                "%(storage_format_version)s, %(prev_event_hash)s, %(event_hash)s, "
                "%(created_at)s)",
                marker,
            )
    _rewrap_postgres_audit_preimages(conn, keyring=keyring)
    _validate_postgres_audit_gate_postconditions(conn, keyring=keyring)
    _record_postgres_audit_migration(conn)
    _record_postgres_bound_key_gate(
        conn, prefix=_AUDIT_BOUND_KEY_GATE_PREFIX, keyring=keyring
    )


def _install_metadata_storage_epoch_guards(conn: Any) -> None:
    if isinstance(conn, PostgresMetadataConnection):
        conn.executescript(
            f"""
            CREATE OR REPLACE FUNCTION serverware_metadata_storage_epoch_guard()
            RETURNS trigger LANGUAGE plpgsql AS $$
            DECLARE
                payload JSONB;
                committed_operation JSONB;
            BEGIN
                IF EXISTS (
                    SELECT 1 FROM serverware_store_migrations
                    WHERE migration = '{_METADATA_STORAGE_REDACTION_MIGRATION}'
                      AND version = {_STORAGE_REDACTION_MIGRATION_VERSION}
                ) THEN
                    IF TG_TABLE_NAME = 'metadata_audit_outbox' THEN
                        IF NEW.event_type IN ('rate_limit.consumed', 'rate_limit.denied') THEN
                            payload := NEW.event_json::jsonb;
                            committed_operation := payload->'operation';
                            IF NEW.storage_format_version IS DISTINCT FROM
                                   {_AUDIT_STORAGE_FORMAT_VERSION}
                               OR NOT (
                                   committed_operation IS NULL
                                   OR committed_operation = 'null'::jsonb
                                   OR (
                                       jsonb_typeof(committed_operation) = 'object'
                                       AND (SELECT COUNT(*) FROM
                                           jsonb_object_keys(committed_operation)) = 4
                                       AND committed_operation->>'type' =
                                           'serverware.operation_commitment'
                                       AND committed_operation->>'version' = '1'
                                       AND committed_operation->>'algorithm' = 'sha256'
                                       AND committed_operation->>'digest' ~
                                           '^sha256:[0-9a-f]{{64}}$'
                                   )
                               ) THEN
                                RAISE EXCEPTION 'legacy metadata audit storage format is disabled';
                            END IF;
                        END IF;
                    ELSIF NEW.operation_storage_version IS DISTINCT FROM
                              {_OPERATION_STORAGE_VERSION}
                          OR NOT (
                              (NEW.operation IS NULL AND NEW.encrypted_operation IS NULL)
                              OR (
                                  NEW.operation ~ '^sha256:[0-9a-f]{{64}}$'
                                  AND NEW.encrypted_operation IS NOT NULL
                              )
                          )
                          OR (
                              TG_OP = 'UPDATE'
                              AND NEW.operation IS DISTINCT FROM OLD.operation
                              AND NEW.encrypted_operation IS NOT DISTINCT FROM
                                  OLD.encrypted_operation
                          ) THEN
                            RAISE EXCEPTION 'legacy operation storage format is disabled';
                    END IF;
                END IF;
                RETURN NEW;
            END;
            $$;
            DROP TRIGGER IF EXISTS serverware_metadata_audit_storage_epoch_guard
                ON metadata_audit_outbox;
            CREATE TRIGGER serverware_metadata_audit_storage_epoch_guard
                BEFORE INSERT OR UPDATE ON metadata_audit_outbox
                FOR EACH ROW EXECUTE FUNCTION serverware_metadata_storage_epoch_guard();
            DROP TRIGGER IF EXISTS serverware_rate_counter_storage_epoch_guard
                ON rate_limit_counters;
            CREATE TRIGGER serverware_rate_counter_storage_epoch_guard
                BEFORE INSERT OR UPDATE ON rate_limit_counters
                FOR EACH ROW EXECUTE FUNCTION serverware_metadata_storage_epoch_guard();
            DROP TRIGGER IF EXISTS serverware_quota_storage_epoch_guard
                ON release_authorization_quota_reservations;
            CREATE TRIGGER serverware_quota_storage_epoch_guard
                BEFORE INSERT OR UPDATE ON release_authorization_quota_reservations
                FOR EACH ROW EXECUTE FUNCTION serverware_metadata_storage_epoch_guard();
            """
        )
        return
    conn.executescript(
        f"""
        CREATE TRIGGER IF NOT EXISTS metadata_audit_storage_epoch_insert
        BEFORE INSERT ON metadata_audit_outbox
        WHEN NEW.event_type IN ('rate_limit.consumed', 'rate_limit.denied')
         AND EXISTS (
             SELECT 1 FROM serverware_store_migrations
             WHERE migration = '{_METADATA_STORAGE_REDACTION_MIGRATION}'
               AND version = {_STORAGE_REDACTION_MIGRATION_VERSION}
         )
         AND (
             NEW.storage_format_version IS NOT {_AUDIT_STORAGE_FORMAT_VERSION}
             OR json_valid(NEW.event_json) = 0
             OR NOT (
                 json_type(NEW.event_json, '$.operation') IS NULL
                 OR json_type(NEW.event_json, '$.operation') = 'null'
                 OR (
                     json_type(NEW.event_json, '$.operation') = 'object'
                     AND (SELECT COUNT(*) FROM json_each(
                         NEW.event_json, '$.operation')) = 4
                     AND json_extract(NEW.event_json, '$.operation.type') =
                         'serverware.operation_commitment'
                     AND json_extract(NEW.event_json, '$.operation.version') = 1
                     AND json_extract(NEW.event_json, '$.operation.algorithm') =
                         'sha256'
                     AND length(json_extract(
                         NEW.event_json, '$.operation.digest')) = 71
                     AND substr(json_extract(
                         NEW.event_json, '$.operation.digest'), 1, 7) = 'sha256:'
                     AND substr(json_extract(
                         NEW.event_json, '$.operation.digest'), 8)
                         NOT GLOB '*[^0-9a-f]*'
                 )
             )
         )
        BEGIN
            SELECT RAISE(ABORT, 'legacy metadata audit storage format is disabled');
        END;
        CREATE TRIGGER IF NOT EXISTS metadata_audit_storage_epoch_update
        BEFORE UPDATE ON metadata_audit_outbox
        WHEN NEW.event_type IN ('rate_limit.consumed', 'rate_limit.denied')
         AND EXISTS (
             SELECT 1 FROM serverware_store_migrations
             WHERE migration = '{_METADATA_STORAGE_REDACTION_MIGRATION}'
               AND version = {_STORAGE_REDACTION_MIGRATION_VERSION}
         )
         AND (
             NEW.storage_format_version IS NOT {_AUDIT_STORAGE_FORMAT_VERSION}
             OR json_valid(NEW.event_json) = 0
             OR NOT (
                 json_type(NEW.event_json, '$.operation') IS NULL
                 OR json_type(NEW.event_json, '$.operation') = 'null'
                 OR (
                     json_type(NEW.event_json, '$.operation') = 'object'
                     AND (SELECT COUNT(*) FROM json_each(
                         NEW.event_json, '$.operation')) = 4
                     AND json_extract(NEW.event_json, '$.operation.type') =
                         'serverware.operation_commitment'
                     AND json_extract(NEW.event_json, '$.operation.version') = 1
                     AND json_extract(NEW.event_json, '$.operation.algorithm') =
                         'sha256'
                     AND length(json_extract(
                         NEW.event_json, '$.operation.digest')) = 71
                     AND substr(json_extract(
                         NEW.event_json, '$.operation.digest'), 1, 7) = 'sha256:'
                     AND substr(json_extract(
                         NEW.event_json, '$.operation.digest'), 8)
                         NOT GLOB '*[^0-9a-f]*'
                 )
             )
         )
        BEGIN
            SELECT RAISE(ABORT, 'legacy metadata audit storage format is disabled');
        END;
        CREATE TRIGGER IF NOT EXISTS rate_counter_storage_epoch_insert
        BEFORE INSERT ON rate_limit_counters
        WHEN EXISTS (
             SELECT 1 FROM serverware_store_migrations
             WHERE migration = '{_METADATA_STORAGE_REDACTION_MIGRATION}'
               AND version = {_STORAGE_REDACTION_MIGRATION_VERSION}
         )
         AND (
             NEW.operation_storage_version IS NOT {_OPERATION_STORAGE_VERSION}
             OR NOT (
                 (NEW.operation IS NULL AND NEW.encrypted_operation IS NULL)
                 OR (
                     length(NEW.operation) = 71
                     AND substr(NEW.operation, 1, 7) = 'sha256:'
                     AND substr(NEW.operation, 8) NOT GLOB '*[^0-9a-f]*'
                     AND NEW.encrypted_operation IS NOT NULL
                 )
             )
         )
        BEGIN
            SELECT RAISE(ABORT, 'legacy operation storage format is disabled');
        END;
        CREATE TRIGGER IF NOT EXISTS rate_counter_storage_epoch_update
        BEFORE UPDATE ON rate_limit_counters
        WHEN EXISTS (
             SELECT 1 FROM serverware_store_migrations
             WHERE migration = '{_METADATA_STORAGE_REDACTION_MIGRATION}'
               AND version = {_STORAGE_REDACTION_MIGRATION_VERSION}
         )
         AND (
             NEW.operation_storage_version IS NOT {_OPERATION_STORAGE_VERSION}
             OR NOT (
                 (NEW.operation IS NULL AND NEW.encrypted_operation IS NULL)
                 OR (
                     length(NEW.operation) = 71
                     AND substr(NEW.operation, 1, 7) = 'sha256:'
                     AND substr(NEW.operation, 8) NOT GLOB '*[^0-9a-f]*'
                     AND NEW.encrypted_operation IS NOT NULL
                 )
             )
             OR (
                 NEW.operation IS NOT OLD.operation
                 AND NEW.encrypted_operation IS OLD.encrypted_operation
             )
         )
        BEGIN
            SELECT RAISE(ABORT, 'legacy operation storage format is disabled');
        END;
        CREATE TRIGGER IF NOT EXISTS quota_storage_epoch_insert
        BEFORE INSERT ON release_authorization_quota_reservations
        WHEN EXISTS (
             SELECT 1 FROM serverware_store_migrations
             WHERE migration = '{_METADATA_STORAGE_REDACTION_MIGRATION}'
               AND version = {_STORAGE_REDACTION_MIGRATION_VERSION}
         )
         AND (
             NEW.operation_storage_version IS NOT {_OPERATION_STORAGE_VERSION}
             OR NOT (
                 (NEW.operation IS NULL AND NEW.encrypted_operation IS NULL)
                 OR (
                     length(NEW.operation) = 71
                     AND substr(NEW.operation, 1, 7) = 'sha256:'
                     AND substr(NEW.operation, 8) NOT GLOB '*[^0-9a-f]*'
                     AND NEW.encrypted_operation IS NOT NULL
                 )
             )
         )
        BEGIN
            SELECT RAISE(ABORT, 'legacy operation storage format is disabled');
        END;
        CREATE TRIGGER IF NOT EXISTS quota_storage_epoch_update
        BEFORE UPDATE ON release_authorization_quota_reservations
        WHEN EXISTS (
             SELECT 1 FROM serverware_store_migrations
             WHERE migration = '{_METADATA_STORAGE_REDACTION_MIGRATION}'
               AND version = {_STORAGE_REDACTION_MIGRATION_VERSION}
         )
         AND (
             NEW.operation_storage_version IS NOT {_OPERATION_STORAGE_VERSION}
             OR NOT (
                 (NEW.operation IS NULL AND NEW.encrypted_operation IS NULL)
                 OR (
                     length(NEW.operation) = 71
                     AND substr(NEW.operation, 1, 7) = 'sha256:'
                     AND substr(NEW.operation, 8) NOT GLOB '*[^0-9a-f]*'
                     AND NEW.encrypted_operation IS NOT NULL
                 )
             )
             OR (
                 NEW.operation IS NOT OLD.operation
                 AND NEW.encrypted_operation IS OLD.encrypted_operation
             )
         )
        BEGIN
            SELECT RAISE(ABORT, 'legacy operation storage format is disabled');
        END;
        """
    )


def _validate_metadata_storage_postconditions(
    conn: Any, *, keyring: BoundSecretKeyring | None
) -> None:
    if isinstance(conn, PostgresMetadataConnection):
        count = int(
            conn.execute(
                "SELECT COUNT(*)::bigint AS count "
                "FROM (VALUES "
                "('metadata_audit_outbox', "
                "'serverware_metadata_audit_storage_epoch_guard'), "
                "('rate_limit_counters', "
                "'serverware_rate_counter_storage_epoch_guard'), "
                "('release_authorization_quota_reservations', "
                "'serverware_quota_storage_epoch_guard')) "
                "AS expected(relation_name, trigger_name) "
                "JOIN pg_namespace AS namespace "
                "ON namespace.nspname = current_schema() "
                "JOIN pg_class AS relation "
                "ON relation.relnamespace = namespace.oid "
                "AND relation.relname = expected.relation_name "
                "JOIN pg_trigger AS trigger "
                "ON trigger.tgrelid = relation.oid "
                "AND trigger.tgname = expected.trigger_name "
                "AND NOT trigger.tgisinternal"
            ).fetchone()["count"]
        )
        expected = 3
    else:
        count = int(
            conn.execute(
                "SELECT COUNT(*) AS count FROM sqlite_master WHERE type = 'trigger' "
                "AND name IN ('metadata_audit_storage_epoch_insert', "
                "'metadata_audit_storage_epoch_update', "
                "'rate_counter_storage_epoch_insert', "
                "'rate_counter_storage_epoch_update', 'quota_storage_epoch_insert', "
                "'quota_storage_epoch_update')"
            ).fetchone()["count"]
        )
        expected = 6
    if count != expected:
        raise MetadataStoreError("metadata storage migration guard triggers are missing")
    for row in conn.execute(
        "SELECT event_type, event_json, storage_format_version "
        "FROM metadata_audit_outbox WHERE event_type IN (?, ?)",
        tuple(sorted(_RATE_LIMIT_AUDIT_EVENT_TYPES)),
    ).fetchall():
        if row["storage_format_version"] != _AUDIT_STORAGE_FORMAT_VERSION:
            raise MetadataStoreError("metadata audit storage migration is incomplete")
        if _legacy_rate_limit_audit_event_json(
            str(row["event_type"]), str(row["event_json"])
        ) is not None:
            raise MetadataStoreError("metadata audit storage projection is invalid")
    for row in conn.execute("SELECT * FROM rate_limit_counters").fetchall():
        _stored_operation(row, table_kind="rate_counter", keyring=keyring)
    for row in conn.execute(
        "SELECT * FROM release_authorization_quota_reservations"
    ).fetchall():
        _stored_operation(row, table_kind="quota_reservation", keyring=keyring)


def _rewrap_metadata_operations(
    conn: Any, *, keyring: BoundSecretKeyring | None
) -> None:
    table_kinds = (
        ("rate_limit_counters", "rate_counter"),
        ("release_authorization_quota_reservations", "quota_reservation"),
    )
    candidates: list[tuple[str, Any, str]] = []
    for table, table_kind in table_kinds:
        for row in conn.execute(f"SELECT * FROM {table}").fetchall():
            operation = _stored_operation(row, table_kind=table_kind, keyring=keyring)
            encrypted = row["encrypted_operation"]
            if encrypted is None:
                continue
            if keyring is None:
                raise MetadataStoreError(
                    "stored operation encryption key was not preloaded"
                )
            try:
                key_id = bound_secret_envelope_key_id(str(encrypted))
            except Exception as exc:
                raise MetadataStoreError(
                    "stored operation recovery value is invalid"
                ) from exc
            if not hmac.compare_digest(key_id, keyring.active_key_id):
                candidates.append((table_kind, row, operation))
    if not candidates:
        return
    assert keyring is not None
    active_keyring = _active_bound_secret_keyring(keyring)
    for table_kind, row, operation in candidates:
        encrypted = _encrypt_operation(
            operation,
            table_kind=table_kind,
            counter_key=str(row["counter_key"]),
            attempt_id=(
                str(row["attempt_id"])
                if table_kind == "quota_reservation"
                else None
            ),
            keyring=active_keyring,
        )
        if table_kind == "rate_counter":
            updated = conn.execute(
                "UPDATE rate_limit_counters SET encrypted_operation = ? "
                "WHERE counter_key = ?",
                (encrypted, row["counter_key"]),
            )
        else:
            updated = conn.execute(
                "UPDATE release_authorization_quota_reservations "
                "SET encrypted_operation = ? WHERE attempt_id = ? AND counter_key = ?",
                (encrypted, row["attempt_id"], row["counter_key"]),
            )
        if updated.rowcount != 1:
            raise MetadataStoreError("stored operation rewrap candidate changed")
    for table, table_kind in table_kinds:
        for row in conn.execute(f"SELECT * FROM {table}").fetchall():
            _stored_operation(row, table_kind=table_kind, keyring=active_keyring)


def _remediate_metadata_rate_limit_storage(
    conn: Any, *, keyring: BoundSecretKeyring | None
) -> None:
    version = _store_migration_version(conn, _METADATA_STORAGE_REDACTION_MIGRATION)
    if _migration_gate_complete(
        version, migration=_METADATA_STORAGE_REDACTION_MIGRATION
    ):
        if _bound_key_rewrap_required(
            conn, prefix=_METADATA_BOUND_KEY_GATE_PREFIX, keyring=keyring
        ):
            _rewrap_metadata_operations(conn, keyring=keyring)
            _record_bound_key_gate(
                conn, prefix=_METADATA_BOUND_KEY_GATE_PREFIX, keyring=keyring
            )
        _validate_metadata_storage_postconditions(conn, keyring=keyring)
        return
    rows = conn.execute(
        "SELECT id, event_type, event_json, storage_format_version "
        "FROM metadata_audit_outbox "
        "WHERE event_type IN (?, ?)",
        tuple(sorted(_RATE_LIMIT_AUDIT_EVENT_TYPES)),
    ).fetchall()
    for row in rows:
        if row["storage_format_version"] == _AUDIT_STORAGE_FORMAT_VERSION:
            if _legacy_rate_limit_audit_event_json(
                str(row["event_type"]), str(row["event_json"])
            ) is not None:
                raise MetadataStoreError("metadata audit storage projection is invalid")
            continue
        if row["storage_format_version"] is not None:
            raise MetadataStoreError("metadata audit storage version is unsupported")
        replacement = _legacy_rate_limit_audit_event_json(
            str(row["event_type"]), str(row["event_json"])
        )
        conn.execute(
            "UPDATE metadata_audit_outbox SET event_json = ?, "
            "storage_format_version = ? WHERE id = ?",
            (
                replacement if replacement is not None else str(row["event_json"]),
                _AUDIT_STORAGE_FORMAT_VERSION,
                row["id"],
            ),
        )
    for row in conn.execute(
        "SELECT * FROM rate_limit_counters"
    ).fetchall():
        if row["operation_storage_version"] == _OPERATION_STORAGE_VERSION:
            _stored_operation(row, table_kind="rate_counter", keyring=keyring)
            continue
        if row["operation_storage_version"] is not None:
            raise MetadataStoreError("rate counter storage version is unsupported")
        operation = str(row["operation"]) if row["operation"] is not None else None
        if operation is not None and keyring is None:
            raise MetadataStoreError("stored operation encryption key was not preloaded")
        conn.execute(
            "UPDATE rate_limit_counters SET operation = ?, encrypted_operation = ?, "
            "operation_storage_version = ? WHERE counter_key = ?",
            (
                _operation_digest(operation),
                _encrypt_operation(
                    operation,
                    table_kind="rate_counter",
                    counter_key=str(row["counter_key"]),
                    attempt_id=None,
                    keyring=keyring,
                ),
                _OPERATION_STORAGE_VERSION,
                row["counter_key"],
            ),
        )
    for row in conn.execute(
        "SELECT * FROM release_authorization_quota_reservations"
    ).fetchall():
        if row["operation_storage_version"] == _OPERATION_STORAGE_VERSION:
            _stored_operation(row, table_kind="quota_reservation", keyring=keyring)
            continue
        if row["operation_storage_version"] is not None:
            raise MetadataStoreError("quota reservation storage version is unsupported")
        operation = str(row["operation"]) if row["operation"] is not None else None
        if operation is not None and keyring is None:
            raise MetadataStoreError("stored operation encryption key was not preloaded")
        conn.execute(
            "UPDATE release_authorization_quota_reservations "
            "SET operation = ?, encrypted_operation = ?, operation_storage_version = ? "
            "WHERE attempt_id = ? AND counter_key = ?",
            (
                _operation_digest(operation),
                _encrypt_operation(
                    operation,
                    table_kind="quota_reservation",
                    counter_key=str(row["counter_key"]),
                    attempt_id=str(row["attempt_id"]),
                    keyring=keyring,
                ),
                _OPERATION_STORAGE_VERSION,
                row["attempt_id"],
                row["counter_key"],
            ),
        )
    _rewrap_metadata_operations(conn, keyring=keyring)
    _validate_metadata_storage_postconditions(conn, keyring=keyring)
    _record_store_migration(conn, _METADATA_STORAGE_REDACTION_MIGRATION)
    _record_bound_key_gate(
        conn, prefix=_METADATA_BOUND_KEY_GATE_PREFIX, keyring=keyring
    )


def _postgres_audit_crypto_required(conn: Any) -> bool:
    with conn.cursor() as cur:
        row = cur.execute(
            "SELECT EXISTS (SELECT 1 FROM serverware_audit_events "
            "WHERE encrypted_canonical_event_json IS NOT NULL OR "
            "(event_type IN ('rate_limit.consumed', 'rate_limit.denied') AND "
            "storage_format_version IS DISTINCT FROM %s) LIMIT 1) AS required",
            (_AUDIT_STORAGE_FORMAT_VERSION,),
        ).fetchone()
    return bool(row["required"])


def _sqlite_storage_crypto_required() -> bool:
    if not DB_PATH.exists():
        return False
    conn = sqlite3.connect(DB_PATH, timeout=10)
    try:
        tables = {
            str(row[0])
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
        if "audit_events" in tables:
            audit_columns = {
                str(row[1])
                for row in conn.execute("PRAGMA table_info(audit_events)").fetchall()
            }
            encrypted_clause = (
                "encrypted_canonical_event_json IS NOT NULL OR "
                if "encrypted_canonical_event_json" in audit_columns
                else ""
            )
            version_clause = (
                "storage_format_version IS NOT ?"
                if "storage_format_version" in audit_columns
                else "1 = 1"
            )
            params: tuple[Any, ...] = (
                (_AUDIT_STORAGE_FORMAT_VERSION,)
                if "storage_format_version" in audit_columns
                else ()
            )
            row = conn.execute(
                "SELECT EXISTS (SELECT 1 FROM audit_events WHERE "
                + encrypted_clause
                + "(event_type IN ('rate_limit.consumed', 'rate_limit.denied') "
                f"AND {version_clause}) LIMIT 1)",
                params,
            ).fetchone()
            if row and bool(row[0]):
                return True
        for table in (
            "rate_limit_counters",
            "release_authorization_quota_reservations",
        ):
            if table not in tables:
                continue
            columns = {
                str(row[1])
                for row in conn.execute(f"PRAGMA table_info({table})").fetchall()
            }
            encrypted_clause = (
                " OR encrypted_operation IS NOT NULL"
                if "encrypted_operation" in columns
                else ""
            )
            row = conn.execute(
                f"SELECT EXISTS (SELECT 1 FROM {table} WHERE operation IS NOT NULL "
                f"{encrypted_clause} LIMIT 1)"
            ).fetchone()
            if row and bool(row[0]):
                return True
        return False
    finally:
        conn.close()


def _postgres_metadata_crypto_required() -> bool:
    if not metadata_uses_postgres():
        return False
    with connect() as conn:
        for table in (
            "rate_limit_counters",
            "release_authorization_quota_reservations",
        ):
            exists = conn.execute(
                "SELECT to_regclass(?) IS NOT NULL AS present", (table,)
            ).fetchone()
            if not exists or not bool(exists["present"]):
                continue
            columns = {
                str(row["column_name"])
                for row in conn.execute(
                    "SELECT column_name FROM information_schema.columns "
                    "WHERE table_schema = current_schema() AND table_name = ?",
                    (table,),
                ).fetchall()
            }
            encrypted_clause = (
                " OR encrypted_operation IS NOT NULL"
                if "encrypted_operation" in columns
                else ""
            )
            row = conn.execute(
                f"SELECT EXISTS (SELECT 1 FROM {table} WHERE operation IS NOT NULL "
                f"{encrypted_clause} LIMIT 1) AS required"
            ).fetchone()
            if row and bool(row["required"]):
                return True
    return False


def init_audit_store() -> None:
    if not audit_uses_postgres():
        return
    # Schema bootstrap must commit before key release can emit its own audit event.
    with _audit_pg_connect() as conn:
        with conn.transaction():
            with conn.cursor() as cur:
                cur.execute(
                    f"""
                    CREATE TABLE IF NOT EXISTS serverware_audit_events (
                        sequence BIGSERIAL PRIMARY KEY,
                        id TEXT NOT NULL UNIQUE,
                        event_type TEXT NOT NULL,
                        actor_type TEXT NOT NULL,
                        actor_id TEXT,
                        event_json TEXT NOT NULL
                            CONSTRAINT serverware_audit_events_event_json_size
                            CHECK (octet_length(event_json) <= 8388608),
                        encrypted_canonical_event_json TEXT,
                        storage_format_version BIGINT,
                        prev_event_hash TEXT,
                        event_hash TEXT NOT NULL UNIQUE,
                        created_at TEXT NOT NULL
                    );
                    ALTER TABLE serverware_audit_events
                        ADD COLUMN IF NOT EXISTS encrypted_canonical_event_json TEXT;
                    ALTER TABLE serverware_audit_events
                        ADD COLUMN IF NOT EXISTS storage_format_version BIGINT;
                    CREATE TABLE IF NOT EXISTS serverware_store_migrations (
                        migration TEXT PRIMARY KEY,
                        version BIGINT NOT NULL,
                        applied_at TEXT NOT NULL
                    );
                    CREATE INDEX IF NOT EXISTS serverware_audit_events_created_at_desc
                        ON serverware_audit_events (created_at DESC, sequence DESC);
                    CREATE INDEX IF NOT EXISTS serverware_audit_events_type_created_at
                        ON serverware_audit_events (event_type, created_at DESC);
                    DO $$
                    BEGIN
                        IF NOT EXISTS (
                            SELECT 1
                            FROM pg_constraint AS constraint_record
                            JOIN pg_class AS relation
                              ON relation.oid = constraint_record.conrelid
                            JOIN pg_namespace AS namespace
                              ON namespace.oid = relation.relnamespace
                            WHERE namespace.nspname = current_schema()
                              AND relation.relname = 'serverware_audit_events'
                              AND constraint_record.conname =
                                  'serverware_audit_events_event_json_size'
                        ) THEN
                            ALTER TABLE serverware_audit_events
                                ADD CONSTRAINT serverware_audit_events_event_json_size
                                CHECK (octet_length(event_json) <= 8388608) NOT VALID;
                        END IF;
                    END $$;
                    CREATE OR REPLACE FUNCTION serverware_audit_storage_epoch_guard()
                    RETURNS trigger LANGUAGE plpgsql AS $$
                    DECLARE
                        payload JSONB;
                        committed_operation JSONB;
                    BEGIN
                        IF NEW.event_type IN ('rate_limit.consumed', 'rate_limit.denied')
                           AND EXISTS (
                               SELECT 1 FROM serverware_store_migrations
                               WHERE migration = '{_AUDIT_STORAGE_REDACTION_MIGRATION}'
                                 AND version = {_STORAGE_REDACTION_MIGRATION_VERSION}
                           ) THEN
                            payload := NEW.event_json::jsonb;
                            committed_operation := payload->'operation';
                            IF NEW.storage_format_version IS DISTINCT FROM
                                   {_AUDIT_STORAGE_FORMAT_VERSION}
                               OR NOT (
                                   committed_operation IS NULL
                                   OR committed_operation = 'null'::jsonb
                                   OR (
                                       jsonb_typeof(committed_operation) = 'object'
                                       AND (SELECT COUNT(*) FROM
                                           jsonb_object_keys(committed_operation)) = 4
                                       AND committed_operation->>'type' =
                                           'serverware.operation_commitment'
                                       AND committed_operation->>'version' = '1'
                                       AND committed_operation->>'algorithm' = 'sha256'
                                       AND committed_operation->>'digest' ~
                                           '^sha256:[0-9a-f]{{64}}$'
                                   )
                               ) THEN
                                RAISE EXCEPTION 'legacy audit storage format is disabled';
                            END IF;
                        END IF;
                        RETURN NEW;
                    END;
                    $$;
                    DROP TRIGGER IF EXISTS serverware_audit_storage_epoch_guard
                        ON serverware_audit_events;
                    CREATE TRIGGER serverware_audit_storage_epoch_guard
                        BEFORE INSERT OR UPDATE ON serverware_audit_events
                        FOR EACH ROW EXECUTE FUNCTION
                            serverware_audit_storage_epoch_guard();
                    """
                )
    with _audit_pg_connect() as conn:
        crypto_required = _postgres_audit_crypto_required(conn)
    keyring = load_bound_secret_keyring() if crypto_required else None
    with _audit_pg_connect() as conn:
        with conn.transaction():
            _lock_postgres_audit(conn, "migration")
            _lock_postgres_audit(conn, "chain")
            _lock_postgres_audit_migration_tables(conn)
            _assert_no_postgres_destructive_audit_rewrite(conn)
            version = _postgres_audit_migration_version(conn)
            if _migration_gate_complete(
                version, migration=_AUDIT_STORAGE_REDACTION_MIGRATION
            ):
                if _postgres_bound_key_rewrap_required(
                    conn,
                    prefix=_AUDIT_BOUND_KEY_GATE_PREFIX,
                    keyring=keyring,
                ):
                    _rewrap_postgres_audit_preimages(conn, keyring=keyring)
                    _record_postgres_bound_key_gate(
                        conn,
                        prefix=_AUDIT_BOUND_KEY_GATE_PREFIX,
                        keyring=keyring,
                    )
                _validate_postgres_audit_gate_postconditions(conn, keyring=keyring)
                return
            _remediate_postgres_audit_operations(conn, keyring=keyring)


def _append_sqlite_audit_event(
    conn: sqlite3.Connection,
    *,
    event_type: str,
    actor_type: str,
    actor_id: str | None,
    event: dict[str, Any],
    idempotency_key: str | None = None,
) -> dict[str, Any]:
    if not conn.in_transaction:
        conn.execute("BEGIN IMMEDIATE")
    event = _audit_event_for_storage(event_type, event)
    event_json = dumps(event)
    _validate_audit_event_json(event_json)
    event_id = idempotency_key or str(uuid.uuid4())
    if idempotency_key is not None:
        existing = conn.execute(
            "SELECT * FROM audit_events WHERE id = ?", (event_id,)
        ).fetchone()
        if existing is not None:
            if (
                existing["event_type"] != event_type
                or existing["actor_type"] != actor_type
                or existing["actor_id"] != actor_id
                or existing["event_json"] != event_json
            ):
                raise AuditStoreError(
                    "audit idempotency key was reused with different event data"
                )
            return {
                "id": existing["id"],
                "event_type": existing["event_type"],
                "actor_type": existing["actor_type"],
                "actor_id": existing["actor_id"],
                "event": loads(existing["event_json"], {}),
                "prev_event_hash": existing["prev_event_hash"],
                "event_hash": existing["event_hash"],
                "created_at": existing["created_at"],
            }
    created_at = iso_now()
    previous = conn.execute(
        "SELECT event_hash FROM audit_events ORDER BY rowid DESC LIMIT 1"
    ).fetchone()
    prev_hash = previous["event_hash"] if previous else None
    event_hash = _audit_hash(
        event_id=event_id,
        event_type=event_type,
        actor_type=actor_type,
        actor_id=actor_id,
        event_json=event_json,
        prev_event_hash=prev_hash,
        created_at=created_at,
    )
    conn.execute(
        """
        INSERT INTO audit_events (
            id, event_type, actor_type, actor_id, event_json,
            storage_format_version, prev_event_hash, event_hash, created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            event_id,
            event_type,
            actor_type,
            actor_id,
            event_json,
            _AUDIT_STORAGE_FORMAT_VERSION,
            prev_hash,
            event_hash,
            created_at,
        ),
    )
    return {
        "id": event_id,
        "event_type": event_type,
        "actor_type": actor_type,
        "actor_id": actor_id,
        "event": event,
        "prev_event_hash": prev_hash,
        "event_hash": event_hash,
        "created_at": created_at,
    }


def _append_postgres_audit_event(
    *,
    event_type: str,
    actor_type: str,
    actor_id: str | None,
    event: dict[str, Any],
    idempotency_key: str | None = None,
) -> dict[str, Any]:
    event_id = idempotency_key or str(uuid.uuid4())
    event = _audit_event_for_storage(event_type, event)
    event_json = dumps(event)
    _validate_audit_event_json(event_json)
    with _audit_pg_connect() as conn:
        with conn.transaction():
            with conn.cursor() as cur:
                _lock_postgres_audit(conn, "chain")
                if idempotency_key is not None:
                    existing = cur.execute(
                        "SELECT * FROM serverware_audit_events WHERE id = %(id)s",
                        {"id": event_id},
                    ).fetchone()
                    if existing is not None:
                        if (
                            existing["event_type"] != event_type
                            or existing["actor_type"] != actor_type
                            or existing["actor_id"] != actor_id
                            or existing["event_json"] != event_json
                        ):
                            raise AuditStoreError(
                                "audit idempotency key was reused with different event data"
                            )
                        return {
                            "id": existing["id"],
                            "event_type": existing["event_type"],
                            "actor_type": existing["actor_type"],
                            "actor_id": existing["actor_id"],
                            "event": loads(existing["event_json"], {}),
                            "prev_event_hash": existing["prev_event_hash"],
                            "event_hash": existing["event_hash"],
                            "created_at": existing["created_at"],
                        }
                previous = cur.execute(
                    "SELECT event_hash FROM serverware_audit_events ORDER BY sequence DESC LIMIT 1"
                ).fetchone()
                prev_hash = previous["event_hash"] if previous else None
                created_at = iso_now()
                event_hash = _audit_hash(
                    event_id=event_id,
                    event_type=event_type,
                    actor_type=actor_type,
                    actor_id=actor_id,
                    event_json=event_json,
                    prev_event_hash=prev_hash,
                    created_at=created_at,
                )
                cur.execute(
                    """
                    INSERT INTO serverware_audit_events (
                        id, event_type, actor_type, actor_id, event_json,
                        storage_format_version, prev_event_hash, event_hash, created_at
                    )
                    VALUES (
                        %(id)s, %(event_type)s, %(actor_type)s, %(actor_id)s, %(event_json)s,
                        %(storage_format_version)s, %(prev_event_hash)s,
                        %(event_hash)s, %(created_at)s
                    )
                    """,
                    {
                        "id": event_id,
                        "event_type": event_type,
                        "actor_type": actor_type,
                        "actor_id": actor_id,
                        "event_json": event_json,
                        "storage_format_version": _AUDIT_STORAGE_FORMAT_VERSION,
                        "prev_event_hash": prev_hash,
                        "event_hash": event_hash,
                        "created_at": created_at,
                    },
                )
    return {
        "id": event_id,
        "event_type": event_type,
        "actor_type": actor_type,
        "actor_id": actor_id,
        "event": event,
        "prev_event_hash": prev_hash,
        "event_hash": event_hash,
        "created_at": created_at,
    }


def append_audit_event(
    conn: Any,
    *,
    event_type: str,
    actor_type: str,
    actor_id: str | None,
    event: dict[str, Any],
    idempotency_key: str | None = None,
) -> dict[str, Any]:
    if idempotency_key is not None and (
        not isinstance(idempotency_key, str) or not 1 <= len(idempotency_key) <= 256
    ):
        raise AuditStoreError("audit idempotency key must contain 1-256 characters")
    event = _audit_event_for_storage(event_type, event)
    if audit_uses_postgres():
        return _stage_metadata_audit_event(
            conn,
            event_type=event_type,
            actor_type=actor_type,
            actor_id=actor_id,
            event=event,
            idempotency_key=idempotency_key,
        )
    return _append_sqlite_audit_event(
        conn,
        event_type=event_type,
        actor_type=actor_type,
        actor_id=actor_id,
        event=event,
        idempotency_key=idempotency_key,
    )


def record_audit_event(
    event_type: str,
    event: dict[str, Any],
    actor_type: str = "admin",
    actor_id: str = "admin",
    *,
    idempotency_key: str | None = None,
) -> dict[str, Any]:
    if idempotency_key is not None and (
        not isinstance(idempotency_key, str) or not 1 <= len(idempotency_key) <= 256
    ):
        raise AuditStoreError("audit idempotency key must contain 1-256 characters")
    if audit_uses_postgres():
        return _append_postgres_audit_event(
            event_type=event_type,
            actor_type=actor_type,
            actor_id=actor_id,
            event=event,
            idempotency_key=idempotency_key,
        )
    with connect() as conn:
        return append_audit_event(
            conn,
            event_type=event_type,
            actor_type=actor_type,
            actor_id=actor_id,
            event=event,
            idempotency_key=idempotency_key,
        )


def record_audit_event_batch(
    events: list[tuple[str, dict[str, Any]]],
    *,
    actor_type: str,
    actor_id: str | None,
) -> list[dict[str, Any]]:
    if not events:
        return []
    if len(events) > 200:
        raise AuditStoreError("audit batch exceeds 200 events")
    prepared: list[tuple[str, dict[str, Any], str, str]] = []
    for event_type, event in events:
        if not isinstance(event_type, str) or not 1 <= len(event_type) <= 128:
            raise AuditStoreError("audit event_type must contain 1-128 characters")
        if not isinstance(event, dict):
            raise AuditStoreError("audit event must be an object")
        event = _audit_event_for_storage(event_type, event)
        event_json = dumps(event)
        _validate_audit_event_json(event_json)
        prepared.append((event_type, event, event_json, str(uuid.uuid4())))

    if not audit_uses_postgres():
        with connect() as conn:
            if not conn.in_transaction:
                conn.execute("BEGIN IMMEDIATE")
            results = []
            for event_type, event, _event_json, event_id in prepared:
                results.append(
                    _append_sqlite_audit_event(
                        conn,
                        event_type=event_type,
                        actor_type=actor_type,
                        actor_id=actor_id,
                        event=event,
                        idempotency_key=event_id,
                    )
                )
            return results

    results: list[dict[str, Any]] = []
    with _audit_pg_connect() as conn:
        with conn.transaction():
            with conn.cursor() as cur:
                _lock_postgres_audit(conn, "chain")
                previous = cur.execute(
                    "SELECT event_hash FROM serverware_audit_events "
                    "ORDER BY sequence DESC LIMIT 1"
                ).fetchone()
                prev_hash = previous["event_hash"] if previous else None
                for event_type, event, event_json, event_id in prepared:
                    created_at = iso_now()
                    event_hash = _audit_hash(
                        event_id=event_id,
                        event_type=event_type,
                        actor_type=actor_type,
                        actor_id=actor_id,
                        event_json=event_json,
                        prev_event_hash=prev_hash,
                        created_at=created_at,
                    )
                    cur.execute(
                        """
                        INSERT INTO serverware_audit_events (
                            id, event_type, actor_type, actor_id, event_json,
                            storage_format_version, prev_event_hash, event_hash, created_at
                        )
                        VALUES (
                            %(id)s, %(event_type)s, %(actor_type)s, %(actor_id)s,
                            %(event_json)s, %(storage_format_version)s,
                            %(prev_event_hash)s, %(event_hash)s, %(created_at)s
                        )
                        """,
                        {
                            "id": event_id,
                            "event_type": event_type,
                            "actor_type": actor_type,
                            "actor_id": actor_id,
                            "event_json": event_json,
                            "storage_format_version": _AUDIT_STORAGE_FORMAT_VERSION,
                            "prev_event_hash": prev_hash,
                            "event_hash": event_hash,
                            "created_at": created_at,
                        },
                    )
                    results.append(
                        {
                            "id": event_id,
                            "event_type": event_type,
                            "actor_type": actor_type,
                            "actor_id": actor_id,
                            "event": event,
                            "prev_event_hash": prev_hash,
                            "event_hash": event_hash,
                            "created_at": created_at,
                        }
                    )
                    prev_hash = event_hash
    return results


def connect() -> Any:
    ensure_data_dirs()
    if metadata_uses_postgres():
        return PostgresMetadataConnection(_metadata_pg_connect_raw())
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def _lock_metadata_audit_outbox(conn: Any) -> None:
    if isinstance(conn, PostgresMetadataConnection):
        conn.execute(
            "SELECT pg_advisory_xact_lock(?)",
            (_METADATA_AUDIT_OUTBOX_LOCK_KEY,),
        )
    elif not conn.in_transaction:
        conn.execute("BEGIN IMMEDIATE")


def _stage_metadata_audit_event(
    conn: Any,
    *,
    event_type: str,
    actor_type: str,
    actor_id: str | None,
    event: dict[str, Any],
    idempotency_key: str | None = None,
) -> dict[str, Any]:
    event_id = idempotency_key or str(uuid.uuid4())
    event = _audit_event_for_storage(event_type, event)
    event_json = dumps(event)
    _validate_audit_event_json(event_json)
    _lock_metadata_audit_outbox(conn)
    existing = conn.execute(
        "SELECT * FROM metadata_audit_outbox WHERE id = ?", (event_id,)
    ).fetchone()
    if existing is not None:
        if (
            existing["event_type"] != event_type
            or existing["actor_type"] != actor_type
            or existing["actor_id"] != actor_id
            or existing["event_json"] != event_json
        ):
            raise AuditStoreError(
                "metadata audit outbox idempotency key was reused with different event data"
            )
        return {
            "id": str(existing["id"]),
            "event_type": str(existing["event_type"]),
            "actor_type": str(existing["actor_type"]),
            "actor_id": existing["actor_id"],
            "event": loads(existing["event_json"], {}),
            "event_hash": existing["audit_event_hash"],
            "created_at": str(existing["created_at"]),
            "outbox_status": str(existing["status"]),
        }
    count = conn.execute(
        "SELECT COUNT(*) AS count FROM metadata_audit_outbox "
        "WHERE status IN ('pending', 'claimed')"
    ).fetchone()
    if int(count["count"] if count else 0) >= _METADATA_AUDIT_OUTBOX_MAX_PENDING:
        raise AuditStoreError("metadata audit outbox is at capacity")
    created_at = _metadata_utcnow(conn).isoformat()
    conn.execute(
        """
        INSERT INTO metadata_audit_outbox (
            id, event_type, actor_type, actor_id, event_json,
            storage_format_version, status, created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, 'pending', ?)
        """,
        (
            event_id,
            event_type,
            actor_type,
            actor_id,
            event_json,
            _AUDIT_STORAGE_FORMAT_VERSION,
            created_at,
        ),
    )
    return {
        "id": event_id,
        "event_type": event_type,
        "actor_type": actor_type,
        "actor_id": actor_id,
        "event": event,
        "event_hash": None,
        "created_at": created_at,
        "outbox_status": "pending",
    }


def claim_metadata_audit_outbox(
    *, worker_id: str, limit: int = 100
) -> list[dict[str, Any]]:
    if not isinstance(worker_id, str) or not 1 <= len(worker_id) <= 128:
        raise AuditStoreError("metadata audit outbox worker ID must contain 1-128 characters")
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 500:
        raise AuditStoreError("metadata audit outbox claim limit must be between 1 and 500")
    claim_id = f"{worker_id}:{uuid.uuid4()}"
    with connect() as conn:
        _lock_metadata_audit_outbox(conn)
        now = _metadata_utcnow(conn)
        now_s = now.isoformat()
        stale_before = (
            now - timedelta(seconds=_METADATA_AUDIT_OUTBOX_CLAIM_TTL_SECONDS)
        ).isoformat()
        conn.execute(
            """
            UPDATE metadata_audit_outbox
            SET status = 'pending', claim_id = NULL, claimed_at = NULL
            WHERE status = 'claimed' AND claimed_at <= ?
            """,
            (stale_before,),
        )
        active_claim = conn.execute(
            "SELECT 1 FROM metadata_audit_outbox WHERE status = 'claimed' LIMIT 1"
        ).fetchone()
        if active_claim is not None:
            return []
        rows = conn.execute(
            """
            SELECT * FROM metadata_audit_outbox
            WHERE status = 'pending'
            ORDER BY created_at ASC, id ASC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        claimed: list[dict[str, Any]] = []
        for row in rows:
            updated = conn.execute(
                """
                UPDATE metadata_audit_outbox
                SET status = 'claimed', claim_id = ?, claimed_at = ?,
                    attempts = attempts + 1, last_error = NULL
                WHERE id = ? AND status = 'pending'
                """,
                (claim_id, now_s, row["id"]),
            )
            if updated.rowcount != 1:
                continue
            item = conn.execute(
                "SELECT * FROM metadata_audit_outbox WHERE id = ?", (row["id"],)
            ).fetchone()
            claimed.append(
                {
                    "id": str(item["id"]),
                    "event_type": str(item["event_type"]),
                    "actor_type": str(item["actor_type"]),
                    "actor_id": item["actor_id"],
                    "event": loads(item["event_json"], {}),
                    "claim_id": str(item["claim_id"]),
                    "attempts": int(item["attempts"] or 0),
                }
            )
    return claimed


def finish_metadata_audit_outbox(
    event_id: str,
    *,
    claim_id: str,
    audit_event_hash: str | None = None,
    error: str | None = None,
) -> bool:
    if (audit_event_hash is None) == (error is None):
        raise AuditStoreError(
            "finish metadata audit outbox requires exactly one of audit_event_hash or error"
        )
    with connect() as conn:
        _lock_metadata_audit_outbox(conn)
        if error is not None:
            result = conn.execute(
                """
                UPDATE metadata_audit_outbox
                SET status = 'pending', claim_id = NULL, claimed_at = NULL,
                    last_error = ?
                WHERE id = ? AND status = 'claimed' AND claim_id = ?
                """,
                (str(error)[:2048], event_id, claim_id),
            )
        else:
            if not isinstance(audit_event_hash, str) or not re.fullmatch(
                r"sha256:[0-9a-f]{64}", audit_event_hash
            ):
                raise AuditStoreError("metadata audit event hash is invalid")
            now_s = _metadata_utcnow(conn).isoformat()
            result = conn.execute(
                """
                UPDATE metadata_audit_outbox
                SET status = 'audited', audited_at = ?, audit_event_hash = ?,
                    claim_id = NULL, claimed_at = NULL, last_error = NULL
                WHERE id = ? AND status = 'claimed' AND claim_id = ?
                """,
                (now_s, audit_event_hash, event_id, claim_id),
            )
    return result.rowcount == 1


def metadata_audit_outbox_status() -> dict[str, int]:
    with connect() as conn:
        rows = conn.execute(
            "SELECT status, COUNT(*) AS count FROM metadata_audit_outbox GROUP BY status"
        ).fetchall()
    counts = {str(row["status"]): int(row["count"]) for row in rows}
    return {
        "pending": counts.get("pending", 0),
        "claimed": counts.get("claimed", 0),
        "audited": counts.get("audited", 0),
    }


def drain_metadata_audit_outbox(limit: int = 100) -> dict[str, int]:
    if not audit_uses_postgres():
        return {"claimed": 0, "audited": 0, "failed": 0, "pending": 0}
    claimed = claim_metadata_audit_outbox(
        worker_id=f"metadata-audit:{os.getpid()}", limit=limit
    )
    audited = 0
    failed = 0
    for item in claimed:
        try:
            result = record_audit_event(
                item["event_type"],
                item["event"],
                actor_type=item["actor_type"],
                actor_id=item["actor_id"],
                idempotency_key=item["id"],
            )
            if not finish_metadata_audit_outbox(
                item["id"],
                claim_id=item["claim_id"],
                audit_event_hash=result["event_hash"],
            ):
                raise AuditStoreError("metadata audit outbox claim was lost")
            audited += 1
        except Exception as exc:
            failed += 1
            try:
                finish_metadata_audit_outbox(
                    item["id"],
                    claim_id=item["claim_id"],
                    error=f"{type(exc).__name__}: {exc}",
                )
            except Exception:
                pass
    status = metadata_audit_outbox_status()
    return {
        "claimed": len(claimed),
        "audited": audited,
        "failed": failed,
        "pending": status["pending"] + status["claimed"],
    }


def drain_metadata_audit_outbox_fully(
    *, limit: int = 500, max_batches: int = 200
) -> dict[str, int]:
    if isinstance(max_batches, bool) or not isinstance(max_batches, int) or max_batches < 1:
        raise AuditStoreError("metadata audit outbox max batches must be positive")
    result = {"claimed": 0, "audited": 0, "failed": 0, "pending": 0}
    for _ in range(max_batches):
        batch = drain_metadata_audit_outbox(limit=limit)
        result["claimed"] += batch["claimed"]
        result["audited"] += batch["audited"]
        result["failed"] += batch["failed"]
        result["pending"] = batch["pending"]
        if result["failed"] > 0 or result["pending"] == 0:
            break
        if batch["claimed"] == 0:
            time.sleep(0.01)
    return result


def _serialize_sqlite_metadata_migration(function):
    @wraps(function)
    def wrapped(*args, **kwargs):
        if metadata_uses_postgres():
            return function(*args, **kwargs)
        lock_path = DB_PATH.with_name(DB_PATH.name + ".migration.lock")
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        with lock_path.open("a+b") as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                return function(*args, **kwargs)
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

    return wrapped


def _bootstrap_sqlite_audit_store() -> None:
    conn = sqlite3.connect(DB_PATH, timeout=10)
    try:
        conn.executescript(
            f"""
            CREATE TABLE IF NOT EXISTS audit_events (
                id TEXT PRIMARY KEY,
                event_type TEXT NOT NULL,
                actor_type TEXT NOT NULL,
                actor_id TEXT,
                event_json TEXT NOT NULL
                    CHECK (length(CAST(event_json AS BLOB)) <= 8388608),
                encrypted_canonical_event_json TEXT,
                storage_format_version INTEGER,
                prev_event_hash TEXT,
                event_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS serverware_store_migrations (
                migration TEXT PRIMARY KEY,
                version BIGINT NOT NULL,
                applied_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS audit_events_type_created_at
                ON audit_events (event_type, created_at);
            """
        )
        columns = {
            str(row[1]) for row in conn.execute("PRAGMA table_info(audit_events)")
        }
        if "encrypted_canonical_event_json" not in columns:
            conn.execute(
                "ALTER TABLE audit_events ADD COLUMN encrypted_canonical_event_json TEXT"
            )
        if "storage_format_version" not in columns:
            conn.execute(
                "ALTER TABLE audit_events ADD COLUMN storage_format_version INTEGER"
            )
        conn.executescript(
            f"""
            CREATE TRIGGER IF NOT EXISTS audit_storage_epoch_insert
            BEFORE INSERT ON audit_events
            WHEN NEW.event_type IN ('rate_limit.consumed', 'rate_limit.denied')
             AND EXISTS (
                 SELECT 1 FROM serverware_store_migrations
                 WHERE migration = '{_AUDIT_STORAGE_REDACTION_MIGRATION}'
                   AND version = {_STORAGE_REDACTION_MIGRATION_VERSION}
             )
             AND (
                 NEW.storage_format_version IS NOT {_AUDIT_STORAGE_FORMAT_VERSION}
                 OR json_valid(NEW.event_json) = 0
                 OR NOT (
                     json_type(NEW.event_json, '$.operation') IS NULL
                     OR json_type(NEW.event_json, '$.operation') = 'null'
                     OR (
                         json_type(NEW.event_json, '$.operation') = 'object'
                         AND (SELECT COUNT(*) FROM json_each(
                             NEW.event_json, '$.operation')) = 4
                         AND json_extract(NEW.event_json, '$.operation.type') =
                             'serverware.operation_commitment'
                         AND json_extract(NEW.event_json, '$.operation.version') = 1
                         AND json_extract(NEW.event_json, '$.operation.algorithm') =
                             'sha256'
                         AND length(json_extract(
                             NEW.event_json, '$.operation.digest')) = 71
                         AND substr(json_extract(
                             NEW.event_json, '$.operation.digest'), 1, 7) = 'sha256:'
                         AND substr(json_extract(
                             NEW.event_json, '$.operation.digest'), 8)
                             NOT GLOB '*[^0-9a-f]*'
                     )
                 )
             )
            BEGIN
                SELECT RAISE(ABORT, 'legacy audit storage format is disabled');
            END;
            CREATE TRIGGER IF NOT EXISTS audit_storage_epoch_update
            BEFORE UPDATE ON audit_events
            WHEN NEW.event_type IN ('rate_limit.consumed', 'rate_limit.denied')
             AND EXISTS (
                 SELECT 1 FROM serverware_store_migrations
                 WHERE migration = '{_AUDIT_STORAGE_REDACTION_MIGRATION}'
                   AND version = {_STORAGE_REDACTION_MIGRATION_VERSION}
             )
             AND (
                 NEW.storage_format_version IS NOT {_AUDIT_STORAGE_FORMAT_VERSION}
                 OR json_valid(NEW.event_json) = 0
                 OR NOT (
                     json_type(NEW.event_json, '$.operation') IS NULL
                     OR json_type(NEW.event_json, '$.operation') = 'null'
                     OR (
                         json_type(NEW.event_json, '$.operation') = 'object'
                         AND (SELECT COUNT(*) FROM json_each(
                             NEW.event_json, '$.operation')) = 4
                         AND json_extract(NEW.event_json, '$.operation.type') =
                             'serverware.operation_commitment'
                         AND json_extract(NEW.event_json, '$.operation.version') = 1
                         AND json_extract(NEW.event_json, '$.operation.algorithm') =
                             'sha256'
                         AND length(json_extract(
                             NEW.event_json, '$.operation.digest')) = 71
                         AND substr(json_extract(
                             NEW.event_json, '$.operation.digest'), 1, 7) = 'sha256:'
                         AND substr(json_extract(
                             NEW.event_json, '$.operation.digest'), 8)
                             NOT GLOB '*[^0-9a-f]*'
                     )
                 )
             )
            BEGIN
                SELECT RAISE(ABORT, 'legacy audit storage format is disabled');
            END;
            """
        )
        conn.commit()
    finally:
        conn.close()


@_serialize_sqlite_metadata_migration
def init_db(path: Path = DB_PATH) -> None:
    ensure_data_dirs()
    grants.init_grant_store()
    init_audit_store()
    if not audit_uses_postgres():
        _bootstrap_sqlite_audit_store()
    crypto_required = False
    if not audit_uses_postgres() or not metadata_uses_postgres():
        crypto_required = _sqlite_storage_crypto_required()
    if metadata_uses_postgres():
        crypto_required = crypto_required or _postgres_metadata_crypto_required()
    keyring = load_bound_secret_keyring() if crypto_required else None
    init_recovery_witness_store()
    with connect() as conn:
        if isinstance(conn, PostgresMetadataConnection):
            conn.execute(
                "SELECT pg_advisory_xact_lock(?)",
                (_METADATA_MIGRATION_LOCK_KEY,),
            )
        if not isinstance(conn, PostgresMetadataConnection):
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_events (
                    id TEXT PRIMARY KEY,
                    event_type TEXT NOT NULL,
                    actor_type TEXT NOT NULL,
                    actor_id TEXT,
                    event_json TEXT NOT NULL
                        CHECK (length(CAST(event_json AS BLOB)) <= 8388608),
                    encrypted_canonical_event_json TEXT,
                    storage_format_version INTEGER,
                    prev_event_hash TEXT,
                    event_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )
            _ensure_column(
                conn, "audit_events", "encrypted_canonical_event_json", "TEXT"
            )
            _ensure_column(conn, "audit_events", "storage_format_version", "INTEGER")
            conn.execute(
                "CREATE TABLE IF NOT EXISTS serverware_store_migrations ("
                "migration TEXT PRIMARY KEY, version BIGINT NOT NULL, "
                "applied_at TEXT NOT NULL)"
            )
            _remediate_sqlite_audit_operations(conn, keyring=keyring)
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS serverware_store_migrations (
                migration TEXT PRIMARY KEY,
                version BIGINT NOT NULL,
                applied_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS credentials (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                kind TEXT NOT NULL,
                encrypted_secret TEXT NOT NULL,
                encrypted_dek TEXT,
                secret_nonce TEXT,
                secret_ciphertext TEXT,
                secret_kek_id TEXT,
                credential_version INTEGER NOT NULL DEFAULT 1,
                secret_updated_at TEXT,
                metadata TEXT NOT NULL DEFAULT '{}',
                lifecycle_status TEXT NOT NULL DEFAULT 'active',
                revocation_error TEXT,
                revocation_requested_at TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS pending_oauth_credentials (
                id TEXT PRIMARY KEY,
                requester_id TEXT NOT NULL,
                name TEXT NOT NULL,
                kind TEXT NOT NULL,
                encrypted_secret TEXT NOT NULL,
                encrypted_dek TEXT NOT NULL,
                secret_nonce TEXT NOT NULL,
                secret_ciphertext TEXT NOT NULL,
                secret_kek_id TEXT NOT NULL,
                credential_version INTEGER NOT NULL,
                secret_updated_at TEXT NOT NULL,
                metadata TEXT NOT NULL,
                payload_digest TEXT NOT NULL,
                review_json TEXT NOT NULL,
                target_credential_id TEXT,
                target_credential_version INTEGER,
                status TEXT NOT NULL DEFAULT 'pending',
                revocation_status TEXT,
                revocation_error TEXT,
                revocation_attempts INTEGER NOT NULL DEFAULT 0,
                revocation_next_attempt_at TEXT,
                revocation_lease_owner TEXT,
                revocation_lease_until TEXT,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS pending_oauth_credentials_expiry
                ON pending_oauth_credentials (expires_at);

            CREATE TABLE IF NOT EXISTS setup_sessions (
                id TEXT PRIMARY KEY,
                owner_id TEXT NOT NULL,
                current_assignee_id TEXT,
                status TEXT NOT NULL,
                phase TEXT NOT NULL,
                revision BIGINT NOT NULL,
                template_id TEXT,
                principal_id TEXT,
                route_id TEXT,
                route_policy_digest TEXT,
                credential_id TEXT,
                credential_version BIGINT,
                policy_hash TEXT,
                assignment_digest TEXT,
                oauth_provider TEXT,
                oauth_state_digest TEXT,
                oauth_pending_credential_id TEXT,
                canary_id TEXT,
                enrollment_session_id TEXT,
                enrollment_packet_digest TEXT,
                verifier_nonce_hash TEXT,
                enrollment_verifier_receipt_digest TEXT,
                enrollment_verifier_key_id TEXT,
                attestation_challenge_digest TEXT,
                attestation_challenge_issued_at TEXT,
                attestation_challenge_expires_at TEXT,
                attestation_challenge_value TEXT,
                runtime_evidence_digest TEXT,
                hardware_assurance_digest TEXT,
                hardware_verification_receipt_digest TEXT,
                hardware_verifier_key_id TEXT,
                release_identity_digest TEXT,
                current_host_identity_digest TEXT,
                proxy_server_statement_digest TEXT,
                trust_profile_digest TEXT,
                completion_identity_digest TEXT,
                final_authority_key_id TEXT,
                final_consumption_id TEXT,
                final_receipt_digest TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                terminal_at TEXT
            );

            CREATE INDEX IF NOT EXISTS setup_sessions_owner_updated
                ON setup_sessions (owner_id, updated_at);
            CREATE INDEX IF NOT EXISTS setup_sessions_assignee_updated
                ON setup_sessions (current_assignee_id, updated_at);
            CREATE INDEX IF NOT EXISTS setup_sessions_status_expiry
                ON setup_sessions (status, expires_at);
            CREATE UNIQUE INDEX IF NOT EXISTS setup_sessions_one_oauth_state
                ON setup_sessions (oauth_state_digest)
                WHERE oauth_state_digest IS NOT NULL;
            CREATE UNIQUE INDEX IF NOT EXISTS setup_sessions_one_pending_oauth
                ON setup_sessions (oauth_pending_credential_id)
                WHERE oauth_pending_credential_id IS NOT NULL;
            CREATE UNIQUE INDEX IF NOT EXISTS setup_sessions_one_canary
                ON setup_sessions (canary_id)
                WHERE canary_id IS NOT NULL;
            CREATE UNIQUE INDEX IF NOT EXISTS setup_sessions_one_enrollment
                ON setup_sessions (enrollment_session_id)
                WHERE enrollment_session_id IS NOT NULL;
            CREATE TABLE IF NOT EXISTS setup_session_evidence (
                id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL REFERENCES setup_sessions(id) ON DELETE CASCADE,
                kind TEXT NOT NULL,
                evidence_json TEXT NOT NULL,
                evidence_digest TEXT NOT NULL,
                verifier_key_id TEXT NOT NULL,
                observed_at TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE (session_id, kind),
                UNIQUE (evidence_digest)
            );

            CREATE INDEX IF NOT EXISTS setup_session_evidence_session_created
                ON setup_session_evidence (session_id, created_at);
            CREATE UNIQUE INDEX IF NOT EXISTS setup_session_evidence_one_kind
                ON setup_session_evidence (session_id, kind);
            CREATE UNIQUE INDEX IF NOT EXISTS setup_session_evidence_one_digest
                ON setup_session_evidence (evidence_digest);

            CREATE TABLE IF NOT EXISTS setup_session_events (
                id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL REFERENCES setup_sessions(id) ON DELETE CASCADE,
                sequence BIGINT NOT NULL,
                transition TEXT NOT NULL,
                actor_id TEXT NOT NULL,
                payload_digest TEXT NOT NULL,
                event_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                audit_status TEXT NOT NULL,
                audit_claim_id TEXT,
                audit_claimed_at TEXT,
                audit_attempts BIGINT NOT NULL DEFAULT 0,
                audited_at TEXT,
                audit_event_hash TEXT,
                audit_last_error TEXT,
                UNIQUE (session_id, sequence)
            );

            CREATE INDEX IF NOT EXISTS setup_session_events_session_sequence
                ON setup_session_events (session_id, sequence);
            CREATE INDEX IF NOT EXISTS setup_session_events_audit_outbox
                ON setup_session_events (audit_status, audit_claimed_at, created_at);

            CREATE TABLE IF NOT EXISTS metadata_audit_outbox (
                id TEXT PRIMARY KEY,
                event_type TEXT NOT NULL,
                actor_type TEXT NOT NULL,
                actor_id TEXT,
                event_json TEXT NOT NULL,
                storage_format_version BIGINT,
                status TEXT NOT NULL,
                claim_id TEXT,
                claimed_at TEXT,
                attempts BIGINT NOT NULL DEFAULT 0,
                audited_at TEXT,
                audit_event_hash TEXT,
                last_error TEXT,
                created_at TEXT NOT NULL,
                CHECK (status IN ('pending', 'claimed', 'audited'))
            );

            CREATE INDEX IF NOT EXISTS metadata_audit_outbox_delivery
                ON metadata_audit_outbox (status, claimed_at, created_at, id);

            CREATE TABLE IF NOT EXISTS webauthn_trust_publications (
                id TEXT PRIMARY KEY,
                scope TEXT NOT NULL,
                previous_bundle_digest TEXT,
                bundle_digest TEXT NOT NULL UNIQUE,
                sequence BIGINT NOT NULL,
                rollback_epoch BIGINT NOT NULL,
                signing_key_id TEXT NOT NULL,
                bundle_json TEXT NOT NULL,
                payload_digest TEXT NOT NULL,
                actor_id TEXT NOT NULL,
                withdrawn_credential_ids_json TEXT NOT NULL,
                audit_event_json TEXT NOT NULL,
                status TEXT NOT NULL,
                attempts BIGINT NOT NULL DEFAULT 0,
                last_error TEXT,
                created_at TEXT NOT NULL,
                published_at TEXT,
                CHECK (scope = 'global'),
                CHECK (status IN ('pending', 'published')),
                UNIQUE (rollback_epoch, sequence)
            );

            CREATE UNIQUE INDEX IF NOT EXISTS webauthn_trust_publications_one_pending
                ON webauthn_trust_publications (scope)
                WHERE status = 'pending';

            CREATE TABLE IF NOT EXISTS oidc_login_states (
                id TEXT PRIMARY KEY,
                encrypted_secret TEXT NOT NULL,
                encrypted_dek TEXT NOT NULL,
                secret_nonce TEXT NOT NULL,
                secret_ciphertext TEXT NOT NULL,
                secret_kek_id TEXT NOT NULL,
                credential_version INTEGER NOT NULL,
                browser_nonce_sha256 TEXT NOT NULL,
                oidc_nonce TEXT NOT NULL,
                source_key TEXT NOT NULL DEFAULT 'internal',
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS oidc_login_states_expiry
                ON oidc_login_states (expires_at);

            CREATE TABLE IF NOT EXISTS oidc_login_rate_buckets (
                bucket_key TEXT PRIMARY KEY,
                attempt_count INTEGER NOT NULL,
                expires_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS oidc_login_rate_buckets_expiry
                ON oidc_login_rate_buckets (expires_at);

            CREATE TABLE IF NOT EXISTS oauth_revocation_work (
                id TEXT PRIMARY KEY,
                provider_id TEXT NOT NULL,
                actor_id TEXT NOT NULL,
                source TEXT NOT NULL,
                encrypted_secret TEXT NOT NULL,
                encrypted_dek TEXT NOT NULL,
                secret_nonce TEXT NOT NULL,
                secret_ciphertext TEXT NOT NULL,
                secret_kek_id TEXT NOT NULL,
                credential_version INTEGER NOT NULL,
                secret_updated_at TEXT NOT NULL,
                status TEXT NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                last_error TEXT,
                next_attempt_at TEXT NOT NULL,
                lease_owner TEXT,
                lease_until TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS oauth_revocation_work_due
                ON oauth_revocation_work (status, next_attempt_at);

            CREATE TABLE IF NOT EXISTS routes (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                match_host TEXT NOT NULL,
                match_path_prefix TEXT NOT NULL DEFAULT '/',
                credential_id TEXT REFERENCES credentials(id) ON DELETE SET NULL,
                injection TEXT NOT NULL DEFAULT '{}',
                policies TEXT NOT NULL DEFAULT '[]',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS approval_requests (
                id TEXT PRIMARY KEY,
                route_id TEXT REFERENCES routes(id) ON DELETE CASCADE,
                method TEXT NOT NULL,
                url TEXT NOT NULL,
                status TEXT NOT NULL,
                requested_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                approved_until TEXT,
                decision_note TEXT,
                principal_id TEXT,
                credential_id TEXT,
                credential_version INTEGER,
                policy_hash TEXT,
                request_digest TEXT,
                operation_digest TEXT,
                canonical_request TEXT,
                redacted_display TEXT,
                grant_ttl_seconds INTEGER,
                grant_max_uses INTEGER,
                approved_by TEXT,
                approval_authn TEXT,
                approver_webauthn_credential_id TEXT,
                approval_challenge_id TEXT,
                pending_key TEXT
            );

            CREATE TABLE IF NOT EXISTS control_plane_approvals (
                id TEXT PRIMARY KEY,
                action TEXT NOT NULL,
                resource_id TEXT,
                payload_digest TEXT NOT NULL,
                status TEXT NOT NULL,
                requester_id TEXT NOT NULL,
                requested_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                request_json TEXT NOT NULL DEFAULT '{}',
                approved_by TEXT,
                approved_at TEXT,
                consumed_by TEXT,
                consumed_at TEXT,
                decision_note TEXT,
                approval_authn TEXT,
                approver_webauthn_credential_id TEXT
            );

            CREATE INDEX IF NOT EXISTS control_plane_approvals_pending_lookup
                ON control_plane_approvals (action, resource_id, payload_digest, status, expires_at);

            CREATE TABLE IF NOT EXISTS gmail_message_cache (
                route_id TEXT NOT NULL REFERENCES routes(id) ON DELETE CASCADE,
                message_id TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                source_url TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (route_id, message_id)
            );

            CREATE TABLE IF NOT EXISTS request_logs (
                id TEXT PRIMARY KEY,
                route_id TEXT,
                method TEXT NOT NULL,
                url TEXT NOT NULL,
                action TEXT NOT NULL,
                status_code INTEGER,
                reason TEXT,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS approval_grants (
                id TEXT PRIMARY KEY,
                approval_request_id TEXT NOT NULL REFERENCES approval_requests(id) ON DELETE CASCADE,
                state TEXT NOT NULL,
                principal_id TEXT,
                route_id TEXT,
                credential_id TEXT,
                credential_version INTEGER,
                policy_hash TEXT,
                request_digest TEXT,
                operation_digest TEXT,
                approver_webauthn_credential_id TEXT,
                uses_remaining INTEGER NOT NULL,
                valid_from TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                consumed_at TEXT,
                consumed_by_flow_id TEXT,
                reserved_attempt_id TEXT,
                reserved_at_epoch_ms BIGINT,
                reservation_expires_at_epoch_ms BIGINT,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS approval_review_receipts (
                id TEXT PRIMARY KEY,
                approval_request_id TEXT NOT NULL REFERENCES approval_requests(id) ON DELETE CASCADE,
                reviewer_id TEXT NOT NULL,
                review_digest TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                used_at TEXT,
                created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS approval_review_receipts_lookup
                ON approval_review_receipts (approval_request_id, reviewer_id, expires_at, used_at);

            CREATE TABLE IF NOT EXISTS approval_grant_consumptions (
                id TEXT PRIMARY KEY,
                grant_id TEXT NOT NULL REFERENCES approval_grants(id) ON DELETE CASCADE,
                approval_request_id TEXT NOT NULL,
                attempt_id TEXT NOT NULL UNIQUE,
                flow_id TEXT NOT NULL,
                principal_id TEXT NOT NULL,
                route_id TEXT NOT NULL,
                credential_id TEXT NOT NULL,
                credential_version INTEGER NOT NULL,
                policy_hash TEXT NOT NULL,
                request_digest TEXT NOT NULL,
                operation_digest TEXT,
                outcome TEXT NOT NULL,
                uses_remaining_before INTEGER NOT NULL,
                uses_remaining_after INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                audited_at TEXT,
                audit_event_hash TEXT
            );

            CREATE TABLE IF NOT EXISTS approval_events (
                id TEXT PRIMARY KEY,
                approval_request_id TEXT,
                event_type TEXT NOT NULL,
                actor_type TEXT NOT NULL,
                actor_id TEXT,
                event_json TEXT NOT NULL,
                prev_event_hash TEXT,
                event_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS audit_events (
                id TEXT PRIMARY KEY,
                event_type TEXT NOT NULL,
                actor_type TEXT NOT NULL,
                actor_id TEXT,
                event_json TEXT NOT NULL,
                encrypted_canonical_event_json TEXT,
                storage_format_version BIGINT,
                prev_event_hash TEXT,
                event_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS rate_limit_counters (
                counter_key TEXT PRIMARY KEY,
                principal_id TEXT,
                route_id TEXT,
                credential_id TEXT,
                credential_version INTEGER,
                policy_hash TEXT,
                constraint_id TEXT,
                operation TEXT,
                encrypted_operation TEXT,
                operation_storage_version BIGINT,
                window_start_epoch_ms BIGINT NOT NULL,
                window_seconds INTEGER NOT NULL,
                max_count INTEGER NOT NULL,
                count INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS release_authorization_attempts (
                attempt_id TEXT PRIMARY KEY,
                binding_digest TEXT NOT NULL,
                binding_json TEXT NOT NULL,
                flow_id TEXT NOT NULL,
                state TEXT NOT NULL,
                principal_id TEXT NOT NULL,
                route_id TEXT NOT NULL,
                credential_id TEXT NOT NULL,
                credential_version BIGINT NOT NULL,
                policy_hash TEXT NOT NULL,
                request_digest TEXT NOT NULL,
                operation_digest TEXT,
                operation_context_json TEXT NOT NULL,
                grant_id TEXT,
                approval_request_id TEXT,
                reservation_expires_at_epoch_ms BIGINT NOT NULL,
                dispatch_started_at_epoch_ms BIGINT,
                dispatch_expires_at_epoch_ms BIGINT,
                completion_outcome TEXT,
                completed_at_epoch_ms BIGINT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                CHECK (state IN (
                    'reserved', 'dispatching', 'committed', 'cancelled',
                    'committed_indeterminate'
                ))
            );

            CREATE INDEX IF NOT EXISTS release_authorization_attempts_reap
                ON release_authorization_attempts (
                    state, reservation_expires_at_epoch_ms,
                    dispatch_expires_at_epoch_ms, attempt_id
                );

            CREATE TABLE IF NOT EXISTS release_authorization_quota_reservations (
                attempt_id TEXT NOT NULL
                    REFERENCES release_authorization_attempts(attempt_id) ON DELETE CASCADE,
                counter_key TEXT NOT NULL,
                constraint_id TEXT NOT NULL,
                operation TEXT,
                encrypted_operation TEXT,
                operation_storage_version BIGINT,
                window_start_epoch_ms BIGINT NOT NULL,
                window_seconds INTEGER NOT NULL,
                max_count INTEGER NOT NULL,
                count_after INTEGER NOT NULL,
                reservation_state TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (attempt_id, counter_key),
                CHECK (reservation_state IN (
                    'reserved', 'committed', 'refunded', 'refund_skipped_window'
                ))
            );

            CREATE INDEX IF NOT EXISTS release_authorization_quota_counter
                ON release_authorization_quota_reservations (counter_key, attempt_id);

            CREATE TABLE IF NOT EXISTS release_authorization_events (
                id TEXT PRIMARY KEY,
                attempt_id TEXT NOT NULL
                    REFERENCES release_authorization_attempts(attempt_id) ON DELETE CASCADE,
                event_type TEXT NOT NULL,
                actor_id TEXT,
                event_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                audited_at TEXT,
                audit_event_hash TEXT
            );

            CREATE INDEX IF NOT EXISTS release_authorization_events_pending_audit
                ON release_authorization_events (created_at, id)
                WHERE audited_at IS NULL;

            CREATE TABLE IF NOT EXISTS credential_lease_nonces (
                recipient_key_id TEXT NOT NULL,
                nonce_sha256 TEXT NOT NULL,
                expires_at_epoch_ms BIGINT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (recipient_key_id, nonce_sha256)
            );

            CREATE INDEX IF NOT EXISTS credential_lease_nonces_expiry
                ON credential_lease_nonces (expires_at_epoch_ms);

            CREATE TABLE IF NOT EXISTS credential_lease_replay_state (
                scope TEXT PRIMARY KEY,
                nonce_count BIGINT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS credential_generations (
                credential_id TEXT PRIMARY KEY,
                last_version BIGINT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS policy_high_water (
                scope TEXT PRIMARY KEY,
                policy_id TEXT NOT NULL,
                sequence BIGINT NOT NULL,
                rollback_epoch BIGINT NOT NULL,
                policy_hash TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS webauthn_credentials (
                id TEXT PRIMARY KEY,
                credential_id TEXT NOT NULL UNIQUE,
                user_id TEXT NOT NULL,
                label TEXT NOT NULL,
                public_key_cose TEXT NOT NULL,
                sign_count INTEGER NOT NULL DEFAULT 0,
                aaguid TEXT,
                authenticator_class TEXT NOT NULL DEFAULT 'unknown',
                attestation_fmt TEXT,
                attestation_trusted INTEGER NOT NULL DEFAULT 0,
                attestation_trust_path TEXT NOT NULL DEFAULT '[]',
                attestation_leaf_sha256 TEXT,
                attestation_root_sha256 TEXT,
                attestation_trust_bundle_digest TEXT,
                attestation_trust_bundle_sequence INTEGER,
                attestation_verified_at TEXT,
                transports TEXT NOT NULL DEFAULT '[]',
                dev_private_key_pem TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                last_used_at TEXT,
                revoked_at TEXT,
                revoked_by TEXT,
                revocation_reason TEXT,
                revocation_source TEXT
            );

            CREATE TABLE IF NOT EXISTS oidc_browser_sessions (
                id TEXT PRIMARY KEY,
                token_digest TEXT NOT NULL UNIQUE,
                oidc_token_digest TEXT NOT NULL,
                user_id TEXT NOT NULL,
                roles_json TEXT NOT NULL,
                status TEXT NOT NULL,
                provider_expires_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                pending_expires_at TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                activated_at TEXT,
                revoked_at TEXT,
                bound_webauthn_credential_id TEXT
                    REFERENCES webauthn_credentials(id),
                activation_trust_bundle_digest TEXT,
                activation_trust_bundle_sequence BIGINT,
                activation_authenticator_class TEXT,
                revocation_reason TEXT,
                CHECK (
                    length(token_digest) = 71
                    AND substr(token_digest, 1, 7) = 'sha256:'
                ),
                CHECK (
                    length(oidc_token_digest) = 71
                    AND substr(oidc_token_digest, 1, 7) = 'sha256:'
                ),
                CHECK (status IN ('pending_webauthn', 'active', 'revoked')),
                CHECK (length(roles_json) <= 4096),
                CHECK (
                    (status = 'pending_webauthn'
                        AND pending_expires_at IS NOT NULL
                        AND activated_at IS NULL
                        AND revoked_at IS NULL
                        AND bound_webauthn_credential_id IS NULL)
                    OR (status = 'active'
                        AND pending_expires_at IS NULL
                        AND activated_at IS NOT NULL
                        AND revoked_at IS NULL)
                    OR (status = 'revoked' AND revoked_at IS NOT NULL)
                )
            );

            CREATE INDEX IF NOT EXISTS oidc_browser_sessions_status_expiry
                ON oidc_browser_sessions (status, expires_at);

            CREATE INDEX IF NOT EXISTS oidc_browser_sessions_user_live
                ON oidc_browser_sessions (user_id, status, expires_at);

            CREATE INDEX IF NOT EXISTS oidc_browser_sessions_webauthn_binding
                ON oidc_browser_sessions (bound_webauthn_credential_id, status);

            CREATE TABLE IF NOT EXISTS oidc_session_activation_deliveries (
                id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL UNIQUE
                    REFERENCES oidc_browser_sessions(id) ON DELETE CASCADE,
                old_token_digest TEXT NOT NULL UNIQUE,
                new_token_digest TEXT NOT NULL UNIQUE,
                assertion_digest TEXT NOT NULL UNIQUE,
                challenge_id TEXT NOT NULL UNIQUE,
                credential_record_id TEXT NOT NULL
                    REFERENCES webauthn_credentials(id),
                encrypted_active_token TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                consumed_at TEXT,
                CHECK (
                    length(old_token_digest) = 71
                    AND substr(old_token_digest, 1, 7) = 'sha256:'
                ),
                CHECK (
                    length(new_token_digest) = 71
                    AND substr(new_token_digest, 1, 7) = 'sha256:'
                ),
                CHECK (
                    length(assertion_digest) = 71
                    AND substr(assertion_digest, 1, 7) = 'sha256:'
                ),
                CHECK (length(encrypted_active_token) <= 4096)
            );

            CREATE INDEX IF NOT EXISTS oidc_activation_delivery_live
                ON oidc_session_activation_deliveries
                    (old_token_digest, assertion_digest, consumed_at, expires_at);

            CREATE INDEX IF NOT EXISTS oidc_activation_delivery_expiry
                ON oidc_session_activation_deliveries (expires_at, consumed_at);

            CREATE TABLE IF NOT EXISTS webauthn_challenges (
                id TEXT PRIMARY KEY,
                challenge TEXT NOT NULL UNIQUE,
                challenge_type TEXT NOT NULL,
                user_id TEXT NOT NULL,
                scope_key TEXT,
                approval_request_id TEXT,
                payload_json TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                used_at TEXT,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS webauthn_recovery_root_state (
                signing_key_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                last_consumed_sequence BIGINT NOT NULL,
                updated_at TEXT NOT NULL,
                CHECK (last_consumed_sequence >= 0),
                PRIMARY KEY (signing_key_id, user_id)
            );

            CREATE TABLE IF NOT EXISTS webauthn_recovery_ceremonies (
                id TEXT PRIMARY KEY,
                nonce TEXT NOT NULL UNIQUE,
                user_id TEXT NOT NULL,
                oidc_session_id TEXT NOT NULL,
                pending_token_digest TEXT NOT NULL,
                oidc_token_digest TEXT NOT NULL,
                roles_json TEXT NOT NULL,
                identity_digest TEXT NOT NULL,
                session_expires_at TEXT NOT NULL,
                pending_expires_at TEXT NOT NULL,
                label TEXT NOT NULL,
                reason TEXT NOT NULL,
                challenge_id TEXT NOT NULL UNIQUE
                    REFERENCES webauthn_challenges(id),
                challenge_digest TEXT NOT NULL UNIQUE,
                credential_history_digest TEXT NOT NULL,
                credential_history_count BIGINT NOT NULL,
                active_credential_count BIGINT NOT NULL,
                trust_bundle_digest TEXT NOT NULL,
                trust_bundle_sequence BIGINT NOT NULL,
                trust_bundle_rollback_epoch BIGINT NOT NULL,
                trust_signing_key_id TEXT NOT NULL,
                auth_policy_digest TEXT NOT NULL,
                recovery_root_key_id TEXT NOT NULL,
                recovery_root_provider TEXT NOT NULL,
                recovery_audience TEXT NOT NULL,
                rp_id TEXT NOT NULL,
                origin TEXT NOT NULL,
                root_sequence BIGINT,
                status TEXT NOT NULL,
                candidate_json TEXT,
                candidate_digest TEXT UNIQUE,
                statement_json TEXT,
                statement_digest TEXT UNIQUE,
                authorization_json TEXT,
                authorization_digest TEXT UNIQUE,
                signature_digest TEXT UNIQUE,
                replacement_record_id TEXT UNIQUE
                    REFERENCES webauthn_credentials(id),
                created_at TEXT NOT NULL,
                prepared_at TEXT,
                expires_at TEXT NOT NULL,
                consumed_at TEXT,
                invalidated_at TEXT,
                CHECK (
                    status IN (
                        'pending_candidate', 'prepared', 'consumed',
                        'expired', 'invalidated'
                    )
                ),
                CHECK (credential_history_count > 0),
                CHECK (active_credential_count = 0),
                CHECK (root_sequence IS NULL OR root_sequence > 0),
                CHECK (length(roles_json) <= 4096)
            );

            CREATE UNIQUE INDEX IF NOT EXISTS webauthn_recovery_one_live_subject
                ON webauthn_recovery_ceremonies (user_id)
                WHERE status IN ('pending_candidate', 'prepared');

            CREATE UNIQUE INDEX IF NOT EXISTS webauthn_recovery_one_live_session
                ON webauthn_recovery_ceremonies (oidc_session_id)
                WHERE status IN ('pending_candidate', 'prepared');

            CREATE INDEX IF NOT EXISTS webauthn_recovery_status_expiry
                ON webauthn_recovery_ceremonies (status, expires_at);

            CREATE TABLE IF NOT EXISTS webauthn_recovery_revocations (
                id TEXT PRIMARY KEY,
                nonce TEXT NOT NULL UNIQUE,
                user_id TEXT NOT NULL,
                oidc_session_id TEXT NOT NULL,
                pending_token_digest TEXT NOT NULL,
                oidc_token_digest TEXT NOT NULL,
                roles_json TEXT NOT NULL,
                identity_digest TEXT NOT NULL,
                session_expires_at TEXT NOT NULL,
                pending_expires_at TEXT NOT NULL,
                reason TEXT NOT NULL,
                credential_history_digest TEXT NOT NULL,
                credential_history_count BIGINT NOT NULL,
                active_credential_count BIGINT NOT NULL,
                active_credential_record_id TEXT NOT NULL,
                active_credential_id_digest TEXT NOT NULL,
                trust_bundle_digest TEXT NOT NULL,
                trust_bundle_sequence BIGINT NOT NULL,
                trust_bundle_rollback_epoch BIGINT NOT NULL,
                trust_signing_key_id TEXT NOT NULL,
                auth_policy_digest TEXT NOT NULL,
                recovery_root_key_id TEXT NOT NULL,
                recovery_root_provider TEXT NOT NULL,
                recovery_audience TEXT NOT NULL,
                root_sequence BIGINT NOT NULL,
                statement_json TEXT NOT NULL,
                statement_digest TEXT NOT NULL UNIQUE,
                authorization_json TEXT,
                authorization_digest TEXT UNIQUE,
                signature_digest TEXT UNIQUE,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                consumed_at TEXT,
                CHECK (active_credential_count = 1),
                CHECK (credential_history_count > 0),
                CHECK (root_sequence > 0),
                CHECK (status IN ('prepared', 'consumed', 'expired'))
            );

            CREATE UNIQUE INDEX IF NOT EXISTS webauthn_recovery_revocation_one_live_subject
                ON webauthn_recovery_revocations (user_id)
                WHERE status = 'prepared';

            CREATE UNIQUE INDEX IF NOT EXISTS webauthn_recovery_revocation_one_live_session
                ON webauthn_recovery_revocations (oidc_session_id)
                WHERE status = 'prepared';

            CREATE INDEX IF NOT EXISTS webauthn_recovery_revocation_status_expiry
                ON webauthn_recovery_revocations (status, expires_at);
            """
        )
        _lock_postgres_metadata_migration_tables(conn)
        _ensure_column(
            conn,
            "release_authorization_quota_reservations",
            "encrypted_operation",
            "TEXT",
        )
        _ensure_column(
            conn,
            "release_authorization_quota_reservations",
            "operation_storage_version",
            "BIGINT",
        )
        _ensure_column(conn, "rate_limit_counters", "encrypted_operation", "TEXT")
        _ensure_column(
            conn, "rate_limit_counters", "operation_storage_version", "BIGINT"
        )
        _ensure_column(
            conn, "metadata_audit_outbox", "storage_format_version", "BIGINT"
        )
        _install_metadata_storage_epoch_guards(conn)
        _remediate_metadata_rate_limit_storage(conn, keyring=keyring)
        if not isinstance(conn, PostgresMetadataConnection):
            conn.executescript(
                """
                CREATE TRIGGER IF NOT EXISTS audit_events_event_json_size_insert
                BEFORE INSERT ON audit_events
                WHEN length(CAST(NEW.event_json AS BLOB)) > 8388608
                BEGIN
                    SELECT RAISE(ABORT, 'audit event exceeds stored size ceiling');
                END;

                CREATE TRIGGER IF NOT EXISTS audit_events_event_json_size_update
                BEFORE UPDATE OF event_json ON audit_events
                WHEN length(CAST(NEW.event_json AS BLOB)) > 8388608
                BEGIN
                    SELECT RAISE(ABORT, 'audit event exceeds stored size ceiling');
                END;
                """
            )
        _ensure_column(conn, "approval_requests", "principal_id", "TEXT")
        _ensure_column(conn, "approval_requests", "credential_id", "TEXT")
        _ensure_column(conn, "approval_requests", "credential_version", "INTEGER")
        _ensure_column(conn, "approval_requests", "policy_hash", "TEXT")
        _ensure_column(conn, "approval_requests", "request_digest", "TEXT")
        _ensure_column(conn, "approval_requests", "operation_digest", "TEXT")
        _ensure_column(conn, "approval_requests", "canonical_request", "TEXT")
        _ensure_column(conn, "approval_requests", "redacted_display", "TEXT")
        for row in conn.execute(
            "SELECT id, url, canonical_request, redacted_display FROM approval_requests"
        ).fetchall():
            stored_canonical = str(row["canonical_request"] or "")
            stored_display = str(row["redacted_display"] or "")
            if (
                (not stored_canonical or stored_canonical.startswith("v2:"))
                and (not stored_display or stored_display.startswith("v2:"))
                and re.fullmatch(r"sha256:[0-9a-f]{64}", str(row["url"] or ""))
            ):
                continue
            canonical = loads(_decrypt_approval_json(stored_canonical), None)
            display = loads(_decrypt_approval_json(stored_display), None)
            if stored_canonical and not isinstance(canonical, dict):
                raise RuntimeError("stored approval canonical request is not a JSON object")
            if stored_display and not isinstance(display, dict):
                raise RuntimeError("stored approval redacted display is not a JSON object")
            display_url = display.get("url") if isinstance(display, dict) else None
            cleartext_url = display_url if isinstance(display_url, str) else str(row["url"])
            conn.execute(
                "UPDATE approval_requests SET url = ?, canonical_request = ?, "
                "redacted_display = ? WHERE id = ?",
                (
                    _approval_url_commitment(cleartext_url),
                    (
                        stored_canonical
                        if stored_canonical.startswith("v2:")
                        else _encrypt_approval_json(dumps(canonical))
                        if canonical is not None
                        else None
                    ),
                    (
                        stored_display
                        if stored_display.startswith("v2:")
                        else _encrypt_approval_json(dumps(display))
                        if display is not None
                        else None
                    ),
                    row["id"],
                ),
            )
        for row in conn.execute(
            "SELECT attempt_id, binding_digest, binding_json, operation_context_json "
            "FROM release_authorization_attempts"
        ).fetchall():
            binding_digest = str(row["binding_digest"])
            stored_binding = loads(str(row["binding_json"] or ""), {})
            operation_context = loads(str(row["operation_context_json"] or ""), {})
            binding_is_commitment = stored_binding == {"digest": binding_digest}
            if (
                isinstance(operation_context, dict)
                and set(operation_context) == {"digest"}
                and re.fullmatch(
                    r"sha256:[0-9a-f]{64}", str(operation_context.get("digest") or "")
                )
            ):
                operation_context_digest = str(operation_context["digest"])
                if binding_is_commitment:
                    continue
            else:
                operation_context_digest = (
                    "sha256:"
                    + hashlib.sha256(dumps(operation_context).encode("utf-8")).hexdigest()
                )
            conn.execute(
                "UPDATE release_authorization_attempts SET binding_json = ?, "
                "operation_context_json = ? WHERE attempt_id = ?",
                (
                    dumps({"digest": binding_digest}),
                    dumps({"digest": operation_context_digest}),
                    row["attempt_id"],
                ),
            )
        _ensure_column(conn, "approval_requests", "grant_ttl_seconds", "INTEGER")
        _ensure_column(conn, "approval_requests", "grant_max_uses", "INTEGER")
        _ensure_column(conn, "approval_requests", "approved_by", "TEXT")
        _ensure_column(conn, "approval_requests", "approval_authn", "TEXT")
        _ensure_column(
            conn, "approval_requests", "approver_webauthn_credential_id", "TEXT"
        )
        _ensure_column(conn, "approval_requests", "approval_challenge_id", "TEXT")
        _ensure_column(conn, "approval_requests", "pending_key", "TEXT")
        _ensure_column(conn, "approval_grants", "reserved_attempt_id", "TEXT")
        _ensure_column(
            conn, "approval_grants", "approver_webauthn_credential_id", "TEXT"
        )
        _ensure_column(conn, "approval_grants", "reserved_at_epoch_ms", "BIGINT")
        _ensure_column(
            conn,
            "approval_grants",
            "reservation_expires_at_epoch_ms",
            "BIGINT",
        )
        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS approval_grants_reserved_attempt "
            "ON approval_grants (reserved_attempt_id) "
            "WHERE reserved_attempt_id IS NOT NULL"
        )
        _ensure_column(
            conn,
            "control_plane_approvals",
            "request_json",
            "TEXT NOT NULL DEFAULT '{}'",
        )
        _ensure_column(conn, "control_plane_approvals", "approved_by", "TEXT")
        _ensure_column(conn, "control_plane_approvals", "approved_at", "TEXT")
        _ensure_column(conn, "control_plane_approvals", "consumed_by", "TEXT")
        _ensure_column(conn, "control_plane_approvals", "consumed_at", "TEXT")
        _ensure_column(conn, "control_plane_approvals", "decision_note", "TEXT")
        _ensure_column(conn, "control_plane_approvals", "approval_authn", "TEXT")
        _ensure_column(
            conn,
            "control_plane_approvals",
            "approver_webauthn_credential_id",
            "TEXT",
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS control_plane_approvals_webauthn_lookup "
            "ON control_plane_approvals (approver_webauthn_credential_id, status)"
        )
        _ensure_column(
            conn,
            "pending_oauth_credentials",
            "status",
            "TEXT NOT NULL DEFAULT 'pending'",
        )
        _ensure_column(
            conn, "pending_oauth_credentials", "target_credential_id", "TEXT"
        )
        _ensure_column(
            conn, "pending_oauth_credentials", "target_credential_version", "INTEGER"
        )
        _ensure_column(conn, "pending_oauth_credentials", "revocation_status", "TEXT")
        _ensure_column(conn, "pending_oauth_credentials", "revocation_error", "TEXT")
        _ensure_column(
            conn,
            "pending_oauth_credentials",
            "revocation_attempts",
            "INTEGER NOT NULL DEFAULT 0",
        )
        _ensure_column(
            conn, "pending_oauth_credentials", "revocation_next_attempt_at", "TEXT"
        )
        _ensure_column(
            conn, "pending_oauth_credentials", "revocation_lease_owner", "TEXT"
        )
        _ensure_column(
            conn, "pending_oauth_credentials", "revocation_lease_until", "TEXT"
        )
        _ensure_column(conn, "pending_oauth_credentials", "updated_at", "TEXT")
        _ensure_column(conn, "setup_sessions", "route_policy_digest", "TEXT")
        for column in (
            "attestation_challenge_digest",
            "attestation_challenge_issued_at",
            "attestation_challenge_expires_at",
            "attestation_challenge_value",
            "enrollment_verifier_receipt_digest",
            "enrollment_verifier_key_id",
            "runtime_evidence_digest",
            "hardware_assurance_digest",
            "hardware_verification_receipt_digest",
            "hardware_verifier_key_id",
            "release_identity_digest",
            "current_host_identity_digest",
            "proxy_server_statement_digest",
            "trust_profile_digest",
            "completion_identity_digest",
            "final_authority_key_id",
            "final_consumption_id",
            "final_receipt_digest",
        ):
            _ensure_column(conn, "setup_sessions", column, "TEXT")
        for index_name, column in (
            (
                "setup_sessions_one_attestation_challenge",
                "attestation_challenge_digest",
            ),
            (
                "setup_sessions_one_enrollment_verifier_receipt",
                "enrollment_verifier_receipt_digest",
            ),
            ("setup_sessions_one_runtime_evidence", "runtime_evidence_digest"),
            ("setup_sessions_one_hardware_assurance", "hardware_assurance_digest"),
            (
                "setup_sessions_one_hardware_verification_receipt",
                "hardware_verification_receipt_digest",
            ),
            ("setup_sessions_one_final_consumption", "final_consumption_id"),
            ("setup_sessions_one_final_receipt", "final_receipt_digest"),
        ):
            conn.execute(
                f"CREATE UNIQUE INDEX IF NOT EXISTS {index_name} "
                f"ON setup_sessions ({column}) WHERE {column} IS NOT NULL"
            )
        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS setup_session_evidence_one_kind "
            "ON setup_session_evidence (session_id, kind)"
        )
        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS setup_session_evidence_one_digest "
            "ON setup_session_evidence (evidence_digest)"
        )
        _ensure_column(
            conn, "oidc_login_states", "source_key", "TEXT NOT NULL DEFAULT 'internal'"
        )
        _ensure_column(conn, "oidc_browser_sessions", "pending_expires_at", "TEXT")
        _ensure_column(conn, "oidc_browser_sessions", "provider_expires_at", "TEXT")
        _ensure_column(
            conn, "oidc_browser_sessions", "activation_trust_bundle_digest", "TEXT"
        )
        _ensure_column(
            conn,
            "oidc_browser_sessions",
            "activation_trust_bundle_sequence",
            "BIGINT",
        )
        _ensure_column(
            conn, "oidc_browser_sessions", "activation_authenticator_class", "TEXT"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS oidc_browser_sessions_pending_expiry "
            "ON oidc_browser_sessions (status, pending_expires_at)"
        )
        _ensure_column(conn, "webauthn_challenges", "scope_key", "TEXT")
        conn.execute(
            "CREATE INDEX IF NOT EXISTS webauthn_challenges_type_user_state "
            "ON webauthn_challenges "
            "(challenge_type, user_id, used_at, expires_at)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS webauthn_challenges_type_scope_state "
            "ON webauthn_challenges "
            "(challenge_type, scope_key, used_at, expires_at)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS webauthn_challenges_live_expiry "
            "ON webauthn_challenges (used_at, expires_at)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS webauthn_challenges_user_created "
            "ON webauthn_challenges (user_id, created_at)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS webauthn_challenges_created "
            "ON webauthn_challenges (created_at)"
        )
        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS "
            "webauthn_challenges_one_live_oidc_binding "
            "ON webauthn_challenges (challenge_type, user_id, scope_key) "
            "WHERE challenge_type = 'oidc-session-binding' "
            "AND used_at IS NULL AND scope_key IS NOT NULL"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS webauthn_credentials_user_active "
            "ON webauthn_credentials (user_id, revoked_at, created_at)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS webauthn_credentials_user_class_active "
            "ON webauthn_credentials "
            "(user_id, authenticator_class, revoked_at)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS oidc_login_states_source_expiry "
            "ON oidc_login_states (source_key, expires_at)"
        )
        conn.execute(
            "UPDATE pending_oauth_credentials SET updated_at = created_at WHERE updated_at IS NULL"
        )
        _ensure_column(conn, "approval_grants", "credential_version", "INTEGER")
        _backfill_pending_approval_keys(conn)
        conn.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS approval_requests_one_pending_key
            ON approval_requests (pending_key)
            WHERE status = 'pending'
            """
        )
        _ensure_column(conn, "credentials", "encrypted_dek", "TEXT")
        _ensure_column(conn, "credentials", "secret_nonce", "TEXT")
        _ensure_column(conn, "credentials", "secret_ciphertext", "TEXT")
        _ensure_column(conn, "credentials", "secret_kek_id", "TEXT")
        _ensure_column(
            conn, "credentials", "credential_version", "INTEGER NOT NULL DEFAULT 1"
        )
        _ensure_column(conn, "credentials", "secret_updated_at", "TEXT")
        _ensure_column(
            conn, "credentials", "lifecycle_status", "TEXT NOT NULL DEFAULT 'active'"
        )
        _ensure_column(conn, "credentials", "revocation_error", "TEXT")
        _ensure_column(conn, "credentials", "revocation_requested_at", "TEXT")
        _ensure_column(conn, "webauthn_credentials", "attestation_fmt", "TEXT")
        _ensure_column(
            conn,
            "webauthn_credentials",
            "attestation_trusted",
            "INTEGER NOT NULL DEFAULT 0",
        )
        _ensure_column(
            conn,
            "webauthn_credentials",
            "attestation_trust_path",
            "TEXT NOT NULL DEFAULT '[]'",
        )
        _ensure_column(conn, "webauthn_credentials", "attestation_leaf_sha256", "TEXT")
        _ensure_column(conn, "webauthn_credentials", "attestation_root_sha256", "TEXT")
        _ensure_column(
            conn, "webauthn_credentials", "attestation_trust_bundle_digest", "TEXT"
        )
        _ensure_column(
            conn, "webauthn_credentials", "attestation_trust_bundle_sequence", "INTEGER"
        )
        _ensure_column(conn, "webauthn_credentials", "attestation_verified_at", "TEXT")
        _ensure_column(conn, "webauthn_credentials", "revoked_by", "TEXT")
        _ensure_column(conn, "webauthn_credentials", "revocation_reason", "TEXT")
        _ensure_column(conn, "webauthn_credentials", "revocation_source", "TEXT")
        for row in conn.execute(
            "SELECT id, approval_authn FROM approval_requests "
            "WHERE approver_webauthn_credential_id IS NULL "
            "AND approval_authn IS NOT NULL"
        ).fetchall():
            authn = loads(row["approval_authn"], {})
            credential_record_id = (
                authn.get("credential_record_id")
                if isinstance(authn, dict)
                else None
            )
            if not credential_record_id:
                continue
            conn.execute(
                "UPDATE approval_requests "
                "SET approver_webauthn_credential_id = ? WHERE id = ?",
                (credential_record_id, row["id"]),
            )
            conn.execute(
                "UPDATE approval_grants "
                "SET approver_webauthn_credential_id = ? "
                "WHERE approval_request_id = ? "
                "AND approver_webauthn_credential_id IS NULL",
                (credential_record_id, row["id"]),
            )
        for row in conn.execute(
            "SELECT id, credential_version FROM credentials"
        ).fetchall():
            _record_credential_generation(
                conn, str(row["id"]), int(row["credential_version"] or 1)
            )


def _ensure_column(conn: Any, table: str, column: str, decl: str) -> None:
    if isinstance(conn, PostgresMetadataConnection):
        conn.execute(
            f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {column} {decl}"
        )
        return
    columns = {
        row["name"] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()
    }
    if column not in columns:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {decl}")


def _setup_now(value: datetime | None = None) -> datetime:
    current = value or utcnow()
    if current.tzinfo is None:
        raise SetupSessionValidationError(
            "setup session timestamps must include a timezone"
        )
    return current.astimezone(timezone.utc)


def _setup_text(
    label: str, value: Any, *, maximum: int = 512, required: bool = True
) -> str | None:
    if value is None and not required:
        return None
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value.encode("utf-8")) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise SetupSessionValidationError(
            f"{label} must be a non-empty trimmed string of at most {maximum} bytes"
        )
    return value


def _setup_digest(label: str, value: Any, *, required: bool = True) -> str | None:
    digest = _setup_text(label, value, maximum=71, required=required)
    if digest is not None and not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        raise SetupSessionValidationError(f"{label} must be a lowercase sha256 digest")
    return digest


def _setup_timestamp(label: str, value: Any) -> str:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise SetupSessionValidationError(
                f"{label} must be an ISO-8601 timestamp"
            ) from exc
    else:
        raise SetupSessionValidationError(f"{label} must be an ISO-8601 timestamp")
    if parsed.tzinfo is None:
        raise SetupSessionValidationError(f"{label} must include a timezone")
    return parsed.astimezone(timezone.utc).isoformat()


def _setup_canonical_json(value: Any, *, maximum_bytes: int, label: str) -> str:
    key_count = 0

    def walk(item: Any, depth: int) -> None:
        nonlocal key_count
        if depth > 12:
            raise SetupSessionValidationError(
                f"{label} exceeds the maximum nesting depth"
            )
        if isinstance(item, dict):
            key_count += len(item)
            if key_count > 2048:
                raise SetupSessionValidationError(f"{label} contains too many keys")
            for key, child in item.items():
                if (
                    not isinstance(key, str)
                    or not key
                    or len(key.encode("utf-8")) > 256
                ):
                    raise SetupSessionValidationError(
                        f"{label} keys must be non-empty strings of at most 256 bytes"
                    )
                compact = "".join(
                    character
                    for character in key.strip().lower()
                    if character.isalnum()
                )
                if (
                    compact in _SENSITIVE_CREDENTIAL_METADATA_KEYS_COMPACT
                    or compact.endswith(_SENSITIVE_CREDENTIAL_METADATA_SUFFIXES)
                ):
                    raise SetupSessionValidationError(
                        f"{label} key {key!r} may contain secret material"
                    )
                walk(child, depth + 1)
        elif isinstance(item, list):
            for child in item:
                walk(child, depth + 1)

    if not isinstance(value, dict):
        raise SetupSessionValidationError(f"{label} must be a JSON object")
    walk(value, 0)
    try:
        encoded = json.dumps(
            value,
            separators=(",", ":"),
            sort_keys=True,
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise SetupSessionValidationError(f"{label} must contain finite JSON") from exc
    if len(encoded) > maximum_bytes:
        raise SetupSessionValidationError(f"{label} exceeds {maximum_bytes} bytes")
    return encoded.decode("ascii")


def _setup_sha256(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _row_to_setup_session(row: Any) -> dict[str, Any]:
    return {
        "id": str(row["id"]),
        "owner_id": str(row["owner_id"]),
        "current_assignee_id": (
            str(row["current_assignee_id"]) if row["current_assignee_id"] else None
        ),
        "status": str(row["status"]),
        "phase": str(row["phase"]),
        "revision": int(row["revision"]),
        "template_id": str(row["template_id"]) if row["template_id"] else None,
        "principal_id": str(row["principal_id"]) if row["principal_id"] else None,
        "route_id": str(row["route_id"]) if row["route_id"] else None,
        "route_policy_digest": (
            str(row["route_policy_digest"]) if row["route_policy_digest"] else None
        ),
        "credential_id": str(row["credential_id"]) if row["credential_id"] else None,
        "credential_version": (
            int(row["credential_version"])
            if row["credential_version"] is not None
            else None
        ),
        "policy_hash": str(row["policy_hash"]) if row["policy_hash"] else None,
        "assignment_digest": (
            str(row["assignment_digest"]) if row["assignment_digest"] else None
        ),
        "oauth_provider": str(row["oauth_provider"]) if row["oauth_provider"] else None,
        "oauth_state_digest": (
            str(row["oauth_state_digest"]) if row["oauth_state_digest"] else None
        ),
        "oauth_pending_credential_id": (
            str(row["oauth_pending_credential_id"])
            if row["oauth_pending_credential_id"]
            else None
        ),
        "canary_id": str(row["canary_id"]) if row["canary_id"] else None,
        "enrollment_session_id": (
            str(row["enrollment_session_id"]) if row["enrollment_session_id"] else None
        ),
        "enrollment_packet_digest": (
            str(row["enrollment_packet_digest"])
            if row["enrollment_packet_digest"]
            else None
        ),
        "verifier_nonce_hash": (
            str(row["verifier_nonce_hash"]) if row["verifier_nonce_hash"] else None
        ),
        "enrollment_verifier_receipt_digest": (
            str(row["enrollment_verifier_receipt_digest"])
            if row["enrollment_verifier_receipt_digest"]
            else None
        ),
        "enrollment_verifier_key_id": (
            str(row["enrollment_verifier_key_id"])
            if row["enrollment_verifier_key_id"]
            else None
        ),
        "attestation_challenge_digest": (
            str(row["attestation_challenge_digest"])
            if row["attestation_challenge_digest"]
            else None
        ),
        "attestation_challenge_issued_at": (
            str(row["attestation_challenge_issued_at"])
            if row["attestation_challenge_issued_at"]
            else None
        ),
        "attestation_challenge_expires_at": (
            str(row["attestation_challenge_expires_at"])
            if row["attestation_challenge_expires_at"]
            else None
        ),
        "attestation_challenge_value": (
            str(row["attestation_challenge_value"])
            if row["attestation_challenge_value"]
            else None
        ),
        "runtime_evidence_digest": (
            str(row["runtime_evidence_digest"])
            if row["runtime_evidence_digest"]
            else None
        ),
        "hardware_assurance_digest": (
            str(row["hardware_assurance_digest"])
            if row["hardware_assurance_digest"]
            else None
        ),
        "hardware_verification_receipt_digest": (
            str(row["hardware_verification_receipt_digest"])
            if row["hardware_verification_receipt_digest"]
            else None
        ),
        "hardware_verifier_key_id": (
            str(row["hardware_verifier_key_id"])
            if row["hardware_verifier_key_id"]
            else None
        ),
        "release_identity_digest": (
            str(row["release_identity_digest"])
            if row["release_identity_digest"]
            else None
        ),
        "current_host_identity_digest": (
            str(row["current_host_identity_digest"])
            if row["current_host_identity_digest"]
            else None
        ),
        "proxy_server_statement_digest": (
            str(row["proxy_server_statement_digest"])
            if row["proxy_server_statement_digest"]
            else None
        ),
        "trust_profile_digest": (
            str(row["trust_profile_digest"]) if row["trust_profile_digest"] else None
        ),
        "completion_identity_digest": (
            str(row["completion_identity_digest"])
            if row["completion_identity_digest"]
            else None
        ),
        "final_authority_key_id": (
            str(row["final_authority_key_id"])
            if row["final_authority_key_id"]
            else None
        ),
        "final_consumption_id": (
            str(row["final_consumption_id"]) if row["final_consumption_id"] else None
        ),
        "final_receipt_digest": (
            str(row["final_receipt_digest"]) if row["final_receipt_digest"] else None
        ),
        "created_at": str(row["created_at"]),
        "updated_at": str(row["updated_at"]),
        "expires_at": str(row["expires_at"]),
        "terminal_at": str(row["terminal_at"]) if row["terminal_at"] else None,
    }


def _row_to_setup_evidence(row: Any) -> dict[str, Any]:
    return {
        "id": str(row["id"]),
        "session_id": str(row["session_id"]),
        "kind": str(row["kind"]),
        "document": loads(row["evidence_json"], {}),
        "evidence_digest": str(row["evidence_digest"]),
        "verifier_key_id": str(row["verifier_key_id"]),
        "observed_at": str(row["observed_at"]),
        "created_at": str(row["created_at"]),
    }


def _row_to_setup_event(row: Any) -> dict[str, Any]:
    return {
        "id": str(row["id"]),
        "session_id": str(row["session_id"]),
        "sequence": int(row["sequence"]),
        "transition": str(row["transition"]),
        "actor_id": str(row["actor_id"]),
        "payload_digest": str(row["payload_digest"]),
        "event": loads(row["event_json"], {}),
        "created_at": str(row["created_at"]),
        "audit_status": str(row["audit_status"]),
        "audit_claim_id": str(row["audit_claim_id"]) if row["audit_claim_id"] else None,
        "audit_claimed_at": str(row["audit_claimed_at"])
        if row["audit_claimed_at"]
        else None,
        "audit_attempts": int(row["audit_attempts"] or 0),
        "audited_at": str(row["audited_at"]) if row["audited_at"] else None,
        "audit_event_hash": str(row["audit_event_hash"])
        if row["audit_event_hash"]
        else None,
        "audit_last_error": str(row["audit_last_error"])
        if row["audit_last_error"]
        else None,
    }


def _lock_setup_sessions(conn: Any) -> None:
    if isinstance(conn, PostgresMetadataConnection):
        conn.execute("SELECT pg_advisory_xact_lock(?)", (_SETUP_SESSION_LOCK_KEY,))
    elif not conn.in_transaction:
        conn.execute("BEGIN IMMEDIATE")


def _setup_outbox_count(conn: Any) -> int:
    row = conn.execute(
        "SELECT COUNT(*) AS count FROM setup_session_events "
        "WHERE audit_status IN ('pending', 'claimed')"
    ).fetchone()
    return int(row["count"] if row else 0)


def _ensure_setup_outbox_capacity(conn: Any, additional: int) -> None:
    if additional < 0:
        raise SetupSessionValidationError(
            "setup outbox capacity reservation is invalid"
        )
    if _setup_outbox_count(conn) + additional > SETUP_SESSION_AUDIT_OUTBOX_MAX_PENDING:
        raise SetupSessionCapacityError("setup session audit outbox is at capacity")


def _insert_setup_event(
    conn: Any,
    *,
    session_id: str,
    transition: str,
    actor_id: str,
    from_phase: str | None,
    to_phase: str,
    binding_updates: dict[str, Any],
    evidence_digests: list[str],
    details: dict[str, Any],
    created_at: str,
) -> dict[str, Any]:
    sequence_row = conn.execute(
        "SELECT COALESCE(MAX(sequence), 0) AS sequence, COUNT(*) AS count "
        "FROM setup_session_events WHERE session_id = ?",
        (session_id,),
    ).fetchone()
    event_count = int(sequence_row["count"] if sequence_row else 0)
    if event_count >= SETUP_SESSION_EVENT_MAX_COUNT:
        raise SetupSessionCapacityError("setup session event capacity is exhausted")
    sequence = int(sequence_row["sequence"] if sequence_row else 0) + 1
    document = {
        "version": "serverware.setupTransition/v1",
        "setup_session_id": session_id,
        "transition": transition,
        "from_phase": from_phase,
        "to_phase": to_phase,
        "binding_updates": binding_updates,
        "evidence_digests": evidence_digests,
        "details": details,
    }
    event_json = _setup_canonical_json(
        document,
        maximum_bytes=SETUP_SESSION_EVENT_MAX_BYTES,
        label="setup transition event",
    )
    event_id = str(uuid.uuid4())
    conn.execute(
        """
        INSERT INTO setup_session_events (
            id, session_id, sequence, transition, actor_id, payload_digest,
            event_json, created_at, audit_status, audit_attempts
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', 0)
        """,
        (
            event_id,
            session_id,
            sequence,
            transition,
            actor_id,
            _setup_sha256(event_json),
            event_json,
            created_at,
        ),
    )
    row = conn.execute(
        "SELECT * FROM setup_session_events WHERE id = ?", (event_id,)
    ).fetchone()
    return _row_to_setup_event(row)


def _expire_and_prune_setup_sessions(
    conn: Any, now: datetime, *, reserve_outbox: int = 0
) -> dict[str, int]:
    now_s = now.isoformat()
    expiring = conn.execute(
        "SELECT * FROM setup_sessions WHERE status = 'active' AND expires_at <= ? "
        "ORDER BY expires_at ASC, id ASC",
        (now_s,),
    ).fetchall()
    _ensure_setup_outbox_capacity(conn, len(expiring) + reserve_outbox)
    expired_count = 0
    for row in expiring:
        existing_events = conn.execute(
            "SELECT COUNT(*) AS count FROM setup_session_events WHERE session_id = ?",
            (row["id"],),
        ).fetchone()
        if (
            int(existing_events["count"] if existing_events else 0)
            >= SETUP_SESSION_EVENT_MAX_COUNT
        ):
            raise SetupSessionCapacityError(
                f"setup session {row['id']} has no event capacity for expiration"
            )
        result = conn.execute(
            """
            UPDATE setup_sessions
            SET status = 'expired', phase = 'expired', revision = revision + 1,
                updated_at = ?, terminal_at = expires_at
            WHERE id = ? AND status = 'active' AND revision = ?
            """,
            (now_s, row["id"], row["revision"]),
        )
        if result.rowcount != 1:
            raise SetupSessionStaleRevisionError(
                str(row["id"]), int(row["revision"]), int(row["revision"]) + 1
            )
        _insert_setup_event(
            conn,
            session_id=str(row["id"]),
            transition="expire",
            actor_id="system:setup-expiry",
            from_phase=str(row["phase"]),
            to_phase="expired",
            binding_updates={},
            evidence_digests=[],
            details={"reason": "ttl_expired"},
            created_at=now_s,
        )
        expired_count += 1

    cutoff = (now - timedelta(seconds=SETUP_SESSION_RETENTION_SECONDS)).isoformat()
    deleted = conn.execute(
        """
        DELETE FROM setup_sessions
        WHERE status IN ('complete', 'cancelled', 'failed', 'superseded', 'expired')
          AND terminal_at IS NOT NULL
          AND terminal_at <= ?
          AND enrollment_verifier_receipt_digest IS NULL
          AND attestation_challenge_digest IS NULL
          AND runtime_evidence_digest IS NULL
          AND hardware_assurance_digest IS NULL
          AND hardware_verification_receipt_digest IS NULL
          AND final_consumption_id IS NULL
          AND final_receipt_digest IS NULL
          AND NOT EXISTS (
              SELECT 1 FROM setup_session_events
              WHERE setup_session_events.session_id = setup_sessions.id
                AND setup_session_events.audit_status != 'audited'
          )
        """,
        (cutoff,),
    )
    return {"expired": expired_count, "pruned": max(0, int(deleted.rowcount))}


def _expire_setup_sessions_before_mutation(now: datetime) -> None:
    """Commit TTL expiry before a later setup mutation can be rejected."""
    with connect() as conn:
        _lock_setup_sessions(conn)
        _expire_and_prune_setup_sessions(conn, now)


def _validate_setup_bindings(
    values: dict[str, Any], *, partial: bool
) -> dict[str, Any]:
    allowed = _SETUP_BINDING_FIELDS | {"current_assignee_id"}
    unknown = set(values) - allowed
    if unknown:
        raise SetupSessionValidationError(
            "unsupported setup binding fields: " + ", ".join(sorted(unknown))
        )
    validated: dict[str, Any] = {}
    for field, value in values.items():
        if value is None:
            if partial:
                raise SetupSessionValidationError(
                    f"setup binding {field} cannot be cleared"
                )
            validated[field] = None
            continue
        if field == "credential_version":
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise SetupSessionValidationError(
                    "credential_version must be a positive integer"
                )
            validated[field] = value
        elif field in _SETUP_DIGEST_FIELDS:
            validated[field] = _setup_digest(field, value)
        elif field in _SETUP_TIMESTAMP_FIELDS:
            validated[field] = _setup_timestamp(field, value)
        elif field == "attestation_challenge_value":
            validated[field] = _setup_text(field, value, maximum=128)
            if (
                len(validated[field]) < 43
                or re.fullmatch(r"[A-Za-z0-9_-]+", validated[field]) is None
            ):
                raise SetupSessionValidationError(
                    "attestation_challenge_value must be canonical unpadded base64url"
                )
        elif field == "oauth_provider":
            validated[field] = _setup_text(field, value, maximum=128)
        else:
            validated[field] = _setup_text(field, value, maximum=512)
    credential_id = validated.get("credential_id")
    credential_version = validated.get("credential_version")
    if (credential_id is None) != (credential_version is None) and not partial:
        raise SetupSessionValidationError(
            "credential_id and credential_version must be provided together"
        )
    if (
        not partial
        and validated.get("route_policy_digest") is not None
        and validated.get("route_id") is None
    ):
        raise SetupSessionValidationError("route_policy_digest requires route_id")
    return validated


def _assert_setup_binding_unique(
    conn: Any,
    *,
    field: str,
    value: Any,
    session_id: str | None,
) -> None:
    if field not in _SETUP_UNIQUE_BINDING_FIELDS or value is None:
        return
    sql = f"SELECT id FROM setup_sessions WHERE {field} = ?"
    params: list[Any] = [value]
    if session_id is not None:
        sql += " AND id != ?"
        params.append(session_id)
    row = conn.execute(sql, params).fetchone()
    if row:
        raise SetupSessionValidationError(
            f"setup binding {field} is already assigned to another session"
        )


def _prepare_setup_evidence(
    transition: str,
    evidence: list[dict[str, Any]] | None,
    *,
    created_at: str,
) -> list[dict[str, Any]]:
    items = evidence or []
    evidence_contract = _SETUP_EVIDENCE_TRANSITIONS.get(transition)
    if evidence_contract is None:
        if items:
            raise SetupSessionValidationError(
                f"setup transition {transition} does not accept evidence"
            )
        return []
    if len(items) != 1:
        raise SetupSessionValidationError(
            f"setup transition {transition} requires exactly one evidence record"
        )
    item = items[0]
    if not isinstance(item, dict) or set(item) - {
        "kind",
        "document",
        "verifier_key_id",
        "observed_at",
    }:
        raise SetupSessionValidationError("setup evidence contains unsupported fields")
    required_kind = evidence_contract[0]
    if item.get("kind") != required_kind:
        raise SetupSessionValidationError(
            f"setup transition {transition} requires evidence kind {required_kind}"
        )
    document_json = _setup_canonical_json(
        item.get("document"),
        maximum_bytes=SETUP_SESSION_EVIDENCE_MAX_BYTES,
        label="setup evidence",
    )
    return [
        {
            "id": str(uuid.uuid4()),
            "kind": required_kind,
            "evidence_json": document_json,
            "evidence_digest": _setup_sha256(document_json),
            "verifier_key_id": _setup_text(
                "verifier_key_id", item.get("verifier_key_id"), maximum=512
            ),
            "observed_at": _setup_timestamp(
                "observed_at", item.get("observed_at", created_at)
            ),
            "created_at": created_at,
        }
    ]


def create_setup_session(
    *,
    owner_id: str,
    current_assignee_id: str | None = None,
    template_id: str | None = None,
    principal_id: str | None = None,
    route_id: str | None = None,
    route_policy_digest: str | None = None,
    credential_id: str | None = None,
    credential_version: int | None = None,
    policy_hash: str | None = None,
    assignment_digest: str | None = None,
    ttl_seconds: int | None = None,
    actor_id: str | None = None,
) -> dict[str, Any]:
    owner = _setup_text("owner_id", owner_id, maximum=512)
    actor = _setup_text("actor_id", actor_id or owner, maximum=512)
    effective_ttl = SETUP_SESSION_TTL_SECONDS if ttl_seconds is None else ttl_seconds
    if (
        isinstance(effective_ttl, bool)
        or not isinstance(effective_ttl, int)
        or not 300 <= effective_ttl <= 604_800
    ):
        raise SetupSessionValidationError(
            "setup session ttl_seconds must be between 300 and 604800"
        )
    bindings = _validate_setup_bindings(
        {
            "current_assignee_id": current_assignee_id,
            "template_id": template_id,
            "principal_id": principal_id,
            "route_id": route_id,
            "route_policy_digest": route_policy_digest,
            "credential_id": credential_id,
            "credential_version": credential_version,
            "policy_hash": policy_hash,
            "assignment_digest": assignment_digest,
        },
        partial=False,
    )
    now = utcnow()
    now_s = now.isoformat()
    session_id = str(uuid.uuid4())
    expires_at = (now + timedelta(seconds=effective_ttl)).isoformat()
    _expire_setup_sessions_before_mutation(now)
    with connect() as conn:
        _lock_setup_sessions(conn)
        _ensure_setup_outbox_capacity(conn, 1)
        active_row = conn.execute(
            "SELECT COUNT(*) AS count FROM setup_sessions "
            "WHERE status = 'active' AND expires_at > ?",
            (now_s,),
        ).fetchone()
        if int(active_row["count"] if active_row else 0) >= SETUP_SESSION_MAX_ACTIVE:
            raise SetupSessionCapacityError(
                "active setup session capacity is exhausted"
            )
        total_row = conn.execute(
            "SELECT COUNT(*) AS count FROM setup_sessions"
        ).fetchone()
        if int(total_row["count"] if total_row else 0) >= SETUP_SESSION_MAX_RETAINED:
            raise SetupSessionCapacityError(
                "retained setup session capacity is exhausted"
            )
        for field, value in bindings.items():
            _assert_setup_binding_unique(
                conn, field=field, value=value, session_id=None
            )
        conn.execute(
            """
            INSERT INTO setup_sessions (
                id, owner_id, current_assignee_id, status, phase, revision,
                template_id, principal_id, route_id, route_policy_digest,
                credential_id, credential_version,
                policy_hash, assignment_digest, created_at, updated_at, expires_at
            ) VALUES (?, ?, ?, 'active', 'created', 0, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                session_id,
                owner,
                bindings["current_assignee_id"],
                bindings["template_id"],
                bindings["principal_id"],
                bindings["route_id"],
                bindings["route_policy_digest"],
                bindings["credential_id"],
                bindings["credential_version"],
                bindings["policy_hash"],
                bindings["assignment_digest"],
                now_s,
                now_s,
                expires_at,
            ),
        )
        _insert_setup_event(
            conn,
            session_id=session_id,
            transition="create",
            actor_id=actor,
            from_phase=None,
            to_phase="created",
            binding_updates={},
            evidence_digests=[],
            details={},
            created_at=now_s,
        )
        row = conn.execute(
            "SELECT * FROM setup_sessions WHERE id = ?", (session_id,)
        ).fetchone()
    return _row_to_setup_session(row)


def get_setup_session(
    session_id: str,
    *,
    include_evidence: bool = False,
    include_events: bool = False,
) -> dict[str, Any] | None:
    setup_id = _setup_text("session_id", session_id, maximum=64)
    with connect() as conn:
        row = conn.execute(
            "SELECT * FROM setup_sessions WHERE id = ?", (setup_id,)
        ).fetchone()
        if not row:
            return None
        item = _row_to_setup_session(row)
        if include_evidence:
            evidence_rows = conn.execute(
                "SELECT * FROM setup_session_evidence WHERE session_id = ? "
                "ORDER BY created_at ASC, id ASC",
                (setup_id,),
            ).fetchall()
            item["evidence"] = [
                _row_to_setup_evidence(value) for value in evidence_rows
            ]
        if include_events:
            event_rows = conn.execute(
                "SELECT * FROM setup_session_events WHERE session_id = ? ORDER BY sequence ASC",
                (setup_id,),
            ).fetchall()
            item["events"] = [_row_to_setup_event(value) for value in event_rows]
    return item


def list_setup_sessions(
    *,
    owner_id: str | None = None,
    current_assignee_id: str | None = None,
    status: str | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 500:
        raise SetupSessionValidationError(
            "setup session list limit must be between 1 and 500"
        )
    where: list[str] = []
    params: list[Any] = []
    if owner_id is not None:
        where.append("owner_id = ?")
        params.append(_setup_text("owner_id", owner_id, maximum=512))
    if current_assignee_id is not None:
        where.append("current_assignee_id = ?")
        params.append(
            _setup_text("current_assignee_id", current_assignee_id, maximum=512)
        )
    if status is not None:
        valid_statuses = {"active"} | _SETUP_TERMINAL_STATUSES
        if status not in valid_statuses:
            raise SetupSessionValidationError("unsupported setup session status")
        where.append("status = ?")
        params.append(status)
    sql = "SELECT * FROM setup_sessions"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY updated_at DESC, id DESC LIMIT ?"
    params.append(limit)
    with connect() as conn:
        rows = conn.execute(sql, params).fetchall()
    return [_row_to_setup_session(row) for row in rows]


def get_setup_session_by_oauth_pending_credential(
    pending_credential_id: str,
) -> dict[str, Any] | None:
    pending_id = _setup_text(
        "oauth_pending_credential_id",
        pending_credential_id,
        maximum=512,
    )
    with connect() as conn:
        row = conn.execute(
            "SELECT * FROM setup_sessions WHERE oauth_pending_credential_id = ?",
            (pending_id,),
        ).fetchone()
    return _row_to_setup_session(row) if row else None


def _prepare_setup_oauth_callback_binding(
    *,
    session_id: str | None,
    expected_revision: int | None,
    actor_id: str | None,
    provider_id: str | None,
    state_digest: str | None,
) -> dict[str, Any] | None:
    values = (
        session_id,
        expected_revision,
        actor_id,
        provider_id,
        state_digest,
    )
    if all(value is None for value in values):
        return None
    if any(value is None for value in values):
        raise SetupSessionValidationError(
            "setup OAuth callback binding must be provided completely"
        )
    setup_id = _setup_text("setup_session_id", session_id, maximum=64)
    actor = _setup_text("setup_actor_id", actor_id, maximum=512)
    provider = _setup_text("setup_oauth_provider", provider_id, maximum=128)
    digest = _setup_digest("setup_oauth_state_digest", state_digest)
    if (
        isinstance(expected_revision, bool)
        or not isinstance(expected_revision, int)
        or expected_revision < 0
    ):
        raise SetupSessionValidationError(
            "setup expected revision must be a non-negative integer"
        )
    return {
        "session_id": setup_id,
        "expected_revision": expected_revision,
        "actor_id": actor,
        "provider_id": provider,
        "state_digest": digest,
    }


def _lock_setup_oauth_callback_binding(
    conn: Any, binding: dict[str, Any]
) -> dict[str, Any]:
    _lock_setup_sessions(conn)
    _ensure_setup_outbox_capacity(conn, 1)
    row = conn.execute(
        "SELECT * FROM setup_sessions WHERE id = ?", (binding["session_id"],)
    ).fetchone()
    if row is None:
        raise SetupSessionNotFoundError(
            f"setup session not found: {binding['session_id']}"
        )
    current_revision = int(row["revision"])
    if current_revision != binding["expected_revision"]:
        raise SetupSessionStaleRevisionError(
            binding["session_id"],
            int(binding["expected_revision"]),
            current_revision,
        )
    if not (
        row["status"] == "active"
        and row["phase"] == "oauth_started"
        and row["owner_id"] == binding["actor_id"]
        and row["oauth_provider"] == binding["provider_id"]
        and isinstance(row["oauth_state_digest"], str)
        and hmac.compare_digest(
            str(row["oauth_state_digest"]), str(binding["state_digest"])
        )
    ):
        raise SetupSessionValidationError(
            "OAuth callback no longer matches the active setup session"
        )
    return dict(row)


def transition_setup_session(
    session_id: str,
    *,
    expected_revision: int,
    transition: str,
    actor_id: str,
    updates: dict[str, Any] | None = None,
    evidence: list[dict[str, Any]] | None = None,
    event: dict[str, Any] | None = None,
    required_active_credential_id: str | None = None,
    required_active_credential_version: int | None = None,
    _connection: Any | None = None,
    _now: datetime | None = None,
) -> dict[str, Any]:
    setup_id = _setup_text("session_id", session_id, maximum=64)
    actor = _setup_text("actor_id", actor_id, maximum=512)
    if (
        isinstance(expected_revision, bool)
        or not isinstance(expected_revision, int)
        or expected_revision < 0
    ):
        raise SetupSessionValidationError(
            "expected_revision must be a non-negative integer"
        )
    contract = _SETUP_TRANSITIONS.get(transition)
    if not contract:
        raise SetupSessionValidationError(f"unsupported setup transition: {transition}")
    requested_updates = updates or {}
    if not isinstance(requested_updates, dict):
        raise SetupSessionValidationError("setup transition updates must be an object")
    if set(requested_updates) - contract["updates"]:
        raise SetupSessionValidationError(
            f"setup transition {transition} contains unsupported update fields"
        )
    if (required_active_credential_id is None) != (
        required_active_credential_version is None
    ):
        raise SetupSessionValidationError(
            "active credential ID and generation must be provided together"
        )
    if required_active_credential_id is not None:
        if transition != "activate_policy":
            raise SetupSessionValidationError(
                "active credential generation checks are only valid for policy activation"
            )
        _setup_text(
            "required_active_credential_id",
            required_active_credential_id,
            maximum=512,
        )
        if (
            isinstance(required_active_credential_version, bool)
            or not isinstance(required_active_credential_version, int)
            or required_active_credential_version < 1
        ):
            raise SetupSessionValidationError(
                "required active credential generation must be a positive integer"
            )
    validated_updates = _validate_setup_bindings(requested_updates, partial=True)
    details = event or {}
    details_json = _setup_canonical_json(
        details,
        maximum_bytes=SETUP_SESSION_EVENT_MAX_BYTES,
        label="setup transition details",
    )
    details = loads(details_json, {})
    now = _setup_now(_now)
    now_s = now.isoformat()
    prepared_evidence = _prepare_setup_evidence(transition, evidence, created_at=now_s)
    if prepared_evidence:
        receipt = prepared_evidence[0]
        if transition == "record_enrollment_evidence":
            validated_updates.update(
                {
                    "enrollment_verifier_receipt_digest": receipt["evidence_digest"],
                    "enrollment_verifier_key_id": receipt["verifier_key_id"],
                }
            )
        elif transition == "record_runtime_evidence":
            validated_updates["runtime_evidence_digest"] = receipt["evidence_digest"]
        elif transition == "record_hardware_receipt":
            validated_updates.update(
                {
                    "hardware_verifier_key_id": receipt["verifier_key_id"],
                }
            )
        elif transition == "record_final_challenge_receipt":
            validated_updates.update(
                {
                    "final_authority_key_id": receipt["verifier_key_id"],
                    "final_receipt_digest": receipt["evidence_digest"],
                }
            )

    if _connection is None:
        _expire_setup_sessions_before_mutation(now)
    connection_scope = (
        connect() if _connection is None else contextlib.nullcontext(_connection)
    )
    with connection_scope as conn:
        _lock_setup_sessions(conn)
        _ensure_setup_outbox_capacity(conn, 1)
        row = conn.execute(
            "SELECT * FROM setup_sessions WHERE id = ?", (setup_id,)
        ).fetchone()
        if not row:
            raise SetupSessionNotFoundError(f"setup session not found: {setup_id}")
        current_revision = int(row["revision"])
        if current_revision != expected_revision:
            raise SetupSessionStaleRevisionError(
                setup_id, expected_revision, current_revision
            )
        if row["status"] == "active" and now >= datetime.fromisoformat(
            str(row["expires_at"])
        ):
            raise SetupSessionValidationError("setup session has expired")
        if row["status"] != "active":
            raise SetupSessionValidationError(
                f"setup session is terminal with status {row['status']}"
            )
        phases = contract["phases"]
        if phases is not None and row["phase"] not in phases:
            raise SetupSessionValidationError(
                f"setup transition {transition} is invalid from phase {row['phase']}"
            )
        if required_active_credential_id is not None:
            if (
                row["credential_id"] != required_active_credential_id
                or int(row["credential_version"] or 0)
                != required_active_credential_version
            ):
                raise SetupSessionValidationError(
                    "setup policy activation credential binding changed"
                )
            _lock_credential_mutation(conn, required_active_credential_id)
            active_credential = conn.execute(
                "SELECT lifecycle_status, credential_version FROM credentials WHERE id = ?",
                (required_active_credential_id,),
            ).fetchone()
            if not (
                active_credential is not None
                and str(active_credential["lifecycle_status"] or "active") == "active"
                and int(active_credential["credential_version"] or 0)
                == required_active_credential_version
            ):
                raise SetupSessionValidationError(
                    "active credential generation no longer matches the setup assignment"
                )
        next_phase = contract["next_phase"] or str(row["phase"])
        next_status = contract.get("status", "active")
        terminal_at = now_s if next_status in _SETUP_TERMINAL_STATUSES else None
        for field, value in validated_updates.items():
            replacing_expired_challenge = (
                transition == "bind_attestation_challenge"
                and field
                in {
                    "attestation_challenge_digest",
                    "attestation_challenge_issued_at",
                    "attestation_challenge_expires_at",
                    "attestation_challenge_value",
                }
                and row["attestation_challenge_expires_at"] is not None
                and now >= datetime.fromisoformat(
                    str(row["attestation_challenge_expires_at"])
                )
                and row["hardware_verification_receipt_digest"] is None
            )
            if (
                field != "current_assignee_id"
                and row[field] is not None
                and row[field] != value
                and not replacing_expired_challenge
            ):
                raise SetupSessionValidationError(
                    f"immutable setup binding {field} cannot be rebound"
                )
            _assert_setup_binding_unique(
                conn, field=field, value=value, session_id=setup_id
            )

        effective = dict(row)
        effective.update(validated_updates)
        if transition == "bind_oauth_flow" and (
            not effective.get("oauth_provider")
            or not effective.get("oauth_state_digest")
        ):
            raise SetupSessionValidationError(
                "bind_oauth_flow requires provider and state digest"
            )
        if transition == "bind_pending_credential" and not effective.get(
            "oauth_pending_credential_id"
        ):
            raise SetupSessionValidationError(
                "bind_pending_credential requires a pending credential ID"
            )
        if transition == "bind_credential" and (
            not effective.get("credential_id")
            or effective.get("credential_version") is None
        ):
            raise SetupSessionValidationError(
                "bind_credential requires an exact credential generation"
            )
        if transition in {"bind_candidate", "activate_policy"} and (
            not effective.get("policy_hash") or not effective.get("assignment_digest")
        ):
            raise SetupSessionValidationError(
                f"{transition} requires policy and assignment digests"
            )
        if transition == "bind_candidate" and not effective.get("canary_id"):
            raise SetupSessionValidationError("bind_candidate requires a canary ID")
        if transition == "bind_candidate" and (
            not effective.get("route_id") or not effective.get("route_policy_digest")
        ):
            raise SetupSessionValidationError(
                "bind_candidate requires an exact route and reviewed route policy digest"
            )
        if transition == "bind_enrollment" and (
            not effective.get("enrollment_session_id")
            or not effective.get("enrollment_packet_digest")
            or not effective.get("verifier_nonce_hash")
        ):
            raise SetupSessionValidationError(
                "bind_enrollment requires session, packet, and verifier nonce digests"
            )
        challenge_fields = (
            "attestation_challenge_digest",
            "attestation_challenge_issued_at",
            "attestation_challenge_expires_at",
            "attestation_challenge_value",
        )
        if transition == "bind_attestation_challenge":
            if any(not effective.get(field) for field in challenge_fields):
                raise SetupSessionValidationError(
                    "bind_attestation_challenge requires digest, issue, and expiry bindings"
                )
            challenge_issued_at = datetime.fromisoformat(
                str(effective["attestation_challenge_issued_at"])
            )
            challenge_expires_at = datetime.fromisoformat(
                str(effective["attestation_challenge_expires_at"])
            )
            if not challenge_issued_at <= now < challenge_expires_at:
                raise SetupSessionValidationError(
                    "attestation challenge must be currently valid when bound"
                )
            try:
                challenge_value = str(effective["attestation_challenge_value"])
                challenge_bytes = base64.b64decode(
                    challenge_value + "=" * (-len(challenge_value) % 4),
                    altchars=b"-_",
                    validate=True,
                )
            except (TypeError, ValueError) as exc:
                raise SetupSessionValidationError(
                    "attestation challenge value is invalid"
                ) from exc
            canonical_challenge = (
                base64.urlsafe_b64encode(challenge_bytes)
                .decode("ascii")
                .rstrip("=")
            )
            if not (
                32 <= len(challenge_bytes) <= 64
                and hmac.compare_digest(canonical_challenge, challenge_value)
                and hmac.compare_digest(
                    "sha256:" + hashlib.sha256(challenge_bytes).hexdigest(),
                    str(effective["attestation_challenge_digest"]),
                )
            ):
                raise SetupSessionValidationError(
                    "attestation challenge value does not match its digest"
                )
        if transition in {"record_hardware_receipt", "record_final_challenge_receipt"}:
            if any(not effective.get(field) for field in challenge_fields):
                raise SetupSessionValidationError(
                    f"{transition} requires an attestation challenge binding"
                )
        if transition == "record_hardware_receipt":
            if now >= datetime.fromisoformat(
                str(effective["attestation_challenge_expires_at"])
            ):
                raise SetupSessionValidationError(
                    "record_hardware_receipt requires an unexpired attestation challenge"
                )
        if transition == "record_hardware_receipt":
            required_hardware_bindings = (
                "runtime_evidence_digest",
                "hardware_assurance_digest",
                "hardware_verification_receipt_digest",
                "hardware_verifier_key_id",
                "release_identity_digest",
                "current_host_identity_digest",
                "proxy_server_statement_digest",
                "trust_profile_digest",
            )
            if any(not effective.get(field) for field in required_hardware_bindings):
                raise SetupSessionValidationError(
                    "record_hardware_receipt requires the complete verified binding set"
                )
        if transition == "record_final_challenge_receipt":
            required_final_bindings = (
                "hardware_assurance_digest",
                "hardware_verification_receipt_digest",
                "hardware_verifier_key_id",
                "release_identity_digest",
                "current_host_identity_digest",
                "proxy_server_statement_digest",
                "trust_profile_digest",
                "completion_identity_digest",
                "final_authority_key_id",
                "final_consumption_id",
                "final_receipt_digest",
            )
            if any(not effective.get(field) for field in required_final_bindings):
                raise SetupSessionValidationError(
                    "record_final_challenge_receipt requires the complete final binding set"
                )
        if transition == "system_complete":
            receipt_event = conn.execute(
                "SELECT audit_status, audited_at, audit_event_hash "
                "FROM setup_session_events WHERE session_id = ? "
                "AND transition = 'record_final_challenge_receipt' "
                "ORDER BY sequence DESC LIMIT 1",
                (setup_id,),
            ).fetchone()
            if not receipt_event or not (
                receipt_event["audit_status"] == "audited"
                and receipt_event["audited_at"]
                and receipt_event["audit_event_hash"]
            ):
                raise SetupSessionValidationError(
                    "system_complete requires the final receipt transition to be durably audited"
                )

        evidence_count_row = conn.execute(
            "SELECT COUNT(*) AS count FROM setup_session_evidence WHERE session_id = ?",
            (setup_id,),
        ).fetchone()
        if (
            int(evidence_count_row["count"] if evidence_count_row else 0)
            + len(prepared_evidence)
            > SETUP_SESSION_EVIDENCE_MAX_COUNT
        ):
            raise SetupSessionCapacityError(
                "setup session evidence capacity is exhausted"
            )
        event_count_row = conn.execute(
            "SELECT COUNT(*) AS count FROM setup_session_events WHERE session_id = ?",
            (setup_id,),
        ).fetchone()
        event_count = int(event_count_row["count"] if event_count_row else 0)
        event_limit = SETUP_SESSION_EVENT_MAX_COUNT
        if next_status == "active":
            event_limit -= 1
        if event_count >= event_limit:
            raise SetupSessionCapacityError("setup session event capacity is exhausted")
        for evidence_item in prepared_evidence:
            same_kind = conn.execute(
                "SELECT id FROM setup_session_evidence "
                "WHERE session_id = ? AND kind = ?",
                (setup_id, evidence_item["kind"]),
            ).fetchone()
            if same_kind:
                raise SetupSessionValidationError(
                    "setup security evidence kind was already recorded for this session"
                )
            replay = conn.execute(
                "SELECT id FROM setup_session_evidence WHERE evidence_digest = ?",
                (evidence_item["evidence_digest"],),
            ).fetchone()
            if replay:
                raise SetupSessionValidationError(
                    "setup security evidence digest replay was rejected"
                )

        assignments = {
            "status": next_status,
            "phase": next_phase,
            "updated_at": now_s,
            "terminal_at": terminal_at,
            **validated_updates,
        }
        set_clause = ", ".join(f"{field} = ?" for field in assignments)
        params = list(assignments.values()) + [setup_id, expected_revision]
        changed = conn.execute(
            f"UPDATE setup_sessions SET {set_clause}, revision = revision + 1 "
            "WHERE id = ? AND revision = ? AND status = 'active'",
            params,
        )
        if changed.rowcount != 1:
            current = conn.execute(
                "SELECT revision FROM setup_sessions WHERE id = ?", (setup_id,)
            ).fetchone()
            if not current:
                raise SetupSessionNotFoundError(f"setup session not found: {setup_id}")
            raise SetupSessionStaleRevisionError(
                setup_id, expected_revision, int(current["revision"])
            )
        for evidence_item in prepared_evidence:
            conn.execute(
                """
                INSERT INTO setup_session_evidence (
                    id, session_id, kind, evidence_json, evidence_digest,
                    verifier_key_id, observed_at, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    evidence_item["id"],
                    setup_id,
                    evidence_item["kind"],
                    evidence_item["evidence_json"],
                    evidence_item["evidence_digest"],
                    evidence_item["verifier_key_id"],
                    evidence_item["observed_at"],
                    evidence_item["created_at"],
                ),
            )
        _insert_setup_event(
            conn,
            session_id=setup_id,
            transition=transition,
            actor_id=actor,
            from_phase=str(row["phase"]),
            to_phase=next_phase,
            binding_updates=validated_updates,
            evidence_digests=[item["evidence_digest"] for item in prepared_evidence],
            details=details,
            created_at=now_s,
        )
        result = conn.execute(
            "SELECT * FROM setup_sessions WHERE id = ?", (setup_id,)
        ).fetchone()
    return _row_to_setup_session(result)


def claim_or_handoff_setup_session(
    session_id: str,
    *,
    expected_revision: int,
    actor_id: str,
    assignee_id: str,
    handoff: bool = False,
) -> dict[str, Any]:
    assignee = _setup_text("assignee_id", assignee_id, maximum=512)
    transition = "handoff" if handoff else "claim"
    return transition_setup_session(
        session_id,
        expected_revision=expected_revision,
        transition=transition,
        actor_id=actor_id,
        updates={"current_assignee_id": assignee},
        event={"mode": transition},
    )


def cancel_setup_session(
    session_id: str,
    *,
    expected_revision: int,
    actor_id: str,
    reason: str | None = None,
) -> dict[str, Any]:
    details: dict[str, Any] = {}
    if reason is not None:
        details["reason"] = _setup_text("reason", reason, maximum=2048)
    return transition_setup_session(
        session_id,
        expected_revision=expected_revision,
        transition="cancel",
        actor_id=actor_id,
        event=details,
    )


def prune_setup_sessions(*, now: datetime | None = None) -> dict[str, int]:
    current = _setup_now(now)
    with connect() as conn:
        _lock_setup_sessions(conn)
        return _expire_and_prune_setup_sessions(conn, current)


def claim_setup_session_audit_outbox(
    *,
    worker_id: str,
    limit: int = 100,
    now: datetime | None = None,
    claim_ttl_seconds: int | None = None,
) -> list[dict[str, Any]]:
    worker = _setup_text("worker_id", worker_id, maximum=128)
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 500:
        raise SetupSessionValidationError(
            "setup outbox claim limit must be between 1 and 500"
        )
    ttl = (
        SETUP_SESSION_AUDIT_CLAIM_TTL_SECONDS
        if claim_ttl_seconds is None
        else claim_ttl_seconds
    )
    if isinstance(ttl, bool) or not isinstance(ttl, int) or not 5 <= ttl <= 3600:
        raise SetupSessionValidationError(
            "setup outbox claim ttl must be between 5 and 3600"
        )
    current = _setup_now(now)
    now_s = current.isoformat()
    stale_before = (current - timedelta(seconds=ttl)).isoformat()
    claim_id = f"{worker}:{uuid.uuid4()}"
    with connect() as conn:
        _lock_setup_sessions(conn)
        conn.execute(
            """
            UPDATE setup_session_events
            SET audit_status = 'pending', audit_claim_id = NULL, audit_claimed_at = NULL
            WHERE audit_status = 'claimed' AND audit_claimed_at <= ?
            """,
            (stale_before,),
        )
        rows = conn.execute(
            "SELECT candidate.* FROM setup_session_events AS candidate "
            "WHERE candidate.audit_status = 'pending' "
            "AND NOT EXISTS ("
            "SELECT 1 FROM setup_session_events AS predecessor "
            "WHERE predecessor.session_id = candidate.session_id "
            "AND predecessor.sequence < candidate.sequence "
            "AND predecessor.audit_status != 'audited'"
            ") ORDER BY candidate.created_at ASC, candidate.id ASC LIMIT ?",
            (limit,),
        ).fetchall()
        claimed: list[dict[str, Any]] = []
        for row in rows:
            updated = conn.execute(
                """
                UPDATE setup_session_events
                SET audit_status = 'claimed', audit_claim_id = ?, audit_claimed_at = ?,
                    audit_attempts = audit_attempts + 1, audit_last_error = NULL
                WHERE id = ? AND audit_status = 'pending'
                """,
                (claim_id, now_s, row["id"]),
            )
            if updated.rowcount == 1:
                value = conn.execute(
                    "SELECT * FROM setup_session_events WHERE id = ?", (row["id"],)
                ).fetchone()
                item = _row_to_setup_event(value)
                item["audit_event_type"] = f"setup.{item['transition']}"
                item["audit_idempotency_key"] = item["id"]
                claimed.append(item)
    return claimed


def finish_setup_session_audit_outbox(
    event_id: str,
    *,
    claim_id: str,
    audit_event_hash: str | None = None,
    error: str | None = None,
    now: datetime | None = None,
) -> bool:
    item_id = _setup_text("event_id", event_id, maximum=64)
    claim = _setup_text("claim_id", claim_id, maximum=256)
    if (audit_event_hash is None) == (error is None):
        raise SetupSessionValidationError(
            "finish setup outbox requires exactly one of audit_event_hash or error"
        )
    current = _setup_now(now).isoformat()
    with connect() as conn:
        _lock_setup_sessions(conn)
        if error is not None:
            message = _setup_text("error", error, maximum=2048)
            result = conn.execute(
                """
                UPDATE setup_session_events
                SET audit_status = 'pending', audit_claim_id = NULL,
                    audit_claimed_at = NULL, audit_last_error = ?
                WHERE id = ? AND audit_status = 'claimed' AND audit_claim_id = ?
                """,
                (message, item_id, claim),
            )
        else:
            event_hash = _setup_digest("audit_event_hash", audit_event_hash)
            result = conn.execute(
                """
                UPDATE setup_session_events
                SET audit_status = 'audited', audited_at = ?, audit_event_hash = ?,
                    audit_claim_id = NULL, audit_claimed_at = NULL, audit_last_error = NULL
                WHERE id = ? AND audit_status = 'claimed' AND audit_claim_id = ?
                """,
                (current, event_hash, item_id, claim),
            )
    return result.rowcount == 1


def get_policy_high_water() -> dict[str, Any] | None:
    with connect() as conn:
        row = conn.execute(
            "SELECT policy_id, sequence, rollback_epoch, policy_hash, updated_at "
            "FROM policy_high_water WHERE scope = ?",
            ("active",),
        ).fetchone()
    if not row:
        return None
    return {
        "policy_id": str(row["policy_id"]),
        "sequence": int(row["sequence"]),
        "rollback_epoch": int(row["rollback_epoch"]),
        "policy_hash": str(row["policy_hash"]),
        "updated_at": str(row["updated_at"]),
    }


def advance_policy_high_water(
    *,
    policy_id: str,
    sequence: int,
    rollback_epoch: int,
    policy_hash: str,
) -> dict[str, Any]:
    if not policy_id or len(policy_id.encode("utf-8")) > 256:
        raise MetadataStoreError("policy id must be a non-empty string up to 256 bytes")
    if sequence < 1:
        raise MetadataStoreError("policy sequence must be a positive integer")
    if rollback_epoch < 1:
        raise MetadataStoreError("policy rollback epoch must be a positive integer")
    if not isinstance(policy_hash, str) or not re.fullmatch(
        r"sha256:[0-9a-f]{64}", policy_hash
    ):
        raise MetadataStoreError("policy hash must be a canonical SHA-256 digest")

    now_s = iso_now()
    with connect() as conn:
        if isinstance(conn, PostgresMetadataConnection):
            conn.execute(
                "SELECT pg_advisory_xact_lock(?)", (_POLICY_HIGH_WATER_LOCK_KEY,)
            )
        elif not conn.in_transaction:
            conn.execute("BEGIN IMMEDIATE")
        current = conn.execute(
            "SELECT policy_id, sequence, rollback_epoch, policy_hash, updated_at "
            "FROM policy_high_water WHERE scope = ?",
            ("active",),
        ).fetchone()
        if current:
            current_policy_id = str(current["policy_id"])
            current_sequence = int(current["sequence"])
            current_rollback_epoch = int(current["rollback_epoch"])
            current_policy_hash = str(current["policy_hash"])
            if policy_id != current_policy_id:
                raise MetadataStoreError(
                    f"policy id changed from {current_policy_id} to {policy_id}"
                )
            if policy_hash == current_policy_hash:
                if (
                    sequence != current_sequence
                    or rollback_epoch != current_rollback_epoch
                ):
                    raise MetadataStoreError(
                        "policy hash reappeared with different monotonic metadata"
                    )
                return {
                    "policy_id": current_policy_id,
                    "sequence": current_sequence,
                    "rollback_epoch": current_rollback_epoch,
                    "policy_hash": current_policy_hash,
                    "updated_at": str(current["updated_at"]),
                }
            if rollback_epoch < current_rollback_epoch:
                raise MetadataStoreError(
                    f"policy rollback epoch {rollback_epoch} is below persisted high-water "
                    f"{current_rollback_epoch}"
                )
            if sequence <= current_sequence:
                raise MetadataStoreError(
                    f"policy sequence {sequence} does not exceed persisted high-water "
                    f"{current_sequence}"
                )
            conn.execute(
                "UPDATE policy_high_water SET sequence = ?, rollback_epoch = ?, "
                "policy_hash = ?, updated_at = ? WHERE scope = ?",
                (sequence, rollback_epoch, policy_hash, now_s, "active"),
            )
        else:
            conn.execute(
                "INSERT INTO policy_high_water "
                "(scope, policy_id, sequence, rollback_epoch, policy_hash, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                ("active", policy_id, sequence, rollback_epoch, policy_hash, now_s),
            )
    return {
        "policy_id": policy_id,
        "sequence": sequence,
        "rollback_epoch": rollback_epoch,
        "policy_hash": policy_hash,
        "updated_at": now_s,
    }


def row_to_credential(row: sqlite3.Row, include_secret: bool = False) -> dict[str, Any]:
    item = dict(row)
    item["metadata"] = loads(item.get("metadata"), {})
    item["lifecycle_status"] = str(item.get("lifecycle_status") or "active")
    item.pop("encrypted_secret", None)
    item.pop("encrypted_dek", None)
    item.pop("secret_nonce", None)
    item.pop("secret_ciphertext", None)
    if include_secret:
        item["secret"] = decrypt_secret_envelope(row)
    return item


def row_to_pending_oauth_credential(row: Any) -> dict[str, Any]:
    return {
        "id": str(row["id"]),
        "requester_id": str(row["requester_id"]),
        "name": str(row["name"]),
        "kind": str(row["kind"]),
        "payload_digest": str(row["payload_digest"]),
        "review": loads(row["review_json"], {}),
        "target_credential_id": (
            str(row["target_credential_id"]) if row["target_credential_id"] else None
        ),
        "target_credential_version": (
            int(row["target_credential_version"])
            if row["target_credential_version"] is not None
            else None
        ),
        "status": str(row["status"] or "pending"),
        "revocation_status": str(row["revocation_status"])
        if row["revocation_status"]
        else None,
        "revocation_error": str(row["revocation_error"])
        if row["revocation_error"]
        else None,
        "revocation_attempts": int(row["revocation_attempts"] or 0),
        "revocation_next_attempt_at": (
            str(row["revocation_next_attempt_at"])
            if row["revocation_next_attempt_at"]
            else None
        ),
        "created_at": str(row["created_at"]),
        "expires_at": str(row["expires_at"]),
        "updated_at": str(row["updated_at"] or row["created_at"]),
    }


def _encrypted_secret_placeholder() -> str:
    return "envelope:v2"


def _envelope_values(
    item_id: str, secret: str, credential_version: int
) -> dict[str, Any]:
    encrypted = encrypt_secret_envelope(
        secret, credential_id=item_id, credential_version=credential_version
    )
    return {
        "encrypted_secret": _encrypted_secret_placeholder(),
        "encrypted_dek": encrypted["encrypted_dek"],
        "secret_nonce": encrypted["secret_nonce"],
        "secret_ciphertext": encrypted["secret_ciphertext"],
        "secret_kek_id": encrypted["secret_kek_id"],
        "credential_version": credential_version,
        "secret_updated_at": iso_now(),
    }


def validate_credential_metadata(metadata: dict[str, Any] | None) -> dict[str, Any]:
    value = metadata or {}
    if not isinstance(value, dict):
        raise ValueError("credential metadata must be an object")
    key_count = 0

    def walk(item: Any, depth: int) -> None:
        nonlocal key_count
        if depth > _CREDENTIAL_METADATA_MAX_DEPTH:
            raise ValueError("credential metadata exceeds maximum nesting depth")
        if isinstance(item, dict):
            key_count += len(item)
            if key_count > _CREDENTIAL_METADATA_MAX_KEYS:
                raise ValueError("credential metadata has too many keys")
            for key, child in item.items():
                if (
                    not isinstance(key, str)
                    or not key
                    or len(key.encode("utf-8")) > 256
                ):
                    raise ValueError(
                        "credential metadata keys must be non-empty strings up to 256 bytes"
                    )
                compact = "".join(
                    character
                    for character in key.strip().lower()
                    if character.isalnum()
                )
                if (
                    compact in _SENSITIVE_CREDENTIAL_METADATA_KEYS_COMPACT
                    or compact.endswith(_SENSITIVE_CREDENTIAL_METADATA_SUFFIXES)
                ):
                    raise ValueError(
                        f"credential metadata key {key!r} may contain secret material"
                    )
                walk(child, depth + 1)
        elif isinstance(item, list):
            for child in item:
                walk(child, depth + 1)

    walk(value, 0)
    try:
        encoded = json.dumps(
            value,
            separators=(",", ":"),
            sort_keys=True,
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError("credential metadata must be finite JSON") from exc
    if len(encoded) > _CREDENTIAL_METADATA_MAX_BYTES:
        raise ValueError("credential metadata exceeds 16 KiB")
    return value


def validate_credential_secret(secret: str) -> str:
    if not isinstance(secret, str) or not secret:
        raise ValueError("credential secret must be a non-empty string")
    if len(secret.encode("utf-8")) > _CREDENTIAL_SECRET_MAX_BYTES:
        raise ValueError("credential secret exceeds 1 MiB")
    return secret


def validate_managed_oauth_identity(metadata: Any) -> tuple[str, str]:
    if not isinstance(metadata, dict) or metadata.get("oauth") is not True:
        raise ManagedOAuthCredentialError(
            "OAuth credential is not managed by the verified provider flow"
        )
    if metadata.get("provider_identity_verified") is not True:
        raise ManagedOAuthCredentialError(
            "OAuth credential provider identity is not verified"
        )
    provider_id = metadata.get("provider_id")
    provider_subject = metadata.get("provider_subject")
    for label, value, maximum in (
        ("provider", provider_id, 128),
        ("provider subject", provider_subject, 512),
    ):
        if (
            not isinstance(value, str)
            or not value
            or value != value.strip()
            or len(value) > maximum
            or any(ord(character) < 32 or ord(character) == 127 for character in value)
        ):
            raise ManagedOAuthCredentialError(f"OAuth credential {label} is invalid")
    return provider_id, provider_subject


def validate_managed_oauth_account_identity(metadata: Any) -> tuple[str, str, str]:
    provider_id, provider_subject = validate_managed_oauth_identity(metadata)
    provider_account = metadata.get("provider_account")
    if (
        not isinstance(provider_account, str)
        or not provider_account
        or provider_account != provider_account.strip()
        or len(provider_account) > 512
        or any(
            ord(character) < 32 or ord(character) == 127
            for character in provider_account
        )
    ):
        raise ManagedOAuthCredentialError(
            "OAuth credential provider account is invalid"
        )
    return provider_id, provider_subject, provider_account


def _credential_mutation_lock_key(item_id: str) -> int:
    digest = hashlib.sha256(
        f"serverware:credential-mutation:{item_id}".encode("utf-8")
    ).digest()
    return int.from_bytes(digest[:8], "big", signed=True)


def _oauth_refresh_lock_key(item_id: str) -> int:
    digest = hashlib.sha256(
        f"serverware:oauth-refresh:{item_id}".encode("utf-8")
    ).digest()
    return int.from_bytes(digest[:8], "big", signed=True)


@contextlib.contextmanager
def oauth_refresh_lock(item_id: str):
    if metadata_uses_postgres():
        conn = _metadata_pg_connect_raw()
        conn.autocommit = True
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT pg_advisory_lock(%s)", (_oauth_refresh_lock_key(item_id),)
                )
            yield
        finally:
            try:
                with conn.cursor() as cur:
                    cur.execute(
                        "SELECT pg_advisory_unlock(%s)",
                        (_oauth_refresh_lock_key(item_id),),
                    )
            finally:
                conn.close()
        return

    ensure_data_dirs()
    lock_name = hashlib.sha256(item_id.encode("utf-8")).hexdigest()[:32]
    lock_path = DB_PATH.parent / f".oauth-refresh-{lock_name}.lock"
    with lock_path.open("a+", encoding="utf-8") as lock_file:
        os.chmod(lock_path, 0o600)
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


def _lock_credential_mutation(conn: Any, item_id: str) -> None:
    if metadata_uses_postgres():
        conn.execute(
            "SELECT pg_advisory_xact_lock(?)", (_credential_mutation_lock_key(item_id),)
        )
    elif not conn.in_transaction:
        conn.execute("BEGIN IMMEDIATE")


def _record_credential_generation(conn: Any, item_id: str, version: int) -> None:
    row = conn.execute(
        "SELECT last_version FROM credential_generations WHERE credential_id = ?",
        (item_id,),
    ).fetchone()
    if row is None:
        conn.execute(
            "INSERT INTO credential_generations (credential_id, last_version, updated_at) VALUES (?, ?, ?)",
            (item_id, version, iso_now()),
        )
    elif int(row["last_version"]) < version:
        conn.execute(
            "UPDATE credential_generations SET last_version = ?, updated_at = ? WHERE credential_id = ?",
            (version, iso_now(), item_id),
        )


def _next_credential_generation(conn: Any, item_id: str) -> int:
    row = conn.execute(
        "SELECT last_version FROM credential_generations WHERE credential_id = ?",
        (item_id,),
    ).fetchone()
    version = int(row["last_version"]) + 1 if row is not None else 1
    _record_credential_generation(conn, item_id, version)
    return version


def reserve_credential_lease_nonce(
    recipient_key_id: str,
    nonce_sha256: str,
    *,
    now_epoch_ms: int,
) -> str | None:
    tombstone_expires_at_epoch_ms = now_epoch_ms + _CREDENTIAL_LEASE_REPLAY_RETENTION_MS
    with connect() as conn:
        if metadata_uses_postgres():
            conn.execute(
                "SELECT pg_advisory_xact_lock(?)", (_CREDENTIAL_LEASE_REPLAY_LOCK_KEY,)
            )
        elif not conn.in_transaction:
            conn.execute("BEGIN IMMEDIATE")
        deleted = conn.execute(
            "DELETE FROM credential_lease_nonces WHERE expires_at_epoch_ms <= ?",
            (now_epoch_ms,),
        )
        state = conn.execute(
            "SELECT nonce_count FROM credential_lease_replay_state WHERE scope = ?",
            ("global",),
        ).fetchone()
        if state is None:
            counted = conn.execute(
                "SELECT COUNT(*) AS count FROM credential_lease_nonces"
            ).fetchone()
            nonce_count = int(counted["count"])
            conn.execute(
                "INSERT INTO credential_lease_replay_state (scope, nonce_count) VALUES (?, ?)",
                ("global", nonce_count),
            )
        else:
            nonce_count = max(
                0, int(state["nonce_count"]) - max(0, int(deleted.rowcount))
            )
            if nonce_count != int(state["nonce_count"]):
                conn.execute(
                    "UPDATE credential_lease_replay_state SET nonce_count = ? WHERE scope = ?",
                    (nonce_count, "global"),
                )
        if nonce_count >= CREDENTIAL_LEASE_REPLAY_MAX_ENTRIES:
            return "capacity"
        inserted = conn.execute(
            """
            INSERT INTO credential_lease_nonces (
                recipient_key_id, nonce_sha256, expires_at_epoch_ms, created_at
            )
            VALUES (?, ?, ?, ?)
            ON CONFLICT (recipient_key_id, nonce_sha256) DO NOTHING
            """,
            (recipient_key_id, nonce_sha256, tombstone_expires_at_epoch_ms, iso_now()),
        )
        if inserted.rowcount == 0:
            return "replay"
        conn.execute(
            "UPDATE credential_lease_replay_state SET nonce_count = nonce_count + 1 WHERE scope = ?",
            ("global",),
        )
    return None


def credential_lease_nonce_reserved(
    recipient_key_id: str,
    nonce_sha256: str,
    *,
    now_epoch_ms: int,
) -> bool:
    with connect() as conn:
        row = conn.execute(
            """
            SELECT 1
            FROM credential_lease_nonces
            WHERE recipient_key_id = ?
              AND nonce_sha256 = ?
              AND expires_at_epoch_ms > ?
            LIMIT 1
            """,
            (recipient_key_id, nonce_sha256, now_epoch_ms),
        ).fetchone()
    return row is not None


def _needs_envelope_migration(row: sqlite3.Row) -> bool:
    return (
        not row["encrypted_dek"]
        or not row["secret_nonce"]
        or not row["secret_ciphertext"]
    )


def create_credential(
    name: str,
    kind: str,
    secret: str,
    metadata: dict[str, Any] | None = None,
    *,
    revocation_work_id: str | None = None,
    setup_session_id: str | None = None,
    setup_expected_revision: int | None = None,
    setup_actor_id: str | None = None,
    setup_oauth_provider: str | None = None,
    setup_oauth_state_digest: str | None = None,
) -> dict[str, Any]:
    secret = validate_credential_secret(secret)
    metadata = validate_credential_metadata(metadata)
    setup_binding = _prepare_setup_oauth_callback_binding(
        session_id=setup_session_id,
        expected_revision=setup_expected_revision,
        actor_id=setup_actor_id,
        provider_id=setup_oauth_provider,
        state_digest=setup_oauth_state_digest,
    )
    if setup_binding is not None:
        provider_id, _ = validate_managed_oauth_identity(metadata)
        if kind != "oauth2" or provider_id != setup_binding["provider_id"]:
            raise ManagedOAuthCredentialError(
                "setup-bound credential must match the verified OAuth provider"
            )
    item_id = str(uuid.uuid4())
    now = utcnow()
    now_s = now.isoformat()
    if setup_binding is not None:
        _expire_setup_sessions_before_mutation(now)
    with connect() as conn:
        if setup_binding is not None:
            _lock_setup_oauth_callback_binding(conn, setup_binding)
        _lock_credential_mutation(conn, item_id)
        credential_version = _next_credential_generation(conn, item_id)
        encrypted = _envelope_values(item_id, secret, credential_version)
        conn.execute(
            """
            INSERT INTO credentials (
                id, name, kind, encrypted_secret, encrypted_dek, secret_nonce,
                secret_ciphertext, secret_kek_id, credential_version, secret_updated_at,
                metadata, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                item_id,
                name,
                kind,
                encrypted["encrypted_secret"],
                encrypted["encrypted_dek"],
                encrypted["secret_nonce"],
                encrypted["secret_ciphertext"],
                encrypted["secret_kek_id"],
                encrypted["credential_version"],
                encrypted["secret_updated_at"],
                dumps(metadata or {}),
                now_s,
                now_s,
            ),
        )
        if revocation_work_id is not None:
            _consume_oauth_revocation_work(conn, revocation_work_id)
        row = conn.execute(
            "SELECT * FROM credentials WHERE id = ?", (item_id,)
        ).fetchone()
        if setup_binding is not None:
            transition_setup_session(
                setup_binding["session_id"],
                expected_revision=int(setup_binding["expected_revision"]),
                transition="bind_credential",
                actor_id=str(setup_binding["actor_id"]),
                updates={
                    "credential_id": item_id,
                    "credential_version": int(row["credential_version"]),
                    "oauth_provider": str(setup_binding["provider_id"]),
                },
                event={"provider_account": metadata.get("provider_account")},
                _connection=conn,
                _now=now,
            )
    return row_to_credential(row)


_OAUTH_ACTIVATION_REVIEW_FIELDS = {
    "credential_type",
    "provider",
    "provider_subject",
    "provider_account",
    "scopes",
    "credential_name",
    "metadata_keys",
    "expires_at_epoch_ms",
    "x_app_id",
    "reconnect_credential_id",
    "reconnect_credential_version",
}
_OAUTH_ACTIVATION_REQUIRED_REVIEW_FIELDS = _OAUTH_ACTIVATION_REVIEW_FIELDS - {
    "x_app_id",
    "reconnect_credential_id",
    "reconnect_credential_version",
}


def _validate_oauth_activation_review(
    *,
    review: dict[str, Any],
    metadata: dict[str, Any],
    name: str,
    kind: str,
    provider_id: str,
    provider_subject: str,
    target_credential_id: str | None,
    target_credential_version: int | None,
) -> None:
    if set(review) - _OAUTH_ACTIVATION_REVIEW_FIELDS:
        raise ManagedOAuthCredentialError(
            "pending OAuth credential review contains unsupported fields"
        )
    if not _OAUTH_ACTIVATION_REQUIRED_REVIEW_FIELDS.issubset(review):
        raise ManagedOAuthCredentialError(
            "pending OAuth credential review is incomplete"
        )
    provider_account = metadata.get("provider_account")
    if review.get("credential_type") != kind or review.get("credential_name") != name:
        raise ManagedOAuthCredentialError(
            "pending OAuth credential review does not match the credential"
        )
    if (
        review.get("provider") != provider_id
        or review.get("provider_subject") != provider_subject
    ):
        raise ManagedOAuthCredentialError(
            "pending OAuth credential review does not match the verified identity"
        )
    if review.get("provider_account") != provider_account:
        raise ManagedOAuthCredentialError(
            "pending OAuth credential review does not match the verified account"
        )
    scopes = review.get("scopes")
    metadata_scopes = metadata.get("scopes")
    if (
        not isinstance(scopes, list)
        or not scopes
        or any(
            not isinstance(scope, str) or not scope or len(scope) > 1024
            for scope in scopes
        )
        or len(scopes) != len(set(scopes))
        or scopes != metadata_scopes
    ):
        raise ManagedOAuthCredentialError(
            "pending OAuth credential review scopes are invalid"
        )
    metadata_keys = review.get("metadata_keys")
    if metadata_keys != sorted(metadata):
        raise ManagedOAuthCredentialError(
            "pending OAuth credential review metadata keys are invalid"
        )
    expires_at_epoch_ms = review.get("expires_at_epoch_ms")
    if expires_at_epoch_ms is not None and (
        not isinstance(expires_at_epoch_ms, int)
        or isinstance(expires_at_epoch_ms, bool)
        or expires_at_epoch_ms <= 0
    ):
        raise ManagedOAuthCredentialError(
            "pending OAuth credential review expiry is invalid"
        )
    if expires_at_epoch_ms != metadata.get("expires_at_epoch_ms"):
        raise ManagedOAuthCredentialError(
            "pending OAuth credential review expiry does not match metadata"
        )
    if provider_id == "x":
        if not isinstance(review.get("x_app_id"), str) or review.get(
            "x_app_id"
        ) != metadata.get("x_app_id"):
            raise ManagedOAuthCredentialError(
                "pending X OAuth credential review app binding is invalid"
            )
    elif "x_app_id" in review:
        raise ManagedOAuthCredentialError(
            "pending OAuth credential review has an unexpected X app binding"
        )
    if target_credential_id is None:
        if (
            "reconnect_credential_id" in review
            or "reconnect_credential_version" in review
        ):
            raise ManagedOAuthCredentialError(
                "new OAuth credential review has an unexpected reconnect binding"
            )
    elif (
        review.get("reconnect_credential_id") != target_credential_id
        or review.get("reconnect_credential_version") != target_credential_version
    ):
        raise ManagedOAuthCredentialError(
            "pending OAuth credential review has an invalid reconnect binding"
        )


def create_pending_oauth_credential(
    *,
    name: str,
    kind: str,
    secret: str,
    metadata: dict[str, Any],
    requester_id: str,
    payload_digest: str,
    review: dict[str, Any],
    ttl_seconds: int,
    target_credential_id: str | None = None,
    target_credential_version: int | None = None,
    revocation_work_id: str | None = None,
    setup_session_id: str | None = None,
    setup_expected_revision: int | None = None,
    setup_actor_id: str | None = None,
    setup_oauth_provider: str | None = None,
    setup_oauth_state_digest: str | None = None,
) -> dict[str, Any]:
    secret = validate_credential_secret(secret)
    metadata = validate_credential_metadata(metadata)
    provider_id, provider_subject = validate_managed_oauth_identity(metadata)
    if kind != "oauth2":
        raise ManagedOAuthCredentialError(
            "pending OAuth credential kind must be oauth2"
        )
    if not isinstance(requester_id, str) or not requester_id or len(requester_id) > 512:
        raise ManagedOAuthCredentialError(
            "pending OAuth credential requester is invalid"
        )
    if (
        not isinstance(payload_digest, str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", payload_digest) is None
    ):
        raise ManagedOAuthCredentialError(
            "pending OAuth credential payload digest is invalid"
        )
    if not isinstance(review, dict):
        raise ManagedOAuthCredentialError("pending OAuth credential review is invalid")
    if (target_credential_id is None) != (target_credential_version is None):
        raise ManagedOAuthCredentialError(
            "pending OAuth reconnect binding is incomplete"
        )
    if target_credential_id is not None and (
        not isinstance(target_credential_id, str)
        or not target_credential_id
        or len(target_credential_id) > 512
        or not isinstance(target_credential_version, int)
        or isinstance(target_credential_version, bool)
        or target_credential_version < 1
    ):
        raise ManagedOAuthCredentialError("pending OAuth reconnect binding is invalid")
    _validate_oauth_activation_review(
        review=review,
        metadata=metadata,
        name=name,
        kind=kind,
        provider_id=provider_id,
        provider_subject=provider_subject,
        target_credential_id=target_credential_id,
        target_credential_version=target_credential_version,
    )
    expected_payload_digest = (
        "sha256:"
        + hashlib.sha256(
            dumps(
                {
                    "action": "credential.oauth.activate",
                    "review": review,
                    "encrypted_token_source_sha256": "sha256:"
                    + hashlib.sha256(secret.encode("utf-8")).hexdigest(),
                }
            ).encode("utf-8")
        ).hexdigest()
    )
    if payload_digest != expected_payload_digest:
        raise ManagedOAuthCredentialError(
            "pending OAuth credential payload digest does not bind the review and token"
        )
    if not 60 <= ttl_seconds <= 3600:
        raise ManagedOAuthCredentialError(
            "pending OAuth credential ttl must be between 60 and 3600 seconds"
        )
    setup_binding = _prepare_setup_oauth_callback_binding(
        session_id=setup_session_id,
        expected_revision=setup_expected_revision,
        actor_id=setup_actor_id,
        provider_id=setup_oauth_provider,
        state_digest=setup_oauth_state_digest,
    )
    if setup_binding is not None and (
        requester_id != setup_binding["actor_id"]
        or provider_id != setup_binding["provider_id"]
    ):
        raise ManagedOAuthCredentialError(
            "pending OAuth credential does not match its setup callback binding"
        )
    try:
        review_json = dumps(review)
    except (TypeError, ValueError) as exc:
        raise ManagedOAuthCredentialError(
            "pending OAuth credential review must be finite JSON"
        ) from exc
    if len(review_json.encode("utf-8")) > 16 * 1024:
        raise ManagedOAuthCredentialError(
            "pending OAuth credential review exceeds 16 KiB"
        )

    item_id = str(uuid.uuid4())
    now = utcnow()
    created_at = now.isoformat()
    expires_at = (now + timedelta(seconds=ttl_seconds)).isoformat()
    encrypted = _envelope_values(item_id, secret, 1)
    if setup_binding is not None:
        _expire_setup_sessions_before_mutation(now)
    with connect() as conn:
        if setup_binding is not None:
            _lock_setup_oauth_callback_binding(conn, setup_binding)
        _lock_pending_oauth_creation(conn)
        _mark_expired_pending_oauth_credentials(conn, created_at)
        if target_credential_id is not None:
            _lock_credential_mutation(conn, target_credential_id)
            target = conn.execute(
                "SELECT * FROM credentials WHERE id = ?",
                (target_credential_id,),
            ).fetchone()
            if (
                target is None
                or str(target["lifecycle_status"] or "active") != "active"
            ):
                raise ManagedOAuthCredentialError(
                    "OAuth reconnect target is unavailable"
                )
            if target["kind"] != "oauth2":
                raise ManagedOAuthCredentialError(
                    "OAuth reconnect target kind is invalid"
                )
            target_identity = validate_managed_oauth_account_identity(
                loads(target["metadata"], {})
            )
            pending_identity = validate_managed_oauth_account_identity(metadata)
            if target_identity != pending_identity:
                raise ManagedOAuthCredentialError(
                    "OAuth reconnect target identity changed"
                )
            if int(target["credential_version"] or 1) != target_credential_version:
                raise ManagedOAuthCredentialError(
                    "OAuth reconnect target version changed"
                )
        count_row = conn.execute(
            "SELECT COUNT(*) AS count FROM pending_oauth_credentials WHERE status = 'pending'"
        ).fetchone()
        if (
            int(count_row["count"] if count_row else 0)
            >= OAUTH_PENDING_CREDENTIAL_MAX_COUNT
        ):
            raise ManagedOAuthCredentialError(
                "pending OAuth credential capacity has been reached"
            )
        backlog_row = conn.execute(
            "SELECT COUNT(*) AS count FROM pending_oauth_credentials "
            "WHERE status IN ('cancelled', 'expired', 'rejected')"
        ).fetchone()
        if (
            int(backlog_row["count"] if backlog_row else 0)
            >= _OAUTH_REVOCATION_BACKLOG_MAX_COUNT
        ):
            raise ManagedOAuthCredentialError(
                "OAuth revocation backlog capacity has been reached"
            )
        conn.execute(
            """
            INSERT INTO pending_oauth_credentials (
                id, requester_id, name, kind, encrypted_secret, encrypted_dek,
                secret_nonce, secret_ciphertext, secret_kek_id, credential_version,
                secret_updated_at, metadata, payload_digest, review_json, status,
                target_credential_id, target_credential_version, created_at, expires_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?, ?)
            """,
            (
                item_id,
                requester_id,
                name,
                kind,
                encrypted["encrypted_secret"],
                encrypted["encrypted_dek"],
                encrypted["secret_nonce"],
                encrypted["secret_ciphertext"],
                encrypted["secret_kek_id"],
                encrypted["credential_version"],
                encrypted["secret_updated_at"],
                dumps(metadata),
                payload_digest,
                review_json,
                target_credential_id,
                target_credential_version,
                created_at,
                expires_at,
                created_at,
            ),
        )
        if revocation_work_id is not None:
            _consume_oauth_revocation_work(conn, revocation_work_id)
        row = conn.execute(
            "SELECT * FROM pending_oauth_credentials WHERE id = ?", (item_id,)
        ).fetchone()
        if setup_binding is not None:
            transition_setup_session(
                setup_binding["session_id"],
                expected_revision=int(setup_binding["expected_revision"]),
                transition="bind_pending_credential",
                actor_id=str(setup_binding["actor_id"]),
                updates={"oauth_pending_credential_id": item_id},
                event={"provider_account": review.get("provider_account")},
                _connection=conn,
                _now=now,
            )
    return row_to_pending_oauth_credential(row)


def _mark_expired_pending_oauth_credentials(conn: Any, now_s: str) -> None:
    conn.execute(
        """
        UPDATE pending_oauth_credentials
        SET status = 'expired', revocation_status = 'pending', revocation_error = NULL,
            revocation_next_attempt_at = ?, revocation_lease_owner = NULL,
            revocation_lease_until = NULL, updated_at = ?
        WHERE status = 'pending' AND expires_at <= ?
        """,
        (now_s, now_s, now_s),
    )


def _lock_pending_oauth_creation(conn: Any) -> None:
    if isinstance(conn, PostgresMetadataConnection):
        conn.execute(
            "SELECT pg_advisory_xact_lock(?)",
            (_PENDING_OAUTH_CREATION_LOCK_KEY,),
        )
    elif not conn.in_transaction:
        conn.execute("BEGIN IMMEDIATE")


def _oidc_login_state_id(state: str) -> str:
    return "sha256:" + hashlib.sha256(state.encode("ascii")).hexdigest()


@contextlib.contextmanager
def oidc_login_source(source_key: str):
    if (
        not isinstance(source_key, str)
        or not source_key
        or len(source_key) > 128
        or re.fullmatch(r"[A-Za-z0-9:._-]+", source_key) is None
    ):
        raise MetadataStoreError("OIDC login source is invalid")
    token = _oidc_login_source_context.set(source_key)
    try:
        yield
    finally:
        _oidc_login_source_context.reset(token)


def _lock_oidc_login_creation(conn: Any) -> None:
    if isinstance(conn, PostgresMetadataConnection):
        conn.execute(
            "SELECT pg_advisory_xact_lock(?)",
            (_OIDC_LOGIN_STATE_CREATION_LOCK_KEY,),
        )
    elif not conn.in_transaction:
        conn.execute("BEGIN IMMEDIATE")


def _oidc_login_bucket_count(conn: Any, bucket_key: str) -> int:
    row = conn.execute(
        "SELECT attempt_count FROM oidc_login_rate_buckets WHERE bucket_key = ?",
        (bucket_key,),
    ).fetchone()
    return int(row["attempt_count"] if row else 0)


def _increment_oidc_login_bucket(
    conn: Any,
    *,
    bucket_key: str,
    expires_at: str,
) -> None:
    conn.execute(
        """
        INSERT INTO oidc_login_rate_buckets (bucket_key, attempt_count, expires_at)
        VALUES (?, 1, ?)
        ON CONFLICT (bucket_key) DO UPDATE
        SET attempt_count = oidc_login_rate_buckets.attempt_count + 1,
            expires_at = excluded.expires_at
        """,
        (bucket_key, expires_at),
    )


def create_oidc_login_state(
    *,
    state: str,
    browser_nonce: str,
    code_verifier: str,
    oidc_nonce: str,
    ttl_seconds: int,
) -> dict[str, str]:
    for label, value, minimum, maximum in (
        ("state", state, 43, 128),
        ("browser nonce", browser_nonce, 43, 128),
        ("code verifier", code_verifier, 43, 128),
        ("OIDC nonce", oidc_nonce, 43, 128),
    ):
        if (
            not isinstance(value, str)
            or not minimum <= len(value) <= maximum
            or re.fullmatch(r"[A-Za-z0-9_-]+", value) is None
        ):
            raise MetadataStoreError(f"OIDC login {label} is invalid")
    if not 60 <= ttl_seconds <= 900:
        raise MetadataStoreError(
            "OIDC login state ttl must be between 60 and 900 seconds"
        )
    source_key = _oidc_login_source_context.get() or "internal"
    now = utcnow()
    item_id = _oidc_login_state_id(state)
    created_at = now.isoformat()
    expires_at = (now + timedelta(seconds=ttl_seconds)).isoformat()
    encrypted = _envelope_values(item_id, code_verifier, 1)
    browser_hash = "sha256:" + hashlib.sha256(browser_nonce.encode("ascii")).hexdigest()
    bucket_number = int(now.timestamp()) // _OIDC_LOGIN_RATE_WINDOW_SECONDS
    global_bucket = f"global:{bucket_number}"
    source_bucket = f"source:{source_key}:{bucket_number}"
    bucket_expires_at = (
        now
        + timedelta(
            seconds=_OIDC_LOGIN_RATE_WINDOW_SECONDS
            + _OIDC_LOGIN_RATE_BUCKET_RETENTION_SECONDS
        )
    ).isoformat()
    with connect() as conn:
        _lock_oidc_login_creation(conn)
        conn.execute(
            "DELETE FROM oidc_login_states WHERE expires_at <= ?", (created_at,)
        )
        conn.execute(
            "DELETE FROM oidc_login_rate_buckets WHERE expires_at <= ?", (created_at,)
        )
        global_count = conn.execute(
            "SELECT COUNT(*) AS count FROM oidc_login_states"
        ).fetchone()
        if (
            int(global_count["count"] if global_count else 0)
            >= _OIDC_LOGIN_GLOBAL_PENDING_MAX
        ):
            raise MetadataStoreError("OIDC login state capacity has been reached")
        source_count = conn.execute(
            "SELECT COUNT(*) AS count FROM oidc_login_states WHERE source_key = ?",
            (source_key,),
        ).fetchone()
        if (
            int(source_count["count"] if source_count else 0)
            >= _OIDC_LOGIN_SOURCE_PENDING_MAX
        ):
            raise MetadataStoreError("OIDC login source capacity has been reached")
        if _oidc_login_bucket_count(conn, global_bucket) >= _OIDC_LOGIN_GLOBAL_RATE_MAX:
            raise MetadataStoreError("OIDC login global rate limit has been reached")
        if _oidc_login_bucket_count(conn, source_bucket) >= _OIDC_LOGIN_SOURCE_RATE_MAX:
            raise MetadataStoreError("OIDC login source rate limit has been reached")
        conn.execute(
            """
            INSERT INTO oidc_login_states (
                id, encrypted_secret, encrypted_dek, secret_nonce, secret_ciphertext,
                secret_kek_id, credential_version, browser_nonce_sha256, oidc_nonce,
                source_key, created_at, expires_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                item_id,
                encrypted["encrypted_secret"],
                encrypted["encrypted_dek"],
                encrypted["secret_nonce"],
                encrypted["secret_ciphertext"],
                encrypted["secret_kek_id"],
                encrypted["credential_version"],
                browser_hash,
                oidc_nonce,
                source_key,
                created_at,
                expires_at,
            ),
        )
        _increment_oidc_login_bucket(
            conn,
            bucket_key=global_bucket,
            expires_at=bucket_expires_at,
        )
        _increment_oidc_login_bucket(
            conn,
            bucket_key=source_bucket,
            expires_at=bucket_expires_at,
        )
    return {"state_hash": item_id, "created_at": created_at, "expires_at": expires_at}


def consume_oidc_login_state(*, state: str, browser_nonce: str) -> dict[str, str]:
    if (
        not isinstance(state, str)
        or re.fullmatch(r"[A-Za-z0-9_-]{43,128}", state) is None
    ):
        raise MetadataStoreError("OIDC login state is malformed")
    if (
        not isinstance(browser_nonce, str)
        or re.fullmatch(r"[A-Za-z0-9_-]{43,128}", browser_nonce) is None
    ):
        raise MetadataStoreError("OIDC login browser nonce is malformed")
    item_id = _oidc_login_state_id(state)
    now_s = iso_now()
    with connect() as conn:
        _lock_credential_mutation(conn, item_id)
        row = conn.execute(
            "SELECT * FROM oidc_login_states WHERE id = ?", (item_id,)
        ).fetchone()
        if row is None:
            raise MetadataStoreError("OIDC login state is unknown or already consumed")
        if row["expires_at"] <= now_s:
            conn.execute("DELETE FROM oidc_login_states WHERE id = ?", (item_id,))
            raise MetadataStoreError("OIDC login state expired")
        expected_browser_hash = (
            "sha256:" + hashlib.sha256(browser_nonce.encode("ascii")).hexdigest()
        )
        if not hmac.compare_digest(
            str(row["browser_nonce_sha256"]), expected_browser_hash
        ):
            raise MetadataStoreError("OIDC login browser binding mismatch")
        code_verifier = decrypt_secret_envelope(row)
        oidc_nonce = str(row["oidc_nonce"])
        conn.execute("DELETE FROM oidc_login_states WHERE id = ?", (item_id,))
    return {
        "state_hash": item_id,
        "code_verifier": code_verifier,
        "oidc_nonce": oidc_nonce,
    }


def _oidc_browser_session_digest(label: str, value: Any) -> str:
    if (
        not isinstance(value, str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", value) is None
    ):
        raise MetadataStoreError(
            f"OIDC browser session {label} must be a lowercase sha256 digest"
        )
    return value


def _oidc_browser_session_text(
    label: str, value: Any, *, maximum_bytes: int = 512
) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value.encode("utf-8")) > maximum_bytes
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise MetadataStoreError(
            f"OIDC browser session {label} must be a non-empty trimmed string "
            f"of at most {maximum_bytes} bytes"
        )
    return value


def _oidc_browser_session_timestamp(label: str, value: Any) -> str:
    timestamp = _oidc_browser_session_text(label, value, maximum_bytes=64)
    try:
        parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError as exc:
        raise MetadataStoreError(
            f"OIDC browser session {label} must be an ISO-8601 timestamp"
        ) from exc
    if parsed.tzinfo is None:
        raise MetadataStoreError(
            f"OIDC browser session {label} must include a timezone"
        )
    canonical = parsed.astimezone(timezone.utc).isoformat()
    if timestamp != canonical:
        raise MetadataStoreError(
            f"OIDC browser session {label} must be a canonical UTC timestamp"
        )
    return canonical


def _oidc_browser_session_roles(roles: Any) -> tuple[list[str], str]:
    if (
        not isinstance(roles, list)
        or not roles
        or len(roles) > _OIDC_BROWSER_SESSION_ROLE_MAX_COUNT
    ):
        raise MetadataStoreError(
            "OIDC browser session roles must be a non-empty bounded list"
        )
    normalized: list[str] = []
    for role in roles:
        normalized.append(
            _oidc_browser_session_text(
                "role",
                role,
                maximum_bytes=_OIDC_BROWSER_SESSION_ROLE_MAX_BYTES,
            )
        )
    normalized = sorted(set(normalized))
    roles_json = dumps(normalized)
    if len(roles_json.encode("utf-8")) > _OIDC_BROWSER_SESSION_ROLES_JSON_MAX_BYTES:
        raise MetadataStoreError("OIDC browser session roles exceed 4 KiB")
    return normalized, roles_json


def _prune_oidc_browser_sessions(conn: Any, now: datetime) -> int:
    _prune_oidc_activation_deliveries(conn, now)
    deleted = conn.execute(
        """
        DELETE FROM oidc_browser_sessions
        WHERE (
                status = 'pending_webauthn'
                AND COALESCE(pending_expires_at, expires_at) <= ?
              )
           OR (status != 'pending_webauthn' AND expires_at <= ?)
           OR (
                status = 'revoked'
                AND revoked_at <= ?
           )
        """,
        (
            now.isoformat(),
            now.isoformat(),
            (
                now
                - timedelta(seconds=_OIDC_BROWSER_SESSION_TERMINAL_RETENTION_SECONDS)
            ).isoformat(),
        ),
    )
    return max(0, int(deleted.rowcount))


def row_to_oidc_browser_session(row: Any) -> dict[str, Any]:
    roles = loads(row["roles_json"], None)
    if not isinstance(roles, list) or any(not isinstance(role, str) for role in roles):
        raise MetadataStoreError("stored OIDC browser session roles are invalid")
    return {
        "id": str(row["id"]),
        "token_digest": str(row["token_digest"]),
        "oidc_token_digest": str(row["oidc_token_digest"]),
        "user_id": str(row["user_id"]),
        "roles": roles,
        "status": str(row["status"]),
        "provider_expires_at": (
            str(row["provider_expires_at"])
            if row["provider_expires_at"]
            else str(row["expires_at"])
        ),
        "expires_at": str(row["expires_at"]),
        "pending_expires_at": (
            str(row["pending_expires_at"]) if row["pending_expires_at"] else None
        ),
        "created_at": str(row["created_at"]),
        "updated_at": str(row["updated_at"]),
        "activated_at": (str(row["activated_at"]) if row["activated_at"] else None),
        "revoked_at": str(row["revoked_at"]) if row["revoked_at"] else None,
        "bound_webauthn_credential_id": (
            str(row["bound_webauthn_credential_id"])
            if row["bound_webauthn_credential_id"]
            else None
        ),
        "activation_trust_bundle_digest": (
            str(row["activation_trust_bundle_digest"])
            if row["activation_trust_bundle_digest"]
            else None
        ),
        "activation_trust_bundle_sequence": (
            int(row["activation_trust_bundle_sequence"])
            if row["activation_trust_bundle_sequence"] is not None
            else None
        ),
        "activation_authenticator_class": (
            str(row["activation_authenticator_class"])
            if row["activation_authenticator_class"]
            else None
        ),
        "revocation_reason": (
            str(row["revocation_reason"]) if row["revocation_reason"] else None
        ),
    }


_OIDC_BOUND_CREDENTIAL_COLUMNS = (
    "id",
    "credential_id",
    "user_id",
    "label",
    "public_key_cose",
    "sign_count",
    "aaguid",
    "authenticator_class",
    "attestation_fmt",
    "attestation_trusted",
    "attestation_trust_path",
    "attestation_leaf_sha256",
    "attestation_root_sha256",
    "attestation_trust_bundle_digest",
    "attestation_trust_bundle_sequence",
    "attestation_verified_at",
    "transports",
    "dev_private_key_pem",
    "created_at",
    "updated_at",
    "last_used_at",
    "revoked_at",
    "revoked_by",
    "revocation_reason",
    "revocation_source",
)


def _oidc_session_with_bound_credential(row: Any) -> dict[str, Any]:
    session = row_to_oidc_browser_session(row)
    if row["bound_credential_row_id"] is None:
        session["_bound_credential"] = None
        return session
    credential_row = {
        column: row[f"bound_credential_{column}"]
        for column in _OIDC_BOUND_CREDENTIAL_COLUMNS
    }
    session["_bound_credential"] = row_to_webauthn_credential(credential_row)
    return session


def _oidc_session_bound_credential_projection() -> str:
    return ", ".join(
        f"credential.{column} AS bound_credential_{column}"
        for column in _OIDC_BOUND_CREDENTIAL_COLUMNS
    )


def create_oidc_browser_session(
    *,
    token_digest: str,
    oidc_token_digest: str,
    user_id: str,
    roles: list[str],
    ttl_seconds: int,
    provider_expires_at_epoch: int,
    require_webauthn: bool,
    pending_ttl_seconds: int | None = None,
) -> dict[str, Any]:
    token_hash = _oidc_browser_session_digest("token_digest", token_digest)
    oidc_hash = _oidc_browser_session_digest("oidc_token_digest", oidc_token_digest)
    identity_id = _oidc_browser_session_text("user_id", user_id)
    _, roles_json = _oidc_browser_session_roles(roles)
    if not isinstance(require_webauthn, bool):
        raise MetadataStoreError(
            "OIDC browser session require_webauthn must be a boolean"
        )
    if (
        isinstance(ttl_seconds, bool)
        or not isinstance(ttl_seconds, int)
        or not _OIDC_BROWSER_SESSION_TTL_MIN_SECONDS
        <= ttl_seconds
        <= _OIDC_BROWSER_SESSION_TTL_MAX_SECONDS
    ):
        raise MetadataStoreError(
            "OIDC browser session ttl_seconds must be between "
            f"{_OIDC_BROWSER_SESSION_TTL_MIN_SECONDS} and "
            f"{_OIDC_BROWSER_SESSION_TTL_MAX_SECONDS}"
        )
    if pending_ttl_seconds is not None and (
        isinstance(pending_ttl_seconds, bool)
        or not isinstance(pending_ttl_seconds, int)
        or not _OIDC_BROWSER_SESSION_TTL_MIN_SECONDS
        <= pending_ttl_seconds
        <= _OIDC_BROWSER_SESSION_PENDING_TTL_MAX_SECONDS
    ):
        raise MetadataStoreError(
            "OIDC browser session pending_ttl_seconds must be between "
            f"{_OIDC_BROWSER_SESSION_TTL_MIN_SECONDS} and "
            f"{_OIDC_BROWSER_SESSION_PENDING_TTL_MAX_SECONDS}"
        )
    if (
        isinstance(provider_expires_at_epoch, bool)
        or not isinstance(provider_expires_at_epoch, int)
        or provider_expires_at_epoch <= 0
    ):
        raise MetadataStoreError(
            "OIDC browser session provider expiry must be an absolute epoch"
        )
    session_id = str(uuid.uuid4())
    with connect() as conn:
        _lock_webauthn_authority(conn)
        now = _metadata_utcnow(conn)
        now_s = now.isoformat()
        _prune_oidc_browser_sessions(conn, now)
        existing = conn.execute(
            "SELECT id FROM oidc_browser_sessions WHERE token_digest = ?",
            (token_hash,),
        ).fetchone()
        if existing is not None:
            raise MetadataStoreError(
                "OIDC browser session token digest is already registered"
            )
        global_count = conn.execute(
            """
            SELECT COUNT(*) AS count
            FROM oidc_browser_sessions
            WHERE (status = 'active' AND expires_at > ?)
               OR (
                    status = 'pending_webauthn'
                    AND COALESCE(pending_expires_at, expires_at) > ?
               )
            """,
            (now_s, now_s),
        ).fetchone()
        if int(global_count["count"] if global_count else 0) >= (
            _OIDC_BROWSER_SESSION_GLOBAL_LIVE_MAX
        ):
            raise MetadataStoreError(
                "OIDC browser session global live capacity has been reached"
            )
        user_count = conn.execute(
            """
            SELECT COUNT(*) AS count
            FROM oidc_browser_sessions
            WHERE user_id = ?
              AND (
                    (status = 'active' AND expires_at > ?)
                    OR (
                        status = 'pending_webauthn'
                        AND COALESCE(pending_expires_at, expires_at) > ?
                    )
              )
            """,
            (identity_id, now_s, now_s),
        ).fetchone()
        if int(user_count["count"] if user_count else 0) >= (
            _OIDC_BROWSER_SESSION_USER_LIVE_MAX
        ):
            raise MetadataStoreError(
                "OIDC browser session user live capacity has been reached"
            )
        status = "pending_webauthn" if require_webauthn else "active"
        activated_at = None if require_webauthn else now_s
        provider_expires_at = datetime.fromtimestamp(
            provider_expires_at_epoch, tz=timezone.utc
        )
        if provider_expires_at <= now:
            raise MetadataStoreError("OIDC provider token is already expired")
        expires_at = min(
            now + timedelta(seconds=ttl_seconds), provider_expires_at
        ).isoformat()
        effective_pending_ttl = min(
            ttl_seconds,
            pending_ttl_seconds
            if pending_ttl_seconds is not None
            else _OIDC_BROWSER_SESSION_PENDING_TTL_MAX_SECONDS,
        )
        pending_expires_at = (
            min(
                now + timedelta(seconds=effective_pending_ttl),
                datetime.fromisoformat(expires_at),
            ).isoformat()
            if require_webauthn
            else None
        )
        conn.execute(
            """
            INSERT INTO oidc_browser_sessions (
                id, token_digest, oidc_token_digest, user_id, roles_json, status,
                provider_expires_at, expires_at, pending_expires_at,
                created_at, updated_at, activated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                session_id,
                token_hash,
                oidc_hash,
                identity_id,
                roles_json,
                status,
                provider_expires_at.isoformat(),
                expires_at,
                pending_expires_at,
                now_s,
                now_s,
                activated_at,
            ),
        )
        row = conn.execute(
            "SELECT * FROM oidc_browser_sessions WHERE id = ?", (session_id,)
        ).fetchone()
    return row_to_oidc_browser_session(row)


def get_oidc_browser_session(token_digest: str) -> dict[str, Any] | None:
    token_hash = _oidc_browser_session_digest("token_digest", token_digest)
    with connect() as conn:
        now_s = _metadata_utcnow(conn).isoformat()
        row = conn.execute(
            f"""
            SELECT session.*, credential.id AS bound_credential_row_id,
                   {_oidc_session_bound_credential_projection()}
            FROM oidc_browser_sessions AS session
            LEFT JOIN webauthn_credentials AS credential
              ON credential.id = session.bound_webauthn_credential_id
             AND credential.user_id = session.user_id
             AND credential.revoked_at IS NULL
            WHERE session.token_digest = ?
              AND (
                    (
                        session.status = 'pending_webauthn'
                        AND session.expires_at > ?
                        AND session.pending_expires_at > ?
                    )
                    OR (
                        session.status = 'active'
                        AND session.expires_at > ?
                        AND (
                            session.bound_webauthn_credential_id IS NULL
                            OR credential.id IS NOT NULL
                        )
                    )
              )
            """,
            (token_hash, now_s, now_s, now_s),
        ).fetchone()
    return _oidc_session_with_bound_credential(row) if row else None


def get_active_oidc_browser_session(token_digest: str) -> dict[str, Any] | None:
    token_hash = _oidc_browser_session_digest("token_digest", token_digest)
    with connect() as conn:
        now_s = _metadata_utcnow(conn).isoformat()
        row = conn.execute(
            f"""
            SELECT session.*, credential.id AS bound_credential_row_id,
                   {_oidc_session_bound_credential_projection()}
            FROM oidc_browser_sessions AS session
            LEFT JOIN webauthn_credentials AS credential
              ON credential.id = session.bound_webauthn_credential_id
             AND credential.user_id = session.user_id
             AND credential.revoked_at IS NULL
            WHERE session.token_digest = ?
              AND session.status = 'active'
              AND session.expires_at > ?
              AND (
                    session.bound_webauthn_credential_id IS NULL
                    OR credential.id IS NOT NULL
              )
            """,
            (token_hash, now_s),
        ).fetchone()
    return _oidc_session_with_bound_credential(row) if row else None


def _prune_oidc_activation_deliveries(conn: Any, now: datetime) -> None:
    conn.execute(
        "DELETE FROM oidc_session_activation_deliveries "
        "WHERE expires_at <= ? OR (consumed_at IS NOT NULL AND consumed_at <= ?)",
        (now.isoformat(), (now - timedelta(minutes=10)).isoformat()),
    )


def finalize_oidc_browser_session_activation(
    *,
    old_token_digest: str,
    new_token_digest: str,
    session_id: str,
    user_id: str,
    expires_at: str,
    pending_expires_at: str,
    challenge: str,
    credential_id: str,
    credential_record_id: str,
    expected_sign_count: int,
    new_sign_count: int,
    assertion_digest: str,
    encrypted_active_token: str,
    trust_bundle_digest: str | None,
    trust_bundle_sequence: int | None,
    authenticator_class: str,
) -> dict[str, Any]:
    old_token_hash = _oidc_browser_session_digest(
        "old_token_digest", old_token_digest
    )
    new_token_hash = _oidc_browser_session_digest(
        "new_token_digest", new_token_digest
    )
    if hmac.compare_digest(old_token_hash, new_token_hash):
        raise MetadataStoreError(
            "OIDC browser session activation must rotate the session token digest"
        )
    expected_session_id = _oidc_browser_session_text(
        "session_id", session_id, maximum_bytes=128
    )
    expected_user_id = _oidc_browser_session_text("user_id", user_id)
    expected_expires_at = _oidc_browser_session_timestamp("expires_at", expires_at)
    expected_pending_expires_at = _oidc_browser_session_timestamp(
        "pending_expires_at", pending_expires_at
    )
    if expected_pending_expires_at > expected_expires_at:
        raise MetadataStoreError(
            "OIDC browser session pending expiry exceeds the active expiry"
        )
    challenge_value = _oidc_browser_session_text(
        "challenge", challenge, maximum_bytes=128
    )
    if re.fullmatch(r"[A-Za-z0-9_-]{43}", challenge_value) is None:
        raise MetadataStoreError("OIDC browser session challenge is invalid")
    expected_credential_id = _oidc_browser_session_text(
        "credential_id", credential_id, maximum_bytes=2048
    )
    expected_credential_record_id = _oidc_browser_session_text(
        "credential_record_id", credential_record_id
    )
    if (
        isinstance(expected_sign_count, bool)
        or not isinstance(expected_sign_count, int)
        or expected_sign_count < 0
        or isinstance(new_sign_count, bool)
        or not isinstance(new_sign_count, int)
        or new_sign_count < 0
        or not (
            (expected_sign_count == 0 and new_sign_count == 0)
            or new_sign_count > expected_sign_count
        )
    ):
        raise MetadataStoreError(
            "OIDC browser session authenticator sign counter transition is invalid"
        )
    if (trust_bundle_digest is None) != (trust_bundle_sequence is None):
        raise MetadataStoreError(
            "OIDC browser session activation trust bundle binding is incomplete"
        )
    activation_trust_digest = (
        _oidc_browser_session_digest("trust_bundle_digest", trust_bundle_digest)
        if trust_bundle_digest is not None
        else None
    )
    if trust_bundle_sequence is not None and (
        isinstance(trust_bundle_sequence, bool)
        or not isinstance(trust_bundle_sequence, int)
        or trust_bundle_sequence < 1
    ):
        raise MetadataStoreError(
            "OIDC browser session activation trust bundle sequence is invalid"
        )
    activation_authenticator_class = _oidc_browser_session_text(
        "authenticator_class", authenticator_class, maximum_bytes=128
    )
    activation_assertion_digest = _oidc_browser_session_digest(
        "assertion_digest", assertion_digest
    )
    if (
        not isinstance(encrypted_active_token, str)
        or not encrypted_active_token.startswith("v1:")
        or len(encrypted_active_token.encode("utf-8")) > 4096
    ):
        raise MetadataStoreError(
            "OIDC browser session activation token envelope is invalid"
        )
    try:
        active_token = decrypt_secret(encrypted_active_token)
    except (ValueError, TypeError) as exc:
        raise MetadataStoreError(
            "OIDC browser session activation token envelope is invalid"
        ) from exc
    if (
        re.fullmatch(r"[A-Za-z0-9_-]{64}", active_token) is None
        or not hmac.compare_digest(
            "sha256:" + hashlib.sha256(active_token.encode("ascii")).hexdigest(),
            new_token_hash,
        )
    ):
        raise MetadataStoreError(
            "OIDC browser session activation token envelope does not match its digest"
        )

    def deny(reason: str, session: dict[str, Any] | None = None) -> None:
        raise _OIDCBrowserSessionActivationDenied(
            {"ok": False, "reason": reason, "session": session}
        )

    try:
        with connect() as conn:
            _lock_webauthn_authority(conn)
            now = _metadata_utcnow(conn)
            now_s = now.isoformat()
            _prune_oidc_activation_deliveries(conn, now)
            row = conn.execute(
                "SELECT * FROM oidc_browser_sessions WHERE token_digest = ?",
                (old_token_hash,),
            ).fetchone()
            if row is None:
                deny("session_not_found")
            session = row_to_oidc_browser_session(row)
            if str(row["id"]) != expected_session_id:
                deny("session_id_mismatch", session)
            if str(row["user_id"]) != expected_user_id:
                deny("session_user_mismatch", session)
            if str(row["expires_at"]) != expected_expires_at:
                deny("session_expiry_mismatch", session)
            if str(row["pending_expires_at"] or "") != expected_pending_expires_at:
                deny("session_pending_expiry_mismatch", session)
            if row["status"] != "pending_webauthn":
                deny("session_not_pending", session)
            if row["expires_at"] <= now_s:
                deny("session_expired", session)
            if row["pending_expires_at"] <= now_s:
                deny("session_pending_expired", session)
            duplicate = conn.execute(
                "SELECT id FROM oidc_browser_sessions WHERE token_digest = ?",
                (new_token_hash,),
            ).fetchone()
            if duplicate is not None:
                deny("new_token_digest_in_use", session)

            challenge_row = conn.execute(
                """
                SELECT * FROM webauthn_challenges
                WHERE challenge = ?
                  AND challenge_type = 'oidc-session-binding'
                  AND user_id = ?
                  AND approval_request_id IS NULL
                  AND used_at IS NULL
                  AND expires_at > ?
                """,
                (challenge_value, expected_user_id, now_s),
            ).fetchone()
            if challenge_row is None:
                deny("challenge_not_found_or_expired", session)
            challenge_payload = loads(challenge_row["payload_json"], None)
            expected_payload_keys = {
                "v",
                "type",
                "session_id",
                "user_id",
                "session_expires_at",
                "pending_expires_at",
                "nonce",
            }
            if not isinstance(challenge_payload, dict) or set(
                challenge_payload
            ) != expected_payload_keys:
                deny("challenge_payload_mismatch", session)
            nonce = challenge_payload.get("nonce")
            if (
                challenge_payload.get("v") != 1
                or challenge_payload.get("type")
                != "serverware.oidc_session_binding"
                or challenge_payload.get("session_id") != expected_session_id
                or challenge_payload.get("user_id") != expected_user_id
                or challenge_payload.get("session_expires_at")
                != expected_expires_at
                or challenge_payload.get("pending_expires_at")
                != expected_pending_expires_at
                or not isinstance(nonce, str)
                or re.fullmatch(r"[A-Za-z0-9_-]{32}", nonce) is None
            ):
                deny("challenge_payload_mismatch", session)
            expected_challenge = (
                base64.urlsafe_b64encode(
                    hashlib.sha256(dumps(challenge_payload).encode("utf-8")).digest()
                )
                .decode("ascii")
                .rstrip("=")
            )
            if not hmac.compare_digest(challenge_value, expected_challenge):
                deny("challenge_payload_mismatch", session)

            credential = conn.execute(
                "SELECT * FROM webauthn_credentials WHERE id = ?",
                (expected_credential_record_id,),
            ).fetchone()
            if credential is None:
                deny("credential_not_found", session)
            if str(credential["credential_id"]) != expected_credential_id:
                deny("credential_id_mismatch", session)
            if str(credential["user_id"]) != expected_user_id:
                deny("credential_user_mismatch", session)
            if credential["revoked_at"] is not None:
                deny("credential_revoked", session)
            if int(credential["sign_count"]) != expected_sign_count:
                deny("credential_sign_count_mismatch", session)

            claimed = conn.execute(
                """
                UPDATE webauthn_challenges
                SET used_at = ?
                WHERE id = ?
                  AND challenge = ?
                  AND challenge_type = 'oidc-session-binding'
                  AND user_id = ?
                  AND approval_request_id IS NULL
                  AND payload_json = ?
                  AND used_at IS NULL
                  AND expires_at > ?
                """,
                (
                    now_s,
                    challenge_row["id"],
                    challenge_value,
                    expected_user_id,
                    dumps(challenge_payload),
                    now_s,
                ),
            )
            if claimed.rowcount != 1:
                deny("challenge_state_changed", session)
            counter_updated = conn.execute(
                """
                UPDATE webauthn_credentials
                SET sign_count = ?, last_used_at = ?, updated_at = ?
                WHERE id = ?
                  AND credential_id = ?
                  AND user_id = ?
                  AND revoked_at IS NULL
                  AND sign_count = ?
                """,
                (
                    new_sign_count,
                    now_s,
                    now_s,
                    expected_credential_record_id,
                    expected_credential_id,
                    expected_user_id,
                    expected_sign_count,
                ),
            )
            if counter_updated.rowcount != 1:
                deny("credential_sign_count_changed", session)
            activated_update = conn.execute(
                """
                UPDATE oidc_browser_sessions
                SET token_digest = ?, status = 'active',
                    bound_webauthn_credential_id = ?, activated_at = ?,
                    updated_at = ?, pending_expires_at = NULL,
                    activation_trust_bundle_digest = ?,
                    activation_trust_bundle_sequence = ?,
                    activation_authenticator_class = ?
                WHERE id = ?
                  AND token_digest = ?
                  AND user_id = ?
                  AND status = 'pending_webauthn'
                  AND expires_at = ?
                  AND pending_expires_at = ?
                  AND expires_at > ?
                  AND pending_expires_at > ?
                  AND EXISTS (
                        SELECT 1
                        FROM webauthn_credentials AS credential
                        WHERE credential.id = ?
                          AND credential.credential_id = ?
                          AND credential.user_id = oidc_browser_sessions.user_id
                          AND credential.revoked_at IS NULL
                          AND credential.sign_count = ?
                  )
                """,
                (
                    new_token_hash,
                    expected_credential_record_id,
                    now_s,
                    now_s,
                    activation_trust_digest,
                    trust_bundle_sequence,
                    activation_authenticator_class,
                    expected_session_id,
                    old_token_hash,
                    expected_user_id,
                    expected_expires_at,
                    expected_pending_expires_at,
                    now_s,
                    now_s,
                    expected_credential_record_id,
                    expected_credential_id,
                    new_sign_count,
                ),
            )
            if activated_update.rowcount != 1:
                deny("session_state_changed", session)
            activated_row = conn.execute(
                "SELECT * FROM oidc_browser_sessions WHERE id = ?",
                (expected_session_id,),
            ).fetchone()
            delivery_expiry = min(
                now
                + timedelta(seconds=OIDC_SESSION_ACTIVATION_RETRY_TTL_SECONDS),
                datetime.fromisoformat(expected_expires_at),
            ).isoformat()
            conn.execute(
                """
                INSERT INTO oidc_session_activation_deliveries (
                    id, session_id, old_token_digest, new_token_digest,
                    assertion_digest, challenge_id, credential_record_id,
                    encrypted_active_token, created_at, expires_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(uuid.uuid4()),
                    expected_session_id,
                    old_token_hash,
                    new_token_hash,
                    activation_assertion_digest,
                    str(challenge_row["id"]),
                    expected_credential_record_id,
                    encrypted_active_token,
                    now_s,
                    delivery_expiry,
                ),
            )
            append_audit_event(
                conn,
                event_type="oidc.browser_session.activated",
                actor_type="admin",
                actor_id=expected_user_id,
                event={
                    "session_id": expected_session_id,
                    "user_id": expected_user_id,
                    "challenge_id": str(challenge_row["id"]),
                    "expires_at": expected_expires_at,
                    "authenticator_class": activation_authenticator_class,
                    "trust_bundle_digest": activation_trust_digest,
                    "trust_bundle_sequence": trust_bundle_sequence,
                },
                idempotency_key=(
                    f"oidc-browser-session-activation:{expected_session_id}"
                ),
            )
    except _OIDCBrowserSessionActivationDenied as exc:
        return exc.result
    return {
        "ok": True,
        "reason": "activated",
        "session": row_to_oidc_browser_session(activated_row),
        "challenge_id": str(challenge_row["id"]),
        "assertion_digest": activation_assertion_digest,
    }


def recover_oidc_session_activation_delivery(
    *, old_token_digest: str, assertion_digest: str, challenge: str
) -> dict[str, Any]:
    old_token_hash = _oidc_browser_session_digest(
        "old_token_digest", old_token_digest
    )
    expected_assertion_digest = _oidc_browser_session_digest(
        "assertion_digest", assertion_digest
    )
    expected_challenge = _oidc_browser_session_text(
        "challenge", challenge, maximum_bytes=128
    )
    if re.fullmatch(r"[A-Za-z0-9_-]{43}", expected_challenge) is None:
        raise MetadataStoreError("OIDC browser session challenge is invalid")
    with connect() as conn:
        _lock_webauthn_authority(conn)
        now = _metadata_utcnow(conn)
        now_s = now.isoformat()
        _prune_oidc_activation_deliveries(conn, now)
        row = conn.execute(
            """
            SELECT delivery.*
            FROM oidc_session_activation_deliveries AS delivery
            JOIN oidc_browser_sessions AS session
              ON session.id = delivery.session_id
             AND session.token_digest = delivery.new_token_digest
             AND session.status = 'active'
             AND session.expires_at > ?
            JOIN webauthn_credentials AS credential
              ON credential.id = delivery.credential_record_id
             AND credential.id = session.bound_webauthn_credential_id
             AND credential.user_id = session.user_id
             AND credential.revoked_at IS NULL
            JOIN webauthn_challenges AS challenge
              ON challenge.id = delivery.challenge_id
             AND challenge.challenge = ?
             AND challenge.challenge_type = 'oidc-session-binding'
             AND challenge.user_id = session.user_id
             AND challenge.scope_key = session.id
             AND challenge.used_at IS NOT NULL
            WHERE delivery.old_token_digest = ?
              AND delivery.assertion_digest = ?
              AND delivery.consumed_at IS NULL
              AND delivery.expires_at > ?
            """,
            (
                now_s,
                expected_challenge,
                old_token_hash,
                expected_assertion_digest,
                now_s,
            ),
        ).fetchone()
        if row is None:
            return {"ok": False, "reason": "activation_delivery_not_available"}
        try:
            active_token = decrypt_secret(str(row["encrypted_active_token"]))
        except (TypeError, ValueError):
            return {"ok": False, "reason": "activation_delivery_envelope_invalid"}
        if (
            re.fullmatch(r"[A-Za-z0-9_-]{64}", active_token) is None
            or not hmac.compare_digest(
                "sha256:"
                + hashlib.sha256(active_token.encode("ascii")).hexdigest(),
                str(row["new_token_digest"]),
            )
        ):
            return {"ok": False, "reason": "activation_delivery_envelope_mismatch"}
        claimed = conn.execute(
            """
            UPDATE oidc_session_activation_deliveries
            SET consumed_at = ?
            WHERE id = ? AND old_token_digest = ? AND assertion_digest = ?
              AND consumed_at IS NULL AND expires_at > ?
            """,
            (now_s, row["id"], old_token_hash, expected_assertion_digest, now_s),
        )
        if claimed.rowcount != 1:
            return {"ok": False, "reason": "activation_delivery_claim_raced"}
        session = conn.execute(
            "SELECT * FROM oidc_browser_sessions WHERE id = ?",
            (row["session_id"],),
        ).fetchone()
        append_audit_event(
            conn,
            event_type="oidc.browser_session.activation_delivery_recovered",
            actor_type="admin",
            actor_id=str(session["user_id"]),
            event={
                "session_id": str(row["session_id"]),
                "challenge_id": str(row["challenge_id"]),
                "assertion_digest": expected_assertion_digest,
                "delivery_id": str(row["id"]),
            },
            idempotency_key=f"oidc-activation-delivery:{row['id']}",
        )
    return {
        "ok": True,
        "encrypted_active_token": str(row["encrypted_active_token"]),
        "session": row_to_oidc_browser_session(session),
        "challenge_id": str(row["challenge_id"]),
    }


def activate_oidc_browser_session(
    *, token_digest: str, credential_record_id: str
) -> dict[str, Any]:
    token_hash = _oidc_browser_session_digest("token_digest", token_digest)
    credential_id = _oidc_browser_session_text(
        "credential_record_id", credential_record_id
    )
    with connect() as conn:
        _lock_webauthn_authority(conn)
        now_s = _metadata_utcnow(conn).isoformat()
        row = conn.execute(
            "SELECT * FROM oidc_browser_sessions WHERE token_digest = ?",
            (token_hash,),
        ).fetchone()
        if row is None:
            return {"ok": False, "reason": "session_not_found", "session": None}
        session = row_to_oidc_browser_session(row)
        if row["status"] == "active":
            return {
                "ok": False,
                "reason": "session_already_active",
                "session": session,
            }
        if row["status"] == "revoked":
            return {"ok": False, "reason": "session_revoked", "session": session}
        if row["expires_at"] <= now_s:
            return {"ok": False, "reason": "session_expired", "session": session}
        if (
            row["pending_expires_at"] is not None
            and row["pending_expires_at"] <= now_s
        ):
            return {
                "ok": False,
                "reason": "session_pending_expired",
                "session": session,
            }
        credential = conn.execute(
            "SELECT user_id, revoked_at FROM webauthn_credentials WHERE id = ?",
            (credential_id,),
        ).fetchone()
        if credential is None:
            return {
                "ok": False,
                "reason": "credential_not_found",
                "session": session,
            }
        if credential["revoked_at"] is not None:
            return {
                "ok": False,
                "reason": "credential_revoked",
                "session": session,
            }
        if credential["user_id"] != row["user_id"]:
            return {
                "ok": False,
                "reason": "credential_user_mismatch",
                "session": session,
            }
        updated = conn.execute(
            """
            UPDATE oidc_browser_sessions
            SET status = 'active', bound_webauthn_credential_id = ?,
                activated_at = ?, updated_at = ?, pending_expires_at = NULL
            WHERE id = ?
              AND status = 'pending_webauthn'
              AND expires_at > ?
              AND COALESCE(pending_expires_at, expires_at) > ?
              AND EXISTS (
                    SELECT 1
                    FROM webauthn_credentials AS credential
                    WHERE credential.id = ?
                      AND credential.user_id = oidc_browser_sessions.user_id
                      AND credential.revoked_at IS NULL
              )
            """,
            (
                credential_id,
                now_s,
                now_s,
                row["id"],
                now_s,
                now_s,
                credential_id,
            ),
        )
        if updated.rowcount != 1:
            current = conn.execute(
                "SELECT * FROM oidc_browser_sessions WHERE id = ?", (row["id"],)
            ).fetchone()
            return {
                "ok": False,
                "reason": "session_state_changed",
                "session": (row_to_oidc_browser_session(current) if current else None),
            }
        activated = conn.execute(
            "SELECT * FROM oidc_browser_sessions WHERE id = ?", (row["id"],)
        ).fetchone()
    return {
        "ok": True,
        "reason": "activated",
        "session": row_to_oidc_browser_session(activated),
    }


def revoke_oidc_browser_session(
    *, token_digest: str, actor_id: str, reason: str
) -> dict[str, Any]:
    token_hash = _oidc_browser_session_digest("token_digest", token_digest)
    actor = _oidc_browser_session_text("actor_id", actor_id)
    revocation_reason = _oidc_browser_session_text("revocation reason", reason)
    with connect() as conn:
        _lock_webauthn_authority(conn)
        now_s = _metadata_utcnow(conn).isoformat()
        row = conn.execute(
            "SELECT * FROM oidc_browser_sessions WHERE token_digest = ?",
            (token_hash,),
        ).fetchone()
        if row is None:
            return {"ok": False, "reason": "session_not_found", "session": None}
        session = row_to_oidc_browser_session(row)
        if row["status"] == "revoked":
            return {"ok": True, "reason": "already_revoked", "session": session}
        updated = conn.execute(
            """
            UPDATE oidc_browser_sessions
            SET status = 'revoked', revoked_at = ?, revocation_reason = ?,
                updated_at = ?
            WHERE id = ? AND status IN ('pending_webauthn', 'active')
            """,
            (now_s, revocation_reason, now_s, row["id"]),
        )
        if updated.rowcount != 1:
            current = conn.execute(
                "SELECT * FROM oidc_browser_sessions WHERE id = ?", (row["id"],)
            ).fetchone()
            return {
                "ok": False,
                "reason": "session_state_changed",
                "session": (row_to_oidc_browser_session(current) if current else None),
            }
        revoked = conn.execute(
            "SELECT * FROM oidc_browser_sessions WHERE id = ?", (row["id"],)
        ).fetchone()
        append_audit_event(
            conn,
            event_type="oidc.browser_session.revoked",
            actor_type="admin",
            actor_id=actor,
            event={
                "session_id": str(row["id"]),
                "user_id": str(row["user_id"]),
                "revoked_at": now_s,
                "revocation_reason_recorded": True,
            },
            idempotency_key=f"oidc-browser-session-revoked:{row['id']}",
        )
    return {
        "ok": True,
        "reason": "revoked",
        "session": row_to_oidc_browser_session(revoked),
    }


def revoke_unbound_oidc_browser_sessions(
    *, actor_id: str, reason: str
) -> dict[str, Any]:
    actor = _oidc_browser_session_text("actor_id", actor_id)
    revocation_reason = _oidc_browser_session_text("revocation reason", reason)
    with connect() as conn:
        _lock_webauthn_authority(conn)
        now_s = _metadata_utcnow(conn).isoformat()
        rows = conn.execute(
            """
            SELECT id
            FROM oidc_browser_sessions
            WHERE status = 'active'
              AND bound_webauthn_credential_id IS NULL
            ORDER BY id ASC
            """
        ).fetchall()
        session_ids = [str(row["id"]) for row in rows]
        revoked = conn.execute(
            """
            UPDATE oidc_browser_sessions
            SET status = 'revoked', revoked_at = ?, updated_at = ?,
                revocation_reason = ?
            WHERE status = 'active'
              AND bound_webauthn_credential_id IS NULL
            """,
            (now_s, now_s, revocation_reason),
        )
        if revoked.rowcount != len(session_ids):
            raise MetadataStoreError(
                "unbound OIDC browser session revocation state changed"
            )
        if session_ids:
            append_audit_event(
                conn,
                event_type="oidc.browser_sessions.unbound_revoked",
                actor_type="admin",
                actor_id=actor,
                event={
                    "session_ids": session_ids,
                    "revoked_session_count": len(session_ids),
                    "revoked_at": now_s,
                    "revocation_reason_recorded": True,
                },
            )
    return {
        "ok": True,
        "reason": "revoked",
        "revoked_session_count": len(session_ids),
        "session_ids": session_ids,
    }


def get_pending_oauth_credential(item_id: str) -> dict[str, Any] | None:
    now_s = iso_now()
    with connect() as conn:
        _mark_expired_pending_oauth_credentials(conn, now_s)
        row = conn.execute(
            "SELECT * FROM pending_oauth_credentials WHERE id = ?",
            (item_id,),
        ).fetchone()
    return row_to_pending_oauth_credential(row) if row else None


def list_pending_oauth_credentials(
    *, requester_id: str | None = None
) -> list[dict[str, Any]]:
    now_s = iso_now()
    requester = None
    if requester_id is not None:
        if (
            not isinstance(requester_id, str)
            or not requester_id
            or len(requester_id) > 512
        ):
            raise ManagedOAuthCredentialError(
                "pending OAuth credential requester is invalid"
            )
        requester = requester_id
    with connect() as conn:
        _mark_expired_pending_oauth_credentials(conn, now_s)
        if requester is None:
            rows = conn.execute(
                "SELECT * FROM pending_oauth_credentials ORDER BY created_at DESC",
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM pending_oauth_credentials WHERE requester_id = ? "
                "ORDER BY created_at DESC",
                (requester,),
            ).fetchall()
    return [row_to_pending_oauth_credential(row) for row in rows]


def cancel_pending_oauth_credential(item_id: str, *, actor_id: str) -> dict[str, Any]:
    now_s = iso_now()
    with connect() as conn:
        _lock_credential_mutation(conn, item_id)
        _mark_expired_pending_oauth_credentials(conn, now_s)
        row = conn.execute(
            "SELECT * FROM pending_oauth_credentials WHERE id = ?",
            (item_id,),
        ).fetchone()
        if row is None:
            return {"ok": False, "reason": "pending_credential_not_found"}
        if row["requester_id"] != actor_id:
            return {"ok": False, "reason": "requester_mismatch"}
        if row["status"] != "pending":
            return {"ok": False, "reason": f"pending_credential_{row['status']}"}
        updated = conn.execute(
            """
            UPDATE pending_oauth_credentials
            SET status = 'cancelled', revocation_status = 'pending', revocation_error = NULL,
                revocation_next_attempt_at = ?, revocation_lease_owner = NULL,
                revocation_lease_until = NULL, updated_at = ?
            WHERE id = ? AND status = 'pending'
            """,
            (now_s, now_s, item_id),
        )
        if updated.rowcount != 1:
            return {"ok": False, "reason": "pending_credential_state_changed"}
        append_audit_event(
            conn,
            event_type="credential.oauth_pending.cancelled",
            actor_type="admin",
            actor_id=actor_id,
            event={"pending_credential_id": item_id, "requester_id": actor_id},
        )
        result = conn.execute(
            "SELECT * FROM pending_oauth_credentials WHERE id = ?",
            (item_id,),
        ).fetchone()
    return {"ok": True, "pending": row_to_pending_oauth_credential(result)}


def get_pending_oauth_revocation_material(item_id: str) -> dict[str, Any] | None:
    now_s = iso_now()
    with connect() as conn:
        _lock_credential_mutation(conn, item_id)
        _mark_expired_pending_oauth_credentials(conn, now_s)
        row = conn.execute(
            "SELECT * FROM pending_oauth_credentials WHERE id = ?",
            (item_id,),
        ).fetchone()
        if row is None or row["status"] not in {"cancelled", "expired", "rejected"}:
            return None
        result = row_to_pending_oauth_credential(row)
        result["secret"] = decrypt_secret_envelope(row)
    return result


def _oauth_revocation_backoff_seconds(attempts: int) -> int:
    return min(60 * 60, 5 * (2 ** min(max(attempts - 1, 0), 10)))


def finish_pending_oauth_revocation(
    item_id: str,
    *,
    actor_id: str,
    succeeded: bool,
    error: str | None = None,
) -> dict[str, Any]:
    if error is not None and (not isinstance(error, str) or len(error) > 500):
        raise ManagedOAuthCredentialError("pending OAuth revocation error is invalid")
    now_s = iso_now()
    with connect() as conn:
        _lock_credential_mutation(conn, item_id)
        row = conn.execute(
            "SELECT * FROM pending_oauth_credentials WHERE id = ?",
            (item_id,),
        ).fetchone()
        if row is None:
            return {"ok": False, "reason": "pending_credential_not_found"}
        if row["status"] not in {"cancelled", "expired", "rejected"}:
            return {"ok": False, "reason": "pending_credential_not_terminal"}
        append_audit_event(
            conn,
            event_type=(
                "credential.oauth_pending.revoked"
                if succeeded
                else "credential.oauth_pending.revocation_failed"
            ),
            actor_type="admin",
            actor_id=actor_id,
            event={
                "pending_credential_id": item_id,
                "terminal_status": row["status"],
                "provider": loads(row["review_json"], {}).get("provider"),
                "result": "revoked" if succeeded else "failed",
                "error": error,
            },
        )
        if succeeded:
            conn.execute(
                "DELETE FROM pending_oauth_credentials WHERE id = ?", (item_id,)
            )
            return {"ok": True, "revocation_status": "revoked", "deleted": True}
        attempts = int(row["revocation_attempts"] or 0) + 1
        next_attempt_at = (
            utcnow() + timedelta(seconds=_oauth_revocation_backoff_seconds(attempts))
        ).isoformat()
        conn.execute(
            """
            UPDATE pending_oauth_credentials
            SET revocation_status = 'failed', revocation_error = ?,
                revocation_attempts = ?, revocation_next_attempt_at = ?,
                revocation_lease_owner = NULL, revocation_lease_until = NULL,
                updated_at = ?
            WHERE id = ?
            """,
            (
                error or "provider revocation failed",
                attempts,
                next_attempt_at,
                now_s,
                item_id,
            ),
        )
        result = conn.execute(
            "SELECT * FROM pending_oauth_credentials WHERE id = ?",
            (item_id,),
        ).fetchone()
    return {
        "ok": False,
        "reason": "provider_revocation_failed",
        "pending": row_to_pending_oauth_credential(result),
    }


def _lock_oauth_revocation_work(conn: Any) -> None:
    if isinstance(conn, PostgresMetadataConnection):
        conn.execute(
            "SELECT pg_advisory_xact_lock(?)",
            (_OAUTH_REVOCATION_WORK_LOCK_KEY,),
        )
    elif not conn.in_transaction:
        conn.execute("BEGIN IMMEDIATE")


def _validate_oauth_revocation_work_identity(
    *,
    provider_id: str,
    actor_id: str,
    source: str,
) -> None:
    if (
        not isinstance(provider_id, str)
        or not provider_id
        or len(provider_id) > 64
        or re.fullmatch(r"[A-Za-z0-9._-]+", provider_id) is None
    ):
        raise ManagedOAuthCredentialError("OAuth revocation provider is invalid")
    if not isinstance(actor_id, str) or not actor_id or len(actor_id) > 512:
        raise ManagedOAuthCredentialError("OAuth revocation actor is invalid")
    if (
        not isinstance(source, str)
        or not source
        or len(source) > 128
        or re.fullmatch(r"[A-Za-z0-9._-]+", source) is None
    ):
        raise ManagedOAuthCredentialError("OAuth revocation source is invalid")


def reserve_oauth_revocation_work(
    *,
    provider_id: str,
    actor_id: str,
    source: str,
) -> str:
    _validate_oauth_revocation_work_identity(
        provider_id=provider_id,
        actor_id=actor_id,
        source=source,
    )
    item_id = str(uuid.uuid4())
    now = utcnow()
    now_s = now.isoformat()
    reservation_expires_at = (
        now + timedelta(seconds=_OAUTH_REVOCATION_RESERVED_SECONDS)
    ).isoformat()
    encrypted = _envelope_values(item_id, "{}", 1)
    with connect() as conn:
        _lock_oauth_revocation_work(conn)
        _expire_oauth_exchange_reservations(conn, now_s)
        count_row = conn.execute(
            "SELECT COUNT(*) AS count FROM oauth_revocation_work"
        ).fetchone()
        if (
            int(count_row["count"] if count_row else 0)
            >= _OAUTH_REVOCATION_BACKLOG_MAX_COUNT
        ):
            raise ManagedOAuthCredentialError(
                "OAuth revocation work capacity has been reached"
            )
        conn.execute(
            """
            INSERT INTO oauth_revocation_work (
                id, provider_id, actor_id, source, encrypted_secret, encrypted_dek,
                secret_nonce, secret_ciphertext, secret_kek_id, credential_version,
                secret_updated_at, status, attempts, next_attempt_at, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'reserved', 0, ?, ?, ?)
            """,
            (
                item_id,
                provider_id,
                actor_id,
                source,
                encrypted["encrypted_secret"],
                encrypted["encrypted_dek"],
                encrypted["secret_nonce"],
                encrypted["secret_ciphertext"],
                encrypted["secret_kek_id"],
                encrypted["credential_version"],
                encrypted["secret_updated_at"],
                reservation_expires_at,
                now_s,
                now_s,
            ),
        )
    return item_id


def _expire_oauth_exchange_reservations(conn: Any, now_s: str) -> None:
    conn.execute(
        "DELETE FROM oauth_revocation_work WHERE status = 'reserved' AND next_attempt_at <= ?",
        (now_s,),
    )
    conn.execute(
        """
        UPDATE oauth_revocation_work
        SET status = 'issuance_uncertain_unreported',
            last_error = COALESCE(last_error, 'provider exchange outcome is unknown after process interruption'),
            next_attempt_at = ?, lease_owner = NULL, lease_until = NULL, updated_at = ?
        WHERE status = 'exchange_in_flight' AND next_attempt_at <= ?
        """,
        (now_s, now_s, now_s),
    )


def mark_oauth_exchange_started(work_id: str) -> None:
    if not isinstance(work_id, str) or not work_id or len(work_id) > 128:
        raise ManagedOAuthCredentialError("OAuth revocation work binding is invalid")
    now = utcnow()
    now_s = now.isoformat()
    deadline = (now + timedelta(seconds=_OAUTH_REVOCATION_RESERVED_SECONDS)).isoformat()
    with connect() as conn:
        _lock_credential_mutation(conn, work_id)
        updated = conn.execute(
            """
            UPDATE oauth_revocation_work
            SET status = 'exchange_in_flight', next_attempt_at = ?,
                last_error = NULL, updated_at = ?
            WHERE id = ? AND status = 'reserved'
            """,
            (deadline, now_s, work_id),
        )
        if updated.rowcount != 1:
            raise ManagedOAuthCredentialError(
                "OAuth revocation work reservation is unavailable"
            )


def mark_oauth_issuance_uncertain(work_id: str, *, error: str) -> None:
    if not isinstance(error, str) or not error or len(error) > 500:
        raise ManagedOAuthCredentialError("OAuth issuance uncertainty error is invalid")
    now_s = iso_now()
    with connect() as conn:
        _lock_credential_mutation(conn, work_id)
        updated = conn.execute(
            """
            UPDATE oauth_revocation_work
            SET status = 'issuance_uncertain_unreported', last_error = ?,
                next_attempt_at = ?, lease_owner = NULL, lease_until = NULL,
                updated_at = ?
            WHERE id = ? AND status IN ('exchange_in_flight', 'issuance_uncertain_unreported')
            """,
            (error, now_s, now_s, work_id),
        )
        if updated.rowcount != 1:
            raise ManagedOAuthCredentialError(
                "OAuth issuance uncertainty record is unavailable"
            )


def attach_oauth_revocation_material(work_id: str, *, secret: str) -> None:
    secret = validate_credential_secret(secret)
    now = utcnow()
    now_s = now.isoformat()
    encrypted = _envelope_values(work_id, secret, 1)
    with connect() as conn:
        _lock_credential_mutation(conn, work_id)
        updated = conn.execute(
            """
            UPDATE oauth_revocation_work
            SET encrypted_secret = ?, encrypted_dek = ?, secret_nonce = ?,
                secret_ciphertext = ?, secret_kek_id = ?, credential_version = ?,
                secret_updated_at = ?, status = 'held', last_error = NULL,
                next_attempt_at = ?, lease_owner = NULL, lease_until = NULL,
                updated_at = ?
            WHERE id = ? AND status IN ('reserved', 'exchange_in_flight', 'held')
            """,
            (
                encrypted["encrypted_secret"],
                encrypted["encrypted_dek"],
                encrypted["secret_nonce"],
                encrypted["secret_ciphertext"],
                encrypted["secret_kek_id"],
                encrypted["credential_version"],
                encrypted["secret_updated_at"],
                (now + timedelta(seconds=_OAUTH_REVOCATION_HELD_SECONDS)).isoformat(),
                now_s,
                work_id,
            ),
        )
        if updated.rowcount != 1:
            raise ManagedOAuthCredentialError(
                "OAuth revocation work reservation is unavailable"
            )


def create_oauth_revocation_work(
    *,
    provider_id: str,
    actor_id: str,
    source: str,
    secret: str,
) -> str:
    work_id = reserve_oauth_revocation_work(
        provider_id=provider_id,
        actor_id=actor_id,
        source=source,
    )
    try:
        attach_oauth_revocation_material(work_id, secret=secret)
    except Exception:
        complete_oauth_revocation_work(work_id)
        raise
    return work_id


def mark_oauth_revocation_work_pending(work_id: str, *, error: str) -> None:
    if not isinstance(error, str) or not error or len(error) > 500:
        raise ManagedOAuthCredentialError("OAuth revocation work error is invalid")
    now_s = iso_now()
    with connect() as conn:
        _lock_credential_mutation(conn, work_id)
        updated = conn.execute(
            """
            UPDATE oauth_revocation_work
            SET status = 'pending', last_error = ?, next_attempt_at = ?,
                lease_owner = NULL, lease_until = NULL, updated_at = ?
            WHERE id = ? AND status IN ('held', 'pending')
            """,
            (error, now_s, now_s, work_id),
        )
        if updated.rowcount != 1:
            raise ManagedOAuthCredentialError("OAuth revocation work is unavailable")


def complete_oauth_revocation_work(work_id: str) -> bool:
    with connect() as conn:
        _lock_credential_mutation(conn, work_id)
        deleted = conn.execute(
            "DELETE FROM oauth_revocation_work WHERE id = ?",
            (work_id,),
        )
    return deleted.rowcount == 1


def get_oauth_revocation_work_status(work_id: str) -> dict[str, Any] | None:
    with connect() as conn:
        row = conn.execute(
            "SELECT id, provider_id, actor_id, source, status, attempts, last_error, "
            "next_attempt_at, created_at, updated_at "
            "FROM oauth_revocation_work WHERE id = ?",
            (work_id,),
        ).fetchone()
    if row is None:
        return None
    return {
        "id": str(row["id"]),
        "provider_id": str(row["provider_id"]),
        "actor_id": str(row["actor_id"]),
        "source": str(row["source"]),
        "status": str(row["status"]),
        "attempts": int(row["attempts"] or 0),
        "last_error": str(row["last_error"]) if row["last_error"] else None,
        "next_attempt_at": str(row["next_attempt_at"]),
        "created_at": str(row["created_at"]),
        "updated_at": str(row["updated_at"]),
    }


def list_oauth_issuance_uncertainties(
    *, actor_id: str | None = None, limit: int = 100
) -> list[dict[str, Any]]:
    if actor_id is not None and (
        not isinstance(actor_id, str) or not actor_id or len(actor_id) > 512
    ):
        raise ManagedOAuthCredentialError("OAuth issuance uncertainty actor is invalid")
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 1000:
        raise ManagedOAuthCredentialError("OAuth issuance uncertainty limit is invalid")
    now_s = iso_now()
    with connect() as conn:
        _lock_oauth_revocation_work(conn)
        _expire_oauth_exchange_reservations(conn, now_s)
        query = (
            "SELECT id, provider_id, actor_id, source, status, last_error, created_at, updated_at "
            "FROM oauth_revocation_work WHERE status IN "
            "('issuance_uncertain_unreported', 'issuance_uncertain')"
        )
        params: list[Any] = []
        if actor_id is not None:
            query += " AND actor_id = ?"
            params.append(actor_id)
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        rows = conn.execute(query, tuple(params)).fetchall()
    return [
        {
            "id": str(row["id"]),
            "provider_id": str(row["provider_id"]),
            "actor_id": str(row["actor_id"]),
            "source": str(row["source"]),
            "status": str(row["status"]),
            "last_error": str(row["last_error"]) if row["last_error"] else None,
            "created_at": str(row["created_at"]),
            "updated_at": str(row["updated_at"]),
        }
        for row in rows
    ]


def resolve_oauth_issuance_uncertainty(
    work_id: str,
    *,
    actor_id: str,
    _connection: Any | None = None,
) -> dict[str, Any]:
    if not isinstance(work_id, str) or not work_id or len(work_id) > 128:
        raise ManagedOAuthCredentialError("OAuth issuance uncertainty ID is invalid")
    if not isinstance(actor_id, str) or not actor_id or len(actor_id) > 512:
        raise ManagedOAuthCredentialError("OAuth issuance uncertainty actor is invalid")
    connection_scope = (
        connect() if _connection is None else contextlib.nullcontext(_connection)
    )
    with connection_scope as conn:
        _lock_credential_mutation(conn, work_id)
        row = conn.execute(
            "SELECT id, provider_id, actor_id, source, status, created_at "
            "FROM oauth_revocation_work WHERE id = ?",
            (work_id,),
        ).fetchone()
        if row is None:
            return {"ok": False, "reason": "issuance_uncertainty_not_found"}
        if row["status"] not in {
            "issuance_uncertain_unreported",
            "issuance_uncertain",
        }:
            return {"ok": False, "reason": "issuance_uncertainty_not_resolvable"}
        deleted = conn.execute(
            "DELETE FROM oauth_revocation_work WHERE id = ? AND status IN "
            "('issuance_uncertain_unreported', 'issuance_uncertain')",
            (work_id,),
        )
        if deleted.rowcount != 1:
            return {"ok": False, "reason": "issuance_uncertainty_raced"}
    return {
        "ok": True,
        "id": str(row["id"]),
        "provider_id": str(row["provider_id"]),
        "requester_id": str(row["actor_id"]),
        "source": str(row["source"]),
        "created_at": str(row["created_at"]),
        "resolved_by": actor_id,
    }


def _consume_oauth_revocation_work(conn: Any, work_id: str) -> None:
    if not isinstance(work_id, str) or not work_id or len(work_id) > 128:
        raise ManagedOAuthCredentialError("OAuth revocation work binding is invalid")
    deleted = conn.execute(
        "DELETE FROM oauth_revocation_work WHERE id = ? AND status = 'held'",
        (work_id,),
    )
    if deleted.rowcount != 1:
        raise ManagedOAuthCredentialError(
            "OAuth revocation work binding is unavailable"
        )


def _x_oauth_retirement_secret(
    current_secret: str,
    replacement_secret: str | None,
) -> str | None:
    try:
        current = json.loads(current_secret)
        replacement = (
            json.loads(replacement_secret) if replacement_secret is not None else None
        )
    except (json.JSONDecodeError, TypeError):
        raise ManagedOAuthCredentialError(
            "OAuth token retirement material is malformed"
        ) from None
    if not isinstance(current, dict) or (
        replacement is not None and not isinstance(replacement, dict)
    ):
        raise ManagedOAuthCredentialError(
            "OAuth token retirement material is malformed"
        )

    token_sets = (current,) if replacement is None else (current, replacement)
    for token_set in token_sets:
        for field in ("access_token", "refresh_token"):
            value = token_set.get(field)
            if not isinstance(value, str) or not value:
                raise ManagedOAuthCredentialError(
                    "OAuth token retirement material is malformed"
                )

    if replacement is None:
        retirement = {
            "access_token": current["access_token"],
            "refresh_token": current["refresh_token"],
        }
    else:
        retirement = {
            field: current[field]
            for field in ("access_token", "refresh_token")
            if current[field] != replacement[field]
        }
    if not retirement:
        return None
    return dumps(retirement)


def _queue_superseded_oauth_secret(
    conn: Any,
    *,
    credential_row: Any,
    actor_id: str,
    source: str,
    replacing_work_id: str | None = None,
    replacement_secret: str | None = None,
) -> str | None:
    metadata = loads(credential_row["metadata"], {})
    provider_id, _, _ = validate_managed_oauth_account_identity(metadata)
    if provider_id == "google":
        raise ManagedOAuthCredentialError(
            "Google OAuth grants cannot be safely reconnected in place; disconnect and connect again"
        )
    if provider_id != "x":
        raise ManagedOAuthCredentialError(
            "OAuth provider does not declare token-local retirement semantics"
        )
    _validate_oauth_revocation_work_identity(
        provider_id=provider_id,
        actor_id=actor_id,
        source=source,
    )
    retirement_secret = _x_oauth_retirement_secret(
        decrypt_secret_envelope(credential_row),
        replacement_secret,
    )
    if retirement_secret is None:
        return None
    _lock_oauth_revocation_work(conn)
    if replacing_work_id is None:
        count_row = conn.execute(
            "SELECT COUNT(*) AS count FROM oauth_revocation_work"
        ).fetchone()
    else:
        if not isinstance(replacing_work_id, str) or not replacing_work_id:
            raise ManagedOAuthCredentialError(
                "OAuth revocation work replacement is invalid"
            )
        count_row = conn.execute(
            "SELECT COUNT(*) AS count FROM oauth_revocation_work WHERE id <> ?",
            (replacing_work_id,),
        ).fetchone()
    if (
        int(count_row["count"] if count_row else 0)
        >= _OAUTH_REVOCATION_BACKLOG_MAX_COUNT
    ):
        raise ManagedOAuthCredentialError(
            "OAuth revocation work capacity has been reached"
        )

    work_id = str(uuid.uuid4())
    now_s = iso_now()
    encrypted = _envelope_values(
        work_id,
        retirement_secret,
        1,
    )
    conn.execute(
        """
        INSERT INTO oauth_revocation_work (
            id, provider_id, actor_id, source, encrypted_secret, encrypted_dek,
            secret_nonce, secret_ciphertext, secret_kek_id, credential_version,
            secret_updated_at, status, attempts, next_attempt_at, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', 0, ?, ?, ?)
        """,
        (
            work_id,
            provider_id,
            actor_id,
            source,
            encrypted["encrypted_secret"],
            encrypted["encrypted_dek"],
            encrypted["secret_nonce"],
            encrypted["secret_ciphertext"],
            encrypted["secret_kek_id"],
            encrypted["credential_version"],
            encrypted["secret_updated_at"],
            now_s,
            now_s,
            now_s,
        ),
    )
    append_audit_event(
        conn,
        event_type="credential.oauth_token_retirement_queued",
        actor_type="system" if source == "refresh_superseded" else "admin",
        actor_id=actor_id,
        event={
            "credential_id": str(credential_row["id"]),
            "credential_version": int(credential_row["credential_version"] or 1),
            "provider": provider_id,
            "source": source,
            "revocation_work_id": work_id,
        },
    )
    return work_id


def claim_oauth_revocations(
    *,
    worker_id: str,
    limit: int,
    lease_seconds: int = _OAUTH_REVOCATION_LEASE_SECONDS,
) -> list[dict[str, Any]]:
    if not isinstance(worker_id, str) or not worker_id or len(worker_id) > 128:
        raise ManagedOAuthCredentialError("OAuth revocation worker is invalid")
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 100:
        raise ManagedOAuthCredentialError("OAuth revocation claim limit is invalid")
    if not isinstance(lease_seconds, int) or not 5 <= lease_seconds <= 600:
        raise ManagedOAuthCredentialError("OAuth revocation lease is invalid")
    now = utcnow()
    now_s = now.isoformat()
    lease_until = (now + timedelta(seconds=lease_seconds)).isoformat()
    claimed: list[dict[str, Any]] = []
    with connect() as conn:
        _lock_oauth_revocation_work(conn)
        _mark_expired_pending_oauth_credentials(conn, now_s)
        _expire_oauth_exchange_reservations(conn, now_s)
        conn.execute(
            "UPDATE oauth_revocation_work SET status = 'pending', updated_at = ? "
            "WHERE status = 'held' AND next_attempt_at <= ?",
            (now_s, now_s),
        )
        uncertainty_rows = conn.execute(
            """
            SELECT id, provider_id, actor_id, source, last_error
            FROM oauth_revocation_work
            WHERE status = 'issuance_uncertain_unreported'
              AND (lease_until IS NULL OR lease_until <= ?)
            ORDER BY created_at
            LIMIT ?
            """,
            (now_s, limit),
        ).fetchall()
        for row in uncertainty_rows:
            updated = conn.execute(
                "UPDATE oauth_revocation_work SET lease_owner = ?, lease_until = ?, "
                "updated_at = ? WHERE id = ? AND status = 'issuance_uncertain_unreported' "
                "AND (lease_until IS NULL OR lease_until <= ?)",
                (worker_id, lease_until, now_s, row["id"], now_s),
            )
            if updated.rowcount == 1:
                claimed.append(
                    {
                        "kind": "issuance_uncertain",
                        "id": str(row["id"]),
                        "provider_id": str(row["provider_id"]),
                        "actor_id": str(row["actor_id"]),
                        "source": str(row["source"]),
                        "error": str(row["last_error"] or "provider exchange outcome is unknown"),
                    }
                )
        remaining = limit - len(claimed)
        if remaining <= 0:
            return claimed
        pending_rows = conn.execute(
            """
            SELECT * FROM pending_oauth_credentials
            WHERE status IN ('cancelled', 'expired', 'rejected')
              AND COALESCE(revocation_next_attempt_at, updated_at) <= ?
              AND (revocation_lease_until IS NULL OR revocation_lease_until <= ?)
            ORDER BY COALESCE(revocation_next_attempt_at, updated_at), created_at
            LIMIT ?
            """,
            (now_s, now_s, remaining),
        ).fetchall()
        for row in pending_rows:
            conn.execute(
                "UPDATE pending_oauth_credentials SET revocation_lease_owner = ?, "
                "revocation_lease_until = ? WHERE id = ?",
                (worker_id, lease_until, row["id"]),
            )
            review = loads(row["review_json"], {})
            claimed.append(
                {
                    "kind": "pending",
                    "id": str(row["id"]),
                    "provider_id": str(review.get("provider") or ""),
                    "secret": decrypt_secret_envelope(row),
                    "actor_id": str(row["requester_id"]),
                    "source": f"pending_{row['status']}",
                }
            )
        remaining = limit - len(claimed)
        if remaining > 0:
            work_rows = conn.execute(
                """
                SELECT * FROM oauth_revocation_work
                WHERE status = 'pending' AND next_attempt_at <= ?
                  AND (lease_until IS NULL OR lease_until <= ?)
                ORDER BY next_attempt_at, created_at
                LIMIT ?
                """,
                (now_s, now_s, remaining),
            ).fetchall()
            for row in work_rows:
                conn.execute(
                    "UPDATE oauth_revocation_work SET lease_owner = ?, lease_until = ? WHERE id = ?",
                    (worker_id, lease_until, row["id"]),
                )
                claimed.append(
                    {
                        "kind": "exchange",
                        "id": str(row["id"]),
                        "provider_id": str(row["provider_id"]),
                        "secret": decrypt_secret_envelope(row),
                        "actor_id": str(row["actor_id"]),
                        "source": str(row["source"]),
                    }
                )
    return claimed


def finish_oauth_issuance_uncertainty_report(
    work_id: str,
    *,
    worker_id: str,
) -> dict[str, Any]:
    if not isinstance(work_id, str) or not work_id or len(work_id) > 128:
        raise ManagedOAuthCredentialError("OAuth issuance uncertainty ID is invalid")
    if not isinstance(worker_id, str) or not worker_id or len(worker_id) > 128:
        raise ManagedOAuthCredentialError("OAuth issuance uncertainty worker is invalid")
    now_s = iso_now()
    with connect() as conn:
        _lock_credential_mutation(conn, work_id)
        updated = conn.execute(
            """
            UPDATE oauth_revocation_work
            SET status = 'issuance_uncertain', lease_owner = NULL,
                lease_until = NULL, updated_at = ?
            WHERE id = ? AND status = 'issuance_uncertain_unreported'
              AND lease_owner = ?
            """,
            (now_s, work_id, worker_id),
        )
        if updated.rowcount != 1:
            return {"ok": False, "reason": "issuance_uncertainty_report_not_claimed"}
    return {"ok": True, "status": "issuance_uncertain"}


def finish_oauth_revocation_work(
    work_id: str,
    *,
    worker_id: str,
    succeeded: bool,
    error: str | None = None,
) -> dict[str, Any]:
    if error is not None and (not isinstance(error, str) or len(error) > 500):
        raise ManagedOAuthCredentialError("OAuth revocation error is invalid")
    now = utcnow()
    now_s = now.isoformat()
    with connect() as conn:
        _lock_credential_mutation(conn, work_id)
        row = conn.execute(
            "SELECT * FROM oauth_revocation_work WHERE id = ?",
            (work_id,),
        ).fetchone()
        if row is None:
            return {"ok": False, "reason": "revocation_work_not_found"}
        if row["status"] != "pending" or row["lease_owner"] != worker_id:
            return {"ok": False, "reason": "revocation_work_not_claimed"}
        if succeeded:
            conn.execute("DELETE FROM oauth_revocation_work WHERE id = ?", (work_id,))
            return {"ok": True, "revocation_status": "revoked", "deleted": True}
        attempts = int(row["attempts"] or 0) + 1
        next_attempt_at = (
            now + timedelta(seconds=_oauth_revocation_backoff_seconds(attempts))
        ).isoformat()
        conn.execute(
            """
            UPDATE oauth_revocation_work
            SET attempts = ?, last_error = ?, next_attempt_at = ?,
                lease_owner = NULL, lease_until = NULL, updated_at = ?
            WHERE id = ?
            """,
            (
                attempts,
                error or "provider revocation failed",
                next_attempt_at,
                now_s,
                work_id,
            ),
        )
    return {
        "ok": False,
        "reason": "provider_revocation_failed",
        "retry_at": next_attempt_at,
    }


def activate_pending_oauth_credential(
    item_id: str,
    *,
    approval_id: str,
    actor_id: str,
    setup_session_id: str | None = None,
    setup_expected_revision: int | None = None,
    require_webauthn: bool = False,
) -> dict[str, Any]:
    if (setup_session_id is None) != (setup_expected_revision is None):
        raise SetupSessionValidationError(
            "setup_session_id and setup_expected_revision must be provided together"
        )
    setup_id = None
    if setup_session_id is not None:
        setup_id = _setup_text("setup_session_id", setup_session_id, maximum=64)
        if (
            isinstance(setup_expected_revision, bool)
            or not isinstance(setup_expected_revision, int)
            or setup_expected_revision < 0
        ):
            raise SetupSessionValidationError(
                "setup_expected_revision must be a non-negative integer"
            )
    now = utcnow()
    action = "credential.oauth.activate"
    if setup_id is not None:
        _expire_setup_sessions_before_mutation(now)
    with connect() as conn:
        _lock_webauthn_authority(conn)
        now = _metadata_utcnow(conn)
        now_s = now.isoformat()
        setup_row = None
        if setup_id is not None:
            _lock_setup_sessions(conn)
            _ensure_setup_outbox_capacity(conn, 1)
            setup_row = conn.execute(
                "SELECT * FROM setup_sessions WHERE id = ?", (setup_id,)
            ).fetchone()
            if setup_row is None:
                raise SetupSessionNotFoundError(f"setup session not found: {setup_id}")
            current_revision = int(setup_row["revision"])
            if current_revision != setup_expected_revision:
                raise SetupSessionStaleRevisionError(
                    setup_id,
                    int(setup_expected_revision),
                    current_revision,
                )
            if not (
                setup_row["status"] == "active"
                and setup_row["phase"] == "oauth_verified"
                and setup_row["owner_id"] == actor_id
                and setup_row["oauth_pending_credential_id"] == item_id
            ):
                raise SetupSessionValidationError(
                    "pending OAuth grant no longer matches the setup session"
                )
        _lock_credential_mutation(conn, item_id)
        pending = conn.execute(
            "SELECT * FROM pending_oauth_credentials WHERE id = ?",
            (item_id,),
        ).fetchone()
        if pending is None:
            return {"ok": False, "reason": "pending_credential_not_found"}
        if pending["expires_at"] <= now_s:
            conn.execute(
                "UPDATE pending_oauth_credentials SET status = 'expired', revocation_status = 'pending', "
                "revocation_error = NULL, revocation_next_attempt_at = ?, "
                "revocation_lease_owner = NULL, revocation_lease_until = NULL, updated_at = ? "
                "WHERE id = ? AND status = 'pending'",
                (now_s, now_s, item_id),
            )
            return {"ok": False, "reason": "pending_credential_expired"}
        if pending["status"] != "pending":
            return {"ok": False, "reason": f"pending_credential_{pending['status']}"}
        if pending["requester_id"] != actor_id:
            return {"ok": False, "reason": "requester_mismatch"}
        if setup_row is not None:
            review = loads(pending["review_json"], {})
            pending_provider = (
                review.get("provider") if isinstance(review, dict) else None
            )
            if (
                not isinstance(pending_provider, str)
                or setup_row["oauth_provider"] != pending_provider
            ):
                raise SetupSessionValidationError(
                    "pending OAuth provider no longer matches the setup session"
                )

        target_credential_id = pending["target_credential_id"]
        reconnect_target = None
        if target_credential_id:
            target_credential_id = str(target_credential_id)
            _lock_credential_mutation(conn, target_credential_id)
            reconnect_target = conn.execute(
                "SELECT * FROM credentials WHERE id = ?",
                (target_credential_id,),
            ).fetchone()
            if reconnect_target is None:
                return {"ok": False, "reason": "reconnect_credential_not_found"}
            if str(reconnect_target["lifecycle_status"] or "active") != "active":
                return {"ok": False, "reason": "reconnect_credential_inactive"}
            if reconnect_target["kind"] != "oauth2":
                return {"ok": False, "reason": "reconnect_credential_kind_invalid"}
            if int(reconnect_target["credential_version"] or 1) != int(
                pending["target_credential_version"] or 0
            ):
                return {"ok": False, "reason": "reconnect_credential_changed"}
            try:
                current_identity = validate_managed_oauth_account_identity(
                    loads(reconnect_target["metadata"], {})
                )
                pending_identity = validate_managed_oauth_account_identity(
                    loads(pending["metadata"], {})
                )
            except ManagedOAuthCredentialError:
                return {"ok": False, "reason": "reconnect_identity_invalid"}
            if current_identity[0] == "google":
                return {"ok": False, "reason": "google_reconnect_requires_disconnect"}
            if current_identity != pending_identity:
                return {"ok": False, "reason": "reconnect_identity_mismatch"}
            if str(reconnect_target["name"]) != str(pending["name"]):
                return {"ok": False, "reason": "reconnect_credential_name_changed"}

        approval = conn.execute(
            "SELECT * FROM control_plane_approvals WHERE id = ?",
            (approval_id,),
        ).fetchone()
        if approval is None:
            return {"ok": False, "reason": "approval_not_found"}
        if approval["action"] != action:
            return {"ok": False, "reason": "action_mismatch"}
        if approval["resource_id"] != item_id:
            return {"ok": False, "reason": "resource_mismatch"}
        if approval["payload_digest"] != pending["payload_digest"]:
            return {"ok": False, "reason": "payload_digest_mismatch"}
        if approval["requester_id"] != actor_id:
            return {"ok": False, "reason": "requester_mismatch"}
        if approval["approved_by"] == actor_id:
            return {"ok": False, "reason": "self_approval_not_allowed"}
        if approval["status"] != "approved":
            return {"ok": False, "reason": f"approval_{approval['status']}"}
        if approval["expires_at"] <= now_s:
            return {"ok": False, "reason": "approval_expired"}
        approver_webauthn_credential_id = approval[
            "approver_webauthn_credential_id"
        ]
        if require_webauthn and not approver_webauthn_credential_id:
            return {
                "ok": False,
                "reason": "approval_webauthn_required",
            }
        if approver_webauthn_credential_id:
            approver_credential = conn.execute(
                "SELECT revoked_at FROM webauthn_credentials WHERE id = ?",
                (approver_webauthn_credential_id,),
            ).fetchone()
            if (
                approver_credential is None
                or approver_credential["revoked_at"] is not None
            ):
                return {
                    "ok": False,
                    "reason": "approval_authenticator_revoked",
                }
        if (
            reconnect_target is None
            and conn.execute(
                "SELECT 1 FROM credentials WHERE id = ?", (item_id,)
            ).fetchone()
            is not None
        ):
            return {"ok": False, "reason": "credential_already_active"}

        consumed = conn.execute(
            """
            UPDATE control_plane_approvals
            SET status = 'consumed', consumed_by = ?, consumed_at = ?
            WHERE id = ? AND status = 'approved' AND expires_at > ?
              AND (
                approver_webauthn_credential_id IS NULL
                OR EXISTS (
                    SELECT 1 FROM webauthn_credentials
                    WHERE webauthn_credentials.id =
                        control_plane_approvals.approver_webauthn_credential_id
                      AND webauthn_credentials.revoked_at IS NULL
                )
              )
            """,
            (actor_id, now_s, approval_id, now_s),
        )
        if consumed.rowcount != 1:
            if approver_webauthn_credential_id:
                approver_credential = conn.execute(
                    "SELECT revoked_at FROM webauthn_credentials WHERE id = ?",
                    (approver_webauthn_credential_id,),
                ).fetchone()
                if (
                    approver_credential is None
                    or approver_credential["revoked_at"] is not None
                ):
                    return {
                        "ok": False,
                        "reason": "approval_authenticator_revoked",
                    }
            return {"ok": False, "reason": "approval_state_changed"}

        superseded_revocation_work_id = None
        if reconnect_target is not None:
            superseded_revocation_work_id = _queue_superseded_oauth_secret(
                conn,
                credential_row=reconnect_target,
                actor_id=actor_id,
                source="reconnect_superseded",
            )
            next_version = _next_credential_generation(conn, target_credential_id)
            encrypted = _envelope_values(
                target_credential_id,
                decrypt_secret_envelope(pending),
                next_version,
            )
            conn.execute(
                """
                UPDATE credentials
                SET encrypted_secret = ?, encrypted_dek = ?, secret_nonce = ?,
                    secret_ciphertext = ?, secret_kek_id = ?, credential_version = ?,
                    secret_updated_at = ?, metadata = ?, lifecycle_status = 'active',
                    revocation_error = NULL, revocation_requested_at = NULL, updated_at = ?
                WHERE id = ?
                """,
                (
                    encrypted["encrypted_secret"],
                    encrypted["encrypted_dek"],
                    encrypted["secret_nonce"],
                    encrypted["secret_ciphertext"],
                    encrypted["secret_kek_id"],
                    encrypted["credential_version"],
                    encrypted["secret_updated_at"],
                    pending["metadata"],
                    now_s,
                    target_credential_id,
                ),
            )
            credential_id = target_credential_id
        else:
            conn.execute(
                """
                INSERT INTO credentials (
                    id, name, kind, encrypted_secret, encrypted_dek, secret_nonce,
                    secret_ciphertext, secret_kek_id, credential_version, secret_updated_at,
                    metadata, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    pending["id"],
                    pending["name"],
                    pending["kind"],
                    pending["encrypted_secret"],
                    pending["encrypted_dek"],
                    pending["secret_nonce"],
                    pending["secret_ciphertext"],
                    pending["secret_kek_id"],
                    pending["credential_version"],
                    pending["secret_updated_at"],
                    pending["metadata"],
                    now_s,
                    now_s,
                ),
            )
            _record_credential_generation(
                conn, item_id, int(pending["credential_version"])
            )
            credential_id = item_id
        conn.execute("DELETE FROM pending_oauth_credentials WHERE id = ?", (item_id,))
        append_audit_event(
            conn,
            event_type="control_plane.approval.consumed",
            actor_type="admin",
            actor_id=actor_id,
            event={
                "approval_id": approval_id,
                "action": action,
                "resource_id": item_id,
                "credential_id": credential_id,
                "reconnect": reconnect_target is not None,
                "superseded_revocation_work_id": superseded_revocation_work_id,
                "payload_digest": pending["payload_digest"],
                "requester_id": actor_id,
                "approved_by": approval["approved_by"],
            },
        )
        credential_row = conn.execute(
            "SELECT * FROM credentials WHERE id = ?", (credential_id,)
        ).fetchone()
        approval_row = conn.execute(
            "SELECT * FROM control_plane_approvals WHERE id = ?",
            (approval_id,),
        ).fetchone()
        setup_result = None
        if setup_row is not None:
            setup_result = transition_setup_session(
                setup_id,
                expected_revision=int(setup_expected_revision),
                transition="bind_credential",
                actor_id=actor_id,
                updates={
                    "credential_id": credential_id,
                    "credential_version": int(credential_row["credential_version"]),
                    "oauth_provider": str(setup_row["oauth_provider"]),
                },
                event={
                    "provider_account": review.get("provider_account"),
                    "pending_credential_id": item_id,
                    "approval_id": approval_id,
                },
                _connection=conn,
                _now=now,
            )
    return {
        "ok": True,
        "credential": row_to_credential(credential_row),
        "approval": row_to_control_plane_approval(approval_row),
        **({"setup_session": setup_result} if setup_result is not None else {}),
    }


def reconnect_oauth_credential(
    item_id: str,
    *,
    expected_version: int,
    secret: str,
    metadata: dict[str, Any],
    revocation_work_id: str | None = None,
) -> dict[str, Any]:
    secret = validate_credential_secret(secret)
    metadata = validate_credential_metadata(metadata)
    next_identity = validate_managed_oauth_account_identity(metadata)
    if (
        not isinstance(expected_version, int)
        or isinstance(expected_version, bool)
        or expected_version < 1
    ):
        raise ManagedOAuthCredentialError(
            "OAuth reconnect credential version is invalid"
        )
    with connect() as conn:
        _lock_credential_mutation(conn, item_id)
        current = conn.execute(
            "SELECT * FROM credentials WHERE id = ?", (item_id,)
        ).fetchone()
        if current is None:
            raise ManagedOAuthCredentialError(
                "OAuth reconnect credential no longer exists"
            )
        if str(current["lifecycle_status"] or "active") != "active":
            raise ManagedOAuthCredentialError(
                "OAuth reconnect credential is not active"
            )
        if current["kind"] != "oauth2":
            raise ManagedOAuthCredentialError(
                "OAuth reconnect credential kind is invalid"
            )
        if int(current["credential_version"] or 1) != expected_version:
            raise ManagedOAuthCredentialError(
                "OAuth reconnect credential changed during authorization"
            )
        current_identity = validate_managed_oauth_account_identity(
            loads(current["metadata"], {})
        )
        if current_identity != next_identity:
            raise ManagedOAuthCredentialError(
                "OAuth reconnect must verify the exact existing provider subject and account"
            )
        _queue_superseded_oauth_secret(
            conn,
            credential_row=current,
            actor_id=str(metadata.get("created_by") or "oauth-reconnect"),
            source="reconnect_superseded",
            replacing_work_id=revocation_work_id,
        )
        next_version = _next_credential_generation(conn, item_id)
        encrypted = _envelope_values(item_id, secret, next_version)
        now_s = iso_now()
        conn.execute(
            """
            UPDATE credentials
            SET encrypted_secret = ?, encrypted_dek = ?, secret_nonce = ?,
                secret_ciphertext = ?, secret_kek_id = ?, credential_version = ?,
                secret_updated_at = ?, metadata = ?, lifecycle_status = 'active',
                revocation_error = NULL, revocation_requested_at = NULL, updated_at = ?
            WHERE id = ?
            """,
            (
                encrypted["encrypted_secret"],
                encrypted["encrypted_dek"],
                encrypted["secret_nonce"],
                encrypted["secret_ciphertext"],
                encrypted["secret_kek_id"],
                encrypted["credential_version"],
                encrypted["secret_updated_at"],
                dumps(metadata),
                now_s,
                item_id,
            ),
        )
        if revocation_work_id is not None:
            _consume_oauth_revocation_work(conn, revocation_work_id)
        row = conn.execute(
            "SELECT * FROM credentials WHERE id = ?", (item_id,)
        ).fetchone()
    return row_to_credential(row)


def upsert_credential_with_id(
    item_id: str,
    name: str,
    kind: str,
    secret: str,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    secret = validate_credential_secret(secret)
    metadata = validate_credential_metadata(metadata)
    load_master_key()
    now = iso_now()
    with connect() as conn:
        _lock_credential_mutation(conn, item_id)
        existing = conn.execute(
            "SELECT * FROM credentials WHERE id = ?", (item_id,)
        ).fetchone()
        if existing:
            existing_metadata = loads(existing["metadata"], {})
            if existing["kind"] == "oauth2" or (
                isinstance(existing_metadata, dict)
                and existing_metadata.get("oauth") is True
            ):
                raise ManagedOAuthCredentialError(
                    "managed OAuth credentials cannot be replaced through the fixed-ID upsert path"
                )
            current_secret = decrypt_secret_envelope(existing)
            secret_changed = current_secret != secret
            metadata_changed = loads(existing["metadata"], {}) != (metadata or {})
            needs_migration = _needs_envelope_migration(existing)
            if secret_changed or metadata_changed or needs_migration:
                credential_version = int(existing["credential_version"] or 1) + (
                    1 if secret_changed or metadata_changed else 0
                )
                encrypted = _envelope_values(item_id, secret, credential_version)
                _record_credential_generation(conn, item_id, credential_version)
                conn.execute(
                    """
                    UPDATE credentials
                    SET name = ?,
                        kind = ?,
                        encrypted_secret = ?,
                        encrypted_dek = ?,
                        secret_nonce = ?,
                        secret_ciphertext = ?,
                        secret_kek_id = ?,
                        credential_version = ?,
                        secret_updated_at = ?,
                        metadata = ?,
                        updated_at = ?
                    WHERE id = ?
                    """,
                    (
                        name,
                        kind,
                        encrypted["encrypted_secret"],
                        encrypted["encrypted_dek"],
                        encrypted["secret_nonce"],
                        encrypted["secret_ciphertext"],
                        encrypted["secret_kek_id"],
                        encrypted["credential_version"],
                        encrypted["secret_updated_at"],
                        dumps(metadata or {}),
                        now,
                        item_id,
                    ),
                )
            else:
                conn.execute(
                    """
                    UPDATE credentials
                    SET name = ?, kind = ?, metadata = ?, updated_at = ?
                    WHERE id = ?
                    """,
                    (name, kind, dumps(metadata or {}), now, item_id),
                )
        else:
            credential_version = _next_credential_generation(conn, item_id)
            encrypted = _envelope_values(item_id, secret, credential_version)
            conn.execute(
                """
                INSERT INTO credentials (
                    id, name, kind, encrypted_secret, encrypted_dek, secret_nonce,
                    secret_ciphertext, secret_kek_id, credential_version, secret_updated_at,
                    metadata, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    item_id,
                    name,
                    kind,
                    encrypted["encrypted_secret"],
                    encrypted["encrypted_dek"],
                    encrypted["secret_nonce"],
                    encrypted["secret_ciphertext"],
                    encrypted["secret_kek_id"],
                    encrypted["credential_version"],
                    encrypted["secret_updated_at"],
                    dumps(metadata or {}),
                    now,
                    now,
                ),
            )
        row = conn.execute(
            "SELECT * FROM credentials WHERE id = ?", (item_id,)
        ).fetchone()
    return row_to_credential(row)


def update_credential(item_id: str, payload: dict[str, Any]) -> dict[str, Any] | None:
    if "secret" in payload and payload["secret"] is not None:
        payload = {**payload, "secret": validate_credential_secret(payload["secret"])}
    if "metadata" in payload:
        payload = {
            **payload,
            "metadata": validate_credential_metadata(payload["metadata"]),
        }
    if ("secret" in payload and payload["secret"] is not None) or "metadata" in payload:
        load_master_key()
    with connect() as conn:
        _lock_credential_mutation(conn, item_id)
        current = conn.execute(
            "SELECT * FROM credentials WHERE id = ?", (item_id,)
        ).fetchone()
        if not current:
            return None
        if str(current["lifecycle_status"] or "active") != "active":
            raise ManagedOAuthCredentialError(
                "credential is unavailable while provider revocation is pending"
            )
        current_metadata = loads(current["metadata"], {})
        if (
            current["kind"] == "oauth2" or current_metadata.get("oauth") is True
        ) and any(field in payload for field in ("kind", "secret", "metadata")):
            raise ManagedOAuthCredentialError(
                "managed OAuth credentials can only be renamed; reconnect to change the account or scopes"
            )
        fields: list[str] = []
        values: list[Any] = []
        if "name" in payload:
            fields.append("name = ?")
            values.append(payload["name"])
        if "kind" in payload:
            fields.append("kind = ?")
            values.append(payload["kind"])
        if (
            "secret" in payload and payload["secret"] is not None
        ) or "metadata" in payload:
            current_secret = decrypt_secret_envelope(current)
            next_secret = (
                payload.get("secret")
                if payload.get("secret") is not None
                else current_secret
            )
            secret_changed = current_secret != next_secret
            metadata_changed = (
                "metadata" in payload
                and loads(current["metadata"], {}) != payload["metadata"]
            )
            needs_migration = _needs_envelope_migration(current)
            if secret_changed or metadata_changed or needs_migration:
                next_version = int(current["credential_version"] or 1) + (
                    1 if secret_changed or metadata_changed else 0
                )
                encrypted = _envelope_values(item_id, next_secret, next_version)
                _record_credential_generation(conn, item_id, next_version)
                for key in (
                    "encrypted_secret",
                    "encrypted_dek",
                    "secret_nonce",
                    "secret_ciphertext",
                    "secret_kek_id",
                    "credential_version",
                    "secret_updated_at",
                ):
                    fields.append(f"{key} = ?")
                    values.append(encrypted[key])
        if "metadata" in payload:
            fields.append("metadata = ?")
            values.append(dumps(payload["metadata"]))
        if not fields:
            return row_to_credential(current)
        fields.append("updated_at = ?")
        values.append(iso_now())
        values.append(item_id)
        conn.execute(f"UPDATE credentials SET {', '.join(fields)} WHERE id = ?", values)
        row = conn.execute(
            "SELECT * FROM credentials WHERE id = ?", (item_id,)
        ).fetchone()
    return row_to_credential(row) if row else None


def update_credential_secret_if_version(
    item_id: str,
    *,
    expected_version: int,
    secret: str,
    metadata: dict[str, Any],
    revocation_work_id: str | None = None,
) -> tuple[dict[str, Any] | None, bool]:
    secret = validate_credential_secret(secret)
    metadata = validate_credential_metadata(metadata)
    if expected_version < 1:
        raise ValueError("expected credential version must be positive")
    load_master_key()
    with connect() as conn:
        _lock_credential_mutation(conn, item_id)
        current = conn.execute(
            "SELECT * FROM credentials WHERE id = ?", (item_id,)
        ).fetchone()
        if not current:
            return None, False
        if str(current["lifecycle_status"] or "active") != "active":
            return None, False
        current_version = int(current["credential_version"] or 1)
        if current_version != expected_version:
            return row_to_credential(current, include_secret=True), False
        current_secret = decrypt_secret_envelope(current)
        current_metadata = loads(current["metadata"], {})
        managed_oauth_provider = None
        if current["kind"] == "oauth2" or current_metadata.get("oauth") is True:
            current_identity = validate_managed_oauth_identity(current_metadata)
            next_identity = validate_managed_oauth_identity(metadata)
            if next_identity != current_identity:
                raise ManagedOAuthCredentialError(
                    "OAuth refresh cannot change the verified provider account identity"
                )
            managed_oauth_provider = current_identity[0]
        if current_secret == secret and current_metadata == metadata:
            if revocation_work_id is not None:
                _consume_oauth_revocation_work(conn, revocation_work_id)
            return row_to_credential(current, include_secret=True), False

        if managed_oauth_provider == "x" and current_secret != secret:
            _queue_superseded_oauth_secret(
                conn,
                credential_row=current,
                actor_id=str(metadata.get("created_by") or "oauth-refresh"),
                source="refresh_superseded",
                replacing_work_id=revocation_work_id,
                replacement_secret=secret,
            )

        next_version = current_version + 1
        encrypted = _envelope_values(item_id, secret, next_version)
        _record_credential_generation(conn, item_id, next_version)
        conn.execute(
            """
            UPDATE credentials
            SET encrypted_secret = ?, encrypted_dek = ?, secret_nonce = ?,
                secret_ciphertext = ?, secret_kek_id = ?, credential_version = ?,
                secret_updated_at = ?, metadata = ?, updated_at = ?
            WHERE id = ? AND credential_version = ?
            """,
            (
                encrypted["encrypted_secret"],
                encrypted["encrypted_dek"],
                encrypted["secret_nonce"],
                encrypted["secret_ciphertext"],
                encrypted["secret_kek_id"],
                encrypted["credential_version"],
                encrypted["secret_updated_at"],
                dumps(metadata),
                iso_now(),
                item_id,
                expected_version,
            ),
        )
        if revocation_work_id is not None:
            _consume_oauth_revocation_work(conn, revocation_work_id)
        row = conn.execute(
            "SELECT * FROM credentials WHERE id = ?", (item_id,)
        ).fetchone()
    return (row_to_credential(row, include_secret=True) if row else None), True


def get_credential(
    item_id: str,
    include_secret: bool = False,
    *,
    include_inactive: bool = False,
) -> dict[str, Any] | None:
    with connect() as conn:
        row = conn.execute(
            "SELECT * FROM credentials WHERE id = ?", (item_id,)
        ).fetchone()
    if (
        row is not None
        and not include_inactive
        and str(row["lifecycle_status"] or "active") != "active"
    ):
        return None
    return row_to_credential(row, include_secret) if row else None


@contextlib.contextmanager
def credential_lease_snapshot(item_id: str):
    """Hold the credential mutation lock while a lease is assembled and encrypted."""
    load_master_key()
    with connect() as conn:
        _lock_credential_mutation(conn, item_id)
        row = conn.execute(
            "SELECT * FROM credentials WHERE id = ?", (item_id,)
        ).fetchone()
        if row is not None and str(row["lifecycle_status"] or "active") != "active":
            row = None
        yield row_to_credential(row, include_secret=True) if row else None


def list_credentials() -> list[dict[str, Any]]:
    with connect() as conn:
        rows = conn.execute(
            "SELECT * FROM credentials ORDER BY created_at DESC"
        ).fetchall()
    return [row_to_credential(row) for row in rows]


def begin_oauth_credential_disconnect(item_id: str) -> dict[str, Any]:
    now_s = iso_now()
    with connect() as conn:
        _lock_credential_mutation(conn, item_id)
        row = conn.execute(
            "SELECT * FROM credentials WHERE id = ?", (item_id,)
        ).fetchone()
        if row is None:
            return {"ok": False, "reason": "credential_not_found"}
        metadata = loads(row["metadata"], {})
        if row["kind"] != "oauth2" and metadata.get("oauth") is not True:
            return {"ok": False, "reason": "credential_not_managed_oauth"}
        (
            provider_id,
            provider_subject,
            provider_account,
        ) = validate_managed_oauth_account_identity(metadata)
        lifecycle_status = str(row["lifecycle_status"] or "active")
        if lifecycle_status not in {
            "active",
            "revocation_pending",
            "revocation_failed",
        }:
            raise ManagedOAuthCredentialError(
                "OAuth credential lifecycle state is invalid"
            )
        conn.execute(
            """
            UPDATE credentials
            SET lifecycle_status = 'revocation_pending', revocation_error = NULL,
                revocation_requested_at = ?, updated_at = ?
            WHERE id = ?
            """,
            (now_s, now_s, item_id),
        )
        current = conn.execute(
            "SELECT * FROM credentials WHERE id = ?", (item_id,)
        ).fetchone()
        result = row_to_credential(current, include_secret=True)
    return {
        "ok": True,
        "credential": result,
        "provider": provider_id,
        "provider_subject": provider_subject,
        "provider_account": provider_account,
        "previous_status": lifecycle_status,
    }


def finish_oauth_credential_disconnect(
    item_id: str,
    *,
    expected_version: int,
    actor_id: str,
    succeeded: bool,
    error: str | None = None,
) -> dict[str, Any]:
    if error is not None and (not isinstance(error, str) or len(error) > 500):
        raise ManagedOAuthCredentialError(
            "OAuth credential revocation error is invalid"
        )
    now_s = iso_now()
    with connect() as conn:
        _lock_credential_mutation(conn, item_id)
        row = conn.execute(
            "SELECT * FROM credentials WHERE id = ?", (item_id,)
        ).fetchone()
        if row is None:
            return {"ok": False, "reason": "credential_not_found"}
        metadata = loads(row["metadata"], {})
        (
            provider_id,
            provider_subject,
            provider_account,
        ) = validate_managed_oauth_account_identity(metadata)
        if int(row["credential_version"] or 1) != expected_version:
            return {"ok": False, "reason": "credential_changed_during_revocation"}
        if str(row["lifecycle_status"] or "active") != "revocation_pending":
            return {"ok": False, "reason": "credential_revocation_state_changed"}
        append_audit_event(
            conn,
            event_type=(
                "credential.oauth_disconnected"
                if succeeded
                else "credential.oauth_revocation_failed"
            ),
            actor_type="admin",
            actor_id=actor_id,
            event={
                "credential_id": item_id,
                "credential_version": expected_version,
                "provider": provider_id,
                "provider_subject": provider_subject,
                "provider_account": provider_account,
                "result": "revoked" if succeeded else "failed",
                "error": error,
            },
        )
        if succeeded:
            conn.execute("DELETE FROM credentials WHERE id = ?", (item_id,))
            return {"ok": True, "deleted": True, "provider": provider_id}
        conn.execute(
            """
            UPDATE credentials
            SET lifecycle_status = 'revocation_failed', revocation_error = ?, updated_at = ?
            WHERE id = ?
            """,
            (error or "provider revocation failed", now_s, item_id),
        )
        failed = conn.execute(
            "SELECT * FROM credentials WHERE id = ?", (item_id,)
        ).fetchone()
    return {
        "ok": False,
        "reason": "provider_revocation_failed",
        "credential": row_to_credential(failed),
    }


def delete_credential(item_id: str) -> bool:
    with connect() as conn:
        _lock_credential_mutation(conn, item_id)
        row = conn.execute(
            "SELECT * FROM credentials WHERE id = ?", (item_id,)
        ).fetchone()
        if row is not None:
            metadata = loads(row["metadata"], {})
            if row["kind"] == "oauth2" or metadata.get("oauth") is True:
                raise ManagedOAuthCredentialError(
                    "managed OAuth credentials must be revoked through the provider disconnect flow"
                )
        cur = conn.execute("DELETE FROM credentials WHERE id = ?", (item_id,))
    return cur.rowcount > 0


def row_to_route(row: sqlite3.Row) -> dict[str, Any]:
    item = dict(row)
    item["enabled"] = bool(item["enabled"])
    item["injection"] = loads(item.get("injection"), {})
    item["policies"] = loads(item.get("policies"), [])
    return item


def create_route(payload: dict[str, Any]) -> dict[str, Any]:
    item_id = str(uuid.uuid4())
    now = iso_now()
    with connect() as conn:
        conn.execute(
            """
            INSERT INTO routes
                (id, name, enabled, match_host, match_path_prefix, credential_id, injection, policies, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                item_id,
                payload["name"],
                1 if payload.get("enabled", True) else 0,
                payload["match_host"],
                payload.get("match_path_prefix") or "/",
                payload.get("credential_id"),
                dumps(payload.get("injection") or {}),
                dumps(payload.get("policies") or []),
                now,
                now,
            ),
        )
        row = conn.execute("SELECT * FROM routes WHERE id = ?", (item_id,)).fetchone()
    return row_to_route(row)


def upsert_route_with_id(item_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    now = iso_now()
    values = (
        payload["name"],
        1 if payload.get("enabled", True) else 0,
        payload["match_host"],
        payload.get("match_path_prefix") or "/",
        payload.get("credential_id"),
        dumps(payload.get("injection") or {}),
        dumps(payload.get("policies") or []),
        now,
        item_id,
    )
    with connect() as conn:
        existing = conn.execute(
            "SELECT id FROM routes WHERE id = ?", (item_id,)
        ).fetchone()
        if existing:
            conn.execute(
                """
                UPDATE routes
                SET name = ?, enabled = ?, match_host = ?, match_path_prefix = ?,
                    credential_id = ?, injection = ?, policies = ?, updated_at = ?
                WHERE id = ?
                """,
                values,
            )
        else:
            conn.execute(
                """
                INSERT INTO routes (
                    id, name, enabled, match_host, match_path_prefix,
                    credential_id, injection, policies, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    item_id,
                    payload["name"],
                    1 if payload.get("enabled", True) else 0,
                    payload["match_host"],
                    payload.get("match_path_prefix") or "/",
                    payload.get("credential_id"),
                    dumps(payload.get("injection") or {}),
                    dumps(payload.get("policies") or []),
                    now,
                    now,
                ),
            )
        row = conn.execute("SELECT * FROM routes WHERE id = ?", (item_id,)).fetchone()
    return row_to_route(row)


def update_route(item_id: str, payload: dict[str, Any]) -> dict[str, Any] | None:
    field_map = {
        "name": "name",
        "enabled": "enabled",
        "match_host": "match_host",
        "match_path_prefix": "match_path_prefix",
        "credential_id": "credential_id",
    }
    fields: list[str] = []
    values: list[Any] = []
    for key, column in field_map.items():
        if key in payload:
            fields.append(f"{column} = ?")
            value = payload[key]
            if key == "enabled":
                value = 1 if value else 0
            values.append(value)
    if "injection" in payload:
        fields.append("injection = ?")
        values.append(dumps(payload["injection"] or {}))
    if "policies" in payload:
        fields.append("policies = ?")
        values.append(dumps(payload["policies"] or []))
    if not fields:
        return get_route(item_id)
    fields.append("updated_at = ?")
    values.append(iso_now())
    values.append(item_id)
    with connect() as conn:
        conn.execute(f"UPDATE routes SET {', '.join(fields)} WHERE id = ?", values)
        row = conn.execute("SELECT * FROM routes WHERE id = ?", (item_id,)).fetchone()
    return row_to_route(row) if row else None


def get_route(item_id: str) -> dict[str, Any] | None:
    with connect() as conn:
        row = conn.execute("SELECT * FROM routes WHERE id = ?", (item_id,)).fetchone()
    return row_to_route(row) if row else None


def list_routes() -> list[dict[str, Any]]:
    with connect() as conn:
        rows = conn.execute(
            "SELECT * FROM routes ORDER BY length(match_path_prefix) DESC, created_at DESC"
        ).fetchall()
    return [row_to_route(row) for row in rows]


def delete_route(item_id: str) -> bool:
    with connect() as conn:
        cur = conn.execute("DELETE FROM routes WHERE id = ?", (item_id,))
    return cur.rowcount > 0


def _host_matches(rule_host: str, request_host: str) -> bool:
    rule = rule_host.strip().lower()
    host = request_host.strip().lower()
    if rule == host:
        return True
    if rule.startswith("*."):
        suffix = rule[1:]
        return host.endswith(suffix) and host != rule[2:]
    return False


def find_matching_route(host: str, path: str) -> dict[str, Any] | None:
    candidates = list_routes()
    for route in candidates:
        if not route["enabled"]:
            continue
        prefix = route["match_path_prefix"] or "/"
        if _host_matches(route["match_host"], host) and path.startswith(prefix):
            return route
    return None


def row_to_approval(row: sqlite3.Row) -> dict[str, Any]:
    item = dict(row)
    stored_canonical = item.get("canonical_request")
    if isinstance(stored_canonical, str):
        stored_canonical = _decrypt_approval_json(stored_canonical)
    item["canonical_request"] = loads(stored_canonical, None)
    stored_display = item.get("redacted_display")
    if isinstance(stored_display, str):
        stored_display = _decrypt_approval_json(stored_display)
    item["redacted_display"] = loads(stored_display, None)
    if isinstance(item["redacted_display"], dict) and isinstance(
        item["redacted_display"].get("url"), str
    ):
        item["url"] = item["redacted_display"]["url"]
    item["approval_authn"] = loads(item.get("approval_authn"), None)
    return item


def row_to_control_plane_approval(row: sqlite3.Row) -> dict[str, Any]:
    item = dict(row)
    item["request"] = loads(item.pop("request_json", None), {})
    item.pop("approval_authn", None)
    return item


def _control_plane_authn_summary(authn: dict[str, Any]) -> dict[str, Any]:
    allowed = (
        "method",
        "user_id",
        "credential_record_id",
        "authenticator_class",
        "effective_authenticator_class",
        "attestation_trusted",
        "current_trust_bundle_digest",
        "current_trust_bundle_sequence",
        "control_plane_action",
        "resource_id",
        "payload_digest",
        "control_plane_approval_id",
        "approval_requester_id",
        "approval_expires_at",
        "decision",
    )
    return {field: authn[field] for field in allowed if field in authn}


def ensure_control_plane_approval(
    *,
    action: str,
    resource_id: str | None,
    payload_digest: str,
    requester_id: str,
    request: dict[str, Any],
    ttl_seconds: int,
    require_webauthn: bool = False,
) -> dict[str, Any]:
    now = utcnow()
    now_s = now.isoformat()
    expires_at = (now + timedelta(seconds=ttl_seconds)).isoformat()
    resource_clause = (
        "resource_id IS NULL" if resource_id is None else "resource_id = ?"
    )
    resource_args: tuple[Any, ...] = () if resource_id is None else (resource_id,)
    with connect() as conn:
        _lock_webauthn_authority(conn)
        if require_webauthn:
            legacy_rows = conn.execute(
                f"""
                SELECT id, approved_by FROM control_plane_approvals
                WHERE action = ?
                  AND {resource_clause}
                  AND payload_digest = ?
                  AND requester_id = ?
                  AND status = 'approved'
                  AND expires_at > ?
                  AND approver_webauthn_credential_id IS NULL
                """,
                (action, *resource_args, payload_digest, requester_id, now_s),
            ).fetchall()
            conn.execute(
                f"""
                UPDATE control_plane_approvals
                SET status = 'invalidated',
                    decision_note = 'invalidated: WebAuthn enforcement requires new approval'
                WHERE action = ?
                  AND {resource_clause}
                  AND payload_digest = ?
                  AND requester_id = ?
                  AND status = 'approved'
                  AND expires_at > ?
                  AND approver_webauthn_credential_id IS NULL
                """,
                (action, *resource_args, payload_digest, requester_id, now_s),
            )
            for legacy in legacy_rows:
                append_audit_event(
                    conn,
                    event_type="control_plane.approval.invalidated",
                    actor_type="system",
                    actor_id=None,
                    event={
                        "approval_id": legacy["id"],
                        "action": action,
                        "resource_id": resource_id,
                        "payload_digest": payload_digest,
                        "requester_id": requester_id,
                        "approved_by": legacy["approved_by"],
                        "reason": "webauthn_enforcement_requires_new_approval",
                    },
                )
        existing = conn.execute(
            f"""
            SELECT * FROM control_plane_approvals
            WHERE action = ?
              AND {resource_clause}
              AND payload_digest = ?
              AND requester_id = ?
              AND status IN ('pending', 'approved')
              AND expires_at > ?
              AND (
                status = 'pending'
                OR ? = 0
                OR approver_webauthn_credential_id IS NOT NULL
              )
            ORDER BY requested_at DESC
            LIMIT 1
            """,
            (
                action,
                *resource_args,
                payload_digest,
                requester_id,
                now_s,
                1 if require_webauthn else 0,
            ),
        ).fetchone()
        if existing:
            return row_to_control_plane_approval(existing)

        item_id = str(uuid.uuid4())
        conn.execute(
            """
            INSERT INTO control_plane_approvals (
                id, action, resource_id, payload_digest, status, requester_id,
                requested_at, expires_at, request_json
            )
            VALUES (?, ?, ?, ?, 'pending', ?, ?, ?, ?)
            """,
            (
                item_id,
                action,
                resource_id,
                payload_digest,
                requester_id,
                now_s,
                expires_at,
                dumps(request),
            ),
        )
        append_audit_event(
            conn,
            event_type="control_plane.approval.requested",
            actor_type="admin",
            actor_id=requester_id,
            event={
                "approval_id": item_id,
                "action": action,
                "resource_id": resource_id,
                "payload_digest": payload_digest,
                "requester_id": requester_id,
                "expires_at": expires_at,
                "request": request,
            },
        )
        row = conn.execute(
            "SELECT * FROM control_plane_approvals WHERE id = ?", (item_id,)
        ).fetchone()
    return row_to_control_plane_approval(row)


def get_control_plane_approval(item_id: str) -> dict[str, Any] | None:
    with connect() as conn:
        row = conn.execute(
            "SELECT * FROM control_plane_approvals WHERE id = ?", (item_id,)
        ).fetchone()
    return row_to_control_plane_approval(row) if row else None


def approve_control_plane_approval(
    item_id: str,
    *,
    actor_id: str,
    note: str | None = None,
    authn: dict[str, Any] | None = None,
    require_webauthn: bool = False,
) -> dict[str, Any] | None:
    authn_evidence = authn or {}
    approver_webauthn_credential_id = authn_evidence.get(
        "credential_record_id"
    )
    if approver_webauthn_credential_id is not None and (
        not isinstance(approver_webauthn_credential_id, str)
        or not approver_webauthn_credential_id
    ):
        raise MetadataStoreError(
            "control-plane approval WebAuthn credential record is invalid"
        )
    if require_webauthn and not approver_webauthn_credential_id:
        raise MetadataStoreError(
            "control-plane approval requires verified WebAuthn evidence"
        )
    with connect() as conn:
        _lock_webauthn_authority(conn)
        now_s = _metadata_utcnow(conn).isoformat()
        existing = conn.execute(
            "SELECT * FROM control_plane_approvals WHERE id = ?", (item_id,)
        ).fetchone()
        if not existing:
            return None
        if existing["status"] != "pending" or existing["expires_at"] <= now_s:
            return None
        if existing["requester_id"] == actor_id:
            return None
        if approver_webauthn_credential_id:
            expected_evidence = {
                "method": "webauthn",
                "user_id": actor_id,
                "control_plane_action": existing["action"],
                "resource_id": existing["resource_id"],
                "payload_digest": existing["payload_digest"],
                "control_plane_approval_id": existing["id"],
                "approval_requester_id": existing["requester_id"],
                "approval_expires_at": existing["expires_at"],
                "decision": "approve",
            }
            if any(
                authn_evidence.get(field) != expected
                for field, expected in expected_evidence.items()
            ):
                raise MetadataStoreError(
                    "control-plane approval WebAuthn evidence binding is invalid"
                )
            approver_credential = conn.execute(
                "SELECT user_id, revoked_at FROM webauthn_credentials WHERE id = ?",
                (approver_webauthn_credential_id,),
            ).fetchone()
            if (
                approver_credential is None
                or approver_credential["user_id"] != actor_id
                or approver_credential["revoked_at"] is not None
            ):
                raise MetadataStoreError(
                    "control-plane approval WebAuthn credential is not active for the approver"
                )
        cur = conn.execute(
            """
            UPDATE control_plane_approvals
            SET status = 'approved',
                approved_by = ?,
                approved_at = ?,
                decision_note = ?,
                approval_authn = ?,
                approver_webauthn_credential_id = ?
            WHERE id = ? AND status = 'pending' AND expires_at > ?
              AND (
                ? = 0
                OR EXISTS (
                    SELECT 1 FROM webauthn_credentials
                    WHERE webauthn_credentials.id = ?
                      AND webauthn_credentials.user_id = ?
                      AND webauthn_credentials.revoked_at IS NULL
                )
              )
            """,
            (
                actor_id,
                now_s,
                note,
                dumps(_control_plane_authn_summary(authn_evidence)),
                approver_webauthn_credential_id,
                item_id,
                now_s,
                1 if approver_webauthn_credential_id else 0,
                approver_webauthn_credential_id,
                actor_id,
            ),
        )
        if cur.rowcount != 1:
            return None
        append_audit_event(
            conn,
            event_type="control_plane.approval.approved",
            actor_type="admin",
            actor_id=actor_id,
            event={
                "approval_id": item_id,
                "action": existing["action"],
                "resource_id": existing["resource_id"],
                "payload_digest": existing["payload_digest"],
                "requester_id": existing["requester_id"],
                "approved_by": actor_id,
                "approval_authn": _control_plane_authn_summary(authn_evidence),
                "note": note,
            },
        )
        row = conn.execute(
            "SELECT * FROM control_plane_approvals WHERE id = ?", (item_id,)
        ).fetchone()
    return row_to_control_plane_approval(row) if row else None


def consume_control_plane_approval(
    item_id: str,
    *,
    action: str,
    resource_id: str | None,
    payload_digest: str,
    actor_id: str,
    require_webauthn: bool = False,
    _connection: Any | None = None,
    _now: datetime | None = None,
) -> dict[str, Any]:
    connection_scope = (
        connect() if _connection is None else contextlib.nullcontext(_connection)
    )
    with connection_scope as conn:
        _lock_webauthn_authority(conn)
        now = _metadata_utcnow(conn)
        if _now is not None:
            supplied_now = _now
            if supplied_now.tzinfo is None:
                supplied_now = supplied_now.replace(tzinfo=timezone.utc)
            now = max(now, supplied_now.astimezone(timezone.utc))
        now_s = now.isoformat()
        existing = conn.execute(
            "SELECT * FROM control_plane_approvals WHERE id = ?", (item_id,)
        ).fetchone()
        if not existing:
            return {"ok": False, "reason": "approval_not_found"}
        if existing["action"] != action:
            return {"ok": False, "reason": "action_mismatch"}
        if existing["resource_id"] != resource_id:
            return {"ok": False, "reason": "resource_mismatch"}
        if existing["payload_digest"] != payload_digest:
            return {"ok": False, "reason": "payload_digest_mismatch"}
        if existing["requester_id"] != actor_id:
            return {"ok": False, "reason": "requester_mismatch"}
        if existing["approved_by"] == actor_id:
            return {"ok": False, "reason": "self_approval_not_allowed"}
        if existing["status"] != "approved":
            return {"ok": False, "reason": f"approval_{existing['status']}"}
        if existing["expires_at"] <= now_s:
            return {"ok": False, "reason": "approval_expired"}
        approver_webauthn_credential_id = existing[
            "approver_webauthn_credential_id"
        ]
        if require_webauthn and not approver_webauthn_credential_id:
            return {
                "ok": False,
                "reason": "approval_webauthn_required",
            }
        if approver_webauthn_credential_id:
            approver_credential = conn.execute(
                "SELECT revoked_at FROM webauthn_credentials WHERE id = ?",
                (approver_webauthn_credential_id,),
            ).fetchone()
            if (
                approver_credential is None
                or approver_credential["revoked_at"] is not None
            ):
                return {
                    "ok": False,
                    "reason": "approval_authenticator_revoked",
                }
        cur = conn.execute(
            """
            UPDATE control_plane_approvals
            SET status = 'consumed',
                consumed_by = ?,
                consumed_at = ?
            WHERE id = ? AND status = 'approved' AND expires_at > ?
              AND (
                approver_webauthn_credential_id IS NULL
                OR EXISTS (
                    SELECT 1 FROM webauthn_credentials
                    WHERE webauthn_credentials.id =
                        control_plane_approvals.approver_webauthn_credential_id
                      AND webauthn_credentials.revoked_at IS NULL
                )
              )
            """,
            (actor_id, now_s, item_id, now_s),
        )
        if cur.rowcount != 1:
            if approver_webauthn_credential_id:
                approver_credential = conn.execute(
                    "SELECT revoked_at FROM webauthn_credentials WHERE id = ?",
                    (approver_webauthn_credential_id,),
                ).fetchone()
                if (
                    approver_credential is None
                    or approver_credential["revoked_at"] is not None
                ):
                    return {
                        "ok": False,
                        "reason": "approval_authenticator_revoked",
                    }
            return {"ok": False, "reason": "approval_state_changed"}
        append_audit_event(
            conn,
            event_type="control_plane.approval.consumed",
            actor_type="admin",
            actor_id=actor_id,
            event={
                "approval_id": item_id,
                "action": action,
                "resource_id": resource_id,
                "payload_digest": payload_digest,
                "requester_id": actor_id,
                "approved_by": existing["approved_by"],
                "approver_webauthn_credential_id": approver_webauthn_credential_id,
            },
        )
        row = conn.execute(
            "SELECT * FROM control_plane_approvals WHERE id = ?", (item_id,)
        ).fetchone()
    return {"ok": True, "approval": row_to_control_plane_approval(row)}


def deny_control_plane_approval(
    item_id: str, *, actor_id: str, note: str | None = None
) -> dict[str, Any] | None:
    now_s = iso_now()
    with connect() as conn:
        existing = conn.execute(
            "SELECT * FROM control_plane_approvals WHERE id = ?", (item_id,)
        ).fetchone()
        if not existing:
            return None
        if existing["status"] != "pending" or existing["expires_at"] <= now_s:
            return None
        cur = conn.execute(
            """
            UPDATE control_plane_approvals
            SET status = 'denied',
                decision_note = ?
            WHERE id = ? AND status = 'pending' AND expires_at > ?
            """,
            (note, item_id, now_s),
        )
        if cur.rowcount != 1:
            return None
        if (
            existing["action"] == "credential.oauth.activate"
            and existing["resource_id"]
        ):
            pending_update = conn.execute(
                """
                UPDATE pending_oauth_credentials
                SET status = 'rejected', revocation_status = 'pending', revocation_error = NULL,
                    revocation_next_attempt_at = ?, revocation_lease_owner = NULL,
                    revocation_lease_until = NULL, updated_at = ?
                WHERE id = ? AND payload_digest = ? AND status = 'pending'
                """,
                (now_s, now_s, existing["resource_id"], existing["payload_digest"]),
            )
            if pending_update.rowcount != 1:
                raise MetadataStoreError(
                    "OAuth activation denial could not terminalize the exact pending credential"
                )
        append_audit_event(
            conn,
            event_type="control_plane.approval.denied",
            actor_type="admin",
            actor_id=actor_id,
            event={
                "approval_id": item_id,
                "action": existing["action"],
                "resource_id": existing["resource_id"],
                "payload_digest": existing["payload_digest"],
                "requester_id": existing["requester_id"],
                "denied_by": actor_id,
                "note": note,
            },
        )
        row = conn.execute(
            "SELECT * FROM control_plane_approvals WHERE id = ?", (item_id,)
        ).fetchone()
    return row_to_control_plane_approval(row) if row else None


def list_control_plane_approvals(
    status: str | None = None, limit: int = 100
) -> list[dict[str, Any]]:
    args: list[Any] = []
    where = ""
    if status:
        where = "WHERE status = ?"
        args.append(status)
    args.append(limit)
    with connect() as conn:
        rows = conn.execute(
            f"SELECT * FROM control_plane_approvals {where} ORDER BY requested_at DESC LIMIT ?",
            args,
        ).fetchall()
    return [row_to_control_plane_approval(row) for row in rows]


def create_approval_request(
    route_id: str, method: str, url: str, ttl_seconds: int = 300
) -> dict[str, Any]:
    if not 1 <= ttl_seconds <= 3600:
        raise MetadataStoreError(
            "pending approval ttl_seconds must be between 1 and 3600"
        )
    _validate_pending_approval_payload(route_id, method, url)
    now = utcnow()
    now_s = now.isoformat()
    pending_key = _pending_approval_key(
        route_id=route_id,
        method=method,
        url=url,
        principal_id=None,
        credential_id=None,
        credential_version=None,
        policy_hash=None,
        request_digest=None,
        operation_digest=None,
        grant_ttl_seconds=None,
        grant_max_uses=None,
    )
    with connect() as conn:
        _lock_pending_approval_creation(conn)
        pending_count = _expire_and_count_pending_approvals(conn, now_s)
        existing = conn.execute(
            """
            SELECT * FROM approval_requests
            WHERE pending_key = ? AND status = 'pending' AND expires_at > ?
            ORDER BY requested_at DESC LIMIT 1
            """,
            (pending_key, now_s),
        ).fetchone()
        if existing:
            return row_to_approval(existing)
        if pending_count >= _PENDING_APPROVAL_MAX_COUNT:
            raise MetadataStoreError("pending approval count limit reached")
        item_id = str(uuid.uuid4())
        conn.execute(
            """
            INSERT INTO approval_requests
                (id, route_id, method, url, status, requested_at, expires_at, pending_key)
            VALUES (?, ?, ?, ?, 'pending', ?, ?, ?)
            """,
            (
                item_id,
                route_id,
                method,
                url,
                now_s,
                (now + timedelta(seconds=ttl_seconds)).isoformat(),
                pending_key,
            ),
        )
        row = conn.execute(
            "SELECT * FROM approval_requests WHERE id = ?", (item_id,)
        ).fetchone()
    return row_to_approval(row)


def _ensure_jit_approval_request_on_connection(
    conn: Any,
    *,
    route_id: str,
    method: str,
    url: str,
    principal_id: str,
    credential_id: str,
    credential_version: int,
    policy_hash: str,
    request_digest: str,
    operation_digest: str | None,
    canonical_request: dict[str, Any],
    redacted_display: dict[str, Any],
    pending_ttl_seconds: int,
    grant_ttl_seconds: int,
    grant_max_uses: int,
    now: datetime | None = None,
) -> dict[str, Any]:
    if not 1 <= pending_ttl_seconds <= 3600:
        raise MetadataStoreError(
            "pending approval pending_ttl_seconds must be between 1 and 3600"
        )
    if not 1 <= grant_ttl_seconds <= 3600:
        raise MetadataStoreError(
            "pending approval grant_ttl_seconds must be between 1 and 3600"
        )
    if grant_max_uses < 1:
        raise MetadataStoreError("pending approval grant_max_uses must be positive")
    if not isinstance(canonical_request, dict) or not isinstance(
        redacted_display, dict
    ):
        raise MetadataStoreError(
            "pending approval review payloads must be JSON objects"
        )
    canonical_json = dumps(canonical_request)
    redacted_json = dumps(redacted_display)
    _validate_pending_approval_payload(
        route_id,
        method,
        url,
        principal_id,
        credential_id,
        policy_hash,
        request_digest,
        operation_digest or "",
        canonical_json,
        redacted_json,
    )
    now = now or utcnow()
    now_s = now.isoformat()
    expires = (now + timedelta(seconds=pending_ttl_seconds)).isoformat()
    pending_key = _pending_approval_key(
        route_id=route_id,
        method=method,
        url=url,
        principal_id=principal_id,
        credential_id=credential_id,
        credential_version=credential_version,
        policy_hash=policy_hash,
        request_digest=request_digest,
        operation_digest=operation_digest,
        grant_ttl_seconds=grant_ttl_seconds,
        grant_max_uses=grant_max_uses,
    )
    _lock_pending_approval_creation(conn)
    pending_count = _expire_and_count_pending_approvals(conn, now_s)
    existing = conn.execute(
        """
        SELECT * FROM approval_requests
        WHERE pending_key = ?
          AND status = 'pending'
          AND expires_at > ?
        ORDER BY requested_at DESC
        LIMIT 1
        """,
        (pending_key, now_s),
    ).fetchone()
    if existing:
        if (
            _stored_approval_json_digest(str(existing["canonical_request"] or ""))
            != _approval_json_digest(canonical_json)
            or _stored_approval_json_digest(str(existing["redacted_display"] or ""))
            != _approval_json_digest(redacted_json)
        ):
            raise MetadataStoreError(
                "pending approval immutable review payload does not match existing request"
            )
        approval = dict(existing)
        approval["canonical_request"] = canonical_request
        approval["url"] = url
        approval["redacted_display"] = redacted_display
        approval["approval_authn"] = loads(approval.get("approval_authn"), None)
        approval["approval_created"] = False
        return approval
    if pending_count >= _PENDING_APPROVAL_MAX_COUNT:
        raise MetadataStoreError("pending approval count limit reached")

    _ensure_policy_route_reference(conn, route_id)
    item_id = str(uuid.uuid4())
    conn.execute(
        """
        INSERT INTO approval_requests (
            id, route_id, method, url, status, requested_at, expires_at,
            principal_id, credential_id, credential_version, policy_hash, request_digest, operation_digest,
            canonical_request, redacted_display, grant_ttl_seconds, grant_max_uses, pending_key
        )
        VALUES (?, ?, ?, ?, 'pending', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            item_id,
            route_id,
            method,
            _approval_url_commitment(url),
            now_s,
            expires,
            principal_id,
            credential_id,
            credential_version,
            policy_hash,
            request_digest,
            operation_digest,
            _encrypt_approval_json(canonical_json),
            _encrypt_approval_json(redacted_json),
            grant_ttl_seconds,
            grant_max_uses,
            pending_key,
        ),
    )
    row = conn.execute(
        "SELECT * FROM approval_requests WHERE id = ?", (item_id,)
    ).fetchone()
    approval = row_to_approval(row)
    approval["approval_created"] = True
    return approval


def ensure_jit_approval_request(
    *,
    route_id: str,
    method: str,
    url: str,
    principal_id: str,
    credential_id: str,
    credential_version: int,
    policy_hash: str,
    request_digest: str,
    operation_digest: str | None,
    canonical_request: dict[str, Any],
    redacted_display: dict[str, Any],
    pending_ttl_seconds: int,
    grant_ttl_seconds: int,
    grant_max_uses: int,
) -> dict[str, Any]:
    with connect() as conn:
        return _ensure_jit_approval_request_on_connection(
            conn,
            route_id=route_id,
            method=method,
            url=url,
            principal_id=principal_id,
            credential_id=credential_id,
            credential_version=credential_version,
            policy_hash=policy_hash,
            request_digest=request_digest,
            operation_digest=operation_digest,
            canonical_request=canonical_request,
            redacted_display=redacted_display,
            pending_ttl_seconds=pending_ttl_seconds,
            grant_ttl_seconds=grant_ttl_seconds,
            grant_max_uses=grant_max_uses,
        )


def _ensure_policy_route_reference(conn: Any, route_id: str) -> None:
    existing = conn.execute(
        "SELECT id FROM routes WHERE id = ?", (route_id,)
    ).fetchone()
    if existing:
        return
    now_s = iso_now()
    conn.execute(
        """
        INSERT INTO routes (
            id, name, enabled, match_host, match_path_prefix,
            credential_id, injection, policies, created_at, updated_at
        )
        VALUES (?, ?, 0, ?, '/', NULL, '{}', '[]', ?, ?)
        """,
        (
            route_id,
            f"Policy bundle route {route_id}",
            "__policy_bundle__",
            now_s,
            now_s,
        ),
    )


def get_approval_request(item_id: str) -> dict[str, Any] | None:
    with connect() as conn:
        row = conn.execute(
            "SELECT * FROM approval_requests WHERE id = ?", (item_id,)
        ).fetchone()
    return row_to_approval(row) if row else None


def issue_approval_review_receipt(
    *,
    approval_request_id: str,
    reviewer_id: str,
    review_digest: str,
    ttl_seconds: int = 120,
) -> dict[str, Any]:
    if not isinstance(approval_request_id, str) or not approval_request_id:
        raise MetadataStoreError("approval review receipt approval ID is invalid")
    if not isinstance(reviewer_id, str) or not reviewer_id or len(reviewer_id) > 512:
        raise MetadataStoreError("approval review receipt reviewer is invalid")
    if re.fullmatch(r"sha256:[0-9a-f]{64}", review_digest or "") is None:
        raise MetadataStoreError("approval review receipt digest is invalid")
    if not isinstance(ttl_seconds, int) or isinstance(ttl_seconds, bool) or not 30 <= ttl_seconds <= 300:
        raise MetadataStoreError("approval review receipt TTL must be between 30 and 300 seconds")
    now = utcnow()
    now_s = now.isoformat()
    expires_at = (now + timedelta(seconds=ttl_seconds)).isoformat()
    receipt_id = str(uuid.uuid4())
    with connect() as conn:
        _lock_pending_approval_creation(conn)
        approval = conn.execute(
            "SELECT status, expires_at FROM approval_requests WHERE id = ?",
            (approval_request_id,),
        ).fetchone()
        if approval is None:
            raise MetadataStoreError("approval review receipt approval is unavailable")
        if approval["status"] != "pending" or approval["expires_at"] <= now_s:
            raise MetadataStoreError("approval review receipt requires a live pending approval")
        conn.execute(
            "DELETE FROM approval_review_receipts WHERE used_at IS NOT NULL OR expires_at <= ?",
            (now_s,),
        )
        count_row = conn.execute(
            "SELECT COUNT(*) AS count FROM approval_review_receipts"
        ).fetchone()
        if int(count_row["count"] if count_row else 0) >= _APPROVAL_REVIEW_RECEIPT_MAX_COUNT:
            raise MetadataStoreError("approval review receipt capacity has been reached")
        conn.execute(
            """
            INSERT INTO approval_review_receipts (
                id, approval_request_id, reviewer_id, review_digest,
                expires_at, used_at, created_at
            ) VALUES (?, ?, ?, ?, ?, NULL, ?)
            """,
            (
                receipt_id,
                approval_request_id,
                reviewer_id,
                review_digest,
                expires_at,
                now_s,
            ),
        )
    return {
        "id": receipt_id,
        "approval_request_id": approval_request_id,
        "reviewer_id": reviewer_id,
        "review_digest": review_digest,
        "expires_at": expires_at,
        "created_at": now_s,
    }


def get_active_approval_review_receipt(
    receipt_id: str,
    *,
    approval_request_id: str,
    reviewer_id: str,
) -> dict[str, Any] | None:
    now_s = iso_now()
    with connect() as conn:
        row = conn.execute(
            """
            SELECT * FROM approval_review_receipts
            WHERE id = ? AND approval_request_id = ? AND reviewer_id = ?
              AND used_at IS NULL AND expires_at > ?
            """,
            (receipt_id, approval_request_id, reviewer_id, now_s),
        ).fetchone()
    if row is None:
        return None
    return {
        "id": str(row["id"]),
        "approval_request_id": str(row["approval_request_id"]),
        "reviewer_id": str(row["reviewer_id"]),
        "review_digest": str(row["review_digest"]),
        "expires_at": str(row["expires_at"]),
        "created_at": str(row["created_at"]),
    }


def has_active_approval(route_id: str, url: str | None = None) -> bool:
    now_s = iso_now()
    args: list[Any] = [route_id, now_s]
    url_clause = ""
    if url is not None:
        url_clause = "AND url = ?"
        args.append(_approval_url_commitment(url))
    with connect() as conn:
        row = conn.execute(
            f"""
            SELECT id FROM approval_requests
            WHERE route_id = ? AND status = 'approved' AND approved_until > ? {url_clause}
            ORDER BY approved_until DESC LIMIT 1
            """,
            args,
        ).fetchone()
    return row is not None


def approve_request(
    item_id: str,
    ttl_seconds: int = 30,
    note: str | None = None,
    actor_id: str = "admin",
    authn: dict[str, Any] | None = None,
    challenge_id: str | None = None,
    review_receipt_id: str | None = None,
    review_digest: str | None = None,
    require_review_receipt: bool = False,
) -> dict[str, Any] | None:
    now = utcnow()
    now_s = now.isoformat()
    approved_until = (now + timedelta(seconds=ttl_seconds)).isoformat()
    with connect() as conn:
        _lock_pending_approval_creation(conn)
        existing = conn.execute(
            "SELECT * FROM approval_requests WHERE id = ?", (item_id,)
        ).fetchone()
        if not existing:
            return None
        if existing["status"] != "pending" or existing["expires_at"] <= now_s:
            return None
        review_receipt = None
        if require_review_receipt:
            if not review_receipt_id or not review_digest:
                raise MetadataStoreError("approval requires a review receipt")
            review_receipt = conn.execute(
                """
                SELECT * FROM approval_review_receipts
                WHERE id = ? AND approval_request_id = ? AND reviewer_id = ?
                  AND review_digest = ? AND used_at IS NULL AND expires_at > ?
                """,
                (
                    review_receipt_id,
                    item_id,
                    actor_id,
                    review_digest,
                    now_s,
                ),
            ).fetchone()
            if review_receipt is None:
                raise MetadataStoreError("approval review receipt is invalid, expired, or already used")
        grant_ttl_seconds = int(existing["grant_ttl_seconds"] or ttl_seconds)
        grant_max_uses = int(existing["grant_max_uses"] or 1)
        if not 1 <= grant_ttl_seconds <= 3600 or grant_max_uses < 1:
            raise MetadataStoreError("approval contains invalid grant bounds")
        if existing["request_digest"] and any(
            existing[field] is None
            for field in (
                "principal_id",
                "route_id",
                "credential_id",
                "credential_version",
                "policy_hash",
            )
        ):
            raise MetadataStoreError("approval grant binding is incomplete")
        if existing["request_digest"] and grants.uses_postgres():
            if not isinstance(
                conn, PostgresMetadataConnection
            ) or not grants.can_share_transaction(METADATA_STORE_POSTGRES_DSN):
                raise MetadataStoreError(
                    "postgres approval and grant stores must use the same DSN for atomic issuance"
                )
        approved_until = (now + timedelta(seconds=grant_ttl_seconds)).isoformat()
        approver_webauthn_credential_id = (
            (authn or {}).get("credential_record_id")
            if isinstance(authn, dict)
            else None
        )
        cur = conn.execute(
            """
            UPDATE approval_requests
            SET status = 'approved',
                approved_until = ?,
                decision_note = ?,
                approved_by = ?,
                approval_authn = ?,
                approver_webauthn_credential_id = ?,
                approval_challenge_id = ?
            WHERE id = ? AND status = 'pending' AND expires_at > ?
            """,
            (
                approved_until,
                note,
                actor_id,
                dumps(authn or {}),
                approver_webauthn_credential_id,
                challenge_id,
                item_id,
                now_s,
            ),
        )
        if cur.rowcount != 1:
            return None
        if review_receipt is not None:
            consumed = conn.execute(
                "UPDATE approval_review_receipts SET used_at = ? "
                "WHERE id = ? AND used_at IS NULL AND expires_at > ?",
                (now_s, review_receipt_id, now_s),
            )
            if consumed.rowcount != 1:
                raise MetadataStoreError("approval review receipt changed before approval")
        grant_result: dict[str, Any] | None = None
        if existing["request_digest"]:
            if grants.uses_postgres():
                grant_result = grants.create_grant(
                    grant_id=f"approval:{item_id}",
                    approval_request_id=item_id,
                    principal_id=existing["principal_id"],
                    route_id=existing["route_id"],
                    credential_id=existing["credential_id"],
                    credential_version=int(existing["credential_version"]),
                    policy_hash=existing["policy_hash"],
                    request_digest=existing["request_digest"],
                    operation_digest=existing["operation_digest"],
                    approver_webauthn_credential_id=approver_webauthn_credential_id,
                    uses_remaining=grant_max_uses,
                    valid_from=now_s,
                    expires_at=approved_until,
                    created_at=now_s,
                    connection=conn.raw_connection,
                    require_created=True,
                )
            else:
                grant_id = f"approval:{item_id}"
                conn.execute(
                    """
                    INSERT INTO approval_grants (
                        id, approval_request_id, state, principal_id, route_id, credential_id,
                        credential_version, policy_hash, request_digest, operation_digest, uses_remaining,
                        approver_webauthn_credential_id, valid_from, expires_at, created_at
                    )
                    VALUES (?, ?, 'active', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        grant_id,
                        item_id,
                        existing["principal_id"],
                        existing["route_id"],
                        existing["credential_id"],
                        existing["credential_version"],
                        existing["policy_hash"],
                        existing["request_digest"],
                        existing["operation_digest"],
                        grant_max_uses,
                        approver_webauthn_credential_id,
                        now_s,
                        approved_until,
                        now_s,
                    ),
                )
                grant_result = {"backend": "sqlite", "id": grant_id, "created": True}
        append_audit_event(
            conn,
            event_type="approval.approved",
            actor_type="admin",
            actor_id=actor_id,
            event={
                "approval_request_id": item_id,
                "route_id": existing["route_id"],
                "principal_id": existing["principal_id"],
                "credential_id": existing["credential_id"],
                "credential_version": existing["credential_version"],
                "policy_hash": existing["policy_hash"],
                "request_digest": existing["request_digest"],
                "operation_digest": existing["operation_digest"],
                "approved_until": approved_until,
                "approved_by": actor_id,
                "approval_authn": authn or {},
                "approval_challenge_id": challenge_id,
                "review_receipt_id": review_receipt_id,
                "review_digest": review_digest,
                "grant_max_uses": grant_max_uses,
                "grant_store_backend": (
                    grant_result or {"backend": grants.backend_name()}
                ).get("backend"),
                "grant_id": (grant_result or {}).get("id"),
                "note": note,
            },
        )
        row = conn.execute(
            "SELECT * FROM approval_requests WHERE id = ?", (item_id,)
        ).fetchone()
    return row_to_approval(row) if row else None


def _stable_grant_attempt_id(attempt_id: str | None, flow_id: str) -> str:
    value = attempt_id or flow_id
    if not value or len(value.encode("utf-8")) > _GRANT_ATTEMPT_ID_MAX_BYTES:
        raise MetadataStoreError(
            "grant attempt_id must be between 1 and 256 UTF-8 bytes"
        )
    return value


def _local_attempt_result(
    row: Any,
    *,
    principal_id: str,
    route_id: str,
    credential_id: str,
    credential_version: int,
    policy_hash: str,
    request_digest: str,
    operation_digest: str | None,
) -> dict[str, Any]:
    expected = {
        "principal_id": principal_id,
        "route_id": route_id,
        "credential_id": credential_id,
        "credential_version": credential_version,
        "policy_hash": policy_hash,
        "request_digest": request_digest,
        "operation_digest": operation_digest,
    }
    actual = {
        **{key: row[key] for key in expected},
        "credential_version": int(row["credential_version"]),
    }
    if actual != expected:
        return {
            "consumed": False,
            "reason": "attempt_id_conflict",
            "grant_store_backend": "sqlite",
        }
    return {
        "consumed": True,
        "reason": "already_consumed",
        "idempotent_replay": True,
        "grant_id": row["grant_id"],
        "approval_id": row["approval_request_id"],
        "approval_request_id": row["approval_request_id"],
        "uses_remaining_before": int(row["uses_remaining_before"]),
        "uses_remaining_after": int(row["uses_remaining_after"]),
        "consumption_id": row["id"],
        "attempt_id": row["attempt_id"],
        "grant_store_backend": "sqlite",
    }


def consume_jit_grant_result(
    *,
    principal_id: str,
    route_id: str,
    credential_id: str,
    credential_version: int,
    policy_hash: str,
    request_digest: str,
    operation_digest: str | None,
    flow_id: str,
    attempt_id: str | None = None,
) -> dict[str, Any]:
    stable_attempt_id = _stable_grant_attempt_id(attempt_id, flow_id)
    if grants.uses_postgres():
        result = grants.consume_grant_result(
            principal_id=principal_id,
            route_id=route_id,
            credential_id=credential_id,
            credential_version=credential_version,
            policy_hash=policy_hash,
            request_digest=request_digest,
            operation_digest=operation_digest,
            flow_id=flow_id,
            attempt_id=stable_attempt_id,
        )
        if not result["consumed"]:
            return result
        if result.get("idempotent_replay"):
            return result
        try:
            audit = record_audit_event(
                "jit.grant.consumed",
                {
                    "grant_id": result["grant_id"],
                    "approval_request_id": result["approval_request_id"],
                    "flow_id": flow_id,
                    "attempt_id": stable_attempt_id,
                    "principal_id": principal_id,
                    "route_id": route_id,
                    "credential_id": credential_id,
                    "credential_version": credential_version,
                    "policy_hash": policy_hash,
                    "request_digest": request_digest,
                    "operation_digest": operation_digest,
                    "consume_result": "consumed",
                    "uses_remaining_before": result["uses_remaining_before"],
                    "grant_store_backend": "postgres",
                    "consumption_id": result["consumption_id"],
                },
                actor_type="proxy",
                actor_id=route_id,
            )
            try:
                grants.mark_consumption_audited(
                    result["consumption_id"], audit["event_hash"]
                )
            except grants.GrantStoreError as exc:
                result["audit_mark_error"] = str(exc)
            result["audit_event_hash"] = audit["event_hash"]
        except Exception as exc:
            # The grant-store consumption row was committed atomically and remains
            # the authoritative record even if the secondary audit store is down.
            result["audit_delivery"] = "pending"
            result["audit_delivery_error"] = type(exc).__name__
        return result

    now_s = iso_now()
    consumption_id = str(uuid.uuid4())
    try:
        with connect() as conn:
            if isinstance(conn, PostgresMetadataConnection):
                conn.execute("SET LOCAL lock_timeout = '500ms'")
                lock_clause = "FOR UPDATE"
            else:
                if not conn.in_transaction:
                    conn.execute("BEGIN IMMEDIATE")
                lock_clause = ""

            def find_attempt() -> Any:
                return conn.execute(
                    """
                    SELECT id, grant_id, approval_request_id, attempt_id, flow_id,
                           principal_id, route_id, credential_id, credential_version,
                           policy_hash, request_digest, operation_digest,
                           uses_remaining_before, uses_remaining_after
                    FROM approval_grant_consumptions
                    WHERE attempt_id = ?
                    """,
                    (stable_attempt_id,),
                ).fetchone()

            existing_attempt = find_attempt()
            if existing_attempt is not None:
                return _local_attempt_result(
                    existing_attempt,
                    principal_id=principal_id,
                    route_id=route_id,
                    credential_id=credential_id,
                    credential_version=credential_version,
                    policy_hash=policy_hash,
                    request_digest=request_digest,
                    operation_digest=operation_digest,
                )
            row = conn.execute(
                f"""
                SELECT id, approval_request_id, uses_remaining FROM approval_grants
                WHERE state = 'active'
                  AND principal_id = ?
                  AND route_id = ?
                  AND credential_id = ?
                  AND credential_version = ?
                  AND policy_hash = ?
                  AND request_digest = ?
                  AND ((CAST(? AS TEXT) IS NULL AND operation_digest IS NULL) OR operation_digest = ?)
                  AND valid_from <= ?
                  AND expires_at > ?
                  AND uses_remaining > 0
                  AND reserved_attempt_id IS NULL
                ORDER BY created_at ASC
                LIMIT 1
                {lock_clause}
                """,
                (
                    principal_id,
                    route_id,
                    credential_id,
                    credential_version,
                    policy_hash,
                    request_digest,
                    operation_digest,
                    operation_digest,
                    now_s,
                    now_s,
                ),
            ).fetchone()
            if not row:
                existing_attempt = find_attempt()
                if existing_attempt is not None:
                    return _local_attempt_result(
                        existing_attempt,
                        principal_id=principal_id,
                        route_id=route_id,
                        credential_id=credential_id,
                        credential_version=credential_version,
                        policy_hash=policy_hash,
                        request_digest=request_digest,
                        operation_digest=operation_digest,
                    )
                return {
                    "consumed": False,
                    "reason": "missing_expired_not_yet_valid_or_already_consumed",
                    "grant_store_backend": "sqlite",
                }
            existing_attempt = find_attempt()
            if existing_attempt is not None:
                return _local_attempt_result(
                    existing_attempt,
                    principal_id=principal_id,
                    route_id=route_id,
                    credential_id=credential_id,
                    credential_version=credential_version,
                    policy_hash=policy_hash,
                    request_digest=request_digest,
                    operation_digest=operation_digest,
                )
            grant_id = row["id"]
            approval_request_id = row["approval_request_id"]
            uses_remaining = int(row["uses_remaining"])
            uses_after = uses_remaining - 1
            next_state = "consumed" if uses_after == 0 else "active"
            cur = conn.execute(
                """
                UPDATE approval_grants
                SET uses_remaining = ?,
                    state = ?,
                    consumed_at = CASE WHEN ? = 'consumed' THEN ? ELSE consumed_at END,
                    consumed_by_flow_id = CASE WHEN ? = 'consumed' THEN ? ELSE consumed_by_flow_id END
                WHERE id = ? AND state = 'active' AND uses_remaining = ?
                  AND valid_from <= ? AND expires_at > ?
                """,
                (
                    uses_after,
                    next_state,
                    next_state,
                    now_s,
                    next_state,
                    flow_id,
                    grant_id,
                    uses_remaining,
                    now_s,
                    now_s,
                ),
            )
            if cur.rowcount != 1:
                raise MetadataStoreError("grant update lost its locked row")
            conn.execute(
                """
                INSERT INTO approval_grant_consumptions (
                    id, grant_id, approval_request_id, attempt_id, flow_id,
                    principal_id, route_id, credential_id, credential_version,
                    policy_hash, request_digest, operation_digest, outcome,
                    uses_remaining_before, uses_remaining_after, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'consumed', ?, ?, ?)
                """,
                (
                    consumption_id,
                    grant_id,
                    approval_request_id,
                    stable_attempt_id,
                    flow_id,
                    principal_id,
                    route_id,
                    credential_id,
                    credential_version,
                    policy_hash,
                    request_digest,
                    operation_digest,
                    uses_remaining,
                    uses_after,
                    now_s,
                ),
            )
            append_audit_event(
                conn,
                event_type="jit.grant.consumed",
                actor_type="proxy",
                actor_id=route_id,
                event={
                    "grant_id": grant_id,
                    "approval_request_id": approval_request_id,
                    "flow_id": flow_id,
                    "attempt_id": stable_attempt_id,
                    "principal_id": principal_id,
                    "route_id": route_id,
                    "credential_id": credential_id,
                    "credential_version": credential_version,
                    "policy_hash": policy_hash,
                    "request_digest": request_digest,
                    "operation_digest": operation_digest,
                    "consume_result": "consumed",
                    "uses_remaining_before": uses_remaining,
                    "grant_store_backend": "sqlite",
                    "consumption_id": consumption_id,
                },
            )
    except Exception as exc:
        if getattr(exc, "sqlstate", None) == "55P03":
            return {
                "consumed": False,
                "reason": "grant_locked_retry",
                "retryable": True,
                "retry_after_ms": 500,
                "grant_store_backend": "sqlite",
            }
        raise
    return {
        "consumed": True,
        "reason": "consumed",
        "grant_id": grant_id,
        "approval_id": approval_request_id,
        "approval_request_id": approval_request_id,
        "uses_remaining_before": uses_remaining,
        "uses_remaining_after": uses_after,
        "consumption_id": consumption_id,
        "attempt_id": stable_attempt_id,
        "grant_store_backend": "sqlite",
    }


def find_jit_grant_result(
    *,
    principal_id: str,
    route_id: str,
    credential_id: str,
    credential_version: int,
    policy_hash: str,
    request_digest: str,
    operation_digest: str | None,
) -> dict[str, Any]:
    if grants.uses_postgres():
        return grants.find_grant_result(
            principal_id=principal_id,
            route_id=route_id,
            credential_id=credential_id,
            credential_version=credential_version,
            policy_hash=policy_hash,
            request_digest=request_digest,
            operation_digest=operation_digest,
        )

    now_s = iso_now()
    args: list[Any] = [
        principal_id,
        route_id,
        credential_id,
        credential_version,
        policy_hash,
        request_digest,
        operation_digest,
        operation_digest,
        now_s,
        now_s,
    ]
    with connect() as conn:
        row = conn.execute(
            """
            SELECT id, approval_request_id, uses_remaining FROM approval_grants
            WHERE state = 'active'
              AND principal_id = ?
              AND route_id = ?
              AND credential_id = ?
              AND credential_version = ?
              AND policy_hash = ?
              AND request_digest = ?
              AND ((CAST(? AS TEXT) IS NULL AND operation_digest IS NULL) OR operation_digest = ?)
              AND valid_from <= ?
              AND expires_at > ?
              AND uses_remaining > 0
              AND reserved_attempt_id IS NULL
            ORDER BY created_at ASC
            LIMIT 1
            """,
            args,
        ).fetchone()
    if not row:
        return {
            "available": False,
            "consumed": False,
            "reason": "missing_expired_not_yet_valid_or_already_consumed",
            "grant_store_backend": "sqlite",
        }
    uses_remaining = int(row["uses_remaining"])
    return {
        "available": True,
        "consumed": False,
        "reason": "available",
        "grant_id": row["id"],
        "approval_id": row["approval_request_id"],
        "approval_request_id": row["approval_request_id"],
        "uses_remaining_before": uses_remaining,
        "uses_remaining_after": uses_remaining,
        "grant_store_backend": "sqlite",
    }


def consume_jit_grant(
    *,
    principal_id: str,
    route_id: str,
    credential_id: str,
    credential_version: int,
    policy_hash: str,
    request_digest: str,
    operation_digest: str | None,
    flow_id: str,
    attempt_id: str | None = None,
) -> bool:
    return bool(
        consume_jit_grant_result(
            principal_id=principal_id,
            route_id=route_id,
            credential_id=credential_id,
            credential_version=credential_version,
            policy_hash=policy_hash,
            request_digest=request_digest,
            operation_digest=operation_digest,
            flow_id=flow_id,
            attempt_id=attempt_id,
        )["consumed"]
    )


def _rate_limit_retry_after(
    window_start_epoch_ms: int, window_seconds: int, now_epoch_ms: int
) -> int:
    reset_at = window_start_epoch_ms + window_seconds * 1000
    return max(1, int((max(reset_at - now_epoch_ms, 0) + 999) // 1000))


def _rate_limit_response(
    *,
    allowed: bool,
    reason: str,
    counter_key: str,
    window_start_epoch_ms: int,
    window_seconds: int,
    max_count: int,
    count: int,
    now_epoch_ms: int,
    consumed: bool,
) -> dict[str, Any]:
    remaining = max(max_count - count, 0)
    return {
        "allowed": allowed,
        "consumed": consumed,
        "reason": reason,
        "counter_key": counter_key,
        "window_start_epoch_ms": window_start_epoch_ms,
        "window_seconds": window_seconds,
        "max": max_count,
        "count": count,
        "remaining": remaining,
        "retry_after_seconds": 0
        if allowed
        else _rate_limit_retry_after(
            window_start_epoch_ms, window_seconds, now_epoch_ms
        ),
        "rate_limit_store_backend": metadata_store_backend_name(),
        "rate_limit_store_ha": metadata_uses_postgres(),
    }


def _consume_rate_limit_sqlite(
    *,
    counter_key: str,
    principal_id: str,
    route_id: str,
    credential_id: str,
    credential_version: int,
    policy_hash: str,
    constraint_id: str,
    operation: str | None,
    window_seconds: int,
    max_count: int,
    consume: bool,
    now_epoch_ms: int,
) -> dict[str, Any]:
    now_s = datetime.fromtimestamp(now_epoch_ms / 1000, timezone.utc).isoformat()
    preflight_row = None
    if not consume:
        with connect() as preflight:
            preflight_row = preflight.execute(
                "SELECT encrypted_operation FROM rate_limit_counters "
                "WHERE counter_key = ?",
                (counter_key,),
            ).fetchone()
        if preflight_row is None:
            return _rate_limit_response(
                allowed=True,
                reason="available",
                counter_key=counter_key,
                window_start_epoch_ms=now_epoch_ms,
                window_seconds=window_seconds,
                max_count=max_count,
                count=0,
                now_epoch_ms=now_epoch_ms,
                consumed=False,
            )
    crypto_required = operation is not None and (consume or preflight_row is not None)
    crypto_required = crypto_required or bool(
        preflight_row is not None and preflight_row["encrypted_operation"] is not None
    )
    keyring = load_bound_secret_keyring() if crypto_required else None
    stored_operation = _operation_digest(operation)
    encrypted_operation = (
        _encrypt_operation(
            operation,
            table_kind="rate_counter",
            counter_key=counter_key,
            attempt_id=None,
            keyring=keyring,
        )
        if operation is not None and keyring is not None
        else None
    )
    with connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT * FROM rate_limit_counters WHERE counter_key = ?",
            (counter_key,),
        ).fetchone()
        if row is None:
            count = 1 if consume else 0
            if consume:
                conn.execute(
                    """
                    INSERT INTO rate_limit_counters (
                        counter_key, principal_id, route_id, credential_id, credential_version,
                        policy_hash, constraint_id, operation, encrypted_operation,
                        operation_storage_version, window_start_epoch_ms,
                        window_seconds, max_count, count, created_at, updated_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        counter_key,
                        principal_id,
                        route_id,
                        credential_id,
                        credential_version,
                        policy_hash,
                        constraint_id,
                        stored_operation,
                        encrypted_operation,
                        _OPERATION_STORAGE_VERSION,
                        now_epoch_ms,
                        window_seconds,
                        max_count,
                        count,
                        now_s,
                        now_s,
                    ),
                )
            return _rate_limit_response(
                allowed=True,
                reason="consumed" if consume else "available",
                counter_key=counter_key,
                window_start_epoch_ms=now_epoch_ms,
                window_seconds=window_seconds,
                max_count=max_count,
                count=count,
                now_epoch_ms=now_epoch_ms,
                consumed=consume,
            )

        _stored_operation(row, table_kind="rate_counter", keyring=keyring)
        window_start = int(row["window_start_epoch_ms"])
        count = int(row["count"])
        expired = now_epoch_ms >= window_start + int(row["window_seconds"]) * 1000
        if expired:
            if not consume:
                return _rate_limit_response(
                    allowed=True,
                    reason="available",
                    counter_key=counter_key,
                    window_start_epoch_ms=now_epoch_ms,
                    window_seconds=window_seconds,
                    max_count=max_count,
                    count=0,
                    now_epoch_ms=now_epoch_ms,
                    consumed=False,
                )
            window_start = now_epoch_ms
            count = 0
        if count >= max_count:
            if (
                expired
                or int(row["window_seconds"]) != window_seconds
                or int(row["max_count"]) != max_count
            ):
                conn.execute(
                    """
                    UPDATE rate_limit_counters
                    SET principal_id = ?, route_id = ?, credential_id = ?, credential_version = ?,
                        policy_hash = ?, constraint_id = ?, operation = ?,
                        encrypted_operation = ?, operation_storage_version = ?,
                        window_start_epoch_ms = ?, window_seconds = ?, max_count = ?,
                        count = ?, updated_at = ?
                    WHERE counter_key = ?
                    """,
                    (
                        principal_id,
                        route_id,
                        credential_id,
                        credential_version,
                        policy_hash,
                        constraint_id,
                        stored_operation,
                        encrypted_operation,
                        _OPERATION_STORAGE_VERSION,
                        window_start,
                        window_seconds,
                        max_count,
                        count,
                        now_s,
                        counter_key,
                    ),
                )
            return _rate_limit_response(
                allowed=False,
                reason="rate_limited",
                counter_key=counter_key,
                window_start_epoch_ms=window_start,
                window_seconds=window_seconds,
                max_count=max_count,
                count=count,
                now_epoch_ms=now_epoch_ms,
                consumed=False,
            )

        if consume:
            count += 1
        if (
            consume
            or expired
            or int(row["window_seconds"]) != window_seconds
            or int(row["max_count"]) != max_count
        ):
            conn.execute(
                """
                UPDATE rate_limit_counters
                SET principal_id = ?, route_id = ?, credential_id = ?, credential_version = ?,
                    policy_hash = ?, constraint_id = ?, operation = ?,
                    encrypted_operation = ?, operation_storage_version = ?,
                    window_start_epoch_ms = ?, window_seconds = ?, max_count = ?,
                    count = ?, updated_at = ?
                WHERE counter_key = ?
                """,
                (
                    principal_id,
                    route_id,
                    credential_id,
                    credential_version,
                    policy_hash,
                    constraint_id,
                    stored_operation,
                    encrypted_operation,
                    _OPERATION_STORAGE_VERSION,
                    window_start,
                    window_seconds,
                    max_count,
                    count,
                    now_s,
                    counter_key,
                ),
            )
    return _rate_limit_response(
        allowed=True,
        reason="consumed" if consume else "available",
        counter_key=counter_key,
        window_start_epoch_ms=window_start,
        window_seconds=window_seconds,
        max_count=max_count,
        count=count,
        now_epoch_ms=now_epoch_ms,
        consumed=consume,
    )


def _consume_rate_limit_postgres(
    *,
    counter_key: str,
    principal_id: str,
    route_id: str,
    credential_id: str,
    credential_version: int,
    policy_hash: str,
    constraint_id: str,
    operation: str | None,
    window_seconds: int,
    max_count: int,
    consume: bool,
    now_epoch_ms: int,
) -> dict[str, Any]:
    now_s = datetime.fromtimestamp(now_epoch_ms / 1000, timezone.utc).isoformat()
    preflight_row = None
    if not consume:
        with _metadata_pg_connect_raw() as preflight:
            preflight_row = preflight.execute(
                "SELECT encrypted_operation FROM rate_limit_counters "
                "WHERE counter_key = %s",
                (counter_key,),
            ).fetchone()
        if preflight_row is None:
            return _rate_limit_response(
                allowed=True,
                reason="available",
                counter_key=counter_key,
                window_start_epoch_ms=now_epoch_ms,
                window_seconds=window_seconds,
                max_count=max_count,
                count=0,
                now_epoch_ms=now_epoch_ms,
                consumed=False,
            )
    crypto_required = operation is not None and (consume or preflight_row is not None)
    crypto_required = crypto_required or bool(
        preflight_row is not None and preflight_row["encrypted_operation"] is not None
    )
    keyring = load_bound_secret_keyring() if crypto_required else None
    stored_operation = _operation_digest(operation)
    encrypted_operation = (
        _encrypt_operation(
            operation,
            table_kind="rate_counter",
            counter_key=counter_key,
            attempt_id=None,
            keyring=keyring,
        )
        if operation is not None and keyring is not None
        else None
    )
    with _metadata_pg_connect_raw() as conn:
        with conn.transaction():
            with conn.cursor() as cur:
                if consume:
                    cur.execute(
                        """
                        INSERT INTO rate_limit_counters (
                            counter_key, principal_id, route_id, credential_id, credential_version,
                            policy_hash, constraint_id, operation, encrypted_operation,
                            operation_storage_version, window_start_epoch_ms,
                            window_seconds, max_count, count, created_at, updated_at
                        )
                        VALUES (
                            %(counter_key)s, %(principal_id)s, %(route_id)s, %(credential_id)s,
                            %(credential_version)s, %(policy_hash)s, %(constraint_id)s, %(operation)s,
                            %(encrypted_operation)s, %(operation_storage_version)s,
                            %(window_start_epoch_ms)s, %(window_seconds)s, %(max_count)s,
                            0, %(created_at)s, %(updated_at)s
                        )
                        ON CONFLICT (counter_key) DO NOTHING
                        """,
                        {
                            "counter_key": counter_key,
                            "principal_id": principal_id,
                            "route_id": route_id,
                            "credential_id": credential_id,
                            "credential_version": credential_version,
                            "policy_hash": policy_hash,
                            "constraint_id": constraint_id,
                            "operation": stored_operation,
                            "encrypted_operation": encrypted_operation,
                            "operation_storage_version": _OPERATION_STORAGE_VERSION,
                            "window_start_epoch_ms": now_epoch_ms,
                            "window_seconds": window_seconds,
                            "max_count": max_count,
                            "created_at": now_s,
                            "updated_at": now_s,
                        },
                    )
                cur.execute(
                    """
                    SELECT *
                    FROM rate_limit_counters
                    WHERE counter_key = %(counter_key)s
                    FOR UPDATE
                    """,
                    {"counter_key": counter_key},
                )
                row = cur.fetchone()
                if row is None:
                    if consume:
                        raise RateLimitStoreError(
                            "postgres rate limit counter insert did not create a locked row"
                        )
                    return _rate_limit_response(
                        allowed=True,
                        reason="available",
                        counter_key=counter_key,
                        window_start_epoch_ms=now_epoch_ms,
                        window_seconds=window_seconds,
                        max_count=max_count,
                        count=0,
                        now_epoch_ms=now_epoch_ms,
                        consumed=False,
                    )

                _stored_operation(row, table_kind="rate_counter", keyring=keyring)
                window_start = int(row["window_start_epoch_ms"])
                count = int(row["count"])
                expired = (
                    now_epoch_ms >= window_start + int(row["window_seconds"]) * 1000
                )
                if expired:
                    if not consume:
                        return _rate_limit_response(
                            allowed=True,
                            reason="available",
                            counter_key=counter_key,
                            window_start_epoch_ms=now_epoch_ms,
                            window_seconds=window_seconds,
                            max_count=max_count,
                            count=0,
                            now_epoch_ms=now_epoch_ms,
                            consumed=False,
                        )
                    window_start = now_epoch_ms
                    count = 0
                if count >= max_count:
                    if (
                        expired
                        or int(row["window_seconds"]) != window_seconds
                        or int(row["max_count"]) != max_count
                    ):
                        cur.execute(
                            """
                            UPDATE rate_limit_counters
                            SET principal_id = %(principal_id)s,
                                route_id = %(route_id)s,
                                credential_id = %(credential_id)s,
                                credential_version = %(credential_version)s,
                                policy_hash = %(policy_hash)s,
                                constraint_id = %(constraint_id)s,
                                operation = %(operation)s,
                                encrypted_operation = %(encrypted_operation)s,
                                operation_storage_version = %(operation_storage_version)s,
                                window_start_epoch_ms = %(window_start_epoch_ms)s,
                                window_seconds = %(window_seconds)s,
                                max_count = %(max_count)s,
                                count = %(count)s,
                                updated_at = %(updated_at)s
                            WHERE counter_key = %(counter_key)s
                            """,
                            {
                                "counter_key": counter_key,
                                "principal_id": principal_id,
                                "route_id": route_id,
                                "credential_id": credential_id,
                                "credential_version": credential_version,
                                "policy_hash": policy_hash,
                                "constraint_id": constraint_id,
                                "operation": stored_operation,
                                "encrypted_operation": encrypted_operation,
                                "operation_storage_version": _OPERATION_STORAGE_VERSION,
                                "window_start_epoch_ms": window_start,
                                "window_seconds": window_seconds,
                                "max_count": max_count,
                                "count": count,
                                "updated_at": now_s,
                            },
                        )
                    return _rate_limit_response(
                        allowed=False,
                        reason="rate_limited",
                        counter_key=counter_key,
                        window_start_epoch_ms=window_start,
                        window_seconds=window_seconds,
                        max_count=max_count,
                        count=count,
                        now_epoch_ms=now_epoch_ms,
                        consumed=False,
                    )

                if consume:
                    count += 1
                if (
                    consume
                    or expired
                    or int(row["window_seconds"]) != window_seconds
                    or int(row["max_count"]) != max_count
                ):
                    cur.execute(
                        """
                        UPDATE rate_limit_counters
                        SET principal_id = %(principal_id)s,
                            route_id = %(route_id)s,
                            credential_id = %(credential_id)s,
                            credential_version = %(credential_version)s,
                            policy_hash = %(policy_hash)s,
                            constraint_id = %(constraint_id)s,
                            operation = %(operation)s,
                            encrypted_operation = %(encrypted_operation)s,
                            operation_storage_version = %(operation_storage_version)s,
                            window_start_epoch_ms = %(window_start_epoch_ms)s,
                            window_seconds = %(window_seconds)s,
                            max_count = %(max_count)s,
                            count = %(count)s,
                            updated_at = %(updated_at)s
                        WHERE counter_key = %(counter_key)s
                        """,
                        {
                            "counter_key": counter_key,
                            "principal_id": principal_id,
                            "route_id": route_id,
                            "credential_id": credential_id,
                            "credential_version": credential_version,
                            "policy_hash": policy_hash,
                            "constraint_id": constraint_id,
                            "operation": stored_operation,
                            "encrypted_operation": encrypted_operation,
                            "operation_storage_version": _OPERATION_STORAGE_VERSION,
                            "window_start_epoch_ms": window_start,
                            "window_seconds": window_seconds,
                            "max_count": max_count,
                            "count": count,
                            "updated_at": now_s,
                        },
                    )
    return _rate_limit_response(
        allowed=True,
        reason="consumed" if consume else "available",
        counter_key=counter_key,
        window_start_epoch_ms=window_start,
        window_seconds=window_seconds,
        max_count=max_count,
        count=count,
        now_epoch_ms=now_epoch_ms,
        consumed=consume,
    )


def consume_rate_limit(
    *,
    counter_key: str,
    principal_id: str,
    route_id: str,
    credential_id: str,
    credential_version: int,
    policy_hash: str,
    constraint_id: str,
    operation: str | None,
    window_seconds: int,
    max_count: int,
    consume: bool = True,
    now_epoch_ms: int | None = None,
    actor_type: str = "proxy",
    actor_id: str | None = None,
    audit: bool = True,
) -> dict[str, Any]:
    if not counter_key.startswith("sha256:") or len(counter_key) != 71:
        raise RateLimitStoreError("rate limit counter_key must be a sha256: digest")
    if window_seconds < 1 or max_count < 1:
        raise RateLimitStoreError(
            "rate limit max_count and window_seconds must be positive"
        )
    now_ms = int(
        now_epoch_ms if now_epoch_ms is not None else utcnow().timestamp() * 1000
    )
    if metadata_uses_postgres():
        result = _consume_rate_limit_postgres(
            counter_key=counter_key,
            principal_id=principal_id,
            route_id=route_id,
            credential_id=credential_id,
            credential_version=credential_version,
            policy_hash=policy_hash,
            constraint_id=constraint_id,
            operation=operation,
            window_seconds=window_seconds,
            max_count=max_count,
            consume=consume,
            now_epoch_ms=now_ms,
        )
    else:
        result = _consume_rate_limit_sqlite(
            counter_key=counter_key,
            principal_id=principal_id,
            route_id=route_id,
            credential_id=credential_id,
            credential_version=credential_version,
            policy_hash=policy_hash,
            constraint_id=constraint_id,
            operation=operation,
            window_seconds=window_seconds,
            max_count=max_count,
            consume=consume,
            now_epoch_ms=now_ms,
        )
    if audit and (consume or not result["allowed"]):
        try:
            audit_event = record_audit_event(
                "rate_limit.consumed"
                if result["allowed"] and consume
                else "rate_limit.denied",
                {
                    "counter_key": counter_key,
                    "principal_id": principal_id,
                    "route_id": route_id,
                    "credential_id": credential_id,
                    "credential_version": credential_version,
                    "policy_hash": policy_hash,
                    "constraint_id": constraint_id,
                    "operation": operation,
                    "consume": consume,
                    "allowed": result["allowed"],
                    "reason": result["reason"],
                    "count": result["count"],
                    "max": result["max"],
                    "remaining": result["remaining"],
                    "window_seconds": result["window_seconds"],
                    "window_start_epoch_ms": result["window_start_epoch_ms"],
                    "retry_after_seconds": result["retry_after_seconds"],
                    "rate_limit_store_backend": result["rate_limit_store_backend"],
                },
                actor_type=actor_type,
                actor_id=actor_id or route_id,
            )
            result["audit_event_hash"] = audit_event["event_hash"]
        except Exception as exc:
            result["audit_error"] = str(exc)
    return result


def clear_rate_limit_counters(
    route_ids: list[str] | tuple[str, ...] | None = None,
) -> int:
    with connect() as conn:
        if route_ids is None:
            cur = conn.execute("DELETE FROM rate_limit_counters")
            return int(cur.rowcount or 0)
        deleted = 0
        for route_id in route_ids:
            cur = conn.execute(
                "DELETE FROM rate_limit_counters WHERE route_id = ?", (route_id,)
            )
            deleted += int(cur.rowcount or 0)
        return deleted


def release_authorization_writer_status() -> dict[str, Any]:
    metadata_backend = metadata_store_backend_name()
    grant_backend = grants.backend_name()
    if metadata_backend == "sqlite" and grant_backend == "sqlite":
        shared_transaction = True
        writer = "sqlite-metadata"
    elif metadata_backend == "postgres" and grant_backend == "postgres":
        shared_transaction = grants.can_share_transaction(METADATA_STORE_POSTGRES_DSN)
        writer = "postgres-metadata" if shared_transaction else None
    else:
        shared_transaction = False
        writer = None
    return {
        "metadata_backend": metadata_backend,
        "grant_backend": grant_backend,
        "shared_transaction": shared_transaction,
        "writer": writer,
    }


def require_atomic_release_writer() -> dict[str, Any]:
    status = release_authorization_writer_status()
    if not status["shared_transaction"]:
        raise ReleaseAuthorizationError(
            "atomic release authorization requires metadata and grant stores "
            "to use the same writer DSN and schema"
        )
    return status


def _release_text(label: str, value: Any, *, maximum: int = 256) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value.encode("utf-8")) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ReleaseAuthorizationError(
            f"{label} must be a non-empty trimmed string of at most {maximum} bytes"
        )
    return value


def _release_digest(label: str, value: Any, *, required: bool = True) -> str | None:
    if value is None and not required:
        return None
    digest = _release_text(label, value, maximum=71)
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        raise ReleaseAuthorizationError(f"{label} must be a lowercase sha256 digest")
    return digest


def _release_now_epoch_ms(value: int | None = None) -> int:
    now = int(value if value is not None else utcnow().timestamp() * 1000)
    if now < 0:
        raise ReleaseAuthorizationError("release authorization time is invalid")
    return now


def _release_timestamp_epoch_ms(value: Any) -> int:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    else:
        raise ReleaseAuthorizationError("grant expiry timestamp is invalid")
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return int(parsed.astimezone(timezone.utc).timestamp() * 1000)


def _begin_release_transaction(conn: Any) -> None:
    if isinstance(conn, PostgresMetadataConnection):
        conn.execute(
            f"SET LOCAL lock_timeout = '{_RELEASE_AUTHORIZATION_LOCK_WAIT_MS}ms'"
        )
    elif not conn.in_transaction:
        conn.execute("BEGIN IMMEDIATE")


def _release_lock_id(resource: str) -> int:
    return int.from_bytes(
        hashlib.sha256(resource.encode("utf-8")).digest()[:8],
        byteorder="big",
        signed=True,
    )


def _lock_release_resources(conn: Any, resources: list[str] | set[str]) -> None:
    if not isinstance(conn, PostgresMetadataConnection):
        return
    for resource in sorted(set(resources)):
        conn.execute(
            "SELECT pg_advisory_xact_lock(?)",
            (_release_lock_id(resource),),
        )


def _release_attempt_row(
    conn: Any, attempt_id: str, *, for_update: bool = False
) -> Any | None:
    suffix = " FOR UPDATE" if for_update and isinstance(conn, PostgresMetadataConnection) else ""
    return conn.execute(
        "SELECT * FROM release_authorization_attempts WHERE attempt_id = ?" + suffix,
        (attempt_id,),
    ).fetchone()


def _release_consumption_row(
    conn: Any, attempt_id: str, *, for_update: bool = False
) -> Any | None:
    suffix = " FOR UPDATE" if for_update and isinstance(conn, PostgresMetadataConnection) else ""
    return conn.execute(
        "SELECT * FROM approval_grant_consumptions WHERE attempt_id = ?" + suffix,
        (attempt_id,),
    ).fetchone()


def _release_consumption_matches_attempt(consumption: Any, attempt: Any) -> bool:
    expected = {
        "grant_id": attempt["grant_id"],
        "approval_request_id": attempt["approval_request_id"],
        "attempt_id": attempt["attempt_id"],
        "flow_id": attempt["flow_id"],
        "principal_id": attempt["principal_id"],
        "route_id": attempt["route_id"],
        "credential_id": attempt["credential_id"],
        "credential_version": int(attempt["credential_version"]),
        "policy_hash": attempt["policy_hash"],
        "request_digest": attempt["request_digest"],
        "operation_digest": attempt["operation_digest"],
    }
    actual = {
        key: int(consumption[key]) if key == "credential_version" else consumption[key]
        for key in expected
    }
    return actual == expected


def _validate_release_consumption_state(conn: Any, attempt: Any) -> None:
    consumption = _release_consumption_row(
        conn, str(attempt["attempt_id"]), for_update=True
    )
    committed_with_grant = (
        attempt["state"] in {"committed", "committed_indeterminate"}
        and attempt["grant_id"] is not None
    )
    if committed_with_grant:
        if consumption is None:
            raise ReleaseAuthorizationError(
                "committed release authorization is missing its grant consumption"
            )
        if not _release_consumption_matches_attempt(consumption, attempt):
            raise ReleaseAuthorizationError(
                "release authorization attempt_id collides with a mismatched "
                "grant consumption"
            )
    elif consumption is not None:
        raise ReleaseAuthorizationError(
            "release authorization has a grant consumption in an incompatible state"
        )


def _release_quota_rows(conn: Any, attempt_id: str) -> list[Any]:
    return list(
        conn.execute(
            "SELECT * FROM release_authorization_quota_reservations "
            "WHERE attempt_id = ? ORDER BY counter_key ASC",
            (attempt_id,),
        ).fetchall()
    )


def _release_authorization_result(
    conn: Any,
    row: Any,
    *,
    idempotent_replay: bool,
    reason: str | None = None,
    keyring: BoundSecretKeyring | None = None,
) -> dict[str, Any]:
    keyring = keyring or load_bound_secret_keyring()
    quotas = [
        {
            "counter_key": item["counter_key"],
            "constraint_id": item["constraint_id"],
            "operation": _release_operation(item, keyring=keyring),
            "window_start_epoch_ms": int(item["window_start_epoch_ms"]),
            "window_seconds": int(item["window_seconds"]),
            "max": int(item["max_count"]),
            "count": int(item["count_after"]),
            "remaining": max(
                int(item["max_count"]) - int(item["count_after"]), 0
            ),
            "reservation_state": item["reservation_state"],
        }
        for item in _release_quota_rows(conn, str(row["attempt_id"]))
    ]
    state = str(row["state"])
    return {
        "authorized": state in _RELEASE_AUTHORIZATION_STATES - {"cancelled"},
        "state": state,
        "reason": reason or state,
        "attempt_id": str(row["attempt_id"]),
        "binding_digest": str(row["binding_digest"]),
        "idempotent_replay": idempotent_replay,
        "grant_id": row["grant_id"],
        "approval_request_id": row["approval_request_id"],
        "reservation_expires_at_epoch_ms": int(
            row["reservation_expires_at_epoch_ms"]
        ),
        "dispatch_started_at_epoch_ms": (
            int(row["dispatch_started_at_epoch_ms"])
            if row["dispatch_started_at_epoch_ms"] is not None
            else None
        ),
        "dispatch_expires_at_epoch_ms": (
            int(row["dispatch_expires_at_epoch_ms"])
            if row["dispatch_expires_at_epoch_ms"] is not None
            else None
        ),
        "completion_outcome": row["completion_outcome"],
        "quotas": quotas,
        "release_authorization_store_backend": metadata_store_backend_name(),
        "release_authorization_store_ha": metadata_uses_postgres(),
    }


def _insert_release_event(
    conn: Any,
    *,
    attempt_id: str,
    state: str,
    actor_id: str | None,
    event: dict[str, Any],
) -> None:
    event_type = f"release_authorization.{state}"
    conn.execute(
        """
        INSERT INTO release_authorization_events (
            id, attempt_id, event_type, actor_id, event_json, created_at
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            str(uuid.uuid4()),
            attempt_id,
            event_type,
            actor_id,
            dumps(event),
            iso_now(),
        ),
    )


def _release_denial(
    *,
    attempt_id: str,
    binding_digest: str,
    reason: str,
    retry_after_seconds: int = 0,
) -> _ReleaseAuthorizationDenied:
    return _ReleaseAuthorizationDenied(
        {
            "authorized": False,
            "state": "denied",
            "reason": reason,
            "attempt_id": attempt_id,
            "binding_digest": binding_digest,
            "idempotent_replay": False,
            "retry_after_seconds": max(0, retry_after_seconds),
            "release_authorization_store_backend": metadata_store_backend_name(),
            "release_authorization_store_ha": metadata_uses_postgres(),
        }
    )


def _prepare_release_quotas(
    shared_quotas: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    prepared: dict[str, dict[str, Any]] = {}
    for item in shared_quotas:
        if not isinstance(item, dict):
            raise ReleaseAuthorizationError("shared quota claim must be an object")
        counter_key = _release_digest("shared quota counter_key", item.get("counter_key"))
        assert counter_key is not None
        constraint_id = _release_text(
            "shared quota constraint_id", item.get("constraint_id")
        )
        operation = item.get("operation")
        if operation is not None:
            operation = _release_text("shared quota operation", operation)
        window_seconds = item.get("window_seconds")
        max_count = item.get("max_count")
        if (
            not isinstance(window_seconds, int)
            or isinstance(window_seconds, bool)
            or not 1 <= window_seconds <= 31_536_000
            or not isinstance(max_count, int)
            or isinstance(max_count, bool)
            or not 1 <= max_count <= 1_000_000_000
        ):
            raise ReleaseAuthorizationError("shared quota bounds are invalid")
        normalized = {
            "counter_key": counter_key,
            "constraint_id": constraint_id,
            "operation": operation,
            "window_seconds": window_seconds,
            "max_count": max_count,
        }
        previous = prepared.get(counter_key)
        if previous is not None and previous != normalized:
            raise ReleaseAuthorizationError(
                "duplicate shared quota key has conflicting policy claims"
            )
        prepared[counter_key] = normalized
    return [prepared[key] for key in sorted(prepared)]


def reserve_release_authorization(
    *,
    attempt_id: str,
    flow_id: str,
    principal_id: str,
    route_id: str,
    credential_id: str,
    credential_version: int,
    policy_hash: str,
    request_digest: str,
    operation_digest: str | None,
    operation_context: dict[str, Any],
    shared_quotas: list[dict[str, Any]],
    require_jit_grant: bool,
    reservation_ttl_seconds: int,
    jit_approval_request: dict[str, Any] | None = None,
    now_epoch_ms: int | None = None,
    actor_id: str | None = None,
) -> dict[str, Any]:
    require_atomic_release_writer()
    attempt_id = _release_text(
        "release authorization attempt_id",
        attempt_id,
        maximum=_RELEASE_AUTHORIZATION_ATTEMPT_ID_MAX_BYTES,
    )
    flow_id = _release_text("release authorization flow_id", flow_id)
    principal_id = _release_text("release authorization principal_id", principal_id)
    route_id = _release_text("release authorization route_id", route_id)
    if credential_id:
        credential_id = _release_text(
            "release authorization credential_id", credential_id
        )
    if (
        not isinstance(credential_version, int)
        or isinstance(credential_version, bool)
        or credential_version < 0
    ):
        raise ReleaseAuthorizationError("credential_version must be non-negative")
    policy_hash = _release_digest("release authorization policy_hash", policy_hash) or ""
    request_digest = (
        _release_digest("release authorization request_digest", request_digest) or ""
    )
    operation_digest = _release_digest(
        "release authorization operation_digest",
        operation_digest,
        required=False,
    )
    if not isinstance(operation_context, dict):
        raise ReleaseAuthorizationError("operation_context must be an object")
    canonical_operation_context = dumps(operation_context)
    if len(canonical_operation_context.encode("utf-8")) > _RELEASE_AUTHORIZATION_BINDING_MAX_BYTES:
        raise ReleaseAuthorizationError("operation_context exceeds 64 KiB")
    operation_context_digest = (
        "sha256:"
        + hashlib.sha256(canonical_operation_context.encode("utf-8")).hexdigest()
    )
    operation_context_json = dumps({"digest": operation_context_digest})
    if not isinstance(reservation_ttl_seconds, int) or not 1 <= reservation_ttl_seconds <= 300:
        raise ReleaseAuthorizationError("reservation TTL must be between 1 and 300 seconds")
    quotas = _prepare_release_quotas(shared_quotas)
    binding = {
        "attempt_id": attempt_id,
        "flow_id": flow_id,
        "principal_id": principal_id,
        "route_id": route_id,
        "credential_id": credential_id,
        "credential_version": credential_version,
        "policy_hash": policy_hash,
        "request_digest": request_digest,
        "operation_digest": operation_digest,
        "operation_context": operation_context,
        "require_jit_grant": bool(require_jit_grant),
        "shared_quotas": quotas,
    }
    binding_json = dumps(binding)
    if len(binding_json.encode("utf-8")) > _RELEASE_AUTHORIZATION_BINDING_MAX_BYTES:
        raise ReleaseAuthorizationError("release authorization binding exceeds 64 KiB")
    binding_digest = "sha256:" + hashlib.sha256(binding_json.encode("utf-8")).hexdigest()
    persisted_binding_json = dumps({"digest": binding_digest})
    if now_epoch_ms is None:
        release_now = utcnow()
        now_ms = int(release_now.timestamp() * 1000)
    else:
        now_ms = _release_now_epoch_ms(now_epoch_ms)
        release_now = datetime.fromtimestamp(now_ms / 1000, timezone.utc)
    now_s = release_now.isoformat()
    keyring = load_bound_secret_keyring()

    try:
        with connect() as conn:
            _begin_release_transaction(conn)
            existing = _release_attempt_row(conn, attempt_id, for_update=True)
            if existing is not None:
                if not hmac.compare_digest(str(existing["binding_digest"]), binding_digest):
                    raise ReleaseAuthorizationConflictError(
                        "release authorization attempt_id is bound to a different request"
                    )
                _validate_release_consumption_state(conn, existing)
                return _release_authorization_result(
                    conn, existing, idempotent_replay=True, keyring=keyring
                )

            if require_jit_grant:
                if not credential_id or credential_version < 1:
                    raise ReleaseAuthorizationError(
                        "JIT release authorization requires a credential binding"
                    )

            resources = {f"attempt:{attempt_id}"}
            resources.update(f"quota:{item['counter_key']}" for item in quotas)
            _lock_release_resources(conn, resources)

            existing = _release_attempt_row(conn, attempt_id, for_update=True)
            if existing is not None:
                if not hmac.compare_digest(str(existing["binding_digest"]), binding_digest):
                    raise ReleaseAuthorizationConflictError(
                        "release authorization attempt_id is bound to a different request"
                    )
                _validate_release_consumption_state(conn, existing)
                return _release_authorization_result(
                    conn, existing, idempotent_replay=True, keyring=keyring
                )
            if _release_consumption_row(conn, attempt_id, for_update=True) is not None:
                raise ReleaseAuthorizationError(
                    "release authorization attempt_id collides with a grant "
                    "consumption that has no durable release attempt"
                )

            reservation_expires_at_ms = now_ms + reservation_ttl_seconds * 1000
            grant = None
            if require_jit_grant:
                _lock_pending_approval_creation(conn)
                lock_suffix = ""
                if isinstance(conn, PostgresMetadataConnection):
                    lock_suffix = " FOR UPDATE SKIP LOCKED"
                grant = conn.execute(
                    """
                    SELECT * FROM approval_grants
                    WHERE state = 'active'
                      AND principal_id = ?
                      AND route_id = ?
                      AND credential_id = ?
                      AND credential_version = ?
                      AND policy_hash = ?
                      AND request_digest = ?
                      AND COALESCE(operation_digest, '') = COALESCE(?, '')
                      AND expires_at > ?
                      AND uses_remaining > 0
                      AND reserved_attempt_id IS NULL
                    ORDER BY created_at ASC, id ASC
                    LIMIT 1
                    """
                    + lock_suffix,
                    (
                        principal_id,
                        route_id,
                        credential_id,
                        credential_version,
                        policy_hash,
                        request_digest,
                        operation_digest,
                        now_s,
                    ),
                ).fetchone()
                if (
                    grant is None
                    or grant["state"] != "active"
                    or int(grant["uses_remaining"]) < 1
                    or grant["reserved_attempt_id"] is not None
                    or _release_timestamp_epoch_ms(grant["valid_from"]) > now_ms
                    or _release_timestamp_epoch_ms(grant["expires_at"]) <= now_ms
                ):
                    if jit_approval_request is not None:
                        try:
                            approval = _ensure_jit_approval_request_on_connection(
                                conn,
                                route_id=route_id,
                                method=jit_approval_request["method"],
                                url=jit_approval_request["url"],
                                principal_id=principal_id,
                                credential_id=credential_id,
                                credential_version=credential_version,
                                policy_hash=policy_hash,
                                request_digest=request_digest,
                                operation_digest=operation_digest,
                                canonical_request=jit_approval_request[
                                    "canonical_request"
                                ],
                                redacted_display=jit_approval_request[
                                    "redacted_display"
                                ],
                                pending_ttl_seconds=jit_approval_request[
                                    "pending_ttl_seconds"
                                ],
                                grant_ttl_seconds=jit_approval_request[
                                    "grant_ttl_seconds"
                                ],
                                grant_max_uses=jit_approval_request[
                                    "grant_max_uses"
                                ],
                                now=release_now,
                            )
                        except (KeyError, MetadataStoreError) as exc:
                            raise ReleaseAuthorizationError(
                                "JIT approval request could not be committed"
                            ) from exc
                        denial = _release_denial(
                            attempt_id=attempt_id,
                            binding_digest=binding_digest,
                            reason="jit_grant_unavailable",
                            retry_after_seconds=3,
                        ).result
                        denial.update(
                            {
                                "approval_request_id": approval["id"],
                                "approval_status": approval["status"],
                                "approval_expires_at": approval["expires_at"],
                                "approval_created": bool(
                                    approval.get("approval_created")
                                ),
                            }
                        )
                        return denial
                    raise _release_denial(
                        attempt_id=attempt_id,
                        binding_digest=binding_digest,
                        reason="jit_grant_unavailable",
                        retry_after_seconds=1,
                    )
                reservation_expires_at_ms = min(
                    reservation_expires_at_ms,
                    _release_timestamp_epoch_ms(grant["expires_at"]),
                )
                if reservation_expires_at_ms <= now_ms:
                    raise _release_denial(
                        attempt_id=attempt_id,
                        binding_digest=binding_digest,
                        reason="jit_grant_expired",
                    )

            prepared_counters: list[dict[str, Any]] = []
            for quota in quotas:
                encrypted_counter_operation = _encrypt_operation(
                    quota["operation"],
                    table_kind="rate_counter",
                    counter_key=quota["counter_key"],
                    attempt_id=None,
                    keyring=keyring,
                )
                conn.execute(
                    """
                    INSERT INTO rate_limit_counters (
                        counter_key, principal_id, route_id, credential_id,
                        credential_version, policy_hash, constraint_id, operation,
                        encrypted_operation, operation_storage_version,
                        window_start_epoch_ms, window_seconds, max_count, count,
                        created_at, updated_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)
                    ON CONFLICT (counter_key) DO NOTHING
                    """,
                    (
                        quota["counter_key"],
                        principal_id,
                        route_id,
                        credential_id,
                        credential_version,
                        policy_hash,
                        quota["constraint_id"],
                        _operation_digest(quota["operation"]),
                        encrypted_counter_operation,
                        _OPERATION_STORAGE_VERSION,
                        now_ms,
                        quota["window_seconds"],
                        quota["max_count"],
                        now_s,
                        now_s,
                    ),
                )
                lock_suffix = (
                    " FOR UPDATE" if isinstance(conn, PostgresMetadataConnection) else ""
                )
                counter = conn.execute(
                    "SELECT * FROM rate_limit_counters WHERE counter_key = ?"
                    + lock_suffix,
                    (quota["counter_key"],),
                ).fetchone()
                if counter is None:
                    raise ReleaseAuthorizationError(
                        "shared quota counter could not be locked"
                    )
                _stored_operation(
                    counter, table_kind="rate_counter", keyring=keyring
                )
                window_start = int(counter["window_start_epoch_ms"])
                count = int(counter["count"])
                expired = now_ms >= (
                    window_start + int(counter["window_seconds"]) * 1000
                )
                if expired:
                    window_start = now_ms
                    count = 0
                if count >= quota["max_count"]:
                    raise _release_denial(
                        attempt_id=attempt_id,
                        binding_digest=binding_digest,
                        reason="shared_quota_denied",
                        retry_after_seconds=_rate_limit_retry_after(
                            window_start,
                            quota["window_seconds"],
                            now_ms,
                        ),
                    )
                prepared_counters.append(
                    {
                        **quota,
                        "window_start_epoch_ms": window_start,
                        "count_after": count + 1,
                    }
                )

            conn.execute(
                """
                INSERT INTO release_authorization_attempts (
                    attempt_id, binding_digest, binding_json, flow_id, state,
                    principal_id, route_id, credential_id, credential_version,
                    policy_hash, request_digest, operation_digest,
                    operation_context_json, grant_id, approval_request_id,
                    reservation_expires_at_epoch_ms, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, 'reserved', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    attempt_id,
                    binding_digest,
                    persisted_binding_json,
                    flow_id,
                    principal_id,
                    route_id,
                    credential_id,
                    credential_version,
                    policy_hash,
                    request_digest,
                    operation_digest,
                    operation_context_json,
                    grant["id"] if grant is not None else None,
                    grant["approval_request_id"] if grant is not None else None,
                    reservation_expires_at_ms,
                    now_s,
                    now_s,
                ),
            )
            if grant is not None:
                updated = conn.execute(
                    """
                    UPDATE approval_grants
                    SET reserved_attempt_id = ?, reserved_at_epoch_ms = ?,
                        reservation_expires_at_epoch_ms = ?
                    WHERE id = ? AND state = 'active' AND uses_remaining > 0
                      AND reserved_attempt_id IS NULL
                    """,
                    (
                        attempt_id,
                        now_ms,
                        reservation_expires_at_ms,
                        grant["id"],
                    ),
                )
                if updated.rowcount != 1:
                    raise _release_denial(
                        attempt_id=attempt_id,
                        binding_digest=binding_digest,
                        reason="jit_grant_unavailable",
                        retry_after_seconds=1,
                    )

            for quota in prepared_counters:
                conn.execute(
                    """
                    UPDATE rate_limit_counters
                    SET principal_id = ?, route_id = ?, credential_id = ?,
                        credential_version = ?, policy_hash = ?, constraint_id = ?,
                        operation = ?, encrypted_operation = ?,
                        operation_storage_version = ?, window_start_epoch_ms = ?,
                        window_seconds = ?,
                        max_count = ?, count = ?, updated_at = ?
                    WHERE counter_key = ?
                    """,
                    (
                        principal_id,
                        route_id,
                        credential_id,
                        credential_version,
                        policy_hash,
                        quota["constraint_id"],
                        _operation_digest(quota["operation"]),
                        _encrypt_operation(
                            quota["operation"],
                            table_kind="rate_counter",
                            counter_key=quota["counter_key"],
                            attempt_id=None,
                            keyring=keyring,
                        ),
                        _OPERATION_STORAGE_VERSION,
                        quota["window_start_epoch_ms"],
                        quota["window_seconds"],
                        quota["max_count"],
                        quota["count_after"],
                        now_s,
                        quota["counter_key"],
                    ),
                )
                conn.execute(
                    """
                    INSERT INTO release_authorization_quota_reservations (
                        attempt_id, counter_key, constraint_id, operation,
                        encrypted_operation, operation_storage_version,
                        window_start_epoch_ms, window_seconds, max_count,
                        count_after, reservation_state, created_at, updated_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'reserved', ?, ?)
                    """,
                    (
                        attempt_id,
                        quota["counter_key"],
                        quota["constraint_id"],
                        _operation_digest(quota["operation"]),
                        _encrypt_operation(
                            quota["operation"],
                            table_kind="quota_reservation",
                            counter_key=quota["counter_key"],
                            attempt_id=attempt_id,
                            keyring=keyring,
                        ),
                        _OPERATION_STORAGE_VERSION,
                        quota["window_start_epoch_ms"],
                        quota["window_seconds"],
                        quota["max_count"],
                        quota["count_after"],
                        now_s,
                        now_s,
                    ),
                )
            _insert_release_event(
                conn,
                attempt_id=attempt_id,
                state="reserved",
                actor_id=actor_id,
                event={
                    "attempt_id": attempt_id,
                    "binding_digest": binding_digest,
                    "principal_id": principal_id,
                    "route_id": route_id,
                    "credential_id": credential_id,
                    "credential_version": credential_version,
                    "policy_hash": policy_hash,
                    "request_digest": request_digest,
                    "operation_digest": operation_digest,
                    "grant_id": grant["id"] if grant is not None else None,
                    "quota_counter_keys": [
                        item["counter_key"] for item in prepared_counters
                    ],
                    "reservation_expires_at_epoch_ms": reservation_expires_at_ms,
                },
            )
            row = _release_attempt_row(conn, attempt_id)
            if row is None:
                raise ReleaseAuthorizationError(
                    "release authorization reservation disappeared"
                )
            return _release_authorization_result(
                conn,
                row,
                idempotent_replay=False,
                reason="reserved",
                keyring=keyring,
            )
    except _ReleaseAuthorizationDenied as denied:
        return denied.result
    except Exception as exc:
        if getattr(exc, "sqlstate", None) == "55P03":
            return {
                "authorized": False,
                "state": "denied",
                "reason": "release_authorization_busy",
                "attempt_id": attempt_id,
                "binding_digest": binding_digest,
                "idempotent_replay": False,
                "retry_after_seconds": 1,
                "release_authorization_store_backend": metadata_store_backend_name(),
                "release_authorization_store_ha": metadata_uses_postgres(),
            }
        raise


def _cancel_release_attempt(
    conn: Any,
    row: Any,
    *,
    now_ms: int,
    actor_id: str | None,
    reason: str,
) -> Any:
    attempt_id = str(row["attempt_id"])
    quotas = _release_quota_rows(conn, attempt_id)
    _lock_release_resources(
        conn, {f"quota:{item['counter_key']}" for item in quotas}
    )
    now_s = datetime.fromtimestamp(now_ms / 1000, timezone.utc).isoformat()
    for quota in quotas:
        if quota["reservation_state"] != "reserved":
            continue
        counter = conn.execute(
            "SELECT window_start_epoch_ms, count FROM rate_limit_counters "
            "WHERE counter_key = ?"
            + (" FOR UPDATE" if isinstance(conn, PostgresMetadataConnection) else ""),
            (quota["counter_key"],),
        ).fetchone()
        matching_window = (
            counter is not None
            and int(counter["window_start_epoch_ms"])
            == int(quota["window_start_epoch_ms"])
        )
        if matching_window:
            conn.execute(
                "UPDATE rate_limit_counters SET count = CASE WHEN count > 0 "
                "THEN count - 1 ELSE 0 END, updated_at = ? "
                "WHERE counter_key = ? AND window_start_epoch_ms = ?",
                (now_s, quota["counter_key"], quota["window_start_epoch_ms"]),
            )
        conn.execute(
            "UPDATE release_authorization_quota_reservations "
            "SET reservation_state = ?, updated_at = ? "
            "WHERE attempt_id = ? AND counter_key = ? "
            "AND reservation_state = 'reserved'",
            (
                "refunded" if matching_window else "refund_skipped_window",
                now_s,
                attempt_id,
                quota["counter_key"],
            ),
        )
    if row["grant_id"] is not None:
        conn.execute(
            """
            UPDATE approval_grants
            SET reserved_attempt_id = NULL, reserved_at_epoch_ms = NULL,
                reservation_expires_at_epoch_ms = NULL
            WHERE id = ? AND reserved_attempt_id = ?
            """,
            (row["grant_id"], attempt_id),
        )
    conn.execute(
        """
        UPDATE release_authorization_attempts
        SET state = 'cancelled', completion_outcome = 'not_forwarded',
            completed_at_epoch_ms = ?, updated_at = ?
        WHERE attempt_id = ? AND state = 'reserved'
        """,
        (now_ms, now_s, attempt_id),
    )
    _insert_release_event(
        conn,
        attempt_id=attempt_id,
        state="cancelled",
        actor_id=actor_id,
        event={
            "attempt_id": attempt_id,
            "binding_digest": row["binding_digest"],
            "reason": reason,
            "completed_at_epoch_ms": now_ms,
        },
    )
    return _release_attempt_row(conn, attempt_id)


def _commit_release_attempt(
    conn: Any,
    row: Any,
    *,
    now_ms: int,
    actor_id: str | None,
    outcome: str,
    indeterminate: bool,
    reason: str,
) -> Any:
    attempt_id = str(row["attempt_id"])
    now_s = datetime.fromtimestamp(now_ms / 1000, timezone.utc).isoformat()
    _validate_release_consumption_state(conn, row)
    if row["grant_id"] is not None:
        grant = conn.execute(
            "SELECT * FROM approval_grants WHERE id = ?"
            + (" FOR UPDATE" if isinstance(conn, PostgresMetadataConnection) else ""),
            (row["grant_id"],),
        ).fetchone()
        if (
            grant is None
            or grant["state"] != "active"
            or grant["reserved_attempt_id"] != attempt_id
            or int(grant["uses_remaining"]) < 1
        ):
            raise ReleaseAuthorizationError(
                "reserved JIT grant no longer matches release authorization"
            )
        uses_before = int(grant["uses_remaining"])
        uses_after = uses_before - 1
        next_state = "consumed" if uses_after == 0 else "active"
        conn.execute(
            """
            UPDATE approval_grants
            SET uses_remaining = ?, state = ?, consumed_at = ?,
                consumed_by_flow_id = ?, reserved_attempt_id = NULL,
                reserved_at_epoch_ms = NULL,
                reservation_expires_at_epoch_ms = NULL
            WHERE id = ? AND reserved_attempt_id = ?
            """,
            (
                uses_after,
                next_state,
                now_s if next_state == "consumed" else None,
                row["flow_id"] if next_state == "consumed" else None,
                grant["id"],
                attempt_id,
            ),
        )
        conn.execute(
            """
            INSERT INTO approval_grant_consumptions (
                id, grant_id, approval_request_id, attempt_id, flow_id,
                principal_id, route_id, credential_id, credential_version,
                policy_hash, request_digest, operation_digest, outcome,
                uses_remaining_before, uses_remaining_after, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'consumed', ?, ?, ?)
            """,
            (
                str(uuid.uuid4()),
                grant["id"],
                grant["approval_request_id"],
                attempt_id,
                row["flow_id"],
                row["principal_id"],
                row["route_id"],
                row["credential_id"],
                row["credential_version"],
                row["policy_hash"],
                row["request_digest"],
                row["operation_digest"],
                uses_before,
                uses_after,
                now_s,
            ),
        )
    conn.execute(
        "UPDATE release_authorization_quota_reservations "
        "SET reservation_state = 'committed', updated_at = ? "
        "WHERE attempt_id = ? AND reservation_state = 'reserved'",
        (now_s, attempt_id),
    )
    state = "committed_indeterminate" if indeterminate else "committed"
    updated = conn.execute(
        """
        UPDATE release_authorization_attempts
        SET state = ?, completion_outcome = ?, completed_at_epoch_ms = ?,
            updated_at = ?
        WHERE attempt_id = ? AND state IN ('reserved', 'dispatching')
        """,
        (state, outcome, now_ms, now_s, attempt_id),
    )
    if updated.rowcount != 1:
        raise ReleaseAuthorizationError(
            "release authorization commit lost its state transition"
        )
    _insert_release_event(
        conn,
        attempt_id=attempt_id,
        state=state,
        actor_id=actor_id,
        event={
            "attempt_id": attempt_id,
            "binding_digest": row["binding_digest"],
            "outcome": outcome,
            "reason": reason,
            "completed_at_epoch_ms": now_ms,
        },
    )
    return _release_attempt_row(conn, attempt_id)


def _bound_release_attempt(
    conn: Any, attempt_id: str, binding_digest: str
) -> Any:
    attempt_id = _release_text(
        "release authorization attempt_id",
        attempt_id,
        maximum=_RELEASE_AUTHORIZATION_ATTEMPT_ID_MAX_BYTES,
    )
    binding_digest = _release_digest(
        "release authorization binding_digest", binding_digest
    ) or ""
    _lock_release_resources(conn, {f"attempt:{attempt_id}"})
    row = _release_attempt_row(conn, attempt_id, for_update=True)
    if row is None:
        raise ReleaseAuthorizationError("release authorization attempt was not found")
    if not hmac.compare_digest(str(row["binding_digest"]), binding_digest):
        raise ReleaseAuthorizationConflictError(
            "release authorization binding does not match the durable attempt"
        )
    _validate_release_consumption_state(conn, row)
    return row


def dispatch_release_authorization(
    *,
    attempt_id: str,
    binding_digest: str,
    dispatch_ttl_seconds: int,
    now_epoch_ms: int | None = None,
    actor_id: str | None = None,
) -> dict[str, Any]:
    require_atomic_release_writer()
    if not isinstance(dispatch_ttl_seconds, int) or not 1 <= dispatch_ttl_seconds <= 300:
        raise ReleaseAuthorizationError("dispatch TTL must be between 1 and 300 seconds")
    now_ms = _release_now_epoch_ms(now_epoch_ms)
    with connect() as conn:
        _begin_release_transaction(conn)
        row = _bound_release_attempt(conn, attempt_id, binding_digest)
        if row["state"] in {"committed", "cancelled", "committed_indeterminate"}:
            return _release_authorization_result(conn, row, idempotent_replay=True)
        if row["state"] == "dispatching":
            if int(row["dispatch_expires_at_epoch_ms"] or 0) <= now_ms:
                row = _commit_release_attempt(
                    conn,
                    row,
                    now_ms=now_ms,
                    actor_id=actor_id,
                    outcome="unknown",
                    indeterminate=True,
                    reason="dispatch_ttl_expired",
                )
                return _release_authorization_result(
                    conn,
                    row,
                    idempotent_replay=True,
                    reason="dispatch_ttl_expired",
                )
            return _release_authorization_result(conn, row, idempotent_replay=True)
        if int(row["reservation_expires_at_epoch_ms"]) <= now_ms:
            row = _cancel_release_attempt(
                conn,
                row,
                now_ms=now_ms,
                actor_id=actor_id,
                reason="reservation_ttl_expired",
            )
            return _release_authorization_result(
                conn,
                row,
                idempotent_replay=False,
                reason="reservation_ttl_expired",
            )
        now_s = datetime.fromtimestamp(now_ms / 1000, timezone.utc).isoformat()
        dispatch_expires_at_ms = now_ms + dispatch_ttl_seconds * 1000
        updated = conn.execute(
            """
            UPDATE release_authorization_attempts
            SET state = 'dispatching', dispatch_started_at_epoch_ms = ?,
                dispatch_expires_at_epoch_ms = ?, updated_at = ?
            WHERE attempt_id = ? AND state = 'reserved'
            """,
            (now_ms, dispatch_expires_at_ms, now_s, attempt_id),
        )
        if updated.rowcount != 1:
            raise ReleaseAuthorizationError(
                "release authorization dispatch lost its state transition"
            )
        _insert_release_event(
            conn,
            attempt_id=attempt_id,
            state="dispatching",
            actor_id=actor_id,
            event={
                "attempt_id": attempt_id,
                "binding_digest": binding_digest,
                "dispatch_started_at_epoch_ms": now_ms,
                "dispatch_expires_at_epoch_ms": dispatch_expires_at_ms,
            },
        )
        row = _release_attempt_row(conn, attempt_id)
        return _release_authorization_result(
            conn, row, idempotent_replay=False, reason="dispatching"
        )


def complete_release_authorization(
    *,
    attempt_id: str,
    binding_digest: str,
    outcome: str,
    now_epoch_ms: int | None = None,
    actor_id: str | None = None,
) -> dict[str, Any]:
    require_atomic_release_writer()
    if outcome not in {"forwarded", "not_forwarded", "unknown"}:
        raise ReleaseAuthorizationError(
            "release authorization outcome must be forwarded, not_forwarded, or unknown"
        )
    now_ms = _release_now_epoch_ms(now_epoch_ms)
    with connect() as conn:
        _begin_release_transaction(conn)
        row = _bound_release_attempt(conn, attempt_id, binding_digest)
        if row["state"] in {"committed", "cancelled", "committed_indeterminate"}:
            return _release_authorization_result(conn, row, idempotent_replay=True)
        if row["state"] == "reserved" and outcome == "not_forwarded":
            row = _cancel_release_attempt(
                conn,
                row,
                now_ms=now_ms,
                actor_id=actor_id,
                reason="confirmed_not_forwarded_before_dispatch",
            )
            return _release_authorization_result(
                conn, row, idempotent_replay=False, reason="cancelled"
            )
        dispatch_stale = (
            row["state"] == "dispatching"
            and int(row["dispatch_expires_at_epoch_ms"] or 0) <= now_ms
        )
        indeterminate = (
            row["state"] != "dispatching"
            or outcome != "forwarded"
            or dispatch_stale
        )
        reason = (
            "dispatch_ttl_expired"
            if dispatch_stale
            else "forward_outcome_indeterminate"
            if indeterminate
            else "forwarded"
        )
        row = _commit_release_attempt(
            conn,
            row,
            now_ms=now_ms,
            actor_id=actor_id,
            outcome=outcome,
            indeterminate=indeterminate,
            reason=reason,
        )
        return _release_authorization_result(
            conn, row, idempotent_replay=False, reason=reason
        )


def reconcile_release_authorizations(
    *,
    limit: int = 100,
    now_epoch_ms: int | None = None,
    actor_id: str | None = "release-authorization-reconciler",
) -> dict[str, Any]:
    require_atomic_release_writer()
    if not isinstance(limit, int) or not 1 <= limit <= 500:
        raise ReleaseAuthorizationError("reconciliation limit must be between 1 and 500")
    now_ms = _release_now_epoch_ms(now_epoch_ms)
    with connect() as conn:
        _begin_release_transaction(conn)
        suffix = (
            " FOR UPDATE SKIP LOCKED"
            if isinstance(conn, PostgresMetadataConnection)
            else ""
        )
        rows = conn.execute(
            """
            SELECT * FROM release_authorization_attempts
            WHERE (state = 'reserved' AND reservation_expires_at_epoch_ms <= ?)
               OR (state = 'dispatching' AND dispatch_expires_at_epoch_ms <= ?)
            ORDER BY CASE WHEN state = 'dispatching' THEN dispatch_expires_at_epoch_ms
                          ELSE reservation_expires_at_epoch_ms END ASC,
                     attempt_id ASC
            LIMIT ?
            """
            + suffix,
            (now_ms, now_ms, limit),
        ).fetchall()
        cancelled = 0
        indeterminate = 0
        attempt_ids: list[str] = []
        for row in rows:
            attempt_ids.append(str(row["attempt_id"]))
            if row["state"] == "reserved":
                _cancel_release_attempt(
                    conn,
                    row,
                    now_ms=now_ms,
                    actor_id=actor_id,
                    reason="reservation_ttl_expired",
                )
                cancelled += 1
            else:
                _commit_release_attempt(
                    conn,
                    row,
                    now_ms=now_ms,
                    actor_id=actor_id,
                    outcome="unknown",
                    indeterminate=True,
                    reason="dispatch_ttl_expired",
                )
                indeterminate += 1
    return {
        "ok": True,
        "processed": len(attempt_ids),
        "cancelled": cancelled,
        "committed_indeterminate": indeterminate,
        "attempt_ids": attempt_ids,
        "limit": limit,
    }


def _mark_release_authorization_audit_delivery(
    kind: str, row_id: str, event_hash: str
) -> int:
    if kind == "grant_consumption":
        table = "approval_grant_consumptions"
    elif kind == "lifecycle":
        table = "release_authorization_events"
    else:
        raise ReleaseAuthorizationError("unknown release authorization outbox kind")
    with connect() as conn:
        updated = conn.execute(
            f"UPDATE {table} SET audited_at = ?, audit_event_hash = ? "
            "WHERE id = ? AND audited_at IS NULL",
            (iso_now(), event_hash, row_id),
        )
    return int(updated.rowcount or 0)


def _atomic_grant_consumption_audit_event(row: Any) -> dict[str, Any]:
    return {
        "grant_id": row["grant_id"],
        "approval_id": row["approval_request_id"],
        "approval_request_id": row["approval_request_id"],
        "flow_id": row["flow_id"],
        "attempt_id": row["attempt_id"],
        "principal_id": row["principal_id"],
        "route_id": row["route_id"],
        "credential_id": row["credential_id"],
        "credential_version": int(row["credential_version"]),
        "policy_hash": row["policy_hash"],
        "request_digest": row["request_digest"],
        "operation_digest": row["operation_digest"],
        "consume_result": "consumed",
        "uses_remaining_before": int(row["uses_remaining_before"]),
        "uses_remaining_after": int(row["uses_remaining_after"]),
        "grant_store_backend": metadata_store_backend_name(),
        "consumption_id": row["id"],
        "atomic_release_authorization": True,
    }


def drain_release_authorization_audit_outbox(limit: int = 100) -> dict[str, Any]:
    if not isinstance(limit, int) or not 1 <= limit <= 500:
        raise ReleaseAuthorizationError("audit outbox limit must be between 1 and 500")
    with connect() as conn:
        grant_rows = list(
            conn.execute(
                "SELECT consumption.* FROM approval_grant_consumptions AS consumption "
                "INNER JOIN release_authorization_attempts AS attempt "
                "ON attempt.attempt_id = consumption.attempt_id "
                "WHERE consumption.audited_at IS NULL "
                "ORDER BY consumption.created_at ASC, consumption.id ASC LIMIT ?",
                (limit,),
            ).fetchall()
        )
        lifecycle_rows = list(
            conn.execute(
                "SELECT * FROM release_authorization_events "
                "WHERE audited_at IS NULL ORDER BY created_at ASC, id ASC LIMIT ?",
                (limit,),
            ).fetchall()
        )
    rows = [("grant_consumption", row) for row in grant_rows] + [
        ("lifecycle", row) for row in lifecycle_rows
    ]
    rows.sort(
        key=lambda item: (
            str(item[1]["created_at"]),
            str(item[1]["id"]),
            item[0],
        )
    )
    rows = rows[:limit]
    completed = 0
    completed_by_kind = {"grant_consumption": 0, "lifecycle": 0}
    for kind, row in rows:
        if kind == "grant_consumption":
            audit_event = record_audit_event(
                "jit.grant.consumed",
                _atomic_grant_consumption_audit_event(row),
                actor_type="proxy",
                actor_id=str(row["route_id"]),
                idempotency_key=str(row["id"]),
            )
        else:
            audit_event = record_audit_event(
                str(row["event_type"]),
                loads(row["event_json"], {}),
                actor_type="data-plane",
                actor_id=str(row["actor_id"] or "release-authorization"),
                idempotency_key=str(row["id"]),
            )
        marked = _mark_release_authorization_audit_delivery(
            kind, str(row["id"]), str(audit_event["event_hash"])
        )
        completed += marked
        completed_by_kind[kind] += marked
    return {
        "ok": True,
        "claimed": len(rows),
        "completed": completed,
        "pending": max(len(rows) - completed, 0),
        "grant_consumptions_completed": completed_by_kind["grant_consumption"],
        "lifecycle_events_completed": completed_by_kind["lifecycle"],
    }


def deny_request(
    item_id: str, note: str | None = None, actor_id: str = "admin"
) -> dict[str, Any] | None:
    with connect() as conn:
        existing = conn.execute(
            "SELECT * FROM approval_requests WHERE id = ?", (item_id,)
        ).fetchone()
        if not existing:
            return None
        now_s = iso_now()
        if existing["status"] != "pending" or existing["expires_at"] <= now_s:
            return None
        cur = conn.execute(
            """
            UPDATE approval_requests
            SET status = 'denied', decision_note = ?
            WHERE id = ? AND status = 'pending' AND expires_at > ?
            """,
            (note, item_id, now_s),
        )
        if cur.rowcount != 1:
            return None
        if existing:
            append_audit_event(
                conn,
                event_type="approval.denied",
                actor_type="admin",
                actor_id=actor_id,
                event={
                    "approval_request_id": item_id,
                    "route_id": existing["route_id"],
                    "principal_id": existing["principal_id"],
                    "credential_id": existing["credential_id"],
                    "credential_version": existing["credential_version"],
                    "policy_hash": existing["policy_hash"],
                    "request_digest": existing["request_digest"],
                    "operation_digest": existing["operation_digest"],
                    "note": note,
                },
            )
        row = conn.execute(
            "SELECT * FROM approval_requests WHERE id = ?", (item_id,)
        ).fetchone()
    return row_to_approval(row) if row else None


def list_approvals(status: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
    args: list[Any] = []
    where = ""
    if status:
        where = "WHERE status = ?"
        args.append(status)
    args.append(limit)
    with connect() as conn:
        rows = conn.execute(
            f"SELECT * FROM approval_requests {where} ORDER BY requested_at DESC LIMIT ?",
            args,
        ).fetchall()
    return [row_to_approval(row) for row in rows]


def list_similar_approvals(
    approval: dict[str, Any], limit: int = 5
) -> list[dict[str, Any]]:
    args: list[Any] = [approval["id"]]
    clauses = ["id <> ?"]
    for field in ("principal_id", "route_id", "credential_id", "policy_hash"):
        value = approval.get(field)
        if value is not None:
            clauses.append(f"{field} = ?")
            args.append(value)
    args.append(limit)
    with connect() as conn:
        rows = conn.execute(
            f"""
            SELECT * FROM approval_requests
            WHERE {" AND ".join(clauses)}
            ORDER BY requested_at DESC
            LIMIT ?
            """,
            args,
        ).fetchall()
    return [row_to_approval(row) for row in rows]


def _row_to_webauthn_trust_publication(row: Any) -> dict[str, Any]:
    return {
        "id": str(row["id"]),
        "previous_bundle_digest": row["previous_bundle_digest"],
        "bundle_digest": str(row["bundle_digest"]),
        "sequence": int(row["sequence"]),
        "rollback_epoch": int(row["rollback_epoch"]),
        "signing_key_id": str(row["signing_key_id"]),
        "bundle": loads(row["bundle_json"], {}),
        "payload_digest": str(row["payload_digest"]),
        "actor_id": str(row["actor_id"]),
        "withdrawn_credential_ids": loads(
            row["withdrawn_credential_ids_json"], []
        ),
        "audit_event": loads(row["audit_event_json"], {}),
        "status": str(row["status"]),
        "attempts": int(row["attempts"] or 0),
        "last_error": row["last_error"],
        "created_at": str(row["created_at"]),
        "published_at": row["published_at"],
    }


def stage_webauthn_trust_publication(
    *,
    previous_bundle_digest: str | None,
    bundle_digest: str,
    sequence: int,
    rollback_epoch: int,
    signing_key_id: str,
    bundle: dict[str, Any],
    payload_digest: str,
    actor_id: str,
    withdrawn_credential_ids: list[str],
    audit_event: dict[str, Any],
    _connection: Any,
) -> dict[str, Any]:
    conn = _connection
    _lock_webauthn_authority(conn)
    bundle_json = dumps(bundle)
    event_json = dumps(audit_event)
    _validate_audit_event_json(event_json)
    if len(bundle_json.encode("utf-8")) > _AUDIT_EVENT_JSON_WRITE_MAX_BYTES:
        raise MetadataStoreError("WebAuthn trust publication bundle exceeds 2 MiB")
    existing = conn.execute(
        "SELECT * FROM webauthn_trust_publications WHERE bundle_digest = ?",
        (bundle_digest,),
    ).fetchone()
    if existing is not None:
        if (
            existing["bundle_json"] != bundle_json
            or int(existing["sequence"]) != sequence
            or int(existing["rollback_epoch"]) != rollback_epoch
        ):
            raise MetadataStoreError("WebAuthn trust publication digest was reused")
        return _row_to_webauthn_trust_publication(existing)
    pending = conn.execute(
        "SELECT id FROM webauthn_trust_publications WHERE status = 'pending' LIMIT 1"
    ).fetchone()
    if pending is not None:
        raise MetadataStoreError("a WebAuthn trust publication is already pending")
    latest = conn.execute(
        """
        SELECT rollback_epoch, sequence, bundle_digest
        FROM webauthn_trust_publications
        ORDER BY rollback_epoch DESC, sequence DESC
        LIMIT 1
        """
    ).fetchone()
    if latest is not None and (
        rollback_epoch < int(latest["rollback_epoch"])
        or (
            rollback_epoch == int(latest["rollback_epoch"])
            and sequence <= int(latest["sequence"])
        )
    ):
        raise MetadataStoreError("WebAuthn trust publication is not monotonic")
    publication_id = str(uuid.uuid4())
    created_at = _metadata_utcnow(conn).isoformat()
    conn.execute(
        """
        INSERT INTO webauthn_trust_publications (
            id, scope, previous_bundle_digest, bundle_digest, sequence,
            rollback_epoch, signing_key_id, bundle_json, payload_digest,
            actor_id, withdrawn_credential_ids_json, audit_event_json,
            status, created_at
        )
        VALUES (?, 'global', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?)
        """,
        (
            publication_id,
            previous_bundle_digest,
            bundle_digest,
            sequence,
            rollback_epoch,
            signing_key_id,
            bundle_json,
            payload_digest,
            actor_id,
            dumps(sorted(withdrawn_credential_ids)),
            event_json,
            created_at,
        ),
    )
    row = conn.execute(
        "SELECT * FROM webauthn_trust_publications WHERE id = ?",
        (publication_id,),
    ).fetchone()
    return _row_to_webauthn_trust_publication(row)


def get_pending_webauthn_trust_publication() -> dict[str, Any] | None:
    with connect() as conn:
        row = conn.execute(
            """
            SELECT * FROM webauthn_trust_publications
            WHERE status = 'pending'
            ORDER BY created_at ASC
            LIMIT 1
            """
        ).fetchone()
    return _row_to_webauthn_trust_publication(row) if row else None


def record_webauthn_trust_publication_error(
    publication_id: str, error: str
) -> None:
    with connect() as conn:
        _lock_webauthn_authority(conn)
        conn.execute(
            """
            UPDATE webauthn_trust_publications
            SET attempts = attempts + 1, last_error = ?
            WHERE id = ? AND status = 'pending'
            """,
            (str(error)[:2048], publication_id),
        )


def complete_webauthn_trust_publication(
    publication_id: str,
) -> dict[str, Any]:
    with connect() as conn:
        _lock_webauthn_authority(conn)
        row = conn.execute(
            "SELECT * FROM webauthn_trust_publications WHERE id = ?",
            (publication_id,),
        ).fetchone()
        if row is None:
            raise MetadataStoreError("WebAuthn trust publication was not found")
        if row["status"] == "published":
            return _row_to_webauthn_trust_publication(row)
        now_s = _metadata_utcnow(conn).isoformat()
        updated = conn.execute(
            """
            UPDATE webauthn_trust_publications
            SET status = 'published', published_at = ?, last_error = NULL
            WHERE id = ? AND status = 'pending'
            """,
            (now_s, publication_id),
        )
        if updated.rowcount != 1:
            raise MetadataStoreError("WebAuthn trust publication state changed")
        append_audit_event(
            conn,
            event_type="webauthn.trust_bundle.published",
            actor_type="admin",
            actor_id=row["actor_id"],
            event=loads(row["audit_event_json"], {}),
            idempotency_key=f"webauthn-trust:{publication_id}",
        )
        published = conn.execute(
            "SELECT * FROM webauthn_trust_publications WHERE id = ?",
            (publication_id,),
        ).fetchone()
    return _row_to_webauthn_trust_publication(published)


def row_to_webauthn_credential(row: sqlite3.Row) -> dict[str, Any]:
    item = dict(row)
    item["transports"] = loads(item.get("transports"), [])
    item["attestation_trusted"] = bool(item.get("attestation_trusted"))
    item["attestation_trust_path"] = loads(item.get("attestation_trust_path"), [])
    return item


def _insert_webauthn_credential(
    conn: Any,
    *,
    item_id: str,
    now_s: str,
    credential_id: str,
    user_id: str,
    label: str,
    public_key_cose: str,
    sign_count: int,
    aaguid: str | None,
    authenticator_class: str,
    attestation_fmt: str | None,
    attestation_trusted: bool,
    attestation_trust_path: list[str] | None,
    attestation_leaf_sha256: str | None,
    attestation_root_sha256: str | None,
    attestation_trust_bundle_digest: str | None,
    attestation_trust_bundle_sequence: int | None,
    attestation_verified_at: str | None,
    transports: list[str] | None,
    dev_private_key_pem: str | None,
) -> dict[str, Any]:
    existing = conn.execute(
        "SELECT id FROM webauthn_credentials WHERE credential_id = ?",
        (credential_id,),
    ).fetchone()
    if existing is not None:
        raise ValueError(
            "WebAuthn credential ID was already registered and cannot be reused"
        )
    conn.execute(
        """
        INSERT INTO webauthn_credentials (
            id, credential_id, user_id, label, public_key_cose, sign_count,
            aaguid, authenticator_class, attestation_fmt, attestation_trusted,
            attestation_trust_path, attestation_leaf_sha256, attestation_root_sha256,
            attestation_trust_bundle_digest, attestation_trust_bundle_sequence,
            attestation_verified_at, transports, dev_private_key_pem,
            created_at, updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            item_id,
            credential_id,
            user_id,
            label,
            public_key_cose,
            sign_count,
            aaguid,
            authenticator_class,
            attestation_fmt,
            1 if attestation_trusted else 0,
            dumps(attestation_trust_path or []),
            attestation_leaf_sha256,
            attestation_root_sha256,
            attestation_trust_bundle_digest,
            attestation_trust_bundle_sequence,
            attestation_verified_at,
            dumps(transports or []),
            dev_private_key_pem,
            now_s,
            now_s,
        ),
    )
    row = conn.execute(
        "SELECT * FROM webauthn_credentials WHERE credential_id = ?",
        (credential_id,),
    ).fetchone()
    return row_to_webauthn_credential(row)


def create_webauthn_credential(
    *,
    credential_id: str,
    user_id: str,
    label: str,
    public_key_cose: str,
    sign_count: int,
    aaguid: str | None,
    authenticator_class: str,
    attestation_fmt: str | None = None,
    attestation_trusted: bool = False,
    attestation_trust_path: list[str] | None = None,
    attestation_leaf_sha256: str | None = None,
    attestation_root_sha256: str | None = None,
    attestation_trust_bundle_digest: str | None = None,
    attestation_trust_bundle_sequence: int | None = None,
    attestation_verified_at: str | None = None,
    transports: list[str] | None = None,
    dev_private_key_pem: str | None = None,
) -> dict[str, Any]:
    item_id = str(uuid.uuid4())
    with connect() as conn:
        _lock_webauthn_authority(conn)
        now_s = _metadata_utcnow(conn).isoformat()
        stored = _insert_webauthn_credential(
            conn,
            item_id=item_id,
            now_s=now_s,
            credential_id=credential_id,
            user_id=user_id,
            label=label,
            public_key_cose=public_key_cose,
            sign_count=sign_count,
            aaguid=aaguid,
            authenticator_class=authenticator_class,
            attestation_fmt=attestation_fmt,
            attestation_trusted=attestation_trusted,
            attestation_trust_path=attestation_trust_path,
            attestation_leaf_sha256=attestation_leaf_sha256,
            attestation_root_sha256=attestation_root_sha256,
            attestation_trust_bundle_digest=attestation_trust_bundle_digest,
            attestation_trust_bundle_sequence=attestation_trust_bundle_sequence,
            attestation_verified_at=attestation_verified_at,
            transports=transports,
            dev_private_key_pem=dev_private_key_pem,
        )
        if dev_private_key_pem is not None:
            append_audit_event(
                conn,
                event_type="webauthn.dev_credential_created",
                actor_type="admin",
                actor_id=user_id,
                event={"user_id": user_id, "credential_id": credential_id},
            )
        return stored


def finalize_webauthn_registration(
    *,
    challenge: str,
    user_id: str,
    credential_id: str,
    label: str,
    public_key_cose: str,
    sign_count: int,
    aaguid: str | None,
    authenticator_class: str,
    attestation_fmt: str | None = None,
    attestation_trusted: bool = False,
    attestation_trust_path: list[str] | None = None,
    attestation_leaf_sha256: str | None = None,
    attestation_root_sha256: str | None = None,
    attestation_trust_bundle_digest: str | None = None,
    attestation_trust_bundle_sequence: int | None = None,
    attestation_verified_at: str | None = None,
    transports: list[str] | None = None,
) -> dict[str, Any] | None:
    item_id = str(uuid.uuid4())
    with connect() as conn:
        _lock_webauthn_authority(conn)
        now_s = _metadata_utcnow(conn).isoformat()
        challenge_row = conn.execute(
            """
            SELECT * FROM webauthn_challenges
            WHERE challenge = ?
              AND challenge_type = 'registration'
              AND user_id = ?
              AND approval_request_id IS NULL
              AND used_at IS NULL
              AND expires_at > ?
            """,
            (challenge, user_id, now_s),
        ).fetchone()
        if challenge_row is None:
            return None
        challenge_payload = loads(challenge_row["payload_json"], {})
        authorization = (
            challenge_payload.get("authorization")
            if isinstance(challenge_payload, dict)
            else None
        )
        first_oidc_enrollment = (
            isinstance(authorization, dict)
            and authorization.get("mode") == "oidc-session-first-enrollment"
        )
        if first_oidc_enrollment:
            authorization_session_id = authorization.get("session_id")
            authorization_user_id = authorization.get("user_id")
            authorization_pending_expires_at = authorization.get(
                "pending_expires_at"
            )
            if (
                challenge_payload.get("type") != "registration"
                or challenge_payload.get("user_id") != user_id
                or challenge_payload.get("label") != label
                or not isinstance(authorization_session_id, str)
                or not authorization_session_id
                or authorization_user_id != challenge_payload.get("user_id")
                or authorization_user_id != user_id
                or not isinstance(authorization_pending_expires_at, str)
                or authorization.get("existing_credential_count") != 0
                or re.fullmatch(
                    r"sha256:[0-9a-f]{64}",
                    str(authorization.get("payload_digest") or ""),
                )
                is None
            ):
                raise ValueError(
                    "OIDC first-enrollment registration authorization is invalid"
                )
            authorized_session = conn.execute(
                """
                SELECT id
                FROM oidc_browser_sessions
                WHERE id = ?
                  AND user_id = ?
                  AND status = 'pending_webauthn'
                  AND pending_expires_at = ?
                  AND expires_at > ?
                  AND pending_expires_at > ?
                """,
                (
                    authorization_session_id,
                    authorization_user_id,
                    authorization_pending_expires_at,
                    now_s,
                    now_s,
                ),
            ).fetchone()
            if authorized_session is None:
                raise ValueError(
                    "OIDC first-enrollment registration session is invalid or expired"
                )
            credential_history = conn.execute(
                "SELECT 1 FROM webauthn_credentials WHERE user_id = ? LIMIT 1",
                (user_id,),
            ).fetchone()
            if credential_history is not None:
                raise ValueError(
                    "OIDC first enrollment is closed because credential history exists"
                )
        consumed = conn.execute(
            """
            UPDATE webauthn_challenges
            SET used_at = ?
            WHERE id = ? AND used_at IS NULL AND expires_at > ?
            """,
            (now_s, challenge_row["id"], now_s),
        )
        if consumed.rowcount != 1:
            return None
        credential = _insert_webauthn_credential(
            conn,
            item_id=item_id,
            now_s=now_s,
            credential_id=credential_id,
            user_id=user_id,
            label=label,
            public_key_cose=public_key_cose,
            sign_count=sign_count,
            aaguid=aaguid,
            authenticator_class=authenticator_class,
            attestation_fmt=attestation_fmt,
            attestation_trusted=attestation_trusted,
            attestation_trust_path=attestation_trust_path,
            attestation_leaf_sha256=attestation_leaf_sha256,
            attestation_root_sha256=attestation_root_sha256,
            attestation_trust_bundle_digest=attestation_trust_bundle_digest,
            attestation_trust_bundle_sequence=attestation_trust_bundle_sequence,
            attestation_verified_at=attestation_verified_at,
            transports=transports,
            dev_private_key_pem=None,
        )
        invalidated_sibling_challenge_count = 0
        if first_oidc_enrollment:
            invalidated_siblings = conn.execute(
                """
                UPDATE webauthn_challenges
                SET used_at = ?
                WHERE challenge_type = 'registration'
                  AND user_id = ?
                  AND id != ?
                  AND used_at IS NULL
                  AND expires_at > ?
                """,
                (now_s, user_id, challenge_row["id"], now_s),
            )
            invalidated_sibling_challenge_count = invalidated_siblings.rowcount
        append_audit_event(
            conn,
            event_type="webauthn.credential_registered",
            actor_type="admin",
            actor_id=user_id,
            event={
                "user_id": user_id,
                "credential_id": credential_id,
                "authenticator_class": authenticator_class,
                "aaguid": aaguid,
                "attestation_fmt": attestation_fmt,
                "attestation_trusted": attestation_trusted,
                "attestation_root_sha256": attestation_root_sha256,
                "registration_authorization": challenge_payload.get("authorization"),
                **(
                    {
                        "invalidated_sibling_registration_challenge_count": (
                            invalidated_sibling_challenge_count
                        )
                    }
                    if first_oidc_enrollment
                    else {}
                ),
            },
        )
        claimed = conn.execute(
            "SELECT * FROM webauthn_challenges WHERE id = ?",
            (challenge_row["id"],),
        ).fetchone()
        result = {
            "challenge": row_to_webauthn_challenge(claimed),
            "credential": credential,
        }
        if first_oidc_enrollment:
            result["invalidated_sibling_registration_challenge_count"] = (
                invalidated_sibling_challenge_count
            )
        return result


def get_webauthn_credential(
    credential_id: str, *, include_revoked: bool = False
) -> dict[str, Any] | None:
    revoked_clause = "" if include_revoked else " AND revoked_at IS NULL"
    with connect() as conn:
        row = conn.execute(
            "SELECT * FROM webauthn_credentials WHERE credential_id = ?"
            + revoked_clause,
            (credential_id,),
        ).fetchone()
    return row_to_webauthn_credential(row) if row else None


def get_webauthn_credential_by_record_id(
    record_id: str, *, include_revoked: bool = False
) -> dict[str, Any] | None:
    where = "id = ?" if include_revoked else "id = ? AND revoked_at IS NULL"
    with connect() as conn:
        row = conn.execute(
            f"SELECT * FROM webauthn_credentials WHERE {where}", (record_id,)
        ).fetchone()
    return row_to_webauthn_credential(row) if row else None


def list_webauthn_credentials(
    user_id: str | None = None,
    *,
    include_revoked: bool = False,
    limit: int | None = None,
) -> list[dict[str, Any]]:
    args: list[Any] = []
    clauses: list[str] = []
    if not include_revoked:
        clauses.append("revoked_at IS NULL")
    if user_id:
        clauses.append("user_id = ?")
        args.append(user_id)
    if limit is not None and (
        isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100_000
    ):
        raise MetadataStoreError("WebAuthn credential list limit is invalid")
    where = "WHERE " + " AND ".join(clauses) if clauses else ""
    limit_clause = " LIMIT ?" if limit is not None else ""
    if limit is not None:
        args.append(limit)
    with connect() as conn:
        rows = conn.execute(
            f"SELECT * FROM webauthn_credentials {where} "
            f"ORDER BY created_at DESC{limit_clause}",
            args,
        ).fetchall()
    return [row_to_webauthn_credential(row) for row in rows]


def _webauthn_recovery_digest(label: str, value: str) -> str:
    if re.fullmatch(r"sha256:[0-9a-f]{64}", value or "") is None:
        raise WebAuthnRecoveryError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _webauthn_credential_history_snapshot(
    conn: Any, user_id: str
) -> dict[str, Any]:
    rows = conn.execute(
        "SELECT * FROM webauthn_credentials WHERE user_id = ? "
        "ORDER BY created_at ASC, id ASC LIMIT ?",
        (user_id, WEBAUTHN_RECOVERY_CREDENTIAL_HISTORY_MAX_COUNT + 1),
    ).fetchall()
    if len(rows) > WEBAUTHN_RECOVERY_CREDENTIAL_HISTORY_MAX_COUNT:
        raise WebAuthnRecoveryError(
            "WebAuthn credential history count exceeds the recovery limit"
        )
    history: list[dict[str, Any]] = []
    active_count = 0
    for row in rows:
        if row["revoked_at"] is None:
            active_count += 1
        history.append(
            {
                "record_id": str(row["id"]),
                "credential_id_digest": "sha256:"
                + hashlib.sha256(str(row["credential_id"]).encode("utf-8")).hexdigest(),
                "public_key_cose_digest": "sha256:"
                + hashlib.sha256(str(row["public_key_cose"]).encode("ascii")).hexdigest(),
                "sign_count": int(row["sign_count"]),
                "aaguid": row["aaguid"],
                "authenticator_class": str(row["authenticator_class"]),
                "attestation_fmt": row["attestation_fmt"],
                "attestation_trusted": bool(row["attestation_trusted"]),
                "attestation_trust_path": loads(
                    row["attestation_trust_path"], []
                ),
                "attestation_leaf_sha256": row["attestation_leaf_sha256"],
                "attestation_root_sha256": row["attestation_root_sha256"],
                "attestation_trust_bundle_digest": row[
                    "attestation_trust_bundle_digest"
                ],
                "attestation_trust_bundle_sequence": row[
                    "attestation_trust_bundle_sequence"
                ],
                "attestation_verified_at": row["attestation_verified_at"],
                "transports": loads(row["transports"], []),
                "development_material_digest": (
                    "sha256:"
                    + hashlib.sha256(
                        str(row["dev_private_key_pem"]).encode("utf-8")
                    ).hexdigest()
                    if row["dev_private_key_pem"] is not None
                    else None
                ),
                "created_at": str(row["created_at"]),
                "updated_at": str(row["updated_at"]),
                "last_used_at": row["last_used_at"],
                "revoked_at": row["revoked_at"],
                "revoked_by": row["revoked_by"],
                "revocation_reason": row["revocation_reason"],
                "revocation_source": row["revocation_source"],
            }
        )
    canonical = dumps(history)
    if len(canonical.encode("utf-8")) > WEBAUTHN_RECOVERY_CREDENTIAL_HISTORY_MAX_BYTES:
        raise WebAuthnRecoveryError(
            "WebAuthn credential history size exceeds the recovery limit"
        )
    return {
        "digest": "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
        "count": len(history),
        "active_count": active_count,
    }


def _row_to_webauthn_recovery(row: Any) -> dict[str, Any]:
    item = dict(row)
    item["roles"] = loads(item.pop("roles_json"), [])
    item["candidate"] = loads(item.pop("candidate_json"), None)
    item["statement"] = loads(item.pop("statement_json"), None)
    for field in (
        "credential_history_count",
        "active_credential_count",
        "trust_bundle_sequence",
        "trust_bundle_rollback_epoch",
        "root_sequence",
    ):
        if item.get(field) is not None:
            item[field] = int(item[field])
    return item


def get_webauthn_recovery_ceremony(recovery_id: str) -> dict[str, Any] | None:
    with connect() as conn:
        row = conn.execute(
            "SELECT * FROM webauthn_recovery_ceremonies WHERE id = ?",
            (recovery_id,),
        ).fetchone()
    return _row_to_webauthn_recovery(row) if row else None


def invalidate_witnessed_webauthn_recovery(
    *,
    recovery_id: str,
    ceremony_type: str,
    authorization: dict[str, Any],
    authorization_digest: str,
    signature_digest: str,
) -> None:
    authorization_json = dumps(authorization)
    with connect() as conn:
        _lock_webauthn_authority(conn)
        now_s = _metadata_utcnow(conn).isoformat()
        if ceremony_type == "replacement-registration":
            row = conn.execute(
                "SELECT user_id, challenge_id FROM webauthn_recovery_ceremonies "
                "WHERE id = ? AND status IN ('pending_candidate', 'prepared')",
                (recovery_id,),
            ).fetchone()
            if row is None:
                return
            conn.execute(
                "UPDATE webauthn_challenges SET used_at = COALESCE(used_at, ?) "
                "WHERE id = ?",
                (now_s, row["challenge_id"]),
            )
            updated = conn.execute(
                "UPDATE webauthn_recovery_ceremonies SET status = 'invalidated', "
                "authorization_json = ?, authorization_digest = ?, "
                "signature_digest = ?, invalidated_at = ? "
                "WHERE id = ? AND status IN ('pending_candidate', 'prepared')",
                (
                    authorization_json,
                    authorization_digest,
                    signature_digest,
                    now_s,
                    recovery_id,
                ),
            )
            user_id = str(row["user_id"])
        elif ceremony_type == "lost-active-key-decommission":
            row = conn.execute(
                "SELECT user_id FROM webauthn_recovery_revocations "
                "WHERE id = ? AND status = 'prepared'",
                (recovery_id,),
            ).fetchone()
            if row is None:
                return
            updated = conn.execute(
                "UPDATE webauthn_recovery_revocations SET status = 'expired', "
                "authorization_json = ?, authorization_digest = ?, "
                "signature_digest = ?, consumed_at = ? "
                "WHERE id = ? AND status = 'prepared'",
                (
                    authorization_json,
                    authorization_digest,
                    signature_digest,
                    now_s,
                    recovery_id,
                ),
            )
            user_id = str(row["user_id"])
        else:
            raise WebAuthnRecoveryError("recovery witness ceremony type is invalid")
        if updated.rowcount != 1:
            return
        append_audit_event(
            conn,
            event_type="webauthn.recovery.authorization_burned",
            actor_type="system",
            actor_id=user_id,
            event={
                "recovery_id": recovery_id,
                "ceremony_type": ceremony_type,
                "authorization_digest": authorization_digest,
                "signature_digest": signature_digest,
                "witness_claim_preserved": True,
            },
            idempotency_key=f"webauthn-recovery-burned:{recovery_id}",
        )


def _expire_webauthn_recovery_ceremonies(conn: Any, now_s: str) -> int:
    rows = conn.execute(
        "SELECT id, challenge_id FROM webauthn_recovery_ceremonies "
        "WHERE status IN ('pending_candidate', 'prepared') AND expires_at <= ?",
        (now_s,),
    ).fetchall()
    for row in rows:
        conn.execute(
            "UPDATE webauthn_challenges SET used_at = COALESCE(used_at, ?) WHERE id = ?",
            (now_s, row["challenge_id"]),
        )
    if rows:
        conn.execute(
            "UPDATE webauthn_recovery_ceremonies "
            "SET status = 'expired', invalidated_at = ? "
            "WHERE status IN ('pending_candidate', 'prepared') AND expires_at <= ?",
            (now_s, now_s),
        )
    return len(rows)


def _prune_webauthn_recovery_terminal(conn: Any, now: datetime) -> int:
    cutoff = (
        now - timedelta(seconds=WEBAUTHN_RECOVERY_TERMINAL_RETENTION_SECONDS)
    ).isoformat()
    deleted = 0
    for table, terminal_time in (
        (
            "webauthn_recovery_ceremonies",
            "COALESCE(consumed_at, invalidated_at, expires_at)",
        ),
        (
            "webauthn_recovery_revocations",
            "COALESCE(consumed_at, expires_at)",
        ),
    ):
        removed_old = conn.execute(
            f"DELETE FROM {table} WHERE status IN ('consumed', 'expired', 'invalidated') "
            f"AND {terminal_time} <= ?",
            (cutoff,),
        )
        removed_overflow = conn.execute(
            f"DELETE FROM {table} WHERE id IN ("
            f"SELECT id FROM (SELECT id, ROW_NUMBER() OVER ("
            f"ORDER BY {terminal_time} DESC, id DESC) AS ordinal FROM {table} "
            "WHERE status IN ('consumed', 'expired', 'invalidated')) AS ranked "
            "WHERE ordinal > ?)",
            (WEBAUTHN_RECOVERY_MAX_RETAINED,),
        )
        deleted += max(0, int(removed_old.rowcount))
        deleted += max(0, int(removed_overflow.rowcount))
    return deleted


def expire_webauthn_recovery_ceremonies() -> int:
    with connect() as conn:
        _lock_webauthn_authority(conn)
        return _expire_webauthn_recovery_ceremonies(
            conn, _metadata_utcnow(conn).isoformat()
        )


def _webauthn_recovery_live_count(conn: Any, now_s: str) -> int:
    row = conn.execute(
        "SELECT ("
        "(SELECT COUNT(*) FROM webauthn_recovery_ceremonies "
        "WHERE status IN ('pending_candidate', 'prepared') AND expires_at > ?) + "
        "(SELECT COUNT(*) FROM webauthn_recovery_revocations "
        "WHERE status = 'prepared' AND expires_at > ?)"
        ") AS count",
        (now_s, now_s),
    ).fetchone()
    return int(row["count"] if row else 0)


def create_webauthn_recovery_ceremony(
    *,
    recovery_id: str,
    nonce: str,
    pending_token_digest: str,
    oidc_session_id: str,
    user_id: str,
    label: str,
    reason: str,
    trust_bundle_digest: str,
    trust_bundle_sequence: int,
    trust_bundle_rollback_epoch: int,
    trust_signing_key_id: str,
    auth_policy_digest: str,
    recovery_root_key_id: str,
    recovery_root_provider: str,
    recovery_audience: str,
    rp_id: str,
    origin: str,
    ttl_seconds: int,
) -> dict[str, Any]:
    token_digest = _webauthn_recovery_digest(
        "pending token digest", pending_token_digest
    )
    for field_name, value in (
        ("trust bundle digest", trust_bundle_digest),
        ("trust signing key ID", trust_signing_key_id),
        ("authorization policy digest", auth_policy_digest),
        ("recovery root key ID", recovery_root_key_id),
    ):
        _webauthn_recovery_digest(field_name, value)
    if not 1 <= ttl_seconds <= 300:
        raise WebAuthnRecoveryError("recovery TTL is outside the supported range")
    with connect() as conn:
        _lock_webauthn_authority(conn)
        now = _metadata_utcnow(conn)
        now_s = now.isoformat()
        _expire_webauthn_recovery_ceremonies(conn, now_s)
        _prune_webauthn_recovery_terminal(conn, now)
        if conn.execute(
            "SELECT 1 FROM webauthn_trust_publications "
            "WHERE status = 'pending' LIMIT 1"
        ).fetchone() is not None:
            raise WebAuthnRecoveryError(
                "WebAuthn recovery is unavailable while trust publication is pending"
            )
        session = conn.execute(
            "SELECT * FROM oidc_browser_sessions WHERE id = ? AND token_digest = ?",
            (oidc_session_id, token_digest),
        ).fetchone()
        if (
            session is None
            or str(session["user_id"]) != user_id
            or session["status"] != "pending_webauthn"
            or session["expires_at"] <= now_s
            or session["pending_expires_at"] is None
            or session["pending_expires_at"] <= now_s
        ):
            raise WebAuthnRecoveryError(
                "pending OIDC browser session is invalid or expired"
            )
        history = _webauthn_credential_history_snapshot(conn, user_id)
        if history["count"] == 0:
            raise WebAuthnRecoveryError(
                "credential history is empty; first enrollment bootstrap is required"
            )
        if history["active_count"] != 0:
            raise WebAuthnRecoveryError(
                "an active WebAuthn credential still exists; ordinary WebAuthn is required"
            )
        if _webauthn_recovery_live_count(conn, now_s) >= WEBAUTHN_RECOVERY_MAX_LIVE:
            raise WebAuthnRecoveryError("WebAuthn recovery live capacity reached")
        pending_expiry = datetime.fromisoformat(str(session["pending_expires_at"]))
        ceremony_expiry = min(
            now + timedelta(seconds=ttl_seconds), pending_expiry
        ).isoformat()
        roles = loads(session["roles_json"], [])
        roles_json = dumps(sorted(str(role) for role in roles))
        identity_digest = "sha256:" + hashlib.sha256(
            dumps(
                {
                    "user_id": user_id,
                    "roles": loads(roles_json, []),
                    "oidc_token_digest": str(session["oidc_token_digest"]),
                }
            ).encode("utf-8")
        ).hexdigest()
        challenge_payload = {
            "v": 1,
            "type": "serverware.webauthn_recovery_registration",
            "recovery_id": recovery_id,
            "nonce": nonce,
            "user_id": user_id,
            "oidc_session_id": oidc_session_id,
            "pending_expires_at": str(session["pending_expires_at"]),
            "credential_history_digest": history["digest"],
            "trust_bundle_digest": trust_bundle_digest,
            "auth_policy_digest": auth_policy_digest,
        }
        challenge = base64.urlsafe_b64encode(
            hashlib.sha256(dumps(challenge_payload).encode("utf-8")).digest()
        ).decode("ascii").rstrip("=")
        challenge_id = str(uuid.uuid4())
        challenge_digest = "sha256:" + hashlib.sha256(
            challenge.encode("ascii")
        ).hexdigest()
        _admit_webauthn_challenge(
            conn,
            now=now,
            challenge_type="recovery-registration",
            user_id=user_id,
            scope_key=recovery_id,
            replace_scope=True,
        )
        conn.execute(
            """
            INSERT INTO webauthn_challenges (
                id, challenge, challenge_type, user_id, scope_key,
                approval_request_id,
                payload_json, expires_at, created_at
            ) VALUES (?, ?, 'recovery-registration', ?, ?, NULL, ?, ?, ?)
            """,
            (
                challenge_id,
                challenge,
                user_id,
                recovery_id,
                dumps(challenge_payload),
                ceremony_expiry,
                now_s,
            ),
        )
        try:
            conn.execute(
                """
                INSERT INTO webauthn_recovery_ceremonies (
                    id, nonce, user_id, oidc_session_id, pending_token_digest,
                    oidc_token_digest, roles_json, identity_digest,
                    session_expires_at, pending_expires_at, label, reason,
                    challenge_id, challenge_digest, credential_history_digest,
                    credential_history_count, active_credential_count,
                    trust_bundle_digest, trust_bundle_sequence,
                    trust_bundle_rollback_epoch, trust_signing_key_id,
                    auth_policy_digest, recovery_root_key_id,
                    recovery_root_provider, recovery_audience, rp_id, origin,
                    status, created_at, expires_at
                ) VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending_candidate', ?, ?
                )
                """,
                (
                    recovery_id,
                    nonce,
                    user_id,
                    oidc_session_id,
                    token_digest,
                    str(session["oidc_token_digest"]),
                    roles_json,
                    identity_digest,
                    str(session["expires_at"]),
                    str(session["pending_expires_at"]),
                    label,
                    reason,
                    challenge_id,
                    challenge_digest,
                    history["digest"],
                    history["count"],
                    history["active_count"],
                    trust_bundle_digest,
                    trust_bundle_sequence,
                    trust_bundle_rollback_epoch,
                    trust_signing_key_id,
                    auth_policy_digest,
                    recovery_root_key_id,
                    recovery_root_provider,
                    recovery_audience,
                    rp_id,
                    origin,
                    now_s,
                    ceremony_expiry,
                ),
            )
        except Exception as exc:
            raise WebAuthnRecoveryError(
                "a live WebAuthn recovery ceremony already exists"
            ) from exc
        append_audit_event(
            conn,
            event_type="webauthn.recovery.started",
            actor_type="admin",
            actor_id=user_id,
            event={
                "recovery_id": recovery_id,
                "oidc_session_id": oidc_session_id,
                "credential_history_digest": history["digest"],
                "credential_history_count": history["count"],
                "trust_bundle_digest": trust_bundle_digest,
                "trust_bundle_sequence": trust_bundle_sequence,
                "recovery_root_key_id": recovery_root_key_id,
                "expires_at": ceremony_expiry,
            },
            idempotency_key=f"webauthn-recovery-started:{recovery_id}",
        )
        row = conn.execute(
            "SELECT * FROM webauthn_recovery_ceremonies WHERE id = ?",
            (recovery_id,),
        ).fetchone()
        challenge_row = conn.execute(
            "SELECT * FROM webauthn_challenges WHERE id = ?", (challenge_id,)
        ).fetchone()
    result = _row_to_webauthn_recovery(row)
    result["challenge"] = row_to_webauthn_challenge(challenge_row)
    return result


def prepare_webauthn_recovery_candidate(
    *,
    recovery_id: str,
    pending_token_digest: str,
    candidate: dict[str, Any],
    witness_last_sequence: int,
) -> dict[str, Any]:
    token_digest = _webauthn_recovery_digest(
        "pending token digest", pending_token_digest
    )
    candidate_json = dumps(candidate)
    if len(candidate_json.encode("utf-8")) > 64 * 1024:
        raise WebAuthnRecoveryError("recovery candidate exceeds 64 KiB")
    candidate_digest = "sha256:" + hashlib.sha256(
        candidate_json.encode("utf-8")
    ).hexdigest()
    with connect() as conn:
        _lock_webauthn_authority(conn)
        now = _metadata_utcnow(conn)
        now_s = now.isoformat()
        _prune_webauthn_recovery_terminal(conn, now)
        _expire_webauthn_recovery_ceremonies(conn, now_s)
        row = conn.execute(
            "SELECT * FROM webauthn_recovery_ceremonies WHERE id = ?",
            (recovery_id,),
        ).fetchone()
        if row is None or row["status"] != "pending_candidate":
            raise WebAuthnRecoveryError(
                "recovery ceremony is not awaiting a candidate"
            )
        if row["expires_at"] <= now_s:
            raise WebAuthnRecoveryError("recovery ceremony expired")
        if not hmac.compare_digest(str(row["pending_token_digest"]), token_digest):
            raise WebAuthnRecoveryError("recovery pending session mismatch")
        session = conn.execute(
            "SELECT * FROM oidc_browser_sessions WHERE id = ? AND token_digest = ?",
            (row["oidc_session_id"], token_digest),
        ).fetchone()
        if (
            session is None
            or session["status"] != "pending_webauthn"
            or session["pending_expires_at"] <= now_s
            or str(session["user_id"]) != str(row["user_id"])
            or str(session["oidc_token_digest"]) != str(row["oidc_token_digest"])
            or str(session["roles_json"]) != str(row["roles_json"])
            or str(session["expires_at"]) != str(row["session_expires_at"])
            or str(session["pending_expires_at"]) != str(row["pending_expires_at"])
        ):
            raise WebAuthnRecoveryError("recovery OIDC session state changed")
        history = _webauthn_credential_history_snapshot(conn, str(row["user_id"]))
        if (
            history["digest"] != row["credential_history_digest"]
            or history["count"] != int(row["credential_history_count"])
            or history["active_count"] != 0
        ):
            raise WebAuthnRecoveryError("WebAuthn credential history changed")
        if conn.execute(
            "SELECT 1 FROM webauthn_trust_publications "
            "WHERE status = 'pending' LIMIT 1"
        ).fetchone() is not None:
            raise WebAuthnRecoveryError(
                "WebAuthn recovery is unavailable while trust publication is pending"
            )
        challenge = conn.execute(
            "SELECT * FROM webauthn_challenges WHERE id = ?",
            (row["challenge_id"],),
        ).fetchone()
        if (
            challenge is None
            or challenge["used_at"] is not None
            or challenge["expires_at"] <= now_s
        ):
            raise WebAuthnRecoveryError("recovery challenge is invalid or expired")
        root_state = conn.execute(
            "SELECT last_consumed_sequence FROM webauthn_recovery_root_state "
            "WHERE signing_key_id = ? AND user_id = ?",
            (row["recovery_root_key_id"], row["user_id"]),
        ).fetchone()
        metadata_last_sequence = int(
            root_state["last_consumed_sequence"] if root_state else 0
        )
        root_sequence = max(metadata_last_sequence, witness_last_sequence) + 1
        statement_expiry = min(
            datetime.fromisoformat(str(row["expires_at"])),
            datetime.fromisoformat(str(row["pending_expires_at"])),
        ).isoformat()
        statement = {
            "apiVersion": "serverware.webauthnRecoveryAuthorization/v1",
            "type": "serverware.webauthn_last_key_recovery",
            "recoveryId": str(row["id"]),
            "nonce": str(row["nonce"]),
            "audience": str(row["recovery_audience"]),
            "root": {
                "provider": str(row["recovery_root_provider"]),
                "keyId": str(row["recovery_root_key_id"]),
                "sequence": root_sequence,
            },
            "deployment": {
                "rpId": str(row["rp_id"]),
                "origin": str(row["origin"]),
            },
            "subject": {
                "userId": str(row["user_id"]),
                "oidcSessionId": str(row["oidc_session_id"]),
                "pendingTokenDigest": token_digest,
                "oidcTokenDigest": str(row["oidc_token_digest"]),
                "roles": loads(row["roles_json"], []),
                "identityDigest": str(row["identity_digest"]),
                "sessionExpiresAt": str(row["session_expires_at"]),
                "pendingExpiresAt": str(row["pending_expires_at"]),
            },
            "request": {
                "label": str(row["label"]),
                "reason": str(row["reason"]),
                "challengeId": str(row["challenge_id"]),
                "challenge": str(challenge["challenge"]),
                "challengeDigest": str(row["challenge_digest"]),
            },
            "credentialHistory": {
                "digest": str(row["credential_history_digest"]),
                "count": int(row["credential_history_count"]),
                "activeCredentialCount": 0,
            },
            "trust": {
                "bundleDigest": str(row["trust_bundle_digest"]),
                "bundleSequence": int(row["trust_bundle_sequence"]),
                "rollbackEpoch": int(row["trust_bundle_rollback_epoch"]),
                "signingKeyId": str(row["trust_signing_key_id"]),
            },
            "authorizationPolicyDigest": str(row["auth_policy_digest"]),
            "candidate": candidate,
            "signedAt": now_s,
            "notBefore": now_s,
            "expiresAt": statement_expiry,
        }
        statement_json = dumps(statement)
        statement_digest = "sha256:" + hashlib.sha256(
            statement_json.encode("utf-8")
        ).hexdigest()
        updated = conn.execute(
            """
            UPDATE webauthn_recovery_ceremonies
            SET status = 'prepared', candidate_json = ?, candidate_digest = ?,
                statement_json = ?, statement_digest = ?, root_sequence = ?,
                prepared_at = ?
            WHERE id = ? AND status = 'pending_candidate' AND expires_at > ?
            """,
            (
                candidate_json,
                candidate_digest,
                statement_json,
                statement_digest,
                root_sequence,
                now_s,
                recovery_id,
                now_s,
            ),
        )
        if updated.rowcount != 1:
            raise WebAuthnRecoveryError("recovery candidate state changed")
        append_audit_event(
            conn,
            event_type="webauthn.recovery.prepared",
            actor_type="admin",
            actor_id=str(row["user_id"]),
            event={
                "recovery_id": recovery_id,
                "candidate_digest": candidate_digest,
                "statement_digest": statement_digest,
                "root_sequence": root_sequence,
                "expires_at": statement_expiry,
            },
            idempotency_key=f"webauthn-recovery-prepared:{recovery_id}",
        )
        prepared = conn.execute(
            "SELECT * FROM webauthn_recovery_ceremonies WHERE id = ?",
            (recovery_id,),
        ).fetchone()
    return _row_to_webauthn_recovery(prepared)


def finalize_webauthn_recovery_registration(
    *,
    recovery_id: str,
    pending_token_digest: str,
    candidate: dict[str, Any],
    statement: dict[str, Any],
    authorization: dict[str, Any],
    authorization_digest: str,
    signature_digest: str,
    current_trust: dict[str, Any],
    auth_policy_digest: str,
) -> dict[str, Any]:
    token_digest = _webauthn_recovery_digest(
        "pending token digest", pending_token_digest
    )
    authorization_digest = _webauthn_recovery_digest(
        "authorization digest", authorization_digest
    )
    signature_digest = _webauthn_recovery_digest(
        "signature digest", signature_digest
    )
    candidate_json = dumps(candidate)
    candidate_digest = "sha256:" + hashlib.sha256(
        candidate_json.encode("utf-8")
    ).hexdigest()
    statement_json = dumps(statement)
    statement_digest = "sha256:" + hashlib.sha256(
        statement_json.encode("utf-8")
    ).hexdigest()
    authorization_json = dumps(authorization)
    if len(authorization_json.encode("utf-8")) > 128 * 1024:
        raise WebAuthnRecoveryError("recovery authorization exceeds 128 KiB")
    item_id = str(uuid.uuid4())
    with connect() as conn:
        _lock_webauthn_authority(conn)
        now_s = _metadata_utcnow(conn).isoformat()
        _expire_webauthn_recovery_ceremonies(conn, now_s)
        row = conn.execute(
            "SELECT * FROM webauthn_recovery_ceremonies WHERE id = ?",
            (recovery_id,),
        ).fetchone()
        if row is None or row["status"] != "prepared":
            raise WebAuthnRecoveryError("recovery ceremony is not prepared")
        if row["expires_at"] <= now_s:
            raise WebAuthnRecoveryError("recovery ceremony expired")
        exact_values = (
            ("pending_token_digest", token_digest),
            ("candidate_digest", candidate_digest),
            ("candidate_json", candidate_json),
            ("statement_digest", statement_digest),
            ("statement_json", statement_json),
            ("auth_policy_digest", auth_policy_digest),
            ("trust_bundle_digest", current_trust.get("digest")),
            ("trust_bundle_sequence", current_trust.get("sequence")),
            ("trust_bundle_rollback_epoch", current_trust.get("rollback_epoch")),
            ("trust_signing_key_id", current_trust.get("signing_key_id")),
        )
        for field, expected in exact_values:
            actual = row[field]
            if isinstance(actual, int):
                try:
                    expected = int(expected)
                except (TypeError, ValueError) as exc:
                    raise WebAuthnRecoveryError(
                        f"recovery {field} binding is invalid"
                    ) from exc
            if actual != expected:
                raise WebAuthnRecoveryError(f"recovery {field} binding changed")
        if conn.execute(
            "SELECT 1 FROM webauthn_trust_publications "
            "WHERE status = 'pending' LIMIT 1"
        ).fetchone() is not None:
            raise WebAuthnRecoveryError(
                "WebAuthn recovery is unavailable while trust publication is pending"
            )
        session = conn.execute(
            "SELECT * FROM oidc_browser_sessions WHERE id = ? AND token_digest = ?",
            (row["oidc_session_id"], token_digest),
        ).fetchone()
        if (
            session is None
            or session["status"] != "pending_webauthn"
            or session["pending_expires_at"] <= now_s
            or str(session["user_id"]) != str(row["user_id"])
            or str(session["oidc_token_digest"]) != str(row["oidc_token_digest"])
            or str(session["roles_json"]) != str(row["roles_json"])
            or str(session["expires_at"]) != str(row["session_expires_at"])
            or str(session["pending_expires_at"]) != str(row["pending_expires_at"])
        ):
            raise WebAuthnRecoveryError("recovery OIDC session state changed")
        history = _webauthn_credential_history_snapshot(conn, str(row["user_id"]))
        if (
            history["digest"] != row["credential_history_digest"]
            or history["count"] != int(row["credential_history_count"])
            or history["active_count"] != 0
        ):
            raise WebAuthnRecoveryError("WebAuthn credential history changed")
        challenge = conn.execute(
            "SELECT * FROM webauthn_challenges WHERE id = ?",
            (row["challenge_id"],),
        ).fetchone()
        if (
            challenge is None
            or challenge["used_at"] is not None
            or challenge["expires_at"] <= now_s
        ):
            raise WebAuthnRecoveryError("recovery challenge is invalid or expired")
        if conn.execute(
            "SELECT 1 FROM webauthn_recovery_ceremonies "
            "WHERE id != ? AND (authorization_digest = ? OR signature_digest = ?) "
            "LIMIT 1",
            (recovery_id, authorization_digest, signature_digest),
        ).fetchone() is not None:
            raise WebAuthnRecoveryError("recovery authorization was already used")
        root_sequence = int(row["root_sequence"])
        root_state = conn.execute(
            "SELECT last_consumed_sequence FROM webauthn_recovery_root_state "
            "WHERE signing_key_id = ? AND user_id = ?",
            (row["recovery_root_key_id"], row["user_id"]),
        ).fetchone()
        previous_root_sequence = int(
            root_state["last_consumed_sequence"] if root_state else 0
        )
        if root_sequence <= previous_root_sequence:
            raise WebAuthnRecoveryError("recovery root sequence is stale or replayed")
        claim_webauthn_recovery_authorization(
            authorization_digest=authorization_digest,
            signature_digest=signature_digest,
            statement_digest=statement_digest,
            recovery_id=recovery_id,
            ceremony_type="replacement-registration",
            user_id=str(row["user_id"]),
            root_key_id=str(row["recovery_root_key_id"]),
            root_sequence=root_sequence,
        )
        if root_state is None:
            conn.execute(
                "INSERT INTO webauthn_recovery_root_state "
                "(signing_key_id, user_id, last_consumed_sequence, updated_at) "
                "VALUES (?, ?, ?, ?)",
                (row["recovery_root_key_id"], row["user_id"], root_sequence, now_s),
            )
        else:
            advanced = conn.execute(
                "UPDATE webauthn_recovery_root_state "
                "SET last_consumed_sequence = ?, updated_at = ? "
                "WHERE signing_key_id = ? AND user_id = ? "
                "AND last_consumed_sequence = ?",
                (
                    root_sequence,
                    now_s,
                    row["recovery_root_key_id"],
                    row["user_id"],
                    previous_root_sequence,
                ),
            )
            if advanced.rowcount != 1:
                raise WebAuthnRecoveryError("recovery root sequence changed")
        claimed = conn.execute(
            "UPDATE webauthn_challenges SET used_at = ? "
            "WHERE id = ? AND used_at IS NULL AND expires_at > ?",
            (now_s, row["challenge_id"], now_s),
        )
        if claimed.rowcount != 1:
            raise WebAuthnRecoveryError("recovery challenge state changed")
        credential = _insert_webauthn_credential(
            conn,
            item_id=item_id,
            now_s=now_s,
            credential_id=str(candidate["credentialId"]),
            user_id=str(row["user_id"]),
            label=str(row["label"]),
            public_key_cose=str(candidate["publicKeyCose"]),
            sign_count=int(candidate["signCount"]),
            aaguid=candidate.get("aaguid"),
            authenticator_class=str(candidate["authenticatorClass"]),
            attestation_fmt=str(candidate["attestationFormat"]),
            attestation_trusted=bool(candidate["attestationTrusted"]),
            attestation_trust_path=list(candidate.get("attestationTrustPath") or []),
            attestation_leaf_sha256=candidate.get("attestationLeafSha256"),
            attestation_root_sha256=candidate.get("attestationRootSha256"),
            attestation_trust_bundle_digest=candidate.get("trustBundleDigest"),
            attestation_trust_bundle_sequence=candidate.get("trustBundleSequence"),
            attestation_verified_at=str(row["prepared_at"]),
            transports=list(candidate.get("transports") or []),
            dev_private_key_pem=None,
        )
        invalidated = conn.execute(
            "UPDATE webauthn_challenges SET used_at = ? "
            "WHERE user_id = ? AND id != ? "
            "AND challenge_type IN ('registration', 'recovery-registration') "
            "AND used_at IS NULL AND expires_at > ?",
            (now_s, row["user_id"], row["challenge_id"], now_s),
        )
        consumed = conn.execute(
            """
            UPDATE webauthn_recovery_ceremonies
            SET status = 'consumed', authorization_json = ?, authorization_digest = ?,
                signature_digest = ?, replacement_record_id = ?, consumed_at = ?
            WHERE id = ? AND status = 'prepared'
            """,
            (
                authorization_json,
                authorization_digest,
                signature_digest,
                credential["id"],
                now_s,
                recovery_id,
            ),
        )
        if consumed.rowcount != 1:
            raise WebAuthnRecoveryError("recovery ceremony state changed")
        append_audit_event(
            conn,
            event_type="webauthn.credential_registered",
            actor_type="admin",
            actor_id=str(row["user_id"]),
            event={
                "user_id": str(row["user_id"]),
                "credential_id": str(candidate["credentialId"]),
                "authenticator_class": str(candidate["authenticatorClass"]),
                "aaguid": candidate.get("aaguid"),
                "attestation_fmt": candidate.get("attestationFormat"),
                "attestation_trusted": True,
                "attestation_root_sha256": candidate.get(
                    "attestationRootSha256"
                ),
                "registration_authorization": {
                    "mode": "offline-last-key-recovery",
                    "recovery_id": recovery_id,
                    "authorization_digest": authorization_digest,
                    "root_sequence": root_sequence,
                },
            },
            idempotency_key=f"webauthn-recovery-credential:{recovery_id}",
        )
        append_audit_event(
            conn,
            event_type="webauthn.recovery.consumed",
            actor_type="admin",
            actor_id=str(row["user_id"]),
            event={
                "recovery_id": recovery_id,
                "oidc_session_id": str(row["oidc_session_id"]),
                "credential_record_id": credential["id"],
                "credential_id_digest": "sha256:"
                + hashlib.sha256(
                    str(candidate["credentialId"]).encode("utf-8")
                ).hexdigest(),
                "candidate_digest": candidate_digest,
                "statement_digest": statement_digest,
                "authorization_digest": authorization_digest,
                "signature_digest": signature_digest,
                "root_key_id": str(row["recovery_root_key_id"]),
                "root_sequence": root_sequence,
                "invalidated_sibling_challenge_count": invalidated.rowcount,
            },
            idempotency_key=f"webauthn-recovery-consumed:{recovery_id}",
        )
        completed = conn.execute(
            "SELECT * FROM webauthn_recovery_ceremonies WHERE id = ?",
            (recovery_id,),
        ).fetchone()
    return {
        "ceremony": _row_to_webauthn_recovery(completed),
        "credential": credential,
        "invalidated_sibling_challenge_count": invalidated.rowcount,
    }


def _row_to_webauthn_recovery_revocation(row: Any) -> dict[str, Any]:
    item = dict(row)
    item["roles"] = loads(item.pop("roles_json"), [])
    item["statement"] = loads(item.pop("statement_json"), {})
    item["authorization"] = loads(item.pop("authorization_json"), None)
    for field in (
        "credential_history_count",
        "active_credential_count",
        "trust_bundle_sequence",
        "trust_bundle_rollback_epoch",
        "root_sequence",
    ):
        item[field] = int(item[field])
    return item


def get_webauthn_recovery_revocation(revocation_id: str) -> dict[str, Any] | None:
    with connect() as conn:
        row = conn.execute(
            "SELECT * FROM webauthn_recovery_revocations WHERE id = ?",
            (revocation_id,),
        ).fetchone()
    return _row_to_webauthn_recovery_revocation(row) if row else None


def create_webauthn_recovery_revocation(
    *,
    revocation_id: str,
    nonce: str,
    pending_token_digest: str,
    oidc_session_id: str,
    user_id: str,
    reason: str,
    trust: dict[str, Any],
    auth_policy_digest: str,
    recovery_root_key_id: str,
    recovery_root_provider: str,
    recovery_audience: str,
    rp_id: str,
    origin: str,
    ttl_seconds: int,
    witness_last_sequence: int,
) -> dict[str, Any]:
    token_digest = _webauthn_recovery_digest(
        "pending token digest", pending_token_digest
    )
    for field_name, value in (
        ("trust bundle digest", trust.get("digest")),
        ("trust signing key ID", trust.get("signing_key_id")),
        ("authorization policy digest", auth_policy_digest),
        ("recovery root key ID", recovery_root_key_id),
    ):
        _webauthn_recovery_digest(field_name, str(value or ""))
    if not 1 <= ttl_seconds <= 300:
        raise WebAuthnRecoveryError("recovery TTL is outside the supported range")
    with connect() as conn:
        _lock_webauthn_authority(conn)
        now = _metadata_utcnow(conn)
        now_s = now.isoformat()
        _prune_webauthn_recovery_terminal(conn, now)
        conn.execute(
            "UPDATE webauthn_recovery_revocations SET status = 'expired' "
            "WHERE status = 'prepared' AND expires_at <= ?",
            (now_s,),
        )
        if _webauthn_recovery_live_count(conn, now_s) >= WEBAUTHN_RECOVERY_MAX_LIVE:
            raise WebAuthnRecoveryError("WebAuthn recovery live capacity reached")
        if conn.execute(
            "SELECT 1 FROM webauthn_trust_publications WHERE status = 'pending' LIMIT 1"
        ).fetchone() is not None:
            raise WebAuthnRecoveryError(
                "WebAuthn recovery is unavailable while trust publication is pending"
            )
        session = conn.execute(
            "SELECT * FROM oidc_browser_sessions WHERE id = ? AND token_digest = ?",
            (oidc_session_id, token_digest),
        ).fetchone()
        if (
            session is None
            or session["status"] != "pending_webauthn"
            or str(session["user_id"]) != user_id
            or session["expires_at"] <= now_s
            or session["pending_expires_at"] <= now_s
        ):
            raise WebAuthnRecoveryError(
                "pending OIDC browser session is invalid or expired"
            )
        history = _webauthn_credential_history_snapshot(conn, user_id)
        if history["active_count"] != 1:
            raise WebAuthnRecoveryError(
                "lost-key decommission requires exactly one active WebAuthn credential"
            )
        active = conn.execute(
            "SELECT * FROM webauthn_credentials "
            "WHERE user_id = ? AND revoked_at IS NULL",
            (user_id,),
        ).fetchone()
        if active is None:
            raise WebAuthnRecoveryError("active WebAuthn credential disappeared")
        root_state = conn.execute(
            "SELECT last_consumed_sequence FROM webauthn_recovery_root_state "
            "WHERE signing_key_id = ? AND user_id = ?",
            (recovery_root_key_id, user_id),
        ).fetchone()
        metadata_last_sequence = int(
            root_state["last_consumed_sequence"] if root_state else 0
        )
        root_sequence = max(metadata_last_sequence, witness_last_sequence) + 1
        roles = sorted(loads(session["roles_json"], []))
        identity_digest = "sha256:" + hashlib.sha256(
            dumps(
                {
                    "user_id": user_id,
                    "roles": roles,
                    "oidc_token_digest": str(session["oidc_token_digest"]),
                }
            ).encode("utf-8")
        ).hexdigest()
        expires_at = min(
            now + timedelta(seconds=ttl_seconds),
            datetime.fromisoformat(str(session["pending_expires_at"])),
        ).isoformat()
        credential_id_digest = "sha256:" + hashlib.sha256(
            str(active["credential_id"]).encode("utf-8")
        ).hexdigest()
        statement = {
            "apiVersion": "serverware.webauthnRecoveryRevocation/v1",
            "type": "serverware.webauthn_lost_active_key_decommission",
            "revocationId": revocation_id,
            "nonce": nonce,
            "audience": recovery_audience,
            "root": {
                "provider": recovery_root_provider,
                "keyId": recovery_root_key_id,
                "sequence": root_sequence,
            },
            "deployment": {"rpId": rp_id, "origin": origin},
            "subject": {
                "userId": user_id,
                "oidcSessionId": oidc_session_id,
                "pendingTokenDigest": token_digest,
                "oidcTokenDigest": str(session["oidc_token_digest"]),
                "roles": roles,
                "identityDigest": identity_digest,
                "sessionExpiresAt": str(session["expires_at"]),
                "pendingExpiresAt": str(session["pending_expires_at"]),
            },
            "decommission": {
                "reason": reason,
                "credentialRecordId": str(active["id"]),
                "credentialIdDigest": credential_id_digest,
                "credentialHistoryDigest": history["digest"],
                "credentialHistoryCount": history["count"],
                "activeCredentialCount": 1,
            },
            "trust": {
                "bundleDigest": str(trust["digest"]),
                "bundleSequence": int(trust["sequence"]),
                "rollbackEpoch": int(trust["rollback_epoch"]),
                "signingKeyId": str(trust["signing_key_id"]),
            },
            "authorizationPolicyDigest": auth_policy_digest,
            "signedAt": now_s,
            "notBefore": now_s,
            "expiresAt": expires_at,
        }
        statement_json = dumps(statement)
        statement_digest = "sha256:" + hashlib.sha256(
            statement_json.encode("utf-8")
        ).hexdigest()
        try:
            conn.execute(
                """
                INSERT INTO webauthn_recovery_revocations (
                    id, nonce, user_id, oidc_session_id, pending_token_digest,
                    oidc_token_digest, roles_json, identity_digest,
                    session_expires_at, pending_expires_at, reason,
                    credential_history_digest, credential_history_count,
                    active_credential_count, active_credential_record_id,
                    active_credential_id_digest, trust_bundle_digest,
                    trust_bundle_sequence, trust_bundle_rollback_epoch,
                    trust_signing_key_id, auth_policy_digest,
                    recovery_root_key_id, recovery_root_provider,
                    recovery_audience, root_sequence, statement_json,
                    statement_digest, status, created_at, expires_at
                ) VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, 'prepared', ?, ?
                )
                """,
                (
                    revocation_id, nonce, user_id, oidc_session_id, token_digest,
                    session["oidc_token_digest"], dumps(roles), identity_digest,
                    session["expires_at"], session["pending_expires_at"], reason,
                    history["digest"], history["count"], history["active_count"],
                    active["id"], credential_id_digest, trust["digest"],
                    trust["sequence"], trust["rollback_epoch"],
                    trust["signing_key_id"], auth_policy_digest,
                    recovery_root_key_id, recovery_root_provider,
                    recovery_audience, root_sequence, statement_json,
                    statement_digest, now_s, expires_at,
                ),
            )
        except Exception as exc:
            raise WebAuthnRecoveryError(
                "a live lost-key decommission ceremony already exists"
            ) from exc
        append_audit_event(
            conn,
            event_type="webauthn.recovery_revocation.prepared",
            actor_type="admin",
            actor_id=user_id,
            event={
                "revocation_id": revocation_id,
                "credential_record_id": str(active["id"]),
                "credential_history_digest": history["digest"],
                "statement_digest": statement_digest,
                "root_sequence": root_sequence,
                "expires_at": expires_at,
            },
            idempotency_key=f"webauthn-recovery-revocation-prepared:{revocation_id}",
        )
        stored = conn.execute(
            "SELECT * FROM webauthn_recovery_revocations WHERE id = ?",
            (revocation_id,),
        ).fetchone()
    return _row_to_webauthn_recovery_revocation(stored)


def finalize_webauthn_recovery_revocation(
    *,
    revocation_id: str,
    pending_token_digest: str,
    statement: dict[str, Any],
    authorization: dict[str, Any],
    authorization_digest: str,
    signature_digest: str,
    current_trust: dict[str, Any],
    auth_policy_digest: str,
) -> dict[str, Any]:
    token_digest = _webauthn_recovery_digest(
        "pending token digest", pending_token_digest
    )
    authorization_digest = _webauthn_recovery_digest(
        "authorization digest", authorization_digest
    )
    signature_digest = _webauthn_recovery_digest(
        "signature digest", signature_digest
    )
    authorization_json = dumps(authorization)
    if len(authorization_json.encode("utf-8")) > 128 * 1024:
        raise WebAuthnRecoveryError("recovery authorization exceeds 128 KiB")
    with connect() as conn:
        _lock_webauthn_authority(conn)
        now_s = _metadata_utcnow(conn).isoformat()
        row = conn.execute(
            "SELECT * FROM webauthn_recovery_revocations WHERE id = ?",
            (revocation_id,),
        ).fetchone()
        if row is None or row["status"] != "prepared" or row["expires_at"] <= now_s:
            raise WebAuthnRecoveryError(
                "lost-key decommission ceremony is not live"
            )
        if conn.execute(
            "SELECT 1 FROM webauthn_trust_publications "
            "WHERE status = 'pending' LIMIT 1"
        ).fetchone() is not None:
            raise WebAuthnRecoveryError(
                "WebAuthn recovery is unavailable while trust publication is pending"
            )
        bindings = {
            "pending_token_digest": token_digest,
            "statement_json": dumps(statement),
            "statement_digest": "sha256:"
            + hashlib.sha256(dumps(statement).encode("utf-8")).hexdigest(),
            "auth_policy_digest": auth_policy_digest,
            "trust_bundle_digest": current_trust["digest"],
            "trust_bundle_sequence": int(current_trust["sequence"]),
            "trust_bundle_rollback_epoch": int(current_trust["rollback_epoch"]),
            "trust_signing_key_id": current_trust["signing_key_id"],
        }
        for field, expected in bindings.items():
            actual = int(row[field]) if field in {
                "trust_bundle_sequence", "trust_bundle_rollback_epoch"
            } else row[field]
            if actual != expected:
                raise WebAuthnRecoveryError(
                    f"lost-key decommission {field} binding changed"
                )
        session = conn.execute(
            "SELECT * FROM oidc_browser_sessions WHERE id = ? AND token_digest = ?",
            (row["oidc_session_id"], token_digest),
        ).fetchone()
        if (
            session is None
            or session["status"] != "pending_webauthn"
            or session["expires_at"] <= now_s
            or session["pending_expires_at"] <= now_s
            or str(session["user_id"]) != str(row["user_id"])
            or session["roles_json"] != row["roles_json"]
            or session["oidc_token_digest"] != row["oidc_token_digest"]
            or session["expires_at"] != row["session_expires_at"]
            or session["pending_expires_at"] != row["pending_expires_at"]
        ):
            raise WebAuthnRecoveryError("lost-key decommission session changed")
        history = _webauthn_credential_history_snapshot(conn, str(row["user_id"]))
        if (
            history["digest"] != row["credential_history_digest"]
            or history["count"] != int(row["credential_history_count"])
            or history["active_count"] != 1
        ):
            raise WebAuthnRecoveryError(
                "lost-key decommission credential history changed"
            )
        active = conn.execute(
            "SELECT credential_id FROM webauthn_credentials "
            "WHERE id = ? AND user_id = ? AND revoked_at IS NULL",
            (row["active_credential_record_id"], row["user_id"]),
        ).fetchone()
        if active is None or not hmac.compare_digest(
            "sha256:" + hashlib.sha256(
                str(active["credential_id"]).encode("utf-8")
            ).hexdigest(),
            str(row["active_credential_id_digest"]),
        ):
            raise WebAuthnRecoveryError("lost active credential changed")
        if conn.execute(
            "SELECT 1 FROM webauthn_recovery_revocations "
            "WHERE id != ? AND (authorization_digest = ? OR signature_digest = ?) "
            "UNION ALL "
            "SELECT 1 FROM webauthn_recovery_ceremonies "
            "WHERE authorization_digest = ? OR signature_digest = ? LIMIT 1",
            (
                revocation_id,
                authorization_digest,
                signature_digest,
                authorization_digest,
                signature_digest,
            ),
        ).fetchone() is not None:
            raise WebAuthnRecoveryError("recovery authorization was already used")
        root_state = conn.execute(
            "SELECT last_consumed_sequence FROM webauthn_recovery_root_state "
            "WHERE signing_key_id = ? AND user_id = ?",
            (row["recovery_root_key_id"], row["user_id"]),
        ).fetchone()
        previous_root_sequence = int(
            root_state["last_consumed_sequence"] if root_state else 0
        )
        root_sequence = int(row["root_sequence"])
        if root_sequence <= previous_root_sequence:
            raise WebAuthnRecoveryError("recovery root sequence is stale or replayed")
        claim_webauthn_recovery_authorization(
            authorization_digest=authorization_digest,
            signature_digest=signature_digest,
            statement_digest=str(row["statement_digest"]),
            recovery_id=revocation_id,
            ceremony_type="lost-active-key-decommission",
            user_id=str(row["user_id"]),
            root_key_id=str(row["recovery_root_key_id"]),
            root_sequence=root_sequence,
        )
        if root_state is None:
            conn.execute(
                "INSERT INTO webauthn_recovery_root_state "
                "(signing_key_id, user_id, last_consumed_sequence, updated_at) "
                "VALUES (?, ?, ?, ?)",
                (row["recovery_root_key_id"], row["user_id"], root_sequence, now_s),
            )
        else:
            advanced = conn.execute(
                "UPDATE webauthn_recovery_root_state "
                "SET last_consumed_sequence = ?, updated_at = ? "
                "WHERE signing_key_id = ? AND user_id = ? "
                "AND last_consumed_sequence = ?",
                (
                    root_sequence,
                    now_s,
                    row["recovery_root_key_id"],
                    row["user_id"],
                    previous_root_sequence,
                ),
            )
            if advanced.rowcount != 1:
                raise WebAuthnRecoveryError("recovery root sequence changed")
        revoked = revoke_webauthn_credential(
            str(row["active_credential_record_id"]),
            actor_id=f"offline-recovery:{revocation_id}",
            reason=str(row["reason"]),
            source="offline-last-key-decommission",
            audit_event={
                "user_id": str(row["user_id"]),
                "credential_record_id": str(row["active_credential_record_id"]),
                "credential_id_digest": str(row["active_credential_id_digest"]),
                "reason": str(row["reason"]),
                "revocation_authorization": {
                    "mode": "offline-last-key-decommission",
                    "revocation_id": revocation_id,
                    "authorization_digest": authorization_digest,
                    "root_sequence": root_sequence,
                },
            },
            _connection=conn,
        )
        if not revoked.get("ok"):
            raise WebAuthnRecoveryError("lost active credential revocation raced")
        updated = conn.execute(
            "UPDATE webauthn_recovery_revocations SET status = 'consumed', "
            "authorization_json = ?, authorization_digest = ?, signature_digest = ?, consumed_at = ? "
            "WHERE id = ? AND status = 'prepared'",
            (authorization_json, authorization_digest, signature_digest, now_s, revocation_id),
        )
        if updated.rowcount != 1:
            raise WebAuthnRecoveryError("lost-key decommission state changed")
        append_audit_event(
            conn,
            event_type="webauthn.recovery_revocation.consumed",
            actor_type="admin",
            actor_id=str(row["user_id"]),
            event={
                "revocation_id": revocation_id,
                "credential_record_id": str(row["active_credential_record_id"]),
                "authorization_digest": authorization_digest,
                "signature_digest": signature_digest,
                "root_sequence": root_sequence,
            },
            idempotency_key=f"webauthn-recovery-revocation-consumed:{revocation_id}",
        )
    return {"ok": True, "revoked": revoked, "revocationId": revocation_id}


def _invalidate_live_webauthn_registration_challenges(
    conn: Any, now_s: str
) -> int:
    invalidated = conn.execute(
        """
        UPDATE webauthn_challenges
        SET used_at = ?
        WHERE challenge_type = 'registration'
          AND used_at IS NULL
          AND expires_at > ?
        """,
        (now_s, now_s),
    )
    return invalidated.rowcount


def invalidate_webauthn_registration_challenges(
    *, _connection: Any | None = None
) -> int:
    connection_scope = (
        connect() if _connection is None else contextlib.nullcontext(_connection)
    )
    with connection_scope as conn:
        _lock_webauthn_authority(conn)
        now_s = _metadata_utcnow(conn).isoformat()
        return _invalidate_live_webauthn_registration_challenges(conn, now_s)


def revoke_webauthn_credential(
    record_id: str,
    *,
    actor_id: str,
    reason: str | None = None,
    source: str = "explicit",
    audit_event: dict[str, Any] | None = None,
    _connection: Any | None = None,
) -> dict[str, Any]:
    connection_scope = (
        connect() if _connection is None else contextlib.nullcontext(_connection)
    )
    with connection_scope as conn:
        _lock_webauthn_authority(conn)
        now_s = _metadata_utcnow(conn).isoformat()
        row = conn.execute(
            "SELECT * FROM webauthn_credentials WHERE id = ?", (record_id,)
        ).fetchone()
        if row is None:
            return {
                "ok": False,
                "reason": "credential_not_found",
                "revoked_oidc_browser_session_count": 0,
            }
        if row["revoked_at"] is not None:
            return {
                "ok": False,
                "reason": "credential_already_revoked",
                "credential": row_to_webauthn_credential(row),
                "revoked_oidc_browser_session_count": 0,
            }
        cur = conn.execute(
            """
            UPDATE webauthn_credentials
            SET revoked_at = ?, revoked_by = ?, revocation_reason = ?,
                revocation_source = ?, updated_at = ?
            WHERE id = ? AND revoked_at IS NULL
            """,
            (now_s, actor_id, reason, source, now_s, record_id),
        )
        if cur.rowcount != 1:
            return {
                "ok": False,
                "reason": "credential_revocation_raced",
                "revoked_oidc_browser_session_count": 0,
            }
        revoked_oidc_browser_sessions = conn.execute(
            """
            UPDATE oidc_browser_sessions
            SET status = 'revoked', revoked_at = ?, updated_at = ?,
                revocation_reason = 'bound_webauthn_credential_revoked'
            WHERE bound_webauthn_credential_id = ?
              AND status IN ('pending_webauthn', 'active')
            """,
            (now_s, now_s, record_id),
        )
        revoked_grants = conn.execute(
            """
            UPDATE approval_grants
            SET state = 'revoked', uses_remaining = 0,
                reserved_attempt_id = NULL, reserved_at_epoch_ms = NULL,
                reservation_expires_at_epoch_ms = NULL
            WHERE approver_webauthn_credential_id = ? AND state = 'active'
            """,
            (record_id,),
        )
        invalidated_approvals = conn.execute(
            """
            SELECT id, action, resource_id, payload_digest, requester_id, approved_by
            FROM control_plane_approvals
            WHERE approver_webauthn_credential_id = ? AND status = 'approved'
            """,
            (record_id,),
        ).fetchall()
        revoked_control_plane_approvals = conn.execute(
            """
            UPDATE control_plane_approvals
            SET status = 'invalidated'
            WHERE approver_webauthn_credential_id = ? AND status = 'approved'
            """,
            (record_id,),
        )
        invalidated_registration_challenge_count = 0
        if source == "explicit":
            invalidated_registration_challenge_count = (
                _invalidate_live_webauthn_registration_challenges(conn, now_s)
            )
        updated = conn.execute(
            "SELECT * FROM webauthn_credentials WHERE id = ?", (record_id,)
        ).fetchone()
        for approval in invalidated_approvals:
            append_audit_event(
                conn,
                event_type="control_plane.approval.invalidated",
                actor_type="system",
                actor_id=None,
                event={
                    "approval_id": approval["id"],
                    "action": approval["action"],
                    "resource_id": approval["resource_id"],
                    "payload_digest": approval["payload_digest"],
                    "requester_id": approval["requester_id"],
                    "approved_by": approval["approved_by"],
                    "approver_webauthn_credential_id": record_id,
                    "reason": "approver_webauthn_credential_revoked",
                },
            )
        if audit_event is not None:
            append_audit_event(
                conn,
                event_type="webauthn.credential_revoked",
                actor_type="admin",
                actor_id=actor_id,
                event={
                    **audit_event,
                    "revoked_at": updated["revoked_at"],
                    "revoked_by": updated["revoked_by"],
                    "revoked_grant_count": revoked_grants.rowcount,
                    "revoked_control_plane_approval_count": (
                        revoked_control_plane_approvals.rowcount
                    ),
                    "revoked_oidc_browser_session_count": (
                        revoked_oidc_browser_sessions.rowcount
                    ),
                    "invalidated_registration_challenge_count": (
                        invalidated_registration_challenge_count
                    ),
                },
            )
    return {
        "ok": True,
        "credential": row_to_webauthn_credential(updated),
        "revoked_grant_count": revoked_grants.rowcount,
        "revoked_control_plane_approval_count": revoked_control_plane_approvals.rowcount,
        "revoked_oidc_browser_session_count": (
            revoked_oidc_browser_sessions.rowcount
        ),
        "invalidated_registration_challenge_count": (
            invalidated_registration_challenge_count
        ),
    }


def update_webauthn_sign_count(credential_id: str, sign_count: int) -> None:
    with connect() as conn:
        conn.execute(
            """
            UPDATE webauthn_credentials
            SET sign_count = ?, last_used_at = ?, updated_at = ?
            WHERE credential_id = ?
            """,
            (sign_count, iso_now(), iso_now(), credential_id),
        )


def compare_and_swap_webauthn_sign_count(
    credential_id: str,
    *,
    expected_sign_count: int,
    new_sign_count: int,
) -> bool:
    if expected_sign_count < 0 or new_sign_count < 0:
        return False
    if not (
        (expected_sign_count == 0 and new_sign_count == 0)
        or new_sign_count > expected_sign_count
    ):
        return False
    now_s = iso_now()
    with connect() as conn:
        cur = conn.execute(
            """
            UPDATE webauthn_credentials
            SET sign_count = ?, last_used_at = ?, updated_at = ?
            WHERE credential_id = ?
              AND revoked_at IS NULL
              AND sign_count = ?
            """,
            (
                new_sign_count,
                now_s,
                now_s,
                credential_id,
                expected_sign_count,
            ),
        )
    return cur.rowcount == 1


def _prune_webauthn_challenges(conn: Any, now: datetime) -> dict[str, int]:
    now_s = now.isoformat()
    expired = conn.execute(
        "UPDATE webauthn_challenges SET used_at = ? "
        "WHERE used_at IS NULL AND expires_at <= ?",
        (now_s, now_s),
    )
    cutoff = (
        now - timedelta(seconds=WEBAUTHN_CHALLENGE_TERMINAL_RETENTION_SECONDS)
    ).isoformat()
    retained_reference = (
        "id NOT IN (SELECT challenge_id FROM webauthn_recovery_ceremonies)"
    )
    deleted_old = conn.execute(
        "DELETE FROM webauthn_challenges WHERE used_at IS NOT NULL "
        "AND used_at <= ? AND " + retained_reference,
        (cutoff,),
    )
    deleted_overflow = conn.execute(
        "DELETE FROM webauthn_challenges WHERE id IN ("
        "SELECT id FROM ("
        "SELECT id, ROW_NUMBER() OVER (ORDER BY used_at DESC, id DESC) AS ordinal "
        "FROM webauthn_challenges WHERE used_at IS NOT NULL AND "
        + retained_reference
        + ") AS ranked WHERE ordinal > ?) ",
        (WEBAUTHN_CHALLENGE_MAX_RETAINED - 1,),
    )
    return {
        "expired": max(0, int(expired.rowcount)),
        "deleted": max(0, int(deleted_old.rowcount))
        + max(0, int(deleted_overflow.rowcount)),
    }


def _admit_webauthn_challenge(
    conn: Any,
    *,
    now: datetime,
    challenge_type: str,
    user_id: str,
    scope_key: str | None,
    replace_scope: bool,
) -> None:
    _prune_webauthn_challenges(conn, now)
    now_s = now.isoformat()
    rate_start = (
        now - timedelta(seconds=WEBAUTHN_CHALLENGE_RATE_WINDOW_SECONDS)
    ).isoformat()
    recent = conn.execute(
        "SELECT COUNT(*) AS count FROM webauthn_challenges "
        "WHERE user_id = ? AND created_at > ?",
        (user_id, rate_start),
    ).fetchone()
    if int(recent["count"] if recent else 0) >= WEBAUTHN_CHALLENGE_USER_RATE_MAX:
        raise MetadataStoreError("WebAuthn challenge user rate limit reached")
    global_recent = conn.execute(
        "SELECT COUNT(*) AS count FROM webauthn_challenges WHERE created_at > ?",
        (rate_start,),
    ).fetchone()
    if int(global_recent["count"] if global_recent else 0) >= (
        WEBAUTHN_CHALLENGE_GLOBAL_RATE_MAX
    ):
        raise MetadataStoreError("WebAuthn challenge global rate limit reached")
    if replace_scope and scope_key is not None:
        conn.execute(
            "UPDATE webauthn_challenges SET used_at = ? "
            "WHERE challenge_type = ? AND user_id = ? AND scope_key = ? "
            "AND used_at IS NULL",
            (now_s, challenge_type, user_id, scope_key),
        )
    global_live = conn.execute(
        "SELECT COUNT(*) AS count FROM webauthn_challenges "
        "WHERE used_at IS NULL AND expires_at > ?",
        (now_s,),
    ).fetchone()
    user_live = conn.execute(
        "SELECT COUNT(*) AS count FROM webauthn_challenges "
        "WHERE user_id = ? AND used_at IS NULL AND expires_at > ?",
        (user_id, now_s),
    ).fetchone()
    if int(global_live["count"] if global_live else 0) >= (
        WEBAUTHN_CHALLENGE_GLOBAL_LIVE_MAX
    ):
        raise MetadataStoreError("WebAuthn challenge global live capacity reached")
    if int(user_live["count"] if user_live else 0) >= (
        WEBAUTHN_CHALLENGE_USER_LIVE_MAX
    ):
        raise MetadataStoreError("WebAuthn challenge user live capacity reached")
    retained = conn.execute(
        "SELECT COUNT(*) AS count FROM webauthn_challenges WHERE used_at IS NOT NULL"
    ).fetchone()
    if int(retained["count"] if retained else 0) >= WEBAUTHN_CHALLENGE_MAX_RETAINED:
        raise MetadataStoreError("WebAuthn challenge terminal capacity reached")


def create_oidc_session_binding_challenge(
    *,
    challenge: str,
    user_id: str,
    session_id: str,
    payload: dict[str, Any],
    ttl_seconds: int,
) -> dict[str, Any]:
    item_id = str(uuid.uuid4())
    if not 30 <= ttl_seconds <= 300:
        raise MetadataStoreError(
            "OIDC binding challenge TTL must be between 30 and 300 seconds"
        )
    with connect() as conn:
        _lock_webauthn_authority(conn)
        now = _metadata_utcnow(conn)
        now_s = now.isoformat()
        session = conn.execute(
            "SELECT id FROM oidc_browser_sessions "
            "WHERE id = ? AND user_id = ? AND status = 'pending_webauthn' "
            "AND expires_at > ? AND pending_expires_at > ?",
            (session_id, user_id, now_s, now_s),
        ).fetchone()
        if session is None:
            raise MetadataStoreError(
                "OIDC browser session is not eligible for a binding challenge"
            )
        _admit_webauthn_challenge(
            conn,
            now=now,
            challenge_type="oidc-session-binding",
            user_id=user_id,
            scope_key=session_id,
            replace_scope=True,
        )
        rate_window = (
            now - timedelta(seconds=_OIDC_BINDING_CHALLENGE_RATE_WINDOW_SECONDS)
        ).isoformat()
        recent = conn.execute(
            "SELECT COUNT(*) AS count FROM webauthn_challenges "
            "WHERE challenge_type = 'oidc-session-binding' "
            "AND user_id = ? AND created_at > ?",
            (user_id, rate_window),
        ).fetchone()
        if int(recent["count"] if recent else 0) >= _OIDC_BINDING_CHALLENGE_USER_RATE_MAX:
            raise MetadataStoreError("OIDC binding challenge rate limit reached")
        global_live = conn.execute(
            "SELECT COUNT(*) AS count FROM webauthn_challenges "
            "WHERE challenge_type = 'oidc-session-binding' "
            "AND used_at IS NULL AND expires_at > ?",
            (now_s,),
        ).fetchone()
        user_live = conn.execute(
            "SELECT COUNT(*) AS count FROM webauthn_challenges "
            "WHERE challenge_type = 'oidc-session-binding' AND user_id = ? "
            "AND used_at IS NULL AND expires_at > ?",
            (user_id, now_s),
        ).fetchone()
        if int(global_live["count"] if global_live else 0) >= (
            _OIDC_BINDING_CHALLENGE_GLOBAL_LIVE_MAX
        ):
            raise MetadataStoreError("OIDC binding challenge global capacity reached")
        if int(user_live["count"] if user_live else 0) >= (
            _OIDC_BINDING_CHALLENGE_USER_LIVE_MAX
        ):
            raise MetadataStoreError("OIDC binding challenge user capacity reached")
        expires_at = (now + timedelta(seconds=ttl_seconds)).isoformat()
        conn.execute(
            """
            INSERT INTO webauthn_challenges (
                id, challenge, challenge_type, user_id, scope_key,
                approval_request_id, payload_json, expires_at, created_at
            ) VALUES (?, ?, 'oidc-session-binding', ?, ?, NULL, ?, ?, ?)
            """,
            (
                item_id,
                challenge,
                user_id,
                session_id,
                dumps(payload),
                expires_at,
                now_s,
            ),
        )
        row = conn.execute(
            "SELECT * FROM webauthn_challenges WHERE id = ?", (item_id,)
        ).fetchone()
    return row_to_webauthn_challenge(row)


def create_webauthn_challenge(
    *,
    challenge: str,
    challenge_type: str,
    user_id: str,
    payload: dict[str, Any],
    approval_request_id: str | None = None,
    scope_key: str | None = None,
    ttl_seconds: int = 300,
) -> dict[str, Any]:
    item_id = str(uuid.uuid4())
    if not 30 <= ttl_seconds <= 300:
        raise MetadataStoreError(
            "WebAuthn challenge TTL must be between 30 and 300 seconds"
        )
    if (
        not isinstance(challenge, str)
        or re.fullmatch(r"[A-Za-z0-9_-]{32,128}", challenge) is None
    ):
        raise MetadataStoreError("WebAuthn challenge value is invalid")
    if not isinstance(challenge_type, str) or not 1 <= len(challenge_type) <= 64:
        raise MetadataStoreError("WebAuthn challenge type is invalid")
    if not isinstance(user_id, str) or not 1 <= len(user_id.encode("utf-8")) <= 512:
        raise MetadataStoreError("WebAuthn challenge user is invalid")
    if scope_key is not None and (
        not isinstance(scope_key, str)
        or not 1 <= len(scope_key.encode("utf-8")) <= 512
    ):
        raise MetadataStoreError("WebAuthn challenge scope is invalid")
    payload_json = dumps(payload)
    if len(payload_json.encode("utf-8")) > 64 * 1024:
        raise MetadataStoreError("WebAuthn challenge payload exceeds 64 KiB")
    with connect() as conn:
        _lock_webauthn_authority(conn)
        now = _metadata_utcnow(conn)
        now_s = now.isoformat()
        _admit_webauthn_challenge(
            conn,
            now=now,
            challenge_type=challenge_type,
            user_id=user_id,
            scope_key=scope_key,
            replace_scope=scope_key is not None,
        )
        expires_at = (now + timedelta(seconds=ttl_seconds)).isoformat()
        conn.execute(
            """
            INSERT INTO webauthn_challenges (
                id, challenge, challenge_type, user_id, scope_key,
                approval_request_id, payload_json, expires_at, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                item_id,
                challenge,
                challenge_type,
                user_id,
                scope_key,
                approval_request_id,
                payload_json,
                expires_at,
                now_s,
            ),
        )
        row = conn.execute(
            "SELECT * FROM webauthn_challenges WHERE id = ?", (item_id,)
        ).fetchone()
    return row_to_webauthn_challenge(row)


def row_to_webauthn_challenge(row: sqlite3.Row) -> dict[str, Any]:
    item = dict(row)
    item["payload"] = loads(item.pop("payload_json"), {})
    return item


def get_unused_webauthn_challenge(
    challenge: str,
    *,
    challenge_type: str | None = None,
    user_id: str | None = None,
) -> dict[str, Any] | None:
    clauses = ["challenge = ?", "used_at IS NULL", "expires_at > ?"]
    if challenge_type is not None:
        clauses.append("challenge_type = ?")
    if user_id is not None:
        clauses.append("user_id = ?")
    with connect() as conn:
        now_s = _metadata_utcnow(conn).isoformat()
        params: list[Any] = [challenge, now_s]
        if challenge_type is not None:
            params.append(challenge_type)
        if user_id is not None:
            params.append(user_id)
        row = conn.execute(
            f"SELECT * FROM webauthn_challenges WHERE {' AND '.join(clauses)}",
            params,
        ).fetchone()
    return row_to_webauthn_challenge(row) if row else None


def claim_webauthn_challenge(
    challenge: str,
    *,
    challenge_type: str,
    user_id: str,
    approval_request_id: str | None = None,
) -> dict[str, Any] | None:
    with connect() as conn:
        now_s = _metadata_utcnow(conn).isoformat()
        params = (
            now_s,
            challenge,
            challenge_type,
            user_id,
            approval_request_id,
            approval_request_id,
            now_s,
        )
        if isinstance(conn, PostgresMetadataConnection):
            row = conn.execute(
                """
                UPDATE webauthn_challenges
                SET used_at = ?
                WHERE challenge = ?
                  AND challenge_type = ?
                  AND user_id = ?
                  AND (
                    (CAST(? AS TEXT) IS NULL AND approval_request_id IS NULL)
                    OR approval_request_id = ?
                  )
                  AND used_at IS NULL
                  AND expires_at > ?
                RETURNING *
                """,
                params,
            ).fetchone()
            return row_to_webauthn_challenge(row) if row else None

        if not conn.in_transaction:
            conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            """
            SELECT * FROM webauthn_challenges
            WHERE challenge = ?
              AND challenge_type = ?
              AND user_id = ?
              AND ((CAST(? AS TEXT) IS NULL AND approval_request_id IS NULL) OR approval_request_id = ?)
              AND used_at IS NULL
              AND expires_at > ?
            """,
            (
                challenge,
                challenge_type,
                user_id,
                approval_request_id,
                approval_request_id,
                now_s,
            ),
        ).fetchone()
        if row is None:
            return None
        cur = conn.execute(
            """
            UPDATE webauthn_challenges
            SET used_at = ?
            WHERE id = ? AND used_at IS NULL AND expires_at > ?
            """,
            (now_s, row["id"], now_s),
        )
        if cur.rowcount != 1:
            return None
        claimed = conn.execute(
            "SELECT * FROM webauthn_challenges WHERE id = ?",
            (row["id"],),
        ).fetchone()
    return row_to_webauthn_challenge(claimed) if claimed else None


def mark_webauthn_challenge_used(challenge_id: str) -> None:
    with connect() as conn:
        now_s = _metadata_utcnow(conn).isoformat()
        conn.execute(
            "UPDATE webauthn_challenges SET used_at = ? WHERE id = ? AND used_at IS NULL",
            (now_s, challenge_id),
        )


def cache_gmail_message_ids(
    route_id: str, message_ids: list[str], source_url: str, ttl_seconds: int
) -> None:
    if not message_ids:
        return
    now = iso_now()
    expires = (utcnow() + timedelta(seconds=ttl_seconds)).isoformat()
    with connect() as conn:
        conn.executemany(
            """
            INSERT INTO gmail_message_cache (route_id, message_id, expires_at, source_url, created_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(route_id, message_id) DO UPDATE SET
                expires_at = excluded.expires_at,
                source_url = excluded.source_url,
                created_at = excluded.created_at
            """,
            [
                (route_id, message_id, expires, source_url, now)
                for message_id in message_ids
            ],
        )


def gmail_message_allowed(route_id: str, message_id: str) -> bool:
    now_s = iso_now()
    with connect() as conn:
        row = conn.execute(
            """
            SELECT message_id FROM gmail_message_cache
            WHERE route_id = ? AND message_id = ? AND expires_at > ?
            """,
            (route_id, message_id, now_s),
        ).fetchone()
    return row is not None


def prune_expired() -> None:
    now_s = iso_now()
    with connect() as conn:
        conn.execute("DELETE FROM gmail_message_cache WHERE expires_at <= ?", (now_s,))


def log_request(
    route_id: str | None,
    method: str,
    url: str,
    action: str,
    status_code: int | None = None,
    reason: str | None = None,
    event: dict[str, Any] | None = None,
) -> None:
    with connect() as conn:
        created_at = iso_now()
        conn.execute(
            """
            INSERT INTO request_logs (id, route_id, method, url, action, status_code, reason, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(uuid.uuid4()),
                route_id,
                method,
                url,
                action,
                status_code,
                reason,
                created_at,
            ),
        )
        audit_event = {
            "route_id": route_id,
            "method": method,
            "url": url,
            "action": action,
            "status_code": status_code,
            "reason": reason,
            "created_at": created_at,
        }
        if event:
            audit_event.update(event)
        append_audit_event(
            conn,
            event_type="proxy.request_decision",
            actor_type="proxy",
            actor_id=route_id,
            event=audit_event,
        )


def list_logs(limit: int = 100) -> list[dict[str, Any]]:
    with connect() as conn:
        rows = conn.execute(
            "SELECT * FROM request_logs ORDER BY created_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [dict(row) for row in rows]


def clear_logs() -> None:
    with connect() as conn:
        conn.execute("DELETE FROM request_logs")


def list_audit_events(limit: int = 100) -> list[dict[str, Any]]:
    if audit_uses_postgres():
        with _audit_pg_connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT id, event_type, actor_type, actor_id, event_json,
                           encrypted_canonical_event_json, prev_event_hash,
                           event_hash, created_at
                    FROM serverware_audit_events
                    ORDER BY sequence DESC
                    LIMIT %(limit)s
                    """,
                    {"limit": limit},
                )
                rows = cur.fetchall()
        items = []
        for row in rows:
            item = dict(row)
            item["event"] = loads(item.pop("event_json"), {})
            item.pop("encrypted_canonical_event_json", None)
            items.append(item)
        return items

    with connect() as conn:
        rows = conn.execute(
            "SELECT * FROM audit_events ORDER BY created_at DESC, id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    items = []
    for row in rows:
        item = dict(row)
        item["event"] = loads(item.pop("event_json"), {})
        item.pop("encrypted_canonical_event_json", None)
        items.append(item)
    return items


def _audit_item_from_row(row: Any) -> dict[str, Any]:
    item = dict(row)
    item["event"] = loads(item.pop("event_json"), {})
    item.pop("encrypted_canonical_event_json", None)
    return item


def _nested_field_values(value: Any, aliases: set[str]) -> list[Any]:
    values: list[Any] = []
    if isinstance(value, dict):
        for key, item in value.items():
            if str(key) in aliases:
                values.append(item)
            values.extend(_nested_field_values(item, aliases))
    elif isinstance(value, list):
        for item in value:
            values.extend(_nested_field_values(item, aliases))
    return values


def _stringify_audit_value(value: Any) -> str:
    if isinstance(value, (dict, list)):
        return dumps(value)
    return str(value)


def _audit_value_matches(value: Any, expected: str) -> bool:
    if value is None:
        return False
    if isinstance(value, list):
        return any(_audit_value_matches(item, expected) for item in value)
    if isinstance(value, dict):
        return any(_audit_value_matches(item, expected) for item in value.values())
    return _stringify_audit_value(value) == expected


AUDIT_SEARCH_ALIASES: dict[str, set[str]] = {
    "principal_id": {"principal_id", "principalId", "principal"},
    "route_id": {"route_id", "routeId"},
    "policy_hash": {
        "policy_hash",
        "policyHash",
        "policy_bundle_digest",
        "policyBundleDigest",
    },
    "credential_id": {
        "credential_id",
        "credentialId",
        "credential_ref",
        "credentialRef",
    },
    "credential_version": {"credential_version", "credentialVersion"},
    "approval_id": {
        "approval_id",
        "approvalId",
        "approval_request_id",
        "approvalRequestId",
    },
    "decision": {"decision", "action", "status", "reason", "consume_result", "result"},
    "attestation_measurement": {
        "attestation_measurement",
        "attestationMeasurement",
        "measurement",
        "runtime_manifest_digest",
        "runtimeManifestDigest",
        "source_tree_digest",
        "sourceTreeDigest",
        "data_plane_binary_digest",
        "dataPlaneBinaryDigest",
        "module_id",
        "moduleId",
        "pcr0",
        "pcr1",
        "pcr2",
    },
}


def _audit_item_matches(item: dict[str, Any], filters: dict[str, Any]) -> bool:
    event = item.get("event") or {}
    for field, expected in filters.items():
        if expected is None or expected == "":
            continue
        if field == "q":
            haystack = dumps(
                {
                    "event_type": item.get("event_type"),
                    "actor_type": item.get("actor_type"),
                    "actor_id": item.get("actor_id"),
                    "event": event,
                }
            )
            if str(expected) not in haystack:
                return False
            continue
        values = _nested_field_values(event, AUDIT_SEARCH_ALIASES[field])
        if not any(_audit_value_matches(value, str(expected)) for value in values):
            return False
    return True


def search_audit_events(
    *,
    limit: int = 100,
    scan_limit: int = 5000,
    event_type: str | None = None,
    actor_type: str | None = None,
    actor_id: str | None = None,
    principal_id: str | None = None,
    route_id: str | None = None,
    policy_hash: str | None = None,
    credential_id: str | None = None,
    credential_version: int | None = None,
    approval_id: str | None = None,
    decision: str | None = None,
    attestation_measurement: str | None = None,
    start: str | None = None,
    end: str | None = None,
    q: str | None = None,
) -> dict[str, Any]:
    limit = max(1, min(int(limit), 10000))
    scan_limit = max(limit, min(int(scan_limit), 50000))
    if audit_uses_postgres():
        conditions: list[str] = []
        params: dict[str, Any] = {"scan_limit": scan_limit}
        if event_type:
            conditions.append("event_type = %(event_type)s")
            params["event_type"] = event_type
        if actor_type:
            conditions.append("actor_type = %(actor_type)s")
            params["actor_type"] = actor_type
        if actor_id:
            conditions.append("actor_id = %(actor_id)s")
            params["actor_id"] = actor_id
        if start:
            conditions.append("created_at >= %(start)s")
            params["start"] = start
        if end:
            conditions.append("created_at <= %(end)s")
            params["end"] = end
        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        with _audit_pg_connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    f"SELECT COUNT(*)::bigint AS count FROM serverware_audit_events {where}",
                    params,
                )
                total_candidates = int(cur.fetchone()["count"])
                cur.execute(
                    f"""
                    SELECT id, event_type, actor_type, actor_id, event_json,
                           prev_event_hash, event_hash, created_at
                    FROM serverware_audit_events
                    {where}
                    ORDER BY sequence DESC
                    LIMIT %(scan_limit)s
                    """,
                    params,
                )
                rows = cur.fetchall()
    else:
        conditions = []
        params_list: list[Any] = []
        if event_type:
            conditions.append("event_type = ?")
            params_list.append(event_type)
        if actor_type:
            conditions.append("actor_type = ?")
            params_list.append(actor_type)
        if actor_id:
            conditions.append("actor_id = ?")
            params_list.append(actor_id)
        if start:
            conditions.append("created_at >= ?")
            params_list.append(start)
        if end:
            conditions.append("created_at <= ?")
            params_list.append(end)
        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        with connect() as conn:
            total_candidates = int(
                conn.execute(
                    f"SELECT COUNT(*) AS count FROM audit_events {where}",
                    tuple(params_list),
                ).fetchone()["count"]
            )
            rows = conn.execute(
                f"""
                SELECT * FROM audit_events
                {where}
                ORDER BY created_at DESC, id DESC
                LIMIT ?
                """,
                (*params_list, scan_limit),
            ).fetchall()
    items = [_audit_item_from_row(row) for row in rows]
    field_filters = {
        "principal_id": principal_id,
        "route_id": route_id,
        "policy_hash": policy_hash,
        "credential_id": credential_id,
        "credential_version": None
        if credential_version is None
        else str(credential_version),
        "approval_id": approval_id,
        "decision": decision,
        "attestation_measurement": attestation_measurement,
        "q": q,
    }
    matches = [item for item in items if _audit_item_matches(item, field_filters)]
    return {
        "ok": True,
        "backend": audit_store_backend_name(),
        "filters": {
            "event_type": event_type,
            "actor_type": actor_type,
            "actor_id": actor_id,
            "principal_id": principal_id,
            "route_id": route_id,
            "policy_hash": policy_hash,
            "credential_id": credential_id,
            "credential_version": credential_version,
            "approval_id": approval_id,
            "decision": decision,
            "attestation_measurement": attestation_measurement,
            "start": start,
            "end": end,
            "q": q,
        },
        "count": min(len(matches), limit),
        "matched_in_scan": len(matches),
        "scanned": len(items),
        "total_candidates": total_candidates,
        "complete": len(items) >= total_candidates,
        "items": matches[:limit],
    }


def export_audit_events_jsonl(
    *,
    limit: int = 1000,
    scan_limit: int = 50000,
    event_type: str | None = None,
    actor_type: str | None = None,
    actor_id: str | None = None,
    principal_id: str | None = None,
    route_id: str | None = None,
    policy_hash: str | None = None,
    credential_id: str | None = None,
    credential_version: int | None = None,
    approval_id: str | None = None,
    decision: str | None = None,
    attestation_measurement: str | None = None,
    start: str | None = None,
    end: str | None = None,
    q: str | None = None,
) -> str:
    result = search_audit_events(
        limit=limit,
        scan_limit=scan_limit,
        event_type=event_type,
        actor_type=actor_type,
        actor_id=actor_id,
        principal_id=principal_id,
        route_id=route_id,
        policy_hash=policy_hash,
        credential_id=credential_id,
        credential_version=credential_version,
        approval_id=approval_id,
        decision=decision,
        attestation_measurement=attestation_measurement,
        start=start,
        end=end,
        q=q,
    )
    chain = verify_audit_chain()
    header = {
        "kind": "serverware.auditExport.v1",
        "generated_at": iso_now(),
        "backend": result["backend"],
        "filters": result["filters"],
        "count": result["count"],
        "matched_in_scan": result["matched_in_scan"],
        "scanned": result["scanned"],
        "total_candidates": result["total_candidates"],
        "complete": result["complete"],
        "chain": {
            "ok": chain.get("ok"),
            "backend": chain.get("backend"),
            "ha": chain.get("ha"),
            "complete": chain.get("complete"),
            "count": chain.get("count"),
            "total": chain.get("total"),
            "head": chain.get("head"),
        },
    }
    lines = [dumps(header)]
    for index, item in enumerate(result["items"]):
        lines.append(
            dumps(
                {
                    "kind": "serverware.auditEvent.v1",
                    "export_index": index,
                    "event": item,
                }
            )
        )
    lines.append(
        dumps(
            {
                "kind": "serverware.auditExportEnd.v1",
                "count": result["count"],
                "complete": result["complete"],
                "chain_head": chain.get("head"),
            }
        )
    )
    return "\n".join(lines) + "\n"


def _verify_audit_rows(
    cursor: Any,
    *,
    total: int,
    selected_count: int,
    batch_size: int,
    backend: str,
    ha: bool,
    keyring: BoundSecretKeyring | None = None,
    require_current_rate_storage: bool = False,
) -> dict[str, Any]:
    previous_hash = None
    processed = 0
    common = {
        "backend": backend,
        "ha": ha,
        "serial_append": "pg_advisory_xact_lock" if ha else "sqlite_begin_immediate",
    }
    while rows := cursor.fetchmany(batch_size):
        for row in rows:
            index = processed
            processed += 1
            try:
                if (
                    require_current_rate_storage
                    and str(row["event_type"]) in _RATE_LIMIT_AUDIT_EVENT_TYPES
                    and _row_value(row, "storage_format_version")
                    != _AUDIT_STORAGE_FORMAT_VERSION
                ):
                    raise AuditStoreError("audit_storage_format_unsupported")
                encrypted_canonical_event_json = _row_value(
                    row, "encrypted_canonical_event_json"
                )
                if encrypted_canonical_event_json is not None and keyring is None:
                    try:
                        keyring = load_bound_secret_keyring()
                    except Exception as exc:
                        raise AuditStoreError(
                            "canonical_preimage_key_unavailable"
                        ) from exc
                canonical_event_json = _canonical_audit_event_json(
                    row, keyring=keyring
                )
            except AuditStoreError as exc:
                return {
                    **common,
                    "ok": False,
                    "error": str(exc),
                    "index": index,
                    "event_id": row["id"],
                    "complete": selected_count == total,
                    "count": selected_count,
                    "total": total,
                }
            if (
                len(str(row["event_json"]).encode("utf-8"))
                > _AUDIT_EVENT_JSON_STORED_MAX_BYTES
                or len(canonical_event_json.encode("utf-8"))
                > _AUDIT_EVENT_JSON_STORED_MAX_BYTES
                or (
                    encrypted_canonical_event_json is not None
                    and len(
                        str(encrypted_canonical_event_json).encode("utf-8")
                    )
                    > _AUDIT_EVENT_JSON_STORED_MAX_BYTES
                )
            ):
                return {
                    **common,
                    "ok": False,
                    "error": "event_size_exceeded",
                    "index": index,
                    "event_id": row["id"],
                    "complete": selected_count == total,
                    "count": selected_count,
                    "total": total,
                }
            expected = _audit_hash(
                event_id=row["id"],
                event_type=row["event_type"],
                actor_type=row["actor_type"],
                actor_id=row["actor_id"],
                event_json=canonical_event_json,
                prev_event_hash=row["prev_event_hash"],
                created_at=row["created_at"],
            )
            if row["prev_event_hash"] != previous_hash:
                return {
                    **common,
                    "ok": False,
                    "error": "prev_hash_mismatch",
                    "index": index,
                    "event_id": row["id"],
                    "complete": selected_count == total,
                    "count": selected_count,
                    "total": total,
                }
            if row["event_hash"] != expected:
                return {
                    **common,
                    "ok": False,
                    "error": "event_hash_mismatch",
                    "index": index,
                    "event_id": row["id"],
                    "complete": selected_count == total,
                    "count": selected_count,
                    "total": total,
                }
            previous_hash = row["event_hash"]
    if processed != selected_count:
        return {
            **common,
            "ok": False,
            "error": "row_count_mismatch",
            "complete": False,
            "count": processed,
            "total": total,
        }
    return {
        **common,
        "ok": True,
        "count": processed,
        "total": total,
        "complete": selected_count == total,
        "head": previous_hash,
    }


def verify_audit_chain(limit: int | None = None) -> dict[str, Any]:
    if audit_uses_postgres():
        with _audit_pg_connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"
                )
                cur.execute(
                    "SELECT COUNT(*)::bigint AS count, COALESCE(("
                    "SELECT version FROM serverware_store_migrations "
                    "WHERE migration = %s), 0)::bigint AS storage_gate_version "
                    "FROM serverware_audit_events",
                    (_AUDIT_STORAGE_REDACTION_MIGRATION,),
                )
                count_row = cur.fetchone()
                total = int(count_row["count"])
                storage_gate_version = int(
                    _row_value(count_row, "storage_gate_version", 0)
                )
                try:
                    storage_gate_complete = _migration_gate_complete(
                        storage_gate_version,
                        migration=_AUDIT_STORAGE_REDACTION_MIGRATION,
                    )
                except RuntimeError:
                    return {
                        "backend": "postgres",
                        "ha": True,
                        "serial_append": "pg_advisory_xact_lock",
                        "ok": False,
                        "error": "unsupported_storage_migration_version",
                        "storage_migration_version": storage_gate_version,
                        "complete": False,
                        "count": 0,
                        "total": total,
                    }
                size_query = """
                    SELECT COALESCE(MAX(event_json_bytes), 0)::bigint AS max_bytes,
                           COALESCE(MAX(storage_bytes), 0)::bigint AS max_storage_bytes
                    FROM (
                        SELECT octet_length(event_json) AS event_json_bytes,
                               GREATEST(
                                   octet_length(event_json),
                                   COALESCE(
                                       octet_length(encrypted_canonical_event_json), 0
                                   )
                               ) AS storage_bytes
                        FROM serverware_audit_events
                        ORDER BY sequence ASC
                """
                size_params: dict[str, Any] = {}
                if limit is not None:
                    size_query += " LIMIT %(limit)s"
                    size_params["limit"] = limit
                size_query += ") AS selected_audit_events"
                cur.execute(size_query, size_params)
                size_row = cur.fetchone()
                max_event_json_bytes = int(size_row["max_bytes"])
                max_storage_bytes = int(
                    _row_value(
                        size_row, "max_storage_bytes", max_event_json_bytes
                    )
                )
            selected_count = total if limit is None else min(total, limit)
            if max_event_json_bytes > _AUDIT_EVENT_JSON_STORED_MAX_BYTES:
                return {
                    "backend": "postgres",
                    "ha": True,
                    "serial_append": "pg_advisory_xact_lock",
                    "ok": False,
                    "error": "event_size_exceeded",
                    "complete": False,
                    "count": 0,
                    "total": total,
                    "max_event_json_bytes": max_event_json_bytes,
                }
            batch_size = _audit_verify_batch_size(max_storage_bytes)
            with conn.cursor(name="serverware_audit_verify") as cur:
                query = """
                    SELECT id, event_type, actor_type, actor_id, event_json,
                           encrypted_canonical_event_json, storage_format_version,
                           prev_event_hash,
                           event_hash, created_at
                    FROM serverware_audit_events
                    ORDER BY sequence ASC
                """
                params: dict[str, Any] = {}
                if limit is not None:
                    query += " LIMIT %(limit)s"
                    params["limit"] = limit
                cur.execute(query, params)
                return _verify_audit_rows(
                    cur,
                    total=total,
                    selected_count=selected_count,
                    batch_size=batch_size,
                    backend="postgres",
                    ha=True,
                    require_current_rate_storage=storage_gate_complete,
                )

    with connect() as conn:
        conn.execute("BEGIN")
        count_row = conn.execute(
            "SELECT COUNT(*) AS count, COALESCE((SELECT version FROM "
            "serverware_store_migrations WHERE migration = ?), 0) "
            "AS storage_gate_version FROM audit_events",
            (_AUDIT_STORAGE_REDACTION_MIGRATION,),
        ).fetchone()
        total = count_row["count"]
        storage_gate_version = int(count_row["storage_gate_version"])
        try:
            storage_gate_complete = _migration_gate_complete(
                storage_gate_version,
                migration=_AUDIT_STORAGE_REDACTION_MIGRATION,
            )
        except RuntimeError:
            return {
                "backend": "sqlite",
                "ha": False,
                "serial_append": "sqlite_begin_immediate",
                "ok": False,
                "error": "unsupported_storage_migration_version",
                "storage_migration_version": storage_gate_version,
                "complete": False,
                "count": 0,
                "total": total,
            }
        size_query = """
            SELECT COALESCE(MAX(event_json_bytes), 0) AS max_bytes,
                   COALESCE(MAX(storage_bytes), 0) AS max_storage_bytes
            FROM (
                SELECT length(CAST(event_json AS BLOB)) AS event_json_bytes,
                       CASE
                           WHEN length(CAST(event_json AS BLOB)) >= COALESCE(
                               length(CAST(encrypted_canonical_event_json AS BLOB)), 0
                           )
                           THEN length(CAST(event_json AS BLOB))
                           ELSE COALESCE(
                               length(CAST(encrypted_canonical_event_json AS BLOB)), 0
                           )
                       END AS storage_bytes
                FROM audit_events
                ORDER BY rowid ASC
        """
        size_params: tuple[Any, ...] = ()
        if limit is not None:
            size_query += " LIMIT ?"
            size_params = (limit,)
        size_query += ") AS selected_audit_events"
        size_row = conn.execute(size_query, size_params).fetchone()
        max_event_json_bytes = int(size_row["max_bytes"])
        max_storage_bytes = int(
            _row_value(size_row, "max_storage_bytes", max_event_json_bytes)
        )
        selected_count = total if limit is None else min(total, limit)
        if max_event_json_bytes > _AUDIT_EVENT_JSON_STORED_MAX_BYTES:
            return {
                "backend": "sqlite",
                "ha": False,
                "serial_append": "sqlite_begin_immediate",
                "ok": False,
                "error": "event_size_exceeded",
                "complete": False,
                "count": 0,
                "total": total,
                "max_event_json_bytes": max_event_json_bytes,
            }
        batch_size = _audit_verify_batch_size(max_storage_bytes)
        query = "SELECT * FROM audit_events ORDER BY rowid ASC"
        params: tuple[Any, ...] = ()
        if limit is not None:
            query += " LIMIT ?"
            params = (limit,)
        cursor = conn.execute(query, params)
        return _verify_audit_rows(
            cursor,
            total=total,
            selected_count=selected_count,
            batch_size=batch_size,
            backend="sqlite",
            ha=False,
            require_current_rate_storage=storage_gate_complete,
        )


def audit_store_status() -> dict[str, Any]:
    name = audit_store_backend_name()
    if name != "postgres":
        verification = verify_audit_chain()
        return {
            "backend": "sqlite",
            "ha": False,
            "events": int(verification.get("total") or 0),
            "head": verification.get("head"),
        }
    with _audit_pg_connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT COUNT(*)::bigint AS events
                FROM serverware_audit_events
                """
            )
            counts = cur.fetchone()
            cur.execute(
                """
                SELECT event_hash, created_at
                FROM serverware_audit_events
                ORDER BY sequence DESC
                LIMIT 1
                """
            )
            latest = cur.fetchone()
    return {
        "backend": "postgres",
        "ha": True,
        "serial_append": "pg_advisory_xact_lock",
        "events": int((counts or {}).get("events") or 0),
        "head": (latest or {}).get("event_hash"),
        "latest_created_at": (latest or {}).get("created_at"),
    }


def metadata_store_status() -> dict[str, Any]:
    backend = metadata_store_backend_name()
    tables = [
        "credentials",
        "pending_oauth_credentials",
        "setup_sessions",
        "setup_session_evidence",
        "setup_session_events",
        "metadata_audit_outbox",
        "webauthn_trust_publications",
        "oidc_login_states",
        "oidc_browser_sessions",
        "oauth_revocation_work",
        "routes",
        "approval_requests",
        "approval_review_receipts",
        "control_plane_approvals",
        "webauthn_credentials",
        "webauthn_challenges",
        "webauthn_recovery_ceremonies",
        "webauthn_recovery_root_state",
        "webauthn_recovery_revocations",
        "gmail_message_cache",
        "request_logs",
        "rate_limit_counters",
        "release_authorization_attempts",
        "release_authorization_quota_reservations",
        "release_authorization_events",
    ]
    counts: dict[str, int] = {}
    with connect() as conn:
        for table in tables:
            row = conn.execute(f"SELECT COUNT(*) AS count FROM {table}").fetchone()
            counts[table] = int(row["count"] if row else 0)
    return {
        "backend": backend,
        "ha": backend == "postgres",
        "tables": counts,
        "atomic_release_writer": release_authorization_writer_status(),
    }
