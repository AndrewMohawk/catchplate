from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
import re
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from serverware import grants
from serverware.config import (
    AUDIT_STORE_BACKEND,
    AUDIT_STORE_CONNECT_TIMEOUT_SECONDS,
    AUDIT_STORE_POSTGRES_DSN,
    DB_PATH,
    METADATA_STORE_BACKEND,
    METADATA_STORE_CONNECT_TIMEOUT_SECONDS,
    METADATA_STORE_POSTGRES_DSN,
    RBAC_BINDINGS_PATH,
    ensure_data_dirs,
)
from serverware.crypto import decrypt_secret_envelope, encrypt_secret_envelope, load_master_key


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso_now() -> str:
    return utcnow().isoformat()


def dumps(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), sort_keys=True)


def loads(value: str | None, fallback: Any) -> Any:
    if not value:
        return fallback
    return json.loads(value)


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


class AuditStoreError(RuntimeError):
    pass


class MetadataStoreError(RuntimeError):
    pass


class RateLimitStoreError(RuntimeError):
    pass


class RBACBindingStoreError(RuntimeError):
    pass


class ManagedOAuthCredentialError(ValueError):
    pass


_AUDIT_CHAIN_LOCK_KEY = 0x5357524155444348
_CREDENTIAL_LEASE_REPLAY_LOCK_KEY = 0x5357524C45415345
_CREDENTIAL_LEASE_REPLAY_MAX = 10_000
_CREDENTIAL_LEASE_REPLAY_RETENTION_MS = 24 * 60 * 60 * 1000
_CREDENTIAL_METADATA_MAX_BYTES = 16 * 1024
_CREDENTIAL_METADATA_MAX_KEYS = 128
_CREDENTIAL_METADATA_MAX_DEPTH = 8
_CREDENTIAL_SECRET_MAX_BYTES = 1024 * 1024
_PENDING_APPROVAL_CREATION_LOCK_KEY = 0x53575250454E4447
_POLICY_HIGH_WATER_LOCK_KEY = 0x535752504F4C4943
_PENDING_APPROVAL_MAX_COUNT = 10_000
_PENDING_APPROVAL_MAX_PAYLOAD_BYTES = 64 * 1024
_GRANT_ATTEMPT_ID_MAX_BYTES = 256
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


def audit_store_backend_name() -> str:
    if AUDIT_STORE_BACKEND in {"", "sqlite", "local"}:
        return "sqlite"
    if AUDIT_STORE_BACKEND in {"postgres", "postgresql"}:
        return "postgres"
    raise AuditStoreError(f"unsupported audit store backend: {AUDIT_STORE_BACKEND}")


def audit_uses_postgres() -> bool:
    return audit_store_backend_name() == "postgres"


def metadata_store_backend_name() -> str:
    if METADATA_STORE_BACKEND in {"", "sqlite", "local"}:
        return "sqlite"
    if METADATA_STORE_BACKEND in {"postgres", "postgresql"}:
        return "postgres"
    raise MetadataStoreError(f"unsupported metadata store backend: {METADATA_STORE_BACKEND}")


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
    if binding_status not in {"active", "deprovisioned"} or not isinstance(raw_roles, list):
        raise RBACBindingStoreError("RBAC subject binding is invalid")
    if any(not isinstance(role, str) or not role or role != role.strip() for role in raw_roles):
        raise RBACBindingStoreError("RBAC subject roles are invalid")
    roles = sorted(set(raw_roles))
    if len(roles) != len(raw_roles) or set(roles) - _VALID_RBAC_ROLES:
        raise RBACBindingStoreError("RBAC subject roles are invalid")
    if (binding_status == "active" and not roles) or (binding_status == "deprovisioned" and roles):
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
        raise MetadataStoreError("postgres metadata store requires psycopg[binary]") from exc
    return psycopg, dict_row


def _audit_pg_connect():
    if not AUDIT_STORE_POSTGRES_DSN:
        raise AuditStoreError("SERVERWARE_AUDIT_STORE_POSTGRES_DSN is required for postgres audit store")
    psycopg, dict_row = _audit_psycopg()
    return psycopg.connect(
        AUDIT_STORE_POSTGRES_DSN,
        connect_timeout=AUDIT_STORE_CONNECT_TIMEOUT_SECONDS,
        row_factory=dict_row,
    )


def _metadata_pg_connect_raw():
    if not METADATA_STORE_POSTGRES_DSN:
        raise MetadataStoreError("SERVERWARE_METADATA_STORE_POSTGRES_DSN is required for postgres metadata store")
    psycopg, dict_row = _metadata_psycopg()
    return psycopg.connect(
        METADATA_STORE_POSTGRES_DSN,
        connect_timeout=METADATA_STORE_CONNECT_TIMEOUT_SECONDS,
        row_factory=dict_row,
    )


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
            int(row["grant_max_uses"])
            if row["grant_max_uses"] is not None
            else None
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


def init_audit_store() -> None:
    if not audit_uses_postgres():
        return
    with _audit_pg_connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS serverware_audit_events (
                    sequence BIGSERIAL PRIMARY KEY,
                    id TEXT NOT NULL UNIQUE,
                    event_type TEXT NOT NULL,
                    actor_type TEXT NOT NULL,
                    actor_id TEXT,
                    event_json TEXT NOT NULL,
                    prev_event_hash TEXT,
                    event_hash TEXT NOT NULL UNIQUE,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS serverware_audit_events_created_at_desc
                    ON serverware_audit_events (created_at DESC, sequence DESC);
                CREATE INDEX IF NOT EXISTS serverware_audit_events_type_created_at
                    ON serverware_audit_events (event_type, created_at DESC);
                """
            )


def _append_sqlite_audit_event(
    conn: sqlite3.Connection,
    *,
    event_type: str,
    actor_type: str,
    actor_id: str | None,
    event: dict[str, Any],
) -> dict[str, Any]:
    if not conn.in_transaction:
        conn.execute("BEGIN IMMEDIATE")
    event_id = str(uuid.uuid4())
    created_at = iso_now()
    event_json = dumps(event)
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
            prev_event_hash, event_hash, created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (event_id, event_type, actor_type, actor_id, event_json, prev_hash, event_hash, created_at),
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
) -> dict[str, Any]:
    event_id = str(uuid.uuid4())
    event_json = dumps(event)
    with _audit_pg_connect() as conn:
        with conn.transaction():
            with conn.cursor() as cur:
                cur.execute("SELECT pg_advisory_xact_lock(%(lock_key)s)", {"lock_key": _AUDIT_CHAIN_LOCK_KEY})
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
                        prev_event_hash, event_hash, created_at
                    )
                    VALUES (
                        %(id)s, %(event_type)s, %(actor_type)s, %(actor_id)s, %(event_json)s,
                        %(prev_event_hash)s, %(event_hash)s, %(created_at)s
                    )
                    """,
                    {
                        "id": event_id,
                        "event_type": event_type,
                        "actor_type": actor_type,
                        "actor_id": actor_id,
                        "event_json": event_json,
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
    conn: sqlite3.Connection,
    *,
    event_type: str,
    actor_type: str,
    actor_id: str | None,
    event: dict[str, Any],
) -> dict[str, Any]:
    if audit_uses_postgres():
        return _append_postgres_audit_event(
            event_type=event_type,
            actor_type=actor_type,
            actor_id=actor_id,
            event=event,
        )
    return _append_sqlite_audit_event(
        conn,
        event_type=event_type,
        actor_type=actor_type,
        actor_id=actor_id,
        event=event,
    )


def record_audit_event(event_type: str, event: dict[str, Any], actor_type: str = "admin", actor_id: str = "admin") -> dict[str, Any]:
    if audit_uses_postgres():
        return _append_postgres_audit_event(
            event_type=event_type,
            actor_type=actor_type,
            actor_id=actor_id,
            event=event,
        )
    with connect() as conn:
        return append_audit_event(
            conn,
            event_type=event_type,
            actor_type=actor_type,
            actor_id=actor_id,
            event=event,
        )


def connect() -> Any:
    ensure_data_dirs()
    if metadata_uses_postgres():
        return PostgresMetadataConnection(_metadata_pg_connect_raw())
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db(path: Path = DB_PATH) -> None:
    ensure_data_dirs()
    grants.init_grant_store()
    init_audit_store()
    with connect() as conn:
        conn.executescript(
            """
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
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

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
                approval_authn TEXT
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
                uses_remaining INTEGER NOT NULL,
                valid_from TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                consumed_at TEXT,
                consumed_by_flow_id TEXT,
                created_at TEXT NOT NULL
            );

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
                window_start_epoch_ms BIGINT NOT NULL,
                window_seconds INTEGER NOT NULL,
                max_count INTEGER NOT NULL,
                count INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS credential_lease_nonces (
                recipient_key_id TEXT NOT NULL,
                nonce_sha256 TEXT NOT NULL,
                expires_at_epoch_ms BIGINT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (recipient_key_id, nonce_sha256)
            );

            CREATE INDEX IF NOT EXISTS credential_lease_nonces_expiry
                ON credential_lease_nonces (expires_at_epoch_ms);

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
                revoked_at TEXT
            );

            CREATE TABLE IF NOT EXISTS webauthn_challenges (
                id TEXT PRIMARY KEY,
                challenge TEXT NOT NULL UNIQUE,
                challenge_type TEXT NOT NULL,
                user_id TEXT NOT NULL,
                approval_request_id TEXT,
                payload_json TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                used_at TEXT,
                created_at TEXT NOT NULL
            );
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
        _ensure_column(conn, "approval_requests", "grant_ttl_seconds", "INTEGER")
        _ensure_column(conn, "approval_requests", "grant_max_uses", "INTEGER")
        _ensure_column(conn, "approval_requests", "approved_by", "TEXT")
        _ensure_column(conn, "approval_requests", "approval_authn", "TEXT")
        _ensure_column(conn, "approval_requests", "approval_challenge_id", "TEXT")
        _ensure_column(conn, "approval_requests", "pending_key", "TEXT")
        _ensure_column(conn, "control_plane_approvals", "request_json", "TEXT NOT NULL DEFAULT '{}'")
        _ensure_column(conn, "control_plane_approvals", "approved_by", "TEXT")
        _ensure_column(conn, "control_plane_approvals", "approved_at", "TEXT")
        _ensure_column(conn, "control_plane_approvals", "consumed_by", "TEXT")
        _ensure_column(conn, "control_plane_approvals", "consumed_at", "TEXT")
        _ensure_column(conn, "control_plane_approvals", "decision_note", "TEXT")
        _ensure_column(conn, "control_plane_approvals", "approval_authn", "TEXT")
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
        _ensure_column(conn, "credentials", "credential_version", "INTEGER NOT NULL DEFAULT 1")
        _ensure_column(conn, "credentials", "secret_updated_at", "TEXT")
        _ensure_column(conn, "webauthn_credentials", "attestation_fmt", "TEXT")
        _ensure_column(conn, "webauthn_credentials", "attestation_trusted", "INTEGER NOT NULL DEFAULT 0")
        _ensure_column(conn, "webauthn_credentials", "attestation_trust_path", "TEXT NOT NULL DEFAULT '[]'")
        _ensure_column(conn, "webauthn_credentials", "attestation_leaf_sha256", "TEXT")
        _ensure_column(conn, "webauthn_credentials", "attestation_root_sha256", "TEXT")
        _ensure_column(conn, "webauthn_credentials", "attestation_trust_bundle_digest", "TEXT")
        _ensure_column(conn, "webauthn_credentials", "attestation_trust_bundle_sequence", "INTEGER")
        _ensure_column(conn, "webauthn_credentials", "attestation_verified_at", "TEXT")
        for row in conn.execute("SELECT id, credential_version FROM credentials").fetchall():
            _record_credential_generation(conn, str(row["id"]), int(row["credential_version"] or 1))

def _ensure_column(conn: Any, table: str, column: str, decl: str) -> None:
    if isinstance(conn, PostgresMetadataConnection):
        row = conn.execute(
            """
            SELECT 1
            FROM information_schema.columns
            WHERE table_schema = current_schema()
              AND table_name = ?
              AND column_name = ?
            """,
            (table, column),
        ).fetchone()
        if not row:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {decl}")
        return
    columns = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}
    if column not in columns:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {decl}")


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
    if not isinstance(policy_hash, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", policy_hash):
        raise MetadataStoreError("policy hash must be a canonical SHA-256 digest")

    now_s = iso_now()
    with connect() as conn:
        if isinstance(conn, PostgresMetadataConnection):
            conn.execute("SELECT pg_advisory_xact_lock(?)", (_POLICY_HIGH_WATER_LOCK_KEY,))
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
                if sequence != current_sequence or rollback_epoch != current_rollback_epoch:
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
    item.pop("encrypted_secret", None)
    item.pop("encrypted_dek", None)
    item.pop("secret_nonce", None)
    item.pop("secret_ciphertext", None)
    if include_secret:
        item["secret"] = decrypt_secret_envelope(row)
    return item


def _encrypted_secret_placeholder() -> str:
    return "envelope:v2"


def _envelope_values(item_id: str, secret: str, credential_version: int) -> dict[str, Any]:
    encrypted = encrypt_secret_envelope(secret, credential_id=item_id, credential_version=credential_version)
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
                if not isinstance(key, str) or not key or len(key.encode("utf-8")) > 256:
                    raise ValueError("credential metadata keys must be non-empty strings up to 256 bytes")
                compact = "".join(character for character in key.strip().lower() if character.isalnum())
                if compact in _SENSITIVE_CREDENTIAL_METADATA_KEYS_COMPACT or compact.endswith(
                    _SENSITIVE_CREDENTIAL_METADATA_SUFFIXES
                ):
                    raise ValueError(f"credential metadata key {key!r} may contain secret material")
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
        raise ManagedOAuthCredentialError("OAuth credential is not managed by the verified provider flow")
    if metadata.get("provider_identity_verified") is not True:
        raise ManagedOAuthCredentialError("OAuth credential provider identity is not verified")
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


def _credential_mutation_lock_key(item_id: str) -> int:
    digest = hashlib.sha256(f"serverware:credential-mutation:{item_id}".encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big", signed=True)


def _oauth_refresh_lock_key(item_id: str) -> int:
    digest = hashlib.sha256(f"serverware:oauth-refresh:{item_id}".encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big", signed=True)


@contextlib.contextmanager
def oauth_refresh_lock(item_id: str):
    if metadata_uses_postgres():
        conn = _metadata_pg_connect_raw()
        conn.autocommit = True
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT pg_advisory_lock(%s)", (_oauth_refresh_lock_key(item_id),))
            yield
        finally:
            try:
                with conn.cursor() as cur:
                    cur.execute("SELECT pg_advisory_unlock(%s)", (_oauth_refresh_lock_key(item_id),))
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
        conn.execute("SELECT pg_advisory_xact_lock(?)", (_credential_mutation_lock_key(item_id),))
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
            conn.execute("SELECT pg_advisory_xact_lock(?)", (_CREDENTIAL_LEASE_REPLAY_LOCK_KEY,))
        elif not conn.in_transaction:
            conn.execute("BEGIN IMMEDIATE")
        conn.execute(
            "DELETE FROM credential_lease_nonces WHERE expires_at_epoch_ms <= ?",
            (now_epoch_ms,),
        )
        count = conn.execute("SELECT COUNT(*) AS count FROM credential_lease_nonces").fetchone()
        if int(count["count"]) >= _CREDENTIAL_LEASE_REPLAY_MAX:
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
    return None


def _needs_envelope_migration(row: sqlite3.Row) -> bool:
    return not row["encrypted_dek"] or not row["secret_nonce"] or not row["secret_ciphertext"]


def create_credential(name: str, kind: str, secret: str, metadata: dict[str, Any] | None = None) -> dict[str, Any]:
    secret = validate_credential_secret(secret)
    metadata = validate_credential_metadata(metadata)
    item_id = str(uuid.uuid4())
    now = iso_now()
    with connect() as conn:
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
                now,
                now,
            ),
        )
        row = conn.execute("SELECT * FROM credentials WHERE id = ?", (item_id,)).fetchone()
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
        existing = conn.execute("SELECT * FROM credentials WHERE id = ?", (item_id,)).fetchone()
        if existing:
            existing_metadata = loads(existing["metadata"], {})
            if existing["kind"] == "oauth2" or (
                isinstance(existing_metadata, dict) and existing_metadata.get("oauth") is True
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
        row = conn.execute("SELECT * FROM credentials WHERE id = ?", (item_id,)).fetchone()
    return row_to_credential(row)


def update_credential(item_id: str, payload: dict[str, Any]) -> dict[str, Any] | None:
    if "secret" in payload and payload["secret"] is not None:
        payload = {**payload, "secret": validate_credential_secret(payload["secret"])}
    if "metadata" in payload:
        payload = {**payload, "metadata": validate_credential_metadata(payload["metadata"])}
    if ("secret" in payload and payload["secret"] is not None) or "metadata" in payload:
        load_master_key()
    with connect() as conn:
        _lock_credential_mutation(conn, item_id)
        current = conn.execute("SELECT * FROM credentials WHERE id = ?", (item_id,)).fetchone()
        if not current:
            return None
        current_metadata = loads(current["metadata"], {})
        if (current["kind"] == "oauth2" or current_metadata.get("oauth") is True) and any(
            field in payload for field in ("kind", "secret", "metadata")
        ):
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
        if ("secret" in payload and payload["secret"] is not None) or "metadata" in payload:
            current_secret = decrypt_secret_envelope(current)
            next_secret = payload.get("secret") if payload.get("secret") is not None else current_secret
            secret_changed = current_secret != next_secret
            metadata_changed = "metadata" in payload and loads(current["metadata"], {}) != payload["metadata"]
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
        row = conn.execute("SELECT * FROM credentials WHERE id = ?", (item_id,)).fetchone()
    return row_to_credential(row) if row else None


def update_credential_secret_if_version(
    item_id: str,
    *,
    expected_version: int,
    secret: str,
    metadata: dict[str, Any],
) -> tuple[dict[str, Any] | None, bool]:
    secret = validate_credential_secret(secret)
    metadata = validate_credential_metadata(metadata)
    if expected_version < 1:
        raise ValueError("expected credential version must be positive")
    load_master_key()
    with connect() as conn:
        _lock_credential_mutation(conn, item_id)
        current = conn.execute("SELECT * FROM credentials WHERE id = ?", (item_id,)).fetchone()
        if not current:
            return None, False
        current_version = int(current["credential_version"] or 1)
        if current_version != expected_version:
            return row_to_credential(current, include_secret=True), False
        current_secret = decrypt_secret_envelope(current)
        current_metadata = loads(current["metadata"], {})
        if current["kind"] == "oauth2" or current_metadata.get("oauth") is True:
            current_identity = validate_managed_oauth_identity(current_metadata)
            next_identity = validate_managed_oauth_identity(metadata)
            if next_identity != current_identity:
                raise ManagedOAuthCredentialError(
                    "OAuth refresh cannot change the verified provider account identity"
                )
        if current_secret == secret and current_metadata == metadata:
            return row_to_credential(current, include_secret=True), False

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
        row = conn.execute("SELECT * FROM credentials WHERE id = ?", (item_id,)).fetchone()
    return (row_to_credential(row, include_secret=True) if row else None), True


def get_credential(item_id: str, include_secret: bool = False) -> dict[str, Any] | None:
    with connect() as conn:
        row = conn.execute("SELECT * FROM credentials WHERE id = ?", (item_id,)).fetchone()
    return row_to_credential(row, include_secret) if row else None


@contextlib.contextmanager
def credential_lease_snapshot(item_id: str):
    """Hold the credential mutation lock while a lease is assembled and encrypted."""
    load_master_key()
    with connect() as conn:
        _lock_credential_mutation(conn, item_id)
        row = conn.execute("SELECT * FROM credentials WHERE id = ?", (item_id,)).fetchone()
        yield row_to_credential(row, include_secret=True) if row else None


def list_credentials() -> list[dict[str, Any]]:
    with connect() as conn:
        rows = conn.execute("SELECT * FROM credentials ORDER BY created_at DESC").fetchall()
    return [row_to_credential(row) for row in rows]


def delete_credential(item_id: str) -> bool:
    with connect() as conn:
        _lock_credential_mutation(conn, item_id)
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
        existing = conn.execute("SELECT id FROM routes WHERE id = ?", (item_id,)).fetchone()
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
    item["canonical_request"] = loads(item.get("canonical_request"), None)
    item["redacted_display"] = loads(item.get("redacted_display"), None)
    item["approval_authn"] = loads(item.get("approval_authn"), None)
    return item


def row_to_control_plane_approval(row: sqlite3.Row) -> dict[str, Any]:
    item = dict(row)
    item["request"] = loads(item.pop("request_json", None), {})
    item["approval_authn"] = loads(item.get("approval_authn"), None)
    return item


def ensure_control_plane_approval(
    *,
    action: str,
    resource_id: str | None,
    payload_digest: str,
    requester_id: str,
    request: dict[str, Any],
    ttl_seconds: int,
) -> dict[str, Any]:
    now = utcnow()
    now_s = now.isoformat()
    expires_at = (now + timedelta(seconds=ttl_seconds)).isoformat()
    resource_clause = "resource_id IS NULL" if resource_id is None else "resource_id = ?"
    resource_args: tuple[Any, ...] = () if resource_id is None else (resource_id,)
    with connect() as conn:
        existing = conn.execute(
            f"""
            SELECT * FROM control_plane_approvals
            WHERE action = ?
              AND {resource_clause}
              AND payload_digest = ?
              AND requester_id = ?
              AND status IN ('pending', 'approved')
              AND expires_at > ?
            ORDER BY requested_at DESC
            LIMIT 1
            """,
            (action, *resource_args, payload_digest, requester_id, now_s),
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
            (item_id, action, resource_id, payload_digest, requester_id, now_s, expires_at, dumps(request)),
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
        row = conn.execute("SELECT * FROM control_plane_approvals WHERE id = ?", (item_id,)).fetchone()
    return row_to_control_plane_approval(row)


def get_control_plane_approval(item_id: str) -> dict[str, Any] | None:
    with connect() as conn:
        row = conn.execute("SELECT * FROM control_plane_approvals WHERE id = ?", (item_id,)).fetchone()
    return row_to_control_plane_approval(row) if row else None


def approve_control_plane_approval(
    item_id: str,
    *,
    actor_id: str,
    note: str | None = None,
    authn: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    now_s = iso_now()
    with connect() as conn:
        existing = conn.execute("SELECT * FROM control_plane_approvals WHERE id = ?", (item_id,)).fetchone()
        if not existing:
            return None
        if existing["status"] != "pending" or existing["expires_at"] <= now_s:
            return None
        if existing["requester_id"] == actor_id:
            return None
        cur = conn.execute(
            """
            UPDATE control_plane_approvals
            SET status = 'approved',
                approved_by = ?,
                approved_at = ?,
                decision_note = ?,
                approval_authn = ?
            WHERE id = ? AND status = 'pending' AND expires_at > ?
            """,
            (actor_id, now_s, note, dumps(authn or {}), item_id, now_s),
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
                "approval_authn": authn or {},
                "note": note,
            },
        )
        row = conn.execute("SELECT * FROM control_plane_approvals WHERE id = ?", (item_id,)).fetchone()
    return row_to_control_plane_approval(row) if row else None


def consume_control_plane_approval(
    item_id: str,
    *,
    action: str,
    resource_id: str | None,
    payload_digest: str,
    actor_id: str,
) -> dict[str, Any]:
    now_s = iso_now()
    with connect() as conn:
        existing = conn.execute("SELECT * FROM control_plane_approvals WHERE id = ?", (item_id,)).fetchone()
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
        cur = conn.execute(
            """
            UPDATE control_plane_approvals
            SET status = 'consumed',
                consumed_by = ?,
                consumed_at = ?
            WHERE id = ? AND status = 'approved' AND expires_at > ?
            """,
            (actor_id, now_s, item_id, now_s),
        )
        if cur.rowcount != 1:
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
            },
        )
        row = conn.execute("SELECT * FROM control_plane_approvals WHERE id = ?", (item_id,)).fetchone()
    return {"ok": True, "approval": row_to_control_plane_approval(row)}


def deny_control_plane_approval(item_id: str, *, actor_id: str, note: str | None = None) -> dict[str, Any] | None:
    now_s = iso_now()
    with connect() as conn:
        existing = conn.execute("SELECT * FROM control_plane_approvals WHERE id = ?", (item_id,)).fetchone()
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
        row = conn.execute("SELECT * FROM control_plane_approvals WHERE id = ?", (item_id,)).fetchone()
    return row_to_control_plane_approval(row) if row else None


def list_control_plane_approvals(status: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
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


def create_approval_request(route_id: str, method: str, url: str, ttl_seconds: int = 300) -> dict[str, Any]:
    if not 1 <= ttl_seconds <= 3600:
        raise MetadataStoreError("pending approval ttl_seconds must be between 1 and 3600")
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
        row = conn.execute("SELECT * FROM approval_requests WHERE id = ?", (item_id,)).fetchone()
    return row_to_approval(row)


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
    if not isinstance(canonical_request, dict) or not isinstance(redacted_display, dict):
        raise MetadataStoreError("pending approval review payloads must be JSON objects")
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
    now = utcnow()
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
    with connect() as conn:
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
                existing["canonical_request"] != canonical_json
                or existing["redacted_display"] != redacted_json
            ):
                raise MetadataStoreError(
                    "pending approval immutable review payload does not match existing request"
                )
            return row_to_approval(existing)
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
                url,
                now_s,
                expires,
                principal_id,
                credential_id,
                credential_version,
                policy_hash,
                request_digest,
                operation_digest,
                canonical_json,
                redacted_json,
                grant_ttl_seconds,
                grant_max_uses,
                pending_key,
            ),
        )
        row = conn.execute("SELECT * FROM approval_requests WHERE id = ?", (item_id,)).fetchone()
    return row_to_approval(row)


def _ensure_policy_route_reference(conn: Any, route_id: str) -> None:
    existing = conn.execute("SELECT id FROM routes WHERE id = ?", (route_id,)).fetchone()
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
        row = conn.execute("SELECT * FROM approval_requests WHERE id = ?", (item_id,)).fetchone()
    return row_to_approval(row) if row else None


def has_active_approval(route_id: str, url: str | None = None) -> bool:
    now_s = iso_now()
    args: list[Any] = [route_id, now_s]
    url_clause = ""
    if url is not None:
        url_clause = "AND url = ?"
        args.append(url)
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
) -> dict[str, Any] | None:
    now = utcnow()
    now_s = now.isoformat()
    approved_until = (now + timedelta(seconds=ttl_seconds)).isoformat()
    with connect() as conn:
        existing = conn.execute("SELECT * FROM approval_requests WHERE id = ?", (item_id,)).fetchone()
        if not existing:
            return None
        if existing["status"] != "pending" or existing["expires_at"] <= now_s:
            return None
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
            if (
                not isinstance(conn, PostgresMetadataConnection)
                or not grants.can_share_transaction(METADATA_STORE_POSTGRES_DSN)
            ):
                raise MetadataStoreError(
                    "postgres approval and grant stores must use the same DSN for atomic issuance"
                )
        approved_until = (now + timedelta(seconds=grant_ttl_seconds)).isoformat()
        cur = conn.execute(
            """
            UPDATE approval_requests
            SET status = 'approved',
                approved_until = ?,
                decision_note = ?,
                approved_by = ?,
                approval_authn = ?,
                approval_challenge_id = ?
            WHERE id = ? AND status = 'pending' AND expires_at > ?
            """,
            (approved_until, note, actor_id, dumps(authn or {}), challenge_id, item_id, now_s),
        )
        if cur.rowcount != 1:
            return None
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
                        valid_from, expires_at, created_at
                    )
                    VALUES (?, ?, 'active', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                "grant_max_uses": grant_max_uses,
                "grant_store_backend": (grant_result or {"backend": grants.backend_name()}).get("backend"),
                "grant_id": (grant_result or {}).get("id"),
                "note": note,
            },
        )
        row = conn.execute("SELECT * FROM approval_requests WHERE id = ?", (item_id,)).fetchone()
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
                grants.mark_consumption_audited(result["consumption_id"], audit["event_hash"])
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


def _rate_limit_retry_after(window_start_epoch_ms: int, window_seconds: int, now_epoch_ms: int) -> int:
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
        else _rate_limit_retry_after(window_start_epoch_ms, window_seconds, now_epoch_ms),
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
                        policy_hash, constraint_id, operation, window_start_epoch_ms,
                        window_seconds, max_count, count, created_at, updated_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        counter_key,
                        principal_id,
                        route_id,
                        credential_id,
                        credential_version,
                        policy_hash,
                        constraint_id,
                        operation,
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
            if expired or int(row["window_seconds"]) != window_seconds or int(row["max_count"]) != max_count:
                conn.execute(
                    """
                    UPDATE rate_limit_counters
                    SET principal_id = ?, route_id = ?, credential_id = ?, credential_version = ?,
                        policy_hash = ?, constraint_id = ?, operation = ?,
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
                        operation,
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
        if consume or expired or int(row["window_seconds"]) != window_seconds or int(row["max_count"]) != max_count:
            conn.execute(
                """
                UPDATE rate_limit_counters
                SET principal_id = ?, route_id = ?, credential_id = ?, credential_version = ?,
                    policy_hash = ?, constraint_id = ?, operation = ?,
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
                    operation,
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
    with _metadata_pg_connect_raw() as conn:
        with conn.transaction():
            with conn.cursor() as cur:
                if consume:
                    cur.execute(
                        """
                        INSERT INTO rate_limit_counters (
                            counter_key, principal_id, route_id, credential_id, credential_version,
                            policy_hash, constraint_id, operation, window_start_epoch_ms,
                            window_seconds, max_count, count, created_at, updated_at
                        )
                        VALUES (
                            %(counter_key)s, %(principal_id)s, %(route_id)s, %(credential_id)s,
                            %(credential_version)s, %(policy_hash)s, %(constraint_id)s, %(operation)s,
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
                            "operation": operation,
                            "window_start_epoch_ms": now_epoch_ms,
                            "window_seconds": window_seconds,
                            "max_count": max_count,
                            "created_at": now_s,
                            "updated_at": now_s,
                        },
                    )
                cur.execute(
                    """
                    SELECT counter_key, window_start_epoch_ms, window_seconds, max_count, count
                    FROM rate_limit_counters
                    WHERE counter_key = %(counter_key)s
                    FOR UPDATE
                    """,
                    {"counter_key": counter_key},
                )
                row = cur.fetchone()
                if row is None:
                    if consume:
                        raise RateLimitStoreError("postgres rate limit counter insert did not create a locked row")
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
                    if expired or int(row["window_seconds"]) != window_seconds or int(row["max_count"]) != max_count:
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
                                "operation": operation,
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
                if consume or expired or int(row["window_seconds"]) != window_seconds or int(row["max_count"]) != max_count:
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
                            "operation": operation,
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
        raise RateLimitStoreError("rate limit max_count and window_seconds must be positive")
    now_ms = int(now_epoch_ms if now_epoch_ms is not None else utcnow().timestamp() * 1000)
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
                "rate_limit.consumed" if result["allowed"] and consume else "rate_limit.denied",
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


def clear_rate_limit_counters(route_ids: list[str] | tuple[str, ...] | None = None) -> int:
    with connect() as conn:
        if route_ids is None:
            cur = conn.execute("DELETE FROM rate_limit_counters")
            return int(cur.rowcount or 0)
        deleted = 0
        for route_id in route_ids:
            cur = conn.execute("DELETE FROM rate_limit_counters WHERE route_id = ?", (route_id,))
            deleted += int(cur.rowcount or 0)
        return deleted


def deny_request(item_id: str, note: str | None = None, actor_id: str = "admin") -> dict[str, Any] | None:
    with connect() as conn:
        existing = conn.execute("SELECT * FROM approval_requests WHERE id = ?", (item_id,)).fetchone()
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
        row = conn.execute("SELECT * FROM approval_requests WHERE id = ?", (item_id,)).fetchone()
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


def list_similar_approvals(approval: dict[str, Any], limit: int = 5) -> list[dict[str, Any]]:
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
            WHERE {' AND '.join(clauses)}
            ORDER BY requested_at DESC
            LIMIT ?
            """,
            args,
        ).fetchall()
    return [row_to_approval(row) for row in rows]


def row_to_webauthn_credential(row: sqlite3.Row) -> dict[str, Any]:
    item = dict(row)
    item["transports"] = loads(item.get("transports"), [])
    item["attestation_trusted"] = bool(item.get("attestation_trusted"))
    item["attestation_trust_path"] = loads(item.get("attestation_trust_path"), [])
    return item


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
    now = iso_now()
    with connect() as conn:
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
            ON CONFLICT(credential_id) DO UPDATE SET
                user_id = excluded.user_id,
                label = excluded.label,
                public_key_cose = excluded.public_key_cose,
                sign_count = excluded.sign_count,
                aaguid = excluded.aaguid,
                authenticator_class = excluded.authenticator_class,
                attestation_fmt = excluded.attestation_fmt,
                attestation_trusted = excluded.attestation_trusted,
                attestation_trust_path = excluded.attestation_trust_path,
                attestation_leaf_sha256 = excluded.attestation_leaf_sha256,
                attestation_root_sha256 = excluded.attestation_root_sha256,
                attestation_trust_bundle_digest = excluded.attestation_trust_bundle_digest,
                attestation_trust_bundle_sequence = excluded.attestation_trust_bundle_sequence,
                attestation_verified_at = excluded.attestation_verified_at,
                transports = excluded.transports,
                dev_private_key_pem = excluded.dev_private_key_pem,
                updated_at = excluded.updated_at,
                revoked_at = NULL
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
                now,
                now,
            ),
        )
        row = conn.execute(
            "SELECT * FROM webauthn_credentials WHERE credential_id = ?",
            (credential_id,),
        ).fetchone()
    return row_to_webauthn_credential(row)


def get_webauthn_credential(credential_id: str) -> dict[str, Any] | None:
    with connect() as conn:
        row = conn.execute(
            "SELECT * FROM webauthn_credentials WHERE credential_id = ? AND revoked_at IS NULL",
            (credential_id,),
        ).fetchone()
    return row_to_webauthn_credential(row) if row else None


def list_webauthn_credentials(user_id: str | None = None) -> list[dict[str, Any]]:
    args: list[Any] = []
    where = "WHERE revoked_at IS NULL"
    if user_id:
        where += " AND user_id = ?"
        args.append(user_id)
    with connect() as conn:
        rows = conn.execute(
            f"SELECT * FROM webauthn_credentials {where} ORDER BY created_at DESC",
            args,
        ).fetchall()
    return [row_to_webauthn_credential(row) for row in rows]


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


def create_webauthn_challenge(
    *,
    challenge: str,
    challenge_type: str,
    user_id: str,
    payload: dict[str, Any],
    approval_request_id: str | None = None,
    ttl_seconds: int = 300,
) -> dict[str, Any]:
    item_id = str(uuid.uuid4())
    now = utcnow()
    now_s = now.isoformat()
    expires_at = (now + timedelta(seconds=ttl_seconds)).isoformat()
    with connect() as conn:
        conn.execute(
            """
            INSERT INTO webauthn_challenges (
                id, challenge, challenge_type, user_id, approval_request_id,
                payload_json, expires_at, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (item_id, challenge, challenge_type, user_id, approval_request_id, dumps(payload), expires_at, now_s),
        )
        row = conn.execute("SELECT * FROM webauthn_challenges WHERE id = ?", (item_id,)).fetchone()
    return row_to_webauthn_challenge(row)


def row_to_webauthn_challenge(row: sqlite3.Row) -> dict[str, Any]:
    item = dict(row)
    item["payload"] = loads(item.pop("payload_json"), {})
    return item


def get_unused_webauthn_challenge(challenge: str) -> dict[str, Any] | None:
    now_s = iso_now()
    with connect() as conn:
        row = conn.execute(
            """
            SELECT * FROM webauthn_challenges
            WHERE challenge = ? AND used_at IS NULL AND expires_at > ?
            """,
            (challenge, now_s),
        ).fetchone()
    return row_to_webauthn_challenge(row) if row else None


def claim_webauthn_challenge(
    challenge: str,
    *,
    challenge_type: str,
    user_id: str,
    approval_request_id: str | None = None,
) -> dict[str, Any] | None:
    now_s = iso_now()
    params = (
        now_s,
        challenge,
        challenge_type,
        user_id,
        approval_request_id,
        approval_request_id,
        now_s,
    )
    with connect() as conn:
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
        conn.execute(
            "UPDATE webauthn_challenges SET used_at = ? WHERE id = ? AND used_at IS NULL",
            (iso_now(), challenge_id),
        )


def cache_gmail_message_ids(route_id: str, message_ids: list[str], source_url: str, ttl_seconds: int) -> None:
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
            [(route_id, message_id, expires, source_url, now) for message_id in message_ids],
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
            (str(uuid.uuid4()), route_id, method, url, action, status_code, reason, created_at),
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
                           prev_event_hash, event_hash, created_at
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
        items.append(item)
    return items


def _audit_item_from_row(row: Any) -> dict[str, Any]:
    item = dict(row)
    item["event"] = loads(item.pop("event_json"), {})
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
    "policy_hash": {"policy_hash", "policyHash", "policy_bundle_digest", "policyBundleDigest"},
    "credential_id": {"credential_id", "credentialId", "credential_ref", "credentialRef"},
    "credential_version": {"credential_version", "credentialVersion"},
    "approval_id": {"approval_id", "approvalId", "approval_request_id", "approvalRequestId"},
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
                cur.execute(f"SELECT COUNT(*)::bigint AS count FROM serverware_audit_events {where}", params)
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
            total_candidates = int(conn.execute(f"SELECT COUNT(*) AS count FROM audit_events {where}", tuple(params_list)).fetchone()["count"])
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
        "credential_version": None if credential_version is None else str(credential_version),
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
    rows: list[Any],
    *,
    total: int,
    limit: int | None,
    backend: str,
    ha: bool,
) -> dict[str, Any]:
    previous_hash = None
    common = {
        "backend": backend,
        "ha": ha,
        "serial_append": "pg_advisory_xact_lock" if ha else "sqlite_begin_immediate",
    }
    for index, row in enumerate(rows):
        expected = _audit_hash(
            event_id=row["id"],
            event_type=row["event_type"],
            actor_type=row["actor_type"],
            actor_id=row["actor_id"],
            event_json=row["event_json"],
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
                "complete": limit is None or len(rows) == total,
                "count": len(rows),
                "total": total,
            }
        if row["event_hash"] != expected:
            return {
                **common,
                "ok": False,
                "error": "event_hash_mismatch",
                "index": index,
                "event_id": row["id"],
                "complete": limit is None or len(rows) == total,
                "count": len(rows),
                "total": total,
            }
        previous_hash = row["event_hash"]
    return {
        **common,
        "ok": True,
        "count": len(rows),
        "total": total,
        "complete": limit is None or len(rows) == total,
        "head": previous_hash,
    }


def verify_audit_chain(limit: int | None = None) -> dict[str, Any]:
    if audit_uses_postgres():
        with _audit_pg_connect() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT COUNT(*)::bigint AS count FROM serverware_audit_events")
                total = int(cur.fetchone()["count"])
                query = """
                    SELECT id, event_type, actor_type, actor_id, event_json,
                           prev_event_hash, event_hash, created_at
                    FROM serverware_audit_events
                    ORDER BY sequence ASC
                """
                params: dict[str, Any] = {}
                if limit is not None:
                    query += " LIMIT %(limit)s"
                    params["limit"] = limit
                cur.execute(query, params)
                rows = cur.fetchall()
        return _verify_audit_rows(rows, total=total, limit=limit, backend="postgres", ha=True)

    with connect() as conn:
        total = conn.execute("SELECT COUNT(*) AS count FROM audit_events").fetchone()["count"]
        query = "SELECT * FROM audit_events ORDER BY rowid ASC"
        params: tuple[Any, ...] = ()
        if limit is not None:
            query += " LIMIT ?"
            params = (limit,)
        rows = conn.execute(query, params).fetchall()
    return _verify_audit_rows(list(rows), total=total, limit=limit, backend="sqlite", ha=False)


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
        "routes",
        "approval_requests",
        "control_plane_approvals",
        "webauthn_credentials",
        "webauthn_challenges",
        "gmail_message_cache",
        "request_logs",
        "rate_limit_counters",
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
    }
