from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from catchplate.config import (
    GRANT_STORE_BACKEND,
    GRANT_STORE_CONNECT_TIMEOUT_SECONDS,
    GRANT_STORE_POSTGRES_DSN,
)


class GrantStoreError(RuntimeError):
    pass


_GRANT_LOCK_WAIT_MS = 500
_ATTEMPT_ID_MAX_BYTES = 256


def backend_name() -> str:
    if GRANT_STORE_BACKEND in {"", "sqlite", "local"}:
        return "sqlite"
    if GRANT_STORE_BACKEND in {"postgres", "postgresql"}:
        return "postgres"
    raise GrantStoreError(f"unsupported grant store backend: {GRANT_STORE_BACKEND}")


def uses_postgres() -> bool:
    return backend_name() == "postgres"


def _psycopg():
    try:
        import psycopg
        from psycopg.rows import dict_row
    except ImportError as exc:
        raise GrantStoreError("postgres grant store requires psycopg[binary]") from exc
    return psycopg, dict_row


def _connect():
    if not GRANT_STORE_POSTGRES_DSN:
        raise GrantStoreError("CATCHPLATE_GRANT_STORE_POSTGRES_DSN is required for postgres grant store")
    psycopg, dict_row = _psycopg()
    return psycopg.connect(
        GRANT_STORE_POSTGRES_DSN,
        connect_timeout=GRANT_STORE_CONNECT_TIMEOUT_SECONDS,
        row_factory=dict_row,
    )


def can_share_transaction(metadata_postgres_dsn: str) -> bool:
    return bool(
        GRANT_STORE_POSTGRES_DSN.strip()
        and GRANT_STORE_POSTGRES_DSN.strip() == metadata_postgres_dsn.strip()
    )


def _stable_attempt_id(attempt_id: str | None, flow_id: str) -> str:
    value = attempt_id or flow_id
    if not value or len(value.encode("utf-8")) > _ATTEMPT_ID_MAX_BYTES:
        raise GrantStoreError("grant attempt_id must be between 1 and 256 UTF-8 bytes")
    return value


def init_grant_store() -> None:
    if not uses_postgres():
        return
    with _connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS approval_grants (
                    id TEXT PRIMARY KEY,
                    approval_request_id TEXT NOT NULL,
                    state TEXT NOT NULL,
                    principal_id TEXT NOT NULL,
                    route_id TEXT NOT NULL,
                    credential_id TEXT NOT NULL,
                    credential_version BIGINT NOT NULL,
                    policy_hash TEXT NOT NULL,
                    request_digest TEXT NOT NULL,
                    operation_digest TEXT,
                    approver_webauthn_credential_id TEXT,
                    uses_remaining INTEGER NOT NULL,
                    valid_from TIMESTAMPTZ NOT NULL,
                    expires_at TIMESTAMPTZ NOT NULL,
                    consumed_at TIMESTAMPTZ,
                    consumed_by_flow_id TEXT,
                    created_at TIMESTAMPTZ NOT NULL,
                    updated_at TIMESTAMPTZ NOT NULL,
                    CHECK (state IN ('active', 'consumed', 'revoked')),
                    CHECK (uses_remaining >= 0)
                );
                ALTER TABLE approval_grants
                    ADD COLUMN IF NOT EXISTS reserved_attempt_id TEXT;
                ALTER TABLE approval_grants
                    ADD COLUMN IF NOT EXISTS reserved_at_epoch_ms BIGINT;
                ALTER TABLE approval_grants
                    ADD COLUMN IF NOT EXISTS reservation_expires_at_epoch_ms BIGINT;
                ALTER TABLE approval_grants
                    ADD COLUMN IF NOT EXISTS approver_webauthn_credential_id TEXT;
                CREATE INDEX IF NOT EXISTS approval_grants_active_lookup
                    ON approval_grants (
                        principal_id, route_id, credential_id, credential_version,
                        policy_hash, request_digest, operation_digest, created_at
                    )
                    WHERE state = 'active' AND uses_remaining > 0;
                CREATE INDEX IF NOT EXISTS approval_grants_approval_request
                    ON approval_grants (approval_request_id);
                CREATE UNIQUE INDEX IF NOT EXISTS approval_grants_reserved_attempt
                    ON approval_grants (reserved_attempt_id)
                    WHERE reserved_attempt_id IS NOT NULL;
                CREATE TABLE IF NOT EXISTS approval_grant_consumptions (
                    id TEXT PRIMARY KEY,
                    grant_id TEXT NOT NULL REFERENCES approval_grants(id) ON DELETE CASCADE,
                    approval_request_id TEXT NOT NULL,
                    attempt_id TEXT NOT NULL,
                    flow_id TEXT NOT NULL,
                    principal_id TEXT NOT NULL,
                    route_id TEXT NOT NULL,
                    credential_id TEXT NOT NULL,
                    credential_version BIGINT NOT NULL,
                    policy_hash TEXT NOT NULL,
                    request_digest TEXT NOT NULL,
                    operation_digest TEXT,
                    outcome TEXT NOT NULL,
                    uses_remaining_before INTEGER NOT NULL,
                    uses_remaining_after INTEGER NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL,
                    audited_at TIMESTAMPTZ,
                    audit_event_hash TEXT,
                    CHECK (outcome IN ('consumed'))
                );
                DROP INDEX IF EXISTS approval_grant_consumptions_flow;
                ALTER TABLE approval_grant_consumptions
                    ADD COLUMN IF NOT EXISTS attempt_id TEXT;
                UPDATE approval_grant_consumptions
                    SET attempt_id = 'legacy:' || id
                    WHERE attempt_id IS NULL;
                ALTER TABLE approval_grant_consumptions
                    ALTER COLUMN attempt_id SET NOT NULL;
                CREATE UNIQUE INDEX IF NOT EXISTS approval_grant_consumptions_attempt
                    ON approval_grant_consumptions (attempt_id);
                CREATE INDEX IF NOT EXISTS approval_grant_consumptions_pending_audit
                    ON approval_grant_consumptions (created_at)
                    WHERE audited_at IS NULL;
                """
            )


def create_grant(
    *,
    grant_id: str,
    approval_request_id: str,
    principal_id: str,
    route_id: str,
    credential_id: str,
    credential_version: int,
    policy_hash: str,
    request_digest: str,
    operation_digest: str | None,
    approver_webauthn_credential_id: str | None,
    uses_remaining: int,
    valid_from: str,
    expires_at: str,
    created_at: str,
    connection: Any | None = None,
    require_created: bool = False,
) -> dict[str, Any]:
    if not uses_postgres():
        raise GrantStoreError("create_grant is only used by the postgres grant store")
    if uses_remaining < 1:
        raise GrantStoreError("grant uses_remaining must be positive")

    def insert(conn: Any) -> tuple[Any, bool]:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO approval_grants (
                    id, approval_request_id, state, principal_id, route_id, credential_id,
                    credential_version, policy_hash, request_digest, operation_digest,
                    approver_webauthn_credential_id, uses_remaining, valid_from,
                    expires_at, created_at, updated_at
                )
                VALUES (
                    %(id)s, %(approval_request_id)s, 'active', %(principal_id)s, %(route_id)s,
                    %(credential_id)s, %(credential_version)s, %(policy_hash)s, %(request_digest)s,
                    %(operation_digest)s, %(approver_webauthn_credential_id)s,
                    %(uses_remaining)s, %(valid_from)s::timestamptz,
                    %(expires_at)s::timestamptz, %(created_at)s::timestamptz,
                    %(created_at)s::timestamptz
                )
                ON CONFLICT (id) DO NOTHING
                RETURNING id, approval_request_id, state, uses_remaining, expires_at;
                """,
                {
                    "id": grant_id,
                    "approval_request_id": approval_request_id,
                    "principal_id": principal_id,
                    "route_id": route_id,
                    "credential_id": credential_id,
                    "credential_version": credential_version,
                    "policy_hash": policy_hash,
                    "request_digest": request_digest,
                    "operation_digest": operation_digest,
                    "approver_webauthn_credential_id": approver_webauthn_credential_id,
                    "uses_remaining": uses_remaining,
                    "valid_from": valid_from,
                    "expires_at": expires_at,
                    "created_at": created_at,
                },
            )
            row = cur.fetchone()
            created = row is not None
            if row is None:
                cur.execute(
                    """
                    SELECT id, approval_request_id, state, uses_remaining, expires_at
                    FROM approval_grants
                    WHERE id = %(id)s
                    """,
                    {"id": grant_id},
                )
                row = cur.fetchone()
        return row, created

    if connection is None:
        with _connect() as conn:
            row, created = insert(conn)
    else:
        row, created = insert(connection)
    if row is None:
        raise GrantStoreError(f"postgres grant was not created: {grant_id}")
    if require_created and not created:
        raise GrantStoreError(f"postgres grant already existed before approval transition: {grant_id}")
    return {"backend": "postgres", "created": created, **dict(row)}


def _attempt_consumption(cur: Any, attempt_id: str) -> Any:
    cur.execute(
        """
        SELECT id, grant_id, approval_request_id, attempt_id, flow_id,
               principal_id, route_id, credential_id, credential_version,
               policy_hash, request_digest, operation_digest,
               uses_remaining_before, uses_remaining_after
        FROM approval_grant_consumptions
        WHERE attempt_id = %(attempt_id)s
        """,
        {"attempt_id": attempt_id},
    )
    return cur.fetchone()


def _attempt_result(
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
            "grant_store_backend": "postgres",
        }
    return {
        "consumed": True,
        "reason": "already_consumed",
        "idempotent_replay": True,
        "grant_id": str(row["grant_id"]),
        "approval_id": str(row["approval_request_id"]),
        "approval_request_id": str(row["approval_request_id"]),
        "uses_remaining_before": int(row["uses_remaining_before"]),
        "uses_remaining_after": int(row["uses_remaining_after"]),
        "consumption_id": str(row["id"]),
        "attempt_id": str(row["attempt_id"]),
        "grant_store_backend": "postgres",
    }


def consume_grant_result(
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
    if not uses_postgres():
        raise GrantStoreError("consume_grant_result is only used by the postgres grant store")
    stable_attempt_id = _stable_attempt_id(attempt_id, flow_id)
    now = datetime.now(timezone.utc)
    consumption_id = str(uuid.uuid4())
    try:
        with _connect() as conn:
            with conn.transaction():
                with conn.cursor() as cur:
                    cur.execute(f"SET LOCAL lock_timeout = '{_GRANT_LOCK_WAIT_MS}ms'")
                    existing_attempt = _attempt_consumption(cur, stable_attempt_id)
                    if existing_attempt is not None:
                        return _attempt_result(
                            existing_attempt,
                            principal_id=principal_id,
                            route_id=route_id,
                            credential_id=credential_id,
                            credential_version=credential_version,
                            policy_hash=policy_hash,
                            request_digest=request_digest,
                            operation_digest=operation_digest,
                        )
                    cur.execute(
                        """
                        SELECT id, approval_request_id, uses_remaining
                        FROM approval_grants
                        WHERE state = 'active'
                          AND principal_id = %(principal_id)s
                          AND route_id = %(route_id)s
                          AND credential_id = %(credential_id)s
                          AND credential_version = %(credential_version)s
                          AND policy_hash = %(policy_hash)s
                          AND request_digest = %(request_digest)s
                          AND (
                            (%(operation_digest)s::text IS NULL AND operation_digest IS NULL)
                            OR operation_digest = %(operation_digest)s::text
                          )
                          AND valid_from <= %(now)s
                          AND expires_at > %(now)s
                          AND uses_remaining > 0
                          AND reserved_attempt_id IS NULL
                        ORDER BY created_at ASC
                        LIMIT 1
                        FOR UPDATE
                        """,
                        {
                            "principal_id": principal_id,
                            "route_id": route_id,
                            "credential_id": credential_id,
                            "credential_version": credential_version,
                            "policy_hash": policy_hash,
                            "request_digest": request_digest,
                            "operation_digest": operation_digest,
                            "now": now,
                        },
                    )
                    row = cur.fetchone()
                    if row is None:
                        existing_attempt = _attempt_consumption(cur, stable_attempt_id)
                        if existing_attempt is not None:
                            return _attempt_result(
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
                            "grant_store_backend": "postgres",
                        }
                    existing_attempt = _attempt_consumption(cur, stable_attempt_id)
                    if existing_attempt is not None:
                        return _attempt_result(
                            existing_attempt,
                            principal_id=principal_id,
                            route_id=route_id,
                            credential_id=credential_id,
                            credential_version=credential_version,
                            policy_hash=policy_hash,
                            request_digest=request_digest,
                            operation_digest=operation_digest,
                        )
                    uses_before = int(row["uses_remaining"])
                    uses_after = max(uses_before - 1, 0)
                    next_state = "consumed" if uses_after == 0 else "active"
                    cur.execute(
                        """
                        UPDATE approval_grants
                        SET uses_remaining = %(uses_after)s,
                            state = %(next_state)s,
                            consumed_at = CASE
                                WHEN %(next_state)s = 'consumed' THEN %(now)s
                                ELSE consumed_at
                            END,
                            consumed_by_flow_id = CASE
                                WHEN %(next_state)s = 'consumed' THEN %(flow_id)s
                                ELSE consumed_by_flow_id
                            END,
                            updated_at = %(now)s
                        WHERE id = %(id)s
                        RETURNING id, approval_request_id, uses_remaining, state
                        """,
                        {
                            "id": row["id"],
                            "uses_after": uses_after,
                            "next_state": next_state,
                            "now": now,
                            "flow_id": flow_id,
                        },
                    )
                    updated = cur.fetchone()
                    if updated is None:
                        raise GrantStoreError("postgres grant update lost its locked row")
                    cur.execute(
                        """
                        INSERT INTO approval_grant_consumptions (
                            id, grant_id, approval_request_id, attempt_id, flow_id,
                            principal_id, route_id, credential_id, credential_version,
                            policy_hash, request_digest, operation_digest, outcome,
                            uses_remaining_before, uses_remaining_after, created_at
                        )
                        VALUES (
                            %(id)s, %(grant_id)s, %(approval_request_id)s, %(attempt_id)s,
                            %(flow_id)s, %(principal_id)s, %(route_id)s, %(credential_id)s,
                            %(credential_version)s, %(policy_hash)s, %(request_digest)s,
                            %(operation_digest)s, 'consumed', %(uses_before)s,
                            %(uses_after)s, %(created_at)s
                        )
                        """,
                        {
                            "id": consumption_id,
                            "grant_id": updated["id"],
                            "approval_request_id": updated["approval_request_id"],
                            "attempt_id": stable_attempt_id,
                            "flow_id": flow_id,
                            "principal_id": principal_id,
                            "route_id": route_id,
                            "credential_id": credential_id,
                            "credential_version": credential_version,
                            "policy_hash": policy_hash,
                            "request_digest": request_digest,
                            "operation_digest": operation_digest,
                            "uses_before": uses_before,
                            "uses_after": uses_after,
                            "created_at": now,
                        },
                    )
    except Exception as exc:
        if getattr(exc, "sqlstate", None) == "55P03":
            return {
                "consumed": False,
                "reason": "grant_locked_retry",
                "retryable": True,
                "retry_after_ms": _GRANT_LOCK_WAIT_MS,
                "grant_store_backend": "postgres",
            }
        raise
    return {
        "consumed": True,
        "reason": "consumed",
        "grant_id": str(updated["id"]),
        "approval_id": str(updated["approval_request_id"]),
        "approval_request_id": str(updated["approval_request_id"]),
        "uses_remaining_before": uses_before,
        "uses_remaining_after": uses_after,
        "consumption_id": consumption_id,
        "attempt_id": stable_attempt_id,
        "grant_store_backend": "postgres",
    }


def find_grant_result(
    *,
    principal_id: str,
    route_id: str,
    credential_id: str,
    credential_version: int,
    policy_hash: str,
    request_digest: str,
    operation_digest: str | None,
) -> dict[str, Any]:
    if not uses_postgres():
        raise GrantStoreError("find_grant_result is only used by the postgres grant store")
    now = datetime.now(timezone.utc)
    with _connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, approval_request_id, uses_remaining
                FROM approval_grants
                WHERE state = 'active'
                  AND principal_id = %(principal_id)s
                  AND route_id = %(route_id)s
                  AND credential_id = %(credential_id)s
                  AND credential_version = %(credential_version)s
                  AND policy_hash = %(policy_hash)s
                  AND request_digest = %(request_digest)s
                  AND (
                    (%(operation_digest)s::text IS NULL AND operation_digest IS NULL)
                    OR operation_digest = %(operation_digest)s::text
                  )
                  AND valid_from <= %(now)s
                  AND expires_at > %(now)s
                  AND uses_remaining > 0
                  AND reserved_attempt_id IS NULL
                ORDER BY created_at ASC
                LIMIT 1
                """,
                {
                    "principal_id": principal_id,
                    "route_id": route_id,
                    "credential_id": credential_id,
                    "credential_version": credential_version,
                    "policy_hash": policy_hash,
                    "request_digest": request_digest,
                    "operation_digest": operation_digest,
                    "now": now,
                },
            )
            row = cur.fetchone()
    if row is None:
        return {
            "available": False,
            "consumed": False,
            "reason": "missing_expired_not_yet_valid_or_already_consumed",
            "grant_store_backend": "postgres",
        }
    return {
        "available": True,
        "consumed": False,
        "reason": "available",
        "grant_id": str(row["id"]),
        "approval_id": str(row["approval_request_id"]),
        "approval_request_id": str(row["approval_request_id"]),
        "uses_remaining_before": int(row["uses_remaining"]),
        "uses_remaining_after": int(row["uses_remaining"]),
        "grant_store_backend": "postgres",
    }


def mark_consumption_audited(consumption_id: str, audit_event_hash: str) -> None:
    if not uses_postgres():
        return
    with _connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE approval_grant_consumptions
                SET audited_at = %(audited_at)s,
                    audit_event_hash = %(audit_event_hash)s
                WHERE id = %(id)s AND audited_at IS NULL
                """,
                {
                    "id": consumption_id,
                    "audited_at": datetime.now(timezone.utc),
                    "audit_event_hash": audit_event_hash,
                },
            )


def status() -> dict[str, Any]:
    name = backend_name()
    if name != "postgres":
        return {"backend": "sqlite", "ha": False}
    with _connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    COUNT(*)::bigint AS grants,
                    COUNT(*) FILTER (WHERE state = 'active')::bigint AS active_grants,
                    COUNT(*) FILTER (
                        WHERE state = 'active' AND reserved_attempt_id IS NOT NULL
                    )::bigint AS reserved_grants,
                    COUNT(*) FILTER (WHERE state = 'consumed')::bigint AS consumed_grants
                FROM approval_grants
                """
            )
            grants = cur.fetchone()
            cur.execute(
                """
                SELECT
                    COUNT(*)::bigint AS consumptions,
                    COUNT(*) FILTER (WHERE audited_at IS NULL)::bigint AS pending_audit
                FROM approval_grant_consumptions
                """
            )
            consumptions = cur.fetchone()
    return {
        "backend": "postgres",
        "ha": True,
        "transactional_consume": "select_for_update_bounded_wait",
        "grants": {key: int(value or 0) for key, value in dict(grants or {}).items()},
        "consumptions": {key: int(value or 0) for key, value in dict(consumptions or {}).items()},
    }
