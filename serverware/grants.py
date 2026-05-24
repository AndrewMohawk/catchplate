from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from serverware.config import (
    GRANT_STORE_BACKEND,
    GRANT_STORE_CONNECT_TIMEOUT_SECONDS,
    GRANT_STORE_POSTGRES_DSN,
)


class GrantStoreError(RuntimeError):
    pass


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
        raise GrantStoreError("SERVERWARE_GRANT_STORE_POSTGRES_DSN is required for postgres grant store")
    psycopg, dict_row = _psycopg()
    return psycopg.connect(
        GRANT_STORE_POSTGRES_DSN,
        connect_timeout=GRANT_STORE_CONNECT_TIMEOUT_SECONDS,
        row_factory=dict_row,
    )


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
                CREATE INDEX IF NOT EXISTS approval_grants_active_lookup
                    ON approval_grants (
                        principal_id, route_id, credential_id, credential_version,
                        policy_hash, request_digest, operation_digest, created_at
                    )
                    WHERE state = 'active' AND uses_remaining > 0;
                CREATE INDEX IF NOT EXISTS approval_grants_approval_request
                    ON approval_grants (approval_request_id);
                CREATE TABLE IF NOT EXISTS approval_grant_consumptions (
                    id TEXT PRIMARY KEY,
                    grant_id TEXT NOT NULL REFERENCES approval_grants(id) ON DELETE CASCADE,
                    approval_request_id TEXT NOT NULL,
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
                CREATE UNIQUE INDEX IF NOT EXISTS approval_grant_consumptions_flow
                    ON approval_grant_consumptions (flow_id, grant_id);
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
    uses_remaining: int,
    valid_from: str,
    expires_at: str,
    created_at: str,
) -> dict[str, Any]:
    if not uses_postgres():
        raise GrantStoreError("create_grant is only used by the postgres grant store")
    if uses_remaining < 1:
        raise GrantStoreError("grant uses_remaining must be positive")
    with _connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO approval_grants (
                    id, approval_request_id, state, principal_id, route_id, credential_id,
                    credential_version, policy_hash, request_digest, operation_digest,
                    uses_remaining, valid_from, expires_at, created_at, updated_at
                )
                VALUES (
                    %(id)s, %(approval_request_id)s, 'active', %(principal_id)s, %(route_id)s,
                    %(credential_id)s, %(credential_version)s, %(policy_hash)s, %(request_digest)s,
                    %(operation_digest)s, %(uses_remaining)s, %(valid_from)s::timestamptz,
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
    if row is None:
        raise GrantStoreError(f"postgres grant was not created: {grant_id}")
    return {"backend": "postgres", "created": created, **dict(row)}


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
) -> dict[str, Any]:
    if not uses_postgres():
        raise GrantStoreError("consume_grant_result is only used by the postgres grant store")
    now = datetime.now(timezone.utc)
    consumption_id = str(uuid.uuid4())
    with _connect() as conn:
        with conn.transaction():
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
                    ORDER BY created_at ASC
                    FOR UPDATE SKIP LOCKED
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
                        "consumed": False,
                        "reason": "missing_expired_or_already_consumed",
                        "grant_store_backend": "postgres",
                    }
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
                        id, grant_id, approval_request_id, flow_id, principal_id, route_id,
                        credential_id, credential_version, policy_hash, request_digest,
                        operation_digest, outcome, uses_remaining_before, uses_remaining_after,
                        created_at
                    )
                    VALUES (
                        %(id)s, %(grant_id)s, %(approval_request_id)s, %(flow_id)s,
                        %(principal_id)s, %(route_id)s, %(credential_id)s, %(credential_version)s,
                        %(policy_hash)s, %(request_digest)s, %(operation_digest)s, 'consumed',
                        %(uses_before)s, %(uses_after)s, %(created_at)s
                    )
                    """,
                    {
                        "id": consumption_id,
                        "grant_id": updated["id"],
                        "approval_request_id": updated["approval_request_id"],
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
    return {
        "consumed": True,
        "reason": "consumed",
        "grant_id": str(updated["id"]),
        "approval_id": str(updated["approval_request_id"]),
        "approval_request_id": str(updated["approval_request_id"]),
        "uses_remaining_before": uses_before,
        "uses_remaining_after": uses_after,
        "consumption_id": consumption_id,
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
        "transactional_consume": "select_for_update_skip_locked",
        "grants": {key: int(value or 0) for key, value in dict(grants or {}).items()},
        "consumptions": {key: int(value or 0) for key, value in dict(consumptions or {}).items()},
    }
