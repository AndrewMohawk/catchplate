#!/usr/bin/env python3
from __future__ import annotations

import argparse
from contextlib import ExitStack
import hashlib
import json
import os
import sqlite3
import sys
import tempfile
import time
import urllib.error
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any
from unittest.mock import patch
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def configure_sqlite(data_dir: str) -> None:
    os.environ["SERVERWARE_DATA_DIR"] = data_dir
    os.environ["SERVERWARE_METADATA_STORE_BACKEND"] = "sqlite"
    os.environ["SERVERWARE_GRANT_STORE_BACKEND"] = "sqlite"
    os.environ["SERVERWARE_AUDIT_STORE_BACKEND"] = "sqlite"
    os.environ["SERVERWARE_RELEASE_CHANNEL"] = "test"
    os.environ["SERVERWARE_DATA_PLANE_INSTANCE_ID"] = "jit-transaction-test"
    os.environ["SERVERWARE_DATA_PLANE_RELEASE_AUTHORIZATION_TOKEN"] = "jit-release-test-token"


def configure_postgres(base_dsn: str, data_dir: str) -> tuple[str, str]:
    import psycopg

    schema = f"serverware_jit_test_{uuid.uuid4().hex}"
    with psycopg.connect(base_dsn, autocommit=True) as conn:
        conn.execute(f'CREATE SCHEMA "{schema}"')
    separator = "&" if "?" in base_dsn else "?"
    options = quote(f"-csearch_path={schema}", safe="")
    dsn = f"{base_dsn}{separator}options={options}"
    os.environ["SERVERWARE_DATA_DIR"] = data_dir
    os.environ["SERVERWARE_METADATA_STORE_BACKEND"] = "postgres"
    os.environ["SERVERWARE_METADATA_STORE_POSTGRES_DSN"] = dsn
    os.environ["SERVERWARE_GRANT_STORE_BACKEND"] = "postgres"
    os.environ["SERVERWARE_GRANT_STORE_POSTGRES_DSN"] = dsn
    os.environ["SERVERWARE_AUDIT_STORE_BACKEND"] = "postgres"
    os.environ["SERVERWARE_AUDIT_STORE_POSTGRES_DSN"] = dsn
    os.environ["SERVERWARE_RELEASE_CHANNEL"] = "test"
    os.environ["SERVERWARE_DATA_PLANE_INSTANCE_ID"] = "jit-transaction-test"
    os.environ["SERVERWARE_DATA_PLANE_RELEASE_AUTHORIZATION_TOKEN"] = "jit-release-test-token"
    return schema, dsn


def drop_postgres_schema(base_dsn: str, schema: str) -> None:
    import psycopg

    with psycopg.connect(base_dsn, autocommit=True) as conn:
        conn.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')


def approval_kwargs(suffix: str) -> dict[str, Any]:
    return {
        "route_id": f"route:{suffix}",
        "method": "POST",
        "url": f"https://upstream.invalid/{suffix}",
        "principal_id": f"agent:{suffix}",
        "credential_id": f"credential:{suffix}",
        "credential_version": 1,
        "policy_hash": "sha256:" + "a" * 64,
        "request_digest": "sha256:" + "b" * 64,
        "operation_digest": "sha256:" + "c" * 64,
        "canonical_request": {"operation": {"name": suffix}},
        "redacted_display": {"summary": suffix},
        "pending_ttl_seconds": 300,
        "grant_ttl_seconds": 60,
        "grant_max_uses": 1,
    }


def assert_raises(expected: type[BaseException], callback: Any, message: str) -> None:
    try:
        callback()
    except expected:
        return
    raise AssertionError(message)


def exercise_policy_high_water(db: Any, backend: str) -> None:
    policy_id = f"serverware-{backend}"
    digest = lambda value: "sha256:" + value * 64
    first = db.advance_policy_high_water(
        policy_id=policy_id,
        sequence=1,
        rollback_epoch=1,
        policy_hash=digest("a"),
    )
    if db.advance_policy_high_water(
        policy_id=policy_id,
        sequence=1,
        rollback_epoch=1,
        policy_hash=digest("a"),
    ) != first:
        raise AssertionError("exact policy high-water replay was not idempotent")

    candidates = (digest("b"), digest("c"))

    def advance(candidate_hash: str) -> tuple[str, str]:
        try:
            db.advance_policy_high_water(
                policy_id=policy_id,
                sequence=2,
                rollback_epoch=1,
                policy_hash=candidate_hash,
            )
            return ("accepted", candidate_hash)
        except db.MetadataStoreError:
            return ("rejected", candidate_hash)

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(advance, candidates))
    if [status for status, _ in outcomes].count("accepted") != 1:
        raise AssertionError(f"concurrent policy advancement did not have one winner: {outcomes}")
    high_water = db.get_policy_high_water()
    if not high_water or high_water["sequence"] != 2 or high_water["policy_hash"] not in candidates:
        raise AssertionError(f"policy high-water winner was not persisted: {high_water}")

    assert_raises(
        db.MetadataStoreError,
        lambda: db.advance_policy_high_water(
            policy_id=policy_id,
            sequence=1,
            rollback_epoch=1,
            policy_hash=digest("d"),
        ),
        "policy high-water accepted a stale sequence",
    )
    assert_raises(
        db.MetadataStoreError,
        lambda: db.advance_policy_high_water(
            policy_id=f"{policy_id}-replacement",
            sequence=3,
            rollback_epoch=1,
            policy_hash=digest("e"),
        ),
        "policy high-water accepted a policy ID switch",
    )
    db.advance_policy_high_water(
        policy_id=policy_id,
        sequence=3,
        rollback_epoch=2,
        policy_hash=digest("f"),
    )
    assert_raises(
        db.MetadataStoreError,
        lambda: db.advance_policy_high_water(
            policy_id=policy_id,
            sequence=4,
            rollback_epoch=1,
            policy_hash=digest("0"),
        ),
        "policy high-water accepted a rollback epoch downgrade",
    )


def exercise_atomic_approval(db: Any, grants: Any, backend: str) -> dict[str, Any]:
    kwargs = approval_kwargs(backend)
    with ThreadPoolExecutor(max_workers=8) as pool:
        approvals = list(pool.map(lambda _: db.ensure_jit_approval_request(**kwargs), range(16)))
    approval_ids = {item["id"] for item in approvals}
    if len(approval_ids) != 1:
        raise AssertionError(f"duplicate pending approval race created multiple rows: {approval_ids}")
    if sum(item.get("approval_created") is True for item in approvals) != 1:
        raise AssertionError(
            f"pending approval race did not report exactly one creator: {approvals}"
        )
    approval_id = approvals[0]["id"]

    mismatched = {**kwargs, "redacted_display": {"summary": "changed"}}
    assert_raises(
        db.MetadataStoreError,
        lambda: db.ensure_jit_approval_request(**mismatched),
        "pending approval accepted a changed immutable review payload",
    )
    oversized = approval_kwargs(f"{backend}-oversized")
    oversized["canonical_request"] = {"value": "x" * (65 * 1024)}
    assert_raises(
        db.MetadataStoreError,
        lambda: db.ensure_jit_approval_request(**oversized),
        "oversized pending approval payload was accepted",
    )
    previous_limit = db._PENDING_APPROVAL_MAX_COUNT
    db._PENDING_APPROVAL_MAX_COUNT = 1
    try:
        bounded = approval_kwargs(f"{backend}-bounded")
        assert_raises(
            db.MetadataStoreError,
            lambda: db.ensure_jit_approval_request(**bounded),
            "pending approval count limit was not enforced",
        )
    finally:
        db._PENDING_APPROVAL_MAX_COUNT = previous_limit

    if backend == "postgres":
        original_create = grants.create_grant
        injected_connections: list[Any] = []

        def fail_after_insert(**grant_kwargs: Any) -> dict[str, Any]:
            injected_connections.append(grant_kwargs.get("connection"))
            original_create(**grant_kwargs)
            raise grants.GrantStoreError("forced rollback after grant insert")

        grants.create_grant = fail_after_insert
        try:
            assert_raises(
                grants.GrantStoreError,
                lambda: db.approve_request(approval_id, ttl_seconds=60),
                "forced PostgreSQL grant failure did not abort approval",
            )
        finally:
            grants.create_grant = original_create
        if not injected_connections or injected_connections[0] is None:
            raise AssertionError("PostgreSQL grant creation did not receive the metadata connection")
    else:
        with db.connect() as conn:
            conn.execute(
                """
                CREATE TRIGGER fail_jit_grant_insert
                BEFORE INSERT ON approval_grants
                BEGIN
                    SELECT RAISE(ABORT, 'forced rollback after grant insert');
                END
                """
            )
        try:
            assert_raises(
                sqlite3.DatabaseError,
                lambda: db.approve_request(approval_id, ttl_seconds=60),
                "forced SQLite grant failure did not abort approval",
            )
        finally:
            with db.connect() as conn:
                conn.execute("DROP TRIGGER fail_jit_grant_insert")

    pending = db.get_approval_request(approval_id)
    if not pending or pending["status"] != "pending":
        raise AssertionError(f"approval transition survived rolled-back grant issuance: {pending}")
    with db.connect() as conn:
        orphan = conn.execute(
            "SELECT COUNT(*) AS count FROM approval_grants WHERE approval_request_id = ?",
            (approval_id,),
        ).fetchone()
    if int(orphan["count"]) != 0:
        raise AssertionError("rolled-back approval left an orphaned grant")

    approved = db.approve_request(approval_id, ttl_seconds=60)
    if not approved or approved["status"] != "approved":
        raise AssertionError(f"approval did not transition with grant issuance: {approved}")
    return {"approval": approved, "lookup": {
        "principal_id": kwargs["principal_id"],
        "route_id": kwargs["route_id"],
        "credential_id": kwargs["credential_id"],
        "credential_version": kwargs["credential_version"],
        "policy_hash": kwargs["policy_hash"],
        "request_digest": kwargs["request_digest"],
        "operation_digest": kwargs["operation_digest"],
    }}


def exercise_grant_consumption(
    db: Any,
    grants: Any,
    backend: str,
    approval: dict[str, Any],
    lookup: dict[str, Any],
    postgres_dsn: str | None,
) -> None:
    null_operation = {**lookup, "operation_digest": None}
    if db.find_jit_grant_result(**null_operation).get("available"):
        raise AssertionError("NULL operation digest matched an operation-bound grant")

    if backend == "postgres":
        import psycopg

        with psycopg.connect(postgres_dsn) as lock_conn:
            lock_conn.execute(
                "SELECT id FROM approval_grants WHERE approval_request_id = %s FOR UPDATE",
                (approval["id"],),
            )
            started = time.monotonic()
            locked = db.consume_jit_grant_result(
                **lookup,
                flow_id="flow-locked",
                attempt_id="attempt-locked",
            )
            elapsed = time.monotonic() - started
            if locked.get("reason") != "grant_locked_retry" or not locked.get("retryable"):
                raise AssertionError(f"locked grant was reported as missing: {locked}")
            if elapsed > 2:
                raise AssertionError(f"bounded grant lock wait took too long: {elapsed:.3f}s")
            lock_conn.rollback()

    consumed = db.consume_jit_grant_result(
        **lookup,
        flow_id="flow-first",
        attempt_id="attempt-stable",
    )
    replayed = db.consume_jit_grant_result(
        **lookup,
        flow_id="flow-retry",
        attempt_id="attempt-stable",
    )
    if not consumed.get("consumed") or not replayed.get("idempotent_replay"):
        raise AssertionError(f"stable attempt was not idempotent: {consumed} {replayed}")
    if consumed["consumption_id"] != replayed["consumption_id"]:
        raise AssertionError("idempotent retry returned a different consumption record")
    conflicting = db.consume_jit_grant_result(
        **{**lookup, "request_digest": "sha256:" + "d" * 64},
        flow_id="flow-conflict",
        attempt_id="attempt-stable",
    )
    if conflicting.get("reason") != "attempt_id_conflict":
        raise AssertionError(f"attempt ID was reusable across bindings: {conflicting}")
    reused = db.consume_jit_grant_result(
        **lookup,
        flow_id="flow-second",
        attempt_id="attempt-second",
    )
    if reused.get("consumed"):
        raise AssertionError(f"one-use grant was consumed twice: {reused}")
    with db.connect() as conn:
        grant = conn.execute(
            "SELECT state, uses_remaining FROM approval_grants WHERE approval_request_id = ?",
            (approval["id"],),
        ).fetchone()
        ledger = conn.execute(
            "SELECT COUNT(*) AS count FROM approval_grant_consumptions WHERE grant_id = ?",
            (consumed["grant_id"],),
        ).fetchone()
    if grant["state"] != "consumed" or int(grant["uses_remaining"]) != 0:
        raise AssertionError(f"one-use grant retained authority after consumption: {dict(grant)}")
    if int(ledger["count"]) != 1:
        raise AssertionError(f"idempotent retry duplicated consumption ledger rows: {dict(ledger)}")


def approved_release_binding(db: Any, suffix: str) -> dict[str, Any]:
    kwargs = approval_kwargs(suffix)
    approval = db.ensure_jit_approval_request(**kwargs)
    approved = db.approve_request(approval["id"], ttl_seconds=60)
    if not approved or approved.get("status") != "approved":
        raise AssertionError(f"release test approval was not issued: {approved}")
    return {
        "principal_id": kwargs["principal_id"],
        "route_id": kwargs["route_id"],
        "credential_id": kwargs["credential_id"],
        "credential_version": kwargs["credential_version"],
        "policy_hash": kwargs["policy_hash"],
        "request_digest": kwargs["request_digest"],
        "operation_digest": kwargs["operation_digest"],
    }


def quota_claim(suffix: str, *, maximum: int = 1) -> dict[str, Any]:
    return {
        "counter_key": "sha256:" + hashlib.sha256(suffix.encode("utf-8")).hexdigest(),
        "constraint_id": f"quota:{suffix}",
        "operation": "test.forward",
        "window_seconds": 60,
        "max_count": maximum,
    }


def release_reserve_kwargs(
    binding: dict[str, Any],
    *,
    attempt_id: str,
    quotas: list[dict[str, Any]],
    require_jit_grant: bool = True,
    now_epoch_ms: int | None = None,
) -> dict[str, Any]:
    return {
        "attempt_id": attempt_id,
        "flow_id": f"flow:{attempt_id}",
        **binding,
        "operation_context": {"operation": "test.forward", "account": "acct:test"},
        "shared_quotas": quotas,
        "require_jit_grant": require_jit_grant,
        "reservation_ttl_seconds": 5,
        "now_epoch_ms": now_epoch_ms,
        "actor_id": "spiffe://test.serverware/decision-gate/atomic",
    }


def counter_count(db: Any, counter_key: str) -> int | None:
    with db.connect() as conn:
        row = conn.execute(
            "SELECT count FROM rate_limit_counters WHERE counter_key = ?",
            (counter_key,),
        ).fetchone()
    return int(row["count"]) if row is not None else None


def exercise_atomic_release_authorization(db: Any, backend: str) -> None:
    writer = db.release_authorization_writer_status()
    if not writer.get("shared_transaction"):
        raise AssertionError(f"test stores cannot share an atomic writer: {writer}")

    first_multi_binding = approved_release_binding(db, f"{backend}-atomic-multi-grant")
    second_multi_binding = approved_release_binding(db, f"{backend}-atomic-multi-grant")
    if first_multi_binding != second_multi_binding:
        raise AssertionError("matching approval grants did not retain the same binding")
    first_multi = db.reserve_release_authorization(
        **release_reserve_kwargs(
            first_multi_binding,
            attempt_id=f"attempt:{backend}:multi-grant:first",
            quotas=[],
        )
    )
    second_multi = db.reserve_release_authorization(
        **release_reserve_kwargs(
            second_multi_binding,
            attempt_id=f"attempt:{backend}:multi-grant:second",
            quotas=[],
        )
    )
    if (
        first_multi.get("state") != "reserved"
        or second_multi.get("state") != "reserved"
        or not first_multi.get("grant_id")
        or first_multi.get("grant_id") == second_multi.get("grant_id")
    ):
        raise AssertionError(
            "grant selection did not skip the grant reserved by another attempt: "
            f"{first_multi} {second_multi}"
        )
    for reservation in (first_multi, second_multi):
        cancelled = db.complete_release_authorization(
            attempt_id=reservation["attempt_id"],
            binding_digest=reservation["binding_digest"],
            outcome="not_forwarded",
        )
        if cancelled.get("state") != "cancelled":
            raise AssertionError(f"multi-grant fixture did not cancel: {cancelled}")

    denial_binding = approved_release_binding(db, f"{backend}-atomic-denial")
    first_quota = quota_claim(f"{backend}-atomic-denial-first")
    full_quota = quota_claim(f"{backend}-atomic-denial-full")
    prefilled = db.consume_rate_limit(
        counter_key=full_quota["counter_key"],
        principal_id=denial_binding["principal_id"],
        route_id=denial_binding["route_id"],
        credential_id=denial_binding["credential_id"],
        credential_version=denial_binding["credential_version"],
        policy_hash=denial_binding["policy_hash"],
        constraint_id=full_quota["constraint_id"],
        operation=full_quota["operation"],
        window_seconds=full_quota["window_seconds"],
        max_count=full_quota["max_count"],
        audit=False,
    )
    if not prefilled.get("allowed") or counter_count(db, full_quota["counter_key"]) != 1:
        raise AssertionError(f"failed to prefill quota denial fixture: {prefilled}")
    denied = db.reserve_release_authorization(
        **release_reserve_kwargs(
            denial_binding,
            attempt_id=f"attempt:{backend}:quota-denial",
            quotas=[first_quota, full_quota],
        )
    )
    if denied.get("state") != "denied" or denied.get("reason") != "shared_quota_denied":
        raise AssertionError(f"multi-counter quota denial did not fail closed: {denied}")
    if counter_count(db, first_quota["counter_key"]) is not None:
        raise AssertionError("quota denial committed an earlier unique counter reservation")
    if counter_count(db, full_quota["counter_key"]) != 1:
        raise AssertionError("quota denial changed the already-full counter")
    with db.connect() as conn:
        grant_after_quota_denial = conn.execute(
            "SELECT reserved_attempt_id, uses_remaining FROM approval_grants "
            "WHERE route_id = ? AND request_digest = ?",
            (denial_binding["route_id"], denial_binding["request_digest"]),
        ).fetchone()
        denied_attempt = conn.execute(
            "SELECT COUNT(*) AS count FROM release_authorization_attempts "
            "WHERE attempt_id = ?",
            (f"attempt:{backend}:quota-denial",),
        ).fetchone()
    if (
        grant_after_quota_denial["reserved_attempt_id"] is not None
        or int(grant_after_quota_denial["uses_remaining"]) != 1
        or int(denied_attempt["count"]) != 0
    ):
        raise AssertionError("quota denial left a grant or attempt mutation")

    missing_grant_quota = quota_claim(f"{backend}-missing-grant")
    missing_grant = db.reserve_release_authorization(
        **release_reserve_kwargs(
            {**denial_binding, "request_digest": "sha256:" + "9" * 64},
            attempt_id=f"attempt:{backend}:grant-denial",
            quotas=[missing_grant_quota],
        )
    )
    if missing_grant.get("reason") != "jit_grant_unavailable":
        raise AssertionError(f"missing grant denial was ambiguous: {missing_grant}")
    if counter_count(db, missing_grant_quota["counter_key"]) is not None:
        raise AssertionError("grant denial mutated a shared quota counter")

    cancel_binding = approved_release_binding(db, f"{backend}-atomic-cancel")
    cancel_quotas = [
        quota_claim(f"{backend}-cancel-a", maximum=2),
        quota_claim(f"{backend}-cancel-b", maximum=2),
    ]
    cancel_kwargs = release_reserve_kwargs(
        cancel_binding,
        attempt_id=f"attempt:{backend}:cancel",
        quotas=list(reversed(cancel_quotas)),
    )
    reserved = db.reserve_release_authorization(**cancel_kwargs)
    replayed = db.reserve_release_authorization(**cancel_kwargs)
    if reserved.get("state") != "reserved" or not replayed.get("idempotent_replay"):
        raise AssertionError(f"reservation replay was not durable: {reserved} {replayed}")
    if reserved.get("binding_digest") != replayed.get("binding_digest"):
        raise AssertionError("reservation replay returned a different binding digest")
    try:
        db.reserve_release_authorization(
            **{
                **cancel_kwargs,
                "operation_context": {"operation": "test.changed"},
            }
        )
    except db.ReleaseAuthorizationConflictError:
        pass
    else:
        raise AssertionError("attempt ID accepted a different durable binding")
    with db.connect() as conn:
        reserved_grant = conn.execute(
            "SELECT state, uses_remaining, reserved_attempt_id FROM approval_grants "
            "WHERE id = ?",
            (reserved["grant_id"],),
        ).fetchone()
        consumption = conn.execute(
            "SELECT COUNT(*) AS count FROM approval_grant_consumptions "
            "WHERE attempt_id = ?",
            (cancel_kwargs["attempt_id"],),
        ).fetchone()
    if (
        reserved_grant["state"] != "active"
        or int(reserved_grant["uses_remaining"]) != 1
        or reserved_grant["reserved_attempt_id"] != cancel_kwargs["attempt_id"]
        or int(consumption["count"]) != 0
    ):
        raise AssertionError("tentative reserve created final grant consumption")
    cancelled = db.complete_release_authorization(
        attempt_id=cancel_kwargs["attempt_id"],
        binding_digest=reserved["binding_digest"],
        outcome="not_forwarded",
        actor_id="spiffe://test.serverware/decision-gate/atomic",
    )
    if cancelled.get("state") != "cancelled":
        raise AssertionError(f"pre-dispatch cancellation was not refunded: {cancelled}")
    if any(counter_count(db, item["counter_key"]) != 0 for item in cancel_quotas):
        raise AssertionError("pre-dispatch cancellation did not refund every matching window")
    with db.connect() as conn:
        cancelled_grant = conn.execute(
            "SELECT state, uses_remaining, reserved_attempt_id FROM approval_grants "
            "WHERE id = ?",
            (reserved["grant_id"],),
        ).fetchone()
    if (
        cancelled_grant["state"] != "active"
        or int(cancelled_grant["uses_remaining"]) != 1
        or cancelled_grant["reserved_attempt_id"] is not None
    ):
        raise AssertionError("cancellation consumed or retained the JIT grant")

    collision_binding = approved_release_binding(db, f"{backend}-atomic-collision")
    collision_quota = quota_claim(f"{backend}-collision", maximum=2)
    collision_attempt = f"attempt:{backend}:collision"
    collision_reservation = db.reserve_release_authorization(
        **release_reserve_kwargs(
            collision_binding,
            attempt_id=collision_attempt,
            quotas=[collision_quota],
        )
    )
    db.dispatch_release_authorization(
        attempt_id=collision_attempt,
        binding_digest=collision_reservation["binding_digest"],
        dispatch_ttl_seconds=5,
    )
    collision_id = str(uuid.uuid4())
    with db.connect() as conn:
        collision_grant = conn.execute(
            "SELECT * FROM approval_grants WHERE id = ?",
            (collision_reservation["grant_id"],),
        ).fetchone()
        conn.execute(
            """
            INSERT INTO approval_grant_consumptions (
                id, grant_id, approval_request_id, attempt_id, flow_id,
                principal_id, route_id, credential_id, credential_version,
                policy_hash, request_digest, operation_digest, outcome,
                uses_remaining_before, uses_remaining_after, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'consumed', 1, 0, ?)
            """,
            (
                collision_id,
                collision_grant["id"],
                collision_grant["approval_request_id"],
                collision_attempt,
                f"flow:{collision_attempt}",
                collision_binding["principal_id"],
                collision_binding["route_id"],
                collision_binding["credential_id"],
                collision_binding["credential_version"],
                collision_binding["policy_hash"],
                "sha256:" + "d" * 64,
                collision_binding["operation_digest"],
                db.iso_now(),
            ),
        )
    assert_raises(
        db.ReleaseAuthorizationError,
        lambda: db.complete_release_authorization(
            attempt_id=collision_attempt,
            binding_digest=collision_reservation["binding_digest"],
            outcome="forwarded",
        ),
        "mismatched consumption attempt collision did not fail closed",
    )
    with db.connect() as conn:
        collision_attempt_row = conn.execute(
            "SELECT state FROM release_authorization_attempts WHERE attempt_id = ?",
            (collision_attempt,),
        ).fetchone()
        collision_grant_after = conn.execute(
            "SELECT state, uses_remaining, reserved_attempt_id FROM approval_grants "
            "WHERE id = ?",
            (collision_reservation["grant_id"],),
        ).fetchone()
        collision_quota_row = conn.execute(
            "SELECT reservation_state FROM release_authorization_quota_reservations "
            "WHERE attempt_id = ? AND counter_key = ?",
            (collision_attempt, collision_quota["counter_key"]),
        ).fetchone()
        conn.execute(
            "DELETE FROM approval_grant_consumptions WHERE id = ?", (collision_id,)
        )
    if (
        collision_attempt_row["state"] != "dispatching"
        or collision_grant_after["state"] != "active"
        or int(collision_grant_after["uses_remaining"]) != 1
        or collision_grant_after["reserved_attempt_id"] != collision_attempt
        or collision_quota_row["reservation_state"] != "reserved"
        or counter_count(db, collision_quota["counter_key"]) != 1
    ):
        raise AssertionError("consumption collision partially mutated grant or quota state")
    collision_committed = db.complete_release_authorization(
        attempt_id=collision_attempt,
        binding_digest=collision_reservation["binding_digest"],
        outcome="forwarded",
    )
    if collision_committed.get("state") != "committed":
        raise AssertionError(
            f"collision rollback did not leave the attempt recoverable: {collision_committed}"
        )

    commit_binding = approved_release_binding(db, f"{backend}-atomic-commit")
    commit_quotas = [
        quota_claim(f"{backend}-commit-a", maximum=2),
        quota_claim(f"{backend}-commit-b", maximum=2),
    ]
    commit_attempt = f"attempt:{backend}:commit"
    committed_reservation = db.reserve_release_authorization(
        **release_reserve_kwargs(
            commit_binding,
            attempt_id=commit_attempt,
            quotas=commit_quotas,
        )
    )
    dispatched = db.dispatch_release_authorization(
        attempt_id=commit_attempt,
        binding_digest=committed_reservation["binding_digest"],
        dispatch_ttl_seconds=5,
        actor_id="spiffe://test.serverware/decision-gate/atomic",
    )
    committed = db.complete_release_authorization(
        attempt_id=commit_attempt,
        binding_digest=committed_reservation["binding_digest"],
        outcome="forwarded",
        actor_id="spiffe://test.serverware/decision-gate/atomic",
    )
    committed_replay = db.complete_release_authorization(
        attempt_id=commit_attempt,
        binding_digest=committed_reservation["binding_digest"],
        outcome="forwarded",
    )
    if (
        dispatched.get("state") != "dispatching"
        or committed.get("state") != "committed"
        or not committed_replay.get("idempotent_replay")
    ):
        raise AssertionError(
            f"forwarded release did not commit idempotently: {dispatched} {committed} {committed_replay}"
        )
    with db.connect() as conn:
        committed_grant = conn.execute(
            "SELECT state, uses_remaining, reserved_attempt_id FROM approval_grants "
            "WHERE id = ?",
            (committed["grant_id"],),
        ).fetchone()
        committed_ledger = conn.execute(
            "SELECT COUNT(*) AS count FROM approval_grant_consumptions "
            "WHERE attempt_id = ?",
            (commit_attempt,),
        ).fetchone()
    if (
        committed_grant["state"] != "consumed"
        or int(committed_grant["uses_remaining"]) != 0
        or committed_grant["reserved_attempt_id"] is not None
        or int(committed_ledger["count"]) != 1
        or any(counter_count(db, item["counter_key"]) != 1 for item in commit_quotas)
    ):
        raise AssertionError("forwarded completion did not commit grant and quotas once")

    expired_binding = approved_release_binding(db, f"{backend}-atomic-expired")
    now_ms = int(time.time() * 1000)
    expired_quota = quota_claim(f"{backend}-expired")
    expired_attempt = f"attempt:{backend}:expired"
    expired_reservation = db.reserve_release_authorization(
        **{
            **release_reserve_kwargs(
                expired_binding,
                attempt_id=expired_attempt,
                quotas=[expired_quota],
                now_epoch_ms=now_ms,
            ),
            "reservation_ttl_seconds": 1,
        }
    )
    if expired_reservation.get("state") != "reserved":
        raise AssertionError(f"expiry fixture did not reserve: {expired_reservation}")
    reaped = db.reconcile_release_authorizations(
        limit=10, now_epoch_ms=now_ms + 1001
    )
    if reaped.get("cancelled", 0) < 1 or counter_count(db, expired_quota["counter_key"]) != 0:
        raise AssertionError(f"expired reservation was not cancelled and refunded: {reaped}")

    stale_binding = approved_release_binding(db, f"{backend}-atomic-stale")
    stale_now_ms = int(time.time() * 1000)
    stale_quota = quota_claim(f"{backend}-stale")
    stale_attempt = f"attempt:{backend}:stale"
    stale_reservation = db.reserve_release_authorization(
        **release_reserve_kwargs(
            stale_binding,
            attempt_id=stale_attempt,
            quotas=[stale_quota],
            now_epoch_ms=stale_now_ms,
        )
    )
    db.dispatch_release_authorization(
        attempt_id=stale_attempt,
        binding_digest=stale_reservation["binding_digest"],
        dispatch_ttl_seconds=1,
        now_epoch_ms=stale_now_ms,
    )
    stale_reaped = db.reconcile_release_authorizations(
        limit=10, now_epoch_ms=stale_now_ms + 1001
    )
    with db.connect() as conn:
        stale_row = conn.execute(
            "SELECT state FROM release_authorization_attempts WHERE attempt_id = ?",
            (stale_attempt,),
        ).fetchone()
    if (
        stale_reaped.get("committed_indeterminate", 0) < 1
        or stale_row["state"] != "committed_indeterminate"
        or counter_count(db, stale_quota["counter_key"]) != 1
    ):
        raise AssertionError(f"stale dispatch was not committed indeterminate: {stale_reaped}")

    contention_quotas = [
        quota_claim(f"{backend}-contention-a", maximum=8),
        quota_claim(f"{backend}-contention-b", maximum=8),
    ]
    contention_binding = {
        "principal_id": f"agent:{backend}:contention",
        "route_id": f"route:{backend}:contention",
        "credential_id": "",
        "credential_version": 0,
        "policy_hash": "sha256:" + "7" * 64,
        "request_digest": "sha256:" + "8" * 64,
        "operation_digest": None,
    }

    def contend(index: int) -> dict[str, Any]:
        return db.reserve_release_authorization(
            **release_reserve_kwargs(
                contention_binding,
                attempt_id=f"attempt:{backend}:contention:{index}",
                quotas=contention_quotas,
                require_jit_grant=False,
            )
        )

    with ThreadPoolExecutor(max_workers=32) as pool:
        contention = list(pool.map(contend, range(32)))
    winners = [item for item in contention if item.get("state") == "reserved"]
    denials = [item for item in contention if item.get("state") == "denied"]
    if len(winners) != 8 or len(denials) != 24:
        raise AssertionError(
            f"32-way multi-counter contention was not atomic: {len(winners)} winners, {len(denials)} denials"
        )
    if any(counter_count(db, item["counter_key"]) != 8 for item in contention_quotas):
        raise AssertionError("multi-counter contention partially incremented one counter")

    with db.connect() as reopened:
        durable = reopened.execute(
            "SELECT state, binding_digest FROM release_authorization_attempts "
            "WHERE attempt_id = ?",
            (commit_attempt,),
        ).fetchone()
        event_rows = reopened.execute(
            "SELECT event_type, audited_at FROM release_authorization_events "
            "WHERE attempt_id = ? ORDER BY created_at ASC",
            (commit_attempt,),
        ).fetchall()
    if durable is None or durable["state"] != "committed":
        raise AssertionError("release state did not survive connection close and reopen")
    event_types = {item["event_type"] for item in event_rows}
    if event_types != {
        "release_authorization.reserved",
        "release_authorization.dispatching",
        "release_authorization.committed",
    }:
        raise AssertionError(f"transactional lifecycle outbox is incomplete: {event_types}")
    with db.connect() as conn:
        commit_consumption = conn.execute(
            "SELECT id, audited_at FROM approval_grant_consumptions "
            "WHERE attempt_id = ?",
            (commit_attempt,),
        ).fetchone()
    if commit_consumption is None or commit_consumption["audited_at"] is not None:
        raise AssertionError("atomic grant consumption was not durably pending audit")
    original_mark = db._mark_release_authorization_audit_delivery
    crash_injected = False

    def crash_after_delivery(kind: str, row_id: str, event_hash: str) -> int:
        nonlocal crash_injected
        if kind == "grant_consumption" and row_id == commit_consumption["id"] and not crash_injected:
            crash_injected = True
            raise RuntimeError("forced crash after grant consumption audit delivery")
        return original_mark(kind, row_id, event_hash)

    with patch.object(
        db,
        "_mark_release_authorization_audit_delivery",
        side_effect=crash_after_delivery,
    ):
        assert_raises(
            RuntimeError,
            lambda: db.drain_release_authorization_audit_outbox(500),
            "grant consumption audit crash window was not exercised",
        )
    if not crash_injected:
        raise AssertionError("grant consumption audit drain did not reach the committed attempt")
    delivered_before_ack = db.search_audit_events(
        event_type="jit.grant.consumed", limit=100, scan_limit=5000
    )
    delivered_matches = [
        item
        for item in delivered_before_ack.get("items") or []
        if item.get("event", {}).get("attempt_id") == commit_attempt
    ]
    with db.connect() as conn:
        pending_consumption = conn.execute(
            "SELECT audited_at FROM approval_grant_consumptions WHERE id = ?",
            (commit_consumption["id"],),
        ).fetchone()
    if len(delivered_matches) != 1 or pending_consumption["audited_at"] is not None:
        raise AssertionError(
            "audit delivery crash did not retain one idempotent event and pending acknowledgement"
        )
    drained = db.drain_release_authorization_audit_outbox(500)
    if not drained.get("ok") or drained.get("grant_consumptions_completed", 0) < 1:
        raise AssertionError(f"release audit outbox retry did not acknowledge consumption: {drained}")
    db.drain_release_authorization_audit_outbox(500)
    audited = db.search_audit_events(
        event_type="release_authorization.committed", limit=100, scan_limit=5000
    )
    if not any(
        item.get("event", {}).get("attempt_id") == commit_attempt
        for item in audited.get("items") or []
    ):
        raise AssertionError("committed release lifecycle event did not reach audit chain")
    consumed_audited = db.search_audit_events(
        event_type="jit.grant.consumed", limit=100, scan_limit=5000
    )
    consumed_matches = [
        item
        for item in consumed_audited.get("items") or []
        if item.get("event", {}).get("attempt_id") == commit_attempt
    ]
    with db.connect() as conn:
        acknowledged = conn.execute(
            "SELECT audited_at, audit_event_hash FROM approval_grant_consumptions "
            "WHERE id = ?",
            (commit_consumption["id"],),
        ).fetchone()
    if (
        len(consumed_matches) != 1
        or acknowledged["audited_at"] is None
        or acknowledged["audit_event_hash"] != consumed_matches[0]["event_hash"]
        or consumed_matches[0].get("event", {}).get("consumption_id")
        != commit_consumption["id"]
    ):
        raise AssertionError(
            "authoritative grant consumption evidence was duplicated or not acknowledged"
        )


def exercise_control_plane_jit_approval(app_module: Any, db: Any, backend: str) -> None:
    principal_id = f"agent:{backend}:reserve-approval"
    route_id = f"route:{backend}:reserve-approval"
    credential_id = f"credential:{backend}:reserve-approval"
    policy_hash = "sha256:" + hashlib.sha256(
        f"{backend}:reserve-approval:policy".encode("utf-8")
    ).hexdigest()
    operation = {"account": "acct:test", "operation": "test.forward"}
    body_sha256 = "sha256:" + hashlib.sha256(b'{"safe":true}').hexdigest()
    canonical = {
        "v": 1,
        "principal": principal_id,
        "client_ip": "192.0.2.10",
        "route_id": route_id,
        "credential_ref": credential_id,
        "credential_version": "1",
        "policy_hash": policy_hash,
        "request": {
            "method": "POST",
            "scheme": "https",
            "authority": "upstream.invalid",
            "path": "/actual/request",
            "query": [["access_token", "must-not-be-presented"], ["page", "1"]],
            "headers": {
                "accept": "application/json",
                "content-length": "13",
                "host": "upstream.invalid",
            },
            "body_sha256": body_sha256,
        },
        "operation": operation,
    }

    def digest(value: dict[str, Any]) -> str:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
        return "sha256:" + hashlib.sha256(encoded).hexdigest()

    def operation_digest(value: dict[str, Any]) -> str:
        return digest(
            {
                "principal": value["principal"],
                "route_id": value["route_id"],
                "credential_ref": value["credential_ref"],
                "credential_version": value["credential_version"],
                "policy_hash": value["policy_hash"],
                "request": value["request"],
                "operation": value["operation"],
            }
        )

    def reserve_payload(
        attempt_id: str,
        *,
        canonical_request: dict[str, Any] | None = canonical,
        request_digest: str | None = None,
        submitted_operation_digest: str | None = None,
    ) -> dict[str, Any]:
        payload = {
            "apiVersion": "serverware.releaseAuthorizationReserve/v1",
            "attemptId": attempt_id,
            "flowId": f"flow:{attempt_id}",
            "principalId": principal_id,
            "routeId": route_id,
            "credentialRef": credential_id,
            "credentialVersion": 1,
            "policyHash": policy_hash,
            "requestDigest": request_digest or digest(canonical_request or canonical),
            "operationDigest": submitted_operation_digest
            or operation_digest(canonical_request or canonical),
            "operationContext": operation,
        }
        if canonical_request is not None:
            payload["canonicalRequest"] = canonical_request
        return payload

    quota = {
        "id": f"quota:{backend}:reserve-approval",
        "type": "rateLimit",
        "store": "shared",
        "max": 10,
        "windowSeconds": 60,
        "key": {
            "scope": ["principal", "credential", "route", "operation"]
        },
    }
    route = SimpleNamespace(
        id=route_id,
        principals=(principal_id,),
        scheme="https",
        host="upstream.invalid",
        port=443,
        methods=frozenset({"POST"}),
        match_path=lambda path: {} if path == "/actual/request" else None,
        credential_ref=credential_id,
        constraints=(quota,),
        jit={
            "required": True,
            "pendingTtlSeconds": 300,
            "ttlSeconds": 60,
            "maxUses": 1,
            "consumeOn": "forwardStart",
            "binding": {"type": "operationDigest"},
        },
    )
    snapshot = SimpleNamespace(hash=policy_hash, routes=(route,))

    def reserve(payload: dict[str, Any]) -> dict[str, Any]:
        return app_module.data_plane_release_authorization_reserve(
            app_module.DataPlaneReleaseAuthorizationReserve.model_validate(payload),
            app_module.DATA_PLANE_RELEASE_AUTHORIZATION_TOKEN,
        )

    def expect_http_status(payload: dict[str, Any], status_code: int) -> None:
        with patch.object(
            app_module.db,
            "reserve_release_authorization",
            side_effect=AssertionError("invalid canonical data reached reservation"),
        ):
            try:
                reserve(payload)
            except app_module.HTTPException as exc:
                if exc.status_code != status_code:
                    raise AssertionError(
                        f"canonical reserve failed with {exc.status_code}: {exc.detail}"
                    ) from exc
            else:
                raise AssertionError(
                    f"canonical reserve unexpectedly succeeded: {payload}"
                )

    with (
        patch.object(app_module, "get_policy_snapshot", return_value=snapshot),
        patch.object(
            app_module.db,
            "get_credential",
            return_value={"credential_version": 1},
        ),
        patch.object(app_module, "_release_authorization_maintenance"),
    ):
        with ThreadPoolExecutor(max_workers=8) as pool:
            responses = list(
                pool.map(
                    lambda index: reserve(
                        reserve_payload(
                            f"attempt:{backend}:reserve-approval:{index}"
                        )
                    ),
                    range(16),
                )
            )
        approval_ids = {item.get("approvalRequestId") for item in responses}
        if len(approval_ids) != 1 or None in approval_ids:
            raise AssertionError(
                f"concurrent reserve denials created multiple approvals: {responses}"
            )
        if sum(item.get("approvalCreated") is True for item in responses) != 1:
            raise AssertionError(
                f"concurrent reserve denials did not identify one creator: {responses}"
            )
        if any(
            item.get("authorized")
            or item.get("state") != "denied"
            or item.get("reason") != "jit_grant_unavailable"
            or item.get("approvalStatus") != "pending"
            or not item.get("approvalExpiresAt")
            or item.get("retryAfterSeconds") != 3
            for item in responses
        ):
            raise AssertionError(
                f"reserve denial did not return retryable approval state: {responses}"
            )

        replay_payload = reserve_payload(f"attempt:{backend}:reserve-approval:replay")
        replay = reserve(replay_payload)
        exact_replay = reserve(replay_payload)
        if (
            replay.get("approvalRequestId") not in approval_ids
            or replay.get("approvalCreated") is not False
            or replay.get("approvalStatus") != "pending"
            or exact_replay.get("approvalRequestId") != replay.get("approvalRequestId")
            or exact_replay.get("bindingDigest") != replay.get("bindingDigest")
            or exact_replay.get("approvalCreated") is not False
        ):
            raise AssertionError(
                "reserve denial did not reuse its approval and binding: "
                f"{replay} {exact_replay}"
            )

        normal_request_digest = digest(canonical)
        normal_operation_digest = operation_digest(canonical)
        expect_http_status(
            reserve_payload(
                f"attempt:{backend}:bad-request-digest",
                request_digest="sha256:" + "f" * 64,
            ),
            409,
        )
        expect_http_status(
            reserve_payload(
                f"attempt:{backend}:bad-operation-digest",
                submitted_operation_digest="sha256:" + "e" * 64,
            ),
            409,
        )
        if normal_request_digest == "sha256:" + "f" * 64 or normal_operation_digest == "sha256:" + "e" * 64:
            raise AssertionError("digest mismatch fixtures unexpectedly matched")

        binding_mismatches = {
            "principal": "agent:other",
            "route_id": "route:other",
            "credential_ref": "credential:other",
            "credential_version": "2",
            "policy_hash": "sha256:" + "d" * 64,
            "operation": {"account": "acct:other", "operation": "test.forward"},
        }
        for field, value in binding_mismatches.items():
            changed = json.loads(json.dumps(canonical))
            changed[field] = value
            expect_http_status(
                reserve_payload(
                    f"attempt:{backend}:binding-mismatch:{field}",
                    canonical_request=changed,
                ),
                409,
            )
        hostile_targets = {
            "method": {"method": "GET"},
            "scheme": {"scheme": "http"},
            "host": {"authority": "attacker.invalid"},
            "port": {"authority": "upstream.invalid:444"},
            "path": {"path": "/outside/route"},
        }
        for label, request_changes in hostile_targets.items():
            changed = json.loads(json.dumps(canonical))
            changed["request"].update(request_changes)
            if "authority" in request_changes:
                changed["request"]["headers"]["host"] = request_changes["authority"]
            expect_http_status(
                reserve_payload(
                    f"attempt:{backend}:hostile-target:{label}",
                    canonical_request=changed,
                ),
                409,
            )
        hostile_headers = {
            "invalid-name": {
                "bad header": "value",
                "host": "upstream.invalid",
            },
            "uppercase-name": {
                "Host": "upstream.invalid",
                "host": "upstream.invalid",
            },
            "name-control": {
                "bad\x01header": "value",
                "host": "upstream.invalid",
            },
            "value-control": {
                "host": "upstream.invalid",
                "x-test": "safe\x01unsafe",
            },
            "value-tab": {
                "host": "upstream.invalid",
                "x-test": "safe\tunsafe",
            },
        }
        for label, headers in hostile_headers.items():
            changed = json.loads(json.dumps(canonical))
            changed["request"]["headers"] = headers
            expect_http_status(
                reserve_payload(
                    f"attempt:{backend}:hostile-header:{label}",
                    canonical_request=changed,
                ),
                409,
            )
        oversized_url = json.loads(json.dumps(canonical))
        oversized_url["request"]["query"] = [
            ["a", "1" * 6000],
            ["b", "2" * 6000],
            ["c", "3" * 6000],
        ]
        expect_http_status(
            reserve_payload(
                f"attempt:{backend}:oversized-derived-url",
                canonical_request=oversized_url,
            ),
            413,
        )
        expect_http_status(
            reserve_payload(
                f"attempt:{backend}:missing-canonical",
                canonical_request=None,
            ),
            409,
        )
        try:
            app_module.DataPlaneReleaseAuthorizationReserve.model_validate(
                {
                    **reserve_payload(f"attempt:{backend}:client-display"),
                    "redactedDisplay": {"url": "https://attacker.invalid"},
                }
            )
        except app_module.ValidationError:
            pass
        else:
            raise AssertionError("reserve accepted a client-controlled redactedDisplay")
        oversized_canonical = json.loads(json.dumps(canonical))
        oversized_canonical["request"]["headers"].update(
            {f"x-large-{index}": "x" * 16_000 for index in range(5)}
        )
        try:
            app_module.DataPlaneReleaseAuthorizationReserve.model_validate(
                reserve_payload(
                    f"attempt:{backend}:oversized-canonical",
                    canonical_request=oversized_canonical,
                )
            )
        except app_module.ValidationError:
            pass
        else:
            raise AssertionError("reserve accepted a canonicalRequest larger than 64 KiB")

    approval_id = next(iter(approval_ids))
    approval = db.get_approval_request(approval_id)
    expected_url = (
        "https://upstream.invalid/actual/request?"
        "access_token=redacted&page=1"
    )
    expected_display = {
        "method": "POST",
        "url": expected_url,
        "route_id": route_id,
        "principal": principal_id,
        "body_sha256": body_sha256,
    }
    if (
        not approval
        or approval.get("status") != "pending"
        or approval.get("method") != "POST"
        or approval.get("url") != expected_url
        or approval.get("canonical_request") != canonical
        or approval.get("redacted_display") != expected_display
    ):
        raise AssertionError(
            f"control plane did not persist the derived canonical approval: {approval}"
        )
    if "must-not-be-presented" in json.dumps(expected_display, sort_keys=True):
        raise AssertionError("derived approval presentation retained a sensitive query value")

    with db.connect() as conn:
        grant_count = conn.execute(
            "SELECT COUNT(*) AS count FROM approval_grants WHERE request_digest = ?",
            (digest(canonical),),
        ).fetchone()
        quota_count = conn.execute(
            "SELECT COUNT(*) AS count FROM rate_limit_counters WHERE route_id = ?",
            (route_id,),
        ).fetchone()
        attempt_count = conn.execute(
            "SELECT COUNT(*) AS count FROM release_authorization_attempts "
            "WHERE route_id = ?",
            (route_id,),
        ).fetchone()
        approval_count = conn.execute(
            "SELECT COUNT(*) AS count FROM approval_requests "
            "WHERE route_id = ? AND status = 'pending'",
            (route_id,),
        ).fetchone()
    if (
        int(grant_count["count"]) != 0
        or int(quota_count["count"]) != 0
        or int(attempt_count["count"]) != 0
        or int(approval_count["count"]) != 1
    ):
        raise AssertionError(
            "JIT reserve denial mutated grants, quotas, attempts, or duplicate approvals: "
            f"grant={dict(grant_count)} quota={dict(quota_count)} "
            f"attempt={dict(attempt_count)} approval={dict(approval_count)}"
        )


def exercise_proxy_credential_binding(policy_engine: Any, credential_policy_type: Any) -> None:
    scopes = ("tweet.read", "tweet.write")
    policy = credential_policy_type(
        id="credential:x",
        provider="twitter",
        provider_subject="subject-123",
        scopes=scopes,
        injection={
            "type": "bearer",
            "header": "Authorization",
            "field": "access_token",
        },
    )
    credential = {
        "id": policy.id,
        "kind": "oauth2",
        "secret": json.dumps({"access_token": "test-token"}),
        "credential_version": 1,
        "metadata": {
            "oauth": True,
            "provider_identity_verified": True,
            "provider_id": "x.oauth2",
            "provider_subject": "subject-123",
            "scopes": list(reversed(scopes)),
        },
    }
    if policy_engine._credential_policy_binding_decision(policy, credential) is not None:
        raise AssertionError("proxy binding rejected lease-equivalent provider aliases or scope order")

    mismatches = (
        (
            credential_policy_type(
                id=policy.id,
                provider="x",
                provider_subject="different-subject",
                scopes=scopes,
                injection=policy.injection,
            ),
            credential,
            "providerSubject",
        ),
        (
            credential_policy_type(
                id=policy.id,
                provider="x",
                provider_subject="subject-123",
                scopes=("tweet.read",),
                injection=policy.injection,
            ),
            credential,
            "scope",
        ),
        (
            policy,
            {
                **credential,
                "metadata": {**credential["metadata"], "provider_id": "google"},
            },
            "provider",
        ),
    )
    for candidate_policy, candidate_credential, binding in mismatches:
        decision = policy_engine._credential_policy_binding_decision(
            candidate_policy,
            candidate_credential,
        )
        if (
            decision is None
            or decision.allowed
            or decision.status_code != 409
            or decision.payload.get("binding") != binding
        ):
            raise AssertionError(f"proxy accepted mismatched signed credential {binding}: {decision}")

    malformed = {
        **credential,
        "metadata": {**credential["metadata"], "scopes": [scopes[0], scopes[0]]},
    }
    malformed_decision = policy_engine._credential_policy_binding_decision(policy, malformed)
    if (
        malformed_decision is None
        or malformed_decision.status_code != 503
        or malformed_decision.payload.get("error") != "credential_policy_binding_invalid"
    ):
        raise AssertionError(f"proxy did not fail closed on malformed stored scopes: {malformed_decision}")

    service_policy = credential_policy_type(
        id="credential:service",
        provider="stripe",
        scopes=("charges.write",),
        injection={"type": "header", "name": "X-Api-Key"},
    )
    service_credential = {
        "kind": "header",
        "metadata": {"provider": "stripe", "scope": "charges.write"},
    }
    if policy_engine._credential_policy_binding_decision(service_policy, service_credential) is not None:
        raise AssertionError("proxy rejected a non-OAuth credential within its signed scope binding")
    expanded = {
        **service_credential,
        "metadata": {"provider": "stripe", "scope": "charges.write refunds.write"},
    }
    expanded_decision = policy_engine._credential_policy_binding_decision(service_policy, expanded)
    if expanded_decision is None or expanded_decision.status_code != 409:
        raise AssertionError("proxy allowed stored non-OAuth scopes to exceed signed policy")


def exercise_internal_header_boundary(
    policy_engine: Any,
    compile_policy_bundle: Any,
    demo_policy_bundle: Any,
    policy_bundle_error: type[BaseException],
) -> None:
    request = SimpleNamespace(
        pretty_url="https://upstream.invalid/resource",
        headers={
            "accept": "application/json",
            "X-Serverware-Data-Plane-Token": "service-secret",
            "X-Serverware-Debug-Only": "mutable-outside-digest",
        },
        raw_content=b"",
    )
    flow = SimpleNamespace(request=request)
    forwarded = policy_engine._canonical_forwarded_request_headers(flow, None)
    if forwarded != {"accept": "application/json", "host": "upstream.invalid"}:
        raise AssertionError(f"internal headers entered canonical forwarding state: {forwarded}")

    adapter_route = SimpleNamespace(
        adapter_config={
            "request": {
                "allowedHeaders": ["accept"],
                "requiredHeaders": {},
                "allowedQueryKeys": [],
                "bodyMode": "none",
                "maxBodyBytes": 0,
            }
        },
        credential_ref=None,
        constraints=(),
    )
    adapter_decision = policy_engine.get_adapter("generic.rest").validate_request(
        flow,
        adapter_route,
        {},
    )
    if not adapter_decision.allowed:
        raise AssertionError(f"generic adapter did not treat internal headers as non-forwarded: {adapter_decision}")

    principal = SimpleNamespace(required_headers={})
    policy_engine._strip_identity_headers(flow, principal)
    if any(str(name).lower().startswith("x-serverware-") for name in request.headers):
        raise AssertionError(f"internal headers survived upstream stripping: {request.headers}")

    bundle = demo_policy_bundle()
    generic_route = next(
        route for route in bundle["routes"] if route["adapter"]["type"] == "generic.rest"
    )
    generic_route["adapter"]["config"]["request"]["allowedHeaders"].append(
        "X-Serverware-Debug-Only"
    )
    try:
        compile_policy_bundle(bundle, validate_schema=False)
    except policy_bundle_error as exc:
        if "credential or internal headers" not in str(exc):
            raise AssertionError(f"internal allowedHeaders failed for the wrong reason: {exc}") from exc
    else:
        raise AssertionError("generic allowedHeaders accepted an internal Serverware header")


def _run_proxy_transaction(
    policy_engine: Any,
    credential_policy_type: Any,
    *,
    credential_policy: Any = None,
    credential: dict[str, Any] | None = None,
    jit_required: bool = True,
    reserve_result: dict[str, Any] | BaseException | None = None,
    rewrite_allowed: bool = True,
    rewrite_error: BaseException | None = None,
    dispatch_result: dict[str, Any] | BaseException | None = None,
    complete_result: dict[str, Any] | BaseException | None = None,
    followup: str | None = None,
) -> tuple[Any, list[str], Any, Any]:
    events: list[str] = []
    credential_policy = credential_policy or credential_policy_type(
        id="credential:test",
        provider="generic",
        provider_subject=None,
        scopes=(),
        injection={"type": "bearer"},
    )
    credential = credential or {
        "id": credential_policy.id,
        "kind": "bearer",
        "secret": "test-secret",
        "credential_version": 1,
        "metadata": {},
    }
    principal = SimpleNamespace(id="agent:test", required_headers={})
    route = SimpleNamespace(
        id="route:test",
        credential_ref=credential_policy.id,
        adapter_type="generic.rest",
        constraints=(
            {
                "id": "shared-quota",
                "type": "rateLimit",
                "store": "shared",
                "max": 1,
                "windowSeconds": 60,
                "key": {"scope": ["principal", "credential", "route", "operation"]},
            },
        ),
        jit={"required": jit_required},
    )

    class Adapter:
        def validate_credential(self, _route: Any, _credential: Any) -> Any:
            events.append("validate_credential")
            return policy_engine.PolicyDecision(True)

        def validate_request(self, _flow: Any, _route: Any, _params: Any) -> Any:
            events.append("validate_request")
            return policy_engine.PolicyDecision(True)

        def operation_fields(self, _flow: Any, _route: Any, _params: Any) -> dict[str, str]:
            events.append("operation_fields")
            return {"operation": "test.forward"}

        def rewrite_request(self, _flow: Any, _route: Any, _params: Any) -> Any:
            events.append("rewrite")
            if rewrite_error is not None:
                raise rewrite_error
            return policy_engine.PolicyDecision(
                rewrite_allowed,
                "rewrite denied" if not rewrite_allowed else None,
                403,
                {"error": "rewrite_denied"} if not rewrite_allowed else {},
            )

        def validate_response(self, _flow: Any, _route: Any, _params: Any) -> Any:
            events.append("validate_response")
            return policy_engine.PolicyDecision(True)

    adapter = Adapter()
    snapshot = SimpleNamespace(
        hash="sha256:" + "f" * 64,
        credentials={credential_policy.id: credential_policy},
        identify_principal=lambda _ip, _headers: principal,
        match_route=lambda *_args: SimpleNamespace(route=route, params={}),
    )
    request = SimpleNamespace(
        method="POST",
        pretty_url="https://upstream.invalid/resource",
        headers={"accept": "application/json", "X-Serverware-Debug-Only": "strip-me"},
        raw_content=b"",
    )

    class MutableQuery(dict[str, str]):
        def __setitem__(self, key: str, value: str) -> None:
            super().__setitem__(key, value)
            parts = urlsplit(request.pretty_url)
            pairs = [
                (existing_key, existing_value)
                for existing_key, existing_value in parse_qsl(
                    parts.query,
                    keep_blank_values=True,
                )
                if existing_key != key
            ]
            pairs.append((key, value))
            request.pretty_url = urlunsplit(
                (
                    parts.scheme,
                    parts.netloc,
                    parts.path,
                    urlencode(pairs),
                    parts.fragment,
                )
            )

    request.query = MutableQuery()
    audit_records: list[dict[str, Any]] = []
    flow = SimpleNamespace(
        request=request,
        client_conn=SimpleNamespace(peername=("127.0.0.1", 43123)),
        metadata={},
        response=None,
        audit_records=audit_records,
    )

    def constraints(*_args: Any, **kwargs: Any) -> Any:
        if kwargs.get("skip_rate_limits"):
            events.append("policy_validate")
        elif kwargs.get("rate_limits_only") and kwargs.get("skip_shared_rate_limits"):
            events.append(
                "shared_commit_bypassed"
                if kwargs.get("consume_rate_limits")
                else "shared_preview_bypassed"
            )
        else:
            events.append("legacy_quota_call")
        return policy_engine.PolicyDecision(True)

    def credential_version(_credential_id: str | None) -> int:
        events.append("credential_version")
        return 1

    def credential_read(_credential_id: str | None) -> dict[str, Any]:
        events.append("credential_read")
        return credential

    def reserve(**kwargs: Any) -> dict[str, Any]:
        events.append("reserve")
        if isinstance(reserve_result, BaseException):
            raise reserve_result
        result = {
            "authorized": True,
            "state": "reserved",
            "reason": "reserved",
            "attempt_id": kwargs["attempt_id"],
            "binding_digest": "sha256:" + "1" * 64,
            "idempotent_replay": False,
            "grant_id": "grant:exact:test" if jit_required else None,
            "approval_request_id": "approval:exact:test" if jit_required else None,
            "approval_status": None,
            "approval_expires_at": None,
            "approval_created": None,
            "reservation_expires_at_epoch_ms": int(time.time() * 1000) + 60_000,
            "dispatch_started_at_epoch_ms": None,
            "dispatch_expires_at_epoch_ms": None,
            "completion_outcome": None,
            "retry_after_seconds": 0,
        }
        if isinstance(reserve_result, dict):
            result.update(reserve_result)
            result["attempt_id"] = kwargs["attempt_id"]
        return result

    def dispatch(**kwargs: Any) -> dict[str, Any]:
        events.append("dispatch")
        if isinstance(dispatch_result, BaseException):
            raise dispatch_result
        now_ms = int(time.time() * 1000)
        result = {
            "authorized": True,
            "state": "dispatching",
            "reason": "dispatching",
            "attempt_id": kwargs["attempt_id"],
            "binding_digest": kwargs["binding_digest"],
            "idempotent_replay": False,
            "grant_id": kwargs.get("grant_id"),
            "approval_request_id": kwargs.get("approval_request_id"),
            "approval_status": None,
            "approval_expires_at": None,
            "approval_created": None,
            "reservation_expires_at_epoch_ms": now_ms + 60_000,
            "dispatch_started_at_epoch_ms": now_ms,
            "dispatch_expires_at_epoch_ms": now_ms + 30_000,
            "completion_outcome": None,
            "retry_after_seconds": 0,
        }
        if isinstance(dispatch_result, dict):
            result.update(dispatch_result)
        return result

    def complete(**kwargs: Any) -> dict[str, Any]:
        events.append(f"complete:{kwargs['outcome']}")
        if isinstance(complete_result, BaseException):
            raise complete_result
        expected = {
            "forwarded": "committed",
            "not_forwarded": "cancelled",
            "unknown": "committed_indeterminate",
        }[kwargs["outcome"]]
        completion_reason = {
            "forwarded": "forwarded",
            "not_forwarded": "cancelled",
            "unknown": "forward_outcome_indeterminate",
        }[kwargs["outcome"]]
        now_ms = int(time.time() * 1000)
        result = {
            "authorized": expected != "cancelled",
            "state": expected,
            "reason": completion_reason,
            "attempt_id": kwargs["attempt_id"],
            "binding_digest": kwargs["binding_digest"],
            "idempotent_replay": False,
            "grant_id": kwargs.get("grant_id"),
            "approval_request_id": kwargs.get("approval_request_id"),
            "approval_status": None,
            "approval_expires_at": None,
            "approval_created": None,
            "reservation_expires_at_epoch_ms": now_ms + 60_000,
            "dispatch_started_at_epoch_ms": (
                None if kwargs["outcome"] == "not_forwarded" else now_ms
            ),
            "dispatch_expires_at_epoch_ms": (
                None if kwargs["outcome"] == "not_forwarded" else now_ms + 30_000
            ),
            "completion_outcome": kwargs["outcome"],
            "retry_after_seconds": 0,
        }
        if isinstance(complete_result, dict):
            result.update(complete_result)
        return result

    def log_request(
        route_id: str | None,
        method: str,
        url: str,
        action: str,
        status_code: int | None,
        reason: str | None,
        event: dict[str, Any] | None = None,
    ) -> None:
        audit_records.append(
            {
                "route_id": route_id,
                "method": method,
                "url": url,
                "action": action,
                "status_code": status_code,
                "reason": reason,
                "event": event,
            }
        )

    def reject_legacy(*_args: Any, **_kwargs: Any) -> Any:
        events.append("legacy_authorization_call")
        raise AssertionError("atomic mode called a legacy JIT or shared-quota path")

    with ExitStack() as stack:
        stack.enter_context(patch.object(policy_engine, "get_policy_snapshot", return_value=snapshot))
        stack.enter_context(patch.object(policy_engine, "get_adapter", return_value=adapter))
        stack.enter_context(patch.object(policy_engine.runtime, "prune_expired_caches", return_value=None))
        stack.enter_context(patch.object(policy_engine.runtime, "log_request", side_effect=log_request))
        stack.enter_context(patch.object(policy_engine.runtime, "atomic_release_authorization_enabled", return_value=True))
        stack.enter_context(patch.object(policy_engine.runtime, "get_credential_version", side_effect=credential_version))
        stack.enter_context(patch.object(policy_engine.runtime, "get_credential", side_effect=credential_read))
        stack.enter_context(patch.object(policy_engine.runtime, "reserve_release_authorization", side_effect=reserve))
        stack.enter_context(patch.object(policy_engine.runtime, "dispatch_release_authorization", side_effect=dispatch))
        stack.enter_context(patch.object(policy_engine.runtime, "complete_release_authorization", side_effect=complete))
        stack.enter_context(patch.object(policy_engine, "evaluate_request_constraints", side_effect=constraints))
        stack.enter_context(
            patch.object(
                policy_engine,
                "evaluate_response_constraints",
                return_value=policy_engine.PolicyDecision(True),
            )
        )
        stack.enter_context(patch.object(policy_engine.db, "find_jit_grant_result", side_effect=reject_legacy))
        stack.enter_context(patch.object(policy_engine.db, "consume_jit_grant_result", side_effect=reject_legacy))
        result = policy_engine.evaluate_request(flow)
        followup_decision = None
        if followup in {"dispatch", "response", "error", "audit_response"} and result.decision.allowed:
            followup_decision = policy_engine.dispatch_release_authorization(flow)
        if followup == "response" and followup_decision and followup_decision.allowed:
            events.append("response_policy_pending")
            completion = policy_engine.complete_release_authorization(flow, "forwarded")
            if completion.allowed:
                events.append("response_policy")
            followup_decision = completion
        elif followup == "error" and followup_decision and followup_decision.allowed:
            followup_decision = policy_engine.complete_release_authorization_for_error(flow)
        elif followup == "audit_response" and followup_decision and followup_decision.allowed:
            completion = policy_engine.complete_release_authorization(flow, "forwarded")
            if completion.allowed:
                flow.response = SimpleNamespace(
                    status_code=200,
                    raw_content=b'{"ok":true}',
                    content=b'{"ok":true}',
                    headers={"content-type": "application/json"},
                )
                followup_decision = policy_engine.evaluate_response(flow)
            else:
                followup_decision = completion
        elif followup == "reserved_error" and result.decision.allowed:
            followup_decision = policy_engine.complete_release_authorization_for_error(flow)
    return result, events, flow, followup_decision


def exercise_proxy_forward_start_ordering(policy_engine: Any, credential_policy_type: Any) -> None:
    allowed, events, flow, dispatched = _run_proxy_transaction(
        policy_engine,
        credential_policy_type,
        followup="dispatch",
    )
    if not allowed.decision.allowed:
        raise AssertionError(f"ordered proxy transaction was denied: {allowed.decision}")
    if not dispatched or not dispatched.allowed:
        raise AssertionError(f"reserved proxy transaction was not dispatched: {dispatched}")
    ordered = [
        events.index(name)
        for name in (
            "validate_request",
            "operation_fields",
            "policy_validate",
            "credential_version",
            "reserve",
            "credential_read",
            "validate_credential",
            "rewrite",
            "dispatch",
        )
    ]
    if ordered != sorted(ordered) or events[-1] != "dispatch":
        raise AssertionError(f"proxy lifecycle ordering is unsafe: {events}")
    if allowed.attempt_id != flow.metadata.get("serverware_release_attempt_id"):
        raise AssertionError("RequestEvaluation and flow metadata lost attempt correlation")
    lifecycle = flow.metadata.get("serverware_release_authorization") or {}
    if lifecycle.get("attempt_id") != lifecycle.get("flow_id"):
        raise AssertionError(f"attempt and flow IDs diverged: {lifecycle}")
    if any(name in events for name in ("legacy_authorization_call", "legacy_quota_call")):
        raise AssertionError(f"atomic mode used a legacy authorization path: {events}")
    if any(str(name).lower().startswith("x-serverware-") for name in flow.request.headers):
        raise AssertionError(f"proxy forwarded an internal Serverware header: {flow.request.headers}")

    quota_denied, quota_events, _, _ = _run_proxy_transaction(
        policy_engine,
        credential_policy_type,
        reserve_result={
            "authorized": False,
            "state": "denied",
            "reason": "shared_quota_denied",
            "binding_digest": "sha256:" + "2" * 64,
            "idempotent_replay": False,
            "grant_id": None,
            "approval_request_id": None,
            "approval_status": None,
            "approval_expires_at": None,
            "approval_created": None,
            "reservation_expires_at_epoch_ms": None,
            "dispatch_started_at_epoch_ms": None,
            "dispatch_expires_at_epoch_ms": None,
            "completion_outcome": None,
            "retry_after_seconds": 3,
        },
    )
    if quota_denied.decision.allowed or quota_denied.decision.status_code != 429:
        raise AssertionError(f"quota denial did not fail closed: {quota_denied.decision}")
    if "credential_read" in quota_events:
        raise AssertionError(f"quota denial read the credential secret: {quota_events}")

    uncertain, uncertain_events, _, _ = _run_proxy_transaction(
        policy_engine,
        credential_policy_type,
        reserve_result=policy_engine.runtime.ReleaseAuthorizationClientError("lost reserve response"),
    )
    if (
        uncertain.decision.allowed
        or uncertain.decision.status_code != 503
        or uncertain.decision.payload.get("error") != "release_authorization_reserve_uncertain"
    ):
        raise AssertionError(f"uncertain reserve did not fail closed: {uncertain.decision}")
    if any(name in uncertain_events for name in ("credential_read", "rewrite", "dispatch")):
        raise AssertionError(f"uncertain reserve reached credential or upstream preparation: {uncertain_events}")

    expired, expired_events, _, expired_dispatch = _run_proxy_transaction(
        policy_engine,
        credential_policy_type,
        reserve_result={
            "reservation_expires_at_epoch_ms": int(time.time() * 1000) - 1,
        },
        followup="dispatch",
    )
    if (
        not expired.decision.allowed
        or expired_dispatch is None
        or expired_dispatch.allowed
        or expired_dispatch.payload.get("error")
        != "release_authorization_reservation_expired"
        or "dispatch" in expired_events
        or "complete:not_forwarded" not in expired_events
    ):
        raise AssertionError(
            f"expired reservation reached upstream dispatch: {expired_dispatch} {expired_events}"
        )

    cancelled, cancel_events, cancel_flow, _ = _run_proxy_transaction(
        policy_engine,
        credential_policy_type,
        rewrite_allowed=False,
    )
    if cancelled.decision.allowed or "complete:not_forwarded" not in cancel_events:
        raise AssertionError(f"post-reserve preparation failure did not cancel: {cancel_events}")
    if cancel_flow.metadata.get("serverware_release_state") != "cancelled":
        raise AssertionError(f"cancelled release state was not retained: {cancel_flow.metadata}")

    exception_cancelled, exception_events, _, _ = _run_proxy_transaction(
        policy_engine,
        credential_policy_type,
        rewrite_error=RuntimeError("forced preparation exception"),
    )
    if (
        exception_cancelled.decision.allowed
        or exception_cancelled.decision.payload.get("error") != "request_rewrite_failed"
        or "complete:not_forwarded" not in exception_events
    ):
        raise AssertionError(
            f"post-reserve preparation exception was not cancelled: {exception_events}"
        )

    ambiguous, ambiguity_events, ambiguity_flow, ambiguity_decision = _run_proxy_transaction(
        policy_engine,
        credential_policy_type,
        dispatch_result=policy_engine.runtime.ReleaseAuthorizationClientError("lost response"),
        followup="dispatch",
    )
    if (
        not ambiguous.decision.allowed
        or not ambiguity_decision
        or ambiguity_decision.allowed
        or ambiguity_decision.payload.get("error") != "release_authorization_dispatch_uncertain"
    ):
        raise AssertionError(f"dispatch ambiguity did not fail closed: {ambiguity_decision}")
    if ambiguity_events[-2:] != ["dispatch", "complete:unknown"]:
        raise AssertionError(f"dispatch ambiguity was not committed unknown: {ambiguity_events}")
    if ambiguity_flow.metadata.get("serverware_release_state") != "committed_indeterminate":
        raise AssertionError("dispatch ambiguity lifecycle was not retained")

    for label, dispatch_response in (
        (
            "expired",
            {
                "dispatch_started_at_epoch_ms": int(time.time() * 1000) - 2_000,
                "dispatch_expires_at_epoch_ms": int(time.time() * 1000) - 1_000,
            },
        ),
        ("unauthorized", {"authorized": False}),
        (
            "completed",
            {
                "state": "committed",
                "reason": "committed",
                "completion_outcome": "forwarded",
            },
        ),
    ):
        prepared, invalid_events, _invalid_flow, invalid_dispatch = _run_proxy_transaction(
            policy_engine,
            credential_policy_type,
            dispatch_result=dispatch_response,
            followup="dispatch",
        )
        if (
            not prepared.decision.allowed
            or invalid_dispatch is None
            or invalid_dispatch.allowed
            or invalid_dispatch.payload.get("error")
            != "release_authorization_dispatch_invalid"
            or "complete:unknown" not in invalid_events
        ):
            raise AssertionError(
                f"{label} dispatch response was not rejected before upstream: "
                f"{invalid_dispatch} {invalid_events}"
            )

    _, response_events, response_flow, response_completion = _run_proxy_transaction(
        policy_engine,
        credential_policy_type,
        followup="response",
    )
    if not response_completion or not response_completion.allowed:
        raise AssertionError(f"forwarded response completion failed: {response_completion}")
    if response_events.index("complete:forwarded") > response_events.index("response_policy"):
        raise AssertionError(f"response policy ran before forwarded completion: {response_events}")
    if response_flow.metadata.get("serverware_release_state") != "committed":
        raise AssertionError("forwarded completion state was not retained")

    _, contradictory_events, _, contradictory_completion = _run_proxy_transaction(
        policy_engine,
        credential_policy_type,
        complete_result={"authorized": False},
        followup="response",
    )
    if (
        contradictory_completion is None
        or contradictory_completion.allowed
        or contradictory_completion.payload.get("error")
        != "release_authorization_completion_invalid"
        or "response_policy" in contradictory_events
    ):
        raise AssertionError(
            "authorized/state completion contradiction reached response release: "
            f"{contradictory_completion} {contradictory_events}"
        )

    _, reserved_error_events, _, reserved_error = _run_proxy_transaction(
        policy_engine,
        credential_policy_type,
        followup="reserved_error",
    )
    if not reserved_error or not reserved_error.allowed or reserved_error_events[-1] != "complete:not_forwarded":
        raise AssertionError(f"reserved transport error was not refunded: {reserved_error_events}")

    _, dispatched_error_events, _, dispatched_error = _run_proxy_transaction(
        policy_engine,
        credential_policy_type,
        followup="error",
    )
    if not dispatched_error or not dispatched_error.allowed or dispatched_error_events[-1] != "complete:unknown":
        raise AssertionError(f"dispatched transport error was not committed unknown: {dispatched_error_events}")

    bound_policy = credential_policy_type(
        id="credential:x",
        provider="x",
        provider_subject="signed-subject",
        scopes=("tweet.write",),
        injection={"type": "bearer", "field": "access_token"},
    )
    mismatched_credential = {
        "kind": "oauth2",
        "credential_version": 1,
        "secret": json.dumps({"access_token": "test-token"}),
        "metadata": {
            "oauth": True,
            "provider_identity_verified": True,
            "provider_id": "x",
            "provider_subject": "stored-other-subject",
            "scopes": ["tweet.write"],
        },
    }
    mismatched, mismatch_events, mismatch_flow, _ = _run_proxy_transaction(
        policy_engine,
        credential_policy_type,
        credential_policy=bound_policy,
        credential=mismatched_credential,
    )
    if mismatched.decision.allowed or mismatched.decision.status_code != 409:
        raise AssertionError(f"stored identity mismatch did not block the proxy: {mismatched.decision}")
    if mismatch_events.index("reserve") > mismatch_events.index("credential_read"):
        raise AssertionError(f"credential binding validation happened before reserve: {mismatch_events}")
    if "complete:not_forwarded" not in mismatch_events:
        raise AssertionError(f"credential mismatch did not cancel its reservation: {mismatch_events}")
    if mismatch_flow.metadata.get("serverware_release_state") != "cancelled":
        raise AssertionError("credential mismatch cancellation state was not retained")


def exercise_query_credential_audit_redaction(
    policy_engine: Any,
    credential_policy_type: Any,
) -> None:
    query_name = "credential_value"
    secret = "plain-query-secret-must-not-persist"
    credential_policy = credential_policy_type(
        id="credential:query-audit",
        provider="generic",
        provider_subject=None,
        scopes=(),
        injection={"type": "query", "name": query_name},
    )
    credential = {
        "id": credential_policy.id,
        "kind": "query",
        "secret": secret,
        "credential_version": 1,
        "metadata": {},
    }
    result, _events, flow, response_decision = _run_proxy_transaction(
        policy_engine,
        credential_policy_type,
        credential_policy=credential_policy,
        credential=credential,
        followup="audit_response",
    )
    if not result.decision.allowed or not response_decision or not response_decision.allowed:
        raise AssertionError(
            f"query credential audit fixture did not complete: {result.decision} {response_decision}"
        )
    if query_name not in flow.request.pretty_url or secret not in flow.request.pretty_url:
        raise AssertionError(
            f"query credential was not actually injected upstream: {flow.request.pretty_url}"
        )
    audit_records = flow.audit_records
    actions = {record.get("action") for record in audit_records}
    if not {"allowed", "response"}.issubset(actions):
        raise AssertionError(f"request/response audit records are missing: {audit_records}")
    serialized_audit = json.dumps(audit_records, sort_keys=True)
    if secret in serialized_audit or query_name in serialized_audit:
        raise AssertionError(
            f"custom query credential persisted in request/response audit: {audit_records}"
        )


def exercise_release_client_idempotent_retry(runtime: Any) -> None:
    attempt_id = "attempt:idempotent-retry"
    binding_digest = "sha256:" + "3" * 64
    reserve_payload = {
        "apiVersion": "serverware.releaseAuthorizationReserve/v1",
        "attemptId": attempt_id,
        "flowId": attempt_id,
        "principalId": "agent:test",
        "routeId": "route:test",
        "credentialRef": "credential:test",
        "credentialVersion": 1,
        "policyHash": "sha256:" + "4" * 64,
        "requestDigest": "sha256:" + "5" * 64,
        "operationDigest": "sha256:" + "6" * 64,
        "operationContext": {"operation": "test.forward"},
    }
    requests: list[dict[str, Any]] = []

    def flaky_request(request: Any, **_kwargs: Any) -> Any:
        requests.append(json.loads(request.data))
        if len(requests) == 1:
            raise urllib.error.URLError("response lost")
        return SimpleNamespace(
            body=json.dumps(
                {
                    "apiVersion": "serverware.releaseAuthorization/v1",
                    "ok": True,
                    "authorized": True,
                    "state": "reserved",
                    "reason": "reserved",
                    "attemptId": attempt_id,
                    "bindingDigest": binding_digest,
                    "idempotentReplay": True,
                    "reservationExpiresAtEpochMs": int(time.time() * 1000) + 60_000,
                    "retryAfterSeconds": 0,
                    "quotas": [],
                    "store": {"backend": "postgres", "ha": True},
                }
            ).encode("utf-8")
        )

    with ExitStack() as stack:
        stack.enter_context(
            patch.object(
                runtime,
                "_release_authorization_base_url",
                return_value="https://control.test/api/data-plane/release-authorizations",
            )
        )
        stack.enter_context(
            patch.object(runtime, "_release_authorization_token", return_value="test-token")
        )
        stack.enter_context(
            patch.object(runtime, "_release_authorization_ssl_context", return_value=None)
        )
        stack.enter_context(patch.object(runtime, "request_bytes", side_effect=flaky_request))
        stack.enter_context(patch.object(runtime.time, "sleep", return_value=None))
        result = runtime._release_authorization_http_post("reserve", reserve_payload)
    if result.get("state") != "reserved" or not result.get("idempotent_replay"):
        raise AssertionError(f"idempotent reserve retry did not recover: {result}")
    if len(requests) != 2 or requests[0] != requests[1]:
        raise AssertionError(f"reserve retry changed the durable attempt binding: {requests}")


def exercise_proxy_atomic_backend_integration(
    app_module: Any,
    policy_engine: Any,
    credential_policy_type: Any,
    db: Any,
    backend: str,
) -> None:
    credential_policy = credential_policy_type(
        id=f"credential:{backend}:proxy-integration",
        provider="generic",
        provider_subject=None,
        scopes=(),
        injection={"type": "bearer"},
    )
    principal = SimpleNamespace(id=f"agent:{backend}:proxy-integration", required_headers={})
    route = SimpleNamespace(
        id=f"route:{backend}:proxy-integration",
        principals=(principal.id,),
        scheme="https",
        host="upstream.invalid",
        port=443,
        methods=frozenset({"POST"}),
        match_path=lambda path: {} if path == "/integration" else None,
        credential_ref=credential_policy.id,
        adapter_type="generic.rest",
        constraints=(
            {
                "id": f"quota:{backend}:proxy-integration",
                "type": "rateLimit",
                "store": "shared",
                "max": 2,
                "windowSeconds": 60,
                "key": {
                    "scope": [
                        "principal",
                        "credential",
                        "credentialVersion",
                        "route",
                        "operation",
                    ]
                },
            },
        ),
        jit={
            "required": True,
            "pendingTtlSeconds": 300,
            "ttlSeconds": 60,
            "maxUses": 1,
        },
    )

    class Adapter:
        def validate_request(self, *_args: Any) -> Any:
            return policy_engine.PolicyDecision(True)

        def operation_fields(self, *_args: Any) -> dict[str, str]:
            return {"operation": "test.forward"}

        def validate_credential(self, *_args: Any) -> Any:
            return policy_engine.PolicyDecision(True)

        def rewrite_request(self, *_args: Any) -> Any:
            return policy_engine.PolicyDecision(True)

    snapshot = SimpleNamespace(
        hash="sha256:" + "d" * 64,
        routes=(route,),
        credentials={credential_policy.id: credential_policy},
        identify_principal=lambda *_args: principal,
        match_route=lambda *_args: SimpleNamespace(route=route, params={}),
    )
    credential = {
        "id": credential_policy.id,
        "kind": "bearer",
        "secret": f"secret-{backend}",
        "credential_version": 1,
        "metadata": {},
    }

    def request_flow() -> Any:
        return SimpleNamespace(
            request=SimpleNamespace(
                method="POST",
                pretty_url="https://upstream.invalid/integration",
                headers={"accept": "application/json"},
                raw_content=b"",
                query={},
            ),
            client_conn=SimpleNamespace(peername=("127.0.0.1", 43124)),
            metadata={},
        )

    def reserve_via_control_plane(**kwargs: Any) -> dict[str, Any]:
        response = app_module.data_plane_release_authorization_reserve(
            app_module.DataPlaneReleaseAuthorizationReserve.model_validate(
                {
                    "apiVersion": "serverware.releaseAuthorizationReserve/v1",
                    "attemptId": kwargs["attempt_id"],
                    "flowId": kwargs["flow_id"],
                    "principalId": kwargs["principal_id"],
                    "routeId": kwargs["route_id"],
                    "credentialRef": kwargs["credential_ref"],
                    "credentialVersion": kwargs["credential_version"],
                    "policyHash": kwargs["policy_hash"],
                    "requestDigest": kwargs["request_digest"],
                    "operationDigest": kwargs["operation_digest"],
                    "operationContext": kwargs["operation_context"],
                    "canonicalRequest": kwargs["canonical_request"],
                }
            ),
            app_module.DATA_PLANE_RELEASE_AUTHORIZATION_TOKEN,
        )
        return policy_engine.runtime._normalized_release_authorization_response(
            response,
            attempt_id=kwargs["attempt_id"],
        )

    with ExitStack() as stack:
        stack.enter_context(patch.object(policy_engine, "get_policy_snapshot", return_value=snapshot))
        stack.enter_context(patch.object(app_module, "get_policy_snapshot", return_value=snapshot))
        stack.enter_context(patch.object(policy_engine, "get_adapter", return_value=Adapter()))
        stack.enter_context(patch.object(policy_engine.runtime, "prune_expired_caches", return_value=None))
        stack.enter_context(patch.object(policy_engine.runtime, "log_request", return_value=None))
        stack.enter_context(
            patch.object(
                policy_engine.runtime,
                "atomic_release_authorization_enabled",
                return_value=True,
            )
        )
        stack.enter_context(
            patch.object(
                policy_engine.runtime,
                "_release_authorization_base_url",
                return_value="",
            )
        )
        stack.enter_context(
            patch.object(policy_engine.runtime, "get_credential_version", return_value=1)
        )
        stack.enter_context(
            patch.object(policy_engine.runtime, "get_credential", return_value=credential)
        )
        stack.enter_context(
            patch.object(app_module.db, "get_credential", return_value=credential)
        )
        stack.enter_context(
            patch.object(app_module, "_release_authorization_maintenance")
        )
        stack.enter_context(
            patch.object(
                policy_engine.runtime,
                "reserve_release_authorization",
                side_effect=reserve_via_control_plane,
            )
        )
        stack.enter_context(
            patch.object(
                policy_engine.db,
                "find_jit_grant_result",
                side_effect=AssertionError("atomic integration used legacy grant preview"),
            )
        )
        stack.enter_context(
            patch.object(
                policy_engine.db,
                "consume_jit_grant_result",
                side_effect=AssertionError("atomic integration used legacy grant consume"),
            )
        )

        pending = policy_engine.evaluate_request(request_flow())
        if (
            pending.decision.allowed
            or pending.decision.status_code != 428
            or pending.decision.payload.get("error") != "serverware_approval_required"
        ):
            raise AssertionError(f"atomic proxy did not create a retry approval: {pending.decision}")
        approved = db.approve_request(
            pending.decision.payload["approval_id"],
            ttl_seconds=60,
        )
        if not approved or approved.get("status") != "approved":
            raise AssertionError(f"atomic proxy approval did not activate: {approved}")

        forwarded_flow = request_flow()
        prepared = policy_engine.evaluate_request(forwarded_flow)
        if not prepared.decision.allowed or prepared.release_state != "reserved":
            raise AssertionError(f"atomic proxy did not reserve after approval: {prepared}")
        lifecycle = forwarded_flow.metadata.get("serverware_release_authorization") or {}
        if lifecycle.get("attempt_id") != lifecycle.get("flow_id"):
            raise AssertionError(f"atomic proxy split attempt and flow IDs: {lifecycle}")
        dispatched = policy_engine.dispatch_release_authorization(forwarded_flow)
        if not dispatched.allowed or forwarded_flow.metadata.get("serverware_release_state") != "dispatching":
            raise AssertionError(f"atomic proxy dispatch failed: {dispatched}")
        completed = policy_engine.complete_release_authorization(
            forwarded_flow,
            "forwarded",
        )
        if not completed.allowed or forwarded_flow.metadata.get("serverware_release_state") != "committed":
            raise AssertionError(f"atomic proxy completion failed: {completed}")


def exercise_webauthn_state(db: Any, backend: str) -> None:
    user_id = f"user:{backend}"
    challenge = f"challenge-{backend}"
    payload = {"binding": backend, "request_digest": "sha256:" + "e" * 64}
    db.create_webauthn_challenge(
        challenge=challenge,
        challenge_type="control-plane-mutation",
        user_id=user_id,
        payload=payload,
    )
    claimed = db.claim_webauthn_challenge(
        challenge,
        challenge_type="control-plane-mutation",
        user_id=user_id,
    )
    if not claimed or claimed["payload"] != payload or not claimed["used_at"]:
        raise AssertionError(f"claimed challenge lost binding fields: {claimed}")
    if db.claim_webauthn_challenge(
        challenge,
        challenge_type="control-plane-mutation",
        user_id=user_id,
    ) is not None:
        raise AssertionError("WebAuthn challenge was claimable twice")

    bound_challenge = f"challenge-bound-{backend}"
    db.create_webauthn_challenge(
        challenge=bound_challenge,
        challenge_type="approval",
        user_id=user_id,
        approval_request_id="approval-bound",
        payload={"approval_id": "approval-bound"},
    )
    wrong_binding = db.claim_webauthn_challenge(
        bound_challenge,
        challenge_type="approval",
        user_id=user_id,
        approval_request_id="approval-wrong",
    )
    if wrong_binding is not None:
        raise AssertionError("WebAuthn challenge claim ignored approval binding")
    correct_binding = db.claim_webauthn_challenge(
        bound_challenge,
        challenge_type="approval",
        user_id=user_id,
        approval_request_id="approval-bound",
    )
    if not correct_binding or correct_binding["approval_request_id"] != "approval-bound":
        raise AssertionError("failed binding did not leave challenge available for the bound request")

    race_challenge = f"challenge-race-{backend}"
    db.create_webauthn_challenge(
        challenge=race_challenge,
        challenge_type="registration",
        user_id=user_id,
        payload={"type": "registration"},
    )
    with ThreadPoolExecutor(max_workers=8) as pool:
        claims = list(pool.map(
            lambda _: db.claim_webauthn_challenge(
                race_challenge,
                challenge_type="registration",
                user_id=user_id,
            ),
            range(16),
        ))
    if sum(item is not None for item in claims) != 1:
        raise AssertionError("concurrent WebAuthn challenge claims did not have one winner")

    credential_id = f"credential-webauthn-{backend}"
    db.create_webauthn_credential(
        credential_id=credential_id,
        user_id=user_id,
        label="test credential",
        public_key_cose="test-public-key",
        sign_count=5,
        aaguid=None,
        authenticator_class="test",
    )
    with ThreadPoolExecutor(max_workers=2) as pool:
        updates = list(pool.map(
            lambda _: db.compare_and_swap_webauthn_sign_count(
                credential_id,
                expected_sign_count=5,
                new_sign_count=6,
            ),
            range(2),
        ))
    if updates.count(True) != 1:
        raise AssertionError(f"sign-count CAS did not have one winner: {updates}")
    if db.compare_and_swap_webauthn_sign_count(
        credential_id,
        expected_sign_count=6,
        new_sign_count=0,
    ):
        raise AssertionError("sign-count CAS accepted a counter downgrade")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--postgres-dsn")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory() as tmp:
        schema = None
        postgres_dsn = None
        backend = "sqlite"
        if args.postgres_dsn:
            backend = "postgres"
            schema, postgres_dsn = configure_postgres(args.postgres_dsn, tmp)
        else:
            configure_sqlite(tmp)
        try:
            try:
                import mitmproxy  # noqa: F401
            except ModuleNotFoundError:
                mitmproxy_module = ModuleType("mitmproxy")
                http_module = ModuleType("mitmproxy.http")
                http_module.HTTPFlow = object
                mitmproxy_module.http = http_module
                sys.modules["mitmproxy"] = mitmproxy_module
                sys.modules["mitmproxy.http"] = http_module

            from serverware import app as app_module
            from serverware import db, grants, policy_engine
            from serverware.policy_bundle import (
                CredentialPolicy,
                PolicyBundleError,
                compile_policy_bundle,
                demo_policy_bundle,
            )

            db.init_db()
            exercise_policy_high_water(db, backend)
            state = exercise_atomic_approval(db, grants, backend)
            exercise_grant_consumption(
                db,
                grants,
                backend,
                state["approval"],
                state["lookup"],
                postgres_dsn,
            )
            exercise_atomic_release_authorization(db, backend)
            exercise_control_plane_jit_approval(app_module, db, backend)
            exercise_proxy_credential_binding(policy_engine, CredentialPolicy)
            exercise_internal_header_boundary(
                policy_engine,
                compile_policy_bundle,
                demo_policy_bundle,
                PolicyBundleError,
            )
            exercise_proxy_forward_start_ordering(policy_engine, CredentialPolicy)
            exercise_query_credential_audit_redaction(
                policy_engine,
                CredentialPolicy,
            )
            exercise_release_client_idempotent_retry(policy_engine.runtime)
            exercise_proxy_atomic_backend_integration(
                app_module,
                policy_engine,
                CredentialPolicy,
                db,
                backend,
            )
            exercise_webauthn_state(db, backend)
        finally:
            if schema and args.postgres_dsn:
                drop_postgres_schema(args.postgres_dsn, schema)
    print(json.dumps({"backend": backend, "jit_transaction_state": "pass", "ok": True}, sort_keys=True))


if __name__ == "__main__":
    main()
