#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
import tempfile
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any
from urllib.parse import quote


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def configure_sqlite(data_dir: str) -> None:
    os.environ["SERVERWARE_DATA_DIR"] = data_dir
    os.environ["SERVERWARE_METADATA_STORE_BACKEND"] = "sqlite"
    os.environ["SERVERWARE_GRANT_STORE_BACKEND"] = "sqlite"
    os.environ["SERVERWARE_AUDIT_STORE_BACKEND"] = "sqlite"


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
            from serverware import db, grants

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
            exercise_webauthn_state(db, backend)
        finally:
            if schema and args.postgres_dsn:
                drop_postgres_schema(args.postgres_dsn, schema)
    print(json.dumps({"backend": backend, "jit_transaction_state": "pass", "ok": True}, sort_keys=True))


if __name__ == "__main__":
    main()
