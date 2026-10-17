#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
from contextlib import ExitStack
import hashlib
import hmac
import http.client
import json
import os
import re
import socket
import sqlite3
import sys
import tempfile
import threading
import time
import urllib.error
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any
from unittest.mock import patch
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def configure_sqlite(data_dir: str) -> None:
    os.environ["CATCHPLATE_DATA_DIR"] = data_dir
    os.environ["CATCHPLATE_METADATA_STORE_BACKEND"] = "sqlite"
    os.environ["CATCHPLATE_GRANT_STORE_BACKEND"] = "sqlite"
    os.environ["CATCHPLATE_AUDIT_STORE_BACKEND"] = "sqlite"
    os.environ["CATCHPLATE_RELEASE_CHANNEL"] = "test"
    os.environ["CATCHPLATE_KEY_RELEASE_REQUIRED"] = "0"
    os.environ["CATCHPLATE_DATA_PLANE_INSTANCE_ID"] = "jit-transaction-test"
    os.environ["CATCHPLATE_DATA_PLANE_RELEASE_AUTHORIZATION_TOKEN"] = "jit-release-test-token"


def postgres_schema_dsn(base_dsn: str, schema: str) -> str:
    separator = "&" if "?" in base_dsn else "?"
    options = quote(f"-csearch_path={schema}", safe="")
    return f"{base_dsn}{separator}options={options}"


def configure_postgres(base_dsn: str, data_dir: str) -> tuple[str, str]:
    import psycopg

    schema = f"catchplate_jit_test_{uuid.uuid4().hex}"
    with psycopg.connect(base_dsn, autocommit=True) as conn:
        conn.execute(f'CREATE SCHEMA "{schema}"')
    dsn = postgres_schema_dsn(base_dsn, schema)
    os.environ["CATCHPLATE_DATA_DIR"] = data_dir
    os.environ["CATCHPLATE_METADATA_STORE_BACKEND"] = "postgres"
    os.environ["CATCHPLATE_METADATA_STORE_POSTGRES_DSN"] = dsn
    os.environ["CATCHPLATE_GRANT_STORE_BACKEND"] = "postgres"
    os.environ["CATCHPLATE_GRANT_STORE_POSTGRES_DSN"] = dsn
    os.environ["CATCHPLATE_AUDIT_STORE_BACKEND"] = "postgres"
    os.environ["CATCHPLATE_AUDIT_STORE_POSTGRES_DSN"] = dsn
    os.environ["CATCHPLATE_RELEASE_CHANNEL"] = "test"
    os.environ["CATCHPLATE_KEY_RELEASE_REQUIRED"] = "0"
    os.environ["CATCHPLATE_DATA_PLANE_INSTANCE_ID"] = "jit-transaction-test"
    os.environ["CATCHPLATE_DATA_PLANE_RELEASE_AUTHORIZATION_TOKEN"] = "jit-release-test-token"
    return schema, dsn


def drop_postgres_schema(base_dsn: str, schema: str) -> None:
    import psycopg

    with psycopg.connect(base_dsn, autocommit=True) as conn:
        conn.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')


def exercise_postgres_catalog_schema_isolation(db: Any, base_dsn: str) -> None:
    import psycopg

    suffix = uuid.uuid4().hex
    table_name = f"catchplate_catalog_shadow_{suffix}"
    function_name = f"catchplate_catalog_shadow_guard_{suffix}"
    trigger_names = (
        "catchplate_audit_storage_epoch_guard",
        "catchplate_metadata_audit_storage_epoch_guard",
        "catchplate_rate_counter_storage_epoch_guard",
        "catchplate_quota_storage_epoch_guard",
    )
    with psycopg.connect(base_dsn, autocommit=True) as admin:
        admin.execute(
            f'''
            CREATE TABLE public."{table_name}" (
                value TEXT CONSTRAINT catchplate_audit_events_event_json_size
                    CHECK (octet_length(value) <= 8388608)
            );
            CREATE FUNCTION public."{function_name}"()
            RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN
                RETURN NEW;
            END;
            $$;
            '''
        )
        for trigger_name in trigger_names:
            admin.execute(
                f'CREATE TRIGGER "{trigger_name}" BEFORE INSERT OR UPDATE '
                f'ON public."{table_name}" FOR EACH ROW EXECUTE FUNCTION '
                f'public."{function_name}"()'
            )
    try:
        db.init_db()
        with psycopg.connect(base_dsn) as admin:
            count = int(
                admin.execute(
                    "SELECT COUNT(*)::bigint AS count FROM pg_trigger AS trigger "
                    "JOIN pg_class AS relation ON relation.oid = trigger.tgrelid "
                    "JOIN pg_namespace AS namespace "
                    "ON namespace.oid = relation.relnamespace "
                    "WHERE namespace.nspname = 'public' "
                    "AND relation.relname = %s AND trigger.tgname = ANY(%s) "
                    "AND NOT trigger.tgisinternal",
                    (table_name, list(trigger_names)),
                ).fetchone()[0]
            )
        if count != len(trigger_names):
            raise AssertionError(
                f"public duplicate-trigger fixture was incomplete: {count}"
            )
    finally:
        with psycopg.connect(base_dsn, autocommit=True) as admin:
            admin.execute(f'DROP TABLE IF EXISTS public."{table_name}" CASCADE')
            admin.execute(
                f'DROP FUNCTION IF EXISTS public."{function_name}"() CASCADE'
            )


def exercise_postgres_audit_lock_namespace(db: Any, base_dsn: str) -> None:
    import psycopg
    from psycopg.rows import dict_row

    schemas = [f"catchplate_lock_test_{uuid.uuid4().hex}" for _ in range(2)]
    with psycopg.connect(base_dsn, autocommit=True) as admin:
        for schema in schemas:
            admin.execute(f'CREATE SCHEMA "{schema}"')
    try:
        dsns = [postgres_schema_dsn(base_dsn, schema) for schema in schemas]
        with psycopg.connect(dsns[0], row_factory=dict_row) as first, psycopg.connect(
            dsns[1], row_factory=dict_row
        ) as second:
            with first.transaction(), second.transaction():
                for purpose in ("migration", "chain"):
                    first_key = db._postgres_audit_lock_key(first, purpose)
                    second_key = db._postgres_audit_lock_key(second, purpose)
                    if first_key == second_key:
                        raise AssertionError(
                            f"PostgreSQL audit {purpose} lock was not schema namespaced"
                        )
                    db._lock_postgres_audit(first, purpose)
                    db._lock_postgres_audit(second, purpose)

        same_schema_dsn = dsns[0]
        with psycopg.connect(
            same_schema_dsn, row_factory=dict_row
        ) as holder, psycopg.connect(same_schema_dsn, row_factory=dict_row) as waiter:
            with holder.transaction():
                db._lock_postgres_audit(holder, "chain")
                try:
                    with waiter.transaction(), patch.object(
                        db, "_AUDIT_LOCK_WAIT_MS", 100
                    ):
                        db._lock_postgres_audit(waiter, "chain")
                except db.AuditStoreError as exc:
                    if (
                        "timed out acquiring compatible legacy/namespaced "
                        "PostgreSQL audit chain locks"
                    ) not in str(exc):
                        raise AssertionError(f"audit lock timeout failed unclearly: {exc}") from exc
                else:
                    raise AssertionError("same-schema audit lock did not honor its timeout")
    finally:
        with psycopg.connect(base_dsn, autocommit=True) as admin:
            for schema in schemas:
                admin.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')


def exercise_postgres_rolling_audit_lock_compatibility(
    db: Any, dsn: str
) -> None:
    import psycopg
    from psycopg.rows import dict_row

    old_started = threading.Event()
    new_started = threading.Event()
    old_event_id = f"rolling-old:{uuid.uuid4().hex}"
    new_event_id = f"rolling-new:{uuid.uuid4().hex}"
    with psycopg.connect(dsn, row_factory=dict_row) as old_conn:
        old_conn.execute(
            "SELECT pg_advisory_xact_lock(%s)", (db._AUDIT_CHAIN_LOCK_KEY,)
        )
        previous = old_conn.execute(
            "SELECT event_hash FROM catchplate_audit_events "
            "ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        old_prev_hash = previous["event_hash"] if previous else None
        old_created_at = db.iso_now()
        old_event_json = db.dumps({"writer": "legacy-fixed-lock"})
        old_event_hash = db._audit_hash(
            event_id=old_event_id,
            event_type="test.audit.rolling-old",
            actor_type="test",
            actor_id="test:rolling-old",
            event_json=old_event_json,
            prev_event_hash=old_prev_hash,
            created_at=old_created_at,
        )
        old_started.set()

        def append_new() -> dict[str, Any]:
            if not old_started.wait(timeout=2):
                raise AssertionError("legacy audit writer did not start")
            new_started.set()
            return db.record_audit_event(
                "test.audit.rolling-new",
                {"writer": "dual-lock"},
                actor_type="test",
                actor_id="test:rolling-new",
                idempotency_key=new_event_id,
            )

        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(append_new)
            if not new_started.wait(timeout=2):
                raise AssertionError("new audit writer did not start")
            time.sleep(0.15)
            if future.done():
                raise AssertionError(
                    "new writer bypassed the legacy fixed audit-chain lock"
                )
            old_conn.execute(
                "INSERT INTO catchplate_audit_events "
                "(id, event_type, actor_type, actor_id, event_json, "
                "prev_event_hash, event_hash, created_at) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                (
                    old_event_id,
                    "test.audit.rolling-old",
                    "test",
                    "test:rolling-old",
                    old_event_json,
                    old_prev_hash,
                    old_event_hash,
                    old_created_at,
                ),
            )
            old_conn.commit()
            new_result = future.result(timeout=5)

    if new_result["prev_event_hash"] != old_event_hash:
        raise AssertionError(
            "rolling old/new audit writers produced sibling chain hashes: "
            f"old={old_event_hash} new={new_result}"
        )
    with psycopg.connect(dsn, row_factory=dict_row) as check:
        rows = check.execute(
            "SELECT id, prev_event_hash, event_hash FROM catchplate_audit_events "
            "WHERE id IN (%s, %s) ORDER BY sequence ASC",
            (old_event_id, new_event_id),
        ).fetchall()
    if (
        [row["id"] for row in rows] != [old_event_id, new_event_id]
        or rows[1]["prev_event_hash"] != rows[0]["event_hash"]
    ):
        raise AssertionError(f"rolling audit writer chain is invalid: {rows}")


def exercise_postgres_inflight_legacy_migration_barrier(
    db: Any, base_dsn: str
) -> None:
    import psycopg
    from psycopg.rows import dict_row

    schema = f"catchplate_inflight_legacy_{uuid.uuid4().hex}"
    dsn = postgres_schema_dsn(base_dsn, schema)
    keyring = db.load_bound_secret_keyring()
    with psycopg.connect(base_dsn, autocommit=True) as admin:
        admin.execute(f'CREATE SCHEMA "{schema}"')
    try:
        with psycopg.connect(dsn, row_factory=dict_row) as setup:
            with setup.transaction():
                setup.execute(
                    """
                    CREATE TABLE catchplate_audit_events (
                        sequence BIGSERIAL PRIMARY KEY,
                        id TEXT NOT NULL UNIQUE,
                        event_type TEXT NOT NULL,
                        actor_type TEXT NOT NULL,
                        actor_id TEXT,
                        event_json TEXT NOT NULL,
                        encrypted_canonical_event_json TEXT,
                        storage_format_version BIGINT,
                        prev_event_hash TEXT,
                        event_hash TEXT NOT NULL UNIQUE,
                        created_at TEXT NOT NULL
                    );
                    CREATE TABLE catchplate_store_migrations (
                        migration TEXT PRIMARY KEY,
                        version BIGINT NOT NULL,
                        applied_at TEXT NOT NULL
                    );
                    CREATE FUNCTION catchplate_audit_storage_epoch_guard()
                    RETURNS trigger LANGUAGE plpgsql AS $$
                    BEGIN
                        RETURN NEW;
                    END;
                    $$;
                    CREATE TRIGGER catchplate_audit_storage_epoch_guard
                        BEFORE INSERT OR UPDATE ON catchplate_audit_events
                        FOR EACH ROW EXECUTE FUNCTION
                            catchplate_audit_storage_epoch_guard();
                    CREATE TABLE metadata_audit_outbox (
                        id TEXT PRIMARY KEY,
                        event_type TEXT NOT NULL,
                        event_json TEXT NOT NULL,
                        storage_format_version BIGINT
                    );
                    CREATE TABLE rate_limit_counters (
                        counter_key TEXT PRIMARY KEY,
                        operation TEXT,
                        encrypted_operation TEXT,
                        operation_storage_version BIGINT
                    );
                    CREATE TABLE release_authorization_quota_reservations (
                        attempt_id TEXT NOT NULL,
                        counter_key TEXT NOT NULL,
                        operation TEXT,
                        encrypted_operation TEXT,
                        operation_storage_version BIGINT,
                        PRIMARY KEY (attempt_id, counter_key)
                    );
                    """
                )
                wrapper = db.PostgresMetadataConnection(setup)
                db._install_metadata_storage_epoch_guards(wrapper)

        audit_event_id = f"inflight-audit:{uuid.uuid4().hex}"
        audit_operation = "legacy.inflight.audit.operation"
        audit_event_json = db.dumps({"operation": audit_operation})
        audit_created_at = db.iso_now()
        audit_event_hash = db._audit_hash(
            event_id=audit_event_id,
            event_type="rate_limit.denied",
            actor_type="test",
            actor_id="test:inflight-legacy",
            event_json=audit_event_json,
            prev_event_hash=None,
            created_at=audit_created_at,
        )
        with psycopg.connect(dsn, row_factory=dict_row) as legacy:
            legacy.execute(
                "INSERT INTO catchplate_audit_events "
                "(id, event_type, actor_type, actor_id, event_json, "
                "prev_event_hash, event_hash, created_at) "
                "VALUES (%s, 'rate_limit.denied', 'test', "
                "'test:inflight-legacy', %s, NULL, %s, %s)",
                (
                    audit_event_id,
                    audit_event_json,
                    audit_event_hash,
                    audit_created_at,
                ),
            )

            def migrate_audit() -> None:
                with psycopg.connect(dsn, row_factory=dict_row) as migration:
                    with migration.transaction():
                        db._lock_postgres_audit(migration, "migration")
                        db._lock_postgres_audit(migration, "chain")
                        db._lock_postgres_audit_migration_tables(migration)
                        db._remediate_postgres_audit_operations(
                            migration, keyring=keyring
                        )

            with ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(migrate_audit)
                time.sleep(0.15)
                if future.done():
                    raise AssertionError(
                        "audit migration bypassed an in-flight legacy transaction"
                    )
                legacy.commit()
                future.result(timeout=5)

        with psycopg.connect(dsn, row_factory=dict_row) as check:
            audit_row = check.execute(
                "SELECT event_json, encrypted_canonical_event_json, "
                "storage_format_version, event_hash FROM catchplate_audit_events "
                "WHERE id = %s",
                (audit_event_id,),
            ).fetchone()
            audit_gate = check.execute(
                "SELECT version FROM catchplate_store_migrations "
                "WHERE migration = %s",
                (db._AUDIT_STORAGE_REDACTION_MIGRATION,),
            ).fetchone()
        if (
            audit_row is None
            or audit_row["storage_format_version"]
            != db._AUDIT_STORAGE_FORMAT_VERSION
            or audit_row["event_hash"] != audit_event_hash
            or audit_operation in audit_row["event_json"]
            or audit_operation in str(audit_row["encrypted_canonical_event_json"])
            or audit_gate is None
        ):
            raise AssertionError(
                f"in-flight legacy audit row escaped migration: {audit_row}"
            )

        counter_key = "sha256:" + hashlib.sha256(
            b"inflight-legacy-metadata"
        ).hexdigest()
        metadata_operation = "legacy.inflight.metadata.operation"
        with psycopg.connect(dsn, row_factory=dict_row) as legacy:
            legacy.execute(
                "INSERT INTO rate_limit_counters "
                "(counter_key, operation) VALUES (%s, %s)",
                (counter_key, metadata_operation),
            )

            def migrate_metadata() -> None:
                with psycopg.connect(dsn, row_factory=dict_row) as migration:
                    with migration.transaction():
                        wrapper = db.PostgresMetadataConnection(migration)
                        db._lock_postgres_metadata_migration_tables(wrapper)
                        db._remediate_metadata_rate_limit_storage(
                            wrapper, keyring=keyring
                        )

            with ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(migrate_metadata)
                time.sleep(0.15)
                if future.done():
                    raise AssertionError(
                        "metadata migration bypassed an in-flight legacy transaction"
                    )
                legacy.commit()
                future.result(timeout=5)

        with psycopg.connect(dsn, row_factory=dict_row) as check:
            counter = check.execute(
                "SELECT operation, encrypted_operation, operation_storage_version "
                "FROM rate_limit_counters WHERE counter_key = %s",
                (counter_key,),
            ).fetchone()
            metadata_gate = check.execute(
                "SELECT version FROM catchplate_store_migrations "
                "WHERE migration = %s",
                (db._METADATA_STORAGE_REDACTION_MIGRATION,),
            ).fetchone()
        if (
            counter is None
            or counter["operation"] != operation_digest(metadata_operation)
            or counter["operation_storage_version"]
            != db._OPERATION_STORAGE_VERSION
            or metadata_operation in str(counter["encrypted_operation"])
            or metadata_gate is None
        ):
            raise AssertionError(
                f"in-flight legacy metadata row escaped migration: {counter}"
            )
    finally:
        drop_postgres_schema(base_dsn, schema)


def exercise_postgres_audit_migration_faults(db: Any, base_dsn: str) -> None:
    import psycopg
    from psycopg.rows import dict_row

    keyring = db.load_bound_secret_keyring()

    def run_case(label: str, fault: str) -> None:
        schema = f"catchplate_audit_fault_{uuid.uuid4().hex}"
        dsn = postgres_schema_dsn(base_dsn, schema)
        with psycopg.connect(base_dsn, autocommit=True) as admin:
            admin.execute(f'CREATE SCHEMA "{schema}"')
        try:
            with psycopg.connect(dsn, row_factory=dict_row) as conn:
                with conn.transaction():
                    conn.execute(
                        """
                        CREATE TABLE catchplate_audit_events (
                            sequence BIGSERIAL PRIMARY KEY,
                            id TEXT NOT NULL UNIQUE,
                            event_type TEXT NOT NULL,
                            actor_type TEXT NOT NULL,
                            actor_id TEXT,
                            event_json TEXT NOT NULL,
                            encrypted_canonical_event_json TEXT,
                            storage_format_version BIGINT,
                            prev_event_hash TEXT,
                            event_hash TEXT NOT NULL UNIQUE,
                            created_at TEXT NOT NULL
                        );
                        CREATE TABLE catchplate_store_migrations (
                            migration TEXT PRIMARY KEY,
                            version BIGINT NOT NULL,
                            applied_at TEXT NOT NULL
                        );
                        CREATE FUNCTION catchplate_fault_audit_guard()
                        RETURNS trigger LANGUAGE plpgsql AS $$
                        BEGIN
                            RETURN NEW;
                        END;
                        $$;
                        CREATE TRIGGER catchplate_audit_storage_epoch_guard
                            BEFORE INSERT OR UPDATE ON catchplate_audit_events
                            FOR EACH ROW EXECUTE FUNCTION catchplate_fault_audit_guard();
                        """
                    )
                    created_at = "2026-07-15T00:00:00+00:00"
                    legacy_json = db.dumps(
                        {"operation": f"legacy.postgres.{label}", "case": label}
                    )
                    first_hash = db._audit_hash(
                        event_id=f"{label}:legacy",
                        event_type="rate_limit.denied",
                        actor_type="test",
                        actor_id="test:postgres:fault",
                        event_json=legacy_json,
                        prev_event_hash=None,
                        created_at=created_at,
                    )
                    tail_json = db.dumps({"case": label, "tail": True})
                    tail_hash = db._audit_hash(
                        event_id=f"{label}:tail",
                        event_type="test.tail",
                        actor_type="test",
                        actor_id="test:postgres:fault",
                        event_json=tail_json,
                        prev_event_hash=first_hash,
                        created_at=created_at,
                    )
                    if fault == "invalid_tail":
                        tail_hash = "sha256:" + "0" * 64
                    conn.execute(
                        "INSERT INTO catchplate_audit_events (id, event_type, "
                        "actor_type, actor_id, event_json, prev_event_hash, event_hash, "
                        "created_at) VALUES (%s, 'rate_limit.denied', 'test', "
                        "'test:postgres:fault', %s, NULL, %s, %s)",
                        (f"{label}:legacy", legacy_json, first_hash, created_at),
                    )
                    conn.execute(
                        "INSERT INTO catchplate_audit_events (id, event_type, "
                        "actor_type, actor_id, event_json, prev_event_hash, event_hash, "
                        "created_at) VALUES (%s, 'test.tail', 'test', "
                        "'test:postgres:fault', %s, %s, %s, %s)",
                        (
                            f"{label}:tail",
                            tail_json,
                            first_hash,
                            tail_hash,
                            created_at,
                        ),
                    )

            def snapshot() -> tuple[list[tuple[Any, ...]], int, int]:
                with psycopg.connect(dsn, row_factory=dict_row) as check:
                    rows = [
                        (
                            row["id"],
                            row["event_json"],
                            row["encrypted_canonical_event_json"],
                            row["storage_format_version"],
                            row["prev_event_hash"],
                            row["event_hash"],
                        )
                        for row in check.execute(
                            "SELECT * FROM catchplate_audit_events ORDER BY sequence ASC"
                        ).fetchall()
                    ]
                    markers = int(
                        check.execute(
                            "SELECT COUNT(*)::bigint AS count FROM "
                            "catchplate_audit_events WHERE event_type = "
                            "'audit.storage_redacted'"
                        ).fetchone()["count"]
                    )
                    gates = int(
                        check.execute(
                            "SELECT COUNT(*)::bigint AS count FROM "
                            "catchplate_store_migrations"
                        ).fetchone()["count"]
                    )
                    return rows, markers, gates

            before = snapshot()
            patches = ExitStack()
            with patches:
                if fault == "encryption":
                    patches.enter_context(
                        patch.object(
                            db,
                            "encrypt_bound_secret",
                            side_effect=RuntimeError("forced encryption failure"),
                        )
                    )
                elif fault == "marker":
                    patches.enter_context(
                        patch.object(
                            db,
                            "_audit_storage_redaction_marker",
                            side_effect=RuntimeError("forced marker failure"),
                        )
                    )
                elif fault == "gate":
                    patches.enter_context(
                        patch.object(
                            db,
                            "_record_postgres_audit_migration",
                            side_effect=RuntimeError("forced gate failure"),
                        )
                    )
                try:
                    with psycopg.connect(dsn, row_factory=dict_row) as conn:
                        with conn.transaction():
                            db._remediate_postgres_audit_operations(
                                conn, keyring=keyring
                            )
                except (db.AuditStoreError, RuntimeError):
                    pass
                else:
                    raise AssertionError(f"PostgreSQL {label} fault did not abort")
            after = snapshot()
            # These checks cover logical atomicity; MVCC/WAL and backups may retain
            # historical physical bytes and are outside logical storage redaction.
            if after != before or after[1:] != (0, 0):
                raise AssertionError(
                    f"PostgreSQL {label} fault partially committed: before={before} "
                    f"after={after}"
                )
        finally:
            drop_postgres_schema(base_dsn, schema)

    for label, fault in (
        ("invalid-tail", "invalid_tail"),
        ("encryption-failure", "encryption"),
        ("marker-failure", "marker"),
        ("gate-failure", "gate"),
    ):
        run_case(label, fault)


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


def exercise_bound_secret_key_rotation(crypto: Any) -> None:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    old_key = os.urandom(32)
    new_key = os.urandom(32)
    old_ring = crypto.build_bound_secret_keyring(old_key)
    rotated_ring = crypto.build_bound_secret_keyring(new_key, [old_key])
    retired_ring = crypto.build_bound_secret_keyring(new_key)
    restored_ring = crypto.build_bound_secret_keyring(old_key)
    binding = {
        "event_id": "rotation-fixture",
        "event_hash": "sha256:" + "a" * 64,
        "storage_format_version": 2,
    }
    plaintext = "rotation.restore.canonical-preimage"
    old_envelope = crypto.encrypt_bound_secret(
        plaintext,
        purpose="audit-canonical-event-preimage",
        binding=binding,
        keyring=old_ring,
    )
    if crypto.decrypt_bound_secret(
        old_envelope,
        purpose="audit-canonical-event-preimage",
        binding=binding,
        keyring=rotated_ring,
    ) != plaintext:
        raise AssertionError("rotated historical-key keyring could not verify old data")
    reencrypted = crypto.encrypt_bound_secret(
        plaintext,
        purpose="audit-canonical-event-preimage",
        binding=binding,
        keyring=rotated_ring,
    )
    if crypto.decrypt_bound_secret(
        reencrypted,
        purpose="audit-canonical-event-preimage",
        binding=binding,
        keyring=retired_ring,
    ) != plaintext:
        raise AssertionError("re-encrypted data did not survive historical-key retirement")
    if crypto.decrypt_bound_secret(
        old_envelope,
        purpose="audit-canonical-event-preimage",
        binding=binding,
        keyring=restored_ring,
    ) != plaintext:
        raise AssertionError("restored historical key could not verify the old envelope")
    legacy_nonce = os.urandom(12)
    legacy_ciphertext = AESGCM(old_key).encrypt(
        legacy_nonce, plaintext.encode("utf-8"), None
    )
    legacy_envelope = (
        "v1:"
        + base64.urlsafe_b64encode(legacy_nonce).decode("ascii")
        + ":"
        + base64.urlsafe_b64encode(legacy_ciphertext).decode("ascii")
    )
    if crypto.decrypt_legacy_secret_with_keyring(
        legacy_envelope, keyring=rotated_ring
    ) != plaintext:
        raise AssertionError(
            "legacy v1 canonical preimage ignored the historical keyring"
        )
    try:
        crypto.decrypt_legacy_secret_with_keyring(
            legacy_envelope, keyring=retired_ring
        )
    except ValueError:
        pass
    else:
        raise AssertionError("legacy v1 canonical preimage survived key retirement")
    for callback, label in (
        (
            lambda: crypto.decrypt_bound_secret(
                old_envelope,
                purpose="audit-canonical-event-preimage",
                binding=binding,
                keyring=retired_ring,
            ),
            "unknown retired key",
        ),
        (
            lambda: crypto.decrypt_bound_secret(
                old_envelope,
                purpose="audit-canonical-event-preimage",
                binding={**binding, "event_id": "transplanted"},
                keyring=rotated_ring,
            ),
            "mismatched AAD binding",
        ),
    ):
        try:
            callback()
        except ValueError as exc:
            error = str(exc)
            if old_key.hex() in error or new_key.hex() in error:
                raise AssertionError("bound secret error disclosed key material") from exc
        else:
            raise AssertionError(f"bound secret accepted {label}")

    historical_env = json.dumps(
        {
            "sha256:" + hashlib.sha256(old_key).hexdigest(): base64.urlsafe_b64encode(
                old_key
            ).decode("ascii")
        }
    )
    with patch.object(crypto, "RELEASE_CHANNEL", "production"), patch.object(
        crypto, "load_master_key", return_value=new_key
    ), patch.dict(
        os.environ,
        {"CATCHPLATE_HISTORICAL_MASTER_KEYS": historical_env},
        clear=False,
    ):
        try:
            crypto.load_bound_secret_keyring()
        except ValueError as exc:
            if "forbidden in production" not in str(exc):
                raise AssertionError(
                    f"production raw historical-key rejection was unclear: {exc}"
                ) from exc
        else:
            raise AssertionError("production accepted raw historical keys from env")

    release_digest = "sha256:" + "d" * 64
    receipt = crypto.build_bound_secret_historical_keyring_receipt(
        active_key=new_key,
        historical_keys=[old_key],
        broker_release_receipt_digest=release_digest,
    )
    with tempfile.TemporaryDirectory() as tmp:
        receipt_path = Path(tmp) / "historical-keyring.json"
        receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
        receipt_path.chmod(0o600)

        def load_production_receipt(path: Path) -> Any:
            with patch.object(
                crypto, "RELEASE_CHANNEL", "production"
            ), patch.object(
                crypto, "load_master_key", return_value=new_key
            ), patch.object(
                crypto, "_MASTER_KEY_RELEASE_RECEIPT_DIGEST", release_digest
            ), patch.dict(
                os.environ,
                {
                    "CATCHPLATE_HISTORICAL_MASTER_KEYS": "",
                    "CATCHPLATE_HISTORICAL_MASTER_KEYRING_FILE": str(path),
                },
                clear=False,
            ):
                return crypto.load_bound_secret_keyring()

        def expect_receipt_rejected(
            name: str, document: dict[str, Any] | bytes, expected: str
        ) -> None:
            candidate = Path(tmp) / name
            if isinstance(document, bytes):
                candidate.write_bytes(document)
            else:
                candidate.write_text(json.dumps(document), encoding="utf-8")
            candidate.chmod(0o600)
            try:
                load_production_receipt(candidate)
            except ValueError as exc:
                if expected not in str(exc):
                    raise AssertionError(
                        f"production historical-key receipt rejection was unclear: {exc}"
                    ) from exc
            else:
                raise AssertionError(
                    f"production historical-key receipt accepted {name}"
                )

        released_ring = load_production_receipt(receipt_path)
        if set(released_ring.keys) != set(rotated_ring.keys):
            raise AssertionError(
                "attested production historical-key receipt lost key material"
            )

        expect_receipt_rejected(
            "bad-hmac.json",
            {**receipt, "receipt_hmac": "sha256:" + "0" * 64},
            "authentication failed",
        )
        expect_receipt_rejected(
            "wrong-broker.json",
            {
                **receipt,
                "broker_release_receipt_digest": "sha256:" + "e" * 64,
            },
            "binding is invalid",
        )
        expect_receipt_rejected(
            "wrong-active.json",
            {**receipt, "active_key_id": "sha256:" + "f" * 64},
            "binding is invalid",
        )
        expect_receipt_rejected(
            "future-version.json",
            {**receipt, "version": "catchplate.boundSecretHistoricalKeyring/v2"},
            "binding is invalid",
        )

        wrong_entry = dict(receipt)
        wrong_entry["historical_keys"] = {
            "sha256:" + "1" * 64: base64.urlsafe_b64encode(old_key).decode("ascii")
        }
        payload = {
            key: value for key, value in wrong_entry.items() if key != "receipt_hmac"
        }
        wrong_entry["receipt_hmac"] = "sha256:" + hmac.new(
            new_key,
            crypto.canonical_json_bytes(payload),
            hashlib.sha256,
        ).hexdigest()
        expect_receipt_rejected(
            "wrong-entry-binding.json",
            wrong_entry,
            "entry binding is invalid",
        )

        broad_path = Path(tmp) / "broad-permissions.json"
        broad_path.write_text(json.dumps(receipt), encoding="utf-8")
        broad_path.chmod(0o644)
        try:
            load_production_receipt(broad_path)
        except ValueError as exc:
            if "permissions are too broad" not in str(exc):
                raise AssertionError(
                    f"broad historical-key receipt rejection was unclear: {exc}"
                ) from exc
        else:
            raise AssertionError("production accepted a broadly readable key receipt")

        symlink_path = Path(tmp) / "historical-keyring-link.json"
        symlink_path.symlink_to(receipt_path)
        try:
            load_production_receipt(symlink_path)
        except ValueError as exc:
            if "could not be read" not in str(exc):
                raise AssertionError(
                    f"symlink historical-key receipt rejection was unclear: {exc}"
                ) from exc
        else:
            raise AssertionError("production followed a historical-key receipt symlink")

        expect_receipt_rejected(
            "oversized.json",
            b"x" * (crypto._BOUND_SECRET_HISTORICAL_KEYRING_MAX_BYTES + 1),
            "too large",
        )


def exercise_fresh_startup_key_release_order(db: Any) -> None:
    with patch.object(
        db,
        "load_bound_secret_keyring",
        side_effect=AssertionError(
            "fresh startup requested key release before policy attestation"
        ),
    ):
        db.init_db()


def exercise_modern_audit_verification_without_key(db: Any, backend: str) -> None:
    stored = db.record_audit_event(
        "test.audit.modern",
        {"backend": backend, "storage": "visible-canonical"},
        actor_type="test",
        actor_id=f"test:{backend}:lazy-audit-key",
    )
    with patch.object(
        db,
        "load_bound_secret_keyring",
        side_effect=AssertionError(
            "modern audit verification requested canonical-preimage keys"
        ),
    ):
        verification = db.verify_audit_chain()
    if (
        not verification.get("ok")
        or verification.get("head") != stored["event_hash"]
    ):
        raise AssertionError(
            f"modern audit chain did not verify independently: {verification}"
        )


def exercise_audit_verification_keyring_cache(db: Any, backend: str) -> None:
    keyring = db.load_bound_secret_keyring()
    rows: list[dict[str, Any]] = []
    previous_hash = None
    for index in range(2):
        event_id = f"lazy-key-cache:{backend}:{index}"
        operation = f"legacy.lazy-key-cache.{index}"
        canonical_event_json = db.dumps(
            {"operation": operation, "fixture": "lazy-key-cache"}
        )
        visible_event_json = db.dumps(
            {
                "operation": operation_commitment(operation),
                "fixture": "lazy-key-cache",
            }
        )
        created_at = f"2026-07-15T00:00:0{index}+00:00"
        event_hash = db._audit_hash(
            event_id=event_id,
            event_type="rate_limit.denied",
            actor_type="test",
            actor_id=f"test:{backend}:lazy-key-cache",
            event_json=canonical_event_json,
            prev_event_hash=previous_hash,
            created_at=created_at,
        )
        rows.append(
            {
                "id": event_id,
                "event_type": "rate_limit.denied",
                "actor_type": "test",
                "actor_id": f"test:{backend}:lazy-key-cache",
                "event_json": visible_event_json,
                "encrypted_canonical_event_json": db.encrypt_bound_secret(
                    canonical_event_json,
                    purpose="audit-canonical-event-preimage",
                    binding={
                        "event_id": event_id,
                        "event_hash": event_hash,
                        "storage_format_version": db._AUDIT_STORAGE_FORMAT_VERSION,
                    },
                    keyring=keyring,
                ),
                "storage_format_version": db._AUDIT_STORAGE_FORMAT_VERSION,
                "prev_event_hash": previous_hash,
                "event_hash": event_hash,
                "created_at": created_at,
            }
        )
        previous_hash = event_hash

    class Cursor:
        def __init__(self, values: list[dict[str, Any]] | None = None) -> None:
            self.position = 0
            self.values = values if values is not None else rows

        def fetchmany(self, size: int) -> list[dict[str, Any]]:
            batch = self.values[self.position : self.position + size]
            self.position += len(batch)
            return batch

    with patch.object(
        db, "load_bound_secret_keyring", return_value=keyring
    ) as lazy_loader:
        verification = db._verify_audit_rows(
            Cursor(),
            total=len(rows),
            selected_count=len(rows),
            batch_size=1,
            backend=backend,
            ha=backend == "postgres",
        )
    if not verification.get("ok") or lazy_loader.call_count != 1:
        raise AssertionError(
            "encrypted audit stream did not cache one lazy keyring: "
            f"verification={verification} calls={lazy_loader.call_count}"
        )
    legacy_after_gate = dict(rows[0])
    legacy_after_gate["storage_format_version"] = None
    legacy_after_gate["encrypted_canonical_event_json"] = None
    rejected = db._verify_audit_rows(
        Cursor([legacy_after_gate]),
        total=1,
        selected_count=1,
        batch_size=1,
        backend=backend,
        ha=backend == "postgres",
        require_current_rate_storage=True,
    )
    if rejected.get("error") != "audit_storage_format_unsupported":
        raise AssertionError(
            f"completed audit gate accepted legacy rate storage: {rejected}"
        )


def exercise_pre_policy_rate_limit_storage(
    crypto: Any, db: Any, backend: str
) -> None:
    counter_key = "sha256:" + hashlib.sha256(
        f"pre-policy-rate-limit:{backend}".encode("utf-8")
    ).hexdigest()
    operation = "tweets.write.before-policy-activation"
    kwargs = {
        "counter_key": counter_key,
        "principal_id": "agent:pre-policy",
        "route_id": f"route:pre-policy:{backend}",
        "credential_id": "credential:pre-policy",
        "credential_version": 1,
        "policy_hash": "sha256:" + "1" * 64,
        "constraint_id": "constraint:pre-policy",
        "operation": operation,
        "window_seconds": 60,
        "max_count": 1,
        "audit": False,
    }
    original_required = os.environ.get("CATCHPLATE_KEY_RELEASE_REQUIRED")
    os.environ["CATCHPLATE_KEY_RELEASE_REQUIRED"] = "1"
    try:
        with patch.object(
            crypto,
            "load_master_key",
            side_effect=RuntimeError("rollback epoch is stale"),
        ):
            first = db.consume_rate_limit(**kwargs)
            second = db.consume_rate_limit(**kwargs)
            if not first.get("allowed") or first.get("count") != 1:
                raise AssertionError(
                    f"pre-policy encrypted rate-limit consume failed: {first}"
                )
            if second.get("allowed") or second.get("reason") != "rate_limited":
                raise AssertionError(
                    f"pre-policy encrypted rate-limit replay was not denied: {second}"
                )
            try:
                crypto.load_master_key()
            except RuntimeError as exc:
                if str(exc) != "rollback epoch is stale":
                    raise
            else:
                raise AssertionError("pre-policy storage disabled broker key release")
            with patch.object(crypto, "RELEASE_CHANNEL", "production"):
                try:
                    crypto.load_bound_secret_keyring()
                except RuntimeError as exc:
                    if str(exc) != "rollback epoch is stale":
                        raise
                else:
                    raise AssertionError(
                        "production bound storage bypassed broker key release"
                    )

        with db.connect() as conn:
            row = conn.execute(
                "SELECT operation, encrypted_operation, operation_storage_version "
                "FROM rate_limit_counters WHERE counter_key = ?",
                (counter_key,),
            ).fetchone()
        if row is None:
            raise AssertionError("pre-policy rate-limit row was not persisted")
        if row["operation"] != operation_digest(operation):
            raise AssertionError("pre-policy rate-limit row retained a raw operation")
        if operation in str(row["encrypted_operation"]):
            raise AssertionError("pre-policy ciphertext exposed the operation plaintext")
        db.clear_rate_limit_counters((kwargs["route_id"],))
    finally:
        if original_required is None:
            os.environ.pop("CATCHPLATE_KEY_RELEASE_REQUIRED", None)
        else:
            os.environ["CATCHPLATE_KEY_RELEASE_REQUIRED"] = original_required


def exercise_policy_high_water(db: Any, backend: str) -> None:
    policy_id = f"catchplate-{backend}"

    def digest(value: str) -> str:
        return "sha256:" + value * 64

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


def advance_active_policy_hash(db: Any, policy_hash: str) -> dict[str, Any]:
    current = db.get_policy_high_water()
    if current is None:
        return db.advance_policy_high_water(
            policy_id="catchplate-test",
            sequence=1,
            rollback_epoch=1,
            policy_hash=policy_hash,
        )
    if current["policy_hash"] == policy_hash:
        return current
    return db.advance_policy_high_water(
        policy_id=current["policy_id"],
        sequence=int(current["sequence"]) + 1,
        rollback_epoch=int(current["rollback_epoch"]),
        policy_hash=policy_hash,
    )


def _release_lock_digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _record_release_lock_order(db: Any, call: Any) -> tuple[Any, list[Any]]:
    events: list[tuple[str, tuple[str, ...]]] = []
    lock_resources = db._lock_release_resources
    lock_authority = db._lock_release_authority_resources
    release_attempt_row = db._release_attempt_row

    def record_resources(conn: Any, resources: Any) -> None:
        events.append(("resources", tuple(sorted(set(resources)))))
        lock_resources(conn, resources)

    def record_authority(conn: Any, **kwargs: Any) -> None:
        events.append(("authority", ()))
        lock_authority(conn, **kwargs)

    def record_attempt_row(
        conn: Any,
        attempt_id: str,
        *,
        for_update: bool = False,
    ) -> Any:
        if for_update:
            events.append(("row", (f"attempt:{attempt_id}",)))
        return release_attempt_row(
            conn,
            attempt_id,
            for_update=for_update,
        )

    with (
        patch.object(
            db,
            "_lock_release_resources",
            side_effect=record_resources,
        ),
        patch.object(
            db,
            "_lock_release_authority_resources",
            side_effect=record_authority,
        ),
        patch.object(
            db,
            "_release_attempt_row",
            side_effect=record_attempt_row,
        ),
    ):
        result = call()
    return result, events


def _assert_release_lock_order(
    events: list[Any],
    expected_resources: set[str],
    *,
    label: str,
) -> None:
    phases = [phase for phase, _ in events]
    if phases.count("authority") != 1:
        raise AssertionError(
            f"{label} did not acquire one authority phase: {events}"
        )
    authority_index = phases.index("authority")
    if (
        authority_index < 1
        or any(
            phase != "resources"
            for phase in phases[:authority_index]
        )
        or "resources" in phases[authority_index + 1 :]
        or "row" not in phases[authority_index + 1 :]
    ):
        raise AssertionError(
            f"{label} violated resources-authority-row order: {events}"
        )
    locked_resources = {
        resource
        for phase, resources in events[:authority_index]
        if phase == "resources"
        for resource in resources
    }
    if locked_resources != expected_resources:
        raise AssertionError(
            f"{label} acquired the wrong release resource set: "
            f"{locked_resources} != {expected_resources}"
        )


def exercise_v1_route_protocol_authority(db: Any) -> None:
    policy_hash = _release_lock_digest("release-v1-route-authority")
    legacy_route = SimpleNamespace(
        id="route.release-v1.legacy",
        constraints=(
            {
                "id": "legacy-fixed-window",
                "type": "rateLimit",
                "store": "shared",
                "windowSeconds": 60,
                "max": 2,
            },
        ),
    )
    traversal_route = SimpleNamespace(
        id="route.release-v1.operation-scoped",
        constraints=(
            {
                "id": "operation-scoped-traversal",
                "type": "traversalBudget",
                "operations": ["search.read"],
            },
        ),
    )
    durable_route = SimpleNamespace(
        id="route.release-v1.durable",
        constraints=(
            {
                "id": "durable-sliding-window",
                "type": "slidingWindowLimit",
            },
        ),
    )
    snapshot = SimpleNamespace(
        hash=policy_hash,
        routes=(legacy_route, traversal_route, durable_route),
    )

    def require_v1(route_id: str, operation: str) -> None:
        db._require_v1_route_protocol_authority(
            policy_hash=policy_hash,
            route_id=route_id,
            operation_context={"operation": operation},
            authority_policy_hash=policy_hash,
            authority_route_id=route_id,
        )

    with (
        patch.object(db, "RELEASE_CHANNEL", "production"),
        patch.object(
            db,
            "_load_release_policy_snapshot",
            return_value=snapshot,
        ),
    ):
        require_v1(legacy_route.id, "legacy.read")
        require_v1(traversal_route.id, "profile.read")
        assert_raises(
            db.ReleaseAuthorizationConflictError,
            lambda: require_v1(
                traversal_route.id,
                "search.read",
            ),
            "v1 accepted an operation-scoped traversal route operation",
        )
        assert_raises(
            db.ReleaseAuthorizationConflictError,
            lambda: require_v1(
                durable_route.id,
                "durable.write",
            ),
            "v1 accepted a durable route",
        )
        assert_raises(
            db.ReleaseAuthorizationError,
            lambda: db._require_v1_route_protocol_authority(
                policy_hash=policy_hash,
                route_id=legacy_route.id,
                operation_context={"operation": "legacy.read"},
                authority_policy_hash=None,
                authority_route_id=None,
            ),
            "v1 accepted missing route-derived protocol authority",
        )
        assert_raises(
            db.ReleaseAuthorizationError,
            lambda: db._require_v1_route_protocol_authority(
                policy_hash=policy_hash,
                route_id=legacy_route.id,
                operation_context={"operation": "legacy.read"},
                authority_policy_hash=policy_hash,
                authority_route_id=durable_route.id,
            ),
            "v1 accepted substituted route-derived protocol authority",
        )
        substituted_policy_hash = _release_lock_digest(
            "release-v1-substituted-policy"
        )
        assert_raises(
            db.ReleaseAuthorizationError,
            lambda: db._require_v1_route_protocol_authority(
                policy_hash=substituted_policy_hash,
                route_id=legacy_route.id,
                operation_context={"operation": "legacy.read"},
                authority_policy_hash=substituted_policy_hash,
                authority_route_id=legacy_route.id,
            ),
            "v1 accepted protocol authority outside the signed snapshot",
        )
        durable_attempt_id = _release_lock_digest(
            "release-v1-durable-attempt"
        )
        assert_raises(
            db.ReleaseAuthorizationConflictError,
            lambda: db.reserve_release_authorization(
                attempt_id=durable_attempt_id,
                flow_id=durable_attempt_id,
                principal_id="agent:release-v1",
                route_id=durable_route.id,
                credential_id="",
                credential_version=0,
                policy_hash=policy_hash,
                request_digest=_release_lock_digest(
                    "release-v1-durable-request"
                ),
                operation_digest=_release_lock_digest(
                    "release-v1-durable-operation"
                ),
                operation_context={"operation": "durable.write"},
                shared_quotas=[],
                require_jit_grant=False,
                reservation_ttl_seconds=60,
                authority_policy_hash=policy_hash,
                authority_route_id=durable_route.id,
            ),
            "the public v1 reserve primitive accepted a durable route",
        )

    with (
        patch.object(db, "RELEASE_CHANNEL", "test"),
        patch.object(
            db,
            "_load_release_policy_snapshot",
            side_effect=AssertionError(
                "development v1 loaded a production policy snapshot"
            ),
        ),
    ):
        db._require_v1_route_protocol_authority(
            policy_hash=policy_hash,
            route_id=legacy_route.id,
            operation_context={"operation": "legacy.read"},
            authority_policy_hash=None,
            authority_route_id=None,
        )


def exercise_durable_traversal_cursor_sources(db: Any) -> None:
    policy_hash = _release_lock_digest("durable-traversal-cursor-sources")
    claim = {
        "type": "traversalBudget",
        "constraint_id": "durable-traversal-cursor-source",
        "chain_key": _release_lock_digest(
            "durable-traversal-cursor-source:chain"
        ),
        "lineage_digest": _release_lock_digest(
            "durable-traversal-cursor-source:lineage"
        ),
        "principal_id": "agent:durable-traversal-cursor-source",
        "route_id": "route.durable-traversal-cursor-source",
        "credential_id": "",
        "credential_version": 0,
        "policy_hash": policy_hash,
        "operation": "search.read",
        "store": "shared",
        "phases": ["request", "response"],
        "on_replay": "deny",
        "on_cross_lineage": "deny",
        "on_missing_evidence": "deny",
        "request_cursor_digest": None,
        "request_cursor_source": "query",
        "request_cursor_field": "pageToken",
        "response_cursor_field": "nextPageToken",
        "record_count_field": "messages",
        "byte_source": "validatedDecodedResponseBytes",
        "commit_mode": "atomicAfterResponseValidation",
        "max_pages": 4,
        "max_records": 100,
        "max_bytes": 1_048_576,
        "lifetime_seconds": 300,
    }
    for source in ("query", "header"):
        candidate = {**claim, "request_cursor_source": source}
        normalized = db._normalize_policy_state_claims(
            [candidate],
            policy_hash=policy_hash,
        )
        if normalized != [candidate]:
            raise AssertionError(
                f"durable traversal rejected canonical {source} cursor source"
            )
    assert_raises(
        db.PolicyStateBundleStoreError,
        lambda: db._normalize_policy_state_claims(
            [{**claim, "request_cursor_source": "jsonBody"}],
            policy_hash=policy_hash,
        ),
        "durable traversal accepted jsonBody request cursor source",
    )


def exercise_release_lock_order(db: Any, backend: str) -> None:
    policy_hash = _release_lock_digest(
        f"{backend}:release-lock-order-policy"
    )
    actor_id = "spiffe://test.catchplate/decision-gate/release-lock-order"
    advance_active_policy_hash(db, policy_hash)

    def material(
        suffix: str,
        *,
        durable: bool,
        quota_key: str | None = None,
        identity_suffix: str | None = None,
        quota_maximum: int = 4,
    ) -> dict[str, Any]:
        identity = identity_suffix or suffix
        attempt_id = _release_lock_digest(
            f"{backend}:release-lock:{suffix}:attempt"
        )
        principal_id = f"agent:{backend}:release-lock:{identity}"
        route_id = f"route:{backend}:release-lock:{identity}"
        quota = {
            "counter_key": quota_key
            or _release_lock_digest(
                f"{backend}:release-lock:{suffix}:quota"
            ),
            "constraint_id": f"quota:{backend}:release-lock:{identity}",
            "operation": "test.forward",
            "window_seconds": 60,
            "max_count": quota_maximum,
        }
        reserve = {
            "attempt_id": attempt_id,
            "flow_id": attempt_id,
            "principal_id": principal_id,
            "route_id": route_id,
            "credential_id": "",
            "credential_version": 0,
            "policy_hash": policy_hash,
            "request_digest": _release_lock_digest(
                f"{backend}:release-lock:{suffix}:request"
            ),
            "operation_digest": _release_lock_digest(
                f"{backend}:release-lock:{suffix}:operation"
            ),
            "operation_context": {"operation": "test.forward"},
            "shared_quotas": [quota],
            "require_jit_grant": False,
            "reservation_ttl_seconds": 60,
            "actor_id": actor_id,
            "authority_policy_hash": policy_hash,
            "authority_route_id": route_id,
        }
        claims: list[dict[str, Any]] = []
        claim_digest = None
        if durable:
            claims = [
                {
                    "type": "slidingWindowLimit",
                    "constraint_id": (
                        f"durable:{backend}:release-lock:{suffix}"
                    ),
                    "budget_key": _release_lock_digest(
                        f"{backend}:release-lock:{suffix}:budget"
                    ),
                    "principal_id": principal_id,
                    "route_id": route_id,
                    "credential_id": "",
                    "credential_version": 0,
                    "policy_hash": policy_hash,
                    "operation": "test.forward",
                    "window_semantics": "sliding",
                    "measure": "operationCount",
                    "reservation_mode": "atomicReserveCommitRelease",
                    "on_overflow": "deny",
                    "unit_field": "operations",
                    "units": 1,
                    "window_seconds": 60,
                    "max_units": quota_maximum,
                }
            ]
            claim_digest = db._policy_state_digest(claims)
            reserve["durable_policy_binding"] = {
                "actorId": actor_id,
                "claimDigest": claim_digest,
                "claims": claims,
            }
        return {
            "reserve": reserve,
            "quota": quota,
            "claims": claims,
            "claim_digest": claim_digest,
        }

    v1 = material("v1-order", durable=False)
    v1_reserved, v1_reserve_events = _record_release_lock_order(
        db,
        lambda: db.reserve_release_authorization(**v1["reserve"]),
    )
    v1_resources = {
        f"attempt:{v1['reserve']['attempt_id']}",
        f"quota:{v1['quota']['counter_key']}",
    }
    _assert_release_lock_order(
        v1_reserve_events,
        v1_resources,
        label=f"{backend} v1 reserve",
    )
    v1_dispatched, v1_dispatch_events = _record_release_lock_order(
        db,
        lambda: db.dispatch_release_authorization(
            attempt_id=v1["reserve"]["attempt_id"],
            binding_digest=v1_reserved["binding_digest"],
            dispatch_ttl_seconds=30,
            actor_id=actor_id,
        ),
    )
    if v1_dispatched.get("state") != "dispatching":
        raise AssertionError(
            f"{backend} v1 lock-order dispatch failed: {v1_dispatched}"
        )
    _assert_release_lock_order(
        v1_dispatch_events,
        v1_resources,
        label=f"{backend} v1 dispatch",
    )
    v1_terminal = db.complete_release_authorization(
        attempt_id=v1["reserve"]["attempt_id"],
        binding_digest=v1_reserved["binding_digest"],
        outcome="unknown",
        actor_id=actor_id,
    )
    if v1_terminal.get("state") != "committed_indeterminate":
        raise AssertionError(
            f"{backend} v1 lock-order fixture did not terminate: {v1_terminal}"
        )

    v2 = material("v2-order", durable=True)
    v2_reserved, v2_reserve_events = _record_release_lock_order(
        db,
        lambda: db.reserve_release_authorization_v2(**v2["reserve"]),
    )
    v2_resources = db._policy_state_resources(
        v2_reserved["durable_policy"]["reservation_id"],
        v2["reserve"]["attempt_id"],
        v2["claims"],
    )
    v2_resources.add(f"quota:{v2['quota']['counter_key']}")
    _assert_release_lock_order(
        v2_reserve_events,
        v2_resources,
        label=f"{backend} v2 reserve",
    )
    dispatch_deadline = int(time.time() * 1000) + 30_000
    v2_dispatch_transition = {
        "actorId": actor_id,
        "attemptId": v2["reserve"]["attempt_id"],
        "claimDigest": v2["claim_digest"],
        "reservationId": v2_reserved["durable_policy"][
            "reservation_id"
        ],
        "dispatchDeadlineAtEpochMs": dispatch_deadline,
    }
    v2_dispatched, v2_dispatch_events = _record_release_lock_order(
        db,
        lambda: db.dispatch_release_authorization_v2(
            attempt_id=v2["reserve"]["attempt_id"],
            binding_digest=v2_reserved["binding_digest"],
            actor_id=actor_id,
            durable_policy_transition=v2_dispatch_transition,
        ),
    )
    if v2_dispatched.get("state") != "dispatching":
        raise AssertionError(
            f"{backend} v2 lock-order dispatch failed: {v2_dispatched}"
        )
    _assert_release_lock_order(
        v2_dispatch_events,
        v2_resources,
        label=f"{backend} v2 dispatch",
    )
    v2_unknown_transition = {
        "actorId": actor_id,
        "attemptId": v2["reserve"]["attempt_id"],
        "claimDigest": v2["claim_digest"],
        "reservationId": v2_reserved["durable_policy"][
            "reservation_id"
        ],
        "responseEvidence": [],
        "responseEvidenceDigest": db._policy_state_digest([]),
        "failureReason": (
            db._DURABLE_POLICY_UNKNOWN_FAILURE_REASON
        ),
        "responseBodySha256": db._POLICY_STATE_EMPTY_RESPONSE_DIGEST,
        "uncertainty": db._DURABLE_POLICY_CHARGED_UNCERTAINTY,
    }
    v2_terminal = db.complete_release_authorization_v2(
        attempt_id=v2["reserve"]["attempt_id"],
        binding_digest=v2_reserved["binding_digest"],
        outcome="unknown",
        actor_id=actor_id,
        durable_policy_transition=v2_unknown_transition,
    )
    if (
        v2_terminal.get("state") != "committed_indeterminate"
        or v2_terminal.get("completion_outcome") != "unknown"
        or v2_terminal.get("durable_policy", {}).get("state")
        != "indeterminate"
        or v2_terminal.get("durable_policy", {}).get("failure_reason")
        != db._DURABLE_POLICY_UNKNOWN_FAILURE_REASON
        or v2_terminal.get("durable_policy", {}).get("uncertainty")
        != db._DURABLE_POLICY_CHARGED_UNCERTAINTY
        or not v2_terminal.get("quotas")
        or any(
            quota.get("reservation_state") != "committed"
            for quota in v2_terminal["quotas"]
        )
    ):
        raise AssertionError(
            f"{backend} v2 lock-order fixture did not terminate: {v2_terminal}"
        )
    with db.connect() as conn:
        durable_charge = conn.execute(
            "SELECT state FROM durable_budget_events "
            "WHERE bundle_reservation_id = ?",
            (v2_reserved["durable_policy"]["reservation_id"],),
        ).fetchone()
    if durable_charge is None or durable_charge["state"] != "committed":
        raise AssertionError(
            f"{backend} v2 indeterminate replay was not conservatively "
            f"charged: {durable_charge}"
        )

    def reserve_terminal_fixture(
        suffix: str,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        fixture = material(suffix, durable=True)
        fixture["reserve"]["shared_quotas"] = []
        reserved = db.reserve_release_authorization_v2(**fixture["reserve"])
        if (
            reserved.get("state") != "reserved"
            or reserved.get("durable_policy", {}).get("state") != "reserved"
        ):
            raise AssertionError(
                f"{backend} v2 terminal replay fixture was not reserved: "
                f"{reserved}"
            )
        return fixture, reserved

    def dispatch_terminal_fixture(
        fixture: dict[str, Any],
        reserved: dict[str, Any],
    ) -> int:
        deadline = int(time.time() * 1000) + 30_000
        dispatched = db.dispatch_release_authorization_v2(
            attempt_id=fixture["reserve"]["attempt_id"],
            binding_digest=reserved["binding_digest"],
            actor_id=actor_id,
            durable_policy_transition={
                "actorId": actor_id,
                "attemptId": fixture["reserve"]["attempt_id"],
                "claimDigest": fixture["claim_digest"],
                "reservationId": reserved["durable_policy"][
                    "reservation_id"
                ],
                "dispatchDeadlineAtEpochMs": deadline,
            },
        )
        if (
            dispatched.get("state") != "dispatching"
            or dispatched.get("durable_policy", {}).get("state")
            != "dispatched"
        ):
            raise AssertionError(
                f"{backend} v2 terminal replay fixture was not dispatched: "
                f"{dispatched}"
            )
        return deadline

    def unknown_terminal_transition(
        fixture: dict[str, Any],
        reserved: dict[str, Any],
    ) -> dict[str, Any]:
        return {
            "actorId": actor_id,
            "attemptId": fixture["reserve"]["attempt_id"],
            "claimDigest": fixture["claim_digest"],
            "reservationId": reserved["durable_policy"]["reservation_id"],
            "responseEvidence": [],
            "responseEvidenceDigest": db._policy_state_digest([]),
            "failureReason": db._DURABLE_POLICY_UNKNOWN_FAILURE_REASON,
            "responseBodySha256": db._POLICY_STATE_EMPTY_RESPONSE_DIGEST,
            "uncertainty": db._DURABLE_POLICY_CHARGED_UNCERTAINTY,
        }

    def replace_outer_terminal(
        fixture: dict[str, Any],
        *,
        state: str,
        completion_outcome: str,
    ) -> None:
        with db.connect() as conn:
            db._begin_release_transaction(conn)
            updated = conn.execute(
                "UPDATE release_authorization_attempts "
                "SET state = ?, completion_outcome = ? "
                "WHERE attempt_id = ?",
                (
                    state,
                    completion_outcome,
                    fixture["reserve"]["attempt_id"],
                ),
            )
            if updated.rowcount != 1:
                raise AssertionError(
                    f"{backend} could not construct crossed v2 terminal"
                )

    def assert_stored_durable_state(
        reserved: dict[str, Any],
        expected_state: str,
    ) -> None:
        with db.connect() as conn:
            row = conn.execute(
                "SELECT state FROM policy_state_bundles "
                "WHERE reservation_id = ?",
                (reserved["durable_policy"]["reservation_id"],),
            ).fetchone()
        if row is None or row["state"] != expected_state:
            raise AssertionError(
                f"{backend} crossed replay changed durable state: {row}"
            )

    forwarded, forwarded_reserved = reserve_terminal_fixture(
        "v2-unknown-replay-forwarded"
    )
    forwarded_deadline = dispatch_terminal_fixture(
        forwarded,
        forwarded_reserved,
    )
    forwarded_terminal = db.complete_release_authorization_v2(
        attempt_id=forwarded["reserve"]["attempt_id"],
        binding_digest=forwarded_reserved["binding_digest"],
        outcome="forwarded",
        actor_id=actor_id,
        durable_policy_transition={
            "actorId": actor_id,
            "attemptId": forwarded["reserve"]["attempt_id"],
            "claimDigest": forwarded["claim_digest"],
            "reservationId": forwarded_reserved["durable_policy"][
                "reservation_id"
            ],
            "dispatchDeadlineAtEpochMs": forwarded_deadline,
            "responseEvidence": [],
            "responseEvidenceDigest": db._policy_state_digest([]),
            "responseBodySha256": db._POLICY_STATE_EMPTY_RESPONSE_DIGEST,
        },
    )
    if (
        (
            forwarded_terminal.get("state"),
            forwarded_terminal.get("completion_outcome"),
            forwarded_terminal.get("durable_policy", {}).get("state"),
        )
        != ("committed", "forwarded", "committed")
    ):
        raise AssertionError(
            f"{backend} v2 forwarded fixture did not commit: "
            f"{forwarded_terminal}"
        )
    forwarded_unknown = unknown_terminal_transition(
        forwarded,
        forwarded_reserved,
    )
    forwarded_replay = db.complete_release_authorization_v2(
        attempt_id=forwarded["reserve"]["attempt_id"],
        binding_digest=forwarded_reserved["binding_digest"],
        outcome="unknown",
        actor_id=actor_id,
        durable_policy_transition=forwarded_unknown,
    )
    if (
        forwarded_replay.get("authorized") is not True
        or forwarded_replay.get("idempotent_replay") is not True
        or (
            forwarded_replay.get("state"),
            forwarded_replay.get("completion_outcome"),
            forwarded_replay.get("durable_policy", {}).get("state"),
        )
        != ("committed", "forwarded", "committed")
    ):
        raise AssertionError(
            f"{backend} unknown replay did not observe aligned forwarded "
            f"terminal: {forwarded_replay}"
        )

    cancelled, cancelled_reserved = reserve_terminal_fixture(
        "v2-unknown-replay-cancelled"
    )
    cancelled_terminal = db.complete_release_authorization_v2(
        attempt_id=cancelled["reserve"]["attempt_id"],
        binding_digest=cancelled_reserved["binding_digest"],
        outcome="not_forwarded",
        actor_id=actor_id,
        durable_policy_transition={
            "actorId": actor_id,
            "attemptId": cancelled["reserve"]["attempt_id"],
            "claimDigest": cancelled["claim_digest"],
            "reservationId": cancelled_reserved["durable_policy"][
                "reservation_id"
            ],
        },
    )
    if (
        (
            cancelled_terminal.get("state"),
            cancelled_terminal.get("completion_outcome"),
            cancelled_terminal.get("durable_policy", {}).get("state"),
        )
        != ("cancelled", "not_forwarded", "aborted")
    ):
        raise AssertionError(
            f"{backend} v2 not-forwarded fixture did not abort: "
            f"{cancelled_terminal}"
        )
    cancelled_unknown = unknown_terminal_transition(
        cancelled,
        cancelled_reserved,
    )
    cancelled_replay = db.complete_release_authorization_v2(
        attempt_id=cancelled["reserve"]["attempt_id"],
        binding_digest=cancelled_reserved["binding_digest"],
        outcome="unknown",
        actor_id=actor_id,
        durable_policy_transition=cancelled_unknown,
    )
    if (
        cancelled_replay.get("authorized") is not False
        or cancelled_replay.get("idempotent_replay") is not True
        or (
            cancelled_replay.get("state"),
            cancelled_replay.get("completion_outcome"),
            cancelled_replay.get("durable_policy", {}).get("state"),
        )
        != ("cancelled", "not_forwarded", "aborted")
        or cancelled_replay["durable_policy"][
            "response_evidence_digest"
        ]
        is not None
        or cancelled_replay["durable_policy"]["response_body_sha256"]
        is not None
        or cancelled_replay["durable_policy"]["uncertainty"] is not None
    ):
        raise AssertionError(
            f"{backend} unknown replay did not observe aligned cancelled "
            f"terminal: {cancelled_replay}"
        )

    split_forwarded, split_forwarded_reserved = reserve_terminal_fixture(
        "v2-unknown-replay-split-forwarded"
    )
    dispatch_terminal_fixture(split_forwarded, split_forwarded_reserved)
    split_forwarded_unknown = unknown_terminal_transition(
        split_forwarded,
        split_forwarded_reserved,
    )
    replace_outer_terminal(
        split_forwarded,
        state="committed",
        completion_outcome="forwarded",
    )
    assert_raises(
        db.ReleaseAuthorizationConflictError,
        lambda: db.complete_release_authorization_v2(
            attempt_id=split_forwarded["reserve"]["attempt_id"],
            binding_digest=split_forwarded_reserved["binding_digest"],
            outcome="unknown",
            actor_id=actor_id,
            durable_policy_transition=split_forwarded_unknown,
        ),
        "unknown replay repaired committed outer with dispatched durable state",
    )
    assert_stored_durable_state(split_forwarded_reserved, "dispatched")

    split_cancelled, split_cancelled_reserved = reserve_terminal_fixture(
        "v2-unknown-replay-split-cancelled"
    )
    split_cancelled_unknown = unknown_terminal_transition(
        split_cancelled,
        split_cancelled_reserved,
    )
    replace_outer_terminal(
        split_cancelled,
        state="cancelled",
        completion_outcome="not_forwarded",
    )
    assert_raises(
        db.ReleaseAuthorizationConflictError,
        lambda: db.complete_release_authorization_v2(
            attempt_id=split_cancelled["reserve"]["attempt_id"],
            binding_digest=split_cancelled_reserved["binding_digest"],
            outcome="unknown",
            actor_id=actor_id,
            durable_policy_transition=split_cancelled_unknown,
        ),
        "unknown replay repaired cancelled outer with reserved durable state",
    )
    assert_stored_durable_state(split_cancelled_reserved, "reserved")

    replace_outer_terminal(
        forwarded,
        state="cancelled",
        completion_outcome="not_forwarded",
    )
    assert_raises(
        db.ReleaseAuthorizationError,
        lambda: db.complete_release_authorization_v2(
            attempt_id=forwarded["reserve"]["attempt_id"],
            binding_digest=forwarded_reserved["binding_digest"],
            outcome="unknown",
            actor_id=actor_id,
            durable_policy_transition=forwarded_unknown,
        ),
        "unknown replay accepted cancelled outer with committed durable state",
    )
    replace_outer_terminal(
        cancelled,
        state="committed",
        completion_outcome="forwarded",
    )
    assert_raises(
        db.ReleaseAuthorizationError,
        lambda: db.complete_release_authorization_v2(
            attempt_id=cancelled["reserve"]["attempt_id"],
            binding_digest=cancelled_reserved["binding_digest"],
            outcome="unknown",
            actor_id=actor_id,
            durable_policy_transition=cancelled_unknown,
        ),
        "unknown replay accepted committed outer with aborted durable state",
    )
    for crossed_state, crossed_outcome in (
        ("committed", "forwarded"),
        ("cancelled", "not_forwarded"),
    ):
        replace_outer_terminal(
            v2,
            state=crossed_state,
            completion_outcome=crossed_outcome,
        )
        assert_raises(
            db.ReleaseAuthorizationError,
            lambda: db.complete_release_authorization_v2(
                attempt_id=v2["reserve"]["attempt_id"],
                binding_digest=v2_reserved["binding_digest"],
                outcome="unknown",
                actor_id=actor_id,
                durable_policy_transition=v2_unknown_transition,
            ),
            "unknown replay accepted terminal outer with indeterminate "
            "durable state",
        )

    if backend != "postgres":
        return

    shared_quota_key = _release_lock_digest(
        "postgres:release-lock-order-race:shared-quota"
    )
    race_v1 = material(
        "race-v1",
        durable=False,
        quota_key=shared_quota_key,
        identity_suffix="race",
        quota_maximum=2,
    )
    race_v2 = material(
        "race-v2",
        durable=True,
        quota_key=shared_quota_key,
        identity_suffix="race",
        quota_maximum=2,
    )
    quota_resource = f"quota:{shared_quota_key}"
    v2_resources_held = threading.Event()
    release_v2_resources = threading.Event()
    v1_resource_entered = threading.Event()
    v1_authority_entered = threading.Event()
    v2_authority_entered = threading.Event()
    original_resource_lock = db._lock_release_resources
    original_authority_lock = db._lock_release_authority_resources
    results: dict[str, Any] = {}

    def observed_resource_lock(conn: Any, resources: Any) -> None:
        resource_set = set(resources)
        thread_name = threading.current_thread().name
        if thread_name == "release-lock-order-v1" and quota_resource in resource_set:
            v1_resource_entered.set()
        original_resource_lock(conn, resources)
        if thread_name == "release-lock-order-v2" and quota_resource in resource_set:
            v2_resources_held.set()
            if not release_v2_resources.wait(timeout=5):
                raise AssertionError(
                    "v2 release lock-order race was not released"
                )

    def observed_authority_lock(conn: Any, **kwargs: Any) -> None:
        thread_name = threading.current_thread().name
        if thread_name == "release-lock-order-v1":
            v1_authority_entered.set()
        elif thread_name == "release-lock-order-v2":
            v2_authority_entered.set()
        original_authority_lock(conn, **kwargs)

    def reserve_race(label: str, request: dict[str, Any]) -> None:
        try:
            if "durable_policy_binding" in request:
                results[label] = db.reserve_release_authorization_v2(
                    **request
                )
            else:
                results[label] = db.reserve_release_authorization(
                    **request
                )
        except BaseException as exc:
            results[f"{label}_error"] = exc

    v2_worker = threading.Thread(
        target=reserve_race,
        args=("v2", race_v2["reserve"]),
        name="release-lock-order-v2",
    )
    v1_worker = threading.Thread(
        target=reserve_race,
        args=("v1", race_v1["reserve"]),
        name="release-lock-order-v1",
    )
    with (
        patch.object(
            db,
            "_lock_release_resources",
            side_effect=observed_resource_lock,
        ),
        patch.object(
            db,
            "_lock_release_authority_resources",
            side_effect=observed_authority_lock,
        ),
    ):
        try:
            v2_worker.start()
            if not v2_resources_held.wait(timeout=5):
                raise AssertionError(
                    "v2 did not acquire the shared PostgreSQL quota lock"
                )
            v1_worker.start()
            if not v1_resource_entered.wait(timeout=5):
                raise AssertionError(
                    "v1 did not attempt the shared PostgreSQL quota lock"
                )
            if v1_authority_entered.wait(timeout=0.1):
                raise AssertionError(
                    "v1 acquired policy authority before the shared quota"
                )
        finally:
            release_v2_resources.set()
            v2_worker.join(timeout=10)
            v1_worker.join(timeout=10)
    if v2_worker.is_alive() or v1_worker.is_alive():
        raise AssertionError(
            "PostgreSQL release lock-order race did not terminate"
        )
    if (
        results.get("v1_error") is not None
        or results.get("v2_error") is not None
        or results.get("v1", {}).get("state") != "reserved"
        or results.get("v2", {}).get("state") != "reserved"
        or not v1_authority_entered.is_set()
        or not v2_authority_entered.is_set()
    ):
        raise AssertionError(
            f"PostgreSQL release lock-order race failed closed incorrectly: {results}"
        )

    race_v1_terminal = db.complete_release_authorization(
        attempt_id=race_v1["reserve"]["attempt_id"],
        binding_digest=results["v1"]["binding_digest"],
        outcome="not_forwarded",
        actor_id=actor_id,
    )
    race_v2_terminal = db.complete_release_authorization_v2(
        attempt_id=race_v2["reserve"]["attempt_id"],
        binding_digest=results["v2"]["binding_digest"],
        outcome="not_forwarded",
        actor_id=actor_id,
        durable_policy_transition={
            "actorId": actor_id,
            "attemptId": race_v2["reserve"]["attempt_id"],
            "claimDigest": race_v2["claim_digest"],
            "reservationId": results["v2"]["durable_policy"][
                "reservation_id"
            ],
        },
    )
    if (
        race_v1_terminal.get("state") != "cancelled"
        or race_v2_terminal.get("state") != "cancelled"
    ):
        raise AssertionError(
            "PostgreSQL release lock-order race cleanup failed: "
            f"{race_v1_terminal} {race_v2_terminal}"
        )


def exercise_release_policy_authority_race(db: Any, backend: str) -> None:
    suffix = f"{backend}-release-policy-race"
    binding = approval_kwargs(suffix)
    active_policy_hash = "sha256:" + hashlib.sha256(
        f"{suffix}:active".encode("utf-8")
    ).hexdigest()
    restrictive_policy_hash = "sha256:" + hashlib.sha256(
        f"{suffix}:restrictive".encode("utf-8")
    ).hexdigest()
    binding["policy_hash"] = active_policy_hash
    advance_active_policy_hash(db, active_policy_hash)
    approval = db.ensure_jit_approval_request(**binding)
    approved = db.approve_request(approval["id"], ttl_seconds=60)
    if not approved or approved["status"] != "approved":
        raise AssertionError(
            f"release policy race grant fixture was not approved: {approved}"
        )
    operation = "release.policy-race"
    quota = {
        "counter_key": "sha256:"
        + hashlib.sha256(f"{suffix}:quota".encode("utf-8")).hexdigest(),
        "constraint_id": f"constraint:{suffix}",
        "operation": operation,
        "window_seconds": 60,
        "max_count": 1,
    }
    reserve_kwargs = {
        "attempt_id": f"attempt:{suffix}",
        "flow_id": f"attempt:{suffix}",
        "principal_id": binding["principal_id"],
        "route_id": binding["route_id"],
        "credential_id": binding["credential_id"],
        "credential_version": binding["credential_version"],
        "policy_hash": active_policy_hash,
        "request_digest": binding["request_digest"],
        "operation_digest": binding["operation_digest"],
        "operation_context": {"operation": operation},
        "shared_quotas": [quota],
        "require_jit_grant": True,
        "reservation_ttl_seconds": 30,
        "authority_policy_hash": active_policy_hash,
        "authority_route_id": binding["route_id"],
    }
    transaction_barrier = threading.Barrier(2)
    transaction_ready = threading.Event()
    original_begin = db._begin_release_transaction

    def delayed_begin(conn: Any) -> None:
        if threading.current_thread().name == "release-policy-race":
            transaction_ready.set()
            transaction_barrier.wait(timeout=5)
        original_begin(conn)

    result: dict[str, Any] = {}

    def reserve() -> None:
        try:
            result["value"] = db.reserve_release_authorization(**reserve_kwargs)
        except BaseException as exc:
            result["error"] = exc

    db._begin_release_transaction = delayed_begin
    worker = threading.Thread(target=reserve, name="release-policy-race")
    try:
        worker.start()
        if not transaction_ready.wait(timeout=5):
            raise AssertionError(
                "release reservation did not reach the transaction barrier"
            )
        advance_active_policy_hash(db, restrictive_policy_hash)
        transaction_barrier.wait(timeout=5)
        worker.join(timeout=10)
    finally:
        db._begin_release_transaction = original_begin
    if worker.is_alive():
        raise AssertionError("release policy authority race did not terminate")
    if result.get("error") is not None:
        raise AssertionError(
            f"release policy authority race raised unexpectedly: {result}"
        )
    if result.get("value", {}).get("reason") != "active_policy_changed":
        raise AssertionError(
            f"restrictive policy publication did not deny release: {result}"
        )
    with db.connect() as conn:
        grant = conn.execute(
            "SELECT uses_remaining, reserved_attempt_id FROM approval_grants "
            "WHERE approval_request_id = ?",
            (approval["id"],),
        ).fetchone()
        attempt_count = conn.execute(
            "SELECT COUNT(*) AS count FROM release_authorization_attempts "
            "WHERE attempt_id = ?",
            (reserve_kwargs["attempt_id"],),
        ).fetchone()
        quota_count = conn.execute(
            "SELECT COUNT(*) AS count FROM rate_limit_counters WHERE counter_key = ?",
            (quota["counter_key"],),
        ).fetchone()
    if (
        grant is None
        or int(grant["uses_remaining"]) != 1
        or grant["reserved_attempt_id"] is not None
        or int(attempt_count["count"]) != 0
        or int(quota_count["count"]) != 0
    ):
        raise AssertionError(
            "restrictive policy race consumed grant or quota state: "
            f"grant={dict(grant) if grant else None} "
            f"attempt={dict(attempt_count)} quota={dict(quota_count)}"
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


def assert_jit_authority_rejection_left_no_grant(
    db: Any,
    approval_id: str,
    *,
    label: str,
) -> None:
    approval = db.get_approval_request(approval_id)
    if not approval or approval["status"] != "pending":
        raise AssertionError(f"{label} changed the approval state: {approval}")
    with db.connect() as conn:
        row = conn.execute(
            "SELECT COUNT(*) AS count FROM approval_grants WHERE approval_request_id = ?",
            (approval_id,),
        ).fetchone()
    if int(row["count"]) != 0:
        raise AssertionError(f"{label} created a JIT grant")


def exercise_google_grant_family_quarantine(db: Any, backend: str) -> None:
    scope = "https://www.googleapis.com/auth/gmail.readonly"

    def metadata(label: str) -> dict[str, Any]:
        return {
            "oauth": True,
            "refreshable": True,
            "provider": "google.oauth2",
            "provider_id": "google",
            "provider_subject": f"google-family-{label}-{backend}",
            "provider_account": f"{label}-{backend}@example.test",
            "provider_identity_verified": True,
            "oauth_client_id": f"google-client-{backend}",
            "scopes": [scope],
            "token_type": "Bearer",
            "injection_field": "access_token",
        }

    def secret(label: str) -> str:
        return db.dumps(
            {
                "access_token": f"{label}-access",
                "refresh_token": f"{label}-refresh",
                "token_type": "Bearer",
                "scope": scope,
                "expires_at_epoch_ms": 4_102_444_800_000,
            }
        )

    active_metadata = metadata("active")
    active = db.create_credential(
        f"Google family quarantine {backend}",
        "oauth2",
        secret(f"active-{backend}"),
        active_metadata,
    )
    active_version = int(active["credential_version"])
    barrier = threading.Barrier(2)

    def quarantine() -> tuple[str, Any]:
        barrier.wait(timeout=5)
        return (
            "quarantined",
            db.quarantine_google_oauth_grant_family(
                oauth_client_id=str(active_metadata["oauth_client_id"]),
                provider_subject=str(active_metadata["provider_subject"]),
                actor_id="user:google-family-race",
            ),
        )

    def collide() -> tuple[str, Any]:
        barrier.wait(timeout=5)
        try:
            db.create_credential(
                f"Duplicate Google family {backend}",
                "oauth2",
                secret(f"duplicate-{backend}"),
                active_metadata,
            )
        except db.OAuthGrantCollisionError as exc:
            return "collision", exc.detail
        return "created", None

    with ThreadPoolExecutor(max_workers=2) as executor:
        race_results = [
            executor.submit(quarantine),
            executor.submit(collide),
        ]
        race_results = [future.result(timeout=10) for future in race_results]
    if sorted(result[0] for result in race_results) != ["collision", "quarantined"]:
        raise AssertionError(
            f"Google quarantine and collision were not serialized: {race_results}"
        )
    quarantine_result = next(
        result[1] for result in race_results if result[0] == "quarantined"
    )
    if quarantine_result.get("credentialCount") != 1:
        raise AssertionError(f"Google active family was not quarantined: {quarantine_result}")
    if db.get_credential(active["id"]) is not None:
        raise AssertionError("quarantined Google credential remained active")
    inactive = db.get_credential(
        active["id"], include_secret=True, include_inactive=True
    )
    if not (
        inactive is not None
        and inactive.get("lifecycle_status") == "revocation_pending"
        and int(inactive.get("credential_version") or 0) == active_version + 1
        and json.loads(inactive["secret"])["refresh_token"]
        == f"active-{backend}-refresh"
    ):
        raise AssertionError(f"Google quarantine did not rotate the generation: {inactive}")

    pending_metadata = metadata("pending")
    pending_name = f"Google pending quarantine {backend}"
    pending_secret = secret(f"pending-{backend}")
    pending_review = {
        "credential_type": "oauth2",
        "provider": "google",
        "provider_subject": pending_metadata["provider_subject"],
        "provider_account": pending_metadata["provider_account"],
        "scopes": [scope],
        "credential_name": pending_name,
        "metadata_keys": sorted(pending_metadata),
        "expires_at_epoch_ms": None,
    }
    pending_digest = (
        "sha256:"
        + hashlib.sha256(
            db.dumps(
                {
                    "action": "credential.oauth.activate",
                    "review": pending_review,
                    "encrypted_token_source_sha256": "sha256:"
                    + hashlib.sha256(pending_secret.encode("utf-8")).hexdigest(),
                }
            ).encode("utf-8")
        ).hexdigest()
    )
    pending = db.create_pending_oauth_credential(
        name=pending_name,
        kind="oauth2",
        secret=pending_secret,
        metadata=pending_metadata,
        requester_id="user:google-family-race",
        payload_digest=pending_digest,
        review=pending_review,
        ttl_seconds=300,
    )
    pending_quarantine = db.quarantine_google_oauth_grant_family(
        oauth_client_id=str(pending_metadata["oauth_client_id"]),
        provider_subject=str(pending_metadata["provider_subject"]),
        actor_id="user:google-family-race",
    )
    retained_pending = db.get_pending_oauth_credential(pending["id"])
    if not (
        pending_quarantine.get("pendingCredentialIds") == [pending["id"]]
        and retained_pending is not None
        and retained_pending.get("status") == "rejected"
        and retained_pending.get("revocation_status") == "pending"
    ):
        raise AssertionError(
            f"Google pending family was not terminally quarantined: {pending_quarantine} {retained_pending}"
        )
    rejected_activation = db.activate_pending_oauth_credential(
        pending["id"],
        approval_id="unused-after-terminal-quarantine",
        actor_id="user:google-family-race",
    )
    if rejected_activation != {
        "ok": False,
        "reason": "pending_credential_rejected",
    }:
        raise AssertionError(
            f"terminal Google pending grant remained activatable: {rejected_activation}"
        )


def exercise_approval_authority_revalidation(db: Any, backend: str) -> None:
    webauthn_actor_id = f"user:jit-webauthn-{backend}"
    webauthn_credential = db.create_webauthn_credential(
        credential_id=f"jit-webauthn-credential-{backend}",
        user_id=webauthn_actor_id,
        label="JIT authority race fixture",
        public_key_cose="test-public-key",
        sign_count=0,
        aaguid=None,
        authenticator_class="test",
    )
    revoked_approval = db.ensure_jit_approval_request(
        **approval_kwargs(f"{backend}-revoked-webauthn")
    )
    revoked = db.revoke_webauthn_credential(
        webauthn_credential["id"],
        actor_id="user:authority-test",
        reason="revoke immediately before JIT commit",
    )
    if revoked.get("ok") is not True:
        raise AssertionError(f"WebAuthn authority fixture was not revoked: {revoked}")
    assert_raises(
        db.MetadataStoreError,
        lambda: db.approve_request(
            revoked_approval["id"],
            actor_id=webauthn_actor_id,
            authn={
                "method": "webauthn",
                "user_id": webauthn_actor_id,
                "credential_record_id": webauthn_credential["id"],
            },
            required_approver_roles={"approver"},
        ),
        "revoked WebAuthn credential approved a JIT request",
    )
    assert_jit_authority_rejection_left_no_grant(
        db,
        revoked_approval["id"],
        label="revoked WebAuthn authority",
    )

    oidc_approver_id = f"oidc:jit-approver-{backend}@example.com"
    authority = db.get_rbac_authority_state()
    provisioned_approver = db.mutate_rbac_role_binding(
        subject_id=oidc_approver_id,
        roles=["approver"],
        status="active",
        expected_generation=authority["generation"],
        actor_id="user:authority-test",
        reason="JIT approver authority fixture",
        event_type="rbac.role_changed",
        event={"test": "jit_approver_commit_time_authorization"},
    )
    role_approval = db.ensure_jit_approval_request(
        **approval_kwargs(f"{backend}-revoked-approver-role")
    )
    db.mutate_rbac_role_binding(
        subject_id=oidc_approver_id,
        roles=[],
        status="deprovisioned",
        expected_generation=provisioned_approver["generation"],
        actor_id="user:authority-test",
        reason="deprovision immediately before JIT commit",
        event_type="rbac.deprovisioned",
        event={"test": "jit_approver_commit_time_authorization"},
    )
    assert_raises(
        db.MetadataStoreError,
        lambda: db.approve_request(
            role_approval["id"],
            actor_id=oidc_approver_id,
            authn={"method": "oidc", "user_id": oidc_approver_id},
            required_approver_roles={"approver"},
        ),
        "deprovisioned OIDC approver approved a JIT request",
    )
    assert_jit_authority_rejection_left_no_grant(
        db,
        role_approval["id"],
        label="deprovisioned JIT approver authority",
    )

    control_approver_id = f"oidc:control-approver-{backend}@example.com"
    authority = db.get_rbac_authority_state()
    provisioned_control_approver = db.mutate_rbac_role_binding(
        subject_id=control_approver_id,
        roles=["credential_owner"],
        status="active",
        expected_generation=authority["generation"],
        actor_id="user:authority-test",
        reason="control-plane approver authority fixture",
        event_type="rbac.role_changed",
        event={"test": "control_approver_commit_time_authorization"},
    )
    stale_control_approval = db.ensure_control_plane_approval(
        action="credential.create",
        resource_id=f"stale-approver-{backend}",
        payload_digest="sha256:" + "c" * 64,
        requester_id="user:control-requester",
        request={"summary": "stale approver race fixture"},
        ttl_seconds=300,
    )
    db.mutate_rbac_role_binding(
        subject_id=control_approver_id,
        roles=[],
        status="deprovisioned",
        expected_generation=provisioned_control_approver["generation"],
        actor_id="user:authority-test",
        reason="deprovision immediately before approval commit",
        event_type="rbac.deprovisioned",
        event={"test": "control_approver_commit_time_authorization"},
    )
    if (
        db.approve_control_plane_approval(
            stale_control_approval["id"],
            actor_id=control_approver_id,
            required_approver_roles={"credential_owner"},
        )
        is not None
    ):
        raise AssertionError("deprovisioned OIDC approver committed an approval")
    if (
        db.get_control_plane_approval(stale_control_approval["id"])["status"]
        != "pending"
    ):
        raise AssertionError("stale approver rejection changed control-plane state")

    oidc_requester_id = f"oidc:control-requester-{backend}@example.com"
    authority = db.get_rbac_authority_state()
    provisioned_requester = db.mutate_rbac_role_binding(
        subject_id=oidc_requester_id,
        roles=["credential_owner"],
        status="active",
        expected_generation=authority["generation"],
        actor_id="user:authority-test",
        reason="control-plane requester authority fixture",
        event_type="rbac.role_changed",
        event={"test": "control_requester_commit_time_authorization"},
    )
    payload_digest = "sha256:" + "e" * 64
    control_approval = db.ensure_control_plane_approval(
        action="credential.create",
        resource_id=f"requester-authority-{backend}",
        payload_digest=payload_digest,
        requester_id=oidc_requester_id,
        request={"summary": "requester authority race fixture"},
        ttl_seconds=300,
    )
    if (
        db.approve_control_plane_approval(
            control_approval["id"],
            actor_id=f"user:control-approver-{backend}",
        )
        is None
    ):
        raise AssertionError(
            "control-plane requester authority fixture was not approved"
        )
    db.mutate_rbac_role_binding(
        subject_id=oidc_requester_id,
        roles=[],
        status="deprovisioned",
        expected_generation=provisioned_requester["generation"],
        actor_id="user:authority-test",
        reason="deprovision immediately before protected mutation commit",
        event_type="rbac.deprovisioned",
        event={"test": "control_requester_commit_time_authorization"},
    )
    consumed = db.consume_control_plane_approval(
        control_approval["id"],
        action="credential.create",
        resource_id=f"requester-authority-{backend}",
        payload_digest=payload_digest,
        actor_id=oidc_requester_id,
        required_requester_roles={"credential_owner"},
        required_approver_roles={"credential_owner"},
    )
    if consumed != {
        "ok": False,
        "reason": "approval_requester_role_revoked",
    }:
        raise AssertionError(
            f"deprovisioned control-plane requester was not rejected: {consumed}"
        )
    if db.get_control_plane_approval(control_approval["id"])["status"] != "approved":
        raise AssertionError("requester authority rejection consumed the approval")

    oauth_requester_id = f"oidc:oauth-requester-{backend}@example.com"
    authority = db.get_rbac_authority_state()
    provisioned_oauth_requester = db.mutate_rbac_role_binding(
        subject_id=oauth_requester_id,
        roles=["credential_owner"],
        status="active",
        expected_generation=authority["generation"],
        actor_id="user:authority-test",
        reason="OAuth requester authority fixture",
        event_type="rbac.role_changed",
        event={"test": "oauth_requester_commit_time_authorization"},
    )
    oauth_scope = "https://www.googleapis.com/auth/gmail.readonly"
    oauth_metadata = {
        "oauth": True,
        "refreshable": True,
        "provider": "google.oauth2",
        "provider_id": "google",
        "provider_subject": f"oauth-requester-subject-{backend}",
        "provider_account": f"oauth-requester-{backend}@example.test",
        "provider_identity_verified": True,
        "oauth_client_id": f"oauth-requester-client-{backend}",
        "scopes": [oauth_scope],
        "token_type": "Bearer",
        "injection_field": "access_token",
    }
    oauth_secret = db.dumps(
        {
            "access_token": f"oauth-access-{backend}",
            "refresh_token": f"oauth-refresh-{backend}",
            "token_type": "Bearer",
            "scope": oauth_scope,
            "expires_at_epoch_ms": 4_102_444_800_000,
        }
    )
    oauth_review = {
        "credential_type": "oauth2",
        "provider": "google",
        "provider_subject": oauth_metadata["provider_subject"],
        "provider_account": oauth_metadata["provider_account"],
        "scopes": [oauth_scope],
        "credential_name": f"OAuth requester authority {backend}",
        "metadata_keys": sorted(oauth_metadata),
        "expires_at_epoch_ms": None,
    }
    oauth_payload_digest = (
        "sha256:"
        + hashlib.sha256(
            db.dumps(
                {
                    "action": "credential.oauth.activate",
                    "review": oauth_review,
                    "encrypted_token_source_sha256": "sha256:"
                    + hashlib.sha256(oauth_secret.encode("utf-8")).hexdigest(),
                }
            ).encode("utf-8")
        ).hexdigest()
    )
    pending_oauth = db.create_pending_oauth_credential(
        name=f"OAuth requester authority {backend}",
        kind="oauth2",
        secret=oauth_secret,
        metadata=oauth_metadata,
        requester_id=oauth_requester_id,
        payload_digest=oauth_payload_digest,
        review=oauth_review,
        ttl_seconds=300,
    )
    oauth_approval = db.ensure_control_plane_approval(
        action="credential.oauth.activate",
        resource_id=pending_oauth["id"],
        payload_digest=oauth_payload_digest,
        requester_id=oauth_requester_id,
        request=oauth_review,
        ttl_seconds=300,
    )
    if (
        db.approve_control_plane_approval(
            oauth_approval["id"],
            actor_id=f"user:oauth-approver-{backend}",
            required_approver_roles={"credential_owner"},
        )
        is None
    ):
        raise AssertionError("OAuth requester authority fixture was not approved")
    db.mutate_rbac_role_binding(
        subject_id=oauth_requester_id,
        roles=[],
        status="deprovisioned",
        expected_generation=provisioned_oauth_requester["generation"],
        actor_id="user:authority-test",
        reason="deprovision immediately before OAuth activation commit",
        event_type="rbac.deprovisioned",
        event={"test": "oauth_requester_commit_time_authorization"},
    )
    oauth_activation = db.activate_pending_oauth_credential(
        pending_oauth["id"],
        approval_id=oauth_approval["id"],
        actor_id=oauth_requester_id,
        required_requester_roles={"credential_owner"},
        required_approver_roles={"credential_owner"},
    )
    if oauth_activation != {
        "ok": False,
        "reason": "approval_requester_role_revoked",
    }:
        raise AssertionError(
            f"deprovisioned OAuth requester was not rejected: {oauth_activation}"
        )
    if db.get_pending_oauth_credential(pending_oauth["id"]) is None:
        raise AssertionError(
            "OAuth requester authority rejection removed pending state"
        )
    if db.get_control_plane_approval(oauth_approval["id"])["status"] != "approved":
        raise AssertionError("OAuth requester authority rejection consumed approval")


def exercise_denial_authority_races(db: Any, backend: str) -> None:
    jit_actor_id = f"oidc:jit-denier-{backend}@example.com"
    authority = db.get_rbac_authority_state()
    provisioned_jit_actor = db.mutate_rbac_role_binding(
        subject_id=jit_actor_id,
        roles=["approver"],
        status="active",
        expected_generation=authority["generation"],
        actor_id="user:authority-test",
        reason="JIT denial race fixture",
        event_type="rbac.role_changed",
        event={"test": "jit_denial_authority_race"},
    )
    active_policy_hash = "sha256:" + hashlib.sha256(
        f"{backend}:jit-denial-active".encode("utf-8")
    ).hexdigest()
    restrictive_policy_hash = "sha256:" + hashlib.sha256(
        f"{backend}:jit-denial-restrictive".encode("utf-8")
    ).hexdigest()
    advance_active_policy_hash(db, active_policy_hash)
    route_race_kwargs = approval_kwargs(f"{backend}-jit-route-denial-race")
    route_race_kwargs["policy_hash"] = active_policy_hash
    route_race_approval = db.ensure_jit_approval_request(**route_race_kwargs)
    route_barrier = threading.Barrier(2)
    route_ready = threading.Event()
    original_policy_lock = db._lock_policy_high_water

    def delayed_policy_lock(conn: Any) -> None:
        if threading.current_thread().name == "jit-route-denial-race":
            route_ready.set()
            route_barrier.wait(timeout=5)
        original_policy_lock(conn)

    route_result: dict[str, Any] = {}

    def deny_with_stale_route_authority() -> None:
        try:
            route_result["value"] = db.deny_request(
                route_race_approval["id"],
                actor_id=jit_actor_id,
                required_approver_roles={"approver"},
                authority_policy_hash=active_policy_hash,
                authority_route_id=route_race_kwargs["route_id"],
                allowed_approver_ids={jit_actor_id},
            )
        except BaseException as exc:
            route_result["error"] = exc

    db._lock_policy_high_water = delayed_policy_lock
    route_worker = threading.Thread(
        target=deny_with_stale_route_authority,
        name="jit-route-denial-race",
    )
    try:
        route_worker.start()
        if not route_ready.wait(timeout=5):
            raise AssertionError("JIT route denial did not reach its authority barrier")
        advance_active_policy_hash(db, restrictive_policy_hash)
        route_barrier.wait(timeout=5)
        route_worker.join(timeout=10)
    finally:
        db._lock_policy_high_water = original_policy_lock
    if route_worker.is_alive() or route_result.get("error") is not None:
        raise AssertionError(
            f"JIT route denial race did not terminate cleanly: {route_result}"
        )
    if route_result.get("value") is not None or db.get_approval_request(
        route_race_approval["id"]
    )["status"] != "pending":
        raise AssertionError(
            "stale route approver authority terminalized a JIT denial"
        )

    rbac_race_kwargs = approval_kwargs(f"{backend}-jit-rbac-denial-race")
    rbac_race_kwargs["policy_hash"] = restrictive_policy_hash
    rbac_race_approval = db.ensure_jit_approval_request(**rbac_race_kwargs)
    rbac_barrier = threading.Barrier(2)
    rbac_ready = threading.Event()

    def delayed_rbac_policy_lock(conn: Any) -> None:
        if threading.current_thread().name == "jit-rbac-denial-race":
            rbac_ready.set()
            rbac_barrier.wait(timeout=5)
        original_policy_lock(conn)

    rbac_result: dict[str, Any] = {}

    def deny_with_stale_rbac_authority() -> None:
        try:
            rbac_result["value"] = db.deny_request(
                rbac_race_approval["id"],
                actor_id=jit_actor_id,
                required_approver_roles={"approver"},
                authority_policy_hash=restrictive_policy_hash,
                authority_route_id=rbac_race_kwargs["route_id"],
                allowed_approver_ids={jit_actor_id},
            )
        except BaseException as exc:
            rbac_result["error"] = exc

    db._lock_policy_high_water = delayed_rbac_policy_lock
    rbac_worker = threading.Thread(
        target=deny_with_stale_rbac_authority,
        name="jit-rbac-denial-race",
    )
    try:
        rbac_worker.start()
        if not rbac_ready.wait(timeout=5):
            raise AssertionError("JIT RBAC denial did not reach its authority barrier")
        deprovisioned_jit_actor = db.mutate_rbac_role_binding(
            subject_id=jit_actor_id,
            roles=[],
            status="deprovisioned",
            expected_generation=provisioned_jit_actor["generation"],
            actor_id="user:authority-test",
            reason="deprovision during JIT denial",
            event_type="rbac.deprovisioned",
            event={"test": "jit_denial_authority_race"},
        )
        rbac_barrier.wait(timeout=5)
        rbac_worker.join(timeout=10)
    finally:
        db._lock_policy_high_water = original_policy_lock
    if rbac_worker.is_alive() or rbac_result.get("error") is not None:
        raise AssertionError(
            f"JIT RBAC denial race did not terminate cleanly: {rbac_result}"
        )
    if rbac_result.get("value") is not None or db.get_approval_request(
        rbac_race_approval["id"]
    )["status"] != "pending":
        raise AssertionError("revoked OIDC authority terminalized a JIT denial")

    control_actor_id = f"oidc:control-denier-{backend}@example.com"
    provisioned_control_actor = db.mutate_rbac_role_binding(
        subject_id=control_actor_id,
        roles=["credential_owner"],
        status="active",
        expected_generation=deprovisioned_jit_actor["generation"],
        actor_id="user:authority-test",
        reason="control-plane denial race fixture",
        event_type="rbac.role_changed",
        event={"test": "control_denial_authority_race"},
    )
    scope = "https://www.googleapis.com/auth/gmail.readonly"
    pending_metadata = {
        "oauth": True,
        "refreshable": True,
        "provider": "google.oauth2",
        "provider_id": "google",
        "provider_subject": f"control-denial-{backend}",
        "provider_account": f"control-denial-{backend}@example.test",
        "provider_identity_verified": True,
        "oauth_client_id": f"control-denial-client-{backend}",
        "scopes": [scope],
        "token_type": "Bearer",
        "injection_field": "access_token",
    }
    pending_secret = db.dumps(
        {
            "access_token": f"control-denial-access-{backend}",
            "refresh_token": f"control-denial-refresh-{backend}",
            "token_type": "Bearer",
            "scope": scope,
            "expires_at_epoch_ms": 4_102_444_800_000,
        }
    )
    pending_review = {
        "credential_type": "oauth2",
        "provider": "google",
        "provider_subject": pending_metadata["provider_subject"],
        "provider_account": pending_metadata["provider_account"],
        "scopes": [scope],
        "credential_name": f"Control denial race {backend}",
        "metadata_keys": sorted(pending_metadata),
        "expires_at_epoch_ms": None,
    }
    pending_digest = "sha256:" + hashlib.sha256(
        db.dumps(
            {
                "action": "credential.oauth.activate",
                "review": pending_review,
                "encrypted_token_source_sha256": "sha256:"
                + hashlib.sha256(pending_secret.encode("utf-8")).hexdigest(),
            }
        ).encode("utf-8")
    ).hexdigest()
    pending_oauth = db.create_pending_oauth_credential(
        name=f"Control denial race {backend}",
        kind="oauth2",
        secret=pending_secret,
        metadata=pending_metadata,
        requester_id=f"user:control-denial-requester-{backend}",
        payload_digest=pending_digest,
        review=pending_review,
        ttl_seconds=300,
    )
    control_approval = db.ensure_control_plane_approval(
        action="credential.oauth.activate",
        resource_id=pending_oauth["id"],
        payload_digest=pending_digest,
        requester_id=f"user:control-denial-requester-{backend}",
        request=pending_review,
        ttl_seconds=300,
    )
    control_barrier = threading.Barrier(2)
    control_ready = threading.Event()
    original_webauthn_lock = db._lock_webauthn_authority

    def delayed_webauthn_lock(conn: Any) -> None:
        if threading.current_thread().name == "control-denial-race":
            control_ready.set()
            control_barrier.wait(timeout=5)
        original_webauthn_lock(conn)

    control_result: dict[str, Any] = {}

    def deny_with_stale_control_authority() -> None:
        try:
            control_result["value"] = db.deny_control_plane_approval(
                control_approval["id"],
                actor_id=control_actor_id,
                required_approver_roles={"credential_owner"},
            )
        except BaseException as exc:
            control_result["error"] = exc

    db._lock_webauthn_authority = delayed_webauthn_lock
    control_worker = threading.Thread(
        target=deny_with_stale_control_authority,
        name="control-denial-race",
    )
    try:
        control_worker.start()
        if not control_ready.wait(timeout=5):
            raise AssertionError(
                "control-plane denial did not reach its authority barrier"
            )
        db.mutate_rbac_role_binding(
            subject_id=control_actor_id,
            roles=[],
            status="deprovisioned",
            expected_generation=provisioned_control_actor["generation"],
            actor_id="user:authority-test",
            reason="deprovision during control-plane denial",
            event_type="rbac.deprovisioned",
            event={"test": "control_denial_authority_race"},
        )
        control_barrier.wait(timeout=5)
        control_worker.join(timeout=10)
    finally:
        db._lock_webauthn_authority = original_webauthn_lock
    retained_pending = db.get_pending_oauth_credential(pending_oauth["id"])
    if control_worker.is_alive() or control_result.get("error") is not None:
        raise AssertionError(
            f"control-plane denial race did not terminate cleanly: {control_result}"
        )
    if (
        control_result.get("value") is not None
        or db.get_control_plane_approval(control_approval["id"])["status"]
        != "pending"
        or retained_pending is None
        or retained_pending.get("status") != "pending"
        or retained_pending.get("revocation_status") is not None
    ):
        raise AssertionError(
            "revoked control-plane authority scheduled provider revocation: "
            f"denial={control_result} pending={retained_pending}"
        )


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


def approved_release_binding(
    db: Any,
    suffix: str,
    *,
    credential: dict[str, Any] | None = None,
) -> dict[str, Any]:
    kwargs = approval_kwargs(suffix)
    if credential is None:
        credential = db.create_credential(
            name=f"{suffix} release credential",
            kind="bearer",
            secret=f"secret:{suffix}",
            metadata={"test_fixture": suffix},
        )
    kwargs["credential_id"] = credential["id"]
    kwargs["credential_version"] = int(credential["credential_version"])
    advance_active_policy_hash(db, kwargs["policy_hash"])
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
        "authority_policy_hash": kwargs["policy_hash"],
        "authority_route_id": kwargs["route_id"],
    }


def quota_claim(suffix: str, *, maximum: int = 1) -> dict[str, Any]:
    return {
        "counter_key": "sha256:" + hashlib.sha256(suffix.encode("utf-8")).hexdigest(),
        "constraint_id": f"quota:{suffix}",
        "operation": "test.forward",
        "window_seconds": 60,
        "max_count": maximum,
    }


def calendar_quota_claim(
    suffix: str, *, calendar_window: str, maximum: int = 1
) -> dict[str, Any]:
    claim = quota_claim(suffix, maximum=maximum)
    claim.pop("window_seconds")
    claim["window_kind"] = calendar_window
    return claim


def exercise_calendar_rate_limits(db: Any, backend: str) -> None:
    def epoch_ms(value: str) -> int:
        return int(
            datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
            * 1000
        )

    boundary_cases = (
        (
            "leap-day",
            "utcDay",
            "2024-02-29T00:00:00Z",
            "2024-03-01T00:00:00Z",
        ),
        (
            "dst-day",
            "utcDay",
            "2025-03-09T00:00:00Z",
            "2025-03-10T00:00:00Z",
        ),
        (
            "iso-year",
            "utcIsoWeek",
            "2024-12-30T00:00:00Z",
            "2025-01-06T00:00:00Z",
        ),
        (
            "leap-month",
            "utcMonth",
            "2024-02-01T00:00:00Z",
            "2024-03-01T00:00:00Z",
        ),
        (
            "month-year",
            "utcMonth",
            "2024-12-01T00:00:00Z",
            "2025-01-01T00:00:00Z",
        ),
    )
    for label, window_kind, start_text, end_text in boundary_cases:
        start_ms = epoch_ms(start_text)
        end_ms = epoch_ms(end_text)
        counter_key = "sha256:" + hashlib.sha256(
            f"{backend}:calendar:{label}".encode("utf-8")
        ).hexdigest()
        request = {
            "counter_key": counter_key,
            "principal_id": f"agent:{backend}:calendar",
            "route_id": f"route:{backend}:calendar:{label}",
            "credential_id": "",
            "credential_version": 0,
            "policy_hash": "sha256:" + "c" * 64,
            "constraint_id": f"quota:{backend}:calendar:{label}",
            "operation": None,
            "calendar_window": window_kind,
            "max_count": 1,
            "now_epoch_ms": start_ms + 1_234,
            "audit": False,
        }
        preview = db.consume_rate_limit(**{**request, "consume": False})
        if (
            not preview.get("allowed")
            or preview.get("consumed")
            or preview.get("window_kind") != window_kind
            or preview.get("window_start_epoch_ms") != start_ms
            or preview.get("window_end_epoch_ms") != end_ms
        ):
            raise AssertionError(
                f"{backend} {label} calendar preview was invalid: {preview}"
            )
        with db.connect() as conn:
            preview_row = conn.execute(
                "SELECT count(*) AS count FROM rate_limit_counters "
                "WHERE counter_key = ?",
                (counter_key,),
            ).fetchone()
        if int(preview_row["count"]) != 0:
            raise AssertionError(f"{backend} {label} preview mutated the counter")

        consumed = db.consume_rate_limit(**request)
        denied = db.consume_rate_limit(
            **{**request, "now_epoch_ms": end_ms - 1}
        )
        reset = db.consume_rate_limit(**{**request, "now_epoch_ms": end_ms})
        if (
            not consumed.get("allowed")
            or consumed.get("count") != 1
            or denied.get("allowed")
            or denied.get("retry_after_seconds") != 1
            or not reset.get("allowed")
            or reset.get("count") != 1
            or reset.get("window_start_epoch_ms") != end_ms
        ):
            raise AssertionError(
                f"{backend} {label} half-open calendar behavior failed: "
                f"{consumed} {denied} {reset}"
            )

    rollback_key = "sha256:" + hashlib.sha256(
        f"{backend}:calendar:rollback".encode("utf-8")
    ).hexdigest()
    rollback_request = {
        "counter_key": rollback_key,
        "principal_id": f"agent:{backend}:calendar",
        "route_id": f"route:{backend}:calendar:rollback",
        "credential_id": "",
        "credential_version": 0,
        "policy_hash": "sha256:" + "c" * 64,
        "constraint_id": f"quota:{backend}:calendar:rollback",
        "operation": None,
        "calendar_window": "utcDay",
        "max_count": 2,
        "now_epoch_ms": epoch_ms("2025-03-09T12:00:00Z"),
        "audit": False,
    }
    db.consume_rate_limit(**rollback_request)
    try:
        db.consume_rate_limit(
            **{
                **rollback_request,
                "now_epoch_ms": epoch_ms("2025-03-08T23:59:59.999Z"),
            }
        )
    except db.RateLimitStoreError:
        pass
    else:
        raise AssertionError(f"{backend} calendar clock rollback was accepted")
    with db.connect() as conn:
        rollback_row = conn.execute(
            "SELECT count, window_kind FROM rate_limit_counters "
            "WHERE counter_key = ?",
            (rollback_key,),
        ).fetchone()
    if int(rollback_row["count"]) != 1 or rollback_row["window_kind"] != "utcDay":
        raise AssertionError(f"{backend} clock rollback mutated the counter")

    transition_key = "sha256:" + hashlib.sha256(
        f"{backend}:calendar:transition".encode("utf-8")
    ).hexdigest()
    fixed_start = epoch_ms("2025-01-15T12:00:00Z")
    fixed = {
        **rollback_request,
        "counter_key": transition_key,
        "constraint_id": f"quota:{backend}:calendar:transition",
        "calendar_window": None,
        "window_seconds": 60,
        "now_epoch_ms": fixed_start,
    }
    db.consume_rate_limit(**fixed)
    calendar = {**fixed, "window_seconds": None, "calendar_window": "utcMonth"}
    try:
        db.consume_rate_limit(**calendar)
    except db.RateLimitStoreError:
        pass
    else:
        raise AssertionError(f"{backend} live quota kind transition was accepted")
    transitioned = db.consume_rate_limit(
        **{**calendar, "now_epoch_ms": fixed_start + 60_000}
    )
    if not transitioned.get("allowed") or transitioned.get("window_kind") != "utcMonth":
        raise AssertionError(
            f"{backend} expired quota did not transition window kind: {transitioned}"
        )

    duration_key = "sha256:" + hashlib.sha256(
        f"{backend}:fixed:duration-change".encode("utf-8")
    ).hexdigest()
    duration_request = {
        **rollback_request,
        "counter_key": duration_key,
        "constraint_id": f"quota:{backend}:fixed:duration-change",
        "calendar_window": None,
        "window_seconds": 60,
        "max_count": 1,
        "now_epoch_ms": fixed_start,
    }
    first_duration = db.consume_rate_limit(**duration_request)
    extended_duration = db.consume_rate_limit(
        **{
            **duration_request,
            "window_seconds": 120,
            "now_epoch_ms": fixed_start + 61_000,
        }
    )
    if (
        not first_duration.get("allowed")
        or extended_duration.get("allowed")
        or extended_duration.get("count") != 1
        or extended_duration.get("window_start_epoch_ms") != fixed_start
        or extended_duration.get("window_end_epoch_ms") != fixed_start + 120_000
    ):
        raise AssertionError(
            f"{backend} live fixed duration change reset usage: "
            f"{first_duration} {extended_duration}"
        )


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
        "flow_id": attempt_id,
        **binding,
        "operation_context": {"operation": "test.forward", "account": "acct:test"},
        "shared_quotas": quotas,
        "require_jit_grant": require_jit_grant,
        "reservation_ttl_seconds": 5,
        "now_epoch_ms": now_epoch_ms,
        "actor_id": "spiffe://test.catchplate/decision-gate/atomic",
    }


def counter_count(db: Any, counter_key: str) -> int | None:
    with db.connect() as conn:
        row = conn.execute(
            "SELECT count FROM rate_limit_counters WHERE counter_key = ?",
            (counter_key,),
        ).fetchone()
    return int(row["count"]) if row is not None else None


def operation_digest(operation: str) -> str:
    return "sha256:" + hashlib.sha256(operation.encode("utf-8")).hexdigest()


def _jit_authority_policy_hash(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode("utf-8")).hexdigest()


def _provision_release_authority_fixture(
    db: Any,
    backend: str,
    label: str,
    *,
    reserve: bool,
) -> dict[str, Any]:
    suffix = f"{backend}-authority-{label}"
    actor_id = f"oidc:{suffix}@example.test"
    policy_hash = _jit_authority_policy_hash(f"{suffix}:policy")
    advance_active_policy_hash(db, policy_hash)
    authority = db.get_rbac_authority_state()
    role_binding = db.mutate_rbac_role_binding(
        subject_id=actor_id,
        roles=["approver"],
        status="active",
        expected_generation=authority["generation"],
        actor_id="user:jit-authority-test",
        reason=f"{label} authority fixture",
        event_type="rbac.role_changed",
        event={"test": "jit_release_authority"},
    )
    webauthn = db.create_webauthn_credential(
        credential_id=f"passkey-{suffix}",
        user_id=actor_id,
        label=f"{label} authority fixture",
        public_key_cose="test-public-key",
        sign_count=0,
        aaguid=None,
        authenticator_class="test",
    )
    credential = db.create_credential(
        f"{label} release authority fixture",
        "bearer",
        f"secret-{suffix}",
        {},
    )
    request = approval_kwargs(suffix)
    request["policy_hash"] = policy_hash
    request["credential_id"] = credential["id"]
    request["credential_version"] = int(credential["credential_version"])
    approval = db.ensure_jit_approval_request(**request)
    approved = db.approve_request(
        approval["id"],
        ttl_seconds=120,
        actor_id=actor_id,
        authn={
            "method": "webauthn",
            "user_id": actor_id,
            "credential_record_id": webauthn["id"],
        },
        required_approver_roles={"approver"},
        authority_policy_hash=policy_hash,
        authority_route_id=request["route_id"],
        allowed_approver_ids={actor_id},
    )
    if not approved or approved.get("status") != "approved":
        raise AssertionError(f"{label} authority fixture was not approved: {approved}")
    binding = {
        "principal_id": request["principal_id"],
        "route_id": request["route_id"],
        "credential_id": request["credential_id"],
        "credential_version": request["credential_version"],
        "policy_hash": request["policy_hash"],
        "request_digest": request["request_digest"],
        "operation_digest": request["operation_digest"],
    }
    quota = quota_claim(f"{suffix}-quota", maximum=2)
    reserve_kwargs = {
        **release_reserve_kwargs(
            binding,
            attempt_id=_jit_authority_policy_hash(
                f"credential-issuance-attempt:{suffix}"
            ),
            quotas=[quota],
        ),
        "reservation_ttl_seconds": 60,
        "authority_policy_hash": policy_hash,
        "authority_route_id": request["route_id"],
        "required_approver_roles": {"approver"},
        "allowed_approver_ids": {actor_id},
        "require_approver_webauthn": True,
    }
    reservation = None
    if reserve:
        reservation = db.reserve_release_authorization(**reserve_kwargs)
        if reservation.get("state") != "reserved":
            raise AssertionError(
                f"{label} authority fixture was not reserved: {reservation}"
            )
    return {
        "actor_id": actor_id,
        "approval_id": approval["id"],
        "binding": binding,
        "grant_id": f"approval:{approval['id']}",
        "policy_hash": policy_hash,
        "quota": quota,
        "reserve_kwargs": reserve_kwargs,
        "reservation": reservation,
        "role_generation": role_binding["generation"],
        "webauthn_id": webauthn["id"],
    }


def _assert_reserve_authority_rejected(
    db: Any,
    fixture: dict[str, Any],
    result: dict[str, Any],
    *,
    label: str,
) -> None:
    if result.get("authorized") is not False or result.get("state") != "denied":
        raise AssertionError(f"{label} reserve did not fail closed: {result}")
    with db.connect() as conn:
        attempt = conn.execute(
            "SELECT COUNT(*) AS count FROM release_authorization_attempts "
            "WHERE attempt_id = ?",
            (fixture["reserve_kwargs"]["attempt_id"],),
        ).fetchone()
        grant = conn.execute(
            "SELECT state, uses_remaining, reserved_attempt_id "
            "FROM approval_grants WHERE id = ?",
            (fixture["grant_id"],),
        ).fetchone()
        quota = conn.execute(
            "SELECT COUNT(*) AS count FROM release_authorization_quota_reservations "
            "WHERE attempt_id = ?",
            (fixture["reserve_kwargs"]["attempt_id"],),
        ).fetchone()
    if (
        int(attempt["count"]) != 0
        or grant is None
        or grant["state"] not in {"active", "revoked"}
        or int(grant["uses_remaining"]) not in {0, 1}
        or (grant["state"] == "active" and int(grant["uses_remaining"]) != 1)
        or grant["reserved_attempt_id"] is not None
        or int(quota["count"]) != 0
        or counter_count(db, fixture["quota"]["counter_key"]) is not None
    ):
        raise AssertionError(
            f"{label} reserve rejection mutated attempt, grant, or quota state"
        )


def _assert_dispatch_authority_cancelled(
    db: Any,
    fixture: dict[str, Any],
    result: dict[str, Any],
    *,
    label: str,
) -> None:
    attempt_id = fixture["reserve_kwargs"]["attempt_id"]
    if result.get("authorized") is not False or result.get("state") != "cancelled":
        raise AssertionError(f"{label} dispatch did not cancel fail-closed: {result}")
    with db.connect() as conn:
        attempt = conn.execute(
            "SELECT state, completion_outcome FROM release_authorization_attempts "
            "WHERE attempt_id = ?",
            (attempt_id,),
        ).fetchone()
        grant = conn.execute(
            "SELECT state, uses_remaining, reserved_attempt_id "
            "FROM approval_grants WHERE id = ?",
            (fixture["grant_id"],),
        ).fetchone()
        quota = conn.execute(
            "SELECT reservation_state FROM release_authorization_quota_reservations "
            "WHERE attempt_id = ? AND counter_key = ?",
            (attempt_id, fixture["quota"]["counter_key"]),
        ).fetchone()
        dispatch_events = conn.execute(
            "SELECT COUNT(*) AS count FROM release_authorization_events "
            "WHERE attempt_id = ? AND event_type = 'release_authorization.dispatching'",
            (attempt_id,),
        ).fetchone()
        consumptions = conn.execute(
            "SELECT COUNT(*) AS count FROM approval_grant_consumptions "
            "WHERE attempt_id = ?",
            (attempt_id,),
        ).fetchone()
    if (
        attempt is None
        or attempt["state"] != "cancelled"
        or attempt["completion_outcome"] != "not_forwarded"
        or grant is None
        or grant["state"] not in {"active", "revoked"}
        or int(grant["uses_remaining"]) not in {0, 1}
        or (grant["state"] == "active" and int(grant["uses_remaining"]) != 1)
        or grant["reserved_attempt_id"] is not None
        or quota is None
        or quota["reservation_state"] != "refunded"
        or counter_count(db, fixture["quota"]["counter_key"]) != 0
        or int(dispatch_events["count"]) != 0
        or int(consumptions["count"]) != 0
    ):
        raise AssertionError(
            f"{label} cancellation forwarded, consumed, or retained authority: "
            f"attempt={dict(attempt) if attempt else None} "
            f"grant={dict(grant) if grant else None} "
            f"quota={dict(quota) if quota else None}"
        )


def exercise_jit_approval_route_authority(db: Any, backend: str) -> None:
    suffix = f"{backend}-approval-route-authority"
    actor_id = f"oidc:{suffix}@example.test"
    authority = db.get_rbac_authority_state()
    db.mutate_rbac_role_binding(
        subject_id=actor_id,
        roles=["approver"],
        status="active",
        expected_generation=authority["generation"],
        actor_id="user:jit-authority-test",
        reason="transactional approval route authority fixture",
        event_type="rbac.role_changed",
        event={"test": "jit_approval_route_authority"},
    )
    policy_hash = _jit_authority_policy_hash(f"{suffix}:active")
    advance_active_policy_hash(db, policy_hash)
    request = approval_kwargs(f"{suffix}-policy-race")
    request["policy_hash"] = policy_hash
    approval = db.ensure_jit_approval_request(**request)
    lock_ready = threading.Event()
    continue_lock = threading.Event()
    original_lock = db._lock_policy_high_water
    result: dict[str, Any] = {}

    def delayed_policy_lock(conn: Any) -> None:
        if threading.current_thread().name == "jit-approval-policy-race":
            lock_ready.set()
            if not continue_lock.wait(timeout=5):
                raise AssertionError("approval policy race barrier timed out")
        original_lock(conn)

    def approve() -> None:
        try:
            result["value"] = db.approve_request(
                approval["id"],
                actor_id=actor_id,
                authn={"method": "oidc", "user_id": actor_id},
                required_approver_roles={"approver"},
                authority_policy_hash=policy_hash,
                authority_route_id=request["route_id"],
                allowed_approver_ids={actor_id},
            )
        except BaseException as exc:
            result["error"] = exc

    db._lock_policy_high_water = delayed_policy_lock
    worker = threading.Thread(target=approve, name="jit-approval-policy-race")
    try:
        worker.start()
        if not lock_ready.wait(timeout=5):
            raise AssertionError(
                "JIT approval did not enter transactional policy serialization"
            )
        advance_active_policy_hash(
            db, _jit_authority_policy_hash(f"{suffix}:restrictive")
        )
        continue_lock.set()
        worker.join(timeout=10)
    finally:
        continue_lock.set()
        db._lock_policy_high_water = original_lock
    if worker.is_alive():
        raise AssertionError("JIT approval policy race did not terminate")
    if result.get("value") is not None or (
        result.get("error") is not None
        and not isinstance(result["error"], db.MetadataStoreError)
    ):
        raise AssertionError(
            f"stale-policy JIT approval did not fail closed: {result}"
        )
    assert_jit_authority_rejection_left_no_grant(
        db, approval["id"], label="stale-policy JIT approval"
    )

    current_policy = str(db.get_policy_high_water()["policy_hash"])
    for label, route_id, allowed_ids in (
        ("removed-route", f"route:{suffix}:removed", {actor_id}),
        ("removed-approver", None, {f"oidc:other-{suffix}@example.test"}),
    ):
        candidate = approval_kwargs(f"{suffix}-{label}")
        candidate["policy_hash"] = current_policy
        pending = db.ensure_jit_approval_request(**candidate)
        try:
            approved = db.approve_request(
                pending["id"],
                actor_id=actor_id,
                authn={"method": "oidc", "user_id": actor_id},
                required_approver_roles={"approver"},
                authority_policy_hash=current_policy,
                authority_route_id=route_id or candidate["route_id"],
                allowed_approver_ids=allowed_ids,
            )
        except db.MetadataStoreError:
            approved = None
        if approved is not None:
            raise AssertionError(f"{label} JIT authority committed approval: {approved}")
        assert_jit_authority_rejection_left_no_grant(
            db, pending["id"], label=f"{label} JIT authority"
        )

    positive = approval_kwargs(f"{suffix}-positive")
    positive["policy_hash"] = current_policy
    pending = db.ensure_jit_approval_request(**positive)
    approved = db.approve_request(
        pending["id"],
        actor_id=actor_id,
        authn={"method": "oidc", "user_id": actor_id},
        required_approver_roles={"approver"},
        authority_policy_hash=current_policy,
        authority_route_id=positive["route_id"],
        allowed_approver_ids={actor_id},
    )
    if not approved or approved.get("status") != "approved":
        raise AssertionError(f"current JIT route authority was rejected: {approved}")


def exercise_release_authority_lifecycle(db: Any, backend: str) -> None:
    for authority_kind in ("policy", "grant", "webauthn", "rbac"):
        fixture = _provision_release_authority_fixture(
            db,
            backend,
            f"reserve-{authority_kind}",
            reserve=False,
        )
        if authority_kind == "policy":
            advance_active_policy_hash(
                db,
                _jit_authority_policy_hash(
                    f"{backend}:reserve-policy:restrictive"
                ),
            )
        elif authority_kind == "grant":
            with db.connect() as conn:
                conn.execute(
                    "UPDATE approval_grants SET state = 'revoked' WHERE id = ?",
                    (fixture["grant_id"],),
                )
        elif authority_kind == "webauthn":
            with db.connect() as conn:
                conn.execute(
                    "UPDATE webauthn_credentials SET revoked_at = ? WHERE id = ?",
                    (db.iso_now(), fixture["webauthn_id"]),
                )
        else:
            db.mutate_rbac_role_binding(
                subject_id=fixture["actor_id"],
                roles=[],
                status="deprovisioned",
                expected_generation=fixture["role_generation"],
                actor_id="user:jit-authority-test",
                reason="revoke immediately before release reserve",
                event_type="rbac.deprovisioned",
                event={"test": "jit_release_reserve_authority"},
            )
        rejected = db.reserve_release_authorization(**fixture["reserve_kwargs"])
        _assert_reserve_authority_rejected(
            db,
            fixture,
            rejected,
            label=f"{backend} {authority_kind} authority",
        )

    for authority_kind in ("policy", "grant", "webauthn", "rbac"):
        fixture = _provision_release_authority_fixture(
            db,
            backend,
            f"dispatch-{authority_kind}",
            reserve=True,
        )
        if authority_kind == "policy":
            advance_active_policy_hash(
                db,
                _jit_authority_policy_hash(
                    f"{backend}:dispatch-policy:restrictive"
                ),
            )
        elif authority_kind == "grant":
            with db.connect() as conn:
                conn.execute(
                    "UPDATE approval_grants SET state = 'revoked' WHERE id = ?",
                    (fixture["grant_id"],),
                )
        elif authority_kind == "webauthn":
            revoked = db.revoke_webauthn_credential(
                fixture["webauthn_id"],
                actor_id="user:jit-authority-test",
                reason="revoke between release reserve and dispatch",
            )
            if revoked.get("ok") is not True:
                raise AssertionError(
                    f"dispatch WebAuthn fixture did not revoke: {revoked}"
                )
        else:
            db.mutate_rbac_role_binding(
                subject_id=fixture["actor_id"],
                roles=[],
                status="deprovisioned",
                expected_generation=fixture["role_generation"],
                actor_id="user:jit-authority-test",
                reason="revoke between release reserve and dispatch",
                event_type="rbac.deprovisioned",
                event={"test": "jit_release_dispatch_authority"},
            )
        dispatched = db.dispatch_release_authorization(
            attempt_id=fixture["reserve_kwargs"]["attempt_id"],
            binding_digest=fixture["reservation"]["binding_digest"],
            dispatch_ttl_seconds=5,
            actor_id="spiffe://test.catchplate/decision-gate/authority",
            required_approver_roles={"approver"},
        )
        _assert_dispatch_authority_cancelled(
            db,
            fixture,
            dispatched,
            label=f"{backend} {authority_kind} authority",
        )


def operation_commitment(operation: str) -> dict[str, Any]:
    return {
        "type": "catchplate.operation_commitment",
        "version": 1,
        "algorithm": "sha256",
        "digest": operation_digest(operation),
    }


def inject_legacy_rate_limit_audit_head(
    db: Any, backend: str, operation: str
) -> tuple[str, str, str, int]:
    payload = {
        "counter_key": "sha256:" + "d" * 64,
        "operation": operation,
        "reason": "legacy-fixture",
    }
    stored = db.record_audit_event(
        "rate_limit.denied",
        payload,
        actor_type="test",
        actor_id=f"test:{backend}:legacy-audit",
    )
    if payload["operation"] != operation:
        raise AssertionError("audit storage normalization mutated the in-memory event")
    if stored.get("event", {}).get("operation") != operation_commitment(operation):
        raise AssertionError(f"new audit write retained raw operation: {stored}")

    event_json = db.dumps(payload)
    if backend == "postgres":
        with db._audit_pg_connect() as conn:
            with conn.transaction():
                row = conn.execute(
                    "SELECT * FROM catchplate_audit_events WHERE id = %s",
                    (stored["id"],),
                ).fetchone()
                old_head = db._audit_hash(
                    event_id=row["id"],
                    event_type=row["event_type"],
                    actor_type=row["actor_type"],
                    actor_id=row["actor_id"],
                    event_json=event_json,
                    prev_event_hash=row["prev_event_hash"],
                    created_at=row["created_at"],
                )
                conn.execute(
                    "UPDATE catchplate_audit_events SET event_json = %s, "
                    "storage_format_version = NULL, event_hash = %s WHERE id = %s",
                    (event_json, old_head, stored["id"]),
                )
    else:
        with db.connect() as conn:
            row = conn.execute(
                "SELECT * FROM audit_events WHERE id = ?", (stored["id"],)
            ).fetchone()
            old_head = db._audit_hash(
                event_id=row["id"],
                event_type=row["event_type"],
                actor_type=row["actor_type"],
                actor_id=row["actor_id"],
                event_json=event_json,
                prev_event_hash=row["prev_event_hash"],
                created_at=row["created_at"],
            )
            conn.execute(
                "UPDATE audit_events SET event_json = ?, storage_format_version = NULL, "
                "event_hash = ? WHERE id = ?",
                (event_json, old_head, stored["id"]),
            )
    verification = db.verify_audit_chain()
    if not verification.get("ok") or verification.get("head") != old_head:
        raise AssertionError(
            f"legacy audit fixture was not a valid old chain head: {verification}"
        )
    return stored["id"], old_head, event_json, int(verification["count"])


def exercise_sqlite_audit_redaction_abort(db: Any) -> None:
    def fixture_connection() -> sqlite3.Connection:
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        conn.executescript(
            """
            CREATE TABLE audit_events (
                id TEXT PRIMARY KEY,
                event_type TEXT NOT NULL,
                actor_type TEXT NOT NULL,
                actor_id TEXT,
                event_json TEXT NOT NULL,
                encrypted_canonical_event_json TEXT,
                storage_format_version INTEGER,
                prev_event_hash TEXT,
                event_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE catchplate_store_migrations (
                migration TEXT PRIMARY KEY,
                version BIGINT NOT NULL,
                applied_at TEXT NOT NULL
            );
            """
        )
        return conn

    def insert_event(
        conn: sqlite3.Connection,
        *,
        event_id: str,
        event_type: str,
        event_json: str,
        prev_event_hash: str | None,
        event_hash: str | None = None,
    ) -> str:
        created_at = "2026-07-15T00:00:00+00:00"
        calculated = db._audit_hash(
            event_id=event_id,
            event_type=event_type,
            actor_type="test",
            actor_id="test:sqlite:redaction-abort",
            event_json=event_json,
            prev_event_hash=prev_event_hash,
            created_at=created_at,
        )
        conn.execute(
            "INSERT INTO audit_events (id, event_type, actor_type, actor_id, "
            "event_json, prev_event_hash, event_hash, created_at) "
            "VALUES (?, ?, 'test', 'test:sqlite:redaction-abort', ?, ?, ?, ?)",
            (
                event_id,
                event_type,
                event_json,
                prev_event_hash,
                event_hash or calculated,
                created_at,
            ),
        )
        return calculated

    def snapshot(conn: sqlite3.Connection) -> list[tuple[Any, ...]]:
        return [
            tuple(row)
            for row in conn.execute(
                "SELECT id, event_json, encrypted_canonical_event_json, "
                "prev_event_hash, event_hash FROM audit_events ORDER BY rowid ASC"
            ).fetchall()
        ]

    invalid = fixture_connection()
    try:
        first_json = db.dumps(
            {"operation": "legacy.sqlite.valid-before-invalid", "reason": "fixture"}
        )
        first_hash = insert_event(
            invalid,
            event_id="valid-candidate",
            event_type="rate_limit.denied",
            event_json=first_json,
            prev_event_hash=None,
        )
        insert_event(
            invalid,
            event_id="invalid-tail",
            event_type="test.invalid",
            event_json=db.dumps({"invalid": True}),
            prev_event_hash=first_hash,
            event_hash="sha256:" + "0" * 64,
        )
        invalid.commit()
        before = snapshot(invalid)
        try:
            db._remediate_sqlite_audit_operations(
                invalid, keyring=db.load_bound_secret_keyring()
            )
        except db.AuditStoreError:
            invalid.rollback()
        else:
            raise AssertionError("invalid legacy audit chain was migrated")
        if snapshot(invalid) != before:
            raise AssertionError("invalid legacy audit chain was partially mutated")
    finally:
        invalid.close()

    oversized = fixture_connection()
    try:
        oversized_json = db.dumps(
            {
                "operation": "x" * (db._AUDIT_EVENT_JSON_STORED_MAX_BYTES + 1),
                "reason": "oversized-fixture",
            }
        )
        insert_event(
            oversized,
            event_id="oversized-candidate",
            event_type="rate_limit.denied",
            event_json=oversized_json,
            prev_event_hash=None,
        )
        oversized.commit()
        before = snapshot(oversized)
        try:
            db._remediate_sqlite_audit_operations(
                oversized, keyring=db.load_bound_secret_keyring()
            )
        except db.AuditStoreError as exc:
            oversized.rollback()
            if str(exc) != "event_size_exceeded":
                raise AssertionError(
                    f"oversized audit chain failed for the wrong reason: {exc}"
                ) from exc
        else:
            raise AssertionError("oversized legacy audit chain was migrated")
        if snapshot(oversized) != before:
            raise AssertionError("oversized legacy audit chain was partially mutated")
    finally:
        oversized.close()

    destructive = fixture_connection()
    try:
        insert_event(
            destructive,
            event_id="destructive-rewrite-evidence",
            event_type="audit.chain.superseded",
            event_json=db.dumps({"reason": "legacy-destructive-rewrite"}),
            prev_event_hash=None,
        )
        destructive.commit()
        before = snapshot(destructive)
        try:
            db._remediate_sqlite_audit_operations(
                destructive, keyring=db.load_bound_secret_keyring()
            )
        except db.AuditStoreError as exc:
            destructive.rollback()
            if "restore from a pre-rewrite backup" not in str(exc):
                raise AssertionError(
                    f"destructive rewrite evidence failed unclearly: {exc}"
                ) from exc
        else:
            raise AssertionError("destructive rewrite evidence was accepted")
        if snapshot(destructive) != before:
            raise AssertionError("destructive rewrite rejection mutated the chain")
    finally:
        destructive.close()


def exercise_legacy_writer_storage_guards(
    db: Any,
    backend: str,
    *,
    existing_attempt_id: str,
    existing_audit_id: str,
    existing_outbox_id: str,
    existing_counter_key: str,
    existing_quota_counter_key: str,
) -> None:
    now = db.iso_now()

    def legacy_outbox_insert() -> None:
        with db.connect() as conn:
            conn.execute(
                "INSERT INTO metadata_audit_outbox (id, event_type, actor_type, "
                "actor_id, event_json, status, created_at) VALUES (?, "
                "'rate_limit.denied', 'legacy', 'legacy', ?, 'pending', ?)",
                (
                    f"legacy-writer:{backend}:outbox",
                    db.dumps({"operation": "legacy.plaintext"}),
                    now,
                ),
            )

    def legacy_counter_insert() -> None:
        with db.connect() as conn:
            conn.execute(
                "INSERT INTO rate_limit_counters (counter_key, operation, "
                "window_start_epoch_ms, window_seconds, max_count, count, created_at, "
                "updated_at) VALUES (?, ?, 0, 60, 1, 0, ?, ?)",
                (
                    "sha256:" + hashlib.sha256(
                        f"{backend}:legacy-writer-counter".encode("utf-8")
                    ).hexdigest(),
                    "legacy.plaintext",
                    now,
                    now,
                ),
            )

    def legacy_quota_insert() -> None:
        with db.connect() as conn:
            conn.execute(
                "INSERT INTO release_authorization_quota_reservations "
                "(attempt_id, counter_key, constraint_id, operation, "
                "window_start_epoch_ms, window_seconds, max_count, count_after, "
                "reservation_state, created_at, updated_at) VALUES (?, ?, 'legacy', "
                "'legacy.plaintext', 0, 60, 1, 1, 'reserved', ?, ?)",
                (
                    existing_attempt_id,
                    "sha256:" + hashlib.sha256(
                        f"{backend}:legacy-writer-quota".encode("utf-8")
                    ).hexdigest(),
                    now,
                    now,
                ),
            )

    def legacy_audit_insert() -> None:
        event_id = f"legacy-writer:{backend}:audit"
        event_json = db.dumps({"operation": "legacy.plaintext"})
        if backend == "postgres":
            with db._audit_pg_connect() as conn:
                with conn.transaction():
                    conn.execute(
                        "INSERT INTO catchplate_audit_events (id, event_type, "
                        "actor_type, actor_id, event_json, prev_event_hash, event_hash, "
                        "created_at) VALUES (%s, 'rate_limit.denied', 'legacy', "
                        "'legacy', %s, NULL, %s, %s)",
                        (event_id, event_json, "sha256:" + "f" * 64, now),
                    )
        else:
            with db.connect() as conn:
                conn.execute(
                    "INSERT INTO audit_events (id, event_type, actor_type, actor_id, "
                    "event_json, prev_event_hash, event_hash, created_at) VALUES (?, "
                    "'rate_limit.denied', 'legacy', 'legacy', ?, NULL, ?, ?)",
                    (event_id, event_json, "sha256:" + "f" * 64, now),
                )

    def legacy_outbox_update() -> None:
        with db.connect() as conn:
            conn.execute(
                "UPDATE metadata_audit_outbox SET event_json = ? WHERE id = ?",
                (
                    db.dumps({"operation": "legacy.update.plaintext"}),
                    existing_outbox_id,
                ),
            )

    def legacy_counter_update() -> None:
        with db.connect() as conn:
            conn.execute(
                "UPDATE rate_limit_counters SET operation = ? WHERE counter_key = ?",
                (
                    operation_digest("legacy.update.digest-shaped-literal"),
                    existing_counter_key,
                ),
            )

    def legacy_quota_update() -> None:
        with db.connect() as conn:
            conn.execute(
                "UPDATE release_authorization_quota_reservations SET operation = ? "
                "WHERE attempt_id = ? AND counter_key = ?",
                (
                    operation_digest("legacy.update.quota-digest-shaped-literal"),
                    existing_attempt_id,
                    existing_quota_counter_key,
                ),
            )

    def legacy_audit_update() -> None:
        event_json = db.dumps({"operation": "legacy.update.plaintext"})
        if backend == "postgres":
            with db._audit_pg_connect() as conn:
                with conn.transaction():
                    conn.execute(
                        "UPDATE catchplate_audit_events SET event_json = %s "
                        "WHERE id = %s",
                        (event_json, existing_audit_id),
                    )
        else:
            with db.connect() as conn:
                conn.execute(
                    "UPDATE audit_events SET event_json = ? WHERE id = ?",
                    (event_json, existing_audit_id),
                )

    for callback, label in (
        (legacy_audit_insert, "audit"),
        (legacy_outbox_insert, "metadata outbox"),
        (legacy_counter_insert, "rate counter"),
        (legacy_quota_insert, "quota reservation"),
        (legacy_audit_update, "audit update"),
        (legacy_outbox_update, "metadata outbox update"),
        (legacy_counter_update, "rate counter update"),
        (legacy_quota_update, "quota reservation update"),
    ):
        assert_raises(
            Exception,
            callback,
            f"simulated rolling legacy {label} writer bypassed the storage epoch gate",
        )


def exercise_operation_storage_commitments(db: Any, backend: str) -> None:
    standalone_operation = f"custom.{backend}.standalone.plaintext"
    standalone_key = (
        "sha256:"
        + hashlib.sha256(
            f"{backend}:standalone-operation-storage".encode("utf-8")
        ).hexdigest()
    )
    consumed = db.consume_rate_limit(
        counter_key=standalone_key,
        principal_id=f"agent:{backend}:operation-storage",
        route_id=f"route:{backend}:operation-storage",
        credential_id=f"credential:{backend}:operation-storage",
        credential_version=1,
        policy_hash="sha256:" + "9" * 64,
        constraint_id=f"quota:{backend}:operation-storage",
        operation=standalone_operation,
        window_seconds=60,
        max_count=2,
    )
    if (
        not consumed.get("allowed")
        or consumed.get("count") != 1
        or not consumed.get("audit_event_hash")
    ):
        raise AssertionError(f"operation storage fixture was not consumed: {consumed}")
    consumed_events = db.search_audit_events(
        event_type="rate_limit.consumed", limit=100, scan_limit=5000
    )
    consumed_event = next(
        (
            item
            for item in consumed_events.get("items") or []
            if item.get("event_hash") == consumed["audit_event_hash"]
        ),
        None,
    )
    if (
        consumed_event is None
        or consumed_event.get("event", {}).get("operation")
        != operation_commitment(standalone_operation)
        or standalone_operation in json.dumps(consumed_event, sort_keys=True)
    ):
        raise AssertionError(
            f"rate-limit audit retained raw operation: {consumed_event}"
        )

    collision_source = f"custom.{backend}.commitment-source"
    digest_shaped_literal = operation_digest(collision_source)
    direct_payload = {
        "operation": digest_shaped_literal,
        "path": "direct",
    }
    direct = db.record_audit_event(
        "rate_limit.denied",
        direct_payload,
        actor_type="test",
        actor_id=f"test:{backend}:direct-commitment",
    )
    batch_payload = {"operation": collision_source, "path": "batch"}
    batch = db.record_audit_event_batch(
        [("rate_limit.denied", batch_payload)],
        actor_type="test",
        actor_id=f"test:{backend}:batch-commitment",
    )[0]
    staged_payload = {
        "operation": f"custom.{backend}.staged-commitment",
        "path": "staged",
    }
    with db.connect() as conn:
        staged = db.append_audit_event(
            conn,
            event_type="rate_limit.denied",
            actor_type="test",
            actor_id=f"test:{backend}:staged-commitment",
            event=staged_payload,
            idempotency_key=f"test:{backend}:staged-commitment",
        )
    if (
        direct_payload["operation"] != digest_shaped_literal
        or batch_payload["operation"] != collision_source
        or staged_payload["operation"] != f"custom.{backend}.staged-commitment"
        or direct.get("event", {}).get("operation")
        != operation_commitment(digest_shaped_literal)
        or batch.get("event", {}).get("operation")
        != operation_commitment(collision_source)
        or staged.get("event", {}).get("operation")
        != operation_commitment(f"custom.{backend}.staged-commitment")
        or direct["event"]["operation"] == batch["event"]["operation"]
    ):
        raise AssertionError(
            "direct, batched, or staged audit commitment storage was ambiguous or "
            "mutated caller data"
        )

    quota = quota_claim(f"{backend}-operation-storage", maximum=2)
    atomic_operation = f"custom.{backend}.atomic.plaintext"
    quota["operation"] = atomic_operation
    attempt_id = f"attempt:{backend}:operation-storage"
    binding = {
        "principal_id": f"agent:{backend}:operation-storage",
        "route_id": f"route:{backend}:operation-storage",
        "credential_id": "",
        "credential_version": 0,
        "policy_hash": "sha256:" + "a" * 64,
        "request_digest": "sha256:" + "b" * 64,
        "operation_digest": None,
    }
    advance_active_policy_hash(db, binding["policy_hash"])
    reserve_kwargs = release_reserve_kwargs(
        binding,
        attempt_id=attempt_id,
        quotas=[quota],
        require_jit_grant=False,
    )
    reserve_kwargs.update(
        {
            "authority_policy_hash": binding["policy_hash"],
            "authority_route_id": binding["route_id"],
        }
    )
    reserved = db.reserve_release_authorization(**reserve_kwargs)
    if reserved.get("state") != "reserved":
        raise AssertionError(f"operation storage reservation failed: {reserved}")
    if [item.get("operation") for item in reserved.get("quotas") or []] != [
        atomic_operation
    ]:
        raise AssertionError(f"quota operation API behavior changed: {reserved}")

    with db.connect() as conn:
        stored_standalone = conn.execute(
            "SELECT operation, count FROM rate_limit_counters WHERE counter_key = ?",
            (standalone_key,),
        ).fetchone()
        stored_atomic = conn.execute(
            "SELECT operation, count FROM rate_limit_counters WHERE counter_key = ?",
            (quota["counter_key"],),
        ).fetchone()
        stored_reservation = conn.execute(
            "SELECT operation, encrypted_operation, reservation_state FROM "
            "release_authorization_quota_reservations "
            "WHERE attempt_id = ? AND counter_key = ?",
            (attempt_id, quota["counter_key"]),
        ).fetchone()
    if (
        stored_standalone is None
        or stored_standalone["operation"] != operation_digest(standalone_operation)
        or standalone_operation in str(stored_standalone["operation"])
        or int(stored_standalone["count"]) != 1
    ):
        raise AssertionError(
            f"new rate-limit operation was not committed at rest: {stored_standalone}"
        )
    if (
        stored_atomic is None
        or stored_atomic["operation"] != operation_digest(atomic_operation)
        or atomic_operation in str(stored_atomic["operation"])
        or int(stored_atomic["count"]) != 1
        or stored_reservation is None
        or stored_reservation["operation"] != operation_digest(atomic_operation)
        or atomic_operation in str(stored_reservation["operation"])
        or atomic_operation in str(stored_reservation["encrypted_operation"])
        or stored_reservation["reservation_state"] != "reserved"
    ):
        raise AssertionError(
            "new atomic quota operation was not committed at rest: "
            f"counter={stored_atomic} reservation={stored_reservation}"
        )

    legacy_standalone = operation_digest(
        f"legacy.{backend}.digest-shaped-literal-source"
    )
    legacy_atomic = f"legacy.{backend}.atomic.plaintext"
    legacy_audit = f"legacy.{backend}.audit.plaintext"
    with db.connect() as conn:
        conn.execute(
            "DELETE FROM catchplate_store_migrations WHERE migration IN (?, ?)",
            (
                db._AUDIT_STORAGE_REDACTION_MIGRATION,
                db._METADATA_STORAGE_REDACTION_MIGRATION,
            ),
        )
    if backend == "postgres":
        with db._audit_pg_connect() as conn:
            with conn.transaction():
                conn.execute(
                    "DELETE FROM catchplate_store_migrations WHERE migration = %s",
                    (db._AUDIT_STORAGE_REDACTION_MIGRATION,),
                )
    with db.connect() as conn:
        conn.execute(
            "UPDATE rate_limit_counters SET operation = ?, encrypted_operation = NULL, "
            "operation_storage_version = NULL WHERE counter_key = ?",
            (legacy_standalone, standalone_key),
        )
        conn.execute(
            "UPDATE rate_limit_counters SET operation = ?, encrypted_operation = NULL, "
            "operation_storage_version = NULL WHERE counter_key = ?",
            (legacy_atomic, quota["counter_key"]),
        )
        conn.execute(
            "UPDATE release_authorization_quota_reservations "
            "SET operation = ?, encrypted_operation = NULL, "
            "operation_storage_version = NULL "
            "WHERE attempt_id = ? AND counter_key = ?",
            (legacy_atomic, attempt_id, quota["counter_key"]),
        )
    legacy_api_before = db.reserve_release_authorization(**reserve_kwargs)
    if (
        [item.get("operation") for item in legacy_api_before.get("quotas") or []]
        != [legacy_atomic]
        or legacy_api_before.get("quotas", [{}])[0].get("count") != 1
    ):
        raise AssertionError(
            f"legacy quota API fixture did not retain raw semantics: {legacy_api_before}"
        )
    (
        legacy_audit_event_id,
        old_audit_head,
        original_event_json,
        old_audit_count,
    ) = inject_legacy_rate_limit_audit_head(db, backend, legacy_audit)
    setup = db.create_setup_session(
        owner_id=f"owner:{backend}:audit-storage-redaction",
        actor_id=f"owner:{backend}:audit-storage-redaction",
    )
    legacy_outbox_operation = f"legacy.{backend}.outbox.plaintext"
    legacy_outbox_event_json = db.dumps(
        {
            "operation": legacy_outbox_operation,
            "reason": "legacy-outbox-fixture",
        }
    )
    outbox_id = f"legacy:{backend}:rate-limit-outbox"
    with db.connect() as conn:
        setup_event = conn.execute(
            "SELECT id FROM setup_session_events WHERE session_id = ? "
            "ORDER BY sequence ASC LIMIT 1",
            (setup["id"],),
        ).fetchone()
        release_event = conn.execute(
            "SELECT id FROM release_authorization_events WHERE attempt_id = ? "
            "ORDER BY created_at ASC, id ASC LIMIT 1",
            (attempt_id,),
        ).fetchone()
        if setup_event is None or release_event is None:
            raise AssertionError("durable audit reference fixtures were not created")
        conn.execute(
            "UPDATE setup_session_events SET audit_status = 'audited', audited_at = ?, "
            "audit_event_hash = ? WHERE id = ?",
            (db.iso_now(), old_audit_head, setup_event["id"]),
        )
        conn.execute(
            "UPDATE release_authorization_events SET audited_at = ?, "
            "audit_event_hash = ? WHERE id = ?",
            (db.iso_now(), old_audit_head, release_event["id"]),
        )
        conn.execute(
            "INSERT INTO metadata_audit_outbox (id, event_type, actor_type, actor_id, "
            "event_json, status, audited_at, audit_event_hash, created_at) "
            "VALUES (?, 'rate_limit.denied', 'test', ?, ?, 'audited', ?, ?, ?)",
            (
                outbox_id,
                f"test:{backend}:legacy-outbox",
                legacy_outbox_event_json,
                db.iso_now(),
                old_audit_head,
                db.iso_now(),
            ),
        )
        durable_reference_ids = {
            "setup": str(setup_event["id"]),
            "release": str(release_event["id"]),
        }
    if backend == "postgres":
        with db._audit_pg_connect() as conn:
            old_audit_row = conn.execute(
                "SELECT prev_event_hash FROM catchplate_audit_events WHERE id = %s",
                (legacy_audit_event_id,),
            ).fetchone()
            old_prefix_hashes = {
                str(row["id"]): str(row["event_hash"])
                for row in conn.execute(
                    "SELECT id, event_hash FROM catchplate_audit_events "
                    "ORDER BY sequence ASC"
                ).fetchall()
            }
    else:
        with db.connect() as conn:
            old_audit_row = conn.execute(
                "SELECT prev_event_hash FROM audit_events WHERE id = ?",
                (legacy_audit_event_id,),
            ).fetchone()
            old_prefix_hashes = {
                str(row["id"]): str(row["event_hash"])
                for row in conn.execute(
                    "SELECT id, event_hash FROM audit_events ORDER BY rowid ASC"
                ).fetchall()
            }
    old_prev_event_hash = old_audit_row["prev_event_hash"]

    preloaded_keyring = db.load_bound_secret_keyring()
    preload_event: dict[str, Any] | None = None

    def simulate_first_key_release_audit() -> Any:
        nonlocal preload_event
        if preload_event is None:
            preload_event = db.record_audit_event(
                "key_release.material_released",
                {"material": "test-migration-preload"},
                actor_type="system",
                actor_id=f"test:{backend}:migration-key-preload",
            )
        return preloaded_keyring

    with patch.object(
        db,
        "load_bound_secret_keyring",
        side_effect=simulate_first_key_release_audit,
    ):
        db.init_db()
    if preload_event is None:
        raise AssertionError("migration did not preload encryption material")
    pre_migration_head = preload_event["event_hash"]
    pre_migration_count = old_audit_count + 1
    old_prefix_hashes[str(preload_event["id"])] = str(pre_migration_head)
    with db.connect() as conn:
        migrated_standalone = conn.execute(
            "SELECT operation, encrypted_operation, operation_storage_version, count "
            "FROM rate_limit_counters WHERE counter_key = ?",
            (standalone_key,),
        ).fetchone()
        migrated_atomic = conn.execute(
            "SELECT operation, encrypted_operation, operation_storage_version, count "
            "FROM rate_limit_counters WHERE counter_key = ?",
            (quota["counter_key"],),
        ).fetchone()
        migrated_reservation = conn.execute(
            "SELECT operation, encrypted_operation, operation_storage_version, "
            "reservation_state FROM "
            "release_authorization_quota_reservations "
            "WHERE attempt_id = ? AND counter_key = ?",
            (attempt_id, quota["counter_key"]),
        ).fetchone()
        durable_references = {
            "setup": conn.execute(
                "SELECT audit_event_hash FROM setup_session_events WHERE id = ?",
                (durable_reference_ids["setup"],),
            ).fetchone()["audit_event_hash"],
            "release": conn.execute(
                "SELECT audit_event_hash FROM release_authorization_events WHERE id = ?",
                (durable_reference_ids["release"],),
            ).fetchone()["audit_event_hash"],
            "outbox": conn.execute(
                "SELECT audit_event_hash FROM metadata_audit_outbox WHERE id = ?",
                (outbox_id,),
            ).fetchone()["audit_event_hash"],
        }
        migrated_outbox = conn.execute(
            "SELECT event_json FROM metadata_audit_outbox WHERE id = ?", (outbox_id,)
        ).fetchone()
        metadata_gate = conn.execute(
            "SELECT version FROM catchplate_store_migrations WHERE migration = ?",
            (db._METADATA_STORAGE_REDACTION_MIGRATION,),
        ).fetchone()
    if backend == "postgres":
        with db._audit_pg_connect() as conn:
            migrated_audit_row = conn.execute(
                "SELECT event_json, encrypted_canonical_event_json, prev_event_hash, "
                "event_hash, storage_format_version FROM catchplate_audit_events "
                "WHERE id = %s",
                (legacy_audit_event_id,),
            ).fetchone()
            audit_gate = conn.execute(
                "SELECT version FROM catchplate_store_migrations WHERE migration = %s",
                (db._AUDIT_STORAGE_REDACTION_MIGRATION,),
            ).fetchone()
            migrated_prefix_hashes = {
                str(row["id"]): str(row["event_hash"])
                for row in conn.execute(
                    "SELECT id, event_hash FROM catchplate_audit_events "
                    "ORDER BY sequence ASC LIMIT %s",
                    (pre_migration_count,),
                ).fetchall()
            }
    else:
        with db.connect() as conn:
            migrated_audit_row = conn.execute(
                "SELECT event_json, encrypted_canonical_event_json, prev_event_hash, "
                "event_hash, storage_format_version FROM audit_events WHERE id = ?",
                (legacy_audit_event_id,),
            ).fetchone()
            audit_gate = conn.execute(
                "SELECT version FROM catchplate_store_migrations WHERE migration = ?",
                (db._AUDIT_STORAGE_REDACTION_MIGRATION,),
            ).fetchone()
            migrated_prefix_hashes = {
                str(row["id"]): str(row["event_hash"])
                for row in conn.execute(
                    "SELECT id, event_hash FROM audit_events ORDER BY rowid ASC LIMIT ?",
                    (pre_migration_count,),
                ).fetchall()
            }
    with patch.object(
        db,
        "load_bound_secret_keyring",
        side_effect=RuntimeError("forced canonical-preimage key failure"),
    ):
        unavailable_key_verification = db.verify_audit_chain()
    if (
        unavailable_key_verification.get("ok") is not False
        or unavailable_key_verification.get("error")
        != "canonical_preimage_key_unavailable"
        or unavailable_key_verification.get("event_id") != legacy_audit_event_id
    ):
        raise AssertionError(
            "encrypted canonical preimage did not fail closed without its key: "
            f"{unavailable_key_verification}"
        )
    with patch.object(
        db,
        "load_bound_secret_keyring",
        wraps=db.load_bound_secret_keyring,
    ) as lazy_keyring_loader:
        audit_verification = db.verify_audit_chain()
    if lazy_keyring_loader.call_count != 1:
        raise AssertionError(
            "audit verification did not cache its lazy canonical-preimage keyring: "
            f"calls={lazy_keyring_loader.call_count}"
        )
    prefix_verification = db.verify_audit_chain(limit=pre_migration_count)
    audit_events = db.list_audit_events(limit=5000)
    markers = [
        item
        for item in audit_events
        if item.get("event_type") == "audit.storage_redacted"
    ]
    legacy_event = next(
        (item for item in audit_events if item.get("id") == legacy_audit_event_id),
        None,
    )
    expected_redacted_event_json = db.dumps(
        {
            "counter_key": "sha256:" + "d" * 64,
            "operation": operation_commitment(legacy_audit),
            "reason": "legacy-fixture",
        }
    )
    expected_manifest = [
        {
            "id": legacy_audit_event_id,
            "event_hash": old_audit_head,
            "original_event_json_digest": operation_digest(original_event_json),
            "redacted_event_json_digest": operation_digest(
                expected_redacted_event_json
            ),
        }
    ]
    outbox_event = json.loads(migrated_outbox["event_json"])
    canonical_original = db.decrypt_bound_secret(
        migrated_audit_row["encrypted_canonical_event_json"],
        purpose="audit-canonical-event-preimage",
        binding={
            "event_id": legacy_audit_event_id,
            "event_hash": old_audit_head,
            "storage_format_version": db._AUDIT_STORAGE_FORMAT_VERSION,
        },
        keyring=db.load_bound_secret_keyring(),
    )
    if (
        not audit_verification.get("ok")
        or audit_verification.get("head") == pre_migration_head
        or audit_verification.get("count") != pre_migration_count + 1
        or migrated_prefix_hashes != old_prefix_hashes
        or not prefix_verification.get("ok")
        or prefix_verification.get("head") != pre_migration_head
        or legacy_event is None
        or "encrypted_canonical_event_json" in legacy_event
        or legacy_event.get("event", {}).get("operation")
        != operation_commitment(legacy_audit)
        or legacy_audit in json.dumps(audit_events, sort_keys=True)
        or migrated_audit_row["event_hash"] != old_audit_head
        or migrated_audit_row["prev_event_hash"] != old_prev_event_hash
        or migrated_audit_row["event_json"] != expected_redacted_event_json
        or canonical_original != original_event_json
        or migrated_audit_row["storage_format_version"]
        != db._AUDIT_STORAGE_FORMAT_VERSION
        or legacy_audit in migrated_audit_row["event_json"]
        or legacy_audit in migrated_audit_row["encrypted_canonical_event_json"]
        or outbox_event.get("operation")
        != operation_commitment(legacy_outbox_operation)
        or legacy_outbox_operation in migrated_outbox["event_json"]
        or set(durable_references.values()) != {old_audit_head}
        or int(metadata_gate["version"]) != db._STORAGE_REDACTION_MIGRATION_VERSION
        or int(audit_gate["version"]) != db._STORAGE_REDACTION_MIGRATION_VERSION
        or len(markers) != 1
        or markers[0].get("event", {}).get("old_head_event_hash")
        != pre_migration_head
        or markers[0].get("event", {}).get("affected_event_count") != 1
        or markers[0].get("event", {}).get("manifest_digest")
        != operation_digest(db.dumps(expected_manifest))
        or markers[0].get("prev_event_hash") != pre_migration_head
    ):
        raise AssertionError(
            "legacy audit storage redaction did not preserve the canonical chain: "
            f"verification={audit_verification} prefix={prefix_verification} "
            f"legacy={legacy_event} markers={markers} refs={durable_references}"
        )
    remediated_head = audit_verification["head"]
    remediated_count = audit_verification["count"]
    with patch.object(
        db,
        "_validated_audit_row_hash",
        side_effect=AssertionError("durable audit migration gate was bypassed"),
    ), patch.object(
        db,
        "_encrypt_operation",
        side_effect=AssertionError("durable metadata migration gate was bypassed"),
    ):
        db.init_db()
    repeated_verification = db.verify_audit_chain()
    if (
        not repeated_verification.get("ok")
        or repeated_verification.get("head") != remediated_head
        or repeated_verification.get("count") != remediated_count
    ):
        raise AssertionError(
            f"audit storage redaction was not idempotent: {repeated_verification}"
        )
    exercise_legacy_writer_storage_guards(
        db,
        backend,
        existing_attempt_id=attempt_id,
        existing_audit_id=legacy_audit_event_id,
        existing_outbox_id=outbox_id,
        existing_counter_key=standalone_key,
        existing_quota_counter_key=quota["counter_key"],
    )

    def update_legacy_audit_storage(
        event_json: str, encrypted_canonical_event_json: str
    ) -> None:
        if backend == "postgres":
            with db._audit_pg_connect() as conn:
                with conn.transaction():
                    conn.execute(
                        "UPDATE catchplate_audit_events SET event_json = %s, "
                        "encrypted_canonical_event_json = %s WHERE id = %s",
                        (
                            event_json,
                            encrypted_canonical_event_json,
                            legacy_audit_event_id,
                        ),
                    )
        else:
            with db.connect() as conn:
                conn.execute(
                    "UPDATE audit_events SET event_json = ?, "
                    "encrypted_canonical_event_json = ? WHERE id = ?",
                    (
                        event_json,
                        encrypted_canonical_event_json,
                        legacy_audit_event_id,
                    ),
                )

    tampered_visible = json.loads(expected_redacted_event_json)
    tampered_visible["operation"]["digest"] = operation_digest("visible-tamper")
    update_legacy_audit_storage(
        db.dumps(tampered_visible),
        migrated_audit_row["encrypted_canonical_event_json"],
    )
    visible_tamper_verification = db.verify_audit_chain()
    assert_raises(
        db.AuditStoreError,
        db.init_db,
        "completed audit migration gate ignored a broken visible projection",
    )
    update_legacy_audit_storage(
        expected_redacted_event_json,
        migrated_audit_row["encrypted_canonical_event_json"],
    )
    update_legacy_audit_storage(expected_redacted_event_json, "v1:AA:AA")
    ciphertext_tamper_verification = db.verify_audit_chain()
    update_legacy_audit_storage(
        expected_redacted_event_json,
        migrated_audit_row["encrypted_canonical_event_json"],
    )
    restored_verification = db.verify_audit_chain()
    if (
        visible_tamper_verification.get("ok")
        or visible_tamper_verification.get("error")
        != "redacted_projection_mismatch"
        or ciphertext_tamper_verification.get("ok")
        or ciphertext_tamper_verification.get("error")
        != "canonical_preimage_invalid"
        or not restored_verification.get("ok")
        or restored_verification.get("head") != remediated_head
    ):
        raise AssertionError(
            "visible or encrypted canonical audit tampering was not detected: "
            f"visible={visible_tamper_verification} "
            f"ciphertext={ciphertext_tamper_verification} "
            f"restored={restored_verification}"
        )
    if (
        migrated_standalone["operation"] != operation_digest(legacy_standalone)
        or legacy_standalone in str(migrated_standalone["operation"])
        or migrated_standalone["operation_storage_version"]
        != db._OPERATION_STORAGE_VERSION
        or legacy_standalone in str(migrated_standalone["encrypted_operation"])
        or int(migrated_standalone["count"]) != 1
        or migrated_atomic["operation"] != operation_digest(legacy_atomic)
        or legacy_atomic in str(migrated_atomic["operation"])
        or migrated_atomic["operation_storage_version"]
        != db._OPERATION_STORAGE_VERSION
        or int(migrated_atomic["count"]) != 1
        or migrated_reservation["operation"] != operation_digest(legacy_atomic)
        or legacy_atomic in str(migrated_reservation["operation"])
        or legacy_atomic in str(migrated_reservation["encrypted_operation"])
        or migrated_reservation["operation_storage_version"]
        != db._OPERATION_STORAGE_VERSION
        or migrated_reservation["reservation_state"] != "reserved"
    ):
        raise AssertionError(
            "legacy plaintext quota operations were not migrated without state loss: "
            f"standalone={dict(migrated_standalone)} "
            f"counter={dict(migrated_atomic)} "
            f"reservation={dict(migrated_reservation)}"
        )

    with db.connect() as conn:
        conn.execute(
            "UPDATE rate_limit_counters SET encrypted_operation = ? "
            "WHERE counter_key = ?",
            (migrated_reservation["encrypted_operation"], standalone_key),
        )
    assert_raises(
        db.MetadataStoreError,
        db.init_db,
        "completed metadata migration gate ignored transplanted ciphertext",
    )
    assert_raises(
        Exception,
        lambda: db.consume_rate_limit(
            counter_key=standalone_key,
            principal_id=f"agent:{backend}:operation-storage",
            route_id=f"route:{backend}:operation-storage",
            credential_id=f"credential:{backend}:operation-storage",
            credential_version=1,
            policy_hash="sha256:" + "9" * 64,
            constraint_id=f"quota:{backend}:operation-storage",
            operation=standalone_operation,
            window_seconds=60,
            max_count=2,
            consume=False,
            audit=False,
        ),
        "transplanted rate-counter recovery ciphertext was accepted",
    )
    with db.connect() as conn:
        conn.execute(
            "UPDATE rate_limit_counters SET encrypted_operation = ? "
            "WHERE counter_key = ?",
            (migrated_standalone["encrypted_operation"], standalone_key),
        )
        conn.execute(
            "UPDATE release_authorization_quota_reservations "
            "SET encrypted_operation = ? WHERE attempt_id = ? AND counter_key = ?",
            (migrated_atomic["encrypted_operation"], attempt_id, quota["counter_key"]),
        )
    assert_raises(
        Exception,
        lambda: db.reserve_release_authorization(**reserve_kwargs),
        "transplanted quota recovery ciphertext was accepted",
    )
    with db.connect() as conn:
        conn.execute(
            "UPDATE release_authorization_quota_reservations "
            "SET encrypted_operation = ? WHERE attempt_id = ? AND counter_key = ?",
            (
                migrated_reservation["encrypted_operation"],
                attempt_id,
                quota["counter_key"],
            ),
        )

    replayed = db.reserve_release_authorization(**reserve_kwargs)
    available = db.consume_rate_limit(
        counter_key=standalone_key,
        principal_id=f"agent:{backend}:operation-storage",
        route_id=f"route:{backend}:operation-storage",
        credential_id=f"credential:{backend}:operation-storage",
        credential_version=1,
        policy_hash="sha256:" + "9" * 64,
        constraint_id=f"quota:{backend}:operation-storage",
        operation=standalone_operation,
        window_seconds=60,
        max_count=2,
        consume=False,
        audit=False,
    )
    if (
        replayed.get("state") != "reserved"
        or replayed.get("binding_digest") != reserved.get("binding_digest")
        or [item.get("operation") for item in replayed.get("quotas") or []]
        != [item.get("operation") for item in legacy_api_before.get("quotas") or []]
        or replayed.get("quotas", [{}])[0].get("count") != 1
        or not available.get("allowed")
        or available.get("count") != 1
    ):
        raise AssertionError(
            "operation remediation changed quota state or raw API behavior: "
            f"replayed={replayed} available={available}"
        )

    cancelled = db.complete_release_authorization(
        attempt_id=attempt_id,
        binding_digest=reserved["binding_digest"],
        outcome="not_forwarded",
    )
    if (
        cancelled.get("state") != "cancelled"
        or counter_count(db, quota["counter_key"]) != 0
    ):
        raise AssertionError(
            f"migrated quota reservation no longer refunded correctly: {cancelled}"
        )

    chain_before_future_gate = db.verify_audit_chain()
    with db.connect() as conn:
        conn.execute(
            "UPDATE catchplate_store_migrations SET version = ? WHERE migration = ?",
            (
                db._STORAGE_REDACTION_MIGRATION_VERSION + 1,
                db._AUDIT_STORAGE_REDACTION_MIGRATION,
            ),
        )
    rejected_chain = db.verify_audit_chain()
    if (
        rejected_chain.get("ok") is not False
        or rejected_chain.get("error")
        != "unsupported_storage_migration_version"
        or rejected_chain.get("storage_migration_version")
        != db._STORAGE_REDACTION_MIGRATION_VERSION + 1
    ):
        raise AssertionError(
            "audit verification accepted an unsupported future migration gate: "
            f"{rejected_chain}"
        )
    try:
        db.init_db()
    except RuntimeError as exc:
        if "unsupported future version" not in str(exc):
            raise AssertionError(f"future migration gate failed unclearly: {exc}") from exc
    else:
        raise AssertionError("future audit migration gate version was accepted")
    with db.connect() as conn:
        conn.execute(
            "UPDATE catchplate_store_migrations SET version = ? WHERE migration = ?",
            (
                db._STORAGE_REDACTION_MIGRATION_VERSION,
                db._AUDIT_STORAGE_REDACTION_MIGRATION,
            ),
        )
    chain_after_future_gate = db.verify_audit_chain()
    if chain_after_future_gate != chain_before_future_gate:
        raise AssertionError("future migration gate failure mutated the audit chain")


def exercise_transactional_bound_storage_rewrap(
    crypto: Any, db: Any, backend: str
) -> None:
    original_ring = db.load_bound_secret_keyring()
    original_key = original_ring.keys[original_ring.active_key_id]
    rotated_key = os.urandom(32)
    rollback_key = os.urandom(32)
    rotated_ring = crypto.build_bound_secret_keyring(
        rotated_key, [original_key]
    )
    rotated_only = crypto.build_bound_secret_keyring(rotated_key)

    def snapshot() -> dict[str, Any]:
        if backend == "postgres":
            with db._audit_pg_connect() as conn:
                audit_rows = conn.execute(
                    "SELECT id, encrypted_canonical_event_json FROM "
                    "catchplate_audit_events WHERE "
                    "encrypted_canonical_event_json IS NOT NULL ORDER BY sequence"
                ).fetchall()
        else:
            with db.connect() as conn:
                audit_rows = conn.execute(
                    "SELECT id, encrypted_canonical_event_json FROM audit_events "
                    "WHERE encrypted_canonical_event_json IS NOT NULL ORDER BY rowid"
                ).fetchall()
        with db.connect() as conn:
            counters = conn.execute(
                "SELECT counter_key, encrypted_operation FROM rate_limit_counters "
                "WHERE encrypted_operation IS NOT NULL ORDER BY counter_key"
            ).fetchall()
            quotas = conn.execute(
                "SELECT attempt_id, counter_key, encrypted_operation FROM "
                "release_authorization_quota_reservations "
                "WHERE encrypted_operation IS NOT NULL "
                "ORDER BY attempt_id, counter_key"
            ).fetchall()
            gates = conn.execute(
                "SELECT migration, version FROM catchplate_store_migrations "
                "WHERE migration LIKE ? OR migration LIKE ? ORDER BY migration",
                (
                    db._AUDIT_BOUND_KEY_GATE_PREFIX + "%",
                    db._METADATA_BOUND_KEY_GATE_PREFIX + "%",
                ),
            ).fetchall()
        return {
            "audit": [dict(row) for row in audit_rows],
            "counters": [dict(row) for row in counters],
            "quotas": [dict(row) for row in quotas],
            "gates": [dict(row) for row in gates],
        }

    def assert_active_key(snapshot_value: dict[str, Any], key_id: str) -> None:
        encrypted_values = [
            row["encrypted_canonical_event_json"]
            for row in snapshot_value["audit"]
        ] + [
            row["encrypted_operation"]
            for row in snapshot_value["counters"] + snapshot_value["quotas"]
        ]
        if not encrypted_values:
            raise AssertionError("bound storage rewrap fixture has no ciphertext")
        actual = {
            crypto.bound_secret_envelope_key_id(str(value))
            for value in encrypted_values
        }
        if actual != {key_id}:
            raise AssertionError(
                f"bound storage rewrap retained non-active key IDs: {actual}"
            )

    with patch.object(db, "load_bound_secret_keyring", return_value=rotated_ring):
        db.init_db()
    rotated_snapshot = snapshot()
    assert_active_key(rotated_snapshot, rotated_ring.active_key_id)
    with patch.object(db, "load_bound_secret_keyring", return_value=rotated_only):
        db.init_db()
        verification = db.verify_audit_chain()
    if not verification.get("ok"):
        raise AssertionError(
            f"historical-key retirement broke rewrapped audit data: {verification}"
        )

    rollback_ring = crypto.build_bound_secret_keyring(
        rollback_key, [rotated_key]
    )
    before_audit_failure = snapshot()
    with patch.object(
        db, "load_bound_secret_keyring", return_value=rollback_ring
    ), patch.object(
        db,
        "encrypt_bound_secret",
        side_effect=RuntimeError("forced audit rewrap failure"),
    ):
        assert_raises(
            RuntimeError,
            db.init_db,
            "audit rewrap failure committed partial ciphertext",
        )
    if snapshot() != before_audit_failure:
        raise AssertionError("failed audit rewrap mutated ciphertext or key gates")

    before_metadata_failure = snapshot()
    try:
        with patch.object(
            db,
            "_encrypt_operation",
            side_effect=RuntimeError("forced metadata rewrap failure"),
        ):
            with db.connect() as conn:
                db._lock_postgres_metadata_migration_tables(conn)
                db._rewrap_metadata_operations(conn, keyring=rollback_ring)
                db._record_bound_key_gate(
                    conn,
                    prefix=db._METADATA_BOUND_KEY_GATE_PREFIX,
                    keyring=rollback_ring,
                )
    except RuntimeError:
        pass
    else:
        raise AssertionError("metadata rewrap fault did not abort")
    if snapshot() != before_metadata_failure:
        raise AssertionError("failed metadata rewrap mutated ciphertext or key gates")

    restored_ring = crypto.build_bound_secret_keyring(
        original_key, [rotated_key]
    )
    with patch.object(db, "load_bound_secret_keyring", return_value=restored_ring):
        db.init_db()
    restored_snapshot = snapshot()
    assert_active_key(restored_snapshot, restored_ring.active_key_id)
    with patch.object(
        db,
        "load_bound_secret_keyring",
        return_value=crypto.build_bound_secret_keyring(original_key),
    ):
        db.init_db()
        restored_verification = db.verify_audit_chain()
    if not restored_verification.get("ok"):
        raise AssertionError(
            "restored active key could not verify after historical removal: "
            f"{restored_verification}"
            )


def exercise_release_credential_issuance_claim(db: Any, backend: str) -> None:
    def request_authority_sha256(claim: dict[str, Any]) -> str:
        authority = {
            "apiVersion": (
                "catchplate.credentialLeaseRequestAuthority/v1"
            ),
            "attemptId": claim["attempt_id"],
            "reservationId": claim["reservation_id"],
            "bindingDigest": claim["binding_digest"],
            "requestDigest": claim["request_digest"],
            "operationDigest": claim["operation_digest"],
            "operationContext": claim["operation_context"],
            "reservationExpiresAtEpochMs": claim[
                "reservation_expires_at_epoch_ms"
            ],
        }
        return (
            "sha256:"
            + hashlib.sha256(
                json.dumps(
                    authority,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest()
        )

    fixture = _provision_release_authority_fixture(
        db,
        backend,
        "credential-issuance",
        reserve=True,
    )
    reservation = fixture["reservation"]
    binding = {
        **fixture["binding"],
        "authority_policy_hash": fixture["policy_hash"],
        "authority_route_id": fixture["binding"]["route_id"],
    }
    request_binding_sha256 = _jit_authority_policy_hash(
        f"{backend}:credential-issuance:request"
    )
    recipient_key_id = _jit_authority_policy_hash(
        f"{backend}:credential-issuance:recipient"
    )
    recipient_nonce_sha256 = _jit_authority_policy_hash(
        f"{backend}:credential-issuance:nonce"
    )
    operation_context = {
        "operation": "test.forward",
        "account": "acct:test",
    }
    with db.connect() as conn:
        quota_claims = db._release_credential_quota_claims(
            conn, reservation["attempt_id"]
        )
    claim_kwargs = {
        "release_kind": "jitGrant",
        "attempt_id": reservation["attempt_id"],
        "reservation_id": db.release_reservation_id(
            reservation["attempt_id"], reservation["binding_digest"]
        ),
        "binding_digest": reservation["binding_digest"],
        "request_digest": binding["request_digest"],
        "operation_digest": binding["operation_digest"],
        "operation_context": operation_context,
        "quota_claims": quota_claims,
        "request_binding_sha256": request_binding_sha256,
        "recipient_key_id": recipient_key_id,
        "recipient_nonce_sha256": recipient_nonce_sha256,
        "principal_id": binding["principal_id"],
        "route_id": binding["route_id"],
        "credential_id": binding["credential_id"],
        "credential_version": binding["credential_version"],
        "policy_hash": binding["policy_hash"],
        "grant_id": fixture["grant_id"],
        "approval_request_id": fixture["approval_id"],
        "reservation_expires_at_epoch_ms": reservation[
            "reservation_expires_at_epoch_ms"
        ],
        "required_approver_roles": {"approver"},
        "allowed_approver_ids": {fixture["actor_id"]},
        "require_approver_webauthn": True,
    }
    claim_kwargs["request_authority_sha256"] = (
        request_authority_sha256(claim_kwargs)
    )
    jit_authority_lock_calls = {"webauthn": 0, "rbac": 0}
    original_webauthn_lock = db._lock_webauthn_authority
    original_rbac_lock = db._lock_rbac_authority

    def record_webauthn_lock(conn: Any) -> None:
        jit_authority_lock_calls["webauthn"] += 1
        original_webauthn_lock(conn)

    def record_rbac_lock(conn: Any) -> None:
        jit_authority_lock_calls["rbac"] += 1
        original_rbac_lock(conn)

    with (
        patch.object(db, "_lock_webauthn_authority", record_webauthn_lock),
        patch.object(db, "_lock_rbac_authority", record_rbac_lock),
    ):
        claimed = db.claim_release_credential_issuance(**claim_kwargs)
    if jit_authority_lock_calls != {"webauthn": 1, "rbac": 1}:
        raise AssertionError(
            f"{backend} JIT credential issuance did not lock WebAuthn and RBAC "
            f"authority exactly once: {jit_authority_lock_calls}"
        )
    if (
        claimed.get("attempt_id") != reservation["attempt_id"]
        or claimed.get("request_binding_sha256") != request_binding_sha256
        or claimed.get("request_authority_sha256")
        != claim_kwargs["request_authority_sha256"]
        or claimed.get("recipient_key_id") != recipient_key_id
        or claimed.get("recipient_nonce_sha256") != recipient_nonce_sha256
    ):
        raise AssertionError(
            f"{backend} credential issuance claim lost exact bindings: {claimed}"
        )
    try:
        db.claim_release_credential_issuance(
            **{
                **claim_kwargs,
                "request_binding_sha256": _jit_authority_policy_hash(
                    f"{backend}:credential-issuance:replacement-request"
                ),
                "recipient_key_id": _jit_authority_policy_hash(
                    f"{backend}:credential-issuance:replacement-recipient"
                ),
                "recipient_nonce_sha256": _jit_authority_policy_hash(
                    f"{backend}:credential-issuance:replacement-nonce"
                ),
            }
        )
    except db.ReleaseAuthorizationConflictError:
        pass
    else:
        raise AssertionError(
            f"{backend} one release attempt minted multiple credential issuances"
        )
    with db.connect() as conn:
        row = conn.execute(
            "SELECT COUNT(*) AS count "
            "FROM release_authorization_credential_issuances "
            "WHERE attempt_id = ?",
            (reservation["attempt_id"],),
        ).fetchone()
    if row is None or int(row["count"]) != 1:
        raise AssertionError(
            f"{backend} credential issuance claim count is not exactly one: {row}"
        )

    def atomic_claim_fixture(label: str) -> tuple[dict[str, Any], dict[str, Any]]:
        attempt_id = _jit_authority_policy_hash(
            f"{backend}:atomic-credential:{label}"
        )
        reservation = db.reserve_release_authorization(
            **release_reserve_kwargs(
                binding,
                attempt_id=attempt_id,
                quotas=[
                    quota_claim(
                        f"{backend}-atomic-credential-{label}",
                        maximum=1,
                    )
                ],
                require_jit_grant=False,
            )
        )
        if reservation.get("state") != "reserved":
            raise AssertionError(
                f"{backend} non-JIT credential reservation failed: {reservation}"
            )
        with db.connect() as conn:
            claims = db._release_credential_quota_claims(conn, attempt_id)
        claim = {
            "release_kind": "atomicReservation",
            "attempt_id": attempt_id,
            "reservation_id": db.release_reservation_id(
                attempt_id, reservation["binding_digest"]
            ),
            "binding_digest": reservation["binding_digest"],
            "request_digest": binding["request_digest"],
            "operation_digest": binding["operation_digest"],
            "operation_context": operation_context,
            "quota_claims": claims,
            "request_binding_sha256": _jit_authority_policy_hash(
                f"{backend}:atomic:{label}:request"
            ),
            "recipient_key_id": _jit_authority_policy_hash(
                f"{backend}:atomic:{label}:recipient"
            ),
            "recipient_nonce_sha256": _jit_authority_policy_hash(
                f"{backend}:atomic:{label}:nonce"
            ),
            "principal_id": binding["principal_id"],
            "route_id": binding["route_id"],
            "credential_id": binding["credential_id"],
            "credential_version": binding["credential_version"],
            "policy_hash": binding["policy_hash"],
            "grant_id": None,
            "approval_request_id": None,
            "reservation_expires_at_epoch_ms": reservation[
                "reservation_expires_at_epoch_ms"
            ],
        }
        claim["request_authority_sha256"] = request_authority_sha256(
            claim
        )
        return reservation, claim

    def claim_atomic(claim: dict[str, Any]) -> dict[str, Any]:
        def reject_webauthn_lock(_conn: Any) -> None:
            raise AssertionError(
                f"{backend} atomic credential issuance called the WebAuthn lock"
            )

        def reject_rbac_lock(_conn: Any) -> None:
            raise AssertionError(
                f"{backend} atomic credential issuance called the RBAC lock"
            )

        with (
            patch.object(
                db,
                "_lock_webauthn_authority",
                reject_webauthn_lock,
            ),
            patch.object(db, "_lock_rbac_authority", reject_rbac_lock),
        ):
            return db.claim_release_credential_issuance(**claim)

    def assert_exact_atomic_claim(
        claimed: dict[str, Any],
        claim: dict[str, Any],
        *,
        label: str,
    ) -> None:
        quota_claims_digest = "sha256:" + hashlib.sha256(
            json.dumps(
                claim["quota_claims"],
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        expected = {
            "release_kind": "atomicReservation",
            "attempt_id": claim["attempt_id"],
            "reservation_id": claim["reservation_id"],
            "binding_digest": claim["binding_digest"],
            "request_digest": claim["request_digest"],
            "operation_digest": claim["operation_digest"],
            "quota_claims_digest": quota_claims_digest,
            "request_binding_sha256": claim["request_binding_sha256"],
            "request_authority_sha256": claim[
                "request_authority_sha256"
            ],
            "recipient_key_id": claim["recipient_key_id"],
            "recipient_nonce_sha256": claim["recipient_nonce_sha256"],
            "reservation_expires_at_epoch_ms": claim[
                "reservation_expires_at_epoch_ms"
            ],
        }
        if any(claimed.get(field) != value for field, value in expected.items()):
            raise AssertionError(
                f"{backend} {label} atomic claim lost exact authority: "
                f"expected={expected} claimed={claimed}"
            )
        with db.connect() as conn:
            row = conn.execute(
                "SELECT release_kind, reservation_id, binding_digest, "
                "request_digest, operation_digest, quota_claims_digest, "
                "request_binding_sha256, request_authority_sha256, "
                "recipient_key_id, "
                "recipient_nonce_sha256, reservation_expires_at_epoch_ms "
                "FROM release_authorization_credential_issuances "
                "WHERE attempt_id = ?",
                (claim["attempt_id"],),
            ).fetchone()
        durable = dict(row) if row is not None else {}
        if any(
            durable.get(field) != value
            for field, value in expected.items()
            if field != "attempt_id"
        ):
            raise AssertionError(
                f"{backend} {label} atomic claim was not stored exactly: "
                f"expected={expected} durable={durable}"
            )

    _, atomic_claim = atomic_claim_fixture("success")
    claimed_atomic = claim_atomic(atomic_claim)
    assert_exact_atomic_claim(claimed_atomic, atomic_claim, label="successful")
    assert_raises(
        db.ReleaseAuthorizationConflictError,
        lambda: claim_atomic(atomic_claim),
        "non-JIT atomic credential authority replay minted a second lease",
    )

    _, wrong_binding_claim = atomic_claim_fixture("wrong-binding")
    assert_raises(
        db.ReleaseAuthorizationConflictError,
        lambda: claim_atomic(
            {
                **wrong_binding_claim,
                "reservation_id": _jit_authority_policy_hash(
                    f"{backend}:wrong-reservation"
                ),
            }
        ),
        "non-JIT atomic credential authority accepted a wrong reservation ID",
    )
    assert_raises(
        db.ReleaseAuthorizationConflictError,
        lambda: db.claim_release_credential_issuance(
            **{
                **wrong_binding_claim,
                "release_kind": "jitGrant",
                "grant_id": "grant:wrong-kind",
                "approval_request_id": "approval:wrong-kind",
            }
        ),
        "non-JIT atomic credential authority accepted JIT fields",
    )
    claimed_after_wrong_binding = claim_atomic(wrong_binding_claim)
    assert_exact_atomic_claim(
        claimed_after_wrong_binding,
        wrong_binding_claim,
        label="post-reservation-mismatch",
    )

    durable_binding_mutations = (
        (
            "principal",
            "principal_id",
            f"agent:{backend}:atomic-mutated",
        ),
        (
            "route",
            "route_id",
            f"route:{backend}:atomic-mutated",
        ),
        (
            "credential",
            "credential_id",
            f"credential:{backend}:atomic-mutated",
        ),
        (
            "credential-version",
            "credential_version",
            int(binding["credential_version"]) + 1,
        ),
        (
            "policy",
            "policy_hash",
            _jit_authority_policy_hash(f"{backend}:atomic-mutated-policy"),
        ),
        (
            "request",
            "request_digest",
            _jit_authority_policy_hash(f"{backend}:atomic-mutated-request"),
        ),
        (
            "operation",
            "operation_digest",
            _jit_authority_policy_hash(f"{backend}:atomic-mutated-operation"),
        ),
        (
            "operation-context",
            "operation_context",
            {"operation": "test.substituted", "account": "acct:test"},
        ),
        (
            "request-authority",
            "request_authority_sha256",
            _jit_authority_policy_hash(
                f"{backend}:atomic-mutated-request-authority"
            ),
        ),
        ("quota", "quota_claims", []),
    )
    for label, field, mutated_value in durable_binding_mutations:
        _, exact_claim = atomic_claim_fixture(f"binding-{label}")
        mutated_claim = {**exact_claim, field: mutated_value}
        assert_raises(
            db.ReleaseAuthorizationConflictError,
            lambda claim=mutated_claim: claim_atomic(claim),
            f"non-JIT atomic credential authority accepted a mutated {label}",
        )
        exact_result = claim_atomic(exact_claim)
        assert_exact_atomic_claim(
            exact_result,
            exact_claim,
            label=f"{label}-binding",
        )
        assert_raises(
            db.ReleaseAuthorizationConflictError,
            lambda claim=exact_claim: claim_atomic(claim),
            f"non-JIT atomic {label} fixture remained usable after issuance",
        )

    issuance_binding_fields = (
        ("request-binding", "request_binding_sha256"),
        ("request-authority", "request_authority_sha256"),
        ("recipient-key", "recipient_key_id"),
        ("recipient-nonce", "recipient_nonce_sha256"),
    )
    for label, field in issuance_binding_fields:
        _, exact_claim = atomic_claim_fixture(f"issuance-{label}")
        exact_result = claim_atomic(exact_claim)
        assert_exact_atomic_claim(
            exact_result,
            exact_claim,
            label=f"{label}-issuance",
        )
        mutated_claim = {
            **exact_claim,
            field: _jit_authority_policy_hash(
                f"{backend}:atomic-mutated-{label}"
            ),
        }
        assert_raises(
            db.ReleaseAuthorizationConflictError,
            lambda claim=mutated_claim: claim_atomic(claim),
            f"non-JIT atomic issuance allowed a second {label} binding",
        )

    def decision_bound_claim_fixture(
        label: str,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        attempt_id = _jit_authority_policy_hash(
            f"{backend}:decision-bound:{label}:attempt"
        )
        reservation = db.reserve_release_authorization(
            **release_reserve_kwargs(
                binding,
                attempt_id=attempt_id,
                quotas=[],
                require_jit_grant=False,
            )
        )
        if reservation.get("state") != "reserved":
            raise AssertionError(
                f"{backend} decision-bound reservation failed: {reservation}"
            )
        claim = {
            "release_kind": "decisionBound",
            "attempt_id": attempt_id,
            "reservation_id": db.release_reservation_id(
                attempt_id,
                reservation["binding_digest"],
            ),
            "binding_digest": reservation["binding_digest"],
            "request_digest": binding["request_digest"],
            "operation_digest": binding["operation_digest"],
            "operation_context": operation_context,
            "quota_claims": [],
            "request_binding_sha256": _jit_authority_policy_hash(
                f"{backend}:decision-bound:{label}:request"
            ),
            "recipient_key_id": _jit_authority_policy_hash(
                f"{backend}:decision-bound:{label}:recipient"
            ),
            "recipient_nonce_sha256": _jit_authority_policy_hash(
                f"{backend}:decision-bound:{label}:nonce"
            ),
            "principal_id": binding["principal_id"],
            "route_id": binding["route_id"],
            "credential_id": binding["credential_id"],
            "credential_version": binding["credential_version"],
            "policy_hash": binding["policy_hash"],
            "grant_id": None,
            "approval_request_id": None,
            "reservation_expires_at_epoch_ms": reservation[
                "reservation_expires_at_epoch_ms"
            ],
        }
        claim["request_authority_sha256"] = request_authority_sha256(
            claim
        )
        return reservation, claim

    _, concurrent_decision_claim = decision_bound_claim_fixture(
        "concurrent"
    )
    concurrent_barrier = threading.Barrier(2)

    def claim_decision_bound(recipient_marker: str) -> str:
        concurrent_barrier.wait(timeout=10)
        try:
            db.claim_release_credential_issuance(
                **{
                    **concurrent_decision_claim,
                    "request_binding_sha256": _jit_authority_policy_hash(
                        f"{backend}:decision-bound:concurrent:"
                        f"{recipient_marker}:request"
                    ),
                    "recipient_key_id": _jit_authority_policy_hash(
                        f"{backend}:decision-bound:concurrent:"
                        f"{recipient_marker}:recipient"
                    ),
                    "recipient_nonce_sha256": _jit_authority_policy_hash(
                        f"{backend}:decision-bound:concurrent:"
                        f"{recipient_marker}:nonce"
                    ),
                }
            )
        except (
            db.ReleaseAuthorizationConflictError,
            db.ReleaseAuthorizationError,
        ):
            return "conflict"
        return "issued"

    with ThreadPoolExecutor(max_workers=2) as executor:
        decision_futures = [
            executor.submit(
                claim_decision_bound,
                recipient_marker,
            )
            for recipient_marker in ("first", "second")
        ]
        decision_outcomes = sorted(
            future.result(timeout=20)
            for future in decision_futures
        )
    if decision_outcomes != ["conflict", "issued"]:
        raise AssertionError(
            f"{backend} concurrent decision-bound issuance was not "
            f"exactly-once: {decision_outcomes}"
        )
    with db.connect() as conn:
        decision_row = conn.execute(
            "SELECT release_kind, request_authority_sha256, COUNT(*) "
            "AS count FROM release_authorization_credential_issuances "
            "WHERE attempt_id = ? GROUP BY release_kind, "
            "request_authority_sha256",
            (concurrent_decision_claim["attempt_id"],),
        ).fetchone()
    if (
        decision_row is None
        or decision_row["release_kind"] != "decisionBound"
        or int(decision_row["count"]) != 1
        or decision_row["request_authority_sha256"]
        != concurrent_decision_claim["request_authority_sha256"]
    ):
        raise AssertionError(
            f"{backend} decision-bound issuance was not stored exactly: "
            f"{dict(decision_row) if decision_row is not None else None}"
        )

    legacy_reservation, legacy_claim = decision_bound_claim_fixture(
        "legacy-operation-context"
    )
    operation_context_json = json.dumps(
        legacy_claim["operation_context"],
        sort_keys=True,
        separators=(",", ":"),
    )
    operation_context_digest = (
        "sha256:"
        + hashlib.sha256(operation_context_json.encode("utf-8")).hexdigest()
    )
    with db.connect() as conn:
        conn.execute(
            "UPDATE release_authorization_attempts SET "
            "operation_context_json = ? WHERE attempt_id = ?",
            (
                json.dumps(
                    {"digest": operation_context_digest},
                    sort_keys=True,
                    separators=(",", ":"),
                ),
                legacy_claim["attempt_id"],
            ),
        )
    assert_raises(
        db.ReleaseAuthorizationError,
        lambda: db.release_credential_request_authority_snapshot(
            attempt_id=legacy_claim["attempt_id"],
            reservation_id=legacy_claim["reservation_id"],
            binding_digest=legacy_claim["binding_digest"],
            request_digest=legacy_claim["request_digest"],
            operation_digest=legacy_claim["operation_digest"],
            operation_context=legacy_claim["operation_context"],
            reservation_expires_at_epoch_ms=legacy_reservation[
                "reservation_expires_at_epoch_ms"
            ],
            principal_id=legacy_claim["principal_id"],
            route_id=legacy_claim["route_id"],
            credential_id=legacy_claim["credential_id"],
            credential_version=legacy_claim["credential_version"],
            policy_hash=legacy_claim["policy_hash"],
        ),
        "digest-only legacy operation context authorized credential lease v4",
    )

    expired_reservation, expired_claim = atomic_claim_fixture("expired")
    assert_raises(
        db.ReleaseAuthorizationError,
        lambda: claim_atomic(
            {
                **expired_claim,
                "now_epoch_ms": expired_reservation[
                    "reservation_expires_at_epoch_ms"
                ],
            }
        ),
        "expired non-JIT atomic credential authority remained usable",
    )


def exercise_atomic_release_authorization(db: Any, backend: str) -> None:
    writer = db.release_authorization_writer_status()
    if not writer.get("shared_transaction"):
        raise AssertionError(f"test stores cannot share an atomic writer: {writer}")

    mismatched_flow = release_reserve_kwargs(
        {
            "principal_id": f"agent:{backend}:mismatched-flow",
            "route_id": f"route:{backend}:mismatched-flow",
            "credential_id": "",
            "credential_version": 0,
            "policy_hash": "sha256:" + "a" * 64,
            "request_digest": "sha256:" + "b" * 64,
            "operation_digest": None,
        },
        attempt_id=f"attempt:{backend}:mismatched-flow",
        quotas=[],
        require_jit_grant=False,
    )
    mismatched_flow["flow_id"] = f"flow:{mismatched_flow['attempt_id']}"
    assert_raises(
        db.ReleaseAuthorizationError,
        lambda: db.reserve_release_authorization(**mismatched_flow),
        "atomic release reserve accepted a flow ID distinct from its attempt ID",
    )

    multi_credential = db.create_credential(
        name=f"{backend} atomic multi-grant credential",
        kind="bearer",
        secret=f"secret:{backend}:atomic-multi-grant",
        metadata={"test_fixture": f"{backend}-atomic-multi-grant"},
    )
    first_multi_binding = approved_release_binding(
        db,
        f"{backend}-atomic-multi-grant",
        credential=multi_credential,
    )
    second_multi_binding = approved_release_binding(
        db,
        f"{backend}-atomic-multi-grant",
        credential=multi_credential,
    )
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
    absent_attempt = f"attempt:{backend}:reserve-transport-failed"
    with db.connect() as conn:
        lifecycle_events_before_failed_completion = conn.execute(
            "SELECT COUNT(*) AS count FROM release_authorization_events "
            "WHERE attempt_id = ?",
            (cancel_kwargs["attempt_id"],),
        ).fetchone()
    absent_cleanup = db.cancel_release_authorization_if_present(
        attempt_id=absent_attempt,
        binding_digest="sha256:" + "e" * 64,
    )
    wrong_binding_cleanup = db.cancel_release_authorization_if_present(
        attempt_id=cancel_kwargs["attempt_id"],
        binding_digest="sha256:" + "e" * 64,
    )
    if (
        absent_cleanup.get("state") != "absent"
        or wrong_binding_cleanup.get("state") != "absent"
        or absent_cleanup.get("binding_digest") != "sha256:" + "e" * 64
        or wrong_binding_cleanup.get("binding_digest") != "sha256:" + "e" * 64
    ):
        raise AssertionError(
            "expected cancellation did not return an exact no-op for absent "
            f"or mismatched state: {absent_cleanup} {wrong_binding_cleanup}"
        )
    with db.connect() as conn:
        absent_attempt_row = conn.execute(
            "SELECT COUNT(*) AS count FROM release_authorization_attempts "
            "WHERE attempt_id = ?",
            (absent_attempt,),
        ).fetchone()
        preserved_attempt = conn.execute(
            "SELECT state, binding_digest FROM release_authorization_attempts "
            "WHERE attempt_id = ?",
            (cancel_kwargs["attempt_id"],),
        ).fetchone()
        preserved_grant = conn.execute(
            "SELECT state, uses_remaining, reserved_attempt_id FROM approval_grants "
            "WHERE id = ?",
            (reserved["grant_id"],),
        ).fetchone()
        preserved_quotas = conn.execute(
            "SELECT counter_key, reservation_state "
            "FROM release_authorization_quota_reservations "
            "WHERE attempt_id = ? ORDER BY counter_key",
            (cancel_kwargs["attempt_id"],),
        ).fetchall()
        lifecycle_events_after_failed_completion = conn.execute(
            "SELECT COUNT(*) AS count FROM release_authorization_events "
            "WHERE attempt_id = ?",
            (cancel_kwargs["attempt_id"],),
        ).fetchone()
    if (
        int(absent_attempt_row["count"]) != 0
        or preserved_attempt["state"] != "reserved"
        or preserved_attempt["binding_digest"] != reserved["binding_digest"]
        or preserved_grant["state"] != "active"
        or int(preserved_grant["uses_remaining"]) != 1
        or preserved_grant["reserved_attempt_id"] != cancel_kwargs["attempt_id"]
        or len(preserved_quotas) != len(cancel_quotas)
        or any(row["reservation_state"] != "reserved" for row in preserved_quotas)
        or any(counter_count(db, item["counter_key"]) != 1 for item in cancel_quotas)
        or int(lifecycle_events_after_failed_completion["count"])
        != int(lifecycle_events_before_failed_completion["count"])
    ):
        raise AssertionError(
            "absent or incorrectly bound cancellation mutated unrelated "
            f"reservation state: {preserved_attempt} {preserved_grant} "
            f"{preserved_quotas}"
        )
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
    cancelled = db.cancel_release_authorization_if_present(
        attempt_id=cancel_kwargs["attempt_id"],
        binding_digest=reserved["binding_digest"],
        actor_id="spiffe://test.catchplate/decision-gate/atomic",
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
        actor_id="spiffe://test.catchplate/decision-gate/atomic",
    )
    committed = db.complete_release_authorization(
        attempt_id=commit_attempt,
        binding_digest=committed_reservation["binding_digest"],
        outcome="forwarded",
        actor_id="spiffe://test.catchplate/decision-gate/atomic",
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

    calendar_binding = approved_release_binding(db, f"{backend}-calendar-boundary")
    calendar_quota = calendar_quota_claim(
        f"{backend}-calendar-boundary",
        calendar_window="utcDay",
        maximum=2,
    )
    calendar_end_ms = int(
        datetime(2025, 1, 2, tzinfo=timezone.utc).timestamp() * 1000
    )
    calendar_attempt = f"attempt:{backend}:calendar-boundary"
    calendar_reservation = db.reserve_release_authorization(
        **{
            **release_reserve_kwargs(
                calendar_binding,
                attempt_id=calendar_attempt,
                quotas=[calendar_quota],
                require_jit_grant=False,
                now_epoch_ms=calendar_end_ms - 500,
            ),
            "reservation_ttl_seconds": 5,
        }
    )
    calendar_result_quota = calendar_reservation.get("quotas", [None])[0]
    if (
        calendar_reservation.get("state") != "reserved"
        or calendar_reservation.get("reservation_expires_at_epoch_ms")
        != calendar_end_ms
        or calendar_result_quota is None
        or calendar_result_quota.get("window_kind") != "utcDay"
        or calendar_result_quota.get("window_end_epoch_ms") != calendar_end_ms
    ):
        raise AssertionError(
            "calendar reservation was not capped at its authoritative boundary: "
            f"{calendar_reservation}"
        )
    boundary_dispatch = db.dispatch_release_authorization(
        attempt_id=calendar_attempt,
        binding_digest=calendar_reservation["binding_digest"],
        dispatch_ttl_seconds=5,
        now_epoch_ms=calendar_end_ms,
    )
    if (
        boundary_dispatch.get("state") != "cancelled"
        or boundary_dispatch.get("authorized") is not False
        or counter_count(db, calendar_quota["counter_key"]) != 0
        or boundary_dispatch.get("quotas", [{}])[0].get("reservation_state")
        != "refunded"
    ):
        raise AssertionError(
            "calendar dispatch at the boundary was not cancelled and refunded: "
            f"{boundary_dispatch}"
        )

    fixed_boundary_binding = approved_release_binding(
        db, f"{backend}-fixed-boundary"
    )
    fixed_boundary_quota = quota_claim(
        f"{backend}-fixed-boundary", maximum=2
    )
    fixed_boundary_quota["window_seconds"] = 1
    fixed_boundary_now = calendar_end_ms + 10_000
    fixed_boundary_kwargs = {
        **release_reserve_kwargs(
            fixed_boundary_binding,
            attempt_id=f"attempt:{backend}:fixed-boundary",
            quotas=[fixed_boundary_quota],
            require_jit_grant=False,
            now_epoch_ms=fixed_boundary_now,
        ),
        "reservation_ttl_seconds": 5,
    }
    fixed_boundary_reservation = db.reserve_release_authorization(
        **fixed_boundary_kwargs
    )
    if (
        fixed_boundary_reservation.get("state") != "reserved"
        or fixed_boundary_reservation.get("reservation_expires_at_epoch_ms")
        != fixed_boundary_now + 1_000
    ):
        raise AssertionError(
            "fixed reservation was not capped at its counted window: "
            f"{fixed_boundary_reservation}"
        )
    fixed_boundary_dispatch = db.dispatch_release_authorization(
        attempt_id=fixed_boundary_kwargs["attempt_id"],
        binding_digest=fixed_boundary_reservation["binding_digest"],
        dispatch_ttl_seconds=5,
        now_epoch_ms=fixed_boundary_now + 1_000,
    )
    if (
        fixed_boundary_dispatch.get("state") != "cancelled"
        or fixed_boundary_dispatch.get("authorized") is not False
        or counter_count(db, fixed_boundary_quota["counter_key"]) != 0
    ):
        raise AssertionError(
            "fixed-window dispatch at the boundary was not cancelled and refunded: "
            f"{fixed_boundary_dispatch}"
        )

    replay_binding = approved_release_binding(db, f"{backend}-expired-replay")
    replay_quota = quota_claim(f"{backend}-expired-replay", maximum=2)
    replay_quota["window_seconds"] = 1
    replay_now = fixed_boundary_now + 20_000
    replay_kwargs = {
        **release_reserve_kwargs(
            replay_binding,
            attempt_id=f"attempt:{backend}:expired-replay",
            quotas=[replay_quota],
            require_jit_grant=False,
            now_epoch_ms=replay_now,
        ),
        "reservation_ttl_seconds": 5,
    }
    replay_reservation = db.reserve_release_authorization(**replay_kwargs)
    expired_replay = db.reserve_release_authorization(
        **{**replay_kwargs, "now_epoch_ms": replay_now + 1_000}
    )
    if (
        replay_reservation.get("state") != "reserved"
        or expired_replay.get("state") != "cancelled"
        or expired_replay.get("authorized") is not False
        or expired_replay.get("reason") != "reservation_ttl_expired"
        or not expired_replay.get("idempotent_replay")
        or counter_count(db, replay_quota["counter_key"]) != 0
    ):
        raise AssertionError(
            f"expired idempotent reservation replay remained authorized: {expired_replay}"
        )

    duration_binding = approved_release_binding(db, f"{backend}-atomic-duration")
    duration_quota = quota_claim(f"{backend}-atomic-duration")
    duration_now = replay_now + 20_000
    duration_reservation = db.reserve_release_authorization(
        **release_reserve_kwargs(
            duration_binding,
            attempt_id=f"attempt:{backend}:atomic-duration:first",
            quotas=[duration_quota],
            require_jit_grant=False,
            now_epoch_ms=duration_now,
        )
    )
    extended_quota = {**duration_quota, "window_seconds": 120}
    extended_reservation = db.reserve_release_authorization(
        **release_reserve_kwargs(
            duration_binding,
            attempt_id=f"attempt:{backend}:atomic-duration:second",
            quotas=[extended_quota],
            require_jit_grant=False,
            now_epoch_ms=duration_now + 1_000,
        )
    )
    if (
        duration_reservation.get("state") != "reserved"
        or extended_reservation.get("state") != "denied"
        or extended_reservation.get("reason") != "shared_quota_denied"
        or counter_count(db, duration_quota["counter_key"]) != 1
    ):
        raise AssertionError(
            "atomic fixed duration change reset the accumulated count: "
            f"{duration_reservation} {extended_reservation}"
        )
    db.complete_release_authorization(
        attempt_id=duration_reservation["attempt_id"],
        binding_digest=duration_reservation["binding_digest"],
        outcome="not_forwarded",
        now_epoch_ms=duration_now + 2_000,
    )

    rollback_binding = approved_release_binding(db, f"{backend}-calendar-rollback")
    rollback_quota = calendar_quota_claim(
        f"{backend}-calendar-rollback", calendar_window="utcDay", maximum=2
    )
    rollback_attempt = f"attempt:{backend}:calendar-rollback"
    rollback_reservation = db.reserve_release_authorization(
        **release_reserve_kwargs(
            rollback_binding,
            attempt_id=rollback_attempt,
            quotas=[rollback_quota],
            require_jit_grant=False,
            now_epoch_ms=calendar_end_ms - 500,
        )
    )
    advanced_after_boundary = db.consume_rate_limit(
        counter_key=rollback_quota["counter_key"],
        principal_id=rollback_binding["principal_id"],
        route_id=rollback_binding["route_id"],
        credential_id=rollback_binding["credential_id"],
        credential_version=rollback_binding["credential_version"],
        policy_hash=rollback_binding["policy_hash"],
        constraint_id=rollback_quota["constraint_id"],
        operation=rollback_quota["operation"],
        calendar_window="utcDay",
        max_count=2,
        now_epoch_ms=calendar_end_ms,
        audit=False,
    )
    rollback_dispatch = db.dispatch_release_authorization(
        attempt_id=rollback_attempt,
        binding_digest=rollback_reservation["binding_digest"],
        dispatch_ttl_seconds=5,
        now_epoch_ms=calendar_end_ms - 250,
    )
    if (
        not advanced_after_boundary.get("allowed")
        or rollback_dispatch.get("state") != "cancelled"
        or rollback_dispatch.get("reason") != "shared_quota_window_changed"
        or rollback_dispatch.get("quotas", [{}])[0].get("reservation_state")
        != "refund_skipped_window"
        or counter_count(db, rollback_quota["counter_key"]) != 1
    ):
        raise AssertionError(
            "clock rollback revived a reservation from an advanced calendar window: "
            f"{advanced_after_boundary} {rollback_dispatch}"
        )

    refund_binding = approved_release_binding(db, f"{backend}-calendar-refund")
    refund_quota = calendar_quota_claim(
        f"{backend}-calendar-refund",
        calendar_window="utcDay",
        maximum=2,
    )
    refund_attempt = f"attempt:{backend}:calendar-refund"
    refund_reservation = db.reserve_release_authorization(
        **release_reserve_kwargs(
            refund_binding,
            attempt_id=refund_attempt,
            quotas=[refund_quota],
            require_jit_grant=False,
            now_epoch_ms=calendar_end_ms - 500,
        )
    )
    advanced = db.consume_rate_limit(
        counter_key=refund_quota["counter_key"],
        principal_id=refund_binding["principal_id"],
        route_id=refund_binding["route_id"],
        credential_id=refund_binding["credential_id"],
        credential_version=refund_binding["credential_version"],
        policy_hash=refund_binding["policy_hash"],
        constraint_id=refund_quota["constraint_id"],
        operation=refund_quota["operation"],
        calendar_window="utcDay",
        max_count=2,
        now_epoch_ms=calendar_end_ms,
        audit=False,
    )
    skipped_refund = db.complete_release_authorization(
        attempt_id=refund_attempt,
        binding_digest=refund_reservation["binding_digest"],
        outcome="not_forwarded",
        now_epoch_ms=calendar_end_ms + 1,
    )
    if (
        not advanced.get("allowed")
        or counter_count(db, refund_quota["counter_key"]) != 1
        or skipped_refund.get("quotas", [{}])[0].get("reservation_state")
        != "refund_skipped_window"
    ):
        raise AssertionError(
            "calendar refund crossed into a different stored window: "
            f"{advanced} {skipped_refund}"
        )

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
            "SELECT state, binding_digest, binding_json, operation_context_json "
            "FROM release_authorization_attempts "
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
    retained_operation_context = json.loads(durable["operation_context_json"])
    recovered_operation_context_json, recovered_operation_context_digest = (
        db._recover_release_operation_context_json(
            durable["operation_context_json"]
        )
    )
    expected_operation_context_json = json.dumps(
        {"operation": "test.forward", "account": "acct:test"},
        sort_keys=True,
        separators=(",", ":"),
    )
    if (
        set(retained_operation_context)
        != {"apiVersion", "ciphertext", "digest"}
        or recovered_operation_context_json
        != expected_operation_context_json
        or recovered_operation_context_digest
        != retained_operation_context["digest"]
        or "test.forward" in durable["operation_context_json"]
        or "acct:test" in durable["operation_context_json"]
    ):
        raise AssertionError(
            "release state did not persist a protected recoverable operation context"
        )
    retained_binding = json.loads(durable["binding_json"])
    if retained_binding != {"digest": durable["binding_digest"]}:
        raise AssertionError("release state persisted raw authorization binding")
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
    with db.connect() as conn:
        conn.execute(
            "UPDATE release_authorization_attempts SET binding_json = ?, "
            "operation_context_json = ? WHERE attempt_id = ?",
            (
                json.dumps({"operation_context": {"reset_token": "legacy-secret"}}),
                json.dumps({"reset_token": "legacy-secret"}),
                commit_attempt,
            ),
        )
    db.init_db()
    with db.connect() as conn:
        migrated = conn.execute(
            "SELECT binding_digest, binding_json, operation_context_json "
            "FROM release_authorization_attempts WHERE attempt_id = ?",
            (commit_attempt,),
        ).fetchone()
    migrated_operation_storage = json.loads(
        migrated["operation_context_json"]
    )
    migrated_operation_json, migrated_operation_digest = (
        db._recover_release_operation_context_json(
            migrated["operation_context_json"]
        )
    )
    if (
        json.loads(migrated["binding_json"])
        != {"digest": migrated["binding_digest"]}
        or set(migrated_operation_storage)
        != {"apiVersion", "ciphertext", "digest"}
        or json.loads(migrated_operation_json)
        != {"reset_token": "legacy-secret"}
        or migrated_operation_digest
        != migrated_operation_storage["digest"]
    ):
        raise AssertionError("legacy release authorization material was not migrated")
    if "legacy-secret" in migrated["binding_json"] + migrated["operation_context_json"]:
        raise AssertionError("legacy release authorization migration retained plaintext")


def exercise_control_plane_jit_approval(app_module: Any, db: Any, backend: str) -> None:
    principal_id = f"agent:{backend}:reserve-approval"
    route_id = f"route:{backend}:reserve-approval"
    credential = db.create_credential(
        name=f"{backend} control-plane JIT credential",
        kind="bearer",
        secret=f"secret:{backend}:reserve-approval",
        metadata={"test_fixture": f"{backend}-reserve-approval"},
    )
    credential_id = credential["id"]
    credential_version = int(credential["credential_version"])
    policy_hash = "sha256:" + hashlib.sha256(
        f"{backend}:reserve-approval:policy".encode("utf-8")
    ).hexdigest()
    advance_active_policy_hash(db, policy_hash)
    operation = {"account": "acct:test", "operation": "test.forward"}
    body_sha256 = "sha256:" + hashlib.sha256(b'{"safe":true}').hexdigest()
    canonical = {
        "v": 1,
        "principal": principal_id,
        "client_ip": "192.0.2.10",
        "route_id": route_id,
        "credential_ref": credential_id,
        "credential_version": str(credential_version),
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
        canonical_request: dict[str, Any] = canonical,
        request_digest: str | None = None,
        submitted_operation_digest: str | None = None,
    ) -> dict[str, Any]:
        return {
            "apiVersion": "catchplate.releaseAuthorizationReserve/v1",
            "attemptId": attempt_id,
            "flowId": attempt_id,
            "principalId": principal_id,
            "routeId": route_id,
            "credentialRef": credential_id,
            "credentialVersion": credential_version,
            "policyHash": policy_hash,
            "requestDigest": request_digest or digest(canonical_request),
            "operationDigest": submitted_operation_digest
            or operation_digest(canonical_request),
            "operationContext": operation,
            "canonicalRequest": canonical_request,
        }

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
        adapter_config={
            "request": {
                "allowedHeaders": ["accept"],
                "allowedMediaTypes": [],
                "allowedQueryKeys": [],
                "bodyMode": "none",
                "maxBodyBytes": 0,
                "discardHeaders": [],
                "requiredHeaders": {},
            }
        },
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
    snapshot = SimpleNamespace(
        hash=policy_hash,
        principals={
            principal_id: SimpleNamespace(required_headers={}),
        },
        credentials={
            credential_id: SimpleNamespace(injection={"type": "bearer"}),
        },
        routes=(route,),
    )

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
            side_effect=AssertionError(
                "control-plane reserve read a dispatch-secret credential"
            ),
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
        missing_canonical = reserve_payload(
            f"attempt:{backend}:missing-canonical"
        )
        missing_canonical.pop("canonicalRequest")
        try:
            app_module.DataPlaneReleaseAuthorizationReserve.model_validate(
                missing_canonical
            )
        except app_module.ValidationError:
            pass
        else:
            raise AssertionError(
                "reserve request model accepted a missing canonicalRequest"
            )
        mismatched_flow = reserve_payload(f"attempt:{backend}:mismatched-flow")
        mismatched_flow["flowId"] = f"flow:{mismatched_flow['attemptId']}"
        try:
            app_module.DataPlaneReleaseAuthorizationReserve.model_validate(
                mismatched_flow
            )
        except app_module.ValidationError:
            pass
        else:
            raise AssertionError(
                "reserve request model accepted a flow ID distinct from its attempt ID"
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
    with db.connect() as conn:
        stored_approval = conn.execute(
            "SELECT url, canonical_request, redacted_display FROM approval_requests WHERE id = ?",
            (approval_id,),
        ).fetchone()
    encrypted_canonical = str(stored_approval["canonical_request"] or "")
    encrypted_display = str(stored_approval["redacted_display"] or "")
    if (
        not encrypted_canonical.startswith("v2:")
        or not encrypted_display.startswith("v2:")
        or not re.fullmatch(r"sha256:[0-9a-f]{64}", str(stored_approval["url"] or ""))
        or "must-not-be-presented" in encrypted_canonical
        or "actual/request" in encrypted_display
    ):
        raise AssertionError("approval review material was not encrypted at rest")
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
        oauth_client_id="x-client",
        scopes=scopes,
        injection={
            "type": "bearer",
            "header": "Authorization",
            "field": "access_token",
            "prefix": "Bearer ",
        },
    )

    def route_for(candidate_policy: Any) -> Any:
        return SimpleNamespace(
            adapter_type="x.v2",
            adapter_config={
                "appIds": [candidate_policy.oauth_client_id],
                "credentialBinding": {
                    "credentialType": "oauth2",
                    "provider": candidate_policy.provider,
                    "subjects": [candidate_policy.provider_subject],
                    "clientIds": [candidate_policy.oauth_client_id],
                    "requiredScopes": list(scopes),
                },
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
            "account_subject": "subject-123",
            "oauth_client_id": "x-client",
            "scopes": list(reversed(scopes)),
        },
    }
    if (
        policy_engine._credential_policy_binding_decision(
            route_for(policy), policy, credential, "post.create"
        )
        is not None
    ):
        raise AssertionError("proxy binding rejected lease-equivalent provider aliases or scope order")

    mismatches = (
        (
            credential_policy_type(
                id=policy.id,
                provider="x",
                provider_subject="different-subject",
                oauth_client_id="x-client",
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
                oauth_client_id="x-client",
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
            route_for(candidate_policy),
            candidate_policy,
            candidate_credential,
            "post.create",
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
    malformed_decision = policy_engine._credential_policy_binding_decision(
        route_for(policy), policy, malformed, "post.create"
    )
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
        "metadata": {
            "provider": "stripe",
            "provider_subject": "stripe-account",
            "secret_class": "customHeader",
            "scope": "charges.write",
            "injection_name": "X-Api-Key",
        },
    }
    service_policy = credential_policy_type(
        id=service_policy.id,
        provider=service_policy.provider,
        provider_subject="stripe-account",
        scopes=service_policy.scopes,
        injection=service_policy.injection,
    )
    service_route = SimpleNamespace(
        adapter_type="generic.rest",
        adapter_config={
            "credentialBinding": {
                "credentialType": "static",
                "provider": "stripe",
                "subjects": ["stripe-account"],
                "secretClass": "customHeader",
            }
        },
    )
    if (
        policy_engine._credential_policy_binding_decision(
            service_route, service_policy, service_credential, "charge.create"
        )
        is not None
    ):
        raise AssertionError("proxy rejected a non-OAuth credential within its signed scope binding")
    expanded = {
        **service_credential,
        "metadata": {"provider": "stripe", "scope": "charges.write refunds.write"},
    }
    expanded_decision = policy_engine._credential_policy_binding_decision(
        service_route, service_policy, expanded, "charge.create"
    )
    if expanded_decision is None or expanded_decision.status_code != 409:
        raise AssertionError("proxy allowed stored non-OAuth scopes to exceed signed policy")
    duplicate_static_scopes = {
        **service_credential,
        "metadata": {
            **service_credential["metadata"],
            "scopes": ["charges.write", "charges.write"],
        },
    }
    duplicate_static_decision = policy_engine._credential_policy_binding_decision(
        service_route,
        service_policy,
        duplicate_static_scopes,
        "charge.create",
    )
    if (
        duplicate_static_decision is None
        or duplicate_static_decision.status_code != 503
        or duplicate_static_decision.payload.get("error")
        != "credential_policy_binding_invalid"
    ):
        raise AssertionError(
            "proxy did not classify malformed static scopes as invalid"
        )


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
            "X-Catchplate-Data-Plane-Token": "service-secret",
            "X-Catchplate-Debug-Only": "mutable-outside-digest",
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
                "allowedMediaTypes": [],
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
    if any(str(name).lower().startswith("x-catchplate-") for name in request.headers):
        raise AssertionError(f"internal headers survived upstream stripping: {request.headers}")

    bundle = demo_policy_bundle()
    generic_route = next(
        route for route in bundle["routes"] if route["adapter"]["type"] == "generic.rest"
    )
    generic_route["adapter"]["config"]["request"]["allowedHeaders"].append(
        "X-Catchplate-Debug-Only"
    )
    try:
        compile_policy_bundle(bundle, validate_schema=False)
    except policy_bundle_error as exc:
        if "credential or internal headers" not in str(exc):
            raise AssertionError(f"internal allowedHeaders failed for the wrong reason: {exc}") from exc
    else:
        raise AssertionError("generic allowedHeaders accepted an internal Catchplate header")


def exercise_physical_header_preflight(policy_engine: Any) -> None:
    from mitmproxy import http as mitm_http

    headers = mitm_http.Headers(
        fields=[
            (b"Host", b"upstream.invalid"),
            (b"Npm-Session", b"first-physical-value"),
            (b"npm-session", b"second-physical-value"),
        ]
    )
    flow = SimpleNamespace(
        request=SimpleNamespace(
            method="PUT",
            pretty_url=(
                "https://upstream.invalid/integration"
                "?caller-chosen-secret-key=caller-secret-must-not-enter-audit"
            ),
            headers=headers,
            raw_content=b"",
        ),
        client_conn=SimpleNamespace(peername=("127.0.0.1", 43125)),
        metadata={},
    )
    audit_records: list[dict[str, Any]] = []

    def capture_audit(*args: Any, **kwargs: Any) -> None:
        audit_records.append({"args": args, "kwargs": kwargs})

    with (
        patch.object(
            policy_engine.runtime,
            "prune_expired_caches",
            side_effect=AssertionError(
                "duplicate physical headers reached runtime maintenance"
            ),
        ),
        patch.object(
            policy_engine.runtime,
            "log_request",
            side_effect=capture_audit,
        ),
        patch.object(
            policy_engine,
            "get_policy_snapshot",
            side_effect=AssertionError(
                "duplicate physical headers reached policy authorization"
            ),
        ),
    ):
        result = policy_engine.evaluate_request(flow)
    if (
        result.decision.allowed
        or result.decision.status_code != 400
        or result.decision.payload.get("error") != "invalid_forwarding_headers"
        or "repeats header npm-session"
        not in result.decision.payload.get("detail", "")
    ):
        raise AssertionError(
            f"duplicate physical headers did not fail at preflight: {result.decision}"
        )
    if len(audit_records) != 1:
        raise AssertionError(
            f"physical-header preflight emitted unexpected audit work: {audit_records}"
        )
    audit_url = audit_records[0]["args"][2]
    if "?" in audit_url or "caller-chosen-secret-key" in audit_url or "caller-secret" in audit_url:
        raise AssertionError(
            f"pre-policy duplicate-header audit retained caller query material: {audit_records}"
        )

    for invalid_target in (
        "HTTPS://upstream.invalid/resource?value=ok",
        "https://UPSTREAM.invalid/resource?value=ok",
        "https://upstream.invalid:0443/resource?value=ok",
        "https://upstream.invalid/resource?value=raw+plus",
        "https://upstream.invalid/resource?value=%zz",
        "https://upstream.invalid/resource?value=%252B",
        "https://upstream.invalid/resource?value=%C0%AF",
        "https://user@upstream.invalid/resource",
        "https://upstream.invalid/resource#fragment",
        "https://upstream.invalid\\attacker/resource",
        "https://upstream.invalid/résumé",
        "https://upstream.invalid/resource?value="
        + "x" * (64 * 1024),
    ):
        invalid_flow = SimpleNamespace(
            request=SimpleNamespace(
                method="GET",
                pretty_url=invalid_target,
                headers={},
                raw_content=b"",
            ),
            client_conn=SimpleNamespace(peername=("127.0.0.1", 43125)),
            metadata={},
        )
        with (
            patch.object(
                policy_engine,
                "get_policy_snapshot",
                side_effect=AssertionError(
                    "invalid raw target reached policy snapshot acquisition"
                ),
            ),
            patch.object(
                policy_engine.runtime,
                "log_request",
                side_effect=AssertionError(
                    "invalid raw target reached audit emission"
                ),
            ),
            patch.object(
                policy_engine.runtime,
                "get_credential_generation",
                side_effect=AssertionError(
                    "invalid raw target reached credential metadata"
                ),
            ),
        ):
            invalid_result = policy_engine.evaluate_request(invalid_flow)
        if (
            invalid_result.decision.allowed
            or invalid_result.decision.status_code != 400
            or invalid_result.decision.payload
            != {"error": "invalid_request_target"}
            or invalid_flow.metadata
        ):
            raise AssertionError(
                "invalid raw target was not rejected with a fixed pre-policy "
                f"error: {invalid_target!r} {invalid_result.decision}"
            )


def _run_proxy_transaction(
    policy_engine: Any,
    credential_policy_type: Any,
    *,
    credential_policy: Any = None,
    credential: dict[str, Any] | None = None,
    jit_required: bool = True,
    reserve_result: Any = None,
    replace_reserve_result: bool = False,
    credential_read_error: BaseException | None = None,
    audit_error: BaseException | None = None,
    rewrite_allowed: bool = True,
    rewrite_error: BaseException | None = None,
    rewrite_mutation: Any = None,
    dispatch_result: dict[str, Any] | BaseException | None = None,
    complete_result: dict[str, Any] | BaseException | None = None,
    followup: str | None = None,
    request_url: str = "https://upstream.invalid/resource",
    allowed_query_keys: tuple[str, ...] = (),
    rate_store: str = "shared",
    atomic_enabled: bool = True,
    route_constraints: tuple[dict[str, Any], ...] | None = None,
    operation_fields: dict[str, str] | None = None,
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
        principals=(principal.id,),
        scheme="https",
        host="upstream.invalid",
        port=443,
        methods=frozenset({"POST"}),
        match_path=lambda path: {} if path == "/resource" else None,
        credential_ref=credential_policy.id,
        adapter_type="generic.rest",
        adapter_config={
            "request": {
                "allowedHeaders": ["accept"],
                "allowedMediaTypes": [],
                "allowedQueryKeys": list(allowed_query_keys),
                "bodyMode": "none",
                "maxBodyBytes": 0,
                "discardHeaders": [],
                "requiredHeaders": {},
            }
        },
        constraints=(
            route_constraints
            if route_constraints is not None
            else (
                {
                    "id": "shared-quota",
                    "type": "rateLimit",
                    "store": rate_store,
                    "max": 1,
                    "windowSeconds": 60,
                    "key": {
                        "scope": [
                            "principal",
                            "credential",
                            "route",
                            "operation",
                        ]
                    },
                },
            )
        ),
        jit={"required": jit_required},
    )

    class Adapter:
        def validate_credential_metadata(
            self,
            _route: Any,
            _metadata: Any,
        ) -> Any:
            events.append("validate_credential_metadata")
            return policy_engine.PolicyDecision(True)

        def validate_credential(self, _route: Any, _credential: Any) -> Any:
            events.append("validate_credential")
            return policy_engine.PolicyDecision(True)

        def validate_request(self, _flow: Any, _route: Any, _params: Any) -> Any:
            events.append("validate_request")
            return policy_engine.PolicyDecision(True)

        def operation_fields(self, _flow: Any, _route: Any, _params: Any) -> dict[str, str]:
            events.append("operation_fields")
            return dict(
                operation_fields
                if operation_fields is not None
                else {"operation": "test.forward"}
            )

        def rewrite_request(self, _flow: Any, _route: Any, _params: Any) -> Any:
            events.append("rewrite")
            if rewrite_error is not None:
                raise rewrite_error
            if rewrite_mutation is not None:
                rewrite_mutation(_flow)
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

    def match_route(
        scheme: str,
        host: str,
        port: int,
        method: str,
        path: str,
        principal_id: str,
    ) -> Any:
        if (
            scheme == route.scheme
            and host == route.host
            and port == route.port
            and method in route.methods
            and principal_id in route.principals
            and route.match_path(path) is not None
        ):
            return SimpleNamespace(route=route, params={})
        return None

    snapshot = SimpleNamespace(
        hash="sha256:" + "f" * 64,
        credentials={credential_policy.id: credential_policy},
        identify_principal=lambda _ip, _headers: principal,
        match_route=match_route,
    )
    request = SimpleNamespace(
        method="POST",
        pretty_url=request_url,
        headers={"accept": "application/json", "X-Catchplate-Debug-Only": "strip-me"},
        raw_content=b"",
    )
    request.get_content = lambda strict=True: request.raw_content

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

    request.query = MutableQuery(
        parse_qsl(
            urlsplit(request.pretty_url).query,
            keep_blank_values=True,
        )
    )
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
        elif (
            rate_store == "shared"
            and kwargs.get("rate_limits_only")
            and kwargs.get("skip_shared_rate_limits")
        ):
            events.append(
                "shared_commit_bypassed"
                if kwargs.get("consume_rate_limits")
                else "shared_preview_bypassed"
            )
        elif rate_store == "local" and kwargs.get("rate_limits_only"):
            events.append(
                "local_commit_non_refundable"
                if kwargs.get("consume_rate_limits")
                else "local_preview"
            )
        else:
            events.append("legacy_quota_call")
        return policy_engine.PolicyDecision(True)

    def credential_generation(_credential_id: str | None) -> dict[str, Any]:
        events.append("credential_generation")
        return {
            key: value
            for key, value in credential.items()
            if key != "secret"
        }

    def credential_read(
        _credential_id: str | None,
        **authority: Any,
    ) -> dict[str, Any]:
        events.append("credential_read")
        flow.metadata["observed_credential_authority"] = authority
        if credential_read_error is not None:
            raise credential_read_error
        return credential

    def reserve(**kwargs: Any) -> dict[str, Any]:
        events.append("reserve")
        guard = kwargs["guard"]
        expected = guard.expected
        flow.metadata["observed_reserve_canonical_request"] = json.loads(
            json.dumps(kwargs["canonical_request"])
        )
        if isinstance(reserve_result, BaseException):
            raise reserve_result
        if replace_reserve_result:
            return reserve_result
        now_ms = int(time.time() * 1000)
        quotas = []
        for claim in kwargs["shared_quotas"]:
            window_kind = claim["window_kind"]
            if window_kind != "fixed":
                raise AssertionError(f"proxy fixture does not support {window_kind}")
            window_start = now_ms
            window_end = window_start + int(claim["window_seconds"]) * 1000
            quotas.append(
                {
                    "counter_key": claim["counter_key"],
                    "constraint_id": claim["constraint_id"],
                    "operation": claim["operation"],
                    "window_kind": window_kind,
                    "window_seconds": claim["window_seconds"],
                    "calendar_window": None,
                    "window_start_epoch_ms": window_start,
                    "window_end_epoch_ms": window_end,
                    "max": claim["max_count"],
                    "count": 1,
                    "remaining": claim["max_count"] - 1,
                    "reservation_state": "reserved",
                }
            )
        result = {
            "authorized": True,
            "state": "reserved",
            "reason": "reserved",
            "attempt_id": expected.attempt_id,
            "binding_digest": expected.binding_digest,
            "idempotent_replay": False,
            "grant_id": "grant:exact:test" if jit_required else None,
            "approval_request_id": "approval:exact:test" if jit_required else None,
            "approval_status": None,
            "approval_expires_at": None,
            "approval_created": None,
            "reservation_expires_at_epoch_ms": now_ms + 55_000,
            "dispatch_started_at_epoch_ms": None,
            "dispatch_expires_at_epoch_ms": None,
            "completion_outcome": None,
            "retry_after_seconds": 0,
            "quotas": quotas,
        }
        durable_binding = guard.durable_policy
        if durable_binding is not None:
            flow.metadata["observed_durable_policy_claims"] = copy.deepcopy(
                kwargs.get("durable_policy_claims")
            )
            result.update(
                {
                    "api_version": "catchplate.releaseAuthorization/v2",
                    "durable_policy": {
                        "state": "reserved",
                        "attempt_id": expected.attempt_id,
                        "claim_digest": durable_binding["claimDigest"],
                        "reservation_id": durable_binding["reservationId"],
                        "actor_id": durable_binding["actorId"],
                        "reservation_deadline_at_epoch_ms": result[
                            "reservation_expires_at_epoch_ms"
                        ],
                        "dispatch_deadline_at_epoch_ms": None,
                        "response_evidence_digest": None,
                        "failure_reason": None,
                        "response_body_sha256": None,
                        "uncertainty": None,
                    },
                }
            )
        if isinstance(reserve_result, dict):
            result.update(reserve_result)
            if result.get("authorized") is False and "quotas" not in reserve_result:
                result["quotas"] = []
        if result.get("state") == "denied":
            guard.disarm_denial()
        elif result.get("state") == "reserved":
            guard.promote_reserved()
        return result

    def cancel_expected(
        expected: Any,
        *,
        durable_policy: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        events.append("complete:not_forwarded")
        flow.metadata["observed_cleanup_identity"] = expected
        lifecycle = flow.metadata.get("catchplate_release_authorization")
        if not isinstance(lifecycle, dict):
            return {
                "authorized": False,
                "state": "absent",
                "reason": "reservation_absent",
                "attempt_id": expected.attempt_id,
                "binding_digest": expected.binding_digest,
                "idempotent_replay": True,
                "grant_id": None,
                "approval_request_id": None,
                "approval_status": None,
                "approval_expires_at": None,
                "approval_created": None,
                "reservation_expires_at_epoch_ms": None,
                "dispatch_started_at_epoch_ms": None,
                "dispatch_expires_at_epoch_ms": None,
                "completion_outcome": None,
                "retry_after_seconds": 0,
                "quotas": [],
            }
        result = {
            "authorized": False,
            "state": "cancelled",
            "reason": "cancelled",
            "attempt_id": expected.attempt_id,
            "binding_digest": expected.binding_digest,
            "idempotent_replay": False,
            "grant_id": lifecycle.get("grant_id"),
            "approval_request_id": lifecycle.get("approval_request_id"),
            "approval_status": None,
            "approval_expires_at": None,
            "approval_created": None,
            "reservation_expires_at_epoch_ms": lifecycle[
                "reservation_expires_at_epoch_ms"
            ],
            "dispatch_started_at_epoch_ms": None,
            "dispatch_expires_at_epoch_ms": None,
            "completion_outcome": "not_forwarded",
            "retry_after_seconds": 0,
            "quotas": [
                {**item, "reservation_state": "refunded"}
                for item in lifecycle["quotas"]
            ],
        }
        if durable_policy is not None:
            result.update(
                {
                    "api_version": "catchplate.releaseAuthorization/v2",
                    "durable_policy": {
                        "state": "aborted",
                        "attempt_id": expected.attempt_id,
                        "claim_digest": durable_policy["claimDigest"],
                        "reservation_id": durable_policy["reservationId"],
                        "actor_id": durable_policy["actorId"],
                        "reservation_deadline_at_epoch_ms": result[
                            "reservation_expires_at_epoch_ms"
                        ],
                        "dispatch_deadline_at_epoch_ms": None,
                        "response_evidence_digest": None,
                        "failure_reason": None,
                        "response_body_sha256": None,
                        "uncertainty": None,
                    },
                }
            )
        return result

    def dispatch(**kwargs: Any) -> dict[str, Any]:
        events.append("dispatch")
        if isinstance(dispatch_result, BaseException):
            raise dispatch_result
        now_ms = int(time.time() * 1000)
        previous = kwargs["previous_lifecycle"]
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
            "reservation_expires_at_epoch_ms": previous[
                "reservation_expires_at_epoch_ms"
            ],
            "dispatch_started_at_epoch_ms": now_ms,
            "dispatch_expires_at_epoch_ms": now_ms + 30_000,
            "completion_outcome": None,
            "retry_after_seconds": 0,
            "quotas": [dict(item) for item in previous["quotas"]],
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
        previous = kwargs["previous_lifecycle"]
        previous_dispatch_started = previous.get("dispatch_started_at_epoch_ms")
        previous_dispatch_expires = previous.get("dispatch_expires_at_epoch_ms")
        if kwargs["outcome"] == "unknown" and previous_dispatch_started is None:
            previous_dispatch_started = now_ms
            previous_dispatch_expires = now_ms + 30_000
        reservation_state = "refunded" if expected == "cancelled" else "committed"
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
            "reservation_expires_at_epoch_ms": previous[
                "reservation_expires_at_epoch_ms"
            ],
            "dispatch_started_at_epoch_ms": previous_dispatch_started,
            "dispatch_expires_at_epoch_ms": previous_dispatch_expires,
            "completion_outcome": kwargs["outcome"],
            "retry_after_seconds": 0,
            "quotas": [
                {**item, "reservation_state": reservation_state}
                for item in previous["quotas"]
            ],
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
        if audit_error is not None and action == "allowed":
            raise audit_error
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
        stack.enter_context(
            patch.object(
                policy_engine.runtime,
                "atomic_release_authorization_enabled",
                return_value=atomic_enabled,
            )
        )
        stack.enter_context(patch.object(policy_engine.runtime, "get_credential_generation", side_effect=credential_generation))
        stack.enter_context(patch.object(policy_engine.runtime, "get_credential", side_effect=credential_read))
        stack.enter_context(patch.object(policy_engine.runtime, "reserve_expected_release_authorization", side_effect=reserve))
        stack.enter_context(patch.object(policy_engine.runtime, "cancel_expected_release_authorization", side_effect=cancel_expected))
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
            if followup_decision.allowed:
                policy_engine.mark_provider_dispatch_uncertain(flow)
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
    for label, jit_required, rate_store in (
        ("non-JIT shared quota", False, "shared"),
        ("JIT local quota", True, "local"),
    ):
        non_atomic, non_atomic_events, _, _ = _run_proxy_transaction(
            policy_engine,
            credential_policy_type,
            jit_required=jit_required,
            rate_store=rate_store,
            atomic_enabled=False,
        )
        if (
            non_atomic.decision.allowed
            or non_atomic.decision.payload.get("error")
            != "atomic_release_authorization_required"
            or "credential_read" in non_atomic_events
            or "reserve" in non_atomic_events
        ):
            raise AssertionError(
                f"{label} did not fail before secret access without atomic authority: "
                f"{non_atomic_events} {non_atomic.decision}"
            )

    local_compatibility, local_compatibility_events, local_compatibility_flow, _ = (
        _run_proxy_transaction(
            policy_engine,
            credential_policy_type,
            jit_required=False,
            rate_store="local",
            atomic_enabled=False,
        )
    )
    if (
        not local_compatibility.decision.allowed
        or "reserve" in local_compatibility_events
        or local_compatibility_events.count("local_commit_non_refundable") != 1
        or local_compatibility_flow.metadata.get(
            "catchplate_local_rate_limit_mode"
        )
        != "conservative_non_refundable"
    ):
        raise AssertionError(
            "local-only compatibility rate limiting lost its explicit "
            "non-refundable contract: "
            f"{local_compatibility_events} {local_compatibility_flow.metadata}"
        )

    raw_plus, raw_plus_events, _, _ = _run_proxy_transaction(
        policy_engine,
        credential_policy_type,
        request_url="https://upstream.invalid/resource?value=customer+name",
        allowed_query_keys=("value",),
    )
    if (
        raw_plus.decision.allowed
        or raw_plus.decision.payload.get("error") != "invalid_request_target"
        or "reserve" in raw_plus_events
        or "credential_read" in raw_plus_events
        or "credential_generation" in raw_plus_events
    ):
        raise AssertionError(
            "raw query plus reached credential or reservation processing: "
            f"{raw_plus_events} {raw_plus.decision}"
        )

    encoded_query, encoded_query_events, encoded_query_flow, _ = (
        _run_proxy_transaction(
            policy_engine,
            credential_policy_type,
            request_url=(
                "https://upstream.invalid/resource?"
                "space=a%20b&literal=%2B&data=a%26b%3Dc"
            ),
            allowed_query_keys=("data", "literal", "space"),
        )
    )
    encoded_query_canonical = encoded_query_flow.metadata.get(
        "observed_reserve_canonical_request"
    )
    expected_query_pairs = [["data", "a&b=c"], ["literal", "+"], ["space", "a b"]]
    policy_bound_query_wire = (
        policy_engine._canonical_query_wire(
            [tuple(pair) for pair in expected_query_pairs]
        )
    )
    if (
        not encoded_query.decision.allowed
        or "reserve" not in encoded_query_events
        or not isinstance(encoded_query_canonical, dict)
        or encoded_query_canonical["request"]["query"]
        != expected_query_pairs
        or policy_bound_query_wire
        != "data=a%26b%3Dc&literal=%2B&space=a%20b"
        or encoded_query_flow.request.pretty_url
        != f"https://upstream.invalid/resource?{policy_bound_query_wire}"
    ):
        raise AssertionError(
            "provider-visible query bytes diverged from the reserved canonical query: "
            f"{encoded_query_events} {encoded_query_canonical} "
            f"{encoded_query_flow.request.pretty_url}"
        )

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
            "rewrite",
            "credential_generation",
            "validate_credential_metadata",
            "validate_request",
            "operation_fields",
            "policy_validate",
            "reserve",
            "credential_read",
            "validate_credential",
            "dispatch",
        )
    ]
    if ordered != sorted(ordered) or events[-1] != "dispatch":
        raise AssertionError(f"proxy lifecycle ordering is unsafe: {events}")
    if allowed.attempt_id != flow.metadata.get("catchplate_release_attempt_id"):
        raise AssertionError("RequestEvaluation and flow metadata lost attempt correlation")
    lifecycle = flow.metadata.get("catchplate_release_authorization") or {}
    if lifecycle.get("attempt_id") != lifecycle.get("flow_id"):
        raise AssertionError(f"attempt and flow IDs diverged: {lifecycle}")
    if any(name in events for name in ("legacy_authorization_call", "legacy_quota_call")):
        raise AssertionError(f"atomic mode used a legacy authorization path: {events}")
    if any(str(name).lower().startswith("x-catchplate-") for name in flow.request.headers):
        raise AssertionError(f"proxy forwarded an internal Catchplate header: {flow.request.headers}")

    rewritten, rewritten_events, rewritten_flow, _ = _run_proxy_transaction(
        policy_engine,
        credential_policy_type,
        rewrite_mutation=lambda rewritten_flow: (
            setattr(rewritten_flow.request, "raw_content", b'{"provider":"visible"}'),
            rewritten_flow.request.query.__setitem__("mode", "rewritten"),
        ),
    )
    rewritten_canonical = rewritten_flow.metadata.get(
        "observed_reserve_canonical_request"
    )
    if (
        not rewritten.decision.allowed
        or not isinstance(rewritten_canonical, dict)
        or rewritten_canonical["request"]["query"] != [["mode", "rewritten"]]
        or rewritten_canonical["request"]["body_sha256"]
        != "sha256:" + hashlib.sha256(b'{"provider":"visible"}').hexdigest()
        or rewritten_events.index("rewrite") > rewritten_events.index("reserve")
    ):
        raise AssertionError(
            "reservation did not bind the exact provider-visible rewritten request: "
            f"{rewritten_events} {rewritten_canonical}"
        )

    rewritten_outside_route, outside_events, _, _ = _run_proxy_transaction(
        policy_engine,
        credential_policy_type,
        rewrite_mutation=lambda rewritten_flow: setattr(
            rewritten_flow.request,
            "method",
            "DELETE",
        ),
    )
    if (
        rewritten_outside_route.decision.allowed
        or rewritten_outside_route.decision.payload.get("error")
        != "rewritten_request_route_mismatch"
        or any(
            name in outside_events
            for name in (
                "validate_request",
                "credential_generation",
                "reserve",
                "credential_read",
            )
        )
    ):
        raise AssertionError(
            "unauthorized rewritten target reached authorization state: "
            f"{outside_events} {rewritten_outside_route.decision}"
        )

    quota_denied, quota_events, _, _ = _run_proxy_transaction(
        policy_engine,
        credential_policy_type,
        reserve_result={
            "authorized": False,
            "state": "denied",
            "reason": "shared_quota_denied",
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
        raise AssertionError(
            "quota denial acquired dispatch-secret credential material: "
            f"{quota_events}"
        )

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
    if "dispatch" in uncertain_events:
        raise AssertionError(
            f"uncertain reserve reached upstream dispatch: {uncertain_events}"
        )
    if "credential_read" in uncertain_events:
        raise AssertionError(
            "uncertain reserve acquired dispatch-secret credential material: "
            f"{uncertain_events}"
        )
    if uncertain_events.count("complete:not_forwarded") != 1:
        raise AssertionError(
            f"uncertain reserve did not emit exactly one expected cleanup: {uncertain_events}"
        )

    for transport_label in (
        "declared oversized reserve response",
        "streamed oversized reserve response",
        "reserve response timeout",
        "post-commit reserve response loss",
        "pre-create reserve transport loss",
    ):
        transport_failure, transport_events, transport_flow, _ = (
            _run_proxy_transaction(
                policy_engine,
                credential_policy_type,
                reserve_result=policy_engine.runtime.ReleaseAuthorizationClientError(
                    transport_label
                ),
            )
        )
        cleanup_identity = transport_flow.metadata.get(
            "observed_cleanup_identity"
        )
        expected_guard = transport_flow.metadata.get(
            "catchplate_release_authorization_guard"
        )
        if (
            transport_failure.decision.allowed
            or transport_failure.decision.payload.get("error")
            != "release_authorization_reserve_uncertain"
            or transport_events.count("complete:not_forwarded") != 1
            or "credential_read" in transport_events
            or expected_guard is None
            or cleanup_identity is not expected_guard.expected
            or cleanup_identity.attempt_id
            != transport_flow.metadata.get("catchplate_release_attempt_id")
            and transport_flow.metadata.get("catchplate_release_attempt_id")
            is not None
            or cleanup_identity.binding_digest
            != expected_guard.expected.binding_digest
        ):
            raise AssertionError(
                f"{transport_label} did not use one expected outbound cleanup: "
                f"{transport_events} {transport_flow.metadata}"
            )

    for label, malformed_reserve in (
        ("non-object", ["reserved"]),
        (
            "contradictory",
            {
                "authorized": False,
                "state": "reserved",
                "reason": "reserved",
            },
        ),
        (
            "binding-mismatch",
            {"binding_digest": "sha256:" + "0" * 64},
        ),
    ):
        malformed, malformed_events, _, _ = _run_proxy_transaction(
            policy_engine,
            credential_policy_type,
            reserve_result=malformed_reserve,
            replace_reserve_result=label == "non-object",
        )
        if (
            malformed.decision.allowed
            or malformed.decision.payload.get("error")
            != "release_authorization_reserve_invalid"
            or malformed_events.count("complete:not_forwarded") != 1
            or "credential_read" in malformed_events
        ):
            raise AssertionError(
                f"{label} reserve response escaped expected cleanup: "
                f"{malformed.decision} {malformed_events}"
            )

    for jit_mode in (False, True):
        secret_failure, secret_events, _, _ = _run_proxy_transaction(
            policy_engine,
            credential_policy_type,
            jit_required=jit_mode,
            credential_read_error=RuntimeError("forced secret acquisition failure"),
        )
        if (
            secret_failure.decision.allowed
            or secret_failure.decision.payload.get("error")
            != "credential_unavailable"
            or secret_events.index("reserve") > secret_events.index(
                "credential_read"
            )
            or secret_events.count("complete:not_forwarded") != 1
        ):
            raise AssertionError(
                "secret acquisition failure did not refund its shared reserve: "
                f"{jit_mode} {secret_events} {secret_failure.decision}"
            )

        audit_failure, audit_events, audit_flow, audit_dispatch = (
            _run_proxy_transaction(
                policy_engine,
                credential_policy_type,
                jit_required=jit_mode,
                audit_error=RuntimeError("forced audit delivery failure"),
                followup="dispatch",
            )
        )
        if (
            audit_failure.decision.allowed
            or audit_failure.decision.payload.get("error")
            != "request_audit_delivery_failed"
            or audit_dispatch is not None
            or audit_events.count("complete:not_forwarded") != 1
            or "dispatch" in audit_events
            or audit_flow.metadata.get(
                "catchplate_audit_delivery_uncertain"
            )
            is not True
            or audit_events.index("reserve") > audit_events.index(
                "credential_read"
            )
        ):
            raise AssertionError(
                "audit delivery failure did not refund its shared reserve: "
                f"{jit_mode} {audit_events} {audit_failure.decision}"
            )

        malformed_secret_policy = credential_policy_type(
            id="credential:test",
            provider="generic",
            provider_subject=None,
            scopes=(),
            injection={"type": "bearer", "field": "access_token"},
        )
        injection_failure, injection_events, _, _ = _run_proxy_transaction(
            policy_engine,
            credential_policy_type,
            credential_policy=malformed_secret_policy,
            credential={
                "id": "credential:test",
                "kind": "bearer",
                "secret": "not-json",
                "credential_version": 1,
                "metadata": {},
            },
            jit_required=jit_mode,
        )
        if (
            injection_failure.decision.allowed
            or injection_failure.decision.payload.get("error")
            != "credential_injection_failed"
            or injection_events.count("complete:not_forwarded") != 1
            or injection_events.index("reserve") > injection_events.index(
                "credential_read"
            )
        ):
            raise AssertionError(
                "injection failure did not refund its shared reserve: "
                f"{jit_mode} {injection_events} {injection_failure.decision}"
            )

    local_failure, local_events, local_flow, _ = _run_proxy_transaction(
        policy_engine,
        credential_policy_type,
        jit_required=False,
        rate_store="local",
        audit_error=RuntimeError("forced audit failure after local quota use"),
    )
    if (
        local_failure.decision.allowed
        or local_failure.decision.payload.get("error")
        != "request_audit_delivery_failed"
        or local_events.count("complete:not_forwarded") != 1
        or local_events.count("local_commit_non_refundable") != 1
        or local_flow.metadata.get("catchplate_local_rate_limit_mode")
        != "conservative_non_refundable"
    ):
        raise AssertionError(
            "local-only counter behavior was not distinguished from refundable "
            f"shared authority: {local_events} {local_flow.metadata}"
        )

    expired, expired_events, _, expired_dispatch = _run_proxy_transaction(
        policy_engine,
        credential_policy_type,
        reserve_result={
            "reservation_expires_at_epoch_ms": int(time.time() * 1000) - 1,
        },
        followup="dispatch",
    )
    if (
        expired.decision.allowed
        or expired.decision.payload.get("error")
        != "release_authorization_reserve_invalid"
        or expired_dispatch is not None
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
    if (
        cancelled.decision.allowed
        or "reserve" in cancel_events
        or "credential_read" in cancel_events
        or any(event.startswith("complete:") for event in cancel_events)
        or cancel_flow.metadata.get("catchplate_release_state") is not None
    ):
        raise AssertionError(
            f"rewrite denial mutated release state before final request validity: {cancel_events}"
        )

    exception_cancelled, exception_events, _, _ = _run_proxy_transaction(
        policy_engine,
        credential_policy_type,
        rewrite_error=RuntimeError("forced preparation exception"),
    )
    if (
        exception_cancelled.decision.allowed
        or exception_cancelled.decision.payload.get("error") != "request_rewrite_failed"
        or "reserve" in exception_events
        or "credential_read" in exception_events
        or any(event.startswith("complete:") for event in exception_events)
    ):
        raise AssertionError(
            f"rewrite exception mutated release state before final request validity: {exception_events}"
        )

    for jit_mode in (False, True):
        ambiguous, ambiguity_events, ambiguity_flow, ambiguity_decision = (
            _run_proxy_transaction(
                policy_engine,
                credential_policy_type,
                jit_required=jit_mode,
                dispatch_result=policy_engine.runtime.ReleaseAuthorizationClientError(
                    "lost response"
                ),
                followup="dispatch",
            )
        )
        if (
            not ambiguous.decision.allowed
            or not ambiguity_decision
            or ambiguity_decision.allowed
            or ambiguity_decision.payload.get("error")
            != "release_authorization_dispatch_uncertain"
            or ambiguity_events.index("reserve") > ambiguity_events.index(
                "credential_read"
            )
        ):
            raise AssertionError(
                f"dispatch ambiguity did not fail closed: {jit_mode} "
                f"{ambiguity_decision}"
            )
        if ambiguity_events[-2:] != ["dispatch", "complete:unknown"]:
            raise AssertionError(
                "dispatch ambiguity was not committed unknown: "
                f"{jit_mode} {ambiguity_events}"
            )
        if (
            ambiguity_flow.metadata.get("catchplate_release_state")
            != "committed_indeterminate"
        ):
            raise AssertionError(
                f"dispatch ambiguity lifecycle was not retained: {jit_mode}"
            )

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
    if response_flow.metadata.get("catchplate_release_state") != "committed":
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
    if "reserve" in mismatch_events or any(
        event.startswith("complete:") for event in mismatch_events
    ):
        raise AssertionError(
            "credential mismatch reached release authorization state: "
            f"{mismatch_events}"
        )
    if (
        mismatch_flow.metadata.get("catchplate_release_state") is not None
        or "authorization"
        in {
            str(name).lower()
            for name in mismatch_flow.request.headers
        }
    ):
        raise AssertionError(
            "credential mismatch retained release or injected request state"
        )


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


def exercise_release_client_single_attempt_guard_contract(runtime: Any) -> None:
    attempt_id = "attempt:idempotent-retry"
    binding_digest = "sha256:" + "3" * 64
    operation_context = {"operation": "test.forward"}
    canonical_request = {
        "v": 1,
        "principal": "agent:test",
        "client_ip": None,
        "route_id": "route:test",
        "credential_ref": "credential:test",
        "credential_version": "1",
        "policy_hash": "sha256:" + "4" * 64,
        "request": {
            "method": "POST",
            "scheme": "https",
            "authority": "upstream.invalid",
            "path": "/resource",
            "query": [],
            "headers": {"host": "upstream.invalid"},
            "body_sha256": "sha256:" + hashlib.sha256(b"").hexdigest(),
        },
        "operation": operation_context,
    }

    def canonical_digest(value: dict[str, Any]) -> str:
        return "sha256:" + hashlib.sha256(
            json.dumps(
                value,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            ).encode("utf-8")
        ).hexdigest()

    reserve_payload = {
        "apiVersion": "catchplate.releaseAuthorizationReserve/v1",
        "attemptId": attempt_id,
        "flowId": attempt_id,
        "principalId": "agent:test",
        "routeId": "route:test",
        "credentialRef": "credential:test",
        "credentialVersion": 1,
        "policyHash": "sha256:" + "4" * 64,
        "requestDigest": canonical_digest(canonical_request),
        "operationDigest": canonical_digest(
            {
                key: canonical_request[key]
                for key in (
                    "principal",
                    "route_id",
                    "credential_ref",
                    "credential_version",
                    "policy_hash",
                    "request",
                    "operation",
                )
            }
        ),
        "operationContext": operation_context,
        "canonicalRequest": canonical_request,
    }
    requests: list[dict[str, Any]] = []

    def flaky_request(request: Any, **_kwargs: Any) -> Any:
        requests.append(json.loads(request.data))
        if len(requests) == 1:
            raise urllib.error.URLError("response lost")
        return SimpleNamespace(
            value={
                "apiVersion": "catchplate.releaseAuthorization/v1",
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
        stack.enter_context(
            patch.object(runtime, "request_json_bytes", side_effect=flaky_request)
        )
        stack.enter_context(patch.object(runtime.time, "sleep", return_value=None))
        try:
            runtime._release_authorization_http_post(
                "reserve",
                reserve_payload,
                expected_binding_digest=binding_digest,
                expected_shared_quotas=[],
            )
        except runtime.ReleaseAuthorizationClientError:
            pass
        else:
            raise AssertionError("uncertain reserve response was retried into success")
    if requests != [reserve_payload]:
        raise AssertionError(
            f"reserve response loss emitted more than one reserve request: {requests}"
        )

    calendar_start_ms = int(
        datetime(2025, 1, 1, tzinfo=timezone.utc).timestamp() * 1000
    )
    calendar_end_ms = int(
        datetime(2025, 1, 2, tzinfo=timezone.utc).timestamp() * 1000
    )
    calendar_response = {
        "apiVersion": "catchplate.releaseAuthorization/v1",
        "ok": True,
        "authorized": True,
        "state": "reserved",
        "reason": "reserved",
        "attemptId": attempt_id,
        "bindingDigest": binding_digest,
        "idempotentReplay": False,
        "reservationExpiresAtEpochMs": calendar_end_ms,
        "retryAfterSeconds": 0,
        "quotas": [
            {
                "counterKey": "sha256:" + "7" * 64,
                "constraintId": "calendar-client-validation",
                "operation": "test.forward",
                "windowKind": "utcDay",
                "calendarWindow": "utcDay",
                "windowStartEpochMs": calendar_start_ms,
                "windowEndEpochMs": calendar_end_ms,
                "max": 2,
                "count": 1,
                "remaining": 1,
                "reservationState": "reserved",
            }
        ],
        "store": {"backend": "postgres", "ha": True},
    }
    normalized = runtime._normalized_release_authorization_response(
        calendar_response,
        attempt_id=attempt_id,
    )
    calendar_claim = {
        "counter_key": "sha256:" + "7" * 64,
        "constraint_id": "calendar-client-validation",
        "operation": "test.forward",
        "window_kind": "utcDay",
        "max_count": 2,
    }
    runtime.validate_reserve_release_authorization_response(
        normalized,
        attempt_id=attempt_id,
        require_jit_grant=False,
        expected_binding_digest=binding_digest,
        expected_shared_quotas=[calendar_claim],
        now_epoch_ms=calendar_start_ms + 1_000,
    )
    for label, mutate in (
        (
            "forged boundary",
            lambda body: body["quotas"][0].update(
                {"windowStartEpochMs": calendar_start_ms + 1}
            ),
        ),
        (
            "descriptor mismatch",
            lambda body: body["quotas"][0].update({"calendarWindow": "utcMonth"}),
        ),
        (
            "expiry beyond boundary",
            lambda body: body.update(
                {"reservationExpiresAtEpochMs": calendar_end_ms + 1}
            ),
        ),
    ):
        malformed = json.loads(json.dumps(calendar_response))
        mutate(malformed)
        try:
            malformed_normalized = runtime._normalized_release_authorization_response(
                malformed,
                attempt_id=attempt_id,
            )
            runtime.validate_reserve_release_authorization_response(
                malformed_normalized,
                attempt_id=attempt_id,
                require_jit_grant=False,
                expected_binding_digest=binding_digest,
                expected_shared_quotas=[calendar_claim],
                now_epoch_ms=calendar_start_ms + 1_000,
            )
        except runtime.ReleaseAuthorizationClientError:
            pass
        else:
            raise AssertionError(
                f"release client accepted {label}: {malformed_normalized}"
            )

    expected = runtime.expected_release_authorization_identity(
        attempt_id=attempt_id,
        flow_id=attempt_id,
        principal_id=reserve_payload["principalId"],
        route_id=reserve_payload["routeId"],
        credential_ref=reserve_payload["credentialRef"],
        credential_version=reserve_payload["credentialVersion"],
        policy_hash=reserve_payload["policyHash"],
        request_digest=reserve_payload["requestDigest"],
        operation_digest=reserve_payload["operationDigest"],
        operation_context=operation_context,
        shared_quotas=[],
        require_jit_grant=False,
    )
    for failure_label in (
        "declared oversized",
        "streamed oversized",
        "malformed JSON",
        "response timeout",
        "post-commit response loss",
        "pre-create transport loss",
    ):
        cleanup_identities: list[Any] = []

        def cancel_once(identity: Any) -> dict[str, Any]:
            cleanup_identities.append(identity)
            return {
                "authorized": False,
                "state": "absent",
                "reason": "reservation_absent",
                "attempt_id": identity.attempt_id,
                "binding_digest": identity.binding_digest,
                "idempotent_replay": True,
                "grant_id": None,
                "approval_request_id": None,
                "reservation_expires_at_epoch_ms": None,
                "dispatch_started_at_epoch_ms": None,
                "dispatch_expires_at_epoch_ms": None,
                "completion_outcome": None,
                "retry_after_seconds": 0,
                "quotas": [],
            }

        guard = runtime.ReleaseAuthorizationGuard(expected)
        with (
            patch.object(
                runtime,
                "_release_authorization_base_url",
                return_value=(
                    "https://control.test/api/data-plane/"
                    "release-authorizations"
                ),
            ),
            patch.object(
                runtime,
                "_release_authorization_token",
                return_value="test-token",
            ),
            patch.object(
                runtime,
                "_release_authorization_ssl_context",
                return_value=None,
            ),
            patch.object(
                runtime,
                "request_json_bytes",
                side_effect=runtime.HttpClientError(failure_label),
            ),
            patch.object(runtime.time, "sleep", return_value=None),
            patch.object(
                runtime,
                "cancel_expected_release_authorization",
                side_effect=cancel_once,
            ),
        ):
            try:
                runtime.reserve_expected_release_authorization(
                    guard=guard,
                    operation_context=operation_context,
                    canonical_request=canonical_request,
                    shared_quotas=[],
                )
            except runtime.ReleaseAuthorizationClientError:
                guard.cancel_not_forwarded_once()
                guard.cancel_not_forwarded_once()
            else:
                raise AssertionError(
                    f"{failure_label} reserve unexpectedly succeeded"
                )
        if cleanup_identities != [expected] or not guard.cleanup_emitted:
            raise AssertionError(
                f"{failure_label} did not emit one expected cleanup: "
                f"{cleanup_identities}"
            )

    failed_cleanup_identities: list[Any] = []

    def fail_cleanup(identity: Any) -> dict[str, Any]:
        failed_cleanup_identities.append(identity)
        raise runtime.ReleaseAuthorizationClientError(
            "fixture cleanup transport loss"
        )

    failed_cleanup_guard = runtime.ReleaseAuthorizationGuard(expected)
    failed_cleanup_guard.promote_reserved()
    with patch.object(
        runtime,
        "cancel_expected_release_authorization",
        side_effect=fail_cleanup,
    ):
        assert failed_cleanup_guard.cancel_not_forwarded_once() is None
        assert failed_cleanup_guard.cancel_not_forwarded_once() is None
    if (
        failed_cleanup_identities != [expected]
        or not failed_cleanup_guard.cleanup_emitted
        or not failed_cleanup_guard.cleanup_error
        or failed_cleanup_guard.phase != "cleanup_unknown"
        or failed_cleanup_guard.requires_not_forwarded
        or failed_cleanup_guard.cleanup_error_detail
        != "fixture cleanup transport loss"
    ):
        raise AssertionError(
            "cleanup transport loss did not latch one terminal unknown cleanup: "
            f"{failed_cleanup_identities} {failed_cleanup_guard.phase} "
            f"{failed_cleanup_guard.cleanup_error_detail}"
        )

    valid_raw_reserve_response = {
        "apiVersion": "catchplate.releaseAuthorization/v1",
        "ok": True,
        "authorized": True,
        "state": "reserved",
        "reason": "reserved",
        "attemptId": expected.attempt_id,
        "bindingDigest": expected.binding_digest,
        "idempotentReplay": False,
        "grantId": None,
        "approvalRequestId": None,
        "approvalStatus": None,
        "approvalExpiresAt": None,
        "approvalCreated": None,
        "reservationExpiresAtEpochMs": int(time.time() * 1000) + 60_000,
        "dispatchStartedAtEpochMs": None,
        "dispatchExpiresAtEpochMs": None,
        "completionOutcome": None,
        "retryAfterSeconds": 0,
        "quotas": [],
        "store": {"backend": "postgres", "ha": True},
    }
    contradictory_raw_reserve = dict(valid_raw_reserve_response)
    contradictory_raw_reserve["authorized"] = False
    mismatched_raw_reserve = dict(valid_raw_reserve_response)
    mismatched_raw_reserve["bindingDigest"] = "sha256:" + "0" * 64
    for failure_label, raw_response in (
        ("malformed reserve object", ["reserved"]),
        ("contradictory reserved response", contradictory_raw_reserve),
        ("reserve binding mismatch", mismatched_raw_reserve),
    ):
        cleanup_identities = []

        def cancel_malformed(identity: Any) -> dict[str, Any]:
            cleanup_identities.append(identity)
            return {
                "authorized": False,
                "state": "absent",
                "reason": "reservation_absent",
                "attempt_id": identity.attempt_id,
                "binding_digest": identity.binding_digest,
                "idempotent_replay": True,
                "grant_id": None,
                "approval_request_id": None,
                "approval_status": None,
                "approval_expires_at": None,
                "approval_created": None,
                "reservation_expires_at_epoch_ms": None,
                "dispatch_started_at_epoch_ms": None,
                "dispatch_expires_at_epoch_ms": None,
                "completion_outcome": None,
                "retry_after_seconds": 0,
                "quotas": [],
            }

        guard = runtime.ReleaseAuthorizationGuard(expected)
        with (
            patch.object(
                runtime,
                "_release_authorization_base_url",
                return_value=(
                    "https://control.test/api/data-plane/"
                    "release-authorizations"
                ),
            ),
            patch.object(
                runtime,
                "_release_authorization_token",
                return_value="test-token",
            ),
            patch.object(
                runtime,
                "_release_authorization_ssl_context",
                return_value=None,
            ),
            patch.object(
                runtime,
                "request_json_bytes",
                return_value=SimpleNamespace(value=raw_response),
            ),
            patch.object(
                runtime,
                "cancel_expected_release_authorization",
                side_effect=cancel_malformed,
            ),
        ):
            try:
                runtime.reserve_expected_release_authorization(
                    guard=guard,
                    operation_context=operation_context,
                    canonical_request=canonical_request,
                    shared_quotas=[],
                )
            except runtime.ReleaseAuthorizationClientError:
                guard.cancel_not_forwarded_once()
            else:
                raise AssertionError(
                    f"{failure_label} unexpectedly passed reserve validation"
                )
        if cleanup_identities != [expected] or not guard.cleanup_emitted:
            raise AssertionError(
                f"{failure_label} did not emit one expected cleanup: "
                f"{cleanup_identities}"
            )


def exercise_python_v2_release_coordinator(
    policy_engine: Any,
    runtime: Any,
    credential_policy_type: Any,
) -> None:
    actor_id = runtime.DATA_PLANE_INSTANCE_ID or "catchplate-python-mitm"
    policy_hash = _release_lock_digest("python-v2-release-policy")
    credential_id = "credential:python-v2-release"
    operation_context = {
        "operation": "test.forward",
        "requestCost": "3",
    }
    coordinator_events: list[tuple[str, str]] = []
    reservations: dict[str, dict[str, Any]] = {}
    completion_modes: dict[str, str] = {}
    issuance_claims: list[dict[str, Any]] = []

    def exact_outer(
        *,
        attempt_id: str,
        state: str,
        reason: str,
        authorized: bool,
        completion_outcome: str | None,
        durable_policy: dict[str, Any],
    ) -> dict[str, Any]:
        retained = reservations[attempt_id]
        return {
            "authorized": authorized,
            "state": state,
            "reason": reason,
            "attempt_id": attempt_id,
            "binding_digest": retained["binding_digest"],
            "idempotent_replay": False,
            "grant_id": None,
            "approval_request_id": None,
            "reservation_expires_at_epoch_ms": retained[
                "reservation_expires_at_epoch_ms"
            ],
            "dispatch_started_at_epoch_ms": retained.get(
                "dispatch_started_at_epoch_ms"
            ),
            "dispatch_expires_at_epoch_ms": retained.get(
                "dispatch_expires_at_epoch_ms"
            ),
            "completion_outcome": completion_outcome,
            "retry_after_seconds": 0,
            "quotas": [],
            "durable_policy": durable_policy,
        }

    def durable_route_constraints(
        *,
        traversal_operations: list[str],
        include_sliding_budgets: bool,
    ) -> tuple[dict[str, Any], ...]:
        budgets: list[dict[str, Any]] = []
        if include_sliding_budgets:
            budgets = [
                {
                    "id": "python-v2-sliding",
                    "type": "slidingWindowLimit",
                    "store": "shared",
                    "windowSemantics": "sliding",
                    "measure": "operationCount",
                    "reservationMode": "atomicReserveCommitRelease",
                    "onOverflow": "deny",
                    "windowSeconds": 60,
                    "max": 10,
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
                {
                    "id": "python-v2-weighted",
                    "type": "weightedBudget",
                    "store": "shared",
                    "windowSemantics": "sliding",
                    "measure": "weightedCanonicalInteger",
                    "reservationMode": "atomicReserveCommitRelease",
                    "onOverflow": "deny",
                    "windowSeconds": 60,
                    "max": 30,
                    "key": {
                        "scope": [
                            "principal",
                            "credential",
                            "credentialVersion",
                            "route",
                            "operation",
                        ],
                        "operationFields": ["requestCost"],
                    },
                    "weight": {
                        "source": "operationField",
                        "field": "requestCost",
                        "representation": "canonicalNonNegativeInteger",
                        "unit": "requests",
                        "minimumPerOperation": 1,
                        "maximumPerOperation": 10,
                    },
                },
            ]
        return tuple(
            [
                *budgets,
                {
                    "id": "python-v2-traversal",
                    "type": "traversalBudget",
                    "operations": traversal_operations,
                    "traversal": {
                        "store": "shared",
                        "phases": ["request", "response"],
                        "cursor": {
                            "requestSource": "query",
                            "requestField": "cursor",
                            "responseField": "nextCursor",
                            "digest": "sha256",
                            "firstPageMayOmit": True,
                        },
                        "lineage": {
                            "scope": [
                                "principal",
                                "route",
                                "credential",
                                "credentialVersion",
                            ],
                            "queryFields": ["query"],
                            "queryDigest": "sha256",
                        },
                        "limits": {
                            "maxPages": 3,
                            "maxLifetimeSeconds": 300,
                            "maxRecords": 20,
                            "maxDecodedBytes": 64 * 1024,
                        },
                        "accounting": {
                            "recordCountField": "items",
                            "byteSource": "validatedDecodedResponseBytes",
                            "commit": "atomicAfterResponseValidation",
                        },
                        "onReplay": "deny",
                        "onCrossLineage": "deny",
                        "onMissingEvidence": "deny",
                    },
                },
            ]
        )

    def durable_claims(
        expected: Any,
        *,
        traversal_operations: list[str] | None = None,
        include_sliding_budgets: bool = True,
    ) -> list[dict[str, Any]]:
        route = SimpleNamespace(
            id=expected.route_id,
            credential_ref=expected.credential_ref,
            adapter_type="generic.rest",
            adapter_config={
                "request": {
                    "allowedQueryKeys": ["query", "cursor"],
                }
            },
            constraints=durable_route_constraints(
                traversal_operations=(
                    traversal_operations
                    if traversal_operations is not None
                    else ["test.forward"]
                ),
                include_sliding_budgets=include_sliding_budgets,
            ),
        )
        flow = SimpleNamespace(
            request=SimpleNamespace(
                pretty_url=(
                    "https://upstream.invalid/resource?query=bounded"
                ),
                raw_content=b"",
                headers={},
            )
        )
        return policy_engine._durable_policy_claims(
            flow,
            snapshot=SimpleNamespace(hash=expected.policy_hash),
            principal=SimpleNamespace(id=expected.principal_id),
            route=route,
            credential_version=expected.credential_version,
            operation_fields=operation_context,
        )

    applicable_admission, _, applicable_flow, _ = _run_proxy_transaction(
        policy_engine,
        credential_policy_type,
        jit_required=False,
        request_url=(
            "https://upstream.invalid/resource?query=bounded"
        ),
        allowed_query_keys=("query", "cursor"),
        route_constraints=durable_route_constraints(
            traversal_operations=["test.forward"],
            include_sliding_budgets=True,
        ),
        operation_fields=operation_context,
    )
    applicable_claims = applicable_flow.metadata.get(
        "observed_durable_policy_claims"
    )
    applicable_authority = applicable_flow.metadata.get(
        "observed_credential_authority"
    )
    applicable_release = (
        applicable_authority.get("release_authorization")
        if isinstance(applicable_authority, dict)
        else None
    )
    if (
        not applicable_admission.decision.allowed
        or [
            claim.get("type")
            for claim in (
                applicable_claims
                if isinstance(applicable_claims, list)
                else []
            )
        ]
        != [
            "slidingWindowLimit",
            "weightedBudget",
            "traversalBudget",
        ]
        or not isinstance(applicable_release, dict)
        or applicable_release.get("apiVersion")
        != "catchplate.credentialLeaseReleaseAuthorization/v2"
    ):
        raise AssertionError(
            "applicable durable route did not enter the atomic v2 lifecycle"
        )

    nonapplicable_admission, _, nonapplicable_flow, _ = (
        _run_proxy_transaction(
            policy_engine,
            credential_policy_type,
            jit_required=False,
            request_url=(
                "https://upstream.invalid/resource?query=bounded"
            ),
            allowed_query_keys=("query", "cursor"),
            route_constraints=durable_route_constraints(
                traversal_operations=["test.other"],
                include_sliding_budgets=False,
            ),
            operation_fields=operation_context,
        )
    )
    nonapplicable_authority = nonapplicable_flow.metadata.get(
        "observed_credential_authority"
    )
    if (
        not nonapplicable_admission.decision.allowed
        or nonapplicable_flow.metadata.get(
            "observed_durable_policy_claims"
        )
        is not None
        or not isinstance(nonapplicable_authority, dict)
        or nonapplicable_authority.get("request_authority") is None
        or nonapplicable_authority.get("release_authorization") is not None
    ):
        raise AssertionError(
            "nonapplicable traversal did not preserve decision-bound authority"
        )

    nonapplicable_without_authority, nonapplicable_events, _, _ = (
        _run_proxy_transaction(
            policy_engine,
            credential_policy_type,
            jit_required=False,
            atomic_enabled=False,
            request_url=(
                "https://upstream.invalid/resource?query=bounded"
            ),
            allowed_query_keys=("query", "cursor"),
            route_constraints=durable_route_constraints(
                traversal_operations=["test.other"],
                include_sliding_budgets=False,
            ),
            operation_fields=operation_context,
        )
    )
    if (
        nonapplicable_without_authority.decision.allowed
        or nonapplicable_without_authority.decision.payload.get(
            "error"
        )
        != "atomic_release_authorization_required"
        or "credential_read" in nonapplicable_events
    ):
        raise AssertionError(
            "controlled nonapplicable traversal fell back to authority-free loading"
        )

    uncontrolled_admission, _, uncontrolled_flow, _ = (
        _run_proxy_transaction(
            policy_engine,
            credential_policy_type,
            jit_required=False,
            route_constraints=(),
            operation_fields=operation_context,
        )
    )
    if (
        not uncontrolled_admission.decision.allowed
        or uncontrolled_flow.metadata.get(
            "observed_credential_authority"
        )
        != {}
    ):
        raise AssertionError(
            "uncontrolled route unexpectedly carried credential authority"
        )

    legacy_bound_calls: list[str | None] = []

    def legacy_credential_reader(
        requested_id: str | None,
    ) -> None:
        legacy_bound_calls.append(requested_id)
        return None

    with patch.object(
        runtime,
        "get_credential",
        side_effect=legacy_credential_reader,
    ):
        if runtime.get_bound_credential_lease(credential_id) is not None:
            raise AssertionError(
                "legacy authority-free bound lease unexpectedly resolved"
            )
    if legacy_bound_calls != [credential_id]:
        raise AssertionError(
            "authority-free bound lease passed v4 keyword arguments"
        )

    partial_authority_cases = (
        ("identity-only", {"expected_release_identity": object()}),
        ("jit-only", {"jit_policy": {}}),
        ("release-only", {"release_authorization": {}}),
        ("request-without-identity", {"request_authority": {}}),
    )
    for reader in (
        runtime.get_credential,
        runtime.get_bound_credential_lease,
    ):
        with patch.object(
            db,
            "get_credential",
            side_effect=AssertionError(
                "partial authority reached credential storage"
            ),
        ):
            for label, partial_kwargs in partial_authority_cases:
                try:
                    reader(credential_id, **partial_kwargs)
                except runtime.ReleaseAuthorizationClientError:
                    pass
                else:
                    raise AssertionError(
                        f"{reader.__name__} accepted partial authority {label}"
                    )

    def expected_case(
        label: str,
    ) -> tuple[Any, dict[str, Any]]:
        attempt_id = _release_lock_digest(
            f"python-v2-release:{label}:attempt"
        )
        canonical_request = {
            "apiVersion": "catchplate.pythonV2Fixture/v1",
            "label": label,
            "operation": operation_context,
        }
        request_digest = runtime._durable_policy_digest(canonical_request)
        operation_digest = runtime._durable_policy_digest(
            {
                "label": label,
                "operation": operation_context,
            },
        )
        return (
            runtime.expected_release_authorization_identity(
                attempt_id=attempt_id,
                flow_id=attempt_id,
                principal_id="agent:python-v2-release",
                route_id="route:python-v2-release",
                credential_ref=credential_id,
                credential_version=1,
                policy_hash=policy_hash,
                request_digest=request_digest,
                operation_digest=operation_digest,
                operation_context=operation_context,
                shared_quotas=[],
                require_jit_grant=False,
            ),
            canonical_request,
        )

    def reserve_v2(**kwargs: Any) -> dict[str, Any]:
        attempt_id = kwargs["attempt_id"]
        coordinator_events.append(("reserve:v2", attempt_id))
        durable_binding = kwargs["durable_policy_binding"]
        if (
            set(durable_binding) != {"actorId", "claimDigest", "claims"}
            or durable_binding["actorId"] != actor_id
            or durable_binding["claimDigest"]
            != runtime._durable_policy_digest(durable_binding["claims"])
        ):
            raise AssertionError(
                f"Python v2 reserve lost its exact durable binding: {kwargs}"
            )
        binding_digest = runtime.release_authorization_binding_digest(
            attempt_id=attempt_id,
            flow_id=kwargs["flow_id"],
            principal_id=kwargs["principal_id"],
            route_id=kwargs["route_id"],
            credential_ref=kwargs["credential_id"],
            credential_version=kwargs["credential_version"],
            policy_hash=kwargs["policy_hash"],
            request_digest=kwargs["request_digest"],
            operation_digest=kwargs["operation_digest"],
            operation_context=kwargs["operation_context"],
            shared_quotas=kwargs["shared_quotas"],
            require_jit_grant=kwargs["require_jit_grant"],
        )
        claim_digest = durable_binding["claimDigest"]
        reservation_id = runtime._durable_policy_digest(
            {
                "attemptId": attempt_id,
                "policyHash": kwargs["policy_hash"],
                "requestDigest": kwargs["request_digest"],
                "operationDigest": kwargs["operation_digest"],
                "claimDigest": claim_digest,
            }
        )
        expires_at = int(time.time() * 1000) + 60_000
        durable = {
            "state": "reserved",
            "attempt_id": attempt_id,
            "claim_digest": claim_digest,
            "reservation_id": reservation_id,
            "actor_id": actor_id,
            "reservation_deadline_at_epoch_ms": expires_at,
            "dispatch_deadline_at_epoch_ms": None,
            "response_evidence_digest": None,
            "failure_reason": None,
            "response_body_sha256": None,
            "uncertainty": None,
        }
        reservations[attempt_id] = {
            "binding_digest": binding_digest,
            "reservation_expires_at_epoch_ms": expires_at,
            "durable_policy": durable,
            "claims": durable_binding["claims"],
        }
        return exact_outer(
            attempt_id=attempt_id,
            state="reserved",
            reason="reserved",
            authorized=True,
            completion_outcome=None,
            durable_policy=durable,
        )

    def dispatch_v2(**kwargs: Any) -> dict[str, Any]:
        attempt_id = kwargs["attempt_id"]
        coordinator_events.append(("dispatch:v2", attempt_id))
        retained = reservations[attempt_id]
        transition = kwargs["durable_policy_transition"]
        expected_identity = retained["durable_policy"]
        if (
            transition
            != {
                "actorId": expected_identity["actor_id"],
                "attemptId": attempt_id,
                "claimDigest": expected_identity["claim_digest"],
                "reservationId": expected_identity["reservation_id"],
                "dispatchDeadlineAtEpochMs": transition.get(
                    "dispatchDeadlineAtEpochMs"
                ),
            }
            or type(transition["dispatchDeadlineAtEpochMs"]) is not int
        ):
            raise AssertionError(
                f"Python v2 dispatch lost its exact transition: {transition}"
            )
        started_at = int(time.time() * 1000)
        deadline = transition["dispatchDeadlineAtEpochMs"]
        retained["dispatch_started_at_epoch_ms"] = started_at
        retained["dispatch_expires_at_epoch_ms"] = deadline
        durable = {
            **expected_identity,
            "state": "dispatched",
            "dispatch_deadline_at_epoch_ms": deadline,
        }
        retained["durable_policy"] = durable
        return exact_outer(
            attempt_id=attempt_id,
            state="dispatching",
            reason="dispatching",
            authorized=True,
            completion_outcome=None,
            durable_policy=durable,
        )

    def complete_v2(**kwargs: Any) -> dict[str, Any]:
        attempt_id = kwargs["attempt_id"]
        outcome = kwargs["outcome"]
        coordinator_events.append((f"complete:v2:{outcome}", attempt_id))
        retained = reservations[attempt_id]
        transition = kwargs["durable_policy_transition"]
        durable_before = retained["durable_policy"]
        identity = {
            "actorId": durable_before["actor_id"],
            "attemptId": attempt_id,
            "claimDigest": durable_before["claim_digest"],
            "reservationId": durable_before["reservation_id"],
        }
        if any(transition.get(key) != value for key, value in identity.items()):
            raise AssertionError(
                f"Python v2 completion changed durable identity: {transition}"
            )
        if outcome == "not_forwarded":
            if set(transition) != set(identity):
                raise AssertionError(
                    f"Python v2 refund carried completion evidence: {transition}"
                )
            durable = {
                **durable_before,
                "state": "aborted",
                "dispatch_deadline_at_epoch_ms": None,
            }
            return exact_outer(
                attempt_id=attempt_id,
                state="cancelled",
                reason="cancelled",
                authorized=False,
                completion_outcome="not_forwarded",
                durable_policy=durable,
            )
        if (
            transition.get("responseEvidenceDigest")
            != runtime._durable_policy_digest(
                transition.get("responseEvidence")
            )
            or not re.fullmatch(
                r"sha256:[0-9a-f]{64}",
                str(transition.get("responseBodySha256") or ""),
            )
        ):
            raise AssertionError(
                f"Python v2 completion evidence is not exact: {transition}"
            )
        mode = completion_modes.get(attempt_id, "committed")
        if outcome == "unknown":
            if (
                transition.get("failureReason")
                != "provider_outcome_or_response_validation_uncertain"
                or transition.get("uncertainty") != "charged_fail_closed"
            ):
                raise AssertionError(
                    f"Python v2 unknown was not charged fail closed: {transition}"
                )
            durable_state = "indeterminate"
            outer_state = "committed_indeterminate"
            reason = "forward_outcome_indeterminate"
            authorized = True
        else:
            durable_state = "denied" if mode == "denied" else "committed"
            outer_state = "committed"
            reason = "forwarded"
            authorized = True
        durable = {
            **durable_before,
            "state": durable_state,
            "dispatch_deadline_at_epoch_ms": transition.get(
                "dispatchDeadlineAtEpochMs"
            ),
            "response_evidence_digest": transition[
                "responseEvidenceDigest"
            ],
            "response_body_sha256": (
                "sha256:" + "0" * 64
                if mode == "mismatched_evidence"
                else transition["responseBodySha256"]
            ),
            "failure_reason": (
                "traversal_record_budget_exceeded"
                if durable_state == "denied"
                else transition.get("failureReason")
            ),
            "uncertainty": transition.get("uncertainty"),
        }
        return exact_outer(
            attempt_id=attempt_id,
            state=outer_state,
            reason=reason,
            authorized=authorized,
            completion_outcome=outcome,
            durable_policy=durable,
        )

    def reject_v1(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("Python durable lifecycle downgraded to v1")

    credential = {
        "id": credential_id,
        "kind": "bearer",
        "secret": "python-v2-secret",
        "credential_version": 1,
        "metadata": {},
        "lifecycle_status": "active",
    }

    def get_credential(
        requested_id: str,
        include_secret: bool = False,
    ) -> dict[str, Any]:
        if requested_id != credential_id:
            raise AssertionError(
                f"Python v2 fixture requested another credential: {requested_id}"
            )
        return dict(credential)

    def claim_credential(**kwargs: Any) -> dict[str, Any]:
        issuance_claims.append(kwargs)
        return {"claimed": True, **kwargs}

    def reserve_case(
        label: str,
    ) -> tuple[Any, Any, dict[str, Any], dict[str, Any]]:
        expected, canonical_request = expected_case(label)
        claims = durable_claims(expected)
        if [claim.get("type") for claim in claims] != [
            "slidingWindowLimit",
            "weightedBudget",
            "traversalBudget",
        ]:
            raise AssertionError(
                f"applicable durable route lost policy claims: {claims}"
            )
        durable_binding = runtime.durable_policy_reserve_binding(
            expected,
            claims,
        )
        guard = runtime.ReleaseAuthorizationGuard(
            expected,
            durable_policy=durable_binding,
        )
        reserved = runtime.reserve_expected_release_authorization(
            guard=guard,
            operation_context=operation_context,
            canonical_request=canonical_request,
            shared_quotas=[],
            durable_policy_claims=claims,
        )
        request_authority = runtime.credential_lease_request_authority(
            expected,
            reserved,
            operation_context=operation_context,
            controlled=True,
        )
        release_authorization = (
            runtime.credential_lease_release_authorization(
                expected,
                reserved,
            )
        )
        if (
            request_authority is None
            or release_authorization is None
            or release_authorization.get("apiVersion")
            != "catchplate.credentialLeaseReleaseAuthorization/v2"
            or release_authorization.get("durablePolicy")
            != {
                "reservationId": reserved["durable_policy"][
                    "reservation_id"
                ],
                "actorId": actor_id,
                "claimDigest": reserved["durable_policy"]["claim_digest"],
                "reservationDeadlineAtEpochMs": reserved[
                    "reservation_expires_at_epoch_ms"
                ],
                "releaseBindingDigest": expected.binding_digest,
            }
        ):
            raise AssertionError(
                "Python v2 credential authority did not bind the durable reserve"
            )
        loaded = runtime.get_credential(
            credential_id,
            request_authority=request_authority,
            release_authorization=release_authorization,
            expected_release_identity=expected,
            jit_policy={},
        )
        claim = issuance_claims[-1]
        request_authority_sha256 = runtime._durable_policy_digest(
            request_authority
        )
        if (
            loaded is None
            or claim.get("release_kind") != "atomicReservation"
            or claim.get("operation_context") != operation_context
            or claim.get("request_authority_sha256")
            != request_authority_sha256
            or claim.get("durable_policy")
            != release_authorization["durablePolicy"]
        ):
            raise AssertionError(
                f"Python v2 credential claim lost exact authority: {claim}"
            )
        lifecycle = {
            "attempt_id": expected.attempt_id,
            "binding_digest": expected.binding_digest,
            "state": "reserved",
            "dispatch_attempted": False,
            "grant_id": None,
            "approval_request_id": None,
            "reservation_expires_at_epoch_ms": reserved[
                "reservation_expires_at_epoch_ms"
            ],
            "dispatch_started_at_epoch_ms": None,
            "dispatch_expires_at_epoch_ms": None,
            "quotas": [],
            "durable_policy": reserved["durable_policy"],
        }
        return expected, guard, reserved, lifecycle

    def dispatch_case(lifecycle: dict[str, Any]) -> dict[str, Any]:
        deadline = runtime.release_authorization_dispatch_deadline(lifecycle)
        dispatched = runtime.dispatch_release_authorization(
            attempt_id=lifecycle["attempt_id"],
            binding_digest=lifecycle["binding_digest"],
            previous_lifecycle=lifecycle,
            dispatch_deadline_at_epoch_ms=deadline,
        )
        lifecycle.update(
            {
                "state": "dispatching",
                "dispatch_attempted": True,
                "dispatch_started_at_epoch_ms": dispatched[
                    "dispatch_started_at_epoch_ms"
                ],
                "dispatch_expires_at_epoch_ms": dispatched[
                    "dispatch_expires_at_epoch_ms"
                ],
                "durable_policy": dispatched["durable_policy"],
            }
        )
        return dispatched

    response_body = b'{"items":[{"id":"one"}],"nextCursor":"cursor:next"}'
    response_body_sha256 = (
        "sha256:" + hashlib.sha256(response_body).hexdigest()
    )

    with ExitStack() as stack:
        stack.enter_context(
            patch.object(
                runtime,
                "atomic_release_authorization_enabled",
                return_value=True,
            )
        )
        stack.enter_context(
            patch.object(
                runtime,
                "_release_authorization_base_url",
                return_value="",
            )
        )
        stack.enter_context(
            patch.object(
                runtime,
                "_require_development_release_authorization_fallback",
                return_value=None,
            )
        )
        stack.enter_context(
            patch.object(
                runtime,
                "start_runtime_workers",
                return_value=None,
            )
        )
        stack.enter_context(
            patch.object(
                runtime.db,
                "reserve_release_authorization_v2",
                side_effect=reserve_v2,
            )
        )
        stack.enter_context(
            patch.object(
                runtime.db,
                "dispatch_release_authorization_v2",
                side_effect=dispatch_v2,
            )
        )
        stack.enter_context(
            patch.object(
                runtime.db,
                "complete_release_authorization_v2",
                side_effect=complete_v2,
            )
        )
        stack.enter_context(
            patch.object(
                runtime.db,
                "claim_release_credential_issuance",
                side_effect=claim_credential,
            )
        )
        stack.enter_context(
            patch.object(
                runtime.db,
                "get_credential",
                side_effect=get_credential,
            )
        )
        for legacy_name in (
            "reserve_release_authorization",
            "dispatch_release_authorization",
            "complete_release_authorization",
            "cancel_release_authorization_if_present",
        ):
            stack.enter_context(
                patch.object(
                    runtime.db,
                    legacy_name,
                    side_effect=reject_v1,
                )
            )

        uncertain_expected, uncertain_request = expected_case(
            "uncertain-reserve"
        )
        uncertain_claims = durable_claims(uncertain_expected)
        uncertain_binding = runtime.durable_policy_reserve_binding(
            uncertain_expected,
            uncertain_claims,
        )
        uncertain_guard = runtime.ReleaseAuthorizationGuard(
            uncertain_expected,
            durable_policy=uncertain_binding,
        )

        def reserve_then_lose_response(**kwargs: Any) -> dict[str, Any]:
            reserve_v2(**kwargs)
            raise RuntimeError("v2 reserve response lost")

        with patch.object(
            runtime.db,
            "reserve_release_authorization_v2",
            side_effect=reserve_then_lose_response,
        ):
            assert_raises(
                runtime.ReleaseAuthorizationClientError,
                lambda: runtime.reserve_expected_release_authorization(
                    guard=uncertain_guard,
                    operation_context=operation_context,
                    canonical_request=uncertain_request,
                    shared_quotas=[],
                    durable_policy_claims=uncertain_claims,
                ),
                "uncertain Python v2 reserve did not fail closed",
            )
        if (
            uncertain_guard.cleanup_error
            or uncertain_guard.cleanup_result is None
            or uncertain_guard.cleanup_result.get(
                "durable_policy", {}
            ).get("state")
            != "aborted"
            or (
                "complete:v2:not_forwarded",
                uncertain_expected.attempt_id,
            )
            not in coordinator_events
        ):
            raise AssertionError(
                "uncertain Python v2 reserve did not cancel through v2"
            )

        _, forwarded_guard, _, forwarded = reserve_case("forwarded")
        dispatch_case(forwarded)
        traversal_claim = next(
            claim
            for claim in reservations[forwarded["attempt_id"]]["claims"]
            if claim["type"] == "traversalBudget"
        )
        forwarded_evidence = [
            {
                "constraint_id": "python-v2-traversal",
                "lineage_digest": traversal_claim["lineage_digest"],
                "request_cursor_digest": traversal_claim[
                    "request_cursor_digest"
                ],
                "response_digest": response_body_sha256,
                "next_cursor_digest": _release_lock_digest("cursor:next"),
                "record_count": 1,
                "decoded_bytes": len(response_body),
                "validation": "passed",
            }
        ]
        committed = runtime.complete_release_authorization(
            attempt_id=forwarded["attempt_id"],
            binding_digest=forwarded["binding_digest"],
            outcome="forwarded",
            previous_lifecycle=forwarded,
            durable_completion={
                "response_evidence": forwarded_evidence,
                "response_body_sha256": response_body_sha256,
                "dispatch_deadline_at_epoch_ms": forwarded[
                    "dispatch_expires_at_epoch_ms"
                ],
            },
        )
        forwarded_guard.mark_terminal()
        if (
            committed.get("state") != "committed"
            or committed.get("durable_policy", {}).get("state")
            != "committed"
            or committed["durable_policy"]["response_body_sha256"]
            != response_body_sha256
        ):
            raise AssertionError(
                f"Python v2 forwarded completion was not retained: {committed}"
            )

        denied_expected, denied_guard, _, denied = reserve_case("denied")
        completion_modes[denied_expected.attempt_id] = "denied"
        dispatch_case(denied)
        denied_terminal = runtime.complete_release_authorization(
            attempt_id=denied["attempt_id"],
            binding_digest=denied["binding_digest"],
            outcome="forwarded",
            previous_lifecycle=denied,
            durable_completion={
                "response_evidence": forwarded_evidence,
                "response_body_sha256": response_body_sha256,
                "dispatch_deadline_at_epoch_ms": denied[
                    "dispatch_expires_at_epoch_ms"
                ],
            },
        )
        denied_guard.mark_terminal()
        if denied_terminal.get("durable_policy", {}).get("state") != "denied":
            raise AssertionError(
                f"Python v2 response denial was not closed: {denied_terminal}"
            )

        mismatched_expected, _, _, mismatched = reserve_case(
            "mismatched-terminal-evidence"
        )
        completion_modes[
            mismatched_expected.attempt_id
        ] = "mismatched_evidence"
        dispatch_case(mismatched)
        assert_raises(
            runtime.ReleaseAuthorizationClientError,
            lambda: runtime.complete_release_authorization(
                attempt_id=mismatched["attempt_id"],
                binding_digest=mismatched["binding_digest"],
                outcome="forwarded",
                previous_lifecycle=mismatched,
                durable_completion={
                    "response_evidence": forwarded_evidence,
                    "response_body_sha256": response_body_sha256,
                    "dispatch_deadline_at_epoch_ms": mismatched[
                        "dispatch_expires_at_epoch_ms"
                    ],
                },
            ),
            "Python v2 completion accepted changed durable evidence",
        )

        _, unknown_guard, _, unknown = reserve_case("unknown")
        dispatch_case(unknown)
        unknown_terminal = runtime.complete_release_authorization(
            attempt_id=unknown["attempt_id"],
            binding_digest=unknown["binding_digest"],
            outcome="unknown",
            previous_lifecycle=unknown,
            durable_completion={
                "response_evidence": [],
                "response_body_sha256": response_body_sha256,
                "dispatch_deadline_at_epoch_ms": unknown[
                    "dispatch_expires_at_epoch_ms"
                ],
                "failure_reason": (
                    "provider_outcome_or_response_validation_uncertain"
                ),
                "uncertainty": "charged_fail_closed",
            },
        )
        unknown_guard.mark_terminal()
        if (
            unknown_terminal.get("state") != "committed_indeterminate"
            or unknown_terminal.get("durable_policy", {}).get("state")
            != "indeterminate"
            or unknown_terminal["durable_policy"].get("uncertainty")
            != "charged_fail_closed"
        ):
            raise AssertionError(
                f"Python v2 unknown completion was not charged: {unknown_terminal}"
            )
        mismatched_unknown_terminal = copy.deepcopy(unknown_terminal)
        mismatched_unknown_terminal["durable_policy"]["state"] = "committed"
        assert_raises(
            runtime.ReleaseAuthorizationClientError,
            lambda: runtime.validate_complete_release_authorization_response(
                mismatched_unknown_terminal,
                attempt_id=unknown["attempt_id"],
                binding_digest=unknown["binding_digest"],
                outcome="unknown",
                grant_id=None,
                approval_request_id=None,
                previous_lifecycle=unknown,
            ),
            "Python v2 unknown accepted a committed durable terminal",
        )

        _, refund_guard, _, refund = reserve_case("refund")
        refunded = refund_guard.cancel_not_forwarded_once()
        if (
            refunded is None
            or refunded.get("state") != "cancelled"
            or refunded.get("durable_policy", {}).get("state") != "aborted"
            or refund_guard.cancel_not_forwarded_once() is not refunded
        ):
            raise AssertionError(
                f"Python v2 pre-dispatch refund was not exactly once: {refunded}"
            )

        dispatch_calls_before_downgrade = coordinator_events.count(
            ("dispatch:v2", refund["attempt_id"])
        )
        assert_raises(
            runtime.ReleaseAuthorizationClientError,
            lambda: runtime.dispatch_release_authorization(
                attempt_id=refund["attempt_id"],
                binding_digest=refund["binding_digest"],
                previous_lifecycle=refund,
            ),
            "Python v2 lifecycle accepted a v1-shaped dispatch",
        )
        if (
            coordinator_events.count(("dispatch:v2", refund["attempt_id"]))
            != dispatch_calls_before_downgrade
        ):
            raise AssertionError(
                "Python v2 downgrade reached the durable dispatch backend"
            )

        decision_expected, _ = expected_case(
            "nonapplicable-traversal"
        )
        nonapplicable_claims = durable_claims(
            decision_expected,
            traversal_operations=["test.other"],
            include_sliding_budgets=False,
        )
        if nonapplicable_claims:
            raise AssertionError(
                "nonapplicable traversal emitted a durable policy claim"
            )
        decision_v1_reserved = {
            "authorized": True,
            "state": "reserved",
            "reason": "reserved",
            "attempt_id": decision_expected.attempt_id,
            "binding_digest": decision_expected.binding_digest,
            "idempotent_replay": False,
            "grant_id": None,
            "approval_request_id": None,
            "reservation_expires_at_epoch_ms": (
                int(time.time() * 1000) + 60_000
            ),
            "dispatch_started_at_epoch_ms": None,
            "dispatch_expires_at_epoch_ms": None,
            "completion_outcome": None,
            "retry_after_seconds": 0,
            "quotas": [],
            "api_version": "catchplate.releaseAuthorization/v1",
        }
        decision_authority = runtime.credential_lease_request_authority(
            decision_expected,
            decision_v1_reserved,
            operation_context=operation_context,
            controlled=True,
        )
        if (
            decision_authority is None
            or runtime.credential_lease_release_authorization(
                decision_expected,
                decision_v1_reserved,
            )
            is not None
        ):
            raise AssertionError(
                "nonapplicable traversal did not retain v1 request authority"
            )
        claims_before_decision_bound = len(issuance_claims)
        runtime.get_credential(
            credential_id,
            request_authority=decision_authority,
            release_authorization=None,
            expected_release_identity=decision_expected,
            jit_policy={},
        )
        decision_claim = issuance_claims[-1]
        if (
            len(issuance_claims) != claims_before_decision_bound + 1
            or decision_claim.get("release_kind") != "decisionBound"
            or decision_claim.get("operation_context") != operation_context
            or decision_claim.get("durable_policy") is not None
        ):
            raise AssertionError(
                "nonapplicable traversal did not preserve decision-bound authority"
            )
        claims_before_uncontrolled = len(issuance_claims)
        runtime.get_credential(credential_id)
        if len(issuance_claims) != claims_before_uncontrolled:
            raise AssertionError(
                "truly uncontrolled credential lookup minted request authority"
            )

        downgrade_expected, _, downgrade_reserved, _ = reserve_case(
            "credential-downgrade"
        )
        downgraded_release = runtime.credential_lease_release_authorization(
            downgrade_expected,
            downgrade_reserved,
        )
        if downgraded_release is None:
            raise AssertionError("v2 downgrade fixture lacked release authority")
        downgraded_release["apiVersion"] = (
            "catchplate.credentialLeaseReleaseAuthorization/v1"
        )
        assert_raises(
            runtime.ReleaseAuthorizationClientError,
            lambda: runtime.get_credential(
                credential_id,
                request_authority=runtime.credential_lease_request_authority(
                    downgrade_expected,
                    downgrade_reserved,
                    operation_context=operation_context,
                    controlled=True,
                ),
                release_authorization=downgraded_release,
                expected_release_identity=downgrade_expected,
                jit_policy={},
            ),
            "credential release v2 accepted an authority downgrade",
        )


def exercise_proxy_discard_header_jit_transaction(
    app_module: Any,
    policy_engine: Any,
    credential_policy_type: Any,
    db: Any,
    backend: str,
) -> None:
    stored_credential = db.create_credential(
        name=f"{backend} proxy integration credential",
        kind="bearer",
        secret=f"secret-{backend}",
        metadata={"test_fixture": f"{backend}-proxy-integration"},
    )
    credential_policy = credential_policy_type(
        id=stored_credential["id"],
        provider="generic",
        provider_subject=None,
        scopes=(),
        injection={"type": "bearer"},
    )
    principal = SimpleNamespace(
        id=f"agent:{backend}:proxy-integration",
        required_headers={"x-agent-selector": "bound-agent"},
    )
    route = SimpleNamespace(
        id=f"route:{backend}:proxy-integration",
        principals=(principal.id,),
        scheme="https",
        host="upstream.invalid",
        port=443,
        methods=frozenset({"PUT"}),
        match_path=lambda path: {} if path == "/integration" else None,
        credential_ref=credential_policy.id,
        adapter_type="npm.registry",
        adapter_config={
            "request": {
                "allowedHeaders": [
                    "accept",
                    "content-type",
                    "x-required-provider",
                ],
                "allowedMediaTypes": ["application/json"],
                "allowedQueryKeys": [],
                "maxBodyBytes": 1024,
                "discardHeaders": ["npm-session"],
                "requiredHeaders": {
                    "x-required-provider": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": 64,
                    }
                },
            }
        },
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
    adapter_state = {"reintroduce_discarded_header": False}
    adapter_events: list[str] = []

    class Adapter:
        def validate_credential_metadata(self, *_args: Any) -> Any:
            adapter_events.append("validate_credential_metadata")
            return policy_engine.PolicyDecision(True)

        def validate_request(self, *_args: Any) -> Any:
            flow = _args[0]
            normalized_headers = {
                str(name).lower() for name in flow.request.headers
            }
            if "npm-session" in normalized_headers:
                raise AssertionError("discarded npm-session reached adapter validation")
            if "x-agent-selector" in normalized_headers:
                raise AssertionError("principal selector reached provider admission")
            if flow.request.headers.get("x-required-provider") != "provider-bound":
                raise AssertionError("provider required header was not preserved")
            adapter_events.append("validate_request")
            return policy_engine.PolicyDecision(True)

        def operation_fields(self, *args: Any) -> dict[str, str]:
            adapter_events.append("operation_fields")
            return {
                "operation": "npm.publish",
                "bodySha256": "sha256:"
                + hashlib.sha256(args[0].request.raw_content).hexdigest(),
            }

        def validate_credential(self, *_args: Any) -> Any:
            adapter_events.append("validate_credential")
            return policy_engine.PolicyDecision(True)

        def rewrite_request(self, *args: Any) -> Any:
            adapter_events.append("rewrite_request")
            if adapter_state["reintroduce_discarded_header"]:
                args[0].request.headers["npm-session"] = "rewrite-reintroduced"
            return policy_engine.PolicyDecision(True)

    snapshot = SimpleNamespace(
        hash="sha256:" + "d" * 64,
        routes=(route,),
        principals={principal.id: principal},
        credentials={credential_policy.id: credential_policy},
        identify_principal=lambda *_args: principal,
        match_route=lambda *_args: SimpleNamespace(route=route, params={}),
    )
    advance_active_policy_hash(db, snapshot.hash)
    credential = {
        "id": credential_policy.id,
        "kind": "bearer",
        "secret": f"secret-{backend}",
        "credential_version": int(stored_credential["credential_version"]),
        "metadata": {},
    }

    use_buffered_body = object()

    def request_flow(
        session_value: str,
        body: bytes,
        *,
        url: str = "https://upstream.invalid/integration",
        content_type: str | None = "application/json",
        extra_headers: dict[str, str] | None = None,
        raw_content: Any = use_buffered_body,
        get_content_result: Any = use_buffered_body,
        get_content_error: Exception | None = None,
    ) -> Any:
        headers = {
            "accept": "application/json",
            "npm-session": session_value,
            "x-agent-selector": "bound-agent",
            "x-required-provider": "provider-bound",
        }
        if content_type is not None:
            headers["content-type"] = content_type
        headers.update(extra_headers or {})
        request = SimpleNamespace(
            method="PUT",
            pretty_url=url,
            headers=headers,
            raw_content=body if raw_content is use_buffered_body else raw_content,
            query={},
        )
        content_access = {"calls": 0}

        def get_content(strict: bool = True) -> Any:
            del strict
            content_access["calls"] += 1
            if get_content_error is not None:
                raise get_content_error
            if get_content_result is use_buffered_body:
                if not isinstance(request.raw_content, bytes):
                    raise ValueError("request body is not buffered bytes")
                return request.raw_content
            return get_content_result

        request.get_content = get_content
        request.test_content_access = content_access
        return SimpleNamespace(
            request=request,
            client_conn=SimpleNamespace(peername=("127.0.0.1", 43124)),
            metadata={},
        )

    audit_records: list[dict[str, Any]] = []

    def capture_audit(
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

    reserve_payload_mutation: Any = None

    def canonical_digest(value: dict[str, Any]) -> str:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
        return "sha256:" + hashlib.sha256(encoded).hexdigest()

    def canonical_operation_digest(value: dict[str, Any]) -> str:
        return canonical_digest(
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

    def reserve_via_control_plane(**kwargs: Any) -> dict[str, Any]:
        expected = kwargs["guard"].expected
        payload = {
            "apiVersion": "catchplate.releaseAuthorizationReserve/v1",
            "attemptId": expected.attempt_id,
            "flowId": expected.flow_id,
            "principalId": expected.principal_id,
            "routeId": expected.route_id,
            "credentialRef": expected.credential_ref,
            "credentialVersion": expected.credential_version,
            "policyHash": expected.policy_hash,
            "requestDigest": expected.request_digest,
            "operationDigest": expected.operation_digest,
            "operationContext": kwargs["operation_context"],
            "canonicalRequest": json.loads(
                json.dumps(kwargs["canonical_request"])
            ),
        }
        if reserve_payload_mutation is not None:
            reserve_payload_mutation(payload)
        try:
            request = app_module.DataPlaneReleaseAuthorizationReserve.model_validate(
                payload
            )
            response = app_module.data_plane_release_authorization_reserve(
                request,
                app_module.DATA_PLANE_RELEASE_AUTHORIZATION_TOKEN,
            )
        except (app_module.HTTPException, app_module.ValidationError) as exc:
            raise policy_engine.runtime.ReleaseAuthorizationClientError(
                "control-plane release authorization rejected the reserve payload"
            ) from exc
        result = policy_engine.runtime._normalized_release_authorization_response(
            response,
            attempt_id=expected.attempt_id,
        )
        policy_engine.runtime.validate_reserve_release_authorization_response(
            result,
            attempt_id=expected.attempt_id,
            require_jit_grant=expected.require_jit_grant,
            expected_binding_digest=expected.binding_digest,
            expected_shared_quotas=kwargs["shared_quotas"],
        )
        if result.get("state") == "denied":
            kwargs["guard"].disarm_denial()
        else:
            kwargs["guard"].promote_reserved()
        return result

    class ProviderSocketBoundary:
        def __init__(self) -> None:
            self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._listener.bind(("127.0.0.1", 0))
            self._listener.listen(4)
            self._listener.settimeout(0.05)
            self.port = int(self._listener.getsockname()[1])
            self._stop = threading.Event()
            self._lock = threading.Lock()
            self.contact_count = 0
            self.effect_count = 0
            self.last_request: dict[str, Any] | None = None
            self._thread = threading.Thread(target=self._serve, daemon=True)
            self._thread.start()

        def _serve(self) -> None:
            while not self._stop.is_set():
                try:
                    connection, _ = self._listener.accept()
                except TimeoutError:
                    continue
                except OSError:
                    return
                with connection:
                    connection.settimeout(2)
                    reader = connection.makefile("rb")
                    request_line = reader.readline(8193)
                    headers: dict[str, str] = {}
                    while True:
                        line = reader.readline(8193)
                        if line in {b"\r\n", b""}:
                            break
                        name, value = line.decode("latin-1").split(":", 1)
                        headers[name.strip().lower()] = value.strip()
                    content_length = int(headers.get("content-length", "0"))
                    body = reader.read(content_length)
                    with self._lock:
                        self.contact_count += 1
                        self.last_request = {
                            "request_line": request_line.decode("ascii").strip(),
                            "headers": headers,
                            "body": body,
                        }
                        valid = (
                            request_line.startswith(b"PUT /integration HTTP/1.1")
                            and headers.get("authorization")
                            == f"Bearer secret-{backend}"
                            and "npm-session" not in headers
                            and body == provider_body
                        )
                        if valid:
                            self.effect_count += 1
                    status = b"204 No Content" if valid else b"400 Bad Request"
                    connection.sendall(
                        b"HTTP/1.1 "
                        + status
                        + b"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    )

        def forward(self, provider_flow: Any) -> None:
            if (
                provider_flow.metadata.get("catchplate_release_state")
                != "dispatching"
            ):
                raise AssertionError(
                    "provider socket observed a request outside dispatching state"
                )
            parts = urlsplit(provider_flow.request.pretty_url)
            connection = http.client.HTTPConnection(
                "127.0.0.1",
                self.port,
                timeout=2,
            )
            connection.putrequest(
                provider_flow.request.method,
                urlunsplit(("", "", parts.path or "/", parts.query, "")),
                skip_host=True,
                skip_accept_encoding=True,
            )
            normalized_headers = {
                str(name).lower(): str(value)
                for name, value in provider_flow.request.headers.items()
            }
            normalized_headers["host"] = parts.netloc
            normalized_headers["content-length"] = str(
                len(provider_flow.request.raw_content)
            )
            for name, value in normalized_headers.items():
                connection.putheader(name, value)
            connection.endheaders(provider_flow.request.raw_content)
            response = connection.getresponse()
            response.read()
            connection.close()
            if response.status != 204:
                raise AssertionError(
                    f"provider socket rejected forwarded request: {response.status}"
                )

        def snapshot(self) -> tuple[int, int, dict[str, Any] | None]:
            with self._lock:
                return self.contact_count, self.effect_count, self.last_request

        def close(self) -> None:
            self._stop.set()
            self._thread.join(timeout=2)
            self._listener.close()

    with ExitStack() as stack:
        stack.enter_context(patch.object(policy_engine, "get_policy_snapshot", return_value=snapshot))
        stack.enter_context(patch.object(app_module, "get_policy_snapshot", return_value=snapshot))
        stack.enter_context(patch.object(policy_engine, "get_adapter", return_value=Adapter()))
        stack.enter_context(patch.object(policy_engine.runtime, "prune_expired_caches", return_value=None))
        stack.enter_context(
            patch.object(
                policy_engine.runtime,
                "log_request",
                side_effect=capture_audit,
            )
        )
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
        credential_generation_read = stack.enter_context(
            patch.object(
                policy_engine.runtime,
                "get_credential_generation",
                return_value={
                    key: value
                    for key, value in credential.items()
                    if key != "secret"
                },
            )
        )
        credential_read = stack.enter_context(
            patch.object(policy_engine.runtime, "get_credential", return_value=credential)
        )
        control_plane_secret_read = stack.enter_context(
            patch.object(
                app_module.db,
                "get_credential",
                side_effect=AssertionError(
                    "control-plane reserve read a dispatch-secret credential"
                ),
            )
        )
        stack.enter_context(
            patch.object(app_module, "_release_authorization_maintenance")
        )
        reserve_call = stack.enter_context(
            patch.object(
                policy_engine.runtime,
                "reserve_expected_release_authorization",
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

        provider_body = b'{"name":"package","version":"1.2.3"}'
        provider_boundary = ProviderSocketBoundary()
        stack.callback(provider_boundary.close)

        def release_state_counts() -> dict[str, int]:
            with db.connect() as conn:
                attempts = conn.execute(
                    "SELECT COUNT(*) AS count FROM release_authorization_attempts "
                    "WHERE route_id = ?",
                    (route.id,),
                ).fetchone()
                approvals = conn.execute(
                    "SELECT COUNT(*) AS count FROM approval_requests "
                    "WHERE route_id = ?",
                    (route.id,),
                ).fetchone()
                grants = conn.execute(
                    "SELECT COUNT(*) AS count FROM approval_grants "
                    "WHERE route_id = ?",
                    (route.id,),
                ).fetchone()
                quota_uses = conn.execute(
                    "SELECT COALESCE(SUM(count), 0) AS count "
                    "FROM rate_limit_counters WHERE route_id = ?",
                    (route.id,),
                ).fetchone()
            return {
                "attempts": int(attempts["count"]),
                "approvals": int(approvals["count"]),
                "grants": int(grants["count"]),
                "quota_uses": int(quota_uses["count"]),
            }

        def preflight_effect_snapshot() -> dict[str, Any]:
            return {
                "adapter_rewrites": adapter_events.count("rewrite_request"),
                "reserve_calls": reserve_call.call_count,
                "credential_generation_reads": (
                    credential_generation_read.call_count
                ),
                "credential_reads": credential_read.call_count,
                "control_plane_secret_reads": (
                    control_plane_secret_read.call_count
                ),
                "release_state": release_state_counts(),
                "provider": provider_boundary.snapshot()[:2],
            }

        def request_wire_snapshot(candidate_flow: Any) -> dict[str, Any]:
            return {
                "url": candidate_flow.request.pretty_url,
                "headers": tuple(
                    policy_engine._physical_request_header_entries(
                        candidate_flow
                    )
                ),
                "body": candidate_flow.request.raw_content,
            }

        def assert_preflight_denied(
            label: str,
            denied_flow: Any,
            *,
            status_code: int,
            error: str,
            content_access_calls: int = 0,
        ) -> None:
            before = preflight_effect_snapshot()
            before_request = request_wire_snapshot(denied_flow)
            denied = policy_engine.evaluate_request(denied_flow)
            after = preflight_effect_snapshot()
            after_request = request_wire_snapshot(denied_flow)
            if (
                denied.decision.allowed
                or denied.decision.status_code != status_code
                or denied.decision.payload.get("error") != error
                or denied_flow.metadata.get("catchplate_release_state") is not None
                or "authorization"
                in {
                    str(name).lower()
                    for name in denied_flow.request.headers
                }
            ):
                raise AssertionError(
                    f"{label} did not fail closed during request preflight: "
                    f"{denied.decision} {denied_flow.metadata}"
                )
            if (
                denied_flow.request.test_content_access["calls"]
                != content_access_calls
            ):
                raise AssertionError(
                    f"{label} performed unexpected decoded body access: "
                    f"{denied_flow.request.test_content_access}"
                )
            if after != before:
                raise AssertionError(
                    f"{label} mutated adapter, reserve, approval, quota, "
                    "credential, or provider state: "
                    f"before={before} after={after}"
                )
            if after_request != before_request:
                raise AssertionError(
                    f"{label} changed denied request URL, physical headers, "
                    f"or body: before={before_request} after={after_request}"
                )

        for label, path in (
            ("raw dot segment", "/public/../admin"),
            ("encoded dot segment", "/public/%2E%2E/admin"),
            ("encoded backslash", "/public/%5Cadmin"),
            ("raw backslash", "/public\\admin"),
            ("invalid percent escape", "/public/%zz/admin"),
            ("double encoding", "/public/%252e%252e/admin"),
            ("empty path segment", "/public//admin"),
            ("non-npm encoded slash", "/public/value%2fadmin"),
        ):
            assert_preflight_denied(
                label,
                request_flow(
                    f"npm-session-path-{label.replace(' ', '-')}",
                    provider_body,
                    url="https://upstream.invalid" + path,
                ),
                status_code=400,
                error="invalid_request_target",
            )

        assert_preflight_denied(
            "unavailable raw body",
            request_flow(
                "npm-session-raw-unavailable",
                provider_body,
                raw_content=None,
            ),
            status_code=400,
            error="request_body_not_buffered",
        )
        assert_preflight_denied(
            "oversized raw body",
            request_flow(
                "npm-session-oversized",
                b"x" * 1025,
            ),
            status_code=413,
            error="request_body_too_large",
        )
        assert_preflight_denied(
            "transfer encoding",
            request_flow(
                "npm-session-transfer-encoding",
                provider_body,
                extra_headers={"transfer-encoding": "chunked"},
            ),
            status_code=400,
            error="request_transfer_encoding_denied",
        )
        assert_preflight_denied(
            "malformed content length",
            request_flow(
                "npm-session-malformed-content-length",
                provider_body,
                extra_headers={"content-length": "12x"},
            ),
            status_code=400,
            error="request_content_length_invalid",
        )
        assert_preflight_denied(
            "mismatched content length",
            request_flow(
                "npm-session-mismatched-content-length",
                provider_body,
                extra_headers={"content-length": str(len(provider_body) + 1)},
            ),
            status_code=400,
            error="request_content_length_mismatch",
        )
        for label, encoding in (
            ("non-identity content encoding", "gzip"),
            ("noncanonical identity content encoding", "Identity"),
        ):
            assert_preflight_denied(
                label,
                request_flow(
                    f"npm-session-{label.replace(' ', '-')}",
                    provider_body,
                    extra_headers={"content-encoding": encoding},
                ),
                status_code=415,
                error="request_content_encoding_denied",
            )
        identity_flow = request_flow(
            "npm-session-identity-content-encoding",
            provider_body,
            extra_headers={"content-encoding": "identity"},
        )
        identity_before = preflight_effect_snapshot()
        identity_decision = policy_engine.preflight_request_admission(
            identity_flow,
            route,
            policy_engine._normalized_request_headers(identity_flow),
        )
        if (
            not identity_decision.allowed
            or identity_flow.request.test_content_access["calls"] != 1
            or "content-encoding"
            not in {
                str(name).lower()
                for name in identity_flow.request.headers
            }
            or preflight_effect_snapshot() != identity_before
        ):
            raise AssertionError(
                "raw preflight did not preserve exact identity content encoding "
                f"through semantic admission: {identity_decision}"
            )
        policy_engine._strip_identity_content_encoding(identity_flow, "identity")
        if "content-encoding" in {
            str(name).lower()
            for name in identity_flow.request.headers
        }:
            raise AssertionError(
                "exact identity content encoding was not removed after semantic admission"
            )
        assert_preflight_denied(
            "wrong media type",
            request_flow(
                "npm-session-wrong-media",
                provider_body,
                content_type="text/plain",
            ),
            status_code=415,
            error="request_content_type_denied",
        )
        assert_preflight_denied(
            "duplicate content type parameter",
            request_flow(
                "npm-session-duplicate-content-type-parameter",
                provider_body,
                content_type=(
                    "application/json; charset=utf-8; CHARSET=utf-8"
                ),
            ),
            status_code=415,
            error="request_content_type_denied",
        )
        assert_preflight_denied(
            "missing media type",
            request_flow(
                "npm-session-missing-media",
                provider_body,
                content_type=None,
            ),
            status_code=415,
            error="request_content_type_required",
        )
        assert_preflight_denied(
            "throwing decoded body access",
            request_flow(
                "npm-session-get-content-error",
                provider_body,
                get_content_error=ValueError("fixture decoded access failure"),
            ),
            status_code=400,
            error="request_body_unavailable",
            content_access_calls=1,
        )
        assert_preflight_denied(
            "non-byte decoded body access",
            request_flow(
                "npm-session-get-content-non-byte",
                provider_body,
                get_content_result="not bytes",
            ),
            status_code=400,
            error="request_body_unavailable",
            content_access_calls=1,
        )
        assert_preflight_denied(
            "changed decoded body access",
            request_flow(
                "npm-session-get-content-changed",
                provider_body,
                get_content_result=b'{"different":true}',
            ),
            status_code=400,
            error="request_body_unavailable",
            content_access_calls=1,
        )
        original_body_mode = route.adapter_config["request"].get("bodyMode")
        route.adapter_config["request"]["bodyMode"] = "none"
        try:
            assert_preflight_denied(
                "forbidden request body",
                request_flow(
                    "npm-session-body-forbidden",
                    provider_body,
                ),
                status_code=403,
                error="request_body_not_allowed",
            )
        finally:
            if original_body_mode is None:
                route.adapter_config["request"].pop("bodyMode", None)
            else:
                route.adapter_config["request"]["bodyMode"] = original_body_mode

        def remove_payload_field(field: str) -> Any:
            return lambda payload: payload.pop(field, None)

        def replace_payload_field(field: str, value: Any) -> Any:
            return lambda payload: payload.__setitem__(field, value)

        def mismatch_digest_field(field: str) -> Any:
            def mutate(payload: dict[str, Any]) -> None:
                current = str(payload[field])
                replacement = "0" if current[7] != "0" else "1"
                payload[field] = current[:7] + replacement + current[8:]

            return mutate

        def make_canonical_malformed(payload: dict[str, Any]) -> None:
            payload["canonicalRequest"]["request"]["query"] = {
                "not": "a canonical query pair list"
            }

        def make_canonical_mismatched(payload: dict[str, Any]) -> None:
            canonical_request = payload["canonicalRequest"]
            canonical_request["principal"] = "agent:canonical-substitution"
            payload["requestDigest"] = canonical_digest(canonical_request)
            payload["operationDigest"] = canonical_operation_digest(
                canonical_request
            )



        jit_provider_baseline = provider_boundary.snapshot()[:2]
        jit_rewrite_baseline = adapter_events.count("rewrite_request")

        pending_flow = request_flow("npm-session-first-process", provider_body)
        pending = policy_engine.evaluate_request(pending_flow)
        if (
            pending.decision.allowed
            or pending.decision.status_code != 428
            or pending.decision.payload.get("error") != "catchplate_approval_required"
        ):
            raise AssertionError(f"atomic proxy did not create a retry approval: {pending.decision}")
        if pending.decision.payload.get("approval_url") != (
            f"/approvals/{pending.decision.payload['approval_id']}"
        ):
            raise AssertionError(
                f"atomic proxy did not return an exact operator approval link: {pending.decision}"
            )
        pending_approval = db.get_approval_request(
            pending.decision.payload["approval_id"]
        )
        if (
            not pending_approval
            or pending_approval["canonical_request"].get("v") != 2
            or pending_approval["canonical_request"]["request"].get(
                "discard_headers"
            )
            != ["npm-session"]
            or "npm-session"
            in pending_approval["canonical_request"]["request"]["headers"]
            or "x-agent-selector"
            in pending_approval["canonical_request"]["request"]["headers"]
            or pending_approval["canonical_request"]["request"]["headers"].get(
                "x-required-provider"
            )
            != "provider-bound"
        ):
            raise AssertionError(
                "discard-header approval did not persist the exact v2 canonical request: "
                f"{pending_approval}"
            )
        approved = db.approve_request(
            pending.decision.payload["approval_id"],
            ttl_seconds=60,
        )
        if not approved or approved.get("status") != "approved":
            raise AssertionError(f"atomic proxy approval did not activate: {approved}")

        def reserve_then_lose_response(**kwargs: Any) -> dict[str, Any]:
            reserved = reserve_via_control_plane(**kwargs)
            if reserved.get("state") != "reserved":
                raise AssertionError(
                    "post-commit response-loss fixture did not create a reservation"
                )
            raise policy_engine.runtime.ReleaseAuthorizationClientError(
                "post-commit reserve response lost"
            )

        reserve_call.side_effect = reserve_then_lose_response
        pre_loss_secret_reads = credential_read.call_count
        post_commit_loss_flow = request_flow(
            "npm-session-post-commit-response-loss",
            provider_body,
        )
        post_commit_loss = policy_engine.evaluate_request(post_commit_loss_flow)
        reserve_call.side_effect = reserve_via_control_plane
        post_commit_guard = post_commit_loss_flow.metadata.get(
            "catchplate_release_authorization_guard"
        )
        post_commit_attempt_id = (
            post_commit_guard.expected.attempt_id
            if isinstance(
                post_commit_guard,
                policy_engine.runtime.ReleaseAuthorizationGuard,
            )
            else None
        )
        with db.connect() as conn:
            post_commit_attempt = conn.execute(
                "SELECT state FROM release_authorization_attempts "
                "WHERE attempt_id = ?",
                (post_commit_attempt_id,),
            ).fetchone()
            post_commit_cancellations = conn.execute(
                "SELECT COUNT(*) AS count FROM release_authorization_events "
                "WHERE attempt_id = ? AND state = 'cancelled'",
                (post_commit_attempt_id,),
            ).fetchone()
        if (
            post_commit_loss.decision.allowed
            or post_commit_loss.decision.payload.get("error")
            != "release_authorization_reserve_uncertain"
            or credential_read.call_count != pre_loss_secret_reads
            or post_commit_guard is None
            or not post_commit_guard.cleanup_emitted
            or post_commit_guard.cleanup_error
            or post_commit_guard.phase != "terminal"
            or post_commit_attempt is None
            or post_commit_attempt["state"] != "cancelled"
            or int(post_commit_cancellations["count"]) != 1
            or provider_boundary.snapshot()[:2] != jit_provider_baseline
        ):
            raise AssertionError(
                "post-commit reserve response loss did not exactly cancel before "
                f"secret acquisition or provider dispatch: {post_commit_loss.decision} "
                f"{post_commit_loss_flow.metadata}"
            )

        forwarded_flow = request_flow(
            "npm-session-approved-retry",
            provider_body,
        )
        prepared = policy_engine.evaluate_request(forwarded_flow)
        if not prepared.decision.allowed or prepared.release_state != "reserved":
            raise AssertionError(f"atomic proxy did not reserve after approval: {prepared}")
        if (
            prepared.request_digest != pending.request_digest
            or prepared.operation_digest != pending.operation_digest
        ):
            raise AssertionError(
                "discarded npm-session changed the exact retry binding: "
                f"{pending.request_digest} {prepared.request_digest} "
                f"{pending.operation_digest} {prepared.operation_digest}"
            )
        if (
            "npm-session"
            in {str(name).lower() for name in forwarded_flow.request.headers}
            or forwarded_flow.request.headers.get("Authorization")
            != f"Bearer secret-{backend}"
        ):
            raise AssertionError(
                "approved retry was not discarded and credential-injected exactly: "
                f"{forwarded_flow.request.headers}"
            )
        lifecycle = forwarded_flow.metadata.get("catchplate_release_authorization") or {}
        if (
            lifecycle.get("attempt_id") != lifecycle.get("flow_id")
            or lifecycle.get("approval_request_id")
            != pending.decision.payload["approval_id"]
            or not lifecycle.get("grant_id")
        ):
            raise AssertionError(
                f"atomic proxy did not reserve and consume the exact approved grant: {lifecycle}"
            )
        dispatched = policy_engine.dispatch_release_authorization(forwarded_flow)
        if (
            not dispatched.allowed
            or forwarded_flow.metadata.get("catchplate_release_state")
            != "dispatch_authorized"
        ):
            raise AssertionError(f"atomic proxy dispatch failed: {dispatched}")
        policy_engine.mark_provider_dispatch_uncertain(forwarded_flow)
        provider_boundary.forward(forwarded_flow)
        completed = policy_engine.complete_release_authorization(
            forwarded_flow,
            "forwarded",
        )
        if not completed.allowed or forwarded_flow.metadata.get("catchplate_release_state") != "committed":
            raise AssertionError(f"atomic proxy completion failed: {completed}")

        rejected_body = b'{"name":"package","version":"1.2.4"}'
        rejected_pending_flow = request_flow(
            "npm-session-reintroduced-pending",
            rejected_body,
        )
        rejected_pending = policy_engine.evaluate_request(rejected_pending_flow)
        if (
            rejected_pending.decision.allowed
            or rejected_pending.decision.status_code != 428
        ):
            raise AssertionError(
                f"reintroduction fixture did not require its own approval: {rejected_pending}"
            )
        rejected_approved = db.approve_request(
            rejected_pending.decision.payload["approval_id"],
            ttl_seconds=60,
        )
        if not rejected_approved or rejected_approved.get("status") != "approved":
            raise AssertionError(
                f"reintroduction fixture approval failed: {rejected_approved}"
            )
        adapter_state["reintroduce_discarded_header"] = True
        rejected_retry_flow = request_flow(
            "npm-session-reintroduced-retry",
            rejected_body,
        )
        rejected_retry = policy_engine.evaluate_request(rejected_retry_flow)
        adapter_state["reintroduce_discarded_header"] = False
        if (
            rejected_retry.decision.allowed
            or rejected_retry.decision.status_code != 500
            or rejected_retry.decision.payload.get("error")
            != "discarded_header_reintroduced"
        ):
            raise AssertionError(
                "rewritten discarded header did not fail closed before forwarding: "
                f"{rejected_retry.decision}"
            )
        contacts, effects, observed_request = provider_boundary.snapshot()
        if (
            contacts != jit_provider_baseline[0] + 1
            or effects != jit_provider_baseline[1] + 1
        ):
            raise AssertionError(
                "discard-header JIT transaction did not produce exactly one "
                "additional socket-observed provider effect: "
                f"{(contacts, effects, observed_request)}"
            )
        if adapter_events.count("rewrite_request") != jit_rewrite_baseline + 5:
            raise AssertionError(
                f"pending or denied requests crossed rewrite unexpectedly: {adapter_events}"
            )
        audit_json = json.dumps(audit_records, sort_keys=True)
        for secret_session_value in (
            "npm-session-first-process",
            "npm-session-post-commit-response-loss",
            "npm-session-approved-retry",
            "npm-session-reintroduced-pending",
            "npm-session-reintroduced-retry",
            "rewrite-reintroduced",
        ):
            if secret_session_value in audit_json:
                raise AssertionError(
                    "audit evidence retained a discarded low-entropy header value"
                )
        discarded_audit_events = [
            record["event"]["discarded_request_headers"]
            for record in audit_records
            if isinstance(record.get("event"), dict)
            and isinstance(
                record["event"].get("discarded_request_headers"),
                dict,
            )
            and record["event"]["discarded_request_headers"].get(
                "present_names"
            )
            == ["npm-session"]
        ]
        if not discarded_audit_events or any(
            item.get("present_count") != 1
            or item.get("raw_values_logged") is not False
            or item.get("value_commitment") is not None
            or item.get("value_commitment_reason")
            != "no_dedicated_audit_hmac_key"
            for item in discarded_audit_events
        ):
            raise AssertionError(
                f"discarded input audit metadata was not closed and privacy-preserving: {audit_records}"
            )


def exercise_compiled_v2_reserve_fixtures(
    app_module: Any,
    policy_engine: Any,
    compile_policy_bundle: Any,
    demo_policy_bundle: Any,
    db: Any,
    backend: str,
) -> None:
    stored_credential = db.create_credential(
        name=f"{backend} compiled v2 fixture credential",
        kind="bearer",
        secret=f"secret-{backend}-compiled-v2",
        metadata={"test_fixture": f"{backend}-compiled-v2"},
    )
    credential_version = int(stored_credential["credential_version"])

    def request_flow(
        method: str,
        url: str,
        headers: dict[str, str],
        body: bytes,
    ) -> Any:
        request = SimpleNamespace(
            method=method,
            pretty_url=url,
            headers=dict(headers),
            raw_content=body,
            query=dict(parse_qsl(urlsplit(url).query, keep_blank_values=True)),
        )
        request.get_content = lambda strict=True: request.raw_content
        return SimpleNamespace(
            request=request,
            client_conn=SimpleNamespace(peername=("192.0.2.44", 43127)),
            metadata={},
        )

    def reserve(
        snapshot: Any,
        route: Any,
        principal: Any,
        canonical_request: dict[str, Any],
        *,
        numeric_credential_version: int,
    ) -> dict[str, Any]:
        attempt_id = f"attempt:{backend}:{route.id}:{uuid.uuid4()}"
        payload = {
            "apiVersion": "catchplate.releaseAuthorizationReserve/v1",
            "attemptId": attempt_id,
            "flowId": attempt_id,
            "principalId": principal.id,
            "routeId": route.id,
            "credentialRef": route.credential_ref,
            "credentialVersion": numeric_credential_version,
            "policyHash": snapshot.hash,
            "requestDigest": policy_engine._digest(canonical_request),
            "operationDigest": policy_engine._operation_digest(
                canonical_request
            ),
            "operationContext": dict(canonical_request["operation"]),
            "canonicalRequest": canonical_request,
        }
        with (
            patch.object(
                app_module,
                "get_policy_snapshot",
                return_value=snapshot,
            ),
            patch.object(app_module, "_release_authorization_maintenance"),
        ):
            response = app_module.data_plane_release_authorization_reserve(
                app_module.DataPlaneReleaseAuthorizationReserve.model_validate(
                    payload
                ),
                app_module.DATA_PLANE_RELEASE_AUTHORIZATION_TOKEN,
            )
        return response

    npm_snapshot = compile_policy_bundle(
        demo_policy_bundle(stored_credential["id"]),
        validate_schema=False,
    )
    npm_route = next(
        item
        for item in npm_snapshot.routes
        if item.adapter_type == "npm.registry"
    )
    npm_principal = npm_snapshot.principals["agent:demo"]
    tarball = b"compiled v2 npm tarball bytes"
    npm_document = {
        "_id": "@scope/compiled-v2",
        "name": "@scope/compiled-v2",
        "dist-tags": {"latest": "1.2.3"},
        "versions": {
            "1.2.3": {
                "name": "@scope/compiled-v2",
                "version": "1.2.3",
                "dist": {},
            }
        },
        "_attachments": {
            "compiled-v2-1.2.3.tgz": {
                "content_type": "application/octet-stream",
                "data": base64.b64encode(tarball).decode("ascii"),
                "length": len(tarball),
            }
        },
    }
    npm_body = json.dumps(
        npm_document,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    npm_flow = request_flow(
        "PUT",
        "https://registry.npmjs.org/@scope%2fcompiled-v2",
        {
            "content-type": "application/json",
            "npm-command": "publish",
            "npm-session": "compiled-v2-session",
            "user-agent": "npm/11.8.0 node/v24.4.1",
            "x-catchplate-agent": "demo-agent",
        },
        npm_body,
    )
    npm_preflight = policy_engine.preflight_request_admission(
        npm_flow,
        npm_route,
        policy_engine._normalized_request_headers(npm_flow),
    )
    if not npm_preflight.allowed:
        raise AssertionError(
            f"compiled npm v2 request failed preflight: {npm_preflight}"
        )
    npm_discard = policy_engine._discard_declared_request_headers(
        npm_flow,
        npm_route,
        npm_principal,
        npm_snapshot.credentials[npm_route.credential_ref],
    )
    policy_engine._strip_identity_headers(npm_flow, npm_principal)
    npm_adapter = policy_engine.get_adapter(npm_route.adapter_type)
    npm_params = {"package": "@scope%2fcompiled-v2"}
    npm_admission = npm_adapter.validate_request(
        npm_flow,
        npm_route,
        npm_params,
    )
    if not npm_admission.allowed:
        raise AssertionError(
            f"compiled npm v2 request was denied: {npm_admission}"
        )
    npm_operation = npm_adapter.operation_fields(
        npm_flow,
        npm_route,
        npm_params,
    )
    expected_integrity = "sha512-" + base64.b64encode(
        hashlib.sha512(tarball).digest()
    ).decode("ascii")
    if npm_operation.get("tarballIntegrity") != expected_integrity:
        raise AssertionError(
            f"compiled npm integrity binding is wrong: {npm_operation}"
        )
    npm_canonical = policy_engine._canonical_request(
        npm_flow,
        principal=npm_principal,
        route=npm_route,
        credential_version=policy_engine._canonical_credential_version(
            credential_version
        ),
        policy_hash=npm_snapshot.hash,
        operation_fields=npm_operation,
        forwarded_headers=policy_engine._canonical_forwarded_request_headers(
            npm_flow,
            npm_snapshot.credentials[npm_route.credential_ref],
        ),
        discard_headers=npm_discard,
    )
    if (
        npm_canonical["v"] != 2
        or npm_canonical["credential_version"]
        != policy_engine._canonical_credential_version(credential_version)
        or npm_canonical["request"]["discard_headers"] != ["npm-session"]
        or npm_route.jit.get("required") is not True
        or npm_route.jit.get("maxUses") != 1
        or "tarballIntegrity"
        not in set((npm_route.jit.get("binding") or {}).get("fields") or [])
    ):
        raise AssertionError(
            f"compiled npm v2 JIT binding is incomplete: {npm_canonical}"
        )
    advance_active_policy_hash(db, npm_snapshot.hash)
    npm_reserve = reserve(
        npm_snapshot,
        npm_route,
        npm_principal,
        npm_canonical,
        numeric_credential_version=credential_version,
    )
    if (
        npm_reserve.get("authorized")
        or npm_reserve.get("state") != "denied"
        or npm_reserve.get("reason") != "jit_grant_unavailable"
        or not npm_reserve.get("approvalRequestId")
    ):
        raise AssertionError(
            f"compiled npm v2 reserve did not preserve hardware JIT: {npm_reserve}"
        )

    generic_bundle = demo_policy_bundle(stored_credential["id"])
    generic_route_raw = next(
        item
        for item in generic_bundle["routes"]
        if item["id"] == "demo.stream"
    )
    generic_route_raw["adapter"]["config"]["request"][
        "discardHeaders"
    ] = ["x-client-retry"]
    generic_snapshot = compile_policy_bundle(
        generic_bundle,
        validate_schema=False,
    )
    generic_route = next(
        item
        for item in generic_snapshot.routes
        if item.id == "demo.stream"
    )
    generic_principal = generic_snapshot.principals["agent:demo"]
    generic_flow = request_flow(
        "GET",
        "https://demo-upstream:8443/stream-bytes",
        {
            "accept": "application/json",
            "x-client-retry": "attempt-1",
            "x-catchplate-agent": "demo-agent",
        },
        b"",
    )
    generic_preflight = policy_engine.preflight_request_admission(
        generic_flow,
        generic_route,
        policy_engine._normalized_request_headers(generic_flow),
    )
    if not generic_preflight.allowed:
        raise AssertionError(
            f"compiled generic v2 request failed preflight: {generic_preflight}"
        )
    generic_discard = policy_engine._discard_declared_request_headers(
        generic_flow,
        generic_route,
        generic_principal,
        None,
    )
    policy_engine._strip_identity_headers(generic_flow, generic_principal)
    generic_adapter = policy_engine.get_adapter(generic_route.adapter_type)
    generic_admission = generic_adapter.validate_request(
        generic_flow,
        generic_route,
        {},
    )
    if not generic_admission.allowed:
        raise AssertionError(
            f"compiled generic v2 request was denied: {generic_admission}"
        )
    generic_operation = generic_adapter.operation_fields(
        generic_flow,
        generic_route,
        {},
    )
    generic_canonical = policy_engine._canonical_request(
        generic_flow,
        principal=generic_principal,
        route=generic_route,
        credential_version=policy_engine._canonical_credential_version(0),
        policy_hash=generic_snapshot.hash,
        operation_fields=generic_operation,
        forwarded_headers=policy_engine._canonical_forwarded_request_headers(
            generic_flow,
            None,
        ),
        discard_headers=generic_discard,
    )
    if (
        generic_canonical["v"] != 2
        or generic_canonical["credential_ref"] is not None
        or generic_canonical["credential_version"]
        != policy_engine._canonical_credential_version(0)
        or generic_route.jit.get("required") is True
    ):
        raise AssertionError(
            f"compiled generic non-JIT canonical is invalid: {generic_canonical}"
        )
    advance_active_policy_hash(db, generic_snapshot.hash)
    generic_reserve = reserve(
        generic_snapshot,
        generic_route,
        generic_principal,
        generic_canonical,
        numeric_credential_version=0,
    )
    if (
        not generic_reserve.get("authorized")
        or generic_reserve.get("state") != "reserved"
        or generic_reserve.get("grantId") is not None
        or generic_reserve.get("approvalRequestId") is not None
    ):
        raise AssertionError(
            f"compiled generic non-JIT reserve is invalid: {generic_reserve}"
        )
    with patch.object(app_module, "_release_authorization_maintenance"):
        dispatched = app_module.data_plane_release_authorization_dispatch(
            app_module.DataPlaneReleaseAuthorizationDispatch.model_validate(
                {
                    "apiVersion": "catchplate.releaseAuthorizationDispatch/v1",
                    "attemptId": generic_reserve["attemptId"],
                    "bindingDigest": generic_reserve["bindingDigest"],
                }
            ),
            app_module.DATA_PLANE_RELEASE_AUTHORIZATION_TOKEN,
        )
        completed = app_module.data_plane_release_authorization_complete(
            app_module.DataPlaneReleaseAuthorizationComplete.model_validate(
                {
                    "apiVersion": "catchplate.releaseAuthorizationComplete/v1",
                    "attemptId": generic_reserve["attemptId"],
                    "bindingDigest": generic_reserve["bindingDigest"],
                    "outcome": "forwarded",
                }
            ),
            app_module.DATA_PLANE_RELEASE_AUTHORIZATION_TOKEN,
        )
    if (
        dispatched.get("state") != "dispatching"
        or dispatched.get("grantId") is not None
        or completed.get("state") != "committed"
        or completed.get("grantId") is not None
        or completed.get("approvalRequestId") is not None
    ):
        raise AssertionError(
            "compiled generic non-JIT lifecycle acquired approval identity: "
            f"{dispatched} {completed}"
        )

    absent_attempt = "attempt:compiled-v2:pre-create-transport-loss"
    absent_binding = "sha256:" + "e" * 64
    with patch.object(
        app_module,
        "_release_authorization_maintenance",
        side_effect=AssertionError(
            "bound not_forwarded cleanup ran unrelated global maintenance"
        ),
    ):
        absent_cleanup = app_module.data_plane_release_authorization_complete(
            app_module.DataPlaneReleaseAuthorizationComplete.model_validate(
                {
                    "apiVersion": "catchplate.releaseAuthorizationComplete/v1",
                    "attemptId": absent_attempt,
                    "bindingDigest": absent_binding,
                    "outcome": "not_forwarded",
                }
            ),
            app_module.DATA_PLANE_RELEASE_AUTHORIZATION_TOKEN,
        )
        mismatched_cleanup = (
            app_module.data_plane_release_authorization_complete(
                app_module.DataPlaneReleaseAuthorizationComplete.model_validate(
                    {
                        "apiVersion": (
                            "catchplate.releaseAuthorizationComplete/v1"
                        ),
                        "attemptId": generic_reserve["attemptId"],
                        "bindingDigest": absent_binding,
                        "outcome": "not_forwarded",
                    }
                ),
                app_module.DATA_PLANE_RELEASE_AUTHORIZATION_TOKEN,
            )
        )
    with db.connect() as conn:
        absent_rows = conn.execute(
            "SELECT COUNT(*) AS count FROM release_authorization_attempts "
            "WHERE attempt_id = ?",
            (absent_attempt,),
        ).fetchone()
        preserved_generic = conn.execute(
            "SELECT state, binding_digest FROM release_authorization_attempts "
            "WHERE attempt_id = ?",
            (generic_reserve["attemptId"],),
        ).fetchone()
    if (
        absent_cleanup.get("state") != "absent"
        or mismatched_cleanup.get("state") != "absent"
        or int(absent_rows["count"]) != 0
        or preserved_generic["state"] != "committed"
        or preserved_generic["binding_digest"]
        != generic_reserve["bindingDigest"]
    ):
        raise AssertionError(
            "control-plane expected cleanup affected absent or unrelated "
            f"state: {absent_cleanup} {mismatched_cleanup} "
            f"{preserved_generic}"
        )


def exercise_webauthn_state(db: Any, backend: str) -> None:
    user_id = f"user:{backend}"
    challenge = f"challenge-{backend}-".ljust(32, "x")
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

    bound_challenge = f"challenge-bound-{backend}-".ljust(32, "x")
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

    race_challenge = f"challenge-race-{backend}-".ljust(32, "x")
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
    parser.add_argument("--authority-only", action="store_true")
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

            from catchplate import app as app_module
            from catchplate import crypto, db, grants, policy_engine
            from catchplate.crypto import load_master_key
            from catchplate.policy_bundle import (
                CredentialPolicy,
                PolicyBundleError,
                compile_policy_bundle,
                demo_policy_bundle,
            )

            if args.authority_only:
                db.init_db()
                load_master_key()
                exercise_policy_high_water(db, backend)
                exercise_v1_route_protocol_authority(db)
                exercise_durable_traversal_cursor_sources(db)
                exercise_release_lock_order(db, backend)
                exercise_release_policy_authority_race(db, backend)
                exercise_approval_authority_revalidation(db, backend)
                exercise_jit_approval_route_authority(db, backend)
                exercise_denial_authority_races(db, backend)
                exercise_release_authority_lifecycle(db, backend)
                exercise_release_credential_issuance_claim(db, backend)
                print(
                    json.dumps(
                        {
                            "authority_only": "pass",
                            "backend": backend,
                            "ok": True,
                        },
                        sort_keys=True,
                    )
                )
                return

            exercise_fresh_startup_key_release_order(db)
            exercise_modern_audit_verification_without_key(db, backend)
            exercise_pre_policy_rate_limit_storage(crypto, db, backend)
            load_master_key()
            exercise_bound_secret_key_rotation(crypto)
            exercise_audit_verification_keyring_cache(db, backend)
            if args.postgres_dsn:
                exercise_postgres_catalog_schema_isolation(db, args.postgres_dsn)
                exercise_postgres_audit_lock_namespace(db, args.postgres_dsn)
                assert postgres_dsn is not None
                exercise_postgres_rolling_audit_lock_compatibility(
                    db, postgres_dsn
                )
                exercise_postgres_inflight_legacy_migration_barrier(
                    db, args.postgres_dsn
                )
                exercise_postgres_audit_migration_faults(db, args.postgres_dsn)
            exercise_policy_high_water(db, backend)
            exercise_v1_route_protocol_authority(db)
            exercise_durable_traversal_cursor_sources(db)
            exercise_release_lock_order(db, backend)
            exercise_release_policy_authority_race(db, backend)
            state = exercise_atomic_approval(db, grants, backend)
            exercise_google_grant_family_quarantine(db, backend)
            exercise_approval_authority_revalidation(db, backend)
            exercise_jit_approval_route_authority(db, backend)
            exercise_denial_authority_races(db, backend)
            exercise_grant_consumption(
                db,
                grants,
                backend,
                state["approval"],
                state["lookup"],
                postgres_dsn,
            )
            if backend == "sqlite":
                exercise_sqlite_audit_redaction_abort(db)
            exercise_operation_storage_commitments(db, backend)
            exercise_transactional_bound_storage_rewrap(
                crypto, db, backend
            )
            exercise_calendar_rate_limits(db, backend)
            exercise_release_authority_lifecycle(db, backend)
            exercise_release_credential_issuance_claim(db, backend)
            exercise_atomic_release_authorization(db, backend)
            exercise_control_plane_jit_approval(app_module, db, backend)
            exercise_proxy_credential_binding(policy_engine, CredentialPolicy)
            exercise_internal_header_boundary(
                policy_engine,
                compile_policy_bundle,
                demo_policy_bundle,
                PolicyBundleError,
            )
            exercise_physical_header_preflight(policy_engine)
            exercise_proxy_forward_start_ordering(policy_engine, CredentialPolicy)
            exercise_query_credential_audit_redaction(
                policy_engine,
                CredentialPolicy,
            )
            exercise_release_client_single_attempt_guard_contract(
                policy_engine.runtime
            )
            exercise_python_v2_release_coordinator(
                policy_engine,
                policy_engine.runtime,
                CredentialPolicy,
            )
            exercise_compiled_v2_reserve_fixtures(
                app_module,
                policy_engine,
                compile_policy_bundle,
                demo_policy_bundle,
                db,
                backend,
            )
            exercise_proxy_discard_header_jit_transaction(
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
