#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
from contextlib import ExitStack
import hashlib
import hmac
import json
import os
import re
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
    os.environ["SERVERWARE_DATA_DIR"] = data_dir
    os.environ["SERVERWARE_METADATA_STORE_BACKEND"] = "sqlite"
    os.environ["SERVERWARE_GRANT_STORE_BACKEND"] = "sqlite"
    os.environ["SERVERWARE_AUDIT_STORE_BACKEND"] = "sqlite"
    os.environ["SERVERWARE_RELEASE_CHANNEL"] = "test"
    os.environ["SERVERWARE_KEY_RELEASE_REQUIRED"] = "0"
    os.environ["SERVERWARE_DATA_PLANE_INSTANCE_ID"] = "jit-transaction-test"
    os.environ["SERVERWARE_DATA_PLANE_RELEASE_AUTHORIZATION_TOKEN"] = "jit-release-test-token"


def postgres_schema_dsn(base_dsn: str, schema: str) -> str:
    separator = "&" if "?" in base_dsn else "?"
    options = quote(f"-csearch_path={schema}", safe="")
    return f"{base_dsn}{separator}options={options}"


def configure_postgres(base_dsn: str, data_dir: str) -> tuple[str, str]:
    import psycopg

    schema = f"serverware_jit_test_{uuid.uuid4().hex}"
    with psycopg.connect(base_dsn, autocommit=True) as conn:
        conn.execute(f'CREATE SCHEMA "{schema}"')
    dsn = postgres_schema_dsn(base_dsn, schema)
    os.environ["SERVERWARE_DATA_DIR"] = data_dir
    os.environ["SERVERWARE_METADATA_STORE_BACKEND"] = "postgres"
    os.environ["SERVERWARE_METADATA_STORE_POSTGRES_DSN"] = dsn
    os.environ["SERVERWARE_GRANT_STORE_BACKEND"] = "postgres"
    os.environ["SERVERWARE_GRANT_STORE_POSTGRES_DSN"] = dsn
    os.environ["SERVERWARE_AUDIT_STORE_BACKEND"] = "postgres"
    os.environ["SERVERWARE_AUDIT_STORE_POSTGRES_DSN"] = dsn
    os.environ["SERVERWARE_RELEASE_CHANNEL"] = "test"
    os.environ["SERVERWARE_KEY_RELEASE_REQUIRED"] = "0"
    os.environ["SERVERWARE_DATA_PLANE_INSTANCE_ID"] = "jit-transaction-test"
    os.environ["SERVERWARE_DATA_PLANE_RELEASE_AUTHORIZATION_TOKEN"] = "jit-release-test-token"
    return schema, dsn


def drop_postgres_schema(base_dsn: str, schema: str) -> None:
    import psycopg

    with psycopg.connect(base_dsn, autocommit=True) as conn:
        conn.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')


def exercise_postgres_catalog_schema_isolation(db: Any, base_dsn: str) -> None:
    import psycopg

    suffix = uuid.uuid4().hex
    table_name = f"serverware_catalog_shadow_{suffix}"
    function_name = f"serverware_catalog_shadow_guard_{suffix}"
    trigger_names = (
        "serverware_audit_storage_epoch_guard",
        "serverware_metadata_audit_storage_epoch_guard",
        "serverware_rate_counter_storage_epoch_guard",
        "serverware_quota_storage_epoch_guard",
    )
    with psycopg.connect(base_dsn, autocommit=True) as admin:
        admin.execute(
            f'''
            CREATE TABLE public."{table_name}" (
                value TEXT CONSTRAINT serverware_audit_events_event_json_size
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

    schemas = [f"serverware_lock_test_{uuid.uuid4().hex}" for _ in range(2)]
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
            "SELECT event_hash FROM serverware_audit_events "
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
                "INSERT INTO serverware_audit_events "
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
            "SELECT id, prev_event_hash, event_hash FROM serverware_audit_events "
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

    schema = f"serverware_inflight_legacy_{uuid.uuid4().hex}"
    dsn = postgres_schema_dsn(base_dsn, schema)
    keyring = db.load_bound_secret_keyring()
    with psycopg.connect(base_dsn, autocommit=True) as admin:
        admin.execute(f'CREATE SCHEMA "{schema}"')
    try:
        with psycopg.connect(dsn, row_factory=dict_row) as setup:
            with setup.transaction():
                setup.execute(
                    """
                    CREATE TABLE serverware_audit_events (
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
                    CREATE TABLE serverware_store_migrations (
                        migration TEXT PRIMARY KEY,
                        version BIGINT NOT NULL,
                        applied_at TEXT NOT NULL
                    );
                    CREATE FUNCTION serverware_audit_storage_epoch_guard()
                    RETURNS trigger LANGUAGE plpgsql AS $$
                    BEGIN
                        RETURN NEW;
                    END;
                    $$;
                    CREATE TRIGGER serverware_audit_storage_epoch_guard
                        BEFORE INSERT OR UPDATE ON serverware_audit_events
                        FOR EACH ROW EXECUTE FUNCTION
                            serverware_audit_storage_epoch_guard();
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
                "INSERT INTO serverware_audit_events "
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
                "storage_format_version, event_hash FROM serverware_audit_events "
                "WHERE id = %s",
                (audit_event_id,),
            ).fetchone()
            audit_gate = check.execute(
                "SELECT version FROM serverware_store_migrations "
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
                "SELECT version FROM serverware_store_migrations "
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
        schema = f"serverware_audit_fault_{uuid.uuid4().hex}"
        dsn = postgres_schema_dsn(base_dsn, schema)
        with psycopg.connect(base_dsn, autocommit=True) as admin:
            admin.execute(f'CREATE SCHEMA "{schema}"')
        try:
            with psycopg.connect(dsn, row_factory=dict_row) as conn:
                with conn.transaction():
                    conn.execute(
                        """
                        CREATE TABLE serverware_audit_events (
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
                        CREATE TABLE serverware_store_migrations (
                            migration TEXT PRIMARY KEY,
                            version BIGINT NOT NULL,
                            applied_at TEXT NOT NULL
                        );
                        CREATE FUNCTION serverware_fault_audit_guard()
                        RETURNS trigger LANGUAGE plpgsql AS $$
                        BEGIN
                            RETURN NEW;
                        END;
                        $$;
                        CREATE TRIGGER serverware_audit_storage_epoch_guard
                            BEFORE INSERT OR UPDATE ON serverware_audit_events
                            FOR EACH ROW EXECUTE FUNCTION serverware_fault_audit_guard();
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
                        "INSERT INTO serverware_audit_events (id, event_type, "
                        "actor_type, actor_id, event_json, prev_event_hash, event_hash, "
                        "created_at) VALUES (%s, 'rate_limit.denied', 'test', "
                        "'test:postgres:fault', %s, NULL, %s, %s)",
                        (f"{label}:legacy", legacy_json, first_hash, created_at),
                    )
                    conn.execute(
                        "INSERT INTO serverware_audit_events (id, event_type, "
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
                            "SELECT * FROM serverware_audit_events ORDER BY sequence ASC"
                        ).fetchall()
                    ]
                    markers = int(
                        check.execute(
                            "SELECT COUNT(*)::bigint AS count FROM "
                            "serverware_audit_events WHERE event_type = "
                            "'audit.storage_redacted'"
                        ).fetchone()["count"]
                    )
                    gates = int(
                        check.execute(
                            "SELECT COUNT(*)::bigint AS count FROM "
                            "serverware_store_migrations"
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
        {"SERVERWARE_HISTORICAL_MASTER_KEYS": historical_env},
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
                    "SERVERWARE_HISTORICAL_MASTER_KEYS": "",
                    "SERVERWARE_HISTORICAL_MASTER_KEYRING_FILE": str(path),
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
            {**receipt, "version": "serverware.boundSecretHistoricalKeyring/v2"},
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
    original_required = os.environ.get("SERVERWARE_KEY_RELEASE_REQUIRED")
    os.environ["SERVERWARE_KEY_RELEASE_REQUIRED"] = "1"
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
            os.environ.pop("SERVERWARE_KEY_RELEASE_REQUIRED", None)
        else:
            os.environ["SERVERWARE_KEY_RELEASE_REQUIRED"] = original_required


def exercise_policy_high_water(db: Any, backend: str) -> None:
    policy_id = f"serverware-{backend}"

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
            policy_id="serverware-test",
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
        "actor_id": "spiffe://test.serverware/decision-gate/atomic",
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
            attempt_id=f"attempt:{suffix}",
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
            actor_id="spiffe://test.serverware/decision-gate/authority",
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
        "type": "serverware.operation_commitment",
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
                    "SELECT * FROM serverware_audit_events WHERE id = %s",
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
                    "UPDATE serverware_audit_events SET event_json = %s, "
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
            CREATE TABLE serverware_store_migrations (
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
                        "INSERT INTO serverware_audit_events (id, event_type, "
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
                        "UPDATE serverware_audit_events SET event_json = %s "
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
            "DELETE FROM serverware_store_migrations WHERE migration IN (?, ?)",
            (
                db._AUDIT_STORAGE_REDACTION_MIGRATION,
                db._METADATA_STORAGE_REDACTION_MIGRATION,
            ),
        )
    if backend == "postgres":
        with db._audit_pg_connect() as conn:
            with conn.transaction():
                conn.execute(
                    "DELETE FROM serverware_store_migrations WHERE migration = %s",
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
                "SELECT prev_event_hash FROM serverware_audit_events WHERE id = %s",
                (legacy_audit_event_id,),
            ).fetchone()
            old_prefix_hashes = {
                str(row["id"]): str(row["event_hash"])
                for row in conn.execute(
                    "SELECT id, event_hash FROM serverware_audit_events "
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
            "SELECT version FROM serverware_store_migrations WHERE migration = ?",
            (db._METADATA_STORAGE_REDACTION_MIGRATION,),
        ).fetchone()
    if backend == "postgres":
        with db._audit_pg_connect() as conn:
            migrated_audit_row = conn.execute(
                "SELECT event_json, encrypted_canonical_event_json, prev_event_hash, "
                "event_hash, storage_format_version FROM serverware_audit_events "
                "WHERE id = %s",
                (legacy_audit_event_id,),
            ).fetchone()
            audit_gate = conn.execute(
                "SELECT version FROM serverware_store_migrations WHERE migration = %s",
                (db._AUDIT_STORAGE_REDACTION_MIGRATION,),
            ).fetchone()
            migrated_prefix_hashes = {
                str(row["id"]): str(row["event_hash"])
                for row in conn.execute(
                    "SELECT id, event_hash FROM serverware_audit_events "
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
                "SELECT version FROM serverware_store_migrations WHERE migration = ?",
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
                        "UPDATE serverware_audit_events SET event_json = %s, "
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
            "UPDATE serverware_store_migrations SET version = ? WHERE migration = ?",
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
            "UPDATE serverware_store_migrations SET version = ? WHERE migration = ?",
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
                    "serverware_audit_events WHERE "
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
                "SELECT migration, version FROM serverware_store_migrations "
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
    if set(retained_operation_context) != {"digest"} or not re.fullmatch(
        r"sha256:[0-9a-f]{64}", str(retained_operation_context.get("digest") or "")
    ):
        raise AssertionError("release state persisted raw operation context")
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
    if json.loads(migrated["binding_json"]) != {
        "digest": migrated["binding_digest"]
    } or set(json.loads(migrated["operation_context_json"])) != {"digest"}:
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
        canonical_request: dict[str, Any] | None = canonical,
        request_digest: str | None = None,
        submitted_operation_digest: str | None = None,
    ) -> dict[str, Any]:
        payload = {
            "apiVersion": "serverware.releaseAuthorizationReserve/v1",
            "attemptId": attempt_id,
            "flowId": attempt_id,
            "principalId": principal_id,
            "routeId": route_id,
            "credentialRef": credential_id,
            "credentialVersion": credential_version,
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
            return_value={"credential_version": credential_version},
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
            "attempt_id": kwargs["attempt_id"],
            "binding_digest": policy_engine.runtime.release_authorization_binding_digest(
                attempt_id=kwargs["attempt_id"],
                flow_id=kwargs["flow_id"],
                principal_id=kwargs["principal_id"],
                route_id=kwargs["route_id"],
                credential_ref=kwargs["credential_ref"],
                credential_version=kwargs["credential_version"],
                policy_hash=kwargs["policy_hash"],
                request_digest=kwargs["request_digest"],
                operation_digest=kwargs["operation_digest"],
                operation_context=kwargs["operation_context"],
                shared_quotas=kwargs["shared_quotas"],
                require_jit_grant=kwargs["require_jit_grant"],
            ),
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
        if isinstance(reserve_result, dict):
            result.update(reserve_result)
            result["attempt_id"] = kwargs["attempt_id"]
            if result.get("authorized") is False and "quotas" not in reserve_result:
                result["quotas"] = []
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
        result = runtime._release_authorization_http_post(
            "reserve",
            reserve_payload,
            expected_binding_digest=binding_digest,
            expected_shared_quotas=[],
        )
    if result.get("state") != "reserved" or not result.get("idempotent_replay"):
        raise AssertionError(f"idempotent reserve retry did not recover: {result}")
    if len(requests) != 2 or requests[0] != requests[1]:
        raise AssertionError(f"reserve retry changed the durable attempt binding: {requests}")

    calendar_start_ms = int(
        datetime(2025, 1, 1, tzinfo=timezone.utc).timestamp() * 1000
    )
    calendar_end_ms = int(
        datetime(2025, 1, 2, tzinfo=timezone.utc).timestamp() * 1000
    )
    calendar_response = {
        "apiVersion": "serverware.releaseAuthorization/v1",
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


def exercise_proxy_atomic_backend_integration(
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
    advance_active_policy_hash(db, snapshot.hash)
    credential = {
        "id": credential_policy.id,
        "kind": "bearer",
        "secret": f"secret-{backend}",
        "credential_version": int(stored_credential["credential_version"]),
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
            patch.object(
                policy_engine.runtime,
                "get_credential_version",
                return_value=int(stored_credential["credential_version"]),
            )
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
        if pending.decision.payload.get("approval_url") != (
            f"/approvals/{pending.decision.payload['approval_id']}"
        ):
            raise AssertionError(
                f"atomic proxy did not return an exact operator approval link: {pending.decision}"
            )
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

            from serverware import app as app_module
            from serverware import crypto, db, grants, policy_engine
            from serverware.crypto import load_master_key
            from serverware.policy_bundle import (
                CredentialPolicy,
                PolicyBundleError,
                compile_policy_bundle,
                demo_policy_bundle,
            )

            if args.authority_only:
                db.init_db()
                load_master_key()
                exercise_policy_high_water(db, backend)
                exercise_release_policy_authority_race(db, backend)
                exercise_approval_authority_revalidation(db, backend)
                exercise_jit_approval_route_authority(db, backend)
                exercise_denial_authority_races(db, backend)
                exercise_release_authority_lifecycle(db, backend)
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
