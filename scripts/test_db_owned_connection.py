#!/usr/bin/env python3
"""Owned-handle regressions over real disposable SQLite, not service acceptance.

Only the database factory/backend selectors and an in-memory synthetic KEK are
substituted. SQL, audit hashing, credential envelopes, mutation locks, facade
ownership, and transaction contexts run unchanged. The PostgreSQL check covers
its Python wrapper contract, not a PostgreSQL server or SQL implementation.
"""
from __future__ import annotations

from contextlib import ExitStack, closing
import hashlib
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

SCHEMA = """
CREATE TABLE audit_events (
 id TEXT PRIMARY KEY, event_type TEXT NOT NULL, actor_type TEXT NOT NULL,
 actor_id TEXT, event_json TEXT NOT NULL, storage_format_version INTEGER,
 prev_event_hash TEXT, event_hash TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE credentials (
 id TEXT PRIMARY KEY, kind TEXT NOT NULL, credential_version INTEGER NOT NULL,
 metadata TEXT NOT NULL, lifecycle_status TEXT NOT NULL,
 encrypted_secret TEXT, encrypted_dek TEXT, secret_nonce TEXT,
 secret_ciphertext TEXT, secret_kek_id TEXT);
CREATE TABLE operator_demo_nonces (
 recipient_key_id TEXT NOT NULL, nonce_sha256 TEXT NOT NULL,
 expires_at_epoch_ms INTEGER NOT NULL,
 PRIMARY KEY(recipient_key_id, nonce_sha256));
CREATE TABLE sentinel (id TEXT PRIMARY KEY);
"""


class TrackingConnection(sqlite3.Connection):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.events, self.statements = [], []
        self.close_count = 0
        self.transaction_at_close = None
        self.fault = None
        self.failure = RuntimeError("synthetic connection boundary")
        self.set_trace_callback(self.statements.append)

    def __enter__(self):
        self.events.append("enter")
        if self.fault == "enter":
            raise self.failure
        return super().__enter__()

    def __exit__(self, kind, value, traceback):
        result = super().__exit__(kind, value, traceback)
        self.events.append(("exit", kind))
        if self.fault == "exit":
            raise self.failure
        return result

    def close(self):
        self.close_count += 1
        self.transaction_at_close = self.in_transaction
        self.events.append("close")
        super().close()


class DbOwnedConnectionTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        for target in ("socket.socket", "socket.create_connection", "socket.getaddrinfo"):
            self.stack.enter_context(patch(target, side_effect=AssertionError("SQLite unit attempted network I/O")))
        from catchplate import config, crypto, db, operator_demo, operator_demo_store
        self.db, self.store, self.config = db, operator_demo_store, config
        self.operator_demo = operator_demo
        directory = self.stack.enter_context(tempfile.TemporaryDirectory(prefix="catchplate-owned-db-unit-"))
        self.path = Path(directory) / "synthetic.sqlite3"
        with closing(sqlite3.connect(self.path)) as conn, conn:
            conn.executescript(SCHEMA)
        self.connections = []
        self.stack.callback(self.close_leaks)
        self.stack.enter_context(patch.object(db, "audit_uses_postgres", return_value=False))
        self.stack.enter_context(patch.object(db, "metadata_uses_postgres", return_value=False))
        self.active = self.stack.enter_context(patch.object(operator_demo, "active", return_value=True))
        self.connect = self.stack.enter_context(patch.object(db, "connect", side_effect=self.open_connection))
        self.master = self.stack.enter_context(patch.object(db, "load_master_key", return_value=bytes(range(32))))
        self.stack.enter_context(patch.object(crypto, "load_master_key", return_value=bytes(range(32))))
        self.credential_id = "synthetic-owned-credential"
        self.secret = "synthetic-only-envelope-material"
        envelope = crypto.encrypt_secret_envelope(self.secret, credential_id=self.credential_id, credential_version=3)
        with closing(sqlite3.connect(self.path)) as conn, conn:
            conn.execute("INSERT INTO credentials VALUES(?,?,?,?,?,?,?,?,?,?)", (
                self.credential_id, "api_key", 3, db.dumps({"synthetic": True}), "active",
                "envelope:v2", envelope["encrypted_dek"], envelope["secret_nonce"],
                envelope["secret_ciphertext"], envelope["secret_kek_id"]))

    def open_connection(self):
        conn = sqlite3.connect(self.path, timeout=0, factory=TrackingConnection)
        conn.row_factory = sqlite3.Row
        self.connections.append(conn)
        return conn

    def close_leaks(self):
        for conn in self.connections:
            if conn.close_count == 0:
                conn.close()

    def rows(self, table):
        self.assertIn(table, {"audit_events", "credentials", "operator_demo_nonces", "sentinel"})
        with closing(sqlite3.connect(self.path)) as conn:
            conn.row_factory = sqlite3.Row
            return [dict(row) for row in conn.execute(f"SELECT * FROM {table} ORDER BY rowid")]

    def write(self, sql, params=()):
        with closing(sqlite3.connect(self.path)) as conn, conn:
            conn.execute(sql, params)

    def closed(self, conn, *, error=None, entered=True):
        self.assertEqual(conn.close_count, 1)
        self.assertFalse(conn.transaction_at_close)
        self.assertEqual(conn.events, ["enter", ("exit", error), "close"] if entered else ["enter", "close"])
        with self.assertRaises(sqlite3.ProgrammingError):
            sqlite3.Connection.execute(conn, "SELECT 1")

    def batch(self, events=None, ids=None):
        events = events if events is not None else [
            ("test.owned.first", {"synthetic": 1}), ("test.owned.second", {"synthetic": 2})]
        ids = ids if ids is not None else [
            "sha256:" + hashlib.sha256(label.encode()).hexdigest() for label in ("first", "second")]
        return self.db.record_audit_event_batch(events, actor_type="system", actor_id="synthetic",
            producer_event_ids=ids, producer_instance_id="synthetic-owned-instance")

    def test_helper_lazy_entry_commit_rollback_and_boundary_errors(self):
        context = self.db.metadata_connection()
        self.connect.assert_not_called()
        with context as conn:
            self.assertIs(conn, self.connections[-1])
            conn.execute("INSERT INTO sentinel VALUES ('committed')")
            self.assertEqual(conn.close_count, 0)
            self.assertTrue(conn.in_transaction)
        self.closed(conn)
        self.assertIn("COMMIT", conn.statements)
        self.assertEqual(self.rows("sentinel"), [{"id": "committed"}])
        failure = RuntimeError("synthetic body failure")
        with self.assertRaises(RuntimeError) as raised:
            with self.db.metadata_connection() as rollback:
                rollback.execute("INSERT INTO sentinel VALUES ('rolled-back')")
                raise failure
        self.assertIs(raised.exception, failure)
        self.closed(rollback, error=RuntimeError)
        self.assertIn("ROLLBACK", rollback.statements)
        self.assertEqual(self.rows("sentinel"), [{"id": "committed"}])
        for fault in ("enter", "exit"):
            with self.subTest(fault=fault):
                conn = self.open_connection()
                conn.fault = fault
                with patch.object(self.db, "connect", return_value=conn), self.assertRaises(RuntimeError) as raised:
                    with self.db.metadata_connection() as selected:
                        selected.execute("INSERT INTO sentinel VALUES ('exit-committed')")
                self.assertIs(raised.exception, conn.failure)
                self.closed(conn, entered=fault != "enter")
        self.assertEqual(len(self.rows("sentinel")), 2)
        with patch.object(self.db, "connect", side_effect=failure), self.assertRaises(RuntimeError) as raised:
            with self.db.metadata_connection():
                self.fail("failed connection entered")
        self.assertIs(raised.exception, failure)

    def test_record_audit_commits_and_real_sql_failure_rolls_back_then_closes(self):
        result = self.db.record_audit_event("test.owned", {"synthetic": True}, idempotency_key="one")
        self.closed(self.connections[-1])
        self.assertIn("COMMIT", self.connections[-1].statements)
        before = self.rows("audit_events")
        self.assertEqual(before[0]["id"], result["id"])
        self.assertEqual(before[0]["event_hash"], result["event_hash"])
        self.write("""CREATE TRIGGER reject_audit BEFORE INSERT ON audit_events
            BEGIN SELECT RAISE(ABORT, 'synthetic audit rejection'); END""")
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.record_audit_event("test.owned", {"synthetic": False}, idempotency_key="two")
        self.closed(self.connections[-1], error=sqlite3.IntegrityError)
        self.assertIn("ROLLBACK", self.connections[-1].statements)
        self.assertEqual(self.rows("audit_events"), before)

    def test_batch_replay_conflict_partial_batch_and_atomic_failure_close(self):
        first = self.batch()
        self.closed(self.connections[-1])
        before = self.rows("audit_events")
        self.assertEqual(self.batch(), first)
        self.closed(self.connections[-1])
        self.assertEqual(first[1]["prev_event_hash"], first[0]["event_hash"])
        for events, ids in (
            ([("test.owned.first", {"changed": True}), ("test.owned.second", {"synthetic": 2})], None),
            (None, ["sha256:" + hashlib.sha256(b"first").hexdigest(), "sha256:" + hashlib.sha256(b"new").hexdigest()]),
        ):
            with self.assertRaises(self.db.AuditBatchConflictError):
                self.batch(events, ids)
            self.closed(self.connections[-1], error=self.db.AuditBatchConflictError)
            self.assertEqual(self.rows("audit_events"), before)
        self.write("""CREATE TRIGGER reject_second BEFORE INSERT ON audit_events
            WHEN NEW.event_type='test.owned.fail'
            BEGIN SELECT RAISE(ABORT, 'synthetic second insert rejection'); END""")
        with self.assertRaises(sqlite3.IntegrityError):
            self.batch([("test.owned.new", {}), ("test.owned.fail", {})], ["sha256:" + "a" * 64, "sha256:" + "b" * 64])
        failed = self.connections[-1]
        self.closed(failed, error=sqlite3.IntegrityError)
        self.assertTrue(any("INSERT INTO audit_events" in sql for sql in failed.statements))
        self.assertIn("ROLLBACK", failed.statements)
        self.assertEqual(self.rows("audit_events"), before)
        count = len(self.connections)
        self.assertEqual(self.db.record_audit_event_batch([], actor_type="system", actor_id=None), [])
        with self.assertRaises(self.db.AuditStoreError):
            self.batch(ids=["sha256:" + "a" * 64] * 2)
        self.assertEqual(len(self.connections), count)

    def test_get_credential_missing_inactive_and_detached_encrypted_row(self):
        self.assertIsNone(self.db.get_credential("synthetic-missing"))
        self.closed(self.connections[-1])
        public = self.db.get_credential(self.credential_id)
        self.closed(self.connections[-1])
        self.assertEqual(public["metadata"], {"synthetic": True})
        self.assertNotIn("secret", public)
        self.assertNotIn("encrypted_dek", public)
        private = self.db.get_credential(self.credential_id, include_secret=True)
        self.closed(self.connections[-1])
        self.assertEqual(private["secret"], self.secret)
        self.write("UPDATE credentials SET lifecycle_status='revoked'")
        self.assertIsNone(self.db.get_credential(self.credential_id))
        self.closed(self.connections[-1])
        self.assertEqual(self.db.get_credential(self.credential_id, include_inactive=True)["id"], self.credential_id)
        self.closed(self.connections[-1])
        self.write("DROP TABLE credentials")
        with self.assertRaises(sqlite3.OperationalError):
            self.db.get_credential(self.credential_id)
        self.closed(self.connections[-1], error=sqlite3.OperationalError)

    def test_both_snapshots_hold_actual_writer_lock_through_yield_and_close_on_exit(self):
        for name in ("credential_lease_snapshot", "credential_generation_snapshot"):
            snapshot = getattr(self.db, name)
            for fail in (False, True):
                with self.subTest(snapshot=name, fail=fail):
                    failure = RuntimeError("synthetic snapshot consumer")
                    try:
                        with snapshot(self.credential_id) as item:
                            conn = self.connections[-1]
                            self.assertEqual(conn.close_count, 0)
                            self.assertTrue(conn.in_transaction)
                            self.assertEqual(conn.execute("SELECT 1").fetchone()[0], 1)
                            self.assertEqual(item["credential_version"], 3)
                            self.assertEqual(item["metadata"], {"synthetic": True})
                            if name == "credential_lease_snapshot":
                                self.assertEqual(item["secret"], self.secret)
                            else:
                                self.assertNotIn("secret", item)
                            with closing(sqlite3.connect(self.path, timeout=0)) as competitor:
                                with self.assertRaisesRegex(sqlite3.OperationalError, "locked"):
                                    competitor.execute("BEGIN IMMEDIATE")
                            if fail:
                                conn.execute("INSERT INTO sentinel VALUES ('snapshot-rollback')")
                                raise failure
                    except RuntimeError as error:
                        self.assertTrue(fail)
                        self.assertIs(error, failure)
                    self.closed(conn, error=RuntimeError if fail else None)
                    self.assertIn("ROLLBACK" if fail else "COMMIT", conn.statements)
                    self.assertEqual(self.rows("sentinel"), [])
            for identifier in ("missing", self.credential_id):
                if identifier == self.credential_id:
                    self.write("UPDATE credentials SET lifecycle_status='revoked'")
                with snapshot(identifier) as item:
                    self.assertIsNone(item)
                    self.assertTrue(self.connections[-1].in_transaction)
                self.closed(self.connections[-1])
            self.write("UPDATE credentials SET lifecycle_status='active'")

    def test_snapshot_metadata_validation_and_key_failure_keep_original_refusals(self):
        for metadata in ("[]", '"' + "x" * (32 * 1024) + '"'):
            self.write("UPDATE credentials SET metadata=?", (metadata,))
            with self.assertRaises(self.db.MetadataStoreError):
                with self.db.credential_generation_snapshot(self.credential_id):
                    self.fail("invalid metadata yielded")
            self.closed(self.connections[-1], error=self.db.MetadataStoreError)
        self.master.assert_not_called()
        count = len(self.connections)
        failure = RuntimeError("synthetic key admission refusal")
        with patch.object(self.db, "load_master_key", side_effect=failure), self.assertRaises(RuntimeError) as raised:
            with self.db.credential_lease_snapshot(self.credential_id):
                self.fail("failed key admission yielded")
        self.assertIs(raised.exception, failure)
        self.assertEqual(len(self.connections), count)

    def test_nonce_reservation_duplicate_capacity_expiry_and_read_close(self):
        key, nonce = "sha256:" + "1" * 64, "sha256:" + "2" * 64
        reserve, read = self.store.reserve_credential_lease_nonce, self.store.credential_lease_nonce_reserved
        self.assertFalse(read(key, nonce, now_epoch_ms=1000))
        self.closed(self.connections[-1])
        self.assertIsNone(reserve(key, nonce, now_epoch_ms=1000))
        self.closed(self.connections[-1])
        before = self.rows("operator_demo_nonces")
        self.assertEqual(reserve(key, nonce, now_epoch_ms=1001), "replay")
        self.closed(self.connections[-1])
        self.assertEqual(self.rows("operator_demo_nonces"), before)
        self.assertTrue(read(key, nonce, now_epoch_ms=1001))
        self.closed(self.connections[-1])
        with patch.object(self.config, "CREDENTIAL_LEASE_REPLAY_MAX_ENTRIES", 1):
            self.assertEqual(reserve(key, "sha256:" + "3" * 64, now_epoch_ms=1001), "capacity")
        self.closed(self.connections[-1])
        expiry = before[0]["expires_at_epoch_ms"]
        self.assertFalse(read(key, nonce, now_epoch_ms=expiry))
        self.closed(self.connections[-1])
        self.assertIsNone(reserve(key, nonce, now_epoch_ms=expiry))
        self.closed(self.connections[-1])
        before = self.rows("operator_demo_nonces")
        self.write("""CREATE TRIGGER reject_nonce BEFORE INSERT ON operator_demo_nonces
            BEGIN SELECT RAISE(ABORT, 'synthetic nonce rejection'); END""")
        with self.assertRaises(sqlite3.IntegrityError):
            reserve(key, nonce, now_epoch_ms=before[0]["expires_at_epoch_ms"])
        self.closed(self.connections[-1], error=sqlite3.IntegrityError)
        self.assertEqual(self.rows("operator_demo_nonces"), before)  # Expiry deletion rolled back too.
        count = len(self.connections)
        with self.assertRaises(ValueError):
            read(key, nonce, now_epoch_ms=True)
        with patch.object(self.operator_demo, "active", return_value=False), self.assertRaises(RuntimeError):
            reserve(key, nonce, now_epoch_ms=1000)
        self.assertEqual(len(self.connections), count)
        self.write("DROP TABLE operator_demo_nonces")
        with self.assertRaises(sqlite3.OperationalError):
            read(key, nonce, now_epoch_ms=1000)
        self.closed(self.connections[-1], error=sqlite3.OperationalError)

    def test_borrowed_facade_keeps_caller_transaction_open_for_hot_paths(self):
        for commit in (False, True):
            conn = self.open_connection()
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("INSERT INTO sentinel VALUES (?)", (str(commit),))
            facade = self.db._BorrowedMetadataConnection(conn)
            with patch.object(self.db, "connect", return_value=facade):
                self.batch()
                self.db.record_audit_event("test.borrowed", {}, idempotency_key="borrowed-single")
                self.assertEqual(self.db.get_credential(self.credential_id)["id"], self.credential_id)
                for name in ("credential_lease_snapshot", "credential_generation_snapshot"):
                    with getattr(self.db, name)(self.credential_id) as item:
                        self.assertEqual(item["id"], self.credential_id)
                key, nonce = "sha256:" + "4" * 64, "sha256:" + "5" * 64
                self.assertFalse(self.store.credential_lease_nonce_reserved(key, nonce, now_epoch_ms=1000))
                # Existing unconditional BEGIN is deliberately not repaired.
                with self.assertRaisesRegex(sqlite3.OperationalError, "within a transaction"):
                    self.store.reserve_credential_lease_nonce(key, nonce, now_epoch_ms=1000)
                failure = RuntimeError("synthetic borrowed consumer")
                with self.assertRaises(RuntimeError) as raised:
                    with self.db.credential_generation_snapshot(self.credential_id):
                        raise failure
                self.assertIs(raised.exception, failure)
            self.assertEqual(conn.close_count, 0)
            self.assertEqual(conn.events, [])
            self.assertTrue(conn.in_transaction)
            self.assertNotIn("COMMIT", conn.statements)
            self.assertNotIn("ROLLBACK", conn.statements)
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0], 3)
            self.assertEqual(self.rows("audit_events"), [])
            self.assertEqual(self.rows("sentinel"), [])
            conn.commit() if commit else conn.rollback()
            self.assertEqual(len(self.rows("audit_events")), 3 if commit else 0)
            self.assertEqual(self.rows("sentinel"), [{"id": "True"}] if commit else [])
            self.assertEqual(conn.execute("SELECT 1").fetchone()[0], 1)
            conn.close()  # Only this caller owns the final close.

    def test_non_sqlite_and_postgres_context_semantics_are_not_reowned(self):
        conn = self.open_connection()
        class Wrapper:
            def __enter__(self):
                return conn.__enter__()
            def __exit__(self, *args):
                return conn.__exit__(*args)
            def close(self):
                raise AssertionError("non-SQLite wrapper close was called")
        with patch.object(self.db, "connect", return_value=Wrapper()):
            with self.db.metadata_connection() as yielded:
                self.assertIs(yielded, conn)
                yielded.execute("INSERT INTO sentinel VALUES ('wrapper')")
        self.assertEqual(conn.close_count, 0)
        self.assertEqual(conn.events, ["enter", ("exit", None)])
        self.assertEqual(self.rows("sentinel"), [{"id": "wrapper"}])
        conn.close()

        class PgContext:
            def __init__(self, suppress):
                self.events, self.suppress = [], suppress
            def __enter__(self):
                self.events.append("enter")
                return object()
            def __exit__(self, kind, value, traceback):
                self.events.append((kind, value))
                return self.suppress
            def close(self):
                raise AssertionError("PostgreSQL ownership was changed")
        failure = RuntimeError("synthetic PostgreSQL context failure")
        for suppress in (False, True):
            raw = PgContext(suppress)
            wrapper = self.db.PostgresMetadataConnection(raw)
            with patch.object(self.db, "connect", return_value=wrapper):
                try:
                    with self.db.metadata_connection() as yielded:
                        self.assertIs(yielded, wrapper)
                        raise failure
                except RuntimeError as error:
                    self.assertFalse(suppress)
                    self.assertIs(error, failure)
                else:
                    self.assertTrue(suppress)
            self.assertEqual(raw.events, ["enter", (RuntimeError, failure)])


if __name__ == "__main__":
    unittest.main()
