#!/usr/bin/env python3
"""Real db-function unit tests on private temporary SQLite WAL databases.

Run only in the isolated backend test environment. This imports the actual db
module but replaces its connection factory and backend selectors; it does not
call db.init_db, app startup, a provider, or a PostgreSQL server. The minimal
tables exercise actual audit hashing, append, outbox verification and CAS, not
the complete deployed schema or native authority. No latency claim is made.
"""
from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
import sqlite3
import sys
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from serverware import db


PROBE = ("SELECT 1 FROM metadata_audit_outbox "
    "WHERE status IN ('pending', 'claimed') LIMIT 1")
ZERO = {"claimed": 0, "audited": 0, "failed": 0, "pending": 0}
SCHEMA = """
CREATE TABLE audit_events (
    id TEXT PRIMARY KEY, event_type TEXT NOT NULL, actor_type TEXT NOT NULL,
    actor_id TEXT, event_json TEXT NOT NULL, storage_format_version INTEGER,
    prev_event_hash TEXT, event_hash TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE metadata_audit_outbox (
    id TEXT PRIMARY KEY, event_type TEXT NOT NULL, actor_type TEXT NOT NULL,
    actor_id TEXT, event_json TEXT NOT NULL, event_digest TEXT NOT NULL,
    storage_format_version INTEGER, status TEXT NOT NULL,
    claim_id TEXT, claimed_at TEXT, attempts INTEGER NOT NULL DEFAULT 0,
    audited_at TEXT, audit_event_hash TEXT, last_error TEXT,
    created_at TEXT NOT NULL,
    CHECK (status IN ('pending', 'claimed', 'audited')),
    UNIQUE (id, event_digest)
);
CREATE INDEX metadata_audit_outbox_delivery
    ON metadata_audit_outbox(status, claimed_at, created_at, id);
CREATE TABLE unrelated (id TEXT PRIMARY KEY);
"""


class ProbeCursor:
    """Observe only the real SQLite probe's completion and release order."""
    def __init__(self, cursor, connection):
        self.cursor, self.connection = cursor, connection
        self.exhausted = self.closed = False

    def fetchall(self):
        rows = self.cursor.fetchall()
        self.exhausted = True
        return rows

    def close(self):
        self.cursor.close()
        self.closed = True
        owner = self.connection.owner
        hook, owner.after_probe = owner.after_probe, None
        if hook is not None:
            hook()


class ObservedConnection(sqlite3.Connection):
    def execute(self, sql, parameters=()):
        if sql == "BEGIN IMMEDIATE" and getattr(self, "probe", None) is not None:
            if not self.probe.exhausted or not self.probe.closed:
                raise AssertionError("probe snapshot remained open at writer acquisition")
        cursor = super().execute(sql, parameters)
        if sql == PROBE:
            self.probe = ProbeCursor(cursor, self)
            self.owner.probes.append(self.probe)
            return self.probe
        return cursor


class EmptyOutboxFastPathTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="metadata-outbox-unit-")
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name) / "outbox.sqlite3"
        self.queries, self.probes = [], []
        self.after_probe = None
        with self.connection() as conn:
            self.assertEqual(conn.execute("PRAGMA journal_mode=WAL").fetchone()[0], "wal")
            conn.executescript(SCHEMA)
        self.queries.clear()
        for name, value in (("connect", self.connection), ("audit_uses_postgres", lambda: False),
                ("metadata_uses_postgres", lambda: False)):
            mocked = patch.object(db, name, value)
            mocked.start()
            self.addCleanup(mocked.stop)

    @contextmanager
    def connection(self):
        # timeout=0 makes accidental writer acquisition fail deterministically
        # while another connection holds the lock; no sleep/timing threshold.
        conn = sqlite3.connect(self.path, timeout=0, factory=ObservedConnection)
        conn.owner, conn.row_factory = self, sqlite3.Row
        conn.set_trace_callback(self.queries.append)
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def seed(self, identifier, status="pending", *, connection=None):
        event = {"synthetic": True, "identifier": identifier}
        raw = db.dumps(event)
        values = (identifier, "test.outbox", "system", None, raw,
            db._metadata_outbox_event_digest(raw), db._AUDIT_STORAGE_FORMAT_VERSION,
            status, "test-claim" if status == "claimed" else None,
            "2026-01-01T00:00:00+00:00" if status == "claimed" else None,
            "2026-01-01T00:00:00+00:00")
        sql = ("INSERT INTO metadata_audit_outbox (id,event_type,actor_type,actor_id,"
            "event_json,event_digest,storage_format_version,status,claim_id,claimed_at,created_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?)")
        if connection is not None:
            connection.execute(sql, values)
        else:
            with self.connection() as conn:
                conn.execute(sql, values)

    def rows(self, table):
        self.assertIn(table, {"audit_events", "metadata_audit_outbox", "unrelated"})
        with self.connection() as conn:
            return [dict(row) for row in conn.execute("SELECT * FROM " + table + " ORDER BY rowid")]

    def assert_read_only_probe(self, queries):
        self.assertEqual(queries, [PROBE])
        self.assertTrue(self.probes[-1].exhausted and self.probes[-1].closed)

    def test_empty_and_audited_only_are_read_only(self):
        self.assertEqual(db.drain_metadata_audit_outbox(), ZERO)
        self.assert_read_only_probe(self.queries)
        self.seed("already-audited", "audited")
        before = self.rows("metadata_audit_outbox")
        self.queries.clear()
        self.assertEqual(db.drain_metadata_audit_outbox(), ZERO)
        self.assert_read_only_probe(self.queries)
        self.assertEqual(self.rows("metadata_audit_outbox"), before)
        self.assertEqual(self.rows("audit_events"), [])

    def test_empty_read_does_not_acquire_an_unrelated_held_writer(self):
        closed = threading.Event()
        with self.connection() as writer:
            writer.execute("BEGIN IMMEDIATE")
            writer.execute("INSERT INTO unrelated VALUES ('held')")
            self.after_probe = closed.set
            self.queries.clear()
            self.assertEqual(db.drain_metadata_audit_outbox(), ZERO)
            self.assertTrue(closed.is_set())
            self.assertTrue(writer.in_transaction)
            self.assert_read_only_probe(self.queries)
        self.assertEqual(self.rows("unrelated"), [{"id": "held"}])

    def test_pending_and_claimed_keep_locked_delivery_and_batch_counts(self):
        self.seed("first", "pending")
        self.seed("second", "claimed")
        self.queries.clear()
        self.assertEqual(db.drain_metadata_audit_outbox(limit=1),
            {"claimed": 1, "audited": 1, "failed": 0, "pending": 1})
        self.assertLess(self.queries.index(PROBE), self.queries.index("BEGIN IMMEDIATE"))
        self.assertTrue(self.probes[-1].exhausted and self.probes[-1].closed)
        self.assertEqual(db.drain_metadata_audit_outbox(limit=1),
            {"claimed": 1, "audited": 1, "failed": 0, "pending": 0})
        audits, outbox = self.rows("audit_events"), self.rows("metadata_audit_outbox")
        self.assertEqual([row["id"] for row in audits], ["first", "second"])
        self.assertIsNone(audits[0]["prev_event_hash"])
        self.assertEqual(audits[1]["prev_event_hash"], audits[0]["event_hash"])
        for audit, queued in zip(audits, outbox):
            self.assertEqual(audit["event_json"], queued["event_json"])
            self.assertEqual(queued["audit_event_hash"], audit["event_hash"])
            self.assertEqual(queued["status"], "audited")
            self.assertIsNone(queued["claim_id"])
            self.assertIsNone(queued["claimed_at"])
        self.assertEqual(db.drain_metadata_audit_outbox(), ZERO)
        self.assertEqual(self.rows("audit_events"), audits)

    def test_nonempty_probe_is_reread_after_another_drain(self):
        self.seed("shared")
        competing = []
        self.after_probe = lambda: competing.append(db.drain_metadata_audit_outbox())
        self.assertEqual(db.drain_metadata_audit_outbox(), ZERO)
        self.assertEqual(competing, [{"claimed": 1, "audited": 1, "failed": 0, "pending": 0}])
        self.assertEqual(len(self.rows("audit_events")), 1)
        # Both the inner drainer and the outer stale-probe drainer acquire the
        # writer and reread; only the former appends or terminalizes the row.
        self.assertEqual(self.queries.count("BEGIN IMMEDIATE"), 2)

    def test_empty_is_not_a_quiescence_barrier_for_fully_helper(self):
        self.after_probe = lambda: self.seed("committed-after-empty-read")
        self.assertEqual(db.drain_metadata_audit_outbox_fully(limit=1, max_batches=2), ZERO)
        self.assertEqual(self.rows("audit_events"), [])
        self.assertEqual(self.rows("metadata_audit_outbox")[0]["status"], "pending")
        self.assertEqual(db.drain_metadata_audit_outbox(),
            {"claimed": 1, "audited": 1, "failed": 0, "pending": 0})
        self.assertEqual(db.drain_metadata_audit_outbox(), ZERO)
        self.assertEqual(len(self.rows("audit_events")), 1)

    def test_uncommitted_later_row_stays_durable_for_next_drain(self):
        with self.connection() as writer:
            writer.execute("BEGIN IMMEDIATE")
            self.seed("later-commit", connection=writer)
            self.assertEqual(db.drain_metadata_audit_outbox(), ZERO)
            self.assertEqual(self.rows("metadata_audit_outbox"), [])
        self.assertEqual(self.rows("metadata_audit_outbox")[0]["status"], "pending")
        self.assertEqual(db.drain_metadata_audit_outbox(),
            {"claimed": 1, "audited": 1, "failed": 0, "pending": 0})

    def test_sqlite_producer_audit_and_terminal_row_commit_atomically(self):
        event = {"synthetic": True}
        with self.assertRaisesRegex(RuntimeError, "rollback fixture"):
            with self.connection() as conn:
                conn.execute("INSERT INTO unrelated VALUES ('rollback')")
                staged = db._stage_metadata_audit_event(conn, event_type="test.outbox",
                    actor_type="system", actor_id=None, event=event, idempotency_key="producer")
                self.assertEqual(staged["outbox_status"], "audited")
                self.assertIsNotNone(staged["event_hash"])
                raise RuntimeError("rollback fixture")
        for table in ("audit_events", "metadata_audit_outbox", "unrelated"):
            self.assertEqual(self.rows(table), [])
        with self.connection() as conn:
            conn.execute("INSERT INTO unrelated VALUES ('commit')")
            db._stage_metadata_audit_event(conn, event_type="test.outbox",
                actor_type="system", actor_id=None, event=event, idempotency_key="producer")
        before = self.rows("audit_events")
        self.assertEqual(len(before), 1)
        self.assertEqual(self.rows("metadata_audit_outbox")[0]["status"], "audited")
        self.queries.clear()
        self.assertEqual(db.drain_metadata_audit_outbox(), ZERO)
        self.assert_read_only_probe(self.queries)
        self.assertEqual(self.rows("audit_events"), before)

    def test_corrupt_pending_row_rolls_back_existing_delivery_transaction(self):
        self.seed("corrupt")
        with self.connection() as conn:
            conn.execute("UPDATE metadata_audit_outbox SET event_digest = ?", ("sha256:" + "0" * 64,))
        before = self.rows("metadata_audit_outbox")
        self.queries.clear()
        with self.assertRaises(db.AuditStoreError):
            db.drain_metadata_audit_outbox()
        self.assertIn("BEGIN IMMEDIATE", self.queries)
        self.assertIn("ROLLBACK", self.queries)
        self.assertEqual(self.rows("metadata_audit_outbox"), before)
        self.assertEqual(self.rows("audit_events"), [])

    def test_invalid_limits_and_probe_errors_are_not_empty_success(self):
        forbidden = Mock(side_effect=AssertionError("invalid input opened a connection"))
        with patch.object(db, "connect", forbidden):
            for value in (True, False, None, "1", 1.0, 0, -1, 501):
                with self.subTest(value=value), self.assertRaises(db.AuditStoreError):
                    db.drain_metadata_audit_outbox(value)
        forbidden.assert_not_called()
        with self.connection() as conn:
            conn.execute("DROP TABLE metadata_audit_outbox")
        with self.assertRaises(sqlite3.OperationalError):
            db.drain_metadata_audit_outbox()

    def test_borrowed_active_transaction_keeps_original_path_and_owner_commit(self):
        with self.connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("INSERT INTO unrelated VALUES ('borrowed')")
            self.queries.clear()
            with patch.object(db, "connect", lambda: db._BorrowedMetadataConnection(conn)):
                self.assertEqual(db.drain_metadata_audit_outbox(), ZERO)
            self.assertNotIn(PROBE, self.queries)
            self.assertTrue(any("SELECT COUNT(*)" in sql for sql in self.queries))
            self.assertTrue(conn.in_transaction)
            self.assertEqual(self.rows("unrelated"), [])
            conn.rollback()
        self.assertEqual(self.rows("unrelated"), [])

    def test_postgres_branch_never_uses_sqlite_empty_shortcut(self):
        forbidden = Mock(side_effect=AssertionError("measured PostgreSQL refusal opened a connection"))
        with patch.object(db, "audit_uses_postgres", lambda: True), \
                patch.object(db, "metadata_uses_postgres", lambda: True), \
                patch.object(db, "connect", forbidden):
            with self.assertRaisesRegex(db.AuditStoreError, "measured policy-authority verifier"):
                db.drain_metadata_audit_outbox()
        forbidden.assert_not_called()
        # The separate legacy SQLite-metadata/PostgreSQL-audit branch still
        # uses its original claim path even when there are no rows to send.
        self.queries.clear()
        with patch.object(db, "audit_uses_postgres", lambda: True):
            self.assertEqual(db.drain_metadata_audit_outbox(), ZERO)
        self.assertNotIn(PROBE, self.queries)
        self.assertIn("BEGIN IMMEDIATE", self.queries)


if __name__ == "__main__":
    unittest.main()
