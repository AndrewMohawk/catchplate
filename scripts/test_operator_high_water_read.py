#!/usr/bin/env python3
"""Real disposable-SQLite reader controls, not deployment/profile acceptance.

The actual _require/get/verify functions run with a synthetic operator-active
flag and a connection factory selecting only this test's temporary database.
No retained application data, signing keys, network or service is accessed.
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

SQL = "SELECT sequence, policy_hash, updated_at FROM operator_demo_policy WHERE singleton=1"
SCHEMA = """CREATE TABLE operator_demo_policy (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1), sequence INTEGER NOT NULL,
    policy_hash TEXT NOT NULL, signed_bundle_json TEXT NOT NULL,
    initial_hash TEXT NOT NULL, updated_at TEXT NOT NULL)"""


class TrackingCursor(sqlite3.Cursor):
    def fetchone(self):
        self.connection.events.append("fetch")
        row = super().fetchone()
        self.connection.projection = tuple(item[0] for item in self.description)
        if self.connection.fault == "fetch":
            raise self.connection.failure
        return row


class TrackingConnection(sqlite3.Connection):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.events, self.read_columns, self.statements = [], [], []
        self.close_count, self.fault, self.failure = 0, None, None

    def __enter__(self):
        self.events.append("enter")
        if self.fault == "enter":
            raise self.failure
        return super().__enter__()

    def __exit__(self, kind, value, traceback):
        self.events.append(("exit", kind))
        result = super().__exit__(kind, value, traceback)
        if self.fault == "exit":
            raise self.failure
        return result

    def execute(self, sql, parameters=()):
        self.events.append("execute")
        return self.cursor(factory=TrackingCursor).execute(sql, parameters)

    def close(self):
        self.close_count += 1
        self.events.append("close")
        return super().close()


class OperatorHighWaterReadTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        for target in ("socket.socket", "socket.create_connection", "socket.getaddrinfo"):
            self.stack.enter_context(patch(target, side_effect=AssertionError("SQLite unit test attempted network I/O")))
        from catchplate import db, operator_demo, operator_demo_store
        self.db, self.store = db, operator_demo_store
        directory = self.stack.enter_context(tempfile.TemporaryDirectory(prefix="catchplate-high-water-unit-"))
        self.path = Path(directory) / "synthetic.sqlite3"
        self.bundle = '{"syntheticOnly":true,"canary":"' + "synthetic-bundle-not-selected-" * 4096 + '"}'
        self.first_hash = "sha256:" + hashlib.sha256(self.bundle.encode()).hexdigest()
        self.first_time = "2026-10-10T12:00:00+00:00"
        with closing(sqlite3.connect(self.path)) as conn, conn:
            conn.execute(SCHEMA)
            conn.execute("INSERT INTO operator_demo_policy VALUES(1,?,?,?,?,?)",
                         (7, self.first_hash, self.bundle, "sha256:" + "0" * 64, self.first_time))
        self.connections, self.fault, self.failure = [], None, None
        # Close any leaked fixture connection only after assertions have failed.
        self.stack.callback(self.close_leaks)
        self.active = self.stack.enter_context(patch.object(operator_demo, "active", return_value=True))
        self.connect = self.stack.enter_context(patch.object(db, "connect", side_effect=self.open_connection))

    def close_leaks(self):
        for conn in self.connections:
            if conn.close_count == 0:
                conn.close()

    def open_connection(self):
        conn = sqlite3.connect(self.path, factory=TrackingConnection)
        conn.row_factory = sqlite3.Row
        conn.fault, conn.failure = self.fault, self.failure
        def authorize(action, table, column, database, trigger):
            if action == sqlite3.SQLITE_READ and table == "operator_demo_policy":
                conn.read_columns.append(column)
                if column in {"signed_bundle_json", "initial_hash"}:
                    return sqlite3.SQLITE_DENY
            return sqlite3.SQLITE_OK
        conn.set_authorizer(authorize)
        conn.set_trace_callback(conn.statements.append)
        self.connections.append(conn)
        return conn

    def expected(self, *, sequence=7, policy_hash=None, updated_at=None):
        return {"policy_id": "catchplate-operator-demo", "sequence": sequence, "rollback_epoch": 1,
                "policy_hash": self.first_hash if policy_hash is None else policy_hash,
                "updated_at": self.first_time if updated_at is None else updated_at}

    def closed(self, conn):
        self.assertEqual(conn.close_count, 1)
        self.assertEqual(conn.events[-1], "close")
        with self.assertRaises(sqlite3.ProgrammingError):
            sqlite3.Connection.execute(conn, "SELECT 1")

    def test_exact_projection_succeeds_when_full_bundle_column_reads_are_denied(self):
        # The same actual authorizer rejects the former SELECT * query.
        probe = self.open_connection()
        try:
            with probe, self.assertRaises(sqlite3.DatabaseError):
                probe.execute("SELECT * FROM operator_demo_policy WHERE singleton=1").fetchone()
        finally:
            probe.close()
        self.assertIn("signed_bundle_json", probe.read_columns)
        self.closed(probe)
        self.assertEqual(self.store.get_policy_high_water(), self.expected())
        conn = self.connections[-1]
        self.assertEqual(conn.projection, ("sequence", "policy_hash", "updated_at"))
        self.assertEqual(set(conn.read_columns), {"sequence", "policy_hash", "updated_at", "singleton"})
        self.assertEqual(conn.statements, [SQL])
        self.assertEqual(conn.events, ["enter", "execute", "fetch", ("exit", None), "close"])
        self.connect.assert_called_once_with()
        self.active.assert_called_once_with()
        self.closed(conn)

    def test_absent_singleton_returns_none_and_closes_owned_connection(self):
        with closing(sqlite3.connect(self.path)) as writer, writer:
            writer.execute("DELETE FROM operator_demo_policy")
        self.assertIsNone(self.store.get_policy_high_water())
        conn = self.connections[-1]
        self.assertEqual(conn.statements, [SQL])
        self.assertEqual(conn.events, ["enter", "execute", "fetch", ("exit", None), "close"])
        self.closed(conn)
        with self.assertRaisesRegex(ValueError, "signed policy does not match committed operator demo state"):
            self.store.verify_policy_high_water(**self.expected())
        self.closed(self.connections[-1])

    def test_real_sqlite_query_error_is_preserved_and_connection_closed(self):
        with closing(sqlite3.connect(self.path)) as writer, writer:
            writer.execute("DROP TABLE operator_demo_policy")
        with self.assertRaises(sqlite3.OperationalError):
            self.store.get_policy_high_water()
        conn = self.connections[-1]
        self.assertEqual(conn.events, ["enter", "execute", ("exit", sqlite3.OperationalError), "close"])
        self.closed(conn)

    def test_enter_fetch_exit_and_state_failures_close_once_without_replacing_error(self):
        for stage in ("enter", "fetch", "exit", "state"):
            with self.subTest(stage=stage):
                self.fault = stage
                failure = self.failure = RuntimeError("synthetic high-water failure")
                with ExitStack() as faults:
                    if stage == "state":
                        def reject_state(row):
                            self.assertIs(type(row), sqlite3.Row)
                            self.assertEqual(row.keys(), ["sequence", "policy_hash", "updated_at"])
                            self.closed(self.connections[-1])
                            raise failure
                        faults.enter_context(patch.object(self.store, "_state", reject_state))
                    with self.assertRaises(RuntimeError) as caught:
                        self.store.get_policy_high_water()
                self.assertIs(caught.exception, failure)
                conn = self.connections[-1]
                self.closed(conn)
                if stage == "enter":
                    self.assertEqual(conn.events, ["enter", "close"])
                elif stage == "fetch":
                    self.assertIn(("exit", RuntimeError), conn.events)
                else:
                    self.assertIn(("exit", None), conn.events)

    def test_each_read_observes_new_commit_and_verifier_preserves_all_comparisons(self):
        before = self.store.get_policy_high_water()
        next_hash = "sha256:" + hashlib.sha256(b"synthetic-next-policy").hexdigest()
        next_time = "2026-10-10T12:01:00+00:00"
        with closing(sqlite3.connect(self.path)) as writer, writer:
            writer.execute("UPDATE operator_demo_policy SET sequence=?,policy_hash=?,updated_at=? WHERE singleton=1",
                           (8, next_hash, next_time))
        after = self.store.get_policy_high_water()
        expected = self.expected(sequence=8, policy_hash=next_hash, updated_at=next_time)
        self.assertEqual(before, self.expected())
        self.assertEqual(after, expected)
        self.assertEqual(self.store.verify_policy_high_water(**expected, _connection=None, _allow_pending=False), expected)
        for key, wrong in (("policy_id", "synthetic-other-policy"), ("sequence", 7), ("rollback_epoch", 2),
                           ("policy_hash", self.first_hash), ("updated_at", self.first_time), ("unknown", "value")):
            with self.subTest(field=key), self.assertRaisesRegex(ValueError, "signed policy does not match committed operator demo state"):
                self.store.verify_policy_high_water(**{**expected, key: wrong})
        with closing(sqlite3.connect(self.path)) as supplied:
            for extra in ({"_connection": supplied}, {"_allow_pending": True}):
                with self.assertRaisesRegex(ValueError, "signed policy does not match committed operator demo state"):
                    self.store.verify_policy_high_water(**expected, **extra)
                self.assertEqual(supplied.execute("SELECT sequence FROM operator_demo_policy").fetchone(), (8,))
        self.assertEqual(len({id(conn) for conn in self.connections}), len(self.connections))
        for conn in self.connections:
            self.closed(conn)
            self.assertEqual(conn.statements, [SQL])

    def test_profile_refusal_and_connection_failure_do_not_open_or_hide_owned_resources(self):
        self.active.return_value = False
        with self.assertRaisesRegex(RuntimeError, "operator demo store unavailable"):
            self.store.get_policy_high_water()
        self.connect.assert_not_called()
        self.assertEqual(self.connections, [])
        failure = RuntimeError("synthetic profile refusal")
        self.active.side_effect = failure
        with self.assertRaises(RuntimeError) as caught:
            self.store.get_policy_high_water()
        self.assertIs(caught.exception, failure)
        self.connect.assert_not_called()
        self.active.side_effect, self.active.return_value = None, True
        failure = sqlite3.OperationalError("synthetic open failure")
        self.connect.side_effect = failure
        with self.assertRaises(sqlite3.OperationalError) as caught:
            self.store.get_policy_high_water()
        self.assertIs(caught.exception, failure)
        self.connect.assert_called_once_with()
        self.assertEqual(self.connections, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
