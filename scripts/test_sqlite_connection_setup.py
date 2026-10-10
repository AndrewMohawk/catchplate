#!/usr/bin/env python3
"""Real disposable-SQLite setup controls, not deployed latency acceptance.

Synthetic clocks and registration/SQL fault seams test sampled deadlines and
cleanup, not forced interruption of CPU or filesystem stalls. A separate finite
child tests fork reset without reusing any inherited SQLite connection.
"""
from __future__ import annotations

from contextlib import ExitStack, closing
from pathlib import Path
import os
import sqlite3
import subprocess
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from serverware import sqlite_connection_setup as setup

REAL_CONNECT = sqlite3.connect


class TrackingConnection(sqlite3.Connection):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.statements, self.close_count = [], 0
        self.failure, self.fault, self.close_failure, self.after_execute = None, None, False, None

    def create_function(self, name, *args, **kwargs):
        if self.fault == name:
            raise self.failure
        return super().create_function(name, *args, **kwargs)

    def execute(self, statement, parameters=()):
        restoring = statement == "PRAGMA busy_timeout=10000" and "PRAGMA foreign_keys=ON" in self.statements
        self.statements.append(statement)
        if statement == self.fault or (self.fault == "restore" and restoring):
            raise self.failure
        cursor = super().execute(statement, parameters)
        if self.after_execute:
            self.after_execute(statement, restoring)
        return cursor

    def close(self):
        self.close_count += 1
        super().close()
        if self.close_failure:
            raise OSError("synthetic secondary close failure")


class SqliteConnectionSetupTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        for name in ("socket.socket", "socket.create_connection", "socket.getaddrinfo"):
            self.stack.enter_context(patch(name, side_effect=AssertionError("SQLite setup test attempted network")))
        directory = self.stack.enter_context(tempfile.TemporaryDirectory(prefix="serverware-sqlite-setup-"))
        self.path = Path(directory) / "synthetic.sqlite3"
        with closing(REAL_CONNECT(self.path)) as conn, conn:
            conn.executescript("CREATE TABLE parent(id INTEGER PRIMARY KEY);"
                "CREATE TABLE child(parent_id INTEGER REFERENCES parent(id));"
                "INSERT INTO parent VALUES(1);")
        self.connections, self.timeouts, self.deadlines = [], [], []
        self.fault, self.failure, self.close_failure, self.after_execute = None, None, False, None
        self.stack.callback(self.close_leaks)
        self.stack.enter_context(patch.object(setup, "_SETUP_LOCK", threading.RLock()))
        self.stack.enter_context(patch.object(setup, "_SETUP_STATE", threading.local()))
        self.connect = self.stack.enter_context(patch.object(setup.sqlite3, "connect", side_effect=self.connection))

    def connection(self, path, *, timeout):
        conn = REAL_CONNECT(path, timeout=timeout, factory=TrackingConnection)
        conn.fault, conn.failure = self.fault, self.failure
        conn.close_failure, conn.after_execute = self.close_failure, self.after_execute
        self.connections.append(conn)
        self.timeouts.append(timeout)
        self.deadlines.append(setup._SETUP_STATE.deadline_ns)
        return conn

    def close_leaks(self):
        for conn in self.connections:
            if conn.close_count == 0:
                sqlite3.Connection.close(conn)

    def closed(self, conn):
        self.assertEqual(conn.close_count, 1)
        with self.assertRaises(sqlite3.ProgrammingError):
            sqlite3.Connection.execute(conn, "SELECT 1")

    def assert_ready(self, conn):
        self.assertIs(conn.row_factory, sqlite3.Row)
        self.assertEqual(conn.execute("PRAGMA journal_mode").fetchone()[0], "wal")
        self.assertEqual(conn.execute("PRAGMA foreign_keys").fetchone()[0], 1)
        self.assertEqual(conn.execute("PRAGMA busy_timeout").fetchone()[0], 10000)
        self.assertEqual(conn.execute("SELECT regexp('^yes$', 'yes'), operator_google_cleanup_retire_allowed('synthetic')").fetchone()[:], (1, 0))
        self.assertFalse(conn.in_transaction)

    def test_real_transition_udfs_foreign_keys_fresh_handles_and_replaced_path(self):
        with closing(REAL_CONNECT(self.path)) as baseline:
            self.assertEqual(baseline.execute("PRAGMA journal_mode").fetchone()[0], "delete")
        first, second = setup.open_metadata_connection(self.path), setup.open_metadata_connection(self.path)
        try:
            self.assertIsNot(first, second)
            self.assert_ready(first)
            self.assert_ready(second)
            with self.assertRaises(sqlite3.IntegrityError):
                first.execute("INSERT INTO child VALUES(99)")
            first.rollback()
            first.execute("INSERT INTO child VALUES(1)")
            first.commit()
            self.assertEqual(second.execute("SELECT parent_id FROM child").fetchone()[0], 1)
        finally:
            first.close()
            second.close()
        replacement = self.path.with_name("replacement.sqlite3")
        with closing(REAL_CONNECT(replacement)) as conn, conn:
            conn.execute("CREATE TABLE replacement (id INTEGER)")
        replacement.replace(self.path)
        with closing(setup.open_metadata_connection(self.path)) as fresh:
            self.assert_ready(fresh)
            self.assertEqual(fresh.execute("SELECT count(*) FROM replacement").fetchone()[0], 0)
            with self.assertRaises(sqlite3.OperationalError):
                fresh.execute("SELECT * FROM parent")

    def test_concurrent_setup_exclusion_and_returned_queries_are_outside_gate(self):
        entered, release, waiter = threading.Event(), threading.Event(), threading.Event()
        original_register = setup.metadata_schema.configure_sqlite_metadata_connection
        native_gate = threading.RLock()
        class Gate:
            def acquire(self, **kwargs):
                if threading.current_thread().name == "setup-second":
                    waiter.set()
                return native_gate.acquire(**kwargs)
            def release(self):
                native_gate.release()
        def register(conn):
            if threading.current_thread().name == "setup-first":
                entered.set()
                if not release.wait(3):
                    raise AssertionError("setup release was not delivered")
            original_register(conn)
        failures, finished = [], []
        def worker():
            try:
                with closing(setup.open_metadata_connection(self.path)) as conn:
                    self.assert_ready(conn)
                    finished.append(threading.current_thread().name)
            except BaseException as error:
                failures.append(error)
        threads = [threading.Thread(target=worker, name=name, daemon=True)
            for name in ("setup-first", "setup-second")]
        with patch.object(setup, "_SETUP_LOCK", Gate()), \
                patch.object(setup.metadata_schema, "configure_sqlite_metadata_connection", side_effect=register):
            try:
                threads[0].start()
                self.assertTrue(entered.wait(3))
                acquired = native_gate.acquire(blocking=False)
                if acquired:
                    native_gate.release()
                self.assertFalse(acquired, "registration must still own the setup gate")
                threads[1].start()
                self.assertTrue(waiter.wait(3))
                self.assertEqual(len(self.connections), 1)
            finally:
                release.set()
                for thread in threads:
                    if thread.ident is not None:
                        thread.join(4)
            self.assertFalse(any(thread.is_alive() for thread in threads))
            self.assertEqual(failures, [])
            self.assertCountEqual(finished, ["setup-first", "setup-second"])
        # The query executes in its owning thread while another thread holds
        # the setup gate. No elapsed-time threshold is used as the oracle.
        ready, query, done, release_worker = (threading.Event() for _ in range(4))
        def caller():
            try:
                with closing(setup.open_metadata_connection(self.path)) as conn:
                    ready.set()
                    if not query.wait(3):
                        raise AssertionError("query signal missing")
                    conn.execute("INSERT INTO child VALUES(1)")
                    conn.commit()
                    done.set()
                    release_worker.wait(3)
            except BaseException as error:
                failures.append(error)
        thread = threading.Thread(target=caller, daemon=True)
        thread.start()
        try:
            self.assertTrue(ready.wait(3))
            with setup._SETUP_LOCK:
                query.set()
                self.assertTrue(done.wait(3))
        finally:
            query.set()
            release_worker.set()
            thread.join(4)
        self.assertFalse(thread.is_alive())
        self.assertEqual(failures, [])

    def test_nested_setup_inherits_earliest_deadline_without_deadlock_or_reset(self):
        clock = SimpleNamespace(now=100_000_000_000)
        original_register = setup.metadata_schema.configure_sqlite_metadata_connection
        nested = []
        def register(conn):
            original_register(conn)
            if not nested:
                nested.append(True)
                clock.now += 3_000_000_000
                with closing(setup.open_metadata_connection(self.path.with_name("nested.sqlite3"))) as child:
                    self.assert_ready(child)
        with patch.object(setup, "time", SimpleNamespace(monotonic_ns=lambda: clock.now)), \
                patch.object(setup.metadata_schema, "configure_sqlite_metadata_connection", side_effect=register):
            with closing(setup.open_metadata_connection(self.path)) as conn:
                self.assert_ready(conn)
            self.assertEqual(self.timeouts, [10.0, 7.0])
            self.assertEqual(self.deadlines, [110_000_000_000, 110_000_000_000])
            self.assertIsNone(setup._SETUP_STATE.deadline_ns)
            clock.now += 20_000_000_000
            with closing(setup.open_metadata_connection(self.path)):
                pass
            self.assertEqual(self.timeouts[-1], 10.0)
            self.assertEqual(self.deadlines[-1], 133_000_000_000)

    def test_gate_wait_consumes_busy_budget_and_expired_work_never_opens_or_returns(self):
        clock = SimpleNamespace(now=100_000_000_000)
        waits, releases = [], []
        class DelayedGate:
            delay = 4_000_000_000
            def acquire(self, *, timeout):
                waits.append(timeout)
                clock.now += self.delay
                return True
            def release(self):
                releases.append(True)
        gate = DelayedGate()
        with patch.object(setup, "time", SimpleNamespace(monotonic_ns=lambda: clock.now)), \
                patch.object(setup, "_SETUP_LOCK", gate):
            with closing(setup.open_metadata_connection(self.path)) as conn:
                self.assertEqual(self.timeouts, [6.0])
                self.assertEqual([sql for sql in conn.statements if sql.startswith("PRAGMA busy_timeout=")],
                    ["PRAGMA busy_timeout=6000", "PRAGMA busy_timeout=6000", "PRAGMA busy_timeout=10000"])
            self.assertEqual(waits, [10.0])
            self.assertEqual(len(releases), 1)
            gate.delay = 10_000_000_000
            count = len(self.connections)
            with self.assertRaises(sqlite3.OperationalError):
                setup.open_metadata_connection(self.path)
            self.assertEqual(len(self.connections), count)
            self.assertEqual(len(releases), 2)
            with patch.object(setup, "_SETUP_TIMEOUT_NS", 0), self.assertRaises(sqlite3.OperationalError):
                setup.open_metadata_connection(self.path)
            self.assertEqual(len(waits), 2)
        count = len(self.connections)
        refusing_gate = SimpleNamespace(acquire=lambda **kwargs: False,
            release=lambda: self.fail("unacquired gate was released"))
        with patch.object(setup, "_SETUP_LOCK", refusing_gate), self.assertRaises(sqlite3.OperationalError):
            setup.open_metadata_connection(self.path)
        self.assertEqual(len(self.connections), count)
        for late_stage in ("foreign_keys", "restore"):
            def expire(sql, restoring):
                if (late_stage == "foreign_keys" and sql == "PRAGMA foreign_keys=ON") or (late_stage == "restore" and restoring):
                    clock.now += 11_000_000_000
            self.after_execute = expire
            with patch.object(setup, "time", SimpleNamespace(monotonic_ns=lambda: clock.now)):
                with self.assertRaises(sqlite3.OperationalError):
                    setup.open_metadata_connection(self.path)
            self.closed(self.connections[-1])
            self.assertIsNone(setup._SETUP_STATE.deadline_ns)

    def test_registration_sql_and_restore_failures_close_and_preserve_original_exception(self):
        for stage in ("regexp", "operator_google_cleanup_retire_allowed", "PRAGMA journal_mode=WAL", "PRAGMA foreign_keys=ON", "restore"):
            for close_fails in (False, True):
                with self.subTest(stage=stage, close_fails=close_fails):
                    self.fault, self.failure, self.close_failure = stage, RuntimeError("synthetic setup failure"), close_fails
                    with self.assertRaises(RuntimeError) as raised:
                        setup.open_metadata_connection(self.path)
                    self.assertIs(raised.exception, self.failure)
                    self.closed(self.connections[-1])
                    self.assertIsNone(setup._SETUP_STATE.deadline_ns)
        self.fault, self.failure, self.close_failure = "PRAGMA foreign_keys=ON", KeyboardInterrupt(), True
        with self.assertRaises(KeyboardInterrupt) as raised:
            setup.open_metadata_connection(self.path)
        self.assertIs(raised.exception, self.failure)
        self.closed(self.connections[-1])
        self.fault, self.failure, self.close_failure = None, None, False
        with closing(setup.open_metadata_connection(self.path)) as recovered:
            self.assert_ready(recovered)

    def test_real_delete_exclusive_timeout_closes_then_next_setup_recovers(self):
        with closing(REAL_CONNECT(self.path)) as holder:
            self.assertEqual(holder.execute("PRAGMA journal_mode").fetchone()[0], "delete")
            holder.execute("BEGIN EXCLUSIVE")
            try:
                with patch.object(setup, "_SETUP_TIMEOUT_NS", 50_000_000):
                    with self.assertRaises(sqlite3.OperationalError):
                        setup.open_metadata_connection(self.path)
                self.closed(self.connections[-1])
            finally:
                holder.rollback()
        with closing(setup.open_metadata_connection(self.path)) as recovered:
            self.assert_ready(recovered)

    def test_child_fork_resets_held_gate_and_inherited_deadline(self):
        code = r'''
import os, signal, socket, sys, threading
sys.path.insert(0, sys.argv[1])
from serverware import sqlite_connection_setup as setup
def forbidden(*args, **kwargs):
    raise AssertionError("synthetic fork control attempted network")
socket.socket = socket.create_connection = socket.getaddrinfo = forbidden
assert "serverware.app" not in sys.modules
signal.alarm(8)
held, release = threading.Event(), threading.Event()
def holder():
    with setup._SETUP_LOCK:
        held.set()
        release.wait(6)
thread = threading.Thread(target=holder, daemon=True)
thread.start()
assert held.wait(2)
setup._SETUP_STATE.deadline_ns = 1
pid = os.fork()
if pid == 0:
    signal.alarm(3)
    try:
        assert getattr(setup._SETUP_STATE, "deadline_ns", None) is None
        conn = setup.open_metadata_connection(sys.argv[2])
        assert conn.execute("SELECT 1").fetchone()[0] == 1
        conn.close()
    except BaseException:
        os._exit(2)
    os._exit(0)
try:
    result, status = os.waitpid(pid, 0)
    assert result == pid and os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0
    assert setup._SETUP_STATE.deadline_ns == 1
finally:
    release.set()
    thread.join(2)
assert not thread.is_alive()
signal.alarm(0)
'''
        result = subprocess.run([sys.executable, "-I", "-B", "-c", code, str(ROOT), str(self.path)],
            capture_output=True, timeout=10, check=False)
        self.assertEqual(result.returncode, 0, "bounded synthetic fork control failed")
        self.assertEqual(result.stdout, b"")
        self.assertEqual(result.stderr, b"")

    def test_actual_db_connect_borrowed_postgres_and_sqlite_dispatch(self):
        from serverware import db
        with closing(REAL_CONNECT(self.path)) as borrowed:
            token = db._policy_candidate_offline_connection.set(borrowed)
            try:
                with patch.object(setup, "open_metadata_connection", side_effect=AssertionError("borrowed entered setup")), \
                        patch.object(db, "ensure_data_dirs", side_effect=AssertionError("borrowed entered directory setup")):
                    facade = db.connect()
                    self.assertIsInstance(facade, db._BorrowedMetadataConnection)
                    with facade as exact:
                        self.assertIs(exact, borrowed)
                    self.assertEqual(borrowed.execute("SELECT 1").fetchone()[0], 1)
            finally:
                db._policy_candidate_offline_connection.reset(token)
        raw = object()
        with patch.object(db, "_reject_runtime_metadata_admin_dsn") as admission, \
                patch.object(db, "ensure_data_dirs") as directories, \
                patch.object(db, "metadata_uses_postgres", return_value=True), \
                patch.object(db, "_metadata_pg_connect_raw", return_value=raw) as postgres, \
                patch.object(setup, "open_metadata_connection", side_effect=AssertionError("PostgreSQL entered SQLite setup")):
            wrapper = db.connect()
            self.assertIsInstance(wrapper, db.PostgresMetadataConnection)
            self.assertIs(wrapper.raw_connection, raw)
            admission.assert_called_once_with()
            directories.assert_called_once_with()
            postgres.assert_called_once_with()
        with patch.object(db, "_reject_runtime_metadata_admin_dsn"), patch.object(db, "ensure_data_dirs"), \
                patch.object(db, "metadata_uses_postgres", return_value=False), patch.object(db, "DB_PATH", self.path), \
                patch.object(setup, "open_metadata_connection", wraps=setup.open_metadata_connection) as real_setup:
            with closing(db.connect()) as conn:
                self.assert_ready(conn)
            real_setup.assert_called_once_with(self.path)


if __name__ == "__main__":
    unittest.main()
