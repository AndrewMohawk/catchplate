#!/usr/bin/env python3
"""Synthetic libpq protocol controls only; no DB, socket, process or native run.

The real helper and profile parser are used. All pq/select/clock boundaries are
scripted, so these tests establish neither libpq timing nor server isolation.
"""
from __future__ import annotations

from contextlib import ExitStack
import json
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from catchplate import native_postgres_probe as subject
from catchplate.native_postgres_profile import NativePostgresProfileError


class OperationalError(Exception):
    pass


def good_values() -> list[bytes | None]:
    settings = {
        "listen_addresses": "", "unix_socket_directories": "/run/catchplate-native-postgres",
        "unix_socket_permissions": "0700", "port": "5432", "ssl": "off",
        "fsync": "on", "full_page_writes": "on", "synchronous_commit": "on",
        "log_destination": "stderr", "logging_collector": "off", "max_connections": "32",
        "shared_buffers": "8192", "work_mem": "4096", "maintenance_work_mem": "32768",
        "max_wal_size": "256", "min_wal_size": "80", "temp_file_limit": "131072",
        "jit": "off", "restart_after_crash": "off",
        "data_directory": "/var/lib/catchplate-runner/native-postgres/pgdata",
        "data_checksums": "on", "block_size": "8192",
    }
    return [b"160006", b"UTF8", b"UTF8", b"postgres", b"catchplate_fixture_admin",
            b"catchplate_fixture_admin", b"t", None, b"f", b"7423456789012345678",
            json.dumps(settings).encode("ascii")]


class Result:
    def __init__(self):
        self.status = 2
        self.ntuples = 1
        self.nfields = 11
        self.values = good_values()
        self.formats = [0] * 11

    def fformat(self, index):
        return self.formats[index]

    def get_value(self, row, column):
        if row != 0:
            raise AssertionError("helper requested an unexpected row")
        return self.values[column]


def take(values):
    return values.pop(0) if len(values) > 1 else values[0]


class Connection:
    def __init__(self, harness):
        self.harness = harness
        self.status = 0
        self.socket = 37
        self.polls = [3]
        self.flushes = [0]
        self.busy = [0]
        self.last_busy = None
        self.results = [Result(), None]
        self.errors = {}
        self._nonblocking = 0
        self.finished = False

    def step(self, name):
        self.harness.events.append(name)
        if name in self.errors:
            raise self.errors[name]

    def connect_poll(self):
        self.step("poll")
        return take(self.polls)

    @property
    def nonblocking(self):
        return self._nonblocking

    @nonblocking.setter
    def nonblocking(self, value):
        self.step("nonblocking")
        self._nonblocking = value

    def send_query(self, query):
        self.step("send")
        if self._nonblocking != 1:
            raise AssertionError("query sent before nonblocking mode")
        self.harness.queries.append(query)

    def flush(self):
        self.step("flush")
        return take(self.flushes)

    def consume_input(self):
        self.step("consume")
        if not self.harness.readable:
            raise AssertionError("input consumed without observed readable socket")
        self.harness.readable = False

    def is_busy(self):
        self.step("busy")
        self.last_busy = take(self.busy)
        return self.last_busy

    def get_result(self):
        self.step("result")
        if self.last_busy != 0 or not self.results:
            raise AssertionError("blocking or excess result retrieval")
        return self.results.pop(0)

    def finish(self):
        self.finished = True
        self.step("finish")


class Harness:
    def __init__(self):
        self.now = 100.0
        self.events = []
        self.pumps = []
        self.selects = []
        self.connections = []
        self.queries = []
        self.readiness = []
        self.readable = False
        self.alive_error = None
        self.alive_at = None
        self.start_error = None
        self.connection = Connection(self)

    def start(self, conninfo):
        self.events.append("start")
        self.connections.append(conninfo)
        if self.start_error is not None:
            raise self.start_error
        return self.connection

    def pump(self, duration):
        if not 0 <= duration <= 0.05:
            raise AssertionError("unbounded supervisor pump")
        self.events.append("pump")
        self.pumps.append(duration)
        self.now += max(duration, 0.001)

    def alive(self):
        self.events.append("alive")
        if self.alive_error is not None and (self.alive_at is None or self.now >= self.alive_at):
            raise self.alive_error

    def select(self, readers, writers, exceptional, timeout):
        if timeout != 0 or exceptional != [self.connection.socket]:
            raise AssertionError("select is not a nonblocking exact socket check")
        self.events.append("select")
        self.selects.append((readers, writers, exceptional, timeout))
        readable, writable, failure = self.readiness.pop(0) if self.readiness else (True, True, False)
        self.readable = bool(readers) and readable
        return (readers if readable else [], writers if writable else [],
                exceptional if failure else [])

    def __enter__(self):
        self.stack = ExitStack()
        pq = types.ModuleType("psycopg.pq")
        pq.PGconn = types.SimpleNamespace(connect_start=self.start)
        pq.ConnStatus = types.SimpleNamespace(OK=0, BAD=1)
        pq.PollingStatus = types.SimpleNamespace(FAILED=0, READING=1, WRITING=2, OK=3)
        pq.ExecStatus = types.SimpleNamespace(TUPLES_OK=2)
        psycopg = types.ModuleType("psycopg")
        psycopg.pq = pq
        psycopg.OperationalError = OperationalError
        self.stack.enter_context(patch.dict(sys.modules, {"psycopg": psycopg, "psycopg.pq": pq}))
        self.stack.enter_context(patch.object(subject.time, "monotonic", lambda: self.now))
        self.stack.enter_context(patch.object(subject.select, "select", self.select))
        return self

    def __exit__(self, *args):
        return self.stack.__exit__(*args)

    def run(self, deadline=None):
        return subject.probe(pump=self.pump, check_alive=self.alive,
                             deadline=self.now + 5 if deadline is None else deadline)


class NativePostgresProbeTests(unittest.TestCase):
    def test_fixed_positive_decodes_real_profile_and_drains_terminal_result(self):
        with Harness() as harness:
            result = harness.run()
            self.assertEqual(result, subject.NativePostgresProbe(160006, "7423456789012345678"))
            self.assertEqual(harness.queries, [subject.READINESS_SQL.encode("ascii")])
            self.assertEqual(harness.connections, [subject.CONNECTION_INFO])
            self.assertIn(b"host=/run/catchplate-native-postgres port=5432", harness.connections[0])
            self.assertIn(b"password='' passfile=/dev/null", harness.connections[0])
            self.assertEqual(harness.events.count("result"), 2)
            self.assertEqual(harness.events[-1], "finish")
            self.assertLess(harness.events.index("nonblocking"), harness.events.index("send"))
            self.assertTrue(harness.connection.finished)

    def test_connection_read_write_poll_waits_keep_pumping_and_checking_liveness(self):
        with Harness() as harness:
            harness.connection.polls = [2, 1, 3]
            harness.readiness = [(False, False, False), (False, True, False), (True, False, False)]
            harness.run()
            self.assertEqual(harness.events.count("poll"), 3)
            self.assertEqual(harness.selects[0][0:2], ([], [37]))
            self.assertEqual(harness.selects[-1][0:2], ([37], []))
            self.assertIn(0.05, harness.pumps)
            self.assertGreater(harness.events.count("alive"), 3)

    def test_pending_query_flush_consumes_readable_input_without_blocking(self):
        with Harness() as harness:
            harness.connection.flushes = [1, 1, 0]
            harness.readiness = [(True, False, False), (False, True, False)]
            harness.run()
            self.assertEqual(harness.events.count("flush"), 3)
            self.assertEqual(harness.events.count("consume"), 1)
            self.assertTrue(all(read == [37] and write == [37] for read, write, _, _ in harness.selects))

    def test_busy_row_and_terminal_marker_each_require_nonblocking_input(self):
        with Harness() as harness:
            harness.connection.busy = [1, 0, 1, 0]
            harness.run()
            self.assertEqual(harness.events.count("consume"), 2)
            self.assertEqual(harness.events.count("result"), 2)
            self.assertTrue(all(read == [37] and write == [] for read, write, _, _ in harness.selects))

    def test_only_initial_bad_failed_and_operational_connect_errors_are_unavailable(self):
        for variant in ("bad", "failed", "start", "poll"):
            with self.subTest(variant=variant), Harness() as harness:
                if variant == "bad":
                    harness.connection.status = 1
                elif variant == "failed":
                    harness.connection.polls = [0]
                elif variant == "start":
                    harness.start_error = OperationalError("connect")
                else:
                    harness.connection.errors["poll"] = OperationalError("poll")
                with self.assertRaises(subject.NativePostgresProbeUnavailable):
                    harness.run()
                self.assertEqual(harness.connection.finished, variant != "start")
                self.assertEqual(harness.queries, [])

    def test_liveness_failures_are_not_mislabeled_connection_unavailable(self):
        with Harness() as harness:
            failure = OperationalError("caller liveness denial")
            harness.alive_error = failure
            harness.alive_at = 100.002
            with self.assertRaises(OperationalError) as caught:
                harness.run()
            self.assertIs(caught.exception, failure)
            self.assertTrue(harness.connection.finished)
            self.assertEqual(harness.queries, [])

    def test_postconnect_operational_failures_are_terminal_and_always_finish(self):
        for stage in ("nonblocking", "send", "flush", "consume", "result", "finish"):
            with self.subTest(stage=stage), Harness() as harness:
                error = OperationalError(stage)
                harness.connection.errors[stage] = error
                if stage == "consume":
                    harness.connection.busy = [1]
                with self.assertRaises(OperationalError) as caught:
                    harness.run()
                self.assertIs(caught.exception, error)
                self.assertTrue(harness.connection.finished)

    def test_connect_and_query_stalls_are_deadline_terminal_not_retryable(self):
        for stage in ("connect", "flush", "row", "terminal"):
            with self.subTest(stage=stage), Harness() as harness:
                if stage == "connect":
                    harness.connection.polls = [1]
                elif stage == "flush":
                    harness.connection.flushes = [1]
                elif stage == "row":
                    harness.connection.busy = [1]
                else:
                    harness.connection.busy = [0, 1]
                harness.readiness = [(False, False, False)] * 200
                with self.assertRaisesRegex(subject.NativePostgresProbeError, "deadline exceeded") as caught:
                    harness.run()
                self.assertNotIsInstance(caught.exception, subject.NativePostgresProbeUnavailable)
                self.assertTrue(harness.connection.finished)
                self.assertLessEqual(harness.now, 105.051)
                self.assertEqual(harness.events.count("result"), int(stage == "terminal"))

    def test_invalid_deadline_and_callbacks_deny_before_connect(self):
        for deadline in (True, "105", None, float("nan"), float("inf"), -1, 100, 105.001, 1 << 4096):
            with self.subTest(deadline=deadline), Harness() as harness:
                with self.assertRaises(subject.NativePostgresProbeError):
                    subject.probe(pump=harness.pump, check_alive=harness.alive, deadline=deadline)
                self.assertEqual(harness.connections, [])
        with Harness() as harness:
            with self.assertRaises(subject.NativePostgresProbeError):
                subject.probe(pump=None, check_alive=harness.alive, deadline=105)
            self.assertEqual(harness.connections, [])

    def test_cancellation_during_query_finishes_without_success(self):
        with Harness() as harness:
            harness.connection.busy = [1]
            harness.readiness = [(False, False, False)] * 20
            cancelled = RuntimeError("cancelled")
            harness.alive_error = cancelled
            harness.alive_at = 100.1
            with self.assertRaises(RuntimeError) as caught:
                harness.run()
            self.assertIs(caught.exception, cancelled)
            self.assertTrue(harness.connection.finished)
            self.assertLess(harness.now, 101)

    def test_invalid_poll_flush_busy_or_socket_state_denies(self):
        for variant in ("poll", "flush", "busy", "socket", "exceptional"):
            with self.subTest(variant=variant), Harness() as harness:
                if variant == "poll":
                    harness.connection.polls = [99]
                elif variant == "flush":
                    harness.connection.flushes = [True]
                elif variant == "busy":
                    harness.connection.busy = [True]
                else:
                    harness.connection.polls = [1]
                    if variant == "socket":
                        harness.connection.socket = -1
                    else:
                        harness.readiness = [(False, False, True)]
                with self.assertRaises(subject.NativePostgresProbeError):
                    harness.run()
                self.assertTrue(harness.connection.finished)

    def test_result_status_shape_and_text_formats_are_exact(self):
        for field, value in (("status", 1), ("ntuples", 0), ("ntuples", 2),
                             ("ntuples", True), ("nfields", 10), ("nfields", 12)):
            with self.subTest(field=field, value=value), Harness() as harness:
                setattr(harness.connection.results[0], field, value)
                with self.assertRaisesRegex(subject.NativePostgresProbeError, "eleven-column"):
                    harness.run()
                self.assertTrue(harness.connection.finished)
        with Harness() as harness:
            harness.connection.results[0].formats[10] = 1
            with self.assertRaisesRegex(subject.NativePostgresProbeError, "text format"):
                harness.run()

    def test_missing_and_extra_results_never_succeed(self):
        for results in ([None], [Result(), Result(), None]):
            with self.subTest(count=len(results)), Harness() as harness:
                harness.connection.results = results
                with self.assertRaisesRegex(subject.NativePostgresProbeError, "missing|extra results"):
                    harness.run()
                self.assertTrue(harness.connection.finished)

    def test_fields_are_bounded_exact_bytes_ascii_and_null_only_for_socket(self):
        cases = ((1, None), (1, b""), (1, "UTF8"), (1, bytearray(b"UTF8")),
                 (1, b"x" * 257), (10, b"x" * 16385), (1, b"UTF8\x00"),
                 (1, b"\xc3\xa9"), (7, b"127.0.0.1"))
        for index, value in cases:
            with self.subTest(index=index, value_type=type(value)), Harness() as harness:
                harness.connection.results[0].values[index] = value
                with self.assertRaises(subject.NativePostgresProbeError):
                    harness.run()
                self.assertTrue(harness.connection.finished)

    def test_scalar_spelling_and_actual_profile_drift_are_rejected(self):
        cases = ((0, b"0160006"), (0, b"160006.0"), (6, b"true"), (8, b"0"),
                 (0, b"150006"), (6, b"f"), (8, b"t"), (9, b"01"), (4, b"another_role"))
        for index, value in cases:
            with self.subTest(index=index, value=value), Harness() as harness:
                harness.connection.results[0].values[index] = value
                with self.assertRaises((subject.NativePostgresProbeError, NativePostgresProfileError)):
                    harness.run()

    def test_settings_json_rejects_duplicates_numbers_nonfinite_nested_and_drift(self):
        cases = (b'{"port":"5432","port":"5432"}', b'{"port":5432}',
                 b'{"port":5.432e3}', b'{"port":NaN}', b'{"port":true}',
                 b'{"port":null}', b'{"port":{}}', b'[]', b'{"port":"5433"}',
                 b'{"port":"5432\\u0000"}', b'{')
        for raw in cases:
            with self.subTest(raw=raw), Harness() as harness:
                harness.connection.results[0].values[10] = raw
                with self.assertRaises((subject.NativePostgresProbeError, NativePostgresProfileError)):
                    harness.run()
                self.assertTrue(harness.connection.finished)


if __name__ == "__main__":
    unittest.main()
