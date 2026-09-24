#!/usr/bin/env python3
"""Synthetic lifecycle/source-input controls: no processes, filesystem or SQL.

The production orchestration and batch consumer run against explicit fake
directories/process observations and syscall doubles. One control feeds the
real recorder's synthetic TestCases. None proves actual PG16 startup, pidfds,
FD/path safety, kernel limits, storage cleanup or controller admission.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import signal
import stat
import sys
import unittest
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from serverware import native_postgres_runner as runtime
from serverware.native_postgres_batch import prepared_fixture_argv
from serverware.native_postgres_inventory import SUITES
from serverware.native_postgres_results import NativePostgresRunner


SOURCE = tuple("sha256:" + format(index + 1, "064x") for index in range(14))


def canonical(value):
    return json.dumps(value, ensure_ascii=True, allow_nan=False,
                      sort_keys=True, separators=(",", ":")).encode("ascii")


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def report(index):
    """Independent cooperative wire oracle, deliberately no native test bodies."""
    suite = SUITES[index]
    count = len(suite.test_ids)
    return {
        "schema": "serverware.nativePostgresFixtureResult/v1", "script": suite.script,
        "sourceSha256": SOURCE[index], "expectedTestIds": list(suite.test_ids),
        "tests": [{"id": identity, "started": True, "stopped": True, "status": "PASS",
                   "subtests": {"passed": 0, "failed": 0, "errored": 0, "skipped": 0}}
                  for identity in suite.test_ids],
        "suiteStatus": "PASS", "counts": {
            "expected": count, "started": count, "stopped": count, "passed": count,
            "failed": 0, "errored": 0, "skipped": 0, "expectedFailures": 0,
            "unexpectedSuccesses": 0, "incomplete": 0, "notRun": 0,
            "subtestsPassed": 0, "subtestsFailed": 0, "subtestsErrored": 0,
            "subtestsSkipped": 0, "auxiliaryErrors": 0, "protocolErrors": 0,
        }, "auxiliaryErrors": [], "protocolErrors": [],
    }


def prepared_manifest():
    return {"schema": "serverware.nativePostgresPreparedSources/v1", "scripts": [
        {"path": suite.script, "sha256": SOURCE[index]} for index, suite in enumerate(SUITES)]}


class FakeDirectory:
    def __init__(self, harness, path):
        self.harness = harness
        self.path = Path(path)
        self.closed = False
        harness.directories.append(self)

    def child(self, name):
        self.harness.events.append(("mkdir", str(self.path / name)))
        return FakeDirectory(self.harness, str(self.path / name))

    def check(self):
        self.harness.events.append(("directory-check", str(self.path)))

    def read(self, name, maximum):
        self.harness.events.append(("read", name, maximum))
        value = self.harness.reports.get(int(name[:2]))
        if isinstance(value, BaseException):
            raise value
        if value is None:
            raise FileNotFoundError(name)
        if len(value) > maximum:
            raise runtime.NativePostgresRuntimeError("synthetic oversized report")
        return value

    def publish(self, name, raw, maximum):
        self.harness.events.append(("publish", name))
        if name == self.harness.options.get("publish_failure"):
            raise OSError("synthetic publication failure")
        if type(raw) is not bytes or len(raw) > maximum:
            raise AssertionError("publication exceeds declared bound")
        self.harness.published[(str(self.path), name)] = raw

    def close(self):
        self.closed = True
        self.harness.events.append(("directory-close", str(self.path)))


class FakeChild:
    def __init__(self, phase):
        self.phase = phase
        self.returncode = None
        self.log = bytearray(("synthetic:" + str(phase)).encode("ascii"))
        self.eof = False
        self.lost = False
        self.overflow = False
        self.forced_kill = False
        self.timed_out = False

    @property
    def complete_log(self):
        return (self.returncode is not None and self.eof and not self.lost
                and not self.overflow and not self.forced_kill and not self.timed_out)


class FakeProcessSet:
    def __init__(self, harness):
        self.harness = harness
        self._children = []
        self.cancelled = False
        self.closed = False

    @property
    def children(self):
        return tuple(self._children)

    def start(self, argv, *, env, cwd):
        if argv == runtime.initdb_argv():
            phase = "init"
        elif argv == runtime.postgres_argv():
            phase = "server"
        else:
            matching = [index for index in range(14) if argv == prepared_fixture_argv(index)]
            if len(matching) != 1:
                raise AssertionError("lifecycle attempted non-fixed command")
            phase = matching[0]
        self.harness.events.append(("start", phase, argv, dict(env), cwd))
        child = FakeChild(phase)
        self._children.append(child)
        if self.harness.options.get("start_failure") == phase:
            raise OSError("synthetic failure after child retention")
        return child

    def wait(self, child, deadline, *, must_remain_alive=None):
        self.harness.events.append(("wait", child.phase, deadline, self.harness.now,
                                    None if must_remain_alive is None else must_remain_alive.phase))
        self.harness.now += 0.1
        termination = self.harness.options.get("termination", {}).get(child.phase, "exited")
        if self.harness.options.get("cancel_at") == child.phase:
            self.cancelled = True
            termination = "lost"
        if termination == "exited":
            child.returncode = self.harness.options.get("exit_codes", {}).get(child.phase, 0)
            child.eof = True
        else:
            child.timed_out = termination == "timeout"
            child.lost = termination == "lost"
        return termination

    def pump(self, timeout=0.05):
        self.harness.now += max(0.001, timeout)

    def stop(self, child, *, initial_signal, deadline):
        self.harness.events.append(("stop", child.phase, initial_signal, deadline))
        if child.phase == "server" and self.harness.options.get("unreaped_server"):
            child.lost = True
            return False
        if child.returncode is None:
            if child.phase == "server" and self.harness.options.get("forced_server"):
                child.returncode, child.forced_kill, child.lost = -9, True, True
            else:
                child.returncode = 0 if child.phase == "server" else -15
            child.eof = True
        return True

    def close(self):
        self.harness.events.append(("process-close",))
        if self.harness.options.get("close_failure") or any(c.returncode is None for c in self._children):
            raise RuntimeError("synthetic direct-child cleanup failure")
        self.closed = True


class LifecycleHarness:
    def __init__(self, **options):
        self.options = options
        self.now = 100.0
        self.events = []
        self.directories = []
        self.published = {}
        self.reports = {index: canonical(report(index)) for index in range(14)}
        self.processes = FakeProcessSet(self)
        self.probe = runtime.NativePostgresProbe(160004, "987654321")
        self.verifications = 0
        self.probes = 0
        self.signal_calls = []
        self.mask_calls = []
        self.stack = ExitStack()

    def __enter__(self):
        for name, value in (
                ("_Directory", lambda path: FakeDirectory(self, path)),
                ("ProcessSet", lambda: self.processes), ("_runtime_preflight", self.preflight),
                ("_verify_sources", self.verify_sources), ("_ready", self.ready),
                ("_probe", self.query), ("time.monotonic", lambda: self.now),
                ("signal.getsignal", lambda number: signal.SIG_DFL),
                ("signal.signal", lambda number, handler: self.signal_calls.append((number, handler))),
                ("os.umask", self.umask),
                ("os.path.lexists", lambda path: bool(self.options.get("retained_socket")))):
            self.stack.enter_context(mock.patch("serverware.native_postgres_runner." + name, value))
        # Unexpected expansion must not silently spawn or touch SQL/files.
        self.stack.enter_context(mock.patch("subprocess.Popen", side_effect=AssertionError("unexpected real spawn")))
        self.stack.enter_context(mock.patch("serverware.native_postgres_runner.query_probe",
                                           side_effect=AssertionError("unexpected actual libpq probe")))
        return self

    def __exit__(self, *exception):
        return self.stack.__exit__(*exception)

    def umask(self, value):
        self.mask_calls.append(value)
        return 0o022

    def preflight(self):
        self.events.append(("preflight",))

    def verify_sources(self, sources):
        if sources != SOURCE:
            raise AssertionError("wrong prepared source context")
        self.verifications += 1
        self.events.append(("verify-sources", self.verifications))
        if self.options.get("post_source_drift") and self.verifications == 2:
            raise runtime.NativePostgresRuntimeError("synthetic prepared source drift")

    def ready(self, processes, server, socket, deadline):
        self.events.append(("ready", deadline))
        if self.options.get("ready_failure"):
            raise runtime.NativePostgresRuntimeError("synthetic readiness failure")
        if self.options.get("exhaust_budget"):
            self.now += 5200
        return self.probe

    def query(self, *args):
        self.probes += 1
        self.events.append(("probe", self.probes))
        if self.options.get("server_dies_after_last_probe") and self.probes == 14:
            server = next(child for child in self.processes.children if child.phase == "server")
            server.returncode, server.eof = 0, True
        if self.options.get("changed_cluster"):
            return runtime.NativePostgresProbe(160004, "987654322")
        return self.probe

    def run(self):
        return runtime.execute_native_postgres(source_sha256=SOURCE)

    def phases(self):
        return [event[1] for event in self.events if event[0] == "start"]


class NativePostgresLifecycleTests(unittest.TestCase):
    def test_ten_fixed_suites_sequential_real_consumer_and_all_logs_before_local_completion(self):
        with LifecycleHarness() as harness:
            result = harness.run()
        self.assertEqual(harness.phases(), ["init", "server", *range(14)])
        self.assertEqual(result["runtimeStatus"], "COMPLETE")
        self.assertEqual((result["tests"]["tests_status"], result["tests"]["expected_tests"],
                          result["tests"]["stopped_tests"]), ("PASS", 244, 244))
        self.assertEqual(result["fixtureProcesses"], [
            {"script": suite.script, "termination": "exited", "exitCode": 0} for suite in SUITES])
        self.assertEqual([item["path"] for item in result["processLogs"]],
                         ["logs/initdb.log", *(f"logs/{index:02d}.log" for index in range(14)), "logs/postgres.log"])
        for item in result["processLogs"]:
            raw = harness.published[(runtime.OUTPUT_ROOT + "/logs", item["path"].split("/")[1])]
            self.assertEqual((item["sha256"], item["bytes"], item["complete"]), (digest(raw), len(raw), True))
        waits = [event for event in harness.events if event[0] == "wait" and type(event[1]) is int]
        self.assertEqual(len(waits), 14)
        for event, expected in zip(waits, (300, 300, 300, 300, 300, 300, 900, 300, 300, 300, 300, 300, 300, 300)):
            self.assertAlmostEqual(event[2] - event[3], expected, places=8)
        self.assertTrue(all(event[4] == "server" for event in waits))
        self.assertEqual(harness.verifications, 2)
        self.assertEqual(harness.probes, 14)
        self.assertTrue(result["externalDestructionRequired"])
        self.assertTrue(result["postmasterCleanStopObserved"])
        self.assertTrue(result["directChildrenReaped"])
        self.assertEqual(result["errors"], [])
        self.assertEqual(harness.mask_calls, [0o077, 0o022])
        self.assertTrue(all(directory.closed for directory in harness.directories))
        self.assertEqual(harness.published[(runtime.OUTPUT_ROOT, "runtime-result.json")], canonical(result))
        self.assertEqual(harness.signal_calls[-2:], [(signal.SIGTERM, signal.SIG_DFL), (signal.SIGINT, signal.SIG_DFL)])

    def test_actual_recorder_synthetic_methods_feed_actual_lifecycle_consumer(self):
        suite = SUITES[0]
        name = suite.test_ids[0].split(".")[0]
        methods = {identity.split(".")[1]: lambda case: None for identity in suite.test_ids}
        synthetic = type(name, (unittest.TestCase,), {"__module__": __name__, **methods})
        recording = NativePostgresRunner(expected_test_ids=suite.test_ids, module_name=__name__, stream=io.StringIO())
        observed = recording.run(unittest.TestSuite(synthetic(method) for method in sorted(methods)))
        with LifecycleHarness() as harness:
            harness.reports[0] = canonical(observed.document(script=suite.script, source_sha256=SOURCE[0]))
            self.assertEqual(harness.run()["runtimeStatus"], "COMPLETE")

    def test_exit_report_mismatch_aborts_later_suites_without_restart(self):
        with LifecycleHarness(exit_codes={0: 1}) as harness:
            result = harness.run()
        self.assertEqual(harness.phases(), ["init", "server", 0])
        self.assertEqual(result["runtimeStatus"], "INCOMPLETE")
        self.assertEqual(result["tests"]["fixtures"][0]["tests_status"], "INCOMPLETE")
        self.assertEqual(result["fixtureProcesses"][0]["exitCode"], 1)
        self.assertTrue(all(item["termination"] == "not-started" for item in result["fixtureProcesses"][1:]))

    def test_timeout_keeps_actual_timeout_and_stops_fixture_before_postmaster(self):
        with LifecycleHarness(termination={0: "timeout"}) as harness:
            result = harness.run()
        self.assertEqual(harness.phases(), ["init", "server", 0])
        self.assertEqual(result["fixtureProcesses"][0]["termination"], "timeout")
        self.assertIsNone(result["fixtureProcesses"][0]["exitCode"])
        self.assertEqual([event[1] for event in harness.events if event[0] == "stop"], [0, "server"])
        self.assertFalse(next(item for item in result["processLogs"] if item["path"] == "logs/00.log")["complete"])
        self.assertEqual(result["runtimeStatus"], "INCOMPLETE")

    def test_failed_init_or_startup_cleans_retained_children_without_any_fixture(self):
        for options in ({"exit_codes": {"init": 1}}, {"ready_failure": True}, {"start_failure": "init"}):
            with self.subTest(options=options), LifecycleHarness(**options) as harness:
                result = harness.run()
                self.assertFalse(any(type(phase) is int for phase in harness.phases()))
                self.assertEqual(result["runtimeStatus"], "INCOMPLETE")
                self.assertTrue(result["directChildrenReaped"])
                self.assertTrue(all(item["termination"] == "not-started" for item in result["fixtureProcesses"]))
                self.assertTrue(all(directory.closed for directory in harness.directories))

    def test_spawn_attempt_log_failure_and_report_failure_never_relabel_as_not_started(self):
        for options, report_error, termination in (
                ({"start_failure": 0}, None, "lost"),
                ({"publish_failure": "00.log"}, None, "exited"),
                ({}, runtime.NativePostgresRuntimeError("synthetic report ownership error"), "exited")):
            with self.subTest(options=options, report_error=report_error), LifecycleHarness(**options) as harness:
                if report_error is not None:
                    harness.reports[0] = report_error
                result = harness.run()
                self.assertEqual(result["fixtureProcesses"][0]["termination"], termination)
                self.assertTrue(all(item["termination"] == "not-started" for item in result["fixtureProcesses"][1:]))
                self.assertEqual(result["runtimeStatus"], "INCOMPLETE")
                self.assertEqual(harness.phases(), ["init", "server", 0])

    def test_unexpected_postmaster_exit_zero_before_shutdown_is_not_clean_shutdown(self):
        with LifecycleHarness(server_dies_after_last_probe=True) as harness:
            result = harness.run()
        self.assertEqual(result["tests"]["tests_status"], "PASS")
        self.assertEqual(result["runtimeStatus"], "INCOMPLETE")
        self.assertFalse(result["postmasterCleanStopObserved"])
        self.assertIn("postgres-clean-stop-not-observed", result["errors"])

    def test_forced_kill_retained_socket_or_failed_reap_cannot_complete_passing_tests(self):
        for options in ({"forced_server": True}, {"retained_socket": True},
                        {"unreaped_server": True}, {"close_failure": True}):
            with self.subTest(options=options), LifecycleHarness(**options) as harness:
                result = harness.run()
                self.assertEqual(result["tests"]["tests_status"], "PASS")
                self.assertEqual(result["runtimeStatus"], "INCOMPLETE")
                self.assertTrue(result["errors"])
                if options.get("unreaped_server") or options.get("close_failure"):
                    self.assertFalse(result["directChildrenReaped"])
                    self.assertIn("direct-children-not-reaped", result["errors"])
                else:
                    self.assertFalse(result["postmasterCleanStopObserved"])

    def test_post_source_drift_preserves_process_observations_but_denies_completion(self):
        with LifecycleHarness(post_source_drift=True) as harness:
            result = harness.run()
        self.assertEqual(harness.phases(), ["init", "server", *range(14)])
        self.assertEqual(result["runtimeStatus"], "INCOMPLETE")
        self.assertFalse(result["sourceUnchanged"])
        self.assertIsNone(result["tests"])
        self.assertTrue(all(item["termination"] == "exited" for item in result["fixtureProcesses"]))

    def test_cancellation_and_changed_cluster_abort_without_resuming_or_restarting(self):
        for options in ({"cancel_at": 0}, {"changed_cluster": True}):
            with self.subTest(options=options), LifecycleHarness(**options) as harness:
                result = harness.run()
                self.assertEqual(harness.phases(), ["init", "server", 0])
                self.assertEqual(result["runtimeStatus"], "INCOMPLETE")
                if options.get("cancel_at") == 0:
                    self.assertIn("cancelled", result["errors"])

    def test_insufficient_remaining_budget_never_shortens_suite_or_starts_it(self):
        with LifecycleHarness(exhaust_budget=True) as harness:
            result = harness.run()
        self.assertEqual(harness.phases(), ["init", "server"])
        self.assertTrue(all(item["termination"] == "not-started" for item in result["fixtureProcesses"]))
        self.assertIn("execution:native fixture has no full remaining time budget", result["errors"])

    def test_malformed_or_missing_report_stays_incomplete_without_report_repair(self):
        for value in (None, b"{}", b"not-json", canonical(report(0)) + b"\n"):
            with self.subTest(value=value), LifecycleHarness() as harness:
                harness.reports[0] = value
                result = harness.run()
                self.assertEqual(result["runtimeStatus"], "INCOMPLETE")
                self.assertEqual(result["fixtureProcesses"][0]["termination"], "exited")
                self.assertEqual(harness.phases(), ["init", "server", 0])


class NativePostgresPreparedInputTests(unittest.TestCase):
    def test_exact_prepared_manifest_reads_only_fixed_artifact_and_retains_order(self):
        with mock.patch.object(runtime, "_prepared_file", return_value=canonical(prepared_manifest())) as read:
            self.assertEqual(runtime.load_prepared_sources(), SOURCE)
        read.assert_called_once_with("/opt/serverware/artifacts/native-postgres-sources-v1.json", 16384)

    def test_manifest_wrong_schema_shape_order_digest_and_representation_are_not_repaired(self):
        values = []
        for change in ("schema", "extra", "order", "missing", "row-extra", "digest", "duplicate"):
            value = prepared_manifest()
            if change == "schema":
                value["schema"] = "serverware.nativePostgresPreparedSources/v0"
            elif change == "extra":
                value["approval"] = True
            elif change == "order":
                value["scripts"] = value["scripts"][::-1]
            elif change == "missing":
                value["scripts"].pop()
            elif change == "row-extra":
                value["scripts"][0]["skip"] = False
            elif change == "digest":
                value["scripts"][0]["sha256"] = "sha256:" + "A" * 64
            elif change == "duplicate":
                value["scripts"][1] = value["scripts"][0]
            values.append(canonical(value))
        good = canonical(prepared_manifest())
        values.extend((good + b"\n", json.dumps(prepared_manifest(), indent=2).encode(),
                       b'{"schema":"ignored",' + good[1:]))
        for raw in values:
            with self.subTest(raw=raw), mock.patch.object(runtime, "_prepared_file", return_value=raw):
                with self.assertRaises(runtime.NativePostgresRuntimeError):
                    runtime.load_prepared_sources()

    def test_source_tuple_types_and_each_actual_source_hash_are_checked_before_work(self):
        for value in (list(SOURCE), SOURCE[:-1], (True, *SOURCE[1:]), ("0" * 64, *SOURCE[1:])):
            with self.subTest(value=value), mock.patch.object(runtime, "_runtime_preflight") as preflight:
                with self.assertRaises(runtime.NativePostgresRuntimeError):
                    runtime.execute_native_postgres(source_sha256=value)
                preflight.assert_not_called()
        content = tuple(("source:" + str(index)).encode() for index in range(14))
        expected = tuple(digest(raw) for raw in content)
        with mock.patch.object(runtime, "_prepared_file", side_effect=content) as read:
            self.assertIsNone(runtime._verify_sources(expected))
        self.assertEqual(read.call_args_list, [mock.call(runtime.SOURCE_ROOT + "/" + suite.script,
                                                       2 * 1024 * 1024) for suite in SUITES])
        with mock.patch.object(runtime, "_prepared_file", return_value=b"drift"):
            with self.assertRaisesRegex(runtime.NativePostgresRuntimeError, "differs from prepared"):
                runtime._verify_sources(expected)

    def test_prepared_file_requires_readonly_canonical_parent_before_open(self):
        with mock.patch.object(Path, "resolve", lambda path, strict=False: path), \
                mock.patch.object(runtime.os, "statvfs", return_value=SimpleNamespace(f_flag=os.ST_RDONLY)), \
                mock.patch.object(runtime.os, "open", return_value=99) as opened, \
                mock.patch.object(runtime.os, "close") as closed, \
                mock.patch.object(runtime, "_read_file", return_value=b"prepared") as read:
            self.assertEqual(runtime._prepared_file(runtime.PREPARED_SOURCES, 16384), b"prepared")
            read.assert_called_once_with(99, "native-postgres-sources-v1.json", 16384, private=False)
            closed.assert_called_once_with(99)
            self.assertEqual(opened.call_args.args[0], Path("/opt/serverware/artifacts"))
            self.assertTrue(opened.call_args.args[1] & os.O_NOFOLLOW)
        with mock.patch.object(Path, "resolve", lambda path, strict=False: path), \
                mock.patch.object(runtime.os, "statvfs", return_value=SimpleNamespace(f_flag=0)), \
                mock.patch.object(runtime.os, "open") as opened:
            with self.assertRaisesRegex(runtime.NativePostgresRuntimeError, "read-only storage"):
                runtime._prepared_file(runtime.PREPARED_SOURCES, 16384)
            opened.assert_not_called()

    def test_prepared_leaf_requires_root_ownership_and_exact_file_read_identity(self):
        def info(**changes):
            fields = dict(st_dev=1, st_ino=2, st_mode=stat.S_IFREG | 0o444, st_uid=0, st_gid=0,
                          st_nlink=1, st_size=6, st_mtime_ns=3, st_ctime_ns=4)
            fields.update(changes)
            return SimpleNamespace(**fields)
        for changes in ({}, {"st_uid": 10001}, {"st_mode": stat.S_IFREG | 0o666}, {"st_nlink": 2},
                        {"st_mode": stat.S_IFIFO | 0o444}, {"st_size": 16385}):
            observed = info(**changes)
            with self.subTest(changes=changes), mock.patch.object(runtime.os, "open", return_value=99), \
                    mock.patch.object(runtime.os, "fstat", return_value=observed), \
                    mock.patch.object(runtime.os, "stat", return_value=observed), \
                    mock.patch.object(runtime.os, "read", side_effect=[b"source", b""]), \
                    mock.patch.object(runtime.os, "close") as closed:
                if changes:
                    with self.assertRaises(runtime.NativePostgresRuntimeError):
                        runtime._read_file(90, "input.json", 16384, private=False)
                else:
                    self.assertEqual(runtime._read_file(90, "input.json", 16384, private=False), b"source")
                closed.assert_called_once_with(99)
        with mock.patch.object(runtime.os, "open", return_value=99), \
                mock.patch.object(runtime.os, "fstat", side_effect=[info(), info(st_ino=7)]), \
                mock.patch.object(runtime.os, "read", side_effect=[b"source", b""]), \
                mock.patch.object(runtime.os, "close"):
            with self.assertRaisesRegex(runtime.NativePostgresRuntimeError, "changed during"):
                runtime._read_file(90, "input.json", 16384, private=False)

    def test_runtime_preflight_fixed_identity_ambient_pg_and_readonly_executables(self):
        with ExitStack() as stack:
            for target, value in (
                    ("sys.platform", "linux"), ("sys.version_info", (3, 11, 0)),
                    ("sys.executable", "/usr/local/bin/python3.11"),
                    ("__file__", "/opt/serverware/src/serverware/native_postgres_runner.py"),
                    ("os.uname", lambda: SimpleNamespace(machine="x86_64")),
                    ("os.getuid", lambda: 10001), ("os.geteuid", lambda: 10001),
                    ("os.getgid", lambda: 10001), ("os.getegid", lambda: 10001),
                    ("os.getgroups", lambda: [10001]),
                    ("os.statvfs", lambda path: SimpleNamespace(f_flag=os.ST_RDONLY))):
                stack.enter_context(mock.patch("serverware.native_postgres_runner." + target, value))
            stack.enter_context(mock.patch.dict(os.environ, {}, clear=True))
            stack.enter_context(mock.patch.object(Path, "resolve", lambda path, strict=False: path))
            stack.enter_context(mock.patch.object(Path, "stat", return_value=SimpleNamespace(
                st_mode=stat.S_IFREG | 0o755, st_uid=0)))
            self.assertIsNone(runtime._runtime_preflight())
            with mock.patch.object(runtime.os, "geteuid", return_value=0):
                with self.assertRaisesRegex(runtime.NativePostgresRuntimeError, "nonroot identity"):
                    runtime._runtime_preflight()
            with mock.patch.object(runtime.os, "getgroups", return_value=[10001, 0]):
                with self.assertRaisesRegex(runtime.NativePostgresRuntimeError, "nonroot identity"):
                    runtime._runtime_preflight()
            with mock.patch.dict(os.environ, {"PGHOST": "/caller"}):
                with self.assertRaisesRegex(runtime.NativePostgresRuntimeError, "ambient PostgreSQL"):
                    runtime._runtime_preflight()
            with mock.patch.object(runtime.os, "statvfs", return_value=SimpleNamespace(f_flag=0)):
                with self.assertRaisesRegex(runtime.NativePostgresRuntimeError, "read-only prepared file"):
                    runtime._runtime_preflight()

    def test_cli_has_no_argument_path_and_never_loads_or_runs_on_extra_arguments(self):
        with mock.patch.object(sys, "argv", ["run-native", "--postgres-dsn=caller"]), \
                mock.patch.object(runtime, "load_prepared_sources") as load, \
                mock.patch.object(runtime, "execute_native_postgres") as execute, \
                mock.patch.object(sys, "stderr", io.StringIO()):
            self.assertEqual(runtime.main(), 2)
            load.assert_not_called()
            execute.assert_not_called()
        for status, code in (("COMPLETE", 0), ("INCOMPLETE", 2)):
            with self.subTest(status=status), mock.patch.object(sys, "argv", ["run-native"]), \
                    mock.patch.object(runtime, "load_prepared_sources", return_value=SOURCE), \
                    mock.patch.object(runtime, "execute_native_postgres", return_value={"runtimeStatus": status}) as execute:
                self.assertEqual(runtime.main(), code)
                execute.assert_called_once_with(source_sha256=SOURCE)


if __name__ == "__main__":
    unittest.main()
