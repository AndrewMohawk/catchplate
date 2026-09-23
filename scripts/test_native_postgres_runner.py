#!/usr/bin/env python3
"""Synthetic contracts for the fixed native PostgreSQL profile/supervisor.

These tests never spawn a process, open PostgreSQL, run SQL or use a container.
Scripted process/descriptor/clock doubles exercise the production supervisor;
they do not establish Linux pidfd behavior, engine readiness, bounded storage,
real teardown, prepared-lane coverage or independent controller authority.
"""
from __future__ import annotations

import os
import signal
import sys
import unittest
from contextlib import ExitStack
from dataclasses import FrozenInstanceError
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from serverware import native_postgres_inventory as inventory
from serverware import native_postgres_profile as profile
from serverware import native_postgres_process as processes


# Independent source-contract oracles, not copies returned by the producer.
EXPECTED_SETTINGS = {
    "listen_addresses": "", "unix_socket_directories": "/run/serverware-native-postgres",
    "unix_socket_permissions": "0700", "port": "5432", "ssl": "off",
    "fsync": "on", "full_page_writes": "on", "synchronous_commit": "on",
    "log_destination": "stderr", "logging_collector": "off", "max_connections": "32",
    "shared_buffers": "8192", "work_mem": "4096", "maintenance_work_mem": "32768",
    "max_wal_size": "256", "min_wal_size": "80", "temp_file_limit": "131072",
    "jit": "off", "restart_after_crash": "off",
    "data_directory": "/var/lib/serverware-runner/native-postgres/pgdata",
    "data_checksums": "on", "block_size": "8192",
}
EXPECTED_POSTGRES_SETTINGS = (
    "listen_addresses=", "unix_socket_directories=/run/serverware-native-postgres",
    "unix_socket_permissions=0700", "port=5432", "ssl=off", "fsync=on",
    "full_page_writes=on", "synchronous_commit=on", "log_destination=stderr",
    "logging_collector=off", "max_connections=32", "shared_buffers=64MB",
    "work_mem=4MB", "maintenance_work_mem=32MB", "max_wal_size=256MB",
    "min_wal_size=80MB", "temp_file_limit=128MB", "jit=off", "restart_after_crash=off",
)


def readiness_row():
    return (160004, "UTF8", "UTF8", "postgres", "serverware_fixture_admin",
            "serverware_fixture_admin", True, None, False, "987654321", dict(EXPECTED_SETTINGS))


class NativePostgresProfileTests(unittest.TestCase):
    def test_fixed_paths_identity_and_deadline_budget_preserve_all_ten_suite_limits(self):
        self.assertEqual((profile.PG_BINDIR, profile.PRIVATE_ROOT, profile.NATIVE_ROOT,
                          profile.PGDATA, profile.SOCKET_ROOT, profile.OUTPUT_ROOT), (
            "/opt/serverware/postgresql-16/bin", "/var/lib/serverware-runner",
            "/var/lib/serverware-runner/native-postgres",
            "/var/lib/serverware-runner/native-postgres/pgdata",
            "/run/serverware-native-postgres", "/opt/serverware/output/native-postgres"))
        self.assertEqual((profile.USER, profile.UID, profile.GID), ("serverware_fixture_admin", 10001, 10001))
        self.assertEqual((profile.TOTAL_SECONDS, profile.INIT_SECONDS, profile.STARTUP_SECONDS,
                          profile.SHUTDOWN_SECONDS), (4800, 120, 60, 60))
        self.assertEqual(tuple(suite.timeout_seconds for suite in inventory.SUITES),
                         (300, 300, 300, 300, 300, 300, 900, 300, 300, 300, 300, 300))
        self.assertEqual(sum(suite.timeout_seconds for suite in inventory.SUITES), 4200)
        self.assertEqual(profile.TOTAL_SECONDS - profile.INIT_SECONDS - profile.STARTUP_SECONDS
                         - profile.SHUTDOWN_SECONDS - 4200, 360)

    def test_exact_initdb_vector_has_no_shell_no_sync_or_external_wal_override(self):
        self.assertEqual(profile.initdb_argv(), (
            "/opt/serverware/postgresql-16/bin/initdb",
            "--pgdata=/var/lib/serverware-runner/native-postgres/pgdata",
            "--username=serverware_fixture_admin", "--encoding=UTF8", "--locale=C",
            "--locale-provider=libc", "--auth-local=trust", "--auth-host=reject",
            "--data-checksums", "--no-instructions", "--no-clean"))
        self.assertIs(type(profile.initdb_argv()), tuple)

    def test_exact_foreground_postmaster_vector_and_explicit_resource_settings(self):
        expected = (
            "/opt/serverware/postgresql-16/bin/postgres", "-D",
            "/var/lib/serverware-runner/native-postgres/pgdata",
        ) + tuple(part for setting in EXPECTED_POSTGRES_SETTINGS for part in ("-c", setting))
        self.assertEqual(profile.postgres_argv(), expected)
        self.assertIs(type(profile.postgres_argv()), tuple)

    def test_environment_is_fresh_closed_and_ignores_host_pg_python_and_loader_overrides(self):
        expected = {
            "PATH": "/opt/serverware/postgresql-16/bin:/usr/local/bin:/usr/bin:/bin",
            "HOME": "/var/lib/serverware-runner/native-postgres", "LANG": "C",
            "LC_ALL": "C", "TZ": "UTC", "PYTHONPATH": "/opt/serverware/src",
            "PYTHONDONTWRITEBYTECODE": "1", "PYTHONNOUSERSITE": "1", "PYTHONUNBUFFERED": "1",
        }
        with mock.patch.dict(os.environ, {"PGHOST": "remote.invalid", "PGDATA": "/caller",
                                         "LD_PRELOAD": "/caller.so", "PYTHONPATH": "/caller"}, clear=True):
            first, second = profile.environment(), profile.environment()
        self.assertEqual(first, expected)
        self.assertEqual(second, expected)
        self.assertIsNot(first, second)
        first["PGHOST"] = "changed"
        self.assertEqual(profile.environment(), expected)

    def test_readiness_accepts_only_actual_tuple_and_retains_immutable_scalar_observation(self):
        row = readiness_row()
        result = profile.validate_probe_row(row)
        self.assertEqual((result.server_version_num, result.system_identifier), (160004, "987654321"))
        row[10]["fsync"] = "off"
        self.assertEqual(result.system_identifier, "987654321")
        with self.assertRaises(FrozenInstanceError):
            result.system_identifier = "1"
        self.assertFalse(hasattr(result, "__dict__"))
        for malformed in (None, list(readiness_row()), readiness_row()[:-1], (*readiness_row(), None)):
            with self.subTest(value=malformed), self.assertRaisesRegex(
                    profile.NativePostgresProfileError, "row is not exact"):
                profile.validate_probe_row(malformed)

    def test_readiness_version_and_system_identifier_exact_type_range_and_canonical_decimal(self):
        for version in (160000, 169999):
            for identifier in ("1", "18446744073709551615"):
                row = list(readiness_row())
                row[0], row[9] = version, identifier
                self.assertEqual(profile.validate_probe_row(tuple(row)),
                                 profile.NativePostgresProbe(version, identifier))
        for version in (True, 160000.0, "160000", 159999, 170000, None):
            row = list(readiness_row())
            row[0] = version
            with self.subTest(version=version), self.assertRaisesRegex(
                    profile.NativePostgresProfileError, "requires PG16"):
                profile.validate_probe_row(tuple(row))
        for identifier in (None, 1, True, "", "0", "01", "+1", "-1", " 1", "1 ",
                           "1\x00", "\N{ARABIC-INDIC DIGIT ONE}", "18446744073709551616", "1" * 21):
            row = list(readiness_row())
            row[9] = identifier
            with self.subTest(identifier=identifier), self.assertRaisesRegex(
                    profile.NativePostgresProfileError, "system identifier is invalid"):
                profile.validate_probe_row(tuple(row))

    def test_readiness_session_fields_reject_coercion_tcp_replica_or_wrong_principal(self):
        changes = ((1, "SQL_ASCII"), (2, "LATIN1"), (3, "other"), (4, "other"), (5, "other"),
                   (6, False), (6, 1), (7, "127.0.0.1"), (7, False), (8, True), (8, 0))
        for index, value in changes:
            row = list(readiness_row())
            row[index] = value
            with self.subTest(index=index, value=value), self.assertRaisesRegex(
                    profile.NativePostgresProfileError, "session differs"):
                profile.validate_probe_row(tuple(row))

    def test_readiness_settings_exact_complete_and_string_typed(self):
        variants = [None, list(EXPECTED_SETTINGS.items()), {}, {**EXPECTED_SETTINGS, "extra": "on"}]
        for key in EXPECTED_SETTINGS:
            missing = dict(EXPECTED_SETTINGS)
            del missing[key]
            variants.append(missing)
            variants.append({**EXPECTED_SETTINGS, key: "different"})
        variants.extend(({**EXPECTED_SETTINGS, "port": 5432}, {**EXPECTED_SETTINGS, "fsync": True},
                         {**EXPECTED_SETTINGS, "data_directory": "/caller"}))
        for settings in variants:
            row = (*readiness_row()[:10], settings)
            with self.subTest(settings=settings), self.assertRaisesRegex(
                    profile.NativePostgresProfileError, "settings differ"):
                profile.validate_probe_row(row)
        self.assertEqual(profile.validate_probe_row(readiness_row()).server_version_num, 160004)

    def test_probe_constructor_checks_data_but_never_claims_process_or_hba_authority(self):
        self.assertEqual(profile.NativePostgresProbe(160000, "1").system_identifier, "1")
        for version, identifier in ((True, "1"), (170000, "1"), (160000, "0")):
            with self.subTest(version=version, identifier=identifier), self.assertRaises(
                    profile.NativePostgresProfileError):
                profile.NativePostgresProbe(version, identifier)

    def test_readiness_query_reads_fixed_identity_and_complete_guc_inventory(self):
        # Text/source closure only: no SQL parser or database is invoked.
        query = profile.READINESS_SQL
        self.assertTrue(query.startswith("SELECT "))
        for fragment in ("pg_catalog.pg_control_system()", "current_user::pg_catalog.text",
                         "session_user::pg_catalog.text", "role_record.rolsuper",
                         "pg_catalog.inet_server_addr()", "pg_catalog.pg_is_in_recovery()",
                         "pg_catalog.pg_settings", "WHERE role_record.rolname = current_user"):
            self.assertIn(fragment, query)
        for setting in EXPECTED_SETTINGS:
            self.assertEqual(query.count("'" + setting + "'"), 1)
        self.assertNotIn("%s", query)
        self.assertNotIn(";", query)


class FakePipe:
    def __init__(self, descriptor):
        self.descriptor = descriptor
        self.closed = False

    def fileno(self):
        return self.descriptor

    def close(self):
        self.closed = True


class FakeProcess:
    def __init__(self, harness, plan):
        self.harness = harness
        self.pid = 1000 + len(harness.spawned)
        self.stdout = FakePipe(2000 + len(harness.spawned))
        self.returncode = None
        self.chunks = list(plan.get("chunks", (b"output\n", b"")))
        delay = plan.get("exit_after", 0.0)
        self.exit_at = None if delay is None else harness.now + delay
        self.exit_code = plan.get("exit_code", 0)
        self.signal_exits = plan.get("signal_exits", True)
        self.ignore_kill = plan.get("ignore_kill", False)
        self.poll_error = plan.get("poll_error")

    def poll(self):
        self.harness.events.append(("poll", self.pid))
        if self.poll_error is not None:
            raise self.poll_error
        if self.returncode is None and self.exit_at is not None and self.harness.now >= self.exit_at:
            self.returncode = self.exit_code
        return self.returncode

    def kill(self):
        # This double represents the setup-only fallback before supervisor
        # polling; it does not model Popen.kill's internal waitpid safeguards.
        self.harness.events.append(("setup-kill", self.pid))
        self.receive(signal.SIGKILL)

    def receive(self, number):
        if ((number == signal.SIGKILL and not self.ignore_kill)
                or (number != signal.SIGKILL and self.signal_exits)):
            self.exit_at = self.harness.now
            self.exit_code = -int(number)
            if not self.chunks:
                self.chunks.append(b"")


class FakeSelector:
    def __init__(self, harness):
        self.harness = harness
        self.registered = {}
        self.closed = False
        self.fail_select = False
        self.fail_register = False

    def register(self, descriptor, events, data):
        if self.fail_register:
            raise OSError("synthetic selector registration failure")
        self.registered[descriptor] = SimpleNamespace(data=data)

    def unregister(self, descriptor):
        del self.registered[descriptor]

    def select(self, timeout):
        self.harness.select_timeouts.append(timeout)
        self.harness.now += max(timeout, 0.01)
        if self.fail_select:
            raise OSError("synthetic selector failure")
        return [(key, 1) for key in tuple(self.registered.values())
                if key.data.process.chunks and not key.data.process.stdout.closed]

    def close(self):
        self.closed = True


class ProcessHarness:
    """Scripted kernel boundary: every FD, clock tick and Popen is synthetic."""

    def __init__(self, *plans):
        self.plans = list(plans)
        self.spawned = []
        self.spawn_calls = []
        self.events = []
        self.closed_descriptors = []
        self.read_sizes = []
        self.select_timeouts = []
        self.now = 100.0
        self.fail_child_pidfd = False
        self.fail_nonblocking = False
        self.selector = FakeSelector(self)
        self.stack = ExitStack()

    def __enter__(self):
        for target, value in (
                ("sys.platform", "linux"), ("signal.getsignal", lambda _: signal.SIG_DFL),
                ("os.getpid", lambda: 700), ("os.pidfd_open", self.pidfd_open),
                ("os.close", self.closed_descriptors.append), ("os.read", self.read),
                ("os.set_blocking", self.set_blocking), ("subprocess.Popen", self.spawn),
                ("selectors.DefaultSelector", lambda: self.selector),
                ("time.monotonic", lambda: self.now),
                ("time.sleep", self.sleep),
                ("signal.pidfd_send_signal", self.send_signal)):
            self.stack.enter_context(mock.patch("serverware.native_postgres_process." + target, value))
        self.stack.enter_context(mock.patch("serverware.native_postgres_process.os.kill",
                                           side_effect=AssertionError("numeric PID signaling is forbidden")))
        self.supervisor = processes.ProcessSet()
        return self

    def __exit__(self, *exception):
        # There are no real processes/FDs to clean up; explicit tests below
        # exercise production close rather than substituting a fake close.
        return self.stack.__exit__(*exception)

    def spawn(self, argv, **kwargs):
        if not self.plans:
            raise AssertionError("unexpected synthetic spawn")
        self.spawn_calls.append((argv, kwargs))
        plan = self.plans.pop(0)
        if "spawn_error" in plan:
            raise plan["spawn_error"]
        process = FakeProcess(self, plan)
        self.spawned.append(process)
        self.events.append(("spawn", process.pid))
        return process

    def pidfd_open(self, pid, flags):
        self.events.append(("pidfd", pid, flags))
        if pid != 700 and self.fail_child_pidfd:
            raise OSError("synthetic pidfd acquisition failure")
        return 10000 + pid

    def set_blocking(self, descriptor, blocking):
        self.events.append(("set-blocking", descriptor, blocking))
        if self.fail_nonblocking:
            raise OSError("synthetic nonblocking setup failure")

    def read(self, descriptor, size):
        self.read_sizes.append(size)
        process = next(item for item in self.spawned if item.stdout.descriptor == descriptor)
        if not process.chunks:
            raise BlockingIOError()
        chunk = process.chunks.pop(0)
        if isinstance(chunk, BaseException):
            raise chunk
        if len(chunk) > size:
            process.chunks.insert(0, chunk[size:])
        return chunk[:size]

    def send_signal(self, descriptor, number, info, flags):
        self.events.append(("signal", descriptor, number, info, flags))
        process = next(item for item in self.spawned if 10000 + item.pid == descriptor)
        process.receive(number)

    def sleep(self, seconds):
        self.now += max(seconds, 0.01)

    def start(self, **kwargs):
        return self.supervisor.start(("/fixed/executable", "argument"),
                                     env=kwargs.get("env", {"LANG": "C"}), cwd="/fixed/cwd")


class NativePostgresProcessTests(unittest.TestCase):
    def test_start_owns_environment_fixed_popen_flags_and_child_pidfd_before_poll(self):
        with ProcessHarness({}) as harness:
            environment = {"LANG": "C"}
            child = harness.start(env=environment)
            environment["LANG"] = "mutated"
            argv, options = harness.spawn_calls[0]
            self.assertEqual(argv, ("/fixed/executable", "argument"))
            self.assertEqual(options, {
                "stdin": processes.subprocess.DEVNULL, "stdout": processes.subprocess.PIPE,
                "stderr": processes.subprocess.STDOUT, "env": {"LANG": "C"}, "cwd": "/fixed/cwd",
                "start_new_session": True, "close_fds": True, "shell": False, "bufsize": 0})
            self.assertEqual(child.pidfd, 11000)
            self.assertEqual(harness.supervisor.children, (child,))
            self.assertFalse(any(event[0] == "poll" for event in harness.events))
            self.assertEqual(harness.closed_descriptors, [10700])

    def test_complete_exit_requires_bounded_full_log_eof_and_retained_real_returncode(self):
        with ProcessHarness({"chunks": [b"one", b"two", b""], "exit_code": 1}) as harness:
            child = harness.start()
            self.assertEqual(harness.supervisor.wait(child, harness.now + 5), "exited")
            self.assertEqual(child.returncode, 1)
            self.assertEqual(bytes(child.log), b"onetwo")
            self.assertTrue(child.complete_log)
            self.assertTrue(child.eof)
            self.assertTrue(all(size == 65536 for size in harness.read_sizes))
            harness.supervisor.close()
            self.assertIn(11000, harness.closed_descriptors)
            self.assertTrue(harness.selector.closed)

    def test_exact_log_limit_completes_but_one_extra_byte_is_lost_and_never_complete(self):
        self.assertEqual(processes.MAX_LOG_BYTES, 8 * 1024 * 1024)
        # Small injected cap exercises the actual read/append boundary without
        # manufacturing a huge allocation. The production constant is pinned above.
        with mock.patch.object(processes, "MAX_LOG_BYTES", 8):
            for content, expected in ((b"12345678", "exited"), (b"123456789", "lost")):
                with self.subTest(content=content), ProcessHarness({"chunks": [content, b""]}) as harness:
                    child = harness.start()
                    self.assertEqual(harness.supervisor.wait(child, harness.now + 5), expected)
                    self.assertEqual(bytes(child.log), b"12345678")
                    self.assertEqual(child.overflow, expected == "lost")
                    harness.supervisor.pump(0)
                    self.assertEqual(child.complete_log, expected == "exited")

    def test_background_postmaster_death_defeats_fixture_exit_zero_and_good_eof(self):
        for server_exit in (0.0, None):
            with self.subTest(server_exit=server_exit), ProcessHarness(
                    {"chunks": [b""], "exit_after": server_exit}, {"chunks": [b""]}) as harness:
                postmaster, fixture = harness.start(), harness.start()
                self.assertEqual(harness.supervisor.wait(fixture, harness.now + 5,
                                                       must_remain_alive=postmaster), "lost")
                self.assertEqual(fixture.returncode, 0)
                self.assertTrue(fixture.eof)
                self.assertFalse(fixture.complete_log)
                if server_exit is None:
                    self.assertIsNone(postmaster.returncode)
                    self.assertTrue(postmaster.eof)

    def test_background_log_overflow_also_defeats_otherwise_completed_fixture(self):
        with mock.patch.object(processes, "MAX_LOG_BYTES", 8), ProcessHarness(
                {"chunks": [b"123456789"], "exit_after": None}, {"chunks": [b""]}) as harness:
            postmaster, fixture = harness.start(), harness.start()
            self.assertEqual(harness.supervisor.wait(fixture, harness.now + 5,
                                                   must_remain_alive=postmaster), "lost")
            self.assertTrue(postmaster.overflow)
            self.assertFalse(fixture.complete_log)

    def test_timeout_is_sticky_even_after_later_exit_and_eof(self):
        with ProcessHarness({"chunks": [], "exit_after": None}) as harness:
            child = harness.start()
            self.assertEqual(harness.supervisor.wait(child, harness.now + 0.2), "timeout")
            child.process.exit_at = harness.now
            child.process.chunks.append(b"")
            self.assertEqual(harness.supervisor.wait(child, harness.now + 5), "timeout")
            self.assertEqual(child.returncode, 0)
            self.assertTrue(child.eof)
            self.assertFalse(child.complete_log)

    def test_exited_child_with_inherited_pipe_never_eof_has_bounded_drain_then_loss(self):
        with ProcessHarness({"chunks": [b"prefix"], "exit_after": 0}) as harness:
            child = harness.start()
            start = harness.now
            self.assertEqual(harness.supervisor.wait(child, start + 10), "lost")
            self.assertLess(harness.now - start, 2)
            self.assertEqual(bytes(child.log), b"prefix")
            self.assertFalse(child.eof)
            self.assertTrue(child.process.stdout.closed)
            self.assertFalse(child.complete_log)

    def test_nonblocking_retry_is_not_loss_but_read_error_never_becomes_complete(self):
        for error, expected in ((BlockingIOError(), "exited"), (OSError("read failure"), "lost")):
            with self.subTest(error=type(error)), ProcessHarness({"chunks": [error, b"ok", b""]}) as harness:
                child = harness.start()
                self.assertEqual(harness.supervisor.wait(child, harness.now + 5), expected)
                self.assertEqual(child.complete_log, expected == "exited")

    def test_selector_failure_latches_loss_and_preserves_finite_cleanup(self):
        with ProcessHarness({"chunks": [], "exit_after": None}) as harness:
            child = harness.start()
            harness.selector.fail_select = True
            self.assertEqual(harness.supervisor.wait(child, harness.now + 5), "lost")
            with self.assertRaisesRegex(processes.NativePostgresProcessError, "cannot start"):
                harness.start()
            start = harness.now
            harness.supervisor.close()
            self.assertLessEqual(harness.now - start, 5.1)
            self.assertIsNotNone(child.returncode)
            self.assertFalse(child.complete_log)

    def test_stop_uses_only_retained_pidfd_and_forced_kill_is_not_clean_completion(self):
        with ProcessHarness({"chunks": [], "exit_after": None, "signal_exits": False}) as harness:
            child = harness.start()
            self.assertTrue(harness.supervisor.stop(child, initial_signal=signal.SIGINT,
                                                  deadline=harness.now + 3))
            sent = [event for event in harness.events if event[0] == "signal"]
            self.assertEqual([event[2] for event in sent], [signal.SIGINT, signal.SIGKILL])
            self.assertTrue(all(event[1] == child.pidfd and event[3:] == (None, 0) for event in sent))
            self.assertFalse(any(event[0] == "setup-kill" for event in harness.events))
            self.assertTrue(child.forced_kill)
            self.assertFalse(child.complete_log)
            self.assertEqual(harness.supervisor.wait(child, harness.now + 5), "lost")

    def test_cancelled_wait_is_lost_but_cancellation_does_not_disable_stop(self):
        with ProcessHarness({"chunks": [], "exit_after": None}) as harness:
            child = harness.start()
            harness.supervisor.cancelled = True
            self.assertEqual(harness.supervisor.wait(child, harness.now + 5), "lost")
            self.assertTrue(harness.supervisor.stop(child, initial_signal=signal.SIGTERM,
                                                  deadline=harness.now + 3))
            self.assertFalse(child.complete_log)
            with self.assertRaisesRegex(processes.NativePostgresProcessError, "cannot start"):
                harness.start()

    def test_pidfd_setup_failure_retains_child_and_only_then_uses_unreaped_fallback(self):
        with ProcessHarness({"chunks": [], "exit_after": None}) as harness:
            harness.fail_child_pidfd = True
            with self.assertRaisesRegex(OSError, "pidfd acquisition"):
                harness.start()
            self.assertEqual(len(harness.supervisor.children), 1)
            child = harness.supervisor.children[0]
            self.assertIsNone(child.pidfd)
            self.assertIsNotNone(child.returncode)
            self.assertTrue(child.forced_kill)
            self.assertFalse(child.complete_log)
            kinds = [event[0] for event in harness.events]
            self.assertLess(kinds.index("setup-kill"), kinds.index("poll"))
            with self.assertRaisesRegex(processes.NativePostgresProcessError, "cannot start"):
                harness.start()
            harness.supervisor.close()

    def test_setup_failure_after_pidfd_uses_pidfd_kill_and_retains_cleanup_inventory(self):
        with ProcessHarness({"chunks": [], "exit_after": None}) as harness:
            harness.fail_nonblocking = True
            with self.assertRaisesRegex(OSError, "nonblocking setup"):
                harness.start()
            child, = harness.supervisor.children
            self.assertEqual(child.pidfd, 11000)
            self.assertTrue(child.forced_kill)
            self.assertFalse(child.complete_log)
            self.assertFalse(any(event[0] == "setup-kill" for event in harness.events))
            self.assertIn(("signal", 11000, signal.SIGKILL, None, 0), harness.events)
            harness.supervisor.close()
            self.assertIn(11000, harness.closed_descriptors)

    def test_unreaped_child_cleanup_raises_and_keeps_pidfd_instead_of_false_success(self):
        with ProcessHarness({"chunks": [], "exit_after": None, "signal_exits": False,
                             "ignore_kill": True}) as harness:
            child = harness.start()
            start = harness.now
            with self.assertRaisesRegex(processes.NativePostgresProcessError, "cleanup remains incomplete"):
                harness.supervisor.close()
            self.assertLessEqual(harness.now - start, 5.1)
            self.assertIsNone(child.returncode)
            self.assertEqual(child.pidfd, 11000)
            self.assertNotIn(11000, harness.closed_descriptors)
            self.assertEqual(harness.supervisor.children, (child,))
            self.assertFalse(child.complete_log)

    def test_command_and_deadline_controls_fail_before_any_spawn_or_signal(self):
        with ProcessHarness({}) as harness:
            for argv, env, cwd in (([], {}, "/fixed"), (("relative",), {}, "/fixed"),
                                   (("/fixed", "\x00"), {}, "/fixed"),
                                   (("/fixed",), {"A=B": "x"}, "/fixed"),
                                   (("/fixed",), {"A": "\ud800"}, "/fixed"),
                                   (("/fixed",), {}, "relative")):
                with self.subTest(argv=argv, env=env, cwd=cwd), self.assertRaises(
                        processes.NativePostgresProcessError):
                    harness.supervisor.start(argv, env=env, cwd=cwd)
            self.assertEqual(harness.spawn_calls, [])
            child = harness.start()
            for deadline in (True, "101", -1, float("inf"), float("nan"), harness.now + 7201):
                with self.subTest(deadline=deadline), self.assertRaises(processes.NativePostgresProcessError):
                    harness.supervisor.wait(child, deadline)
            for interval in (True, -1, 0.251, float("nan")):
                with self.subTest(interval=interval), self.assertRaises(processes.NativePostgresProcessError):
                    harness.supervisor.pump(interval)
            with self.assertRaisesRegex(processes.NativePostgresProcessError, "own liveness"):
                harness.supervisor.wait(child, harness.now + 5, must_remain_alive=child)

    def test_lifetime_child_inventory_is_bounded_and_closed_supervisor_cannot_restart(self):
        self.assertEqual(processes.MAX_CHILDREN, 14)
        with ProcessHarness(*({"chunks": [b""]} for _ in range(14))) as harness:
            for _ in range(14):
                child = harness.start()
                self.assertEqual(harness.supervisor.wait(child, harness.now + 5), "exited")
            self.assertEqual(len(harness.supervisor.children), 14)
            with self.assertRaisesRegex(processes.NativePostgresProcessError, "inventory is full"):
                harness.start()
            harness.supervisor.close()
            harness.supervisor.close()
            with self.assertRaisesRegex(processes.NativePostgresProcessError, "cannot start"):
                harness.start()


if __name__ == "__main__":
    unittest.main()
