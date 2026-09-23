"""Cooperative fixed native-PG job inside an independently admitted runner.

This owns a fresh cluster, never a supplied DSN or retained database. It does
not build/install anything or grant controller/release authority. The outer
controller must enforce resource/output/deadline limits and destroy the entire
container/cgroup, including descendants and retained data, even after success.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import signal
import stat
import sys
import time
from contextlib import ExitStack
from dataclasses import asdict, replace
from pathlib import Path

from .native_postgres_batch import (
    MAX_LOG_BYTES, MAX_REPORT_BYTES, PYTHON_EXECUTABLE, REPORT_ROOT, SOURCE_ROOT,
    NativeFixtureObservation, prepared_fixture_argv, reconcile_native_postgres_batch,
)
from .native_postgres_inventory import SUITES, validate_inventory
from .native_postgres_process import Child, ProcessSet
from .native_postgres_probe import NativePostgresProbeUnavailable, probe as query_probe
from .native_postgres_profile import (
    GID, INIT_SECONDS, NATIVE_ROOT, OUTPUT_ROOT, PGDATA, PG_BINDIR, PRIVATE_ROOT,
    SHUTDOWN_SECONDS, SOCKET_ROOT, STARTUP_SECONDS, TOTAL_SECONDS,
    UID, NativePostgresProbe, environment, initdb_argv, postgres_argv,
)


PREPARED_SOURCES = "/opt/serverware/artifacts/native-postgres-sources-v1.json"
PREPARED_SCHEMA = "serverware.nativePostgresPreparedSources/v1"
RESULT_SCHEMA = "serverware.nativePostgresRuntimeResult/v1"
MAX_SOURCE_BYTES = 2 * 1024 * 1024
MAX_MANIFEST_BYTES = 16384
MAX_SUMMARY_BYTES = 65536
_SHA256 = re.compile(r"sha256:[0-9a-f]{64}", re.ASCII)


class NativePostgresRuntimeError(RuntimeError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise NativePostgresRuntimeError(message)


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, allow_nan=False,
                      sort_keys=True, separators=(",", ":")).encode("ascii")


def _identity(info: os.stat_result) -> tuple:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _read_file(directory: int, name: str, maximum: int, *, private: bool) -> bytes:
    """One bounded leaf, through the retained parent, never a symlink/FIFO."""
    _require(name not in ("", ".", "..") and "/" not in name and "\0" not in name,
             "invalid native file leaf")
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                         dir_fd=directory)
    try:
        before = os.fstat(descriptor)
        _require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                 and 0 < before.st_size <= maximum, "invalid bounded native file")
        if private:
            _require(before.st_uid == UID and before.st_gid == GID
                     and stat.S_IMODE(before.st_mode) & 0o077 == 0,
                     "native output is not private and owned")
        else:
            _require(before.st_uid == 0 and before.st_mode & 0o022 == 0,
                     "native prepared input is not root-owned immutable input")
        chunks, total = [], 0
        while total <= maximum:
            chunk = os.read(descriptor, min(65536, maximum + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        _require(total == before.st_size and total <= maximum
                 and _identity(before) == _identity(os.fstat(descriptor))
                 and _identity(before) == _identity(os.stat(name, dir_fd=directory,
                                                          follow_symlinks=False)),
                 "native file changed during bounded read")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


class _Directory:
    """Retained local directory identity; close does not remove any storage."""

    def __init__(self, path: str) -> None:
        self.path = Path(path)
        _require(self.path.is_absolute() and str(self.path) == path
                 and self.path.resolve(strict=True) == self.path,
                 "native directory is not canonical")
        self.fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            info = os.fstat(self.fd)
            self.identity = (info.st_dev, info.st_ino)
            self.check()
        except BaseException:
            os.close(self.fd)
            raise

    def check(self) -> None:
        info = os.fstat(self.fd)
        at_path = self.path.lstat()
        _require(stat.S_ISDIR(info.st_mode) and info.st_uid == UID and info.st_gid == GID
                 and stat.S_IMODE(info.st_mode) == 0o700
                 and (info.st_dev, info.st_ino) == self.identity
                 and (at_path.st_dev, at_path.st_ino) == self.identity
                 and self.path.resolve(strict=True) == self.path,
                 "native directory identity or ownership changed")

    def child(self, name: str) -> _Directory:
        self.check()
        _require(re.fullmatch(r"[a-z][a-z0-9-]{0,63}", name) is not None,
                 "invalid native child directory")
        os.mkdir(name, 0o700, dir_fd=self.fd)  # Existing directories are never adopted.
        return _Directory(str(self.path / name))

    def read(self, name: str, maximum: int) -> bytes:
        self.check()
        result = _read_file(self.fd, name, maximum, private=True)
        self.check()
        return result

    def publish(self, name: str, raw: bytes, maximum: int) -> None:
        self.check()
        _require(re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,63}", name) is not None
                 and type(raw) is bytes and len(raw) <= maximum,
                 "invalid native publication")
        descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                             | os.O_CLOEXEC, 0o600, dir_fd=self.fd)
        try:
            offset = 0
            while offset < len(raw):
                written = os.write(descriptor, raw[offset:])
                _require(written > 0, "native publication made no progress")
                offset += written
            os.fsync(descriptor)
            self.check()
            info = os.fstat(descriptor)
            _require(stat.S_ISREG(info.st_mode) and info.st_uid == UID and info.st_gid == GID
                     and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1
                     and info.st_size == len(raw)
                     and _identity(info) == _identity(os.stat(name, dir_fd=self.fd,
                                                           follow_symlinks=False)),
                     "native publication identity changed")
            os.fsync(self.fd)
        finally:
            os.close(descriptor)

    def close(self) -> None:
        os.close(self.fd)


def _prepared_file(path: str, maximum: int) -> bytes:
    value = Path(path)
    _require(value.is_absolute() and str(value) == path
             and value.parent.resolve(strict=True) == value.parent
             and os.statvfs(value.parent).f_flag & os.ST_RDONLY != 0,
             "prepared native source/artifact mount is not canonical read-only storage")
    descriptor = os.open(value.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        return _read_file(descriptor, value.name, maximum, private=False)
    finally:
        os.close(descriptor)


def _sources(values: tuple[str, ...]) -> None:
    _require(type(values) is tuple and len(values) == len(SUITES)
             and all(type(value) is str and _SHA256.fullmatch(value) for value in values),
             "prepared native source digests do not match the exact inventory")


def load_prepared_sources() -> tuple[str, ...]:
    """Read fixed artifact input; root ownership is not independent approval.

    The external signed plan must bind this file through its artifact CAS. No
    digest computed from a newly observed fixture substitutes for this input.
    """
    raw = _prepared_file(PREPARED_SOURCES, MAX_MANIFEST_BYTES)
    value = json.loads(raw)
    _require(_canonical(value) == raw and type(value) is dict
             and set(value) == {"schema", "scripts"} and value["schema"] == PREPARED_SCHEMA,
             "prepared native source manifest is not canonical or has unknown fields")
    rows = value["scripts"]
    _require(type(rows) is list and len(rows) == len(SUITES), "prepared source inventory differs")
    result = []
    for row, suite in zip(rows, SUITES):
        _require(type(row) is dict and set(row) == {"path", "sha256"}
                 and row["path"] == suite.script, "prepared source order or fields differ")
        result.append(row["sha256"])
    captured = tuple(result)
    _sources(captured)
    return captured


def _verify_sources(source_sha256: tuple[str, ...]) -> None:
    for suite, expected in zip(SUITES, source_sha256):
        _require(_digest(_prepared_file(SOURCE_ROOT + "/" + suite.script, MAX_SOURCE_BYTES))
                 == expected, "native fixture differs from prepared source")


def _runtime_preflight() -> None:
    validate_inventory()
    _require(sys.platform == "linux" and os.uname().machine == "x86_64"
             and sys.version_info[:2] == (3, 11), "native runtime platform differs")
    _require(os.getuid() == os.geteuid() == UID and os.getgid() == os.getegid() == GID
             and set(os.getgroups()) <= {GID}, "native runner requires its fixed nonroot identity")
    _require(not any(name.startswith("PG") for name in os.environ),
             "native runner forbids ambient PostgreSQL configuration")
    _require(Path(sys.executable).resolve(strict=True) == Path(PYTHON_EXECUTABLE)
             and Path(__file__).resolve(strict=True).parents[1] == Path(SOURCE_ROOT),
             "native runner is not executing the fixed prepared source and Python")
    for executable in (PYTHON_EXECUTABLE, PG_BINDIR + "/initdb", PG_BINDIR + "/postgres"):
        path = Path(executable)
        _require(path.resolve(strict=True) == path, "native executable is not canonical")
        info = path.stat()
        _require(stat.S_ISREG(info.st_mode) and info.st_uid == 0
                 and info.st_mode & 0o022 == 0 and info.st_mode & 0o111 != 0
                 and os.statvfs(path).f_flag & os.ST_RDONLY != 0,
                 "native executable is not a root-owned read-only prepared file")


def _probe(processes: ProcessSet, server: Child, deadline: float) -> NativePostgresProbe:
    return query_probe(pump=processes.pump, check_alive=lambda: _alive(processes, server),
                       deadline=min(deadline, time.monotonic() + 5))


def _alive(processes: ProcessSet, server: Child) -> None:
    processes.pump(0)
    _require(not processes.cancelled and server.returncode is None and not server.lost
             and not server.overflow and not server.eof, "native PostgreSQL exited or lost observation")


def _ready(processes: ProcessSet, server: Child, socket: _Directory,
           deadline: float) -> NativePostgresProbe:
    while time.monotonic() < deadline:
        _alive(processes, server)
        socket.check()
        try:
            observed = _probe(processes, server, deadline)
        except NativePostgresProbeUnavailable:
            # Only initial readiness retries. No fixture or failed cluster is retried.
            processes.pump(0.05)
            continue
        _alive(processes, server)
        _require(time.monotonic() < deadline, "native readiness deadline exceeded")
        return observed
    raise NativePostgresRuntimeError("native PostgreSQL readiness timed out")


def _log(logs: _Directory, name: str, child: Child, records: list[dict]) -> tuple[str | None, int]:
    raw = bytes(child.log)
    logs.publish(name, raw, MAX_LOG_BYTES)
    records.append({"path": "logs/" + name, "sha256": _digest(raw), "bytes": len(raw),
                    "complete": child.complete_log})
    # An incomplete prefix is retained but never used as a complete fixture log.
    return (_digest(raw), len(raw)) if child.complete_log else (None, 0)


def execute_native_postgres(*, source_sha256: tuple[str, ...]) -> dict:
    """Run the sole fixed workload; accepted digests must be artifact-CAS-bound.

    All paths and commands are source constants. No implicit image construction,
    database adoption, arbitrary command/SQL/DSN selection or runtime download.
    Even COMPLETE requires external container/cgroup/data destruction.
    """
    _sources(source_sha256)
    _runtime_preflight()
    _verify_sources(source_sha256)
    started = time.monotonic()
    end = started + TOTAL_SECONDS
    work_end = end - SHUTDOWN_SECONDS - 10  # Emergency close and report reserve.
    observations = [NativeFixtureObservation(suite.script, "not-started", None, None, None, 0)
                    for suite in SUITES]
    errors: list[str] = []
    process_logs: list[dict] = []
    probe = None
    server = None
    normal_stop = False
    direct_reaped = False
    sources_unchanged = False
    summary = None
    old_mask = os.umask(0o077)
    try:
        with ExitStack() as stack:
            def retain(directory: _Directory) -> _Directory:
                stack.callback(directory.close)
                return directory

            private = retain(_Directory(PRIVATE_ROOT))
            runtime = retain(_Directory("/run"))
            output = retain(_Directory(str(Path(OUTPUT_ROOT).parent)))
            native = retain(private.child("native-postgres"))
            data = retain(native.child("pgdata"))
            socket = retain(runtime.child("serverware-native-postgres"))
            result = retain(output.child("native-postgres"))
            reports = retain(result.child("reports"))
            logs = retain(result.child("logs"))
            _require(str(native.path) == NATIVE_ROOT and str(data.path) == PGDATA
                     and str(reports.path) == REPORT_ROOT
                     and str(socket.path) == SOCKET_ROOT, "native fixed directory map differs")
            processes = ProcessSet()
            prior_signals = {number: signal.getsignal(number) for number in (signal.SIGTERM, signal.SIGINT)}

            def cancelled(_number, _frame):
                processes.cancelled = True

            try:
                for number in prior_signals:
                    signal.signal(number, cancelled)
                init = processes.start(initdb_argv(), env=environment(), cwd=SOURCE_ROOT)
                termination = processes.wait(init, min(work_end, time.monotonic() + INIT_SECONDS))
                if termination != "exited":
                    processes.stop(init, initial_signal=signal.SIGTERM,
                                   deadline=min(end - 5, time.monotonic() + 5))
                _log(logs, "initdb.log", init, process_logs)
                _require(termination == "exited" and init.returncode == 0 and init.complete_log,
                         "native cluster initialization incomplete")
                server = processes.start(postgres_argv(), env=environment(), cwd=SOURCE_ROOT)
                probe = _ready(processes, server, socket, min(work_end, time.monotonic() + STARTUP_SECONDS))
                for index, suite in enumerate(SUITES):
                    _alive(processes, server)
                    socket.check()
                    _require(time.monotonic() + suite.timeout_seconds <= work_end,
                             "native fixture has no full remaining time budget")
                    # An attempted spawn can fail after creating a process. It
                    # must never be reported as an untouched, unstarted suite.
                    observations[index] = NativeFixtureObservation(suite.script, "lost", None, None, None, 0)
                    child = processes.start(prepared_fixture_argv(index), env=environment(), cwd=SOURCE_ROOT)
                    termination = processes.wait(child, time.monotonic() + suite.timeout_seconds,
                                                 must_remain_alive=server)
                    observations[index] = replace(observations[index], termination=termination,
                        exit_code=child.returncode if termination == "exited" else None)
                    if termination != "exited":
                        processes.stop(child, initial_signal=signal.SIGTERM,
                                       deadline=min(end - 5, time.monotonic() + 5))
                    log_sha256, log_bytes = _log(logs, f"{index:02d}.log", child, process_logs)
                    observations[index] = replace(observations[index], log_sha256=log_sha256,
                                                  log_bytes=log_bytes)
                    raw = None
                    try:
                        raw = reports.read(f"{index:02d}.json", MAX_REPORT_BYTES)
                    except FileNotFoundError:
                        pass
                    observations[index] = replace(observations[index], report=raw)
                    current = reconcile_native_postgres_batch(tuple(observations), source_sha256=source_sha256)
                    _require(current.fixtures[index].tests_status == "PASS",
                             "native fixture did not complete successfully")
                    _alive(processes, server)
                    _require(_probe(processes, server, work_end) == probe,
                             "native cluster identity changed during fixtures")
                _alive(processes, server)
            except Exception as exc:
                errors.append("execution:" + (str(exc) if isinstance(exc, NativePostgresRuntimeError)
                                              else type(exc).__name__))
            finally:
                # Stop direct fixture/init children before PostgreSQL. No PID file,
                # unowned signal, recursive removal, restart or retained-data reuse.
                for child in processes.children:
                    if child is not server and child.returncode is None:
                        try:
                            processes.stop(child, initial_signal=signal.SIGTERM,
                                           deadline=min(end - 5, time.monotonic() + 5))
                        except Exception:
                            errors.append("child-stop-incomplete")
                if server is not None:
                    try:
                        # Already-exited PostgreSQL is not an intentional clean stop.
                        processes.pump(0)
                        was_alive = (server.returncode is None and not server.lost
                                     and not server.overflow and not server.eof)
                        reaped = processes.stop(server, initial_signal=signal.SIGINT,
                                                deadline=min(end - 5, time.monotonic() + SHUTDOWN_SECONDS))
                        socket.check()
                        socket_absent = all(not os.path.lexists(socket.path / name)
                                            for name in (".s.PGSQL.5432", ".s.PGSQL.5432.lock"))
                        normal_stop = (was_alive and reaped and server.returncode == 0
                                       and not server.forced_kill and server.complete_log and socket_absent)
                        _log(logs, "postgres.log", server, process_logs)
                    except Exception:
                        errors.append("postgres-stop-incomplete")
                try:
                    processes.close()
                    direct_reaped = all(child.returncode is not None for child in processes.children)
                except Exception:
                    errors.append("direct-child-reap-incomplete")
                for number, previous in prior_signals.items():
                    signal.signal(number, previous)
            try:
                _verify_sources(source_sha256)
                sources_unchanged = True
                summary = reconcile_native_postgres_batch(tuple(observations), source_sha256=source_sha256)
            except Exception as exc:
                errors.append("reconciliation:" + type(exc).__name__)
            if not normal_stop:
                errors.append("postgres-clean-stop-not-observed")
            if not direct_reaped:
                errors.append("direct-children-not-reaped")
            if processes.cancelled:
                errors.append("cancelled")
            if time.monotonic() >= end:
                errors.append("runtime-deadline-exceeded")
            complete = (not errors and not processes.cancelled and normal_stop and direct_reaped
                        and sources_unchanged and summary is not None and summary.tests_status == "PASS"
                        and time.monotonic() < end)
            document = {
                "schema": RESULT_SCHEMA, "runtimeStatus": "COMPLETE" if complete else "INCOMPLETE",
                "tests": asdict(summary) if summary is not None else None,
                "observedCluster": asdict(probe) if probe is not None else None,
                "sourceSha256": list(source_sha256), "sourceUnchanged": sources_unchanged,
                "processLogs": process_logs,
                "fixtureProcesses": [{"script": item.script, "termination": item.termination,
                                      "exitCode": item.exit_code} for item in observations],
                "postmasterCleanStopObserved": normal_stop, "directChildrenReaped": direct_reaped,
                "externalDestructionRequired": True, "errors": errors,
            }
            result.publish("runtime-result.json", _canonical(document), MAX_SUMMARY_BYTES)
            return document
    finally:
        os.umask(old_mask)


def main() -> int:
    if sys.argv[1:]:
        print("native PostgreSQL runner accepts no arguments", file=sys.stderr)
        return 2
    try:
        result = execute_native_postgres(source_sha256=load_prepared_sources())
    except Exception as exc:
        print("native PostgreSQL runner incomplete: " + type(exc).__name__, file=sys.stderr)
        return 2
    return 0 if result["runtimeStatus"] == "COMPLETE" else 2


if __name__ == "__main__":
    raise SystemExit(main())
