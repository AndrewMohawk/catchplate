"""Closed unittest accounting for the source-owned native PostgreSQL fixtures.

This records local test outcomes, not cluster ownership, cleanup, trusted build
identity, or production authority. The generic runner is also usable for pure
synthetic unittest controls; only ``run_native_fixture`` binds a source-owned
script and its actual __main__ module. An external prepared controller must
independently bind the complete source/image closure and process outcome.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import sys
import traceback
import unittest
from pathlib import Path

from serverware.native_postgres_inventory import SUITES, validate_inventory


SCHEMA = "serverware.nativePostgresFixtureResult/v1"
MAX_REPORT_BYTES = 256 * 1024
MAX_SCRIPT_BYTES = 2 * 1024 * 1024
MAX_ERRORS = 256
MAX_ERROR_BYTES = 1024
MAX_EVENTS = 1_000_000
_STATUSES = ("PASS", "FAIL", "ERROR", "SKIP", "EXPECTED_FAILURE",
             "UNEXPECTED_SUCCESS", "INCOMPLETE", "NOT_RUN")
_STATUS_COUNTS = dict(zip(_STATUSES, ("passed", "failed", "errored", "skipped",
    "expectedFailures", "unexpectedSuccesses", "incomplete", "notRun")))
_SUBTEST_COUNTS = ("passed", "failed", "errored", "skipped")


class NativePostgresResultsError(ValueError):
    pass


def _expected_ids(value: tuple[str, ...]) -> tuple[str, ...]:
    if (type(value) is not tuple or not 1 <= len(value) <= 1024
            or any(type(item) is not str or len(item) > 256
                   or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*\.test_[A-Za-z0-9_]+", item) is None
                   for item in value)
            or tuple(sorted(set(value))) != value):
        raise NativePostgresResultsError("native fixture expected test inventory is invalid")
    return tuple(item for item in value)


def _module_name(value: str) -> str:
    if (type(value) is not str or len(value) > 256
            or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*", value) is None):
        raise NativePostgresResultsError("native fixture module identity is invalid")
    return value


def _leaf_id(test: unittest.TestCase, module_name: str) -> str:
    if not isinstance(test, unittest.TestCase):
        raise NativePostgresResultsError("native fixture leaf is not a TestCase")
    cls = type(test)
    method = getattr(test, "_testMethodName", None)
    if (cls.__module__ != module_name or cls.__qualname__ != cls.__name__
            or type(method) is not str):
        raise NativePostgresResultsError("native fixture leaf module or class identity differs")
    identity = cls.__name__ + "." + method
    if test.id() != module_name + "." + identity:
        raise NativePostgresResultsError("native fixture leaf id differs")
    return identity


def _validate_inventory(suite, expected_test_ids: tuple[str, ...], module_name: str) -> None:
    found = []
    visited = set()
    nodes = 0

    def walk(node, depth):
        nonlocal nodes
        nodes += 1
        if depth > 16 or nodes > 4 * len(expected_test_ids) + 32:
            raise NativePostgresResultsError("native fixture loaded suite exceeds its bound")
        if id(node) in visited:
            raise NativePostgresResultsError("native fixture loaded suite repeats an object")
        visited.add(id(node))
        if type(node) is unittest.TestSuite:
            for child in node:
                walk(child, depth + 1)
        else:
            found.append(_leaf_id(node, module_name))
            if len(found) > len(expected_test_ids):
                raise NativePostgresResultsError("native fixture loaded inventory has extra tests")

    walk(suite, 0)
    if tuple(sorted(found)) != expected_test_ids:
        raise NativePostgresResultsError("native fixture loaded inventory is not source exact")


class NativePostgresResult(unittest.TextTestResult):
    def __init__(self, stream, descriptions, verbosity, *, expected_test_ids, module_name="__main__"):
        super().__init__(stream, descriptions, verbosity)
        self.expected_test_ids = _expected_ids(expected_test_ids)
        self.module_name = _module_name(module_name)
        self._rows = {identity: {"id": identity, "started": False, "stopped": False,
            "status": "NOT_RUN", "subtests": {key: 0 for key in _SUBTEST_COUNTS}}
            for identity in self.expected_test_ids}
        self._outcomes = {identity: [] for identity in self.expected_test_ids}
        self._broken = set()
        self._active = None
        self._events = 0
        self._run_started = False
        self._run_stopped = False
        self._runner_returned = False
        self._auxiliary_errors = []
        self._protocol_errors = []

    def _error(self, target, message):
        # Diagnostics are bounded ASCII labels, not arbitrary traceback text.
        text = str(message).encode("ascii", "backslashreplace")[:MAX_ERROR_BYTES].decode("ascii")
        if len(target) < MAX_ERRORS:
            target.append(text or "unspecified native fixture accounting error")

    def mark_incomplete(self, message):
        self._error(self._protocol_errors, message)

    def _charge(self):
        if not self._run_started or self._run_stopped:
            self.mark_incomplete("test callback arrived outside an active run")
            raise NativePostgresResultsError("native fixture callback is outside an active run")
        self._events += 1
        if self._events > MAX_EVENTS:
            self.mark_incomplete("native fixture event bound exceeded")
            raise NativePostgresResultsError("native fixture event bound exceeded")

    def _identity(self, test):
        try:
            identity = _leaf_id(test, self.module_name)
        except NativePostgresResultsError:
            return None
        return identity if identity in self._rows else None

    def _active_row(self, test):
        identity = self._identity(test)
        if identity is None or test is not self._active or self._rows[identity]["stopped"]:
            self.mark_incomplete("outcome has no exact active test")
            if identity is not None:
                self._broken.add(identity)
            return None
        return self._rows[identity]

    def startTestRun(self):
        if self._run_started or self._run_stopped:
            self.mark_incomplete("duplicate or out-of-order startTestRun")
        self._run_started = True
        super().startTestRun()

    def stopTestRun(self):
        if not self._run_started or self._run_stopped or self._active is not None:
            self.mark_incomplete("incomplete or duplicate stopTestRun")
        self._run_stopped = True
        super().stopTestRun()

    def startTest(self, test):
        self._charge()
        identity = self._identity(test)
        if identity is None or self._active is not None or self._rows[identity]["started"]:
            self.mark_incomplete("unexpected, duplicate or overlapping test start")
            if identity is not None:
                self._broken.add(identity)
            raise NativePostgresResultsError("native fixture test start is invalid")
        self._active = test
        self._rows[identity].update(started=True, status="INCOMPLETE")
        super().startTest(test)

    def _outcome(self, test, status):
        self._charge()
        row = self._active_row(test)
        if row is None:
            return
        outcomes = self._outcomes[row["id"]]
        if (status == "PASS" and (outcomes or any(row["subtests"][key]
                for key in ("failed", "errored", "skipped"))) or "PASS" in outcomes):
            self.mark_incomplete("success conflicts with another parent outcome")
            self._broken.add(row["id"])
        outcomes.append(status)

    def addSuccess(self, test):
        self._outcome(test, "PASS")
        super().addSuccess(test)

    def addFailure(self, test, err):
        self._outcome(test, "FAIL")
        super().addFailure(test, err)

    def addError(self, test, err):
        if self._identity(test) is None:
            self._charge()
            if type(test) is unittest.suite._ErrorHolder and self._active is None:
                self._error(self._auxiliary_errors, "fixture error outside a loaded method: " + test.id())
            else:
                self.mark_incomplete("error belongs to an unexpected test object")
        else:
            self._outcome(test, "ERROR")
        super().addError(test, err)

    def addSkip(self, test, reason):
        if isinstance(test, unittest.case._SubTest):
            self._charge()
            row = self._active_row(test.test_case)
            if row is not None:
                row["subtests"]["skipped"] += 1
        elif self._identity(test) is None:
            self._charge()
            if type(test) is unittest.suite._ErrorHolder and self._active is None:
                self._error(self._auxiliary_errors, "fixture skip outside a loaded method: " + test.id())
            else:
                self.mark_incomplete("skip belongs to an unexpected test object")
        else:
            self._outcome(test, "SKIP")
        super().addSkip(test, reason)

    def addExpectedFailure(self, test, err):
        self._outcome(test, "EXPECTED_FAILURE")
        super().addExpectedFailure(test, err)

    def addUnexpectedSuccess(self, test):
        self._outcome(test, "UNEXPECTED_SUCCESS")
        super().addUnexpectedSuccess(test)

    def addSubTest(self, test, subtest, err):
        self._charge()
        row = self._active_row(test)
        if not isinstance(subtest, unittest.case._SubTest) or subtest.test_case is not test:
            self.mark_incomplete("subtest is not bound to its actual parent")
            if row is not None:
                self._broken.add(row["id"])
        elif row is not None:
            kind = "passed" if err is None else (
                "failed" if issubclass(err[0], test.failureException) else "errored")
            row["subtests"][kind] += 1
            if self._outcomes[row["id"]]:
                self.mark_incomplete("subtest arrived after a parent terminal outcome")
                self._broken.add(row["id"])
        super().addSubTest(test, subtest, err)

    def stopTest(self, test):
        self._charge()
        row = self._active_row(test)
        if row is not None:
            identity = row["id"]
            outcomes = self._outcomes[identity]
            subtests = row["subtests"]
            # Multiple failures and cleanup errors are legitimate callbacks;
            # finalize one method status only when its single stop arrives.
            if identity in self._broken:
                status = "INCOMPLETE"
            elif "ERROR" in outcomes or subtests["errored"]:
                status = "ERROR"
            elif "FAIL" in outcomes or subtests["failed"]:
                status = "FAIL"
            elif "UNEXPECTED_SUCCESS" in outcomes:
                status = "UNEXPECTED_SUCCESS"
            elif "EXPECTED_FAILURE" in outcomes:
                status = "EXPECTED_FAILURE"
            elif "SKIP" in outcomes or subtests["skipped"]:
                status = "SKIP"
            elif outcomes == ["PASS"]:
                status = "PASS"
            else:
                status = "INCOMPLETE"
                self.mark_incomplete("test stopped without an explicit terminal outcome")
            row.update(stopped=True, status=status)
            self._active = None
        super().stopTest(test)

    @property
    def suite_status(self):
        rows = self._rows.values()
        if (self._protocol_errors or any(row["status"] in {"INCOMPLETE", "NOT_RUN"} for row in rows)
                or not (self._run_started and self._run_stopped and self._runner_returned)):
            return "INCOMPLETE"
        if self._auxiliary_errors or any(row["status"] != "PASS" for row in rows):
            return "FAIL"
        return "PASS"

    def wasSuccessful(self):
        # TextTestRunner prints its summary before returning. Its display must
        # still deny skips/xfails/auxiliary errors; the document additionally
        # requires the normal runner-return flag below.
        return (not self._protocol_errors and not self._auxiliary_errors
                and all(row["status"] == "PASS" for row in self._rows.values()))

    def document(self, *, script: str, source_sha256: str) -> dict:
        if (type(script) is not str or re.fullmatch(r"scripts/test_[a-z0-9_]+\.py", script) is None
                or type(source_sha256) is not str
                or re.fullmatch(r"sha256:[0-9a-f]{64}", source_sha256) is None):
            raise NativePostgresResultsError("native fixture report identity is invalid")
        if not (self._run_started and self._run_stopped and self._runner_returned):
            if "runner did not complete its exact lifecycle" not in self._protocol_errors:
                self.mark_incomplete("runner did not complete its exact lifecycle")
        rows = [{**row, "subtests": dict(row["subtests"])} for row in self._rows.values()]
        counts = {"expected": len(rows), "started": sum(row["started"] for row in rows),
                  "stopped": sum(row["stopped"] for row in rows)}
        counts.update({name: sum(row["status"] == status for row in rows)
                       for status, name in _STATUS_COUNTS.items()})
        counts.update({"subtests" + key.title(): sum(row["subtests"][key] for row in rows)
                       for key in _SUBTEST_COUNTS})
        counts.update(auxiliaryErrors=len(self._auxiliary_errors), protocolErrors=len(self._protocol_errors))
        return {"schema": SCHEMA, "script": script, "sourceSha256": source_sha256,
                "expectedTestIds": list(self.expected_test_ids), "tests": rows,
                "suiteStatus": self.suite_status, "counts": counts,
                "auxiliaryErrors": list(self._auxiliary_errors), "protocolErrors": list(self._protocol_errors)}


class NativePostgresRunner(unittest.TextTestRunner):
    def __init__(self, *, expected_test_ids, module_name="__main__", stream=None):
        super().__init__(stream=stream, descriptions=True, verbosity=2, failfast=False, buffer=False)
        self.expected_test_ids = _expected_ids(expected_test_ids)
        self.module_name = _module_name(module_name)
        self.result = None
        self._ran = False

    def _makeResult(self):
        if self.result is None:
            self.result = NativePostgresResult(self.stream, self.descriptions, self.verbosity,
                expected_test_ids=self.expected_test_ids, module_name=self.module_name)
        return self.result

    def run(self, test):
        if self._ran:
            raise NativePostgresResultsError("native fixture runner cannot be reused")
        self._ran = True
        result = self._makeResult()
        try:
            _validate_inventory(test, self.expected_test_ids, self.module_name)
            returned = super().run(test)
            if returned is not result:
                raise NativePostgresResultsError("native fixture runner result changed")
            result._runner_returned = True
        except BaseException as exc:
            result.mark_incomplete("native fixture runner aborted: " + type(exc).__name__)
            traceback.print_exc(file=self.stream)
        return result


def _script_digest(path: Path) -> str:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or not 1 <= before.st_size <= MAX_SCRIPT_BYTES:
            raise NativePostgresResultsError("native fixture source is not a bounded regular file")
        chunks = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(65536, MAX_SCRIPT_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_SCRIPT_BYTES:
                raise NativePostgresResultsError("native fixture source byte bound exceeded")
        after = os.fstat(descriptor)
        if ((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                or total != before.st_size):
            raise NativePostgresResultsError("native fixture source changed while hashing")
        return "sha256:" + hashlib.sha256(b"".join(chunks)).hexdigest()
    finally:
        os.close(descriptor)


def _open_report(path_value: str) -> tuple[int, int]:
    if type(path_value) is not str or len(path_value) > 4096 or "\0" in path_value:
        raise NativePostgresResultsError("native fixture result path is invalid")
    path = Path(path_value)
    if (not path.is_absolute() or str(path) != path_value
            or re.fullmatch(r"[a-z0-9][a-z0-9_.-]{0,127}\.json", path.name) is None
            or path.parent.resolve(strict=True) != path.parent):
        raise NativePostgresResultsError("native fixture result path is not canonical")
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        metadata = os.fstat(directory)
        if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o700:
            raise NativePostgresResultsError("native fixture result directory must be owned and mode 0700")
        output = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o600, dir_fd=directory)
        return directory, output
    except BaseException:
        os.close(directory)
        raise


def _write_report(directory: int, output: int, document: dict) -> None:
    raw = json.dumps(document, ensure_ascii=True, allow_nan=False,
                     sort_keys=True, separators=(",", ":")).encode("ascii")
    if len(raw) > MAX_REPORT_BYTES:
        raise NativePostgresResultsError("native fixture report byte bound exceeded")
    offset = 0
    while offset < len(raw):
        written = os.write(output, raw[offset:])
        if written <= 0:
            raise NativePostgresResultsError("native fixture result write made no progress")
        offset += written
    os.fsync(output)
    os.fsync(directory)


def run_native_fixture(script: str, *, argv: list[str], result_path: str | None) -> None:
    """Run the unchanged standalone CLI or its fixed prepared accounting mode."""
    if result_path is None:
        unittest.main(argv=argv)
        return
    validate_inventory()
    matches = [suite for suite in SUITES if suite.script == script]
    if type(script) is not str or len(matches) != 1:
        raise NativePostgresResultsError("native fixture script is not source owned")
    if type(argv) is not list or any(type(item) is not str for item in argv) or argv != [sys.argv[0], "-v"]:
        raise NativePostgresResultsError("prepared native fixture argv must be exactly script and -v")
    root = Path(__file__).resolve().parents[1]
    source = root / script
    main_file = getattr(sys.modules.get("__main__"), "__file__", None)
    if (type(main_file) is not str or source.resolve(strict=True) != source
            or Path(main_file).resolve(strict=True) != source
            or Path(argv[0]).resolve(strict=True) != source):
        raise NativePostgresResultsError("native fixture actual __main__ file differs from source script")
    digest = _script_digest(source)
    runner = NativePostgresRunner(expected_test_ids=matches[0].test_ids, module_name="__main__")
    # Reserve the output before suite loading/execution. Existing files are
    # never overwritten; failure or interruption may leave only an empty or
    # partial, non-admissible report. No fallback path or implicit mkdir exists.
    directory, output = _open_report(result_path)
    result = runner._makeResult()
    try:
        try:
            unittest.main(module="__main__", argv=argv, exit=False, testRunner=runner)
            if _script_digest(source) != digest:
                result.mark_incomplete("native fixture source changed during execution")
        except BaseException as exc:
            result.mark_incomplete("native fixture program aborted: " + type(exc).__name__)
            traceback.print_exc()
        document = result.document(script=script, source_sha256=digest)
        _write_report(directory, output, document)
    finally:
        try:
            os.close(output)
        finally:
            os.close(directory)
    raise SystemExit({"PASS": 0, "FAIL": 1, "INCOMPLETE": 2}[document["suiteStatus"]])
