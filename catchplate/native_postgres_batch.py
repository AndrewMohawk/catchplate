"""Closed command and result reconciliation for the prepared native-PG suite.

This module does not start PostgreSQL, execute commands, read files, accept a
caller-selected DSN, install dependencies, or grant verification authority.
Its results describe cooperative fixture reports joined to caller-observed
process results. An independently admitted controller must still bind the
source/runtime/command closure, enforce resource limits and deadlines, capture
logs, and prove complete teardown. These values are not that controller proof.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass

from .native_postgres_inventory import SUITES, TOTAL_TESTS, validate_inventory


SOURCE_ROOT = "/opt/catchplate/src"
PYTHON_EXECUTABLE = "/usr/local/bin/python3.11"
REPORT_ROOT = "/opt/catchplate/output/native-postgres/reports"
LOCAL_DSN = (
    "host=/run/catchplate-native-postgres port=5432 "
    "dbname=postgres user=catchplate_fixture_admin"
)
REPORT_SCHEMA = "catchplate.nativePostgresFixtureResult/v1"
MAX_REPORT_BYTES = 262144
MAX_LOG_BYTES = 8 * 1024 * 1024
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}", re.ASCII)
_STATUS_COUNTS = {
    "PASS": "passed", "FAIL": "failed", "ERROR": "errored", "SKIP": "skipped",
    "EXPECTED_FAILURE": "expectedFailures", "UNEXPECTED_SUCCESS": "unexpectedSuccesses",
    "INCOMPLETE": "incomplete", "NOT_RUN": "notRun",
}
_SUBTEST_COUNTS = {
    "passed": "subtestsPassed", "failed": "subtestsFailed",
    "errored": "subtestsErrored", "skipped": "subtestsSkipped",
}


class NativePostgresBatchError(ValueError):
    pass


def prepared_fixture_argv(index: int) -> tuple[str, ...]:
    """Return one source-fixed invocation, not a general command constructor.

    The owning runner must create a private, canonical, mode-0700 socket and
    report directory before invoking any command. The disposable acknowledgment
    does not by itself prove that a database is safe to modify.
    """
    validate_inventory()
    if type(index) is not int or not 0 <= index < len(SUITES):
        raise NativePostgresBatchError("native fixture index is outside the fixed inventory")
    suite = SUITES[index]
    arguments = (
        PYTHON_EXECUTABLE,
        SOURCE_ROOT + "/" + suite.script,
        "--postgres-dsn", LOCAL_DSN,
        "--prepared-result", REPORT_ROOT + f"/{index:02d}.json",
    )
    if suite.disposable_cluster:
        arguments += ("--disposable-cluster",)
    return arguments + ("-v",)


@dataclass(frozen=True, slots=True)
class NativeFixtureObservation:
    """Inputs collected by a runner, not authenticated execution receipts.

    A missing/oversized log cannot support completion. The future runner must
    capture bounded logs while running, not buffer unlimited output and truncate
    it after the child exits. A timeout stays incomplete even if a report exists.
    """

    script: str
    termination: str  # exited, timeout, lost, or not-started
    exit_code: int | None
    report: bytes | None
    log_sha256: str | None
    log_bytes: int


@dataclass(frozen=True, slots=True)
class NativeFixtureSummary:
    script: str
    tests_status: str
    stopped_tests: int
    source_sha256: str
    report_sha256: str | None
    log_sha256: str | None
    log_bytes: int


@dataclass(frozen=True, slots=True)
class NativeBatchSummary:
    """Test accounting only; PASS is neither teardown nor lane/release approval."""

    tests_status: str
    expected_tests: int
    stopped_tests: int
    fixtures: tuple[NativeFixtureSummary, ...]


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise NativePostgresBatchError(message)


def _digest(value: str) -> None:
    _require(type(value) is str and _DIGEST.fullmatch(value) is not None,
             "native result digest is not canonical SHA-256")


def _integer(value: int, maximum: int = 2**31 - 1) -> None:
    _require(type(value) is int and 0 <= value <= maximum,
             "native result count is not a bounded exact integer")


def _keys(value: dict, expected: set[str]) -> None:
    _require(type(value) is dict and set(value) == expected,
             "native result has missing or unknown fields")


def _pairs(pairs: list[tuple[str, object]]) -> dict:
    result: dict = {}
    for key, value in pairs:
        _require(key not in result, "native result has duplicate JSON keys")
        result[key] = value
    return result


def _invalid_constant(value: str) -> None:
    raise NativePostgresBatchError("native result contains a non-JSON constant")


def _messages(value: list) -> None:
    _require(type(value) is list and len(value) <= 256,
             "native result error list is unbounded")
    for message in value:
        _require(type(message) is str and 1 <= len(message) <= 1024 and message.isascii(),
                 "native result error message is invalid")


def _read_report(raw: bytes, index: int, source_sha256: str) -> tuple[str, int]:
    _require(type(raw) is bytes and 0 < len(raw) <= MAX_REPORT_BYTES,
             "native report is missing or exceeds its byte bound")
    try:
        value = json.loads(raw.decode("ascii"), object_pairs_hook=_pairs,
                           parse_constant=_invalid_constant)
        canonical = json.dumps(value, allow_nan=False, ensure_ascii=True,
                               sort_keys=True, separators=(",", ":")).encode("ascii")
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise NativePostgresBatchError("native report JSON is invalid") from exc
    _require(canonical == raw, "native report JSON is not canonical")
    _keys(value, {"schema", "script", "sourceSha256", "expectedTestIds", "tests",
                  "suiteStatus", "counts", "auxiliaryErrors", "protocolErrors"})
    suite = SUITES[index]
    _require(value["schema"] == REPORT_SCHEMA and value["script"] == suite.script,
             "native report schema or script identity differs")
    _require(value["sourceSha256"] == source_sha256,
             "native report source digest differs from prepared source")
    _require(value["expectedTestIds"] == list(suite.test_ids),
             "native report expected inventory differs")
    _messages(value["auxiliaryErrors"])
    _messages(value["protocolErrors"])
    rows = value["tests"]
    _require(type(rows) is list and len(rows) == len(suite.test_ids),
             "native report does not account for every expected test")
    counts = {key: 0 for key in (
        "expected", "started", "stopped", *_STATUS_COUNTS.values(),
        *_SUBTEST_COUNTS.values(), "auxiliaryErrors", "protocolErrors",
    )}
    counts["expected"] = len(suite.test_ids)
    counts["auxiliaryErrors"] = len(value["auxiliaryErrors"])
    counts["protocolErrors"] = len(value["protocolErrors"])
    for expected_id, row in zip(suite.test_ids, rows):
        _keys(row, {"id", "started", "stopped", "status", "subtests"})
        _require(row["id"] == expected_id, "native report test IDs are missing, duplicated or reordered")
        status = row["status"]
        _require(type(status) is str and status in _STATUS_COUNTS,
                 "native report test status is unknown")
        started, stopped = row["started"], row["stopped"]
        _require(type(started) is bool and type(stopped) is bool and (started or not stopped),
                 "native report test lifecycle is invalid")
        _keys(row["subtests"], set(_SUBTEST_COUNTS))
        for key, total in _SUBTEST_COUNTS.items():
            _integer(row["subtests"][key])
            counts[total] += row["subtests"][key]
        if status == "NOT_RUN":
            _require(not started and not stopped and not any(row["subtests"].values()),
                     "native report unstarted test has execution evidence")
        elif status == "INCOMPLETE":
            _require(started, "native report incomplete test was never started")
        else:
            _require(started and stopped, "native report terminal test has incomplete lifecycle")
        if status == "PASS":
            _require(not any(row["subtests"][key] for key in ("failed", "errored", "skipped")),
                     "native report passing test contains negative subtests")
        counts["started"] += int(started)
        counts["stopped"] += int(stopped)
        counts[_STATUS_COUNTS[status]] += 1
    _keys(value["counts"], set(counts))
    for key, expected in counts.items():
        _integer(value["counts"][key])
        _require(value["counts"][key] == expected, "native report summary count differs from its rows")
    if counts["protocolErrors"] or counts["incomplete"] or counts["notRun"]:
        status = "INCOMPLETE"
    elif counts["auxiliaryErrors"] or counts["passed"] != counts["expected"]:
        status = "FAIL"
    else:
        status = "PASS"
    _require(value["suiteStatus"] == status, "native report suite status differs from its outcomes")
    return status, counts["stopped"]


def reconcile_native_postgres_batch(
    observations: tuple[NativeFixtureObservation, ...], *, source_sha256: tuple[str, ...],
) -> NativeBatchSummary:
    """Reconcile the complete ordered source inventory with prepared digests.

    ``source_sha256`` must come from the independently admitted prepared source,
    not from the child report. This pure function cannot authenticate its caller.
    Unstarted/timeout/lost children and missing logs/reports stay INCOMPLETE;
    malformed or internally inconsistent input raises rather than being repaired.
    A nonzero exit cannot be hidden by a syntactically passing report.
    """
    validate_inventory()
    _require(type(observations) is tuple and len(observations) == len(SUITES),
             "native batch must account for the exact source fixture inventory")
    _require(type(source_sha256) is tuple and len(source_sha256) == len(SUITES),
             "native batch requires every prepared source digest")
    summaries = []
    for index, (observation, source) in enumerate(zip(observations, source_sha256)):
        _digest(source)
        _require(type(observation) is NativeFixtureObservation, "native observation has the wrong type")
        try:
            # Own a fresh immutable snapshot, including constructor-bypassed inputs.
            observed = NativeFixtureObservation(
                observation.script, observation.termination, observation.exit_code,
                observation.report, observation.log_sha256, observation.log_bytes,
            )
        except AttributeError as exc:
            raise NativePostgresBatchError("native observation is incomplete") from exc
        _require(type(observed.script) is str and observed.script == SUITES[index].script,
                 "native batch fixture is missing, duplicated or reordered")
        _require(type(observed.termination) is str and observed.termination in
                 {"exited", "timeout", "lost", "not-started"}, "native process termination is unknown")
        if observed.termination == "exited":
            _require(type(observed.exit_code) is int and -64 <= observed.exit_code <= 255,
                     "native process exit code is invalid")
        else:
            _require(observed.exit_code is None, "native nonterminal observation carries an exit code")
        _integer(observed.log_bytes, MAX_LOG_BYTES)
        if observed.log_sha256 is not None:
            _digest(observed.log_sha256)
        else:
            _require(observed.log_bytes == 0, "native missing log carries a byte count")
        if observed.termination == "not-started":
            _require(observed.report is None and observed.log_sha256 is None,
                     "native unstarted fixture carries execution output")
        report_digest, status, stopped = None, "INCOMPLETE", 0
        if observed.report is not None:
            status, stopped = _read_report(observed.report, index, source)
            report_digest = "sha256:" + hashlib.sha256(observed.report).hexdigest()
        if (observed.termination != "exited" or observed.log_sha256 is None
                or observed.report is None or observed.exit_code not in (0, 1, 2)):
            status = "INCOMPLETE"
        elif status == "PASS" and observed.exit_code != 0:
            status = "INCOMPLETE"
        elif status == "FAIL" and observed.exit_code != 1:
            status = "INCOMPLETE"
        summaries.append(NativeFixtureSummary(
            observed.script, status, stopped, source, report_digest,
            observed.log_sha256, observed.log_bytes,
        ))
    states = {summary.tests_status for summary in summaries}
    status = "INCOMPLETE" if "INCOMPLETE" in states else "FAIL" if "FAIL" in states else "PASS"
    return NativeBatchSummary(status, TOTAL_TESTS,
                             sum(summary.stopped_tests for summary in summaries), tuple(summaries))
