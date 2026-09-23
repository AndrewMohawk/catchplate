#!/usr/bin/env python3
"""Pure result-consumer controls; synthetic reports are not native SQL evidence."""
from __future__ import annotations

import hashlib
import io
import json
import sys
import unittest
from dataclasses import FrozenInstanceError, replace
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from serverware.native_postgres_batch import (
    MAX_LOG_BYTES, MAX_REPORT_BYTES, NativeFixtureObservation,
    NativePostgresBatchError, reconcile_native_postgres_batch,
)
from serverware.native_postgres_inventory import SUITES
from serverware.native_postgres_results import NativePostgresRunner


SOURCE = tuple("sha256:" + format(index + 1, "064x") for index in range(14))
LOG = "sha256:" + hashlib.sha256(b"synthetic log").hexdigest()


def canonical(value):
    return json.dumps(value, allow_nan=False, ensure_ascii=True,
                      sort_keys=True, separators=(",", ":")).encode("ascii")


def report(index=0):
    suite = SUITES[index]
    count = len(suite.test_ids)
    return {
        "schema": "serverware.nativePostgresFixtureResult/v1",
        "script": suite.script,
        "sourceSha256": SOURCE[index],
        "expectedTestIds": list(suite.test_ids),
        "tests": [{"id": name, "started": True, "stopped": True, "status": "PASS",
                   "subtests": {"passed": 0, "failed": 0, "errored": 0, "skipped": 0}}
                  for name in suite.test_ids],
        "suiteStatus": "PASS",
        "counts": {
            "expected": count, "started": count, "stopped": count, "passed": count,
            "failed": 0, "errored": 0, "skipped": 0, "expectedFailures": 0,
            "unexpectedSuccesses": 0, "incomplete": 0, "notRun": 0,
            "subtestsPassed": 0, "subtestsFailed": 0, "subtestsErrored": 0,
            "subtestsSkipped": 0, "auxiliaryErrors": 0, "protocolErrors": 0,
        },
        "auxiliaryErrors": [], "protocolErrors": [],
    }


def observations():
    return tuple(NativeFixtureObservation(suite.script, "exited", 0,
                 canonical(report(index)), LOG, len(b"synthetic log"))
                 for index, suite in enumerate(SUITES))


def changed_first(**changes):
    current = observations()
    return (replace(current[0], **changes), *current[1:])


def reconcile(observed=None, sources=SOURCE):
    return reconcile_native_postgres_batch(
        observations() if observed is None else observed, source_sha256=sources)


class NativePostgresBatchTests(unittest.TestCase):
    def assert_bad_report(self, value):
        with self.assertRaises(NativePostgresBatchError):
            reconcile(changed_first(report=canonical(value)))

    def test_exact_ten_synthetic_reports_reconcile_as_tests_only_not_controller_proof(self):
        result = reconcile()
        self.assertEqual((result.tests_status, result.expected_tests, result.stopped_tests),
                         ("PASS", 238, 238))
        self.assertEqual(tuple(row.script for row in result.fixtures), tuple(s.script for s in SUITES))
        self.assertEqual(result.fixtures[0].source_sha256, SOURCE[0])
        self.assertEqual(result.fixtures[0].report_sha256,
                         "sha256:" + hashlib.sha256(canonical(report())).hexdigest())
        self.assertFalse(hasattr(result, "cleanup_complete"))
        with self.assertRaises(FrozenInstanceError):
            result.tests_status = "FAIL"
        with self.assertRaises(FrozenInstanceError):
            result.fixtures[0].tests_status = "FAIL"

    def test_real_recorder_wire_is_consumed_without_importing_native_fixtures(self):
        # Synthetic classes borrow only the fixed identity spelling. Their
        # trivial bodies deliberately prove no PostgreSQL behavior or authority.
        suite = SUITES[0]
        class_name = suite.test_ids[0].split(".")[0]
        methods = {identity.split(".")[1]: (lambda case: None) for identity in suite.test_ids}
        synthetic_type = type(class_name, (unittest.TestCase,), {"__module__": __name__, **methods})
        runner = NativePostgresRunner(expected_test_ids=suite.test_ids,
                                      module_name=__name__, stream=io.StringIO())
        result = runner.run(unittest.TestSuite(synthetic_type(method) for method in sorted(methods)))
        wire = canonical(result.document(script=suite.script, source_sha256=SOURCE[0]))
        self.assertEqual(reconcile(changed_first(report=wire)).tests_status, "PASS")
        result.mark_incomplete("synthetic interruption after methods")
        wire = canonical(result.document(script=suite.script, source_sha256=SOURCE[0]))
        self.assertEqual(reconcile(changed_first(report=wire, exit_code=2)).tests_status, "INCOMPLETE")

    def test_every_complete_negative_outcome_is_failure_not_missing_execution(self):
        for status, counter in (
            ("FAIL", "failed"), ("ERROR", "errored"), ("SKIP", "skipped"),
            ("EXPECTED_FAILURE", "expectedFailures"), ("UNEXPECTED_SUCCESS", "unexpectedSuccesses"),
        ):
            value = report()
            value["tests"][0]["status"] = status
            value["counts"]["passed"] -= 1
            value["counts"][counter] += 1
            value["suiteStatus"] = "FAIL"
            with self.subTest(status=status):
                result = reconcile(changed_first(report=canonical(value), exit_code=1))
                self.assertEqual((result.tests_status, result.stopped_tests), ("FAIL", 238))

    def test_not_run_and_interrupted_methods_cannot_be_hidden_by_complete_count(self):
        for status, started, stopped, counter in (
            ("NOT_RUN", False, False, "notRun"),
            ("INCOMPLETE", True, False, "incomplete"),
            ("INCOMPLETE", True, True, "incomplete"),
        ):
            value = report()
            value["tests"][0].update(status=status, started=started, stopped=stopped)
            value["counts"]["passed"] -= 1
            value["counts"][counter] += 1
            value["counts"]["started"] -= int(not started)
            value["counts"]["stopped"] -= int(not stopped)
            value["suiteStatus"] = "INCOMPLETE"
            with self.subTest(status=status, stopped=stopped):
                result = reconcile(changed_first(report=canonical(value), exit_code=2))
                self.assertEqual(result.tests_status, "INCOMPLETE")
                self.assertEqual(result.stopped_tests, 238 - int(not stopped))

    def test_auxiliary_error_fails_and_protocol_error_makes_even_full_run_incomplete(self):
        for key, status, code in (("auxiliaryErrors", "FAIL", 1),
                                  ("protocolErrors", "INCOMPLETE", 2)):
            value = report()
            value[key] = ["synthetic setup or accounting error"]
            value["counts"][key] = 1
            value["suiteStatus"] = status
            with self.subTest(key=key):
                self.assertEqual(reconcile(changed_first(report=canonical(value), exit_code=code)).tests_status,
                                 status)
                value["suiteStatus"] = "PASS"
                self.assert_bad_report(value)

    def test_timeout_lost_or_bad_exit_remain_incomplete_despite_passing_report(self):
        for changes in (
            {"termination": "timeout", "exit_code": None},
            {"termination": "lost", "exit_code": None},
            {"exit_code": 1}, {"exit_code": 2}, {"exit_code": -9}, {"exit_code": 255},
        ):
            with self.subTest(changes=changes):
                self.assertEqual(reconcile(changed_first(**changes)).tests_status, "INCOMPLETE")

    def test_missing_report_log_or_unstarted_fixture_is_incomplete(self):
        for changes in (
            {"report": None}, {"log_sha256": None, "log_bytes": 0},
            {"termination": "not-started", "exit_code": None, "report": None,
             "log_sha256": None, "log_bytes": 0},
        ):
            with self.subTest(changes=changes):
                self.assertEqual(reconcile(changed_first(**changes)).tests_status, "INCOMPLETE")

    def test_negative_report_requires_matching_nonzero_exit(self):
        value = report()
        value["tests"][0]["status"] = "FAIL"
        value["counts"].update(passed=7, failed=1)
        value["suiteStatus"] = "FAIL"
        for code in (0, 2, -9):
            with self.subTest(code=code):
                self.assertEqual(reconcile(changed_first(report=canonical(value), exit_code=code)).tests_status,
                                 "INCOMPLETE")

    def test_batch_shape_and_order_cannot_silently_drop_or_duplicate_suites(self):
        current = observations()
        for altered in (list(current), current[:-1], current + current[:1],
                        (current[1], current[0], *current[2:]), (current[0], *current[:-1])):
            with self.subTest(length=len(altered)), self.assertRaises(NativePostgresBatchError):
                reconcile(altered)

    def test_prepared_source_digest_is_not_taken_from_report(self):
        for sources in (list(SOURCE), SOURCE[:-1], (SOURCE[1], *SOURCE[1:]),
                        ("sha256:" + "A" * 64, *SOURCE[1:]), (True, *SOURCE[1:])):
            with self.subTest(sources=sources), self.assertRaises(NativePostgresBatchError):
                reconcile(sources=sources)
        for key, value in (("script", SUITES[1].script), ("sourceSha256", SOURCE[1]),
                           ("schema", "serverware.nativePostgresFixtureResult/v0")):
            altered = report()
            altered[key] = value
            self.assert_bad_report(altered)

    def test_missing_unknown_duplicate_and_reordered_test_ids_are_rejected(self):
        for mutation in ("missing", "extra", "duplicate", "reordered", "changed-expectation"):
            value = report()
            if mutation == "missing":
                value["tests"].pop()
            elif mutation == "extra":
                value["tests"].append(value["tests"][0].copy())
            elif mutation == "duplicate":
                value["tests"][1]["id"] = value["tests"][0]["id"]
            elif mutation == "reordered":
                value["tests"].reverse()
            else:
                value["expectedTestIds"][0] = "AnotherTests.test_filtered"
            with self.subTest(mutation=mutation):
                self.assert_bad_report(value)

    def test_counts_are_rederived_and_boolean_or_coerced_numbers_are_not_integers(self):
        for key in report()["counts"]:
            value = report()
            value["counts"][key] += 1
            self.assert_bad_report(value)
        for bad in (True, False, 0.0, "0", -1, 2**31, None):
            value = report()
            value["counts"]["failed"] = bad
            self.assert_bad_report(value)
            value = report()
            value["tests"][0]["subtests"]["passed"] = bad
            self.assert_bad_report(value)

    def test_subtest_results_must_match_counts_and_no_negative_subtest_can_pass(self):
        value = report()
        value["tests"][0]["subtests"]["passed"] = 2
        value["counts"]["subtestsPassed"] = 2
        self.assertEqual(reconcile(changed_first(report=canonical(value))).tests_status, "PASS")
        for key, counter in (("failed", "subtestsFailed"), ("errored", "subtestsErrored"),
                             ("skipped", "subtestsSkipped")):
            value = report()
            value["tests"][0]["subtests"][key] = 1
            value["counts"][counter] = 1
            self.assert_bad_report(value)

    def test_lifecycle_flags_and_unknown_statuses_are_not_repaired(self):
        for changes in (
            {"started": 1}, {"stopped": 1}, {"started": False}, {"stopped": False},
            {"status": "NOT_RUN"}, {"status": "SUCCESS"}, {"status": []},
        ):
            value = report()
            value["tests"][0].update(changes)
            self.assert_bad_report(value)

    def test_every_report_object_rejects_extra_and_missing_fields(self):
        for selector in (lambda x: x, lambda x: x["counts"],
                         lambda x: x["tests"][0], lambda x: x["tests"][0]["subtests"]):
            value = report()
            selector(value)["unexpected"] = False
            self.assert_bad_report(value)
            value = report()
            target = selector(value)
            target.pop(next(iter(target)))
            self.assert_bad_report(value)

    def test_error_lists_have_exact_bounded_ascii_shape(self):
        for bad in (None, {}, [""], ["e" * 1025], ["non-ascii-雪"], [True], ["x"] * 257):
            value = report()
            value["protocolErrors"] = bad
            self.assert_bad_report(value)

    def test_raw_reports_reject_partial_duplicate_noncanonical_or_unbounded_json(self):
        good = canonical(report())
        for raw in (
            b"", good[:-1], good + b"\n", b" " + good, good.decode("ascii"), bytearray(good),
            b'{"schema":"duplicate",' + good[1:], b"null", b"[]", b"NaN", b"Infinity",
            b"\xff", b"[" * 3000 + b"]" * 3000, b" " * (MAX_REPORT_BYTES + 1),
        ):
            with self.subTest(kind=type(raw), size=len(raw)), self.assertRaises(NativePostgresBatchError):
                reconcile(changed_first(report=raw))

    def test_observed_process_fields_are_closed_and_bounded(self):
        for changes in (
            {"termination": "unknown"}, {"exit_code": True}, {"exit_code": -65}, {"exit_code": 256},
            {"exit_code": None}, {"termination": "timeout", "exit_code": 0},
            {"termination": "not-started", "exit_code": None},
            {"log_sha256": "0" * 64}, {"log_sha256": None},
            {"log_bytes": True}, {"log_bytes": -1}, {"log_bytes": MAX_LOG_BYTES + 1},
        ):
            with self.subTest(changes=changes), self.assertRaises(NativePostgresBatchError):
                reconcile(changed_first(**changes))

    def test_constructor_bypassed_and_subclassed_observations_are_revalidated(self):
        class ObservationSubclass(NativeFixtureObservation):
            pass
        current = observations()
        inherited = ObservationSubclass(SUITES[0].script, "exited", 0, canonical(report()), LOG, 13)
        for bad in (None, {}, object.__new__(NativeFixtureObservation), inherited):
            with self.subTest(kind=type(bad)), self.assertRaises(NativePostgresBatchError):
                reconcile((bad, *current[1:]))

    def test_incomplete_takes_precedence_over_another_completed_failure(self):
        current = observations()
        value = report()
        value["tests"][0]["status"] = "ERROR"
        value["counts"].update(passed=7, errored=1)
        value["suiteStatus"] = "FAIL"
        result = reconcile((replace(current[0], report=canonical(value), exit_code=1),
                            replace(current[1], report=None), *current[2:]))
        self.assertEqual(result.tests_status, "INCOMPLETE")
        self.assertEqual(result.fixtures[0].tests_status, "FAIL")
        self.assertEqual(result.fixtures[1].tests_status, "INCOMPLETE")


if __name__ == "__main__":
    unittest.main()
