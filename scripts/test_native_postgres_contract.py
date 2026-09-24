#!/usr/bin/env python3
"""Pure native-suite inventory/reporting controls, not PostgreSQL execution.

The result tests run only synthetic unittest cases through the real recorder;
publication controls use small owned temporary files and actual filesystem I/O.
Source checks inspect, but never import or execute, the fourteen native fixtures.
Neither these controls nor a passing cooperative report authorize a prepared
lane, prove engine isolation/cleanup, or satisfy the external prerequisite gate.
"""
from __future__ import annotations

import ast
import io
import json
import os
import sys
import tempfile
import unittest
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from serverware import native_postgres_batch as batch
from serverware import native_postgres_inventory as inventory
from serverware import native_postgres_results as reporting


EXPECTED_SUITES = (
    ("scripts/test_webauthn_trust_projection_postgres.py", 8, False, 300),
    ("scripts/test_postgres_trigger_manifest.py", 5, False, 300),
    ("scripts/test_authority_mutation_postgres.py", 14, False, 300),
    ("scripts/test_authority_root_transition_postgres.py", 21, False, 300),
    ("scripts/test_authority_primary_tree_postgres.py", 9, False, 300),
    ("scripts/test_authority_audit_initialization_postgres.py", 31, False, 300),
    ("scripts/test_authority_audit_initialization_store_postgres.py", 36, True, 900),
    ("scripts/test_authority_global_audit_capacity_postgres.py", 25, False, 300),
    ("scripts/test_authority_verifier_read_postgres.py", 21, True, 300),
    ("scripts/test_authority_wire_json_postgres.py", 14, False, 300),
    ("scripts/test_authority_counted_hash_postgres.py", 10, False, 300),
    ("scripts/test_authority_counted_projection_postgres.py", 16, False, 300),
    ("scripts/test_authority_counted_store_postgres.py", 10, False, 300),
    ("scripts/test_authority_counted_maintenance_postgres.py", 24, False, 300),
)
SYNTHETIC_SCRIPT = "scripts/test_native_postgres_contract.py"
SYNTHETIC_SOURCE_DIGEST = "sha256:" + "a" * 64


def source_test_ids(script):
    """Static declaration closure only; this is not unittest discovery."""
    tree = ast.parse((ROOT / script).read_text(encoding="utf-8"))
    result = []
    for node in tree.body:
        if not isinstance(node, ast.ClassDef):
            continue
        if not any(isinstance(base, ast.Attribute) and base.attr == "TestCase"
                   and isinstance(base.value, ast.Name) and base.value.id == "unittest"
                   for base in node.bases):
            continue
        result.extend(f"{node.name}.{method.name}" for method in node.body
                      if isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef))
                      and method.name.startswith("test_"))
    return tuple(sorted(result))


def synthetic_cases(methods, *, name="SyntheticNative", setup=None, teardown=None, run_override=None):
    """Build local TestCases, never substitutes for a native fixture."""
    namespace = {"__module__": __name__, **methods}
    if setup is not None:
        namespace["setUpClass"] = classmethod(setup)
    if teardown is not None:
        namespace["tearDownClass"] = classmethod(teardown)
    if run_override is not None:
        namespace["run"] = run_override
    case_type = type(name, (unittest.TestCase,), namespace)
    return [case_type(method) for method in sorted(methods)]


def run_cases(cases, *, expected=None, suite=None):
    if expected is None:
        expected = tuple(sorted(f"{type(case).__name__}.{case._testMethodName}" for case in cases))
    runner = reporting.NativePostgresRunner(
        expected_test_ids=expected, module_name=__name__, stream=io.StringIO(),
    )
    return runner.run(unittest.TestSuite(cases) if suite is None else suite)


def pass_case(case):
    case.assertEqual(2 + 2, 4)


def fail_case(case):
    case.fail("synthetic method failure")


def error_case(case):
    raise RuntimeError("synthetic method error")


def exception_info(kind=AssertionError):
    try:
        raise kind("synthetic callback diagnostic")
    except kind:
        return sys.exc_info()


def document(result):
    return result.document(script=SYNTHETIC_SCRIPT, source_sha256=SYNTHETIC_SOURCE_DIGEST)


class NativePostgresInventoryTests(unittest.TestCase):
    def test_exact_closed_ten_suite_shapes_and_182_declared_methods(self):
        self.assertEqual(inventory.INVENTORY_SCHEMA, "serverware.nativePostgresInventory/v1")
        self.assertIsNone(inventory.validate_inventory())
        self.assertIs(type(inventory.SUITES), tuple)
        self.assertEqual(tuple((suite.script, len(suite.test_ids), suite.disposable_cluster,
                                suite.timeout_seconds) for suite in inventory.SUITES), EXPECTED_SUITES)
        self.assertIs(type(inventory.TOTAL_TESTS), int)
        self.assertEqual(inventory.TOTAL_TESTS, 244)
        self.assertEqual(sum(shape[1] for shape in EXPECTED_SUITES), 244)
        all_ids = tuple(test_id for suite in inventory.SUITES for test_id in suite.test_ids)
        self.assertEqual(len(all_ids), len(set(all_ids)))

    def test_inventory_matches_actual_source_declarations_without_importing_native_fixtures(self):
        for suite in inventory.SUITES:
            with self.subTest(script=suite.script):
                self.assertEqual(suite.test_ids, source_test_ids(suite.script))
                self.assertEqual(suite.test_ids, tuple(sorted(set(suite.test_ids))))

    def test_suite_is_frozen_data_not_constructor_authority(self):
        suite = inventory.SUITES[0]
        with self.assertRaises(FrozenInstanceError):
            suite.timeout_seconds = 1
        self.assertFalse(hasattr(suite, "__dict__"))
        untrusted = inventory.NativePostgresSuite("caller.py", (), True, 1)
        self.assertEqual(untrusted.script, "caller.py")
        with mock.patch.object(inventory, "SUITES", (untrusted, *inventory.SUITES[1:])):
            with self.assertRaises(ValueError):
                inventory.validate_inventory()
        self.assertIsNone(inventory.validate_inventory())

    def test_fixed_inventory_validator_rejects_count_type_order_identity_and_deadline_drift(self):
        first = inventory.SUITES[0]
        malformed = (
            replace(first, script="scripts/../caller.py"),
            replace(first, test_ids=first.test_ids[:-1]),
            replace(first, test_ids=tuple(reversed(first.test_ids))),
            replace(first, test_ids=(first.test_ids[0], *first.test_ids[:-1])),
            replace(first, test_ids=("BadClass.test_\N{LATIN SMALL LETTER E WITH ACUTE}", *first.test_ids[1:])),
            replace(first, test_ids=list(first.test_ids)),
            replace(first, disposable_cluster=0),
            replace(first, timeout_seconds=True),
            replace(first, timeout_seconds=301),
        )
        for value in malformed:
            with self.subTest(value=value), mock.patch.object(
                    inventory, "SUITES", (value, *inventory.SUITES[1:])):
                with self.assertRaises(ValueError):
                    inventory.validate_inventory()
        for suites in (list(inventory.SUITES), inventory.SUITES[:-1], inventory.SUITES[::-1]):
            with self.subTest(suites=suites), mock.patch.object(inventory, "SUITES", suites):
                with self.assertRaises(ValueError):
                    inventory.validate_inventory()
        for total in (True, 243, 244.0, "244"):
            with self.subTest(total=total), mock.patch.object(inventory, "TOTAL_TESTS", total):
                with self.assertRaises(ValueError):
                    inventory.validate_inventory()
        for schema in (None, "serverware.nativePostgresInventory/v0"):
            with self.subTest(schema=schema), mock.patch.object(inventory, "INVENTORY_SCHEMA", schema):
                with self.assertRaises(ValueError):
                    inventory.validate_inventory()

    def test_all_fixed_commands_bind_source_script_socket_report_and_exact_disposable_flags(self):
        for index, (script, _, disposable, _) in enumerate(EXPECTED_SUITES):
            expected = (
                "/usr/local/bin/python3.11", "/opt/serverware/src/" + script,
                "--postgres-dsn",
                "host=/run/serverware-native-postgres port=5432 dbname=postgres user=serverware_fixture_admin",
                "--prepared-result", f"/opt/serverware/output/native-postgres/reports/{index:02d}.json",
            )
            if disposable:
                expected += ("--disposable-cluster",)
            with self.subTest(script=script):
                self.assertEqual(batch.prepared_fixture_argv(index), expected + ("-v",))
                self.assertIs(type(batch.prepared_fixture_argv(index)), tuple)
        for index in (-1, 14, True, False, 0.0, "0", None):
            with self.subTest(index=index), self.assertRaises(batch.NativePostgresBatchError):
                batch.prepared_fixture_argv(index)


class NativePostgresRecorderTests(unittest.TestCase):
    def test_actual_synthetic_unittest_methods_all_complete(self):
        result = run_cases(synthetic_cases({"test_first": pass_case, "test_second": pass_case}))
        self.assertEqual(result.suite_status, "PASS")
        self.assertEqual(result.testsRun, 2)
        self.assertTrue(result.wasSuccessful())

    def test_closed_deterministic_document_and_fresh_nested_copies(self):
        first = run_cases(synthetic_cases({"test_first": pass_case, "test_second": pass_case}))
        second = run_cases(synthetic_cases({"test_first": pass_case, "test_second": pass_case}))
        actual = document(first)
        counts = {key: 0 for key in (
            "expected", "started", "stopped", "passed", "failed", "errored", "skipped",
            "expectedFailures", "unexpectedSuccesses", "incomplete", "notRun",
            "subtestsPassed", "subtestsFailed", "subtestsErrored", "subtestsSkipped",
            "auxiliaryErrors", "protocolErrors",
        )}
        counts.update(expected=2, started=2, stopped=2, passed=2)
        expected_ids = ["SyntheticNative.test_first", "SyntheticNative.test_second"]
        expected = {
            "schema": "serverware.nativePostgresFixtureResult/v1",
            "script": SYNTHETIC_SCRIPT, "sourceSha256": SYNTHETIC_SOURCE_DIGEST,
            "expectedTestIds": expected_ids,
            "tests": [{"id": test_id, "started": True, "stopped": True, "status": "PASS",
                       "subtests": {"passed": 0, "failed": 0, "errored": 0, "skipped": 0}}
                      for test_id in expected_ids],
            "suiteStatus": "PASS", "counts": counts,
            "auxiliaryErrors": [], "protocolErrors": [],
        }
        self.assertEqual(actual, expected)
        self.assertEqual(document(second), expected)
        self.assertEqual(json.dumps(actual, sort_keys=True, separators=(",", ":")),
                         json.dumps(document(second), sort_keys=True, separators=(",", ":")))
        actual["expectedTestIds"].clear()
        actual["tests"][0]["subtests"]["failed"] = 100
        actual["counts"]["passed"] = 0
        actual["protocolErrors"].append("caller edit")
        self.assertEqual(document(first), expected)

    def test_real_failure_and_error_continue_through_remaining_methods(self):
        completed = []

        def last(case):
            completed.append("last")

        result = run_cases(synthetic_cases({
            "test_a_failure": fail_case, "test_b_error": error_case, "test_c_last": last,
        }))
        self.assertEqual(result.suite_status, "FAIL")
        self.assertEqual(result.testsRun, 3)
        self.assertFalse(result.wasSuccessful())
        self.assertEqual(completed, ["last"])

    def test_skips_expected_failures_and_unexpected_successes_never_pass(self):
        def skip(case):
            case.skipTest("synthetic skip")

        @unittest.expectedFailure
        def expected_failure(case):
            fail_case(case)

        @unittest.expectedFailure
        def unexpected_success(case):
            pass_case(case)

        for method in (skip, expected_failure, unexpected_success):
            with self.subTest(method=method):
                result = run_cases(synthetic_cases({"test_case": method}))
                self.assertEqual(result.suite_status, "FAIL")
                self.assertEqual(result.testsRun, 1)

    def test_real_subtest_success_failure_error_and_skip_account_for_one_parent(self):
        def successful(case):
            for value in (1, 2):
                with case.subTest(value=value):
                    case.assertGreater(value, 0)

        def failing(case):
            with case.subTest(value="pass"):
                case.assertTrue(True)
            with case.subTest(value="fail"):
                case.fail("synthetic subtest failure")

        def errored(case):
            with case.subTest(value="error"):
                raise RuntimeError("synthetic subtest error")

        def skipped(case):
            with case.subTest(value="skip"):
                case.skipTest("synthetic subtest skip")

        for method, status in ((successful, "PASS"), (failing, "FAIL"),
                               (errored, "FAIL"), (skipped, "FAIL")):
            with self.subTest(method=method.__name__):
                result = run_cases(synthetic_cases({"test_case": method}))
                self.assertEqual(result.suite_status, status)
                self.assertEqual(result.testsRun, 1)

    def test_class_setup_error_is_incomplete_not_zero_test_success(self):
        def setup(cls):
            raise RuntimeError("synthetic class setup failure")

        result = run_cases(synthetic_cases({"test_first": pass_case, "test_second": pass_case}, setup=setup))
        self.assertEqual(result.suite_status, "INCOMPLETE")
        self.assertEqual(result.testsRun, 0)

    def test_class_teardown_error_after_all_methods_is_complete_failure(self):
        def teardown(cls):
            raise RuntimeError("synthetic class teardown failure")

        result = run_cases(synthetic_cases({"test_first": pass_case, "test_second": pass_case}, teardown=teardown))
        self.assertEqual(result.suite_status, "FAIL")
        self.assertEqual(result.testsRun, 2)

    def test_duplicate_or_unexpected_real_method_is_incomplete(self):
        for methods, expected in (
            ({"test_first": pass_case}, ("SyntheticNative.test_other",)),
            ({"test_first": pass_case, "test_second": pass_case}, ("SyntheticNative.test_first",)),
        ):
            with self.subTest(methods=methods):
                result = run_cases(synthetic_cases(methods), expected=expected)
                self.assertEqual(result.suite_status, "INCOMPLETE")
        cases = synthetic_cases({"test_first": pass_case})
        result = run_cases(cases + cases, expected=("SyntheticNative.test_first",))
        self.assertEqual(result.suite_status, "INCOMPLETE")

    def test_missing_method_and_early_stop_are_incomplete(self):
        expected = ("SyntheticNative.test_first", "SyntheticNative.test_second")
        result = run_cases(synthetic_cases({"test_first": pass_case}), expected=expected)
        self.assertEqual(result.suite_status, "INCOMPLETE")
        self.assertEqual(result.testsRun, 0)  # Loaded inventory fails before methods run.

        def stop(case):
            case._outcome.result.stop()

        cases = synthetic_cases({"test_first": stop, "test_second": pass_case})
        result = run_cases(cases, expected=expected)
        self.assertEqual(result.suite_status, "INCOMPLETE")
        self.assertEqual(result.testsRun, 1)

    def test_late_missing_case_cannot_repair_an_already_returned_incomplete_run(self):
        def stop(case):
            case._outcome.result.stop()

        cases = synthetic_cases({"test_first": stop, "test_second": pass_case})
        result = run_cases(cases)
        self.assertEqual(result.suite_status, "INCOMPLETE")
        self.assertEqual(document(result)["counts"]["notRun"], 1)
        with self.assertRaisesRegex(reporting.NativePostgresResultsError, "outside an active run"):
            cases[1](result)
        self.assertEqual(result.suite_status, "INCOMPLETE")
        self.assertEqual(document(result)["counts"]["notRun"], 1)
        self.assertEqual(document(result)["counts"]["stopped"], 1)

    def test_unexpected_real_test_error_or_skip_is_protocol_not_class_fixture_error(self):
        foreign = synthetic_cases({"test_extra": pass_case}, name="UnexpectedNative")[0]
        for callback in ("error", "skip"):
            def run(case, result):
                result.startTest(case)
                result.addSuccess(case)
                result.stopTest(case)
                if callback == "error":
                    result.addError(foreign, exception_info(RuntimeError))
                else:
                    result.addSkip(foreign, "not a loaded method")
                return result

            with self.subTest(callback=callback):
                result = run_cases(synthetic_cases({"test_case": pass_case}, run_override=run))
                value = document(result)
                self.assertEqual(value["suiteStatus"], "INCOMPLETE")
                self.assertTrue(value["protocolErrors"])
                self.assertEqual(value["auxiliaryErrors"], [])

    def test_malformed_start_stop_and_outcome_callbacks_cannot_be_complete(self):
        def driver(kind):
            def run(case, result):
                if kind == "outcome-before-start":
                    result.addSuccess(case)
                    return result
                result.startTest(case)
                if kind == "duplicate-start":
                    result.startTest(case)
                elif kind == "missing-outcome":
                    result.stopTest(case)
                elif kind == "missing-stop":
                    result.addSuccess(case)
                elif kind == "duplicate-stop":
                    result.addSuccess(case)
                    result.stopTest(case)
                    result.stopTest(case)
                elif kind == "outcome-after-stop":
                    result.addSuccess(case)
                    result.stopTest(case)
                    result.addSuccess(case)
                elif kind == "duplicate-success":
                    result.addSuccess(case)
                    result.addSuccess(case)
                    result.stopTest(case)
                elif kind == "success-after-failure":
                    result.addFailure(case, exception_info())
                    result.addSuccess(case)
                    result.stopTest(case)
                elif kind == "foreign-subtest":
                    result.addSubTest(case, case, None)
                    result.stopTest(case)
                return result
            return run

        for kind in ("outcome-before-start", "duplicate-start", "missing-outcome", "missing-stop",
                     "duplicate-stop", "outcome-after-stop", "duplicate-success",
                     "success-after-failure", "foreign-subtest"):
            with self.subTest(kind=kind):
                cases = synthetic_cases({"test_case": pass_case}, run_override=driver(kind))
                result = run_cases(cases)
                self.assertEqual(result.suite_status, "INCOMPLETE")
                self.assertTrue(document(result)["protocolErrors"])

    def test_real_method_failure_and_cleanup_error_are_one_terminal_error_not_protocol_failure(self):
        def failure_with_cleanup(case):
            case.addCleanup(error_case, case)
            case.fail("synthetic body failure followed by cleanup error")

        result = run_cases(synthetic_cases({"test_case": failure_with_cleanup}))
        value = document(result)
        self.assertEqual(result.suite_status, "FAIL")
        self.assertEqual(value["tests"][0]["status"], "ERROR")
        self.assertEqual(value["counts"]["errored"], 1)
        self.assertEqual(value["counts"]["stopped"], 1)
        self.assertEqual(value["protocolErrors"], [])
        self.assertEqual((len(result.failures), len(result.errors)), (1, 1))

    def test_runner_escaped_exception_is_incomplete_and_same_runner_cannot_be_reused(self):
        def interrupted(case, result):
            result.startTest(case)
            raise RuntimeError("synthetic runner interruption")

        cases = synthetic_cases({"test_case": pass_case}, run_override=interrupted)
        runner = reporting.NativePostgresRunner(
            expected_test_ids=("SyntheticNative.test_case",), module_name=__name__, stream=io.StringIO(),
        )
        result = runner.run(unittest.TestSuite(cases))
        self.assertEqual(result.suite_status, "INCOMPLETE")
        self.assertEqual(document(result)["counts"]["started"], 1)
        self.assertEqual(document(result)["counts"]["stopped"], 0)
        with self.assertRaises(reporting.NativePostgresResultsError):
            runner.run(unittest.TestSuite(synthetic_cases({"test_case": pass_case})))

    def test_missing_or_repeated_run_lifecycle_never_produces_a_complete_document(self):
        runner = reporting.NativePostgresRunner(
            expected_test_ids=("SyntheticNative.test_case",), module_name=__name__, stream=io.StringIO(),
        )
        unrun = runner._makeResult()
        first = document(unrun)
        self.assertEqual(first["suiteStatus"], "INCOMPLETE")
        self.assertEqual(first["counts"]["notRun"], 1)
        self.assertEqual(document(unrun), first)
        with self.assertRaisesRegex(reporting.NativePostgresResultsError, "outside an active run"):
            unrun.startTest(synthetic_cases({"test_case": pass_case})[0])
        self.assertEqual(document(unrun)["counts"]["started"], 0)
        for callback in ("startTestRun", "stopTestRun"):
            with self.subTest(callback=callback):
                result = run_cases(synthetic_cases({"test_case": pass_case}))
                self.assertEqual(result.suite_status, "PASS")
                getattr(result, callback)()
                self.assertEqual(result.suite_status, "INCOMPLETE")
                self.assertTrue(document(result)["protocolErrors"])

    def test_runner_expected_ids_and_module_identity_are_strict(self):
        for expected in ((), ["SyntheticNative.test_case"],
                         ("SyntheticNative.test_case", "SyntheticNative.test_case"),
                         ("SyntheticNative.test_second", "SyntheticNative.test_first"),
                         ("not-a-method",), (True,), ("SyntheticNative.test_\N{LATIN SMALL LETTER E WITH ACUTE}",)):
            with self.subTest(expected=expected), self.assertRaises(reporting.NativePostgresResultsError):
                reporting.NativePostgresRunner(expected_test_ids=expected, stream=io.StringIO())
        for module in (None, True, "", "wrong-module", "a/../b"):
            with self.subTest(module=module), self.assertRaises(reporting.NativePostgresResultsError):
                reporting.NativePostgresRunner(expected_test_ids=("SyntheticNative.test_case",),
                                               module_name=module, stream=io.StringIO())
        cases = synthetic_cases({"test_case": pass_case})
        runner = reporting.NativePostgresRunner(expected_test_ids=("SyntheticNative.test_case",),
                                               module_name="not_the_loaded_module", stream=io.StringIO())
        result = runner.run(unittest.TestSuite(cases))
        self.assertEqual(result.suite_status, "INCOMPLETE")
        self.assertEqual(result.testsRun, 0)

    def test_document_identity_does_not_coerce_or_normalize_caller_fields(self):
        result = run_cases(synthetic_cases({"test_case": pass_case}))
        for script, digest in ((None, SYNTHETIC_SOURCE_DIGEST), ("../test_case.py", SYNTHETIC_SOURCE_DIGEST),
                               (SYNTHETIC_SCRIPT, "a" * 64), (SYNTHETIC_SCRIPT, "sha256:" + "A" * 64),
                               (SYNTHETIC_SCRIPT, True)):
            with self.subTest(script=script, digest=digest), self.assertRaises(reporting.NativePostgresResultsError):
                result.document(script=script, source_sha256=digest)


class NativePostgresPublicationTests(unittest.TestCase):
    def test_numeric_report_name_real_canonical_write_and_both_fsyncs(self):
        value = document(run_cases(synthetic_cases({"test_case": pass_case})))
        expected = json.dumps(value, ensure_ascii=True, allow_nan=False,
                              sort_keys=True, separators=(",", ":")).encode("ascii")
        with tempfile.TemporaryDirectory(prefix="native-report-contract-") as temporary:
            path = Path(temporary).resolve() / "00.json"
            directory, output = reporting._open_report(str(path))
            try:
                real_fsync = os.fsync
                with mock.patch.object(reporting.os, "fsync", wraps=real_fsync) as observed:
                    reporting._write_report(directory, output, value)
                self.assertEqual(observed.call_args_list, [mock.call(output), mock.call(directory)])
                self.assertEqual(os.fstat(output).st_mode & 0o777, 0o600)
            finally:
                os.close(output)
                os.close(directory)
            self.assertEqual(path.read_bytes(), expected)
            self.assertEqual(json.loads(path.read_bytes()), value)

    def test_existing_and_symlink_reports_are_never_overwritten_and_empty_reservation_is_not_pass(self):
        with tempfile.TemporaryDirectory(prefix="native-report-contract-") as temporary:
            root = Path(temporary).resolve()
            path = root / "00.json"
            directory, output = reporting._open_report(str(path))
            os.close(output)
            os.close(directory)
            self.assertEqual(path.read_bytes(), b"")
            with self.assertRaises(batch.NativePostgresBatchError):
                batch._read_report(path.read_bytes(), 0, SYNTHETIC_SOURCE_DIGEST)
            path.write_bytes(b"prior report must remain untouched")
            with self.assertRaises(FileExistsError):
                reporting._open_report(str(path))
            self.assertEqual(path.read_bytes(), b"prior report must remain untouched")
            target = root / "retained"
            target.write_bytes(b"untouched retained bytes")
            link = root / "01.json"
            link.symlink_to(target)
            with self.assertRaises(FileExistsError):
                reporting._open_report(str(link))
            self.assertEqual(target.read_bytes(), b"untouched retained bytes")

    def test_report_parent_mode_and_noncanonical_paths_fail_before_output_creation(self):
        with tempfile.TemporaryDirectory(prefix="native-report-contract-") as temporary:
            root = Path(temporary).resolve()
            root.chmod(0o755)
            try:
                with self.assertRaisesRegex(reporting.NativePostgresResultsError, "owned and mode 0700"):
                    reporting._open_report(str(root / "00.json"))
                self.assertFalse((root / "00.json").exists())
            finally:
                root.chmod(0o700)
            (root / "child").mkdir()
            (root / "alias").symlink_to(root / "child", target_is_directory=True)
            for path in ("relative.json", str(root / "child" / ".." / "00.json"),
                         str(root / "alias" / "00.json"), str(root / ".hidden.json")):
                with self.subTest(path=path), self.assertRaises(reporting.NativePostgresResultsError):
                    reporting._open_report(path)
            self.assertFalse((root / "00.json").exists())
            self.assertFalse((root / "child" / "00.json").exists())


class NativePostgresSourceHookTests(unittest.TestCase):
    def test_all_ten_main_hooks_preserve_dsn_and_disposable_initialization_before_closed_runner(self):
        for script, _, disposable, _ in EXPECTED_SUITES:
            with self.subTest(script=script):
                tree = ast.parse((ROOT / script).read_text(encoding="utf-8"))
                imports = [node for node in tree.body if isinstance(node, ast.ImportFrom)
                           and node.module == "serverware.native_postgres_results"]
                self.assertEqual(len(imports), 1)
                self.assertEqual([(alias.name, alias.asname) for alias in imports[0].names],
                                 [("run_native_fixture", None)])
                mains = [node for node in tree.body if isinstance(node, ast.If)
                         and ast.unparse(node.test) == "__name__ == '__main__'"]
                self.assertEqual(len(mains), 1)
                main = mains[0]
                calls = [node for node in ast.walk(main) if isinstance(node, ast.Call)]
                parsers = [node for node in calls if ast.unparse(node.func) == "argparse.ArgumentParser"]
                self.assertEqual(len(parsers), 1)
                options = {keyword.arg: keyword.value for keyword in parsers[0].keywords}
                self.assertIsInstance(options["allow_abbrev"], ast.Constant)
                self.assertIs(options["allow_abbrev"].value, False)
                arguments = [node for node in calls if ast.unparse(node.func) == "parser.add_argument"]
                names = [node.args[0].value for node in arguments if node.args
                         and isinstance(node.args[0], ast.Constant)]
                self.assertEqual(names.count("--postgres-dsn"), 1)
                self.assertEqual(names.count("--prepared-result"), 1)
                self.assertEqual(names.count("--disposable-cluster"), int(disposable))
                dsn = next(node for node in arguments if node.args[0].value == "--postgres-dsn")
                self.assertIs(next(keyword.value.value for keyword in dsn.keywords
                                   if keyword.arg == "required"), True)
                entries = [node for node in calls if isinstance(node.func, ast.Name)
                           and node.func.id == "run_native_fixture"]
                self.assertEqual(len(entries), 1)
                entry = entries[0]
                self.assertEqual([argument.value for argument in entry.args], [script])
                self.assertEqual({keyword.arg: ast.unparse(keyword.value) for keyword in entry.keywords},
                                 {"argv": "[sys.argv[0], *test_arguments]",
                                  "result_path": "arguments.prepared_result"})
                assignments = {target.id: node for node in main.body if isinstance(node, ast.Assign)
                               for target in node.targets if isinstance(target, ast.Name)}
                connection = assignments["CONNECTION_PARAMETERS"]
                self.assertEqual(ast.unparse(connection.value),
                                 "local_connection_parameters(arguments.postgres_dsn)")
                self.assertLess(connection.lineno, entry.lineno)
                if disposable:
                    acknowledgement = assignments["DISPOSABLE_CLUSTER_ACKNOWLEDGED"]
                    self.assertEqual(ast.unparse(acknowledgement.value), "arguments.disposable_cluster")
                    self.assertLess(acknowledgement.lineno, entry.lineno)
                    switch = next(node for node in arguments if node.args[0].value == "--disposable-cluster")
                    self.assertEqual(next(keyword.value.value for keyword in switch.keywords
                                          if keyword.arg == "action"), "store_true")
                    switch_options = {keyword.arg: keyword.value for keyword in switch.keywords}
                    if script == "scripts/test_authority_verifier_read_postgres.py":
                        self.assertIs(switch_options["required"].value, True)
                    else:
                        self.assertNotIn("required", switch_options)
                self.assertFalse(any(ast.unparse(node.func) == "unittest.main" for node in calls))


if __name__ == "__main__":
    unittest.main()
