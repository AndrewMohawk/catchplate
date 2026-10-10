#!/usr/bin/env python3
"""Closed failure breadcrumbs under synthetic callers; no runtime acceptance."""
from contextlib import ExitStack
from copy import deepcopy
import io
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from scripts import check_operator_npm_publish as check
from scripts import test_operator_npm_publish_fixture as fixtures

CANARY = "synthetic-secret https://private.invalid/?token=private-canary"
PHASES = {"prerequisite", "unscoped", "scoped", "wrong_package", "outside_window",
          "wrong_placeholder", "revoked_app", "startup", "final", "unknown"}
STAGES = {"startup", "pre_client_catalog", "client", "checkpoint_registry", "checkpoint_audit",
          "checkpoint_health", "post_checkpoint_catalog", "final_verification", "unknown"}


class NpmPublishBreadcrumbTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        for target in ("socket.socket", "socket.create_connection", "socket.getaddrinfo",
                       "subprocess.Popen", "subprocess.run", "os.open", "os.mkdir", "os.makedirs", "os.fsync"):
            self.stack.enter_context(patch(target, side_effect=AssertionError("breadcrumb test attempted runtime I/O")))
        self.stack.enter_context(patch.object(check.time, "monotonic", return_value=0))
        self.sleep = self.stack.enter_context(patch.object(check.time, "sleep"))
        self.stack.enter_context(patch.object(check.signal, "alarm", side_effect=AssertionError("breadcrumb rearmed alarm")))
        self.stack.enter_context(patch.object(check.signal, "setitimer", side_effect=AssertionError("breadcrumb rearmed timer")))

    def test_projection_is_exact_allowlisted_and_never_serializes_raw_attributes(self):
        self.assertEqual(check.FAILURE_PHASES, PHASES)
        self.assertEqual(check.FAILURE_STAGES, STAGES)
        self.assertEqual(check.failure_location(None), {"phase": "startup", "stage": "startup"})
        for phase in PHASES:
            for stage in STAGES:
                value = SimpleNamespace(failure_phase=phase, failure_stage=stage, token=CANARY)
                self.assertEqual(check.failure_location(value), {"phase": phase, "stage": stage})
        class StringSubclass(str):
            pass
        class BrokenAttributes:
            def __getattr__(self, name):
                raise ValueError(CANARY)
        for invalid in (CANARY, "unscoped\n", "x" * 8192, StringSubclass("unscoped"), None, [], {}, True, 1):
            for phase, stage, expected in ((invalid, "client", {"phase": "unknown", "stage": "client"}),
                    ("unscoped", invalid, {"phase": "unscoped", "stage": "unknown"})):
                result = check.failure_location(SimpleNamespace(failure_phase=phase, failure_stage=stage, raw=CANARY))
                self.assertEqual(result, expected)
                self.assertEqual(set(result), {"phase", "stage"})
                self.assertNotIn("private", json.dumps(result))
        self.assertEqual(check.failure_location(BrokenAttributes()), {"phase": "unknown", "stage": "unknown"})
        self.assertEqual(check.failure_location(object()), {"phase": "unknown", "stage": "unknown"})
        self.sleep.assert_not_called()

    def checkpoint_fixture(self, failed_call=None):
        instance = object.__new__(check.NpmPublishCheck)
        instance.failure_phase, instance.failure_stage = "unscoped", "client"
        instance.deadline, instance.cutoff = 10.0, {}
        calls, failure = [], OSError(CANARY)
        evidence = {"syntheticEvidence": True}
        def invoke(name, result):
            def call(*args):
                calls.append(name)
                if name == failed_call:
                    raise failure
                return result
            return call
        instance.observe = invoke("registry", {})
        instance.accept_observation = invoke("registry_validation", [])
        instance.audit = invoke("audit", [])
        instance.validate_audits = invoke("audit_validation", (True, evidence))
        instance.audit_drained = invoke("health", True)
        instance.timeout = invoke("timeout", 0.1)
        return instance, calls, failure, evidence

    def test_checkpoint_failures_preserve_original_error_and_stop_at_exact_boundary(self):
        order = ["registry", "registry_validation", "audit", "audit_validation", "health"]
        for index, failed in enumerate(order):
            with self.subTest(boundary=failed):
                instance, calls, failure, _ = self.checkpoint_fixture(failed)
                with self.assertRaises(OSError) as caught:
                    instance.checkpoint()
                self.assertIs(caught.exception, failure)
                self.assertEqual(calls, order[:index + 1])
                stage = "checkpoint_registry" if index < 2 else "checkpoint_audit" if index < 4 else "checkpoint_health"
                self.assertEqual(check.failure_location(instance), {"phase": "unscoped", "stage": stage})
                self.assertEqual(instance.deadline, 10.0)
                self.sleep.assert_not_called()

    def test_successful_checkpoint_preserves_original_two_read_cycles_and_evidence(self):
        instance, calls, _, evidence = self.checkpoint_fixture()
        self.assertIs(instance.checkpoint(), evidence)
        cycle = ["registry", "registry_validation", "audit", "audit_validation", "health"]
        self.assertEqual(calls, cycle + ["timeout"] + cycle)
        self.sleep.assert_called_once_with(0.1)
        self.assertEqual(instance.deadline, 10.0)
        self.assertEqual(evidence, {"syntheticEvidence": True})

    def test_real_run_catalog_and_client_boundaries_add_no_reads_retries_or_phase_completion(self):
        for boundary in ("pre_client_catalog", "client", "post_checkpoint_catalog"):
            with self.subTest(boundary=boundary):
                failure = RuntimeError(CANARY)
                instance, calls = fixtures.NpmPublishFixtureTests().failing_run(failure)
                instance.failure_phase, instance.failure_stage = "startup", "startup"
                original_client = instance.client
                catalog_calls = []
                def unchanged(pins):
                    catalog_calls.append("catalog")
                    if boundary == "pre_client_catalog" or boundary == "post_checkpoint_catalog" and len(catalog_calls) == 2:
                        raise failure
                instance.unchanged = unchanged
                def client(spec, app, token):
                    if boundary == "client":
                        calls.append(("client", spec["case"]))
                        raise failure
                    return original_client(spec, app, token)
                instance.client = client
                with patch.object(check, "token_file", return_value="synthetic-admin"), \
                        patch.object(check, "failure_audit_observation", side_effect=AssertionError("new diagnostic I/O")):
                    with self.assertRaises(RuntimeError) as caught:
                        instance.run()
                self.assertIs(caught.exception, failure)
                self.assertEqual(check.failure_location(instance), {"phase": "prerequisite", "stage": boundary})
                expected_clients = [] if boundary == "pre_client_catalog" else [("client", "prerequisite")]
                self.assertEqual([row for row in calls if row[0] == "client"], expected_clients)
                self.assertEqual(instance.completed, ["prerequisite"] if boundary == "post_checkpoint_catalog" else [])
                self.assertEqual(len([row for row in calls if row[0] == "mutation"]), 9)
                self.assertEqual(len(catalog_calls), 2 if boundary == "post_checkpoint_catalog" else 1)
                self.assertEqual(instance.deadline, 10.0)
                self.sleep.assert_not_called()

    def main_result(self, instance):
        args = SimpleNamespace(timeout_seconds=180, expected_binary_sha256="sha256:" + "a" * 64,
                               fixture_marker_file=Path("/synthetic/marker"), run_claim_file=Path("/synthetic/claim"))
        output = io.StringIO()
        with patch.object(check.argparse.ArgumentParser, "parse_args", return_value=args), \
                patch.object(check, "NpmPublishCheck", return_value=instance) as create, \
                patch.object(check, "claim_fixture") as claim, patch.object(check.signal, "signal"), \
                patch.object(check.signal, "alarm") as alarm, patch("sys.stdout", output):
            status = check.main()
        create.assert_called_once_with(args)
        claim.assert_called_once_with(args.fixture_marker_file, args.run_claim_file)
        self.assertEqual([call.args for call in alarm.call_args_list], [(180,), (0,)])
        return status, json.loads(output.getvalue())

    def test_actual_main_failure_preserves_optional_client_fields_and_original_error(self):
        raw = {"schema": "serverware.privateNpmPublishClient/v1", "phase": "unscoped", "npmVersion": "11.8.0",
            "pacoteVersion": "21.0.4", "registryFetchVersion": "19.1.1", "strictSSL": True,
            "extraCaPreservesDefaultRoots": True, "configuredRetries": 0, "isolatedCache": True,
            "requestRewrite": False, "force": False, "dryRun": False, "provenance": False, "ok": False,
            "error": "stock npm publish operation failed", "stage": "npm_process", "errorCode": "E503",
            "processExitCode": 1, "stdoutBytes": 76, "stderrBytes": 0,
            "stdoutShape": "npm_error", "stdoutCodeKind": "recognized", "stdoutContext": "http_error"}
        for failure in (check.ClientFailure("unscoped", raw), check.ClientFailure("unscoped", None), ValueError(CANARY)):
            with self.subTest(error_type=type(failure).__name__, client_details=getattr(failure, "observation", None) is not None):
                audit = {"schema": "serverware.privateNpmPublishFailureAudit/v1", "healthReads": 0,
                         "queueState": "deadline", "counters": None, "auditRead": "deadline", "durableEventCount": None}
                instance = SimpleNamespace(run=Mock(side_effect=failure), clean=Mock(), clients=[{"phase": "prerequisite"}],
                    failure_phase="unscoped", failure_stage="client", failure_audit=audit, deadline=10.0)
                original_audit = deepcopy(audit)
                status, value = self.main_result(instance)
                expected = {"ok": False, "syntheticOnly": True, "productionReady": False,
                    "error": str(failure) if isinstance(failure, check.CheckFailure) else "ValueError",
                    "completedClientPhases": ["prerequisite"], "failureLocation": {"phase": "unscoped", "stage": "client"}}
                if isinstance(failure, check.ClientFailure):
                    expected["failureAuditObservation"] = audit
                    if failure.observation is not None:
                        expected["failedClient"] = failure.observation
                self.assertEqual((status, value), (1, expected))
                self.assertEqual(audit, original_audit)
                self.assertEqual(instance.deadline, 10.0)
                instance.run.assert_called_once_with()
                instance.clean.assert_not_called()
                for private in (CANARY, "private.invalid", "private-canary"):
                    self.assertNotIn(private, json.dumps(value))

    def test_actual_main_success_does_not_project_or_add_failure_fields(self):
        receipt = {"ok": True, "syntheticOnly": True, "productionReady": False, "syntheticReceipt": [1, 2]}
        original = deepcopy(receipt)
        instance = SimpleNamespace(run=Mock(return_value=receipt), clean=Mock(),
                                   failure_phase=CANARY, failure_stage=CANARY)
        with patch.object(check, "failure_location", side_effect=AssertionError("success inspected failure breadcrumb")):
            status, value = self.main_result(instance)
        self.assertEqual((status, value), (0, original))
        self.assertEqual(receipt, original)
        instance.run.assert_called_once_with()
        instance.clean.assert_called_once_with(json.dumps(receipt).encode())


if __name__ == "__main__":
    unittest.main(verbosity=2)
