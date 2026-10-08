#!/usr/bin/env python3
"""Deterministic warm-check telemetry controls; no sockets, fixture or clock sleeps."""
from copy import deepcopy
import json
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

try:
    from scripts import check_operator_catalog as checker
except ModuleNotFoundError:
    import check_operator_catalog as checker


class Clock:
    def __init__(self):
        self.epoch_ms, self.monotonic_ns = 1_790_000_000_000, 5_000_000_000

    def advance(self, milliseconds):
        self.epoch_ms += milliseconds
        self.monotonic_ns += milliseconds * 1_000_000


class WarmTelemetryTests(unittest.TestCase):
    def fixture(self):
        clock = Clock()
        value = object.__new__(checker.OperatorCatalogCheck)
        value.results, value.warm_observations, value.warm_lease_checks = [], [], []
        value.credential = "synthetic-provider-material-must-not-escape"
        value.admin_token = "synthetic-admin-material-must-not-escape"
        value.wrong_token = "synthetic-invalid-material-must-not-escape"
        value.client_token = "synthetic-client-material-must-not-escape"
        value.issued_tokens = [value.client_token]
        value.policy_hash = "sha256:" + "a" * 64
        value.args = SimpleNamespace(expected_binary_sha256="sha256:" + "b" * 64)
        application, rule, credential = {"principal_id": "agent:operator-demo:app1"}, {"route_id": "operator.rule1"}, {"id": "credential1"}
        health = {"credential_lease_earliest_expiry_epoch_ms": clock.epoch_ms + 5000,
            "policy_hash": value.policy_hash, "credential_leases": 2, "credential_generation_hot_scopes": 2,
            "ignored_untrusted_body": value.credential}
        event = {"id": "synthetic-audit-row1", "event_type": "data_plane.credential_lease.issued",
            "event": {"purpose": "dispatchSecret", "principal_id": application["principal_id"],
                "route_id": rule["route_id"], "credential_id": credential["id"], "policy_hash": value.policy_hash,
                "data_plane_binary_digest": value.args.expected_binary_sha256,
                "issued_at_epoch_ms": clock.epoch_ms - 100, "expires_at_epoch_ms": clock.epoch_ms + 5000,
                "ignored_untrusted_body": value.admin_token}}
        value.health, value.audit = Mock(return_value=health), Mock(return_value=[event])
        return clock, value, application, rule, credential, health, event

    def observe(self, clock, value, application, rule, credential):
        with patch.object(checker.time, "time_ns", side_effect=lambda: clock.epoch_ms * 1_000_000), \
                patch.object(checker.time, "monotonic_ns", side_effect=lambda: clock.monotonic_ns):
            return value.observe_live_lease("before_app1_revoke", application, rule, credential, minimum_scopes=2)

    def test_each_health_conjunct_is_named_without_bodies_or_tokens(self):
        cases = [
            ({"credential_lease_earliest_expiry_epoch_ms": None}, {"health_expiry_integer", "health_remaining_gt_1000ms"}),
            ({"credential_lease_earliest_expiry_epoch_ms": 0}, {"health_remaining_gt_1000ms"}),
            ({"policy_hash": "different"}, {"health_policy_hash_matches"}),
            ({"credential_leases": "untrusted"}, {"health_lease_count_integer", "health_lease_count_at_least_minimum"}),
            ({"credential_leases": 1}, {"health_lease_count_at_least_minimum"}),
            ({"credential_generation_hot_scopes": 1}, {"health_hot_scope_count_at_least_minimum"}),
        ]
        for changes, expected in cases:
            clock, value, application, rule, credential, health, _ = self.fixture()
            health.update(changes)
            with self.subTest(changes=changes), self.assertRaises(checker.CheckFailure) as caught:
                self.observe(clock, value, application, rule, credential)
            observation = value.warm_lease_evidence()["warmLeaseChecks"][0]
            self.assertEqual(set(observation["failedConjuncts"]), expected)
            self.assertTrue(observation["completed"])
            self.assertTrue(observation["healthFetch"]["completed"])
            self.assertTrue(observation["auditFetch"]["completed"])
            self.assertTrue(all(name in str(caught.exception) for name in expected))
            encoded = json.dumps(observation)
            for secret in (value.credential, value.admin_token, value.client_token, "ignored_untrusted_body", "untrusted"):
                self.assertNotIn(secret, encoded)
            value.health.assert_called_once()
            value.audit.assert_called_once()

    def test_audit_latency_is_measured_without_replacing_the_original_health_sample(self):
        clock, value, application, rule, credential, health, event = self.fixture()
        initial = clock.epoch_ms
        health["credential_lease_earliest_expiry_epoch_ms"] = initial + 2100

        def fetch_health():
            clock.advance(20)
            return health

        def fetch_audit():
            clock.advance(1200)
            return [event]

        value.health.side_effect, value.audit.side_effect = fetch_health, fetch_audit
        with self.assertRaisesRegex(checker.CheckFailure, "health_remaining_gt_1000ms"):
            self.observe(clock, value, application, rule, credential)
        observation = value.warm_lease_evidence()["warmLeaseChecks"][0]
        self.assertEqual(observation["healthFetch"]["elapsedMonotonicNs"], 20_000_000)
        self.assertEqual(observation["auditFetch"]["elapsedMonotonicNs"], 1_200_000_000)
        self.assertEqual(observation["healthAgeAtComparisonMonotonicNs"], 1_200_000_000)
        self.assertEqual(observation["comparison"]["epochMs"], initial + 1220)
        self.assertEqual(observation["healthRemainingMsAtComparison"], 880)
        value.health.assert_called_once()
        value.audit.assert_called_once()

    def test_exact_one_second_is_still_rejected_and_no_retry_occurs(self):
        clock, value, application, rule, credential, health, _ = self.fixture()
        health["credential_lease_earliest_expiry_epoch_ms"] = clock.epoch_ms + 1000
        with self.assertRaisesRegex(checker.CheckFailure, "health_remaining_gt_1000ms"):
            self.observe(clock, value, application, rule, credential)
        value.health.assert_called_once()
        value.audit.assert_called_once()

    def test_scoped_receipt_failure_reports_the_failed_cumulative_condition(self):
        for scenario, expected in [("missing", "scoped_dispatch_receipt_present"),
                ("untyped", "scoped_receipt_timestamps_integer"), ("future", "scoped_receipt_issued_not_future"),
                ("short", "scoped_receipt_remaining_gt_1000ms")]:
            clock, value, application, rule, credential, _, event = self.fixture()
            if scenario == "missing":
                value.audit.return_value = []
            elif scenario == "untyped":
                event["event"]["issued_at_epoch_ms"] = "untrusted"
            elif scenario == "future":
                event["event"]["issued_at_epoch_ms"] = clock.epoch_ms + 1
            else:
                event["event"]["expires_at_epoch_ms"] = clock.epoch_ms + 1000
            with self.subTest(scenario=scenario), self.assertRaisesRegex(checker.CheckFailure, expected):
                self.observe(clock, value, application, rule, credential)
            self.assertIn(expected, value.warm_lease_evidence()["warmLeaseChecks"][0]["failedConjuncts"])

    def test_success_retains_the_same_warm_deadline_and_only_safe_diagnostics(self):
        clock, value, application, rule, credential, health, event = self.fixture()
        event["event"]["expires_at_epoch_ms"] -= 100
        warm = self.observe(clock, value, application, rule, credential)
        self.assertEqual(warm["denialDeadlineEpochMs"], clock.epoch_ms + 4900)
        self.assertEqual(warm["_captured_monotonic_ns"], clock.monotonic_ns)
        observation = value.warm_lease_evidence()["warmLeaseChecks"][0]
        self.assertEqual(observation["failedConjuncts"], [])
        self.assertTrue(all(observation["conditions"].values()))
        self.assertEqual(observation["scopedLeaseAuditEventId"], event["id"])
        self.assertEqual(observation["healthEarliestExpiryEpochMs"], health["credential_lease_earliest_expiry_epoch_ms"])
        self.assertEqual(observation["scopedLeaseRemainingMsAtComparison"], 4900)

    def test_failed_reads_leave_partial_timing_without_an_error_body(self):
        for operation in ("healthFetch", "auditFetch"):
            clock, value, application, rule, credential, _, _ = self.fixture()
            target = value.health if operation == "healthFetch" else value.audit
            target.side_effect = RuntimeError(value.credential)
            with self.subTest(operation=operation), self.assertRaises(RuntimeError):
                self.observe(clock, value, application, rule, credential)
            observation = value.warm_lease_evidence()["warmLeaseChecks"][0]
            self.assertEqual(observation["failedConjuncts"], [operation + "_completed"])
            self.assertFalse(observation[operation]["completed"])
            self.assertIn("finished", observation[operation])
            self.assertNotIn(value.credential, json.dumps(observation))

    def test_run_checks_retains_warm_telemetry_even_if_other_evidence_is_unavailable(self):
        clock, value, application, rule, credential, health, _ = self.fixture()
        health["credential_leases"] = 1
        value.run = lambda: self.observe(clock, value, application, rule, credential)
        args = SimpleNamespace(expected_binary_sha256=value.args.expected_binary_sha256,
            timeout_seconds=120, fixture_marker_file=None, run_claim_file=None)
        with patch.object(checker, "claim_fixture"), patch.object(checker, "OperatorCatalogCheck", return_value=value), \
                patch.object(checker.features, "safe_evidence", side_effect=RuntimeError("unavailable")):
            result = checker.run_checks(args)
        self.assertFalse(result["ok"])
        self.assertTrue(result["safeEvidenceUnavailable"])
        self.assertEqual(result["warmLeaseChecks"][0]["failedConjuncts"], ["health_lease_count_at_least_minimum"])

    def test_capture_and_serialized_evidence_are_bounded(self):
        clock, value, application, rule, credential, _, _ = self.fixture()
        self.observe(clock, value, application, rule, credential)
        self.observe(clock, value, application, rule, credential)
        with self.assertRaisesRegex(checker.CheckFailure, "observation bound"):
            self.observe(clock, value, application, rule, credential)
        self.assertEqual(value.health.call_count, 2)
        huge = deepcopy(value.warm_lease_checks[0])
        huge["unexpected"] = "x" * 16385
        value.warm_lease_checks = [huge]
        with self.assertRaisesRegex(checker.CheckFailure, "evidence exceeds bound"):
            value.warm_lease_evidence()


if __name__ == "__main__":
    unittest.main()
