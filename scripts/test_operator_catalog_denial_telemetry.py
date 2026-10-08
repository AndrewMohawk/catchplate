#!/usr/bin/env python3
"""Deterministic denial timing controls; no sockets, runtime or clock sleeps."""
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


class DenialTelemetryTests(unittest.TestCase):
    def fixture(self):
        clock = Clock()
        value = object.__new__(checker.OperatorCatalogCheck)
        value.results, value.warm_observations = [], []
        value.warm_lease_checks, value.warm_denial_checks = [], []
        value.credential = "synthetic-provider-material-must-not-escape"
        value.admin_token = "synthetic-admin-material-must-not-escape"
        value.wrong_token = "synthetic-invalid-material-must-not-escape"
        value.client_token = "synthetic-client-material-must-not-escape"
        value.issued_tokens = [value.client_token]
        value.args = SimpleNamespace(expected_binary_sha256="sha256:" + "b" * 64)
        warm = {"stage": "before_app1_revoke", "principalId": "agent:operator-demo:app1",
            "routeId": "operator.rule1", "scopedLeaseAuditEventId": "synthetic-audit-row1",
            "capturedAtEpochMs": clock.epoch_ms, "_captured_monotonic_ns": clock.monotonic_ns,
            "healthEarliestUnexpiredLeaseEpochMs": clock.epoch_ms + 3000,
            "scopedLeaseExpiryEpochMs": clock.epoch_ms + 2000,
            "denialDeadlineEpochMs": clock.epoch_ms + 2000}
        value.count, value.tunnel = Mock(return_value=4), Mock()
        return clock, value, warm

    def deny(self, clock, value, warm):
        with patch.object(checker.time, "time_ns", side_effect=lambda: clock.epoch_ms * 1_000_000), \
                patch.object(checker.time, "monotonic_ns", side_effect=lambda: clock.monotonic_ns):
            value.denied_without_dispatch(value.client_token, warm=warm)

    def diagnostic(self, value):
        evidence = value.warm_lease_evidence()
        self.assertEqual(len(evidence["warmDenialChecks"]), 1)
        encoded = json.dumps(evidence)
        for secret in (value.credential, value.admin_token, value.wrong_token, value.client_token):
            self.assertNotIn(secret, encoded)
        return evidence["warmDenialChecks"][0]

    def test_timely_headers_are_not_retimed_by_slow_post_counts(self):
        clock, value, warm = self.fixture()
        captured = clock.epoch_ms

        def count():
            clock.advance(100 if value.count.call_count == 1 else 2500)
            return 4

        value.count.side_effect = count
        value.tunnel.side_effect = lambda *args, **kwargs: clock.advance(400)
        self.deny(clock, value, warm)
        observation = self.diagnostic(value)
        self.assertTrue(observation["headersValidated"])
        self.assertTrue(observation["completed"])
        self.assertEqual(observation["failedConjuncts"], [])
        self.assertEqual(observation["connect403"]["finished"]["epochMs"], captured + 500)
        self.assertEqual(observation["postCount"]["finished"]["epochMs"], captured + 3000)
        self.assertEqual(observation["comparison"]["epochMs"], captured + 3000)
        self.assertEqual(value.warm_observations[0]["denialVerifiedAtEpochMs"], captured + 500)
        self.assertEqual(value.warm_observations[0]["denialElapsedMonotonicMs"], 500)
        self.assertEqual(value.count.call_count, 2)
        value.tunnel.assert_called_once_with(value.client_token, expected_status=403)

    def test_late_headers_fail_but_still_collect_post_counts(self):
        for delay in (2000, 2001):
            clock, value, warm = self.fixture()
            value.tunnel.side_effect = lambda *args, **kwargs: clock.advance(delay)
            with self.subTest(delay=delay), self.assertRaisesRegex(checker.CheckFailure, "captured lease expiry"):
                self.deny(clock, value, warm)
            observation = self.diagnostic(value)
            self.assertEqual(set(observation["failedConjuncts"]), {
                "wall_before_original_expiry", "monotonic_before_original_window"})
            self.assertTrue(observation["postCount"]["completed"])
            self.assertTrue(observation["conditions"]["upstream_count_unchanged"])
            self.assertTrue(observation["completed"])
            self.assertEqual(value.count.call_count, 2)
            self.assertEqual(value.warm_observations, [])

    def test_both_clock_boundaries_remain_strict_and_independent(self):
        cases = [(1999, 1999, set()), (2000, 100, {"wall_before_original_expiry"}),
            (100, 2000, {"monotonic_before_original_window"}),
            (-1, 100, {"wall_not_before_capture"}), (100, -1, {"monotonic_nonnegative"}),
            (0, 0, set())]
        for wall_delta, monotonic_delta, expected in cases:
            clock, value, warm = self.fixture()

            def headers(*args, **kwargs):
                clock.epoch_ms = warm["capturedAtEpochMs"] + wall_delta
                clock.monotonic_ns = warm["_captured_monotonic_ns"] + monotonic_delta * 1_000_000

            value.tunnel.side_effect = headers
            with self.subTest(wall_delta=wall_delta, monotonic_delta=monotonic_delta):
                if expected:
                    with self.assertRaises(checker.CheckFailure):
                        self.deny(clock, value, warm)
                else:
                    self.deny(clock, value, warm)
            self.assertEqual(set(self.diagnostic(value)["failedConjuncts"]), expected)
            self.assertEqual(len(value.warm_observations), 0 if expected else 1)

    def test_slow_pre_count_cannot_renew_the_original_window(self):
        clock, value, warm = self.fixture()

        def count():
            if value.count.call_count == 1:
                clock.advance(2001)
            return 4

        value.count.side_effect = count
        with self.assertRaisesRegex(checker.CheckFailure, "captured lease expiry"):
            self.deny(clock, value, warm)
        observation = self.diagnostic(value)
        self.assertEqual(observation["preCount"]["elapsedMonotonicNs"], 2_001_000_000)
        self.assertEqual(observation["denialDeadlineEpochMs"], warm["denialDeadlineEpochMs"])
        self.assertEqual(value.warm_observations, [])

    def test_original_health_and_scoped_minimum_are_retained(self):
        for health_ms, scoped_ms in ((1500, 5000), (5000, 1500)):
            clock, value, warm = self.fixture()
            warm["healthEarliestUnexpiredLeaseEpochMs"] = clock.epoch_ms + health_ms
            warm["scopedLeaseExpiryEpochMs"] = clock.epoch_ms + scoped_ms
            warm["denialDeadlineEpochMs"] = clock.epoch_ms + min(health_ms, scoped_ms)
            original = deepcopy(warm)
            value.tunnel.side_effect = lambda *args, **kwargs: clock.advance(1600)
            with self.subTest(health_ms=health_ms), self.assertRaises(checker.CheckFailure):
                self.deny(clock, value, warm)
            self.assertEqual(warm, original)
            observation = self.diagnostic(value)
            for key in ("healthEarliestUnexpiredLeaseEpochMs", "scopedLeaseExpiryEpochMs", "denialDeadlineEpochMs"):
                self.assertEqual(observation[key], original[key])

    def test_timely_denial_still_rejects_changed_counter(self):
        clock, value, warm = self.fixture()
        value.count.side_effect = [4, 5]
        with self.assertRaisesRegex(checker.CheckFailure, "upstream_count_unchanged"):
            self.deny(clock, value, warm)
        observation = self.diagnostic(value)
        self.assertEqual(observation["beforeCount"], 4)
        self.assertEqual(observation["afterCount"], 5)
        self.assertEqual(observation["failedConjuncts"], ["upstream_count_unchanged"])
        self.assertTrue(observation["headersValidated"])
        self.assertEqual(value.warm_observations, [])

    def test_real_count_still_checks_global_and_per_run_agreement(self):
        clock, value, warm = self.fixture()
        del value.count
        value.upstream, value.upstream_ca, value.run_id = object(), None, "synthetic-run"
        value.json_request = Mock(side_effect=[(200, {"count": number}) for number in (4, 4, 4, 5)])
        with self.assertRaisesRegex(checker.CheckFailure, "unexpected traffic"):
            self.deny(clock, value, warm)
        observation = self.diagnostic(value)
        self.assertTrue(observation["headersValidated"])
        self.assertFalse(observation["postCount"]["completed"])
        self.assertEqual(observation["failedConjuncts"], ["postCount_completed"])
        self.assertEqual(value.json_request.call_count, 4)
        self.assertEqual(value.warm_observations, [])

    def test_partial_phase_failure_retains_only_safe_timing(self):
        for phase in ("preCount", "connect403", "postCount"):
            clock, value, warm = self.fixture()

            def fail():
                clock.advance(25)
                raise RuntimeError(value.credential)

            if phase == "connect403":
                value.tunnel.side_effect = lambda *args, **kwargs: fail()
            else:
                def count():
                    if phase == "preCount" or value.count.call_count == 2:
                        return fail()
                    return 4
                value.count.side_effect = count
            with self.subTest(phase=phase), self.assertRaises(RuntimeError):
                self.deny(clock, value, warm)
            observation = self.diagnostic(value)
            self.assertFalse(observation["completed"])
            self.assertEqual(observation["headersValidated"], phase == "postCount")
            self.assertFalse(observation[phase]["completed"])
            self.assertEqual(observation[phase]["elapsedMonotonicNs"], 25_000_000)
            self.assertEqual(observation["failedConjuncts"], [phase + "_completed"])
            self.assertEqual(value.count.call_count, 2 if phase == "postCount" else 1)
            self.assertEqual(value.warm_observations, [])

    def test_inherited_tunnel_requires_complete_expected_headers(self):
        for response in (b"HTTP/1.1 200 OK\r\n\r\n", b"HTTP/1.1 403 Forbidden\r\n", None):
            clock, value, warm = self.fixture()
            del value.tunnel
            raw = Mock()
            if response is None:
                raw.recv.side_effect = TimeoutError(value.credential)
            else:
                raw.recv.side_effect = [bytes([byte]) for byte in response] + [b""]
            value.proxy, value.proxy_ca, value.timeout = Mock(), None, Mock(return_value=1)
            value.proxy.connect.return_value = raw
            with self.subTest(response=response), self.assertRaises((checker.CheckFailure, TimeoutError)):
                self.deny(clock, value, warm)
            observation = self.diagnostic(value)
            self.assertFalse(observation["headersValidated"])
            self.assertEqual(observation["failedConjuncts"], ["connect403_completed"])
            self.assertNotIn("postCount", observation)
            self.assertEqual(value.warm_observations, [])
            raw.close.assert_called_once()

    def test_warm_none_preserves_original_denial_and_counter_behavior(self):
        for changed in (False, True):
            clock, value, _ = self.fixture()
            value.count.side_effect = [4, 5 if changed else 4]
            if changed:
                with self.assertRaises(checker.CheckFailure):
                    self.deny(clock, value, None)
            else:
                self.deny(clock, value, None)
            self.assertEqual(value.count.call_count, 2)
            value.tunnel.assert_called_once_with(value.client_token, expected_status=403)
            self.assertEqual(value.warm_denial_checks, [])

    def test_failure_result_keeps_partial_denial_diagnostics(self):
        clock, value, warm = self.fixture()
        value.tunnel.side_effect = RuntimeError(value.credential)
        value.run = lambda: self.deny(clock, value, warm)
        args = SimpleNamespace(expected_binary_sha256=value.args.expected_binary_sha256,
            timeout_seconds=120, fixture_marker_file=None, run_claim_file=None)
        with patch.object(checker, "claim_fixture"), patch.object(checker, "OperatorCatalogCheck", return_value=value), \
                patch.object(checker.features, "safe_evidence", side_effect=RuntimeError("unavailable")):
            result = checker.run_checks(args)
        self.assertFalse(result["ok"])
        self.assertTrue(result["safeEvidenceUnavailable"])
        self.assertEqual(result["error"], "RuntimeError")
        self.assertEqual(result["warmDenialChecks"][0]["failedConjuncts"], ["connect403_completed"])
        self.assertNotIn(value.credential, json.dumps(result))

    def test_diagnostics_have_two_record_and_shared_16k_bounds(self):
        clock, value, warm = self.fixture()
        self.deny(clock, value, deepcopy(warm))
        self.deny(clock, value, deepcopy(warm))
        self.assertLess(len(json.dumps(value.warm_lease_evidence()).encode("utf-8")), 16384)
        with self.assertRaisesRegex(checker.CheckFailure, "observation bound"):
            self.deny(clock, value, deepcopy(warm))
        self.assertEqual(value.tunnel.call_count, 2)
        value.warm_denial_checks.append({})
        with self.assertRaisesRegex(checker.CheckFailure, "count exceeds bound"):
            value.warm_lease_evidence()
        value.warm_denial_checks.pop()
        value.warm_lease_checks = [{"bounded_test_padding": "x" * 16384}]
        with self.assertRaisesRegex(checker.CheckFailure, "evidence exceeds bound"):
            value.warm_lease_evidence()
        value.warm_lease_checks = []
        value.warm_denial_checks[0]["injected_test_value"] = value.client_token
        with self.assertRaises(checker.CheckFailure):
            value.warm_lease_evidence()


if __name__ == "__main__":
    unittest.main()
