#!/usr/bin/env python3
"""Focused policy controls; no signed admission, SQL, clocks or activation."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from serverware import authority_challenge_policy as policy
from serverware import authority_query_read_work as measured


BOUNDS = {
    "globalLiveMaximum": (100, 1_000_000),
    "userLiveMaximum": (4, 10_000),
    "userRateMaximum": (10, 100_000),
    "globalRateMaximum": (100, 1_000_000),
    "rateWindowSeconds": (10, 3600),
    "terminalRetentionSeconds": (60, 604_800),
    "maximumRetained": (100, 1_000_000),
}


def selected():
    return {"schema": policy.SCHEMA, **{name: low for name, (low, _high) in BOUNDS.items()}}


def meter(**limits):
    return measured._ValidationWork(measured.QueryReadValidationLimits(**limits))


class ChallengePolicyTests(unittest.TestCase):
    def test_exact_bounds_and_detached_policy(self):
        self.assertEqual(policy.FIELD, "webauthnChallengeMaintenance")
        self.assertEqual(policy.SCHEMA, "serverware.policyAuthorityChallengeMaintenancePolicy/v1")
        for field, (low, high) in BOUNDS.items():
            for boundary in (low, high):
                with self.subTest(field=field, boundary=boundary):
                    original = selected()
                    original[field] = boundary
                    work = meter()
                    result = policy.validate_policy(original, work=work)
                    self.assertEqual(result, original)
                    self.assertIsNot(result, original)
                    original[field] = low - 1
                    self.assertEqual(result[field], boundary)
                    self.assertGreater(work.input_bytes, 0)
                    self.assertGreater(work.json_nodes, 0)

    def test_outside_each_bound_is_refused(self):
        for field, (low, high) in BOUNDS.items():
            for rejected in (low - 1, high + 1, -(2**63), 2**128):
                with self.subTest(field=field, rejected=rejected):
                    with self.assertRaises(policy.ChallengePolicyError):
                        policy.validate_policy(dict(selected(), **{field: rejected}), work=meter())

    def test_numeric_aliases_are_refused(self):
        class Integer(int):
            pass
        for field, (low, _high) in BOUNDS.items():
            for rejected in (True, False, float(low), str(low), Integer(low), None, [low]):
                with self.subTest(field=field, rejected_type=type(rejected).__name__):
                    with self.assertRaises(policy.ChallengePolicyError):
                        policy.validate_policy(dict(selected(), **{field: rejected}), work=meter())

    def test_closed_fields_schema_and_exact_containers(self):
        self.assertIsNone(policy._shape(selected()))
        class Dictionary(dict):
            pass
        class String(str):
            pass
        invalid = [None, [], Dictionary(selected()), {},
            dict(selected(), schema="serverware.policyAuthorityChallengeMaintenancePolicy/v2"),
            dict(selected(), schema=String(policy.SCHEMA)),
            dict(selected(), schema=policy.SCHEMA + "x"),
            dict(selected(), expiresAtUnixNanos=1)]
        for name in selected():
            missing = selected()
            del missing[name]
            invalid.append(missing)
        alias = selected()
        del alias["maximumRetained"]
        alias[String("maximumRetained")] = 100
        invalid.append(alias)
        unknown = selected()
        del unknown["maximumRetained"]
        unknown["unknown"] = 100
        invalid.append(unknown)
        for value in invalid:
            with self.subTest(value_type=type(value).__name__):
                with self.assertRaises(policy.ChallengePolicyError):
                    policy.validate_policy(value, work=meter())
                with self.assertRaises(policy.ChallengePolicyError):
                    policy._shape(value)

    def test_context_uses_only_validated_retention_fields(self):
        for seconds in (60, 604_800):
            original = dict(selected(), terminalRetentionSeconds=seconds, maximumRetained=654321)
            result = policy.maintenance_context(original, work=meter())
            self.assertEqual(result, {"retentionUs": seconds * 1_000_000, "maximumRetained": 654321})
            original["terminalRetentionSeconds"] = 0
            self.assertEqual(result["retentionUs"], seconds * 1_000_000)
        with self.assertRaises(policy.ChallengePolicyError):
            policy.maintenance_context({"retentionUs": 60_000_000, "maximumRetained": 100}, work=meter())
        with self.assertRaises(policy.ChallengePolicyError):
            policy.maintenance_context(dict(selected(), globalLiveMaximum=True), work=meter())

    def test_original_work_budget_is_required_and_never_replaced(self):
        class OtherWork(measured._ValidationWork):
            pass
        for invalid in (None, object(), OtherWork(measured.QueryReadValidationLimits())):
            with self.assertRaises(policy.ChallengePolicyError):
                policy.validate_policy(selected(), work=invalid)
        constrained = meter(max_input_bytes=1)
        with self.assertRaises(measured.QueryReadWorkError):
            policy.validate_policy(selected(), work=constrained)
        constrained = meter(max_json_nodes=1)
        with self.assertRaises(measured.QueryReadWorkError):
            policy.maintenance_context(selected(), work=constrained)
        shared = meter(max_input_bytes=2048)
        original_limits = shared.limits
        policy.validate_policy(selected(), work=shared)
        before = shared.metrics
        policy.maintenance_context(selected(), work=shared)
        self.assertGreater(shared.input_bytes, before.input_bytes)
        self.assertGreater(shared.json_nodes, before.json_nodes)
        self.assertIs(shared.limits, original_limits)
        with self.assertRaises(measured.QueryReadWorkError):
            for _ in range(10):
                policy.validate_policy(selected(), work=shared)


if __name__ == "__main__":
    unittest.main()
