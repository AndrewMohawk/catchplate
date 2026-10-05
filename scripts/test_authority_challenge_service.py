"""Owned live-service joins, not measured launch, transport or SQL acceptance.

These controls exercise actual inert ownership/validation and inspect fixed
caller composition. They never substitute a successful producer/replay DTO.
"""
from __future__ import annotations

import ast
import inspect
from pathlib import Path
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from serverware import authority_challenge_service as source
from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork
from test_authority_challenge_manifest import context
from test_authority_challenge_plan_request import fixture


def work(**changes):
    return _ValidationWork(QueryReadValidationLimits(**changes))


def anchors():
    maintenance = source.plan.maintenance
    selected = context()
    root = maintenance._root(selected["primaryRoot"])
    meter = work()
    heads = tuple(maintenance._head(value, maintenance.projection.profile_for(value["indexId"]),
        root, meter) for value in selected["indexHeads"])
    return root, heads


class ChallengeServiceControls(unittest.TestCase):
    def test_exact_original_anchor_ownership_and_actual_source_profiles(self):
        root, heads = anchors()
        meter = work()
        copied_root, copied_heads = source._anchors(root, heads, meter)
        self.assertEqual(copied_root, root)
        self.assertEqual(copied_heads, heads)
        self.assertIsNot(copied_root, root)
        self.assertIsNot(copied_heads, heads)
        self.assertTrue(all(actual is not previous and actual.index_root is not previous.index_root
            for actual, previous in zip(copied_heads, heads, strict=True)))
        object.__setattr__(root, "root_revision", 99)
        object.__setattr__(heads[0].index_root, "count", 123)
        self.assertEqual(copied_root.root_revision, 0)
        self.assertEqual(copied_heads[0].index_root.count, 0)
        self.assertGreater(meter.hash_work, 64)
        self.assertGreater(meter.input_bytes, 0)
        self.assertGreater(meter.json_nodes, 0)

    def test_anchor_roster_scalar_types_and_original_remaining_work(self):
        root, heads = anchors()
        for selected in (list(heads), heads[:-1], heads[::-1]):
            with self.assertRaises(ValueError):
                source._anchors(root, selected, work())
        for field, value in (("root_revision", True), ("table", "other")):
            selected, roster = anchors()
            object.__setattr__(selected, field, value)
            with self.assertRaises(ValueError):
                source._anchors(selected, roster, work())
        root, heads = anchors()
        object.__setattr__(heads[0], "projection_digest", "sha256:" + "0" * 64)
        with self.assertRaises(ValueError):
            source._anchors(root, heads, work())
        root, heads = anchors()
        meter = work(max_hashes=1)
        original_limits = meter.limits
        with self.assertRaises(ValueError):
            source._anchors(root, heads, meter)
        self.assertIs(meter.limits, original_limits)

    def test_unsupported_production_refuses_before_role_fd_or_key_callbacks(self):
        root, heads = anchors()
        raw = source.plan.requests.commitment.canonical_bytes(fixture("webauthn.challenge.create"))
        with mock.patch.object(source.pages, "_caller_on_work",
                side_effect=AssertionError("measured page configuration reached")):
            for request in (raw, b"{}", bytearray(raw)):
                with self.assertRaises(ValueError):
                    source._produce_on_work(object(), request_bytes=request, primary_root=root,
                        index_heads=heads, live_window=None, original_deadline_ns=1,
                        check=lambda: None, work=work())

    def test_replay_rejects_nonoriginal_frames_or_context_before_configuration(self):
        arguments = dict(envelope_bytes=b"{}", request_bytes=b"{}", manifest_bytes=b"{}",
            context=context(), before_vector_bytes=b"{}", now_epoch_ns=5_000_000_000,
            deadline_epoch_ns=6_000_000_000, live_window=None, check=lambda stage: None)
        with mock.patch.object(source.pages, "_caller_on_work",
                side_effect=AssertionError("measured page configuration reached")):
            for name, value in (("before_vector_bytes", bytearray(b"{}")),
                    ("now_epoch_ns", True), ("deadline_epoch_ns", 1)):
                with self.subTest(name=name), self.assertRaises(ValueError):
                    source._verify_vector_on_work(object(), **(arguments | {name: value}), work=work())
            selected = context()
            selected["operation"] = "webauthn.challenge.create"
            with self.assertRaises(ValueError):
                source._verify_vector_on_work(object(), **(arguments | {"context": selected}), work=work())

    def test_live_callers_use_real_retention_and_replay_without_override_parameters(self):
        produce = inspect.getsource(source._produce_on_work)
        replay = inspect.getsource(source._verify_vector_on_work)
        self.assertLess(produce.index("_anchors("), produce.index("pages._caller_on_work("))
        self.assertLess(produce.index("capture_request("), produce.index("pages._caller_on_work("))
        self.assertIn("MaintenancePlanner.produce(producer", produce)
        self.assertIn("pages._PageCaller.retain(caller, *arguments)", produce)
        self.assertIn("mapping.MaintenanceVerifier.verify_vector(verifier", replay)
        self.assertIn("pages._PageCaller.reader(caller, context=owned", replay)
        self.assertIn("now_epoch_ns=now_epoch_ns, deadline_epoch_ns=deadline_epoch_ns", replay)
        self.assertNotIn("now_epoch_ns=window[0]", replay)
        for method in (source._produce_on_work, source._verify_vector_on_work):
            parameters = inspect.signature(method).parameters
            self.assertFalse({"retain_page", "read_original", "apply_mutation", "observe_effect",
                "observation", "result", "planner_private_key", "configuration"} & set(parameters))
        for expression in ("lambda: check(stage)", "stage.work", "stage.check()"):
            self.assertIn(expression, replay)

    def test_real_service_methods_forward_only_exact_original_inputs(self):
        root = Path(__file__).resolve().parents[1]
        tree = ast.parse((root / "serverware/authority_service.py").read_text())
        owner = next(node for node in tree.body if isinstance(node, ast.ClassDef)
            and node.name == "AuthorityProcess")
        expected = {"_produce_challenge_maintenance": "challenges._produce_on_work",
            "_verify_challenge_maintenance_vector": "challenges._verify_vector_on_work"}
        for name, target in expected.items():
            method = next(node for node in owner.body if isinstance(node, ast.FunctionDef) and node.name == name)
            calls = [node for node in ast.walk(method) if isinstance(node, ast.Call)]
            self.assertEqual(len(calls), 1)
            self.assertEqual(ast.unparse(calls[0].func), target)
            self.assertEqual(ast.unparse(calls[0].args[0]), "self")
            self.assertTrue(all(keyword.arg == ast.unparse(keyword.value)
                for keyword in calls[0].keywords))

    def test_actual_receiver_epoch_must_remain_within_unchanged_original_interval(self):
        interval = dict(issuedAtEpochNs=5_000_000_000, expiresAtEpochNs=6_000_000_000)
        expected = dict(context=dict(cutoffUs=5_000_000), policy=dict(nowEpochNs=5_000_000_000,
            deadlineEpochNs=6_000_000_000, maximumPlanAgeNs=2_000_000_000,
            maximumClockSkewNs=0))
        # A later, narrower receiving window is legitimate. The original
        # issued time is not replaced by this new opening sample.
        window = (5_500_000_000, 100_000_000, 100_000_000, 5_900_000_000,
            500_000_000, 2_000_000_000, 0)
        with mock.patch.object(source.plan.clock.time, "monotonic_ns", return_value=200_000_000), \
                mock.patch.object(source.plan.clock.time, "time_ns", return_value=5_600_000_000):
            meter = work()
            before = meter.metrics
            source._live_original(interval, expected, window, meter)
            self.assertEqual(meter.metrics, before)
        # A receiving window extending past original expiry must not extend
        # the signed parent. Real clock samples remain internally consistent.
        longer = (5_500_000_000, 100_000_000, 100_000_000, 7_000_000_000,
            1_600_000_000, 2_000_000_000, 0)
        with mock.patch.object(source.plan.clock.time, "monotonic_ns", return_value=700_000_000), \
                mock.patch.object(source.plan.clock.time, "time_ns", return_value=6_100_000_000):
            with self.assertRaises(ValueError):
                source._live_original(interval, expected, longer, work())
        body = inspect.getsource(source._verify_vector_on_work)
        self.assertEqual(body.count("_live_original(interval, expected, window, stage.work)"), 2)
        self.assertEqual(body.count("_live_original(interval, expected, window, work)"), 2)
        self.assertIn("plan._same(result.original_interval", body)


if __name__ == "__main__":
    unittest.main()
