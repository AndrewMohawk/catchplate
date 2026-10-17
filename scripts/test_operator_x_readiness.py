#!/usr/bin/env python3
"""Inert X readiness boundary tests, not gate/provider/lifecycle acceptance.

The snapshot and existing health transport are explicit doubles. The companion
manifest suite exercises actual retained SQLite/publication projection.
"""
from contextlib import ExitStack, contextmanager
from copy import deepcopy
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import catchplate
from catchplate import operator_publication as publication, operator_x_readiness as readiness

POLICY = "sha256:" + "1" * 64
BINARY = "sha256:" + "2" * 64
IDENTITY = {"operation": {"operation_id": "11111111-2222-4333-8444-555555555555",
    "owner_id": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", "config_version": 1},
    "profile_binding_digest": "sha256:" + "3" * 64,
    "effective_settings_digest": "sha256:" + "4" * 64}
DESCRIPTOR = {"schema": "catchplate.operatorXPostGate/v1", "adapter": "x.post.v1", "operation": "tweets.write"}
QUOTA_DESCRIPTOR = {"schema": "catchplate.operatorXPostAttemptQuota/v1", "field": "daily_post_attempt_limit",
    "period": "utc_day", "scope": "verified_x_account", "unit": "posting_attempt",
    "minimum": 1, "maximum": 1_000_000_000}


@contextmanager
def owners(**modules):
    with ExitStack() as stack:
        stack.enter_context(patch.dict(sys.modules, {"catchplate." + name: value for name, value in modules.items()}))
        for name, value in modules.items():
            stack.enter_context(patch.object(catchplate, name, value, create=True))
        yield


def snapshot():
    return {"policy_hash": POLICY, "managed_x": deepcopy(IDENTITY),
        "expected_binary_digest": BINARY, "destination_allowed": True}


def health():
    return {"ok": True, "policy_hash": POLICY, "data_plane_binary_digest": BINARY,
        "policy_shadow": {"managed_x": deepcopy(IDENTITY)}, "operator_x_post": dict(DESCRIPTOR)}


class ReadinessTests(unittest.TestCase):
    def observe(self, received, *, before=None, after=None, enabled=True, reused=False, quota=False):
        before = snapshot() if before is None else before
        if quota and "quota_store_ready" not in before:
            before = {**before, "quota_store_ready": True}
        after = deepcopy(before) if after is None else after
        reader = Mock(return_value=received)
        with owners(operator_x_admission=SimpleNamespace(enabled=lambda: enabled),
                operator_demo_store=SimpleNamespace(loaded_gate_status=reader)), \
                patch.object(readiness, "_snapshot", side_effect=[before, after]) as snapshots:
            if quota:
                result = readiness.observe_health_quota(received) if reused else readiness.observe_quota()
            else:
                result = readiness.observe_health(received) if reused else readiness.observe()
        self.assertEqual(set(result), {"ready", "policy_hash", "loaded_policy_hash", "managed_x"}
            | ({"daily_quota_available"} if quota else set()))
        return result, reader, snapshots

    def test_exact_configured_pair_uses_one_request_catalog_reuses_none(self):
        result, reader, snapshots = self.observe(health())
        self.assertTrue(result["ready"])
        self.assertEqual(reader.call_count, 1)
        self.assertEqual(snapshots.call_count, 2)
        result, reader, snapshots = self.observe(health(), reused=True)
        self.assertTrue(result["ready"])
        reader.assert_not_called()
        self.assertEqual(snapshots.call_count, 2)

    def test_disabled_missing_health_and_owned_context_never_fetch(self):
        for options in ({"enabled": False}, {"reused": True}):
            result, reader, snapshots = self.observe(None, **options)
            self.assertFalse(result["ready"])
            reader.assert_not_called()
            snapshots.assert_not_called()
        for attribute in ("depth", "bootstrap"):
            with patch.object(publication._state, attribute, 1, create=True):
                result, reader, snapshots = self.observe(health())
            self.assertFalse(result["ready"])
            reader.assert_not_called()
            snapshots.assert_not_called()

    def test_unconfigured_or_unapproved_destination_never_ready(self):
        before, received = snapshot(), health()
        before["managed_x"].update(operation=None, profile_binding_digest=None)
        received["policy_shadow"]["managed_x"] = deepcopy(before["managed_x"])
        self.assertFalse(self.observe(received, before=before)[0]["ready"])
        before = snapshot()
        before["destination_allowed"] = False
        self.assertFalse(self.observe(health(), before=before)[0]["ready"])

    def test_wrong_current_policy_binary_descriptor_and_changed_snapshot(self):
        for key in ("policy_hash", "data_plane_binary_digest"):
            self.assertFalse(self.observe({**health(), key: "sha256:" + "9" * 64})[0]["ready"])
        for descriptor in (None, {}, True, {**DESCRIPTOR, "extra": False},
                {**DESCRIPTOR, "adapter": "x.v2"}, {**DESCRIPTOR, "operation": "x.username.read"}):
            self.assertFalse(self.observe({**health(), "operator_x_post": descriptor})[0]["ready"])
        for key in ("policy_hash", "expected_binary_digest", "destination_allowed"):
            after = snapshot()
            after[key] = False if key == "destination_allowed" else "sha256:" + "9" * 64
            self.assertFalse(self.observe(health(), after=after)[0]["ready"])

    def test_closed_identity_and_scalar_types(self):
        for identity in (None, {}, True, {**IDENTITY, "extra": False},
                {**IDENTITY, "operation": None},
                {**IDENTITY, "profile_binding_digest": "3" * 64}):
            received = health()
            received["policy_shadow"]["managed_x"] = identity
            self.assertFalse(self.observe(received)[0]["ready"])
        for key, value in (("config_version", True), ("config_version", 2),
                ("owner_id", "AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE"),
                ("operation_id", "not-a-uuid")):
            received = health()
            received["policy_shadow"]["managed_x"]["operation"][key] = value
            self.assertFalse(self.observe(received)[0]["ready"])

    def test_failed_observation_does_not_reflect_internal_exception(self):
        with owners(operator_x_admission=SimpleNamespace(enabled=lambda: True)), \
                patch.object(readiness, "_snapshot", side_effect=RuntimeError("private-canary-path")):
            result = readiness.observe()
        self.assertFalse(result["ready"])
        self.assertNotIn("private-canary", repr(result))

    def test_capture_is_detached_and_writer_rechecks_without_network(self):
        observation = self.observe(health())[0]
        with patch.object(readiness, "observe", return_value=observation):
            captured = readiness.capture_start()
        captured["managed_x"]["operation"]["config_version"] = 2
        self.assertEqual(observation["managed_x"]["operation"]["config_version"], 1)
        connection = object()
        with patch.object(readiness, "_local", return_value=snapshot()) as local:
            readiness.require_start(connection, observation)
        local.assert_called_once_with(connection, query_only=False)
        class Conflict(RuntimeError):
            pass
        for changes in ({"destination_allowed": False}, {"policy_hash": "sha256:" + "9" * 64}):
            with owners(operator_catalog_schema=SimpleNamespace(CatalogConflict=Conflict)), \
                    patch.object(readiness, "_local", return_value={**snapshot(), **changes}):
                with self.assertRaises(Conflict):
                    readiness.require_start(connection, observation)

    def test_quota_mode_joins_exact_same_health_without_changing_consent_contract(self):
        received = {**health(), "operator_x_post_attempt_quota": dict(QUOTA_DESCRIPTOR)}
        for reused in (False, True):
            result, reader, snapshots = self.observe(received, quota=True, reused=reused)
            self.assertTrue(result["ready"])
            self.assertTrue(result["daily_quota_available"])
            self.assertEqual(reader.call_count, 0 if reused else 1)
            self.assertEqual(snapshots.call_count, 2)
            self.assertTrue(all(call.kwargs == {"quota": True} for call in snapshots.call_args_list))
        legacy, reader, snapshots = self.observe(received)
        self.assertTrue(legacy["ready"])
        self.assertNotIn("daily_quota_available", legacy)
        self.assertTrue(all(call.kwargs == {} for call in snapshots.call_args_list))

    def test_quota_marker_and_durable_storage_cannot_be_inferred_from_post_support(self):
        for descriptor in (None, {}, {**QUOTA_DESCRIPTOR, "minimum": True},
                {**QUOTA_DESCRIPTOR, "maximum": 1e9}, {**QUOTA_DESCRIPTOR, "scope": "credential"},
                {**QUOTA_DESCRIPTOR, "extra": False}):
            result, _, _ = self.observe({**health(), "operator_x_post_attempt_quota": descriptor}, quota=True)
            self.assertTrue(result["ready"])
            self.assertFalse(result["daily_quota_available"])
        received = {**health(), "operator_x_post_attempt_quota": dict(QUOTA_DESCRIPTOR)}
        for marker in (False, None, 1):
            result, _, _ = self.observe(received, quota=True, before={**snapshot(), "quota_store_ready": marker})
            self.assertTrue(result["ready"])
            self.assertFalse(result["daily_quota_available"])
        for after in ({**snapshot(), "quota_store_ready": False},
                {**snapshot(), "quota_store_ready": True, "policy_hash": "sha256:" + "9" * 64}):
            result, _, _ = self.observe(received, quota=True, after=after)
            self.assertFalse(result["ready"])
            self.assertFalse(result["daily_quota_available"])

    def test_quota_marker_never_bypasses_original_binary_policy_identity_and_origin(self):
        received = {**health(), "operator_x_post_attempt_quota": dict(QUOTA_DESCRIPTOR)}
        for key in ("policy_hash", "data_plane_binary_digest"):
            result, _, _ = self.observe({**received, key: "sha256:" + "9" * 64}, quota=True)
            self.assertFalse(result["daily_quota_available"])
        for key, value in (("destination_allowed", False), ("managed_x", {
                **IDENTITY, "operation": None, "profile_binding_digest": None})):
            result, _, _ = self.observe(received, quota=True, before={**snapshot(), key: value})
            self.assertFalse(result["daily_quota_available"])
        result, reader, snapshots = self.observe(None, reused=True, quota=True)
        self.assertFalse(result["daily_quota_available"])
        reader.assert_not_called()
        snapshots.assert_not_called()

    def test_writer_quota_recheck_is_read_only_and_never_initializes_or_fetches(self):
        observation = self.observe({**health(), "operator_x_post_attempt_quota": dict(QUOTA_DESCRIPTOR)},
            quota=True)[0]
        connection = object()
        require_ready = Mock()
        with owners(operator_x_quota=SimpleNamespace(require_ready=require_ready)), \
                patch.object(readiness, "_local", return_value=snapshot()) as local, \
                patch.object(readiness, "observe_quota", side_effect=AssertionError("no HTTP in writer")):
            readiness.require_quota_start(connection, observation)
        local.assert_called_once_with(connection, query_only=False)
        require_ready.assert_called_once_with(connection)
        from catchplate.operator_catalog_schema import CatalogConflict
        for changed in ({**observation, "daily_quota_available": False},
                {**observation, "daily_quota_available": 1}, {**observation, "extra": False},
                {**observation, "loaded_policy_hash": "sha256:" + "9" * 64}):
            require_ready.reset_mock()
            with owners(operator_x_quota=SimpleNamespace(require_ready=require_ready)), \
                    patch.object(readiness, "_local", return_value=snapshot()), self.assertRaises(CatalogConflict):
                readiness.require_quota_start(connection, changed)
            require_ready.assert_not_called()
        with owners(operator_x_quota=SimpleNamespace(require_ready=Mock(side_effect=RuntimeError("private-canary")))), \
                patch.object(readiness, "_local", return_value=snapshot()):
            with self.assertRaises(CatalogConflict) as failure:
                readiness.require_quota_start(connection, observation)
            self.assertNotIn("private-canary", str(failure.exception))
            self.assertFalse(readiness._quota_store_ready(connection))


if __name__ == "__main__":
    unittest.main(verbosity=2)
