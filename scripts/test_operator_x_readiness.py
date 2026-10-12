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
import serverware
from serverware import operator_publication as publication, operator_x_readiness as readiness

POLICY = "sha256:" + "1" * 64
BINARY = "sha256:" + "2" * 64
IDENTITY = {"operation": {"operation_id": "11111111-2222-4333-8444-555555555555",
    "owner_id": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", "config_version": 1},
    "profile_binding_digest": "sha256:" + "3" * 64,
    "effective_settings_digest": "sha256:" + "4" * 64}
DESCRIPTOR = {"schema": "serverware.operatorXPostGate/v1", "adapter": "x.post.v1", "operation": "tweets.write"}


@contextmanager
def owners(**modules):
    with ExitStack() as stack:
        stack.enter_context(patch.dict(sys.modules, {"serverware." + name: value for name, value in modules.items()}))
        for name, value in modules.items():
            stack.enter_context(patch.object(serverware, name, value, create=True))
        yield


def snapshot():
    return {"policy_hash": POLICY, "managed_x": deepcopy(IDENTITY),
        "expected_binary_digest": BINARY, "destination_allowed": True}


def health():
    return {"ok": True, "policy_hash": POLICY, "data_plane_binary_digest": BINARY,
        "policy_shadow": {"managed_x": deepcopy(IDENTITY)}, "operator_x_post": dict(DESCRIPTOR)}


class ReadinessTests(unittest.TestCase):
    def observe(self, received, *, before=None, after=None, enabled=True, reused=False):
        before = snapshot() if before is None else before
        after = deepcopy(before) if after is None else after
        reader = Mock(return_value=received)
        with owners(operator_x_admission=SimpleNamespace(enabled=lambda: enabled),
                operator_demo_store=SimpleNamespace(loaded_gate_status=reader)), \
                patch.object(readiness, "_snapshot", side_effect=[before, after]) as snapshots:
            result = readiness.observe_health(received) if reused else readiness.observe()
        self.assertEqual(set(result), {"ready", "policy_hash", "loaded_policy_hash", "managed_x"})
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
