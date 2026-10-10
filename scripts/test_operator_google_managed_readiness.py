#!/usr/bin/env python3
"""Inert managed readiness classifier/reader tests, not deployment acceptance.

Snapshots and gate HTTP are synthetic. These checks do not bootstrap the app,
open a database/socket, or prove real publication-lock/activation integration;
the separate connected suite owns that evidence. Production reader functions
are AST-loaded to avoid importing configured application modules in this suite.
"""
from __future__ import annotations

import ast
from contextlib import ExitStack, contextmanager
from copy import deepcopy
import http.client
import json
from pathlib import Path
import re
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import serverware
from serverware import operator_google_managed_readiness as readiness
from serverware import operator_publication as publication

POLICY = "sha256:" + "1" * 64
BINARY = "sha256:" + "2" * 64
IDENTITY = {"operation": {"operation_id": "11111111-2222-4333-8444-555555555555",
    "owner_id": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", "config_version": 1},
    "profile_binding_digest": "sha256:" + "3" * 64,
    "effective_settings_digest": "sha256:" + "4" * 64}


def snapshot():
    return {"policy_hash": POLICY, "managed_google": deepcopy(IDENTITY), "expected_binary_digest": BINARY}


def health():
    return {"ok": True, "policy_hash": POLICY, "data_plane_binary_digest": BINARY,
        "policy_shadow": {"managed_google": deepcopy(IDENTITY)}}


@contextmanager
def owners(**modules):
    """Explicit inert import seams; no configured owner is executed."""
    with ExitStack() as stack:
        stack.enter_context(patch.dict(sys.modules, {"serverware." + name: value for name, value in modules.items()}))
        for name, value in modules.items():
            stack.enter_context(patch.object(serverware, name, value, create=True))
        yield


class ReadinessTests(unittest.TestCase):
    def observe(self, received=None, *, before=None, after=None, enabled=True, require_x=False):
        before = snapshot() if before is None else before
        after = deepcopy(before) if after is None else after
        reader = Mock(return_value=health() if received is None else received)
        with owners(operator_google_managed_config=SimpleNamespace(enabled=lambda: enabled),
                operator_demo_store=SimpleNamespace(loaded_gate_status=reader)), \
                patch.object(readiness, "_snapshot", side_effect=[before, after]) as snapshots:
            result = readiness.observe_x() if require_x else readiness.observe()
        self.assertEqual(set(result), {"ready", "policy_hash", "loaded_policy_hash", "managed_google"})
        return result, reader, snapshots

    def test_x_feature_is_bound_to_the_same_managed_gate_observation(self):
        descriptor = {"schema": "serverware.operatorXAppReadGate/v1",
            "adapter": "x.app_read.v1", "operation": "x.username.read"}
        received = {**health(), "operator_x_app_read": descriptor}
        result, reader, snapshots = self.observe(received, require_x=True)
        self.assertTrue(result["ready"])
        self.assertEqual(reader.call_count, 1)
        self.assertEqual(snapshots.call_count, 2)
        for changes in ({"data_plane_binary_digest": "sha256:" + "9" * 64},
                {"policy_hash": "sha256:" + "9" * 64}):
            result, reader, _ = self.observe({**received, **changes}, require_x=True)
            self.assertFalse(result["ready"])
            self.assertEqual(reader.call_count, 1)
        after = snapshot()
        after["expected_binary_digest"] = "sha256:" + "9" * 64
        self.assertFalse(self.observe(received, after=after, require_x=True)[0]["ready"])

    def test_missing_or_malformed_x_feature_does_not_change_legacy_readiness(self):
        descriptor = {"schema": "serverware.operatorXAppReadGate/v1",
            "adapter": "x.app_read.v1", "operation": "x.username.read"}
        for marker in (None, {}, True, {**descriptor, "extra": True},
                {**descriptor, "schema": "old"}, {**descriptor, "operation": "x.write"},
                {**descriptor, "adapter": "generic.rest"}):
            received = {**health(), "operator_x_app_read": marker}
            result, reader, snapshots = self.observe(received, require_x=True)
            self.assertFalse(result["ready"])
            self.assertEqual(reader.call_count, 1)
            self.assertEqual(snapshots.call_count, 1)
            self.assertTrue(self.observe(received)[0]["ready"])
        self.assertFalse(self.observe(health(), require_x=True)[0]["ready"])

    def test_exact_pair_and_unconfigured_pair(self):
        result, reader, snapshots = self.observe()
        self.assertTrue(result["ready"])
        self.assertEqual(result["managed_google"], IDENTITY)
        self.assertEqual(reader.call_count, 1)
        self.assertEqual(snapshots.call_count, 2)
        before, received = snapshot(), health()
        before["managed_google"].update(operation=None, profile_binding_digest=None)
        received["policy_shadow"]["managed_google"] = deepcopy(before["managed_google"])
        self.assertTrue(self.observe(received, before=before)[0]["ready"])

    def test_wrong_policy_binary_operation_profile_and_settings_refused(self):
        mutations = (
            lambda value: value.update(policy_hash="sha256:" + "9" * 64),
            lambda value: value.update(data_plane_binary_digest="sha256:" + "9" * 64),
            lambda value: value["policy_shadow"]["managed_google"]["operation"].update(config_version=2),
            lambda value: value["policy_shadow"]["managed_google"].update(profile_binding_digest="sha256:" + "9" * 64),
            lambda value: value["policy_shadow"]["managed_google"].update(effective_settings_digest="sha256:" + "9" * 64),
        )
        for mutate in mutations:
            received = health()
            mutate(received)
            self.assertFalse(self.observe(received)[0]["ready"])

    def test_missing_or_malformed_managed_identity_never_falls_back(self):
        for malformed in (None, {}, True, {**IDENTITY, "extra": False},
                {**IDENTITY, "operation": {**IDENTITY["operation"], "config_version": True}},
                {**IDENTITY, "operation": {**IDENTITY["operation"], "config_version": 17}},
                {**IDENTITY, "operation": None}):
            received = health()
            received["policy_shadow"]["managed_google"] = malformed
            self.assertFalse(self.observe(received)[0]["ready"])
        received = health()
        del received["policy_shadow"]["managed_google"]
        self.assertFalse(self.observe(received)[0]["ready"])

    def test_snapshot_change_during_request_refuses_readiness(self):
        for key in ("policy_hash", "expected_binary_digest"):
            after = snapshot()
            after[key] = "sha256:" + "9" * 64
            self.assertFalse(self.observe(after=after)[0]["ready"])
        after = snapshot()
        after["managed_google"]["effective_settings_digest"] = "sha256:" + "9" * 64
        self.assertFalse(self.observe(after=after)[0]["ready"])

    def test_disabled_does_not_read_snapshot_or_http(self):
        result, reader, snapshots = self.observe(enabled=False)
        self.assertFalse(result["ready"])
        reader.assert_not_called()
        snapshots.assert_not_called()

    def test_outer_publication_state_refuses_before_snapshot_or_http(self):
        # This unit supplies the actual guard's thread-local state explicitly;
        # the connected suite separately proves a real EX owner is refused.
        for attribute, value in (("depth", 1), ("depth", 2), ("bootstrap", True)):
            with patch.object(publication._state, attribute, value, create=True):
                result, reader, snapshots = self.observe()
            self.assertFalse(result["ready"])
            reader.assert_not_called()
            snapshots.assert_not_called()

    def test_exception_is_fixed_public_unavailability(self):
        reader = Mock(side_effect=RuntimeError("synthetic-secret-and-path"))
        with owners(operator_google_managed_config=SimpleNamespace(enabled=lambda: True),
                operator_demo_store=SimpleNamespace(loaded_gate_status=reader)), \
                patch.object(readiness, "_snapshot", return_value=snapshot()):
            result = readiness.observe()
        self.assertFalse(result["ready"])
        self.assertNotIn("synthetic-secret", repr(result))


class ReaderTests(unittest.TestCase):
    def setUp(self):
        names = {"_health_object", "loaded_gate_status", "loaded_policy_hash"}
        tree = ast.parse((ROOT / "serverware/operator_demo_store.py").read_text())
        selected = ast.Module(body=[node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names],
            type_ignores=[])
        self.assertEqual({node.name for node in selected.body}, names)
        self.body, self.code, self.calls = json.dumps(health()).encode(), 200, []
        test = self

        class Reply:
            @property
            def status(self):
                return test.code

            def read(self, maximum):
                return test.body[:maximum]

        class Client:
            def __init__(self, *args, **kwargs):
                test.calls.append((args, kwargs))

            def request(self, *args, **kwargs):
                test.calls.append((args, kwargs))

            def getresponse(self):
                return Reply()

            def close(self):
                pass

        self.namespace = {"_require": lambda: None, "operator_publication": publication,
            "http": SimpleNamespace(client=SimpleNamespace(HTTPConnection=Client, HTTPException=http.client.HTTPException)),
            "json": json, "urlsplit": urlsplit, "_SHA": re.compile(r"sha256:[0-9a-f]{64}\Z")}
        exec(compile(selected, "<actual-store-reader-functions>", "exec"), self.namespace)
        self.config = SimpleNamespace(DECISION_GATE_BASE="http://decision-gate-rs:9091")

    def read(self):
        with owners(config=self.config):
            return self.namespace["loaded_gate_status"]()

    def test_real_reader_shape_bound_duplicate_and_status_checks(self):
        self.assertEqual(self.read(), health())
        for value in (None, [], True, {"ok": 1, "policy_hash": POLICY}, {"ok": True, "policy_hash": True}):
            self.body = json.dumps(value).encode()
            self.assertIsNone(self.read())
        for raw in (b'{"ok":false,"ok":true,"policy_hash":"' + POLICY.encode() + b'"}', b" " * 131073):
            self.body = raw
            self.assertIsNone(self.read())
        self.body, self.code = json.dumps(health()).encode(), 503
        self.assertIsNone(self.read())

    def test_outer_publication_state_prevents_http_constructor(self):
        for attribute, value in (("depth", 1), ("bootstrap", True)):
            self.calls.clear()
            with patch.object(publication._state, attribute, value, create=True):
                self.assertIsNone(self.read())
            self.assertEqual(self.calls, [])

    def test_disabled_legacy_hash_and_managed_delegation(self):
        with owners(config=self.config, operator_google_managed_config=SimpleNamespace(enabled=lambda: False)):
            self.assertEqual(self.namespace["loaded_policy_hash"](), POLICY)
        self.calls.clear()
        with owners(operator_google_managed_config=SimpleNamespace(enabled=lambda: True)), \
                patch.object(readiness, "observe", return_value={"ready": False, "loaded_policy_hash": POLICY}):
            self.assertIsNone(self.namespace["loaded_policy_hash"]())
        with owners(operator_google_managed_config=SimpleNamespace(enabled=lambda: True)), \
                patch.object(readiness, "observe", return_value={"ready": True, "loaded_policy_hash": POLICY}):
            self.assertEqual(self.namespace["loaded_policy_hash"](), POLICY)
        self.assertEqual(self.calls, [])


if __name__ == "__main__":
    unittest.main()
