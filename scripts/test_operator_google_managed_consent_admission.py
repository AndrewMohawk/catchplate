#!/usr/bin/env python3
"""Inert consent-receipt helper tests; not OAuth or writer acceptance.

Only actual function definitions/constants and the actual CatalogConflict class
are AST-loaded. Explicit inert owners replace configured imports, observation,
and publication. No app startup, SQLite connection, HTTP, provider or mutation
is performed. The separate connected suite owns real EX/writer/CAS proof.

Runner: python3 -B -m unittest scripts.test_operator_google_managed_consent_admission
"""
from __future__ import annotations

import ast
import builtins
from contextlib import ExitStack, contextmanager
from copy import deepcopy
import http.client
from pathlib import Path
import re
import socket
import sqlite3
import sys
import traceback
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import catchplate

POLICY = "sha256:" + "1" * 64
OTHER_POLICY = "sha256:" + "2" * 64
CANARY = "synthetic-private-secret:/inert/private/path"
ERROR = "operator Google managed consent unavailable"
IDENTITY = {"operation": {"operation_id": "11111111-2222-4333-8444-555555555555",
    "owner_id": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", "config_version": 1},
    "profile_binding_digest": "sha256:" + "3" * 64,
    "effective_settings_digest": "sha256:" + "4" * 64}


def receipt():
    return {"ready": True, "policy_hash": POLICY, "loaded_policy_hash": POLICY,
        "managed_google": deepcopy(IDENTITY)}


def definitions():
    """Execute definitions, never the configured application/module imports."""
    source = ROOT / "catchplate/operator_google_managed_readiness.py"
    tree = ast.parse(source.read_text(), filename=str(source))
    functions = {node.name for node in tree.body if isinstance(node, ast.FunctionDef)}
    required = {"capture_start", "require_start", "_require", "_digest", "_identity", "observe"}
    if not required <= functions:
        raise AssertionError("actual consent helper definitions are missing")
    selected = ast.Module(body=[ast.ImportFrom(module="__future__", names=[ast.alias(name="annotations")], level=0)]
        + [node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.Assign))], type_ignores=[])
    namespace = {"__name__": "inert_actual_consent_helpers", "__package__": "catchplate", "re": re, "uuid": uuid}
    exec(compile(ast.fix_missing_locations(selected), str(source), "exec"), namespace)
    schema = ROOT / "catchplate/operator_catalog_schema.py"
    classes = [node for node in ast.parse(schema.read_text()).body
        if isinstance(node, ast.ClassDef) and node.name == "CatalogConflict"]
    if len(classes) != 1:
        raise AssertionError("actual CatalogConflict class is missing")
    errors = {}
    exec(compile(ast.Module(body=classes, type_ignores=[]), str(schema), "exec"), errors)
    custody = ast.parse((ROOT / "catchplate/operator_provider_custody.py").read_text())
    versions = [ast.literal_eval(node.value) for node in custody.body if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "MAX_VERSIONS" for target in node.targets)]
    if len(versions) != 1 or type(versions[0]) is not int:
        raise AssertionError("actual custody version bound is missing")
    return namespace, errors["CatalogConflict"], versions[0]


@contextmanager
def owners(**modules):
    """Record any attempt to leave the explicitly inert owner inventory."""
    forbidden, effects, original_import = [], [], builtins.__import__
    def guarded(name, globals=None, locals=None, fromlist=(), level=0):
        requested = (["catchplate." + item for item in fromlist if item != "*"]
            if name == "catchplate" else [name])
        for item in requested:
            if item.startswith("catchplate.") and item.removeprefix("catchplate.") not in modules:
                forbidden.append(item)
                raise AssertionError("configured owner import refused by inert test")
        return original_import(name, globals, locals, fromlist, level)
    def no_effect(*_args, **_kwargs):
        effects.append(True)
        raise AssertionError("network or SQLite open refused by inert test")
    with ExitStack() as stack:
        stack.enter_context(patch.dict(sys.modules, {"catchplate." + name: value for name, value in modules.items()}))
        for name, value in modules.items():
            stack.enter_context(patch.object(catchplate, name, value, create=True))
        for target in ("sqlite3.connect", "socket.socket", "socket.create_connection", "socket.getaddrinfo",
                "http.client.HTTPConnection", "http.client.HTTPSConnection"):
            stack.enter_context(patch(target, side_effect=no_effect))
        stack.enter_context(patch("builtins.__import__", side_effect=guarded))
        try:
            yield forbidden
        finally:
            if forbidden:
                raise AssertionError("helper attempted a configured import outside inert owners")
            if effects:
                raise AssertionError("helper attempted network or SQLite open")


class ConsentAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.namespace, self.CatalogConflict, self.maximum_versions = definitions()
        self.observer = Mock(return_value=receipt())
        self.namespace["observe"] = self.observer
        self.snapshot = Mock(side_effect=AssertionError("snapshot is not part of this inert helper suite"))
        self.namespace["_snapshot"] = self.snapshot
        self.enabled = Mock(return_value=True)
        self.http = Mock(side_effect=AssertionError("HTTP forbidden in inert helper suite"))
        # Always refuses ownership. Never manufacture a successful writer/EX.
        self.exclusive_owner = Mock(side_effect=RuntimeError(CANARY))
        self.modules = {
            "operator_google_managed_config": SimpleNamespace(enabled=self.enabled),
            "operator_catalog_schema": SimpleNamespace(CatalogConflict=self.CatalogConflict),
            "operator_provider_custody": SimpleNamespace(MAX_VERSIONS=self.maximum_versions),
            "operator_publication": SimpleNamespace(assert_not_held=Mock(), assert_held=self.exclusive_owner),
            "operator_demo_store": SimpleNamespace(loaded_gate_status=self.http),
            "config": SimpleNamespace(DB_PATH=Path("/inert/not-opened/catchplate.sqlite3")),
        }

    def tearDown(self):
        self.http.assert_not_called()
        self.snapshot.assert_not_called()

    def capture(self, value):
        self.observer.return_value = value
        with owners(**self.modules):
            return self.namespace["capture_start"]()

    def conflict(self, call):
        with self.assertRaises(self.CatalogConflict) as raised:
            with owners(**self.modules):
                call()
        error = raised.exception
        self.assertEqual(error.args, (ERROR,))
        self.assertEqual(str(error), ERROR)
        self.assertIs(error.__suppress_context__, True)
        self.assertNotIn(CANARY, repr(error))
        self.assertNotIn(CANARY, "".join(traceback.format_exception(type(error), error, error.__traceback__)))

    def test_capture_exact_ready_receipt_is_detached(self):
        original = receipt()
        captured = self.capture(original)
        self.assertEqual(captured, original)
        self.assertIsNot(captured, original)
        self.assertIsNot(captured["managed_google"], original["managed_google"])
        self.assertIsNot(captured["managed_google"]["operation"], original["managed_google"]["operation"])
        original["managed_google"]["operation"]["config_version"] = self.maximum_versions
        original["loaded_policy_hash"] = OTHER_POLICY
        self.assertEqual(captured, receipt())
        self.observer.assert_called_once_with()

    def test_capture_admits_exact_integer_version_boundaries(self):
        for version in (1, self.maximum_versions):
            with self.subTest(version=version):
                value = receipt()
                value["managed_google"]["operation"]["config_version"] = version
                self.assertEqual(self.capture(value), value)

    def test_capture_outer_owner_refusal_precedes_observation(self):
        self.modules["operator_publication"].assert_not_held.side_effect = RuntimeError(CANARY)
        self.conflict(self.namespace["capture_start"])
        self.observer.assert_not_called()

    def test_flag_off_does_not_observe_or_inspect_compatibility_receipts(self):
        touched = []
        class NoConnectionAccess:
            def __getattribute__(self, name):
                touched.append(name)
                raise AssertionError("disabled mode inspected connection")
        self.enabled.return_value = False
        with owners(**self.modules):
            self.assertIsNone(self.namespace["capture_start"]())
            for value in (None, receipt(), {"unexpected": CANARY}, True):
                self.assertIsNone(self.namespace["require_start"](NoConnectionAccess(), value))
        self.assertEqual(touched, [])
        self.observer.assert_not_called()
        self.exclusive_owner.assert_not_called()
        self.modules["operator_publication"].assert_not_held.assert_not_called()

    def test_capture_refuses_unready_nonbool_and_wrong_outer_shape(self):
        malformed = [None, [], True, {}, {**receipt(), "extra": CANARY}]
        for ready in (False, None, 0, 1, "true", []):
            malformed.append({**receipt(), "ready": ready})
        for key in receipt():
            value = receipt()
            del value[key]
            malformed.append(value)
        for value in malformed:
            with self.subTest(value_type=type(value).__name__):
                self.observer.return_value = value
                self.conflict(self.namespace["capture_start"])

    def test_capture_refuses_null_or_unconfigured_operation(self):
        for identity in (None, {}, True, [], {**IDENTITY, "operation": None},
                {**IDENTITY, "operation": None, "profile_binding_digest": None}):
            self.observer.return_value = {**receipt(), "managed_google": identity}
            self.conflict(self.namespace["capture_start"])

    def test_capture_closes_identity_uuid_and_integer_shapes(self):
        changes = [lambda value: value.update(extra=CANARY),
            lambda value: value["operation"].update(extra=CANARY),
            lambda value: value["operation"].pop("owner_id")]
        for version in (True, False, 0, -1, self.maximum_versions + 1, 1.0, "1", None):
            changes.append(lambda value, version=version: value["operation"].update(config_version=version))
        for name in ("operation_id", "owner_id"):
            for invalid in (True, [], "not-a-uuid", "AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE"):
                changes.append(lambda value, name=name, invalid=invalid: value["operation"].update({name: invalid}))
        for change in changes:
            value = receipt()
            change(value["managed_google"])
            self.observer.return_value = value
            self.conflict(self.namespace["capture_start"])

    def test_capture_refuses_digest_shapes_and_mismatched_loaded_policy(self):
        for name in ("policy_hash", "loaded_policy_hash"):
            for invalid in (True, False, None, [], CANARY, "sha256:" + "A" * 64):
                self.observer.return_value = {**receipt(), name: invalid}
                self.conflict(self.namespace["capture_start"])
        for name in ("profile_binding_digest", "effective_settings_digest"):
            for invalid in (True, None, [], CANARY):
                value = receipt()
                value["managed_google"][name] = invalid
                self.observer.return_value = value
                self.conflict(self.namespace["capture_start"])
        self.observer.return_value = {**receipt(), "loaded_policy_hash": OTHER_POLICY}
        self.conflict(self.namespace["capture_start"])

    def test_managed_require_refuses_absent_receipt_without_http(self):
        for value in (None, True, [], {**receipt(), "ready": False},
                {**receipt(), "loaded_policy_hash": OTHER_POLICY}):
            self.conflict(lambda value=value: self.namespace["require_start"](object(), value))
        self.observer.assert_not_called()
        self.exclusive_owner.assert_not_called()

    def test_managed_require_refuses_unowned_context_without_observation(self):
        # Negative inert check only: a real transaction is deliberately absent.
        # This does not assert any actual EX, SQLite or catalog-CAS integration.
        self.conflict(lambda: self.namespace["require_start"](object(), receipt()))
        self.observer.assert_not_called()
        self.exclusive_owner.assert_called_once_with()

    def test_owner_and_observer_errors_never_escape_fixed_catalog_conflict(self):
        for error in (RuntimeError(CANARY), ValueError(CANARY), self.CatalogConflict(CANARY)):
            self.observer.side_effect = error
            self.conflict(self.namespace["capture_start"])
        self.observer.side_effect = None
        self.observer.reset_mock()
        self.enabled.side_effect = RuntimeError(CANARY)
        self.conflict(self.namespace["capture_start"])
        self.conflict(lambda: self.namespace["require_start"](object(), None))
        self.observer.assert_not_called()


if __name__ == "__main__":
    unittest.main()
