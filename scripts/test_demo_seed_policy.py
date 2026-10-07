#!/usr/bin/env python3
"""Pure demo semantics and dispatch controls; no commissioned authority claim."""
from __future__ import annotations

import ast
import copy
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from fastapi import HTTPException
from serverware import demo_seed_policy as policy


def candidate():
    # These signature-shaped fields are synthetic comparison data, not signed
    # evidence. Authority dispatch is checked separately with explicit mocks.
    value = policy.bundles.demo_policy_bundle("cred-demo-bearer")
    value["metadata"].update(signingKeyId="sha256:" + "1" * 64,
                             signature="ed25519:" + "A" * 86)
    return value


def endpoint(admit, database, *, development=True, channel="dev", production_image=False, authenticator=False):
    # Exercise the exact route body without importing the entire application
    # or initializing a database. Authentication remains on the real route.
    module = ast.parse((ROOT / "serverware/app.py").read_text())
    function = next(item for item in module.body
                    if isinstance(item, ast.FunctionDef) and item.name == "seed_demo")
    guard = next(item for item in module.body
                 if isinstance(item, ast.FunctionDef) and item.name == "_development_demo_seed_enabled")
    function.decorator_list = []
    function.args.defaults = []
    function.args.args[0].annotation = None
    function.returns = None
    namespace = dict(DEV_DEMO_SEED_ENABLED=development, DEV_AUTHENTICATOR_ENABLED=authenticator,
                     PRODUCTION_IMAGE=production_image, RELEASE_CHANNEL=channel,
                     HTTPException=HTTPException, DemoSeedPolicyError=policy.DemoSeedPolicyError,
                     require_commissioned_demo_policy=admit, db=database)
    exec(compile(ast.fix_missing_locations(ast.Module(body=[guard, function], type_ignores=[])),
                 str(ROOT / "serverware/app.py"), "exec"), namespace)
    return namespace["seed_demo"]


class DemoSeedPolicyTests(unittest.TestCase):
    def test_seed_permission_is_default_off_and_not_authenticator_permission(self):
        module = ast.parse((ROOT / "serverware/config.py").read_text())
        assignment = next(item for item in module.body if isinstance(item, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == "DEV_DEMO_SEED_ENABLED" for target in item.targets))
        import os
        for environment, expected in (({}, False), ({"SERVERWARE_DEV_AUTHENTICATOR": "1"}, False),
                ({"SERVERWARE_DEV_DEMO_SEED": "1"}, True), ({"SERVERWARE_DEV_DEMO_SEED": "true"}, False)):
            with self.subTest(environment=environment), patch.dict(os.environ, environment, clear=True):
                value = eval(compile(ast.Expression(assignment.value), "config.py", "eval"), {"os": os})
                self.assertIs(value, expected)
        database, admit = Mock(), Mock()
        with self.assertRaises(HTTPException) as caught:
            endpoint(admit, database, development=False, authenticator=True)(None)
        self.assertEqual(caught.exception.status_code, 404)
        admit.assert_not_called(); self.assertEqual(database.mock_calls, [])

    def test_demo_permission_never_opens_production_image_or_release(self):
        for channel, image in (("production", False), ("dev", True), ("production", True)):
            database, admit = Mock(), Mock()
            with self.subTest(channel=channel, image=image), self.assertRaises(HTTPException) as caught:
                endpoint(admit, database, channel=channel, production_image=image)(None)
            self.assertEqual(caught.exception.status_code, 404)
            admit.assert_not_called(); self.assertEqual(database.mock_calls, [])

    def test_seed_ui_uses_same_permission_and_cannot_enable_software_authenticator(self):
        source = (ROOT / "serverware/app.py").read_text()
        module = ast.parse(source)
        selected = [item for item in module.body if isinstance(item, ast.FunctionDef)
            and item.name in {"_development_demo_seed_enabled", "_portal_document"}]
        import json
        for enabled, image, channel, visible in ((False, False, "dev", False),
                (True, False, "dev", True), (True, True, "dev", False), (True, False, "production", False)):
            namespace = dict(DEV_DEMO_SEED_ENABLED=enabled, PRODUCTION_IMAGE=image, RELEASE_CHANNEL=channel,
                UI_HTML="__SERVERWARE_ENROLLED_OAUTH_PROFILE__ __SERVERWARE_DEMO_SEED_BUTTON__",
                json=json, enrolled_oauth_profile=lambda: {"syntheticTestOnly": True},
                _protected_static_credentials=lambda: False)
            exec(compile(ast.fix_missing_locations(ast.Module(body=selected, type_ignores=[])), "app.py", "exec"), namespace)
            self.assertEqual("Seed demo</button>" in namespace["_portal_document"](), visible)
        self.assertNotIn("advance its policy sequence", source)
        # No software-authenticator consumer receives the new permission.
        webauthn = (ROOT / "serverware/webauthn.py").read_text()
        self.assertNotIn("DEV_DEMO_SEED", webauthn)
        self.assertIn("if not DEV_AUTHENTICATOR_ENABLED:", webauthn)

    def test_demo_npm_allowlist_compiles_and_preserves_denials(self):
        from serverware.constraints import _enforce_operation_policy

        # Structural/compiler admission only; synthetic signature-shaped data
        # does not claim genuine signing or commissioned policy authority.
        value = candidate()
        snapshot = policy.bundles.compile_policy_bundle(value, validate_schema=True)
        route = next(route for route in value["routes"] if route["id"] == "demo.npm.publish.jit")
        constraint = next(item for item in route["constraints"] if item["type"] == "operationPolicy")
        self.assertIsNotNone(snapshot)
        self.assertEqual(constraint["allowedOperations"], ["npm.publish", "npm.distTagWrite"])
        self.assertNotIn("deniedOperations", constraint)
        for operation in ("npm.publish", "npm.distTagWrite"):
            with self.subTest(operation=operation):
                self.assertTrue(_enforce_operation_policy(constraint, {"operation": operation}).allowed)
        for operation in ("npm.tokenWrite", "npm.metadataWrite", "npm.unknown", ""):
            with self.subTest(operation=operation):
                decision = _enforce_operation_policy(constraint, {"operation": operation})
                self.assertFalse(decision.allowed)
                self.assertEqual(decision.status_code, 403)
                self.assertEqual(decision.payload["error"], "credential_operation_not_allowed")

    def test_exact_semantics_allow_existing_counters_without_mutation(self):
        value = candidate()
        value["metadata"].update(sequence=23, rollbackEpoch=7)
        original = copy.deepcopy(value)
        policy.require_demo_semantics(value)
        self.assertEqual(value, original)

    def test_all_policy_content_is_compared(self):
        for change in (
            lambda v: v["defaults"].update(action="allow"),
            lambda v: v["routes"][0]["match"].update(host="other-upstream"),
            lambda v: v["principals"][0].update(sourceCidrs=["0.0.0.0/0"]),
            lambda v: v["credentials"][0].update(id="other-credential"),
            lambda v: v.update(unexpected=True),
        ):
            value = candidate()
            change(value)
            with self.assertRaises(policy.DemoSeedPolicyError):
                policy.require_demo_semantics(value)

    def test_metadata_is_closed_and_counters_are_integers(self):
        for changes in ({"sequence": True}, {"sequence": 0}, {"rollbackEpoch": 0},
                        {"id": "other-policy"}, {"unexpected": "value"}):
            value = candidate()
            value["metadata"].update(changes)
            with self.assertRaises(policy.DemoSeedPolicyError):
                policy.require_demo_semantics(value)

    def test_missing_or_unavailable_authority_is_not_accepted(self):
        with patch.object(policy.bundles, "get_policy_snapshot", return_value=None), \
                patch.object(policy.bundles, "enforce_policy_high_water") as verify:
            with self.assertRaises(policy.DemoSeedPolicyError):
                policy.require_commissioned_demo_policy()
            verify.assert_not_called()
        with patch.object(policy.bundles, "get_policy_snapshot", side_effect=RuntimeError("unavailable")):
            with self.assertRaises(policy.DemoSeedPolicyError):
                policy.require_commissioned_demo_policy()

    def test_current_authority_is_rechecked_before_return(self):
        synthetic = SimpleNamespace(raw=candidate())
        with patch.object(policy.bundles, "get_policy_snapshot", return_value=synthetic), \
                patch.object(policy.bundles, "enforce_policy_high_water") as verify:
            self.assertIs(policy.require_commissioned_demo_policy(), synthetic)
            verify.assert_called_once_with(synthetic)
            verify.side_effect = RuntimeError("authority changed")
            with self.assertRaises(policy.DemoSeedPolicyError):
                policy.require_commissioned_demo_policy()

    def test_endpoint_refuses_before_any_write_and_preserves_dev_guard(self):
        database = Mock()
        admit = Mock(side_effect=policy.DemoSeedPolicyError("missing"))
        with self.assertRaises(HTTPException) as caught:
            endpoint(admit, database)(None)
        self.assertEqual(caught.exception.status_code, 409)
        self.assertEqual(caught.exception.detail["error"], "demo_policy_commissioning_required")
        self.assertIs(caught.exception.detail["dataWritten"], False)
        self.assertEqual(database.mock_calls, [])
        admit.reset_mock()
        with self.assertRaises(HTTPException) as caught:
            endpoint(admit, database, channel="production")(None)
        self.assertEqual(caught.exception.status_code, 404)
        admit.assert_not_called()

    def test_endpoint_proceeds_to_data_only_after_admission(self):
        class FirstDataWrite(Exception):
            pass

        events = []
        admit = Mock(side_effect=lambda: events.append("admitted") or object())
        database = Mock()

        def write(*args):
            events.append("data")
            raise FirstDataWrite

        database.upsert_credential_with_id.side_effect = write
        with self.assertRaises(FirstDataWrite):
            endpoint(admit, database)(None)
        self.assertEqual(events, ["admitted", "data"])
        self.assertEqual(len(database.mock_calls), 1)
        self.assertEqual(database.mock_calls[0][0], "upsert_credential_with_id")


if __name__ == "__main__":
    unittest.main()
