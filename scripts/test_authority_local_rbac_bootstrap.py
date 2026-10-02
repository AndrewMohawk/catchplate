#!/usr/bin/env python3
"""Pure local timestamp selection; no database, genesis, or bootstrap effects."""
import ast
import copy
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from serverware import authority_local_rbac_bootstrap as local

STAMP = 1_700_000_000_123_456_000


def selection():
    return dict(initialRbacTimestamp=STAMP, issuedAtUnixNanos=STAMP - 1_000_000_000,
                expiresAtUnixNanos=STAMP + 1_000_000_000)


class LocalRbacBootstrapControls(unittest.TestCase):
    def setUp(self):
        self.enterContext(patch.object(local.config, "PRODUCTION_IMAGE", False))
        self.release = self.enterContext(patch.object(local.config, "_production_release", return_value=False))
        self.clock = self.enterContext(patch.object(local.time, "time_ns", return_value=STAMP + 500_000_000))
        self.enterContext(patch.dict(os.environ, {"SERVERWARE_PROCESS_MODE": "metadata-bootstrap",
            "SERVERWARE_RELEASE_CHANNEL": "dev", "SERVERWARE_PRODUCTION_IMAGE": "0"}))

    def test_exact_utc_microseconds_without_selection_rewrite(self):
        value = selection(); original = copy.deepcopy(value)
        self.assertEqual(local.selected_timestamp(value), "2023-11-14T22:13:20.123456+00:00")
        self.assertEqual(value, original)
        value["initialRbacTimestamp"] = 1_700_000_000_000_000_000
        self.assertEqual(local.selected_timestamp(value), "2023-11-14T22:13:20+00:00")
        value["issuedAtUnixNanos"] = value["initialRbacTimestamp"]
        self.clock.return_value = value["initialRbacTimestamp"]
        value["expiresAtUnixNanos"] = value["issuedAtUnixNanos"] + 300_000_000_000
        self.assertEqual(local.selected_timestamp(value), "2023-11-14T22:13:20+00:00")

    def test_closed_dictionary_and_exact_integer_fields(self):
        values = [None, [], {}, dict(selection(), extra=1)]
        for field in selection():
            missing = selection(); missing.pop(field); values.append(missing)
            for wrong in (True, False, float(STAMP), str(STAMP), None):
                changed = selection(); changed[field] = wrong; values.append(changed)
        for value in values:
            with self.subTest(value=value), self.assertRaises(ValueError):
                local.selected_timestamp(value)

    def test_original_window_current_time_and_microsecond_alignment(self):
        for field, wrong in (("issuedAtUnixNanos", 0), ("issuedAtUnixNanos", -1),
                ("issuedAtUnixNanos", STAMP + 1),
                ("initialRbacTimestamp", STAMP - 1_000_001_000),
                ("initialRbacTimestamp", STAMP + 500_001_000),
                ("initialRbacTimestamp", STAMP + 1),
                ("expiresAtUnixNanos", STAMP + 500_000_000),
                ("expiresAtUnixNanos", STAMP + 499_999_999),
                ("expiresAtUnixNanos", STAMP - 1_000_000_000 + 300_000_000_001),
                ("expiresAtUnixNanos", 2**63), ("expiresAtUnixNanos", 2**63 + 1)):
            value = selection(); value[field] = wrong
            with self.subTest(field=field, value=wrong), self.assertRaises(ValueError):
                local.selected_timestamp(value)
        for invalid_clock in (STAMP - 1, STAMP + 1_000_000_000, True, float(STAMP)):
            self.clock.return_value = invalid_clock
            with self.subTest(clock=invalid_clock), self.assertRaises(ValueError):
                local.selected_timestamp(selection())

    def test_only_explicit_development_metadata_bootstrap(self):
        with patch.object(local.config, "PRODUCTION_IMAGE", True), self.assertRaises(ValueError):
            local.selected_timestamp(selection())
        self.release.return_value = True
        with self.assertRaises(ValueError): local.selected_timestamp(selection())
        self.release.return_value = False
        for field, value in (("SERVERWARE_PRODUCTION_IMAGE", "1"), ("SERVERWARE_RELEASE_CHANNEL", "production")):
            with patch.dict(os.environ, {field: value}), self.subTest(field=field):
                with self.assertRaises(ValueError): local.selected_timestamp(selection())
        for mode in ("", "serverware-control-plane", "policy-authority-runtime", "unknown"):
            with patch.dict(os.environ, {"SERVERWARE_PROCESS_MODE": mode}), self.subTest(mode=mode):
                with self.assertRaises(ValueError): local.selected_timestamp(selection())
        with patch.dict(os.environ, {}, clear=True), self.assertRaises(ValueError):
            local.selected_timestamp(selection())

    def test_source_hooks_keep_default_flow_and_reject_existing_state(self):
        # Inspect the actual DB owner; never import or simulate its connections.
        root = Path(__file__).resolve().parents[1]
        tree = ast.parse((root / "serverware/db.py").read_text())
        functions = {node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)}
        for name, parameter in (("init_db", "local_initial_rbac"),
                ("initialize_rbac_authority", "_local_initial_rbac")):
            function = functions[name]
            defaults = dict(zip((arg.arg for arg in function.args.kwonlyargs), function.args.kw_defaults))
            self.assertIsNone(ast.literal_eval(defaults[parameter]))
        initialize = functions["initialize_rbac_authority"]
        selected = next(node for node in ast.walk(initialize) if isinstance(node, ast.If)
            and ast.unparse(node.test) == "_local_initial_rbac is not None"
            and any(isinstance(child, ast.Assign) for child in node.body))
        self.assertIn("now_s = selected_timestamp(_local_initial_rbac)", ast.unparse(selected))
        self.assertEqual(ast.unparse(selected.orelse[0]), "now_s = _metadata_utcnow(conn).isoformat()")
        self.assertIn("legacy_subjects", ast.unparse(selected.test) + ast.unparse(selected))
        self.assertIn("SELECT 1 FROM rbac_role_bindings LIMIT 1", ast.unparse(selected))
        existing = next(node for node in ast.walk(initialize) if isinstance(node, ast.If)
            and ast.unparse(node.test) == "existing is not None")
        self.assertEqual(ast.unparse(existing.body[0].test), "_local_initial_rbac is not None")
        self.assertIsInstance(existing.body[0].body[0], ast.Raise)
        source = ast.unparse(initialize)
        self.assertIn("isinstance(_connection, PostgresMetadataConnection)", source)
        self.assertLess(source.index("selected_timestamp(_local_initial_rbac)"), source.index("with connection_scope as conn"))
        script = ast.parse((root / "scripts/bootstrap_metadata_store.py").read_text())
        main = next(node for node in script.body if isinstance(node, ast.FunctionDef) and node.name == "main")
        branch = next(node for node in ast.walk(main) if isinstance(node, ast.If)
            and ast.unparse(node.test) == "local_initial_rbac is None")
        self.assertEqual(ast.unparse(branch.body[0]), "db.init_db(bootstrap_contract_id=CONTRACT)")
        self.assertEqual(ast.unparse(branch.orelse[0]),
            "db.init_db(bootstrap_contract_id=CONTRACT, local_initial_rbac=local_initial_rbac)")
        source = ast.unparse(main)
        self.assertLess(source.index("selected_timestamp(local_initial_rbac)"), source.index("db = _load_db()"))


if __name__ == "__main__": unittest.main()
