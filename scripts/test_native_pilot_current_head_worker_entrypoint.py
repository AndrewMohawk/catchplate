#!/usr/bin/env python3
"""Fixed public worker/update grammar, not installed state authority."""
from __future__ import annotations

import ast
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import native_pilot_supervisor_runtime_entrypoint as entrypoint
from scripts import native_pilot_runtime_artifacts as artifacts
from scripts import run_native_pilot_current_head_worker as cli


def arguments(mode=cli.MODE):
    inputs = cli.INPUTS if mode == cli.MODE else cli.UPDATE_INPUTS
    result = [mode]
    for index, name in enumerate(inputs):
        result.extend(("--" + name + "-fd", str(10 + index),
            "--" + name + "-sha256", "sha256:" + str(index + 1) * 64))
    return result


class CurrentHeadWorkerEntrypointControls(unittest.TestCase):
    def test_both_closed_modes_have_only_two_distinct_protected_public_inputs(self):
        for mode in (cli.MODE, cli.UPDATE_MODE):
            values = arguments(mode)
            selected_mode, selected = cli._arguments(values)
            self.assertEqual(selected_mode, mode)
            self.assertTrue(entrypoint.valid_arguments(values))
            self.assertEqual(selected["supervisor_inventory_fd"], 10)
            self.assertEqual(selected["policy_fd" if mode == cli.MODE else "authorization_fd"], 11)
            self.assertFalse(any("key" in name or "socket" in name or "path" in name for name in selected))

    def test_bounds_canonical_pins_aliases_and_extra_capabilities_refuse(self):
        for mode in (cli.MODE, cli.UPDATE_MODE):
            values = [arguments(mode)[:-2], arguments(mode) + ["--authority-key", "head=50"]]
            for index, value in ((0, "automatic-approve"), (2, "2"), (2, "010"), (6, "10"),
                    (6, str(1 << 31)), (4, "1" * 64), (8, "sha256:" + "A" * 64),
                    (5, "--socket-fd"), (7, "--path")):
                changed = arguments(mode); changed[index] = value; values.append(changed)
            for value in values:
                with self.subTest(mode=mode, value=value[:5]), self.assertRaises(ValueError): cli._arguments(value)
                self.assertFalse(entrypoint.valid_arguments(value))

    def test_worker_policy_and_state_update_authorization_are_not_interchangeable(self):
        for mode, other in ((cli.MODE, cli.UPDATE_MODE), (cli.UPDATE_MODE, cli.MODE)):
            values = arguments(mode); values[0] = other
            with self.assertRaises(ValueError): cli._arguments(values)
            self.assertFalse(entrypoint.valid_arguments(values))
        for value in ([], tuple(arguments()), [True, *arguments()[1:]]):
            with self.assertRaises(ValueError): cli._arguments(value)
            self.assertFalse(entrypoint.valid_arguments(value))

    def test_closed_entrypoint_roster_and_default_do_not_change(self):
        self.assertEqual((entrypoint.HEAD_WORKER_MODE, entrypoint.HEAD_UPDATE_MODE), (cli.MODE, cli.UPDATE_MODE))
        self.assertEqual((entrypoint.HEAD_WORKER_INPUTS, entrypoint.HEAD_UPDATE_INPUTS), (cli.INPUTS, cli.UPDATE_INPUTS))
        name = entrypoint.HEAD_WORKER_CLI.removeprefix("/supervisor/app/")
        self.assertIn(name, artifacts.SUPERVISOR_FILES)
        self.assertNotIn(name, artifacts.AUTHORITY_FILES)
        self.assertIn("install -m 0444 /source/" + name + " /supervisor-runtime-root/supervisor/app/" + name,
            (ROOT / "Dockerfile.production").read_text())
        self.assertEqual(artifacts.SUPERVISOR_COMMAND[-1], "--run-native-pilot")

    def test_failure_does_not_claim_no_state_change_and_unknown_cleanup_retains_owner(self):
        tree = ast.parse((ROOT / "scripts/run_native_pilot_current_head_worker.py").read_text())
        functions = {node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)}
        report = ast.unparse(functions["_report"])
        self.assertIn("not-established", report)
        self.assertIn("productionReleaseEligible=False", report)
        self.assertIn("pilotAcceptanceVerified=False", report)
        main = ast.unparse(functions["main"])
        self.assertIn("owner = error.owner", main)
        self.assertIn("cleanup-unknown-owner-retained", main)
        self.assertIn("while True:", main)
        self.assertIn("signal.pause()", main)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                self.assertNotIn(node.func.attr, ("sign", "signing_key", "from_private_bytes", "Popen", "import_module"))


if __name__ == "__main__": unittest.main()
