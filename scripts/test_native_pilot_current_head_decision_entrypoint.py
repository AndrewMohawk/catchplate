#!/usr/bin/env python3
"""Closed service invocation/packaging controls, not an installed service run."""
from __future__ import annotations

import ast
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import native_pilot_runtime_artifacts as artifacts
from scripts import native_pilot_supervisor_runtime_entrypoint as entrypoint
from scripts import run_native_pilot_current_head_decisions as cli


def arguments():
    return [cli.MODE, "--supervisor-inventory-fd", "3", "--supervisor-inventory-sha256", "sha256:" + "1" * 64,
        "--configuration-fd", "4", "--configuration-sha256", "sha256:" + "2" * 64,
        "--approval-socket-fd", "5"]


class CurrentHeadDecisionEntrypointControls(unittest.TestCase):
    def test_exact_two_public_sources_one_socket_and_no_signing_keys(self):
        selected = cli._arguments(arguments())
        self.assertEqual(selected, dict(supervisor_inventory_fd=3, supervisor_inventory_sha256="sha256:" + "1" * 64,
            configuration_fd=4, configuration_sha256="sha256:" + "2" * 64, approval_socket_fd=5))
        self.assertTrue(entrypoint.valid_arguments(arguments()))
        self.assertEqual(cli.MODE, entrypoint.DECISION_MODE)
        self.assertEqual(cli.INPUTS, entrypoint.DECISION_INPUTS)

    def test_exact_closed_mode_order_and_count_in_both_parsers(self):
        reordered = arguments(); reordered[1:5] = reordered[3:5] + reordered[1:3]
        values = [[], tuple(arguments()), arguments()[:-2], arguments()[1:], reordered,
            arguments() + ["--authority-key-fd", "6"], arguments() + ["--approve-all", "true"]]
        values += [[mode, *arguments()[1:]] for mode in
            (entrypoint.PROVIDER_MODE, entrypoint.LIFECYCLE_MODE, "--run-native-pilot", "--run-adopted-native-pilot")]
        for value in values:
            with self.subTest(value=value[:2]), self.assertRaises(ValueError): cli._arguments(value)
            with self.subTest(value=value[:2]): self.assertFalse(entrypoint.valid_arguments(value))

    def test_three_fds_must_be_distinct_and_numbers_and_pins_canonical(self):
        for index, replacements in ((2, ("2", "03", "+3", "-3", str(1 << 31), True)),
                (6, ("3",)), (10, ("3", "4")),
                (4, ("1" * 64, "sha256:" + "A" * 64, "sha256:" + "1" * 63)),
                (8, ("sha256:" + "g" * 64, "sha256:" + "2" * 65)),
                (1, ("--configuration-fd",)), (9, ("--current-head-socket-fd",))):
            for replacement in replacements:
                value = arguments(); value[index] = replacement
                with self.subTest(index=index, replacement=replacement), self.assertRaises(ValueError):
                    cli._arguments(value)
                self.assertFalse(entrypoint.valid_arguments(value))

    def test_fixed_supervisor_only_packaging_keeps_legacy_command_default(self):
        name = "scripts/run_native_pilot_current_head_decisions.py"
        self.assertEqual(entrypoint.DECISION_CLI, "/supervisor/app/" + name)
        self.assertIn(name, artifacts.SUPERVISOR_FILES)
        self.assertNotIn(name, artifacts.AUTHORITY_FILES)
        self.assertEqual(artifacts.SUPERVISOR_COMMAND[-1], "--run-native-pilot")
        docker = (ROOT / "Dockerfile.production").read_text()
        self.assertIn("install -m 0444 /source/" + name + " /supervisor-runtime-root/supervisor/app/" + name, docker)

    def test_unknown_cleanup_retains_actual_owner_without_success_or_retry(self):
        tree = ast.parse((ROOT / "scripts/run_native_pilot_current_head_decisions.py").read_text())
        main = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "main")
        calls = [node for node in ast.walk(main) if isinstance(node, ast.Call)]
        attributes = [node.func.attr for node in calls if isinstance(node.func, ast.Attribute)]
        self.assertEqual(attributes.count("open"), 1)
        self.assertEqual(attributes.count("run"), 1)
        self.assertEqual(attributes.count("close"), 1)
        self.assertIn("pause", attributes)
        self.assertFalse(set(attributes) & {"sign", "signing_key", "execve", "Popen", "system"})


if __name__ == "__main__":
    unittest.main()
