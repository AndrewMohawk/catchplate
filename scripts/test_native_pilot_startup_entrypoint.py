#!/usr/bin/env python3
"""Fixed launcher/child invocation controls, not protected commissioning."""
from __future__ import annotations

import ast
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import native_pilot_runtime_artifacts as artifacts
from scripts import native_pilot_supervisor_runtime_entrypoint as entrypoint
from scripts import run_native_pilot_startup as cli
from scripts import run_native_pilot_startup_child as child
from serverware.native_pilot_genesis_jobs import KEY_PURPOSES as COLD
from serverware.native_pilot_adopted_phase_profile import KEY_PURPOSES as ADOPTED


def inputs():
    return ["--configuration-fd", "10", "--configuration-sha256", "sha256:" + "1" * 64,
        "--supervisor-inventory-fd", "11", "--supervisor-inventory-sha256", "sha256:" + "2" * 64]


def parent_arguments():
    values = [cli.MODE, *inputs()]
    for family, purposes in (("cold", COLD), ("adopted", ADOPTED)):
        for purpose in purposes: values += ["--" + family + "-authority-key", purpose + "=50"]
    return values


def child_arguments(role="lifecycle"):
    return [child.MODE, role, *inputs(), "--parent-pid", "123", "--parent-start-time-ticks", "456"]


class StartupEntrypointControls(unittest.TestCase):
    def test_parent_exact_static_publics_and_existing_159_purpose_slots(self):
        selected = cli._arguments(parent_arguments(), COLD, ADOPTED)
        self.assertTrue(entrypoint.valid_arguments(parent_arguments()))
        self.assertEqual((len(COLD), len(ADOPTED)), (36, 123))
        self.assertEqual(tuple(selected["cold_authority_key_fds"]), COLD)
        self.assertEqual(tuple(selected["adopted_authority_key_fds"]), ADOPTED)
        self.assertEqual(selected["configuration_fd"], 10)
        self.assertEqual(selected["supervisor_inventory_fd"], 11)
        self.assertFalse(any("approval" in field or "peer" in field for field in selected))

    def test_parent_extra_missing_public_key_aliases_and_reordered_keys_refuse(self):
        samples = [parent_arguments()[:-2], parent_arguments() + ["--approve-all", "true"]]
        for index, value in ((0, entrypoint.LIFECYCLE_MODE), (2, "010"), (6, "10"),
                (4, "sha256:" + "A" * 64), (10, COLD[0] + "=10"), (10, COLD[1] + "=50"),
                (9, "--adopted-authority-key")):
            changed = parent_arguments(); changed[index] = value; samples.append(changed)
        for value in samples:
            with self.subTest(value=value[:5]), self.assertRaises(ValueError): cli._arguments(value, COLD, ADOPTED)
        # Entrypoint shape checks do not replace exact source-purpose checks in CLI.
        for value in samples[:-2]: self.assertFalse(entrypoint.valid_arguments(value))

    def test_child_three_fixed_roles_no_keys_or_arbitrary_module(self):
        for role in child.ROLES:
            values = child_arguments(role)
            selected = child._arguments(values)
            self.assertEqual(selected["role"], role)
            self.assertEqual((selected["parent_pid"], selected["parent_start_time_ticks"]), (123, 456))
            self.assertTrue(entrypoint.valid_arguments(values))
            self.assertFalse(any("key" in field for field in selected))
        for role in ("../provider", "supervisor", "python", "", "approve-all"):
            with self.subTest(role=role), self.assertRaises(ValueError): child._arguments(child_arguments(role))
            self.assertFalse(entrypoint.valid_arguments(child_arguments(role)))

    def test_child_exact_flags_bounds_and_public_descriptor_alias_refuse(self):
        values = [[], tuple(child_arguments()), child_arguments()[:-2],
            child_arguments() + ["--authority-key", "purpose=50"]]
        for index, changed in ((3, "2"), (7, "10"), (5, "1" * 64), (11, "1"), (11, "0123"),
                (13, "0"), (13, "0456"), (13, str(1 << 64)), (1, True), (10, "--peer-pid")):
            sample = child_arguments(); sample[index] = changed; values.append(sample)
        for value in values:
            with self.subTest(value=value[:4]), self.assertRaises(ValueError): child._arguments(value)
            self.assertFalse(entrypoint.valid_arguments(value))
        large_start = child_arguments(); large_start[13] = str((1 << 64) - 1)
        self.assertTrue(entrypoint.valid_arguments(large_start))
        self.assertEqual(child._arguments(large_start)["parent_start_time_ticks"], (1 << 64) - 1)

    def test_modes_cannot_reinterpret_each_other_or_change_legacy_default(self):
        for mode in (entrypoint.PROVIDER_MODE, entrypoint.DECISION_MODE, "--run-native-pilot", "--run-adopted-native-pilot"):
            self.assertFalse(entrypoint.valid_arguments([mode, *parent_arguments()[1:]]))
            self.assertFalse(entrypoint.valid_arguments([mode, *child_arguments()[1:]]))
        self.assertEqual(artifacts.SUPERVISOR_COMMAND[-1], "--run-native-pilot")

    def test_both_scripts_are_source_fixed_supervisor_only_artifacts(self):
        self.assertEqual((entrypoint.STARTUP_MODE, entrypoint.STARTUP_CHILD_MODE), (cli.MODE, child.MODE))
        self.assertEqual(entrypoint.STARTUP_INPUTS, cli.INPUTS)
        self.assertEqual(entrypoint.STARTUP_ROLES, child.ROLES)
        docker = (ROOT / "Dockerfile.production").read_text()
        for path in (entrypoint.STARTUP_CLI, entrypoint.STARTUP_CHILD_CLI):
            name = path.removeprefix("/supervisor/app/")
            self.assertIn(name, artifacts.SUPERVISOR_FILES)
            self.assertNotIn(name, artifacts.AUTHORITY_FILES)
            self.assertIn("install -m 0444 /source/" + name + " /supervisor-runtime-root/supervisor/app/" + name, docker)

    def test_child_dispatch_is_in_process_and_unexpected_role_error_retains_owners(self):
        tree = ast.parse((ROOT / "scripts/run_native_pilot_startup_child.py").read_text())
        methods = {node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)}
        dispatch = methods["_run_role"]
        for node in ast.walk(dispatch):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                self.assertNotIn(node.func.attr, ("execve", "execv", "Popen", "system", "run_path", "import_module"))
        self.assertIn("return cli.main()", ast.unparse(dispatch))
        main = ast.unparse(methods["main"])
        self.assertIn("retained_error = error", main)
        guard = next(node for node in ast.walk(methods["main"]) if isinstance(node, ast.If)
            and isinstance(node.test, ast.BoolOp) and isinstance(node.test.op, ast.And)
            and [ast.unparse(value) for value in node.test.values] == ["entered", "not returned"])
        close = next(node for node in ast.walk(methods["main"]) if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute) and node.func.attr == "close")
        self.assertLess(guard.lineno, close.lineno)
        self.assertTrue(any(isinstance(node, ast.While) for node in ast.walk(guard)))


if __name__ == "__main__": unittest.main()
