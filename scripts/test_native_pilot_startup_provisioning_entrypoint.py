#!/usr/bin/env python3
"""Pure packaged invocation controls, not live provisioning or approval proof."""
from __future__ import annotations

import ast
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import native_pilot_supervisor_runtime_entrypoint as entrypoint
from scripts import native_pilot_runtime_artifacts as artifacts
from scripts import run_native_pilot_startup_provisioning as cli


def arguments():
    result = [cli.MODE]
    for index, name in enumerate(cli.INPUTS):
        result.extend(("--" + name + "-fd", str(10 + index),
            "--" + name + "-sha256", "sha256:" + str(index + 1) * 64))
    return result


class StartupProvisioningEntrypointControls(unittest.TestCase):
    def test_fixed_six_public_pairs_match_packaged_dispatch(self):
        value = arguments(); selected = cli._arguments(value)
        self.assertEqual(len(value), 25)
        self.assertTrue(entrypoint.valid_arguments(value))
        self.assertEqual(cli.INPUTS, ("supervisor-inventory", "delegation", "configuration", "recipe",
            "conductor-inventory", "authority-inventory"))
        self.assertEqual((entrypoint.PROVISIONING_MODE, entrypoint.PROVISIONING_INPUTS), (cli.MODE, cli.INPUTS))
        for index, name in enumerate(cli.INPUTS):
            self.assertEqual(selected[name.replace("-", "_") + "_fd"], 10 + index)
            self.assertEqual(selected[name.replace("-", "_") + "_sha256"], "sha256:" + str(index + 1) * 64)
        self.assertFalse(any(part in name for name in selected for part in ("socket", "key", "path", "command")))

    def test_each_descriptor_is_canonical_bounded_and_distinct(self):
        for index in range(6):
            for number in ("2", "010", "+10", "-1", "0", str(1 << 31), "1" * 11):
                value = arguments(); value[2 + 4 * index] = number
                with self.subTest(index=index, number=number), self.assertRaises(ValueError): cli._arguments(value)
                self.assertFalse(entrypoint.valid_arguments(value))
        for index in range(1, 6):
            value = arguments(); value[2 + 4 * index] = value[2]
            with self.subTest(alias=index), self.assertRaises(ValueError): cli._arguments(value)
            self.assertFalse(entrypoint.valid_arguments(value))

    def test_missing_extra_reordered_or_unpinned_inputs_refuse(self):
        variants = [arguments()[:-4], arguments() + ["--path", "/tmp/output"],
            arguments() + ["--authority-key", "checkpoint=20"],
            arguments() + ["--approval-socket-fd", "20"]]
        for index, replacement in ((1, "--policy-fd"), (7, "--delegation-path"),
                (4, "a" * 64), (8, "sha256:" + "A" * 64), (12, "sha256:" + "1" * 63)):
            value = arguments(); value[index] = replacement; variants.append(value)
        value = arguments(); value[1:5], value[5:9] = value[5:9], value[1:5]; variants.append(value)
        for value in variants:
            with self.subTest(value=value[:9]), self.assertRaises(ValueError): cli._arguments(value)
            self.assertFalse(entrypoint.valid_arguments(value))

    def test_no_implicit_legacy_or_other_mode_selection(self):
        for mode in ("--run-native-pilot", "--run-adopted-native-pilot", "commissioning-startup",
                "commissioning-startup-child", "approval-provider", "current-head-worker", "current-head-state-update"):
            value = arguments(); value[0] = mode
            with self.subTest(mode=mode), self.assertRaises(ValueError): cli._arguments(value)
            self.assertFalse(entrypoint.valid_arguments(value))
        for value in ([], tuple(arguments()), [True, *arguments()[1:]], [cli.MODE, 3, *arguments()[2:]]):
            with self.assertRaises(ValueError): cli._arguments(value)
            self.assertFalse(entrypoint.valid_arguments(value))

    def test_supervisor_only_roster_and_default_are_preserved(self):
        name = entrypoint.PROVISIONING_CLI.removeprefix("/supervisor/app/")
        self.assertEqual(name, "scripts/run_native_pilot_startup_provisioning.py")
        self.assertEqual(artifacts.SUPERVISOR_FILES.count(name), 1)
        self.assertNotIn(name, artifacts.AUTHORITY_FILES)
        self.assertIn("install -m 0444 /source/" + name + " /supervisor-runtime-root/supervisor/app/" + name,
            (ROOT / "Dockerfile.production").read_text())
        self.assertEqual(artifacts.SUPERVISOR_COMMAND[-1], "--run-native-pilot")
        source = (ROOT / "scripts/native_pilot_supervisor_runtime_entrypoint.py").read_text()
        self.assertIn("PROVISIONING_MODE: PROVISIONING_CLI", source)

    def test_result_is_bounded_truthful_data_not_acceptance_or_reset(self):
        pin = "sha256:" + "a" * 64
        value = cli._result("complete-public-provisioning", "admission-published", 7, pin)
        self.assertEqual(value["admissionSha256"], pin)
        self.assertIs(value["pilotAcceptanceVerified"], False)
        self.assertIs(value["productionReleaseEligible"], False)
        for status in cli.STATUSES[1:]:
            value = cli._result(status, "partial-publication", 4, None)
            self.assertEqual(value["provisioningOutcome"], "not-established")
            self.assertEqual(value["publishedOriginals"], 4)
            with self.assertRaises(ValueError): cli._result(status, "partial-publication", 4, pin)
        for stage, count, digest in (("complete", 6, pin), ("complete", True, pin),
                ("x" * 129, 7, pin), ("complete", 7, None), ("complete", 7, "unverified")):
            with self.assertRaises(ValueError): cli._result(cli.STATUSES[0], stage, count, digest)

    def test_owner_handoff_and_unknown_cleanup_are_retained_without_runtime_fakes(self):
        tree = ast.parse((ROOT / "scripts/run_native_pilot_startup_provisioning.py").read_text())
        functions = {node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)}
        main = ast.unparse(functions["main"])
        self.assertIn("with ownership.owning():", main)
        self.assertIn("owner = error.owner", main)
        self.assertIn("type(owner) is StartupProvisioner", main)
        self.assertLess(main.index("owner.run()"), main.index("owner.close()"))
        self.assertIn("cleanup_failure = error", main)
        self.assertIn("while True:", main)
        self.assertIn("signal.pause()", main)
        self.assertIn("0 if completed and reported else 1", main)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                self.assertNotIn(node.func.attr, ("sign", "signing_key", "from_private_bytes", "Popen", "execv", "import_module"))


if __name__ == "__main__": unittest.main()
