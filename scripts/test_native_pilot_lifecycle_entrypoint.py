#!/usr/bin/env python3
"""Closed packaged-caller grammar; no installed runtime or owner is fabricated."""
from __future__ import annotations

from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts import native_pilot_runtime_artifacts as artifacts
from scripts import native_pilot_supervisor_runtime_entrypoint as entrypoint
from serverware.native_pilot_adopted_phase_profile import KEY_PURPOSES as ADOPTED
from serverware.native_pilot_genesis_jobs import KEY_PURPOSES as COLD


def arguments():
    values = [entrypoint.LIFECYCLE_MODE]
    for index, name in enumerate(entrypoint.LIFECYCLE_INPUTS):
        values += ["--" + name + "-fd", str(10 + index),
            "--" + name + "-sha256", "sha256:" + str(index + 1) * 64]
    values += ["--approval-fd", "12", "--approval-peer-pid", "100",
        "--approval-peer-uid", "0", "--approval-peer-gid", "0"]
    for flag, purposes in (("cold-authority-key", COLD), ("adopted-authority-key", ADOPTED)):
        for purpose in purposes:
            values += ["--" + flag, purpose + "=50"]
    return values


def provider_arguments():
    values = [entrypoint.PROVIDER_MODE]
    for index, name in enumerate(entrypoint.PROVIDER_INPUTS):
        values += ["--" + name + "-fd", str(20 + index),
            "--" + name + "-sha256", "sha256:" + str(index + 1) * 64]
    return values + ["--approval-socket-fd", "25", "--current-head-socket-fd", "26"]


class LifecycleEntrypointControls(unittest.TestCase):
    def test_provider_exact_public_arguments_and_supervisor_only_namespace(self):
        values = provider_arguments()
        self.assertEqual(len(values), 25)
        self.assertTrue(entrypoint.valid_arguments(values))
        self.assertEqual(entrypoint.PROVIDER_MODE, "approval-provider")
        self.assertEqual(entrypoint.PROVIDER_CLI,
            "/supervisor/app/scripts/run_native_pilot_approval_provider.py")
        name = entrypoint.PROVIDER_CLI.removeprefix("/supervisor/app/")
        self.assertIn(name, artifacts.SUPERVISOR_FILES)
        self.assertNotIn(name, artifacts.AUTHORITY_FILES)
        self.assertEqual(artifacts.SUPERVISOR_COMMAND[-1], "--run-native-pilot")

    def test_provider_requires_all_seven_distinct_descriptors_and_exact_pin_syntax(self):
        for index, replacement in ((2, "2"), (2, "020"), (2, "2147483648"), (6, "20"),
                (22, "20"), (24, "25"), (24, "2"), (4, "sha256:" + "A" * 64),
                (8, "1" * 64), (1, "--recipe-fd"), (21, "--approval-fd")):
            changed = provider_arguments(); changed[index] = replacement
            with self.subTest(index=index, replacement=replacement):
                self.assertFalse(entrypoint.valid_arguments(changed))
        self.assertFalse(entrypoint.valid_arguments(provider_arguments()[:-2]))
        self.assertFalse(entrypoint.valid_arguments(provider_arguments() + ["--authority-key", "synthetic=30"]))

    def test_provider_never_reinterprets_legacy_lifecycle_or_arbitrary_mode(self):
        for mode in ("--run-native-pilot", "--run-adopted-native-pilot", entrypoint.LIFECYCLE_MODE,
                "--approval-provider", "/tmp/provider.py", "--approve-all"):
            with self.subTest(mode=mode):
                self.assertFalse(entrypoint.valid_arguments([mode, *provider_arguments()[1:]]))
        self.assertFalse(entrypoint.valid_arguments([entrypoint.PROVIDER_MODE, *arguments()[1:]]))

    def test_source_catalogue_counts_match_fixed_syntax_and_packaged_path(self):
        self.assertEqual((len(COLD), len(ADOPTED)), (36, 123))
        self.assertTrue(entrypoint.valid_arguments(arguments()))
        self.assertEqual(entrypoint.LIFECYCLE_CLI,
            "/supervisor/app/scripts/run_native_pilot_lifecycle.py")
        self.assertIn(entrypoint.LIFECYCLE_CLI.removeprefix("/supervisor/app/"),
            artifacts.SUPERVISOR_FILES)
        self.assertNotIn("scripts/run_native_pilot_lifecycle.py", artifacts.AUTHORITY_FILES)

    def test_new_mode_does_not_reinterpret_operational_profiles(self):
        for mode in ("--run-native-pilot", "--run-adopted-native-pilot",
                "--run-native-genesis-rendezvous", "--approve-all", "run_native_pilot_lifecycle.py"):
            self.assertFalse(entrypoint.valid_arguments([mode, *arguments()[1:]]))

    def test_extra_missing_reordered_and_duplicate_key_groups_refused(self):
        value = arguments()
        self.assertFalse(entrypoint.valid_arguments(value[:-2]))
        self.assertFalse(entrypoint.valid_arguments(value + value[-2:]))
        changed = list(value); changed[17] = "--adopted-authority-key"
        self.assertFalse(entrypoint.valid_arguments(changed))
        changed = list(value); changed[20] = changed[18]
        self.assertFalse(entrypoint.valid_arguments(changed))

    def test_public_descriptors_and_key_aliases_are_not_interchangeable(self):
        value = arguments()
        for index, replacement in ((6, "10"), (10, "10"), (18, COLD[0] + "=12"),
                (18 + 2 * len(COLD), ADOPTED[0] + "=11")):
            changed = list(value); changed[index] = replacement
            self.assertFalse(entrypoint.valid_arguments(changed))
        self.assertTrue(entrypoint.valid_arguments(value))  # Shared selected key only.

    def test_numbers_pins_and_flags_are_closed_without_opening_fds(self):
        for index, replacement in ((2, "03"), (2, "2"), (4, "sha256:" + "A" * 64),
                (8, "1" * 64), (12, "1"), (14, "-1"), (16, str((1 << 32) - 1)),
                (1, "--listener-configuration-fd"), (18, COLD[0] + "=2147483648")):
            changed = arguments(); changed[index] = replacement
            self.assertFalse(entrypoint.valid_arguments(changed))

    def test_arbitrary_types_and_scripts_are_not_invocations(self):
        for value in (None, (), {}, [], [entrypoint.LIFECYCLE_MODE, 10], "--run-native-pilot-lifecycle"):
            self.assertFalse(entrypoint.valid_arguments(value))
        changed = arguments(); changed[0] = "/tmp/custom.py"
        self.assertFalse(entrypoint.valid_arguments(changed))

    def test_real_cli_and_packaged_entrypoint_accept_same_canonical_invocation(self):
        from scripts import run_native_pilot_lifecycle as cli
        value = arguments()
        selected = cli._arguments(value, COLD, ADOPTED)
        self.assertEqual(selected["supervisor_inventory_fd"], 10)
        self.assertEqual(selected["listener_configuration_fd"], 11)
        self.assertTrue(entrypoint.valid_arguments(value))


if __name__ == "__main__":
    unittest.main()
