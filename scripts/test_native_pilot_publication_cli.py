#!/usr/bin/env python3
"""Pure CLI grammar controls. Never launches a privileged process or signs."""
from pathlib import Path
import ast
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import native_pilot_publication_runtime_entrypoint as entry


def arguments(signing=False):
    values = ["--sign-assignment" if signing else "--prepare-closure-set",
        "--supervisor-inventory-fd", "3", "--supervisor-inventory-sha256", "sha256:" + "a" * 64,
        "--input-fd", "4", "--input-sha256", "sha256:" + "b" * 64]
    return values + (["--authority-key-fd", "5"] if signing else [])


class PublicationCliTests(unittest.TestCase):
    def test_fixed_modes_and_import_roots(self):
        self.assertTrue(entry.valid_arguments(arguments()))
        self.assertTrue(entry.valid_arguments(arguments(True)))
        self.assertEqual(entry.IMPORT_ROOTS, ("/supervisor/app", "/authority/app", "/vendor", "/app"))
        self.assertEqual(entry.SCRIPT, "/supervisor/app/scripts/native_pilot_publication_runtime_entrypoint.py")

    def test_cold_modes_require_separate_purpose_and_correct_key_presence(self):
        self.assertEqual(set(entry.MODES), {"--prepare-closure-set", "--prepare-genesis-binding",
            "--sign-assignment", "--sign-genesis-precreation", "--sign-genesis-release",
            "--sign-genesis-ordinary-checkpoint", "--sign-genesis-ordinary-root-anchor",
            "--sign-genesis-ordinary-checkpoint-anchor", "--sign-genesis-ordinary-service-anchor",
            "--assemble-genesis-ordinary-history", "--sign-genesis-ordinary-delivery",
            "--sign-genesis-ordinary-grant", "--sign-genesis-endpoints-release", "--sign-publication-adoption"}
            | set(entry.NATIVE_MODES) | set(entry.SERVICE_MODES) | set(entry.TRANSPORT_MODES) | set(entry.LAUNCH_MODES))
        for mode, purpose in (("--sign-genesis-precreation", "precreation"),
                              ("--sign-genesis-release", "release")):
            values = arguments(True)
            values[0] = mode
            self.assertTrue(entry.valid_arguments(values))
            self.assertFalse(entry.valid_arguments(values[:-2]))
            self.assertEqual(entry.genesis_operation(mode), purpose)
        values = arguments()
        values[0] = "--prepare-genesis-binding"
        self.assertTrue(entry.valid_arguments(values))
        self.assertFalse(entry.valid_arguments(values + ["--authority-key-fd", "5"]))
        for mode in ("--sign-assignment", "--prepare-closure-set", "--prepare-genesis-binding",
                     "--sign-adoption", "--sign-genesis"):
            self.assertIsNone(entry.genesis_operation(mode))

    def test_no_extra_key_or_missing_signing_key(self):
        values = arguments(True)
        self.assertFalse(entry.valid_arguments(values[:-2]))
        values[0] = "--prepare-closure-set"
        self.assertFalse(entry.valid_arguments(values))

    def test_initial_history_modes_are_fixed_and_assembly_is_keyless(self):
        self.assertEqual(set(entry.INITIAL_MODES.values()),
            {"checkpoint", "root-anchor", "checkpoint-anchor", "service-anchor", "assemble"})
        for mode, operation in entry.INITIAL_MODES.items():
            values = arguments(operation != "assemble")
            values[0] = mode
            self.assertTrue(entry.valid_arguments(values))
            wrong = values + ["--authority-key-fd", "5"] if operation == "assemble" else values[:-2]
            self.assertFalse(entry.valid_arguments(wrong))
            self.assertIsNone(entry.genesis_operation(mode))

    def test_ordinary_c9_and_grant_have_distinct_keyed_purposes(self):
        self.assertEqual(entry.ORDINARY_MODES, {
            "--sign-genesis-ordinary-delivery": "delivery", "--sign-genesis-ordinary-grant": "grant"})
        for mode in entry.ORDINARY_MODES:
            values = arguments(True)
            values[0] = mode
            self.assertTrue(entry.valid_arguments(values))
            self.assertFalse(entry.valid_arguments(values[:-2]))
            self.assertIsNone(entry.genesis_operation(mode))
            self.assertNotIn(mode, entry.INITIAL_MODES)

    def test_alias_fds_and_noncanonical_numbers_refuse(self):
        for index, value in ((2, "0"), (2, "03"), (6, "3"), (10, "3"), (10, "4"),
                (10, "+5"), (10, "2147483648")):
            values = arguments(True)
            values[index] = value
            with self.subTest(index=index, value=value):
                self.assertFalse(entry.valid_arguments(values))
        for values in ([], None, tuple(arguments()), arguments() + ["--retry"], [1] * 9):
            with self.subTest(values=values):
                self.assertFalse(entry.valid_arguments(values))

    def test_cold_native_roles_and_operations_are_fixed_not_payload_selected(self):
        self.assertEqual(len(entry.NATIVE_MODES), 12)
        self.assertEqual(set(entry.NATIVE_MODES.values()), {(role, operation)
            for role in ("publicationGenesisRetrieval", "publicationGenesis", "publicationGenesisCoordinator")
            for operation in ("delivery", "role-keys", "admission", "closure")})
        self.assertEqual(entry.SERVICE_MODES, {"--sign-genesis-native-publication-grant": "publication",
            "--sign-genesis-native-retrieval-grant": "retrieval"})
        for mode in (*entry.NATIVE_MODES, *entry.SERVICE_MODES, "--sign-genesis-endpoints-release"):
            values = arguments(True); values[0] = mode
            self.assertTrue(entry.valid_arguments(values))
            self.assertFalse(entry.valid_arguments(values[:-2]))
        for mode in ("--sign-genesis-native", "--sign-genesis-native-bridge-delivery",
                "--sign-genesis-native-coordinator-grant"):
            values = arguments(True); values[0] = mode
            self.assertFalse(entry.valid_arguments(values))

    def test_cold_transports_are_keyed_and_launch_bundles_are_keyless(self):
        roles = ("publicationGenesisRetrieval", "publicationGenesis", "publicationGenesisCoordinator")
        self.assertEqual(len(entry.TRANSPORT_MODES), 6)
        self.assertEqual(set(entry.TRANSPORT_MODES.values()), {(role, operation)
            for role in roles for operation in ("encrypted-delivery", "verifier")})
        self.assertEqual(set(entry.LAUNCH_MODES.values()), set(roles))
        self.assertEqual(len(entry.LAUNCH_MODES), 3)
        for mode in entry.TRANSPORT_MODES:
            values = arguments(True); values[0] = mode
            self.assertTrue(entry.valid_arguments(values))
            self.assertFalse(entry.valid_arguments(values[:-2]))
        for mode in entry.LAUNCH_MODES:
            values = arguments(); values[0] = mode
            self.assertTrue(entry.valid_arguments(values))
            self.assertFalse(entry.valid_arguments(values + ["--authority-key-fd", "5"]))
        for mode in ("--sign-genesis-native-bridge-verifier", "--sign-genesis-native-coordinator-request-commitment",
                "--assemble-genesis-native-coordinator", "--sign-genesis-native-coordinator-launch",
                "--assemble-genesis-native-retrieval-encrypted-delivery"):
            values = arguments(True); values[0] = mode
            self.assertFalse(entry.valid_arguments(values))
            self.assertFalse(entry.valid_arguments(values[:-2]))

    def test_unknown_mode_flags_paths_or_hashes_refuse(self):
        for index, value in ((0, "--sign-adoption"), (1, "--runtime-inventory-fd"),
                (3, "--inventory-sha256"), (5, "--input-path"), (6, "/tmp/input.json"),
                (8, "a" * 64), (8, "sha256:" + "A" * 64), (9, "--key-file")):
            values = arguments(True)
            values[index] = value
            with self.subTest(index=index, value=value):
                self.assertFalse(entry.valid_arguments(values))

    def test_adoption_requires_separate_validator_control_and_key(self):
        values = arguments()
        values[0] = entry.ADOPTION_MODE
        values += ["--validator-control-fd", "5", "--validator-control-sha256", "sha256:" + "c" * 64,
            "--authority-key-fd", "6"]
        self.assertTrue(entry.valid_arguments(values))
        for index, value in ((10, "3"), (10, "4"), (14, "3"), (14, "4"), (14, "5"),
                (10, "05"), (9, "--validator-path"), (12, "sha256:" + "C" * 64), (13, "--key-file")):
            changed = list(values); changed[index] = value
            with self.subTest(index=index, value=value):
                self.assertFalse(entry.valid_arguments(changed))
        for mode in entry.SIGNING_MODES:
            changed = list(values); changed[0] = mode
            self.assertFalse(entry.valid_arguments(changed))
        self.assertFalse(entry.valid_arguments(values[:-4] + values[-2:]))
        self.assertFalse(entry.valid_arguments(values[:-2]))

    def test_adoption_entry_keeps_actual_owner_until_after_output(self):
        tree = ast.parse(Path(entry.__file__).read_text())
        helper = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "_sign_adoption")
        calls = {}
        for node in ast.walk(helper):
            if isinstance(node, ast.Call): calls.setdefault(ast.unparse(node.func), []).append(node.lineno)
        for left, right in (("AdoptionAuthority.prepare", "owner.validate"), ("owner.validate", "owner.sign"),
                ("owner.sign", "io.write_public"), ("io.write_public", "owner.close"), ("owner.close", "runtime.close")):
            self.assertLess(min(calls[left]), min(calls[right]))
        self.assertIn("owner.check_identity", calls)
        self.assertIn("signal.pause", calls)


if __name__ == "__main__":
    unittest.main()
