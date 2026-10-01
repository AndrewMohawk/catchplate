#!/usr/bin/env python3
"""Pure CLI grammar controls. Never launches a privileged process or signs."""
from pathlib import Path
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
            "--sign-assignment", "--sign-genesis-precreation", "--sign-genesis-release"})
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

    def test_alias_fds_and_noncanonical_numbers_refuse(self):
        for index, value in ((2, "0"), (2, "03"), (6, "3"), (10, "3"), (10, "4"),
                (10, "+5"), (10, "2147483648")):
            values = arguments(True)
            values[index] = value
            with self.subTest(index=index, value=value):
                self.assertFalse(entry.valid_arguments(values))

    def test_unknown_mode_flags_paths_or_hashes_refuse(self):
        for index, value in ((0, "--sign-adoption"), (1, "--runtime-inventory-fd"),
                (3, "--inventory-sha256"), (5, "--input-path"), (6, "/tmp/input.json"),
                (8, "a" * 64), (8, "sha256:" + "A" * 64), (9, "--key-file")):
            values = arguments(True)
            values[index] = value
            with self.subTest(index=index, value=value):
                self.assertFalse(entry.valid_arguments(values))
        for values in ([], None, tuple(arguments()), arguments() + ["--retry"], [1] * 9):
            with self.subTest(values=values):
                self.assertFalse(entry.valid_arguments(values))


if __name__ == "__main__":
    unittest.main()
