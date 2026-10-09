#!/usr/bin/env python3
"""Pure/mocked executable-pin checks: no files, subprocesses or containers."""
from copy import deepcopy
from io import StringIO
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

try:
    from scripts import prepare_operator_catalog_fixture as fixture
except ModuleNotFoundError:
    import prepare_operator_catalog_fixture as fixture


SOURCE = Path("/fixture/source")
BINARY = Path("/fixture/serverware-decision-gate")
INITIALIZER = Path("/fixture/initialize.py")
ROOT = fixture.SCRATCH / "serverware-catalog-private.PinCheck01"
SUBNET = "172.16.249.48/28"
SELECTED = "9be25b5dbca69befbbbdfab7b1fab9a852f3c6212a73078ea0c05a32375ef3a4"
ENV_KEY = "SERVERWARE_EXPECTED_DATA_PLANE_BINARY_DIGEST"
INVALID = (None, True, 1, b"a" * 64, "", "a" * 63, "a" * 65,
           "A" * 64, "g" * 64, "sha256:" + "a" * 64, " " + "a" * 64,
           "a" * 64 + "\n", "a" * 32 + " " + "a" * 31)


class BinaryPinTests(unittest.TestCase):
    def build(self, **kwargs):
        return fixture.build(SOURCE, BINARY, INITIALIZER, ROOT, SUBNET, **kwargs)

    def args(self, **kwargs):
        return SimpleNamespace(source=SOURCE, binary=BINARY, initializer=INITIALIZER,
            job_root=ROOT, subnet=SUBNET, write=False, **kwargs)

    def test_historical_default_unchanged(self):
        self.assertEqual(self.build(), self.build(expected_binary_sha256=fixture.BINARY_SHA256))
        self.assertEqual(self.build()["services"]["serverware"]["environment"][ENV_KEY],
                         "sha256:" + fixture.BINARY_SHA256)
        fixture.validate(self.build(), SOURCE, BINARY, INITIALIZER, ROOT)

    def test_selected_pin_changes_only_expected_environment(self):
        historical = self.build()
        selected = self.build(expected_binary_sha256=SELECTED)
        expected = deepcopy(historical)
        expected["services"]["serverware"]["environment"][ENV_KEY] = "sha256:" + SELECTED
        self.assertEqual(selected, expected)
        fixture.validate(selected, SOURCE, BINARY, INITIALIZER, ROOT, expected_binary_sha256=SELECTED)

    def test_invalid_pin_refused_before_prepare_side_effects(self):
        for value in INVALID:
            with self.subTest(value=repr(value)):
                with self.assertRaises(ValueError):
                    self.build(expected_binary_sha256=value)
                with self.assertRaises(ValueError):
                    fixture.validate(self.build(), SOURCE, BINARY, INITIALIZER, ROOT,
                                     expected_binary_sha256=value)
                with patch.object(fixture, "fresh_root") as fresh, patch.object(fixture, "command") as command:
                    with self.assertRaises(ValueError):
                        fixture.prepare(self.args(expected_binary_sha256=value))
                    fresh.assert_not_called()
                    command.assert_not_called()

    def test_validation_rejects_missing_or_different_environment_pin(self):
        for value in (None, SELECTED, "sha256:" + fixture.BINARY_SHA256,
                      "sha256:" + SELECTED.upper(), "sha256:sha256:" + SELECTED):
            config = self.build(expected_binary_sha256=SELECTED)
            environment = config["services"]["serverware"]["environment"]
            if value is None:
                del environment[ENV_KEY]
            else:
                environment[ENV_KEY] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                fixture.validate(config, SOURCE, BINARY, INITIALIZER, ROOT,
                                 expected_binary_sha256=SELECTED)

    def test_explicit_pin_not_silently_validated_as_default(self):
        with self.assertRaises(ValueError):
            fixture.validate(self.build(expected_binary_sha256=SELECTED), SOURCE, BINARY, INITIALIZER, ROOT)

    def mocked_prepare(self, args, *, actual_binary=SELECTED, actual_initializer=fixture.INITIALIZER_SHA256):
        def digest(path):
            return {BINARY: actual_binary, INITIALIZER: actual_initializer,
                    SOURCE / "serverware/app.py": "f" * 64}[path]

        def command(argv):
            if argv[:3] == ["docker", "image", "inspect"]:
                return "cached-image\n"
            if argv[:3] == ["docker", "ps", "-a"]:
                return ""
            if argv[0] == "findmnt":
                return '{"filesystems":[{"target":"/fixture","fstype":"ext4"}]}'
            if argv[:3] == ["git", "-C", str(SOURCE)]:
                return {"ls-files": "serverware/app.py\n", "rev-parse": "a" * 40 + "\n",
                        "status": ""}[argv[3]]
            self.fail("unexpected external command in mocked preparation")

        with patch.object(fixture, "fresh_root"), \
                patch.object(Path, "resolve", lambda path: path), \
                patch.object(Path, "is_symlink", return_value=False), \
                patch.object(Path, "is_file", return_value=True), \
                patch.object(fixture, "digest", side_effect=digest), \
                patch.object(fixture, "command", side_effect=command) as commands, \
                patch.object(fixture, "overlaps", return_value={"candidate": SUBNET, "conflicts": []}), \
                patch.object(fixture.os, "statvfs", return_value=SimpleNamespace(f_bavail=2**22, f_frsize=4096)), \
                patch.object(fixture.os, "open", side_effect=AssertionError("unexpected write")):
            return fixture.prepare(args), commands

    def test_preparation_receipt_and_environment_share_verified_pin(self):
        result, commands = self.mocked_prepare(self.args(expected_binary_sha256=SELECTED))
        self.assertEqual(result["preparation"]["binarySha256"], SELECTED)
        self.assertEqual(result["compose"]["services"]["serverware"]["environment"][ENV_KEY], "sha256:" + SELECTED)
        self.assertEqual(result["preparation"]["initializerSha256"], fixture.INITIALIZER_SHA256)
        self.assertFalse(result["preparation"]["launched"])
        self.assertTrue(commands.called)

    def test_preparation_legacy_args_keep_historical_pin(self):
        result, _ = self.mocked_prepare(self.args(), actual_binary=fixture.BINARY_SHA256)
        self.assertEqual(result["preparation"]["binarySha256"], fixture.BINARY_SHA256)
        self.assertEqual(result["compose"]["services"]["serverware"]["environment"][ENV_KEY],
                         "sha256:" + fixture.BINARY_SHA256)

    def test_file_digest_mismatch_fails_before_external_checks(self):
        for selected, actual, initializer in ((SELECTED, fixture.BINARY_SHA256, fixture.INITIALIZER_SHA256),
                (fixture.BINARY_SHA256, SELECTED, fixture.INITIALIZER_SHA256), (SELECTED, SELECTED, "0" * 64)):
            with self.subTest(selected=selected, actual=actual, initializer=initializer), \
                    patch.object(fixture, "fresh_root"), \
                    patch.object(Path, "resolve", lambda path: path), \
                    patch.object(Path, "is_symlink", return_value=False), \
                    patch.object(fixture, "digest", side_effect=lambda path: actual if path == BINARY else initializer), \
                    patch.object(fixture, "command") as command:
                with self.assertRaises(ValueError):
                    fixture.prepare(self.args(expected_binary_sha256=selected))
                command.assert_not_called()

    def test_cli_default_and_explicit_selection(self):
        base = ["prepare", "--source", str(SOURCE), "--binary", str(BINARY),
                "--initializer", str(INITIALIZER), "--job-root", str(ROOT)]
        for extra, expected in (([], fixture.BINARY_SHA256), (["--expected-binary-sha256", SELECTED], SELECTED)):
            with self.subTest(expected=expected), patch("sys.argv", base + extra), \
                    patch("sys.stdout", new_callable=StringIO), patch.object(fixture, "prepare", return_value={}) as prepare:
                fixture.main()
                self.assertEqual(prepare.call_args.args[0].expected_binary_sha256, expected)

    def test_cli_rejects_noncanonical_pin_before_preparation(self):
        base = ["prepare", "--source", str(SOURCE), "--binary", str(BINARY),
                "--initializer", str(INITIALIZER), "--job-root", str(ROOT), "--expected-binary-sha256"]
        for invalid in ("sha256:" + SELECTED, SELECTED.upper(), " " + SELECTED, SELECTED + "\n"):
            with self.subTest(value=invalid), patch("sys.argv", base + [invalid]), \
                    patch("sys.stderr", new_callable=StringIO), patch.object(fixture, "prepare") as prepare:
                with self.assertRaises(SystemExit) as raised:
                    fixture.main()
                self.assertEqual(raised.exception.code, 2)
                prepare.assert_not_called()


if __name__ == "__main__":
    unittest.main()
