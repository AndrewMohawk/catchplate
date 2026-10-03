#!/usr/bin/env python3
"""Synthetic failure-only CLI diagnostics; no authority owner is admitted."""
from __future__ import annotations

import io
import ast
import os
from pathlib import Path
import re
import stat
import sys
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.authority import local_startup as cli
from serverware import authority_fd_entrypoint as entrypoint
from serverware import authority_launcher as launcher

SECRET = "sentinel-private-credential-do-not-print"
ARGS = ["--plan-fd", "4", "--plan-sha256", "sha256:" + "1" * 64, "--listener-fd", "3"]


def nested_failure(depth):
    private_local = SECRET
    if depth:
        return nested_failure(depth - 1)
    raise ValueError(private_local)


class FailureDiagnosticsTests(unittest.TestCase):
    def test_bounded_chain_frames_and_strict_owner_metadata_exclude_secrets(self):
        previous = None
        for _ in range(7):
            try:
                nested_failure(10)
            except ValueError as error:
                error.__cause__ = previous
                previous = error
        for admitted, status, expected_admitted, expected_status in (
            (True, -15, "1", "-15"), (False, None, "0", "none"),
            (1, True, "unknown", "unknown"), (SECRET, 2**40, "unknown", "unknown"),
        ):
            with self.subTest(admitted=expected_admitted, status=expected_status):
                output = io.StringIO()
                with patch.object(cli.sys, "stderr", output):
                    cli._failure_diagnostics(previous, SimpleNamespace(admitted=admitted, child_status=status))
                text = output.getvalue()
                self.assertNotIn(SECRET, text)
                self.assertNotIn(str(ROOT), text)
                self.assertTrue(text.isascii())
                self.assertIn("LOCAL_STARTUP_FAILURE_ADMITTED=" + expected_admitted, text)
                self.assertIn("LOCAL_STARTUP_FAILURE_CHILD_STATUS=" + expected_status, text)
                causes = [line for line in text.splitlines() if line.startswith("LOCAL_STARTUP_FAILURE_CAUSE=")]
                frames = [line for line in text.splitlines() if line.startswith("LOCAL_STARTUP_FAILURE_FRAME=")]
                self.assertEqual(len(causes), 5)
                self.assertEqual(len(frames), 40)
                self.assertTrue(all(re.fullmatch(r"LOCAL_STARTUP_FAILURE_FRAME=[0-4]:[A-Za-z0-9_.<>-]{1,96}:[A-Za-z0-9_.<>-]{1,96}:[0-9]+", line) for line in frames))

    def run_failure(self, output, *, close_error=None):
        def fail():
            try:
                raise ValueError(SECRET)
            except ValueError:
                raise RuntimeError(SECRET)
        owner = SimpleNamespace(admitted=False, child_status=None, run=fail,
            close=Mock(side_effect=close_error))
        module = ModuleType("serverware.authority_local_startup")
        module.LocalAuthorityStartup = SimpleNamespace(open=Mock(return_value=owner))
        module.encode = Mock(side_effect=AssertionError("failure fixture must not encode success"))
        with patch.dict(sys.modules, {module.__name__: module}), \
                patch.object(cli.signal, "signal"), patch.object(cli.sys, "stderr", output):
            result = cli.main(ARGS)
        owner.close.assert_called_once_with(cancel=True)
        module.encode.assert_not_called()
        self.assertEqual(result, 1)

    def test_main_reports_context_without_messages_and_still_cleans_up(self):
        output = io.StringIO()
        self.run_failure(output)
        text = output.getvalue()
        self.assertNotIn(SECRET, text)
        self.assertIn("LOCAL_STARTUP_FAILURE_CAUSE=0:RuntimeError", text)
        self.assertIn("LOCAL_STARTUP_FAILURE_CAUSE=1:ValueError", text)
        self.assertIn("no readiness asserted", text)

    def test_broken_diagnostic_output_never_prevents_cleanup_or_return_one(self):
        class BrokenOutput:
            def write(self, value):
                raise OSError(SECRET)
            def flush(self):
                raise OSError(SECRET)
        for close_error in (None, RuntimeError(SECRET)):
            with self.subTest(cleanup_failed=close_error is not None):
                self.run_failure(BrokenOutput(), close_error=close_error)


class ChildFailureDiagnosticsTests(unittest.TestCase):
    def private_metadata(self, **changes):
        values = dict(st_dev=10, st_ino=20, st_mode=stat.S_IFREG | 0o600,
                      st_uid=0, st_gid=0, st_nlink=1)
        values.update(changes)
        return SimpleNamespace(**values)

    def test_child_reports_bounded_metadata_without_messages_paths_or_locals(self):
        previous = None
        for _ in range(7):
            try:
                nested_failure(10)
            except ValueError as error:
                error.__cause__ = previous
                previous = error
        for subject in (entrypoint, launcher):
            with self.subTest(subject=subject.__name__), \
                    patch.object(subject.os, "fstat", return_value=self.private_metadata()), \
                    patch.object(subject.fcntl, "fcntl", return_value=os.O_WRONLY), \
                    patch.object(subject.os, "write") as written:
                subject._startup_failure(previous)
                written.assert_called_once()
                descriptor, raw = written.call_args.args
                self.assertEqual(descriptor, 2)
                self.assertLessEqual(len(raw), 16384)
                text = raw.decode("ascii")
                self.assertNotIn(SECRET, text)
                self.assertNotIn(str(ROOT), text)
                self.assertEqual(text.count("AUTHORITY_CHILD_STARTUP_FAILURE_CAUSE="), 5)
                self.assertEqual(text.count("AUTHORITY_CHILD_STARTUP_FAILURE_FRAME="), 40)
                self.assertTrue(all(re.fullmatch(
                    r"AUTHORITY_CHILD_STARTUP_FAILURE_(?:CAUSE=[0-4]:[A-Za-z0-9_.<>-]{1,96}|FRAME=[0-4]:[A-Za-z0-9_.<>-]{1,96}:[A-Za-z0-9_.<>-]{1,96}:[0-9]+)", line)
                    for line in text.splitlines()))
                written.reset_mock()
                try:
                    exec(compile("raise ValueError(secret)", "/proc/self/fd/4096", "exec"), {"secret": SECRET})
                except ValueError as error:
                    subject._startup_failure(error)
                self.assertIn(b":bootstrap:<module>:", written.call_args.args[1])
                self.assertNotIn(b"4096", written.call_args.args[1])

    def test_child_rejects_nonprivate_sinks_and_broken_output_preserves_failure(self):
        for subject in (entrypoint, launcher):
            for changes, flags in (
                ({"st_uid": 1000}, os.O_WRONLY), ({"st_gid": 1000}, os.O_WRONLY),
                ({"st_nlink": 2}, os.O_WRONLY), ({"st_mode": stat.S_IFREG | 0o644}, os.O_WRONLY),
                ({"st_mode": stat.S_IFSOCK | 0o600}, os.O_WRONLY), ({}, os.O_RDONLY),
            ):
                with self.subTest(subject=subject.__name__, changes=changes, flags=flags), \
                        patch.object(subject.os, "fstat", return_value=self.private_metadata(**changes)), \
                        patch.object(subject.fcntl, "fcntl", return_value=flags), \
                        patch.object(subject.os, "write") as written:
                    subject._startup_failure(ValueError(SECRET))
                    written.assert_not_called()
            cleaned = []

            def failing_main():
                try:
                    raise ValueError(SECRET)
                finally:
                    cleaned.append(True)

            with patch.object(subject, "main", side_effect=failing_main), \
                    patch.object(subject.os, "fstat", return_value=self.private_metadata()), \
                    patch.object(subject.fcntl, "fcntl", return_value=os.O_WRONLY), \
                    patch.object(subject.os, "write", side_effect=OSError(SECRET)):
                self.assertEqual(subject._startup_main(), 1)
                self.assertEqual(cleaned, [True])
            class IntegerExit(int):
                pass
            for code in (None, 0, 2, 127, False, True, IntegerExit(4)):
                failure = SystemExit(code)
                with patch.object(subject, "main", side_effect=failure), \
                        patch.object(subject, "_startup_failure") as report:
                    with self.assertRaises(SystemExit) as actual:
                        subject._startup_main()
                    self.assertIs(actual.exception, failure)
                    report.assert_not_called()
            with patch.object(subject, "main", side_effect=KeyboardInterrupt), \
                    patch.object(subject, "_startup_failure") as report:
                self.assertEqual(subject._startup_main(), 130)
                report.assert_called_once()

    def test_both_measured_scripts_share_formatter_and_stdio_has_no_new_slots(self):
        trees = [ast.parse(Path(subject.__file__).read_text()) for subject in (entrypoint, launcher)]
        for name in ("_private_startup_stderr", "_startup_failure", "_startup_main"):
            definitions = [next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == name)
                           for tree in trees]
            self.assertEqual(ast.dump(definitions[0]), ast.dump(definitions[1]))
        tree = ast.parse((ROOT / "serverware/authority_local_startup.py").read_text())
        owner = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "LocalAuthorityStartup")
        spawn = next(node for node in owner.body if isinstance(node, ast.FunctionDef) and node.name == "_spawn")
        stdio = [node for node in ast.walk(spawn) if isinstance(node, ast.For)
                 and isinstance(node.iter, ast.Tuple)]
        self.assertEqual([[value.value for value in node.iter.elts] for node in stdio], [[0, 1]])
        # Existing stderr is inherited directly; no diagnostic descriptor is
        # added to the signed >=3 roster or local admission transport.
        calls = [node for node in ast.walk(spawn) if isinstance(node, ast.Call)]
        self.assertTrue(any(isinstance(node.func, ast.Attribute) and node.func.attr == "set_inheritable"
                            and isinstance(node.args[0], ast.Constant) and node.args[0].value == 2 for node in calls))


if __name__ == "__main__":
    unittest.main()
