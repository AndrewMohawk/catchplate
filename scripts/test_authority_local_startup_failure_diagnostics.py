#!/usr/bin/env python3
"""Synthetic failure-only CLI diagnostics; no authority owner is admitted."""
from __future__ import annotations

import io
from pathlib import Path
import re
import sys
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.authority import local_startup as cli

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


if __name__ == "__main__":
    unittest.main()
