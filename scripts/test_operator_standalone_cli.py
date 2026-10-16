#!/usr/bin/env python3
"""Focused local CLI checks: no Docker, network, real secrets or state changes."""
from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import serverware_standalone as cli
from operator_install.config import InstallError


class CommandLineTests(unittest.TestCase):
    def test_help_and_defaults(self):
        with redirect_stdout(io.StringIO()) as output, self.assertRaises(SystemExit) as exited:
            cli.parser().parse_args(["--help"])
        self.assertEqual(exited.exception.code, 0)
        self.assertIn("never", output.getvalue())
        args = cli.parser().parse_args(["status"])
        self.assertEqual(args.state_dir, Path("/var/lib/serverware-standalone"))

    def test_private_password_file(self):
        with tempfile.TemporaryDirectory(prefix="serverware-cli-") as folder:
            path = Path(folder) / "password"
            path.write_bytes(b"synthetic-password-only\n")
            path.chmod(0o600)
            self.assertEqual(cli.password_file(path), b"synthetic-password-only")
            path.chmod(0o400)
            self.assertEqual(cli.password_file(path), b"synthetic-password-only")
            path.chmod(0o644)
            with self.assertRaises(InstallError):
                cli.password_file(path)
            path.chmod(0o600)
            path.write_bytes(b"synthetic\nsecond-line")
            with self.assertRaises(InstallError):
                cli.password_file(path)
            path.write_bytes(b"synthetic-password-only\n")
            link = Path(folder) / "symlink"
            link.symlink_to(path)
            with self.assertRaises(OSError):
                cli.password_file(link)
            alias = Path(folder) / "hardlink"
            os.link(path, alias)
            with self.assertRaises(InstallError):
                cli.password_file(path)

    def test_noninteractive_init_does_not_read_stdin(self):
        with patch("sys.stdin.isatty", return_value=False), patch.object(cli.getpass, "getpass") as prompt:
            with self.assertRaises(InstallError):
                cli.console_password(None)
            prompt.assert_not_called()

    def test_password_confirmation(self):
        with patch("sys.stdin.isatty", return_value=True), patch.object(cli.getpass, "getpass", side_effect=["one", "two"]):
            with self.assertRaises(InstallError):
                cli.console_password(None)

    def test_partial_cache_selection_does_not_build(self):
        args = cli.parser().parse_args(["build", "--cached-binary", "/not-used"])
        with self.assertRaisesRegex(InstallError, "together"):
            cli.dispatch(args)

    def test_readiness_wait_is_bounded(self):
        for timeout in (0, 601):
            args = cli.parser().parse_args(["start", "--timeout", str(timeout)])
            with patch("operator_install.lifecycle.start") as start:
                with self.assertRaises(InstallError):
                    cli.dispatch(args)
                start.assert_not_called()

    def test_status_dispatch_is_read_only(self):
        args = cli.parser().parse_args(["status", "--state-dir", "/not-used"])
        with patch("operator_install.lifecycle.status", return_value={"status": "stopped"}) as status, \
                patch("operator_install.lifecycle.start") as start:
            self.assertEqual(cli.dispatch(args), {"status": "stopped"})
            status.assert_called_once_with(Path("/not-used"))
            start.assert_not_called()

    def test_os_errors_do_not_echo_private_content(self):
        with patch.object(cli, "dispatch", side_effect=OSError("synthetic-private-value")), \
                redirect_stderr(io.StringIO()) as errors, redirect_stdout(io.StringIO()) as output:
            self.assertEqual(cli.main(["status", "--json"]), 1)
        self.assertNotIn("synthetic-private-value", errors.getvalue())
        self.assertIn('"ok": false', errors.getvalue())
        self.assertEqual(output.getvalue(), "")

    def test_private_diagnostic_location_is_available_without_contents(self):
        error = InstallError("A local command failed; private diagnostics were retained.")
        error.diagnostic_path = "/tmp/serverware-command-error-example.log"
        with patch.object(cli, "dispatch", side_effect=error), redirect_stderr(io.StringIO()) as errors:
            self.assertEqual(cli.main(["start", "--json"]), 1)
        self.assertIn('"diagnostic_path": "/tmp/serverware-command-error-example.log"', errors.getvalue())

    def test_init_prints_copyable_next_command(self):
        with redirect_stdout(io.StringIO()) as output:
            cli.show({"operation": "init", "status": "initialized", "state_dir": "/private/my instance"}, as_json=False)
        self.assertIn("Next: sudo python3 scripts/serverware_standalone.py start --state-dir '/private/my instance'", output.getvalue())


if __name__ == "__main__":
    unittest.main()
