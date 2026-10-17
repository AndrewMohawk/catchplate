#!/usr/bin/env python3
"""Focused local CLI checks: no Docker, network, real secrets or state changes."""
from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import io
import hashlib
import json
import os
from pathlib import Path
import tempfile
import tarfile
import unittest
from unittest.mock import patch

import catchplate_standalone as cli
from operator_install.config import InstallError


class CommandLineTests(unittest.TestCase):
    def test_help_and_defaults(self):
        with redirect_stdout(io.StringIO()) as output, self.assertRaises(SystemExit) as exited:
            cli.parser().parse_args(["--help"])
        self.assertEqual(exited.exception.code, 0)
        self.assertIn("never", output.getvalue())
        args = cli.parser().parse_args(["status"])
        self.assertEqual(args.state_dir, Path("/var/lib/catchplate-standalone"))

    def test_private_password_file(self):
        with tempfile.TemporaryDirectory(prefix="catchplate-cli-") as folder:
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

    def test_prior_cache_namespace_is_explicit_and_build_only(self):
        args = cli.parser().parse_args(["build", "--prior-cache-namespace", "prior-project"])
        with patch("operator_install.build.build", return_value={"status": "built"}) as build:
            self.assertEqual(cli.dispatch(args), {"status": "built"})
            self.assertEqual(build.call_args.kwargs["prior_cache_namespace"], "prior-project")
        self.assertIsNone(cli.parser().parse_args(["build"]).prior_cache_namespace)

    def test_verified_binary_can_use_fresh_or_cached_dependencies(self):
        for extra in ([], ["--cached-app-image", "cached-image"]):
            args = cli.parser().parse_args(["build", "--cached-binary", "/binary",
                                           "--compiler-inputs", "/receipt", *extra])
            with patch("operator_install.build.build", return_value={"status": "built"}) as build:
                self.assertEqual(cli.dispatch(args), {"status": "built"})
                self.assertEqual(build.call_args.kwargs["cached_binary"], Path("/binary"))
                self.assertEqual(build.call_args.kwargs["compiler_inputs"], Path("/receipt"))
                self.assertEqual(build.call_args.kwargs["cached_app_image"], "cached-image" if extra else None)

    def test_dependency_image_alone_is_not_a_binary_proof(self):
        args = cli.parser().parse_args(["build", "--cached-app-image", "cached-image"])
        with patch("operator_install.build.build") as build:
            with self.assertRaises(InstallError):
                cli.dispatch(args)
            build.assert_not_called()

    def test_verified_assembly_selects_only_requested_dependency_stage(self):
        from operator_install import build
        for app_image in (None, "cached-image"):
            with self.subTest(app_image=app_image), tempfile.TemporaryDirectory(prefix="catchplate-build-check-") as folder:
                root = Path(folder)
                binary, proof_path = root / "binary", root / "proof"
                binary.write_bytes(b"synthetic-normal")
                proof_path.write_text("{}")
                digest = hashlib.sha256(binary.read_bytes()).hexdigest()
                proof = {"binarySha256": digest}
                entries = {"catchplate/app.py": {"raw": b"pass\n", "mode": 0o644, "sha256": "a" * 64}}
                observed = {}
                def command(argv, **kwargs):
                    if argv[:2] == ["docker", "info"]:
                        return b'{"OSType":"linux","Architecture":"amd64"}'
                    if argv[:3] == ["docker", "image", "tag"]:
                        return b""
                    if argv[:2] == ["docker", "build"]:
                        observed["argv"] = argv
                        with tarfile.open(fileobj=kwargs["stdin"], mode="r:") as archive:
                            observed["metadata"] = json.load(archive.extractfile("artifact/metadata.json"))
                            self.assertEqual(archive.extractfile("artifact/catchplate-decision-gate").read(), binary.read_bytes())
                        return b""
                    if argv[:2] == ["docker", "run"]:
                        return json.dumps({**{key: value for key, value in observed["metadata"].items() if key != "expectedBinaryDigest"},
                                           "dataPlaneBinaryDigest": "sha256:" + digest}).encode()
                    raise AssertionError("unexpected command")
                with patch.object(build, "_run", side_effect=command), \
                     patch.object(build, "_source", return_value=("b" * 40, entries)), \
                     patch.object(build, "_cached_proof", return_value=(binary.read_bytes(), proof)) as verify, \
                     patch.object(build, "_image", return_value={"Id": "sha256:" + "c" * 64}):
                    result = build.build(root, cached_binary=binary, compiler_inputs=proof_path, cached_app_image=app_image)
                verify.assert_called_once()
                self.assertFalse(result["compilerInvoked"])
                self.assertIn("BINARY_STAGE=cached-binary", observed["argv"])
                self.assertEqual("DEPENDENCY_STAGE=cached-dependencies" in observed["argv"], app_image is not None)
                self.assertEqual("--network" in observed["argv"], app_image is not None)
                self.assertEqual(result["dependencyMode"], "cached-image" if app_image else "pinned-fresh-stage")

    def test_prior_cache_namespace_validation_precedes_docker(self):
        from operator_install import build
        self.assertEqual(build._cache_namespace(None), "catchplate-standalone")
        self.assertEqual(build._cache_namespace("prior-project"), "prior-project")
        for value in ("", "UPPER", "../path", "name,sharing=shared", "a" * 65, 1):
            with patch.object(build, "_run") as command:
                with self.assertRaises(InstallError):
                    build.build(Path("/not-used"), prior_cache_namespace=value)
                command.assert_not_called()

    def test_prior_cache_namespace_cannot_be_silently_ignored(self):
        from operator_install import build
        with patch.object(build, "_run") as command:
            with self.assertRaises(InstallError):
                build.build(Path("/not-used"), cached_binary="/not-used", compiler_inputs="/not-used",
                            cached_app_image="unused", prior_cache_namespace="prior-project")
            command.assert_not_called()

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
        error.diagnostic_path = "/tmp/catchplate-command-error-example.log"
        with patch.object(cli, "dispatch", side_effect=error), redirect_stderr(io.StringIO()) as errors:
            self.assertEqual(cli.main(["start", "--json"]), 1)
        self.assertIn('"diagnostic_path": "/tmp/catchplate-command-error-example.log"', errors.getvalue())

    def test_init_prints_copyable_next_command(self):
        with redirect_stdout(io.StringIO()) as output:
            cli.show({"operation": "init", "status": "initialized", "state_dir": "/private/my instance"}, as_json=False)
        self.assertIn("Next: sudo python3 scripts/catchplate_standalone.py start --state-dir '/private/my instance'", output.getvalue())

    def test_long_commands_explain_wait_before_dispatch(self):
        errors = io.StringIO()
        def build(_args):
            self.assertIn("first source build may take several minutes", errors.getvalue())
            return {"status": "built"}
        with patch.object(cli, "dispatch", side_effect=build), redirect_stderr(errors), redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(["build"]), 0)
        with patch.object(cli, "dispatch", return_value={"status": "built"}), redirect_stderr(io.StringIO()) as machine_errors, \
                redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(["build", "--json"]), 0)
        self.assertEqual(machine_errors.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
