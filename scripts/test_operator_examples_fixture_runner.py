"""Pure runner configuration/diagnostic checks: no Docker, builds, or providers."""
from __future__ import annotations

import contextlib
import io
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from scripts import run_operator_x_examples_fixture as runner
from scripts.run_operator_alchemy_examples_fixture import AlchemyRun


class ExamplesRunnerTests(unittest.TestCase):
    def test_x_profile_defaults_remain_exact(self):
        self.assertEqual(runner.Run.SOURCE_SCRIPT, "scripts/run_operator_x_examples_fixture.py")
        self.assertEqual(runner.Run.SOURCE_FILE, Path(runner.__file__).resolve())
        self.assertEqual(runner.Run.RECIPE_MODULE, "scripts.prepare_operator_x_fixture")
        self.assertEqual(runner.Run.CHECKER_MODULE, "scripts.check_operator_x_examples")
        self.assertEqual(runner.Run.CHECKER_SCRIPT, "/app/scripts/check_operator_x_examples.py")
        self.assertEqual(runner.Run.PROVIDER_SERVICE, "x")
        self.assertEqual(runner.Run.PROVIDER_PKI_SERVICE, "x-pki")
        self.assertEqual(runner.Run.NODE_EXAMPLE_DIRECTORY, "examples/x-username-node")
        self.assertEqual(runner.Run.GO_MOUNT_TARGET, "/example-go/x-username")
        self.assertEqual(runner.Run.CLAIM_SCHEMA, "catchplate.privateXExamplesRunClaim/v1")
        self.assertEqual(runner.Run.TERMINAL_SCHEMA, "catchplate.privateXExamplesRun/v1")
        self.assertEqual(runner.Run.REAL_PROVIDER_VERIFIED, "realXVerified")
        self.assertEqual(runner.RUNTIME_SERVICES,
            {"network", "x", "catchplate", "decision-gate-rs", "edge", "check"})

    def test_alchemy_changes_only_fixed_profile_constants(self):
        overrides = {
            "SOURCE_FILE", "SOURCE_SCRIPT", "RECIPE_MODULE", "CHECKER_MODULE", "CHECKER_SCRIPT",
            "PROVIDER_SERVICE", "PROVIDER_PKI_SERVICE", "NODE_EXAMPLE_DIRECTORY", "GO_MOUNT_TARGET",
            "CLAIM_SCHEMA", "TERMINAL_SCHEMA", "REAL_PROVIDER_VERIFIED",
        }
        self.assertEqual({name for name in vars(AlchemyRun) if not name.startswith("__")}, overrides)
        for method in ("execute", "command", "save", "cleanup", "container_rows", "no_project_networks"):
            self.assertIs(getattr(AlchemyRun, method), getattr(runner.Run, method))
        source = Path(runner.__file__).resolve().parent.parent
        self.assertEqual(AlchemyRun.SOURCE_FILE, source / AlchemyRun.SOURCE_SCRIPT)
        self.assertEqual(AlchemyRun.SOURCE_SCRIPT, "scripts/run_operator_alchemy_examples_fixture.py")
        self.assertEqual(AlchemyRun.RECIPE_MODULE, "scripts.prepare_operator_alchemy_fixture")
        self.assertEqual(AlchemyRun.CHECKER_MODULE, "scripts.check_operator_alchemy_examples")
        self.assertEqual(AlchemyRun.CHECKER_SCRIPT, "/app/scripts/check_operator_alchemy_examples.py")
        self.assertEqual(AlchemyRun.PROVIDER_SERVICE, "alchemy")
        self.assertEqual(AlchemyRun.PROVIDER_PKI_SERVICE, "alchemy-pki")
        self.assertEqual(AlchemyRun.NODE_EXAMPLE_DIRECTORY, "examples/alchemy-chain-status-node")
        self.assertEqual(AlchemyRun.GO_MOUNT_TARGET, "/example-go/alchemy-chain-status")
        self.assertEqual(AlchemyRun.CLAIM_SCHEMA, "catchplate.privateAlchemyExamplesRunClaim/v1")
        self.assertEqual(AlchemyRun.TERMINAL_SCHEMA, "catchplate.privateAlchemyExamplesRun/v1")
        self.assertEqual(AlchemyRun.REAL_PROVIDER_VERIFIED, "realAlchemyVerified")

    def test_cli_retains_input_validation_without_profile_selection(self):
        arguments = ["runner"]
        for name in ("source", "job-root", "evidence", "binary", "node", "go",
                "python-runtime", "python-packages", "initializer"):
            arguments.extend(["--" + name, "/synthetic/" + name])
        arguments.extend(["--commit", "a" * 40, "--expected-binary-sha256", "b" * 64,
            "--expected-go-sha256", "c" * 64])
        instance = SimpleNamespace(execute=mock.Mock(return_value=0))
        constructor = mock.Mock(return_value=instance)
        with mock.patch.object(runner.sys, "argv", arguments), mock.patch.object(runner.os, "umask"):
            self.assertEqual(runner.main(constructor), 0)
        parsed = constructor.call_args.args[0]
        self.assertEqual(parsed.go, Path("/synthetic/go"))
        self.assertEqual(parsed.expected_go_sha256, "c" * 64)
        self.assertEqual(parsed.commit, "a" * 40)
        instance.execute.assert_called_once_with()
        for forbidden in ("--recipe-module", "--checker-module", "--provider-service",
                "--go-mount-target", "--node-example-directory", "--timeout-seconds"):
            with self.subTest(forbidden=forbidden), contextlib.redirect_stderr(io.StringIO()), \
                    mock.patch.object(runner.sys, "argv", arguments + [forbidden, "untrusted"]), \
                    mock.patch.object(runner.os, "umask"), \
                    self.assertRaises(SystemExit):
                runner.main(constructor)
        self.assertEqual(constructor.call_count, 1)

    def test_absolute_paths_and_hashes_remain_strict(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            link = root / "alias"
            link.symlink_to(root, target_is_directory=True)
            self.assertEqual(runner.absolute_path(str(root)), root)
            for value in ("relative", str(link), str(root) + "/../" + root.name):
                with self.subTest(path=value), self.assertRaises(runner.argparse.ArgumentTypeError):
                    runner.absolute_path(value)
        self.assertEqual(runner.sha256("a" * 64), "a" * 64)
        for value in ("A" * 64, "a" * 63, "a" * 65, "a" * 63 + " "):
            with self.subTest(hash=value), self.assertRaises(runner.argparse.ArgumentTypeError):
                runner.sha256(value)

    def test_failure_site_excludes_exception_details_and_generic_guard(self):
        source = Path(__file__).resolve().parent.parent
        try:
            runner.require(False, "synthetic-secret-must-never-appear")
        except ValueError as error:
            site = runner.failure_site(error, source)
        self.assertEqual(set(site), {"module", "line"})
        self.assertEqual(site["module"], "scripts.test_operator_examples_fixture_runner")
        self.assertIs(type(site["line"]), int)
        self.assertGreater(site["line"], 0)
        self.assertNotIn("synthetic-secret", str(site))

    def test_failure_site_omits_external_and_unraised_errors(self):
        self.assertIsNone(runner.failure_site(ValueError("unraised-secret"), Path("/synthetic")))
        try:
            raise ValueError("external-secret")
        except ValueError as error:
            self.assertIsNone(runner.failure_site(error, Path("/synthetic")))


if __name__ == "__main__":
    unittest.main()
