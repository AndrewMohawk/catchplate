#!/usr/bin/env python3
"""API/CLI routing controls only: no DB import, connection or authority proof."""
from __future__ import annotations

import contextlib
import importlib.util
import io
from pathlib import Path
import sys
from types import ModuleType
import unittest
from unittest.mock import Mock, call, patch


SOURCE = Path(__file__).with_name("bootstrap_metadata_store.py")
spec = importlib.util.spec_from_file_location("bootstrap_metadata_store", SOURCE)
cli = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cli)


def configuration():
    # These inert values select CLI dispatch only. No validator accepts them as
    # real credentials, pins, roles or a provisioned database in this suite.
    return {
        **{name: "explicit-test-selection" for name in cli.REQUIRED},
        **{"CATCHPLATE_" + name + "_BACKEND": "postgres" for name in cli.BACKENDS},
        "CATCHPLATE_PROCESS_MODE": "metadata-bootstrap",
    }


class BootstrapMetadataStoreTests(unittest.TestCase):
    def invoke(self, arguments, environment, target=None):
        output, errors = io.StringIO(), io.StringIO()
        with patch.dict(cli.os.environ, environment, clear=True), \
                patch.object(cli, "_load_db", return_value=target) as loader, \
                contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            status = cli.main(arguments)
        return status, output.getvalue(), errors.getvalue(), loader

    def test_help_and_unknown_arguments_never_import_database(self):
        status, output, errors, loader = self.invoke(["--help"], {})
        self.assertEqual((status, errors), (0, ""))
        self.assertIn("partial initialization", output)
        loader.assert_not_called()
        status, output, errors, loader = self.invoke(["secret-DSN-argument"], configuration())
        self.assertEqual((status, output), (2, ""))
        self.assertNotIn("secret-DSN-argument", errors)
        loader.assert_not_called()

    def test_normal_runtime_and_missing_mode_are_refused_before_import(self):
        for mode in ("", "catchplate", "policy-authority-executor"):
            with self.subTest(mode=mode):
                selected = configuration()
                selected["CATCHPLATE_PROCESS_MODE"] = mode
                status, _, _, loader = self.invoke([], selected)
                self.assertEqual(status, 2)
                loader.assert_not_called()

    def test_sqlite_and_missing_backends_are_refused_before_import(self):
        for backend in cli.BACKENDS:
            for value in ("sqlite", ""):
                with self.subTest(backend=backend, value=value):
                    selected = configuration()
                    selected["CATCHPLATE_" + backend + "_BACKEND"] = value
                    status, _, _, loader = self.invoke([], selected)
                    self.assertEqual(status, 2)
                    loader.assert_not_called()

    def test_each_missing_database_identity_is_refused_before_import(self):
        for name in cli.REQUIRED:
            with self.subTest(name=name):
                selected = configuration()
                del selected[name]
                status, _, _, loader = self.invoke([], selected)
                self.assertEqual(status, 2)
                loader.assert_not_called()
        selected = configuration()
        selected["CATCHPLATE_WEBAUTHN_RECOVERY_WITNESS_BACKEND"] = "postgres"
        status, _, _, loader = self.invoke([], selected)
        self.assertEqual(status, 2)
        loader.assert_not_called()

    def target(self):
        target = Mock()
        target.metadata_store_backend_name.return_value = "postgres"
        target.audit_store_backend_name.return_value = "postgres"
        return target

    def test_dispatch_uses_existing_guards_and_exact_contract(self):
        target = self.target()
        status, output, errors, loader = self.invoke([], configuration(), target)
        self.assertEqual((status, errors), (0, ""))
        self.assertIn("readiness are not asserted", output)
        loader.assert_called_once_with()
        self.assertEqual(target.mock_calls, [
            call._reject_runtime_metadata_admin_dsn(),
            call.metadata_store_backend_name(), call.audit_store_backend_name(),
            call._successor_installation_pins("ISSUER"),
            call._successor_installation_pins("EXECUTOR"),
            call._successor_installation_pins("RECOVERY"),
            call._policy_authority_verifier_public_key(),
            call.init_db(bootstrap_contract_id="catchplate.metadataStoreBootstrap/v1"),
        ])

    def test_guard_rejection_prevents_dispatch_without_secret_output(self):
        target = self.target()
        target._successor_installation_pins.side_effect = ValueError("postgres://secret:password@host/db")
        status, output, errors, _ = self.invoke([], configuration(), target)
        self.assertEqual((status, output), (1, ""))
        self.assertNotIn("password", errors)
        target.init_db.assert_not_called()

    def test_installer_failure_reports_possible_partial_state_without_secrets(self):
        target = self.target()
        target.init_db.side_effect = RuntimeError("postgres://secret:password@host/db")
        status, output, errors, _ = self.invoke([], configuration(), target)
        self.assertEqual((status, output), (1, ""))
        self.assertNotIn("password", errors)
        self.assertIn("partial initialization may remain", errors)
        target.init_db.assert_called_once_with(bootstrap_contract_id=cli.CONTRACT)

    def test_python_api_has_same_guard_order_without_cli_output(self):
        cli_target, api_target = self.target(), self.target()
        self.assertEqual(self.invoke([], configuration(), cli_target)[0], 0)
        output, errors = io.StringIO(), io.StringIO()
        with patch.dict(cli.os.environ, configuration(), clear=True), \
                patch.object(cli, "_load_db", return_value=api_target) as loader, \
                contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            self.assertIsNone(cli.bootstrap())
        loader.assert_called_once_with()
        self.assertEqual(api_target.mock_calls, cli_target.mock_calls)
        self.assertEqual((output.getvalue(), errors.getvalue()), ("", ""))

    def test_python_api_preserves_exact_preflight_and_execution_errors(self):
        failure = ValueError("synthetic-private-error")
        with patch.object(cli, "_preflight", side_effect=failure), \
                patch.object(cli, "_load_db") as loader:
            with self.assertRaises(ValueError) as caught:
                cli.bootstrap()
        self.assertIs(caught.exception, failure)
        loader.assert_not_called()
        for method in ("_reject_runtime_metadata_admin_dsn", "_successor_installation_pins",
                       "_policy_authority_verifier_public_key", "init_db"):
            for failure in (RuntimeError("synthetic-private-error"), KeyboardInterrupt()):
                with self.subTest(method=method, error=type(failure).__name__):
                    target = self.target()
                    getattr(target, method).side_effect = failure
                    with patch.dict(cli.os.environ, configuration(), clear=True), \
                            patch.object(cli, "_load_db", return_value=target):
                        with self.assertRaises(type(failure)) as caught:
                            cli.bootstrap()
                    self.assertIs(caught.exception, failure)
                    if method != "init_db":
                        target.init_db.assert_not_called()

    def test_initial_rbac_validation_and_exact_selection_shared_by_api_and_cli(self):
        # A routing fixture, not acceptance of these synthetic clock values.
        validator_module = ModuleType("catchplate.authority_local_rbac_bootstrap")
        validator_module.selected_timestamp = Mock()
        arguments = dict(initial_rbac_timestamp_epoch_ns=2000,
            original_issued_at_unix_ns=1000, original_expires_at_unix_ns=3000)
        selection = dict(initialRbacTimestamp=2000, issuedAtUnixNanos=1000, expiresAtUnixNanos=3000)
        entries = ((lambda: cli.main([], **arguments), 0, 2),
                   (lambda: cli.bootstrap(**arguments), None, "raised"))
        for entry, success_status, failure_status in entries:
            for failure in (None, ValueError("synthetic-private-error")):
                target = self.target()
                validator_module.selected_timestamp.reset_mock()
                validator_module.selected_timestamp.side_effect = failure
                output, errors = io.StringIO(), io.StringIO()
                with patch.dict(cli.os.environ, configuration(), clear=True), \
                        patch.dict(sys.modules, {validator_module.__name__: validator_module}), \
                        patch.object(cli, "_load_db", return_value=target) as loader, \
                        contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
                    try:
                        status = entry()
                    except ValueError as error:
                        self.assertIs(error, failure)
                        status = "raised"
                validator_module.selected_timestamp.assert_called_once_with(selection)
                if failure is None:
                    self.assertEqual(status, success_status)
                    target.init_db.assert_called_once_with(bootstrap_contract_id=cli.CONTRACT,
                        local_initial_rbac=selection)
                else:
                    self.assertEqual(status, failure_status)
                    loader.assert_not_called()
                self.assertNotIn("synthetic-private-error", output.getvalue() + errors.getvalue())


if __name__ == "__main__":
    unittest.main()
