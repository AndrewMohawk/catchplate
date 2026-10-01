#!/usr/bin/env python3
"""CLI routing/refusal controls only: no DB import, connection or authority proof."""
from __future__ import annotations

import contextlib
import importlib.util
import io
from pathlib import Path
import sys
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
        **{"SERVERWARE_" + name + "_BACKEND": "postgres" for name in cli.BACKENDS},
        "SERVERWARE_PROCESS_MODE": "metadata-bootstrap",
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
        for mode in ("", "serverware", "policy-authority-executor"):
            with self.subTest(mode=mode):
                selected = configuration()
                selected["SERVERWARE_PROCESS_MODE"] = mode
                status, _, _, loader = self.invoke([], selected)
                self.assertEqual(status, 2)
                loader.assert_not_called()

    def test_sqlite_and_missing_backends_are_refused_before_import(self):
        for backend in cli.BACKENDS:
            for value in ("sqlite", ""):
                with self.subTest(backend=backend, value=value):
                    selected = configuration()
                    selected["SERVERWARE_" + backend + "_BACKEND"] = value
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
        selected["SERVERWARE_WEBAUTHN_RECOVERY_WITNESS_BACKEND"] = "postgres"
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
            call.init_db(bootstrap_contract_id="serverware.metadataStoreBootstrap/v1"),
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


if __name__ == "__main__":
    unittest.main()
