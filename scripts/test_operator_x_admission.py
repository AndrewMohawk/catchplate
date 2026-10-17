#!/usr/bin/env python3
"""Synthetic runtime selections with real private directories/SQLite/key bytes.

The config module and already-active demo/enrollment boundary are explicit test
doubles. Raw environment validation, filesystem pinning, connection checks and
DevelopmentOwner construction are real. These controls prove no actual serving,
publication ownership, lifecycle activation, native admission or provider access.
"""
from __future__ import annotations

from contextlib import ExitStack
from dataclasses import replace
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
from types import ModuleType
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import catchplate
from catchplate import oauth_application_owner, operator_demo
from catchplate import operator_provider_custody as custody
from catchplate import operator_provider_key as keys
from catchplate import operator_x_admission as admission

FLAG = "CATCHPLATE_OPERATOR_MANAGED_X_ENABLED"
X_DIRECTORY = "CATCHPLATE_OPERATOR_X_CUSTODY_DIR"
GOOGLE_DIRECTORY = "CATCHPLATE_OPERATOR_PROVIDER_CUSTODY_DIR"
ORIGIN = "https://operator.example.com"
OWNER = "12345678-1234-4234-8234-123456789abc"


class XAdmissionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="x-admission-component-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.data, self.x, self.google = (self.root / name for name in ("data", "x", "google"))
        for directory in (self.data, self.x, self.google):
            directory.mkdir(mode=0o700)
        self.raw = {FLAG: "1", X_DIRECTORY: str(self.x), GOOGLE_DIRECTORY: str(self.google),
            "CATCHPLATE_OPERATOR_DEMO": "1", "CATCHPLATE_RELEASE_CHANNEL": "dev",
            "CATCHPLATE_PROCESS_MODE": "catchplate-control-plane", "CATCHPLATE_DATA_DIR": str(self.data),
            "CATCHPLATE_METADATA_STORE_BACKEND": "sqlite", "CATCHPLATE_AUDIT_STORE_BACKEND": "sqlite",
            "CATCHPLATE_GRANT_STORE_BACKEND": "sqlite", "CATCHPLATE_ATOMIC_RELEASE_AUTHORIZATION_ENABLED": "0",
            "CATCHPLATE_KEY_RELEASE_REQUIRED": "0", "CATCHPLATE_DEV_AUTHENTICATOR": "0",
            "CATCHPLATE_DEV_DEMO_SEED": "0", "CATCHPLATE_OPERATOR_GATE_PUBLICATION_ENABLED": "1",
            "CATCHPLATE_PRODUCTION_IMAGE": "0", "CATCHPLATE_DEVELOPMENT_SANDBOX": "0",
            "CATCHPLATE_TEE_PLATFORM": "none-dev", "CATCHPLATE_TEE_QUOTE_PROVIDER": "dev-signed-quote",
            "CATCHPLATE_PUBLIC_URL": ORIGIN}
        self.config = ModuleType("catchplate.config")
        values = {"DATA_DIR": self.data, "RELEASE_CHANNEL": "dev", "PRODUCTION_IMAGE": False,
            "METADATA_STORE_BACKEND": "sqlite", "AUDIT_STORE_BACKEND": "sqlite", "GRANT_STORE_BACKEND": "sqlite",
            "ATOMIC_RELEASE_AUTHORIZATION_ENABLED": False, "KEY_RELEASE_REQUIRED": False,
            "TEE_PLATFORM": "none-dev", "TEE_QUOTE_PROVIDER": "dev-signed-quote",
            "DEV_AUTHENTICATOR_ENABLED": False, "DEV_DEMO_SEED_ENABLED": False,
            "X_OAUTH_CLIENT_ID": "", "X_OAUTH_CLIENT_SECRET": "", "X_OAUTH_CLIENT_SECRET_FILE": None,
            "X_OAUTH_REDIRECT_URI": ORIGIN + "/api/oauth/callback/x", "PUBLIC_URL": ORIGIN}
        for name, value in values.items():
            setattr(self.config, name, value)
        stack = ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(patch.dict(os.environ, self.raw, clear=True))
        stack.enter_context(patch.dict(sys.modules, {"catchplate.config": self.config}))
        stack.enter_context(patch.object(catchplate, "config", self.config, create=True))
        self.active = stack.enter_context(patch.object(operator_demo, "active", return_value=True))
        self.enrolled = stack.enter_context(patch.object(oauth_application_owner, "require_started", return_value=None))

    def connection(self, path=None):
        conn = sqlite3.connect(self.data / "catchplate.sqlite3" if path is None else path)
        self.addCleanup(conn.close)
        conn.execute("BEGIN IMMEDIATE")
        return conn

    def refused(self, function, *args, **kwargs):
        with self.assertRaises(admission.AdmissionError) as caught:
            function(*args, **kwargs)
        self.assertEqual(str(caught.exception), "operator X configuration unavailable")
        self.assertNotIn(str(self.root), repr(caught.exception))

    def test_flag_is_explicit_strict_and_not_admission(self):
        for value, expected in ((None, False), ("0", False), ("1", True)):
            with patch.dict(os.environ, {}, clear=True):
                if value is not None:
                    os.environ[FLAG] = value
                self.assertIs(admission.enabled(), expected)
                self.refused(admission.require_runtime)
        for value in ("", "true", "false", "01", " 1", "1\n"):
            with patch.dict(os.environ, {FLAG: value}):
                self.refused(admission.enabled)
        self.assertEqual(list(self.x.iterdir()), [])

    def test_real_private_directory_and_exact_sqlite_transaction_no_initialization(self):
        pinned = admission.require_runtime()
        self.assertIs(type(pinned), keys.DirectoryAdmission)
        self.assertEqual((pinned.path, pinned.data_directory), (self.x, self.data))
        self.assertEqual(pinned, keys.admit_directory(self.x, data_directory=self.data))
        self.assertGreaterEqual(self.active.call_count, 2)
        self.enrolled.assert_called()
        conn = self.connection()
        statements = []
        conn.set_trace_callback(statements.append)
        admission.check_connection(conn, pinned)
        admission.check_connection(conn, pinned)  # Empty SQLite temp schema is legitimate.
        self.assertTrue(conn.in_transaction)
        self.assertEqual(conn.total_changes, 0)
        self.assertTrue(all(sql.startswith(("PRAGMA", "SELECT")) for sql in statements))
        self.assertEqual(list(self.x.iterdir()), [])
        self.assertEqual(list(self.google.iterdir()), [])

    def test_raw_explicit_development_modes_are_not_inferred(self):
        changes = {"CATCHPLATE_OPERATOR_DEMO": "0", "CATCHPLATE_RELEASE_CHANNEL": "production",
            "CATCHPLATE_PROCESS_MODE": "proxy", "CATCHPLATE_METADATA_STORE_BACKEND": "postgres",
            "CATCHPLATE_AUDIT_STORE_BACKEND": "postgres", "CATCHPLATE_GRANT_STORE_BACKEND": "postgres",
            "CATCHPLATE_ATOMIC_RELEASE_AUTHORIZATION_ENABLED": "1", "CATCHPLATE_KEY_RELEASE_REQUIRED": "1",
            "CATCHPLATE_DEV_AUTHENTICATOR": "1", "CATCHPLATE_DEV_DEMO_SEED": "1",
            "CATCHPLATE_OPERATOR_GATE_PUBLICATION_ENABLED": "0", "CATCHPLATE_PRODUCTION_IMAGE": "1",
            "CATCHPLATE_DEVELOPMENT_SANDBOX": "1", "CATCHPLATE_TEE_PLATFORM": "nitro",
            "CATCHPLATE_TEE_QUOTE_PROVIDER": "native"}
        for name, value in changes.items():
            with self.subTest(name=name), patch.dict(os.environ, {name: value}):
                self.refused(admission.require_runtime)
        for name in ("CATCHPLATE_PROCESS_MODE", "CATCHPLATE_METADATA_STORE_BACKEND", "CATCHPLATE_DEV_AUTHENTICATOR"):
            with patch.dict(os.environ):
                del os.environ[name]
                self.refused(admission.require_runtime)
        admission.require_runtime()

    def test_native_enrolled_and_global_x_or_twitter_selections_refuse(self):
        for name in ("CATCHPLATE_NATIVE_CONFIG_FD", "CATCHPLATE_OAUTH_APPLICATION_CONFIG_FD",
                "CATCHPLATE_CONTROL_PLANE_CUSTODY_FD", "CATCHPLATE_AUTHORITY_TOKEN",
                "CATCHPLATE_METADATA_STORE_DSN"):
            with self.subTest(name=name), patch.dict(os.environ, {name: "synthetic"}):
                self.refused(admission.require_runtime)
        for prefix in ("CATCHPLATE_X_OAUTH_", "CATCHPLATE_TWITTER_OAUTH_"):
            for value in ("", "synthetic"):
                with patch.dict(os.environ, {prefix + "CLIENT_SECRET": value}):
                    self.refused(admission.require_runtime)
        for owner in (object(), {"synthetic": True}):
            self.enrolled.return_value = owner
            self.refused(admission.require_runtime)
        self.enrolled.return_value = None
        self.enrolled.side_effect = RuntimeError("synthetic private owner detail")
        self.refused(admission.require_runtime)

    def test_imported_config_must_match_each_runtime_selection(self):
        changes = {"DATA_DIR": self.google, "RELEASE_CHANNEL": "production", "PRODUCTION_IMAGE": True,
            "METADATA_STORE_BACKEND": "postgres", "AUDIT_STORE_BACKEND": "postgres", "GRANT_STORE_BACKEND": "postgres",
            "ATOMIC_RELEASE_AUTHORIZATION_ENABLED": True, "KEY_RELEASE_REQUIRED": True,
            "TEE_PLATFORM": "nitro", "TEE_QUOTE_PROVIDER": "native", "DEV_AUTHENTICATOR_ENABLED": True,
            "DEV_DEMO_SEED_ENABLED": True, "X_OAUTH_CLIENT_ID": "global-client",
            "X_OAUTH_CLIENT_SECRET": "synthetic-global-secret", "X_OAUTH_CLIENT_SECRET_FILE": self.root / "missing",
            "X_OAUTH_REDIRECT_URI": "https://other.example.com/api/oauth/callback/x"}
        for name, value in changes.items():
            with self.subTest(name=name), patch.object(self.config, name, value):
                self.refused(admission.require_runtime)
        admission.require_runtime()

    def test_demo_admission_is_checked_again_after_directory_validation(self):
        for outcome in (False, RuntimeError("synthetic private admission detail")):
            self.active.side_effect = [True, outcome]
            self.refused(admission.require_runtime)
        self.active.side_effect = None
        self.active.return_value = False
        self.refused(admission.require_runtime)

    def test_public_origin_requires_canonical_raw_imported_equality(self):
        self.assertEqual(admission.public_origin(), ORIGIN)
        for value in ("http://operator.example.com", ORIGIN + "/", ORIGIN + ":443",
                "https://operator.example.com/path", "https://operator.example.com?x=1",
                "https://demo-upstream:8443", "https://127.0.0.1", "https://user@operator.example.com"):
            with self.subTest(value=value), patch.dict(os.environ, {"CATCHPLATE_PUBLIC_URL": value}), \
                    patch.object(self.config, "PUBLIC_URL", value):
                self.refused(admission.public_origin)
        with patch.dict(os.environ, {"CATCHPLATE_PUBLIC_URL": "https://other.example.com"}):
            self.refused(admission.public_origin)

    def test_x_directory_is_private_existing_and_not_data_or_google(self):
        alias = self.root / "alias"
        alias.symlink_to(self.x, target_is_directory=True)
        for value in (str(self.data), str(self.google), str(self.root), "relative", str(self.root / "missing"),
                str(self.x) + "/", str(alias)):
            with self.subTest(value=value), patch.dict(os.environ, {X_DIRECTORY: value}):
                self.refused(admission.require_runtime)
        self.x.chmod(0o750)
        self.refused(admission.require_runtime)
        self.x.chmod(0o700)
        for parent in (self.data, self.google):
            child = parent / "nested-x"
            child.mkdir(mode=0o700)
            with patch.dict(os.environ, {X_DIRECTORY: str(child)}):
                self.refused(admission.require_runtime)
            child.rmdir()
        with patch.dict(os.environ, {GOOGLE_DIRECTORY: str(self.x)}):
            self.refused(admission.require_runtime)
        admission.require_runtime()
        with patch.dict(os.environ):
            del os.environ[GOOGLE_DIRECTORY]
            admission.require_runtime()

    def test_connection_refuses_other_database_attached_temp_and_uncommitted_modes(self):
        pinned = admission.require_runtime()
        for path in (":memory:", self.data / "other.sqlite3", self.root / "catchplate.sqlite3"):
            conn = self.connection(path)
            self.refused(admission.check_connection, conn, pinned)
            conn.close()
        conn = self.connection()
        conn.execute("ATTACH DATABASE ':memory:' AS foreign_database")
        self.refused(admission.check_connection, conn, pinned)
        conn.close()
        conn = self.connection()
        conn.execute("CREATE TEMP TABLE unexpected(value)")
        self.refused(admission.check_connection, conn, pinned)
        conn.close()
        conn = self.connection()
        conn.execute("PRAGMA read_uncommitted=ON")
        self.refused(admission.check_connection, conn, pinned)
        conn.execute("PRAGMA read_uncommitted=OFF")
        conn.rollback()
        self.refused(admission.check_connection, conn, pinned)
        conn.close()
        self.refused(admission.check_connection, conn, pinned)
        self.refused(admission.check_connection, object(), pinned)

    def test_connection_rechecks_environment_process_and_directory_pins(self):
        pinned, conn = admission.require_runtime(), self.connection()
        with patch.dict(os.environ, {"CATCHPLATE_SYNTHETIC_CONFIGURATION_DRIFT": "1"}):
            self.refused(admission.check_connection, conn, pinned)
        self.refused(admission.check_connection, conn, replace(pinned,
            process=(os.getpid() + 1, os.geteuid(), os.getegid())))
        self.x.rename(self.root / "old-x")
        self.x.mkdir(mode=0o700)
        self.refused(admission.check_connection, conn, pinned)
        self.x.rmdir()
        (self.root / "old-x").rename(self.x)
        admission.check_connection(conn, pinned)
        self.data.rename(self.root / "old-data")
        self.data.mkdir(mode=0o700)
        self.refused(admission.check_connection, conn, pinned)

    def test_actual_owner_construction_follows_runtime_checks_without_key_creation(self):
        owner = admission.admit_owner(OWNER)
        self.assertIs(type(owner), custody.DevelopmentOwner)
        self.assertEqual((owner.owner_id, owner.pid, owner.uid), (OWNER, os.getpid(), os.geteuid()))
        for identifier in ("invalid", OWNER.upper(), None, 1):
            self.refused(admission.admit_owner, identifier)
        self.active.return_value = False
        self.refused(admission.admit_owner, OWNER)
        self.assertEqual(list(self.x.iterdir()), [])

    def test_real_first_x_key_initializer_then_same_connection_recheck(self):
        pinned, conn = admission.require_runtime(), self.connection()
        admission.check_connection(conn, pinned)
        with patch("catchplate.operator_publication.assert_held") as held:
            key = keys.initialize_first_x(pinned, conn, no_retained_provider_state=True)
        self.addCleanup(keys.close_pin, key)
        held.assert_called_once_with()  # Synthetic EX boundary, not publication acceptance.
        keys.check_pin(key)
        admission.check_connection(conn, pinned)
        self.assertTrue(conn.in_transaction)
        self.assertEqual(len(key.material), 32)
        self.assertEqual(conn.execute("SELECT count(*) FROM sqlite_master").fetchone()[0], 0)
        self.assertEqual(conn.execute("SELECT count(*) FROM sqlite_temp_master").fetchone()[0], 0)
        self.assertEqual(list(self.google.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
