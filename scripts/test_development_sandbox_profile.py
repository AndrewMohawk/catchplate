#!/usr/bin/env python3
"""Real process/profile/filesystem controls; no live application or provider."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
_ENVIRONMENT = {
    "CATCHPLATE_DEVELOPMENT_SANDBOX": "1", "CATCHPLATE_RELEASE_CHANNEL": "dev",
    "CATCHPLATE_PROCESS_MODE": "catchplate-control-plane",
    "CATCHPLATE_METADATA_STORE_BACKEND": "sqlite", "CATCHPLATE_AUDIT_STORE_BACKEND": "sqlite",
    "CATCHPLATE_GRANT_STORE_BACKEND": "sqlite", "CATCHPLATE_ATOMIC_RELEASE_AUTHORIZATION_ENABLED": "0",
    "CATCHPLATE_KEY_RELEASE_REQUIRED": "0", "PYTHONDONTWRITEBYTECODE": "1",
}
_MARKER = ".catchplate-development-sandbox.json"
_MARKER_BYTES = b'{"schema": "catchplate.developmentSandbox/v1", "syntheticOnly": true}\n'


def refused(call):
    try:
        call()
    except (RuntimeError, OSError, ValueError):
        return
    raise AssertionError("invalid sandbox activation remained usable")


def worker(operation):
    from catchplate import development_sandbox as profile
    if operation == "inactive":
        assert not profile.active()
        assert not Path(os.environ["CATCHPLATE_DATA_DIR"]).exists()
        return
    if operation == "refuse":
        refused(profile.activate)
        assert not profile.active()
        return
    if operation == "refuse-before-config":
        refused(profile.activate)
        assert "catchplate.config" not in sys.modules
        assert not profile.active()
        return
    if operation == "stale-import":
        original = os.environ["CATCHPLATE_DATA_DIR"]
        os.environ["CATCHPLATE_DATA_DIR"] = original + "-old"
        from catchplate import config
        os.environ["CATCHPLATE_DATA_DIR"] = original
        refused(profile.activate)
        assert not profile.active()
        return
    profile.activate()
    assert profile.active()
    directory = Path(os.environ["CATCHPLATE_DATA_DIR"])
    if operation == "activate":
        profile.activate()
        assert profile.active()
    elif operation == "change-core":
        os.environ["CATCHPLATE_ATOMIC_RELEASE_AUTHORIZATION_ENABLED"] = "1"
        refused(profile.active)
    elif operation == "add-authority":
        os.environ["CATCHPLATE_POLICY_AUTHORITY_RUNTIME_TRUST_PATH"] = "/not-opened"
        refused(profile.active)
    elif operation == "add-key":
        os.environ["CATCHPLATE_POLICY_SIGNING_KEY"] = "/not-opened"
        refused(profile.active)
    elif operation == "startup-pid":
        os.environ["CATCHPLATE_CONTROL_PLANE_STARTUP_VALIDATED_PID"] = str(os.getpid())
        assert profile.active()
        os.environ["CATCHPLATE_CONTROL_PLANE_STARTUP_VALIDATED_PID"] = str(os.getpid() + 1)
        refused(profile.active)
    elif operation == "fork":
        child = os.fork()
        if child == 0:
            try:
                refused(profile.active)
            except BaseException:
                os._exit(1)
            os._exit(0)
        assert os.waitpid(child, 0)[1] == 0
        assert profile.active()
    elif operation == "replace-marker":
        replacement = directory / "new-marker"
        replacement.write_bytes(_MARKER_BYTES)
        replacement.chmod(0o600)
        replacement.replace(directory / _MARKER)
        refused(profile.active)
    elif operation == "replace-directory":
        directory.rename(directory.with_name("old-data"))
        directory.mkdir(mode=0o700)
        marker = directory / _MARKER
        marker.write_bytes(_MARKER_BYTES)
        marker.chmod(0o600)
        refused(profile.active)
    elif operation == "legitimate-subdirectory":
        (directory / "mitmproxy").mkdir(mode=0o700)
        assert profile.active()
    else:
        raise AssertionError("unknown test operation")


class DevelopmentSandboxProfileTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(prefix="catchplate-sandbox-profile-",
            dir=os.getenv("TMPDIR", "/srv/catchplate-fast/tmp"))
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)
        self.data = self.root / "data"
        self.environment = {key: value for key, value in os.environ.items()
                            if not key.startswith("CATCHPLATE_")}
        self.environment.update(_ENVIRONMENT, CATCHPLATE_DATA_DIR=str(self.data))

    def run_worker(self, operation, *, environment=None):
        result = subprocess.run([sys.executable, "-B", str(Path(__file__).resolve()), "--worker", operation],
            cwd=ROOT, env=environment or self.environment, text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_environment_flag_does_not_activate_normal_process(self):
        self.run_worker("inactive")

    def test_valid_private_marker_is_idempotent_across_processes(self):
        self.run_worker("activate")
        before = (self.data / _MARKER).stat().st_ino
        self.run_worker("activate")
        self.assertEqual((self.data / _MARKER).read_bytes(), _MARKER_BYTES)
        self.assertEqual((self.data / _MARKER).stat().st_ino, before)

    def test_late_configuration_changes_are_rejected(self):
        for operation in ("change-core", "add-authority", "add-key", "startup-pid"):
            with self.subTest(operation=operation):
                self.run_worker(operation)

    def test_activation_cannot_cross_fork(self):
        self.run_worker("fork")

    def test_marker_and_directory_replacement_are_rejected(self):
        self.run_worker("replace-marker")
        # A new process can reopen an unchanged canonical replacement; it
        # cannot inherit the old process's activated identity across that swap.
        self.run_worker("replace-directory")

    def test_normal_data_subdirectory_creation_does_not_change_identity(self):
        self.run_worker("legitimate-subdirectory")

    def test_unmarked_data_is_preserved_and_refused(self):
        self.data.mkdir(mode=0o700)
        sentinel = self.data / "old-data"
        sentinel.write_bytes(b"untouched")
        self.run_worker("refuse")
        self.assertEqual(list(self.data.iterdir()), [sentinel])
        self.assertEqual(sentinel.read_bytes(), b"untouched")

    def test_directory_and_ancestor_symlinks_are_refused(self):
        target = self.root / "target"
        target.mkdir(mode=0o700)
        self.data.symlink_to(target, target_is_directory=True)
        self.run_worker("refuse")
        nested = dict(self.environment, CATCHPLATE_DATA_DIR=str(self.data / "nested"))
        self.run_worker("refuse", environment=nested)
        self.assertEqual(list(target.iterdir()), [])

    def test_marker_shape_permissions_links_and_fifo_are_refused(self):
        self.data.mkdir(mode=0o700)
        marker = self.data / _MARKER
        variants = (_MARKER_BYTES.replace(b"true", b"1"), _MARKER_BYTES.replace(b"v1", b"v2"),
                    _MARKER_BYTES[:-2] + b', "extra": true}\n',
                    b'{"schema":"catchplate.developmentSandbox/v1","syntheticOnly":false,"syntheticOnly":true}')
        for payload in variants:
            with self.subTest(payload=payload):
                marker.write_bytes(payload)
                marker.chmod(0o600)
                self.run_worker("refuse")
        marker.write_bytes(_MARKER_BYTES)
        marker.chmod(0o644)
        self.run_worker("refuse")
        marker.chmod(0o600)
        other = self.root / "marker-target"
        marker.rename(other)
        marker.symlink_to(other)
        self.run_worker("refuse")
        marker.unlink()
        os.link(other, marker)
        self.run_worker("refuse")
        marker.unlink()
        os.mkfifo(marker, 0o600)
        self.run_worker("refuse")

    def test_inherited_authority_provider_and_external_key_config_is_refused_before_import(self):
        selections = ({"CATCHPLATE_POLICY_AUTHORITY_RUNTIME_TRUST_PATH": "/not-opened"},
            {"CATCHPLATE_POLICY_SIGNING_KEY": "/not-opened"},
            {"CATCHPLATE_RESPONSE_SIGNING_KEY": "/not-opened"},
            {"CATCHPLATE_OIDC_ENABLED": "1"}, {"CATCHPLATE_GOOGLE_OAUTH_CLIENT_SECRET": "synthetic-fixture"},
            {"CATCHPLATE_TWITTER_OAUTH_CLIENT_SECRET": "synthetic-fixture"},
            {"CATCHPLATE_WEBAUTHN_RECOVERY_ENABLED": "1"},
            {"CATCHPLATE_SETUP_ENROLLMENT_VERIFIER_PUBLIC_KEY": "/not-opened"},
            {"CATCHPLATE_METADATA_STORE_POSTGRES_DSN": "synthetic-not-a-dsn"},
            {"CATCHPLATE_TEE_QUOTE_COMMAND": "/not-executed"}, {"CATCHPLATE_ADMIN_TOKEN_FILE": "/not-opened"},
            {"CATCHPLATE_MASTER_KEY": "synthetic-not-a-key"}, {"CATCHPLATE_PRODUCTION_IMAGE": "1"})
        for selection in selections:
            with self.subTest(settings=list(selection)):
                self.run_worker("refuse-before-config", environment=dict(self.environment, **selection))
                self.assertFalse(self.data.exists())

    def test_stale_imported_data_configuration_is_refused(self):
        self.run_worker("stale-import")
        self.assertFalse(self.data.exists())

    def test_request_rule_blocks_get_oauth_and_preserves_fixed_synthetic_routes(self):
        from catchplate import development_sandbox as profile
        for method in ("GET", "HEAD", "POST"):
            for path in ("/api/auth/oidc/start", "/api/auth/oidc/callback", "/api/oauth/callback/google"):
                self.assertFalse(profile.request_allowed(method, path))
        for path in ("/", "/api/bootstrap", "/api/sandbox/status"):
            self.assertTrue(profile.request_allowed("GET", path))
        for path in ("/api/demo/seed", "/api/sandbox/check", "/api/data-plane/credential-leases", "/api/data-plane/audit"):
            self.assertTrue(profile.request_allowed("POST", path))
        self.assertFalse(profile.request_allowed("POST", "/api/credentials"))


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--worker":
        worker(sys.argv[2])
    else:
        unittest.main()
