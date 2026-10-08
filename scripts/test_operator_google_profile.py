#!/usr/bin/env python3
"""Cold operator-Google admission controls; no DB, server, provider, or network.

Every case imports the real config/operator profile in a fresh bounded child.
Only disposable synthetic files are modified. These controls do not prove OAuth
consent, catalog persistence, encrypted refresh, gate admission, or deployment.
"""
from __future__ import annotations

from dataclasses import FrozenInstanceError
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import test_operator_demo_persistence as common

ROOT = Path(__file__).resolve().parents[1]
_SECRET = "synthetic-google-profile-secret"
_CLIENT_ID = "123-fixture.apps.googleusercontent.com"
_PUBLIC_URL = "https://control.example.com"
_CALLBACK = _PUBLIC_URL + "/api/oauth/callback/google"
_SCOPES = ["email", "https://www.googleapis.com/auth/gmail.readonly", "openid"]


def _must_refuse(function):
    try:
        function()
    except RuntimeError:
        return
    raise AssertionError("closed admission accepted a negative control")


def worker(action):
    from serverware import operator_catalog_oauth_profile as profile
    if action == "invalid_selection":
        _must_refuse(profile.selected)
        return
    if action in {"refuse", "refuse_before_secret", "config_refuse_before_secret"}:
        opened = []
        # The audit hook observes the real descriptor-relative open; it does
        # not replace the file reader or any admission guard.
        def audit(event, arguments):
            if event == "open" and arguments and arguments[0] == "client-secret":
                opened.append(True)
        sys.addaudithook(audit)
        if action == "config_refuse_before_secret":
            _must_refuse(lambda: __import__("serverware.config"))
        else:
            from serverware import operator_demo
            _must_refuse(operator_demo.activate)
        if action in {"refuse_before_secret", "config_refuse_before_secret"}:
            assert not opened, "invalid owner/config reached secret open"
        return
    from serverware import operator_demo
    operator_demo.activate()
    if action == "disabled":
        assert profile.selected() is False
        _must_refuse(profile.require_profile)
        assert not operator_demo.request_allowed("GET", "/api/oauth/callback/google")
        assert not operator_demo.request_allowed("POST", "/api/operator-demo/oauth/google/start")
        assert operator_demo.request_allowed("POST", "/api/operator-demo/access-rules")
        return
    from serverware import config
    admitted = profile.require_profile()
    assert profile.require_lease_reconciliation_profile() == admitted
    assert admitted.client_id == _CLIENT_ID and admitted.redirect_uri == _CALLBACK
    assert admitted.scopes == tuple(_SCOPES)
    assert admitted.api_origins == ("https://gmail.googleapis.com",)
    assert config.GOOGLE_OAUTH_CLIENT_SECRET == _SECRET
    if action == "positive":
        expected = {
            "schema": "serverware.operatorGoogleProfile/v1", "profile": "operator-google-v1",
            "provider_id": "google", "client_id": _CLIENT_ID, "redirect_uri": _CALLBACK,
            "permission_preset": "gmail_readonly", "scopes": _SCOPES,
            "api_origins": ["https://gmail.googleapis.com"],
            "authorization_url": "https://accounts.google.com/o/oauth2/v2/auth",
            "token_url": "https://oauth2.googleapis.com/token",
            "revocation_url": "https://oauth2.googleapis.com/revoke",
            "identity_url": "https://openidconnect.googleapis.com/v1/userinfo",
        }
        assert profile.binding_record() == expected
        encoded = json.dumps(expected, sort_keys=True, separators=(",", ":"),
            ensure_ascii=True, allow_nan=False).encode("utf-8")
        assert admitted.binding_digest == "sha256:" + hashlib.sha256(encoded).hexdigest()
        assert _SECRET not in repr(admitted) and _SECRET not in encoded.decode()
        changed = profile.binding_record()
        changed["scopes"].append("not-a-permission")
        assert profile.binding_record() == expected
        try:
            admitted.client_id = "different"
        except FrozenInstanceError:
            pass
        else:
            raise AssertionError("profile is mutable")
        return
    if action == "routes":
        assert operator_demo.request_allowed("POST", "/api/operator-demo/oauth/google/start")
        assert operator_demo.request_allowed("GET", "/api/oauth/callback/google")
        assert operator_demo.request_allowed("GET", "/api/operator-demo/oauth/google/intents")
        for method, path in (
            ("POST", "/api/oauth/start"), ("POST", "/api/operator-demo/oauth/google/activate"),
            ("POST", "/api/oauth/pending/activate"), ("POST", "/api/oauth/callback/google"),
            ("HEAD", "/api/oauth/callback/google"), ("GET", "/api/oauth/callback/google/"),
            ("GET", "/api/oauth/callback/x"), ("GET", "/api/auth/oidc/callback"),
            ("POST", "/api/operator-demo/oauth/google/start/"),
        ):
            assert not operator_demo.request_allowed(method, path), (method, path)
        return
    if action.startswith("imported:"):
        attribute = action.partition(":")[2]
        old = getattr(config, attribute)
        value = True if isinstance(old, bool) else "different-imported-value"
        setattr(config, attribute, value)
        _must_refuse(profile.require_profile)
        return
    if action == "environment":
        os.environ["SERVERWARE_GOOGLE_OAUTH_CLIENT_ID"] = "123-changed.apps.googleusercontent.com"
    elif action == "disable_after_admission":
        del os.environ["SERVERWARE_OPERATOR_GOOGLE_PROFILE"]
        _must_refuse(profile.selected)
    elif action == "file_replace":
        secret = Path(os.environ["SERVERWARE_GOOGLE_OAUTH_CLIENT_SECRET_FILE"])
        replacement = secret.with_name("replacement")
        replacement.write_text(_SECRET, encoding="utf-8")
        replacement.chmod(0o600)
        os.replace(replacement, secret)
    elif action == "file_content":
        Path(os.environ["SERVERWARE_GOOGLE_OAUTH_CLIENT_SECRET_FILE"]).write_text(
            "synthetic-changed-secret", encoding="utf-8")
    elif action == "file_mode":
        Path(os.environ["SERVERWARE_GOOGLE_OAUTH_CLIENT_SECRET_FILE"]).chmod(0o644)
    elif action == "file_unlink":
        Path(os.environ["SERVERWARE_GOOGLE_OAUTH_CLIENT_SECRET_FILE"]).unlink()
    elif action == "fork":
        child = os.fork()
        if child == 0:
            try:
                profile.require_profile()
            except RuntimeError:
                os._exit(0)
            os._exit(19)
        _, status = os.waitpid(child, 0)
        assert os.waitstatus_to_exitcode(status) == 0
        assert profile.require_profile() == admitted
        return
    else:
        raise AssertionError("unknown test action")
    _must_refuse(profile.require_profile)


class OperatorGoogleProfileTests(unittest.TestCase):
    def run_case(self, action="positive", *, overrides=None, file_variant=None, enabled=True):
        with tempfile.TemporaryDirectory(prefix="operator-google-profile-") as raw:
            base = Path(raw)
            data = base / "data"
            secret = base / "client-secret"
            secret.write_text(_SECRET, encoding="utf-8")
            secret.chmod(0o600)
            environment = {key: value for key, value in os.environ.items() if not key.startswith("SERVERWARE_")}
            environment.update(common._ENVIRONMENT)
            environment.update({"SERVERWARE_DATA_DIR": str(data),
                "SERVERWARE_OPERATOR_DEMO_UPSTREAMS": '["https://api.example.com","https://gmail.googleapis.com"]',
                "SERVERWARE_PUBLIC_URL": _PUBLIC_URL})
            if enabled:
                environment.update({"SERVERWARE_OPERATOR_GOOGLE_PROFILE": "operator-google-v1",
                    "SERVERWARE_GOOGLE_OAUTH_CLIENT_ID": _CLIENT_ID,
                    "SERVERWARE_GOOGLE_OAUTH_CLIENT_SECRET_FILE": str(secret),
                    "SERVERWARE_GOOGLE_OAUTH_REDIRECT_URI": _CALLBACK})
            if file_variant == "missing":
                secret.unlink()
            elif file_variant == "mode":
                secret.chmod(0o644)
            elif file_variant == "hardlink":
                os.link(secret, base / "other-link")
            elif file_variant == "symlink":
                target = base / "target"
                secret.rename(target)
                secret.symlink_to(target)
            elif file_variant == "ancestor_symlink":
                parent = base / "actual"
                parent.mkdir(mode=0o700)
                secret.rename(parent / "client-secret")
                (base / "alias").symlink_to(parent, target_is_directory=True)
                environment["SERVERWARE_GOOGLE_OAUTH_CLIENT_SECRET_FILE"] = str(base / "alias" / "client-secret")
            elif file_variant in {"fifo", "directory"}:
                secret.unlink()
                if file_variant == "fifo":
                    os.mkfifo(secret, 0o600)
                else:
                    secret.mkdir(mode=0o700)
            elif file_variant is not None:
                payload = {"empty": b"", "large": b"x" * 4097, "utf8": b"\xff",
                    "multiline": b"first\nsecond", "space": b" leading", "nul": b"has\x00nul",
                    "newline": (_SECRET + "\n").encode(), "crlf": (_SECRET + "\r\n").encode(),
                    "double_newline": (_SECRET + "\n\n").encode()}[file_variant]
                secret.write_bytes(payload)
            for key, value in (overrides or {}).items():
                if value is None:
                    environment.pop(key, None)
                else:
                    environment[key] = value
            completed = subprocess.run([sys.executable, "-B", str(Path(__file__).resolve()), "--worker", action],
                env=environment, cwd=ROOT, capture_output=True, text=True, timeout=15, check=False)
            self.assertEqual(completed.returncode, 0, completed.stderr[-4000:])
            self.assertEqual(completed.stdout.strip(), "profile-control-passed")

    def test_01_exact_public_immutable_binding(self):
        self.run_case()
        self.run_case(file_variant="newline")
        self.run_case(file_variant="crlf")

    def test_02_disabled_profile_and_invalid_selection(self):
        self.run_case("disabled", enabled=False)
        self.run_case("disabled", enabled=False, overrides={"SERVERWARE_OPERATOR_GOOGLE_PROFILE": ""})
        for value in ("1", "0", "operator-google-v2", " operator-google-v1"):
            with self.subTest(value=value):
                self.run_case("invalid_selection", overrides={"SERVERWARE_OPERATOR_GOOGLE_PROFILE": value})

    def test_03_only_exact_additive_routes(self):
        self.run_case("routes")

    def test_04_explicit_local_ownership_before_secret_open(self):
        for key, value in {
            "SERVERWARE_OPERATOR_DEMO": "0", "SERVERWARE_RELEASE_CHANNEL": "prod",
            "SERVERWARE_PROCESS_MODE": "other", "SERVERWARE_PRODUCTION_IMAGE": "1",
            "SERVERWARE_DEVELOPMENT_SANDBOX": "1", "SERVERWARE_METADATA_STORE_BACKEND": "postgres",
            "SERVERWARE_AUDIT_STORE_BACKEND": "postgres", "SERVERWARE_GRANT_STORE_BACKEND": "postgres",
            "SERVERWARE_ATOMIC_RELEASE_AUTHORIZATION_ENABLED": "1", "SERVERWARE_KEY_RELEASE_REQUIRED": "1",
            "SERVERWARE_OAUTH_APPLICATION_CONFIG_FD": "9", "SERVERWARE_OAUTH_APPLICATION_UNKNOWN": "configured",
            "SERVERWARE_NATIVE_MODE": "1", "SERVERWARE_CONTROL_PLANE_ENROLLMENT_CONFIG_FD": "9",
            "SERVERWARE_CONTROL_PLANE_CUSTODY_CONFIG_FD": "9", "SERVERWARE_WORKLOAD_IDENTITY_CONFIG_FD": "9",
            "SERVERWARE_DATA_PLANE_LEASE_RECIPIENT_VERIFY_COMMAND": "/does/not/run",
        }.items():
            with self.subTest(key=key):
                self.run_case("refuse_before_secret", overrides={key: value})

    def test_05_protected_configuration_refused_without_disabling(self):
        for key, value in {
            "SERVERWARE_CONTROL_PLANE_MUTATION_WEBAUTHN_REQUIRED": "1",
            "SERVERWARE_CONTROL_PLANE_MUTATION_REQUIRE_HARDWARE_ATTESTATION": "1",
            "SERVERWARE_CONTROL_PLANE_MUTATION_ALLOWED_AUTHENTICATOR_CLASSES": "hardware",
            "SERVERWARE_CONTROL_PLANE_TWO_PERSON_REQUIRED": "1",
        }.items():
            with self.subTest(key=key):
                self.run_case("refuse_before_secret", overrides={key: value})

    def test_05b_config_import_preflights_before_read(self):
        # Application imports config before operator activation; exercising only
        # activate() would miss an early file-read regression at that boundary.
        for key, value in {
            "SERVERWARE_OAUTH_APPLICATION_CONFIG_FD": "9",
            "SERVERWARE_NATIVE_MODE": "1",
            "SERVERWARE_CONTROL_PLANE_MUTATION_WEBAUTHN_REQUIRED": "1",
            "SERVERWARE_CONTROL_PLANE_TWO_PERSON_REQUIRED": "1",
            "SERVERWARE_GOOGLE_OAUTH_CLIENT_SECRET": "synthetic-inline-refused",
            "SERVERWARE_GOOGLE_OAUTH_REDIRECT_URI": _CALLBACK + "?not-exact=1",
        }.items():
            with self.subTest(key=key):
                self.run_case("config_refuse_before_secret", overrides={key: value})

    def test_06_provider_configuration_is_not_a_blanket_exemption(self):
        for key in ("SERVERWARE_GOOGLE_OAUTH_CLIENT_SECRET", "SERVERWARE_GOOGLE_TOKEN_URL",
                "SERVERWARE_GOOGLE_SCOPE", "SERVERWARE_X_OAUTH_CLIENT_ID", "SERVERWARE_OIDC_ENABLED"):
            with self.subTest(key=key):
                self.run_case("refuse_before_secret", overrides={key: "configured"})

    def test_07_exact_client_and_callback(self):
        for value in ("", "fixture", "123-fixture.apps.googleusercontent.com ",
                "123-fixture.apps.googleusercontent.com.attacker.example", "f" * 201 + ".apps.googleusercontent.com"):
            with self.subTest(client=value):
                self.run_case("refuse_before_secret", overrides={"SERVERWARE_GOOGLE_OAUTH_CLIENT_ID": value})
        for value in ("", _CALLBACK + "/", _CALLBACK + "?x=1", _CALLBACK + "#fragment",
                "https://other.example.com/api/oauth/callback/google", _CALLBACK.replace("https:", "http:")):
            with self.subTest(callback=value):
                self.run_case("refuse_before_secret", overrides={"SERVERWARE_GOOGLE_OAUTH_REDIRECT_URI": value})

    def test_08_public_origin_and_preexisting_api_allowlist(self):
        for value in (_PUBLIC_URL + "/", _PUBLIC_URL + ":443", "https://127.0.0.1",
                "https://control.internal", "https://Control.example.com", "https://user@control.example.com"):
            with self.subTest(origin=value):
                self.run_case("refuse_before_secret", overrides={"SERVERWARE_PUBLIC_URL": value,
                    "SERVERWARE_GOOGLE_OAUTH_REDIRECT_URI": value + "/api/oauth/callback/google"})
        self.run_case("refuse_before_secret", overrides={
            "SERVERWARE_OPERATOR_DEMO_UPSTREAMS": '["https://api.example.com"]'})

    def test_09_private_existing_nonblocking_file(self):
        for variant in ("missing", "mode", "hardlink", "symlink", "ancestor_symlink", "fifo", "directory"):
            with self.subTest(variant=variant):
                self.run_case("refuse", file_variant=variant)
        for value in ("client-secret", "/does/not/exist/../client-secret", "/does//not/exist"):
            with self.subTest(path=value):
                self.run_case("refuse_before_secret", overrides={"SERVERWARE_GOOGLE_OAUTH_CLIENT_SECRET_FILE": value})

    def test_10_bounded_single_line_secret(self):
        for variant in ("empty", "large", "utf8", "multiline", "space", "nul", "double_newline"):
            with self.subTest(variant=variant):
                self.run_case("refuse", file_variant=variant)

    def test_11_imported_configuration_drift(self):
        for attribute in ("GOOGLE_OAUTH_CLIENT_ID", "GOOGLE_OAUTH_CLIENT_SECRET", "GOOGLE_OAUTH_CLIENT_SECRET_FILE",
                "GOOGLE_OAUTH_REDIRECT_URI", "PUBLIC_URL", "CONTROL_PLANE_MUTATION_WEBAUTHN_REQUIRED",
                "CONTROL_PLANE_MUTATION_REQUIRE_HARDWARE_ATTESTATION", "CONTROL_PLANE_TWO_PERSON_REQUIRED",
                "CONTROL_PLANE_MUTATION_ALLOWED_AUTHENTICATOR_CLASSES", "ATOMIC_RELEASE_AUTHORIZATION_ENABLED",
                "KEY_RELEASE_REQUIRED", "DATA_DIR", "METADATA_STORE_BACKEND", "AUDIT_STORE_BACKEND",
                "GRANT_STORE_BACKEND", "DATA_PLANE_LEASE_RECIPIENT_VERIFY_COMMAND", "TEE_QUOTE_PROVIDER", "TEE_PLATFORM"):
            with self.subTest(attribute=attribute):
                self.run_case("imported:" + attribute)

    def test_12_process_environment_and_file_lifetime_pins(self):
        for action in ("environment", "disable_after_admission", "file_replace", "file_content",
                "file_mode", "file_unlink", "fork"):
            with self.subTest(action=action):
                self.run_case(action)


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--worker":
        worker(sys.argv[2])
        print("profile-control-passed")
    else:
        unittest.main()
