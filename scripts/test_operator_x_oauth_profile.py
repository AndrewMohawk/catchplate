#!/usr/bin/env python3
"""Offline pure-profile checks; no OAuth configuration, consent or readiness."""
from dataclasses import FrozenInstanceError
import hashlib
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from pydantic import ValidationError
from serverware import operator_x_oauth_profile as profile

CLIENT = "synthetic-X-client_123"
ORIGIN = "https://console.example.com"
SECRET = "synthetic-X-application-secret-only"


def no_network(event, _args):
    if event.startswith(("socket.", "subprocess.")):
        raise AssertionError("network and child processes forbidden in pure profile tests")


sys.addaudithook(no_network)


def selected():
    return profile.build_profile(client_id=CLIENT, public_origin=ORIGIN)


def payload(**changes):
    return {"expected_revision": 1, "expected_policy_hash": "sha256:" + "a" * 64,
        "operation_id": "12345678-1234-4234-8234-123456789abc", "client_id": CLIENT,
        "client_secret": SECRET, **changes}


class ProfileTests(unittest.TestCase):
    def refused(self, function, *args, **kwargs):
        with self.assertRaises(profile.ProfileError) as caught:
            function(*args, **kwargs)
        self.assertEqual(str(caught.exception), "operator X OAuth profile refused")
        self.assertNotIn(SECRET, repr(caught.exception))

    def test_exact_public_record_and_independent_digest(self):
        expected = {"schema": "serverware.operatorXOAuthProfile/v1", "profile": "operator-x-oauth-v1",
            "provider_id": "x", "client_id": CLIENT, "redirect_uri": ORIGIN + "/api/oauth/callback/x",
            "client_auth_method": "client_secret_basic", "permission_preset": "x_text_post_v1",
            "scopes": ["offline.access", "tweet.read", "tweet.write", "users.read"],
            "api_origins": ["https://api.x.com"],
            "authorization_url": "https://x.com/i/oauth2/authorize",
            "token_url": "https://api.x.com/2/oauth2/token",
            "revocation_url": "https://api.x.com/2/oauth2/revoke",
            "identity_url": "https://api.x.com/2/users/me"}
        value = selected()
        self.assertEqual(profile.public_record(value), expected)
        raw = json.dumps(expected, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        self.assertEqual(value.binding_digest, "sha256:" + hashlib.sha256(raw).hexdigest())
        self.assertEqual(profile.parse_profile(expected), value)
        self.assertIs(profile.validate_profile(value), value)

    def test_immutable_and_fresh_public_projection(self):
        value = selected()
        with self.assertRaises(FrozenInstanceError):
            value.client_id = "other"
        first = profile.public_record(value)
        first["scopes"].append("unapproved")
        first["token_url"] = "https://other.example.com"
        self.assertEqual(profile.public_record(value)["scopes"], list(profile.SCOPES))
        self.assertEqual(value.token_url, "https://api.x.com/2/oauth2/token")
        object.__setattr__(value, "token_url", "https://other.example.com")
        self.refused(profile.validate_profile, value)

    def test_every_fixed_field_and_scope_order_is_closed(self):
        record = profile.public_record(selected())
        for key in record:
            if key in {"client_id", "redirect_uri"}:
                continue
            bad = list(reversed(record[key])) if key == "scopes" else ([] if type(record[key]) is list else "other")
            with self.subTest(field=key):
                self.refused(profile.parse_profile, {**record, key: bad})
        for value in ({**record, "client_secret": SECRET}, {**record, "scopes": tuple(profile.SCOPES)},
                {key: value for key, value in record.items() if key != "provider_id"}):
            self.refused(profile.parse_profile, value)
        self.assertNotEqual(selected().binding_digest,
            profile.build_profile(client_id="other", public_origin=ORIGIN).binding_digest)

    def test_exact_callback_origin(self):
        for origin in ("http://console.example.com", ORIGIN + "/", ORIGIN + ":443", ORIGIN + "/path",
                "https://user@console.example.com", "https://127.0.0.1", "https://console.localhost",
                "https://demo-upstream:8443", "https://CONSOLE.example.com", ORIGIN + "?", "", None):
            self.refused(profile.build_profile, client_id=CLIENT, public_origin=origin)
        for callback in (ORIGIN + "/api/oauth/callback/google", ORIGIN + "/api/oauth/callback/x?code=x",
                ORIGIN + "/api/oauth/callback/x/", ORIGIN + ":443/api/oauth/callback/x"):
            self.refused(profile.Profile, CLIENT, callback)

    def test_client_and_secret_exact_byte_bounds(self):
        self.assertEqual(profile.validate_client_id("a" * 256), "a" * 256)
        for value in ("", "a" * 257, "x y", "x\t", "é", 1, True, None):
            self.refused(profile.validate_client_id, value)
        for value in ("s" * 4096, "é" * 2048):
            self.assertEqual(profile.validate_client_secret(value), value)
        for value in ("", "s" * 4097, "é" * 2049, " x", "x ", "x\n", "x\r", "x\x00", "\ud800", None):
            self.refused(profile.validate_client_secret, value)

    def test_dto_write_only_serialization_and_repr(self):
        value = profile.XOAuthApplicationInput.model_validate(payload())
        self.assertEqual(value.client_secret, SECRET)
        expected = payload()
        del expected["client_secret"]
        self.assertEqual(value.model_dump(), expected)
        self.assertEqual(json.loads(value.model_dump_json()), expected)
        self.assertNotIn(SECRET, repr(value))
        self.assertNotIn(SECRET, str(value))

    def test_dto_required_closed_strict_cas_and_locator(self):
        for key in payload():
            value = payload()
            del value[key]
            with self.assertRaises(ValidationError):
                profile.XOAuthApplicationInput.model_validate(value)
        for changes in ({"scopes": ["tweet.write"]}, {"redirect_uri": ORIGIN}, {"key_source": "other"},
                {"client_secret": None}, {"expected_revision": True}, {"expected_revision": "1"},
                {"expected_policy_hash": "a" * 64}, {"operation_id": "12345678-1234-4234-8234-123456789ABC"}):
            with self.assertRaises(ValidationError):
                profile.XOAuthApplicationInput.model_validate(payload(**changes))

    def test_dto_error_redaction_requires_safe_structured_diagnostics(self):
        secret = SECRET + "\n"
        with self.assertRaises(ValidationError) as caught:
            profile.XOAuthApplicationInput.model_validate(payload(client_secret=secret))
        self.assertNotIn(SECRET, str(caught.exception))
        self.assertNotIn(SECRET, repr(caught.exception))
        safe = caught.exception.errors(include_input=False, include_context=False)
        self.assertNotIn(SECRET, json.dumps(safe))
        # This is precisely why raw Pydantic diagnostics must never be API output.
        self.assertEqual(caught.exception.errors()[0]["input"], secret)

    def test_profile_objects_do_not_import_runtime_or_admit_lifecycle(self):
        selected()
        for name in ("serverware.config", "serverware.db", "serverware.oauth", "serverware.operator_google_managed_config"):
            self.assertNotIn(name, sys.modules)
        self.assertFalse(hasattr(profile, "require_profile"))
        self.assertFalse(hasattr(profile, "load_configuration"))
        self.assertFalse(hasattr(profile, "selected"))


if __name__ == "__main__":
    unittest.main()
