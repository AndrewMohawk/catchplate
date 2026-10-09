#!/usr/bin/env python3
"""Focused fixture controls, no server sockets, provider calls or Docker launches.

Production guards are not patched. The synthetic provider clock alone is held
at exact boundaries here; the isolated normal-binary checker waits real expiry.
"""
from __future__ import annotations

from copy import deepcopy
from email.message import Message
import io
import json
from pathlib import Path
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlencode, urlsplit

from scripts import operator_google_fixture as fixture
from scripts import prepare_operator_google_fixture as prepare


SOURCE = Path("/srv/catchplate-fast/projects/serverware-operator-workspace")
BINARY = Path("/srv/catchplate-fast/tmp/reviewed/serverware-decision-gate")
INITIALIZER = Path("/srv/catchplate-fast/projects/serverware-operator-audit-integration/scripts/private_operator_audit/initialize.py")
ROOT = prepare.base.SCRATCH / "serverware-google-private.Review01"
SCOPES = ("email", "https://www.googleapis.com/auth/gmail.readonly", "openid")


class CapturedProvider(fixture.GoogleFixture):
    """Capture serializer output only; all OAuth admission is the real fixture."""
    def __init__(self):
        super().__init__(Path("/unused-fixture-pki"))
        self.replies = []

    def _send_json(self, handler, status, payload):
        self.replies.append((status, payload))

    def _send_redirect(self, handler, location):
        self.replies.append((302, location))


def request(path, *, host="gmail.googleapis.com", token=None, method="GET", form=None):
    headers = Message()
    headers["Host"] = host
    body = b"" if form is None else urlencode(form).encode("ascii")
    if form is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        headers["Content-Length"] = str(len(body))
    if token is not None:
        headers["Authorization"] = "Bearer " + token
    return SimpleNamespace(path=path, headers=headers, rfile=io.BytesIO(body),
        raw_requestline=(method + " " + path + " HTTP/1.1\r\n").encode("ascii"))


def authorize(provider, *, bad_verifier=False):
    verifier = "v" * 43
    params = {"response_type": "code", "client_id": fixture.CLIENT_ID,
        "redirect_uri": fixture.CONTROL_ORIGIN + "/api/oauth/callback/google",
        "scope": " ".join(SCOPES), "state": "s" * 43,
        "code_challenge": provider._pkce_challenge(verifier), "code_challenge_method": "S256",
        "access_type": "offline", "prompt": "consent", "include_granted_scopes": "true"}
    provider._handle_get(request("/o/oauth2/v2/auth?" + urlencode(params), host="accounts.google.com"))
    status, location = provider.replies[-1]
    assert status == 302
    parsed = urlsplit(location)
    assert parsed.scheme + "://" + parsed.netloc == fixture.CONTROL_ORIGIN
    assert parse_qs(parsed.query)["state"] == ["s" * 43]
    form = {"grant_type": "authorization_code", "client_id": fixture.CLIENT_ID,
        "client_secret": fixture.CLIENT_SECRET, "redirect_uri": params["redirect_uri"],
        "code": parse_qs(parsed.query)["code"][0], "code_verifier": "z" * 43 if bad_verifier else verifier}
    provider._handle_post(request("/token", host="oauth2.googleapis.com", method="POST", form=form))
    return provider.replies[-1], form


class ManifestTests(unittest.TestCase):
    def test_keeper_health_drops_identity_before_private_marker_read(self):
        value = prepare.build(SOURCE, BINARY, INITIALIZER, ROOT)
        service = value["services"]["network"]
        self.assertEqual(service["cap_add"], ["NET_ADMIN", "SETUID", "SETGID"])
        command = service["healthcheck"]["test"]
        self.assertEqual(command[:3], ["CMD", "python", "-c"])
        for bad_field, bad_value in ((None, None), ("st_mode", 0o100644),
                ("st_mode", 0o120400), ("st_uid", 0), ("st_gid", 0),
                ("st_nlink", 2), ("st_size", 0), ("st_size", 1025)):
            calls = []
            info = {"st_mode": 0o100400, "st_uid": 10001, "st_gid": 10001, "st_nlink": 1, "st_size": 145}
            if bad_field is not None:
                info[bad_field] = bad_value

            def observed_stat(path, *, follow_symlinks):
                self.assertEqual(calls, [("groups", []), ("gid", 10001), ("uid", 10001)])
                self.assertEqual(path, "/fixture-network/ready")
                self.assertFalse(follow_symlinks)
                return SimpleNamespace(**info)

            observed_os = SimpleNamespace(setgroups=lambda value: calls.append(("groups", value)),
                setgid=lambda value: calls.append(("gid", value)),
                setuid=lambda value: calls.append(("uid", value)), stat=observed_stat)
            # Execute only the fixed health expression against a recording OS;
            # this proves command order, not a real UID transition or startup.
            modules = {"os": observed_os, "stat": stat}
            with self.assertRaises(SystemExit) as exited:
                exec(command[3], {"__builtins__": {"__import__": lambda name, *a: modules[name],
                    "SystemExit": SystemExit}})
            self.assertEqual(exited.exception.code, 0 if bad_field is None else 1)

    def test_no_external_network_and_normal_binary_and_real_runner(self):
        value = prepare.build(SOURCE, BINARY, INITIALIZER, ROOT)
        prepare.validate(value, SOURCE, BINARY, INITIALIZER, ROOT)
        self.assertNotIn("networks", value)
        self.assertEqual(set(value["services"]), {"initialize", "network", "provider", "serverware", "decision-gate-rs", "check"})
        for name, service in value["services"].items():
            self.assertFalse(service.get("ports") or service.get("privileged") or service.get("extra_hosts"))
            self.assertEqual(service["pull_policy"], "never")
            self.assertEqual(service["cap_drop"], ["ALL"])
            self.assertEqual(service["network_mode"], "none" if name in {"initialize", "network"} else "service:network")
            if name not in {"initialize", "network"}:
                self.assertNotIn("cap_add", service)
                self.assertEqual(service["user"], "10001:10001")
        self.assertEqual(value["services"]["network"]["cap_add"], ["NET_ADMIN", "SETUID", "SETGID"])
        self.assertEqual(value["services"]["serverware"]["command"], ["python", "-B", "-m", "serverware.operator_demo_runner"])
        gate = value["services"]["decision-gate-rs"]
        self.assertEqual(gate["entrypoint"], ["/usr/local/bin/serverware-decision-gate"])
        self.assertEqual(gate["environment"]["SERVERWARE_OPERATOR_DEMO_UPSTREAMS"], '["https://gmail.googleapis.com"]')
        self.assertNotIn("SERVERWARE_OPERATOR_DEMO_FIXTURE_CIDRS", gate["environment"])

    def test_manifest_mutations_fail_closed(self):
        original = prepare.build(SOURCE, BINARY, INITIALIZER, ROOT)
        for name, key, replacement in (("network", "network_mode", "host"),
                ("network", "cap_add", ["NET_ADMIN"]), ("provider", "ports", ["443:443"]),
                ("serverware", "privileged", True), ("decision-gate-rs", "entrypoint", ["/test-gate"]),
                ("check", "cap_add", ["NET_ADMIN"])):
            value = deepcopy(original)
            value["services"][name][key] = replacement
            with self.assertRaises(ValueError):
                prepare.validate(value, SOURCE, BINARY, INITIALIZER, ROOT)
        with self.assertRaises(ValueError):
            prepare.build(SOURCE, BINARY, INITIALIZER, Path("/tmp/fixture"))

    def test_only_fixture_trust_and_client_secret_file(self):
        value = prepare.build(SOURCE, BINARY, INITIALIZER, ROOT)
        app = value["services"]["serverware"]
        self.assertEqual(app["environment"]["SSL_CERT_FILE"], "/fixture-google/ca.pem")
        self.assertEqual(app["environment"]["SERVERWARE_GOOGLE_OAUTH_CLIENT_SECRET_FILE"],
                         "/run/secrets/serverware/google-client.secret")
        for service in value["services"].values():
            self.assertNotIn(fixture.CLIENT_SECRET, json.dumps(service))
            for mount in service["volumes"]:
                self.assertTrue(Path(mount["source"]).is_relative_to(ROOT)
                    or Path(mount["source"]) in (SOURCE, BINARY, INITIALIZER))
                self.assertNotIn(mount["target"], ("/etc/ssl/certs", "/var/run/docker.sock"))


class ProviderTests(unittest.TestCase):
    def test_consent_refuses_missing_broader_and_duplicate_scope(self):
        for scope in ("email openid", " ".join((*SCOPES, "profile")), " ".join((*SCOPES, "email"))):
            provider = CapturedProvider()
            params = {"response_type": "code", "client_id": fixture.CLIENT_ID,
                "redirect_uri": fixture.CONTROL_ORIGIN + "/api/oauth/callback/google",
                "scope": scope, "state": "s" * 43, "code_challenge": provider._pkce_challenge("v" * 43),
                "code_challenge_method": "S256", "access_type": "offline", "prompt": "consent",
                "include_granted_scopes": "true"}
            provider._handle_get(request("/o/oauth2/v2/auth?" + urlencode(params), host="accounts.google.com"))
            self.assertEqual(provider.replies[-1][0], 400)
            self.assertEqual(provider.observations()["active"]["authorizationCodes"], 0)

    def test_real_code_pkce_client_scope_and_one_use(self):
        provider = CapturedProvider()
        with patch.object(fixture.time, "monotonic", return_value=1000):
            (status, result), form = authorize(provider)
        self.assertEqual(status, 200)
        self.assertEqual(result["expires_in"], 90)
        self.assertEqual(set(result["scope"].split()), set(SCOPES))
        provider._handle_post(request("/token", host="oauth2.googleapis.com", method="POST", form=form))
        self.assertEqual(provider.replies[-1], (400, {"error": "invalid_grant"}))
        self.assertEqual(provider.observations()["counts"]["google"]["authorization_code_exchanges"], 1)
        other = CapturedProvider()
        (status, _), _ = authorize(other, bad_verifier=True)
        self.assertEqual(status, 400)
        self.assertEqual(other.observations()["active"]["grants"], 0)

    def test_expired_access_denied_then_rotated_refresh_authorizes(self):
        provider = CapturedProvider()
        with patch.object(fixture.time, "monotonic", return_value=1000):
            (_, tokens), _ = authorize(provider)
            provider._handle_get(request(fixture.GMAIL_PATH, token=tokens["access_token"]))
        self.assertEqual(provider.replies[-1][0], 200)
        self.assertEqual(json.dumps(provider.replies[-1][1], sort_keys=True,
            separators=(",", ":")).encode(), fixture.GMAIL_RESPONSE_BODY)
        with patch.object(fixture.time, "monotonic", return_value=1090):
            provider._handle_get(request(fixture.GMAIL_PATH, token=tokens["access_token"]))
            self.assertEqual(provider.replies[-1], (401, {"error": "invalid_token"}))
            provider._handle_get(request("/v1/userinfo", host="openidconnect.googleapis.com", token=tokens["access_token"]))
            self.assertEqual(provider.replies[-1], (401, {"error": "invalid_token"}))
            form = {"grant_type": "refresh_token", "refresh_token": tokens["refresh_token"],
                "client_id": fixture.CLIENT_ID, "client_secret": fixture.CLIENT_SECRET}
            provider._handle_post(request("/token", host="oauth2.googleapis.com", method="POST", form=form))
            status, refreshed = provider.replies[-1]
            self.assertEqual(status, 200)
            self.assertEqual(refreshed["expires_in"], 300)
            self.assertNotEqual(refreshed["access_token"], tokens["access_token"])
            provider._handle_get(request(fixture.GMAIL_PATH, token=refreshed["access_token"]))
            self.assertEqual(provider.replies[-1][0], 200)
            provider._handle_post(request("/token", host="oauth2.googleapis.com", method="POST", form=form))
            self.assertEqual(provider.replies[-1], (400, {"error": "invalid_grant"}))
            observed = provider.observations()
        self.assertTrue(observed["initialAccessExpired"])
        self.assertEqual(observed["counts"]["google"]["refresh_exchanges"], 1)
        self.assertEqual([event["token_generation"] for event in observed["events"]
            if event["type"] == "resource_authorized"], [1, 2])
        provider.assert_no_token_values(json.dumps(observed))

    def test_wrong_host_legacy_path_client_and_duplicate_auth_refused(self):
        provider = CapturedProvider()
        with patch.object(fixture.time, "monotonic", return_value=1000):
            (_, tokens), form = authorize(provider)
            for host, path in (("oauth2.googleapis.com", "/v1/userinfo"),
                    ("openidconnect.googleapis.com", "/google/identity"), ("evil.example", fixture.GMAIL_PATH)):
                provider._handle_get(request(path, host=host, token=tokens["access_token"]))
                self.assertIn(provider.replies[-1][0], (400, 404))
            duplicate = request(fixture.GMAIL_PATH, token=tokens["access_token"])
            duplicate.headers["Authorization"] = "Bearer " + tokens["access_token"]
            provider._handle_get(duplicate)
            self.assertEqual(provider.replies[-1][0], 401)
            form["client_secret"] = "wrong-synthetic-client"
            provider._handle_post(request("/token", host="oauth2.googleapis.com", method="POST", form=form))
            self.assertEqual(provider.replies[-1][0], 401)
        self.assertEqual(provider.observations()["counts"]["google"].get("resource_requests", 0), 0)

    def test_arrivals_count_before_validation_without_reflecting_input(self):
        provider = CapturedProvider()
        incoming = request(fixture.GMAIL_PATH, host="gmail.googleapis.com", method="POST", token="not-valid")
        incoming.headers["Proxy-Authorization"] = "Bearer caller-secret-do-not-reflect"
        provider.note_arrival(incoming)
        provider._handle_post(incoming)
        observed = provider.observations()
        self.assertEqual(provider.replies[-1][0], 400)
        self.assertEqual(observed["counts"]["google"]["resource_attempts"], 1)
        self.assertEqual(observed["counts"]["google"].get("resource_requests", 0), 0)
        self.assertNotIn("caller-secret", json.dumps(observed))


if __name__ == "__main__":
    unittest.main()
