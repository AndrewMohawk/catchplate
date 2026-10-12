#!/usr/bin/env python3
"""Offline GitHub App protocol tests; no provider, catalog or custody proof.

Only the HTTP transport is synthetic. RSA keys are generated in memory, JWTs
are independently verified, and actual bounded default HTTP configuration is
inspected using an inert opener. No credentials are stored in this fixture.
"""
import base64
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timezone
from email.message import Message
import io
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from serverware import github_app as app, http_client


def forbid_network(event, args):
    if event.startswith(("socket.", "subprocess.")):
        raise AssertionError("Network and subprocesses are forbidden in this suite")


sys.addaudithook(forbid_network)
NOW = 1791806400
CONFIG = app.AppConfig(123, 456, "fixture-owner", "fixture-repo", "write")
TOKEN = "synthetic_installation_canary"
REPO = {"id": 900, "name": "fixture-repo", "full_name": "fixture-owner/fixture-repo",
        "owner": {"id": 700, "login": "fixture-owner"}}
INSTALLATION = {"id": 456, "app_id": 123,
    "account": {"id": 700, "login": "fixture-owner", "type": "Organization"},
    "target_id": 700, "target_type": "Organization", "suspended_at": None,
    "suspended_by": None, "permissions": {"issues": "write", "metadata": "read", "contents": "write"}}


def utc(epoch):
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def mint(**changes):
    return {"token": TOKEN, "expires_at": utc(NOW + 3600),
        "permissions": {"issues": "write", "metadata": "read"},
        "repository_selection": "selected", **changes}


def response(value, status=200, *, raw=None, headers=None):
    raw = json.dumps(value, separators=(",", ":")).encode() if raw is None else raw
    headers = (("Content-Type", "application/json; charset=utf-8"),
               ("Content-Length", str(len(raw)))) if headers is None else headers
    return http_client.HttpResponse(status, dict(headers), tuple(headers), raw)


def script(*, installation=None, token=None, listing=None):
    return [response(INSTALLATION if installation is None else installation),
        response(mint() if token is None else token, 201),
        response({"total_count": 1, "repositories": [REPO]} if listing is None else listing)]


class Transport:
    def __init__(self, replies):
        self.replies, self.calls = list(replies), []

    def __call__(self, request, **kwargs):
        self.calls.append((request, kwargs))
        if not self.replies:
            raise AssertionError("Unexpected extra request")
        result = self.replies.pop(0)
        if isinstance(result, Exception):
            raise result
        return result


class GithubAppTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rsa = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.pem = cls.rsa.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        cls.key = app.load_private_key(cls.pem)

    def invoke(self, transport, *, config=CONFIG, clock=lambda: NOW):
        return app.mint_installation_token(config, self.key, transport=transport, clock=clock)

    def refused(self, replies, *, phase, uncertain, config=CONFIG):
        transport = Transport(replies)
        with self.assertRaises(app.GitHubAppError) as caught:
            self.invoke(transport, config=config)
        self.assertEqual(caught.exception.phase, phase)
        self.assertIs(caught.exception.issuance_uncertain, uncertain)
        self.assertNotIn(TOKEN, repr(caught.exception))
        self.assertNotIn(TOKEN, str(caught.exception))
        return caught.exception, transport

    def test_config_and_private_key_admission(self):
        for changes in ({"app_id": True}, {"installation_id": 0}, {"owner": "bad/owner"},
                        {"repository": ".."}, {"issues": "admin"}, {"repository_id": 1},
                        {"account_id": 1}, {"account_id": True, "repository_id": 1}):
            with self.subTest(changes=changes), self.assertRaises(app.GitHubAppError):
                replace(CONFIG, **changes)
        self.assertNotIn("PRIVATE KEY", repr(self.key))
        pkcs1 = self.rsa.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption())
        self.assertEqual(app.load_private_key(pkcs1).fingerprint, self.key.fingerprint)
        other = ec.generate_private_key(ec.SECP256R1()).private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        small = rsa.generate_private_key(public_exponent=65537, key_size=1024).private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        encrypted = self.rsa.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.BestAvailableEncryption(b"synthetic-passphrase"))
        for value in (b"", self.pem + self.pem, self.pem + b"suffix", other, small, encrypted,
                      b"x" * 16385, self.pem.decode()):
            with self.subTest(length=len(value)), self.assertRaises(app.GitHubAppError):
                app.load_private_key(value)

    def test_rs256_signature_and_claims(self):
        token = app.app_jwt(CONFIG, self.key, NOW)
        header, payload, signature = token.split(".")
        decode = lambda value: base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        self.assertEqual(json.loads(decode(header)), {"alg": "RS256", "typ": "JWT"})
        self.assertEqual(json.loads(decode(payload)), {"iss": "123", "iat": NOW - 60, "exp": NOW + 540})
        self.rsa.public_key().verify(decode(signature), (header + "." + payload).encode(),
            padding.PKCS1v15(), hashes.SHA256())
        for value in (True, float("nan"), 0):
            with self.assertRaises(app.GitHubAppError):
                app.app_jwt(CONFIG, self.key, value)
        with self.assertRaises(app.GitHubAppError):
            app.app_jwt(CONFIG, replace(self.key, fingerprint="sha256:" + "0" * 64), NOW)

    def test_first_connect_exact_calls_permissions_and_independent_binding(self):
        transport = Transport(script())
        result = self.invoke(transport)
        self.assertEqual(result.config, replace(CONFIG, account_id=700, repository_id=900))
        self.assertEqual((result.token, result.issued_at, result.expires_at), (TOKEN, NOW, NOW + 3600))
        self.assertNotIn(TOKEN, repr(result))
        calls = transport.calls
        self.assertEqual([r.get_method() for r, _ in calls], ["GET", "POST", "GET"])
        self.assertEqual([r.full_url for r, _ in calls], [
            "https://api.github.com/repos/fixture-owner/fixture-repo/installation",
            "https://api.github.com/app/installations/456/access_tokens",
            "https://api.github.com/installation/repositories?per_page=100&page=1"])
        self.assertEqual(json.loads(calls[1][0].data), {"repositories": ["fixture-repo"],
            "permissions": {"issues": "write", "metadata": "read"}})
        for index, (request, options) in enumerate(calls):
            headers = {k.lower(): v for k, v in request.header_items()}
            self.assertEqual(set(headers), {"accept", "authorization", "x-github-api-version",
                "user-agent", "accept-encoding"} | ({"content-type"} if index == 1 else set()))
            self.assertEqual(headers["accept"], "application/vnd.github+json")
            self.assertEqual(headers["accept-encoding"], "identity")
            self.assertEqual(headers["x-github-api-version"], "2022-11-28")
            self.assertTrue(options["require_https"])
            self.assertEqual(options["timeout"], 10.0)
            self.assertEqual(options["max_bytes"], 65536 if index == 1 else 1048576)
            self.assertIs(options["deadline"], calls[0][1]["deadline"])
            self.assertEqual(options["expected_statuses"], tuple(range(200, 600)))
        self.assertEqual(calls[0][0].get_header("Authorization"), calls[1][0].get_header("Authorization"))
        self.assertEqual(calls[2][0].get_header("Authorization"), "Bearer " + TOKEN)

    def test_installation_failures_precede_mint(self):
        variants = [{**INSTALLATION, "app_id": 124}, {**INSTALLATION, "id": 457},
            {**INSTALLATION, "suspended_at": "2026-10-01T00:00:00Z"},
            {**INSTALLATION, "target_id": 701}, {**INSTALLATION, "target_type": "User"},
            {**INSTALLATION, "permissions": {"metadata": "read", "issues": "read"}}]
        for account in ({"id": True, "login": "fixture-owner", "type": "Organization"},
                        {"id": 700, "login": "different", "type": "Organization"}):
            variants.append({**INSTALLATION, "account": account})
        missing = dict(INSTALLATION)
        del missing["suspended_at"]
        variants.append(missing)
        for value in variants:
            with self.subTest(value=value):
                _, transport = self.refused(script(installation=value), phase="installation", uncertain=False)
                self.assertEqual(len(transport.calls), 1)
        self.refused([response({}, 301)], phase="installation", uncertain=False)
        self.refused([ConnectionError("private transport canary")], phase="installation", uncertain=False)

    def test_read_ceiling_and_case_insensitive_names(self):
        config = replace(CONFIG, owner="Fixture-Owner", repository="Fixture-Repo", issues="read")
        transport = Transport(script(token=mint(permissions={"issues": "read", "metadata": "read"})))
        result = self.invoke(transport, config=config)
        self.assertEqual(result.config.repository_id, 900)
        self.assertEqual(json.loads(transport.calls[1][0].data)["permissions"]["issues"], "read")

    def test_opaque_stateless_and_legacy_bearer_tokens(self):
        for token in ("ghs_legacySynthetic", "ghs_123_eyJhbGciOiJSUzI1NiJ9.eyJleHAiOjF9.signature-with_underscore",
                      "synthetic+opaque/token~with.padding=="):
            transport = Transport(script(token=mint(token=token)))
            self.assertEqual(self.invoke(transport).token, token)
            self.assertEqual(transport.calls[2][0].get_header("Authorization"), "Bearer " + token)
        for token in ("", "bad token", "bad\nheader", "bad:token", "=padding", "mid=dle", "x" * 8193):
            self.refused(script(token=mint(token=token)), phase="mint", uncertain=True)

    def test_mint_failure_uncertainty_and_private_evidence(self):
        variants = [mint(permissions={"issues": "write", "metadata": "read", "contents": "read"}),
            mint(permissions={"issues": "read", "metadata": "read"}), mint(repository_selection="all"),
            mint(expires_at=utc(NOW)), mint(expires_at=utc(NOW + 3661)),
            mint(expires_at="2026-10-12T12:00:00+00:00"), mint(token="bad\r\nheader")]
        for value in variants:
            with self.subTest(value=value):
                error, transport = self.refused(script(token=value), phase="mint", uncertain=True)
                self.assertEqual(len(transport.calls), 2)
                self.assertEqual(json.loads(error.mint_body), value)
        for raw in (b'{"token":"first","token":"second"}',
                    b'{"token":"synthetic_installation_canary","error":"canary"}', b"not json"):
            error, _ = self.refused([response(INSTALLATION), response({}, 201, raw=raw)],
                phase="mint", uncertain=True)
            self.assertEqual(error.mint_body, raw)
        error, transport = self.refused([response(INSTALLATION), TimeoutError("private canary")],
            phase="mint", uncertain=True)
        self.assertEqual(error.mint_body, b"")
        self.assertEqual(len(transport.calls), 2)
        self.assertNotIn("private canary", repr(error))
        for status in (200, 301, 401, 422, 503):
            error, _ = self.refused([response(INSTALLATION), response(mint(), status)],
                phase="mint", uncertain=True)
            self.assertEqual(json.loads(error.mint_body)["token"], TOKEN)

    def test_response_framing_media_duplicate_json_and_limits(self):
        raw = json.dumps(INSTALLATION).encode()
        invalid_headers = [(('Content-Type', 'text/plain'),),
            (('Content-Type', 'application/json'), ('Content-Type', 'application/json')),
            (('Content-Type', 'application/json'), ('Content-Encoding', 'gzip')),
            (('Content-Type', 'application/json'), ('Content-Length', '2')),
            (('Content-Type', 'application/json'), ('Content-Length', str(len(raw))),
             ('Transfer-Encoding', 'chunked'))]
        for headers in invalid_headers:
            self.refused([response({}, raw=raw, headers=headers)], phase="installation", uncertain=False)
        self.refused([response({}, raw=b'{"id":1,"id":2}')], phase="installation", uncertain=False)
        self.refused([response({}, raw=b"x" * (1048576 + 1))], phase="installation", uncertain=False)
        replies = script()
        replies[0] = response(INSTALLATION, headers=(("Content-Type", "application/json"),
                                                   ("Transfer-Encoding", "chunked")))
        self.assertEqual(self.invoke(Transport(replies)).config.repository_id, 900)

    def test_independent_repository_exactness_and_retained_candidate(self):
        variants = [{"total_count": 2, "repositories": [REPO]},
            {"total_count": True, "repositories": [REPO]}, {"total_count": 1, "repositories": []},
            {"total_count": 1, "repositories": [REPO, REPO]}]
        for change in ({"id": True}, {"name": "other"}, {"full_name": "other/fixture-repo"},
                       {"owner": {"id": 701, "login": "fixture-owner"}}):
            variants.append({"total_count": 1, "repositories": [{**REPO, **change}]})
        for listing in variants:
            error, transport = self.refused(script(listing=listing), phase="repository", uncertain=True)
            self.assertEqual(error.candidate_tokens, (TOKEN,))
            self.assertEqual(len(transport.calls), 3)
        self.refused(script(token=mint(repositories=[{**REPO, "id": 901}])),
            phase="repository", uncertain=True)
        self.refused(script(token=mint(repositories=[REPO, REPO])), phase="mint", uncertain=True)

    def test_renewal_uses_pinned_ids_and_refuses_identity_adoption(self):
        config = replace(CONFIG, account_id=700, repository_id=900)
        transport = Transport(script())
        self.assertEqual(self.invoke(transport, config=config).config, config)
        self.assertEqual(json.loads(transport.calls[1][0].data), {"repository_ids": [900],
            "permissions": {"issues": "write", "metadata": "read"}})
        self.refused(script(listing={"total_count": 1, "repositories": [{**REPO, "id": 901}]}),
            phase="repository", uncertain=True, config=config)
        installation = deepcopy(INSTALLATION)
        installation["account"]["id"] = installation["target_id"] = 701
        self.refused(script(installation=installation), phase="installation", uncertain=False, config=config)

    def test_refresh_margin_reuse_rotation_and_no_stale_fallback(self):
        current = self.invoke(Transport(script()))
        empty = Transport([])
        self.assertIs(app.get_or_refresh(CONFIG, self.key, current, transport=empty, clock=lambda: NOW + 1), current)
        self.assertEqual(empty.calls, [])
        self.assertFalse(app.needs_refresh(current, NOW + 3539))
        self.assertTrue(app.needs_refresh(current, NOW + 3540))
        self.assertTrue(app.needs_refresh(current, NOW - 1))
        for config in (replace(CONFIG, issues="read"), replace(CONFIG, repository="other"),
                       replace(CONFIG, account_id=700, repository_id=901)):
            with self.assertRaises(app.GitHubAppError):
                app.get_or_refresh(config, self.key, current, transport=empty, clock=lambda: NOW)
        self.assertEqual(empty.calls, [])
        next_key = app.load_private_key(rsa.generate_private_key(public_exponent=65537, key_size=2048)
            .private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        refresh = Transport(script())
        renewed = app.get_or_refresh(CONFIG, next_key, current, transport=refresh, clock=lambda: NOW)
        self.assertEqual(renewed.key_fingerprint, next_key.fingerprint)
        self.assertEqual(json.loads(refresh.calls[1][0].data)["repository_ids"], [900])
        failing = Transport([ConnectionError("private canary")])
        with self.assertRaises(app.GitHubAppError):
            app.get_or_refresh(CONFIG, self.key, current, transport=failing, clock=lambda: NOW + 3540)
        self.assertEqual(len(failing.calls), 1)

    def test_clock_checked_after_repository_verification(self):
        for end in (NOW - 1, NOW + 3600, float("nan")):
            clock = iter((NOW, end))
            error, transport = None, Transport(script())
            with self.assertRaises(app.GitHubAppError) as caught:
                self.invoke(transport, clock=lambda: next(clock))
            error = caught.exception
            self.assertEqual((error.phase, error.issuance_uncertain), ("repository", True))
            self.assertEqual(error.candidate_tokens, (TOKEN,))

    def test_default_transport_disables_environment_proxies_and_redirects(self):
        # Exercise request_bytes' real opener construction without opening a socket.
        class Stream(io.BytesIO):
            status = 200
            def __init__(self):
                super().__init__(b"{}")
                self.headers = Message()
                self.headers["Content-Type"] = "application/json"
                self.headers["Content-Length"] = "2"
            def settimeout(self, timeout):
                self.timeout = timeout
            def getcode(self):
                return self.status
        class Opener:
            def open(self, request, timeout):
                self.request, self.timeout = request, timeout
                return Stream()
        opener = Opener()
        with patch.dict(os.environ, {"HTTPS_PROXY": "https://forbidden.invalid", "HTTP_PROXY": "http://forbidden.invalid"}), \
             patch.object(urllib.request, "build_opener", return_value=opener) as build:
            result = http_client.request_bytes(urllib.request.Request(app.ORIGIN + "/app"),
                timeout=1, max_bytes=8, require_https=True, expected_statuses=(200,))
        self.assertEqual(result.body, b"{}")
        handlers = build.call_args.args
        proxy = next(h for h in handlers if isinstance(h, urllib.request.ProxyHandler))
        self.assertEqual(proxy.proxies, {})
        redirect = next(h for h in handlers if isinstance(h, http_client._NoRedirectHandler))
        self.assertIsNone(redirect.redirect_request(None, None, 301, "", {}, "https://other.invalid"))
        https = next(h for h in handlers if isinstance(h, urllib.request.HTTPSHandler))
        self.assertIsNone(https._context)  # urllib's default verifies certificates and hostnames.
        self.assertEqual(opener.addheaders, [])


if __name__ == "__main__":
    unittest.main()
