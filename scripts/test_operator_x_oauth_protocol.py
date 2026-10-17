#!/usr/bin/env python3
"""Synthetic codec tests only: no provider, transport or lifecycle admission."""
from __future__ import annotations

import base64
from dataclasses import FrozenInstanceError, replace
import hashlib
import json
from pathlib import Path
import socket
import sys
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, quote_plus, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from catchplate import operator_x_oauth_profile as profiles
from catchplate import operator_x_oauth_protocol as p

HEADERS = (("Content-Type", "application/json; charset=utf-8"),)
SECRET = "synthetic:s+e%cret λ"
ACCESS = "synthetic-access-material"
REFRESH = "synthetic-refresh-material"
VERIFIER = "V" * 43


def raw(value):
    return json.dumps(value, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def token(**changes):
    value = {"access_token": ACCESS, "refresh_token": REFRESH, "token_type": "bearer",
        "expires_in": 7200, "scope": " ".join(p.SCOPES)}
    value.update(changes)
    return value


class XOAuthProtocolTests(unittest.TestCase):
    def setUp(self):
        self.profile = profiles.build_profile(client_id="synthetic:id+%",
            public_origin="https://operator.example.com")
        self.request = p.code_exchange_request(self.profile, SECRET, "synthetic-code", VERIFIER)

    def classify(self, value=None, *, body=None, status=200, headers=HEADERS, request=None):
        return p.classify_token_response(request or self.request, status=status,
            headers=headers, body=raw(token() if value is None else value) if body is None else body)

    def uncertain(self, value):
        self.assertIs(type(value), p.UncertainResponse)
        for secret in (SECRET, ACCESS, REFRESH):
            self.assertNotIn(secret, repr(value))
        return value

    def test_fixed_requests_s256_and_rfc6749_basic(self):
        authorization = p.authorization_url(self.profile, state="S" * 43, code_verifier=VERIFIER)
        self.assertEqual(authorization.split("?")[0], "https://x.com/i/oauth2/authorize")
        query = parse_qs(urlsplit(authorization).query, strict_parsing=True)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(VERIFIER.encode()).digest()).rstrip(b"=").decode()
        self.assertEqual(query, {"response_type": ["code"], "client_id": [self.profile.client_id],
            "redirect_uri": [self.profile.redirect_uri], "scope": [" ".join(p.SCOPES)],
            "state": ["S" * 43], "code_challenge": [challenge], "code_challenge_method": ["S256"]})
        self.assertNotIn(VERIFIER, authorization)
        self.assertEqual(base64.b64decode(self.request.headers[0][1][6:]).decode(),
            quote_plus(self.profile.client_id, safe="") + ":" + quote_plus(SECRET, safe=""))
        self.assertEqual(parse_qs(self.request.body.decode()), {"grant_type": ["authorization_code"],
            "code": ["synthetic-code"], "redirect_uri": [self.profile.redirect_uri], "code_verifier": [VERIFIER]})
        refresh = p.refresh_request(self.profile, SECRET, REFRESH)
        self.assertEqual(refresh.url, "https://api.x.com/2/oauth2/token")
        self.assertEqual(parse_qs(refresh.body.decode()), {"grant_type": ["refresh_token"], "refresh_token": [REFRESH]})
        revoke = p.revoke_request(self.profile, SECRET, REFRESH, "refresh_token")
        self.assertEqual(revoke.url, "https://api.x.com/2/oauth2/revoke")
        self.assertEqual(parse_qs(revoke.body.decode()), {"token": [REFRESH], "token_type_hint": ["refresh_token"]})
        identity = p.identity_request(self.profile, ACCESS)
        self.assertEqual((identity.method, identity.url, identity.body), ("GET", "https://api.x.com/2/users/me", b""))
        for request in (self.request, refresh, revoke, identity):
            self.assertNotIn(SECRET, repr(request))
            self.assertNotIn(REFRESH, repr(request))
            self.assertNotIn(ACCESS, repr(request))

    def test_bad_inputs_fail_with_fixed_redacted_error(self):
        operations = [lambda: p.authorization_url(self.profile, state="short", code_verifier=VERIFIER),
            lambda: p.code_exchange_request(self.profile, SECRET, "secret\ncode", VERIFIER),
            lambda: p.code_exchange_request(self.profile, SECRET, "code", "x" * 42),
            lambda: p.refresh_request(self.profile, SECRET + "\n", REFRESH),
            lambda: p.refresh_request(self.profile, SECRET, "x" * (p.MAX_TOKEN_BYTES + 1)),
            lambda: p.revoke_request(self.profile, SECRET, REFRESH, "other"),
            lambda: p.identity_request(self.profile, "secret\r\nheader"),
            lambda: p.identity_request(object(), ACCESS)]
        for operation in operations:
            with self.subTest(operation=operations.index(operation)):
                with self.assertRaises(p.ProtocolError) as caught:
                    operation()
                self.assertEqual(str(caught.exception), "operator X OAuth protocol refused")

    def test_success_requires_exact_explicit_scope_refresh_and_lifetime(self):
        requests = (self.request, p.refresh_request(self.profile, SECRET, "old-refresh"))
        for request in requests:
            result = self.classify(token(scope=" ".join(reversed(p.SCOPES)), refresh_token_expires_in=3600), request=request)
            self.assertIs(type(result), p.AcceptedToken)
            self.assertIs(result.request, request)
            self.assertEqual((result.access_token, result.refresh_token, result.scopes), (ACCESS, REFRESH, p.SCOPES))
            self.assertEqual(result.refresh_token_expires_in, 3600)
            self.assertNotIn(ACCESS, repr(result))
            self.assertNotIn(REFRESH, repr(result))
            for field in ("scope", "refresh_token"):
                missing = token()
                del missing[field]
                uncertain = self.uncertain(self.classify(missing, request=request))
                self.assertIn(("access_token", ACCESS), uncertain.token_material)
                self.assertNotIn(("refresh_token", "old-refresh"), uncertain.token_material)
        invalid = [{"expires_in": True}, {"expires_in": 1.0}, {"expires_in": 0},
            {"expires_in": p.MAX_LIFETIME_SECONDS + 1}, {"refresh_token_expires_in": None},
            {"scope": " ".join(p.SCOPES[:-1])}, {"scope": " ".join(p.SCOPES) + " extra"},
            {"scope": " ".join(p.SCOPES) + " "}, {"scope": "tweet.write " * 4},
            {"token_type": "MAC"}, {"access_token": "contains space"}, {"unexpected": "value"}]
        for changes in invalid:
            with self.subTest(changes=changes):
                self.uncertain(self.classify(token(**changes)))

    def test_closed_rejection_is_not_mixed_issuance_or_retirement_proof(self):
        for status, error in ((400, "invalid_grant"), (401, "invalid_client")):
            result = self.classify({"error": error, "error_description": "synthetic denial"}, status=status)
            self.assertIs(type(result), p.RejectedToken)
            self.assertIs(result.request, self.request)
            self.assertEqual(result.error_code, error)
            self.assertFalse(hasattr(result, "consume"))
            self.assertFalse(hasattr(result, "claim_retirement"))
        for status in (200, 302, 429, 500):
            self.uncertain(self.classify({"error": "invalid_grant"}, status=status))
        for extra in ({"access_token": ACCESS}, {"refresh_token": REFRESH},
                {"access_token": None}, {"unknown": "extension"}):
            result = self.uncertain(self.classify({"error": "invalid_grant", **extra}, status=400))
            self.assertEqual(result.raw_body, raw({"error": "invalid_grant", **extra}))
        self.uncertain(self.classify({"error": "invalid_grant"}, status=401))

    def test_duplicate_and_malformed_issuance_retains_private_original(self):
        body = b'{"access_token":"first","access_token":"second","refresh_token":"synthetic-refresh-material","error":"invalid_grant"}'
        result = self.uncertain(self.classify(body=body, status=400))
        self.assertEqual(result.token_material, (("access_token", "first"), ("access_token", "second"), ("refresh_token", REFRESH)))
        self.assertEqual(result.raw_body, body)
        for body in (b'{"access_token":"synthetic-access-material","expiry":NaN}',
                b'{"access_token":"synthetic-access-material","bad":"\\ud800"}',
                b'{"access_token":"synthetic-access-material","nested":{"a":1,"a":2}}',
                b'{"access_token":"synthetic-access-material","bad":1.0}'):
            result = self.uncertain(self.classify(body=body))
            self.assertIn(("access_token", ACCESS), result.token_material)
            self.assertEqual(result.raw_body, body)
        for body in (b'{"access_token":"synthetic-access-material",', b"\xff", b"[1,2]", b"[" * 40 + b"0" + b"]" * 40):
            result = self.uncertain(self.classify(body=body))
            self.assertEqual(result.raw_body, body)
            self.assertTrue(result.raw_complete)
        result = self.uncertain(self.classify(body=b"x" * (p.MAX_TOKEN_RESPONSE_BYTES + 1)))
        self.assertFalse(result.raw_complete)
        self.assertEqual(len(result.raw_body), p.MAX_TOKEN_RESPONSE_BYTES)

    def test_physical_header_framing_and_chunked_responses(self):
        payload = raw(token())
        good = (HEADERS, HEADERS + (("Content-Length", str(len(payload))),),
            HEADERS + (("Transfer-Encoding", "chunked"),))
        for headers in good:
            self.assertIs(type(self.classify(body=payload, headers=headers)), p.AcceptedToken)
        invalid = ((), HEADERS + HEADERS, (("Content-Type", "application/json; charset=utf-8; charset=utf-8"),),
            HEADERS + (("Transfer-Encoding", "chunked"), ("Content-Length", str(len(payload)))),
            HEADERS + (("Transfer-Encoding", "gzip, chunked"),),
            HEADERS + (("Transfer-Encoding", "chunked"), ("transfer-encoding", "chunked")),
            HEADERS + (("Content-Encoding", "gzip"),), HEADERS + (("Location", "https://other.example.com"),),
            HEADERS + (("Content-Length", "1"),), HEADERS + (("X-Test", "bad\r\nheader"),))
        for headers in invalid:
            self.uncertain(self.classify(body=payload, headers=headers))
        for status in (True, "200", None):
            self.uncertain(self.classify(status=status))

    def test_request_profile_binding_cannot_be_relabelled(self):
        other = profiles.build_profile(client_id="other", public_origin="https://operator.example.com")
        foreign = p.code_exchange_request(other, SECRET, "synthetic-code", VERIFIER)
        bad = (replace(self.request, headers=()), replace(self.request, headers=foreign.headers),
            replace(self.request, body=b"grant_type=refresh_token&client_id=other"),
            replace(self.request, phase=[]), replace(self.request, phase="refresh"),
            replace(self.request, url="https://api.x.com:443/2/oauth2/token"),
            replace(self.request, body=self.request.body.replace(b"authorization_code", b"password")),
            replace(self.request, body=self.request.body + b"&code=other"),
            replace(self.request, body=self.request.body.replace(b"operator.example.com", b"other.example.com")))
        for request in bad:
            with self.assertRaises(p.ProtocolError) as caught:
                self.classify(request=request)
            self.assertEqual(str(caught.exception), "operator X OAuth protocol refused")
        identity = replace(p.identity_request(self.profile, ACCESS), headers=())
        with self.assertRaises(p.ProtocolError):
            p.classify_identity_response(identity, status=200, headers=HEADERS, body=b"{}")

    def test_numeric_identity_not_mutable_username_or_verified_badge(self):
        request = p.identity_request(self.profile, ACCESS)
        value = {"data": {"id": "123456789", "username": "Example_User", "name": "Synthetic λ"}}
        for headers in (HEADERS, HEADERS + (("Transfer-Encoding", "chunked"),)):
            result = p.classify_identity_response(request, status=200, headers=headers, body=raw(value))
            self.assertIs(type(result), p.AcceptedIdentity)
            self.assertIs(result.request, request)
            self.assertEqual(result.subject, "123456789")
        changed = {"data": {**value["data"], "username": "Renamed"}}
        result = p.classify_identity_response(request, status=200, headers=HEADERS, body=raw(changed))
        self.assertEqual(result.subject, "123456789")
        for subject in ("0", "01", "name", 123456789, str(2**64)):
            bad = {"data": {**value["data"], "id": subject}}
            self.uncertain(p.classify_identity_response(request, status=200, headers=HEADERS, body=raw(bad)))
        for bad in ({"data": {**value["data"], "verified": True}},
                {**value, "errors": []}, {"data": {"username": "Example_User", "verified": True}}):
            self.uncertain(p.classify_identity_response(request, status=200, headers=HEADERS, body=raw(bad)))

    def test_revocation_recognizes_only_supported_200_observations(self):
        request = p.revoke_request(self.profile, SECRET, REFRESH, "refresh_token")
        for body, headers in ((b"", ()), (b"", (("Content-Length", "0"),)),
                (b'{"revoked":true}', HEADERS),
                (b'{"revoked":true}', HEADERS + (("Transfer-Encoding", "chunked"),))):
            result = p.classify_revoke_response(request, status=200, headers=headers, body=body)
            self.assertIs(type(result), p.AcceptedRevocation)
            self.assertIs(result.request, request)
            self.assertFalse(hasattr(result, "consume"))
        for status, body in ((204, b""), (400, b'{"error":"invalid_token"}'),
                (200, b'{"revoked":false}'), (200, b'{"revoked":1}'), (200, b'{"revoked":true,"revoked":true}'),
                (200, b'{"revoked":true,"access_token":"synthetic-access-material"}'), (200, b"{}")):
            result = self.uncertain(p.classify_revoke_response(request, status=status, headers=HEADERS, body=body))
            self.assertEqual(result.raw_body, body)

    def test_immutable_redacted_values_and_no_network_work(self):
        with patch.object(socket, "socket", side_effect=AssertionError("codec attempted network")), \
                patch.object(socket, "getaddrinfo", side_effect=AssertionError("codec attempted DNS")):
            request = p.refresh_request(self.profile, SECRET, REFRESH)
            result = self.classify(request=request)
            uncertain = self.uncertain(self.classify(token(error="invalid_grant"), request=request))
        for value in (request, result, uncertain):
            with self.assertRaises((FrozenInstanceError, AttributeError, TypeError)):
                value.body = b"changed"
            self.assertNotIn(SECRET, repr(value))
            self.assertNotIn(ACCESS, repr(value))
            self.assertNotIn(REFRESH, repr(value))
        self.assertIs(type(request.headers), tuple)
        self.assertIs(type(uncertain.token_material), tuple)


if __name__ == "__main__":
    unittest.main()
