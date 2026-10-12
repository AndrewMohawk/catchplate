"""In-memory receiver controls, not SDK, TLS, proxy or real-provider acceptance.

Actual fixture PKCE/token/expiry/resource functions run; only the response sink
and synthetic provider clock are replaced. No sockets or files are opened.
"""
from contextlib import contextmanager
from copy import deepcopy
from email.message import Message
import hashlib
import io
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlencode, urlsplit

from scripts import operator_gmail_sdk_fixture as fixture


PATH = "/gmail/v1/users/me/messages"
CASES = ("list_page_1", "message_metadata_1", "list_page_2", "message_metadata_2")
LIST = "alt=json&labelIds=INBOX&maxResults=5&prettyPrint=false"
NEXT = "alt=json&labelIds=INBOX&maxResults=5&pageToken=next%2Bpage+%2F%3D&prettyPrint=false"
META = "alt=json&format=metadata&metadataHeaders=From&metadataHeaders=Subject&metadataHeaders=Date&prettyPrint=false"
TARGETS = (PATH + "?" + LIST, PATH + "/msg_1?" + META,
           PATH + "?" + NEXT, PATH + "/msg-2?" + META)
PUBLIC_HEADERS = {"accept": "*/*", "host": "gmail.googleapis.com",
    "user-agent": "google-api-go-client/0.5", "x-goog-api-client": "gl-go/1.26.9 gdcl/0.264.0"}
SCOPES = ["email", "https://www.googleapis.com/auth/gmail.readonly", "openid"]
EPOCH_MS = 1_800_000_000_000
ROW_KEYS = {"ordinal", "case", "method", "path", "rawQuery", "hostMatches", "headersMatch",
    "framingMatch", "requestHeaders", "requestBodySha256", "requestBodyBytes", "requestCommitment",
    "authorized", "status", "tokenGeneration", "tokenState", "timestampEpochMs",
    "responseBodySha256", "responseBodyBytes"}


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


@contextmanager
def clock(seconds):
    with patch.object(fixture.time, "monotonic", return_value=1000 + seconds), \
            patch.object(fixture.time, "time_ns", return_value=(EPOCH_MS + seconds * 1000) * 1_000_000):
        yield


@contextmanager
def captured():
    provider = fixture.GmailSdkFixture(Path("/unused-synthetic-fixture"))
    provider.replies = []
    # Preserve the subclass's actual status/body commitment recording.
    with patch.object(fixture.base.GoogleFixture, "_send_json",
            lambda self, handler, status, payload: self.replies.append((status, deepcopy(payload)))), \
            patch.object(fixture.base.GoogleFixture, "_send_redirect",
            lambda self, handler, location: self.replies.append((302, location))):
        yield provider


def request(target=TARGETS[0], *, token=None, host="gmail.googleapis.com", method="GET", form=None):
    headers = Message()
    headers["Host"] = host
    if host == "gmail.googleapis.com":
        for name, value in PUBLIC_HEADERS.items():
            if name != "host":
                headers[name] = value
        headers["Connection"] = "close"
    if token is not None:
        headers["Authorization"] = "Bearer " + token
    body = b"" if form is None else urlencode(form).encode("ascii")
    if form is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        headers["Content-Length"] = str(len(body))
    return SimpleNamespace(path=target, command=method, headers=headers, rfile=io.BytesIO(body),
        raw_requestline=(method + " " + target + " HTTP/1.1\r\n").encode("ascii"))


def send(provider, handler):
    provider.note_arrival(handler)
    if handler.command == "GET":
        provider._handle_get(handler)
    elif handler.command == "POST":
        provider._handle_post(handler)
    else:
        provider._send_json(handler, 405, {"error": "fixture_method_refused"})
    return provider.replies[-1]


def authorize(provider):
    verifier = "v" * 43
    params = {"response_type": "code", "client_id": fixture.base.CLIENT_ID,
        "redirect_uri": fixture.base.CONTROL_ORIGIN + "/api/oauth/callback/google",
        "scope": " ".join(SCOPES), "state": "s" * 43,
        "code_challenge": provider._pkce_challenge(verifier), "code_challenge_method": "S256",
        "access_type": "offline", "prompt": "consent", "include_granted_scopes": "true"}
    status, location = send(provider, request("/o/oauth2/v2/auth?" + urlencode(params), host="accounts.google.com"))
    assert status == 302
    form = {"grant_type": "authorization_code", "client_id": fixture.base.CLIENT_ID,
        "client_secret": fixture.base.CLIENT_SECRET, "redirect_uri": params["redirect_uri"],
        "code": parse_qs(urlsplit(location).query)["code"][0], "code_verifier": verifier}
    status, tokens = send(provider, request("/token", host="oauth2.googleapis.com", method="POST", form=form))
    assert status == 200
    return tokens


def refresh(provider, tokens):
    return send(provider, request("/token", host="oauth2.googleapis.com", method="POST", form={
        "grant_type": "refresh_token", "refresh_token": tokens["refresh_token"],
        "client_id": fixture.base.CLIENT_ID, "client_secret": fixture.base.CLIENT_SECRET}))


class GmailSdkFixtureTests(unittest.TestCase):
    def test_literal_stock_targets_preserve_order_plus_and_repeated_header_queries(self):
        self.assertEqual(tuple(fixture.TARGETS), CASES)
        for case, target in zip(CASES, TARGETS):
            self.assertEqual(fixture.recognized_case(target), case)
            self.assertEqual(fixture.TARGETS[case]["path"] + "?" + fixture.TARGETS[case]["raw_query"], target)
        for invalid in (TARGETS[2].replace("+%2F", "%20%2F"), TARGETS[2].replace("%2B", "%2b"),
                TARGETS[1].replace("metadataHeaders=From&metadataHeaders=Subject", "metadataHeaders=Subject&metadataHeaders=From"),
                TARGETS[0] + "&maxResults=5", TARGETS[0].replace("maxResults=5", "maxResults=1"), PATH, PATH + "?"):
            self.assertIsNone(fixture.recognized_case(invalid))

    def test_real_exchange_two_runs_and_refresh_join_closed_public_commitments(self):
        with captured() as provider, clock(0):
            tokens = authorize(provider)
            for index, target in enumerate(TARGETS):
                status, body = send(provider, request(target, token=tokens["access_token"]))
                self.assertEqual(status, 200)
                self.assertEqual(body.get("id"), (None, "msg_1", None, "msg-2")[index])
                row = provider.observations()["gmailSdk"]["attempts"][-1]
                self.assertEqual(set(row), ROW_KEYS)
                self.assertEqual((row["case"], row["authorized"], row["tokenGeneration"], row["tokenState"]),
                                 (CASES[index], True, 1, "active"))
                path, query = target.split("?", 1)
                public = {"schema": "serverware.privateGmailSdkRequest/v1", "method": "GET",
                    "authority": "gmail.googleapis.com", "path": path, "rawQuery": query,
                    "headers": PUBLIC_HEADERS, "bodySha256": digest(b""), "bodyBytes": 0}
                self.assertEqual(row["requestCommitment"], digest(encoded(public)))
                self.assertEqual((row["responseBodySha256"], row["responseBodyBytes"]), (digest(encoded(body)), len(encoded(body))))
            with clock(91):
                status, renewed = refresh(provider, tokens)
                self.assertEqual(status, 200)
                self.assertNotEqual(renewed["access_token"], tokens["access_token"])
                for target in TARGETS:
                    self.assertEqual(send(provider, request(target, token=renewed["access_token"]))[0], 200)
                observed = provider.observations()
                self.assertTrue(observed["initialAccessExpired"])
                self.assertEqual(observed["initialAccessExpiresAtEpochMs"], EPOCH_MS + 90_000)
                self.assertEqual(observed["counts"]["google"]["refresh_exchanges"], 1)
                self.assertEqual([row["tokenGeneration"] for row in observed["gmailSdk"]["attempts"]], [1]*4 + [2]*4)
                self.assertEqual(refresh(provider, tokens)[0], 400)  # no refresh-token replay
            for secret in (tokens["access_token"], tokens["refresh_token"], renewed["access_token"], renewed["refresh_token"]):
                self.assertNotIn(secret, json.dumps(observed))
                self.assertNotIn(digest(secret.encode()), json.dumps(observed))

    def test_exact_real_expiry_refuses_old_token_without_claiming_refresh(self):
        with captured() as provider, clock(0):
            tokens = authorize(provider)
            with clock(90):
                self.assertEqual(send(provider, request(token=tokens["access_token"])), (401, {"error": "invalid_token"}))
                observed = provider.observations()
                row = observed["gmailSdk"]["attempts"][0]
                self.assertEqual((row["authorized"], row["tokenState"], row["tokenGeneration"]), (False, "expired", 1))
                self.assertEqual(observed["counts"]["google"]["resource_attempts"], 1)
                self.assertEqual(observed["counts"]["google"].get("resource_requests", 0), 0)
                self.assertEqual(observed["counts"]["google"].get("refresh_exchanges", 0), 0)

    def test_header_duplicates_extra_values_and_framing_never_echo_canaries(self):
        bad = (("Authorization", "Bearer secret-canary"), ("Host", "secret-canary.invalid"),
            ("User-Agent", "secret-canary"), ("X-Goog-Api-Client", "secret-canary"),
            ("Proxy-Authorization", "secret-canary"), ("Cookie", "secret-canary"),
            ("Transfer-Encoding", "chunked"), ("Accept-Encoding", "gzip"), ("Content-Length", "1"))
        for name, value in bad:
            with self.subTest(name=name), captured() as provider, clock(0):
                tokens = authorize(provider)
                handler = request(token=tokens["access_token"])
                handler.headers[name] = value
                self.assertGreaterEqual(send(provider, handler)[0], 400)
                observed = provider.observations()
                row = observed["gmailSdk"]["attempts"][0]
                self.assertFalse(row["authorized"])
                self.assertIsNone(row["requestCommitment"])
                self.assertNotIn("secret-canary", json.dumps(observed))
                self.assertNotIn(digest(b"secret-canary"), json.dumps(observed))
                self.assertEqual(observed["counts"]["google"]["resource_attempts"], 1)

    def test_public_header_values_and_optional_zero_framing_are_exact(self):
        for name, value in (("Accept", "application/json"), ("User-Agent", "google-api-go-client/0.6"),
                ("X-Goog-Api-Client", "gl-go/1.26.9 gdcl/0.265.0"), ("Connection", "keep-alive"),
                ("Content-Length", "00"), ("Host", "gmail.googleapis.com:443")):
            with self.subTest(name=name), captured() as provider, clock(0):
                tokens = authorize(provider)
                handler = request(token=tokens["access_token"])
                del handler.headers[name]
                handler.headers[name] = value
                self.assertEqual(send(provider, handler)[0], 400)
        with captured() as provider, clock(0):
            tokens = authorize(provider)
            handler = request(token=tokens["access_token"])
            del handler.headers["Connection"]
            handler.headers["Content-Length"] = "0"
            self.assertEqual(send(provider, handler)[0], 200)

    def test_supported_go_fingerprint_refuses_old_mixed_and_extra_headers(self):
        self.assertEqual((fixture.GO_VERSION, fixture.SDK_VERSION), ("1.26.9", "0.264.0"))
        self.assertEqual(fixture.PROVIDER_HEADERS, PUBLIC_HEADERS)
        for name, value in (("X-Goog-Api-Client", "gl-go/1.23.12 gdcl/0.230.0"),
                ("X-Goog-Api-Client", "gl-go/1.23.12 gdcl/0.264.0"),
                ("X-Goog-Api-Client", "gl-go/1.26.9 gdcl/0.230.0"),
                ("X-Goog-Api-Client", "gl-go/1.26.9 gdcl/0.264.0 extra/1"),
                ("X-Extra-SDK", "extra/1")):
            with self.subTest(name=name, value=value), captured() as provider, clock(0):
                tokens = authorize(provider)
                handler = request(token=tokens["access_token"])
                del handler.headers[name]
                handler.headers[name] = value
                self.assertEqual(send(provider, handler)[0], 400)
                row = provider.observations()["gmailSdk"]["attempts"][0]
                self.assertFalse(row["headersMatch"])
                self.assertFalse(row["authorized"])
                self.assertIsNone(row["requestCommitment"])

    def test_missing_unknown_ambiguous_credentials_are_counted_not_exported(self):
        for token, duplicate, state in ((None, False, "missing"), ("secret-canary", False, "unknown"),
                ("secret-canary", True, "ambiguous")):
            with captured() as provider, clock(0):
                handler = request(token=token)
                if duplicate:
                    handler.headers["Authorization"] = "Bearer another-secret-canary"
                self.assertEqual(send(provider, handler)[0], 400 if duplicate else 401)
                observed = provider.observations()
                row = observed["gmailSdk"]["attempts"][0]
                self.assertEqual(row["tokenState"], state)
                self.assertIsNone(row["tokenGeneration"])
                self.assertNotIn("secret-canary", json.dumps(observed))

    def test_wrong_hosts_paths_methods_and_observer_aliases_remain_arrivals(self):
        for method, host, target in (("GET", "gmail.googleapis.com", "/secret-canary"),
                ("GET", "outside.invalid", TARGETS[0]), ("POST", "gmail.googleapis.com", TARGETS[0]),
                ("DELETE", "gmail.googleapis.com", TARGETS[0]),
                ("GET", "gmail.googleapis.com", "/__test__/observations?secret-canary")):
            with self.subTest(method=method, host=host), captured() as provider, clock(0):
                self.assertGreaterEqual(send(provider, request(target, host=host, method=method))[0], 400)
                observed = provider.observations()
                self.assertEqual(observed["counts"]["google"]["resource_attempts"], 1)
                self.assertNotIn("secret-canary", json.dumps(observed))
        with captured() as provider, clock(0):
            self.assertEqual(send(provider, request("/__test__/observations"))[0], 200)
            self.assertEqual(provider.observations()["gmailSdk"]["attempts"], [])

    def test_arrival_bound_and_copy_do_not_hide_overflow_or_allow_reset(self):
        with captured() as provider, clock(0):
            for _ in range(34):
                send(provider, request())
            observed = provider.observations()
            self.assertEqual(observed["counts"]["google"]["resource_attempts"], 34)
            self.assertEqual(len(observed["gmailSdk"]["attempts"]), 32)
            self.assertEqual(provider.replies[-1], (503, {"error": "fixture_attempt_bound"}))
            observed["gmailSdk"]["attempts"].clear()
            self.assertEqual(len(provider.observations()["gmailSdk"]["attempts"]), 32)
            self.assertEqual(provider.observations()["gmailSdk"]["maxAttempts"], 32)


if __name__ == "__main__":
    unittest.main()
