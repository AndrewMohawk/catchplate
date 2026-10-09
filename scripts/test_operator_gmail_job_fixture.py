#!/usr/bin/env python3
"""Pure finite-provider controls; no sockets, app, gate, imports of SDKs or live I/O.

Real fixture OAuth/serialization functions run against an in-memory HTTP handler.
Clock patches below test synthetic expiry boundaries, not the eventual real-time
Requests acceptance job. No production code or original fixture is patched.
"""
from email.message import Message
import io
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlencode, urlsplit

from scripts import operator_gmail_job_fixture as fixture


SCOPES = ("email", "https://www.googleapis.com/auth/gmail.readonly", "openid")


class Request(SimpleNamespace):
    def send_response(self, status):
        self.status = status

    def send_header(self, name, value):
        self.response_headers.append((name, value))

    def end_headers(self):
        pass


def request(path, *, host="gmail.googleapis.com", token=None, method="GET", form=None):
    headers = Message()
    headers["Host"] = host
    body = b"" if form is None else urlencode(form).encode("ascii")
    if form is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        headers["Content-Length"] = str(len(body))
    if token is not None:
        headers["Authorization"] = "Bearer " + token
    return Request(path=path, command=method, headers=headers, rfile=io.BytesIO(body),
        wfile=io.BytesIO(), response_headers=[], status=None,
        raw_requestline=(method + " " + path + " HTTP/1.1\r\n").encode("ascii"))


def dispatch(provider, incoming):
    provider.note_arrival(incoming)
    (provider._handle_get if incoming.command == "GET" else provider._handle_post)(incoming)
    return incoming


def target(case):
    spec = fixture.TARGETS[case]
    return spec["path"] + "?" + spec["raw_query"]


def authorize(provider):
    verifier = "v" * 43
    fields = {"response_type": "code", "client_id": fixture.base.CLIENT_ID,
        "redirect_uri": fixture.base.CONTROL_ORIGIN + "/api/oauth/callback/google",
        "scope": " ".join(SCOPES), "state": "s" * 43,
        "code_challenge": provider._pkce_challenge(verifier), "code_challenge_method": "S256",
        "access_type": "offline", "prompt": "consent", "include_granted_scopes": "true"}
    consent = dispatch(provider, request("/o/oauth2/v2/auth?" + urlencode(fields), host="accounts.google.com"))
    assert consent.status == 302
    location = dict(consent.response_headers)["Location"]
    parsed = urlsplit(location)
    assert parsed.scheme + "://" + parsed.netloc == fixture.base.CONTROL_ORIGIN
    callback = parse_qs(parsed.query)
    assert callback["state"] == ["s" * 43]
    form = {"grant_type": "authorization_code", "client_id": fixture.base.CLIENT_ID,
        "client_secret": fixture.base.CLIENT_SECRET, "redirect_uri": fields["redirect_uri"],
        "code": callback["code"][0], "code_verifier": verifier}
    response = dispatch(provider, request("/token", host="oauth2.googleapis.com", method="POST", form=form))
    assert response.status == 200
    return json.loads(response.wfile.getvalue())


class GmailJobFixtureTests(unittest.TestCase):
    def provider(self):
        return fixture.GmailJobFixture(Path("/unused-fixture-pki"))

    def test_exact_ordinary_query_vectors_and_two_page_response_shapes(self):
        self.assertEqual(list(fixture.TARGETS), ["list_page_1", "list_page_2", "message_full", "message_metadata"])
        first = "maxResults=1&labelIds=INBOX&labelIds=UNREAD&q=subject%3AServerware+fixture&prettyPrint=false"
        self.assertEqual(fixture.TARGETS["list_page_1"]["raw_query"], first)
        self.assertEqual(fixture.TARGETS["list_page_2"]["raw_query"], first + "&pageToken=fixture-page-2%2B%2F%3D")
        self.assertEqual(fixture.TARGETS["message_metadata"]["raw_query"],
            "metadataHeaders=Subject&format=metadata&metadataHeaders=From&prettyPrint=false")
        for identifier in (*fixture.MESSAGE_IDS, *fixture.THREAD_IDS):
            self.assertRegex(identifier, r"\A[0-9a-f]{16}\Z")
        page_one = json.loads(fixture.TARGETS["list_page_1"]["body"])
        page_two = json.loads(fixture.TARGETS["list_page_2"]["body"])
        self.assertEqual([page_one["messages"][0]["id"], page_two["messages"][0]["id"]], list(fixture.MESSAGE_IDS))
        self.assertEqual(page_one["nextPageToken"], fixture.PAGE_TOKEN)
        self.assertNotIn("nextPageToken", page_two)
        self.assertEqual(page_one["resultSizeEstimate"], page_two["resultSizeEstimate"])
        self.assertEqual(page_one["resultSizeEstimate"], 2)
        self.assertIn("body", json.loads(fixture.TARGETS["message_full"]["body"])["payload"])
        metadata = json.loads(fixture.TARGETS["message_metadata"]["body"])["payload"]
        self.assertNotIn("body", metadata)
        self.assertEqual([item["name"] for item in metadata["headers"]], ["Subject", "From"])

    def test_real_authorization_and_four_resource_serializations_are_observed(self):
        provider = self.provider()
        with patch.object(fixture.base.time, "monotonic", return_value=1000):
            tokens = authorize(provider)
            self.assertEqual(tokens["expires_in"], 90)
            for case, spec in fixture.TARGETS.items():
                response = dispatch(provider, request(target(case), token=tokens["access_token"]))
                self.assertEqual(response.status, 200)
                self.assertEqual(response.wfile.getvalue(), spec["body"])
                self.assertNotIn("Content-Encoding", dict(response.response_headers))
            observed = provider.observations()
        counts = observed["counts"]["google"]
        self.assertEqual(counts["authorization_code_exchanges"], 1)
        self.assertEqual(counts["resource_attempts"], 4)
        self.assertEqual(counts["resource_requests"], 4)
        self.assertEqual(counts["resource_gmail.messages.list"], 2)
        self.assertEqual(counts["resource_gmail.message.get"], 2)
        self.assertEqual(counts.get("refresh_exchanges", 0), 0)
        attempts = observed["gmailJob"]["attempts"]
        self.assertEqual([item["case"] for item in attempts], list(fixture.TARGETS))
        self.assertEqual([item["ordinal"] for item in attempts], [1, 2, 3, 4])
        self.assertTrue(all(item["authorized"] and item["status"] == 200 and item["tokenGeneration"] == 1
            and item["acceptEncodingAbsent"] for item in attempts))
        self.assertFalse(observed["initialAccessExpired"])
        provider.assert_no_token_values(json.dumps(observed))

    def test_unknown_query_compression_wrong_host_and_auth_fail_closed_and_redact(self):
        provider = self.provider()
        with patch.object(fixture.base.time, "monotonic", return_value=1000):
            tokens = authorize(provider)
            cases = []
            cases.append((request(target("list_page_1")), 401))
            duplicate = request(target("list_page_1"), token=tokens["access_token"])
            duplicate.headers["Authorization"] = "Bearer " + tokens["access_token"]
            cases.append((duplicate, 401))
            compressed = request(target("list_page_1"), token=tokens["access_token"])
            compressed.headers["Accept-Encoding"] = "gzip, deflate, br"
            cases.append((compressed, 400))
            cases.append((request(target("list_page_1"), host="oauth2.googleapis.com", token=tokens["access_token"]), 404))
            changed = fixture.base.GMAIL_PATH + "?" + urlencode(sorted(fixture.LIST_PARAMS))
            cases.append((request(changed, token=tokens["access_token"]), 400))
            private = "unknown-private-caller-material"
            cases.append((request(fixture.base.GMAIL_PATH + "?q=" + private, token=tokens["access_token"]), 400))
            cases.append((request(target("message_full"), token=tokens["access_token"], method="POST"), 404))
            for incoming, status in cases:
                self.assertEqual(dispatch(provider, incoming).status, status)
            observed = provider.observations()
        self.assertEqual(observed["counts"]["google"]["resource_attempts"], len(cases))
        self.assertEqual(observed["counts"]["google"].get("resource_requests", 0), 0)
        self.assertNotIn(private, json.dumps(observed))
        self.assertTrue(all(not item["authorized"] and item["tokenGeneration"] is None
            for item in observed["gmailJob"]["attempts"]))
        self.assertIsNone(observed["gmailJob"]["attempts"][5]["rawQuery"])
        provider.assert_no_token_values(json.dumps(observed))

    def test_unchanged_ninety_second_expiry_requires_real_rotated_refresh(self):
        provider = self.provider()
        with patch.object(fixture.base.time, "monotonic", return_value=1000):
            tokens = authorize(provider)
            self.assertEqual(dispatch(provider, request(target("list_page_1"), token=tokens["access_token"])).status, 200)
        with patch.object(fixture.base.time, "monotonic", return_value=1090):
            self.assertEqual(dispatch(provider, request(target("list_page_1"), token=tokens["access_token"])).status, 401)
            form = {"grant_type": "refresh_token", "refresh_token": tokens["refresh_token"],
                "client_id": fixture.base.CLIENT_ID, "client_secret": fixture.base.CLIENT_SECRET}
            refreshed = dispatch(provider, request("/token", host="oauth2.googleapis.com", method="POST", form=form))
            self.assertEqual(refreshed.status, 200)
            new_tokens = json.loads(refreshed.wfile.getvalue())
            self.assertEqual(new_tokens["expires_in"], 300)
            self.assertNotEqual(new_tokens["access_token"], tokens["access_token"])
            self.assertEqual(dispatch(provider, request(target("message_metadata"), token=new_tokens["access_token"])).status, 200)
            self.assertEqual(dispatch(provider, request("/token", host="oauth2.googleapis.com", method="POST", form=form)).status, 400)
            observed = provider.observations()
        self.assertTrue(observed["initialAccessExpired"])
        self.assertEqual(observed["counts"]["google"]["refresh_exchanges"], 1)
        self.assertEqual([event["token_generation"] for event in observed["events"]
            if event["type"] == "resource_authorized"], [1, 2])
        self.assertEqual(observed["tokenLifetimes"],
            {"authorizationCodeExchangeSeconds": 90, "refreshExchangeSeconds": 300})
        provider.assert_no_token_values(json.dumps(observed))

    def test_attempt_log_is_bounded_and_existing_transport_is_inherited(self):
        provider = self.provider()
        for _ in range(fixture.MAX_ATTEMPTS + 1):
            last = dispatch(provider, request(target("list_page_1")))
        observed = provider.observations()
        self.assertEqual(last.status, 503)
        self.assertEqual(len(observed["gmailJob"]["attempts"]), fixture.MAX_ATTEMPTS)
        self.assertEqual(observed["counts"]["google"]["resource_attempts"], fixture.MAX_ATTEMPTS + 1)
        self.assertIs(fixture.GmailJobFixture.start, fixture.base.GoogleFixture.start)
        self.assertIs(fixture.GmailJobFixture._issue_tokens_locked, fixture.base.GoogleFixture._issue_tokens_locked)
        self.assertIs(fixture.GmailJobFixture._handle_post, fixture.base.GoogleFixture._handle_post)


if __name__ == "__main__":
    unittest.main(verbosity=2)
