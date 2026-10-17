#!/usr/bin/env python3
"""Fixed callback navigation: pure controls plus real synthetic ASGI branches.

Run ASGI groups only in the bounded network-none backend harness. They reuse
the existing cold profile, state/browser/PKCE, encrypted SQLite registration and
audit fixture; only the fixed provider HTTP transport is synthetic. Pure legacy
and setup controls prove helper non-interference, not those complete workflows.
No real provider, browser, Rust proxy or deployment acceptance is claimed.
"""
from __future__ import annotations

from html.parser import HTMLParser
from http.cookies import SimpleCookie
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch
from urllib.parse import urlencode

ROOT = Path(__file__).resolve().parents[1]
for directory in (ROOT, Path(__file__).resolve().parent):
    if str(directory) not in sys.path:
        sys.path.insert(0, str(directory))

from catchplate import operator_google_landing as landing

IDENTIFIER = "01234567-89ab-4cde-8fab-0123456789ab"
OTHER_IDENTIFIER = "00000000-0000-4000-8000-000000000000"
TARGET = "/?operator_google_intent=" + IDENTIFIER + "#connect"


class Links(HTMLParser):
    def __init__(self, body):
        super().__init__(convert_charrefs=True)
        self.links = []
        self.feed(body.decode("utf-8"))

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self.links.extend(value for name, value in attrs if name == "href")


def cookie_cleared(fixture, headers):
    assert [value for name, value in headers if name.lower() == b"cache-control"] == [b"no-store"]
    values = [value.decode() for name, value in headers if name.lower() == b"set-cookie"]
    assert len(values) == 1
    cookies = SimpleCookie(values[0])
    name = fixture.oauth.browser_cookie_name(fixture.started["state"])
    assert set(cookies) == {name}
    cookie = cookies[name]
    assert cookie.value == "" and cookie["max-age"] == "0" and cookie["path"] == "/"
    assert cookie["secure"] and cookie["httponly"] and cookie["samesite"].lower() == "lax"


def success_branch():
    import test_operator_google_consent as consent
    f = consent.Fixture()
    with patch.object(f.oauth, "request_bytes", side_effect=f.transport):
        f.begin()
        target = landing.intent_target(f.started["operatorGoogleIntent"]["id"])
        code, body, headers = f.callback(operator_google_intent=OTHER_IDENTIFIER,
            return_url="https://outside.invalid/", redirect_uri="//outside.invalid/")
        assert code == 200 and Links(body).links == [target]
        assert ('window.location.href = ' + json.dumps(target) + ';').encode() in body
        assert b'}, 1200);' in body
        for value in (OTHER_IDENTIFIER, "outside.invalid", consent.CODE, f.started["state"], f.browser_nonce):
            assert value.encode() not in body
        cookie_cleared(f, headers)
        assert f.started["state"] not in f.oauth._read_states()["states"]
        f.connected()  # Actual actor intent + encrypted core + catalog join, no app grant.
        assert f.calls == [("POST", "https://oauth2.googleapis.com/token"),
            ("GET", "https://openidconnect.googleapis.com/v1/userinfo")]
        calls = list(f.calls)
        repeated, raw, _ = f.callback(operator_google_intent=OTHER_IDENTIFIER)
        assert repeated == 400 and Links(raw).links == [] and f.calls == calls
    return {"registered": True, "trusted_uuid_only": True, "state_replay_refused": True}


def denial_branch():
    import test_operator_google_consent as consent
    f = consent.Fixture()
    with patch.object(f.oauth, "request_bytes", side_effect=f.transport):
        f.begin()
        target = landing.intent_target(f.started["operatorGoogleIntent"]["id"])
        query = {"state": f.started["state"], "error": "access_denied",
            "error_description": '<a href="https://outside.invalid/">provider description</a>',
            "operator_google_intent": OTHER_IDENTIFIER, "return_url": "https://outside.invalid/"}
        code, body, headers = f.request("GET", consent.CALLBACK + "?" + urlencode(query), auth=False, origin=False)
        assert code == 400 and Links(body).links == [target]
        assert b"<script" not in body and b"window.location" not in body
        assert b"&lt;a href=" in body  # Existing escaped provider text stays text, not a link.
        assert OTHER_IDENTIFIER.encode() not in body
        assert f.started["state"].encode() not in body and f.browser_nonce.encode() not in body
        cookie_cleared(f, headers)
        assert f.started["state"] not in f.oauth._read_states()["states"]
        code, raw, _ = f.request("GET", consent.INTENTS)
        intent = json.loads(raw)["intents"][-1]
        assert code == 200 and intent["id"] == f.started["operatorGoogleIntent"]["id"]
        assert intent["status"] == "failed" and intent["reason"] == "consent_denied"
        assert not f.rows("credentials") and not f.rows("operator_catalog_credentials") and not f.calls
        f.assert_redacted()
        repeated, raw, _ = f.request("GET", consent.CALLBACK + "?" + urlencode(query), auth=False, origin=False)
        assert repeated == 400 and Links(raw).links == [] and not f.calls
    return {"manual_return_only": True, "consumed_denial": True, "provider_contacts": 0}


def untrusted_failure_branch():
    import test_operator_google_consent as consent
    f = consent.Fixture()
    with patch.object(f.oauth, "request_bytes", side_effect=f.transport):
        f.begin()
        query = {"error": "access_denied", "operator_google_intent": OTHER_IDENTIFIER,
            "return_url": "https://outside.invalid/"}
        for values in (query, {**query, "state": f.started["state"]}):
            code, body, _ = f.request("GET", consent.CALLBACK + "?" + urlencode(values),
                auth=False, origin=False, cookie=False)
            assert code == 400 and Links(body).links == []
            assert b"operator_google_intent" not in body and OTHER_IDENTIFIER.encode() not in body
            assert f.started["state"] in f.oauth._read_states()["states"] and not f.calls
        assert not f.rows("credentials") and not f.rows("operator_catalog_credentials")
    return {"unconsumed_failures_unchanged": 2, "provider_contacts": 0}


class OperatorGoogleLandingPureTests(unittest.TestCase):
    def test_canonical_uuid_has_only_fixed_relative_destination(self):
        self.assertEqual(landing.intent_target(IDENTIFIER), TARGET)
        self.assertEqual(landing.return_link(TARGET), '<p><a href="' + TARGET + '">Continue credential setup</a></p>')

    def test_reauthorization_returns_to_credentials_with_fixed_navigation(self):
        self.assertEqual(landing.reauthorization_link(IDENTIFIER),
            '<p><a href="/?operator_google_reauthorization=' + IDENTIFIER +
            '#credentials">Return to Credentials</a></p>')
        for value in (None, {}, IDENTIFIER.upper(), IDENTIFIER + '&state=secret',
                'https://outside.invalid/'):
            with self.subTest(value=value):
                self.assertEqual(landing.reauthorization_link(value),
                    '<p><a href="/#credentials">Return to Credentials</a></p>')

    def test_invalid_or_missing_uuid_uses_marker_free_fallback(self):
        for value in (None, {}, 1, "", IDENTIFIER.upper(), " " + IDENTIFIER, IDENTIFIER + "\n",
                IDENTIFIER.replace("-", ""), "{" + IDENTIFIER + "}", "https://outside.invalid/",
                IDENTIFIER + "&state=secret", IDENTIFIER + '#\"><script>'):
            with self.subTest(value=value):
                self.assertEqual(landing.intent_target(value), "/#connect")
        self.assertEqual(landing.success_target({"provider": "google", "_operator_catalog_intent": {}}), "/#connect")
        self.assertEqual(landing.denial_target({"provider": "google", "operator_catalog_intent_id": "bad"}), "/#connect")

    def test_nonoperator_other_provider_and_setup_keep_existing_navigation(self):
        exchanged = {"provider": "google", "_operator_catalog_intent": {"id": IDENTIFIER}}
        self.assertEqual(landing.success_target(exchanged), TARGET)
        self.assertIsNone(landing.success_target({"provider": "google"}))
        self.assertIsNone(landing.success_target({**exchanged, "provider": "x"}))
        self.assertIsNone(landing.success_target({**exchanged, "setupSessionId": IDENTIFIER}))
        self.assertIsNone(landing.success_target(exchanged, setup_session={"id": IDENTIFIER}))
        consumed = {"provider": "google", "operator_catalog_intent_id": IDENTIFIER}
        self.assertEqual(landing.denial_target(consumed), TARGET)
        self.assertIsNone(landing.denial_target({"provider": "google"}))
        self.assertIsNone(landing.denial_target({**consumed, "provider": "x"}))
        self.assertIsNone(landing.denial_target({**consumed, "setup_session_id": IDENTIFIER}))
        self.assertEqual(landing.return_link(None), "")

    def test_link_renderer_cannot_accept_an_arbitrary_return_url(self):
        self.assertIn('href="/#connect"', landing.return_link(landing.FALLBACK))
        for target in ("/", "//outside.invalid/", "https://outside.invalid/", TARGET + "&state=secret",
                TARGET.replace("#connect", "#other"), TARGET.replace(IDENTIFIER, IDENTIFIER.upper())):
            with self.subTest(target=target), self.assertRaises(ValueError):
                landing.return_link(target)


OPERATIONS = {"success": success_branch, "denial": denial_branch, "untrusted": untrusted_failure_branch}


class OperatorGoogleLandingASGITests(unittest.TestCase):
    def setUp(self):
        import test_operator_google_consent as consent
        consent.OperatorGoogleConsentTests.setUp(self)

    def worker(self, operation):
        result = subprocess.run([sys.executable, "-B", str(Path(__file__).resolve()), "--worker", operation],
            cwd=ROOT, env=self.environment, capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, "\n".join(result.stderr.splitlines()[-40:]))
        return json.loads(result.stdout)

    def test_success_returns_to_exact_registered_intent_and_preserves_cookie_and_state_guards(self):
        self.assertTrue(self.worker("success")["trusted_uuid_only"])

    def test_known_denial_has_manual_trusted_intent_link_without_provider_contact(self):
        self.assertTrue(self.worker("denial")["consumed_denial"])

    def test_unconsumed_callback_failures_never_trust_query_return_markers(self):
        self.assertEqual(self.worker("untrusted")["unconsumed_failures_unchanged"], 2)


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--worker":
        os.umask(0o077)
        print(json.dumps(OPERATIONS[sys.argv[2]](), sort_keys=True))
    else:
        unittest.main()
