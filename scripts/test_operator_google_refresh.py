#!/usr/bin/env python3
"""Focused pure/mocked checker controls; no HTTP, consent, proxy or timer run.

The separate one-shot checker must prove actual end-to-end behavior. These
controls only verify that its local oracles and uncertainty boundaries refuse
misleading synthetic observations without retries or token-bearing diagnostics.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch
from urllib.parse import urlencode

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts import check_operator_google_refresh as checker


STATE = "S" * 43
NONCE = "N" * 43
CODE = "synthetic-code-001"
POLICY = "sha256:" + "a" * 64
SCOPE = ("application-principal", "gmail-rule", POLICY)
CREDENTIAL = "credential-id"
COMMITMENTS = [("sha256:" + "b" * 64, "sha256:" + "c" * 64)] * 2


def start_document():
    values = {"response_type": "code", "client_id": checker.fixture.CLIENT_ID,
        "redirect_uri": checker.fixture.CONTROL_ORIGIN + checker.CALLBACK_PATH,
        "scope": " ".join(checker.SCOPES), "state": STATE, "code_challenge": "P" * 43,
        "code_challenge_method": "S256", "access_type": "offline", "prompt": "consent", "include_granted_scopes": "true"}
    return {"provider": "google", "state": STATE, "scopes": checker.SCOPES,
        "redirectUri": values["redirect_uri"], "authorizationUrl": checker.fixture.AUTHORIZATION_URL + "?" + urlencode(values),
        "operatorGoogleIntent": {"id": "intent-id", "status": "awaiting_consent", "scopes": checker.SCOPES,
                                "permission_preset": "gmail_readonly"}}


def cookie_header():
    return [("Set-Cookie", "__Host-serverware-oauth-" + STATE + "=" + NONCE
        + "; HttpOnly; Max-Age=300; Path=/; SameSite=lax; Secure")]


def callback_header():
    return [("Location", checker.fixture.CONTROL_ORIGIN + checker.CALLBACK_PATH + "?" + urlencode({"code": CODE, "state": STATE}))]


def observations(stage):
    consent, refresh, resources = checker.STAGES[stage]
    counts = {"authorization_requests": consent, "authorization_codes_issued": consent,
        "authorization_code_exchanges": consent, "token_requests": consent + refresh,
        "token_responses": consent + refresh, "refresh_exchanges": refresh, "identity_requests": consent,
        "resource_requests": resources, "resource_attempts": resources, "resource_gmail.messages.list": resources}
    expiry = 1090000
    events = []
    def add(kind, timestamp=1000000, **values):
        events.append({"sequence": len(events) + 1, "provider": "google", "type": kind,
                       "timestamp_epoch_ms": timestamp, **values})
    if consent:
        add("authorization_validated", outcome="success", requested_scopes=checker.SCOPES)
        add("authorization_code_issued", requested_scopes=checker.SCOPES)
        add("authorization_code_exchanged", pkce="S256", granted_scopes=checker.SCOPES)
        add("tokens_issued", grant_type="authorization_code", granted_scopes=checker.SCOPES)
        add("identity_returned", malformed=False)
    if resources:
        add("resource_received", timestamp=1005000)
        add("resource_authorized", timestamp=1005000, token_generation=1, operation="gmail.messages.list")
    if refresh:
        add("refresh_token_rotated", timestamp=expiry + 1000, granted_scopes=checker.SCOPES)
        add("tokens_issued", timestamp=expiry + 1000, grant_type="refresh_token", granted_scopes=checker.SCOPES)
        add("resource_received", timestamp=expiry + 1001)
        add("resource_authorized", timestamp=expiry + 1001, token_generation=2, operation="gmail.messages.list")
    return {"schema": "serverware.privateGoogleObservations/v1", "counts": {"google": {key: value for key, value in counts.items() if value}, "x": {}},
        "events": events, "active": {"authorizationCodes": 0, "grants": consent},
        "tokenLifetimes": {"authorizationCodeExchangeSeconds": 90, "refreshExchangeSeconds": 300},
        "initialAccessExpiresAtEpochMs": expiry if consent else None,
        "initialAccessExpired": stage in {"expired", "refreshed"}}


def generation_rows():
    rows = [
        {"id": "connected", "event_type": "credential.oauth_connected", "event": {"credential_id": CREDENTIAL, "credential_version": 1}},
        {"id": "refreshed", "event_type": "credential.oauth_refreshed", "event": {"credential_id": CREDENTIAL, "provider": "google",
            "previous_credential_version": 1, "credential_version": 2, "refresh_token_rotated": True, "scopes": checker.SCOPES}}]
    for version in (1, 2):
        common = {"principal_id": SCOPE[0], "route_id": SCOPE[1], "policy_hash": SCOPE[2], "method": "GET"}
        rows.append({"id": "start-" + str(version), "event_type": "data_plane.credential.release_started",
            "event": {**common, "credential_ref": CREDENTIAL, "credential_version": version}})
        rows.append({"id": "response-" + str(version), "event_type": "data_plane.response.released",
            "event": {**common, "request_digest": COMMITMENTS[0][0], "operation_digest": COMMITMENTS[0][1],
                "response_body_sha256": "sha256:" + hashlib.sha256(checker.fixture.GMAIL_RESPONSE_BODY).hexdigest(),
                "response_body_bytes": len(checker.fixture.GMAIL_RESPONSE_BODY)}})
    return rows


class GoogleRefreshCheckerTests(unittest.TestCase):
    def test_exact_consent_url_scope_and_pkce_are_required(self):
        value = start_document()
        self.assertTrue(checker.authorization_target(value).startswith("/o/oauth2/v2/auth?"))
        bad = []
        for old, new in (("accounts.google.com", "attacker.example"), ("response_type=code", "response_type=token"),
                ("code_challenge_method=S256", "code_challenge_method=plain"), ("access_type=offline", "access_type=online"),
                ("prompt=consent", "prompt=none"), ("code_challenge=" + "P" * 43, "code_challenge=" + "P" * 44)):
            item = deepcopy(value)
            item["authorizationUrl"] = item["authorizationUrl"].replace(old, new)
            bad.append(item)
        for extra in ("&state=extra", "&unreviewed=1", "#fragment"):
            bad.append({**value, "authorizationUrl": value["authorizationUrl"] + extra})
        bad.extend(({**value, "state": "T" * 43}, {**value, "scopes": checker.SCOPES + ["profile"]}))
        for index, item in enumerate(bad):
            with self.subTest(case=index), self.assertRaises(checker.CheckFailure):
                checker.authorization_target(item)

    def test_browser_cookie_is_host_secure_httponly_and_exactly_one(self):
        expected = "__Host-serverware-oauth-" + STATE + "=" + NONCE
        self.assertEqual(checker.browser_cookie(cookie_header(), STATE), (expected, NONCE))
        original = cookie_header()[0][1]
        candidates = [[], cookie_header() * 2]
        candidates.extend([[("Set-Cookie", original.replace(old, new))] for old, new in (
            ("; Secure", ""), ("; HttpOnly", ""), ("Path=/", "Path=/other"), ("SameSite=lax", "SameSite=none"),
            ("__Host-", ""), (NONCE, "short"))])
        candidates.append([("Set-Cookie", original + "; Domain=example.test")])
        for value in candidates:
            with self.assertRaises(checker.CheckFailure):
                checker.browser_cookie(value, STATE)

    def test_callback_is_one_exact_control_origin_with_matching_state(self):
        target, code = checker.callback_target(callback_header(), STATE)
        self.assertTrue(target.startswith(checker.CALLBACK_PATH + "?"))
        self.assertEqual(code, CODE)
        original = callback_header()[0][1]
        candidates = [[], callback_header() * 2]
        candidates.extend([[("Location", original.replace(old, new))] for old, new in (
            (checker.fixture.CONTROL_ORIGIN, "https://external.example"), ("https://", "http://"),
            (checker.CALLBACK_PATH, "/other"), (STATE, "T" * 43), (CODE, "code%0Ainjected"))])
        candidates.extend([[("Location", original + suffix)] for suffix in ("&code=duplicate", "&extra=x", "#fragment")])
        for value in candidates:
            with self.assertRaises(checker.CheckFailure):
                checker.callback_target(value, STATE)

    def test_all_five_real_provider_observation_checkpoints_have_exact_inventory(self):
        for stage in checker.STAGES:
            result = checker.validate_observations(observations(stage), stage)
            self.assertEqual(result["stage"], stage)
            self.assertNotIn("events", result)
            self.assertIsNone(checker.re.search(checker.fixture.TOKEN_PATTERN, json.dumps(result).encode()))

    def test_provider_extra_refresh_attempt_denial_or_other_provider_is_not_hidden(self):
        changes = [lambda value: value["counts"]["google"].update(refresh_exchanges=2),
            lambda value: value["counts"]["google"].update(resource_attempts=3),
            lambda value: value["counts"]["google"].update(resource_rejections=1),
            lambda value: value["counts"]["x"].update(token_requests=1),
            lambda value: value["counts"]["google"].update(identity_requests=True),
            lambda value: value["events"].append(deepcopy(value["events"][-1])),
            lambda value: value["events"][0].update(sequence=True),
            lambda value: value["events"][0].update(outcome="denial"),
            lambda value: value["events"][2].update(pkce="plain"),
            lambda value: value["active"].update(authorizationCodes=1)]
        for index, change in enumerate(changes):
            value = observations("refreshed")
            change(value)
            with self.subTest(case=index), self.assertRaises(checker.CheckFailure):
                checker.validate_observations(value, "refreshed")

    def test_refresh_skew_actual_expiry_and_new_token_generation_cannot_be_fabricated(self):
        changes = [lambda value: value.update(initialAccessExpired=False),
            lambda value: value["tokenLifetimes"].update(authorizationCodeExchangeSeconds=1),
            lambda value: value["events"][6].update(timestamp_epoch_ms=value["initialAccessExpiresAtEpochMs"] - 60000),
            lambda value: value["events"][-1].update(timestamp_epoch_ms=value["initialAccessExpiresAtEpochMs"] + 999),
            lambda value: value["events"][-1].update(token_generation=1),
            lambda value: value["events"][-1].update(operation="gmail.message.get")]
        for index, change in enumerate(changes):
            value = observations("refreshed")
            change(value)
            with self.subTest(case=index), self.assertRaises(checker.CheckFailure):
                checker.validate_observations(value, "refreshed")

    def test_negative_controls_refuse_any_principal_lease_or_refresh_effect(self):
        checker.no_dispatch_effects([{"event_type": "data_plane.connect.denied"}])
        for kind in ("data_plane.credential_lease.issued", "data_plane.credential.release_started", "credential.oauth_refreshed"):
            with self.assertRaises(checker.CheckFailure):
                checker.no_dispatch_effects([{"event_type": kind, "event": {"principal_id": "unassigned-app"}}])

    def test_real_persisted_and_rust_dispatch_generations_join_wire_commitments(self):
        result = checker.generation_evidence(generation_rows(), SCOPE, CREDENTIAL, COMMITMENTS)
        self.assertEqual(result["initialCredentialVersion"], 1)
        self.assertEqual(result["refreshedCredentialVersion"], 2)
        for change in (
            lambda value: value[0]["event"].update(credential_version=True),
            lambda value: value[1]["event"].update(previous_credential_version=2),
            lambda value: value[1]["event"].update(credential_id="another"),
            lambda value: value[1]["event"].update(refresh_token_rotated=False),
            lambda value: value[4]["event"].update(credential_version=1),
            lambda value: value[2]["event"].update(principal_id="unassigned"),
            lambda value: value[3]["event"].update(request_digest="sha256:" + "f" * 64),
            lambda value: value[5]["event"].update(response_body_bytes=0),
            lambda value: value.append(deepcopy(value[1]))):
            rows = generation_rows()
            change(rows)
            with self.assertRaises(checker.CheckFailure):
                checker.generation_evidence(rows, SCOPE, CREDENTIAL, COMMITMENTS)

    def test_escaped_provider_tokens_and_all_application_tokens_are_refused(self):
        check = object.__new__(checker.GoogleRefreshCheck)
        check.credential, check.admin_token, check.wrong_token = "synthetic-unused", "synthetic-admin", "synthetic-invalid"
        check.client_token, check.issued_tokens = "synthetic-current-app", ["synthetic-current-app", "synthetic-unassigned-app"]
        check.clean(b'{"credential_version":2}')
        for value in ("oauth-sim-access-google-000001-material", "oauth-sim-refresh-google-000002-material",
                      checker.fixture.CLIENT_SECRET, check.admin_token, *check.issued_tokens):
            with self.assertRaises(checker.CheckFailure):
                check.clean(json.dumps({"value": value}).encode())
            escaped = '"' + "".join("\\u%04x" % ord(char) for char in value) + '"'
            with self.assertRaises(checker.CheckFailure):
                check.clean(json.dumps(json.loads(escaped)).encode())

    def test_isolation_refusal_precedes_claim_credentials_or_constructor(self):
        args = argparse.Namespace(control_base=checker.fixture.CONTROL_ORIGIN, operator_origin=checker.fixture.CONTROL_ORIGIN,
            management_base="http://127.0.0.1:9091", proxy_url="http://127.0.0.1:9090",
            expected_binary_sha256=POLICY, timeout_seconds=180)
        with patch.object(checker.fixture, "assert_isolated_network", side_effect=ValueError("sensitive detail")), \
                patch.object(checker, "read_google_marker") as marker, patch.object(checker, "claim_fixture") as claim, \
                patch.object(checker, "GoogleRefreshCheck") as constructor:
            result = checker.run_checks(args)
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "ValueError")
        self.assertNotIn("sensitive detail", json.dumps(result))
        marker.assert_not_called()
        claim.assert_not_called()
        constructor.assert_not_called()

    def test_uncertain_start_and_failed_fresh_reconciliation_never_replay_consent(self):
        before = {"revision": 1, "policy": {"policy_hash": POLICY}}
        for status, catalog in ((503, None), (200, {"revision": 1, "credentials": [], "policy": {"policy_hash": POLICY}})):
            check = object.__new__(checker.GoogleRefreshCheck)
            check.run_id, check.control = "synthetic-check", object()
            check.exchange = Mock(return_value=(status, cookie_header(), json.dumps(start_document()).encode()))
            check.catalog = Mock(return_value=catalog)
            with self.assertRaises(checker.CheckFailure):
                check.connect_account(before)
            self.assertEqual(check.exchange.call_count, 1)
            self.assertEqual(check.catalog.call_count, 1 if status == 200 else 0)

    def test_successful_callback_with_failed_catalog_reconciliation_never_repeats(self):
        check = object.__new__(checker.GoogleRefreshCheck)
        check.run_id, check.control, check.accounts = "synthetic-check", object(), object()
        check.transient_values = []
        before = {"revision": 1, "policy": {"policy_hash": POLICY}}
        check.exchange = Mock(side_effect=[(200, cookie_header(), json.dumps(start_document()).encode()),
            (302, callback_header(), b""), (200, [], b"<h1>OAuth credential connected</h1>No application access has been granted")])
        check.catalog = Mock(side_effect=[{"revision": 3, "credentials": [], "policy": {"policy_hash": POLICY}},
                                          {"revision": 3}])
        with self.assertRaises(checker.CheckFailure):
            check.connect_account(before)
        self.assertEqual(check.exchange.call_count, 3)
        self.assertEqual(check.catalog.call_count, 2)
        self.assertEqual(check.transient_values, [STATE, NONCE, CODE])


if __name__ == "__main__":
    unittest.main()
