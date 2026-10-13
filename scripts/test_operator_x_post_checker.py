#!/usr/bin/env python3
"""Inert checker-contract controls, not SDK, TLS, custody or gate acceptance.

Literal synthetic wire/authority observations exercise refusal and exact joins.
Process/HTTP orchestration doubles only test the checker; they never stand in
for an accepted lifecycle, provider contact, encrypted lease or durable audit.
No fixture, subprocess, socket, dependency installation or database is opened.
"""
from __future__ import annotations

from collections import Counter
from contextlib import redirect_stdout
from copy import deepcopy
import hashlib
import io
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from urllib.parse import urlencode

from scripts import check_operator_x_post as check


APP = "11111111-1111-4111-8111-111111111111"
CREDENTIAL = "22222222-2222-4222-8222-222222222222"
RULE = "33333333-3333-4333-8333-333333333333"
CONSENT = "44444444-4444-4444-8444-444444444444"
DISCONNECT = "55555555-5555-4555-8555-555555555555"
SCOPE = ("operator." + APP, "operator." + RULE, "sha256:" + "a" * 64)
ANCHOR = 2_000_000_000_000
TEXT = "Serverware local check: caf\u00e9 & <verified>\n"
BODIES = {
    "node": b'{"text":"Serverware local check: caf\xc3\xa9 & <verified>\\n"}',
    "python": b'{"text": "Serverware local check: caf\\u00e9 & <verified>\\n"}',
    "go": b'{"text":"Serverware local check: caf\xc3\xa9 \\u0026 \\u003cverified\\u003e\\n"}',
}
REFLECTION = b'{"text":"Serverware local check: reflect response"}'


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def sha(value):
    return "sha256:" + hashlib.sha256(value if type(value) is bytes else canonical(value)).hexdigest()


def headers(client, raw):
    result = {"host": "api.x.com", "content-length": str(len(raw)), "content-type": "application/json",
        "accept": "*/*" if client == "python" else "application/json",
        "user-agent": {"node": "xdk-typescript/0.6.6", "python": "xdk-python/0.10.6", "go": "Go-http-client/1.1"}[client]}
    if client == "node":
        result.update({"accept-language": "*", "sec-fetch-mode": "cors"})
    return result


def provider(*, disconnected=True):
    rows = []
    for ordinal, client in enumerate(("node", "python", "go", "node", "python", "go", "node"), 1):
        raw = REFLECTION if ordinal == 7 else BODIES[client]
        response = canonical({"data": {"id": str(9000000000000000000 + ordinal), "text": TEXT}})
        rows.append({"ordinal": ordinal, "client": client, "case": "reflection" if ordinal == 7 else "success",
            "generation": 1 if ordinal <= 3 else 2, "requestBodySha256": sha(raw), "requestBodyBytes": len(raw),
            "requestHeaders": headers(client, raw), "timestampEpochMs": ANCHOR + (1000 if ordinal <= 3 else 122000) + ordinal,
            "responseBodySha256": sha(b"opaque-reflected-response") if ordinal == 7 else sha(response),
            "responseBytes": 250 if ordinal == 7 else len(response), "status": 201,
            "postId": str(9000000000000000000 + ordinal), "providerCredentialMatched": True,
            "proxyAuthorizationPresent": False})
    counts = {"authorize": 1, "code": 1, "refresh": 1, "identity": 2, "revoke": 4 if disconnected else 0,
        "posts": 7, "rejected": 0}
    counts["total"] = sum(counts.values())
    return {"schema": "serverware.privateXPostObservations/v1", "syntheticOnly": True, "terminal": "running",
        "counts": counts, "initialAccessIssuedAtEpochMs": ANCHOR + 100,
        "initialAccessExpiresAtEpochMs": ANCHOR + 120100, "initialAccessExpired": True,
        "refreshAfterInitialExpiry": True, "tokenLifetimes": {"initial": 120, "refreshed": 600},
        "issuedGenerations": [1, 2], "posts": rows,
        "revocations": [{"generation": g, "tokenTypeHint": hint, "originalClientVerified": True}
            for g in (1, 2) for hint in ("access_token", "refresh_token")] if disconnected else [],
        "cleanupComplete": disconnected, "overflowed": False}


def commitments(row):
    raw = REFLECTION if row["case"] == "reflection" else BODIES[row["client"]]
    value = {"v": 2, "principal": SCOPE[0], "client_ip": "127.0.0.1", "route_id": SCOPE[1],
        "credential_ref": CREDENTIAL, "credential_version": str(row["generation"]), "policy_hash": SCOPE[2],
        "request": {"method": "POST", "scheme": "https", "authority": "api.x.com", "path": "/2/tweets",
            "query": [], "headers": headers(row["client"], raw), "body_sha256": sha(raw),
            "discard_headers": ["accept-encoding"]}, "operation": {"operation": "tweets.write"}}
    return sha(value), sha({k: v for k, v in value.items() if k not in {"v", "client_ip"}})


def event(kind, value, index):
    return {"id": sha(str(index).encode()), "event_type": kind, "event": deepcopy(value),
        "event_hash": sha(("audit" + str(index)).encode())}


def attempts(rows=None):
    result = []
    for index, row in enumerate(provider()["posts"] if rows is None else rows):
        request, operation = commitments(row)
        binding = {"principal_id": SCOPE[0], "route_id": SCOPE[1], "policy_hash": SCOPE[2],
            "credential_ref": CREDENTIAL, "credential_version": row["generation"], "method": "POST",
            "attempt_id": sha(("attempt" + str(index)).encode()), "flow_id": sha(("attempt" + str(index)).encode()),
            "request_digest": request, "operation_digest": operation, "body_sha256": row["requestBodySha256"]}
        result.append(event(check.START, {**binding, "outcome": "release_started"}, index * 2))
        if row["case"] == "reflection":
            terminal = {**binding, "outcome": "blocked", "upstream_status": 201,
                "response_validation": {"ok": False, "error": "response_credential_reflection"},
                "upstreamDispatch": "response_received", "providerOutcome": "unknown",
                "retryProviderRequest": False, "providerOperationMayHaveCommitted": True}
            kind = check.BLOCK
        else:
            terminal = {**binding, "outcome": "released", "upstream_status": 201,
                "response_validation": {"ok": True, "body_bytes_preserved": True, "mode": "xPostJsonV1"},
                "response_body_sha256": row["responseBodySha256"], "response_body_bytes": row["responseBytes"]}
            kind = check.RELEASE
        result.append(event(kind, terminal, index * 2 + 1))
    return result


def catalog():
    return {"revision": 8, "policy": {"policy_hash": SCOPE[2], "sequence": 2},
        "credentials": [{"id": CREDENTIAL, "version": 1, "credential_generation": 1, "status": "active",
            "oauth_client_id": "original-client", "provider_subject": "18446744073709551001", "scopes": list(check.SCOPES)}],
        "applications": [{"id": APP, "principal_id": SCOPE[0]}],
        "access_rules": [{"id": RULE, "route_id": SCOPE[1], "status": "active"}],
        "observed_activity": {"timestamp": 1}, "capabilities": {"x": "unchanged"}}


def receipt():
    counts = {check.START: 7, check.RELEASE: 6, check.BLOCK: 1, check.CONNECT: 10, check.CONNECT_DENIED: 6,
        "operator_catalog.application.created": 2, "operator_catalog.access_rule.x_post_created": 1,
        check.LEASE: 4, check.RELOAD: 3}
    counts.update({"operator_catalog.x_oauth." + name: 1 for name in ("configuration_saved", "consent_started",
        "exchange_claimed", "account_connected", "account_refreshed", "disconnect_fenced", "disconnected")})
    negatives = []
    for phase in ("wrong_app", "wrong_outer_ca", "wrong_inner_ca", "disconnected"):
        for client in ("node", "python", "go"):
            kind = check.CONNECT if phase == "wrong_inner_ca" else None if phase == "wrong_outer_ca" else check.CONNECT_DENIED
            negatives.append({"phase": client + ":" + phase, "providerPostsAdded": 0, "kind": kind,
                "auditIds": [] if kind is None else [sha((client + phase).encode())]})
    return {"schema": "serverware.privateXPostCheck/v1", "ok": True, "syntheticOnly": True, "realXVerified": False,
        "productionReady": False, "publicDnsVerified": False, "actualExampleEntrypoints": True,
        "actualManagedLifecycle": True, "auditChainVerified": True, "separateOuterInnerTrust": True,
        "dataPlaneBinaryDigest": "sha256:" + "b" * 64, "goExampleSha256": "c" * 64,
        "dependenciesSha256": "d" * 64, "exampleSourceSha256": {name: "e" * 64 for name in check.profiles.SOURCE_FILES},
        "completed": [{"phase": phase, "exitCode": 0 if phase.endswith((":first", ":refreshed")) else 2,
            "confirmed": phase.endswith((":first", ":refreshed"))} for phase in check.profiles.PHASES],
        "negativeControls": negatives, "provider": provider(), "canonicalRequestVersion": 2,
        "credentialGenerations": [1, 2], "preCallbackEpochMs": ANCHOR, "providerPropagationProven": False,
        "attemptIds": [sha(("attempt" + str(i)).encode()) for i in range(7)],
        "generationAuditIds": [CONSENT, DISCONNECT], "namedAuditInventory": counts, "reconciliationRejections": 0}


class CheckerTests(unittest.TestCase):
    def setUp(self):
        self.addCleanup(patch.stopall)
        patch("socket.socket", side_effect=AssertionError("inert checker test attempted a socket")).start()
        patch("subprocess.Popen", side_effect=AssertionError("inert checker test attempted a process")).start()

    def validate_provider(self, value):
        return check.validate_observations(value, posts=7, connected=True, refreshed=True,
            disconnected=True, first_anchor=ANCHOR, expired=True)

    def test_closed_json_rejects_duplicate_nonfinite_and_bounds(self):
        self.assertEqual(check.document(b'{"x":[1,"value"]}'), {"x": [1, "value"]})
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":Infinity}', b'\xff', b'{}' * 524289, b'{'):
            with self.subTest(size=len(raw)), self.assertRaises(check.CheckFailure):
                check.document(raw)

    def test_all_nineteen_environments_use_fixed_commands_and_separate_trust(self):
        self.assertEqual(len(check.profiles.PHASES), 19)
        for phase in check.profiles.PHASES:
            value = check.client_environment(phase, APP, "t" * 43)
            self.assertEqual(set(value), {"LANG", "SERVERWARE_PROXY_URL", "SERVERWARE_APP_ID", "SERVERWARE_PROXY_TOKEN",
                "SERVERWARE_CA_FILE", "SERVERWARE_PROXY_CA_FILE", "SERVERWARE_X_POST_TEXT", "SERVERWARE_X_POST_CONFIRM"})
            self.assertEqual(value["SERVERWARE_PROXY_URL"], "https://proxy.operator-basic.example.test:8443")
            self.assertEqual(value["SERVERWARE_X_POST_CONFIRM"], "post-once")
            self.assertEqual(value["SERVERWARE_X_POST_TEXT"], "Serverware local check: reflect response" if phase == "node:reflected" else TEXT)
            self.assertEqual(value["SERVERWARE_CA_FILE"], "/client-trust/outer-ca.pem" if phase.endswith(":wrong_inner_ca") else "/client-trust/inner-ca.pem")
            self.assertEqual(value["SERVERWARE_PROXY_CA_FILE"], "/client-trust/inner-ca.pem" if phase.endswith(":wrong_outer_ca") else "/client-trust/outer-ca.pem")
        for app, token in (("wrong", "t" * 43), (APP, "short")):
            with self.assertRaises(check.CheckFailure):
                check.client_environment("node:first", app, token)

    def test_sdk_success_and_unknown_are_exact_and_never_report_retry_safe(self):
        for client in ("node", "python", "go"):
            self.assertTrue(check.validate_client_result(client + ":first", 0,
                b'{"status":201,"id":"9000000000000000001"}\n', b"", "9000000000000000001")["confirmed"])
        node = {"ok": False, "operation": "create-post", "outcome": "unknown", "mayHaveBeenPosted": True,
            "automaticRetryAllowed": False, "httpStatus": 409, "error": check.profiles.NODE_UNKNOWN}
        self.assertFalse(check.validate_client_result("node:reflected", 2, b"", canonical(node))["confirmed"])
        for key, value in (("httpStatus", 502), ("automaticRetryAllowed", True), ("error", "secret-canary"), ("extra", "secret-canary")):
            with self.subTest(field=key), self.assertRaises(check.CheckFailure):
                check.validate_client_result("node:reflected", 2, b"", canonical({**node, key: value}))
        for client in ("python", "go"):
            check.validate_client_result(client + ":wrong_app", 2, b"", check.profiles.FAILURE_MESSAGES[client])
            with self.assertRaises(check.CheckFailure):
                check.validate_client_result(client + ":wrong_app", 2, b"", b"secret-canary")
        for code in (True, 0, 1):
            with self.assertRaises(check.CheckFailure):
                check.validate_client_result("node:reflected", code, b"", canonical(node))

    def test_provider_literal_bytes_headers_generations_and_original_cleanup(self):
        self.assertEqual(self.validate_provider(provider()), provider())
        for index, raw in enumerate(BODIES.values()):
            self.assertEqual(provider()["posts"][index]["requestBodySha256"], sha(raw))
        # Equivalent text is intentionally three different original byte commitments.
        self.assertEqual(len({sha(raw) for raw in BODIES.values()}), 3)
        for modify in (
            lambda v: v["counts"].update(posts=8, total=20),
            lambda v: v["posts"][0].update(generation=True),
            lambda v: v["posts"][1]["requestHeaders"].update(authorization="secret-canary"),
            lambda v: v["posts"][2].update(requestBodySha256=sha(BODIES["node"])),
            lambda v: v["posts"][3].update(responseBodySha256="sha256:" + "0" * 64),
            lambda v: v["revocations"][0].update(originalClientVerified=False),
            lambda v: v["revocations"].__setitem__(0, deepcopy(v["revocations"][1])),
            lambda v: v.update(overflowed=True),
        ):
            value = provider(); modify(value)
            with self.subTest(control=repr(modify.__code__.co_firstlineno)), self.assertRaises(check.CheckFailure):
                self.validate_provider(value)

    def test_expiry_is_original_and_first_wave_uses_pre_callback_anchor(self):
        for modify in (
            lambda v: v.update(initialAccessExpiresAtEpochMs=ANCHOR + 120101),
            lambda v: v.update(refreshAfterInitialExpiry=False),
            lambda v: v.update(initialAccessExpired=False),
            lambda v: v["posts"][0].update(timestampEpochMs=ANCHOR + 60000),
            lambda v: v["posts"][3].update(timestampEpochMs=ANCHOR + 121099),
            lambda v: v["tokenLifetimes"].update(initial=121),
        ):
            value = provider(); modify(value)
            with self.subTest(line=modify.__code__.co_firstlineno), self.assertRaises(check.CheckFailure):
                self.validate_provider(value)

    def test_canonical_v2_joins_actual_raw_body_header_and_generation(self):
        for row in provider()["posts"]:
            self.assertEqual(check.canonical_digests(row, SCOPE, CREDENTIAL), commitments(row))
        first, refreshed = provider()["posts"][0], provider()["posts"][3]
        self.assertEqual(first["requestBodySha256"], refreshed["requestBodySha256"])
        self.assertNotEqual(commitments(first), commitments(refreshed))
        with self.assertRaises(check.CheckFailure):
            check.canonical_digests({**first, "generation": True}, SCOPE, CREDENTIAL)

    def test_attempt_multiset_allows_duplicate_digest_but_not_replayed_identity(self):
        rows = [provider()["posts"][0], deepcopy(provider()["posts"][0])]
        evidence = attempts(rows)
        self.assertEqual(evidence[0]["event"]["request_digest"], evidence[2]["event"]["request_digest"])
        self.assertEqual(len(check.match_attempts(evidence, rows, SCOPE, CREDENTIAL)), 2)
        for mutate in (
            lambda v: v.pop(),
            lambda v: v.append(deepcopy(v[0])),
            lambda v: v[2]["event"].update(attempt_id=v[0]["event"]["attempt_id"], flow_id=v[0]["event"]["flow_id"]),
            lambda v: v[3]["event"].update(policy_hash="sha256:" + "f" * 64),
        ):
            changed = deepcopy(evidence); mutate(changed)
            with self.subTest(line=mutate.__code__.co_firstlineno), self.assertRaises(check.CheckFailure):
                check.match_attempts(changed, rows, SCOPE, CREDENTIAL)

    def test_actual_reflection_pair_requires_unknown_no_retry_and_exact_response_join(self):
        rows = provider()["posts"]
        self.assertEqual(len(check.match_attempts(attempts(), rows, SCOPE, CREDENTIAL)), 7)
        for key, value in (("providerOutcome", "not_forwarded"), ("retryProviderRequest", True),
                ("providerOperationMayHaveCommitted", False), ("upstreamDispatch", "attempted"), ("upstream_status", 409)):
            changed = attempts(); changed[-1]["event"][key] = value
            with self.subTest(field=key), self.assertRaises(check.CheckFailure):
                check.match_attempts(changed, rows, SCOPE, CREDENTIAL)
        changed = attempts(); changed[1]["event"]["response_body_bytes"] += 1
        with self.assertRaises(check.CheckFailure):
            check.match_attempts(changed, rows, SCOPE, CREDENTIAL)

    def test_refresh_only_changes_revision_record_version_generation_and_live_observation(self):
        before = catalog(); after = deepcopy(before)
        after["revision"] += 1; after["credentials"][0].update(version=2, credential_generation=2)
        after["observed_activity"] = {"timestamp": 99, "actual_posts": 6}
        self.assertTrue(check.require_refresh_projection(before, after, CREDENTIAL))
        for mutate in (
            lambda v: v["policy"].update(sequence=3),
            lambda v: v["credentials"][0].update(oauth_client_id="replacement"),
            lambda v: v["credentials"][0].update(scopes=[]),
            lambda v: v["credentials"][0].update(credential_generation=True),
            lambda v: v["applications"].append({"id": DISCONNECT}),
            lambda v: v["access_rules"][0].update(status="revoked"),
            lambda v: v.update(revision=10),
        ):
            value = deepcopy(after); mutate(value)
            with self.subTest(line=mutate.__code__.co_firstlineno), self.assertRaises(check.CheckFailure):
                check.require_refresh_projection(before, value, CREDENTIAL)

    def test_closed_consent_and_browser_binding_never_redirect_credentials(self):
        query = {"response_type": "code", "client_id": "fixture-client", "redirect_uri": check.CONTROL + check.CALLBACK,
            "scope": "offline.access tweet.read tweet.write users.read", "state": "s" * 43,
            "code_challenge": "c" * 43, "code_challenge_method": "S256"}
        value = {"schema": "serverware.operatorXConsent/v1", "operation_id": CONSENT, "status": "consent_pending",
            "authorization_url": "https://x.com/i/oauth2/authorize?" + urlencode(query), "state": "s" * 43,
            "expires_at_epoch_ms": ANCHOR + 600000, "profile_binding_digest": "sha256:" + "f" * 64}
        with patch.object(check.time, "time_ns", return_value=ANCHOR * 1_000_000):
            self.assertTrue(check.consent_target(value, "fixture-client").startswith("/i/oauth2/authorize?"))
            for altered in ({**value, "authorization_url": value["authorization_url"].replace("x.com/", "other.test/")},
                    {**value, "authorization_url": value["authorization_url"] + "&state=duplicate"},
                    {**value, "expires_at_epoch_ms": ANCHOR}):
                with self.assertRaises(check.CheckFailure):
                    check.consent_target(altered, "fixture-client")
        name = "__Host-serverware-x-oauth-" + "s" * 43
        cookie = name + "=" + "n" * 43 + "; Secure; HttpOnly; Path=/; SameSite=Lax"
        self.assertEqual(check.consent_cookie([("Set-Cookie", cookie)], "s" * 43), (name + "=" + "n" * 43, "n" * 43))
        with self.assertRaises(check.CheckFailure):
            check.consent_cookie([("Set-Cookie", cookie + "; Domain=other.test")], "s" * 43)
        target = check.CONTROL + check.CALLBACK + "?" + urlencode({"code": "private-code", "state": "s" * 43})
        self.assertEqual(check.callback_target([("Location", target)], "s" * 43)[1], "private-code")
        with self.assertRaises(check.CheckFailure):
            check.callback_target([("Location", target.replace(check.CONTROL, "https://other.test"))], "s" * 43)

    def test_actual_http_serializer_uses_fixed_https_host_without_default_port(self):
        class RecordingSocket:
            def __init__(self):
                self.sent = bytearray()
                self.closed = False
            def sendall(self, data):
                self.sent.extend(data)
            def makefile(self, mode):
                self.assert_mode = mode
                return io.BytesIO(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n{}")
            def close(self):
                self.closed = True

        # Demonstrate the real stdlib default; no socket is constructed.
        original = RecordingSocket()
        connection = check.http.client.HTTPConnection("api.x.com", 443)
        connection.sock = original
        connection.request("GET", "/__test__/observations")
        connection.close()
        self.assertIn(b"\r\nHost: api.x.com:443\r\n", original.sent)

        instance = object.__new__(check.XPostCheck)
        instance.control = SimpleNamespace(host="serverware-x.example.com", port=443, scheme="https")
        instance.accounts = SimpleNamespace(host="x.com", port=443, scheme="https")
        instance.upstream = SimpleNamespace(host="api.x.com", port=443, scheme="https")
        instance.control_ca, instance.upstream_ca = object(), object()
        instance.admin_token = "synthetic-private-admin"
        instance.timeout, instance.clean = Mock(return_value=0.25), Mock()
        for endpoint in (instance.control, instance.accounts, instance.upstream):
            recorded = RecordingSocket()
            endpoint.connect = Mock(return_value=recorded)
            self.assertEqual(instance.exchange(endpoint, "/observed")[0], 200)
            self.assertEqual(recorded.sent.count(b"\r\nHost:"), 1)
            self.assertIn(b"\r\nHost: " + endpoint.host.encode() + b"\r\n", recorded.sent)
            self.assertNotIn(b":443\r\n", recorded.sent)
            self.assertNotIn(instance.admin_token.encode(), recorded.sent)
            self.assertTrue(recorded.closed)
            endpoint.connect.assert_called_once_with(0.25,
                instance.control_ca if endpoint is instance.control else instance.upstream_ca)
        recorded = RecordingSocket(); instance.control.connect = Mock(return_value=recorded)
        instance.exchange(instance.control, check.CONFIGURATION, method="POST", payload={"public": True}, authenticated=True)
        self.assertIn(b"\r\nOrigin: https://serverware-x.example.com\r\n", recorded.sent)
        self.assertIn(b"\r\nX-Serverware-Admin-Token: synthetic-private-admin\r\n", recorded.sent)
        self.assertTrue(instance.clean.called)
        for options in ({"authenticated": True}, {"cookie": "synthetic-private-cookie"}):
            instance.upstream.connect.reset_mock()
            with self.assertRaises(check.CheckFailure):
                instance.exchange(instance.upstream, "/observed", **options)
            instance.upstream.connect.assert_not_called()
        for changed in ({"host": "unselected.example.com"}, {"port": 8443}, {"scheme": "http"}):
            original_values = vars(instance.upstream).copy()
            vars(instance.upstream).update(changed)
            with self.assertRaises(check.CheckFailure):
                instance.exchange(instance.upstream, "/observed")
            vars(instance.upstream).update(original_values)

    def test_provider_observation_uses_owned_exchange_and_strict_document(self):
        observed = provider(disconnected=False)
        observed.update(initialAccessIssuedAtEpochMs=None, initialAccessExpiresAtEpochMs=None,
            initialAccessExpired=False, refreshAfterInitialExpiry=False, issuedGenerations=[], posts=[])
        observed["counts"] = dict.fromkeys(observed["counts"], 0)
        instance = object.__new__(check.XPostCheck)
        instance.upstream = object()
        instance.provider_checkpoints = []
        instance.exchange = Mock(return_value=(200, [], canonical(observed)))
        instance.json_request = Mock(side_effect=AssertionError("legacy HTTP Host framing used"))
        self.assertEqual(instance.observe(0, connected=False), observed)
        instance.exchange.assert_called_once_with(instance.upstream, "/__test__/observations")
        instance.json_request.assert_not_called()
        self.assertEqual(instance.provider_checkpoints, [observed])
        self.assertEqual(instance.arrivals, [])
        for status, body in ((503, canonical(observed)), (200, b'{"x":1,"x":2}'), (200, b'{}')):
            instance.exchange = Mock(return_value=(status, [], body))
            with self.assertRaises(check.CheckFailure):
                instance.observe(0, connected=False)
        self.assertEqual(instance.provider_checkpoints, [observed])

    def test_terminal_receipt_revalidates_all_nineteen_controls_and_no_live_claim(self):
        self.assertTrue(check.validate_success_result(receipt()))
        for mutate in (
            lambda v: v.update(realXVerified=True),
            lambda v: v["completed"].pop(),
            lambda v: v["completed"][0].update(exitCode=False),
            lambda v: v["attemptIds"].__setitem__(0, v["attemptIds"][1]),
            lambda v: v["negativeControls"][0].update(providerPostsAdded=1),
            lambda v: v["negativeControls"][0].update(auditIds=v["negativeControls"][1]["auditIds"]),
            lambda v: v["namedAuditInventory"].pop("operator_catalog.x_oauth.account_refreshed"),
            lambda v: v["namedAuditInventory"].update(unexpected_event=1),
            lambda v: v.update(sdkDependenciesSha256=v.pop("dependenciesSha256")),
        ):
            value = receipt(); mutate(value)
            with self.subTest(line=mutate.__code__.co_firstlineno), self.assertRaises(check.CheckFailure):
                check.validate_success_result(value)

    def test_negative_orchestration_denies_dispatch_secret_even_without_provider_arrival(self):
        # Explicit orchestration doubles: this does not prove a real refusal.
        instance = object.__new__(check.XPostCheck)
        instance.negative_controls = []
        instance.sdk = Mock()
        instance.observe = Mock(return_value=provider(disconnected=False))
        blocked = event(check.CONNECT_DENIED, {"target": "api.x.com:443"}, 90)
        instance.settled_audit = Mock(side_effect=[[], [blocked]])
        instance.negative("node:wrong_app", {"id": APP}, "t" * 43, provider(disconnected=False))
        self.assertEqual(instance.negative_controls[0]["providerPostsAdded"], 0)
        instance.settled_audit = Mock(side_effect=[[], [blocked,
            event(check.LEASE, {"purpose": "dispatchSecret"}, 91)]])
        with self.assertRaises(check.CheckFailure):
            instance.negative("node:wrong_app", {"id": APP}, "t" * 43, provider(disconnected=False))

    def test_fixed_process_argv_original_deadline_and_owned_cleanup_are_propagated(self):
        class Selector:
            def __init__(self): self.items = {}
            def __enter__(self): return self
            def __exit__(self, *_): return False
            def register(self, stream, _events, key): self.items[stream] = SimpleNamespace(fd=stream.fileno(), fileobj=stream, data=key)
            def unregister(self, stream): self.items.pop(stream)
            def get_map(self): return self.items
            def select(self, _timeout): return [(item, 1) for item in list(self.items.values())]
        process = SimpleNamespace(stdout=Mock(), stderr=Mock())
        process.stdout.fileno.return_value = 10; process.stderr.fileno.return_value = 11
        environment = check.client_environment("node:first", APP, "t" * 43)
        with patch.object(check.subprocess, "Popen", return_value=process) as spawn, \
                patch.object(check.selectors, "DefaultSelector", Selector), patch.object(check.os, "read", return_value=b""), \
                patch.object(check, "_child_exit_status", return_value=0), patch.object(check, "_cleanup_example_group") as cleanup:
            self.assertEqual(check.run_example("node:first", environment, 0.5), (0, b"", b""))
            self.assertEqual(spawn.call_args.args[0], ("/node", "/app/examples/x-post-node/client.mjs"))
            self.assertEqual(spawn.call_args.kwargs["env"], environment)
            self.assertTrue(spawn.call_args.kwargs["close_fds"] and spawn.call_args.kwargs["start_new_session"])
            cleanup.assert_called_once_with(process)
        with patch.object(check.subprocess, "Popen", return_value=process), \
                patch.object(check.selectors, "DefaultSelector", Selector), patch.object(check.os, "read", return_value=b"x" * 8193), \
                patch.object(check, "_cleanup_example_group") as cleanup:
            with self.assertRaises(check.CheckFailure):
                check.run_example("node:first", environment, 0.5)
            cleanup.assert_called_once_with(process)
        for seconds in (0, True, 36):
            with self.assertRaises(check.CheckFailure):
                check.run_example("node:first", environment, seconds)

    def test_disconnect_exact_revision_and_affected_inventory_are_checked(self):
        # HTTP doubles supply already-observed public DTOs, never fake custody.
        before = catalog(); before["credentials"][0].update(version=2, credential_generation=2)
        current = deepcopy(before); current["revision"] += 2
        current["credentials"][0]["status"] = current["access_rules"][0]["status"] = "revoked"
        current["policy"] = {"policy_hash": "sha256:" + "f" * 64, "sequence": 3}
        review = {"schema": "serverware.operatorXDisconnectReview/v1", "credential_id": CREDENTIAL,
            "expected_credential_generation": 2, "expected_revision": before["revision"],
            "expected_policy_hash": SCOPE[2], "review_digest": "sha256:" + "d" * 64,
            "affected_credential_ids": [CREDENTIAL], "affected_rule_ids": [RULE]}
        result = {"schema": "serverware.operatorXAccountOperation/v1", "operation_id": DISCONNECT,
            "kind": "disconnect", "status": "disconnected", "credential_id": CREDENTIAL, "reason": None,
            "created_at": "synthetic", "expires_at_epoch_ms": ANCHOR + 300000}
        for alteration in (None, "revision", "inventory"):
            observed = deepcopy(current)
            if alteration == "revision": observed["revision"] += 1
            if alteration == "inventory": observed["credentials"].append({"id": APP, "status": "revoked"})
            instance = object.__new__(check.XPostCheck); instance.credential_id = CREDENTIAL
            instance.lifecycle_expected = {}; instance.lifecycle_json = Mock(side_effect=[review, result, result])
            instance.catalog = Mock(side_effect=[before, observed]); instance.wait_catalog_loaded = Mock()
            instance.observe = Mock(return_value=provider())
            with patch.object(check.uuid, "uuid4", return_value=DISCONNECT):
                if alteration is None:
                    self.assertEqual(instance.disconnect(before, before["applications"][0], before["access_rules"][0]), provider())
                else:
                    with self.assertRaises(check.CheckFailure):
                        instance.disconnect(before, before["applications"][0], before["access_rules"][0])

    def test_main_failure_receipt_is_bounded_redacted_and_arms_original_alarm(self):
        values = {"control-base": check.CONTROL, "operator-origin": check.CONTROL,
            "management-base": "http://127.0.0.1:9091", "proxy-url": check.PROXY,
            "expected-binary-sha256": "sha256:" + "a" * 64, "expected-go-sha256": "b" * 64,
            "expected-dependencies-sha256": "c" * 64, "expected-initial-revision": "1"}
        values.update({key: "/synthetic/" + key for key in ("ca-file", "proxy-ca-file", "upstream-ca-file",
            "admin-token-file", "fixture-marker-file", "run-claim-file", "dependencies-file")})
        argv = ["check_operator_x_post.py"] + [part for key, value in values.items() for part in ("--" + key, value)]
        output = io.StringIO()
        with patch.object(check.sys, "argv", argv), patch.object(check.signal, "signal"), \
                patch.object(check.signal, "alarm") as alarm, \
                patch.object(check, "claim_fixture", side_effect=RuntimeError("private-secret-path-canary")), \
                patch.object(check, "XPostCheck") as construct, redirect_stdout(output):
            self.assertEqual(check.main(), 1)
        result = json.loads(output.getvalue())
        self.assertFalse(result["ok"]); self.assertEqual(result["completed"], [])
        self.assertNotIn("private-secret-path-canary", output.getvalue())
        self.assertEqual([call.args for call in alarm.call_args_list], [(180,), (0,)])
        construct.assert_not_called()
        self.assertEqual(set(result), {"schema", "ok", "syntheticOnly", "productionReady", "error", "failureSite", "phase", "completed"})


if __name__ == "__main__":
    unittest.main()
