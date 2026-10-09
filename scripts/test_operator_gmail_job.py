#!/usr/bin/env python3
"""Pure/mocked checker oracles, not end-to-end Gmail or Requests proof.

Request preparation uses the actual Requests dependency, but no send reaches a
socket. The separately authorized isolated normal-binary run remains required.
"""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts import check_operator_gmail_job as check


TOKEN = "synthetic-application-" + "x" * 32
CA = Path("/fixture/proxy-ca.pem")
POLICY = "sha256:" + "a" * 64
SCOPE = ("synthetic-principal", "synthetic-route", POLICY)
CREDENTIAL = "synthetic-credential"


def capability():
    return {"capabilities": {"operation_bundles": [{"operation_bundle": "gmail_read_v1",
        "create_path": check.CREATE_PATH, "credential_type": "google_oauth", "permission_preset": "gmail_readonly",
        "api_origin": check.ORIGIN, "methods": ["GET"], "paths": [check.base.fixture.GMAIL_PATH,
            check.base.fixture.GMAIL_PATH + "/{message_id}"], "query_mode": "orderedFormV1",
        "age_policy": {"mode": "unrestricted"}, "response_mode": "gmail_read_json_v1",
        "response_contract": {"mode": "gmailReadJsonV1", "success_status_codes": [200], "content_types": ["application/json"],
            "body_presence": "required", "unlisted_header_policy": "discardUnselectedV1"}}]}}


def rule():
    return {"operation_bundle": "gmail_read_v1", "query_mode": "orderedFormV1", "age_policy": {"mode": "unrestricted"},
        "response_mode": "gmail_read_json_v1", "credential_input": "insert", "methods": ["GET"],
        "request_fields": [], "response_fields": [], "allowed_headers": ["accept", "user-agent", "x-goog-api-client"],
        "application_id": "app", "credential_id": CREDENTIAL, "upstream_url": check.ORIGIN + check.base.fixture.GMAIL_PATH,
        "status": "active"}


def prepared(case="list_page_1"):
    spec = check.fixture.TARGETS[case]
    with check.requests_session(TOKEN, CA) as session:
        return session.prepare_request(check.requests.Request("GET", check.ORIGIN + spec["path"], params=list(spec["params"])))


def commitment(case, generation):
    expected = check.request_commitments(prepared(case), scope=SCOPE, credential_id=CREDENTIAL, generation=generation)
    body = check.fixture.TARGETS[case]["body"]
    return {"case": case, "generation": generation, "requestDigest": expected[0], "operationDigest": expected[1],
        "responseBodySha256": "sha256:" + check.hashlib.sha256(body).hexdigest(), "responseBodyBytes": len(body)}


def fields(item):
    return [("Content-Type", "application/json"), ("X-Serverware-Policy-Hash", POLICY),
        ("X-Serverware-Request-Digest", item["requestDigest"]), ("X-Serverware-Operation-Digest", item["operationDigest"]),
        ("X-Serverware-Response-Body-Sha256", item["responseBodySha256"])]


def observation(stage, *, prefetched=False):
    consent, refresh, resources = check.STAGES[stage]
    if stage == "expired" and prefetched:
        refresh = 1
    counts = {"authorization_requests": consent, "authorization_codes_issued": consent,
        "authorization_code_exchanges": consent, "token_requests": consent + refresh, "token_responses": consent + refresh,
        "refresh_exchanges": refresh, "identity_requests": consent, "resource_requests": resources, "resource_attempts": resources,
        "resource_gmail.messages.list": resources // 2, "resource_gmail.message.get": resources // 2}
    expiry, events, attempts = 1090000, [], []
    def event(kind, timestamp=1000000, **values):
        events.append({"sequence": len(events) + 1, "provider": "google", "type": kind,
            "timestamp_epoch_ms": timestamp, **values})
    if consent:
        event("authorization_validated", outcome="success", requested_scopes=check.base.SCOPES)
        event("authorization_code_issued", requested_scopes=check.base.SCOPES)
        event("authorization_code_exchanged", pkce="S256", granted_scopes=check.base.SCOPES)
        event("tokens_issued", grant_type="authorization_code", granted_scopes=check.base.SCOPES)
        event("identity_returned", malformed=False)
    for index in range(resources):
        if index == 4:
            event("refresh_token_rotated", timestamp=expiry - 50000, granted_scopes=check.base.SCOPES)
            event("tokens_issued", timestamp=expiry - 50000, grant_type="refresh_token", granted_scopes=check.base.SCOPES)
        case, generation = check.CASES[index % 4], 1 + index // 4
        spec = check.fixture.TARGETS[case]
        timestamp = 1001000 + index if generation == 1 else expiry + 1001 + index
        event("resource_received", timestamp=timestamp, attempt=index + 1)
        event("resource_authorized", timestamp=timestamp, token_generation=generation,
            operation="gmail.messages.list" if index % 4 < 2 else "gmail.message.get")
        attempts.append({"ordinal": index + 1, "case": case, "method": "GET", "path": spec["path"],
            "rawQuery": spec["raw_query"], "authorized": True, "status": 200, "tokenGeneration": generation,
            "acceptEncodingAbsent": True, "timestampEpochMs": timestamp})
    if resources < 8 and refresh:
        event("refresh_token_rotated", timestamp=expiry - 50000, granted_scopes=check.base.SCOPES)
        event("tokens_issued", timestamp=expiry - 50000, grant_type="refresh_token", granted_scopes=check.base.SCOPES)
    return {"schema": "serverware.privateGoogleObservations/v1", "counts": {"google": {key: value for key, value in counts.items() if value}, "x": {}},
        "active": {"authorizationCodes": 0, "grants": consent}, "events": events,
        "tokenLifetimes": {"authorizationCodeExchangeSeconds": 90, "refreshExchangeSeconds": 300},
        "initialAccessExpiresAtEpochMs": expiry if consent else None, "initialAccessExpired": stage in {"expired", "refreshed"},
        "gmailJob": {"schema": check.fixture.JOB_SCHEMA, "maxAttempts": 16, "attempts": attempts}}


def audit_rows():
    commitments = [commitment(case, generation) for generation in (1, 2) for case in check.CASES]
    rows = [{"id": "connected", "event_type": "credential.oauth_connected",
        "event": {"credential_id": CREDENTIAL, "credential_version": 1}},
        {"id": "refresh", "event_type": "credential.oauth_refreshed", "event": {"credential_id": CREDENTIAL,
            "provider": "google", "previous_credential_version": 1, "credential_version": 2,
            "refresh_token_rotated": True, "scopes": check.base.SCOPES}}]
    for index, item in enumerate(commitments):
        attempt = "sha256:" + f"{index + 1:064x}"
        common = {"principal_id": SCOPE[0], "route_id": SCOPE[1], "policy_hash": POLICY, "method": "GET",
            "attempt_id": attempt, "flow_id": attempt, "request_digest": item["requestDigest"], "operation_digest": item["operationDigest"]}
        rows.extend([{"id": f"start-{index}", "event_type": "data_plane.credential.release_started",
            "event": {**common, "credential_ref": CREDENTIAL, "credential_version": item["generation"], "outcome": "release_started"}},
            {"id": f"end-{index}", "event_type": "data_plane.response.released", "event": {**common,
                "response_body_sha256": item["responseBodySha256"], "response_body_bytes": item["responseBodyBytes"],
                "upstream_status": 200, "outcome": "released"}}])
    return rows, commitments


class GmailJobCheckerTests(unittest.TestCase):
    def test_proxy_bearer_is_connect_only_with_ordinary_requests_defaults(self):
        with check.requests_session(TOKEN, CA) as session:
            self.assertFalse(session.trust_env)
            self.assertEqual(session.verify, str(CA))
            self.assertEqual(session.proxies, {"https": check.PROXY})
            self.assertEqual(list(session.adapters), [check.ORIGIN + "/"])
            adapter = session.get_adapter(check.ORIGIN + "/")
            self.assertEqual(adapter.proxy_headers(check.PROXY), {"Proxy-Authorization": "Bearer " + TOKEN})
            self.assertEqual(adapter.max_retries.total, 0)
            self.assertNotIn("Proxy-Authorization", session.headers)
            self.assertNotIn("Authorization", session.headers)
            self.assertIn("gzip", session.headers["Accept-Encoding"])
            request = session.prepare_request(check.requests.Request("GET", check.ORIGIN + check.base.fixture.GMAIL_PATH))
            self.assertNotIn("Proxy-Authorization", request.headers)
            for proxy in ("https://127.0.0.1:9090", "http://example.com:9090", "http://user:pass@127.0.0.1:9090"):
                with self.subTest(proxy=proxy), self.assertRaises(check.CheckFailure):
                    adapter.proxy_headers(proxy)

    def test_adapter_refuses_target_proxy_ca_and_upstream_auth_before_send(self):
        request = prepared()
        options = {"proxies": {"https": check.PROXY}, "verify": str(CA), "stream": True}
        adapter = check.ProxyBearerAdapter(TOKEN, CA)
        with patch.object(check.HTTPAdapter, "send", return_value=object()) as send:
            adapter.send(request, **options)
            self.assertEqual(send.call_count, 1)
            for change in ({"proxies": {}}, {"verify": False}, {"verify": "/different.pem"}, {"stream": False}):
                with self.subTest(change=change), self.assertRaises(check.CheckFailure):
                    adapter.send(request, **{**options, **change})
            for name in ("Proxy-Authorization", "Authorization", "Cookie", "X-Serverware-Admin-Token"):
                altered = deepcopy(request); altered.headers[name] = "synthetic-private"
                with self.subTest(name=name), self.assertRaises(check.CheckFailure):
                    adapter.send(altered, **options)
            for url in ("http://gmail.googleapis.com/a", "https://gmail.googleapis.com.evil/a", "https://gmail.googleapis.com:443/a"):
                altered = deepcopy(request); altered.url = url
                with self.subTest(url=url), self.assertRaises(check.CheckFailure):
                    adapter.send(altered, **options)
            self.assertEqual(send.call_count, 1)
        adapter.close()

    def test_bundle_capability_requires_new_explicit_query_contract(self):
        check.require_bundle(capability())
        for field, value in (("query_mode", None), ("operation_bundle", "old"), ("create_path", "/api/other"),
                ("age_policy", {"mode": "maxAgeDays", "maxAgeDays": 7}), ("methods", ["GET", "POST"])):
            document = capability(); document["capabilities"]["operation_bundles"][0][field] = value
            with self.subTest(field=field), self.assertRaises(check.CheckFailure):
                check.require_bundle(document)
        document = capability(); document["capabilities"]["operation_bundles"] *= 2
        with self.assertRaises(check.CheckFailure):
            check.require_bundle(document)

    def test_saved_rule_requires_persisted_query_account_app_and_no_projection(self):
        check.require_rule(rule(), application_id="app", credential_id=CREDENTIAL)
        for delta in ({"query_mode": None}, {"application_id": "other"}, {"credential_id": "other"},
                {"status": "revoked"}, {"response_fields": ["id"]}, {"request_body_mode": None},
                {"allowed_headers": ["accept", "accept-encoding", "user-agent", "x-goog-api-client"]}):
            with self.subTest(delta=delta), self.assertRaises(check.CheckFailure):
                check.require_rule({**rule(), **delta}, application_id="app", credential_id=CREDENTIAL)

    def test_real_requests_preparation_retains_order_repeats_and_form_encoding(self):
        for case, spec in check.fixture.TARGETS.items():
            request = prepared(case)
            with self.subTest(case=case):
                self.assertEqual(request.url, check.ORIGIN + spec["path"] + "?" + spec["raw_query"])
                self.assertEqual(check.parse_qsl(check.urlsplit(request.url).query), list(spec["params"]))
                self.assertIn("gzip", request.headers["Accept-Encoding"])
                self.assertIsNone(request.body)
        self.assertIn("labelIds=INBOX&labelIds=UNREAD", prepared().url)
        self.assertIn("subject%3AServerware+fixture", prepared().url)
        self.assertIn("pageToken=fixture-page-2%2B%2F%3D", prepared("list_page_2").url)

    def test_v3_commitments_bind_raw_query_generation_and_compression_discard(self):
        request = prepared()
        expected = check.request_commitments(request, scope=SCOPE, credential_id=CREDENTIAL, generation=1)
        with patch.object(check, "digest", wraps=check.digest) as hashed:
            self.assertEqual(check.request_commitments(request, scope=SCOPE, credential_id=CREDENTIAL, generation=1), expected)
            canonical = hashed.call_args_list[0].args[0]
            self.assertEqual(canonical["v"], 3)
            self.assertEqual(canonical["client_ip"], "127.0.0.1")
            self.assertEqual(canonical["request"]["discard_headers"], ["accept-encoding"])
            self.assertNotIn("accept-encoding", canonical["request"]["headers"])
            self.assertEqual(canonical["request"]["headers"]["host"], "gmail.googleapis.com")
        changed = deepcopy(request); changed.url = changed.url.replace("+fixture", "%20fixture")
        self.assertNotEqual(check.request_commitments(changed, scope=SCOPE, credential_id=CREDENTIAL, generation=1), expected)
        self.assertNotEqual(check.request_commitments(request, scope=SCOPE, credential_id=CREDENTIAL, generation=2), expected)
        request.headers.pop("Accept-Encoding")
        with self.assertRaises(check.CheckFailure):
            check.request_commitments(request, scope=SCOPE, credential_id=CREDENTIAL, generation=1)

    def test_wire_bodies_metadata_and_v3_commitments_are_not_format_only(self):
        item = commitment("list_page_1", 1); body = check.fixture.TARGETS[item["case"]]["body"]
        expected = (item["requestDigest"], item["operationDigest"])
        result = check.response_commitment(200, fields(item), body, case=item["case"], policy_hash=POLICY, expected=expected)
        self.assertEqual(result["responseBodyBytes"], len(body))
        for status, headers, raw in ((201, fields(item), body), (200, fields(item), body + b" "),
                (200, fields(item) + [("Server", "synthetic")], body),
                (200, fields(item) + [("Date", "date")], body),
                (200, fields(item) + [("Cache-Control", "no-store")], body),
                (200, fields(item) + [("Content-Encoding", "gzip")], body),
                (200, fields(item) + [("content-type", "application/json")], body)):
            with self.subTest(status=status, headers=headers), self.assertRaises(check.CheckFailure):
                check.response_commitment(status, headers, raw, case=item["case"], policy_hash=POLICY, expected=expected)
        with self.assertRaises(check.CheckFailure):
            check.response_commitment(200, fields(item), body, case=item["case"], policy_hash=POLICY,
                expected=("sha256:" + "f" * 64, expected[1]))

    def test_provider_inventory_all_stages_and_natural_prefetch(self):
        for stage in check.STAGES:
            with self.subTest(stage=stage):
                result = check.observations(observation(stage), stage)
                self.assertEqual(len(result["cases"]), check.STAGES[stage][2])
        self.assertFalse(check.observations(observation("expired"), "expired")["refreshCompletedAtExpiry"])
        self.assertTrue(check.observations(observation("expired", prefetched=True), "expired")["refreshCompletedAtExpiry"])
        self.assertEqual(check.observations(observation("refreshed"), "refreshed")["resourceGenerations"], [1] * 4 + [2] * 4)

    def test_every_actual_arrival_must_match_raw_target_generation_and_discard(self):
        for field, value in (("case", None), ("method", "POST"), ("rawQuery", "changed"), ("path", "/changed"),
                ("authorized", False), ("status", 400), ("tokenGeneration", 2), ("acceptEncodingAbsent", False),
                ("timestampEpochMs", 1090000)):
            document = observation("first"); document["gmailJob"]["attempts"][0][field] = value
            with self.subTest(field=field), self.assertRaises(check.CheckFailure):
                check.observations(document, "first")
        document = observation("connected"); document["counts"]["google"]["resource_attempts"] = 1
        with self.assertRaises(check.CheckFailure):
            check.observations(document, "connected")
        document = observation("fresh"); document.pop("gmailJob")
        with self.assertRaises(check.CheckFailure):
            check.observations(document, "fresh")

    def test_scope_pkce_refresh_count_and_true_expiry_refuse_false_success(self):
        for edit in (lambda d: d.update(initialAccessExpired=False),
                lambda d: d["counts"]["google"].update(refresh_exchanges=2),
                lambda d: d["events"][2].update(pkce="none"),
                lambda d: d["events"][3].update(granted_scopes=["openid"]),
                lambda d: d["tokenLifetimes"].update(authorizationCodeExchangeSeconds=1),
                lambda d: d["gmailJob"]["attempts"][4].update(timestampEpochMs=1090000)):
            document = observation("refreshed"); edit(document)
            with self.assertRaises(check.CheckFailure):
                check.observations(document, "refreshed")

    def test_job_follows_actual_cursor_and_returned_ids_without_a_credential_lookup(self):
        instance = object.__new__(check.GmailJobCheck); instance.successes = []
        instance.send = Mock(side_effect=[json.loads(check.fixture.TARGETS[case]["body"]) for case in check.CASES])
        instance.job(object(), SCOPE, CREDENTIAL, 1)
        calls = instance.send.call_args_list
        self.assertEqual(len(calls), 4)
        self.assertEqual(calls[1].kwargs["params"][-1], ("pageToken", check.fixture.PAGE_TOKEN))
        self.assertEqual(calls[2].kwargs["path"], check.base.fixture.GMAIL_PATH + "/" + check.fixture.MESSAGE_IDS[0])
        self.assertEqual(calls[3].kwargs["params"], check.fixture.METADATA_PARAMS)
        self.assertEqual(instance.successes, [SCOPE] * 4)

    def test_job_refuses_missing_cursor_extra_page_and_wrong_listed_ids(self):
        for index, edit in ((0, lambda d: d.pop("nextPageToken")), (1, lambda d: d.update(nextPageToken="extra")),
                (1, lambda d: d["messages"][0].update(id="unlisted"))):
            values = [json.loads(check.fixture.TARGETS[case]["body"]) for case in check.CASES]
            edit(values[index]); instance = object.__new__(check.GmailJobCheck); instance.successes = []
            instance.send = Mock(side_effect=values)
            with self.subTest(index=index), self.assertRaises(check.CheckFailure):
                instance.job(object(), SCOPE, CREDENTIAL, 1)
            self.assertLess(instance.send.call_count, 4)

    def test_durable_attempts_join_every_wire_digest_body_and_generation(self):
        rows, items = audit_rows()
        evidence = check.generation_evidence(rows, SCOPE, CREDENTIAL, items)
        self.assertEqual(evidence["canonicalRequestVersion"], 3)
        actual, pairs = check.features.release_attempt_pairs(rows, check.Counter({SCOPE: 8}))
        self.assertEqual(actual[SCOPE], 8); self.assertEqual(len(pairs), 8)
        for index, delta in ((1, {"credential_version": 3}), (2, {"credential_version": 2}),
                (3, {"request_digest": "sha256:" + "f" * 64}), (3, {"response_body_bytes": 1}),
                (3, {"attempt_id": "different"}), (2, {"principal_id": "other"})):
            altered = deepcopy(rows); altered[index]["event"].update(delta)
            with self.subTest(index=index, delta=delta), self.assertRaises(check.CheckFailure):
                check.generation_evidence(altered, SCOPE, CREDENTIAL, items)

    def test_denial_payload_and_transport_failure_are_fixed_and_never_retried(self):
        instance = object.__new__(check.GmailJobCheck)
        instance.args = SimpleNamespace(ca_file=CA); instance.timeout = lambda: 1.0; instance.clean = Mock()
        with check.requests_session(TOKEN, CA) as session:
            response = Mock(status_code=403)
            response.raw.headers.iteritems.return_value = []
            response.raw.read.return_value = b'{"allowed":false,"action":"deny"}'
            with patch.object(session, "send", return_value=response) as sent:
                self.assertIsNone(instance.send(session, method="POST", path=check.base.fixture.GMAIL_PATH, params=[]))
                self.assertEqual(sent.call_count, 1)
                self.assertFalse(sent.call_args.kwargs["allow_redirects"])
                self.assertTrue(sent.call_args.kwargs["stream"])
            with patch.object(session, "send", side_effect=check.requests.RequestException("sensitive-proxy-value")) as sent:
                with self.assertRaisesRegex(check.CheckFailure, "^normal Requests Gmail transport failed$"):
                    instance.send(session, method="POST", path=check.base.fixture.GMAIL_PATH, params=[])
                self.assertEqual(sent.call_count, 1)


if __name__ == "__main__":
    unittest.main()
