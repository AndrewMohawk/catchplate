#!/usr/bin/env python3
"""Synthetic Gmail-read compiler/adapter checks; no provider or transport.

Current canonical sorted/singleton queries remain required. These fixtures do
not prove arbitrary SDK query support, OAuth custody, dispatch, or refresh.
"""
from copy import deepcopy
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from mitmproxy import http
from catchplate import adapters, policy_bundle as pb, policy_engine as engine
import test_buffered_passthrough_response as buffered

LIST = "https://gmail.googleapis.com/gmail/v1/users/me/messages"
SECRET = "fixture-private-oauth-access-value"


def document():
    value = buffered.bundle()
    value["credentials"][0] = {
        "id": "credential:buffered-fixture", "credentialType": "oauth2", "provider": "google",
        "providerSubject": "verified-fixture-subject", "oauthClientId": "fixture-client",
        "scopes": ["email", "https://www.googleapis.com/auth/gmail.readonly", "openid"],
        "injection": {"type": "bearer", "header": "Authorization", "field": "access_token"}}
    route = value["routes"][0]
    route["match"] = {"scheme": "https", "host": "gmail.googleapis.com", "port": 443,
        "methods": ["GET"], "paths": list(pb.GMAIL_READ_PATHS)}
    route["adapter"] = {"type": "gmail.read.v1", "config": {
        "credentialBinding": {"credentialType": "oauth2", "provider": "google",
            "subjects": ["verified-fixture-subject"], "clientIds": ["fixture-client"],
            "requiredScopes": ["https://www.googleapis.com/auth/gmail.readonly"]},
        "request": pb.provider_request_profile("gmail.read.v1"),
        "agePolicy": {"mode": "unrestricted"}, "response": pb.gmail_read_response_profile()}}
    route["constraints"] = [pb.gmail_read_response_envelope("fixture.gmail-read")]
    return value


def compile_route(value=None, *, schema=True):
    return pb.compile_policy_bundle(document() if value is None else value,
        validate_schema=schema).routes[0]


def request(url=LIST, *, method="GET", body=b"", fields=()):
    obj = http.Request.make(method, url, body)
    obj.headers = http.Headers(list(fields))
    obj.raw_content = body
    return SimpleNamespace(request=obj, response=None, metadata={})


class GmailReadBundleTests(unittest.TestCase):
    def setUp(self):
        self.route = compile_route()
        self.adapter = adapters.get_adapter("gmail.read.v1")

    def response(self, body, *, params=None, url=LIST, status=200, fields=None, guarded=True):
        flow = request(url)
        flow.response = http.Response.make(status, b"")
        flow.response.headers = http.Headers(fields if fields is not None else [(b"Content-Type", b"application/json")])
        flow.response.raw_content = body
        flow.metadata.update(catchplate_route=self.route,
            catchplate_operation=self.adapter.operation_fields(flow, self.route, params or {}))
        if guarded:
            guard = engine._ResponseCredentialGuard()
            guard.add_text_encodings(SECRET)
            engine._install_response_credential_guard(flow, guard)
        return flow

    def admit_response(self, flow, params=None):
        for stage, check in (("content_encoding", lambda: engine._validate_response_content_encoding(flow)),
                ("envelope", lambda: engine._evaluate_response_envelope(flow, self.route)),
                ("prepare", lambda: self.adapter.prepare_response(flow, self.route, params or {})),
                ("validate", lambda: self.adapter.validate_response(flow, self.route, params or {}))):
            result = check()
            self.response_decision_details = {"stage": stage, "status": result.status_code,
                "reason": result.reason, "payload": result.payload}
            if not result.allowed:
                return result
        return result

    def test_schema_compiler_exact_bundle_and_original_profiles_unchanged(self):
        value = document()
        before = deepcopy(value)
        for schema in (True, False):
            route = compile_route(value, schema=schema)
            self.assertEqual(route.adapter_type, "gmail.read.v1")
            self.assertEqual(route.path_templates, tuple(pb.GMAIL_READ_PATHS))
            self.assertEqual(route.adapter_config["response"], pb.gmail_read_response_profile())
        self.assertEqual(value, before)
        legacy = json.loads((ROOT / "policies/credential-limits.examples.json").read_text())
        old = next(row for row in legacy["routes"] if row["adapter"]["type"] == "gmail.v1")
        self.assertEqual(old["adapter"]["config"]["maxAgeDays"], 30)
        self.assertTrue(old["adapter"]["config"]["allowMessageGetOnlyFromPriorSearch"])
        self.assertIsInstance(adapters.get_adapter("gmail.v1"), adapters.GmailV1Adapter)
        old_document = buffered.bundle()
        old_hash = pb.compile_policy_bundle(old_document).hash
        compile_route()
        self.assertEqual(pb.compile_policy_bundle(old_document).hash, old_hash)

    def test_account_scope_injection_and_route_authority_are_not_broadened(self):
        changes = [
            ("provider", lambda d: d["credentials"][0].update(provider="x")),
            ("subject", lambda d: d["credentials"][0].update(providerSubject="other")),
            ("client", lambda d: d["credentials"][0].update(oauthClientId="other")),
            ("scopes", lambda d: d["credentials"][0].update(scopes=["email", "openid"])),
            ("injection", lambda d: d["credentials"][0]["injection"].update(field="refresh_token")),
            ("host", lambda d: d["routes"][0]["match"].update(host="www.googleapis.com")),
            ("scheme", lambda d: d["routes"][0]["match"].update(scheme="http")),
            ("port", lambda d: d["routes"][0]["match"].update(port=444)),
            ("method", lambda d: d["routes"][0]["match"].update(methods=["POST"])),
            ("method_case", lambda d: d["routes"][0]["match"].update(methods=["get"])),
            ("method_duplicate", lambda d: d["routes"][0]["match"].update(methods=["GET", "GET"])),
            ("account", lambda d: d["routes"][0]["match"].update(paths=["/gmail/v1/users/{user}/messages"])),
            ("attachments", lambda d: d["routes"][0]["match"].update(paths=[pb.GMAIL_READ_PATHS[0], pb.GMAIL_READ_PATHS[1] + "/attachments/{part}"])),
        ]
        for schema in (True, False):
            for name, change in changes:
                value = document(); change(value)
                with self.subTest(schema=schema, case=name), self.assertRaises(pb.PolicyBundleError):
                    compile_route(value, schema=schema)

    def test_new_request_arrays_are_exact_without_changing_legacy_set_semantics(self):
        for field in ("allowedHeaders", "allowedQueryKeys"):
            value = document()
            config = value["routes"][0]["adapter"]["config"]
            config["request"][field].reverse()
            # Exercise the real semantic validator directly, independently of
            # the final schema pass also performed by schema=False compilation.
            with self.subTest(field=field, stage="semantic"), self.assertRaises(pb.PolicyBundleError):
                pb._validate_provider_request_profile("fixture", "gmail.read.v1", config)
            for schema in (True, False):
                with self.subTest(field=field, schema=schema), self.assertRaises(pb.PolicyBundleError):
                    compile_route(value, schema=schema)
            legacy = {"request": pb.provider_request_profile("gmail.v1")}
            legacy["request"][field].reverse()
            pb._validate_provider_request_profile("legacy-fixture", "gmail.v1", legacy)
        value = document()
        config = value["routes"][0]["adapter"]["config"]
        config["request"].pop("discardHeaders")
        for schema in (True, False):
            self.assertEqual(compile_route(value, schema=schema).methods, frozenset({"GET"}))

    def test_unknown_age_projection_proof_and_constraint_extensions_refuse(self):
        changes = [
            lambda r: r["adapter"]["config"].update(agePolicy={"mode": "maxAgeDays", "maxAgeDays": 30}),
            lambda r: r["adapter"]["config"].update(forceQuery=True),
            lambda r: r["adapter"]["config"]["request"].update(queryMode="unknownOrderedForm"),
            lambda r: r["adapter"]["config"]["request"].update(valueRules=[{"source": "query", "name": "q", "predicate": {"kind": "present"}}]),
            lambda r: r["adapter"]["config"]["response"].update(mode="bufferedJsonOrEmpty204V2"),
            lambda r: r["adapter"]["config"]["response"].update(allowedFields=["id"]),
            lambda r: r["adapter"]["config"]["response"].update(maxBodyBytes=1048577),
            lambda r: r["constraints"][0].update(statusCodes=[200, 204]),
            lambda r: r["constraints"][0].pop("unlistedHeaderPolicy"),
            lambda r: r["constraints"].append(deepcopy(r["constraints"][0])),
            lambda r: r.update(jit={}),
            lambda r: r.update(responseObservation={}),
        ]
        for index, change in enumerate(changes):
            value = document(); change(value["routes"][0])
            with self.subTest(case=index), self.assertRaises(pb.PolicyBundleError):
                compile_route(value)

    def test_list_page_and_known_id_get_keep_current_query_contract(self):
        cases = [(LIST, {}), (LIST + "?maxResults=2&pageToken=next-page", {}),
            (LIST + "?includeSpamTrash=false&q=hello", {}),
            (LIST + "/message-1?format=full", {"message_id": "message-1"}),
            (LIST + "/send?format=metadata&metadataHeaders=Subject", {"message_id": "send"})]
        for url, params in cases:
            flow = request(url, fields=[(b"accept-encoding", b"identity")])
            before = (flow.request.pretty_url, flow.request.raw_content)
            with self.subTest(url=url):
                self.assertTrue(self.adapter.validate_request(flow, self.route, params).allowed)
                self.assertTrue(self.adapter.rewrite_request(flow, self.route, params).allowed)
                self.assertEqual((flow.request.pretty_url, flow.request.raw_content), before)
                operation = self.adapter.operation_fields(flow, self.route, params)
                self.assertEqual(operation["gmailUser"], "me")
                self.assertEqual(operation["operation"], "gmail.message.get" if params else "gmail.messages.list")
        for url in (LIST + "?q=a&maxResults=2", LIST + "?labelIds=A&labelIds=B"):
            with self.subTest(current_query_boundary=url), self.assertRaises(ValueError):
                pb.validate_raw_absolute_target(url)

    def test_request_values_other_operations_body_and_observation_refuse(self):
        for query in ("alt=media", "format=raw", "includeSpamTrash=true", "maxResults=0", "maxResults=501",
                "maxResults=01", "pageToken=", "fields=id", "q=%0A", "pageToken=%7F",
                "metadataHeaders=Subject", "labelIds=bad%2Flabel", "q=" + "a" * 2049):
            with self.subTest(query=query):
                self.assertFalse(self.adapter.validate_request(request(LIST + "?" + query), self.route, {}).allowed)
        for flow, params in ((request(method="POST"), {}), (request(body=b"x"), {}),
                (request(LIST + "/id/attachments/part"), {"message_id": "id"}),
                (request(LIST + "/id?pageToken=x"), {"message_id": "id"}),
                (request(fields=[(b"accept-encoding", b"gzip")]), {})):
            self.assertFalse(self.adapter.validate_request(flow, self.route, params).allowed)
        for header in (b"x-catchplate-proof-nonce", b"x-catchplate-stream-proof-nonce", b"x-catchplate-observation-nonce"):
            self.assertFalse(self.adapter.validate_request(request(fields=[(header, b"fixture")]), self.route, {}).allowed)

    def test_whole_json_list_detail_errors_and_metadata_preserve_body(self):
        cases = [(b' {"messages":[{"id":"id1","threadId":"th1","extra":true}],"nextPageToken":"p2","resultSizeEstimate":1,"extra":{"keep":1}}\n', {}, LIST, 200),
            (b'{"resultSizeEstimate":0}', {}, LIST, 200),
            (b' {"id":"id1","payload":{"body":"unchanged"}}\n', {"message_id": "id1"}, LIST + "/id1", 200),
            (b'{"error":{"message":"fixture"},"extra":true}', {}, LIST, 429)]
        for body, params, url, status in cases:
            flow = self.response(body, params=params, url=url, status=status, fields=[
                (b"Content-Type", b"application/json; charset=utf-8"), (b"Date", b"fixture"),
                (b"Server", b"fixture"), (b"X-Provider-Metadata", b"bounded")])
            with self.subTest(status=status, params=params):
                self.assertTrue(self.admit_response(flow, params).allowed, self.response_decision_details)
                self.assertEqual(flow.response.raw_content, body)
                self.assertEqual(set(name.lower() for name in flow.response.headers), {"content-type", "content-length"})
        for media in (b"application/json; charset", b"application/json, text/plain", b"text/plain"):
            flow = self.response(b"{}", fields=[(b"Content-Type", media)])
            with self.subTest(invalid_media=media):
                self.assertFalse(self.admit_response(flow).allowed, self.response_decision_details)
                self.assertEqual(self.response_decision_details["stage"], "envelope")
                self.assertEqual(self.response_decision_details["payload"]["error"],
                    "response_envelope_content_type_denied")
        duplicate = self.response(b"{}", fields=[(b"Content-Type", b"application/json"),
            (b"Content-Type", b"application/json; charset=utf-8")])
        self.assertFalse(self.admit_response(duplicate).allowed, self.response_decision_details)
        self.assertEqual(self.response_decision_details["payload"]["error"], "response_metadata_duplicate")
        no_content = self.response(b"", status=204)
        self.assertFalse(self.admit_response(no_content).allowed, self.response_decision_details)
        # Existing required-body envelopes retain their exact media literals.
        legacy = pb.compile_policy_bundle(buffered.bundle()).routes[0]
        flow = self.response(b"{}", fields=[(b"Content-Type", b"application/json; charset=utf-8")])
        result = engine._evaluate_response_envelope(flow, legacy)
        self.assertFalse(result.allowed, {"reason": result.reason, "payload": result.payload})
        self.assertEqual(result.payload["error"], "response_envelope_content_type_denied")

    def test_response_identity_shapes_paging_bounds_and_empty_status_refuse(self):
        for body in (b'[]', b'{"messages":null}', b'{"messages":[{"id":"a"},{"id":"a"}]}',
                b'{"messages":[{"id":"a","threadId":"../b"}]}', b'{"nextPageToken":""}',
                b'{"nextPageToken":"\\u0000"}', b'{"resultSizeEstimate":true}',
                b'{"resultSizeEstimate":18446744073709551616}', b'{"id":1,"id":2}',
                b'{"extra":"\\ud800"}'):
            with self.subTest(body=body):
                self.assertFalse(self.admit_response(self.response(body)).allowed)
        flow = self.response(b'{"messages":[{"id":"a"},{"id":"b"}]}', url=LIST + "?maxResults=1")
        self.assertFalse(self.admit_response(flow).allowed)
        for body in (b'{"id":"other"}', b'{"payload":{}}'):
            self.assertFalse(self.admit_response(self.response(body, params={"message_id": "id1"}, url=LIST + "/id1"), {"message_id": "id1"}).allowed)
        for status, body in ((204, b""), (302, b'{}'), (201, b'{}'), (200, b""), (429, b'[]')):
            self.assertFalse(self.admit_response(self.response(body, status=status)).allowed)

    def test_raw_decoded_and_discarded_header_credentials_are_denied(self):
        escaped = "".join("\\u%04x" % ord(char) for char in SECRET)
        for body in (json.dumps({"extra": SECRET}).encode(), ('{"extra":"' + escaped + '"}').encode()):
            decision = self.admit_response(self.response(body))
            self.assertFalse(decision.allowed)
            self.assertEqual(decision.payload["error"], "response_credential_reflection")
        flow = self.response(b'{}', fields=[(b"Content-Type", b"application/json"), (b"X-Unselected", SECRET.encode())])
        self.assertFalse(self.admit_response(flow).allowed)
        self.assertFalse(self.admit_response(self.response(b'{}', guarded=False)).allowed)
        for header in (b"Set-Cookie", b"Authorization", b"x_catchplate_token"):
            self.assertFalse(self.admit_response(self.response(b'{}', fields=[(b"Content-Type", b"application/json"), (header, b"x")])).allowed)

    def test_json_inspection_and_container_limits_do_not_rewrite_wire_bytes(self):
        positive = b'{"extra":' + b"[" * 126 + b"0" + b"]" * 126 + b"}"
        flow = self.response(positive)
        self.assertTrue(self.admit_response(flow).allowed)
        self.assertEqual(flow.response.raw_content, positive)
        negative = b'{"extra":' + b"[" * 127 + b"0" + b"]" * 127 + b"}"
        self.assertFalse(self.admit_response(self.response(negative)).allowed)
        spelling = b'{"n":1e100}'
        # Python's normalized finite-number spelling adds a '+'. The inspection
        # allocation has its own bound even when the raw wire body fits.
        with self.assertRaises(ValueError):
            adapters.gmail_read_json_inspection(spelling, len(spelling))
        original = b' {"n":1.2300,"text":"\\u0061"}\n'
        _, inspection = adapters.gmail_read_json_inspection(original, 1024)
        self.assertNotEqual(bytes(inspection), original)
        inspection[:] = b"\x00" * len(inspection)


if __name__ == "__main__":
    unittest.main()
