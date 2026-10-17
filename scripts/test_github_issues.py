#!/usr/bin/env python3
"""Synthetic GitHub compiler/adapter/canonical checks, not SDK/proxy acceptance.

Uses real schema, typed guards and parsed mitmproxy objects. No provider contact,
credential lease issuance or socket/framing proof. Python forwarding remains
closed for this credential-replacement profile; the Rust lane is separate.
"""
from copy import deepcopy
from dataclasses import replace
import os
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from mitmproxy import http
from catchplate import adapters, github_issues as gh, policy_bundle as pb, policy_engine as engine
import test_buffered_passthrough_response as buffered
import test_gmail_read_bundle as gmail

REPOSITORY = {"owner": "fixture-owner", "name": "fixture-repo"}
LIST = gh.ORIGIN + gh.route_paths(REPOSITORY)[0]
HEADERS = [(b"Accept", b"application/vnd.github.v3+json"),
    (b"Accept-Encoding", b"gzip, deflate"), (b"Accept-Language", b"*"),
    (b"Sec-Fetch-Mode", b"cors"), (b"User-Agent", b"synthetic-octokit-profile"),
    (b"X-Catchplate-Agent", b"buffered-fixture")]


def document(bundle=gh.READ):
    value = buffered.bundle()
    value["credentials"][0]["provider"] = "operator-demo"
    route = value["routes"][0]
    route["credentialHeader"] = dict(gh.REPLACEMENT)
    route["match"] = {"scheme": "https", "host": "api.github.com", "port": 443,
        "methods": ["GET"] if bundle == gh.READ else ["GET", "POST"],
        "paths": gh.route_paths(REPOSITORY)}
    route["adapter"]["config"] = {"credentialMode": "required",
        "credentialBinding": {"credentialType": "static", "provider": "operator-demo",
            "subjects": ["fixture-subject"], "secretClass": "bearerToken"},
        "githubRepository": dict(REPOSITORY), "operationBundle": bundle,
        "request": gh.request_profile(bundle), "response": gh.response_profile()}
    route["constraints"] = [gh.response_envelope("fixture.github-response")]
    return value


def flow(url=LIST, *, method="GET", body=b"", headers=None):
    request = http.Request.make(method, url, body)
    request.headers = http.Headers(HEADERS if headers is None else headers)
    request.raw_content = body
    return SimpleNamespace(request=request, response=None, metadata={},
        client_conn=SimpleNamespace(peername=("127.0.0.1", 12345)))


class GithubIssuesTests(unittest.TestCase):
    def setUp(self):
        self.snapshot = pb.compile_policy_bundle(document())
        self.write_snapshot = pb.compile_policy_bundle(document(gh.WRITE))
        self.route = self.snapshot.routes[0]
        self.principal = self.snapshot.principals["agent:buffered-fixture"]
        self.credential = self.snapshot.credentials[self.route.credential_ref]
        self.adapter = adapters.get_adapter("generic.rest")

    def prepare(self, url=LIST, *, route=None, method="GET", body=b"", headers=None):
        route = self.route if route is None else route
        headers = list(HEADERS if headers is None else headers)
        if body:
            headers.append((b"Content-Type", b"application/json"))
        value = flow(url, method=method, body=body, headers=headers)
        self.assertTrue(adapters.preflight_request_admission(value, route,
            engine._normalized_request_headers(value)).allowed)
        discarded = engine._discard_declared_request_headers(value, route, self.principal, self.credential)
        engine._strip_identity_headers(value, self.principal)
        decision = self.adapter.validate_request(value, route, {})
        self.assertTrue(decision.allowed, decision.payload)
        self.assertTrue(self.adapter.rewrite_request(value, route, {}).allowed)
        engine._canonicalize_provider_query(value, trusted_query_view=True, route=route)
        canonical = engine._canonical_request(value, principal=self.principal, route=route,
            credential_version="7", policy_hash=(self.snapshot.hash if route is self.route else self.write_snapshot.hash),
            operation_fields=self.adapter.operation_fields(value, route, {}),
            forwarded_headers=engine._canonical_forwarded_request_headers(value, self.credential, route=route),
            discard_headers=discarded)
        return value, canonical

    def response(self, *, body=b' [ {"unprojected":18446744073709551617} ] ', fields=(),
            secret="synthetic-private-key", content_type=b"application/json"):
        value = flow(headers=[])
        value.response = http.Response.make(200, b"")
        value.response.headers = http.Headers(([(b"Content-Type", content_type)]
            if content_type is not None else []) + list(fields))
        value.response.raw_content = body
        value.metadata.update(catchplate_route=self.route, catchplate_route_id=self.route.id,
            catchplate_operation={"operation": "github.issues.read"})
        guard = engine._ResponseCredentialGuard()
        guard.add_text_encodings(secret)
        engine._install_response_credential_guard(value, guard)
        return value

    def test_closed_profile_compiles_without_widening_legacy(self):
        old = buffered.bundle()
        old_hash = pb.compile_policy_bundle(old).hash
        gmail_hash = pb.compile_policy_bundle(gmail.document()).hash
        for bundle in (gh.READ, gh.WRITE):
            for schema in (True, False):
                route = pb.compile_policy_bundle(document(bundle), validate_schema=schema).routes[0]
                self.assertEqual(route.adapter_config["request"], gh.request_profile(bundle))
                self.assertEqual(route.adapter_config["response"], gh.response_profile())
                self.assertTrue(pb.validate_ordered_form_route(route))
        changes = [lambda r: r.pop("credentialHeader"),
            lambda r: r["credentialHeader"].update(expectedValue="token wrong-placeholder"),
            lambda r: r.update(jit={}), lambda r: r.update(responseObservation={}),
            lambda r: r["adapter"]["config"].update(operationBundle=None),
            lambda r: r["adapter"]["config"].update(operationBundle="unknown"),
            lambda r: r["adapter"]["config"].pop("githubRepository"),
            lambda r: r["adapter"]["config"]["request"].update(queryMode="orderedFormV1"),
            lambda r: r["adapter"]["config"]["request"].update(discardHeaders=[]),
            lambda r: r["adapter"]["config"]["credentialBinding"].update(provider="github"),
            lambda r: r["adapter"]["config"]["credentialBinding"].update(subjects=["other"]),
            lambda r: r["constraints"][0].pop("contentTypePolicy"),
            lambda r: r["constraints"][0].update(contentTypePolicy=None),
            lambda r: r["constraints"][0].update(contentTypePolicy="unknown")]
        for change in changes:
            value = document(); change(value["routes"][0])
            for schema in (True, False):
                with self.subTest(change=changes.index(change), schema=schema), self.assertRaises(pb.PolicyBundleError):
                    pb.compile_policy_bundle(value, validate_schema=schema)
        for injection in ({"type": "bearer", "header": "X-Api-Key"},
                {"type": "bearer", "header": "Authorization", "field": "access_token"},
                {"type": "bearer", "header": "Authorization", "prefix": "Bearer "}):
            value = document(); value["credentials"][0]["injection"] = injection
            with self.assertRaises(pb.PolicyBundleError):
                pb.compile_policy_bundle(value, validate_schema=False)
        for descriptor in (None, {"mode": "replaceExact", "expectedValue": "token wrong"}):
            with self.assertRaises(ValueError):
                gh.validate_route(replace(self.route, credential_header=descriptor))
        self.assertEqual(pb.compile_policy_bundle(old).hash, old_hash)
        self.assertEqual(pb.compile_policy_bundle(gmail.document()).hash, gmail_hash)
        legacy_route = pb.compile_policy_bundle(old).routes[0]
        legacy_response = buffered.flow(b"{}", fields=[(b"Content-Type", b"application/json; charset=utf-8")])
        self.assertFalse(engine._evaluate_response_envelope(legacy_response, legacy_route).allowed)
        for original in (old, gmail.document()):
            for marker in (gh.CONTENT_TYPE_POLICY, None, "unknown"):
                altered = deepcopy(original)
                altered["routes"][0]["constraints"][0]["contentTypePolicy"] = marker
                for schema in (True, False):
                    with self.assertRaises(pb.PolicyBundleError):
                        pb.compile_policy_bundle(altered, validate_schema=schema)
        old["routes"][0]["adapter"]["config"]["response"]["allowedHeaders"] = ["link"]
        with self.assertRaises(pb.PolicyBundleError):
            pb.compile_policy_bundle(old)

    def test_actual_adapter_preserves_query_and_body_bytes(self):
        for wire in ("state=open&per_page=2&page=1", "labels=good+first+issue&page=2",
                "labels=owner%27s&&page=2", "since=2026-10-09t12:00:00.123456789z&page=2"):
            value, canonical = self.prepare(LIST + "?" + wire)
            self.assertEqual(value.request.pretty_url, LIST + "?" + wire)
            self.assertEqual(canonical["v"], 3)
            self.assertEqual(canonical["request"]["query_mode"], "githubRestV1")
            self.assertEqual(canonical["request"]["query_wire"], wire)
            self.assertEqual(canonical["request"]["discard_headers"], ["accept-encoding"])
            self.assertNotIn("accept-encoding", value.request.headers)
            self.assertEqual(canonical["operation"], {"operation": "github.issues.read"})
        write = self.write_snapshot.routes[0]
        for url, body in ((LIST, b' { "title":"new issue", "labels":["triage"], "extra":1e2 } '),
                (LIST + "/7/comments", b'{"body":"new comment","extra":{"keep":true}}')):
            value, canonical = self.prepare(url, route=write, method="POST", body=body)
            self.assertEqual(value.request.raw_content, body)
            self.assertTrue(engine._provider_request_matches_canonical(value, canonical, self.credential, route=write))

    def test_typed_paths_values_headers_and_body_refuse(self):
        bad_urls = [LIST + "?" + query for query in ("page=0", "page=01", "page=1000001", "per_page=101",
            "page=1&page=2", "labels=a&%6cabels=b", "state=merged", "labels=owner's", "labels=%0a",
            "since=0000-01-01T00:00:00Z", "since=2026-01-01T00:00:60Z", "since=2026-01-01T00:00:00+01:99")]
        bad_urls += [LIST + "/7?page=1", LIST + "/7/comments?state=all", LIST + "/07",
            LIST + "/9007199254740992", LIST.replace("fixture-repo", "other"),
            gh.ORIGIN + "/repositories/1/issues?page=2"]
        for url in bad_urls:
            with self.subTest(url=url):
                self.assertFalse(self.adapter.validate_request(flow(url, headers=[]), self.route, {}).allowed)
        for field, value in ((b"Accept-Language", b"en"), (b"Sec-Fetch-Mode", b"navigate"),
                (b"X-Github-Api-Version", b"0000-01-01"), (b"X-Unexpected", b"x"), (b"Accept_Encoding", b"gzip")):
            self.assertFalse(self.adapter.validate_request(flow(headers=[(field, value)]), self.route, {}).allowed)
        write = self.write_snapshot.routes[0]
        for url, body in ((LIST, b'{}'), (LIST, b'{"title":"a","title":"b"}'),
                (LIST + "/7", b'{"title":"a"}'), (LIST + "/7/comments", b'{"body":""}'),
                (LIST, b'{"title":"' + b"a" * 1025 + b'"}'), (LIST, b" " * 65537)):
            self.assertFalse(self.adapter.validate_request(flow(url, method="POST", body=body,
                headers=[(b"Content-Type", b"application/json")]), write, {}).allowed)
        self.assertFalse(self.adapter.validate_request(flow(method="GET", body=b"{}", headers=[]), self.route, {}).allowed)

    def test_go_github_reactions_accept_is_exact_and_scoped(self):
        # Official v74.0.0 github.go mediaTypeReactionsPreview; issues.go uses
        # it directly. The guessed +json suffix is deliberately NOT admitted.
        preview = b"application/vnd.github.squirrel-girl-preview"
        headers = [(b"Accept", preview), *HEADERS[1:]]
        for route, operation in ((self.route, "github.issues.read"),
                (self.write_snapshot.routes[0], "github.issues.write")):
            value, canonical = self.prepare(headers=headers, route=route)
            self.assertEqual(canonical["request"]["headers"]["accept"], preview.decode())
            self.assertEqual(canonical["operation"], {"operation": operation})
            self.assertTrue(engine._provider_request_matches_canonical(value, canonical, self.credential, route=route))
            self.assertEqual(route.credential_header, gh.REPLACEMENT)
            self.assertEqual(route.adapter_config["githubRepository"], REPOSITORY)
            self.assertEqual(route.adapter_config["request"]["valueRules"], [])
            # An alternative still-admitted value cannot reuse this commitment.
            value.request.headers["Accept"] = "application/vnd.github.v3+json"
            self.assertFalse(engine._provider_request_matches_canonical(value, canonical, self.credential, route=route))
        for accept in (preview + b"+json", b"application/vnd.github.mockingbird-preview+json",
                b"application/vnd.other.squirrel-girl-preview", preview + b", application/json",
                preview + b";q=1", b" " + preview, preview + b" ", preview.upper()):
            self.assertFalse(self.adapter.validate_request(flow(headers=[(b"Accept", accept)]), self.route, {}).allowed)
        for second_name in (b"Accept", b"accept"):
            self.assertFalse(self.adapter.validate_request(flow(headers=[(b"Accept", preview),
                (second_name, preview)]), self.route, {}).allowed)
        for url in (LIST.replace("fixture-repo", "other"), LIST.replace("api.github.com", "other.example"),
                    LIST.replace("https://", "http://")):
            self.assertFalse(self.adapter.validate_request(flow(url, headers=[(b"Accept", preview)]), self.route, {}).allowed)
        self.assertFalse(self.adapter.validate_request(flow(method="POST", body=b'{"title":"not granted"}',
            headers=[(b"Accept", preview), (b"Content-Type", b"application/json")]), self.route, {}).allowed)
        legacy = pb.compile_policy_bundle(buffered.bundle()).routes[0]
        self.assertFalse(self.adapter.validate_request(flow("https://api.example.com/fixture",
            headers=[(b"Accept", preview)]), legacy, {}).allowed)
        self.assertEqual(pb.compile_policy_bundle(document()).hash, self.snapshot.hash)
        self.assertEqual(pb.compile_policy_bundle(document(gh.WRITE)).hash, self.write_snapshot.hash)

    def test_v3_final_binding_and_unsupported_consumers_fail_closed(self):
        value, canonical = self.prepare(LIST + "?labels=good+issue&page=2")
        self.assertTrue(engine._provider_request_matches_canonical(value, canonical, self.credential, route=self.route))
        for wire in ("page=2&labels=good+issue", "labels=good%20issue&page=2"):
            altered, _ = self.prepare(LIST + "?" + wire)
            self.assertFalse(engine._provider_request_matches_canonical(altered, canonical, self.credential, route=self.route))
        for field, content in (("query_mode", "orderedFormV1"), ("query_wire", None), ("discard_headers", []),
                ("query", [["page", "2"], ["labels", "good issue"]])):
            changed = deepcopy(canonical); changed["request"][field] = content
            self.assertFalse(engine._provider_request_matches_canonical(value, changed, self.credential, route=self.route))
        value.request.headers["Accept-Encoding"] = "identity"
        self.assertFalse(engine._provider_request_matches_canonical(value, canonical, self.credential, route=self.route))
        for atomic, proof in (("1", None), ("0", b"x-catchplate-proof-nonce")):
            headers = list(HEADERS) + ([(proof, b"synthetic")] if proof else [])
            with patch.dict(os.environ, {"CATCHPLATE_ATOMIC_RELEASE_AUTHORIZATION_ENABLED": atomic}), \
                    patch.object(engine, "get_policy_snapshot", return_value=self.snapshot), \
                    patch.object(engine.runtime, "get_credential_generation", side_effect=AssertionError("unexpected credential lookup")) as lookup:
                result = engine.evaluate_request(flow(headers=headers))
                self.assertEqual(result.decision.payload["error"], "ordered_form_consumer_unsupported")
                lookup.assert_not_called()
        denial = engine._legacy_mitm_route_admission(flow(), self.route)
        self.assertEqual(denial.status_code, 503)
        self.assertEqual(denial.payload["error"], "python_credential_header_replacement_unsupported")

    def test_link_protocol_metadata_normalizes_only_same_list(self):
        numeric = gh.ORIGIN + "/repositories/123/issues?page=2&per_page=1"
        cases = (("<" + numeric + '>;rel="next"', b"application/json"),
            (" <" + numeric + '>;   rel="next" ', b"application/json; charset=utf-8"),
            ("<" + numeric + '>; rel="next"', b"APPLICATION/JSON;\tCHARSET=UTF-8"))
        for raw, content_type in cases:
            value = self.response(fields=[(b"Link", raw.encode()), (b"X-Ratelimit-Remaining", b"42"),
                (b"Server", b"discard"), (b"Server", b"also-discard")], content_type=content_type)
            original = value.response.raw_content
            self.assertTrue(engine._evaluate_response_envelope(value, self.route).allowed)
            self.assertTrue(self.adapter.prepare_response(value, self.route, {}).allowed)
            self.assertTrue(self.adapter.validate_response(value, self.route, {}).allowed)
            self.assertEqual(value.response.raw_content, original)
            self.assertEqual(value.response.headers["Link"], '<' + LIST + '?page=2&per_page=1>; rel="next"')
            self.assertEqual(value.response.headers["X-Ratelimit-Remaining"], "42")
            self.assertNotIn("Server", value.response.headers)
        for content_type in (b"application/json; charset=iso-8859-1", b"application/json; charset=ascii",
                b"application/json; charset=utf-8; charset=utf-8", b"application/json; charset=\"utf-8\"",
                b"application/json; charset =utf-8", b" application/json", b"application/json ",
                b"application/json; other=utf-8"):
            value = self.response(content_type=content_type)
            self.assertFalse(engine._evaluate_response_envelope(value, self.route).allowed)
            self.assertFalse(self.adapter.prepare_response(value, self.route, {}).allowed)
        duplicate = self.response(fields=[(b"content-type", b"application/json; charset=utf-8")])
        self.assertFalse(engine._evaluate_response_envelope(duplicate, self.route).allowed)
        self.assertFalse(self.adapter.prepare_response(duplicate, self.route, {}).allowed)
        no_content = self.response(body=b"", content_type=None)
        no_content.response.status_code = 204
        self.assertTrue(engine._evaluate_response_envelope(no_content, self.route).allowed)
        self.assertTrue(self.adapter.prepare_response(no_content, self.route, {}).allowed)
        self.assertTrue(self.adapter.validate_response(no_content, self.route, {}).allowed)
        for target in (LIST + "?per_page=1", LIST.replace("fixture-repo", "other") + "?page=2",
                numeric.replace("/issues?", "/issues/7/comments?"), numeric.replace("api.github.com", "example.com"),
                numeric + "&page=3"):
            with self.assertRaises(ValueError):
                gh.normalize_link('<' + target + '>; rel="next"', url=LIST, method="GET", repository=REPOSITORY)
        for raw in ('<' + numeric + '>;\trel="next"', '<' + numeric + '>; rel="next", <' + numeric + '>; rel="next"'):
            with self.assertRaises(ValueError):
                gh.normalize_link(raw, url=LIST, method="GET", repository=REPOSITORY)

    def test_original_and_normalized_metadata_are_secret_scanned(self):
        for fields in ([(b"X-Unlisted", b"synthetic-private-key")],
                [(b"synthetic-private-key", b"metadata")], [(b"Set_Cookie", b"x=y")],
                [(b"Link", b"x"), (b"Link", b"y")]):
            value = self.response(fields=fields)
            self.assertFalse(engine._evaluate_response_envelope(value, self.route).allowed)
        reflected = REPOSITORY["owner"] + "/" + REPOSITORY["name"]
        value = self.response(body=b"[]", fields=[(b"Link",
            ("<" + gh.ORIGIN + '/repositories/123/issues?page=2>; rel="next"').encode())], secret=reflected)
        self.assertNotIn(reflected, value.response.headers["Link"])
        # Only the audit sink is suppressed: the real envelope, adapter rewrite
        # and final credential-reflection guard all execute unchanged.
        with patch.object(engine.runtime, "log_request"):
            decision = engine.evaluate_response(value)
        self.assertEqual(decision.payload["error"], "response_credential_reflection")
        self.assertFalse(decision.allowed)


if __name__ == "__main__":
    unittest.main()
