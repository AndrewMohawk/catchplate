#!/usr/bin/env python3
"""Source-bounded Python integration of opted-in Gmail form queries.

Real schema/compiler/adapter/header/canonical guards, synthetic request objects
and secrets only. No provider, network, lease issuance or transport proof. The
normal Rust proxy still requires its separate end-to-end acceptance.
"""
from copy import deepcopy
from dataclasses import replace
import json
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
from catchplate import adapters, policy_bundle as pb, policy_engine as engine
import test_gmail_read_bundle as baseline

LIST = baseline.LIST
MODE = "orderedFormV1"
DEFAULT_HEADERS = [(b"Accept", b"*/*"), (b"Accept-Encoding", b"gzip, deflate"),
    (b"User-Agent", b"python-requests-fixture"), (b"Connection", b"keep-alive"),
    (b"X-Catchplate-Agent", b"buffered-fixture")]


def document(*, ordered=True):
    value = baseline.document()
    if ordered:
        value["routes"][0]["adapter"]["config"]["request"] = pb.provider_request_profile(
            "gmail.read.v1", query_mode=MODE)
    return value


def flow(url=LIST, *, headers=None, method="GET", body=b""):
    result = baseline.request(url, fields=DEFAULT_HEADERS if headers is None else headers,
        method=method, body=body)
    result.client_conn = SimpleNamespace(peername=("127.0.0.1", 12345))
    return result


class GmailOrderedQueryIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.snapshot = pb.compile_policy_bundle(document())
        self.route = self.snapshot.routes[0]
        self.principal = self.snapshot.principals["agent:buffered-fixture"]
        self.credential_policy = self.snapshot.credentials[self.route.credential_ref]
        self.adapter = adapters.get_adapter("gmail.read.v1")

    def prepare(self, url=LIST, *, headers=None):
        request = flow(url, headers=headers)
        before = request.request.pretty_url
        decision = adapters.preflight_request_admission(request, self.route,
            engine._normalized_request_headers(request))
        self.assertTrue(decision.allowed, decision.payload)
        discarded = engine._discard_declared_request_headers(request, self.route,
            self.principal, self.credential_policy)
        engine._strip_identity_headers(request, self.principal)
        parts = pb.validated_request_urlsplit_for_route(request.request.pretty_url, self.route)
        params = {} if parts.path == "/gmail/v1/users/me/messages" else {"message_id": parts.path.rsplit("/", 1)[1]}
        decision = self.adapter.validate_request(request, self.route, params)
        self.assertTrue(decision.allowed, decision.payload)
        self.assertTrue(self.adapter.rewrite_request(request, self.route, params).allowed)
        engine._canonicalize_provider_query(request, trusted_query_view=True, route=self.route)
        self.assertEqual(request.request.pretty_url, before)
        operation = self.adapter.operation_fields(request, self.route, params)
        canonical = engine._canonical_request(request, principal=self.principal, route=self.route,
            credential_version="7", policy_hash=self.snapshot.hash, operation_fields=operation,
            forwarded_headers=engine._canonical_forwarded_request_headers(request, self.credential_policy,
                route=self.route),
            discard_headers=discarded)
        return request, canonical, params

    def matches(self, request, canonical, *, route=None):
        return engine._provider_request_matches_canonical(request, canonical,
            self.credential_policy, route=self.route if route is None else route)

    def test_explicit_profile_schema_and_legacy_hash_retention(self):
        legacy = document(ordered=False)
        old = deepcopy(legacy)
        before = pb.compile_policy_bundle(legacy).hash
        for validate_schema in (True, False):
            current = pb.compile_policy_bundle(document(), validate_schema=validate_schema)
            self.assertEqual(current.routes[0].adapter_config["request"], {
                "queryMode": MODE, "allowedHeaders": ["accept", "user-agent", "x-goog-api-client"],
                "discardHeaders": ["accept-encoding"], "allowedQueryKeys": list(pb.GMAIL_READ_QUERY_KEYS),
                "allowedMediaTypes": [], "maxBodyBytes": 0, "valueRules": []})
            self.assertTrue(pb.validate_ordered_form_route(current.routes[0]))
        self.assertEqual(legacy, old)
        self.assertEqual(pb.compile_policy_bundle(legacy).hash, before)
        self.assertNotIn("queryMode", pb.provider_request_profile("gmail.read.v1"))
        self.assertFalse(pb.validate_ordered_form_route(pb.compile_policy_bundle(legacy).routes[0]))
        for mutate in (lambda r: r.update(queryMode=None), lambda r: r.update(queryMode="unknown"),
                lambda r: r.pop("discardHeaders"), lambda r: r.update(discardHeaders=[]),
                lambda r: r.update(allowedHeaders=list(pb.GMAIL_READ_REQUEST_HEADERS)),
                lambda r: r.update(discardHeaders=["accept-encoding", "x-extra"])):
            value = document(); mutate(value["routes"][0]["adapter"]["config"]["request"])
            for validate_schema in (True, False):
                with self.subTest(value=value["routes"][0]["adapter"]["config"]["request"], schema=validate_schema):
                    with self.assertRaises(pb.PolicyBundleError):
                        pb.compile_policy_bundle(value, validate_schema=validate_schema)

    def test_fixed_ingress_candidate_never_opts_legacy_routes_in(self):
        target = LIST + "?q=from:alice@example.test+has:attachment&maxResults=2&labelIds=A&labelIds=B"
        self.assertEqual(pb.validated_request_routing_target(target, "GET").query, target.partition("?")[2])
        with self.assertRaises(ValueError):
            pb.validate_raw_absolute_target(target)
        legacy = pb.compile_policy_bundle(document(ordered=False)).routes[0]
        with self.assertRaises(ValueError):
            pb.validated_request_urlsplit_for_route(target, legacy)
        for url, method in ((target, "POST"), (target.replace("gmail.googleapis.com", "api.example.com"), "GET"),
                (target.replace("https://", "http://"), "GET"), (LIST + "/id/attachments/part?q=a+b", "GET"),
                (LIST + "?q=%0a", "GET"), (LIST + "?q=%ZZ", "GET")):
            with self.subTest(url=url, method=method), self.assertRaises(ValueError):
                pb.validated_request_routing_target(url, method)

    def test_real_adapter_accepts_form_order_repeats_and_default_headers_without_rewrite(self):
        for query in ("q=from:alice@example.test+has:attachment&maxResults=2&labelIds=A&labelIds=B",
                "labelIds=A&&q=a=b;c/%25%2b&labelIds=A&maxResults=1",
                "q&maxResults=2", "q=hello%20world&maxResults=2", "maxResults=2&q=%C3%A9"):
            request, canonical, _ = self.prepare(LIST + "?" + query)
            with self.subTest(query=query):
                self.assertEqual(canonical["v"], 3)
                self.assertEqual(canonical["request"]["query_wire"], query)
                self.assertEqual(canonical["request"]["discard_headers"], ["accept-encoding"])
                self.assertNotIn("accept-encoding", request.request.headers)
                self.assertNotIn("connection", canonical["request"]["headers"])
                self.assertTrue(self.matches(request, canonical))
        request, canonical, _ = self.prepare(LIST + "/message-1?metadataHeaders=Subject&format=metadata&metadataHeaders=From")
        self.assertEqual(canonical["request"]["query"], [["metadataHeaders", "Subject"],
            ["format", "metadata"], ["metadataHeaders", "From"]])
        self.assertTrue(self.matches(request, canonical))

    def test_provider_values_cardinality_and_physical_headers_still_refuse(self):
        for query in ("maxResults=0", "maxResults=1&maxResults=2", "q=x&q=y", "pageToken=", "includeSpamTrash=true",
                "fields=id", "metadataHeaders=Subject", "labelIds=bad/slash",
                "&".join(["labelIds=A"] * 33), "q=" + "x" * 2049):
            request = flow(LIST + "?" + query, headers=[])
            with self.subTest(query=query):
                self.assertFalse(self.adapter.validate_request(request, self.route, {}).allowed)
        for query in ("format=raw", "metadataHeaders=", "labelIds=A", "format=full&format=metadata"):
            self.assertFalse(self.adapter.validate_request(flow(LIST + "/id?" + query, headers=[]),
                self.route, {"message_id": "id"}).allowed)
        for headers in (DEFAULT_HEADERS + [(b"Accept-Encoding", b"identity")],
                DEFAULT_HEADERS + [(b"aCcEpT-EnCoDiNg", b"gzip")]):
            with self.subTest(headers=headers), self.assertRaises(ValueError):
                engine._normalized_request_headers(flow(headers=headers))
        alias = flow(headers=DEFAULT_HEADERS + [(b"Accept_Encoding", b"gzip")])
        engine._discard_declared_request_headers(alias, self.route, self.principal, self.credential_policy)
        engine._strip_identity_headers(alias, self.principal)
        self.assertIn("Accept_Encoding", alias.request.headers)
        self.assertFalse(self.adapter.validate_request(alias, self.route, {}).allowed)
        unexpected = flow(headers=[(b"X-Unexpected", b"value")])
        self.assertFalse(self.adapter.validate_request(unexpected, self.route, {}).allowed)
        # The isolated adapter cannot silently consume a client's offer; the
        # signed discard stage must actually run first.
        self.assertFalse(self.adapter.validate_request(flow(), self.route, {}).allowed)

    def test_v3_pins_wire_pairs_absence_empty_discard_and_generation(self):
        digests = []
        pairs = []
        for query in ("q=a+b", "q=a%20b", "q=a%2Bb", "q=a%2bb"):
            request, canonical, _ = self.prepare(LIST + "?" + query)
            digests.append(engine._digest(canonical)); pairs.append(canonical["request"]["query"])
            self.assertTrue(self.matches(request, canonical))
        self.assertEqual(pairs[0], pairs[1])
        self.assertEqual(pairs[2], pairs[3])
        self.assertNotEqual(pairs[0], pairs[2])
        self.assertEqual(len(set(digests)), 4)
        no_query, canonical, _ = self.prepare()
        self.assertIsNone(canonical["request"]["query_wire"])
        # Preserve the parser-visible trailing '?' explicitly in this object;
        # this is not evidence about an HTTP library's target serialization.
        empty = SimpleNamespace(request=SimpleNamespace(method="GET", pretty_url=LIST + "?",
            headers=http.Headers(), raw_content=b"", get_content=lambda strict: b""),
            client_conn=no_query.client_conn, metadata={})
        empty_canonical = engine._canonical_request(empty, principal=self.principal, route=self.route,
            credential_version="7", policy_hash=self.snapshot.hash,
            operation_fields={"operation": "gmail.messages.list", "gmailUser": "me"},
            forwarded_headers=engine._canonical_forwarded_request_headers(empty, self.credential_policy,
                route=self.route), discard_headers=("accept-encoding",))
        self.assertEqual(empty_canonical["request"]["headers"], {"host": "gmail.googleapis.com"})
        self.assertEqual(empty_canonical["request"]["query_wire"], "")
        self.assertTrue(self.matches(empty, empty_canonical))
        self.assertFalse(self.matches(empty, {**empty_canonical,
            "request": {**empty_canonical["request"], "query_wire": None}}))
        for field, value in (("credential_version", "8"), ("policy_hash", "sha256:" + "f" * 64),
                ("principal", "different-app"), ("route_id", "different-route")):
            altered = deepcopy(canonical); altered[field] = value
            self.assertNotEqual(engine._digest(altered), engine._digest(canonical))
            self.assertNotEqual(engine._operation_digest(altered), engine._operation_digest(canonical))

    def test_dispatch_binding_rejects_reorder_reserialize_pairs_and_discard_tampering(self):
        url = LIST + "?q=a+b&labelIds=A&labelIds=B"
        request, canonical, _ = self.prepare(url)
        for query in ("labelIds=A&labelIds=B&q=a+b", "q=a%20b&labelIds=A&labelIds=B",
                "q=a+b&labelIds=B&labelIds=A", "q=a+b&labelIds=A"):
            changed, _, _ = self.prepare(LIST + "?" + query)
            self.assertFalse(self.matches(changed, canonical))
        for mutate in (lambda c: c["request"].update(query=list(reversed(c["request"]["query"]))),
                lambda c: c["request"].update(query_wire="q=other"),
                lambda c: c["request"].update(query_mode="unknown"),
                lambda c: c["request"].update(discard_headers=[]),
                lambda c: c["request"].pop("query_wire"), lambda c: c.update(v=2)):
            altered = deepcopy(canonical); mutate(altered)
            self.assertFalse(self.matches(request, altered))
        request.request.headers["Accept-Encoding"] = "identity"
        self.assertFalse(self.matches(request, canonical))
        del request.request.headers["Accept-Encoding"]
        synthetic = {"kind": "oauth2", "secret": json.dumps({"access_token": "synthetic-private-value"})}
        engine._inject_credential(request, self.credential_policy, synthetic)
        self.assertTrue(self.matches(request, canonical))
        self.assertFalse(engine._provider_request_matches_canonical(request, canonical, self.credential_policy))
        self.assertFalse(self.matches(request, canonical,
            route=pb.compile_policy_bundle(document(ordered=False)).routes[0]))

    def test_v1_v2_canonical_shapes_are_unchanged(self):
        legacy_snapshot = pb.compile_policy_bundle(document(ordered=False))
        legacy = legacy_snapshot.routes[0]
        request = flow(LIST + "?maxResults=2&q=a%20b", headers=[])
        common = dict(principal=self.principal, route=legacy, credential_version="7",
            policy_hash=legacy_snapshot.hash, operation_fields={"operation": "gmail.messages.list", "gmailUser": "me"},
            forwarded_headers=engine._canonical_forwarded_request_headers(request, self.credential_policy))
        old = engine._canonical_request(request, discard_headers=(), **common)
        self.assertEqual(old, {"v": 1, "principal": self.principal.id, "client_ip": "127.0.0.1",
            "route_id": legacy.id, "credential_ref": legacy.credential_ref, "credential_version": "7",
            "policy_hash": legacy_snapshot.hash, "operation": common["operation_fields"],
            "request": {"method": "GET", "scheme": "https", "authority": "gmail.googleapis.com",
                "path": "/gmail/v1/users/me/messages", "query": [("maxResults", "2"), ("q", "a b")],
                "headers": {"host": "gmail.googleapis.com"},
                "body_sha256": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}})
        v2 = engine._canonical_request(request, discard_headers=("x-fixture-client-info",), **common)
        expected = deepcopy(old); expected["v"] = 2
        expected["request"]["discard_headers"] = ["x-fixture-client-info"]
        self.assertEqual(v2, expected)
        self.assertTrue(engine._provider_request_matches_canonical(request, old, self.credential_policy, route=legacy))

    def test_proof_controlled_and_scalar_consumers_refuse_before_credential_observation(self):
        for mutate in (lambda r: r.update(jit={}), lambda r: r.update(responseObservation={}),
                lambda r: r["adapter"]["config"]["request"].update(valueRules=[{"source": "query", "name": "q"}]),
                lambda r: r["constraints"].append({"id": "quota", "type": "rateLimit", "max": 1, "windowSeconds": 60})):
            value = document(); mutate(value["routes"][0])
            with self.assertRaises(pb.PolicyBundleError):
                pb.compile_policy_bundle(value)
        self.assertIsNone(pb.adapter_operation_query_fields("gmail.read.v1", self.route.adapter_config, "gmail.messages.list"))
        corrupt = replace(self.route, constraints=(*self.route.constraints, {"type": "traversalBudget"}))
        with self.assertRaises(pb.PolicyBundleError):
            engine._durable_policy_claims(flow(), snapshot=self.snapshot, principal=self.principal,
                route=corrupt, credential_version=7, operation_fields={"operation": "gmail.messages.list"})
        for atomic, proof in (("1", None), ("0", b"x-catchplate-proof-nonce"),
                ("0", b"x-catchplate-stream-proof-nonce"), ("0", b"x-catchplate-observation-nonce")):
            headers = list(DEFAULT_HEADERS)
            if proof is not None:
                headers.append((proof, b"synthetic"))
            with patch.dict(os.environ, {"CATCHPLATE_ATOMIC_RELEASE_AUTHORIZATION_ENABLED": atomic}), \
                    patch.object(engine, "get_policy_snapshot", return_value=self.snapshot), \
                    patch.object(engine.runtime, "get_credential_generation", side_effect=AssertionError("must not read generation")) as generation:
                result = engine.evaluate_request(flow(LIST + "?q=a+b", headers=headers))
                self.assertFalse(result.decision.allowed)
                self.assertEqual(result.decision.payload["error"], "ordered_form_consumer_unsupported")
                generation.assert_not_called()

    def test_response_bound_uses_admitted_singleton_without_query_reserialization(self):
        request, _, params = self.prepare(LIST + "?q=hello+world&maxResults=1&labelIds=A&labelIds=B")
        request.response = http.Response.make(200, b'{"messages":[{"id":"a"},{"id":"b"}]}',
            {"Content-Type": "application/json"})
        before = request.request.pretty_url
        result = self.adapter.validate_response(request, self.route, params)
        self.assertFalse(result.allowed)
        self.assertEqual(result.payload["error"], "gmail_read_response_invalid")
        request.response.raw_content = b'{"messages":[{"id":"a"}]}'
        self.assertTrue(self.adapter.validate_response(request, self.route, params).allowed)
        self.assertEqual(request.request.pretty_url, before)


if __name__ == "__main__":
    unittest.main()
