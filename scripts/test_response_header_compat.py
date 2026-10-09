#!/usr/bin/env python3
"""Focused synthetic V2 checks using real schema/compiler/engine/adapters.

No transport, provider, proof issuance, or production acceptance is established.
Physical fields are real mitmproxy Headers; hidden-wire framing remains a Rust
transport obligation. Run only in the root-authorized bounded offline batch.
"""
from copy import deepcopy
from dataclasses import replace
import base64
import json
import unittest

import ordinary_client_compat_fixtures as fx
from serverware import policy_bundle as pb
from serverware.response_header_compat import (
    HeaderCompatibilityError, RESPONSE_MODE, TRANSPORT_HEADERS,
    inspect_physical_headers,
)

SECRET = "synthetic-private-response-token"


def document():
    value = fx.document()
    response = fx.response_config(value)
    response["mode"] = response["error"]["mode"] = RESPONSE_MODE
    value["routes"][0]["constraints"][0]["unlistedHeaderPolicy"] = "discardUnselectedV1"
    return value


def compile_route(value=None, schema=True):
    return pb.compile_policy_bundle(document() if value is None else value,
        validate_schema=schema).routes[0]


class ResponseHeaderCompatibilityTests(unittest.TestCase):
    def setUp(self):
        self.adapters, self.engine, self.adapter = fx.runtime()
        self.route = compile_route()

    def flow(self, fields, body=b' {"ok": true}\n', status=200, route=None, guarded=True):
        route = self.route if route is None else route
        flow = fx.response_flow(body, status=status, fields=fields)
        flow.metadata["serverware_route"] = route
        if guarded:
            guard = self.engine._ResponseCredentialGuard()
            guard.add_text_encodings(SECRET)
            self.engine._install_response_credential_guard(flow, guard)
        return flow

    def admit(self, flow, route=None):
        route = self.route if route is None else route
        for check in (
            lambda: self.engine._validate_response_content_encoding(flow),
            lambda: self.engine._evaluate_response_envelope(flow, route),
            lambda: self.adapter.prepare_response(flow, route, {}),
            lambda: self.adapter.validate_response(flow, route, {}),
        ):
            decision = check()
            if not decision.allowed:
                return decision
        return decision

    def assert_refused(self, fields, code):
        with self.assertRaises(HeaderCompatibilityError) as raised:
            inspect_physical_headers(fields, listed_names=())
        self.assertEqual(raised.exception.code, code)
        self.assertEqual(set(raised.exception.payload()), {"error", "headerCount", "headerBytes"})

    def test_compiler_schema_pairing_and_old_policy_identity(self):
        old = fx.document()
        new = document()
        self.assertNotEqual(pb.compile_policy_bundle(old).hash, pb.compile_policy_bundle(new).hash)
        reverted = deepcopy(new)
        response = fx.response_config(reverted)
        response["mode"] = response["error"]["mode"] = fx.RESPONSE_MODE
        del reverted["routes"][0]["constraints"][0]["unlistedHeaderPolicy"]
        self.assertEqual(pb.compile_policy_bundle(old).hash, pb.compile_policy_bundle(reverted).hash)
        malformed = []
        value = document(); del value["routes"][0]["constraints"][0]["unlistedHeaderPolicy"]; malformed.append(value)
        value = document(); fx.response_config(value)["error"]["mode"] = fx.RESPONSE_MODE; malformed.append(value)
        value = document(); value["routes"][0]["constraints"][0]["unlistedHeaderPolicy"] = "future"; malformed.append(value)
        value = document(); value["routes"][0]["constraints"][0]["bodyPresence"] = "required"; malformed.append(value)
        value = document(); value["routes"][0]["adapter"]["type"] = "gmail.v1"; malformed.append(value)
        for old_mode in (fx.RESPONSE_MODE, "bufferedPassthrough", "json"):
            value = document(); response = fx.response_config(value)
            response["mode"] = response["error"]["mode"] = old_mode
            malformed.append(value)
        for schema in (False, True):
            compile_route(schema=schema)
            for index, value in enumerate(malformed):
                with self.subTest(schema=schema, case=index), self.assertRaises(pb.PolicyBundleError):
                    compile_route(value, schema=schema)

    def test_all_physical_bounds_and_ascii_controls(self):
        accepted = (
            [(b"x", b"v")] * 128,
            [(b"n" * 128, b"v" * 8192)],
            [(b"x", b"v" * 8191)] * 8,
            [(b"X-Trace", b"\t visible ASCII ~ ")],
        )
        for fields in accepted:
            self.assertEqual(inspect_physical_headers(fields, listed_names=()), [])
        for fields in ([(b"x", b"v")] * 129, [(b"n" * 129, b"v")],
                [(b"x", b"v" * 8193)], [(b"x", b"v" * 8191)] * 7 + [(b"x", b"v" * 8192)]):
            self.assert_refused(fields, "response_metadata_limit_exceeded")
        for name, value in ((b"", b"v"), (b"bad name", b"v"), (b"x\xff", b"v"),
                *((b"x", bytes([byte])) for byte in (0, 1, 8, 10, 13, 31, 127, 128, 255))):
            self.assert_refused([(name, value)], "response_metadata_invalid")
        self.assert_refused(None, "response_metadata_evidence_unavailable")
        self.assert_refused({"x": "v"}, "response_metadata_evidence_unavailable")
        self.assert_refused([("x", "v")], "response_metadata_invalid")

    def test_transport_security_aliases_and_listed_duplicates_deny(self):
        for name in TRANSPORT_HEADERS:
            raw = name.encode()
            self.assert_refused([(raw, b"x"), (raw.upper(), b"x")], "response_metadata_duplicate")
            if "-" in name:
                self.assert_refused([(raw.replace(b"-", b"_"), b"x")], "response_metadata_reserved_header")
        for name in (b"Authorization", b"Proxy-Authorization", b"proxy_authorization", b"Cookie",
                b"Set-Cookie", b"set_cookie", b"X-Serverware-Any", b"x_serverware_any", b"X-Serverware_Any"):
            self.assert_refused([(name, b"synthetic")], "response_metadata_reserved_header")
        with self.assertRaises(HeaderCompatibilityError) as raised:
            inspect_physical_headers([(b"ETag", b"one"), (b"etag", b"two")], listed_names={"etag"})
        self.assertEqual(raised.exception.code, "response_metadata_duplicate")

    def test_every_envelope_selection_and_predicates_remain_binding(self):
        value = document(); response = fx.response_config(value)
        response["allowedHeaders"] = ["etag"]
        envelope = value["routes"][0]["constraints"][0]
        envelope["allowedResponseHeaderNames"] = ["etag"]
        envelope["responseHeaderRules"] = [{"name": "etag", "required": True,
            "predicate": {"kind": "equals", "value": '"stable"'}}]
        route = compile_route(value)
        fields = [(b"Content-Type", b"application/json"), (b"ETag", b'"stable"'), (b"Server", b"fixture")]
        flow = self.flow(fields, route=route)
        self.assertTrue(self.admit(flow, route).allowed)
        self.assertEqual(flow.response.headers["etag"], '"stable"')
        self.assertNotIn("server", flow.response.headers)
        for bad_fields in (fields[:1], fields[:1] + [(b"etag", b'"wrong"')], fields + [(b"etag", b'"stable"')]):
            self.assertFalse(self.admit(self.flow(bad_fields, route=route), route).allowed)
        other = deepcopy(envelope); other.update(id="other", allowedResponseHeaderNames=[], responseHeaderRules=[])
        value["routes"][0]["constraints"].append(other)
        for schema in (False, True):
            with self.assertRaises(pb.PolicyBundleError):compile_route(value, schema=schema)
        for name in ("x_serverware_token", "proxy_connection", "n" * 129):
            value = document(); envelope = value["routes"][0]["constraints"][0]
            envelope["allowedResponseHeaderNames"] = [name]
            envelope["responseHeaderRules"] = [{"name": name, "required": False,
                "predicate": {"kind": "equals", "value": "safe"}}]
            with self.assertRaises(pb.PolicyBundleError):compile_route(value, schema=False)

    def test_v2_discards_metadata_but_preserves_json_and_204_contract(self):
        metadata = [(b"Date", b"fixture-time"), (b"date", b"second-time"),
            (b"Server", b"fixture"), (b"X-Trace", b"one"), (b"x-trace", b"two")]
        raw = b' \n{"n":18446744073709551617,"s":"\\u0061"}\t'
        for status in (200, 400, 500):
            flow = self.flow([(b"Content-Type", b"application/json")] + metadata, raw, status)
            self.assertTrue(self.admit(flow).allowed)
            self.assertEqual(flow.response.raw_content, raw)
            self.assertEqual(set(flow.response.headers.keys()), {"Content-Type", "Content-Length"})
        for fields in (metadata, [(b"Content-Type", b"application/json")] + metadata):
            flow = self.flow(fields, b"", 204)
            self.assertTrue(self.admit(flow).allowed)
            self.assertEqual(flow.response.raw_content, b"")
            self.assertNotIn("content-length", flow.response.headers)
            self.assertNotIn("transfer-encoding", flow.response.headers)
            self.assertEqual("content-type" in flow.response.headers, fields is not metadata)
        for fields, body in ((metadata, b"x"), (metadata + [(b"Content-Length", b"0")], b""),
                (metadata + [(b"Transfer-Encoding", b"chunked")], b""),
                (metadata + [(b"Content-Type", b"text/plain")], b"")):
            self.assertFalse(self.admit(self.flow(fields, body, 204)).allowed)
        old_route = fx.compile_snapshot().routes[0]
        self.assertFalse(self.admit(self.flow([(b"Content-Type", b"application/json"),
            (b"Server", b"fixture")], route=old_route), old_route).allowed)

    def test_all_header_reflection_before_discard_and_missing_guard_refuse(self):
        for fields in (
            [(b"X-Unselected", SECRET.encode())],
            [(b"X-" + SECRET.encode(), b"safe")],
            [(b"X-Unselected", base64.b64encode(SECRET.encode()))],
            [(b"X-Unselected", b"safe"), (b"x-unselected", SECRET.encode())],
        ):
            flow = self.flow(fields, b"", 204)
            decision = self.admit(flow)
            self.assertFalse(decision.allowed)
            self.assertEqual(decision.payload["error"], "response_credential_reflection")
            self.assertNotIn(SECRET, json.dumps(decision.payload))
            self.assertNotIn("X-Unselected", json.dumps(decision.payload))
        flow = self.flow([], b"", 204, guarded=False)
        decision = self.engine._evaluate_response_envelope(flow, self.route)
        self.assertEqual(decision.payload["error"], "response_metadata_guard_unavailable")
        flow = self.flow([(b"Content-Type", b"application/json")])
        guard = self.engine._take_response_credential_guard(flow)
        self.assertTrue(self.engine._evaluate_response_envelope(flow, self.route, credential_guard=guard).allowed)
        guard.clear()

    def test_missing_physical_evidence_and_legacy_transport_fail_closed(self):
        flow = self.flow([], b"", 204)
        # A mapping cannot attest that duplicate physical occurrences survived.
        from types import SimpleNamespace
        flow.response = SimpleNamespace(headers={}, raw_content=b"", status_code=204)
        self.assertEqual(self.engine._evaluate_response_envelope(flow, self.route).payload["error"],
            "response_metadata_evidence_unavailable")
        self.assertFalse(self.adapter.prepare_response(flow, self.route, {}).allowed)
        route = replace(self.route, credential_ref=None, credential_header=None, resolved_cidrs=None)
        flow = fx.request_flow(b"")
        flow.metadata[self.engine.LEGACY_MITM_TRANSPORT_METADATA_KEY] = True
        decision = self.engine._legacy_mitm_route_admission(flow, route)
        self.assertEqual(decision.status_code, 503)
        self.assertEqual(decision.payload["error"], "python_json_or_empty_204_transport_unsupported")
        old_route = replace(fx.compile_snapshot(fx.document(new_response=False)).routes[0],
            credential_ref=None, credential_header=None, resolved_cidrs=None)
        self.assertIsNone(self.engine._legacy_mitm_route_admission(flow, old_route))


if __name__ == "__main__":
    unittest.main()
