#!/usr/bin/env python3
"""Bounded buffered JSON policy/compiler/adapter checks, without live services.

Uses actual module imports, schema validation, strict JSON and mitmproxy response
objects. New-mode release preserves the exact validated input body bytes.
Policies are unsigned local fixtures: these tests do not establish
signature, Rust transport, credential-reflection or production acceptance.
Python forwarding remains a credentialless prototype. Credential-bearing
policy fixtures here exercise compilation and isolated adapters only, never
credential forwarding or decoded credential-inspection hooks.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from mitmproxy import http
from serverware import adapters, policy_engine
from serverware.policy_bundle import PolicyBundleError, compile_policy_bundle


def normalized_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False, allow_nan=False).encode("utf-8")


def passthrough(maximum=1024, *, error=False):
    result = {"mode": "bufferedPassthrough", "bodyFormat": "json",
        "maxBodyBytes": maximum, "contentTypes": ["application/json"], "allowedHeaders": []}
    if error:
        result["onInvalid"] = "block"
    else:
        result["error"] = passthrough(min(maximum, 65536), error=True)
    return result


def projected():
    return {"mode": "json", "maxBodyBytes": 1024, "contentTypes": ["application/json"],
        "allowedFields": ["keep"], "allowedHeaders": [], "error": {"mode": "json",
            "maxBodyBytes": 1024, "allowedFields": ["error"], "allowedHeaders": [], "onInvalid": "block"}}


def bundle(response=None):
    return {"apiVersion": "serverware.policy/v1", "kind": "PolicyBundle",
        "metadata": {"id": "buffered-json-test", "sequence": 1, "rollbackEpoch": 1},
        "defaults": {"action": "deny", "failMode": "closed", "unknownHosts": "block",
            "unknownPaths": "block", "validationFailure": "block"},
        "principals": [{"id": "agent:buffered-fixture", "sourceCidrs": ["127.0.0.1/32"],
            "requiredHeaders": {"X-Serverware-Agent": "buffered-fixture"}}],
        "credentials": [{"id": "credential:buffered-fixture", "credentialType": "static",
            "provider": "fixture", "providerSubject": "fixture-subject",
            "injection": {"type": "bearer", "header": "Authorization"}}],
        "routes": [{"id": "route.buffered-fixture", "principals": ["agent:buffered-fixture"],
            "credentialRef": "credential:buffered-fixture",
            "match": {"scheme": "https", "host": "api.example.com", "port": 443,
                "methods": ["GET"], "paths": ["/fixture"]},
            "adapter": {"type": "generic.rest", "config": {
                "credentialMode": "required", "credentialBinding": {"credentialType": "static",
                    "provider": "fixture", "subjects": ["fixture-subject"], "secretClass": "bearerToken"},
                "request": {"allowedHeaders": [], "allowedQueryKeys": [], "allowedMediaTypes": [],
                    "bodyMode": "none", "maxBodyBytes": 0, "valueRules": [],
                    "operation": {"name": "fixture.read"}},
                "response": passthrough() if response is None else copy.deepcopy(response)}},
            "constraints": [{"id": "fixture.response", "type": "responseEnvelope", "phase": "response",
                "statusCodes": [200, 400, 404, 429, 500], "bodyPresence": "required",
                "contentTypes": ["application/json"], "allowedResponseHeaderNames": [], "responseHeaderRules": []}]}]}


def response_config(document):
    return document["routes"][0]["adapter"]["config"]["response"]


def compile_route(document):
    return compile_policy_bundle(document, validate_schema=True).routes[0]


def flow(body, *, status=200, fields=None):
    if fields is None:
        fields = [(b"Content-Type", b"application/json")]
    response = http.Response.make(status, b"")
    # Response.make assigns decoded content and may remove encodings it cannot
    # produce. Attach physical fields afterward, then raw bytes, so test setup
    # cannot remove the malformed upstream headers this suite must reject.
    response.headers = http.Headers(fields)
    response.raw_content = body
    return SimpleNamespace(response=response, request=SimpleNamespace(method="GET"),
        metadata={"serverware_operation": {"operation": "fixture.read"}})


class BufferedPassthroughResponseTests(unittest.TestCase):
    def setUp(self):
        self.adapter = adapters.get_adapter("generic.rest")

    def assert_denied(self, route, value, *, status=200, fields=None):
        sample = flow(value, status=status, fields=fields)
        decision = self.adapter.validate_response(sample, route, {})
        self.assertFalse(decision.allowed, "invalid buffered response was released")
        self.assertEqual(decision.status_code, 502)
        return decision

    def test_exact_paired_contract_compiles_and_is_not_projection(self):
        route = compile_route(bundle())
        config = route.adapter_config["response"]
        self.assertEqual(config["mode"], "bufferedPassthrough")
        self.assertEqual(config["bodyFormat"], "json")
        self.assertNotIn("allowedFields", config)
        self.assertNotIn("allowedFields", config["error"])
        self.assertEqual(config["error"]["mode"], "bufferedPassthrough")

    def test_full_nested_objects_arrays_and_scalars_survive_success_and_error(self):
        route = compile_route(bundle())
        values = ({"keep": 1, "extra": {"deep": [True, None, {"unprojected": "value"}]}},
            [{"not_an_allowlisted_field": 3}, [False, None]], "text", "caf\u00e9", 0, 7, 1.25, True, False, None)
        for status in (200, 400, 500):
            for value in values:
                with self.subTest(status=status, value_type=type(value).__name__):
                    raw = (" \n" + json.dumps(value, ensure_ascii=False) + "\t").encode()
                    sample = flow(raw, status=status, fields=[(b"Content-Type", b"application/json"),
                        (b"Set-Cookie", b"fixture=not-released"), (b"X-Upstream-Private", b"not-released")])
                    self.assertTrue(self.adapter.prepare_response(sample, route, {}).allowed)
                    decision = self.adapter.validate_response(sample, route, {})
                    self.assertTrue(decision.allowed, decision)
                    self.assertEqual(json.loads(sample.response.raw_content), value)
                    self.assertEqual(sample.response.raw_content, raw)
                    self.assertEqual(dict(sample.response.headers), {"Content-Type": "application/json",
                        "Content-Length": str(len(sample.response.raw_content))})

    def test_exact_wire_bytes_preserve_large_numbers_spelling_whitespace_and_escapes(self):
        route = compile_route(bundle())
        bodies = (b"18446744073709551617", b'{"id":18446744073709551617}',
            b"1e2", b"1e+02", b"1.2300", b'"caf\\u00e9"',
            b'"\\ud83d\\ude00"', b'"\\u0061\\/b"',
            b' \n\t{"z": [1e2, 18446744073709551617], "a": "\\u0061"} \r\n')
        for status in (200, 400, 500):
            for raw in bodies:
                with self.subTest(status=status, raw=raw):
                    sample = flow(raw, status=status)
                    self.assertTrue(self.adapter.prepare_response(sample, route, {}).allowed)
                    decision = self.adapter.validate_response(sample, route, {})
                    self.assertTrue(decision.allowed, decision)
                    self.assertEqual(sample.response.raw_content, raw)
                    self.assertEqual(sample.response.headers["Content-Length"], str(len(raw)))

    def test_raw_and_inspection_limits_apply_independently_on_both_profiles(self):
        numeric_raw = b"1e2"
        inspection = normalized_json(json.loads(numeric_raw))
        self.assertEqual(inspection, b"100.0")
        self.assertGreater(len(inspection), len(numeric_raw))
        for status in (200, 400):
            with self.subTest(status=status):
                # Raw input fits, but normalized inspection representation does not.
                denied = self.assert_denied(compile_route(bundle(passthrough(len(numeric_raw)))),
                    numeric_raw, status=status)
                self.assertEqual(denied.payload["error"], "response_inspection_body_too_large")
                # Inspection representation fits, but raw input with padding does not.
                padded_raw = b'  {"n":1}  '
                denied = self.assert_denied(compile_route(bundle(passthrough(7))), padded_raw, status=status)
                self.assertEqual(denied.payload["error"], "response_body_too_large")
                exact = flow(numeric_raw, status=status)
                decision = self.adapter.validate_response(exact,
                    compile_route(bundle(passthrough(len(inspection)))), {})
                self.assertTrue(decision.allowed, decision)
                self.assertEqual(exact.response.raw_content, numeric_raw)
                exact_raw = flow(padded_raw, status=status)
                decision = self.adapter.validate_response(exact_raw,
                    compile_route(bundle(passthrough(len(padded_raw)))), {})
                self.assertTrue(decision.allowed, decision)
                self.assertEqual(exact_raw.response.raw_content, padded_raw)

    def test_malformed_duplicate_nonfinite_and_invalid_unicode_json_deny(self):
        route = compile_route(bundle())
        invalid = (b"", b"{", b"[] trailing", b'{"a":1,"a":2}', b'{"n":{"a":1,"a":2}}',
            b"NaN", b"Infinity", b"-Infinity", b"1e999", b"-0", b'"\xff"', b'"\\ud800"', b'"raw\nnewline"')
        for status in (200, 400):
            for raw in invalid:
                with self.subTest(status=status, raw=raw):
                    self.assert_denied(route, raw, status=status)

    def test_json_content_type_is_closed(self):
        route = compile_route(bundle())
        for media_type in (b"application/json", b'Application/JSON; charset="utf-8"'):
            sample = flow(b"{}", fields=[(b"Content-Type", media_type)])
            self.assertTrue(self.adapter.validate_response(sample, route, {}).allowed)
        invalid_headers = ([], [(b"Content-Type", b"text/plain")],
            [(b"Content-Type", b"application/json;")],
            [(b"Content-Type", b"application/json; charset=utf-8; CHARSET=utf-8")],
            [(b"Content-Type", b"application/json"), (b"content-type", b"application/json")])
        for status in (200, 400):
            for fields in invalid_headers:
                with self.subTest(status=status, fields=fields):
                    self.assert_denied(route, b"{}", status=status, fields=fields)

    def test_real_engine_content_encoding_guard_precedes_adapter(self):
        route = compile_route(bundle())
        # This is the actual engine transport guard, tested separately from
        # adapter admission. Calling it here is not a full engine/HTTP replay.
        for status in (200, 400):
            for encodings in ([], [(b"Content-Encoding", b"identity")]):
                with self.subTest(status=status, accepted=encodings):
                    sample = flow(b"{}", status=status,
                        fields=[(b"Content-Type", b"application/json"), *encodings])
                    self.assertEqual(sample.response.headers.fields,
                        ((b"Content-Type", b"application/json"), *encodings))
                    self.assertTrue(policy_engine._validate_response_content_encoding(sample).allowed)
                    self.assertTrue(self.adapter.validate_response(sample, route, {}).allowed)
                    self.assertNotIn("content-encoding", sample.response.headers)
            for encodings in ([(b"Content-Encoding", b"gzip")], [(b"Content-Encoding", b"br")],
                    [(b"Content-Encoding", b"identity, identity")],
                    [(b"Content-Encoding", b"identity"), (b"content-encoding", b"identity")]):
                with self.subTest(status=status, denied=encodings):
                    sample = flow(b"{}", status=status,
                        fields=[(b"Content-Type", b"application/json"), *encodings])
                    self.assertEqual(sample.response.headers.fields,
                        ((b"Content-Type", b"application/json"), *encodings))
                    decision = policy_engine._validate_response_content_encoding(sample)
                    self.assertFalse(decision.allowed)
                    self.assertEqual(decision.status_code, 502)
                    self.assertEqual(decision.payload["error"], "response_content_encoding_denied")
                    self.assertEqual(sample.response.raw_content, b"{}")

    def test_redirects_and_unadmitted_error_statuses_do_not_release(self):
        route = compile_route(bundle())
        for status in (100, 302, 399, 418, 600):
            with self.subTest(status=status):
                self.assert_denied(route, b'{"whole":"body"}', status=status)

    def test_closed_format_projection_and_size_policy_controls(self):
        changes = ({"bodyFormat": "text"}, {"bodyFormat": None}, {"allowedFields": []},
            {"allowedFields": ["keep"]}, {"maxBodyBytes": 0}, {"maxBodyBytes": True},
            {"maxBodyBytes": 16777217}, {"contentTypes": []}, {"contentTypes": ["text/plain"]},
            {"contentTypes": ["application/json", "text/plain"]}, {"maxRecordBytes": 128},
            {"allowedHeaders": ["set-cookie"]}, {"unknown": True})
        for error in (False, True):
            for change in changes:
                with self.subTest(error=error, change=change):
                    document = bundle()
                    config = response_config(document)
                    selected = config["error"] if error else config
                    selected.update(change)
                    with self.assertRaises(PolicyBundleError):
                        compile_route(document)
            for missing in ("bodyFormat", "maxBodyBytes", "contentTypes", "allowedHeaders"):
                with self.subTest(error=error, missing=missing):
                    document = bundle()
                    config = response_config(document)
                    del (config["error"] if error else config)[missing]
                    with self.assertRaises(PolicyBundleError):
                        compile_route(document)
        for change in ({"maxBodyBytes": 65537}, {"onInvalid": "pass"}):
            document = bundle()
            response_config(document)["error"].update(change)
            with self.assertRaises(PolicyBundleError):
                compile_route(document)

    def test_new_and_old_success_error_profiles_cannot_mix(self):
        missing = bundle()
        del response_config(missing)["error"]
        new_old = bundle()
        response_config(new_old)["error"] = projected()["error"]
        old_new = bundle(projected())
        response_config(old_new)["error"] = passthrough(error=True)
        old_format = bundle(projected())
        response_config(old_format)["bodyFormat"] = "json"
        for index, document in enumerate((missing, new_old, old_new, old_format)):
            with self.subTest(case=index), self.assertRaises(PolicyBundleError):
                compile_route(document)

    def test_non_generic_adapters_refuse_mode_with_valid_old_profile_controls(self):
        examples = json.loads((ROOT / "policies/credential-limits.examples.json").read_text())
        for adapter_type in ("gmail.v1", "x.v2", "npm.registry"):
            document = copy.deepcopy(examples)
            selected = next(route for route in document["routes"] if route["adapter"]["type"] == adapter_type)
            document["routes"] = [selected]
            document["credentials"] = [item for item in document["credentials"] if item["id"] == selected["credentialRef"]]
            document["principals"] = [item for item in document["principals"] if item["id"] in selected["principals"]]
            with self.subTest(adapter=adapter_type):
                compile_route(document)
                selected["adapter"]["config"]["response"] = passthrough()
                with self.assertRaises(PolicyBundleError):
                    compile_route(document)

    def test_durable_claims_refuse_new_mode_with_valid_projected_control(self):
        document = bundle(projected())
        document["routes"][0]["constraints"].append({"id": "fixture.durable", "type": "slidingWindowLimit",
            "max": 5, "windowSeconds": 3600, "windowSemantics": "sliding", "measure": "operationCount",
            "reservationMode": "atomicReserveCommitRelease", "onOverflow": "deny", "store": "shared",
            "key": {"scope": ["route", "operation"], "operationFields": ["providerAccount"]}})
        compile_route(document)
        document["routes"][0]["adapter"]["config"]["response"] = passthrough()
        with self.assertRaises(PolicyBundleError):
            compile_route(document)

    def test_existing_projected_json_and_headers_only_behavior_is_unchanged(self):
        route = compile_route(bundle(projected()))
        for status, expected in ((200, {"keep": 1}), (400, {"error": "retained"})):
            sample = flow(b'{"keep":1,"error":"retained","extra":{"not":"released"}}', status=status)
            self.assertTrue(self.adapter.validate_response(sample, route, {}).allowed)
            self.assertEqual(json.loads(sample.response.raw_content), expected)
        document = bundle(projected())
        config = response_config(document)
        config.update(mode="headersOnly", maxBodyBytes=0, contentTypes=[])
        config.pop("allowedFields")
        envelope = document["routes"][0]["constraints"][0]
        envelope.update(statusCodes=[204], bodyPresence="forbidden", contentTypes=[])
        route = compile_route(document)
        sample = flow(b"", status=204, fields=[])
        self.assertTrue(self.adapter.validate_response(sample, route, {}).allowed)
        self.assertEqual(sample.response.raw_content, b"")
        self.assertNotIn("content-type", sample.response.headers)


if __name__ == "__main__":
    unittest.main(verbosity=2)
