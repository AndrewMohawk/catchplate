#!/usr/bin/env python3
"""Offline X app-read normalizer/compiler/response controls, not forwarding.

Uses the existing parsed-field fixture (annotation-only mitmproxy import stub
when absent), not an HTTP parser. No store, provider or SDK is contacted. The
legacy Python MITM transport remains denied for exact credential replacement;
real replacement/framing belongs to the separately executed Rust lane.
"""
from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
# Module import only; its suites are not executed/discovered here. The existing
# fixture installs a socket/SQLite-denying audit hook and preserves raw pairs.
import test_npm_metadata as parsed
from catchplate import adapters, policy_bundle as pb, policy_engine as engine
from catchplate import policy_route_authority as authority, x_app_read as x

VECTORS = json.loads((ROOT / "scripts/fixtures/x_app_read_v1.json").read_text())
SECRET = "synthetic-x-private-token-NEVER-RELEASE"


def document():
    return {"apiVersion": "catchplate.policy/v1", "kind": "PolicyBundle",
        "metadata": {"id": "x-app-read-test", "sequence": 1, "rollbackEpoch": 1},
        "defaults": {"action": "deny", "failMode": "closed", "unknownHosts": "block",
            "unknownPaths": "block", "validationFailure": "block"},
        "principals": [{"id": "agent:fixture", "sourceCidrs": ["127.0.0.1/32"],
            "requiredHeaders": {"X-Catchplate-Agent": "fixture"}}],
        "credentials": [{"id": "credential:fixture", "credentialType": "static",
            "provider": "operator-demo", "providerSubject": "synthetic-x-subject",
            "injection": {"type": "bearer", "header": "Authorization"}}],
        "routes": [{"id": "route.x-fixture", "principals": ["agent:fixture"],
            "credentialRef": "credential:fixture", "credentialHeader": deepcopy(VECTORS["replacement"]),
            "match": {"scheme": "https", "host": "api.x.com", "port": 443,
                "methods": ["GET"], "paths": ["/2/users/by/username/fixture_user"]},
            "adapter": {"type": "x.app_read.v1", "config": {"credentialBinding": deepcopy(VECTORS["credentialBinding"]),
                "username": VECTORS["username"], "request": deepcopy(VECTORS["request"]),
                "response": deepcopy(VECTORS["response"])}},
            "constraints": [{"id": "fixture.x-response", "type": "responseEnvelope", "phase": "response",
                "statusCodes": [200, 400, 401, 403, 404, 429, 500, 502, 503, 504], "bodyPresence": "required",
                "contentTypes": ["application/json"], "allowedResponseHeaderNames": [], "responseHeaderRules": [],
                "unlistedHeaderPolicy": "discardUnselectedV1", "contentTypePolicy": "xAppReadJsonUtf8V1"}]}]}


def flow(*, url=None, method="GET", body=b"", headers=()):
    return parsed.request(VECTORS["url"] if url is None else url, method=method, body=body, headers=headers)


class XAppReadTests(unittest.TestCase):
    def setUp(self):
        self.snapshot = pb.compile_policy_bundle(document())
        self.route = self.snapshot.routes[0]
        self.adapter = adapters.get_adapter("x.app_read.v1")

    def response(self, body=b'{"data":{"id":"123","username":"fixture_user"}}', *,
            status=200, media=b"application/json", headers=(), guard=True):
        value = flow()
        value.response = SimpleNamespace(status_code=status, raw_content=body, content=body, trailers=None,
            headers=parsed.ParsedHeaders(([(b"Content-Type", media)] if media is not None else []) + list(headers)))
        value.metadata.update(catchplate_route=self.route, catchplate_operation=dict(VECTORS["operation"]))
        if guard:
            checker = engine._ResponseCredentialGuard()
            checker.add_text_encodings(SECRET)
            engine._install_response_credential_guard(value, checker)
        return value

    def admit_response(self, value):
        for callback in (lambda: engine._validate_response_content_encoding(value),
                lambda: engine._evaluate_response_envelope(value, self.route),
                lambda: self.adapter.prepare_response(value, self.route, {}),
                lambda: self.adapter.validate_response(value, self.route, {})):
            result = callback()
            if not result.allowed: return result
        return result

    def test_independent_profiles_embedded_schema_and_v1_v2_compilation(self):
        self.assertEqual(x.request_profile(), VECTORS["request"])
        self.assertEqual(x.response_profile(), VECTORS["response"])
        self.assertEqual(x.response_envelope("fixture.x-response"), document()["routes"][0]["constraints"][0])
        schema = json.loads((ROOT / "schemas/adapters/x.app_read.v1.schema.json").read_text())
        self.assertIsInstance(schema.get("$defs"), dict)
        self.assertTrue(schema["$defs"], "real local definitions required by embedded loader")
        self.assertIs(schema["additionalProperties"], False)
        self.assertEqual(set(schema["required"]), {"credentialBinding", "username", "request", "response"})
        self.assertEqual(set(schema["properties"]), set(schema["required"]))
        for schema_validation in (True, False):
            snapshot = pb.compile_policy_bundle(document(), validate_schema=schema_validation)
            x.validate_route(snapshot.routes[0])
            v2 = document()
            v2["apiVersion"] = "catchplate.policy/v2"
            pb.compile_policy_bundle(authority.prepare_unsigned(v2, []), validate_schema=schema_validation)
        self.assertEqual(authority._builtin("x.app_read.v1", "x.username.read"), "read")
        self.assertEqual(pb.adapter_operation_field_names("x.app_read.v1", "x.username.read"),
            frozenset({"operation", "username"}))
        changed = document()
        changed["routes"][0]["adapter"]["config"]["username"] = "different"
        changed["routes"][0]["match"]["paths"] = ["/2/users/by/username/different"]
        self.assertNotEqual(pb.compile_policy_bundle(changed).hash, self.snapshot.hash)

    def test_signed_transport_dummy_binding_and_profiles_cannot_be_widened(self):
        mutations = [lambda r: r["match"].update(host="api.twitter.com"), lambda r: r["match"].update(scheme="http"),
            lambda r: r["match"].update(port=443.0), lambda r: r["match"].update(methods=["GET", "POST"]),
            lambda r: r["match"].update(paths=["/2/users/by/username/{username}"]),
            lambda r: r.update(jit={}), lambda r: r.update(responseObservation={}),
            lambda r: r.pop("credentialHeader"), lambda r: r["credentialHeader"].update(expectedValue="Bearer other"),
            lambda r: r["credentialHeader"].update(mode="insert"),
            lambda r: r["adapter"]["config"]["credentialBinding"].update(provider="x"),
            lambda r: r["adapter"]["config"]["credentialBinding"].update(subjects=["different"]),
            lambda r: r["adapter"]["config"]["request"].update(maxBodyBytes=False),
            lambda r: r["adapter"]["config"]["request"].update(maxBodyBytes=0.0),
            lambda r: r["adapter"]["config"]["request"].update(allowedQueryKeys=["user.fields"]),
            lambda r: r["adapter"]["config"]["request"].update(allowedMediaTypes=[]),
            lambda r: r["adapter"]["config"]["response"].update(maxBodyBytes=1048576.0),
            lambda r: r["adapter"]["config"]["response"].update(allowedHeaders=["etag"]),
            lambda r: r["constraints"][0].update(statusCodes=[200.0, 400, 401, 403, 404, 429, 500, 502, 503, 504]),
            lambda r: r["constraints"][0].update(contentTypePolicy="npmJsonUtf8V1")]
        for validate_schema in (True, False):
            for index, mutate in enumerate(mutations):
                value = document()
                mutate(value["routes"][0])
                with self.subTest(index=index, schema=validate_schema), self.assertRaises(pb.PolicyBundleError):
                    pb.compile_policy_bundle(value, validate_schema=validate_schema)
        value = document()
        value["credentials"][0].update(credentialType="oauth2", provider="x")
        with self.assertRaises(pb.PolicyBundleError): pb.compile_policy_bundle(value)

    def test_username_token_and_subject_bounds_are_closed_and_secret_safe(self):
        for username in ("a", "_", "a0_", "a" * 15): self.assertEqual(x.validate_username(username), username)
        for username in (None, True, "", "a" * 16, "UPPER", "a-b", "a.b", "a/b", "a%2fb", "a\n", "é"):
            with self.assertRaises(ValueError): x.validate_username(username)
        for token in ("opaque", "opaque%2F+_=/", "x" * 8192): self.assertEqual(x.validate_token(token), token)
        for token in ("", None, "x" * 8193, "private value", "private\nvalue", "é"):
            with self.assertRaises(ValueError) as raised: x.validate_token(token)
            if token: self.assertNotIn(token, str(raised.exception))
        for subject in ("", " padded", "padded ", "bad\x00subject", "é" * 257):
            config = deepcopy(self.route.adapter_config)
            config["credentialBinding"]["subjects"] = [subject]
            with self.assertRaises(ValueError): x.validate_config(config)

    def test_normalizer_is_literal_and_has_no_request_or_route_mutation(self):
        before = deepcopy(self.route.adapter_config)
        for row in VECTORS["requests"]:
            if row["allowed"]:
                self.assertEqual(x.validate_request(row["method"], row["url"], row["body"].encode(),
                    username=VECTORS["username"], headers={key.lower(): value for key, value in row["headers"]}), "fixture_user")
        for target in ("http://api.x.com/2/users/by/username/fixture_user", VECTORS["url"] + "/..",
                VECTORS["url"].replace("api.x.com", "API.X.COM"), VECTORS["url"].replace("api.x.com", "user@api.x.com"),
                VECTORS["url"].replace("api.x.com", "api.x.com."), VECTORS["url"].replace("fixture_user", "%2566ixture_user")):
            with self.assertRaises(ValueError): x.validate_request("GET", target, b"", username="fixture_user")
        self.assertEqual(self.route.adapter_config, before)

    def test_shared_request_vectors_reach_actual_adapter_and_exact_operation(self):
        for row in VECTORS["requests"]:
            with self.subTest(case=row["id"]):
                value = flow(url=row["url"], method=row["method"], body=row["body"].encode(),
                    headers=[(name.encode(), item.encode()) for name, item in row["headers"]])
                original = (value.request.pretty_url, value.request.raw_content, value.request.headers.fields)
                self.assertEqual(self.adapter.validate_request(value, self.route, {}).allowed, row["allowed"])
                if row["allowed"]:
                    self.assertEqual(self.adapter.operation_fields(value, self.route, {}), VECTORS["operation"])
                    self.assertTrue(self.adapter.rewrite_request(value, self.route, {}).allowed)
                self.assertEqual((value.request.pretty_url, value.request.raw_content, value.request.headers.fields), original)
        self.assertFalse(self.adapter.validate_request(flow(), self.route, {"username": "fixture_user"}).allowed)

    def test_bodyless_json_header_and_discard_commitment_use_actual_engine_functions(self):
        value = flow(headers=[(b"Content-Type", b"application/json; charset=utf-8"),
            (b"Accept", b"application/json"), (b"Accept-Encoding", b"gzip, deflate"),
            (b"X-Catchplate-Agent", b"fixture")])
        principal = self.snapshot.principals["agent:fixture"]
        credential = self.snapshot.credentials[self.route.credential_ref]
        self.assertTrue(adapters.preflight_request_admission(value, self.route, engine._normalized_request_headers(value)).allowed)
        discarded = engine._discard_declared_request_headers(value, self.route, principal, credential)
        engine._strip_identity_headers(value, principal)
        self.assertNotIn("accept-encoding", value.request.headers)
        self.assertTrue(self.adapter.validate_request(value, self.route, {}).allowed)
        canonical = engine._canonical_request(value, principal=principal, route=self.route,
            credential_version="1", policy_hash=self.snapshot.hash, operation_fields=VECTORS["operation"],
            forwarded_headers=engine._canonical_forwarded_request_headers(value, credential, route=self.route), discard_headers=discarded)
        self.assertIn("x.username.read", json.dumps(canonical))
        self.assertNotIn("gzip, deflate", json.dumps(canonical))
        self.assertEqual(value.request.raw_content, b"")

    def test_shared_response_vectors_preserve_whole_bytes_not_lookup_success(self):
        for row in VECTORS["responses"]:
            with self.subTest(case=row["id"]):
                body = row["body"].encode("utf-8")
                value = self.response(body, status=row["status"], media=row["content_type"].encode())
                self.assertEqual(self.admit_response(value).allowed, row["allowed"])
                if row["allowed"]:
                    self.assertEqual(value.response.raw_content, body)
                    self.assertEqual(set(value.response.headers), {"content-type", "content-length"})
                    self.assertEqual(value.response.headers["content-type"], "application/json")

    def test_status_and_exact_response_byte_bounds(self):
        for status in (200, 400, 401, 403, 404, 429, 500, 502, 503, 504):
            self.assertTrue(self.admit_response(self.response(b'{"arbitrary":"object"}', status=status)).allowed)
        for status in (201, 204, 206, 301, 418, 501):
            self.assertFalse(self.admit_response(self.response(status=status)).allowed)
        for status, maximum in ((200, 1048576), (404, 65536)):
            body = b'{"x":"' + b"a" * (maximum - 8) + b'"}'
            self.assertEqual(len(body), maximum)
            self.assertTrue(self.admit_response(self.response(body, status=status)).allowed)
            self.assertFalse(self.admit_response(self.response(body + b" ", status=status)).allowed)

    def test_strict_json_invalid_utf8_depth_and_trailing_content_refuse(self):
        for body in (b"", b"\xef\xbb\xbf{}", b'{"x":"\xff"}', b"{} trailing",
                b'{"x":' + b"[" * 128 + b"0" + b"]" * 128 + b"}", b'{"x":Infinity}'):
            with self.subTest(body=body[:32]): self.assertFalse(self.admit_response(self.response(body)).allowed)

    def test_guard_rejects_raw_decoded_and_discarded_header_secret_reflection(self):
        bodies = [json.dumps({"x": SECRET}).encode(),
            ('{"x":"' + "".join("\\u%04x" % ord(char) for char in SECRET) + '"}').encode()]
        for body in bodies: self.assertFalse(self.admit_response(self.response(body)).allowed)
        for fields in ([(b"X-Metadata", SECRET.encode())],
                [(b"X-Metadata", b"safe"), (b"x-metadata", SECRET.encode())]):
            self.assertFalse(self.admit_response(self.response(headers=fields)).allowed)
        self.assertFalse(self.admit_response(self.response(guard=False)).allowed)

    def test_response_media_and_bounded_unselected_metadata_are_not_general_plus_json(self):
        value = self.response(headers=[(b"X-Cache", b"one"), (b"x-cache", b"two")])
        self.assertTrue(self.admit_response(value).allowed)
        self.assertNotIn("x-cache", value.response.headers)
        for media in (None, b"text/html", b"application/vnd.npm.install-v1+json", b'application/json;charset="utf-8"'):
            self.assertFalse(self.admit_response(self.response(media=media)).allowed)
        for headers in ([(b"Content-Type", b"application/json")], [(b"Content-Encoding", b"gzip")],
                [(b"Set-Cookie", b"x=y")], [(b"X-Catchplate-Internal", b"synthetic")],
                [(b"Content-Length", b"1"), (b"content-length", b"1")], [(b"X-Large", b"x" * 8193)]):
            self.assertFalse(self.admit_response(self.response(headers=headers)).allowed)

    def test_unknown_duplicate_request_headers_and_wrong_media_refuse(self):
        for headers in ([(b"X-Unknown", b"synthetic")], [(b"User-Agent", b"a"), (b"user-agent", b"a")],
                [(b"Accept-Language", b"en")], [(b"Content-Type", b"application/json; foo=bar")]):
            self.assertFalse(self.adapter.validate_request(flow(headers=headers), self.route, {}).allowed)
        for media in ("application/json", "APPLICATION/JSON;charset=UTF-8", "application/json;\tcharset=utf-8"):
            self.assertTrue(x.is_json_content_type(media))
        for media in ("application/problem+json", "application/json ", " application/json", "application/json\n", None):
            self.assertFalse(x.is_json_content_type(media))

    def test_no_legacy_oauth_generic_or_python_transport_widening(self):
        denial = engine._legacy_mitm_route_admission(flow(), self.route)
        self.assertEqual((denial.status_code, denial.payload["error"]),
            (503, "python_credential_header_replacement_unsupported"))
        for adapter in ("generic.rest", "x.v2", "npm.metadata.v1"):
            with self.assertRaises(pb.PolicyBundleError):
                pb.validate_buffered_passthrough_response("fixture", adapter, VECTORS["response"])
        self.assertNotEqual(type(adapters.get_adapter("x.v2")), type(self.adapter))
        with self.assertRaises(ValueError): x.validate_route(replace(self.route, adapter_type="x.v2"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
