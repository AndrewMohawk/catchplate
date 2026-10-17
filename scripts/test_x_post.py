#!/usr/bin/env python3
"""Offline X post compiler/parsed-field guards; not OAuth or posting acceptance.

The shared fixture blocks sockets and SQLite before importing the real compiler,
adapter and engine. Its mitmproxy stub supplies annotations only. Audit output
is collected in memory; no token, grant, quota consumption or dispatch occurs.
"""
from copy import deepcopy
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import test_npm_metadata as parsed
from catchplate import adapters, policy_bundle as pb, policy_engine as engine
from catchplate import policy_route_authority as authority, x_post as post

VECTORS = json.loads((ROOT / "scripts/fixtures/x_post_v1.json").read_text())
BODY = b'{ "text" : "synthetic private request text" }'
SECRET = "synthetic-private-X-token-NEVER-RELEASE"


def document(quota=False):
    return {"apiVersion": "catchplate.policy/v1", "kind": "PolicyBundle",
        "metadata": {"id": "x-post-test", "sequence": 1, "rollbackEpoch": 1},
        "defaults": {"action": "deny", "failMode": "closed", "unknownHosts": "block",
            "unknownPaths": "block", "validationFailure": "block"},
        "principals": [{"id": "agent:fixture", "sourceCidrs": ["127.0.0.1/32"],
            "requiredHeaders": {"X-Catchplate-Agent": "fixture"}}],
        "credentials": [{"id": "credential:fixture", "credentialType": "oauth2", "provider": "x",
            "providerSubject": "fixture-x-account", "oauthClientId": "fixture-x-client",
            "scopes": ["offline.access", "tweet.read", "tweet.write", "users.read"],
            "injection": {"type": "bearer", "header": "Authorization", "field": "access_token"}}],
        "routes": [{"id": "route.x-post", "principals": ["agent:fixture"],
            "credentialRef": "credential:fixture", "credentialHeader": deepcopy(VECTORS["replacement"]),
            "match": {"scheme": "https", "host": "api.x.com", "port": 443,
                "methods": ["POST"], "paths": ["/2/tweets"]},
            "adapter": {"type": "x.post.v1", "config": {key: deepcopy(VECTORS[key])
                for key in ("credentialBinding", "request", "response")}},
            "constraints": [{"id": "fixture.x-post-response", "type": "responseEnvelope", "phase": "response",
                "statusCodes": [201, 400, 401, 402, 403, 404, 408, 409, 422, 429, 500, 502, 503, 504],
                "bodyPresence": "required", "contentTypes": ["application/json"],
                "allowedResponseHeaderNames": [], "responseHeaderRules": [],
                "unlistedHeaderPolicy": "discardUnselectedV1", "contentTypePolicy": "xPostJsonUtf8V1"}]
                + ([deepcopy(VECTORS["quota"])] if quota else [])}]}


def flow(body=BODY, *, method="POST", url=VECTORS["url"], headers=None):
    return parsed.request(url, method=method, body=body,
        headers=[(b"Content-Type", b"application/json")] if headers is None else headers)


class XPostTests(unittest.TestCase):
    def setUp(self):
        self.snapshot = pb.compile_policy_bundle(document())
        self.route = self.snapshot.routes[0]
        self.adapter = adapters.get_adapter(post.ADAPTER)
        self.audit = []
        sink = patch.object(engine.runtime, "log_request", side_effect=lambda *a, **k: self.audit.append((a, k)))
        sink.start()
        self.addCleanup(sink.stop)

    def response(self, body=b'{"data":{"id":"123","text":"hello"}}', *, status=201,
            media=b"application/json", headers=(), guarded=True):
        value = flow()
        value.response = SimpleNamespace(status_code=status, raw_content=body, content=body, trailers=None,
            headers=parsed.ParsedHeaders(([(b"Content-Type", media)] if media is not None else []) + list(headers)))
        value.metadata.update(catchplate_route=self.route, catchplate_route_id=self.route.id,
            catchplate_policy_hash=self.snapshot.hash, catchplate_operation={"operation": "tweets.write"})
        if guarded:
            guard = engine._ResponseCredentialGuard()
            guard.add_text_encodings(SECRET)
            engine._install_response_credential_guard(value, guard)
        self.addCleanup(engine.discard_response_guards, value)
        return value

    def release(self, value):
        for stage in (engine.prepare_response, engine.evaluate_response, engine.validate_response_completion):
            decision = stage(value)
            if not decision.allowed:
                return decision
        return decision

    def test_independent_profiles_schema_v1_v2_and_write_classification(self):
        self.assertEqual(post.request_profile(), VECTORS["request"])
        self.assertEqual(post.response_profile(), VECTORS["response"])
        self.assertEqual(post.quota_constraint(50), VECTORS["quota"])
        self.assertEqual(post.response_envelope("fixture.x-post-response"), document()["routes"][0]["constraints"][0])
        schema = json.loads((ROOT / "schemas/adapters/x.post.v1.schema.json").read_text())
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(set(schema["properties"]), {"credentialBinding", "request", "response"})
        self.assertTrue(schema["$defs"])
        for quota in (False, True):
            for validate_schema in (False, True):
                raw = document(quota)
                compiled = pb.compile_policy_bundle(raw, validate_schema=validate_schema)
                post.validate_route(compiled.routes[0])
                raw["apiVersion"] = "catchplate.policy/v2"
                v2 = authority.prepare_unsigned(raw, [])
                pb.compile_policy_bundle(v2, validate_schema=validate_schema)
                self.assertEqual(authority.admit(v2)["mapping"]["profiles"][0]["profile"]["operations"],
                    [{"operationName": "tweets.write", "operation": "write", "requestAuthorityClass": "write"}])
        self.assertEqual(pb.adapter_operation_field_names(post.ADAPTER, post.OPERATION), frozenset({"operation"}))
        self.assertIsNone(authority._builtin(post.ADAPTER, "tweets.read"))

    def test_compiler_oauth_exact_binding_and_closed_transport(self):
        cases = [lambda r: r["match"].update(host="api.twitter.com"),
            lambda r: r["match"].update(methods=["GET", "POST"]),
            lambda r: r["match"].update(paths=["/2/{resource}"]),
            lambda r: r["match"].update(scheme="http"), lambda r: r["match"].update(port=443.0),
            lambda r: r.pop("credentialHeader"), lambda r: r["credentialHeader"].update(expectedValue="Bearer other"),
            lambda r: r.update(jit={}), lambda r: r.update(responseObservation={}),
            lambda r: r["adapter"]["config"].update(mode="controlledWrite"),
            lambda r: r["adapter"]["config"]["request"].update(maxBodyBytes=32768.0),
            lambda r: r["adapter"]["config"]["request"].update(allowedQueryKeys=["x"]),
            lambda r: r["adapter"]["config"]["credentialBinding"].update(requiredScopes=["tweet.write"]),
            lambda r: r["adapter"]["config"]["credentialBinding"].update(subjects=["other"]),
            lambda r: r["adapter"]["config"]["credentialBinding"].update(clientIds=["other"]),
            lambda r: r["constraints"][0].update(id=post.QUOTA_ID),
            lambda r: r["constraints"].append({"id": "extra", "type": "jsonBody", "phase": "request"})]
        for schema in (False, True):
            for index, mutate in enumerate(cases):
                raw = document()
                mutate(raw["routes"][0])
                with self.subTest(index=index, schema=schema), self.assertRaises(pb.PolicyBundleError):
                    pb.compile_policy_bundle(raw, validate_schema=schema)
        for changes in ({"provider": "google"}, {"providerSubject": "different"},
                {"oauthClientId": "different"}, {"scopes": ["tweet.read"]},
                {"injection": {"type": "bearer", "header": "Authorization"}}):
            raw = document()
            raw["credentials"][0].update(changes)
            with self.assertRaises(pb.PolicyBundleError): pb.compile_policy_bundle(raw)
        raw = document()
        raw["credentials"][0]["scopes"].append("users.email")
        pb.compile_policy_bundle(raw)  # Extra credential scope does not broaden the fixed route.

    def test_shared_request_vectors_and_unchanged_original_bytes(self):
        for row in VECTORS["requests"]:
            with self.subTest(case=row["id"]):
                value = flow(row["body"].encode(), method=row["method"], url=row["url"],
                    headers=[(key.encode(), item.encode()) for key, item in row["headers"]])
                original = (value.request.raw_content, value.request.pretty_url, value.request.headers.fields)
                self.assertEqual(self.adapter.validate_request(value, self.route, {}).allowed, row["allowed"])
                if row["allowed"]:
                    self.assertEqual(self.adapter.operation_fields(value, self.route, {}), VECTORS["operation"])
                    self.assertTrue(self.adapter.rewrite_request(value, self.route, {}).allowed)
                self.assertEqual((value.request.raw_content, value.request.pretty_url, value.request.headers.fields), original)

    def test_actual_runtime_oauth_binding_refuses_unverified_or_contradictory_metadata(self):
        policy = self.snapshot.credentials[self.route.credential_ref]
        # Synthetic stored metadata, not an admitted OAuth grant. Exercise the
        # real existing runtime validator without a store, lease or refresh.
        credential = {"kind": "oauth2", "metadata": {"oauth": True,
            "provider_identity_verified": True, "provider_id": "x",
            "provider_subject": "fixture-x-account", "oauth_client_id": "fixture-x-client",
            "scopes": ["offline.access", "tweet.read", "tweet.write", "users.read"]}}
        self.assertIsNone(engine._credential_policy_binding_decision(self.route, policy, credential, "tweets.write"))
        for changes in ({"provider_identity_verified": False}, {"oauth": False},
                {"provider_id": "google"}, {"provider_subject": "different"},
                {"oauth_client_id": "different"}, {"account_subject": "contradictory"},
                {"client_id": "contradictory"}, {"scopes": ["tweet.read", "users.read"]},
                {"scope": "tweet.read"}, {"injection_field": "refresh_token"}):
            changed = deepcopy(credential)
            changed["metadata"].update(changes)
            with self.subTest(changes=changes):
                decision = engine._credential_policy_binding_decision(self.route, policy, changed, "tweets.write")
                self.assertIsNotNone(decision)
                self.assertFalse(decision.allowed)
        self.assertIsNotNone(engine._credential_policy_binding_decision(self.route, policy, credential, "tweets.read"))

    def test_utf8_text_and_wire_bounds_framing_and_no_fake_captures(self):
        for text in ("x" * 16384, "é" * 8192, "\n\r\t"):
            body = json.dumps({"text": text}, ensure_ascii=False).encode()
            self.assertTrue(self.adapter.validate_request(flow(body), self.route, {}).allowed)
        exact = BODY + b" " * (32768 - len(BODY))
        self.assertTrue(self.adapter.validate_request(flow(exact), self.route, {}).allowed)
        for body in (exact + b" ", json.dumps({"text": "é" * 8193}, ensure_ascii=False).encode(),
                b'\xef\xbb\xbf' + BODY, b'{"text":"\xff"}', b'[[[[', b'{"text":NaN}', b'{}'):
            self.assertFalse(self.adapter.validate_request(flow(body), self.route, {}).allowed)
        for extra in ([(b"Content-Length", b"1")], [(b"Transfer-Encoding", b"chunked")],
                [(b"Content-Encoding", b"gzip")]):
            value = flow(headers=[(b"Content-Type", b"application/json"), *extra])
            self.assertFalse(adapters.preflight_request_admission(value, self.route,
                engine._normalized_request_headers(value)).allowed)
        self.assertFalse(self.adapter.validate_request(flow(), self.route, {"text": "fake"}).allowed)

    def test_canonical_operation_excludes_private_text_but_commits_original_body(self):
        value = flow(headers=[(b"Content-Type", b"application/json"),
            (b"Accept-Encoding", b"gzip"), (b"X-Catchplate-Agent", b"fixture")])
        principal = self.snapshot.principals["agent:fixture"]
        credential = self.snapshot.credentials[self.route.credential_ref]
        discarded = engine._discard_declared_request_headers(value, self.route, principal, credential)
        engine._strip_identity_headers(value, principal)
        operation = self.adapter.operation_fields(value, self.route, {})
        canonical = engine._canonical_request(value, principal=principal, route=self.route,
            credential_version="1", policy_hash=self.snapshot.hash, operation_fields=operation,
            forwarded_headers=engine._canonical_forwarded_request_headers(value, credential, route=self.route),
            discard_headers=discarded)
        encoded = json.dumps(canonical)
        self.assertNotIn("synthetic private request text", encoded)
        self.assertIn(hashlib.sha256(BODY).hexdigest(), encoded)
        self.assertEqual(operation, {"operation": "tweets.write"})
        self.assertEqual(value.request.raw_content, BODY)
        self.assertNotIn("accept-encoding", value.request.headers)

    def test_shared_response_vectors_reach_actual_engine_without_projection(self):
        for row in VECTORS["responses"]:
            with self.subTest(case=row["id"]):
                body = row["body"].encode()
                value = self.response(body, status=row["status"], media=row["content_type"].encode())
                self.assertEqual(self.release(value).allowed, row["allowed"])
                if row["allowed"]:
                    self.assertEqual(value.response.raw_content, body)
                    self.assertEqual(set(value.response.headers), {"content-type", "content-length"})
                    self.assertEqual(value.metadata["catchplate_response_validation_body_sha256"],
                        "sha256:" + hashlib.sha256(body).hexdigest())
                else:
                    self.assertNotIn("catchplate_response_release_audit_logged", value.metadata)

    def test_response_limits_reflection_metadata_and_final_completion_guards(self):
        for status, maximum in ((201, 1048576), (422, 65536)):
            body = b'{}' + b' ' * (maximum - 2)
            self.assertTrue(self.release(self.response(body, status=status)).allowed)
            self.assertFalse(self.release(self.response(body + b' ', status=status)).allowed)
        escaped = ('{"secret":"' + ''.join('\\u%04x' % ord(c) for c in SECRET) + '"}').encode()
        for body, headers in ((json.dumps({"secret": SECRET}).encode(), []), (escaped, []),
                (b'{}', [(b"X-Cache", b"safe"), (b"x-cache", SECRET.encode())])):
            value = self.response(body, headers=headers)
            before = value.response.headers.fields
            self.assertFalse(engine.prepare_response(value).allowed)
            self.assertEqual(value.response.headers.fields, before)
            self.assertNotIn("catchplate_response_validation_body_sha256", value.metadata)
        for headers in ([(b"Content-Type", b"application/json")], [(b"Content-Encoding", b"gzip")],
                [(b"Set-Cookie", b"x=y")]):
            self.assertFalse(self.release(self.response(headers=headers)).allowed)
        self.assertFalse(self.release(self.response(guarded=False)).allowed)
        value = self.response()
        self.assertTrue(self.release(value).allowed)
        value.response.raw_content += b' '
        self.assertEqual(engine.validate_response_completion(value).payload["error"], "response_changed_after_validation")

    def test_quota_shape_and_same_account_cross_client_consistency(self):
        raw = document(True)
        raw["principals"].append({"id": "agent:other", "sourceCidrs": ["127.0.0.1/32"],
            "requiredHeaders": {"X-Catchplate-Agent": "other"}})
        credential = deepcopy(raw["credentials"][0])
        credential.update(id="credential:other", oauthClientId="second-client")
        raw["credentials"].append(credential)
        route = deepcopy(raw["routes"][0])
        route.update(id="route.other", principals=["agent:other"], credentialRef="credential:other")
        route["adapter"]["config"]["credentialBinding"]["clientIds"] = ["second-client"]
        raw["routes"].append(route)
        pb.compile_policy_bundle(raw)
        for quota in (None, 51):
            changed = deepcopy(raw)
            if quota is None: changed["routes"][1]["constraints"].pop()
            else: changed["routes"][1]["constraints"][-1]["max"] = quota
            with self.assertRaises(pb.PolicyBundleError): pb.compile_policy_bundle(changed)
        for change in ({"max": True}, {"max": 0}, {"max": 1000000001}, {"id": "other"},
                {"store": "local"}, {"key": {"scope": ["route", "operation"], "operationFields": ["providerAccount"]}}):
            changed = document(True)
            changed["routes"][0]["constraints"][-1].update(change)
            with self.assertRaises(pb.PolicyBundleError): pb.compile_policy_bundle(changed)
        # Independent expected account identity: no route, client, principal or generation.
        self.assertEqual(pb.provider_account_scope_value("x", "fixture-x-account"),
            "sha256:" + hashlib.sha256(b'x\x00fixture-x-account').hexdigest())

    def test_quota_rejects_legacy_and_generic_matching_write_routes_only_when_selected(self):
        credential = self.snapshot.credentials["credential:fixture"]
        credentials = {"credential:fixture": credential}
        for kind, config in (("x.v2", {"mode": "controlledWrite"}), ("generic.rest", {})):
            for path in ("/2/tweets", "/2/*", "/{version}/tweets", "/**"):
                extra = {"adapter": {"type": kind, "config": config}, "credentialRef": "credential:fixture",
                    "match": {"scheme": "https", "host": "api.x.com", "port": 443,
                        "methods": ["POST"], "paths": [path]}}
                # Actual shared compiler overlap predicate with actual validated credential.
                with self.subTest(kind=kind, path=path), self.assertRaises(ValueError):
                    post.validate_policy_routes([*document(True)["routes"], extra], credentials)
                post.validate_policy_routes([*document(False)["routes"], extra], credentials)
                if kind == "generic.rest":
                    for field, value in (("host", "other.example"), ("methods", ["GET"]), ("paths", ["/2/users"])):
                        changed = deepcopy(extra)
                        changed["match"][field] = value
                        post.validate_policy_routes([*document(True)["routes"], changed], credentials)
        other = replace(credential, provider_subject="different-account")
        extra["credentialRef"] = "other"
        post.validate_policy_routes([*document(True)["routes"], extra], {**credentials, "other": other})

    def test_legacy_modes_and_python_dispatch_refusal_remain_unchanged(self):
        legacy = json.loads((ROOT / "policies/credential-limits.examples.json").read_text())
        old = pb.compile_policy_bundle(legacy).hash
        pb.compile_policy_bundle(document())
        self.assertEqual(pb.compile_policy_bundle(legacy).hash, old)
        for adapter in ("generic.rest", "x.v2", "x.app_read.v1"):
            with self.assertRaises(pb.PolicyBundleError):
                pb.validate_buffered_passthrough_response("fixture", adapter, post.response_profile())
        # The Python proxy still refuses credentialHeader replacement, before effects;
        # its parsed-field response tests do not claim actual dispatch/unknown outcomes.
        denied = engine._legacy_mitm_route_admission(flow(), self.route)
        self.assertEqual(denied.payload["error"], "python_credential_header_replacement_unsupported")


if __name__ == "__main__":
    unittest.main(verbosity=2)
