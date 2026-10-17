#!/usr/bin/env python3
"""Offline Alchemy contract/compiler/parsed-field tests, not SDK forwarding.

Actual compiler, adapter and response guards run against synthetic parsed HTTP
fields. The inherited fixture forbids sockets and SQLite and uses only a
mitmproxy annotation stub. Real framing/replacement remains the Rust lane.
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
import test_npm_metadata as parsed
from catchplate import adapters, alchemy_rpc_read as rpc, policy_bundle as pb
from catchplate import policy_engine as engine, policy_route_authority as authority

VECTORS = json.loads((ROOT / "scripts/fixtures/alchemy_rpc_read_v1.json").read_text())
SECRET = "synthetic-alchemy-private-token-NEVER-RELEASE"
BODY = b'{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}'
RESPONSE = b'{"jsonrpc":"2.0","id":1,"result":"0x1"}'


def document():
    return {"apiVersion": "catchplate.policy/v1", "kind": "PolicyBundle",
        "metadata": {"id": "alchemy-rpc-read-test", "sequence": 1, "rollbackEpoch": 1},
        "defaults": {"action": "deny", "failMode": "closed", "unknownHosts": "block",
            "unknownPaths": "block", "validationFailure": "block"},
        "principals": [{"id": "agent:fixture", "sourceCidrs": ["127.0.0.1/32"],
            "requiredHeaders": {"X-Catchplate-Agent": "fixture"}}],
        "credentials": [{"id": "credential:fixture", "credentialType": "static",
            "provider": "operator-demo", "providerSubject": "synthetic-alchemy-subject",
            "injection": {"type": "bearer", "header": "Authorization"}}],
        "routes": [{"id": "route.alchemy-fixture", "principals": ["agent:fixture"],
            "credentialRef": "credential:fixture", "credentialHeader": deepcopy(VECTORS["replacement"]),
            "match": {"scheme": "https", "host": "eth-mainnet.g.alchemy.com", "port": 443,
                "methods": ["POST"], "paths": ["/v2"]},
            "adapter": {"type": "alchemy.rpc_read.v1", "config": {
                "credentialBinding": deepcopy(VECTORS["credentialBinding"]), "chain": "eth-mainnet",
                "request": deepcopy(VECTORS["request"]), "response": deepcopy(VECTORS["response"])}},
            "constraints": [{"id": "fixture.alchemy-response", "type": "responseEnvelope", "phase": "response",
                "statusCodes": [200, 400, 401, 403, 404, 429, 500, 502, 503, 504], "bodyPresence": "required",
                "contentTypes": ["application/json"], "allowedResponseHeaderNames": [], "responseHeaderRules": [],
                "unlistedHeaderPolicy": "discardUnselectedV1", "contentTypePolicy": "alchemyRpcReadJsonUtf8V1"}]}]}


def flow(*, url=None, method="POST", body=BODY, headers=None):
    return parsed.request(VECTORS["url"] if url is None else url, method=method, body=body,
        headers=[(b"Content-Type", b"application/json")] if headers is None else headers)


class AlchemyRpcReadTests(unittest.TestCase):
    def setUp(self):
        self.snapshot = pb.compile_policy_bundle(document())
        self.route = self.snapshot.routes[0]
        self.adapter = adapters.get_adapter("alchemy.rpc_read.v1")

    def response(self, body=RESPONSE, *, status=200, request_id=1, media=b"application/json", headers=(), guard=True):
        request_body = json.dumps({"jsonrpc": "2.0", "id": request_id,
            "method": "eth_chainId", "params": []}, separators=(",", ":")).encode()
        value = flow(body=request_body)
        value.response = SimpleNamespace(status_code=status, raw_content=body, content=body, trailers=None,
            headers=parsed.ParsedHeaders(([(b"Content-Type", media)] if media is not None else []) + list(headers)))
        value.metadata.update(catchplate_route=self.route,
            catchplate_operation={**VECTORS["operation"], "requestId": request_id})
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
            if not result.allowed:
                return result
        return result

    def test_independent_profiles_schema_and_read_classification_despite_post(self):
        self.assertEqual(rpc.request_profile(), VECTORS["request"])
        self.assertEqual(rpc.response_profile(), VECTORS["response"])
        self.assertEqual(rpc.response_envelope("fixture.alchemy-response"), document()["routes"][0]["constraints"][0])
        schema = json.loads((ROOT / "schemas/adapters/alchemy.rpc_read.v1.schema.json").read_text())
        self.assertIsInstance(schema.get("$defs"), dict)
        self.assertTrue(schema["$defs"])
        self.assertIs(schema["additionalProperties"], False)
        self.assertEqual(set(schema["required"]), {"credentialBinding", "chain", "request", "response"})
        self.assertEqual(set(schema["properties"]), set(schema["required"]))
        before = document()
        for validate_schema in (True, False):
            compiled = pb.compile_policy_bundle(before, validate_schema=validate_schema)
            rpc.validate_route(compiled.routes[0])
            v2 = document()
            v2["apiVersion"] = "catchplate.policy/v2"
            pb.compile_policy_bundle(authority.prepare_unsigned(v2, []), validate_schema=validate_schema)
        self.assertEqual(before, document())
        self.assertEqual(authority._builtin("alchemy.rpc_read.v1", "alchemy.rpc.read"), "read")
        self.assertEqual(pb.adapter_operation_field_names(rpc.ADAPTER, rpc.OPERATION),
            frozenset({"operation", "chain", "method", "requestId"}))
        self.assertIsNone(pb.adapter_operation_field_names(rpc.ADAPTER, "eth_sendRawTransaction"))
        other = document()
        other["routes"][0]["adapter"]["config"]["chain"] = "eth-sepolia"
        other["routes"][0]["match"]["host"] = "eth-sepolia.g.alchemy.com"
        route = pb.compile_policy_bundle(other).routes[0]
        self.assertNotEqual(pb.compile_policy_bundle(other).hash, self.snapshot.hash)
        self.assertTrue(self.adapter.validate_request(flow(url="https://eth-sepolia.g.alchemy.com/v2"), route, {}).allowed)

    def test_signed_authority_and_profiles_refuse_widening_with_or_without_schema(self):
        mutations = [lambda r: r["match"].update(host="eth-sepolia.g.alchemy.com"),
            lambda r: r["match"].update(scheme="http"), lambda r: r["match"].update(port=443.0),
            lambda r: r["match"].update(methods=["GET", "POST"]), lambda r: r["match"].update(paths=["/v2/{key}"]),
            lambda r: r.update(jit={}), lambda r: r.update(responseObservation={}),
            lambda r: r.pop("credentialHeader"), lambda r: r["credentialHeader"].update(expectedValue="Bearer other"),
            lambda r: r["credentialHeader"].update(mode="insert"),
            lambda r: r["adapter"]["config"]["credentialBinding"].update(provider="alchemy"),
            lambda r: r["adapter"]["config"]["credentialBinding"].update(subjects=["different"]),
            lambda r: r["adapter"]["config"].update(methods=["eth_chainId"]),
            lambda r: r["adapter"]["config"]["request"].update(maxBodyBytes=65536.0),
            lambda r: r["adapter"]["config"]["request"].update(maxBodyBytes=True),
            lambda r: r["adapter"]["config"]["request"].update(allowedQueryKeys=["id"]),
            lambda r: r["adapter"]["config"]["request"].update(allowedMediaTypes=[]),
            lambda r: r["adapter"]["config"]["request"].update(discardHeaders=[]),
            lambda r: r["adapter"]["config"]["response"].update(maxBodyBytes=65536.0),
            lambda r: r["adapter"]["config"]["response"].update(allowedHeaders=["etag"]),
            lambda r: r["constraints"][0].update(statusCodes=[200.0, 400, 401, 403, 404, 429, 500, 502, 503, 504]),
            lambda r: r["constraints"][0].update(contentTypePolicy="xAppReadJsonUtf8V1")]
        for validate_schema in (True, False):
            for index, mutate in enumerate(mutations):
                value = document()
                mutate(value["routes"][0])
                with self.subTest(index=index, schema=validate_schema), self.assertRaises(pb.PolicyBundleError):
                    pb.compile_policy_bundle(value, validate_schema=validate_schema)

    def test_chain_token_request_id_and_subject_bounds_have_fixed_errors(self):
        for chain in ("eth-mainnet", "eth-sepolia"):
            self.assertEqual(rpc.host(chain), chain + ".g.alchemy.com")
            self.assertEqual(rpc.route_paths(chain), ["/v2"])
        for chain in ("ETH-MAINNET", "eth", "eth-mainnet/other", None, True):
            with self.assertRaises(ValueError): rpc.validate_chain(chain)
        for token in ("opaque", "opaque%2F+_=/", "x" * 8192): self.assertEqual(rpc.validate_token(token), token)
        for token in ("", None, "x" * 8193, "private value", "private\nvalue", "é"):
            with self.assertRaises(ValueError) as raised: rpc.validate_token(token)
            self.assertEqual(str(raised.exception), "Alchemy RPC read contract refused")
        for request_id in (0, 9007199254740991, " ", "x" * 64):
            self.assertEqual(rpc.validate_request_id(request_id), request_id)
        for request_id in (True, False, None, 1.0, -1, 9007199254740992, "", "x" * 65, "é", "\x7f", [], {}):
            with self.assertRaises(ValueError): rpc.validate_request_id(request_id)
        for subject in ("", " padded", "padded ", "bad\x00subject", "é" * 257):
            config = deepcopy(self.route.adapter_config)
            config["credentialBinding"]["subjects"] = [subject]
            with self.assertRaises(ValueError): rpc.validate_config(config)

    def test_shared_request_vectors_reach_adapter_and_preserve_original_bytes(self):
        for row in VECTORS["requests"]:
            with self.subTest(case=row["id"]):
                value = flow(url=row["url"], method=row["method"], body=row["body"].encode(),
                    headers=[(name.encode(), item.encode()) for name, item in row["headers"]])
                original = (value.request.pretty_url, value.request.raw_content, value.request.headers.fields)
                self.assertEqual(self.adapter.validate_request(value, self.route, {}).allowed, row["allowed"])
                if row["allowed"]:
                    self.assertEqual(self.adapter.operation_fields(value, self.route, {}), row["operation"])
                    self.assertTrue(self.adapter.rewrite_request(value, self.route, {}).allowed)
                self.assertEqual((value.request.pretty_url, value.request.raw_content, value.request.headers.fields), original)
        self.assertFalse(self.adapter.validate_request(flow(), self.route, {"chain": "eth-mainnet"}).allowed)

    def test_request_limits_framing_headers_and_literal_target(self):
        exact = BODY + b" " * (65536 - len(BODY))
        self.assertTrue(self.adapter.validate_request(flow(body=exact), self.route, {}).allowed)
        for body in (exact + b" ", b"\xef\xbb\xbf" + BODY, b'{"id":"\xff"}', b"[" * 1024 + b"]" * 1024):
            self.assertFalse(self.adapter.validate_request(flow(body=body), self.route, {}).allowed)
        for headers in ([(b"X-Unknown", b"synthetic")], [(b"User-Agent", b"a"), (b"user-agent", b"a")],
                [(b"Alchemy-Ethers-Sdk-Method", b"a"), (b"alchemy-ethers-sdk-method", b"b")],
                [(b"Accept-Language", b"en")]):
            self.assertFalse(self.adapter.validate_request(flow(headers=[(b"Content-Type", b"application/json"), *headers]), self.route, {}).allowed)
        for extra in ([(b"Content-Length", b"1")], [(b"Transfer-Encoding", b"chunked")], [(b"Content-Encoding", b"gzip")]):
            value = flow(headers=[(b"Content-Type", b"application/json"), *extra])
            self.assertFalse(adapters.preflight_request_admission(value, self.route, engine._normalized_request_headers(value)).allowed)
        for target in (VECTORS["url"] + "/", VECTORS["url"] + "#", VECTORS["url"] + "?",
                VECTORS["url"].replace("https://", "http://"), VECTORS["url"].replace("eth-mainnet", "ETH-MAINNET"),
                VECTORS["url"].replace("https://", "https://user@"), VECTORS["url"].replace("/v2", "/%762")):
            with self.assertRaises(ValueError): rpc.validate_request("POST", target, BODY, chain="eth-mainnet")

    def test_canonical_request_keeps_typed_id_and_original_body_with_discard_commitment(self):
        canonical_values = []
        for request_id in (1, "1"):
            body = json.dumps({"jsonrpc": "2.0", "id": request_id, "method": "eth_chainId", "params": []}).encode()
            value = flow(body=body, headers=[(b"Content-Type", b"application/json"),
                (b"Accept-Encoding", b"gzip, deflate"), (b"X-Catchplate-Agent", b"fixture")])
            principal = self.snapshot.principals["agent:fixture"]
            credential = self.snapshot.credentials[self.route.credential_ref]
            self.assertTrue(adapters.preflight_request_admission(value, self.route, engine._normalized_request_headers(value)).allowed)
            discarded = engine._discard_declared_request_headers(value, self.route, principal, credential)
            engine._strip_identity_headers(value, principal)
            self.assertTrue(self.adapter.validate_request(value, self.route, {}).allowed)
            fields = self.adapter.operation_fields(value, self.route, {})
            self.assertIs(type(fields["requestId"]), type(request_id))
            canonical = engine._canonical_request(value, principal=principal, route=self.route,
                credential_version="1", policy_hash=self.snapshot.hash, operation_fields=fields,
                forwarded_headers=engine._canonical_forwarded_request_headers(value, credential, route=self.route),
                discard_headers=discarded)
            canonical_values.append(canonical)
            self.assertNotIn("gzip, deflate", json.dumps(canonical))
            self.assertNotIn("accept-encoding", value.request.headers)
            self.assertEqual(value.request.raw_content, body)
        self.assertNotEqual(canonical_values[0], canonical_values[1])

    def test_shared_response_vectors_bind_original_typed_id_and_preserve_bytes(self):
        for row in VECTORS["responses"]:
            with self.subTest(case=row["id"]):
                body = row["body"].encode("utf-8")
                value = self.response(body, status=row["status"], request_id=row["request_id"], media=row["content_type"].encode())
                self.assertEqual(self.admit_response(value).allowed, row["allowed"])
                if row["allowed"]:
                    self.assertEqual(value.response.raw_content, body)
                    self.assertEqual(set(value.response.headers), {"content-type", "content-length"})
                    self.assertEqual(value.response.headers["content-type"], "application/json")
        # Metadata is not the binding source: the admitted original request is.
        value = self.response(b'{"jsonrpc":"2.0","id":2,"result":true}')
        value.metadata["catchplate_operation"]["requestId"] = 2
        self.assertFalse(self.admit_response(value).allowed)

    def test_http_statuses_response_bounds_depth_and_encoding(self):
        for status in (400, 401, 403, 404, 429, 500, 502, 503, 504):
            self.assertTrue(self.admit_response(self.response(b'{"arbitrary":"object"}', status=status)).allowed)
        for status in (201, 204, 206, 301, 418, 501): self.assertFalse(self.admit_response(self.response(status=status)).allowed)
        for status, base in ((200, RESPONSE), (404, b'{"message":"error"}')):
            body = base + b" " * (65536 - len(base))
            self.assertEqual(len(body), 65536)
            self.assertTrue(self.admit_response(self.response(body, status=status)).allowed)
            self.assertFalse(self.admit_response(self.response(body + b" ", status=status)).allowed)
        for body in (b"", b"\xef\xbb\xbf" + RESPONSE, b'{"x":"\xff"}', RESPONSE + b" trailing",
                b'{"jsonrpc":"2.0","id":1,"result":' + b"[" * 128 + b"0" + b"]" * 128 + b"}"):
            self.assertFalse(self.admit_response(self.response(body)).allowed)

    def test_raw_decoded_and_discarded_metadata_reflection_are_blocked(self):
        raw = json.dumps({"jsonrpc": "2.0", "id": 1, "result": SECRET}).encode()
        escaped = ('{"jsonrpc":"2.0","id":1,"result":"' + "".join("\\u%04x" % ord(c) for c in SECRET) + '"}').encode()
        for body in (raw, escaped): self.assertFalse(self.admit_response(self.response(body)).allowed)
        for headers in ([(b"X-Metadata", SECRET.encode())], [(b"X-Metadata", b"safe"), (b"x-metadata", SECRET.encode())]):
            self.assertFalse(self.admit_response(self.response(headers=headers)).allowed)
        self.assertFalse(self.admit_response(self.response(guard=False)).allowed)

    def test_response_metadata_closure_and_no_general_json_widening(self):
        value = self.response(headers=[(b"X-Cache", b"one"), (b"x-cache", b"two")])
        self.assertTrue(self.admit_response(value).allowed)
        self.assertNotIn("x-cache", value.response.headers)
        for media in (None, b"text/html", b"application/problem+json", b'application/json;charset="utf-8"'):
            self.assertFalse(self.admit_response(self.response(media=media)).allowed)
        for headers in ([(b"Content-Type", b"application/json")], [(b"Content-Encoding", b"gzip")],
                [(b"Set-Cookie", b"x=y")], [(b"X-Catchplate-Internal", b"synthetic")],
                [(b"Content-Length", b"1"), (b"content-length", b"1")], [(b"X-Large", b"x" * 8193)]):
            self.assertFalse(self.admit_response(self.response(headers=headers)).allowed)
        for adapter in ("generic.rest", "x.v2", "x.app_read.v1", "npm.metadata.v1"):
            with self.assertRaises(pb.PolicyBundleError):
                pb.validate_buffered_passthrough_response("fixture", adapter, VECTORS["response"])
        with self.assertRaises(ValueError): rpc.validate_route(replace(self.route, adapter_type="generic.rest"))
        denial = engine._legacy_mitm_route_admission(flow(), self.route)
        self.assertEqual((denial.status_code, denial.payload["error"]),
            (503, "python_credential_header_replacement_unsupported"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
