#!/usr/bin/env python3
"""Offline parsed-field Alchemy engine joins, not transport/provider acceptance.

Uses the actual compiler, classifier, adapter, and public response-engine stages.
Only the external audit sink is replaced by an in-memory collector. The shared
fixture forbids SQLite and sockets; its optional mitmproxy stub supplies type
annotations only. No credentials are acquired and no HTTP traffic is sent.
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
import test_alchemy_rpc_read as fixture
from catchplate import adapters, alchemy_rpc_read as rpc, policy_bundle as pb
from catchplate import policy_engine as engine, policy_route_authority as authority


class AlchemyPolicyEngineTests(unittest.TestCase):
    def setUp(self):
        self.snapshot = pb.compile_policy_bundle(fixture.document())
        self.route = self.snapshot.routes[0]
        self.audit = []
        sink = patch.object(engine.runtime, "log_request",
            side_effect=lambda *args, **kwargs: self.audit.append((args, kwargs)))
        sink.start()
        self.addCleanup(sink.stop)

    def response(self, body=fixture.RESPONSE, *, status=200, request_id=1,
            media=b"application/json", headers=(), guard=True):
        request_body = json.dumps({"jsonrpc": "2.0", "id": request_id,
            "method": "eth_chainId", "params": []}, separators=(",", ":")).encode()
        value = fixture.flow(body=request_body)
        value.response = SimpleNamespace(status_code=status, raw_content=body,
            content=body, trailers=None, headers=fixture.parsed.ParsedHeaders(
                ([(b"Content-Type", media)] if media is not None else []) + list(headers)))
        value.metadata.update(catchplate_route=self.route, catchplate_route_id=self.route.id,
            catchplate_policy_hash=self.snapshot.hash,
            catchplate_operation={**fixture.VECTORS["operation"], "requestId": request_id})
        if guard:
            secret_guard = engine._ResponseCredentialGuard()
            secret_guard.add_text_encodings(fixture.SECRET)
            engine._install_response_credential_guard(value, secret_guard)
        self.addCleanup(engine.discard_response_guards, value)
        return value

    def release(self, value):
        for stage in (engine.prepare_response, engine.evaluate_response,
                engine.validate_response_completion):
            decision = stage(value)
            if not decision.allowed:
                return decision
        return decision

    def test_exact_read_classifier_is_not_a_post_or_operation_name_heuristic(self):
        for chain in rpc.CHAINS:
            raw = fixture.document()
            raw["apiVersion"] = "catchplate.policy/v2"
            raw["routes"][0]["adapter"]["config"]["chain"] = chain
            raw["routes"][0]["match"]["host"] = rpc.host(chain)
            selected = authority.prepare_unsigned(raw, [])
            compiled = authority.admit(selected)
            self.assertEqual(compiled["mapping"]["profiles"][0]["profile"]["operations"],
                [{"operationName": rpc.OPERATION, "operation": "read", "requestAuthorityClass": "read"}])
            route = pb.compile_policy_bundle(selected).routes[0]
            for method in rpc.METHODS:
                body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": []}).encode()
                flow = fixture.flow(url="https://" + rpc.host(chain) + "/v2", body=body)
                adapter = adapters.get_adapter(rpc.ADAPTER)
                self.assertTrue(adapter.validate_request(flow, route, {}).allowed)
                self.assertEqual(adapter.operation_fields(flow, route, {})["operation"], rpc.OPERATION)
            with self.assertRaises(pb.PolicyBundleError):
                authority.prepare_unsigned(raw, [{"routeId": route.id,
                    "operationName": rpc.OPERATION, "operation": "write"}])
        for name in ("eth_chainId", "eth_sendRawTransaction", "alchemy.rpc.write", "alchemy.rpc.read.extra"):
            self.assertIsNone(authority._builtin(rpc.ADAPTER, name))
        self.assertIsNone(authority._builtin("generic.rest", rpc.OPERATION))
        denied = engine._legacy_mitm_route_admission(fixture.flow(), self.route)
        self.assertIsNotNone(denied)
        self.assertEqual((denied.status_code, denied.payload["error"]),
            (503, "python_credential_header_replacement_unsupported"))

    def test_public_response_stages_preserve_bytes_and_commit_final_body(self):
        body = b'{ "jsonrpc":"2.0", "id":1, "result":{"opaque":[true,null,3]}, "extra":"kept" }'
        value = self.response(body, media=b"application/json; charset=utf-8",
            headers=[(b"X-Cache", b"one"), (b"x-cache", b"two")])
        request_before = (value.request.pretty_url, value.request.raw_content, value.request.headers.fields)
        self.assertTrue(self.release(value).allowed)
        self.assertEqual(value.response.raw_content, body)
        self.assertEqual((value.request.pretty_url, value.request.raw_content, value.request.headers.fields), request_before)
        self.assertEqual(set(value.response.headers), {"content-type", "content-length"})
        self.assertEqual(value.metadata["catchplate_response_validation_body_sha256"],
            "sha256:" + hashlib.sha256(body).hexdigest())
        self.assertEqual([row[0][3] for row in self.audit],
            ["response_validated", "response_release_authorized"])
        self.assertTrue(engine.validate_response_completion(value).allowed)
        self.assertEqual(len(self.audit), 2)
        value.response.raw_content = body + b" "
        decision = engine.validate_response_completion(value)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.payload["error"], "response_changed_after_validation")

    def test_shared_response_vectors_reach_public_engine_not_just_adapter(self):
        for row in fixture.VECTORS["responses"]:
            with self.subTest(case=row["id"]):
                body = row["body"].encode()
                value = self.response(body, status=row["status"], request_id=row["request_id"],
                    media=row["content_type"].encode())
                decision = self.release(value)
                self.assertEqual(decision.allowed, row["allowed"], decision)
                if row["allowed"]:
                    self.assertEqual(value.response.raw_content, body)
                else:
                    self.assertNotIn("catchplate_response_release_audit_logged", value.metadata)
        # Caller metadata cannot replace the original request's typed ID.
        value = self.response(b'{"jsonrpc":"2.0","id":"1","result":true}')
        value.metadata["catchplate_operation"]["requestId"] = "1"
        self.assertFalse(self.release(value).allowed)

    def test_engine_enforces_64k_for_success_and_error_before_release(self):
        for status, base in ((200, fixture.RESPONSE), (429, b'{"message":"rate limited"}')):
            body = base + b" " * (65536 - len(base))
            self.assertTrue(self.release(self.response(body, status=status)).allowed)
            value = self.response(body + b" ", status=status)
            decision = engine.prepare_response(value)
            self.assertFalse(decision.allowed)
            self.assertEqual(decision.payload["error"], "alchemy_rpc_read_response_invalid")
            self.assertNotIn("catchplate_response_validation_body_sha256", value.metadata)

    def test_raw_decoded_and_discarded_header_reflection_fail_before_normalization(self):
        escaped = ('{"jsonrpc":"2.0","id":1,"result":"' +
            "".join("\\u%04x" % ord(char) for char in fixture.SECRET) + '"}').encode()
        raw = json.dumps({"jsonrpc": "2.0", "id": 1, "result": fixture.SECRET}).encode()
        for body, headers in ((raw, []), (escaped, []), (fixture.RESPONSE,
                [(b"X-Metadata", b"safe"), (b"x-metadata", fixture.SECRET.encode())])):
            value = self.response(body, headers=headers)
            before = value.response.headers.fields
            self.assertFalse(engine.prepare_response(value).allowed)
            self.assertEqual(value.response.headers.fields, before)
            self.assertNotIn("catchplate_response_validation_body_sha256", value.metadata)
        value = self.response(guard=False)
        inspection = engine._typed_json_response_inspection(value, self.route)
        self.assertFalse(inspection.allowed)
        self.assertEqual(inspection.payload["error"], "response_credential_guard_unavailable")
        decision = engine.prepare_response(value)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.payload["error"], "response_metadata_guard_unavailable")
        self.assertEqual(self.audit, [])

    def test_media_metadata_and_mode_binding_remain_closed(self):
        for media in (None, b"text/html", b"application/problem+json", b'application/json;charset="utf-8"'):
            self.assertFalse(self.release(self.response(media=media)).allowed)
        for headers in ([(b"Content-Type", b"application/json")], [(b"Content-Encoding", b"gzip")],
                [(b"Set-Cookie", b"x=y")], [(b"X-Catchplate-Internal", b"synthetic")],
                [(b"Content-Length", b"1"), (b"content-length", b"1")]):
            self.assertFalse(self.release(self.response(headers=headers)).allowed)
        for adapter in ("generic.rest", "x.app_read.v1", "npm.metadata.v1", "npm.publish.v1"):
            value = self.response()
            value.metadata["catchplate_route"] = replace(self.route, adapter_type=adapter)
            self.assertFalse(engine.prepare_response(value).allowed)
        raw = fixture.document()
        raw["routes"][0]["adapter"]["config"]["response"]["mode"] = "xAppReadJsonV1"
        for schema in (True, False):
            with self.assertRaises(pb.PolicyBundleError):
                pb.compile_policy_bundle(deepcopy(raw), validate_schema=schema)


if __name__ == "__main__":
    unittest.main(verbosity=2)
