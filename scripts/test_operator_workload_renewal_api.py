#!/usr/bin/env python3
"""Offline renewal transport controls; not durable store or deployed acceptance.

Real framing, strict models, Ed25519 verification and route-owned middleware
run here. Only the transactional worker is an explicit inert double. Separate
loopback SQLite tests own persistence/admin-session acceptance.
"""
from __future__ import annotations

import ast
import asyncio
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse
from catchplate import operator_demo, operator_workload_renewal as wire
from catchplate import operator_workload_renewal_api as api
from catchplate.operator_catalog_mutations import CatalogNotFound
from catchplate.operator_catalog_schema import CatalogConflict, CatalogIntegrityError


def offline(event, _args):
    if event in {"socket.connect", "socket.bind", "socket.getaddrinfo", "subprocess.Popen"} or event.startswith("sqlite3."):
        raise AssertionError("offline transport test attempted external effects")


sys.addaudithook(offline)
KEY = Ed25519PrivateKey.from_private_bytes(b"\x35" * 32)
PUBLIC = KEY.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
AUDIENCE = "https://proxy.example.com/v1/workload/renew"
NOW = 1_800_000_000_000
ID = "12345678-1234-4234-8234-123456789abc"


def signed():
    value = {"schema": wire.SCHEMA, "audience": AUDIENCE, "application_id": ID,
        "enrollment_id": "22345678-1234-4234-8234-123456789abc",
        "operation_id": "32345678-1234-4234-8234-123456789abc",
        "expected_token_generation": 1, "issued_at_epoch_ms": NOW,
        "expires_at_epoch_ms": NOW + 60_000, "token_sha256": "sha256:" + "4" * 64,
        "token_expires_at_epoch_ms": NOW + 3_600_000}
    value["signature"] = KEY.sign(wire.DOMAIN + wire.canonical(value)).hex()
    return value


def request(body=None, *, method="POST", path=wire.INTERNAL_PATH, raw_path=None,
        query=b"", headers=None, append=(), chunks=None, stalled=False):
    body = wire.canonical(signed()) if body is None else body
    reads = []
    chunks = list(chunks) if chunks is not None else [body]

    async def receive():
        reads.append(True)
        if chunks:
            return {"type": "http.request", "body": chunks.pop(0), "more_body": bool(chunks) or stalled}
        if stalled:
            await asyncio.Event().wait()
        return {"type": "http.disconnect"}

    if headers is None:
        headers = [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())]
    return Request({"type": "http", "method": method, "scheme": "https", "path": path,
        "raw_path": path.encode() if raw_path is None else raw_path, "query_string": query,
        "headers": [*headers, *append]}, receive), reads


def middleware():
    tree = ast.parse((ROOT / "catchplate/app.py").read_text())
    names = {"bounded_control_plane_request_middleware", "_operator_catalog_body_is_route_owned"}
    nodes = [node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in names
        or isinstance(node, ast.Assign) and any(isinstance(name, ast.Name) and
            name.id == "_OPERATOR_CATALOG_BODY_POST_PATHS" for name in node.targets)]
    assert len(nodes) == 3
    for node in nodes:
        if hasattr(node, "decorator_list"):
            node.decorator_list = []
    namespace = {"Request": Request, "JSONResponse": JSONResponse}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), "<actual-renewal-body-routing>", "exec"), namespace)
    return namespace


class RenewalApiTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.profile = patch.object(operator_demo, "active", return_value=True)
        self.profile.start()
        self.addCleanup(self.profile.stop)

    async def refused(self, expected, **options):
        item, reads = request(**options)
        with self.assertRaises(HTTPException) as caught:
            await api._payload(item)
        self.assertEqual(caught.exception.status_code, expected)
        self.assertEqual(caught.exception.headers["Cache-Control"], "no-store")
        return reads

    async def test_genuine_signed_flat_input_preserved(self):
        original = signed()
        item, reads = request(wire.canonical(original))
        payload = await api._payload(item)
        payload.verify(PUBLIC, AUDIENCE)
        payload.check_fresh(NOW)
        self.assertEqual(payload.model_dump(by_alias=True), original)
        self.assertEqual(len(reads), 1)

    async def test_profile_disabled_or_changed_refuses_before_body(self):
        for value, error, status in ((False, None, 404), (None, RuntimeError("private canary"), 503)):
            with patch.object(operator_demo, "active", return_value=value, side_effect=error):
                self.assertFalse(await self.refused(status, stalled=True, chunks=[]))

    async def test_methods_queries_and_raw_aliases_refused_before_body(self):
        for options in ({"method": "GET"}, {"method": "PUT"}, {"query": b"x=1"},
                {"path": wire.INTERNAL_PATH + "/"}, {"raw_path": b"/api/operator-demo/workloads/%72enew"}):
            with self.subTest(options=options):
                self.assertFalse(await self.refused(400, stalled=True, chunks=[], **options))

    async def test_all_credential_and_browser_headers_refused_before_body(self):
        for name in sorted(api._CREDENTIAL_HEADERS):
            with self.subTest(header=name):
                self.assertFalse(await self.refused(401, append=[(name.encode(), b"private canary")],
                    stalled=True, chunks=[]))

    async def test_duplicate_header_even_unrelated_is_rejected(self):
        for extra in ([(b"content-type", b"application/json")],
                [(b"x-unrelated", b"1"), (b"x-unrelated", b"2")], [(b"content-length", b"1")]):
            self.assertFalse(await self.refused(400, append=extra, chunks=[], stalled=True))

    async def test_canonical_framing_and_encoding_before_body(self):
        for headers in ([], [(b"content-type", b"application/json")],
                [(b"content-type", b"application/json"), (b"content-length", b"01")],
                [(b"content-type", b"application/json; charset=utf-8"), (b"content-length", b"1")]):
            self.assertFalse(await self.refused(400, headers=headers, chunks=[], stalled=True))
        for header in (b"content-encoding", b"transfer-encoding"):
            self.assertFalse(await self.refused(400, append=[(header, b"identity")], chunks=[], stalled=True))

    async def test_declared_oversize_and_zero_before_body(self):
        for length in (0, 4097):
            self.assertFalse(await self.refused(413, headers=[(b"content-type", b"application/json"),
                (b"content-length", str(length).encode())], chunks=[], stalled=True))

    async def test_actual_stream_cannot_exceed_bound_or_declaration(self):
        await self.refused(413, body=b"a", chunks=[b"a" * 4096, b"b"])
        await self.refused(400, body=b"a", chunks=[b"ab"])
        await self.refused(400, body=b"ab", chunks=[b"a"])

    async def test_duplicate_extra_unknown_nested_and_wrong_scalar(self):
        raw = wire.canonical(signed())
        values = [b'{"schema":"extra",' + raw[1:]]
        for change in ({"extra": "private canary"}, {"expected_token_generation": True},
                {"audience": {"nested": "private canary"}}, {"signature": "bad"}, {"schema": "native"}):
            values.append(wire.canonical({**signed(), **change}))
        for value in values:
            with self.subTest(length=len(value)):
                await self.refused(422, body=value)

    async def test_body_timeout_is_total_fixed_five_seconds(self):
        calls = []
        def timeout(seconds):
            calls.append(seconds)
            return asyncio.timeout(0.01)
        with patch.object(api, "asyncio", SimpleNamespace(timeout=timeout)):
            await self.refused(408, chunks=[b"{"], stalled=True)
        self.assertEqual(calls, [5])

    async def test_exact_success_once_and_no_store(self):
        result = {"operation": {"operation_id": signed()["operation_id"]}, "application": {"id": ID},
            "revision": 2, "policy": {"activation": "pending"}}
        async def worker(payload):
            payload.verify(PUBLIC, AUDIENCE)
            return result
        with patch.object(api, "_renew", new=AsyncMock(side_effect=worker)) as effect:
            response = await api.renew(request()[0])
        self.assertEqual(effect.await_count, 1)
        self.assertEqual(json.loads(response.body), result)
        self.assertLessEqual(len(response.body), wire.MAX_RESPONSE_BYTES)
        self.assertEqual(response.headers["cache-control"], "no-store")
        self.assertNotIn(b"signature", response.body)

    async def test_altered_genuine_proof_is_not_retried_or_echoed(self):
        async def worker(payload):
            payload.verify(PUBLIC, AUDIENCE)
        value = signed()
        value["token_sha256"] = "sha256:" + "6" * 64
        with patch.object(api, "_renew", new=AsyncMock(side_effect=worker)) as effect:
            with self.assertRaises(HTTPException) as caught:
                await api.renew(request(wire.canonical(value))[0])
        self.assertEqual(caught.exception.status_code, 401)
        self.assertEqual(effect.await_count, 1)
        self.assertNotIn(value["signature"], str(caught.exception.detail))

    async def test_owner_errors_have_fixed_status_and_single_attempt(self):
        for error, status in ((CatalogNotFound, 404), (CatalogConflict, 409), (CatalogIntegrityError, 503),
                (ValueError, 401), (TimeoutError, 503), (RuntimeError, 503)):
            with patch.object(api, "_renew", new=AsyncMock(side_effect=error("private canary"))) as effect:
                with self.assertRaises(HTTPException) as caught:
                    await api.renew(request()[0])
            self.assertEqual(caught.exception.status_code, status)
            self.assertNotIn("private canary", str(caught.exception.detail))
            self.assertEqual(effect.await_count, 1)

    async def test_invalid_input_never_reaches_worker(self):
        with patch.object(api, "_renew", new=AsyncMock()) as effect:
            with self.assertRaises(HTTPException):
                await api.renew(request(b"{}")[0])
        effect.assert_not_awaited()

    async def test_oversize_or_unserializable_result_refuses_without_retry(self):
        for result in ({"oversize": "x" * 8192}, {"bad": object()}):
            with patch.object(api, "_renew", new=AsyncMock(return_value=result)) as effect:
                with self.assertRaises(HTTPException) as caught:
                    await api.renew(request()[0])
            self.assertEqual(caught.exception.status_code, 503)
            self.assertEqual(effect.await_count, 1)

    async def test_exact_machine_middleware_bypass_before_generic_buffering(self):
        from catchplate import development_sandbox
        namespace = middleware()
        next_handler = AsyncMock(return_value="route-owned")
        item, reads = request(stalled=True, chunks=[])
        with patch.object(development_sandbox, "active", return_value=False):
            result = await namespace["bounded_control_plane_request_middleware"](item, next_handler)
        self.assertEqual(result, "route-owned")
        self.assertEqual(next_handler.await_count, 1)
        self.assertFalse(reads)
        roster = namespace["_OPERATOR_CATALOG_BODY_POST_PATHS"]
        self.assertTrue({wire.ENROLL_PATH, wire.CANCEL_PATH} <= roster)
        self.assertNotIn(wire.INTERNAL_PATH, roster)

    async def test_profile_allowlist_reserves_all_three_paths_to_post(self):
        for path in (wire.INTERNAL_PATH, wire.ENROLL_PATH, wire.CANCEL_PATH):
            self.assertTrue(operator_demo.request_allowed("POST", path))
            for method in ("GET", "HEAD", "OPTIONS", "PUT", "DELETE"):
                self.assertFalse(operator_demo.request_allowed(method, path))

    async def test_admin_endpoints_keep_existing_dependency_and_same_origin_owner(self):
        tree = ast.parse((ROOT / "catchplate/operator_catalog_api.py").read_text())
        routes = [node for node in tree.body if isinstance(node, ast.AsyncFunctionDef)
            and node.name in {"enroll_workload_renewal", "cancel_workload_renewal"}]
        self.assertEqual(len(routes), 2)
        for route in routes:
            dependency = route.args.defaults[0]
            self.assertIsInstance(dependency, ast.Call)
            self.assertEqual(dependency.func.id, "Depends")
            self.assertEqual(dependency.args[0].id, "_admin_identity")
        owner = next(node for node in tree.body if isinstance(node, ast.AsyncFunctionDef) and node.name == "_renewal_admin")
        calls = {node.func.id: node.lineno for node in ast.walk(owner)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)}
        self.assertLess(calls["_admit"], calls["_payload"])
        self.assertLess(calls["_payload"], calls["_blocking"])

    async def test_machine_refusal_does_not_drain_unrelated_audit_outbox(self):
        tree = ast.parse((ROOT / "catchplate/app.py").read_text())
        node = next(node for node in tree.body if isinstance(node, ast.AsyncFunctionDef)
            and node.name == "csrf_middleware")
        guards = [node for node in ast.walk(node) if isinstance(node, ast.If)
            and any(isinstance(call, ast.Call) and isinstance(call.func, ast.Name)
                and call.func.id == "_run_bounded_blocking" for call in ast.walk(node))]
        self.assertEqual(len(guards), 1)
        self.assertIn(wire.INTERNAL_PATH, [value.value for value in ast.walk(guards[0].test)
            if isinstance(value, ast.Constant)])


if __name__ == "__main__":
    unittest.main(verbosity=2)
