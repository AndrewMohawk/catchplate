#!/usr/bin/env python3
"""In-process X configuration transport controls; no store or OAuth acceptance.

The real FastAPI router, admin-token/role/Origin checks, strict DTO/parser and
ASGI body stream run here. Configuration services and process admission are
explicit synthetic boundaries. Actual bounded-worker functions are extracted
unchanged from app.py, avoiding full application startup; cancellation retains
the occupied slot. Network, SQLite and subprocess effects are forbidden.
"""
from __future__ import annotations

import ast
import asyncio
from contextlib import ExitStack, redirect_stderr, redirect_stdout
from copy import deepcopy
from functools import lru_cache
import io
import json
from pathlib import Path
import sys
import threading
from types import ModuleType
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def no_effects(event, _arguments):
    if event in {"socket.connect", "socket.bind", "socket.getaddrinfo", "subprocess.Popen"} or event.startswith("sqlite3."):
        raise AssertionError("configuration API controls forbid external effects")


sys.addaudithook(no_effects)

from fastapi import FastAPI, HTTPException  # noqa: E402
import serverware  # noqa: E402
from serverware import auth, operator_catalog_api as admission  # noqa: E402
from serverware import operator_x_admission as feature, operator_x_configuration as service  # noqa: E402
from serverware import operator_x_configuration_api as api  # noqa: E402
from serverware.operator_catalog_schema import CatalogConflict  # noqa: E402
from serverware.operator_x_oauth_profile import XOAuthApplicationInput  # noqa: E402

ORIGIN = "https://console.example.com"
ADMIN = "synthetic-x-configuration-admin-private-canary"
SECRET = "synthetic-x-client-secret-private-canary"
ACTOR = "x-configuration-api-test"
OPERATION = "10000000-0000-4000-8000-00000000000a"
UNKNOWN = "20000000-0000-4000-8000-00000000000b"
PREFIX = "/api/operator-demo/oauth/x/configuration/v1"
SHA = "sha256:" + "1" * 64


@lru_cache(maxsize=1)
def actual_worker_module():
    names = {"_finish_bounded_blocking_worker", "_run_bounded_blocking"}
    tree = ast.parse((ROOT / "serverware/app.py").read_text())
    definitions = [node for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in names]
    if len(definitions) != len(names):
        raise AssertionError("actual bounded worker source changed")
    module = ModuleType("serverware.app")
    module.__dict__["asyncio"] = asyncio
    selected = ast.Module(body=[ast.ImportFrom(module="__future__",
        names=[ast.alias(name="annotations")], level=0), *definitions], type_ignores=[])
    exec(compile(ast.fix_missing_locations(selected), str(ROOT / "serverware/app.py"), "exec"), module.__dict__)
    return module


class XConfigurationApiTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(admission.operator_demo, "active", return_value=True))
        self.enabled = self.stack.enter_context(patch.object(feature, "enabled", return_value=True))
        self.stack.enter_context(patch.object(admission.config, "PUBLIC_URL", ORIGIN))
        self.stack.enter_context(patch.multiple(auth, ADMIN_TOKEN=ADMIN, ADMIN_USER_ID=ACTOR,
            ADMIN_ROLES=("admin",), OIDC_ENABLED=False, OIDC_BROWSER_LOGIN_ENABLED=False))
        self.worker = actual_worker_module()
        self.stack.enter_context(patch.dict(sys.modules, {"serverware.app": self.worker}))
        self.stack.enter_context(patch.object(serverware, "app", self.worker, create=True))
        self.slots = asyncio.BoundedSemaphore(1)
        self.stack.enter_context(patch.object(admission, "_WORKER_SLOTS", self.slots))
        self.discover = self.stack.enter_context(patch.object(service, "configuration",
            return_value={"schema": "serverware.operatorXConfiguration/v1", "state": "unconfigured",
                "consent_ready": False}))
        self.receipt = {"schema": "serverware.operatorXConfigurationOperation/v1",
            "operation_id": OPERATION, "status": "committed", "config_version": 1,
            "committed_revision": 2, "policy_hash": SHA, "profile_binding_digest": SHA,
            "public_profile": {"provider_id": "x"}, "client_secret_configured": True, "consent_ready": False}
        self.save = self.stack.enter_context(patch.object(service, "configure", return_value=deepcopy(self.receipt)))
        self.observe = self.stack.enter_context(patch.object(service, "status", return_value=deepcopy(self.receipt)))
        self.app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
        self.app.include_router(api.router)

    def payload(self, **changes):
        return {"operation_id": OPERATION, "client_id": "synthetic-x-client",
            "client_secret": SECRET, "expected_revision": 1, "expected_policy_hash": SHA, **changes}

    async def request(self, method="GET", path=PREFIX, *, body=b"", headers=None,
            authenticate=True, origin=True, receive_error=None):
        if not isinstance(body, bytes):
            body = json.dumps(body, ensure_ascii=True).encode("ascii")
        fields = [(b"host", b"console.example.com")]
        if authenticate:
            fields.append((b"x-serverware-admin-token", ADMIN.encode()))
        if origin:
            fields.append((b"origin", ORIGIN.encode()))
        if headers is None and method == "POST":
            headers = [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())]
        fields.extend(headers or [])
        route, _, query = path.partition("?")
        messages, delivered = [], False

        async def receive():
            nonlocal delivered
            if receive_error is not None:
                raise receive_error
            if delivered:
                return {"type": "http.disconnect"}
            delivered = True
            return {"type": "http.request", "body": body, "more_body": False}

        async def send(message):
            messages.append(message)

        scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1",
            "method": method, "scheme": "https", "path": route, "raw_path": route.encode(),
            "query_string": query.encode(), "headers": fields, "root_path": "",
            "client": ("127.0.0.1", 10000), "server": ("console.example.com", 443)}
        output, errors = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors):
            await self.app(scope, receive, send)
        self.assertEqual(output.getvalue(), "")
        self.assertEqual(errors.getvalue(), "")
        starts = [item for item in messages if item["type"] == "http.response.start"]
        self.assertEqual(len(starts), 1)
        raw = b"".join(item.get("body", b"") for item in messages if item["type"] == "http.response.body")
        response_headers = dict(starts[0]["headers"])
        exposed = raw + repr(response_headers).encode()
        for canary in (ADMIN, SECRET):
            self.assertNotIn(canary.encode(), exposed)
        return starts[0]["status"], json.loads(raw), response_headers

    async def expect(self, expected, *args, **kwargs):
        status, value, headers = await self.request(*args, **kwargs)
        self.assertEqual(status, expected, value)
        self.assertEqual(headers.get(b"cache-control"), b"no-store")
        self.assertEqual(headers.get(b"pragma"), b"no-cache")
        self.assertEqual(headers.get(b"x-content-type-options"), b"nosniff")
        if expected >= 400:
            self.assertEqual(set(value), {"detail"})
        return value

    def no_service(self):
        for method in (self.discover, self.save, self.observe):
            method.assert_not_called()

    async def test_three_routes_dispatch_exact_actor_and_private_dto_once(self):
        self.assertEqual({(route.path, tuple(sorted(route.methods))) for route in self.app.routes}, {
            (PREFIX, ("GET",)), (PREFIX, ("POST",)), (PREFIX + "/{operation_id}", ("GET",))})
        await self.expect(200, origin=False)
        result = await self.expect(201, "POST", body=self.payload())
        self.assertEqual(result, self.receipt)
        self.discover.assert_called_once_with(ACTOR)
        self.save.assert_called_once()
        payload, actor = self.save.call_args.args
        self.assertIs(type(payload), XOAuthApplicationInput)
        self.assertEqual((payload.client_secret, actor), (SECRET, ACTOR))
        self.assertNotIn(SECRET, repr(payload))
        self.assertNotIn("client_secret", payload.model_dump())
        self.assertEqual(await self.expect(200, path=PREFIX + "/" + OPERATION), self.receipt)
        self.observe.assert_called_once_with(OPERATION, ACTOR)

    async def test_actual_admin_role_duplicate_credentials_origin_and_query_guards(self):
        for options, expected in (({"authenticate": False}, 401),
                ({"headers": [(b"x-serverware-admin-token", b"extra")]}, 401),
                ({"headers": [(b"authorization", b"Bearer a"), (b"authorization", b"Bearer b")]}, 401)):
            await self.expect(expected, **options)
        with patch.object(auth, "ADMIN_ROLES", ("viewer",)):
            await self.expect(403)
        for origin, headers in ((False, []), (False, [(b"origin", b"https://foreign.example.com")]),
                (True, [(b"origin", ORIGIN.encode())])):
            await self.expect(403, "POST", body=self.payload(), origin=origin, headers=headers)
        for method in ("GET", "POST"):
            await self.expect(422, method, PREFIX + "?unexpected=1", body=self.payload() if method == "POST" else b"")
        self.no_service()

    async def test_feature_disabled_unknown_and_profile_failure_never_dispatch(self):
        for selection, expected in ((False, 404), (None, 503), (1, 503)):
            self.enabled.return_value = selection
            for method, path in (("GET", PREFIX), ("POST", PREFIX), ("GET", PREFIX + "/" + OPERATION)):
                await self.expect(expected, method, path, body=self.payload() if method == "POST" else b"")
        self.enabled.side_effect = RuntimeError(SECRET)
        await self.expect(503)
        with patch.object(admission.operator_demo, "active", return_value=False):
            await self.expect(404)
        with patch.object(admission.operator_demo, "active", side_effect=RuntimeError(SECRET)):
            await self.expect(503)
        self.no_service()

    async def test_get_refuses_framing_and_actual_body_on_both_read_routes(self):
        for path in (PREFIX, PREFIX + "/" + OPERATION):
            for headers in ([ (b"transfer-encoding", b"chunked") ],
                    [(b"content-encoding", b"identity")], [(b"content-length", b"1")],
                    [(b"content-length", b"00")], [(b"content-length", b"0"), (b"content-length", b"0")]):
                await self.expect(400, path=path, headers=headers)
            for headers in ([], [(b"content-length", b"0")]):
                await self.expect(400, path=path, headers=headers, body=SECRET.encode())
            await self.expect(400, path=path, receive_error=RuntimeError(SECRET))
            await self.expect(408, path=path, receive_error=TimeoutError(SECRET))
        self.no_service()

    async def test_post_strict_closed_secret_dto_and_body_bounds(self):
        invalid = [b"{", b"\xff", [], {}, self.payload(extra=SECRET), self.payload(client_secret=123),
            self.payload(client_secret=SECRET + "\n"), self.payload(client_secret="x" * 4097),
            self.payload(expected_revision=True), self.payload(expected_revision=1.0),
            self.payload(expected_policy_hash="sha256:" + "A" * 64), self.payload(operation_id=OPERATION.upper()),
            self.payload(client_id="client with spaces"),
            b'{"client_secret":"' + SECRET.encode() + b'","client_secret":"again"}']
        for body in invalid:
            await self.expect(422, "POST", body=body)
        await self.expect(413, "POST", body=b" " * (api.MAX_INPUT_BYTES + 1))
        self.no_service()

    async def test_post_media_and_framing_do_not_reach_service(self):
        cases = [([], 415), ([(b"content-type", b"text/plain")], 415),
            ([(b"content-type", b"application/json"), (b"content-type", b"application/json")], 415)]
        for extra, expected in (([(b"content-encoding", b"gzip")], 415),
                ([(b"content-length", b"0")], 400),
                ([(b"content-length", b"1"), (b"content-length", b"1")], 400),
                ([(b"transfer-encoding", b"chunked"), (b"content-length", b"1")], 400),
                ([(b"transfer-encoding", b"gzip")], 400),
                ([(b"content-length", b"+1")], 400),
                ([(b"content-length", b"999999")], 413)):
            cases.append(([(b"content-type", b"application/json"), *extra], expected))
        for headers, expected in cases:
            await self.expect(expected, "POST", body=self.payload(), headers=headers)
        self.no_service()

    async def test_status_identifier_actor_and_absence_are_not_retry_authority(self):
        for identifier in ("not-a-uuid", OPERATION.upper(), OPERATION.replace("-", "")):
            await self.expect(422, path=PREFIX + "/" + identifier)
        self.no_service()

        def owned(identifier, actor):
            if identifier != OPERATION or actor != ACTOR:
                raise service.ConfigurationNotFound(SECRET)
            return deepcopy(self.receipt)

        self.observe.side_effect = owned
        value = await self.expect(404, path=PREFIX + "/" + UNKNOWN)
        self.assertIn("absence does not authorize retry", value["detail"])
        with patch.object(auth, "ADMIN_USER_ID", "another-admin"):
            await self.expect(404, path=PREFIX + "/" + OPERATION)
        self.save.assert_not_called()

    async def test_service_conflict_uncertainty_and_serialization_failures_are_fixed(self):
        for failure, status in ((CatalogConflict(SECRET), 409),
                (service.ConfigurationUnavailable(SECRET), 503), (ValueError(SECRET), 503),
                (HTTPException(418, SECRET, headers={"X-Private": SECRET}), 503)):
            self.save.reset_mock()
            self.save.side_effect = failure
            await self.expect(status, "POST", body=self.payload())
            self.save.assert_called_once()
        self.save.side_effect = None
        for result in (None, [], {"invalid": object()}, {"invalid": float("nan")}):
            self.save.reset_mock()
            self.save.return_value = result
            await self.expect(503, "POST", body=self.payload())
            self.save.assert_called_once()

    async def test_cancelled_http_wait_keeps_actual_worker_slot_until_completion(self):
        entered, release = threading.Event(), threading.Event()

        def blocked(_payload, _actor):
            entered.set()
            if not release.wait(2):
                raise RuntimeError("bounded synthetic worker deadline")
            return deepcopy(self.receipt)

        self.save.side_effect = blocked
        payload = XOAuthApplicationInput.model_validate(self.payload())
        task = asyncio.create_task(api._result(service.configure, payload, ACTOR, created=True))
        try:
            self.assertTrue(await asyncio.to_thread(entered.wait, 1))
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            self.assertTrue(self.slots.locked())
            self.save.assert_called_once()
        finally:
            release.set()
            if not task.done():
                await task
        await asyncio.wait_for(self.slots.acquire(), 2)
        self.slots.release()
        self.save.assert_called_once()


if __name__ == "__main__":
    unittest.main()
