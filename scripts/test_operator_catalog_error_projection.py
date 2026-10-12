#!/usr/bin/env python3
"""Offline catalog ASGI framing and fixed exception-projection regressions.

Runs the actual router, administrator/role/Origin admission and strict parser.
Process activation and the bounded service worker result are synthetic: this
does not claim storage, provider, full-app middleware or proxy acceptance.
The real-loopback workspace suite separately covers normal full-app GETs.
"""
from __future__ import annotations

import asyncio
from contextlib import ExitStack, redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import AsyncMock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def no_effects(event, _arguments):
    if event in {"socket.connect", "socket.bind", "socket.getaddrinfo", "subprocess.Popen"} or event.startswith("sqlite3."):
        raise AssertionError("catalog projection controls forbid external effects")


sys.addaudithook(no_effects)

from fastapi import FastAPI  # noqa: E402
from serverware import auth, operator_catalog_api as api  # noqa: E402
from serverware import operator_catalog_mutations as mutations  # noqa: E402
from serverware.operator_github_app import GitHubAppUnavailable  # noqa: E402

ADMIN = "synthetic-catalog-projection-admin-private-canary"
SECRET = "synthetic-catalog-projection-secret-private-canary"
ACTOR = "catalog-projection-test"
ORIGIN = "https://console.example.com"
CATALOG = "/api/operator-demo/catalog"
POST = "/api/operator-demo/credentials"


class CatalogProjectionTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(api.operator_demo, "active", return_value=True))
        self.stack.enter_context(patch.object(api.config, "PUBLIC_URL", ORIGIN))
        self.stack.enter_context(patch.multiple(auth, ADMIN_TOKEN=ADMIN, ADMIN_USER_ID=ACTOR,
            ADMIN_ROLES=("admin",), OIDC_ENABLED=False, OIDC_BROWSER_LOGIN_ENABLED=False))
        self.worker = self.stack.enter_context(patch.object(api, "_blocking", new_callable=AsyncMock))
        self.worker.return_value = {"synthetic_catalog_observation": True}
        self.app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
        self.app.include_router(api.router)
        self.reads = 0

    async def request(self, *, method="GET", headers=(), chunks=(b"",), authenticate=True,
            stalled=False, disconnected=False, failure=None):
        path = CATALOG if method == "GET" else POST
        fields = [(b"host", b"console.example.com"), *headers]
        if authenticate:
            fields.append((b"x-serverware-admin-token", ADMIN.encode()))
        if method == "POST":
            raw = json.dumps({"expected_revision": 1, "expected_policy_hash": "sha256:" + "1" * 64,
                "name": "Projection control", "auth_type": "bearer", "secret": SECRET}).encode()
            fields.extend(((b"origin", ORIGIN.encode()), (b"content-type", b"application/json"),
                (b"content-length", str(len(raw)).encode())))
            chunks = (raw,)
        pending = list(chunks)
        messages = []

        async def receive():
            self.reads += 1
            if stalled:
                await asyncio.Event().wait()
            if failure is not None:
                raise failure
            if disconnected or not pending:
                return {"type": "http.disconnect"}
            body = pending.pop(0)
            return {"type": "http.request", "body": body, "more_body": bool(pending)}

        async def send(message):
            messages.append(message)

        scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1",
            "method": method, "scheme": "https", "path": path, "raw_path": path.encode(),
            "query_string": b"", "headers": fields, "root_path": "",
            "client": ("127.0.0.1", 10000), "server": ("console.example.com", 443)}
        output, errors = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors):
            await asyncio.wait_for(self.app(scope, receive, send), 2)
        self.assertEqual(output.getvalue(), "")
        self.assertEqual(errors.getvalue(), "")
        starts = [item for item in messages if item["type"] == "http.response.start"]
        self.assertEqual(len(starts), 1)
        body = b"".join(item.get("body", b"") for item in messages if item["type"] == "http.response.body")
        response_headers = dict(starts[0]["headers"])
        for canary in (ADMIN, SECRET):
            self.assertNotIn(canary.encode(), body + repr(response_headers).encode())
        self.assertEqual(response_headers.get(b"cache-control"), b"no-store")
        self.assertEqual(response_headers.get(b"pragma"), b"no-cache")
        self.assertEqual(response_headers.get(b"x-content-type-options"), b"nosniff")
        return starts[0]["status"], json.loads(body)

    async def test_normal_empty_stream_with_absent_or_zero_length_completes(self):
        for headers in ((), ((b"content-length", b"0"),)):
            self.worker.reset_mock()
            self.assertEqual(await self.request(headers=headers),
                (200, {"synthetic_catalog_observation": True}))
            self.worker.assert_awaited_once_with(mutations.catalog_status)
        self.assertEqual(self.reads, 2)

    async def test_nonempty_stream_refuses_without_declared_body_or_with_zero_length(self):
        for headers in ((), ((b"content-length", b"0"),)):
            for chunks in ((SECRET.encode(),), (b"", SECRET.encode())):
                self.assertEqual(await self.request(headers=headers, chunks=chunks),
                    (400, {"detail": "operator catalog status accepts no body"}))
        self.worker.assert_not_awaited()

    async def test_declared_or_encoded_body_refuses_before_receiving(self):
        for headers in (((b"content-length", b"1"),), ((b"transfer-encoding", b"chunked"),),
                ((b"content-encoding", b"gzip"),), ((b"content-length", b"0"), (b"content-length", b"0"))):
            self.assertEqual(await self.request(headers=headers, stalled=True),
                (400, {"detail": "operator catalog status accepts no body"}))
        self.assertEqual(self.reads, 0)
        self.worker.assert_not_awaited()

    async def test_stalled_stream_has_one_total_deadline_and_no_catalog_call(self):
        actual_timeout = asyncio.timeout
        # Accelerate only the existing deadline; cancellation still comes from
        # the real asyncio timeout context and the actual blocked ASGI receive.
        with patch.object(api.asyncio, "timeout", side_effect=lambda seconds: actual_timeout(0.01)) as deadline:
            self.assertEqual(await self.request(stalled=True),
                (408, {"detail": "operator catalog status body timed out"}))
        deadline.assert_called_once_with(30)
        self.assertEqual(self.reads, 1)
        self.worker.assert_not_awaited()

    async def test_disconnect_and_receive_failure_have_fixed_safe_refusals(self):
        for options in ({"disconnected": True}, {"failure": RuntimeError(SECRET)}):
            self.assertEqual(await self.request(**options),
                (400, {"detail": "operator catalog status body unavailable"}))
        self.worker.assert_not_awaited()

    async def test_authentication_and_role_precede_stream_or_service_access(self):
        self.assertEqual(await self.request(authenticate=False, stalled=True),
            (401, {"detail": "administrator authentication required"}))
        with patch.object(auth, "ADMIN_ROLES", ("auditor",)):
            self.assertEqual(await self.request(stalled=True),
                (403, {"detail": "administrator access required"}))
        self.assertEqual(self.reads, 0)
        self.worker.assert_not_awaited()

    async def test_github_app_unavailable_uses_imported_exception_and_fixed_503(self):
        self.worker.side_effect = GitHubAppUnavailable(SECRET)
        self.assertEqual(await self.request(method="POST"), (503, {"detail":
            "GitHub App verification failed; check app, installation and repository permissions"}))
        self.worker.assert_awaited_once()
        function, payload, actor = self.worker.await_args.args
        self.assertIs(function, mutations.create_credential)
        self.assertEqual(actor, ACTOR)
        self.assertEqual(payload.secret, SECRET)

    async def test_value_error_is_not_masked_by_an_unbound_prior_exception_clause(self):
        self.worker.side_effect = ValueError(SECRET)
        self.assertEqual(await self.request(method="POST"),
            (422, {"detail": "invalid operator catalog input or unsupported policy"}))
        self.worker.assert_awaited_once()


if __name__ == "__main__":
    unittest.main(verbosity=2)
