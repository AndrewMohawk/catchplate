#!/usr/bin/env python3
"""Closed capability route controls plus real ordinary-runner loopback HTTP.

The small ASGI app selects the actual route source, with explicit identity
doubles only for role/error branches. The two ordinary tests use the unchanged
real runner, HTTP authentication and fresh SQLite; no native admission, private
review, provider or decision capability is established. Run network-none with
read-only source, allowing only this suite's disposable loopback runner.
"""
from __future__ import annotations

import ast
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import sys
from types import SimpleNamespace
import unittest
from urllib.parse import unquote, urlsplit

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse

import test_operator_demo_runtime as runtime

ROOT = Path(__file__).resolve().parents[1]
PATH = "/api/approvals/capabilities"
EXPECTED = {"schema": "serverware.approvalCapabilities/v1", "can_list": True,
    "can_open_native_review": False, "can_decide": False, "reason": "protected_review_unavailable"}
SOURCE = ast.parse((ROOT / "serverware/app.py").read_text())
ROUTE = next(node for node in SOURCE.body if isinstance(node, ast.FunctionDef)
    and node.name == "approval_capabilities")


class Identity:
    def __init__(self, roles):
        self.roles = frozenset(roles)

    def has_any_role(self, required):
        return "admin" in self.roles or bool(self.roles & required)


class CapabilityRouteTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.identity, self.error, self.auth_calls = Identity({"admin"}), None, 0
        self.app = FastAPI()

        def authenticate():
            self.auth_calls += 1
            if self.error is not None:
                raise self.error
            return self.identity

        def forbidden(*_args, **_kwargs):
            raise AssertionError("capability read attempted authority effects")

        namespace = {"app": self.app, "Request": Request, "Response": Response,
            "AdminIdentity": Identity, "Depends": Depends, "require_admin": authenticate,
            "HTTPException": HTTPException, "JSONResponse": JSONResponse,
            "db": SimpleNamespace(get_approval_request=forbidden,
                get_approval_request_metadata=forbidden, issue_approval_review_receipt=forbidden),
            "bootstrap": forbidden, "get_policy_snapshot": forbidden}
        exec(compile(ast.Module(body=[ROUTE], type_ignores=[]), "<actual-approval-capability-route>", "exec"), namespace)

    async def request(self, method, target, *, content=None, headers=None):
        parsed = urlsplit(target)
        content = b"" if content is None else content
        fields = [(b"host", b"console.example.test")]
        if content:
            fields.append((b"content-length", str(len(content)).encode("ascii")))
        fields.extend((name.encode("ascii"), value.encode("ascii")) for name, value in (headers or {}).items())
        scope = {"type": "http", "asgi": {"version": "3.0", "spec_version": "2.4"},
            "http_version": "1.1", "method": method, "scheme": "https", "path": unquote(parsed.path),
            "raw_path": parsed.path.encode("ascii"), "query_string": parsed.query.encode("ascii"),
            "root_path": "", "headers": fields, "client": ("127.0.0.1", 12345),
            "server": ("console.example.test", 443)}
        messages, reads = [], []

        async def receive():
            reads.append(True)
            return {"type": "http.request", "body": content, "more_body": False}

        async def send(message):
            messages.append(message)

        await self.app(scope, receive, send)
        self.assertEqual(reads, [], "capability route consumed a request body")
        starts = [message for message in messages if message["type"] == "http.response.start"]
        self.assertEqual(len(starts), 1)
        body = b"".join(message.get("body", b"") for message in messages if message["type"] == "http.response.body")
        self.assertLessEqual(len(body), 4096)
        return SimpleNamespace(status_code=starts[0]["status"], content=body,
            headers={name.decode("ascii"): value.decode("ascii") for name, value in starts[0]["headers"]},
            json=lambda: json.loads(body))

    async def test_admin_approver_and_auditor_are_list_only(self):
        for roles in ({"admin"}, {"approver"}, {"auditor"}, {"approver", "auditor"}):
            self.identity = Identity(roles)
            result = await self.request("GET", PATH)
            self.assertEqual(result.status_code, 200)
            self.assertEqual(result.json(), EXPECTED)
            self.assertEqual(result.headers["cache-control"], "no-store")
            self.assertEqual(result.headers["pragma"], "no-cache")
            self.assertTrue(all(type(result.json()[key]) is bool
                for key in ("can_list", "can_open_native_review", "can_decide")))
        self.assertEqual(self.auth_calls, 4)

    async def test_authenticated_other_role_is_explicitly_unavailable(self):
        for roles in (set(), {"policy_author"}, {"credential_owner"}):
            self.identity = Identity(roles)
            result = await self.request("GET", PATH)
            self.assertEqual(result.status_code, 200)
            self.assertEqual(result.json(), {**EXPECTED, "can_list": False, "reason": "role_required"})

    async def test_authentication_failure_does_not_return_capabilities(self):
        for code in (401, 403, 503):
            self.error = HTTPException(code, "authentication unavailable")
            result = await self.request("GET", PATH + "?ignored=1")
            self.assertEqual(result.status_code, code)
            self.assertEqual(result.json(), {"detail": "authentication unavailable"})

    async def test_query_body_and_raw_alias_refused(self):
        for target, body in ((PATH + "?native=true", None), (PATH, b"private-body-canary"),
                (PATH.replace("capabilities", "%63apabilities"), None)):
            result = await self.request("GET", target, content=body)
            self.assertEqual(result.status_code, 400)
            self.assertEqual(result.headers["cache-control"], "no-store")
            self.assertNotIn(b"private-body-canary", result.content)
        result = await self.request("GET", PATH, headers={"transfer-encoding": "chunked"})
        self.assertEqual(result.status_code, 400)

    async def test_other_methods_are_not_capability_authority(self):
        for method in ("POST", "PUT", "DELETE"):
            result = await self.request(method, PATH, content=b"private-body-canary")
            self.assertEqual(result.status_code, 405)
            self.assertNotIn(b"private-body-canary", result.content)
        self.assertEqual(self.auth_calls, 0)

    async def test_route_only_observes_opening_availability_without_bootstrap(self):
        # Permit only the observational owner-availability API, never startup,
        # private reads, authorization, receipt issuance or authority dispatch.
        calls = {ast.unparse(node.func) for node in ast.walk(ROUTE) if isinstance(node, ast.Call)}
        self.assertEqual(calls, {"app.get", "Depends", "request.scope.get", "request.headers.get",
            "HTTPException", "identity.has_any_role", "native_review.available", "JSONResponse"})
        imports = [node for node in ast.walk(ROUTE) if isinstance(node, ast.ImportFrom)]
        self.assertEqual(len(imports), 1)
        self.assertEqual((imports[0].level, imports[0].module), (0, "serverware"))
        self.assertEqual([(alias.name, alias.asname) for alias in imports[0].names],
            [("control_plane_native_jit_review", "native_review")])
        self.assertFalse(any(isinstance(node, (ast.Import, ast.Await)) for node in ast.walk(ROUTE)))


class OrdinaryCapabilityHTTPTests(unittest.TestCase):
    setUp = runtime.OperatorDemoRuntimeTests.setUp
    runner = runtime.OperatorDemoRuntimeTests.runner
    request = runtime.OperatorDemoRuntimeTests.request

    def snapshot(self):
        path = self.directory / "data" / "serverware.sqlite3"
        with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)) as connection:
            connection.execute("BEGIN")
            tables = [row[0] for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")]
            return {table: sorted(connection.execute('SELECT * FROM "' + table.replace('"', '""') + '"').fetchall(), key=repr)
                for table in tables}

    def test_real_admin_http_auth_framing_and_zero_database_changes(self):
        with self.runner():
            before = self.snapshot()
            self.assertIn("approval_requests", before)
            self.assertIn("approval_review_receipts", before)
            self.assertIn("policy_authority_native_jit_review_pairs", before)
            self.assertIn("operator_catalog_state", before)
            for options, status in (({}, 200), ({"auth": False}, 401),
                    ({"body": b"private-body-canary"}, 400)):
                code, body, headers = self.request("GET", PATH, **options)
                self.assertEqual(code, status, body)
                self.assertEqual(headers.get("cache-control"), "no-store")
                self.assertEqual(headers.get("pragma"), "no-cache")
                self.assertNotIn(self.admin.encode(), body)
                self.assertNotIn(b"private-body-canary", body)
                if status == 200:
                    self.assertEqual(json.loads(body), EXPECTED)
            code, body, headers = self.request("GET", PATH + "?native=true")
            self.assertEqual(code, 400, body)
            self.assertEqual(headers.get("cache-control"), "no-store")
            code, body, _ = self.request("GET", "/api/approvals?status=pending")
            self.assertEqual((code, json.loads(body)), (200, []))
            self.assertEqual(self.snapshot(), before)

    def test_real_authenticated_nonreviewer_is_role_required_and_read_only(self):
        self.environment["SERVERWARE_ADMIN_ROLES"] = "policy_author"
        with self.runner():
            before = self.snapshot()
            code, body, headers = self.request("GET", PATH)
            self.assertEqual(code, 200, body)
            self.assertEqual(json.loads(body), {**EXPECTED, "can_list": False, "reason": "role_required"})
            self.assertEqual(headers.get("cache-control"), "no-store")
            code, _, _ = self.request("GET", "/api/approvals?status=pending")
            self.assertEqual(code, 403)
            self.assertEqual(self.snapshot(), before)


if __name__ == "__main__":
    unittest.main(verbosity=2)
