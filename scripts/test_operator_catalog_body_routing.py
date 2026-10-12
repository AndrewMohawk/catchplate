#!/usr/bin/env python3
"""Bounded catalog body ownership through the real full ASGI application.

Run in the approved network-none app image with read-only /app. The cold worker
uses real admission, startup, SQLite, encryption and audit. Only the parser's
30-second timeout duration is accelerated; its cancellation and error path are
real. This is not browser, TCP, provider, proxy, native or deployed acceptance.
"""
from __future__ import annotations

import ast
import asyncio
from contextlib import closing
import inspect
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import textwrap
import traceback
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "scripts")]
import test_operator_workspace_store as workspace
from test_operator_notifications_connected_backend import FAILURE_CONTEXT, FullASGI, require

ORIGIN = "https://console.example.com"
PATH = "/api/operator-demo/credentials"
ADMIN = "synthetic-body-routing-administrator"
SECRET = "synthetic-body-routing-private-credential"
RESULT = "BODY_ROUTING_RESULT "
NETWORK_ATTEMPTS = []


def classification():
    tree = ast.parse((ROOT / "serverware/app.py").read_text())
    selected = [node for node in tree.body if
        isinstance(node, ast.Assign) and any(isinstance(name, ast.Name) and
            name.id == "_OPERATOR_CATALOG_BODY_POST_PATHS" for name in node.targets)
        or isinstance(node, ast.FunctionDef) and node.name == "_operator_catalog_body_is_route_owned"]
    require(len(selected) == 2, "exact body classifier source")
    namespace = {}
    exec(compile(ast.Module(body=selected, type_ignores=[]), "<actual-body-classifier>", "exec"), namespace)
    return namespace["_OPERATOR_CATALOG_BODY_POST_PATHS"], namespace["_operator_catalog_body_is_route_owned"]


def calls(function):
    tree = ast.parse(textwrap.dedent(inspect.getsource(function)))
    # Decorators and Depends defaults establish registration, not handler I/O.
    # Dependency identity is checked separately against the actual route.
    body = ast.Module(body=tree.body[0].body, type_ignores=[])
    return sorted((node.lineno, node.func.id if isinstance(node.func, ast.Name) else node.func.attr)
        for node in ast.walk(body) if isinstance(node, ast.Call)
        and isinstance(node.func, (ast.Name, ast.Attribute)))


def no_network(event, _arguments):
    if event in {"socket.connect", "socket.bind", "socket.getaddrinfo"}:
        NETWORK_ATTEMPTS.append(event)
        raise AssertionError("body routing attempted network contact")


class BodyTransport(FullASGI):
    async def post(self, *, path=PATH, chunks=(), stall=False, authenticate=True,
            origin=ORIGIN, media="application/json", declared=None, delay=0):
        headers = [(b"host", b"console.example.com"), (b"origin", origin.encode()),
            (b"content-type", media.encode())]
        if authenticate:
            headers.append((b"x-serverware-admin-token", self.administrator.encode()))
        if declared is not None:
            headers.append((b"content-length", str(declared).encode()))
        scope = {"type": "http", "asgi": {"version": "3.0", "spec_version": "2.3"},
            "http_version": "1.1", "scheme": "https", "method": "POST", "path": path,
            "raw_path": path.encode(), "root_path": "", "query_string": b"",
            "server": ("console.example.com", 443), "client": ("127.0.0.1", 31001),
            "headers": headers}
        complete, never = asyncio.Event(), asyncio.Event()
        offset, delivered, status = 0, 0, None
        response_headers, body = {}, bytearray()

        async def receive():
            nonlocal offset, delivered
            if offset < len(chunks):
                if delay:
                    await asyncio.sleep(delay)
                chunk = chunks[offset]
                offset += 1
                delivered += len(chunk)
                return {"type": "http.request", "body": chunk,
                    "more_body": offset < len(chunks) or stall}
            if stall:
                await never.wait()
            if not chunks and offset == 0:
                offset += 1
                return {"type": "http.request", "body": b"", "more_body": False}
            await complete.wait()
            return {"type": "http.disconnect"}

        async def send(message):
            nonlocal status, response_headers
            if message["type"] == "http.response.start":
                status = message["status"]
                response_headers = {key.decode().lower(): value.decode()
                    for key, value in message["headers"]}
            elif message["type"] == "http.response.body":
                body.extend(message.get("body", b""))
                require(len(body) <= 64 * 1024, "bounded public response")
                if not message.get("more_body", False):
                    complete.set()

        await asyncio.wait_for(self.app(scope, receive, send), 10)
        require(complete.is_set(), "complete ASGI response")
        for key, value in {"cache-control": "no-store", "pragma": "no-cache",
                "x-content-type-options": "nosniff", "x-frame-options": "DENY",
                "referrer-policy": "no-referrer", "cross-origin-opener-policy": "same-origin",
                "cross-origin-resource-policy": "same-origin",
                "strict-transport-security": "max-age=31536000; includeSubDomains"}.items():
            require(response_headers.get(key) == value, "common response security header")
        require("frame-ancestors 'none'" in response_headers.get("content-security-policy", ""),
            "common content security policy")
        require(SECRET.encode() not in body and ADMIN.encode() not in body, "private response material")
        return status, json.loads(body), delivered


async def connected_story():
    require(ROOT == Path("/app"), "isolated read-only app source required")
    interfaces = {line.split(":", 1)[0].strip() for line in Path("/proc/net/dev").read_text().splitlines()
        if ":" in line}
    require(interfaces == {"lo"}, "network-none required")
    os.umask(0o077)
    sys.addaudithook(no_network)
    Path(os.environ["SERVERWARE_DATA_DIR"]).mkdir(mode=0o700)
    from serverware import operator_demo
    operator_demo.activate()
    from serverware.control_plane_startup import validate_control_plane_startup
    validate_control_plane_startup()
    from serverware import app as application, config, db, operator_demo_store as store
    from serverware import operator_catalog_api as api, operator_catalog_schema as schema
    from serverware import policy_bundle
    app = BodyTransport(application.app, ADMIN)
    await app.start()
    try:
        before = workspace.snapshot(db, catalog=True)
        catalog = workspace.catalog(db, schema)
        policy, high_water = config.POLICY_BUNDLE_PATH.read_bytes(), store.get_policy_high_water()
        with patch.object(api, "_payload", wraps=api._payload) as parser:
            for values, expected in (({"authenticate": False}, 401),
                    ({"origin": "https://foreign.example.com"}, 403)):
                count = parser.await_count
                status, _, delivered = await app.post(stall=True, **values)
                require(status == expected and delivered == 0 and parser.await_count == count,
                    "admission must finish before body parser")
            for values, expected in (({"media": "text/plain"}, 415), ({"declared": 16385}, 413)):
                count = parser.await_count
                status, _, delivered = await app.post(stall=True, **values)
                require(status == expected and delivered == 0 and parser.await_count == count + 1,
                    "route parser must reject headers without waiting for body")
            for raw, expected in ((b"x" * 16385, 413), (b"{", 422),
                    (b'{"name":"first","name":"second"}', 422)):
                count = parser.await_count
                status, _, _ = await app.post(chunks=(raw[:8192], raw[8192:]))
                require(status == expected and parser.await_count == count + 1, "single bounded stream parser")
            budgets = []

            def short_timeout(seconds):
                budgets.append(seconds)
                require(seconds == 30, "production parser timeout changed")
                return asyncio.timeout(0.02)

            count = parser.await_count
            with patch.object(api, "asyncio", SimpleNamespace(timeout=short_timeout)):
                status, body, _ = await app.post(chunks=(b"{",), stall=True)
            require(status == 408 and body == {"detail": "operator catalog request body timed out"}
                and budgets == [30] and parser.await_count == count + 1, "actual stream timeout")
            # These remain outside the roster: the existing operator allowlist
            # or generic 2MiB prebuffer guard still handles them, not _payload.
            count = parser.await_count
            for path, expected in (("/api/operator-demo/credentials/new-unreviewed", 403),
                    ("/api/authority/control-plane/custody", 403),
                    ("/api/operator-demo/oauth/x/configuration/v1", 413)):
                status, _, delivered = await app.post(path=path, declared=2 * 1024**2 + 1, stall=True)
                require(status == expected and delivered == 0 and parser.await_count == count,
                    "unreviewed or authority route changed body owner")
            require(workspace.snapshot(db, catalog=True) == before
                and config.POLICY_BUNDLE_PATH.read_bytes() == policy
                and store.get_policy_high_water() == high_water, "refusal changed state")
            raw = json.dumps({**workspace.review(db, store, schema), "name": "Body routing fixture",
                "auth_type": "bearer", "secret": SECRET}, separators=(",", ":")).encode()
            count = parser.await_count
            status, saved, delivered = await app.post(chunks=(raw[:23], raw[23:]),
                declared=len(raw), delay=0.005)
            require(status == 201 and delivered == len(raw) and parser.await_count == count + 1,
                "valid fragmented body did not use exactly one real parser/save")
        current = workspace.catalog(db, schema)
        require(current["revision"] == catalog["revision"] + 1 and len(current["credentials"]) == 1,
            "one actual credential revision")
        require(current["applications"] == catalog["applications"]
            and current["access_rules"] == catalog["access_rules"]
            and config.POLICY_BUNDLE_PATH.read_bytes() == policy
            and store.get_policy_high_water() == high_water, "save changed unrelated authority")
        events = workspace.rows(db, "audit_events")
        require(len(events) == len(before["audit_events"]) + 1
            and events[-1]["event_type"] == "operator_catalog.credential.created", "one real save audit")
        require(db.get_credential(saved["credential"]["id"], include_secret=True)["secret"] == SECRET,
            "actual encrypted credential readback")
        with closing(db.connect()) as connection:
            require(SECRET not in "\n".join(connection.iterdump()), "plaintext persisted in SQLite")
        require(db.verify_audit_chain().get("ok") is True and not NETWORK_ATTEMPTS, "audit or network boundary")
        workspace.verify_signed(config, db, store, policy_bundle)
        return {"full_asgi": True, "single_parser": True, "bounded_timeout": True,
            "admission_first": True, "security_headers": True, "revision_delta": 1,
            "save_audits": 1, "encrypted_readback": True, "network_attempts": 0}
    finally:
        await app.stop()


class OperatorCatalogBodyRoutingTests(unittest.TestCase):
    def test_exact_registered_roster_and_actual_endpoint_guards(self):
        from serverware import operator_catalog_api as api, operator_notification_api as notifications
        roster, _ = classification()
        self.assertEqual(len(roster), 32)
        self.assertEqual(roster, api.MUTATION_PATHS)
        routes = [route for router in (api.router, notifications.router) for route in router.routes
            if "POST" in route.methods]
        self.assertEqual(len(routes), 32)
        self.assertEqual({route.path for route in routes}, roster)
        for route in routes:
            with self.subTest(path=route.path):
                params = inspect.signature(route.endpoint).parameters
                self.assertEqual(set(params), {"request", "identity"})
                self.assertIs(params["identity"].default.dependency, api._admin_identity)
                sequence = calls(route.endpoint)
                if any(name == "_mutate" for _, name in sequence):
                    self.assertEqual([name for _, name in sequence], ["_mutate"])
                    sequence = calls(api._mutate)
                admit = [line for line, name in sequence if name == "_admit"]
                payload = [line for line, name in sequence if name == "_payload"]
                self.assertEqual(len(admit), 1)
                self.assertEqual(len(payload), 1)
                self.assertLess(admit[0], payload[0])
                self.assertFalse(any(name in {"body", "json", "stream"} for _, name in sequence))

    def test_classifier_is_closed_to_method_path_and_active_profile(self):
        roster, owns = classification()
        for path in roster:
            self.assertTrue(owns("POST", path, operator_active=True))
            for active in (False, None, 1):
                self.assertFalse(owns("POST", path, operator_active=active))
            for method in ("GET", "PUT", "DELETE", "PATCH", "post"):
                self.assertFalse(owns(method, path, operator_active=True))
            for suffix in ("/", "/new", "?x=1"):
                self.assertFalse(owns("POST", path + suffix, operator_active=True))
        for path in (None, b"/api/operator-demo/credentials", "/api/operator-demo/%63redentials",
                "/api/operator-demo/oauth/google/configuration/v2", "/api/operator-demo/oauth/x/configuration/v1",
                "/api/operator-demo/oauth/google/start", "/api/authority/control-plane/custody",
                "/api/webauthn/register/prepare", "/api/operator-demo/catalog"):
            self.assertFalse(owns("POST", path, operator_active=True))

    def test_real_cold_full_asgi_admission_stream_and_commit(self):
        with patch.dict(os.environ, {"TMPDIR": "/tmp"}):
            workspace.common.OperatorDemoPersistenceTests.setUp(self)
        self.environment.update(SERVERWARE_PUBLIC_URL=ORIGIN, SERVERWARE_ADMIN_TOKEN=ADMIN,
            SERVERWARE_ADMIN_USER="body-routing-test", SERVERWARE_ADMIN_ROLES="admin",
            SERVERWARE_DECISION_GATE_BASE="", TMPDIR="/tmp")
        for key in tuple(self.environment):
            if key.lower() in {"http_proxy", "https_proxy", "all_proxy", "no_proxy"}:
                self.environment.pop(key)
        result = subprocess.run([sys.executable, "-B", str(Path(__file__).resolve()), "--worker"],
            cwd=ROOT, env=self.environment, capture_output=True, text=True, timeout=110)
        self.assertNotIn(SECRET, result.stdout + result.stderr)
        self.assertNotIn(ADMIN, result.stdout + result.stderr)
        receipts = [json.loads(line.removeprefix(RESULT)) for line in result.stdout.splitlines()
            if line.startswith(RESULT)]
        self.assertEqual(len(receipts), 1, "missing closed worker receipt")
        self.assertEqual(result.returncode, 0, json.dumps(receipts[0], sort_keys=True))
        self.assertEqual(receipts[0], {"full_asgi": True, "single_parser": True, "bounded_timeout": True,
            "admission_first": True, "security_headers": True, "revision_delta": 1,
            "save_audits": 1, "encrypted_readback": True, "network_attempts": 0})


if __name__ == "__main__":
    if sys.argv[1:] == ["--worker"]:
        signal.alarm(105)
        try:
            receipt = asyncio.run(connected_story())
        except BaseException as error:
            receipt = {"failed": True, "frames": [[Path(frame.filename).name, frame.name, frame.lineno]
                for frame in traceback.extract_tb(error.__traceback__)[-10:]],
                "lifespan_frames": FAILURE_CONTEXT.get("lifespan_frames", [])}
            print(RESULT + json.dumps(receipt, sort_keys=True), flush=True)
            raise SystemExit(1) from None
        print(RESULT + json.dumps(receipt, sort_keys=True), flush=True)
    else:
        unittest.main()
