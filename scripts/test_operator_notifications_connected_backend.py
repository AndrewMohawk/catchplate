#!/usr/bin/env python3
"""Isolated full-app notification acceptance transport, never a live service.

Root must run --serve in a fresh network-none container with frozen /app source.
The browser adapter forwards HTTP bytes to the exact exported ASGI application;
this does not verify browser TCP ingress, uvicorn or a deployed reverse proxy.
Only synthetic notification DNS/address/dial/trust-root seams are substituted.
Application admission, lifespan, API, custody, SQLite and delivery remain real.
--source-digest and --codec-test are pure and do not import application owners.
"""
from __future__ import annotations

import argparse
import asyncio
import base64
from contextlib import ExitStack, closing
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import socket
import ssl
import sys
import threading
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SOURCE_DIRS = ("catchplate", "catchplate_agent_trust", "scripts", "schemas", "policies", "security")
SOURCE_FILES = ("pyproject.toml", "docker-compose.apparmor.yml", "data-plane/decision-gate-rs/src/main.rs")
ORIGIN = "https://console.example.com"
PREFIX = "/api/operator-demo/notifications"
SLOTS = ("action_required.slack", "action_required.webhook", "audit_log.slack", "audit_log.webhook")
URLS = {
    "action_required.slack": "https://hooks.slack.com/services/SYNTHETIC/ACTION/CONNECTED_PRIVATE_ACTION_SLACK",
    "action_required.webhook": "https://receiver.example.test/notification/CONNECTED_PRIVATE_ACTION_WEBHOOK",
    "audit_log.slack": "https://hooks.slack.com/services/SYNTHETIC/AUDIT/CONNECTED_PRIVATE_AUDIT_SLACK",
    "audit_log.webhook": "https://receiver.example.test/notification/CONNECTED_PRIVATE_AUDIT_WEBHOOK",
}
EVENTS = {slot: ("approval.requested" if slot.startswith("action_required") else
    "operator_catalog.application.created" if slot.endswith("webhook") else
    "operator_catalog.application.revoked") for slot in SLOTS}
UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
MAX_MESSAGE = 1024 * 1024
MAX_HTTP_REQUESTS = 100
FAILURE_CONTEXT = {}


def require(condition, label):
    if not condition:
        raise AssertionError(label)


def source_digest(root=ROOT):
    names = list(SOURCE_FILES)
    for directory in SOURCE_DIRS:
        base = root / directory
        require(base.is_dir() and not base.is_symlink(), "source directory unavailable")
        for path in base.rglob("*"):
            require(not path.is_symlink(), "source symlink refused")
            if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc":
                names.append(path.relative_to(root).as_posix())
    digest = hashlib.sha256()
    for name in sorted(names):
        path = root / name
        require(path.is_file() and not path.is_symlink(), "source file unavailable")
        digest.update(name.encode("ascii") + b"\0" + hashlib.sha256(path.read_bytes()).hexdigest().encode("ascii") + b"\n")
    return digest.hexdigest()


def strict_json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate protocol field")
            result[key] = value
        return result
    require(type(raw) is bytes and 0 < len(raw) <= MAX_MESSAGE, "protocol frame size")
    return json.loads(raw, object_pairs_hook=unique,
        parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("nonfinite protocol value")))


def decode_request(value):
    require(type(value) is dict and set(value) == {"id", "op", "method", "path", "headers", "body_b64"}, "HTTP protocol fields")
    require(type(value["id"]) is int and 1 <= value["id"] <= 200 and value["op"] == "http", "HTTP protocol identity")
    method, path = value["method"], value["path"]
    reads = {"/", "/api/operator-demo/catalog", PREFIX}
    mutations = {PREFIX + "/settings": 16384, PREFIX + "/test": 1024, "/api/operator-demo/applications": 16384}
    receipt = (type(path) is str and path.startswith(PREFIX + "/operations/")
        and UUID.fullmatch(path.removeprefix(PREFIX + "/operations/")) is not None)
    require(method == "GET" and (path in reads or receipt) or method == "POST" and path in mutations, "HTTP route refused")
    require(type(value["body_b64"]) is str, "HTTP body encoding")
    raw = base64.b64decode(value["body_b64"], validate=True)
    require(base64.b64encode(raw).decode() == value["body_b64"] and len(raw) <= mutations.get(path, 0), "HTTP body bound")
    headers = value["headers"]
    require(type(headers) is list and len(headers) <= 8, "HTTP header bound")
    allowed = {"origin", "content-type", "content-length", "accept", "referer"}
    seen = set()
    for pair in headers:
        require(type(pair) is list and len(pair) == 2 and all(type(item) is str for item in pair), "HTTP header shape")
        name, content = pair
        require(name in allowed and name not in seen and len(content) <= 2048 and
            all(32 <= ord(c) <= 126 for c in content), "HTTP header refused")
        seen.add(name)
    mapped = dict(headers)
    if method == "POST":
        require(mapped.get("origin") == ORIGIN and mapped.get("content-type") == "application/json", "browser mutation admission")
    require("content-length" not in mapped or mapped["content-length"] == str(len(raw)), "HTTP body framing")
    return method, path, headers, raw


def public_clean(raw):
    if isinstance(raw, (bytes, bytearray, memoryview)):
        raw = bytes(raw)
    else:
        raw = json.dumps(raw, sort_keys=True).encode()
    for secret in [*URLS.values(), "CONNECTED_PRIVATE_", "synthetic-notification-integration-administrator-token"]:
        require(secret.encode() not in raw, "private fixture value exposed")


def unique_response_headers(headers):
    require(len({key.lower() for key, _ in headers}) == len(headers), "duplicate response header transport unsupported")


def codec_test():
    valid = {"id": 1, "op": "http", "method": "GET", "path": PREFIX, "headers": [], "body_b64": ""}
    require(decode_request(valid)[3] == b"", "codec positive")
    invalid = [valid | {"path": "/api/ca.pem"}, valid | {"path": PREFIX + "?x=1"},
        valid | {"body_b64": "YQ=="}, valid | {"headers": [["cookie", "a=b"]]},
        valid | {"headers": [["origin", ORIGIN], ["origin", ORIGIN]]}, valid | {"extra": True},
        valid | {"id": True}, valid | {"path": PREFIX + "/operations/not-a-uuid"}]
    for value in invalid:
        try:
            decode_request(value)
        except (AssertionError, ValueError, TypeError):
            continue
        raise AssertionError("codec refusal missing")
    try:
        strict_json(b'{"id":1,"id":2}')
    except AssertionError:
        pass
    else:
        raise AssertionError("duplicate codec field admitted")
    for buffer_type in (bytes, bytearray, memoryview):
        body = buffer_type(b'{"public":"unchanged"}')
        before = base64.b64encode(body)
        public_clean(body)
        require(base64.b64encode(body) == before, "sanitizer changed response bytes")
        try:
            public_clean(buffer_type(URLS[SLOTS[0]].encode()))
        except AssertionError:
            pass
        else:
            raise AssertionError("byte-like secret exposure admitted")
    public_clean({"public": "unchanged"})
    try:
        public_clean({"private": URLS[SLOTS[0]]})
    except AssertionError:
        pass
    else:
        raise AssertionError("structured secret exposure admitted")
    unique_response_headers([["Cache-Control", "no-store"], ["content-length", "2"]])
    try:
        unique_response_headers([["Cache-Control", "no-store"], ["cache-control", "public"]])
    except AssertionError:
        pass
    else:
        raise AssertionError("case-insensitive response header duplicate admitted")
    return {"pure_codec_cases": 20, "application_imported": any(name.startswith("catchplate.") for name in sys.modules)}


class FullASGI:
    """Raw HTTP and lifespan transport; no handler or success-response mocks."""
    def __init__(self, app, administrator):
        self.app, self.administrator = app, administrator
        self.incoming, self.outgoing = asyncio.Queue(), asyncio.Queue()
        self.task = None

    async def start(self):
        self.task = asyncio.create_task(self.app({"type": "lifespan", "asgi": {"version": "3.0", "spec_version": "2.0"}},
            self.incoming.get, self.outgoing.put))
        await self.incoming.put({"type": "lifespan.startup"})
        result = await asyncio.wait_for(self.outgoing.get(), 45)
        if result["type"] == "lifespan.startup.failed":
            # A lifespan failure embeds an arbitrary exception in its message.
            # Retain only source file/line/function frames, never that message.
            FAILURE_CONTEXT["lifespan_frames"] = re.findall(
                r'File "(/app/[A-Za-z0-9_./-]+\.py)", line (\d+), in ([A-Za-z0-9_<>]+)',
                result.get("message", ""))[-12:]
        require(result["type"] == "lifespan.startup.complete", "actual full-app startup failed")

    async def stop(self):
        require(self.task is not None, "lifespan not started")
        await self.incoming.put({"type": "lifespan.shutdown"})
        result = await asyncio.wait_for(self.outgoing.get(), 20)
        require(result["type"] == "lifespan.shutdown.complete", "actual full-app shutdown failed")
        await asyncio.wait_for(self.task, 5)

    async def request(self, method, path, headers, raw, *, authenticate=True):
        values = [("host", "console.example.com"), *headers]
        if authenticate:
            values.append(("x-catchplate-admin-token", self.administrator))
        scope = {"type": "http", "asgi": {"version": "3.0", "spec_version": "2.3"},
            "http_version": "1.1", "scheme": "https", "method": method, "path": path,
            "raw_path": path.encode("ascii"), "root_path": "", "query_string": b"",
            "server": ("console.example.com", 443), "client": ("127.0.0.1", 31001),
            "headers": [(name.encode("ascii"), value.encode("ascii")) for name, value in values]}
        received = False
        complete = asyncio.Event()
        started = None
        body = bytearray()

        async def receive():
            nonlocal received
            if not received:
                received = True
                return {"type": "http.request", "body": raw, "more_body": False}
            # BaseHTTPMiddleware listens for disconnect concurrently. Sending an
            # immediate fake disconnect can truncate a real streaming response.
            await complete.wait()
            return {"type": "http.disconnect"}

        async def send(message):
            nonlocal started
            if message["type"] == "http.response.start":
                require(started is None, "duplicate ASGI response start")
                started = message
            else:
                require(message["type"] == "http.response.body" and started is not None and not complete.is_set(), "ASGI response framing")
                body.extend(message.get("body", b""))
                require(len(body) <= (524288 if path == "/" else 131072), "ASGI response bound")
                if not message.get("more_body", False):
                    complete.set()
        await asyncio.wait_for(self.app(scope, receive, send), 20)
        require(started is not None and complete.is_set(), "ASGI incomplete response")
        result = {"status": started["status"], "headers": [[key.decode("ascii"), value.decode("latin-1")]
            for key, value in started["headers"]], "body_b64": base64.b64encode(body).decode("ascii")}
        public_clean(body)
        unique_response_headers(result["headers"])
        return result


class Receiver:
    """At most two bounded, real verified-TLS HTTP exchanges on private loopback."""
    def __init__(self, context, ack):
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(2)
        self.listener.settimeout(0.2)
        self.port = self.listener.getsockname()[1]
        self.context, self.ack = context, ack
        self.requests, self.errors = [], []
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.run, name="synthetic-notification-receiver", daemon=True)

    def run(self):
        while not self.stop.is_set():
            try:
                raw, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                require(len(self.requests) < 2, "unexpected additional delivery")
                with raw, self.context.wrap_socket(raw, server_side=True) as conn:
                    conn.settimeout(3)
                    request = bytearray()
                    while b"\r\n\r\n" not in request:
                        chunk = conn.recv(4096)
                        require(bool(chunk), "receiver truncated headers")
                        request.extend(chunk)
                        require(len(request) <= 32768, "receiver header bound")
                    head, body = bytes(request).split(b"\r\n\r\n", 1)
                    pairs = [line.split(b": ", 1) for line in head.split(b"\r\n")[1:]]
                    require(all(len(pair) == 2 for pair in pairs), "receiver header framing")
                    headers = dict(pairs)
                    require(len(headers) == len(pairs), "receiver repeated headers")
                    size = int(headers[b"Content-Length"])
                    require(0 < size <= 16384 and len(body) <= size, "receiver body bound")
                    while len(body) < size:
                        chunk = conn.recv(size - len(body))
                        require(bool(chunk), "receiver truncated body")
                        body += chunk
                    payload = strict_json(body)
                    public_clean(payload)
                    self.requests.append((head, payload))
                    conn.sendall(self.ack)
            except Exception as error:
                self.errors.append(type(error).__name__)
                self.stop.set()

    def close(self):
        self.stop.set()
        self.thread.join(4)
        self.listener.close()
        require(not self.thread.is_alive(), "receiver did not stop")


class Story:
    def __init__(self, fixture, receiver, tls):
        self.fixture, self.receiver, self.tls = fixture, receiver, tls
        self.posts = []
        self.current_checks = []
        self.resolutions = []
        self.connections = []
        self.denied_contacts = []

    def seams(self, stack):
        transport = self.fixture.transport
        original_socket = socket.socket
        story = self

        class FixtureSocket(original_socket):
            def connect(self, address):
                require(address == ("127.0.0.1", 443), "synthetic dial escaped pinned address")
                story.connections.append(address)
                return super().connect(("127.0.0.1", story.receiver.port))

        def resolve(host, port, deadline):
            require(host in {"hooks.slack.com", "receiver.example.test"} and port == 443 and deadline > time.monotonic(), "synthetic DNS target refused")
            story.resolutions.append(host)
            return ((socket.AF_INET, "127.0.0.1"),)

        def addresses(destination, answers):
            require(destination.host in {"hooks.slack.com", "receiver.example.test"} and destination.port == 443
                and answers == ((socket.AF_INET, "127.0.0.1"),), "synthetic address admission refused")

        def context():
            result = ssl.create_default_context(cafile=str(story.tls.root / "cert.pem"))
            result.set_alpn_protocols(["http/1.1"])
            require(result.check_hostname and result.verify_mode == ssl.CERT_REQUIRED, "TLS verification weakened")
            return result

        current = self.fixture.store.current

        def inspect_current(claim, now):
            from catchplate import operator_publication
            try:
                operator_publication.assert_held()
            except operator_publication.PublicationError:
                pass
            else:
                raise AssertionError("publication lock across transport")
            with closing(self.fixture.db.connect()) as conn:
                conn.execute("BEGIN IMMEDIATE")
                conn.rollback()
            self.current_checks.append(claim.delivery_id)
            return current(claim, now)

        def network_guard(event, args):
            if event == "socket.getaddrinfo" or event == "socket.connect" and args[1] != ("127.0.0.1", story.receiver.port):
                story.denied_contacts.append(event)
                raise AssertionError("unlisted network contact refused")
        sys.addaudithook(network_guard)
        stack.enter_context(patch.object(transport, "_resolve", side_effect=resolve))
        stack.enter_context(patch.object(transport, "_admit_addresses", side_effect=addresses))
        stack.enter_context(patch.object(transport, "_tls_context", side_effect=context))
        stack.enter_context(patch.object(transport.socket, "socket", FixtureSocket))
        stack.enter_context(patch.object(self.fixture.store, "current", side_effect=inspect_current))

    def admit_mutation(self, path, raw):
        body = strict_json(raw)
        require(type(body) is dict, "browser mutation object")
        if path == PREFIX + "/settings":
            require(len(self.posts) < 4 and body.get("slot") == SLOTS[len(self.posts)], "save order or count")
            slot = body["slot"]
            require(set(body) == {"operation_id", "slot", "expected_revision", "label", "enabled", "event_types", "max_attempts", "url_action", "url"}, "save fields")
            require(UUID.fullmatch(body["operation_id"]) and body["expected_revision"] == 0 and body["label"] == "Connected " + slot
                and body["enabled"] is True and body["event_types"] == [EVENTS[slot]] and body["max_attempts"] == 1
                and body["url_action"] == "replace" and body["url"] == URLS[slot], "synthetic save contract")
        elif path == PREFIX + "/test":
            require(len(self.posts) == 4 and set(body) == {"operation_id", "slot", "expected_revision"}, "test must be explicit once")
            require(UUID.fullmatch(body["operation_id"]) and body["slot"] == SLOTS[0] and body["expected_revision"] == 1, "test saved binding")
        else:
            require(len(self.posts) == 5 and path == "/api/operator-demo/applications"
                and body.get("name") == "Connected notification audit source" and body.get("token_lifetime_seconds") == 3600, "single audit source mutation")
        # Keep only public operation metadata; never retain URL-bearing bodies.
        public = {key: body[key] for key in ("operation_id", "slot", "expected_revision") if key in body}
        self.posts.append({"path": path, **public})

    def inspect(self, phase):
        f = self.fixture
        require(not self.receiver.errors and not self.denied_contacts, "unexpected receiver or network failure")
        with closing(f.db.connect()) as conn:
            conn.execute("BEGIN")
            dump = "\n".join(conn.iterdump()).encode()
            public_clean(dump)
            configs = [dict(row) for row in conn.execute("SELECT * FROM operator_notification_config ORDER BY slot")]
            operations = [dict(row) for row in conn.execute("SELECT * FROM operator_notification_operations")]
            deliveries = [dict(row) for row in conn.execute("SELECT * FROM operator_notification_deliveries ORDER BY created_ms,delivery_id")]
            attempts = [dict(row) for row in conn.execute("SELECT * FROM operator_notification_attempts ORDER BY started_ms,delivery_id")]
            owner = conn.execute("SELECT owner_id FROM operator_notification_meta").fetchone()[0]
            audit_events = [dict(row) for row in conn.execute("SELECT id,event_type FROM audit_events WHERE event_type='operator_catalog.application.created'")]
            key = f.custody.read(f.directory, owner)
            require(len(configs) == 4, "four independent persisted destinations")
            for row in configs:
                require(row["revision"] == 1 and row["enabled"] == 1 and row["label"] == "Connected " + row["slot"]
                    and json.loads(row["event_types_json"]) == [EVENTS[row["slot"]]] and row["max_attempts"] == 1, "saved slot changed")
                require(f.custody.unseal(key, row["slot"], 1, row["nonce"], row["ciphertext"]) == URLS[row["slot"]], "exact encrypted destination mismatch")
        # Scan actual durable SQLite bytes too, not only its SQL projection.
        for path in f.config.DATA_DIR.glob("catchplate.sqlite3*"):
            require(path.stat().st_size <= 64 * 1024 * 1024, "fixture database size bound")
            public_clean(path.read_bytes())
        expected = {"saved": 0, "tested": 1, "complete": 2}[phase]
        require(len(self.receiver.requests) == len(deliveries) == len(attempts) == expected, "delivery count differs from explicit story")
        require(len(operations) == (4 if phase == "saved" else 5), "operation count differs from explicit story")
        require(len(self.connections) == len(self.resolutions) == expected, "outbound connection count")
        require(len(self.current_checks) == 2 * expected, "dispatch currentness checks")
        require(len(audit_events) == (1 if phase == "complete" else 0), "audit source event count")
        public_deliveries = []
        for row in deliveries:
            require(row["status"] == "acknowledged" and row["attempts"] == 1 and row["last_code"] == "acknowledged"
                and row["http_status"] == 200 and self.current_checks.count(row["delivery_id"]) == 2, "real delivery not acknowledged exactly once")
            attempt = next(item for item in attempts if item["delivery_id"] == row["delivery_id"])
            require(attempt["state"] == "acknowledged" and attempt["attempt"] == 1 and attempt["code"] == "acknowledged"
                and attempt["http_status"] == 200 and attempt["finished_ms"] is not None, "durable ACK attempt missing")
            public_deliveries.append({key: row[key] for key in ("delivery_id", "slot", "revision", "source_event_id", "status", "attempts")})
        if expected:
            test = next(item for item in operations if item["kind"] == "test")
            row = next(item for item in deliveries if item["delivery_id"] == test["delivery_id"])
            require(row["slot"] == SLOTS[0] and row["source_event_id"] == "test:" + test["operation_id"], "test operation-to-delivery join")
            head, payload = self.receiver.requests[0]
            require(head.startswith(b"POST /services/SYNTHETIC/ACTION/CONNECTED_PRIVATE_ACTION_SLACK HTTP/1.1\r\n")
                and b"Host: hooks.slack.com" in head and self.tls.sni[0] == "hooks.slack.com", "Slack TLS destination mismatch")
            require("synthetic notification test" in payload["text"] and payload["mrkdwn"] is False
                and payload["unfurl_links"] is False and payload["unfurl_media"] is False, "real Slack projection mismatch")
        if expected == 2:
            head, payload = self.receiver.requests[1]
            require(head.startswith(b"POST /notification/CONNECTED_PRIVATE_AUDIT_WEBHOOK HTTP/1.1\r\n")
                and b"Host: receiver.example.test" in head and self.tls.sni[1] == "receiver.example.test", "webhook TLS destination mismatch")
            row = next(item for item in deliveries if item["slot"] == "audit_log.webhook")
            require(payload["channel"] == "audit_log" and payload["slot"] == row["slot"] and "test" not in payload
                and payload["delivery_id"] == row["delivery_id"] and payload["source"]["event_id"] == row["source_event_id"]
                and row["source_event_id"] == audit_events[0]["id"] and payload["source"]["event_type"] == EVENTS[row["slot"]]
                and payload["review_url"] == ORIGIN + "/#audit", "committed source-to-webhook join")
        verification = f.db.verify_audit_chain()
        require(verification.get("ok") is True and verification.get("complete") is True, "audit chain incomplete")
        return {"phase": phase, "saved_slots": 4, "encrypted_destinations_exact": True,
            "deliveries": public_deliveries, "tls_sni": list(self.tls.sni), "tls_verification_required": True,
            "audit_chain_verified": True, "outbound_connections": expected, "dispatch_currentness_checks": len(self.current_checks)}


def emit(value):
    raw = json.dumps(value, separators=(",", ":"), allow_nan=False).encode()
    require(len(raw) <= MAX_MESSAGE, "protocol output bound")
    sys.stdout.buffer.write(raw + b"\n")
    sys.stdout.buffer.flush()


async def serve(args):
    require(ROOT == Path("/app") and os.geteuid() == 10001, "backend requires isolated /app and fixture UID")
    interfaces = {line.split(":", 1)[0].strip() for line in Path("/proc/net/dev").read_text().splitlines() if ":" in line}
    require(interfaces == {"lo"}, "backend requires network-none namespace")
    require(source_digest() == args.expected_source_digest, "source digest before startup")
    # Match the existing isolated store worker: SQLite and custody files must
    # be private from creation, before any configured fixture owner imports.
    os.umask(0o077)
    sys.path[:0] = [str(ROOT), str(ROOT / "scripts")]
    import test_operator_notification_integration as integration
    import test_operator_notification_store as fixtures
    import test_operator_notification_transport as tls_fixture
    owner = unittest.TestCase()
    fixtures.configure_environment(owner)
    # Full-app legacy daemon workers have no stop hooks. Leave their temporary
    # files to container disposal, never a TemporaryDirectory finalizer while
    # these threads can still be scheduled during interpreter shutdown.
    owner.scratch._finalizer.detach()
    owner.environment.update(CATCHPLATE_ADMIN_TOKEN=integration.ADMIN, CATCHPLATE_ADMIN_USER="connected-browser-operator",
        CATCHPLATE_ADMIN_ROLES="admin")
    for name in tuple(owner.environment):
        if name.lower() in {"http_proxy", "https_proxy", "all_proxy", "no_proxy"}:
            owner.environment.pop(name)
    os.environ.clear()
    os.environ.update(owner.environment)
    require("CATCHPLATE_OPERATOR_NOTIFICATIONS_PILOT_SOURCE_JSON" not in os.environ, "native source must remain unconfigured")
    fixture = fixtures.Fixture()
    tls_fixture.TlsTests.setUpClass()
    receiver = Receiver(tls_fixture.TlsTests.server_context, integration.ACK)
    story = Story(fixture, receiver, tls_fixture.TlsTests)
    app = None
    started = False
    try:
        with ExitStack() as stack:
            story.seams(stack)
            from catchplate import app as application, operator_notifications
            app = FullASGI(application.app, integration.ADMIN)
            receiver.thread.start()
            await app.start()
            started = True
            require(operator_notifications._THREAD is not None and operator_notifications._THREAD.is_alive(), "lifespan did not start real worker")
            denied = await app.request("GET", PREFIX, [], b"", authenticate=False)
            require(denied["status"] == 401, "real administrator admission missing")
            denied = await app.request("POST", PREFIX + "/settings", [("origin", "https://foreign.example.com"),
                ("content-type", "application/json"), ("content-length", "2")], b"{}")
            require(denied["status"] == 403, "real origin admission missing")
            require(not fixture.key_path.exists(), "startup or rejected request initialized notification custody")
            emit({"type": "ready", "source_digest": args.expected_source_digest, "full_asgi_app": True,
                "lifespan_started": True, "real_admin_origin_refusals": [401, 403], "pid": os.getpid()})
            count, last_id = 0, 0
            while True:
                raw = await asyncio.wait_for(asyncio.to_thread(sys.stdin.buffer.readline, MAX_MESSAGE + 1), 60)
                require(bool(raw) and raw.endswith(b"\n") and len(raw) <= MAX_MESSAGE, "protocol input ended or oversized")
                message = strict_json(raw)
                require(type(message) is dict and type(message.get("id")) is int and message["id"] == last_id + 1, "protocol sequence")
                last_id = message["id"]
                if message.get("op") == "http":
                    count += 1
                    require(count <= MAX_HTTP_REQUESTS, "HTTP request budget exhausted")
                    method, path, headers, body = decode_request(message)
                    if method == "POST":
                        story.admit_mutation(path, body)
                    response = await app.request(method, path, headers, body)
                    emit({"id": last_id, "type": "http", **response})
                elif message.get("op") == "inspect":
                    require(set(message) == {"id", "op", "phase"} and message["phase"] in {"saved", "tested", "complete"}, "inspection protocol")
                    emit({"id": last_id, "type": "inspection", **story.inspect(message["phase"])})
                elif message.get("op") == "shutdown":
                    require(set(message) == {"id", "op"} and len(story.posts) == 6, "incomplete connected story")
                    # Wait for one additional real idle cycle; no direct run_once
                    # call and no manual queue drain can stand in for lifecycle.
                    previous = operator_notifications._LAST_CYCLE
                    deadline = time.monotonic() + 5
                    while operator_notifications._LAST_CYCLE == previous and time.monotonic() < deadline:
                        await asyncio.sleep(0.05)
                    require(operator_notifications._LAST_CYCLE != previous, "real idle worker cycle absent")
                    final = story.inspect("complete")
                    await app.stop()
                    started = False
                    require(not operator_notifications._THREAD.is_alive(), "notification worker survived lifespan shutdown")
                    receiver.close()
                    require(source_digest() == args.expected_source_digest, "source digest after shutdown")
                    emit({"id": last_id, "type": "complete", "lifespan_stopped": True, "notification_worker_stopped": True,
                        "receiver_stopped": True, "source_digest": args.expected_source_digest, "requests": count, **final})
                    return
                else:
                    raise AssertionError("unsupported protocol operation")
    finally:
        if started and app is not None:
            await app.stop()
        if receiver.thread.is_alive():
            receiver.close()
        # Legacy full-app spool/CA/revocation workers have no stop hooks. Their
        # fresh process exits immediately; never remove their data beneath them.
        # Container /tmp is disposed by root after process exit.


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--source-digest", action="store_true")
    modes.add_argument("--codec-test", action="store_true")
    modes.add_argument("--serve", action="store_true")
    parser.add_argument("--expected-source-digest")
    args = parser.parse_args()
    if args.source_digest:
        print(source_digest())
        return
    if args.codec_test:
        print(json.dumps(codec_test()))
        return
    require(args.expected_source_digest is not None and re.fullmatch(r"[0-9a-f]{64}", args.expected_source_digest), "expected immutable source digest required")
    signal.alarm(240)
    try:
        asyncio.run(serve(args))
    except BaseException as error:
        # Never emit arbitrary exceptions, request URLs, keys or HTTP bodies.
        import traceback
        frames = [{"file": Path(frame.filename).name, "line": frame.lineno, "function": frame.name}
            for frame in traceback.extract_tb(error.__traceback__)[-12:]]
        emit({"type": "failed", "error_type": type(error).__name__, "frames": frames, **FAILURE_CONTEXT})
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
