#!/usr/bin/env python3
"""Joined ordinary X lifecycle, using real ASGI, custody and SQLite owners.

The provider connection supplies synthetic HTTP wire bytes to the actual
operator_x_transport.send/parser. No CapturedResponse or successful owner
result is constructed by the fixture. Gate health is a separately labelled
synthetic transport. This is not browser, TLS, Rust, SDK, native or live-X
acceptance. Run only in root's bounded network-none, read-only /app image.
"""
from __future__ import annotations

import asyncio
import base64
from contextlib import ExitStack, closing
import hashlib
from http.cookies import SimpleCookie
import json
import math
import os
from pathlib import Path
import signal
import sqlite3
import subprocess
import sys
import threading
import time
import traceback
import unittest
from unittest.mock import patch
from urllib.parse import parse_qsl, quote_plus, urlencode, urlsplit
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "scripts")]
import test_operator_x_configuration_connected as configuration_fixture
from test_operator_notifications_connected_backend import FAILURE_CONTEXT, FullASGI, require

fixtures = configuration_fixture.fixtures
ORIGIN = configuration_fixture.ORIGIN
ADMIN = configuration_fixture.ADMIN
CLIENT = configuration_fixture.CLIENT
SECRET = configuration_fixture.SECRET
PREFIX = "/api/operator-demo/oauth/x"
CALLBACK = "/api/oauth/callback/x"
CATALOG = "/api/operator-demo/catalog"
RESULT = "CONNECTED_X_LIFECYCLE_RESULT "
BINARY = "sha256:" + "7" * 64
CODE = "synthetic-x-connected-authorization-code-PRIVATE"
ACCESS = "synthetic-x-connected-access-token-PRIVATE"
REFRESH = "synthetic-x-connected-refresh-token-PRIVATE"
NEXT_ACCESS = "synthetic-x-connected-next-access-token-PRIVATE"
NEXT_REFRESH = "synthetic-x-connected-next-refresh-token-PRIVATE"
SUBJECT = "18446744073709551001"
NETWORK_ATTEMPTS = []


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def private_clean(value):
    raw = value if type(value) is bytes else encoded(value)
    require(all(secret.encode() not in raw for secret in
        (ADMIN, SECRET, CODE, ACCESS, REFRESH, NEXT_ACCESS, NEXT_REFRESH)),
        "private X material exposed")


def no_network(event, _arguments):
    if event in {"socket.connect", "socket.bind", "socket.getaddrinfo"}:
        NETWORK_ATTEMPTS.append(event)
        raise AssertionError("connected X lifecycle attempted network contact")


def failure_locations(error):
    """Fixed structural diagnostics only; never stringify private exceptions."""
    result, seen = [], set()
    while error is not None and id(error) not in seen and len(result) < 8:
        seen.add(id(error))
        result.append({"type": type(error).__name__, "frames": [
            [Path(frame.filename).name, frame.name, frame.lineno]
            for frame in traceback.extract_tb(error.__traceback__)[-12:]]})
        error = error.__cause__ if error.__cause__ is not None else error.__context__
    return result


class QueryApplication:
    """Encode the raw target into ASGI path/query; do not replace any handler."""
    def __init__(self, application):
        self.application = application

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            target = scope["raw_path"].decode("ascii")
            parsed = urlsplit(target)
            require(not parsed.scheme and not parsed.netloc and not parsed.fragment
                and target.startswith("/") and len(target) <= 16384, "fixture request target")
            scope = {**scope, "path": parsed.path, "raw_path": parsed.path.encode("ascii"),
                "query_string": parsed.query.encode("ascii")}
        await self.application(scope, receive, send)


class WireStream:
    """A bounded synthetic socket seam beneath the actual HTTP sender/parser."""
    def __init__(self, provider):
        self.provider = provider
        self.request = bytearray()
        self.response = None
        self.offset = 0
        self.closed = False

    def settimeout(self, value):
        require(type(value) in {int, float} and math.isfinite(value) and 0 < value <= 20,
            "original provider deadline")

    def sendall(self, value):
        require(not self.closed and self.response is None and type(value) in {bytes, bytearray}
            and len(self.request) + len(value) <= 600_000, "bounded provider request")
        self.request.extend(value)

    def recv(self, maximum):
        require(not self.closed and type(maximum) is int and 0 < maximum <= 16384,
            "bounded provider receive")
        if self.response is None:
            self.response = self.provider.respond(bytes(self.request))
        result = self.response[self.offset:self.offset + min(maximum, 79)]
        self.offset += len(result)
        return result

    def close(self):
        require(not self.closed, "provider stream closed once")
        self.closed = True


class SyntheticProvider:
    """Independent response bytes; real protocol/capture/custody run unchanged."""
    def __init__(self, fixture):
        self.fixture = fixture
        self.streams, self.calls, self.checks = [], [], []
        self.challenge = None
        self.token_case = "valid"
        self.before_response = None
        self.revoke_pairs = []
        self.lock = threading.Lock()

    def connect(self, expires_at):
        require(type(expires_at) in {int, float} and 0 < expires_at - time.monotonic() <= 20,
            "provider connection original deadline")
        self.fixture.store.operator_publication.assert_not_held()
        with closing(self.fixture.db.connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.rollback()
        stream = WireStream(self)
        self.streams.append(stream)
        return stream

    def respond(self, raw):
        require(raw.count(b"\r\n\r\n") == 1, "actual provider HTTP framing")
        head, body = raw.split(b"\r\n\r\n", 1)
        lines = head.split(b"\r\n")
        method, target, version = lines[0].decode("ascii").split(" ")
        pairs = [line.decode("ascii").split(": ", 1) for line in lines[1:]]
        require(all(len(pair) == 2 for pair in pairs), "actual provider header framing")
        headers = {name.lower(): value for name, value in pairs}
        require(len(headers) == len(pairs) and version == "HTTP/1.1"
            and headers.get("host") == "api.x.com" and headers.get("connection") == "close"
            and headers.get("accept") == "application/json", "fixed provider request identity")
        if method == "GET":
            require(target == "/2/users/me" and body == b""
                and set(headers) == {"host", "authorization", "accept", "connection"}
                and headers["authorization"] in {"Bearer " + ACCESS, "Bearer " + NEXT_ACCESS},
                "exact identity request")
            phase = "identity"
            payload = {"data": {"id": SUBJECT, "username": "fixture_user", "name": "Synthetic X user"}}
        else:
            require(method == "POST" and target in {"/2/oauth2/token", "/2/oauth2/revoke"}
                and set(headers) == {"host", "authorization", "accept", "connection",
                    "content-type", "content-length"}
                and headers["content-type"] == "application/x-www-form-urlencoded"
                and headers["content-length"] == str(len(body)), "exact token request framing")
            expected_basic = base64.b64encode((quote_plus(CLIENT, safe="") + ":"
                + quote_plus(SECRET, safe="")).encode("ascii")).decode("ascii")
            require(headers["authorization"] == "Basic " + expected_basic, "original configured client")
            values = parse_qsl(body.decode("ascii"), keep_blank_values=True, strict_parsing=True)
            fields = dict(values)
            require(len(fields) == len(values) and urlencode(fields).encode("ascii") == body,
                "canonical unique provider form")
            if target == "/2/oauth2/revoke":
                phase = "revoke"
                require(set(fields) == {"token", "token_type_hint"}
                    and fields["token"] in {ACCESS, REFRESH, NEXT_ACCESS, NEXT_REFRESH}
                    and fields["token_type_hint"] in {"access_token", "refresh_token"}, "retained revoke input")
                self.revoke_pairs.append((fields["token_type_hint"], fields["token"]))
                payload = {"revoked": True}
            else:
                phase = "code" if fields.get("grant_type") == "authorization_code" else "refresh"
                if phase == "code":
                    require(set(fields) == {"grant_type", "code", "redirect_uri", "code_verifier"}
                        and fields["code"] == CODE and fields["redirect_uri"] == ORIGIN + CALLBACK
                        and base64.urlsafe_b64encode(hashlib.sha256(fields["code_verifier"].encode("ascii")).digest())
                            .rstrip(b"=").decode("ascii") == self.challenge, "original code/PKCE/callback binding")
                else:
                    require(fields == {"grant_type": "refresh_token", "refresh_token": REFRESH},
                        "original refresh token")
                payload = {"access_token": ACCESS if phase == "code" else NEXT_ACCESS,
                    "refresh_token": REFRESH if phase == "code" else NEXT_REFRESH,
                    "token_type": "bearer", "expires_in": 60 if phase == "code" else 3600,
                    "scope": "offline.access tweet.read tweet.write users.read"}
        with self.lock:
            require(len(self.calls) < 12, "bounded lifecycle provider effects")
            self.calls.append(phase)
        check = {"phase": phase, "complete": False}
        self.checks.append(check)
        self.observe_durable(phase)
        if self.before_response is not None:
            self.before_response(phase)
        response = encoded(payload)
        if phase == "code" and self.token_case == "malformed":
            response = b'{"access_token":"' + ACCESS.encode() + b'","refresh_token":"' + REFRESH.encode() + b'"'
        declared = len(response) + (1 if phase == "code" and self.token_case == "truncated" else 0)
        wire = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " \
            + str(declared).encode() + b"\r\nConnection: close\r\n\r\n" + response
        check["complete"] = True
        return wire

    def observe_durable(self, phase):
        from serverware import operator_x_account_store as durable
        self.fixture.store.operator_publication.assert_not_held()
        with closing(self.fixture.db.connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            claims = conn.execute("SELECT * FROM operator_x_account_captures WHERE status='claimed'").fetchall()
            matching = [row for row in claims if row["phase"] == phase
                or phase == "revoke" and row["phase"].startswith("revoke:")]
            require(len(matching) == 1, "one real committed pre-contact claim")
            claim = matching[0]
            row = conn.execute("SELECT * FROM operator_x_account_work WHERE id=?", (claim["work_id"],)).fetchone()
            work = json.loads(row["metadata_json"])
            intent = conn.execute("SELECT * FROM operator_x_account_intents WHERE id=?", (work["operation_id"],)).fetchone()
            require(intent is not None and work["pid"] == os.getpid()
                and work["deadline"] > time.monotonic(), "claimed work original owner/deadline")
            if phase == "code":
                require(intent["status"] == "exchanging" and row["status"] == "exchange_in_flight",
                    "consent consumed before exchange")
            elif phase == "refresh":
                require(row["status"] == "exchange_in_flight" and work["operation"] == "refresh",
                    "refresh reserved before exchange")
            elif phase == "identity":
                require(row["status"] == "material_held", "issued material held before identity")
                token_row = conn.execute("SELECT * FROM operator_x_account_captures WHERE work_id=? AND phase=?",
                    (work["id"], work["operation"])).fetchone()
                require(token_row is not None and token_row["status"] == "captured", "capture committed before identity")
                retained = durable._open(token_row)  # Actual owned-fixture AEAD readback, not an admission mock.
                token = json.loads(base64.b64decode(retained["body"], validate=True))
                require(retained["complete"] is True and retained["matched"] is True
                    and token["access_token"] == (ACCESS if work["operation"] == "code" else NEXT_ACCESS)
                    and token["refresh_token"] == (REFRESH if work["operation"] == "code" else NEXT_REFRESH)
                    and base64.b64decode(retained["wire_prefix"], validate=True).endswith(encoded(token)),
                    "exact encrypted original issuance before identity")
            else:
                require(row["status"] == "cleanup_pending", "cleanup claim after local fence")
                core = conn.execute("SELECT lifecycle_status FROM credentials WHERE id=?", (work["credential_id"],)).fetchone()
                require(core is not None and core[0] == "revocation_pending", "local account fenced before provider revoke")
                resources = self.fixture.schema.read_catalog(conn)
                require(all(rule["status"] != "active" for rule in resources["access_rules"]
                    if rule["credential_id"] == work["credential_id"]), "dependent grants fenced before provider revoke")
            conn.rollback()

    def assert_complete(self):
        require(all(stream.closed for stream in self.streams)
            and all(check["complete"] for check in self.checks), "provider observation was swallowed")


class SyntheticHealth:
    """Actual readiness reader, current local identity, synthetic gate reply."""
    def __init__(self, fixture, original):
        self.fixture, self.original = fixture, original
        self.connections = []

    def connection(self, host, port=None, **options):
        if (host, port, options) == ("api.x.com", 443, {}):
            # Preserve actual HTTP emission inside operator_x_transport.send.
            return self.original(host, port)
        require((host, port, options) == ("127.0.0.1", 9091, {"timeout": 1}), "fixed health destination")
        fixture = self.fixture
        fixture.store.operator_publication.assert_not_held()
        entry = {"requested": False, "closed": False}
        self.connections.append(entry)

        class Connection:
            status = 200

            def request(self, method, path, *, headers):
                require((method, path, headers) == ("GET", "/healthz", {"Connection": "close"})
                    and not entry["requested"], "fixed health request")
                entry["requested"] = True
                from serverware import operator_google_gate_configuration as producer
                from serverware import operator_x_gate_configuration as x_producer
                with fixture.store.operator_publication.exclusive(), closing(fixture.db.connect()) as conn:
                    conn.execute("PRAGMA query_only=ON")
                    conn.execute("BEGIN")
                    identity = producer.expected_identity(conn)
                    x_identity = x_producer.expected_identity(conn)
                    policy = conn.execute("SELECT policy_hash FROM operator_demo_policy WHERE singleton=1").fetchone()[0]
                self.raw = encoded({"ok": True, "policy_hash": policy, "data_plane_binary_digest": BINARY,
                    "policy_shadow": {"managed_google": identity, "managed_x": x_identity},
                    "operator_x_post": {"schema": "serverware.operatorXPostGate/v1",
                        "adapter": "x.post.v1", "operation": "tweets.write"}})

            def getresponse(self):
                require(entry["requested"], "health response ordering")
                return self

            def read(self, bound):
                require(bound == 131073, "health response bound")
                return self.raw

            def close(self):
                require(not entry["closed"], "health connection closed once")
                entry["closed"] = True

        return Connection()


class ResponseLost(RuntimeError):
    pass


class LoseCallbackResponse(QueryApplication):
    """Lose only the actual successful callback's delivery, after its commit."""
    def __init__(self, application):
        super().__init__(application)
        self.armed = False
        self.dropped = False

    async def __call__(self, scope, receive, send):
        target = scope.get("raw_path", b"").split(b"?", 1)[0]
        drop = self.armed and not self.dropped and scope["type"] == "http" and target == CALLBACK.encode()
        status = None

        async def observed(message):
            nonlocal status
            if message["type"] == "http.response.start":
                status = message["status"]
            await send(message)

        await super().__call__(scope, receive, observed)
        if drop:
            require(status == 200, "lost acknowledgement requires real successful callback")
            self.dropped = True
            raise ResponseLost("synthetic completed callback was not delivered")


class Story:
    def __init__(self):
        self.fixture = fixtures.Fixture()
        self.transport = LoseCallbackResponse(self.fixture.app.app)
        self.app = FullASGI(self.transport, ADMIN)
        self.provider = SyntheticProvider(self.fixture)
        self.health = SyntheticHealth(self.fixture, self.fixture.store.http.client.HTTPConnection)
        self.started = self.cookie = None
        self.application = self.rule = None
        self.extra_canaries = []
        self.http_count = 0

    def snapshot(self):
        with closing(self.fixture.db.connect()) as conn:
            return tuple(conn.iterdump()), self.fixture.config.POLICY_BUNDLE_PATH.read_bytes()

    def tables(self):
        with closing(self.fixture.db.connect()) as conn:
            return {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}

    def rows(self, table):
        require(table in {"operator_x_account_intents", "operator_x_account_work", "operator_x_account_captures",
            "credentials", "credential_generations", "audit_events", "operator_catalog_credentials",
            "operator_catalog_applications", "operator_catalog_rules", "operator_demo_policy"}, "fixture table roster")
        with closing(self.fixture.db.connect()) as conn:
            return [dict(row) for row in conn.execute("SELECT * FROM " + table + " ORDER BY rowid")]

    def privacy(self):
        dump, policy = self.snapshot()
        raw = ("\n".join(dump)).encode() + policy
        private_clean(raw)
        require(all(value.encode() not in raw for value in self.extra_canaries),
            "browser/client secret entered durable plaintext")
        for suffix in ("", "-wal", "-shm"):
            path = Path(str(self.fixture.config.DB_PATH) + suffix)
            if path.exists():
                require(path.stat().st_size <= 32 * 1024 * 1024, "bounded plaintext storage inspection")
                private_clean(path.read_bytes())
        fixtures.workspace.verify_signed(self.fixture.config, self.fixture.db,
            self.fixture.store, self.fixture.bundles)

    async def request(self, method, target, *, body=None, expected=200, authenticate=True,
            cookie=None, origin=ORIGIN, json_response=True):
        self.http_count += 1
        require(self.http_count <= 80, "bounded lifecycle HTTP story")
        raw = b"" if body is None else encoded(body)
        headers = []
        if body is not None:
            headers.extend((("origin", origin), ("content-type", "application/json"),
                ("content-length", str(len(raw)))))
        if cookie is not None:
            headers.append(("cookie", cookie))
        response = await self.app.request(method, target, headers, raw, authenticate=authenticate)
        require(response["status"] in (expected if type(expected) is tuple else (expected,)),
            "unexpected actual X HTTP status")
        returned_headers = response["headers"]
        require([value for name, value in returned_headers if name.lower() == "cache-control"] == ["no-store"],
            "X HTTP no-store boundary")
        content = base64.b64decode(response["body_b64"], validate=True)
        private_clean(content)
        return (json.loads(content) if json_response else content), returned_headers

    async def catalog(self):
        value, _ = await self.request("GET", CATALOG)
        require(value["schema"] == "serverware.operatorCatalog/v1", "actual catalog schema")
        return value

    async def review(self):
        value = await self.catalog()
        return {"expected_revision": value["revision"], "expected_policy_hash": value["policy"]["policy_hash"]}

    async def configure(self):
        before = self.snapshot()
        require(not any(name in self.tables() for name in (
            "operator_x_account_intents", "operator_x_account_work", "operator_x_account_captures")),
            "X lifecycle began from seeded records")
        await self.request("GET", configuration_fixture.PREFIX, expected=401, authenticate=False)
        discovered, _ = await self.request("GET", configuration_fixture.PREFIX)
        require(discovered["state"] == "unconfigured" and discovered["configuration"] is None,
            "X configuration must start absent")
        require(self.snapshot() == before and not self.provider.calls, "discovery mutated existing state")
        payload = {**discovered["review"], "operation_id": str(uuid.uuid4()),
            "client_id": CLIENT, "client_secret": SECRET}
        await self.request("POST", configuration_fixture.PREFIX, body=payload,
            expected=403, origin="https://foreign.example.com")
        require(self.snapshot() == before and not self.provider.calls, "origin refusal changed state")
        result, _ = await self.request("POST", configuration_fixture.PREFIX, body=payload, expected=201)
        require(result["status"] == "committed" and result["public_profile"]["client_id"] == CLIENT,
            "actual configured original client")
        self.privacy()

    async def begin(self):
        before_calls = list(self.provider.calls)
        operation_id = str(uuid.uuid4())
        self.started, headers = await self.request("POST", PREFIX + "/start", expected=201,
            body={**await self.review(), "operation_id": operation_id, "name": "Joined synthetic X account"})
        require(self.started["operation_id"] == operation_id and self.started["status"] == "consent_pending",
            "actual consent reservation")
        cookies = [value for name, value in headers if name.lower() == "set-cookie"]
        require(len(cookies) == 1 and all(word in cookies[0].lower()
            for word in ("secure", "httponly", "samesite=lax")), "browser nonce cookie attributes")
        parsed_cookie = SimpleCookie(cookies[0])
        name = "__Host-serverware-x-oauth-" + self.started["state"]
        require(set(parsed_cookie) == {name} and parsed_cookie[name]["path"] == "/", "cookie state/path binding")
        nonce = parsed_cookie[name].value
        require(len(nonce) == 43, "browser nonce size")
        self.extra_canaries.extend((nonce, self.started["state"]))
        self.cookie = name + "=" + nonce
        parsed = urlsplit(self.started["authorization_url"])
        require((parsed.scheme, parsed.netloc, parsed.path, parsed.fragment)
            == ("https", "x.com", "/i/oauth2/authorize", ""), "fixed authorization destination")
        query = dict(parse_qsl(parsed.query, strict_parsing=True))
        require(query["state"] == self.started["state"] and query["client_id"] == CLIENT
            and query["redirect_uri"] == ORIGIN + CALLBACK and query["code_challenge_method"] == "S256"
            and query["scope"] == "offline.access tweet.read tweet.write users.read", "consent original bindings")
        self.provider.challenge = query["code_challenge"]
        require(self.provider.calls == before_calls, "consent reservation contacted provider")
        self.privacy()

    def callback_target(self, **changes):
        return CALLBACK + "?" + urlencode({"state": self.started["state"], "code": CODE, **changes})

    async def callback(self, *, expected=200):
        return await self.request("GET", self.callback_target(), expected=expected,
            authenticate=False, cookie=self.cookie, json_response=False)

    async def operation(self, identifier=None):
        before, calls = self.snapshot(), list(self.provider.calls)
        result, _ = await self.request("GET", PREFIX + "/operations/" + (identifier or self.started["operation_id"]))
        require(self.snapshot() == before and self.provider.calls == calls, "recovery GET produced effects")
        return result

    async def connected(self):
        await self.configure()
        await self.begin()
        html, _ = await self.callback()
        require(b"X account connected" in html, "actual callback success document")
        result = await self.operation()
        require(result["status"] == "connected" and result["credential_id"] is not None,
            "actual atomic connected outcome")
        require(self.provider.calls == ["code", "identity"], "single code exchange and identity")
        return result["credential_id"]

    async def grant(self, credential_id):
        catalog = await self.catalog()
        account = next(row for row in catalog["credentials"] if row["id"] == credential_id)
        require(account["auth_type"] == "x_oauth" and account["connection_type"] == "x_user_oauth_v1"
            and account["provider_id"] == "x" and account["provider_subject"] == SUBJECT
            and account["provider_account"] == "@fixture_user" and account["credential_generation"] == 1,
            "exact connected public account")
        created, _ = await self.request("POST", "/api/operator-demo/applications", expected=201,
            body={**await self.review(), "name": "Joined X SDK application", "token_lifetime_seconds": 3600,
                "proxy_authentication": "basic_and_bearer_v1"})
        self.application = created["application"]
        self.extra_canaries.append(created["client_token"])
        created, _ = await self.request("POST", "/api/operator-demo/access-rules/x-post", expected=201,
            body={**await self.review(), "name": "Joined exact text-post permission",
                "application_id": self.application["id"], "credential_id": credential_id,
                "operation_bundle": "x_text_post_v1"})
        self.rule = created["access_rule"]
        signed = fixtures.workspace.verify_signed(self.fixture.config, self.fixture.db,
            self.fixture.store, self.fixture.bundles)
        route = next(row for row in signed["routes"] if row["id"] == self.rule["route_id"])
        require(route["adapter"]["type"] == "x.post.v1"
            and route["credentialRef"] == credential_id
            and route["match"]["methods"] == ["POST"] and route["match"]["paths"] == ["/2/tweets"],
            "actual signed exact-post authority")
        self.privacy()

    async def disconnect(self, credential_id):
        before, calls = self.snapshot(), list(self.provider.calls)
        review, _ = await self.request("GET", PREFIX + "/accounts/" + credential_id + "/disconnect-review")
        require(self.snapshot() == before and self.provider.calls == calls, "disconnect review produced effects")
        require(review["affected_credential_ids"] == [credential_id]
            and review["affected_rule_ids"] == [self.rule["id"]], "exact disconnect affected scope")
        payload = {key: review[key] for key in ("credential_id", "expected_credential_generation",
            "expected_revision", "expected_policy_hash", "review_digest")}
        payload["operation_id"] = str(uuid.uuid4())
        operation, _ = await self.request("POST", PREFIX + "/disconnect", body=payload)
        require(operation["operation_id"] == payload["operation_id"], "disconnect operation binding")
        self.privacy()
        return operation, payload

    async def lease_binding(self, credential_id):
        current = await self.catalog()
        application = next(row for row in current["applications"] if row["id"] == self.application["id"])
        rule = next(row for row in current["access_rules"] if row["id"] == self.rule["id"])
        require(application["status"] == rule["status"] == "active"
            and rule["application_id"] == application["id"]
            and rule["credential_id"] == credential_id, "actual active lease authority")
        return {"principal_id": application["principal_id"], "route_id": rule["route_id"],
            "policy_hash": current["policy"]["policy_hash"]}

    def core(self, identifier):
        with closing(self.fixture.db.connect()) as conn:
            row = conn.execute("SELECT * FROM credentials WHERE id=?", (identifier,)).fetchone()
            require(row is not None, "actual X core row retained")
            secret = json.loads(self.fixture.db.decrypt_secret_envelope(row))
            return dict(row), secret

    def inactive(self, identifier):
        with closing(self.fixture.db.connect()) as conn:
            raw = conn.execute("SELECT lifecycle_status FROM credentials WHERE id=?", (identifier,)).fetchone()
            require(raw is None or raw[0] == "revocation_pending", "fenced account reactivated")
            generation = conn.execute("SELECT last_version FROM credential_generations WHERE credential_id=?",
                (identifier,)).fetchone()
            require(generation is not None, "disconnect erased the retained generation floor")
        catalog = fixtures.workspace.catalog(self.fixture.db, self.fixture.schema)
        account = next(row for row in catalog["credentials"] if row["id"] == identifier)
        require(account["status"] in {"quarantined", "revoked"}, "catalog fence missing")
        require(all(row["status"] != "active" for row in catalog["access_rules"]
            if row["credential_id"] == identifier), "fenced permission reactivated")
        signed = fixtures.workspace.verify_signed(self.fixture.config, self.fixture.db,
            self.fixture.store, self.fixture.bundles)
        require(not any(row.get("credentialRef") == identifier for row in signed["routes"]),
            "fenced signed route retained")


async def full_lifecycle(story):
    from serverware import operator_x_refresh as refresh
    credential = await story.connected()
    await story.grant(credential)
    initial, initial_secret = story.core(credential)
    require(initial["credential_version"] == 1 and initial_secret["access_token"] == ACCESS
        and initial_secret["refresh_token"] == REFRESH, "actual first encrypted account material")
    result = await asyncio.to_thread(refresh.prepare_for_lease, credential, 1,
        **await story.lease_binding(credential), deadline=time.monotonic() + 20)
    require(result["credential_version"] == 2 and "secret" not in result
        and result["metadata"]["provider_subject"] == SUBJECT, "real refresh returns only current metadata")
    current, current_secret = story.core(credential)
    require(current["credential_version"] == 2 and current_secret["access_token"] == NEXT_ACCESS
        and current_secret["refresh_token"] == NEXT_REFRESH
        and story.provider.calls == ["code", "identity", "refresh", "identity"], "real refreshed encrypted generation")
    before, calls = story.snapshot(), list(story.provider.calls)
    stale = await asyncio.to_thread(refresh.prepare_for_lease, credential, 1,
        **await story.lease_binding(credential), deadline=time.monotonic() + 20)
    require(stale == result and story.snapshot() == before and story.provider.calls == calls,
        "stale generation caused a repeated refresh")
    operation, payload = await story.disconnect(credential)
    require(operation["status"] == "disconnected", "actual bounded cleanup completion")
    require(set(story.provider.revoke_pairs) == {("access_token", ACCESS), ("refresh_token", REFRESH),
        ("access_token", NEXT_ACCESS), ("refresh_token", NEXT_REFRESH)}
        and len(story.provider.revoke_pairs) == 4, "cleanup includes exact old/new tokens without retries")
    story.inactive(credential)
    retained, calls = story.snapshot(), list(story.provider.calls)
    await story.operation(operation["operation_id"])
    # An acknowledged or lost acknowledgement never grants permission to repeat.
    await story.request("POST", PREFIX + "/disconnect", body=payload, expected=409)
    require(story.snapshot() == retained and story.provider.calls == calls, "duplicate cleanup produced effects")
    return {"connected": True, "refreshed_generation": 2, "dependent_rule_fenced": True,
        "cleanup_contacts": 4, "provider_propagation_proven": False}


async def callback_controls(story):
    await story.configure()
    await story.begin()
    before = story.snapshot()
    targets = ((story.callback_target(), None),
        (story.callback_target(), story.cookie.rsplit("=", 1)[0] + "=" + "x" * 43),
        (story.callback_target() + "&state=" + story.started["state"], story.cookie),
        (story.callback_target() + "&error=access_denied", story.cookie))
    for target, cookie in targets:
        await story.request("GET", target, expected=409, authenticate=False,
            cookie=cookie, json_response=False)
        require(story.snapshot() == before and not story.provider.calls, "invalid callback mutated or dispatched")
    from serverware import operator_x_accounts as service
    try:
        await asyncio.to_thread(service.status, story.started["operation_id"], "other-synthetic-administrator")
    except service.AccountNotFound:
        pass
    else:
        raise AssertionError("foreign actor recovered private operation")
    require(story.snapshot() == before, "foreign recovery changed state")
    outcomes = await asyncio.gather(story.callback(expected=(200, 409)), story.callback(expected=(200, 409)))
    require(sum(b"X account connected" in html for html, _ in outcomes) == 1
        and story.provider.calls == ["code", "identity"], "duplicate callbacks must produce one exchange")
    require((await story.operation())["status"] == "connected", "single winning callback")
    before = story.snapshot()
    await story.callback(expected=409)
    require(story.snapshot() == before and story.provider.calls == ["code", "identity"], "used callback replay")
    return {"binding_refusals": len(targets), "foreign_actor_refused": True, "code_exchanges": 1}


async def retained_uncertainty(story):
    from serverware import operator_x_account_store as durable
    await story.configure()
    await story.begin()
    story.transport.armed = True
    try:
        await story.callback()
    except ResponseLost:
        pass
    else:
        raise AssertionError("lost callback response was delivered")
    require(story.transport.dropped and (await story.operation())["status"] == "connected",
        "read-only recovery of actual committed callback")
    calls = list(story.provider.calls)
    await story.callback(expected=409)
    require(story.provider.calls == calls, "lost acknowledgement exchanged again")
    # Real complete malformed JSON and incomplete valid-looking JSON both stay
    # in encrypted custody. Neither is reconstructed as a successful response.
    for case in ("malformed", "truncated"):
        story.provider.token_case = case
        await story.begin()
        before_calls = list(story.provider.calls)
        before_credentials = story.rows("credentials")
        await story.callback(expected=409)
        operation = await story.operation()
        require(operation["status"] == "uncertain" and operation["credential_id"] is None
            and story.provider.calls == before_calls + ["code"]
            and story.rows("credentials") == before_credentials, "uncertain issuance was adopted or identity-read")
        works = [row for row in story.rows("operator_x_account_work")
            if row["operation_id"] == operation["operation_id"]]
        require(len(works) == 1 and works[0]["status"] == "uncertain", "uncertain work retained")
        captures = [row for row in story.rows("operator_x_account_captures") if row["work_id"] == works[0]["id"]]
        require(len(captures) == 1 and captures[0]["status"] == "captured", "uncertain original capture retained")
        capture = durable._open(captures[0])
        wire = base64.b64decode(capture["wire_prefix"], validate=True)
        require(ACCESS.encode() in wire and REFRESH.encode() in wire
            and capture["complete"] is (case == "malformed"), "actual encrypted uncertain wire readback")
        before = story.snapshot()
        await story.callback(expected=409)
        require(story.snapshot() == before and story.provider.calls == before_calls + ["code"],
            "uncertain callback replayed")
    return {"lost_ack_recovered": True, "uncertain_captures_retained": 2, "uncertain_retries": 0}


async def refresh_disconnect_race(story):
    from serverware import operator_x_refresh as refresh
    from serverware import operator_x_account_store as durable
    credential = await story.connected()
    await story.grant(credential)
    entered, release = threading.Event(), threading.Event()

    def paused(phase):
        if phase == "refresh":
            entered.set()
            require(release.wait(15), "bounded refresh response hold")

    story.provider.before_response = paused
    lease_binding = await story.lease_binding(credential)
    task = asyncio.create_task(asyncio.to_thread(refresh.prepare_for_lease,
        credential, 1, **lease_binding, deadline=time.monotonic() + 30))
    try:
        require(await asyncio.to_thread(entered.wait, 10), "actual refresh reached provider")
        # A second caller cannot obtain another dispatch while the first is in flight.
        try:
            await asyncio.to_thread(refresh.prepare_for_lease, credential, 1,
                **lease_binding, deadline=time.monotonic() + 10)
        except refresh.RefreshUnavailable:
            pass
        else:
            raise AssertionError("concurrent refresh obtained a second result")
        require(story.provider.calls.count("refresh") == 1, "concurrent refresh dispatched twice")
        operation, _ = await story.disconnect(credential)
        require(operation["status"] != "disconnected", "pending issuance incorrectly proved complete cleanup")
        story.inactive(credential)
    finally:
        release.set()
    try:
        await asyncio.wait_for(task, 20)
    except refresh.RefreshUnavailable:
        pass
    else:
        raise AssertionError("late refresh reactivated disconnected account")
    story.inactive(credential)
    works = [row for row in story.rows("operator_x_account_work")
        if json.loads(row["metadata_json"])["operation"] == "refresh"]
    require(len(works) == 1 and works[0]["status"] == "uncertain", "late refresh work not held")
    capture_rows = [row for row in story.rows("operator_x_account_captures")
        if row["work_id"] == works[0]["id"] and row["phase"] == "refresh"]
    require(len(capture_rows) == 1 and capture_rows[0]["status"] == "captured", "late issued bytes not retained")
    captured = durable._open(capture_rows[0])
    require(NEXT_ACCESS.encode() in base64.b64decode(captured["wire_prefix"], validate=True),
        "late capture original bytes")
    require(story.provider.calls.count("identity") == 1, "late refresh performed identity/adoption after fence")
    return {"concurrent_refresh_contacts": 1, "late_material_retained": True, "reactivated": False}


STORIES = {"lifecycle": full_lifecycle, "callbacks": callback_controls,
    "uncertainty": retained_uncertainty, "race": refresh_disconnect_race}


def retained_checkpoint():
    """Read-only persisted bytes/identity, before and after actual cold startup."""
    directory = Path(os.environ["SERVERWARE_DATA_DIR"])
    database = directory / "serverware.sqlite3"
    with closing(sqlite3.connect(database.as_uri() + "?mode=ro", uri=True)) as conn:
        logical = tuple(conn.iterdump())
    private_clean("\n".join(logical).encode())
    key = Path(os.environ["SERVERWARE_OPERATOR_X_CUSTODY_DIR"]) / "provider-key.json"
    evidence = configuration_fixture.key_evidence(key)
    return {"database_logical_sha256": hashlib.sha256(encoded(logical)).hexdigest(),
        "policy_sha256": hashlib.sha256((directory / "policy-bundle.json").read_bytes()).hexdigest(),
        "key_identity": list(evidence)}


async def run_story(mode, expected=None):
    require(ROOT == Path("/app") and os.geteuid() == 10001, "isolated root-owned test environment required")
    require({line.split(":", 1)[0].strip() for line in Path("/proc/net/dev").read_text().splitlines()[2:]} == {"lo"},
        "network-none fixture required")
    os.umask(0o077)
    sys.addaudithook(no_network)
    if mode == "reopen":
        require(type(expected) is dict and retained_checkpoint() == expected, "retained cold-start input")
    story = Story()
    from serverware import operator_x_transport as transport
    started = False
    try:
        with ExitStack() as patches:
            patches.enter_context(patch.object(transport, "_connect", side_effect=story.provider.connect))
            patches.enter_context(patch.object(story.fixture.store.http.client, "HTTPConnection",
                side_effect=story.health.connection))
            await story.app.start()
            started = True
            if mode == "reopen":
                before = story.snapshot()
                discovery, _ = await story.request("GET", configuration_fixture.PREFIX)
                require(discovery["state"] == "configured", "configured original client on cold restart")
                await story.catalog()
                require(story.snapshot() == before and not story.provider.calls, "cold recovery GET caused effects")
                result = {"existing_key_retained": True, "read_only_recovery": True}
            else:
                result = await STORIES[mode](story)
            story.provider.assert_complete()
            require(not NETWORK_ATTEMPTS and all(row == {"requested": True, "closed": True}
                for row in story.health.connections), "fixture network or health lifecycle failure")
            story.privacy()
            await story.app.stop()
            started = False
            checkpoint = retained_checkpoint()
            if mode == "reopen":
                require(checkpoint == expected, "cold restart modified retained authority or key")
            return {"story": mode, "full_asgi": True, "real_encrypted_custody": True,
                "synthetic_provider_wire": True, "synthetic_gate_health": True,
                "tls_or_rust_or_sdk_verified": False, "network_attempts": 0,
                "provider_phases": list(story.provider.calls), "checks": result, "retained": checkpoint}
    finally:
        if started:
            await story.app.stop()


class OperatorXLifecycleConnectedTests(unittest.TestCase):
    def setUp(self):
        configuration_fixture.OperatorXConfigurationConnectedTests.setUp(self)
        self.environment.update(SERVERWARE_OPERATOR_DEMO_UPSTREAMS=json.dumps(
            ["https://api.example.com", "https://api.x.com", "https://demo-upstream:8443"]),
            SERVERWARE_DECISION_GATE_BASE="http://127.0.0.1:9091",
            SERVERWARE_EXPECTED_DATA_PLANE_BINARY_DIGEST=BINARY)

    def run_story(self, mode, expected=None):
        process = subprocess.run([sys.executable, "-B", str(Path(__file__).resolve()), "--worker", mode],
            cwd=ROOT, env=self.environment, input=json.dumps(expected), capture_output=True, text=True, timeout=150)
        private_clean((process.stdout + process.stderr).encode())
        lines = [line.removeprefix(RESULT) for line in process.stdout.splitlines() if line.startswith(RESULT)]
        self.assertEqual(len(lines), 1, "worker did not return its closed receipt")
        receipt = json.loads(lines[0])
        # Retain each structural worker receipt so a failed cold reopen cannot
        # hide the preceding completed lifecycle in the parent test's log.
        print(RESULT + json.dumps(receipt, sort_keys=True), flush=True)
        self.assertEqual(process.returncode, 0, json.dumps(receipt, sort_keys=True))
        self.assertEqual(receipt["story"], mode)
        self.assertTrue(receipt["full_asgi"] and receipt["real_encrypted_custody"])
        self.assertFalse(receipt["tls_or_rust_or_sdk_verified"])
        self.assertEqual(receipt["network_attempts"], 0)
        self.assertTrue(receipt["checks"])
        return receipt

    def test_actual_configuration_consent_grant_refresh_disconnect(self):
        result = self.run_story("lifecycle")
        self.run_story("reopen", result["retained"])

    def test_callback_cookie_actor_binding_and_concurrent_one_use(self):
        self.run_story("callbacks")

    def test_lost_callback_ack_and_uncertain_wire_retained_without_replay(self):
        self.run_story("uncertainty")

    def test_refresh_single_flight_disconnect_fences_late_response(self):
        self.run_story("race")


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--worker" and sys.argv[2] in {*STORIES, "reopen"}:
        signal.alarm(140)
        try:
            raw = sys.stdin.buffer.read(8193)
            require(len(raw) <= 8192, "worker input bound")
            outcome = asyncio.run(run_story(sys.argv[2], json.loads(raw)))
        except BaseException as error:
            outcome = {"failed": True, "story": sys.argv[2],
                "frames": [[Path(frame.filename).name, frame.name, frame.lineno]
                for frame in traceback.extract_tb(error.__traceback__)[-12:]],
                "exception_locations": failure_locations(error),
                "lifespan_frames": FAILURE_CONTEXT.get("lifespan_frames", [])}
            print(RESULT + json.dumps(outcome, sort_keys=True), flush=True)
            raise SystemExit(1) from None
        print(RESULT + json.dumps(outcome, sort_keys=True), flush=True)
    else:
        unittest.main(verbosity=2)
