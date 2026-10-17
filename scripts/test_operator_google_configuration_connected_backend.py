#!/usr/bin/env python3
"""One isolated managed-Google browser story against the real full ASGI app.

Run --serve only in the root-approved network-none fixture container. Browser
HTTP bytes cross stdin/stdout unchanged; this does not prove TCP ingress,
deployment, Google consent or cold activation. No successful handler is mocked.
The existing managed fixture supplies real bootstrap, SQLite and key custody.
"""
from __future__ import annotations

import argparse
import asyncio
import base64
from contextlib import closing
import json
import os
from pathlib import Path
import re
import signal
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "scripts")]
from test_operator_notifications_connected_backend import (  # noqa: E402
    FAILURE_CONTEXT, FullASGI, MAX_MESSAGE, emit, require, source_digest, strict_json,
)

ORIGIN = "https://console.example.com"
PREFIX = "/api/operator-demo/oauth/google/configuration/v2"
CATALOG = "/api/operator-demo/catalog"
CLIENT = "123-connected-configuration.apps.googleusercontent.com"
SECRET = "synthetic-connected-Google-application-secret-NEVER-RETAIN"
ADMIN = "synthetic-connected-Google-configuration-administrator"
UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
NETWORK_ATTEMPTS = []


def no_network(event, _arguments):
    if event in {"socket.connect", "socket.bind", "socket.getaddrinfo"}:
        NETWORK_ATTEMPTS.append(event)
        raise AssertionError("connected configuration attempted network contact")


def public_clean(value):
    raw = bytes(value) if isinstance(value, (bytes, bytearray, memoryview)) else json.dumps(value).encode()
    require(SECRET.encode() not in raw and ADMIN.encode() not in raw, "private fixture material exposed")


def decode_request(value):
    require(type(value) is dict and set(value) == {"id", "op", "method", "path", "headers", "body_b64"}, "HTTP fields")
    require(type(value["id"]) is int and 1 <= value["id"] <= 80 and value["op"] == "http", "HTTP identity")
    method, path = value["method"], value["path"]
    receipt = (type(path) is str and path.startswith(PREFIX + "/")
        and UUID.fullmatch(path.removeprefix(PREFIX + "/")) is not None)
    mutations = {PREFIX: 8192, PREFIX + "/cancel": 2048}
    require(method == "GET" and (path in {"/", CATALOG, PREFIX} or receipt)
        or method == "POST" and path in mutations, "HTTP route refused")
    require(type(value["body_b64"]) is str, "body encoding")
    body = base64.b64decode(value["body_b64"], validate=True)
    require(base64.b64encode(body).decode() == value["body_b64"]
        and len(body) <= (mutations[path] if method == "POST" else 0), "body bound")
    headers = value["headers"]
    require(type(headers) is list and len(headers) <= 8, "header count")
    seen = set()
    for pair in headers:
        require(type(pair) is list and len(pair) == 2 and all(type(item) is str for item in pair), "header shape")
        name, content = pair
        require(name in {"origin", "content-type", "content-length", "accept", "referer"}
            and name not in seen and len(content) <= 2048 and all(32 <= ord(c) <= 126 for c in content), "header admission")
        seen.add(name)
    mapped = dict(headers)
    require("content-length" not in mapped or mapped["content-length"] == str(len(body)), "HTTP framing")
    if method == "POST":
        require(mapped.get("origin") == ORIGIN and mapped.get("content-type") == "application/json", "mutation origin/type")
    return method, path, headers, body


class Story:
    def __init__(self, fixture, actor):
        self.fixture, self.actor = fixture, actor
        self.authority = fixture.authority()
        self.posts, self.operation, self.discovery = [], None, None
        self.recovery_reads = 0
        self.pending_inspected = False
        self.custody_before_cancel = None
        require(not (fixture.config.DATA_DIR / "master.key").exists(), "old master key unexpectedly present")

    def before(self, method, path, raw):
        if method != "POST":
            return
        body = strict_json(raw)
        require(type(body) is dict and self.discovery is not None, "mutation requires actual discovery")
        require(body.get("expected_revision") == self.discovery["revision"]
            and body.get("expected_policy_hash") == self.discovery["policy_hash"], "current discovery CAS")
        if path == PREFIX:
            require(not self.posts and self.discovery["state"] == "unconfigured"
                and self.discovery["review"]["eligible"] is True, "exactly one explicit reviewed prepare")
            require(set(body) == {"operation_id", "client_id", "client_secret", "expected_revision",
                "expected_policy_hash", "expected_settings_digest"}, "prepare fields")
            require(UUID.fullmatch(body["operation_id"]) is not None and body["client_id"] == CLIENT
                and body["client_secret"] == SECRET
                and body["expected_settings_digest"] == self.discovery["effective_settings_digest"], "reviewed prepare input")
            self.posts.append({"kind": "prepare", "operation_id": body["operation_id"]})
        else:
            require(len(self.posts) == 1 and self.pending_inspected and self.recovery_reads >= 1, "cancel requires recovered pending state")
            require(set(body) == {"operation_id", "expected_revision", "expected_policy_hash"}
                and body["operation_id"] == self.operation["operation_id"]
                and self.discovery["state"] == "pending", "cancel exact current pending CAS")
            self.posts.append({"kind": "cancel", "operation_id": body["operation_id"]})

    def after(self, method, path, response):
        raw = base64.b64decode(response["body_b64"], validate=True)
        public_clean(raw)
        require(response["status"] == (201 if method == "POST" and path == PREFIX else 200), "actual application refused story request")
        if path == "/":
            return
        headers = {key.lower(): value for key, value in response["headers"]}
        require(headers.get("cache-control") == "no-store", "public API cache boundary")
        value = strict_json(raw)
        if path == PREFIX and method == "GET":
            require(value["schema"] == "catchplate.operatorGoogleConfiguration/v2", "discovery schema")
            require(value["readiness"]["consent_ready"] is False, "no serving claim before restart")
            self.discovery = value
        elif path.startswith(PREFIX) and (method == "POST" or path != PREFIX):
            require(value["schema"] == "catchplate.operatorGoogleManagedSetup/v2"
                and value["setup_contract"] == "catchplate.operatorGoogleManagedSetupBinding/v2"
                and value["activation_receipt"] is None, "exact inactive v2 receipt")
            require(value["operation_id"] == self.posts[0]["operation_id"], "exact operation receipt")
            if method == "POST" and path == PREFIX:
                require(value["status"] == "pending" and value["revision"] == value["staged_revision"]
                    == self.discovery["revision"] + 1, "prepared revision and inactive state")
            if method == "GET":
                self.recovery_reads += 1
            self.operation = value

    def inspect(self, phase):
        f, value = self.fixture, self.operation
        require(phase in {"pending", "cancelled"} and value is not None and value["status"] == phase, "inspection state")
        require(len(self.posts) == (1 if phase == "pending" else 2), "mutation count")
        require(f.authority() == self.authority, "prepare/cancel changed policy, credentials, applications or CA")
        require(not f.profiles.selected() and f.config.GOOGLE_OAUTH_CLIENT_ID == ""
            and f.config.GOOGLE_OAUTH_CLIENT_SECRET == "", "Google hot activation refused")
        require(f.setup.status(value["operation_id"], self.actor) == value, "HTTP receipt differs from retained operation")
        require(f.selected() == (value if phase == "pending" else None), "exact lifecycle selector")
        ref = value["custody_ref"]
        require(ref["config_version"] == 1 and ref["key_source"] == "operator-provider-key-v1" and value["secret_present"], "exact dedicated custody")
        owner = f.setup._admit_managed_owner(ref["owner_id"])
        binding = f.custody.bind_google(owner, config_version=1, public_profile=value["profile_binding"])
        directory = f.keys.admit_directory(os.environ["CATCHPLATE_OPERATOR_PROVIDER_CUSTODY_DIR"], data_directory=f.config.DATA_DIR)
        key = f.keys.read_existing_pinned(directory, ref["owner_id"])
        try:
            with closing(f.db.connect()) as conn:
                conn.execute("PRAGMA query_only=ON")
                conn.execute("BEGIN")
                require(f.custody.read_secret(conn, owner, binding, key=key.material).secret == SECRET, "authenticated exact ciphertext round trip")
                require(conn.execute("SELECT count(*) FROM " + f.custody.TABLE).fetchone()[0] == 1, "single custody version")
                require(SECRET not in "\n".join(conn.iterdump()), "secret stored as plaintext")
                events = [row[0] for row in conn.execute("SELECT event_type FROM audit_events WHERE event_type LIKE 'operator_catalog.google_setup.%' ORDER BY rowid")]
                require(events == ["operator_catalog.google_setup.prepared"] +
                    (["operator_catalog.google_setup.cancelled"] if phase == "cancelled" else []), "exact setup audit history")
            f.keys.check_pin(key)
        finally:
            f.keys.close_pin(key)
        require(not (f.config.DATA_DIR / "master.key").exists(), "legacy master key initialized")
        require({path.name for path in directory.path.iterdir()} == {f.keys.FILENAME}, "dedicated key inventory")
        for suffix in ("", "-wal", "-shm"):
            path = Path(str(f.config.DB_PATH) + suffix)
            if path.exists():
                require(path.stat().st_size <= 32 * 1024**2 and SECRET.encode() not in path.read_bytes(), "plaintext database material")
        retained = f.retained()
        if phase == "pending":
            self.pending_inspected, self.custody_before_cancel = True, retained
        else:
            require(retained == self.custody_before_cancel, "cancel altered retained key/ciphertext/authority")
        require(f.db.verify_audit_chain().get("ok") is True, "real audit chain")
        require(not NETWORK_ATTEMPTS and not f.provider_calls, "provider/network contact")
        return {"phase": phase, "operation_id": value["operation_id"], "encrypted_exact_secret": True,
            "dedicated_key_only": True, "authority_preserved": True, "audit_chain_verified": True,
            "profile_active": False, "provider_calls": 0, "network_calls": 0, "mutations": len(self.posts),
            "recovery_reads": self.recovery_reads}


async def serve(args):
    require(ROOT == Path("/app") and os.geteuid() == 10001, "isolated source/UID required")
    interfaces = {line.split(":", 1)[0].strip() for line in Path("/proc/net/dev").read_text().splitlines() if ":" in line}
    require(interfaces == {"lo"}, "network-none required")
    require(source_digest() == args.expected_source_digest, "source before startup")
    os.umask(0o077)
    os.environ["TMPDIR"] = "/tmp"  # The inspected container's fresh bounded tmpfs only.
    import test_operator_google_managed_config as fixtures
    owner = unittest.TestCase()
    fixtures.ManagedGoogleConfigurationTests.setUp(owner)
    owner.scratch._finalizer.detach()  # Lifespan's legacy daemon threads lack stop hooks.
    owner.environment.update(CATCHPLATE_PUBLIC_URL=ORIGIN, CATCHPLATE_ADMIN_TOKEN=ADMIN,
        CATCHPLATE_ADMIN_USER=fixtures.ACTOR, CATCHPLATE_ADMIN_ROLES="admin")
    for name in tuple(owner.environment):
        if name.lower() in {"http_proxy", "https_proxy", "all_proxy", "no_proxy"}:
            owner.environment.pop(name)
    os.environ.clear()
    os.environ.update(owner.environment)
    sys.addaudithook(no_network)
    fixture = fixtures.Fixture()
    app = FullASGI(fixture.app.app, ADMIN)
    started = False
    try:
        await app.start()
        started = True
        story = Story(fixture, fixtures.ACTOR)
        denied = await app.request("GET", PREFIX, [], b"", authenticate=False)
        require(denied["status"] == 401, "real administrator admission")
        denied = await app.request("POST", PREFIX, [("origin", "https://foreign.example.com"),
            ("content-type", "application/json"), ("content-length", "2")], b"{}")
        require(denied["status"] == 403, "real origin admission")
        require(not list(owner.provider.iterdir()), "read/startup unexpectedly initialized key custody")
        emit({"type": "ready", "source_digest": args.expected_source_digest, "full_asgi_app": True,
            "lifespan_started": True, "real_admin_origin_refusals": [401, 403], "managed_startup": True})
        last_id, requests = 0, 0
        while True:
            raw = await asyncio.wait_for(asyncio.to_thread(sys.stdin.buffer.readline, MAX_MESSAGE + 1), 60)
            require(raw.endswith(b"\n") and 0 < len(raw) <= MAX_MESSAGE, "protocol frame")
            message = strict_json(raw)
            require(type(message) is dict and type(message.get("id")) is int
                and message["id"] == last_id + 1 and message["id"] <= 80, "protocol sequence")
            last_id = message["id"]
            if message.get("op") == "http":
                requests += 1
                require(requests <= 60, "HTTP budget")
                method, path, headers, body = decode_request(message)
                story.before(method, path, body)
                response = await app.request(method, path, headers, body)
                story.after(method, path, response)
                emit({"id": last_id, "type": "http", **response})
            elif message.get("op") == "inspect":
                require(set(message) == {"id", "op", "phase"}, "inspection fields")
                emit({"id": last_id, "type": "inspection", **story.inspect(message["phase"])})
            elif message.get("op") == "shutdown":
                require(set(message) == {"id", "op"}, "shutdown fields")
                final = story.inspect("cancelled")
                await app.stop()
                started = False
                require(not NETWORK_ATTEMPTS and source_digest() == args.expected_source_digest, "final source/network boundary")
                emit({"id": last_id, "type": "complete", "lifespan_stopped": True,
                    "source_digest": args.expected_source_digest, "requests": requests, **final})
                return
            else:
                raise AssertionError("unsupported protocol operation")
    finally:
        if started:
            await app.stop()
        # Root disposes container tmpfs only after process exit, never below workers.


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--source-digest", action="store_true")
    mode.add_argument("--serve", action="store_true")
    parser.add_argument("--expected-source-digest")
    args = parser.parse_args()
    if args.source_digest:
        print(source_digest())
        return
    require(re.fullmatch(r"[0-9a-f]{64}", args.expected_source_digest or "") is not None, "exact source digest required")
    signal.alarm(240)
    try:
        asyncio.run(serve(args))
    except BaseException as error:
        import traceback
        frames = [{"file": Path(frame.filename).name, "line": frame.lineno, "function": frame.name}
            for frame in traceback.extract_tb(error.__traceback__)[-12:]]
        emit({"type": "failed", "error_type": type(error).__name__, "frames": frames, **FAILURE_CONTEXT})
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
