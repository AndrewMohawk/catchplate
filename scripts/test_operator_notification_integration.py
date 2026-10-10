#!/usr/bin/env python3
"""Connected notification acceptance; run only in root's network-none harness.

Real operator admission, admin/origin API checks, SQLite/publication/custody,
worker and verified TLS POST are connected. The API uses ASGI transport; only
the notification fixture's DNS/address admission/dial/trust-root seams map its
exact synthetic hosts to loopback. No provider, live webhook or native pilot is
contacted. This is not deployed or native-action acceptance.
"""
from __future__ import annotations

import asyncio
from contextlib import closing, contextmanager
from dataclasses import dataclass
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import unittest
from unittest.mock import patch
import uuid

import test_operator_notification_store as fixtures
import test_operator_notification_transport as tls_fixture

ROOT = Path(__file__).resolve().parents[1]
PREFIX = "/api/operator-demo/notifications"
ORIGIN = "https://console.example.com"
ADMIN = "synthetic-notification-integration-administrator-token"
WEBHOOK = "https://receiver.example.test/notification/SYNTHETIC_SECRET_URL_CANARY?token=PRIVATE_CANARY"
ACK = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 2\r\n\r\nok"


@dataclass(frozen=True)
class ApiResponse:
    status_code: int
    headers: dict
    content: bytes

    @property
    def text(self):
        return self.content.decode("utf-8")

    def json(self):
        return json.loads(self.content)


class ApiClient:
    """Bounded ASGI client without optional HTTP-client dependencies."""
    def __init__(self, application):
        self.application = application

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return None

    async def request(self, method, path, *, headers=None, payload=None):
        raw = b"" if payload is None else json.dumps(payload).encode("utf-8")
        assert len(raw) <= 16384
        values = {"Host": "console.example.com", **(headers or {})}
        if raw:
            values.update({"Content-Type": "application/json", "Content-Length": str(len(raw))})
        target, _, query = path.partition("?")
        scope = {"type": "http", "asgi": {"version": "3.0", "spec_version": "2.3"},
            "http_version": "1.1", "method": method, "scheme": "https", "root_path": "",
            "path": target, "raw_path": target.encode("ascii"), "query_string": query.encode("ascii"),
            "server": ("console.example.com", 443), "client": ("127.0.0.1", 31001),
            "headers": [(key.lower().encode("ascii"), value.encode("ascii")) for key, value in values.items()]}
        received = False
        started = None
        body = bytearray()
        finished = False

        async def receive():
            nonlocal received
            if received:
                return {"type": "http.disconnect"}
            received = True
            return {"type": "http.request", "body": raw, "more_body": False}

        async def send(message):
            nonlocal started, finished
            if message["type"] == "http.response.start":
                assert started is None and not finished
                started = message
            else:
                assert message["type"] == "http.response.body" and started is not None and not finished
                chunk = message.get("body", b"")
                assert len(body) + len(chunk) <= 131072
                body.extend(chunk)
                finished = not message.get("more_body", False)

        await asyncio.wait_for(self.application(scope, receive, send), timeout=20)
        assert started is not None and finished
        return ApiResponse(started["status"], {
            key.decode("ascii").lower(): value.decode("latin-1") for key, value in started["headers"]}, bytes(body))

    async def get(self, path, *, headers=None):
        return await self.request("GET", path, headers=headers)


@contextmanager
def local_transport(fixture, receiver):
    """Reuse the TLS fixture's precise loopback-only transport test seams."""
    transport = fixture.transport
    original_socket = socket.socket
    connects = []

    class TestSocket(original_socket):
        def connect(self, address):
            assert address == ("127.0.0.1", 443), "fixture attempted a non-loopback connection"
            connects.append(address)
            return super().connect(("127.0.0.1", receiver.port))

    def context():
        result = ssl.create_default_context(cafile=str(tls_fixture.TlsTests.root / "cert.pem"))
        result.set_alpn_protocols(["http/1.1"])
        assert result.check_hostname and result.verify_mode == ssl.CERT_REQUIRED
        return result

    def admission(_destination, answers):
        assert answers == ((socket.AF_INET, "127.0.0.1"),)

    with patch.object(transport, "_resolve", return_value=((socket.AF_INET, "127.0.0.1"),)) as resolver, \
            patch.object(transport, "_admit_addresses", side_effect=admission), \
            patch.object(transport.socket, "socket", TestSocket), \
            patch.object(transport, "_tls_context", side_effect=context):
        yield
    assert resolver.call_count == 1 and connects == [("127.0.0.1", 443)]


def receiver_attempt(fixture):
    from serverware import operator_notifications as notifications, operator_publication

    # A separate SQLite writer and the actual publication assertion prove that
    # the network phase is outside the store's mutation ownership.
    original = fixture.store.current
    inspections = []

    def current(claim, now):
        try:
            operator_publication.assert_held()
        except operator_publication.PublicationError:
            pass
        else:
            raise AssertionError("notification worker retained publication ownership")
        with closing(fixture.db.connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.rollback()
        inspections.append(claim.delivery_id)
        return original(claim, now)

    with tls_fixture._Receiver(tls_fixture.TlsTests.server_context, [ACK]) as receiver:
        with local_transport(fixture, receiver), patch.object(fixture.store, "current", side_effect=current):
            assert notifications.run_once()
    assert not receiver.errors and len(receiver.requests) == 1
    # Once before connection setup and again after TLS, before first HTTP write.
    assert len(inspections) == 2 and inspections[0] == inspections[1]
    head, raw = receiver.requests[0]
    assert b"POST " in head and b"Cookie:" not in head and b"Proxy-Authorization:" not in head
    payload = json.loads(raw)
    fixture.clean_public(payload)
    return head, payload


async def api_tls_flow():
    fixture = fixtures.Fixture()
    from fastapi import FastAPI
    from serverware import operator_notification_api as routes, operator_notifications

    application = FastAPI()
    application.include_router(routes.router)
    saved = {}
    tests = []
    async with ApiClient(application) as client:
        async def request(method, path, body=None, *, authenticated=True, origin=ORIGIN):
            headers = {}
            if authenticated:
                headers["X-Serverware-Admin-Token"] = ADMIN
            if origin is not None:
                headers["Origin"] = origin
            kwargs = {"payload": body} if body is not None else {}
            response = await client.request(method, path, headers=headers, **kwargs)
            fixture.clean_public(response.json())
            assert response.headers.get("cache-control") == "no-store"
            return response

        assert (await request("GET", PREFIX, authenticated=False)).status_code == 401
        assert (await request("POST", PREFIX + "/settings", fixture.payload(), origin="https://foreign.example.com")).status_code == 403
        initial = await request("GET", PREFIX)
        assert initial.status_code == 200 and initial.json()["available"]
        assert not initial.json()["capabilities"]["native_hardware"]["source_available"]
        assert not initial.json()["capabilities"]["action_required"]["source_available"]
        assert not fixture.key_path.exists()

        with patch.object(fixture.transport, "deliver", side_effect=AssertionError("Save sent a message")), \
                patch.object(fixture.transport, "_resolve", side_effect=AssertionError("Save resolved a host")):
            for slot in fixture.store.SLOTS:
                body = fixture.payload(slot, url=fixtures.SLACK_URL if slot.endswith("slack") else WEBHOOK)
                response = await request("POST", PREFIX + "/settings", body)
                assert response.status_code == 200, response.text
                saved[slot] = response.json()
                assert saved[slot]["status"] == "saved"
                located = await request("GET", PREFIX + "/operations/" + body["operation_id"])
                assert located.json() == saved[slot]
            assert fixture.store.status()["queue"]["queued"] == 0
        assert fixture.key_path.exists() and not (fixture.config.DATA_DIR / "master.key").exists()

        # Bad inputs are definitive and secret-safe; a saved-operation conflict
        # remains distinguishable from a new operation's stale revision.
        sample = fixture.payload("audit_log.webhook", url=WEBHOOK)
        bad = await request("POST", PREFIX + "/settings", sample | {"url": "http://receiver.example.test/PRIVATE_CANARY"})
        assert bad.status_code == 422
        stale = await request("POST", PREFIX + "/settings", sample | {"expected_revision": 0})
        assert stale.status_code == 409 and stale.json()["code"] == "notification_revision_conflict"
        repeated = await request("POST", PREFIX + "/settings", sample | {
            "operation_id": saved["audit_log.webhook"]["operation_id"]})
        assert repeated.status_code == 409 and repeated.json()["code"] == "notification_operation_conflict"

        for slot in fixture.store.SLOTS:
            body = {"operation_id": str(uuid.uuid4()), "slot": slot,
                "expected_revision": saved[slot]["revision"]}
            forbidden = await request("POST", PREFIX + "/test", body | {"url": WEBHOOK})
            assert forbidden.status_code == 422
            queued = await request("POST", PREFIX + "/test", body)
            assert queued.status_code == 202 and queued.json()["status"] == "queued"
            before = await request("GET", PREFIX + "/operations/" + body["operation_id"])
            assert before.json() == queued.json()
            head, payload = receiver_attempt(fixture)
            if slot.endswith("webhook"):
                assert payload["test"] is True and payload["slot"] == slot
                assert payload["source"]["event_id"] == "test:" + body["operation_id"]
                assert payload["delivery_id"] == queued.json()["delivery_id"]
                assert payload["review_url"] == ORIGIN + "/#audit"
                assert tls_fixture.TlsTests.sni[-1] == "receiver.example.test"
            else:
                assert b"Host: hooks.slack.com" in head
                assert "synthetic notification test" in payload["text"]
                assert payload["mrkdwn"] is False
                assert tls_fixture.TlsTests.sni[-1] == "hooks.slack.com"
            located = await request("GET", PREFIX + "/operations/" + body["operation_id"])
            assert located.status_code == 200 and located.json()["status"] == "acknowledged"
            assert located.json()["delivery_id"] == queued.json()["delivery_id"]
            tests.append(located.json()["delivery_id"])

        # A real catalog mutation, not a hand-built notification, writes the
        # committed source subsequently projected by the actual worker.
        fixtures.workspace.create_application(fixture.db, fixture.demo, fixture.catalog,
            fixture.inputs, fixture.mutations, name="Notification source application")
        audit_payloads = []
        for _ in range(2):
            head, payload = receiver_attempt(fixture)
            if b"Host: receiver.example.test" in head:
                assert payload["channel"] == "audit_log" and "test" not in payload
                assert payload["source"]["event_type"] == "operator_catalog.application.created"
                assert payload["projection"] in {"approved_fields", "metadata_only"}
                audit_payloads.append(payload)
        assert len(audit_payloads) == 1 and len(set(tests)) == 4
        status = await request("GET", PREFIX)
        assert status.json()["queue"]["acknowledged"] == 6
        with patch.object(fixture.transport, "deliver", side_effect=AssertionError("duplicate source delivery")):
            assert not operator_notifications.run_once()
        assert fixture.db.verify_audit_chain()["ok"]
    return {"api_tls_test_slots": 4, "committed_audit_deliveries": 2,
        "real_admin_origin_and_tls": True, "native_action_source_connected": False}


def api_tls():
    tls_fixture.TlsTests.setUpClass()
    try:
        return asyncio.run(api_tls_flow())
    finally:
        tls_fixture.TlsTests.tearDownClass()


def disabled():
    fixture = fixtures.Fixture()
    from serverware import operator_notifications

    async def inspect_api():
        from fastapi import FastAPI
        from serverware import operator_notification_api
        application = FastAPI()
        application.include_router(operator_notification_api.router)
        async with ApiClient(application) as client:
            response = await client.get(PREFIX, headers={"X-Serverware-Admin-Token": ADMIN})
            assert response.status_code == 200 and response.headers["cache-control"] == "no-store"
            assert response.json()["available"] is False
            assert response.json()["disabled_reason"] == "deployment_disabled"
            assert all(not slot["enabled"] and not slot["secret_present"] for slot in response.json()["slots"])

    before = fixture.snapshot()
    with patch.object(fixture.transport, "deliver", side_effect=AssertionError("disabled delivery")):
        value = operator_notifications.status()
        assert value["available"] is False and value["worker"]["state"] == "disabled"
        assert len(value["slots"]) == 4 and not operator_notifications.start_worker()
        assert not operator_notifications.run_once()
        asyncio.run(inspect_api())
    assert before == fixture.snapshot() and not fixture.key_path.exists()
    with closing(fixture.db.connect()) as conn:
        assert conn.execute("SELECT count(*) FROM sqlite_master WHERE name LIKE 'operator_notification_%'").fetchone()[0] == 0
    return {"default_off_no_initialization_or_worker": True}


def lifecycle():
    fixture = fixtures.Fixture()
    from serverware import operator_notifications as notifications
    with patch.object(notifications, "run_once", return_value=False):
        assert notifications.start_worker()
        first = notifications._THREAD
        assert notifications.start_worker() and notifications._THREAD is first
        notifications.stop_worker()
        assert not first.is_alive()
        assert notifications.start_worker()
        second = notifications._THREAD
        assert second is not first and second.is_alive()
        notifications.stop_worker()
        assert not second.is_alive()
    assert not fixture.key_path.exists()
    return {"sequential_lifespans_restart_without_duplicate_worker": True}


def backpressure():
    fixture = fixtures.Fixture()
    from serverware import operator_notifications as notifications
    fixture.save()
    operation = fixture.test()
    sent = []

    def deliver(_adapter, _url, payload, _policy, *, before_dispatch):
        assert before_dispatch() is True
        sent.append(payload["delivery_id"])
        return fixture.transport.DeliveryResult("acknowledged", "acknowledged", 200)

    with patch.object(fixture.store, "consume_events", side_effect=fixture.store.NotificationConflict(
            "synthetic queue full", code="notification_capacity_conflict")), \
            patch.object(fixture.transport, "deliver", side_effect=deliver):
        assert notifications.run_once()
    assert sent == [operation["delivery_id"]]
    assert fixture.store.operation_status(operation["operation_id"], fixtures.ACTOR)["status"] == "acknowledged"
    assert notifications.status()["worker"]["last_code"] == "notification_source_backlog"
    return {"source_backpressure_still_drains_real_queue": True}


def unknown_and_predispatch():
    fixture = fixtures.Fixture()
    from serverware import operator_notifications as notifications
    fixture.save(max_attempts=3)
    uncertain = fixture.test()
    with patch.object(fixture.transport, "deliver", side_effect=RuntimeError(fixtures.SECRET_URL)) as transport:
        assert notifications.run_once()
        assert not notifications.run_once()
        assert transport.call_count == 1
    receipt = fixture.store.operation_status(uncertain["operation_id"], fixtures.ACTOR)
    assert receipt["status"] == "outcome_unknown"
    fixture.clean_public(receipt)
    pending = fixture.test()
    def connected(_adapter, _url, _payload, _policy, *, before_dispatch):
        # Models destination disable during TLS setup, before any HTTP bytes.
        fixture.save(url_action="keep", url=None, enabled=False)
        assert before_dispatch() is False
        return fixture.transport.DeliveryResult("failed", "dispatch_cancelled")

    with patch.object(fixture.transport, "deliver", side_effect=connected):
        assert notifications.run_once()
    assert fixture.store.operation_status(pending["operation_id"], fixtures.ACTOR)["status"] == "suppressed"
    return {"unknown_not_retried": True, "predispatch_disable_suppresses": True}


class NotificationIntegrationTests(unittest.TestCase):
    def setUp(self):
        fixtures.configure_environment(self)
        self.environment["SERVERWARE_ADMIN_TOKEN"] = ADMIN

    def run_worker(self, name):
        environment = dict(self.environment)
        if name == "disabled":
            environment.pop("SERVERWARE_OPERATOR_NOTIFICATIONS_ENABLED")
        result = subprocess.run([sys.executable, "-B", str(Path(__file__).resolve()), "--worker", name],
            cwd=ROOT, env=environment, capture_output=True, text=True, timeout=75)
        self.assertEqual(result.returncode, 0, "\n".join(result.stderr.splitlines()[-60:]))
        self.assertNotIn("PRIVATE_CANARY", result.stdout)
        return json.loads(result.stdout)

    def test_real_admin_api_four_tests_and_committed_audit_reach_verified_tls(self):
        result = self.run_worker("api-tls")
        self.assertEqual(result["api_tls_test_slots"], 4)
        self.assertEqual(result["committed_audit_deliveries"], 2)

    def test_default_off_has_no_storage_initialization_or_worker(self):
        self.assertTrue(self.run_worker("disabled")["default_off_no_initialization_or_worker"])

    def test_sequential_lifespans_restart_one_worker(self):
        self.assertTrue(self.run_worker("lifecycle")["sequential_lifespans_restart_without_duplicate_worker"])

    def test_full_source_queue_does_not_deadlock_delivery(self):
        self.assertTrue(self.run_worker("backpressure")["source_backpressure_still_drains_real_queue"])

    def test_unknown_receipt_and_final_predispatch_disable(self):
        self.assertTrue(self.run_worker("unknown")["unknown_not_retried"])


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--worker":
        os.umask(0o077)
        actions = {"api-tls": api_tls, "disabled": disabled, "lifecycle": lifecycle,
            "backpressure": backpressure, "unknown": unknown_and_predispatch}
        print(json.dumps(actions[sys.argv[2]](), sort_keys=True))
    else:
        unittest.main()
