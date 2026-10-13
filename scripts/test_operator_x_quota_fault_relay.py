"""Pure by default; --loopback requires an isolated no-default-route namespace.

Synthetic app replies test byte preservation/fault mechanics, not production
quota commits or signatures. Joined real-app/Rust acceptance remains separate.
"""
from copy import deepcopy
import json
from pathlib import Path
import socket
import socketserver
import sys
import threading
import time
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts import operator_x_quota_fault_relay as relay

APP_ID = "00000000-0000-4000-8000-000000000001"
RULE_ID = "00000000-0000-4000-8000-000000000002"
RESERVATION_ID = "00000000-0000-4000-8000-000000000003"
SECRET = "synthetic-private-dataplane-token-canary"


def fixture(mode="drop_ack", *, wall=None):
    now = time.time() if wall is None else wall
    arm = {"schema": "serverware.privateXQuotaFaultArm/v1", "mode": mode,
        "principal_id": "agent:operator-demo:" + APP_ID, "route_id": "operator." + RULE_ID,
        "body_sha256": "sha256:" + "1" * 64}
    wire = {"apiVersion": relay.QUOTA_VERSION, "principalId": arm["principal_id"],
        "routeId": arm["route_id"], "policyHash": "sha256:" + "2" * 64,
        "operatorXQuota": {"attemptNonce": "sha256:" + "3" * 64,
            "expiresAtEpochMs": int(now * 1000) + 4500,
            "canonicalRequest": {"request": {"body_sha256": arm["body_sha256"]}}}}
    reservation = {"schema": "serverware.operatorXPostingQuotaReservation/v1",
        "reservation_id": RESERVATION_ID, "bucket_key": "sha256:" + "4" * 64,
        "utc_day": 22000, "expires_at_epoch_ms": wire["operatorXQuota"]["expiresAtEpochMs"],
        "binding_digest": "sha256:" + "5" * 64}
    lease = {"apiVersion": "serverware.operatorXQuotaCredentialLeaseResponse/v1",
        "requestBindingSha256": relay.digest(relay.encoded(wire)), "reservation": reservation,
        "credentialLease": {"synthetic_encrypted_payload": "encrypted-canary"}}
    claim = {"apiVersion": "serverware.operatorXQuotaClaimRequest/v1", "leaseRequest": wire,
        "reservationId": RESERVATION_ID}
    ack = {"apiVersion": "serverware.operatorXQuotaClaimResponse/v1",
        "requestBindingSha256": relay.digest(relay.encoded(wire)),
        "claim": {**reservation, "schema": "serverware.operatorXPostingQuotaClaim/v1",
            "claimed_at_epoch_ms": int(now * 1000)}}
    return arm, wire, lease, claim, ack


def reply(value, status=200):
    body = relay.encoded(value)
    fields = {"content-type": "application/json", "content-length": str(len(body)),
        "x-serverware-response-body-sha256": relay.digest(body),
        "x-serverware-response-key-id": "sha256:" + "6" * 64,
        "x-serverware-response-statement-sha256": "sha256:" + "7" * 64,
        "x-serverware-response-statement-b64": "synthetic-statement",
        "x-serverware-response-signature": "ed25519:" + "a" * 86}
    raw = (f"HTTP/1.1 {status} Synthetic\r\n" + "".join(f"{k}: {v}\r\n" for k, v in fields.items())
        + "\r\n").encode() + body
    return raw, status, fields, body


def request(path, value=None):
    body = b"" if value is None else relay.encoded(value)
    fields = {"host": "127.0.0.1:3001" if path in {relay.ARM, relay.STATUS, relay.RELEASE} else "serverware:3000"}
    if value is not None:
        fields.update({"content-type": "application/json", "content-length": str(len(body))})
    if path in {relay.LEASE, relay.CLAIM, relay.AUDIT}:
        fields.update({"x-serverware-data-plane-token": SECRET, "x-serverware-response-nonce": "n" * 43})
    first = ("GET " if value is None else "POST ") + path + " HTTP/1.1"
    raw = (first + "\r\n" + "".join(f"{k}: {v}\r\n" for k, v in fields.items()) + "\r\n").encode() + body
    return raw, first.encode(), fields, body


def bound(state, data):
    arm, wire, lease, _, _ = data
    state.arm(arm)
    assert state.before(relay.LEASE, relay.encoded(wire))
    raw, status, fields, body = reply(lease)
    assert state.response(relay.LEASE, raw, status, fields, body, time.monotonic() + 3) == raw


def release(state):
    status = state.status()
    return {"schema": "serverware.privateXQuotaFaultRelease/v1", "arm_sha256": status["arm_sha256"],
        "claim_sha256": status["claim_sha256"], "revoked_rule_id": RULE_ID,
        "policy_hash": "sha256:" + "8" * 64, "loaded_policy_hash": "sha256:" + "8" * 64}


class Pure(unittest.TestCase):
    def test_bounded_raw_message_and_framing(self):
        class BytesSocket:
            def __init__(self, raw): self.raw = raw
            def settimeout(self, _): pass
            def recv(self, maximum):
                raw, self.raw = self.raw[:maximum], self.raw[maximum:]
                return raw
        raw, first, fields, body = request(relay.LEASE, {"fixed": "payload"})
        self.assertEqual(relay.read_message(BytesSocket(raw), time.monotonic() + 1, relay.MAX_REQUEST),
            (raw, first, fields, body))
        for malformed in (raw + b"extra", raw[:-1], b"A" * (relay.MAX_HEAD + 5),
                b"HTTP/1.1 200 OK\r\nContent-Length: 262145\r\n\r\n"):
            with self.assertRaises(ValueError):
                relay.read_message(BytesSocket(malformed), time.monotonic() + 1, relay.MAX_RESPONSE)

    def test_closed_routes_headers_and_duplicate_json(self):
        raw, first, fields, body = request(relay.LEASE, {})
        self.assertEqual(relay.admit(first, fields, body), relay.LEASE)
        for start in (b"GET /api/data-plane/credential-leases HTTP/1.1", b"POST http://example.test/ HTTP/1.1",
                b"POST /api/data-plane/credential-leases?x=1 HTTP/1.1"):
            with self.assertRaises(ValueError): relay.admit(start, fields, body)
        for change in ({"host": "example.com"}, {"transfer-encoding": "chunked"}, {"authorization": "secret"}):
            with self.assertRaises(ValueError): relay.admit(first, {**fields, **change}, body)
        for bad in (b'{"a":1,"a":2}', b'{"a":NaN}', b'[]'):
            with self.assertRaises(ValueError): relay.json_body(bad)
        for head in (b'HTTP/1.1 200 OK\r\nContent-Length: 1\r\ncontent-length: 1',
                b'HTTP/1.1 200 OK\r\nContent-Length: 01', b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked'):
            with self.assertRaises(ValueError): relay.headers(head)

    def test_fixed_data_control_separation_and_attestation_query(self):
        self.assertEqual((relay.DATA, relay.CONTROL, relay.APP),
            (("127.0.0.2", 3000), ("127.0.0.1", 3001), ("127.0.0.1", 3000)))
        for path, value, listener in ((relay.STATUS, None, relay.CONTROL),
                (relay.ARM, {}, relay.CONTROL), (relay.RELEASE, {}, relay.CONTROL),
                (relay.LEASE, {}, relay.DATA), (relay.CLAIM, {}, relay.DATA),
                (relay.AUDIT, {}, relay.DATA),
                ("/attestation?nonce=decision-gate-policy-trust-1-1234567890123", None, relay.DATA)):
            _, first, fields, body = request(path, value)
            self.assertEqual(relay.admit(first, fields, body, listener), path)
            other = relay.CONTROL if listener == relay.DATA else relay.DATA
            with self.assertRaises(ValueError): relay.admit(first, fields, body, other)
            # Correcting Host cannot move a route across the listener boundary.
            host = "serverware:3000" if other == relay.DATA else "127.0.0.1:3001"
            with self.assertRaises(ValueError): relay.admit(first, {**fields, "host": host}, body, other)
        for path in ("/attestation", "/attestation?nonce=x", "/attestation?nonce=decision-gate-policy-trust-01-1",
                "/attestation?nonce=decision-gate-policy-trust-1-1&extra=1", "/healthz", "/api/operator-demo"):
            _, first, fields, body = request(path)
            with self.assertRaises(ValueError): relay.admit(first, fields, body)
        _, first, fields, body = request("/attestation?nonce=decision-gate-policy-trust-1-1")
        for change in ({"content-length": "1"}, {"content-length": "00"}, {"content-type": "application/json"},
                {"x-serverware-data-plane-token": SECRET}, {"x-serverware-response-nonce": "n" * 43}):
            with self.assertRaises(ValueError): relay.admit(first, {**fields, **change}, body)
        for path in (relay.AUDIT, relay.LEASE, relay.CLAIM):
            _, first, fields, body = request(path, {})
            for key in ("x-serverware-data-plane-token", "x-serverware-response-nonce"):
                missing = dict(fields); del missing[key]
                with self.assertRaises(ValueError): relay.admit(first, missing, body)

    def test_route_specific_head_first_bounds_preserve_ack_limits(self):
        class HeadSocket:
            def __init__(self, raw): self.raw, self.calls = raw, 0
            def settimeout(self, _): pass
            def recv(self, _):
                self.calls += 1
                if self.calls > 1: raise AssertionError("oversized body must not be read")
                return self.raw
        for path, maximum in ((relay.LEASE, 32768), (relay.CLAIM, 32768), (relay.AUDIT, 1572864)):
            _, first, fields, _ = request(path, {})
            self.assertEqual(relay.request_limit(first, fields, relay.DATA), maximum)
            fields["content-length"] = str(maximum + 1)
            head = first + b"\r\n" + "".join(f"{k}: {v}\r\n" for k, v in fields.items()).encode() + b"\r\n"
            stream = HeadSocket(head)
            with self.assertRaises(ValueError):
                relay.read_message(stream, time.monotonic() + 1,
                    lambda first, fields: relay.request_limit(first, fields, relay.DATA))
            self.assertEqual(stream.calls, 1)
        self.assertEqual(relay.response_limit(relay.LEASE), 262144)
        self.assertEqual(relay.response_limit(relay.CLAIM), 262144)
        self.assertEqual(relay.response_limit(relay.AUDIT), 32768)
        self.assertEqual(relay.response_limit("/attestation?nonce=decision-gate-policy-trust-1-1"), 65536)

    def test_actual_handler_transparently_forwards_only_fixed_auxiliary_routes(self):
        class MemorySocket:
            def __init__(self, raw): self.raw, self.sent = raw, b""
            def settimeout(self, _): pass
            def recv(self, maximum):
                raw, self.raw = self.raw[:maximum], self.raw[maximum:]
                return raw
            def sendall(self, raw): self.sent += raw
            def __enter__(self): return self
            def __exit__(self, *_): pass
        state = relay.State()
        original = state.status()
        for path, value in ((relay.AUDIT, {"events": [], "inert_padding": "x" * 32768}),
                ("/attestation?nonce=decision-gate-policy-trust-1-1234567890123", None)):
            raw = request(path, value)[0]
            response = reply({"actual_synthetic_body": path})[0]
            downstream, upstream = MemorySocket(raw), MemorySocket(response)
            server = type("Server", (), {"state": state, "listener": relay.DATA,
                "deadline": time.monotonic() + 3})()
            with mock.patch.object(relay.socket, "create_connection", return_value=upstream) as connect:
                relay.Handler(downstream, ("127.0.0.1", 10000), server)
            self.assertEqual(connect.call_count, 1)
            self.assertEqual(connect.call_args.args, (relay.APP,))
            self.assertEqual(upstream.sent, raw)
            self.assertEqual(downstream.sent, response)
            self.assertEqual(state.status(), original)
        for path, value in ((relay.STATUS, None), ("/not-admitted", {})):
            downstream = MemorySocket(request(path, value)[0])
            with mock.patch.object(relay.socket, "create_connection") as connect:
                relay.Handler(downstream, ("127.0.0.1", 10000), server)
            connect.assert_not_called()
            self.assertEqual(downstream.sent, b"")

    def test_shared_budget_has_eight_slots_128_requests_and_one_deadline(self):
        with mock.patch.object(relay.time, "monotonic", return_value=100):
            budget = relay.Budget(240)
            self.assertEqual(budget.deadline, 340)
            # Both listeners receive this same budget; neither owns a fresh cap.
            for _ in range(8): self.assertTrue(budget.take())
            self.assertFalse(budget.take())
            for _ in range(8): budget.slots.release()
            for _ in range(119):
                self.assertTrue(budget.take()); budget.slots.release()
            self.assertEqual(budget.accepted, 128)
            self.assertFalse(budget.take())
        with mock.patch.object(relay.time, "monotonic", return_value=340):
            self.assertFalse(budget.take())
            self.assertEqual(budget.deadline, 340)

    def test_one_arm_exact_scope_and_deadline(self):
        state, data = relay.State(), fixture()
        state.arm(data[0])
        with self.assertRaises(ValueError): state.arm(data[0])
        for field in ("principalId", "routeId"):
            altered = deepcopy(data[1]); altered[field] = "other"
            self.assertFalse(state.before(relay.LEASE, relay.encoded(altered)))
        altered = deepcopy(data[1]); altered["operatorXQuota"]["expiresAtEpochMs"] = int(time.time() * 1000) + 9000
        with self.assertRaises(ValueError): state.before(relay.LEASE, relay.encoded(altered))
        self.assertEqual(state.status()["status"], "armed")

    def test_actual_lease_binding_refuses_wrong_ack(self):
        for change in ("digest", "reservation", "expiry", "signature"):
            state, data = relay.State(), fixture()
            state.arm(data[0]); state.before(relay.LEASE, relay.encoded(data[1]))
            value = deepcopy(data[2])
            if change == "digest": value["requestBindingSha256"] = "sha256:" + "0" * 64
            if change == "reservation": value["reservation"]["reservation_id"] = "invalid"
            if change == "expiry": value["reservation"]["expires_at_epoch_ms"] += 1
            raw, status, fields, body = reply(value)
            if change == "signature": del fields["x-serverware-response-signature"]
            with self.assertRaises(ValueError): state.response(relay.LEASE, raw, status, fields, body, time.monotonic() + 3)

    def test_drop_exact_ack_once_and_public_only(self):
        events, data = [], fixture()
        state = relay.State(emit=events.append)
        bound(state, data)
        state.before(relay.CLAIM, relay.encoded(data[3]))
        raw, status, fields, body = reply(data[4])
        self.assertIsNone(state.response(relay.CLAIM, raw, status, fields, body, time.monotonic() + 3))
        self.assertEqual(state.status()["claim_response_sha256"], relay.digest(raw))
        self.assertEqual(state.status()["status"], "dropped")
        with self.assertRaises(ValueError): state.before(relay.CLAIM, relay.encoded(data[3]))
        serialized = relay.encoded({"events": events})
        for canary in (SECRET, "encrypted-canary", APP_ID, RULE_ID, RESERVATION_ID, "ed25519:"):
            self.assertNotIn(canary.encode(), serialized)

    def test_claim_binding_and_failure_never_rearms(self):
        for field in ("reservationId", "leaseRequest"):
            state, data = relay.State(), fixture()
            bound(state, data)
            altered = deepcopy(data[3])
            if field == "reservationId": altered[field] = APP_ID
            else: altered[field]["policyHash"] = "sha256:" + "9" * 64
            with self.assertRaises(ValueError): state.before(relay.CLAIM, relay.encoded(altered))
        state, data = relay.State(), fixture()
        bound(state, data); state.before(relay.CLAIM, relay.encoded(data[3])); state.failed()
        with self.assertRaises(ValueError): state.arm(data[0])
        with self.assertRaises(ValueError): state.before(relay.CLAIM, relay.encoded(data[3]))

    def test_actual_error_response_passes_unchanged_without_fault(self):
        state, data = relay.State(), fixture()
        bound(state, data); state.before(relay.CLAIM, relay.encoded(data[3]))
        raw, status, fields, body = reply({"detail": "synthetic fixed refusal"}, 409)
        self.assertEqual(state.response(relay.CLAIM, raw, status, fields, body, time.monotonic() + 3), raw)
        self.assertEqual(state.status()["status"], "failed")
        with self.assertRaises(ValueError): state.before(relay.CLAIM, relay.encoded(data[3]))

    def test_hold_releases_identical_bytes_only_after_exact_control(self):
        state, data, result = relay.State(), fixture("hold_ack"), []
        bound(state, data); state.before(relay.CLAIM, relay.encoded(data[3]))
        raw, status, fields, body = reply(data[4])
        worker = threading.Thread(target=lambda: result.append(state.response(
            relay.CLAIM, raw, status, fields, body, time.monotonic() + 2)))
        worker.start()
        try:
            with state.condition:
                self.assertTrue(state.condition.wait_for(lambda: state.public["status"] == "held", timeout=1))
            for field, value in (("revoked_rule_id", APP_ID), ("claim_sha256", "sha256:" + "0" * 64),
                    ("loaded_policy_hash", "sha256:" + "0" * 64)):
                wrong = release(state); wrong[field] = value
                with self.assertRaises(ValueError): state.release(wrong)
            same = release(state); same["policy_hash"] = same["loaded_policy_hash"] = data[1]["policyHash"]
            with self.assertRaises(ValueError): state.release(same)
            state.release(release(state)); worker.join(timeout=1)
            self.assertEqual(result, [raw]); self.assertEqual(state.status()["status"], "released")
            with self.assertRaises(ValueError): state.release(release(state))
        finally:
            state.failed(); worker.join(timeout=2)

    def test_hold_expiry_drops_without_deadline_renewal(self):
        state, data = relay.State(), fixture("hold_ack")
        bound(state, data); state.before(relay.CLAIM, relay.encoded(data[3]))
        raw, status, fields, body = reply(data[4])
        original = state.deadline
        self.assertIsNone(state.response(relay.CLAIM, raw, status, fields, body, time.monotonic() + .02))
        self.assertEqual(state.deadline, original); self.assertEqual(state.status()["status"], "expired")
        with self.assertRaises(ValueError): state.release(release(state))


class Loopback(unittest.TestCase):
    def test_real_socket_bytes_drop_and_no_retry(self):
        from scripts.operator_github_fixture_network import assert_isolated_network
        assert_isolated_network(attached=False)
        data, seen = fixture(), []
        attestation = "/attestation?nonce=decision-gate-policy-trust-1-1234567890123"
        replies = {relay.LEASE: data[2], relay.CLAIM: data[4],
            relay.AUDIT: {"synthetic_audit_ack": True}, attestation: {"synthetic_attestation": True}}
        class App(socketserver.BaseRequestHandler):
            def handle(self):
                raw, first, fields, body = relay.read_message(self.request, time.monotonic() + 2, relay.MAX_REQUEST)
                seen.append(raw)
                self.request.sendall(reply(replies[first.split(b" ")[1].decode("ascii")])[0])
        state, budget = relay.State(), relay.Budget(15)
        with socketserver.TCPServer(relay.APP, App) as app, relay.Server(state, budget, relay.DATA) as data_server, \
                relay.Server(state, budget, relay.CONTROL) as control_server:
            servers = (app, data_server, control_server)
            workers = [threading.Thread(target=item.serve_forever, daemon=True) for item in servers]
            for worker in workers: worker.start()
            def send(raw, address=relay.DATA):
                with socket.create_connection(address, timeout=2) as stream:
                    stream.settimeout(2); stream.sendall(raw)
                    result = b""
                    while True:
                        part = stream.recv(65536)
                        if not part: return result
                        result += part
            try:
                auxiliary = []
                for path, value in ((attestation, None), (relay.AUDIT, {"events": []})):
                    raw = request(path, value)[0]
                    self.assertEqual(send(raw), reply(replies[path])[0]); auxiliary.append(raw)
                self.assertEqual(state.status()["status"], "idle")
                self.assertEqual(send(request(relay.STATUS)[0]), b"")
                self.assertTrue(send(request(relay.ARM, data[0])[0], relay.CONTROL).startswith(b"HTTP/1.1 200"))
                lease = request(relay.LEASE, data[1])[0]
                self.assertEqual(send(lease), reply(data[2])[0])
                claim = request(relay.CLAIM, data[3])[0]
                self.assertEqual(send(claim), b""); self.assertEqual(send(claim), b"")
                self.assertEqual(seen, [*auxiliary, lease, claim])
                self.assertEqual(state.status()["status"], "dropped")
                self.assertIs(data_server.budget, control_server.budget)
                self.assertEqual(data_server.deadline, control_server.deadline)
            finally:
                for item in reversed(servers): item.shutdown()
                for worker in workers: worker.join(timeout=3)


if __name__ == "__main__":
    loopback = "--loopback" in sys.argv
    if loopback: sys.argv.remove("--loopback")
    else:
        sys.addaudithook(lambda event, _args: (_ for _ in ()).throw(RuntimeError("network forbidden"))
            if event.startswith("socket.") else None)
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(Pure)
    if loopback: suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(Loopback))
    raise SystemExit(not unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful())
