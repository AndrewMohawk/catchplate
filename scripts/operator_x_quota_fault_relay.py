"""Single-use, network-none fixture fault at an actual quota claim ACK.

Raw app request/response bytes are never rewritten, signed, persisted or logged.
Only public hashes/statuses leave State. Signature syntax/body bindings are
checked here; cryptographic verification remains the real gate's responsibility.
The checker proves actual revoke+loaded-policy before sending release: a control
message alone is not policy evidence. Each process admits one arm, even on error.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import signal
import socket
import socketserver
import threading
import time
import uuid
from pathlib import Path

LISTEN, APP = ("127.0.0.1", 3001), ("127.0.0.1", 3000)
LEASE = "/api/data-plane/credential-leases"
CLAIM = "/api/data-plane/operator-x-quota/claim"
ARM, STATUS, RELEASE = "/__fault/arm", "/__fault/status", "/__fault/release"
MAX_HEAD, MAX_REQUEST, MAX_RESPONSE = 16 * 1024, 32 * 1024, 256 * 1024
REQUEST_HEADERS = {"host", "content-length", "content-type", "accept", "accept-encoding",
    "connection", "user-agent", "x-serverware-data-plane-token", "x-serverware-response-nonce"}
QUOTA_VERSION = "serverware.operatorXQuotaCredentialLeaseRequest/v1"


def require(condition):
    if not condition:
        raise ValueError("isolated X quota relay refused")


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False).encode("ascii")


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def json_body(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            require(key not in value)
            value[key] = item
        return value
    require(type(raw) is bytes and len(raw) <= MAX_RESPONSE)
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
        parse_constant=lambda _: require(False))
    require(type(value) is dict)
    return value


def sha(value):
    return type(value) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None


def identifier(value):
    try:
        return type(value) is str and str(uuid.UUID(value)) == value
    except ValueError:
        return False


def headers(head):
    lines = head.split(b"\r\n")
    require(len(head) <= MAX_HEAD and len(lines) <= 40)
    values = {}
    for line in lines[1:]:
        require(b":" in line and not line.startswith((b" ", b"\t")))
        name, value = line.split(b":", 1)
        require(re.fullmatch(rb"[A-Za-z0-9-]{1,64}", name) is not None)
        name, value = name.lower().decode("ascii"), value.strip(b" \t")
        require(name not in values and all(32 <= item < 127 or item == 9 for item in value))
        values[name] = value.decode("ascii")
    require("transfer-encoding" not in values and "content-encoding" not in values)
    length = values.get("content-length", "0")
    require(re.fullmatch(r"0|[1-9][0-9]{0,6}", length) is not None)
    return lines[0], values, int(length)


def read_message(stream, deadline, maximum):
    raw = b""
    while b"\r\n\r\n" not in raw:
        remaining = deadline - time.monotonic()
        require(remaining > 0 and len(raw) <= MAX_HEAD)
        stream.settimeout(remaining)
        part = stream.recv(min(4096, MAX_HEAD + 4 - len(raw)))
        require(bool(part))
        raw += part
    head, body = raw.split(b"\r\n\r\n", 1)
    first, fields, length = headers(head)
    require(length <= maximum and len(body) <= length)
    while len(body) < length:
        remaining = deadline - time.monotonic()
        require(remaining > 0)
        stream.settimeout(remaining)
        part = stream.recv(min(16384, length - len(body)))
        require(bool(part))
        body += part
    return head + b"\r\n\r\n" + body, first, fields, body


def admit(first, fields, body):
    require(first in {b"POST " + path.encode() + b" HTTP/1.1" for path in (LEASE, CLAIM, ARM, RELEASE)}
        | {b"GET " + STATUS.encode() + b" HTTP/1.1"})
    path = first.split(b" ")[1].decode("ascii")
    require(set(fields) <= REQUEST_HEADERS and fields.get("host") in {"serverware:3001", "127.0.0.1:3001"})
    if path == STATUS:
        require(not body and "x-serverware-data-plane-token" not in fields)
    else:
        require(fields.get("content-type") == "application/json" and "content-length" in fields
            and len(body) <= MAX_REQUEST)
    if path in {LEASE, CLAIM}:
        require(0 < len(fields.get("x-serverware-data-plane-token", "")) <= 512
            and re.fullmatch(r"[A-Za-z0-9_-]{43}", fields.get("x-serverware-response-nonce", "")) is not None)
    else:
        require("x-serverware-data-plane-token" not in fields and "x-serverware-response-nonce" not in fields)
    return path


def signed_ack(fields, body):
    # No signing key or credential is read. Preserve the actual proof for gate verification.
    require(fields.get("x-serverware-response-body-sha256") == digest(body)
        and sha(fields.get("x-serverware-response-key-id"))
        and sha(fields.get("x-serverware-response-statement-sha256"))
        and re.fullmatch(r"[A-Za-z0-9_-]{1,12000}", fields.get("x-serverware-response-statement-b64", ""))
        and re.fullmatch(r"ed25519:[A-Za-z0-9_-]{86}", fields.get("x-serverware-response-signature", "")))


class State:
    def __init__(self, *, wall=time.time, monotonic=time.monotonic, emit=lambda _: None):
        self.wall, self.monotonic, self.emit = wall, monotonic, emit
        self.condition = threading.Condition()
        self.arm_value = self.wire = self.reservation = None
        self.deadline = None
        self.public = {"schema": "serverware.privateXQuotaFaultStatus/v1", "status": "idle", "mode": None,
            **{key: None for key in ("arm_sha256", "lease_request_sha256", "lease_response_sha256",
                "claim_request_sha256", "claim_response_sha256", "claim_sha256", "http_status")}}

    def update(self, status, **values):
        self.public.update(status=status, **values)
        self.emit(dict(self.public))
        self.condition.notify_all()

    def status(self):
        with self.condition:
            return dict(self.public)

    def arm(self, value):
        with self.condition:
            require(self.public["status"] == "idle" and type(value) is dict
                and set(value) == {"schema", "mode", "principal_id", "route_id", "body_sha256"}
                and value["schema"] == "serverware.privateXQuotaFaultArm/v1"
                and value["mode"] in {"drop_ack", "hold_ack"}
                and type(value["principal_id"]) is str and value["principal_id"].startswith("agent:operator-demo:")
                and identifier(value["principal_id"].removeprefix("agent:operator-demo:"))
                and type(value["route_id"]) is str and value["route_id"].startswith("operator.")
                and identifier(value["route_id"].removeprefix("operator.")) and sha(value["body_sha256"]))
            self.arm_value = dict(value)
            self.update("armed", mode=value["mode"], arm_sha256=digest(encoded(value)))
            return dict(self.public)

    def before(self, path, raw):
        """Consume exact selected work before app contact; unrelated requests pass."""
        value = json_body(raw)
        wire = value.get("leaseRequest") if path == CLAIM else value
        with self.condition:
            if self.arm_value is None or type(wire) is not dict or wire.get("apiVersion") != QUOTA_VERSION:
                return False
            arm = self.arm_value
            if wire.get("principalId") != arm["principal_id"] or wire.get("routeId") != arm["route_id"]:
                return False
            quota = wire.get("operatorXQuota")
            require(type(quota) is dict)
            if quota.get("canonicalRequest", {}).get("request", {}).get("body_sha256") != arm["body_sha256"]:
                return False
            if path == LEASE:
                require(self.public["status"] == "armed" and sha(quota.get("attemptNonce")) and sha(wire.get("policyHash")))
                expiry = quota.get("expiresAtEpochMs")
                require(type(expiry) is int)
                remaining = expiry / 1000 - self.wall()
                require(0 < remaining <= 5)
                self.wire = value
                self.deadline = self.monotonic() + remaining
                self.update("lease_inflight", lease_request_sha256=digest(raw))
            else:
                require(self.public["status"] == "bound" and set(value) == {"apiVersion", "leaseRequest", "reservationId"}
                    and value["apiVersion"] == "serverware.operatorXQuotaClaimRequest/v1"
                    and wire == self.wire and value["reservationId"] == self.reservation["reservation_id"])
                require(self.monotonic() < self.deadline and self.wall() * 1000 < quota["expiresAtEpochMs"])
                self.update("claim_inflight", claim_request_sha256=digest(raw))
            return True

    def response(self, path, raw, status, fields, body, connection_deadline):
        with self.condition:
            require(self.public["status"] == ("lease_inflight" if path == LEASE else "claim_inflight"))
            if status != 200:
                self.update("failed", http_status=status)
                return raw
            signed_ack(fields, body)
            reply = json_body(body)
            require(reply.get("requestBindingSha256") == digest(encoded(self.wire)))
            if path == LEASE:
                require(set(reply) == {"apiVersion", "requestBindingSha256", "reservation", "credentialLease"}
                    and reply["apiVersion"] == "serverware.operatorXQuotaCredentialLeaseResponse/v1")
                reservation = reply["reservation"]
                require(type(reservation) is dict and set(reservation) == {"schema", "reservation_id", "bucket_key",
                    "utc_day", "expires_at_epoch_ms", "binding_digest"}
                    and reservation["schema"] == "serverware.operatorXPostingQuotaReservation/v1"
                    and identifier(reservation["reservation_id"]) and sha(reservation["binding_digest"])
                    and reservation["expires_at_epoch_ms"] == self.wire["operatorXQuota"]["expiresAtEpochMs"])
                self.reservation = dict(reservation)
                binding = {"attempt_nonce": self.wire["operatorXQuota"]["attemptNonce"],
                    "reservation_id": reservation["reservation_id"], "request_binding_sha256": digest(encoded(self.wire))}
                self.update("bound", lease_response_sha256=digest(raw), claim_sha256=digest(encoded(binding)), http_status=200)
                return raw
            require(set(reply) == {"apiVersion", "requestBindingSha256", "claim"}
                and reply["apiVersion"] == "serverware.operatorXQuotaClaimResponse/v1")
            claim = reply["claim"]
            require(type(claim) is dict and set(claim) == set(self.reservation) | {"claimed_at_epoch_ms"}
                and claim["schema"] == "serverware.operatorXPostingQuotaClaim/v1"
                and all(claim[key] == value for key, value in self.reservation.items() if key != "schema")
                and type(claim["claimed_at_epoch_ms"]) is int
                and 0 < claim["claimed_at_epoch_ms"] < claim["expires_at_epoch_ms"])
            self.update("dropped" if self.arm_value["mode"] == "drop_ack" else "held",
                claim_response_sha256=digest(raw), http_status=200)
            if self.arm_value["mode"] == "drop_ack":
                return None
            deadline = min(self.deadline, connection_deadline)
            while self.public["status"] == "held":
                remaining = min(deadline - self.monotonic(), claim["expires_at_epoch_ms"] / 1000 - self.wall())
                if remaining <= 0:
                    self.update("expired")
                    return None
                self.condition.wait(timeout=remaining)
            if (self.public["status"] != "release_requested" or self.monotonic() >= deadline
                    or self.wall() * 1000 >= claim["expires_at_epoch_ms"]):
                self.update("expired")
                return None
            self.update("released")
            return raw

    def release(self, value):
        with self.condition:
            require(type(value) is dict and set(value) == {"schema", "arm_sha256", "claim_sha256",
                "revoked_rule_id", "policy_hash", "loaded_policy_hash"}
                and value["schema"] == "serverware.privateXQuotaFaultRelease/v1"
                and self.public["status"] == "held" and self.monotonic() < self.deadline
                and self.wall() * 1000 < self.wire["operatorXQuota"]["expiresAtEpochMs"]
                and value["arm_sha256"] == self.public["arm_sha256"] and value["claim_sha256"] == self.public["claim_sha256"]
                and value["revoked_rule_id"] == self.arm_value["route_id"].removeprefix("operator.")
                and sha(value["policy_hash"])
                and value["policy_hash"] == value["loaded_policy_hash"] != self.wire["policyHash"])
            self.update("release_requested")
            return dict(self.public)

    def failed(self):
        with self.condition:
            if self.public["status"] in {"lease_inflight", "claim_inflight", "held", "release_requested"}:
                self.update("failed")


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        selected = False
        try:
            deadline = min(self.server.deadline, time.monotonic() + 3)
            raw, first, fields, body = read_message(self.request, deadline, MAX_REQUEST)
            path = admit(first, fields, body)
            if path in {ARM, STATUS, RELEASE}:
                state = self.server.state
                result = state.status() if path == STATUS else (state.arm if path == ARM else state.release)(json_body(body))
                payload = encoded(result)
                self.request.settimeout(max(.001, deadline - time.monotonic()))
                self.request.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
                    + str(len(payload)).encode() + b"\r\nConnection: close\r\n\r\n" + payload)
                return
            selected = self.server.state.before(path, body)
            with socket.create_connection(APP, timeout=max(.001, deadline - time.monotonic())) as upstream:
                upstream.settimeout(max(.001, deadline - time.monotonic()))
                upstream.sendall(raw)
                response, first, response_fields, response_body = read_message(upstream, deadline, MAX_RESPONSE)
            require(re.fullmatch(rb"HTTP/1\.1 [1-5][0-9]{2} [ -~]*", first) is not None)
            if selected:
                response = self.server.state.response(path, response, int(first.split()[1]),
                    response_fields, response_body, deadline)
            if response is not None:
                require(time.monotonic() < deadline)
                self.request.settimeout(deadline - time.monotonic())
                self.request.sendall(response)
        except Exception:
            if selected:
                self.server.state.failed()
            # No exception/input text, synthetic app response, replay or retry.


class Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads, allow_reuse_address, request_queue_size = True, False, 8

    def __init__(self, state, lifetime):
        require(type(lifetime) is int and 1 <= lifetime <= 300)
        self.state, self.deadline = state, time.monotonic() + lifetime
        self.slots, self.accepted = threading.BoundedSemaphore(8), 0
        super().__init__(LISTEN, Handler)

    def process_request(self, request, address):
        self.accepted += 1
        if self.accepted > 128 or time.monotonic() >= self.deadline or not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.slots.release()

    def handle_error(self, *_):
        pass


def main():
    import os
    from scripts.operator_x_post_fixture_network import assert_isolated_network
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lifetime-seconds", type=int, default=240)
    args = parser.parse_args()
    require(30 <= args.lifetime_seconds <= 300 and os.geteuid() == os.getegid() == 10001)
    assert_isolated_network()
    require(json_body(Path("/private-audit-fixture.json").read_bytes()) == {
        "schema": "serverware.privateOperatorAuditFixture/v1", "syntheticOnly": True})
    stopped = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stopped.set())
    with Server(State(emit=lambda value: print(encoded(value).decode(), flush=True)), args.lifetime_seconds) as server:
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            print('{"ready":true,"syntheticOnly":true}', flush=True)
            stopped.wait(args.lifetime_seconds)
        finally:
            server.shutdown()
            worker.join(timeout=4)


if __name__ == "__main__":
    main()
