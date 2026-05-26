#!/usr/bin/env bash
set -euo pipefail

BASE="${BASE:-http://localhost:3000}"
GATE_HOST="${DECISION_GATE_HOST:-localhost}"
GATE_PORT="${DECISION_GATE_PORT:-9090}"
ADMIN_TOKEN="${SERVERWARE_ADMIN_TOKEN:-dev-admin-token}"

python3 - "$BASE" "$GATE_HOST" "$GATE_PORT" "$ADMIN_TOKEN" <<'PY'
import hashlib
import json
import socket
import sys
import time
import urllib.request

base = sys.argv[1].rstrip("/")
gate_host = sys.argv[2]
gate_port = int(sys.argv[3])
admin_token = sys.argv[4]
marker = f"audit-{time.time_ns()}"


def gate_request(raw: bytes) -> tuple[int, dict | None]:
    with socket.create_connection((gate_host, gate_port), timeout=10) as sock:
        sock.sendall(raw)
        chunks = []
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
    data = b"".join(chunks)
    head, _, body = data.partition(b"\r\n\r\n")
    status = int(head.split(b" ", 2)[1])
    payload = json.loads(body.decode("utf-8")) if body else None
    return status, payload


def connect_header_status(raw: bytes) -> int:
    with socket.create_connection((gate_host, gate_port), timeout=10) as sock:
        sock.sendall(raw)
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
    head, _, _ = data.partition(b"\r\n\r\n")
    return int(head.split(b" ", 2)[1])


known_connect = (
    b"CONNECT demo-upstream:8443 HTTP/1.1\r\n"
    b"Host: demo-upstream:8443\r\n"
    b"X-Serverware-Agent: demo-agent\r\n\r\n"
)
status = connect_header_status(known_connect)
assert status == 200, status

unknown_authority = f"{marker}.invalid:8443"
unknown_connect = (
    f"CONNECT {unknown_authority} HTTP/1.1\r\n"
    f"Host: {unknown_authority}\r\n"
    "X-Serverware-Agent: demo-agent\r\n\r\n"
).encode("ascii")
status, payload = gate_request(unknown_connect)
assert status == 403, payload

body = json.dumps({"audit_marker": marker}, separators=(",", ":"), sort_keys=True)
body_sha = "sha256:" + hashlib.sha256(body.encode("utf-8")).hexdigest()
raw = (
    "POST https://demo-upstream:8443/echo HTTP/1.1\r\n"
    "Host: demo-upstream:8443\r\n"
    "X-Serverware-Agent: demo-agent\r\n"
    "Content-Type: application/json\r\n"
    f"Content-Length: {len(body.encode('utf-8'))}\r\n"
    "Connection: close\r\n\r\n"
    f"{body}"
).encode("utf-8")
status, payload = gate_request(raw)
assert status == 200, payload

raw = (
    "GET https://demo-upstream:8443/gmail/v1/users/me/messages?oldInternalDate=1 HTTP/1.1\r\n"
    "Host: demo-upstream:8443\r\n"
    "X-Serverware-Agent: demo-agent\r\n"
    "Connection: close\r\n\r\n"
).encode("utf-8")
status, payload = gate_request(raw)
assert status == 502, payload


def audit_events() -> list[dict]:
    req = urllib.request.Request(
        f"{base}/api/audit?limit=500",
        headers={"X-Serverware-Admin-Token": admin_token},
    )
    with urllib.request.urlopen(req, timeout=10) as response:
        return json.loads(response.read())


deadline = time.time() + 20
last_events = []
while time.time() < deadline:
    last_events = [
        item for item in audit_events() if item.get("actor_type") == "data-plane"
    ]
    event_types = {item.get("event_type") for item in last_events}
    released = any(
        item.get("event_type") == "data_plane.response.released"
        and (item.get("event") or {}).get("body_sha256") == body_sha
        for item in last_events
    )
    connect_denied = any(
        item.get("event_type") == "data_plane.connect.denied"
        and (item.get("event") or {}).get("target") == unknown_authority
        for item in last_events
    )
    response_blocked = any(
        item.get("event_type") == "data_plane.response.blocked"
        and ((item.get("event") or {}).get("payload") or {}).get("error") == "response_date_window_exceeded"
        for item in last_events
    )
    required_types = {
        "data_plane.connect.established",
        "data_plane.grant.received",
        "data_plane.jit.grant_consumed",
    }
    if required_types.issubset(event_types) and released and connect_denied and response_blocked:
        print(json.dumps({"ok": True, "audit_events": "pass", "marker": marker}, sort_keys=True))
        break
    time.sleep(0.5)
else:
    observed = sorted({item.get("event_type") for item in last_events})
    raise SystemExit(f"missing expected data-plane audit events; observed={observed}")
PY
