#!/usr/bin/env bash
set -euo pipefail

BASE="${BASE:-http://localhost:3000}"
GATE="${DECISION_GATE_BASE:-http://localhost:9091}"
GATE_HOST="${DECISION_GATE_HOST:-localhost}"
GATE_PORT="${DECISION_GATE_PORT:-9090}"
ADMIN_HEADER=(-H "X-Serverware-Admin-Token: ${SERVERWARE_ADMIN_TOKEN:-dev-admin-token}")

curl -fsS "${ADMIN_HEADER[@]}" -X POST "$BASE/api/demo/seed" >/dev/null

python3 - "$GATE" "$GATE_HOST" "$GATE_PORT" <<'PY'
import json
import os
import socket
import subprocess
import sys
import time
import urllib.request

gate = sys.argv[1].rstrip("/")
gate_host = sys.argv[2]
gate_port = int(sys.argv[3])
management_token = os.environ.get("SERVERWARE_DATA_PLANE_MANAGEMENT_TOKEN", "").strip() or "dev-rust-management-token"


def decide(text: str) -> dict:
    payload = {
        "clientIp": "127.0.0.1",
        "method": "POST",
        "url": "https://demo-upstream:8443/2/tweets",
        "headers": {"X-Serverware-Agent": "demo-agent", "Content-Type": "application/json"},
        "body": json.dumps({"text": text}, separators=(",", ":")),
        "preview": True,
    }
    req = urllib.request.Request(
        f"{gate}/v1/decide",
        data=json.dumps(payload, separators=(",", ":"), sort_keys=True).encode(),
        headers={
            "Content-Type": "application/json",
            "X-Serverware-Data-Plane-Token": management_token,
        },
    )
    with urllib.request.urlopen(req, timeout=10) as response:
        return json.loads(response.read())


def release_store() -> dict:
    query = """
    SELECT json_build_object(
      'attempts', (SELECT COUNT(*) FROM release_authorization_attempts WHERE route_id = 'demo.x.tweet.one_per_day'),
      'quota_count', (SELECT COALESCE(SUM(count), 0) FROM rate_limit_counters WHERE route_id = 'demo.x.tweet.one_per_day'),
      'latest_state', (SELECT state FROM release_authorization_attempts WHERE route_id = 'demo.x.tweet.one_per_day' ORDER BY created_at DESC, attempt_id DESC LIMIT 1),
      'latest_outcome', (SELECT completion_outcome FROM release_authorization_attempts WHERE route_id = 'demo.x.tweet.one_per_day' ORDER BY created_at DESC, attempt_id DESC LIMIT 1),
      'latest_correlated', (SELECT attempt_id = flow_id FROM release_authorization_attempts WHERE route_id = 'demo.x.tweet.one_per_day' ORDER BY created_at DESC, attempt_id DESC LIMIT 1)
    )
    """
    output = subprocess.check_output(
        ["docker", "compose", "exec", "-T", "grant-store", "psql", "-U", "serverware", "-d", "serverware", "-Atq", "-c", query],
        text=True,
    )
    return json.loads(output)


def forward(text: str) -> tuple[int, dict]:
    body = json.dumps({"text": text}, separators=(",", ":")).encode()
    raw = (
        "POST https://demo-upstream:8443/2/tweets HTTP/1.1\r\n"
        "Host: demo-upstream:8443\r\n"
        "X-Serverware-Agent: demo-agent\r\n"
        "Content-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n\r\n"
    ).encode() + body
    with socket.create_connection((gate_host, gate_port), timeout=10) as sock:
        sock.sendall(raw)
        response = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
    head, _, response_body = response.partition(b"\r\n\r\n")
    return int(head.split(b" ", 2)[1]), json.loads(response_body)


before_preview = release_store()
last = None
for _ in range(20):
    last = decide(f"shared quota {int(time.time())}")
    if last.get("route_id") == "demo.x.tweet.one_per_day":
        break
    time.sleep(0.25)
else:
    raise AssertionError(f"decision gate did not load shared quota policy route: {last}")

first = last
assert first["action"] == "allow", first
assert first["route_id"] == "demo.x.tweet.one_per_day", first
assert first["preview"] is True, first
assert first["allowed"] is False, first
assert first["authorizes_forwarding"] is False, first
assert first["injection"] is None, first

second = decide("shared quota second")
assert second["action"] == "allow", second
assert second["preview"] is True, second
assert release_store() == before_preview, (before_preview, release_store())

before_forward = release_store()
status, forwarded = forward("shared quota actual")
assert status == 200, forwarded
after_forward = release_store()
assert after_forward["attempts"] == before_forward["attempts"] + 1, (before_forward, after_forward)
assert after_forward["quota_count"] == 1, after_forward
assert after_forward["latest_state"] == "committed", after_forward
assert after_forward["latest_outcome"] == "forwarded", after_forward
assert after_forward["latest_correlated"] is True, after_forward

before_denial = release_store()
status, denied = forward("shared quota denied")
assert status == 403, denied
assert denied["payload"]["error"] == "credential_rate_limit_exceeded", denied
assert denied["payload"]["store"] == "shared", denied
assert denied["payload"]["retry_after_seconds"] > 0, denied
assert release_store() == before_denial, (before_denial, release_store())

print(json.dumps({"ok": True, "shared_rate_limit": "pass", "preview": "non_mutating", "forward": "consumed", "denial": "zero_mutation"}, sort_keys=True))
PY
