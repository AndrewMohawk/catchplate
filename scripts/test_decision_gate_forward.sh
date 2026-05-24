#!/usr/bin/env bash
set -euo pipefail

GATE_HOST="${DECISION_GATE_HOST:-localhost}"
GATE_PORT="${DECISION_GATE_PORT:-9090}"

python3 - "$GATE_HOST" "$GATE_PORT" <<'PY'
import hashlib
import json
import socket
import sys

host = sys.argv[1]
port = int(sys.argv[2])


def request(raw: str) -> tuple[int, dict]:
    with socket.create_connection((host, port), timeout=10) as sock:
        sock.sendall(raw.encode("utf-8"))
        chunks = []
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
    data = b"".join(chunks)
    head, _, body = data.partition(b"\r\n\r\n")
    status = int(head.split(b" ", 2)[1])
    return status, json.loads(body.decode("utf-8"))


status, payload = request(
    "GET https://demo-upstream:8443/echo HTTP/1.1\r\n"
    "Host: demo-upstream:8443\r\n"
    "X-Serverware-Agent: demo-agent\r\n"
    "Connection: close\r\n\r\n"
)
assert status == 200, payload
assert payload["authorization_present"] is True, payload
assert payload["authorization_scheme"] == "Bearer", payload
assert payload["authorization_sha256"] == "sha256:" + hashlib.sha256(b"Bearer demo-token-from-vault").hexdigest(), payload
assert "authorization" not in payload, payload
assert "proxy_authorization" not in payload, payload
assert "serverware_agent" not in payload, payload
assert payload["path"] == "/echo", payload

status, payload = request(
    "GET https://demo-upstream:8443/echo HTTP/1.1\r\n"
    "Host: demo-upstream:8443\r\n"
    "X-Serverware-Agent: demo-token-agent\r\n"
    "Proxy-Authorization: Bearer demo-agent-proxy-token\r\n"
    "Connection: close\r\n\r\n"
)
assert status == 200, payload
assert payload["authorization_present"] is True, payload
assert payload["authorization_scheme"] == "Bearer", payload
assert payload["authorization_sha256"] == "sha256:" + hashlib.sha256(b"Bearer demo-token-from-vault").hexdigest(), payload
assert "authorization" not in payload, payload
assert "proxy_authorization" not in payload, payload
assert "serverware_agent" not in payload, payload
assert payload["path"] == "/echo", payload

status, payload = request(
    "GET https://demo-upstream:8443/echo HTTP/1.1\r\n"
    "Host: demo-upstream:8443\r\n"
    "X-Serverware-Agent: demo-token-agent\r\n"
    "Connection: close\r\n\r\n"
)
assert status == 403, payload
assert payload["payload"]["error"] == "client_principal_denied", payload

status, payload = request(
    "GET https://demo-upstream:8443/not-allowed HTTP/1.1\r\n"
    "Host: demo-upstream:8443\r\n"
    "X-Serverware-Agent: demo-agent\r\n"
    "Connection: close\r\n\r\n"
)
assert status == 403, payload
assert payload["payload"]["error"] == "unknown_route_denied", payload

status, payload = request(
    "GET https://demo-upstream:8443/echo HTTP/1.1\r\n"
    "Host: demo-upstream:8443\r\n"
    "Connection: close\r\n\r\n"
)
assert status == 403, payload
assert payload["payload"]["error"] == "client_principal_denied", payload

status, payload = request(
    "GET https://unknown-upstream:8443/echo HTTP/1.1\r\n"
    "Host: unknown-upstream:8443\r\n"
    "X-Serverware-Agent: demo-agent\r\n"
    "Connection: close\r\n\r\n"
)
assert status == 403, payload
assert payload["payload"]["error"] == "unknown_route_denied", payload

print(json.dumps({"ok": True, "absolute_form_forward": "pass"}, sort_keys=True))
PY
