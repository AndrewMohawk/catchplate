#!/usr/bin/env bash
set -euo pipefail

GATE_HOST="${DECISION_GATE_HOST:-localhost}"
GATE_PORT="${DECISION_GATE_PORT:-9090}"

python3 - "$GATE_HOST" "$GATE_PORT" <<'PY'
import json
import socket
import sys

host = sys.argv[1]
port = int(sys.argv[2])


def connect(authority: str, agent: str | None = "demo-agent", proxy_auth: str | None = None) -> tuple[int, dict | None]:
    headers = [f"CONNECT {authority} HTTP/1.1", f"Host: {authority}"]
    if agent:
        headers.append(f"X-Catchplate-Agent: {agent}")
    if proxy_auth:
        headers.append(f"Proxy-Authorization: {proxy_auth}")
    request = ("\r\n".join(headers) + "\r\n\r\n").encode("ascii")
    with socket.create_connection((host, port), timeout=10) as sock:
        sock.sendall(request)
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
        head, _, rest = data.partition(b"\r\n\r\n")
        status = int(head.split(b" ", 2)[1])
        content_length = 0
        for line in head.split(b"\r\n")[1:]:
            if line.lower().startswith(b"content-length:"):
                content_length = int(line.split(b":", 1)[1].strip())
        chunks = [rest]
        while sum(map(len, chunks)) < content_length:
            chunk = sock.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
    raw = b"".join(chunks)
    payload = json.loads(raw.decode("utf-8")) if raw else None
    return status, payload


status, payload = connect("demo-upstream:8443")
assert status == 200, payload
assert payload is None, payload

status, payload = connect("demo-upstream:8443", agent="demo-token-agent", proxy_auth="Bearer demo-agent-proxy-token")
assert status == 200, payload
assert payload is None, payload

status, payload = connect("demo-upstream:8443", agent="demo-token-agent")
assert status == 403, payload
assert payload["payload"]["error"] == "client_principal_denied", payload

status, payload = connect("demo-upstream:8443", agent="demo-token-agent", proxy_auth="Bearer wrong-token")
assert status == 403, payload
assert payload["payload"]["error"] == "client_principal_denied", payload

status, payload = connect("unknown-upstream:8443")
assert status == 403, payload
assert payload["payload"]["error"] == "unknown_connect_denied", payload

status, payload = connect("demo-upstream:9443")
assert status == 403, payload
assert payload["payload"]["error"] == "unknown_connect_denied", payload

status, payload = connect("demo-upstream:8443", agent=None)
assert status == 403, payload
assert payload["payload"]["error"] == "client_principal_denied", payload

status, payload = connect("demo-upstream")
assert status == 400, payload
assert payload["payload"]["error"] == "invalid_connect_target", payload

print(json.dumps({"ok": True, "connect_preflight": "pass"}, sort_keys=True))
PY
