#!/usr/bin/env bash
set -euo pipefail

GATE_HOST="${DECISION_GATE_HOST:-localhost}"
GATE_PORT="${DECISION_GATE_PORT:-9090}"
CA_FILE="${SERVERWARE_CA_OUT:-.tmp/serverware-ca.pem}"
TMP_DIR="${TMP_DIR:-.tmp}"

mkdir -p "$TMP_DIR"

release_lifecycle_store() {
  docker compose exec -T grant-store psql -U serverware -d serverware -Atq -c \
    "SELECT json_build_object('attempts', COUNT(*), 'forwarded', COUNT(*) FILTER (WHERE state = 'committed' AND completion_outcome = 'forwarded'), 'terminal', COUNT(*) FILTER (WHERE state NOT IN ('reserved', 'dispatching')), 'correlated', COUNT(*) FILTER (WHERE attempt_id = flow_id)) FROM release_authorization_attempts"
}
RELEASE_LIFECYCLE_BEFORE="$(release_lifecycle_store)"

curl -fsS \
  --max-time 10 \
  --proxy "http://$GATE_HOST:$GATE_PORT" \
  --proxy-header "X-Serverware-Agent: demo-agent" \
  --cacert "$CA_FILE" \
  -H "X-Serverware-Agent: demo-agent" \
  https://demo-upstream:8443/echo > "$TMP_DIR/decision-gate-mitm-echo.json"

python3 - "$TMP_DIR/decision-gate-mitm-echo.json" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    payload = json.load(handle)

assert payload["authorization_present"] is True, payload
assert payload["authorization_scheme"] == "Bearer", payload
assert payload["credential_marker"] == "initial", payload
assert "authorization_sha256" not in payload, payload
assert "authorization" not in payload, payload
assert "proxy_authorization" not in payload, payload
assert "serverware_agent" not in payload, payload
assert payload["path"] == "/echo", payload
PY

curl -fsS \
  --max-time 10 \
  --proxy "http://$GATE_HOST:$GATE_PORT" \
  --proxy-header "X-Serverware-Agent: demo-token-agent" \
  --proxy-header "Proxy-Authorization: Bearer demo-agent-proxy-token" \
  --cacert "$CA_FILE" \
  https://demo-upstream:8443/echo > "$TMP_DIR/decision-gate-mitm-proxy-auth-echo.json"

python3 - "$TMP_DIR/decision-gate-mitm-proxy-auth-echo.json" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    payload = json.load(handle)

assert payload["authorization_present"] is True, payload
assert payload["authorization_scheme"] == "Bearer", payload
assert payload["credential_marker"] == "initial", payload
assert "authorization_sha256" not in payload, payload
assert "authorization" not in payload, payload
assert "proxy_authorization" not in payload, payload
assert "serverware_agent" not in payload, payload
assert payload["path"] == "/echo", payload
PY

python3 - "$GATE_HOST" "$GATE_PORT" "$CA_FILE" <<'PY'
import json
import socket
import ssl
import sys

host = sys.argv[1]
port = int(sys.argv[2])
ca_file = sys.argv[3]


def read_http(sock) -> tuple[int, dict[str, str], bytes]:
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            raise AssertionError("connection closed before response headers")
        data += chunk
    head, _, body = data.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    status = int(lines[0].split(b" ", 2)[1])
    headers: dict[str, str] = {}
    content_length = 0
    for line in lines[1:]:
        if b":" not in line:
            continue
        name, value = line.split(b":", 1)
        headers[name.decode("ascii").lower()] = value.strip().decode("ascii")
        if name.lower() == b"content-length":
            content_length = int(value.strip())
    while len(body) < content_length:
        chunk = sock.recv(4096)
        if not chunk:
            raise AssertionError("connection closed before response body")
        body += chunk
    return status, headers, body[:content_length]


with socket.create_connection((host, port), timeout=10) as raw:
    raw.sendall(
        b"CONNECT demo-upstream:8443 HTTP/1.1\r\n"
        b"Host: demo-upstream:8443\r\n"
        b"X-Serverware-Agent: demo-agent\r\n"
        b"\r\n"
    )
    status, _, _ = read_http(raw)
    assert status == 200, status

    context = ssl.create_default_context(cafile=ca_file)
    with context.wrap_socket(raw, server_hostname="demo-upstream") as tls:
        tls.sendall(
            b"GET /echo HTTP/1.1\r\n"
            b"Host: demo-upstream:8443\r\n"
            b"Connection: keep-alive\r\n"
            b"\r\n"
        )
        status, headers, body = read_http(tls)
        payload = json.loads(body)
        assert status == 200, (status, payload)
        assert headers.get("connection") == "keep-alive", headers
        assert payload["authorization_present"] is True, payload
        assert payload["authorization_scheme"] == "Bearer", payload
        assert payload["credential_marker"] == "initial", payload
        assert "authorization_sha256" not in payload, payload
        assert "authorization" not in payload, payload
        assert "serverware_agent" not in payload, payload
        assert payload["method"] == "GET", payload

        tls.sendall(
            b"POST /echo HTTP/1.1\r\n"
            b"Host: demo-upstream:8443\r\n"
            b"Connection: close\r\n"
            b"Content-Length: 0\r\n"
            b"\r\n"
        )
        status, headers, body = read_http(tls)
        payload = json.loads(body)
        assert status == 200, (status, payload)
        assert headers.get("connection") == "close", headers
        assert payload["authorization_present"] is True, payload
        assert payload["authorization_scheme"] == "Bearer", payload
        assert payload["credential_marker"] == "initial", payload
        assert "authorization_sha256" not in payload, payload
        assert "authorization" not in payload, payload
        assert "serverware_agent" not in payload, payload
        assert payload["method"] == "POST", payload
PY

status="$(
  curl -sS \
    --max-time 10 \
    --proxy "http://$GATE_HOST:$GATE_PORT" \
    --proxy-header "X-Serverware-Agent: demo-agent" \
    --cacert "$CA_FILE" \
    -H "X-Serverware-Agent: demo-agent" \
    -o "$TMP_DIR/decision-gate-mitm-deny.json" \
    -w "%{http_code}" \
    https://demo-upstream:8443/not-allowed
)"

python3 - "$status" "$TMP_DIR/decision-gate-mitm-deny.json" <<'PY'
import json
import sys

status = int(sys.argv[1])
with open(sys.argv[2], "r", encoding="utf-8") as handle:
    payload = json.load(handle)

assert status == 403, (status, payload)
assert payload["payload"]["error"] == "unknown_route_denied", payload
PY

python3 - <<'PY'
import json
print(json.dumps({"ok": True, "connect_mitm": "pass"}, sort_keys=True))
PY

python3 - "$RELEASE_LIFECYCLE_BEFORE" "$(release_lifecycle_store)" 4 <<'PY'
import json, sys
before, after, expected = json.loads(sys.argv[1]), json.loads(sys.argv[2]), int(sys.argv[3])
attempts = after["attempts"] - before["attempts"]
assert attempts >= expected, (before, after)
assert after["forwarded"] - before["forwarded"] >= expected, (before, after)
assert after["terminal"] - before["terminal"] == attempts, (before, after)
assert after["correlated"] - before["correlated"] == attempts, (before, after)
PY
