#!/usr/bin/env bash
set -euo pipefail

GATE_HOST="${DECISION_GATE_HOST:-localhost}"
GATE_PORT="${DECISION_GATE_PORT:-9090}"
CA_FILE="${SERVERWARE_CA_OUT:-.tmp/serverware-ca.pem}"

release_lifecycle_store() {
  docker compose exec -T grant-store psql -U serverware -d serverware -Atq -c \
    "SELECT json_build_object('attempts', COUNT(*), 'forwarded', COUNT(*) FILTER (WHERE state = 'committed' AND completion_outcome = 'forwarded'), 'terminal', COUNT(*) FILTER (WHERE state NOT IN ('reserved', 'dispatching')), 'correlated', COUNT(*) FILTER (WHERE attempt_id = flow_id)) FROM release_authorization_attempts"
}
RELEASE_LIFECYCLE_BEFORE="$(release_lifecycle_store)"

python3 - "$GATE_HOST" "$GATE_PORT" "$CA_FILE" <<'PY'
import hashlib
import json
import socket
import ssl
import sys

host = sys.argv[1]
port = int(sys.argv[2])
ca_file = sys.argv[3]


def expected_body(chunks: int, chunk_size: int) -> bytes:
    return b"".join(bytes([index % 251]) * chunk_size for index in range(chunks))


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
        lower = name.decode("ascii").lower()
        headers[lower] = value.strip().decode("ascii")
        if lower == "content-length":
            content_length = int(value.strip())
    while len(body) < content_length:
        chunk = sock.recv(8192)
        if not chunk:
            raise AssertionError("connection closed before response body")
        body += chunk
    return status, headers, body[:content_length]


chunks = 17
chunk_size = 4096
body = expected_body(chunks, chunk_size)
raw_request = (
    f"GET https://demo-upstream:8443/stream-bytes?chunks={chunks}&chunkSize={chunk_size} HTTP/1.1\r\n"
    "Host: demo-upstream:8443\r\n"
    "X-Serverware-Agent: demo-agent\r\n"
    "Connection: close\r\n\r\n"
)
with socket.create_connection((host, port), timeout=10) as sock:
    sock.sendall(raw_request.encode("ascii"))
    status, headers, payload = read_http(sock)
assert status == 200, (status, headers, payload[:64])
assert headers.get("content-length") == str(len(body)), headers
assert headers.get("content-type") == "application/octet-stream", headers
assert payload == body, (len(payload), hashlib.sha256(payload).hexdigest())

reflected_token = b"demo-token-from-vault"
raw_request = (
    "GET https://demo-upstream:8443/stream-bytes?reflectCredential=1 HTTP/1.1\r\n"
    "Host: demo-upstream:8443\r\n"
    "X-Serverware-Agent: demo-agent\r\n"
    "Connection: close\r\n\r\n"
)
with socket.create_connection((host, port), timeout=10) as sock:
    sock.sendall(raw_request.encode("ascii"))
    chunks_out = []
    while True:
        chunk = sock.recv(8192)
        if not chunk:
            break
        chunks_out.append(chunk)
reflected_response = b"".join(chunks_out)
head, _, reflected_body = reflected_response.partition(b"\r\n\r\n")
assert int(head.split(b" ", 2)[1]) == 200, head
content_length = next(
    int(line.split(b":", 1)[1].strip())
    for line in head.split(b"\r\n")[1:]
    if line.lower().startswith(b"content-length:")
)
assert len(reflected_body) == content_length, (len(reflected_body), content_length)
assert reflected_token not in reflected_body, reflected_body[-128:]

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
            b"GET /stream-bytes?chunks=3&chunkSize=1024 HTTP/1.1\r\n"
            b"Host: demo-upstream:8443\r\n"
            b"Connection: keep-alive\r\n"
            b"\r\n"
        )
        status, headers, payload = read_http(tls)
        expected = expected_body(3, 1024)
        assert status == 200, (status, headers)
        assert headers.get("connection") == "close", headers
        assert payload == expected, (len(payload), hashlib.sha256(payload).hexdigest())


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
            b"Connection: close\r\n"
            b"\r\n"
        )
        status, headers, payload = read_http(tls)
        assert status == 200, (status, headers, payload)
        assert headers.get("connection") == "close", headers
        echo = json.loads(payload)
        assert echo["authorization_present"] is True, echo
        assert "authorization" not in echo, echo

print(json.dumps({"ok": True, "streaming": "pass"}, sort_keys=True))
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
