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


def request(headers: bytes, body: bytes = b"", chunk_size: int = 8192) -> tuple[int, dict[str, str], bytes]:
    with socket.create_connection((host, port), timeout=10) as sock:
        sock.sendall(headers)
        for offset in range(0, len(body), chunk_size):
            sock.sendall(body[offset : offset + chunk_size])
        return read_http(sock)


payload = bytes((index * 31) % 251 for index in range(192 * 1024))
payload_sha = "sha256:" + hashlib.sha256(payload).hexdigest()
status, headers, body = request(
    (
        "POST https://demo-upstream:8443/upload-bytes HTTP/1.1\r\n"
        "Host: demo-upstream:8443\r\n"
        "X-Serverware-Agent: demo-agent\r\n"
        "Content-Type: application/octet-stream\r\n"
        f"Content-Length: {len(payload)}\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode("ascii"),
    payload,
)
assert status == 200, (status, headers, body[:256])
result = json.loads(body)
assert result["method"] == "POST", result
assert result["path"] == "/upload-bytes", result
assert result["bytes"] == len(payload), result
assert result["sha256"] == payload_sha, result
assert result["authorization_present"] is False, result
assert result["authorization_scheme"] is None, result
assert "authorization_sha256" not in result, result
assert "authorization" not in result, result

connect_payload = bytes((index * 17) % 251 for index in range(160 * 1024))
connect_payload_sha = "sha256:" + hashlib.sha256(connect_payload).hexdigest()
with socket.create_connection((host, port), timeout=10) as raw:
    raw.sendall(
        b"CONNECT demo-upstream:8443 HTTP/1.1\r\n"
        b"Host: demo-upstream:8443\r\n"
        b"X-Serverware-Agent: demo-agent\r\n"
        b"\r\n"
    )
    status, _, body = read_http(raw)
    assert status == 200, (status, body)

    context = ssl.create_default_context(cafile=ca_file)
    with context.wrap_socket(raw, server_hostname="demo-upstream") as tls:
        tls.sendall(
            (
                "POST /upload-bytes HTTP/1.1\r\n"
                "Host: demo-upstream:8443\r\n"
                "Content-Type: application/octet-stream\r\n"
                f"Content-Length: {len(connect_payload)}\r\n"
                "Connection: close\r\n"
                "\r\n"
            ).encode("ascii")
        )
        for offset in range(0, len(connect_payload), 4096):
            tls.sendall(connect_payload[offset : offset + 4096])
        status, headers, body = read_http(tls)
        assert status == 200, (status, headers, body[:256])
        result = json.loads(body)
        assert result["method"] == "POST", result
        assert result["path"] == "/upload-bytes", result
        assert result["bytes"] == len(connect_payload), result
        assert result["sha256"] == connect_payload_sha, result
        assert result["authorization_present"] is False, result
        assert result["authorization_scheme"] is None, result
        assert "authorization_sha256" not in result, result
        assert "authorization" not in result, result

status, _, body = request(
    b"POST https://demo-upstream:8443/upload-bytes HTTP/1.1\r\n"
    b"Host: demo-upstream:8443\r\n"
    b"X-Serverware-Agent: demo-agent\r\n"
    b"Content-Type: application/octet-stream\r\n"
    b"Connection: close\r\n"
    b"\r\n"
)
missing_length = json.loads(body)
assert status == 411, (status, missing_length)
assert missing_length["error"] == "streaming_request_requires_content_length", missing_length

status, _, body = request(
    b"POST https://demo-upstream:8443/upload-bytes HTTP/1.1\r\n"
    b"Host: demo-upstream:8443\r\n"
    b"X-Serverware-Agent: demo-agent\r\n"
    b"Content-Type: application/octet-stream\r\n"
    b"Content-Length: 1048577\r\n"
    b"Connection: close\r\n"
    b"\r\n"
)
too_large = json.loads(body)
assert status == 413, (status, too_large)
assert too_large["error"] == "request_body_too_large", too_large

print(json.dumps({"ok": True, "request_streaming": "pass", "absolute_bytes": len(payload), "connect_bytes": len(connect_payload)}, sort_keys=True))
PY

python3 - "$RELEASE_LIFECYCLE_BEFORE" "$(release_lifecycle_store)" 2 <<'PY'
import json, sys
before, after, expected = json.loads(sys.argv[1]), json.loads(sys.argv[2]), int(sys.argv[3])
attempts = after["attempts"] - before["attempts"]
assert attempts >= expected, (before, after)
assert after["forwarded"] - before["forwarded"] >= expected, (before, after)
assert after["terminal"] - before["terminal"] == attempts, (before, after)
assert after["correlated"] - before["correlated"] == attempts, (before, after)
PY
