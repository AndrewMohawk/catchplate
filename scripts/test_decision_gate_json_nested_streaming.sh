#!/usr/bin/env bash
set -euo pipefail

GATE_HOST="${DECISION_GATE_HOST:-localhost}"
GATE_PORT="${DECISION_GATE_PORT:-9090}"
CA_FILE="${CATCHPLATE_CA_OUT:-.tmp/catchplate-ca.pem}"

release_lifecycle_store() {
  docker compose exec -T grant-store psql -U catchplate -d catchplate -Atq -c \
    "SELECT json_build_object('attempts', COUNT(*), 'forwarded', COUNT(*) FILTER (WHERE state = 'committed' AND completion_outcome = 'forwarded'), 'terminal', COUNT(*) FILTER (WHERE state NOT IN ('reserved', 'dispatching')), 'correlated', COUNT(*) FILTER (WHERE attempt_id = flow_id)) FROM release_authorization_attempts"
}
RELEASE_LIFECYCLE_BEFORE="$(release_lifecycle_store)"

python3 - "$GATE_HOST" "$GATE_PORT" "$CA_FILE" <<'PY'
import json
import socket
import ssl
import sys

host = sys.argv[1]
port = int(sys.argv[2])
ca_file = sys.argv[3]


def read_http(sock):
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            raise AssertionError("connection closed before response headers")
        data += chunk
    head, _, body = data.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    status = int(lines[0].split(b" ", 2)[1])
    headers = {}
    for line in lines[1:]:
        if b":" not in line:
            continue
        name, value = line.split(b":", 1)
        headers[name.decode("ascii").lower()] = value.strip().decode("ascii")
    if headers.get("transfer-encoding", "").lower() == "chunked":
        decoded = b""
        while True:
            while b"\r\n" not in body:
                chunk = sock.recv(4096)
                if not chunk:
                    raise AssertionError("connection closed before chunk size")
                body += chunk
            size_raw, _, body = body.partition(b"\r\n")
            size = int(size_raw.split(b";", 1)[0], 16)
            if size == 0:
                while len(body) < 2:
                    chunk = sock.recv(4096)
                    if not chunk:
                        raise AssertionError("connection closed before final chunk")
                    body += chunk
                break
            while len(body) < size + 2:
                chunk = sock.recv(4096)
                if not chunk:
                    raise AssertionError("connection closed during chunk body")
                body += chunk
            decoded += body[:size]
            body = body[size + 2 :]
        return status, headers, decoded
    content_length = int(headers.get("content-length", "0"))
    while len(body) < content_length:
        chunk = sock.recv(8192)
        if not chunk:
            raise AssertionError("connection closed before response body")
        body += chunk
    return status, headers, body[:content_length]


def nested_payload(count: int, request_id: str) -> bytes:
    payload = {
        "requestId": request_id,
        "profile": {
            "email": f"{request_id}@example.test",
            "settings": {
                "theme": "dark",
                "token": f"profile-token-{request_id}",
            },
            "secret": f"profile-secret-{request_id}",
        },
        "items": [
            {
                "id": index,
                "name": f"name-{index}",
                "secret": f"top-secret-{index}",
                "details": {
                    "safe": f"safe-{index}",
                    "secret": f"nested-secret-{index}",
                },
                "padding": "x" * 96,
            }
            for index in range(count)
        ],
        "audit": {
            "trace": f"trace-{request_id}",
            "privateToken": f"audit-token-{request_id}",
        },
        "secret": f"root-secret-{request_id}",
        "padding": "z" * 512,
    }
    return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")


def assert_nested_result(body: bytes, expected_count: int, request_id: str) -> None:
    denied_markers = [
        b"top-secret",
        b"nested-secret",
        b"profile-secret",
        b"profile-token",
        b"audit-token",
        b"root-secret",
        b"response-profile-secret",
        b"response-settings-token",
        b"response-item-secret",
        b"response-detail-secret",
        b"must-be-redacted",
        b"privateToken",
        b"upstreamSecret",
        b"echoedSecret",
        b"padding",
    ]
    for marker in denied_markers:
        assert marker not in body, (marker, body[:1024])
    doc = json.loads(body)
    assert set(doc) == {
        "audit",
        "authorization_present",
        "authorization_scheme",
        "items",
        "profile",
        "requestId",
        "sawSecret",
    }, doc
    assert doc["requestId"] == request_id, doc
    assert doc["profile"] == {
        "email": f"{request_id}@example.test",
        "settings": {"theme": "dark"},
    }, doc["profile"]
    assert doc["audit"] == {"trace": f"trace-{request_id}"}, doc["audit"]
    assert doc["sawSecret"] is False, doc
    assert doc["authorization_present"] is False, doc
    assert doc["authorization_scheme"] is None, doc
    assert "authorization_sha256" not in doc, doc
    assert len(doc["items"]) == expected_count, len(doc["items"])
    for index, item in enumerate(doc["items"]):
        assert item == {
            "details": {"safe": f"safe-{index}"},
            "id": index,
        }, item


def request_absolute(payload: bytes):
    with socket.create_connection((host, port), timeout=10) as sock:
        sock.sendall(
            (
                "POST https://demo-upstream:8443/json-nested-redact HTTP/1.1\r\n"
                "Host: demo-upstream:8443\r\n"
                "X-Catchplate-Agent: demo-agent\r\n"
                "Content-Type: application/json\r\n"
                f"Content-Length: {len(payload)}\r\n"
                "Connection: close\r\n"
                "\r\n"
            ).encode("ascii")
        )
        for offset in range(0, len(payload), 3072):
            sock.sendall(payload[offset : offset + 3072])
        return read_http(sock)


def request_connect(payload: bytes):
    with socket.create_connection((host, port), timeout=10) as raw:
        raw.sendall(
            b"CONNECT demo-upstream:8443 HTTP/1.1\r\n"
            b"Host: demo-upstream:8443\r\n"
            b"X-Catchplate-Agent: demo-agent\r\n"
            b"\r\n"
        )
        status, _, body = read_http(raw)
        assert status == 200, (status, body)
        context = ssl.create_default_context(cafile=ca_file)
        with context.wrap_socket(raw, server_hostname="demo-upstream") as tls:
            tls.sendall(
                (
                    "POST /json-nested-redact HTTP/1.1\r\n"
                    "Host: demo-upstream:8443\r\n"
                    "Content-Type: application/json\r\n"
                    f"Content-Length: {len(payload)}\r\n"
                    "Connection: close\r\n"
                    "\r\n"
                ).encode("ascii")
            )
            for offset in range(0, len(payload), 2048):
                tls.sendall(payload[offset : offset + 2048])
            return read_http(tls)


absolute_payload = nested_payload(260, "absolute-nested")
status, headers, body = request_absolute(absolute_payload)
assert status == 200, (status, headers, body[:1024])
assert headers.get("transfer-encoding", "").lower() == "chunked", headers
assert headers.get("content-type", "").startswith("application/json"), headers
assert_nested_result(body, 260, "absolute-nested")

connect_payload = nested_payload(185, "connect-nested")
status, headers, body = request_connect(connect_payload)
assert status == 200, (status, headers, body[:1024])
assert headers.get("transfer-encoding", "").lower() == "chunked", headers
assert headers.get("content-type", "").startswith("application/json"), headers
assert_nested_result(body, 185, "connect-nested")

print(json.dumps({"ok": True, "json_nested_streaming_redaction": "pass", "absolute_items": 260, "connect_items": 185}, sort_keys=True))
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
