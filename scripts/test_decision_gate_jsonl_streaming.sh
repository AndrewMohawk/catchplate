#!/usr/bin/env bash
set -euo pipefail

GATE_HOST="${DECISION_GATE_HOST:-localhost}"
GATE_PORT="${DECISION_GATE_PORT:-9090}"
CA_FILE="${SERVERWARE_CA_OUT:-.tmp/serverware-ca.pem}"

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


def jsonl_payload(count: int) -> bytes:
    rows = []
    for index in range(count):
        rows.append(
            json.dumps(
                {
                    "index": index,
                    "kept": f"value-{index}",
                    "secret": f"top-secret-{index}",
                    "nested": {"safe": f"nested-{index}", "secret": f"nested-secret-{index}"},
                    "padding": "x" * 80,
                },
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        )
    return b"\n".join(rows) + b"\n"


def assert_jsonl_result(body: bytes, expected_count: int) -> None:
    assert b"top-secret" not in body, body[:512]
    assert b"nested-secret" not in body, body[:512]
    assert b"must-be-redacted" not in body, body[:512]
    lines = [json.loads(line) for line in body.splitlines() if line.strip()]
    assert len(lines) == expected_count, len(lines)
    for index, item in enumerate(lines):
        assert item == {
            "authorization_present": False,
            "authorization_scheme": None,
            "index": index,
            "kept": f"value-{index}",
            "nested": {"safe": f"nested-{index}"},
            "sawSecret": False,
        }, item
        assert "authorization_sha256" not in item, item


def request_absolute(payload: bytes):
    with socket.create_connection((host, port), timeout=10) as sock:
        sock.sendall(
            (
                "POST https://demo-upstream:8443/jsonl-redact HTTP/1.1\r\n"
                "Host: demo-upstream:8443\r\n"
                "X-Serverware-Agent: demo-agent\r\n"
                "Content-Type: application/x-ndjson\r\n"
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
            b"X-Serverware-Agent: demo-agent\r\n"
            b"\r\n"
        )
        status, _, body = read_http(raw)
        assert status == 200, (status, body)
        context = ssl.create_default_context(cafile=ca_file)
        with context.wrap_socket(raw, server_hostname="demo-upstream") as tls:
            tls.sendall(
                (
                    "POST /jsonl-redact HTTP/1.1\r\n"
                    "Host: demo-upstream:8443\r\n"
                    "Content-Type: application/x-ndjson\r\n"
                    f"Content-Length: {len(payload)}\r\n"
                    "Connection: close\r\n"
                    "\r\n"
                ).encode("ascii")
            )
            for offset in range(0, len(payload), 2048):
                tls.sendall(payload[offset : offset + 2048])
            return read_http(tls)


absolute_payload = jsonl_payload(420)
status, headers, body = request_absolute(absolute_payload)
assert status == 200, (status, headers, body[:512])
assert headers.get("transfer-encoding", "").lower() == "chunked", headers
assert_jsonl_result(body, 420)

connect_payload = jsonl_payload(333)
status, headers, body = request_connect(connect_payload)
assert status == 200, (status, headers, body[:512])
assert headers.get("transfer-encoding", "").lower() == "chunked", headers
assert_jsonl_result(body, 333)

print(json.dumps({"ok": True, "jsonl_streaming_redaction": "pass", "absolute_lines": 420, "connect_lines": 333}, sort_keys=True))
PY
