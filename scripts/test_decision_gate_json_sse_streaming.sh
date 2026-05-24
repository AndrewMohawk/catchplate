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


def json_sse_payload(count: int) -> bytes:
    events = []
    for index in range(count):
        payload = {
            "index": index,
            "kept": f"value-{index}",
            "secret": f"top-secret-{index}",
            "nested": {"safe": f"nested-{index}", "secret": f"nested-secret-{index}"},
            "padding": "x" * 80,
        }
        events.append(
            (
                f"event: request-secret-{index}\n"
                f"id: request-id-secret-{index}\n"
                f"data: {json.dumps(payload, separators=(',', ':'), sort_keys=True)}\n\n"
            ).encode("utf-8")
        )
    events.append(b"data: [DONE]\n\n")
    return b"".join(events)


def parse_sse_events(body: bytes):
    events = []
    done = False
    event_lines = []
    for raw_line in body.splitlines():
        line = raw_line.rstrip(b"\r")
        if not line:
            data_parts = []
            for event_line in event_lines:
                if event_line.startswith(b"data:"):
                    value = event_line[5:]
                    if value.startswith(b" "):
                        value = value[1:]
                    data_parts.append(value)
            event_lines = []
            if not data_parts:
                continue
            data = b"\n".join(data_parts).strip()
            if data == b"[DONE]":
                done = True
                continue
            events.append(json.loads(data))
            continue
        event_lines.append(line)
    return events, done


def assert_json_sse_result(body: bytes, expected_count: int) -> None:
    assert b"top-secret" not in body, body[:512]
    assert b"nested-secret" not in body, body[:512]
    assert b"must-be-redacted" not in body, body[:512]
    assert b"upstream-secret" not in body, body[:512]
    assert b"event-secret" not in body, body[:512]
    events, done = parse_sse_events(body)
    assert done is True, body[-128:]
    assert len(events) == expected_count, len(events)
    for index, item in enumerate(events):
        assert item == {
            "authorization_present": True,
            "authorization_scheme": "Bearer",
            "authorization_sha256": item["authorization_sha256"],
            "index": index,
            "kept": f"value-{index}",
            "nested": {"safe": f"nested-{index}"},
            "sawSecret": False,
        }, item
        assert item["authorization_sha256"].startswith("sha256:"), item


def request_absolute(payload: bytes):
    with socket.create_connection((host, port), timeout=10) as sock:
        sock.sendall(
            (
                "POST https://demo-upstream:8443/json-sse-redact HTTP/1.1\r\n"
                "Host: demo-upstream:8443\r\n"
                "X-Serverware-Agent: demo-agent\r\n"
                "Content-Type: text/event-stream\r\n"
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
                    "POST /json-sse-redact HTTP/1.1\r\n"
                    "Host: demo-upstream:8443\r\n"
                    "Content-Type: text/event-stream\r\n"
                    f"Content-Length: {len(payload)}\r\n"
                    "Connection: close\r\n"
                    "\r\n"
                ).encode("ascii")
            )
            for offset in range(0, len(payload), 2048):
                tls.sendall(payload[offset : offset + 2048])
            return read_http(tls)


absolute_payload = json_sse_payload(360)
status, headers, body = request_absolute(absolute_payload)
assert status == 200, (status, headers, body[:512])
assert headers.get("transfer-encoding", "").lower() == "chunked", headers
assert headers.get("content-type", "").startswith("text/event-stream"), headers
assert_json_sse_result(body, 360)

connect_payload = json_sse_payload(275)
status, headers, body = request_connect(connect_payload)
assert status == 200, (status, headers, body[:512])
assert headers.get("transfer-encoding", "").lower() == "chunked", headers
assert headers.get("content-type", "").startswith("text/event-stream"), headers
assert_json_sse_result(body, 275)

print(json.dumps({"ok": True, "json_sse_streaming_redaction": "pass", "absolute_events": 360, "connect_events": 275}, sort_keys=True))
PY
