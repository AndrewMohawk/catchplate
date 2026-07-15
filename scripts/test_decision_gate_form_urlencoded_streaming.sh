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
import json
import socket
import ssl
import sys
from urllib.parse import parse_qs, urlencode

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


def form_payload(count: int) -> bytes:
    pairs = []
    for index in range(count):
        pairs.extend(
            [
                ("kept", f"value-{index}"),
                ("secret", f"top-secret-{index}"),
                ("safe", f"nested-{index}"),
                ("nested_secret", f"nested-secret-{index}"),
                ("padding", "x" * 80),
            ]
        )
    return urlencode(pairs, doseq=True).encode("utf-8")


def assert_form_result(body: bytes, expected_count: int) -> None:
    assert b"top-secret" not in body, body[:512]
    assert b"nested-secret" not in body, body[:512]
    assert b"must-be-redacted" not in body, body[:512]
    assert b"upstreamSecret" not in body, body[:512]
    parsed = parse_qs(body.decode("utf-8"), keep_blank_values=True)
    assert set(parsed) == {
        "authorization_present",
        "authorization_scheme",
        "kept",
        "safe",
        "sawSecret",
    }, parsed
    assert parsed["kept"] == [f"value-{index}" for index in range(expected_count)], parsed["kept"][:5]
    assert parsed["safe"] == [f"nested-{index}" for index in range(expected_count)], parsed["safe"][:5]
    assert parsed["sawSecret"] == ["false"], parsed["sawSecret"]
    assert parsed["authorization_present"] == ["false"], parsed["authorization_present"]
    assert parsed["authorization_scheme"] == [""], parsed["authorization_scheme"]
    assert "authorization_sha256" not in parsed, parsed


def request_absolute(payload: bytes):
    with socket.create_connection((host, port), timeout=10) as sock:
        sock.sendall(
            (
                "POST https://demo-upstream:8443/form-redact HTTP/1.1\r\n"
                "Host: demo-upstream:8443\r\n"
                "X-Serverware-Agent: demo-agent\r\n"
                "Content-Type: application/x-www-form-urlencoded\r\n"
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
                    "POST /form-redact HTTP/1.1\r\n"
                    "Host: demo-upstream:8443\r\n"
                    "Content-Type: application/x-www-form-urlencoded\r\n"
                    f"Content-Length: {len(payload)}\r\n"
                    "Connection: close\r\n"
                    "\r\n"
                ).encode("ascii")
            )
            for offset in range(0, len(payload), 2048):
                tls.sendall(payload[offset : offset + 2048])
            return read_http(tls)


absolute_payload = form_payload(480)
status, headers, body = request_absolute(absolute_payload)
assert status == 200, (status, headers, body[:512])
assert headers.get("transfer-encoding", "").lower() == "chunked", headers
assert headers.get("content-type", "").startswith("application/x-www-form-urlencoded"), headers
assert_form_result(body, 480)

connect_payload = form_payload(355)
status, headers, body = request_connect(connect_payload)
assert status == 200, (status, headers, body[:512])
assert headers.get("transfer-encoding", "").lower() == "chunked", headers
assert headers.get("content-type", "").startswith("application/x-www-form-urlencoded"), headers
assert_form_result(body, 355)

print(json.dumps({"ok": True, "form_urlencoded_streaming_redaction": "pass", "absolute_pairs": 480, "connect_pairs": 355}, sort_keys=True))
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
