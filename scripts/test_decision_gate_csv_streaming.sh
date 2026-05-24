#!/usr/bin/env bash
set -euo pipefail

GATE_HOST="${DECISION_GATE_HOST:-localhost}"
GATE_PORT="${DECISION_GATE_PORT:-9090}"
CA_FILE="${SERVERWARE_CA_OUT:-.tmp/serverware-ca.pem}"

python3 - "$GATE_HOST" "$GATE_PORT" "$CA_FILE" <<'PY'
import csv
import io
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


def csv_payload(count: int) -> bytes:
    out = io.StringIO(newline="")
    writer = csv.DictWriter(
        out,
        fieldnames=["id", "public", "safe_note", "secret", "token", "padding"],
        lineterminator="\n",
    )
    writer.writeheader()
    for index in range(count):
        writer.writerow(
            {
                "id": str(index),
                "public": f"value-{index}",
                "safe_note": f"safe-{index}\ncontinued" if index % 57 == 0 else f"safe-{index}",
                "secret": f"top-secret-{index}",
                "token": f"token-secret-{index}",
                "padding": "x" * 80,
            }
        )
    return out.getvalue().encode("utf-8")


def assert_csv_result(body: bytes, expected_count: int) -> None:
    assert b"top-secret" not in body, body[:512]
    assert b"token-secret" not in body, body[:512]
    assert b"must-be-redacted" not in body, body[:512]
    assert b"upstreamSecret" not in body, body[:512]
    reader = csv.DictReader(io.StringIO(body.decode("utf-8"), newline=""))
    assert reader.fieldnames == [
        "id",
        "public",
        "safe_note",
        "sawSecret",
        "authorization_present",
        "authorization_scheme",
        "authorization_sha256",
    ], reader.fieldnames
    rows = list(reader)
    assert len(rows) == expected_count, len(rows)
    for index, row in enumerate(rows):
        assert row["id"] == str(index), row
        assert row["public"] == f"value-{index}", row
        expected_safe = f"safe-{index}\ncontinued" if index % 57 == 0 else f"safe-{index}"
        assert row["safe_note"] == expected_safe, row
        assert row["sawSecret"] == "false", row
        assert row["authorization_present"] == "true", row
        assert row["authorization_scheme"] == "Bearer", row
        assert row["authorization_sha256"].startswith("sha256:"), row


def request_absolute(payload: bytes):
    with socket.create_connection((host, port), timeout=10) as sock:
        sock.sendall(
            (
                "POST https://demo-upstream:8443/csv-redact HTTP/1.1\r\n"
                "Host: demo-upstream:8443\r\n"
                "X-Serverware-Agent: demo-agent\r\n"
                "Content-Type: text/csv\r\n"
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
                    "POST /csv-redact HTTP/1.1\r\n"
                    "Host: demo-upstream:8443\r\n"
                    "Content-Type: text/csv\r\n"
                    f"Content-Length: {len(payload)}\r\n"
                    "Connection: close\r\n"
                    "\r\n"
                ).encode("ascii")
            )
            for offset in range(0, len(payload), 2048):
                tls.sendall(payload[offset : offset + 2048])
            return read_http(tls)


absolute_payload = csv_payload(260)
status, headers, body = request_absolute(absolute_payload)
assert status == 200, (status, headers, body[:512])
assert headers.get("transfer-encoding", "").lower() == "chunked", headers
assert headers.get("content-type", "").startswith("text/csv"), headers
assert_csv_result(body, 260)

connect_payload = csv_payload(185)
status, headers, body = request_connect(connect_payload)
assert status == 200, (status, headers, body[:512])
assert headers.get("transfer-encoding", "").lower() == "chunked", headers
assert headers.get("content-type", "").startswith("text/csv"), headers
assert_csv_result(body, 185)

status, headers, body = request_absolute(b"id,id,secret\n1,dupe,top-secret\n")
assert status >= 400, (status, headers, body[:512])
assert b"top-secret" not in body, body[:512]

print(json.dumps({"ok": True, "csv_streaming_redaction": "pass", "absolute_records": 260, "connect_records": 185}, sort_keys=True))
PY
