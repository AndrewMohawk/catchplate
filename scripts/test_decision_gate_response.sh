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


def request(path: str) -> tuple[int, dict]:
    raw = (
        f"GET https://demo-upstream:8443{path} HTTP/1.1\r\n"
        "Host: demo-upstream:8443\r\n"
        "X-Serverware-Agent: demo-agent\r\n"
        "Connection: close\r\n\r\n"
    )
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


def assert_gmail_redaction(payload: dict, proof: str) -> None:
    assert "authorization" not in payload and "query" not in payload, payload
    assert "serverware_agent" not in payload and "proxy_authorization" not in payload, payload
    for item in payload["messages"]:
        assert item["serverwareAgeProof"] == proof, item
        assert item["threadId"].startswith("thread-"), item
        assert int(item["internalDate"]) > 1776900000000, item
        for key in ("authorization", "query", "payload", "raw", "secretDebug", "serverDebugSecret"):
            assert key not in item, item


status, payload = request("/echo")
assert status == 200, payload
assert payload["authorization_present"] is True, payload
assert payload["authorization_scheme"] == "Bearer", payload
assert payload["credential_marker"] == "initial", payload
assert payload["method"] == "GET", payload
assert payload["path"] == "/echo", payload
for key in ("authorization", "proxy_authorization", "serverware_agent", "cookie", "x_api_key"):
    assert key not in payload, payload

status, payload = request("/echo?reflectCredential=1")
assert status == 502, payload
assert payload == {"error": "response_credential_reflection"}, payload

status, payload = request("/2/tweets")
assert status == 200, payload
assert payload["authorization_present"] is True, payload
assert payload["authorization_scheme"] == "Bearer", payload
assert payload["data"] == [{"id": "tweet-1", "text": "demo"}], payload
for key in ("authorization", "authorization_sha256", "proxy_authorization", "serverware_agent", "cookie", "path", "query"):
    assert key not in payload, payload

status, payload = request("/gmail/v1/users/me/messages?q=subject%3Aserverware-fixture-omit-internal-date")
assert status == 200, payload
assert len(payload["messages"]) == 2, payload
assert_gmail_redaction(payload, "validated")

status, payload = request("/gmail/v1/users/me/messages")
assert status == 200, payload
assert set(payload) == {"messages"}, payload
assert_gmail_redaction(payload, "validated")

status, payload = request("/gmail/v1/users/me/messages/recent-message-1")
assert status == 200, payload
assert payload["id"] == "recent-message-1", payload
assert payload["payload"]["headers"][0]["name"] == "From", payload
assert "body" not in payload["payload"], payload

status, payload = request("/gmail/v1/users/me/messages?q=subject%3Aserverware-fixture-metadata-not-found")
assert status == 200, payload
assert [item["id"] for item in payload["messages"]] == ["recent-message-1"], payload

status, payload = request("/gmail/v1/users/me/messages?q=subject%3Aserverware-fixture-duplicate-message-id")
assert status == 502, payload
assert payload == {"error": "gmail_metadata_fetch_duplicate_id"}, payload

status, payload = request("/gmail/v1/users/me/messages?q=subject%3Aserverware-fixture-old-internal-date")
assert status == 502, payload
assert payload == {"error": "gmail_response_too_old", "max_days": 30}, payload

status, payload = request("/gmail/v1/users/me/messages/old-list-message-1")
assert status == 403, payload
denial = payload.get("payload") if isinstance(payload.get("payload"), dict) else payload
assert denial["error"] == "gmail_message_age_not_proven", payload

print(json.dumps({"ok": True, "response_validation": "pass"}, sort_keys=True))
PY
