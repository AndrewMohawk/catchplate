#!/usr/bin/env bash
set -euo pipefail

GATE_HOST="${DECISION_GATE_HOST:-localhost}"
GATE_PORT="${DECISION_GATE_PORT:-9090}"

python3 - "$GATE_HOST" "$GATE_PORT" <<'PY'
import json
import socket
import subprocess
import sys

host = sys.argv[1]
port = int(sys.argv[2])


def release_store() -> dict:
    query = """
    SELECT json_build_object(
      'attempts', COUNT(*),
      'forwarded', COUNT(*) FILTER (WHERE state = 'committed' AND completion_outcome = 'forwarded'),
      'nonterminal', COUNT(*) FILTER (WHERE state IN ('reserved', 'dispatching')),
      'uncorrelated', COUNT(*) FILTER (WHERE attempt_id <> flow_id)
    ) FROM release_authorization_attempts WHERE route_id = 'demo.echo'
    """
    output = subprocess.check_output(
        ["docker", "compose", "exec", "-T", "grant-store", "psql", "-U", "serverware", "-d", "serverware", "-Atq", "-c", query],
        text=True,
    )
    return json.loads(output)


def request(raw: str) -> tuple[int, dict]:
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


before_forward = release_store()
status, payload = request(
    "GET https://demo-upstream:8443/echo HTTP/1.1\r\n"
    "Host: demo-upstream:8443\r\n"
    "X-Serverware-Agent: demo-agent\r\n"
    "X-Serverware-Data-Plane-Token: caller-controlled-value\r\n"
    "Connection: close\r\n\r\n"
)
assert status == 200, payload
assert payload["authorization_present"] is True, payload
assert payload["authorization_scheme"] == "Bearer", payload
assert payload["credential_marker"] == "initial", payload
assert "authorization_sha256" not in payload, payload
assert "authorization" not in payload, payload
assert "proxy_authorization" not in payload, payload
assert "serverware_agent" not in payload, payload
assert payload["query"]["_data_plane_token_seen"] is False, payload
assert payload["path"] == "/echo", payload

status, payload = request(
    "GET https://demo-upstream:8443/echo HTTP/1.1\r\n"
    "Host: demo-upstream:8443\r\n"
    "X-Serverware-Agent: demo-token-agent\r\n"
    "Proxy-Authorization: Bearer demo-agent-proxy-token\r\n"
    "Connection: close\r\n\r\n"
)
assert status == 200, payload
assert payload["authorization_present"] is True, payload
assert payload["authorization_scheme"] == "Bearer", payload
assert payload["credential_marker"] == "initial", payload
assert "authorization_sha256" not in payload, payload
assert "authorization" not in payload, payload
assert "proxy_authorization" not in payload, payload
assert "serverware_agent" not in payload, payload
assert payload["path"] == "/echo", payload

after_forward = release_store()
assert after_forward["attempts"] == before_forward["attempts"] + 2, (before_forward, after_forward)
assert after_forward["forwarded"] == before_forward["forwarded"] + 2, (before_forward, after_forward)
assert after_forward["nonterminal"] == before_forward["nonterminal"], (before_forward, after_forward)
assert after_forward["uncorrelated"] == before_forward["uncorrelated"], (before_forward, after_forward)

status, payload = request(
    "GET https://demo-upstream:8443/echo HTTP/1.1\r\n"
    "Host: demo-upstream:8443\r\n"
    "X-Serverware-Agent: demo-token-agent\r\n"
    "Connection: close\r\n\r\n"
)
assert status == 403, payload
assert payload["payload"]["error"] == "client_principal_denied", payload

status, payload = request(
    "GET https://demo-upstream:8443/not-allowed HTTP/1.1\r\n"
    "Host: demo-upstream:8443\r\n"
    "X-Serverware-Agent: demo-agent\r\n"
    "Connection: close\r\n\r\n"
)
assert status == 403, payload
assert payload["payload"]["error"] == "unknown_route_denied", payload

status, payload = request(
    "GET https://demo-upstream:8443/echo HTTP/1.1\r\n"
    "Host: demo-upstream:8443\r\n"
    "Connection: close\r\n\r\n"
)
assert status == 403, payload
assert payload["payload"]["error"] == "client_principal_denied", payload

status, payload = request(
    "GET https://unknown-upstream:8443/echo HTTP/1.1\r\n"
    "Host: unknown-upstream:8443\r\n"
    "X-Serverware-Agent: demo-agent\r\n"
    "Connection: close\r\n\r\n"
)
assert status == 403, payload
assert payload["payload"]["error"] == "unknown_route_denied", payload

assert release_store() == after_forward, (after_forward, release_store())

print(json.dumps({"ok": True, "absolute_form_forward": "pass"}, sort_keys=True))
PY
