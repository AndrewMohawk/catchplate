#!/usr/bin/env bash
# Two read-only synthetic application requests, not production acceptance.
# Usage: CATCHPLATE_PILOT_CA=/absolute/public-ca.pem bash scripts/check_development_pilot.sh
set -euo pipefail

if test "$#" -ne 0 || [[ "${CATCHPLATE_PILOT_CA:-}" != /* ]] \
    || test ! -f "$CATCHPLATE_PILOT_CA" || test ! -r "$CATCHPLATE_PILOT_CA"; then
    printf '%s\n' 'FAIL: set CATCHPLATE_PILOT_CA to a readable absolute public CA file; no arguments accepted' >&2
    exit 2
fi
if ! command -v curl >/dev/null || ! command -v python3 >/dev/null; then
    printf '%s\n' 'FAIL: curl and Python 3 are required' >&2
    exit 2
fi

check_response() {
    # Bounded input only; neither JSON parse errors nor response bytes escape.
    python3 -I -S -c '
import json
import sys

try:
    maximum = 65536
    raw = sys.stdin.buffer.read(maximum + 5)
    if len(raw) > maximum + 4:
        raise ValueError("response bound")
    body, status = raw.rsplit(b"\n", 1)
    if not body or len(body) > maximum:
        raise ValueError("body bound")
    value = json.loads(body)
    if type(value) is not dict:
        raise ValueError("response shape")
    if sys.argv[1] == "allow":
        forbidden = {"authorization", "authorization_sha256", "proxy_authorization", "catchplate_agent"}
        valid = (status == b"200" and value.get("authorization_present") is True
            and value.get("authorization_scheme") == "Bearer"
            and value.get("credential_marker") == "initial"
            and value.get("path") == "/echo" and not forbidden.intersection(value))
    else:
        payload = value.get("payload")
        valid = (status == b"403" and type(payload) is dict
            and payload.get("error") == "unknown_route_denied")
    if not valid:
        raise ValueError("expected marker absent")
except Exception:
    raise SystemExit(1)
' "$1" 2>/dev/null
}

request() {
    # --disable must be first: ignore curlrc, including redirects or tracing.
    # The body reader also enforces the cap when Content-Length is absent.
    curl --disable --silent --connect-timeout 3 --max-time 10 \
        --max-filesize 65536 --proto '=https' --max-redirs 0 --noproxy '' \
        --proxy http://127.0.0.1:18080 \
        --proxy-header 'X-Catchplate-Agent: demo-token-agent' \
        --proxy-header 'Proxy-Authorization: Bearer demo-agent-proxy-token' \
        --cacert "$CATCHPLATE_PILOT_CA" --write-out '\n%{http_code}' \
        "https://demo-upstream:8443/$1" 2>/dev/null
}

if ! request echo | check_response allow; then
    printf '%s\n' 'FAIL: allowed request did not prove HTTP 200 injection/redaction; response not printed' >&2
    exit 1
fi
printf '%s\n' 'PASS: synthetic upstream credential used; raw credentials and proxy identity absent'

if ! request not-allowed | check_response deny; then
    printf '%s\n' 'FAIL: denied request did not prove HTTP 403 unknown_route_denied; response not printed' >&2
    exit 1
fi
printf '%s\n' 'PASS: valid workload identity denied access to an unlisted route (HTTP 403)'
