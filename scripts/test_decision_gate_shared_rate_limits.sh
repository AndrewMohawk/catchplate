#!/usr/bin/env bash
set -euo pipefail

BASE="${BASE:-http://localhost:3000}"
GATE="${DECISION_GATE_BASE:-http://localhost:9091}"
ADMIN_HEADER=(-H "X-Serverware-Admin-Token: ${SERVERWARE_ADMIN_TOKEN:-dev-admin-token}")

curl -fsS "${ADMIN_HEADER[@]}" -X POST "$BASE/api/demo/seed" >/dev/null

python3 - "$GATE" <<'PY'
import json
import os
import sys
import time
import urllib.request

gate = sys.argv[1].rstrip("/")
management_token = os.environ.get("SERVERWARE_DATA_PLANE_MANAGEMENT_TOKEN", "").strip() or "dev-rust-management-token"


def decide(text: str) -> dict:
    payload = {
        "clientIp": "127.0.0.1",
        "method": "POST",
        "url": "https://demo-upstream:8443/2/tweets",
        "headers": {"X-Serverware-Agent": "demo-agent", "Content-Type": "application/json"},
        "body": json.dumps({"text": text}, separators=(",", ":")),
    }
    req = urllib.request.Request(
        f"{gate}/v1/decide",
        data=json.dumps(payload, separators=(",", ":"), sort_keys=True).encode(),
        headers={
            "Content-Type": "application/json",
            "X-Serverware-Data-Plane-Token": management_token,
        },
    )
    with urllib.request.urlopen(req, timeout=10) as response:
        return json.loads(response.read())


last = None
for _ in range(20):
    last = decide(f"shared quota {int(time.time())}")
    if last.get("route_id") == "demo.x.tweet.one_per_day":
        break
    time.sleep(0.25)
else:
    raise AssertionError(f"decision gate did not load shared quota policy route: {last}")

first = last
assert first["action"] == "allow", first
assert first["route_id"] == "demo.x.tweet.one_per_day", first
assert first["injection"]["credential_ref"] == "cred-demo-bearer", first

second = decide("shared quota second")
assert second["action"] == "deny", second
assert second["payload"]["error"] == "credential_rate_limit_exceeded", second
assert second["payload"]["store"] == "shared", second
assert second["payload"]["constraint_id"] == "x-one-tweet-per-day", second
assert second["payload"]["retry_after_seconds"] > 0, second

print(json.dumps({"ok": True, "shared_rate_limit": "pass", "first": first["action"], "second": second["payload"]["error"]}, sort_keys=True))
PY
