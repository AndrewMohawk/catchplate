#!/usr/bin/env bash
set -euo pipefail

BASE="${BASE:-http://localhost:3000}"
ADMIN_TOKEN="${SERVERWARE_ADMIN_TOKEN:-dev-admin-token}"
DATA_PLANE_TOKEN="${SERVERWARE_DATA_PLANE_AUDIT_TOKEN:-dev-data-plane-audit-token}"

python3 - "$BASE" "$ADMIN_TOKEN" "$DATA_PLANE_TOKEN" <<'PY'
import concurrent.futures
import json
import sys
import time
import urllib.request

base = sys.argv[1].rstrip("/")
admin_token = sys.argv[2]
data_plane_token = sys.argv[3]
marker = f"pg-audit-{time.time_ns()}"
event_count = 48


def request_json(path: str, *, method: str = "GET", headers: dict[str, str] | None = None, payload: dict | None = None) -> dict | list:
    body = None
    request_headers = dict(headers or {})
    if payload is not None:
        body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        request_headers["Content-Type"] = "application/json"
    req = urllib.request.Request(f"{base}{path}", data=body, method=method, headers=request_headers)
    with urllib.request.urlopen(req, timeout=15) as response:
        return json.loads(response.read())


admin_headers = {"X-Serverware-Admin-Token": admin_token}
data_plane_headers = {"X-Serverware-Data-Plane-Token": data_plane_token}

status = request_json("/api/audit/store/status", headers=admin_headers)
assert status["backend"] == "postgres", status
assert status["ha"] is True, status
assert status["serial_append"] == "pg_advisory_xact_lock", status

before = request_json("/api/audit/verify", headers=admin_headers)
assert before["ok"] is True and before["complete"] is True, before
assert before["backend"] == "postgres" and before["ha"] is True, before
start_total = int(before["total"])


def post_event(index: int) -> dict:
    payload = {
        "events": [
            {
                "event_type": "data_plane.audit_store.concurrent_append",
                "actor_id": f"decision-gate-rs-{index % 6}",
                "event": {
                    "marker": marker,
                    "index": index,
                    "created_by": "test_control_plane_audit_store",
                },
            }
        ]
    }
    return request_json("/api/data-plane/audit", method="POST", headers=data_plane_headers, payload=payload)


with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
    results = list(pool.map(post_event, range(event_count)))

assert all(item.get("ok") is True and item.get("accepted") == 1 for item in results), results

deadline = time.time() + 20
last_verify = {}
latest_events: list[dict] = []
while time.time() < deadline:
    last_verify = request_json("/api/audit/verify", headers=admin_headers)
    latest_events = request_json("/api/audit?limit=500", headers=admin_headers)
    found = {
        int((item.get("event") or {}).get("index"))
        for item in latest_events
        if (item.get("event") or {}).get("marker") == marker
    }
    if (
        last_verify.get("ok") is True
        and last_verify.get("complete") is True
        and int(last_verify.get("total") or 0) >= start_total + event_count
        and found == set(range(event_count))
    ):
        print(
            json.dumps(
                {
                    "ok": True,
                    "audit_store": "postgres",
                    "ha": True,
                    "serial_append": last_verify.get("serial_append"),
                    "concurrent_events": event_count,
                    "start_total": start_total,
                    "end_total": int(last_verify.get("total") or 0),
                },
                sort_keys=True,
            )
        )
        break
    time.sleep(0.25)
else:
    raise SystemExit(
        f"postgres audit chain did not contain all concurrent events; verify={last_verify} marker={marker}"
    )
PY
