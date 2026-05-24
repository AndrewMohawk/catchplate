#!/usr/bin/env bash
set -euo pipefail

GATE="${DECISION_GATE_BASE:-http://localhost:9090}"
BASE="${BASE:-http://localhost:3000}"

python3 - "$GATE" <<'PY'
import json
import sys
import urllib.request

gate = sys.argv[1].rstrip("/")


def request_json(path: str, payload: dict | None = None) -> dict:
    data = None if payload is None else json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    req = urllib.request.Request(f"{gate}{path}", data=data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as response:
        return json.loads(response.read())


payload = {
    "clientIp": "127.0.0.1",
    "method": "GET",
    "url": "https://demo-upstream:8443/echo",
    "headers": {"X-Serverware-Agent": "demo-agent"},
}
health = request_json("/healthz")
decision = request_json("/v1/decide", payload)
assert health["routes"] == 12, health
assert decision["action"] == "allow" and decision["route_id"] == "demo.echo", decision
print(json.dumps({"ok": True, "stage": "initial", "policy_hash": health["policy_hash"]}, sort_keys=True))
PY

docker compose exec -T serverware python - <<'PY'
import os
import time

from serverware.config import POLICY_BUNDLE_PATH
from serverware.policy_bundle import demo_policy_bundle, write_policy_bundle

bundle = demo_policy_bundle("cred-demo-bearer")
bundle["metadata"]["sequence"] = 101
bundle["routes"] = [route for route in bundle["routes"] if route["id"] != "demo.echo"]
snapshot = write_policy_bundle(bundle)
now = time.time()
os.utime(POLICY_BUNDLE_PATH, (now, now))
print(snapshot.hash)
PY

python3 - "$GATE" <<'PY'
import json
import sys
import time
import urllib.request

gate = sys.argv[1].rstrip("/")


def request_json(path: str, payload: dict | None = None) -> dict:
    data = None if payload is None else json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    req = urllib.request.Request(f"{gate}{path}", data=data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as response:
        return json.loads(response.read())


payload = {
    "clientIp": "127.0.0.1",
    "method": "GET",
    "url": "https://demo-upstream:8443/echo",
    "headers": {"X-Serverware-Agent": "demo-agent"},
}
deadline = time.time() + 15
while time.time() < deadline:
    health = request_json("/healthz")
    if health["routes"] == 11:
        break
    time.sleep(0.25)
else:
    raise SystemExit("Rust gate did not hot-reload the reduced policy")

decision = request_json("/v1/decide", payload)
assert decision["action"] == "deny", decision
assert decision["payload"]["error"] == "unknown_route_denied", decision
print(json.dumps({"ok": True, "stage": "reduced-policy", "policy_hash": health["policy_hash"]}, sort_keys=True))
PY

failed_before="$(python3 - "$GATE" <<'PY'
import json
import sys
import urllib.request

gate = sys.argv[1].rstrip("/")
with urllib.request.urlopen(f"{gate}/healthz", timeout=10) as response:
    health = json.loads(response.read())
print((health.get("policy_reload") or {}).get("failed", 0))
PY
)"

docker compose exec -T serverware python - <<'PY'
import os
import time

from serverware.config import POLICY_BUNDLE_PATH

POLICY_BUNDLE_PATH.write_text("{ invalid policy\n")
now = time.time()
os.utime(POLICY_BUNDLE_PATH, (now, now))
PY

python3 - "$GATE" "$failed_before" "$BASE" <<'PY'
import json
import sys
import time
import urllib.request

gate = sys.argv[1].rstrip("/")
failed_before = int(sys.argv[2])
base = sys.argv[3].rstrip("/")


def request_json(path: str, payload: dict | None = None) -> dict:
    data = None if payload is None else json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    req = urllib.request.Request(f"{gate}{path}", data=data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as response:
        return json.loads(response.read())


payload = {
    "clientIp": "127.0.0.1",
    "method": "GET",
    "url": "https://demo-upstream:8443/echo",
    "headers": {"X-Serverware-Agent": "demo-agent"},
}
deadline = time.time() + 15
while time.time() < deadline:
    health = request_json("/healthz")
    failed = (health.get("policy_reload") or {}).get("failed", 0)
    if failed > failed_before:
        break
    time.sleep(0.25)
else:
    raise SystemExit("Rust gate did not observe invalid policy reload")

assert health["routes"] == 11, health
decision = request_json("/v1/decide", payload)
assert decision["action"] == "deny", decision
assert decision["payload"]["error"] == "unknown_route_denied", decision
with urllib.request.urlopen(f"{base}/healthz", timeout=10) as response:
    control_health = json.loads(response.read())
assert control_health["ok"] is True, control_health
assert control_health["policy_ready"] is False, control_health
print(json.dumps({"ok": True, "stage": "invalid-policy-retained-last-good", "failed": failed}, sort_keys=True))
PY

docker compose exec -T serverware python - <<'PY'
import os
import time

from serverware.config import POLICY_BUNDLE_PATH
from serverware.policy_bundle import demo_policy_bundle, write_policy_bundle

bundle = demo_policy_bundle("cred-demo-bearer")
bundle["metadata"]["sequence"] = 102
snapshot = write_policy_bundle(bundle)
now = time.time()
os.utime(POLICY_BUNDLE_PATH, (now, now))
print(snapshot.hash)
PY

python3 - "$GATE" <<'PY'
import json
import sys
import time
import urllib.request

gate = sys.argv[1].rstrip("/")


def request_json(path: str, payload: dict | None = None) -> dict:
    data = None if payload is None else json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    req = urllib.request.Request(f"{gate}{path}", data=data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as response:
        return json.loads(response.read())


payload = {
    "clientIp": "127.0.0.1",
    "method": "GET",
    "url": "https://demo-upstream:8443/echo",
    "headers": {"X-Serverware-Agent": "demo-agent"},
}
deadline = time.time() + 15
while time.time() < deadline:
    health = request_json("/healthz")
    if health["routes"] == 12:
        break
    time.sleep(0.25)
else:
    raise SystemExit("Rust gate did not hot-reload the restored policy")

decision = request_json("/v1/decide", payload)
assert decision["action"] == "allow" and decision["route_id"] == "demo.echo", decision
print(json.dumps({"ok": True, "stage": "restored-policy", "policy_hash": health["policy_hash"]}, sort_keys=True))
PY
