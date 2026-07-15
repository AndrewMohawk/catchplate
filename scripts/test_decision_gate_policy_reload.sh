#!/usr/bin/env bash
set -euo pipefail

GATE="${DECISION_GATE_BASE:-http://localhost:9091}"
BASE="${BASE:-http://localhost:3000}"
export SERVERWARE_DATA_PLANE_MANAGEMENT_TOKEN="${SERVERWARE_DATA_PLANE_MANAGEMENT_TOKEN:-dev-rust-management-token}"

python3 - "$GATE" <<'PY'
import json
import os
import sys
import urllib.request

gate = sys.argv[1].rstrip("/")


def request_json(path: str, payload: dict | None = None) -> dict:
    data = None if payload is None else json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    req = urllib.request.Request(
        f"{gate}{path}",
        data=data,
        headers={
            "Content-Type": "application/json",
            "X-Serverware-Data-Plane-Token": os.environ["SERVERWARE_DATA_PLANE_MANAGEMENT_TOKEN"],
        },
    )
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
assert int(health["routes"]) > 0, health
assert decision["action"] == "allow" and decision["route_id"] == "demo.echo", decision
print(json.dumps({"ok": True, "stage": "initial", "policy_hash": health["policy_hash"]}, sort_keys=True))
PY

reduced_hash="$(docker compose exec -T serverware python - <<'PY'
import os
import time

from serverware.config import POLICY_BUNDLE_PATH
from serverware.policy_bundle import demo_policy_bundle, get_policy_snapshot, write_policy_bundle

bundle = demo_policy_bundle("cred-demo-bearer")
current = get_policy_snapshot()
bundle["metadata"]["sequence"] = int(current.raw["metadata"]["sequence"]) + 1
bundle["routes"] = [route for route in bundle["routes"] if route["id"] != "demo.echo"]
snapshot = write_policy_bundle(bundle, enforce_high_water=True)
now = time.time()
os.utime(POLICY_BUNDLE_PATH, (now, now))
print(snapshot.hash)
PY
)"

python3 - "$GATE" "$reduced_hash" <<'PY'
import json
import os
import sys
import time
import urllib.request

gate = sys.argv[1].rstrip("/")
expected_hash = sys.argv[2]


def request_json(path: str, payload: dict | None = None) -> dict:
    data = None if payload is None else json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    req = urllib.request.Request(
        f"{gate}{path}",
        data=data,
        headers={
            "Content-Type": "application/json",
            "X-Serverware-Data-Plane-Token": os.environ["SERVERWARE_DATA_PLANE_MANAGEMENT_TOKEN"],
        },
    )
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
    if health["policy_hash"] == expected_hash and health.get("credential_generations_ready") is True:
        break
    time.sleep(0.25)
else:
    raise SystemExit("Rust gate did not hot-reload the reduced policy")

decision = request_json("/v1/decide", payload)
assert decision["action"] == "deny", decision
assert decision["payload"]["error"] == "unknown_route_denied", decision
print(json.dumps({"ok": True, "stage": "reduced-policy", "policy_hash": health["policy_hash"]}, sort_keys=True))
PY

unsupported_failed_before="$(python3 - "$GATE" <<'PY'
import json
import sys
import urllib.request

gate = sys.argv[1].rstrip("/")
with urllib.request.urlopen(f"{gate}/healthz", timeout=10) as response:
    health = json.loads(response.read())
print((health.get("policy_reload") or {}).get("failed", 0))
PY
)"

unsupported_hash="$(docker compose exec -T serverware python - <<'PY'
import json
import os
import time

from serverware.config import POLICY_BUNDLE_PATH
from serverware.policy_bundle import demo_policy_bundle, get_policy_snapshot, policy_hash, sign_policy_bundle

bundle = demo_policy_bundle("cred-demo-bearer")
current = get_policy_snapshot()
bundle["metadata"]["sequence"] = int(current.raw["metadata"]["sequence"]) + 1
jit_route = next(route for route in bundle["routes"] if route["id"] == "demo.npm.publish.jit")
jit_route["jit"]["approvers"]["quorum"] = 2
signed = sign_policy_bundle(bundle)
POLICY_BUNDLE_PATH.write_text(json.dumps(signed, indent=2, sort_keys=True) + "\n")
now = time.time()
os.utime(POLICY_BUNDLE_PATH, (now, now))
print(policy_hash(signed))
PY
)"

python3 - "$GATE" "$unsupported_failed_before" "$reduced_hash" "$unsupported_hash" <<'PY'
import json
import os
import sys
import time
import urllib.request

gate = sys.argv[1].rstrip("/")
failed_before = int(sys.argv[2])
expected_hash = sys.argv[3]
unsupported_hash = sys.argv[4]


def request_json(path: str, payload: dict | None = None) -> dict:
    data = None if payload is None else json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    req = urllib.request.Request(
        f"{gate}{path}",
        data=data,
        headers={
            "Content-Type": "application/json",
            "X-Serverware-Data-Plane-Token": os.environ["SERVERWARE_DATA_PLANE_MANAGEMENT_TOKEN"],
        },
    )
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
    raise SystemExit("Rust gate did not reject the signed unsupported policy reload")

assert unsupported_hash != expected_hash, (unsupported_hash, expected_hash)
assert health["policy_hash"] == expected_hash, health
decision = request_json("/v1/decide", payload)
assert decision["action"] == "deny", decision
assert decision["payload"]["error"] == "unknown_route_denied", decision
print(json.dumps({
    "ok": True,
    "stage": "signed-unsupported-policy-retained-last-good",
    "failed": failed,
    "rejected_policy_hash": unsupported_hash,
}, sort_keys=True))
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

python3 - "$GATE" "$failed_before" "$BASE" "$reduced_hash" <<'PY'
import json
import os
import sys
import time
import urllib.request

gate = sys.argv[1].rstrip("/")
failed_before = int(sys.argv[2])
base = sys.argv[3].rstrip("/")
expected_hash = sys.argv[4]


def request_json(path: str, payload: dict | None = None) -> dict:
    data = None if payload is None else json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    req = urllib.request.Request(
        f"{gate}{path}",
        data=data,
        headers={
            "Content-Type": "application/json",
            "X-Serverware-Data-Plane-Token": os.environ["SERVERWARE_DATA_PLANE_MANAGEMENT_TOKEN"],
        },
    )
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

assert health["policy_hash"] == expected_hash, health
decision = request_json("/v1/decide", payload)
assert decision["action"] == "deny", decision
assert decision["payload"]["error"] == "unknown_route_denied", decision
with urllib.request.urlopen(f"{base}/healthz", timeout=10) as response:
    control_health = json.loads(response.read())
assert control_health["ok"] is True, control_health
assert control_health["policy_ready"] is False, control_health
print(json.dumps({"ok": True, "stage": "invalid-policy-retained-last-good", "failed": failed}, sort_keys=True))
PY

restored_hash="$(docker compose exec -T serverware python - <<'PY'
import os
import time

from serverware.config import POLICY_BUNDLE_PATH
from serverware import db
from serverware.policy_bundle import demo_policy_bundle, write_policy_bundle

bundle = demo_policy_bundle("cred-demo-bearer")
bundle["metadata"]["sequence"] = int(db.get_policy_high_water()["sequence"]) + 1
snapshot = write_policy_bundle(bundle, enforce_high_water=True)
now = time.time()
os.utime(POLICY_BUNDLE_PATH, (now, now))
print(snapshot.hash)
PY
)"

python3 - "$GATE" "$restored_hash" <<'PY'
import json
import os
import sys
import time
import urllib.request

gate = sys.argv[1].rstrip("/")
expected_hash = sys.argv[2]


def request_json(path: str, payload: dict | None = None) -> dict:
    data = None if payload is None else json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    req = urllib.request.Request(
        f"{gate}{path}",
        data=data,
        headers={
            "Content-Type": "application/json",
            "X-Serverware-Data-Plane-Token": os.environ["SERVERWARE_DATA_PLANE_MANAGEMENT_TOKEN"],
        },
    )
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
    if health["policy_hash"] == expected_hash and health.get("credential_generations_ready") is True:
        break
    time.sleep(0.25)
else:
    raise SystemExit("Rust gate did not hot-reload the restored policy and reacquire its credential generation")

decision = request_json("/v1/decide", payload)
assert decision["action"] == "allow" and decision["route_id"] == "demo.echo", decision
print(json.dumps({"ok": True, "stage": "restored-policy", "policy_hash": health["policy_hash"]}, sort_keys=True))
PY
