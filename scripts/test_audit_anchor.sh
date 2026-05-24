#!/usr/bin/env bash
set -euo pipefail

BASE="${BASE:-http://localhost:3000}"
ANCHOR="${AUDIT_ANCHOR_BASE:-http://localhost:9100}"
ADMIN_TOKEN="${SERVERWARE_ADMIN_TOKEN:-dev-admin-token}"
ANCHOR_TOKEN="${SERVERWARE_AUDIT_ANCHOR_TOKEN:-dev-audit-anchor-token}"

python3 - "$BASE" "$ANCHOR" "$ADMIN_TOKEN" "$ANCHOR_TOKEN" <<'PY'
import json
import sys
import time
import urllib.request

base = sys.argv[1].rstrip("/")
anchor = sys.argv[2].rstrip("/")
admin_token = sys.argv[3]
anchor_token = sys.argv[4]


def request_json(url: str, *, method: str = "GET", headers: dict[str, str] | None = None) -> dict:
    req = urllib.request.Request(url, method=method, headers=headers or {})
    with urllib.request.urlopen(req, timeout=10) as response:
        return json.loads(response.read())


admin_headers = {"X-Serverware-Admin-Token": admin_token}
anchor_headers = {"X-Serverware-Audit-Anchor-Token": anchor_token}

flush = request_json(f"{base}/api/audit/anchors/flush", method="POST", headers=admin_headers)
assert flush["enabled"] is True, flush
assert flush["exported"] is True, flush
local = flush["verification"]
assert local["ok"] is True and local["complete"] is True, local

deadline = time.time() + 15
last = {}
while time.time() < deadline:
    last = request_json(f"{anchor}/anchors/verify", headers=anchor_headers)
    record = last.get("last_record") or {}
    if (
        last.get("ok") is True
        and last.get("mode") == "signed-merkle-transparency-log"
        and record.get("audit_head") == local.get("head")
        and record.get("audit_count") == local.get("count")
        and (last.get("signed_tree_head") or {}).get("tree_head_hash") == last.get("head")
    ):
        break
    time.sleep(0.25)
else:
    raise SystemExit(f"anchor sink did not contain latest local chain head: local={local} remote={last}")

status = request_json(f"{base}/api/audit/anchors/status", headers=admin_headers)
assert status["enabled"] is True, status
assert (status.get("last_exported") or {}).get("head") == local["head"], status
proof = request_json(f"{anchor}/anchors/inclusion/{last['count']}", headers=anchor_headers)
assert proof["verified"] is True, proof
assert proof["tree_head_hash"] == last["head"], proof
assert (proof["item"].get("record") or {}).get("audit_head") == local["head"], proof
external = (proof["item"].get("external_checkpoint") or {})
assert external.get("ok") is True, proof
assert external.get("mode") == "external-managed-transparency-log", proof
assert external.get("tree_head_hash") == proof["tree_head_hash"], proof
print(json.dumps({"ok": True, "audit_anchor": "pass", "backend": last["mode"], "external_checkpoint": external.get("provider"), "local_count": local["count"], "anchor_count": last["count"], "inclusion_verified": True}, sort_keys=True))
PY
