#!/usr/bin/env bash
set -euo pipefail

BASE="${BASE:-http://localhost:3000}"
ANCHOR="${AUDIT_ANCHOR_BASE:-http://localhost:9100}"
ADMIN_TOKEN="${SERVERWARE_ADMIN_TOKEN:-dev-admin-token}"
ANCHOR_TOKEN="${SERVERWARE_AUDIT_ANCHOR_TOKEN:-dev-audit-anchor-token}"

python3 - "$BASE" "$ANCHOR" "$ADMIN_TOKEN" "$ANCHOR_TOKEN" <<'PY'
import json
import sys
import urllib.request

base = sys.argv[1].rstrip("/")
anchor = sys.argv[2].rstrip("/")
admin_token = sys.argv[3]
anchor_token = sys.argv[4]


def request_json(
    url: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    timeout: float = 10,
) -> dict:
    req = urllib.request.Request(url, method=method, headers=headers or {})
    with urllib.request.urlopen(req, timeout=timeout) as response:
        return json.loads(response.read())


admin_headers = {"X-Serverware-Admin-Token": admin_token}
anchor_headers = {"X-Serverware-Audit-Anchor-Token": anchor_token}

flush = request_json(f"{base}/api/audit/anchors/flush", method="POST", headers=admin_headers, timeout=60)
assert flush["enabled"] is True, flush
assert flush["exported"] is True, flush
local = flush["verification"]
assert local["ok"] is True and local["complete"] is True, local

anchor_response = flush.get("anchor_response") or {}
assert anchor_response.get("ok") is True, anchor_response
accepted = anchor_response.get("anchors") or []
assert len(accepted) == 1, anchor_response
sequence = accepted[0]["sequence"]

status = request_json(f"{base}/api/audit/anchors/status", headers=admin_headers)
assert status["enabled"] is True, status
assert (status.get("last_exported") or {}).get("count", 0) >= local["count"], status
proof = request_json(f"{anchor}/anchors/inclusion/{sequence}", headers=anchor_headers)
assert proof["verified"] is True, proof
assert (proof["item"].get("record") or {}).get("audit_head") == local["head"], proof
assert (proof["item"].get("record") or {}).get("audit_count") == local["count"], proof
external = (proof["item"].get("external_checkpoint") or {})
item_signed_head = proof["item"].get("signed_tree_head") or {}
assert external.get("ok") is True, proof
assert external.get("mode") == "external-managed-transparency-log", proof
assert external.get("tree_head_hash") == item_signed_head.get("tree_head_hash"), proof
assert external.get("tree_size") == item_signed_head.get("tree_size"), proof
print(json.dumps({"ok": True, "audit_anchor": "pass", "backend": anchor_response["mode"], "external_checkpoint": external.get("provider"), "local_count": local["count"], "anchor_sequence": sequence, "inclusion_verified": True}, sort_keys=True))
PY
