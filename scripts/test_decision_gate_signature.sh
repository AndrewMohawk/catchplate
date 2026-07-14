#!/usr/bin/env bash
set -euo pipefail

BASE="${BASE:-http://localhost:3000}"
ADMIN_TOKEN="${SERVERWARE_ADMIN_TOKEN:-dev-admin-token}"
TMP_DIR="${TMP_DIR:-.tmp}"
WORK_DIR="$TMP_DIR/decision-gate-signature"

mkdir -p "$WORK_DIR"

curl -fsS -H "X-Serverware-Admin-Token: $ADMIN_TOKEN" "$BASE/api/policy" > "$WORK_DIR/policy-status.json"
python3 - "$WORK_DIR/policy-status.json" "$WORK_DIR/policy-tampered.json" "$WORK_DIR/policy-valid.json" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    status = json.load(handle)
bundle = status["bundle"]
with open(sys.argv[3], "w", encoding="utf-8") as handle:
    json.dump(bundle, handle, separators=(",", ":"), sort_keys=True)
    handle.write("\n")
metadata = bundle.setdefault("metadata", {})
metadata["sequence"] = int(metadata.get("sequence") or 1) + 1
with open(sys.argv[2], "w", encoding="utf-8") as handle:
    json.dump(bundle, handle, separators=(",", ":"), sort_keys=True)
    handle.write("\n")
PY

docker compose cp serverware:/data/policy-signing-ed25519.pub.pem "$WORK_DIR/policy-signing-ed25519.pub.pem" >/dev/null 2>&1
image="$(docker compose images -q decision-gate-rs)"
if [[ -z "$image" ]]; then
  echo "decision-gate-rs image is not built" >&2
  exit 1
fi

abs_work_dir="$(cd "$WORK_DIR" && pwd)"
if docker run --rm \
  -e SERVERWARE_RELEASE_CHANNEL=test \
  -e SERVERWARE_POLICY_BUNDLE=/policy/policy-tampered.json \
  -e SERVERWARE_POLICY_SIGNING_PUBLIC_KEY=/policy/policy-signing-ed25519.pub.pem \
  -v "$abs_work_dir:/policy:ro" \
  "$image" > "$WORK_DIR/tampered.out" 2> "$WORK_DIR/tampered.err"; then
  echo "expected tampered policy bundle to fail Rust gate startup" >&2
  cat "$WORK_DIR/tampered.out" >&2
  cat "$WORK_DIR/tampered.err" >&2
  exit 1
fi

if ! grep -qi "policy signature verification failed" "$WORK_DIR/tampered.err"; then
  echo "expected signature failure in Rust gate stderr" >&2
  cat "$WORK_DIR/tampered.err" >&2
  exit 1
fi

if docker run --rm \
  -e SERVERWARE_RELEASE_CHANNEL=test \
  -e SERVERWARE_POLICY_BUNDLE=/policy/policy-valid.json \
  -e SERVERWARE_POLICY_SIGNING_PUBLIC_KEY=/policy/policy-signing-ed25519.pub.pem \
  -e SERVERWARE_EXPECTED_POLICY_SIGNING_KEY_ID=sha256:0000000000000000000000000000000000000000000000000000000000000000 \
  -v "$abs_work_dir:/policy:ro" \
  "$image" > "$WORK_DIR/wrong-key.out" 2> "$WORK_DIR/wrong-key.err"; then
  echo "expected untrusted policy signing key to fail Rust gate startup" >&2
  cat "$WORK_DIR/wrong-key.out" >&2
  cat "$WORK_DIR/wrong-key.err" >&2
  exit 1
fi

if ! grep -qi "policy signing key is not trusted" "$WORK_DIR/wrong-key.err"; then
  echo "expected signing key trust failure in Rust gate stderr" >&2
  cat "$WORK_DIR/wrong-key.err" >&2
  exit 1
fi

echo "decision gate signature tamper test passed"
