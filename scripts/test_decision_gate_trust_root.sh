#!/usr/bin/env bash
set -euo pipefail

GATE="${DECISION_GATE_BASE:-http://localhost:9090}"
TMP_DIR="${TMP_DIR:-.tmp}"
WORK_DIR="$TMP_DIR/decision-gate-trust-root"
mkdir -p "$WORK_DIR"

python3 - "$GATE" <<'PY'
import json
import secrets
import subprocess
import sys
import urllib.request

gate = sys.argv[1].rstrip("/")


def request_json(path: str) -> dict:
    with urllib.request.urlopen(f"{gate}{path}", timeout=10) as response:
        return json.loads(response.read())


health = request_json("/healthz")
assert health["policy_trust_root_source"] == "attested-control-plane", health
nonce = secrets.token_urlsafe(18)
attestation = request_json(f"/attestation?nonce={nonce}")
assert attestation["nonce"] == nonce, attestation
assert attestation["policy_trust_root_source"] == "attested-control-plane", attestation
manifest = attestation["runtime_manifest"]
assert manifest["policy_trust_root_source"] == "attested-control-plane", manifest
assert attestation["policy_signing_key_id"] == manifest["policy_signing_key_id"], attestation

container_id = subprocess.check_output(
    ["docker", "compose", "ps", "-q", "decision-gate-rs"],
    text=True,
).strip()
inspect = json.loads(
    subprocess.check_output(["docker", "inspect", container_id], text=True)
)[0]
env = inspect["Config"]["Env"]
assert any(item.startswith("SERVERWARE_POLICY_TRUST_ROOT_ATTESTATION_URL=") for item in env), env
assert not any(item.startswith("SERVERWARE_POLICY_SIGNING_PUBLIC_KEY=") for item in env), env

print(json.dumps({"ok": True, "policy_trust_root": "attested-control-plane"}, sort_keys=True))
PY

bad_key="sha256:0000000000000000000000000000000000000000000000000000000000000000"
if docker compose run --rm --no-deps \
  -e SERVERWARE_EXPECTED_CONTROL_PLANE_QUOTE_KEY_ID="$bad_key" \
  decision-gate-rs > "$WORK_DIR/wrong-quote-key.out" 2> "$WORK_DIR/wrong-quote-key.err"; then
  echo "expected wrong control-plane quote key to fail Rust gate startup" >&2
  cat "$WORK_DIR/wrong-quote-key.out" >&2
  cat "$WORK_DIR/wrong-quote-key.err" >&2
  exit 1
fi

if ! grep -qi "control-plane quote signing key is not trusted" "$WORK_DIR/wrong-quote-key.err"; then
  echo "expected control-plane quote trust failure in Rust gate stderr" >&2
  cat "$WORK_DIR/wrong-quote-key.err" >&2
  exit 1
fi

echo '{"ok":true,"wrong_quote_key_rejected":true}'
