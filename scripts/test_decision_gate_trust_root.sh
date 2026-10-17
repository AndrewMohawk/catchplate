#!/usr/bin/env bash
set -euo pipefail

GATE="${DECISION_GATE_BASE:-http://localhost:9090}"
TMP_DIR="${TMP_DIR:-.tmp}"
WORK_DIR="$TMP_DIR/decision-gate-trust-root"
mkdir -p "$WORK_DIR"

wrong_digest_control_plane="catchplate-wrong-binary-attestation"
cleanup() {
  docker rm -f "$wrong_digest_control_plane" >/dev/null 2>&1 || true
}
trap cleanup EXIT

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
assert any(item.startswith("CATCHPLATE_POLICY_TRUST_ROOT_ATTESTATION_URL=") for item in env), env
assert not any(item.startswith("CATCHPLATE_POLICY_SIGNING_PUBLIC_KEY=") for item in env), env

print(json.dumps({"ok": True, "policy_trust_root": "attested-control-plane"}, sort_keys=True))
PY

bad_key="sha256:0000000000000000000000000000000000000000000000000000000000000000"
if docker compose run --rm --no-deps \
  -e CATCHPLATE_EXPECTED_CONTROL_PLANE_QUOTE_KEY_ID="$bad_key" \
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

bad_digest="sha256:0000000000000000000000000000000000000000000000000000000000000000"
docker compose run -d --no-deps --name "$wrong_digest_control_plane" \
  -e CATCHPLATE_EXPECTED_DATA_PLANE_BINARY_DIGEST="$bad_digest" \
  catchplate > "$WORK_DIR/wrong-binary-control-plane.id"

for _ in $(seq 1 30); do
  if docker exec "$wrong_digest_control_plane" \
    curl -fsS http://localhost:3000/healthz >/dev/null 2>&1; then
    break
  fi
  sleep 0.25
done
if ! docker exec "$wrong_digest_control_plane" \
  curl -fsS http://localhost:3000/healthz >/dev/null 2>&1; then
  echo "isolated wrong-binary control plane did not become healthy" >&2
  docker logs "$wrong_digest_control_plane" >&2
  exit 1
fi

if docker compose run --rm --no-deps \
  -e CATCHPLATE_POLICY_TRUST_ROOT_ATTESTATION_URL="http://$wrong_digest_control_plane:3000/attestation" \
  decision-gate-rs > "$WORK_DIR/wrong-binary.out" 2> "$WORK_DIR/wrong-binary.err"; then
  echo "expected attested executable mismatch to fail Rust gate startup" >&2
  cat "$WORK_DIR/wrong-binary.out" >&2
  cat "$WORK_DIR/wrong-binary.err" >&2
  exit 1
fi

if ! grep -qi "running data-plane binary is not the control-plane attested executable" \
  "$WORK_DIR/wrong-binary.err"; then
  echo "expected attested executable mismatch in Rust gate stderr" >&2
  cat "$WORK_DIR/wrong-binary.err" >&2
  exit 1
fi

echo '{"attested_executable_mismatch_rejected":true,"ok":true}'
