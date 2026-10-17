#!/usr/bin/env bash
set -euo pipefail

TMP_DIR="${TMP_DIR:-.tmp}"
if [[ -z "${COMPOSE_PROJECT_NAME:-}" ]]; then
  COMPOSE_PROJECT_NAME="catchplate-custody-$(date +%s)-$$-$(openssl rand -hex 6)"
fi
if [[ ! "$COMPOSE_PROJECT_NAME" =~ ^[a-z0-9][a-z0-9_-]*$ ]]; then
  echo "COMPOSE_PROJECT_NAME is not a valid disposable Compose project name: $COMPOSE_PROJECT_NAME" >&2
  exit 64
fi
export COMPOSE_PROJECT_NAME
export CATCHPLATE_CONTROL_PLANE_HOST_PORT=0
export CATCHPLATE_AUDIT_ANCHOR_HOST_PORT=0
export CATCHPLATE_DECISION_GATE_PROXY_HOST_PORT=0
export CATCHPLATE_DECISION_GATE_DIRECT_HOST_PORT=0
export CATCHPLATE_DECISION_GATE_MANAGEMENT_HOST_PORT=0
export CATCHPLATE_DECISION_GATE_DEV_IMAGE="${COMPOSE_PROJECT_NAME}-decision-gate-rs:dev"

COMPOSE=(docker compose -p "$COMPOSE_PROJECT_NAME" --profile custody -f docker-compose.yml -f docker-compose.custody.yml)
LOCAL_COMPOSE=(docker compose -p "$COMPOSE_PROJECT_NAME" -f docker-compose.yml)
SOCKET_PATH=/run/catchplate-custody/custody.sock
GATE_IMAGE=""
CLIENT_IMAGE=""
CLIENT_NETWORK=""
CONTROL_BASE=""
ANCHOR_BASE=""
GATE_BASE=""
MANAGEMENT_BASE=""
PROJECT_MUTATED=0
PROJECT_IMAGES_BUILT=0
ORDINARY_GATE_RESTORED=0
ARTIFACT_DIR=""
PROJECT_LOCK_DIR=""
PROJECT_LOCK_TOKEN=""

acquire_project_lock() {
  local project_digest=""
  local lock_dir=""
  local lock_token=""

  project_digest="$(printf '%s' "$COMPOSE_PROJECT_NAME" | openssl dgst -sha256 -r | awk '{print $1}')"
  if [[ ! "$project_digest" =~ ^[a-f0-9]{64}$ ]]; then
    echo "unable to derive custody lifecycle project lock identity" >&2
    return 1
  fi
  lock_dir="/tmp/catchplate-custody-project-$project_digest.lock"
  lock_token="$(openssl rand -hex 32)"
  PROJECT_LOCK_DIR="$lock_dir"
  PROJECT_LOCK_TOKEN="$lock_token"
  if ! mkdir -m 0700 "$lock_dir" 2>/dev/null; then
    PROJECT_LOCK_DIR=""
    PROJECT_LOCK_TOKEN=""
    echo "refusing custody lifecycle mutation: project lock already exists for $COMPOSE_PROJECT_NAME at $lock_dir" >&2
    return 1
  fi
  if ! printf '%s\n' "$lock_token" >"$lock_dir/owner"; then
    rmdir "$lock_dir" 2>/dev/null || true
    echo "unable to initialize custody lifecycle project lock for $COMPOSE_PROJECT_NAME" >&2
    return 1
  fi
}

release_project_lock() {
  if [[ -z "$PROJECT_LOCK_DIR" ]]; then
    return 0
  fi
  if [[ ! -e "$PROJECT_LOCK_DIR" ]]; then
    PROJECT_LOCK_DIR=""
    PROJECT_LOCK_TOKEN=""
    return 0
  fi
  if [[ -L "$PROJECT_LOCK_DIR" || ! -d "$PROJECT_LOCK_DIR" \
    || ! -f "$PROJECT_LOCK_DIR/owner" \
    || "$(cat "$PROJECT_LOCK_DIR/owner" 2>/dev/null)" != "$PROJECT_LOCK_TOKEN" ]]; then
    echo "custody lifecycle project lock ownership changed for $COMPOSE_PROJECT_NAME" >&2
    return 1
  fi
  if ! rm -f -- "$PROJECT_LOCK_DIR/owner" || ! rmdir -- "$PROJECT_LOCK_DIR"; then
    echo "custody lifecycle project lock cleanup failed for $COMPOSE_PROJECT_NAME" >&2
    return 1
  fi
  PROJECT_LOCK_DIR=""
  PROJECT_LOCK_TOKEN=""
}

assert_project_absent() {
  local phase="$1"
  local allow_images="${2:-0}"
  local container_ids=""
  local volume_ids=""
  local network_ids=""
  local image_ids=""
  local local_image_refs=""
  local existing_local_image_refs=""

  if ! container_ids="$(docker container ls -aq --filter "label=com.docker.compose.project=$COMPOSE_PROJECT_NAME")" \
    || ! volume_ids="$(docker volume ls -q --filter "label=com.docker.compose.project=$COMPOSE_PROJECT_NAME")" \
    || ! network_ids="$(docker network ls -q --filter "label=com.docker.compose.project=$COMPOSE_PROJECT_NAME")" \
    || ! image_ids="$(docker image ls -q --filter "label=com.docker.compose.project=$COMPOSE_PROJECT_NAME")" \
    || ! local_image_refs="$(python3 - "$COMPOSE_PROJECT_NAME" "${COMPOSE[@]}" <<'PY'
import json
import subprocess
import sys

project = sys.argv[1]
compose = sys.argv[2:]
model = json.loads(subprocess.check_output([*compose, "config", "--format", "json"], text=True))
for service_name, service in (model.get("services") or {}).items():
    if service.get("build"):
        print(service.get("image") or f"{project}-{service_name}")
PY
    )"; then
    echo "unable to inventory Compose resources for $COMPOSE_PROJECT_NAME during $phase" >&2
    return 1
  fi
  while IFS= read -r image_ref; do
    if [[ -n "$image_ref" ]] && docker image inspect "$image_ref" >/dev/null 2>&1; then
      existing_local_image_refs+="${existing_local_image_refs:+$'\n'}$image_ref"
    fi
  done <<<"$local_image_refs"
  if [[ -n "$container_ids" || -n "$volume_ids" || -n "$network_ids" \
    || ( "$allow_images" -ne 1 && ( -n "$image_ids" || -n "$existing_local_image_refs" ) ) ]]; then
    echo "refusing custody lifecycle mutation: Compose project $COMPOSE_PROJECT_NAME already owns resources during $phase" >&2
    [[ -z "$container_ids" ]] || printf 'containers:\n%s\n' "$container_ids" >&2
    [[ -z "$volume_ids" ]] || printf 'volumes:\n%s\n' "$volume_ids" >&2
    [[ -z "$network_ids" ]] || printf 'networks:\n%s\n' "$network_ids" >&2
    if [[ "$allow_images" -ne 1 ]]; then
      [[ -z "$image_ids" ]] || printf 'images:\n%s\n' "$image_ids" >&2
      [[ -z "$existing_local_image_refs" ]] || printf 'local image tags:\n%s\n' "$existing_local_image_refs" >&2
    fi
    return 1
  fi
}

assert_ephemeral_compose_ports() {
  python3 - "$COMPOSE_PROJECT_NAME" "${COMPOSE[@]}" <<'PY'
import json
import subprocess
import sys

project = sys.argv[1]
compose = sys.argv[2:]
model = json.loads(
    subprocess.check_output([*compose, "config", "--format", "json"], text=True)
)
assert model.get("name") == project, (model.get("name"), project)
expected = {
    "catchplate": {3000: 1},
    "audit-anchor": {9100: 1},
    # Compose normalizes the two ordinary 9090 aliases into one binding when both
    # published ports are overridden to the same ephemeral value.
    "decision-gate-rs": {9090: 1, 9091: 1},
}
for service, targets in expected.items():
    ports = model["services"][service].get("ports") or []
    for target, count in targets.items():
        matches = [item for item in ports if int(item["target"]) == target]
        assert len(matches) == count, (service, target, ports)
        for binding in matches:
            assert binding.get("host_ip") == "127.0.0.1", (service, binding)
            assert str(binding.get("published")) == "0", (service, binding)
PY
}

discover_loopback_url() {
  local service="$1"
  local container_port="$2"
  local container_ids=""
  local confirmed_container_ids=""
  local url=""

  for _ in $(seq 1 100); do
    container_ids="$("${COMPOSE[@]}" ps --status running -q "$service" 2>/dev/null || true)"
    if [[ -n "$container_ids" && "$container_ids" != *$'\n'* ]]; then
      if url="$(python3 - "$container_ids" "$container_port" "$service" "$COMPOSE_PROJECT_NAME" 2>/dev/null <<'PY'
import json
import subprocess
import sys

container_id, container_port, service, project = sys.argv[1:]
container = json.loads(
    subprocess.check_output(["docker", "inspect", container_id], text=True)
)[0]
assert (container.get("State") or {}).get("Running") is True, container.get("State")
labels = (container.get("Config") or {}).get("Labels") or {}
assert labels.get("com.docker.compose.project") == project, labels
assert labels.get("com.docker.compose.service") == service, labels
bindings = (container.get("NetworkSettings") or {}).get("Ports", {}).get(
    f"{container_port}/tcp"
) or []
assert bindings, (service, container_port, container.get("NetworkSettings"))
ports = []
for binding in bindings:
    assert binding.get("HostIp") == "127.0.0.1", (service, binding)
    port = int(binding["HostPort"])
    assert 0 < port < 65536, (service, binding)
    ports.append(port)
print(f"http://127.0.0.1:{min(ports)}")
PY
      )"; then
        confirmed_container_ids="$("${COMPOSE[@]}" ps --status running -q "$service" 2>/dev/null || true)"
        if [[ "$confirmed_container_ids" == "$container_ids" ]]; then
          printf '%s\n' "$url"
          return 0
        fi
      fi
    fi
    sleep 0.1
  done
  "${COMPOSE[@]}" ps -a "$service" >&2 || true
  "${COMPOSE[@]}" logs --tail=200 "$service" >&2 || true
  echo "$service did not expose a stable loopback port $container_port in $COMPOSE_PROJECT_NAME" >&2
  return 1
}

refresh_base_urls() {
  CONTROL_BASE="$(discover_loopback_url catchplate 3000)" || return 1
  ANCHOR_BASE="$(discover_loopback_url audit-anchor 9100)" || return 1
}

refresh_gate_urls() {
  GATE_BASE="$(discover_loopback_url decision-gate-rs 9090)" || return 1
  MANAGEMENT_BASE="$(discover_loopback_url decision-gate-rs 9091)" || return 1
}

prepare_gate_images() {
  local binary_digest=""

  PROJECT_IMAGES_BUILT=1
  "${COMPOSE[@]}" build decision-gate-rs
  GATE_IMAGE="$(
    docker image inspect --format '{{.Id}}' "$CATCHPLATE_DECISION_GATE_DEV_IMAGE"
  )"
  binary_digest="$(
    docker run --rm --entrypoint sha256sum "$GATE_IMAGE" \
      /usr/local/bin/catchplate-decision-gate | awk '{print $1}'
  )"
  if [[ ! "$binary_digest" =~ ^[0-9a-f]{64}$ ]]; then
    echo "failed to measure the disposable decision-gate executable" >&2
    return 1
  fi
  export CATCHPLATE_EXPECTED_DATA_PLANE_BINARY_DIGEST="sha256:$binary_digest"
}

assert_shared_gate_image_identity() {
  local phase="$1"
  local custody_container=""
  local gate_container=""

  custody_container="$("${COMPOSE[@]}" ps --status running -q custody-runtime)"
  gate_container="$("${COMPOSE[@]}" ps --status running -q decision-gate-rs)"
  if [[ -z "$custody_container" || "$custody_container" == *$'\n'* \
    || -z "$gate_container" || "$gate_container" == *$'\n'* ]]; then
    echo "custody/gate image identity check did not find one running container per service during $phase" >&2
    return 1
  fi
  python3 - \
    "$custody_container" \
    "$gate_container" \
    "$CATCHPLATE_DECISION_GATE_DEV_IMAGE" \
    "$GATE_IMAGE" \
    "$phase" <<'PY'
import json
import subprocess
import sys

custody_id, gate_id, expected_ref, expected_image_id, phase = sys.argv[1:]
custody, gate = json.loads(
    subprocess.check_output(
        ["docker", "inspect", custody_id, gate_id],
        text=True,
    )
)
for service, container in (
    ("custody-runtime", custody),
    ("decision-gate-rs", gate),
):
    labels = (container.get("Config") or {}).get("Labels") or {}
    assert labels.get("com.docker.compose.service") == service, (
        phase,
        service,
        labels,
    )
    assert (container.get("Config") or {}).get("Image") == expected_ref, (
        phase,
        service,
        (container.get("Config") or {}).get("Image"),
        expected_ref,
    )
    assert container.get("Image") == expected_image_id, (
        phase,
        service,
        container.get("Image"),
        expected_image_id,
    )
assert custody["Image"] == gate["Image"], (phase, custody["Image"], gate["Image"])
PY
}

restore_ordinary_gate() {
  local ordinary_container=""
  local custody_containers=""

  if [[ "$PROJECT_MUTATED" -ne 1 || "$ORDINARY_GATE_RESTORED" -eq 1 ]]; then
    return 0
  fi
  echo "Restoring and verifying the ordinary decision gate in disposable project $COMPOSE_PROJECT_NAME" >&2
  if ! "${COMPOSE[@]}" rm -sf custody-runtime decision-gate-rs >/dev/null; then
    return 1
  fi
  if ! "${LOCAL_COMPOSE[@]}" up -d --no-build --force-recreate decision-gate-rs >/dev/null; then
    return 1
  fi
  if ! refresh_gate_urls; then
    return 1
  fi
  if ! DECISION_GATE_BASE="$GATE_BASE" ./scripts/wait_for_decision_gate.sh >/dev/null; then
    return 1
  fi
  ordinary_container="$("${LOCAL_COMPOSE[@]}" ps --status running -q decision-gate-rs)"
  if [[ -z "$ordinary_container" || "$ordinary_container" == *$'\n'* ]]; then
    echo "ordinary decision gate restoration did not yield exactly one running container" >&2
    return 1
  fi
  custody_containers="$("${COMPOSE[@]}" ps -a -q custody-runtime)"
  if [[ -n "$custody_containers" ]]; then
    echo "custody runtime still exists after ordinary decision gate restoration" >&2
    return 1
  fi
  if ! python3 - "$ordinary_container" "$COMPOSE_PROJECT_NAME" <<'PY'
import json
import subprocess
import sys

container_id, project = sys.argv[1:]
container = json.loads(
    subprocess.check_output(["docker", "inspect", container_id], text=True)
)[0]
labels = (container.get("Config") or {}).get("Labels") or {}
assert labels.get("com.docker.compose.project") == project, labels
assert labels.get("com.docker.compose.service") == "decision-gate-rs", labels
assert (container.get("Config") or {}).get("User") == "10001:10001", container
assert "10003" not in ((container.get("HostConfig") or {}).get("GroupAdd") or []), container
environment = {
    item.split("=", 1)[0] for item in ((container.get("Config") or {}).get("Env") or [])
}
assert "CATCHPLATE_RESPONSE_PROOF_CUSTODY_SOCKET" not in environment, environment
assert "CATCHPLATE_RESPONSE_PROOF_CUSTODY_EXPECTED_UID" not in environment, environment
PY
  then
    return 1
  fi
  if ! curl -fsS "$MANAGEMENT_BASE/attestation?nonce=ordinary-restored" | python3 -c '
import json
import sys

data = json.load(sys.stdin)
assert data["nonce"] == "ordinary-restored", data
assert data["response_proof_signer_mode"] == "local-ephemeral", data
assert data["runtime_manifest"]["response_proof_signer_mode"] == "local-ephemeral", data
' >/dev/null; then
    echo "ordinary decision gate attestation did not prove local-ephemeral signing" >&2
    return 1
  fi
  ORDINARY_GATE_RESTORED=1
}

cleanup() {
  local test_status=$?
  local cleanup_status=0

  trap '' INT TERM
  trap - EXIT
  set +e
  if [[ "$PROJECT_MUTATED" -eq 1 ]]; then
    if [[ "$ORDINARY_GATE_RESTORED" -ne 1 ]] && ! restore_ordinary_gate; then
      echo "failed to restore and verify the ordinary gate before disposable teardown (test status $test_status)" >&2
      cleanup_status=1
    fi
    if ! "${COMPOSE[@]}" down --rmi local --volumes --remove-orphans --timeout 10; then
      echo "failed to tear down disposable Compose project $COMPOSE_PROJECT_NAME" >&2
      cleanup_status=1
    fi
    if ! assert_project_absent "post-teardown verification"; then
      cleanup_status=1
    fi
  elif [[ "$PROJECT_IMAGES_BUILT" -eq 1 ]]; then
    if ! "${COMPOSE[@]}" down --rmi local --volumes --remove-orphans --timeout 10; then
      echo "failed to remove disposable Compose images for $COMPOSE_PROJECT_NAME" >&2
      cleanup_status=1
    fi
    if ! assert_project_absent "post-build-failure verification"; then
      cleanup_status=1
    fi
  fi
  if [[ -n "$ARTIFACT_DIR" ]] && ! rm -rf -- "$ARTIFACT_DIR"; then
    echo "custody test artifact cleanup failed (test status $test_status)" >&2
    cleanup_status=1
  fi
  if ! release_project_lock; then
    cleanup_status=1
  fi
  if [[ "$cleanup_status" -ne 0 ]]; then
    exit 125
  fi
  exit "$test_status"
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap '' INT TERM
if ! acquire_project_lock; then
  trap 'exit 130' INT
  trap 'exit 143' TERM
  exit 65
fi
trap 'exit 130' INT
trap 'exit 143' TERM

assert_project_absent "startup preflight" || exit 65
assert_ephemeral_compose_ports

mkdir -p "$TMP_DIR"
TMP_DIR="$(cd "$TMP_DIR" && pwd -P)"
ARTIFACT_DIR="$(mktemp -d "$TMP_DIR/custody-response-proof.XXXXXX")"
COLLECTOR_KEY="$ARTIFACT_DIR/collector-key.pem"
CONTROL_PLANE_RESPONSE_KEY="$ARTIFACT_DIR/control-plane-response-signing.pub.pem"
FIRST_PROOF="$ARTIFACT_DIR/proof-before/response-proof.json"
FIRST_SUMMARY="$ARTIFACT_DIR/proof-before-summary.json"
STREAMING_PROOF="$ARTIFACT_DIR/stream-proof-before/response-proof.json"
STREAMING_BODY="$ARTIFACT_DIR/stream-proof-before/response-body.bin"
STREAMING_SUMMARY="$ARTIFACT_DIR/stream-proof-before-summary.json"
RECOVERED_PROOF="$ARTIFACT_DIR/proof-after/response-proof.json"
RECOVERED_SUMMARY="$ARTIFACT_DIR/proof-after-summary.json"
OUTAGE_HEADERS="$ARTIFACT_DIR/outage-headers.txt"
OUTAGE_BODY="$ARTIFACT_DIR/outage-body.json"
STREAMING_OUTAGE_HEADERS="$ARTIFACT_DIR/streaming-outage-headers.txt"
STREAMING_OUTAGE_BODY="$ARTIFACT_DIR/streaming-outage-body.json"
RESTART_HEADERS="$ARTIFACT_DIR/restart-headers.txt"
RESTART_BODY="$ARTIFACT_DIR/restart-body.json"
LEDGER_BEFORE_RESTART="$ARTIFACT_DIR/ledger-before-restart.json"
LEDGER_AFTER_RESTART="$ARTIFACT_DIR/ledger-after-restart.json"
ATTESTATION_BEFORE="$ARTIFACT_DIR/attestation-before.json"
ATTESTATION_AFTER="$ARTIFACT_DIR/attestation-after.json"
HEALTH_AFTER_OUTAGE="$ARTIFACT_DIR/health-after-outage.json"
HEALTH_AFTER_RESTART="$ARTIFACT_DIR/health-after-restart.json"
CONTAINER_INSPECT="$ARTIFACT_DIR/container-inspect.json"
PROVENANCE_SUMMARY="$ARTIFACT_DIR/release-provenance-summary.json"
GATE_CA="$ARTIFACT_DIR/decision-gate-ca-cert.pem"
UPSTREAM_CA="$ARTIFACT_DIR/demo-upstream-ca.pem"

openssl genpkey -algorithm ED25519 -out "$COLLECTOR_KEY" >/dev/null 2>&1
chmod 0600 "$COLLECTOR_KEY"
prepare_gate_images

wait_for_custody_socket() {
  local container=""
  local socket_state=""
  for _ in $(seq 1 100); do
    container="$("${COMPOSE[@]}" ps -q custody-runtime)"
    if [[ -n "$container" ]] && [[ "$(docker inspect --format '{{.State.Running}}' "$container")" == "true" ]]; then
      socket_state="$(docker exec "$container" stat -c '%u:%g:%a:%F' "$SOCKET_PATH" 2>/dev/null || true)"
      if [[ "$socket_state" == "10002:10003:660:socket" ]]; then
        printf '%s\n' "$container"
        return 0
      fi
    fi
    sleep 0.1
  done
  "${COMPOSE[@]}" logs custody-runtime >&2 || true
  echo "custody runtime did not publish the expected 10002:10003 mode-0660 socket" >&2
  return 1
}

health_status() {
  local output_path="$1"
  curl -sS -o "$output_path" -w '%{http_code}' "$MANAGEMENT_BASE/healthz"
}

wait_for_unhealthy_custody() {
  local output_path="$1"
  for _ in $(seq 1 100); do
    if [[ "$(health_status "$output_path")" == "503" ]]; then
      return 0
    fi
    sleep 0.1
  done
  "${COMPOSE[@]}" logs --tail=200 custody-runtime decision-gate-rs >&2 || true
  echo "decision gate did not detect the custody outage before dispatch" >&2
  return 1
}

upstream_request_count() {
  local path="$1"
  docker run --rm \
    --network "$CLIENT_NETWORK" \
    --user "$(id -u):$(id -g)" \
    -v "$UPSTREAM_CA:/proof/demo-upstream-ca.pem:ro" \
    --entrypoint curl \
    "$CLIENT_IMAGE" \
    -fsS \
    --cacert /proof/demo-upstream-ca.pem \
    "https://demo-upstream:8443/_test/request-count?method=GET&path=$path" \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["count"])'
}

upstream_echo_request_count() {
  upstream_request_count /echo
}

upstream_stream_request_count() {
  upstream_request_count /stream-bytes
}

wait_for_custody_gate() {
  if DECISION_GATE_BASE="$GATE_BASE" ./scripts/wait_for_decision_gate.sh; then
    return 0
  fi
  "${COMPOSE[@]}" ps -a >&2 || true
  "${COMPOSE[@]}" logs --tail=200 custody-runtime decision-gate-rs >&2 || true
  return 1
}

wait_for_demo_upstream() {
  for _ in $(seq 1 60); do
    if "${LOCAL_COMPOSE[@]}" exec -T demo-upstream sh -c \
      'test -s /data/demo-upstream/ca.pem && test -s /data/demo-upstream/cert.pem' \
      >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  "${LOCAL_COMPOSE[@]}" logs --tail=200 demo-upstream >&2 || true
  echo "demo upstream CA and leaf certificates did not become available in $COMPOSE_PROJECT_NAME" >&2
  return 1
}

assert_project_absent "immediately before startup" 1 || exit 65
PROJECT_MUTATED=1
"${LOCAL_COMPOSE[@]}" up -d --build --force-recreate \
  catchplate audit-anchor grant-store demo-upstream
refresh_base_urls
BASE="$CONTROL_BASE" ./scripts/wait_for_catchplate.sh
wait_for_demo_upstream
demo_upstream_container="$("${LOCAL_COMPOSE[@]}" ps -q demo-upstream)"
docker cp "$demo_upstream_container:/data/demo-upstream/ca.pem" "$UPSTREAM_CA"
chmod 0644 "$UPSTREAM_CA"
curl -fsS \
  -H "X-Catchplate-Admin-Token: ${CATCHPLATE_ADMIN_TOKEN:-dev-admin-token}" \
  -X POST "$CONTROL_BASE/api/demo/seed" >/dev/null
curl -fsS "$CONTROL_BASE/attestation?nonce=custody-proof-client-control-plane-key" \
  | python3 -c 'import json,sys; sys.stdout.write(json.load(sys.stdin)["response_signing_public_key_pem"])' \
  > "$CONTROL_PLANE_RESPONSE_KEY"
chmod 0600 "$CONTROL_PLANE_RESPONSE_KEY"

run_proof() {
  local output_path="$1"
  local summary_path="$2"
  local output_directory
  output_directory="$(dirname "$output_path")"
  mkdir -p "$output_directory"
  docker run --rm \
    --network "$CLIENT_NETWORK" \
    --user "$(id -u):$(id -g)" \
    -v "$GATE_CA:/proof/decision-gate-ca-cert.pem:ro" \
    -v "$COLLECTOR_KEY:/proof/collector-key.pem:ro" \
    -v "$CONTROL_PLANE_RESPONSE_KEY:/proof/control-plane-response-signing.pub.pem:ro" \
    -v "$output_directory:/proof/output" \
    --entrypoint /usr/local/bin/catchplate-proof-client \
    "$GATE_IMAGE" \
    --proxy decision-gate-rs:9090 \
    --url https://demo-upstream:8443/echo \
    --ca /proof/decision-gate-ca-cert.pem \
    --out /proof/output/response-proof.json \
    --collector-key /proof/collector-key.pem \
    --control-plane-response-key /proof/control-plane-response-signing.pub.pem \
    --expected-principal-id agent:demo \
    --proxy-header "X-Catchplate-Agent: demo-agent" \
    --header "X-Catchplate-Agent: demo-agent" \
    > "$summary_path"
}

run_stream_proof() {
  local output_path="$1"
  local body_path="$2"
  local summary_path="$3"
  local output_directory
  output_directory="$(dirname "$output_path")"
  if [[ "$(dirname "$body_path")" != "$output_directory" ]]; then
    echo "streaming proof and body must share one publication directory" >&2
    return 1
  fi
  mkdir -p "$output_directory"
  chmod 0700 "$output_directory"
  docker run --rm \
    --network "$CLIENT_NETWORK" \
    --user "$(id -u):$(id -g)" \
    -v "$GATE_CA:/proof/decision-gate-ca-cert.pem:ro" \
    -v "$COLLECTOR_KEY:/proof/collector-key.pem:ro" \
    -v "$CONTROL_PLANE_RESPONSE_KEY:/proof/control-plane-response-signing.pub.pem:ro" \
    -v "$output_directory:/proof/output" \
    --entrypoint /usr/local/bin/catchplate-proof-client \
    "$GATE_IMAGE" \
    --stream \
    --proxy decision-gate-rs:9090 \
    --url 'https://demo-upstream:8443/stream-bytes?chunks=2&chunkSize=16' \
    --ca /proof/decision-gate-ca-cert.pem \
    --out "/proof/output/$(basename "$output_path")" \
    --body-out "/proof/output/$(basename "$body_path")" \
    --collector-key /proof/collector-key.pem \
    --control-plane-response-key /proof/control-plane-response-signing.pub.pem \
    --expected-principal-id agent:demo \
    --proxy-header "X-Catchplate-Agent: demo-agent" \
    --header "X-Catchplate-Agent: demo-agent" \
    --max-stream-bytes 1048576 \
    > "$summary_path"
}

run_failed_raw_proof() {
  local headers_path="$1"
  local body_path="$2"
  local nonce
  nonce="$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=\n')"
  : > "$headers_path"
  : > "$body_path"
  docker run --rm \
    --network "$CLIENT_NETWORK" \
    --user "$(id -u):$(id -g)" \
    -v "$GATE_CA:/proof/decision-gate-ca-cert.pem:ro" \
    -v "$headers_path:/proof/headers.txt" \
    -v "$body_path:/proof/body.json" \
    --entrypoint curl \
    "$CLIENT_IMAGE" \
    -sS \
    -D /proof/headers.txt \
    -o /proof/body.json \
    -w '%{http_code}' \
    --proxy http://decision-gate-rs:9090 \
    --proxy-header "X-Catchplate-Agent: demo-agent" \
    --cacert /proof/decision-gate-ca-cert.pem \
    -H "X-Catchplate-Agent: demo-agent" \
    -H "X-Catchplate-Proof-Nonce: $nonce" \
    https://demo-upstream:8443/echo
}

run_failed_raw_stream_proof() {
  local headers_path="$1"
  local body_path="$2"
  local nonce
  nonce="$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=\n')"
  : > "$headers_path"
  : > "$body_path"
  docker run --rm \
    --network "$CLIENT_NETWORK" \
    --user "$(id -u):$(id -g)" \
    -v "$GATE_CA:/proof/decision-gate-ca-cert.pem:ro" \
    -v "$headers_path:/proof/headers.txt" \
    -v "$body_path:/proof/body.json" \
    --entrypoint curl \
    "$CLIENT_IMAGE" \
    -sS \
    -D /proof/headers.txt \
    -o /proof/body.json \
    -w '%{http_code}' \
    --proxy http://decision-gate-rs:9090 \
    --proxy-header "X-Catchplate-Agent: demo-agent" \
    --cacert /proof/decision-gate-ca-cert.pem \
    -H "X-Catchplate-Agent: demo-agent" \
    -H "X-Catchplate-Stream-Proof-Nonce: $nonce" \
    'https://demo-upstream:8443/stream-bytes?chunks=2&chunkSize=16'
}

assert_failed_wire_response() {
  local http_status="$1"
  local headers_path="$2"
  local body_path="$3"
  python3 - "$http_status" "$headers_path" "$body_path" <<'PY'
import json
import sys

status, headers_path, body_path = sys.argv[1:]
assert status == "503", status
body = open(body_path, "rb").read()
assert body == b'{"error":"response_proof_unavailable"}', body
assert json.loads(body) == {"error": "response_proof_unavailable"}
headers = open(headers_path, "rb").read().lower()
for forbidden in (
    b"x-catchplate-response-proof-b64:",
    b"x-catchplate-response-proof-sha256:",
    b"x-catchplate-response-key-id:",
    b"x-catchplate-client-request-digest:",
    b"x-catchplate-policy-hash:",
    b"x-catchplate-request-digest:",
    b"x-catchplate-operation-digest:",
    b"x-catchplate-response-body-sha256:",
):
    assert forbidden not in headers, (forbidden, headers)
PY
}

CLIENT_NETWORK="$("${LOCAL_COMPOSE[@]}" config --format json | python3 -c 'import json,sys; print(json.load(sys.stdin)["networks"]["default"]["name"])')"
CLIENT_IMAGE="$("${LOCAL_COMPOSE[@]}" images -q catchplate)"
if [[ -z "$CLIENT_IMAGE" ]]; then
  echo "catchplate client image is unavailable" >&2
  exit 1
fi

"${COMPOSE[@]}" up -d --no-build --force-recreate custody-runtime decision-gate-rs
refresh_gate_urls
wait_for_custody_gate
custody_container="$(wait_for_custody_socket)"
assert_shared_gate_image_identity "initial custody startup"
COMPOSE_PROJECT_NAME="$COMPOSE_PROJECT_NAME" \
  COMPOSE_FILE="docker-compose.yml:docker-compose.custody.yml" \
  COMPOSE_PROFILES=custody \
  BASE="$CONTROL_BASE" \
  DECISION_GATE_BASE="$GATE_BASE" \
  CATCHPLATE_RELEASE_ANCHOR_BASE="$ANCHOR_BASE" \
  python3 scripts/generate_release_provenance.py > "$PROVENANCE_SUMMARY"

COMPOSE_PROJECT_NAME="$COMPOSE_PROJECT_NAME" \
  COMPOSE_FILE="docker-compose.yml:docker-compose.custody.yml" \
  COMPOSE_PROFILES=custody \
  CATCHPLATE_HARDENING_SERVICES=custody-runtime \
  ./scripts/test_container_hardening.sh >/dev/null
CATCHPLATE_APPARMOR_DRY_RUN=1 \
  CATCHPLATE_APPARMOR_SERVICES=decision-gate-rs,custody-runtime \
  ./scripts/test_apparmor_runtime.sh >/dev/null

if [[ -z "$custody_container" ]]; then
  echo "custody runtime container is not running" >&2
  exit 1
fi
if [[ "$(docker inspect --format '{{.HostConfig.NetworkMode}}' "$custody_container")" != "none" ]]; then
  echo "custody runtime unexpectedly has a network namespace" >&2
  exit 1
fi
gate_container="$("${COMPOSE[@]}" ps -q decision-gate-rs)"
compose_gate_image="$("${COMPOSE[@]}" images -q decision-gate-rs)"
if [[ -z "$compose_gate_image" || "$compose_gate_image" == *$'\n'* ]]; then
  echo "decision-gate client image is unavailable" >&2
  exit 1
fi
compose_gate_image="$(docker image inspect --format '{{.Id}}' "$compose_gate_image")"
if [[ "$compose_gate_image" != "$GATE_IMAGE" ]]; then
  echo "decision-gate client image identity does not match the built shared image" >&2
  exit 1
fi
docker cp "$gate_container:/data/decision-gate-ca-cert.pem" "$GATE_CA"
chmod 0644 "$GATE_CA"
if [[ "$(docker exec "$custody_container" id -u):$(docker exec "$custody_container" id -g)" != "10002:10003" ]]; then
  echo "custody runtime effective UID/GID mismatch" >&2
  exit 1
fi
if [[ "$(docker exec "$gate_container" id -u):$(docker exec "$gate_container" id -g)" != "10001:10001" ]] \
  || [[ " $(docker exec "$gate_container" id -G) " != *" 10003 "* ]]; then
  echo "decision gate custody socket identity or supplemental group mismatch" >&2
  exit 1
fi
if [[ "$(docker exec "$gate_container" stat -c '%u:%g:%a:%F' /run/catchplate-custody)" != "10002:10003:710:directory" ]] \
  || [[ "$(docker exec "$gate_container" stat -c '%u:%g:%a:%F' "$SOCKET_PATH")" != "10002:10003:660:socket" ]]; then
  echo "decision gate sees an unexpected custody socket ownership or mode" >&2
  exit 1
fi
docker inspect "$custody_container" "$gate_container" > "$CONTAINER_INSPECT"
python3 - "$CONTAINER_INSPECT" <<'PY'
import json
import sys

custody, gate = json.load(open(sys.argv[1], encoding="utf-8"))

def mount(container, target):
    return next(item for item in container["Mounts"] if item["Destination"] == target)

assert mount(custody, "/custody-trust")["RW"] is False, custody["Mounts"]
assert mount(custody, "/var/lib/catchplate-custody")["RW"] is True, custody["Mounts"]
assert mount(gate, "/run/catchplate-custody")["RW"] is False, gate["Mounts"]
assert "10003" in gate["HostConfig"]["GroupAdd"], gate["HostConfig"]
assert all(
    item["Destination"] != "/run/catchplate/response-signing-private"
    for container in (custody, gate)
    for item in container["Mounts"]
), (custody["Mounts"], gate["Mounts"])
PY

curl -fsS "$MANAGEMENT_BASE/attestation?nonce=custody-before" \
  > "$ATTESTATION_BEFORE"
python3 - "$ATTESTATION_BEFORE" "$PROVENANCE_SUMMARY" <<'PY'
import json
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
provenance = json.load(open(sys.argv[2], encoding="utf-8"))
assert data["nonce"] == "custody-before", data
assert data["provenance_digest"] == provenance["provenance_digest"], (data, provenance)
assert data["response_proof_signer_mode"] == "custody-uds", data
assert data["response_proof_signer_hardware_proof"] is False, data
assert data["response_proof_signer_boot_digest"].startswith("sha256:"), data
assert data["runtime_manifest"]["response_proof_signer_mode"] == "custody-uds", data
assert data["runtime_manifest"]["response_proof_signer_hardware_proof"] is False, data
assert data["runtime_manifest"]["response_proof_signer_boot_digest"] == data["response_proof_signer_boot_digest"], data
custody = data["runtime_manifest"]["response_proof_custody"]
status = data["response_proof_custody_status"]
assert custody["signer_key_id"] == data["response_proof_signing_key_id"], data
assert custody["signer_boot_digest"] == data["response_proof_signer_boot_digest"], data
assert custody["control_plane_response_signing_key_id"].startswith("sha256:"), data
assert status["control_plane_response_signing_key_id"] == custody["control_plane_response_signing_key_id"], data
assert status["healthy"] is True and status["sign_failure_count"] == 0, data
PY

run_proof "$FIRST_PROOF" "$FIRST_SUMMARY"
python3 - "$FIRST_PROOF" "$FIRST_SUMMARY" "$ATTESTATION_BEFORE" <<'PY'
import json
import sys

proof = json.load(open(sys.argv[1], encoding="utf-8"))
summary = json.load(open(sys.argv[2], encoding="utf-8"))
attestation = json.load(open(sys.argv[3], encoding="utf-8"))
assert summary["ok"] is True, summary
signature = proof["server_signature"]
assert signature["key_id"] == attestation["response_proof_signing_key_id"], (signature, attestation)
assert signature["public_key_pem"] == attestation["response_proof_signing_public_key_pem"], (signature, attestation)
assert proof["server_statement"]["apiVersion"] == "catchplate.proxyResponseStatement/v2", proof
PY
run_stream_proof "$STREAMING_PROOF" "$STREAMING_BODY" "$STREAMING_SUMMARY"
python3 - \
  "$STREAMING_PROOF" \
  "$STREAMING_BODY" \
  "$STREAMING_SUMMARY" \
  "$ATTESTATION_BEFORE" <<'PY'
import hashlib
import json
import sys

proof_path, body_path, summary_path, attestation_path = sys.argv[1:]
proof_bytes = open(proof_path, "rb").read()
proof = json.loads(proof_bytes)
body = open(body_path, "rb").read()
summary = json.load(open(summary_path, encoding="utf-8"))
attestation = json.load(open(attestation_path, encoding="utf-8"))

proof_digest = "sha256:" + hashlib.sha256(proof_bytes).hexdigest()
body_digest = "sha256:" + hashlib.sha256(body).hexdigest()
statement = proof["streaming_response_statement"]
capture = proof["external_capture"]
released = statement["released_response"]
signature = proof["server_signature"]

assert summary["ok"] is True and summary["stream_verified"] is True, summary
assert summary["proof_sha256"] == proof_digest, (summary, proof_digest)
assert summary["body_sha256"] == body_digest, (summary, body_digest)
assert summary["body_bytes"] == len(body) == 32, (summary, len(body))
assert proof["apiVersion"] == "catchplate.streamingProxyResponseProof/v1", proof
assert statement["apiVersion"] == "catchplate.streamingResponseStatement/v1", statement
assert capture["runtime_proof_sha256"].startswith("sha256:"), capture
assert signature["key_id"] == attestation["response_proof_signing_key_id"], (signature, attestation)
assert signature["public_key_pem"] == attestation["response_proof_signing_public_key_pem"], (signature, attestation)
assert attestation["response_proof_signer_hardware_proof"] is False, attestation
assert attestation["runtime_manifest"]["response_proof_signer_hardware_proof"] is False, attestation
assert proof["vendor_tee"]["platform"] == "none-dev", proof["vendor_tee"]
assert capture["released_response"] == released, (capture, statement)
assert released["body_digest"] == body_digest, (released, body_digest)
assert released["body_bytes"] == len(body), (released, len(body))
assert released["framing"] == "http1.1-chunked-trailers", released
assert released["completion"] == "normal-eof", released
assert released["trailer_names"] == [
    "X-Catchplate-Stream-Proof-B64",
    "X-Catchplate-Stream-Proof-SHA256",
], released
PY
docker exec "$custody_container" cat /var/lib/catchplate-custody/manifest.json \
  > "$LEDGER_BEFORE_RESTART"

"${COMPOSE[@]}" stop custody-runtime >/dev/null
wait_for_unhealthy_custody "$HEALTH_AFTER_OUTAGE"
outage_upstream_before="$(upstream_echo_request_count)"
outage_http_status="$(run_failed_raw_proof "$OUTAGE_HEADERS" "$OUTAGE_BODY")"
assert_failed_wire_response "$outage_http_status" "$OUTAGE_HEADERS" "$OUTAGE_BODY"
outage_upstream_after="$(upstream_echo_request_count)"
if [[ "$outage_upstream_after" != "$outage_upstream_before" ]]; then
  echo "custody outage request reached the upstream before denial" >&2
  exit 1
fi
streaming_outage_upstream_before="$(upstream_stream_request_count)"
streaming_outage_http_status="$(run_failed_raw_stream_proof "$STREAMING_OUTAGE_HEADERS" "$STREAMING_OUTAGE_BODY")"
assert_failed_wire_response \
  "$streaming_outage_http_status" \
  "$STREAMING_OUTAGE_HEADERS" \
  "$STREAMING_OUTAGE_BODY"
streaming_outage_upstream_after="$(upstream_stream_request_count)"
if [[ "$streaming_outage_upstream_after" != "$streaming_outage_upstream_before" ]]; then
  echo "custody outage streaming request reached the upstream before denial" >&2
  exit 1
fi
if [[ "$(health_status "$HEALTH_AFTER_OUTAGE")" != "503" ]]; then
  echo "gate health recovered unexpectedly during the custody outage" >&2
  exit 1
fi
python3 - "$HEALTH_AFTER_OUTAGE" <<'PY'
import json
import sys

health = json.load(open(sys.argv[1], encoding="utf-8"))
status = health["response_proof_custody_status"]
assert health["ok"] is False and status["healthy"] is False, health
assert status["probe_failure_count"] >= 1, health
assert status["sign_failure_count"] == 0, health
PY

"${COMPOSE[@]}" up -d --no-build --force-recreate custody-runtime >/dev/null
custody_container="$(wait_for_custody_socket)"
assert_shared_gate_image_identity "custody restart"
docker exec "$custody_container" cat /var/lib/catchplate-custody/manifest.json \
  > "$LEDGER_AFTER_RESTART"
python3 - "$LEDGER_BEFORE_RESTART" "$LEDGER_AFTER_RESTART" <<'PY'
import json
import sys

before = json.load(open(sys.argv[1], encoding="utf-8"))
after = json.load(open(sys.argv[2], encoding="utf-8"))
for field in ("activeBindingCount", "activeBindingsAccumulator", "prunedThroughEpochMs"):
    assert after["payload"][field] == before["payload"][field], (field, before, after)
assert after["payload"]["maxObservedEpochMs"] >= before["payload"]["maxObservedEpochMs"], (before, after)
assert after["payload"]["commitSequence"] >= before["payload"]["commitSequence"], (before, after)
assert before["payload"]["activeBindingCount"] >= 1, before
assert before["payload"]["commitSequence"] >= 1, before
PY
restart_upstream_before="$(upstream_echo_request_count)"
restart_http_status="$(run_failed_raw_proof "$RESTART_HEADERS" "$RESTART_BODY")"
assert_failed_wire_response "$restart_http_status" "$RESTART_HEADERS" "$RESTART_BODY"
restart_upstream_after="$(upstream_echo_request_count)"
if [[ "$restart_upstream_after" != "$restart_upstream_before" ]]; then
  echo "changed custody boot request reached the upstream before denial" >&2
  exit 1
fi
if [[ "$(health_status "$HEALTH_AFTER_RESTART")" != "503" ]]; then
  echo "gate health recovered without a coordinated restart after custody boot changed" >&2
  exit 1
fi
python3 - "$HEALTH_AFTER_OUTAGE" "$HEALTH_AFTER_RESTART" <<'PY'
import json
import sys

before = json.load(open(sys.argv[1], encoding="utf-8"))["response_proof_custody_status"]
after = json.load(open(sys.argv[2], encoding="utf-8"))["response_proof_custody_status"]
assert after["healthy"] is False, after
assert after["probe_failure_count"] > before["probe_failure_count"], (before, after)
PY

"${COMPOSE[@]}" up -d --no-build --force-recreate decision-gate-rs >/dev/null
refresh_gate_urls
wait_for_custody_gate
assert_shared_gate_image_identity "coordinated gate restart"
curl -fsS "$MANAGEMENT_BASE/attestation?nonce=custody-after" \
  > "$ATTESTATION_AFTER"
run_proof "$RECOVERED_PROOF" "$RECOVERED_SUMMARY"

python3 - \
  "$ATTESTATION_BEFORE" \
  "$ATTESTATION_AFTER" \
  "$RECOVERED_PROOF" \
  "$RECOVERED_SUMMARY" <<'PY'
import json
import sys

before = json.load(open(sys.argv[1], encoding="utf-8"))
after = json.load(open(sys.argv[2], encoding="utf-8"))
proof = json.load(open(sys.argv[3], encoding="utf-8"))
summary = json.load(open(sys.argv[4], encoding="utf-8"))
assert after["nonce"] == "custody-after", after
assert after["response_proof_signer_mode"] == "custody-uds", after
assert after["response_proof_signer_hardware_proof"] is False, after
assert after["response_proof_signer_boot_digest"] != before["response_proof_signer_boot_digest"], (before, after)
assert after["response_proof_signing_key_id"] != before["response_proof_signing_key_id"], (before, after)
assert after["response_proof_custody_status"]["healthy"] is True, after
assert after["response_proof_custody_status"]["sign_failure_count"] == 0, after
assert after["runtime_manifest"]["response_proof_custody"]["control_plane_response_signing_key_id"] == before["runtime_manifest"]["response_proof_custody"]["control_plane_response_signing_key_id"], (before, after)
assert summary["ok"] is True, summary
assert proof["server_signature"]["key_id"] == after["response_proof_signing_key_id"], (proof, after)
PY

restore_ordinary_gate
echo '{"buffered_custody_response_proof":"pass","hardware_proof":false,"ok":true,"streaming_custody_response_proof":"pass","transport":"uds-development"}'
