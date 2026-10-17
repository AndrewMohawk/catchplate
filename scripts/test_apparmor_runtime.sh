#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PROFILE_NAME="${CATCHPLATE_APPARMOR_PROFILE:-catchplate-docker}"
PROFILE_PATH="${CATCHPLATE_APPARMOR_PROFILE_PATH:-security/apparmor/catchplate-docker}"
OVERRIDE_PATH="${CATCHPLATE_APPARMOR_COMPOSE_OVERRIDE:-docker-compose.apparmor.yml}"
SERVICES_RAW="${CATCHPLATE_APPARMOR_SERVICES:-catchplate,audit-anchor,grant-store,demo-upstream,decision-gate-rs}"

python3 - <<'PY'
import json
import os
import re
from pathlib import Path

profile_name = os.environ.get("CATCHPLATE_APPARMOR_PROFILE", "catchplate-docker")
profile_path = Path(os.environ.get("CATCHPLATE_APPARMOR_PROFILE_PATH", "security/apparmor/catchplate-docker"))
override_path = Path(os.environ.get("CATCHPLATE_APPARMOR_COMPOSE_OVERRIDE", "docker-compose.apparmor.yml"))
services = [
    item.strip()
    for item in os.environ.get(
        "CATCHPLATE_APPARMOR_SERVICES",
        "catchplate,audit-anchor,grant-store,demo-upstream,decision-gate-rs",
    ).split(",")
    if item.strip()
]

profile = profile_path.read_text(encoding="utf-8")
override = override_path.read_text(encoding="utf-8")
required_profile_snippets = [
    f"profile {profile_name}",
    "deny capability *",
    "deny mount",
    "deny ptrace",
    "deny /proc/sys/** rwklx",
    "deny /sys/** wklx",
]
missing_profile = [snippet for snippet in required_profile_snippets if snippet not in profile]
if missing_profile:
    raise SystemExit(f"AppArmor profile is missing required snippets: {missing_profile}")

missing_services: list[str] = []
for service in services:
    pattern = rf"(?ms)^\s{{2}}{re.escape(service)}:\s*\n(?:(?:\s{{4,}}.*\n)+)"
    match = re.search(pattern, override)
    if not match or f"apparmor={profile_name}" not in match.group(0):
        missing_services.append(service)
if missing_services:
    raise SystemExit(f"AppArmor compose override does not cover services: {missing_services}")

print(json.dumps({"ok": True, "stage": "static", "profile": str(profile_path), "override": str(override_path), "services": services}, sort_keys=True))
PY

if [[ "${CATCHPLATE_APPARMOR_DRY_RUN:-0}" =~ ^(1|true|TRUE|yes|YES)$ ]]; then
  python3 - <<'PY'
import json
import os
print(json.dumps({
    "ok": True,
    "apparmor_runtime": "dry-run",
    "reason": "static profile and compose override checks passed",
    "profile": os.environ.get("CATCHPLATE_APPARMOR_PROFILE", "catchplate-docker"),
}, sort_keys=True))
PY
  exit 0
fi

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "AppArmor runtime verification requires a Linux Docker host; set CATCHPLATE_APPARMOR_DRY_RUN=1 for static contract checks" >&2
  exit 1
fi

if [[ "${CATCHPLATE_APPARMOR_INSTALL:-0}" =~ ^(1|true|TRUE|yes|YES)$ ]]; then
  ./scripts/install_apparmor_profile.sh >/dev/null
fi

if [[ ! -r /sys/kernel/security/apparmor/profiles ]]; then
  echo "AppArmor profiles are not readable; ensure AppArmor is enabled on the Linux host" >&2
  exit 1
fi

if ! grep -q "^${PROFILE_NAME} " /sys/kernel/security/apparmor/profiles; then
  echo "AppArmor profile ${PROFILE_NAME} is not loaded; run make install-apparmor first" >&2
  exit 1
fi

IFS=',' read -r -a SERVICES <<< "$SERVICES_RAW"

if [[ "${CATCHPLATE_APPARMOR_START:-1}" =~ ^(1|true|TRUE|yes|YES)$ ]]; then
  docker compose -f docker-compose.yml -f "$OVERRIDE_PATH" up -d --build "${SERVICES[@]}"
fi

python3 - <<'PY'
import json
import os
import subprocess

profile_name = os.environ.get("CATCHPLATE_APPARMOR_PROFILE", "catchplate-docker")
override = os.environ.get("CATCHPLATE_APPARMOR_COMPOSE_OVERRIDE", "docker-compose.apparmor.yml")
services = [
    item.strip()
    for item in os.environ.get(
        "CATCHPLATE_APPARMOR_SERVICES",
        "catchplate,audit-anchor,grant-store,demo-upstream,decision-gate-rs",
    ).split(",")
    if item.strip()
]
compose = ["docker", "compose", "-f", "docker-compose.yml", "-f", override]


def command(args: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=check)


checked: list[dict[str, str]] = []
for service in services:
    container_id = command([*compose, "ps", "-q", service]).stdout.strip()
    if not container_id:
        raise AssertionError(f"{service}: no running container found")
    inspect = json.loads(command(["docker", "inspect", container_id]).stdout)[0]
    security_opt = inspect.get("HostConfig", {}).get("SecurityOpt") or []
    if f"apparmor={profile_name}" not in security_opt:
        raise AssertionError(f"{service}: apparmor profile is not configured: {security_opt!r}")
    attr = command([*compose, "exec", "-T", service, "sh", "-c", "cat /proc/self/attr/current"]).stdout.strip()
    if not attr.startswith(profile_name):
        raise AssertionError(f"{service}: expected /proc/self/attr/current to start with {profile_name!r}, got {attr!r}")
    checked.append({"service": service, "attr": attr})

probe = command(
    [*compose, "exec", "-T", "catchplate", "sh", "-c", "cat /proc/sys/kernel/hostname >/dev/null"],
    check=False,
)
if probe.returncode == 0:
    raise AssertionError("catchplate: expected AppArmor to deny reading /proc/sys/kernel/hostname")

print(
    json.dumps(
        {
            "ok": True,
            "apparmor_runtime": "pass",
            "profile": profile_name,
            "services": checked,
            "denied_probe": "/proc/sys/kernel/hostname",
        },
        sort_keys=True,
    )
)
PY
