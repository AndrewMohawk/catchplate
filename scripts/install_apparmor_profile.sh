#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROFILE="$ROOT/security/apparmor/serverware-docker"

if ! command -v apparmor_parser >/dev/null 2>&1; then
  echo "apparmor_parser is required; install AppArmor on the Linux Docker host first" >&2
  exit 1
fi

if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
  apparmor_parser -r "$PROFILE"
else
  sudo apparmor_parser -r "$PROFILE"
fi

echo "installed AppArmor profile serverware-docker"
