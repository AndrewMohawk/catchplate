#!/usr/bin/env bash
set -euo pipefail

python3 - <<'PY'
import json
import hashlib
import os
import subprocess
from pathlib import Path

raw_services = os.getenv("SERVERWARE_HARDENING_SERVICES")
services = tuple(item.strip() for item in raw_services.split(",")) if raw_services else (
    "serverware",
    "audit-anchor",
    "grant-store",
    "demo-upstream",
    "decision-gate-rs",
)
seccomp_profile = Path("security/seccomp/serverware-deny-dangerous.json")
seccomp_json = json.loads(seccomp_profile.read_text(encoding="utf-8"))
seccomp_digest = "sha256:" + hashlib.sha256(
    json.dumps(seccomp_json, separators=(",", ":"), sort_keys=True).encode("utf-8")
).hexdigest()
checked = []


def command(args: list[str]) -> str:
    return subprocess.check_output(args, text=True).strip()


def seccomp_profile_matches(security_opt: list[str]) -> bool:
    for item in security_opt:
        if not item.startswith("seccomp="):
            continue
        value = item.split("=", 1)[1]
        if value.endswith("serverware-deny-dangerous.json"):
            return True
        if value.startswith("{"):
            try:
                observed = json.loads(value)
            except json.JSONDecodeError:
                continue
            return observed == seccomp_json
    return False


for service in services:
    container_id = command(["docker", "compose", "ps", "-q", service])
    if not container_id:
        raise AssertionError(f"{service}: requested compose service is not running")
    data = json.loads(command(["docker", "inspect", container_id]))[0]
    config = data["Config"]
    host = data["HostConfig"]
    user = config.get("User") or ""
    if service == "grant-store":
        if user in {"", "0", "0:0", "root"}:
            raise AssertionError(f"{service}: expected a non-root database user, got {user!r}")
    elif service == "custody-runtime":
        if user != "10002:10003":
            raise AssertionError(f"{service}: expected the isolated custody identity, got {user!r}")
    elif user not in {"serverware", "10001", "10001:10001"}:
        raise AssertionError(f"{service}: expected non-root Serverware user, got {user!r}")
    if host.get("ReadonlyRootfs") is not True:
        raise AssertionError(f"{service}: root filesystem is not read-only")
    if "ALL" not in (host.get("CapDrop") or []):
        raise AssertionError(f"{service}: capabilities are not fully dropped")
    if "no-new-privileges:true" not in (host.get("SecurityOpt") or []):
        raise AssertionError(f"{service}: no-new-privileges is not enabled")
    security_opt = host.get("SecurityOpt") or []
    if not seccomp_profile_matches(security_opt):
        raise AssertionError(f"{service}: custom Serverware seccomp profile is not configured: {security_opt!r}")
    seccomp_mode = command(["docker", "compose", "exec", "-T", service, "sh", "-c", "awk '/^Seccomp:/ {print $2}' /proc/self/status"])
    if seccomp_mode != "2":
        raise AssertionError(f"{service}: expected seccomp filter mode 2, got {seccomp_mode!r}")
    if int(host.get("PidsLimit") or 0) <= 0:
        raise AssertionError(f"{service}: pids_limit is not set")
    if int(host.get("Memory") or 0) <= 0:
        raise AssertionError(f"{service}: memory limit is not set")
    ulimits = {item.get("Name"): item for item in host.get("Ulimits") or []}
    core_limit = ulimits.get("core")
    if (
        not core_limit
        or int(core_limit.get("Soft", -1)) != 0
        or int(core_limit.get("Hard", -1)) != 0
    ):
        raise AssertionError(f"{service}: core dump ulimit is not disabled")
    core_runtime = command(["docker", "compose", "exec", "-T", service, "sh", "-c", "ulimit -c"])
    if core_runtime != "0":
        raise AssertionError(f"{service}: runtime core dump limit is not zero, got {core_runtime!r}")
    tmpfs = host.get("Tmpfs") or {}
    tmp_options = tmpfs.get("/tmp", "")
    for option in ("noexec", "nosuid", "nodev"):
        if option not in tmp_options:
            raise AssertionError(f"{service}: /tmp tmpfs is missing {option}")
    checked.append(service)

if not checked:
    raise AssertionError("no compose services were available to inspect")

probe = r'''
import ctypes
import platform
import sys

numbers = {
    "aarch64": 280,
    "arm64": 280,
    "x86_64": 321,
}
arch = platform.machine()
nr_bpf = numbers.get(arch)
if nr_bpf is None:
    raise SystemExit(f"unsupported architecture for seccomp bpf probe: {arch}")
libc = ctypes.CDLL(None, use_errno=True)
ctypes.set_errno(0)
ret = libc.syscall(nr_bpf, 0, 0, 0)
err = ctypes.get_errno()
if err != 77:
    raise SystemExit(f"expected custom seccomp errno 77 for bpf syscall, got ret={ret} errno={err}")
'''
subprocess.check_output(["docker", "compose", "exec", "-T", "serverware", "python", "-c", probe], text=True)

print(
    json.dumps(
        {
            "ok": True,
            "container_hardening": "pass",
            "services": checked,
            "seccomp_profile": str(seccomp_profile),
            "seccomp_profile_sha256": seccomp_digest,
            "seccomp_syscall_probe": "pass",
            "core_dumps": "disabled",
            "memory_limits": "configured",
        },
        sort_keys=True,
    )
)
PY
