#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import math
import os
import re
import secrets
import selectors
import shlex
import stat
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
KEY_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
PLACEHOLDER_RE = re.compile(
    r"(<[^>]+>|\$\{[^}]+\}|CHANGE[_-]?ME|REPLACE[_-]?ME|FILL[_-]?ME|TODO|TBD)",
    re.IGNORECASE,
)
EXAMPLE_DOMAIN_RE = re.compile(r"(^|[/:@,])([A-Za-z0-9-]+\.)*example([/:,]|$)", re.IGNORECASE)
SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}")
PRODUCTION_PYTHON_EXECUTABLE_ENV = "SERVERWARE_PRODUCTION_PYTHON_EXECUTABLE"
EXECUTABLE_DIGEST_MANIFEST_ENV = "SERVERWARE_ATTESTATION_EXECUTABLE_SHA256_MANIFEST"
ATTESTATION_HELPER_COMMAND_SETTINGS = (
    "SERVERWARE_NITRO_NSM_ATTEST_COMMAND_TEMPLATE",
    "SERVERWARE_NITRO_NSM_UNSEAL_COMMAND_TEMPLATE",
    "SERVERWARE_DATA_PLANE_RECIPIENT_ATTESTATION_COMMAND",
    "SERVERWARE_DATA_PLANE_RESPONSE_PROOF_ATTESTATION_COMMAND",
    "SERVERWARE_DATA_PLANE_LEASE_RECIPIENT_VERIFY_COMMAND",
    "SERVERWARE_CONTROL_PLANE_ATTESTATION_VERIFY_COMMAND",
)
PROOF_COLLECTOR_COMMAND_SETTING = "SERVERWARE_PROXY_PROOF_COLLECTOR_COMMAND"
PRODUCTION_DOCKER_EXECUTABLE_ENV = "SERVERWARE_DOCKER_EXECUTABLE"
DOCKER_COMPOSE_PLUGIN_EXECUTABLE_ENV = "SERVERWARE_DOCKER_COMPOSE_PLUGIN_EXECUTABLE"
DOCKER_COMPOSE_PLUGIN_SHA256_ENV = "SERVERWARE_DOCKER_COMPOSE_PLUGIN_SHA256"
DOCKER_UNIX_SOCKET_ENV = "SERVERWARE_DOCKER_UNIX_SOCKET"
DOCKER_DAEMON_ID_ENV = "SERVERWARE_DOCKER_DAEMON_ID"
DOCKER_COMPOSE_PROJECT_NAME_ENV = "SERVERWARE_DOCKER_COMPOSE_PROJECT_NAME"
VERIFY_PRODUCTION_READINESS_SCRIPT_SHA256_ENV = (
    "SERVERWARE_VERIFY_PRODUCTION_READINESS_SCRIPT_SHA256"
)
VERIFY_RELEASE_COMPLETION_SCRIPT_SHA256_ENV = (
    "SERVERWARE_VERIFY_RELEASE_COMPLETION_SCRIPT_SHA256"
)
PRODUCTION_HOST_PREFLIGHT_SCRIPT_SHA256_ENV = (
    "SERVERWARE_PRODUCTION_HOST_PREFLIGHT_SCRIPT_SHA256"
)
PRODUCTION_HOST_PREFLIGHT_MAX_AGE_ENV = "SERVERWARE_PRODUCTION_HOST_PREFLIGHT_MAX_AGE_SECONDS"
PRODUCTION_HOST_PREFLIGHT_SIGNING_PRIVATE_KEY_ENV = (
    "SERVERWARE_PRODUCTION_HOST_PREFLIGHT_SIGNING_PRIVATE_KEY"
)
PRODUCTION_HOST_PREFLIGHT_SIGNING_PUBLIC_KEY_ENV = (
    "SERVERWARE_PRODUCTION_HOST_PREFLIGHT_SIGNING_PUBLIC_KEY"
)
PRODUCTION_HOST_PREFLIGHT_SIGNING_KEY_ID_ENV = (
    "SERVERWARE_PRODUCTION_HOST_PREFLIGHT_SIGNING_KEY_ID"
)
PINNED_PYTHON_SCRIPTS = {
    "production_host_preflight.py": PRODUCTION_HOST_PREFLIGHT_SCRIPT_SHA256_ENV,
    "verify_production_readiness.py": VERIFY_PRODUCTION_READINESS_SCRIPT_SHA256_ENV,
    "verify_release_completion.py": VERIFY_RELEASE_COMPLETION_SCRIPT_SHA256_ENV,
}
FINAL_LAUNCHER_CONTRACT_ENV = "SERVERWARE_FINAL_LAUNCHER_CONTRACT"
FINAL_LAUNCHER_CONTRACT = "root-owned-minimal-environment-v1"
POLICY_TRUST_ROOT_ENV = "SERVERWARE_POLICY_IDENTITY_TRUSTED_PUBLIC_KEY"
POLICY_TRUST_ROOT_ID_ENV = "SERVERWARE_POLICY_IDENTITY_TRUSTED_PUBLIC_KEY_ID"
POLICY_ACTIVATION_TRUST_ROOT_ENV = (
    "SERVERWARE_POLICY_ACTIVATION_TRUSTED_PUBLIC_KEY"
)
POLICY_ACTIVATION_TRUST_ROOT_ID_ENV = (
    "SERVERWARE_POLICY_ACTIVATION_TRUSTED_PUBLIC_KEY_ID"
)
REPRODUCIBLE_BUILD_TRUST_ROOT_ENV = (
    "SERVERWARE_REPRODUCIBLE_BUILD_TRUSTED_PUBLIC_KEY"
)
REPRODUCIBLE_BUILD_TRUST_ROOT_ID_ENV = (
    "SERVERWARE_REPRODUCIBLE_BUILD_TRUSTED_PUBLIC_KEY_ID"
)
FINAL_CONTROL_PLANE_UID = 65532
FINAL_CONTROL_PLANE_GID = 65532
FINAL_SERVICE_USERS = {
    "serverware": "65532:65532",
    "audit-anchor": "nonroot:nonroot",
    "decision-gate-rs": "nonroot:nonroot",
}
LAUNCHER_TRUSTED_ENV_PATH_INPUT = "SERVERWARE_LAUNCHER_TRUSTED_PRODUCTION_ENV_PATH"
LAUNCHER_TRUSTED_ENV_SHA256_INPUT = "SERVERWARE_LAUNCHER_TRUSTED_PRODUCTION_ENV_SHA256"
LAUNCHER_TRUST_INPUT_NAMES = frozenset(
    (LAUNCHER_TRUSTED_ENV_PATH_INPUT, LAUNCHER_TRUSTED_ENV_SHA256_INPUT)
)
PINNED_EXECUTABLE_COMMAND_SETTINGS = frozenset(
    (
        *ATTESTATION_HELPER_COMMAND_SETTINGS,
        PROOF_COLLECTOR_COMMAND_SETTING,
        PRODUCTION_PYTHON_EXECUTABLE_ENV,
        PRODUCTION_DOCKER_EXECUTABLE_ENV,
    )
)
PROXY_DIGEST_ENV_SETTINGS = {
    "proxy_client_request_digest": "SERVERWARE_PROXY_EXPECTED_CLIENT_REQUEST_DIGEST",
    "proxy_request_digest": "SERVERWARE_PROXY_EXPECTED_REQUEST_DIGEST",
    "proxy_operation_digest": "SERVERWARE_PROXY_EXPECTED_OPERATION_DIGEST",
}
COMPLETION_P99_LIMIT_ENV = "SERVERWARE_COMPLETION_P99_LIMIT_MS"
MAX_COMPLETION_PROOF_BYTES = 64 * 1024 * 1024
MAX_EXECUTABLE_BYTES = 256 * 1024 * 1024
MAX_PRODUCTION_ENV_BYTES = 8 * 1024 * 1024
COMPLETION_PROOF_FUTURE_SKEW_SECONDS = 5
FINAL_CHILD_FIXED_ENV = {
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
    "TZ": "UTC",
}
FORBIDDEN_PROCESS_ENV_NAMES = frozenset(
    {
        "BASH_ENV",
        "ENV",
        "GCONV_PATH",
        "GLIBC_TUNABLES",
        "NODE_OPTIONS",
        "PERL5LIB",
        "RUBYLIB",
    }
)
FORBIDDEN_PROCESS_ENV_PREFIXES = (
    "COMPOSE_",
    "DOCKER_",
    "DYLD_",
    "LD_",
    "MALLOC_",
    "PYTHON",
)
PYTHON_FD_BOOTSTRAP = (
    "import os,sys;fd=int(sys.argv[1]);path=sys.argv[2];"
    "root=os.path.dirname(os.path.dirname(path));"
    "sys.path[:0]=[os.path.join(root,'scripts'),root];"
    "os.environ['SERVERWARE_EXECUTING_SCRIPT_FD']=str(fd);"
    "sys.argv=[path,*sys.argv[3:]];"
    "size=os.fstat(fd).st_size;os.lseek(fd,0,os.SEEK_SET);"
    "data=b'';"
    "\nwhile len(data)<size:\n data+=os.read(fd,min(65536,size-len(data)))\n"
    "\nif len(data)!=size: raise RuntimeError('measured Python script changed while executing')\n"
    "scope={'__name__':'__main__','__file__':path,'__package__':None,'__cached__':None};"
    "exec(compile(data,path,'exec'),scope,scope)"
)


@dataclass
class MeasuredExecutable:
    path: Path
    setting: str
    fd: int
    metadata: os.stat_result
    sha256: str

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1


@dataclass
class MeasuredScript:
    path: Path
    setting: str
    fd: int
    metadata: os.stat_result
    sha256: str

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_prefixed_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def normalize_command_value(value: Any, label: str) -> list[str] | None:
    if value is None:
        return None
    if isinstance(value, str):
        return [value]
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"{label} must be a string list or null")
    return list(value)


def normalize_environment_hashes(value: Any, label: str) -> list[dict[str, str]]:
    if value is None:
        value = {}
    if not isinstance(value, dict):
        raise ValueError(f"{label} environment must be an object")
    normalized = []
    for name, raw in sorted(value.items()):
        if not isinstance(name, str) or not name or "=" in name:
            raise ValueError(f"{label} environment contains an invalid variable name")
        if raw is None:
            rendered = ""
        elif isinstance(raw, bool):
            rendered = "true" if raw else "false"
        else:
            rendered = str(raw)
        normalized.append(
            {
                "name": name,
                "value_sha256": sha256_prefixed_bytes(rendered.encode("utf-8")),
            }
        )
    return normalized


def normalize_string_list(value: Any, label: str) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"{label} must be a string list")
    return sorted(value)


def normalize_compose_networks(value: Any, label: str) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return sorted(value)
    if isinstance(value, dict) and all(isinstance(item, str) for item in value):
        return sorted(value)
    raise ValueError(f"{label} networks must be a string list or object")


def normalize_compose_devices(value: Any, label: str) -> list[dict[str, str]]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError(f"{label} devices must be a list")
    devices: list[dict[str, str]] = []
    for item in value:
        if isinstance(item, str):
            parts = item.split(":")
            source = parts[0]
            target = parts[1] if len(parts) > 1 and parts[1] else source
            permissions = parts[2] if len(parts) > 2 else "rwm"
        elif isinstance(item, dict):
            source = item.get("source") or item.get("path_on_host")
            target = item.get("target") or item.get("path_in_container") or source
            permissions = item.get("permissions") or item.get("cgroup_permissions") or "rwm"
        else:
            raise ValueError(f"{label} device entry is invalid")
        if not all(isinstance(field, str) and field for field in (source, target, permissions)):
            raise ValueError(f"{label} device entry is incomplete")
        devices.append(
            {"source": source, "target": target, "permissions": permissions}
        )
    return sorted(devices, key=lambda item: (item["target"], item["source"], item["permissions"]))


def normalize_compose_mounts(value: Any, label: str) -> list[dict[str, Any]]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError(f"{label} volumes must be a list")
    mounts: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, dict):
            raise ValueError(f"{label} volume entry must be an object")
        mount_type = item.get("type")
        source = item.get("source")
        target = item.get("target")
        if mount_type not in {"bind", "volume", "tmpfs"} or not isinstance(target, str):
            raise ValueError(f"{label} volume entry is invalid")
        if mount_type != "tmpfs" and not isinstance(source, str):
            raise ValueError(f"{label} volume source is invalid")
        normalized = {
            "type": mount_type,
            "source": source if isinstance(source, str) else "",
            "target": target,
            "read_only": bool(item.get("read_only", False)),
            "bind": json.loads(canonical_json(item.get("bind") or {})),
            "volume": json.loads(canonical_json(item.get("volume") or {})),
            "tmpfs": json.loads(canonical_json(item.get("tmpfs") or {})),
            "consistency": str(item.get("consistency") or ""),
        }
        mounts.append(normalized)
    return sorted(mounts, key=lambda item: (item["target"], item["type"], item["source"]))


def normalize_tmpfs(value: Any, label: str) -> list[dict[str, Any]]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError(f"{label} tmpfs must be a list")
    normalized: list[dict[str, Any]] = []
    for item in value:
        if isinstance(item, str):
            target, separator, raw_options = item.partition(":")
            options = normalize_tmpfs_options(raw_options.split(",") if separator else [])
        elif isinstance(item, dict):
            target = item.get("target")
            options_value = item.get("options") or []
            options = normalize_tmpfs_options(options_value)
        else:
            raise ValueError(f"{label} tmpfs entry is invalid")
        if not isinstance(target, str) or not target.startswith("/"):
            raise ValueError(f"{label} tmpfs target is invalid")
        normalized.append({"target": target, "options": options})
    return sorted(normalized, key=lambda item: item["target"])


def normalize_tmpfs_options(value: Any) -> list[str]:
    normalized: list[str] = []
    for raw in value:
        option = str(raw)
        if not option:
            continue
        if option.startswith("size="):
            option = "size_bytes=" + str(
                parse_compose_byte_limit(option.split("=", 1)[1], "tmpfs size")
            )
        normalized.append(option)
    return sorted(normalized)


def parse_compose_byte_limit(value: Any, label: str) -> int:
    if value in (None, "", 0, "0"):
        return 0
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if not isinstance(value, str):
        raise ValueError(f"{label} must be an integer byte count or size string")
    match = re.fullmatch(r"([0-9]+)([kmgt]i?b?|b)?", value.strip().lower())
    if match is None:
        raise ValueError(f"{label} has an invalid size")
    powers = {None: 0, "b": 0, "k": 1, "kb": 1, "ki": 1, "kib": 1,
              "m": 2, "mb": 2, "mi": 2, "mib": 2,
              "g": 3, "gb": 3, "gi": 3, "gib": 3,
              "t": 4, "tb": 4, "ti": 4, "tib": 4}
    return int(match.group(1)) * (1024 ** powers[match.group(2)])


def normalize_compose_runtime_model(model: Any) -> dict[str, Any]:
    if not isinstance(model, dict) or not isinstance(model.get("services"), dict):
        raise ValueError("rendered Compose model has no service object")
    services = model["services"]
    if set(services) != set(FINAL_SERVICE_USERS):
        raise ValueError("rendered Compose runtime service set is not closed and complete")
    normalized_services: dict[str, Any] = {}
    for service in sorted(services):
        config = services[service]
        if not isinstance(config, dict):
            raise ValueError(f"rendered Compose service {service} is invalid")
        compose_user = str(config.get("user") or "")
        if service == "serverware" and compose_user != FINAL_SERVICE_USERS[service]:
            raise ValueError("final control-plane Compose user must be exactly 65532:65532")
        normalized_services[service] = {
            "image": str(config.get("image") or ""),
            "compose_user": compose_user,
            "required_runtime_user": FINAL_SERVICE_USERS[service],
            "entrypoint": normalize_command_value(config.get("entrypoint"), service),
            "command": normalize_command_value(config.get("command"), service),
            "working_dir": str(config.get("working_dir") or ""),
            "environment": normalize_environment_hashes(config.get("environment"), service),
            "devices": normalize_compose_devices(config.get("devices"), service),
            "networks": normalize_compose_networks(config.get("networks"), service),
            "mounts": normalize_compose_mounts(config.get("volumes"), service),
            "tmpfs": normalize_tmpfs(config.get("tmpfs"), service),
            "ports": json.loads(canonical_json(config.get("ports") or [])),
            "links": normalize_string_list(config.get("links"), f"{service} links"),
            "external_links": normalize_string_list(
                config.get("external_links"), f"{service} external_links"
            ),
            "host_config": {
                "read_only": bool(config.get("read_only", False)),
                "privileged": bool(config.get("privileged", False)),
                "cap_add": sorted(str(item) for item in (config.get("cap_add") or [])),
                "cap_drop": sorted(str(item) for item in (config.get("cap_drop") or [])),
                "security_opt": sorted(str(item) for item in (config.get("security_opt") or [])),
                "pids_limit": int(config.get("pids_limit") or 0),
                "memory": parse_compose_byte_limit(config.get("mem_limit"), f"{service} mem_limit"),
                "init": bool(config.get("init", False)),
                "group_add": normalize_string_list(
                    config.get("group_add"), f"{service} group_add"
                ),
                "volumes_from": normalize_string_list(
                    config.get("volumes_from"), f"{service} volumes_from"
                ),
                "dns": normalize_string_list(config.get("dns"), f"{service} dns"),
                "dns_search": normalize_string_list(
                    config.get("dns_search"), f"{service} dns_search"
                ),
                "dns_opt": normalize_string_list(
                    config.get("dns_opt"), f"{service} dns_opt"
                ),
                "extra_hosts": normalize_string_list(
                    config.get("extra_hosts"), f"{service} extra_hosts"
                ),
                "pid": str(config.get("pid") or ""),
                "ipc": str(config.get("ipc") or ""),
                "uts": str(config.get("uts") or ""),
                "network_mode": str(config.get("network_mode") or ""),
                "userns_mode": str(config.get("userns_mode") or ""),
                "ulimits": json.loads(canonical_json(config.get("ulimits") or {})),
            },
        }
    resources: dict[str, dict[str, dict[str, Any]]] = {}
    for kind in ("networks", "volumes"):
        raw_resources = model.get(kind) or {}
        if not isinstance(raw_resources, dict):
            raise ValueError(f"rendered Compose {kind} must be an object")
        normalized_resources: dict[str, dict[str, Any]] = {}
        for name, value in sorted(raw_resources.items()):
            if not isinstance(name, str) or not name or not isinstance(value, dict):
                raise ValueError(f"rendered Compose {kind} entry is invalid")
            normalized_resources[name] = {
                "name": (
                    str(value.get("name") or name)
                    if bool(value.get("external", False))
                    else ""
                ),
                "external": bool(value.get("external", False)),
                "driver": str(value.get("driver") or ""),
                "driver_opts": json.loads(
                    canonical_json(value.get("driver_opts") or {})
                ),
            }
        resources[kind] = normalized_resources
    runtime_model = {"services": normalized_services, **resources}
    runtime_model["sha256"] = sha256_prefixed_bytes(
        canonical_json(runtime_model).encode("utf-8")
    )
    return runtime_model


def nested_socket_path(value: Any) -> Any:
    return (value.get("socket") or {}).get("path") if isinstance(value, dict) else None


def sha256_prefixed_file(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def validate_secure_ancestors(path: Path, label: str) -> None:
    if not path.is_absolute():
        raise ValueError(f"{label} path must be absolute")
    current = Path(path.anchor)
    for component in path.parts[1:-1]:
        current /= component
        try:
            metadata = current.lstat()
        except OSError as exc:
            raise ValueError(f"{label} ancestor is unavailable: {current}") from exc
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise ValueError(f"{label} ancestors must be non-symlink directories: {current}")
        if stat.S_IMODE(metadata.st_mode) & 0o022:
            raise ValueError(f"{label} ancestor must not be writable by group/other: {current}")


def read_fd_bytes(
    descriptor: int,
    opened: os.stat_result,
    label: str,
    *,
    max_bytes: int,
) -> bytes:
    chunks: list[bytes] = []
    remaining = max_bytes + 1
    while remaining:
        chunk = os.read(descriptor, min(64 * 1024, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    data = b"".join(chunks)
    completed = os.fstat(descriptor)
    identity = lambda item: (
        item.st_dev,
        item.st_ino,
        item.st_size,
        item.st_mtime_ns,
        item.st_ctime_ns,
    )
    if identity(opened) != identity(completed) or len(data) != opened.st_size:
        raise ValueError(f"{label} changed while being read")
    if len(data) > max_bytes:
        raise ValueError(f"{label} exceeds the {max_bytes}-byte size limit")
    return data


def open_measured_executable(
    path: Path,
    expected_digest: str,
    setting: str,
) -> MeasuredExecutable:
    validate_secure_ancestors(path, setting)
    if SHA256_RE.fullmatch(expected_digest) is None:
        raise ValueError(f"{setting} digest pin is invalid")
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise ValueError(f"{setting} could not be opened without following symlinks: {path}") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"{setting} must be a regular file: {path}")
        if metadata.st_uid not in {0, os.geteuid()}:
            raise ValueError(f"{setting} must be owned by root or the executing user: {path}")
        if stat.S_IMODE(metadata.st_mode) & 0o022:
            raise ValueError(f"{setting} must not be writable by group/other: {path}")
        if not metadata.st_mode & stat.S_IXUSR:
            raise ValueError(f"{setting} must be executable by its owner: {path}")
        if metadata.st_size <= 0 or metadata.st_size > MAX_EXECUTABLE_BYTES:
            raise ValueError(f"{setting} has an invalid executable size: {path}")
        data = read_fd_bytes(
            descriptor,
            metadata,
            setting,
            max_bytes=MAX_EXECUTABLE_BYTES,
        )
        actual_digest = "sha256:" + hashlib.sha256(data).hexdigest()
        if not hmac.compare_digest(actual_digest, expected_digest):
            raise ValueError(f"{setting} bytes do not match the hashed production env executable pin")
        os.lseek(descriptor, 0, os.SEEK_SET)
        return MeasuredExecutable(path, setting, descriptor, metadata, actual_digest)
    except Exception:
        os.close(descriptor)
        raise


def open_measured_script(
    path: Path,
    expected_digest: str | None,
    setting: str,
) -> MeasuredScript:
    validate_secure_ancestors(path, setting)
    if expected_digest is not None and SHA256_RE.fullmatch(expected_digest) is None:
        raise ValueError(f"{setting} digest pin is invalid")
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ValueError(f"{setting} could not be opened without following symlinks: {path}") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"{setting} must be a regular file: {path}")
        if metadata.st_uid not in {0, os.geteuid()}:
            raise ValueError(f"{setting} must be owned by root or the executing user: {path}")
        if stat.S_IMODE(metadata.st_mode) & 0o022:
            raise ValueError(f"{setting} must not be writable by group/other: {path}")
        if metadata.st_size <= 0 or metadata.st_size > MAX_EXECUTABLE_BYTES:
            raise ValueError(f"{setting} has an invalid script size: {path}")
        data = read_fd_bytes(
            descriptor,
            metadata,
            setting,
            max_bytes=MAX_EXECUTABLE_BYTES,
        )
        actual_digest = "sha256:" + hashlib.sha256(data).hexdigest()
        if expected_digest is not None and not hmac.compare_digest(actual_digest, expected_digest):
            raise ValueError(f"{setting} bytes do not match the hashed production env script pin")
        os.lseek(descriptor, 0, os.SEEK_SET)
        return MeasuredScript(path, setting, descriptor, metadata, actual_digest)
    except Exception:
        os.close(descriptor)
        raise


def measured_executable_reference(descriptor: int) -> str:
    if sys.platform.startswith("linux"):
        return f"/proc/self/fd/{descriptor}"
    if sys.platform == "darwin":
        return f"/dev/fd/{descriptor}"
    raise ValueError("measured-descriptor execution is supported only on Linux and macOS")


def run_measured_command(
    argv: list[str],
    *,
    setting: str,
    expected_digest: str,
    after_open: Any | None = None,
    **kwargs: Any,
) -> subprocess.CompletedProcess[Any]:
    measured = open_measured_executable(Path(argv[0]), expected_digest, setting)
    try:
        if after_open is not None:
            after_open(measured)
        if not sys.platform.startswith("linux"):
            return subprocess.run(argv, **kwargs)
        inherited = tuple(kwargs.pop("pass_fds", ()))
        return subprocess.run(
            argv,
            executable=measured_executable_reference(measured.fd),
            pass_fds=(*inherited, measured.fd),
            **kwargs,
        )
    finally:
        measured.close()


def run_measured_binary_command_bounded(
    argv: list[str],
    *,
    setting: str,
    expected_digest: str,
    max_stdout_bytes: int,
    max_stderr_bytes: int = 1024 * 1024,
    **kwargs: Any,
) -> subprocess.CompletedProcess[bytes]:
    if max_stdout_bytes < 0 or max_stderr_bytes < 0:
        raise ValueError("measured binary command byte limits must be non-negative")
    measured = open_measured_executable(Path(argv[0]), expected_digest, setting)
    process: subprocess.Popen[bytes] | None = None
    try:
        if not sys.platform.startswith("linux"):
            raise ValueError("bounded measured binary execution requires Linux")
        inherited = tuple(kwargs.pop("pass_fds", ()))
        process = subprocess.Popen(
            argv,
            executable=measured_executable_reference(measured.fd),
            pass_fds=(*inherited, measured.fd),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=False,
            **kwargs,
        )
        assert process.stdout is not None and process.stderr is not None
        streams = {
            process.stdout.fileno(): (process.stdout, max_stdout_bytes, "stdout"),
            process.stderr.fileno(): (process.stderr, max_stderr_bytes, "stderr"),
        }
        captured: dict[str, bytearray] = {"stdout": bytearray(), "stderr": bytearray()}
        selector = selectors.DefaultSelector()
        for stream, _, label in streams.values():
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, label)
        try:
            while selector.get_map():
                for key, _ in selector.select(timeout=1.0):
                    label = key.data
                    stream = key.fileobj
                    chunk = os.read(stream.fileno(), 64 * 1024)
                    if not chunk:
                        selector.unregister(stream)
                        continue
                    captured[label].extend(chunk)
                    limit = max_stdout_bytes if label == "stdout" else max_stderr_bytes
                    if len(captured[label]) > limit:
                        process.kill()
                        process.wait()
                        raise ValueError(
                            f"measured binary command {label} exceeded {limit} bytes"
                        )
                if process.poll() is not None and not selector.get_map():
                    break
            returncode = process.wait()
        finally:
            selector.close()
        return subprocess.CompletedProcess(
            argv,
            returncode,
            bytes(captured["stdout"]),
            bytes(captured["stderr"]),
        )
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait()
        measured.close()


def run_measured_python_script(
    argv: list[str],
    *,
    python_setting: str,
    python_expected_digest: str,
    script_setting: str,
    script_expected_digest: str | None,
    after_script_open: Any | None = None,
    **kwargs: Any,
) -> subprocess.CompletedProcess[Any]:
    if len(argv) < 2:
        raise ValueError("measured Python command is missing its script")
    python = open_measured_executable(Path(argv[0]), python_expected_digest, python_setting)
    script_path = Path(argv[1])
    if not script_path.is_absolute():
        script_path = (Path(kwargs.get("cwd") or os.getcwd()) / script_path).resolve()
    script = open_measured_script(script_path, script_expected_digest, script_setting)
    try:
        if after_script_open is not None:
            after_script_open(script)
        if not sys.platform.startswith("linux"):
            raise ValueError("measured Python script descriptor execution requires Linux")
        inherited = tuple(kwargs.pop("pass_fds", ()))
        command = [
            argv[0],
            "-I",
            "-c",
            PYTHON_FD_BOOTSTRAP,
            str(script.fd),
            str(script_path),
            *argv[2:],
        ]
        return subprocess.run(
            command,
            executable=measured_executable_reference(python.fd),
            pass_fds=(*inherited, python.fd, script.fd),
            **kwargs,
        )
    finally:
        script.close()
        python.close()


def forbidden_process_environment_names(environment: dict[str, str]) -> list[str]:
    return sorted(
        name
        for name in environment
        if name in FORBIDDEN_PROCESS_ENV_NAMES
        or any(name.startswith(prefix) for prefix in FORBIDDEN_PROCESS_ENV_PREFIXES)
    )


def build_final_child_environment(
    loaded: dict[str, str],
    additions: dict[str, str] | None = None,
    *,
    ambient: dict[str, str] | None = None,
) -> dict[str, str]:
    ambient_injections = forbidden_process_environment_names(dict(os.environ) if ambient is None else ambient)
    if ambient_injections:
        raise ValueError(
            "final launcher environment contains forbidden runtime/loader injection settings: "
            + ", ".join(ambient_injections)
        )
    invalid_loaded = sorted(name for name in loaded if not name.startswith("SERVERWARE_"))
    if invalid_loaded:
        raise ValueError(
            "final production env contains non-SERVERWARE child environment settings: "
            + ", ".join(invalid_loaded)
        )
    loaded_injections = forbidden_process_environment_names(loaded)
    if loaded_injections:
        raise ValueError(
            "final production env contains forbidden runtime/loader injection settings: "
            + ", ".join(loaded_injections)
        )
    child = {**FINAL_CHILD_FIXED_ENV, **loaded}
    for name, value in (additions or {}).items():
        if not name.startswith("SERVERWARE_"):
            raise ValueError(f"final child env addition is not allowlisted: {name}")
        child[name] = value
    return child


def docker_subprocess_environment(base: dict[str, str], socket_path: Path) -> dict[str, str]:
    environment = {
        name: value
        for name, value in base.items()
        if not name.startswith("DOCKER_") and not name.startswith("COMPOSE_")
    }
    environment["DOCKER_HOST"] = f"unix://{socket_path}"
    return environment


def require_root_owned_docker_socket_ancestor(
    metadata: os.stat_result | Any,
    path: Path,
) -> None:
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise ValueError(f"Docker Unix socket ancestor must be a non-symlink directory: {path}")
    if metadata.st_uid != 0:
        raise ValueError(f"Docker Unix socket ancestor must be owned by UID 0: {path}")
    if stat.S_IMODE(metadata.st_mode) & 0o022:
        raise ValueError(
            f"Docker Unix socket ancestor must not be writable by group/other: {path}"
        )


def validate_docker_unix_socket(path: Path, *, allow_current_owner: bool = False) -> dict[str, Any]:
    if path != Path("/run/docker.sock") and not allow_current_owner:
        raise ValueError("final Docker Unix socket must be exactly /run/docker.sock")
    validate_secure_ancestors(path, "Docker Unix socket")
    current = Path(path.anchor)
    require_root_owned_docker_socket_ancestor(current.lstat(), current)
    for component in path.parts[1:-1]:
        current /= component
        metadata = current.lstat()
        require_root_owned_docker_socket_ancestor(metadata, current)
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ValueError(f"Docker Unix socket is unavailable: {path}") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISSOCK(metadata.st_mode):
        raise ValueError("Docker endpoint must be a non-symlink local Unix socket")
    allowed_owners = {0, os.geteuid()} if allow_current_owner else {0}
    if metadata.st_uid not in allowed_owners:
        raise ValueError("Docker Unix socket must be owned by root")
    if stat.S_IMODE(metadata.st_mode) & 0o002:
        raise ValueError("Docker Unix socket must not be world-writable")
    return {
        "path": str(path),
        "owner_uid": metadata.st_uid,
        "mode": oct(stat.S_IMODE(metadata.st_mode)),
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "local_unix_socket": True,
        "nofollow": True,
        "secure_ancestors": True,
    }


def verify_docker_daemon_identity(
    *,
    docker_executable: Path,
    docker_sha256: str,
    socket_path: Path,
    expected_daemon_id: str,
    base_env: dict[str, str],
) -> dict[str, Any]:
    socket_binding = validate_docker_unix_socket(socket_path)
    result = run_measured_command(
        [
            str(docker_executable),
            "--host",
            f"unix://{socket_path}",
            "info",
            "--format",
            "{{.ID}}",
        ],
        setting=PRODUCTION_DOCKER_EXECUTABLE_ENV,
        expected_digest=docker_sha256,
        env=docker_subprocess_environment(base_env, socket_path),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        text=True,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        raise ValueError(f"pinned Docker daemon identity query failed: {detail}")
    actual_daemon_id = result.stdout.strip()
    if not hmac.compare_digest(actual_daemon_id, expected_daemon_id):
        raise ValueError("current Docker daemon ID does not match the hashed production env pin")
    return {
        "daemon_id": actual_daemon_id,
        "daemon_id_verified": True,
        "socket": socket_binding,
    }


def require_stable_docker_daemon_binding(
    before: dict[str, Any],
    after: dict[str, Any],
) -> None:
    if before != after:
        raise ValueError("Docker socket identity or daemon ID changed during runtime inspection")


def validate_launcher_trusted_env(
    path: Path,
    data: bytes,
    metadata: os.stat_result,
    *,
    expected_path: str | None,
    expected_sha256: str | None,
) -> dict[str, Any]:
    if not isinstance(expected_path, str) or not expected_path:
        raise ValueError(f"launcher trust input {LAUNCHER_TRUSTED_ENV_PATH_INPUT} is required")
    if not isinstance(expected_sha256, str) or SHA256_RE.fullmatch(expected_sha256) is None:
        raise ValueError(
            f"launcher trust input {LAUNCHER_TRUSTED_ENV_SHA256_INPUT} must be sha256:<64 lowercase hex>"
        )
    if not Path(expected_path).is_absolute() or str(path) != expected_path:
        raise ValueError("production env path does not exactly match the out-of-band launcher trust path")
    validate_secure_ancestors(path, "production readiness env")
    if metadata.st_uid not in {0, os.geteuid()}:
        raise ValueError("production readiness env must be owned by root or the executing user")
    mode = stat.S_IMODE(metadata.st_mode)
    if mode not in {0o400, 0o600}:
        raise ValueError("production readiness env must use mode 0400 or 0600 with no group/world bits")
    actual_digest = "sha256:" + hashlib.sha256(data).hexdigest()
    if not hmac.compare_digest(actual_digest, expected_sha256):
        raise ValueError("production readiness env does not match the out-of-band launcher trust digest")
    return {
        "path": expected_path,
        "sha256": expected_sha256,
        "owner_uid": metadata.st_uid,
        "mode": oct(mode),
        "regular_file": True,
        "nofollow": True,
        "secure_ancestors": True,
        "authority": "out-of-band launcher trust root",
    }


def validate_final_launcher_contract(loaded: dict[str, str]) -> dict[str, Any]:
    contract = loaded.get(FINAL_LAUNCHER_CONTRACT_ENV)
    if contract != FINAL_LAUNCHER_CONTRACT:
        raise ValueError(
            f"{FINAL_LAUNCHER_CONTRACT_ENV} must be exactly {FINAL_LAUNCHER_CONTRACT} in final mode"
        )
    return {
        "name": contract,
        "enforced_before_python_startup_by": "trusted root-owned launcher/systemd unit",
        "in_process_validation_is_not_startup_attestation": True,
    }


def read_regular_file_once(
    path: Path,
    label: str,
    *,
    max_bytes: int,
    owner_only: bool = False,
    executable: bool = False,
) -> tuple[bytes, os.stat_result]:
    if not hasattr(os, "O_NOFOLLOW"):
        raise ValueError(f"{label} cannot be opened safely on this platform")
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise ValueError(f"{label} could not be opened without following symlinks: {path}") from exc
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise ValueError(f"{label} must be a regular file: {path}")
        if opened.st_size <= 0 or opened.st_size > max_bytes:
            raise ValueError(f"{label} must contain between 1 and {max_bytes} bytes: {path}")
        if owner_only:
            if stat.S_IMODE(opened.st_mode) != 0o600:
                raise ValueError(f"{label} must use owner-only mode 0600: {path}")
            if opened.st_uid != os.geteuid():
                raise ValueError(f"{label} must be owned by the readiness runner user: {path}")
        if executable and not opened.st_mode & stat.S_IXUSR:
            raise ValueError(f"{label} must be executable by its owner: {path}")
        data = read_fd_bytes(descriptor, opened, f"{label}: {path}", max_bytes=max_bytes)
        return data, opened
    finally:
        os.close(descriptor)


def remeasure_executable(path: Path, expected_digest: str, label: str) -> str:
    measured = open_measured_executable(path, expected_digest, label)
    try:
        return measured.sha256
    finally:
        measured.close()


def parse_executable_digest_manifest(
    loaded: dict[str, str],
    *,
    expected_settings: set[str],
) -> dict[str, str]:
    raw = loaded.get(EXECUTABLE_DIGEST_MANIFEST_ENV)
    if not isinstance(raw, str) or not raw:
        raise ValueError(f"{EXECUTABLE_DIGEST_MANIFEST_ENV} is required")
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{EXECUTABLE_DIGEST_MANIFEST_ENV} must be valid JSON") from exc
    if not isinstance(parsed, dict) or set(parsed) != expected_settings:
        raise ValueError(f"{EXECUTABLE_DIGEST_MANIFEST_ENV} must contain the exact executable setting set")
    for setting, digest in parsed.items():
        if not isinstance(digest, str) or SHA256_RE.fullmatch(digest) is None:
            raise ValueError(
                f"{EXECUTABLE_DIGEST_MANIFEST_ENV} entry {setting} must be sha256:<64 lowercase hex>"
            )
    return dict(parsed)


def parse_python_script_digest_pins(loaded: dict[str, str]) -> dict[str, tuple[str, str]]:
    pins: dict[str, tuple[str, str]] = {}
    for script_name, setting in PINNED_PYTHON_SCRIPTS.items():
        digest = loaded.get(setting)
        if not isinstance(digest, str) or SHA256_RE.fullmatch(digest) is None:
            raise ValueError(f"{setting} must be sha256:<64 lowercase hex>")
        pins[str((ROOT / "scripts" / script_name).resolve())] = (setting, digest)
    return pins


def validate_docker_toolchain_settings(loaded: dict[str, str]) -> dict[str, str]:
    values = {
        name: loaded.get(name)
        for name in (
            DOCKER_COMPOSE_PLUGIN_EXECUTABLE_ENV,
            DOCKER_COMPOSE_PLUGIN_SHA256_ENV,
            DOCKER_UNIX_SOCKET_ENV,
            DOCKER_DAEMON_ID_ENV,
            DOCKER_COMPOSE_PROJECT_NAME_ENV,
        )
    }
    if not isinstance(values[DOCKER_COMPOSE_PLUGIN_EXECUTABLE_ENV], str) or not Path(
        values[DOCKER_COMPOSE_PLUGIN_EXECUTABLE_ENV]
    ).is_absolute():
        raise ValueError(f"{DOCKER_COMPOSE_PLUGIN_EXECUTABLE_ENV} must be an absolute path")
    if (
        not isinstance(values[DOCKER_COMPOSE_PLUGIN_SHA256_ENV], str)
        or SHA256_RE.fullmatch(values[DOCKER_COMPOSE_PLUGIN_SHA256_ENV]) is None
    ):
        raise ValueError(f"{DOCKER_COMPOSE_PLUGIN_SHA256_ENV} must be sha256:<64 lowercase hex>")
    if not isinstance(values[DOCKER_UNIX_SOCKET_ENV], str) or not Path(
        values[DOCKER_UNIX_SOCKET_ENV]
    ).is_absolute():
        raise ValueError(f"{DOCKER_UNIX_SOCKET_ENV} must be an absolute path")
    daemon_id = values[DOCKER_DAEMON_ID_ENV]
    if (
        not isinstance(daemon_id, str)
        or daemon_id != daemon_id.strip()
        or not 8 <= len(daemon_id) <= 256
        or not all(character.isalnum() or character in "._:-" for character in daemon_id)
    ):
        raise ValueError(f"{DOCKER_DAEMON_ID_ENV} is invalid")
    project_name = values[DOCKER_COMPOSE_PROJECT_NAME_ENV]
    if (
        not isinstance(project_name, str)
        or re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,62}", project_name) is None
    ):
        raise ValueError(f"{DOCKER_COMPOSE_PROJECT_NAME_ENV} is invalid")
    return {name: str(value) for name, value in values.items()}


def completion_proof_digest_path(path: Path, generation: str) -> Path:
    if re.fullmatch(r"[0-9a-f]{32}", generation) is None:
        raise ValueError("completion proof checksum generation is invalid")
    return path.with_name(f"{path.name}.sha256.{generation}")


def capture_optional_proof_state(path: Path) -> dict[str, Any]:
    try:
        data, metadata = read_regular_file_once(
            path,
            "pre-run completion proof",
            max_bytes=MAX_COMPLETION_PROOF_BYTES,
            owner_only=True,
        )
    except FileNotFoundError:
        return {"exists": False}
    state: dict[str, Any] = {
        "exists": True,
        "sha256": "sha256:" + hashlib.sha256(data).hexdigest(),
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
    }
    try:
        parsed = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return state
    if isinstance(parsed, dict):
        integrity = parsed.get("integrity_metadata")
        if isinstance(integrity, dict) and isinstance(integrity.get("generation"), str):
            state["generation"] = integrity["generation"]
    return state


def sha256_prefixed_base64url(value: str, label: str) -> str:
    try:
        padding = "=" * (-len(value) % 4)
        decoded = base64.urlsafe_b64decode(value + padding)
    except (ValueError, TypeError) as exc:
        raise ValueError(f"{label} is not valid base64url") from exc
    if len(decoded) < 32:
        raise ValueError(f"{label} must decode to at least 32 bytes")
    return "sha256:" + hashlib.sha256(decoded).hexdigest()


def verify_completion_output(path: Path, expected: argparse.Namespace | None = None) -> str:
    proof_bytes, proof_metadata = read_regular_file_once(
        path,
        "completion proof",
        max_bytes=MAX_COMPLETION_PROOF_BYTES,
        owner_only=True,
    )
    try:
        proof = json.loads(proof_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("completion proof is not valid UTF-8 JSON") from exc
    if not isinstance(proof, dict):
        raise ValueError("completion proof must be a JSON object")

    required_fields = {
        "apiVersion",
        "kind",
        "ok",
        "verification_passed",
        "verification_mode",
        "result_scope",
        "readiness_only",
        "readiness_ok",
        "completion_status",
        "release_completion",
        "final_completion",
        "hardware_proof",
        "assurance_ceiling",
        "generated_at_unix",
        "artifacts",
        "production_readiness",
        "production_readiness_config",
        "current_completion_host",
        "production_env_binding",
        "running_production_containers",
        "production_host_preflight",
        "nitro_kms_evidence",
        "nitro_evidence_binding",
        "hardware_assurance_evidence",
        "final_challenge_consumption",
        "production_images_build",
        "production_images_published",
        "release_provenance",
        "image_signatures",
        "benchmark",
        "release_security_evidence",
        "production_proxy_response_proof",
        "proof_path",
        "integrity_metadata",
    }
    if set(proof) != required_fields:
        raise ValueError("completion proof persisted field set does not match the v3 contract")
    verification_mode = expected.verification_mode if expected is not None else proof.get("verification_mode")
    is_final = verification_mode == "final"
    expected_contract = {
        "apiVersion": "serverware.completionProof/v3",
        "kind": "ServerwareCompletionProof" if is_final else "ServerwarePreEnclaveReadiness",
        "ok": True,
        "verification_passed": True,
        "verification_mode": verification_mode,
        "result_scope": "final-completion" if is_final else "readiness-only",
        "readiness_only": not is_final,
        "readiness_ok": True,
        "completion_status": "hardware-backed-release-completion" if is_final else "pre-enclave-readiness",
        "release_completion": "pass" if is_final else "not-final",
        "final_completion": is_final,
        "hardware_proof": is_final,
        "proof_path": str(path),
    }
    for field, value in expected_contract.items():
        if proof.get(field) != value:
            raise ValueError(f"completion proof persisted {field} does not match the expected contract")
    if not isinstance(proof.get("generated_at_unix"), int) or proof["generated_at_unix"] <= 0:
        raise ValueError("completion proof generated_at_unix is invalid")
    if expected is not None:
        runner_started_at = getattr(expected, "runner_started_at_unix", None)
        if not isinstance(runner_started_at, int) or proof["generated_at_unix"] < runner_started_at:
            raise ValueError("completion proof predates the current readiness runner invocation")
        if proof["generated_at_unix"] > int(time.time()) + COMPLETION_PROOF_FUTURE_SKEW_SECONDS:
            raise ValueError("completion proof generated_at_unix is in the future")
    assurance = proof.get("assurance_ceiling")
    if not isinstance(assurance, dict) or assurance.get("final_completion") is not is_final:
        raise ValueError("completion proof assurance ceiling is inconsistent")
    challenge = proof.get("final_challenge_consumption")
    if not isinstance(challenge, dict):
        raise ValueError("completion proof final challenge contract is invalid")
    if is_final and (challenge.get("consumed") is not True or challenge.get("completion_identity") is None):
        raise ValueError("final completion proof did not persist consumed off-host challenge evidence")
    if not is_final and challenge != {"required": False, "consumed": False}:
        raise ValueError("readiness proof persisted an invalid final challenge contract")

    integrity = proof.get("integrity_metadata")
    if not isinstance(integrity, dict) or set(integrity) != {
        "generation",
        "detached_sha256_path",
        "scope",
        "independently_authenticated",
        "authenticity_requires_external_signature_or_checkpoint",
    }:
        raise ValueError("completion proof detached integrity metadata is invalid")
    generation = integrity.get("generation")
    if not isinstance(generation, str):
        raise ValueError("completion proof checksum generation is invalid")
    digest_path = completion_proof_digest_path(path, generation)
    if (
        integrity.get("detached_sha256_path") != str(digest_path)
        or integrity.get("scope") != "checksum-only"
        or integrity.get("independently_authenticated") is not False
        or integrity.get("authenticity_requires_external_signature_or_checkpoint") is not True
    ):
        raise ValueError("completion proof detached integrity metadata is invalid")
    digest_bytes, digest_metadata = read_regular_file_once(
        digest_path,
        "completion proof detached SHA-256",
        max_bytes=128,
        owner_only=True,
    )
    try:
        detached_digest = digest_bytes.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError("completion proof detached SHA-256 is non-ASCII") from exc
    if not detached_digest.endswith("\n") or detached_digest.count("\n") != 1:
        raise ValueError("completion proof detached SHA-256 must contain exactly one digest line")
    expected_digest = detached_digest[:-1]
    if SHA256_RE.fullmatch(expected_digest) is None:
        raise ValueError("completion proof detached SHA-256 must be sha256:<64 lowercase hex>")
    actual_digest = "sha256:" + hashlib.sha256(proof_bytes).hexdigest()
    if not hmac.compare_digest(expected_digest, actual_digest):
        raise ValueError("completion proof detached SHA-256 does not match the completion proof bytes")
    if expected is not None:
        previous = getattr(expected, "pre_run_completion_proof_state", {"exists": False})
        if previous.get("exists"):
            if previous.get("sha256") == actual_digest:
                raise ValueError("completion proof path was not changed by the current verifier invocation")
            if previous.get("generation") == generation:
                raise ValueError("completion proof generation was reused from the pre-run output")
            if (previous.get("device"), previous.get("inode")) == (
                proof_metadata.st_dev,
                proof_metadata.st_ino,
            ):
                raise ValueError("completion proof commit marker inode was not replaced")
        runner_started_at_ns = getattr(expected, "runner_started_at_unix", 0) * 1_000_000_000
        if digest_metadata.st_mtime_ns < runner_started_at_ns or proof_metadata.st_mtime_ns < runner_started_at_ns:
            raise ValueError("completion proof generation was not published during the current runner invocation")

    artifacts = proof.get("artifacts")
    if not isinstance(artifacts, dict) or not artifacts:
        raise ValueError("completion proof artifact contract is empty")
    for label, artifact in artifacts.items():
        if (
            not isinstance(label, str)
            or not isinstance(artifact, dict)
            or set(artifact) != {"path", "sha256"}
            or not isinstance(artifact.get("path"), str)
            or SHA256_RE.fullmatch(str(artifact.get("sha256"))) is None
        ):
            raise ValueError("completion proof artifact contract is invalid")
        artifact_bytes, _ = read_regular_file_once(
            Path(artifact["path"]),
            f"completion proof artifact {label}",
            max_bytes=MAX_COMPLETION_PROOF_BYTES,
        )
        artifact_digest = "sha256:" + hashlib.sha256(artifact_bytes).hexdigest()
        if not hmac.compare_digest(artifact_digest, artifact["sha256"]):
            raise ValueError(f"completion proof artifact {label} digest does not match current bytes")
    binding = proof.get("production_env_binding")
    proxy = proof.get("production_proxy_response_proof")
    if not isinstance(binding, dict) or not isinstance(proxy, dict):
        raise ValueError("completion proof proxy/env binding contract is missing")
    if expected is not None:
        for attribute, env_name in PROXY_DIGEST_ENV_SETTINGS.items():
            value = getattr(expected, attribute)
            if binding.get(env_name) != value:
                raise ValueError(f"completion proof production env binding omitted {env_name}")
        for field, attribute in (
            ("client_request_digest", "proxy_client_request_digest"),
            ("request_digest", "proxy_request_digest"),
            ("operation_digest", "proxy_operation_digest"),
        ):
            if proxy.get(field) != getattr(expected, attribute):
                raise ValueError(f"completion proof proxy response {field} mismatch")
        if proxy.get("server_instance_id") != expected.proxy_server_instance_id:
            raise ValueError("completion proof proxy server instance mismatch")
        if proxy.get("principal_id") != expected.proxy_principal_id:
            raise ValueError("completion proof proxy principal mismatch")
        for field in (
            "vendor_quote_verified",
            "collector_signature_verified",
            "server_statement_signature_verified",
            "fresh_client_nonce_bound",
            "authenticated_external_client_capture_bound",
            "release_authority_bound",
            "embedded_control_plane_authorization_receipt_bound",
            "signed_policy_route_bound",
            "signed_policy_response_headers_bound",
            "upstream_response_bound",
            "release_artifacts_bound",
        ):
            if proxy.get(field) is not True:
                raise ValueError(f"completion proof proxy contract omitted {field}")
        if binding.get("verification_mode") != verification_mode:
            raise ValueError("completion proof production env binding mode mismatch")
        if binding.get("expected_server_instance_id") != expected.proxy_server_instance_id:
            raise ValueError("completion proof production env binding server instance mismatch")
        if binding.get("expected_proxy_principal_id") != expected.proxy_principal_id:
            raise ValueError("completion proof production env binding principal mismatch")
        if binding.get("production_readiness_env_sha256") != expected.production_readiness_env_sha256:
            raise ValueError("completion proof production env digest mismatch")
        if is_final and binding.get("final_trust_roots_env_bound") is not True:
            raise ValueError("final completion proof did not bind final trust roots")

        expected_artifact_paths = {
            "production_readiness": expected.readiness_out,
            "production_readiness_config": expected.config_out,
            "production_readiness_env": expected.env_file,
            "production_host_preflight": expected.production_host_preflight,
            "nitro_evidence": expected.nitro_evidence_out,
            "production_images_build": expected.production_images_build,
            "production_images_env": expected.production_images_env,
            "production_images_published": expected.production_images_published,
            "release_provenance_summary": expected.release_provenance_summary,
            "release_provenance": expected.release_provenance,
            "release_provenance_trusted_public_key": expected.release_provenance_trusted_public_key,
            "image_signatures_summary": expected.image_signatures_summary,
            "image_signatures": expected.image_signatures,
            "sigstore_trusted_public_key": expected.sigstore_trusted_public_key,
            "rekor_trusted_public_key": expected.rekor_trusted_public_key,
            "external_checkpoint_trusted_public_key": expected.external_checkpoint_trusted_public_key,
            "bench": expected.bench,
            "policy_bundle": expected.policy_bundle,
            "policy_trusted_public_key": expected.policy_trusted_public_key,
            "policy_identity_verification": expected.policy_identity_verification,
            "policy_activation_verification": expected.policy_activation_verification,
            "policy_activation_signature": expected.policy_activation_signature,
            "policy_activation_trusted_public_key": expected.policy_activation_trusted_public_key,
            "reproducible_build_verification": expected.reproducible_build_verification,
            "reproducible_build_signature": expected.reproducible_build_signature,
            "reproducible_build_trusted_public_key": expected.reproducible_build_trusted_public_key,
            "kms_materials": expected.kms_materials,
            "control_plane_response_signing_public_key": expected.control_plane_response_signing_public_key,
            "proxy_response_proof": expected.proxy_response_proof,
            "proxy_proof_verifier_public_key": expected.proxy_proof_verifier_public_key,
            "proxy_collector_public_key": expected.proxy_collector_public_key,
            "compose_file": expected.compose_file,
        }
        if expected.hardware_assurance:
            expected_artifact_paths["hardware_assurance"] = expected.hardware_assurance
            expected_artifact_paths["hardware_assurance_trusted_public_key"] = (
                expected.hardware_assurance_trusted_public_key
            )
        if is_final:
            expected_artifact_paths["production_host_preflight_signing_public_key"] = (
                expected.production_host_preflight_signing_public_key
            )
            expected_artifact_paths["final_challenge_receipt"] = expected.final_challenge_receipt
            expected_artifact_paths["final_challenge_authority_public_key"] = (
                expected.final_challenge_authority_public_key
            )
        for label, expected_path in expected_artifact_paths.items():
            artifact = artifacts.get(label)
            if not isinstance(artifact, dict) or artifact.get("path") != str(Path(expected_path)):
                raise ValueError(f"completion proof artifact {label} path mismatch")
        unexpected_artifacts = set(artifacts) - set(expected_artifact_paths) - {
            "production_host_preflight_config",
            "kms_ciphertext_broker-kek",
            "kms_ciphertext_decision-gate-ca",
        }
        if unexpected_artifacts:
            raise ValueError(f"completion proof contains unexpected artifact bindings: {sorted(unexpected_artifacts)}")

        required_summaries = {
            "production_readiness",
            "production_readiness_config",
            "current_completion_host",
            "production_env_binding",
            "running_production_containers",
            "production_host_preflight",
            "nitro_kms_evidence",
            "nitro_evidence_binding",
            "hardware_assurance_evidence",
            "production_images_build",
            "production_images_published",
            "release_provenance",
            "image_signatures",
            "benchmark",
            "release_security_evidence",
            "production_proxy_response_proof",
        }
        if any(not isinstance(proof.get(field), dict) or not proof[field] for field in required_summaries):
            raise ValueError("completion proof persisted summary contract is incomplete")
        for field in ("production_readiness", "production_readiness_config"):
            environment = proof[field].get("environment")
            if not isinstance(environment, dict) or environment.get(
                "production_readiness_env_sha256"
            ) != expected.production_readiness_env_sha256:
                raise ValueError(f"completion proof {field} is not bound to the hashed production env")
        if is_final:
            hardware = proof["hardware_assurance_evidence"]
            if hardware.get("verified") is not True or assurance.get("hardware_evidence_verified") is not True:
                raise ValueError("final completion proof hardware assurance contract is incomplete")
            completion_identity = challenge.get("completion_identity")
            completion_identity_fields = {
                "apiVersion",
                "release_identity_sha256",
                "current_host_identity_sha256",
                "hardware_verifier_key_id",
                "hardware_assurance_document_sha256",
                "hardware_assurance_signed_statement_sha256",
                "challenge_nonce_sha256",
                "proxy_server_statement_sha256",
            }
            if not isinstance(completion_identity, dict) or set(completion_identity) != completion_identity_fields:
                raise ValueError("final completion identity does not match its schema")
            if completion_identity.get("apiVersion") != "serverware.finalCompletionIdentity/v1":
                raise ValueError("final completion identity apiVersion is invalid")
            for field in completion_identity_fields - {"apiVersion"}:
                if SHA256_RE.fullmatch(str(completion_identity.get(field))) is None:
                    raise ValueError(f"final completion identity {field} is invalid")
            if not isinstance(binding.get("executing_interpreter"), dict) or binding[
                "executing_interpreter"
            ].get("matches_pinned_path_inode") is not True:
                raise ValueError("final completion proof omitted executing-interpreter identity")
            if not isinstance(binding.get("executing_script"), dict) or binding[
                "executing_script"
            ].get("matches_pinned_path_inode") is not True:
                raise ValueError("final completion proof omitted executing verifier-script identity")
            expected_script_digests = {
                setting: digest
                for setting, digest in getattr(expected, "script_digest_pins", {}).values()
            }
            if (
                set(expected_script_digests) != set(PINNED_PYTHON_SCRIPTS.values())
                or binding.get("current_python_script_digests") != expected_script_digests
            ):
                raise ValueError("final completion proof did not bind every pinned Python script digest")
            preflight_scripts = (
                proof["production_host_preflight"]
                .get("runtime_trust_materials", {})
                .get("python_script_digests")
            )
            if preflight_scripts != expected_script_digests:
                raise ValueError("final completion proof host preflight script digest binding mismatch")
            preflight_executing_script = proof["production_host_preflight"].get(
                "executing_script"
            )
            if (
                not isinstance(preflight_executing_script, dict)
                or preflight_executing_script.get("sha256")
                != expected_script_digests[PRODUCTION_HOST_PREFLIGHT_SCRIPT_SHA256_ENV]
                or preflight_executing_script.get("matches_pinned_path_inode") is not True
            ):
                raise ValueError(
                    "final completion proof omitted the descriptor-bound host preflight script identity"
                )
            preflight_authenticity = proof["production_host_preflight"].get("authenticity")
            if (
                not isinstance(preflight_authenticity, dict)
                or preflight_authenticity.get("verified") is not True
                or preflight_authenticity.get("key_id")
                != expected.production_host_preflight_signing_key_id
                or preflight_authenticity.get("max_age_seconds")
                != expected.production_host_preflight_max_age_seconds
            ):
                raise ValueError("final completion proof omitted authenticated fresh host preflight evidence")
            completion_policy_roots = proof["release_security_evidence"].get(
                "trust_roots"
            )
            preflight_policy_roots = (
                proof["production_host_preflight"]
                .get("release_security_evidence", {})
                .get("trust_roots")
            )
            if (
                not isinstance(completion_policy_roots, dict)
                or set(completion_policy_roots)
                != {"policy_identity", "policy_activation", "reproducible_build"}
                or completion_policy_roots != preflight_policy_roots
            ):
                raise ValueError(
                    "final completion proof policy-role trust roots differ from authenticated preflight"
                )
            for role, expected_id in (
                ("policy_identity", expected.policy_trusted_public_key_id),
                (
                    "policy_activation",
                    expected.policy_activation_trusted_public_key_id,
                ),
                (
                    "reproducible_build",
                    expected.reproducible_build_trusted_public_key_id,
                ),
            ):
                if completion_policy_roots[role].get("spki_sha256") != expected_id:
                    raise ValueError(
                        f"final completion proof {role} trust-root identity mismatch"
                    )

        launcher_binding = binding.get("launcher_trust")
        expected_launcher_binding = getattr(expected, "launcher_env_binding", None)
        if expected_launcher_binding is not None and launcher_binding != expected_launcher_binding:
            raise ValueError("completion proof launcher trust binding mismatch")
        if binding.get("proxy_proof_max_age_seconds") != expected.proxy_proof_max_age_seconds:
            raise ValueError("completion proof proxy max-age policy mismatch")
        if binding.get("p99_limit_ms") != expected.p99_limit_ms:
            raise ValueError("completion proof p99 policy mismatch")
        if binding.get("docker_executable") != expected.docker_executable:
            raise ValueError("completion proof Docker executable mismatch")
        if is_final:
            for field, attribute in (
                ("docker_compose_plugin_executable", "docker_compose_plugin_executable"),
                ("docker_compose_plugin_sha256", "docker_compose_plugin_sha256"),
                ("docker_unix_socket", "docker_unix_socket"),
                ("docker_daemon_id", "docker_daemon_id"),
                (
                    "docker_compose_project_name",
                    "docker_compose_project_name",
                ),
                (
                    "production_host_preflight_signing_public_key",
                    "production_host_preflight_signing_public_key",
                ),
                (
                    "production_host_preflight_signing_key_id",
                    "production_host_preflight_signing_key_id",
                ),
                (
                    "production_host_preflight_max_age_seconds",
                    "production_host_preflight_max_age_seconds",
                ),
                ("policy_trusted_public_key_id", "policy_trusted_public_key_id"),
                (
                    "policy_activation_trusted_public_key_id",
                    "policy_activation_trusted_public_key_id",
                ),
                (
                    "reproducible_build_trusted_public_key_id",
                    "reproducible_build_trusted_public_key_id",
                ),
            ):
                if binding.get(field) != getattr(expected, attribute):
                    raise ValueError(f"completion proof production binding mismatch: {field}")
            running = proof["running_production_containers"]
            if (
                running.get("compose_plugin_executable")
                != expected.docker_compose_plugin_executable
                or running.get("compose_plugin_sha256")
                != expected.docker_compose_plugin_sha256
                or running.get("docker_daemon_before")
                != running.get("docker_daemon_after")
                or (running.get("docker_daemon_after") or {}).get("daemon_id")
                != expected.docker_daemon_id
                or nested_socket_path(running.get("docker_daemon_after"))
                != expected.docker_unix_socket
                or running.get("compose_project_name")
                != expected.docker_compose_project_name
            ):
                raise ValueError("completion proof Docker renderer or stable daemon binding mismatch")
            generation_before = running.get("service_generation_before")
            generation_after = running.get("service_generation_after")
            expected_services = set(FINAL_SERVICE_USERS)
            if (
                not isinstance(generation_before, dict)
                or set(generation_before) != expected_services
                or generation_before != generation_after
            ):
                raise ValueError(
                    "completion proof did not retain one stable complete Compose service generation"
                )
            for service, generation_entry in generation_before.items():
                if (
                    not isinstance(generation_entry, dict)
                    or re.fullmatch(
                        r"[0-9a-f]{64}", str(generation_entry.get("container_id"))
                    )
                    is None
                    or not isinstance(generation_entry.get("started_at"), str)
                    or not generation_entry["started_at"]
                    or SHA256_RE.fullmatch(str(generation_entry.get("image_id")))
                    is None
                    or not isinstance(generation_entry.get("runtime_projection"), dict)
                    or not generation_entry["runtime_projection"]
                ):
                    raise ValueError(
                        f"completion proof has an invalid live generation entry for {service}"
                    )
            preflight_runtime_model = proof["production_host_preflight"].get(
                "production_runtime_model"
            )
            if (
                not isinstance(preflight_runtime_model, dict)
                or running.get("runtime_model_sha256")
                != preflight_runtime_model.get("sha256")
            ):
                raise ValueError(
                    "completion proof live runtime projection is not bound to the signed preflight model"
                )
            container_summaries = running.get("containers")
            if (
                not isinstance(container_summaries, list)
                or {item.get("service") for item in container_summaries if isinstance(item, dict)}
                != expected_services
            ):
                raise ValueError("completion proof live container summary set is incomplete")
            for item in container_summaries:
                service = item.get("service")
                if (
                    item.get("container_id")
                    != generation_before[service]["container_id"]
                    or item.get("started_at")
                    != generation_before[service]["started_at"]
                    or item.get("runtime_projection")
                    != generation_before[service]["runtime_projection"]
                ):
                    raise ValueError(
                        f"completion proof live container summary changed generation for {service}"
                    )
                namespace_artifacts = item.get("container_namespace_artifacts")
                expected_artifact_destinations = (
                    {
                        "/run/serverware/release/release-provenance.json",
                        "/run/serverware/release/image-signatures.json",
                    }
                    if service in {"serverware", "decision-gate-rs"}
                    else set()
                )
                if (
                    not isinstance(namespace_artifacts, dict)
                    or set(namespace_artifacts) != expected_artifact_destinations
                    or any(
                        not isinstance(report, dict)
                        or report.get("container_namespace_verified") is not True
                        or report.get("regular_file") is not True
                        or report.get("tar_members") != 1
                        or SHA256_RE.fullmatch(str(report.get("sha256"))) is None
                        or not isinstance(report.get("bytes"), int)
                        or report["bytes"] <= 0
                        for report in namespace_artifacts.values()
                    )
                ):
                    raise ValueError(
                        f"completion proof lacks exact container-namespace artifact evidence for {service}"
                    )
                for destination, artifact_label in (
                    (
                        "/run/serverware/release/release-provenance.json",
                        "release_provenance",
                    ),
                    (
                        "/run/serverware/release/image-signatures.json",
                        "image_signatures",
                    ),
                ):
                    if destination in namespace_artifacts and (
                        namespace_artifacts[destination].get("sha256")
                        != (artifacts.get(artifact_label) or {}).get("sha256")
                    ):
                        raise ValueError(
                            f"completion proof container-visible {artifact_label} differs from the approved snapshot"
                        )
        expected_nonce_digest = sha256_prefixed_base64url(
            expected.proxy_client_nonce,
            "runner proxy client nonce",
        )
        if proxy.get("client_nonce_sha256") != expected_nonce_digest:
            raise ValueError("completion proof proxy nonce does not bind the current runner challenge")
        expected_channel_digest = "sha256:" + hashlib.sha256(
            canonical_json(
                {"type": "tls-exporter", "value": expected.proxy_tls_channel_binding}
            ).encode("utf-8")
        ).hexdigest()
        if proxy.get("tls_channel_binding_sha256") != expected_channel_digest:
            raise ValueError("completion proof TLS channel binding does not match the current collector result")
        collector_proof_digest = getattr(expected, "collected_proxy_proof_sha256", None)
        proxy_artifact = artifacts.get("proxy_response_proof")
        if collector_proof_digest is None or proxy_artifact.get("sha256") != collector_proof_digest:
            raise ValueError("completion proof does not bind the exact collector proof bytes")
        collector_contract = getattr(expected, "collector_proof_contract", None)
        if is_final:
            if not isinstance(collector_contract, dict):
                raise ValueError("runner did not retain the current collector proof contract")
            for field in (
                "server_statement_sha256",
                "captured_at_unix",
                "issued_at_unix",
                "client_nonce_sha256",
                "tls_channel_binding_sha256",
            ):
                if proxy.get(field) != collector_contract.get(field):
                    raise ValueError(f"completion proof {field} differs from the current collector proof")
        maximum_age = expected.proxy_proof_max_age_seconds
        now = int(time.time())
        for timestamp_field in ("captured_at_unix", "issued_at_unix"):
            timestamp = proxy.get(timestamp_field)
            if not isinstance(timestamp, int) or timestamp > now + COMPLETION_PROOF_FUTURE_SKEW_SECONDS:
                raise ValueError(f"completion proof proxy {timestamp_field} is invalid")
            if now - timestamp > maximum_age or timestamp < expected.runner_started_at_unix - maximum_age:
                raise ValueError(f"completion proof proxy {timestamp_field} is stale")
    return actual_digest


def parse_env_assignment(raw: str, lineno: int) -> tuple[str, str] | None:
    stripped = raw.strip()
    if not stripped or stripped.startswith("#"):
        return None
    if stripped.startswith("export "):
        stripped = stripped[len("export ") :].lstrip()
    lexer = shlex.shlex(stripped, posix=True)
    lexer.whitespace_split = True
    lexer.commenters = "#"
    try:
        tokens = list(lexer)
    except ValueError as exc:
        raise ValueError(f"line {lineno}: invalid shell-style quoting: {exc}") from exc
    if len(tokens) != 1 or "=" not in tokens[0]:
        raise ValueError(f"line {lineno}: expected KEY=value assignment")
    key, value = tokens[0].split("=", 1)
    if not KEY_RE.fullmatch(key):
        raise ValueError(f"line {lineno}: invalid environment key {key!r}")
    if value == "":
        raise ValueError(f"line {lineno}: {key} must not be empty")
    return key, value


def load_env_bytes(data: bytes, path: Path) -> dict[str, str]:
    loaded: dict[str, str] = {}
    try:
        text_value = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"production readiness env file is not valid UTF-8: {path}") from exc
    for lineno, raw in enumerate(text_value.splitlines(), start=1):
        parsed = parse_env_assignment(raw, lineno)
        if parsed is None:
            continue
        key, value = parsed
        if key in loaded:
            raise ValueError(f"line {lineno}: duplicate environment key {key}")
        if PLACEHOLDER_RE.search(value):
            raise ValueError(f"line {lineno}: {key} still contains a placeholder value")
        if EXAMPLE_DOMAIN_RE.search(value):
            raise ValueError(f"line {lineno}: {key} still contains an example placeholder domain")
        loaded[key] = value
    if not loaded:
        raise ValueError(f"production readiness env file is empty: {path}")
    return loaded


def load_env_file_snapshot(path: Path) -> tuple[dict[str, str], bytes, os.stat_result]:
    data, metadata = read_regular_file_once(
        path,
        "production readiness env",
        max_bytes=MAX_PRODUCTION_ENV_BYTES,
    )
    return load_env_bytes(data, path), data, metadata


def load_env_file(path: Path) -> dict[str, str]:
    loaded, _, _ = load_env_file_snapshot(path)
    return loaded


def validate_proxy_proof_policy_consistency(
    policy_bundle_path: Path,
    *,
    agent_id: str,
    principal_id: str,
    proof_url: str,
) -> None:
    from serverware.policy_bundle import compile_policy_bundle, strict_json_loads

    try:
        bundle = strict_json_loads(policy_bundle_path.read_bytes())
        if not isinstance(bundle, dict):
            raise ValueError("policy bundle must be a JSON object")
        policy = compile_policy_bundle(
            bundle,
            validate_schema=False,
            verify_signature=False,
        )
    except Exception as exc:
        raise ValueError(
            f"exact --policy-bundle JSON could not be compiled: {exc}"
        ) from exc

    mapped_principals = []
    for principal in policy.principals.values():
        expected_agent_ids = [
            value
            for name, value in principal.required_headers.items()
            if name.lower() == "x-serverware-agent"
        ]
        if expected_agent_ids and all(value == agent_id for value in expected_agent_ids):
            mapped_principals.append(principal.id)
    if mapped_principals != [principal_id]:
        raise ValueError(
            "SERVERWARE_PROXY_PROOF_AGENT_ID and SERVERWARE_PROXY_PROOF_PRINCIPAL_ID "
            "do not map to the same unique principal in the exact --policy-bundle JSON"
        )

    try:
        parsed_url = urlsplit(proof_url)
        proof_host = parsed_url.hostname
        proof_port = parsed_url.port
    except ValueError as exc:
        raise ValueError("SERVERWARE_PROXY_PROOF_URL is invalid") from exc
    if (
        not parsed_url.scheme
        or not proof_host
        or parsed_url.username is not None
        or parsed_url.password is not None
        or parsed_url.fragment
    ):
        raise ValueError("SERVERWARE_PROXY_PROOF_URL is invalid")
    if proof_port is None:
        proof_port = 443 if parsed_url.scheme.lower() == "https" else 80
    proof_path = parsed_url.path or "/"
    matched = policy.match_route(
        parsed_url.scheme,
        proof_host,
        proof_port,
        "GET",
        proof_path,
        principal_id,
    )
    if matched is None:
        raise ValueError(
            "SERVERWARE_PROXY_PROOF_PRINCIPAL_ID is not authorized for the GET proof URL "
            "scheme, host, port, and path in the exact --policy-bundle JSON"
        )


def generated_client_nonce() -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode("ascii")


def collector_command(args: argparse.Namespace) -> dict[str, Any]:
    command = shlex.split(args.proxy_proof_collector_command)
    if not command:
        raise ValueError("proxy proof collector command is empty")
    argv = [
        *command,
        "--proxy",
        args.proxy_address,
        "--url",
        args.proxy_proof_url,
        "--ca",
        args.proxy_proof_ca,
        "--out",
        args.proxy_response_proof,
        "--collector-key",
        args.proxy_collector_key,
        "--verifier-key",
        args.proxy_proof_verifier_public_key,
        "--expected-server-instance-id",
        args.proxy_server_instance_id,
        "--expected-principal-id",
        args.proxy_principal_id,
        "--max-age-seconds",
        str(args.proxy_proof_max_age_seconds),
        "--nonce",
        args.proxy_client_nonce,
    ]
    if args.proxy_agent_id:
        agent_header = f"X-Serverware-Agent: {args.proxy_agent_id}"
        argv.extend(["--proxy-header", agent_header, "--header", agent_header])
    return {"label": "collect-production-proxy-response-proof", "argv": argv}


def completion_command(args: argparse.Namespace) -> dict[str, Any]:
    command = {
        "label": "verify-release-completion",
        "argv": [
            args.python,
            "scripts/verify_release_completion.py",
            "--verification-mode",
            args.verification_mode,
            "--production-readiness",
            str(Path(args.readiness_out)),
            "--production-readiness-config",
            str(Path(args.config_out)),
            "--production-readiness-env",
            args.env_file,
            "--launcher-trusted-production-env-path",
            args.launcher_trusted_production_env_path,
            "--launcher-trusted-production-env-sha256",
            args.launcher_trusted_production_env_sha256,
            "--docker-executable",
            args.docker_executable,
            "--docker-compose-plugin-executable",
            args.docker_compose_plugin_executable,
            "--docker-unix-socket",
            args.docker_unix_socket,
            "--docker-daemon-id",
            args.docker_daemon_id,
            "--compose-file",
            args.compose_file,
            "--production-host-preflight",
            args.production_host_preflight,
            "--production-host-preflight-signing-public-key",
            args.production_host_preflight_signing_public_key,
            "--production-host-preflight-signing-key-id",
            args.production_host_preflight_signing_key_id,
            "--production-host-preflight-max-age-seconds",
            str(args.production_host_preflight_max_age_seconds),
            "--nitro-evidence",
            str(Path(args.nitro_evidence_out)),
            "--production-images-build",
            args.production_images_build,
            "--production-images-env",
            args.production_images_env,
            "--production-images-published",
            args.production_images_published,
            "--release-provenance-summary",
            args.release_provenance_summary,
            "--release-provenance",
            args.release_provenance,
            "--release-provenance-trusted-public-key",
            args.release_provenance_trusted_public_key,
            "--image-signatures-summary",
            args.image_signatures_summary,
            "--image-signatures",
            args.image_signatures,
            "--sigstore-trusted-public-key",
            args.sigstore_trusted_public_key,
            "--rekor-trusted-public-key",
            args.rekor_trusted_public_key,
            "--external-checkpoint-provider",
            args.external_checkpoint_provider,
            "--external-checkpoint-trusted-public-key",
            args.external_checkpoint_trusted_public_key,
            "--bench",
            args.bench,
            "--policy-bundle",
            args.policy_bundle,
            "--policy-trusted-public-key",
            args.policy_trusted_public_key,
            "--policy-trusted-public-key-id",
            args.policy_trusted_public_key_id,
            "--policy-identity-verification",
            args.policy_identity_verification,
            "--policy-activation-verification",
            args.policy_activation_verification,
            "--policy-activation-signature",
            args.policy_activation_signature,
            "--policy-activation-trusted-public-key",
            args.policy_activation_trusted_public_key,
            "--policy-activation-trusted-public-key-id",
            args.policy_activation_trusted_public_key_id,
            "--reproducible-build-verification",
            args.reproducible_build_verification,
            "--reproducible-build-signature",
            args.reproducible_build_signature,
            "--reproducible-build-trusted-public-key",
            args.reproducible_build_trusted_public_key,
            "--reproducible-build-trusted-public-key-id",
            args.reproducible_build_trusted_public_key_id,
            "--kms-materials",
            args.kms_materials,
            "--control-plane-response-signing-public-key",
            args.control_plane_response_signing_public_key,
            "--control-plane-response-signing-public-key-id",
            args.control_plane_response_signing_public_key_id,
            "--proxy-response-proof",
            args.proxy_response_proof,
            "--proxy-proof-verifier-public-key",
            args.proxy_proof_verifier_public_key,
            "--proxy-collector-public-key",
            args.proxy_collector_public_key,
            "--proxy-server-instance-id",
            args.proxy_server_instance_id,
            "--proxy-client-nonce",
            args.proxy_client_nonce,
            "--proxy-client-request-digest",
            args.proxy_client_request_digest,
            "--proxy-request-digest",
            args.proxy_request_digest,
            "--proxy-operation-digest",
            args.proxy_operation_digest,
            "--proxy-tls-channel-binding",
            args.proxy_tls_channel_binding,
            "--proxy-proof-max-age-seconds",
            str(args.proxy_proof_max_age_seconds),
            "--p99-limit-ms",
            str(args.p99_limit_ms),
            "--out",
            str(Path(args.completion_proof_out)),
        ],
    }
    if args.verification_mode == "final":
        command["argv"].extend(
            [
                "--hardware-assurance",
                args.hardware_assurance,
                "--hardware-assurance-trusted-public-key",
                args.hardware_assurance_trusted_public_key,
                "--hardware-assurance-trusted-public-key-id",
                args.hardware_assurance_trusted_public_key_id,
                "--final-challenge-receipt",
                args.final_challenge_receipt,
                "--final-challenge-authority-public-key",
                args.final_challenge_authority_public_key,
                "--final-challenge-authority-public-key-id",
                args.final_challenge_authority_public_key_id,
                "--final-challenge-authority-provider",
                args.final_challenge_authority_provider,
            ]
        )
        if args.hardware_assurance_expected_challenge_nonce:
            command["argv"].extend(
                [
                    "--hardware-assurance-expected-challenge-nonce",
                    args.hardware_assurance_expected_challenge_nonce,
                ]
            )
        else:
            command["argv"].extend(
                [
                    "--hardware-assurance-expected-challenge-nonce-sha256",
                    args.hardware_assurance_expected_challenge_nonce_sha256,
                ]
            )
    return command


def command_plan(args: argparse.Namespace) -> list[dict[str, Any]]:
    python = args.python
    config_out = str(Path(args.config_out))
    claims_file = str(Path(args.claims_file))
    nitro_evidence_out = str(Path(args.nitro_evidence_out))
    readiness_out = str(Path(args.readiness_out))

    commands: list[dict[str, Any]] = [
        {
            "label": "verify-production-config",
            "argv": [
                python,
                "scripts/verify_production_readiness.py",
                "--mode",
                "config",
                "--expected-control-plane-uid",
                str(args.expected_control_plane_uid),
                "--expected-control-plane-gid",
                str(args.expected_control_plane_gid),
                "--out",
                config_out,
            ],
        }
    ]
    if args.config_only:
        return commands
    if not args.use_existing_claims:
        commands.append(
            {
                "label": "generate-production-readiness-claims",
                "argv": [
                    python,
                    "scripts/generate_production_readiness_claims.py",
                    "--out",
                    claims_file,
                    *args.claims_args,
                ],
            }
        )
    commands.extend(
        [
            {
                "label": "collect-nitro-kms-evidence",
                "argv": [
                    python,
                    "scripts/collect_nitro_kms_evidence.py",
                    "--claims-file",
                    claims_file,
                    "--out",
                    nitro_evidence_out,
                ],
            },
            {
                "label": "verify-production-readiness",
                "argv": [
                    python,
                    "scripts/verify_production_readiness.py",
                    "--mode",
                    "live",
                    "--expected-control-plane-uid",
                    str(args.expected_control_plane_uid),
                    "--expected-control-plane-gid",
                    str(args.expected_control_plane_gid),
                    "--claims-file",
                    claims_file,
                    "--nitro-evidence-file",
                    nitro_evidence_out,
                    "--out",
                    readiness_out,
                ],
            },
            collector_command(args),
            completion_command(args),
        ]
    )
    return commands


def remeasure_command_before_use(
    argv: list[str],
    executable_pins: dict[str, tuple[str, str]] | None,
) -> None:
    if not executable_pins or not argv:
        return
    selected = executable_pins.get(os.path.abspath(argv[0]))
    if selected is None:
        return
    setting, expected_digest = selected
    remeasure_executable(Path(argv[0]), expected_digest, setting)


def run_command_with_optional_pin(
    argv: list[str],
    executable_pins: dict[str, tuple[str, str]] | None,
    *,
    script_digest_pins: dict[str, tuple[str, str]] | None = None,
    isolated_python: bool = False,
    **kwargs: Any,
) -> subprocess.CompletedProcess[Any]:
    selected = executable_pins.get(os.path.abspath(argv[0])) if executable_pins and argv else None
    if isolated_python and selected is not None and len(argv) >= 2 and argv[1].endswith(".py"):
        script_path = Path(argv[1])
        if not script_path.is_absolute():
            script_path = (Path(kwargs.get("cwd") or os.getcwd()) / script_path).resolve()
        script_pin = (script_digest_pins or {}).get(str(script_path))
        script_setting = script_pin[0] if script_pin else f"one-open Python script {script_path.name}"
        script_digest = script_pin[1] if script_pin else None
        return run_measured_python_script(
            argv,
            python_setting=selected[0],
            python_expected_digest=selected[1],
            script_setting=script_setting,
            script_expected_digest=script_digest,
            **kwargs,
        )
    if selected is None:
        return subprocess.run(argv, **kwargs)
    setting, expected_digest = selected
    return run_measured_command(
        argv,
        setting=setting,
        expected_digest=expected_digest,
        **kwargs,
    )


def run_commands(
    commands: list[dict[str, Any]],
    env: dict[str, str],
    *,
    executable_pins: dict[str, tuple[str, str]] | None = None,
    script_digest_pins: dict[str, tuple[str, str]] | None = None,
    isolated_python: bool = False,
) -> None:
    for command in commands:
        label = command["label"]
        argv = command["argv"]
        print(f"==> {label}", file=sys.stderr)
        result = run_command_with_optional_pin(
            argv,
            executable_pins,
            script_digest_pins=script_digest_pins,
            isolated_python=isolated_python,
            cwd=ROOT,
            env=env,
            check=False,
        )
        if result.returncode != 0:
            raise SystemExit(result.returncode)


def write_private_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    payload = (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode("utf-8")
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    finally:
        temporary.unlink(missing_ok=True)


def run_collector(command: dict[str, Any], args: argparse.Namespace, env: dict[str, str]) -> dict[str, Any]:
    expected_digests = {
        "client_request_digest": args.proxy_client_request_digest,
        "request_digest": args.proxy_request_digest,
        "operation_digest": args.proxy_operation_digest,
    }
    for field, expected_digest in expected_digests.items():
        if not isinstance(expected_digest, str) or SHA256_RE.fullmatch(expected_digest) is None:
            raise ValueError(
                f"independent expected proxy {field} pin must be sha256:<64 lowercase hex> before collection"
            )
    print(f"==> {command['label']}", file=sys.stderr)
    result = run_command_with_optional_pin(
        command["argv"],
        getattr(args, "pre_use_executable_pins", None),
        script_digest_pins=getattr(args, "script_digest_pins", None),
        isolated_python=getattr(args, "verification_mode", None) == "final",
        cwd=ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=120,
        check=False,
    )
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        print(f"production proxy response proof collection failed: {detail}", file=sys.stderr)
        raise SystemExit(result.returncode)
    try:
        summary = json.loads(result.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("production proxy response proof collector returned invalid JSON") from exc
    if not isinstance(summary, dict) or summary.get("ok") is not True:
        raise ValueError("production proxy response proof collector did not return ok=true")
    if summary.get("client_nonce") != args.proxy_client_nonce:
        raise ValueError("production proxy response proof collector did not bind the runner challenge")
    for field, expected_digest in expected_digests.items():
        value = summary.get(field)
        if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
            raise ValueError(f"production proxy response proof collector returned an invalid {field}")
        if not hmac.compare_digest(value, expected_digest):
            raise ValueError(
                f"production proxy response proof collector {field} does not match the independent expected pin"
            )
    tls_binding = summary.get("tls_channel_binding")
    if not isinstance(tls_binding, str) or len(tls_binding) < 43:
        raise ValueError("production proxy response proof collector returned an invalid TLS channel binding")
    if summary.get("server_instance_id") != args.proxy_server_instance_id:
        raise ValueError("production proxy response proof collector reached an unexpected server instance")
    expected_proof_path = str(Path(args.proxy_response_proof))
    if summary.get("proof_path") != expected_proof_path:
        raise ValueError("production proxy response proof collector wrote an unexpected proof path")
    proof_path = Path(args.proxy_response_proof)
    proof_bytes, _ = read_regular_file_once(
        proof_path,
        "production proxy response proof",
        max_bytes=MAX_COMPLETION_PROOF_BYTES,
    )
    proof_digest = "sha256:" + hashlib.sha256(proof_bytes).hexdigest()
    if summary.get("proof_sha256") != proof_digest:
        raise ValueError("production proxy response proof collector summary does not bind the proof artifact")
    args.collected_proxy_proof_sha256 = proof_digest
    if getattr(args, "verification_mode", None) == "final":
        try:
            proof_document = json.loads(proof_bytes.decode("utf-8"))
            external_capture = proof_document["external_capture"]
            server_statement = proof_document["server_statement"]
            tls_channel_binding = external_capture["tls_channel_binding"]
            nonce = external_capture["client_nonce"]
            args.collector_proof_contract = {
                "server_statement_sha256": "sha256:"
                + hashlib.sha256(canonical_json(server_statement).encode("utf-8")).hexdigest(),
                "captured_at_unix": external_capture["captured_at_unix"],
                "issued_at_unix": server_statement["issued_at_unix"],
                "client_nonce_sha256": sha256_prefixed_base64url(nonce, "collector proof client nonce"),
                "tls_channel_binding_sha256": "sha256:"
                + hashlib.sha256(canonical_json(tls_channel_binding).encode("utf-8")).hexdigest(),
            }
        except (KeyError, TypeError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("production proxy response proof does not contain the final collector contract") from exc
    args.collector_summary = summary
    write_private_json(Path(args.proxy_proof_summary_out), summary)
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description="Run Serverware's production readiness gates from a strict env file.")
    parser.add_argument("--env-file", default=os.getenv("PRODUCTION_READINESS_ENV", "ops/production-readiness.env"))
    parser.add_argument("--compose-file", default="docker-compose.production.yml")
    parser.add_argument("--python", default=None)
    parser.add_argument("--docker-executable", default=None)
    parser.add_argument("--docker-compose-plugin-executable", default=None)
    parser.add_argument("--docker-unix-socket", default=None)
    parser.add_argument("--docker-daemon-id", default=None)
    parser.add_argument(
        "--launcher-trusted-production-env-path",
        default=os.getenv(LAUNCHER_TRUSTED_ENV_PATH_INPUT),
    )
    parser.add_argument(
        "--launcher-trusted-production-env-sha256",
        default=os.getenv(LAUNCHER_TRUSTED_ENV_SHA256_INPUT),
    )
    parser.add_argument("--expected-control-plane-uid", type=int, default=65532)
    parser.add_argument("--expected-control-plane-gid", type=int, default=65532)
    parser.add_argument("--config-out", default=".tmp/production-readiness-config.json")
    parser.add_argument("--claims-file", default=".tmp/production-readiness-claims.json")
    parser.add_argument("--nitro-evidence-out", default=".tmp/nitro-kms-evidence.json")
    parser.add_argument("--readiness-out", default=".tmp/production-readiness.json")
    parser.add_argument("--completion-proof-out", default=".tmp/serverware-completion-proof.json")
    parser.add_argument("--production-host-preflight", default=".tmp/production-host-preflight.json")
    parser.add_argument("--production-host-preflight-signing-public-key", default=None)
    parser.add_argument("--production-host-preflight-signing-key-id", default=None)
    parser.add_argument("--production-host-preflight-max-age-seconds", type=int, default=None)
    parser.add_argument("--production-images-build", default=".tmp/production-images-build.json")
    parser.add_argument("--production-images-env", default=".tmp/production-images.env")
    parser.add_argument("--production-images-published", default=".tmp/production-images-published.json")
    parser.add_argument("--release-provenance-summary", default=".tmp/release-provenance-summary.json")
    parser.add_argument("--release-provenance", default=".tmp/release-provenance.json")
    parser.add_argument("--release-provenance-trusted-public-key", default=None)
    parser.add_argument("--image-signatures-summary", default=".tmp/image-signatures-summary.json")
    parser.add_argument("--image-signatures", default=".tmp/image-signatures.json")
    parser.add_argument("--sigstore-trusted-public-key", default=None)
    parser.add_argument("--rekor-trusted-public-key", default=None)
    parser.add_argument("--external-checkpoint-provider", default=None)
    parser.add_argument("--external-checkpoint-trusted-public-key", default=None)
    parser.add_argument("--verification-mode", choices=("readiness", "final"), default="readiness")
    parser.add_argument("--hardware-assurance", default=None)
    parser.add_argument("--hardware-assurance-trusted-public-key", default=None)
    parser.add_argument("--hardware-assurance-trusted-public-key-id", default=None)
    parser.add_argument("--hardware-assurance-expected-challenge-nonce", default=None)
    parser.add_argument("--hardware-assurance-expected-challenge-nonce-sha256", default=None)
    parser.add_argument("--final-challenge-receipt", default=None)
    parser.add_argument("--final-challenge-authority-public-key", default=None)
    parser.add_argument("--final-challenge-authority-public-key-id", default=None)
    parser.add_argument("--final-challenge-authority-provider", default=None)
    parser.add_argument("--bench", default=".tmp/decision-gate-rs-bench.json")
    parser.add_argument("--policy-bundle", required=True)
    parser.add_argument("--policy-trusted-public-key", required=True)
    parser.add_argument("--policy-trusted-public-key-id", default=None)
    parser.add_argument("--policy-identity-verification", required=True)
    parser.add_argument("--policy-activation-verification", required=True)
    parser.add_argument("--policy-activation-signature", required=True)
    parser.add_argument("--policy-activation-trusted-public-key", required=True)
    parser.add_argument("--policy-activation-trusted-public-key-id", default=None)
    parser.add_argument("--reproducible-build-verification", required=True)
    parser.add_argument("--reproducible-build-signature", required=True)
    parser.add_argument("--reproducible-build-trusted-public-key", required=True)
    parser.add_argument("--reproducible-build-trusted-public-key-id", default=None)
    parser.add_argument("--kms-materials", default="/etc/serverware/kms-materials.json")
    parser.add_argument(
        "--control-plane-response-signing-public-key",
        default=None,
    )
    parser.add_argument(
        "--control-plane-response-signing-public-key-id",
        default=None,
    )
    parser.add_argument("--proxy-response-proof", default=None)
    parser.add_argument("--proxy-proof-summary-out", default=".tmp/proxy-response-proof-summary.json")
    parser.add_argument("--proxy-proof-collector-command", default=None)
    parser.add_argument("--proxy-address", default=None)
    parser.add_argument("--proxy-proof-url", default=None)
    parser.add_argument("--proxy-proof-ca", default=None)
    parser.add_argument("--proxy-collector-key", default=None)
    parser.add_argument("--proxy-collector-public-key", default=None)
    parser.add_argument("--proxy-proof-verifier-public-key", default=None)
    parser.add_argument("--proxy-server-instance-id", default=None)
    parser.add_argument("--proxy-agent-id", default=None)
    parser.add_argument("--proxy-principal-id", default=None)
    parser.add_argument("--proxy-client-request-digest", default=None)
    parser.add_argument("--proxy-request-digest", default=None)
    parser.add_argument("--proxy-operation-digest", default=None)
    parser.add_argument("--proxy-proof-max-age-seconds", type=int, default=None)
    parser.add_argument("--p99-limit-ms", type=float, default=None)
    parser.add_argument("--control-plane-base", default=None)
    parser.add_argument("--control-plane-ca-bundle", default=None)
    parser.add_argument("--config-only", action="store_true")
    parser.add_argument("--use-existing-claims", action="store_true")
    parser.add_argument("--dry-run", action="store_true", help="load and validate the env file, then print the command plan")
    parser.add_argument(
        "--claims-arg",
        dest="claims_args",
        action="append",
        default=[],
        help="extra argument to pass through to generate_production_readiness_claims.py; repeat as needed",
    )
    args = parser.parse_args()
    args.runner_started_at_unix = int(time.time())
    if args.verification_mode == "final" and not args.dry_run and not sys.platform.startswith("linux"):
        print("production readiness env error: final descriptor execution requires Linux", file=sys.stderr)
        raise SystemExit(1)

    env_file = Path(args.env_file)
    try:
        production_env_bytes, production_env_metadata = read_regular_file_once(
            env_file,
            "production readiness env",
            max_bytes=MAX_PRODUCTION_ENV_BYTES,
        )
        if args.verification_mode == "final":
            args.launcher_env_binding = validate_launcher_trusted_env(
                env_file,
                production_env_bytes,
                production_env_metadata,
                expected_path=args.launcher_trusted_production_env_path,
                expected_sha256=args.launcher_trusted_production_env_sha256,
            )
        else:
            args.launcher_env_binding = None
            args.launcher_trusted_production_env_path = str(env_file)
            args.launcher_trusted_production_env_sha256 = (
                "sha256:" + hashlib.sha256(production_env_bytes).hexdigest()
            )
        loaded = load_env_bytes(production_env_bytes, env_file)
        if LAUNCHER_TRUST_INPUT_NAMES & set(loaded):
            raise ValueError("out-of-band launcher trust inputs must not be defined inside the production env")
    except Exception as exc:
        print(f"production readiness env error: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc

    env_verification_mode = loaded.get("SERVERWARE_COMPLETION_VERIFICATION_MODE")
    if env_verification_mode and env_verification_mode not in {"readiness", "final"}:
        print(
            "production readiness env error: SERVERWARE_COMPLETION_VERIFICATION_MODE must be readiness or final",
            file=sys.stderr,
        )
        raise SystemExit(1)
    if args.verification_mode == "final" and env_verification_mode is None:
        print(
            "production readiness env error: final verification mode must be pinned as "
            "SERVERWARE_COMPLETION_VERIFICATION_MODE=final in the production readiness env file",
            file=sys.stderr,
        )
        raise SystemExit(1)
    if env_verification_mode and env_verification_mode != args.verification_mode:
        print(
            "production readiness env error: --verification-mode must match "
            "SERVERWARE_COMPLETION_VERIFICATION_MODE in the production readiness env file",
            file=sys.stderr,
        )
        raise SystemExit(1)
    if args.verification_mode == "final":
        try:
            args.launcher_env_binding["startup_environment_contract"] = (
                validate_final_launcher_contract(loaded)
            )
        except ValueError as exc:
            print(f"production readiness env error: {exc}", file=sys.stderr)
            raise SystemExit(1) from exc
        if (
            args.expected_control_plane_uid != FINAL_CONTROL_PLANE_UID
            or args.expected_control_plane_gid != FINAL_CONTROL_PLANE_GID
        ):
            print(
                "production readiness env error: final control-plane UID/GID are fixed at "
                f"{FINAL_CONTROL_PLANE_UID}:{FINAL_CONTROL_PLANE_GID}",
                file=sys.stderr,
            )
            raise SystemExit(1)

    supplied_python = args.python
    env_python = loaded.get(PRODUCTION_PYTHON_EXECUTABLE_ENV)
    if args.verification_mode == "final":
        if not env_python:
            print(
                f"production readiness env error: {PRODUCTION_PYTHON_EXECUTABLE_ENV} must be pinned in final mode",
                file=sys.stderr,
            )
            raise SystemExit(1)
        if supplied_python is not None and supplied_python != env_python:
            print(
                f"production readiness env error: --python must match {PRODUCTION_PYTHON_EXECUTABLE_ENV} "
                "in final verification mode",
                file=sys.stderr,
            )
            raise SystemExit(1)
        args.python = env_python
    else:
        args.python = supplied_python or env_python or sys.executable
    if not Path(args.python).is_absolute():
        print("production readiness env error: production Python executable must be absolute", file=sys.stderr)
        raise SystemExit(1)

    supplied_docker = args.docker_executable
    env_docker = loaded.get(PRODUCTION_DOCKER_EXECUTABLE_ENV)
    if args.verification_mode == "final":
        if not env_docker:
            print(
                f"production readiness env error: {PRODUCTION_DOCKER_EXECUTABLE_ENV} must be pinned in final mode",
                file=sys.stderr,
            )
            raise SystemExit(1)
        if supplied_docker is not None and supplied_docker != env_docker:
            print(
                f"production readiness env error: --docker-executable must match {PRODUCTION_DOCKER_EXECUTABLE_ENV} "
                "in final verification mode",
                file=sys.stderr,
            )
            raise SystemExit(1)
        args.docker_executable = env_docker
    else:
        args.docker_executable = supplied_docker or env_docker or "/usr/bin/docker"
    if not Path(args.docker_executable).is_absolute():
        print("production readiness env error: Docker executable must be absolute", file=sys.stderr)
        raise SystemExit(1)

    if args.verification_mode == "final":
        try:
            docker_toolchain = validate_docker_toolchain_settings(loaded)
        except ValueError as exc:
            print(f"production readiness env error: {exc}", file=sys.stderr)
            raise SystemExit(1) from exc
        for attribute, setting in (
            ("docker_compose_plugin_executable", DOCKER_COMPOSE_PLUGIN_EXECUTABLE_ENV),
            ("docker_unix_socket", DOCKER_UNIX_SOCKET_ENV),
            ("docker_daemon_id", DOCKER_DAEMON_ID_ENV),
        ):
            supplied = getattr(args, attribute)
            expected_value = docker_toolchain[setting]
            if supplied is not None and supplied != expected_value:
                print(
                    f"production readiness env error: --{attribute.replace('_', '-')} must match {setting} "
                    "in final verification mode",
                    file=sys.stderr,
                )
                raise SystemExit(1)
            setattr(args, attribute, expected_value)
        args.docker_compose_plugin_sha256 = docker_toolchain[
            DOCKER_COMPOSE_PLUGIN_SHA256_ENV
        ]
        args.docker_compose_project_name = docker_toolchain[
            DOCKER_COMPOSE_PROJECT_NAME_ENV
        ]
        if args.docker_unix_socket != "/run/docker.sock":
            print(
                f"production readiness env error: {DOCKER_UNIX_SOCKET_ENV} must be exactly /run/docker.sock in final mode",
                file=sys.stderr,
            )
            raise SystemExit(1)
    else:
        args.docker_compose_plugin_executable = (
            args.docker_compose_plugin_executable
            or loaded.get(DOCKER_COMPOSE_PLUGIN_EXECUTABLE_ENV)
            or "/usr/libexec/docker/cli-plugins/docker-compose"
        )
        args.docker_unix_socket = (
            args.docker_unix_socket
            or loaded.get(DOCKER_UNIX_SOCKET_ENV)
            or "/var/run/docker.sock"
        )
        args.docker_daemon_id = args.docker_daemon_id or loaded.get(DOCKER_DAEMON_ID_ENV) or "readiness-unbound"
        args.docker_compose_plugin_sha256 = loaded.get(DOCKER_COMPOSE_PLUGIN_SHA256_ENV)
        args.docker_compose_project_name = loaded.get(
            DOCKER_COMPOSE_PROJECT_NAME_ENV, "readiness-unbound"
        )

    env_p99_limit = loaded.get(COMPLETION_P99_LIMIT_ENV)
    if args.verification_mode == "final" and env_p99_limit is None:
        print(
            f"production readiness env error: {COMPLETION_P99_LIMIT_ENV} must be pinned in final mode",
            file=sys.stderr,
        )
        raise SystemExit(1)
    try:
        parsed_env_p99_limit = float(env_p99_limit or "20.0")
    except ValueError as exc:
        print(f"production readiness env error: {COMPLETION_P99_LIMIT_ENV} must be numeric", file=sys.stderr)
        raise SystemExit(1) from exc
    if (
        args.verification_mode == "final"
        and args.p99_limit_ms is not None
        and args.p99_limit_ms != parsed_env_p99_limit
    ):
        print(
            f"production readiness env error: --p99-limit-ms must match {COMPLETION_P99_LIMIT_ENV} in final mode",
            file=sys.stderr,
        )
        raise SystemExit(1)
    args.p99_limit_ms = (
        parsed_env_p99_limit
        if args.verification_mode == "final" or args.p99_limit_ms is None
        else args.p99_limit_ms
    )
    if not math.isfinite(args.p99_limit_ms) or args.p99_limit_ms <= 0:
        print("production readiness env error: completion p99 limit must be finite and positive", file=sys.stderr)
        raise SystemExit(1)

    if args.verification_mode == "final":
        for attribute, setting in (
            (
                "production_host_preflight_signing_public_key",
                PRODUCTION_HOST_PREFLIGHT_SIGNING_PUBLIC_KEY_ENV,
            ),
            (
                "production_host_preflight_signing_key_id",
                PRODUCTION_HOST_PREFLIGHT_SIGNING_KEY_ID_ENV,
            ),
        ):
            supplied = getattr(args, attribute)
            pinned = loaded.get(setting)
            if not pinned:
                print(f"production readiness env error: {setting} must be pinned in final mode", file=sys.stderr)
                raise SystemExit(1)
            if supplied is not None and supplied != pinned:
                print(
                    f"production readiness env error: --{attribute.replace('_', '-')} must match {setting} "
                    "in final verification mode",
                    file=sys.stderr,
                )
                raise SystemExit(1)
            setattr(args, attribute, pinned)
        if SHA256_RE.fullmatch(args.production_host_preflight_signing_key_id) is None:
            print("production readiness env error: preflight signing key ID must be sha256:<64 lowercase hex>", file=sys.stderr)
            raise SystemExit(1)
        raw_preflight_age = loaded.get(PRODUCTION_HOST_PREFLIGHT_MAX_AGE_ENV)
        try:
            pinned_preflight_age = int(raw_preflight_age or "")
        except ValueError as exc:
            print(
                f"production readiness env error: {PRODUCTION_HOST_PREFLIGHT_MAX_AGE_ENV} must be an integer",
                file=sys.stderr,
            )
            raise SystemExit(1) from exc
        if not 1 <= pinned_preflight_age <= 900:
            print(
                f"production readiness env error: {PRODUCTION_HOST_PREFLIGHT_MAX_AGE_ENV} must be between 1 and 900",
                file=sys.stderr,
            )
            raise SystemExit(1)
        if (
            args.production_host_preflight_max_age_seconds is not None
            and args.production_host_preflight_max_age_seconds != pinned_preflight_age
        ):
            print(
                "production readiness env error: --production-host-preflight-max-age-seconds must match "
                f"{PRODUCTION_HOST_PREFLIGHT_MAX_AGE_ENV} in final verification mode",
                file=sys.stderr,
            )
            raise SystemExit(1)
        args.production_host_preflight_max_age_seconds = pinned_preflight_age
    else:
        args.production_host_preflight_signing_public_key = (
            args.production_host_preflight_signing_public_key
            or loaded.get(PRODUCTION_HOST_PREFLIGHT_SIGNING_PUBLIC_KEY_ENV)
            or loaded.get("SERVERWARE_RELEASE_PROVENANCE_TRUSTED_PUBLIC_KEY")
            or "readiness-unbound"
        )
        args.production_host_preflight_signing_key_id = (
            args.production_host_preflight_signing_key_id
            or loaded.get(PRODUCTION_HOST_PREFLIGHT_SIGNING_KEY_ID_ENV)
            or "sha256:" + "0" * 64
        )
        args.production_host_preflight_max_age_seconds = (
            args.production_host_preflight_max_age_seconds or 300
        )

    if args.verification_mode == "final":
        try:
            env = build_final_child_environment(loaded)
        except ValueError as exc:
            print(f"production readiness env error: {exc}", file=sys.stderr)
            raise SystemExit(1) from exc
    else:
        env = os.environ.copy()
        env.update(loaded)
    trust_settings = {
        "release_provenance_trusted_public_key": "SERVERWARE_RELEASE_PROVENANCE_TRUSTED_PUBLIC_KEY",
        "sigstore_trusted_public_key": "SERVERWARE_SIGSTORE_TRUSTED_PUBLIC_KEY",
        "rekor_trusted_public_key": "SERVERWARE_REKOR_TRUSTED_PUBLIC_KEY",
        "external_checkpoint_provider": "SERVERWARE_EXTERNAL_CHECKPOINT_PROVIDER",
        "external_checkpoint_trusted_public_key": "SERVERWARE_EXTERNAL_CHECKPOINT_TRUSTED_PUBLIC_KEY",
        "control_plane_response_signing_public_key": (
            "SERVERWARE_CONTROL_PLANE_RESPONSE_SIGNING_PUBLIC_KEY"
        ),
        "control_plane_response_signing_public_key_id": (
            "SERVERWARE_CONTROL_PLANE_RESPONSE_SIGNING_PUBLIC_KEY_ID"
        ),
        "policy_trusted_public_key": POLICY_TRUST_ROOT_ENV,
        "policy_activation_trusted_public_key": POLICY_ACTIVATION_TRUST_ROOT_ENV,
        "reproducible_build_trusted_public_key": REPRODUCIBLE_BUILD_TRUST_ROOT_ENV,
    }
    missing_trust = []
    for attribute, env_name in trust_settings.items():
        argument_value = getattr(args, attribute)
        env_value = loaded.get(env_name)
        if args.verification_mode == "final":
            if argument_value and env_value and argument_value != env_value:
                print(
                    f"production readiness env error: --{attribute.replace('_', '-')} must match {env_name} "
                    "in final verification mode",
                    file=sys.stderr,
                )
                raise SystemExit(1)
            value = env_value
        else:
            value = argument_value or env_value
        if not value:
            if args.verification_mode == "final":
                missing_trust.append(f"{env_name} (must be pinned in the production readiness env file)")
            else:
                missing_trust.append(f"--{attribute.replace('_', '-')} or {env_name}")
            continue
        if PLACEHOLDER_RE.search(value) or EXAMPLE_DOMAIN_RE.search(value):
            print(f"production readiness env error: {env_name} contains a placeholder value", file=sys.stderr)
            raise SystemExit(1)
        setattr(args, attribute, value)
        env[env_name] = value
    if missing_trust:
        print(
            "production readiness env error: missing release completion trust settings: "
            + ", ".join(missing_trust),
            file=sys.stderr,
        )
        raise SystemExit(1)
    if args.verification_mode == "final":
        for attribute, env_name in (
            ("policy_trusted_public_key_id", POLICY_TRUST_ROOT_ID_ENV),
            (
                "policy_activation_trusted_public_key_id",
                POLICY_ACTIVATION_TRUST_ROOT_ID_ENV,
            ),
            (
                "reproducible_build_trusted_public_key_id",
                REPRODUCIBLE_BUILD_TRUST_ROOT_ID_ENV,
            ),
        ):
            selected = getattr(args, attribute)
            pinned = loaded.get(env_name)
            if selected is not None and selected != pinned:
                print(
                    f"production readiness env error: --{attribute.replace('_', '-')} must match "
                    f"{env_name} in final verification mode",
                    file=sys.stderr,
                )
                raise SystemExit(1)
            if not isinstance(pinned, str) or SHA256_RE.fullmatch(pinned) is None:
                print(
                    f"production readiness env error: {env_name} must be sha256:<64 lowercase hex>",
                    file=sys.stderr,
                )
                raise SystemExit(1)
            setattr(args, attribute, pinned)
            env[env_name] = pinned
    else:
        for attribute, env_name in (
            ("policy_trusted_public_key_id", POLICY_TRUST_ROOT_ID_ENV),
            (
                "policy_activation_trusted_public_key_id",
                POLICY_ACTIVATION_TRUST_ROOT_ID_ENV,
            ),
            (
                "reproducible_build_trusted_public_key_id",
                REPRODUCIBLE_BUILD_TRUST_ROOT_ID_ENV,
            ),
        ):
            value = getattr(args, attribute) or loaded.get(env_name) or "sha256:" + "0" * 64
            setattr(args, attribute, value)
    if (
        SHA256_RE.fullmatch(
            args.control_plane_response_signing_public_key_id
        )
        is None
    ):
        print(
            "production readiness env error: control-plane response signing public key ID "
            "must be sha256:<64 lowercase hex>",
            file=sys.stderr,
        )
        raise SystemExit(1)
    final_challenge_settings = {
        "final_challenge_receipt": "SERVERWARE_FINAL_CHALLENGE_RECEIPT",
        "final_challenge_authority_public_key": "SERVERWARE_FINAL_CHALLENGE_AUTHORITY_PUBLIC_KEY",
        "final_challenge_authority_public_key_id": "SERVERWARE_FINAL_CHALLENGE_AUTHORITY_PUBLIC_KEY_ID",
        "final_challenge_authority_provider": "SERVERWARE_FINAL_CHALLENGE_AUTHORITY_PROVIDER",
    }
    hardware_assurance_settings = {
        "hardware_assurance": "SERVERWARE_HARDWARE_ASSURANCE",
        "hardware_assurance_trusted_public_key": "SERVERWARE_HARDWARE_ASSURANCE_TRUSTED_PUBLIC_KEY",
        "hardware_assurance_trusted_public_key_id": "SERVERWARE_HARDWARE_ASSURANCE_TRUSTED_PUBLIC_KEY_ID",
        "hardware_assurance_expected_challenge_nonce": "SERVERWARE_HARDWARE_ASSURANCE_EXPECTED_CHALLENGE_NONCE",
        "hardware_assurance_expected_challenge_nonce_sha256": (
            "SERVERWARE_HARDWARE_ASSURANCE_EXPECTED_CHALLENGE_NONCE_SHA256"
        ),
    }
    for env_name in final_challenge_settings.values():
        env.pop(env_name, None)
    for env_name in hardware_assurance_settings.values():
        env.pop(env_name, None)
    resolved_final_challenge = {
        attribute: loaded.get(env_name) for attribute, env_name in final_challenge_settings.items()
    }
    resolved_hardware_assurance = {
        attribute: loaded.get(env_name) for attribute, env_name in hardware_assurance_settings.items()
    }
    supplied_final_challenge = {
        attribute: getattr(args, attribute) for attribute in final_challenge_settings
    }
    supplied_hardware_assurance = {
        attribute: getattr(args, attribute) for attribute in hardware_assurance_settings
    }
    if args.verification_mode == "readiness" and (
        any(resolved_final_challenge.values())
        or any(resolved_hardware_assurance.values())
        or any(supplied_final_challenge.values())
        or any(supplied_hardware_assurance.values())
    ):
        print(
            "production readiness env error: final hardware and challenge-authority inputs are only valid with "
            "--verification-mode final",
            file=sys.stderr,
        )
        raise SystemExit(1)
    if args.verification_mode == "final":
        missing_final_challenge = []
        for attribute, env_name in final_challenge_settings.items():
            value = resolved_final_challenge[attribute]
            argument_value = supplied_final_challenge[attribute]
            if argument_value and value and argument_value != value:
                print(
                    f"production readiness env error: --{attribute.replace('_', '-')} must match {env_name} "
                    "in final verification mode",
                    file=sys.stderr,
                )
                raise SystemExit(1)
            if not value:
                missing_final_challenge.append(
                    f"{env_name} (must be pinned in the production readiness env file)"
                )
                continue
            if PLACEHOLDER_RE.search(value) or EXAMPLE_DOMAIN_RE.search(value):
                print(f"production readiness env error: {env_name} contains a placeholder value", file=sys.stderr)
                raise SystemExit(1)
            setattr(args, attribute, value)
            env[env_name] = value
        if missing_final_challenge:
            print(
                "production readiness env error: final verification mode requires off-host challenge authority "
                "inputs: " + ", ".join(missing_final_challenge),
                file=sys.stderr,
            )
            raise SystemExit(1)
        if len(args.final_challenge_authority_provider) > 256:
            print(
                "production readiness env error: final challenge authority provider must not exceed 256 characters",
                file=sys.stderr,
            )
            raise SystemExit(1)
        missing_hardware_assurance = []
        for attribute, env_name in hardware_assurance_settings.items():
            value = resolved_hardware_assurance[attribute]
            argument_value = supplied_hardware_assurance[attribute]
            if argument_value and value and argument_value != value:
                print(
                    f"production readiness env error: --{attribute.replace('_', '-')} must match {env_name} "
                    "in final verification mode",
                    file=sys.stderr,
                )
                raise SystemExit(1)
            if value:
                if PLACEHOLDER_RE.search(value) or EXAMPLE_DOMAIN_RE.search(value):
                    print(f"production readiness env error: {env_name} contains a placeholder value", file=sys.stderr)
                    raise SystemExit(1)
                setattr(args, attribute, value)
                env[env_name] = value
            elif attribute in {
                "hardware_assurance",
                "hardware_assurance_trusted_public_key",
                "hardware_assurance_trusted_public_key_id",
            }:
                missing_hardware_assurance.append(
                    f"{env_name} (must be pinned in the production readiness env file)"
                )
        if missing_hardware_assurance:
            print(
                "production readiness env error: final verification mode requires hardware assurance inputs: "
                + ", ".join(missing_hardware_assurance),
                file=sys.stderr,
            )
            raise SystemExit(1)
        expected_challenges = sum(
            bool(resolved_hardware_assurance[name])
            for name in (
                "hardware_assurance_expected_challenge_nonce",
                "hardware_assurance_expected_challenge_nonce_sha256",
            )
        )
        if expected_challenges != 1:
            print(
                "production readiness env error: final verification mode requires exactly one hardware assurance "
                "expected challenge nonce or digest",
                file=sys.stderr,
            )
            raise SystemExit(1)
        hardware_key_id = args.hardware_assurance_trusted_public_key_id
        authority_key_id = args.final_challenge_authority_public_key_id
        if SHA256_RE.fullmatch(hardware_key_id) is None:
            print(
                "production readiness env error: hardware assurance trusted public key ID must be "
                "sha256:<64 lowercase hex>",
                file=sys.stderr,
            )
            raise SystemExit(1)
        if SHA256_RE.fullmatch(authority_key_id) is None:
            print(
                "production readiness env error: final challenge authority public key ID must be "
                "sha256:<64 lowercase hex>",
                file=sys.stderr,
            )
            raise SystemExit(1)
        if hardware_key_id == authority_key_id:
            print(
                "production readiness env error: hardware assurance verifier and final challenge authority "
                "must use different public keys",
                file=sys.stderr,
            )
            raise SystemExit(1)
    env["SERVERWARE_COMPLETION_VERIFICATION_MODE"] = args.verification_mode
    if not args.config_only:
        proof_settings = {
            "proxy_response_proof": "SERVERWARE_PROXY_RESPONSE_PROOF_FILE",
            "proxy_proof_collector_command": "SERVERWARE_PROXY_PROOF_COLLECTOR_COMMAND",
            "proxy_address": "SERVERWARE_PROXY_PROOF_ADDRESS",
            "proxy_proof_url": "SERVERWARE_PROXY_PROOF_URL",
            "proxy_proof_ca": "SERVERWARE_PROXY_PROOF_CA_BUNDLE",
            "proxy_collector_key": "SERVERWARE_PROXY_PROOF_COLLECTOR_PRIVATE_KEY",
            "proxy_collector_public_key": "SERVERWARE_PROXY_PROOF_COLLECTOR_PUBLIC_KEY",
            "proxy_proof_verifier_public_key": "SERVERWARE_PROXY_PROOF_VERIFIER_PUBLIC_KEY",
        }
        missing = []
        for attribute, env_name in proof_settings.items():
            argument_value = getattr(args, attribute)
            env_value = loaded.get(env_name)
            if args.verification_mode == "final" and argument_value is not None and argument_value != env_value:
                print(
                    f"production readiness env error: --{attribute.replace('_', '-')} must match {env_name} "
                    "in final verification mode",
                    file=sys.stderr,
                )
                raise SystemExit(1)
            value = env_value if args.verification_mode == "final" else argument_value or env_value
            if not value:
                missing.append(
                    f"{env_name} (must be pinned in the production readiness env file)"
                    if args.verification_mode == "final"
                    else f"--{attribute.replace('_', '-')} or {env_name}"
                )
            else:
                setattr(args, attribute, value)
        explicit_server_instance = loaded.get("SERVERWARE_PROXY_SERVER_INSTANCE_ID")
        data_plane_instance = loaded.get("SERVERWARE_DATA_PLANE_INSTANCE_ID")
        if explicit_server_instance and data_plane_instance and explicit_server_instance != data_plane_instance:
            print(
                "production readiness env error: SERVERWARE_PROXY_SERVER_INSTANCE_ID and "
                "SERVERWARE_DATA_PLANE_INSTANCE_ID must match",
                file=sys.stderr,
            )
            raise SystemExit(1)
        env_server_instance = explicit_server_instance or data_plane_instance
        if (
            args.verification_mode == "final"
            and args.proxy_server_instance_id is not None
            and args.proxy_server_instance_id != env_server_instance
        ):
            print(
                "production readiness env error: --proxy-server-instance-id must match the production env "
                "server instance in final verification mode",
                file=sys.stderr,
            )
            raise SystemExit(1)
        args.proxy_server_instance_id = (
            env_server_instance
            if args.verification_mode == "final"
            else args.proxy_server_instance_id or env_server_instance
        )
        if not args.proxy_server_instance_id:
            missing.append(
                "SERVERWARE_PROXY_SERVER_INSTANCE_ID or SERVERWARE_DATA_PLANE_INSTANCE_ID"
                if args.verification_mode == "final"
                else "--proxy-server-instance-id or SERVERWARE_PROXY_SERVER_INSTANCE_ID or "
                "SERVERWARE_DATA_PLANE_INSTANCE_ID"
            )
        for attribute, env_name in (
            ("proxy_agent_id", "SERVERWARE_PROXY_PROOF_AGENT_ID"),
            ("proxy_principal_id", "SERVERWARE_PROXY_PROOF_PRINCIPAL_ID"),
        ):
            argument_value = getattr(args, attribute)
            env_value = loaded.get(env_name)
            if args.verification_mode == "final" and argument_value is not None and argument_value != env_value:
                print(
                    f"production readiness env error: --{attribute.replace('_', '-')} must match {env_name} "
                    "in final verification mode",
                    file=sys.stderr,
                )
                raise SystemExit(1)
            setattr(
                args,
                attribute,
                env_value if args.verification_mode == "final" else argument_value or env_value,
            )
        if not args.proxy_agent_id:
            missing.append(
                "SERVERWARE_PROXY_PROOF_AGENT_ID (must be pinned in the production readiness env file)"
                if args.verification_mode == "final"
                else "--proxy-agent-id or SERVERWARE_PROXY_PROOF_AGENT_ID"
            )
        if not args.proxy_principal_id:
            missing.append(
                "SERVERWARE_PROXY_PROOF_PRINCIPAL_ID (must be pinned in the production readiness env file)"
                if args.verification_mode == "final"
                else "--proxy-principal-id or SERVERWARE_PROXY_PROOF_PRINCIPAL_ID"
            )
        for attribute, env_name in PROXY_DIGEST_ENV_SETTINGS.items():
            argument_value = getattr(args, attribute)
            env_value = loaded.get(env_name)
            if args.verification_mode == "final":
                if argument_value and env_value and argument_value != env_value:
                    print(
                        f"production readiness env error: --{attribute.replace('_', '-')} must match {env_name} "
                        "in final verification mode",
                        file=sys.stderr,
                    )
                    raise SystemExit(1)
                value = env_value
                if not value:
                    missing.append(f"{env_name} (must be pinned in the production readiness env file)")
                    continue
            else:
                value = argument_value or env_value
                if not value:
                    missing.append(f"--{attribute.replace('_', '-')} or {env_name}")
                    continue
            if SHA256_RE.fullmatch(value) is None:
                print(
                    f"production readiness env error: expected proxy digest {env_name} must be "
                    "sha256:<64 lowercase hex>",
                    file=sys.stderr,
                )
                raise SystemExit(1)
            setattr(args, attribute, value)
        env_max_age = loaded.get("SERVERWARE_PROXY_PROOF_MAX_AGE_SECONDS")
        if args.verification_mode == "final" and env_max_age is None:
            missing.append(
                "SERVERWARE_PROXY_PROOF_MAX_AGE_SECONDS (must be pinned in the production readiness env file)"
            )
            max_age = None
        else:
            raw_max_age = env_max_age or "300"
            try:
                parsed_env_max_age = int(raw_max_age)
            except ValueError as exc:
                print(
                    "production readiness env error: SERVERWARE_PROXY_PROOF_MAX_AGE_SECONDS must be an integer",
                    file=sys.stderr,
                )
                raise SystemExit(1) from exc
            if (
                args.verification_mode == "final"
                and args.proxy_proof_max_age_seconds is not None
                and args.proxy_proof_max_age_seconds != parsed_env_max_age
            ):
                print(
                    "production readiness env error: --proxy-proof-max-age-seconds must match "
                    "SERVERWARE_PROXY_PROOF_MAX_AGE_SECONDS in final verification mode",
                    file=sys.stderr,
                )
                raise SystemExit(1)
            max_age = (
                parsed_env_max_age
                if args.verification_mode == "final" or args.proxy_proof_max_age_seconds is None
                else args.proxy_proof_max_age_seconds
            )
        if max_age is not None and not 1 <= max_age <= 900:
            print(
                "production readiness env error: proxy proof max age must be between 1 and 900 seconds",
                file=sys.stderr,
            )
            raise SystemExit(1)
        args.proxy_proof_max_age_seconds = max_age
        if missing:
            print(
                "production readiness env error: missing production proxy proof settings: "
                + ", ".join(missing),
                file=sys.stderr,
            )
            raise SystemExit(1)
        if args.verification_mode == "final":
            try:
                collector_words = shlex.split(args.proxy_proof_collector_command)
            except ValueError as exc:
                print(f"production readiness env error: invalid proof collector command: {exc}", file=sys.stderr)
                raise SystemExit(1) from exc
            if len(collector_words) != 1 or not Path(collector_words[0]).is_absolute():
                print(
                    "production readiness env error: SERVERWARE_PROXY_PROOF_COLLECTOR_COMMAND must be one "
                    "absolute executable in final mode",
                    file=sys.stderr,
                )
                raise SystemExit(1)
        try:
            validate_proxy_proof_policy_consistency(
                Path(args.policy_bundle),
                agent_id=args.proxy_agent_id,
                principal_id=args.proxy_principal_id,
                proof_url=args.proxy_proof_url,
            )
        except Exception as exc:
            print(
                f"production readiness env error: proxy proof policy consistency validation failed: {exc}",
                file=sys.stderr,
            )
            raise SystemExit(1) from exc
        args.proxy_client_nonce = generated_client_nonce()
        args.proxy_tls_channel_binding = "$COLLECTOR_SUMMARY.tls_channel_binding"
    if args.verification_mode == "final":
        try:
            executable_manifest = parse_executable_digest_manifest(
                loaded,
                expected_settings=set(PINNED_EXECUTABLE_COMMAND_SETTINGS),
            )
            args.script_digest_pins = parse_python_script_digest_pins(loaded)
            for script_path, (setting, digest) in args.script_digest_pins.items():
                measured_script = open_measured_script(Path(script_path), digest, setting)
                measured_script.close()
            compose_plugin = open_measured_executable(
                Path(args.docker_compose_plugin_executable),
                args.docker_compose_plugin_sha256,
                DOCKER_COMPOSE_PLUGIN_EXECUTABLE_ENV,
            )
            compose_plugin.close()
            if not args.dry_run:
                args.docker_socket_binding = validate_docker_unix_socket(
                    Path(args.docker_unix_socket)
                )
            executable_pins: dict[str, tuple[str, str]] = {}
            pinned_commands = [
                (PRODUCTION_PYTHON_EXECUTABLE_ENV, args.python),
                (PRODUCTION_DOCKER_EXECUTABLE_ENV, args.docker_executable),
            ]
            if not args.config_only:
                pinned_commands.append((PROOF_COLLECTOR_COMMAND_SETTING, collector_words[0]))
            for setting, executable in pinned_commands:
                absolute = os.path.abspath(executable)
                existing = executable_pins.get(absolute)
                pin = executable_manifest[setting]
                if existing is not None and existing[1] != pin:
                    raise ValueError("one executable path has conflicting production digest pins")
                executable_pins[absolute] = (setting, pin)
            args.pre_use_executable_pins = executable_pins
        except Exception as exc:
            print(f"production readiness env error: {exc}", file=sys.stderr)
            raise SystemExit(1) from exc
    control_plane_base = (
        args.control_plane_base
        or loaded.get("SERVERWARE_PRODUCTION_CONTROL_PLANE_BASE")
        or loaded.get("SERVERWARE_PUBLIC_URL")
        or "https://localhost:3000"
    )
    control_plane_ca_bundle = (
        args.control_plane_ca_bundle
        or loaded.get("SERVERWARE_PRODUCTION_CONTROL_PLANE_CA_BUNDLE")
        or str(Path(loaded.get("SERVERWARE_CONTROL_PLANE_TLS_DIR", "/etc/serverware/control-plane-tls")) / "ca.pem")
    )
    args.claims_args = [
        "--base",
        control_plane_base,
        "--ca-bundle",
        control_plane_ca_bundle,
        *args.claims_args,
    ]
    images_env = Path(args.production_images_env)
    env["SERVERWARE_PRODUCTION_READINESS_ENV_PATH"] = str(env_file)
    env["SERVERWARE_PRODUCTION_READINESS_ENV_SHA256"] = (
        "sha256:" + hashlib.sha256(production_env_bytes).hexdigest()
    )
    args.production_readiness_env_sha256 = env[
        "SERVERWARE_PRODUCTION_READINESS_ENV_SHA256"
    ]
    args.pre_run_completion_proof_state = capture_optional_proof_state(
        Path(args.completion_proof_out)
    )
    env["SERVERWARE_PRODUCTION_IMAGES_ENV_PATH"] = str(images_env)
    if images_env.exists():
        env["SERVERWARE_PRODUCTION_IMAGES_ENV_SHA256"] = sha256_prefixed_file(images_env)
    commands = command_plan(args)
    if args.dry_run:
        print(
            canonical_json(
                {
                    "ok": True,
                    "env_file": args.env_file,
                    "env_keys": sorted(loaded),
                    "commands": commands,
                }
            )
        )
        return
    if args.config_only:
        run_commands(
            commands,
            env,
            executable_pins=getattr(args, "pre_use_executable_pins", None),
            script_digest_pins=getattr(args, "script_digest_pins", None),
            isolated_python=args.verification_mode == "final",
        )
        return
    run_commands(
        commands[:-2],
        env,
        executable_pins=getattr(args, "pre_use_executable_pins", None),
        script_digest_pins=getattr(args, "script_digest_pins", None),
        isolated_python=args.verification_mode == "final",
    )
    summary = run_collector(commands[-2], args, env)
    args.proxy_tls_channel_binding = summary["tls_channel_binding"]
    run_commands(
        [completion_command(args)],
        env,
        executable_pins=getattr(args, "pre_use_executable_pins", None),
        script_digest_pins=getattr(args, "script_digest_pins", None),
        isolated_python=args.verification_mode == "final",
    )
    try:
        verify_completion_output(Path(args.completion_proof_out), args)
    except Exception as exc:
        print(f"release completion output integrity error: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
