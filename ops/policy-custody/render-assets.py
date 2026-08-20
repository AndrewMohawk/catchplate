#!/usr/bin/env python3
"""Render fail-closed policy-custody configs and systemd assets.

Usage: render-assets.py INPUT_MANIFEST_JSON OUTPUT_DIRECTORY

The input object must contain exactly:
  apiVersion: serverware.policyCustodyAssetRenderManifest/v5
  runtimeConfigMode: trusted-launcher-after-live-measurement-v1
  releaseRoot, runtimeConfigRoot: absolute paths
  driverIdentity: exact measured effective uid and primary gid
  socketAccessGroup: exact swpc-driver group/gid
  serviceIdentities: exact user/group/uid/gid for every service role
  runtimeHeaderReplacements: object keyed by each service role
  configReplacements: object keyed by each *.json.in basename
  credentialDirectives: object keyed by each service role

Replacement keys omit the surrounding @ characters. String placeholders
already quoted by a template are JSON-escaped by this renderer. Other values
are emitted as canonical compact JSON. The trusted launcher must invoke this
renderer only after measuring the live peer and activation directories. No
credential value is generated. The output runtime-config directory is an
install payload: the launcher must place it in a new root-owned generation
directory and atomically switch runtimeConfigRoot to that complete generation
before starting or restarting any service unit.

This renderer is intentionally production-host only. It requires euid 0,
root-owned non-writable path ancestry, root-private input and output parents,
root-owned release executables, and root-owned credential sources. It never
reads credential contents, but it does pin their metadata and rejects reuse of
one encrypted signing-key source by multiple authorities.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
from typing import NoReturn


ROLES = (
    "durable-recovery-store",
    "cleanup-authorization-consumer",
    "recovery-target-provider",
    "current-signature-authority",
    "bounded-cleanup-helper",
)
CONFIG_TEMPLATES = tuple(
    f"serverware-policy-custody-{role}.json.in" for role in ROLES
)
ASSET_RENDER_MANIFEST_VERSION = (
    "serverware.policyCustodyAssetRenderManifest/v5"
)
RUNTIME_CONFIG_MODE = (
    "trusted-launcher-after-live-measurement-v1"
)
POLICY_CUSTODY_RUNTIME_CONFIG_ROOT = (
    "/run/serverware/policy-custody/runtime/current"
)
TOP_LEVEL_KEYS = {
    "apiVersion",
    "runtimeConfigMode",
    "releaseRoot",
    "runtimeConfigRoot",
    "driverIdentity",
    "socketAccessGroup",
    "serviceIdentities",
    "runtimeHeaderReplacements",
    "configReplacements",
    "credentialDirectives",
}
SERVICE_IDENTITY_KEYS = {"user", "group", "uid", "gid"}
DRIVER_IDENTITY_KEYS = {"uid", "gid"}
SOCKET_GROUP_IDENTITY_KEYS = {"group", "gid"}
DRIVER_GROUP = "swpc-driver"
SERVICE_IDENTITIES = {
    "durable-recovery-store": ("swpc-store", "swpc-store"),
    "cleanup-authorization-consumer": (
        "swpc-consume",
        "swpc-consume",
    ),
    "recovery-target-provider": ("swpc-target", "swpc-target"),
    "current-signature-authority": (
        "swpc-signature",
        "swpc-signature",
    ),
    "bounded-cleanup-helper": ("swpc-cleanup", "swpc-cleanup"),
}
TOKEN = re.compile(r"@([A-Z][A-Z0-9_]*)@")
DIRECTIVE = re.compile(
    r"LoadCredential(?:Encrypted)?=[A-Za-z0-9_.-]+:[^\s]+"
)
CREDENTIAL_NAME = re.compile(r"[A-Za-z0-9_.-]{1,128}")
SHA256 = re.compile(r"sha256:[0-9a-f]{64}")
SAFE_ABSOLUTE_PATH = re.compile(r"/[A-Za-z0-9_./-]+")
EMPTY_SHA256 = (
    "sha256:e3b0c44298fc1c149afbf4c8996fb924"
    "27ae41e4649b934ca495991b7852b855"
)
PEER_PROCESS_IDENTITY_DOMAIN = (
    b"serverware.policyCustodyPeerProcessIdentity/v4"
)
MAX_STARTUP_TIMEOUT_MILLIS = 30_000
MAX_EXECUTABLE_LENGTH = 256 * 1024 * 1024
MAX_CREDENTIAL_SOURCE_LENGTH = 16 * 1024 * 1024
EXPECTED_DIRECTORY_NAMES = {
    "durable-recovery-store": {"journal"},
    "cleanup-authorization-consumer": {"state", "journal"},
    "recovery-target-provider": {"journal"},
    "current-signature-authority": set(),
    "bounded-cleanup-helper": {"journal"},
}
RUNTIME_KEYS = {
    "apiVersion",
    "startupTimeoutMillis",
    "operationGeneration",
    "serviceRestartEpoch",
    "serviceInvocationIdSha256",
    "readinessEpoch",
    "durabilityWorkerQueueDepth",
    "maximumDurabilityWorkerNanos",
    "authorityHistoryManifestSha256",
    "authorityHistoryManifestCredential",
    "authorityHistoryRootKeyId",
    "authorityHistoryRootKeySpkiSha256",
    "productionDispatchProtocolSetSha256",
    "deploymentGenerationSha256",
    "sharedConfigurationSha256",
    "listenerSocketPath",
    "expectedPeer",
    "activationDirectoryIdentities",
}
EXPECTED_PEER_KEYS = {
    "uid",
    "gid",
    "pid",
    "processIdentitySha256",
    "startTimeTicks",
    "executableDevice",
    "executableInode",
    "executableLength",
    "executableSha256",
}
DIRECTORY_IDENTITY_KEYS = {
    "mountId",
    "deviceMajor",
    "deviceMinor",
    "inode",
    "uid",
    "gid",
    "mode",
}


def fail(message: str) -> NoReturn:
    raise SystemExit(f"policy-custody asset render failed: {message}")


def canonical_json(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
    )


def require_root_owned_path_ancestry(
    path: Path,
    label: str,
    *,
    include_leaf: bool,
    private_leaf: bool = False,
) -> os.stat_result:
    if not path.is_absolute():
        fail(f"{label} must be absolute")
    parts = path.parts
    current = Path(parts[0])
    last: os.stat_result | None = None
    limit = len(parts) - 1
    for index in range(1, limit):
        current = current / parts[index]
        try:
            observed = os.lstat(current)
        except OSError as error:
            fail(f"cannot inspect {label} ancestor {current}: {error}")
        if (
            stat.S_ISLNK(observed.st_mode)
            or not stat.S_ISDIR(observed.st_mode)
            or observed.st_uid != 0
            or observed.st_mode & 0o022
        ):
            fail(
                f"{label} ancestor {current} must be a root-owned "
                "non-symlink directory not writable by group or other"
            )
        last = observed
    if include_leaf:
        try:
            observed = os.lstat(path)
        except OSError as error:
            fail(f"cannot inspect {label}: {error}")
        if stat.S_ISLNK(observed.st_mode) or observed.st_uid != 0:
            fail(f"{label} must be root-owned and must not be a symlink")
        if observed.st_mode & 0o022:
            fail(f"{label} must not be writable by group or other")
        if private_leaf and observed.st_mode & 0o077:
            fail(f"{label} must be accessible only to root")
        last = observed
    if last is None:
        fail(f"{label} path cannot be inspected")
    return last


def read_root_manifest(path: Path) -> tuple[object, bytes]:
    require_root_owned_path_ancestry(
        path,
        "input manifest",
        include_leaf=False,
    )
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
    except OSError as error:
        fail(f"cannot open input manifest: {error}")
    try:
        before = os.fstat(descriptor)
        path_stat = os.lstat(path)
        mode = stat.S_IMODE(before.st_mode)
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_ISLNK(path_stat.st_mode)
            or before.st_dev != path_stat.st_dev
            or before.st_ino != path_stat.st_ino
            or before.st_uid != 0
            or before.st_gid != 0
            or mode not in {0o400, 0o600}
            or before.st_size <= 0
            or before.st_size > 16 * 1024 * 1024
        ):
            fail(
                "input manifest must be a root:root regular non-symlink "
                "file with mode 0400 or 0600 and a bounded size"
            )
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            if not chunk:
                fail("input manifest was truncated while read")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            fail("input manifest grew while read")
        after = os.fstat(descriptor)
        if (
            before.st_dev != after.st_dev
            or before.st_ino != after.st_ino
            or before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
            or before.st_ctime_ns != after.st_ctime_ns
        ):
            fail("input manifest metadata changed while read")
        raw = b"".join(chunks)
    except OSError as error:
        fail(f"cannot read input manifest: {error}")
    finally:
        os.close(descriptor)
    try:
        return json.loads(raw), raw
    except (UnicodeError, json.JSONDecodeError) as error:
        fail(f"input manifest is not strict JSON: {error}")


def require_absolute(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.startswith("/"):
        fail(f"{label} must be an absolute path")
    if "\x00" in value or "\n" in value or "\r" in value:
        fail(f"{label} contains a forbidden character")
    normalized = os.path.normpath(value)
    if (
        normalized != value
        or value == "/"
        or value.startswith("//")
        or not SAFE_ABSOLUTE_PATH.fullmatch(value)
    ):
        fail(
            f"{label} must be a normalized, unambiguous system path"
        )
    return value


def render_json_template(
    template_path: Path,
    replacements: object,
) -> tuple[bytes, dict[str, object]]:
    if not isinstance(replacements, dict):
        fail(f"{template_path.name} replacements must be an object")
    template = template_path.read_text(encoding="ascii")
    required = set(TOKEN.findall(template))
    supplied = set(replacements)
    if supplied != required:
        fail(
            f"{template_path.name} replacement keys differ: "
            f"missing={sorted(required - supplied)} "
            f"extra={sorted(supplied - required)}"
        )
    rendered = template
    for name in sorted(required):
        marker = f"@{name}@"
        value = replacements[name]
        quoted = f'"{marker}"'
        if quoted in rendered:
            if not isinstance(value, str):
                fail(
                    f"{template_path.name}:{name} must be a string"
                )
            rendered = rendered.replace(quoted, canonical_json(value))
        else:
            rendered = rendered.replace(marker, canonical_json(value))
    if TOKEN.search(rendered):
        fail(f"{template_path.name} retains a template token")
    try:
        parsed = json.loads(rendered)
    except json.JSONDecodeError as error:
        fail(f"{template_path.name} rendered invalid JSON: {error}")
    exact = canonical_json(parsed)
    if exact != rendered:
        fail(
            f"{template_path.name} is not canonical compact JSON "
            "after rendering"
        )
    if not isinstance(parsed, dict):
        fail(f"{template_path.name} must render a JSON object")
    return exact.encode("ascii"), parsed


def render_text_template(
    template_path: Path,
    replacements: dict[str, str],
) -> bytes:
    rendered = template_path.read_text(encoding="ascii")
    required = set(TOKEN.findall(rendered))
    if set(replacements) != required:
        fail(
            f"{template_path.name} text replacement keys differ: "
            f"missing={sorted(required - set(replacements))} "
            f"extra={sorted(set(replacements) - required)}"
        )
    for name in sorted(required):
        value = replacements[name]
        if "\n" in value or "\r" in value or "\x00" in value:
            fail(f"{template_path.name}:{name} is not one line")
        rendered = rendered.replace(f"@{name}@", value)
    if TOKEN.search(rendered):
        fail(f"{template_path.name} retains a template token")
    return rendered.encode("ascii")


def write_exact(
    path: Path,
    content: bytes,
    mode: int,
    *,
    parent_mode: int = 0o755,
) -> None:
    path.parent.mkdir(mode=parent_mode, parents=True, exist_ok=True)
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
        mode,
    )
    try:
        written = 0
        while written < len(content):
            count = os.write(descriptor, content[written:])
            if count <= 0:
                fail(f"short write while creating {path}")
            written += count
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def fsync_directory(path: Path) -> None:
    descriptor = os.open(
        path,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC,
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def require_exact_object(
    value: object,
    expected_keys: set[str],
    label: str,
) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != expected_keys:
        actual = set(value) if isinstance(value, dict) else set()
        fail(
            f"{label} keys differ: "
            f"missing={sorted(expected_keys - actual)} "
            f"extra={sorted(actual - expected_keys)}"
        )
    return value


def require_integer(
    value: object,
    label: str,
    minimum: int = 0,
    maximum: int | None = None,
) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < minimum
        or (maximum is not None and value > maximum)
    ):
        fail(f"{label} is outside its exact integer bound")
    return value


def validate_identity(
    value: object,
    label: str,
    expected_user: str,
    expected_group: str,
) -> dict[str, object]:
    identity = require_exact_object(
        value, SERVICE_IDENTITY_KEYS, label
    )
    if (
        identity["user"] != expected_user
        or identity["group"] != expected_group
    ):
        fail(
            f"{label} must name {expected_user}:{expected_group}"
        )
    require_integer(identity["uid"], f"{label}.uid", 1, 2**32 - 2)
    require_integer(identity["gid"], f"{label}.gid", 1, 2**32 - 2)
    return identity


def validate_declared_identities(
    manifest: dict[str, object],
) -> tuple[
    dict[str, object],
    dict[str, object],
    dict[str, dict[str, object]],
]:
    driver = require_exact_object(
        manifest["driverIdentity"],
        DRIVER_IDENTITY_KEYS,
        "driverIdentity",
    )
    require_integer(
        driver["uid"], "driverIdentity.uid", 1, 2**32 - 2
    )
    require_integer(
        driver["gid"], "driverIdentity.gid", 1, 2**32 - 2
    )
    socket_group = require_exact_object(
        manifest["socketAccessGroup"],
        SOCKET_GROUP_IDENTITY_KEYS,
        "socketAccessGroup",
    )
    if socket_group["group"] != DRIVER_GROUP:
        fail(f"socketAccessGroup.group must be {DRIVER_GROUP}")
    require_integer(
        socket_group["gid"],
        "socketAccessGroup.gid",
        1,
        2**32 - 2,
    )
    declared = manifest["serviceIdentities"]
    if not isinstance(declared, dict) or set(declared) != set(ROLES):
        fail("serviceIdentities must name exactly the five roles")
    services: dict[str, dict[str, object]] = {}
    seen_uids = {driver["uid"]}
    seen_gids = {driver["gid"], socket_group["gid"]}
    for role in ROLES:
        expected_user, expected_group = SERVICE_IDENTITIES[role]
        identity = validate_identity(
            declared[role],
            f"serviceIdentities.{role}",
            expected_user,
            expected_group,
        )
        if identity["uid"] in seen_uids or identity["gid"] in seen_gids:
            fail(
                f"serviceIdentities.{role} must have a distinct uid "
                "and primary gid"
            )
        seen_uids.add(identity["uid"])
        seen_gids.add(identity["gid"])
        services[role] = identity
    return driver, socket_group, services


def inspect_root_file(
    path: Path,
    label: str,
    *,
    private: bool,
    executable: bool,
    maximum_length: int,
) -> tuple[os.stat_result, str]:
    require_root_owned_path_ancestry(
        path,
        label,
        include_leaf=False,
    )
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
    except OSError as error:
        fail(f"cannot open {label}: {error}")
    try:
        before = os.fstat(descriptor)
        path_stat = os.lstat(path)
        mode = stat.S_IMODE(before.st_mode)
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_ISLNK(path_stat.st_mode)
            or before.st_dev != path_stat.st_dev
            or before.st_ino != path_stat.st_ino
            or before.st_uid != 0
            or before.st_gid != 0
            or before.st_mode & 0o022
            or (private and before.st_mode & 0o077)
            or (executable and mode & 0o111 == 0)
            or before.st_size <= 0
            or before.st_size > maximum_length
        ):
            fail(
                f"{label} has unsafe ownership, type, mode, or size"
            )
        digest = hashlib.sha256()
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            if not chunk:
                fail(f"{label} was truncated while read")
            digest.update(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            fail(f"{label} grew while read")
        after = os.fstat(descriptor)
        if (
            before.st_dev != after.st_dev
            or before.st_ino != after.st_ino
            or before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
            or before.st_ctime_ns != after.st_ctime_ns
        ):
            fail(f"{label} metadata changed while read")
        return before, f"sha256:{digest.hexdigest()}"
    except OSError as error:
        fail(f"cannot inspect {label}: {error}")
    finally:
        os.close(descriptor)


def inspect_release_binaries(
    release_root: Path,
) -> dict[str, dict[str, object]]:
    root_stat = require_root_owned_path_ancestry(
        release_root,
        "releaseRoot",
        include_leaf=True,
    )
    if not stat.S_ISDIR(root_stat.st_mode):
        fail("releaseRoot must be a root-owned immutable directory")
    binaries: dict[str, dict[str, object]] = {}
    for role in ROLES:
        path = release_root / "bin" / f"serverware-policy-custody-{role}"
        observed, digest = inspect_root_file(
            path,
            f"{role} release executable",
            private=False,
            executable=True,
            maximum_length=MAX_EXECUTABLE_LENGTH,
        )
        binaries[role] = {
            "path": str(path),
            "sha256": digest,
            "length": observed.st_size,
            "mode": format(stat.S_IMODE(observed.st_mode), "04o"),
            "uid": observed.st_uid,
            "gid": observed.st_gid,
        }
    return binaries


def require_nonempty_sha256(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or not SHA256.fullmatch(value)
        or value == EMPTY_SHA256
    ):
        fail(f"{label} must be a nonempty lowercase sha256 digest")
    return value


def domain_frame_sha256(domain: bytes, parts: tuple[bytes, ...]) -> str:
    digest = hashlib.sha256()
    digest.update(domain)
    digest.update(b"\x00")
    for part in parts:
        digest.update(len(part).to_bytes(8, "big"))
        digest.update(part)
    return f"sha256:{digest.hexdigest()}"


def validate_runtime_header(
    config: dict[str, object],
    role: str,
    driver_identity: dict[str, object],
    service_identity: dict[str, object],
) -> tuple[object, ...]:
    runtime = require_exact_object(
        config.get("runtime"),
        RUNTIME_KEYS,
        f"{role}:runtime",
    )
    if (
        runtime["apiVersion"]
        != "serverware.policyCustodyServiceRuntimeConfig/v4"
    ):
        fail(f"{role}:runtime apiVersion is unsupported")
    require_integer(
        runtime["startupTimeoutMillis"],
        f"{role}:startupTimeoutMillis",
        1,
        MAX_STARTUP_TIMEOUT_MILLIS,
    )
    operation_generation = require_integer(
        runtime["operationGeneration"],
        f"{role}:operationGeneration",
        1,
    )
    service_restart_epoch = require_integer(
        runtime["serviceRestartEpoch"],
        f"{role}:serviceRestartEpoch",
        1,
    )
    service_invocation_id = require_nonempty_sha256(
        runtime["serviceInvocationIdSha256"],
        f"{role}:serviceInvocationIdSha256",
    )
    readiness_epoch = require_integer(
        runtime["readinessEpoch"],
        f"{role}:readinessEpoch",
        service_restart_epoch,
    )
    if readiness_epoch < service_restart_epoch:
        fail(
            f"{role}:readinessEpoch must not precede "
            "serviceRestartEpoch"
        )
    durability_worker_queue_depth = require_integer(
        runtime["durabilityWorkerQueueDepth"],
        f"{role}:durabilityWorkerQueueDepth",
        8,
        8,
    )
    maximum_durability_worker_nanos = require_integer(
        runtime["maximumDurabilityWorkerNanos"],
        f"{role}:maximumDurabilityWorkerNanos",
        1,
        1_000_000_000,
    )
    require_nonempty_sha256(
        runtime["authorityHistoryManifestSha256"],
        f"{role}:authorityHistoryManifestSha256",
    )
    history_credential = runtime[
        "authorityHistoryManifestCredential"
    ]
    if (
        not isinstance(history_credential, str)
        or not CREDENTIAL_NAME.fullmatch(history_credential)
    ):
        fail(
            f"{role}:authorityHistoryManifestCredential "
            "is not a valid credential name"
        )
    require_nonempty_sha256(
        runtime["authorityHistoryRootKeyId"],
        f"{role}:authorityHistoryRootKeyId",
    )
    require_nonempty_sha256(
        runtime["authorityHistoryRootKeySpkiSha256"],
        f"{role}:authorityHistoryRootKeySpkiSha256",
    )
    production_dispatch_protocol_set = require_nonempty_sha256(
        runtime["productionDispatchProtocolSetSha256"],
        f"{role}:productionDispatchProtocolSetSha256",
    )
    deployment_generation = require_nonempty_sha256(
        runtime["deploymentGenerationSha256"],
        f"{role}:deploymentGenerationSha256",
    )
    shared_configuration = require_nonempty_sha256(
        runtime["sharedConfigurationSha256"],
        f"{role}:sharedConfigurationSha256",
    )
    expected_listener = (
        f"/run/serverware/policy-custody/{role}.sock"
    )
    if runtime["listenerSocketPath"] != expected_listener:
        fail(
            f"{role}:listenerSocketPath must be {expected_listener}"
        )

    peer = require_exact_object(
        runtime["expectedPeer"],
        EXPECTED_PEER_KEYS,
        f"{role}:expectedPeer",
    )
    peer_uid = require_integer(
        peer["uid"], f"{role}:expectedPeer.uid"
    )
    peer_gid = require_integer(
        peer["gid"], f"{role}:expectedPeer.gid"
    )
    if (
        peer_uid != driver_identity["uid"]
        or peer_gid != driver_identity["gid"]
    ):
        fail(
            f"{role}:expectedPeer uid/gid must equal the declared "
            "swpc-driver identity"
        )
    peer_pid = require_integer(
        peer["pid"], f"{role}:expectedPeer.pid", 1
    )
    peer_identity = require_nonempty_sha256(
        peer["processIdentitySha256"],
        f"{role}:expectedPeer.processIdentitySha256",
    )
    peer_start_time = require_integer(
        peer["startTimeTicks"],
        f"{role}:expectedPeer.startTimeTicks",
        1,
    )
    peer_executable_device = require_integer(
        peer["executableDevice"],
        f"{role}:expectedPeer.executableDevice",
        1,
    )
    peer_executable_inode = require_integer(
        peer["executableInode"],
        f"{role}:expectedPeer.executableInode",
        1,
    )
    peer_executable_length = require_integer(
        peer["executableLength"],
        f"{role}:expectedPeer.executableLength",
        1,
        MAX_EXECUTABLE_LENGTH,
    )
    peer_executable_sha256 = require_nonempty_sha256(
        peer["executableSha256"],
        f"{role}:expectedPeer.executableSha256",
    )
    expected_peer_identity = domain_frame_sha256(
        PEER_PROCESS_IDENTITY_DOMAIN,
        (
            peer_uid.to_bytes(4, "big"),
            peer_gid.to_bytes(4, "big"),
            peer_pid.to_bytes(4, "big", signed=True),
            peer_start_time.to_bytes(8, "big"),
            peer_executable_device.to_bytes(8, "big"),
            peer_executable_inode.to_bytes(8, "big"),
            peer_executable_length.to_bytes(8, "big"),
            bytes.fromhex(peer_executable_sha256.removeprefix("sha256:")),
        ),
    )
    if peer_identity != expected_peer_identity:
        fail(
            f"{role}:expectedPeer.processIdentitySha256 does not "
            "bind the exact uid, gid, pid, start time, and executable"
        )

    identities = runtime["activationDirectoryIdentities"]
    expected_names = EXPECTED_DIRECTORY_NAMES[role]
    if not isinstance(identities, dict) or set(identities) != expected_names:
        actual = set(identities) if isinstance(identities, dict) else set()
        fail(
            f"{role}:activationDirectoryIdentities differ: "
            f"missing={sorted(expected_names - actual)} "
            f"extra={sorted(actual - expected_names)}"
        )
    directory_owner: tuple[int, int] | None = None
    for name in sorted(expected_names):
        identity = require_exact_object(
            identities[name],
            DIRECTORY_IDENTITY_KEYS,
            f"{role}:{name} identity",
        )
        require_integer(
            identity["mountId"], f"{role}:{name}.mountId", 1
        )
        require_integer(
            identity["deviceMajor"],
            f"{role}:{name}.deviceMajor",
        )
        require_integer(
            identity["deviceMinor"],
            f"{role}:{name}.deviceMinor",
        )
        require_integer(
            identity["inode"], f"{role}:{name}.inode", 1
        )
        identity_uid = require_integer(
            identity["uid"], f"{role}:{name}.uid", 1
        )
        identity_gid = require_integer(
            identity["gid"], f"{role}:{name}.gid", 1
        )
        observed_owner = (identity_uid, identity_gid)
        if observed_owner != (
            service_identity["uid"],
            service_identity["gid"],
        ):
            fail(
                f"{role}:{name} must be owned by the declared "
                "role identity"
            )
        if directory_owner is None:
            directory_owner = observed_owner
        elif directory_owner != observed_owner:
            fail(
                f"{role} activation directories have different owners"
            )
        if identity["mode"] != 0o40700:
            fail(
                f"{role}:{name}.mode must be an owner-only directory"
            )

    return (
        operation_generation,
        durability_worker_queue_depth,
        maximum_durability_worker_nanos,
        production_dispatch_protocol_set,
        deployment_generation,
        shared_configuration,
        peer_uid,
        peer_gid,
        peer_pid,
        peer_identity,
        peer_start_time,
        peer_executable_device,
        peer_executable_inode,
        peer_executable_length,
        peer_executable_sha256,
    )


def add_credential_reference(
    required: dict[str, bool],
    container: object,
    key: str,
    label: str,
    encrypted: bool = False,
) -> None:
    if not isinstance(container, dict):
        fail(f"{label} must be an object")
    value = container.get(key)
    if not isinstance(value, str) or not CREDENTIAL_NAME.fullmatch(value):
        fail(f"{label}.{key} is not a valid credential name")
    required[value] = required.get(value, False) or encrypted


def add_pin_credentials(
    required: dict[str, bool],
    pin: object,
    label: str,
) -> None:
    add_credential_reference(
        required,
        pin,
        "endpointVerifyingKeyCredential",
        label,
    )
    add_credential_reference(
        required,
        pin,
        "checkpointAuthorityVerifyingKeyCredential",
        label,
    )


def required_role_credentials(
    role: str,
    config: dict[str, object],
) -> dict[str, bool]:
    required: dict[str, bool] = {}
    add_credential_reference(
        required,
        config.get("runtime"),
        "authorityHistoryManifestCredential",
        f"{role}.runtime",
    )
    if role == "durable-recovery-store":
        add_credential_reference(
            required,
            config,
            "signingKeyCredential",
            role,
            encrypted=True,
        )
        add_credential_reference(
            required,
            config,
            "currentHeadAuthorityVerifyingKeyCredential",
            role,
        )
    elif role == "cleanup-authorization-consumer":
        add_credential_reference(
            required,
            config,
            "signingKeyCredential",
            role,
            encrypted=True,
        )
        add_credential_reference(
            required,
            config,
            "currentHeadAuthorityVerifyingKeyCredential",
            role,
        )
        add_credential_reference(
            required,
            config,
            "cleanupAuthorityVerifyingKeyCredential",
            role,
        )
    elif role == "recovery-target-provider":
        add_credential_reference(
            required,
            config,
            "signingKeyCredential",
            role,
            encrypted=True,
        )
        add_credential_reference(
            required,
            config,
            "lineageAuthorityVerifyingKeyCredential",
            role,
        )
        add_pin_credentials(
            required,
            config.get("serviceSigningPin"),
            f"{role}.serviceSigningPin",
        )
    elif role == "current-signature-authority":
        add_credential_reference(
            required,
            config,
            "serviceSigningKeyCredential",
            role,
            encrypted=True,
        )
        add_pin_credentials(
            required,
            config.get("serviceSigningPin"),
            f"{role}.serviceSigningPin",
        )
        subjects = config.get("currentSubjects")
        if (
            not isinstance(subjects, list)
            or not subjects
            or len(subjects) > 64
        ):
            fail(
                f"{role}.currentSubjects must contain 1 through 64 entries"
            )
        for index, subject in enumerate(subjects):
            if not isinstance(subject, dict):
                fail(f"{role}.currentSubjects[{index}] is not an object")
            add_pin_credentials(
                required,
                subject.get("pin"),
                f"{role}.currentSubjects[{index}].pin",
            )
    elif role == "bounded-cleanup-helper":
        add_credential_reference(
            required,
            config,
            "signingKeyCredential",
            role,
            encrypted=True,
        )
        add_credential_reference(
            required,
            config,
            "currentHeadAuthorityVerifyingKeyCredential",
            role,
        )
    else:
        fail(f"unsupported role {role}")
    return required


def validate_directives(
    value: object,
    role: str,
    required: dict[str, bool],
) -> tuple[bytes, dict[str, tuple[str, str]]]:
    if not isinstance(value, list) or not value:
        fail(f"{role} credentialDirectives must be a nonempty array")
    directives: dict[str, tuple[str, str]] = {}
    for directive in value:
        if not isinstance(directive, str) or not DIRECTIVE.fullmatch(
            directive
        ):
            fail(f"{role} has an invalid credential directive")
        kind, payload = directive.split("=", 1)
        name, source = payload.split(":", 1)
        require_absolute(source, f"{role}:{name} credential source")
        if name == f"serverware-policy-custody-{role}.json":
            fail(f"{role} duplicates the base configuration credential")
        if name in directives:
            fail(f"{role} repeats credential name {name}")
        inspect_root_file(
            Path(source),
            f"{role}:{name} credential source",
            private=kind == "LoadCredentialEncrypted",
            executable=False,
            maximum_length=MAX_CREDENTIAL_SOURCE_LENGTH,
        )
        directives[name] = (kind, source)
    names = set(directives)
    expected = set(required)
    if names != expected:
        fail(
            f"{role} credential names differ from rendered config: "
            f"missing={sorted(expected - names)} "
            f"extra={sorted(names - expected)}"
        )
    lines = ["[Service]"]
    for name in sorted(names):
        kind, source = directives[name]
        if required[name] and kind != "LoadCredentialEncrypted":
            fail(
                f"{role}:{name} signing key must use "
                "LoadCredentialEncrypted"
            )
        lines.append(f"{kind}={name}:{source}")
    return ("\n".join(lines) + "\n").encode("ascii"), directives


def emitted_file_record(path: Path, root: Path) -> dict[str, object]:
    observed = os.lstat(path)
    if (
        stat.S_ISLNK(observed.st_mode)
        or not stat.S_ISREG(observed.st_mode)
        or observed.st_uid != 0
        or observed.st_gid != 0
        or observed.st_mode & 0o222
    ):
        fail(f"generated payload {path} is not immutable root:root data")
    return {
        "path": path.relative_to(root).as_posix(),
        "sha256": (
            "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
        ),
        "length": observed.st_size,
        "mode": format(stat.S_IMODE(observed.st_mode), "04o"),
        "uid": observed.st_uid,
        "gid": observed.st_gid,
    }


def main() -> None:
    if len(sys.argv) != 3:
        fail("expected INPUT_MANIFEST_JSON and OUTPUT_DIRECTORY")
    if os.geteuid() != 0:
        fail("trusted host rendering requires euid 0")
    os.umask(0o077)
    script_dir = Path(__file__).resolve().parent
    repo_root = script_dir.parent.parent
    input_path = Path(
        require_absolute(sys.argv[1], "INPUT_MANIFEST_JSON")
    )
    output = Path(
        require_absolute(sys.argv[2], "OUTPUT_DIRECTORY")
    )
    manifest, manifest_bytes = read_root_manifest(input_path)
    if not isinstance(manifest, dict) or set(manifest) != TOP_LEVEL_KEYS:
        fail("input manifest has missing or unknown top-level keys")
    if canonical_json(manifest).encode("ascii") != manifest_bytes:
        fail("input manifest must be exact canonical compact JSON")
    if manifest["apiVersion"] != ASSET_RENDER_MANIFEST_VERSION:
        fail("input manifest apiVersion is unsupported")
    if manifest["runtimeConfigMode"] != RUNTIME_CONFIG_MODE:
        fail(
            "runtimeConfigMode must require trusted-launcher "
            "post-measurement generation"
        )
    release_root_text = require_absolute(
        manifest["releaseRoot"], "releaseRoot"
    )
    release_root = Path(release_root_text)
    release_binaries = inspect_release_binaries(release_root)
    runtime_config_root = require_absolute(
        manifest["runtimeConfigRoot"], "runtimeConfigRoot"
    )
    if runtime_config_root != POLICY_CUSTODY_RUNTIME_CONFIG_ROOT:
        fail(
            "runtimeConfigRoot must match the root-owned tmpfiles "
            f"path {POLICY_CUSTODY_RUNTIME_CONFIG_ROOT}"
        )
    runtime_parent = Path(runtime_config_root).parent
    runtime_parent_stat = require_root_owned_path_ancestry(
        runtime_parent,
        "runtimeConfigRoot parent",
        include_leaf=True,
        private_leaf=True,
    )
    if not stat.S_ISDIR(runtime_parent_stat.st_mode):
        fail("runtimeConfigRoot parent must be a root-private directory")
    driver_identity, socket_access_group, service_identities = (
        validate_declared_identities(manifest)
    )
    replacements = manifest["configReplacements"]
    runtime_header_replacements = manifest[
        "runtimeHeaderReplacements"
    ]
    directives = manifest["credentialDirectives"]
    if (
        not isinstance(runtime_header_replacements, dict)
        or set(runtime_header_replacements) != set(ROLES)
    ):
        fail(
            "runtimeHeaderReplacements must name exactly the five roles"
        )
    if not isinstance(replacements, dict) or set(replacements) != set(
        CONFIG_TEMPLATES
    ):
        fail("configReplacements must name exactly the five templates")
    if not isinstance(directives, dict) or set(directives) != set(ROLES):
        fail("credentialDirectives must name exactly the five roles")
    if os.path.lexists(output):
        fail("output directory already exists")
    output_parent_stat = require_root_owned_path_ancestry(
        output.parent,
        "OUTPUT_DIRECTORY parent",
        include_leaf=True,
        private_leaf=True,
    )
    if not stat.S_ISDIR(output_parent_stat.st_mode):
        fail("OUTPUT_DIRECTORY parent must be a root-private directory")
    staging = Path(
        tempfile.mkdtemp(
            prefix=f".{output.name}.", dir=output.parent
        )
    )
    emitted: list[Path] = []
    rendered_configs: dict[str, dict[str, object]] = {}
    runtime_coherence: tuple[object, ...] | None = None
    service_invocation_ids: set[str] = set()
    encrypted_credential_sources: set[str] = set()
    try:
        runtime_header_template = (
            script_dir / "runtime-header-v4.json.in"
        )
        for template_name in CONFIG_TEMPLATES:
            template = script_dir / template_name
            role = template_name.removeprefix(
                "serverware-policy-custody-"
            ).removesuffix(".json.in")
            destination = (
                staging
                / "runtime-config"
                / template_name.removesuffix(".in")
            )
            _, runtime_header = render_json_template(
                runtime_header_template,
                runtime_header_replacements[role],
            )
            role_replacements = replacements[template_name]
            if not isinstance(role_replacements, dict):
                fail(f"{template_name} replacements must be an object")
            if "RUNTIME_HEADER_JSON" in role_replacements:
                fail(
                    f"{template_name} must not supply an opaque "
                    "RUNTIME_HEADER_JSON"
                )
            complete_replacements = dict(role_replacements)
            complete_replacements["RUNTIME_HEADER_JSON"] = (
                runtime_header
            )
            content, config = render_json_template(
                template, complete_replacements
            )
            observed_coherence = validate_runtime_header(
                config,
                role,
                driver_identity,
                service_identities[role],
            )
            if runtime_coherence is None:
                runtime_coherence = observed_coherence
            elif runtime_coherence != observed_coherence:
                fail(
                    f"{role} runtime generation or live peer identity "
                    "differs from the other service configs"
                )
            invocation_id = config["runtime"][
                "serviceInvocationIdSha256"
            ]
            if invocation_id in service_invocation_ids:
                fail(
                    f"{role} reuses another service invocation identity"
                )
            service_invocation_ids.add(invocation_id)
            write_exact(
                destination,
                content,
                0o400,
                parent_mode=0o700,
            )
            rendered_configs[role] = config
            emitted.append(destination)

        systemd_source = repo_root / "ops" / "systemd"
        service_destination = (
            staging
            / "systemd"
            / "serverware-policy-custody@.service"
        )
        write_exact(
            service_destination,
            render_text_template(
                systemd_source
                / "serverware-policy-custody@.service.in",
                {
                    "RELEASE_ROOT": release_root_text,
                    "RUNTIME_CONFIG_ROOT": runtime_config_root,
                },
            ),
            0o444,
        )
        emitted.append(service_destination)
        for plain_name in (
            "serverware-policy-custody@.socket",
            "serverware-policy-custody-sockets.target",
            "serverware-policy-custody.target",
        ):
            destination = staging / "systemd" / plain_name
            write_exact(
                destination,
                (systemd_source / plain_name).read_bytes(),
                0o444,
            )
            emitted.append(destination)

        for role in ROLES:
            dropin = (
                staging
                / "systemd"
                / f"serverware-policy-custody@{role}.service.d"
            )
            capability_destination = dropin / "capabilities.conf"
            write_exact(
                capability_destination,
                render_text_template(
                    systemd_source
                    / f"serverware-policy-custody@{role}.service.d"
                    / "capabilities.conf.in",
                    {},
                ),
                0o444,
            )
            emitted.append(capability_destination)
            credentials_destination = dropin / "credentials.conf"
            credential_dropin, role_directives = validate_directives(
                directives[role],
                role,
                required_role_credentials(
                    role, rendered_configs[role]
                ),
            )
            for kind, source in role_directives.values():
                if kind != "LoadCredentialEncrypted":
                    continue
                if source in encrypted_credential_sources:
                    fail(
                        f"{role} reuses another authority's encrypted "
                        "signing-key source"
                    )
                encrypted_credential_sources.add(source)
            write_exact(
                credentials_destination,
                credential_dropin,
                0o400,
            )
            emitted.append(credentials_destination)

        sysusers_destination = (
            staging
            / "sysusers.d"
            / "serverware-policy-custody.conf"
        )
        write_exact(
            sysusers_destination,
            (
                script_dir
                / "serverware-policy-custody.sysusers.conf"
            ).read_bytes(),
            0o444,
        )
        emitted.append(sysusers_destination)

        tmpfiles_destination = (
            staging
            / "tmpfiles.d"
            / "serverware-policy-custody.conf"
        )
        write_exact(
            tmpfiles_destination,
            (
                script_dir
                / "serverware-policy-custody.tmpfiles.conf"
            ).read_bytes(),
            0o444,
        )
        emitted.append(tmpfiles_destination)

        state_capabilities = {
            "durable-recovery-store": ["journal"],
            "cleanup-authorization-consumer": ["state", "journal"],
            "recovery-target-provider": ["journal"],
            "current-signature-authority": [],
            "bounded-cleanup-helper": ["journal"],
        }
        payload_records = {
            path.relative_to(staging).as_posix(): emitted_file_record(
                path, staging
            )
            for path in sorted(emitted)
        }
        installation_manifest = canonical_json(
            {
                "apiVersion": (
                    "serverware.policyCustodyHostInstallation/v1"
                ),
                "authorityMode": "trusted-host-no-tee",
                "hardwareProof": False,
                "coLocated": True,
                "networkAccess": False,
                "runtimeConfig": {
                    "installRoot": runtime_config_root,
                    "activationMode": (
                        "root-owned-atomic-current-symlink/v1"
                    ),
                    "generationDirectoryMode": "0500",
                    "configMode": "0400",
                },
                "driverIdentity": driver_identity,
                "socketContract": {
                    "directory": "/run/serverware/policy-custody",
                    "directoryMode": "0750",
                    "ownerUser": "root",
                    "ownerGroup": socket_access_group["group"],
                    "ownerGroupGid": socket_access_group["gid"],
                    "socketMode": "0660",
                    "addressFamily": "AF_UNIX",
                    "socketType": "SOCK_SEQPACKET",
                    "backlog": 1,
                    "passCredentials": True,
                },
                "socketActivationTarget": (
                    "serverware-policy-custody-sockets.target"
                ),
                "readinessTarget": (
                    "serverware-policy-custody.target"
                ),
                "services": [
                    {
                        "role": role,
                        "identity": service_identities[role],
                        "binary": release_binaries[role],
                        "configCredential": (
                            f"serverware-policy-custody-{role}.json"
                        ),
                        "socketPath": (
                            "/run/serverware/policy-custody/"
                            f"{role}.sock"
                        ),
                        "stateCapabilities": [
                            (
                                "/var/lib/serverware/policy-custody/"
                                f"{role}/{name}"
                            )
                            for name in state_capabilities[role]
                        ],
                    }
                    for role in ROLES
                ],
                "payloadOutputs": payload_records,
            }
        ).encode("ascii")
        installation_manifest_path = (
            staging / "policy-custody-host-installation.json"
        )
        write_exact(
            installation_manifest_path,
            installation_manifest,
            0o400,
        )
        emitted.append(installation_manifest_path)

        output_hashes = {}
        for path in sorted(emitted):
            relative = path.relative_to(staging).as_posix()
            output_hashes[relative] = (
                "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
            )
        source_manifest_sha256 = (
            "sha256:"
            + hashlib.sha256(manifest_bytes).hexdigest()
        )
        receipt = canonical_json(
            {
                "apiVersion": (
                    "serverware.policyCustodyRenderedAssets/v5"
                ),
                "runtimeConfigMode": RUNTIME_CONFIG_MODE,
                "runtimeConfigInstallRoot": runtime_config_root,
                "sourceManifestSha256": source_manifest_sha256,
                "outputs": output_hashes,
            }
        ).encode("ascii")
        receipt_path = staging / "rendered-assets.json"
        write_exact(receipt_path, receipt, 0o400)
        directories = {
            path.parent for path in (*emitted, receipt_path)
        }
        directories.add(staging)
        for directory in sorted(
            directories,
            key=lambda path: len(path.parts),
            reverse=True,
        ):
            fsync_directory(directory)
        for directory in sorted(
            directories,
            key=lambda path: len(path.parts),
            reverse=True,
        ):
            os.chmod(
                directory,
                (
                    0o500
                    if directory
                    in {staging, staging / "runtime-config"}
                    else 0o555
                ),
            )
            fsync_directory(directory)
        os.rename(staging, output)
        fsync_directory(output.parent)
    except BaseException:
        for path in sorted(
            staging.rglob("*"), reverse=True
        ):
            try:
                path.rmdir() if path.is_dir() else path.unlink()
            except OSError:
                pass
        try:
            staging.rmdir()
        except OSError:
            pass
        raise


if __name__ == "__main__":
    main()
