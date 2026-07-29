#!/usr/bin/env python3
"""Externally installed launcher for promoted OCI verification lanes.

The launcher is part of the external Coder/TEE trust root. It does not execute
repository code and does not inspect a container daemon. It validates the
signed promotion receipt and Manifest v6, authenticates the live root watchdog,
and requests only manifest-selected OCI lanes.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import re
import secrets
import signal
import socket
import stat
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


MAX_JSON_BYTES = 32 * 1024 * 1024
MAX_RUNTIME_BYTES = 8 * 1024 * 1024 * 1024
MAX_RUNTIME_FILES = 200_000
MAX_MESSAGE_BYTES = 4 * 1024 * 1024
MAX_LANE_SECONDS = 3600
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
NONCE_RE = re.compile(r"^[0-9a-f]{64}$")
LEASE_RE = re.compile(r"^[0-9a-f]{64}$")
RUNTIME_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@+-]{11,255}$")
LANE_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{0,63}$")
ENV_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,127}$")
PROMOTION_RECEIPT_VERSION = "serverware.verificationPromotionReceipt/v4"
PROMOTION_ACCEPTANCE_VERSION = "serverware.verificationPromotionAcceptance/v2"
BUILD_MANIFEST_VERSION = "serverware.consolidatedTestArtifacts/v6"
TRUSTED_RUNTIME_VERSION = "serverware.trustedLauncherRuntime/v4"
WATCHDOG_PROTOCOL_VERSION = "serverware.ociVerificationWatchdog/v4"
SOURCE_SELECTION_MODEL = (
    "signed-raw-git-index-tree-worktree-status-plus-approved-untracked/v3"
)
PROMOTION_SIGNATURE_DOMAIN = (
    b"serverware.verificationPromotionReceipt/v4\x00Ed25519\x00"
)
CONTROL_MESSAGE_DOMAIN = b"serverware.ociWatchdogMessage/v4\x00"
DAEMON_EVIDENCE_DOMAIN = b"serverware.ociDaemonEvidence/v1\x00"
RUNTIME_EVIDENCE_SIGNATURE_DOMAIN = (
    b"serverware.ociRuntimeEvidence/v2\x00Ed25519\x00"
)
CAPABILITY_ATTESTATION_SIGNATURE_DOMAIN = (
    b"serverware.dependencyCapabilityAttestation/v1\x00Ed25519\x00"
)
ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
ED25519_FIELD = 2**255 - 19
ED25519_ORDER = 2**252 + 27742317777372353535851937790883648493
ED25519_D = (
    -121665 * pow(121666, ED25519_FIELD - 2, ED25519_FIELD)
) % ED25519_FIELD
ED25519_SQRT_M1 = pow(2, (ED25519_FIELD - 1) // 4, ED25519_FIELD)
ED25519_IDENTITY = (0, 1, 1, 0)
REQUIRED_MOUNT_OPTIONS = frozenset({"nodev", "nosuid", "ro"})
WATCHDOG_SOCKET_PATH = Path("/run/serverware-watchdog/control.sock")
DAEMON_SOCKET_PATH = Path(
    "/run/serverware-verification-daemon/containerd.sock"
)
BOOT_ID_PATH = Path("/proc/sys/kernel/random/boot_id")
PYTHON_CAPABILITY_PROBES = [
    "dns-nss-local-bounded",
    "multiprocessing-spawn-bounded",
    "openssl-provider-load",
    "sqlite-memory-and-file",
]
LANE_ORDER = (
    "approval-review",
    "browser-python-compatibility",
    "chromium-compatibility",
    "clean-room",
    "credential-constraints",
    "credential-constraints-proxy",
    "host-python-compatibility",
    "internal-service-auth",
    "jit-transaction-sqlite-full",
    "onboarding-evidence",
    "portal-browser-oauth",
    "proxy-python-compatibility",
    "rust-decision-gate-tests",
    "webauthn-attestation",
)
IMAGE_ORDER = tuple(f"lane-{name}" for name in LANE_ORDER) + (
    "npm-publish-companion",
)
BASE_ENVIRONMENT = {
    "HOME": "/work/home",
    "LANG": "C",
    "LC_ALL": "C",
    "PYTHONDONTWRITEBYTECODE": "1",
    "PYTHONHASHSEED": "0",
    "PYTHONNOUSERSITE": "1",
    "TMPDIR": "/work/tmp",
    "TZ": "UTC",
    "XDG_RUNTIME_DIR": "/run/serverware-runtime",
}
PORTAL_DYNAMIC_ENVIRONMENT = [
    "SERVERWARE_ATTEMPT",
    "SERVERWARE_LANE",
    "SERVERWARE_LEASE_ID",
    "SERVERWARE_MANIFEST_SHA256",
    "SERVERWARE_NPM_COMPANION_IMAGE_ID",
    "SERVERWARE_NPM_ENTRYPOINT_SHA256",
    "SERVERWARE_NPM_NODE_SHA256",
    "SERVERWARE_NPM_PACKAGE_SHA256",
    "SERVERWARE_ONE_USE_NONCE",
    "SERVERWARE_PROMOTION_RECEIPT_SHA256",
    "SERVERWARE_WATCHDOG_ENDPOINT",
    "SERVERWARE_WATCHDOG_TLS_SPKI_SHA256",
]
RESOURCE_KINDS = frozenset({"container", "network", "snapshot", "task"})
LANE_SOURCE_CONTRACTS = {
    "approval-review": {
        "exact": [
            "scripts/oci_lane_entrypoint.py",
            "scripts/test_approval_review.py",
        ],
        "prefixes": ["serverware/", "serverware_agent_trust/"],
    },
    "browser-python-compatibility": {
        "exact": ["scripts/oci_lane_entrypoint.py"],
        "prefixes": [],
    },
    "chromium-compatibility": {
        "exact": ["scripts/oci_lane_entrypoint.py"],
        "prefixes": [],
    },
    "clean-room": {
        "exact": [
            "scripts/oci_lane_entrypoint.py",
            "scripts/test_agent_trust_clean_room.py",
            "scripts/verify_offline_artifact_manifest.py",
        ],
        "prefixes": ["serverware_agent_trust/"],
    },
    "credential-constraints": {
        "exact": [
            "scripts/oci_lane_entrypoint.py",
            "scripts/test_credential_constraints.py",
        ],
        "prefixes": ["serverware/", "serverware_agent_trust/"],
    },
    "credential-constraints-proxy": {
        "exact": [
            "scripts/oci_lane_entrypoint.py",
            "scripts/test_credential_constraints.py",
        ],
        "prefixes": ["serverware/", "serverware_agent_trust/"],
    },
    "host-python-compatibility": {
        "exact": ["scripts/oci_lane_entrypoint.py"],
        "prefixes": [],
    },
    "internal-service-auth": {
        "exact": [
            "scripts/oci_lane_entrypoint.py",
            "scripts/test_internal_service_auth.py",
        ],
        "prefixes": ["serverware/", "serverware_agent_trust/"],
    },
    "jit-transaction-sqlite-full": {
        "exact": [
            "scripts/oci_lane_entrypoint.py",
            "scripts/test_jit_transaction_state.py",
        ],
        "prefixes": ["serverware/", "serverware_agent_trust/"],
    },
    "onboarding-evidence": {
        "exact": [
            "scripts/oci_lane_entrypoint.py",
            "scripts/test_onboarding_evidence.py",
            "scripts/verify_onboarding_evidence.py",
        ],
        "prefixes": ["serverware/", "serverware_agent_trust/"],
    },
    "portal-browser-oauth": {
        "exact": [
            "scripts/oauth_provider_simulator.py",
            "scripts/oci_lane_entrypoint.py",
            "scripts/test_portal_browser_oauth.py",
        ],
        "prefixes": [
            "data-plane/decision-gate-rs/",
            "serverware/",
            "serverware_agent_trust/",
        ],
    },
    "proxy-python-compatibility": {
        "exact": ["scripts/oci_lane_entrypoint.py"],
        "prefixes": [],
    },
    "rust-decision-gate-tests": {
        "exact": [],
        "prefixes": ["data-plane/decision-gate-rs/"],
    },
    "webauthn-attestation": {
        "exact": [
            "scripts/oci_lane_entrypoint.py",
            "scripts/test_webauthn_attestation.py",
        ],
        "prefixes": ["serverware/", "serverware_agent_trust/"],
    },
}
DEPENDENCY_CAPABILITIES = {
    "browser-runtime": ["chromium", "python"],
    "clean-room-runtime": [
        "packaging-25.0",
        "python",
        "sealed-wheelhouse",
    ],
    "npm-11.8-runtime": ["node", "npm-11.8"],
    "python-runtime": ["python"],
    "rust-runtime": ["rust-test-binary"],
}
DEPENDENCY_ALLOWED_CAPABILITY_CLASSES = {
    "browser-runtime": [
        "chromium-helper",
        "chromium-runtime",
        "python-runtime",
        "runtime-data",
        "shared-library",
    ],
    "clean-room-runtime": [
        "clean-room-payload",
        "pep508-parser",
        "python-runtime",
        "runtime-data",
        "shared-library",
    ],
    "npm-11.8-runtime": [
        "node-runtime",
        "npm-package-manager",
        "runtime-data",
        "shared-library",
    ],
    "python-runtime": [
        "python-runtime",
        "runtime-data",
        "shared-library",
    ],
    "rust-runtime": [
        "fixed-rust-test-binary",
        "runtime-data",
        "shared-library",
    ],
}
PORTAL_FORBIDDEN_CAPABILITY_CLASSES = frozenset(
    {
        "build-tool",
        "compiler",
        "dynamic-command-loader",
        "generic-command-execution",
        "node-runtime",
        "npm-package-manager",
        "package-manager",
        "shell",
    }
)


class LauncherError(RuntimeError):
    pass


class StoreOnce(argparse.Action):
    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: Any,
        option_string: str | None = None,
    ) -> None:
        if getattr(namespace, self.dest, None) is not None:
            parser.error(f"{option_string or self.dest} may be specified only once")
        setattr(namespace, self.dest, values)


class AppendUnique(argparse.Action):
    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: Any,
        option_string: str | None = None,
    ) -> None:
        current = list(getattr(namespace, self.dest, None) or ())
        if values in current:
            parser.error(f"{option_string or self.dest} contains a duplicate value")
        current.append(values)
        setattr(namespace, self.dest, current)


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise LauncherError(f"JSON contains duplicate key: {key}")
        result[key] = value
    return result


def _reject_number(value: str) -> None:
    raise LauncherError(f"JSON contains an unsupported number: {value}")


def _canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise LauncherError("value is not canonical JSON") from exc


def _load_json(raw: bytes, *, label: str) -> Any:
    if len(raw) > MAX_JSON_BYTES:
        raise LauncherError(f"{label} exceeds its byte limit")
    try:
        return json.loads(
            raw.decode("ascii"),
            object_pairs_hook=_strict_object,
            parse_constant=_reject_number,
            parse_float=_reject_number,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise LauncherError(f"{label} is not strict ASCII JSON") from exc


def _sha256(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _required_digest(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise LauncherError(f"{label} must be sha256:<64 lowercase hex>")
    return value


def _absolute(path: Path, *, label: str) -> Path:
    if not path.is_absolute() or "\x00" in str(path):
        raise LauncherError(f"{label} must be one absolute path")
    if any(part in {"", ".", ".."} for part in path.parts[1:]):
        raise LauncherError(f"{label} contains an unsafe component")
    return path


def _read_fd_stable(
    descriptor: int,
    *,
    label: str,
    max_bytes: int,
) -> tuple[bytes, os.stat_result]:
    before = os.fstat(descriptor)
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise LauncherError(f"{label} is not a single-link regular file")
    if before.st_size < 0 or before.st_size > max_bytes:
        raise LauncherError(f"{label} exceeds its byte limit")
    os.lseek(descriptor, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    total = 0
    while True:
        raw = os.read(descriptor, min(1024 * 1024, max_bytes + 1 - total))
        if not raw:
            break
        chunks.append(raw)
        total += len(raw)
        if total > max_bytes:
            raise LauncherError(f"{label} exceeds its byte limit")
    after = os.fstat(descriptor)
    identity = lambda item: (
        item.st_dev,
        item.st_ino,
        item.st_mode,
        item.st_uid,
        item.st_gid,
        item.st_nlink,
        item.st_size,
        item.st_mtime_ns,
        item.st_ctime_ns,
    )
    if identity(before) != identity(after):
        raise LauncherError(f"{label} changed while read")
    return b"".join(chunks), after


def _safe_directory_descriptor(path: Path, *, label: str) -> int:
    absolute = _absolute(path, label=label)
    descriptor = os.open(
        "/",
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0),
    )
    try:
        root = os.fstat(descriptor)
        if root.st_uid != 0 or stat.S_IMODE(root.st_mode) & 0o022:
            raise LauncherError("filesystem root is not root-controlled")
        for component in absolute.parts[1:]:
            next_descriptor = os.open(
                component,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NONBLOCK", 0)
                | os.O_NOFOLLOW,
                dir_fd=descriptor,
            )
            metadata = os.fstat(next_descriptor)
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid != 0
                or stat.S_IMODE(metadata.st_mode) & 0o022
            ):
                os.close(next_descriptor)
                raise LauncherError(f"{label} has an unsafe ancestor")
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _safe_ancestor_identities(path: Path, *, label: str) -> list[dict[str, Any]]:
    absolute = _absolute(path, label=label)
    descriptor = os.open(
        "/",
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0),
    )
    identities: list[dict[str, Any]] = []
    current = Path("/")
    try:
        for index, component in enumerate(("/", *absolute.parts[1:])):
            if index:
                next_descriptor = os.open(
                    component,
                    os.O_RDONLY
                    | getattr(os, "O_DIRECTORY", 0)
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NONBLOCK", 0)
                    | os.O_NOFOLLOW,
                    dir_fd=descriptor,
                )
                os.close(descriptor)
                descriptor = next_descriptor
                current /= component
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid != 0
                or metadata.st_gid != 0
                or stat.S_IMODE(metadata.st_mode) & 0o022
            ):
                raise LauncherError(f"{label} has an unsafe ancestor")
            identities.append(
                {
                    "device": metadata.st_dev,
                    "gid": metadata.st_gid,
                    "inode": metadata.st_ino,
                    "mode": stat.S_IMODE(metadata.st_mode),
                    "nlink": metadata.st_nlink,
                    "path": str(current),
                    "uid": metadata.st_uid,
                }
            )
        return identities
    finally:
        os.close(descriptor)


def _open_safe_regular(path: Path, *, label: str) -> tuple[int, Path]:
    absolute = _absolute(path, label=label)
    parent = _safe_directory_descriptor(absolute.parent, label=f"{label} parent")
    try:
        descriptor = os.open(
            absolute.name,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NONBLOCK", 0)
            | os.O_NOFOLLOW,
            dir_fd=parent,
        )
    finally:
        os.close(parent)
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) & 0o222
    ):
        os.close(descriptor)
        raise LauncherError(f"{label} is not root-owned and immutable")
    return descriptor, absolute


def _file_identity_from_fd(
    descriptor: int,
    *,
    path: Path,
    label: str,
    max_bytes: int = MAX_RUNTIME_BYTES,
) -> tuple[dict[str, Any], bytes]:
    raw, metadata = _read_fd_stable(
        descriptor,
        label=label,
        max_bytes=max_bytes,
    )
    return {
        "device": metadata.st_dev,
        "gid": metadata.st_gid,
        "inode": metadata.st_ino,
        "mode": stat.S_IMODE(metadata.st_mode),
        "nlink": metadata.st_nlink,
        "path": str(path),
        "sha256": _sha256(raw),
        "size": len(raw),
        "uid": metadata.st_uid,
    }, raw


def _read_safe_regular(
    path: Path,
    *,
    label: str,
    max_bytes: int = MAX_JSON_BYTES,
) -> tuple[dict[str, Any], bytes]:
    descriptor, absolute = _open_safe_regular(path, label=label)
    try:
        return _file_identity_from_fd(
            descriptor,
            path=absolute,
            label=label,
            max_bytes=max_bytes,
        )
    finally:
        os.close(descriptor)


def _mountinfo_unescape(value: str) -> str:
    return re.sub(
        r"\\([0-7]{3})",
        lambda match: chr(int(match.group(1), 8)),
        value,
    )


def _mount_evidence(path: Path) -> dict[str, Any]:
    try:
        lines = Path("/proc/self/mountinfo").read_text(
            encoding="ascii"
        ).splitlines()
    except (OSError, UnicodeError) as exc:
        raise LauncherError("cannot read the current mount table") from exc
    matches: list[tuple[int, dict[str, Any]]] = []
    for raw in lines:
        before, separator, after = raw.partition(" - ")
        fields = before.split()
        trailing = after.split()
        if (
            not separator
            or len(fields) < 6
            or len(trailing) < 3
            or not fields[0].isdigit()
            or not fields[1].isdigit()
        ):
            raise LauncherError("mount table contains a malformed record")
        mountpoint = Path(_mountinfo_unescape(fields[4]))
        if not mountpoint.is_absolute() or not (
            path == mountpoint or path.is_relative_to(mountpoint)
        ):
            continue
        evidence = {
            "device": fields[2],
            "filesystem": trailing[0],
            "mountId": int(fields[0]),
            "mountPoint": str(mountpoint),
            "options": sorted(set(fields[5].split(","))),
            "parentMountId": int(fields[1]),
            "root": _mountinfo_unescape(fields[3]),
            "superOptions": sorted(set(trailing[2].split(","))),
        }
        matches.append((len(mountpoint.parts), evidence))
    if not matches:
        raise LauncherError(f"path has no mount evidence: {path}")
    specificity = max(depth for depth, _ in matches)
    exact = [item for depth, item in matches if depth == specificity]
    if len(exact) != 1:
        raise LauncherError(f"path is hidden by ambiguous stacked mounts: {path}")
    return exact[0]


def _require_mount(
    path: Path,
    expected: Any,
    *,
    label: str,
    allowed_mount_ids: set[int],
) -> dict[str, Any]:
    actual = _mount_evidence(path)
    options = set(actual["options"]) | set(actual["superOptions"])
    if (
        not isinstance(expected, dict)
        or actual != expected
        or actual["mountId"] not in allowed_mount_ids
        or not REQUIRED_MOUNT_OPTIONS.issubset(options)
        or not os.statvfs(path).f_flag & getattr(os, "ST_RDONLY", 1)
    ):
        raise LauncherError(f"{label} is not on its allowlisted read-only mount")
    return actual


def _ed25519_add(
    left: tuple[int, int, int, int],
    right: tuple[int, int, int, int],
) -> tuple[int, int, int, int]:
    x1, y1, z1, t1 = left
    x2, y2, z2, t2 = right
    field = ED25519_FIELD
    a = ((y1 - x1) * (y2 - x2)) % field
    b = ((y1 + x1) * (y2 + x2)) % field
    c = (2 * ED25519_D * t1 * t2) % field
    d = (2 * z1 * z2) % field
    e = (b - a) % field
    f = (d - c) % field
    g = (d + c) % field
    h = (b + a) % field
    return (
        (e * f) % field,
        (g * h) % field,
        (f * g) % field,
        (e * h) % field,
    )


def _ed25519_double(
    point: tuple[int, int, int, int],
) -> tuple[int, int, int, int]:
    x, y, z, _ = point
    field = ED25519_FIELD
    a = (x * x) % field
    b = (y * y) % field
    c = (2 * z * z) % field
    d = (-a) % field
    e = ((x + y) * (x + y) - a - b) % field
    g = (d + b) % field
    f = (g - c) % field
    h = (d - b) % field
    return (
        (e * f) % field,
        (g * h) % field,
        (f * g) % field,
        (e * h) % field,
    )


def _ed25519_multiply(
    point: tuple[int, int, int, int],
    scalar: int,
) -> tuple[int, int, int, int]:
    if scalar < 0:
        raise LauncherError("Ed25519 scalar is negative")
    result = ED25519_IDENTITY
    addend = point
    value = scalar
    while value:
        if value & 1:
            result = _ed25519_add(result, addend)
        addend = _ed25519_double(addend)
        value >>= 1
    return result


def _ed25519_equal(
    left: tuple[int, int, int, int],
    right: tuple[int, int, int, int],
) -> bool:
    return (
        (left[0] * right[2] - right[0] * left[2]) % ED25519_FIELD == 0
        and (left[1] * right[2] - right[1] * left[2]) % ED25519_FIELD == 0
    )


def _ed25519_encode(point: tuple[int, int, int, int]) -> bytes:
    inverse = pow(point[2], ED25519_FIELD - 2, ED25519_FIELD)
    x = (point[0] * inverse) % ED25519_FIELD
    y = (point[1] * inverse) % ED25519_FIELD
    encoded = bytearray(y.to_bytes(32, "little"))
    encoded[31] |= (x & 1) << 7
    return bytes(encoded)


def _ed25519_decode(
    encoded: bytes,
    *,
    label: str,
) -> tuple[int, int, int, int]:
    if len(encoded) != 32:
        raise LauncherError(f"{label} is not 32 bytes")
    sign = encoded[31] >> 7
    y = int.from_bytes(encoded, "little") & ((1 << 255) - 1)
    if y >= ED25519_FIELD:
        raise LauncherError(f"{label} is not canonical")
    y_squared = y * y % ED25519_FIELD
    denominator = (ED25519_D * y_squared + 1) % ED25519_FIELD
    if denominator == 0:
        raise LauncherError(f"{label} is not on the curve")
    x_squared = (
        (y_squared - 1)
        * pow(denominator, ED25519_FIELD - 2, ED25519_FIELD)
    ) % ED25519_FIELD
    x = pow(x_squared, (ED25519_FIELD + 3) // 8, ED25519_FIELD)
    if (x * x - x_squared) % ED25519_FIELD:
        x = x * ED25519_SQRT_M1 % ED25519_FIELD
    if (x * x - x_squared) % ED25519_FIELD:
        raise LauncherError(f"{label} is not on the curve")
    if (x & 1) != sign:
        x = (-x) % ED25519_FIELD
    if x == 0 and sign:
        raise LauncherError(f"{label} has a non-canonical sign bit")
    point = (x, y, 1, x * y % ED25519_FIELD)
    if _ed25519_encode(point) != encoded:
        raise LauncherError(f"{label} is not canonical")
    if _ed25519_equal(_ed25519_multiply(point, 8), ED25519_IDENTITY):
        raise LauncherError(f"{label} has small order")
    if not _ed25519_equal(
        _ed25519_multiply(point, ED25519_ORDER),
        ED25519_IDENTITY,
    ):
        raise LauncherError(f"{label} is outside the prime-order subgroup")
    return point


def _verify_ed25519(
    *,
    public_key: bytes,
    signature: bytes,
    message: bytes,
) -> None:
    if len(signature) != 64:
        raise LauncherError("receipt signature is not 64 bytes")
    public_point = _ed25519_decode(public_key, label="promotion public key")
    encoded_r = signature[:32]
    r_point = _ed25519_decode(encoded_r, label="receipt signature R")
    scalar = int.from_bytes(signature[32:], "little")
    if scalar >= ED25519_ORDER:
        raise LauncherError("receipt signature scalar is non-canonical")
    base_point = _ed25519_decode(
        b"\x58" + b"\x66" * 31,
        label="trusted Ed25519 base point",
    )
    challenge = int.from_bytes(
        hashlib.sha512(encoded_r + public_key + message).digest(),
        "little",
    ) % ED25519_ORDER
    if not _ed25519_equal(
        _ed25519_multiply(base_point, scalar),
        _ed25519_add(r_point, _ed25519_multiply(public_point, challenge)),
    ):
        raise LauncherError("promotion receipt signature is invalid")


def _load_public_key(
    args: argparse.Namespace,
) -> tuple[dict[str, Any], bytes]:
    identity, raw = _read_safe_regular(
        args.promotion_public_key,
        label="promotion public key",
        max_bytes=1024,
    )
    if (
        identity["sha256"]
        != args.expected_promotion_public_key_spki_sha256
        or len(raw) != len(ED25519_SPKI_PREFIX) + 32
        or not raw.startswith(ED25519_SPKI_PREFIX)
    ):
        raise LauncherError("promotion public key differs from its SPKI pin")
    public_key = raw[len(ED25519_SPKI_PREFIX) :]
    raw_digest = _sha256(public_key)
    if raw_digest != args.expected_promotion_public_key_raw_sha256:
        raise LauncherError("promotion public key differs from its raw-key pin")
    _ed25519_decode(public_key, label="promotion public key")
    return {**identity, "rawKeySha256": raw_digest}, public_key


def _load_capability_authority_public_key(
    args: argparse.Namespace,
) -> tuple[dict[str, Any], bytes]:
    identity, raw = _read_safe_regular(
        args.capability_authority_public_key,
        label="dependency capability authority public key",
        max_bytes=1024,
    )
    if (
        identity["sha256"]
        != args.expected_capability_authority_public_key_spki_sha256
        or len(raw) != len(ED25519_SPKI_PREFIX) + 32
        or not raw.startswith(ED25519_SPKI_PREFIX)
    ):
        raise LauncherError(
            "dependency capability authority key differs from its SPKI pin"
        )
    public_key = raw[len(ED25519_SPKI_PREFIX) :]
    raw_digest = _sha256(public_key)
    if (
        raw_digest
        != args.expected_capability_authority_public_key_raw_sha256
    ):
        raise LauncherError(
            "dependency capability authority key differs from its raw pin"
        )
    _ed25519_decode(
        public_key,
        label="dependency capability authority public key",
    )
    return {**identity, "rawKeySha256": raw_digest}, public_key


def _closure(root: Path) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    absolute = _absolute(root, label="trusted runtime root")
    root_fd = _safe_directory_descriptor(absolute, label="trusted runtime root")
    entries: list[dict[str, Any]] = []
    identities: dict[str, dict[str, Any]] = {}
    total = 0

    def walk(descriptor: int, relative: tuple[str, ...]) -> None:
        nonlocal total
        names = sorted(os.listdir(descriptor))
        for name in names:
            if name in {"", ".", ".."} or "/" in name or "\x00" in name:
                raise LauncherError("trusted runtime contains an unsafe name")
            metadata = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            path = absolute.joinpath(*relative, name)
            if metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) & 0o222:
                raise LauncherError(f"trusted runtime entry is mutable: {path}")
            if stat.S_ISDIR(metadata.st_mode):
                child = os.open(
                    name,
                    os.O_RDONLY
                    | getattr(os, "O_DIRECTORY", 0)
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NONBLOCK", 0)
                    | os.O_NOFOLLOW,
                    dir_fd=descriptor,
                )
                try:
                    entries.append(
                        {
                            "mode": stat.S_IMODE(metadata.st_mode),
                            "path": str(path),
                            "type": "directory",
                        }
                    )
                    walk(child, (*relative, name))
                finally:
                    os.close(child)
                continue
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise LauncherError(
                    f"trusted runtime contains a non-regular entry: {path}"
                )
            child = os.open(
                name,
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NONBLOCK", 0)
                | os.O_NOFOLLOW,
                dir_fd=descriptor,
            )
            try:
                identity, _ = _file_identity_from_fd(
                    child,
                    path=path,
                    label="trusted runtime file",
                )
            finally:
                os.close(child)
            total += identity["size"]
            if total > MAX_RUNTIME_BYTES or len(entries) >= MAX_RUNTIME_FILES:
                raise LauncherError("trusted runtime closure exceeds its bound")
            entries.append({"identity": identity, "type": "file"})
            identities[str(path)] = identity

    try:
        walk(root_fd, ())
    finally:
        os.close(root_fd)
    payload = {
        "aggregateBytes": total,
        "entries": entries,
        "fileCount": len(identities),
        "path": str(absolute),
    }
    return {
        **payload,
        "closureSha256": _sha256(_canonical_json(payload)),
    }, identities


def _identity_list(
    value: Any,
    *,
    label: str,
    identities: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    if not isinstance(value, list) or value != sorted(
        value,
        key=lambda item: str(item.get("path") if isinstance(item, dict) else ""),
    ):
        raise LauncherError(f"{label} is not a sorted identity list")
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for expected in value:
        if (
            not isinstance(expected, dict)
            or not isinstance(expected.get("path"), str)
            or expected["path"] in seen
            or identities.get(expected["path"]) != expected
        ):
            raise LauncherError(f"{label} differs from the immutable root")
        seen.add(expected["path"])
        result.append(expected)
    return result


def _load_trusted_runtime(
    args: argparse.Namespace,
    *,
    receipt_runtime: dict[str, Any],
    public_key_identity: dict[str, Any],
    capability_key_identity: dict[str, Any],
    allowed_mount_ids: set[int],
) -> dict[str, Any]:
    manifest_identity, raw = _read_safe_regular(
        args.trusted_runtime_manifest,
        label="trusted runtime manifest",
        max_bytes=8 * 1024 * 1024,
    )
    if manifest_identity["sha256"] != args.expected_runtime_manifest_sha256:
        raise LauncherError("trusted runtime manifest differs from its pin")
    document = _load_json(raw, label="trusted runtime manifest")
    required = {
        "apiVersion",
        "baseMeasurement",
        "dependencyCapabilityAuthorityPublicKey",
        "extensionModules",
        "helperDsos",
        "immutableRoot",
        "launcher",
        "loader",
        "promotionPublicKey",
        "python",
        "rootClosure",
        "runtimeManifestSha256",
        "stdlibRoots",
    }
    if (
        raw != _canonical_json(document) + b"\n"
        or not isinstance(document, dict)
        or set(document) != required
        or document.get("apiVersion") != TRUSTED_RUNTIME_VERSION
        or document.get("baseMeasurement") != args.expected_base_measurement
    ):
        raise LauncherError("trusted runtime manifest fields are invalid")
    payload = dict(document)
    internal_digest = payload.pop("runtimeManifestSha256", None)
    if internal_digest != _sha256(_canonical_json(payload)):
        raise LauncherError("trusted runtime manifest digest is invalid")
    root = _absolute(Path(str(document["immutableRoot"])), label="runtime root")
    for external_path, label in (
        (args.manifest, "promoted Manifest v6"),
        (args.promotion_receipt, "promotion receipt"),
        (args.trusted_runtime_manifest, "trusted runtime manifest"),
    ):
        if external_path == root or external_path.is_relative_to(root):
            raise LauncherError(
                f"{label} must be outside the runtime closure to avoid "
                "a self-referential digest"
            )
    closure, identities = _closure(root)
    if document["rootClosure"] != closure:
        raise LauncherError("trusted runtime closure changed")
    launcher_identity = identities.get(str(Path(__file__)))
    python_identity = identities.get(str(args.expected_python_path))
    key_identity = identities.get(str(args.promotion_public_key))
    capability_identity = identities.get(
        str(args.capability_authority_public_key)
    )
    if (
        not isinstance(launcher_identity, dict)
        or not isinstance(python_identity, dict)
        or not isinstance(key_identity, dict)
        or not isinstance(capability_identity, dict)
        or launcher_identity != document["launcher"]
        or python_identity != document["python"]
        or key_identity != document["promotionPublicKey"]
        or key_identity != {
            key: value
            for key, value in public_key_identity.items()
            if key != "rawKeySha256"
        }
        or capability_identity
        != document["dependencyCapabilityAuthorityPublicKey"]
        or capability_identity
        != {
            key: value
            for key, value in capability_key_identity.items()
            if key != "rawKeySha256"
        }
        or launcher_identity.get("sha256") != args.expected_launcher_sha256
        or python_identity.get("sha256") != args.expected_python_sha256
        or Path(sys.executable) != args.expected_python_path
    ):
        raise LauncherError("trusted launcher, Python, or key identity changed")
    loader = _identity_list(
        [document["loader"]],
        label="trusted loader",
        identities=identities,
    )[0]
    extensions = _identity_list(
        document["extensionModules"],
        label="trusted extension modules",
        identities=identities,
    )
    helper_dsos = _identity_list(
        document["helperDsos"],
        label="trusted helper DSOs",
        identities=identities,
    )
    stdlib_values = document["stdlibRoots"]
    if (
        not isinstance(stdlib_values, list)
        or not stdlib_values
        or any(
            not isinstance(item, str)
            or not Path(item).is_absolute()
            or not (
                Path(item) == root or Path(item).is_relative_to(root)
            )
            for item in stdlib_values
        )
        or len(stdlib_values) != len(set(stdlib_values))
        or stdlib_values != [item for item in sys.path if item]
        or any(
            not (
                Path(prefix) == root or Path(prefix).is_relative_to(root)
            )
            for prefix in {
                sys.base_exec_prefix,
                sys.base_prefix,
                sys.exec_prefix,
                sys.prefix,
            }
        )
    ):
        raise LauncherError("trusted live Python stdlib path/prefixes are invalid")
    shared_objects = {
        path
        for path in identities
        if Path(path).name.endswith(".so") or ".so." in Path(path).name
    }
    classified = {
        loader["path"],
        *(item["path"] for item in extensions),
        *(item["path"] for item in helper_dsos),
    }
    if shared_objects != classified:
        raise LauncherError("trusted runtime shared objects are not exact")
    if (
        not isinstance(receipt_runtime, dict)
        or set(receipt_runtime)
        != {
            "baseMeasurement",
            "dependencyCapabilityAuthorityKeyRawSha256",
            "dependencyCapabilityAuthorityKeySpkiSha256",
            "immutableRoot",
            "mount",
            "promotionPublicKeyRawSha256",
            "promotionPublicKeySpkiSha256",
            "rootClosureSha256",
            "runtimeManifest",
            "runtimeManifestMount",
        }
        or receipt_runtime["baseMeasurement"] != document["baseMeasurement"]
        or receipt_runtime["immutableRoot"] != str(root)
        or receipt_runtime["rootClosureSha256"] != closure["closureSha256"]
        or receipt_runtime["promotionPublicKeyRawSha256"]
        != args.expected_promotion_public_key_raw_sha256
        or receipt_runtime["promotionPublicKeySpkiSha256"]
        != args.expected_promotion_public_key_spki_sha256
        or receipt_runtime[
            "dependencyCapabilityAuthorityKeyRawSha256"
        ]
        != args.expected_capability_authority_public_key_raw_sha256
        or receipt_runtime[
            "dependencyCapabilityAuthorityKeySpkiSha256"
        ]
        != args.expected_capability_authority_public_key_spki_sha256
        or receipt_runtime["runtimeManifest"] != manifest_identity
    ):
        raise LauncherError("receipt trusted-runtime binding is invalid")
    _require_mount(
        root,
        receipt_runtime["mount"],
        label="trusted runtime",
        allowed_mount_ids=allowed_mount_ids,
    )
    _require_mount(
        args.trusted_runtime_manifest,
        receipt_runtime["runtimeManifestMount"],
        label="trusted runtime manifest",
        allowed_mount_ids=allowed_mount_ids,
    )
    return {
        "baseMeasurement": document["baseMeasurement"],
        "immutableRoot": str(root),
        "rootClosureSha256": closure["closureSha256"],
        "runtimeManifestSha256": manifest_identity["sha256"],
    }


def _validate_clean_room_contract(value: Any) -> dict[str, Any]:
    if (
        not isinstance(value, dict)
        or set(value)
        != {
            "apiVersion",
            "contractSha256",
            "derivedEntries",
            "derivedInstallationSha256",
            "exerciseScenarios",
            "installContractSha256",
            "payloadClosureSha256",
            "requirementsResolution",
            "requirementsResolutionSha256",
            "wheelRecords",
            "wheelRecordsSha256",
            "wheelhouseManifestPayloadSha256",
        }
        or value.get("apiVersion")
        != "serverware.cleanRoomExpectedDerivation/v1"
    ):
        raise LauncherError("clean-room semantic contract is invalid")
    payload = dict(value)
    supplied = payload.pop("contractSha256", None)
    if supplied != _sha256(_canonical_json(payload)):
        raise LauncherError("clean-room semantic contract digest is invalid")
    for key in (
        "derivedInstallationSha256",
        "installContractSha256",
        "payloadClosureSha256",
        "requirementsResolutionSha256",
        "wheelRecordsSha256",
        "wheelhouseManifestPayloadSha256",
    ):
        _required_digest(value.get(key), label=f"clean-room contract {key}")
    if (
        not isinstance(value["derivedEntries"], list)
        or not value["derivedEntries"]
        or value["derivedInstallationSha256"]
        != _sha256(_canonical_json(value["derivedEntries"]))
        or not isinstance(value["requirementsResolution"], list)
        or value["requirementsResolutionSha256"]
        != _sha256(_canonical_json(value["requirementsResolution"]))
        or not isinstance(value["wheelRecords"], list)
        or not value["wheelRecords"]
        or value["wheelRecordsSha256"]
        != _sha256(_canonical_json(value["wheelRecords"]))
        or not isinstance(value["exerciseScenarios"], list)
        or len(value["exerciseScenarios"]) != 3
    ):
        raise LauncherError("clean-room derivation contract is invalid")
    return value


def _validate_image(value: Any, *, role: str) -> dict[str, Any]:
    required = {
        "capabilityAttestation",
        "capabilityCatalog",
        "capabilityCatalogSha256",
        "configDigest",
        "containerdImageId",
        "dependencyClosureSha256",
        "dependencyFileManifestSha256",
        "dependencyPackageInventorySha256",
        "dependencyRole",
        "executableInventorySha256",
        "fileManifestSha256",
        "fixedToolIdentities",
        "independentInspectionSha256",
        "manifestDigest",
        "platform",
        "role",
        "rootfsDiffIds",
        "rootfsDigest",
        "sbomSha256",
        "semanticContract",
    }
    if (
        not isinstance(value, dict)
        or set(value) != required
        or value.get("role") != role
        or value.get("platform") != {"architecture": "amd64", "os": "linux"}
        or value.get("containerdImageId") != value.get("manifestDigest")
        or value.get("dependencyRole")
        != _expected_dependency_role(role.removeprefix("lane-"))
    ):
        raise LauncherError(f"{role} image record is invalid")
    for key in (
        "capabilityCatalogSha256",
        "configDigest",
        "containerdImageId",
        "dependencyClosureSha256",
        "dependencyFileManifestSha256",
        "dependencyPackageInventorySha256",
        "executableInventorySha256",
        "fileManifestSha256",
        "independentInspectionSha256",
        "manifestDigest",
        "rootfsDigest",
        "sbomSha256",
    ):
        _required_digest(value.get(key), label=f"{role} {key}")
    catalog = value["capabilityCatalog"]
    if (
        not isinstance(catalog, dict)
        or catalog.get("apiVersion")
        != "serverware.dependencyCapabilityCatalog/v2"
        or value["capabilityCatalogSha256"]
        != catalog.get("catalogSha256")
    ):
        raise LauncherError(f"{role} capability catalog is invalid")
    catalog_payload = dict(catalog)
    if catalog_payload.pop("catalogSha256", None) != _sha256(
        _canonical_json(catalog_payload)
    ):
        raise LauncherError(f"{role} capability catalog digest is invalid")
    if role == "lane-clean-room":
        _validate_clean_room_contract(value.get("semanticContract"))
    elif value.get("semanticContract") is not None:
        raise LauncherError(f"{role} has an unauthorized semantic contract")
    tools = value["fixedToolIdentities"]
    if role == "npm-publish-companion":
        if (
            not isinstance(tools, dict)
            or set(tools) != {"node", "npmEntrypoint", "npmPackageManifest"}
        ):
            raise LauncherError("npm fixed tool identities are invalid")
        for tool in tools.values():
            if (
                not isinstance(tool, dict)
                or set(tool) != {"path", "sha256", "size"}
                or not isinstance(tool.get("path"), str)
                or not tool["path"].startswith("/")
                or type(tool.get("size")) is not int
                or tool["size"] < 0
            ):
                raise LauncherError("npm fixed tool identity is invalid")
            _required_digest(tool.get("sha256"), label="npm fixed tool")
    elif tools is not None:
        raise LauncherError(f"{role} has unauthorized fixed tool identities")
    for key in ("rootfsDiffIds",):
        items = value.get(key)
        if (
            not isinstance(items, list)
            or not items
            or any(
                not isinstance(item, str)
                or SHA256_RE.fullmatch(item) is None
                for item in items
            )
            or items != list(dict.fromkeys(items))
        ):
            raise LauncherError(f"{role} {key} is invalid")
    return value


def _validate_image_mapping(
    value: Any,
    *,
    role: str,
    imported_image: dict[str, Any],
) -> dict[str, Any]:
    if (
        not isinstance(value, dict)
        or set(value) != {"candidate", "imported", "mappingSha256", "role"}
        or value.get("role") != role
        or value.get("imported") != imported_image
    ):
        raise LauncherError(f"{role} image mapping is invalid")
    candidate = value["candidate"]
    if (
        not isinstance(candidate, dict)
        or set(candidate)
        != {
            "archiveSha256",
            "archiveSize",
            "capabilityAttestation",
            "capabilityCatalog",
            "capabilityCatalogSha256",
            "configDigest",
            "dependencyClosureSha256",
            "dependencyFileManifestSha256",
            "dependencyPackageInventorySha256",
            "dependencyRole",
            "executableInventorySha256",
            "fileManifestSha256",
            "fixedToolIdentities",
            "indexDigest",
            "layerDigests",
            "manifestDigest",
            "rootfsDiffIds",
            "rootfsDigest",
            "sbomSha256",
            "semanticContract",
        }
        or type(candidate.get("archiveSize")) is not int
        or candidate["archiveSize"] <= 0
    ):
        raise LauncherError(f"{role} candidate image mapping is invalid")
    for key in (
        "archiveSha256",
        "capabilityCatalogSha256",
        "configDigest",
        "dependencyClosureSha256",
        "dependencyFileManifestSha256",
        "dependencyPackageInventorySha256",
        "executableInventorySha256",
        "fileManifestSha256",
        "indexDigest",
        "manifestDigest",
        "rootfsDigest",
        "sbomSha256",
    ):
        _required_digest(candidate.get(key), label=f"{role} candidate {key}")
    for key in ("layerDigests", "rootfsDiffIds"):
        if (
            not isinstance(candidate.get(key), list)
            or not candidate[key]
            or any(SHA256_RE.fullmatch(str(item)) is None for item in candidate[key])
        ):
            raise LauncherError(f"{role} candidate {key} is invalid")
    for candidate_key, imported_key in (
        ("capabilityAttestation", "capabilityAttestation"),
        ("capabilityCatalog", "capabilityCatalog"),
        ("capabilityCatalogSha256", "capabilityCatalogSha256"),
        ("configDigest", "configDigest"),
        ("dependencyClosureSha256", "dependencyClosureSha256"),
        ("dependencyFileManifestSha256", "dependencyFileManifestSha256"),
        (
            "dependencyPackageInventorySha256",
            "dependencyPackageInventorySha256",
        ),
        ("dependencyRole", "dependencyRole"),
        ("executableInventorySha256", "executableInventorySha256"),
        ("fileManifestSha256", "fileManifestSha256"),
        ("fixedToolIdentities", "fixedToolIdentities"),
        ("manifestDigest", "manifestDigest"),
        ("rootfsDiffIds", "rootfsDiffIds"),
        ("rootfsDigest", "rootfsDigest"),
        ("sbomSha256", "sbomSha256"),
        ("semanticContract", "semanticContract"),
    ):
        if candidate[candidate_key] != imported_image[imported_key]:
            raise LauncherError(
                f"{role} candidate/imported {candidate_key} mapping differs"
            )
    mapping_payload = {
        "candidate": candidate,
        "imported": imported_image,
        "role": role,
    }
    if value.get("mappingSha256") != _sha256(_canonical_json(mapping_payload)):
        raise LauncherError(f"{role} image mapping digest is invalid")
    return value


def _validate_signed_file_identity(value: Any, *, label: str) -> dict[str, Any]:
    if (
        not isinstance(value, dict)
        or set(value)
        != {
            "device",
            "gid",
            "inode",
            "mode",
            "nlink",
            "path",
            "sha256",
            "size",
            "uid",
        }
        or type(value.get("device")) is not int
        or type(value.get("inode")) is not int
        or type(value.get("mode")) is not int
        or type(value.get("nlink")) is not int
        or type(value.get("size")) is not int
        or type(value.get("uid")) is not int
        or type(value.get("gid")) is not int
        or value["device"] < 0
        or value["inode"] <= 0
        or value["nlink"] != 1
        or value["size"] < 0
        or value["uid"] != 0
        or value["gid"] != 0
        or value["mode"] & 0o222
    ):
        raise LauncherError(f"{label} identity is invalid")
    _absolute(Path(str(value.get("path") or "")), label=label)
    _required_digest(value.get("sha256"), label=f"{label} digest")
    return value


def _validate_signed_mount(value: Any, *, label: str) -> dict[str, Any]:
    if (
        not isinstance(value, dict)
        or set(value)
        != {
            "device",
            "filesystem",
            "mountId",
            "mountPoint",
            "options",
            "parentMountId",
            "root",
            "superOptions",
        }
        or type(value.get("mountId")) is not int
        or type(value.get("parentMountId")) is not int
        or value["mountId"] <= 0
        or value["parentMountId"] < 0
        or not isinstance(value.get("device"), str)
        or not isinstance(value.get("filesystem"), str)
        or not isinstance(value.get("root"), str)
        or not isinstance(value.get("options"), list)
        or not isinstance(value.get("superOptions"), list)
        or any(
            not isinstance(item, str) or not item
            for item in [*value["options"], *value["superOptions"]]
        )
        or value["options"] != sorted(set(value["options"]))
        or value["superOptions"] != sorted(set(value["superOptions"]))
    ):
        raise LauncherError(f"{label} mount evidence is invalid")
    _absolute(Path(str(value.get("mountPoint") or "")), label=f"{label} mountpoint")
    if not REQUIRED_MOUNT_OPTIONS.issubset(
        set(value["options"]) | set(value["superOptions"])
    ):
        raise LauncherError(f"{label} mount is not read-only and hardened")
    return value


def _validate_boot_identity_record(value: Any, *, label: str) -> dict[str, str]:
    if (
        not isinstance(value, dict)
        or set(value) != {"sha256", "value"}
        or re.fullmatch(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
            r"[0-9a-f]{4}-[0-9a-f]{12}",
            str(value.get("value") or ""),
        )
        is None
    ):
        raise LauncherError(f"{label} boot identity is invalid")
    _required_digest(value.get("sha256"), label=f"{label} boot digest")
    return value


def _validate_cgroup_record(
    value: Any,
    *,
    label: str,
    unit: str,
) -> dict[str, Any]:
    if (
        not isinstance(value, dict)
        or set(value) != {"path", "sha256"}
        or not isinstance(value.get("path"), str)
        or not value["path"].startswith("/")
        or not value["path"].endswith("/" + unit)
        or "\x00" in value["path"]
    ):
        raise LauncherError(f"{label} cgroup identity is invalid")
    _required_digest(value.get("sha256"), label=f"{label} cgroup digest")
    return value


def _validate_socket_ancestor_records(
    value: Any,
    *,
    path: Path,
    label: str,
) -> list[dict[str, Any]]:
    expected_paths = [
        str(Path(*path.parent.parts[:index]))
        for index in range(1, len(path.parent.parts) + 1)
    ]
    if (
        not isinstance(value, list)
        or len(value) != len(expected_paths)
    ):
        raise LauncherError(f"{label} safe ancestors are invalid")
    for record, expected_path in zip(value, expected_paths, strict=True):
        if (
            not isinstance(record, dict)
            or set(record)
            != {
                "device",
                "gid",
                "inode",
                "mode",
                "nlink",
                "path",
                "uid",
            }
            or record.get("path") != expected_path
            or type(record.get("device")) is not int
            or type(record.get("inode")) is not int
            or type(record.get("mode")) is not int
            or type(record.get("nlink")) is not int
            or type(record.get("uid")) is not int
            or type(record.get("gid")) is not int
            or record["device"] < 0
            or record["inode"] <= 0
            or record["nlink"] < 1
            or record["uid"] != 0
            or record["gid"] != 0
            or record["mode"] & 0o022
        ):
            raise LauncherError(f"{label} safe ancestor identity is invalid")
    return value


def _validate_boot_cleanup_contract(value: Any) -> dict[str, Any]:
    if (
        not isinstance(value, dict)
        or set(value)
        != {
            "absenceObservations",
            "apiVersion",
            "cleanupTriggers",
            "contractSha256",
            "leaseState",
            "powerLossBoundary",
            "resourceSelection",
            "serviceUnit",
        }
        or value.get("apiVersion")
        != "serverware.ociWatchdogBootCleanup/v1"
        or value.get("absenceObservations") != 3
        or value.get("cleanupTriggers")
        != [
            "boot",
            "client-disconnect",
            "host-service-restart",
            "lane-error",
            "lane-oom",
            "lane-output-cap",
            "lane-signal",
            "lane-timeout",
            "launcher-abort",
            "lease-expiry",
        ]
        or value.get("resourceSelection")
        != "exact-kind-id-pairs-and-complete-label-set"
        or value.get("serviceUnit")
        != "serverware-verification-watchdog.service"
        or value.get("powerLossBoundary")
        != "cleanup-resumes-after-host-power-and-storage-return"
        or value.get("leaseState")
        != {
            "fsyncBeforeLaunch": True,
            "mode": 0o600,
            "owner": "root",
            "path": "/var/lib/serverware-watchdog/leases",
        }
    ):
        raise LauncherError("watchdog boot-cleanup contract is invalid")
    contract = dict(value)
    digest = contract.pop("contractSha256", None)
    if digest != _sha256(_canonical_json(contract)):
        raise LauncherError("watchdog boot-cleanup digest is invalid")
    return value


def _validate_receipt_watchdog(value: Any) -> dict[str, Any]:
    if (
        not isinstance(value, dict)
        or set(value)
        != {
            "bootCleanupContract",
            "laneEndpoint",
            "runtimeEvidencePublicKey",
            "serviceIdentity",
            "socketIdentity",
            "socketPath",
            "socketSafeAncestors",
        }
        or value.get("socketPath") != str(WATCHDOG_SOCKET_PATH)
    ):
        raise LauncherError("receipt watchdog contract is invalid")
    _validate_boot_cleanup_contract(value["bootCleanupContract"])
    endpoint = value["laneEndpoint"]
    if (
        not isinstance(endpoint, dict)
        or set(endpoint)
        != {
            "networkRole",
            "protocol",
            "tlsSpkiSha256",
            "url",
        }
        or endpoint.get("networkRole") != "portal-npm-private"
        or endpoint.get("protocol") != "serverware.npmOneUse/v2"
        or endpoint.get("url")
        != "https://watchdog.serverware.internal/v1/npm-publish-one-use"
    ):
        raise LauncherError("receipt watchdog lane endpoint is invalid")
    _required_digest(
        endpoint.get("tlsSpkiSha256"),
        label="watchdog lane endpoint SPKI",
    )
    runtime_key = value["runtimeEvidencePublicKey"]
    if (
        not isinstance(runtime_key, dict)
        or set(runtime_key) != {"rawKeySha256", "spkiBase64", "spkiSha256"}
        or not isinstance(runtime_key.get("spkiBase64"), str)
    ):
        raise LauncherError("watchdog runtime-evidence key is invalid")
    try:
        runtime_spki = base64.b64decode(
            runtime_key["spkiBase64"], validate=True
        )
    except (ValueError, binascii.Error) as exc:
        raise LauncherError(
            "watchdog runtime-evidence key is not strict base64"
        ) from exc
    if (
        len(runtime_spki) != len(ED25519_SPKI_PREFIX) + 32
        or not runtime_spki.startswith(ED25519_SPKI_PREFIX)
        or _sha256(runtime_spki) != runtime_key.get("spkiSha256")
        or _sha256(runtime_spki[len(ED25519_SPKI_PREFIX) :])
        != runtime_key.get("rawKeySha256")
    ):
        raise LauncherError("watchdog runtime-evidence key binding is invalid")
    _ed25519_decode(
        runtime_spki[len(ED25519_SPKI_PREFIX) :],
        label="watchdog runtime-evidence public key",
    )
    service = value["serviceIdentity"]
    unit = "serverware-verification-watchdog.service"
    if (
        not isinstance(service, dict)
        or set(service)
        != {
            "binary",
            "binaryMount",
            "bootId",
            "cgroup",
            "gid",
            "pid",
            "pidStartTime",
            "uid",
            "unit",
        }
        or service.get("unit") != unit
        or type(service.get("pid")) is not int
        or service["pid"] <= 1
        or type(service.get("pidStartTime")) is not int
        or service["pidStartTime"] <= 0
        or service.get("uid") != 0
        or service.get("gid") != 0
    ):
        raise LauncherError("receipt watchdog service identity is invalid")
    _validate_signed_file_identity(service["binary"], label="watchdog binary")
    _validate_signed_mount(service["binaryMount"], label="watchdog binary")
    _validate_boot_identity_record(service["bootId"], label="watchdog")
    _validate_cgroup_record(service["cgroup"], label="watchdog", unit=unit)
    socket_identity = value["socketIdentity"]
    if (
        not isinstance(socket_identity, dict)
        or set(socket_identity)
        != {"device", "gid", "inode", "mode", "nlink", "uid"}
        or type(socket_identity.get("device")) is not int
        or type(socket_identity.get("inode")) is not int
        or type(socket_identity.get("mode")) is not int
        or type(socket_identity.get("nlink")) is not int
        or type(socket_identity.get("uid")) is not int
        or type(socket_identity.get("gid")) is not int
        or socket_identity.get("uid") != 0
        or socket_identity.get("gid") != 0
        or socket_identity.get("mode") != 0o600
        or socket_identity.get("nlink") != 1
    ):
        raise LauncherError("receipt watchdog socket identity is invalid")
    _validate_socket_ancestor_records(
        value["socketSafeAncestors"],
        path=WATCHDOG_SOCKET_PATH,
        label="watchdog socket",
    )
    return value


def _validate_receipt_daemon(
    value: Any,
    *,
    images: Any,
) -> dict[str, Any]:
    if (
        not isinstance(value, dict)
        or set(value)
        != {
            "bootId",
            "cgroup",
            "daemonId",
            "executable",
            "executableMount",
            "importedImages",
            "pid",
            "pidStartTime",
            "runtime",
            "serviceUnit",
            "socket",
        }
        or value.get("serviceUnit")
        != "serverware-verification-daemon.service"
        or value.get("runtime") != "containerd-oci-task-v2"
        or type(value.get("pid")) is not int
        or value["pid"] <= 1
        or type(value.get("pidStartTime")) is not int
        or value["pidStartTime"] <= 0
        or RUNTIME_ID_RE.fullmatch(str(value.get("daemonId") or "")) is None
        or value.get("importedImages") != images
    ):
        raise LauncherError("receipt daemon identity is invalid")
    for role, image in images.items():
        _validate_image(image, role=role)
    _validate_signed_file_identity(value["executable"], label="daemon executable")
    _validate_signed_mount(value["executableMount"], label="daemon executable")
    _validate_boot_identity_record(value["bootId"], label="daemon")
    if value["bootId"] != _boot_identity():
        raise LauncherError("receipt daemon belongs to a different boot")
    _validate_cgroup_record(
        value["cgroup"],
        label="daemon",
        unit=value["serviceUnit"],
    )
    daemon_socket = value["socket"]
    if (
        not isinstance(daemon_socket, dict)
        or set(daemon_socket)
        != {"identity", "path", "safeAncestors"}
        or daemon_socket.get("path") != str(DAEMON_SOCKET_PATH)
    ):
        raise LauncherError("receipt daemon socket binding is invalid")
    identity = daemon_socket["identity"]
    if (
        not isinstance(identity, dict)
        or set(identity)
        != {"device", "gid", "inode", "mode", "nlink", "uid"}
        or type(identity.get("device")) is not int
        or type(identity.get("inode")) is not int
        or type(identity.get("mode")) is not int
        or type(identity.get("nlink")) is not int
        or type(identity.get("uid")) is not int
        or type(identity.get("gid")) is not int
        or identity.get("uid") != 0
        or identity.get("gid") != 0
        or identity.get("mode") != 0o600
        or identity.get("nlink") != 1
    ):
        raise LauncherError("receipt daemon socket identity is invalid")
    _validate_socket_ancestor_records(
        daemon_socket["safeAncestors"],
        path=DAEMON_SOCKET_PATH,
        label="daemon socket",
    )
    return value


def _expected_process(lane: str) -> dict[str, Any]:
    if lane == "npm-publish-companion":
        return {
            "argv": [],
            "cwd": "/work",
            "dynamicEnvironment": [],
            "entrypoint": [
                "/opt/serverware/node/bin/node",
                "/opt/serverware/src/scripts/npm_publish_companion.js",
            ],
            "environment": {
                "CI": "true",
                "HOME": "/work/home",
                "LANG": "C",
                "LC_ALL": "C",
                "NO_PROXY": "",
                "TMPDIR": "/work/tmp",
                "XDG_RUNTIME_DIR": "/run/serverware-runtime",
                "npm_config_audit": "false",
                "npm_config_fund": "false",
                "npm_config_update_notifier": "false",
            },
            "gid": 65532,
            "uid": 65532,
        }
    if lane == "rust-decision-gate-tests":
        entrypoint = ["/opt/serverware/bin/serverware-decision-gate-tests"]
        argv = ["--test-threads=1"]
    else:
        entrypoint = [
            "/opt/serverware/python/bin/python3",
            "-I",
            "/opt/serverware/src/scripts/oci_lane_entrypoint.py",
        ]
        argv = ["--role", lane]
    return {
        "argv": argv,
        "cwd": "/work",
        "dynamicEnvironment": (
            list(PORTAL_DYNAMIC_ENVIRONMENT)
            if lane == "portal-browser-oauth"
            else []
        ),
        "entrypoint": entrypoint,
        "environment": dict(BASE_ENVIRONMENT),
        "gid": 65532,
        "uid": 65532,
    }


def _validate_process(value: Any, *, lane: str) -> dict[str, Any]:
    if (
        not isinstance(value, dict)
        or set(value)
        != {
            "argv",
            "cwd",
            "dynamicEnvironment",
            "entrypoint",
            "environment",
            "gid",
            "uid",
        }
        or not isinstance(value["entrypoint"], list)
        or not value["entrypoint"]
        or not isinstance(value["argv"], list)
        or any(
            not isinstance(item, str) or not item or "\x00" in item
            for item in [*value["entrypoint"], *value["argv"]]
        )
        or not str(value["entrypoint"][0]).startswith("/")
        or not isinstance(value["cwd"], str)
        or not value["cwd"].startswith("/")
        or type(value["uid"]) is not int
        or type(value["gid"]) is not int
        or value["uid"] <= 0
        or value["gid"] <= 0
        or not isinstance(value["environment"], dict)
        or any(
            ENV_RE.fullmatch(str(name)) is None
            or not isinstance(item, str)
            or "\x00" in item
            for name, item in value["environment"].items()
        )
        or not isinstance(value["dynamicEnvironment"], list)
        or any(
            not isinstance(item, str)
            for item in value["dynamicEnvironment"]
        )
        or value["dynamicEnvironment"]
        != sorted(set(value["dynamicEnvironment"]))
    ):
        raise LauncherError(f"{lane} process contract is invalid")
    if value != _expected_process(lane):
        raise LauncherError(f"{lane} process contract is not externally fixed")
    return value


def _validate_isolation(value: Any, *, lane: str) -> dict[str, Any]:
    required = {
        "apparmorProfileSha256",
        "capDrop",
        "cpuQuotaMicros",
        "memoryBytes",
        "mounts",
        "noNewPrivileges",
        "outputStderrBytes",
        "outputStdoutBytes",
        "pidsLimit",
        "readOnlyRootfs",
        "seccompProfileSha256",
        "tmpfs",
        "timeoutSeconds",
    }
    if (
        not isinstance(value, dict)
        or set(value) != required
        or value.get("capDrop") != ["ALL"]
        or value.get("mounts")
        != [
            {
                "destination": "/dev",
                "gid": 0,
                "mode": 0o755,
                "options": ["nosuid", "strictatime"],
                "sizeBytes": 16 * 1024 * 1024,
                "source": "tmpfs",
                "type": "tmpfs",
                "uid": 0,
            },
            {
                "destination": "/proc",
                "options": ["nosuid", "noexec", "nodev"],
                "source": "proc",
                "type": "proc",
            },
        ]
        or value.get("noNewPrivileges") is not True
        or value.get("readOnlyRootfs") is not True
        or value.get("pidsLimit") != 256
        or value.get("cpuQuotaMicros") != 1_000_000
        or value.get("memoryBytes")
        != (
            1024 * 1024 * 1024
            if lane == "portal-browser-oauth"
            else 512 * 1024 * 1024
        )
        or value.get("timeoutSeconds")
        != (
            900
            if lane == "portal-browser-oauth"
            else 120
            if lane == "npm-publish-companion"
            else 300
        )
        or value.get("outputStdoutBytes") != 32 * 1024 * 1024
        or value.get("outputStderrBytes") != 16 * 1024 * 1024
        or value.get("tmpfs")
        != [
            {
                "destination": "/run/serverware-runtime",
                "gid": 65532,
                "mode": 0o700,
                "options": ["nodev", "noexec", "nosuid", "strictatime"],
                "sizeBytes": 16 * 1024 * 1024,
                "uid": 65532,
            },
            {
                "destination": "/tmp",
                "gid": 65532,
                "mode": 0o700,
                "options": ["nodev", "noexec", "nosuid", "strictatime"],
                "sizeBytes": 256 * 1024 * 1024,
                "uid": 65532,
            },
            {
                "destination": "/work",
                "gid": 65532,
                "mode": 0o700,
                "options": ["nodev", "nosuid", "strictatime"],
                "sizeBytes": 256 * 1024 * 1024,
                "uid": 65532,
            },
        ]
    ):
        raise LauncherError(f"{lane} isolation contract is invalid")
    _required_digest(
        value.get("apparmorProfileSha256"),
        label=f"{lane} AppArmor profile",
    )
    _required_digest(
        value.get("seccompProfileSha256"),
        label=f"{lane} seccomp profile",
    )
    for item in value["tmpfs"]:
        if (
            not isinstance(item, dict)
            or set(item)
            != {
                "destination",
                "gid",
                "mode",
                "options",
                "sizeBytes",
                "uid",
            }
            or not isinstance(item["destination"], str)
            or not item["destination"].startswith("/")
            or type(item["mode"]) is not int
            or item["mode"] & ~0o777
            or item["uid"] != 65532
            or item["gid"] != 65532
            or item["options"] != sorted(set(item["options"]))
            or type(item["sizeBytes"]) is not int
            or not 4096 <= item["sizeBytes"] <= 1024**3
        ):
            raise LauncherError(f"{lane} tmpfs contract is invalid")
    return value


def _validate_network(value: Any, *, lane: str) -> dict[str, Any]:
    if (
        not isinstance(value, dict)
        or set(value) != {"egress", "mode", "namespace", "role"}
        or value.get("egress") != "none"
    ):
        raise LauncherError(f"{lane} network contract is invalid")
    if lane == "portal-browser-oauth":
        expected = {
            "egress": "none",
            "mode": "internal",
            "namespace": "private-anchor",
            "role": "portal-npm-private",
        }
    elif lane == "npm-publish-companion":
        expected = {
            "egress": "none",
            "mode": "join",
            "namespace": "lane:portal-browser-oauth",
            "role": "portal-npm-private",
        }
    else:
        expected = {
            "egress": "none",
            "mode": "none",
            "namespace": "private",
            "role": None,
        }
    if value != expected:
        raise LauncherError(f"{lane} network contract is not exact")
    return value


def _expected_capability_probes(lane: str) -> list[str]:
    if lane in {
        "browser-python-compatibility",
        "host-python-compatibility",
        "proxy-python-compatibility",
    }:
        return list(PYTHON_CAPABILITY_PROBES)
    if lane == "chromium-compatibility":
        return ["chromium-startup-no-network"]
    return []


def _expected_dependency_role(lane: str) -> str:
    if lane in {
        "browser-python-compatibility",
        "chromium-compatibility",
        "portal-browser-oauth",
    }:
        return "browser-runtime"
    if lane == "clean-room":
        return "clean-room-runtime"
    if lane == "rust-decision-gate-tests":
        return "rust-runtime"
    if lane == "npm-publish-companion":
        return "npm-11.8-runtime"
    return "python-runtime"


def _validate_source_evidence(value: Any) -> dict[str, Any]:
    if (
        not isinstance(value, dict)
        or set(value)
        != {
            "apiVersion",
            "gitInventory",
            "identitySha256",
            "untrackedApproval",
        }
        or value.get("apiVersion")
        != "serverware.sourceEvidenceIdentity/v1"
    ):
        raise LauncherError("raw source evidence binding is invalid")
    git = value["gitInventory"]
    approval = value["untrackedApproval"]
    if (
        not isinstance(git, dict)
        or set(git)
        != {
            "envelopeSha256",
            "headTree",
            "indexEntriesSha256",
            "indexRawSha256",
            "indexTree",
            "keyRawSha256",
            "keySpkiSha256",
            "payloadSha256",
            "signatureSha256",
            "statusRawSha256",
            "treeEntriesSha256",
            "treeRawSha256",
            "worktreeEntriesSha256",
        }
        or not isinstance(approval, dict)
        or set(approval)
        != {
            "challengeSha256",
            "envelopeSha256",
            "keyRawSha256",
            "keySpkiSha256",
            "pathListSha256",
            "payloadSha256",
            "signatureSha256",
        }
    ):
        raise LauncherError("raw source evidence inventory is not closed")
    for name, record in (
        ("Git source evidence", git),
        ("untracked source approval", approval),
    ):
        for key, item in record.items():
            if key in {"headTree", "indexTree"}:
                continue
            _required_digest(item, label=f"{name} {key}")
    git_object = re.compile(
        r"^(?:sha1:[0-9a-f]{40}|sha256:[0-9a-f]{64})$"
    )
    if (
        git_object.fullmatch(str(git.get("headTree") or "")) is None
        or git["indexTree"] != git["headTree"]
        or git["keyRawSha256"] == approval["keyRawSha256"]
        or value.get("identitySha256")
        != _sha256(
            _canonical_json(
                {
                    key: item
                    for key, item in value.items()
                    if key != "identitySha256"
                }
            )
        )
    ):
        raise LauncherError("raw source evidence identity is invalid")
    return value


def _validate_image_capability_attestation(
    image: dict[str, Any],
    *,
    public_key: bytes,
    expected_key_spki_sha256: str,
    expected_key_raw_sha256: str,
) -> None:
    role = image["dependencyRole"]
    catalog = image["capabilityCatalog"]
    expected_allowed = DEPENDENCY_ALLOWED_CAPABILITY_CLASSES[role]
    expected_forbidden = (
        sorted(PORTAL_FORBIDDEN_CAPABILITY_CLASSES)
        if role == "browser-runtime"
        else []
    )
    if (
        set(catalog)
        != {
            "allowedCapabilityClasses",
            "apiVersion",
            "catalogSha256",
            "executables",
            "forbiddenCapabilityClasses",
            "packages",
        }
        or catalog["allowedCapabilityClasses"] != expected_allowed
        or catalog["forbiddenCapabilityClasses"] != expected_forbidden
        or not isinstance(catalog["executables"], list)
        or not isinstance(catalog["packages"], list)
    ):
        raise LauncherError(
            f"{role} signed capability catalog is not closed"
        )
    seen_executables: set[str] = set()
    for executable in catalog["executables"]:
        if (
            not isinstance(executable, dict)
            or set(executable)
            != {
                "argvPolicy",
                "argvPolicySha256",
                "capabilityClass",
                "invocationPolicy",
                "path",
                "sha256",
            }
            or not isinstance(executable.get("path"), str)
            or not executable["path"].startswith("/")
            or executable["path"] in seen_executables
            or executable.get("capabilityClass") not in expected_allowed
            or executable.get("capabilityClass") in expected_forbidden
            or executable.get("invocationPolicy")
            != "fixed-oci-entrypoint-or-fixed-transitive-child-only"
        ):
            raise LauncherError(
                f"{role} signed executable capability is invalid"
            )
        _required_digest(
            executable.get("sha256"),
            label=f"{role} executable",
        )
        policy = executable["argvPolicy"]
        if (
            not isinstance(policy, dict)
            or set(policy) != {"apiVersion", "invocations"}
            or policy.get("apiVersion")
            != "serverware.executableArgvPolicy/v1"
            or not isinstance(policy.get("invocations"), list)
            or not policy["invocations"]
            or policy["invocations"]
            != sorted(
                policy["invocations"],
                key=lambda item: _canonical_json(item),
            )
            or executable.get("argvPolicySha256")
            != _sha256(_canonical_json(policy))
        ):
            raise LauncherError(
                f"{role} signed executable argv policy is invalid"
            )
        for invocation in policy["invocations"]:
            if (
                not isinstance(invocation, dict)
                or set(invocation) != {"argv", "callerRole", "match"}
                or invocation.get("match") not in {"exact", "fixed-prefix"}
                or not isinstance(invocation.get("callerRole"), str)
                or LANE_RE.fullmatch(invocation["callerRole"]) is None
                or not isinstance(invocation.get("argv"), list)
                or not invocation["argv"]
                or invocation["argv"][0] != executable["path"]
                or any(
                    not isinstance(argument, str)
                    or not argument
                    or "\x00" in argument
                    for argument in invocation["argv"]
                )
            ):
                raise LauncherError(
                    f"{role} signed executable invocation is invalid"
                )
        seen_executables.add(executable["path"])
    if catalog["executables"] != sorted(
        catalog["executables"],
        key=lambda item: item["path"],
    ):
        raise LauncherError(
            f"{role} signed executable inventory is unordered"
        )
    executable_inventory = [
        {"path": item["path"], "sha256": item["sha256"]}
        for item in catalog["executables"]
    ]
    if image["executableInventorySha256"] != _sha256(
        _canonical_json(executable_inventory)
    ):
        raise LauncherError(
            f"{role} measured executables differ from the signed catalog"
        )
    seen_packages: set[str] = set()
    for package in catalog["packages"]:
        if (
            not isinstance(package, dict)
            or set(package) != {"capabilityClasses", "purl"}
            or not isinstance(package.get("purl"), str)
            or not package["purl"]
            or package["purl"] in seen_packages
            or not isinstance(package.get("capabilityClasses"), list)
            or not package["capabilityClasses"]
            or package["capabilityClasses"]
            != sorted(set(package["capabilityClasses"]))
            or any(
                item not in expected_allowed or item in expected_forbidden
                for item in package["capabilityClasses"]
            )
        ):
            raise LauncherError(
                f"{role} signed package capability is invalid"
            )
        seen_packages.add(package["purl"])
    if catalog["packages"] != sorted(
        catalog["packages"],
        key=lambda item: item["purl"],
    ):
        raise LauncherError(f"{role} signed package inventory is unordered")
    if role == "clean-room-runtime":
        packaging = [
            item
            for item in catalog["packages"]
            if item["purl"] == "pkg:pypi/packaging@25.0"
        ]
        if (
            len(packaging) != 1
            or packaging[0]["capabilityClasses"] != ["pep508-parser"]
        ):
            raise LauncherError(
                "clean-room signed catalog omits packaging 25.0"
            )

    document = image["capabilityAttestation"]
    if (
        not isinstance(document, dict)
        or set(document)
        != {"apiVersion", "payload", "payloadSha256", "signature"}
        or document.get("apiVersion")
        != "serverware.dependencyCapabilityAttestation/v1"
        or not isinstance(document.get("payload"), dict)
        or document.get("payloadSha256")
        != _sha256(_canonical_json(document["payload"]))
    ):
        raise LauncherError("dependency capability attestation is invalid")
    payload = document["payload"]
    expected_roles = sorted(DEPENDENCY_CAPABILITIES)
    if (
        set(payload)
        != {
            "apiVersion",
            "bindings",
            "bundleApiVersion",
            "bundlesSha256",
            "roles",
        }
        or payload.get("apiVersion")
        != "serverware.dependencyCapabilityAttestation/v1"
        or payload.get("bundleApiVersion")
        != "serverware.ociDependencyBundle/v5"
        or payload.get("roles") != expected_roles
        or not isinstance(payload.get("bindings"), dict)
        or list(payload["bindings"]) != expected_roles
    ):
        raise LauncherError(
            "dependency capability attestation payload is not closed"
        )
    _required_digest(
        payload.get("bundlesSha256"),
        label="dependency bundle inventory",
    )
    for binding_role, binding in payload["bindings"].items():
        if (
            not isinstance(binding, dict)
            or set(binding)
            != {
                "capabilityCatalogSha256",
                "closureSha256",
                "fileManifestSha256",
                "packageInventorySha256",
                "semanticContractSha256",
            }
        ):
            raise LauncherError(
                f"{binding_role} capability binding is invalid"
            )
        for key, item in binding.items():
            if key == "semanticContractSha256" and item is None:
                continue
            _required_digest(
                item,
                label=f"{binding_role} capability binding {key}",
            )
    semantic = image["semanticContract"]
    expected_binding = {
        "capabilityCatalogSha256": image["capabilityCatalogSha256"],
        "closureSha256": image["dependencyClosureSha256"],
        "fileManifestSha256": image["dependencyFileManifestSha256"],
        "packageInventorySha256": image[
            "dependencyPackageInventorySha256"
        ],
        "semanticContractSha256": (
            semantic["contractSha256"] if semantic is not None else None
        ),
    }
    if payload["bindings"].get(role) != expected_binding:
        raise LauncherError(
            f"{role} image differs from its signed capability binding"
        )
    signature = document["signature"]
    if (
        not isinstance(signature, dict)
        or set(signature)
        != {
            "algorithm",
            "domain",
            "keyFileSha256",
            "rawKeySha256",
            "value",
        }
        or signature.get("algorithm") != "Ed25519"
        or signature.get("domain")
        != CAPABILITY_ATTESTATION_SIGNATURE_DOMAIN[:-1].decode("ascii")
        or signature.get("keyFileSha256") != expected_key_spki_sha256
        or signature.get("rawKeySha256") != expected_key_raw_sha256
        or not isinstance(signature.get("value"), str)
        or re.fullmatch(r"[A-Za-z0-9+/]{86}==", signature["value"]) is None
    ):
        raise LauncherError(
            "dependency capability attestation signature is invalid"
        )
    try:
        signature_raw = base64.b64decode(
            signature["value"],
            validate=True,
        )
    except (ValueError, binascii.Error) as exc:
        raise LauncherError(
            "dependency capability signature is not strict base64"
        ) from exc
    _verify_ed25519(
        public_key=public_key,
        signature=signature_raw,
        message=CAPABILITY_ATTESTATION_SIGNATURE_DOMAIN
        + _canonical_json(
            {
                "payload": payload,
                "payloadSha256": document["payloadSha256"],
            }
        ),
    )


def _validate_manifest(
    raw: bytes,
    *,
    args: argparse.Namespace,
    capability_public_key: bytes,
) -> dict[str, Any]:
    document = _load_json(raw, label="promoted Manifest v6")
    if (
        raw != _canonical_json(document) + b"\n"
        or not isinstance(document, dict)
        or set(document)
        != {
            "apiVersion",
            "candidate",
            "companions",
            "imageMappings",
            "images",
            "laneOrder",
            "lanes",
            "manifestSha256",
            "platform",
            "promotion",
            "sourceSnapshot",
            "watchdog",
        }
        or document.get("apiVersion") != BUILD_MANIFEST_VERSION
        or document.get("platform") != {"architecture": "amd64", "os": "linux"}
    ):
        raise LauncherError("promoted Manifest v6 fields are invalid")
    payload = dict(document)
    manifest_sha256 = payload.pop("manifestSha256", None)
    if (
        manifest_sha256 != _sha256(_canonical_json(payload))
        or manifest_sha256 != args.expected_manifest_sha256
    ):
        raise LauncherError("promoted Manifest v6 digest binding is invalid")
    candidate = document["candidate"]
    if (
        not isinstance(candidate, dict)
        or set(candidate)
        != {
            "fileSha256",
            "indexSha256",
            "payloadSha256",
            "promotionContractSha256",
        }
        or candidate.get("indexSha256")
        != args.expected_candidate_index_sha256
        or candidate.get("fileSha256")
        != args.expected_candidate_file_sha256
        or candidate.get("payloadSha256")
        != args.expected_candidate_payload_sha256
    ):
        raise LauncherError("candidate promotion identity is invalid")
    _required_digest(
        candidate.get("promotionContractSha256"),
        label="candidate promotion contract",
    )
    source = document["sourceSnapshot"]
    if (
        not isinstance(source, dict)
        or set(source)
        != {
            "sourceClosureSha256",
            "sourceEvidence",
            "sourceEvidenceSha256",
            "sourceFileInventorySha256",
            "sourceManifestFileSha256",
            "sourceManifestPayloadSha256",
            "sourcePathListSha256",
            "sourceGitInventoryKeyRawSha256",
            "sourceGitInventoryKeySpkiSha256",
            "sourceGitInventoryPayloadSha256",
            "sourceRootBindingSha256",
            "sourceSelectionManifestFileSha256",
            "sourceSelectionManifestPayloadSha256",
            "sourceSelectionModel",
            "sourceUntrackedApprovalKeyRawSha256",
            "sourceUntrackedApprovalKeySpkiSha256",
            "sourceUntrackedApprovalPayloadSha256",
            "snapshotRootBindingSha256",
        }
        or source.get("sourceSelectionModel") != SOURCE_SELECTION_MODEL
    ):
        raise LauncherError("source snapshot binding is invalid")
    source_evidence = _validate_source_evidence(source["sourceEvidence"])
    if (
        source["sourceEvidenceSha256"]
        != source_evidence["identitySha256"]
        or source["sourceGitInventoryKeyRawSha256"]
        != source_evidence["gitInventory"]["keyRawSha256"]
        or source["sourceGitInventoryKeySpkiSha256"]
        != source_evidence["gitInventory"]["keySpkiSha256"]
        or source["sourceGitInventoryPayloadSha256"]
        != source_evidence["gitInventory"]["payloadSha256"]
        or source["sourceUntrackedApprovalKeyRawSha256"]
        != source_evidence["untrackedApproval"]["keyRawSha256"]
        or source["sourceUntrackedApprovalKeySpkiSha256"]
        != source_evidence["untrackedApproval"]["keySpkiSha256"]
        or source["sourceUntrackedApprovalPayloadSha256"]
        != source_evidence["untrackedApproval"]["payloadSha256"]
    ):
        raise LauncherError("source evidence and Manifest v6 fields differ")
    for key, value in source.items():
        if key in {"sourceEvidence", "sourceSelectionModel"}:
            continue
        _required_digest(value, label=f"source snapshot {key}")
    lane_order = document["laneOrder"]
    lanes = document["lanes"]
    if (
        lane_order != list(LANE_ORDER)
        or not isinstance(lanes, dict)
        or list(lanes) != list(LANE_ORDER)
    ):
        raise LauncherError("lane order is invalid")
    images = document["images"]
    mappings = document["imageMappings"]
    if (
        not isinstance(images, dict)
        or list(images) != list(IMAGE_ORDER)
        or not isinstance(mappings, dict)
        or list(mappings) != list(IMAGE_ORDER)
    ):
        raise LauncherError("promoted image role inventory is not exact")
    for role in IMAGE_ORDER:
        imported = _validate_image(images[role], role=role)
        _validate_image_capability_attestation(
            imported,
            public_key=capability_public_key,
            expected_key_spki_sha256=(
                args.expected_capability_authority_public_key_spki_sha256
            ),
            expected_key_raw_sha256=(
                args.expected_capability_authority_public_key_raw_sha256
            ),
        )
        _validate_image_mapping(
            mappings[role],
            role=role,
            imported_image=imported,
        )
    if len(
        {
            _sha256(
                _canonical_json(images[role]["capabilityAttestation"])
            )
            for role in IMAGE_ORDER
        }
    ) != 1:
        raise LauncherError(
            "promoted images do not share one capability attestation"
        )
    for name in lane_order:
        lane = lanes[name]
        if (
            not isinstance(lane, dict)
            or set(lane)
            != {
                "capabilityProbes",
                "imageRole",
                "isolation",
                "name",
                "network",
                "process",
                "runtime",
                "sourceSet",
            }
            or lane.get("name") != name
            or lane.get("imageRole") != f"lane-{name}"
            or lane.get("capabilityProbes")
            != _expected_capability_probes(name)
        ):
            raise LauncherError(f"{name} lane contract is invalid")
        _validate_process(lane["process"], lane=name)
        _validate_isolation(lane["isolation"], lane=name)
        _validate_network(lane["network"], lane=name)
        runtime = lane["runtime"]
        dependency_role = _expected_dependency_role(name)
        if (
            not isinstance(runtime, dict)
            or set(runtime)
            != {
                "dependencyCapabilityCatalogSha256",
                "dependencyCapabilities",
                "dependencyClosureSha256",
                "dependencyFileManifestSha256",
                "dependencyRole",
                "semanticContractSha256",
            }
            or runtime.get("dependencyRole") != dependency_role
            or runtime.get("dependencyCapabilities")
            != DEPENDENCY_CAPABILITIES[dependency_role]
            or lane.get("sourceSet") != LANE_SOURCE_CONTRACTS[name]
            or runtime.get("dependencyCapabilityCatalogSha256")
            != images[f"lane-{name}"]["capabilityCatalogSha256"]
            or runtime.get("semanticContractSha256")
            != (
                images["lane-clean-room"]["semanticContract"][
                    "contractSha256"
                ]
                if name == "clean-room"
                else None
            )
        ):
            raise LauncherError(f"{name} runtime/source contract is invalid")
        _required_digest(
            runtime.get("dependencyCapabilityCatalogSha256"),
            label=f"{name} dependency capability catalog",
        )
        _required_digest(
            runtime.get("dependencyClosureSha256"),
            label=f"{name} dependency closure",
        )
        _required_digest(
            runtime.get("dependencyFileManifestSha256"),
            label=f"{name} dependency file manifest",
        )
    companion = document["companions"]
    if not isinstance(companion, dict) or set(companion) != {"npmPublish"}:
        raise LauncherError("companion inventory is invalid")
    npm = companion["npmPublish"]
    if (
        not isinstance(npm, dict)
        or set(npm)
        != {
            "imageRole",
            "inputProtocol",
            "isolation",
            "network",
            "npmVersion",
            "operation",
            "operationCount",
            "process",
            "retryEquality",
            "runtime",
            "sourceSet",
        }
        or npm.get("imageRole") != "npm-publish-companion"
        or npm.get("npmVersion") != "11.8.0"
        or npm.get("operation") != "npm.publish.fixture"
        or npm.get("operationCount") != 2
        or npm.get("inputProtocol")
        != "one-canonical-json-frame-on-stdin-no-generic-command"
        or npm.get("retryEquality")
        != {
            "canonicalHttpRequestBytes": "identical",
            "operationInputBytes": "identical",
            "rawHttpRequestBytes": "different-only-by-npm-session",
            "requestBodyBytes": "identical",
        }
    ):
        raise LauncherError("npm companion contract is not fixed")
    _validate_process(npm["process"], lane="npm-publish-companion")
    _validate_isolation(npm["isolation"], lane="npm-publish-companion")
    _validate_network(npm["network"], lane="npm-publish-companion")
    npm_runtime = npm["runtime"]
    if (
        not isinstance(npm_runtime, dict)
        or set(npm_runtime)
        != {
            "dependencyCapabilityCatalogSha256",
            "dependencyCapabilities",
            "dependencyClosureSha256",
            "dependencyFileManifestSha256",
            "dependencyRole",
            "semanticContractSha256",
        }
        or npm_runtime.get("dependencyRole") != "npm-11.8-runtime"
        or npm_runtime.get("dependencyCapabilities")
        != DEPENDENCY_CAPABILITIES["npm-11.8-runtime"]
        or npm_runtime.get("dependencyCapabilityCatalogSha256")
        != images["npm-publish-companion"]["capabilityCatalogSha256"]
        or npm_runtime.get("semanticContractSha256") is not None
        or npm.get("sourceSet")
        != {
            "exact": ["scripts/npm_publish_companion.js"],
            "prefixes": [],
        }
    ):
        raise LauncherError("npm companion runtime/source contract is invalid")
    _required_digest(
        npm_runtime.get("dependencyCapabilityCatalogSha256"),
        label="npm dependency capability catalog",
    )
    _required_digest(
        npm_runtime.get("dependencyClosureSha256"),
        label="npm dependency closure",
    )
    _required_digest(
        npm_runtime.get("dependencyFileManifestSha256"),
        label="npm dependency file manifest",
    )
    promotion = document["promotion"]
    if (
        not isinstance(promotion, dict)
        or set(promotion)
        != {
            "acceptanceSha256",
            "apiVersion",
            "candidatePromotionContractSha256",
        }
        or promotion.get("apiVersion") != PROMOTION_ACCEPTANCE_VERSION
    ):
        raise LauncherError("promotion acceptance is invalid")
    _required_digest(
        promotion.get("candidatePromotionContractSha256"),
        label="candidate promotion contract",
    )
    acceptance = dict(promotion)
    acceptance_sha256 = acceptance.pop("acceptanceSha256", None)
    if (
        acceptance_sha256 != _sha256(_canonical_json(acceptance))
        or acceptance_sha256 != args.expected_promotion_acceptance_sha256
    ):
        raise LauncherError("promotion acceptance digest is invalid")
    watchdog = document["watchdog"]
    if (
        not isinstance(watchdog, dict)
        or set(watchdog)
        != {
            "bootCleanupContractSha256",
            "protocolVersion",
            "resourceLabelNames",
            "selectionMode",
        }
        or watchdog.get("protocolVersion") != WATCHDOG_PROTOCOL_VERSION
        or watchdog.get("selectionMode")
        != "exact-kind-id-pairs-and-complete-label-set"
        or watchdog.get("resourceLabelNames")
        != [
            "org.serverware.attempt",
            "org.serverware.kind",
            "org.serverware.lane",
            "org.serverware.lane-sequence",
            "org.serverware.lease",
            "org.serverware.manifest",
            "org.serverware.promotion-receipt",
            "org.serverware.role",
        ]
    ):
        raise LauncherError("watchdog Manifest v6 contract is invalid")
    _required_digest(
        watchdog.get("bootCleanupContractSha256"),
        label="watchdog boot cleanup contract",
    )
    return document


def _load_receipt(
    args: argparse.Namespace,
    *,
    public_key: bytes,
    public_key_identity: dict[str, Any],
    capability_public_key: bytes,
    allowed_mount_ids: set[int],
) -> tuple[dict[str, Any], dict[str, Any], bytes]:
    receipt_identity, raw = _read_safe_regular(
        args.promotion_receipt,
        label="promotion receipt",
    )
    if receipt_identity["sha256"] != args.expected_promotion_receipt_sha256:
        raise LauncherError("promotion receipt differs from its external pin")
    document = _load_json(raw, label="promotion receipt")
    if (
        raw != _canonical_json(document) + b"\n"
        or not isinstance(document, dict)
        or set(document)
        != {"apiVersion", "payload", "payloadSha256", "signature"}
        or document.get("apiVersion") != PROMOTION_RECEIPT_VERSION
    ):
        raise LauncherError("promotion receipt fields are invalid")
    payload = document.get("payload")
    required_payload = {
        "candidateIndexSha256",
        "candidateManifestFileSha256",
        "candidateManifestPayloadSha256",
        "candidatePromotionContractSha256",
        "daemon",
        "finalManifestSha256",
        "imageMappings",
        "images",
        "launcherRuntime",
        "manifest",
        "promotionAcceptanceSha256",
        "promotionPublicKey",
        "receiptStorage",
        "sourceEvidence",
        "sourceEvidenceSha256",
        "watchdog",
    }
    if not isinstance(payload, dict) or set(payload) != required_payload:
        raise LauncherError("promotion receipt payload is invalid")
    payload_sha256 = _sha256(_canonical_json(payload))
    if document.get("payloadSha256") != payload_sha256:
        raise LauncherError("promotion receipt payload digest is invalid")
    signature = document.get("signature")
    if (
        not isinstance(signature, dict)
        or set(signature)
        != {
            "algorithm",
            "domain",
            "keyFileSha256",
            "rawKeySha256",
            "value",
        }
        or signature.get("algorithm") != "Ed25519"
        or signature.get("domain")
        != PROMOTION_SIGNATURE_DOMAIN[:-1].decode("ascii")
        or signature.get("keyFileSha256") != public_key_identity["sha256"]
        or signature.get("rawKeySha256")
        != public_key_identity["rawKeySha256"]
        or not isinstance(signature.get("value"), str)
        or re.fullmatch(r"[A-Za-z0-9+/]{86}==", signature["value"]) is None
    ):
        raise LauncherError("promotion receipt signature envelope is invalid")
    try:
        signature_raw = base64.b64decode(signature["value"], validate=True)
    except (ValueError, binascii.Error) as exc:
        raise LauncherError("receipt signature is not strict base64") from exc
    _verify_ed25519(
        public_key=public_key,
        signature=signature_raw,
        message=PROMOTION_SIGNATURE_DOMAIN
        + _canonical_json(
            {"payload": payload, "payloadSha256": payload_sha256}
        ),
    )
    if (
        not isinstance(payload["images"], dict)
        or list(payload["images"]) != list(IMAGE_ORDER)
        or not isinstance(payload["imageMappings"], dict)
        or list(payload["imageMappings"]) != list(IMAGE_ORDER)
    ):
        raise LauncherError("receipt promoted image inventory is invalid")
    for role in IMAGE_ORDER:
        imported = _validate_image(payload["images"][role], role=role)
        _validate_image_capability_attestation(
            imported,
            public_key=capability_public_key,
            expected_key_spki_sha256=(
                args.expected_capability_authority_public_key_spki_sha256
            ),
            expected_key_raw_sha256=(
                args.expected_capability_authority_public_key_raw_sha256
            ),
        )
        _validate_image_mapping(
            payload["imageMappings"][role],
            role=role,
            imported_image=imported,
        )
    if len(
        {
            _sha256(
                _canonical_json(
                    payload["images"][role]["capabilityAttestation"]
                )
            )
            for role in IMAGE_ORDER
        }
    ) != 1:
        raise LauncherError(
            "receipt images do not share one capability attestation"
        )
    _validate_receipt_daemon(
        payload["daemon"],
        images=payload["images"],
    )
    _validate_receipt_watchdog(payload["watchdog"])
    _required_digest(
        payload.get("candidatePromotionContractSha256"),
        label="receipt candidate promotion contract",
    )
    source_evidence = _validate_source_evidence(payload["sourceEvidence"])
    if (
        source_evidence["identitySha256"]
        != payload["sourceEvidenceSha256"]
    ):
        raise LauncherError("promotion receipt source evidence is invalid")
    if (
        payload.get("candidateIndexSha256")
        != args.expected_candidate_index_sha256
        or payload.get("candidateManifestFileSha256")
        != args.expected_candidate_file_sha256
        or payload.get("candidateManifestPayloadSha256")
        != args.expected_candidate_payload_sha256
        or payload.get("finalManifestSha256") != args.expected_manifest_sha256
        or payload.get("promotionAcceptanceSha256")
        != args.expected_promotion_acceptance_sha256
    ):
        raise LauncherError("receipt external digest bindings are invalid")
    storage = payload["receiptStorage"]
    if (
        not isinstance(storage, dict)
        or set(storage) != {"mount", "path"}
        or storage["path"] != str(args.promotion_receipt)
    ):
        raise LauncherError("receipt storage binding is invalid")
    _require_mount(
        args.promotion_receipt,
        storage["mount"],
        label="promotion receipt",
        allowed_mount_ids=allowed_mount_ids,
    )
    key_record = payload["promotionPublicKey"]
    if (
        not isinstance(key_record, dict)
        or set(key_record) != {"identity", "mount", "rawKeySha256"}
        or key_record["identity"]
        != {
            key: value
            for key, value in public_key_identity.items()
            if key != "rawKeySha256"
        }
        or key_record["rawKeySha256"]
        != args.expected_promotion_public_key_raw_sha256
    ):
        raise LauncherError("receipt public-key binding is invalid")
    _require_mount(
        args.promotion_public_key,
        key_record["mount"],
        label="promotion public key",
        allowed_mount_ids=allowed_mount_ids,
    )
    manifest_record = payload["manifest"]
    if (
        not isinstance(manifest_record, dict)
        or set(manifest_record) != {"identity", "mount"}
        or not isinstance(manifest_record.get("identity"), dict)
        or manifest_record["identity"].get("path") != str(args.manifest)
    ):
        raise LauncherError("receipt manifest binding is invalid")
    manifest_identity, manifest_raw = _read_safe_regular(
        args.manifest,
        label="promoted Manifest v6",
    )
    if (
        manifest_identity != manifest_record["identity"]
        or manifest_identity["sha256"] != args.expected_manifest_file_sha256
    ):
        raise LauncherError("promoted Manifest v6 identity changed")
    _require_mount(
        args.manifest,
        manifest_record["mount"],
        label="promoted Manifest v6",
        allowed_mount_ids=allowed_mount_ids,
    )
    return document, manifest_identity, manifest_raw


def _read_proc_regular(
    path: Path,
    *,
    label: str,
    max_bytes: int,
) -> bytes:
    descriptor = os.open(
        path,
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0),
    )
    try:
        raw, _ = _read_fd_stable(
            descriptor,
            label=label,
            max_bytes=max_bytes,
        )
        return raw
    finally:
        os.close(descriptor)


def _boot_identity() -> dict[str, str]:
    raw = _read_proc_regular(
        BOOT_ID_PATH,
        label="kernel boot ID",
        max_bytes=256,
    )
    try:
        value = raw.decode("ascii").strip()
    except UnicodeError as exc:
        raise LauncherError("kernel boot ID is not ASCII") from exc
    if re.fullmatch(
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
        r"[0-9a-f]{4}-[0-9a-f]{12}",
        value,
    ) is None:
        raise LauncherError("kernel boot ID is malformed")
    return {"sha256": _sha256(raw), "value": value}


def _pid_start_time(pid: int) -> int:
    raw = _read_proc_regular(
        Path(f"/proc/{pid}/stat"),
        label="watchdog process stat",
        max_bytes=64 * 1024,
    )
    try:
        text = raw.decode("ascii")
    except UnicodeError as exc:
        raise LauncherError("watchdog process stat is not ASCII") from exc
    close = text.rfind(")")
    fields = text[close + 2 :].split() if close >= 0 else []
    if len(fields) <= 19 or not fields[19].isdigit():
        raise LauncherError("watchdog process start time is malformed")
    return int(fields[19])


def _cgroup_identity(pid: int) -> dict[str, Any]:
    raw = _read_proc_regular(
        Path(f"/proc/{pid}/cgroup"),
        label="watchdog cgroup",
        max_bytes=1024 * 1024,
    )
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeError as exc:
        raise LauncherError("watchdog cgroup is not ASCII") from exc
    unified = [
        line.removeprefix("0::")
        for line in lines
        if line.startswith("0::/")
    ]
    if len(unified) != 1 or "\x00" in unified[0]:
        raise LauncherError("watchdog unified cgroup is ambiguous")
    return {"path": unified[0], "sha256": _sha256(raw)}


@dataclass
class WatchdogPeer:
    connection: socket.socket
    executable_fd: int
    pidfd: int
    pid: int

    def close(self) -> None:
        failures: list[str] = []
        for closeable, label in (
            (self.connection, "watchdog socket"),
            (self.executable_fd, "watchdog executable FD"),
            (self.pidfd, "watchdog pidfd"),
        ):
            try:
                if isinstance(closeable, socket.socket):
                    closeable.close()
                else:
                    os.close(closeable)
            except OSError as exc:
                failures.append(f"{label}: {exc}")
        if failures:
            raise LauncherError("watchdog peer close failed: " + " | ".join(failures))


def _authenticate_watchdog(
    *,
    receipt_watchdog: dict[str, Any],
    allowed_mount_ids: set[int],
) -> WatchdogPeer:
    if (
        not isinstance(receipt_watchdog, dict)
        or set(receipt_watchdog)
        != {
            "bootCleanupContract",
            "laneEndpoint",
            "runtimeEvidencePublicKey",
            "serviceIdentity",
            "socketIdentity",
            "socketPath",
            "socketSafeAncestors",
        }
        or receipt_watchdog.get("socketPath") != str(WATCHDOG_SOCKET_PATH)
    ):
        raise LauncherError("receipt watchdog contract is invalid")
    if (
        _safe_ancestor_identities(
            WATCHDOG_SOCKET_PATH.parent,
            label="watchdog socket parent",
        )
        != receipt_watchdog["socketSafeAncestors"]
    ):
        raise LauncherError("watchdog socket safe ancestors changed")
    parent = _safe_directory_descriptor(
        WATCHDOG_SOCKET_PATH.parent,
        label="watchdog socket parent",
    )
    try:
        socket_metadata = os.stat(
            WATCHDOG_SOCKET_PATH.name,
            dir_fd=parent,
            follow_symlinks=False,
        )
    finally:
        os.close(parent)
    socket_identity = {
        "device": socket_metadata.st_dev,
        "gid": socket_metadata.st_gid,
        "inode": socket_metadata.st_ino,
        "mode": stat.S_IMODE(socket_metadata.st_mode),
        "nlink": socket_metadata.st_nlink,
        "uid": socket_metadata.st_uid,
    }
    if (
        not stat.S_ISSOCK(socket_metadata.st_mode)
        or socket_metadata.st_uid != 0
        or socket_metadata.st_nlink != 1
        or socket_identity != receipt_watchdog["socketIdentity"]
    ):
        raise LauncherError("watchdog control socket identity changed")
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    connection.settimeout(30)
    executable_fd = -1
    pidfd = -1
    try:
        connection.connect(str(WATCHDOG_SOCKET_PATH))
        peer_raw = connection.getsockopt(
            socket.SOL_SOCKET,
            socket.SO_PEERCRED,
            struct.calcsize("3i"),
        )
        peer_pid, peer_uid, peer_gid = struct.unpack("3i", peer_raw)
        service = receipt_watchdog["serviceIdentity"]
        if (
            peer_pid <= 1
            or peer_uid != 0
            or peer_gid != 0
            or not isinstance(service, dict)
            or set(service)
            != {
                "binary",
                "binaryMount",
                "bootId",
                "cgroup",
                "gid",
                "pid",
                "pidStartTime",
                "uid",
                "unit",
            }
            or service.get("pid") != peer_pid
            or service.get("uid") != peer_uid
            or service.get("gid") != peer_gid
            or service.get("unit")
            != "serverware-verification-watchdog.service"
        ):
            raise LauncherError("live watchdog peer differs from the receipt")
        if not hasattr(os, "pidfd_open"):
            raise LauncherError("watchdog authentication requires pidfd_open")
        pidfd = os.pidfd_open(peer_pid, 0)
        executable_fd = os.open(
            f"/proc/{peer_pid}/exe",
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NONBLOCK", 0),
        )
        binary_path = _absolute(
            Path(str(service["binary"].get("path") or "")),
            label="watchdog binary",
        )
        live_binary, _ = _file_identity_from_fd(
            executable_fd,
            path=binary_path,
            label="live watchdog executable",
        )
        path_binary, _ = _read_safe_regular(
            binary_path,
            label="watchdog binary",
            max_bytes=MAX_RUNTIME_BYTES,
        )
        if live_binary != service["binary"] or path_binary != service["binary"]:
            raise LauncherError("live watchdog executable identity changed")
        _require_mount(
            binary_path,
            service["binaryMount"],
            label="watchdog binary",
            allowed_mount_ids=allowed_mount_ids,
        )
        if (
            _boot_identity() != service["bootId"]
            or _pid_start_time(peer_pid) != service["pidStartTime"]
            or _cgroup_identity(peer_pid) != service["cgroup"]
            or not service["cgroup"]["path"].endswith(
                "/serverware-verification-watchdog.service"
            )
        ):
            raise LauncherError("live watchdog boot/cgroup identity changed")
        return WatchdogPeer(
            connection=connection,
            executable_fd=executable_fd,
            pidfd=pidfd,
            pid=peer_pid,
        )
    except BaseException:
        connection.close()
        if executable_fd >= 0:
            os.close(executable_fd)
        if pidfd >= 0:
            os.close(pidfd)
        raise


def _message_digest(value: dict[str, Any]) -> str:
    return _sha256(CONTROL_MESSAGE_DOMAIN + _canonical_json(value))


def _exchange_packet(
    connection: socket.socket,
    request: dict[str, Any],
    *,
    timeout_seconds: int,
) -> dict[str, Any]:
    if not 1 <= timeout_seconds <= MAX_LANE_SECONDS + 120:
        raise LauncherError("watchdog request timeout is outside its bound")
    raw = _canonical_json(request)
    if len(raw) > MAX_MESSAGE_BYTES:
        raise LauncherError("watchdog request exceeds its byte limit")
    previous_timeout = connection.gettimeout()
    connection.settimeout(timeout_seconds)
    try:
        connection.sendall(raw)
        response_raw = connection.recv(MAX_MESSAGE_BYTES + 1)
    finally:
        connection.settimeout(previous_timeout)
    if not response_raw or len(response_raw) > MAX_MESSAGE_BYTES:
        raise LauncherError("watchdog response is missing or oversized")
    response = _load_json(response_raw, label="watchdog response")
    if not isinstance(response, dict):
        raise LauncherError("watchdog response is not an object")
    return response


@dataclass
class WatchdogSession:
    peer: WatchdogPeer
    manifest_sha256: str
    receipt_sha256: str
    daemon: dict[str, Any]
    requested_lease_id: str
    lease_id: str | None = None
    session_id: str | None = None
    sequence: int = 0
    previous_response_sha256: str | None = None
    seen_server_nonces: set[str] = field(default_factory=set)
    server_nonce_history: list[str] = field(default_factory=list)
    lease_event_head_sha256: str | None = None

    def exchange(
        self,
        command: str,
        payload: dict[str, Any],
        *,
        timeout_seconds: int,
        recovery: bool = False,
        recovery_challenge: str | None = None,
    ) -> dict[str, Any]:
        if command not in {"BEGIN", "RUN_LANE", "FINISH", "ABORT"}:
            raise LauncherError("unsupported watchdog command")
        if LEASE_RE.fullmatch(self.requested_lease_id) is None:
            raise LauncherError("watchdog requested lease ID is invalid")
        wire_lease_id = (
            self.requested_lease_id if command == "BEGIN" else self.lease_id
        )
        nonce = secrets.token_hex(32)
        request_payload = {
            "apiVersion": WATCHDOG_PROTOCOL_VERSION,
            "clientNonce": nonce,
            "command": command,
            "leaseId": wire_lease_id,
            "manifestSha256": self.manifest_sha256,
            "messageSequence": self.sequence,
            "nonceHistorySha256": _sha256(
                _canonical_json(self.server_nonce_history)
            ),
            "payload": payload,
            "previousLeaseEventHeadSha256": self.lease_event_head_sha256,
            "previousResponseSha256": self.previous_response_sha256,
            "promotionReceiptSha256": self.receipt_sha256,
            "recovery": recovery,
            "recoveryChallenge": recovery_challenge,
            "sessionId": self.session_id,
        }
        request = {
            **request_payload,
            "requestSha256": _message_digest(request_payload),
        }
        response = _exchange_packet(
            self.peer.connection,
            request,
            timeout_seconds=timeout_seconds,
        )
        required = {
            "apiVersion",
            "clientNonce",
            "command",
            "leaseId",
            "manifestSha256",
            "messageSequence",
            "nonceHistorySha256",
            "payload",
            "previousLeaseEventHeadSha256",
            "previousResponseSha256",
            "promotionReceiptSha256",
            "requestSha256",
            "recovery",
            "recoveryChallenge",
            "responseSha256",
            "serverNonce",
            "sessionId",
            "leaseEventHeadSha256",
        }
        response_payload = dict(response)
        response_sha256 = response_payload.pop("responseSha256", None)
        if (
            set(response) != required
            or response.get("apiVersion") != WATCHDOG_PROTOCOL_VERSION
            or response.get("clientNonce") != nonce
            or response.get("command") != command
            or response.get("manifestSha256") != self.manifest_sha256
            or response.get("promotionReceiptSha256") != self.receipt_sha256
            or response.get("messageSequence") != self.sequence
            or response.get("nonceHistorySha256")
            != request_payload["nonceHistorySha256"]
            or response.get("requestSha256") != request["requestSha256"]
            or response.get("previousLeaseEventHeadSha256")
            != self.lease_event_head_sha256
            or response.get("previousResponseSha256")
            != self.previous_response_sha256
            or not isinstance(response.get("payload"), dict)
            or not isinstance(response.get("sessionId"), str)
            or LEASE_RE.fullmatch(str(response.get("sessionId"))) is None
            or not isinstance(response.get("leaseId"), str)
            or LEASE_RE.fullmatch(str(response.get("leaseId"))) is None
            or NONCE_RE.fullmatch(str(response.get("serverNonce"))) is None
            or response["serverNonce"] in self.seen_server_nonces
            or response.get("recovery") is not recovery
            or response.get("recoveryChallenge") != recovery_challenge
            or SHA256_RE.fullmatch(
                str(response.get("leaseEventHeadSha256") or "")
            )
            is None
            or response_sha256 != _message_digest(response_payload)
        ):
            raise LauncherError("watchdog response failed replay/binding checks")
        if command == "BEGIN":
            if (
                self.lease_id is not None
                or self.session_id is not None
                or response["leaseId"] != self.requested_lease_id
            ):
                raise LauncherError("BEGIN attempted on an active session")
        elif command == "ABORT" and recovery:
            if (
                response["leaseId"] != self.lease_id
                or (
                    self.session_id is not None
                    and response["sessionId"] != self.session_id
                )
            ):
                raise LauncherError("recovery ABORT changed the session or lease")
        elif (
            response["leaseId"] != self.lease_id
            or response["sessionId"] != self.session_id
        ):
            raise LauncherError("watchdog response crossed sessions")
        self.lease_id = response["leaseId"]
        self.session_id = response["sessionId"]
        self.sequence += 1
        self.previous_response_sha256 = response_sha256
        self.seen_server_nonces.add(response["serverNonce"])
        self.server_nonce_history.append(response["serverNonce"])
        self.lease_event_head_sha256 = response["leaseEventHeadSha256"]
        return response["payload"]


def _daemon_evidence_digest(
    *,
    daemon: dict[str, Any],
    lease_id: str,
    manifest_sha256: str,
    receipt_sha256: str,
) -> str:
    return _sha256(
        DAEMON_EVIDENCE_DOMAIN
        + _canonical_json(
            {
                "daemon": daemon,
                "leaseId": lease_id,
                "manifestSha256": manifest_sha256,
                "promotionReceiptSha256": receipt_sha256,
            }
        )
    )


def _validate_begin(
    payload: dict[str, Any],
    *,
    session: WatchdogSession,
    receipt: dict[str, Any],
    manifest: dict[str, Any],
) -> str:
    required = {
        "bootCleanupComplete",
        "bootCleanupEvidence",
        "daemonEvidence",
        "daemonEvidenceSha256",
        "daemonLiveVerification",
        "importedImages",
        "startupInspectedResources",
        "watchdogServiceIdentity",
    }
    receipt_payload = receipt["payload"]
    boot_cleanup = payload.get("bootCleanupEvidence")
    if not isinstance(boot_cleanup, dict):
        raise LauncherError("watchdog boot-cleanup evidence is invalid")
    boot_cleanup_payload = dict(boot_cleanup)
    boot_cleanup_sha256 = boot_cleanup_payload.pop("cleanupRunSha256", None)
    inspected_boot_resources = boot_cleanup.get("inspectedResources")
    if (
        set(boot_cleanup)
        != {
            "absenceObservations",
            "bootId",
            "cleanupRunSha256",
            "contractSha256",
            "inspectedResources",
            "persistentLeaseStateScanned",
            "remainingResources",
            "status",
        }
        or boot_cleanup.get("bootId")
        != receipt_payload["watchdog"]["serviceIdentity"]["bootId"]
        or boot_cleanup.get("contractSha256")
        != receipt_payload["watchdog"]["bootCleanupContract"][
            "contractSha256"
        ]
        or boot_cleanup.get("persistentLeaseStateScanned") is not True
        or boot_cleanup.get("status") != "completed"
        or not isinstance(inspected_boot_resources, list)
        or any(
            not isinstance(item, dict)
            or set(item) != {"id", "kind"}
            or item.get("kind")
            not in {"container", "network", "snapshot", "task"}
            or RUNTIME_ID_RE.fullmatch(str(item.get("id") or "")) is None
            for item in inspected_boot_resources
        )
        or inspected_boot_resources
        != sorted(
            inspected_boot_resources,
            key=lambda item: (item["kind"], item["id"]),
        )
        or len(
            {
                (item["kind"], item["id"])
                for item in inspected_boot_resources
            }
        )
        != len(inspected_boot_resources)
        or boot_cleanup.get("remainingResources") != []
        or boot_cleanup.get("absenceObservations")
        != [
            {
                "inspectedResources": inspected_boot_resources,
                "ordinal": ordinal,
                "presentResources": [],
            }
            for ordinal in range(1, 4)
        ]
        or boot_cleanup_sha256
        != _sha256(_canonical_json(boot_cleanup_payload))
    ):
        raise LauncherError("watchdog boot-cleanup evidence is invalid")
    daemon = receipt_payload["daemon"]
    expected_live_verification = {
        "bootId": daemon["bootId"],
        "cgroup": daemon["cgroup"],
        "daemonId": daemon["daemonId"],
        "executable": daemon["executable"],
        "executableMount": daemon["executableMount"],
        "pid": daemon["pid"],
        "pidStartTime": daemon["pidStartTime"],
        "runtime": daemon["runtime"],
        "serviceUnit": daemon["serviceUnit"],
        "socket": daemon["socket"],
        "status": "verified-by-root-watchdog",
    }
    if (
        set(payload) != required
        or payload.get("bootCleanupComplete") is not True
        or payload.get("watchdogServiceIdentity")
        != receipt_payload["watchdog"]["serviceIdentity"]
        or payload.get("daemonEvidence") != receipt_payload["daemon"]
        or payload.get("daemonLiveVerification")
        != expected_live_verification
        or payload.get("importedImages") != receipt_payload["images"]
        or payload.get("importedImages") != manifest["images"]
        or payload.get("startupInspectedResources") != []
        or session.lease_id is None
    ):
        raise LauncherError("watchdog BEGIN evidence is invalid")
    expected = _daemon_evidence_digest(
        daemon=receipt_payload["daemon"],
        lease_id=session.lease_id,
        manifest_sha256=session.manifest_sha256,
        receipt_sha256=session.receipt_sha256,
    )
    if payload.get("daemonEvidenceSha256") != expected:
        raise LauncherError("watchdog daemon evidence is not lease-bound")
    return expected


def _resource_labels(
    *,
    kind: str,
    lease_id: str,
    lane: str,
    lane_sequence: int,
    receipt_sha256: str,
    manifest_sha256: str,
    role: str,
    attempt: int,
) -> dict[str, str]:
    return {
        "org.serverware.attempt": str(attempt),
        "org.serverware.kind": kind,
        "org.serverware.lane": lane,
        "org.serverware.lane-sequence": str(lane_sequence),
        "org.serverware.lease": lease_id,
        "org.serverware.manifest": manifest_sha256,
        "org.serverware.promotion-receipt": receipt_sha256,
        "org.serverware.role": role,
    }


def _validate_resource(
    value: Any,
    *,
    lease_id: str,
    lane: str,
    lane_sequence: int,
    manifest: dict[str, Any],
    receipt_sha256: str,
) -> dict[str, Any]:
    if (
        not isinstance(value, dict)
        or set(value)
        != {
            "attempt",
            "id",
            "imageId",
            "inspectionSha256",
            "kind",
            "labels",
            "lane",
            "laneSequence",
            "name",
            "role",
        }
        or value.get("lane") != lane
        or value.get("laneSequence") != lane_sequence
        or type(value.get("attempt")) is not int
        or not 0 <= value["attempt"] <= 2
        or value.get("kind")
        not in {"container", "network", "snapshot", "task"}
        or RUNTIME_ID_RE.fullmatch(str(value.get("id") or "")) is None
        or RUNTIME_ID_RE.fullmatch(str(value.get("name") or "")) is None
    ):
        raise LauncherError(f"{lane} runtime resource is invalid")
    _required_digest(value.get("inspectionSha256"), label="resource inspection")
    role = value.get("role")
    if not isinstance(role, str):
        raise LauncherError(f"{lane} resource role is invalid")
    permitted = (
        {
            ("container", "lane", 0),
            ("snapshot", "lane", 0),
            ("task", "lane", 0),
            ("container", "npm-companion", 1),
            ("snapshot", "npm-companion", 1),
            ("task", "npm-companion", 1),
            ("container", "npm-companion", 2),
            ("snapshot", "npm-companion", 2),
            ("task", "npm-companion", 2),
            ("network", "private-network", 0),
        }
        if lane == "portal-browser-oauth"
        else {
            ("container", "lane", 0),
            ("snapshot", "lane", 0),
            ("task", "lane", 0),
        }
    )
    if (value["kind"], role, value["attempt"]) not in permitted:
        raise LauncherError(f"{lane} runtime resource role is not authorized")
    if value["kind"] in {"container", "snapshot", "task"}:
        image_role = (
            "npm-publish-companion"
            if role == "npm-companion"
            else f"lane-{lane}"
        )
        if value.get("imageId") != manifest["images"][image_role]["containerdImageId"]:
            raise LauncherError(f"{lane} resource selected the wrong image")
    elif value.get("imageId") is not None or role != "private-network":
        raise LauncherError(f"{lane} network resource is invalid")
    if value.get("labels") != _resource_labels(
        kind=value["kind"],
        lease_id=lease_id,
        lane=lane,
        lane_sequence=lane_sequence,
        receipt_sha256=receipt_sha256,
        manifest_sha256=manifest["manifestSha256"],
        role=role,
        attempt=value["attempt"],
    ):
        raise LauncherError(f"{lane} resource labels are not exact")
    return value


def _validate_portal_operations(
    transcript: Any,
    *,
    lane: str,
    lane_sequence: int,
    lease_id: str,
    manifest: dict[str, Any],
    receipt_watchdog: dict[str, Any],
    receipt_sha256: str,
    service_identity_sha256: str,
    session_id: str,
    one_use_nonce: str,
    network_namespace_sha256: str,
    resources: list[dict[str, Any]],
) -> None:
    if not isinstance(transcript, list) or len(transcript) != 2:
        raise LauncherError("portal npm transcript is not exactly two operations")
    companion_resources = {
        item["attempt"]: item
        for item in resources
        if item["kind"] == "task" and item["role"] == "npm-companion"
    }
    if set(companion_resources) != {1, 2}:
        raise LauncherError("portal npm companion resources are not exact")
    request_inputs: list[str] = []
    request_bodies: list[str] = []
    canonical_requests: list[str] = []
    raw_requests: list[str] = []
    request_nonces: list[str] = []
    for attempt, operation in enumerate(transcript, start=1):
        if (
            not isinstance(operation, dict)
            or set(operation)
            != {
                "attempt",
                "canonicalHttpSha256",
                "companionExitCode",
                "companionImageId",
                "companionInputProtocol",
                "companionIsolation",
                "companionNetwork",
                "companionOutput",
                "companionProcess",
                "companionResource",
                "companionRuntimeEvidence",
                "lane",
                "laneOneUseNonce",
                "laneSequence",
                "leaseId",
                "manifestSha256",
                "oneUse",
                "operation",
                "operationInputSha256",
                "outcome",
                "promotionReceiptSha256",
                "protocol",
                "rawDifferenceContract",
                "rawHttpSha256",
                "requestBodySha256",
                "requestDigest",
                "requestNonce",
                "watchdogPeerAuthenticated",
                "watchdogRequestSha256",
                "watchdogResponseSha256",
                "watchdogServiceIdentitySha256",
                "watchdogSessionId",
            }
            or operation.get("attempt") != attempt
            or operation.get("lane") != lane
            or operation.get("laneSequence") != lane_sequence
            or operation.get("leaseId") != lease_id
            or operation.get("manifestSha256") != manifest["manifestSha256"]
            or operation.get("promotionReceiptSha256") != receipt_sha256
            or operation.get("protocol") != "serverware.npmOneUse/v2"
            or operation.get("companionInputProtocol")
            != "one-canonical-json-frame-on-stdin-no-generic-command"
            or operation.get("companionProcess")
            != manifest["companions"]["npmPublish"]["process"]
            or operation.get("companionIsolation")
            != manifest["companions"]["npmPublish"]["isolation"]
            or operation.get("companionNetwork")
            != manifest["companions"]["npmPublish"]["network"]
            or operation.get("companionExitCode")
            != (1 if attempt == 1 else 0)
            or operation.get("rawDifferenceContract")
            != "npm-session-header-only-between-attempts"
            or operation.get("laneOneUseNonce") != one_use_nonce
            or operation.get("watchdogSessionId") != session_id
            or operation.get("watchdogServiceIdentitySha256")
            != service_identity_sha256
            or operation.get("operation") != "npm.publish.fixture"
            or operation.get("oneUse") is not True
            or operation.get("watchdogPeerAuthenticated") is not True
            or NONCE_RE.fullmatch(str(operation.get("requestNonce") or "")) is None
            or operation.get("companionImageId")
            != manifest["images"]["npm-publish-companion"]["containerdImageId"]
            or operation.get("companionResource")
            != {
                "id": companion_resources[attempt]["id"],
                "kind": companion_resources[attempt]["kind"],
            }
            or operation.get("outcome")
            != ("jit-approval-required" if attempt == 1 else "published")
            or operation.get("watchdogRequestSha256")
            == operation.get("watchdogResponseSha256")
        ):
            raise LauncherError("portal npm operation binding is invalid")
        companion_runtime_evidence = operation["companionRuntimeEvidence"]
        companion_event_head = (
            companion_runtime_evidence.get("payload", {}).get(
                "leaseEventHeadSha256"
            )
            if isinstance(companion_runtime_evidence, dict)
            else None
        )
        _required_digest(
            companion_event_head,
            label="npm companion lease event head",
        )
        companion_runtime = _validate_runtime_evidence(
            companion_runtime_evidence,
            lane=lane,
            lane_sequence=lane_sequence,
            lease_id=lease_id,
            manifest=manifest,
            receipt_watchdog=receipt_watchdog,
            receipt_sha256=receipt_sha256,
            lease_event_head_sha256=companion_event_head,
            runtime_role="npm-companion",
            attempt=attempt,
        )
        if (
            companion_runtime["networkNamespaceSha256"]
            != network_namespace_sha256
        ):
            raise LauncherError(
                "npm companion joined the wrong portal network namespace"
            )
        companion_output = operation["companionOutput"]
        companion_isolation = manifest["companions"]["npmPublish"][
            "isolation"
        ]
        if (
            not isinstance(companion_output, dict)
            or set(companion_output)
            != {
                "stderrBytes",
                "stderrSha256",
                "stdoutBytes",
                "stdoutSha256",
            }
            or type(companion_output.get("stdoutBytes")) is not int
            or type(companion_output.get("stderrBytes")) is not int
            or not 0
            <= companion_output["stdoutBytes"]
            <= companion_isolation["outputStdoutBytes"]
            or not 0
            <= companion_output["stderrBytes"]
            <= companion_isolation["outputStderrBytes"]
        ):
            raise LauncherError("portal npm companion output is invalid")
        _required_digest(
            companion_output.get("stdoutSha256"),
            label="portal npm companion stdout",
        )
        _required_digest(
            companion_output.get("stderrSha256"),
            label="portal npm companion stderr",
        )
        for key in (
            "canonicalHttpSha256",
            "operationInputSha256",
            "rawHttpSha256",
            "requestBodySha256",
            "requestDigest",
            "watchdogRequestSha256",
            "watchdogResponseSha256",
        ):
            _required_digest(operation.get(key), label=f"portal operation {key}")
        request_binding = {
            "attempt": operation["attempt"],
            "companionImageId": operation["companionImageId"],
            "companionInputProtocol": operation["companionInputProtocol"],
            "companionIsolation": operation["companionIsolation"],
            "companionNetwork": operation["companionNetwork"],
            "companionProcess": operation["companionProcess"],
            "companionResource": operation["companionResource"],
            "companionRuntimeEvidenceSha256": operation[
                "companionRuntimeEvidence"
            ]["payloadSha256"],
            "lane": operation["lane"],
            "laneOneUseNonce": operation["laneOneUseNonce"],
            "laneSequence": operation["laneSequence"],
            "leaseId": operation["leaseId"],
            "manifestSha256": operation["manifestSha256"],
            "operation": operation["operation"],
            "operationInputSha256": operation["operationInputSha256"],
            "promotionReceiptSha256": operation["promotionReceiptSha256"],
            "protocol": operation["protocol"],
            "requestNonce": operation["requestNonce"],
            "watchdogRequestSha256": operation["watchdogRequestSha256"],
            "watchdogServiceIdentitySha256": (
                operation["watchdogServiceIdentitySha256"]
            ),
            "watchdogSessionId": operation["watchdogSessionId"],
        }
        if operation["requestDigest"] != _sha256(
            _canonical_json(request_binding)
        ):
            raise LauncherError("portal operation request digest is invalid")
        response_binding = {
            "canonicalHttpSha256": operation["canonicalHttpSha256"],
            "companionExitCode": operation["companionExitCode"],
            "companionOutput": operation["companionOutput"],
            "oneUse": operation["oneUse"],
            "outcome": operation["outcome"],
            "rawDifferenceContract": operation["rawDifferenceContract"],
            "rawHttpSha256": operation["rawHttpSha256"],
            "requestBodySha256": operation["requestBodySha256"],
            "requestDigest": operation["requestDigest"],
            "watchdogPeerAuthenticated": (
                operation["watchdogPeerAuthenticated"]
            ),
        }
        if operation["watchdogResponseSha256"] != _sha256(
            _canonical_json(response_binding)
        ):
            raise LauncherError("portal operation response digest is invalid")
        request_inputs.append(operation["operationInputSha256"])
        request_bodies.append(operation["requestBodySha256"])
        canonical_requests.append(operation["canonicalHttpSha256"])
        raw_requests.append(operation["rawHttpSha256"])
        request_nonces.append(operation["requestNonce"])
    if (
        len(set(request_inputs)) != 1
        or len(set(request_bodies)) != 1
        or len(set(canonical_requests)) != 1
        or len(set(raw_requests)) != 2
        or len(set(request_nonces)) != 2
    ):
        raise LauncherError("portal retry byte-identity contract failed")


def _validate_capability_results(
    value: Any,
    *,
    lane: str,
    manifest: dict[str, Any],
) -> None:
    expected = manifest["lanes"][lane]["capabilityProbes"]
    if not isinstance(value, list) or len(value) != len(expected):
        raise LauncherError(f"{lane} capability result inventory is invalid")
    rootfs_digest = manifest["images"][f"lane-{lane}"]["rootfsDigest"]
    for name, result in zip(expected, value, strict=True):
        if (
            not isinstance(result, dict)
            or set(result)
            != {
                "bounded",
                "name",
                "networkEgress",
                "rootfsDigest",
                "status",
                "transcriptSha256",
            }
            or result.get("name") != name
            or result.get("bounded") is not True
            or result.get("networkEgress") != "none"
            or result.get("rootfsDigest") != rootfs_digest
            or result.get("status") != "passed"
        ):
            raise LauncherError(f"{lane} capability result is invalid")
        _required_digest(
            result.get("transcriptSha256"),
            label=f"{lane} {name} transcript",
        )


def _validate_runtime_evidence(
    value: Any,
    *,
    lane: str,
    lane_sequence: int,
    lease_id: str,
    manifest: dict[str, Any],
    receipt_watchdog: dict[str, Any],
    receipt_sha256: str,
    lease_event_head_sha256: str,
    runtime_role: str = "lane",
    attempt: int = 0,
) -> dict[str, Any]:
    if (
        not isinstance(value, dict)
        or set(value)
        != {"apiVersion", "payload", "payloadSha256", "signature"}
        or value.get("apiVersion") != "serverware.ociRuntimeEvidence/v2"
        or not isinstance(value.get("payload"), dict)
        or value.get("payloadSha256")
        != _sha256(_canonical_json(value["payload"]))
    ):
        raise LauncherError(f"{lane} runtime evidence envelope is invalid")
    payload = value["payload"]
    if runtime_role == "lane" and attempt == 0:
        isolation = manifest["lanes"][lane]["isolation"]
        network = manifest["lanes"][lane]["network"]
        process = manifest["lanes"][lane]["process"]
        image_id = manifest["images"][f"lane-{lane}"]["containerdImageId"]
    elif (
        runtime_role == "npm-companion"
        and lane == "portal-browser-oauth"
        and attempt in {1, 2}
    ):
        isolation = manifest["companions"]["npmPublish"]["isolation"]
        network = manifest["companions"]["npmPublish"]["network"]
        process = manifest["companions"]["npmPublish"]["process"]
        image_id = manifest["images"]["npm-publish-companion"][
            "containerdImageId"
        ]
    else:
        raise LauncherError(f"{lane} runtime evidence role is invalid")
    if (
        set(payload)
        != {
            "apparmorProfileSha256",
            "attempt",
            "capabilitySets",
            "cgroup",
            "cwd",
            "gid",
            "imageId",
            "lane",
            "laneSequence",
            "leaseEventHeadSha256",
            "leaseId",
            "manifestSha256",
            "mounts",
            "namespaces",
            "namespaceIdentities",
            "network",
            "networkNamespaceSha256",
            "noNewPrivileges",
            "ociSpecSha256",
            "promotionReceiptSha256",
            "preStartContractSha256",
            "readOnlyRootfs",
            "role",
            "seccompProfileSha256",
            "tmpfs",
            "uid",
            "verificationPhase",
            "verifiedBeforeEntrypoint",
        }
        or payload.get("lane") != lane
        or payload.get("laneSequence") != lane_sequence
        or payload.get("role") != runtime_role
        or payload.get("attempt") != attempt
        or payload.get("leaseId") != lease_id
        or payload.get("manifestSha256") != manifest["manifestSha256"]
        or payload.get("promotionReceiptSha256") != receipt_sha256
        or payload.get("imageId") != image_id
        or payload.get("uid") != 65532
        or payload.get("gid") != 65532
        or payload.get("noNewPrivileges") is not True
        or payload.get("readOnlyRootfs") is not True
        or payload.get("verifiedBeforeEntrypoint") is not True
        or payload.get("verificationPhase")
        != "after-create-before-entrypoint-exec"
        or payload.get("apparmorProfileSha256")
        != isolation["apparmorProfileSha256"]
        or payload.get("seccompProfileSha256")
        != isolation["seccompProfileSha256"]
        or payload.get("mounts") != isolation["mounts"]
        or payload.get("tmpfs") != isolation["tmpfs"]
        or payload.get("leaseEventHeadSha256")
        != lease_event_head_sha256
        or payload.get("capabilitySets")
        != {
            "ambient": "0000000000000000",
            "bounding": "0000000000000000",
            "effective": "0000000000000000",
            "inheritable": "0000000000000000",
            "permitted": "0000000000000000",
        }
        or payload.get("cgroup")
        != {
            "cpuQuotaMicros": isolation["cpuQuotaMicros"],
            "memoryBytes": isolation["memoryBytes"],
            "pidsLimit": isolation["pidsLimit"],
        }
        or payload.get("cwd")
        != {
            "gid": 65532,
            "mode": 0o700,
            "path": "/work",
            "uid": 65532,
            "writable": True,
        }
        or payload.get("namespaces")
        != {
            "cgroup": "private",
            "ipc": "private",
            "mount": "private",
            "network": (
                "portal-npm-private"
                if network["mode"] == "internal"
                else "join:portal-browser-oauth"
                if network["mode"] == "join"
                else "none"
            ),
            "pid": "private",
            "uts": "private",
        }
        or payload.get("network")
        != {
            "contract": network,
            "defaultRoutes": [],
            "interfaces": (
                ["eth0", "lo"]
                if network["mode"] in {"internal", "join"}
                else ["lo"]
            ),
        }
        or payload.get("preStartContractSha256")
        != _sha256(
            _canonical_json(
                {
                    "imageId": image_id,
                    "isolation": isolation,
                    "network": network,
                    "process": process,
                }
            )
        )
    ):
        raise LauncherError(f"{lane} runtime evidence payload is invalid")
    namespace_identities = payload["namespaceIdentities"]
    namespace_names = {
        "cgroup": "cgroup",
        "ipc": "ipc",
        "mount": "mnt",
        "network": "net",
        "pid": "pid",
        "uts": "uts",
    }
    if (
        not isinstance(namespace_identities, dict)
        or set(namespace_identities) != set(namespace_names)
        or any(
            re.fullmatch(
                rf"{kernel_name}:\[[0-9]+\]",
                str(namespace_identities.get(name) or ""),
            )
            is None
            for name, kernel_name in namespace_names.items()
        )
        or payload.get("networkNamespaceSha256")
        != _sha256(namespace_identities["network"].encode("ascii"))
    ):
        raise LauncherError(f"{lane} namespace identity evidence is invalid")
    _required_digest(payload.get("ociSpecSha256"), label=f"{lane} OCI spec")
    signature = value["signature"]
    if (
        not isinstance(signature, dict)
        or set(signature) != {"algorithm", "domain", "value"}
        or signature.get("algorithm") != "Ed25519"
        or signature.get("domain")
        != RUNTIME_EVIDENCE_SIGNATURE_DOMAIN[:-1].decode("ascii")
        or not isinstance(signature.get("value"), str)
    ):
        raise LauncherError(f"{lane} runtime evidence signature is invalid")
    try:
        signature_raw = base64.b64decode(signature["value"], validate=True)
        runtime_spki = base64.b64decode(
            receipt_watchdog["runtimeEvidencePublicKey"]["spkiBase64"],
            validate=True,
        )
    except (ValueError, binascii.Error) as exc:
        raise LauncherError(
            f"{lane} runtime evidence signature/key is invalid"
        ) from exc
    _verify_ed25519(
        public_key=runtime_spki[len(ED25519_SPKI_PREFIX) :],
        signature=signature_raw,
        message=RUNTIME_EVIDENCE_SIGNATURE_DOMAIN
        + _canonical_json(
            {
                "payload": payload,
                "payloadSha256": value["payloadSha256"],
            }
        ),
    )
    return payload


def _validate_clean_room_result(
    value: Any,
    *,
    expected_contract: dict[str, Any],
    output: dict[str, Any],
) -> None:
    expected_contract = _validate_clean_room_contract(expected_contract)
    expected_scenarios = [
        (
            "attestation-verify-offline",
            [
                "/opt/serverware/clean-room/installed/bin/serverware-attestation",
                "--base",
                "http://127.0.0.1:1",
                "--enrollment-packet",
                (
                    "/opt/serverware/clean-room/fixtures/"
                    "rejected-enrollment-packet.json"
                ),
                "--ca-out",
                "/work/attestation-verify-offline/verified-ca.pem",
            ],
            1,
        ),
        (
            "enrollment-install-offline",
            [
                "/opt/serverware/clean-room/installed/bin/serverware-enrollment",
                "--base",
                "http://127.0.0.1:1",
                "--verify-packet",
                (
                    "/opt/serverware/clean-room/fixtures/"
                    "rejected-enrollment-packet.json"
                ),
            ],
            1,
        ),
        (
            "evidence-verify-offline",
            [
                "/opt/serverware/clean-room/installed/bin/serverware-evidence",
                "--root",
                "/opt/serverware/clean-room/fixtures",
                "verify",
                "--manifest",
                "onboarding-evidence.json",
            ],
            0,
        ),
    ]
    if (
        not isinstance(value, dict)
        or set(value)
        != {
            "apiVersion",
            "derivedInstallationSha256",
            "exerciseScenarios",
            "installContractSha256",
            "payloadClosureSha256",
            "requirementsResolutionSha256",
            "resultSha256",
            "sandboxEvidenceSha256",
            "wheelRecordsSha256",
            "wheelhouseManifestPayloadSha256",
        }
        or value.get("apiVersion")
        != "serverware.agentTrustCleanRoomResult/v5"
        or not isinstance(value.get("exerciseScenarios"), list)
        or [item.get("scenario") for item in value["exerciseScenarios"]]
        != [item[0] for item in expected_scenarios]
    ):
        raise LauncherError("clean-room semantic result is invalid")
    for key in (
        "derivedInstallationSha256",
        "installContractSha256",
        "payloadClosureSha256",
        "requirementsResolutionSha256",
        "sandboxEvidenceSha256",
        "wheelRecordsSha256",
        "wheelhouseManifestPayloadSha256",
    ):
        _required_digest(value.get(key), label=f"clean-room {key}")
    result_payload = dict(value)
    result_sha256 = result_payload.pop("resultSha256", None)
    if result_sha256 != _sha256(_canonical_json(result_payload)):
        raise LauncherError("clean-room result digest is invalid")
    for result_key, contract_key in (
        ("derivedInstallationSha256", "derivedInstallationSha256"),
        ("installContractSha256", "installContractSha256"),
        ("payloadClosureSha256", "payloadClosureSha256"),
        ("requirementsResolutionSha256", "requirementsResolutionSha256"),
        ("wheelRecordsSha256", "wheelRecordsSha256"),
        (
            "wheelhouseManifestPayloadSha256",
            "wheelhouseManifestPayloadSha256",
        ),
    ):
        if value[result_key] != expected_contract[contract_key]:
            raise LauncherError(
                f"clean-room {result_key} differs from Manifest v6"
            )
    for scenario, expected, expected_scenario in zip(
        value["exerciseScenarios"],
        expected_scenarios,
        expected_contract["exerciseScenarios"],
        strict=True,
    ):
        if (
            not isinstance(scenario, dict)
            or set(scenario)
            != {
                "argv",
                "exitCode",
                "scenario",
                "stateSha256",
                "stderrSha256",
                "stdoutSha256",
            }
            or scenario.get("scenario") != expected[0]
            or scenario.get("argv") != expected[1]
            or scenario.get("exitCode") != expected[2]
        ):
            raise LauncherError("clean-room fixed exercise is invalid")
        for key in ("stateSha256", "stderrSha256", "stdoutSha256"):
            _required_digest(
                scenario.get(key),
                label=f"clean-room scenario {key}",
            )
        if (
            scenario["stdoutSha256"] != expected_scenario["stdoutSha256"]
            or scenario["stderrSha256"] != expected_scenario["stderrSha256"]
            or scenario["stateSha256"]
            != _sha256(_canonical_json(expected_scenario["expectedState"]))
        ):
            raise LauncherError(
                "clean-room scenario differs from its promoted derivation"
            )
    emitted = (
        b"SERVERWARE_CLEAN_ROOM_RESULT="
        + _canonical_json(value)
        + b"\n"
    )
    if (
        output["stdoutBytes"] != len(emitted)
        or output["stdoutSha256"] != _sha256(emitted)
        or output["stderrBytes"] != 0
        or output["stderrSha256"] != _sha256(b"")
    ):
        raise LauncherError(
            "clean-room semantic result is not the exact lane transcript"
        )


def _validate_lane_result(
    payload: dict[str, Any],
    *,
    lane: str,
    lane_sequence: int,
    lease_id: str,
    daemon_evidence_sha256: str,
    manifest: dict[str, Any],
    receipt_watchdog: dict[str, Any],
    receipt_sha256: str,
    session_id: str,
    lease_event_head_sha256: str,
) -> list[dict[str, Any]]:
    required = {
        "capabilityResults",
        "daemonEvidenceSha256",
        "dynamicEnvironment",
        "exitCode",
        "imageId",
        "isolation",
        "lane",
        "laneSequence",
        "network",
        "npmOperations",
        "output",
        "process",
        "resources",
        "resultSha256",
        "runtimeEvidence",
        "semanticResult",
    }
    if (
        set(payload) != required
        or payload.get("lane") != lane
        or payload.get("laneSequence") != lane_sequence
        or payload.get("daemonEvidenceSha256") != daemon_evidence_sha256
        or payload.get("imageId")
        != manifest["images"][f"lane-{lane}"]["containerdImageId"]
        or payload.get("process") != manifest["lanes"][lane]["process"]
        or payload.get("isolation") != manifest["lanes"][lane]["isolation"]
        or payload.get("network") != manifest["lanes"][lane]["network"]
        or not isinstance(payload.get("dynamicEnvironment"), dict)
        or type(payload.get("exitCode")) is not int
        or payload["exitCode"] != 0
        or not isinstance(payload.get("resources"), list)
    ):
        raise LauncherError(f"{lane} lane result is invalid")
    result_payload = dict(payload)
    result_sha256 = result_payload.pop("resultSha256", None)
    if result_sha256 != _sha256(_canonical_json(result_payload)):
        raise LauncherError(f"{lane} lane result digest is invalid")
    _validate_capability_results(
        payload["capabilityResults"],
        lane=lane,
        manifest=manifest,
    )
    lane_runtime = _validate_runtime_evidence(
        payload["runtimeEvidence"],
        lane=lane,
        lane_sequence=lane_sequence,
        lease_id=lease_id,
        manifest=manifest,
        receipt_watchdog=receipt_watchdog,
        receipt_sha256=receipt_sha256,
        lease_event_head_sha256=lease_event_head_sha256,
    )
    output = payload["output"]
    isolation = manifest["lanes"][lane]["isolation"]
    if (
        not isinstance(output, dict)
        or set(output)
        != {
            "stderrBytes",
            "stderrSha256",
            "stdoutBytes",
            "stdoutSha256",
        }
        or type(output["stdoutBytes"]) is not int
        or type(output["stderrBytes"]) is not int
        or not 0 <= output["stdoutBytes"] <= isolation["outputStdoutBytes"]
        or not 0 <= output["stderrBytes"] <= isolation["outputStderrBytes"]
    ):
        raise LauncherError(f"{lane} output transcript is invalid")
    _required_digest(output.get("stdoutSha256"), label=f"{lane} stdout")
    _required_digest(output.get("stderrSha256"), label=f"{lane} stderr")
    if lane == "clean-room":
        _validate_clean_room_result(
            payload["semanticResult"],
            expected_contract=manifest["images"][
                "lane-clean-room"
            ]["semanticContract"],
            output=output,
        )
    elif payload["semanticResult"] is not None:
        raise LauncherError(f"{lane} returned an unauthorized semantic result")
    resources = [
        _validate_resource(
            item,
            lease_id=lease_id,
            lane=lane,
            lane_sequence=lane_sequence,
            manifest=manifest,
            receipt_sha256=receipt_sha256,
        )
        for item in payload["resources"]
    ]
    refs = [(item["kind"], item["id"]) for item in resources]
    names = [(item["kind"], item["name"]) for item in resources]
    if len(refs) != len(set(refs)) or len(names) != len(set(names)):
        raise LauncherError(f"{lane} returned duplicate runtime resources")
    if lane == "portal-browser-oauth":
        endpoint = receipt_watchdog["laneEndpoint"]
        dynamic = payload["dynamicEnvironment"]
        one_use_nonce = dynamic.get("SERVERWARE_ONE_USE_NONCE")
        npm_image = manifest["images"]["npm-publish-companion"]
        npm_tools = npm_image["fixedToolIdentities"]
        if (
            dynamic
            != {
                "SERVERWARE_ATTEMPT": "0",
                "SERVERWARE_LANE": lane,
                "SERVERWARE_LEASE_ID": lease_id,
                "SERVERWARE_MANIFEST_SHA256": manifest["manifestSha256"],
                "SERVERWARE_NPM_COMPANION_IMAGE_ID": npm_image[
                    "containerdImageId"
                ],
                "SERVERWARE_NPM_ENTRYPOINT_SHA256": npm_tools[
                    "npmEntrypoint"
                ]["sha256"],
                "SERVERWARE_NPM_NODE_SHA256": npm_tools["node"]["sha256"],
                "SERVERWARE_NPM_PACKAGE_SHA256": npm_tools[
                    "npmPackageManifest"
                ]["sha256"],
                "SERVERWARE_ONE_USE_NONCE": one_use_nonce,
                "SERVERWARE_PROMOTION_RECEIPT_SHA256": receipt_sha256,
                "SERVERWARE_WATCHDOG_ENDPOINT": endpoint["url"],
                "SERVERWARE_WATCHDOG_TLS_SPKI_SHA256": (
                    endpoint["tlsSpkiSha256"]
                ),
            }
            or NONCE_RE.fullmatch(str(one_use_nonce or "")) is None
        ):
            raise LauncherError("portal dynamic environment is not exact")
        roles = [
            (item["kind"], item["role"], item["attempt"])
            for item in resources
        ]
        if sorted(roles) != sorted(
            [
                ("container", "lane", 0),
                ("snapshot", "lane", 0),
                ("task", "lane", 0),
                ("network", "private-network", 0),
                ("container", "npm-companion", 1),
                ("snapshot", "npm-companion", 1),
                ("task", "npm-companion", 1),
                ("container", "npm-companion", 2),
                ("snapshot", "npm-companion", 2),
                ("task", "npm-companion", 2),
            ]
        ):
            raise LauncherError("portal resource inventory is not exact")
        _validate_portal_operations(
            payload["npmOperations"],
            lane=lane,
            lane_sequence=lane_sequence,
            lease_id=lease_id,
            manifest=manifest,
            receipt_watchdog=receipt_watchdog,
            receipt_sha256=receipt_sha256,
            service_identity_sha256=_sha256(
                _canonical_json(receipt_watchdog["serviceIdentity"])
            ),
            session_id=session_id,
            one_use_nonce=one_use_nonce,
            network_namespace_sha256=lane_runtime[
                "networkNamespaceSha256"
            ],
            resources=resources,
        )
    elif (
        payload["dynamicEnvironment"] != {}
        or payload["npmOperations"] is not None
        or [
            (item["kind"], item["role"], item["attempt"])
            for item in resources
        ]
        != [
            ("container", "lane", 0),
            ("snapshot", "lane", 0),
            ("task", "lane", 0),
        ]
    ):
        raise LauncherError(f"{lane} returned unauthorized companion resources")
    return resources


def _validate_cleanup(
    payload: dict[str, Any],
    *,
    lease_id: str,
    daemon_evidence_sha256: str,
    manifest: dict[str, Any],
    receipt_sha256: str,
    terminal: str,
    lease_event_head_sha256: str,
) -> dict[str, Any]:
    required = {
        "absenceObservations",
        "authoritativeInventorySha256",
        "cleanupActions",
        "daemonEvidenceSha256",
        "importedImages",
        "inspectedResources",
        "leaseEventHeadSha256",
        "leaseEvents",
        "leaseId",
        "terminal",
    }
    events = payload.get("leaseEvents")
    if not isinstance(events, list) or not events:
        raise LauncherError("watchdog durable lease event log is invalid")
    previous = _sha256(b"")
    created: dict[tuple[str, str], dict[str, Any]] = {}
    created_slots: set[tuple[str, int, str, str, int]] = set()
    chained_cleanup_actions: list[dict[str, Any]] = []
    chained_absence_observations: list[dict[str, Any]] = []
    started_lanes: list[str] = []
    finished_lanes: list[str] = []
    phase = "lease"
    lease_begun = False
    cleanup_started = False
    inventory_started = False
    lease_terminal = False
    for sequence, event in enumerate(events, start=1):
        if (
            not isinstance(event, dict)
            or set(event)
            != {
                "event",
                "eventSha256",
                "previousEventSha256",
                "sequence",
            }
            or event.get("sequence") != sequence
            or event.get("previousEventSha256") != previous
            or not isinstance(event.get("event"), dict)
        ):
            raise LauncherError("watchdog lease event chain is invalid")
        event_payload = {
            "event": event["event"],
            "previousEventSha256": previous,
            "sequence": sequence,
        }
        measured = _sha256(_canonical_json(event_payload))
        if event.get("eventSha256") != measured:
            raise LauncherError("watchdog lease event digest is invalid")
        previous = measured
        body = event["event"]
        if lease_terminal:
            raise LauncherError("watchdog emitted events after lease terminal")
        if body.get("type") == "resource-created":
            if phase != "lanes":
                raise LauncherError("watchdog created a resource outside lane phase")
            if set(body) != {"resource", "type"}:
                raise LauncherError("watchdog resource event is invalid")
            resource = body["resource"]
            if not isinstance(resource, dict):
                raise LauncherError("watchdog resource event is invalid")
            lane = resource.get("lane")
            lane_sequence = resource.get("laneSequence")
            if (
                not isinstance(lane, str)
                or lane not in manifest["lanes"]
                or type(lane_sequence) is not int
                or not 0 <= lane_sequence < len(manifest["laneOrder"])
                or manifest["laneOrder"][lane_sequence] != lane
            ):
                raise LauncherError("watchdog resource event crossed lanes")
            validated = _validate_resource(
                resource,
                lease_id=lease_id,
                lane=lane,
                lane_sequence=lane_sequence,
                manifest=manifest,
                receipt_sha256=receipt_sha256,
            )
            key = (validated["kind"], validated["id"])
            if key in created:
                raise LauncherError("watchdog resource pair was created twice")
            slot = (
                validated["lane"],
                validated["laneSequence"],
                validated["kind"],
                validated["role"],
                validated["attempt"],
            )
            if slot in created_slots:
                raise LauncherError("watchdog runtime resource slot was reused")
            created[key] = validated
            created_slots.add(slot)
        elif body.get("type") == "cleanup-action":
            if phase != "cleanup" or inventory_started:
                raise LauncherError("watchdog cleanup action is out of order")
            action = {
                key: value
                for key, value in body.items()
                if key != "type"
            }
            if (
                set(body) != {"action", "resource", "result", "type"}
                or action.get("action") not in {"inspect", "kill", "remove"}
                or action.get("result")
                not in {
                    "killed-reaped-or-already-absent",
                    "present-or-already-absent",
                    "removed-or-already-absent",
                }
                or not isinstance(action.get("resource"), dict)
                or set(action["resource"]) != {"id", "kind"}
                or (
                    action["resource"]["kind"],
                    action["resource"]["id"],
                )
                not in created
            ):
                raise LauncherError("watchdog chained cleanup action is invalid")
            chained_cleanup_actions.append(action)
        elif body.get("type") == "inventory-observed":
            if (
                phase != "cleanup"
                or set(body) != {"observation", "type"}
                or not isinstance(body.get("observation"), dict)
            ):
                raise LauncherError("watchdog chained inventory is invalid")
            inventory_started = True
            chained_absence_observations.append(body["observation"])
        elif body.get("type") == "lease-begin":
            if (
                sequence != 1
                or lease_begun
                or phase != "lease"
                or body
                != {
                    "leaseId": lease_id,
                    "manifestSha256": manifest["manifestSha256"],
                    "promotionReceiptSha256": receipt_sha256,
                    "type": "lease-begin",
                }
            ):
                raise LauncherError("watchdog lease-begin event is invalid")
            lease_begun = True
            phase = "lanes"
        elif body.get("type") == "lane-started":
            if (
                phase != "lanes"
                or set(body)
                != {"lane", "laneSequence", "requestSha256", "type"}
                or body.get("lane") not in manifest["lanes"]
                or type(body.get("laneSequence")) is not int
                or not 0 <= body["laneSequence"] < len(manifest["laneOrder"])
                or manifest["laneOrder"][body["laneSequence"]]
                != body["lane"]
                or body["laneSequence"] != len(started_lanes)
                or len(finished_lanes) != len(started_lanes)
                or SHA256_RE.fullmatch(str(body.get("requestSha256") or ""))
                is None
            ):
                raise LauncherError("watchdog lane-started event is invalid")
            started_lanes.append(body["lane"])
        elif body.get("type") == "lane-finished":
            if (
                phase != "lanes"
                or set(body)
                != {"lane", "laneSequence", "resultSha256", "type"}
                or body.get("lane") not in manifest["lanes"]
                or type(body.get("laneSequence")) is not int
                or not 0 <= body["laneSequence"] < len(manifest["laneOrder"])
                or manifest["laneOrder"][body["laneSequence"]]
                != body["lane"]
                or not started_lanes
                or body["laneSequence"] != len(finished_lanes)
                or body["lane"] != started_lanes[len(finished_lanes)]
                or SHA256_RE.fullmatch(str(body.get("resultSha256") or ""))
                is None
            ):
                raise LauncherError("watchdog lane-finished event is invalid")
            finished_lanes.append(body["lane"])
        elif body.get("type") == "cleanup-started":
            if (
                phase != "lanes"
                or cleanup_started
                or body
                != {
                    "leaseId": lease_id,
                    "terminal": terminal,
                    "type": "cleanup-started",
                }
            ):
                raise LauncherError("watchdog cleanup-started event is invalid")
            cleanup_started = True
            phase = "cleanup"
        elif body.get("type") == "lease-terminal":
            if (
                phase != "cleanup"
                or not cleanup_started
                or len(chained_absence_observations) != 3
                or body
                != {
                    "leaseId": lease_id,
                    "terminal": terminal,
                    "type": "lease-terminal",
                }
            ):
                raise LauncherError("watchdog lease-terminal event is invalid")
            lease_terminal = True
            phase = "terminal"
        else:
            raise LauncherError("watchdog lease event type is unsupported")
    if (
        not lease_begun
        or not cleanup_started
        or not lease_terminal
        or events[-1]["event"].get("type") != "lease-terminal"
        or previous != lease_event_head_sha256
        or payload.get("leaseEventHeadSha256") != lease_event_head_sha256
    ):
        raise LauncherError("watchdog lease event head changed")
    expected_prefix = list(manifest["laneOrder"][: len(started_lanes)])
    if (
        started_lanes != expected_prefix
        or finished_lanes != expected_prefix[: len(finished_lanes)]
        or len(started_lanes) - len(finished_lanes) not in {0, 1}
        or (
            terminal == "finished"
            and (
                started_lanes != manifest["laneOrder"]
                or finished_lanes != manifest["laneOrder"]
            )
        )
    ):
        raise LauncherError("watchdog lane event coverage is invalid")
    inspected = payload.get("inspectedResources")
    if not isinstance(inspected, list):
        raise LauncherError("watchdog cleanup resource inventory is invalid")
    validated_resources: list[dict[str, Any]] = []
    for item in inspected:
        if not isinstance(item, dict):
            raise LauncherError("watchdog cleanup resource is invalid")
        lane = item.get("lane")
        lane_sequence = item.get("laneSequence")
        if (
            not isinstance(lane, str)
            or lane not in manifest["lanes"]
            or type(lane_sequence) is not int
            or not 0 <= lane_sequence < len(manifest["laneOrder"])
            or manifest["laneOrder"][lane_sequence] != lane
        ):
            raise LauncherError("watchdog cleanup resource crossed lanes")
        validated_resources.append(
            _validate_resource(
                item,
                lease_id=lease_id,
                lane=lane,
                lane_sequence=lane_sequence,
                manifest=manifest,
                receipt_sha256=receipt_sha256,
            )
        )
    if (
        len({(item["kind"], item["id"]) for item in validated_resources})
        != len(validated_resources)
        or len({(item["kind"], item["name"]) for item in validated_resources})
        != len(validated_resources)
    ):
        raise LauncherError("watchdog cleanup resource IDs/names are duplicated")
    expected_resources = sorted(
        created.values(),
        key=lambda item: (item["kind"], item["id"]),
    )
    if terminal == "finished":
        expected_slots: set[tuple[str, int, str, str, int]] = set()
        for lane_sequence, lane in enumerate(manifest["laneOrder"]):
            expected_slots.update(
                {
                    (lane, lane_sequence, "container", "lane", 0),
                    (lane, lane_sequence, "snapshot", "lane", 0),
                    (lane, lane_sequence, "task", "lane", 0),
                }
            )
            if lane == "portal-browser-oauth":
                expected_slots.add(
                    (lane, lane_sequence, "network", "private-network", 0)
                )
                for attempt in (1, 2):
                    expected_slots.update(
                        {
                            (
                                lane,
                                lane_sequence,
                                "container",
                                "npm-companion",
                                attempt,
                            ),
                            (
                                lane,
                                lane_sequence,
                                "snapshot",
                                "npm-companion",
                                attempt,
                            ),
                            (
                                lane,
                                lane_sequence,
                                "task",
                                "npm-companion",
                                attempt,
                            ),
                        }
                    )
        if created_slots != expected_slots:
            raise LauncherError(
                "watchdog successful lease resource inventory is not exact"
            )
    if validated_resources != expected_resources:
        raise LauncherError(
            "cleanup inventory differs from watchdog durable lease inventory"
        )
    expected_refs = [
        {"id": item["id"], "kind": item["kind"]}
        for item in expected_resources
    ]
    expected_searches = sorted(
        (
            {
                "expectedResource": {
                    "id": item["id"],
                    "kind": item["kind"],
                },
                "expectedResourceName": item["name"],
                "labels": item["labels"],
            }
            for item in expected_resources
        ),
        key=lambda item: (
            item["expectedResource"]["kind"],
            item["expectedResource"]["id"],
        ),
    )
    if (
        set(payload) != required
        or payload.get("leaseId") != lease_id
        or payload.get("terminal") != terminal
        or payload.get("daemonEvidenceSha256")
        != daemon_evidence_sha256
        or payload.get("importedImages") != manifest["images"]
        or inspected != expected_resources
        or payload.get("authoritativeInventorySha256")
        != _sha256(_canonical_json(expected_resources))
        or not isinstance(payload.get("cleanupActions"), list)
        or not isinstance(payload.get("absenceObservations"), list)
        or len(payload["absenceObservations"]) != 3
        or payload["cleanupActions"] != chained_cleanup_actions
        or payload["absenceObservations"] != chained_absence_observations
    ):
        raise LauncherError("watchdog cleanup transcript is invalid")
    expected_actions: list[dict[str, Any]] = []
    for resource in expected_resources:
        expected_actions.append(
            {
                "action": "inspect",
                "resource": {
                    "id": resource["id"],
                    "kind": resource["kind"],
                },
                "result": "present-or-already-absent",
            }
        )
        if resource["kind"] in {"container", "task"}:
            expected_actions.append(
                {
                    "action": "kill",
                    "resource": {
                        "id": resource["id"],
                        "kind": resource["kind"],
                    },
                    "result": "killed-reaped-or-already-absent",
                }
            )
        expected_actions.append(
            {
                "action": "remove",
                "resource": {
                    "id": resource["id"],
                    "kind": resource["kind"],
                },
                "result": "removed-or-already-absent",
            }
        )
    if payload["cleanupActions"] != expected_actions:
        raise LauncherError(
            "watchdog did not inspect and force-remove every exact resource"
        )
    for ordinal, observation in enumerate(
        payload["absenceObservations"],
        start=1,
    ):
        if observation != {
            "absentResources": expected_refs,
            "labelledAlternates": [],
            "ordinal": ordinal,
            "presentResources": [],
            "searchedExactResourcesAndLabels": expected_searches,
        }:
            raise LauncherError("watchdog absence proof is not exact")
    return payload


def _reconnect_abort(
    *,
    previous: WatchdogSession,
    receipt: dict[str, Any],
    manifest: dict[str, Any],
    allowed_mount_ids: set[int],
) -> dict[str, Any]:
    lease_id = previous.lease_id or previous.requested_lease_id
    if LEASE_RE.fullmatch(lease_id) is None:
        raise LauncherError("cannot recover an invalid watchdog lease")
    try:
        previous.peer.close()
    except LauncherError:
        pass
    peer = _authenticate_watchdog(
        receipt_watchdog=receipt["payload"]["watchdog"],
        allowed_mount_ids=allowed_mount_ids,
    )
    recovery = WatchdogSession(
        peer=peer,
        manifest_sha256=previous.manifest_sha256,
        receipt_sha256=previous.receipt_sha256,
        daemon=previous.daemon,
        requested_lease_id=lease_id,
        lease_id=lease_id,
        session_id=previous.session_id,
        sequence=previous.sequence,
        previous_response_sha256=previous.previous_response_sha256,
        seen_server_nonces=set(previous.seen_server_nonces),
        server_nonce_history=list(previous.server_nonce_history),
        lease_event_head_sha256=previous.lease_event_head_sha256,
    )
    recovery_challenge = secrets.token_hex(32)
    try:
        payload = recovery.exchange(
            "ABORT",
            {
                "authoritativeLeaseInventory": True,
                "recoveryChallenge": recovery_challenge,
                "reason": "launcher-recovery",
            },
            timeout_seconds=120,
            recovery=True,
            recovery_challenge=recovery_challenge,
        )
        if recovery.lease_event_head_sha256 is None:
            raise LauncherError("recovery omitted its durable lease event head")
        return _validate_cleanup(
            payload,
            lease_id=lease_id,
            daemon_evidence_sha256=_daemon_evidence_digest(
                daemon=previous.daemon,
                lease_id=lease_id,
                manifest_sha256=previous.manifest_sha256,
                receipt_sha256=previous.receipt_sha256,
            ),
            manifest=manifest,
            receipt_sha256=previous.receipt_sha256,
            terminal="aborted",
            lease_event_head_sha256=recovery.lease_event_head_sha256,
        )
    finally:
        recovery.peer.close()


def _verify(args: argparse.Namespace) -> dict[str, Any]:
    for name, label in (
        ("expected_base_measurement", "external base measurement"),
        ("expected_launcher_sha256", "launcher digest"),
        ("expected_python_sha256", "Python digest"),
        ("expected_runtime_manifest_sha256", "runtime-manifest digest"),
        ("expected_promotion_receipt_sha256", "promotion-receipt digest"),
        ("expected_promotion_public_key_spki_sha256", "public-key SPKI digest"),
        ("expected_promotion_public_key_raw_sha256", "public-key raw digest"),
        ("expected_candidate_index_sha256", "candidate-index digest"),
        ("expected_candidate_file_sha256", "candidate-file digest"),
        ("expected_candidate_payload_sha256", "candidate-payload digest"),
        ("expected_manifest_sha256", "final manifest digest"),
        ("expected_manifest_file_sha256", "final manifest file digest"),
        ("expected_promotion_acceptance_sha256", "promotion acceptance digest"),
        (
            "expected_capability_authority_public_key_spki_sha256",
            "capability-authority SPKI digest",
        ),
        (
            "expected_capability_authority_public_key_raw_sha256",
            "capability-authority raw digest",
        ),
    ):
        setattr(args, name, _required_digest(getattr(args, name), label=label))
    args.expected_python_path = _absolute(
        args.expected_python_path,
        label="trusted Python",
    )
    args.promotion_public_key = _absolute(
        args.promotion_public_key,
        label="promotion public key",
    )
    args.capability_authority_public_key = _absolute(
        args.capability_authority_public_key,
        label="dependency capability authority public key",
    )
    args.promotion_receipt = _absolute(
        args.promotion_receipt,
        label="promotion receipt",
    )
    args.trusted_runtime_manifest = _absolute(
        args.trusted_runtime_manifest,
        label="trusted runtime manifest",
    )
    args.manifest = _absolute(args.manifest, label="promoted Manifest v6")
    allowed_mount_ids = set(args.allowed_read_only_mount_id)
    if not allowed_mount_ids:
        raise LauncherError("at least one read-only mount ID is required")
    public_key_identity, public_key = _load_public_key(args)
    (
        capability_key_identity,
        capability_public_key,
    ) = _load_capability_authority_public_key(args)
    if (
        capability_key_identity["rawKeySha256"]
        == public_key_identity["rawKeySha256"]
    ):
        raise LauncherError(
            "promotion and dependency capability authorities are not independent"
        )
    receipt, _manifest_identity, manifest_raw = _load_receipt(
        args,
        public_key=public_key,
        public_key_identity=public_key_identity,
        capability_public_key=capability_public_key,
        allowed_mount_ids=allowed_mount_ids,
    )
    manifest = _validate_manifest(
        manifest_raw,
        args=args,
        capability_public_key=capability_public_key,
    )
    receipt_boot_cleanup_sha256 = receipt["payload"]["watchdog"][
        "bootCleanupContract"
    ]["contractSha256"]
    if (
        receipt["payload"]["images"] != manifest["images"]
        or receipt["payload"]["imageMappings"] != manifest["imageMappings"]
        or receipt["payload"]["sourceEvidence"]
        != manifest["sourceSnapshot"]["sourceEvidence"]
        or receipt["payload"]["sourceEvidenceSha256"]
        != manifest["sourceSnapshot"]["sourceEvidenceSha256"]
        or receipt["payload"]["candidatePromotionContractSha256"]
        != manifest["promotion"]["candidatePromotionContractSha256"]
        or manifest["candidate"]["promotionContractSha256"]
        != manifest["promotion"]["candidatePromotionContractSha256"]
        or receipt_boot_cleanup_sha256
        != manifest["watchdog"]["bootCleanupContractSha256"]
    ):
        raise LauncherError("manifest and signed receipt contracts differ")
    runtime = _load_trusted_runtime(
        args,
        receipt_runtime=receipt["payload"]["launcherRuntime"],
        public_key_identity=public_key_identity,
        capability_key_identity=capability_key_identity,
        allowed_mount_ids=allowed_mount_ids,
    )
    peer = _authenticate_watchdog(
        receipt_watchdog=receipt["payload"]["watchdog"],
        allowed_mount_ids=allowed_mount_ids,
    )
    session = WatchdogSession(
        peer=peer,
        manifest_sha256=manifest["manifestSha256"],
        receipt_sha256=args.expected_promotion_receipt_sha256,
        daemon=receipt["payload"]["daemon"],
        requested_lease_id=secrets.token_hex(32),
    )
    previous_handlers = {
        item: signal.getsignal(item)
        for item in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM)
    }

    def interrupted(signum: int, _frame: Any) -> None:
        raise LauncherError(
            f"trusted launcher received {signal.Signals(signum).name}"
        )

    for item in previous_handlers:
        signal.signal(item, interrupted)
    observed_resources: list[dict[str, Any]] = []
    lane_results: list[dict[str, Any]] = []
    cleanup: dict[str, Any] | None = None
    primary: BaseException | None = None
    postconditions: list[BaseException] = []
    try:
        begin_payload = session.exchange(
            "BEGIN",
            {
                "candidateIndexSha256": args.expected_candidate_index_sha256,
                "candidateManifestFileSha256": (
                    args.expected_candidate_file_sha256
                ),
                "candidateManifestPayloadSha256": (
                    args.expected_candidate_payload_sha256
                ),
                "laneOrder": manifest["laneOrder"],
                "promotionAcceptanceSha256": (
                    args.expected_promotion_acceptance_sha256
                ),
                "requestedLeaseId": session.requested_lease_id,
            },
            timeout_seconds=30,
        )
        daemon_evidence_sha256 = _validate_begin(
            begin_payload,
            session=session,
            receipt=receipt,
            manifest=manifest,
        )
        if session.lease_id is None or session.session_id is None:
            raise LauncherError("watchdog did not allocate a lease/session")
        for lane_sequence, lane in enumerate(manifest["laneOrder"]):
            lane_contract = manifest["lanes"][lane]
            payload = session.exchange(
                "RUN_LANE",
                {
                    "imageId": manifest["images"][
                        lane_contract["imageRole"]
                    ]["containerdImageId"],
                    "lane": lane,
                    "laneContractSha256": _sha256(
                        _canonical_json(lane_contract)
                    ),
                    "laneSequence": lane_sequence,
                },
                timeout_seconds=lane_contract["isolation"]["timeoutSeconds"] + 120,
            )
            if session.lease_event_head_sha256 is None:
                raise LauncherError(
                    f"{lane} omitted its durable lease event head"
                )
            resources = _validate_lane_result(
                payload,
                lane=lane,
                lane_sequence=lane_sequence,
                lease_id=session.lease_id,
                daemon_evidence_sha256=daemon_evidence_sha256,
                manifest=manifest,
                receipt_watchdog=receipt["payload"]["watchdog"],
                receipt_sha256=args.expected_promotion_receipt_sha256,
                session_id=session.session_id,
                lease_event_head_sha256=session.lease_event_head_sha256,
            )
            observed_resources.extend(resources)
            if (
                len(
                    {
                        (item["kind"], item["id"])
                        for item in observed_resources
                    }
                )
                != len(observed_resources)
                or len(
                    {
                        (item["kind"], item["name"])
                        for item in observed_resources
                    }
                )
                != len(observed_resources)
            ):
                raise LauncherError(
                    "runtime resource kind/ID or kind/name was reused"
                )
            lane_results.append(
                {
                    "lane": lane,
                    "resultSha256": payload["resultSha256"],
                    "resources": resources,
                }
            )
        finish_payload = session.exchange(
            "FINISH",
            {"authoritativeLeaseInventory": True},
            timeout_seconds=120,
        )
        if session.lease_event_head_sha256 is None:
            raise LauncherError("FINISH omitted its durable lease event head")
        cleanup = _validate_cleanup(
            finish_payload,
            lease_id=session.lease_id,
            daemon_evidence_sha256=daemon_evidence_sha256,
            manifest=manifest,
            receipt_sha256=args.expected_promotion_receipt_sha256,
            terminal="finished",
            lease_event_head_sha256=session.lease_event_head_sha256,
        )
    except BaseException as exc:
        primary = exc
    finally:
        for item in previous_handlers:
            try:
                signal.signal(item, signal.SIG_IGN)
            except BaseException as exc:
                postconditions.append(exc)
        if cleanup is None:
            try:
                cleanup = _reconnect_abort(
                    previous=session,
                    receipt=receipt,
                    manifest=manifest,
                    allowed_mount_ids=allowed_mount_ids,
                )
            except BaseException as exc:
                postconditions.append(exc)
        else:
            try:
                session.peer.close()
            except BaseException as exc:
                postconditions.append(exc)
        for item, previous in previous_handlers.items():
            try:
                signal.signal(item, previous)
            except BaseException as exc:
                postconditions.append(exc)
    try:
        remeasured_key_identity, remeasured_key = _load_public_key(args)
        (
            remeasured_capability_key_identity,
            remeasured_capability_public_key,
        ) = _load_capability_authority_public_key(args)
        remeasured_receipt, _, remeasured_manifest_raw = _load_receipt(
            args,
            public_key=remeasured_key,
            public_key_identity=remeasured_key_identity,
            capability_public_key=remeasured_capability_public_key,
            allowed_mount_ids=allowed_mount_ids,
        )
        remeasured_manifest = _validate_manifest(
            remeasured_manifest_raw,
            args=args,
            capability_public_key=remeasured_capability_public_key,
        )
        remeasured_runtime = _load_trusted_runtime(
            args,
            receipt_runtime=remeasured_receipt["payload"]["launcherRuntime"],
            public_key_identity=remeasured_key_identity,
            capability_key_identity=remeasured_capability_key_identity,
            allowed_mount_ids=allowed_mount_ids,
        )
        remeasured_peer = _authenticate_watchdog(
            receipt_watchdog=remeasured_receipt["payload"]["watchdog"],
            allowed_mount_ids=allowed_mount_ids,
        )
        remeasured_peer.close()
        if (
            remeasured_receipt != receipt
            or remeasured_manifest != manifest
            or remeasured_runtime != runtime
            or remeasured_key_identity != public_key_identity
            or remeasured_capability_key_identity
            != capability_key_identity
        ):
            raise LauncherError(
                "trusted runtime or promoted identities changed after lanes"
            )
    except BaseException as exc:
        postconditions.append(exc)
    if primary is not None:
        if postconditions:
            raise LauncherError(
                f"OCI verification failed: {primary}; postcondition failures: "
                + " | ".join(str(item) for item in postconditions)
            ) from primary
        raise primary.with_traceback(primary.__traceback__)
    if postconditions:
        raise LauncherError(
            "OCI verification postconditions failed: "
            + " | ".join(str(item) for item in postconditions)
        ) from postconditions[0]
    return {
        "cleanup": cleanup,
        "lanes": lane_results,
        "manifestSha256": manifest["manifestSha256"],
        "promotionReceiptSha256": args.expected_promotion_receipt_sha256,
        "trustRoot": {
            "externalPrerequisite": (
                "Coder/TEE measured the immutable launcher runtime, signed "
                "promotion materials, root watchdog, and dedicated daemon"
            ),
            "laneFilesystemClosure": "promoter-inspected immutable OCI rootfs",
            "selfAttestationClaimed": False,
        },
        "trustedRuntime": runtime,
    }


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Direct trusted launcher for promoted OCI verification lanes.",
        allow_abbrev=False,
    )
    commands = parser.add_subparsers(dest="command", required=True)
    verify = commands.add_parser("verify", allow_abbrev=False)
    for option in (
        "capability-authority-public-key",
        "expected-python-path",
        "manifest",
        "promotion-public-key",
        "promotion-receipt",
        "trusted-runtime-manifest",
    ):
        verify.add_argument(
            f"--{option}",
            required=True,
            type=Path,
            action=StoreOnce,
        )
    for option in (
        "expected-capability-authority-public-key-raw-sha256",
        "expected-capability-authority-public-key-spki-sha256",
        "expected-base-measurement",
        "expected-candidate-index-sha256",
        "expected-candidate-file-sha256",
        "expected-candidate-payload-sha256",
        "expected-launcher-sha256",
        "expected-manifest-file-sha256",
        "expected-manifest-sha256",
        "expected-promotion-acceptance-sha256",
        "expected-promotion-public-key-raw-sha256",
        "expected-promotion-public-key-spki-sha256",
        "expected-promotion-receipt-sha256",
        "expected-python-sha256",
        "expected-runtime-manifest-sha256",
    ):
        verify.add_argument(
            f"--{option}",
            required=True,
            action=StoreOnce,
        )
    verify.add_argument(
        "--allowed-read-only-mount-id",
        required=True,
        action=AppendUnique,
        type=int,
        default=[],
    )
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    try:
        if args.command != "verify":
            raise LauncherError(f"unsupported command: {args.command}")
        result = _verify(args)
        print(
            _canonical_json({"ok": True, "result": result}).decode("ascii"),
            flush=True,
        )
    except (LauncherError, OSError, TypeError, ValueError) as exc:
        raise SystemExit(str(exc)) from exc


if __name__ == "__main__":
    main()
