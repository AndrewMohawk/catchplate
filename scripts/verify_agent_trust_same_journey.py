#!/usr/bin/env python3
"""Build-time recorder for closed OCI verification lanes.

This program never launches a verification lane. It freezes source, emits the
closed OCI build plan, independently measures deterministic OCI archives and
their merged root filesystems, and records Candidate Manifest v6. Final lane
execution belongs exclusively to the externally authenticated root watchdog.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import configparser
import csv
import email.parser
import email.policy
import gzip
import hashlib
import io
import json
import os
import re
import stat
import struct
import tarfile
import unicodedata
import zipfile
import zlib
from pathlib import Path, PurePosixPath
from typing import Any


SOURCE_INPUT_MANIFEST_VERSION = "catchplate.sourceInputManifest/v3"
SOURCE_SNAPSHOT_VERSION = "catchplate.sourceSnapshot/v7"
GIT_SOURCE_INVENTORY_VERSION = "catchplate.gitSourceInventory/v3"
UNTRACKED_APPROVAL_VERSION = "catchplate.untrackedSourceApproval/v2"
OCI_BUILD_PLAN_VERSION = "catchplate.ociLaneBuildPlan/v4"
OCI_DEPENDENCY_BUNDLE_VERSION = "catchplate.ociDependencyBundle/v5"
OCI_BUILD_BUNDLE_VERSION = "catchplate.ociBuildBundle/v3"
OCI_FILE_MANIFEST_VERSION = "catchplate.ociRootfsFileManifest/v2"
BUILD_WATCHDOG_RECEIPT_VERSION = "catchplate.ociBuildWatchdogReceipt/v4"
BUILD_WATCHDOG_CONTRACT_VERSION = "catchplate.ociBuildWatchdogContract/v4"
CANDIDATE_MANIFEST_VERSION = "catchplate.consolidatedCandidateArtifacts/v6"
CANDIDATE_INDEX_VERSION = "catchplate.consolidatedCandidateIndex/v1"
BUILD_MANIFEST_VERSION = "catchplate.consolidatedTestArtifacts/v6"
PROMOTION_CONTRACT_VERSION = "catchplate.verificationPromotionContract/v6"
WATCHDOG_PROTOCOL_VERSION = "catchplate.ociVerificationWatchdog/v4"
BUILD_WATCHDOG_SIGNATURE_DOMAIN = (
    b"catchplate.ociBuildWatchdogReceipt/v4\x00Ed25519\x00"
)
GIT_SOURCE_INVENTORY_SIGNATURE_DOMAIN = (
    b"catchplate.gitSourceInventory/v3\x00Ed25519\x00"
)
UNTRACKED_APPROVAL_SIGNATURE_DOMAIN = (
    b"catchplate.untrackedSourceApproval/v2\x00Ed25519\x00"
)
CAPABILITY_ATTESTATION_VERSION = (
    "catchplate.dependencyCapabilityAttestation/v1"
)
CAPABILITY_ATTESTATION_SIGNATURE_DOMAIN = (
    b"catchplate.dependencyCapabilityAttestation/v1\x00Ed25519\x00"
)
MAX_JSON_BYTES = 64 * 1024 * 1024
MAX_SOURCE_FILES = 100_000
MAX_SOURCE_BYTES = 8 * 1024 * 1024 * 1024
MAX_OCI_ARCHIVE_BYTES = 16 * 1024 * 1024 * 1024
MAX_OCI_MEMBERS = 400_000
MAX_ROOTFS_FILES = 400_000
MAX_ROOTFS_BYTES = 16 * 1024 * 1024 * 1024
MAX_LAYER_BYTES = 8 * 1024 * 1024 * 1024
CLEAN_ROOM_MAX_FILE_BYTES = 256 * 1024 * 1024
CLEAN_ROOM_MAX_FILES = 20_000
CLEAN_ROOM_MAX_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
HEX_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
LANE_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{0,63}$")
SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,254}$")
WHEEL_FILENAME_RE = re.compile(
    r"^(?P<distribution>[A-Za-z0-9][A-Za-z0-9._+]*)-"
    r"(?P<version>[A-Za-z0-9][A-Za-z0-9._+]*)-"
    r"(?P<python>[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)*)-"
    r"(?P<abi>[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)*)-"
    r"(?P<platform>[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)*)\.whl$"
)
LEASE_RE = re.compile(r"^[0-9a-f]{64}$")
RUNTIME_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@+-]{11,255}$")
OCI_MANIFEST_MEDIA_TYPE = "application/vnd.oci.image.manifest.v1+json"
OCI_CONFIG_MEDIA_TYPE = "application/vnd.oci.image.config.v1+json"
OCI_LAYER_MEDIA_TYPE = "application/vnd.oci.image.layer.v1.tar+gzip"
ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
ED25519_FIELD = 2**255 - 19
ED25519_ORDER = 2**252 + 27742317777372353535851937790883648493
ED25519_D = (
    -121665 * pow(121666, ED25519_FIELD - 2, ED25519_FIELD)
) % ED25519_FIELD
ED25519_SQRT_M1 = pow(2, (ED25519_FIELD - 1) // 4, ED25519_FIELD)
ED25519_IDENTITY = (0, 1, 1, 0)
RESOURCE_LABEL_NAMES = [
    "org.catchplate.build-lease",
    "org.catchplate.build-plan",
    "org.catchplate.image-role",
    "org.catchplate.resource-kind",
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
PYTHON_LANE_SCRIPTS = {
    "approval-review": "scripts/test_approval_review.py",
    "credential-constraints": "scripts/test_credential_constraints.py",
    "credential-constraints-proxy": "scripts/test_credential_constraints.py",
    "internal-service-auth": "scripts/test_internal_service_auth.py",
    "jit-transaction-sqlite-full": "scripts/test_jit_transaction_state.py",
    "onboarding-evidence": "scripts/test_onboarding_evidence.py",
    "webauthn-attestation": "scripts/test_webauthn_attestation.py",
}
DEPENDENCY_ROLES = {
    "browser-runtime",
    "clean-room-runtime",
    "npm-11.8-runtime",
    "python-runtime",
    "rust-runtime",
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
CLEAN_ROOM_MARKER_ENVIRONMENT = {
    "implementation_name": "cpython",
    "implementation_version": "3.11.11",
    "os_name": "posix",
    "platform_machine": "x86_64",
    "platform_python_implementation": "CPython",
    "platform_release": "",
    "platform_system": "Linux",
    "platform_version": "",
    "python_full_version": "3.11.11",
    "python_version": "3.11",
    "sys_platform": "linux",
}
CLEAN_ROOM_WHEELHOUSE_SCHEMA = {
    "apiVersion": "catchplate.cleanRoomWheelhouseManifest/v3",
    "fileFields": ["path", "sha256", "size"],
    "packageFields": [
        "name",
        "normalizedName",
        "providesExtras",
        "requires",
        "sha256",
        "version",
        "wheel",
    ],
    "payloadDigestField": "payloadSha256",
}
PYTHON_CAPABILITY_PROBES = (
    "dns-nss-local-bounded",
    "multiprocessing-spawn-bounded",
    "openssl-provider-load",
    "sqlite-memory-and-file",
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
    "XDG_RUNTIME_DIR": "/run/catchplate-runtime",
}
PORTAL_DYNAMIC_ENVIRONMENT = [
    "CATCHPLATE_ATTEMPT",
    "CATCHPLATE_LANE",
    "CATCHPLATE_LEASE_ID",
    "CATCHPLATE_MANIFEST_SHA256",
    "CATCHPLATE_NPM_COMPANION_IMAGE_ID",
    "CATCHPLATE_NPM_ENTRYPOINT_SHA256",
    "CATCHPLATE_NPM_NODE_SHA256",
    "CATCHPLATE_NPM_PACKAGE_SHA256",
    "CATCHPLATE_ONE_USE_NONCE",
    "CATCHPLATE_PROMOTION_RECEIPT_SHA256",
    "CATCHPLATE_WATCHDOG_ENDPOINT",
    "CATCHPLATE_WATCHDOG_TLS_SPKI_SHA256",
]
PYTHON_ENTRYPOINT_SOURCE = "scripts/oci_lane_entrypoint.py"
PYTHON_ENTRYPOINT_IMAGE = "/opt/catchplate/src/scripts/oci_lane_entrypoint.py"
NPM_ENTRYPOINT_SOURCE = "scripts/npm_publish_companion.js"
NPM_ENTRYPOINT_IMAGE = "/opt/catchplate/src/scripts/npm_publish_companion.js"
SOURCE_SELECTION_MODEL = (
    "signed-raw-git-index-tree-worktree-status-plus-approved-untracked/v3"
)
SOURCE_CLASSIFICATIONS = frozenset({"build-input", "source"})
LANE_SOURCE_CONTRACTS = {
    "approval-review": {
        "exact": ["scripts/test_approval_review.py"],
        "prefixes": ["catchplate/", "catchplate_agent_trust/"],
    },
    "browser-python-compatibility": {"exact": [], "prefixes": []},
    "chromium-compatibility": {"exact": [], "prefixes": []},
    "clean-room": {
        "exact": [
            "scripts/test_agent_trust_clean_room.py",
            "scripts/verify_offline_artifact_manifest.py",
        ],
        "prefixes": ["catchplate_agent_trust/"],
    },
    "credential-constraints": {
        "exact": ["scripts/test_credential_constraints.py"],
        "prefixes": ["catchplate/", "catchplate_agent_trust/"],
    },
    "credential-constraints-proxy": {
        "exact": ["scripts/test_credential_constraints.py"],
        "prefixes": ["catchplate/", "catchplate_agent_trust/"],
    },
    "host-python-compatibility": {"exact": [], "prefixes": []},
    "internal-service-auth": {
        "exact": ["scripts/test_internal_service_auth.py"],
        "prefixes": ["catchplate/", "catchplate_agent_trust/"],
    },
    "jit-transaction-sqlite-full": {
        "exact": ["scripts/test_jit_transaction_state.py"],
        "prefixes": ["catchplate/", "catchplate_agent_trust/"],
    },
    "onboarding-evidence": {
        "exact": [
            "scripts/test_onboarding_evidence.py",
            "scripts/verify_onboarding_evidence.py",
        ],
        "prefixes": ["catchplate/", "catchplate_agent_trust/"],
    },
    "portal-browser-oauth": {
        "exact": [
            "scripts/oauth_provider_simulator.py",
            "scripts/test_portal_browser_oauth.py",
        ],
        "prefixes": [
            "data-plane/decision-gate-rs/",
            "catchplate/",
            "catchplate_agent_trust/",
        ],
    },
    "proxy-python-compatibility": {"exact": [], "prefixes": []},
    "rust-decision-gate-tests": {
        "exact": [],
        "prefixes": ["data-plane/decision-gate-rs/"],
    },
    "webauthn-attestation": {
        "exact": ["scripts/test_webauthn_attestation.py"],
        "prefixes": ["catchplate/", "catchplate_agent_trust/"],
    },
}


class VerificationError(RuntimeError):
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


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise VerificationError(f"JSON contains duplicate key: {key}")
        result[key] = value
    return result


def _reject_number(value: str) -> None:
    raise VerificationError(f"JSON contains an unsupported number: {value}")


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
        raise VerificationError("value cannot be represented as canonical JSON") from exc


def _load_json(raw: bytes, *, label: str) -> Any:
    if len(raw) > MAX_JSON_BYTES:
        raise VerificationError(f"{label} exceeds its byte limit")
    try:
        return json.loads(
            raw.decode("ascii"),
            object_pairs_hook=_strict_object,
            parse_constant=_reject_number,
            parse_float=_reject_number,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise VerificationError(f"{label} is not strict ASCII JSON") from exc


def _load_canonical_json_blob(raw: bytes, *, label: str) -> Any:
    value = _load_json(raw, label=label)
    if raw != _canonical_json(value):
        raise VerificationError(f"{label} bytes are not canonical JSON")
    return value


def _sha256(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _required_digest(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise VerificationError(f"{label} must be sha256:<64 lowercase hex>")
    return value


def _absolute(path: Path, *, label: str) -> Path:
    if not path.is_absolute() or "\x00" in str(path):
        raise VerificationError(f"{label} must be one absolute path")
    if any(part in {"", ".", ".."} for part in path.parts[1:]):
        raise VerificationError(f"{label} contains an unsafe component")
    return path


def _under(path: Path, root: Path, *, label: str) -> Path:
    absolute = _absolute(path, label=label)
    base = _absolute(root, label=f"{label} root")
    try:
        relative = absolute.relative_to(base)
    except ValueError as exc:
        raise VerificationError(f"{label} escapes its root") from exc
    if relative == Path("."):
        raise VerificationError(f"{label} must not equal its root")
    return relative


def _read_regular(
    path: Path,
    *,
    label: str,
    max_bytes: int = MAX_JSON_BYTES,
) -> tuple[bytes, os.stat_result]:
    absolute = _absolute(path, label=label)
    parent = os.open(
        "/",
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    descriptor = -1
    try:
        for component in absolute.parts[1:-1]:
            child = os.open(
                component,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NONBLOCK", 0)
                | os.O_NOFOLLOW,
                dir_fd=parent,
            )
            metadata = os.fstat(child)
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid not in {0, os.getuid()}
                or stat.S_IMODE(metadata.st_mode) & 0o022
            ):
                os.close(child)
                raise VerificationError(f"{label} has an unsafe ancestor")
            os.close(parent)
            parent = child
        descriptor = os.open(
            absolute.name,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NONBLOCK", 0)
            | os.O_NOFOLLOW,
            dir_fd=parent,
        )
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid not in {0, os.getuid()}
            or stat.S_IMODE(before.st_mode) & 0o022
            or before.st_size < 0
            or before.st_size > max_bytes
        ):
            raise VerificationError(
                f"{label} is not an owner-controlled bounded regular file"
            )
        chunks: list[bytes] = []
        total = 0
        while True:
            raw = os.read(descriptor, min(1024 * 1024, max_bytes + 1 - total))
            if not raw:
                break
            chunks.append(raw)
            total += len(raw)
            if total > max_bytes:
                raise VerificationError(f"{label} exceeds its byte limit")
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
            raise VerificationError(f"{label} changed while read")
        return b"".join(chunks), after
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent)


def _open_safe_root(path: Path, *, label: str) -> tuple[int, os.stat_result]:
    absolute = _absolute(path, label=label)
    parent = os.open(
        "/",
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        for component in absolute.parts[1:]:
            child = os.open(
                component,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_CLOEXEC", 0)
                | os.O_NOFOLLOW,
                dir_fd=parent,
            )
            metadata = os.fstat(child)
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid not in {0, os.getuid()}
                or stat.S_IMODE(metadata.st_mode) & 0o022
            ):
                os.close(child)
                raise VerificationError(f"{label} has an unsafe component")
            os.close(parent)
            parent = child
        return parent, os.fstat(parent)
    except BaseException:
        os.close(parent)
        raise


def _read_regular_at(
    root_fd: int,
    relative: PurePosixPath,
    *,
    label: str,
    max_bytes: int = MAX_JSON_BYTES,
) -> tuple[bytes, os.stat_result]:
    parent = os.dup(root_fd)
    descriptor = -1
    try:
        for component in relative.parts[:-1]:
            child = os.open(
                component,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_CLOEXEC", 0)
                | os.O_NOFOLLOW,
                dir_fd=parent,
            )
            metadata = os.fstat(child)
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid not in {0, os.getuid()}
                or stat.S_IMODE(metadata.st_mode) & 0o022
            ):
                os.close(child)
                raise VerificationError(f"{label} has an unsafe ancestor")
            os.close(parent)
            parent = child
        descriptor = os.open(
            relative.parts[-1],
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NONBLOCK", 0)
            | os.O_NOFOLLOW,
            dir_fd=parent,
        )
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid not in {0, os.getuid()}
            or stat.S_IMODE(before.st_mode) & 0o022
            or before.st_size < 0
            or before.st_size > max_bytes
        ):
            raise VerificationError(f"{label} is not a safe bounded regular file")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(
                descriptor,
                min(1024 * 1024, max_bytes + 1 - total),
            )
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > max_bytes:
                raise VerificationError(f"{label} exceeds its byte limit")
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
            raise VerificationError(f"{label} changed while read")
        return b"".join(chunks), after
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent)


def _content_identity(
    path: Path,
    *,
    label: str,
    max_bytes: int = MAX_OCI_ARCHIVE_BYTES,
) -> dict[str, Any]:
    raw, _ = _read_regular(path, label=label, max_bytes=max_bytes)
    return {"path": str(path), "sha256": _sha256(raw), "size": len(raw)}


def _open_output_parent(
    path: Path,
    *,
    create: bool,
    label: str,
) -> tuple[int, str]:
    absolute = _absolute(path, label=label)
    parent = os.open(
        "/",
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        for component in absolute.parts[1:-1]:
            try:
                child = os.open(
                    component,
                    os.O_RDONLY
                    | getattr(os, "O_DIRECTORY", 0)
                    | getattr(os, "O_CLOEXEC", 0)
                    | os.O_NOFOLLOW,
                    dir_fd=parent,
                )
            except FileNotFoundError:
                if not create:
                    raise
                os.mkdir(component, 0o700, dir_fd=parent)
                child = os.open(
                    component,
                    os.O_RDONLY
                    | getattr(os, "O_DIRECTORY", 0)
                    | getattr(os, "O_CLOEXEC", 0)
                    | os.O_NOFOLLOW,
                    dir_fd=parent,
                )
            metadata = os.fstat(child)
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid not in {0, os.getuid()}
                or stat.S_IMODE(metadata.st_mode) & 0o022
            ):
                os.close(child)
                raise VerificationError(f"{label} has an unsafe ancestor")
            os.close(parent)
            parent = child
        return parent, absolute.parts[-1]
    except BaseException:
        os.close(parent)
        raise


def _path_type_nofollow(path: Path, *, label: str) -> str | None:
    try:
        parent, name = _open_output_parent(path, create=False, label=label)
    except FileNotFoundError:
        return None
    try:
        try:
            metadata = os.stat(name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            return None
        if stat.S_ISREG(metadata.st_mode):
            return "file"
        if stat.S_ISDIR(metadata.st_mode):
            return "directory"
        if stat.S_ISLNK(metadata.st_mode):
            return "symlink"
        return "other"
    finally:
        os.close(parent)


def _publish(
    path: Path,
    raw: bytes,
    *,
    output_root: Path,
    mode: int = 0o400,
) -> None:
    _under(path, output_root, label="output")
    parent, name = _open_output_parent(path, create=True, label="output")
    parent_identity = os.fstat(parent)
    descriptor = -1
    created_identity: tuple[int, int] | None = None
    try:
        descriptor = os.open(
            name,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | os.O_NOFOLLOW,
            mode,
            dir_fd=parent,
        )
        created = os.fstat(descriptor)
        if (
            not stat.S_ISREG(created.st_mode)
            or created.st_nlink != 1
            or created.st_uid != os.getuid()
            or stat.S_IMODE(created.st_mode) != mode
        ):
            raise VerificationError("output leaf metadata is unsafe")
        created_identity = (created.st_dev, created.st_ino)
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise VerificationError("output write made no progress")
            view = view[written:]
        os.fsync(descriptor)
        final_leaf = os.fstat(descriptor)
        if (
            not stat.S_ISREG(final_leaf.st_mode)
            or final_leaf.st_nlink != 1
            or final_leaf.st_uid != os.getuid()
            or stat.S_IMODE(final_leaf.st_mode) != mode
            or final_leaf.st_size != len(raw)
        ):
            raise VerificationError("published output metadata changed")
        os.close(descriptor)
        descriptor = -1
        os.fsync(parent)
        current_parent, current_name = _open_output_parent(
            path,
            create=False,
            label="output path continuity",
        )
        try:
            current_parent_identity = os.fstat(current_parent)
            current_leaf = os.stat(
                current_name,
                dir_fd=current_parent,
                follow_symlinks=False,
            )
            parent_fields = lambda item: (
                item.st_dev,
                item.st_ino,
                item.st_mode,
                item.st_uid,
                item.st_gid,
            )
            leaf_fields = lambda item: (
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
            if (
                current_name != name
                or parent_fields(current_parent_identity)
                != parent_fields(parent_identity)
                or leaf_fields(current_leaf) != leaf_fields(final_leaf)
            ):
                raise VerificationError(
                    "output pathname changed during publication"
                )
        finally:
            os.close(current_parent)
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
            descriptor = -1
        try:
            current = os.stat(name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            current = None
        if current is not None:
            if (
                created_identity is None
                or not stat.S_ISREG(current.st_mode)
                or (current.st_dev, current.st_ino) != created_identity
            ):
                raise VerificationError(
                    "output leaf was replaced during failed publication"
                )
            os.unlink(name, dir_fd=parent)
            os.fsync(parent)
        raise
    finally:
        os.close(parent)


def _safe_relative(value: str, *, label: str) -> PurePosixPath:
    if (
        not isinstance(value, str)
        or not value
        or "\x00" in value
        or value != unicodedata.normalize("NFC", value)
        or value.startswith("/")
        or value.endswith("/")
        or "//" in value
        or any(component in {"", ".", ".."} for component in value.split("/"))
    ):
        raise VerificationError(f"{label} is empty or invalid")
    path = PurePosixPath(value)
    if path.is_absolute() or path.as_posix() != value:
        raise VerificationError(f"{label} contains an unsafe path")
    return path


def _validate_internal_symlink(
    *,
    link: PurePosixPath,
    target: str,
) -> PurePosixPath:
    if (
        not target
        or "\x00" in target
        or target != unicodedata.normalize("NFC", target)
        or target.startswith("/")
        or target.endswith("/")
        or "//" in target
        or len(target.encode("utf-8")) > 4096
    ):
        raise VerificationError("source contains an invalid symlink")
    components = target.split("/")
    if (
        len(components) > 128
        or any(
            component in {"", "."}
            or len(component.encode("utf-8")) > 255
            for component in components
        )
    ):
        raise VerificationError("source symlink target is not canonical")
    resolved = list(link.parent.parts)
    for component in components:
        if component == "..":
            if not resolved:
                raise VerificationError("source symlink escapes the frozen snapshot")
            resolved.pop()
            continue
        resolved.append(component)
    if not resolved:
        raise VerificationError("source symlink may not target the snapshot root")
    return PurePosixPath(*resolved)


def _validate_source_path(path: PurePosixPath) -> None:
    _safe_relative(path.as_posix(), label="source input path")
    if (
        path.as_posix() != unicodedata.normalize("NFC", path.as_posix())
        or len(path.parts) > 128
        or len(path.as_posix().encode("utf-8")) > 4096
        or any(len(component.encode("utf-8")) > 255 for component in path.parts)
    ):
        raise VerificationError("source input path encoding or bounds are invalid")


def _validate_inventory_path(value: Any, *, label: str) -> str:
    path = _safe_relative(value, label=label)
    encoded = path.as_posix().encode("utf-8")
    if (
        len(path.parts) > 128
        or len(encoded) > 4096
        or any(len(component.encode("utf-8")) > 255 for component in path.parts)
    ):
        raise VerificationError(f"{label} exceeds its path bounds")
    return path.as_posix()


def _decode_git_path(raw: bytes, *, label: str) -> str:
    if not raw or b"\x00" in raw:
        raise VerificationError(f"{label} is empty or invalid")
    try:
        value = raw.decode("utf-8")
    except UnicodeError as exc:
        raise VerificationError(f"{label} is not UTF-8") from exc
    if value != unicodedata.normalize("NFC", value):
        raise VerificationError(f"{label} is not NFC")
    return _validate_inventory_path(value, label=label)


def _decode_raw_git_evidence(
    value: Any,
    *,
    command: list[str],
    label: str,
    allow_empty: bool = False,
) -> bytes:
    if (
        not isinstance(value, dict)
        or set(value) != {"bytesBase64", "command", "sha256"}
        or value.get("command") != command
        or not isinstance(value.get("bytesBase64"), str)
        or re.fullmatch(
            r"(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|"
            r"[A-Za-z0-9+/]{3}=)?",
            value["bytesBase64"],
        )
        is None
    ):
        raise VerificationError(f"{label} raw evidence is invalid")
    try:
        raw = base64.b64decode(value["bytesBase64"], validate=True)
    except (ValueError, binascii.Error) as exc:
        raise VerificationError(f"{label} raw evidence is not base64") from exc
    if (not raw and not allow_empty) or len(raw) > MAX_JSON_BYTES:
        raise VerificationError(f"{label} raw evidence exceeds its bound")
    if value.get("sha256") != _sha256(raw):
        raise VerificationError(f"{label} raw evidence digest is invalid")
    return raw


def _git_object_id(
    object_format: str,
    object_type: str,
    raw: bytes,
) -> str:
    if object_format == "sha1":
        digest = hashlib.sha1()
    elif object_format == "sha256":
        digest = hashlib.sha256()
    else:
        raise VerificationError("Git object format is unsupported")
    digest.update(
        object_type.encode("ascii")
        + b" "
        + str(len(raw)).encode("ascii")
        + b"\x00"
        + raw
    )
    return f"{object_format}:{digest.hexdigest()}"


def _parse_git_index_evidence(
    raw: bytes,
    *,
    object_format: str,
    object_length: int,
) -> list[dict[str, Any]]:
    if not raw.endswith(b"\x00"):
        raise VerificationError("raw Git index inventory is not NUL terminated")
    entries: list[dict[str, Any]] = []
    for record in raw[:-1].split(b"\x00"):
        metadata, separator, raw_path = record.partition(b"\t")
        fields = metadata.split(b" ")
        if (
            not separator
            or len(fields) != 3
            or fields[0] not in {b"100644", b"100755", b"120000"}
            or re.fullmatch(
                rb"[0-9a-f]{" + str(object_length).encode("ascii") + rb"}",
                fields[1],
            )
            is None
            or fields[2] != b"0"
        ):
            raise VerificationError("raw Git index inventory entry is invalid")
        entries.append(
            {
                "gitMode": fields[0].decode("ascii"),
                "objectId": (
                    object_format + ":" + fields[1].decode("ascii")
                ),
                "path": _decode_git_path(raw_path, label="raw Git index path"),
                "stage": 0,
            }
        )
    if (
        not entries
        or entries != sorted(entries, key=lambda item: item["path"])
        or len({item["path"] for item in entries}) != len(entries)
    ):
        raise VerificationError("raw Git index inventory is incomplete or unordered")
    return entries


def _parse_git_tree_evidence(
    raw: bytes,
    *,
    object_format: str,
    object_length: int,
) -> list[dict[str, Any]]:
    if not raw.endswith(b"\x00"):
        raise VerificationError("raw Git tree inventory is not NUL terminated")
    entries: list[dict[str, Any]] = []
    for record in raw[:-1].split(b"\x00"):
        metadata, separator, raw_path = record.partition(b"\t")
        fields = metadata.split(b" ")
        if (
            not separator
            or len(fields) != 3
            or fields[0] not in {b"100644", b"100755", b"120000"}
            or fields[1] != b"blob"
            or re.fullmatch(
                rb"[0-9a-f]{" + str(object_length).encode("ascii") + rb"}",
                fields[2],
            )
            is None
        ):
            raise VerificationError("raw Git tree inventory entry is invalid")
        entries.append(
            {
                "gitMode": fields[0].decode("ascii"),
                "objectId": (
                    object_format + ":" + fields[2].decode("ascii")
                ),
                "objectType": "blob",
                "path": _decode_git_path(raw_path, label="raw Git tree path"),
            }
        )
    if (
        not entries
        or entries != sorted(entries, key=lambda item: item["path"])
        or len({item["path"] for item in entries}) != len(entries)
    ):
        raise VerificationError("raw Git tree inventory is incomplete or unordered")
    return entries


def _parse_git_status_evidence(raw: bytes) -> dict[str, Any]:
    if not raw:
        ignored: list[str] = []
        untracked: list[str] = []
        changes: list[dict[str, str]] = []
        return {
            "ignoredPaths": ignored,
            "ignoredPathsSha256": _sha256(_canonical_json(ignored)),
            "policy": "git-status-v1-z-complete-with-ignored-separate/v2",
            "trackedChanges": changes,
            "trackedChangesSha256": _sha256(_canonical_json(changes)),
            "untrackedPaths": untracked,
            "untrackedPathsSha256": _sha256(_canonical_json(untracked)),
        }
    if not raw.endswith(b"\x00"):
        raise VerificationError("raw Git status evidence is not NUL terminated")
    ignored: list[str] = []
    untracked: list[str] = []
    changes: list[dict[str, str]] = []
    for record in raw[:-1].split(b"\x00"):
        if len(record) < 4 or record[2:3] != b" ":
            raise VerificationError("raw Git status entry is invalid")
        status = record[:2].decode("ascii")
        path = _decode_git_path(record[3:], label="raw Git status path")
        if status == "!!":
            ignored.append(path)
        elif status == "??":
            untracked.append(path)
        elif (
            re.fullmatch(r"[ MADU?!]{2}", status) is not None
            and "R" not in status
            and "C" not in status
        ):
            changes.append({"path": path, "status": status})
        else:
            raise VerificationError(
                "raw Git status contains an unsupported rename/copy/conflict"
            )
    ignored = sorted(ignored)
    untracked = sorted(untracked)
    changes = sorted(changes, key=lambda item: item["path"])
    if (
        len(ignored) != len(set(ignored))
        or len(untracked) != len(set(untracked))
        or len({item["path"] for item in changes}) != len(changes)
    ):
        raise VerificationError("raw Git status contains duplicate paths")
    return {
        "ignoredPaths": ignored,
        "ignoredPathsSha256": _sha256(_canonical_json(ignored)),
        "policy": "git-status-v1-z-complete-with-ignored-separate/v2",
        "trackedChanges": changes,
        "trackedChangesSha256": _sha256(_canonical_json(changes)),
        "untrackedPaths": untracked,
        "untrackedPathsSha256": _sha256(_canonical_json(untracked)),
    }


def _reconstruct_git_tree(
    entries: list[dict[str, Any]],
    *,
    object_format: str,
) -> str:
    root: dict[str, Any] = {}
    for entry in entries:
        components = entry["path"].split("/")
        current = root
        for component in components[:-1]:
            child = current.setdefault(component, {})
            if not isinstance(child, dict) or "__blob__" in child:
                raise VerificationError("Git tree contains a file/directory collision")
            current = child
        leaf = components[-1]
        if leaf in current:
            raise VerificationError("Git tree contains a duplicate path")
        current[leaf] = {"__blob__": entry}

    def digest_tree(node: dict[str, Any]) -> str:
        serialized: list[tuple[bytes, bytes]] = []
        for name, child in node.items():
            encoded_name = name.encode("utf-8")
            if isinstance(child, dict) and "__blob__" in child:
                entry = child["__blob__"]
                mode = entry["gitMode"].encode("ascii")
                object_id = entry["objectId"]
                sort_name = encoded_name
            else:
                mode = b"40000"
                object_id = digest_tree(child)
                sort_name = encoded_name + b"/"
            serialized.append(
                (
                    sort_name,
                    mode
                    + b" "
                    + encoded_name
                    + b"\x00"
                    + bytes.fromhex(object_id.split(":", 1)[1]),
                )
            )
        serialized.sort(key=lambda item: item[0])
        return _git_object_id(
            object_format,
            "tree",
            b"".join(item[1] for item in serialized),
        )

    return digest_tree(root)


def _load_pinned_ed25519_key(
    path: Path,
    *,
    expected_spki_sha256: str,
    expected_raw_sha256: str,
    label: str,
) -> bytes:
    expected_spki_sha256 = _required_digest(
        expected_spki_sha256,
        label=f"{label} SPKI pin",
    )
    expected_raw_sha256 = _required_digest(
        expected_raw_sha256,
        label=f"{label} raw-key pin",
    )
    raw, _ = _read_regular(path, label=f"{label} public key", max_bytes=1024)
    if (
        _sha256(raw) != expected_spki_sha256
        or len(raw) != len(ED25519_SPKI_PREFIX) + 32
        or not raw.startswith(ED25519_SPKI_PREFIX)
    ):
        raise VerificationError(f"{label} public key differs from its SPKI pin")
    public_key = raw[len(ED25519_SPKI_PREFIX) :]
    if _sha256(public_key) != expected_raw_sha256:
        raise VerificationError(f"{label} public key differs from its raw pin")
    _ed25519_decode(public_key, label=f"{label} public key")
    return public_key


def _verify_source_evidence_envelope(
    document: Any,
    *,
    api_version: str,
    domain: bytes,
    public_key: bytes,
    expected_spki_sha256: str,
    expected_raw_sha256: str,
    label: str,
) -> dict[str, Any]:
    if (
        not isinstance(document, dict)
        or set(document) != {"apiVersion", "payload", "payloadSha256", "signature"}
        or document.get("apiVersion") != api_version
        or not isinstance(document.get("payload"), dict)
        or document.get("payloadSha256")
        != _sha256(_canonical_json(document["payload"]))
    ):
        raise VerificationError(f"{label} envelope is invalid")
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
        or signature.get("domain") != domain[:-1].decode("ascii")
        or signature.get("keyFileSha256") != expected_spki_sha256
        or signature.get("rawKeySha256") != expected_raw_sha256
        or not isinstance(signature.get("value"), str)
        or re.fullmatch(r"[A-Za-z0-9+/]{86}==", signature["value"]) is None
    ):
        raise VerificationError(f"{label} signature envelope is invalid")
    try:
        signature_raw = base64.b64decode(signature["value"], validate=True)
    except (ValueError, binascii.Error) as exc:
        raise VerificationError(f"{label} signature is not strict base64") from exc
    _verify_ed25519(
        public_key=public_key,
        signature=signature_raw,
        message=domain
        + _canonical_json(
            {
                "payload": document["payload"],
                "payloadSha256": document["payloadSha256"],
            }
        ),
    )
    return document["payload"]


def _validate_git_inventory_payload(payload: dict[str, Any]) -> dict[str, Any]:
    if set(payload) != {
        "headTree",
        "indexEntries",
        "indexEntriesSha256",
        "indexInventoryRawSha256",
        "indexTree",
        "objectFormat",
        "rawEvidence",
        "repositoryIdSha256",
        "status",
        "treeEntries",
        "treeEntriesSha256",
        "worktreeEntries",
        "worktreeEntriesSha256",
    }:
        raise VerificationError("Git source inventory payload is not closed")
    object_format = payload.get("objectFormat")
    object_length = 40 if object_format == "sha1" else 64 if object_format == "sha256" else 0
    if (
        object_length == 0
        or re.fullmatch(
            rf"{object_format}:[0-9a-f]{{{object_length}}}",
            str(payload.get("headTree") or ""),
        )
        is None
    ):
        raise VerificationError("Git tree identity is invalid")
    if (
        re.fullmatch(
            rf"{object_format}:[0-9a-f]{{{object_length}}}",
            str(payload.get("indexTree") or ""),
        )
        is None
        or payload["indexTree"] != payload["headTree"]
    ):
        raise VerificationError("Git index tree does not equal HEAD")
    _required_digest(
        payload.get("repositoryIdSha256"),
        label="Git inventory repositoryIdSha256",
    )
    raw_evidence = payload["rawEvidence"]
    if (
        not isinstance(raw_evidence, dict)
        or set(raw_evidence) != {"index", "status", "tree"}
    ):
        raise VerificationError("raw Git evidence inventory is invalid")
    raw_index = _decode_raw_git_evidence(
        raw_evidence["index"],
        command=["git", "ls-files", "--stage", "-z"],
        label="Git index",
    )
    raw_tree = _decode_raw_git_evidence(
        raw_evidence["tree"],
        command=["git", "ls-tree", "-rz", "--full-tree", "HEAD"],
        label="Git tree",
    )
    raw_status = _decode_raw_git_evidence(
        raw_evidence["status"],
        command=[
            "git",
            "status",
            "--porcelain=v1",
            "-z",
            "--ignored=matching",
            "--untracked-files=all",
        ],
        label="Git status",
        allow_empty=True,
    )
    if payload.get("indexInventoryRawSha256") != _sha256(raw_index):
        raise VerificationError("Git raw index digest changed")
    index_entries = payload["indexEntries"]
    tree_entries = payload["treeEntries"]
    worktree_entries = payload["worktreeEntries"]
    if (
        not isinstance(index_entries, list)
        or not isinstance(tree_entries, list)
        or not isinstance(worktree_entries, list)
        or not index_entries
        or worktree_entries
        != sorted(worktree_entries, key=lambda item: str(item.get("path", "")))
        or index_entries
        != _parse_git_index_evidence(
            raw_index,
            object_format=object_format,
            object_length=object_length,
        )
        or tree_entries
        != _parse_git_tree_evidence(
            raw_tree,
            object_format=object_format,
            object_length=object_length,
        )
        or payload.get("indexEntriesSha256")
        != _sha256(_canonical_json(index_entries))
        or payload.get("treeEntriesSha256")
        != _sha256(_canonical_json(tree_entries))
        or payload.get("worktreeEntriesSha256")
        != _sha256(_canonical_json(worktree_entries))
    ):
        raise VerificationError("Git index/tree/worktree inventories are invalid")
    projected_tree = [
        {
            "gitMode": item["gitMode"],
            "objectId": item["objectId"],
            "objectType": "blob",
            "path": item["path"],
        }
        for item in index_entries
    ]
    if (
        tree_entries != projected_tree
        or _reconstruct_git_tree(
            index_entries,
            object_format=object_format,
        )
        != payload["indexTree"]
    ):
        raise VerificationError(
            "Git recursive tree does not equal the complete stage-zero index"
        )
    indexed: dict[str, dict[str, Any]] = {}
    for entry in index_entries:
        if (
            not isinstance(entry, dict)
            or set(entry) != {"gitMode", "objectId", "path", "stage"}
            or entry.get("gitMode") not in {"100644", "100755", "120000"}
            or entry.get("stage") != 0
        ):
            raise VerificationError("Git index entry is unsupported")
        path = _validate_inventory_path(entry.get("path"), label="Git index path")
        if (
            path in indexed
            or re.fullmatch(
                rf"{object_format}:[0-9a-f]{{{object_length}}}",
                str(entry.get("objectId") or ""),
            )
            is None
        ):
            raise VerificationError("Git index entry identity is invalid")
        indexed[path] = entry
    worktree: dict[str, dict[str, Any]] = {}
    for entry in worktree_entries:
        if not isinstance(entry, dict):
            raise VerificationError("Git worktree entry is invalid")
        path = _validate_inventory_path(
            entry.get("path"),
            label="Git worktree path",
        )
        indexed_entry = indexed.get(path)
        if (
            indexed_entry is None
            or path in worktree
            or entry.get("classification") not in SOURCE_CLASSIFICATIONS
            or entry.get("gitMode") != indexed_entry["gitMode"]
            or entry.get("indexObjectId") != indexed_entry["objectId"]
            or re.fullmatch(
                rf"{object_format}:[0-9a-f]{{{object_length}}}",
                str(entry.get("worktreeObjectId") or ""),
            )
            is None
        ):
            raise VerificationError("Git worktree provenance is invalid")
        if entry.get("type") == "file":
            if (
                set(entry)
                != {
                    "classification",
                    "gitMode",
                    "indexObjectId",
                    "mode",
                    "path",
                    "sha256",
                    "size",
                    "type",
                    "worktreeObjectId",
                }
                or entry.get("mode")
                != (0o500 if entry["gitMode"] == "100755" else 0o400)
                or entry.get("gitMode") == "120000"
                or type(entry.get("size")) is not int
                or entry["size"] < 0
            ):
                raise VerificationError("Git worktree file identity is invalid")
            _required_digest(entry.get("sha256"), label="Git worktree file")
        elif entry.get("type") == "symlink":
            if (
                set(entry)
                != {
                    "classification",
                    "gitMode",
                    "indexObjectId",
                    "mode",
                    "path",
                    "target",
                    "type",
                    "worktreeObjectId",
                }
                or entry.get("gitMode") != "120000"
                or entry.get("mode") != 0o777
                or not isinstance(entry.get("target"), str)
            ):
                raise VerificationError("Git worktree symlink identity is invalid")
            _validate_internal_symlink(
                link=PurePosixPath(path),
                target=entry["target"],
            )
        else:
            raise VerificationError("Git worktree entry type is unsupported")
        worktree[path] = entry
    if set(indexed) != set(worktree):
        raise VerificationError("Git worktree does not equal the complete stage-0 index")
    status = payload["status"]
    if (
        status != _parse_git_status_evidence(raw_status)
        or set(status["ignoredPaths"])
        & (set(status["untrackedPaths"]) | set(indexed))
        or set(status["untrackedPaths"]) & set(indexed)
    ):
        raise VerificationError("Git status evidence is invalid")
    if any(item["path"] not in indexed for item in status["trackedChanges"]):
        raise VerificationError("Git status names a non-indexed tracked path")
    expected_changed_paths = {
        path
        for path, entry in worktree.items()
        if (
            entry["worktreeObjectId"] != entry["indexObjectId"]
            or (
                entry["type"] == "file"
                and entry["mode"]
                != (
                    0o500
                    if entry["gitMode"] == "100755"
                    else 0o400
                )
            )
        )
    }
    observed_changes = {
        item["path"]: item["status"]
        for item in status["trackedChanges"]
    }
    if (
        set(observed_changes) != expected_changed_paths
        or any(value != " M" for value in observed_changes.values())
    ):
        raise VerificationError(
            "Git status and signed worktree changes differ"
        )
    return payload


def _source_evidence_identity(
    *,
    git_envelope: dict[str, Any],
    git_inventory: dict[str, Any],
    approval_envelope: dict[str, Any],
    untracked_approval: dict[str, Any],
) -> dict[str, Any]:
    git_signature = git_envelope["signature"]
    approval_signature = approval_envelope["signature"]
    try:
        git_signature_raw = base64.b64decode(
            git_signature["value"],
            validate=True,
        )
        approval_signature_raw = base64.b64decode(
            approval_signature["value"],
            validate=True,
        )
    except (ValueError, binascii.Error) as exc:
        raise VerificationError("source evidence signature encoding changed") from exc
    raw_evidence = git_inventory["rawEvidence"]
    payload = {
        "apiVersion": "catchplate.sourceEvidenceIdentity/v1",
        "gitInventory": {
            "envelopeSha256": _sha256(_canonical_json(git_envelope)),
            "headTree": git_inventory["headTree"],
            "indexEntriesSha256": git_inventory["indexEntriesSha256"],
            "indexRawSha256": raw_evidence["index"]["sha256"],
            "indexTree": git_inventory["indexTree"],
            "keyRawSha256": git_signature["rawKeySha256"],
            "keySpkiSha256": git_signature["keyFileSha256"],
            "payloadSha256": git_envelope["payloadSha256"],
            "signatureSha256": _sha256(git_signature_raw),
            "statusRawSha256": raw_evidence["status"]["sha256"],
            "treeEntriesSha256": git_inventory["treeEntriesSha256"],
            "treeRawSha256": raw_evidence["tree"]["sha256"],
            "worktreeEntriesSha256": git_inventory["worktreeEntriesSha256"],
        },
        "untrackedApproval": {
            "challengeSha256": untracked_approval["challengeSha256"],
            "envelopeSha256": _sha256(_canonical_json(approval_envelope)),
            "keyRawSha256": approval_signature["rawKeySha256"],
            "keySpkiSha256": approval_signature["keyFileSha256"],
            "pathListSha256": untracked_approval["pathListSha256"],
            "payloadSha256": approval_envelope["payloadSha256"],
            "signatureSha256": _sha256(approval_signature_raw),
        },
    }
    return {**payload, "identitySha256": _sha256(_canonical_json(payload))}


def _validate_source_input_document(
    document: Any,
    *,
    git_inventory: dict[str, Any],
    untracked_approval: dict[str, Any],
) -> dict[str, Any]:
    required_keys = {
        "aggregateBytes",
        "apiVersion",
        "entries",
        "entryCount",
        "fileCount",
        "gitInventory",
        "gitInventoryPayloadSha256",
        "pathListSha256",
        "payloadSha256",
        "requiredUntrackedInventorySha256",
        "requiredUntrackedPaths",
        "selectionModel",
        "sourceEvidence",
        "sourceEvidenceSha256",
        "symlinkCount",
        "trackedInventorySha256",
        "trackedPaths",
        "untrackedApproval",
        "untrackedApprovalPayloadSha256",
    }
    if (
        not isinstance(document, dict)
        or set(document) != required_keys
        or document.get("apiVersion") != SOURCE_INPUT_MANIFEST_VERSION
        or document.get("selectionModel") != SOURCE_SELECTION_MODEL
    ):
        raise VerificationError("source input manifest fields are invalid")
    payload = dict(document)
    supplied = payload.pop("payloadSha256")
    if supplied != _sha256(_canonical_json(payload)):
        raise VerificationError("source input manifest payload digest is invalid")
    if (
        document["gitInventory"].get("payload") != git_inventory
        or document["gitInventoryPayloadSha256"]
        != document["gitInventory"].get("payloadSha256")
        or document["untrackedApproval"].get("payload") != untracked_approval
        or document["untrackedApprovalPayloadSha256"]
        != document["untrackedApproval"].get("payloadSha256")
    ):
        raise VerificationError("source evidence envelope binding changed")
    tracked = document["trackedPaths"]
    untracked = document["requiredUntrackedPaths"]
    indexed_paths = [item["path"] for item in git_inventory["indexEntries"]]
    worktree_by_path = {
        item["path"]: item for item in git_inventory["worktreeEntries"]
    }
    status = git_inventory["status"]
    if (
        tracked != indexed_paths
        or any(path not in status["untrackedPaths"] for path in untracked)
        or set(untracked) & set(status["ignoredPaths"])
    ):
        raise VerificationError(
            "source selection differs from signed Git index/status evidence"
        )
    if (
        set(untracked_approval)
        != {
            "challengeSha256",
            "decision",
            "entries",
            "gitInventoryPayloadSha256",
            "pathListSha256",
        }
        or untracked_approval.get("decision")
        != "approve-exact-required-untracked-for-source-freeze"
        or untracked_approval.get("gitInventoryPayloadSha256")
        != document["gitInventoryPayloadSha256"]
        or not isinstance(untracked_approval.get("entries"), list)
    ):
        raise VerificationError("untracked source approval payload is invalid")
    _required_digest(
        untracked_approval.get("challengeSha256"),
        label="untracked approval challenge",
    )
    expected_source_evidence = _source_evidence_identity(
        git_envelope=document["gitInventory"],
        git_inventory=git_inventory,
        approval_envelope=document["untrackedApproval"],
        untracked_approval=untracked_approval,
    )
    if (
        document["sourceEvidence"] != expected_source_evidence
        or document["sourceEvidenceSha256"]
        != expected_source_evidence["identitySha256"]
    ):
        raise VerificationError("raw source evidence identity changed")
    if (
        not isinstance(tracked, list)
        or not isinstance(untracked, list)
        or not all(isinstance(value, str) for value in tracked)
        or not all(isinstance(value, str) for value in untracked)
        or not tracked
        or tracked != sorted(tracked)
        or untracked != sorted(untracked)
        or len(set(tracked)) != len(tracked)
        or len(set(untracked)) != len(untracked)
        or set(tracked) & set(untracked)
    ):
        raise VerificationError("source input path inventories are invalid")
    for value in [*tracked, *untracked]:
        _validate_source_path(_safe_relative(value, label="source input path"))
    if (
        document["trackedInventorySha256"]
        != _sha256(_canonical_json(tracked))
        or document["requiredUntrackedInventorySha256"]
        != _sha256(_canonical_json(untracked))
    ):
        raise VerificationError("source input provenance inventories changed")
    selected_paths = sorted([*tracked, *untracked])
    if document["pathListSha256"] != _sha256(
        _canonical_json(selected_paths)
    ):
        raise VerificationError("source input path-list digest is invalid")
    selected_path_set = set(selected_paths)
    required_exact = {
        PYTHON_ENTRYPOINT_SOURCE,
        NPM_ENTRYPOINT_SOURCE,
        "scripts/verify_agent_trust_same_journey.py",
    }
    required_prefixes: set[str] = set()
    for contract in LANE_SOURCE_CONTRACTS.values():
        required_exact.update(contract["exact"])
        required_prefixes.update(contract["prefixes"])
    if (
        required_exact - selected_path_set
        or any(
            not any(path.startswith(prefix) for path in selected_path_set)
            for prefix in required_prefixes
        )
    ):
        raise VerificationError(
            "source input manifest omits a fixed lane or build input"
        )
    entries = document["entries"]
    if (
        not isinstance(entries, list)
        or len(entries) > MAX_SOURCE_FILES
        or [item.get("path") for item in entries if isinstance(item, dict)]
        != selected_paths
    ):
        raise VerificationError("source input entries are not the exact path list")
    aggregate = 0
    file_count = 0
    symlink_count = 0
    untracked_entries: list[dict[str, Any]] = []
    for entry in entries:
        if not isinstance(entry, dict):
            raise VerificationError("source input entry is not an object")
        path = _safe_relative(entry.get("path"), label="source input entry")
        _validate_source_path(path)
        provenance = (
            "tracked"
            if entry["path"] in set(tracked)
            else "required-untracked"
        )
        if (
            entry.get("provenance") != provenance
            or entry.get("classification") not in SOURCE_CLASSIFICATIONS
        ):
            raise VerificationError(
                "source input provenance or classification is invalid"
            )
        if entry.get("type") == "file":
            if (
                set(entry)
                != {
                    "classification",
                    "mode",
                    "path",
                    "provenance",
                    "sha256",
                    "size",
                    "type",
                }
                or entry.get("mode") not in {0o400, 0o500}
                or isinstance(entry.get("size"), bool)
                or not isinstance(entry.get("size"), int)
                or entry["size"] < 0
                or entry["size"] > MAX_SOURCE_BYTES
            ):
                raise VerificationError("source input file identity is invalid")
            _required_digest(entry.get("sha256"), label="source input file")
            aggregate += entry["size"]
            file_count += 1
        elif entry.get("type") == "symlink":
            if (
                set(entry)
                != {
                    "classification",
                    "mode",
                    "path",
                    "provenance",
                    "target",
                    "type",
                }
                or entry.get("mode") != 0o777
                or not isinstance(entry.get("target"), str)
            ):
                raise VerificationError("source input symlink identity is invalid")
            _validate_internal_symlink(link=path, target=entry.get("target"))
            symlink_count += 1
        else:
            raise VerificationError("source input type is invalid")
        if provenance == "tracked":
            signed = worktree_by_path[entry["path"]]
            expected = {
                key: value
                for key, value in signed.items()
                if key
                not in {"gitMode", "indexObjectId", "worktreeObjectId"}
            }
            expected["provenance"] = "tracked"
            if entry != expected:
                raise VerificationError(
                    "tracked source identity differs from signed Git worktree"
                )
        else:
            untracked_entries.append(entry)
    if (
        untracked_approval["entries"] != untracked_entries
        or [item["path"] for item in untracked_entries] != untracked
        or untracked_approval["pathListSha256"]
        != _sha256(_canonical_json(untracked))
    ):
        raise VerificationError(
            "required untracked source differs from its signed approval"
        )
    if (
        aggregate > MAX_SOURCE_BYTES
        or document["aggregateBytes"] != aggregate
        or document["entryCount"] != len(entries)
        or document["fileCount"] != file_count
        or document["symlinkCount"] != symlink_count
    ):
        raise VerificationError("source input aggregate counts are invalid")
    return document


def _load_source_input_manifest(
    path: Path,
    *,
    expected_file_sha256: str,
    git_inventory_public_key: Path,
    expected_git_inventory_key_spki_sha256: str,
    expected_git_inventory_key_raw_sha256: str,
    untracked_approval_public_key: Path,
    expected_untracked_approval_key_spki_sha256: str,
    expected_untracked_approval_key_raw_sha256: str,
) -> tuple[dict[str, Any], str]:
    raw, _ = _read_regular(path, label="external source input manifest")
    expected = _required_digest(
        expected_file_sha256,
        label="expected source input manifest file",
    )
    file_sha256 = _sha256(raw)
    if file_sha256 != expected:
        raise VerificationError("source input manifest file digest changed")
    document = _load_canonical_json_blob(
        raw,
        label="external source input manifest",
    )
    if not isinstance(document, dict):
        raise VerificationError("external source input manifest is not an object")
    git_key = _load_pinned_ed25519_key(
        git_inventory_public_key,
        expected_spki_sha256=expected_git_inventory_key_spki_sha256,
        expected_raw_sha256=expected_git_inventory_key_raw_sha256,
        label="Git source inventory authority",
    )
    approval_key = _load_pinned_ed25519_key(
        untracked_approval_public_key,
        expected_spki_sha256=expected_untracked_approval_key_spki_sha256,
        expected_raw_sha256=expected_untracked_approval_key_raw_sha256,
        label="untracked source approval authority",
    )
    if expected_git_inventory_key_raw_sha256 == expected_untracked_approval_key_raw_sha256:
        raise VerificationError(
            "Git inventory and untracked approval keys must be independent"
        )
    git_inventory = _validate_git_inventory_payload(
        _verify_source_evidence_envelope(
            document.get("gitInventory"),
            api_version=GIT_SOURCE_INVENTORY_VERSION,
            domain=GIT_SOURCE_INVENTORY_SIGNATURE_DOMAIN,
            public_key=git_key,
            expected_spki_sha256=expected_git_inventory_key_spki_sha256,
            expected_raw_sha256=expected_git_inventory_key_raw_sha256,
            label="Git source inventory",
        )
    )
    approval = _verify_source_evidence_envelope(
        document.get("untrackedApproval"),
        api_version=UNTRACKED_APPROVAL_VERSION,
        domain=UNTRACKED_APPROVAL_SIGNATURE_DOMAIN,
        public_key=approval_key,
        expected_spki_sha256=expected_untracked_approval_key_spki_sha256,
        expected_raw_sha256=expected_untracked_approval_key_raw_sha256,
        label="untracked source approval",
    )
    return (
        _validate_source_input_document(
            document,
            git_inventory=git_inventory,
            untracked_approval=approval,
        ),
        file_sha256,
    )


def _read_symlink_at(
    root_fd: int,
    relative: PurePosixPath,
    *,
    label: str,
) -> tuple[str, os.stat_result]:
    parent = os.dup(root_fd)
    try:
        for component in relative.parts[:-1]:
            child = os.open(
                component,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_CLOEXEC", 0)
                | os.O_NOFOLLOW,
                dir_fd=parent,
            )
            metadata = os.fstat(child)
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid not in {0, os.getuid()}
                or stat.S_IMODE(metadata.st_mode) & 0o022
            ):
                os.close(child)
                raise VerificationError(f"{label} has an unsafe ancestor")
            os.close(parent)
            parent = child
        before = os.stat(
            relative.parts[-1],
            dir_fd=parent,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISLNK(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid not in {0, os.getuid()}
        ):
            raise VerificationError(f"{label} is not a safe symlink")
        target = os.readlink(relative.parts[-1], dir_fd=parent)
        after = os.stat(
            relative.parts[-1],
            dir_fd=parent,
            follow_symlinks=False,
        )
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
            raise VerificationError(f"{label} changed while read")
        return target, after
    finally:
        os.close(parent)


def _measure_selected_source(
    root: Path,
    selection: dict[str, Any],
) -> tuple[list[dict[str, Any]], int, dict[str, int]]:
    root_fd, root_before = _open_safe_root(root, label="selected source root")
    content_records: list[dict[str, Any]] = []
    directory_paths: set[PurePosixPath] = set()
    git_inventory = selection["gitInventory"]["payload"]
    object_format = git_inventory["objectFormat"]
    tracked_worktree = {
        item["path"]: item for item in git_inventory["worktreeEntries"]
    }
    current_root_fd = -1
    try:
        for selected in selection["entries"]:
            relative = _safe_relative(
                selected["path"],
                label="selected source path",
            )
            for length in range(1, len(relative.parts)):
                directory_paths.add(PurePosixPath(*relative.parts[:length]))
            if selected["type"] == "file":
                raw, metadata = _read_regular_at(
                    root_fd,
                    relative,
                    label="selected source file",
                    max_bytes=MAX_SOURCE_BYTES,
                )
                measured = {
                    "mode": (
                        0o500
                        if stat.S_IMODE(metadata.st_mode) & 0o111
                        else 0o400
                    ),
                    "path": relative.as_posix(),
                    "sha256": _sha256(raw),
                    "size": len(raw),
                    "type": "file",
                }
                git_object_raw = raw
            else:
                target, _ = _read_symlink_at(
                    root_fd,
                    relative,
                    label="selected source symlink",
                )
                _validate_internal_symlink(link=relative, target=target)
                measured = {
                    "mode": 0o777,
                    "path": relative.as_posix(),
                    "target": target,
                    "type": "symlink",
                }
                git_object_raw = target.encode("utf-8")
            signed_worktree = tracked_worktree.get(relative.as_posix())
            if (
                selected["provenance"] == "tracked"
                and (
                    signed_worktree is None
                    or signed_worktree["worktreeObjectId"]
                    != _git_object_id(
                        object_format,
                        "blob",
                        git_object_raw,
                    )
                )
            ):
                raise VerificationError(
                    f"tracked Git object identity changed: {relative.as_posix()}"
                )
            expected = {
                key: value
                for key, value in selected.items()
                if key not in {"classification", "provenance", "purpose"}
            }
            if measured != expected:
                raise VerificationError(
                    f"selected source identity changed: {relative.as_posix()}"
                )
            content_records.append(measured)
    finally:
        root_after = os.fstat(root_fd)
        try:
            current_root_fd, current_root = _open_safe_root(
                root,
                label="selected source root path continuity",
            )
        finally:
            os.close(root_fd)
            if current_root_fd >= 0:
                os.close(current_root_fd)
    root_identity = {
        "device": root_before.st_dev,
        "gid": root_before.st_gid,
        "inode": root_before.st_ino,
        "mode": stat.S_IMODE(root_before.st_mode),
        "uid": root_before.st_uid,
    }
    if root_identity != {
        "device": root_after.st_dev,
        "gid": root_after.st_gid,
        "inode": root_after.st_ino,
        "mode": stat.S_IMODE(root_after.st_mode),
        "uid": root_after.st_uid,
    } or root_identity != {
        "device": current_root.st_dev,
        "gid": current_root.st_gid,
        "inode": current_root.st_ino,
        "mode": stat.S_IMODE(current_root.st_mode),
        "uid": current_root.st_uid,
    }:
        raise VerificationError(
            "selected source root or live pathname changed during measurement"
        )
    available = {
        PurePosixPath(item["path"]) for item in content_records
    } | directory_paths
    links = {
        PurePosixPath(item["path"]): item["target"]
        for item in content_records
        if item["type"] == "symlink"
    }
    for link in links:
        current = link
        seen: set[PurePosixPath] = set()
        for _ in range(40):
            if current in seen:
                raise VerificationError("source symlink chain contains a loop")
            seen.add(current)
            target = _validate_internal_symlink(
                link=current,
                target=links[current],
            )
            if target not in available:
                raise VerificationError(
                    "source symlink target is outside the selected closure"
                )
            if target not in links:
                break
            current = target
        else:
            raise VerificationError("source symlink chain exceeds its depth bound")
    records = [
        {
            "mode": 0o500,
            "path": path.as_posix(),
            "type": "directory",
        }
        for path in directory_paths
    ] + content_records
    records.sort(
        key=lambda item: (
            len(PurePosixPath(item["path"]).parts),
            item["path"],
            item["type"],
        )
    )
    if len(records) > MAX_SOURCE_FILES:
        raise VerificationError("selected source closure exceeds its file bound")
    return records, selection["aggregateBytes"], root_identity


def _scan_frozen_snapshot(root: Path) -> tuple[list[dict[str, Any]], int]:
    records: list[dict[str, Any]] = []
    total = 0

    def walk(directory: Path, relative: PurePosixPath) -> None:
        nonlocal total
        entries = sorted(os.scandir(directory), key=lambda item: item.name)
        for entry in entries:
            if len(records) >= MAX_SOURCE_FILES:
                raise VerificationError("frozen source closure exceeds its file bound")
            if (
                entry.name in {"", ".", ".."}
                or "/" in entry.name
                or "\x00" in entry.name
                or entry.name != unicodedata.normalize("NFC", entry.name)
            ):
                raise VerificationError("source contains an unsafe name")
            child_relative = relative / entry.name
            metadata = entry.stat(follow_symlinks=False)
            if stat.S_ISDIR(metadata.st_mode):
                if (
                    stat.S_IMODE(metadata.st_mode) != 0o500
                    or metadata.st_uid not in {0, os.getuid()}
                ):
                    raise VerificationError(
                        "frozen source directory metadata is not canonical"
                    )
                records.append(
                    {
                        "mode": 0o500,
                        "path": child_relative.as_posix(),
                        "type": "directory",
                    }
                )
                walk(Path(entry.path), child_relative)
                continue
            if stat.S_ISLNK(metadata.st_mode):
                target = os.readlink(entry.path)
                _validate_internal_symlink(
                    link=child_relative,
                    target=target,
                )
                records.append(
                    {
                        "mode": 0o777,
                        "path": child_relative.as_posix(),
                        "target": target,
                        "type": "symlink",
                    }
                )
                continue
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise VerificationError("source contains a special or hard-linked file")
            raw, stable = _read_regular(
                Path(entry.path),
                label="source file",
                max_bytes=MAX_SOURCE_BYTES,
            )
            if stat.S_IMODE(stable.st_mode) not in {0o400, 0o500}:
                raise VerificationError(
                    "frozen source file metadata is not canonical"
                )
            total += len(raw)
            if total > MAX_SOURCE_BYTES or len(records) >= MAX_SOURCE_FILES:
                raise VerificationError("source closure exceeds its bound")
            records.append(
                {
                    "mode": (
                        0o500
                        if stat.S_IMODE(stable.st_mode) & 0o111
                        else 0o400
                    ),
                    "path": child_relative.as_posix(),
                    "sha256": _sha256(raw),
                    "size": len(raw),
                    "type": "file",
                }
            )

    walk(root, PurePosixPath())
    records.sort(
        key=lambda item: (
            len(PurePosixPath(item["path"]).parts),
            item["path"],
            item["type"],
        )
    )
    return records, total


def _source_closure_payload(
    records: list[dict[str, Any]],
    total: int,
) -> dict[str, Any]:
    return {
        "aggregateBytes": total,
        "entries": records,
        "entryCount": len(records),
        "fileCount": sum(item["type"] == "file" for item in records),
        "symlinkCount": sum(item["type"] == "symlink" for item in records),
    }


def _validate_directory_identity(value: Any, *, label: str) -> dict[str, int]:
    if (
        not isinstance(value, dict)
        or set(value) != {"device", "gid", "inode", "mode", "uid"}
        or any(type(value[key]) is not int for key in value)
        or value["device"] < 0
        or value["inode"] <= 0
        or value["uid"] not in {0, os.getuid()}
        or value["gid"] < 0
        or value["mode"] & ~0o7777
        or value["mode"] & 0o022
    ):
        raise VerificationError(f"{label} is invalid")
    return value


def _source_manifest(
    *,
    source_root: Path,
    snapshot_root: Path,
    records: list[dict[str, Any]],
    total: int,
    selection: dict[str, Any],
    selection_file_sha256: str,
    source_root_identity: dict[str, int],
    snapshot_root_identity: dict[str, int],
) -> dict[str, Any]:
    closure_payload = _source_closure_payload(records, total)
    closure_sha256 = _sha256(_canonical_json(closure_payload))
    source_root_binding = {
        "root": str(source_root),
        "rootIdentity": source_root_identity,
        "sourceClosureSha256": closure_sha256,
    }
    snapshot_root_binding = {
        "root": str(snapshot_root),
        "rootIdentity": snapshot_root_identity,
        "sourceClosureSha256": closure_sha256,
    }
    return {
        "apiVersion": SOURCE_SNAPSHOT_VERSION,
        **closure_payload,
        "closureSha256": closure_sha256,
        "root": str(snapshot_root),
        "rootIdentity": snapshot_root_identity,
        "rootBindingSha256": _sha256(
            _canonical_json(snapshot_root_binding)
        ),
        "selection": selection,
        "selectionManifestFileSha256": selection_file_sha256,
        "selectionManifestPayloadSha256": selection["payloadSha256"],
        "sourceRoot": str(source_root),
        "sourceRootIdentity": source_root_identity,
        "sourceRootBindingSha256": _sha256(
            _canonical_json(source_root_binding)
        ),
    }


def _remeasure_live_selected_source(source_manifest: dict[str, Any]) -> None:
    records, total, root_identity = _measure_selected_source(
        Path(source_manifest["sourceRoot"]),
        source_manifest["selection"],
    )
    if (
        records != source_manifest["entries"]
        or total != source_manifest["aggregateBytes"]
        or root_identity != source_manifest["sourceRootIdentity"]
    ):
        raise VerificationError(
            "live selected source changed at a post-freeze boundary"
        )


def _copy_source(
    source: Path,
    destination: Path,
    records: list[dict[str, Any]],
) -> None:
    parent, name = _open_output_parent(
        destination,
        create=True,
        label="source snapshot destination",
    )
    try:
        os.mkdir(name, 0o700, dir_fd=parent)
        os.fsync(parent)
        destination_fd = os.open(
            name,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | os.O_NOFOLLOW,
            dir_fd=parent,
        )
    finally:
        os.close(parent)

    def open_relative_parent(relative: PurePosixPath) -> tuple[int, str]:
        current = os.dup(destination_fd)
        try:
            for component in relative.parts[:-1]:
                child = os.open(
                    component,
                    os.O_RDONLY
                    | getattr(os, "O_DIRECTORY", 0)
                    | getattr(os, "O_CLOEXEC", 0)
                    | os.O_NOFOLLOW,
                    dir_fd=current,
                )
                metadata = os.fstat(child)
                if (
                    not stat.S_ISDIR(metadata.st_mode)
                    or metadata.st_uid not in {0, os.getuid()}
                    or stat.S_IMODE(metadata.st_mode) & 0o022
                ):
                    os.close(child)
                    raise VerificationError(
                        "source snapshot destination ancestor is unsafe"
                    )
                os.close(current)
                current = child
            return current, relative.parts[-1]
        except BaseException:
            os.close(current)
            raise

    try:
        for record in records:
            relative = _safe_relative(record["path"], label="source record")
            source_path = source.joinpath(*relative.parts)
            record_parent, record_name = open_relative_parent(relative)
            try:
                if record["type"] == "directory":
                    os.mkdir(record_name, 0o700, dir_fd=record_parent)
                    os.fsync(record_parent)
                elif record["type"] == "symlink":
                    os.symlink(
                        record["target"],
                        record_name,
                        dir_fd=record_parent,
                    )
                    os.fsync(record_parent)
                else:
                    raw, _ = _read_regular(
                        source_path,
                        label="source snapshot input",
                        max_bytes=MAX_SOURCE_BYTES,
                    )
                    descriptor = os.open(
                        record_name,
                        os.O_WRONLY
                        | os.O_CREAT
                        | os.O_EXCL
                        | getattr(os, "O_CLOEXEC", 0)
                        | os.O_NOFOLLOW,
                        record["mode"],
                        dir_fd=record_parent,
                    )
                    try:
                        view = memoryview(raw)
                        while view:
                            written = os.write(descriptor, view)
                            view = view[written:]
                        os.fsync(descriptor)
                    except BaseException:
                        os.close(descriptor)
                        os.unlink(record_name, dir_fd=record_parent)
                        raise
                    os.close(descriptor)
                    os.fsync(record_parent)
            finally:
                os.close(record_parent)
        for record in reversed(records):
            if record["type"] != "directory":
                continue
            relative = _safe_relative(
                record["path"],
                label="source directory",
            )
            record_parent, record_name = open_relative_parent(relative)
            try:
                descriptor = os.open(
                    record_name,
                    os.O_RDONLY
                    | getattr(os, "O_DIRECTORY", 0)
                    | getattr(os, "O_CLOEXEC", 0)
                    | os.O_NOFOLLOW,
                    dir_fd=record_parent,
                )
                try:
                    os.fchmod(descriptor, 0o500)
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
                os.fsync(record_parent)
            finally:
                os.close(record_parent)
        os.fchmod(destination_fd, 0o500)
        os.fsync(destination_fd)
    finally:
        os.close(destination_fd)


def _snapshot_source(args: argparse.Namespace) -> dict[str, Any]:
    source = _absolute(args.source_root, label="source root")
    snapshot = _absolute(args.snapshot_root, label="snapshot root")
    source_input_manifest = _absolute(
        args.source_input_manifest,
        label="external source input manifest",
    )
    output_root = source / ".tmp"
    _under(snapshot, output_root, label="snapshot root")
    for external_path, label in (
        (source_input_manifest, "source input manifest"),
        (
            _absolute(
                args.source_git_inventory_public_key,
                label="Git source inventory public key",
            ),
            "Git source inventory public key",
        ),
        (
            _absolute(
                args.source_untracked_approval_public_key,
                label="untracked approval public key",
            ),
            "untracked approval public key",
        ),
    ):
        try:
            external_path.relative_to(source)
        except ValueError:
            continue
        raise VerificationError(f"{label} must be installed outside the checkout")
    if (
        _path_type_nofollow(snapshot, label="source snapshot output") is not None
        or _path_type_nofollow(
            args.manifest,
            label="source snapshot manifest output",
        )
        is not None
    ):
        raise VerificationError("source snapshot outputs already exist")
    selection, selection_file_sha256 = _load_source_input_manifest(
        source_input_manifest,
        expected_file_sha256=args.expected_source_input_manifest_sha256,
        git_inventory_public_key=args.source_git_inventory_public_key,
        expected_git_inventory_key_spki_sha256=(
            args.expected_source_git_inventory_key_spki_sha256
        ),
        expected_git_inventory_key_raw_sha256=(
            args.expected_source_git_inventory_key_raw_sha256
        ),
        untracked_approval_public_key=(
            args.source_untracked_approval_public_key
        ),
        expected_untracked_approval_key_spki_sha256=(
            args.expected_source_untracked_approval_key_spki_sha256
        ),
        expected_untracked_approval_key_raw_sha256=(
            args.expected_source_untracked_approval_key_raw_sha256
        ),
    )
    records, total, source_root_identity = _measure_selected_source(
        source,
        selection,
    )
    _copy_source(source, snapshot, records)
    (
        measured_snapshot_records,
        measured_snapshot_total,
        snapshot_root_identity,
    ) = _measure_selected_source(snapshot, selection)
    snapshot_records, snapshot_total = _scan_frozen_snapshot(snapshot)
    if (
        measured_snapshot_records != records
        or measured_snapshot_total != total
        or snapshot_records != records
        or snapshot_total != total
    ):
        raise VerificationError("source snapshot differs after copying")
    manifest = _source_manifest(
        source_root=source,
        snapshot_root=snapshot,
        records=records,
        total=total,
        selection=selection,
        selection_file_sha256=selection_file_sha256,
        source_root_identity=source_root_identity,
        snapshot_root_identity=snapshot_root_identity,
    )
    _remeasure_live_selected_source(manifest)
    boundary_records, boundary_total, boundary_root_identity = (
        _measure_selected_source(snapshot, selection)
    )
    boundary_scanned_records, boundary_scanned_total = (
        _scan_frozen_snapshot(snapshot)
    )
    if (
        boundary_records != manifest["entries"]
        or boundary_scanned_records != boundary_records
        or boundary_total != manifest["aggregateBytes"]
        or boundary_scanned_total != boundary_total
        or boundary_root_identity != manifest["rootIdentity"]
    ):
        raise VerificationError(
            "source snapshot changed at its publication boundary"
        )
    _publish(
        args.manifest,
        _canonical_json(manifest) + b"\n",
        output_root=output_root,
    )
    return manifest


def _load_source_manifest(
    path: Path,
    *,
    root: Path,
    source_input_manifest: Path,
    expected_source_input_manifest_sha256: str,
    source_git_inventory_public_key: Path,
    expected_source_git_inventory_key_spki_sha256: str,
    expected_source_git_inventory_key_raw_sha256: str,
    source_untracked_approval_public_key: Path,
    expected_source_untracked_approval_key_spki_sha256: str,
    expected_source_untracked_approval_key_raw_sha256: str,
) -> dict[str, Any]:
    root = _absolute(root, label="source snapshot root")
    source_input_manifest = _absolute(
        source_input_manifest,
        label="external source input manifest",
    )
    for external_path, label in (
        (source_input_manifest, "source input manifest"),
        (
            _absolute(
                source_git_inventory_public_key,
                label="Git source inventory public key",
            ),
            "Git source inventory public key",
        ),
        (
            _absolute(
                source_untracked_approval_public_key,
                label="untracked approval public key",
            ),
            "untracked approval public key",
        ),
    ):
        try:
            external_path.relative_to(root)
        except ValueError:
            continue
        raise VerificationError(f"{label} must remain outside the frozen snapshot")
    raw, _ = _read_regular(path, label="source snapshot manifest")
    document = _load_json(raw, label="source snapshot manifest")
    if (
        not isinstance(document, dict)
        or raw != _canonical_json(document) + b"\n"
        or set(document)
        != {
            "aggregateBytes",
            "apiVersion",
            "closureSha256",
            "entries",
            "entryCount",
            "fileCount",
            "root",
            "rootBindingSha256",
            "rootIdentity",
            "selection",
            "selectionManifestFileSha256",
            "selectionManifestPayloadSha256",
            "sourceRoot",
            "sourceRootBindingSha256",
            "sourceRootIdentity",
            "symlinkCount",
        }
        or document.get("apiVersion") != SOURCE_SNAPSHOT_VERSION
        or document.get("root") != str(root)
        or not isinstance(document.get("sourceRoot"), str)
    ):
        raise VerificationError("source snapshot manifest fields are invalid")
    selection = document["selection"]
    _validate_directory_identity(
        document["rootIdentity"],
        label="snapshot root identity",
    )
    _validate_directory_identity(
        document["sourceRootIdentity"],
        label="live source root identity",
    )
    external_selection, external_file_sha256 = _load_source_input_manifest(
        source_input_manifest,
        expected_file_sha256=expected_source_input_manifest_sha256,
        git_inventory_public_key=source_git_inventory_public_key,
        expected_git_inventory_key_spki_sha256=(
            expected_source_git_inventory_key_spki_sha256
        ),
        expected_git_inventory_key_raw_sha256=(
            expected_source_git_inventory_key_raw_sha256
        ),
        untracked_approval_public_key=source_untracked_approval_public_key,
        expected_untracked_approval_key_spki_sha256=(
            expected_source_untracked_approval_key_spki_sha256
        ),
        expected_untracked_approval_key_raw_sha256=(
            expected_source_untracked_approval_key_raw_sha256
        ),
    )
    _required_digest(
        document["selectionManifestFileSha256"],
        label="source selection manifest file",
    )
    if (
        external_selection != selection
        or external_file_sha256 != document["selectionManifestFileSha256"]
        or document["selectionManifestPayloadSha256"]
        != selection["payloadSha256"]
    ):
        raise VerificationError("source selection manifest binding changed")
    records, total, root_identity = _measure_selected_source(root, selection)
    scanned_records, scanned_total = _scan_frozen_snapshot(root)
    if (
        records != document["entries"]
        or scanned_records != records
        or total != document["aggregateBytes"]
        or scanned_total != total
        or root_identity != document["rootIdentity"]
    ):
        raise VerificationError("source snapshot closure changed")
    closure_payload = _source_closure_payload(records, total)
    if (
        document["entryCount"] != closure_payload["entryCount"]
        or document["fileCount"] != closure_payload["fileCount"]
        or document["symlinkCount"] != closure_payload["symlinkCount"]
        or document["closureSha256"]
        != _sha256(_canonical_json(closure_payload))
    ):
        raise VerificationError("source snapshot digest is invalid")
    if (
        document["rootBindingSha256"]
        != _sha256(
            _canonical_json(
                {
                    "root": str(root),
                    "rootIdentity": document["rootIdentity"],
                    "sourceClosureSha256": document["closureSha256"],
                }
            )
        )
        or _absolute(Path(document["sourceRoot"]), label="source root binding")
        != Path(document["sourceRoot"])
        or str(Path(document["sourceRoot"])) != document["sourceRoot"]
        or not isinstance(document["sourceRootIdentity"], dict)
        or document["sourceRootBindingSha256"]
        != _sha256(
            _canonical_json(
                {
                    "root": document["sourceRoot"],
                    "rootIdentity": document["sourceRootIdentity"],
                    "sourceClosureSha256": document["closureSha256"],
                }
            )
        )
    ):
        raise VerificationError("source root binding is invalid")
    live_records, live_total, live_root_identity = _measure_selected_source(
        Path(document["sourceRoot"]),
        selection,
    )
    if (
        live_records != records
        or live_total != total
        or live_root_identity != document["sourceRootIdentity"]
    ):
        raise VerificationError(
            "live selected source changed after the frozen snapshot"
        )
    return document


def _verify_source(args: argparse.Namespace) -> dict[str, Any]:
    return _load_source_manifest(
        args.manifest,
        root=args.snapshot_root,
        source_input_manifest=args.source_input_manifest,
        expected_source_input_manifest_sha256=(
            args.expected_source_input_manifest_sha256
        ),
        source_git_inventory_public_key=args.source_git_inventory_public_key,
        expected_source_git_inventory_key_spki_sha256=(
            args.expected_source_git_inventory_key_spki_sha256
        ),
        expected_source_git_inventory_key_raw_sha256=(
            args.expected_source_git_inventory_key_raw_sha256
        ),
        source_untracked_approval_public_key=(
            args.source_untracked_approval_public_key
        ),
        expected_source_untracked_approval_key_spki_sha256=(
            args.expected_source_untracked_approval_key_spki_sha256
        ),
        expected_source_untracked_approval_key_raw_sha256=(
            args.expected_source_untracked_approval_key_raw_sha256
        ),
    )


def _load_digest_document(
    path: Path,
    *,
    label: str,
    api_version: str,
    digest_field: str,
) -> dict[str, Any]:
    raw, _ = _read_regular(path, label=label)
    document = _load_json(raw, label=label)
    if not isinstance(document, dict) or document.get("apiVersion") != api_version:
        raise VerificationError(f"{label} version is invalid")
    payload = dict(document)
    supplied = payload.pop(digest_field, None)
    if supplied != _sha256(_canonical_json(payload)):
        raise VerificationError(f"{label} digest is invalid")
    return document


def _validate_clean_room_semantic_contract(value: Any) -> dict[str, Any]:
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
        != "catchplate.cleanRoomExpectedDerivation/v1"
    ):
        raise VerificationError("clean-room semantic contract is invalid")
    payload = dict(value)
    supplied = payload.pop("contractSha256", None)
    if supplied != _sha256(_canonical_json(payload)):
        raise VerificationError("clean-room semantic contract digest is invalid")
    for key in (
        "derivedInstallationSha256",
        "installContractSha256",
        "payloadClosureSha256",
        "requirementsResolutionSha256",
        "wheelRecordsSha256",
        "wheelhouseManifestPayloadSha256",
    ):
        _required_digest(value.get(key), label=f"clean-room {key}")
    entries = value["derivedEntries"]
    if (
        not isinstance(entries, list)
        or not entries
        or entries
        != sorted(
            entries,
            key=lambda item: str(
                item.get("path") if isinstance(item, dict) else ""
            ),
        )
        or value["derivedInstallationSha256"]
        != _sha256(_canonical_json(entries))
    ):
        raise VerificationError("clean-room derived installation is invalid")
    seen: set[str] = set()
    for entry in entries:
        path = (
            _validate_inventory_path(
                entry.get("path"),
                label="clean-room installed path",
            )
            if isinstance(entry, dict)
            else ""
        )
        if (
            not isinstance(entry, dict)
            or path in seen
            or type(entry.get("uid")) is not int
            or type(entry.get("gid")) is not int
            or type(entry.get("mode")) is not int
            or entry["uid"] < 0
            or entry["gid"] < 0
            or entry["mode"] & ~0o7777
        ):
            raise VerificationError("clean-room derived entry is invalid")
        if entry.get("type") == "directory":
            if set(entry) != {"gid", "mode", "path", "type", "uid"}:
                raise VerificationError(
                    "clean-room derived directory is invalid"
                )
        elif entry.get("type") == "file":
            if (
                set(entry)
                != {
                    "gid",
                    "mode",
                    "path",
                    "sha256",
                    "size",
                    "type",
                    "uid",
                }
                or type(entry.get("size")) is not int
                or entry["size"] < 0
            ):
                raise VerificationError("clean-room derived file is invalid")
            _required_digest(
                entry.get("sha256"),
                label="clean-room derived file",
            )
        else:
            raise VerificationError("clean-room derived entry type is invalid")
        seen.add(path)
    wheel_records = value["wheelRecords"]
    requirements = value["requirementsResolution"]
    if (
        not isinstance(wheel_records, list)
        or not wheel_records
        or not isinstance(requirements, list)
        or value["wheelRecordsSha256"]
        != _sha256(_canonical_json(wheel_records))
        or value["requirementsResolutionSha256"]
        != _sha256(_canonical_json(requirements))
    ):
        raise VerificationError("clean-room wheel derivation is invalid")
    scenarios = value["exerciseScenarios"]
    expected_scenarios = [
        (
            "attestation-verify-offline",
            "/opt/catchplate/clean-room/installed/bin/catchplate-attestation",
            1,
        ),
        (
            "enrollment-install-offline",
            "/opt/catchplate/clean-room/installed/bin/catchplate-enrollment",
            1,
        ),
        (
            "evidence-verify-offline",
            "/opt/catchplate/clean-room/installed/bin/catchplate-evidence",
            0,
        ),
    ]
    if (
        not isinstance(scenarios, list)
        or len(scenarios) != len(expected_scenarios)
    ):
        raise VerificationError("clean-room exercise scenarios are invalid")
    for scenario, expected in zip(scenarios, expected_scenarios, strict=True):
        if (
            not isinstance(scenario, dict)
            or set(scenario)
            != {
                "argv",
                "expectedExitCode",
                "expectedState",
                "scenario",
                "stderrSha256",
                "stdoutSha256",
            }
            or scenario.get("scenario") != expected[0]
            or not isinstance(scenario.get("argv"), list)
            or not scenario["argv"]
            or scenario["argv"][0] != expected[1]
            or scenario.get("expectedExitCode") != expected[2]
            or not isinstance(scenario.get("expectedState"), list)
        ):
            raise VerificationError("clean-room exercise scenario is invalid")
        _required_digest(
            scenario.get("stdoutSha256"),
            label="clean-room expected stdout",
        )
        _required_digest(
            scenario.get("stderrSha256"),
            label="clean-room expected stderr",
        )
    return value


def _dependency_capability_attestation_payload(
    bundles: dict[str, Any],
) -> dict[str, Any]:
    bindings = {}
    for role in sorted(bundles):
        bundle = bundles[role]
        semantic = bundle["semanticContract"]
        bindings[role] = {
            "capabilityCatalogSha256": bundle[
                "capabilityCatalogSha256"
            ],
            "closureSha256": bundle["closureSha256"],
            "fileManifestSha256": bundle["fileManifestSha256"],
            "packageInventorySha256": _sha256(
                _canonical_json(bundle["packages"])
            ),
            "semanticContractSha256": (
                semantic["contractSha256"]
                if semantic is not None
                else None
            ),
        }
    return {
        "apiVersion": CAPABILITY_ATTESTATION_VERSION,
        "bindings": bindings,
        "bundleApiVersion": OCI_DEPENDENCY_BUNDLE_VERSION,
        "bundlesSha256": _sha256(_canonical_json(bundles)),
        "roles": sorted(bundles),
    }


def _load_dependencies(
    path: Path,
    *,
    capability_authority_public_key: Path,
    expected_capability_authority_key_spki_sha256: str,
    expected_capability_authority_key_raw_sha256: str,
) -> dict[str, Any]:
    document = _load_digest_document(
        path,
        label="OCI dependency bundle",
        api_version=OCI_DEPENDENCY_BUNDLE_VERSION,
        digest_field="manifestSha256",
    )
    if set(document) != {
        "apiVersion",
        "bundles",
        "capabilityAttestation",
        "manifestSha256",
    }:
        raise VerificationError("dependency bundle fields are invalid")
    capability_key = _load_pinned_ed25519_key(
        capability_authority_public_key,
        expected_spki_sha256=(
            expected_capability_authority_key_spki_sha256
        ),
        expected_raw_sha256=(
            expected_capability_authority_key_raw_sha256
        ),
        label="dependency capability authority",
    )
    attested_capabilities = _verify_source_evidence_envelope(
        document["capabilityAttestation"],
        api_version=CAPABILITY_ATTESTATION_VERSION,
        domain=CAPABILITY_ATTESTATION_SIGNATURE_DOMAIN,
        public_key=capability_key,
        expected_spki_sha256=(
            expected_capability_authority_key_spki_sha256
        ),
        expected_raw_sha256=(
            expected_capability_authority_key_raw_sha256
        ),
        label="dependency capability attestation",
    )
    bundles = document["bundles"]
    if not isinstance(bundles, dict) or set(bundles) != DEPENDENCY_ROLES:
        raise VerificationError("dependency bundle role inventory is not exact")
    for role, bundle in bundles.items():
        if (
            not isinstance(bundle, dict)
            or set(bundle)
            != {
                "baseImageDigest",
                "capabilities",
                "capabilityCatalog",
                "capabilityCatalogSha256",
                "closureSha256",
                "fileManifestSha256",
                "files",
                "packages",
                "semanticContract",
            }
            or bundle.get("capabilities") != DEPENDENCY_CAPABILITIES[role]
            or not isinstance(bundle.get("files"), list)
            or bundle["files"]
            != sorted(
                bundle["files"],
                key=lambda item: str(
                    item.get("path") if isinstance(item, dict) else ""
                ),
            )
            or not isinstance(bundle.get("packages"), list)
            or bundle["packages"]
            != sorted(
                bundle["packages"],
                key=lambda item: str(
                    item.get("purl") if isinstance(item, dict) else ""
                ),
            )
        ):
            raise VerificationError(f"{role} dependency bundle is invalid")
        for key in ("baseImageDigest", "closureSha256", "fileManifestSha256"):
            value = bundle[key]
            _required_digest(value, label=f"{role} {key}")
        seen_paths: set[str] = set()
        for item in bundle["files"]:
            raw_path = item.get("path") if isinstance(item, dict) else None
            if (
                not isinstance(raw_path, str)
                or not raw_path.startswith("/")
                or raw_path.endswith("/")
                or "//" in raw_path
                or "\x00" in raw_path
                or raw_path != unicodedata.normalize("NFC", raw_path)
                or any(
                    component in {"", ".", ".."}
                    for component in raw_path.removeprefix("/").split("/")
                )
            ):
                raise VerificationError(f"{role} dependency path is invalid")
            if (
                not isinstance(item, dict)
                or item["path"] in seen_paths
                or type(item.get("mode")) is not int
                or item["mode"] & ~0o7777
                or type(item.get("uid")) is not int
                or type(item.get("gid")) is not int
                or item["uid"] < 0
                or item["gid"] < 0
            ):
                raise VerificationError(f"{role} dependency file is invalid")
            if item.get("type") == "directory":
                if set(item) != {"gid", "mode", "path", "type", "uid"}:
                    raise VerificationError(
                        f"{role} dependency directory is invalid"
                    )
            elif item.get("type") == "file":
                if (
                    set(item)
                    != {
                        "gid",
                        "mode",
                        "path",
                        "sha256",
                        "size",
                        "type",
                        "uid",
                    }
                    or type(item.get("size")) is not int
                    or item["size"] < 0
                ):
                    raise VerificationError(
                        f"{role} dependency regular file is invalid"
                    )
                _required_digest(
                    item.get("sha256"),
                    label=f"{role} dependency file",
                )
            elif item.get("type") == "symlink":
                if (
                    set(item)
                    != {"gid", "mode", "path", "target", "type", "uid"}
                    or not isinstance(item.get("target"), str)
                    or not item["target"]
                    or "\x00" in item["target"]
                    or unicodedata.normalize("NFC", item["target"])
                    != item["target"]
                    or "//" in item["target"]
                    or item["target"].endswith("/")
                    or any(
                        component in {"", "."}
                        for component in item["target"].lstrip("/").split("/")
                    )
                ):
                    raise VerificationError(
                        f"{role} dependency symlink is invalid"
                    )
            else:
                raise VerificationError(
                    f"{role} dependency entry type is invalid"
                )
            seen_paths.add(item["path"])
        for item in bundle["files"]:
            path = PurePosixPath(item["path"])
            for parent in path.parents:
                if str(parent) == "/":
                    break
                parent_record = next(
                    (
                        candidate
                        for candidate in bundle["files"]
                        if candidate["path"] == str(parent)
                    ),
                    None,
                )
                if (
                    parent_record is None
                    or parent_record["type"] != "directory"
                ):
                    raise VerificationError(
                        f"{role} dependency omits an explicit ancestor directory"
                    )
        package_files: set[str] = set()
        package_names: set[str] = set()
        package_purls: set[str] = set()
        for package in bundle["packages"]:
            if (
                not isinstance(package, dict)
                or set(package) != {"files", "name", "purl", "version"}
                or not all(
                    isinstance(package.get(key), str) and package[key]
                    for key in ("name", "purl", "version")
                )
                or not isinstance(package.get("files"), list)
                or package["files"] != sorted(set(package["files"]))
                or any(path not in seen_paths for path in package["files"])
                or package["name"] in package_names
                or package["purl"] in package_purls
                or any(path in package_files for path in package["files"])
            ):
                raise VerificationError(f"{role} dependency package is invalid")
            package_names.add(package["name"])
            package_purls.add(package["purl"])
            package_files.update(package["files"])
        if package_files != seen_paths:
            raise VerificationError(
                f"{role} dependency package/file relationships are incomplete"
            )
        catalog = bundle["capabilityCatalog"]
        if (
            not isinstance(catalog, dict)
            or set(catalog)
            != {
                "allowedCapabilityClasses",
                "apiVersion",
                "catalogSha256",
                "executables",
                "forbiddenCapabilityClasses",
                "packages",
            }
            or catalog.get("apiVersion")
            != "catchplate.dependencyCapabilityCatalog/v2"
            or catalog.get("allowedCapabilityClasses")
            != DEPENDENCY_ALLOWED_CAPABILITY_CLASSES[role]
            or catalog.get("forbiddenCapabilityClasses")
            != (
                sorted(PORTAL_FORBIDDEN_CAPABILITY_CLASSES)
                if role == "browser-runtime"
                else []
            )
            or bundle["capabilityCatalogSha256"]
            != catalog.get("catalogSha256")
        ):
            raise VerificationError(
                f"{role} dependency capability catalog is invalid"
            )
        catalog_payload = dict(catalog)
        supplied_catalog_sha256 = catalog_payload.pop("catalogSha256", None)
        if supplied_catalog_sha256 != _sha256(
            _canonical_json(catalog_payload)
        ):
            raise VerificationError(
                f"{role} dependency capability catalog digest is invalid"
            )
        executable_files = {
            item["path"]: item
            for item in bundle["files"]
            if item["type"] == "file" and item["mode"] & 0o111
        }
        catalog_executables: dict[str, dict[str, Any]] = {}
        if (
            not isinstance(catalog["executables"], list)
            or catalog["executables"]
            != sorted(
                catalog["executables"],
                key=lambda item: str(
                    item.get("path") if isinstance(item, dict) else ""
                ),
            )
        ):
            raise VerificationError(
                f"{role} executable capability inventory is invalid"
            )
        for executable in catalog["executables"]:
            file_record = (
                executable_files.get(executable.get("path"))
                if isinstance(executable, dict)
                else None
            )
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
                or executable.get("path") in catalog_executables
                or executable.get("capabilityClass")
                not in catalog["allowedCapabilityClasses"]
                or (
                    role == "browser-runtime"
                    and executable.get("capabilityClass")
                    in PORTAL_FORBIDDEN_CAPABILITY_CLASSES
                )
                or executable.get("invocationPolicy")
                != "fixed-oci-entrypoint-or-fixed-transitive-child-only"
                or file_record is None
                or executable.get("sha256") != file_record["sha256"]
            ):
                raise VerificationError(
                    f"{role} executable capability record is invalid"
                )
            _required_digest(
                executable.get("argvPolicySha256"),
                label=f"{role} executable argv policy",
            )
            argv_policy = executable["argvPolicy"]
            if (
                not isinstance(argv_policy, dict)
                or set(argv_policy) != {"apiVersion", "invocations"}
                or argv_policy.get("apiVersion")
                != "catchplate.executableArgvPolicy/v1"
                or not isinstance(argv_policy.get("invocations"), list)
                or not argv_policy["invocations"]
                or argv_policy["invocations"]
                != sorted(
                    argv_policy["invocations"],
                    key=lambda item: _canonical_json(item),
                )
                or executable["argvPolicySha256"]
                != _sha256(_canonical_json(argv_policy))
            ):
                raise VerificationError(
                    f"{role} executable argv policy is invalid"
                )
            for invocation in argv_policy["invocations"]:
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
                    raise VerificationError(
                        f"{role} executable invocation policy is invalid"
                    )
            catalog_executables[executable["path"]] = executable
        if set(catalog_executables) != set(executable_files):
            raise VerificationError(
                f"{role} executable capability inventory is incomplete"
            )
        expected_catalog_packages: list[dict[str, Any]] = []
        for package in bundle["packages"]:
            package_catalog = next(
                (
                    item
                    for item in catalog["packages"]
                    if isinstance(item, dict)
                    and item.get("purl") == package["purl"]
                ),
                None,
            )
            if (
                package_catalog is None
                or set(package_catalog) != {"capabilityClasses", "purl"}
                or not isinstance(
                    package_catalog.get("capabilityClasses"),
                    list,
                )
                or not package_catalog["capabilityClasses"]
                or package_catalog["capabilityClasses"]
                != sorted(set(package_catalog["capabilityClasses"]))
                or any(
                    capability
                    not in catalog["allowedCapabilityClasses"]
                    or (
                        role == "browser-runtime"
                        and capability in PORTAL_FORBIDDEN_CAPABILITY_CLASSES
                    )
                    for capability in package_catalog["capabilityClasses"]
                )
            ):
                raise VerificationError(
                    f"{role} package capability record is invalid"
                )
            expected_catalog_packages.append(package_catalog)
        if (
            catalog["packages"]
            != sorted(expected_catalog_packages, key=lambda item: item["purl"])
            or len(catalog["packages"]) != len(bundle["packages"])
        ):
            raise VerificationError(
                f"{role} package capability inventory is incomplete"
            )
        if role == "clean-room-runtime":
            packaging_packages = [
                item
                for item in bundle["packages"]
                if item["purl"] == "pkg:pypi/packaging@25.0"
            ]
            packaging_capabilities = [
                item
                for item in catalog["packages"]
                if item["purl"] == "pkg:pypi/packaging@25.0"
            ]
            if (
                len(packaging_packages) != 1
                or packaging_packages[0]["name"] != "packaging"
                or packaging_packages[0]["version"] != "25.0"
                or len(packaging_capabilities) != 1
                or packaging_capabilities[0]["capabilityClasses"]
                != ["pep508-parser"]
            ):
                raise VerificationError(
                    "clean-room runtime omits exact packaging 25.0 parser bytes"
                )
            _validate_clean_room_semantic_contract(bundle["semanticContract"])
        elif bundle["semanticContract"] is not None:
            raise VerificationError(
                f"{role} has an unauthorized semantic contract"
            )
        if bundle["fileManifestSha256"] != _sha256(
            _canonical_json(bundle["files"])
        ):
            raise VerificationError(
                f"{role} dependency file-manifest digest is invalid"
            )
        closure_payload = {
            "baseImageDigest": bundle["baseImageDigest"],
            "capabilities": bundle["capabilities"],
            "capabilityCatalog": bundle["capabilityCatalog"],
            "files": bundle["files"],
            "packages": bundle["packages"],
            "semanticContract": bundle["semanticContract"],
        }
        if bundle["closureSha256"] != _sha256(
            _canonical_json(closure_payload)
        ):
            raise VerificationError(
                f"{role} dependency closure digest is invalid"
            )
    if attested_capabilities != _dependency_capability_attestation_payload(
        bundles
    ):
        raise VerificationError(
            "dependency capability authority signed a different bundle"
        )
    return document


def _load_build_watchdog_contract(path: Path) -> dict[str, Any]:
    document = _load_digest_document(
        path,
        label="external build-watchdog contract",
        api_version=BUILD_WATCHDOG_CONTRACT_VERSION,
        digest_field="contractSha256",
    )
    if (
        set(document)
        != {
            "apiVersion",
            "buildNetwork",
            "contractSha256",
            "daemonRuntime",
            "daemonServiceUnit",
            "protocol",
            "receiptSignatureDomain",
            "resourceKinds",
            "resourceLabelNames",
            "serviceUnit",
            "socketPath",
            "sourceSelection",
        }
        or document.get("buildNetwork") != "none"
        or document.get("daemonRuntime") != "containerd-oci-task-v2"
        or document.get("daemonServiceUnit")
        != "catchplate-build-daemon.service"
        or document.get("protocol") != "catchplate.ociBuildWatchdog/v4"
        or document.get("receiptSignatureDomain")
        != BUILD_WATCHDOG_SIGNATURE_DOMAIN[:-1].decode("ascii")
        or document.get("resourceKinds")
        != [
            "builder",
            "container",
            "content",
            "image",
            "snapshot",
            "task",
        ]
        or document.get("resourceLabelNames") != RESOURCE_LABEL_NAMES
        or document.get("serviceUnit")
        != "catchplate-build-watchdog.service"
        or document.get("socketPath")
        != "/run/catchplate-build-watchdog/control.sock"
    ):
        raise VerificationError("external build-watchdog contract is not exact")
    selection = document.get("sourceSelection")
    if (
        not isinstance(selection, dict)
        or set(selection)
        != {
            "apiVersion",
            "classificationPolicy",
            "gitInventoryKeyRawSha256",
            "gitInventoryKeySpkiSha256",
            "gitInventorySignatureDomain",
            "model",
            "requiredUntracked",
            "trackedInventory",
            "unexpectedInputs",
            "untrackedApprovalKeyRawSha256",
            "untrackedApprovalKeySpkiSha256",
            "untrackedApprovalSignatureDomain",
        }
        or selection.get("apiVersion") != SOURCE_INPUT_MANIFEST_VERSION
        or selection.get("classificationPolicy")
        != "independently-signed-source-or-build-input-provenance-only"
        or selection.get("gitInventorySignatureDomain")
        != GIT_SOURCE_INVENTORY_SIGNATURE_DOMAIN[:-1].decode("ascii")
        or selection.get("model") != SOURCE_SELECTION_MODEL
        or selection.get("requiredUntracked")
        != "complete-status-subset-each-exactly-approved"
        or selection.get("trackedInventory")
        != "raw-index-and-recursive-head-tree-rederived-equal"
        or selection.get("unexpectedInputs") != "reject"
        or selection.get("untrackedApprovalSignatureDomain")
        != UNTRACKED_APPROVAL_SIGNATURE_DOMAIN[:-1].decode("ascii")
    ):
        raise VerificationError("build-watchdog source selection is not exact")
    for key in (
        "gitInventoryKeyRawSha256",
        "gitInventoryKeySpkiSha256",
        "untrackedApprovalKeyRawSha256",
        "untrackedApprovalKeySpkiSha256",
    ):
        _required_digest(selection.get(key), label=f"source selection {key}")
    if (
        selection["gitInventoryKeyRawSha256"]
        == selection["untrackedApprovalKeyRawSha256"]
    ):
        raise VerificationError("source evidence authorities are not independent")
    return document


def _runtime_process(name: str) -> dict[str, Any]:
    environment = dict(BASE_ENVIRONMENT)
    dynamic_environment = (
        list(PORTAL_DYNAMIC_ENVIRONMENT)
        if name == "portal-browser-oauth"
        else []
    )
    if name == "rust-decision-gate-tests":
        entrypoint = ["/opt/catchplate/bin/catchplate-decision-gate-tests"]
        argv = ["--test-threads=1"]
    else:
        entrypoint = [
            "/opt/catchplate/python/bin/python3",
            "-I",
            PYTHON_ENTRYPOINT_IMAGE,
        ]
        argv = ["--role", name]
    return {
        "argv": argv,
        "cwd": "/work",
        "dynamicEnvironment": dynamic_environment,
        "entrypoint": entrypoint,
        "environment": environment,
        "gid": 65532,
        "uid": 65532,
    }


def _isolation(
    name: str,
    *,
    apparmor_sha256: str,
    seccomp_sha256: str,
) -> dict[str, Any]:
    memory = (
        1024 * 1024 * 1024
        if name == "portal-browser-oauth"
        else 512 * 1024 * 1024
    )
    timeout = (
        900
        if name == "portal-browser-oauth"
        else 120
        if name == "npm-publish-companion"
        else 300
    )
    return {
        "apparmorProfileSha256": apparmor_sha256,
        "capDrop": ["ALL"],
        "cpuQuotaMicros": 1_000_000,
        "memoryBytes": memory,
        "mounts": [
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
        ],
        "noNewPrivileges": True,
        "outputStderrBytes": 16 * 1024 * 1024,
        "outputStdoutBytes": 32 * 1024 * 1024,
        "pidsLimit": 256,
        "readOnlyRootfs": True,
        "seccompProfileSha256": seccomp_sha256,
        "tmpfs": [
            {
                "destination": "/run/catchplate-runtime",
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
        ],
        "timeoutSeconds": timeout,
    }


def _network(name: str) -> dict[str, Any]:
    if name == "portal-browser-oauth":
        return {
            "egress": "none",
            "mode": "internal",
            "namespace": "private-anchor",
            "role": "portal-npm-private",
        }
    if name == "npm-publish-companion":
        return {
            "egress": "none",
            "mode": "join",
            "namespace": "lane:portal-browser-oauth",
            "role": "portal-npm-private",
        }
    return {
        "egress": "none",
        "mode": "none",
        "namespace": "private",
        "role": None,
    }


def _capability_probes(name: str) -> list[str]:
    if name in {
        "browser-python-compatibility",
        "host-python-compatibility",
        "proxy-python-compatibility",
    }:
        return list(PYTHON_CAPABILITY_PROBES)
    if name == "chromium-compatibility":
        return ["chromium-startup-no-network"]
    return []


def _source_files_for_lane(
    name: str,
    entries: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    contract = LANE_SOURCE_CONTRACTS[name]
    exact = set(contract["exact"])
    prefixes = set(contract["prefixes"])
    if name != "rust-decision-gate-tests":
        exact.add(PYTHON_ENTRYPOINT_SOURCE)
    selected = [
        record
        for record in entries
        if record["type"] == "file"
        and (
            record["path"] in exact
            or any(record["path"].startswith(prefix) for prefix in prefixes)
        )
    ]
    selected_paths = {record["path"] for record in selected}
    missing_exact = exact - selected_paths
    missing_prefixes = [
        prefix
        for prefix in prefixes
        if not any(path.startswith(prefix) for path in selected_paths)
    ]
    if not selected or missing_exact or missing_prefixes:
        raise VerificationError(
            f"{name} source closure omits fixed paths or prefixes"
        )
    return selected


def _dependency_role(name: str) -> str:
    if name in {
        "browser-python-compatibility",
        "chromium-compatibility",
        "portal-browser-oauth",
    }:
        return "browser-runtime"
    if name == "clean-room":
        return "clean-room-runtime"
    if name == "rust-decision-gate-tests":
        return "rust-runtime"
    return "python-runtime"


def _dockerfile(process: dict[str, Any], base_digest: str) -> str:
    environment = " ".join(
        f"{name}={json.dumps(value, ensure_ascii=True)}"
        for name, value in sorted(process["environment"].items())
    )
    return "\n".join(
        (
            "FROM scratch",
            f"ARG CATCHPLATE_BASE_IMAGE_DIGEST={base_digest}",
            "ARG SOURCE_DATE_EPOCH=0",
            "COPY --chown=0:0 rootfs/ /",
            f"ENV {environment}",
            f"WORKDIR {json.dumps(process['cwd'])}",
            f"USER {process['uid']}:{process['gid']}",
            "ENTRYPOINT "
            + json.dumps(process["entrypoint"], ensure_ascii=True, separators=(",", ":")),
            "CMD " + json.dumps(process["argv"], ensure_ascii=True, separators=(",", ":")),
            "",
        )
    )


def _lane_plan(
    name: str,
    *,
    source: dict[str, Any],
    dependencies: dict[str, Any],
    security_profiles: dict[str, str],
) -> dict[str, Any]:
    process = _runtime_process(name)
    dependency_role = _dependency_role(name)
    dependency = dependencies["bundles"][dependency_role]
    source_files = _source_files_for_lane(name, source["entries"])
    dependency_paths = {
        item["path"] for item in dependency["files"]
    }
    if any(
        "/opt/catchplate/src/" + item["path"] in dependency_paths
        for item in source_files
    ):
        raise VerificationError(
            f"{name} dependency and frozen source paths collide"
        )
    entrypoint_source = (
        None
        if name == "rust-decision-gate-tests"
        else next(
            (
                item
                for item in source_files
                if item["path"] == PYTHON_ENTRYPOINT_SOURCE
            ),
            None,
        )
    )
    if name != "rust-decision-gate-tests" and entrypoint_source is None:
        raise VerificationError(f"{name} omits the tracked lane entrypoint")
    installed_source_files = [
        {
            "imagePath": "/opt/catchplate/src/" + item["path"],
            "mode": 0o444,
            "source": item,
        }
        for item in source_files
    ]
    context_payload = {
        "dependencyBundle": {
            "capabilities": dependency["capabilities"],
            "closureSha256": dependency["closureSha256"],
            "fileManifestSha256": dependency["fileManifestSha256"],
            "role": dependency_role,
        },
        "installedEntrypoint": (
            {
                "imagePath": PYTHON_ENTRYPOINT_IMAGE,
                "mode": 0o444,
                "source": entrypoint_source,
            }
            if entrypoint_source is not None
            else {
                "imagePath": process["entrypoint"][0],
                "origin": "rust-runtime-bundle",
            }
        ),
        "installedSourceFiles": installed_source_files,
        "sourceFiles": source_files,
    }
    dockerfile = _dockerfile(process, dependency["baseImageDigest"])
    build = {
        "baseImageDigest": dependency["baseImageDigest"],
        "contextManifestSha256": _sha256(_canonical_json(context_payload)),
        "dependencyRole": dependency_role,
        "dockerfile": dockerfile,
        "dockerfileSha256": _sha256(dockerfile.encode("ascii")),
        "network": "none",
        "platform": {"architecture": "amd64", "os": "linux"},
        "sourceDateEpoch": 0,
    }
    return {
        "build": build,
        "capabilityProbes": _capability_probes(name),
        "imageRole": f"lane-{name}",
        "isolation": _isolation(
            name,
            apparmor_sha256=security_profiles["apparmor"],
            seccomp_sha256=security_profiles["seccomp"],
        ),
        "installedSourceFiles": installed_source_files,
        "name": name,
        "network": _network(name),
        "process": process,
        "runtime": {
            "dependencyCapabilityCatalogSha256": dependency[
                "capabilityCatalogSha256"
            ],
            "dependencyCapabilities": dependency["capabilities"],
            "dependencyClosureSha256": dependency["closureSha256"],
            "dependencyFileManifestSha256": dependency["fileManifestSha256"],
            "dependencyRole": dependency_role,
            "semanticContractSha256": (
                dependency["semanticContract"]["contractSha256"]
                if dependency["semanticContract"] is not None
                else None
            ),
        },
        "sourceSet": {
            "exact": sorted(
                set(LANE_SOURCE_CONTRACTS[name]["exact"])
                | (
                    set()
                    if name == "rust-decision-gate-tests"
                    else {PYTHON_ENTRYPOINT_SOURCE}
                )
            ),
            "prefixes": LANE_SOURCE_CONTRACTS[name]["prefixes"],
        },
        "sourceFiles": source_files,
    }


def _npm_plan(
    dependencies: dict[str, Any],
    source: dict[str, Any],
    *,
    security_profiles: dict[str, str],
) -> dict[str, Any]:
    dependency = dependencies["bundles"]["npm-11.8-runtime"]
    process = {
        "argv": [],
        "cwd": "/work",
        "dynamicEnvironment": [],
        "entrypoint": [
            "/opt/catchplate/node/bin/node",
            NPM_ENTRYPOINT_IMAGE,
        ],
        "environment": {
            "CI": "true",
            "HOME": "/work/home",
            "LANG": "C",
            "LC_ALL": "C",
            "NO_PROXY": "",
            "TMPDIR": "/work/tmp",
            "npm_config_audit": "false",
            "npm_config_fund": "false",
            "npm_config_update_notifier": "false",
            "XDG_RUNTIME_DIR": "/run/catchplate-runtime",
        },
        "gid": 65532,
        "uid": 65532,
    }
    dockerfile = _dockerfile(process, dependency["baseImageDigest"])
    source_files = [
        item
        for item in source["entries"]
        if item["type"] == "file" and item["path"] == NPM_ENTRYPOINT_SOURCE
    ]
    if len(source_files) != 1:
        raise VerificationError("tracked npm companion source is missing")
    if any(
        "/opt/catchplate/src/" + item["path"]
        in {entry["path"] for entry in dependency["files"]}
        for item in source_files
    ):
        raise VerificationError(
            "npm dependency and tracked companion source paths collide"
        )
    context = {
        "dependencyBundle": {
            "capabilities": dependency["capabilities"],
            "closureSha256": dependency["closureSha256"],
            "fileManifestSha256": dependency["fileManifestSha256"],
            "role": "npm-11.8-runtime",
        },
        "installedEntrypoint": {
            "imagePath": NPM_ENTRYPOINT_IMAGE,
            "mode": 0o444,
            "source": source_files[0],
        },
        "installedSourceFiles": [
            {
                "imagePath": NPM_ENTRYPOINT_IMAGE,
                "mode": 0o444,
                "source": source_files[0],
            }
        ],
        "sourceFiles": source_files,
    }
    return {
        "build": {
            "baseImageDigest": dependency["baseImageDigest"],
            "contextManifestSha256": _sha256(_canonical_json(context)),
            "dependencyRole": "npm-11.8-runtime",
            "dockerfile": dockerfile,
            "dockerfileSha256": _sha256(dockerfile.encode("ascii")),
            "network": "none",
            "platform": {"architecture": "amd64", "os": "linux"},
            "sourceDateEpoch": 0,
        },
        "imageRole": "npm-publish-companion",
        "isolation": _isolation(
            "npm-publish-companion",
            apparmor_sha256=security_profiles["apparmor"],
            seccomp_sha256=security_profiles["seccomp"],
        ),
        "installedSourceFiles": context["installedSourceFiles"],
        "network": _network("npm-publish-companion"),
        "process": process,
        "runtime": {
            "dependencyCapabilityCatalogSha256": dependency[
                "capabilityCatalogSha256"
            ],
            "dependencyCapabilities": dependency["capabilities"],
            "dependencyClosureSha256": dependency["closureSha256"],
            "dependencyFileManifestSha256": dependency["fileManifestSha256"],
            "dependencyRole": "npm-11.8-runtime",
            "semanticContractSha256": None,
        },
        "sourceFiles": source_files,
        "sourceSet": {
            "exact": [NPM_ENTRYPOINT_SOURCE],
            "prefixes": [],
        },
    }


def _derive_build_plan_payload(
    *,
    source: dict[str, Any],
    source_manifest_file: dict[str, Any],
    dependencies: dict[str, Any],
    watchdog_contract: dict[str, Any],
    apparmor: dict[str, Any],
    seccomp: dict[str, Any],
) -> dict[str, Any]:
    selection_contract = watchdog_contract["sourceSelection"]
    git_signature = source["selection"]["gitInventory"]["signature"]
    approval_signature = source["selection"]["untrackedApproval"]["signature"]
    capability_signature = dependencies["capabilityAttestation"][
        "signature"
    ]
    if (
        selection_contract["gitInventoryKeySpkiSha256"]
        != git_signature["keyFileSha256"]
        or selection_contract["gitInventoryKeyRawSha256"]
        != git_signature["rawKeySha256"]
        or selection_contract["untrackedApprovalKeySpkiSha256"]
        != approval_signature["keyFileSha256"]
        or selection_contract["untrackedApprovalKeyRawSha256"]
        != approval_signature["rawKeySha256"]
        or capability_signature["rawKeySha256"]
        in {
            git_signature["rawKeySha256"],
            approval_signature["rawKeySha256"],
        }
    ):
        raise VerificationError(
            "source/capability evidence authorities are not exact and independent"
        )
    apparmor = _content_identity(
        Path(apparmor["path"]),
        label="OCI lane AppArmor profile continuity",
        max_bytes=1024 * 1024,
    )
    seccomp = _content_identity(
        Path(seccomp["path"]),
        label="OCI lane seccomp profile continuity",
        max_bytes=1024 * 1024,
    )
    security_profiles = {"apparmor": apparmor["sha256"], "seccomp": seccomp["sha256"]}
    lanes = {
        name: _lane_plan(
            name,
            source=source,
            dependencies=dependencies,
            security_profiles=security_profiles,
        )
        for name in LANE_ORDER
    }
    npm = _npm_plan(
        dependencies,
        source,
        security_profiles=security_profiles,
    )
    image_order = [f"lane-{name}" for name in LANE_ORDER] + [
        "npm-publish-companion"
    ]
    payload = {
        "apiVersion": OCI_BUILD_PLAN_VERSION,
        "buildWatchdogContract": watchdog_contract,
        "dependencyBundle": dependencies,
        "export": {
            "archiveFormat": "oci-layout-tar",
            "compression": "gzip",
            "forceCompression": True,
            "gzipMtime": 0,
            "historyCreatedBy": "catchplate-oci-builder-v4:rootfs",
            "layerCount": 1,
            "ociMediaTypes": True,
            "platform": {"architecture": "amd64", "os": "linux"},
            "provenanceMetadata": False,
            "rewriteTimestamps": True,
            "sourceDateEpoch": 0,
            "tarOrdering": (
                "oci-layout-then-index-json-then-sorted-blobs-sha256"
            ),
        },
        "imageOrder": image_order,
        "lanes": lanes,
        "npmCompanion": npm,
        "securityProfiles": {
            "apparmor": apparmor,
            "seccomp": seccomp,
        },
        "sourceSnapshot": {
            "sourceClosureSha256": source["closureSha256"],
            "sourceFileInventorySha256": _sha256(
                _canonical_json(source["entries"])
            ),
            "sourceManifest": source,
            "sourceManifestFileSha256": source_manifest_file["sha256"],
            "sourceManifestPayloadSha256": _sha256(
                _canonical_json(source)
            ),
            "sourcePathListSha256": source["selection"]["pathListSha256"],
            "sourceEvidence": source["selection"]["sourceEvidence"],
            "sourceEvidenceSha256": source["selection"][
                "sourceEvidenceSha256"
            ],
            "sourceGitInventoryKeyRawSha256": source["selection"][
                "gitInventory"
            ]["signature"]["rawKeySha256"],
            "sourceGitInventoryKeySpkiSha256": source["selection"][
                "gitInventory"
            ]["signature"]["keyFileSha256"],
            "sourceGitInventoryPayloadSha256": source["selection"][
                "gitInventoryPayloadSha256"
            ],
            "sourceRootBindingSha256": source["sourceRootBindingSha256"],
            "sourceSelectionManifestFileSha256": source[
                "selectionManifestFileSha256"
            ],
            "sourceSelectionManifestPayloadSha256": source[
                "selectionManifestPayloadSha256"
            ],
            "sourceSelectionModel": SOURCE_SELECTION_MODEL,
            "sourceUntrackedApprovalKeyRawSha256": source["selection"][
                "untrackedApproval"
            ]["signature"]["rawKeySha256"],
            "sourceUntrackedApprovalKeySpkiSha256": source["selection"][
                "untrackedApproval"
            ]["signature"]["keyFileSha256"],
            "sourceUntrackedApprovalPayloadSha256": source["selection"][
                "untrackedApprovalPayloadSha256"
            ],
            "snapshotRootBindingSha256": source["rootBindingSha256"],
        },
    }
    return payload


def _record_build_plan(args: argparse.Namespace) -> dict[str, Any]:
    source = _load_source_manifest(
        args.source_manifest,
        root=args.source_snapshot,
        source_input_manifest=args.source_input_manifest,
        expected_source_input_manifest_sha256=(
            args.expected_source_input_manifest_sha256
        ),
        source_git_inventory_public_key=args.source_git_inventory_public_key,
        expected_source_git_inventory_key_spki_sha256=(
            args.expected_source_git_inventory_key_spki_sha256
        ),
        expected_source_git_inventory_key_raw_sha256=(
            args.expected_source_git_inventory_key_raw_sha256
        ),
        source_untracked_approval_public_key=(
            args.source_untracked_approval_public_key
        ),
        expected_source_untracked_approval_key_spki_sha256=(
            args.expected_source_untracked_approval_key_spki_sha256
        ),
        expected_source_untracked_approval_key_raw_sha256=(
            args.expected_source_untracked_approval_key_raw_sha256
        ),
    )
    source_manifest_raw, _ = _read_regular(
        args.source_manifest,
        label="source snapshot manifest file",
    )
    dependencies = _load_dependencies(
        args.dependency_bundle_manifest,
        capability_authority_public_key=(
            args.dependency_capability_authority_public_key
        ),
        expected_capability_authority_key_spki_sha256=(
            args.expected_dependency_capability_authority_key_spki_sha256
        ),
        expected_capability_authority_key_raw_sha256=(
            args.expected_dependency_capability_authority_key_raw_sha256
        ),
    )
    watchdog_contract = _load_build_watchdog_contract(
        args.build_watchdog_contract
    )
    apparmor = _content_identity(
        args.apparmor_profile,
        label="OCI lane AppArmor profile",
        max_bytes=1024 * 1024,
    )
    seccomp = _content_identity(
        args.seccomp_profile,
        label="OCI lane seccomp profile",
        max_bytes=1024 * 1024,
    )
    payload = _derive_build_plan_payload(
        source=source,
        source_manifest_file={
            "sha256": _sha256(source_manifest_raw),
            "size": len(source_manifest_raw),
        },
        dependencies=dependencies,
        watchdog_contract=watchdog_contract,
        apparmor=apparmor,
        seccomp=seccomp,
    )
    document = {**payload, "planSha256": _sha256(_canonical_json(payload))}
    _remeasure_live_selected_source(source)
    _publish(
        args.out,
        _canonical_json(document) + b"\n",
        output_root=Path(source["sourceRoot"]) / ".tmp",
    )
    return document


def _load_build_plan(path: Path) -> dict[str, Any]:
    document = _load_digest_document(
        path,
        label="OCI lane build plan",
        api_version=OCI_BUILD_PLAN_VERSION,
        digest_field="planSha256",
    )
    if (
        set(document)
        != {
            "apiVersion",
            "buildWatchdogContract",
            "dependencyBundle",
            "export",
            "imageOrder",
            "lanes",
            "npmCompanion",
            "planSha256",
            "securityProfiles",
            "sourceSnapshot",
        }
        or document["imageOrder"]
        != [f"lane-{name}" for name in LANE_ORDER]
        + ["npm-publish-companion"]
        or list(document["lanes"]) != list(LANE_ORDER)
    ):
        raise VerificationError("OCI build plan inventory is invalid")
    return document


def _descriptor(
    value: Any,
    *,
    label: str,
    media_type: str,
    platform: dict[str, str] | None = None,
) -> dict[str, Any]:
    expected_keys = {"digest", "mediaType", "size"}
    if platform is not None:
        expected_keys.add("platform")
    if (
        not isinstance(value, dict)
        or set(value) != expected_keys
        or type(value.get("size")) is not int
        or value["size"] < 0
        or value.get("mediaType") != media_type
        or (platform is not None and value.get("platform") != platform)
    ):
        raise VerificationError(f"{label} OCI descriptor is invalid")
    _required_digest(value.get("digest"), label=f"{label} digest")
    return value


def _blob_name(digest: str) -> str:
    return "blobs/sha256/" + digest.removeprefix("sha256:")


def _tar_string(raw: bytes, *, label: str) -> str:
    value, separator, padding = raw.partition(b"\x00")
    if separator and any(padding):
        raise VerificationError(f"{label} is not canonical NUL padding")
    try:
        text = value.decode("utf-8")
    except UnicodeError as exc:
        raise VerificationError(f"{label} is not UTF-8") from exc
    if unicodedata.normalize("NFC", text) != text:
        raise VerificationError(f"{label} is not NFC")
    return text


def _tar_octal(raw: bytes, *, label: str) -> int:
    if (
        len(raw) < 2
        or raw[-1:] != b"\x00"
        or re.fullmatch(rb"[0-7]+", raw[:-1]) is None
    ):
        raise VerificationError(f"{label} is not canonical octal")
    return int(raw[:-1], 8)


def _canonical_tar_path(
    name: str,
    *,
    directory: bool,
    label: str,
) -> tuple[str, str]:
    if (
        not name
        or name.startswith(("/", "./"))
        or "//" in name
        or "\x00" in name
        or (directory and not name.endswith("/"))
        or (not directory and name.endswith("/"))
    ):
        raise VerificationError(f"{label} is not canonical")
    logical = name[:-1] if directory else name
    if any(component in {"", ".", ".."} for component in logical.split("/")):
        raise VerificationError(f"{label} contains an unsafe component")
    if unicodedata.normalize("NFC", logical) != logical:
        raise VerificationError(f"{label} is not NFC")
    return name, logical


def _canonical_ustar_split(name: str, *, label: str) -> tuple[str, str]:
    encoded = name.encode("utf-8")
    if len(encoded) <= 100:
        return "", name
    candidates: list[tuple[int, str, str]] = []
    for index, character in enumerate(name):
        if character != "/" or index == 0 or index == len(name) - 1:
            continue
        prefix = name[:index]
        leaf = name[index + 1 :]
        prefix_bytes = prefix.encode("utf-8")
        leaf_bytes = leaf.encode("utf-8")
        if len(prefix_bytes) <= 155 and len(leaf_bytes) <= 100:
            candidates.append((len(prefix_bytes), prefix, leaf))
    if not candidates:
        raise VerificationError(f"{label} cannot be represented as canonical USTAR")
    _, prefix, leaf = max(candidates, key=lambda item: item[0])
    return prefix, leaf


def _canonical_symlink_target(value: str, *, label: str) -> str:
    if (
        not value
        or "\x00" in value
        or "//" in value
        or value.endswith("/")
        or unicodedata.normalize("NFC", value) != value
        or any(
            component in {"", "."}
            for component in value.lstrip("/").split("/")
        )
    ):
        raise VerificationError(f"{label} is not canonical")
    return value


def _validate_canonical_tar(
    raw: bytes,
    *,
    label: str,
    outer: bool,
) -> list[dict[str, Any]]:
    if len(raw) < 1024 or len(raw) % 512:
        raise VerificationError(f"{label} has noncanonical block framing")
    offset = 0
    records: list[dict[str, Any]] = []
    normalized: set[str] = set()
    while offset + 1024 <= len(raw):
        header = raw[offset : offset + 512]
        if header == b"\x00" * 512:
            if raw[offset:] != b"\x00" * 1024:
                raise VerificationError(
                    f"{label} must end in exactly two zero blocks"
                )
            offset += 1024
            break
        if header[257:263] != b"ustar\x00" or header[263:265] != b"00":
            raise VerificationError(f"{label} member is not canonical USTAR")
        checksum_field = header[148:156]
        if re.fullmatch(rb"[0-7]{6}\x00 ", checksum_field) is None:
            raise VerificationError(f"{label} checksum is not canonical")
        measured_checksum = sum(header[:148]) + 8 * 32 + sum(header[156:])
        if int(checksum_field[:6], 8) != measured_checksum:
            raise VerificationError(f"{label} header checksum is invalid")
        prefix = _tar_string(header[345:500], label=f"{label} prefix")
        leaf = _tar_string(header[0:100], label=f"{label} name")
        name = prefix + "/" + leaf if prefix else leaf
        member_type = header[156:157]
        if member_type == b"\x00":
            raise VerificationError(
                f"{label} uses the legacy NUL regular-file typeflag"
            )
        if member_type in {b"x", b"g", b"L", b"K", b"S"}:
            raise VerificationError(
                f"{label} contains a PAX/GNU alternate-name or sparse member"
            )
        allowed_types = {b"0"} if outer else {b"0", b"2", b"5"}
        if member_type not in allowed_types:
            raise VerificationError(f"{label} contains a special member")
        directory = member_type == b"5"
        raw_name, logical = _canonical_tar_path(
            name,
            directory=directory,
            label=f"{label} member name",
        )
        if (prefix, leaf) != _canonical_ustar_split(
            raw_name,
            label=f"{label} member name",
        ):
            raise VerificationError(
                f"{label} member uses a noncanonical USTAR name/prefix split"
            )
        if logical in normalized:
            raise VerificationError(f"{label} contains a normalized duplicate")
        normalized.add(logical)
        mode = _tar_octal(header[100:108], label=f"{label} mode")
        if not outer and mode & ~0o7777:
            raise VerificationError(
                f"{label} mode contains bits outside 0o7777"
            )
        uid = _tar_octal(header[108:116], label=f"{label} uid")
        gid = _tar_octal(header[116:124], label=f"{label} gid")
        size = _tar_octal(header[124:136], label=f"{label} size")
        mtime = _tar_octal(header[136:148], label=f"{label} mtime")
        if mtime != 0 or any(header[265:345]) or any(header[500:512]):
            raise VerificationError(f"{label} metadata is not deterministic")
        linkname = _tar_string(header[157:257], label=f"{label} linkname")
        if member_type in {b"0", b"5"} and linkname:
            raise VerificationError(f"{label} ordinary member has a link target")
        if member_type == b"2":
            _canonical_symlink_target(
                linkname,
                label=f"{label} symlink target",
            )
        if member_type in {b"1", b"2", b"5"} and size != 0:
            raise VerificationError(f"{label} link or directory has content")
        data_offset = offset + 512
        padded_size = (size + 511) // 512 * 512
        end = data_offset + padded_size
        if end > len(raw):
            raise VerificationError(f"{label} member exceeds the archive")
        content = raw[data_offset : data_offset + size]
        if any(raw[data_offset + size : end]):
            raise VerificationError(f"{label} member padding is not zero")
        records.append(
            {
                "content": content,
                "gid": gid,
                "linkname": linkname,
                "logical": logical,
                "mode": mode,
                "name": raw_name,
                "size": size,
                "type": member_type.decode("ascii"),
                "uid": uid,
            }
        )
        offset = end
    if offset != len(raw):
        raise VerificationError(f"{label} end blocks are invalid")
    order = [item["logical"] for item in records]
    if outer:
        blob_names = order[2:]
        if (
            order[:2] != ["oci-layout", "index.json"]
            or not blob_names
            or blob_names != sorted(blob_names)
            or any(
                re.fullmatch(r"blobs/sha256/[0-9a-f]{64}", name)
                is None
                for name in blob_names
            )
        ):
            raise VerificationError(
                f"{label} member sequence is not the exact canonical OCI sequence"
            )
    elif order != sorted(order):
        raise VerificationError(f"{label} members are not lexicographically ordered")
    return records


def _read_oci_archive(
    path: Path,
    *,
    root_fd: int | None = None,
    relative: PurePosixPath | None = None,
) -> tuple[dict[str, bytes], dict[str, Any]]:
    if (root_fd is None) != (relative is None):
        raise VerificationError("OCI archive rooted-open arguments are incomplete")
    raw, metadata = (
        _read_regular(
            path,
            label="OCI archive",
            max_bytes=MAX_OCI_ARCHIVE_BYTES,
        )
        if root_fd is None
        else _read_regular_at(
            root_fd,
            relative,
            label="OCI archive",
            max_bytes=MAX_OCI_ARCHIVE_BYTES,
        )
    )
    raw_records = _validate_canonical_tar(raw, label="OCI archive", outer=True)
    files: dict[str, bytes] = {}
    try:
        archive = tarfile.open(fileobj=io.BytesIO(raw), mode="r:")
    except tarfile.TarError as exc:
        raise VerificationError("OCI archive is not a valid tar") from exc
    with archive:
        members = archive.getmembers()
        if len(members) > MAX_OCI_MEMBERS:
            raise VerificationError("OCI archive contains too many members")
        if len(members) != len(raw_records):
            raise VerificationError("OCI archive parser inventory differs")
        for member, raw_record in zip(members, raw_records, strict=True):
            name = raw_record["logical"]
            if (
                member.name != raw_record["name"]
                or member.uid != 0
                or member.gid != 0
                or member.mtime != 0
                or member.uname
                or member.gname
                or member.pax_headers
                or member.mode != 0o644
            ):
                raise VerificationError("OCI archive metadata is not deterministic")
            if not member.isfile() or member.islnk() or member.issym():
                raise VerificationError("OCI archive contains a non-regular member")
            content = raw_record["content"]
            if len(content) > MAX_OCI_ARCHIVE_BYTES:
                raise VerificationError("OCI archive member exceeds its bound")
            if name in files:
                raise VerificationError("OCI archive contains a duplicate member")
            files[name] = content
    return files, {
        "path": str(path),
        "sha256": _sha256(raw),
        "size": metadata.st_size,
    }


def _blob(
    files: dict[str, bytes],
    descriptor: dict[str, Any],
    *,
    label: str,
) -> bytes:
    name = _blob_name(descriptor["digest"])
    raw = files.get(name)
    if raw is None or len(raw) != descriptor["size"] or _sha256(raw) != descriptor["digest"]:
        raise VerificationError(f"{label} OCI blob identity is invalid")
    return raw


def _decompress_layer(raw: bytes) -> bytes:
    if (
        len(raw) < 18
        or raw[:10] != b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\xff"
    ):
        raise VerificationError("OCI gzip layer is not deterministically encoded")
    compressed = raw[10:-8]
    trailer_crc, trailer_size = struct.unpack("<II", raw[-8:])
    try:
        inflater = zlib.decompressobj(wbits=-zlib.MAX_WBITS)
        output = inflater.decompress(compressed, MAX_LAYER_BYTES + 1)
        output += inflater.flush()
    except zlib.error as exc:
        raise VerificationError("OCI gzip layer is invalid") from exc
    if (
        len(output) > MAX_LAYER_BYTES
        or not inflater.eof
        or inflater.unconsumed_tail
        or inflater.unused_data
        or zlib.crc32(output) & 0xFFFFFFFF != trailer_crc
        or len(output) & 0xFFFFFFFF != trailer_size
    ):
        raise VerificationError("OCI gzip layer framing or trailer is invalid")
    return output


def _normalize_layer_path(value: str, *, label: str) -> str:
    path = _safe_relative(value, label=label)
    return "/" + path.as_posix()


def _remove_subtree(state: dict[str, dict[str, Any]], path: str) -> None:
    prefix = path.rstrip("/") + "/"
    for candidate in list(state):
        if candidate == path or candidate.startswith(prefix):
            del state[candidate]


def _apply_layer(
    state: dict[str, dict[str, Any]],
    raw: bytes,
    content_state: dict[str, bytes],
) -> None:
    raw_records = _validate_canonical_tar(raw, label="OCI layer", outer=False)
    try:
        archive = tarfile.open(fileobj=io.BytesIO(raw), mode="r:")
    except tarfile.TarError as exc:
        raise VerificationError("OCI layer tar is invalid") from exc
    with archive:
        members = archive.getmembers()
        if len(members) != len(raw_records):
            raise VerificationError("OCI layer parser inventory differs")
        lower_state = dict(state)
        deletions: list[tuple[str, str]] = []
        additions: list[tuple[tarfile.TarInfo, dict[str, Any], str]] = []
        ordinary_paths: set[str] = set()
        deletion_targets: set[str] = set()
        for member, raw_record in zip(members, raw_records, strict=True):
            if (
                member.name != raw_record["name"]
                or member.mtime != 0
                or member.uid < 0
                or member.gid < 0
                or member.uname
                or member.gname
                or member.pax_headers
            ):
                raise VerificationError("OCI rootfs metadata is not deterministic")
            if getattr(member, "sparse", None):
                raise VerificationError("OCI layer sparse files are unsupported")
            path = "/" + raw_record["logical"]
            basename = PurePosixPath(path).name
            parent = str(PurePosixPath(path).parent)
            if basename == ".wh..wh..opq" or basename.startswith(".wh."):
                if (
                    raw_record["type"] != "0"
                    or raw_record["size"] != 0
                    or raw_record["content"]
                    or raw_record["uid"] != 0
                    or raw_record["gid"] != 0
                    or raw_record["mode"] != 0
                    or raw_record["linkname"]
                    or not member.isfile()
                ):
                    raise VerificationError(
                        "OCI whiteout is not an exact zero-byte regular file"
                    )
                if basename == ".wh..wh..opq":
                    target = parent
                    operation = "opaque"
                else:
                    target_name = basename.removeprefix(".wh.")
                    if not target_name or target_name.startswith(".wh."):
                        raise VerificationError("OCI whiteout target is invalid")
                    target = str(PurePosixPath(parent) / target_name)
                    operation = "delete"
                if target in deletion_targets:
                    raise VerificationError("OCI whiteout target is duplicated")
                deletion_targets.add(target)
                deletions.append((operation, target))
                continue
            if path in ordinary_paths:
                raise VerificationError("OCI ordinary member is duplicated")
            ordinary_paths.add(path)
            additions.append((member, raw_record, path))
        if ordinary_paths & deletion_targets:
            raise VerificationError("OCI layer both whiteouts and adds one path")

        state.clear()
        state.update(lower_state)
        for operation, target in deletions:
            if operation == "opaque":
                prefix = target.rstrip("/") + "/"
                for candidate in list(state):
                    if candidate.startswith(prefix):
                        del state[candidate]
                        content_state.pop(candidate, None)
            else:
                _remove_subtree(state, target)
                for candidate in list(content_state):
                    if candidate == target or candidate.startswith(
                        target.rstrip("/") + "/"
                    ):
                        del content_state[candidate]

        for member, raw_record, path in additions:
            ancestors = list(PurePosixPath(path).parents)
            for ancestor in ancestors[:-1]:
                ancestor_record = state.get(str(ancestor))
                if (
                    ancestor_record is None
                    or ancestor_record["type"] != "directory"
                ):
                    raise VerificationError(
                        "OCI rootfs member omits an explicit ancestor directory"
                    )
            common = {
                "gid": raw_record["gid"],
                "mode": raw_record["mode"],
                "path": path,
                "uid": raw_record["uid"],
                "xattrs": {},
            }
            if raw_record["type"] == "5" and member.isdir():
                if (
                    path in state
                    and state[path]["type"] != "directory"
                ):
                    del state[path]
                    content_state.pop(path, None)
                state[path] = {**common, "type": "directory"}
            elif raw_record["type"] == "0" and member.isfile():
                _remove_subtree(state, path)
                for candidate in list(content_state):
                    if candidate == path or candidate.startswith(path + "/"):
                        del content_state[candidate]
                content = raw_record["content"]
                if len(content) > MAX_ROOTFS_BYTES:
                    raise VerificationError("OCI rootfs file exceeds its bound")
                state[path] = {
                    **common,
                    "sha256": _sha256(content),
                    "size": len(content),
                    "type": "file",
                }
                content_state[path] = content
            elif raw_record["type"] == "2" and member.issym():
                _remove_subtree(state, path)
                content_state.pop(path, None)
                target = _canonical_symlink_target(
                    raw_record["linkname"],
                    label="OCI rootfs symlink target",
                )
                state[path] = {
                    **common,
                    "target": target,
                    "type": "symlink",
                }
            else:
                raise VerificationError(
                    "OCI layer contains a hardlink, device, fifo, or socket"
                )
            if len(state) > MAX_ROOTFS_FILES:
                raise VerificationError("OCI rootfs contains too many files")


def _rootfs_manifest(state: dict[str, dict[str, Any]]) -> dict[str, Any]:
    entries = [state[path] for path in sorted(state)]
    aggregate = sum(
        item.get("size", 0)
        for item in entries
        if item["type"] == "file"
    )
    if aggregate > MAX_ROOTFS_BYTES:
        raise VerificationError("OCI rootfs exceeds its aggregate byte bound")
    payload = {
        "aggregateBytes": aggregate,
        "apiVersion": OCI_FILE_MANIFEST_VERSION,
        "entries": entries,
        "entryCount": len(entries),
    }
    return {**payload, "rootfsDigest": _sha256(_canonical_json(payload))}


def _validate_rootfs_symlink_closure(
    state: dict[str, dict[str, Any]],
) -> None:
    for path, entry in state.items():
        if entry["type"] != "symlink":
            continue
        resolved = list(PurePosixPath(path).parent.parts[1:])
        pending = entry["target"].split("/")
        if entry["target"].startswith("/"):
            resolved = []
            pending = entry["target"].lstrip("/").split("/")
        visited: set[str] = {path}
        hops = 0
        while pending:
            component = pending.pop(0)
            if component == "..":
                if not resolved:
                    raise VerificationError(
                        "OCI rootfs symlink escapes above the root"
                    )
                resolved.pop()
                continue
            candidate = "/" + "/".join([*resolved, component])
            target_entry = state.get(candidate)
            if target_entry is None:
                raise VerificationError(
                    "OCI rootfs symlink targets an unmeasured path"
                )
            if target_entry["type"] == "symlink":
                hops += 1
                if hops > 40 or candidate in visited:
                    raise VerificationError(
                        "OCI rootfs symlink closure contains a cycle or "
                        "exceeds its depth bound"
                    )
                visited.add(candidate)
                nested = target_entry["target"]
                if nested.startswith("/"):
                    resolved = []
                    pending = nested.lstrip("/").split("/") + pending
                else:
                    pending = nested.split("/") + pending
                continue
            resolved.append(component)
            if pending and target_entry["type"] != "directory":
                raise VerificationError(
                    "OCI rootfs symlink traverses a non-directory"
                )


def _sbom_file_id(path: str) -> str:
    return "SPDXRef-File-" + hashlib.sha256(path.encode("utf-8")).hexdigest()


def _validate_sbom(
    raw: bytes,
    *,
    rootfs: dict[str, Any],
    role: str,
    plan: dict[str, Any],
) -> str:
    document = _load_canonical_json_blob(raw, label=f"{role} SBOM")
    expected_plan = (
        plan["npmCompanion"]
        if role == "npm-publish-companion"
        else plan["lanes"][role.removeprefix("lane-")]
    )
    dependency = plan["dependencyBundle"]["bundles"][
        expected_plan["runtime"]["dependencyRole"]
    ]
    package_ids = {
        package["purl"]: "SPDXRef-Package-"
        + hashlib.sha256(package["purl"].encode("utf-8")).hexdigest()
        for package in dependency["packages"]
    }
    source_package_id = "SPDXRef-Package-FrozenSource"
    expected_packages = [
        {
            "SPDXID": package_ids[package["purl"]],
            "downloadLocation": "NOASSERTION",
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceLocator": package["purl"],
                    "referenceType": "purl",
                }
            ],
            "filesAnalyzed": True,
            "name": package["name"],
            "versionInfo": package["version"],
        }
        for package in dependency["packages"]
    ] + [
        {
            "SPDXID": source_package_id,
            "downloadLocation": "NOASSERTION",
            "externalRefs": [],
            "filesAnalyzed": True,
            "name": "catchplate-frozen-source",
            "versionInfo": plan["sourceSnapshot"]["sourceClosureSha256"],
        }
    ]
    if (
        not isinstance(document, dict)
        or set(document)
        != {
            "SPDXID",
            "creationInfo",
            "dataLicense",
            "documentNamespace",
            "files",
            "name",
            "packages",
            "relationships",
            "spdxVersion",
        }
        or document.get("SPDXID") != "SPDXRef-DOCUMENT"
        or document.get("dataLicense") != "CC0-1.0"
        or document.get("spdxVersion") != "SPDX-2.3"
        or document.get("name") != role
        or document.get("documentNamespace")
        != "urn:catchplate:"
        + role
        + ":"
        + rootfs["rootfsDigest"].removeprefix("sha256:")
        or document.get("creationInfo")
        != {
            "created": "1970-01-01T00:00:00Z",
            "creators": ["Tool: catchplate-oci-recorder-v2"],
        }
        or document.get("packages") != expected_packages
    ):
        raise VerificationError(f"{role} SBOM fields are invalid")
    expected = []
    for item in rootfs["entries"]:
        if item["type"] == "file":
            digest = item["sha256"]
            file_types: list[str] = []
        elif item["type"] == "symlink":
            digest = _sha256(item["target"].encode("utf-8"))
            file_types = ["OTHER"]
        else:
            continue
        record = {
            "SPDXID": _sbom_file_id(item["path"]),
            "checksums": [
                {
                    "algorithm": "SHA256",
                    "checksumValue": digest.removeprefix("sha256:"),
                }
            ],
            "fileName": item["path"],
        }
        if file_types:
            record["fileTypes"] = file_types
        expected.append(record)
    if document.get("files") != expected:
        raise VerificationError(f"{role} SBOM does not cover the exact rootfs files")
    ownership: dict[str, str] = {}
    rootfs_by_path = {item["path"]: item for item in rootfs["entries"]}
    for package in dependency["packages"]:
        for path in package["files"]:
            if rootfs_by_path[path]["type"] != "directory":
                ownership[path] = package_ids[package["purl"]]
    for source in expected_plan["sourceFiles"]:
        ownership["/opt/catchplate/src/" + source["path"]] = source_package_id
    rootfs_files = {
        item["path"]
        for item in rootfs["entries"]
        if item["type"] in {"file", "symlink"}
    }
    if set(ownership) != rootfs_files:
        raise VerificationError(f"{role} SBOM ownership is not rootfs-complete")
    described = sorted({*package_ids.values(), source_package_id})
    expected_relationships = [
        {
            "relatedSpdxElement": package_id,
            "relationshipType": "DESCRIBES",
            "spdxElementId": "SPDXRef-DOCUMENT",
        }
        for package_id in described
    ] + [
        {
            "relatedSpdxElement": _sbom_file_id(path),
            "relationshipType": "CONTAINS",
            "spdxElementId": ownership[path],
        }
        for path in sorted(ownership)
    ]
    if document.get("relationships") != expected_relationships:
        raise VerificationError(f"{role} SBOM relationships are incomplete")
    return _sha256(raw)


def _expected_rootfs_entries(
    *,
    role: str,
    expected_plan: dict[str, Any],
    dependency: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    expected: dict[str, dict[str, Any]] = {
        item["path"]: {**item, "xattrs": {}}
        for item in dependency["files"]
    }

    def require_directory(path: PurePosixPath) -> None:
        if str(path) == "/":
            return
        require_directory(path.parent)
        value = expected.get(str(path))
        if value is None:
            expected[str(path)] = {
                "gid": 0,
                "mode": 0o755,
                "path": str(path),
                "type": "directory",
                "uid": 0,
                "xattrs": {},
            }
        elif value["type"] != "directory":
            raise VerificationError(
                f"{role} source path collides with a non-directory dependency"
            )

    for installed in expected_plan["installedSourceFiles"]:
        source = installed["source"]
        image_path = installed["imagePath"]
        require_directory(PurePosixPath(image_path).parent)
        if image_path in expected:
            raise VerificationError(
                f"{role} source path collides with its dependency closure"
            )
        expected[image_path] = {
            "gid": 0,
            "mode": installed["mode"],
            "path": image_path,
            "sha256": source["sha256"],
            "size": source["size"],
            "type": "file",
            "uid": 0,
            "xattrs": {},
        }
    return expected


def _clean_room_normalized_name(value: str) -> str:
    if (
        not isinstance(value, str)
        or re.fullmatch(
            r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?",
            value,
        )
        is None
    ):
        raise VerificationError("clean-room package name is invalid")
    return re.sub(r"[-_.]+", "-", value).lower()


def _clean_room_install_path(member_name: str) -> str:
    relative = _safe_relative(
        member_name,
        label="clean-room wheel member",
    )
    parts = relative.parts
    if parts[0].endswith(".data"):
        if len(parts) < 3:
            raise VerificationError("clean-room wheel .data member is incomplete")
        category = parts[1]
        remainder = PurePosixPath(*parts[2:]).as_posix()
        if category in {"purelib", "platlib"}:
            return f"lib/python3.11/site-packages/{remainder}"
        if category == "scripts":
            return f"bin/{remainder}"
        if category == "data":
            return remainder
        raise VerificationError(
            "clean-room wheel uses an unsupported .data class"
        )
    return f"lib/python3.11/site-packages/{member_name}"


def _clean_room_console_script(target: str) -> bytes:
    match = re.fullmatch(
        r"([A-Za-z_][A-Za-z0-9_.]*):([A-Za-z_][A-Za-z0-9_]*)",
        target,
    )
    if match is None:
        raise VerificationError(
            "clean-room console-script target is invalid"
        )
    module, callable_name = match.groups()
    return (
        "#!/opt/catchplate/clean-room/python/bin/python3\n"
        "import re\n"
        "import sys\n"
        f"from {module} import {callable_name}\n"
        "if __name__ == '__main__':\n"
        "    sys.argv[0] = re.sub(r'(-script\\.pyw|\\.exe)?$', '', sys.argv[0])\n"
        f"    sys.exit({callable_name}())\n"
    ).encode("ascii")


def _independent_clean_room_wheel_derivation(
    *,
    content_state: dict[str, bytes],
    install_contract: dict[str, Any],
    wheelhouse_manifest: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    packages = wheelhouse_manifest.get("packages")
    if (
        not isinstance(packages, list)
        or not packages
        or install_contract.get("wheels")
        != [
            {"path": item.get("wheel"), "sha256": item.get("sha256")}
            for item in packages
            if isinstance(item, dict)
        ]
    ):
        raise VerificationError(
            "clean-room selected wheel inventory is not exact"
        )
    wheel_records: list[dict[str, Any]] = []
    installed: dict[str, dict[str, Any]] = {}
    for package in packages:
        if (
            not isinstance(package, dict)
            or set(package)
            != {
                "name",
                "normalizedName",
                "providesExtras",
                "requires",
                "sha256",
                "version",
                "wheel",
            }
            or not isinstance(package.get("wheel"), str)
        ):
            raise VerificationError(
                "clean-room wheelhouse package is invalid"
            )
        wheel_path = (
            "/opt/catchplate/clean-room/wheelhouse/" + package["wheel"]
        )
        filename = WHEEL_FILENAME_RE.fullmatch(package["wheel"])
        if filename is None:
            raise VerificationError(
                "clean-room wheel filename is not canonical"
            )
        filename_distribution = filename.group("distribution")
        filename_version = filename.group("version")
        expected_dist_info = (
            f"{filename_distribution}-{filename_version}.dist-info"
        )
        expected_data_root = (
            f"{filename_distribution}-{filename_version}.data"
        )
        expected_tags = sorted(
            {
                f"{python_tag}-{abi_tag}-{platform_tag}"
                for python_tag in filename.group("python").split(".")
                for abi_tag in filename.group("abi").split(".")
                for platform_tag in filename.group("platform").split(".")
            }
        )
        raw = content_state.get(wheel_path)
        if raw is None or _sha256(raw) != package.get("sha256"):
            raise VerificationError(
                "clean-room wheel bytes differ from their manifest"
            )
        try:
            archive = zipfile.ZipFile(io.BytesIO(raw), mode="r")
        except zipfile.BadZipFile as exc:
            raise VerificationError(
                "clean-room wheel is not a valid ZIP"
            ) from exc
        with archive:
            members = archive.infolist()
            names = [item.filename for item in members]
            if (
                not members
                or len(members) > CLEAN_ROOM_MAX_FILES
                or names != sorted(names)
                or len(names) != len(set(names))
            ):
                raise VerificationError(
                    "clean-room wheel member inventory is not canonical"
                )
            contents: dict[str, bytes] = {}
            aggregate = 0
            for member in members:
                relative = _safe_relative(
                    member.filename,
                    label="clean-room wheel member",
                )
                unix_mode = member.external_attr >> 16
                if (
                    relative.as_posix() != member.filename
                    or member.is_dir()
                    or member.flag_bits & 0x1
                    or member.file_size < 0
                    or member.file_size > CLEAN_ROOM_MAX_FILE_BYTES
                    or (
                        stat.S_IFMT(unix_mode)
                        and not stat.S_ISREG(unix_mode)
                    )
                    or (
                        relative.parts[0].endswith(".data")
                        and relative.parts[0] != expected_data_root
                    )
                ):
                    raise VerificationError(
                        "clean-room wheel member metadata is unsafe"
                    )
                content = archive.read(member)
                if len(content) != member.file_size:
                    raise VerificationError(
                        "clean-room wheel member size differs"
                    )
                aggregate += len(content)
                if aggregate > CLEAN_ROOM_MAX_TOTAL_BYTES:
                    raise VerificationError(
                        "clean-room wheel content exceeds its bound"
                    )
                contents[member.filename] = content
            record_names = [
                name
                for name in names
                if name.endswith(".dist-info/RECORD")
            ]
            metadata_names = [
                name
                for name in names
                if name.endswith(".dist-info/METADATA")
            ]
            wheel_metadata_names = [
                name
                for name in names
                if name.endswith(".dist-info/WHEEL")
            ]
            if (
                record_names != [f"{expected_dist_info}/RECORD"]
                or metadata_names != [f"{expected_dist_info}/METADATA"]
                or wheel_metadata_names
                != [f"{expected_dist_info}/WHEEL"]
            ):
                raise VerificationError(
                    "clean-room wheel metadata roots are ambiguous"
                )
            try:
                rows = list(
                    csv.reader(
                        io.StringIO(
                            contents[record_names[0]].decode("utf-8")
                        )
                    )
                )
            except UnicodeError as exc:
                raise VerificationError(
                    "clean-room wheel RECORD is not UTF-8"
                ) from exc
            record_entries: dict[str, tuple[str, str]] = {}
            for row in rows:
                if len(row) != 3:
                    raise VerificationError(
                        "clean-room wheel RECORD row is malformed"
                    )
                path = _safe_relative(
                    row[0],
                    label="clean-room wheel RECORD path",
                ).as_posix()
                if path != row[0] or path in record_entries:
                    raise VerificationError(
                        "clean-room wheel RECORD path is not canonical"
                    )
                record_entries[path] = (row[1], row[2])
            if set(record_entries) != set(contents):
                raise VerificationError(
                    "clean-room wheel RECORD inventory is incomplete"
                )
            for name, content in contents.items():
                encoded_hash, encoded_size = record_entries[name]
                if name == record_names[0]:
                    if encoded_hash or encoded_size:
                        raise VerificationError(
                            "clean-room RECORD self-row is not empty"
                        )
                    continue
                if (
                    re.fullmatch(
                        r"sha256=[A-Za-z0-9_-]{43}",
                        encoded_hash,
                    )
                    is None
                    or encoded_size != str(len(content))
                ):
                    raise VerificationError(
                        "clean-room RECORD member identity is invalid"
                    )
                try:
                    recorded = base64.urlsafe_b64decode(
                        encoded_hash.removeprefix("sha256=") + "="
                    )
                except (ValueError, binascii.Error) as exc:
                    raise VerificationError(
                        "clean-room RECORD digest is invalid"
                    ) from exc
                if recorded != hashlib.sha256(content).digest():
                    raise VerificationError(
                        "clean-room RECORD digest differs from member bytes"
                    )
            metadata = email.parser.BytesParser(
                policy=email.policy.default
            ).parsebytes(contents[metadata_names[0]])
            package_names = metadata.get_all("Name", [])
            package_versions = metadata.get_all("Version", [])
            if len(package_names) != 1 or len(package_versions) != 1:
                raise VerificationError(
                    "clean-room wheel identity metadata is ambiguous"
                )
            package_name = package_names[0]
            package_version = package_versions[0]
            requires = sorted(metadata.get_all("Requires-Dist", []))
            provides_extras = sorted(
                {
                    _clean_room_normalized_name(item)
                    for item in metadata.get_all("Provides-Extra", [])
                }
            )
            normalized_name = _clean_room_normalized_name(package_name)
            if (
                not isinstance(package_version, str)
                or not package_version
                or normalized_name
                != _clean_room_normalized_name(filename_distribution)
                or package_version != filename_version
                or any(not isinstance(item, str) or not item for item in requires)
            ):
                raise VerificationError(
                    "clean-room wheel core metadata is invalid"
                )
            wheel_metadata = email.parser.BytesParser(
                policy=email.policy.default
            ).parsebytes(contents[wheel_metadata_names[0]])
            wheel_versions = wheel_metadata.get_all("Wheel-Version", [])
            purelib_values = wheel_metadata.get_all(
                "Root-Is-Purelib",
                [],
            )
            declared_tags = sorted(wheel_metadata.get_all("Tag", []))
            if (
                wheel_versions != ["1.0"]
                or purelib_values != ["true"]
                or declared_tags != expected_tags
                or len(declared_tags) != len(set(declared_tags))
            ):
                raise VerificationError(
                    "clean-room WHEEL metadata differs from its filename"
                )
            record = {
                "memberCount": len(names),
                "name": package_name,
                "normalizedName": normalized_name,
                "providesExtras": provides_extras,
                "recordSha256": _sha256(contents[record_names[0]]),
                "recordPath": record_names[0],
                "requires": requires,
                "sha256": package["sha256"],
                "version": package_version,
                "wheel": package["wheel"],
            }
            if any(
                record[key] != package[key]
                for key in (
                    "name",
                    "normalizedName",
                    "providesExtras",
                    "requires",
                    "version",
                    "wheel",
                )
            ):
                raise VerificationError(
                    "clean-room wheel metadata differs from wheelhouse manifest"
                )
            wheel_records.append(record)
            for name, content in contents.items():
                destination = _clean_room_install_path(name)
                mode = (
                    0o555
                    if archive.getinfo(name).external_attr >> 16 & 0o111
                    else 0o444
                )
                if destination in installed:
                    raise VerificationError(
                        "clean-room wheel install paths collide"
                    )
                installed[destination] = {
                    "gid": 0,
                    "mode": mode,
                    "path": destination,
                    "sha256": _sha256(content),
                    "size": len(content),
                    "type": "file",
                    "uid": 0,
                }
            entry_points = [
                name
                for name in names
                if name.endswith(".dist-info/entry_points.txt")
            ]
            if len(entry_points) > 1:
                raise VerificationError(
                    "clean-room wheel entry points are ambiguous"
                )
            if entry_points:
                if entry_points != [
                    f"{expected_dist_info}/entry_points.txt"
                ]:
                    raise VerificationError(
                        "clean-room entry points use the wrong metadata root"
                    )
                parser = configparser.ConfigParser(
                    interpolation=None,
                    strict=True,
                )
                parser.optionxform = str
                try:
                    parser.read_string(
                        contents[entry_points[0]].decode("ascii")
                    )
                except (UnicodeError, configparser.Error) as exc:
                    raise VerificationError(
                        "clean-room wheel entry points are invalid"
                    ) from exc
                if set(parser.sections()) - {"console_scripts"}:
                    raise VerificationError(
                        "clean-room wheel has unsupported entry points"
                    )
                scripts = (
                    parser.items("console_scripts")
                    if parser.has_section("console_scripts")
                    else []
                )
                for script_name, target in sorted(scripts):
                    if (
                        re.fullmatch(
                            r"[A-Za-z0-9][A-Za-z0-9._+-]{0,254}",
                            script_name,
                        )
                        is None
                    ):
                        raise VerificationError(
                            "clean-room console-script name is invalid"
                        )
                    script = _clean_room_console_script(target.strip())
                    destination = f"bin/{script_name}"
                    if destination in installed:
                        raise VerificationError(
                            "clean-room generated script path collides"
                        )
                    installed[destination] = {
                        "gid": 0,
                        "mode": 0o555,
                        "path": destination,
                        "sha256": _sha256(script),
                        "size": len(script),
                        "type": "file",
                        "uid": 0,
                    }
    directories: set[str] = set()
    for path in installed:
        parent = PurePosixPath(path).parent
        while parent.parts:
            directories.add(parent.as_posix())
            parent = parent.parent
    derived_entries = [
        {
            "gid": 0,
            "mode": 0o555,
            "path": path,
            "type": "directory",
            "uid": 0,
        }
        for path in sorted(directories)
    ]
    derived_entries.extend(installed[path] for path in sorted(installed))
    return (
        sorted(wheel_records, key=lambda item: item["normalizedName"]),
        sorted(derived_entries, key=lambda item: item["path"]),
    )


def _validate_clean_room_image_semantics(
    *,
    content_state: dict[str, bytes],
    rootfs_entries: list[dict[str, Any]],
    semantic_contract: dict[str, Any],
) -> None:
    semantic_contract = _validate_clean_room_semantic_contract(
        semantic_contract
    )
    documents = {}
    for name, path in (
        (
            "install",
            "/opt/catchplate/clean-room/package-install-contract.json",
        ),
        (
            "payload",
            "/opt/catchplate/clean-room/payload-manifest.json",
        ),
        (
            "wheelhouse",
            (
                "/opt/catchplate/clean-room/wheelhouse/"
                "wheelhouse-manifest.json"
            ),
        ),
    ):
        raw = content_state.get(path)
        if raw is None:
            raise VerificationError(
                f"clean-room image omits its {name} manifest"
            )
        if not raw.endswith(b"\n"):
            raise VerificationError(
                f"clean-room {name} manifest is not newline terminated"
            )
        documents[name] = _load_canonical_json_blob(
            raw[:-1],
            label=f"clean-room {name} manifest",
        )
        if raw != _canonical_json(documents[name]) + b"\n":
            raise VerificationError(
                f"clean-room {name} manifest is not canonical"
            )
    install = documents["install"]
    wheelhouse = documents["wheelhouse"]
    payload_manifest = documents["payload"]
    if (
        set(install)
        != {
            "apiVersion",
            "contractSha256",
            "dependencies",
            "exerciseScenarios",
            "generatedArtifacts",
            "markerEnvironment",
            "requestedExtras",
            "requirementsResolution",
            "wheels",
        }
        or install.get("apiVersion")
        != "catchplate.cleanRoomInstallContract/v5"
        or install.get("markerEnvironment")
        != CLEAN_ROOM_MARKER_ENVIRONMENT
        or not all(
            isinstance(install.get(key), expected_type)
            for key, expected_type in (
                ("dependencies", list),
                ("exerciseScenarios", list),
                ("generatedArtifacts", list),
                ("requestedExtras", dict),
                ("requirementsResolution", list),
                ("wheels", list),
            )
        )
    ):
        raise VerificationError(
            "clean-room install contract schema is invalid"
        )
    install_payload = dict(install)
    if install_payload.pop("contractSha256", None) != _sha256(
        _canonical_json(install_payload)
    ):
        raise VerificationError(
            "clean-room install contract digest is invalid"
        )
    if (
        set(wheelhouse)
        != {
            "apiVersion",
            "files",
            "packages",
            "payloadSha256",
            "schemaSha256",
        }
        or wheelhouse.get("apiVersion")
        != "catchplate.cleanRoomWheelhouseManifest/v3"
        or wheelhouse.get("schemaSha256")
        != _sha256(_canonical_json(CLEAN_ROOM_WHEELHOUSE_SCHEMA))
        or not isinstance(wheelhouse.get("files"), list)
        or not isinstance(wheelhouse.get("packages"), list)
    ):
        raise VerificationError(
            "clean-room wheelhouse manifest schema is invalid"
        )
    wheelhouse_payload = dict(wheelhouse)
    if wheelhouse_payload.pop("payloadSha256", None) != _sha256(
        _canonical_json(wheelhouse_payload)
    ):
        raise VerificationError(
            "clean-room wheelhouse manifest digest is invalid"
        )
    wheelhouse_prefix = "/opt/catchplate/clean-room/wheelhouse/"
    checksum_path = wheelhouse_prefix + "SHA256SUMS"
    checksum_raw = content_state.get(checksum_path)
    if checksum_raw is None:
        raise VerificationError("clean-room wheelhouse checksums are missing")
    try:
        checksum_text = checksum_raw.decode("ascii")
    except UnicodeError as exc:
        raise VerificationError(
            "clean-room wheelhouse checksums are not ASCII"
        ) from exc
    if (
        not checksum_text
        or not checksum_text.endswith("\n")
        or "\r" in checksum_text
    ):
        raise VerificationError(
            "clean-room wheelhouse checksums are not canonical LF text"
        )
    checksums: dict[str, str] = {}
    for line in checksum_text[:-1].split("\n"):
        match = re.fullmatch(
            r"([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._+/-]*)",
            line,
        )
        if match is None:
            raise VerificationError(
                "clean-room wheelhouse checksum line is malformed"
            )
        relative = _safe_relative(
            match.group(2),
            label="clean-room wheelhouse checksum path",
        ).as_posix()
        content = content_state.get(wheelhouse_prefix + relative)
        if (
            relative in checksums
            or content is None
            or hashlib.sha256(content).hexdigest() != match.group(1)
        ):
            raise VerificationError(
                "clean-room wheelhouse checksum differs from file bytes"
            )
        checksums[relative] = "sha256:" + match.group(1)
    checksummed_files = {
        path.removeprefix(wheelhouse_prefix)
        for path in content_state
        if path.startswith(wheelhouse_prefix) and path != checksum_path
    }
    if (
        set(checksums) != checksummed_files
        or list(checksums) != sorted(checksums)
    ):
        raise VerificationError(
            "clean-room wheelhouse checksum inventory is not exact"
        )
    package_wheels: set[str] = set()
    package_names: set[str] = set()
    expected_wheel_files: list[dict[str, Any]] = []
    for package in wheelhouse["packages"]:
        normalized = (
            _clean_room_normalized_name(package.get("name"))
            if isinstance(package, dict)
            else ""
        )
        if (
            not isinstance(package, dict)
            or set(package)
            != {
                "name",
                "normalizedName",
                "providesExtras",
                "requires",
                "sha256",
                "version",
                "wheel",
            }
            or package.get("normalizedName") != normalized
            or normalized in package_names
            or not isinstance(package.get("version"), str)
            or not package["version"]
            or not isinstance(package.get("wheel"), str)
            or WHEEL_FILENAME_RE.fullmatch(package["wheel"]) is None
            or package["wheel"] in package_wheels
            or package.get("sha256") != checksums.get(package["wheel"])
            or not isinstance(package.get("requires"), list)
            or package["requires"] != sorted(set(package["requires"]))
            or any(
                not isinstance(item, str) or not item
                for item in package["requires"]
            )
            or not isinstance(package.get("providesExtras"), list)
            or package["providesExtras"]
            != sorted(set(package["providesExtras"]))
            or any(
                _clean_room_normalized_name(item) != item
                for item in package["providesExtras"]
            )
        ):
            raise VerificationError(
                "clean-room wheelhouse package is invalid"
            )
        wheel_path = (
            "/opt/catchplate/clean-room/wheelhouse/" + package["wheel"]
        )
        wheel_bytes = content_state.get(wheel_path)
        if (
            wheel_bytes is None
            or package.get("sha256") != _sha256(wheel_bytes)
        ):
            raise VerificationError(
                "clean-room wheelhouse package bytes differ"
            )
        package_wheels.add(package["wheel"])
        package_names.add(normalized)
        expected_wheel_files.append(
            {
                "path": package["wheel"],
                "sha256": package["sha256"],
                "size": len(wheel_bytes),
            }
        )
    if (
        wheelhouse["packages"]
        != sorted(
            wheelhouse["packages"],
            key=lambda item: item["normalizedName"],
        )
        or wheelhouse["files"]
        != sorted(expected_wheel_files, key=lambda item: item["path"])
        or package_wheels
        != {
            path.removeprefix(wheelhouse_prefix)
            for path in content_state
            if path.startswith(wheelhouse_prefix)
            and path.endswith(".whl")
        }
    ):
        raise VerificationError(
            "clean-room wheelhouse inventory is not exact"
        )
    payload_prefix = "/opt/catchplate/clean-room/"
    payload_manifest_path = payload_prefix + "payload-manifest.json"
    payload_entries: list[dict[str, Any]] = []
    for item in rootfs_entries:
        if (
            not item["path"].startswith(payload_prefix)
            or item["path"] == payload_manifest_path
        ):
            continue
        relative = item["path"].removeprefix(payload_prefix)
        payload_entry = {
            key: value
            for key, value in item.items()
            if key != "xattrs"
        }
        payload_entry["path"] = relative
        payload_entries.append(payload_entry)
    payload_entries.sort(key=lambda item: item["path"])
    expected_payload = {
        "apiVersion": "catchplate.cleanRoomPayloadManifest/v1",
        "entries": payload_entries,
        "excluded": ["payload-manifest.json"],
    }
    if (
        set(payload_manifest)
        != {"apiVersion", "closureSha256", "entries", "excluded"}
        or payload_manifest.get("apiVersion")
        != "catchplate.cleanRoomPayloadManifest/v1"
        or payload_manifest.get("entries") != payload_entries
        or payload_manifest.get("excluded") != ["payload-manifest.json"]
        or payload_manifest.get("closureSha256")
        != _sha256(_canonical_json(expected_payload))
    ):
        raise VerificationError(
            "clean-room payload manifest differs from measured rootfs"
        )
    if (
        install.get("contractSha256")
        != semantic_contract["installContractSha256"]
        or install.get("requirementsResolution")
        != semantic_contract["requirementsResolution"]
        or install.get("exerciseScenarios")
        != semantic_contract["exerciseScenarios"]
        or payload_manifest.get("closureSha256")
        != semantic_contract["payloadClosureSha256"]
        or wheelhouse.get("payloadSha256")
        != semantic_contract["wheelhouseManifestPayloadSha256"]
    ):
        raise VerificationError(
            "clean-room manifests differ from the expected derivation"
        )
    wheel_records, derived_entries = (
        _independent_clean_room_wheel_derivation(
            content_state=content_state,
            install_contract=install,
            wheelhouse_manifest=wheelhouse,
        )
    )
    if (
        wheel_records != semantic_contract["wheelRecords"]
        or _sha256(_canonical_json(wheel_records))
        != semantic_contract["wheelRecordsSha256"]
        or derived_entries != semantic_contract["derivedEntries"]
        or _sha256(_canonical_json(derived_entries))
        != semantic_contract["derivedInstallationSha256"]
    ):
        raise VerificationError(
            "clean-room independent wheel/RECORD derivation differs"
        )
    prefix = "/opt/catchplate/clean-room/installed/"
    observed_entries = []
    for item in rootfs_entries:
        if not item["path"].startswith(prefix):
            continue
        observed = {
            key: value
            for key, value in item.items()
            if key != "xattrs"
        }
        observed["path"] = item["path"].removeprefix(prefix)
        observed_entries.append(observed)
    observed_entries.sort(key=lambda item: item["path"])
    if observed_entries != semantic_contract["derivedEntries"]:
        raise VerificationError(
            "clean-room installed tree differs from its wheel derivation"
        )


def _measure_oci_image(
    *,
    role: str,
    record: dict[str, Any],
    plan: dict[str, Any],
    oci_root: Path,
) -> dict[str, Any]:
    if (
        not isinstance(record, dict)
        or set(record)
        != {
            "archive",
            "fileManifest",
            "role",
            "sbom",
        }
        or record.get("role") != role
    ):
        raise VerificationError(f"{role} bundle record is invalid")
    archive_relative = _safe_relative(record["archive"], label="OCI archive")
    file_manifest_relative = _safe_relative(
        record["fileManifest"], label="OCI file manifest"
    )
    sbom_relative = _safe_relative(record["sbom"], label="OCI SBOM")
    archive_path = oci_root / archive_relative
    file_manifest_path = oci_root / file_manifest_relative
    sbom_path = oci_root / sbom_relative
    root_fd, root_before = _open_safe_root(oci_root, label="OCI output root")
    files, archive_identity = _read_oci_archive(
        archive_path,
        root_fd=root_fd,
        relative=archive_relative,
    )
    if set(files) < {"index.json", "oci-layout"}:
        raise VerificationError(f"{role} OCI archive is incomplete")
    layout = _load_canonical_json_blob(
        files["oci-layout"], label=f"{role} OCI layout"
    )
    index = _load_canonical_json_blob(
        files["index.json"], label=f"{role} OCI index"
    )
    if layout != {"imageLayoutVersion": "1.0.0"}:
        raise VerificationError(f"{role} OCI layout version is invalid")
    if (
        not isinstance(index, dict)
        or set(index) != {"manifests", "schemaVersion"}
        or index.get("schemaVersion") != 2
        or not isinstance(index.get("manifests"), list)
        or len(index["manifests"]) != 1
    ):
        raise VerificationError(f"{role} OCI index is ambiguous")
    manifest_descriptor = _descriptor(
        index["manifests"][0],
        label=f"{role} manifest",
        media_type=OCI_MANIFEST_MEDIA_TYPE,
        platform={"architecture": "amd64", "os": "linux"},
    )
    manifest_raw = _blob(files, manifest_descriptor, label=f"{role} manifest")
    manifest = _load_canonical_json_blob(
        manifest_raw, label=f"{role} OCI manifest"
    )
    if (
        not isinstance(manifest, dict)
        or set(manifest) != {"config", "layers", "mediaType", "schemaVersion"}
        or manifest.get("schemaVersion") != 2
        or manifest.get("mediaType") != OCI_MANIFEST_MEDIA_TYPE
        or not isinstance(manifest.get("layers"), list)
        or len(manifest["layers"]) != 1
    ):
        raise VerificationError(f"{role} OCI manifest fields are invalid")
    config_descriptor = _descriptor(
        manifest["config"],
        label=f"{role} config",
        media_type=OCI_CONFIG_MEDIA_TYPE,
    )
    layer_descriptors = [
        _descriptor(item, label=f"{role} layer", media_type=OCI_LAYER_MEDIA_TYPE)
        for item in manifest["layers"]
    ]
    allowed_blob_names = {
        _blob_name(manifest_descriptor["digest"]),
        _blob_name(config_descriptor["digest"]),
        *(_blob_name(item["digest"]) for item in layer_descriptors),
    }
    actual_blob_names = {name for name in files if name.startswith("blobs/")}
    if (
        actual_blob_names != allowed_blob_names
        or set(files) != {"index.json", "oci-layout", *allowed_blob_names}
    ):
        raise VerificationError(f"{role} OCI archive has missing or extra blobs")
    config_raw = _blob(files, config_descriptor, label=f"{role} config")
    config = _load_canonical_json_blob(config_raw, label=f"{role} OCI config")
    if (
        not isinstance(config, dict)
        or set(config)
        != {
            "architecture",
            "config",
            "created",
            "history",
            "os",
            "rootfs",
        }
        or config.get("architecture") != "amd64"
        or config.get("os") != "linux"
        or config.get("created") != "1970-01-01T00:00:00Z"
        or config.get("history")
        != [
            {
                "created": "1970-01-01T00:00:00Z",
                "created_by": "catchplate-oci-builder-v4:rootfs",
                "empty_layer": False,
            }
        ]
    ):
        raise VerificationError(f"{role} OCI config is not deterministic")
    expected_plan = (
        plan["npmCompanion"]
        if role == "npm-publish-companion"
        else plan["lanes"][role.removeprefix("lane-")]
    )
    process = expected_plan["process"]
    expected_config = {
        "Cmd": process["argv"],
        "Entrypoint": process["entrypoint"],
        "Env": [
            f"{name}={value}"
            for name, value in sorted(process["environment"].items())
        ],
        "User": f"{process['uid']}:{process['gid']}",
        "WorkingDir": process["cwd"],
    }
    if config.get("config") != expected_config:
        raise VerificationError(f"{role} OCI process config differs from the plan")
    rootfs = config.get("rootfs")
    if (
        not isinstance(rootfs, dict)
        or set(rootfs) != {"diff_ids", "type"}
        or rootfs.get("type") != "layers"
        or not isinstance(rootfs.get("diff_ids"), list)
        or len(rootfs["diff_ids"]) != len(layer_descriptors)
    ):
        raise VerificationError(f"{role} OCI rootfs config is invalid")
    state: dict[str, dict[str, Any]] = {}
    content_state: dict[str, bytes] = {}
    measured_diff_ids: list[str] = []
    for descriptor, expected_diff_id in zip(
        layer_descriptors,
        rootfs["diff_ids"],
        strict=True,
    ):
        layer_raw = _blob(files, descriptor, label=f"{role} layer")
        uncompressed = _decompress_layer(layer_raw)
        diff_id = _sha256(uncompressed)
        if diff_id != expected_diff_id:
            raise VerificationError(f"{role} OCI layer diff ID is invalid")
        measured_diff_ids.append(diff_id)
        _apply_layer(state, uncompressed, content_state)
    _validate_rootfs_symlink_closure(state)
    if sum(not item["empty_layer"] for item in config["history"]) != len(
        measured_diff_ids
    ):
        raise VerificationError(f"{role} OCI history/layer count differs")
    measured_rootfs = _rootfs_manifest(state)
    rootfs_paths = {item["path"]: item for item in measured_rootfs["entries"]}
    expected_dependency = plan["dependencyBundle"]["bundles"][
        expected_plan["runtime"]["dependencyRole"]
    ]
    expected_entries = _expected_rootfs_entries(
        role=role,
        expected_plan=expected_plan,
        dependency=expected_dependency,
    )
    if rootfs_paths != expected_entries:
        raise VerificationError(
            f"{role} rootfs differs from its complete typed allowlist"
        )
    dependency_paths = {item["path"] for item in expected_dependency["files"]}
    measured_dependency_executables = [
        {
            "path": item["path"],
            "sha256": item["sha256"],
        }
        for item in measured_rootfs["entries"]
        if (
            item["path"] in dependency_paths
            and item["type"] == "file"
            and item["mode"] & 0o111
        )
    ]
    catalog = expected_dependency["capabilityCatalog"]
    catalog_executables = [
        {"path": item["path"], "sha256": item["sha256"]}
        for item in catalog["executables"]
    ]
    if measured_dependency_executables != catalog_executables:
        raise VerificationError(
            f"{role} executable inventory differs from its capability catalog"
        )
    source_executables = {
        item["path"]
        for item in measured_rootfs["entries"]
        if (
            item["path"].startswith("/opt/catchplate/src/")
            and item["type"] == "file"
            and item["mode"] & 0o111
        )
    }
    expected_source_executables: set[str] = set()
    if source_executables != expected_source_executables:
        raise VerificationError(
            f"{role} source closure exposes an unexpected executable"
        )
    if (
        role == "lane-portal-browser-oauth"
        and (
            catalog["forbiddenCapabilityClasses"]
            != sorted(PORTAL_FORBIDDEN_CAPABILITY_CLASSES)
            or set(catalog["allowedCapabilityClasses"])
            & PORTAL_FORBIDDEN_CAPABILITY_CLASSES
        )
    ):
        raise VerificationError(
            "portal dependency capability catalog permits a forbidden tool"
        )
    if role == "lane-clean-room":
        _validate_clean_room_image_semantics(
            content_state=content_state,
            rootfs_entries=measured_rootfs["entries"],
            semantic_contract=expected_dependency["semanticContract"],
        )
    if role == "npm-publish-companion":
        required_npm_paths = {
            NPM_ENTRYPOINT_IMAGE,
            "/opt/catchplate/npm/bin/npm-cli.js",
            "/opt/catchplate/node/bin/node",
        }
        if not required_npm_paths.issubset(rootfs_paths):
            raise VerificationError(
                "npm companion image omits its exact Node/npm entrypoints"
            )
    entrypoint_path = expected_plan["process"]["entrypoint"][0]
    entrypoint_record = rootfs_paths.get(entrypoint_path)
    if (
        entrypoint_record is None
        or entrypoint_record["type"] != "file"
        or not entrypoint_record["mode"] & 0o111
    ):
        raise VerificationError(f"{role} fixed entrypoint is not executable")
    installed_source = (
        None
        if role == "lane-rust-decision-gate-tests"
        else next(
            (
                item
                for item in expected_plan["sourceFiles"]
                if item["path"]
                == (
                    NPM_ENTRYPOINT_SOURCE
                    if role == "npm-publish-companion"
                    else PYTHON_ENTRYPOINT_SOURCE
                )
            ),
            None,
        )
    )
    installed_path = (
        NPM_ENTRYPOINT_IMAGE
        if role == "npm-publish-companion"
        else PYTHON_ENTRYPOINT_IMAGE
    )
    if installed_source is not None:
        installed_record = rootfs_paths.get(installed_path)
        if (
            installed_record is None
            or installed_record["type"] != "file"
            or installed_record["sha256"] != installed_source["sha256"]
            or installed_record["size"] != installed_source["size"]
        ):
            raise VerificationError(
                f"{role} installed entrypoint bytes differ from tracked source"
            )
    file_manifest_raw, _ = _read_regular_at(
        root_fd,
        file_manifest_relative,
        label=f"{role} rootfs file manifest",
    )
    if _load_canonical_json_blob(
        file_manifest_raw,
        label=f"{role} rootfs file manifest",
    ) != measured_rootfs:
        raise VerificationError(f"{role} rootfs file manifest differs")
    sbom_raw, _ = _read_regular_at(
        root_fd,
        sbom_relative,
        label=f"{role} SBOM",
    )
    root_after = os.fstat(root_fd)
    os.close(root_fd)
    if (
        root_before.st_dev,
        root_before.st_ino,
        root_before.st_mode,
        root_before.st_uid,
        root_before.st_gid,
    ) != (
        root_after.st_dev,
        root_after.st_ino,
        root_after.st_mode,
        root_after.st_uid,
        root_after.st_gid,
    ):
        raise VerificationError("OCI output root changed during measurement")
    sbom_sha256 = _validate_sbom(
        sbom_raw,
        rootfs=measured_rootfs,
        role=role,
        plan=plan,
    )
    fixed_tool_identities = None
    if role == "npm-publish-companion":
        fixed_tool_identities = {}
        for name, path in (
            ("node", "/opt/catchplate/node/bin/node"),
            ("npmEntrypoint", "/opt/catchplate/npm/bin/npm-cli.js"),
            ("npmPackageManifest", "/opt/catchplate/npm/package.json"),
        ):
            item = rootfs_paths.get(path)
            if item is None or item["type"] != "file":
                raise VerificationError(
                    f"npm companion omits its fixed {name} file"
                )
            fixed_tool_identities[name] = {
                "path": path,
                "sha256": item["sha256"],
                "size": item["size"],
            }
    return {
        "archive": archive_identity,
        "build": expected_plan["build"],
        "capabilityAttestation": plan["dependencyBundle"][
            "capabilityAttestation"
        ],
        "capabilityCatalog": expected_dependency["capabilityCatalog"],
        "capabilityCatalogSha256": expected_dependency[
            "capabilityCatalogSha256"
        ],
        "configDigest": config_descriptor["digest"],
        "dependencyClosureSha256": expected_dependency["closureSha256"],
        "dependencyFileManifestSha256": expected_dependency[
            "fileManifestSha256"
        ],
        "dependencyPackageInventorySha256": _sha256(
            _canonical_json(expected_dependency["packages"])
        ),
        "dependencyRole": expected_plan["runtime"]["dependencyRole"],
        "executableInventorySha256": _sha256(
            _canonical_json(measured_dependency_executables)
        ),
        "fileManifest": {
            "path": str(file_manifest_path),
            "sha256": _sha256(file_manifest_raw),
        },
        "fixedToolIdentities": fixed_tool_identities,
        "indexDigest": _sha256(files["index.json"]),
        "layerDigests": [item["digest"] for item in layer_descriptors],
        "manifestDigest": manifest_descriptor["digest"],
        "platform": {"architecture": "amd64", "os": "linux"},
        "role": role,
        "rootfsDiffIds": measured_diff_ids,
        "rootfsDigest": measured_rootfs["rootfsDigest"],
        "sbom": {"path": str(sbom_path), "sha256": sbom_sha256},
        "semanticContract": expected_dependency["semanticContract"],
    }


def _ed25519_add(
    left: tuple[int, int, int, int],
    right: tuple[int, int, int, int],
) -> tuple[int, int, int, int]:
    x1, y1, z1, t1 = left
    x2, y2, z2, t2 = right
    a = ((y1 - x1) * (y2 - x2)) % ED25519_FIELD
    b = ((y1 + x1) * (y2 + x2)) % ED25519_FIELD
    c = (2 * ED25519_D * t1 * t2) % ED25519_FIELD
    d = (2 * z1 * z2) % ED25519_FIELD
    e = (b - a) % ED25519_FIELD
    f = (d - c) % ED25519_FIELD
    g = (d + c) % ED25519_FIELD
    h = (b + a) % ED25519_FIELD
    return (
        e * f % ED25519_FIELD,
        g * h % ED25519_FIELD,
        f * g % ED25519_FIELD,
        e * h % ED25519_FIELD,
    )


def _ed25519_double(
    point: tuple[int, int, int, int],
) -> tuple[int, int, int, int]:
    x, y, z, _ = point
    a = x * x % ED25519_FIELD
    b = y * y % ED25519_FIELD
    c = 2 * z * z % ED25519_FIELD
    d = -a % ED25519_FIELD
    e = ((x + y) * (x + y) - a - b) % ED25519_FIELD
    g = (d + b) % ED25519_FIELD
    f = (g - c) % ED25519_FIELD
    h = (d - b) % ED25519_FIELD
    return (
        e * f % ED25519_FIELD,
        g * h % ED25519_FIELD,
        f * g % ED25519_FIELD,
        e * h % ED25519_FIELD,
    )


def _ed25519_multiply(
    point: tuple[int, int, int, int],
    scalar: int,
) -> tuple[int, int, int, int]:
    if scalar < 0:
        raise VerificationError("Ed25519 scalar is negative")
    result = ED25519_IDENTITY
    addend = point
    while scalar:
        if scalar & 1:
            result = _ed25519_add(result, addend)
        addend = _ed25519_double(addend)
        scalar >>= 1
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
    x = point[0] * inverse % ED25519_FIELD
    y = point[1] * inverse % ED25519_FIELD
    encoded = bytearray(y.to_bytes(32, "little"))
    encoded[31] |= (x & 1) << 7
    return bytes(encoded)


def _ed25519_decode(
    encoded: bytes,
    *,
    label: str,
) -> tuple[int, int, int, int]:
    if len(encoded) != 32:
        raise VerificationError(f"{label} is not 32 bytes")
    sign = encoded[31] >> 7
    y = int.from_bytes(encoded, "little") & ((1 << 255) - 1)
    if y >= ED25519_FIELD:
        raise VerificationError(f"{label} is not canonical")
    y_squared = y * y % ED25519_FIELD
    denominator = (ED25519_D * y_squared + 1) % ED25519_FIELD
    if denominator == 0:
        raise VerificationError(f"{label} is not on the curve")
    x_squared = (
        (y_squared - 1)
        * pow(denominator, ED25519_FIELD - 2, ED25519_FIELD)
    ) % ED25519_FIELD
    x = pow(x_squared, (ED25519_FIELD + 3) // 8, ED25519_FIELD)
    if (x * x - x_squared) % ED25519_FIELD:
        x = x * ED25519_SQRT_M1 % ED25519_FIELD
    if (x * x - x_squared) % ED25519_FIELD:
        raise VerificationError(f"{label} is not on the curve")
    if (x & 1) != sign:
        x = -x % ED25519_FIELD
    if x == 0 and sign:
        raise VerificationError(f"{label} has a noncanonical sign bit")
    point = (x, y, 1, x * y % ED25519_FIELD)
    if (
        _ed25519_encode(point) != encoded
        or _ed25519_equal(_ed25519_multiply(point, 8), ED25519_IDENTITY)
        or not _ed25519_equal(
            _ed25519_multiply(point, ED25519_ORDER),
            ED25519_IDENTITY,
        )
    ):
        raise VerificationError(f"{label} is outside the prime-order subgroup")
    return point


def _verify_ed25519(
    *,
    public_key: bytes,
    signature: bytes,
    message: bytes,
) -> None:
    if len(signature) != 64:
        raise VerificationError("build-watchdog signature is not 64 bytes")
    public_point = _ed25519_decode(
        public_key, label="build-watchdog public key"
    )
    encoded_r = signature[:32]
    r_point = _ed25519_decode(encoded_r, label="build-watchdog signature R")
    scalar = int.from_bytes(signature[32:], "little")
    if scalar >= ED25519_ORDER:
        raise VerificationError("build-watchdog signature scalar is invalid")
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
        _ed25519_add(
            r_point,
            _ed25519_multiply(public_point, challenge),
        ),
    ):
        raise VerificationError("build-watchdog receipt signature is invalid")


def _resource_ref(resource: dict[str, Any]) -> dict[str, str]:
    return {"id": resource["id"], "kind": resource["kind"]}


def _load_build_watchdog_receipt(
    path: Path,
    *,
    plan: dict[str, Any],
    bundle: dict[str, Any],
    image_roles: list[str],
    public_key_path: Path,
    expected_key_spki_sha256: str,
    expected_key_raw_sha256: str,
    expected_challenge_sha256: str,
    expected_capability_sha256: str,
) -> dict[str, Any]:
    for label, value in (
        ("build-watchdog SPKI key pin", expected_key_spki_sha256),
        ("build-watchdog raw key pin", expected_key_raw_sha256),
        ("build-watchdog challenge pin", expected_challenge_sha256),
        ("build-watchdog capability pin", expected_capability_sha256),
    ):
        _required_digest(value, label=label)
    key_raw, _ = _read_regular(
        public_key_path,
        label="build-watchdog public key",
        max_bytes=1024,
    )
    if (
        _sha256(key_raw) != expected_key_spki_sha256
        or len(key_raw) != len(ED25519_SPKI_PREFIX) + 32
        or not key_raw.startswith(ED25519_SPKI_PREFIX)
    ):
        raise VerificationError("build-watchdog key differs from its SPKI pin")
    public_key = key_raw[len(ED25519_SPKI_PREFIX) :]
    if _sha256(public_key) != expected_key_raw_sha256:
        raise VerificationError("build-watchdog key differs from its raw-key pin")
    _ed25519_decode(public_key, label="build-watchdog public key")
    raw, _ = _read_regular(path, label="build-watchdog receipt")
    document = _load_json(raw, label="build-watchdog receipt")
    if (
        raw != _canonical_json(document) + b"\n"
        or not isinstance(document, dict)
        or set(document) != {"apiVersion", "payload", "payloadSha256", "signature"}
        or document.get("apiVersion") != BUILD_WATCHDOG_RECEIPT_VERSION
    ):
        raise VerificationError("build-watchdog receipt envelope is invalid")
    payload = document["payload"]
    if (
        not isinstance(payload, dict)
        or set(payload)
        != {
            "bootId",
            "buildBundleSha256",
            "candidateRequest",
            "candidateRequestSha256",
            "daemonIdentity",
            "daemonIdentitySha256",
            "eventHeadSha256",
            "events",
            "lease",
            "planSha256",
            "request",
            "requestSha256",
            "serviceIdentity",
            "serviceIdentitySha256",
        }
        or document.get("payloadSha256") != _sha256(_canonical_json(payload))
    ):
        raise VerificationError("build-watchdog receipt payload is invalid")
    if (
        not isinstance(payload.get("bootId"), str)
        or re.fullmatch(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
            r"[0-9a-f]{4}-[0-9a-f]{12}",
            payload["bootId"],
        )
        is None
    ):
        raise VerificationError("build-watchdog boot identity is invalid")
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
        != BUILD_WATCHDOG_SIGNATURE_DOMAIN[:-1].decode("ascii")
        or signature.get("keyFileSha256") != expected_key_spki_sha256
        or signature.get("rawKeySha256") != expected_key_raw_sha256
        or not isinstance(signature.get("value"), str)
        or re.fullmatch(r"[A-Za-z0-9+/]{86}==", signature["value"]) is None
    ):
        raise VerificationError("build-watchdog signature envelope is invalid")
    try:
        signature_raw = base64.b64decode(signature["value"], validate=True)
    except (ValueError, binascii.Error) as exc:
        raise VerificationError(
            "build-watchdog signature is not strict base64"
        ) from exc
    _verify_ed25519(
        public_key=public_key,
        signature=signature_raw,
        message=BUILD_WATCHDOG_SIGNATURE_DOMAIN
        + _canonical_json(
            {
                "payload": payload,
                "payloadSha256": document["payloadSha256"],
            }
        ),
    )
    lease = payload["lease"]
    if (
        not isinstance(lease, dict)
        or set(lease) != {"capabilitySha256", "challengeSha256", "id"}
        or lease.get("id") != bundle["buildLeaseId"]
        or LEASE_RE.fullmatch(str(lease.get("id") or "")) is None
        or lease.get("challengeSha256") != expected_challenge_sha256
        or lease.get("capabilitySha256") != expected_capability_sha256
    ):
        raise VerificationError("build-watchdog lease binding is invalid")
    candidate_request = {
        "buildBundleSha256": bundle["bundleSha256"],
        "dependencyBundleSha256": plan["dependencyBundle"]["manifestSha256"],
        "imageRoles": image_roles,
        "network": "none",
        "planSha256": plan["planSha256"],
        "platform": {"architecture": "amd64", "os": "linux"},
        "sourceClosureSha256": plan["sourceSnapshot"]["sourceClosureSha256"],
        "sourceEvidence": plan["sourceSnapshot"]["sourceEvidence"],
        "sourceEvidenceSha256": plan["sourceSnapshot"][
            "sourceEvidenceSha256"
        ],
        "sourceGitInventoryPayloadSha256": plan["sourceSnapshot"][
            "sourceGitInventoryPayloadSha256"
        ],
        "sourceManifestFileSha256": plan["sourceSnapshot"][
            "sourceManifestFileSha256"
        ],
        "sourceSelectionManifestFileSha256": plan["sourceSnapshot"][
            "sourceSelectionManifestFileSha256"
        ],
        "sourceSelectionManifestPayloadSha256": plan["sourceSnapshot"][
            "sourceSelectionManifestPayloadSha256"
        ],
        "sourceUntrackedApprovalPayloadSha256": plan["sourceSnapshot"][
            "sourceUntrackedApprovalPayloadSha256"
        ],
    }
    if (
        payload["candidateRequest"] != candidate_request
        or payload["candidateRequestSha256"]
        != _sha256(_canonical_json(candidate_request))
        or payload["planSha256"] != plan["planSha256"]
        or payload["buildBundleSha256"] != bundle["bundleSha256"]
    ):
        raise VerificationError("build-watchdog candidate request changed")
    request = {
        "candidateRequestSha256": payload["candidateRequestSha256"],
        "challengeSha256": expected_challenge_sha256,
        "contractSha256": plan["buildWatchdogContract"]["contractSha256"],
        "leaseCapabilitySha256": expected_capability_sha256,
        "leaseId": lease["id"],
        "operation": "build-all-oci-v4",
    }
    if (
        payload["request"] != request
        or payload["requestSha256"] != _sha256(_canonical_json(request))
    ):
        raise VerificationError("build-watchdog request digest is invalid")
    for name in ("serviceIdentity", "daemonIdentity"):
        identity = payload[name]
        expected_unit = plan["buildWatchdogContract"][
            "serviceUnit" if name == "serviceIdentity" else "daemonServiceUnit"
        ]
        if (
            not isinstance(identity, dict)
            or set(identity)
            != {
                "bootId",
                "cgroup",
                "exeSha256",
                "pid",
                "pidStartTime",
                "serviceUnit",
            }
            or identity.get("bootId") != payload["bootId"]
            or not isinstance(identity.get("cgroup"), str)
            or not identity["cgroup"].startswith("/")
            or not isinstance(identity.get("serviceUnit"), str)
            or identity["serviceUnit"] != expected_unit
            or type(identity.get("pid")) is not int
            or identity["pid"] <= 0
            or not isinstance(identity.get("pidStartTime"), str)
        ):
            raise VerificationError(f"build-watchdog {name} is invalid")
        _required_digest(identity.get("exeSha256"), label=f"{name} executable")
        digest_name = name + "Sha256"
        if payload[digest_name] != _sha256(_canonical_json(identity)):
            raise VerificationError(f"build-watchdog {name} digest is invalid")

    events = payload["events"]
    if not isinstance(events, list) or len(events) < 6:
        raise VerificationError("build-watchdog event log is incomplete")
    previous = _sha256(b"")
    resources: dict[tuple[str, str], dict[str, Any]] = {}
    cleanup_actions: dict[tuple[str, str], set[str]] = {}
    cleanup_log: list[dict[str, Any]] = []
    absence: list[dict[str, Any]] = []
    phase = "lease"
    lease_begun = False
    cleanup_started = False
    inventory_started = False
    lease_finished = False
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
            raise VerificationError("build-watchdog event chain is invalid")
        event_payload = {
            "event": event["event"],
            "previousEventSha256": previous,
            "sequence": sequence,
        }
        measured = _sha256(_canonical_json(event_payload))
        if event.get("eventSha256") != measured:
            raise VerificationError("build-watchdog event digest is invalid")
        previous = measured
        body = event["event"]
        event_type = body.get("type")
        if (
            not isinstance(event_type, str)
            or "network" in event_type.casefold()
            or body.get("kind") == "network"
            or (
                isinstance(body.get("resource"), dict)
                and body["resource"].get("kind") == "network"
            )
        ):
            raise VerificationError(
                "network:none build receipt contains a network event"
            )
        if lease_finished:
            raise VerificationError(
                "build-watchdog emitted events after lease finish"
            )
        if event_type == "resource-created":
            if phase != "build":
                raise VerificationError(
                    "build-watchdog created a resource outside build phase"
                )
            if set(body) != {"resource", "type"}:
                raise VerificationError("resource-created event is invalid")
            resource = body["resource"]
            if (
                not isinstance(resource, dict)
                or set(resource) != {"id", "kind", "labels", "name", "role"}
                or RUNTIME_ID_RE.fullmatch(str(resource.get("id") or ""))
                is None
                or RUNTIME_ID_RE.fullmatch(str(resource.get("name") or ""))
                is None
                or resource.get("kind")
                not in {
                    "builder",
                    "container",
                    "content",
                    "image",
                    "snapshot",
                    "task",
                }
                or resource.get("role") not in image_roles
                or resource.get("labels")
                != {
                    "org.catchplate.build-lease": lease["id"],
                    "org.catchplate.build-plan": plan["planSha256"],
                    "org.catchplate.image-role": resource["role"],
                    "org.catchplate.resource-kind": resource["kind"],
                }
            ):
                raise VerificationError("build-watchdog resource event is invalid")
            key = (resource["kind"], resource["id"])
            if key in resources:
                raise VerificationError("build-watchdog resource pair is duplicated")
            if any(
                existing["kind"] == resource["kind"]
                and existing["name"] == resource["name"]
                for existing in resources.values()
            ):
                raise VerificationError(
                    "build-watchdog resource kind/name is duplicated"
                )
            resources[key] = resource
        elif event_type == "cleanup-action":
            if phase != "cleanup" or inventory_started:
                raise VerificationError(
                    "build-watchdog cleanup action is out of order"
                )
            if (
                set(body) != {"action", "resource", "result", "type"}
                or body.get("action") not in {"inspect", "kill", "remove"}
                or body.get("result")
                not in {
                    "present-or-already-absent",
                    "killed-reaped-or-already-absent",
                    "removed-or-already-absent",
                }
                or not isinstance(body.get("resource"), dict)
                or set(body["resource"]) != {"id", "kind"}
            ):
                raise VerificationError("build-watchdog cleanup event is invalid")
            key = (body["resource"]["kind"], body["resource"]["id"])
            if key not in resources:
                raise VerificationError("cleanup references an unknown resource")
            actions = cleanup_actions.setdefault(key, set())
            if body["action"] in actions:
                raise VerificationError(
                    "build-watchdog cleanup action is duplicated"
                )
            actions.add(body["action"])
            cleanup_log.append(
                {
                    "action": body["action"],
                    "resource": body["resource"],
                    "result": body["result"],
                }
            )
        elif event_type == "daemon-inventory-absence":
            if (
                phase != "cleanup"
                or set(body)
                != {
                    "absentResources",
                    "labelledAlternates",
                    "ordinal",
                    "presentResources",
                    "type",
                }
                or body.get("ordinal") != len(absence) + 1
            ):
                raise VerificationError("daemon absence event is invalid")
            inventory_started = True
            absence.append(body)
        elif event_type == "lease-begin":
            if (
                sequence != 1
                or lease_begun
                or phase != "lease"
                or body
                != {
                    "leaseId": lease["id"],
                    "requestSha256": payload["requestSha256"],
                    "type": "lease-begin",
                }
            ):
                raise VerificationError(
                    "build-watchdog lease-begin event is invalid"
                )
            lease_begun = True
            phase = "build"
        elif event_type == "cleanup-started":
            if (
                phase != "build"
                or cleanup_started
                or body
                != {
                    "leaseId": lease["id"],
                    "type": "cleanup-started",
                }
            ):
                raise VerificationError(
                    "build-watchdog cleanup-started event is invalid"
                )
            cleanup_started = True
            phase = "cleanup"
        elif event_type == "lease-finished":
            if (
                phase != "cleanup"
                or len(absence) != 3
                or body
                != {
                    "eventHeadBeforeFinishSha256": events[-2][
                        "eventSha256"
                    ],
                    "leaseId": lease["id"],
                    "type": "lease-finished",
                }
            ):
                raise VerificationError(
                    "build-watchdog lease-finished event is invalid"
                )
            lease_finished = True
            phase = "terminal"
        else:
            raise VerificationError("build-watchdog event type is unsupported")
    if (
        not lease_begun
        or not cleanup_started
        or not lease_finished
        or events[-1]["event"].get("type") != "lease-finished"
        or payload["eventHeadSha256"] != previous
    ):
        raise VerificationError("build-watchdog lease event boundaries are invalid")
    expected_refs = sorted(
        (_resource_ref(item) for item in resources.values()),
        key=lambda item: (item["kind"], item["id"]),
    )
    for key, resource in resources.items():
        expected_actions = {"inspect", "remove"}
        if resource["kind"] in {"builder", "container", "task"}:
            expected_actions.add("kill")
        if cleanup_actions.get(key) != expected_actions:
            raise VerificationError(
                "build-watchdog omitted an exact resource cleanup action"
            )
    expected_cleanup_log: list[dict[str, Any]] = []
    for key in sorted(resources):
        resource = resources[key]
        expected_cleanup_log.append(
            {
                "action": "inspect",
                "resource": _resource_ref(resource),
                "result": "present-or-already-absent",
            }
        )
        if resource["kind"] in {"builder", "container", "task"}:
            expected_cleanup_log.append(
                {
                    "action": "kill",
                    "resource": _resource_ref(resource),
                    "result": "killed-reaped-or-already-absent",
                }
            )
        expected_cleanup_log.append(
            {
                "action": "remove",
                "resource": _resource_ref(resource),
                "result": "removed-or-already-absent",
            }
        )
    if cleanup_log != expected_cleanup_log:
        raise VerificationError(
            "build-watchdog cleanup transcript order is not exact"
        )
    if len(absence) != 3:
        raise VerificationError("build-watchdog requires three absence inventories")
    for ordinal, observation in enumerate(absence, start=1):
        if observation != {
            "absentResources": expected_refs,
            "labelledAlternates": [],
            "ordinal": ordinal,
            "presentResources": [],
            "type": "daemon-inventory-absence",
        }:
            raise VerificationError("build-watchdog absence inventory is invalid")
    if sorted(
        resource["role"]
        for resource in resources.values()
        if resource["kind"] == "image"
    ) != sorted(image_roles):
        raise VerificationError("build-watchdog image inventory is incomplete")
    required_role_kinds = {
        "builder",
        "container",
        "content",
        "image",
        "snapshot",
        "task",
    }
    for role in image_roles:
        observed_kinds = {
            resource["kind"]
            for resource in resources.values()
            if resource["role"] == role
        }
        if observed_kinds != required_role_kinds:
            raise VerificationError(
                f"build-watchdog resource inventory is incomplete for {role}"
            )
    return {
        **document,
        "receiptFileSha256": _sha256(raw),
        "resources": [
            resources[key] for key in sorted(resources)
        ],
    }


def _promotion_contract(
    *,
    candidate_payload: dict[str, Any],
) -> dict[str, Any]:
    mappings = [
        {
            "candidate": {
                "archiveSha256": image["archive"]["sha256"],
                "archiveSize": image["archive"]["size"],
                "capabilityAttestation": image[
                    "capabilityAttestation"
                ],
                "capabilityCatalog": image["capabilityCatalog"],
                "capabilityCatalogSha256": image[
                    "capabilityCatalogSha256"
                ],
                "configDigest": image["configDigest"],
                "dependencyClosureSha256": image[
                    "dependencyClosureSha256"
                ],
                "dependencyFileManifestSha256": image[
                    "dependencyFileManifestSha256"
                ],
                "dependencyPackageInventorySha256": image[
                    "dependencyPackageInventorySha256"
                ],
                "dependencyRole": image["dependencyRole"],
                "executableInventorySha256": image[
                    "executableInventorySha256"
                ],
                "fileManifestSha256": image["fileManifest"]["sha256"],
                "fixedToolIdentities": image["fixedToolIdentities"],
                "indexDigest": image["indexDigest"],
                "layerDigests": image["layerDigests"],
                "manifestDigest": image["manifestDigest"],
                "rootfsDiffIds": image["rootfsDiffIds"],
                "rootfsDigest": image["rootfsDigest"],
                "sbomSha256": image["sbom"]["sha256"],
                "semanticContract": image["semanticContract"],
            },
            "importedRequiredFields": [
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
            ],
            "role": role,
        }
        for role, image in candidate_payload["images"].items()
    ]
    payload = {
        "apiVersion": PROMOTION_CONTRACT_VERSION,
        "candidatePayloadSha256": _sha256(_canonical_json(candidate_payload)),
        "finalManifestVersion": BUILD_MANIFEST_VERSION,
        "imageMappings": mappings,
        "promoterRequirements": {
            "buildWatchdogReceiptReverification": {
                "authorship": "Ed25519-v4-against-independent-promoter-pin",
                "leaseLabels": "exact-plan-role-kind-and-lease",
                "resourceIdentity": "exact-kind-id-pairs",
                "transcript": "complete-chained-events-and-three-absence-inventories",
            },
            "daemonAccess": "root-promoter-only",
            "daemonInspection": [
                "daemon-id",
                "daemon-pid-start-time-exe-cgroup-boot",
                "root-owned-socket-safe-ancestors",
                "imported-image-id-config-rootfs",
                "complete-image-inventory-no-extras",
            ],
            "daemonServiceUnit": "catchplate-verification-daemon.service",
            "daemonRuntime": "containerd-oci-task-v2",
            "daemonSocket": (
                "/run/catchplate-verification-daemon/containerd.sock"
            ),
            "importByDigest": True,
            "independentFileManifestComparison": True,
            "independentCapabilityAuthority": {
                "catalog": "catchplate.dependencyCapabilityCatalog/v2",
                "runtimeKeyPlacement": "trusted-runtime-closure",
                "signature": (
                    "catchplate.dependencyCapabilityAttestation/v1-"
                    "externally-key-pinned"
                ),
                "signedBindings": [
                    "catalog",
                    "dependency-closure",
                    "file-manifest",
                    "package-inventory",
                    "semantic-contract",
                ],
            },
            "independentSourceSelectionComparison": {
                "model": SOURCE_SELECTION_MODEL,
                "requiredUntracked": "explicit-only",
                "trackedInventory": "complete-git-index",
                "unexpectedSnapshotEntries": "reject",
            },
            "independentRootfsDerivation": {
                "allowedOrigins": [
                    "digest-pinned-dependency-bundle-entry",
                    "frozen-source-record",
                    "tracked-fixed-entrypoint-source",
                ],
                "npmCompanionExclusiveCapabilities": ["node", "npm-11.8"],
                "portalForbiddenCapabilities": [
                    *sorted(PORTAL_FORBIDDEN_CAPABILITY_CLASSES),
                ],
                "rejectUnmappedEntries": True,
            },
            "laneHostMounts": [],
            "laneSocketMounts": [],
            "noRuntimeArchivePaths": True,
            "safeReadOnlyRuntimeMaterials": [
                "launcher-runtime",
                "dependency-capability-authority-key",
                "promotion-key",
                "promotion-receipt",
                "manifest-v6",
            ],
            "watchdogBootCleanupVersion": (
                "catchplate.ociWatchdogBootCleanup/v1"
            ),
            "watchdogLaneEndpoint": {
                "networkRole": "portal-npm-private",
                "protocol": "catchplate.npmOneUse/v2",
                "url": (
                    "https://watchdog.catchplate.internal/"
                    "v1/npm-publish-one-use"
                ),
            },
            "watchdogProtocol": WATCHDOG_PROTOCOL_VERSION,
            "watchdogProtocolRequirements": {
                "launcherChosenLeaseId": True,
                "laneRequestBindsImageAndContract": True,
                "malformedFinishRecovery": "close-reconnect-abort-by-lease",
                "resourceLabelNames": [
                    "org.catchplate.attempt",
                    "org.catchplate.kind",
                    "org.catchplate.lane",
                    "org.catchplate.lane-sequence",
                    "org.catchplate.lease",
                    "org.catchplate.manifest",
                    "org.catchplate.promotion-receipt",
                    "org.catchplate.role",
                ],
                "runtimeCleanup": (
                    "authoritative-lease-inventory-inspect-kill-reap-"
                    "force-remove-three-absence-observations"
                ),
                "resourceIdentity": "exact-kind-and-id-pair",
                "recovery": (
                    "same-session-lease-nonce-chain-with-recovery-challenge"
                ),
                "runtimeEvidence": (
                    "catchplate.ociRuntimeEvidence/v2-signed-prestart-"
                    "mount-cgroup-capability-namespace-network"
                ),
            },
            "watchdogServiceUnit": (
                "catchplate-verification-watchdog.service"
            ),
            "watchdogSocket": "/run/catchplate-watchdog/control.sock",
        },
        "finalManifestSourceSnapshot": {
            key: value
            for key, value in candidate_payload["sourceSnapshot"].items()
            if key != "sourceManifest"
        },
        "receiptPayloadFields": [
            "candidateIndexSha256",
            "candidateManifestFileSha256",
            "candidateManifestPayloadSha256",
            "candidatePromotionContractSha256",
            "daemon",
            "finalManifestSha256",
            "images",
            "imageMappings",
            "launcherRuntime",
            "manifest",
            "promotionAcceptanceSha256",
            "promotionPublicKey",
            "receiptStorage",
            "sourceEvidence",
            "sourceEvidenceSha256",
            "watchdog",
        ],
        "receiptSignature": {
            "algorithm": "Ed25519",
            "domain": "catchplate.verificationPromotionReceipt/v4\u0000Ed25519",
            "message": (
                "domain-with-terminal-NUL || canonical-json("
                "{payload,payloadSha256})"
            ),
            "publicKey": (
                "canonical DER SPKI and raw key separately externally pinned "
                "inside trusted launcher runtime v4"
            ),
        },
        "sourceSnapshot": candidate_payload["sourceSnapshot"],
    }
    return {**payload, "contractSha256": _sha256(_canonical_json(payload))}


def _rederive_build_plan(args: argparse.Namespace) -> dict[str, Any]:
    plan = _load_build_plan(args.build_plan)
    source = _load_source_manifest(
        args.source_manifest,
        root=args.source_snapshot,
        source_input_manifest=args.source_input_manifest,
        expected_source_input_manifest_sha256=(
            args.expected_source_input_manifest_sha256
        ),
        source_git_inventory_public_key=args.source_git_inventory_public_key,
        expected_source_git_inventory_key_spki_sha256=(
            args.expected_source_git_inventory_key_spki_sha256
        ),
        expected_source_git_inventory_key_raw_sha256=(
            args.expected_source_git_inventory_key_raw_sha256
        ),
        source_untracked_approval_public_key=(
            args.source_untracked_approval_public_key
        ),
        expected_source_untracked_approval_key_spki_sha256=(
            args.expected_source_untracked_approval_key_spki_sha256
        ),
        expected_source_untracked_approval_key_raw_sha256=(
            args.expected_source_untracked_approval_key_raw_sha256
        ),
    )
    source_manifest_raw, _ = _read_regular(
        args.source_manifest,
        label="source manifest continuity file",
    )
    dependencies = _load_dependencies(
        args.dependency_bundle_manifest,
        capability_authority_public_key=(
            args.dependency_capability_authority_public_key
        ),
        expected_capability_authority_key_spki_sha256=(
            args.expected_dependency_capability_authority_key_spki_sha256
        ),
        expected_capability_authority_key_raw_sha256=(
            args.expected_dependency_capability_authority_key_raw_sha256
        ),
    )
    watchdog_contract = _load_build_watchdog_contract(
        args.build_watchdog_contract
    )
    expected_payload = _derive_build_plan_payload(
        source=source,
        source_manifest_file={
            "sha256": _sha256(source_manifest_raw),
            "size": len(source_manifest_raw),
        },
        dependencies=dependencies,
        watchdog_contract=watchdog_contract,
        apparmor=_content_identity(
            args.apparmor_profile,
            label="AppArmor profile continuity",
            max_bytes=1024 * 1024,
        ),
        seccomp=_content_identity(
            args.seccomp_profile,
            label="seccomp profile continuity",
            max_bytes=1024 * 1024,
        ),
    )
    expected = {
        **expected_payload,
        "planSha256": _sha256(_canonical_json(expected_payload)),
    }
    if plan != expected:
        raise VerificationError("OCI build plan is not the fixed rederived plan")
    _remeasure_live_selected_source(source)
    return plan


def _load_build_bundle(
    path: Path,
    *,
    plan: dict[str, Any],
) -> dict[str, Any]:
    bundle = _load_digest_document(
        path,
        label="OCI build bundle manifest",
        api_version=OCI_BUILD_BUNDLE_VERSION,
        digest_field="bundleSha256",
    )
    if (
        set(bundle)
        != {
            "apiVersion",
            "buildLeaseId",
            "bundleSha256",
            "candidateRequestSha256",
            "images",
            "planSha256",
        }
        or bundle.get("planSha256") != plan["planSha256"]
        or LEASE_RE.fullmatch(str(bundle.get("buildLeaseId") or "")) is None
        or not isinstance(bundle.get("images"), dict)
        or list(bundle["images"]) != plan["imageOrder"]
    ):
        raise VerificationError("OCI build bundle fields are invalid")
    for role, record in bundle["images"].items():
        if (
            not isinstance(record, dict)
            or set(record) != {"archive", "fileManifest", "role", "sbom"}
            or record.get("role") != role
        ):
            raise VerificationError("OCI build bundle image record is invalid")
        for key in ("archive", "fileManifest", "sbom"):
            _safe_relative(record[key], label=f"{role} {key}")
    return bundle


def _candidate_companions(plan: dict[str, Any]) -> dict[str, Any]:
    return {
        "npmPublish": {
            "imageRole": "npm-publish-companion",
            "inputProtocol": (
                "one-canonical-json-frame-on-stdin-no-generic-command"
            ),
            "isolation": plan["npmCompanion"]["isolation"],
            "network": plan["npmCompanion"]["network"],
            "npmVersion": "11.8.0",
            "operation": "npm.publish.fixture",
            "operationCount": 2,
            "plan": plan["npmCompanion"],
            "retryEquality": {
                "canonicalHttpRequestBytes": "identical",
                "operationInputBytes": "identical",
                "rawHttpRequestBytes": "different-only-by-npm-session",
                "requestBodyBytes": "identical",
            },
        }
    }


def _record_candidate(args: argparse.Namespace) -> dict[str, Any]:
    plan = _rederive_build_plan(args)
    bundle = _load_build_bundle(args.oci_bundle_manifest, plan=plan)
    oci_root = _absolute(args.oci_root, label="OCI output root")
    images = {
        role: _measure_oci_image(
            role=role,
            record=bundle["images"][role],
            plan=plan,
            oci_root=oci_root,
        )
        for role in plan["imageOrder"]
    }
    watchdog = _load_build_watchdog_receipt(
        args.build_watchdog_receipt,
        plan=plan,
        bundle=bundle,
        image_roles=plan["imageOrder"],
        public_key_path=args.build_watchdog_public_key,
        expected_key_spki_sha256=args.expected_build_watchdog_key_spki_sha256,
        expected_key_raw_sha256=args.expected_build_watchdog_key_raw_sha256,
        expected_challenge_sha256=args.expected_build_watchdog_challenge_sha256,
        expected_capability_sha256=args.expected_build_watchdog_capability_sha256,
    )
    if (
        watchdog["payload"]["lease"]["id"] != bundle["buildLeaseId"]
        or watchdog["payload"]["candidateRequestSha256"]
        != bundle["candidateRequestSha256"]
    ):
        raise VerificationError("build bundle crossed build-watchdog continuity")
    lanes = {
        name: plan["lanes"][name]
        for name in LANE_ORDER
    }
    companions = _candidate_companions(plan)
    payload = {
        "apiVersion": CANDIDATE_MANIFEST_VERSION,
        "buildContinuity": {
            "buildBundle": bundle,
            "buildPlan": plan,
            "buildWatchdogReceipt": {
                "document": {
                    key: value
                    for key, value in watchdog.items()
                    if key not in {"receiptFileSha256", "resources"}
                },
                "receiptFileSha256": watchdog["receiptFileSha256"],
                "resources": watchdog["resources"],
            },
            "dependencyBundle": plan["dependencyBundle"],
            "sourceSnapshot": plan["sourceSnapshot"],
        },
        "companions": companions,
        "images": images,
        "laneOrder": list(LANE_ORDER),
        "lanes": lanes,
        "sourceSnapshot": plan["sourceSnapshot"],
    }
    promotion = _promotion_contract(candidate_payload=payload)
    document_payload = {**payload, "promotionContract": promotion}
    candidate_file = {
        **document_payload,
        "candidateManifestPayloadSha256": _sha256(
            _canonical_json(document_payload)
        ),
    }
    candidate_file_raw = _canonical_json(candidate_file) + b"\n"
    _remeasure_live_selected_source(
        plan["sourceSnapshot"]["sourceManifest"]
    )
    output_root = (
        Path(plan["sourceSnapshot"]["sourceManifest"]["sourceRoot"])
        / ".tmp"
    )
    _publish(
        args.candidate_file_out,
        candidate_file_raw,
        output_root=output_root,
    )
    index_payload = {
        "apiVersion": CANDIDATE_INDEX_VERSION,
        "candidateFile": {
            "fileName": args.candidate_file_out.name,
            "sha256": _sha256(candidate_file_raw),
            "size": len(candidate_file_raw),
        },
        "candidateManifestPayloadSha256": candidate_file[
            "candidateManifestPayloadSha256"
        ],
        "promotionContractSha256": promotion["contractSha256"],
        "roleOrder": plan["imageOrder"],
    }
    index = {
        **index_payload,
        "candidateIndexSha256": _sha256(_canonical_json(index_payload)),
    }
    _remeasure_live_selected_source(
        plan["sourceSnapshot"]["sourceManifest"]
    )
    _publish(
        args.out,
        _canonical_json(index) + b"\n",
        output_root=output_root,
    )
    return {"candidateFile": candidate_file, "candidateIndex": index}


def _verify_candidate(args: argparse.Namespace) -> dict[str, Any]:
    index = _load_digest_document(
        args.manifest,
        label="Candidate Manifest index",
        api_version=CANDIDATE_INDEX_VERSION,
        digest_field="candidateIndexSha256",
    )
    candidate_raw, _ = _read_regular(
        args.candidate_file,
        label="Candidate Manifest payload file",
    )
    document = _load_json(candidate_raw, label="Candidate Manifest payload")
    if (
        candidate_raw != _canonical_json(document) + b"\n"
        or not isinstance(index, dict)
        or set(index)
        != {
            "apiVersion",
            "candidateFile",
            "candidateIndexSha256",
            "candidateManifestPayloadSha256",
            "promotionContractSha256",
            "roleOrder",
        }
        or index["candidateFile"]
        != {
            "fileName": args.candidate_file.name,
            "sha256": _sha256(candidate_raw),
            "size": len(candidate_raw),
        }
        or not isinstance(document, dict)
        or set(document)
        != {
            "apiVersion",
            "buildContinuity",
            "candidateManifestPayloadSha256",
            "companions",
            "images",
            "laneOrder",
            "lanes",
            "promotionContract",
            "sourceSnapshot",
        }
        or document.get("apiVersion") != CANDIDATE_MANIFEST_VERSION
        or document["laneOrder"] != list(LANE_ORDER)
        or index["roleOrder"]
        != [f"lane-{name}" for name in LANE_ORDER]
        + ["npm-publish-companion"]
        or list(document["lanes"]) != list(LANE_ORDER)
        or list(document["images"])
        != [f"lane-{name}" for name in LANE_ORDER]
        + ["npm-publish-companion"]
        or not isinstance(document.get("promotionContract"), dict)
        or set(document["promotionContract"])
        != {
            "apiVersion",
            "candidatePayloadSha256",
            "contractSha256",
            "finalManifestVersion",
            "imageMappings",
            "promoterRequirements",
            "receiptPayloadFields",
            "receiptSignature",
            "sourceSnapshot",
        }
    ):
        raise VerificationError("Candidate Manifest v6 inventory is invalid")
    document_payload = {
        key: value
        for key, value in document.items()
        if key != "candidateManifestPayloadSha256"
    }
    if (
        document["candidateManifestPayloadSha256"]
        != _sha256(_canonical_json(document_payload))
        or index["candidateManifestPayloadSha256"]
        != document["candidateManifestPayloadSha256"]
        or index["promotionContractSha256"]
        != document["promotionContract"]["contractSha256"]
    ):
        raise VerificationError("candidate file and payload digests differ")
    expected_promotion = _promotion_contract(
        candidate_payload={
            key: value
            for key, value in document.items()
            if key
            not in {"candidateManifestPayloadSha256", "promotionContract"}
        }
    )
    if document["promotionContract"] != expected_promotion:
        raise VerificationError("candidate promotion contract changed")
    plan = _rederive_build_plan(args)
    bundle = _load_build_bundle(args.oci_bundle_manifest, plan=plan)
    watchdog = _load_build_watchdog_receipt(
        args.build_watchdog_receipt,
        plan=plan,
        bundle=bundle,
        image_roles=plan["imageOrder"],
        public_key_path=args.build_watchdog_public_key,
        expected_key_spki_sha256=args.expected_build_watchdog_key_spki_sha256,
        expected_key_raw_sha256=args.expected_build_watchdog_key_raw_sha256,
        expected_challenge_sha256=args.expected_build_watchdog_challenge_sha256,
        expected_capability_sha256=args.expected_build_watchdog_capability_sha256,
    )
    expected_continuity = {
        "buildBundle": bundle,
        "buildPlan": plan,
        "buildWatchdogReceipt": {
            "document": {
                key: value
                for key, value in watchdog.items()
                if key not in {"receiptFileSha256", "resources"}
            },
            "receiptFileSha256": watchdog["receiptFileSha256"],
            "resources": watchdog["resources"],
        },
        "dependencyBundle": plan["dependencyBundle"],
        "sourceSnapshot": plan["sourceSnapshot"],
    }
    if (
        document["buildContinuity"] != expected_continuity
        or document["sourceSnapshot"] != plan["sourceSnapshot"]
        or document["lanes"] != {
            name: plan["lanes"][name] for name in LANE_ORDER
        }
        or document["companions"] != _candidate_companions(plan)
    ):
        raise VerificationError("candidate build continuity changed")
    root = _absolute(args.oci_root, label="OCI output root")
    for role, image in document["images"].items():
        try:
            archive_relative = Path(image["archive"]["path"]).relative_to(root)
            file_manifest_relative = Path(
                image["fileManifest"]["path"]
            ).relative_to(root)
            sbom_relative = Path(image["sbom"]["path"]).relative_to(root)
        except ValueError as exc:
            raise VerificationError(
                f"{role} candidate artifact escapes the OCI output root"
            ) from exc
        measured = _measure_oci_image(
            role=role,
            record={
                "archive": archive_relative.as_posix(),
                "fileManifest": file_manifest_relative.as_posix(),
                "role": role,
                "sbom": sbom_relative.as_posix(),
            },
            plan=plan,
            oci_root=root,
        )
        if measured != image:
            raise VerificationError(f"{role} candidate OCI closure changed")
    _remeasure_live_selected_source(
        plan["sourceSnapshot"]["sourceManifest"]
    )
    return document


def _reset_outputs(args: argparse.Namespace) -> dict[str, Any]:
    root = _absolute(args.source_root, label="reset source root") / ".tmp"
    removed: list[str] = []

    def remove_tree_at(parent: int, name: str) -> None:
        metadata = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if not stat.S_ISDIR(metadata.st_mode):
            os.unlink(name, dir_fd=parent)
            os.fsync(parent)
            return
        if (
            metadata.st_uid not in {0, os.getuid()}
            or stat.S_IMODE(metadata.st_mode) & 0o022
        ):
            raise VerificationError("reset output directory metadata is unsafe")
        child = os.open(
            name,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | os.O_NOFOLLOW,
            dir_fd=parent,
        )
        try:
            opened = os.fstat(child)
            if (
                opened.st_dev != metadata.st_dev
                or opened.st_ino != metadata.st_ino
                or not stat.S_ISDIR(opened.st_mode)
                or opened.st_uid not in {0, os.getuid()}
                or stat.S_IMODE(opened.st_mode) & 0o022
            ):
                raise VerificationError("reset output changed during deletion")
            entries = sorted(
                (entry.name for entry in os.scandir(child)),
                key=lambda value: value.encode("utf-8"),
            )
            for entry in entries:
                if entry in {"", ".", ".."} or "/" in entry or "\x00" in entry:
                    raise VerificationError("reset output has an invalid entry")
                remove_tree_at(child, entry)
            if os.listdir(child):
                raise VerificationError("reset output was repopulated")
        finally:
            os.close(child)
        current = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if (
            current.st_dev != metadata.st_dev
            or current.st_ino != metadata.st_ino
            or not stat.S_ISDIR(current.st_mode)
        ):
            raise VerificationError("reset output was replaced before removal")
        os.rmdir(name, dir_fd=parent)
        os.fsync(parent)

    validated_paths: list[Path] = []
    for path in args.path:
        absolute = _absolute(path, label="reset output")
        _under(absolute, root, label="reset output")
        validated_paths.append(absolute)
    if _path_type_nofollow(root, label="output root") is None:
        return {"removed": [str(path) for path in validated_paths]}
    root_fd, root_before = _open_safe_root(root, label="output root")
    try:
        for absolute in validated_paths:
            relative = _safe_relative(
                absolute.relative_to(root).as_posix(),
                label="reset output",
            )
            parent = os.dup(root_fd)
            try:
                missing = False
                for component in relative.parts[:-1]:
                    try:
                        child = os.open(
                            component,
                            os.O_RDONLY
                            | getattr(os, "O_DIRECTORY", 0)
                            | getattr(os, "O_CLOEXEC", 0)
                            | os.O_NOFOLLOW,
                            dir_fd=parent,
                        )
                    except FileNotFoundError:
                        missing = True
                        break
                    metadata = os.fstat(child)
                    if (
                        not stat.S_ISDIR(metadata.st_mode)
                        or metadata.st_uid not in {0, os.getuid()}
                        or stat.S_IMODE(metadata.st_mode) & 0o022
                    ):
                        os.close(child)
                        raise VerificationError(
                            "reset output has an unsafe ancestor directory"
                        )
                    os.close(parent)
                    parent = child
                if not missing:
                    try:
                        remove_tree_at(parent, relative.parts[-1])
                    except FileNotFoundError:
                        pass
            finally:
                os.close(parent)
            removed.append(str(absolute))
        current_fd, root_current = _open_safe_root(
            root,
            label="output root path continuity",
        )
        os.close(current_fd)
        identity = lambda item: (
            item.st_dev,
            item.st_ino,
            item.st_mode,
            item.st_uid,
            item.st_gid,
        )
        if identity(root_current) != identity(root_before):
            raise VerificationError(
                "output root pathname changed during reset"
            )
    finally:
        os.close(root_fd)
    return {"removed": removed}


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Record deterministic OCI verification artifacts.",
        allow_abbrev=False,
    )
    commands = parser.add_subparsers(dest="command", required=True)

    def add_source_authorities(command: argparse.ArgumentParser) -> None:
        for option in (
            "source-git-inventory-public-key",
            "source-untracked-approval-public-key",
        ):
            command.add_argument(
                f"--{option}",
                required=True,
                type=Path,
                action=StoreOnce,
            )
        for option in (
            "expected-source-git-inventory-key-raw-sha256",
            "expected-source-git-inventory-key-spki-sha256",
            "expected-source-untracked-approval-key-raw-sha256",
            "expected-source-untracked-approval-key-spki-sha256",
        ):
            command.add_argument(
                f"--{option}",
                required=True,
                action=StoreOnce,
            )

    def add_dependency_capability_authority(
        command: argparse.ArgumentParser,
    ) -> None:
        command.add_argument(
            "--dependency-capability-authority-public-key",
            required=True,
            type=Path,
            action=StoreOnce,
        )
        for option in (
            "expected-dependency-capability-authority-key-raw-sha256",
            "expected-dependency-capability-authority-key-spki-sha256",
        ):
            command.add_argument(
                f"--{option}",
                required=True,
                action=StoreOnce,
            )

    reset = commands.add_parser("reset-outputs", allow_abbrev=False)
    reset.add_argument(
        "--source-root",
        required=True,
        type=Path,
        action=StoreOnce,
    )
    reset.add_argument("--path", required=True, type=Path, action="append")

    snapshot = commands.add_parser("snapshot-source", allow_abbrev=False)
    snapshot.add_argument("--source-root", required=True, type=Path, action=StoreOnce)
    snapshot.add_argument("--snapshot-root", required=True, type=Path, action=StoreOnce)
    snapshot.add_argument("--manifest", required=True, type=Path, action=StoreOnce)
    snapshot.add_argument(
        "--source-input-manifest",
        required=True,
        type=Path,
        action=StoreOnce,
    )
    snapshot.add_argument(
        "--expected-source-input-manifest-sha256",
        required=True,
        action=StoreOnce,
    )
    add_source_authorities(snapshot)

    verify_source = commands.add_parser("verify-source-snapshot", allow_abbrev=False)
    verify_source.add_argument(
        "--snapshot-root",
        required=True,
        type=Path,
        action=StoreOnce,
    )
    verify_source.add_argument("--manifest", required=True, type=Path, action=StoreOnce)
    verify_source.add_argument(
        "--source-input-manifest",
        required=True,
        type=Path,
        action=StoreOnce,
    )
    verify_source.add_argument(
        "--expected-source-input-manifest-sha256",
        required=True,
        action=StoreOnce,
    )
    add_source_authorities(verify_source)

    plan = commands.add_parser("record-oci-build-plan", allow_abbrev=False)
    plan.add_argument("--source-snapshot", required=True, type=Path, action=StoreOnce)
    plan.add_argument("--source-manifest", required=True, type=Path, action=StoreOnce)
    plan.add_argument(
        "--source-input-manifest",
        required=True,
        type=Path,
        action=StoreOnce,
    )
    plan.add_argument(
        "--expected-source-input-manifest-sha256",
        required=True,
        action=StoreOnce,
    )
    add_source_authorities(plan)
    plan.add_argument(
        "--dependency-bundle-manifest",
        required=True,
        type=Path,
        action=StoreOnce,
    )
    add_dependency_capability_authority(plan)
    plan.add_argument(
        "--build-watchdog-contract",
        required=True,
        type=Path,
        action=StoreOnce,
    )
    plan.add_argument(
        "--apparmor-profile",
        required=True,
        type=Path,
        action=StoreOnce,
    )
    plan.add_argument(
        "--seccomp-profile",
        required=True,
        type=Path,
        action=StoreOnce,
    )
    plan.add_argument("--out", required=True, type=Path, action=StoreOnce)

    def add_candidate_inputs(
        command: argparse.ArgumentParser,
        *,
        recording: bool,
    ) -> None:
        command.add_argument(
            "--build-plan", required=True, type=Path, action=StoreOnce
        )
        command.add_argument(
            "--build-watchdog-receipt",
            required=True,
            type=Path,
            action=StoreOnce,
        )
        command.add_argument(
            "--build-watchdog-public-key",
            required=True,
            type=Path,
            action=StoreOnce,
        )
        command.add_argument(
            "--expected-build-watchdog-key-spki-sha256",
            required=True,
            action=StoreOnce,
        )
        command.add_argument(
            "--expected-build-watchdog-key-raw-sha256",
            required=True,
            action=StoreOnce,
        )
        command.add_argument(
            "--expected-build-watchdog-challenge-sha256",
            required=True,
            action=StoreOnce,
        )
        command.add_argument(
            "--expected-build-watchdog-capability-sha256",
            required=True,
            action=StoreOnce,
        )
        command.add_argument(
            "--build-watchdog-contract",
            required=True,
            type=Path,
            action=StoreOnce,
        )
        command.add_argument(
            "--source-snapshot",
            required=True,
            type=Path,
            action=StoreOnce,
        )
        command.add_argument(
            "--source-manifest",
            required=True,
            type=Path,
            action=StoreOnce,
        )
        command.add_argument(
            "--source-input-manifest",
            required=True,
            type=Path,
            action=StoreOnce,
        )
        command.add_argument(
            "--expected-source-input-manifest-sha256",
            required=True,
            action=StoreOnce,
        )
        add_source_authorities(command)
        command.add_argument(
            "--dependency-bundle-manifest",
            required=True,
            type=Path,
            action=StoreOnce,
        )
        add_dependency_capability_authority(command)
        command.add_argument(
            "--apparmor-profile",
            required=True,
            type=Path,
            action=StoreOnce,
        )
        command.add_argument(
            "--seccomp-profile",
            required=True,
            type=Path,
            action=StoreOnce,
        )
        command.add_argument(
            "--oci-bundle-manifest",
            required=True,
            type=Path,
            action=StoreOnce,
        )
        command.add_argument(
            "--oci-root", required=True, type=Path, action=StoreOnce
        )
        if recording:
            command.add_argument(
                "--candidate-file-out",
                required=True,
                type=Path,
                action=StoreOnce,
            )
        else:
            command.add_argument(
                "--candidate-file",
                required=True,
                type=Path,
                action=StoreOnce,
            )

    candidate = commands.add_parser("record-candidate-manifest", allow_abbrev=False)
    add_candidate_inputs(candidate, recording=True)
    candidate.add_argument("--out", required=True, type=Path, action=StoreOnce)

    verify_candidate = commands.add_parser(
        "verify-candidate-manifest",
        allow_abbrev=False,
    )
    verify_candidate.add_argument(
        "--manifest",
        required=True,
        type=Path,
        action=StoreOnce,
    )
    add_candidate_inputs(verify_candidate, recording=False)

    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    try:
        if args.command == "reset-outputs":
            result = _reset_outputs(args)
        elif args.command == "snapshot-source":
            result = _snapshot_source(args)
        elif args.command == "verify-source-snapshot":
            result = _verify_source(args)
        elif args.command == "record-oci-build-plan":
            result = _record_build_plan(args)
        elif args.command == "record-candidate-manifest":
            result = _record_candidate(args)
        elif args.command == "verify-candidate-manifest":
            result = _verify_candidate(args)
        else:
            raise VerificationError(f"unsupported command: {args.command}")
        print(
            _canonical_json({"ok": True, "result": result}).decode("ascii"),
            flush=True,
        )
    except (OSError, TypeError, VerificationError, ValueError) as exc:
        raise SystemExit(str(exc)) from exc


if __name__ == "__main__":
    main()
