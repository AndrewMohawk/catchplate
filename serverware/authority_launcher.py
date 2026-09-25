from __future__ import annotations

import argparse
import base64
import fcntl
import hashlib
import importlib.abc
import importlib.machinery
import importlib.util
import json
import os
import socket
import stat
import sys
import time
from datetime import datetime, timezone
from pathlib import PurePosixPath
from types import ModuleType
from typing import Any, Callable, Mapping


LAUNCH_MANIFEST_SCHEMA = (
    "serverware.signedPolicyAuthorityLaunchManifest/v4"
)
LAUNCH_PAYLOAD_SCHEMA = "serverware.policyAuthorityLaunchManifest/v4"
GENERATION_CONTEXT_SCHEMA = (
    "serverware.authorityGenerationLaunchContext/v2"
)
MAX_MANIFEST_BYTES = 64 * 1024 * 1024
MAX_STAGE_ZERO_HANDOFF_BYTES = 1024 * 1024
MAX_LAUNCH_IDENTITY_CERTIFICATE_BYTES = 1024 * 1024
MAX_CLOSURE_FILES = 32768
MAX_CLOSURE_FILE_BYTES = 64 * 1024 * 1024
MAX_NATIVE_MAPPING_BYTES = 64 * 1024 * 1024
TRUST_PURPOSES = frozenset(
    {
        "artifact-bundle",
        "generation",
        "artifact-verification-receipt",
        "provisioning-receipt",
        "launch-identity",
    }
)
PROCESS_MODES = {
    "runtime": "policy-authority-runtime",
    "verifier": "policy-authority-verifier",
    "planner": "policy-authority-planner",
    "planner-writer": "policy-authority-planner-writer",
    "issuer": "policy-authority-issuer",
    "executor": "policy-authority-executor",
    "witness": "policy-authority-replay-witness",
}
ROLE_IDENTITIES = {
    "runtime": (65524, 65524),
    "verifier": (65520, 65520),
    "planner": (65518, 65518),
    "planner-writer": (65519, 65519),
    "issuer": (65521, 65521),
    "executor": (65522, 65522),
    "witness": (65523, 65523),
}
ROLE_SUPPLEMENTARY_GIDS = {
    "runtime": (65520,),
    "verifier": (65518, 65521, 65522, 65523),
    "planner": (65519,),
    "planner-writer": (),
    "issuer": (65523,),
    "executor": (65523,),
    "witness": (),
}
ROLE_SOCKET_PATHS = {
    "runtime": "/run/serverware/authority-runtime/authority.sock",
    "verifier": "/run/serverware/authority-verifier/authority.sock",
    "planner": "/run/serverware/authority-planner/authority.sock",
    "planner-writer":
        "/run/serverware/authority-planner-writer/authority.sock",
    "issuer": "/run/serverware/authority-issuer/authority.sock",
    "executor": "/run/serverware/authority-executor/authority.sock",
    "witness": "/run/serverware/authority-witness/authority.sock",
}
ROLE_LISTENER_NAMES = {
    role: f"serverware-authority-{role}"
    for role in ROLE_SOCKET_PATHS
}
REQUIRED_MEMFD_SEALS = (
    fcntl.F_SEAL_SEAL
    | fcntl.F_SEAL_SHRINK
    | fcntl.F_SEAL_GROW
    | fcntl.F_SEAL_WRITE
)
ROLE_CREDENTIAL_DESCRIPTOR_NAMES = {
    "runtime": frozenset(
        {
            "SERVERWARE_POLICY_AUTHORITY_LAUNCH_ROOT_PUBLIC_KEY_FD",
            "SERVERWARE_POLICY_AUTHORITY_LAUNCH_MANIFEST_FD",
            "SERVERWARE_POLICY_AUTHORITY_RUNTIME_ROOT_PUBLIC_KEY_FD",
            "SERVERWARE_POLICY_AUTHORITY_RUNTIME_TRUST_FD",
        }
    ),
    "verifier": frozenset(
        {
            "SERVERWARE_POLICY_AUTHORITY_LAUNCH_ROOT_PUBLIC_KEY_FD",
            "SERVERWARE_POLICY_AUTHORITY_LAUNCH_MANIFEST_FD",
            "SERVERWARE_POLICY_AUTHORITY_ROOT_PUBLIC_KEY_FD",
            "SERVERWARE_POLICY_AUTHORITY_CONFIG_FD",
            "SERVERWARE_POLICY_AUTHORITY_ATTESTATION_FD",
            "SERVERWARE_POLICY_AUTHORITY_VERIFIER_SIGNING_KEY_FD",
            "SERVERWARE_POLICY_AUTHORITY_VERIFIER_READ_POSTGRES_DSN_FD",
        }
    ),
    "planner": frozenset(
        {
            "SERVERWARE_POLICY_AUTHORITY_LAUNCH_ROOT_PUBLIC_KEY_FD",
            "SERVERWARE_POLICY_AUTHORITY_LAUNCH_MANIFEST_FD",
            "SERVERWARE_POLICY_AUTHORITY_ROOT_PUBLIC_KEY_FD",
            "SERVERWARE_POLICY_AUTHORITY_CONFIG_FD",
            "SERVERWARE_POLICY_AUTHORITY_ATTESTATION_FD",
            "SERVERWARE_POLICY_AUTHORITY_PLANNER_SIGNING_KEY_FD",
            "SERVERWARE_POLICY_AUTHORITY_PLANNER_READ_POSTGRES_DSN_FD",
        }
    ),
    "planner-writer": frozenset(
        {
            "SERVERWARE_POLICY_AUTHORITY_LAUNCH_ROOT_PUBLIC_KEY_FD",
            "SERVERWARE_POLICY_AUTHORITY_LAUNCH_MANIFEST_FD",
            "SERVERWARE_POLICY_AUTHORITY_ROOT_PUBLIC_KEY_FD",
            "SERVERWARE_POLICY_AUTHORITY_CONFIG_FD",
            "SERVERWARE_POLICY_AUTHORITY_ATTESTATION_FD",
            "SERVERWARE_POLICY_AUTHORITY_PLANNER_WRITER_SIGNING_KEY_FD",
            "SERVERWARE_POLICY_AUTHORITY_PLANNER_WRITER_POSTGRES_DSN_FD",
        }
    ),
    "issuer": frozenset(
        {
            "SERVERWARE_POLICY_AUTHORITY_LAUNCH_ROOT_PUBLIC_KEY_FD",
            "SERVERWARE_POLICY_AUTHORITY_LAUNCH_MANIFEST_FD",
            "SERVERWARE_POLICY_AUTHORITY_ROOT_PUBLIC_KEY_FD",
            "SERVERWARE_POLICY_AUTHORITY_CONFIG_FD",
            "SERVERWARE_POLICY_AUTHORITY_ATTESTATION_FD",
            "SERVERWARE_POLICY_AUTHORITY_CAPABILITY_ISSUER_POSTGRES_DSN_FD",
        }
    ),
    "executor": frozenset(
        {
            "SERVERWARE_POLICY_AUTHORITY_LAUNCH_ROOT_PUBLIC_KEY_FD",
            "SERVERWARE_POLICY_AUTHORITY_LAUNCH_MANIFEST_FD",
            "SERVERWARE_POLICY_AUTHORITY_ROOT_PUBLIC_KEY_FD",
            "SERVERWARE_POLICY_AUTHORITY_CONFIG_FD",
            "SERVERWARE_POLICY_AUTHORITY_ATTESTATION_FD",
            "SERVERWARE_POLICY_AUTHORITY_EXECUTOR_POSTGRES_DSN_FD",
        }
    ),
    "witness": frozenset(
        {
            "SERVERWARE_POLICY_AUTHORITY_LAUNCH_ROOT_PUBLIC_KEY_FD",
            "SERVERWARE_POLICY_AUTHORITY_LAUNCH_MANIFEST_FD",
            "SERVERWARE_POLICY_AUTHORITY_WITNESS_ROOT_PUBLIC_KEY_FD",
            "SERVERWARE_POLICY_AUTHORITY_WITNESS_CONFIG_FD",
            "SERVERWARE_POLICY_AUTHORITY_WITNESS_SIGNING_KEY_FD",
        }
    ),
}


class LaunchError(RuntimeError):
    pass


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def _domain_digest(domain: str, *frames: bytes) -> str:
    digest = hashlib.sha256()
    encoded_domain = domain.encode("ascii")
    digest.update(len(encoded_domain).to_bytes(8, "big"))
    digest.update(encoded_domain)
    for frame in frames:
        digest.update(len(frame).to_bytes(8, "big"))
        digest.update(frame)
    return "sha256:" + digest.hexdigest()


def _is_digest(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 71
        and value.startswith("sha256:")
        and all(
            character in "0123456789abcdef"
            for character in value[7:]
        )
    )


def _boot_identity_digest() -> str:
    try:
        with open(
            "/proc/sys/kernel/random/boot_id",
            "r",
            encoding="ascii",
        ) as handle:
            boot_id = handle.read(128).strip().lower()
    except OSError as exc:
        raise LaunchError("Linux boot identity is unavailable") from exc
    if (
        len(boot_id) != 36
        or any(
            character not in "0123456789abcdef-"
            for character in boot_id
        )
    ):
        raise LaunchError("Linux boot identity is malformed")
    return _domain_digest(
        "serverware.policyAuthorityBootIdentity/v1",
        boot_id.encode("ascii"),
    )


def _process_identity(pid: int) -> tuple[int, int, str]:
    try:
        with open(
            f"/proc/{pid}/stat",
            "r",
            encoding="ascii",
        ) as handle:
            stat_value = handle.read(16 * 1024)
        closing = stat_value.rfind(")")
        fields = stat_value[closing + 2 :].split()
        start_time_ticks = int(fields[19], 10)
        pid_namespace_inode = os.stat(
            f"/proc/{pid}/ns/pid",
            follow_symlinks=True,
        ).st_ino
    except (OSError, ValueError, IndexError) as exc:
        raise LaunchError("authority process identity is unavailable") from exc
    if (
        closing < 1
        or start_time_ticks <= 0
        or pid_namespace_inode <= 0
    ):
        raise LaunchError("authority process identity is invalid")
    material = {
        "pid": pid,
        "startTimeTicks": start_time_ticks,
        "pidNamespaceInode": pid_namespace_inode,
    }
    return (
        start_time_ticks,
        pid_namespace_inode,
        _domain_digest(
            "serverware.policyAuthorityProcessIdentity/v1",
            _canonical(material),
        ),
    )


def _b64url_decode(value: object, *, size: int) -> bytes:
    if not isinstance(value, str):
        raise LaunchError("launch signature is not base64url")
    try:
        decoded = base64.urlsafe_b64decode(
            value + "=" * (-len(value) % 4)
        )
    except (ValueError, TypeError) as exc:
        raise LaunchError("launch signature is not base64url") from exc
    canonical = base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=")
    if len(decoded) != size or canonical != value:
        raise LaunchError("launch signature has the wrong size")
    return decoded


_ED25519_Q = 2**255 - 19
_ED25519_L = 2**252 + 27742317777372353535851937790883648493
_ED25519_D = (
    -121665 * pow(121666, _ED25519_Q - 2, _ED25519_Q)
) % _ED25519_Q
_ED25519_I = pow(2, (_ED25519_Q - 1) // 4, _ED25519_Q)
_ED25519_B_Y = 4 * pow(5, _ED25519_Q - 2, _ED25519_Q) % _ED25519_Q


def _ed25519_xrecover(y: int) -> int:
    xx = (y * y - 1) * pow(
        _ED25519_D * y * y + 1,
        _ED25519_Q - 2,
        _ED25519_Q,
    )
    x = pow(xx, (_ED25519_Q + 3) // 8, _ED25519_Q)
    if (x * x - xx) % _ED25519_Q != 0:
        x = x * _ED25519_I % _ED25519_Q
    if x & 1:
        x = _ED25519_Q - x
    return x


_ED25519_B = (_ed25519_xrecover(_ED25519_B_Y), _ED25519_B_Y)


def _ed25519_decode_point(value: bytes) -> tuple[int, int]:
    if len(value) != 32:
        raise LaunchError("Ed25519 point has the wrong size")
    encoded = int.from_bytes(value, "little")
    y = encoded & ((1 << 255) - 1)
    if y >= _ED25519_Q:
        raise LaunchError("Ed25519 point is not canonical")
    x = _ed25519_xrecover(y)
    if (x & 1) != (encoded >> 255):
        x = _ED25519_Q - x
    if (
        (-x * x + y * y - 1 - _ED25519_D * x * x * y * y)
        % _ED25519_Q
        != 0
    ):
        raise LaunchError("Ed25519 point is not on the curve")
    return x, y


def _ed25519_add(
    first: tuple[int, int],
    second: tuple[int, int],
) -> tuple[int, int]:
    x1, y1 = first
    x2, y2 = second
    product = _ED25519_D * x1 * x2 * y1 * y2
    return (
        (x1 * y2 + x2 * y1)
        * pow(1 + product, _ED25519_Q - 2, _ED25519_Q)
        % _ED25519_Q,
        (y1 * y2 + x1 * x2)
        * pow(1 - product, _ED25519_Q - 2, _ED25519_Q)
        % _ED25519_Q,
    )


def _ed25519_scalar_multiply(
    point: tuple[int, int],
    scalar: int,
) -> tuple[int, int]:
    result = (0, 1)
    addend = point
    while scalar:
        if scalar & 1:
            result = _ed25519_add(result, addend)
        addend = _ed25519_add(addend, addend)
        scalar >>= 1
    return result


def _ed25519_encode_point(point: tuple[int, int]) -> bytes:
    x, y = point
    encoded = y | ((x & 1) << 255)
    return encoded.to_bytes(32, "little")


def _verify_ed25519(
    public_key: bytes,
    signature: bytes,
    message: bytes,
) -> None:
    if len(public_key) != 32 or len(signature) != 64:
        raise LaunchError("Ed25519 signature input has the wrong size")
    encoded_r = signature[:32]
    scalar_s = int.from_bytes(signature[32:], "little")
    if scalar_s >= _ED25519_L:
        raise LaunchError("Ed25519 scalar is not canonical")
    public_point = _ed25519_decode_point(public_key)
    r_point = _ed25519_decode_point(encoded_r)
    for label, point in (
        ("public key", public_point),
        ("signature point", r_point),
    ):
        if point == (0, 1) or _ed25519_scalar_multiply(
            point, _ED25519_L
        ) != (0, 1):
            raise LaunchError(f"Ed25519 {label} is not prime order")
    challenge = int.from_bytes(
        hashlib.sha512(encoded_r + public_key + message).digest(),
        "little",
    ) % _ED25519_L
    if _ed25519_scalar_multiply(_ED25519_B, scalar_s) != _ed25519_add(
        r_point,
        _ed25519_scalar_multiply(public_point, challenge),
    ):
        raise LaunchError("launch manifest signature is invalid")


def _read_descriptor(environment_name: str, maximum: int) -> bytes:
    descriptor_value = os.environ.get(environment_name + "_FD", "")
    if (
        not descriptor_value
        or os.environ.get(environment_name + "_PATH")
    ):
        raise LaunchError(
            f"{environment_name} must be descriptor-delivered"
        )
    try:
        descriptor = int(descriptor_value)
    except ValueError as exc:
        raise LaunchError(
            f"{environment_name}_FD is invalid"
        ) from exc
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        raise LaunchError(
            f"{environment_name} descriptor is mutable"
        )
    value = os.pread(descriptor, maximum + 1, 0)
    metadata_after = os.fstat(descriptor)
    if (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
    ) != (
        metadata_after.st_dev,
        metadata_after.st_ino,
        metadata_after.st_size,
        metadata_after.st_mtime_ns,
    ):
        raise LaunchError(
            f"{environment_name} changed while read"
        )
    if len(value) > maximum:
        raise LaunchError(f"{environment_name} is oversized")
    return value


def _open_no_symlink(path: str) -> int:
    pure_path = PurePosixPath(path)
    if not pure_path.is_absolute() or ".." in pure_path.parts:
        raise LaunchError("closure path is not canonical and absolute")
    directory = os.open(
        "/",
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC,
    )
    try:
        for component in pure_path.parts[1:-1]:
            next_directory = os.open(
                component,
                os.O_RDONLY
                | os.O_DIRECTORY
                | os.O_CLOEXEC
                | os.O_NOFOLLOW,
                dir_fd=directory,
            )
            os.close(directory)
            directory = next_directory
        return os.open(
            pure_path.name,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=directory,
        )
    finally:
        os.close(directory)


def _read_file(descriptor: int, expected_size: int) -> bytes:
    if not 0 <= expected_size <= MAX_CLOSURE_FILE_BYTES:
        raise LaunchError("closure file size is outside its bound")
    value = bytearray()
    offset = 0
    while len(value) <= expected_size:
        chunk = os.pread(
            descriptor,
            min(1024 * 1024, expected_size + 1 - len(value)),
            offset,
        )
        if not chunk:
            break
        value.extend(chunk)
        offset += len(chunk)
    if len(value) != expected_size:
        raise LaunchError("closure file size changed")
    return bytes(value)


def _seal_bytes(name: str, value: bytes, *, mode: int = 0o400) -> int:
    if not hasattr(os, "memfd_create"):
        raise LaunchError("sealed memfd support is required")
    descriptor = os.memfd_create(
        name,
        flags=os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING,
    )
    offset = 0
    while offset < len(value):
        written = os.write(descriptor, value[offset:])
        if written <= 0:
            os.close(descriptor)
            raise LaunchError("closure memfd write was incomplete")
        offset += written
    os.fchmod(descriptor, mode)
    fcntl.fcntl(
        descriptor,
        fcntl.F_ADD_SEALS,
        REQUIRED_MEMFD_SEALS,
    )
    return descriptor


class _SealedSourceLoader(importlib.abc.SourceLoader):
    def __init__(
        self,
        fullname: str,
        descriptor: int,
        original_path: str,
    ) -> None:
        self.fullname = fullname
        self.descriptor = descriptor
        self.original_path = original_path

    def get_filename(self, fullname: str) -> str:
        if fullname != self.fullname:
            raise ImportError(fullname)
        return f"/proc/self/fd/{self.descriptor}"

    def get_data(self, path: str) -> bytes:
        del path
        metadata = os.fstat(self.descriptor)
        return os.pread(self.descriptor, metadata.st_size, 0)

    def path_stats(self, path: str) -> dict[str, int]:
        del path
        metadata = os.fstat(self.descriptor)
        return {"mtime": 0, "size": metadata.st_size}

    def set_data(self, path: str, data: bytes) -> None:
        del path, data


class _SealedClosureFinder(importlib.abc.MetaPathFinder):
    def __init__(self, entries: dict[str, dict[str, Any]]) -> None:
        self.entries = entries

    def find_spec(
        self,
        fullname: str,
        path: object = None,
        target: object = None,
    ) -> importlib.machinery.ModuleSpec | None:
        del path, target
        entry = self.entries.get(fullname)
        if entry is None:
            if any(
                module.startswith(fullname + ".")
                for module in self.entries
            ):
                namespace = importlib.machinery.ModuleSpec(
                    fullname,
                    loader=None,
                    is_package=True,
                )
                namespace.submodule_search_locations = []
                return namespace
            if (
                fullname in sys.builtin_module_names
                or importlib.machinery.FrozenImporter.find_spec(
                    fullname
                )
                is not None
            ):
                return None
            raise ImportError(
                f"{fullname} is outside the measured import closure"
            )
        descriptor = int(entry["descriptor"])
        kind = entry["kind"]
        if kind == "source":
            loader: importlib.abc.Loader = _SealedSourceLoader(
                fullname,
                descriptor,
                entry["path"],
            )
        elif kind == "extension":
            loader = importlib.machinery.ExtensionFileLoader(
                fullname,
                f"/proc/self/fd/{descriptor}",
            )
        else:
            return None
        return importlib.util.spec_from_loader(
            fullname,
            loader,
            is_package=bool(entry["isPackage"]),
        )


def _read_process_mapping(start: int, end: int) -> bytes:
    size = end - start
    if not 0 < size <= MAX_NATIVE_MAPPING_BYTES:
        raise LaunchError("executable memory mapping is outside its bound")
    try:
        descriptor = os.open(
            "/proc/self/mem",
            os.O_RDONLY | os.O_CLOEXEC,
        )
        try:
            value = os.pread(descriptor, size, start)
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise LaunchError(
            "executable memory mapping cannot be measured"
        ) from exc
    if len(value) != size:
        raise LaunchError("executable memory mapping measurement is partial")
    return value


def _mapped_file_digest(
    *,
    address_range: str,
    device: str,
    inode: str,
) -> str:
    try:
        expected_major_text, expected_minor_text = device.split(":", 1)
        expected_major = int(expected_major_text, 16)
        expected_minor = int(expected_minor_text, 16)
        expected_inode = int(inode, 10)
    except (ValueError, TypeError) as exc:
        raise LaunchError("native mapping identity is malformed") from exc
    if expected_inode <= 0:
        raise LaunchError("file-backed executable mapping has no inode")
    try:
        descriptor = os.open(
            f"/proc/self/map_files/{address_range}",
            os.O_RDONLY | os.O_CLOEXEC,
        )
    except OSError as exc:
        raise LaunchError(
            "mapped executable inode cannot be opened"
        ) from exc
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_ino != expected_inode
            or os.major(metadata.st_dev) != expected_major
            or os.minor(metadata.st_dev) != expected_minor
            or not 0 <= metadata.st_size <= MAX_NATIVE_MAPPING_BYTES
        ):
            raise LaunchError("mapped executable inode identity changed")
        value = _read_file(descriptor, metadata.st_size)
        metadata_after = os.fstat(descriptor)
        if (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_size,
        ) != (
            metadata_after.st_dev,
            metadata_after.st_ino,
            metadata_after.st_size,
        ):
            raise LaunchError("mapped executable inode changed while read")
    finally:
        os.close(descriptor)
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _verify_native_mappings(
    expected: dict[str, str],
    *,
    require_exact: bool,
) -> None:
    if (
        "[vsyscall]" in expected
        or any(
            not isinstance(path, str)
            or not path
            or not isinstance(digest, str)
            or len(digest) != 71
            or not digest.startswith("sha256:")
            or any(
                character not in "0123456789abcdef"
                for character in digest[7:]
            )
            for path, digest in expected.items()
        )
        or len(expected) != len(set(expected))
    ):
        raise LaunchError("native mapping manifest is not canonical")
    try:
        with open("/proc/self/maps", "r", encoding="ascii") as handle:
            lines = handle.readlines()
    except OSError as exc:
        raise LaunchError(
            "Linux native mapping inventory is unavailable"
        ) from exc
    observed: dict[str, str] = {}
    observed_inodes: dict[str, tuple[str, str]] = {}
    for line in lines:
        fields = line.rstrip("\n").split(maxsplit=5)
        if len(fields) < 5:
            raise LaunchError("native mapping inventory is malformed")
        permissions = fields[1]
        if "x" not in permissions:
            continue
        if "w" in permissions or len(fields) != 6:
            raise LaunchError(
                "anonymous or writable executable mapping is forbidden"
            )
        address_range, _offset, device, inode, path = (
            fields[0],
            fields[2],
            fields[3],
            fields[4],
            fields[5],
        )
        if path == "[vsyscall]":
            raise LaunchError(
                "authority host must boot with vsyscall=none"
            )
        if path == "[vdso]":
            try:
                start_text, end_text = address_range.split("-", 1)
                start = int(start_text, 16)
                end = int(end_text, 16)
            except (ValueError, TypeError) as exc:
                raise LaunchError(
                    "kernel executable mapping range is malformed"
                ) from exc
            digest = "sha256:" + hashlib.sha256(
                _read_process_mapping(start, end)
            ).hexdigest()
            inode_identity = ("kernel", address_range)
        elif path.startswith("/"):
            digest = _mapped_file_digest(
                address_range=address_range,
                device=device,
                inode=inode,
            )
            inode_identity = (device, inode)
        else:
            raise LaunchError(
                "unmeasurable executable mapping is forbidden"
            )
        previous_digest = observed.get(path)
        previous_inode = observed_inodes.get(path)
        if (
            previous_digest is not None
            and previous_digest != digest
            or previous_inode is not None
            and previous_inode != inode_identity
        ):
            raise LaunchError("native mapping path identity is ambiguous")
        observed[path] = digest
        observed_inodes[path] = inode_identity
    if (
        any(
            expected.get(path) != digest
            for path, digest in observed.items()
        )
        or require_exact
        and observed != expected
    ):
        raise LaunchError("loaded native mapping closure changed")


def _require_sealed_descriptor(descriptor: int, label: str) -> None:
    try:
        seals = fcntl.fcntl(descriptor, fcntl.F_GET_SEALS)
    except OSError as exc:
        raise LaunchError(f"{label} is not a sealable memfd") from exc
    if seals & REQUIRED_MEMFD_SEALS != REQUIRED_MEMFD_SEALS:
        raise LaunchError(f"{label} is not immutable")


def _consume_bootstrap_descriptor(
    expected_digest: object,
    descriptor: int,
) -> None:
    if (
        not isinstance(descriptor, int)
        or isinstance(descriptor, bool)
        or descriptor < 3
    ):
        raise LaunchError("authority bootstrap descriptor is invalid")
    try:
        metadata = os.fstat(descriptor)
        if (
            descriptor < 3
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_size > MAX_MANIFEST_BYTES
        ):
            raise LaunchError("authority bootstrap descriptor is not trusted")
        _require_sealed_descriptor(descriptor, "authority bootstrap")
        value = _read_file(descriptor, metadata.st_size)
        digest = "sha256:" + hashlib.sha256(value).hexdigest()
        if digest != expected_digest:
            raise LaunchError("authority bootstrap digest changed")
    finally:
        try:
            os.close(descriptor)
        except OSError:
            pass


def _drop_role_identity(role: str) -> None:
    uid, gid = ROLE_IDENTITIES[role]
    supplementary_gids = ROLE_SUPPLEMENTARY_GIDS[role]
    if os.geteuid() != 0 or os.getegid() != 0:
        raise LaunchError("authority measured launcher must begin as root")
    os.setgroups(list(supplementary_gids))
    os.setgid(gid)
    os.setuid(uid)
    if (
        os.geteuid() != uid
        or os.getegid() != gid
        or tuple(sorted(os.getgroups()))
        != tuple(sorted(supplementary_gids))
    ):
        raise LaunchError("authority measured identity drop was not exact")
    values: dict[str, str] = {}
    with open("/proc/self/status", "r", encoding="ascii") as handle:
        for line in handle:
            name, separator, value = line.partition(":")
            if separator and name in {
                "CapEff",
                "CapInh",
                "CapPrm",
                "CapAmb",
                "NoNewPrivs",
            }:
                values[name] = value.strip()
    if (
        set(values)
        != {"CapEff", "CapInh", "CapPrm", "CapAmb", "NoNewPrivs"}
        or any(
            int(values[name], 16) != 0
            for name in {"CapEff", "CapInh", "CapPrm", "CapAmb"}
        )
        or values["NoNewPrivs"] != "1"
    ):
        raise LaunchError(
            "authority runtime retained privilege after identity drop"
        )


def _canonical_timestamp_now() -> str:
    return datetime.now(timezone.utc).replace(
        microsecond=0
    ).strftime("%Y-%m-%dT%H:%M:%SZ")


def _require_contract_callable(
    module: ModuleType,
    name: str,
) -> Callable[..., Any]:
    value = getattr(module, name, None)
    if not callable(value):
        raise LaunchError(
            f"measured authority contract lacks {name}"
        )
    return value

def _environment_descriptor(name: str) -> int:
    value = os.environ.get(name + "_FD", "")
    if not value or os.environ.get(name + "_PATH"):
        raise LaunchError(f"{name} must be descriptor-delivered")
    try:
        descriptor = int(value)
    except ValueError as exc:
        raise LaunchError(f"{name}_FD is invalid") from exc
    if descriptor < 3:
        raise LaunchError(f"{name}_FD is reserved")
    return descriptor


def _require_stage_zero_descriptor(
    name: str,
    maximum: int,
) -> tuple[int, bytes]:
    descriptor = _environment_descriptor(name)
    metadata = os.fstat(descriptor)
    try:
        seals = fcntl.fcntl(descriptor, fcntl.F_GET_SEALS)
    except OSError as exc:
        raise LaunchError(
            f"{name} is not a sealed stage-zero descriptor"
        ) from exc
    value = _read_descriptor(name, maximum)
    if (
        metadata.st_nlink != 0
        or seals & REQUIRED_MEMFD_SEALS != REQUIRED_MEMFD_SEALS
    ):
        raise LaunchError(
            f"{name} is not immutable stage-zero material"
        )
    return descriptor, value


def _require_sealed_descriptor_number(
    descriptor: int,
    *,
    label: str,
    maximum: int,
) -> bytes:
    if (
        not isinstance(descriptor, int)
        or isinstance(descriptor, bool)
        or descriptor < 3
    ):
        raise LaunchError(f"{label} descriptor is invalid")
    metadata = os.fstat(descriptor)
    try:
        seals = fcntl.fcntl(descriptor, fcntl.F_GET_SEALS)
    except OSError as exc:
        raise LaunchError(f"{label} is not a sealed memfd") from exc
    value = os.pread(descriptor, maximum + 1, 0)
    metadata_after = os.fstat(descriptor)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 0
        or metadata.st_size != len(value)
        or len(value) > maximum
        or seals & REQUIRED_MEMFD_SEALS != REQUIRED_MEMFD_SEALS
        or (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_size,
            metadata.st_mtime_ns,
        )
        != (
            metadata_after.st_dev,
            metadata_after.st_ino,
            metadata_after.st_size,
            metadata_after.st_mtime_ns,
        )
    ):
        raise LaunchError(f"{label} is not immutable exact bytes")
    return value


def _listener_identity(
    role: str,
    binding: object,
) -> int:
    required = {
        "name",
        "fd",
        "runtimePath",
        "activationName",
        "family",
        "socketType",
        "accepting",
        "listenPid",
        "listenFds",
        "listenFdNames",
        "device",
        "inode",
        "mode",
        "uid",
        "gid",
    }
    descriptor = 3
    uid, gid = ROLE_IDENTITIES[role]
    if (
        not isinstance(binding, dict)
        or set(binding) != required
        or not isinstance(binding.get("name"), str)
        or not binding["name"]
        or binding.get("fd") != descriptor
        or binding.get("runtimePath") != ROLE_SOCKET_PATHS[role]
        or binding.get("activationName")
            != ROLE_LISTENER_NAMES[role]
        or binding.get("family") != "AF_UNIX"
        or binding.get("socketType") != "SOCK_STREAM"
        or binding.get("accepting") is not True
        or binding.get("listenPid") != os.getpid()
        or binding.get("listenFds") != 1
        or binding.get("listenFdNames")
            != [ROLE_LISTENER_NAMES[role]]
        or binding.get("mode") != 0o660
        or binding.get("uid") != uid
        or binding.get("gid") != gid
    ):
        raise LaunchError("socket activation manifest binding changed")
    metadata = os.fstat(descriptor)
    activated = socket.fromfd(
        descriptor,
        socket.AF_UNIX,
        socket.SOCK_STREAM,
    )
    try:
        socket_path = activated.getsockname()
        if isinstance(socket_path, bytes):
            socket_path = os.fsdecode(socket_path)
        if (
            not stat.S_ISSOCK(metadata.st_mode)
            or activated.family != socket.AF_UNIX
            or activated.type & socket.SOCK_STREAM != socket.SOCK_STREAM
            or activated.getsockopt(
                socket.SOL_SOCKET,
                socket.SO_ACCEPTCONN,
            )
            != 1
            or socket_path != ROLE_SOCKET_PATHS[role]
        ):
            raise LaunchError("activated authority listener changed")
    finally:
        activated.close()
    path_metadata = os.stat(
        ROLE_SOCKET_PATHS[role],
        follow_symlinks=False,
    )
    if (
        not stat.S_ISSOCK(path_metadata.st_mode)
        or path_metadata.st_uid != uid
        or path_metadata.st_gid != gid
        or stat.S_IMODE(path_metadata.st_mode) != 0o660
        or binding.get("device") != path_metadata.st_dev
        or binding.get("inode") != path_metadata.st_ino
    ):
        raise LaunchError("activated authority socket path changed")
    return descriptor


def _load_manifest(role: str) -> tuple[dict[str, Any], str]:
    root_key = _read_descriptor(
        "SERVERWARE_POLICY_AUTHORITY_LAUNCH_ROOT_PUBLIC_KEY",
        32,
    )
    if len(root_key) != 32:
        raise LaunchError("launch root key must be raw Ed25519")
    manifest_value = _read_descriptor(
        "SERVERWARE_POLICY_AUTHORITY_LAUNCH_MANIFEST",
        MAX_MANIFEST_BYTES,
    )
    try:
        envelope = json.loads(manifest_value)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LaunchError("launch manifest is not JSON") from exc
    if (
        not isinstance(envelope, dict)
        or set(envelope) != {"schema", "payload", "signature"}
        or envelope.get("schema") != LAUNCH_MANIFEST_SCHEMA
        or not isinstance(envelope.get("payload"), dict)
        or manifest_value != _canonical(envelope)
    ):
        raise LaunchError("launch manifest envelope is not closed")
    payload = dict(envelope["payload"])
    payload_bytes = _canonical(payload)
    _verify_ed25519(
        root_key,
        _b64url_decode(envelope["signature"], size=64),
        _domain_digest(
            LAUNCH_MANIFEST_SCHEMA,
            payload_bytes,
        ).encode("ascii"),
    )
    if (
        set(payload)
        != {
            "schema",
            "role",
            "processMode",
            "runtimeUid",
            "runtimeGid",
            "supplementaryGids",
            "socketPath",
            "pythonExecutable",
            "bootstrapSha256",
            "closure",
            "packageVersions",
            "nativeExecutableMappings",
            "retainedCredentialDescriptors",
            "artifactPackage",
            "artifactTrustState",
            "artifactVerificationReceipt",
            "provisioningPlan",
            "provisioningReceipt",
            "stageZeroRequest",
        }
        or payload.get("schema") != LAUNCH_PAYLOAD_SCHEMA
        or payload.get("role") != role
        or payload.get("processMode") != PROCESS_MODES[role]
        or (
            payload.get("runtimeUid"),
            payload.get("runtimeGid"),
        )
        != ROLE_IDENTITIES[role]
        or payload.get("supplementaryGids")
        != list(ROLE_SUPPLEMENTARY_GIDS[role])
        or payload.get("socketPath") != ROLE_SOCKET_PATHS[role]
        or not isinstance(payload.get("bootstrapSha256"), str)
        or len(payload["bootstrapSha256"]) != 71
        or not payload["bootstrapSha256"].startswith("sha256:")
        or any(
            character not in "0123456789abcdef"
            for character in payload["bootstrapSha256"][7:]
        )
        or any(
            not isinstance(payload.get(name), dict)
            for name in {
                "artifactPackage",
                "artifactTrustState",
                "artifactVerificationReceipt",
                "provisioningPlan",
                "provisioningReceipt",
                "stageZeroRequest",
            }
        )
    ):
        raise LaunchError("launch manifest role binding changed")
    return payload, _domain_digest(
        LAUNCH_PAYLOAD_SCHEMA,
        payload_bytes,
    )


def _validate_canonical_launch_evidence(
    *,
    role: str,
    launch_payload: Mapping[str, Any],
    artifact_contract: ModuleType,
    stage_zero_contract: ModuleType,
    provisioning_contract: ModuleType,
) -> tuple[dict[str, Any], Any]:
    validation_time = _canonical_timestamp_now()
    expected_peer_pid = os.getpid()
    expected_peer_start_ticks, _namespace_inode, _identity_digest = (
        _process_identity(expected_peer_pid)
    )
    package = launch_payload["artifactPackage"]
    trust_state = launch_payload["artifactTrustState"]
    verification_receipt = launch_payload[
        "artifactVerificationReceipt"
    ]
    provisioning_plan = launch_payload["provisioningPlan"]
    provisioning_receipt = launch_payload["provisioningReceipt"]
    request = launch_payload["stageZeroRequest"]

    verified_package = _require_contract_callable(
        artifact_contract,
        "verify_signed_artifact_package",
    )(
        package,
        trust_state=trust_state,
        validation_time=validation_time,
    )
    if verified_package.disposition != "CurrentExactRetry":
        raise LaunchError(
            "startup requires the exact externally committed generation"
        )

    _require_contract_callable(
        provisioning_contract,
        "validate_provisioning_plan",
    )(provisioning_plan)
    _require_contract_callable(
        provisioning_contract,
        "verify_verification_receipt",
    )(
        verification_receipt,
        verified_package=verified_package,
        validation_time=validation_time,
        accepted_receipt_digests=(),
    )
    _require_contract_callable(
        provisioning_contract,
        "verify_provisioning_receipt",
    )(
        provisioning_receipt,
        plan=provisioning_plan,
        verified_package=verified_package,
        validation_time=validation_time,
        accepted_receipt_digests=(),
    )

    _require_contract_callable(
        stage_zero_contract,
        "validate_stage_zero_request",
    )(
        request,
        verified_package=verified_package,
        expected_listen_pid=expected_peer_pid,
        expected_peer_pid=expected_peer_pid,
        expected_peer_start_ticks=expected_peer_start_ticks,
        validation_time=validation_time,
    )
    generation = package["generation"]
    bundle = package["bundle"]
    generation_digest = verified_package.generation_digest
    role_entries = [
        entry
        for entry in bundle["roleManifests"]
        if entry["role"] == role
    ]
    if len(role_entries) != 1:
        raise LaunchError("artifact package has no unique role manifest")
    role_manifest = role_entries[0]
    if (
        role_manifest["role"] != role
        or role_manifest["processMode"] != PROCESS_MODES[role]
        or (
            role_manifest["runtimeUid"],
            role_manifest["runtimeGid"],
        )
        != ROLE_IDENTITIES[role]
    ):
        raise LaunchError("signed role manifest does not select this role")
    entrypoint_entries = [
        entry
        for entry in bundle["nativeClosure"]["executables"]
        if entry["runtimePath"] == role_manifest["entrypointPath"]
    ]
    if (
        len(entrypoint_entries) != 1
        or entrypoint_entries[0]["sha256"]
            != request["execution"]["executableDigest"]
    ):
        raise LaunchError(
            "role entrypoint differs from the native closure"
        )
    imports_by_module = {
        entry["module"]: entry
        for entry in bundle["pythonImportClosure"]
    }
    for closure_entry in launch_payload["closure"]:
        if closure_entry["kind"] not in {"source", "extension"}:
            continue
        imported = imports_by_module.get(closure_entry["module"])
        if (
            imported is None
            or imported["sha256"] != closure_entry["sha256"]
            or imported["kind"] != closure_entry["kind"]
            or imported["isPackage"] != closure_entry["isPackage"]
        ):
            raise LaunchError(
                "sealed Python closure differs from the artifact package"
            )
    if {
        entry["module"]
        for entry in launch_payload["closure"]
        if entry["kind"] in {"source", "extension"}
    } != set(imports_by_module):
        raise LaunchError(
            "artifact Python closure is not loaded exactly"
        )

    installed = {
        entry["path"]: entry
        for entry in provisioning_receipt["installedEntries"]
    }
    generation_root = PurePosixPath(
        provisioning_plan["destination"]["root"]
    ) / provisioning_plan["destination"][
        "generationsDirectory"
    ] / provisioning_plan["destination"]["generationDirectory"]
    generation_directories = [
        entry
        for entry in request["retainedDirectories"]
        if entry["purpose"] == "artifact-generation-root"
        and entry["runtimePath"] == generation_root.as_posix()
    ]
    directory_identity = provisioning_receipt[
        "generationDirectoryIdentity"
    ]
    if (
        len(generation_directories) != 1
        or {
            name: generation_directories[0][name]
            for name in {
                "device",
                "inode",
                "generation",
                "mode",
                "uid",
                "gid",
            }
        }
        != dict(directory_identity)
    ):
        raise LaunchError(
            "retained generation directory differs from provisioning"
        )
    role_manifest_path = (
        generation_root / role_manifest["path"]
    ).as_posix()
    if not any(
        entry["path"] == role_manifest_path
        and entry["sha256"] == role_manifest["sha256"]
        for entry in launch_payload["closure"]
    ):
        raise LaunchError(
            "role manifest bytes are outside the measured launch closure"
        )
    saw_role_manifest = False
    for retained in request["retainedFiles"]:
        try:
            relative = PurePosixPath(
                retained["runtimePath"]
            ).relative_to(generation_root).as_posix()
        except ValueError as exc:
            raise LaunchError(
                "retained authority file is outside the provisioned generation"
            ) from exc
        installed_entry = installed.get(relative)
        if (
            installed_entry is None
            or (
                retained["device"],
                retained["inode"],
                retained["generation"],
                retained["mode"],
                retained["uid"],
                retained["gid"],
                retained["size"],
                retained["sha256"],
                retained["fsVerityDigest"],
            )
            != (
                installed_entry["device"],
                installed_entry["inode"],
                installed_entry["generation"],
                installed_entry["mode"],
                installed_entry["uid"],
                installed_entry["gid"],
                installed_entry["size"],
                installed_entry["sha256"],
                installed_entry["fsVerityDigest"],
            )
        ):
            raise LaunchError(
                "retained file differs from its provisioning receipt"
            )
        if (
            relative == role_manifest["path"]
            and retained["sha256"] == role_manifest["sha256"]
            and retained["purpose"] == "role-manifest"
        ):
            saw_role_manifest = True
    if not saw_role_manifest:
        raise LaunchError("verified role manifest was not retained")
    credential_bindings = {
        entry["environmentName"]: entry
        for entry in launch_payload["retainedCredentialDescriptors"]
    }
    request_credentials = {
        entry["name"]: entry
        for entry in request["credentials"]
    }
    if set(credential_bindings) != set(request_credentials):
        raise LaunchError(
            "launch credentials differ from the stage-zero request"
        )
    for name, binding in credential_bindings.items():
        credential = request_credentials[name]
        if (
            (
                binding["descriptor"],
                binding["ownerUid"],
                binding["mode"],
                binding["size"],
                binding["sha256"],
            )
            != (
                credential["fd"],
                credential["ownerUid"],
                credential["mode"],
                credential["size"],
                credential["sha256"],
            )
            or credential["ownerRole"] != role
        ):
            raise LaunchError(
                "credential descriptor differs from stage-zero evidence"
            )
    if (
        request["execution"]["argv"] != list(sys.orig_argv)
        or request["environment"]["values"].get(
            "SERVERWARE_OPERATION_MANIFEST_DIGEST"
        )
        != verified_package.operation_manifest_digest
    ):
        raise LaunchError(
            "stage-zero execution or operation-manifest binding changed"
        )
    for name, value in request["environment"]["values"].items():
        if os.environ.get(name) != value:
            raise LaunchError(
                "stage-zero launch environment changed after handoff"
            )

    issuer_key_id = request["launch"]["identityIssuerKeyId"]
    issuer = verified_package.require_key(
        issuer_key_id,
        "launch-certificate-issuer",
        at=validation_time,
    )
    if (
        request["launch"]["identityIssuerAuthorizationDigest"]
        != issuer.authorization_digest
    ):
        raise LaunchError(
            "launch-certificate issuer authorization changed"
        )
    role_manifest_digests = {
        entry["role"]: entry["sha256"]
        for entry in bundle["roleManifests"]
    }
    generation_context = {
        "schema": GENERATION_CONTEXT_SCHEMA,
        "statement": generation,
        "digest": generation_digest,
        "sequence": verified_package.generation_sequence,
        "predecessorDigest": verified_package.predecessor_digest,
        "minimumRollbackSequence":
            verified_package.minimum_rollback_sequence,
        "validFrom": generation["validFrom"],
        "validUntil": generation["validUntil"],
        "packageDigest": verified_package.package_digest,
        "artifactBundleDigest":
            verified_package.artifact_bundle_digest,
        "operationManifestDigest":
            verified_package.operation_manifest_digest,
        "roleManifestDigests": role_manifest_digests,
        "configurationDigests":
            list(generation["configurationDigests"]),
        "configurationPayloadBindings": [
            dict(binding)
            for binding in generation["configurationPayloadBindings"]
        ],
        "trustMode": verified_package.trust_mode,
        "externalHighWater": {
            "sequence": trust_state["currentGenerationSequence"],
            "generationDigest":
                trust_state["currentGenerationDigest"],
            "packageDigest": trust_state["currentPackageDigest"],
            "minimumRollbackSequence":
                trust_state["minimumRollbackSequence"],
            "witnessCheckpointDigest":
                verified_package.witness_checkpoint_digest,
            "witnessRootDigest":
                verified_package.witness_root_digest,
            "witnessTreeSize": verified_package.witness_tree_size,
        },
        "launchIdentityIssuer": {
            "keyId": issuer_key_id,
            "publicKeyBase64Url": base64.urlsafe_b64encode(
                issuer.public_key
            ).decode("ascii").rstrip("="),
            "authorizationDigest": issuer.authorization_digest,
        },
        "artifactVerificationReceiptDigest":
            _require_contract_callable(
                provisioning_contract,
                "verification_receipt_digest",
            )(verification_receipt),
        "provisioningReceiptDigest": _require_contract_callable(
            provisioning_contract,
            "provisioning_receipt_digest",
        )(provisioning_receipt),
        "provisioningPlanDigest": _require_contract_callable(
            provisioning_contract,
            "provisioning_plan_digest",
        )(provisioning_plan),
        "stageZeroRequestDigest": _require_contract_callable(
            stage_zero_contract,
            "stage_zero_request_digest",
        )(
            request,
            verified_package=verified_package,
            expected_listen_pid=expected_peer_pid,
            expected_peer_pid=expected_peer_pid,
            expected_peer_start_ticks=expected_peer_start_ticks,
            validation_time=validation_time,
        ),
    }
    return generation_context, verified_package


def _load_canonical_stage_zero_handoff(
    *,
    role: str,
    launch_payload: Mapping[str, Any],
    handoff_descriptor: int,
    verified_package: Any,
    stage_zero_contract: ModuleType,
) -> tuple[dict[str, Any], int, dict[str, int]]:
    request = launch_payload["stageZeroRequest"]
    validation_time = _canonical_timestamp_now()
    expected_peer_pid = os.getpid()
    expected_peer_start_ticks, _namespace_inode, _identity_digest = (
        _process_identity(expected_peer_pid)
    )
    listener_descriptor = _listener_identity(
        role,
        request["listener"],
    )
    handoff_value = _require_sealed_descriptor_number(
        handoff_descriptor,
        label="native stage-zero handoff",
        maximum=MAX_STAGE_ZERO_HANDOFF_BYTES,
    )
    try:
        handoff = json.loads(handoff_value)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LaunchError("native stage-zero handoff is not JSON") from exc
    if (
        not isinstance(handoff, dict)
        or handoff_value != _canonical(handoff)
    ):
        raise LaunchError("native stage-zero handoff is not canonical")
    private_descriptor, private_key = _require_stage_zero_descriptor(
        "SERVERWARE_AUTHORITY_LAUNCH_PRIVATE_KEY",
        32,
    )
    certificate_descriptor, certificate_value = (
        _require_stage_zero_descriptor(
            "SERVERWARE_AUTHORITY_LAUNCH_CERTIFICATE",
            MAX_LAUNCH_IDENTITY_CERTIFICATE_BYTES,
        )
    )
    if (
        len(
            {
                handoff_descriptor,
                listener_descriptor,
                private_descriptor,
                certificate_descriptor,
            }
        )
        != 4
    ):
        raise LaunchError("native stage-zero descriptors overlap")
    _require_contract_callable(
        stage_zero_contract,
        "validate_stage_zero_handoff",
    )(
        handoff,
        request=request,
        verified_package=verified_package,
        expected_listen_pid=expected_peer_pid,
        expected_peer_pid=expected_peer_pid,
        expected_peer_start_ticks=expected_peer_start_ticks,
        validation_time=validation_time,
        private_key_seed=private_key,
        certificate_bytes=certificate_value,
    )
    os.environ["SERVERWARE_POLICY_AUTHORITY_LISTENER_FD"] = str(
        listener_descriptor
    )
    return (
        dict(handoff),
        listener_descriptor,
        {
            "privateKey": private_descriptor,
            "certificate": certificate_descriptor,
        },
    )


def _load_trusted_host_local_identity(
    *,
    role: str,
    launch_payload: Mapping[str, Any],
    verified_package: Any,
    stage_zero_contract: ModuleType,
) -> tuple[dict[str, Any], int, dict[str, int], dict[str, Any]]:
    if verified_package.trust_mode != "trusted-host-local":
        raise LaunchError(
            "Python trusted-host-local entry cannot claim a production mode"
        )
    request = launch_payload["stageZeroRequest"]
    validation_time = _canonical_timestamp_now()
    expected_peer_pid = os.getpid()
    expected_peer_start_ticks, _namespace_inode, _identity_digest = (
        _process_identity(expected_peer_pid)
    )
    listener_descriptor = _listener_identity(
        role,
        request["listener"],
    )
    private_descriptor, private_key = _require_stage_zero_descriptor(
        "SERVERWARE_AUTHORITY_LAUNCH_PRIVATE_KEY",
        32,
    )
    certificate_descriptor, certificate_value = (
        _require_stage_zero_descriptor(
            "SERVERWARE_AUTHORITY_LAUNCH_CERTIFICATE",
            MAX_LAUNCH_IDENTITY_CERTIFICATE_BYTES,
        )
    )
    if len(
        {
            listener_descriptor,
            private_descriptor,
            certificate_descriptor,
        }
    ) != 3:
        raise LaunchError(
            "trusted-host-local launch descriptors overlap"
        )
    _require_contract_callable(
        stage_zero_contract,
        "validate_trusted_host_local_launch_identity",
    )(
        request=request,
        verified_package=verified_package,
        expected_listen_pid=expected_peer_pid,
        expected_peer_pid=expected_peer_pid,
        expected_peer_start_ticks=expected_peer_start_ticks,
        validation_time=validation_time,
        private_key_seed=private_key,
        certificate_bytes=certificate_value,
    )
    os.environ["SERVERWARE_POLICY_AUTHORITY_LISTENER_FD"] = str(
        listener_descriptor
    )
    return (
        {},
        listener_descriptor,
        {
            "privateKey": private_descriptor,
            "certificate": certificate_descriptor,
        },
        {
            "schema": "serverware.authorityLaunchAssurance/v1",
            "trustMode": "trusted-host-local",
            "coLocated": True,
            "hardwareBacked": False,
            "nativeStageZero": False,
            "hsmBackedKeys": False,
            "teeVerified": False,
            "externalWitnessVerified": False,
        },
    )


def _enter(
    role: str,
    *,
    bootstrap_descriptor: int,
    handoff_descriptor: int | None,
    trusted_host_local: bool,
) -> int:
    flags = sys.flags
    required_isolation_flags = ("-I", "-P", "-s", "-S", "-E")
    original_arguments = list(sys.orig_argv)
    isolation_positions = []
    for isolation_flag in required_isolation_flags:
        if original_arguments.count(isolation_flag) != 1:
            raise LaunchError(
                "native stage zero did not preserve the exact Python "
                "isolation flags"
            )
        isolation_positions.append(
            original_arguments.index(isolation_flag)
        )
    if (
        isolation_positions != sorted(isolation_positions)
        or
        flags.isolated != 1
        or flags.safe_path is not True
        or flags.no_user_site != 1
        or flags.no_site != 1
        or flags.ignore_environment != 1
        or os.geteuid() != 0
        or os.getegid() != 0
    ):
        raise LaunchError(
            "authority launcher requires root and Python -I -P -s -S -E"
        )
    if os.environ.get("SERVERWARE_PROCESS_MODE"):
        raise LaunchError(
            "process mode must be derived after measured launch validation"
        )
    payload, manifest_digest = _load_manifest(role)
    entries = payload.get("closure")
    package_versions = payload.get("packageVersions")
    native_mappings = payload.get("nativeExecutableMappings")
    credential_descriptors = payload.get(
        "retainedCredentialDescriptors"
    )
    if (
        not isinstance(entries, list)
        or not 1 <= len(entries) <= MAX_CLOSURE_FILES
        or not isinstance(package_versions, dict)
        or not isinstance(native_mappings, dict)
        or not isinstance(credential_descriptors, list)
        or any(
            not isinstance(binding, dict)
            or set(binding)
            != {
                "environmentName",
                "descriptor",
                "kind",
                "ownerUid",
                "mode",
                "size",
                "sha256",
            }
            or not isinstance(binding.get("environmentName"), str)
            or not isinstance(binding.get("descriptor"), int)
            or isinstance(binding.get("descriptor"), bool)
            or binding["descriptor"] < 3
            or not isinstance(binding.get("kind"), str)
            or not binding["kind"]
            or not isinstance(binding.get("ownerUid"), int)
            or isinstance(binding.get("ownerUid"), bool)
            or binding["ownerUid"] < 0
            or not isinstance(binding.get("mode"), int)
            or isinstance(binding.get("mode"), bool)
            or not 0 <= binding["mode"] <= 0o7777
            or not isinstance(binding.get("size"), int)
            or isinstance(binding.get("size"), bool)
            or not 0 <= binding["size"] <= MAX_CLOSURE_FILE_BYTES
            or not isinstance(binding.get("sha256"), str)
            or len(binding["sha256"]) != 71
            or not binding["sha256"].startswith("sha256:")
            or any(
                character not in "0123456789abcdef"
                for character in binding["sha256"][7:]
            )
            for binding in credential_descriptors
        )
        or {
            binding["environmentName"]
            for binding in credential_descriptors
        }
            != ROLE_CREDENTIAL_DESCRIPTOR_NAMES[role]
        or len(
            {
                binding["descriptor"]
                for binding in credential_descriptors
            }
        )
            != len(credential_descriptors)
        or payload.get("pythonExecutable")
            != os.readlink("/proc/self/exe")
    ):
        raise LaunchError("launch closure contract is invalid")
    _consume_bootstrap_descriptor(
        payload.get("bootstrapSha256"),
        bootstrap_descriptor,
    )
    private_descriptor = _environment_descriptor(
        "SERVERWARE_AUTHORITY_LAUNCH_PRIVATE_KEY"
    )
    certificate_descriptor = _environment_descriptor(
        "SERVERWARE_AUTHORITY_LAUNCH_CERTIFICATE"
    )
    sealed_entries: dict[str, dict[str, Any]] = {}
    sealed_native_mappings: dict[str, str] = {}
    retained: set[int] = {
        3,
        private_descriptor,
        certificate_descriptor,
    }
    if handoff_descriptor is not None:
        retained.add(handoff_descriptor)
    if len(retained) != (4 if handoff_descriptor is not None else 3):
        raise LaunchError("stage-zero descriptor identities overlap")
    request = payload["stageZeroRequest"]
    retained_file_values = request.get("retainedFiles")
    retained_directory_values = request.get("retainedDirectories")
    mutable_state_values = request.get("mutableStateDescriptors")
    stage_zero_value = request.get("stageZero")
    if (
        not isinstance(retained_file_values, list)
        or not isinstance(retained_directory_values, list)
        or not isinstance(mutable_state_values, list)
        or not isinstance(stage_zero_value, dict)
        or any(
            not isinstance(entry, dict)
            or not isinstance(entry.get("runtimePath"), str)
            or not isinstance(entry.get("fd"), int)
            or isinstance(entry.get("fd"), bool)
            or entry["fd"] < 3
            or any(
                not isinstance(entry.get(name), int)
                or isinstance(entry.get(name), bool)
                or entry[name] < 0
                for name in {"device", "inode", "size"}
            )
            for entry in retained_file_values
        )
        or any(
            not isinstance(entry, dict)
            or not isinstance(entry.get("fd"), int)
            or isinstance(entry.get("fd"), bool)
            or entry["fd"] < 3
            for entry in retained_directory_values
        )
        or any(
            not isinstance(entry, dict)
            or not isinstance(entry.get("name"), str)
            or not entry["name"]
            or not isinstance(entry.get("fd"), int)
            or isinstance(entry.get("fd"), bool)
            or entry["fd"] < 3
            for entry in mutable_state_values
        )
        or not isinstance(stage_zero_value.get("fd"), int)
        or isinstance(stage_zero_value.get("fd"), bool)
        or stage_zero_value["fd"] < 3
    ):
        raise LaunchError(
            "stage-zero retained descriptor bootstrap is malformed"
        )
    retained_files = {
        entry["runtimePath"]: entry
        for entry in retained_file_values
    }
    if len(retained_files) != len(retained_file_values):
        raise LaunchError("stage-zero retained file paths are duplicated")
    retained.update(
        {
            stage_zero_value["fd"],
            *(entry["fd"] for entry in retained_file_values),
            *(entry["fd"] for entry in retained_directory_values),
            *(entry["fd"] for entry in mutable_state_values),
        }
    )
    observed_paths: set[str] = set()
    for entry_value in entries:
        if (
            not isinstance(entry_value, dict)
            or set(entry_value)
            != {
                "path",
                "sha256",
                "size",
                "module",
                "kind",
                "isPackage",
            }
            or entry_value["path"] in observed_paths
            or entry_value["kind"]
            not in {"source", "extension", "data", "runtime"}
            or not isinstance(entry_value["module"], str)
            or entry_value["kind"] in {"source", "extension"}
            and not entry_value["module"]
            or not isinstance(entry_value["isPackage"], bool)
        ):
            raise LaunchError("launch closure entry is invalid")
        observed_paths.add(entry_value["path"])
        retained_file = retained_files.get(entry_value["path"])
        if retained_file is None:
            raise LaunchError(
                "launch closure file was not retained by stage zero"
            )
        descriptor = os.dup(retained_file["fd"])
        os.set_inheritable(descriptor, False)
        try:
            metadata_before = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata_before.st_mode)
                or metadata_before.st_dev != retained_file["device"]
                or metadata_before.st_ino != retained_file["inode"]
                or metadata_before.st_size != retained_file["size"]
            ):
                raise LaunchError(
                    "launch closure retained inode identity changed"
                )
            value = _read_file(descriptor, int(entry_value["size"]))
            metadata_after = os.fstat(descriptor)
            if (
                metadata_before.st_dev,
                metadata_before.st_ino,
                metadata_before.st_size,
                metadata_before.st_mtime_ns,
            ) != (
                metadata_after.st_dev,
                metadata_after.st_ino,
                metadata_after.st_size,
                metadata_after.st_mtime_ns,
            ):
                raise LaunchError("launch closure file changed while read")
            digest = "sha256:" + hashlib.sha256(value).hexdigest()
            if digest != entry_value["sha256"]:
                raise LaunchError("launch closure digest changed")
        finally:
            os.close(descriptor)
        sealed = _seal_bytes(
            str(entry_value["module"] or "authority-data"),
            value,
        )
        retained.add(sealed)
        if entry_value["kind"] == "extension":
            sealed_native_mappings[
                f"/memfd:{entry_value['module']} (deleted)"
            ] = entry_value["sha256"]
        if entry_value["module"]:
            if entry_value["module"] in sealed_entries:
                raise LaunchError("launch module identity is duplicated")
            sealed_entries[entry_value["module"]] = {
                **entry_value,
                "descriptor": sealed,
            }
    expected_native = dict(native_mappings)
    if any(
        path in expected_native
        and expected_native[path] != digest
        for path, digest in sealed_native_mappings.items()
    ):
        raise LaunchError("sealed native mapping identity is ambiguous")
    expected_native.update(sealed_native_mappings)
    _verify_native_mappings(
        expected_native,
        require_exact=False,
    )
    for binding in credential_descriptors:
        descriptor = binding["descriptor"]
        if os.environ.get(binding["environmentName"]) != str(descriptor):
            raise LaunchError(
                "credential descriptor environment binding changed"
            )
        _require_sealed_descriptor(
            descriptor,
            binding["environmentName"],
        )
        metadata_before = os.fstat(descriptor)
        value = _read_file(descriptor, binding["size"])
        metadata_after = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata_before.st_mode)
            or metadata_before.st_uid != binding["ownerUid"]
            or stat.S_IMODE(metadata_before.st_mode) != binding["mode"]
            or metadata_before.st_size != binding["size"]
            or (
                metadata_before.st_dev,
                metadata_before.st_ino,
                metadata_before.st_size,
                metadata_before.st_mtime_ns,
            )
            != (
                metadata_after.st_dev,
                metadata_after.st_ino,
                metadata_after.st_size,
                metadata_after.st_mtime_ns,
            )
            or "sha256:" + hashlib.sha256(value).hexdigest()
                != binding["sha256"]
        ):
            raise LaunchError(
                "credential descriptor measurement changed"
            )
        sealed = _seal_bytes(
            f"authority-{binding['kind']}",
            value,
            mode=binding["mode"],
        )
        try:
            os.dup2(
                sealed,
                descriptor,
                inheritable=False,
            )
        finally:
            os.close(sealed)
        _require_sealed_descriptor(
            descriptor,
            binding["environmentName"],
        )
        retained.add(descriptor)
    required_contract_modules = {
        "serverware.authority_artifact_spec",
        "serverware.authority_stage_zero_contract",
        "scripts.authority.atomic_provisioner_contract",
    }
    if not required_contract_modules.issubset(sealed_entries):
        raise LaunchError(
            "canonical authority contracts are outside the measured closure"
        )
    sys.meta_path.insert(0, _SealedClosureFinder(sealed_entries))
    artifact_contract = importlib.import_module(
        "serverware.authority_artifact_spec"
    )
    stage_zero_contract = importlib.import_module(
        "serverware.authority_stage_zero_contract"
    )
    provisioning_contract = importlib.import_module(
        "scripts.authority.atomic_provisioner_contract"
    )
    generation_context, verified_package = (
        _validate_canonical_launch_evidence(
            role=role,
            launch_payload=payload,
            artifact_contract=artifact_contract,
            stage_zero_contract=stage_zero_contract,
            provisioning_contract=provisioning_contract,
        )
    )
    mutable_state_descriptors: dict[str, dict[str, Any]] = {}
    for state_value in mutable_state_values:
        descriptor = state_value["fd"]
        metadata = os.fstat(descriptor)
        if (
            state_value["name"] in mutable_state_descriptors
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_dev != state_value["device"]
            or metadata.st_ino != state_value["inode"]
            or metadata.st_uid != state_value["uid"]
            or metadata.st_gid != state_value["gid"]
            or stat.S_IMODE(metadata.st_mode) != state_value["mode"]
        ):
            raise LaunchError(
                "stage-zero mutable-state descriptor identity changed"
            )
        os.set_inheritable(descriptor, False)
        mutable_state_descriptors[state_value["name"]] = dict(state_value)
    if (
        native_mappings.get("[vdso]")
        != payload["stageZeroRequest"]["hostEvidence"]["vdsoDigest"]
        or "[vsyscall]" in native_mappings
    ):
        raise LaunchError(
            "measured vDSO or vsyscall policy differs from stage-zero evidence"
        )
    if trusted_host_local:
        if handoff_descriptor is not None:
            raise LaunchError(
                "trusted-host-local launch cannot accept a native handoff"
            )
        (
            native_stage_zero_handoff,
            listener_descriptor,
            launch_identity_descriptors,
            launch_assurance,
        ) = _load_trusted_host_local_identity(
            role=role,
            launch_payload=payload,
            verified_package=verified_package,
            stage_zero_contract=stage_zero_contract,
        )
    else:
        if handoff_descriptor is None:
            raise LaunchError("native stage-zero handoff is unavailable")
        (
            native_stage_zero_handoff,
            listener_descriptor,
            launch_identity_descriptors,
        ) = _load_canonical_stage_zero_handoff(
            role=role,
            launch_payload=payload,
            handoff_descriptor=handoff_descriptor,
            verified_package=verified_package,
            stage_zero_contract=stage_zero_contract,
        )
        launch_assurance = {
            "schema": "serverware.authorityLaunchAssurance/v1",
            "trustMode": verified_package.trust_mode,
            "coLocated": False,
            "hardwareBacked":
                verified_package.trust_mode == "tee-hardware",
            "nativeStageZero": True,
            "hsmBackedKeys": True,
            "teeVerified":
                verified_package.trust_mode == "tee-hardware",
            "externalWitnessVerified": True,
        }
        retained.remove(handoff_descriptor)
        os.close(handoff_descriptor)
    if (
        launch_identity_descriptors["privateKey"]
            != private_descriptor
        or launch_identity_descriptors["certificate"]
            != certificate_descriptor
    ):
        raise LaunchError("stage-zero launch descriptors changed")
    os.environ["SERVERWARE_PROCESS_MODE"] = PROCESS_MODES[role]
    _drop_role_identity(role)
    from serverware import authority_launch_guard

    authority_launch_guard.activate(
        role=role,
        manifest_digest=manifest_digest,
        retained_descriptors=frozenset(retained),
        package_versions={
            str(name): str(version)
            for name, version in package_versions.items()
        },
        generation=generation_context,
        native_stage_zero_handoff=native_stage_zero_handoff,
        listener_descriptor=listener_descriptor,
        launch_identity_descriptors=launch_identity_descriptors,
        mutable_state_descriptors=mutable_state_descriptors,
        stage_zero_request=request,
        verified_artifact_package=verified_package,
        artifact_package=payload["artifactPackage"],
        artifact_trust_state=payload["artifactTrustState"],
        launch_assurance=launch_assurance,
    )
    if role == "witness":
        from serverware import authority_witness

        _verify_native_mappings(
            expected_native,
            require_exact=True,
        )
        return authority_witness.main()
    from serverware import authority_service

    _verify_native_mappings(
        expected_native,
        require_exact=True,
    )
    if role == "runtime":
        return authority_service.runtime_relay_main()
    return authority_service.main([role])


def main(argv: list[str] | None = None) -> int:
    if any(
        os.environ.get(name)
        for name in {
            "SERVERWARE_AUTHORITY_NATIVE_STAGE_ZERO_HANDOFF_FD",
            "SERVERWARE_AUTHORITY_NATIVE_STAGE_ZERO_HANDOFF_PATH",
            "SERVERWARE_AUTHORITY_LAUNCH_IDENTITY_PRIVATE_KEY_FD",
            "SERVERWARE_AUTHORITY_LAUNCH_IDENTITY_PRIVATE_KEY_PATH",
            "SERVERWARE_AUTHORITY_LAUNCH_IDENTITY_CERTIFICATE_FD",
            "SERVERWARE_AUTHORITY_LAUNCH_IDENTITY_CERTIFICATE_PATH",
        }
    ):
        raise LaunchError(
            "legacy stage-zero descriptor environment is forbidden"
        )
    parser = argparse.ArgumentParser(
        prog=(
            "/runtime/python/bin/python3 -I -P -s -S -E "
            "/proc/self/fd/<bootstrap-fd>"
        )
    )
    parser.add_argument(
        "--bootstrap-fd",
        required=True,
        type=int,
    )
    parser.add_argument(
        "--stage-zero-handoff-fd",
        type=int,
    )
    parser.add_argument(
        "--trusted-host-local",
        action="store_true",
    )
    parser.add_argument(
        "--descriptor",
        action="append",
        default=[],
    )
    parser.add_argument("role", choices=sorted(PROCESS_MODES))
    args = parser.parse_args(argv)
    assignments: dict[str, int] = {}
    for assignment in args.descriptor:
        name, separator, descriptor_text = assignment.partition("=")
        try:
            descriptor = int(descriptor_text, 10)
        except ValueError as exc:
            raise LaunchError(
                "measured descriptor assignment is invalid"
            ) from exc
        if (
            separator != "="
            or name not in ROLE_CREDENTIAL_DESCRIPTOR_NAMES[args.role]
            or name in assignments
            or descriptor < 3
            or os.environ.get(name)
        ):
            raise LaunchError(
                "measured descriptor assignment is not exact"
            )
        assignments[name] = descriptor
    launch_private_descriptor = _environment_descriptor(
        "SERVERWARE_AUTHORITY_LAUNCH_PRIVATE_KEY"
    )
    launch_certificate_descriptor = _environment_descriptor(
        "SERVERWARE_AUTHORITY_LAUNCH_CERTIFICATE"
    )
    independent_descriptors = {
        3,
        args.bootstrap_fd,
        launch_private_descriptor,
        launch_certificate_descriptor,
        *assignments.values(),
    }
    if args.stage_zero_handoff_fd is not None:
        independent_descriptors.add(args.stage_zero_handoff_fd)
    expected_descriptor_count = len(assignments) + (
        5 if args.stage_zero_handoff_fd is not None else 4
    )
    if (
        set(assignments)
        != ROLE_CREDENTIAL_DESCRIPTOR_NAMES[args.role]
        or len(set(assignments.values())) != len(assignments)
        or args.bootstrap_fd < 3
        or (
            args.stage_zero_handoff_fd is not None
            and args.stage_zero_handoff_fd < 3
        )
        or args.trusted_host_local
            == (args.stage_zero_handoff_fd is not None)
        or len(independent_descriptors) != expected_descriptor_count
    ):
        raise LaunchError("measured launch descriptor set is invalid")
    for name, descriptor in assignments.items():
        os.environ[name] = str(descriptor)
    return _enter(
        args.role,
        bootstrap_descriptor=args.bootstrap_fd,
        handoff_descriptor=args.stage_zero_handoff_fd,
        trusted_host_local=args.trusted_host_local,
    )


if __name__ == "__main__":
    raise SystemExit(main())
