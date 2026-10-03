from __future__ import annotations

import argparse
import base64
import contextlib
import fcntl
import hashlib
import importlib.abc
import importlib.machinery
import importlib.util
import json
import os
import socket
import stat
import struct
import sys
import time
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import PurePosixPath
from types import ModuleType
from typing import Any, Callable, Mapping


LAUNCH_MANIFEST_SCHEMA = (
    "serverware.signedPolicyAuthorityLaunchManifest/v7"
)
LAUNCH_PAYLOAD_SCHEMA = "serverware.policyAuthorityLaunchManifest/v7"
GENERATION_CONTEXT_SCHEMA = (
    "serverware.authorityGenerationLaunchContext/v4"
)
MAX_MANIFEST_BYTES = 64 * 1024 * 1024
BOOTSTRAP_CONTROL_NAME = "SERVERWARE_POLICY_AUTHORITY_LAUNCH_MANIFEST_FD"
RUNTIME_EVIDENCE_NAME = "SERVERWARE_POLICY_AUTHORITY_ATTESTATION_FD"
RUNTIME_EVIDENCE_ROLES = frozenset(
    {"verifier", "planner", "planner-writer", "issuer", "executor"}
)
MAX_RUNTIME_EVIDENCE_BYTES = 4 * 1024 * 1024
MAX_STAGE_ZERO_HANDOFF_BYTES = 1024 * 1024
MAX_LAUNCH_IDENTITY_CERTIFICATE_BYTES = 1024 * 1024
MAX_CLOSURE_FILES = 32768
MAX_CLOSURE_FILE_BYTES = 64 * 1024 * 1024
MAX_NATIVE_MAPPING_BYTES = 64 * 1024 * 1024
LOCAL_REQUEST_SCHEMA = "serverware.authorityTrustedHostLocalBootstrapRequest/v1"
LOCAL_SETUP_SCHEMA = "serverware.authorityTrustedHostLocalAdmission/v1"
LOCAL_OBSERVATION_SCHEMA = "serverware.authorityTrustedHostLocalObservation/v1"
LOCAL_DELIVERY_SCHEMA = "serverware.authorityTrustedHostLocalObservationDelivery/v1"
LOCAL_REPLY_SCHEMA = "serverware.authorityTrustedHostLocalAdmissionReply/v1"
LOCAL_SLOTS = {"manifest": 256, "certificate": 257, "evidence": 258}
LOCAL_EXEC_ENVIRONMENT = frozenset({
    "LANG", "LC_ALL", "PATH", "PYTHONDONTWRITEBYTECODE", "PYTHONHASHSEED", "TZ",
    "SERVERWARE_ARTIFACT_BUNDLE_DIGEST", "SERVERWARE_AUTHORITY_GENERATION_DIGEST",
    "SERVERWARE_AUTHORITY_LAUNCH_CERTIFICATE_FD", "SERVERWARE_AUTHORITY_LAUNCH_PRIVATE_KEY_FD",
    "SERVERWARE_AUTHORITY_ROLE", "SERVERWARE_OPERATION_MANIFEST_DIGEST",
    BOOTSTRAP_CONTROL_NAME, RUNTIME_EVIDENCE_NAME,
})
MAX_LOCAL_SETUP = 1024 * 1024
MAX_LOCAL_OBSERVATION = 16 * 1024 * 1024
_LOCAL_OWNER = None
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
            "SERVERWARE_POLICY_AUTHORITY_RUNTIME_ROOT_PUBLIC_KEY_FD",
            "SERVERWARE_POLICY_AUTHORITY_RUNTIME_TRUST_FD",
        }
    ),
    "verifier": frozenset(
        {
            "SERVERWARE_POLICY_AUTHORITY_LAUNCH_ROOT_PUBLIC_KEY_FD",
            "SERVERWARE_POLICY_AUTHORITY_ROOT_PUBLIC_KEY_FD",
            "SERVERWARE_POLICY_AUTHORITY_CONFIG_FD",
            "SERVERWARE_POLICY_AUTHORITY_VERIFIER_SIGNING_KEY_FD",
            "SERVERWARE_POLICY_AUTHORITY_VERIFIER_READ_POSTGRES_DSN_FD",
        }
    ),
    "planner": frozenset(
        {
            "SERVERWARE_POLICY_AUTHORITY_LAUNCH_ROOT_PUBLIC_KEY_FD",
            "SERVERWARE_POLICY_AUTHORITY_ROOT_PUBLIC_KEY_FD",
            "SERVERWARE_POLICY_AUTHORITY_CONFIG_FD",
            "SERVERWARE_POLICY_AUTHORITY_PLANNER_SIGNING_KEY_FD",
            "SERVERWARE_POLICY_AUTHORITY_PLANNER_READ_POSTGRES_DSN_FD",
        }
    ),
    "planner-writer": frozenset(
        {
            "SERVERWARE_POLICY_AUTHORITY_LAUNCH_ROOT_PUBLIC_KEY_FD",
            "SERVERWARE_POLICY_AUTHORITY_ROOT_PUBLIC_KEY_FD",
            "SERVERWARE_POLICY_AUTHORITY_CONFIG_FD",
            "SERVERWARE_POLICY_AUTHORITY_PLANNER_WRITER_SIGNING_KEY_FD",
            "SERVERWARE_POLICY_AUTHORITY_PLANNER_WRITER_POSTGRES_DSN_FD",
        }
    ),
    "issuer": frozenset(
        {
            "SERVERWARE_POLICY_AUTHORITY_LAUNCH_ROOT_PUBLIC_KEY_FD",
            "SERVERWARE_POLICY_AUTHORITY_ROOT_PUBLIC_KEY_FD",
            "SERVERWARE_POLICY_AUTHORITY_CONFIG_FD",
            "SERVERWARE_POLICY_AUTHORITY_CAPABILITY_ISSUER_POSTGRES_DSN_FD",
        }
    ),
    "executor": frozenset(
        {
            "SERVERWARE_POLICY_AUTHORITY_LAUNCH_ROOT_PUBLIC_KEY_FD",
            "SERVERWARE_POLICY_AUTHORITY_ROOT_PUBLIC_KEY_FD",
            "SERVERWARE_POLICY_AUTHORITY_CONFIG_FD",
            "SERVERWARE_POLICY_AUTHORITY_EXECUTOR_POSTGRES_DSN_FD",
        }
    ),
    "witness": frozenset(
        {
            "SERVERWARE_POLICY_AUTHORITY_LAUNCH_ROOT_PUBLIC_KEY_FD",
            "SERVERWARE_POLICY_AUTHORITY_WITNESS_ROOT_PUBLIC_KEY_FD",
            "SERVERWARE_POLICY_AUTHORITY_WITNESS_CONFIG_FD",
            "SERVERWARE_POLICY_AUTHORITY_WITNESS_SIGNING_KEY_FD",
        }
    ),
}


for _rbac_role in ("verifier", "planner", "executor"):
    ROLE_CREDENTIAL_DESCRIPTOR_NAMES[_rbac_role] |= frozenset({
        "SERVERWARE_RBAC_WITNESS_CONFIG_FD", "SERVERWARE_RBAC_WITNESS_ROOT_FD", "SERVERWARE_RBAC_WITNESS_TLS_ROOT_FD",
        "SERVERWARE_RBAC_WITNESS_CLIENT_CERTIFICATE_FD", "SERVERWARE_RBAC_WITNESS_CLIENT_KEY_FD",
    })


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


class _MeasuredExtensionLoader(importlib.machinery.ExtensionFileLoader):
    def __init__(self, fullname, binding, loaded):
        self._fullname = fullname
        self._binding = binding
        self._loaded = loaded
        self._origin = f"/proc/self/fd/{binding['fd']}"
        self._mapping_path = f"/memfd:{fullname} (deleted)"
        super().__init__(fullname, self._origin)

    def _check(self, spec):
        if (self.name != self._fullname or self.path != self._origin
                or spec.name != self._fullname or spec.origin != self._origin
                or spec.loader is not self):
            raise LaunchError("sealed extension loader identity changed")
        if _retained_native_digest(self._binding) != self._binding["sha256"]:
            raise LaunchError("sealed extension content changed")

    def create_module(self, spec):
        self._check(spec)
        module = super().create_module(spec)
        self._check(spec)
        return module

    def exec_module(self, module):
        self._check(module.__spec__)
        super().exec_module(module)
        self._check(module.__spec__)
        # The signed closure is an available import inventory. Only completed
        # measured loads add mandatory mappings; cached/unloaded modules do not.
        digest = self._binding["sha256"]
        if self._loaded.get(self._mapping_path, digest) != digest:
            raise LaunchError("sealed extension mapping identity is ambiguous")
        self._loaded[self._mapping_path] = digest


class _SealedClosureFinder(importlib.abc.MetaPathFinder):
    def __init__(self, entries: dict[str, dict[str, Any]], loaded) -> None:
        self.entries = entries
        self.loaded = loaded

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
            loader = _MeasuredExtensionLoader(
                fullname, entry["nativeBinding"], self.loaded,
            )
        else:
            return None
        return importlib.util.spec_from_loader(
            fullname,
            loader,
            is_package=bool(entry["isPackage"]),
        )


def _loaded_native_dependency_mappings(bundle, loaded):
    """Select dependencies of successful imports from the verified ELF graph.

    An extension's own mapping uses its sealed memfd, but the dynamic loader
    maps its DT_NEEDED objects at their signed runtime paths. Available but
    unimported extensions do not make their dependency mappings mandatory.
    """
    objects = bundle["nativeClosure"]["objects"]
    native = [*bundle["nativeClosure"]["executables"], *objects]
    by_path = {row["path"]: row for row in objects}
    by_runtime = {row["runtimePath"]: row for row in native}
    imports = [row for row in bundle["pythonImportClosure"]
               if row["kind"] == "extension"]
    by_mapping = {f"/memfd:{row['module']} (deleted)": row for row in imports}
    if (len(by_path) != len(objects) or len(by_runtime) != len(native)
            or len(by_mapping) != len(imports)):
        raise LaunchError("native dependency graph identity is ambiguous")
    pending = []
    for path, digest in loaded.items():
        imported = by_mapping.get(path)
        root = None if imported is None else by_path.get(imported["path"])
        if (root is None or imported["sha256"] != digest
                or root["sha256"] != digest):
            raise LaunchError("loaded extension differs from signed native graph")
        pending.extend(root["needed"])
    dependencies = {}
    while pending:
        path = pending.pop()
        if path in dependencies:
            continue
        row = by_runtime.get(path)
        if row is None:
            raise LaunchError("loaded native dependency is outside signed graph")
        dependencies[path] = row["sha256"]
        pending.extend(row["needed"])
        if row.get("ptInterp") is not None:
            pending.append(row["ptInterp"])
    return dependencies


def _preload_native_dependencies(bundle, files, already_loaded, *, modules):
    """Resolve selected sealed extensions using only signed retained originals."""
    objects = bundle["nativeClosure"]["objects"]
    native = [*bundle["nativeClosure"]["executables"], *objects]
    by_path = {row["path"]: row for row in objects}
    by_runtime = {row["runtimePath"]: row for row in native}
    imports = [row for row in bundle["pythonImportClosure"]
               if row["kind"] == "extension"]
    by_module = {row["module"]: row for row in imports}
    if (len(by_path) != len(objects) or len(by_runtime) != len(native)
            or len(by_module) != len(imports) or not modules
            or len(set(modules)) != len(modules)
            or len(native) > MAX_CLOSURE_FILES):
        raise LaunchError("native preload graph identity is ambiguous")

    roots = []
    for module in modules:
        imported = by_module.get(module)
        root = None if imported is None else by_path.get(imported["path"])
        if root is None or root["sha256"] != imported["sha256"]:
            raise LaunchError("required extension differs from signed native graph")
        roots.append(root["runtimePath"])

    # Validate the whole selected graph, including already-loaded leaves, before
    # any dlopen. The caller supplies only its verified baseline mapping set.
    required = {}
    pending = list(roots)
    while pending:
        path = pending.pop()
        if path in required:
            continue
        row = by_runtime.get(path)
        binding = files.get(path)
        if (row is None or binding is None
                or binding["sha256"] != row["sha256"]
                or _retained_native_digest(binding) != row["sha256"]
                or path in already_loaded and already_loaded[path] != row["sha256"]):
            raise LaunchError("native preload source differs from signed original")
        edges = list(row["needed"])
        if row.get("ptInterp") is not None:
            edges.append(row["ptInterp"])
        required[path] = (row, binding, edges)
        pending.extend(edges)

    order = []
    state = {}
    pending = [(path, False) for root in reversed(roots)
               for path in reversed(required[root][2])]
    while pending:
        path, completed = pending.pop()
        if path in already_loaded or state.get(path) == 2:
            continue
        if completed:
            state[path] = 2
            order.append(path)
            continue
        if state.get(path) == 1:
            raise LaunchError("native preload has an unresolved dependency cycle")
        state[path] = 1
        pending.append((path, True))
        pending.extend((child, False) for child in reversed(required[path][2]))

    import ctypes

    handles = []
    for path in order:
        row, binding, _edges = required[path]
        if _retained_native_digest(binding) != row["sha256"]:
            raise LaunchError("native preload source changed before load")
        handles.append(ctypes.CDLL(
            f"/proc/self/fd/{binding['fd']}",
            mode=os.RTLD_NOW | os.RTLD_LOCAL,
        ))
        if _retained_native_digest(binding) != row["sha256"]:
            raise LaunchError("native preload source changed during load")
    return tuple(handles)


def _native_identity(metadata):
    return (metadata.st_dev, metadata.st_ino, metadata.st_mode,
            metadata.st_uid, metadata.st_gid, metadata.st_size,
            metadata.st_mtime_ns, metadata.st_ctime_ns)


@contextlib.contextmanager
def _retained_process_memory():
    # Open only our own memory, before permanent UID drop. This temporary
    # descriptor is never part of the signed/service retained-descriptor set.
    descriptor = os.open("/proc/self/mem", os.O_RDONLY | os.O_CLOEXEC)
    try:
        yield (descriptor, _native_identity(os.fstat(descriptor)))
    finally:
        os.close(descriptor)


def _read_process_mapping(memory, start: int, end: int) -> bytes:
    size = end - start
    if not 0 < size <= MAX_NATIVE_MAPPING_BYTES:
        raise LaunchError("executable memory mapping is outside its bound")
    try:
        descriptor, identity = memory
        if _native_identity(os.fstat(descriptor)) != identity:
            raise LaunchError("retained own-memory descriptor changed")
        value = os.pread(descriptor, size, start)
        if _native_identity(os.fstat(descriptor)) != identity:
            raise LaunchError("retained own-memory descriptor changed")
    except OSError as exc:
        raise LaunchError(
            "executable memory mapping cannot be measured"
        ) from exc
    if len(value) != size:
        raise LaunchError("executable memory mapping measurement is partial")
    return value


def _native_file_binding(descriptor, digest, *, sealed=False):
    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode):
        raise LaunchError("retained native descriptor is not regular")
    if sealed:
        _require_sealed_descriptor(descriptor, "native extension")
    return dict(fd=descriptor, identity=_native_identity(metadata),
                sha256=digest, sealed=sealed)


def _native_file_index(retained_files):
    result = {}
    for row in retained_files:
        if type(row.get("surviveExec")) is not bool:
            raise LaunchError("retained native survival declaration is malformed")
        if not row["surviveExec"]:
            continue
        metadata = os.fstat(row["fd"])
        if (not stat.S_ISREG(metadata.st_mode)
                or (metadata.st_dev, metadata.st_ino, metadata.st_size,
                    stat.S_IMODE(metadata.st_mode), metadata.st_uid, metadata.st_gid)
                != (row["device"], row["inode"], row["size"],
                    row["mode"], row["uid"], row["gid"])):
            raise LaunchError("retained native source identity changed")
        key = row["runtimePath"]
        binding = _native_file_binding(row["fd"], row["sha256"])
        if key in result:
            raise LaunchError("retained native source identity is ambiguous")
        result[key] = binding
    return result


def _retain_native_mapped_sources(retained_files, expected, files, owner):
    # Native stage zero may deliberately close a declared source at exec.
    # Acquire that *actual mapped inode*, never its ordinary pathname, while
    # still privileged; the private owner closes it before service entry.
    sources = {row["runtimePath"]: row for row in retained_files}
    if len(sources) != len(retained_files):
        raise LaunchError("retained native source paths are duplicated")
    rows = _executable_mapping_rows()
    for address, _permissions, _offset, device, inode, path in rows:
        if not path.startswith("/"):
            continue  # The full verifier separately handles/rejects kernel rows.
        if path not in expected:
            raise LaunchError("native mapping is outside the signed baseline")
        if path not in files:
            row = sources.get(path)
            if (row is None or row.get("surviveExec") is not False
                    or os.geteuid() != 0):
                raise LaunchError("mapped native source has no approved original")
            descriptor = os.open(
                f"/proc/self/map_files/{address}", os.O_RDONLY | os.O_CLOEXEC,
            )
            owner.callback(os.close, descriptor)
            binding = _native_file_index([
                dict(row, fd=descriptor, surviveExec=True),
            ])[path]
            files[path] = binding
        digest = _mapped_file_digest(files=files, path=path, device=device, inode=inode)
        if digest != expected[path]:
            raise LaunchError("mapped native source differs from signed baseline")
    if rows != _executable_mapping_rows():
        raise LaunchError("executable mappings changed while retaining originals")


def _retained_native_digest(binding):
    descriptor, identity = binding["fd"], binding["identity"]
    metadata = os.fstat(descriptor)
    if (_native_identity(metadata) != identity
            or not stat.S_ISREG(metadata.st_mode)
            or not 0 <= metadata.st_size <= MAX_NATIVE_MAPPING_BYTES):
        raise LaunchError("retained native inode identity changed")
    if binding["sealed"]:
        _require_sealed_descriptor(descriptor, "native extension")
    value = _read_file(descriptor, metadata.st_size)
    if _native_identity(os.fstat(descriptor)) != identity:
        raise LaunchError("retained native inode changed while read")
    if binding["sealed"]:
        _require_sealed_descriptor(descriptor, "native extension")
    digest = "sha256:" + hashlib.sha256(value).hexdigest()
    if digest != binding["sha256"]:
        raise LaunchError("retained native content changed")
    return digest


def _mapped_file_digest(*, files, path: str, device: str, inode: str) -> str:
    try:
        expected_major_text, expected_minor_text = device.split(":", 1)
        expected_major = int(expected_major_text, 16)
        expected_minor = int(expected_minor_text, 16)
        expected_inode = int(inode, 10)
    except (ValueError, TypeError) as exc:
        raise LaunchError("native mapping identity is malformed") from exc
    if expected_inode <= 0:
        raise LaunchError("file-backed executable mapping has no inode")
    key = os.makedev(expected_major, expected_minor), expected_inode
    binding = files.get(path)
    if binding is None or binding["identity"][:2] != key:
        raise LaunchError("mapped executable inode was not retained")
    return _retained_native_digest(binding)


def _executable_mapping_rows():
    try:
        with open("/proc/self/maps", "r", encoding="ascii") as handle:
            lines = handle.readlines()
    except OSError as exc:
        raise LaunchError("Linux native mapping inventory is unavailable") from exc
    rows = []
    for line in lines:
        fields = line.rstrip("\n").split(maxsplit=5)
        if len(fields) < 5:
            raise LaunchError("native mapping inventory is malformed")
        if "x" not in fields[1]:
            continue
        if "w" in fields[1] or len(fields) != 6:
            raise LaunchError("anonymous or writable executable mapping is forbidden")
        rows.append(tuple(fields))
    return tuple(rows)


def _verify_native_mappings(
    expected: dict[str, str],
    *,
    require_exact: bool,
    files,
    memory,
) -> dict[str, str]:
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
    rows = _executable_mapping_rows()
    observed: dict[str, str] = {}
    observed_inodes: dict[str, tuple[str, str]] = {}
    for fields in rows:
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
                _read_process_mapping(memory, start, end)
            ).hexdigest()
            inode_identity = ("kernel", address_range)
        elif path.startswith("/"):
            digest = _mapped_file_digest(
                files=files,
                path=path,
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
    if rows != _executable_mapping_rows():
        raise LaunchError("executable mapping inventory changed while measured")
    if (
        any(
            expected.get(path) != digest
            for path, digest in observed.items()
        )
        or require_exact
        and observed != expected
    ):
        raise LaunchError("loaded native mapping closure changed")
    return observed


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
    *, close: bool = True,
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
        if close:
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


def _bootstrap_control_stamp(descriptor: int) -> tuple[int, ...]:
    if type(descriptor) is not int or not 3 <= descriptor <= 2**31 - 1:
        raise LaunchError("bootstrap control descriptor is invalid")
    if (
        os.environ.get(BOOTSTRAP_CONTROL_NAME) != str(descriptor)
        or os.environ.get("SERVERWARE_POLICY_AUTHORITY_LAUNCH_MANIFEST_PATH")
    ):
        raise LaunchError("bootstrap control environment binding changed")
    _require_sealed_descriptor(descriptor, "launch manifest bootstrap control")
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 0
        or metadata.st_uid != 0
        or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        or not 2 <= metadata.st_size <= MAX_MANIFEST_BYTES
    ):
        raise LaunchError("bootstrap control is not bounded immutable root-owned bytes")
    return (
        descriptor, metadata.st_dev, metadata.st_ino, metadata.st_mode,
        metadata.st_uid, metadata.st_gid, metadata.st_size,
        metadata.st_mtime_ns, metadata.st_ctime_ns,
    )


def _require_bootstrap_control_identity(identity: tuple) -> None:
    if (
        type(identity) is not tuple or len(identity) != 10
        or any(type(value) is not int or value < 0 for value in identity[:9])
        or not _is_digest(identity[9])
        or _bootstrap_control_stamp(identity[0]) != identity[:9]
    ):
        raise LaunchError("verified bootstrap control identity changed")


def _runtime_evidence_stamp(descriptor: int) -> tuple[int, ...]:
    if type(descriptor) is not int or not 3 <= descriptor <= 2**31 - 1:
        raise LaunchError("runtime evidence descriptor is invalid")
    if (
        os.environ.get(RUNTIME_EVIDENCE_NAME) != str(descriptor)
        or os.environ.get("SERVERWARE_POLICY_AUTHORITY_ATTESTATION_PATH")
    ):
        raise LaunchError("runtime evidence environment binding changed")
    _require_sealed_descriptor(descriptor, "runtime attestation evidence")
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 0 or metadata.st_uid != 0
        or stat.S_IMODE(metadata.st_mode) & 0o077
        or not 2 <= metadata.st_size <= MAX_RUNTIME_EVIDENCE_BYTES
    ):
        raise LaunchError("runtime evidence is not private immutable root-owned bytes")
    return (
        descriptor, metadata.st_dev, metadata.st_ino, metadata.st_mode,
        metadata.st_uid, metadata.st_gid, metadata.st_size,
        metadata.st_mtime_ns, metadata.st_ctime_ns,
    )


def _require_runtime_evidence_identity(identity: tuple) -> None:
    if (
        type(identity) is not tuple or len(identity) != 10
        or any(type(value) is not int or value < 0 for value in identity[:9])
        or not _is_digest(identity[9])
        or _runtime_evidence_stamp(identity[0]) != identity[:9]
    ):
        raise LaunchError("runtime evidence custody changed")


def _observe_runtime_evidence(
    role: str, request: Mapping[str, Any], descriptor: int | None,
) -> tuple | None:
    if "runtimeEvidence" not in request:
        raise LaunchError("runtime evidence declaration is missing")
    slot = request["runtimeEvidence"]
    if role not in RUNTIME_EVIDENCE_ROLES:
        if (
            slot is not None or descriptor is not None
            or os.environ.get(RUNTIME_EVIDENCE_NAME)
            or os.environ.get("SERVERWARE_POLICY_AUTHORITY_ATTESTATION_PATH")
        ):
            raise LaunchError("runtime evidence is not permitted for this role")
        return None
    if (
        type(slot) is not dict
        or set(slot) != {"name", "fd", "purpose", "maximumBytes"}
        or slot["name"] != RUNTIME_EVIDENCE_NAME
        or type(slot["fd"]) is not int or slot["fd"] != descriptor
        or slot["purpose"] != "authority-attestation"
        or type(slot["maximumBytes"]) is not int
        or slot["maximumBytes"] != MAX_RUNTIME_EVIDENCE_BYTES
    ):
        raise LaunchError("runtime evidence slot differs from its actual descriptor")
    before = _runtime_evidence_stamp(descriptor)
    value = _require_sealed_descriptor_number(
        descriptor, label="runtime attestation evidence",
        maximum=MAX_RUNTIME_EVIDENCE_BYTES,
    )
    if _runtime_evidence_stamp(descriptor) != before:
        raise LaunchError("runtime evidence changed while read")
    # Observation of supplied originals is not receipt verification.
    identity = (*before, "sha256:" + hashlib.sha256(value).hexdigest())
    _require_runtime_evidence_identity(identity)
    os.set_inheritable(descriptor, False)
    return identity


def _load_manifest(
    role: str, *, manifest_descriptor: int,
) -> tuple[dict[str, Any], str, tuple]:
    before = _bootstrap_control_stamp(manifest_descriptor)
    root_key = _read_descriptor(
        "SERVERWARE_POLICY_AUTHORITY_LAUNCH_ROOT_PUBLIC_KEY",
        32,
    )
    if len(root_key) != 32:
        raise LaunchError("launch root key must be raw Ed25519")
    manifest_value = _require_sealed_descriptor_number(
        manifest_descriptor,
        label="launch manifest bootstrap control",
        maximum=MAX_MANIFEST_BYTES,
    )
    if _bootstrap_control_stamp(manifest_descriptor) != before:
        raise LaunchError("bootstrap control changed while read")
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
    control = payload["stageZeroRequest"].get("bootstrapControl")
    if (
        type(control) is not dict
        or set(control) != {"name", "fd", "envelopeSchema", "maximumBytes"}
        or control["name"] != BOOTSTRAP_CONTROL_NAME
        or type(control["fd"]) is not int or control["fd"] != manifest_descriptor
        or control["envelopeSchema"] != LAUNCH_MANIFEST_SCHEMA
        or type(control["maximumBytes"]) is not int
        or control["maximumBytes"] != MAX_MANIFEST_BYTES
    ):
        raise LaunchError("signed bootstrap control differs from its actual descriptor")
    # This raw identity is observed only after signature and scope validation.
    # It is never a field of the manifest or its stage-zero request.
    identity = (*before, "sha256:" + hashlib.sha256(manifest_value).hexdigest())
    _require_bootstrap_control_identity(identity)
    os.set_inheritable(manifest_descriptor, False)
    return payload, _domain_digest(
        LAUNCH_PAYLOAD_SCHEMA,
        payload_bytes,
    ), identity


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
    installation_paths = _require_contract_callable(
        artifact_contract,
        "retained_installation_paths",
    )(
        bundle=bundle,
        generation_root=generation_root.as_posix(),
        retained_files=request["retainedFiles"],
        launch_closure=launch_payload["closure"],
    )
    saw_role_manifest = False
    for retained in request["retainedFiles"]:
        relative = installation_paths[retained["runtimePath"]]
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
    role_manifests = deepcopy(bundle["roleManifests"])
    role_manifest_digests = {
        entry["role"]: entry["sha256"]
        for entry in role_manifests
    }
    role_binding_digests = _require_contract_callable(
        artifact_contract,
        "role_binding_digests",
    )(role_manifests)
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
        "roleManifests": role_manifests,
        "roleBindingDigests": role_binding_digests,
        "configurationDigests":
            list(generation["configurationDigests"]),
        "configurationPayloadBindings": [
            dict(binding)
            for binding in generation["configurationPayloadBindings"]
        ],
        "configurationBindingDigest": _require_contract_callable(
            artifact_contract,
            "configuration_generation_binding_digest",
        )(generation),
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


def _local_document(raw: bytes, maximum: int) -> dict:
    def pairs(rows):
        result = {}
        for key, value in rows:
            if key in result:
                raise LaunchError("local admission duplicate field")
            result[key] = value
        return result

    def invalid(_value):
        raise LaunchError("local admission noninteger scalar")

    if type(raw) is not bytes or not 0 < len(raw) <= maximum:
        raise LaunchError("local admission original exceeds its bound")
    try:
        value = json.loads(raw, object_pairs_hook=pairs, parse_float=invalid, parse_constant=invalid)
        if type(value) is not dict or _canonical(value) != raw:
            raise LaunchError("local admission original is not canonical")
        return value
    except (ValueError, UnicodeError, RecursionError) as error:
        raise LaunchError("local admission original refused") from error


def _local_stat(fd: int, *, regular: bool = True) -> dict:
    if type(fd) is not int or fd < 3:
        raise LaunchError("local admission descriptor is invalid")
    before = os.fstat(fd)
    if not (stat.S_ISREG(before.st_mode) if regular else stat.S_ISDIR(before.st_mode)):
        raise LaunchError("local admission descriptor type changed")
    row = dict(fd=fd, device=before.st_dev, inode=before.st_ino,
        mode=stat.S_IMODE(before.st_mode), uid=before.st_uid, gid=before.st_gid)
    if regular:
        if not 0 <= before.st_size <= MAX_CLOSURE_FILE_BYTES:
            raise LaunchError("local admission file is oversized")
        digest = hashlib.sha256()
        offset = 0
        while offset < before.st_size:
            raw = os.pread(fd, min(65536, before.st_size - offset), offset)
            if not raw:
                raise LaunchError("local admission file changed")
            digest.update(raw); offset += len(raw)
        row.update(size=before.st_size, sha256="sha256:" + digest.hexdigest())
    if _local_identity(fd) != _local_identity_value(before):
        raise LaunchError("local admission file changed during observation")
    return row


def _local_identity_value(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
        info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _local_identity(fd):
    return _local_identity_value(os.fstat(fd))


@contextlib.contextmanager
def _local_owning():
    previous = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM, signal.SIGHUP})
    try:
        yield
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous)


def _local_boot():
    return _boot_identity_digest()


class _LocalAdmission:
    """One actual same-PID late-input exchange, before authority admission.

    Static inputs remain borrowed from the exact entrypoint; received originals
    and kernel control handles are retained here before any fallible validation.
    No signature or service authority is manufactured by this transport.
    """

    @classmethod
    def open(cls, *, role, setup_fd, setup_sha256, channel_fd, bootstrap_fd, assignments):
        global _LOCAL_OWNER
        # Do not add native extension mappings to the unchanged native entry.
        # Selected local imports occur before its actual mapping observation.
        global array, ctypes, select, signal, threading
        import array
        import ctypes
        import select
        import signal
        import threading
        if cls is not _LocalAdmission or _LOCAL_OWNER is not None:
            raise LaunchError("local admission is one-shot")
        owner = cls(); _LOCAL_OWNER = owner
        owner.role, owner.setup_fd, owner.bootstrap_fd = role, setup_fd, bootstrap_fd
        owner.assignments = dict(assignments)
        owner.handles, owner.incoming, owner.stamps = [], [], {}
        owner.channel = owner.peer_fd = owner.self_fd = None
        owner.failed = owner.closed = owner.closing = owner.delivered = False
        owner.exchange_attempted = owner.bind_attempted = False
        owner.pid, owner.start = os.getpid(), _process_identity(os.getpid())[0]
        owner.boot = _local_boot()
        owner.last_boot, owner.last_epoch = time.clock_gettime_ns(time.CLOCK_BOOTTIME), time.time_ns()
        try:
            raw = _require_sealed_descriptor_number(setup_fd, label="local admission setup", maximum=MAX_LOCAL_SETUP)
            if (os.fstat(setup_fd).st_uid, os.fstat(setup_fd).st_gid,
                    stat.S_IMODE(os.fstat(setup_fd).st_mode)) != (0, 0, 0o400):
                raise LaunchError("local admission setup is not root-private")
            if "sha256:" + hashlib.sha256(raw).hexdigest() != setup_sha256:
                raise LaunchError("local admission setup pin changed")
            owner.setup_sha, owner.setup = setup_sha256, _local_document(raw, MAX_LOCAL_SETUP)
            expected = {"schema", "role", "producer", "bootIdDigest", "issuedAtBoottimeNs",
                "deadlineBoottimeNs", "issuedAtUnixNanos", "expiresAtUnixNanos", "retainedFiles",
                "retainedDirectories", "mutableStateDescriptors", "reservations"}
            value = owner.setup
            if set(value) != expected or value["schema"] != LOCAL_SETUP_SCHEMA or value["role"] != role:
                raise LaunchError("local admission setup schema changed")
            peer = value["producer"]
            if type(peer) is not dict or set(peer) != {"pid", "uid", "gid", "startTimeTicks"} or any(
                    type(peer[name]) is not int for name in peer) or peer["uid"] != 0 or peer["gid"] != 0 or (
                    peer["pid"] != os.getppid() or peer["pid"] <= 1 or peer["startTimeTicks"] <= 0):
                raise LaunchError("local admission producer is not the actual root parent")
            for name in ("issuedAtBoottimeNs", "deadlineBoottimeNs", "issuedAtUnixNanos", "expiresAtUnixNanos"):
                if type(value[name]) is not int or not 0 < value[name] < (1 << 63):
                    raise LaunchError("local admission clock is invalid")
            if value["bootIdDigest"] != owner.boot:
                raise LaunchError("local admission boot changed")
            purposes = ("manifest", "certificate", "evidence") if role in RUNTIME_EVIDENCE_ROLES else ("manifest", "certificate")
            if type(value["reservations"]) is not dict or set(value["reservations"]) != set(purposes):
                raise LaunchError("local admission reservation roster changed")
            owner.purposes = purposes
            for purpose in purposes:
                row = value["reservations"][purpose]
                if type(row) is not dict or set(row) != {"fd", "device", "inode"} or row["fd"] != LOCAL_SLOTS[purpose]:
                    raise LaunchError("local admission reservation is not fixed")
                fd = row["fd"]; info = os.fstat(fd)
                if (info.st_dev, info.st_ino, info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode), info.st_size,
                        info.st_nlink) != (row["device"], row["inode"], 0, 0, 0o400, 0, 0) or not stat.S_ISREG(info.st_mode):
                    raise LaunchError("local admission reservation is not the original empty slot")
                _require_sealed_descriptor(fd, "local admission empty reservation")
            if assignments.get(BOOTSTRAP_CONTROL_NAME) != 256 or _environment_descriptor(
                    "SERVERWARE_AUTHORITY_LAUNCH_CERTIFICATE") != 257 or (
                    role in RUNTIME_EVIDENCE_ROLES and assignments.get(RUNTIME_EVIDENCE_NAME) != 258):
                raise LaunchError("local admission late descriptor assignments changed")
            for name, limit in (("retainedFiles", MAX_CLOSURE_FILES), ("retainedDirectories", 64)):
                rows = value[name]
                if type(rows) is not list or not 1 <= len(rows) <= limit or any(type(fd) is not int or fd < 3 for fd in rows) or rows != sorted(set(rows)):
                    raise LaunchError("local admission static descriptor roster changed")
            states = value["mutableStateDescriptors"]
            if type(states) is not list or len(states) != (1 if role == "witness" else 0):
                raise LaunchError("local admission mutable-state roster changed")
            static = [setup_fd, channel_fd, bootstrap_fd, 3, *assignments.values(),
                _environment_descriptor("SERVERWARE_AUTHORITY_LAUNCH_PRIVATE_KEY"), 257,
                *value["retainedFiles"], *value["retainedDirectories"], *(row["fd"] for row in states)]
            if len(static) != len(set(static)):
                raise LaunchError("local admission descriptor aliases another role input")
            for fd in static:
                owner.stamps[fd] = _local_identity(fd)
            with _local_owning():
                owner.channel = socket.socket(fileno=channel_fd)
                owner.channel.setblocking(False); owner.channel.set_inheritable(False)
                owner.channel.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
                owner.peer_fd = struct.unpack("=i", owner.channel.getsockopt(socket.SOL_SOCKET, 77, 4))[0]
                owner.handles.append(owner.peer_fd)
                os.set_inheritable(owner.peer_fd, False)
                owner.self_fd = os.pidfd_open(owner.pid, 0); owner.handles.append(owner.self_fd)
                os.set_inheritable(owner.self_fd, False)
            owner.check(peer=True)
            owner.observation = owner.observe()
            owner.original = _canonical(owner.observation)
            if len(owner.original) > MAX_LOCAL_OBSERVATION:
                raise LaunchError("local admission observation exceeds bound")
            owner.observation_sha = "sha256:" + hashlib.sha256(owner.original).hexdigest()
            owner.check(peer=True)
            return owner
        except BaseException:
            owner.failed = True
            raise

    def check(self, *, peer=False):
        if self.closed or self.closing or self.failed or os.getpid() != self.pid or _process_identity(self.pid)[0] != self.start or (
                os.getresuid() != (0, 0, 0) or os.getresgid() != (0, 0, 0) or
                threading.current_thread() is not threading.main_thread() or _local_boot() != self.boot):
            raise LaunchError("local admission process changed")
        now_boot, now_epoch = time.clock_gettime_ns(time.CLOCK_BOOTTIME), time.time_ns()
        if not (self.setup["issuedAtBoottimeNs"] <= self.last_boot <= now_boot < self.setup["deadlineBoottimeNs"] and
                self.setup["issuedAtUnixNanos"] <= self.last_epoch <= now_epoch < self.setup["expiresAtUnixNanos"]):
            raise LaunchError("local admission original clock expired or regressed")
        self.last_boot, self.last_epoch = now_boot, now_epoch
        if hasattr(self, "observation") and (
                os.getcwd() != self.observation["execution"]["cwd"] or
                list(sys.orig_argv) != self.observation["argv"] or
                {name: value for name, value in os.environ.items() if name in LOCAL_EXEC_ENVIRONMENT}
                    != self.observation["environment"]):
            raise LaunchError("local admission observed execution context changed")
        for fd, expected in self.stamps.items():
            if _local_identity(fd) != expected:
                raise LaunchError("local admission retained descriptor changed")
        if peer:
            expected = self.setup["producer"]
            observed = struct.unpack("=iII", self.channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if observed != (expected["pid"], 0, 0) or os.getppid() != expected["pid"] or (
                    _process_identity(expected["pid"])[0] != expected["startTimeTicks"] or
                    select.select([self.peer_fd], [], [], 0)[0] or self.channel.family != socket.AF_UNIX or
                    self.channel.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_SEQPACKET or
                    self.channel.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) != 0):
                raise LaunchError("local admission authenticated producer changed")
            with open(f"/proc/self/fdinfo/{self.peer_fd}", "rt", encoding="ascii") as stream:
                pid_rows = [line.split()[1] for line in stream.read(16384).splitlines() if line.startswith("Pid:")]
            if pid_rows != [str(expected["pid"])]:
                raise LaunchError("local admission producer PIDFD changed")

    def observe(self):
        files = [_local_stat(fd) for fd in self.setup["retainedFiles"]]
        directories = [_local_stat(fd, regular=False) for fd in self.setup["retainedDirectories"]]
        executable = os.stat("/proc/self/exe")
        selected = [row for row in files if (row["device"], row["inode"]) == (executable.st_dev, executable.st_ino)]
        if len(selected) != 1:
            raise LaunchError("local admission interpreter is not uniquely retained")
        credentials = []
        for name in sorted(self.assignments):
            if name in {BOOTSTRAP_CONTROL_NAME, RUNTIME_EVIDENCE_NAME}:
                continue
            fd = self.assignments[name]
            _require_sealed_descriptor(fd, "local admission credential")
            credentials.append(dict(name=name, **_local_stat(fd), seals=fcntl.fcntl(fd, fcntl.F_GET_SEALS)))
        allowed = LOCAL_EXEC_ENVIRONMENT | set(self.assignments)
        if set(os.environ) - allowed:
            raise LaunchError("local admission environment contains unapproved names")
        with open("/proc/self/status", "rt", encoding="ascii") as stream:
            status = stream.read(16385)
        nnp = [line.split()[1] for line in status.splitlines() if line.startswith("NoNewPrivs:")]
        if len(status) > 16384 or nnp != ["1"]:
            raise LaunchError("local admission requires actual no-new-privileges")
        uid, gid = ROLE_IDENTITIES[self.role]
        info = os.stat(ROLE_SOCKET_PATHS[self.role], follow_symlinks=False)
        listener = dict(name=ROLE_LISTENER_NAMES[self.role], fd=3, runtimePath=ROLE_SOCKET_PATHS[self.role],
            activationName=ROLE_LISTENER_NAMES[self.role], family="AF_UNIX", socketType="SOCK_STREAM", accepting=True,
            listenPid=self.pid, listenFds=1, listenFdNames=[ROLE_LISTENER_NAMES[self.role]],
            device=info.st_dev, inode=info.st_ino, mode=0o660, uid=uid, gid=gid)
        _listener_identity(self.role, listener)
        for row in self.setup["mutableStateDescriptors"]:
            actual = _local_stat(row["fd"], regular=False)
            if any(row.get(key) != actual[key] for key in actual) or row.get("runtimePath") != "/var/lib/serverware/authority-witness":
                raise LaunchError("local admission witness directory changed")
            named = os.stat(row["runtimePath"], follow_symlinks=False)
            if (named.st_dev, named.st_ino) != (actual["device"], actual["inode"]):
                raise LaunchError("local admission witness path changed")
            fcntl.flock(row["fd"], fcntl.LOCK_EX | fcntl.LOCK_NB)
            with open(f"/proc/self/fdinfo/{row['fd']}", "rt", encoding="ascii") as stream:
                mounts = [line.split()[1] for line in stream.read(16384).splitlines() if line.startswith("mnt_id:")]
            if mounts != [str(row["mountId"])]:
                raise LaunchError("local admission witness mount changed")
        own = os.fstat(self.self_fd); peer = os.fstat(self.peer_fd); setup = os.fstat(self.setup_fd)
        channel = os.fstat(self.channel.fileno())
        return dict(schema=LOCAL_OBSERVATION_SCHEMA, role=self.role, setupSha256=self.setup_sha,
            process=dict(pid=self.pid, uid=0, gid=0, startTimeTicks=self.start, parentPid=os.getppid(),
                bootIdDigest=self.boot, pidNamespaceInode=_process_identity(self.pid)[1],
                pidfd=dict(fd=self.self_fd, device=own.st_dev, inode=own.st_ino, processId=self.pid,
                    processStartTicks=self.start, bootIdDigest=self.boot, surviveExec=False)),
            listener=listener, bootstrap=_local_stat(self.bootstrap_fd),
            interpreter=dict(path=os.readlink("/proc/self/exe"), **selected[0]), retainedFiles=files,
            retainedDirectories=directories, mutableStateDescriptors=deepcopy(self.setup["mutableStateDescriptors"]),
            credentials=credentials, argv=list(sys.orig_argv),
            environment={name: value for name, value in os.environ.items() if name in LOCAL_EXEC_ENVIRONMENT},
            execution=dict(cwd=os.getcwd(), noNewPrivileges=True),
            startupDescriptors=dict(setup=dict(fd=self.setup_fd, device=setup.st_dev, inode=setup.st_ino,
                size=setup.st_size, sha256=self.setup_sha), channel=dict(fd=self.channel.fileno(), device=channel.st_dev,
                inode=channel.st_ino), producerPidfd=dict(fd=self.peer_fd, device=peer.st_dev, inode=peer.st_ino,
                processId=self.setup["producer"]["pid"], processStartTicks=self.setup["producer"]["startTimeTicks"],
                bootIdDigest=self.boot)), deadlineBoottimeNs=self.setup["deadlineBoottimeNs"],
            expiresAtUnixNanos=self.setup["expiresAtUnixNanos"])

    def _wait(self, writing=False):
        self.check(peer=True)
        remaining = min(self.setup["deadlineBoottimeNs"] - self.last_boot,
            self.setup["expiresAtUnixNanos"] - self.last_epoch) / 1_000_000_000
        # Avoid rescanning the full retained roster every 50ms while idle.
        # Channel/PIDFD readiness still wakes immediately; original clocks bind.
        select.select([self.peer_fd] + ([] if writing else [self.channel]),
            [self.channel] if writing else [], [], min(1.0, remaining))
        self.check(peer=True)

    def exchange(self):
        if self.exchange_attempted:
            raise LaunchError("local admission exchange cannot be retried")
        self.exchange_attempted = True
        with _local_owning():
            fd = os.memfd_create("serverware-local-launch-observation", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
            self.handles.append(fd)
        offset = 0
        while offset < len(self.original):
            self.check(peer=True)
            written = os.write(fd, self.original[offset:offset + 65536])
            if written <= 0:
                raise LaunchError("local observation write failed")
            offset += written
        os.fchmod(fd, 0o400); fcntl.fcntl(fd, fcntl.F_ADD_SEALS, REQUIRED_MEMFD_SEALS)
        header = _canonical(dict(schema=LOCAL_DELIVERY_SCHEMA, role=self.role, setupSha256=self.setup_sha,
            observationSha256=self.observation_sha, observationBytes=len(self.original)))
        while True:
            self.check(peer=True)
            try:
                sent = self.channel.sendmsg([header], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [fd]))], socket.MSG_NOSIGNAL)
            except (BlockingIOError, InterruptedError):
                self._wait(True); continue
            if sent != len(header):
                raise LaunchError("local observation frame incomplete")
            break
        while True:
            self.check(peer=True)
            with _local_owning():
                try:
                    raw, ancillary, flags, _ = self.channel.recvmsg(65536, socket.CMSG_SPACE(253 * 4) + socket.CMSG_SPACE(12), socket.MSG_CMSG_CLOEXEC)
                except (BlockingIOError, InterruptedError):
                    raw = None
                if raw is not None:
                    rights, credentials = [], []
                    for level, kind, data in ancillary:
                        if level == socket.SOL_SOCKET and kind in (socket.SCM_RIGHTS, 4):
                            values = array.array("i"); values.frombytes(data[:len(data) - len(data) % 4])
                            for received in values:
                                self.incoming.append(received); rights.append(received)
                        elif level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS:
                            credentials.append(data)
            if raw is None:
                self._wait(); continue
            break
        if not raw or flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) or len(rights) != len(self.purposes) or (
                credentials != [struct.pack("=iII", self.setup["producer"]["pid"], 0, 0)] or any(
                level != socket.SOL_SOCKET or kind not in (socket.SCM_RIGHTS, socket.SCM_CREDENTIALS) or
                kind == socket.SCM_RIGHTS and len(data) % 4 for level, kind, data in ancillary)):
            raise LaunchError("local admission reply transport refused")
        reply = _local_document(raw, 65536)
        if set(reply) != {"schema", "role", "setupSha256", "observationSha256", "originals"} or (
                reply["schema"] != LOCAL_REPLY_SCHEMA or reply["role"] != self.role or
                reply["setupSha256"] != self.setup_sha or reply["observationSha256"] != self.observation_sha or
                type(reply["originals"]) is not list or len(reply["originals"]) != len(rights)):
            raise LaunchError("local admission reply association changed")
        limits = {"manifest": MAX_MANIFEST_BYTES, "certificate": MAX_LAUNCH_IDENTITY_CERTIFICATE_BYTES, "evidence": MAX_RUNTIME_EVIDENCE_BYTES}
        original_ids = set()
        for purpose, received, row in zip(self.purposes, rights, reply["originals"]):
            self.check(peer=True)
            original = _require_sealed_descriptor_number(received, label="local independently signed original", maximum=limits[purpose])
            info = os.fstat(received)
            if (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) != (0, 0, 0o400) or (
                    type(row) is not dict or set(row) != {"purpose", "sha256", "size"} or
                    row != dict(purpose=purpose, sha256="sha256:" + hashlib.sha256(original).hexdigest(), size=len(original)) or
                    (info.st_dev, info.st_ino) in original_ids):
                raise LaunchError("local admission original binding changed")
            original_ids.add((info.st_dev, info.st_ino))
        self.check(peer=True)
        with _local_owning():
            for purpose, received in zip(self.purposes, rights):
                target = LOCAL_SLOTS[purpose]
                if _local_identity(target) != self.stamps[target]:
                    raise LaunchError("local admission owned reservation changed")
                os.dup2(received, target, inheritable=False)
                self.stamps[target] = _local_identity(target)
            # These transport copies are not part of the signed operational
            # boundary. Only the exact reserved targets survive admission.
            try:
                while self.incoming:
                    os.close(self.incoming[-1]); self.incoming.pop()
                os.close(fd)
                self.handles.remove(fd)
            except BaseException:
                self.failed = True
                self.closing = True  # Never retry an uncertain descriptor close.
                raise
        self.delivered = True
        self.check(peer=True)

    def bind(self, payload):
        if self.bind_attempted:
            raise LaunchError("local admission binding cannot be retried")
        self.bind_attempted = True
        self.check(peer=True)
        request = payload.get("stageZeroRequest")
        if not self.delivered or type(request) is not dict or request.get("schema") != LOCAL_REQUEST_SCHEMA:
            raise LaunchError("local admission requires its explicit local request")
        observed = self.observation
        if request.get("listener") != observed["listener"] or request.get("mutableStateDescriptors") != observed["mutableStateDescriptors"] or (
                request.get("startupDescriptors") != observed["startupDescriptors"] or
                request.get("environment", {}).get("values") != observed["environment"] or
                request.get("execution", {}).get("argv") != observed["argv"] or
                any(request.get("execution", {}).get(key) != value for key, value in observed["execution"].items()) or
                os.getcwd() != observed["execution"]["cwd"] or
                request.get("process") != dict(processId=self.pid, processStartTicks=self.start,
                    bootIdDigest=self.boot, pidfd=observed["process"]["pidfd"])):
            raise LaunchError("signed local request differs from actual parked process")
        bootstrap = request.get("stageZero", {})
        if any(bootstrap.get(key) != observed["bootstrap"][key] for key in ("fd", "size", "sha256")) or (
                bootstrap.get("interpreter", {}).get("runtimePath") != observed["interpreter"]["path"] or
                bootstrap.get("interpreter", {}).get("sha256") != observed["interpreter"]["sha256"] or
                request["execution"].get("executableFd") != observed["interpreter"]["fd"]):
            raise LaunchError("signed local bootstrap differs from executed sources")
        for name in ("retainedFiles", "retainedDirectories"):
            actual = observed[name]; declared = request.get(name)
            if type(declared) is not list or len(declared) != len(actual) or {row.get("fd") for row in declared} != {row["fd"] for row in actual}:
                raise LaunchError("signed local descriptor roster changed")
            by_fd = {row["fd"]: row for row in declared}
            if any(any(by_fd[row["fd"]].get(key) != value for key, value in row.items()) for row in actual):
                raise LaunchError("signed local descriptor identity changed")
        actual = {row["name"]: row for row in observed["credentials"]}
        declared = request.get("credentials")
        if type(declared) is not list or len(declared) != len(actual) or {row.get("name") for row in declared} != set(actual):
            raise LaunchError("signed local credential roster changed")
        for row in declared:
            seen = actual[row["name"]]
            if any(row.get(key) != seen[source] for key, source in (("fd", "fd"), ("size", "size"),
                    ("sha256", "sha256"), ("mode", "mode"), ("ownerUid", "uid"), ("seals", "seals"))):
                raise LaunchError("signed local credential binding changed")
        self.check(peer=True)

    def credential_resealed(self, descriptor):
        # The existing launcher replaces an admitted credential with its own
        # sealed copy. This is a source-fixed transition, not arbitrary rebinding.
        rows = [row for row in self.observation["credentials"] if row["fd"] == descriptor]
        actual = _local_stat(descriptor)
        if len(rows) != 1 or any(actual[key] != rows[0][key] for key in ("fd", "uid", "gid", "mode", "size", "sha256")):
            raise LaunchError("local admitted credential reseal changed its original")
        _require_sealed_descriptor(descriptor, "local admitted credential reseal")
        self.stamps[descriptor] = _local_identity(descriptor)

    def rearm_after_identity_drop(self):
        expected = self.setup["producer"]
        if os.getpid() != self.pid or os.getppid() != expected["pid"] or select.select([self.peer_fd], [], [], 0)[0]:
            raise LaunchError("local authority parent disappeared during identity drop")
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.prctl(1, signal.SIGTERM, 0, 0, 0) != 0 or os.getppid() != expected["pid"] or select.select([self.peer_fd], [], [], 0)[0]:
            raise LaunchError("local authority parent-death containment failed")

    def finish_after_identity_drop(self):
        self.rearm_after_identity_drop()
        now_boot, now_epoch = time.clock_gettime_ns(time.CLOCK_BOOTTIME), time.time_ns()
        if not (self.last_boot <= now_boot < self.setup["deadlineBoottimeNs"] and
                self.last_epoch <= now_epoch < self.setup["expiresAtUnixNanos"]):
            raise LaunchError("local authority original admission interval expired")
        uid, gid = ROLE_IDENTITIES[self.role]
        acknowledgment = _canonical(dict(schema="serverware.authorityTrustedHostLocalAdmitted/v1", role=self.role,
            setupSha256=self.setup_sha, observationSha256=self.observation_sha, pid=self.pid, uid=uid, gid=gid,
            startTimeTicks=self.start))
        if self.channel.send(acknowledgment, socket.MSG_NOSIGNAL) != len(acknowledgment):
            raise LaunchError("local authority admission acknowledgment incomplete")
        self.close()

    def close(self):
        if self.closed:
            return
        if self.closing or os.getpid() != self.pid or _process_identity(self.pid)[0] != self.start:
            raise LaunchError("local admission close is uncertain")
        self.closing = True
        with _local_owning():
            while self.incoming:
                os.close(self.incoming[-1]); self.incoming.pop()
            while self.handles:
                os.close(self.handles[-1]); self.handles.pop()
            if self.channel is not None:
                self.channel.close(); self.channel = None
            os.close(self.setup_fd)
        self.closed = True


def _enter(
    role: str,
    *,
    bootstrap_descriptor: int,
    manifest_descriptor: int,
    runtime_evidence_descriptor: int | None,
    handoff_descriptor: int | None,
    trusted_host_local: bool,
    native_readers: contextlib.ExitStack,
    public_revocation: bool = False,
    local_admission: tuple[int, str, int] | None = None,
) -> int:
    if type(public_revocation) is not bool or public_revocation and role not in {"verifier", "issuer", "executor"}:
        raise LaunchError("public revocation launch selection is not a fixed terminal role")
    expected_credentials = ROLE_CREDENTIAL_DESCRIPTOR_NAMES[role] | (
        {"SERVERWARE_PUBLIC_WEBAUTHN_REVOCATION_BOOTSTRAP_FD"} if public_revocation else set())
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
    parking = None
    if local_admission is not None:
        if not trusted_host_local or handoff_descriptor is not None:
            raise LaunchError("late local admission cannot select native or production entry")
        setup_fd, setup_sha, channel_fd = local_admission
        assignments = {name: _environment_descriptor(name.removesuffix("_FD"))
            for name in expected_credentials | {BOOTSTRAP_CONTROL_NAME} | (
                {RUNTIME_EVIDENCE_NAME} if role in RUNTIME_EVIDENCE_ROLES else set())}
        parking = _LocalAdmission.open(role=role, setup_fd=setup_fd, setup_sha256=setup_sha,
            channel_fd=channel_fd, bootstrap_fd=bootstrap_descriptor, assignments=assignments)
        parking.exchange()
    payload, manifest_digest, bootstrap_control_identity = _load_manifest(
        role, manifest_descriptor=manifest_descriptor,
    )
    if parking is not None:
        parking.bind(payload)
    runtime_evidence_identity = _observe_runtime_evidence(
        role, payload["stageZeroRequest"], runtime_evidence_descriptor,
    )
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
            or binding["descriptor"] == manifest_descriptor
            or binding["descriptor"] == runtime_evidence_descriptor
            or not isinstance(binding.get("kind"), str)
            or not binding["kind"]
            or not isinstance(binding.get("ownerUid"), int)
            or isinstance(binding.get("ownerUid"), bool)
            or binding["ownerUid"] != 0
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
            != expected_credentials
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
        close=payload["stageZeroRequest"].get("schema") != LOCAL_REQUEST_SCHEMA,
    )
    private_descriptor = _environment_descriptor(
        "SERVERWARE_AUTHORITY_LAUNCH_PRIVATE_KEY"
    )
    certificate_descriptor = _environment_descriptor(
        "SERVERWARE_AUTHORITY_LAUNCH_CERTIFICATE"
    )
    sealed_entries: dict[str, dict[str, Any]] = {}
    loaded_native_mappings: dict[str, str] = {}
    retained: set[int] = {
        3,
        private_descriptor,
        certificate_descriptor,
        manifest_descriptor,
    }
    if handoff_descriptor is not None:
        retained.add(handoff_descriptor)
    if runtime_evidence_descriptor is not None:
        retained.add(runtime_evidence_descriptor)
    if len(retained) != (
        4 + (handoff_descriptor is not None)
        + (runtime_evidence_descriptor is not None)
    ):
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
    other_request_descriptors = {
        3,
        private_descriptor,
        certificate_descriptor,
        *(binding["descriptor"] for binding in credential_descriptors),
        stage_zero_value["fd"],
        *(entry["fd"] for entry in retained_file_values),
        *(entry["fd"] for entry in retained_directory_values),
        *(entry["fd"] for entry in mutable_state_values),
        request["listener"]["fd"],
        request["process"]["pidfd"]["fd"],
        request["launch"]["privateKeyTargetFd"],
        request["launch"]["certificateTargetFd"],
        *(entry["fd"] for entry in request["credentials"]),
    }
    if handoff_descriptor is not None:
        other_request_descriptors.add(handoff_descriptor)
    if manifest_descriptor in other_request_descriptors:
        raise LaunchError("bootstrap control aliases another stage-zero descriptor")
    if runtime_evidence_descriptor is not None and (
        runtime_evidence_descriptor == manifest_descriptor
        or runtime_evidence_descriptor in other_request_descriptors
    ):
        raise LaunchError("runtime evidence aliases another stage-zero descriptor")
    # Numeric declarations remain disjoint even when stage zero intentionally
    # closes their descriptors at exec. Only inherited descriptors can be
    # checked for a physical alias in this process.
    inherited_descriptors = {
        *request["execution"]["preserveFds"],
        3,
        private_descriptor,
        certificate_descriptor,
        *(binding["descriptor"] for binding in credential_descriptors),
    }
    if handoff_descriptor is not None:
        inherited_descriptors.add(handoff_descriptor)
    if runtime_evidence_descriptor is not None:
        inherited_descriptors.add(runtime_evidence_descriptor)
    inherited_descriptors.discard(manifest_descriptor)
    for descriptor in inherited_descriptors:
        metadata = os.fstat(descriptor)
        if (metadata.st_dev, metadata.st_ino) == bootstrap_control_identity[1:3]:
            raise LaunchError("bootstrap control inode aliases another descriptor")
    if runtime_evidence_identity is not None:
        evidence_others = inherited_descriptors - {runtime_evidence_descriptor}
        evidence_others.add(manifest_descriptor)
        for descriptor in evidence_others:
            metadata = os.fstat(descriptor)
            if (metadata.st_dev, metadata.st_ino) == runtime_evidence_identity[1:3]:
                raise LaunchError("runtime evidence inode aliases another descriptor")
    retained.update(
        {
            *(entry["fd"] for entry in retained_file_values if entry["surviveExec"]),
            *(entry["fd"] for entry in retained_directory_values if entry["surviveExec"]),
            *(entry["fd"] for entry in mutable_state_values),
        }
    )
    if stage_zero_value["fd"] in request["execution"]["preserveFds"]:
        retained.add(stage_zero_value["fd"])
    native_files = _native_file_index(retained_file_values)
    _retain_native_mapped_sources(
        retained_file_values, native_mappings, native_files, native_readers,
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
            # dlopen reopens the proc-FD path after permanent UID drop. These
            # are public immutable code bytes, never sources or credentials.
            mode=0o444 if entry_value["kind"] == "extension" else 0o400,
        )
        retained.add(sealed)
        native_binding = None
        if entry_value["kind"] == "extension":
            native_binding = _native_file_binding(
                sealed, entry_value["sha256"], sealed=True,
            )
            native_path = f"/memfd:{entry_value['module']} (deleted)"
            if native_path in native_files:
                raise LaunchError("sealed native mapping identity is ambiguous")
            native_files[native_path] = native_binding
        if entry_value["module"]:
            if entry_value["module"] in sealed_entries:
                raise LaunchError("launch module identity is duplicated")
            sealed_entries[entry_value["module"]] = {
                **entry_value,
                "descriptor": sealed,
                "nativeBinding": native_binding,
            }
    expected_native = dict(native_mappings)
    with _retained_process_memory() as memory:
        verified_native = _verify_native_mappings(
            expected_native, require_exact=False,
            files=native_files, memory=memory,
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
        if parking is not None:
            parking.credential_resealed(descriptor)
    _require_bootstrap_control_identity(bootstrap_control_identity)
    if runtime_evidence_identity is not None:
        _require_runtime_evidence_identity(runtime_evidence_identity)
    required_contract_modules = {
        "serverware.authority_artifact_spec",
        "serverware.authority_stage_zero_contract",
        "scripts.authority.atomic_provisioner_contract",
    }
    if not required_contract_modules.issubset(sealed_entries):
        raise LaunchError(
            "canonical authority contracts are outside the measured closure"
        )
    sys.meta_path.insert(0, _SealedClosureFinder(sealed_entries, loaded_native_mappings))
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
    if parking is not None:
        parking.check(peer=True)
    os.environ["SERVERWARE_PROCESS_MODE"] = PROCESS_MODES[role]
    # Keep these dlopen handles alive in this frame until service main returns.
    native_dependency_handles = ()
    with _retained_process_memory() as memory:
        _drop_role_identity(role)
        if parking is not None:
            parking.rearm_after_identity_drop()
        from serverware import authority_launch_guard

        _require_bootstrap_control_identity(bootstrap_control_identity)
        if runtime_evidence_identity is not None:
            _require_runtime_evidence_identity(runtime_evidence_identity)
        authority_launch_guard.activate(
            role=role,
            manifest_digest=manifest_digest,
            retained_descriptors=frozenset(retained),
            bootstrap_control_identity=bootstrap_control_identity,
            runtime_evidence_identity=runtime_evidence_identity,
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
        if parking is not None:
            parking.finish_after_identity_drop()
        if role == "witness":
            from serverware import authority_witness
        else:
            from serverware import authority_service

        if role != "witness":
            native_dependency_handles = _preload_native_dependencies(
                verified_package.package["bundle"], native_files, verified_native,
                modules=("psycopg_binary.pq", "psycopg_binary._psycopg"),
            )
            importlib.import_module("psycopg")
        dependencies = _loaded_native_dependency_mappings(
            verified_package.package["bundle"], loaded_native_mappings,
        )
        for additions in (loaded_native_mappings, dependencies):
            if any(path in expected_native and expected_native[path] != digest
                   for path, digest in additions.items()):
                raise LaunchError("sealed native mapping identity is ambiguous")
            expected_native.update(additions)
        _verify_native_mappings(
            expected_native, require_exact=True,
            files=native_files, memory=memory,
        )
    # No own-memory descriptor reaches authority code or runtime FD observation.
    native_readers.close()
    if role == "witness":
        return authority_witness.main()
    if role == "runtime":
        if trusted_host_local:
            # Version selection only; the consumer independently verifies the
            # existing root signature and all trust fields. V1 is unchanged.
            trust_fd = int(os.environ["SERVERWARE_POLICY_AUTHORITY_RUNTIME_TRUST_FD"])
            trust_size = os.fstat(trust_fd).st_size
            if not 1 <= trust_size <= authority_service.MAX_RUNTIME_TRUST_BYTES:
                raise LaunchError("runtime trust size is invalid")
            trust = json.loads(_read_file(trust_fd, trust_size))
            if (isinstance(trust, dict) and isinstance(trust.get("payload"), dict)
                    and trust["payload"].get("schema") == authority_service.RUNTIME_TRUST_POST_SEAL_SCHEMA):
                authority_launch_guard.observe_local_runtime_descriptors()
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
    parser.add_argument("--local-admission-fd", type=int)
    parser.add_argument("--local-admission-sha256")
    parser.add_argument("--local-admission-channel-fd", type=int)
    parser.add_argument(
        "--descriptor",
        action="append",
        default=[],
    )
    parser.add_argument("role", choices=sorted(PROCESS_MODES))
    parser.add_argument("--public-webauthn-revocation", action="store_true")
    args = parser.parse_args(argv)
    selected_local = (args.local_admission_fd, args.local_admission_sha256, args.local_admission_channel_fd)
    local_admission = None
    if any(value is not None for value in selected_local):
        if not all(value is not None for value in selected_local) or not args.trusted_host_local or args.stage_zero_handoff_fd is not None or (
                args.local_admission_fd < 3 or args.local_admission_channel_fd < 3 or
                len(args.local_admission_sha256) != 71 or not args.local_admission_sha256.startswith("sha256:") or
                any(character not in "0123456789abcdef" for character in args.local_admission_sha256[7:])):
            raise LaunchError("local admission requires the exact explicit descriptor triple")
        local_admission = selected_local
    if args.public_webauthn_revocation and args.role not in {"verifier", "issuer", "executor"}:
        raise LaunchError("public revocation launch selection has another role")
    required_assignments = (
        ROLE_CREDENTIAL_DESCRIPTOR_NAMES[args.role] | {BOOTSTRAP_CONTROL_NAME}
    )
    if args.public_webauthn_revocation:
        required_assignments |= {"SERVERWARE_PUBLIC_WEBAUTHN_REVOCATION_BOOTSTRAP_FD"}
    if args.role in RUNTIME_EVIDENCE_ROLES:
        required_assignments |= {RUNTIME_EVIDENCE_NAME}
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
            or name not in required_assignments
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
    if local_admission is not None:
        independent_descriptors.update((args.local_admission_fd, args.local_admission_channel_fd))
    expected_descriptor_count = len(assignments) + (
        5 if args.stage_zero_handoff_fd is not None else 4
    ) + (2 if local_admission is not None else 0)
    if (
        set(assignments)
        != required_assignments
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
    with contextlib.ExitStack() as native_readers:
        return _enter(
            args.role,
            bootstrap_descriptor=args.bootstrap_fd,
            manifest_descriptor=assignments[BOOTSTRAP_CONTROL_NAME],
            runtime_evidence_descriptor=assignments.get(RUNTIME_EVIDENCE_NAME),
            handoff_descriptor=args.stage_zero_handoff_fd,
            trusted_host_local=args.trusted_host_local,
            native_readers=native_readers,
            public_revocation=args.public_webauthn_revocation,
            local_admission=local_admission,
        )



# Duplicated in the measured entrypoint: bootstrap diagnostics must not import
# a new, not-yet-measured formatter module across the exec boundary.
def _private_startup_stderr():
    """Only an already-open private supervisor file is a diagnostic sink."""
    try:
        info = os.fstat(2)
        access = fcntl.fcntl(2, fcntl.F_GETFL) & os.O_ACCMODE
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
                or access not in (os.O_WRONLY, os.O_RDWR)):
            return None
        return (info.st_dev, info.st_ino, info.st_mode, info.st_uid,
                info.st_gid, info.st_nlink, access)
    except BaseException:
        return None


def _startup_failure(error):
    """Bounded metadata only; never format exception messages or frame values."""
    try:
        sink = _private_startup_stderr()
        if sink is None:
            return
        def name(value):
            allowed = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.<>-"
            return value if (type(value) is str and 1 <= len(value) <= 96
                and all(character in allowed for character in value)) else "unknown"
        lines, seen, current = [], set(), error
        for index in range(5):
            if not isinstance(current, BaseException) or id(current) in seen:
                break
            seen.add(id(current))
            lines.append(f"AUTHORITY_CHILD_STARTUP_FAILURE_CAUSE={index}:{name(type(current).__name__)}")
            trace = current.__traceback__
            for _ in range(8):
                if trace is None:
                    break
                code, line = trace.tb_frame.f_code, trace.tb_lineno
                filename = code.co_filename
                basename = filename.rsplit("/", 1)[-1] if type(filename) is str and len(filename) <= 4096 else "unknown"
                if basename.isdecimal():
                    basename = "bootstrap"
                line = line if type(line) is int and 0 < line < 2**31 else 0
                lines.append(f"AUTHORITY_CHILD_STARTUP_FAILURE_FRAME={index}:{name(basename)}:{name(code.co_name)}:{line}")
                trace = trace.tb_next
            current = current.__cause__ if current.__cause__ is not None else current.__context__
        raw = ("\n".join(lines) + "\n").encode("ascii")
        if len(raw) <= 16384 and _private_startup_stderr() == sink:
            os.write(2, raw)
    except BaseException:
        pass  # A broken diagnostic path must not replace the original failure.


def _startup_main():
    try:
        return main()
    except SystemExit as error:
        if error.code is None or isinstance(error.code, int):
            raise
        _startup_failure(error)
        return 1
    except KeyboardInterrupt as error:
        _startup_failure(error)
        return 130
    except BaseException as error:
        _startup_failure(error)
        return 1

if __name__ == "__main__":
    raise SystemExit(_startup_main())
