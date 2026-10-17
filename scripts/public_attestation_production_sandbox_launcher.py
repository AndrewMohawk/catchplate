#!/usr/bin/env python3
"""Fail-closed launcher for the public-attestation production producer.

This source is part of the measured launcher trust boundary. Interpreting the
.py file is fixture-only. Production mode requires a freezer to embed this
source and all imported modules into one isolated, no-site, environment-
ignoring static ELF artifact whose digest is independently pinned by the
parent attestation descriptor. The launcher accepts only retained descriptors,
never invokes a shell, and emits the production READY token only after the
producer is blocked behind a gate and every sandbox control was observed. The
producer must also be a static ELF because the sandbox root has no loader.

Fixture execution uses a distinct descriptor mode, a distinct command-line
flag, and a distinct readiness token. It is never evidence of production
containment. The ordinary host kernel and host root are trusted. This launcher
does not claim hostile-host or whole-codebase proof.
"""

from __future__ import annotations

import argparse
import base64
import ctypes
import errno
import fcntl
import hashlib
import json
import os
import platform
import re
import resource
import select
import signal
import socket
import stat
import struct
import sys
import time
from dataclasses import dataclass, replace
from typing import Any


SANDBOX_VERSION = "catchplate.publicAttestationExecutionSandbox/v2"
MAX_DESCRIPTOR_BYTES = 64 * 1024
MAX_CONFIG_BYTES = 1024 * 1024
MAX_NAMED_FILE_BYTES = 256 * 1024 * 1024
MAX_NAMED_DOCUMENT_BYTES = 4 * 1024 * 1024
MAX_SERVICE_FRAME_BYTES = 16 * 1024
MAX_CONTROL_FILE_BYTES = 64 * 1024
MAX_PROC_FILE_BYTES = 1024 * 1024
MAX_SAFE_FD = 1 << 20
MAX_U64 = (1 << 64) - 1
FIXED_PRODUCER_EXECUTABLE_FD = 126
CGROUP2_SUPER_MAGIC = 0x63677270
SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z", re.ASCII)
IDENTIFIER_RE = re.compile(
    r"[A-Za-z][A-Za-z0-9._:@+-]{0,127}\Z",
    re.ASCII,
)
PATH_COMPONENT_RE = re.compile(r"[A-Za-z0-9._+@=-]+\Z", re.ASCII)
CGROUP_COMPONENT_RE = re.compile(r"[A-Za-z0-9._+@=-]+\Z", re.ASCII)
EXPECTED_NAMESPACES = ("cgroup", "ipc", "mount", "network", "pid", "uts")
NAMESPACE_PROC_NAMES = {
    "cgroup": "cgroup",
    "ipc": "ipc",
    "mount": "mnt",
    "network": "net",
    "pid": "pid",
    "uts": "uts",
}
CAPABILITY_STATUS_FIELDS = (
    "CapAmb",
    "CapBnd",
    "CapEff",
    "CapInh",
    "CapPrm",
)
LIMIT_FILE_NAMES = (
    "cgroup.max.depth",
    "cgroup.max.descendants",
    "cpu.max",
    "cpu.weight",
    "io.max",
    "memory.high",
    "memory.max",
    "memory.oom.group",
    "memory.swap.max",
    "pids.max",
)
PRODUCTION_READY = b"READY\n"
FIXTURE_READY = b"NON_PRODUCTION_FIXTURE_READY\n"
CHILD_PREPARED = b"SANDBOXED\n"
CHILD_GO = b"G"
PRODUCER_COMMAND_VERSION = "catchplate.publicAttestationProducerCommand/v1"
CONFIG_VERSION = "catchplate.publicAttestationConfig/v2"
SERVICE_CHALLENGE_VERSION = (
    "catchplate.publicAttestationServiceChannelChallenge/v1"
)
SERVICE_CHALLENGE_RESPONSE_VERSION = (
    "catchplate.publicAttestationServiceChannelChallengeResponse/v1"
)
PRODUCER_FD_ROLE_FIELDS = (
    "nonceRequest",
    "nonceResponse",
    "producerDescriptor",
    "producerEphemeralSeed",
    "producerExecutableMeasurement",
    "producerRequestSchema",
    "sandboxDescriptorMeasurement",
    "sandboxLauncher",
    "stableReleaseStatement",
    "trustRoots",
    "witnessRequest",
    "witnessResponse",
)
CBPF_INSTRUCTION = struct.Struct("<HBBI")
BPF_LD_W_ABS = 0x20
BPF_JMP_JEQ_K = 0x15
BPF_RET_K = 0x06
SECCOMP_DATA_NR_OFFSET = 0
SECCOMP_DATA_ARCH_OFFSET = 4
SECCOMP_RET_KILL_PROCESS = 0x80000000
SECCOMP_RET_ALLOW = 0x7FFF0000
X32_SYSCALL_BIT = 0x40000000
AUDIT_ARCHITECTURES = {
    "x86_64": 0xC000003E,
    "aarch64": 0xC00000B7,
}
KERNEL_ABI_CONTRACTS = {
    "x86_64": {
        "audit_architecture": 0xC000003E,
        "syscall_table_id": "linux-uapi-x86_64-catchplate-v1",
        "syscall_table_sha256":
            "sha256:2e3b41282fd357204e77d43bf1b9cd9fcf7bfc271c32513bb813052d099e8e0b",
        "syscalls": {
            "brk": 12,
            "clock_gettime": 228,
            "close": 3,
            "execveat": 322,
            "exit": 60,
            "exit_group": 231,
            "fstat": 5,
            "futex": 202,
            "getpid": 39,
            "getrandom": 318,
            "gettid": 186,
            "lseek": 8,
            "read": 0,
            "rt_sigreturn": 15,
            "seccomp": 317,
            "write": 1,
        },
    },
    "aarch64": {
        "audit_architecture": 0xC00000B7,
        "syscall_table_id": "linux-uapi-aarch64-catchplate-v1",
        "syscall_table_sha256":
            "sha256:2111fcbddd04d564b6d478b442b7cd543bf1075b13ce4eef7f9d42677070f21f",
        "syscalls": {
            "brk": 214,
            "clock_gettime": 113,
            "close": 57,
            "execveat": 281,
            "exit": 93,
            "exit_group": 94,
            "fstat": 80,
            "futex": 98,
            "getpid": 172,
            "getrandom": 278,
            "gettid": 178,
            "lseek": 62,
            "read": 63,
            "rt_sigreturn": 139,
            "seccomp": 277,
            "write": 64,
        },
    },
}
BOOTSTRAP_SYSCALL_NAMES = (
    "brk",
    "clock_gettime",
    "close",
    "execveat",
    "exit",
    "exit_group",
    "fstat",
    "futex",
    "getpid",
    "getrandom",
    "gettid",
    "lseek",
    "read",
    "rt_sigreturn",
    "seccomp",
    "write",
)
RUNTIME_SYSCALL_NAMES = tuple(
    name
    for name in BOOTSTRAP_SYSCALL_NAMES
    if name not in {"execveat", "seccomp"}
)
PRODUCTION_POST_EXEC_PREREQUISITE = (
    "measured-static-entry-stubs-plus-launcher-frame-broker-plus-"
    "read-only-cgroupns-v1"
)
SCM_CREDENTIALS_SIZE = struct.calcsize("3i")

# These definitions are intentionally inert. External tests should materialize
# each mutation and prove that the corresponding production admission rejects it.
SOURCE_ONLY_NEGATIVE_SANDBOX_FIXTURES = (
    "seccomp-allow-all",
    "seccomp-profile-byte-drift",
    "seccomp-unknown-syscall",
    "seccomp-wrong-kernel-abi",
    "seccomp-recvmsg-recvmmsg",
    "seccomp-open-pidfd-getfd-or-scm-rights",
    "seccomp-memfd-module-bpf-io-uring-or-network",
    "seccomp-fork-namespace-or-ptrace",
    "seccomp-executable-memory-transition",
    "producer-dynamic-elf",
    "launcher-dynamic-or-interpreted",
    "service-post-exec-filter-digest-unverifiable",
    "service-stream-instead-of-seqpacket",
    "service-missing-scm-credentials",
    "service-wrong-scm-credentials",
    "service-peer-pid-reuse",
    "service-seccomp-filter-count-drift",
    "service-scm-rights",
    "service-unknown-control-message",
    "service-exclusive-custody-overclaim",
    "service-anonymous-executable-map",
    "service-dynamic-shared-object-map",
    "service-cgroup-writable-ancestor",
    "service-cgroup-ancestor-acl",
    "service-cgroup-retained-fd",
    "service-cgroup-fd-under-alternate-path",
    "service-cgroup-writable-mount",
    "owner-liveness-not-seqpacket",
    "owner-liveness-eof",
    "owner-liveness-payload",
    "absolute-command-deadline",
    "producer-descendant-pid-reuse",
    "producer-descendant-pidfd-unavailable",
    "cleanup-reused-pgid-forbidden",
    "producer-fast-success-before-readiness-read",
    "guarded-service-exec-during-response",
    "quarantine-cleanup-timeout",
)


def _source_only_negative_sandbox_fixture_contract() -> dict[str, Any]:
    if len(SOURCE_ONLY_NEGATIVE_SANDBOX_FIXTURES) != len(
        set(SOURCE_ONLY_NEGATIVE_SANDBOX_FIXTURES)
    ):
        raise LauncherError("source-only negative fixture IDs are not unique")
    return {
        "cases": SOURCE_ONLY_NEGATIVE_SANDBOX_FIXTURES,
        "expectedResult": "reject-before-production-ready-or-kill-and-prove-dead",
        "mustNotExecuteAtImport": True,
    }

# Linux clone flags.
CLONE_NEWNS = 0x00020000
CLONE_NEWUTS = 0x04000000
CLONE_NEWIPC = 0x08000000
CLONE_NEWPID = 0x20000000
CLONE_NEWNET = 0x40000000
CLONE_NEWCGROUP = 0x02000000
REQUIRED_UNSHARE_FLAGS = (
    CLONE_NEWNS
    | CLONE_NEWUTS
    | CLONE_NEWIPC
    | CLONE_NEWPID
    | CLONE_NEWNET
    | CLONE_NEWCGROUP
)

# mount(2) and mount_setattr(2).
MS_RDONLY = 1
MS_NOSUID = 2
MS_NODEV = 4
MS_NOEXEC = 8
MS_REC = 16384
MS_PRIVATE = 1 << 18
AT_FDCWD = -100
AT_RECURSIVE = 0x8000
MOUNT_ATTR_RDONLY = 0x00000001
MOUNT_ATTR_NOSUID = 0x00000002
MOUNT_ATTR_NODEV = 0x00000004
MOUNT_ATTR_NOEXEC = 0x00000008
RESTRICTED_MOUNT_ATTRIBUTES = (
    MOUNT_ATTR_RDONLY
    | MOUNT_ATTR_NOSUID
    | MOUNT_ATTR_NODEV
    | MOUNT_ATTR_NOEXEC
)

# prctl(2), seccomp(2), and inotify(7).
PR_SET_PDEATHSIG = 1
PR_CAPBSET_DROP = 24
PR_SET_NO_NEW_PRIVS = 38
PR_SET_CHILD_SUBREAPER = 36
PR_CAP_AMBIENT = 47
PR_CAP_AMBIENT_CLEAR_ALL = 4
SECCOMP_SET_MODE_FILTER = 1
PTRACE_SEIZE = 0x4206
PTRACE_INTERRUPT = 0x4207
PTRACE_GETEVENTMSG = 0x4201
PTRACE_CONT = 7
PTRACE_DETACH = 17
PTRACE_O_TRACEFORK = 0x00000002
PTRACE_O_TRACEVFORK = 0x00000004
PTRACE_O_TRACECLONE = 0x00000008
PTRACE_O_TRACEEXEC = 0x00000010
PTRACE_O_EXITKILL = 0x00100000
PTRACE_EVENT_FORK = 1
PTRACE_EVENT_VFORK = 2
PTRACE_EVENT_CLONE = 3
PTRACE_EVENT_EXEC = 4
PTRACE_EVENT_STOP = 128
SERVICE_PTRACE_OPTIONS = (
    PTRACE_O_TRACEFORK
    | PTRACE_O_TRACEVFORK
    | PTRACE_O_TRACECLONE
    | PTRACE_O_TRACEEXEC
    | PTRACE_O_EXITKILL
)
WAIT_ALL = getattr(os, "WALL", 0x40000000)
IN_NONBLOCK = os.O_NONBLOCK
IN_CLOEXEC = os.O_CLOEXEC
IN_ATTRIB = 0x00000004
IN_MODIFY = 0x00000002
IN_DELETE_SELF = 0x00000400
IN_MOVE_SELF = 0x00000800
IN_IGNORED = 0x00008000
LIMIT_WATCH_MASK = (
    IN_ATTRIB | IN_MODIFY | IN_DELETE_SELF | IN_MOVE_SELF | IN_IGNORED
)
F_SEAL_SEAL = getattr(fcntl, "F_SEAL_SEAL", 0x0001)
F_SEAL_SHRINK = getattr(fcntl, "F_SEAL_SHRINK", 0x0002)
F_SEAL_GROW = getattr(fcntl, "F_SEAL_GROW", 0x0004)
F_SEAL_WRITE = getattr(fcntl, "F_SEAL_WRITE", 0x0008)
REQUIRED_SEALS = F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE

ARCHITECTURES = {
    "x86_64": {
        "elf_machine": 62,
        "seccomp_syscall": 317,
        "mount_setattr_syscall": 442,
    },
    "aarch64": {
        "elf_machine": 183,
        "seccomp_syscall": 277,
        "mount_setattr_syscall": 442,
    },
}

LIBC = ctypes.CDLL(None, use_errno=True)


class LauncherError(RuntimeError):
    """A sanitized fail-closed launcher error."""


class StoreOnce(argparse.Action):
    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: Any,
        option_string: str | None = None,
    ) -> None:
        if getattr(namespace, self.dest, None) is not None:
            parser.error(f"{option_string or self.dest} may appear only once")
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
            parser.error(f"{option_string or self.dest} contains a duplicate")
        current.append(values)
        setattr(namespace, self.dest, current)


class SockFilter(ctypes.Structure):
    _fields_ = [
        ("code", ctypes.c_ushort),
        ("jt", ctypes.c_ubyte),
        ("jf", ctypes.c_ubyte),
        ("k", ctypes.c_uint32),
    ]


class SockFprog(ctypes.Structure):
    _fields_ = [
        ("length", ctypes.c_ushort),
        ("filter", ctypes.POINTER(SockFilter)),
    ]


class MountAttr(ctypes.Structure):
    _fields_ = [
        ("attr_set", ctypes.c_uint64),
        ("attr_clr", ctypes.c_uint64),
        ("propagation", ctypes.c_uint64),
        ("userns_fd", ctypes.c_uint64),
    ]


class StatFs(ctypes.Structure):
    _fields_ = [
        ("f_type", ctypes.c_long),
        ("f_bsize", ctypes.c_long),
        ("f_blocks", ctypes.c_ulong),
        ("f_bfree", ctypes.c_ulong),
        ("f_bavail", ctypes.c_ulong),
        ("f_files", ctypes.c_ulong),
        ("f_ffree", ctypes.c_ulong),
        ("f_fsid", ctypes.c_int * 2),
        ("f_namelen", ctypes.c_long),
        ("f_frsize", ctypes.c_long),
        ("f_flags", ctypes.c_long),
        ("f_spare", ctypes.c_long * 4),
    ]


@dataclass(frozen=True)
class NamedFdRule:
    role: str
    target_fd: int
    kind: str
    access: str
    document: dict[str, Any]


@dataclass(frozen=True)
class ServicePeerState:
    role: str
    descriptor: int
    pid: int
    pidfd: int
    architecture: str
    production_mode: bool
    cgroup_descriptor: int
    cgroup_identity: tuple[int, int]
    executable_identity: tuple[int, int]
    executable_sha256: str
    executable_map_closure_sha256: str
    post_exec_profile_sha256: str
    required_seccomp_filter_count: int
    cgroup_ancestor_closure_sha256: str
    cgroup_path: str


@dataclass
class ServiceExecGuard:
    pid: int
    pidfd: int
    cgroup_descriptor: int
    roles: tuple[str, ...]
    spawned_pidfds: list[int]
    attached: bool = True
    stopped: bool = False
    violated: bool = False


@dataclass(frozen=True)
class ObservedProcessIdentity:
    pid: int
    pidfd: int
    start_time_ticks: int


@dataclass(frozen=True)
class ValidatedDescriptor:
    document: dict[str, Any]
    execution_mode: str
    uid: int
    gid: int
    architecture: str
    root_path: str
    root_identity: dict[str, int]
    root_max_bytes: int
    seccomp_sha256: str
    seccomp_instruction_count: int
    seccomp_profile_id: str
    runtime_seccomp_sha256: str
    cgroup_path: str
    cgroup_membership_path: str
    cgroup_identity: dict[str, int]
    cgroup_limits: dict[str, Any]
    executable_sha256: str
    executable_argv: tuple[str, ...]
    executable_environment: dict[str, str]
    producer_command: dict[str, Any]
    command_timeout_seconds: float
    input_max_bytes: int
    config_target_fd: int
    config_max_bytes: int
    config_binding: dict[str, str]
    named_fd_rules: tuple[NamedFdRule, ...]
    startup_timeout_seconds: float
    poll_seconds: float
    cleanup_timeout_seconds: float


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise LauncherError("JSON contains a duplicate object member")
        result[key] = value
    return result


def _reject_number(value: str) -> None:
    raise LauncherError("JSON contains a non-integer number")


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
        raise LauncherError("document is not canonical JSON") from exc


def _load_canonical_document(
    raw: bytes,
    *,
    label: str,
    maximum: int = MAX_DESCRIPTOR_BYTES,
) -> dict[str, Any]:
    if not raw or len(raw) > maximum:
        raise LauncherError(f"{label} exceeds its closed byte contract")
    try:
        value = json.loads(
            raw.decode("ascii"),
            object_pairs_hook=_strict_object,
            parse_constant=_reject_number,
            parse_float=_reject_number,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise LauncherError(f"{label} is not strict ASCII JSON") from exc
    if not isinstance(value, dict):
        raise LauncherError(f"{label} must be one object")
    if raw != _canonical_json(value) + b"\n":
        raise LauncherError(f"{label} must be canonical JSON plus LF")
    return value


def _exact_object(
    value: Any,
    fields: set[str],
    *,
    label: str,
) -> dict[str, Any]:
    if (
        not isinstance(value, dict)
        or set(value) != fields
        or not all(isinstance(key, str) for key in value)
    ):
        raise LauncherError(f"{label} has an invalid closed shape")
    return value


def _integer(
    value: Any,
    *,
    label: str,
    minimum: int,
    maximum: int,
) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise LauncherError(f"{label} is outside its integer bounds")
    return value


def _text(
    value: Any,
    *,
    label: str,
    minimum: int = 0,
    maximum: int,
    pattern: re.Pattern[str] | None = None,
) -> str:
    if (
        not isinstance(value, str)
        or not minimum <= len(value) <= maximum
        or "\x00" in value
        or (pattern is not None and pattern.fullmatch(value) is None)
    ):
        raise LauncherError(f"{label} is invalid")
    return value


def _digest(value: Any, *, label: str) -> str:
    return _text(
        value,
        label=label,
        minimum=71,
        maximum=71,
        pattern=SHA256_RE,
    )


def _identifier(value: Any, *, label: str) -> str:
    return _text(
        value,
        label=label,
        minimum=1,
        maximum=128,
        pattern=IDENTIFIER_RE,
    )


def _absolute_path(
    value: Any,
    *,
    label: str,
    prefix: str | None = None,
) -> str:
    path = _text(value, label=label, minimum=2, maximum=4096)
    if (
        not path.startswith("/")
        or path.endswith("/")
        or "//" in path
        or any(
            part in {"", ".", ".."}
            or PATH_COMPONENT_RE.fullmatch(part) is None
            for part in path.split("/")[1:]
        )
        or os.path.normpath(path) != path
        or (prefix is not None and not path.startswith(prefix))
    ):
        raise LauncherError(f"{label} is not one normalized absolute path")
    return path


def _membership_path(value: Any, *, label: str) -> str:
    path = _absolute_path(value, label=label)
    if any(
        CGROUP_COMPONENT_RE.fullmatch(part) is None
        for part in path.split("/")[1:]
    ):
        raise LauncherError(f"{label} has an invalid cgroup component")
    return path


def _const(value: Any, expected: Any, *, label: str) -> None:
    if value != expected or type(value) is not type(expected):
        raise LauncherError(f"{label} differs from the required constant")


def _filesystem_identity(
    value: Any,
    *,
    label: str,
    root_owned: bool,
) -> dict[str, int]:
    document = _exact_object(
        value,
        {"device", "gid", "inode", "mode", "uid"},
        label=label,
    )
    identity = {
        "device": _integer(
            document["device"],
            label=f"{label} device",
            minimum=0,
            maximum=MAX_U64,
        ),
        "gid": _integer(
            document["gid"],
            label=f"{label} gid",
            minimum=0,
            maximum=MAX_U64,
        ),
        "inode": _integer(
            document["inode"],
            label=f"{label} inode",
            minimum=1,
            maximum=MAX_U64,
        ),
        "mode": _integer(
            document["mode"],
            label=f"{label} mode",
            minimum=0,
            maximum=0o7777,
        ),
        "uid": _integer(
            document["uid"],
            label=f"{label} uid",
            minimum=0,
            maximum=MAX_U64,
        ),
    }
    if root_owned and identity["uid"] != 0:
        raise LauncherError(f"{label} is not root-owned")
    return identity


def _validate_descriptor(
    document: dict[str, Any],
    *,
    fixture_mode: bool,
) -> ValidatedDescriptor:
    top = _exact_object(
        document,
        {
            "apiVersion",
            "capabilities",
            "cgroup",
            "executionMode",
            "executable",
            "fdPolicy",
            "identity",
            "monitoring",
            "namespaces",
            "network",
            "noNewPrivileges",
            "process",
            "productionClaim",
            "rootFilesystem",
            "seccomp",
            "trustBoundary",
        },
        label="sandbox descriptor",
    )
    _const(top["apiVersion"], SANDBOX_VERSION, label="sandbox API version")
    execution_mode = _text(
        top["executionMode"],
        label="sandbox execution mode",
        minimum=10,
        maximum=32,
    )
    expected_mode = "fixture-non-production" if fixture_mode else "production"
    _const(execution_mode, expected_mode, label="sandbox execution mode")
    _const(
        top["productionClaim"],
        not fixture_mode,
        label="sandbox production claim",
    )
    _const(top["noNewPrivileges"], True, label="no_new_privs policy")
    trust_boundary = _exact_object(
        top["trustBoundary"],
        {
            "claim",
            "hostKernelTrusted",
            "hostRootTrusted",
            "hostileHostProof",
            "launcherStaticElfRequired",
        },
        label="sandbox trust boundary",
    )
    _const(
        trust_boundary["claim"],
        "measured-process-and-retained-fd-containment-v2",
        label="sandbox claim",
    )
    _const(
        trust_boundary["hostKernelTrusted"],
        True,
        label="host-kernel trust",
    )
    _const(
        trust_boundary["hostRootTrusted"],
        True,
        label="host-root trust",
    )
    _const(
        trust_boundary["hostileHostProof"],
        False,
        label="hostile-host claim",
    )
    _const(
        trust_boundary["launcherStaticElfRequired"],
        True,
        label="static launcher policy",
    )

    identity = _exact_object(
        top["identity"],
        {"gid", "supplementaryGroups", "uid"},
        label="sandbox identity",
    )
    uid = _integer(
        identity["uid"],
        label="sandbox uid",
        minimum=1,
        maximum=(1 << 31) - 1,
    )
    gid = _integer(
        identity["gid"],
        label="sandbox gid",
        minimum=1,
        maximum=(1 << 31) - 1,
    )
    _const(
        identity["supplementaryGroups"],
        [],
        label="supplementary group policy",
    )

    capabilities = _exact_object(
        top["capabilities"],
        {"ambient", "bounding", "effective", "inheritable", "permitted"},
        label="capability policy",
    )
    for field in sorted(capabilities):
        _const(capabilities[field], [], label=f"{field} capabilities")

    namespaces = _exact_object(
        top["namespaces"],
        {"required", "userNamespace"},
        label="namespace policy",
    )
    _const(
        namespaces["required"],
        list(EXPECTED_NAMESPACES),
        label="required namespace order",
    )
    _const(namespaces["userNamespace"], False, label="user namespace policy")

    root = _exact_object(
        top["rootFilesystem"],
        {
            "bindMounts",
            "emptyTmpfs",
            "maxBytes",
            "nodev",
            "noexec",
            "nosuid",
            "path",
            "readOnlyAfterSetup",
            "rootDirectoryFdRole",
            "rootDirectoryIdentity",
        },
        label="root filesystem policy",
    )
    _const(
        root["rootDirectoryFdRole"],
        "sandboxRoot",
        label="sandbox root FD role",
    )
    root_path = _absolute_path(root["path"], label="sandbox root path")
    root_identity = _filesystem_identity(
        root["rootDirectoryIdentity"],
        label="sandbox root directory identity",
        root_owned=True,
    )
    if root_identity["mode"] & 0o022:
        raise LauncherError("sandbox root directory is group/other writable")
    _const(root["emptyTmpfs"], True, label="sandbox tmpfs policy")
    _const(root["readOnlyAfterSetup"], True, label="sandbox read-only policy")
    _const(root["nodev"], True, label="sandbox nodev policy")
    _const(root["noexec"], True, label="sandbox noexec policy")
    _const(root["nosuid"], True, label="sandbox nosuid policy")
    root_max_bytes = _integer(
        root["maxBytes"],
        label="sandbox tmpfs byte limit",
        minimum=1024 * 1024,
        maximum=1024 * 1024 * 1024,
    )
    mounts_value = root["bindMounts"]
    _const(
        mounts_value,
        [],
        label="public-attestation bind mount policy",
    )

    seccomp = _exact_object(
        top["seccomp"],
        {
            "architecture",
            "auditArchitecture",
            "bootstrapProfile",
            "contract",
            "defaultAction",
            "format",
            "kernelAbi",
            "runtimeProfile",
            "transition",
            "unknownSyscallAction",
        },
        label="seccomp policy",
    )
    _const(
        seccomp["contract"],
        "catchplate.closedSeccompProfile/v1",
        label="seccomp contract",
    )
    _const(
        seccomp["format"],
        "linux-cbpf-sock-filter-le-v1",
        label="seccomp profile format",
    )
    architecture = _text(
        seccomp["architecture"],
        label="seccomp architecture",
        minimum=7,
        maximum=8,
    )
    if architecture not in ARCHITECTURES:
        raise LauncherError("seccomp architecture is unsupported")
    abi_contract = KERNEL_ABI_CONTRACTS[architecture]
    _const(
        seccomp["auditArchitecture"],
        abi_contract["audit_architecture"],
        label="seccomp audit architecture",
    )
    _const(seccomp["defaultAction"], "kill-process", label="seccomp default")
    _const(
        seccomp["unknownSyscallAction"],
        "kill-process",
        label="unknown syscall action",
    )
    kernel_abi = _exact_object(
        seccomp["kernelAbi"],
        {"endianness", "syscallTableId", "syscallTableSha256", "wordBits"},
        label="seccomp kernel ABI",
    )
    _const(kernel_abi["endianness"], "little", label="kernel ABI endianness")
    _const(kernel_abi["wordBits"], 64, label="kernel ABI word size")
    _const(
        kernel_abi["syscallTableId"],
        abi_contract["syscall_table_id"],
        label="kernel ABI syscall table",
    )
    _const(
        kernel_abi["syscallTableSha256"],
        abi_contract["syscall_table_sha256"],
        label="kernel ABI syscall table digest",
    )
    bootstrap_profile = _exact_object(
        seccomp["bootstrapProfile"],
        {
            "allowedSyscalls",
            "instructionCount",
            "profileFdRole",
            "profileId",
            "profileSha256",
        },
        label="bootstrap seccomp profile",
    )
    _const(
        bootstrap_profile["profileFdRole"],
        "seccompProfile",
        label="seccomp profile FD role",
    )
    _const(
        bootstrap_profile["profileId"],
        f"catchplate-producer-bootstrap-{architecture}-v1",
        label="bootstrap seccomp profile ID",
    )
    _const(
        bootstrap_profile["allowedSyscalls"],
        list(BOOTSTRAP_SYSCALL_NAMES),
        label="bootstrap syscall allowlist",
    )
    seccomp_sha256 = _digest(
        bootstrap_profile["profileSha256"],
        label="seccomp profile digest",
    )
    seccomp_instruction_count = _integer(
        bootstrap_profile["instructionCount"],
        label="seccomp instruction count",
        minimum=1,
        maximum=4096,
    )
    _const(
        seccomp_instruction_count,
        4 + 2 * len(BOOTSTRAP_SYSCALL_NAMES) + 1,
        label="fixed bootstrap seccomp instruction count",
    )
    if seccomp_sha256 != _sha256(
        _closed_seccomp_profile_bytes(
            architecture=architecture,
            syscall_names=BOOTSTRAP_SYSCALL_NAMES,
        )
    ):
        raise LauncherError(
            "bootstrap seccomp digest differs from the fixed reviewed profile"
        )
    runtime_profile = _exact_object(
        seccomp["runtimeProfile"],
        {
            "allowedSyscalls",
            "embeddedInStaticProducer",
            "profileId",
            "profileSha256",
        },
        label="runtime seccomp profile",
    )
    _const(
        runtime_profile["profileId"],
        f"catchplate-producer-runtime-{architecture}-v1",
        label="runtime seccomp profile ID",
    )
    _const(
        runtime_profile["allowedSyscalls"],
        list(RUNTIME_SYSCALL_NAMES),
        label="runtime syscall allowlist",
    )
    _const(
        runtime_profile["embeddedInStaticProducer"],
        True,
        label="runtime profile embedding",
    )
    runtime_seccomp_sha256 = _digest(
        runtime_profile["profileSha256"],
        label="runtime seccomp profile digest",
    )
    if runtime_seccomp_sha256 != _sha256(
        _closed_seccomp_profile_bytes(
            architecture=architecture,
            syscall_names=RUNTIME_SYSCALL_NAMES,
        )
    ):
        raise LauncherError(
            "runtime seccomp digest differs from the fixed reviewed profile"
        )
    transition = _exact_object(
        seccomp["transition"],
        {
            "execFlags",
            "execSyscall",
            "executableFd",
            "externalEnforcementPrerequisite",
            "method",
            "requiredSeccompFilterCount",
        },
        label="seccomp transition",
    )
    _const(
        transition["method"],
        "measured-static-entrypoint-additive-filter",
        label="seccomp transition method",
    )
    _const(transition["execSyscall"], "execveat", label="bootstrap exec syscall")
    _const(
        transition["executableFd"],
        FIXED_PRODUCER_EXECUTABLE_FD,
        label="bootstrap executable FD",
    )
    _const(
        transition["execFlags"],
        ["AT_EMPTY_PATH"],
        label="bootstrap exec flags",
    )
    _const(
        transition["requiredSeccompFilterCount"],
        2,
        label="post-exec seccomp filter count",
    )
    _const(
        transition["externalEnforcementPrerequisite"],
        PRODUCTION_POST_EXEC_PREREQUISITE,
        label="post-exec enforcement prerequisite",
    )

    cgroup = _exact_object(
        top["cgroup"],
        {
            "disposable",
            "fdRole",
            "identity",
            "killMode",
            "limits",
            "ancestorProtection",
            "membershipPath",
            "migrationProtection",
            "path",
            "requireEmptyBeforeLaunch",
            "requireEmptyOnExit",
            "requiredControllers",
        },
        label="cgroup policy",
    )
    _const(cgroup["fdRole"], "cgroup", label="cgroup FD role")
    _const(
        cgroup["ancestorProtection"],
        "root-owned-nondelegated-no-acl-v1",
        label="cgroup ancestor protection",
    )
    _const(
        cgroup["migrationProtection"],
        "nonroot-no-cgroup-fds-no-writable-cgroupfs-v1",
        label="cgroup migration protection",
    )
    cgroup_path = _absolute_path(
        cgroup["path"],
        label="cgroup path",
        prefix="/sys/fs/cgroup/",
    )
    cgroup_membership_path = _membership_path(
        cgroup["membershipPath"],
        label="cgroup membership path",
    )
    cgroup_identity_raw = _exact_object(
        cgroup["identity"],
        {
            "device",
            "filesystemMagic",
            "gid",
            "inode",
            "mode",
            "mountId",
            "uid",
        },
        label="cgroup identity",
    )
    cgroup_identity = {
        "device": _integer(
            cgroup_identity_raw["device"],
            label="cgroup device",
            minimum=0,
            maximum=MAX_U64,
        ),
        "filesystemMagic": _integer(
            cgroup_identity_raw["filesystemMagic"],
            label="cgroup filesystem magic",
            minimum=0,
            maximum=MAX_U64,
        ),
        "gid": _integer(
            cgroup_identity_raw["gid"],
            label="cgroup gid",
            minimum=0,
            maximum=MAX_U64,
        ),
        "inode": _integer(
            cgroup_identity_raw["inode"],
            label="cgroup inode",
            minimum=1,
            maximum=MAX_U64,
        ),
        "mode": _integer(
            cgroup_identity_raw["mode"],
            label="cgroup mode",
            minimum=0,
            maximum=0o7777,
        ),
        "mountId": _integer(
            cgroup_identity_raw["mountId"],
            label="cgroup mount ID",
            minimum=1,
            maximum=MAX_U64,
        ),
        "uid": _integer(
            cgroup_identity_raw["uid"],
            label="cgroup uid",
            minimum=0,
            maximum=MAX_U64,
        ),
    }
    if (
        cgroup_identity["filesystemMagic"] != CGROUP2_SUPER_MAGIC
        or cgroup_identity["uid"] != 0
        or cgroup_identity["gid"] != 0
        or cgroup_identity["mode"] & 0o022
    ):
        raise LauncherError("cgroup identity is not a protected cgroup-v2 leaf")
    _const(
        cgroup["requiredControllers"],
        ["cpu", "io", "memory", "pids"],
        label="required cgroup controllers",
    )
    _const(cgroup["disposable"], True, label="disposable cgroup policy")
    _const(
        cgroup["killMode"],
        "pid-namespace-init-plus-cgroup.kill",
        label="cgroup kill policy",
    )
    _const(
        cgroup["requireEmptyBeforeLaunch"],
        True,
        label="pre-launch cgroup emptiness",
    )
    _const(
        cgroup["requireEmptyOnExit"],
        True,
        label="post-launch cgroup emptiness",
    )
    cgroup_limits = _validate_cgroup_limits(cgroup["limits"])

    process = _exact_object(
        top["process"],
        {
            "launcherIsSessionLeader",
            "namespaceInitIsProducer",
            "absoluteCommandDeadline",
            "ownerLivenessFdRole",
            "ownerLivenessTransport",
            "parentDeathSignal",
            "parentDeathSignalScope",
            "producerIsProcessGroupLeader",
            "producerStartsNewSession",
            "reapEntireTreeBeforeExit",
        },
        label="process policy",
    )
    for field in (
        "launcherIsSessionLeader",
        "namespaceInitIsProducer",
        "absoluteCommandDeadline",
        "producerIsProcessGroupLeader",
        "producerStartsNewSession",
        "reapEntireTreeBeforeExit",
    ):
        _const(process[field], True, label=f"process {field}")
    _const(
        process["parentDeathSignal"],
        "SIGKILL",
        label="producer parent-death signal",
    )
    _const(
        process["parentDeathSignalScope"],
        "direct-producer-child-only",
        label="producer parent-death signal scope",
    )
    _const(
        process["ownerLivenessFdRole"],
        "ownerLiveness",
        label="owner-liveness FD role",
    )
    _const(
        process["ownerLivenessTransport"],
        "connected-unix-seqpacket-eof",
        label="owner-liveness transport",
    )

    network = _exact_object(
        top["network"],
        {
            "allowedAddressFamilies",
            "denyNewNetworkSockets",
            "loopback",
            "mode",
        },
        label="network policy",
    )
    _const(network["mode"], "none", label="network mode")
    _const(network["loopback"], "down", label="loopback state")
    _const(
        network["allowedAddressFamilies"],
        ["AF_UNIX"],
        label="network address-family policy",
    )
    _const(
        network["denyNewNetworkSockets"],
        True,
        label="socket creation policy",
    )

    executable = _exact_object(
        top["executable"],
        {
            "architecture",
            "command",
            "executionSource",
            "executableSha256",
            "format",
            "postExecEnforcement",
            "requireSealed",
            "sourceFdRole",
            "static",
        },
        label="producer executable policy",
    )
    _const(
        executable["sourceFdRole"],
        "producerExecutable",
        label="producer executable FD role",
    )
    _const(executable["format"], "elf", label="producer executable format")
    _const(executable["static"], True, label="producer static-link policy")
    _const(
        executable["requireSealed"],
        True,
        label="producer executable seals",
    )
    _const(
        executable["executionSource"],
        "sealed-memfd",
        label="producer execution source",
    )
    _const(
        executable["architecture"],
        architecture,
        label="producer architecture",
    )
    executable_sha256 = _digest(
        executable["executableSha256"],
        label="producer executable digest",
    )
    producer_command = _validate_producer_command(executable["command"])
    post_exec = _exact_object(
        executable["postExecEnforcement"],
        {
            "entryStubSha256",
            "entryStubMeasured",
            "mechanism",
            "requiredBeforeApplicationCode",
            "runtimeProfileSha256",
        },
        label="producer post-exec enforcement",
    )
    _const(
        post_exec["mechanism"],
        "measured-static-entry-stub-additive-seccomp",
        label="producer post-exec mechanism",
    )
    _const(
        post_exec["entryStubMeasured"],
        True,
        label="producer entry-stub measurement",
    )
    _digest(
        post_exec["entryStubSha256"],
        label="producer entry-stub digest",
    )
    _const(
        post_exec["requiredBeforeApplicationCode"],
        True,
        label="producer post-exec ordering",
    )
    _const(
        post_exec["runtimeProfileSha256"],
        runtime_seccomp_sha256,
        label="producer runtime profile binding",
    )

    fd_policy = _exact_object(
        top["fdPolicy"],
        {
            "closeAllOthers",
            "immutableConfig",
            "namedProducerFds",
            "stderr",
            "stdin",
            "stdout",
        },
        label="producer FD policy",
    )
    stdin_policy = _exact_object(
        fd_policy["stdin"],
        {
            "access",
            "maxBytes",
            "requireSealed",
            "source",
            "targetFd",
        },
        label="producer stdin policy",
    )
    _const(stdin_policy["source"], "launcher-stdin", label="stdin source")
    _const(stdin_policy["targetFd"], 0, label="stdin target")
    _const(stdin_policy["access"], "read-only", label="stdin access")
    input_max_bytes = _integer(
        stdin_policy["maxBytes"],
        label="stdin byte limit",
        minimum=1,
        maximum=256 * 1024,
    )
    _const(stdin_policy["requireSealed"], True, label="stdin seals")
    stdout_policy = _exact_object(
        fd_policy["stdout"],
        {"access", "source", "targetFd"},
        label="producer stdout policy",
    )
    _const(stdout_policy["source"], "launcher-stdout", label="stdout source")
    _const(stdout_policy["targetFd"], 1, label="stdout target")
    _const(stdout_policy["access"], "write-only", label="stdout access")
    _const(fd_policy["stderr"], "closed", label="producer stderr policy")
    _const(
        fd_policy["closeAllOthers"],
        True,
        label="producer inherited FD policy",
    )
    config = _exact_object(
        fd_policy["immutableConfig"],
        {
            "access",
            "binding",
            "maxBytes",
            "requireSealed",
            "sourceFdRole",
            "targetFd",
        },
        label="immutable configuration FD policy",
    )
    _const(
        config["sourceFdRole"],
        "immutableConfig",
        label="immutable configuration FD role",
    )
    _const(config["access"], "read-only", label="configuration FD access")
    _const(config["requireSealed"], True, label="configuration FD seals")
    config_target_fd = _integer(
        config["targetFd"],
        label="configuration target FD",
        minimum=3,
        maximum=63,
    )
    config_max_bytes = _integer(
        config["maxBytes"],
        label="immutable configuration byte limit",
        minimum=1,
        maximum=MAX_CONFIG_BYTES,
    )
    config_binding = _validate_config_binding(config["binding"])
    named_fd_rules = _validate_named_fd_rules(fd_policy["namedProducerFds"])
    executable_argv = _reconstruct_producer_argv(
        producer_command,
        config_target_fd=config_target_fd,
        named_fd_rules=named_fd_rules,
    )
    executable_environment = {
        "CATCHPLATE_PUBLIC_ATTESTATION_CONFIG_FD": str(config_target_fd),
    }
    target_fds = {0, 1, config_target_fd}
    for rule in named_fd_rules:
        if rule.target_fd in target_fds:
            raise LauncherError("producer target FDs are not unique")
        target_fds.add(rule.target_fd)

    monitoring = _exact_object(
        top["monitoring"],
        {
            "commandDeadlineMilliseconds",
            "killAndReapTimeoutMilliseconds",
            "limitMutationWatch",
            "membershipPollMilliseconds",
            "startupTimeoutMilliseconds",
        },
        label="sandbox monitoring policy",
    )
    _const(
        monitoring["limitMutationWatch"],
        "inotify-fail-on-write-attrib-delete-move",
        label="cgroup limit mutation watch",
    )
    command_deadline_milliseconds = _integer(
        monitoring["commandDeadlineMilliseconds"],
        label="absolute command deadline",
        minimum=100,
        maximum=30_000,
    )
    if command_deadline_milliseconds != producer_command["ioTimeoutMilliseconds"]:
        raise LauncherError(
            "absolute command deadline differs from the producer command bound"
        )
    startup_timeout = _integer(
        monitoring["startupTimeoutMilliseconds"],
        label="sandbox startup timeout",
        minimum=100,
        maximum=10_000,
    )
    poll_milliseconds = _integer(
        monitoring["membershipPollMilliseconds"],
        label="sandbox membership poll interval",
        minimum=1,
        maximum=100,
    )
    cleanup_timeout = _integer(
        monitoring["killAndReapTimeoutMilliseconds"],
        label="sandbox cleanup timeout",
        minimum=100,
        maximum=10_000,
    )
    return ValidatedDescriptor(
        document=top,
        execution_mode=execution_mode,
        uid=uid,
        gid=gid,
        architecture=architecture,
        root_path=root_path,
        root_identity=root_identity,
        root_max_bytes=root_max_bytes,
        seccomp_sha256=seccomp_sha256,
        seccomp_instruction_count=seccomp_instruction_count,
        seccomp_profile_id=bootstrap_profile["profileId"],
        runtime_seccomp_sha256=runtime_seccomp_sha256,
        cgroup_path=cgroup_path,
        cgroup_membership_path=cgroup_membership_path,
        cgroup_identity=cgroup_identity,
        cgroup_limits=cgroup_limits,
        executable_sha256=executable_sha256,
        executable_argv=executable_argv,
        executable_environment=executable_environment,
        producer_command=producer_command,
        command_timeout_seconds=(
            producer_command["ioTimeoutMilliseconds"] / 1000.0
        ),
        input_max_bytes=input_max_bytes,
        config_target_fd=config_target_fd,
        config_max_bytes=config_max_bytes,
        config_binding=config_binding,
        named_fd_rules=named_fd_rules,
        startup_timeout_seconds=startup_timeout / 1000.0,
        poll_seconds=poll_milliseconds / 1000.0,
        cleanup_timeout_seconds=cleanup_timeout / 1000.0,
    )


def _validate_cgroup_limits(value: Any) -> dict[str, Any]:
    limits = _exact_object(
        value,
        {
            "cgroupMaxDepth",
            "cgroupMaxDescendants",
            "cpuMaxPeriodMicros",
            "cpuMaxQuotaMicros",
            "cpuWeight",
            "ioMax",
            "memoryHighBytes",
            "memoryMaxBytes",
            "memoryOomGroup",
            "memorySwapMaxBytes",
            "pidsMax",
        },
        label="cgroup limits",
    )
    result: dict[str, Any] = {
        "memoryMaxBytes": _integer(
            limits["memoryMaxBytes"],
            label="memory.max",
            minimum=16 * 1024 * 1024,
            maximum=1024 * 1024 * 1024 * 1024,
        ),
        "memoryHighBytes": _integer(
            limits["memoryHighBytes"],
            label="memory.high",
            minimum=16 * 1024 * 1024,
            maximum=1024 * 1024 * 1024 * 1024,
        ),
        "memorySwapMaxBytes": _integer(
            limits["memorySwapMaxBytes"],
            label="memory.swap.max",
            minimum=0,
            maximum=0,
        ),
        "cpuMaxQuotaMicros": _integer(
            limits["cpuMaxQuotaMicros"],
            label="cpu.max quota",
            minimum=1000,
            maximum=10_000_000,
        ),
        "cpuMaxPeriodMicros": _integer(
            limits["cpuMaxPeriodMicros"],
            label="cpu.max period",
            minimum=1000,
            maximum=1_000_000,
        ),
        "cpuWeight": _integer(
            limits["cpuWeight"],
            label="cpu.weight",
            minimum=1,
            maximum=10_000,
        ),
        "pidsMax": _integer(
            limits["pidsMax"],
            label="pids.max",
            minimum=1,
            maximum=4096,
        ),
    }
    if result["memoryHighBytes"] > result["memoryMaxBytes"]:
        raise LauncherError("memory.high exceeds memory.max")
    _const(limits["memoryOomGroup"], True, label="memory OOM group policy")
    _const(limits["cgroupMaxDepth"], 0, label="cgroup maximum depth")
    _const(
        limits["cgroupMaxDescendants"],
        0,
        label="cgroup maximum descendants",
    )
    result["memoryOomGroup"] = True
    result["cgroupMaxDepth"] = 0
    result["cgroupMaxDescendants"] = 0
    io_value = limits["ioMax"]
    if not isinstance(io_value, list) or not 1 <= len(io_value) <= 64:
        raise LauncherError("io.max rules exceed their closed bound")
    io_rules: list[dict[str, int]] = []
    devices: set[tuple[int, int]] = set()
    for index, raw_rule in enumerate(io_value):
        rule = _exact_object(
            raw_rule,
            {"major", "minor", "rbps", "riops", "wbps", "wiops"},
            label=f"io.max rule {index}",
        )
        normalized = {
            "major": _integer(
                rule["major"],
                label=f"io.max rule {index} major",
                minimum=0,
                maximum=(1 << 20) - 1,
            ),
            "minor": _integer(
                rule["minor"],
                label=f"io.max rule {index} minor",
                minimum=0,
                maximum=(1 << 20) - 1,
            ),
            "rbps": _integer(
                rule["rbps"],
                label=f"io.max rule {index} rbps",
                minimum=1,
                maximum=MAX_U64,
            ),
            "wbps": _integer(
                rule["wbps"],
                label=f"io.max rule {index} wbps",
                minimum=1,
                maximum=MAX_U64,
            ),
            "riops": _integer(
                rule["riops"],
                label=f"io.max rule {index} riops",
                minimum=1,
                maximum=MAX_U64,
            ),
            "wiops": _integer(
                rule["wiops"],
                label=f"io.max rule {index} wiops",
                minimum=1,
                maximum=MAX_U64,
            ),
        }
        device = (normalized["major"], normalized["minor"])
        if device in devices:
            raise LauncherError("io.max devices are not unique")
        devices.add(device)
        io_rules.append(normalized)
    if [
        (rule["major"], rule["minor"]) for rule in io_rules
    ] != sorted(devices):
        raise LauncherError("io.max rules are not in canonical device order")
    result["ioMax"] = io_rules
    return result


def _validate_config_binding(value: Any) -> dict[str, str]:
    binding = _exact_object(
        value,
        {
            "configApiVersion",
            "releaseIdentityConfigurationField",
            "releaseIdentityField",
            "releaseIdentityPublicAttestationField",
            "releaseIdentitySandboxDescriptorSha256Field",
            "sandboxDescriptorSha256Field",
        },
        label="immutable configuration self-binding",
    )
    _const(
        binding["configApiVersion"],
        CONFIG_VERSION,
        label="immutable configuration API version binding",
    )
    _const(
        binding["sandboxDescriptorSha256Field"],
        "sandboxDescriptorSha256",
        label="sandbox descriptor digest field binding",
    )
    for field, expected in (
        ("releaseIdentityField", "releaseIdentity"),
        ("releaseIdentityConfigurationField", "configuration"),
        ("releaseIdentityPublicAttestationField", "publicAttestation"),
        (
            "releaseIdentitySandboxDescriptorSha256Field",
            "sandboxDescriptorSha256",
        ),
    ):
        _const(
            binding[field],
            expected,
            label=f"immutable configuration {field}",
        )
    return binding


def _validate_producer_command(value: Any) -> dict[str, Any]:
    command = _exact_object(
        value,
        {
            "apiVersion",
            "expectedTrustRootsSha256",
            "fdRoles",
            "ioTimeoutMilliseconds",
            "operation",
        },
        label="producer command",
    )
    _const(
        command["apiVersion"],
        PRODUCER_COMMAND_VERSION,
        label="producer command API version",
    )
    _const(
        command["operation"],
        "produce-bundle",
        label="producer command operation",
    )
    roles = _exact_object(
        command["fdRoles"],
        set(PRODUCER_FD_ROLE_FIELDS),
        label="producer command FD roles",
    )
    for field in PRODUCER_FD_ROLE_FIELDS:
        _const(
            roles[field],
            field,
            label=f"producer command {field} role",
        )
    _digest(
        command["expectedTrustRootsSha256"],
        label="producer command trust-root digest",
    )
    _integer(
        command["ioTimeoutMilliseconds"],
        label="producer command I/O timeout",
        minimum=100,
        maximum=30_000,
    )
    return command


def _validate_named_fd_rules(value: Any) -> tuple[NamedFdRule, ...]:
    if not isinstance(value, list) or len(value) != len(PRODUCER_FD_ROLE_FIELDS):
        raise LauncherError(
            "named producer FD list is not the closed produce-bundle set"
        )
    rules: list[NamedFdRule] = []
    roles: set[str] = set()
    targets: set[int] = set()
    for index, raw_rule in enumerate(value):
        if not isinstance(raw_rule, dict):
            raise LauncherError(f"named producer FD {index} is not an object")
        kind = raw_rule.get("kind")
        if kind == "sealed-regular-file":
            fields = {
                "access",
                "expectedSha256",
                "kind",
                "maxBytes",
                "requireSealed",
                "role",
                "targetFd",
            }
        elif kind == "sealed-release-bound-file":
            fields = {
                "access",
                "kind",
                "maxBytes",
                "requireSealed",
                "role",
                "targetFd",
            }
        elif kind == "sealed-measurement-copy":
            fields = {
                "access",
                "kind",
                "maxBytes",
                "measurementOf",
                "requireSealed",
                "role",
                "targetFd",
            }
        elif kind == "sealed-ephemeral-secret":
            fields = {
                "access",
                "exactBytes",
                "kind",
                "requireSealed",
                "role",
                "targetFd",
            }
        elif kind == "connected-unix-service":
            fields = {
                "access",
                "direction",
                "endpointCustodyClaim",
                "kind",
                "messageCredentials",
                "peerCgroupPath",
                "peerCgroupAncestorClosureSha256",
                "peerCgroupMigrationEnforcement",
                "peerExecutableMapClosureSha256",
                "peerExecutableSha256",
                "peerGid",
                "peerPostExecEnforcementProfileSha256",
                "peerRequiredSeccompFilterCount",
                "peerStaticElf",
                "peerUid",
                "protocol",
                "protocolChallenge",
                "rejectAncillaryFds",
                "rejectUnknownControlMessages",
                "role",
                "socketType",
                "targetFd",
            }
        else:
            raise LauncherError(f"named producer FD {index} kind is invalid")
        rule = _exact_object(
            raw_rule,
            fields,
            label=f"named producer FD {index}",
        )
        role = _identifier(rule["role"], label=f"named FD {index} role")
        if role in {
            "cgroup",
            "immutableConfig",
            "producerExecutable",
            "sandboxDescriptor",
            "sandboxRoot",
            "seccompProfile",
        }:
            raise LauncherError("named producer FD uses a reserved role")
        target_fd = _integer(
            rule["targetFd"],
            label=f"named FD {index} target",
            minimum=3,
            maximum=63,
        )
        access = _text(
            rule["access"],
            label=f"named FD {index} access",
            minimum=9,
            maximum=10,
        )
        if kind == "sealed-regular-file":
            _const(access, "read-only", label=f"named FD {index} access")
            _const(
                rule["requireSealed"],
                True,
                label=f"named FD {index} seals",
            )
            maximum = (
                MAX_NAMED_FILE_BYTES
                if role == "sandboxLauncher"
                else MAX_NAMED_DOCUMENT_BYTES
            )
            _const(
                rule["maxBytes"],
                maximum,
                label=f"named FD {index} byte limit",
            )
            _digest(
                rule["expectedSha256"],
                label=f"named FD {index} digest",
            )
        elif kind == "sealed-release-bound-file":
            _const(access, "read-only", label=f"named FD {index} access")
            _const(
                rule["requireSealed"],
                True,
                label=f"named FD {index} seals",
            )
            _integer(
                rule["maxBytes"],
                label=f"named FD {index} byte limit",
                minimum=1,
                maximum=MAX_NAMED_DOCUMENT_BYTES,
            )
        elif kind == "sealed-measurement-copy":
            _const(access, "read-only", label=f"named FD {index} access")
            _const(
                rule["requireSealed"],
                True,
                label=f"named FD {index} seals",
            )
            measurement_of = _text(
                rule["measurementOf"],
                label=f"named FD {index} measurement source",
                minimum=17,
                maximum=18,
            )
            if measurement_of not in {
                "producerExecutable",
                "sandboxDescriptor",
            }:
                raise LauncherError(
                    f"named FD {index} measurement source is invalid"
                )
            expected_maximum = (
                256 * 1024 * 1024
                if measurement_of == "producerExecutable"
                else MAX_DESCRIPTOR_BYTES
            )
            _const(
                rule["maxBytes"],
                expected_maximum,
                label=f"named FD {index} measurement bound",
            )
        elif kind == "sealed-ephemeral-secret":
            _const(access, "read-only", label=f"named FD {index} access")
            _const(
                rule["requireSealed"],
                True,
                label=f"named FD {index} seals",
            )
            _const(
                rule["exactBytes"],
                32,
                label=f"named FD {index} secret size",
            )
        else:
            _const(access, "read-write", label=f"named FD {index} access")
            _integer(
                rule["peerUid"],
                label=f"named FD {index} peer uid",
                minimum=1,
                maximum=(1 << 32) - 1,
            )
            _integer(
                rule["peerGid"],
                label=f"named FD {index} peer gid",
                minimum=1,
                maximum=(1 << 32) - 1,
            )
            _digest(
                rule["peerExecutableSha256"],
                label=f"named FD {index} peer executable digest",
            )
            _membership_path(
                rule["peerCgroupPath"],
                label=f"named FD {index} peer cgroup path",
            )
            protocol = _text(
                rule["protocol"],
                label=f"named FD {index} protocol",
                minimum=8,
                maximum=128,
            )
            if (
                not protocol.isascii()
                or any(
                    character not in (
                        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                        "abcdefghijklmnopqrstuvwxyz"
                        "0123456789._:/+-"
                    )
                    for character in protocol
                )
            ):
                raise LauncherError(
                    f"named FD {index} protocol is not canonical"
                )
            _const(
                rule["socketType"],
                "SOCK_SEQPACKET",
                label=f"named FD {index} socket type",
            )
            _const(
                rule["messageCredentials"],
                "SCM_CREDENTIALS-every-frame",
                label=f"named FD {index} message credentials",
            )
            _const(
                rule["rejectAncillaryFds"],
                True,
                label=f"named FD {index} ancillary FD policy",
            )
            _const(
                rule["rejectUnknownControlMessages"],
                True,
                label=f"named FD {index} control-message policy",
            )
            _const(
                rule["endpointCustodyClaim"],
                "sender-authenticated-not-exclusive",
                label=f"named FD {index} endpoint custody claim",
            )
            _const(
                rule["peerStaticElf"],
                True,
                label=f"named FD {index} static peer policy",
            )
            _digest(
                rule["peerExecutableMapClosureSha256"],
                label=f"named FD {index} executable-map closure",
            )
            _digest(
                rule["peerPostExecEnforcementProfileSha256"],
                label=f"named FD {index} post-exec profile",
            )
            _const(
                rule["peerRequiredSeccompFilterCount"],
                2,
                label=f"named FD {index} seccomp filter count",
            )
            _digest(
                rule["peerCgroupAncestorClosureSha256"],
                label=f"named FD {index} cgroup ancestor closure",
            )
            _const(
                rule["peerCgroupMigrationEnforcement"],
                "nonroot-empty-caps-private-cgroupns-no-writable-cgroupfs-no-cgroup-fds-v1",
                label=f"named FD {index} cgroup migration enforcement",
            )
            if rule["direction"] not in {
                "producer-to-service",
                "service-to-producer",
            }:
                raise LauncherError(
                    f"named FD {index} direction is invalid"
                )
            challenge = _exact_object(
                rule["protocolChallenge"],
                {"apiVersion", "challengeBytes", "required"},
                label=f"named FD {index} protocol challenge",
            )
            _const(
                challenge["apiVersion"],
                SERVICE_CHALLENGE_VERSION,
                label=f"named FD {index} challenge API version",
            )
            _const(
                challenge["challengeBytes"],
                32,
                label=f"named FD {index} challenge size",
            )
            _const(
                challenge["required"],
                True,
                label=f"named FD {index} challenge requirement",
            )
            _integer(
                rule["peerGid"],
                label=f"named FD {index} peer gid",
                minimum=1,
                maximum=(1 << 32) - 1,
            )
        if role in roles or target_fd in targets:
            raise LauncherError("named producer FD roles and targets are unique")
        roles.add(role)
        targets.add(target_fd)
        rules.append(
            NamedFdRule(
                role=role,
                target_fd=target_fd,
                kind=kind,
                access=access,
                document=rule,
            )
        )
    if [rule.target_fd for rule in rules] != sorted(targets):
        raise LauncherError("named producer FDs are not in target-FD order")
    return tuple(rules)


def _reconstruct_producer_argv(
    command: dict[str, Any],
    *,
    config_target_fd: int,
    named_fd_rules: tuple[NamedFdRule, ...],
) -> tuple[str, ...]:
    role_names = command["fdRoles"]
    by_role = {rule.role: rule for rule in named_fd_rules}
    if set(by_role) != {role_names[field] for field in PRODUCER_FD_ROLE_FIELDS}:
        raise LauncherError(
            "named producer FDs differ from the structured command"
        )

    expected_kinds = {
        "producerDescriptor": "sealed-release-bound-file",
        "producerEphemeralSeed": "sealed-ephemeral-secret",
        "producerExecutableMeasurement": "sealed-measurement-copy",
        "producerRequestSchema": "sealed-regular-file",
        "sandboxDescriptorMeasurement": "sealed-measurement-copy",
        "sandboxLauncher": "sealed-regular-file",
        "stableReleaseStatement": "sealed-release-bound-file",
        "trustRoots": "sealed-regular-file",
    }
    for field, expected_kind in expected_kinds.items():
        if by_role[role_names[field]].kind != expected_kind:
            raise LauncherError(
                f"producer command role {field} has the wrong FD kind"
            )
    if (
        by_role[role_names["trustRoots"]].document["expectedSha256"]
        != command["expectedTrustRootsSha256"]
    ):
        raise LauncherError(
            "producer command trust-root digest crossed its FD pin"
        )
    if (
        by_role[role_names["producerExecutableMeasurement"]].document[
            "measurementOf"
        ]
        != "producerExecutable"
        or by_role[role_names["sandboxDescriptorMeasurement"]].document[
            "measurementOf"
        ]
        != "sandboxDescriptor"
    ):
        raise LauncherError("producer measurement roles cross their sources")

    service_contracts = {
        "nonceRequest": (
            "catchplate.attestationNonceService/v2",
            "producer-to-service",
        ),
        "nonceResponse": (
            "catchplate.attestationNonceService/v2",
            "service-to-producer",
        ),
        "witnessRequest": (
            "catchplate.attestationWitnessService/v2",
            "producer-to-service",
        ),
        "witnessResponse": (
            "catchplate.attestationWitnessService/v2",
            "service-to-producer",
        ),
    }
    for field, (protocol, direction) in service_contracts.items():
        rule = by_role[role_names[field]]
        if (
            rule.kind != "connected-unix-service"
            or rule.document["protocol"] != protocol
            or rule.document["direction"] != direction
        ):
            raise LauncherError(
                f"producer command role {field} has the wrong service contract"
            )
    for request_field, response_field in (
        ("nonceRequest", "nonceResponse"),
        ("witnessRequest", "witnessResponse"),
    ):
        request = by_role[role_names[request_field]].document
        response = by_role[role_names[response_field]].document
        comparable = (
            "peerCgroupPath",
            "peerExecutableSha256",
            "peerGid",
            "peerUid",
            "protocol",
            "protocolChallenge",
            "socketType",
        )
        if any(request[field] != response[field] for field in comparable):
            raise LauncherError(
                f"{request_field} and {response_field} do not identify one service"
            )

    target = {
        field: by_role[role_names[field]].target_fd
        for field in PRODUCER_FD_ROLE_FIELDS
    }
    return (
        "catchplate-public-attestation-producer",
        "produce-bundle",
        "--request-fd",
        "0",
        "--response-fd",
        "1",
        "--producer-descriptor-fd",
        str(target["producerDescriptor"]),
        "--producer-ephemeral-seed-fd",
        str(target["producerEphemeralSeed"]),
        "--producer-executable-fd",
        str(target["producerExecutableMeasurement"]),
        "--immutable-config-fd",
        str(config_target_fd),
        "--producer-request-schema-fd",
        str(target["producerRequestSchema"]),
        "--sandbox-descriptor-fd",
        str(target["sandboxDescriptorMeasurement"]),
        "--sandbox-launcher-fd",
        str(target["sandboxLauncher"]),
        "--trust-roots-fd",
        str(target["trustRoots"]),
        "--expected-trust-roots-sha256",
        command["expectedTrustRootsSha256"],
        "--io-timeout-ms",
        str(command["ioTimeoutMilliseconds"]),
        "--stable-statement-fd",
        str(target["stableReleaseStatement"]),
        "--nonce-request-fd",
        str(target["nonceRequest"]),
        "--nonce-response-fd",
        str(target["nonceResponse"]),
        "--witness-request-fd",
        str(target["witnessRequest"]),
        "--witness-response-fd",
        str(target["witnessResponse"]),
    )


def _sha256(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _parse_fd(value: str, *, label: str) -> int:
    if not isinstance(value, str) or not value.isascii() or not value.isdigit():
        raise LauncherError(f"{label} is not a decimal descriptor")
    descriptor = int(value, 10)
    if not 3 <= descriptor < MAX_SAFE_FD:
        raise LauncherError(f"{label} is outside its descriptor bounds")
    try:
        os.fstat(descriptor)
    except OSError as exc:
        raise LauncherError(f"{label} is not open") from exc
    return descriptor


def _parse_role_fd(value: str, *, label: str) -> tuple[str, int]:
    if value.count("=") != 1:
        raise LauncherError(f"{label} must be role=fd")
    raw_role, raw_fd = value.split("=", 1)
    role = _identifier(raw_role, label=f"{label} role")
    return role, _parse_fd(raw_fd, label=f"{label} descriptor")


def _fd_access_mode(descriptor: int) -> int:
    try:
        return fcntl.fcntl(descriptor, fcntl.F_GETFL) & os.O_ACCMODE
    except OSError as exc:
        raise LauncherError("descriptor access mode is unavailable") from exc


def _require_fd_access(
    descriptor: int,
    expected: str,
    *,
    label: str,
) -> None:
    mode = _fd_access_mode(descriptor)
    expected_mode = {
        "read-only": os.O_RDONLY,
        "write-only": os.O_WRONLY,
        "read-write": os.O_RDWR,
    }[expected]
    if mode != expected_mode:
        raise LauncherError(f"{label} access differs from its descriptor")


def _assert_unique_descriptors(descriptors: dict[str, int]) -> None:
    values = list(descriptors.values())
    if len(values) != len(set(values)):
        raise LauncherError("launcher input descriptors are not unique")


def _read_regular_fd(
    descriptor: int,
    *,
    label: str,
    maximum: int,
    require_seals: bool,
) -> bytes:
    before = os.fstat(descriptor)
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_size < 0
        or before.st_size > maximum
    ):
        raise LauncherError(f"{label} is not a bounded regular file")
    _require_fd_access(descriptor, "read-only", label=label)
    if require_seals:
        try:
            seals = fcntl.fcntl(descriptor, fcntl.F_GET_SEALS)
        except (AttributeError, OSError) as exc:
            raise LauncherError(f"{label} does not expose memfd seals") from exc
        if seals & REQUIRED_SEALS != REQUIRED_SEALS:
            raise LauncherError(f"{label} is not fully immutable")
        if before.st_nlink != 0:
            raise LauncherError(f"{label} is not an anonymous sealed file")
    chunks: list[bytes] = []
    offset = 0
    while offset < before.st_size:
        chunk = os.pread(
            descriptor,
            min(64 * 1024, before.st_size - offset),
            offset,
        )
        if not chunk:
            raise LauncherError(f"{label} ended before its measured size")
        chunks.append(chunk)
        offset += len(chunk)
    raw = b"".join(chunks)
    after = os.fstat(descriptor)
    if (
        len(raw) != before.st_size
        or (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_nlink,
            before.st_uid,
            before.st_gid,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        != (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_nlink,
            after.st_uid,
            after.st_gid,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
    ):
        raise LauncherError(f"{label} changed while it was measured")
    return raw


def _validate_sealed_exact_size_fd(
    descriptor: int,
    *,
    label: str,
    exact_bytes: int,
) -> None:
    before = os.fstat(descriptor)
    _require_fd_access(descriptor, "read-only", label=label)
    try:
        seals = fcntl.fcntl(descriptor, fcntl.F_GET_SEALS)
    except (AttributeError, OSError) as exc:
        raise LauncherError(f"{label} does not expose memfd seals") from exc
    after = os.fstat(descriptor)
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 0
        or before.st_size != exact_bytes
        or seals & REQUIRED_SEALS != REQUIRED_SEALS
        or (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_nlink,
            before.st_uid,
            before.st_gid,
            before.st_size,
        )
        != (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_nlink,
            after.st_uid,
            after.st_gid,
            after.st_size,
        )
    ):
        raise LauncherError(f"{label} is not the exact sealed secret")


def _validate_immutable_config_document(
    raw: bytes,
    *,
    policy: ValidatedDescriptor,
    sandbox_descriptor_raw: bytes,
) -> dict[str, Any]:
    document = _load_canonical_document(
        raw,
        label="immutable configuration",
        maximum=policy.config_max_bytes,
    )
    api_version_field = "apiVersion"
    sandbox_digest_field = policy.config_binding[
        "sandboxDescriptorSha256Field"
    ]
    if (
        document.get(api_version_field)
        != policy.config_binding["configApiVersion"]
        or sandbox_digest_field not in document
    ):
        raise LauncherError(
            "immutable configuration lacks its closed sandbox binding"
        )
    sandbox_digest = _digest(
        document[sandbox_digest_field],
        label="immutable configuration sandbox descriptor digest",
    )
    release_identity = document.get(
        policy.config_binding["releaseIdentityField"]
    )
    if not isinstance(release_identity, dict):
        raise LauncherError(
            "immutable configuration release identity binding is absent"
        )
    release_configuration = release_identity.get(
        policy.config_binding["releaseIdentityConfigurationField"]
    )
    if not isinstance(release_configuration, dict):
        raise LauncherError(
            "immutable configuration release identity has no configuration"
        )
    public_attestation = release_configuration.get(
        policy.config_binding["releaseIdentityPublicAttestationField"]
    )
    if not isinstance(public_attestation, dict):
        raise LauncherError(
            "immutable configuration release identity has no attestation pins"
        )
    release_sandbox_digest = _digest(
        public_attestation.get(
            policy.config_binding[
                "releaseIdentitySandboxDescriptorSha256Field"
            ]
        ),
        label="release identity sandbox descriptor digest",
    )
    expected_sandbox_digest = _sha256(sandbox_descriptor_raw)
    if (
        sandbox_digest != expected_sandbox_digest
        or release_sandbox_digest != expected_sandbox_digest
    ):
        raise LauncherError(
            "immutable configuration does not bind this sandbox descriptor"
        )
    return document


def _assert_stat_identity(
    metadata: os.stat_result,
    expected: dict[str, int],
    *,
    label: str,
    kind: str,
) -> None:
    kind_ok = {
        "directory": stat.S_ISDIR(metadata.st_mode),
        "regular-file": stat.S_ISREG(metadata.st_mode),
    }.get(kind, False)
    if (
        not kind_ok
        or metadata.st_dev != expected["device"]
        or metadata.st_ino != expected["inode"]
        or metadata.st_uid != expected["uid"]
        or metadata.st_gid != expected["gid"]
        or stat.S_IMODE(metadata.st_mode) != expected["mode"]
    ):
        raise LauncherError(f"{label} identity differs from its descriptor")


def _assert_fd_path(
    descriptor: int,
    expected_path: str,
    *,
    label: str,
) -> None:
    try:
        actual_path = os.readlink(f"/proc/self/fd/{descriptor}")
    except OSError as exc:
        raise LauncherError(f"{label} path is unavailable") from exc
    if actual_path != expected_path or actual_path.endswith(" (deleted)"):
        raise LauncherError(f"{label} path differs from its descriptor")


def _fd_mount_id(descriptor: int) -> int:
    try:
        raw = _read_path_bounded(
            f"/proc/self/fdinfo/{descriptor}",
            maximum=4096,
            label="descriptor mount identity",
        ).decode("ascii")
    except UnicodeError as exc:
        raise LauncherError("descriptor mount identity is malformed") from exc
    values: list[int] = []
    for line in raw.splitlines():
        if line.startswith("mnt_id:\t"):
            value = line.split("\t", 1)[1]
            if not value.isdigit():
                raise LauncherError("descriptor mount ID is malformed")
            values.append(int(value, 10))
    if len(values) != 1 or values[0] < 1:
        raise LauncherError("descriptor mount ID is unavailable")
    return values[0]


def _fstatfs_magic(descriptor: int) -> int:
    result = StatFs()
    if LIBC.fstatfs(descriptor, ctypes.byref(result)) != 0:
        error = ctypes.get_errno()
        raise LauncherError("descriptor filesystem identity is unavailable") from OSError(
            error,
            os.strerror(error),
        )
    return int(result.f_type) & MAX_U64


def _read_path_bounded(path: str, *, maximum: int, label: str) -> bytes:
    descriptor = os.open(
        path,
        os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        return _read_open_fd_bounded(
            descriptor,
            maximum=maximum,
            label=label,
        )
    finally:
        os.close(descriptor)


def _read_open_fd_bounded(
    descriptor: int,
    *,
    maximum: int,
    label: str,
) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = os.read(descriptor, min(64 * 1024, maximum + 1 - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        if total > maximum:
            raise LauncherError(f"{label} exceeds its byte limit")
    return b"".join(chunks)


def _openat(
    directory_descriptor: int,
    name: str,
    flags: int,
    *,
    label: str,
) -> int:
    if (
        not isinstance(name, str)
        or "/" in name
        or name in {"", ".", ".."}
        or "\x00" in name
    ):
        raise LauncherError(f"{label} has an unsafe relative name")
    try:
        return os.open(
            name,
            flags | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=directory_descriptor,
        )
    except OSError as exc:
        raise LauncherError(f"{label} is unavailable") from exc


def _read_cgroup_file(
    cgroup_descriptor: int,
    name: str,
    *,
    maximum: int = MAX_CONTROL_FILE_BYTES,
) -> str:
    descriptor = _openat(
        cgroup_descriptor,
        name,
        os.O_RDONLY,
        label=f"cgroup control {name}",
    )
    try:
        metadata = os.fstat(descriptor)
        if metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) & 0o022:
            raise LauncherError(f"cgroup control {name} is not protected")
        raw = _read_open_fd_bounded(
            descriptor,
            maximum=maximum,
            label=f"cgroup control {name}",
        )
    finally:
        os.close(descriptor)
    try:
        return raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise LauncherError(f"cgroup control {name} is not ASCII") from exc


def _write_cgroup_file(
    cgroup_descriptor: int,
    name: str,
    value: str,
) -> None:
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise LauncherError(f"cgroup control {name} value is not ASCII") from exc
    if not encoded or len(encoded) > MAX_CONTROL_FILE_BYTES:
        raise LauncherError(f"cgroup control {name} value is invalid")
    descriptor = _openat(
        cgroup_descriptor,
        name,
        os.O_WRONLY,
        label=f"writable cgroup control {name}",
    )
    try:
        metadata = os.fstat(descriptor)
        if metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) & 0o022:
            raise LauncherError(f"cgroup control {name} is not protected")
        written = os.write(descriptor, encoded)
        if written != len(encoded):
            raise LauncherError(f"cgroup control {name} accepted a short write")
    finally:
        os.close(descriptor)


def _parse_integer_lines(raw: str, *, label: str) -> set[int]:
    result: set[int] = set()
    for line in raw.splitlines():
        if not line or not line.isdigit():
            raise LauncherError(f"{label} contains a malformed process ID")
        value = int(line, 10)
        if value < 1 or value in result:
            raise LauncherError(f"{label} contains an invalid process ID")
        result.add(value)
    return result


def _cgroup_processes(cgroup_descriptor: int) -> set[int]:
    return _parse_integer_lines(
        _read_cgroup_file(cgroup_descriptor, "cgroup.procs"),
        label="cgroup.procs",
    )


def _cgroup_threads(cgroup_descriptor: int) -> set[int]:
    return _parse_integer_lines(
        _read_cgroup_file(cgroup_descriptor, "cgroup.threads"),
        label="cgroup.threads",
    )


def _cgroup_populated(cgroup_descriptor: int) -> bool:
    raw = _read_cgroup_file(cgroup_descriptor, "cgroup.events")
    fields: dict[str, str] = {}
    for line in raw.splitlines():
        parts = line.split(" ")
        if len(parts) != 2 or parts[0] in fields:
            raise LauncherError("cgroup.events is malformed")
        fields[parts[0]] = parts[1]
    if fields.get("populated") not in {"0", "1"}:
        raise LauncherError("cgroup.events has no closed populated state")
    return fields["populated"] == "1"


def _parse_io_max(raw: str) -> dict[tuple[int, int], dict[str, str]]:
    result: dict[tuple[int, int], dict[str, str]] = {}
    for line in raw.splitlines():
        fields = line.split()
        if len(fields) != 5 or fields[0].count(":") != 1:
            raise LauncherError("io.max is malformed")
        raw_major, raw_minor = fields[0].split(":", 1)
        if not raw_major.isdigit() or not raw_minor.isdigit():
            raise LauncherError("io.max device is malformed")
        device = (int(raw_major, 10), int(raw_minor, 10))
        controls: dict[str, str] = {}
        for field in fields[1:]:
            if field.count("=") != 1:
                raise LauncherError("io.max control is malformed")
            name, value = field.split("=", 1)
            if (
                name not in {"rbps", "wbps", "riops", "wiops"}
                or name in controls
                or (value != "max" and not value.isdigit())
            ):
                raise LauncherError("io.max control is invalid")
            controls[name] = value
        if set(controls) != {"rbps", "wbps", "riops", "wiops"}:
            raise LauncherError("io.max control set is incomplete")
        if device in result:
            raise LauncherError("io.max contains a duplicate device")
        result[device] = controls
    return result


def _expected_io_max(limits: dict[str, Any]) -> dict[tuple[int, int], dict[str, str]]:
    return {
        (rule["major"], rule["minor"]): {
            "rbps": str(rule["rbps"]),
            "wbps": str(rule["wbps"]),
            "riops": str(rule["riops"]),
            "wiops": str(rule["wiops"]),
        }
        for rule in limits["ioMax"]
    }


def _io_rule_line(device: tuple[int, int], values: dict[str, str]) -> str:
    return (
        f"{device[0]}:{device[1]} "
        f"rbps={values['rbps']} "
        f"wbps={values['wbps']} "
        f"riops={values['riops']} "
        f"wiops={values['wiops']}"
    )


def _configure_cgroup(
    descriptor: ValidatedDescriptor,
    cgroup_descriptor: int,
) -> None:
    _peer_cgroup_ancestor_closure_sha256(
        descriptor.cgroup_membership_path,
        label="producer",
    )
    metadata = os.fstat(cgroup_descriptor)
    _assert_stat_identity(
        metadata,
        {
            "device": descriptor.cgroup_identity["device"],
            "inode": descriptor.cgroup_identity["inode"],
            "uid": descriptor.cgroup_identity["uid"],
            "gid": descriptor.cgroup_identity["gid"],
            "mode": descriptor.cgroup_identity["mode"],
        },
        label="cgroup directory",
        kind="directory",
    )
    _assert_no_posix_acl(cgroup_descriptor, label="cgroup directory")
    _assert_fd_path(
        cgroup_descriptor,
        descriptor.cgroup_path,
        label="cgroup directory",
    )
    if (
        _fstatfs_magic(cgroup_descriptor)
        != descriptor.cgroup_identity["filesystemMagic"]
        or _fd_mount_id(cgroup_descriptor)
        != descriptor.cgroup_identity["mountId"]
    ):
        raise LauncherError("cgroup filesystem identity differs from its pin")
    if _read_cgroup_file(cgroup_descriptor, "cgroup.type").strip() != "domain":
        raise LauncherError("sandbox cgroup is not a domain cgroup")
    controllers = _read_cgroup_file(
        cgroup_descriptor,
        "cgroup.controllers",
    ).split()
    if len(controllers) != len(set(controllers)) or not {
        "cpu",
        "io",
        "memory",
        "pids",
    }.issubset(controllers):
        raise LauncherError("sandbox cgroup controllers are incomplete")
    if _read_cgroup_file(
        cgroup_descriptor,
        "cgroup.subtree_control",
    ).strip():
        raise LauncherError("sandbox cgroup delegates child controllers")
    try:
        entries = list(os.scandir(cgroup_descriptor))
    except OSError as exc:
        raise LauncherError("sandbox cgroup children are unavailable") from exc
    if any(entry.is_dir(follow_symlinks=False) for entry in entries):
        raise LauncherError("sandbox cgroup is not a leaf")
    if (
        _cgroup_processes(cgroup_descriptor)
        or _cgroup_threads(cgroup_descriptor)
        or _cgroup_populated(cgroup_descriptor)
    ):
        raise LauncherError("sandbox cgroup is populated before launch")
    if _read_cgroup_file(cgroup_descriptor, "cgroup.freeze").strip() != "0":
        raise LauncherError("sandbox cgroup is unexpectedly frozen")

    limits = descriptor.cgroup_limits
    expected_io = _expected_io_max(limits)
    existing_io = _parse_io_max(_read_cgroup_file(cgroup_descriptor, "io.max"))
    for device in sorted(set(existing_io) - set(expected_io)):
        _write_cgroup_file(
            cgroup_descriptor,
            "io.max",
            _io_rule_line(
                device,
                {
                    "rbps": "max",
                    "wbps": "max",
                    "riops": "max",
                    "wiops": "max",
                },
            ),
        )
    for device in sorted(expected_io):
        _write_cgroup_file(
            cgroup_descriptor,
            "io.max",
            _io_rule_line(device, expected_io[device]),
        )
    expected_controls = {
        "cgroup.max.depth": str(limits["cgroupMaxDepth"]),
        "cgroup.max.descendants": str(limits["cgroupMaxDescendants"]),
        "cpu.max": (
            f"{limits['cpuMaxQuotaMicros']} "
            f"{limits['cpuMaxPeriodMicros']}"
        ),
        "cpu.weight": str(limits["cpuWeight"]),
        "memory.high": str(limits["memoryHighBytes"]),
        "memory.max": str(limits["memoryMaxBytes"]),
        "memory.oom.group": "1",
        "memory.swap.max": str(limits["memorySwapMaxBytes"]),
        "pids.max": str(limits["pidsMax"]),
    }
    for name in sorted(expected_controls):
        _write_cgroup_file(
            cgroup_descriptor,
            name,
            expected_controls[name],
        )
    _assert_cgroup_limits(descriptor, cgroup_descriptor)


def _assert_cgroup_limits(
    descriptor: ValidatedDescriptor,
    cgroup_descriptor: int,
) -> None:
    _assert_fd_path(
        cgroup_descriptor,
        descriptor.cgroup_path,
        label="cgroup directory",
    )
    limits = descriptor.cgroup_limits
    expected_controls = {
        "cgroup.max.depth": str(limits["cgroupMaxDepth"]),
        "cgroup.max.descendants": str(limits["cgroupMaxDescendants"]),
        "cpu.max": (
            f"{limits['cpuMaxQuotaMicros']} "
            f"{limits['cpuMaxPeriodMicros']}"
        ),
        "cpu.weight": str(limits["cpuWeight"]),
        "memory.high": str(limits["memoryHighBytes"]),
        "memory.max": str(limits["memoryMaxBytes"]),
        "memory.oom.group": "1",
        "memory.swap.max": str(limits["memorySwapMaxBytes"]),
        "pids.max": str(limits["pidsMax"]),
    }
    for name, expected in expected_controls.items():
        if _read_cgroup_file(cgroup_descriptor, name).strip() != expected:
            raise LauncherError(f"cgroup limit {name} drifted")
    if _parse_io_max(
        _read_cgroup_file(cgroup_descriptor, "io.max")
    ) != _expected_io_max(limits):
        raise LauncherError("cgroup limit io.max drifted")
    metadata = os.fstat(cgroup_descriptor)
    if (
        metadata.st_dev != descriptor.cgroup_identity["device"]
        or metadata.st_ino != descriptor.cgroup_identity["inode"]
        or metadata.st_uid != descriptor.cgroup_identity["uid"]
        or metadata.st_gid != descriptor.cgroup_identity["gid"]
        or stat.S_IMODE(metadata.st_mode)
        != descriptor.cgroup_identity["mode"]
        or _fstatfs_magic(cgroup_descriptor)
        != descriptor.cgroup_identity["filesystemMagic"]
        or _fd_mount_id(cgroup_descriptor)
        != descriptor.cgroup_identity["mountId"]
    ):
        raise LauncherError("cgroup identity drifted")


def _kill_cgroup(cgroup_descriptor: int) -> None:
    _write_cgroup_file(cgroup_descriptor, "cgroup.kill", "1")


def _assert_cgroup_kill_available(cgroup_descriptor: int) -> None:
    kill_descriptor = _openat(
        cgroup_descriptor,
        "cgroup.kill",
        os.O_WRONLY,
        label="service cgroup kill control",
    )
    try:
        metadata = os.fstat(kill_descriptor)
        if metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) & 0o022:
            raise LauncherError("service cgroup kill control is not protected")
    finally:
        os.close(kill_descriptor)


def _validate_static_elf(
    raw: bytes,
    *,
    architecture: str,
) -> None:
    if len(raw) < 64 or raw[:4] != b"\x7fELF":
        raise LauncherError("producer executable is not ELF")
    if raw[4] != 2 or raw[5] != 1 or raw[6] != 1:
        raise LauncherError("producer executable is not 64-bit little-endian ELF")
    (
        elf_type,
        elf_machine,
        elf_version,
        entry_point,
        program_offset,
        section_offset,
        _flags,
        elf_header_size,
        program_entry_size,
        program_count,
        section_entry_size,
        section_count,
        section_names,
    ) = struct.unpack_from("<HHIQQQIHHHHHH", raw, 16)
    if (
        elf_type != 2
        or elf_machine != ARCHITECTURES[architecture]["elf_machine"]
        or elf_version != 1
        or entry_point == 0
        or elf_header_size != 64
        or program_entry_size != 56
        or not 1 <= program_count <= 4096
        or program_offset < 64
        or program_offset + program_entry_size * program_count > len(raw)
    ):
        raise LauncherError("producer ELF header is invalid")
    load_ranges: list[tuple[int, int, int, int]] = []
    has_non_executable_stack = False
    entry_is_executable = False
    total_load_memory = 0
    for index in range(program_count):
        offset = program_offset + index * program_entry_size
        (
            program_type,
            segment_flags,
            file_offset,
            virtual_address,
            _physical_address,
            file_size,
            memory_size,
            alignment,
        ) = struct.unpack_from("<IIQQQQQQ", raw, offset)
        if (
            segment_flags & ~0x7
            or memory_size > 1024 * 1024 * 1024
            or file_offset > len(raw)
            or file_size > len(raw) - file_offset
            or memory_size < file_size
            or virtual_address > MAX_U64 - memory_size
            or (
                alignment not in {0, 1}
                and (
                    alignment & (alignment - 1) != 0
                    or file_offset % alignment
                    != virtual_address % alignment
                )
            )
        ):
            raise LauncherError("producer ELF segment is out of bounds")
        if program_type in {2, 3}:
            raise LauncherError(
                "producer executable contains dynamic loading metadata"
            )
        if program_type == 0x6474E551:
            if (
                has_non_executable_stack
                or segment_flags & 0x1
                or file_size != 0
                or memory_size != 0
            ):
                raise LauncherError(
                    "producer executable requests an executable stack"
                )
            has_non_executable_stack = True
        if program_type == 1:
            if (
                memory_size < 1
                or segment_flags & 0x3 == 0x3
                or segment_flags & 0x1 and not segment_flags & 0x4
            ):
                raise LauncherError(
                    "producer executable has an invalid load-segment policy"
                )
            total_load_memory += memory_size
            if total_load_memory > 1024 * 1024 * 1024:
                raise LauncherError(
                    "producer executable exceeds its mapped-memory bound"
                )
            file_end = file_offset + file_size
            memory_end = virtual_address + memory_size
            for (
                previous_file_start,
                previous_file_end,
                previous_memory_start,
                previous_memory_end,
            ) in load_ranges:
                if (
                    max(file_offset, previous_file_start)
                    < min(file_end, previous_file_end)
                    or max(virtual_address, previous_memory_start)
                    < min(memory_end, previous_memory_end)
                ):
                    raise LauncherError(
                        "producer executable has overlapping load segments"
                    )
            load_ranges.append(
                (
                    file_offset,
                    file_end,
                    virtual_address,
                    memory_end,
                )
            )
            if (
                segment_flags & 0x1
                and virtual_address <= entry_point
                < virtual_address + file_size
            ):
                entry_is_executable = True
    if (
        not load_ranges
        or not has_non_executable_stack
        or not entry_is_executable
    ):
        raise LauncherError(
            "producer executable lacks a closed static execution layout"
        )

    if section_offset == 0:
        if section_count != 0 or section_entry_size != 0 or section_names != 0:
            raise LauncherError("producer ELF has inconsistent section metadata")
        return
    if (
        section_entry_size != 64
        or not 1 <= section_count <= 8192
        or section_names >= section_count
        or section_offset < 64
        or section_offset + section_entry_size * section_count > len(raw)
    ):
        raise LauncherError("producer ELF section table is invalid")
    sections: list[tuple[int, int, int, int, int]] = []
    for index in range(section_count):
        offset = section_offset + index * section_entry_size
        (
            name_offset,
            section_type,
            section_flags,
            section_address,
            file_offset,
            section_size,
            _link,
            _info,
            _alignment,
            _entry_size,
        ) = struct.unpack_from("<IIQQQQIIQQ", raw, offset)
        if (
            section_type in {6, 11}
            or section_flags & 0x5 == 0x5
            or section_address > MAX_U64 - section_size
            or (
                section_type != 8
                and (
                    file_offset > len(raw)
                    or section_size > len(raw) - file_offset
                )
            )
        ):
            raise LauncherError(
                "producer ELF section metadata violates the static W^X policy"
            )
        sections.append(
            (
                name_offset,
                section_type,
                file_offset,
                section_size,
                section_flags,
            )
        )
    (
        _names_name_offset,
        names_type,
        names_offset,
        names_size,
        _names_flags,
    ) = sections[section_names]
    if names_type != 3 or names_size < 1:
        raise LauncherError("producer ELF section-name table is invalid")
    section_name_table = raw[names_offset : names_offset + names_size]
    prohibited_names = {
        b".dynamic",
        b".dynstr",
        b".dynsym",
        b".gnu.hash",
        b".got.plt",
        b".hash",
        b".interp",
        b".plt",
        b".rel.plt",
        b".rela.plt",
    }
    for name_offset, _type, _offset, _size, _flags in sections:
        if name_offset >= len(section_name_table):
            raise LauncherError("producer ELF section name is out of bounds")
        terminator = section_name_table.find(b"\x00", name_offset)
        if terminator < 0:
            raise LauncherError("producer ELF section name is unterminated")
        if section_name_table[name_offset:terminator] in prohibited_names:
            raise LauncherError(
                "producer executable contains dynamic-linker sections"
            )


def _assert_frozen_launcher_boundary(architecture: str) -> bytes:
    if (
        getattr(sys, "frozen", False) is not True
        or sys.flags.isolated != 1
        or sys.flags.no_site != 1
        or sys.flags.ignore_environment != 1
        or getattr(sys.flags, "safe_path", False) is not True
    ):
        raise LauncherError(
            "production mode requires the isolated static frozen launcher"
        )
    for module in tuple(sys.modules.values()):
        module_path = getattr(module, "__file__", None)
        if isinstance(module_path, str) and os.path.isabs(module_path):
            raise LauncherError(
                "production launcher imported a host filesystem module"
            )
    launcher_descriptor = os.open(
        "/proc/self/exe",
        os.O_RDONLY | os.O_CLOEXEC,
    )
    try:
        metadata = os.fstat(launcher_descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) & 0o111 == 0
            or metadata.st_nlink != 0
            or metadata.st_size > 256 * 1024 * 1024
        ):
            raise LauncherError("production launcher artifact is not protected")
        raw = _read_regular_fd(
            launcher_descriptor,
            label="production launcher artifact",
            maximum=256 * 1024 * 1024,
            require_seals=True,
        )
    finally:
        os.close(launcher_descriptor)
    _validate_static_elf(raw, architecture=architecture)
    return raw


def _validate_executable_fd(
    descriptor: int,
    policy: ValidatedDescriptor,
) -> bytes:
    raw = _read_regular_fd(
        descriptor,
        label="producer executable",
        maximum=256 * 1024 * 1024,
        require_seals=True,
    )
    metadata = os.fstat(descriptor)
    if (
        stat.S_IMODE(metadata.st_mode) & 0o111 == 0
        or metadata.st_nlink != 0
        or _sha256(raw) != policy.executable_sha256
    ):
        raise LauncherError("producer executable measurement is invalid")
    _validate_static_elf(raw, architecture=policy.architecture)
    return raw


def _validate_named_fd(
    descriptor: int,
    rule: NamedFdRule,
    *,
    measurement_sources: dict[str, tuple[int, bytes]],
    proc_descriptor: int,
    architecture: str,
    production_mode: bool,
    owner_liveness_descriptor: int,
    command_deadline: float,
    timeout_seconds: float,
) -> ServicePeerState | None:
    metadata = os.fstat(descriptor)
    _require_fd_access(
        descriptor,
        rule.access,
        label=f"named producer FD {rule.role}",
    )
    if rule.kind in {
        "sealed-regular-file",
        "sealed-release-bound-file",
    }:
        raw = _read_regular_fd(
            descriptor,
            label=f"named producer FD {rule.role}",
            maximum=rule.document["maxBytes"],
            require_seals=True,
        )
        if (
            rule.kind == "sealed-regular-file"
            and _sha256(raw) != rule.document["expectedSha256"]
        ):
            raise LauncherError(
                f"named producer FD {rule.role} digest is invalid"
            )
        if (
            rule.role == "sandboxLauncher"
            and "sandboxLauncher" in measurement_sources
            and raw != measurement_sources["sandboxLauncher"][1]
        ):
            raise LauncherError(
                "running launcher differs from the independent launcher artifact"
            )
        return None
    if rule.kind == "sealed-measurement-copy":
        raw = _read_regular_fd(
            descriptor,
            label=f"named producer FD {rule.role}",
            maximum=rule.document["maxBytes"],
            require_seals=True,
        )
        source_descriptor, source_raw = measurement_sources[
            rule.document["measurementOf"]
        ]
        if (
            descriptor == source_descriptor
            or raw != source_raw
        ):
            raise LauncherError(
                f"named producer FD {rule.role} is not a distinct sealed byte-exact measurement copy"
            )
        return None
    if rule.kind == "sealed-ephemeral-secret":
        _validate_sealed_exact_size_fd(
            descriptor,
            label=f"named producer FD {rule.role}",
            exact_bytes=rule.document["exactBytes"],
        )
        return None
    if not stat.S_ISSOCK(metadata.st_mode):
        raise LauncherError(f"named producer FD {rule.role} is not a socket")
    duplicate = os.dup(descriptor)
    peer_state: ServicePeerState | None = None
    try:
        connection = socket.socket(fileno=duplicate)
        duplicate = -1
        try:
            expected_socket_type = socket.SOCK_SEQPACKET
            if (
                connection.family != socket.AF_UNIX
                or connection.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE)
                != expected_socket_type
            ):
                raise LauncherError(
                    f"named producer FD {rule.role} has the wrong Unix socket type"
                )
            connection.getpeername()
            if not hasattr(socket, "SO_PASSCRED") or not hasattr(
                socket,
                "SCM_CREDENTIALS",
            ):
                raise LauncherError(
                    "kernel per-message Unix credentials are unavailable"
                )
            connection.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            if connection.getsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED) != 1:
                raise LauncherError(
                    f"named producer FD {rule.role} cannot require message credentials"
                )
            peer_credentials = connection.getsockopt(
                socket.SOL_SOCKET,
                socket.SO_PEERCRED,
                struct.calcsize("iII"),
            )
            peer_pid, peer_uid, peer_gid = struct.unpack(
                "iII",
                peer_credentials,
            )
            if (
                peer_pid < 1
                or peer_uid != rule.document["peerUid"]
                or peer_gid != rule.document["peerGid"]
            ):
                raise LauncherError(
                    f"named producer FD {rule.role} peer is invalid"
                )
            pidfd_open = getattr(os, "pidfd_open", None)
            if pidfd_open is None:
                raise LauncherError("pidfd peer pinning is unavailable")
            try:
                pidfd = pidfd_open(peer_pid, 0)
            except OSError as exc:
                raise LauncherError(
                    f"named producer FD {rule.role} peer pidfd is unavailable"
                ) from exc
            peer_cgroup_descriptor = -1
            try:
                _assert_pidfd_alive(pidfd, label=f"service peer {rule.role}")
                (
                    peer_executable_sha256,
                    peer_executable_identity,
                ) = _peer_executable_measurement(
                    proc_descriptor,
                    peer_pid,
                    architecture=architecture,
                    label=f"service peer {rule.role}",
                )
                peer_cgroup_path = _process_cgroup_membership(
                    proc_descriptor,
                    peer_pid,
                )
                if (
                    peer_executable_sha256
                    != rule.document["peerExecutableSha256"]
                    or peer_cgroup_path != rule.document["peerCgroupPath"]
                ):
                    raise LauncherError(
                        f"named producer FD {rule.role} peer identity crossed its pins"
                    )
                _assert_service_process_restrictions(
                    proc_descriptor,
                    peer_pid,
                    expected_uid=peer_uid,
                    expected_gid=peer_gid,
                    required_seccomp_filter_count=(
                        rule.document["peerRequiredSeccompFilterCount"]
                        if production_mode
                        else None
                    ),
                    label=f"service peer {rule.role}",
                )
                executable_map_closure_sha256 = (
                    _peer_executable_map_closure_sha256(
                        proc_descriptor,
                        peer_pid,
                        architecture=architecture,
                        executable_identity=peer_executable_identity,
                        label=f"service peer {rule.role}",
                    )
                )
                if (
                    executable_map_closure_sha256
                    != rule.document["peerExecutableMapClosureSha256"]
                ):
                    raise LauncherError(
                        f"named producer FD {rule.role} executable maps crossed their pin"
                    )
                cgroup_ancestor_closure_sha256 = (
                    _peer_cgroup_ancestor_closure_sha256(
                        peer_cgroup_path,
                        label=f"service peer {rule.role}",
                    )
                )
                if (
                    cgroup_ancestor_closure_sha256
                    != rule.document["peerCgroupAncestorClosureSha256"]
                ):
                    raise LauncherError(
                        f"named producer FD {rule.role} cgroup ancestors crossed their pin"
                    )
                peer_cgroup_descriptor = _open_peer_cgroup(
                    peer_cgroup_path,
                    peer_pid,
                    label=f"service peer {rule.role}",
                )
                _challenge_service_channel(
                    connection,
                    rule,
                    expected_credentials=(peer_pid, peer_uid, peer_gid),
                    owner_liveness_descriptor=owner_liveness_descriptor,
                    command_deadline=command_deadline,
                    timeout_seconds=timeout_seconds,
                )
                connection.settimeout(None)
                _assert_pidfd_alive(pidfd, label=f"service peer {rule.role}")
                if (
                    _peer_executable_sha256(
                        proc_descriptor,
                        peer_pid,
                        label=f"service peer {rule.role}",
                    )
                    != peer_executable_sha256
                    or _process_cgroup_membership(proc_descriptor, peer_pid)
                    != peer_cgroup_path
                ):
                    raise LauncherError(
                        f"named producer FD {rule.role} peer drifted during challenge"
                    )
                _assert_service_process_restrictions(
                    proc_descriptor,
                    peer_pid,
                    expected_uid=peer_uid,
                    expected_gid=peer_gid,
                    required_seccomp_filter_count=(
                        rule.document["peerRequiredSeccompFilterCount"]
                        if production_mode
                        else None
                    ),
                    label=f"service peer {rule.role}",
                )
                if (
                    _peer_executable_map_closure_sha256(
                        proc_descriptor,
                        peer_pid,
                        architecture=architecture,
                        executable_identity=peer_executable_identity,
                        label=f"service peer {rule.role}",
                    )
                    != executable_map_closure_sha256
                    or _peer_cgroup_ancestor_closure_sha256(
                        peer_cgroup_path,
                        label=f"service peer {rule.role}",
                    )
                    != cgroup_ancestor_closure_sha256
                ):
                    raise LauncherError(
                        f"named producer FD {rule.role} closure drifted during challenge"
                    )
                if rule.document["direction"] == "producer-to-service":
                    connection.shutdown(socket.SHUT_RD)
                else:
                    connection.shutdown(socket.SHUT_WR)
                peer_state = ServicePeerState(
                    role=rule.role,
                    descriptor=descriptor,
                    pid=peer_pid,
                    pidfd=pidfd,
                    architecture=architecture,
                    production_mode=production_mode,
                    cgroup_descriptor=peer_cgroup_descriptor,
                    cgroup_identity=(
                        os.fstat(peer_cgroup_descriptor).st_dev,
                        os.fstat(peer_cgroup_descriptor).st_ino,
                    ),
                    executable_identity=peer_executable_identity,
                    executable_sha256=peer_executable_sha256,
                    executable_map_closure_sha256=(
                        executable_map_closure_sha256
                    ),
                    post_exec_profile_sha256=rule.document[
                        "peerPostExecEnforcementProfileSha256"
                    ],
                    required_seccomp_filter_count=rule.document[
                        "peerRequiredSeccompFilterCount"
                    ],
                    cgroup_ancestor_closure_sha256=(
                        cgroup_ancestor_closure_sha256
                    ),
                    cgroup_path=peer_cgroup_path,
                )
                pidfd = -1
                peer_cgroup_descriptor = -1
            finally:
                if pidfd >= 0:
                    os.close(pidfd)
                if peer_cgroup_descriptor >= 0:
                    os.close(peer_cgroup_descriptor)
        finally:
            connection.close()
    finally:
        if duplicate >= 0:
            os.close(duplicate)
    if peer_state is None:
        raise LauncherError(
            f"named producer FD {rule.role} service admission did not complete"
        )
    return peer_state


def _assert_pidfd_alive(descriptor: int, *, label: str) -> None:
    poller = select.poll()
    poller.register(
        descriptor,
        select.POLLIN | select.POLLERR | select.POLLHUP | select.POLLNVAL,
    )
    if poller.poll(0):
        raise LauncherError(f"{label} exited or became invalid")


def _peer_executable_sha256(
    proc_descriptor: int,
    process_id: int,
    *,
    label: str,
) -> str:
    try:
        executable_descriptor = os.open(
            f"{process_id}/exe",
            os.O_RDONLY | os.O_CLOEXEC,
            dir_fd=proc_descriptor,
        )
    except OSError as exc:
        raise LauncherError(f"{label} executable is unavailable") from exc
    try:
        metadata = os.fstat(executable_descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) & 0o111 == 0
        ):
            raise LauncherError(f"{label} executable is invalid")
        raw = _read_regular_fd(
            executable_descriptor,
            label=f"{label} executable",
            maximum=256 * 1024 * 1024,
            require_seals=False,
        )
        return _sha256(raw)
    finally:
        os.close(executable_descriptor)


def _peer_executable_measurement(
    proc_descriptor: int,
    process_id: int,
    *,
    architecture: str,
    label: str,
) -> tuple[str, tuple[int, int]]:
    try:
        executable_descriptor = os.open(
            f"{process_id}/exe",
            os.O_RDONLY | os.O_CLOEXEC,
            dir_fd=proc_descriptor,
        )
    except OSError as exc:
        raise LauncherError(f"{label} executable is unavailable") from exc
    try:
        metadata = os.fstat(executable_descriptor)
        raw = _read_regular_fd(
            executable_descriptor,
            label=f"{label} executable",
            maximum=256 * 1024 * 1024,
            require_seals=False,
        )
        _validate_static_elf(raw, architecture=architecture)
        return _sha256(raw), (metadata.st_dev, metadata.st_ino)
    finally:
        os.close(executable_descriptor)


def _peer_executable_map_closure_sha256(
    proc_descriptor: int,
    process_id: int,
    *,
    architecture: str,
    executable_identity: tuple[int, int],
    label: str,
) -> str:
    raw = _proc_read(
        proc_descriptor,
        f"{process_id}/maps",
        maximum=MAX_PROC_FILE_BYTES,
        label=f"{label} executable maps",
    )
    records: list[dict[str, Any]] = []
    executable_device = (
        os.major(executable_identity[0]),
        os.minor(executable_identity[0]),
    )
    for index, line in enumerate(raw.splitlines()):
        fields = line.split(None, 5)
        if len(fields) < 5:
            raise LauncherError(f"{label} executable map is malformed")
        _address, permissions, offset_raw, device_raw, inode_raw = fields[:5]
        path = fields[5] if len(fields) == 6 else ""
        if len(permissions) != 4 or permissions[2] != "x":
            continue
        if permissions[1] == "w" or permissions[3] not in {"p", "s"}:
            raise LauncherError(f"{label} has a writable executable mapping")
        if (
            re.fullmatch(r"[0-9a-f]+", offset_raw) is None
            or device_raw.count(":") != 1
            or not inode_raw.isdigit()
        ):
            raise LauncherError(f"{label} executable map identity is malformed")
        device_parts = device_raw.split(":", 1)
        if any(re.fullmatch(r"[0-9a-f]+", part) is None for part in device_parts):
            raise LauncherError(f"{label} executable map device is malformed")
        device = tuple(int(part, 16) for part in device_parts)
        inode = int(inode_raw, 10)
        if path == "[vdso]":
            kind = "kernel-vdso"
        elif path == "[vsyscall]" and architecture == "x86_64":
            kind = "kernel-vsyscall"
        else:
            if (
                not path.startswith("/")
                or path.endswith(" (deleted)")
                or path.startswith("/memfd:")
                or device != executable_device
                or inode != executable_identity[1]
            ):
                raise LauncherError(
                    f"{label} has an unmeasured executable mapping"
                )
            kind = "peer-static-executable"
        records.append(
            {
                "deviceMajor": device[0],
                "deviceMinor": device[1],
                "index": index,
                "inode": inode,
                "kind": kind,
                "offset": int(offset_raw, 16),
                "permissions": permissions,
            }
        )
    if (
        not records
        or not any(record["kind"] == "peer-static-executable" for record in records)
    ):
        raise LauncherError(f"{label} has no measured executable mapping")
    return _sha256(_canonical_json(records))


def _assert_no_cgroup_descriptor(
    proc_descriptor: int,
    process_id: int,
    *,
    label: str,
) -> None:
    o_path = getattr(os, "O_PATH", None)
    if o_path is None:
        raise LauncherError(
            f"{label} descriptor filesystem inspection is unavailable"
        )
    directory_descriptor = -1
    try:
        directory_descriptor = os.open(
            f"{process_id}/fd",
            os.O_RDONLY
            | os.O_DIRECTORY
            | os.O_CLOEXEC
            | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=proc_descriptor,
        )
        entries = os.listdir(directory_descriptor)
        for entry in entries:
            if not entry.isdigit():
                raise LauncherError(f"{label} descriptor table is malformed")
            target = os.readlink(
                f"{process_id}/fd/{entry}",
                dir_fd=proc_descriptor,
            )
            peer_descriptor = -1
            try:
                peer_descriptor = os.open(
                    f"{process_id}/fd/{entry}",
                    o_path | os.O_CLOEXEC,
                    dir_fd=proc_descriptor,
                )
                if (
                    target == "/sys/fs/cgroup"
                    or target.startswith("/sys/fs/cgroup/")
                    or _fstatfs_magic(peer_descriptor) == CGROUP2_SUPER_MAGIC
                ):
                    raise LauncherError(
                        f"{label} retains a cgroup descriptor"
                    )
            finally:
                if peer_descriptor >= 0:
                    os.close(peer_descriptor)
    except OSError as exc:
        raise LauncherError(f"{label} descriptor table is unavailable") from exc
    finally:
        if directory_descriptor >= 0:
            os.close(directory_descriptor)


def _assert_service_process_restrictions(
    proc_descriptor: int,
    process_id: int,
    *,
    expected_uid: int,
    expected_gid: int,
    required_seccomp_filter_count: int | None,
    label: str,
) -> None:
    status = _parse_proc_status(
        _proc_read(
            proc_descriptor,
            f"{process_id}/status",
            maximum=MAX_PROC_FILE_BYTES,
            label=f"{label} status",
        )
    )
    # Filter count is only a structural sanity check; Linux does not expose
    # installed filter bytes. Production therefore remains blocked on the
    # external post-exec identity prerequisite.
    if (
        status.get("Uid", "").split() != [str(expected_uid)] * 4
        or status.get("Gid", "").split() != [str(expected_gid)] * 4
        or status.get("Groups", "") != ""
        or status.get("NoNewPrivs") != "1"
        or status.get("Seccomp") != "2"
        or (
            required_seccomp_filter_count is not None
            and status.get("Seccomp_filters")
            != str(required_seccomp_filter_count)
        )
    ):
        raise LauncherError(f"{label} process restrictions are incomplete")
    for field in CAPABILITY_STATUS_FIELDS:
        value = status.get(field)
        if (
            value is None
            or re.fullmatch(r"[0-9A-Fa-f]{16}", value) is None
            or int(value, 16) != 0
        ):
            raise LauncherError(f"{label} capabilities are not empty")
    if (
        _proc_namespace(proc_descriptor, process_id, "cgroup")
        == _proc_namespace(proc_descriptor, os.getpid(), "cgroup")
    ):
        raise LauncherError(f"{label} does not have a private cgroup namespace")
    mountinfo = _proc_read(
        proc_descriptor,
        f"{process_id}/mountinfo",
        maximum=MAX_PROC_FILE_BYTES,
        label=f"{label} mount table",
    )
    for line in mountinfo.splitlines():
        fields = line.split()
        if "-" not in fields:
            raise LauncherError(f"{label} mount table is malformed")
        separator = fields.index("-")
        if len(fields) <= separator + 1:
            raise LauncherError(f"{label} mount table is malformed")
        if fields[separator + 1] == "cgroup2" and "rw" in fields[5].split(","):
            raise LauncherError(f"{label} exposes a writable cgroup filesystem")
    _assert_no_cgroup_descriptor(proc_descriptor, process_id, label=label)


def _assert_no_posix_acl(descriptor: int, *, label: str) -> None:
    try:
        acl = os.getxattr(descriptor, "system.posix_acl_access")
    except OSError as exc:
        if exc.errno not in {errno.ENODATA, errno.ENOTSUP, errno.EOPNOTSUPP}:
            raise LauncherError(f"{label} ACL state is unavailable") from exc
        return
    if acl:
        raise LauncherError(f"{label} has an unreviewed POSIX ACL")


def _protected_cgroup_control_identity(
    cgroup_descriptor: int,
    name: str,
    *,
    label: str,
) -> dict[str, int]:
    descriptor = _openat(
        cgroup_descriptor,
        name,
        os.O_RDONLY,
        label=f"{label} {name}",
    )
    try:
        metadata = os.fstat(descriptor)
        if metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) & 0o022:
            raise LauncherError(f"{label} {name} is service-writable")
        _assert_no_posix_acl(descriptor, label=f"{label} {name}")
        return {
            "device": metadata.st_dev,
            "gid": metadata.st_gid,
            "inode": metadata.st_ino,
            "mode": stat.S_IMODE(metadata.st_mode),
            "uid": metadata.st_uid,
        }
    finally:
        os.close(descriptor)


def _peer_cgroup_ancestor_closure_sha256(
    membership_path: str,
    *,
    label: str,
) -> str:
    components = membership_path.removeprefix("/").split("/")
    if not components or any(not component for component in components):
        raise LauncherError(f"{label} cgroup path is not canonical")
    current = os.open(
        "/sys/fs/cgroup",
        os.O_RDONLY
        | os.O_DIRECTORY
        | os.O_CLOEXEC
        | getattr(os, "O_NOFOLLOW", 0),
    )
    records: list[dict[str, Any]] = []
    try:
        for depth, component in enumerate(("", *components)):
            if component:
                child = _openat(
                    current,
                    component,
                    os.O_RDONLY | os.O_DIRECTORY,
                    label=f"{label} cgroup ancestor",
                )
                os.close(current)
                current = child
            metadata = os.fstat(current)
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid != 0
                or stat.S_IMODE(metadata.st_mode) & 0o022
                or _fstatfs_magic(current) != CGROUP2_SUPER_MAGIC
            ):
                raise LauncherError(f"{label} has an unprotected cgroup ancestor")
            _assert_no_posix_acl(current, label=f"{label} cgroup ancestor")
            controls = {
                name: _protected_cgroup_control_identity(
                    current,
                    name,
                    label=f"{label} cgroup ancestor",
                )
                for name in (
                    "cgroup.controllers",
                    "cgroup.procs",
                    "cgroup.subtree_control",
                    "cgroup.threads",
                    "cgroup.type",
                )
            }
            controllers = _read_cgroup_file(
                current,
                "cgroup.controllers",
            ).split()
            subtree_control = _read_cgroup_file(
                current,
                "cgroup.subtree_control",
            ).split()
            cgroup_type = _read_cgroup_file(current, "cgroup.type").strip()
            if (
                len(controllers) != len(set(controllers))
                or len(subtree_control) != len(set(subtree_control))
                or cgroup_type not in {"domain", "domain threaded", "threaded"}
            ):
                raise LauncherError(
                    f"{label} cgroup delegation metadata is malformed"
                )
            controllers.sort()
            subtree_control.sort()
            records.append(
                {
                    "cgroupType": cgroup_type,
                    "controllers": controllers,
                    "controls": controls,
                    "depth": depth,
                    "device": metadata.st_dev,
                    "gid": metadata.st_gid,
                    "inode": metadata.st_ino,
                    "mode": stat.S_IMODE(metadata.st_mode),
                    "mountId": _fd_mount_id(current),
                    "subtreeControl": subtree_control,
                    "uid": metadata.st_uid,
                }
            )
    finally:
        os.close(current)
    return _sha256(_canonical_json(records))


def _process_thread_ids(
    proc_descriptor: int,
    process_id: int,
    *,
    label: str,
) -> set[int]:
    task_descriptor = -1
    try:
        task_descriptor = os.open(
            f"{process_id}/task",
            os.O_RDONLY
            | os.O_DIRECTORY
            | os.O_CLOEXEC
            | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=proc_descriptor,
        )
        entries = os.listdir(task_descriptor)
    except OSError as exc:
        raise LauncherError(f"{label} thread set is unavailable") from exc
    finally:
        if task_descriptor >= 0:
            os.close(task_descriptor)
    if (
        not entries
        or any(not entry.isdigit() or int(entry, 10) < 1 for entry in entries)
    ):
        raise LauncherError(f"{label} thread set is malformed")
    thread_ids = {int(entry, 10) for entry in entries}
    if len(thread_ids) != len(entries):
        raise LauncherError(f"{label} thread set contains a duplicate")
    return thread_ids


def _open_peer_cgroup(
    membership_path: str,
    process_id: int,
    *,
    label: str,
) -> int:
    try:
        descriptor = os.open(
            "/sys/fs/cgroup" + membership_path,
            os.O_RDONLY
            | os.O_DIRECTORY
            | os.O_CLOEXEC
            | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError as exc:
        raise LauncherError(f"{label} cgroup is unavailable") from exc
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or _fstatfs_magic(descriptor) != CGROUP2_SUPER_MAGIC
            or metadata.st_uid != 0
            or stat.S_IMODE(metadata.st_mode) & 0o022
            or process_id not in _cgroup_processes(descriptor)
            or _read_cgroup_file(
                descriptor,
                "cgroup.subtree_control",
            ).strip()
        ):
            raise LauncherError(f"{label} is not in the exact cgroup")
        _assert_no_posix_acl(descriptor, label=f"{label} cgroup")
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _receive_service_frame(
    connection: socket.socket,
    *,
    expected_credentials: tuple[int, int, int],
) -> bytes:
    ancillary_size = socket.CMSG_SPACE(SCM_CREDENTIALS_SIZE)
    raw, ancillary, flags, address = connection.recvmsg(
        MAX_SERVICE_FRAME_BYTES + 1,
        ancillary_size,
    )
    if (
        address not in {None, "", b""}
        or not raw
        or flags
        & (
            getattr(socket, "MSG_TRUNC", 0)
            | getattr(socket, "MSG_CTRUNC", 0)
        )
        or len(raw) > MAX_SERVICE_FRAME_BYTES
    ):
        raise LauncherError("service response frame is truncated or oversized")
    credentials: list[tuple[int, int, int]] = []
    for level, control_type, control_data in ancillary:
        if (
            level != socket.SOL_SOCKET
            or control_type != socket.SCM_CREDENTIALS
            or len(control_data) != SCM_CREDENTIALS_SIZE
        ):
            raise LauncherError(
                "service response contains an FD or unknown control message"
            )
        credentials.append(struct.unpack("3i", control_data))
    if credentials != [expected_credentials]:
        raise LauncherError(
            "service response sender differs from the pinned traced peer"
        )
    try:
        queued = connection.recvmsg(
            1,
            ancillary_size,
            socket.MSG_PEEK | socket.MSG_DONTWAIT,
        )
    except BlockingIOError:
        return raw
    if queued[0]:
        raise LauncherError("service response contains an unexpected extra frame")
    raise LauncherError("service response channel closed during authentication")


def _challenge_service_channel(
    connection: socket.socket,
    rule: NamedFdRule,
    *,
    expected_credentials: tuple[int, int, int],
    owner_liveness_descriptor: int,
    command_deadline: float,
    timeout_seconds: float,
) -> None:
    challenge = base64.urlsafe_b64encode(os.getrandom(32)).rstrip(b"=").decode(
        "ascii"
    )
    request = {
        "apiVersion": SERVICE_CHALLENGE_VERSION,
        "challengeBase64url": challenge,
        "direction": rule.document["direction"],
        "protocol": rule.document["protocol"],
        "role": rule.role,
    }
    raw_request = _canonical_json(request) + b"\n"
    operation_deadline = min(
        command_deadline,
        time.monotonic() + timeout_seconds,
    )
    _assert_owner_alive(
        owner_liveness_descriptor,
        command_deadline=command_deadline,
    )
    connection.settimeout(
        max(0.001, min(0.05, operation_deadline - time.monotonic()))
    )
    try:
        if connection.send(raw_request) != len(raw_request):
            raise LauncherError("service challenge request was truncated")
        while True:
            _assert_owner_alive(
                owner_liveness_descriptor,
                command_deadline=command_deadline,
            )
            remaining = operation_deadline - time.monotonic()
            if remaining <= 0:
                raise LauncherError("service challenge exchange timed out")
            connection.settimeout(max(0.001, min(0.05, remaining)))
            try:
                raw_response = _receive_service_frame(
                    connection,
                    expected_credentials=expected_credentials,
                )
                break
            except (TimeoutError, socket.timeout):
                continue
    except OSError as exc:
        raise LauncherError("service challenge exchange failed") from exc
    response = _load_canonical_document(
        raw_response,
        label="service challenge response",
        maximum=MAX_SERVICE_FRAME_BYTES,
    )
    expected_response = {
        "apiVersion": SERVICE_CHALLENGE_RESPONSE_VERSION,
        "challengeBase64url": challenge,
        "direction": rule.document["direction"],
        "peerCgroupPath": rule.document["peerCgroupPath"],
        "peerExecutableSha256": rule.document["peerExecutableSha256"],
        "protocol": rule.document["protocol"],
        "role": rule.role,
    }
    if response != expected_response:
        raise LauncherError("service challenge response crossed its channel")


def _revalidate_service_peer(
    state: ServicePeerState,
    rule: NamedFdRule,
    *,
    proc_descriptor: int,
) -> None:
    _assert_pidfd_alive(state.pidfd, label=f"service peer {state.role}")
    duplicate = os.dup(state.descriptor)
    connection: socket.socket | None = None
    try:
        connection = socket.socket(fileno=duplicate)
        duplicate = -1
        if (
            connection.family != socket.AF_UNIX
            or connection.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE)
            != socket.SOCK_SEQPACKET
            or connection.getsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED) != 1
        ):
            raise LauncherError(
                f"service peer {state.role} transport contract drifted"
            )
        credentials = connection.getsockopt(
            socket.SOL_SOCKET,
            socket.SO_PEERCRED,
            struct.calcsize("iII"),
        )
        peer_pid, peer_uid, peer_gid = struct.unpack("iII", credentials)
        if (
            peer_pid != state.pid
            or peer_uid != rule.document["peerUid"]
            or peer_gid != rule.document["peerGid"]
        ):
            raise LauncherError(
                f"service peer {state.role} credentials drifted"
            )
    finally:
        if connection is not None:
            connection.close()
        if duplicate >= 0:
            os.close(duplicate)
    cgroup_metadata = os.fstat(state.cgroup_descriptor)
    (
        executable_sha256,
        executable_identity,
    ) = _peer_executable_measurement(
        proc_descriptor,
        state.pid,
        architecture=state.architecture,
        label=f"service peer {state.role}",
    )
    _assert_service_process_restrictions(
        proc_descriptor,
        state.pid,
        expected_uid=rule.document["peerUid"],
        expected_gid=rule.document["peerGid"],
        required_seccomp_filter_count=(
            state.required_seccomp_filter_count
            if state.production_mode
            else None
        ),
        label=f"service peer {state.role}",
    )
    if (
        (cgroup_metadata.st_dev, cgroup_metadata.st_ino)
        != state.cgroup_identity
        or not stat.S_ISDIR(cgroup_metadata.st_mode)
        or cgroup_metadata.st_uid != 0
        or stat.S_IMODE(cgroup_metadata.st_mode) & 0o022
        or _fstatfs_magic(state.cgroup_descriptor) != CGROUP2_SUPER_MAGIC
        or state.pid not in _cgroup_processes(state.cgroup_descriptor)
        or executable_sha256 != state.executable_sha256
        or executable_identity != state.executable_identity
        or _peer_executable_map_closure_sha256(
            proc_descriptor,
            state.pid,
            architecture=state.architecture,
            executable_identity=state.executable_identity,
            label=f"service peer {state.role}",
        )
        != state.executable_map_closure_sha256
        or _peer_cgroup_ancestor_closure_sha256(
            state.cgroup_path,
            label=f"service peer {state.role}",
        )
        != state.cgroup_ancestor_closure_sha256
    ):
        raise LauncherError(f"service peer {state.role} identity drifted")


def _ptrace(
    request: int,
    process_id: int,
    *,
    data: int = 0,
    label: str,
) -> None:
    ctypes.set_errno(0)
    result = LIBC.ptrace(
        ctypes.c_uint(request),
        ctypes.c_int(process_id),
        ctypes.c_void_p(0),
        ctypes.c_void_p(data),
    )
    if result == -1:
        error = ctypes.get_errno()
        raise LauncherError(f"{label} failed") from OSError(
            error,
            os.strerror(error),
        )


def _ptrace_event_process_id(process_id: int) -> int:
    event_process_id = ctypes.c_ulong(0)
    ctypes.set_errno(0)
    result = LIBC.ptrace(
        ctypes.c_uint(PTRACE_GETEVENTMSG),
        ctypes.c_int(process_id),
        ctypes.c_void_p(0),
        ctypes.byref(event_process_id),
    )
    if result == -1 or event_process_id.value < 1:
        error = ctypes.get_errno()
        raise LauncherError(
            "service exec guard could not identify a traced descendant"
        ) from OSError(error, os.strerror(error))
    return int(event_process_id.value)


def _wait_service_guard_nonblocking(
    guard: ServiceExecGuard,
) -> int | None:
    try:
        waited_pid, wait_status = os.waitpid(
            guard.pid,
            os.WNOHANG | WAIT_ALL,
        )
    except ChildProcessError as exc:
        raise LauncherError(
            "service exec guard lost kernel trace ownership"
        ) from exc
    if waited_pid == 0:
        _assert_pidfd_alive(
            guard.pidfd,
            label=f"service exec guard {guard.pid}",
        )
        return None
    if waited_pid != guard.pid:
        raise LauncherError("service exec guard observed an unrelated process")
    if os.WIFSTOPPED(wait_status):
        guard.stopped = True
    return wait_status


def _pidfd_exited(descriptor: int) -> bool:
    poller = select.poll()
    poller.register(
        descriptor,
        select.POLLIN
        | select.POLLERR
        | select.POLLHUP
        | select.POLLNVAL,
    )
    return bool(poller.poll(0))


def _assert_service_exec_guards_quiet(
    guards: list[ServiceExecGuard],
) -> None:
    for guard in guards:
        wait_status = _wait_service_guard_nonblocking(guard)
        if wait_status is None:
            continue
        guard.violated = True
        event = wait_status >> 16
        if event in {
            PTRACE_EVENT_FORK,
            PTRACE_EVENT_VFORK,
            PTRACE_EVENT_CLONE,
        }:
            descendant_pid = _ptrace_event_process_id(guard.pid)
            pidfd_open = getattr(os, "pidfd_open", None)
            if pidfd_open is not None:
                try:
                    guard.spawned_pidfds.append(
                        pidfd_open(descendant_pid, 0)
                    )
                except OSError:
                    pass
            raise LauncherError(
                "service peer crossed the no-fork/no-exec admission boundary"
            )
        if event == PTRACE_EVENT_EXEC:
            raise LauncherError(
                "service peer crossed the no-fork/no-exec admission boundary"
            )
        raise LauncherError(
            "service peer stopped or exited while its response was in flight"
        )


def _assert_service_response_channels_empty(
    states: list[ServicePeerState],
    *,
    rules_by_role: dict[str, NamedFdRule],
) -> None:
    for state in states:
        rule = rules_by_role[state.role]
        if rule.document["direction"] != "service-to-producer":
            continue
        duplicate = os.dup(state.descriptor)
        connection: socket.socket | None = None
        try:
            connection = socket.socket(fileno=duplicate)
            duplicate = -1
            try:
                queued = connection.recv(
                    1,
                    socket.MSG_PEEK | socket.MSG_DONTWAIT,
                )
            except BlockingIOError:
                continue
            if queued:
                raise LauncherError(
                    f"service peer {state.role} queued data before admission"
                )
            raise LauncherError(
                f"service peer {state.role} closed before admission"
            )
        finally:
            if connection is not None:
                connection.close()
            if duplicate >= 0:
                os.close(duplicate)


def _assert_exact_service_cgroups(
    states: list[ServicePeerState],
) -> None:
    grouped: dict[
        tuple[int, int],
        tuple[int, set[int]],
    ] = {}
    for state in states:
        current = grouped.get(state.cgroup_identity)
        if current is None:
            grouped[state.cgroup_identity] = (
                state.cgroup_descriptor,
                {state.pid},
            )
        else:
            current[1].add(state.pid)
    for cgroup_descriptor, expected_processes in grouped.values():
        try:
            with os.scandir(cgroup_descriptor) as entries:
                has_child_cgroup = any(
                    entry.is_dir(follow_symlinks=False)
                    for entry in entries
                )
        except OSError as exc:
            raise LauncherError(
                "service cgroup descendants are unavailable"
            ) from exc
        if (
            has_child_cgroup
            or _cgroup_processes(cgroup_descriptor) != expected_processes
        ):
            raise LauncherError(
                "service cgroup is not an exact protected process leaf"
            )


def _start_service_exec_guards(
    states: list[ServicePeerState],
    *,
    rules_by_role: dict[str, NamedFdRule],
    proc_descriptor: int,
    owner_liveness_descriptor: int,
    command_deadline: float,
) -> list[ServiceExecGuard]:
    if getattr(signal, "pidfd_send_signal", None) is None:
        raise LauncherError("service exec guard requires pidfd signaling")
    by_pid: dict[int, list[ServicePeerState]] = {}
    for state in states:
        by_pid.setdefault(state.pid, []).append(state)
    guards: list[ServiceExecGuard] = []
    try:
        for process_id in sorted(by_pid):
            peer_states = by_pid[process_id]
            reference = peer_states[0]
            if (
                any(
                    state.executable_sha256 != reference.executable_sha256
                    or state.executable_identity != reference.executable_identity
                    or state.executable_map_closure_sha256
                    != reference.executable_map_closure_sha256
                    or state.post_exec_profile_sha256
                    != reference.post_exec_profile_sha256
                    or state.required_seccomp_filter_count
                    != reference.required_seccomp_filter_count
                    or state.cgroup_identity != reference.cgroup_identity
                    or state.cgroup_ancestor_closure_sha256
                    != reference.cgroup_ancestor_closure_sha256
                    or state.cgroup_path != reference.cgroup_path
                    for state in peer_states[1:]
                )
            ):
                raise LauncherError(
                    "service peer channels disagree before exec guard admission"
                )
            _assert_cgroup_kill_available(reference.cgroup_descriptor)
            _assert_pidfd_alive(
                reference.pidfd,
                label=f"service peer {process_id}",
            )
            _ptrace(
                PTRACE_SEIZE,
                process_id,
                data=SERVICE_PTRACE_OPTIONS,
                label="service exec guard admission",
            )
            guards.append(
                ServiceExecGuard(
                    pid=process_id,
                    pidfd=reference.pidfd,
                    cgroup_descriptor=reference.cgroup_descriptor,
                    roles=tuple(sorted(state.role for state in peer_states)),
                    spawned_pidfds=[],
                )
            )
        deadline = min(command_deadline, time.monotonic() + 1.0)
        for guard in guards:
            _stop_service_exec_guard(
                guard,
                deadline=deadline,
                owner_liveness_descriptor=owner_liveness_descriptor,
                command_deadline=command_deadline,
            )
        for state in states:
            if (
                _process_thread_ids(
                    proc_descriptor,
                    state.pid,
                    label=f"service peer {state.role}",
                )
                != {state.pid}
            ):
                raise LauncherError(
                    "service peer has an untracked thread at admission"
                )
            _revalidate_service_peer(
                state,
                rules_by_role[state.role],
                proc_descriptor=proc_descriptor,
            )
        _assert_exact_service_cgroups(states)
        _assert_service_response_channels_empty(
            states,
            rules_by_role=rules_by_role,
        )
        for guard in guards:
            _ptrace(
                PTRACE_CONT,
                guard.pid,
                label="service exec guard admission resume",
            )
            guard.stopped = False
        _assert_service_exec_guards_quiet(guards)
        return guards
    except BaseException:
        for guard in guards:
            if guard.attached:
                guard.violated = True
        _release_service_exec_guards(guards)
        raise


def _stop_service_exec_guard(
    guard: ServiceExecGuard,
    *,
    deadline: float,
    owner_liveness_descriptor: int | None = None,
    command_deadline: float | None = None,
) -> None:
    if guard.stopped:
        return
    _ptrace(
        PTRACE_INTERRUPT,
        guard.pid,
        label="service exec guard interrupt",
    )
    while time.monotonic() < deadline:
        if (
            owner_liveness_descriptor is not None
            and command_deadline is not None
        ):
            _assert_owner_alive(
                owner_liveness_descriptor,
                command_deadline=command_deadline,
            )
        wait_status = _wait_service_guard_nonblocking(guard)
        if wait_status is None:
            time.sleep(0.001)
            continue
        event = wait_status >> 16
        if (
            not os.WIFSTOPPED(wait_status)
            or event != PTRACE_EVENT_STOP
        ):
            guard.violated = True
            raise LauncherError(
                "service peer changed before post-response identity proof"
            )
        return
    raise LauncherError("service exec guard interrupt timed out")


def _finish_service_exec_guards(
    guards: list[ServiceExecGuard],
    states: list[ServicePeerState],
    *,
    rules_by_role: dict[str, NamedFdRule],
    proc_descriptor: int,
    timeout_seconds: float,
    owner_liveness_descriptor: int,
    command_deadline: float,
) -> None:
    deadline = min(
        command_deadline,
        time.monotonic() + timeout_seconds,
    )
    states_by_pid: dict[int, list[ServicePeerState]] = {}
    for state in states:
        states_by_pid.setdefault(state.pid, []).append(state)
    try:
        for guard in guards:
            _stop_service_exec_guard(
                guard,
                deadline=deadline,
                owner_liveness_descriptor=owner_liveness_descriptor,
                command_deadline=command_deadline,
            )
        for guard in guards:
            _assert_owner_alive(
                owner_liveness_descriptor,
                command_deadline=command_deadline,
            )
            if (
                _process_thread_ids(
                    proc_descriptor,
                    guard.pid,
                    label=f"service peer {guard.pid}",
                )
                != {guard.pid}
            ):
                raise LauncherError(
                    "service peer thread set changed before response completion"
                )
            for state in states_by_pid[guard.pid]:
                _revalidate_service_peer(
                    state,
                    rules_by_role[state.role],
                    proc_descriptor=proc_descriptor,
                )
        _assert_exact_service_cgroups(states)
        _assert_service_response_channels_empty(
            states,
            rules_by_role=rules_by_role,
        )
        for guard in guards:
            _ptrace(
                PTRACE_DETACH,
                guard.pid,
                label="service exec guard release",
            )
            guard.attached = False
            guard.stopped = False
    except BaseException:
        for guard in guards:
            if guard.attached:
                guard.violated = True
        raise


def _kill_and_prove_service_guard(guard: ServiceExecGuard) -> None:
    pidfd_send_signal = getattr(signal, "pidfd_send_signal", None)
    if pidfd_send_signal is None:
        raise LauncherError("service guard pidfd signaling is unavailable")
    try:
        _kill_cgroup(guard.cgroup_descriptor)
    except LauncherError:
        pass
    for descriptor in (guard.pidfd, *guard.spawned_pidfds):
        try:
            pidfd_send_signal(descriptor, signal.SIGKILL, None, 0)
        except ProcessLookupError:
            pass
    if guard.stopped:
        try:
            _ptrace(
                PTRACE_DETACH,
                guard.pid,
                data=signal.SIGKILL,
                label="violating service exec guard release",
            )
            guard.attached = False
            guard.stopped = False
        except LauncherError:
            pass
    deadline = time.monotonic() + 1.0
    while time.monotonic() < deadline:
        if (
            not _cgroup_populated(guard.cgroup_descriptor)
            and not _cgroup_processes(guard.cgroup_descriptor)
            and not _cgroup_threads(guard.cgroup_descriptor)
            and _pidfd_exited(guard.pidfd)
            and all(
                _pidfd_exited(descriptor)
                for descriptor in guard.spawned_pidfds
            )
        ):
            for descriptor in guard.spawned_pidfds:
                os.close(descriptor)
            guard.spawned_pidfds.clear()
            guard.attached = False
            return
        try:
            _kill_cgroup(guard.cgroup_descriptor)
        except LauncherError:
            pass
        time.sleep(0.005)
    raise LauncherError(
        "violating service peer could not be proven dead; trace and pidfd "
        "ownership cannot be safely released"
    )


def _release_service_exec_guards(
    guards: list[ServiceExecGuard],
) -> None:
    for guard in reversed(guards):
        if not guard.attached:
            for descriptor in guard.spawned_pidfds:
                os.close(descriptor)
            guard.spawned_pidfds.clear()
            continue
        if guard.violated:
            _kill_and_prove_service_guard(guard)
            continue
        try:
            _stop_service_exec_guard(
                guard,
                deadline=time.monotonic() + 1.0,
            )
            _ptrace(
                PTRACE_DETACH,
                guard.pid,
                label="service exec guard release",
            )
        except LauncherError:
            guard.violated = True
            _kill_and_prove_service_guard(guard)
        finally:
            if not guard.attached:
                for descriptor in guard.spawned_pidfds:
                    os.close(descriptor)
                guard.spawned_pidfds.clear()
                guard.stopped = False


def _closed_seccomp_profile_bytes(
    *,
    architecture: str,
    syscall_names: tuple[str, ...],
) -> bytes:
    abi = KERNEL_ABI_CONTRACTS.get(architecture)
    if abi is None or tuple(sorted(syscall_names)) != syscall_names:
        raise LauncherError("closed seccomp profile identity is unsupported")
    syscall_table = abi["syscalls"]
    if (
        _sha256(_canonical_json(syscall_table))
        != abi["syscall_table_sha256"]
    ):
        raise LauncherError("closed seccomp syscall table digest is invalid")
    if any(name not in syscall_table for name in syscall_names):
        raise LauncherError("closed seccomp profile references an unknown syscall")
    syscall_numbers = sorted(syscall_table[name] for name in syscall_names)
    if (
        len(syscall_numbers) != len(set(syscall_numbers))
        or (
            architecture == "x86_64"
            and any(number & X32_SYSCALL_BIT for number in syscall_numbers)
        )
    ):
        raise LauncherError("closed seccomp syscall table is not canonical")
    instructions = [
        (BPF_LD_W_ABS, 0, 0, SECCOMP_DATA_ARCH_OFFSET),
        (
            BPF_JMP_JEQ_K,
            1,
            0,
            abi["audit_architecture"],
        ),
        (BPF_RET_K, 0, 0, SECCOMP_RET_KILL_PROCESS),
        (BPF_LD_W_ABS, 0, 0, SECCOMP_DATA_NR_OFFSET),
    ]
    for number in syscall_numbers:
        instructions.extend(
            (
                (BPF_JMP_JEQ_K, 0, 1, number),
                (BPF_RET_K, 0, 0, SECCOMP_RET_ALLOW),
            )
        )
    instructions.append((BPF_RET_K, 0, 0, SECCOMP_RET_KILL_PROCESS))
    return b"".join(CBPF_INSTRUCTION.pack(*instruction) for instruction in instructions)


def _validate_reviewed_seccomp_program(
    raw: bytes,
    *,
    architecture: str,
    profile_id: str,
) -> None:
    expected_profile_id = f"catchplate-producer-bootstrap-{architecture}-v1"
    if profile_id != expected_profile_id:
        raise LauncherError("seccomp profile ID is not approved for this kernel ABI")
    expected = _closed_seccomp_profile_bytes(
        architecture=architecture,
        syscall_names=BOOTSTRAP_SYSCALL_NAMES,
    )
    if raw != expected:
        raise LauncherError(
            "seccomp profile bytes differ from the fixed reviewed kernel-ABI profile"
        )


def _read_seccomp_program(
    descriptor: int,
    policy: ValidatedDescriptor,
) -> bytes:
    expected_bytes = policy.seccomp_instruction_count * ctypes.sizeof(SockFilter)
    raw = _read_regular_fd(
        descriptor,
        label="seccomp profile",
        maximum=4096 * ctypes.sizeof(SockFilter),
        require_seals=True,
    )
    if (
        len(raw) != expected_bytes
        or _sha256(raw) != policy.seccomp_sha256
    ):
        raise LauncherError("seccomp profile measurement is invalid")
    if policy.execution_mode == "production":
        _validate_reviewed_seccomp_program(
            raw,
            architecture=policy.architecture,
            profile_id=policy.seccomp_profile_id,
        )
    return raw


def _syscall_number(name: str, architecture: str) -> int:
    value = ARCHITECTURES[architecture].get(name)
    if type(value) is not int:
        raise LauncherError(f"syscall {name} is unavailable")
    return value


def _prctl(
    option: int,
    argument2: int = 0,
    argument3: int = 0,
    argument4: int = 0,
    argument5: int = 0,
) -> None:
    if LIBC.prctl(
        option,
        argument2,
        argument3,
        argument4,
        argument5,
    ) != 0:
        error = ctypes.get_errno()
        raise LauncherError("required prctl operation failed") from OSError(
            error,
            os.strerror(error),
        )


def _apply_seccomp(raw: bytes, *, architecture: str) -> None:
    if len(raw) % ctypes.sizeof(SockFilter) != 0:
        raise LauncherError("seccomp profile is not an instruction array")
    instruction_count = len(raw) // ctypes.sizeof(SockFilter)
    instruction_array_type = SockFilter * instruction_count
    instructions = instruction_array_type.from_buffer_copy(raw)
    program = SockFprog(
        length=instruction_count,
        filter=ctypes.cast(instructions, ctypes.POINTER(SockFilter)),
    )
    syscall_number = _syscall_number("seccomp_syscall", architecture)
    result = LIBC.syscall(
        syscall_number,
        SECCOMP_SET_MODE_FILTER,
        0,
        ctypes.byref(program),
    )
    if result != 0:
        error = ctypes.get_errno()
        raise LauncherError("seccomp profile could not be installed") from OSError(
            error,
            os.strerror(error),
        )


def _mount(
    source: str | None,
    target: str,
    filesystem_type: str | None,
    flags: int,
    data: str | None,
) -> None:
    source_bytes = None if source is None else source.encode("ascii")
    target_bytes = target.encode("ascii")
    filesystem_bytes = (
        None if filesystem_type is None else filesystem_type.encode("ascii")
    )
    data_bytes = None if data is None else data.encode("ascii")
    result = LIBC.mount(
        source_bytes,
        target_bytes,
        filesystem_bytes,
        flags,
        data_bytes,
    )
    if result != 0:
        error = ctypes.get_errno()
        raise LauncherError("required mount operation failed") from OSError(
            error,
            os.strerror(error),
        )


def _mount_setattr_recursive(path: str, *, architecture: str) -> None:
    attributes = MountAttr(
        attr_set=RESTRICTED_MOUNT_ATTRIBUTES,
        attr_clr=0,
        propagation=0,
        userns_fd=0,
    )
    syscall_number = _syscall_number("mount_setattr_syscall", architecture)
    result = LIBC.syscall(
        syscall_number,
        AT_FDCWD,
        path.encode("ascii"),
        AT_RECURSIVE,
        ctypes.byref(attributes),
        ctypes.sizeof(attributes),
    )
    if result != 0:
        error = ctypes.get_errno()
        raise LauncherError(
            "recursive mount attributes are unavailable"
        ) from OSError(error, os.strerror(error))


def _namespace_links() -> dict[str, str]:
    result: dict[str, str] = {}
    for logical, proc_name in NAMESPACE_PROC_NAMES.items():
        path = (
            "/proc/self/ns/pid_for_children"
            if logical == "pid"
            else f"/proc/self/ns/{proc_name}"
        )
        try:
            value = os.readlink(path)
        except OSError as exc:
            raise LauncherError("namespace identity is unavailable") from exc
        if not value.startswith(f"{proc_name}:[") or not value.endswith("]"):
            raise LauncherError("namespace identity is malformed")
        result[logical] = value
    return result


def _unshare_required_namespaces() -> dict[str, str]:
    before = _namespace_links()
    if LIBC.unshare(REQUIRED_UNSHARE_FLAGS) != 0:
        error = ctypes.get_errno()
        raise LauncherError("required namespace isolation is unavailable") from OSError(
            error,
            os.strerror(error),
        )
    after = _namespace_links()
    if any(after[name] == before[name] for name in EXPECTED_NAMESPACES):
        raise LauncherError("one or more required namespaces were not replaced")
    hostname = b"catchplate-attestation"
    if LIBC.sethostname(hostname, len(hostname)) != 0:
        error = ctypes.get_errno()
        raise LauncherError("sandbox UTS identity could not be set") from OSError(
            error,
            os.strerror(error),
        )
    _assert_loopback_down()
    return after


def _assert_loopback_down() -> None:
    connection = socket.socket(
        socket.AF_INET,
        socket.SOCK_DGRAM | getattr(socket, "SOCK_CLOEXEC", 0),
    )
    try:
        request = struct.pack("16sH14x", b"lo", 0)
        response = fcntl.ioctl(connection.fileno(), 0x8913, request)
        flags = struct.unpack("16sH14x", response)[1]
    except OSError as exc:
        raise LauncherError("sandbox loopback state is unavailable") from exc
    finally:
        connection.close()
    if flags & 0x1:
        raise LauncherError("sandbox loopback interface is up")


def _prepare_root_filesystem(
    policy: ValidatedDescriptor,
    root_descriptor: int,
) -> tuple[int, os.stat_result]:
    metadata = os.fstat(root_descriptor)
    _assert_stat_identity(
        metadata,
        policy.root_identity,
        label="sandbox root directory",
        kind="directory",
    )
    _assert_fd_path(
        root_descriptor,
        policy.root_path,
        label="sandbox root directory",
    )
    try:
        if os.listdir(root_descriptor):
            raise LauncherError("sandbox root directory is not empty")
    except OSError as exc:
        raise LauncherError("sandbox root directory is unavailable") from exc
    _mount(None, "/", None, MS_REC | MS_PRIVATE, None)
    root_mount_target = f"/proc/self/fd/{root_descriptor}"
    _mount(
        "tmpfs",
        root_mount_target,
        "tmpfs",
        MS_NOSUID | MS_NODEV | MS_NOEXEC,
        f"size={policy.root_max_bytes},mode=0755",
    )
    _mount_setattr_recursive(
        root_mount_target,
        architecture=policy.architecture,
    )
    new_root_descriptor = os.open(
        root_mount_target,
        os.O_RDONLY
        | os.O_DIRECTORY
        | os.O_CLOEXEC
        | getattr(os, "O_NOFOLLOW", 0),
    )
    new_root_metadata = os.fstat(new_root_descriptor)
    if (
        not stat.S_ISDIR(new_root_metadata.st_mode)
        or new_root_metadata.st_uid != 0
        or stat.S_IMODE(new_root_metadata.st_mode) & 0o022
    ):
        os.close(new_root_descriptor)
        raise LauncherError("mounted sandbox root identity is invalid")
    return new_root_descriptor, new_root_metadata


def _inotify_limit_watch(cgroup_descriptor: int) -> tuple[int, dict[int, str]]:
    descriptor = LIBC.inotify_init1(IN_NONBLOCK | IN_CLOEXEC)
    if descriptor < 0:
        error = ctypes.get_errno()
        raise LauncherError("cgroup limit mutation watch is unavailable") from OSError(
            error,
            os.strerror(error),
        )
    watches: dict[int, str] = {}
    try:
        cgroup_watch = LIBC.inotify_add_watch(
            descriptor,
            f"/proc/self/fd/{cgroup_descriptor}".encode("ascii"),
            IN_ATTRIB | IN_DELETE_SELF | IN_MOVE_SELF | IN_IGNORED,
        )
        if cgroup_watch < 0:
            error = ctypes.get_errno()
            raise LauncherError(
                "cgroup identity mutation watch could not be installed"
            ) from OSError(error, os.strerror(error))
        watches[cgroup_watch] = "cgroup-directory"
        for name in LIMIT_FILE_NAMES:
            path = f"/proc/self/fd/{cgroup_descriptor}/{name}".encode("ascii")
            watch = LIBC.inotify_add_watch(
                descriptor,
                path,
                LIMIT_WATCH_MASK,
            )
            if watch < 0 or watch in watches:
                error = ctypes.get_errno()
                raise LauncherError(
                    "cgroup limit mutation watch could not be installed"
                ) from OSError(error, os.strerror(error))
            watches[watch] = name
        return descriptor, watches
    except Exception:
        os.close(descriptor)
        raise


def _consume_limit_watch(
    descriptor: int,
    watches: dict[int, str],
) -> None:
    saw_event = False
    while True:
        try:
            raw = os.read(descriptor, 64 * 1024)
        except BlockingIOError:
            break
        if not raw:
            raise LauncherError("cgroup limit mutation watch closed")
        offset = 0
        while offset < len(raw):
            if len(raw) - offset < 16:
                raise LauncherError("cgroup limit mutation event is malformed")
            watch, mask, _cookie, name_length = struct.unpack_from(
                "iIII",
                raw,
                offset,
            )
            event_length = 16 + name_length
            if event_length > len(raw) - offset:
                raise LauncherError("cgroup limit mutation event is truncated")
            if watch not in watches or mask & LIMIT_WATCH_MASK == 0:
                raise LauncherError("cgroup limit mutation event is invalid")
            saw_event = True
            offset += event_length
    if saw_event:
        raise LauncherError("a cgroup limit changed after sandbox admission")


def _proc_read(
    proc_descriptor: int,
    relative_path: str,
    *,
    maximum: int,
    label: str,
) -> str:
    if (
        not relative_path
        or relative_path.startswith("/")
        or "\x00" in relative_path
        or any(part in {"", ".", ".."} for part in relative_path.split("/"))
    ):
        raise LauncherError(f"{label} proc path is invalid")
    descriptor = os.open(
        relative_path,
        os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
        dir_fd=proc_descriptor,
    )
    try:
        raw = _read_open_fd_bounded(
            descriptor,
            maximum=maximum,
            label=label,
        )
    finally:
        os.close(descriptor)
    try:
        return raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise LauncherError(f"{label} is not ASCII") from exc


def _proc_namespace(
    proc_descriptor: int,
    process_id: int,
    name: str,
) -> str:
    try:
        value = os.readlink(
            f"{process_id}/ns/{name}",
            dir_fd=proc_descriptor,
        )
    except OSError as exc:
        raise LauncherError("process namespace identity is unavailable") from exc
    if not value.startswith(f"{name}:[") or not value.endswith("]"):
        raise LauncherError("process namespace identity is malformed")
    return value


def _parse_proc_status(raw: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in raw.splitlines():
        if ":\t" not in line:
            continue
        name, value = line.split(":\t", 1)
        if name in fields:
            raise LauncherError("process status contains a duplicate field")
        fields[name] = value.strip()
    return fields


def _assert_process_status(
    proc_descriptor: int,
    process_id: int,
    policy: ValidatedDescriptor,
) -> dict[str, str]:
    status = _parse_proc_status(
        _proc_read(
            proc_descriptor,
            f"{process_id}/status",
            maximum=MAX_PROC_FILE_BYTES,
            label="process status",
        )
    )
    uid_fields = status.get("Uid", "").split()
    gid_fields = status.get("Gid", "").split()
    if (
        uid_fields != [str(policy.uid)] * 4
        or gid_fields != [str(policy.gid)] * 4
        or status.get("Groups", "") != ""
        or status.get("NoNewPrivs") != "1"
        or status.get("Seccomp") != "2"
    ):
        raise LauncherError("producer identity or kernel restrictions drifted")
    for field in CAPABILITY_STATUS_FIELDS:
        raw_value = status.get(field)
        if (
            raw_value is None
            or re.fullmatch(r"[0-9A-Fa-f]{16}", raw_value) is None
            or int(raw_value, 16) != 0
        ):
            raise LauncherError("producer capability sets are not empty")
    return status


def _assert_process_namespaces(
    proc_descriptor: int,
    process_id: int,
    expected_namespaces: dict[str, str],
) -> None:
    for logical, proc_name in NAMESPACE_PROC_NAMES.items():
        if (
            _proc_namespace(proc_descriptor, process_id, proc_name)
            != expected_namespaces[logical]
        ):
            raise LauncherError("producer namespace identity drifted")


def _process_cgroup_membership(
    proc_descriptor: int,
    process_id: int,
) -> str:
    raw = _proc_read(
        proc_descriptor,
        f"{process_id}/cgroup",
        maximum=4096,
        label="process cgroup membership",
    )
    lines = raw.splitlines()
    if len(lines) != 1 or not lines[0].startswith("0::"):
        raise LauncherError("process does not have one cgroup-v2 membership")
    return lines[0][3:]


def _process_children(
    proc_descriptor: int,
    process_id: int,
) -> tuple[int, ...]:
    raw = _proc_read(
        proc_descriptor,
        f"{process_id}/task/{process_id}/children",
        maximum=MAX_PROC_FILE_BYTES,
        label="process children",
    ).strip()
    if not raw:
        return ()
    result: list[int] = []
    for value in raw.split():
        if not value.isdigit() or int(value, 10) < 1:
            raise LauncherError("process child list is malformed")
        result.append(int(value, 10))
    if len(result) != len(set(result)):
        raise LauncherError("process child list contains a duplicate")
    return tuple(result)


def _descendant_tree(
    proc_descriptor: int,
    namespace_init_pid: int,
    *,
    maximum: int,
) -> set[int]:
    discovered: set[int] = set()
    pending = [namespace_init_pid]
    while pending:
        process_id = pending.pop()
        if process_id in discovered:
            raise LauncherError("producer process tree contains a cycle")
        discovered.add(process_id)
        if len(discovered) > maximum:
            raise LauncherError("producer process tree exceeds pids.max")
        pending.extend(_process_children(proc_descriptor, process_id))
    return discovered


def _process_start_time_ticks(
    proc_descriptor: int,
    process_id: int,
) -> int:
    raw = _proc_read(
        proc_descriptor,
        f"{process_id}/stat",
        maximum=MAX_PROC_FILE_BYTES,
        label="process stable identity",
    )
    closing = raw.rfind(")")
    if closing < 2 or closing + 2 >= len(raw):
        raise LauncherError("process stable identity is malformed")
    fields = raw[closing + 2 :].split()
    if len(fields) < 20 or not fields[19].isdigit():
        raise LauncherError("process stable identity has no start time")
    return int(fields[19], 10)


def _pin_observed_process_identity(
    proc_descriptor: int,
    process_id: int,
) -> ObservedProcessIdentity:
    pidfd_open = getattr(os, "pidfd_open", None)
    if pidfd_open is None:
        raise LauncherError("producer descendant pidfd pinning is unavailable")
    before = _process_start_time_ticks(proc_descriptor, process_id)
    try:
        pidfd = pidfd_open(process_id, 0)
    except OSError as exc:
        raise LauncherError("producer descendant pidfd could not be retained") from exc
    try:
        after = _process_start_time_ticks(proc_descriptor, process_id)
        if before != after or _pidfd_exited(pidfd):
            raise LauncherError("producer descendant changed during pidfd pinning")
        return ObservedProcessIdentity(
            pid=process_id,
            pidfd=pidfd,
            start_time_ticks=after,
        )
    except BaseException:
        os.close(pidfd)
        raise


def _retain_tree_process_identities(
    proc_descriptor: int,
    tree: set[int],
    observed: list[ObservedProcessIdentity],
) -> None:
    for process_id in sorted(tree):
        start_time = _process_start_time_ticks(proc_descriptor, process_id)
        prior = [
            identity for identity in observed if identity.pid == process_id
        ]
        if any(
            identity.start_time_ticks != start_time
            for identity in prior
        ):
            raise LauncherError("producer descendant PID identity was reused")
        if not prior:
            observed.append(
                _pin_observed_process_identity(proc_descriptor, process_id)
            )
        elif len(prior) != 1 or _pidfd_exited(prior[0].pidfd):
            raise LauncherError("producer descendant PID identity was reused")


def _thread_group_id(status: dict[str, str]) -> int:
    raw = status.get("Tgid")
    if raw is None or not raw.isdigit() or int(raw, 10) < 1:
        raise LauncherError("thread status has no valid thread group")
    return int(raw, 10)


def _assert_mount_contract(
    proc_descriptor: int,
    process_id: int,
    policy: ValidatedDescriptor,
    root_metadata: os.stat_result,
) -> None:
    try:
        process_root = os.stat(
            f"{process_id}/root",
            dir_fd=proc_descriptor,
            follow_symlinks=True,
        )
    except OSError as exc:
        raise LauncherError("producer root identity is unavailable") from exc
    if (
        process_root.st_dev != root_metadata.st_dev
        or process_root.st_ino != root_metadata.st_ino
    ):
        raise LauncherError("producer root differs from the mounted sandbox root")
    raw = _proc_read(
        proc_descriptor,
        f"{process_id}/mountinfo",
        maximum=MAX_PROC_FILE_BYTES,
        label="producer mount table",
    )
    expected_mounts = {"/"}
    observed: dict[str, tuple[set[str], str, set[str]]] = {}
    for line in raw.splitlines():
        fields = line.split()
        if " - " not in line or len(fields) < 10:
            raise LauncherError("producer mount table is malformed")
        separator = fields.index("-")
        if separator < 6 or len(fields) <= separator + 3:
            raise LauncherError("producer mount table is malformed")
        mount_point = fields[4]
        if "\\" in mount_point or mount_point in observed:
            raise LauncherError("producer mount path is not canonical")
        mount_options = set(fields[5].split(","))
        filesystem_type = fields[separator + 1]
        super_options = set(fields[separator + 3].split(","))
        observed[mount_point] = (
            mount_options,
            filesystem_type,
            super_options,
        )
    if set(observed) != expected_mounts:
        raise LauncherError("producer sees an unexpected filesystem mount")
    for mount_point, (mount_options, filesystem_type, _super_options) in observed.items():
        if (
            not {"ro", "nosuid", "nodev", "noexec"}.issubset(mount_options)
            or (mount_point == "/" and filesystem_type != "tmpfs")
        ):
            raise LauncherError("producer filesystem mount restrictions drifted")


def _assert_tree_contained(
    policy: ValidatedDescriptor,
    *,
    namespace_init_pid: int,
    cgroup_descriptor: int,
    proc_descriptor: int,
    expected_namespaces: dict[str, str],
    root_metadata: os.stat_result,
    observed_identities: list[ObservedProcessIdentity],
) -> None:
    _assert_cgroup_limits(policy, cgroup_descriptor)
    tree = _descendant_tree(
        proc_descriptor,
        namespace_init_pid,
        maximum=policy.cgroup_limits["pidsMax"],
    )
    cgroup_processes = _cgroup_processes(cgroup_descriptor)
    if tree != cgroup_processes:
        raise LauncherError("a producer descendant crossed the exact cgroup")
    _retain_tree_process_identities(
        proc_descriptor,
        tree,
        observed_identities,
    )
    if not tree or not _cgroup_populated(cgroup_descriptor):
        raise LauncherError("producer cgroup is not populated")
    thread_ids = _cgroup_threads(cgroup_descriptor)
    if not thread_ids:
        raise LauncherError("producer cgroup has no threads")
    process_statuses: dict[int, dict[str, str]] = {}
    for process_id in sorted(tree):
        if (
            _process_cgroup_membership(proc_descriptor, process_id)
            != policy.cgroup_membership_path
        ):
            raise LauncherError("producer cgroup membership path drifted")
        process_statuses[process_id] = _assert_process_status(
            proc_descriptor,
            process_id,
            policy,
        )
        _assert_process_namespaces(
            proc_descriptor,
            process_id,
            expected_namespaces,
        )
        try:
            if (
                os.getsid(process_id) != namespace_init_pid
                or os.getpgid(process_id) != namespace_init_pid
            ):
                raise LauncherError(
                    "producer descendant escaped its session or process group"
                )
        except ProcessLookupError as exc:
            raise LauncherError("producer process disappeared during proof") from exc
    for thread_id in sorted(thread_ids):
        status = _parse_proc_status(
            _proc_read(
                proc_descriptor,
                f"{thread_id}/status",
                maximum=MAX_PROC_FILE_BYTES,
                label="producer thread status",
            )
        )
        if _thread_group_id(status) not in tree:
            raise LauncherError("a producer thread crossed the process tree")
    _assert_mount_contract(
        proc_descriptor,
        namespace_init_pid,
        policy,
        root_metadata,
    )


def _close_all_except(keep: set[int]) -> None:
    if any(type(descriptor) is not int or descriptor < 0 for descriptor in keep):
        raise LauncherError("internal descriptor allowlist is invalid")
    soft_limit, _hard_limit = resource.getrlimit(resource.RLIMIT_NOFILE)
    if (
        type(soft_limit) is not int
        or soft_limit == resource.RLIM_INFINITY
        or not 64 <= soft_limit <= MAX_SAFE_FD
    ):
        raise LauncherError("kernel descriptor bound is invalid")
    upper_bound = soft_limit
    start = 0
    for descriptor in sorted(keep):
        if start < descriptor:
            os.closerange(start, descriptor)
        start = descriptor + 1
    if start < upper_bound:
        os.closerange(start, upper_bound)


def _drop_all_capabilities() -> None:
    raw = _read_path_bounded(
        "/proc/sys/kernel/cap_last_cap",
        maximum=64,
        label="kernel capability bound",
    ).decode("ascii").strip()
    if not raw.isdigit() or not 0 <= int(raw, 10) <= 63:
        raise LauncherError("kernel capability bound is invalid")
    for capability in range(int(raw, 10) + 1):
        _prctl(PR_CAPBSET_DROP, capability)
    _prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL)


def _move_self_to_cgroup(cgroup_descriptor: int) -> None:
    _write_cgroup_file(cgroup_descriptor, "cgroup.procs", "0")


def _duplicate_sources(
    source_to_target: dict[int, int],
) -> dict[int, int]:
    duplicates: dict[int, int] = {}
    for source in sorted(source_to_target):
        try:
            duplicate = fcntl.fcntl(
                source,
                fcntl.F_DUPFD_CLOEXEC,
                128,
            )
        except OSError as exc:
            raise LauncherError("producer FD snapshot failed") from exc
        duplicates[duplicate] = source_to_target[source]
    return duplicates


def _child_exec(
    policy: ValidatedDescriptor,
    *,
    parent_pid: int,
    cgroup_descriptor: int,
    new_root_descriptor: int,
    seccomp_program: bytes,
    executable_descriptor: int,
    config_descriptor: int,
    named_descriptors: dict[str, int],
    prepared_descriptor: int,
    gate_descriptor: int,
) -> None:
    try:
        _prctl(PR_SET_PDEATHSIG, signal.SIGKILL)
        if os.getppid() != parent_pid:
            raise LauncherError("launcher parent changed before containment")
        os.setsid()
        if os.getsid(0) != os.getpid() or os.getpgrp() != os.getpid():
            raise LauncherError("producer did not become its session leader")
        _move_self_to_cgroup(cgroup_descriptor)
        _drop_all_capabilities()
        os.fchdir(new_root_descriptor)
        os.chroot(".")
        os.chdir("/")
        os.umask(0o077)
        os.setgroups([])
        os.setresgid(policy.gid, policy.gid, policy.gid)
        os.setresuid(policy.uid, policy.uid, policy.uid)
        _prctl(PR_SET_NO_NEW_PRIVS, 1)

        os.lseek(0, 0, os.SEEK_SET)
        os.lseek(config_descriptor, 0, os.SEEK_SET)
        for rule in policy.named_fd_rules:
            if rule.kind in {
                "sealed-ephemeral-secret",
                "sealed-measurement-copy",
                "sealed-regular-file",
                "sealed-release-bound-file",
            }:
                os.lseek(
                    named_descriptors[rule.role],
                    0,
                    os.SEEK_SET,
                )
        source_to_target = {
            0: 0,
            1: 1,
            config_descriptor: policy.config_target_fd,
        }
        for rule in policy.named_fd_rules:
            source_to_target[named_descriptors[rule.role]] = rule.target_fd
        duplicates = _duplicate_sources(source_to_target)
        os.dup2(
            executable_descriptor,
            FIXED_PRODUCER_EXECUTABLE_FD,
            inheritable=True,
        )
        prepared_copy = fcntl.fcntl(
            prepared_descriptor,
            fcntl.F_DUPFD_CLOEXEC,
            128,
        )
        gate_copy = fcntl.fcntl(
            gate_descriptor,
            fcntl.F_DUPFD_CLOEXEC,
            128,
        )
        for duplicate, target in sorted(
            duplicates.items(),
            key=lambda item: item[1],
        ):
            os.dup2(duplicate, target, inheritable=True)
        for duplicate in duplicates:
            os.close(duplicate)
        keep = (
            {
                0,
                1,
                FIXED_PRODUCER_EXECUTABLE_FD,
                prepared_copy,
                gate_copy,
            }
            | {policy.config_target_fd}
            | {rule.target_fd for rule in policy.named_fd_rules}
        )
        _close_all_except(keep)
        _apply_seccomp(
            seccomp_program,
            architecture=policy.architecture,
        )
        if os.write(prepared_copy, CHILD_PREPARED) != len(CHILD_PREPARED):
            raise LauncherError("producer preparation token was truncated")
        if os.read(gate_copy, 2) != CHILD_GO:
            raise LauncherError("producer execution gate was invalid")
        os.close(prepared_copy)
        os.close(gate_copy)
        if os.execve not in os.supports_fd:
            raise LauncherError("descriptor execution is unavailable")
        os.execve(
            FIXED_PRODUCER_EXECUTABLE_FD,
            list(policy.executable_argv),
            dict(policy.executable_environment),
        )
    except BaseException:
        os._exit(126)


def _write_all(descriptor: int, raw: bytes, *, label: str) -> None:
    offset = 0
    while offset < len(raw):
        try:
            written = os.write(descriptor, raw[offset:])
        except OSError as exc:
            raise LauncherError(f"{label} could not be written") from exc
        if written < 1:
            raise LauncherError(f"{label} accepted a short write")
        offset += written


def _read_exact_before(
    descriptor: int,
    expected: bytes,
    *,
    deadline: float,
    command_deadline: float,
    label: str,
    owner_liveness_descriptor: int,
) -> None:
    poller = select.poll()
    poller.register(descriptor, select.POLLIN | select.POLLHUP | select.POLLERR)
    poller.register(
        owner_liveness_descriptor,
        select.POLLIN
        | select.POLLERR
        | select.POLLHUP
        | select.POLLNVAL,
    )
    received = bytearray()
    while len(received) < len(expected):
        _assert_owner_alive(
            owner_liveness_descriptor,
            command_deadline=command_deadline,
        )
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise LauncherError(f"{label} timed out")
        events = poller.poll(max(1, int(remaining * 1000)))
        if not events:
            continue
        if any(
            event_descriptor == owner_liveness_descriptor
            for event_descriptor, _event in events
        ):
            _assert_owner_alive(
                owner_liveness_descriptor,
                command_deadline=command_deadline,
            )
        if any(event & select.POLLERR for _, event in events):
            raise LauncherError(f"{label} failed")
        chunk = os.read(descriptor, len(expected) + 1 - len(received))
        if not chunk:
            raise LauncherError(f"{label} closed early")
        received.extend(chunk)
        if len(received) > len(expected) or not expected.startswith(received):
            raise LauncherError(f"{label} is invalid")
    if bytes(received) != expected:
        raise LauncherError(f"{label} is invalid")


def _validate_owner_liveness_descriptor(descriptor: int) -> None:
    _require_fd_access(
        descriptor,
        "read-write",
        label="owner-liveness FD",
    )
    duplicate = os.dup(descriptor)
    connection: socket.socket | None = None
    try:
        connection = socket.socket(fileno=duplicate)
        duplicate = -1
        if (
            connection.family != socket.AF_UNIX
            or connection.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE)
            != socket.SOCK_SEQPACKET
        ):
            raise LauncherError(
                "owner-liveness FD is not a connected Unix seqpacket endpoint"
            )
        connection.getpeername()
        connection.setblocking(False)
        try:
            pending = connection.recv(1, socket.MSG_PEEK)
        except BlockingIOError:
            pending = None
        if pending is not None:
            raise LauncherError(
                "owner-liveness FD is closed or contains an unexpected payload"
            )
    finally:
        if connection is not None:
            connection.close()
        if duplicate >= 0:
            os.close(duplicate)


def _assert_owner_alive(
    descriptor: int,
    *,
    command_deadline: float,
) -> None:
    if time.monotonic() >= command_deadline:
        raise LauncherError("absolute producer command deadline expired")
    poller = select.poll()
    poller.register(
        descriptor,
        select.POLLIN
        | select.POLLERR
        | select.POLLHUP
        | select.POLLNVAL,
    )
    events = poller.poll(0)
    if not events:
        return
    duplicate = os.dup(descriptor)
    connection: socket.socket | None = None
    try:
        connection = socket.socket(fileno=duplicate)
        duplicate = -1
        connection.setblocking(False)
        try:
            payload = connection.recv(1)
        except BlockingIOError:
            payload = None
    finally:
        if connection is not None:
            connection.close()
        if duplicate >= 0:
            os.close(duplicate)
    if payload:
        raise LauncherError("owner-liveness channel carried an invalid payload")
    raise LauncherError("control-plane owner liveness was lost")


def _waitpid_nonblocking(process_id: int) -> tuple[bool, int]:
    try:
        waited_pid, status_value = os.waitpid(process_id, os.WNOHANG)
    except ChildProcessError:
        return True, 0
    if waited_pid == 0:
        return False, 0
    if waited_pid != process_id:
        raise LauncherError("waitpid returned an unrelated child")
    return True, status_value


def _child_exit_is_waitable(process_id: int) -> bool:
    try:
        result = os.waitid(
            os.P_PID,
            process_id,
            os.WEXITED | os.WNOHANG | os.WNOWAIT,
        )
    except ChildProcessError:
        raise LauncherError("producer was reaped outside the launcher")
    return result is not None


def _exit_code(status_value: int) -> int:
    if os.WIFEXITED(status_value):
        return os.WEXITSTATUS(status_value)
    if os.WIFSIGNALED(status_value):
        return 128 + os.WTERMSIG(status_value)
    raise LauncherError("producer returned an unsupported wait status")


def _kill_and_reap_tree(
    *,
    namespace_init_pid: int,
    namespace_init_pidfd: int,
    cgroup_descriptor: int,
    observed_identities: list[ObservedProcessIdentity],
    timeout_seconds: float,
) -> tuple[bool, int]:
    reaped = False
    wait_status = 0
    pidfd_send_signal = getattr(signal, "pidfd_send_signal", None)
    if pidfd_send_signal is None:
        raise LauncherError("producer pidfd signaling is unavailable")
    try:
        pidfd_send_signal(
            namespace_init_pidfd,
            signal.SIGKILL,
            None,
            0,
        )
    except ProcessLookupError:
        pass
    try:
        if _cgroup_populated(cgroup_descriptor):
            _kill_cgroup(cgroup_descriptor)
    except LauncherError:
        raise
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if not reaped:
            reaped, observed_status = _waitpid_nonblocking(namespace_init_pid)
            if reaped:
                wait_status = observed_status
        populated = _cgroup_populated(cgroup_descriptor)
        processes = _cgroup_processes(cgroup_descriptor)
        threads = _cgroup_threads(cgroup_descriptor)
        survivors = any(
            not _pidfd_exited(identity.pidfd)
            for identity in observed_identities
        )
        if reaped and not populated and not processes and not threads and not survivors:
            return reaped, wait_status
        if populated:
            _kill_cgroup(cgroup_descriptor)
        time.sleep(0.005)
    raise LauncherError("producer tree could not be killed and reaped")


def _kill_cgroup_and_reap_unpinned_direct_child(
    *,
    namespace_init_pid: int,
    cgroup_descriptor: int,
    timeout_seconds: float,
) -> None:
    _kill_cgroup(cgroup_descriptor)
    deadline = time.monotonic() + timeout_seconds
    reaped = False
    while time.monotonic() < deadline:
        if not reaped:
            reaped, _status = _waitpid_nonblocking(namespace_init_pid)
        if (
            reaped
            and not _cgroup_populated(cgroup_descriptor)
            and not _cgroup_processes(cgroup_descriptor)
            and not _cgroup_threads(cgroup_descriptor)
        ):
            return
        if _cgroup_populated(cgroup_descriptor):
            _kill_cgroup(cgroup_descriptor)
        time.sleep(0.005)
    raise LauncherError(
        "un-pidfd-pinned direct child could not be killed by retained cgroup "
        "identity and reaped"
    )


def _monitor_producer(
    policy: ValidatedDescriptor,
    *,
    namespace_init_pid: int,
    cgroup_descriptor: int,
    proc_descriptor: int,
    expected_namespaces: dict[str, str],
    root_metadata: os.stat_result,
    inotify_descriptor: int,
    inotify_watches: dict[int, str],
    service_exec_guards: list[ServiceExecGuard],
    service_peer_states: list[ServicePeerState],
    rules_by_role: dict[str, NamedFdRule],
    owner_liveness_descriptor: int,
    command_deadline: float,
    observed_identities: list[ObservedProcessIdentity],
) -> None:
    poller = select.poll()
    poller.register(
        inotify_descriptor,
        select.POLLIN | select.POLLERR | select.POLLHUP,
    )
    poller.register(
        owner_liveness_descriptor,
        select.POLLIN
        | select.POLLERR
        | select.POLLHUP
        | select.POLLNVAL,
    )
    while True:
        _assert_owner_alive(
            owner_liveness_descriptor,
            command_deadline=command_deadline,
        )
        _assert_service_exec_guards_quiet(service_exec_guards)
        if service_exec_guards:
            _assert_exact_service_cgroups(service_peer_states)
            for state in service_peer_states:
                _revalidate_service_peer(
                    state,
                    rules_by_role[state.role],
                    proc_descriptor=proc_descriptor,
                )
        if _child_exit_is_waitable(namespace_init_pid):
            _consume_limit_watch(inotify_descriptor, inotify_watches)
            _assert_cgroup_limits(policy, cgroup_descriptor)
            _assert_service_exec_guards_quiet(service_exec_guards)
            if service_exec_guards:
                _assert_exact_service_cgroups(service_peer_states)
                for state in service_peer_states:
                    _revalidate_service_peer(
                        state,
                        rules_by_role[state.role],
                        proc_descriptor=proc_descriptor,
                    )
            return
        remaining = command_deadline - time.monotonic()
        if remaining <= 0:
            raise LauncherError("absolute producer command deadline expired")
        events = poller.poll(
            max(1, int(min(policy.poll_seconds, remaining) * 1000))
        )
        if any(
            descriptor == owner_liveness_descriptor
            for descriptor, _event in events
        ):
            _assert_owner_alive(
                owner_liveness_descriptor,
                command_deadline=command_deadline,
            )
        if any(
            descriptor == inotify_descriptor
            and event & (select.POLLERR | select.POLLHUP)
            for descriptor, event in events
        ):
            raise LauncherError("cgroup limit mutation watch failed")
        _consume_limit_watch(inotify_descriptor, inotify_watches)
        _assert_tree_contained(
            policy,
            namespace_init_pid=namespace_init_pid,
            cgroup_descriptor=cgroup_descriptor,
            proc_descriptor=proc_descriptor,
            expected_namespaces=expected_namespaces,
            root_metadata=root_metadata,
            observed_identities=observed_identities,
        )


def _parse_arguments(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Launch one public-attestation producer in the measured sandbox-v2 "
            "boundary."
        ),
        allow_abbrev=False,
    )
    for option in (
        "sandbox-descriptor-fd",
        "producer-executable-fd",
        "immutable-config-fd",
        "cgroup-fd",
        "seccomp-profile-fd",
        "sandbox-root-fd",
        "ready-fd",
        "owner-liveness-fd",
        "command-deadline-monotonic-ns",
        "expected-stable-statement-sha256",
    ):
        parser.add_argument(
            f"--{option}",
            action=StoreOnce,
            required=True,
        )
    parser.add_argument(
        "--producer-fd",
        action=AppendUnique,
        default=[],
    )
    parser.add_argument(
        "--fixture-non-production",
        action="store_true",
        help=(
            "Require fixture-non-production in the descriptor and emit only "
            "the non-production readiness token."
        ),
    )
    return parser.parse_args(argv)


def _role_fd_map(values: list[str], *, label: str) -> dict[str, int]:
    result: dict[str, int] = {}
    for value in values:
        role, descriptor = _parse_role_fd(value, label=label)
        if role in result:
            raise LauncherError(f"{label} contains a duplicate role")
        result[role] = descriptor
    return result


def _assert_runtime_platform(
    architecture: str,
    *,
    fixture_mode: bool,
) -> bytes | None:
    if sys.platform != "linux" or os.geteuid() != 0:
        raise LauncherError("production sandboxing requires Linux root")
    machine = platform.machine().lower()
    normalized = {"amd64": "x86_64", "arm64": "aarch64"}.get(machine, machine)
    if normalized != architecture:
        raise LauncherError("runtime architecture differs from the descriptor")
    if (
        os.getsid(0) != os.getpid()
        or os.getpgrp() != os.getpid()
    ):
        raise LauncherError("launcher was not started as a session leader")
    if os.execve not in os.supports_fd:
        raise LauncherError("kernel-backed descriptor execution is unavailable")
    if not fixture_mode:
        return _assert_frozen_launcher_boundary(architecture)
    return None


def _assert_production_external_prerequisites(*, fixture_mode: bool) -> None:
    if fixture_mode:
        return
    raise LauncherError(
        "production is unavailable until the measured static producer entry stub "
        "installs the exact pinned runtime seccomp profile before application "
        "code, every measured static service peer has its signed post-exec filter "
        "identity externally attested, the measured static launcher brokers every "
        "service frame with SCM_CREDENTIALS while withholding external service "
        "endpoints from the producer, and the supervisor supplies a private "
        "read-only cgroup namespace "
        f"({PRODUCTION_POST_EXEC_PREREQUISITE})"
    )


def _main(argv: list[str]) -> int:
    arguments = _parse_arguments(argv)
    expected_stable_statement_sha256 = _digest(
        arguments.expected_stable_statement_sha256,
        label="independently expected stable release statement",
    )
    fixed_descriptors = {
        "sandboxDescriptor": _parse_fd(
            arguments.sandbox_descriptor_fd,
            label="sandbox descriptor FD",
        ),
        "producerExecutable": _parse_fd(
            arguments.producer_executable_fd,
            label="producer executable FD",
        ),
        "immutableConfig": _parse_fd(
            arguments.immutable_config_fd,
            label="immutable configuration FD",
        ),
        "cgroup": _parse_fd(arguments.cgroup_fd, label="cgroup FD"),
        "seccompProfile": _parse_fd(
            arguments.seccomp_profile_fd,
            label="seccomp profile FD",
        ),
        "sandboxRoot": _parse_fd(
            arguments.sandbox_root_fd,
            label="sandbox root FD",
        ),
        "ready": _parse_fd(arguments.ready_fd, label="readiness FD"),
        "ownerLiveness": _parse_fd(
            arguments.owner_liveness_fd,
            label="owner-liveness FD",
        ),
    }
    named_descriptors = _role_fd_map(
        list(arguments.producer_fd),
        label="named producer FD",
    )
    all_descriptors = dict(fixed_descriptors)
    for role, descriptor in named_descriptors.items():
        all_descriptors[f"producer:{role}"] = descriptor
    _assert_unique_descriptors(all_descriptors)
    _require_fd_access(0, "read-only", label="launcher stdin")
    _require_fd_access(1, "write-only", label="launcher stdout")
    _require_fd_access(
        fixed_descriptors["ready"],
        "write-only",
        label="readiness FD",
    )
    _validate_owner_liveness_descriptor(fixed_descriptors["ownerLiveness"])

    descriptor_raw = _read_regular_fd(
        fixed_descriptors["sandboxDescriptor"],
        label="sandbox descriptor",
        maximum=MAX_DESCRIPTOR_BYTES,
        require_seals=True,
    )
    descriptor_document = _load_canonical_document(
        descriptor_raw,
        label="sandbox descriptor",
    )
    policy = _validate_descriptor(
        descriptor_document,
        fixture_mode=bool(arguments.fixture_non_production),
    )
    raw_command_deadline = arguments.command_deadline_monotonic_ns
    if (
        not isinstance(raw_command_deadline, str)
        or not raw_command_deadline.isdigit()
        or len(raw_command_deadline) > 24
    ):
        raise LauncherError("absolute command deadline is invalid")
    command_deadline = int(raw_command_deadline, 10) / 1_000_000_000
    now = time.monotonic()
    if (
        command_deadline <= now
        or command_deadline - now > policy.command_timeout_seconds
    ):
        raise LauncherError(
            "absolute command deadline is expired or exceeds the signed bound"
        )
    _assert_owner_alive(
        fixed_descriptors["ownerLiveness"],
        command_deadline=command_deadline,
    )
    policy = replace(
        policy,
        executable_argv=(
            *policy.executable_argv,
            "--expected-stable-statement-sha256",
            expected_stable_statement_sha256,
        ),
    )
    launcher_executable_raw = _assert_runtime_platform(
        policy.architecture,
        fixture_mode=bool(arguments.fixture_non_production),
    )
    _assert_production_external_prerequisites(
        fixture_mode=bool(arguments.fixture_non_production)
    )
    request_raw = _read_regular_fd(
        0,
        label="producer request",
        maximum=policy.input_max_bytes,
        require_seals=True,
    )
    if not request_raw:
        raise LauncherError("producer request is empty")
    del request_raw
    if set(named_descriptors) != {
        rule.role for rule in policy.named_fd_rules
    }:
        raise LauncherError("named producer FD roles differ from the descriptor")

    executable_raw = _validate_executable_fd(
        fixed_descriptors["producerExecutable"],
        policy,
    )
    config_raw = _read_regular_fd(
        fixed_descriptors["immutableConfig"],
        label="immutable configuration",
        maximum=policy.config_max_bytes,
        require_seals=True,
    )
    if not config_raw:
        raise LauncherError("immutable configuration is empty")
    _validate_immutable_config_document(
        config_raw,
        policy=policy,
        sandbox_descriptor_raw=descriptor_raw,
    )
    seccomp_program = _read_seccomp_program(
        fixed_descriptors["seccompProfile"],
        policy,
    )
    root_metadata = os.fstat(fixed_descriptors["sandboxRoot"])
    _assert_stat_identity(
        root_metadata,
        policy.root_identity,
        label="sandbox root directory",
        kind="directory",
    )
    proc_descriptor = os.open(
        "/proc",
        os.O_RDONLY
        | os.O_DIRECTORY
        | os.O_CLOEXEC
        | getattr(os, "O_NOFOLLOW", 0),
    )
    if _fstatfs_magic(proc_descriptor) != 0x9FA0:
        os.close(proc_descriptor)
        raise LauncherError("retained process filesystem is not procfs")
    service_peer_states: list[ServicePeerState] = []
    for rule in policy.named_fd_rules:
        _assert_owner_alive(
            fixed_descriptors["ownerLiveness"],
            command_deadline=command_deadline,
        )
        peer_state = _validate_named_fd(
            named_descriptors[rule.role],
            rule,
            measurement_sources={
                "producerExecutable": (
                    fixed_descriptors["producerExecutable"],
                    executable_raw,
                ),
                "sandboxDescriptor": (
                    fixed_descriptors["sandboxDescriptor"],
                    descriptor_raw,
                ),
                **(
                    {
                        "sandboxLauncher": (
                            -1,
                            launcher_executable_raw,
                        )
                    }
                    if launcher_executable_raw is not None
                    else {}
                ),
            },
            proc_descriptor=proc_descriptor,
            architecture=policy.architecture,
            production_mode=policy.execution_mode == "production",
            owner_liveness_descriptor=fixed_descriptors["ownerLiveness"],
            command_deadline=command_deadline,
            timeout_seconds=max(
                0.001,
                min(
                    policy.command_timeout_seconds,
                    command_deadline - time.monotonic(),
                ),
            ),
        )
        if peer_state is not None:
            service_peer_states.append(peer_state)
    stable_statement_rule = next(
        rule
        for rule in policy.named_fd_rules
        if rule.role == "stableReleaseStatement"
    )
    stable_statement_raw = _read_regular_fd(
        named_descriptors["stableReleaseStatement"],
        label="stable release statement",
        maximum=stable_statement_rule.document["maxBytes"],
        require_seals=True,
    )
    if _sha256(stable_statement_raw) != expected_stable_statement_sha256:
        raise LauncherError(
            "stable release statement differs from its independent launch pin"
        )
    service_peers_by_role = {
        state.role: state for state in service_peer_states
    }
    for request_role, response_role in (
        ("nonceRequest", "nonceResponse"),
        ("witnessRequest", "witnessResponse"),
    ):
        request_state = service_peers_by_role[request_role]
        response_state = service_peers_by_role[response_role]
        if (
            request_state.pid != response_state.pid
            or request_state.executable_sha256
            != response_state.executable_sha256
            or request_state.executable_map_closure_sha256
            != response_state.executable_map_closure_sha256
            or request_state.post_exec_profile_sha256
            != response_state.post_exec_profile_sha256
            or request_state.required_seccomp_filter_count
            != response_state.required_seccomp_filter_count
            or request_state.cgroup_ancestor_closure_sha256
            != response_state.cgroup_ancestor_closure_sha256
            or request_state.cgroup_path != response_state.cgroup_path
        ):
            raise LauncherError(
                f"{request_role} and {response_role} do not terminate at one "
                "measured peer"
            )
    child_pid: int | None = None
    child_pidfd: int | None = None
    observed_identities: list[ObservedProcessIdentity] = []
    inotify_descriptor: int | None = None
    inotify_watches: dict[int, str] = {}
    prepared_read: int | None = None
    prepared_write: int | None = None
    gate_read: int | None = None
    gate_write: int | None = None
    new_root_descriptor: int | None = None
    cleanup_complete = False
    service_completion_confirmed = False
    service_exec_guards: list[ServiceExecGuard] = []
    try:
        _assert_owner_alive(
            fixed_descriptors["ownerLiveness"],
            command_deadline=command_deadline,
        )
        _configure_cgroup(policy, fixed_descriptors["cgroup"])
        inotify_descriptor, inotify_watches = _inotify_limit_watch(
            fixed_descriptors["cgroup"]
        )
        _prctl(PR_SET_CHILD_SUBREAPER, 1)
        _assert_owner_alive(
            fixed_descriptors["ownerLiveness"],
            command_deadline=command_deadline,
        )
        expected_namespaces = _unshare_required_namespaces()
        new_root_descriptor, mounted_root_metadata = _prepare_root_filesystem(
            policy,
            fixed_descriptors["sandboxRoot"],
        )
        _assert_owner_alive(
            fixed_descriptors["ownerLiveness"],
            command_deadline=command_deadline,
        )
        prepared_read, prepared_write = os.pipe2(os.O_CLOEXEC)
        gate_read, gate_write = os.pipe2(os.O_CLOEXEC)
        parent_pid = os.getpid()
        child_pid = os.fork()
        if child_pid == 0:
            os.close(prepared_read)
            os.close(gate_write)
            _child_exec(
                policy,
                parent_pid=parent_pid,
                cgroup_descriptor=fixed_descriptors["cgroup"],
                new_root_descriptor=new_root_descriptor,
                seccomp_program=seccomp_program,
                executable_descriptor=fixed_descriptors["producerExecutable"],
                config_descriptor=fixed_descriptors["immutableConfig"],
                named_descriptors=named_descriptors,
                prepared_descriptor=prepared_write,
                gate_descriptor=gate_read,
            )
            os._exit(126)
        pidfd_open = getattr(os, "pidfd_open", None)
        if pidfd_open is None:
            raise LauncherError("producer pidfd lifecycle control is unavailable")
        try:
            child_pidfd = pidfd_open(child_pid, 0)
        except OSError as exc:
            raise LauncherError("producer pidfd could not be retained") from exc
        os.close(prepared_write)
        prepared_write = None
        os.close(gate_read)
        gate_read = None
        _read_exact_before(
            prepared_read,
            CHILD_PREPARED,
            deadline=min(
                command_deadline,
                time.monotonic() + policy.startup_timeout_seconds,
            ),
            command_deadline=command_deadline,
            label="sandbox child preparation",
            owner_liveness_descriptor=fixed_descriptors["ownerLiveness"],
        )
        _assert_tree_contained(
            policy,
            namespace_init_pid=child_pid,
            cgroup_descriptor=fixed_descriptors["cgroup"],
            proc_descriptor=proc_descriptor,
            expected_namespaces=expected_namespaces,
            root_metadata=mounted_root_metadata,
            observed_identities=observed_identities,
        )
        _assert_owner_alive(
            fixed_descriptors["ownerLiveness"],
            command_deadline=command_deadline,
        )
        rules_by_role = {rule.role: rule for rule in policy.named_fd_rules}
        for state in service_peer_states:
            _revalidate_service_peer(
                state,
                rules_by_role[state.role],
                proc_descriptor=proc_descriptor,
            )
        if not arguments.fixture_non_production:
            service_exec_guards = _start_service_exec_guards(
                service_peer_states,
                rules_by_role=rules_by_role,
                proc_descriptor=proc_descriptor,
                owner_liveness_descriptor=fixed_descriptors["ownerLiveness"],
                command_deadline=command_deadline,
            )
            for state in service_peer_states:
                _revalidate_service_peer(
                    state,
                    rules_by_role[state.role],
                    proc_descriptor=proc_descriptor,
                )
            _assert_service_exec_guards_quiet(service_exec_guards)
        _consume_limit_watch(inotify_descriptor, inotify_watches)
        _assert_owner_alive(
            fixed_descriptors["ownerLiveness"],
            command_deadline=command_deadline,
        )
        _write_all(
            fixed_descriptors["ready"],
            FIXTURE_READY if arguments.fixture_non_production else PRODUCTION_READY,
            label="sandbox readiness token",
        )
        os.close(fixed_descriptors["ready"])
        del fixed_descriptors["ready"]
        _write_all(gate_write, CHILD_GO, label="producer execution gate")
        os.close(gate_write)
        gate_write = None
        _monitor_producer(
            policy,
            namespace_init_pid=child_pid,
            cgroup_descriptor=fixed_descriptors["cgroup"],
            proc_descriptor=proc_descriptor,
            expected_namespaces=expected_namespaces,
            root_metadata=mounted_root_metadata,
            inotify_descriptor=inotify_descriptor,
            inotify_watches=inotify_watches,
            service_exec_guards=service_exec_guards,
            service_peer_states=service_peer_states,
            rules_by_role=rules_by_role,
            owner_liveness_descriptor=fixed_descriptors["ownerLiveness"],
            command_deadline=command_deadline,
            observed_identities=observed_identities,
        )
        _assert_owner_alive(
            fixed_descriptors["ownerLiveness"],
            command_deadline=command_deadline,
        )
        if service_exec_guards:
            remaining = command_deadline - time.monotonic()
            if remaining <= 0:
                raise LauncherError("absolute producer command deadline expired")
            _finish_service_exec_guards(
                service_exec_guards,
                service_peer_states,
                rules_by_role=rules_by_role,
                proc_descriptor=proc_descriptor,
                timeout_seconds=min(
                    policy.cleanup_timeout_seconds,
                    remaining,
                ),
                owner_liveness_descriptor=fixed_descriptors["ownerLiveness"],
                command_deadline=command_deadline,
            )
        service_completion_confirmed = True
        reaped, cleanup_status = _kill_and_reap_tree(
            namespace_init_pid=child_pid,
            namespace_init_pidfd=child_pidfd,
            cgroup_descriptor=fixed_descriptors["cgroup"],
            observed_identities=observed_identities,
            timeout_seconds=policy.cleanup_timeout_seconds,
        )
        cleanup_complete = True
        if not reaped:
            raise LauncherError("producer namespace init was not reaped")
        _assert_cgroup_limits(policy, fixed_descriptors["cgroup"])
        if (
            _cgroup_populated(fixed_descriptors["cgroup"])
            or _cgroup_processes(fixed_descriptors["cgroup"])
            or _cgroup_threads(fixed_descriptors["cgroup"])
        ):
            raise LauncherError("producer cgroup is not empty at slot release")
        return _exit_code(cleanup_status)
    finally:
        try:
            try:
                if (
                    child_pid is not None
                    and child_pidfd is not None
                    and not cleanup_complete
                ):
                    _kill_and_reap_tree(
                        namespace_init_pid=child_pid,
                        namespace_init_pidfd=child_pidfd,
                        cgroup_descriptor=fixed_descriptors["cgroup"],
                        observed_identities=observed_identities,
                        timeout_seconds=policy.cleanup_timeout_seconds,
                    )
                elif (
                    child_pid is not None
                    and child_pidfd is None
                    and not cleanup_complete
                ):
                    _kill_cgroup_and_reap_unpinned_direct_child(
                        namespace_init_pid=child_pid,
                        cgroup_descriptor=fixed_descriptors["cgroup"],
                        timeout_seconds=policy.cleanup_timeout_seconds,
                    )
            finally:
                if not service_completion_confirmed:
                    for guard in service_exec_guards:
                        guard.violated = True
                _release_service_exec_guards(service_exec_guards)
        finally:
            for descriptor in (
                prepared_read,
                prepared_write,
                gate_read,
                gate_write,
                inotify_descriptor,
                new_root_descriptor,
                proc_descriptor,
                child_pidfd,
            ):
                if descriptor is not None:
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass
            for state in service_peer_states:
                for descriptor in (state.pidfd, state.cgroup_descriptor):
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass
            for identity in observed_identities:
                try:
                    os.close(identity.pidfd)
                except OSError:
                    pass
            for descriptor in set(all_descriptors.values()):
                try:
                    os.close(descriptor)
                except OSError:
                    pass


if __name__ == "__main__":
    try:
        raise SystemExit(_main(sys.argv[1:]))
    except LauncherError as error:
        print(f"public attestation sandbox launcher: {error}", file=sys.stderr)
        raise SystemExit(125)
