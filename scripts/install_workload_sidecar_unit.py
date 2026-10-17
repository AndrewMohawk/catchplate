#!/usr/bin/env python3
"""Emit one offline fixed systemd unit; never install or start a service.

Consumes an already provisioned, independently pinned sidecar configuration
and an existing bind-mounted workload network namespace. This Linux amd64
operator helper checks only installation joins; the Rust service owns the full
closed configuration, upstream admission and ongoing lifetime validation.
The output is exclusive and retained on uncertainty. No secret is copied.
"""
from __future__ import annotations

import argparse
from contextlib import ExitStack
import ctypes
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

MAX_CONFIGURATION = 32768
FIELDS = frozenset(("apiVersion", "profile", "workloadId", "listenPort",
    "localTokenSha256", "allowedDestinations", "namespace", "issuedAtEpochNs",
    "expiresAtEpochNs", "maximumConnections", "maximumConnectionSeconds",
    "headerTimeoutMilliseconds", "maximumTunnelBytes", "upstream"))


def require(condition: bool) -> None:
    if not condition:
        raise ValueError("sidecar unit preparation refused")


def original_path(value: str) -> str:
    # Literal systemd arguments, not shell fragments: refuse whitespace,
    # specifiers, variable expansion, quotes and escapes rather than guessing.
    require(isinstance(value, str) and 2 <= len(value) <= 4096
            and re.fullmatch(r"/[A-Za-z0-9_./-]+", value) is not None
            and all(part not in ("", ".", "..") for part in value.split("/")[1:]))
    return value


def acquire(stack: ExitStack, path: str, flags: int) -> tuple[int, int, str]:
    original_path(path)
    current = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    stack.callback(os.close, current)
    parts = path.split("/")[1:]
    for part in parts[:-1]:
        current = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                          dir_fd=current)
        stack.callback(os.close, current)
    fd = os.open(parts[-1], flags | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=current)
    stack.callback(os.close, fd)
    return fd, current, parts[-1]


def strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for name, item in pairs:
        require(name not in value)
        value[name] = item
    return value


def integer(value: object, lower: int, upper: int) -> bool:
    return type(value) is int and lower <= value <= upper


def identity(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


class Statfs(ctypes.Structure):
    # Same fixed Linux x86_64 ABI used by the existing retained input owners.
    _fields_ = [("kind", ctypes.c_long), ("block_size", ctypes.c_long),
        ("blocks", ctypes.c_ulong), ("free", ctypes.c_ulong), ("available", ctypes.c_ulong),
        ("files", ctypes.c_ulong), ("free_files", ctypes.c_ulong), ("fsid", ctypes.c_int * 2),
        ("name_length", ctypes.c_long), ("fragment_size", ctypes.c_long), ("flags", ctypes.c_long),
        ("spare", ctypes.c_long * 4)]


def namespace_identity(fd: int) -> tuple[int, int]:
    require(sys.platform == "linux" and os.uname().machine == "x86_64"
            and ctypes.sizeof(Statfs) == 120)
    libc = ctypes.CDLL(None, use_errno=True)
    libc.fstatfs.argtypes = (ctypes.c_int, ctypes.POINTER(Statfs))
    libc.fstatfs.restype = ctypes.c_int
    fs = Statfs()
    require(libc.fstatfs(fd, ctypes.byref(fs)) == 0 and fs.kind == 0x6E736673
            and fcntl.ioctl(fd, 0xB703) == 0x40000000)  # NS_GET_NSTYPE == CLONE_NEWNET
    info = os.fstat(fd)
    return info.st_dev, info.st_ino


def emit(configuration: str, pin: str, netns: str, output: str) -> None:
    require(re.fullmatch(r"sha256:(?!0{64})[0-9a-f]{64}", pin) is not None)
    original_path(configuration)
    original_path(netns)
    original_path(output)
    require(Path(output).name == "catchplate-workload-sidecar.service"
            and output not in (configuration, netns))
    with ExitStack() as stack:
        cfg, cfg_parent, cfg_name = acquire(stack, configuration, os.O_RDONLY | os.O_NONBLOCK)
        info = os.fstat(cfg)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                and stat.S_IMODE(info.st_mode) in (0o400, 0o600)
                and 0 < info.st_size <= MAX_CONFIGURATION)
        raw = os.pread(cfg, MAX_CONFIGURATION + 1, 0)
        require(len(raw) == info.st_size and "sha256:" + hashlib.sha256(raw).hexdigest() == pin)
        scope = json.loads(raw.decode("utf-8"), object_pairs_hook=strict_object,
                           parse_constant=lambda _: require(False))
        require(isinstance(scope, dict) and set(scope) == FIELDS
                and scope["apiVersion"] == "catchplate.nativeWorkloadSidecar/v1"
                and scope["profile"] == "native-attested-local-connect-v1")
        ns = scope["namespace"]
        require(isinstance(ns, dict) and set(ns) == {"device", "inode", "bootId", "uid", "gid"}
                and integer(ns["uid"], 1, 4294967294) and integer(ns["gid"], 1, 4294967294)
                and integer(ns["device"], 1, 18446744073709551615)
                and integer(ns["inode"], 1, 18446744073709551615)
                and info.st_uid == ns["uid"])
        require(isinstance(ns["bootId"], str)
                and re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", ns["bootId"]) is not None)
        require(integer(scope["issuedAtEpochNs"], 1, 9223372036854775807)
                and integer(scope["expiresAtEpochNs"], 1, 9223372036854775807)
                and 0 < scope["expiresAtEpochNs"] - scope["issuedAtEpochNs"] <= 86400_000_000_000)
        namespace, ns_parent, ns_name = acquire(stack, netns, os.O_RDONLY | os.O_NONBLOCK)
        expected_ns = (ns["device"], ns["inode"])

        def check() -> None:
            require(scope["issuedAtEpochNs"] <= time.time_ns() < scope["expiresAtEpochNs"]
                    and namespace_identity(namespace) == expected_ns)
            with open("/proc/sys/kernel/random/boot_id", "rb") as boot:
                require(boot.read(38) == ns["bootId"].encode("ascii") + b"\n")
            require(identity(os.fstat(cfg)) == identity(info)
                    and identity(os.stat(cfg_name, dir_fd=cfg_parent, follow_symlinks=False)) == identity(info)
                    and os.pread(cfg, MAX_CONFIGURATION + 1, 0) == raw)
            named_ns = os.stat(ns_name, dir_fd=ns_parent, follow_symlinks=False)
            require((named_ns.st_dev, named_ns.st_ino) == expected_ns)

        check()
        unit = ("[Unit]\nDescription=Catchplate native workload local CONNECT sidecar\n\n"
                "[Service]\nType=simple\n"
                f"User={ns['uid']}\nGroup={ns['gid']}\n"
                f"NetworkNamespacePath={netns}\n"
                "ExecStart=/usr/local/libexec/catchplate-workload-sidecar "
                f"--configuration {configuration} --configuration-sha256 {pin}\n"
                "Restart=no\nNoNewPrivileges=yes\nCapabilityBoundingSet=\nAmbientCapabilities=\n"
                "UMask=0077\nLimitCORE=0\nKillMode=control-group\nTimeoutStopSec=120s\n"
                "SendSIGKILL=yes\nStandardInput=null\nStandardOutput=null\nStandardError=journal\n\n"
                "# No Install section, namespace creation, egress rules or automatic renewal.\n").encode("ascii")
        # Only this new output is written. An incomplete file is deliberately
        # retained if publication or a final recheck fails; never retry over it.
        parent_path = str(Path(output).parent)
        parent, _, _ = acquire(stack, parent_path, os.O_RDONLY | os.O_DIRECTORY)
        parent_info = os.fstat(parent)
        require(parent_info.st_uid == os.geteuid() and stat.S_IMODE(parent_info.st_mode) == 0o700)
        name = Path(output).name
        result = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                         0o600, dir_fd=parent)
        stack.callback(os.close, result)
        os.fchmod(result, 0o600)
        view = memoryview(unit)
        while view:
            written = os.write(result, view)
            require(written > 0)
            view = view[written:]
        os.fsync(result)
        os.fsync(parent)
        check()
        readback = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent)
        stack.callback(os.close, readback)
        require(identity(os.fstat(readback)) == identity(os.fstat(result))
                and os.read(readback, len(unit) + 1) == unit)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--configuration", required=True)
    parser.add_argument("--configuration-sha256", required=True)
    parser.add_argument("--network-namespace", required=True,
                        help="existing absolute no-symlink bind-mounted workload netns path")
    parser.add_argument("--output", required=True,
                        help="new catchplate-workload-sidecar.service in an existing owner-only directory")
    args = parser.parse_args()
    emit(args.configuration, args.configuration_sha256, args.network_namespace, args.output)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("sidecar unit preparation failed; retain any partial output; no service was started", file=sys.stderr)
        raise SystemExit(1) from None
