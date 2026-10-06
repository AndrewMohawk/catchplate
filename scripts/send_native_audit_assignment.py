#!/usr/bin/env python3
"""Send one pinned public audit assignment to an explicitly selected enclave.

Run with python3 -I -B. The public file must be an absolute nonsymlink path to
a root/current-user owned, single-link, read-only regular file. No keys are
read. The timeout starts before acquisition and is clipped to S's original
expiry; it cannot extend the enclave's independently held startup lifetime.
Success means bytes accepted by the local transport, NOT native admission or
readiness. There is no acknowledgment, retry, reconnect, or discovery. After
any failure, delivery may have occurred: do not automatically invoke again.
An external supervisor must bound blocking public-file/filesystem operations.
"""
from __future__ import annotations

import argparse
import base64
import errno
import fcntl
import hashlib
import json
import os
import re
import select
import socket
import stat
import sys
import time

MAX_ORIGINAL = 3 * 1024 * 1024
MAX_PAYLOAD = 2 * 1024 * 1024
SIGNED_SCHEMA = "serverware.signedMeasuredAuditAuthorityPolicy/v1"
POLICY_SCHEMA = "serverware.measuredAuditAuthorityPolicy/v1"


def require(condition):
    if not condition:
        raise ValueError("public audit assignment sender refused")


class Parser(argparse.ArgumentParser):
    def error(self, _message):
        raise ValueError("invalid public audit assignment sender arguments")


def policy_interval(raw):
    """Check fixed public framing only; no signature or assignment authority."""
    require(type(raw) is bytes and 0 < len(raw) <= MAX_ORIGINAL)

    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result)
            result[key] = value
        return result

    def invalid(_value):
        raise ValueError("invalid JSON numeric constant")

    value = json.loads(raw.decode("ascii"), object_pairs_hook=pairs, parse_constant=invalid)
    require(type(value) is dict and set(value) == {"schema", "payload", "signatureBase64Url"}
            and value["schema"] == SIGNED_SCHEMA)
    signature = value["signatureBase64Url"]
    require(type(signature) is str and re.fullmatch(r"[A-Za-z0-9_-]{86}", signature) is not None)
    decoded = base64.urlsafe_b64decode(signature + "==")
    require(len(decoded) == 64 and base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") == signature)
    payload = value["payload"]
    require(type(payload) is dict and set(payload) == {"schema", "sourceRevision", "configurationDigest",
            "deploymentId", "issuedAtEpochNs", "expiresAtEpochNs", "trustRoots", "assignments"}
            and payload["schema"] == POLICY_SCHEMA)
    require(len(json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                           allow_nan=False).encode("ascii")) <= MAX_PAYLOAD)
    issued, expires = payload["issuedAtEpochNs"], payload["expiresAtEpochNs"]
    require(type(issued) is int and type(expires) is int
            and 0 < issued < expires < 2**64 and expires - issued <= 86_400_000_000_000)
    return issued, expires


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def open_public(path):
    require(type(path) is str and path.startswith("/"))
    components = path.split("/")[1:]
    require(bool(components) and all(item not in {"", ".", ".."} for item in components))
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    directory = os.open("/", flags | os.O_DIRECTORY)
    try:
        for component in components[:-1]:
            next_directory = os.open(component, flags | os.O_DIRECTORY, dir_fd=directory)
            os.close(directory)
            directory = next_directory
        # O_NONBLOCK prevents a substituted FIFO from blocking before fstat.
        descriptor = os.open(components[-1], flags | os.O_NONBLOCK, dir_fd=directory)
    finally:
        os.close(directory)
    try:
        info = os.fstat(descriptor)
        require(stat.S_ISREG(info.st_mode) and info.st_uid in {0, os.geteuid()}
                and info.st_nlink == 1 and not stat.S_IMODE(info.st_mode) & 0o222
                and 0 < info.st_size <= MAX_ORIGINAL)
        return descriptor, identity(info)
    except BaseException:
        os.close(descriptor)
        raise


def read_public(descriptor, original_identity):
    require(identity(os.fstat(descriptor)) == original_identity)
    raw = os.pread(descriptor, MAX_ORIGINAL + 1, 0)
    require(len(raw) == original_identity[6]
            and identity(os.fstat(descriptor)) == original_identity)
    return raw


class Budget:
    def __init__(self, timeout_seconds):
        require(type(timeout_seconds) is int and 1 <= timeout_seconds <= 300)
        self.owner = os.getpid()
        self.started_boot = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
        self.started_wall = time.time_ns()
        self.previous_boot, self.previous_wall = self.started_boot, self.started_wall
        self.deadline = self.started_boot + timeout_seconds * 1_000_000_000
        self.expires = None

    def clip(self, issued, expires):
        require(self.expires is None and issued <= self.started_wall < expires)
        self.expires = expires
        self.deadline = min(self.deadline, self.started_boot + expires - self.started_wall)
        self.remaining()

    def remaining(self):
        now_boot, now_wall = time.clock_gettime_ns(time.CLOCK_BOOTTIME), time.time_ns()
        require(os.getpid() == self.owner and self.previous_boot <= now_boot < self.deadline
                and self.previous_wall <= now_wall
                and (self.expires is None or now_wall < self.expires))
        self.previous_boot, self.previous_wall = now_boot, now_wall
        return (self.deadline - now_boot) / 1_000_000_000


def send_original(raw, cid, port, budget, check_input):
    require(type(cid) is int and 4 <= cid < 2**32 - 1
            and type(port) is int and 1024 <= port < 2**32 - 1)

    def check():
        remaining = budget.remaining()
        check_input()
        return min(remaining, budget.remaining())

    def writable(stream):
        while True:
            remaining = check()
            _, ready, exceptional = select.select([], [stream], [stream], min(0.1, remaining))
            check()
            require(not exceptional)
            if ready:
                return

    check()
    with socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM) as stream:
        stream.setblocking(False)
        check()
        result = stream.connect_ex((cid, port))  # Exactly one connection attempt.
        check()
        require(result in {0, errno.EINPROGRESS, errno.EWOULDBLOCK, errno.EALREADY, errno.EINTR})
        if result != 0:
            writable(stream)
            require(stream.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR) == 0)
        check()
        require(stream.getpeername() == (cid, port))
        frame = memoryview(len(raw).to_bytes(4, "big") + raw)
        while frame:
            writable(stream)
            try:
                sent = stream.send(frame[:65536])
            except BlockingIOError:
                continue  # Continue this same partial frame, never reconnect.
            check()
            require(sent > 0)
            frame = frame[sent:]
        check()
        stream.shutdown(socket.SHUT_WR)  # Required EOF; no native response is read.
        check()
    check()


def report(descriptor, raw):
    fcntl.fcntl(descriptor, fcntl.F_SETFL, fcntl.fcntl(descriptor, fcntl.F_GETFL) | os.O_NONBLOCK)
    require(os.write(descriptor, raw) == len(raw))


def main():
    require(sys.flags.isolated == 1 and sys.flags.dont_write_bytecode == 1)
    parser = Parser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--enclave-cid", type=int, required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--policy-file", required=True)
    parser.add_argument("--policy-sha256", required=True)
    parser.add_argument("--timeout-seconds", type=int, required=True)
    args = parser.parse_args()
    require(4 <= args.enclave_cid < 2**32 - 1 and 1024 <= args.port < 2**32 - 1
            and re.fullmatch(r"sha256:[0-9a-f]{64}", args.policy_sha256) is not None)
    budget = Budget(args.timeout_seconds)
    descriptor, original_identity = open_public(args.policy_file)
    try:
        raw = read_public(descriptor, original_identity)
        require("sha256:" + hashlib.sha256(raw).hexdigest() == args.policy_sha256)
        budget.clip(*policy_interval(raw))
        require(read_public(descriptor, original_identity) == raw)

        def check_input():
            require(identity(os.fstat(descriptor)) == original_identity)

        send_original(raw, args.enclave_cid, args.port, budget, check_input)
        require(read_public(descriptor, original_identity) == raw)
        budget.remaining()
    finally:
        os.close(descriptor)
    budget.remaining()
    report(1, b"bytes-delivered-unverified: local transport only; native admission/readiness unverified\n")


if __name__ == "__main__":
    try:
        main()
    except (Exception, KeyboardInterrupt):
        try:
            report(2, b"Public audit assignment refused or delivery uncertain; no retry authorized.\n")
        except Exception:
            pass
        raise SystemExit(1) from None
