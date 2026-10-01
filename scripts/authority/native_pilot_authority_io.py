"""Bounded I/O for the fixed independently operated pilot authority commands.

Possession of an input FD does not approve its contents. The authority operator
must independently approve the complete input and provision its matching key.
These helpers generate neither. Python/OpenSSL copies are not hardware custody
or guaranteed erased memory. An external supervisor must bound filesystem and
crypto stalls; this module bounds bytes and pipe writes, not kernel I/O latency.
"""
from __future__ import annotations

import ctypes
import fcntl
import os
import resource
import select
import stat
import sys
import threading
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

MAX_PUBLIC = 32 * 1024 * 1024
SEALS = fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE


def _require(value):
    if not value:
        raise ValueError("native pilot authority refused")


def _process():
    _require(threading.current_thread() is threading.main_thread()
             and os.getresuid() == (0, 0, 0) and os.getresgid() == (0, 0, 0)
             and sys.flags.isolated == 1 and sys.flags.dont_write_bytecode == 1)


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _input(fd, maximum, *, private=False):
    _process()
    _require(type(fd) is int and fd >= 3 and type(maximum) is int
             and 0 < maximum <= MAX_PUBLIC)
    flags = fcntl.fcntl(fd, fcntl.F_GETFL)
    _require(not flags & os.O_PATH and flags & os.O_ACCMODE != os.O_WRONLY)
    os.set_inheritable(fd, False)
    info = os.fstat(fd)
    _require(stat.S_ISREG(info.st_mode) and (info.st_uid, info.st_gid) == (0, 0)
             and stat.S_IMODE(info.st_mode) == 0o400 and 0 < info.st_size <= maximum)
    if private or info.st_nlink == 0:
        _require(info.st_nlink == 0 and fcntl.fcntl(fd, fcntl.F_GET_SEALS) == SEALS)
    else:
        _require(info.st_nlink == 1 and flags & os.O_ACCMODE == os.O_RDONLY)
    return _identity(info)


def read_public(fd, maximum):
    """Read literal, stable root:root0400 public bytes without changing offset."""
    before = _input(fd, maximum)
    result = bytearray()
    while len(result) < before[6]:
        part = os.pread(fd, min(65536, before[6] - len(result)), len(result))
        _require(bool(part))
        result.extend(part)
    _require(_input(fd, maximum) == before and not os.pread(fd, 1, len(result)))
    return bytes(result)


def signing_key(fd):
    """Load only an already provisioned, sealed, 32-byte authority memfd.

    The purpose-specific producer must independently check that this key matches
    its approved authority. A valid sealed FD alone grants no signing purpose.
    """
    before = _input(fd, 32, private=True)
    _require(before[6] == 32)
    # Do this before reading key bytes. It does not isolate the authority from
    # its administrator or claim that Python/OpenSSL copies can be erased.
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    libc = ctypes.CDLL(None, use_errno=True)
    _require(libc.prctl(4, 0, 0, 0, 0) == 0 and libc.prctl(3, 0, 0, 0, 0) == 0)
    raw = bytearray(os.pread(fd, 33, 0))
    try:
        _require(len(raw) == 32 and _input(fd, 32, private=True) == before)
        return Ed25519PrivateKey.from_private_bytes(bytes(raw))
    finally:
        raw[:] = b"\0" * len(raw)


def _clock():
    return time.clock_gettime_ns(time.CLOCK_BOOTTIME)


def write_public(raw, *, deadline_boottime_ns=None, check=None):
    """Write one literal original to the supervisor's pipe, without a newline.

    Partial writes continue the same output, never a second signing attempt.
    A failure leaves an incomplete pipe output for the supervisor to reject.
    The one-second I/O ceiling cannot extend a caller's original deadline.
    """
    _process()
    _require(check is None or callable(check))
    if check is not None:
        check()
    _require(type(raw) is bytes and 0 < len(raw) <= MAX_PUBLIC)
    now = _clock()
    deadline = now + 1_000_000_000
    if deadline_boottime_ns is not None:
        _require(type(deadline_boottime_ns) is int and now < deadline_boottime_ns < (1 << 64))
        deadline = min(deadline, deadline_boottime_ns)
    info = os.fstat(1)
    identity = (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)
    flags = fcntl.fcntl(1, fcntl.F_GETFL)
    _require(stat.S_ISFIFO(info.st_mode) and info.st_uid == info.st_gid == 0
             and flags & os.O_ACCMODE == os.O_WRONLY and not flags & os.O_PATH)
    os.set_inheritable(1, False)
    fcntl.fcntl(1, fcntl.F_SETFL, flags | os.O_NONBLOCK)
    offset = 0
    previous = now
    while offset < len(raw):
        now = _clock()
        _require(previous <= now < deadline)
        previous = now
        current = os.fstat(1)
        _require((current.st_dev, current.st_ino, current.st_mode, current.st_uid, current.st_gid) == identity)
        try:
            _, ready, _ = select.select([], [1], [], min(0.05, (deadline - now) / 1_000_000_000))
            if check is not None:
                check()  # Retained source and wall-clock guards consume the same interval.
            _require(previous <= _clock() < deadline)
            if not ready:
                continue
            count = os.write(1, memoryview(raw)[offset:offset + 65536])
        except (BlockingIOError, InterruptedError):
            continue
        _require(count > 0)
        offset += count
    if check is not None:
        check()
    _require(previous <= _clock() < deadline)


def fail():
    """Return failure without exposing originals, keys or exception details."""
    try:
        flags = fcntl.fcntl(2, fcntl.F_GETFL)
        fcntl.fcntl(2, fcntl.F_SETFL, flags | os.O_NONBLOCK)
        os.write(2, b"native pilot authority refused; no retry is authorized\n")
    except OSError:
        pass
    return 1
