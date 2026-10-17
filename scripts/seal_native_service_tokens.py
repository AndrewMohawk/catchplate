#!/usr/bin/env python3
"""Encrypt a fixed startup-token bundle in its authorized secret provisioner.

Inputs are separate, fully sealed inherited memfds, never arguments or paths
containing secrets. Stdout contains ciphertext only. This tool neither creates
tokens nor enrolls a KEK, signs a release, admits configuration or calls AWS.
"""
from __future__ import annotations

import argparse
import ctypes
import fcntl
import os
import resource
import stat
import sys

from catchplate import native_service_tokens as wire


def original(fd, maximum):
    wire.require(type(fd) is int and fd > 2)
    before = os.fstat(fd)
    wire.require(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid()
        and before.st_mode & 0o077 == 0 and before.st_nlink == 0
        and 1 <= before.st_size <= maximum
        and fcntl.fcntl(fd, fcntl.F_GET_SEALS) & 15 == 15
        and fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE != os.O_WRONLY)
    raw = os.pread(fd, maximum + 1, 0)
    after = os.fstat(fd)
    wire.require(len(raw) == before.st_size and (before.st_dev, before.st_ino,
        before.st_mode, before.st_uid, before.st_gid, before.st_size, before.st_mtime_ns,
        before.st_ctime_ns) == (after.st_dev, after.st_ino, after.st_mode, after.st_uid,
        after.st_gid, after.st_size, after.st_mtime_ns, after.st_ctime_ns))
    return raw, (before.st_dev, before.st_ino)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kek-fd", required=True, type=int)
    parser.add_argument("--tokens-fd", required=True, type=int)
    parser.add_argument("--binding-fd", required=True, type=int)
    parser.add_argument("--kek-sha256", required=True)
    args = parser.parse_args()
    wire.require(os.getuid() == os.geteuid() and os.getgid() == os.getegid()
        and len({args.kek_fd, args.tokens_fd, args.binding_fd}) == 3)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    process = ctypes.CDLL(None, use_errno=True)
    wire.require(process.prctl(4, 0, 0, 0, 0) == 0 and process.prctl(3, 0, 0, 0, 0) == 0)
    kek, kek_identity = original(args.kek_fd, 32)
    tokens, token_identity = original(args.tokens_fd, wire.MAX_PLAINTEXT)
    binding, binding_identity = original(args.binding_fd, 24576)
    wire.require(len({kek_identity, token_identity, binding_identity}) == 3)
    result = wire.seal(wire.document(tokens, wire.MAX_PLAINTEXT),
        wire.document(binding, 24576), kek, args.kek_sha256)
    # No secrets, private originals or low-entropy commitment diagnostics.
    sys.stdout.buffer.write(wire.canonical(result) + b"\n")
    sys.stdout.buffer.flush()


if __name__ == "__main__":
    try:
        main()
    except (Exception, SystemExit):
        # The provisioner's own logging must also exclude private descriptors.
        sys.stderr.write("native service-token sealing failed\n")
        raise SystemExit(1)
