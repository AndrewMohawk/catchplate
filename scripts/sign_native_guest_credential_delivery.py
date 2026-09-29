#!/usr/bin/env python3
"""Sign one independently approved guest role delivery using sealed FD inputs.

No seed/path/env secret argument, current-boot discovery, implicit window renewal,
key generation, credential-file write, launch or cloud operation is provided.
Stdout is the exact canonical signed original without a trailing newline.
"""
from __future__ import annotations

import argparse
import ctypes
import fcntl
import os
import resource
import stat
import sys

from serverware import response_v2_guest_delivery as wire


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
    identity = lambda m: (m.st_dev, m.st_ino, m.st_mode, m.st_uid, m.st_gid,
                         m.st_nlink, m.st_size, m.st_mtime_ns, m.st_ctime_ns)
    wire.require(len(raw) == before.st_size and identity(before) == identity(after))
    return raw, (before.st_dev, before.st_ino)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--signing-seed-fd", type=int, required=True)
    parser.add_argument("--configuration-fd", type=int, required=True)
    parser.add_argument("--payload-fd", type=int, required=True)
    parser.add_argument("--generation-root-fd", type=int, required=True)
    parser.add_argument("--configuration-sha256", required=True)
    args = parser.parse_args()
    wire.require(os.getuid() == os.geteuid() and os.getgid() == os.getegid())
    descriptors = (args.signing_seed_fd, args.configuration_fd, args.payload_fd, args.generation_root_fd)
    wire.require(len(set(descriptors)) == 4)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    process = ctypes.CDLL(None, use_errno=True)
    wire.require(process.prctl(4, 0, 0, 0, 0) == 0 and process.prctl(3, 0, 0, 0, 0) == 0)
    values, identities = [], set()
    for fd, maximum in zip(descriptors, (32, wire.MAX_CONFIG, wire.MAX_DELIVERY, 32)):
        value, identity = original(fd, maximum)
        wire.require(identity not in identities)
        identities.add(identity)
        values.append(value)
    seed, config, payload, generation_root = values
    result = wire.sign_delivery(config, payload, seed, generation_root, args.configuration_sha256)
    sys.stdout.buffer.write(result)
    sys.stdout.buffer.flush()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:
        sys.stderr.write("guest credential delivery signing failed\n")
        raise SystemExit(1) from None
