#!/usr/bin/env python3
"""Publish one approved public original at its fixed native-pilot destination.

Run with python3 -I -B as actual root. The inherited input FD is a protected
public JSON original, never a key/credential descriptor. No installation root
is created or repaired; existing destinations and every retry are refused.
An external watchdog must cover blocking original-file/filesystem operations.
"""
from __future__ import annotations

import argparse
import fcntl
import os
from pathlib import Path
import stat
import sys


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError("invalid public publication arguments")


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def main():
    if not (sys.flags.isolated == 1 and sys.flags.dont_write_bytecode == 1):
        raise ValueError("isolated no-bytecode Python is required")
    # Fixed sibling installed/source package only; no supplied import selector.
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from catchplate.native_pilot_publication import DESTINATIONS, LIMITS, PublicPublisher, p

    parser = Parser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--purpose", choices=tuple(DESTINATIONS), required=True)
    parser.add_argument("--input-fd", type=int, required=True,
                        help="inherited root:root0400 read-only regular public-original FD >=3")
    parser.add_argument("--sha256", required=True, help="independently approved exact original hash")
    args = parser.parse_args()
    maximum = LIMITS[args.purpose]
    p.require(args.input_fd >= 3 and os.getresuid() == (0, 0, 0) and os.getresgid() == (0, 0, 0))
    p.digest(args.sha256)
    flags = fcntl.fcntl(args.input_fd, fcntl.F_GETFL)
    p.require(flags & (os.O_ACCMODE | os.O_PATH) == os.O_RDONLY)
    before = os.fstat(args.input_fd)
    p.require(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0
        and before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == 0o400
        and 0 < before.st_size <= maximum)
    descriptor = fcntl.fcntl(args.input_fd, fcntl.F_DUPFD_CLOEXEC, 3)
    owner = None
    try:
        p.require(identity(os.fstat(descriptor)) == identity(before))
        raw = os.pread(descriptor, maximum + 1, 0)
        p.require(len(raw) == before.st_size and p.sha(raw) == args.sha256)

        def check_input():
            p.require(identity(os.fstat(args.input_fd)) == identity(before)
                and identity(os.fstat(descriptor)) == identity(before)
                and os.pread(descriptor, maximum + 1, 0) == raw)

        check_input()
        owner = PublicPublisher.open()
        pin = owner.publish(purpose=args.purpose, raw=raw, expected_sha256=args.sha256)
        check_input()
        owner.check()
        reply = p.canonical(pin) + b"\n"
        p.require(len(reply) <= 512)
        # One bounded nonblocking result write. Output loss never permits a
        # retry, replacement or inference that the publication did not happen.
        fcntl.fcntl(1, fcntl.F_SETFL, fcntl.fcntl(1, fcntl.F_GETFL) | os.O_NONBLOCK)
        p.require(os.write(1, reply) == len(reply))
    finally:
        if owner is not None:
            owner.close()
        os.close(descriptor)


if __name__ == "__main__":
    try:
        main()
    except (Exception, KeyboardInterrupt):
        try:
            fcntl.fcntl(2, fcntl.F_SETFL, fcntl.fcntl(2, fcntl.F_GETFL) | os.O_NONBLOCK)
            os.write(2, b"Public original publication refused or uncertain; preserve any new file and do not retry.\n")
        except OSError:
            pass
        raise SystemExit(1) from None
