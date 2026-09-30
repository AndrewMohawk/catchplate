"""Offline only: emit one signed compiler-analysis event, never send it."""
import argparse
import os
import stat
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from cryptography.hazmat.primitives import serialization

from serverware import authority_policy_canary as profile
from serverware import native_pilot_inventory_publication as publication


def read_fd(number, maximum, *, private=False):
    profile.require(type(number) is int and number >= 3)
    info = os.fstat(number)
    profile.require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 < info.st_size <= maximum)
    if private:
        profile.require(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) in {0o400, 0o600},
            "compiler key must be an operator-owned private regular FD")
    raw = os.pread(number, maximum + 1, 0)
    after = os.fstat(number)
    profile.require(0 < len(raw) == info.st_size <= maximum and (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns))
    return raw


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-fd", type=int, required=True)
    parser.add_argument("--assignment-public-key-fd", type=int, required=True)
    parser.add_argument("--compiler-key-fd", type=int, required=True)
    args = parser.parse_args()
    try:
        profile.require(len({args.input_fd, args.assignment_public_key_fd, args.compiler_key_fd}) == 3)
        value = profile.document(read_fd(args.input_fd, 512 * 1024), 512 * 1024)
        trusted = serialization.load_pem_public_key(read_fd(args.assignment_public_key_fd, 4096))
        key_bytes = bytearray(read_fd(args.compiler_key_fd, 4096, private=True))
        try:
            key = serialization.load_pem_private_key(bytes(key_bytes), password=None)
        finally:
            key_bytes[:] = b"\0" * len(key_bytes)
        event = publication.produce(value, compiler_key=key, assignment_public_key=trusted, now_epoch_ns=time.time_ns())
        sys.stdout.buffer.write(profile.canonical(event) + b"\n")
    except Exception:
        # Never print key data, an input document, or a crypto exception.
        sys.stderr.write("native pilot publication refused\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
