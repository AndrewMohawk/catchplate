"""Offline, purpose-fixed authorization for ciphertext-only control-plane leases.

Input is an independently prepared custody v1 configuration. The runtime root
key stays with the provisioning authority, never with the control-plane service.
Existing files are never overwritten. This does not provision any AWS resource.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat

from cryptography.hazmat.primitives import serialization

from catchplate import authority_contract
from catchplate import control_plane_broker_startup as profile


def _read(path, *, maximum, private=False):
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid not in {0, os.geteuid()}
                or before.st_mode & (0o077 if private else 0o022)
                or not 1 <= before.st_size <= maximum):
            raise ValueError("provisioning input is not a bounded owner-controlled regular file")
        result = bytearray()
        while len(result) <= before.st_size:
            chunk = os.read(fd, min(4096, before.st_size + 1 - len(result)))
            if not chunk:
                break
            result.extend(chunk)
        after = os.fstat(fd)
        identity = lambda value: (value.st_dev, value.st_ino, value.st_mode, value.st_uid,
            value.st_gid, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
        if len(result) != before.st_size or identity(before) != identity(after):
            raise ValueError("provisioning input changed during its original read")
        return bytes(result)
    finally:
        os.close(fd)


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("duplicate provisioning member")
        result[key] = value
    return result


def _constant(_value):
    raise ValueError("non-JSON provisioning member")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--configuration", required=True)
    parser.add_argument("--runtime-root-private-key", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    original = _read(args.configuration, maximum=profile.MAX_BYTES)
    configuration = json.loads(original.decode("ascii"), object_pairs_hook=_pairs, parse_constant=_constant)
    if profile.canonical(configuration) != original or configuration.get("sourceRevision") != authority_contract.SOURCE_REVISION:
        raise ValueError("custody input must be exact canonical current-source configuration")
    key = serialization.load_pem_private_key(
        _read(args.runtime_root_private_key, maximum=65536, private=True), password=None)
    document = profile.sign_configuration(configuration, runtime_root_private_key=key)
    body = profile.canonical(document)
    target = Path(args.output)
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    try:
        offset = 0
        while offset < len(body):
            written = os.write(fd, body[offset:])
            if written < 1:
                raise OSError("broker configuration output write made no progress")
            offset += written
        os.fsync(fd)
    finally:
        os.close(fd)
    directory = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    # Do not print configuration originals, private material or signature bytes.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
