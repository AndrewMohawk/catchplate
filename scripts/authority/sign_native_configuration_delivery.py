#!/usr/bin/env python3
"""Sign one independently approved native configuration DATA delivery, offline.

Use python3 -I -B as root with --input-fd, its independently approved complete
--input-sha256, and a distinct preprovisioned sealed 32-byte --authority-key-fd.
Input is the exact canonical nativeConfigurationDelivery/v1 PAYLOAD original;
all challenge, boot, interval, artifact and key identities already exist there.
The public input FD must be read-only, root:root 0400 and at most 64 MiB.

Output is only the canonical signedNativeConfigurationDelivery/v1 original on
the root supervisor pipe, no length prefix or newline. Require complete bytes
AND exit0. Failure or partial output authorizes no retry. This command creates
no file, key, nonce, timestamp, approval, deployment or claim of attestation.
The native receiver must still verify signature, boot scope, original lifetime
and complete closure. Independent image-key selection and complete-input
approval remain the operator's responsibility. Python/OpenSSL key copies are
software custody, not hardware or guaranteed erasure. An external supervisor
must bound filesystem and cryptographic stalls.
"""
from __future__ import annotations

import argparse
import base64
import fcntl
import hashlib
import os
from pathlib import Path
import select
import stat
import sys

from cryptography.hazmat.primitives import serialization

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import native_pilot_authority_io as io
import send_native_configuration as transport
from serverware import native_shadow_nitro_originals as originals

MAX_INPUT = 64 * 1024 * 1024
OUTPUT_CHUNK = 64 * 1024


class _Parser(argparse.ArgumentParser):
    def error(self, _message):
        raise ValueError("native configuration signing invocation refused")


def _public(fd):
    """Local large-public-original bound; shared private/key I/O is unchanged."""
    io._process()
    transport.require(type(fd) is int and 3 <= fd < 2**31)
    flags = fcntl.fcntl(fd, fcntl.F_GETFL)
    transport.require(not flags & os.O_PATH and flags & os.O_ACCMODE == os.O_RDONLY)
    os.set_inheritable(fd, False)
    info = os.fstat(fd)
    transport.require(stat.S_ISREG(info.st_mode) and (info.st_uid, info.st_gid) == (0, 0)
        and stat.S_IMODE(info.st_mode) == 0o400 and 0 < info.st_size <= MAX_INPUT)
    if info.st_nlink == 0:
        transport.require(fcntl.fcntl(fd, fcntl.F_GET_SEALS) == io.SEALS)
    else:
        transport.require(info.st_nlink == 1)
    return io._identity(info)


def _read(fd, expected, check):
    transport.require(_public(fd) == expected)
    result = bytearray()
    while len(result) < expected[6]:
        check()
        part = os.pread(fd, min(65536, expected[6] - len(result)), len(result))
        check()
        transport.require(bool(part))
        result.extend(part)
    transport.require(_public(fd) == expected and not os.pread(fd, 1, len(result)))
    check()
    return bytes(result)


def _pipe():
    info, flags = os.fstat(1), fcntl.fcntl(1, fcntl.F_GETFL)
    transport.require(stat.S_ISFIFO(info.st_mode) and (info.st_uid, info.st_gid) == (0, 0)
        and flags & os.O_ACCMODE == os.O_WRONLY and not flags & os.O_PATH)
    return info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid


def _write(raw, expected, deadline, check):
    """Continue this literal output only while its original authorization lives."""
    transport.require(type(raw) is bytes and 0 < len(raw) <= transport.MAX_MANIFEST)
    check()
    transport.require(_pipe() == expected)
    flags = fcntl.fcntl(1, fcntl.F_GETFL)
    os.set_inheritable(1, False)
    fcntl.fcntl(1, fcntl.F_SETFL, flags | os.O_NONBLOCK)
    offset = 0
    previous = io._clock()
    while offset < len(raw):
        check()
        now = io._clock()
        transport.require(previous <= now < deadline and _pipe() == expected
            and fcntl.fcntl(1, fcntl.F_GETFL) & os.O_NONBLOCK)
        previous = now
        try:
            _, ready, exceptional = select.select([], [1], [1], min(0.05, (deadline - now) / 1_000_000_000))
            check()
            transport.require(not exceptional and previous <= io._clock() < deadline
                and _pipe() == expected and fcntl.fcntl(1, fcntl.F_GETFL) & os.O_NONBLOCK)
            if not ready:
                continue
            count = os.write(1, memoryview(raw)[offset:offset + OUTPUT_CHUNK])
        except (BlockingIOError, InterruptedError):
            continue
        check()
        transport.require(count > 0)
        offset += count
    check()
    transport.require(previous <= io._clock() < deadline and _pipe() == expected)


def _envelope(payload_original, signature):
    # Sorted closed keys plus the literal canonical payload, never a repaired
    # or regenerated configuration. The signature slot is always exactly 64 B.
    transport.require(type(signature) is bytes and len(signature) == 64)
    return (b'{"apiVersion":' + transport.canonical(transport.SIGNED_API)
        + b',"payload":' + payload_original + b',"signatureBase64Url":"'
        + base64.urlsafe_b64encode(signature).rstrip(b"=") + b'"}')


def main():
    try:
        parser = _Parser(description=__doc__, add_help=False, allow_abbrev=False)
        parser.add_argument("--input-fd", type=int, required=True)
        parser.add_argument("--input-sha256", required=True)
        parser.add_argument("--authority-key-fd", type=int, required=True)
        args = parser.parse_args()
        transport.require(args.input_fd >= 3 and args.authority_key_fd >= 3
            and args.input_fd != args.authority_key_fd)
        approved_pin = transport.digest(args.input_sha256)
        input_identity = _public(args.input_fd)
        key_identity = io._input(args.authority_key_fd, 32, private=True)
        transport.require(key_identity[6] == 32 and input_identity[:2] != key_identity[:2])
        owner = os.getpid(), originals._start(), originals._boot()
        budget = transport.Budget()  # Before reading: all work consumes this original bracket.
        output_identity = None

        def check():
            transport.require(owner == (os.getpid(), originals._start(), originals._boot())
                and _public(args.input_fd) == input_identity
                and io._input(args.authority_key_fd, 32, private=True) == key_identity
                and (output_identity is None or _pipe() == output_identity))
            budget.remaining()

        raw = _read(args.input_fd, input_identity, check)
        transport.require("sha256:" + hashlib.sha256(raw).hexdigest() == approved_pin)
        payload = transport.document(raw, MAX_INPUT, canonical_required=True)
        challenge = transport.hello(transport.canonical({"apiVersion": transport.HELLO_API,
            **{name: payload[name] for name in transport.SCOPE}}))
        # The real sender parser consumes its original interval and checks every
        # artifact's actual bytes/pin. The zero signature is ONLY an unsigned
        # grammar/size slot: never verified, emitted, or treated as authority.
        preflight = _envelope(raw, bytes(64))
        transport.require(len(preflight) <= transport.MAX_MANIFEST)
        output_length = len(preflight)
        transport.manifest(preflight, challenge, budget)
        del preflight
        check()
        # raw is the retained independently hash-approved original. Repeated
        # liveness callbacks check its FD identity; no mutable payload/cache is
        # consulted for the signed or emitted bytes.
        key = io.signing_key(args.authority_key_fd)
        check()
        public = key.public_key()
        spki = public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        transport.require("sha256:" + hashlib.sha256(spki).hexdigest() == payload["deliveryKeySpkiSha256"])
        preimage = transport.PAYLOAD_API.encode("ascii") + b"\0" + raw
        check()
        signature = key.sign(preimage)
        check()
        public.verify(signature, preimage)
        check()
        result = _envelope(raw, signature)
        transport.require(len(result) == output_length and len(result) <= transport.MAX_MANIFEST)
        check()
        output_identity = _pipe()
        # Keep one output pipe and the same original authorization throughout.
        # The shared helper's short per-call ceiling is not this large-frame
        # protocol. There is no fresh setup timeout or per-chunk renewal.
        output_deadline = budget.interval[2]
        _write(result, output_identity, output_deadline, check)
        check()
        transport.require(io._clock() < output_deadline)
        return 0
    except BaseException:
        return io.fail()


if __name__ == "__main__":
    raise SystemExit(main())
