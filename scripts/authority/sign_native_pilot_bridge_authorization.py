#!/usr/bin/env python3
"""One independently approved, bridge-only authorization; no key generation.

Run with python3 -I -B, an exact approved public-input digest, its protected
root-owned 0400 FD, and a distinct existing sealed 32-byte authority-key FD.
FD ownership and a matching digest establish byte identity, not approval,
attestation, currentness, ciphertext provenance or live process ownership.
Require complete output AND successful exit; partial/uncertain output permits
no retry. An independent supervisor must bound filesystem and crypto stalls.
Python/OpenSSL key copies are not hardware custody or guaranteed erasure.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import native_pilot_authority_io as io
from serverware import native_pilot_bridge_authority as authority
from serverware import native_shadow_nitro_originals as originals


class _Parser(argparse.ArgumentParser):
    def error(self, _message):
        raise ValueError("native pilot bridge authorization invocation refused")


def main():
    try:
        parser = _Parser(description=__doc__, add_help=False, allow_abbrev=False)
        parser.add_argument("--operation", required=True,
            choices=("role-keys", "admission", "encrypted-delivery", "verifier-transport"))
        parser.add_argument("--input-fd", type=int, required=True)
        parser.add_argument("--input-sha256", required=True)
        parser.add_argument("--authority-key-fd", type=int, required=True)
        args = parser.parse_args()
        p = authority.p
        p.require(args.input_fd >= 3 and args.authority_key_fd >= 3
            and args.input_fd != args.authority_key_fd)
        digest = p.digest(args.input_sha256)
        input_identity = originals._identity(os.fstat(args.input_fd))
        key_identity = originals._identity(os.fstat(args.authority_key_fd))
        boot, before, wall = originals._boot(), originals._clock(), time.time_ns()
        raw = io.read_public(args.input_fd, authority.MAX_INPUT)
        p.require(p.sha(raw) == digest)
        prepared = authority.prepare_input(args.operation, raw,
            boot=boot, now_boottime_ns=before, now_unix_ns=wall)

        def check():
            nonlocal before, wall
            p.require(originals._identity(os.fstat(args.input_fd)) == input_identity
                and originals._identity(os.fstat(args.authority_key_fd)) == key_identity
                and io.read_public(args.input_fd, authority.MAX_INPUT) == raw
                and originals._boot() == boot)
            now, epoch = originals._clock(), time.time_ns()
            p.require(before <= now < prepared["deadline"]
                and wall <= epoch < prepared["epochLimit"])
            before, wall = now, epoch
            return now, epoch

        check()
        key = io.signing_key(args.authority_key_fd)
        try:
            check()
            output, deadline = authority.sign(args.operation, raw, key)
        finally:
            del key
        p.require(deadline == prepared["deadline"] and len(output) <= authority.MAX_OUTPUT)
        result = {"original": output.decode("ascii"), "sha256": p.sha(output)}
        now, epoch = check()
        p.require(authority.checked_result(args.operation, raw, result,
            boot=boot, now_boottime_ns=now, now_unix_ns=epoch) == output)
        check()
        io.write_public(output, deadline_boottime_ns=deadline)
        check()
        return 0
    except BaseException:
        return io.fail()


if __name__ == "__main__":
    raise SystemExit(main())
