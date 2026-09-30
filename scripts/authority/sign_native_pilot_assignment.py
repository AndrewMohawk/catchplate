#!/usr/bin/env python3
"""Sign one complete independently approved native Assignment/v2 original.

Use python3 -I -B, a protected complete public input FD, and a distinct sealed
preprovisioned assignment-key FD. The issuer creates no scope/timestamp/keys and
does not install, publish or approve input. Output is canonical no-LF bytes on
the root supervisor pipe; incomplete output/nonzero exit must be discarded.
An independent supervisor must bound filesystem and cryptographic stalls.
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
from serverware import native_pilot_assignment as authority
from serverware import native_shadow_nitro_originals as originals


class _Parser(argparse.ArgumentParser):
    def error(self, _message):
        raise ValueError("native pilot assignment invocation refused")


def main():
    try:
        parser = _Parser(description=__doc__, add_help=False, allow_abbrev=False)
        parser.add_argument("--input-fd", type=int, required=True)
        parser.add_argument("--authority-key-fd", type=int, required=True)
        args = parser.parse_args()
        p = authority.p
        p.require(args.input_fd >= 3 and args.authority_key_fd >= 3 and args.input_fd != args.authority_key_fd)
        input_identity = io._input(args.input_fd, authority.MAX_INPUT)
        key_identity = io._input(args.authority_key_fd, 32, private=True)
        owner = os.getpid(), originals._start(), originals._boot()
        before_boot, before_wall = originals._clock(), time.time_ns()
        raw = io.read_public(args.input_fd, authority.MAX_INPUT)
        result = authority.sign(input_original=raw, signing_key=io.signing_key(args.authority_key_fd))
        payload = p.document(result, authority.MAX_BYTES)["payload"]
        now_boot, now_wall = originals._clock(), time.time_ns()
        p.require(before_boot <= now_boot and before_wall <= now_wall)
        p.freshness(payload["issuedAtUnixNanos"], payload["expiresAtUnixNanos"], now_wall)
        deadline = now_boot + min(1_000_000_000, payload["expiresAtUnixNanos"] - now_wall)

        def check():
            p.require(io._input(args.input_fd, authority.MAX_INPUT) == input_identity
                and io._input(args.authority_key_fd, 32, private=True) == key_identity
                and io.read_public(args.input_fd, authority.MAX_INPUT) == raw
                and owner == (os.getpid(), originals._start(), originals._boot())
                and before_boot <= originals._clock() < deadline and now_wall <= time.time_ns())
            p.freshness(payload["issuedAtUnixNanos"], payload["expiresAtUnixNanos"], time.time_ns())

        check()
        io.write_public(result, deadline_boottime_ns=deadline)
        check()
        return 0
    except BaseException:
        return io.fail()


if __name__ == "__main__":
    raise SystemExit(main())
