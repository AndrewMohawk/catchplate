#!/usr/bin/env python3
"""Issue one independently approved portal Assignment/v1 event, offline only.

Run python3 -I -B with a protected complete input FD, its independently approved
sha256:<hex> pin, and a distinct sealed preprovisioned 32-byte assignment-key FD.
Output is canonical no-LF bytes on the root supervisor pipe. Discard partial
output/nonzero exit; no retry, enrollment, delivery or publication is implied.
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
from serverware import native_shadow_nitro_originals as originals
from serverware import policy_shadow_assignment_issuer as authority


class _Parser(argparse.ArgumentParser):
    def error(self, _message):
        raise ValueError("policy shadow assignment invocation refused")


def main():
    try:
        parser = _Parser(description=__doc__, add_help=False, allow_abbrev=False)
        parser.add_argument("--input-fd", type=int, required=True)
        parser.add_argument("--input-sha256", required=True)
        parser.add_argument("--authority-key-fd", type=int, required=True)
        args = parser.parse_args()
        p = authority.p
        p.require(args.input_fd >= 3 and args.authority_key_fd >= 3 and args.input_fd != args.authority_key_fd)
        pin = p.digest(args.input_sha256)
        input_identity = io._input(args.input_fd, authority.MAX_INPUT)
        key_identity = io._input(args.authority_key_fd, 32, private=True)
        owner = os.getpid(), originals._start(), originals._boot()
        before_boot, before_wall = originals._clock(), time.time_ns()
        raw = io.read_public(args.input_fd, authority.MAX_INPUT)
        p.require(p.sha(raw) == pin)
        prepared = authority.prepare_input(raw, now_epoch_ns=time.time_ns())
        expires = prepared["expiresAtEpochNs"]
        # Convert the existing signed expiry using the initial clock pair.
        # Parsing, key loading and signing consume it; none renew the interval.
        deadline = before_boot + expires - before_wall
        previous_boot, previous_wall = before_boot, before_wall

        def check():
            nonlocal previous_boot, previous_wall
            p.require(io._input(args.input_fd, authority.MAX_INPUT) == input_identity
                and io._input(args.authority_key_fd, 32, private=True) == key_identity
                and io.read_public(args.input_fd, authority.MAX_INPUT) == raw
                and owner == (os.getpid(), originals._start(), originals._boot()))
            now_boot, now_wall = originals._clock(), time.time_ns()
            p.require(previous_boot <= now_boot < deadline and previous_wall <= now_wall < expires)
            previous_boot, previous_wall = now_boot, now_wall

        check()  # Complete approved input and original interval precede key use.
        key = io.signing_key(args.authority_key_fd)
        check()
        result = authority.sign(input_original=raw, signing_key=key, check=check)
        check()
        io.write_public(result, deadline_boottime_ns=deadline, check=check)
        check()
        return 0
    except BaseException:
        return io.fail()


if __name__ == "__main__":
    raise SystemExit(main())
