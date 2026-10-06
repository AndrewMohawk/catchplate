#!/usr/bin/env python3
"""Sign one independently approved unsigned PolicyBundle/v1 or /v2.

Run python3 -I -B as root with a protected --input-fd, independently approved
--input-sha256, and distinct preprovisioned sealed --authority-key-fd. Input is
the closed policy_bundle_issuer.API object; no policy or key paths are accepted.
This creates no key, approval, scope, timestamp, enrollment or publication.

Output is the raw canonical signed PolicyBundle, no newline, on the supervisor's
root-owned pipe. Require complete bytes AND exit0; failure authorizes no retry.
The original issuance interval covers all processing/output, not policy runtime
validity. An external supervisor must bound filesystem/crypto stalls. Python/
OpenSSL copies are software custody, not guaranteed erasure or hardware custody.
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
from serverware import policy_bundle_issuer as issuer


class _Parser(argparse.ArgumentParser):
    def error(self, _message):
        raise ValueError("policy bundle issuer invocation refused")


def main():
    try:
        parser = _Parser(description=__doc__, add_help=False, allow_abbrev=False)
        parser.add_argument("--input-fd", type=int, required=True)
        parser.add_argument("--input-sha256", required=True)
        parser.add_argument("--authority-key-fd", type=int, required=True)
        args = parser.parse_args()
        issuer._require(args.input_fd >= 3 and args.authority_key_fd >= 3
            and args.input_fd != args.authority_key_fd)
        input_identity = io._input(args.input_fd, issuer.MAX_INPUT_BYTES)
        key_identity = io._input(args.authority_key_fd, 32, private=True)
        owner = os.getpid(), originals._start(), originals._boot()
        before_boot, before_wall = originals._clock(), time.time_ns()
        raw = io.read_public(args.input_fd, issuer.MAX_INPUT_BYTES)
        selected = issuer.prepare_input(raw, input_sha256=args.input_sha256, now_epoch_ns=before_wall)
        deadline = before_boot + selected["expiresAtEpochNs"] - before_wall
        previous = [before_boot, before_wall]

        def check():
            issuer._require(io._input(args.input_fd, issuer.MAX_INPUT_BYTES) == input_identity
                and io._input(args.authority_key_fd, 32, private=True) == key_identity
                and io.read_public(args.input_fd, issuer.MAX_INPUT_BYTES) == raw
                and owner == (os.getpid(), originals._start(), originals._boot()))
            now_boot, now_wall = originals._clock(), time.time_ns()
            issuer._require(previous[0] <= now_boot < deadline and previous[1] <= now_wall)
            issuer._current(selected, now_wall)
            previous[:] = now_boot, now_wall

        check()
        key = io.signing_key(args.authority_key_fd)
        check()
        result = issuer.sign(input_original=raw, input_sha256=args.input_sha256, signing_key=key, check=check)
        check()
        io.write_public(result, deadline_boottime_ns=deadline, check=check)
        check()
        return 0
    except BaseException:
        return io.fail()


if __name__ == "__main__":
    raise SystemExit(main())
