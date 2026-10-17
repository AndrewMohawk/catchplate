#!/usr/bin/env python3
"""Emit one independently approved PolicyCandidateArtifact/v2 record.

Use python3 -I -B as root with --input-fd, the independently approved complete
--input-sha256, and a distinct preprovisioned sealed --authority-key-fd. The
public input's complete schema is fixed by policy_candidate_artifact_issuer.
No key, build identity, scope, predecessor or timestamp is created here.

Stdout is canonical {kind:'artifact',record} on a root-owned supervisor pipe.
Require complete bytes AND exit0. Failure/partial output permits no retry.
An independent supervisor must bound filesystem/crypto stalls under the original
interval. Python/OpenSSL key copies are software custody, not erased or hardware
protected. This command never enrolls, publishes, opens SQL or claims approval.
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
from catchplate import native_shadow_nitro_originals as originals
from catchplate import policy_candidate_artifact_issuer as issuer


class _Parser(argparse.ArgumentParser):
    def error(self, _message):
        raise ValueError("policy candidate artifact invocation refused")


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
        # Verify the independent pin and all public bindings before key access.
        selected = issuer.prepare_input(raw, input_sha256=args.input_sha256, now_epoch_ns=before_wall)
        _, payload = issuer._original(selected["payloadOriginal"])
        deadline = before_boot + payload["expiresAtEpochNs"] - before_wall
        previous = [before_boot, before_wall]

        def check():
            issuer._require(io._input(args.input_fd, issuer.MAX_INPUT_BYTES) == input_identity
                and io._input(args.authority_key_fd, 32, private=True) == key_identity
                and io.read_public(args.input_fd, issuer.MAX_INPUT_BYTES) == raw
                and owner == (os.getpid(), originals._start(), originals._boot()))
            now_boot, now_wall = originals._clock(), time.time_ns()
            issuer._require(previous[0] <= now_boot < deadline and previous[1] <= now_wall)
            issuer._current(payload, now_wall)
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
