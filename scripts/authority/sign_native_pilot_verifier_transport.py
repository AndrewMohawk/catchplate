#!/usr/bin/env python3
"""Issue one independently approved endpoint verifier transport authorization.

Require complete stdout bytes AND successful exit; partial or uncertain output
does not permit retry. The independently provisioned sealed supervisor key is
not a verifier secret or hardware-custody guarantee. An external supervisor
must bound original-file and cryptographic stalls.
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
from serverware import native_pilot_verifier_authority as authority
from serverware import native_shadow_nitro_originals as originals


class _Parser(argparse.ArgumentParser):
    def error(self, _message):
        raise ValueError("native pilot verifier authority invocation refused")


def main():
    try:
        parser = _Parser(description=__doc__, add_help=False, allow_abbrev=False)
        parser.add_argument("--role", choices=authority.ROLES, required=True)
        parser.add_argument("--input-fd", type=int, required=True)
        parser.add_argument("--authority-key-fd", type=int, required=True)
        args = parser.parse_args()
        p = authority.p
        p.require(args.input_fd >= 3 and args.authority_key_fd >= 3 and args.input_fd != args.authority_key_fd)
        input_identity = originals._identity(os.fstat(args.input_fd))
        key_identity = originals._identity(os.fstat(args.authority_key_fd))
        raw = io.read_public(args.input_fd, authority.MAX_INPUT)
        boot, before, wall = originals._boot(), originals._clock(), time.time_ns()
        result, deadline = authority.sign(args.role, raw, io.signing_key(args.authority_key_fd))

        def check():
            nonlocal before, wall
            now, current_wall = originals._clock(), time.time_ns()
            p.require(originals._identity(os.fstat(args.input_fd)) == input_identity
                and originals._identity(os.fstat(args.authority_key_fd)) == key_identity
                and io.read_public(args.input_fd, authority.MAX_INPUT) == raw
                and originals._boot() == boot and before <= now < deadline and wall <= current_wall)
            authority.checked_result(args.role, raw,
                {"original": result.decode("ascii"), "sha256": p.sha(result)},
                boot=boot, now_boottime_ns=now, now_unix_ns=current_wall)
            context = authority.prepare_input(args.role, raw, boot=boot,
                now_boottime_ns=now, now_unix_ns=current_wall)
            before, wall = authority._current(context, boot, now, current_wall)

        check()
        io.write_public(result, deadline_boottime_ns=deadline)
        check()
        return 0
    except BaseException:
        return io.fail()


if __name__ == "__main__":
    raise SystemExit(main())
