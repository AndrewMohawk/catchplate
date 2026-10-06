#!/usr/bin/env python3
"""Sign one independently approved static native assignment, offline.

Use python3 -I -B as root with --input-fd, its independently approved complete
--input-sha256, and a distinct existing sealed 32-byte --authority-key-fd.
Input is canonical staticCredentialAssignmentAuthorityInput/v1: signed full A
and its pinned root, exact retained role-4 identity original (including LF),
approved native launch original, expected module ID and original epoch interval.
The seven dynamic assignment fields come only from authenticated startup data.

Stdout is the existing signedStaticCredentialAssignment/v1 original, no LF.
Require complete bytes AND exit0; failure/partial output permits no retry.
This creates no key, quote, challenge, clock interval, file or runtime. A retained
startup quote is not fresh action authority or readiness. Collection, independent
input/key approval, actual N closure and per-action native verification remain
separate. Software key copies are neither hardware custody nor guaranteed erased.
An external supervisor must bound filesystem and cryptographic stalls.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys
import time

_SCRIPT = Path(__file__).resolve().parent
_PACKAGED = "/authority/app/scripts/authority/sign_static_credential_assignment.py"
if str(_SCRIPT) == "/authority/app/scripts/authority":
    if not (sys.argv[0] == _PACKAGED and __file__ == _PACKAGED and os.path.realpath(__file__) == _PACKAGED
        and sys.executable == "/runtime/python/bin/python3" and os.path.realpath(sys.executable) == sys.executable
        and sys.prefix == sys.base_prefix == "/runtime/python" and sys.version_info[:2] == (3, 11)
        and sys.flags.isolated == 1 and sys.flags.ignore_environment == 1 and sys.flags.no_user_site == 1
        and sys.flags.safe_path and sys.flags.dont_write_bytecode == 1):
        raise SystemExit("static assignment packaged invocation refused")
    sys.path[:0] = [str(_SCRIPT), "/authority/app", "/vendor", "/app"]
else:
    sys.path[:0] = [str(_SCRIPT.parent.parent), str(_SCRIPT)]

import native_pilot_authority_io as io
from serverware import authority_static_credential_assignment_issuer as issuer
from serverware import native_shadow_nitro_originals as originals


class _Parser(argparse.ArgumentParser):
    def error(self, _message):
        raise ValueError("static assignment invocation refused")


def main():
    try:
        parser = _Parser(description=__doc__, add_help=False, allow_abbrev=False)
        parser.add_argument("--input-fd", type=int, required=True)
        parser.add_argument("--input-sha256", required=True)
        parser.add_argument("--authority-key-fd", type=int, required=True)
        args = parser.parse_args()
        io._process()
        issuer.require(args.input_fd >= 3 and args.authority_key_fd >= 3 and args.input_fd != args.authority_key_fd)
        pin = issuer.digest(args.input_sha256)
        public_identity = io._input(args.input_fd, issuer.MAX_INPUT)
        key_identity = io._input(args.authority_key_fd, 32, private=True)
        issuer.require(key_identity[6] == 32 and public_identity[:2] != key_identity[:2])
        owner = os.getpid(), originals._start(), originals._boot()
        before_boot, before_wall = originals._clock(), time.time_ns()
        raw = io.read_public(args.input_fd, issuer.MAX_INPUT)
        issuer.require(issuer.sha256(raw) == pin)
        prepared = issuer.prepare_input(raw, now_epoch_ns=before_wall)
        # The original approved interval and existing quote/certificate age
        # bound all parsing/key/output work. No newly sampled time is issuance.
        deadline = before_boot + prepared.expires - before_wall
        previous = [before_boot, before_wall]

        def check():
            issuer.require(owner == (os.getpid(), originals._start(), originals._boot())
                and io._input(args.input_fd, issuer.MAX_INPUT) == public_identity
                and io._input(args.authority_key_fd, 32, private=True) == key_identity
                and io.read_public(args.input_fd, issuer.MAX_INPUT) == raw)
            now_boot, now_wall = originals._clock(), time.time_ns()
            issuer.require(previous[0] <= now_boot < deadline and previous[1] <= now_wall)
            prepared.check_time(now_wall)
            previous[:] = now_boot, now_wall
            return now_wall

        check()  # All original signatures and joins precede private-key access.
        key = io.signing_key(args.authority_key_fd)
        check()
        result = issuer.sign(raw, key, check=check)
        check()
        io.write_public(result, deadline_boottime_ns=deadline, check=check)
        check()
        return 0
    except BaseException:
        return io.fail()


if __name__ == "__main__":
    raise SystemExit(main())
