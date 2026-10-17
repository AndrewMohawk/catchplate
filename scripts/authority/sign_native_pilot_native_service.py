#!/usr/bin/env python3
"""Sign one independently approved, fixed native pilot operational grant.

No keys, histories, genesis, approvals or runtime owners are generated. Require
the complete stdout original AND successful exit; never retry uncertain output.
An external supervisor must bound original-file/crypto stalls. Software key
objects are not hardware custody or a guaranteed zeroization boundary.
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
from catchplate import native_pilot_native_service_authority as authority
from catchplate import native_shadow_nitro_originals as originals


class _Parser(argparse.ArgumentParser):
    def error(self, _message):
        raise ValueError("native pilot service authority invocation refused")


def main():
    try:
        parser = _Parser(description=__doc__, add_help=False, allow_abbrev=False)
        parser.add_argument("--operation", choices=authority.OPERATIONS, required=True)
        parser.add_argument("--input-fd", required=True, type=int)
        parser.add_argument("--authority-key-fd", required=True, type=int)
        args = parser.parse_args()
        p = authority.p
        p.require(args.input_fd >= 3 and args.authority_key_fd >= 3 and args.input_fd != args.authority_key_fd)
        input_identity = originals._identity(os.fstat(args.input_fd))
        key_identity = originals._identity(os.fstat(args.authority_key_fd))
        raw = io.read_public(args.input_fd, authority.MAX_INPUT)
        result = authority.sign(args.operation, raw, io.signing_key(args.authority_key_fd))
        payload = authority.grant_original(args.operation, result)["payload"]
        wall, previous = time.time_ns(), authority.c9._live(payload["guest"])

        def check():
            p.require(originals._identity(os.fstat(args.input_fd)) == input_identity
                and originals._identity(os.fstat(args.authority_key_fd)) == key_identity
                and io.read_public(args.input_fd, authority.MAX_INPUT) == raw and wall <= time.time_ns())
            authority.c9._live(payload["guest"], previous)
            p.freshness(payload["issuedAtUnixNanos"], payload["expiresAtUnixNanos"], time.time_ns())

        check()
        io.write_public(result, deadline_boottime_ns=p.ns(payload["guest"]["startupDeadlineBoottimeNs"]))
        check()
        return 0
    except BaseException:
        return io.fail()


if __name__ == "__main__":
    raise SystemExit(main())
