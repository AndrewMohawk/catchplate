#!/usr/bin/env python3
"""Sign one approved endpoint request-commitment or encrypted-delivery original.

The input FD contains public metadata, never a secret or plaintext key inventory.
Require complete stdout AND successful exit; uncertain or partial output cannot
authorize a retry. The independent supervisor bounds original/crypto stalls.
Python/OpenSSL copies are not a hardware-custody or guaranteed-erasure claim.
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
from catchplate import native_pilot_encrypted_authority as authority
from catchplate import native_shadow_nitro_originals as originals


class _Parser(argparse.ArgumentParser):
    def error(self, _message):
        raise ValueError("native pilot encrypted authority invocation refused")


def main():
    try:
        parser = _Parser(description=__doc__, add_help=False, allow_abbrev=False)
        parser.add_argument("--operation", choices=authority.OPERATIONS, required=True)
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
        result, deadline = authority.sign(args.operation, args.role, raw, io.signing_key(args.authority_key_fd))
        value = p.document(result, authority.MAX_OUTPUT)
        payload = value["authorization"]["payload"] if args.operation == "delivery" else value["payload"]
        context = {"payload": payload, "window": payload["guest"], "deadline": deadline,
            "epochLimit": payload["expiresAtUnixNanos"]}

        def check():
            nonlocal before, wall
            now, current_wall = originals._clock(), time.time_ns()
            p.require(originals._identity(os.fstat(args.input_fd)) == input_identity
                and originals._identity(os.fstat(args.authority_key_fd)) == key_identity
                and io.read_public(args.input_fd, authority.MAX_INPUT) == raw
                and originals._boot() == boot and before <= now < deadline and wall <= current_wall)
            authority.checked_result(args.operation, args.role, raw,
                {"original": result.decode("ascii"), "sha256": p.sha(result)},
                boot=boot, now_boottime_ns=now, now_unix_ns=current_wall)
            before, wall = authority._current(context, boot, now, current_wall)

        check()
        io.write_public(result, deadline_boottime_ns=deadline)
        check()
        return 0
    except BaseException:
        return io.fail()


if __name__ == "__main__":
    raise SystemExit(main())
