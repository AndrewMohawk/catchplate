#!/usr/bin/env python3
"""Sign one independently approved legacy bridge v2 or member v3 closure.

Run python3 -I -B with a complete root:root0400 public input FD and a distinct,
already provisioned sealed root:root0400 32-byte supervisor-capability key FD.
Stdout is the existing full closure original, canonical ASCII without LF, on a
root supervisor pipe. Input/v1 is legacy bridge-only; Input/v2 explicitly binds
one of the eleven fixed roles to signed Assignment/v2 and the complete set.
No legacy v1 endpoint issuer, key generation, install or automatic retry.
Must run on the original admitted boot/time namespace before the original
startup deadline. An independent supervisor must bound filesystem/crypto stalls
and reject failed/partial output; Python/OpenSSL copies are not erased custody.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys
import time

_SCRIPT = Path(__file__).resolve().parent
sys.path.insert(0, str(_SCRIPT))
sys.path.insert(0, str(_SCRIPT.parent.parent))

import native_pilot_authority_io as io
from serverware import native_pilot_closure_authority as authority
from serverware import native_shadow_nitro_originals as originals

p = authority.p


class Parser(argparse.ArgumentParser):
    def error(self, _message):
        raise ValueError("native pilot closure invocation refused")


def main():
    try:
        parser = Parser(description=__doc__, add_help=False, allow_abbrev=False)
        parser.add_argument("--input-fd", type=int, required=True)
        parser.add_argument("--authority-key-fd", type=int, required=True)
        args = parser.parse_args()
        p.require(args.input_fd >= 3 and args.authority_key_fd >= 3 and args.input_fd != args.authority_key_fd)
        input_identity = originals._identity(os.fstat(args.input_fd))
        key_identity = originals._identity(os.fstat(args.authority_key_fd))
        raw = io.read_public(args.input_fd, authority.MAX_BRIDGE_INPUT)
        authority.input_document(raw)  # Version-selected bound, not approval.
        boot, wall = originals._boot(), time.time_ns()
        payload = None
        deadline = None

        def check():
            p.require(originals._identity(os.fstat(args.input_fd)) == input_identity
                and originals._identity(os.fstat(args.authority_key_fd)) == key_identity
                and io.read_public(args.input_fd, authority.MAX_BRIDGE_INPUT) == raw
                and originals._boot() == boot and wall <= time.time_ns())
            if payload is not None:
                p.freshness(payload["issuedAtUnixNanos"], payload["expiresAtUnixNanos"], time.time_ns())
                p.require(originals._clock() < deadline)

        key = io.signing_key(args.authority_key_fd)
        check()
        result, deadline = authority.sign(input_original=raw, signing_key=key)
        payload = p.document(result, authority.MAX_BYTES)["authorization"]["payload"]
        check()
        io.write_public(result, deadline_boottime_ns=deadline)
        check()
        return 0
    except BaseException:
        return io.fail()


if __name__ == "__main__":
    raise SystemExit(main())
