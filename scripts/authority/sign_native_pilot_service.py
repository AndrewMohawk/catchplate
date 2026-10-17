#!/usr/bin/env python3
"""Sign one independently approved ordinary pilot service original.

Use python3 -I -B with a complete approved canonical public input on --input-fd
and the matching already provisioned sealed root:root0400 32-byte authority
memfd on --authority-key-fd. No key, peer, history, payload or deadline is
generated. Stdout is the unchanged existing signed-envelope format, without LF.
See native_pilot_service_authority.sign for the closed per-operation fields.
An external supervisor must bound blocking filesystem/crypto operations; output
loss or partial output is never permission to retry an authority operation.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys

_SCRIPT = Path(__file__).resolve().parent
sys.path.insert(0, str(_SCRIPT))
sys.path.insert(0, str(_SCRIPT.parent.parent))

import native_pilot_authority_io as io
from catchplate import native_pilot_service_authority as authority
from catchplate import native_shadow_nitro_originals as originals

p = authority.p


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError("native pilot service arguments refused")


def main():
    try:
        parser = Parser(description=__doc__, allow_abbrev=False)
        parser.add_argument("--operation", choices=authority.OPERATIONS, required=True)
        parser.add_argument("--role", choices=authority.ROLES, required=True)
        parser.add_argument("--input-fd", type=int, required=True)
        parser.add_argument("--authority-key-fd", type=int, required=True)
        args = parser.parse_args()
        p.require(args.input_fd >= 3 and args.authority_key_fd >= 3 and args.input_fd != args.authority_key_fd)
        input_identity = originals._identity(os.fstat(args.input_fd))
        key_identity = originals._identity(os.fstat(args.authority_key_fd))
        raw = io.read_public(args.input_fd, authority.MAX_INPUT_BYTES)
        key = io.signing_key(args.authority_key_fd)
        boot = originals._boot()

        def check():
            p.require(originals._identity(os.fstat(args.input_fd)) == input_identity
                and originals._identity(os.fstat(args.authority_key_fd)) == key_identity
                and io.read_public(args.input_fd, authority.MAX_INPUT_BYTES) == raw
                and originals._boot() == boot)

        check()
        signed, deadline = authority.sign(operation=args.operation, role=args.role,
                                          input_original=raw, signing_key=key)
        check()
        io.write_public(signed, deadline_boottime_ns=deadline)
        check()
        p.require(originals._clock() < deadline)
        return 0
    except Exception:
        return io.fail()


if __name__ == "__main__":
    raise SystemExit(main())
