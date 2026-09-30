#!/usr/bin/env python3
"""Sign one independently approved direct-next ordinary key checkpoint.

Run with python3 -I -B. Public input is a protected approved original; the key
is an independently supplied sealed root:root0400 32-byte checkpoint-authority
FD. The fresh-history issuer verifies the real three-party retained anchor.
It does not create that anchor, any key/history/predecessor, or a live service.
An external supervisor must bound blocking work. Partial output is not retry
permission, and Python/OpenSSL copies are not guaranteed zeroized.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import native_pilot_authority_io as io
from serverware import native_pilot_ordinary_key_authority as authority
from serverware import native_shadow_nitro_originals as originals


class _Parser(argparse.ArgumentParser):
    def error(self, _message):
        raise ValueError("native pilot ordinary key arguments refused")


def main():
    try:
        parser = _Parser(description=__doc__, add_help=False, allow_abbrev=False)
        parser.add_argument("--input-fd", type=int, required=True)
        parser.add_argument("--authority-key-fd", type=int, required=True)
        args = parser.parse_args()
        p = authority.p
        p.require(args.input_fd >= 3 and args.authority_key_fd >= 3 and args.input_fd != args.authority_key_fd)
        input_identity = originals._identity(os.fstat(args.input_fd))
        key_identity = originals._identity(os.fstat(args.authority_key_fd))
        boot = originals._boot()
        raw = io.read_public(args.input_fd, authority.MAX_INPUT)
        key = io.signing_key(args.authority_key_fd)

        def check():
            p.require(originals._identity(os.fstat(args.input_fd)) == input_identity
                and originals._identity(os.fstat(args.authority_key_fd)) == key_identity
                and io.read_public(args.input_fd, authority.MAX_INPUT) == raw and originals._boot() == boot)

        check()
        signed, deadline = authority.sign(input_original=raw, signing_key=key)
        del key
        check()  # Re-read the exact approved FD before any signed output.
        io.write_public(signed, deadline_boottime_ns=deadline)
        check()
        p.require(originals._clock() < deadline)
        return 0
    except BaseException:
        return io.fail()


if __name__ == "__main__":
    raise SystemExit(main())
