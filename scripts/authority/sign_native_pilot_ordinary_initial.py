#!/usr/bin/env python3
"""One independently approved step of the ordinary initial-history ceremony.

Run with python3 -I -B. Signing operations load exactly one independently
provisioned sealed root:root0400 key FD; assemble forbids a key FD and only
verifies supplied public originals. No key, approval, process observation or
empty-directory claim is generated. Initial checkpoint output alone is not a
standalone admitted history. An external supervisor bounds blocking work;
partial output grants no retry and Python/OpenSSL copies are not guaranteed
zeroized.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import native_pilot_authority_io as io
from serverware import native_pilot_ordinary_initial_authority as authority
from serverware import native_shadow_nitro_originals as originals


class _Parser(argparse.ArgumentParser):
    def error(self, _message):
        raise ValueError("native pilot ordinary initial arguments refused")


def main():
    try:
        parser = _Parser(description=__doc__, add_help=False, allow_abbrev=False)
        parser.add_argument("--operation", choices=authority.OPERATIONS, required=True)
        parser.add_argument("--input-fd", type=int, required=True)
        parser.add_argument("--authority-key-fd", type=int)
        args = parser.parse_args()
        p = authority.p
        assembling = args.operation == "assemble"
        p.require(args.input_fd >= 3 and (args.authority_key_fd is None if assembling else
            args.authority_key_fd is not None and args.authority_key_fd >= 3
            and args.authority_key_fd != args.input_fd))
        input_identity = originals._identity(os.fstat(args.input_fd))
        key_identity = None if assembling else originals._identity(os.fstat(args.authority_key_fd))
        boot = originals._boot()
        raw = io.read_public(args.input_fd, authority.MAX_INPUT)

        def check():
            p.require(originals._identity(os.fstat(args.input_fd)) == input_identity
                and io.read_public(args.input_fd, authority.MAX_INPUT) == raw and originals._boot() == boot)
            if not assembling:
                p.require(originals._identity(os.fstat(args.authority_key_fd)) == key_identity)

        check()
        if assembling:
            output, deadline = authority.assemble(input_original=raw)
        else:
            key = io.signing_key(args.authority_key_fd)
            check()
            output, deadline = authority.sign(args.operation, input_original=raw, signing_key=key)
            del key
        check()  # Reread the exact approved input before emitting any bytes.
        io.write_public(output, deadline_boottime_ns=deadline)
        check()
        p.require(originals._clock() < deadline)
        return 0
    except BaseException:
        return io.fail()


if __name__ == "__main__":
    raise SystemExit(main())
