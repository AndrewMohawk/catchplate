#!/usr/bin/env python3
"""Issue an independently approved original driver window; no generated fields.

Requires python3 -I -B and the existing protected public/key FD contract.
No installer, key generation, timestamp refresh or automatic retry is provided.
The supervisor must reject incomplete output and any nonzero exit, and retain
an external bound on filesystem/cryptographic stalls.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import native_pilot_authority_io as io
from serverware import native_pilot_window_authority as authority
from serverware import native_shadow_nitro_originals as originals


class _Parser(argparse.ArgumentParser):
    def error(self, _message):
        raise ValueError("native pilot window invocation refused")


def main():
    try:
        parser = _Parser(description=__doc__, add_help=False, allow_abbrev=False)
        parser.add_argument("--input-fd", type=int, required=True)
        parser.add_argument("--authority-key-fd", type=int, required=True)
        args = parser.parse_args()
        p = authority.p
        p.require(args.input_fd >= 3 and args.authority_key_fd >= 3 and args.input_fd != args.authority_key_fd)
        input_identity = io._input(args.input_fd, authority.MAX_INPUT)
        key_identity = io._input(args.authority_key_fd, 32, private=True)
        owner = os.getpid(), originals._start(), originals._boot()
        before = originals._clock()
        raw = io.read_public(args.input_fd, authority.MAX_INPUT)
        result = authority.sign(raw, io.signing_key(args.authority_key_fd))
        payload = p.document(result, authority.MAX_WINDOW)["payload"]
        deadline = p.ns(payload["startupDeadlineBoottimeNs"])

        def check():
            p.require(io._input(args.input_fd, authority.MAX_INPUT) == input_identity
                and io._input(args.authority_key_fd, 32, private=True) == key_identity
                and io.read_public(args.input_fd, authority.MAX_INPUT) == raw
                and owner == (os.getpid(), originals._start(), originals._boot())
                and before <= originals._clock() < deadline)

        check()
        io.write_public(result, deadline_boottime_ns=deadline)
        check()
        return 0
    except BaseException:
        return io.fail()


if __name__ == "__main__":
    raise SystemExit(main())
