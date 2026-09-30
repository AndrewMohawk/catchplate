#!/usr/bin/env python3
"""Sign one independently approved bootstrap/constructed driver admission.

Uses an existing sealed authority key and the closed full-original input grammar
in serverware.native_pilot_driver_authority. No owner reconstruction, approvals,
key generation, installer, changed deadline or automatic retry. The independent
supervisor must reject incomplete output or a failing invocation, and bound
filesystem/crypto work. Python/OpenSSL key copies are not guaranteed zeroized.
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
from serverware import native_pilot_driver_authority as authority
from serverware import native_shadow_nitro_originals as originals


class _Parser(argparse.ArgumentParser):
    def error(self, _message):
        raise ValueError("native pilot driver invocation refused")


def main():
    try:
        parser = _Parser(description=__doc__, add_help=False, allow_abbrev=False)
        parser.add_argument("--operation", choices=("bootstrap", "constructed"), required=True)
        parser.add_argument("--input-fd", type=int, required=True)
        parser.add_argument("--authority-key-fd", type=int, required=True)
        args = parser.parse_args()
        p = authority.p
        p.require(args.input_fd >= 3 and args.authority_key_fd >= 3 and args.input_fd != args.authority_key_fd)
        input_identity = originals._identity(os.fstat(args.input_fd))
        key_identity = originals._identity(os.fstat(args.authority_key_fd))
        boot = originals._boot()
        before = time.time_ns()
        raw = io.read_public(args.input_fd, authority.MAX_INPUT)
        result = authority.sign(args.operation, raw, io.signing_key(args.authority_key_fd))
        payload = p.document(result, 8192 if args.operation == "bootstrap" else 16384)["payload"]

        def check():
            p.require(originals._identity(os.fstat(args.input_fd)) == input_identity
                and originals._identity(os.fstat(args.authority_key_fd)) == key_identity
                and io.read_public(args.input_fd, authority.MAX_INPUT) == raw and originals._boot() == boot
                and before <= time.time_ns() and originals._clock() < p.ns(payload["startupDeadlineBoottimeNs"]))
            p.freshness(payload["issuedAtUnixNanos"], payload["expiresAtUnixNanos"], time.time_ns(), 30_000_000_000)

        check()
        io.write_public(result, deadline_boottime_ns=p.ns(payload["startupDeadlineBoottimeNs"]))
        check()
        return 0
    except BaseException:
        return io.fail()


if __name__ == "__main__":
    raise SystemExit(main())
