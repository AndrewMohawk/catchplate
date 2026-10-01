#!/usr/bin/env python3
"""Sign one independently approved cold-parent precreation or release original.

Invoke with python3 -I -B, a protected public input FD plus independently
approved SHA-256, and one provisioned sealed key FD. These FDs and pins do not
establish approval or live observation provenance. The operator must establish
those independently, including the actual retained parked child for release.
Require complete output AND successful exit; partial or uncertain output is
terminal, never permission to retry. An external owner bounds filesystem and
crypto stalls. No key, timestamp, PID, image, C9 or approval is generated here.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import native_pilot_authority_io as io
from serverware import native_pilot_genesis_parent_authority as authority
from serverware import native_shadow_nitro_originals as originals


class _Parser(argparse.ArgumentParser):
    def error(self, _message):
        raise ValueError("native pilot genesis parent invocation refused")


def main():
    try:
        parser = _Parser(description=__doc__, add_help=False, allow_abbrev=False)
        parser.add_argument("--operation", choices=authority.OPERATIONS, required=True)
        parser.add_argument("--input-fd", type=int, required=True)
        parser.add_argument("--input-sha256", required=True)
        parser.add_argument("--authority-key-fd", type=int, required=True)
        args = parser.parse_args()
        p = authority.p
        p.require(args.input_fd >= 3 and args.authority_key_fd >= 3 and args.input_fd != args.authority_key_fd)
        digest = p.digest(args.input_sha256)
        input_identity = originals._identity(os.fstat(args.input_fd))
        key_identity = originals._identity(os.fstat(args.authority_key_fd))
        boot, before = originals._boot(), originals._clock()
        raw = io.read_public(args.input_fd, authority.MAX_INPUT)
        p.require(p.sha(raw) == digest and authority.input_document(raw)["operation"] == args.operation)

        def check(deadline):
            nonlocal before
            p.require(originals._identity(os.fstat(args.input_fd)) == input_identity
                and originals._identity(os.fstat(args.authority_key_fd)) == key_identity
                and io.read_public(args.input_fd, authority.MAX_INPUT) == raw and originals._boot() == boot)
            now = originals._clock()
            p.require(before <= now < deadline)
            before = now
            return now

        prepared = authority.prepare_input(raw, boot=boot, now_boottime_ns=before)
        check(prepared["deadline"])
        key = io.signing_key(args.authority_key_fd)
        try:
            check(prepared["deadline"])
            output, deadline = authority.sign(input_original=raw, signing_key=key)
        finally:
            del key
        p.require(deadline == prepared["deadline"] and len(output) <= authority.MAX_OUTPUT)
        now = check(deadline)
        p.require(authority.checked_result(raw, {"original": output.decode("ascii"), "sha256": p.sha(output)},
            boot=boot, now_boottime_ns=now) == output)
        check(deadline)
        io.write_public(output, deadline_boottime_ns=deadline)
        check(deadline)
        return 0
    except BaseException:
        return io.fail()


if __name__ == "__main__":
    raise SystemExit(main())
