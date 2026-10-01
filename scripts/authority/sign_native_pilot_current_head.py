#!/usr/bin/env python3
"""Sign one separately approved checkpoint-authority current-head decision.

Run with python3 -I -B using a protected public input FD, its independently
approved SHA-256, and one already provisioned sealed checkpoint-key FD. Neither
possession of those FDs nor a matching digest establishes independent approval
or the provenance/currentness of the supplied trust request. The authority
operator must establish those before invocation; history alone is insufficient.

Require complete output AND successful exit. Partial or uncertain output never
permits retry. No key, currentness decision, observation or runtime is generated.
An external supervisor bounds filesystem/crypto stalls. Python/OpenSSL copies
are not hardware custody or guaranteed-erased memory.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import native_pilot_authority_io as io
from serverware import native_pilot_current_head_authority as authority
from serverware import native_pilot_current_head_profile as profile
from serverware import native_shadow_nitro_originals as originals


class _Parser(argparse.ArgumentParser):
    def error(self, _message):
        raise ValueError("native pilot current-head invocation refused")


def main():
    try:
        parser = _Parser(description=__doc__, add_help=False, allow_abbrev=False)
        parser.add_argument("--input-fd", type=int, required=True)
        parser.add_argument("--input-sha256", required=True)
        parser.add_argument("--authority-key-fd", type=int, required=True)
        parser.add_argument("--adopted", action="store_true")
        args = parser.parse_args()
        p = authority.p
        p.require(args.input_fd >= 3 and args.authority_key_fd >= 3
            and args.input_fd != args.authority_key_fd)
        digest = p.digest(args.input_sha256)
        input_identity = originals._identity(os.fstat(args.input_fd))
        key_identity = originals._identity(os.fstat(args.authority_key_fd))
        boot, before = originals._boot(), originals._clock()
        raw = io.read_public(args.input_fd, authority.MAX_INPUT)
        p.require(p.sha(raw) == digest)

        def check(deadline):
            nonlocal before
            p.require(originals._identity(os.fstat(args.input_fd)) == input_identity
                and originals._identity(os.fstat(args.authority_key_fd)) == key_identity
                and io.read_public(args.input_fd, authority.MAX_INPUT) == raw
                and originals._boot() == boot)
            now = originals._clock()
            p.require(before <= now < deadline)
            before = now
            return now

        prepared = profile.prepare_input(raw, boot=boot, now_boottime_ns=before, adopted=args.adopted)
        check(prepared["deadline"])
        key = io.signing_key(args.authority_key_fd)
        try:
            check(prepared["deadline"])
            output, deadline = authority.sign(input_original=raw, signing_key=key, adopted=args.adopted)
        finally:
            del key
        p.require(deadline == prepared["deadline"] and len(output) <= authority.MAX_OUTPUT)
        result = {"original": output.decode("ascii"), "sha256": p.sha(output)}
        now = check(deadline)
        p.require(profile.checked_result(raw, result, boot=boot, now_boottime_ns=now, adopted=args.adopted) == output)
        check(deadline)
        io.write_public(output, deadline_boottime_ns=deadline)
        check(deadline)
        return 0
    except BaseException:
        return io.fail()


if __name__ == "__main__":
    raise SystemExit(main())
