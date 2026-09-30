#!/usr/bin/env python3
"""Sign one independently approved initial native GenerationInstall grant.

Run python3 -I -B with --input-fd for the complete protected public object and
--authority-key-fd for the existing matching sealed root:root0400 32-byte
supervisor seed. No key generation, authority selection, publication or launch.
See native_pilot_generation_install_authority.INPUT_FIELDS and sign for the
closed grammar. Supplied epoch 1/empty predecessors, all five authenticated
initial scopes, supplied empty recordOriginals and sequence-zero genesis-bound
journal are mandatory. Historical/recovery authoring is not supported and no
full-project acceptance checkpoint is closed by this producer.

Use the original admitted host/time namespace. Stdout is at most 65536 bytes,
the unchanged signed canonical original without LF. No retry after partial or
lost output. An external supervisor must bound blocking filesystem/crypto work.
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
from serverware import native_pilot_generation_install_authority as authority
from serverware import native_shadow_nitro_originals as originals

p = authority.p


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError("native generation-install arguments refused")


def main():
    try:
        parser = Parser(description=__doc__, allow_abbrev=False)
        parser.add_argument("--input-fd", type=int, required=True)
        parser.add_argument("--authority-key-fd", type=int, required=True)
        args = parser.parse_args()
        p.require(args.input_fd >= 3 and args.authority_key_fd >= 3 and args.input_fd != args.authority_key_fd)
        input_identity = originals._identity(os.fstat(args.input_fd))
        key_identity = originals._identity(os.fstat(args.authority_key_fd))
        raw = io.read_public(args.input_fd, authority.MAX_INPUT_BYTES)
        key = io.signing_key(args.authority_key_fd)
        boot = originals._boot()
        before_wall = time.time_ns()
        payload = None

        def check():
            p.require(originals._identity(os.fstat(args.input_fd)) == input_identity
                and originals._identity(os.fstat(args.authority_key_fd)) == key_identity
                and io.read_public(args.input_fd, authority.MAX_INPUT_BYTES) == raw
                and originals._boot() == boot and before_wall <= time.time_ns())
            if payload is not None:
                p.freshness(payload["issuedAtUnixNanos"], payload["expiresAtUnixNanos"], time.time_ns())

        check()
        signed, deadline = authority.sign(input_original=raw, signing_key=key)
        payload = p.document(signed, authority.MAX_BYTES)["payload"]
        check()
        io.write_public(signed, deadline_boottime_ns=deadline)
        check()
        p.require(originals._clock() < deadline)
        return 0
    except Exception:
        return io.fail()


if __name__ == "__main__":
    raise SystemExit(main())
