#!/usr/bin/env python3
"""Prepare one unsigned, static eleven-guest closure set from pinned inputs.

Run python3 -I -B with a canonical public preparation original in an already
opened root:root0400 FD. The independently selected input pin binds those exact
bytes; this command does not authenticate who approved the pin. Output is one
canonical no-LF closure set on a root supervisor pipe. No key, signature,
installation, process launch, measured identity or startup deadline is created.
An external supervisor must bound filesystem stalls and reject partial output.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

_SCRIPT = Path(__file__).resolve().parent
sys.path.insert(0, str(_SCRIPT))
sys.path.insert(0, str(_SCRIPT.parent.parent))

import native_pilot_authority_io as io
from serverware import native_pilot_closure_set as closure_set

p = closure_set.p
INPUT_API = "serverware.nativePilotClosureSetPreparation/v1"


class Parser(argparse.ArgumentParser):
    def error(self, _message):
        raise ValueError("native pilot closure-set preparation refused")


def prepare(input_original: bytes, expected_sha256: str) -> bytes:
    """Pure preparation only; the caller separately owns input-pin authority."""
    p.require(type(input_original) is bytes and 0 < len(input_original) <= closure_set.MAX_BYTES
        and p.sha(input_original) == p.digest(expected_sha256))
    value = json.loads(input_original.decode("ascii"), object_pairs_hook=p._pairs,
        parse_float=p._reject, parse_constant=p._reject)
    p.fields(value, ("apiVersion", "members"))
    p.require(value["apiVersion"] == INPUT_API)
    result = closure_set.set_original(value["members"])
    # The producer validates each manifest under its own existing node bound.
    # Do not accidentally pool eleven manifests into one smaller document cap.
    p.require(json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True,
        separators=(",", ":")).encode("ascii") == input_original)
    return result


def main():
    try:
        parser = Parser(description=__doc__, add_help=False, allow_abbrev=False)
        parser.add_argument("--input-fd", type=int, required=True)
        parser.add_argument("--input-sha256", required=True)
        args = parser.parse_args()
        p.require(args.input_fd >= 3)
        identity = io._identity(os.fstat(args.input_fd))
        raw = io.read_public(args.input_fd, closure_set.MAX_BYTES)
        result = prepare(raw, args.input_sha256)

        def check():
            p.require(io._identity(os.fstat(args.input_fd)) == identity
                and io.read_public(args.input_fd, closure_set.MAX_BYTES) == raw)

        check()
        io.write_public(result)
        check()
        return 0
    except BaseException:
        return io.fail()


if __name__ == "__main__":
    raise SystemExit(main())
