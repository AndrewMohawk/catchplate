#!/usr/bin/env python3
"""Sign the actual bounded measurement of one already frozen local CAS tree."""
from __future__ import annotations

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

USAGE = """Usage: python -I -B scripts/authority/local_snapshot.py \
--approval-fd N --approval-sha256 sha256:HEX --trust-fd N --trust-sha256 sha256:HEX \
--source-root-fd N --signing-key-fd N

Root-only, fixed local issuer. Public originals must be protected root:root0400;
the independently authorized snapshot key must be an already sealed32-byte FD.
The selected CAS tree must already be immutable/read-only and named by its exact
tree digest. This command never freezes files, creates keys or advances trust.
Writes one actual snapshot receipt to a root-owned pipe, not closure/provenance
or installation evidence. Require complete output AND successful exit; preserve
partial output on failure, never retry. An external supervisor bounds I/O stalls.
"""


def arguments(argv):
    names = ["--approval-fd", "--approval-sha256", "--trust-fd", "--trust-sha256",
             "--source-root-fd", "--signing-key-fd"]
    if len(argv) != 12 or argv[::2] != names:
        raise ValueError("fixed snapshot arguments required")
    result = dict(zip((name[2:].replace("-", "_") for name in names), argv[1::2]))
    for name in ("approval_fd", "trust_fd", "source_root_fd", "signing_key_fd"):
        raw = result[name]
        result[name] = int(raw)
        if str(result[name]) != raw or not 3 <= result[name] < 2**31:
            raise ValueError("snapshot descriptor refused")
    return result


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv == ["--help"]:
        print(USAGE, end="")
        return 0
    try:
        selected = arguments(argv)
        from catchplate.authority_local_snapshot import LocalSnapshotIssuer
        LocalSnapshotIssuer(**selected).publish()
        return 0
    except BaseException:
        try:
            import os
            os.write(2, b"local snapshot refused; no receipt acceptance or retry authorized\n")
        except OSError:
            pass
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
