#!/usr/bin/env python3
"""Issue one local measured-roster receipt; never complete/native closure."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
USAGE = """Usage: python -I -B scripts/authority/local_closure.py --approval-fd N --approval-sha256 sha256:HEX --trust-fd N --trust-sha256 sha256:HEX --snapshot-fd N --snapshot-sha256 sha256:HEX --source-root-fd N --signing-key-fd N

Root-only trusted-host-local measurement. Supply exact protected root0400 public
approval/trust/genuine snapshot originals, retained frozen source-root FD, and
independently authorized sealed32-byte closure-verifier key. No files are frozen,
keys created, processes launched, or artifact trust high-water advanced here.

Measures the complete selected frozen file tree and independently selected Python
and x86_64 native roster; authenticates ordinary ELF metadata/dependency-name
associations without executing files. NOT exhaustive import/dynamic-loader
coverage, rootfs isolation/pivot, native production admission, TEE, or runtime
attestation. Existing native CompleteClosure/v1 remains separately required.

Writes the distinct signed local receipt to a root-owned pipe. Require complete
output AND exit0. Original BOOTTIME/UNIX limits do not renew; externally bound
kernel IO stalls. Partial signing/output never authorizes automatic retry.
"""


def arguments(argv):
    names = ("approval", "trust", "snapshot")
    flags = [flag for name in names for flag in ("--"+name+"-fd", "--"+name+"-sha256")]
    flags += ["--source-root-fd", "--signing-key-fd"]
    if len(argv) != 16 or argv[::2] != flags:
        raise ValueError("fixed local measured-roster arguments required")
    values = {}
    for flag, raw in zip(argv[::2], argv[1::2]):
        key = flag[2:].replace("-", "_")
        if key.endswith("_fd"):
            value = int(raw)
            if str(value) != raw or not 3 <= value < 2**31:
                raise ValueError("descriptor refused")
        else:
            value = raw
            if len(raw) != 71 or not raw.startswith("sha256:") or any(c not in "0123456789abcdef" for c in raw[7:]):
                raise ValueError("pin refused")
        values[key] = value
    descriptors = [value for key, value in values.items() if key.endswith("_fd")]
    if len(descriptors) != len(set(descriptors)):
        raise ValueError("descriptor alias refused")
    return values


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv == ["--help"]:
        print(USAGE, end=""); return 0
    try:
        selected = arguments(argv)
        from catchplate.authority_local_closure import LocalClosureIssuer
        LocalClosureIssuer(**selected).publish()
        return 0
    except BaseException:
        try:
            import os
            os.write(2, b"local measured roster refused; no complete-closure claim or retry authorized\n")
        except OSError:
            pass
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
