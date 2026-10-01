#!/usr/bin/env python3
"""One explicitly approved durable local artifact checkpoint append."""
from __future__ import annotations

from pathlib import Path
import signal
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
USAGE = """Usage: python -I -B scripts/authority/local_artifact_witness.py --approval-fd N --approval-sha256 sha256:HEX --trust-fd N --trust-sha256 sha256:HEX --core-fd N --core-sha256 sha256:HEX --directory-fd N --signing-key-fd N

Root-only trusted-host-local artifact witness, never a runtime replay witness.
Supply independently approved root0400 public originals, a pinned root0700 store
FD, and a sealed32-byte purpose-authorized witness key. Initialization requires
an actually empty store and independently supplied genesis trust; append requires
the exact prior durable head SHA and current artifact trust high-water. No keys,
empty roots, history, package evidence or trust advancement are generated here.

Requires Linux flock/renameat2 and durable regular-file/directory fsync. The local
bounded store supports 4096 generations / 128MiB total. Partial state persists;
there is no retry, reset, repair or deletion. Independently supervise kernel IO
stalls within the original five-minute maximum BOOTTIME/UNIX approval window.
One existing signed checkpoint is written to a root-owned pipe only after the
chain/head are durable, read back and handles known-closed. Require full output
AND exit0. Co-located root administration is not off-host or native trust.
"""


def arguments(argv):
    names = ("approval", "trust", "core")
    flags = [flag for name in names for flag in ("--" + name + "-fd", "--" + name + "-sha256")]
    flags += ["--directory-fd", "--signing-key-fd"]
    if len(argv) != 16 or argv[::2] != flags:
        raise ValueError("fixed artifact witness arguments required")
    result = {}
    for flag, raw in zip(argv[::2], argv[1::2]):
        name = flag[2:].replace("-", "_")
        if name.endswith("_fd"):
            value = int(raw)
            if str(value) != raw or not 3 <= value < 2**31:
                raise ValueError("descriptor refused")
        else:
            value = raw
            if len(raw) != 71 or not raw.startswith("sha256:") or any(c not in "0123456789abcdef" for c in raw[7:]):
                raise ValueError("public pin refused")
        result[name] = value
    fds = [value for name, value in result.items() if name.endswith("_fd")]
    if len(fds) != len(set(fds)):
        raise ValueError("descriptor alias refused")
    return result


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv == ["--help"]:
        print(USAGE, end="")
        return 0
    try:
        selected = arguments(argv)
    except (TypeError, ValueError):
        print("local artifact witness refused: use --help", file=sys.stderr)
        return 2
    from serverware.authority_local_artifact_witness import LocalArtifactWitness
    from scripts.authority import native_pilot_authority_io as io
    owner = None
    def cancelled(signo, frame):
        raise KeyboardInterrupt()
    for signo in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(signo, cancelled)
    try:
        owner = LocalArtifactWitness.open(**selected)
        raw = owner.run()
        io.write_public(raw, deadline_boottime_ns=owner._selected["deadlineBoottimeNs"], check=owner.check_clock)
        return 0
    except BaseException as error:
        owner = getattr(error, "owner", None) or owner
        try:
            if owner is not None:
                owner.close()
        except BaseException:
            print("local witness failed; close uncertain; partial state retained; no retry", file=sys.stderr)
            return 1
        print("local witness failed; partial state retained; no retry or trust advancement", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
