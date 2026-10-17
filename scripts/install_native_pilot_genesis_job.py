#!/usr/bin/env python3
"""Install one independent cold66 approval pair; emit only its existing reply.

Four protected original FD/SHA pairs are required. The caller must buffer stdout
until actual exit zero and consuming reap. No approval, key, directories,
replacement file, deletion or renewed window is produced here.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import signal
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.authority import native_pilot_authority_io as output
from catchplate import native_pilot_genesis_job_install as installation
from catchplate import native_pilot_genesis_parent_control_io as io

p = installation.p
ORIGINALS = ("configuration", "request", "input", "approval")


class _Parser(argparse.ArgumentParser):
    def error(self, _message):
        raise ValueError("cold job installation invocation refused")


def arguments(values):
    p.require(type(values) is list and len(values) == 16 and all(type(value) is str for value in values))
    parser = _Parser(description=__doc__, add_help=False, allow_abbrev=False)
    for name in ORIGINALS:
        parser.add_argument("--" + name + "-fd", required=True, type=int)
        parser.add_argument("--" + name + "-sha256", required=True)
    result = vars(parser.parse_args(values))
    descriptors = []
    for name in ORIGINALS:
        for suffix in ("fd", "sha256"):
            p.require(values.count("--" + name + "-" + suffix) == 1)
        fd = result[name + "_fd"]
        p.integer(fd, minimum=3, maximum=(1 << 31) - 1)
        p.require(values[values.index("--" + name + "-fd") + 1] == str(fd))
        descriptors.append(fd)
        p.digest(result[name + "_sha256"])
    p.require(len(set(descriptors)) == 4)
    return result


def _stop(_signum, _frame):
    raise KeyboardInterrupt


def main():
    owner, failed = None, False
    for number in io.CANCELLATION:
        signal.signal(number, _stop)
    try:
        signal.pthread_sigmask(signal.SIG_UNBLOCK, io.CANCELLATION)
        output._process()
        selected = arguments(sys.argv[1:])
        with io.owning():
            try:
                owner = installation.GenesisJobInstallation.install(**selected)
            except installation.InstallationError as error:
                owner = error.owner
                raise
        raw = p.canonical(owner.reply()) + b"\n"
        output.write_public(raw, deadline_boottime_ns=owner.deadline_boottime_ns, check=owner.check)
        owner.check()
    except BaseException:
        failed = True
    for number in io.CANCELLATION:
        signal.signal(number, signal.SIG_IGN)
    try:
        if owner is not None:
            owner.close()  # Exact inherited sticky close; never unlinks files.
            if not failed:
                p.require(owner._closed and os.getpid() == owner._pid
                    and installation.writer.originals._start() == owner._start
                    and installation.writer.originals._boot() == owner._boot)
                now, wall = installation.writer.originals._clock(), time.time_ns()
                p.require(owner._previous <= now < owner.deadline_boottime_ns and owner._wall <= wall < owner._expiry)
    except BaseException:
        output.fail()
        if owner is not None and not owner._closed:
            while True:
                signal.pause()
        return 1
    return output.fail() if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
