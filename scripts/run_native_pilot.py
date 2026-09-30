#!/usr/bin/env python3
"""Run the fixed privileged pilot; stdin/stdout must be exclusive machine pipes.

Missing prerequisites refuse launch. Never installs dependencies or credentials,
generates authority, runs supplied commands, retries, or claims test success.
"""
from __future__ import annotations

import argparse
import fcntl
import os
import signal
import sys


def _result(status, phase):
    # Bounded nonblocking best-effort status; diagnostics must never prevent
    # cleanup or dump original contents, paths, keys or exception tracebacks.
    import json
    raw = json.dumps({"apiVersion": "serverware.nativePilotOperatorResult/v1",
        "status": status, "phase": phase, "pilotAcceptanceVerified": False,
        "productionReleaseEligible": False}, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"
    try:
        flags = fcntl.fcntl(2, fcntl.F_GETFL)
        fcntl.fcntl(2, fcntl.F_SETFL, flags | os.O_NONBLOCK)
        os.write(2, raw)
    except OSError:
        pass


def _stop(signum, frame):
    raise KeyboardInterrupt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-native-pilot", required=True, action="store_true",
                        help="explicitly start the fixed pilot with independently provisioned originals")
    parser.parse_args()
    # Use only the sibling installed/checked-out package, never a path supplied
    # over the operator pipe. The installation must be protected by its operator.
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
    owner = None
    failed = False
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    try:
        # The fixed coordinator blocks these across spawn/owner acquisition.
        # Install both handlers before unblocking, and claim no live resources
        # until pending termination has had a chance to run the normal cleanup.
        signal.pthread_sigmask(signal.SIG_UNBLOCK, {signal.SIGTERM, signal.SIGINT})
        from serverware.native_pilot_operator import Operator
        owner = Operator.claim()
        owner.run()
    except BaseException as failure:
        failed = True
        if owner is not None:
            owner._failure = failure  # Retain the exact failure without exposing its text.
    # A second termination request cannot interrupt the sole cleanup attempt.
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    try:
        if owner is not None:
            owner.close()
    except BaseException:
        _result("cleanup-unknown-owner-retained", owner._phase)
        # Exiting would drop held resources without proving retirement. The
        # external supervisor must investigate; there is no retry or extra
        # authority window. SIGKILL can terminate the holder, but cannot turn
        # the unknown outcome into completed cleanup or authorize a restart.
        while True:
            signal.pause()
    _result("failed-cleanup-complete" if failed else "stopped-cleanup-complete",
            "open" if owner is None else owner._phase)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
