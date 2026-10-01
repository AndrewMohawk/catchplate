#!/usr/bin/env python3
"""Installed fixed-eight operator decision service; no keys or auto-approval."""
from __future__ import annotations

import fcntl
import json
import os
from pathlib import Path
import re
import signal
import sys

MODE = "current-head-decision-service"
INPUTS = ("supervisor-inventory", "configuration")
_PREFIX = tuple((name + suffix, kind) for name in INPUTS for suffix, kind in
    (("-fd", "fd"), ("-sha256", "sha"))) + (("approval-socket-fd", "fd"),)
_CANCELLATION = {signal.SIGINT, signal.SIGTERM, signal.SIGHUP}


def _require(value):
    if not value: raise ValueError("native pilot current-head service invocation refused")


def _arguments(arguments):
    _require(type(arguments) is list and all(type(value) is str for value in arguments)
        and len(arguments) == 1 + 2 * len(_PREFIX) and arguments[0] == MODE)
    selected, descriptors = {}, set()
    for index, (name, kind) in enumerate(_PREFIX):
        flag, value = arguments[1 + 2 * index:3 + 2 * index]
        _require(flag == "--" + name)
        if kind == "sha":
            _require(re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None)
        else:
            _require(re.fullmatch(r"[1-9][0-9]{0,9}", value) is not None)
            value = int(value)
            _require(3 <= value < (1 << 31) and value not in descriptors)
            descriptors.add(value)
        selected[name.replace("-", "_")] = value
    return selected


def _stop(_number, _frame):
    raise KeyboardInterrupt


def _report(status, owner):
    raw = json.dumps(dict(apiVersion="serverware.nativePilotCurrentHeadDecisionServiceResult/v1",
        status=status, stage="opening" if owner is None else owner.stage,
        decisionsDelivered=0 if owner is None else owner.decisions,
        pilotAcceptanceVerified=False, productionReleaseEligible=False),
        sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"
    try:
        _require(len(raw) <= 4096)
        fcntl.fcntl(2, fcntl.F_SETFL, fcntl.fcntl(2, fcntl.F_GETFL) | os.O_NONBLOCK)
        return os.write(2, raw) == len(raw)
    except (OSError, ValueError):
        return False


def main():
    owner, completed = None, False
    for number in _CANCELLATION: signal.signal(number, _stop)
    try:
        signal.pthread_sigmask(signal.SIG_UNBLOCK, _CANCELLATION)
        _require(sys.flags.isolated == 1 and sys.flags.dont_write_bytecode == 1
            and os.getresuid() == (0, 0, 0) and os.getresgid() == (0, 0, 0))
        selected = _arguments(sys.argv[1:])
        sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
        from serverware import native_pilot_genesis_parent_control_io as ownership
        from serverware.native_pilot_current_head_decision_service import (
            CurrentHeadDecisionService, CurrentHeadDecisionServiceError)
        with ownership.owning():
            try:
                owner = CurrentHeadDecisionService.open(**selected)
            except CurrentHeadDecisionServiceError as error:
                owner = error.owner
                _require(type(owner) is CurrentHeadDecisionService)
                raise
        owner.run()
        completed = True
    except BaseException:
        completed = False
    for number in _CANCELLATION: signal.signal(number, signal.SIG_IGN)
    try:
        if owner is not None: owner.close()
    except BaseException:
        _report("cleanup-unknown-owner-retained", owner)
        while True: signal.pause()
    reported = _report("complete-eight-decisions" if completed else "failed-cleanup-complete", owner)
    return 0 if completed and reported else 1


if __name__ == "__main__":
    raise SystemExit(main())
