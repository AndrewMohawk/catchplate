#!/usr/bin/env python3
"""Fixed delegated decision worker and explicitly authorized state publication."""
from __future__ import annotations

import fcntl
import json
import os
from pathlib import Path
import re
import signal
import sys

MODE = "current-head-worker"
UPDATE_MODE = "current-head-state-update"
INPUTS = ("supervisor-inventory", "policy")
UPDATE_INPUTS = ("supervisor-inventory", "authorization")
_CANCELLATION = {signal.SIGINT, signal.SIGTERM, signal.SIGHUP}


def _require(value):
    if not value: raise ValueError("native pilot current-head worker invocation refused")


def _arguments(arguments):
    _require(type(arguments) is list and all(type(value) is str for value in arguments)
        and len(arguments) == 9 and arguments[0] in (MODE, UPDATE_MODE))
    mode = arguments[0]
    inputs = INPUTS if mode == MODE else UPDATE_INPUTS
    selected, descriptors = {}, set()
    for index, name in enumerate(inputs):
        flag, number, pin_flag, pin = arguments[1 + 4 * index:5 + 4 * index]
        _require(flag == "--" + name + "-fd" and re.fullmatch(r"[1-9][0-9]{0,9}", number) is not None
            and 3 <= int(number) < (1 << 31) and int(number) not in descriptors
            and pin_flag == "--" + name + "-sha256" and re.fullmatch(r"sha256:[0-9a-f]{64}", pin) is not None)
        descriptors.add(int(number))
        selected.update({name.replace("-", "_") + "_fd": int(number),
            name.replace("-", "_") + "_sha256": pin})
    return mode, selected


def _stop(_number, _frame):
    raise KeyboardInterrupt


def _report(status, mode, owner, completed):
    # A failed update may have left durable state/audit files. Known descriptor
    # cleanup never claims that publication did not happen or authorizes retry.
    value = dict(apiVersion="catchplate.nativePilotCurrentHeadWorkerResult/v1",
        mode=mode, status=status, stage="opening" if owner is None else owner.stage,
        decisionsPublished=0 if owner is None or mode != MODE else owner.decisions,
        stateUpdateOutcome=("completed" if completed else "not-established")
            if mode == UPDATE_MODE else "not-selected",
        pilotAcceptanceVerified=False, productionReleaseEligible=False)
    try:
        raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"
        _require(len(raw) <= 4096)
        fcntl.fcntl(2, fcntl.F_SETFL, fcntl.fcntl(2, fcntl.F_GETFL) | os.O_NONBLOCK)
        return os.write(2, raw) == len(raw)
    except (OSError, ValueError):
        return False


def main():
    owner, mode, completed = None, "unselected", False
    for number in _CANCELLATION: signal.signal(number, _stop)
    try:
        signal.pthread_sigmask(signal.SIG_UNBLOCK, _CANCELLATION)
        _require(sys.flags.isolated == 1 and sys.flags.dont_write_bytecode == 1
            and os.getresuid() == os.getresgid() == (0, 0, 0))
        mode, selected = _arguments(sys.argv[1:])
        sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
        from catchplate import native_pilot_genesis_parent_control_io as ownership
        if mode == MODE:
            from catchplate.native_pilot_current_head_worker import CurrentHeadWorker, CurrentHeadWorkerError
            owner_type, owner_error = CurrentHeadWorker, CurrentHeadWorkerError
        else:
            from catchplate.native_pilot_current_head_state import CurrentHeadStatePublisher, CurrentHeadStatePublisherError
            owner_type, owner_error = CurrentHeadStatePublisher, CurrentHeadStatePublisherError
        with ownership.owning():
            try: owner = owner_type.open(**selected)
            except owner_error as error:
                owner = error.owner
                _require(type(owner) is owner_type)
                raise
        owner.run()
        completed = True
    except BaseException:
        completed = False
    for number in _CANCELLATION: signal.signal(number, signal.SIG_IGN)
    try:
        if owner is not None: owner.close()
    except BaseException:
        _report("cleanup-unknown-owner-retained", mode, owner, False)
        while True: signal.pause()
    status = ("complete-eight-decisions" if mode == MODE else "complete-state-update") if completed else "failed-cleanup-complete"
    reported = _report(status, mode, owner, completed)
    return 0 if completed and reported else 1


if __name__ == "__main__":
    raise SystemExit(main())
