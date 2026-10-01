#!/usr/bin/env python3
"""Create real peer sockets, admit late originals, then run a fixed role in-place."""
from __future__ import annotations

import fcntl
import json
import os
from pathlib import Path
import re
import signal
import sys

MODE = "commissioning-startup-child"
ROLES = ("lifecycle", "provider", "decisions")
INPUTS = ("configuration", "supervisor-inventory")
_CANCELLATION = {signal.SIGINT, signal.SIGTERM, signal.SIGHUP}


def _require(value):
    if not value: raise ValueError("native pilot startup child invocation refused")


def _arguments(arguments):
    _require(type(arguments) is list and all(type(value) is str for value in arguments)
        and len(arguments) == 14 and arguments[0] == MODE and arguments[1] in ROLES)
    selected, descriptors = {"role": arguments[1]}, set()
    for index, name in enumerate(INPUTS):
        flag, number, pin_flag, pin = arguments[2 + 4 * index:6 + 4 * index]
        _require(flag == "--" + name + "-fd" and re.fullmatch(r"[1-9][0-9]{0,9}", number) is not None
            and 3 <= int(number) < (1 << 31) and int(number) not in descriptors
            and pin_flag == "--" + name + "-sha256" and re.fullmatch(r"sha256:[0-9a-f]{64}", pin) is not None)
        descriptors.add(int(number))
        selected.update({name.replace("-", "_") + "_fd": int(number),
            name.replace("-", "_") + "_sha256": pin})
    for offset, name, maximum in ((10, "parent-pid", (1 << 31) - 1),
            (12, "parent-start-time-ticks", (1 << 64) - 1)):
        flag, number = arguments[offset:offset + 2]
        _require(flag == "--" + name and re.fullmatch(r"[1-9][0-9]{0,19}", number) is not None
            and (2 if name == "parent-pid" else 1) <= int(number) <= maximum)
        selected[name.replace("-", "_")] = int(number)
    return selected


def _stop(_number, _frame):
    raise KeyboardInterrupt


def _failure(role, status):
    # No startup originals, descriptors, private data or exception text is logged.
    raw = json.dumps(dict(apiVersion="serverware.nativePilotStartupChildResult/v1",
        role=role, status=status, pilotAcceptanceVerified=False, productionReleaseEligible=False),
        sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"
    try:
        fcntl.fcntl(2, fcntl.F_SETFL, fcntl.fcntl(2, fcntl.F_GETFL) | os.O_NONBLOCK)
        os.write(2, raw)
    except OSError:
        pass


def _run_role(role, arguments):
    """A source-selected function call, not an exec or caller-selected module."""
    if role == "lifecycle":
        from scripts import run_native_pilot_lifecycle as cli
    elif role == "provider":
        from scripts import run_native_pilot_approval_provider as cli
    else:
        _require(role == "decisions")
        from scripts import run_native_pilot_current_head_decisions as cli
    _require(arguments[0] == cli.MODE)
    sys.argv = [cli.__file__, *arguments]
    return cli.main()


def main():
    owner, role, outcome, returned = None, "unselected", 1, False
    entered, retained_error = False, None
    for number in _CANCELLATION: signal.signal(number, _stop)
    try:
        signal.pthread_sigmask(signal.SIG_UNBLOCK, _CANCELLATION)
        _require(sys.flags.isolated == 1 and sys.flags.dont_write_bytecode == 1
            and os.getresuid() == os.getresgid() == (0, 0, 0))
        selected = _arguments(sys.argv[1:]); role = selected["role"]
        sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
        from serverware import native_pilot_genesis_parent_control_io as ownership
        from serverware.native_pilot_startup_child import StartupChild, StartupChildError
        with ownership.owning():
            try: owner = StartupChild.open(**selected)
            except StartupChildError as error:
                owner = error.owner
                _require(type(owner) is StartupChild)
                raise
        owner.prepare()
        arguments = owner.admit()
        entered = True
        outcome = _run_role(role, arguments)
        _require(type(outcome) is int and outcome in (0, 1))
        returned = True  # Existing CLI returns only after known local cleanup.
    except BaseException as error:
        retained_error = error  # Keep any unexpected role traceback and its actual owners.
        outcome = 1
    for number in _CANCELLATION: signal.signal(number, signal.SIG_IGN)
    if entered and not returned:
        _failure(role, "cleanup-unknown-owner-retained")
        while True: signal.pause()
    try:
        if owner is not None: owner.close()
    except BaseException:
        _failure(role, "cleanup-unknown-owner-retained")
        while True: signal.pause()
    if not returned: _failure(role, "failed-cleanup-complete")
    return outcome


if __name__ == "__main__":
    raise SystemExit(main())
