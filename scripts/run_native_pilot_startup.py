#!/usr/bin/env python3
"""Fixed three-process startup; independent late admission is still required."""
from __future__ import annotations

import fcntl
import json
import os
from pathlib import Path
import re
import signal
import sys

MODE = "commissioning-startup"
INPUTS = ("configuration", "supervisor-inventory")
_CANCELLATION = {signal.SIGINT, signal.SIGTERM, signal.SIGHUP}


def _require(value):
    if not value: raise ValueError("native pilot startup invocation refused")


def _number(value):
    _require(type(value) is str and re.fullmatch(r"[1-9][0-9]{0,9}", value) is not None)
    number = int(value)
    _require(3 <= number < (1 << 31))
    return number


def _arguments(arguments, cold_purposes, adopted_purposes):
    groups = (("cold", cold_purposes, 36), ("adopted", adopted_purposes, 123))
    for _, purposes, count in groups:
        _require(type(purposes) is tuple and len(purposes) == len(set(purposes)) == count
            and all(type(name) is str and re.fullmatch(r"[A-Za-z][A-Za-z0-9-]{0,127}", name) for name in purposes))
    offset = 1 + 4 * len(INPUTS)
    _require(type(arguments) is list and all(type(value) is str for value in arguments)
        and len(arguments) == offset + 2 * sum(count for _, _, count in groups) and arguments[0] == MODE)
    selected, public = {}, set()
    for index, name in enumerate(INPUTS):
        flag, number, pin_flag, pin = arguments[1 + 4 * index:5 + 4 * index]
        _require(flag == "--" + name + "-fd" and pin_flag == "--" + name + "-sha256"
            and re.fullmatch(r"sha256:[0-9a-f]{64}", pin) is not None)
        descriptor = _number(number)
        _require(descriptor not in public); public.add(descriptor)
        selected.update({name.replace("-", "_") + "_fd": descriptor,
            name.replace("-", "_") + "_sha256": pin})
    for family, purposes, _ in groups:
        keys = {}
        for purpose in purposes:
            flag, value = arguments[offset:offset + 2]; offset += 2
            _require(flag == "--" + family + "-authority-key" and value.startswith(purpose + "="))
            descriptor = _number(value[len(purpose) + 1:])
            _require(descriptor not in public)
            keys[purpose] = descriptor  # Existing purpose admissions permit shared key FDs.
        selected[family + "_authority_key_fds"] = keys
    return selected


def _stop(_number, _frame):
    raise KeyboardInterrupt


def _report(status, stage):
    raw = json.dumps(dict(apiVersion="catchplate.nativePilotStartupResult/v1", status=status, stage=stage,
        pilotAcceptanceVerified=False, productionReleaseEligible=False),
        sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"
    try:
        _require(len(raw) <= 4096)
        fcntl.fcntl(2, fcntl.F_SETFL, fcntl.fcntl(2, fcntl.F_GETFL) | os.O_NONBLOCK)
        return os.write(2, raw) == len(raw)
    except (OSError, ValueError):
        return False


def main():
    owner, completed, stage = None, False, "opening"
    for number in _CANCELLATION: signal.signal(number, _stop)
    try:
        signal.pthread_sigmask(signal.SIG_UNBLOCK, _CANCELLATION)
        _require(sys.flags.isolated == 1 and sys.flags.dont_write_bytecode == 1
            and os.getresuid() == os.getresgid() == (0, 0, 0))
        sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
        from catchplate import native_pilot_genesis_jobs as cold
        from catchplate import native_pilot_adopted_phase_profile as adopted
        from catchplate import native_pilot_genesis_parent_control_io as ownership
        from catchplate.native_pilot_startup import Startup, StartupError
        selected = _arguments(sys.argv[1:], cold.KEY_PURPOSES, adopted.KEY_PURPOSES)
        keys = {name: selected.pop(name) for name in ("cold_authority_key_fds", "adopted_authority_key_fds")}
        with ownership.owning():
            try: owner = Startup.prepare(**selected)
            except StartupError as error:
                owner = error.owner
                _require(type(owner) is Startup)
                raise
        stage = "connecting-real-children"
        owner.start()
        stage = "waiting-independent-admission"
        owner.wait_admission(**keys)
        stage = "running-existing-roles"
        owner.finish()
        completed = True
    except BaseException:
        completed = False
    for number in _CANCELLATION: signal.signal(number, signal.SIG_IGN)
    try:
        if owner is not None:
            result = owner.close(cancel=not completed)
            _require(type(result) is dict and result.get("status") == "closed")
    except BaseException:
        _report("cleanup-unknown-owner-retained", stage)
        while True: signal.pause()
    reported = _report("stopped-cleanup-complete" if completed else "failed-cleanup-complete", stage)
    return 0 if completed and reported else 1


if __name__ == "__main__":
    raise SystemExit(main())
