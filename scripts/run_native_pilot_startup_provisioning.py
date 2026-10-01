#!/usr/bin/env python3
"""Fixed public startup provisioning under independently pinned delegation.

This command supplies no key, state baseline, generic destination or launch
command. Complete public publication is not process admission or pilot proof.
Partial files remain; known descriptor cleanup never authorizes retry/reset.
"""
from __future__ import annotations

import fcntl
import json
import os
from pathlib import Path
import re
import signal
import sys

MODE = "startup-provisioning"
INPUTS = ("supervisor-inventory", "delegation", "configuration", "recipe",
    "conductor-inventory", "authority-inventory")
RESULT_API = "serverware.nativePilotStartupProvisioningResult/v1"
STATUSES = ("complete-public-provisioning", "failed-cleanup-complete", "cleanup-unknown-owner-retained")
_CANCELLATION = {signal.SIGINT, signal.SIGTERM, signal.SIGHUP}


def _require(value):
    if not value: raise ValueError("native pilot startup provisioning invocation refused")


def _arguments(arguments):
    _require(type(arguments) is list and all(type(value) is str for value in arguments)
        and len(arguments) == 1 + 4 * len(INPUTS) and arguments[0] == MODE)
    selected, descriptors = {}, set()
    for index, name in enumerate(INPUTS):
        flag, number, pin_flag, pin = arguments[1 + 4 * index:5 + 4 * index]
        _require(flag == "--" + name + "-fd" and re.fullmatch(r"[1-9][0-9]{0,9}", number) is not None
            and 3 <= int(number) < (1 << 31) and int(number) not in descriptors
            and pin_flag == "--" + name + "-sha256" and re.fullmatch(r"sha256:[0-9a-f]{64}", pin) is not None)
        descriptors.add(int(number))
        selected.update({name.replace("-", "_") + "_fd": int(number),
            name.replace("-", "_") + "_sha256": pin})
    return selected


def _stop(_number, _frame):
    raise KeyboardInterrupt


def _result(status, stage, published, admission_sha256):
    """Bounded terminal data only; never a publication/authority owner."""
    _require(status in STATUSES and type(stage) is str and stage.isascii() and 1 <= len(stage) <= 128
        and type(published) is int and 0 <= published <= 7)
    if status == "complete-public-provisioning":
        _require(published == 7 and type(admission_sha256) is str
            and re.fullmatch(r"sha256:[0-9a-f]{64}", admission_sha256) is not None)
    else:
        _require(admission_sha256 is None)
    return dict(apiVersion=RESULT_API, status=status, stage=stage, publishedOriginals=published,
        admissionSha256=admission_sha256, provisioningOutcome="completed" if status == STATUSES[0] else "not-established",
        pilotAcceptanceVerified=False, productionReleaseEligible=False)


def _report(status, owner, completed):
    try:
        value = _result(status, "opening" if owner is None else owner.stage,
            0 if owner is None else owner.published,
            owner.admission_sha256 if completed and owner is not None else None)
        raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii") + b"\n"
        _require(len(raw) <= 4096)
        fcntl.fcntl(2, fcntl.F_SETFL, fcntl.fcntl(2, fcntl.F_GETFL) | os.O_NONBLOCK)
        return os.write(2, raw) == len(raw)
    except (OSError, ValueError, TypeError, AttributeError):
        return False


def main():
    owner, failure, cleanup_failure, completed = None, None, None, False
    for number in _CANCELLATION: signal.signal(number, _stop)
    try:
        signal.pthread_sigmask(signal.SIG_UNBLOCK, _CANCELLATION)
        _require(sys.flags.isolated == 1 and sys.flags.dont_write_bytecode == 1
            and os.getresuid() == os.getresgid() == (0, 0, 0))
        selected = _arguments(sys.argv[1:])
        sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
        from serverware import native_pilot_genesis_parent_control_io as ownership
        from serverware.native_pilot_startup_provisioning import StartupProvisioner, StartupProvisionerError
        with ownership.owning():
            try: owner = StartupProvisioner.open(**selected)
            except StartupProvisionerError as error:
                owner = error.owner
                _require(type(owner) is StartupProvisioner)
                raise
        owner.run()
        completed = True
    except BaseException as error:
        failure = error  # Retain any partial-acquisition traceback until actual cleanup.
        completed = False
    for number in _CANCELLATION: signal.signal(number, signal.SIG_IGN)
    try:
        if owner is not None: owner.close()
    except BaseException as error:
        cleanup_failure = error
        _report("cleanup-unknown-owner-retained", owner, False)
        while True: signal.pause()
    status = "complete-public-provisioning" if completed else "failed-cleanup-complete"
    reported = _report(status, owner, completed)
    return 0 if completed and reported else 1


if __name__ == "__main__":
    raise SystemExit(main())
