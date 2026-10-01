#!/usr/bin/env python3
"""Own the fixed pilot conductor and relay its machine exchanges to its supervisor.

Run only with separately installed/admitted runtime and protected machine pipes.
The independently operated supervisor must approve, sign and install the required
originals before replying. This process supplies no keys, approvals, credentials,
service provisioning, arbitrary command runner or replacement startup window.
It is a concrete process/transport join, not complete authority automation.
"""
from __future__ import annotations

import argparse
import fcntl
import json
import os
from pathlib import Path
import signal
import sys


class _Parser(argparse.ArgumentParser):
    def error(self, _message):
        raise ValueError("native pilot coordinator invocation refused")


def _result(status, phase, interactive_result=None):
    value = {"apiVersion": "serverware.nativePilotCoordinatorResult/v1",
        "status": status, "phase": phase, "pilotAcceptanceVerified": False,
        "productionReleaseEligible": False}
    if status == "stopped-cleanup-complete" and interactive_result is not None:
        value["interactiveResult"] = interactive_result
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"
    try:
        flags = fcntl.fcntl(2, fcntl.F_GETFL)
        fcntl.fcntl(2, fcntl.F_SETFL, flags | os.O_NONBLOCK)
        os.write(2, raw)
    except OSError:
        pass


def _stop(_signum, _frame):
    raise KeyboardInterrupt


def main():
    owner = channel = None
    phase = "open"
    failed = False
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    try:
        if not (sys.flags.isolated and sys.flags.dont_write_bytecode
                and os.getresuid() == (0, 0, 0) and os.getresgid() == (0, 0, 0)):
            raise ValueError("isolated privileged coordinator required")
        parser = _Parser(description=__doc__, allow_abbrev=False, add_help=False)
        modes = parser.add_mutually_exclusive_group(required=True)
        modes.add_argument("--run-native-pilot", action="store_true")
        modes.add_argument("--run-adopted-native-pilot", action="store_true")
        parser.add_argument("--runtime-inventory-fd", required=True, type=int)
        parser.add_argument("--runtime-inventory-sha256", required=True)
        parser.add_argument("--intake-configuration-fd", type=int)
        parser.add_argument("--intake-configuration-sha256")
        args = parser.parse_args()
        # Fixed sibling code only. No module, path or command from the machine
        # channel becomes executable; the operator protects this installation.
        sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
        from serverware import native_shadow_nitro_profile as p
        from serverware.native_pilot_coordinator_process import ConductorProcess, ProcessPreparationError
        from serverware.native_pilot_operator_channel import Channel, STAGES

        p.require((args.intake_configuration_fd is not None) is args.run_adopted_native_pilot
            and (args.intake_configuration_sha256 is not None) is args.run_adopted_native_pilot)
        selected = dict(runtime_inventory_fd=args.runtime_inventory_fd,
            runtime_inventory_sha256=args.runtime_inventory_sha256)
        if args.run_adopted_native_pilot:
            selected.update(intake_configuration_fd=args.intake_configuration_fd,
                intake_configuration_sha256=args.intake_configuration_sha256)
        channel = Channel.open_adopted() if args.run_adopted_native_pilot else Channel.open()
        try:
            owner = (ConductorProcess.prepare_adopted if args.run_adopted_native_pilot else ConductorProcess.prepare)(**selected)
        except ProcessPreparationError as error:
            p.require(type(error.owner) is ConductorProcess)
            owner = error.owner
            raise
        phase = "starting"
        owner.start()
        for sequence, expected_phase in enumerate(STAGES, 1):
            request = owner.receive()
            phase = expected_phase
            p.require(request.sequence == sequence and request.phase == expected_phase)
            payload = request.payload
            # Channel.exchange emits this exact envelope, so the supervisor's
            # reply hash binds the child's original, not a lossy projection.
            value = {"apiVersion": ("serverware.nativePilotOperatorRequest/v2" if args.run_adopted_native_pilot else
                "serverware.nativePilotOperatorRequest/v1"),
                "sequence": sequence, "phase": expected_phase, "payload": payload,
                "deadlineBoottimeNs": str(request.deadline_boottime_ns)}
            bounds = {"deadline_boottime_ns": request.deadline_boottime_ns}
            if args.run_adopted_native_pilot:
                value["expiresAtUnixNanos"] = str(request.expires_at_unix_ns)
                bounds["expires_at_unix_ns"] = request.expires_at_unix_ns
            expected = p.canonical(value)
            p.require(expected == request.raw)
            inputs = channel.exchange(expected_phase, payload, **bounds)
            owner.reply(request, inputs)
        owner.wait_interactive()  # Retain the same child before bounded cleanup.
    except BaseException:
        failed = True

    # One cleanup attempt. A second signal may not discard a retained child or
    # turn an unknown result into success. External supervision remains needed.
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    terminal = None
    try:
        if owner is not None:
            terminal = owner.close(cancel=failed)
    except BaseException:
        _result("cleanup-unknown-owner-retained", phase)
        while True:
            signal.pause()
    if channel is not None:
        try:
            channel.close()
        except BaseException:
            failed = True
    stopped = terminal is not None and terminal.get("status") == "stopped-cleanup-complete"
    if not failed and stopped:
        _result("stopped-cleanup-complete", phase, terminal.get("interactiveResult"))
        return 0
    # A failed startup/no child is not evidence of completed workload cleanup.
    cleaned = terminal is not None and terminal.get("status") in (
        "stopped-cleanup-complete", "failed-cleanup-complete")
    _result("failed-cleanup-complete" if cleaned else "not-started", phase)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
