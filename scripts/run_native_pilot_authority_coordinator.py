#!/usr/bin/env python3
"""Run fixed pilot jobs under a separately provisioned independent supervisor.

The supervisor must independently approve and install each complete job input
at the source-fixed paths before replying. Root pipes alone are not approval
provenance. This command creates no approval service, keys, credentials or new
windows. Its purpose-key FDs are not passed to the conductor. The existing
transparent run_native_pilot_coordinator.py command remains unchanged.
"""
from __future__ import annotations

import argparse
import fcntl
import json
import os
from pathlib import Path
import signal
import sys
import time


class _Parser(argparse.ArgumentParser):
    def error(self, _message):
        raise ValueError("native pilot authority coordinator invocation refused")


def _stop(_signum, _frame):
    raise KeyboardInterrupt


def _result(status, phase, interactive_result=None, completion=None):
    value = {"apiVersion": "catchplate.nativePilotAuthorityCoordinatorResult/v1", "status": status,
        "phase": phase, "pilotAcceptanceVerified": False, "productionReleaseEligible": False}
    if status == "stopped-cleanup-complete" and interactive_result is not None:
        value["interactiveResult"] = interactive_result
    if completion is not None:
        if status != "stopped-cleanup-complete" or phase != "shutdown":
            return False
        value.update(completion)
        value["apiVersion"] = "catchplate.nativePilotAuthorityCoordinatorResult/v2"
    raw = json.dumps(value,
        sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"
    try:
        if completion is not None:
            now, wall = time.clock_gettime_ns(time.CLOCK_BOOTTIME), time.time_ns()
            expiry = int(completion["expiresAtUnixNanos"])
            action = json.loads(completion["finalResult"]["resultOriginal"])
            if action.get("action") == "run-interactive": expiry = min(expiry, action["expiresAtUnixNanos"])
            if not (len(raw) <= 4096 and now < int(completion["deadlineBoottimeNs"])
                    and wall < expiry):
                return False
        fcntl.fcntl(2, fcntl.F_SETFL, fcntl.fcntl(2, fcntl.F_GETFL) | os.O_NONBLOCK)
        written = os.write(2, raw)
        if completion is not None:
            return written == len(raw) and now <= time.clock_gettime_ns(time.CLOCK_BOOTTIME) < int(completion["deadlineBoottimeNs"]) \
                and wall <= time.time_ns() < expiry
        return written == len(raw)
    except OSError:
        return False


def main():
    if sys.argv[1:2] in (["--run-native-genesis"], ["--run-native-genesis-handoff"], ["--run-native-genesis-listener"],
            ["--run-native-genesis-rendezvous"]):
        # A separate cold profile in the supervisor package. It neither feeds
        # cold jobs into the old conductor nor derives its operational inventory.
        if not (sys.flags.isolated and sys.flags.dont_write_bytecode
                and os.getresuid() == (0, 0, 0) and os.getresgid() == (0, 0, 0)):
            _result("not-started", "open")
            return 1
        sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
        from catchplate.native_pilot_genesis_authority import main as cold_main
        return cold_main(sys.argv[1:])
    owner = executor = channel = None
    phase, failed, adopted = "open", False, False
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    try:
        # The fixed supervisor blocks these only through child/PIDFD/pipe
        # acquisition. Install handlers before unblocking or owning resources.
        signal.pthread_sigmask(signal.SIG_UNBLOCK, {signal.SIGTERM, signal.SIGINT})
        if not (sys.flags.isolated and sys.flags.dont_write_bytecode
                and os.getresuid() == (0, 0, 0) and os.getresgid() == (0, 0, 0)):
            raise ValueError("isolated privileged authority coordinator required")
        parser = _Parser(description=__doc__, allow_abbrev=False, add_help=False)
        selection = parser.add_mutually_exclusive_group(required=True)
        selection.add_argument("--run-native-pilot", action="store_true")
        selection.add_argument("--run-adopted-native-pilot", action="store_true")
        parser.add_argument("--runtime-inventory-fd", required=True, type=int)
        parser.add_argument("--runtime-inventory-sha256", required=True)
        parser.add_argument("--intake-configuration-fd", type=int)
        parser.add_argument("--intake-configuration-sha256")
        parser.add_argument("--authority-key", required=True, action="append")
        args = parser.parse_args()
        sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
        from catchplate import native_shadow_nitro_profile as p
        from catchplate.native_pilot_authority_channel import ApprovalChannel
        from catchplate.native_pilot_coordinator_process import ConductorProcess, ProcessPreparationError
        from catchplate.native_pilot_operator_channel import STAGES
        from catchplate.native_pilot_phase_execution import KEY_PURPOSES, PhaseExecution

        adopted = args.run_adopted_native_pilot
        if adopted:
            from catchplate.native_pilot_adopted_phase_profile import KEY_PURPOSES
            from catchplate.native_pilot_adopted_phase_execution import AdoptedPhaseExecution, require_complete_coverage
            p.require(args.intake_configuration_fd is not None and args.intake_configuration_sha256 is not None
                and args.intake_configuration_fd != args.runtime_inventory_fd)
            p.digest(args.intake_configuration_sha256)
            require_complete_coverage()
            executor_type = AdoptedPhaseExecution
        else:
            p.require(args.intake_configuration_fd is None and args.intake_configuration_sha256 is None)
            executor_type = PhaseExecution

        p.require(len(args.authority_key) == len(KEY_PURPOSES))
        declared = {}
        for literal in args.authority_key:
            p.require(type(literal) is str and literal.count("=") == 1)
            purpose, number = literal.split("=", 1)
            p.require(purpose in KEY_PURPOSES and purpose not in declared and number.isascii()
                and number.isdecimal() and len(number) <= 10)
            fd = int(number)
            p.require(str(fd) == number and 3 <= fd < (1 << 31) and fd != args.runtime_inventory_fd
                and fd != args.intake_configuration_fd)
            declared[purpose] = fd
        channel = ApprovalChannel.open_adopted() if adopted else ApprovalChannel.open()
        try:
            owner = (ConductorProcess.prepare_adopted(runtime_inventory_fd=args.runtime_inventory_fd,
                runtime_inventory_sha256=args.runtime_inventory_sha256,
                intake_configuration_fd=args.intake_configuration_fd,
                intake_configuration_sha256=args.intake_configuration_sha256) if adopted else
                ConductorProcess.prepare(runtime_inventory_fd=args.runtime_inventory_fd,
                    runtime_inventory_sha256=args.runtime_inventory_sha256))
        except ProcessPreparationError as error:
            p.require(type(error.owner) is ConductorProcess)
            owner = error.owner
            raise
        executor = executor_type.open(owner)
        executor.prepare_keys(declared)
        phase = "starting"
        owner.start()
        for phase in STAGES:
            request = owner.receive()
            p.require(request.phase == phase)
            executor.begin(request)
            while executor.has_job():
                # Only this separately provided supervisor can install an
                # approved next input. The child request is observation data.
                reply = channel.exchange(executor)
                executor.execute(reply)
            executor.complete()  # Reply is built from real publications/reads.
        owner.wait_interactive()  # Original approved interval; signals still cancel.
    except BaseException:
        failed = True

    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    terminal = completion = None
    try:
        if adopted and failed and executor is not None:
            # A worker waiting for head requests must receive its own normal
            # cleanup request before waiting for the conductor's retirement.
            executor.cancel_current_head_worker()
        if owner is not None:
            terminal = owner.close(cancel=failed)
        if adopted and not failed and terminal is not None and terminal.get("status") == "stopped-cleanup-complete":
            try:
                completion = executor.final_result()
            except BaseException:
                # Rejected completion is not itself uncertain cleanup. The
                # executor latches failure and still closes actual retained
                # owners; any ambiguous close reaches the outer fence below.
                failed = True
        # Never release authority originals/capabilities before the actual
        # child cleanup result and reap, or proof it was never spawned.
        if executor is not None:
            executor.close()
        if channel is not None:
            channel.close()
    except BaseException:
        _result("cleanup-unknown-owner-retained", phase)
        while True:
            signal.pause()
    stopped = terminal is not None and terminal.get("status") == "stopped-cleanup-complete"
    if not failed and stopped:
        reported = _result("stopped-cleanup-complete", phase, terminal.get("interactiveResult"), completion)
        return 0 if not adopted or reported else 1
    cleaned = terminal is not None and terminal.get("status") in ("stopped-cleanup-complete", "failed-cleanup-complete")
    _result("failed-cleanup-complete" if cleaned else "not-started", phase)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
