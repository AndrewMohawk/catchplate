#!/usr/bin/env python3
"""Run the fixed commissioning supervisor, never provision its authority.

All inventories, policy, recipe, keys and the connected independent approval
peer are separately selected protected inputs. Eight current-head decisions
arrive through the actual descriptor channel; they are never synthesized here.
An unknown child cleanup retains every live owner and does not retry or exit.
"""
from __future__ import annotations

import fcntl
import json
import os
from pathlib import Path
import re
import signal
import sys

_PREFIX = (
    ("supervisor-inventory-fd", "fd"), ("supervisor-inventory-sha256", "sha"),
    ("policy-fd", "fd"), ("policy-sha256", "sha"),
    ("recipe-fd", "fd"), ("recipe-sha256", "sha"),
    ("conductor-inventory-fd", "fd"), ("conductor-inventory-sha256", "sha"),
    ("authority-inventory-fd", "fd"), ("authority-inventory-sha256", "sha"),
    ("approval-fd", "fd"), ("approval-peer-pid", "pid"),
    ("approval-peer-uid", "id"), ("approval-peer-gid", "id"),
)


def _require(value):
    if not value:
        raise ValueError("native pilot supervisor invocation refused")


def _number(value, *, minimum, maximum):
    _require(type(value) is str and re.fullmatch(r"0|[1-9][0-9]{0,9}", value) is not None)
    number = int(value)
    _require(minimum <= number <= maximum)
    return number


def _arguments(arguments, purposes, *, adopted=False):
    """Closed, source-ordered syntax only; no descriptor is opened here."""
    _require(type(adopted) is bool and type(arguments) is list and type(purposes) is tuple and 0 < len(purposes) <= 128
        and len(set(purposes)) == len(purposes) and all(type(name) is str for name in purposes))
    prefix = (_PREFIX[:10] + (("intake-configuration-fd", "fd"), ("intake-configuration-sha256", "sha"))
        + _PREFIX[10:]) if adopted else _PREFIX
    _require(len(arguments) == 1 + 2 * (len(prefix) + len(purposes))
        and arguments[0] == ("--run-adopted-native-pilot" if adopted else "--run-native-pilot"))
    selected, descriptors = {}, set()
    for index, (name, kind) in enumerate(prefix):
        flag, value = arguments[1 + 2 * index:3 + 2 * index]
        _require(flag == "--" + name)
        if kind == "sha":
            _require(type(value) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None)
        else:
            value = _number(value, minimum=3 if kind == "fd" else 2 if kind == "pid" else 0,
                maximum=(1 << 32) - 2 if kind == "id" else (1 << 31) - 1)
            if kind == "fd":
                _require(value not in descriptors)
                descriptors.add(value)
        selected[name.replace("-", "_")] = value
    keys = {}
    offset = 1 + 2 * len(prefix)
    for index, purpose in enumerate(purposes):
        flag, literal = arguments[offset + 2 * index:offset + 2 * index + 2]
        _require(flag == "--authority-key" and type(literal) is str
            and literal.startswith(purpose + "="))
        descriptor = _number(literal[len(purpose) + 1:], minimum=3, maximum=(1 << 31) - 1)
        _require(descriptor not in descriptors)
        # Several independently selected purposes may use the same actual key.
        # The retained process/policy still verify every purpose's public pin.
        keys[purpose] = descriptor
    selected["authority_key_fds"] = keys
    return selected


class _SelfRuntime:
    """Retain the independently pinned running package before reading keys."""

    def __init__(self):
        from catchplate.native_pilot_coordinator_process import _Runtime
        self._runtime = _Runtime()
        self._fd = self._identity = self._raw = self._source = None
        self._pid = os.getpid()
        self._closed = False

    def admit(self, fd, digest):
        from scripts import native_pilot_runtime_artifacts as artifact
        from scripts.authority import native_pilot_authority_io as io
        from catchplate import native_shadow_nitro_profile as p
        _require(self._fd is None and not self._closed and self._pid == os.getpid())
        self._identity = io._input(fd, artifact.MAX_MANIFEST_BYTES)
        self._fd = fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, 3)
        _require(io._input(self._fd, artifact.MAX_MANIFEST_BYTES) == self._identity)
        self._raw = io.read_public(self._fd, artifact.MAX_MANIFEST_BYTES)
        _require(p.sha(self._raw) == p.digest(digest))
        self._runtime.admit(self._raw, supervisor=True)
        self._source = artifact._source(p.document(self._raw, artifact.MAX_MANIFEST_BYTES)["source"])
        _require(io.read_public(fd, artifact.MAX_MANIFEST_BYTES) == self._raw)
        self.check(installed=True)

    def require_inventory_sources(self, selected):
        from scripts import native_pilot_runtime_artifacts as artifact
        from scripts.authority import native_pilot_authority_io as io
        from catchplate import native_shadow_nitro_profile as p
        self.check()
        for role in ("conductor", "authority"):
            raw = io.read_public(selected[role + "_inventory_fd"], artifact.MAX_MANIFEST_BYTES)
            _require(p.sha(raw) == selected[role + "_inventory_sha256"]
                and artifact._source(p.document(raw, artifact.MAX_MANIFEST_BYTES)["source"]) == self._source)
        self.check()

    def check(self, *, installed=False):
        from scripts import native_pilot_runtime_artifacts as artifact
        from scripts.authority import native_pilot_authority_io as io
        _require(not self._closed and self._pid == os.getpid() and self._fd is not None
            and io._input(self._fd, artifact.MAX_MANIFEST_BYTES) == self._identity)
        if installed:
            self._runtime.check()

    def close(self):
        if self._closed:
            return
        _require(self._pid == os.getpid())
        self._runtime.close()
        if self._fd is not None:
            os.close(self._fd)
        self._closed = True


def _stop(_signum, _frame):
    raise KeyboardInterrupt


def _result(status, phase, completed, interactive_result=None):
    value = {"apiVersion": "catchplate.nativePilotSupervisorResult/v1", "status": status,
        "phase": phase, "jobsCompleted": completed, "pilotAcceptanceVerified": False,
        "productionReleaseEligible": False}
    if status == "stopped-cleanup-complete" and interactive_result is not None:
        value["interactiveResult"] = interactive_result
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"
    try:
        fcntl.fcntl(2, fcntl.F_SETFL, fcntl.fcntl(2, fcntl.F_GETFL) | os.O_NONBLOCK)
        os.write(2, raw)
    except OSError:
        pass


def main():
    runtime = policy = recipe = process = supervisor = channel = None
    received = []
    phase, completed, failed = "open", 0, False
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    try:
        signal.pthread_sigmask(signal.SIG_UNBLOCK, {signal.SIGTERM, signal.SIGINT})
        _require(sys.flags.isolated == 1 and sys.flags.dont_write_bytecode == 1
            and os.getresuid() == (0, 0, 0) and os.getresgid() == (0, 0, 0))
        sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
        from catchplate import native_shadow_nitro_profile as p
        from catchplate.native_pilot_measured_configuration import MeasuredConfigurationRecipe
        from catchplate.native_pilot_phase_execution import KEY_PURPOSES
        from catchplate.native_pilot_supervisor import CommissioningSupervisor, SUPPORTED_JOBS, _LATE_JOBS, require_complete_coverage
        from catchplate.native_pilot_supervisor_approval_channel import ApprovalChannel
        from catchplate.native_pilot_supervisor_policy import SupervisorPolicy
        from catchplate.native_pilot_supervisor_process import AuthorityCoordinatorProcess
        from catchplate.native_pilot_coordinator_process import ProcessPreparationError

        adopted = len(sys.argv) > 1 and sys.argv[1] == "--run-adopted-native-pilot"
        if adopted:
            from catchplate.native_pilot_adopted_phase_profile import KEY_PURPOSES
            from catchplate.native_pilot_adopted_supervisor import (
                AdoptedCommissioningSupervisor as CommissioningSupervisor, SUPPORTED_JOBS,
                SupervisorError as AdoptedSupervisorError, require_complete_coverage)
            from catchplate.native_pilot_adopted_supervisor_policy import (
                AdoptedSupervisorPolicy as SupervisorPolicy, PolicyError as AdoptedPolicyError)
        selected = _arguments(sys.argv[1:], KEY_PURPOSES, adopted=adopted)
        runtime = _SelfRuntime()  # Keep partial descriptor admission reachable.
        runtime.admit(selected["supervisor_inventory_fd"], selected["supervisor_inventory_sha256"])
        runtime.require_inventory_sources(selected)
        require_complete_coverage()
        if adopted:
            try:
                policy = SupervisorPolicy.open(policy_fd=selected["policy_fd"], policy_sha256=selected["policy_sha256"])
            except AdoptedPolicyError as error:
                p.require(type(error.owner) is SupervisorPolicy)
                policy = error.owner
                raise
        else:
            policy = SupervisorPolicy.open(policy_fd=selected["policy_fd"], policy_sha256=selected["policy_sha256"])
        recipe = MeasuredConfigurationRecipe.open(recipe_fd=selected["recipe_fd"], recipe_sha256=selected["recipe_sha256"])
        channel = (ApprovalChannel.open_adopted if adopted else ApprovalChannel.open)(selected["approval_fd"], peer_pid=selected["approval_peer_pid"],
            peer_uid=selected["approval_peer_uid"], peer_gid=selected["approval_peer_gid"])
        runtime.check(installed=True)
        process_arguments = dict(
            conductor_inventory_fd=selected["conductor_inventory_fd"],
            conductor_inventory_sha256=selected["conductor_inventory_sha256"],
            authority_inventory_fd=selected["authority_inventory_fd"],
            authority_inventory_sha256=selected["authority_inventory_sha256"],
            authority_key_fds=selected["authority_key_fds"])
        if adopted:
            process_arguments.update(intake_configuration_fd=selected["intake_configuration_fd"],
                intake_configuration_sha256=selected["intake_configuration_sha256"])
        try:
            if adopted:
                process = AuthorityCoordinatorProcess.prepare_adopted(**process_arguments)
            else:
                process = AuthorityCoordinatorProcess.prepare(**process_arguments)
        except ProcessPreparationError as error:
            p.require(type(error.owner) is AuthorityCoordinatorProcess)
            process = error.owner
            raise
        if adopted:
            try:
                supervisor = CommissioningSupervisor.prepare(policy=policy, process=process, measured_recipe=recipe)
            except AdoptedSupervisorError as error:
                p.require(type(error.owner) is CommissioningSupervisor)
                supervisor = error.owner
                raise
        else:
            supervisor = CommissioningSupervisor.prepare(policy=policy, process=process, measured_recipe=recipe)
        policy.require_final_scope(process)
        runtime.check(installed=True)
        channel.check()
        phase = "starting"
        supervisor.start()
        for phase, job in SUPPORTED_JOBS:
            runtime.check()
            result = supervisor.step()
            p.require((result["phase"], result["job"], result["sequence"]) == (phase, job, completed + 1))
            if adopted or (phase, job) in _LATE_JOBS:
                p.require(result["status"] == ("awaiting-independent-job-approval" if adopted
                    else "awaiting-independent-current-head-approval"))
                approval = channel.exchange(result)
                received.append(approval)  # Keep transferred originals until known terminal cleanup.
                runtime.check()
                if adopted:
                    result = supervisor.submit(**approval.resume_kwargs())
                else:
                    result = supervisor.resume_current_head(**approval.resume_kwargs())
                # The peer may retire after its final reply. Only active late
                # exchanges require its liveness; owned originals remain held.
            p.require((result["phase"], result["job"], result["sequence"], result["status"])
                == (phase, job, completed + 1, "approval-installed-and-replied"))
            completed += 1
            runtime.check()
        p.require(completed == len(SUPPORTED_JOBS))
        process.wait_interactive()  # Keep cancellation live throughout the approved interval.
    except BaseException:
        failed = True

    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    terminal = None
    try:
        if supervisor is not None:
            terminal = supervisor.close(cancel=failed)
        elif process is not None:
            # A failed Supervisor.prepare retains its canonical owner, but the
            # separately held actual process/policy suffice for terminal cleanup.
            terminal = process.close(cancel=failed)
        if terminal is not None:
            _require(terminal.get("status") in ("not-started", "stopped-cleanup-complete", "failed-cleanup-complete"))
        if policy is not None:
            policy.close()
        if recipe is not None:
            recipe.close()
        for approval in received:
            approval.close()
        if channel is not None:
            channel.close()
        if runtime is not None:
            if runtime._source is not None:
                runtime.check(installed=True)
            runtime.close()
    except BaseException:
        _result("cleanup-unknown-owner-retained", phase, completed)
        while True:
            signal.pause()
    stopped = terminal is not None and terminal.get("status") == "stopped-cleanup-complete"
    if not failed and stopped:
        _result("stopped-cleanup-complete", phase, completed, terminal.get("interactiveResult"))
        return 0
    cleaned = terminal is not None and terminal.get("status") in ("stopped-cleanup-complete", "failed-cleanup-complete")
    _result("failed-cleanup-complete" if cleaned else "not-started", phase, completed)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
