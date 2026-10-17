#!/usr/bin/env python3
"""Run the fixed cold-to-adopted lifecycle with independent FD approvals.

This executable provisions no policy, key, runtime or approval. Every request
comes from the real retained lifecycle. Unknown cleanup retains its owners and
does not retry, exit successfully, or relabel core custody as pilot acceptance.
"""
from __future__ import annotations

import fcntl
import json
import os
from pathlib import Path
import re
import signal
import sys

MODE = "--run-native-pilot-lifecycle"
RESULT_API = "catchplate.nativePilotLifecycleResult/v1"
_PREFIX = (
    ("supervisor-inventory-fd", "fd"), ("supervisor-inventory-sha256", "sha"),
    ("listener-configuration-fd", "fd"), ("listener-configuration-sha256", "sha"),
    ("approval-fd", "fd"), ("approval-peer-pid", "pid"),
    ("approval-peer-uid", "id"), ("approval-peer-gid", "id"),
)
_CANCELLATION = {signal.SIGINT, signal.SIGTERM, signal.SIGHUP}


def _require(value):
    if not value:
        raise ValueError("native pilot lifecycle invocation refused")


def _number(value, *, minimum, maximum):
    _require(type(value) is str and re.fullmatch(r"0|[1-9][0-9]{0,9}", value) is not None)
    number = int(value)
    _require(minimum <= number <= maximum)
    return number


def _arguments(arguments, cold_purposes, adopted_purposes):
    """Closed source-ordered syntax; no public or private FD is read here."""
    for purposes, count in ((cold_purposes, 36), (adopted_purposes, 123)):
        _require(type(purposes) is tuple and len(purposes) == count and len(set(purposes)) == count
            and all(type(name) is str and re.fullmatch(r"[A-Za-z][A-Za-z0-9-]{0,127}", name)
                is not None for name in purposes))
    _require(type(arguments) is list and all(type(value) is str for value in arguments)
        and len(arguments) == 1 + 2 * (len(_PREFIX) + len(cold_purposes) + len(adopted_purposes))
        and arguments[0] == MODE)
    selected, descriptors = {}, set()
    for index, (name, kind) in enumerate(_PREFIX):
        flag, value = arguments[1 + 2 * index:3 + 2 * index]
        _require(flag == "--" + name)
        if kind == "sha":
            _require(re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None)
        else:
            value = _number(value, minimum=3 if kind == "fd" else 2 if kind == "pid" else 0,
                maximum=(1 << 32) - 2 if kind == "id" else (1 << 31) - 1)
            if kind == "fd":
                _require(value not in descriptors)
                descriptors.add(value)
        selected[name.replace("-", "_")] = value
    offset = 1 + 2 * len(_PREFIX)
    for family, purposes in (("cold", cold_purposes), ("adopted", adopted_purposes)):
        keys = {}
        for index, purpose in enumerate(purposes):
            flag, literal = arguments[offset + 2 * index:offset + 2 * index + 2]
            _require(flag == "--" + family + "-authority-key" and literal.startswith(purpose + "="))
            descriptor = _number(literal[len(purpose) + 1:], minimum=3, maximum=(1 << 31) - 1)
            _require(descriptor not in descriptors)
            # Real purpose-specific admissions still check the supplied key.
            # Multiple purposes may intentionally share one actual inherited FD.
            keys[purpose] = descriptor
        selected[family + "_authority_key_fds"] = keys
        offset += 2 * len(purposes)
    return selected


def _stop(_number, _frame):
    raise KeyboardInterrupt


def _result(status, stage, cold_completed, adopted_completed, bundle_sha256):
    value = dict(apiVersion=RESULT_API, status=status, stage=stage,
        coldJobsCompleted=cold_completed, adoptedJobsCompleted=adopted_completed,
        coldBundleSha256=bundle_sha256, pilotAcceptanceVerified=False, productionReleaseEligible=False)
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"
    try:
        _require(len(raw) <= 4096)
        fcntl.fcntl(2, fcntl.F_SETFL, fcntl.fcntl(2, fcntl.F_GETFL) | os.O_NONBLOCK)
        return os.write(2, raw) == len(raw)
    except (OSError, ValueError):
        return False


def main():
    runtime = lifecycle = channel = None
    received = []
    stage, cold_completed, adopted_completed, bundle_sha256 = "open", 0, 0, None
    failed, completed = False, False
    for number in _CANCELLATION:
        signal.signal(number, _stop)
    try:
        signal.pthread_sigmask(signal.SIG_UNBLOCK, _CANCELLATION)
        _require(sys.flags.isolated == 1 and sys.flags.dont_write_bytecode == 1
            and os.getresuid() == (0, 0, 0) and os.getresgid() == (0, 0, 0))
        sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
        from catchplate import native_pilot_genesis_jobs as cold
        from catchplate import native_pilot_adopted_phase_profile as adopted
        from catchplate import native_pilot_genesis_parent_control_io as ownership
        from catchplate.native_pilot_genesis_authority import _SelfRuntime
        from catchplate.native_pilot_lifecycle import CommissioningLifecycle, LifecycleError
        from catchplate.native_pilot_supervisor_approval_channel import ApprovalChannel, ApprovalChannelError

        selected = _arguments(sys.argv[1:], cold.KEY_PURPOSES, adopted.KEY_PURPOSES)
        runtime = _SelfRuntime()  # Retain partial inventory acquisition before admission.
        runtime.admit(selected["supervisor_inventory_fd"], selected["supervisor_inventory_sha256"])
        with ownership.owning():
            try:
                lifecycle = CommissioningLifecycle.prepare(
                    supervisor_inventory_fd=selected["supervisor_inventory_fd"],
                    supervisor_inventory_sha256=selected["supervisor_inventory_sha256"],
                    listener_configuration_fd=selected["listener_configuration_fd"],
                    listener_configuration_sha256=selected["listener_configuration_sha256"],
                    authority_key_fds=selected["cold_authority_key_fds"])
            except LifecycleError as error:
                lifecycle = error.owner
                _require(type(lifecycle) is CommissioningLifecycle)
                raise

        def current():
            runtime.check()
            lifecycle.check_waiting()  # Actual identities, original clocks, no request advancement.

        limits = lifecycle.approval_context()
        with ownership.owning():
            try:
                channel = ApprovalChannel.open_lifecycle(selected["approval_fd"],
                    peer_pid=selected["approval_peer_pid"], peer_uid=selected["approval_peer_uid"],
                    peer_gid=selected["approval_peer_gid"], deadline_boottime_ns=limits["deadlineBoottimeNs"],
                    expires_at_unix_ns=limits["expiresAtUnixNanos"], check=current, completions=True)
            except ApprovalChannelError as error:
                channel = error.owner
                _require(type(channel) is ApprovalChannel)
                raise

        def exchange(name, pending):
            limits = lifecycle.approval_context()
            # The channel itself owns incoming rights before unmasking signals;
            # this caller also retains every successful returned capability.
            accepted = channel.exchange_lifecycle(name, pending,
                deadline_boottime_ns=limits["waitDeadlineBoottimeNs"],
                expires_at_unix_ns=limits["expiresAtUnixNanos"], check=current)
            received.append(accepted)
            current()  # No peer-live check after the final acknowledged exchange.
            return accepted

        def complete(name):
            original = lifecycle.completion_original(name)

            def completion_current():
                current()
                # Closed child owners can carry tighter final-action limits
                # than the overall lifecycle. Keep those through receipt too.
                _require(lifecycle.completion_original(name) == original)

            limits = lifecycle.approval_context()
            channel.send_completion(name, original,
                deadline_boottime_ns=limits["waitDeadlineBoottimeNs"],
                expires_at_unix_ns=limits["expiresAtUnixNanos"], check=completion_current)
            completion_current()

        runtime.check(installed=True)
        stage = "sender"
        sender = lifecycle.start()
        context = lifecycle.approval_context()
        stage = "bootstrap"
        approved = exchange("bootstrap", dict(senderRequestOriginal=sender.decode("ascii"),
            listenerConfigurationOriginal=context["listenerConfigurationOriginal"]))
        stage = "attach-adopted"
        lifecycle.attach_adopted(**approved.bootstrap_kwargs(),
            authority_key_fds=selected["adopted_authority_key_fds"])
        # attach_adopted owns the actual receiving conductor before this read.
        # The first adopted job is deliberately not received before cold finish.
        stage = "rendezvous"
        request = lifecycle.receive_rendezvous()
        approved = exchange("rendezvous", request)
        lifecycle.submit_rendezvous(**approved.resume_kwargs())
        for selected_job in cold.catalogue(handoff=True):
            stage = "cold:" + selected_job.name
            pending = lifecycle.cold_step()
            _require(pending["job"] == selected_job.name and pending["sequence"] == cold_completed + 1)
            approved = exchange("cold", pending["requestOriginal"].encode("ascii"))
            lifecycle.cold_submit(**approved.resume_kwargs())
            cold_completed += 1
            current()
        stage = "cold-finish"
        bundle = lifecycle.finish_cold()
        bundle_sha256 = cold.p.sha(bundle)
        complete("cold")
        for selected_phase, phase_jobs in adopted.JOBS.items():
            for selected_job in phase_jobs:
                stage = "adopted:" + selected_job.name
                pending = lifecycle.adopted_step()
                _require((pending["phase"], pending["job"], pending["sequence"])
                    == (selected_phase, selected_job.name, adopted_completed + 1))
                approved = exchange("adopted", pending)
                lifecycle.adopted_submit(**approved.resume_kwargs())
                adopted_completed += 1
                current()
        _require(cold_completed == 66 and adopted_completed == 176)
        stage = "adopted-finish"
        terminal = lifecycle.finish_adopted()
        _require(terminal["status"] == "stopped-cleanup-complete")
        complete("adopted")
        runtime.check(installed=True)
        completed = True
    except BaseException:
        failed = True

    for number in _CANCELLATION:
        signal.signal(number, signal.SIG_IGN)
    try:
        # Neither transferred public originals nor installed-runtime handles
        # retire before every real child/resource owner has known cleanup.
        if lifecycle is not None:
            terminal = lifecycle.close(cancel=failed)
            _require(terminal["status"] == "closed" and (not completed or terminal["completed"] is True))
        for approval in received:
            approval.close()
        if channel is not None:
            channel.close()
        if runtime is not None:
            runtime.close()
    except BaseException:
        _result("cleanup-unknown-owner-retained", stage, cold_completed, adopted_completed, bundle_sha256)
        while True:
            signal.pause()
    success = completed and not failed
    status = "stopped-cleanup-complete" if success else "failed-cleanup-complete"
    reported = _result(status, stage, cold_completed, adopted_completed, bundle_sha256)
    return 0 if success and reported else 1


if __name__ == "__main__":
    raise SystemExit(main())
