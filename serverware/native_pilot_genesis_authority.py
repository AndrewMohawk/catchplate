"""Explicit cold commissioning CLI inside the existing supervisor package.

This is not the operational supervisor protocol. No key, protected prerequisite,
approval service or new window is provisioned here. The cold Bundle is not the
live fs-verity core descriptor needed by operational adoption.
"""
from __future__ import annotations

import fcntl
import json
import os
import re
import signal
import sys

from scripts import native_pilot_runtime_artifacts as artifacts
from serverware import native_pilot_genesis_jobs as jobs
from serverware import native_pilot_genesis_parent_control_io as io
from serverware import native_shadow_nitro_originals as originals
from serverware.native_pilot_coordinator_process import _Runtime

p = jobs.p
_PREFIX = (("supervisor-inventory-fd", "fd"), ("supervisor-inventory-sha256", "sha"),
    ("genesis-configuration-fd", "fd"), ("genesis-configuration-sha256", "sha"))


def arguments(values):
    """Canonical closed syntax, checked before any private descriptor read."""
    offset = 1 + 2 * len(_PREFIX)
    p.require(type(values) is list and len(values) == offset + 2 * len(jobs.KEY_PURPOSES)
        and values[0] == "--run-native-genesis" and all(type(v) is str for v in values))
    selected, descriptors = {}, set()
    for index, (name, kind) in enumerate(_PREFIX):
        flag, value = values[1 + 2 * index:3 + 2 * index]
        p.require(flag == "--" + name)
        if kind == "sha":
            p.digest(value)
        else:
            p.require(re.fullmatch(r"[1-9][0-9]{0,9}", value) is not None)
            value = int(value)
            p.require(3 <= value < (1 << 31) and value not in descriptors)
            descriptors.add(value)
        selected[name.replace("-", "_")] = value
    keys = {}
    for index in range(offset, len(values), 2):
        flag, literal = values[index:index + 2]
        p.require(flag == "--authority-key" and literal.count("=") == 1)
        purpose, number = literal.split("=", 1)
        p.require(purpose in jobs.KEY_PURPOSES and purpose not in keys
            and re.fullmatch(r"[1-9][0-9]{0,9}", number) is not None)
        fd = int(number)
        p.require(3 <= fd < (1 << 31) and fd not in descriptors)
        keys[purpose] = fd
    p.require(set(keys) == set(jobs.KEY_PURPOSES))
    selected["authority_key_fds"] = keys
    return selected


class _SelfRuntime:
    def __init__(self):
        self._runtime, self._input = _Runtime(), None
        self._pid, self._start, self._boot = os.getpid(), originals._start(), originals._boot()
        self._closed = False

    def admit(self, fd, digest):
        p.require(self._input is None and not self._closed)
        with io.owning():
            self._input = io.PublicInput(fd, artifacts.MAX_MANIFEST_BYTES, digest)
        # The larger supervisor package actually contains the cold producer
        # commands as well as the fixed authority entrypoint. Do not pretend
        # its manifest is the separate operational authority inventory.
        self._runtime.admit(self._input.raw, supervisor=True)
        self.check(installed=True)

    def check(self, *, installed=False):
        p.require(not self._closed and self._pid == os.getpid() and self._start == originals._start()
            and self._boot == originals._boot() and self._input is not None)
        self._input.check_identity()
        if installed:
            self._runtime.check()

    def close(self):
        if self._closed:
            return
        p.require(self._pid == os.getpid() and self._start == originals._start())
        # Retire slots with their actual close so later interruption cannot
        # close a newly reused descriptor number during partial cleanup.
        with io.owning():
            while self._runtime.directories:
                _, fd = self._runtime.directories.popitem()
                os.close(fd)
            if self._input is not None:
                self._input.close()
            self._closed = True


def _stop(_signum, _frame):
    raise KeyboardInterrupt


def _result(status, phase, completed, digest):
    value = dict(apiVersion="serverware.nativePilotGenesisAuthorityResult/v1", status=status,
        phase=phase, jobsCompleted=completed, bundleSha256=digest,
        pilotAcceptanceVerified=False, productionReleaseEligible=False)
    try:
        fcntl.fcntl(2, fcntl.F_SETFL, fcntl.fcntl(2, fcntl.F_GETFL) | os.O_NONBLOCK)
        os.write(2, json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n")
    except OSError:
        pass


def main(values):
    from serverware.native_pilot_genesis_authority_channel import GenesisApprovalChannel
    from serverware.native_pilot_genesis_execution import GenesisExecution, GenesisExecutionError
    runtime = executor = channel = None
    phase, completed, digest, failed = "open", 0, None, False
    for number in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(number, _stop)
    try:
        signal.pthread_sigmask(signal.SIG_UNBLOCK, io.CANCELLATION)
        p.require(sys.flags.isolated == 1 and sys.flags.dont_write_bytecode == 1
            and os.getresuid() == (0, 0, 0) and os.getresgid() == (0, 0, 0))
        selected = arguments(values)
        runtime = _SelfRuntime()  # Keep partial runtime admission reachable.
        runtime.admit(selected["supervisor_inventory_fd"], selected["supervisor_inventory_sha256"])
        with io.owning():
            channel = GenesisApprovalChannel.open()
        with io.owning():
            executor = GenesisExecution.open(configuration_fd=selected["genesis_configuration_fd"],
                configuration_sha256=selected["genesis_configuration_sha256"])
        runtime.check(installed=True)
        executor.prepare_keys(selected["authority_key_fds"])
        while executor.has_job():
            runtime.check()
            phase = executor.job_request()["job"]
            accepted = channel.exchange(executor)
            runtime.check()
            executor.execute(**accepted)
            completed += 1
        p.require(completed == len(jobs.JOBS))
        runtime.check(installed=True)
        digest = channel.complete(executor)
    except GenesisExecutionError as error:
        if executor is None:
            executor = error.owner
        failed = True
    except BaseException:
        failed = True

    for number in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(number, signal.SIG_IGN)
    try:
        # No key, installed file, source or approval may retire before actual
        # children/helpers and their resources have a known cleanup outcome.
        if executor is not None:
            terminal = executor.close()
            p.require(terminal["status"] == "closed")
        if channel is not None:
            channel.close()
        if runtime is not None:
            runtime.close()
    except BaseException:
        _result("cleanup-unknown-owner-retained", phase, completed, digest)
        while True:
            signal.pause()
    status = "cold-assembly-cleanup-complete" if not failed else "failed-cleanup-complete" if executor is not None else "not-started"
    _result(status, phase, completed, digest)
    return int(failed)
