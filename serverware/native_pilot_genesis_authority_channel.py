"""Distinct cold job approval exchange over the actual retained root pipes.

The independent supervisor installs each complete input/approval before its
reply. This code never creates approval, selects arbitrary paths, or accepts
live owners in JSON. Root-owned pipes are transport, not proof of independent
operation. Originals stay retained until the caller proves actual cleanup.
"""
from __future__ import annotations

import os

from serverware import native_pilot_genesis_execution_protocol as protocol
from serverware import native_pilot_genesis_jobs as jobs
from serverware import native_pilot_genesis_parent_control_io as io
from serverware import native_pilot_operator_channel as transport
from serverware.native_shadow_proof_cohort_control import _Original

p = protocol.p
APPROVAL_ROOT = "/etc/serverware/native-genesis-authority"
REPLY_API = "serverware.nativePilotGenesisJobReply/v1"
TERMINAL_API = "serverware.nativePilotGenesisAuthorityTerminal/v1"
MAX_RETAINED = 128 * 1024 * 1024
_TOKEN = object()
_USED = False


def paths(name):
    selected = jobs.job(name)
    return tuple(APPROVAL_ROOT + "/" + selected.name + suffix for suffix in (".input.json", ".approval.json"))


def reply(raw, request_raw):
    """Framing/literal joins only, never an independent approval verdict."""
    ticket = p.fields(p.document(request_raw, protocol.MAX_REQUEST),
        ("apiVersion", "sequence", "job", "deadlineBoottimeNs", "observation", "previousResult"))
    p.require(ticket["apiVersion"] == protocol.REQUEST_API)
    p.integer(ticket["sequence"]); jobs.job(ticket["job"]); p.ns(ticket["deadlineBoottimeNs"])
    value = p.fields(p.document(raw, 4096),
        ("apiVersion", "sequence", "job", "requestSha256", "inputSha256", "approvalSha256"))
    p.integer(value["sequence"])
    p.require(value["apiVersion"] == REPLY_API and value["sequence"] == ticket["sequence"]
        and value["job"] == ticket["job"] and value["requestSha256"] == p.sha(request_raw))
    p.digest(value["inputSha256"]); p.digest(value["approvalSha256"])
    return value


class GenesisApprovalChannel:
    def __init__(self, token, pipe):
        p.require(token is _TOKEN)
        self._pipe, self._originals = pipe, []
        self._sequence = self._retained = 0
        self._deadline = None
        self._failed = self._complete = self._closed = False

    @classmethod
    def open(cls):
        global _USED
        p.require(cls is GenesisApprovalChannel and not _USED)
        _USED = True
        # This is only the bounded byte transport, not its operational phases.
        with io.owning():
            return cls(_TOKEN, transport.Channel.open())

    def _open(self, path, maximum, digest):
        remaining = MAX_RETAINED - self._retained
        p.require(remaining > 0)
        with io.owning():
            original = _Original(path, min(maximum, remaining), digest, mode=0o400)
            self._originals.append(original)
        self._retained += len(original.raw)
        p.require(self._retained <= MAX_RETAINED)
        return original

    def exchange(self, executor):
        from serverware.native_pilot_genesis_execution import GenesisExecution
        p.require(type(executor) is GenesisExecution and not self._failed and not self._closed and not self._complete)
        try:
            value = executor.job_request()
            selected = jobs.job(value["job"])
            deadline = p.ns(value["deadlineBoottimeNs"])
            p.require(value["sequence"] == self._sequence + 1
                and self._sequence < len(jobs.JOBS) and selected == jobs.JOBS[self._sequence])
            pipe = self._pipe
            pipe._check(deadline)
            p.require(pipe._pending() == 0)
            request_raw = p.canonical(value)
            p.require(len(request_raw) + 1 <= transport.MAX_FRAME)
            pipe._write(request_raw + b"\n", deadline)
            accepted = reply(pipe._read(deadline), request_raw)
            input_path, approval_path = paths(selected.name)
            source = self._open(input_path, selected.maximum, accepted["inputSha256"])
            approval = self._open(approval_path, 8192, accepted["approvalSha256"])
            protocol.approval(approval.raw, request_raw=request_raw, input_sha256=accepted["inputSha256"])
            source.check(); approval.check()
            pipe._check(deadline)
            p.require(pipe._pending() == 0)
            self._sequence += 1
            self._deadline = deadline
            return dict(input_fd=source.fd, input_sha256=accepted["inputSha256"],
                approval_fd=approval.fd, approval_sha256=accepted["approvalSha256"])
        except BaseException:
            self._failed = self._pipe._poisoned = True
            raise ValueError("cold genesis approval exchange failed; no retry") from None

    def complete(self, executor):
        """Publish a real executor's terminal Bundle, never caller-made success."""
        from serverware.native_pilot_genesis_execution import GenesisExecution
        p.require(type(executor) is GenesisExecution and not self._failed and not self._closed and not self._complete)
        try:
            p.require(self._sequence == len(jobs.JOBS) and self._deadline is not None)
            raw = executor.finish()  # Requires actual cleanup, not just the last request.
            p.require(type(raw) is bytes and 0 < len(raw) <= protocol.MAX_REQUEST)
            value = dict(apiVersion=TERMINAL_API, status="cold-assembly-cleanup-complete",
                jobsCompleted=self._sequence, bundleOriginal=raw.decode("ascii"), bundleSha256=p.sha(raw),
                pilotAcceptanceVerified=False, productionReleaseEligible=False)
            wire = p.canonical(value) + b"\n"
            p.require(len(wire) <= transport.MAX_FRAME and self._pipe._pending() == 0)
            self._pipe._check(self._deadline)
            self._pipe._write(wire, self._deadline)
            self._pipe._check(self._deadline)
            p.require(self._pipe._pending() == 0)
            self._complete = True
            return p.sha(raw)
        except BaseException:
            self._failed = self._pipe._poisoned = True
            raise ValueError("cold genesis terminal delivery failed; no retry") from None

    def close(self):
        # The runner must close the actual executor first. Closing this channel
        # alone proves nothing about process, helper or resource retirement.
        if self._closed:
            return
        self._pipe._process()
        while self._originals:
            original = self._originals[-1]
            with io.owning():
                while original.fds:
                    fd = original.fds.pop()
                    os.close(fd)
                self._originals.pop()
        self._pipe.close()
        self._closed = True
