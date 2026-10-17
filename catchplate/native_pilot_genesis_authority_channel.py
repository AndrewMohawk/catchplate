"""Distinct cold job approval exchange over the actual retained root pipes.

The independent supervisor installs each complete input/approval before its
reply. This code never creates approval, selects arbitrary paths, or accepts
live owners in JSON. Root-owned pipes are transport, not proof of independent
operation. Originals stay retained until the caller proves actual cleanup.
"""
from __future__ import annotations

import os

from catchplate import native_pilot_genesis_execution_protocol as protocol
from catchplate import native_pilot_genesis_jobs as jobs
from catchplate import native_pilot_genesis_parent_control_io as io
from catchplate import native_pilot_operator_channel as transport
from catchplate.native_shadow_proof_cohort_control import _Original

p = protocol.p
APPROVAL_ROOT = "/etc/catchplate/native-genesis-authority"
REPLY_API = "catchplate.nativePilotGenesisJobReply/v1"
HANDOFF_REPLY_API = "catchplate.nativePilotGenesisJobReply/v2"
TERMINAL_API = "catchplate.nativePilotGenesisAuthorityTerminal/v1"
HANDOFF_TERMINAL_API = "catchplate.nativePilotGenesisAuthorityTerminal/v2"
RENDEZVOUS_TERMINAL_API = "catchplate.nativePilotGenesisAuthorityTerminal/v3"
MAX_RETAINED = 128 * 1024 * 1024
_TOKEN = object()
_USED = False


def paths(name, *, handoff=False):
    selected = jobs.job(name, handoff=handoff)
    return tuple(APPROVAL_ROOT + "/" + selected.name + suffix for suffix in (".input.json", ".approval.json"))


def reply(raw, request_raw):
    """Framing/literal joins only, never an independent approval verdict."""
    ticket = p.fields(p.document(request_raw, protocol.MAX_REQUEST),
        ("apiVersion", "sequence", "job", "deadlineBoottimeNs", "observation", "previousResult"))
    apis = {protocol.REQUEST_API: REPLY_API, protocol.HANDOFF_REQUEST_API: HANDOFF_REPLY_API}
    p.require(ticket["apiVersion"] in apis)
    p.integer(ticket["sequence"])
    jobs.job(ticket["job"], handoff=ticket["apiVersion"] == protocol.HANDOFF_REQUEST_API)
    p.ns(ticket["deadlineBoottimeNs"])
    value = p.fields(p.document(raw, 4096),
        ("apiVersion", "sequence", "job", "requestSha256", "inputSha256", "approvalSha256"))
    p.integer(value["sequence"])
    p.require(value["apiVersion"] == apis[ticket["apiVersion"]] and value["sequence"] == ticket["sequence"]
        and value["job"] == ticket["job"] and value["requestSha256"] == p.sha(request_raw))
    p.digest(value["inputSha256"]); p.digest(value["approvalSha256"])
    return value


class GenesisApprovalChannel:
    def __init__(self, token, pipe, handoff):
        p.require(token is _TOKEN)
        self._pipe, self._originals = pipe, []
        self._handoff, self._jobs = handoff, jobs.catalogue(handoff=handoff)
        self._sequence = self._retained = 0
        self._deadline = None
        self._failed = self._complete = self._closed = False
        self._listener_attempted = False
        self._rendezvous = False
        self._listener_owner = None

    @classmethod
    def open(cls, *, handoff=False):
        global _USED
        p.require(cls is GenesisApprovalChannel and not _USED and type(handoff) is bool)
        _USED = True
        # This is only the bounded byte transport, not its operational phases.
        with io.owning():
            return cls(_TOKEN, transport.Channel.open(), handoff)

    def _open(self, path, maximum, digest):
        remaining = MAX_RETAINED - self._retained
        p.require(remaining > 0)
        with io.owning():
            original = _Original(path, min(maximum, remaining), digest, mode=0o400)
            self._originals.append(original)
        self._retained += len(original.raw)
        p.require(self._retained <= MAX_RETAINED)
        return original

    def admit_listener(self, listener, *, rendezvous=False):
        """One pre-job independent approval after real sender observation.

        The named v2 execution input is created by the external authority only
        after the recipient exists. This handshake neither signs nor invents it,
        and does not advance or widen the existing 66-job catalogue.
        """
        from catchplate import native_pilot_genesis_handoff_listener as handoff
        p.require(type(listener) is handoff.CoreHandoffListener and type(rendezvous) is bool and self._handoff
            and not self._failed and not self._closed and not self._complete
            and self._sequence == 0 and not self._listener_attempted)
        p.require(listener.rendezvous_selected() is rendezvous)
        self._listener_attempted = True
        self._rendezvous = rendezvous
        self._listener_owner = listener
        try:
            request_raw = listener.request_original()
            deadline = listener.startup_deadline_boottime_ns
            pipe = self._pipe
            p.require(pipe._expiry is None and pipe._pending() == 0)
            pipe._expiry = listener.expires_at_unix_ns  # Original cap inside every blocking pipe wait.
            pipe._check(deadline); listener.check(startup=True)
            pipe._write(request_raw + b"\n", deadline)
            if rendezvous:
                from catchplate import native_pilot_genesis_rendezvous_profile as selected

                def observed_check():
                    # Do not consume approval before actual receiver observation.
                    # The listener holds this exact accepted socket until the
                    # separately approved execution input promotes it.
                    pipe._check(deadline)
                    p.require(pipe._pending() == 0)

                listener.observe_receiver(request_raw, observed_check)
                request_raw = listener.rendezvous_request_original(request_raw)
                selected.verify_request(request_raw)
                observed_check(); listener.check(startup=True)
                pipe._write(request_raw + b"\n", deadline)
                accepted = selected.reply(pipe._read(deadline), request_raw)
                input_path, approval_path = selected.INPUT_PATH, selected.APPROVAL_PATH
                input_maximum, approval_maximum = selected.MAX_INPUT, selected.MAX_APPROVAL
                check_approval = selected.approval
            else:
                accepted = handoff.reply(pipe._read(deadline), request_raw)
                input_path, approval_path = handoff.INPUT_PATH, handoff.APPROVAL_PATH
                input_maximum = approval_maximum = 4096
                check_approval = handoff.approval
            listener.check(startup=True)
            source = self._open(input_path, input_maximum, accepted["inputSha256"])
            approval = self._open(approval_path, approval_maximum, accepted["approvalSha256"])
            check_approval(approval.raw, request_raw=request_raw, input_sha256=accepted["inputSha256"])
            listener.require_execution(source.raw)
            source.check(); approval.check(); listener.check(startup=True); pipe._check(deadline)
            p.require(pipe._pending() == 0)
            return dict(configuration_fd=source.fd, configuration_sha256=accepted["inputSha256"])
        except BaseException:
            self._failed = self._pipe._poisoned = True
            raise ValueError("cold listener approval failed; actual owners retained") from None

    def exchange(self, executor):
        from catchplate.native_pilot_genesis_execution import GenesisExecution
        p.require(type(executor) is GenesisExecution and not self._failed and not self._closed and not self._complete)
        p.require(executor._handoff == self._handoff and executor._jobs == self._jobs)
        try:
            value = executor.job_request()
            selected = jobs.job(value["job"], handoff=self._handoff)
            deadline = p.ns(value["deadlineBoottimeNs"])
            p.require(value["sequence"] == self._sequence + 1
                and self._sequence < len(self._jobs) and selected == self._jobs[self._sequence])
            pipe = self._pipe
            pipe._check(deadline)
            p.require(pipe._pending() == 0)
            request_raw = p.canonical(value)
            p.require(len(request_raw) + 1 <= transport.MAX_FRAME)
            pipe._write(request_raw + b"\n", deadline)
            accepted = reply(pipe._read(deadline), request_raw)
            input_path, approval_path = paths(selected.name, handoff=self._handoff)
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
        from catchplate.native_pilot_genesis_execution import GenesisExecution
        p.require(type(executor) is GenesisExecution and not self._failed and not self._closed and not self._complete)
        p.require(executor._handoff == self._handoff and executor._jobs == self._jobs)
        try:
            p.require(self._sequence == len(self._jobs) and self._deadline is not None)
            raw = executor.finish()  # Requires actual cleanup, not just the last request.
            p.require(type(raw) is bytes and 0 < len(raw) <= protocol.MAX_REQUEST)
            value = dict(apiVersion=HANDOFF_TERMINAL_API if self._handoff else TERMINAL_API,
                status="cold-core-custody-acknowledged" if self._handoff else "cold-assembly-cleanup-complete",
                jobsCompleted=self._sequence, bundleOriginal=raw.decode("ascii"), bundleSha256=p.sha(raw),
                pilotAcceptanceVerified=False, productionReleaseEligible=False)
            if self._handoff:
                value["operationalAdoptionVerified"] = False
            if self._rendezvous:
                # Only this explicit selected dialogue exports the genuine
                # final result. Legacy terminal1/2 remain exact and closed.
                p.require(executor._handoff_listener is self._listener_owner
                    and self._listener_owner.rendezvous_selected())
                value.update(apiVersion=RENDEZVOUS_TERMINAL_API,
                    configurationSha256=p.sha(executor._configuration.raw),
                    finalResult=executor.final_result(),
                    deadlineBoottimeNs=str(min(self._deadline, executor._ceiling())),
                    expiresAtUnixNanos=executor._epoch_limit)
                self._deadline = min(self._deadline, p.ns(value["deadlineBoottimeNs"]))
                self._pipe._expiry = (value["expiresAtUnixNanos"] if self._pipe._expiry is None
                    else min(self._pipe._expiry, value["expiresAtUnixNanos"]))
            wire = p.canonical(value) + b"\n"
            p.require(len(wire) <= transport.MAX_FRAME and self._pipe._pending() == 0)
            self._pipe._check(self._deadline)
            self._pipe._write(wire, self._deadline)
            self._pipe._check(self._deadline)
            p.require(self._pipe._pending() == 0)
            if self._rendezvous:
                executor._check(full=True)
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
