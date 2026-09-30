"""Fixed per-job approval dialogue, separate from the eleven-phase relay.

The operator must independently provide the supervisor and protected approval
installation capability. Root-owned pipes alone do not prove approval provenance.
No paths, keys, commands, templates or success pins are accepted in replies.
"""
from __future__ import annotations

from serverware import native_pilot_operator_channel as transport

p = transport.p
_USED = False


class ApprovalChannel:
    def __init__(self, pipe):
        self._pipe = pipe
        self._sequence = 0
        self._failed = False

    @classmethod
    def open(cls):
        global _USED
        p.require(cls is ApprovalChannel and not _USED)
        _USED = True
        # Use the actual existing root FIFO owner and bounded byte transport,
        # not its distinct eleven-phase exchange protocol or a reconstructed FD.
        return cls(transport.Channel.open())

    def exchange(self, executor):
        from serverware.native_pilot_phase_execution import PhaseExecution
        p.require(type(executor) is PhaseExecution and not self._failed)
        try:
            value = executor.job_request()
            deadline = p.ns(value["deadlineBoottimeNs"])
            pipe = self._pipe
            pipe._check(deadline)
            p.require(value["sequence"] == self._sequence + 1 and pipe._pending() == 0)
            raw = p.canonical(value)
            p.require(len(raw) + 1 <= transport.MAX_FRAME)
            pipe._write(raw + b"\n", deadline)
            reply = p.fields(p.document(pipe._read(deadline), 4096),
                ("apiVersion", "sequence", "conductorSequence", "conductorRequestSha256", "phase",
                 "jobIndex", "job", "requestSha256", "approvalSha256", "inputSha256"))
            p.require(reply["apiVersion"] == "serverware.nativePilotAuthorityJobReply/v1"
                and reply["requestSha256"] == p.sha(raw))
            for name in ("sequence", "conductorSequence", "conductorRequestSha256", "phase", "jobIndex", "job"):
                p.require(p.canonical(reply[name]) == p.canonical(value[name]))
            p.digest(reply["approvalSha256"]); p.digest(reply["inputSha256"])
            pipe._check(deadline)
            p.require(pipe._pending() == 0)
            self._sequence += 1
            return reply
        except BaseException:
            self._failed = self._pipe._poisoned = True
            raise ValueError("native pilot job approval dialogue failed") from None

    def close(self):
        self._pipe.close()
