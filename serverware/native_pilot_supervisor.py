"""Fixed commissioning decisions joined to their real process and installer.

Only the initial three job composers exist. The complete-coverage check refuses
startup before spawning a child, not after a live attempt reaches a missing job.
There is no executable entrypoint, configurable dispatcher, approval callback,
signer, new deadline or source of deployment approval in this module.
"""
from __future__ import annotations

import os

from serverware import native_pilot_approval_install as installation
from serverware import native_pilot_supervisor_precreation as precreation
from serverware import native_shadow_nitro_originals as originals
from serverware import native_shadow_nitro_profile as p
from serverware.native_pilot_operator_channel import STAGES
from serverware.native_pilot_phase_execution import JOBS, MAX_APPROVAL
from serverware.native_pilot_supervisor_policy import SupervisorPolicy
from serverware.native_pilot_supervisor_process import AuthorityCoordinatorProcess

SUPPORTED_JOBS = (("bootstrap-admission", "driver-bootstrap"),
    ("endpoint-precreation", "cohort-precreation"),
    ("endpoint-precreation", "install-precreation"))
_ORDER = tuple((phase, job.name) for phase in STAGES for job in JOBS[phase])
_TOKEN = object()
_USED = False
_LIVE = None


def missing_jobs():
    """Source coverage only, never acceptance or a percentage of remaining effort."""
    p.require(tuple(JOBS) == STAGES and _ORDER[:len(SUPPORTED_JOBS)] == SUPPORTED_JOBS)
    return tuple(item for item in _ORDER if item not in SUPPORTED_JOBS)


def require_complete_coverage():
    """A full-run owner must call this before process.start or any publication."""
    if missing_jobs():
        raise ValueError("native pilot commissioning supervisor has unimplemented jobs")


def _approval(request_raw, input_raw):
    # This is serialization, not an independent decision. Only step calls it,
    # after the fixed composer checks a retained independently admitted policy.
    request = p.document(request_raw, installation.MAX_REQUEST)
    return p.canonical({"apiVersion": "serverware.nativePilotAuthorityJobApproval/v1",
        **{name: request[name] for name in ("conductorSequence", "conductorRequestSha256",
                                          "phase", "jobIndex", "job", "deadlineBoottimeNs")},
        "inputSha256": p.sha(input_raw)})


class CommissioningSupervisor:
    """One originating process, one admitted policy, one non-retryable attempt."""

    def __init__(self, token, policy, process):
        p.require(token is _TOKEN)
        self._policy, self._process = policy, process
        self._pid, self._boot = os.getpid(), originals._boot()
        self._index = 0
        self._started = self._closed = self._failed = False

    @classmethod
    def prepare(cls, *, policy, process, measured_recipe=None):
        global _USED, _LIVE
        p.require(cls is CommissioningSupervisor and not _USED
            and type(policy) is SupervisorPolicy and type(process) is AuthorityCoordinatorProcess)
        _USED = True
        owner = cls(_TOKEN, policy, process)
        _LIVE = owner  # Retain both originals/owners even if binding refuses.
        try:
            policy.retain_measured_recipe(measured_recipe)
            process.prepare_bootstrap()
            policy.bind(process)
            owner._check()
            return owner
        except BaseException:
            owner._failed = True
            raise

    def _origin(self):
        p.require(_LIVE is self and not self._closed and os.getpid() == self._pid
            and originals._boot() == self._boot)

    def _check(self):
        self._origin()
        p.require(not self._failed)
        self._policy.check(self._process)

    def start(self):
        self._check()
        p.require(not self._started and self._index == 0)
        self._failed = True
        require_complete_coverage()  # Currently refuses, with no child or files.
        self._process.start()
        self._started = True
        self._policy.check(self._process)
        self._failed = False

    def step(self):
        """Approve/install/reply once; a reply is not proof that the job succeeded."""
        self._check()
        p.require(self._started and self._index < len(_ORDER))
        self._failed = True
        request = self._process.receive()
        self._process.check_request(request)
        self._policy.check(self._process)
        slot = (request.phase, request.job)
        p.require(slot == _ORDER[self._index] and slot in SUPPORTED_JOBS
            and request.sequence == self._index + 1)
        if slot == SUPPORTED_JOBS[0]:
            input_raw, approval_raw = self._policy.bootstrap(self._process, request)
        else:
            if slot == SUPPORTED_JOBS[1]:
                # v2's real retained owner derives once from the actual prior
                # bootstrap signature/request. Legacy policy returns None.
                self._policy.derive_measured(process=self._process, request=request)
            input_raw = precreation.compose(self._policy, process=self._process, request=request)
            approval_raw = _approval(request.raw, input_raw)
        p.require(type(input_raw) is bytes and type(approval_raw) is bytes)
        p.document(approval_raw, MAX_APPROVAL)
        input_sha, approval_sha = p.sha(input_raw), p.sha(approval_raw)
        # Validate the same complete literals the existing installer will use,
        # then recheck actual process/policy before any fixed filesystem write.
        installation._prepare(request.raw, approval_raw, input_raw, approval_sha, input_sha)
        self._process.check_request(request)
        self._policy.check(self._process)
        reply = installation.install(request.raw, approval_raw, input_raw,
            approval_sha256=approval_sha, input_sha256=input_sha)
        self._process.check_request(request)
        self._policy.check(self._process)
        self._process.reply(request, reply)
        self._index += 1
        self._policy.check(self._process)
        self._failed = False
        return {"phase": request.phase, "job": request.job, "sequence": request.sequence,
            "inputSha256": input_sha, "approvalSha256": approval_sha,
            "status": "approval-installed-and-replied"}

    def close(self):
        """Unknown cleanup retains both process and policy; no rollback or retry."""
        self._origin()
        self._failed = True
        result = self._process.close()
        if result["status"] == "cleanup-unknown-owner-retained":
            return result
        p.require(result["status"] in ("not-started", "stopped-cleanup-complete", "failed-cleanup-complete"))
        self._policy.close()
        self._closed = True
        return result
