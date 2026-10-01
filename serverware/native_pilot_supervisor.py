"""Fixed commissioning decisions joined to their real process and installer.

The initial 158 of 164 jobs have fixed composers or protected late intake. The complete-coverage check refuses
startup before spawning a child, not after a live attempt reaches a missing job.
There is no executable entrypoint, configurable dispatcher, approval callback,
signer, new deadline or source of deployment approval in this module.
"""
from __future__ import annotations

import os

from serverware import native_pilot_approval_install as installation
from serverware import native_pilot_supervisor_precreation as precreation
from serverware import native_pilot_supervisor_endpoint_inputs as endpoint_inputs
from serverware import native_pilot_supervisor_endpoint_deliveries as endpoint_deliveries
from serverware import native_pilot_supervisor_initial_history as initial_history
from serverware import native_pilot_supervisor_ordinary_deliveries as ordinary_deliveries
from serverware import native_pilot_supervisor_ordinary_generations as ordinary_generations
from serverware import native_pilot_supervisor_native_deliveries as native_deliveries
from serverware import native_pilot_supervisor_key_authorizations as key_authorizations
from serverware import native_pilot_supervisor_native_services as native_services
from serverware import native_pilot_supervisor_ordinary_transitions as ordinary_transitions
from serverware import native_pilot_supervisor_launch_authorizations as launch_authorizations
from serverware import native_pilot_supervisor_endpoint_launches as endpoint_launches
from serverware import native_pilot_supervisor_service_material as service_material
from serverware import native_pilot_supervisor_current_heads as current_heads
from serverware import native_pilot_supervisor_bridge_runtime as bridge_runtime
from serverware import native_pilot_supervisor_bridge_commissioning as bridge_commissioning
from serverware import custody_generation_grants as generation
from serverware import native_shadow_nitro_originals as originals
from serverware import native_shadow_nitro_profile as p
from serverware.native_pilot_operator_channel import STAGES
from serverware.native_pilot_phase_execution import CURRENT_HEAD_JOBS, INITIAL_JOBS, HELPER_INITIAL_JOBS, JOBS, KEY_AUTHORIZATION_JOBS, MAX_APPROVAL
from serverware.native_pilot_supervisor_policy import SupervisorPolicy
from serverware.native_pilot_supervisor_process import AuthorityCoordinatorProcess

SUPPORTED_JOBS = (("bootstrap-admission", "driver-bootstrap"),
    ("endpoint-precreation", "cohort-precreation"),
    ("endpoint-precreation", "install-precreation"),
    ("endpoint-inputs", "endpoint-inputs"),
    ("endpoint-deliveries", "native-delivery-retrieval"),
    ("endpoint-deliveries", "native-delivery-persistence"),
    ("endpoint-deliveries", "native-delivery-trustedTime"),
    *(("service-originals", job.name) for job in INITIAL_JOBS),
    *(("service-originals", job.name) for job in HELPER_INITIAL_JOBS),
    *(("service-originals", "ordinary-delivery-" + role) for role in generation.ROLES),
    *(("service-originals", "ordinary-generation-" + role) for role in generation.ROLES),
    *(("service-originals", "native-delivery-" + role) for role in native_deliveries.ROLES),
    *(("service-originals", job.name) for job in KEY_AUTHORIZATION_JOBS),
    *(("service-originals", name) for name in native_services.JOB_NAMES),
    *(("service-originals", name) for name in ordinary_transitions.JOB_NAMES),
    *(("service-originals", name) for name in launch_authorizations.JOB_NAMES),
    *(("service-originals", name) for name in endpoint_launches.JOB_NAMES),
    (service_material.PHASE, service_material.JOB),
    *(("bridge-runtime", job.name) for job in CURRENT_HEAD_JOBS),
    (bridge_runtime.PHASE, bridge_runtime.JOB),
    *((bridge_commissioning.PHASE, name) for name in bridge_commissioning.JOB_NAMES))
_LATE_JOBS = tuple(("bridge-runtime", job.name) for job in CURRENT_HEAD_JOBS)
_COMPOSER_GROUPS = (
    ("endpoint-inputs", ("endpoint-inputs",), endpoint_inputs.compose),
    ("endpoint-deliveries", tuple("native-delivery-" + role for role in endpoint_deliveries.ROLES), endpoint_deliveries.compose),
    ("service-originals", tuple(job.name for job in INITIAL_JOBS + HELPER_INITIAL_JOBS), initial_history.compose),
    ("service-originals", tuple("ordinary-delivery-" + role for role in generation.ROLES), ordinary_deliveries.compose),
    ("service-originals", tuple("ordinary-generation-" + role for role in generation.ROLES), ordinary_generations.compose),
    ("service-originals", tuple("native-delivery-" + role for role in native_deliveries.ROLES), native_deliveries.compose),
    ("service-originals", tuple(job.name for job in KEY_AUTHORIZATION_JOBS), key_authorizations.compose),
    ("service-originals", native_services.JOB_NAMES, native_services.compose),
    ("service-originals", ordinary_transitions.JOB_NAMES, ordinary_transitions.compose),
    ("service-originals", launch_authorizations.JOB_NAMES, launch_authorizations.compose),
    ("service-originals", endpoint_launches.JOB_NAMES, endpoint_launches.compose),
    (service_material.PHASE, (service_material.JOB,), service_material.compose),
    (bridge_runtime.PHASE, (bridge_runtime.JOB,), bridge_runtime.compose),
    (bridge_commissioning.PHASE, bridge_commissioning.JOB_NAMES, bridge_commissioning.compose),
)
_COMPOSERS = {(phase, name): composer for phase, names, composer in _COMPOSER_GROUPS for name in names}
_ORDER = tuple((phase, job.name) for phase in STAGES for job in JOBS[phase])
_TOKEN = object()
_USED = False
_LIVE = None


def missing_jobs():
    """Source coverage only, never acceptance or a percentage of remaining effort."""
    p.require(tuple(JOBS) == STAGES and _ORDER[:len(SUPPORTED_JOBS)] == SUPPORTED_JOBS)
    p.require(tuple(_COMPOSERS) == tuple(slot for slot in SUPPORTED_JOBS[3:] if slot not in _LATE_JOBS)
        and tuple(slot for slot in SUPPORTED_JOBS if slot in _LATE_JOBS) == _LATE_JOBS
        and not set(_COMPOSERS).intersection(_LATE_JOBS)
        and len(_COMPOSERS) == sum(len(names) for _, names, _ in _COMPOSER_GROUPS))
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
        self._pending_head = self._pending_request = None
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
        """Compose a fixed job or pause for an independent late approval."""
        self._check()
        p.require(self._started and self._index < len(_ORDER) and self._pending_head is None)
        self._failed = True
        request = self._process.receive()
        self._process.check_request(request)
        self._policy.check(self._process)
        slot = (request.phase, request.job)
        p.require(slot == _ORDER[self._index] and slot in SUPPORTED_JOBS
            and request.sequence == self._index + 1)
        if slot in _LATE_JOBS:
            # Static commissioning policy permits this intake, but is not a
            # currentness decision over entropy acquired after child startup.
            self._pending_request = request
            self._pending_head = current_heads.claim(self._policy, process=self._process, request=request)
            observation = self._pending_head.observed_original()
            p.require(type(observation) is bytes)
            self._pending_head.check()
            self._failed = False
            return {"phase": request.phase, "job": request.job, "sequence": request.sequence,
                "status": "awaiting-independent-current-head-approval",
                "requestOriginal": request.raw.decode("ascii"), "requestSha256": p.sha(request.raw),
                "observationOriginal": observation.decode("ascii"), "observationSha256": p.sha(observation)}
        if slot == SUPPORTED_JOBS[0]:
            input_raw, approval_raw = self._policy.bootstrap(self._process, request)
        elif slot in SUPPORTED_JOBS[1:3]:
            if slot == SUPPORTED_JOBS[1]:
                # v2's real retained owner derives once from the actual prior
                # bootstrap signature/request. Legacy policy returns None.
                self._policy.derive_measured(process=self._process, request=request)
            input_raw = precreation.compose(self._policy, process=self._process, request=request)
            approval_raw = _approval(request.raw, input_raw)
        else:
            p.require(slot in _COMPOSERS)
            input_raw = _COMPOSERS[slot](self._policy, process=self._process, request=request)
            approval_raw = _approval(request.raw, input_raw)
        return self._install_and_reply(request, input_raw, approval_raw)

    def resume_current_head(self, *, input_fd, input_sha256, approval_fd, approval_sha256):
        """Consume protected independently approved originals; never decide or retry."""
        self._check()
        p.require(self._started and self._pending_head is not None and self._pending_request is not None)
        self._failed = True
        request = self._pending_request
        p.require((request.phase, request.job) == _ORDER[self._index]
            and (request.phase, request.job) in _LATE_JOBS)
        self._pending_head.check()
        input_raw, approval_raw = self._pending_head.admit(input_fd=input_fd, input_sha256=input_sha256,
            approval_fd=approval_fd, approval_sha256=approval_sha256)
        return self._install_and_reply(request, input_raw, approval_raw, late=self._pending_head)

    def _install_and_reply(self, request, input_raw, approval_raw, *, late=None):
        """Only the original pending request may reach the exclusive installer."""
        p.require(self._failed and self._started and (request.phase, request.job) == _ORDER[self._index])
        p.require(((request.phase, request.job) in _LATE_JOBS) == (late is not None)
            and (late is None or (late is self._pending_head and request is self._pending_request)))
        p.require(type(input_raw) is bytes and type(approval_raw) is bytes)
        p.document(approval_raw, MAX_APPROVAL)
        input_sha, approval_sha = p.sha(input_raw), p.sha(approval_raw)
        # Validate the same complete literals the existing installer will use,
        # then recheck actual process/policy before any fixed filesystem write.
        installation._prepare(request.raw, approval_raw, input_raw, approval_sha, input_sha)
        self._process.check_request(request)
        self._policy.check(self._process)
        if late is not None:
            late.check()
        reply = installation.install(request.raw, approval_raw, input_raw,
            approval_sha256=approval_sha, input_sha256=input_sha)
        self._process.check_request(request)
        self._policy.check(self._process)
        if late is not None:
            late.check()
        self._process.reply(request, reply)
        self._index += 1
        self._pending_head = self._pending_request = None
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
