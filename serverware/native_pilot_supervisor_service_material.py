"""One fixed fresh public-material bundle and its genuine cross-phase handoff.

Completed service owners are read only at their actual service-material entry.
The next phase receives immutable authenticated public data, not reconstructed
live predecessor owners. Earlier owners remain retained until terminal cleanup.
Only the existing phase executor publishes after independent complete approval.
"""
from __future__ import annotations

import time

from serverware import native_pilot_publication as publication
from serverware import native_pilot_service_material as profile
from serverware import native_pilot_supervisor_endpoint_deliveries as endpoints
from serverware import native_pilot_supervisor_endpoint_launches as launches
from serverware import native_pilot_supervisor_native_services as services
from serverware import native_shadow_nitro_originals as originals
from serverware import native_shadow_nitro_profile as p
from serverware.native_pilot_operator_channel import STAGES
from serverware.native_pilot_phase_execution import JOBS, MAX_RETAINED_BYTES

PHASE = "service-originals"
JOB = "service-material"
INDEX = 120
NEXT_PHASE = "bridge-runtime"
NEXT_JOB = "install-bridge-runtime"
ROLES = ("persistence", "generationInstall")
SERVICE_JOBS = {"persistence": "native-service-persistence", "generationInstall": "native-generation-install-grant"}
_LIVE = None
_USED = False


def _owners(policy, process, request):
    from serverware.native_pilot_supervisor_policy import SupervisorPolicy
    from serverware.native_pilot_supervisor_process import AuthorityCoordinatorProcess, JobRequest
    p.require(type(policy) is SupervisorPolicy and type(process) is AuthorityCoordinatorProcess
        and type(request) is JobRequest)
    policy.check(process); process.check_request(request)


def _same(first, second):
    p.require(p.canonical(first) == p.canonical(second))


def _approved(process, job):
    raw = process.approved_input_original(PHASE, job)
    p.require(p.sha(raw) == process.approved_input_sha256(PHASE, job))
    return raw


class _Attempt:
    def __init__(self, policy, process):
        self.policy, self.process = policy, process
        self.inflight = None
        self.failed = self.closed = self.close_attempted = self.composed = False
        self.retained_bytes = 0
        self.sources, self.source_results = {}, {}
        self.service_contexts, self.endpoint_launches = {}, {}
        self.launch_records = self.service_records = self.fragment = None
        self.input_raw = self.result_raw = self.phase_raw = self.window = self.boot = None
        self.deadline = self.issuer_deadline = self.epoch_limit = None
        self.last, self.last_wall = originals._clock(), time.time_ns()


def _reserve(owner, count):
    p.integer(count, minimum=0, maximum=MAX_RETAINED_BYTES)
    p.require(owner.retained_bytes + count <= MAX_RETAINED_BYTES)
    owner.retained_bytes += count


def _remember(owner, job, raw, result):
    p.require(type(raw) is bytes and _approved(owner.process, job) == raw)
    actual = owner.process.prior_result(PHASE, job)
    _same(actual, result)
    result_raw = p.canonical(actual)
    _reserve(owner, len(raw) + len(result_raw))
    owner.sources[job], owner.source_results[job] = raw, result_raw


def _capture(owner, request):
    installed = launches.require_launches(owner.policy, process=owner.process, request=request)
    native = services.recheck_services(owner.policy, process=owner.process, request=request)
    p.fields(installed, launches.ROLES); p.fields(native, services.OPERATIONS)
    owner.launch_records = {role: installed[role] for role in ROLES}
    owner.service_records = {role: native[role] for role in ROLES}
    owner.fragment = profile.validate_policy(owner.policy.service_material_policy(process=owner.process, request=request))
    phase = endpoints._phase(owner.process, PHASE)
    owner.phase_raw = p.canonical(phase)
    owner.boot, now, epoch = originals._boot(), originals._clock(), time.time_ns()
    for role in ROLES:
        service = p.fields(owner.service_records[role], ("inputOriginal", "grantOriginal"))
        p.require(all(type(raw) is bytes and raw for raw in service.values()))
        job = SERVICE_JOBS[role]
        result = p.fields(owner.process.prior_result(PHASE, job), ("original", "sha256", "pin"))
        p.require(result["original"] == service["grantOriginal"].decode("ascii")
            and p.digest(result["sha256"]) == p.sha(service["grantOriginal"]))
        _same(result["pin"], {"path": publication.DESTINATIONS[job], "sha256": p.sha(service["grantOriginal"])})
        _remember(owner, job, service["inputOriginal"], result)
        _reserve(owner, len(service["grantOriginal"]))
        owner.service_contexts[role] = dict(service)
        installed_role = p.fields(owner.launch_records[role], ("inputOriginal", "result"))
        _remember(owner, "install-launch-" + role, installed_role["inputOriginal"], installed_role["result"])
        owner.endpoint_launches[role] = dict(installed_role["result"]["launch"])
    raw = profile.build(fragment=owner.fragment, service_contexts=owner.service_contexts,
        endpoint_launches=owner.endpoint_launches, boot=owner.boot, now_boottime_ns=now, now_unix_ns=epoch)
    p.require(type(raw) is bytes and 0 < len(raw) <= JOBS[PHASE][INDEX - 1].maximum)
    checked = profile.prepare_bundle(raw, boot=owner.boot, now_boottime_ns=now, now_unix_ns=epoch)
    owner.input_raw, owner.window = raw, checked["window"]
    owner.issuer_deadline, owner.epoch_limit = checked["deadline"], checked["epochLimit"]
    owner.deadline = min(owner.issuer_deadline, p.ns(phase["deadlineBoottimeNs"]))
    _reserve(owner, len(raw) + len(owner.phase_raw) + len(p.canonical(owner.fragment))
        + len(p.canonical(owner.endpoint_launches)))


def _current(owner, request, *, next_phase=False):
    _owners(owner.policy, owner.process, request)
    p.require(_LIVE is owner and not owner.failed and not owner.closed)
    prior_phase = endpoints._phase(owner.process, PHASE)
    p.require(p.canonical(prior_phase) == owner.phase_raw)
    if next_phase:
        # The actual process admits this new phase only after its preceding
        # service-material reply. This is not permission to call an earlier
        # service owner with a different phase or manufacture a live owner.
        p.require(request.phase == NEXT_PHASE and request.job_index == 1 and request.job == NEXT_JOB
            and JOBS[NEXT_PHASE][0].name == NEXT_JOB and STAGES.index(NEXT_PHASE) == STAGES.index(PHASE) + 1)
        phase = endpoints._phase(owner.process, NEXT_PHASE)
        p.require(phase["sequence"] == prior_phase["sequence"] + 1)
        previous = p.fields(request.value["previousResult"], ("phase", "job", "result"))
        p.require(previous["phase"] == PHASE and previous["job"] == JOB)
        _same(previous["result"], owner.process.prior_result(PHASE, JOB))
    else:
        p.require(request.phase == PHASE and request.job_index == INDEX and request.job == JOB)
        phase = prior_phase
        installed = launches.recheck_launches(owner.policy, process=owner.process, request=request)
        native = services.recheck_services(owner.policy, process=owner.process, request=request)
        p.require({role: installed[role] for role in ROLES} == owner.launch_records
            and {role: native[role] for role in ROLES} == owner.service_records)
    p.require(p.sha(p.canonical(phase)) == request.value["conductorRequestSha256"]
        and request.deadline_boottime_ns == p.ns(phase["deadlineBoottimeNs"]))
    for job, raw in owner.sources.items():
        p.require(_approved(owner.process, job) == raw
            and p.canonical(owner.process.prior_result(PHASE, job)) == owner.source_results[job])
    _same(owner.policy.service_material_policy(process=owner.process, request=request), owner.fragment)
    now, epoch = originals._clock(), time.time_ns()
    p.require(originals._boot() == owner.boot and owner.last <= now < min(owner.deadline, request.deadline_boottime_ns)
        and owner.last_wall <= epoch < owner.epoch_limit)
    raw = profile.build(fragment=owner.fragment, service_contexts=owner.service_contexts,
        endpoint_launches=owner.endpoint_launches, boot=owner.boot, now_boottime_ns=now, now_unix_ns=epoch)
    p.require(raw == owner.input_raw)
    checked = profile.prepare_bundle(raw, boot=owner.boot, now_boottime_ns=now, now_unix_ns=epoch)
    _same(checked["window"], owner.window)
    p.require(checked["deadline"] == owner.issuer_deadline and checked["epochLimit"] == owner.epoch_limit)
    finished, finished_wall = originals._clock(), time.time_ns()
    p.require(originals._boot() == owner.boot
        and now <= finished < min(owner.deadline, request.deadline_boottime_ns)
        and epoch <= finished_wall < owner.epoch_limit)
    owner.last, owner.last_wall = finished, finished_wall
    return finished, finished_wall


def compose(policy, *, process, request) -> bytes:
    """Compose once at the genuine final service-originals job, before writes."""
    global _LIVE, _USED
    _owners(policy, process, request)
    p.require(request.phase == PHASE and request.job_index == INDEX and request.job == JOB
        and JOBS[PHASE][INDEX - 1].name == JOB and len(JOBS[PHASE]) == INDEX)
    p.require(_LIVE is None and not _USED)
    _USED = True
    owner = _Attempt(policy, process)
    _LIVE, owner.inflight = owner, request
    try:
        _capture(owner, request)
        _current(owner, request)
        owner.composed = True
        owner.inflight = None
        return owner.input_raw
    except BaseException:
        owner.failed = True
        raise


def require_material(policy, *, process, request) -> dict:
    """Authenticated public data only, at the genuine first bridge-runtime job."""
    _owners(policy, process, request)
    owner = _LIVE
    p.require(owner is not None and owner.policy is policy and owner.process is process and owner.composed
        and not owner.failed and not owner.closed and owner.inflight is None)
    owner.inflight = request
    try:
        now, epoch = _current(owner, request, next_phase=True)
        p.require(_approved(process, JOB) == owner.input_raw)
        result = process.prior_result(PHASE, JOB)
        checked = profile.checked_result(owner.input_raw, result, boot=owner.boot,
            now_boottime_ns=now, now_unix_ns=epoch)
        _same(checked, result)
        raw = p.canonical(checked)
        if owner.result_raw is None:
            _reserve(owner, len(raw))
            owner.result_raw = raw
        else:
            p.require(owner.result_raw == raw)
        _current(owner, request, next_phase=True)
        owner.inflight = None
        return {"inputOriginal": owner.input_raw, "result": checked}
    except BaseException:
        owner.failed = True
        raise


def close(process):
    """Release retained public data only after genuine terminal cleanup."""
    global _LIVE
    if _LIVE is None:
        return
    from serverware.native_pilot_supervisor_process import AuthorityCoordinatorProcess
    owner = _LIVE
    p.require(type(process) is AuthorityCoordinatorProcess and owner.process is process and process._closed
        and not owner.close_attempted
        and process._result["status"] in ("not-started", "stopped-cleanup-complete", "failed-cleanup-complete"))
    owner.close_attempted = True
    owner.sources.clear(); owner.source_results.clear()
    owner.service_contexts.clear(); owner.endpoint_launches.clear()
    for values in (owner.launch_records, owner.service_records):
        if values is not None:
            values.clear()
    owner.closed = True
    _LIVE = None
