"""One retained full bridge-runtime bundle from actual completed jobs.

The current-head owner transfers immutable verified originals only at the
runtime-install boundary. Earlier live owners are never re-entered. Complete
source signatures are checked when building; the actual installation result
is checked once, then only byte-identical data can be reused inside the same
original clock bounds. This owner neither writes credentials nor publishes.
"""
from __future__ import annotations

import copy
import os
import time

from serverware import custody_generation_grants as generation
from serverware import native_pilot_bridge_runtime_profile as profile
from serverware import native_pilot_endpoint_launch_profile as endpoint_launch
from serverware import native_pilot_native_service_profile as native
from serverware import native_pilot_ordinary_transition_profile as transitions
from serverware import native_pilot_publication as publication
from serverware import native_pilot_supervisor_current_heads as heads
from serverware import native_pilot_supervisor_endpoint_deliveries as endpoints
from serverware import native_shadow_nitro_originals as originals
from serverware import native_shadow_proof_cohort_assignment as cohort
from serverware.native_pilot_phase_execution import JOBS, MAX_RETAINED_BYTES, job_index

p = generation.p
PHASE, JOB = "bridge-runtime", "install-bridge-runtime"
INDEX = job_index(PHASE, JOB)
NEXT_PHASE, NEXT_JOB = "bridge-delivery", "native-delivery-bridge"
NEXT_INDEX = job_index(NEXT_PHASE, NEXT_JOB)
TRANSITION_JOBS = tuple("ordinary-" + operation + ("-" + role if operation == "dispatch" else "")
    for operation, role in transitions.JOBS)
NATIVE_JOBS = {operation: "native-generation-install-grant" if operation == "generationInstall"
    else "native-service-" + operation for operation in native.OPERATIONS}
_LIVE = None
_USED = False


def _owners(policy, process, request):
    from serverware.native_pilot_supervisor_policy import SupervisorPolicy
    from serverware.native_pilot_supervisor_process import AuthorityCoordinatorProcess, JobRequest
    p.require(type(policy) is SupervisorPolicy and type(process) is AuthorityCoordinatorProcess
        and type(request) is JobRequest)
    policy.check(process); process.check_request(request)


def _same(first, second):
    p.require(generation.canonical(first) == generation.canonical(second))


class _Attempt:
    def __init__(self, policy, process):
        self.policy, self.process = policy, process
        self.pid, self.boot = os.getpid(), originals._boot()
        self.failed = self.closed = self.close_attempted = self.composed = False
        self.inflight = self.kwargs = self.handoff = self.window = None
        self.input_raw = self.result_raw = self.result = self.fragment = None
        self.sources, self.source_results, self.phases = {}, {}, {}
        self.retained_bytes = 0
        self.deadline = self.epoch_limit = None
        self.last, self.last_wall = originals._clock(), time.time_ns()

    def reserve(self, count):
        p.integer(count, minimum=0, maximum=MAX_RETAINED_BYTES)
        p.require(self.retained_bytes + count <= MAX_RETAINED_BYTES)
        self.retained_bytes += count

    def clock(self, request):
        now, epoch = originals._clock(), time.time_ns()
        p.require(os.getpid() == self.pid and originals._boot() == self.boot
            and self.last <= now < min(self.deadline, request.deadline_boottime_ns)
            and self.last_wall <= epoch < self.epoch_limit)
        self.last, self.last_wall = now, epoch
        return now, epoch


def _approved(process, phase, job):
    raw = process.approved_input_original(phase, job)
    p.require(type(raw) is bytes and p.sha(raw) == process.approved_input_sha256(phase, job))
    return raw


def _remember(owner, phase, job):
    raw = _approved(owner.process, phase, job)
    result = owner.process.prior_result(phase, job)
    result_raw = p.canonical(result)
    slot = (phase, job)
    if slot in owner.sources:
        p.require(owner.sources[slot] == raw and owner.source_results[slot] == result_raw)
    else:
        owner.reserve(len(raw) + len(result_raw))
        owner.sources[slot], owner.source_results[slot] = raw, result_raw
    return raw, result


def _signed(owner, phase, job, field):
    raw, result = _remember(owner, phase, job)
    p.fields(result, ("original", "sha256", "pin"))
    p.require(type(result["original"]) is str and result["original"].isascii())
    original = result["original"].encode("ascii")
    p.require(p.sha(original) == p.digest(result["sha256"]))
    _same(result["pin"], {"path": publication.DESTINATIONS[job], "sha256": p.sha(original)})
    return {"inputOriginal": raw, field: original}


def _capture(owner, request):
    # This is the only live predecessor-owner entry. All subsequent checks use
    # actual process originals/pins/results and the immutable combined handoff.
    handoff = heads.require_runtime_context(owner.policy, process=owner.process, request=request)
    p.fields(handoff, ("context", "heads", "material", "bootstrapOriginals", "sourceInputs",
        "sourceResults", "conductorOriginals", "deadline", "epochLimit"))
    owner.reserve(heads._public_size(handoff))
    owner.handoff = handoff
    owner.sources = handoff["sourceInputs"].copy()
    owner.source_results = handoff["sourceResults"].copy()
    owner.phases = handoff["conductorOriginals"].copy()
    owner.deadline, owner.epoch_limit = handoff["deadline"], handoff["epochLimit"]
    fragment = owner.policy.bridge_runtime_policy(process=owner.process, request=request)
    owner.reserve(heads._public_size(fragment))
    owner.fragment = fragment
    p.require(handoff["bootstrapOriginals"] == owner.process.bootstrap_originals())
    phase = endpoints._phase(owner.process, PHASE)
    p.require(p.canonical(phase) == owner.phases[PHASE])
    observed = p.fields(phase["payload"], ("bridgePreparationOriginal", "ordinaryGenerationGrants",
        "endpointLaunches", "nativeGrantSha256s", "bridgeJournal", "cohortObservationOriginal", "ordinaryParked"))
    context_sources = handoff["context"]["sources"]
    p.require(observed["bridgePreparationOriginal"].encode("ascii") == context_sources["bridge_preparation_raw"])
    bootstrap = p.document(owner.phases["bootstrap-admission"], 32 * 1024 * 1024)["payload"]
    precreation = endpoints._phase(owner.process, "endpoint-precreation")
    owner.phases["endpoint-precreation"] = p.canonical(precreation)
    owner.reserve(len(owner.phases["endpoint-precreation"]))
    service = p.document(owner.phases["service-originals"], 32 * 1024 * 1024)["payload"]
    p.require(observed["cohortObservationOriginal"] == service["cohortObservationOriginal"])
    transition_context = {job: _signed(owner, "service-originals", job, "grantOriginal")
        for job in TRANSITION_JOBS}
    native_context = {operation: _signed(owner, "service-originals", job, "grantOriginal")
        for operation, job in NATIVE_JOBS.items()}
    native_deliveries = {role: _signed(owner,
        "endpoint-deliveries" if role in endpoints.ROLES else "service-originals",
        "native-delivery-" + role, "deliveryOriginal") for role in cohort.ENDPOINT_ROLES}
    grant_pins = p.fields(observed["nativeGrantSha256s"], cohort.ENDPOINT_ROLES)
    for role in cohort.ENDPOINT_ROLES:
        p.require(p.digest(grant_pins[role])
            == p.sha(native_context[endpoint_launch.SERVICE_OPERATIONS[role]]["grantOriginal"]))
    ordinary_pins = p.fields(observed["ordinaryGenerationGrants"], generation.ROLES)
    for role in generation.ROLES:
        p.require(p.digest(ordinary_pins[role]) == p.sha(
            context_sources["ordinary_context"][role]["generationGrantOriginal"].encode("ascii")))
    kwargs = dict(fragment=owner.fragment, current_context=handoff["context"], heads=handoff["heads"],
        bootstrap_originals=handoff["bootstrapOriginals"],
        driver_observation_raw=bootstrap["bootstrapObservationOriginal"].encode("ascii"),
        cohort_observation_raw=observed["cohortObservationOriginal"].encode("ascii"),
        gate_binding_raw=precreation["payload"]["gateBindingOriginal"].encode("ascii"),
        bridge_journal=copy.deepcopy(observed["bridgeJournal"]), transition_context=transition_context,
        native_context=native_context, native_delivery_context=native_deliveries)
    owner.reserve(heads._public_size(kwargs))
    owner.kwargs = kwargs
    now, epoch = owner.clock(request)
    prepared = profile.prepare(**owner.kwargs, boot=owner.boot, now_boottime_ns=now, now_unix_ns=epoch)
    p.fields(prepared, ("bundleOriginal", "window", "deadline", "epochLimit"))
    raw = prepared["bundleOriginal"]
    p.require(type(raw) is bytes and 0 < len(raw) <= JOBS[PHASE][INDEX - 1].maximum)
    owner.reserve(len(raw) + heads._public_size(prepared["window"]))
    owner.input_raw, owner.window = raw, copy.deepcopy(prepared["window"])
    owner.deadline = min(owner.deadline, prepared["deadline"], request.deadline_boottime_ns)
    owner.epoch_limit = min(owner.epoch_limit, prepared["epochLimit"])


def _current(owner, request, *, installed=False):
    _owners(owner.policy, owner.process, request)
    p.require(_LIVE is owner and not owner.failed and not owner.closed)
    owner.clock(request)
    p.require(owner.policy.bootstrap_originals() == owner.process.bootstrap_originals()
        == owner.handoff["bootstrapOriginals"])
    _same(owner.policy.bridge_runtime_policy(process=owner.process, request=request), owner.fragment)
    sources = owner.handoff["context"]["sources"]
    _same(owner.policy.current_head_policy(process=owner.process, request=request), sources["fragment"])
    _same(owner.policy.ordinary_initial_policy(process=owner.process, request=request), sources["initial_policy"])
    for phase, raw in owner.phases.items():
        p.require(p.canonical(endpoints._phase(owner.process, phase)) == raw)
    for slot, raw in owner.sources.items():
        p.require(_approved(owner.process, *slot) == raw)
    for slot, raw in owner.source_results.items():
        p.require(p.canonical(owner.process.prior_result(*slot)) == raw)
    if installed:
        p.require(request.phase == NEXT_PHASE and request.job == NEXT_JOB and request.job_index == NEXT_INDEX
            and NEXT_INDEX == 1 and JOBS[NEXT_PHASE][0].name == NEXT_JOB)
        current = endpoints._phase(owner.process, NEXT_PHASE)
        previous = p.document(owner.phases[PHASE], 32 * 1024 * 1024)
        p.require(current["sequence"] == previous["sequence"] + 1)
        prior = p.fields(request.value["previousResult"], ("phase", "job", "result"))
        p.require(prior["phase"] == PHASE and prior["job"] == JOB
            and p.canonical(prior["result"]) == p.canonical(owner.process.prior_result(PHASE, JOB)))
        p.require(_approved(owner.process, PHASE, JOB) == owner.input_raw)
    else:
        p.require(request.phase == PHASE and request.job == JOB and request.job_index == INDEX)
        current = endpoints._phase(owner.process, PHASE)
    p.require(p.sha(p.canonical(current)) == request.value["conductorRequestSha256"]
        and request.deadline_boottime_ns == p.ns(current["deadlineBoottimeNs"]))
    _owners(owner.policy, owner.process, request)
    return owner.clock(request)


def compose(policy, *, process, request) -> bytes:
    """Build once for the genuine pending installation; never publish here."""
    global _LIVE, _USED
    _owners(policy, process, request)
    p.require(request.phase == PHASE and request.job == JOB and request.job_index == INDEX
        and JOBS[PHASE][INDEX - 1].name == JOB and len(JOBS[PHASE]) == INDEX)
    p.require(_LIVE is None and not _USED)
    _USED = True
    owner = _Attempt(policy, process)
    _LIVE, owner.inflight = owner, request
    try:
        _capture(owner, request)
        _current(owner, request)
        owner.composed, owner.inflight = True, None
        return owner.input_raw
    except BaseException:
        owner.failed = True
        raise


def checked_result(policy, *, process, request):
    """Check the actual installed result, only at the first delivery request."""
    _owners(policy, process, request)
    owner = _LIVE
    p.require(owner is not None and owner.policy is policy and owner.process is process
        and owner.composed and not owner.failed and not owner.closed and owner.inflight is None)
    owner.inflight = request
    try:
        now, epoch = _current(owner, request, installed=True)
        result = process.prior_result(PHASE, JOB)
        raw = p.canonical(result)
        if owner.result_raw is None:
            checked = profile.checked_result(owner.input_raw, result, **owner.kwargs,
                boot=owner.boot, now_boottime_ns=now, now_unix_ns=epoch)
            p.require(p.canonical(checked) == raw)
            owner.reserve(len(raw) + heads._public_size(checked))
            owner.result_raw, owner.result = raw, copy.deepcopy(checked)
        else:
            p.require(raw == owner.result_raw)
        _current(owner, request, installed=True)
        owner.inflight = None
        return copy.deepcopy(owner.result)
    except BaseException:
        owner.failed = True
        raise


def require_runtime(policy, *, process, request):
    """Return immutable public data at the real first bridge-delivery job only."""
    result = checked_result(policy, process=process, request=request)
    return {"inputOriginal": _LIVE.input_raw, "result": result}


def close(process):
    """Retire data only after this same process has known terminal cleanup."""
    global _LIVE
    if _LIVE is None:
        return
    from serverware.native_pilot_supervisor_process import AuthorityCoordinatorProcess
    owner = _LIVE
    p.require(type(process) is AuthorityCoordinatorProcess and owner.process is process and process._closed
        and os.getpid() == owner.pid and not owner.close_attempted
        and process._result["status"] in ("not-started", "stopped-cleanup-complete", "failed-cleanup-complete"))
    owner.close_attempted = True
    owner.sources.clear(); owner.source_results.clear(); owner.phases.clear()
    owner.kwargs = owner.handoff = owner.fragment = owner.window = None
    owner.input_raw = owner.result_raw = owner.result = owner.inflight = None
    owner.closed = True
    _LIVE = None
