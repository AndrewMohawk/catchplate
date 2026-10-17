"""Seven bridge decisions from one actual immutable runtime-owner handoff.

Every complete input is retained before the existing phase executor uses it.
Actual signed results are authenticated on first observation; later checks
require identical approved inputs, pins and result bytes inside the original
boot/UNIX bounds. No earlier live owner is re-entered, credential provisioned,
signature created, clock renewed or release authorized by this composer.
"""
from __future__ import annotations

import copy
import os
import time

from catchplate import custody_generation_grants as generation
from catchplate import native_pilot_bridge_authorization_profile as authorizations
from catchplate import native_pilot_bridge_delivery_profile as delivery
from catchplate import native_pilot_bridge_launch_profile as launch
from catchplate import native_pilot_supervisor_bridge_runtime as runtime
from catchplate import native_pilot_supervisor_current_heads as heads
from catchplate import native_pilot_supervisor_endpoint_deliveries as endpoints
from catchplate import native_shadow_nitro_originals as originals
from catchplate.native_pilot_phase_execution import JOBS, MAX_RETAINED_BYTES, job_index

p = generation.p
PHASE = "bridge-delivery"
JOB_NAMES = ("native-delivery-bridge", "native-role-keys-bridge", "native-key-admission-bridge",
    "native-closure-bridge", "native-encrypted-delivery-bridge", "native-verifier-transport-bridge",
    "install-launch-bridge")
AUTHORIZATION_JOBS = dict(zip(authorizations.OPERATIONS, JOB_NAMES[1:-1], strict=True))
NEXT_PHASE, NEXT_JOB = "release", "cohort-release"
NEXT_INDEX = job_index(NEXT_PHASE, NEXT_JOB)
_LIVE = None
_USED = False


def _owners(policy, process, request):
    from catchplate.native_pilot_supervisor_policy import SupervisorPolicy
    from catchplate.native_pilot_supervisor_process import AuthorityCoordinatorProcess, JobRequest
    p.require(type(policy) is SupervisorPolicy and type(process) is AuthorityCoordinatorProcess
        and type(request) is JobRequest)
    policy.check(process); process.check_request(request)


def _same(first, second):
    p.require(generation.canonical(first) == generation.canonical(second))


def _slot(request):
    p.require(tuple(job.name for job in JOBS[PHASE]) == JOB_NAMES
        and authorizations.OPERATIONS == ("role-keys", "admission", "closure", "encrypted-delivery", "verifier-transport")
        and request.phase == PHASE and type(request.job_index) is int
        and 1 <= request.job_index <= len(JOB_NAMES))
    index = request.job_index - 1
    p.require(request.job == JOB_NAMES[index])
    return index


class _Attempt:
    def __init__(self, policy, process):
        self.policy, self.process = policy, process
        self.pid, self.boot = os.getpid(), originals._boot()
        self.failed = self.closed = self.close_attempted = self.handoff_attempted = False
        self.inflight = self.handoff = self.fragment = self.activation = None
        self.inputs, self.outputs, self.results = {}, {}, {}
        self.sources, self.source_results, self.phases = {}, {}, {}
        self.next = self.retained_bytes = 0
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


def _capture(owner, request):
    # Only this first pending C9 job may enter the prior live runtime owner.
    handoff = runtime.require_commissioning_context(owner.policy, process=owner.process, request=request)
    p.fields(handoff, ("inputOriginal", "result", "bootstrapOriginals", "recipeOriginals", "measured",
        "historyOriginals", "trustedTime", "sourceInputs", "sourceResults", "conductorOriginals",
        "window", "deadline", "epochLimit"))
    owner.reserve(heads._public_size(handoff))
    owner.handoff = handoff
    owner.sources, owner.source_results = handoff["sourceInputs"].copy(), handoff["sourceResults"].copy()
    owner.phases = handoff["conductorOriginals"].copy()
    owner.deadline, owner.epoch_limit = handoff["deadline"], handoff["epochLimit"]
    phase = endpoints._phase(owner.process, PHASE)
    p.fields(phase["payload"], ("activation",))
    raw = p.canonical(phase)
    owner.reserve(len(raw) + heads._public_size(phase["payload"]["activation"]))
    owner.phases[PHASE] = raw
    owner.activation = copy.deepcopy(phase["payload"]["activation"])
    previous = p.document(owner.phases[runtime.PHASE], 32 * 1024 * 1024)
    p.require(phase["sequence"] == previous["sequence"] + 1)
    prior = p.fields(request.value["previousResult"], ("phase", "job", "result"))
    p.require(prior["phase"] == runtime.PHASE and prior["job"] == runtime.JOB
        and p.canonical(prior["result"]) == p.canonical(handoff["result"]))
    fragment = owner.policy.bridge_commissioning_policy(process=owner.process, request=request)
    owner.reserve(heads._public_size(fragment))
    owner.fragment = fragment
    owner.policy.require_bridge_keys(handoff["recipeOriginals"], process=owner.process, request=request)


def _delivery_options(owner):
    value = owner.handoff
    return dict(fragment=owner.fragment, runtime_bundle_raw=value["inputOriginal"], runtime_result=value["result"],
        bootstrap_originals=value["bootstrapOriginals"], activation=owner.activation,
        recipe_originals=value["recipeOriginals"], measured=value["measured"], history_originals=value["historyOriginals"])


def _common_options(owner):
    value = owner.handoff
    return dict(fragment=owner.fragment, control_original=value["bootstrapOriginals"]["control"],
        delivery_input_raw=owner.inputs[JOB_NAMES[0]], delivery_raw=owner.outputs[JOB_NAMES[0]],
        recipe_originals=value["recipeOriginals"], measured=value["measured"])


def _authorization_records(owner, operations):
    return {operation: {"inputOriginal": owner.inputs[AUTHORIZATION_JOBS[operation]],
        "authorizationOriginal": owner.outputs[AUTHORIZATION_JOBS[operation]]} for operation in operations}


def _launch_options(owner):
    return dict(_common_options(owner), authorizations=_authorization_records(owner, authorizations.OPERATIONS),
        service_context=owner.handoff["trustedTime"])


def _current(owner, request, *, release=False):
    _owners(owner.policy, owner.process, request)
    p.require(_LIVE is owner and not owner.failed and not owner.closed)
    owner.clock(request)
    p.require(owner.policy.bootstrap_originals() == owner.process.bootstrap_originals()
        == owner.handoff["bootstrapOriginals"])
    _same(owner.policy.bridge_commissioning_policy(process=owner.process, request=request), owner.fragment)
    for phase, raw in owner.phases.items():
        p.require(p.canonical(endpoints._phase(owner.process, phase)) == raw)
    for slot, raw in owner.sources.items():
        p.require(_approved(owner.process, *slot) == raw)
    for slot, raw in owner.source_results.items():
        p.require(p.canonical(owner.process.prior_result(*slot)) == raw)
    if release:
        p.require(request.phase == NEXT_PHASE and request.job == NEXT_JOB and request.job_index == NEXT_INDEX
            and NEXT_INDEX == 1 and JOBS[NEXT_PHASE][0].name == NEXT_JOB)
        current = endpoints._phase(owner.process, NEXT_PHASE)
        previous = p.document(owner.phases[PHASE], 32 * 1024 * 1024)
        p.require(current["sequence"] == previous["sequence"] + 1)
        prior = p.fields(request.value["previousResult"], ("phase", "job", "result"))
        p.require(prior["phase"] == PHASE and prior["job"] == JOB_NAMES[-1]
            and p.canonical(prior["result"]) == p.canonical(owner.process.prior_result(PHASE, JOB_NAMES[-1])))
    else:
        _slot(request)
        current = endpoints._phase(owner.process, PHASE)
    p.require(p.sha(p.canonical(current)) == request.value["conductorRequestSha256"]
        and request.deadline_boottime_ns == p.ns(current["deadlineBoottimeNs"]))
    _owners(owner.policy, owner.process, request)
    return owner.clock(request)


def _prior(owner, request):
    for index, job in enumerate(JOB_NAMES[:owner.next]):
        raw = _approved(owner.process, PHASE, job)
        p.require(raw == owner.inputs[job])
        result = owner.process.prior_result(PHASE, job)
        encoded = p.canonical(result)
        now, epoch = owner.clock(request)
        if job in owner.results:
            p.require(encoded == owner.results[job])
            if index < len(JOB_NAMES) - 1:
                p.require(owner.outputs[job] == result["original"].encode("ascii"))
            continue
        clocks = dict(boot=owner.boot, now_boottime_ns=now, now_unix_ns=epoch)
        if index == 0:
            checked = delivery.checked_result(raw, result, **_delivery_options(owner), **clocks)
        elif index == len(JOB_NAMES) - 1:
            checked = launch.checked_result(raw, result, **_launch_options(owner), **clocks)
        else:
            checked = authorizations.checked_result(authorizations.OPERATIONS[index - 1], raw, result, **clocks)
        owner.reserve(len(encoded) + (len(checked) if type(checked) is bytes else heads._public_size(checked)))
        owner.outputs[job], owner.results[job] = checked, encoded


def compose(policy, *, process, request) -> bytes:
    """Compose exactly one complete existing input for this pending job."""
    global _LIVE, _USED
    _owners(policy, process, request)
    index = _slot(request)
    if _LIVE is None:
        p.require(not _USED and index == 0)
        _USED = True
        _LIVE = _Attempt(policy, process)
    owner = _LIVE
    p.require(owner.policy is policy and owner.process is process and not owner.failed and not owner.closed
        and owner.inflight is None and owner.next == index)
    owner.inflight = request
    try:
        if index == 0:
            _capture(owner, request)
        _current(owner, request)
        _prior(owner, request)
        now, epoch = _current(owner, request)
        clocks = dict(boot=owner.boot, now_boottime_ns=now, now_unix_ns=epoch)
        if index == 0:
            prepared = delivery.prepare(**_delivery_options(owner), **clocks)
        elif index == len(JOB_NAMES) - 1:
            prepared = launch.prepare(**_launch_options(owner), **clocks)
        else:
            prepared = authorizations.prepare(authorizations.OPERATIONS[index - 1], **_common_options(owner),
                prior_authorizations=_authorization_records(owner, authorizations.OPERATIONS[:index - 1]), **clocks)
        field = "bundleOriginal" if index == len(JOB_NAMES) - 1 else "inputOriginal"
        p.fields(prepared, (field, "window", "deadline", "epochLimit"))
        _same(prepared["window"], owner.handoff["window"])
        raw = prepared[field]
        p.require(type(raw) is bytes and 0 < len(raw) <= JOBS[PHASE][index].maximum)
        owner.deadline = min(owner.deadline, prepared["deadline"])
        owner.epoch_limit = min(owner.epoch_limit, prepared["epochLimit"])
        _current(owner, request)
        owner.reserve(len(raw))
        owner.inputs[request.job] = raw
        owner.next += 1
        owner.inflight = None
        return raw
    except BaseException:
        owner.failed = True
        raise


def require_commissioning(policy, *, process, request):
    """One immutable seven-result handoff at release/1; not release approval."""
    _owners(policy, process, request)
    owner = _LIVE
    p.require(owner is not None and owner.policy is policy and owner.process is process
        and not owner.failed and not owner.closed and owner.inflight is None
        and owner.next == len(JOB_NAMES) and not owner.handoff_attempted)
    owner.handoff_attempted, owner.inflight = True, request
    try:
        _current(owner, request, release=True)
        _prior(owner, request)
        _current(owner, request, release=True)
        value = {"runtime": copy.deepcopy(owner.handoff),
            "records": {job: {"inputOriginal": owner.inputs[job],
                "result": p.document(owner.results[job], JOBS[PHASE][index].maximum)}
                for index, job in enumerate(JOB_NAMES)},
            "sourceInputs": owner.sources | {(PHASE, job): owner.inputs[job] for job in JOB_NAMES},
            "sourceResults": owner.source_results | {(PHASE, job): owner.results[job] for job in JOB_NAMES},
            "conductorOriginals": owner.phases.copy(), "deadline": owner.deadline, "epochLimit": owner.epoch_limit}
        owner.inflight = None
        return value
    except BaseException:
        owner.failed = True
        raise


def close(process):
    """Keep all partial retained data until this same process is terminal."""
    global _LIVE
    if _LIVE is None:
        return
    from catchplate.native_pilot_supervisor_process import AuthorityCoordinatorProcess
    owner = _LIVE
    p.require(type(process) is AuthorityCoordinatorProcess and owner.process is process and process._closed
        and os.getpid() == owner.pid and not owner.close_attempted
        and process._result["status"] in ("not-started", "stopped-cleanup-complete", "failed-cleanup-complete"))
    owner.close_attempted = True
    owner.inputs.clear(); owner.outputs.clear(); owner.results.clear()
    owner.sources.clear(); owner.source_results.clear(); owner.phases.clear()
    owner.handoff = owner.fragment = owner.activation = owner.inflight = None
    owner.closed = True
    _LIVE = None
