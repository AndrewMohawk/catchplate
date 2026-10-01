"""Retain the six final decisions across the actual conductor's phase changes.

The commissioning owner is entered once at release/1. Thereafter original
approved inputs, reported results and conductor frames must remain identical.
New signatures are authenticated at first observation, not inferred from pins.
Only the genuine origin phase may move from startup to the original lifetime
minus cleanup reserve, after checking the completed constructed admission.
The inherited UNIX expiry ceiling remains in force; this is no long-running
service acceptance claim. Final stop has no following result frame: actual
terminal cleanup, not a fabricated stop result, permits releasing this owner.
"""
from __future__ import annotations

import copy
import os
import time

from serverware import custody_generation_grants as generation
from serverware import native_pilot_continuation_profile as continuation
from serverware import native_pilot_interactive as interactive
from serverware import native_pilot_phase_two_publication as phase_two
from serverware import native_pilot_precreation_install as precreation
from serverware import native_pilot_publication as publication
from serverware import native_pilot_release_profile as release
from serverware import native_pilot_scope_authority as scope
from serverware import native_pilot_supervisor_bridge_commissioning as commissioning
from serverware import native_pilot_supervisor_current_heads as heads
from serverware import native_pilot_supervisor_endpoint_deliveries as endpoints
from serverware import native_shadow_nitro_originals as originals
from serverware import native_shadow_proof_cohort_assignment as cohort
from serverware.native_pilot_phase_execution import JOBS, MAX_RETAINED_BYTES, job_index

p = generation.p
JOB_SLOTS = (("release", "cohort-release"), ("release", "driver-scope"), ("release", "phase-two-public"),
    ("constructed-admission", "driver-constructed"), ("generation-origin", "observe-generation-origin"),
    ("shutdown", "stop"))
PHASES = tuple(dict.fromkeys(phase for phase, _ in JOB_SLOTS))
INDEXES = {slot: job_index(*slot) for slot in JOB_SLOTS}
_SIGNED_MAXIMUM = {"cohort-release": 32768, "driver-scope": 32768, "driver-constructed": 16384}
_SIGNED_PURPOSE = {"cohort-release": "cohort-release", "driver-scope": "driver-scope",
    "driver-constructed": "driver-constructed-admission"}
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


def _slot(request):
    p.require(tuple((phase, job.name) for phase in PHASES for job in JOBS[phase]) == JOB_SLOTS)
    slot = (request.phase, request.job)
    p.require(slot in INDEXES and request.job_index == INDEXES[slot])
    return JOB_SLOTS.index(slot)


def _approved(process, slot):
    raw = process.approved_input_original(*slot)
    p.require(type(raw) is bytes and p.sha(raw) == process.approved_input_sha256(*slot))
    return raw


class _Attempt:
    def __init__(self, policy, process):
        self.policy, self.process = policy, process
        self.pid, self.boot = os.getpid(), originals._boot()
        self.failed = self.closed = self.close_attempted = self.live_admitted = False
        self.inflight = self.handoff = self.fragment = self.window = self.operation_raw = None
        self.sources, self.source_results, self.phases = {}, {}, {}
        self.inputs, self.results, self.outputs, self.samples = {}, {}, {}, {}
        self.next = self.retained_bytes = 0
        self.startup_deadline = self.live_deadline = self.epoch_limit = None
        self.last, self.last_wall = originals._clock(), time.time_ns()

    def reserve(self, count):
        p.integer(count, minimum=0, maximum=MAX_RETAINED_BYTES)
        p.require(self.retained_bytes + count <= MAX_RETAINED_BYTES)
        self.retained_bytes += count

    def clock(self, request, *, observing_constructed=False):
        now, epoch = originals._clock(), time.time_ns()
        live = request.phase in ("generation-origin", "shutdown")
        if live:
            p.require(self.live_admitted or (observing_constructed and self.next == 4
                and (request.phase, request.job) == JOB_SLOTS[4]))
        bound = self.live_deadline if live else self.startup_deadline
        p.require(os.getpid() == self.pid and originals._boot() == self.boot
            and self.last <= now < min(bound, request.deadline_boottime_ns)
            and self.last_wall <= epoch < self.epoch_limit)
        self.last, self.last_wall = now, epoch
        return now, epoch


def _remember(owner, slot):
    raw = _approved(owner.process, slot)
    result_raw = p.canonical(owner.process.prior_result(*slot))
    if slot in owner.sources:
        p.require(owner.sources[slot] == raw and owner.source_results[slot] == result_raw)
    else:
        owner.reserve(len(raw) + len(result_raw))
        owner.sources[slot], owner.source_results[slot] = raw, result_raw


def _lifetime(owner):
    """Project existing operator bounds from authenticated retained originals."""
    installed = p.fields(p.document(owner.sources[("endpoint-precreation", "install-precreation")],
        precreation.MAX_INPUT), precreation.FIELDS)
    cohort_window = p.document(installed["cohortPrecreationOriginal"].encode("ascii"), cohort.MAX_BYTES)["payload"]
    ordinary = generation.document(installed["ordinaryLaunchOriginal"].encode("ascii"), 65536)
    windows = (owner.window, cohort_window, ordinary)
    for window in windows:
        p.require(tuple(window[name] for name in ("bootIdBase64url", "timeNamespaceDevice", "timeNamespaceInode")) == owner.boot
            and p.ns(window["startupDeadlineBoottimeNs"]) <= p.ns(window["lifetimeDeadlineBoottimeNs"]))
    bootstrap = p.document(owner.handoff["runtime"]["bootstrapOriginals"]["configuration"], 65536)
    production = p.fields(owner.handoff["runtime"]["measured"]["production"], scope.PRODUCTION_FIELDS)
    reserve = max(p.integer(bootstrap["lifecycle"]["cleanupReserveNanos"], minimum=1_000_000, maximum=5_000_000_000),
        p.integer(production["cleanupReserveNanos"], maximum=5_000_000_000))
    owner.startup_deadline = min(owner.startup_deadline, *(p.ns(value["startupDeadlineBoottimeNs"]) for value in windows))
    owner.live_deadline = min(p.ns(value["lifetimeDeadlineBoottimeNs"]) for value in windows) - reserve
    if "interactive" in owner.fragment:
        # Same fixed reap reserve as native_guest/parent.rs; not a new lease.
        owner.live_deadline = min(owner.live_deadline,
            p.ns(cohort_window["lifetimeDeadlineBoottimeNs"]) - 250_000_000)
    p.require(owner.live_deadline > 0)


def _capture(owner, request):
    handoff = commissioning.require_commissioning(owner.policy, process=owner.process, request=request)
    p.fields(handoff, ("runtime", "records", "sourceInputs", "sourceResults", "conductorOriginals", "deadline", "epochLimit"))
    owner.reserve(heads._public_size(handoff))
    owner.handoff = handoff
    owner.sources, owner.source_results = handoff["sourceInputs"].copy(), handoff["sourceResults"].copy()
    owner.phases = handoff["conductorOriginals"].copy()
    owner.window = copy.deepcopy(handoff["runtime"]["window"])
    owner.reserve(heads._public_size(owner.window))
    owner.startup_deadline, owner.epoch_limit = handoff["deadline"], handoff["epochLimit"]
    fixed = (("bootstrap-admission", "driver-bootstrap"), ("endpoint-precreation", "cohort-precreation"),
        ("endpoint-precreation", "install-precreation")) + tuple(("service-originals", "install-launch-" + role)
            for role in cohort.ENDPOINT_ROLES) + tuple(("service-originals", "ordinary-generation-" + role)
                for role in generation.ROLES)
    for slot in fixed:
        _remember(owner, slot)
    # These are actual process originals added to public data, not reconstructed
    # owner authority. Every entry is checked byte-for-byte on later requests.
    handoff["sourceInputs"], handoff["sourceResults"] = owner.sources.copy(), owner.source_results.copy()
    owner.fragment = owner.policy.continuation_policy(process=owner.process, request=request)
    owner.reserve(heads._public_size(owner.fragment))
    _lifetime(owner)


def _enter_phase(owner, request, index):
    value = endpoints._phase(owner.process, request.phase)
    raw = p.canonical(value)
    if request.phase in owner.phases:
        p.require(raw == owner.phases[request.phase])
    else:
        p.require(request.job_index == 1)
        previous_phase = commissioning.PHASE if index == 0 else JOB_SLOTS[index - 1][0]
        previous = p.document(owner.phases[previous_phase], 32 * 1024 * 1024)
        p.require(value["sequence"] == previous["sequence"] + 1)
        owner.reserve(len(raw))
        owner.phases[request.phase] = raw
    p.require(p.sha(raw) == request.value["conductorRequestSha256"]
        and p.ns(value["deadlineBoottimeNs"]) == request.deadline_boottime_ns)
    previous_slot = (commissioning.PHASE, commissioning.JOB_NAMES[-1]) if index == 0 else JOB_SLOTS[index - 1]
    prior = p.fields(request.value["previousResult"], ("phase", "job", "result"))
    p.require((prior["phase"], prior["job"]) == previous_slot
        and p.canonical(prior["result"]) == p.canonical(owner.process.prior_result(*previous_slot)))
    if index == 0:
        p.require(p.canonical(prior["result"]) == owner.source_results[previous_slot])
        observed = p.fields(value["payload"], ("operationOriginal",))
        owner.operation_raw = observed["operationOriginal"].encode("ascii")
        owner.reserve(len(owner.operation_raw))
    return value["payload"]


def _current(owner, request, *, observing_constructed=False):
    _owners(owner.policy, owner.process, request)
    p.require(_LIVE is owner and not owner.failed and not owner.closed)
    owner.clock(request, observing_constructed=observing_constructed)
    p.require(owner.policy.bootstrap_originals() == owner.process.bootstrap_originals()
        == owner.handoff["runtime"]["bootstrapOriginals"])
    _same(owner.policy.continuation_policy(process=owner.process, request=request), owner.fragment)
    for phase, raw in owner.phases.items():
        p.require(p.canonical(endpoints._phase(owner.process, phase)) == raw)
    for slot, raw in owner.sources.items():
        p.require(_approved(owner.process, slot) == raw)
    for slot, raw in owner.source_results.items():
        p.require(p.canonical(owner.process.prior_result(*slot)) == raw)
    _owners(owner.policy, owner.process, request)
    return owner.clock(request, observing_constructed=observing_constructed)


def _release_options(owner):
    return dict(commissioning_context=owner.handoff, endpoint_images=owner.fragment["endpointImages"],
        operation_raw=owner.operation_raw)


def _scope_context(owner):
    slot = JOB_SLOTS[1]
    return {"inputOriginal": owner.inputs[slot], "scopeOriginal": owner.outputs[slot]}


def _constructed_context(owner):
    slot = JOB_SLOTS[3]
    sample = owner.samples[slot]
    return {"inputOriginal": owner.inputs[slot], "result": p.document(owner.results[slot], 65536),
        "preparedAtBoottimeNs": sample[0], "preparedAtUnixNanos": sample[1]}


def _signed(result, job):
    p.fields(result, ("original", "sha256", "pin"))
    raw = result["original"].encode("ascii")
    p.require(0 < len(raw) <= _SIGNED_MAXIMUM[job] and p.sha(raw) == p.digest(result["sha256"]))
    _same(result["pin"], {"path": publication.DESTINATIONS[_SIGNED_PURPOSE[job]], "sha256": p.sha(raw)})
    return raw


def _phase_two(owner):
    value = p.document(owner.inputs[JOB_SLOTS[1]], scope.MAX_BRIDGE_INPUT)
    raw = value["publicBundleOriginal"].encode("ascii")
    p.document(raw, scope.MAX_BRIDGE_INPUT)
    return raw


def _prior(owner, request, *, observing_constructed=False):
    for slot in JOB_SLOTS[:owner.next]:
        p.require(_approved(owner.process, slot) == owner.inputs[slot])
        result = owner.process.prior_result(*slot)
        raw = p.canonical(result)
        if slot in owner.results:
            p.require(raw == owner.results[slot])
            continue
        now, epoch = owner.clock(request, observing_constructed=observing_constructed)
        clocks = dict(boot=owner.boot, now_boottime_ns=now, now_unix_ns=epoch)
        job = slot[1]
        if job in ("cohort-release", "driver-scope"):
            signed = _signed(result, job)
            checked = release.checked_result(job, owner.inputs[slot],
                {"original": signed.decode("ascii"), "sha256": p.sha(signed)}, **_release_options(owner), **clocks)
            p.require(checked == signed)
        elif job == "phase-two-public":
            p.require(phase_two.prepare_input(owner.inputs[slot]) == _phase_two(owner))
            checked = phase_two.checked_result(owner.inputs[slot], result)
        elif job == "driver-constructed":
            signed = _signed(result, job)
            prepared = owner.samples[slot]
            checked = continuation.checked_constructed(owner.inputs[slot], result,
                prepared_at_boottime_ns=prepared[0], prepared_at_unix_ns=prepared[1],
                deadline_boottime_ns=owner.live_deadline, **clocks)
            p.require(checked == signed)
        else:
            p.require(job == "observe-generation-origin")
            checked = p.fields(p.document(owner.inputs[slot], 1024), ("action",))
            p.require(checked["action"] == "observe-installed-generation")
            p.fields(result, ("action",)); _same(result, checked)
        owner.reserve(len(raw) + (len(checked) if type(checked) is bytes else heads._public_size(checked)))
        owner.results[slot], owner.outputs[slot] = raw, checked


def compose(policy, *, process, request) -> bytes:
    """Build one complete input; never sign, publish, release or stop a child."""
    global _LIVE, _USED
    _owners(policy, process, request)
    index = _slot(request)
    if _LIVE is None:
        p.require(not _USED and index == 0 and request.job_index == 1)
        _USED = True
        _LIVE = _Attempt(policy, process)
    owner = _LIVE
    p.require(owner.policy is policy and owner.process is process and not owner.failed and not owner.closed
        and owner.inflight is None and owner.next == index)
    owner.inflight = request
    try:
        if index == 0:
            _capture(owner, request)
        observed = _enter_phase(owner, request, index)
        transitional = index == 4 and not owner.live_admitted
        _current(owner, request, observing_constructed=transitional)
        _prior(owner, request, observing_constructed=transitional)
        if transitional:
            p.require(observed["constructedAdmissionSha256"] == p.sha(owner.outputs[JOB_SLOTS[3]]))
            owner.live_admitted = True
        now, epoch = _current(owner, request)
        clocks = dict(boot=owner.boot, now_boottime_ns=now, now_unix_ns=epoch)
        if index < 2:
            prepared = release.prepare(request.job, **_release_options(owner), **clocks)
        elif index == 2:
            prepared = {"inputOriginal": phase_two.build(_phase_two(owner)), "window": owner.window,
                "deadline": owner.startup_deadline, "epochLimit": owner.epoch_limit}
        else:
            prior = None if index == 3 else _constructed_context(owner)
            if index == 5:
                prior.update(originInputOriginal=owner.inputs[JOB_SLOTS[4]],
                    originResult=p.document(owner.results[JOB_SLOTS[4]], 1024),
                    originObservation=p.document(owner.phases["generation-origin"], 32 * 1024 * 1024)["payload"])
            prepared = continuation.prepare(request.job, fragment=owner.fragment["constructedAdmission"],
                commissioning_context=owner.handoff, scope_context=_scope_context(owner), observed=observed,
                prior_context=prior, deadline_boottime_ns=(owner.live_deadline if index >= 4 else owner.startup_deadline),
                **clocks)
            if index == 5 and "interactive" in owner.fragment:
                # The ordinary stop preparation above still verifies the real
                # origin handoff and every inherited clock/ownership bound.
                # Only explicitly selected policy/v20 permits this action.
                selected = interactive.validate_policy(owner.fragment["interactive"])
                stop_at, expires = selected["stopAtBoottimeNanos"], selected["expiresAtUnixNanos"]
                p.require(now < stop_at < min(prepared["deadline"], owner.live_deadline, request.deadline_boottime_ns)
                    and epoch < expires <= min(owner.epoch_limit, prepared["epochLimit"])
                    and stop_at - now < expires - epoch)
                action = interactive.validate_action({"action": "run-interactive",
                    "originHandoffSha256": p.sha(p.canonical(observed["originHandoff"])),
                    "stopAtBoottimeNanos": stop_at, "expiresAtUnixNanos": expires},
                    origin_handoff=observed["originHandoff"])
                prepared["inputOriginal"] = p.canonical(action)
        p.fields(prepared, ("inputOriginal", "window", "deadline", "epochLimit"))
        _same(prepared["window"], owner.window)
        raw = prepared["inputOriginal"]
        p.require(type(raw) is bytes and 0 < len(raw) <= JOBS[request.phase][request.job_index - 1].maximum)
        if index < 4:
            owner.startup_deadline = min(owner.startup_deadline, prepared["deadline"])
        else:
            owner.live_deadline = min(owner.live_deadline, prepared["deadline"])
        owner.epoch_limit = min(owner.epoch_limit, prepared["epochLimit"])
        _current(owner, request)
        owner.reserve(len(raw))
        slot = JOB_SLOTS[index]
        owner.inputs[slot], owner.samples[slot] = raw, (now, epoch)
        owner.next += 1
        owner.inflight = None
        return raw
    except BaseException:
        owner.failed = True
        raise


def close(process):
    """Keep the actual attempt until terminal cleanup; no invented stop result."""
    global _LIVE
    if _LIVE is None:
        return
    from serverware.native_pilot_supervisor_process import AuthorityCoordinatorProcess
    owner = _LIVE
    p.require(type(process) is AuthorityCoordinatorProcess and owner.process is process and process._closed
        and os.getpid() == owner.pid and not owner.close_attempted
        and process._result["status"] in ("not-started", "stopped-cleanup-complete", "failed-cleanup-complete"))
    owner.close_attempted = True
    owner.inputs.clear(); owner.results.clear(); owner.outputs.clear(); owner.samples.clear()
    owner.sources.clear(); owner.source_results.clear(); owner.phases.clear()
    owner.handoff = owner.fragment = owner.window = owner.operation_raw = owner.inflight = None
    owner.closed = True
    _LIVE = None
