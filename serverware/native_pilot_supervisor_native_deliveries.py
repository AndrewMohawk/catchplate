"""Seven retained C9 decisions after the actual ordinary-generation handoff.

The source-fixed jobs use the precreated resources, independently admitted
runtime markers/credential metadata and the original signed cohort window.
No resources, credentials, keys, runtime files or signatures are created here.
Generation grants establish prior-job ordering, never fields in these C9
inputs. A failed attempt cannot retry; public originals stay retained until
genuine process cleanup. The final C9 result first exists at the next job.
"""
from __future__ import annotations

import copy
import time

from serverware import custody_generation_grants as generation
from serverware import native_pilot_delivery_authority as c9
from serverware import native_pilot_native_delivery_profile as profile
from serverware import native_pilot_ordinary_install as installation
from serverware import native_pilot_precreation_install as precreation
from serverware import native_pilot_supervisor_endpoint_deliveries as endpoints
from serverware import native_pilot_supervisor_ordinary_generations as generations
from serverware import native_shadow_nitro_originals as originals
from serverware import native_shadow_proof_cohort_assignment as cohort
from serverware.native_pilot_phase_execution import JOBS, MAX_RETAINED_BYTES, job_index

p = c9.p
ROLES = profile.ROLES
FIRST_INDEX = job_index("service-originals", "native-delivery-" + ROLES[0])
NEXT_JOB = "native-role-keys-retrieval"
NEXT_INDEX = job_index("service-originals", NEXT_JOB)
_LIVE = None
_USED = False


def _same(first, second):
    p.require(generation.canonical(first) == generation.canonical(second))


def _owners(policy, process, request):
    from serverware.native_pilot_supervisor_policy import SupervisorPolicy
    from serverware.native_pilot_supervisor_process import AuthorityCoordinatorProcess, JobRequest
    p.require(type(policy) is SupervisorPolicy and type(process) is AuthorityCoordinatorProcess
        and type(request) is JobRequest)
    policy.check(process); process.check_request(request)


def _slot(request):
    p.require(request.phase == "service-originals" and type(request.job_index) is int
        and FIRST_INDEX <= request.job_index < FIRST_INDEX + len(ROLES))
    index = request.job_index - FIRST_INDEX
    p.require(request.job == "native-delivery-" + ROLES[index]
        and tuple(job.name for job in JOBS["service-originals"][FIRST_INDEX - 1:FIRST_INDEX - 1 + len(ROLES)])
        == tuple("native-delivery-" + role for role in ROLES))
    return index


def checked_result(role, input_raw, result) -> bytes:
    """Pure prior-input/signature/pin check; not an owner or admission verdict."""
    return profile.checked_result(role, input_raw, result)


class _Attempt:
    def __init__(self, policy, process):
        self.policy, self.process = policy, process
        self.next, self.retained_bytes = 0, 0
        self.inflight = None
        self.failed = self.closed = self.close_attempted = False
        self.key_boundary_open = False
        self.inputs, self.deliveries, self.results = {}, {}, {}
        self.generations, self.generation_inputs = {}, {}
        self.fragment = self.measured = self.recipe_originals = None
        self.phase_raw = self.installed_raw = self.earlier_phase_raw = None
        self.configuration_raw = self.window_raw = self.observation_raw = None
        self.window = self.boot = self.deadline = None
        self.cold, self.activations = {}, {}
        self.last, self.last_wall = originals._clock(), time.time_ns()


def _reserve(owner, count):
    p.integer(count, minimum=0, maximum=MAX_RETAINED_BYTES)
    p.require(owner.retained_bytes + count <= MAX_RETAINED_BYTES)
    owner.retained_bytes += count


def _approved(process, phase, job):
    raw = process.approved_input_original(phase, job)
    p.require(p.sha(raw) == process.approved_input_sha256(phase, job))
    return raw


def _current(owner, request):
    _owners(owner.policy, owner.process, request)
    p.require(_LIVE is owner and not owner.failed and not owner.closed)
    actual = generations.recheck_generations(owner.policy, process=owner.process, request=request)
    p.require(actual == owner.generations)
    for role in generation.ROLES:
        p.require(_approved(owner.process, "service-originals", "ordinary-generation-" + role)
            == owner.generation_inputs[role])
    phase = endpoints._phase(owner.process, "service-originals")
    p.require(p.canonical(phase) == owner.phase_raw and p.sha(owner.phase_raw) == request.value["conductorRequestSha256"]
        and phase["deadlineBoottimeNs"] == owner.window["startupDeadlineBoottimeNs"]
        and request.deadline_boottime_ns == owner.deadline == p.ns(phase["deadlineBoottimeNs"]))
    p.require(p.canonical(endpoints._phase(owner.process, "endpoint-deliveries")) == owner.earlier_phase_raw
        and _approved(owner.process, "endpoint-precreation", "install-precreation") == owner.installed_raw)
    _same(owner.policy.native_delivery_policy(process=owner.process, request=request), owner.fragment)
    _same(owner.policy.measured_configuration(process=owner.process, request=request), owner.measured)
    _same(owner.policy.endpoint_recipe_originals(process=owner.process, request=request), owner.recipe_originals)
    p.require(originals._boot() == owner.boot)
    now = c9._live(owner.window, owner.last)
    epoch = time.time_ns()
    p.require(owner.last_wall <= epoch)
    owner.last, owner.last_wall = now, epoch
    return now, epoch


def _capture(owner, request):
    policy, process = owner.policy, owner.process
    selected = generations.require_generations(policy, process=process, request=request)
    p.fields(selected, generation.ROLES)
    _reserve(owner, sum(len(raw) for row in selected.values() for raw in
        p.fields(row, ("deliveryOriginal", "runtimeOriginal", "historyOriginal", "generationGrantOriginal")).values()))
    owner.generations = selected
    for role in generation.ROLES:
        raw = _approved(process, "service-originals", "ordinary-generation-" + role)
        _reserve(owner, len(raw))
        owner.generation_inputs[role] = raw
    owner.installed_raw = _approved(process, "endpoint-precreation", "install-precreation")
    installed = p.fields(p.document(owner.installed_raw, precreation.MAX_INPUT), precreation.FIELDS)
    p.require(installed["apiVersion"] == "serverware.nativePilotPrecreationBundle/v1")
    independent = policy.precreation()
    _same(installed["nativeColdOriginals"], independent["nativeColdOriginals"])
    owner.fragment = profile.validate_policy(policy.native_delivery_policy(process=process, request=request),
        native_cold_originals=independent["nativeColdOriginals"])
    owner.measured = policy.measured_configuration(process=process, request=request)
    owner.recipe_originals = policy.endpoint_recipe_originals(process=process, request=request)
    owner.configuration_raw, _ = c9._original(installed["cohortConfigurationOriginal"], cohort.MAX_BYTES)
    owner.window_raw, signed_window = c9._original(installed["cohortPrecreationOriginal"], cohort.MAX_BYTES)
    p.fields(signed_window, ("apiVersion", "payload", "signatureBase64url"))
    p.require(signed_window["apiVersion"] == "serverware.nativeShadowProofCohortPrecreation/v1")
    owner.window = p.fields(signed_window["payload"], cohort.WINDOW_FIELDS)
    owner.boot = originals._boot()
    owner.deadline = p.ns(owner.window["startupDeadlineBoottimeNs"])
    phase = endpoints._phase(process, "service-originals")
    owner.phase_raw = p.canonical(phase)
    observed = p.fields(phase["payload"], endpoints._RESOURCE_FIELDS + ("driverGenerationRecipe",
        "endpointDeliveries", "endpointDeliveryResult", "ordinaryPreparationOriginal", "ordinaryInitialResourcesOriginal"))
    earlier = endpoints._phase(process, "endpoint-deliveries")
    owner.earlier_phase_raw = p.canonical(earlier)
    p.require(earlier["deadlineBoottimeNs"] == phase["deadlineBoottimeNs"])
    for field in endpoints._RESOURCE_FIELDS + ("driverGenerationRecipe",):
        _same(observed[field], earlier["payload"][field])
    owner.observation_raw, _ = c9._original(observed["cohortObservationOriginal"], cohort.MAX_BYTES)
    activations = p.fields(observed["nativeActivations"], cohort.ENDPOINT_ROLES)
    for role in ROLES:
        raw, _ = c9._original(installed["nativeColdOriginals"][role], 65536)
        c9._activation(activations[role], c9.ENDPOINTS[role])
        _reserve(owner, len(raw) + len(p.canonical(activations[role])))
        owner.cold[role], owner.activations[role] = raw, copy.deepcopy(activations[role])
    _reserve(owner, sum(len(raw) for raw in (owner.installed_raw, owner.phase_raw, owner.earlier_phase_raw,
        owner.configuration_raw, owner.window_raw, owner.observation_raw))
        + sum(len(generation.canonical(value)) for value in (owner.fragment, owner.measured, owner.recipe_originals)))
    _current(owner, request)


def _prior(owner):
    for role in ROLES[:owner.next]:
        job = "native-delivery-" + role
        raw = _approved(owner.process, "service-originals", job)
        p.require(raw == owner.inputs[role])
        result = owner.process.prior_result("service-originals", job)
        verified = checked_result(role, raw, result)
        result_raw = p.canonical(result)
        if role not in owner.deliveries:
            _reserve(owner, len(verified) + len(result_raw))
            owner.deliveries[role], owner.results[role] = verified, result_raw
        else:
            p.require(owner.deliveries[role] == verified and owner.results[role] == result_raw)


def compose(policy, *, process, request) -> bytes:
    """One complete existing C9 input; the separate purpose authority signs it."""
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
        _prior(owner)
        now, epoch = _current(owner, request)
        role = ROLES[index]
        raw = profile.build(role, fragment=owner.fragment, configuration_raw=owner.cold[role],
            owner_configuration_raw=owner.configuration_raw, window_raw=owner.window_raw,
            observation_raw=owner.observation_raw, activation=owner.activations[role], measured=owner.measured,
            recipe_originals=owner.recipe_originals, boot=owner.boot, now_boottime_ns=now, now_unix_ns=epoch)
        p.require(type(raw) is bytes and 0 < len(raw) <= c9.MAX_INPUT)
        _current(owner, request)
        _reserve(owner, len(raw))
        owner.inputs[role] = raw
        owner.next += 1
        owner.inflight = None
        return raw
    except BaseException:
        owner.failed = True
        raise


def require_deliveries(policy, *, process, request) -> dict:
    """Seven verified originals at the first key job; no key approval implied."""
    return _verified_deliveries(policy, process=process, request=request, first=True)


def recheck_deliveries(policy, *, process, request) -> dict:
    """Recheck an opened boundary through the fixed completed-owner scope."""
    return _verified_deliveries(policy, process=process, request=request, first=False)


def _verified_deliveries(policy, *, process, request, first):
    _owners(policy, process, request)
    owner = _LIVE
    p.require(owner is not None and owner.policy is policy and owner.process is process
        and not owner.failed and not owner.closed and owner.inflight is None and owner.next == len(ROLES)
        and installation.native_completed_boundary(request)
        and request.job_index >= NEXT_INDEX
        and (request.job_index == NEXT_INDEX and request.job == NEXT_JOB
             if first else owner.key_boundary_open))
    owner.inflight = request
    try:
        _current(owner, request)
        _prior(owner)
        _current(owner, request)
        p.require(tuple(owner.deliveries) == ROLES)
        result = {role: {"deliveryOriginal": owner.deliveries[role],
            "runtimeOriginal": owner.fragment[role]["runtimeOriginal"].encode("ascii")} for role in ROLES}
        owner.key_boundary_open = True
        owner.inflight = None
        return result
    except BaseException:
        owner.failed = True
        raise


def close(process):
    """Retire public data only after known cleanup of the actual process."""
    global _LIVE
    if _LIVE is None:
        return
    from serverware.native_pilot_supervisor_process import AuthorityCoordinatorProcess
    owner = _LIVE
    p.require(type(process) is AuthorityCoordinatorProcess and owner.process is process and process._closed
        and not owner.close_attempted
        and process._result["status"] in ("not-started", "stopped-cleanup-complete", "failed-cleanup-complete"))
    owner.close_attempted = True
    owner.inputs.clear(); owner.deliveries.clear(); owner.results.clear()
    owner.generations.clear(); owner.generation_inputs.clear(); owner.cold.clear(); owner.activations.clear()
    owner.closed = True
    _LIVE = None
