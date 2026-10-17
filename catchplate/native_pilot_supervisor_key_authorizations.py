"""Twenty fixed public key authorizations after the ten actual C9 results.

Every complete input derives from independently admitted policy and retained
process originals. Existing authorities sign outside this composer. No key,
credential, verifier configuration, file, resource or renewed window is made
here. Prior signatures are checked only after their genuine result arrives;
failure consumes the attempt and public data survives until known cleanup.
"""
from __future__ import annotations

import time

from catchplate import custody_generation_grants as generation
from catchplate import native_pilot_delivery_authority as c9
from catchplate import native_pilot_key_profile as profile
from catchplate import native_pilot_ordinary_install as installation
from catchplate import native_pilot_precreation_install as precreation
from catchplate import native_pilot_supervisor_endpoint_deliveries as endpoints
from catchplate import native_pilot_supervisor_native_deliveries as native
from catchplate import native_shadow_guest_delivery as delivery
from catchplate import native_shadow_nitro_originals as originals
from catchplate import native_shadow_proof_cohort_assignment as cohort
from catchplate.native_pilot_phase_execution import (
    JOBS, KEY_AUTHORIZATION_JOBS, KEY_AUTHORIZATION_JOB_INFO, MAX_RETAINED_BYTES, job_index,
)

p = c9.p
ROLES = profile.ROLES
FIRST_INDEX = job_index("service-originals", KEY_AUTHORIZATION_JOBS[0].name)
NEXT_JOB = "native-service-commitRequest"
NEXT_INDEX = job_index("service-originals", NEXT_JOB)
_LIVE = None
_USED = False


def _same(first, second):
    p.require(generation.canonical(first) == generation.canonical(second))


def _owners(policy, process, request):
    from catchplate.native_pilot_supervisor_policy import SupervisorPolicy
    from catchplate.native_pilot_supervisor_process import AuthorityCoordinatorProcess, JobRequest
    p.require(type(policy) is SupervisorPolicy and type(process) is AuthorityCoordinatorProcess
        and type(request) is JobRequest)
    policy.check(process); process.check_request(request)


def _slot(request):
    p.require(request.phase == "service-originals" and type(request.job_index) is int
        and FIRST_INDEX <= request.job_index < FIRST_INDEX + len(KEY_AUTHORIZATION_JOBS))
    index = request.job_index - FIRST_INDEX
    p.require(request.job == KEY_AUTHORIZATION_JOBS[index].name
        and tuple(JOBS["service-originals"][FIRST_INDEX - 1:FIRST_INDEX - 1 + len(KEY_AUTHORIZATION_JOBS)])
        == KEY_AUTHORIZATION_JOBS
        and tuple(KEY_AUTHORIZATION_JOB_INFO[job.name] for job in KEY_AUTHORIZATION_JOBS)
        == tuple((role, operation) for role in ROLES for operation in profile.OPERATIONS))
    return index


def checked_result(operation, role, input_raw, result, *, boot, now_boottime_ns, now_unix_ns):
    """Pure signature/input check; the caller supplies actual owner provenance."""
    return profile.checked_result(operation, role, input_raw, result, boot=boot,
        now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)


class _Attempt:
    def __init__(self, policy, process):
        self.policy, self.process = policy, process
        self.next = self.retained_bytes = 0
        self.inflight = None
        self.failed = self.closed = self.close_attempted = False
        self.service_boundary_open = False
        self.inputs, self.outputs, self.results = {}, {}, {}
        self.delivery_inputs, self.deliveries, self.delivery_results = {}, {}, {}
        self.cold, self.delivery_policy = {}, {}
        self.native_deliveries = self.fragment = self.measured = self.recipe_originals = None
        self.phase_raw = self.earlier_phase_raw = self.installed_raw = None
        self.configuration_raw = self.window_raw = self.observation_raw = None
        self.window = self.boot = self.deadline = self.activations = None
        self.last, self.last_wall = originals._clock(), time.time_ns()


def _reserve(owner, count):
    p.integer(count, minimum=0, maximum=MAX_RETAINED_BYTES)
    p.require(owner.retained_bytes + count <= MAX_RETAINED_BYTES)
    owner.retained_bytes += count


def _approved(process, phase, job):
    raw = process.approved_input_original(phase, job)
    p.require(p.sha(raw) == process.approved_input_sha256(phase, job))
    return raw


def _delivery_phase(role):
    return "endpoint-deliveries" if role in endpoints.ROLES else "service-originals"


def _verify_delivery(owner, role, *, now):
    """Check complete actual C9 input, policy/resources and returned signature."""
    phase, job = _delivery_phase(role), "native-delivery-" + role
    raw = _approved(owner.process, phase, job)
    p.require(raw == owner.delivery_inputs[role])
    value = p.fields(p.document(raw, c9.MAX_INPUT), c9.INPUT_FIELDS)
    selected = owner.delivery_policy[role]
    cold_raw = owner.cold[role]
    cold = delivery.configuration(cold_raw, p.sha(cold_raw))
    p.require(value["apiVersion"] == "catchplate.nativePilotDeliverySigningInput/v1" and value["role"] == role
        and value["configurationOriginal"] == cold_raw.decode("ascii")
        and value["ownerConfigurationOriginal"] == owner.configuration_raw.decode("ascii")
        and value["windowOriginal"] == owner.window_raw.decode("ascii")
        and value["observationOriginal"] == owner.observation_raw.decode("ascii")
        and value["runtimeOriginal"] == selected["runtimeOriginal"]
        and value["activationOriginal"] == p.canonical(owner.activations[role]).decode("ascii"))
    window = c9.endpoint_owner(role, cold, cold_raw, owner.configuration_raw, owner.window_raw,
        p.document(owner.window_raw, cohort.MAX_BYTES), p.document(owner.observation_raw, cohort.MAX_BYTES),
        boot=owner.boot, now=now)
    payload = {"configurationSha256": p.sha(cold_raw), "authorityKeyId": cold["authority"]["keyId"],
        **{name: cold[name] for name in ("serviceRole", "uid", "gid")},
        **{name: window[name] for name in c9.WINDOW_FIELDS}, "runtimeConfig": selected["runtimeConfig"],
        "credentials": selected["credentials"], "activation": owner.activations[role]}
    p.require(value["payloadOriginal"] == p.canonical(payload).decode("ascii"))
    c9._activation(owner.activations[role], c9.ENDPOINTS[role])
    c9._credentials(selected["credentials"], cold["authority"])
    result = owner.process.prior_result(phase, job)
    p.require(p.canonical(result) == owner.delivery_results[role])
    if role in endpoints.ROLES:
        signed_raw, guest = endpoints._result(owner.process, role, raw, cold)
        observed = p.document(owner.phase_raw, 32 * 1024 * 1024)["payload"]
        _same(observed["endpointDeliveryResult"]["guests"][role], guest)
        _same(observed["endpointDeliveries"][role], result["pin"])
    else:
        signed_raw = native.checked_result(role, raw, result)
    p.require(signed_raw == owner.deliveries[role])


def _current(owner, request):
    _owners(owner.policy, owner.process, request)
    p.require(_LIVE is owner and not owner.failed and not owner.closed)
    p.require(native.recheck_deliveries(owner.policy, process=owner.process, request=request)
        == owner.native_deliveries)
    phase = endpoints._phase(owner.process, "service-originals")
    p.require(p.canonical(phase) == owner.phase_raw and p.sha(owner.phase_raw) == request.value["conductorRequestSha256"]
        and phase["deadlineBoottimeNs"] == owner.window["startupDeadlineBoottimeNs"]
        and request.deadline_boottime_ns == owner.deadline == p.ns(phase["deadlineBoottimeNs"]))
    p.require(p.canonical(endpoints._phase(owner.process, "endpoint-deliveries")) == owner.earlier_phase_raw
        and _approved(owner.process, "endpoint-precreation", "install-precreation") == owner.installed_raw)
    _same(owner.policy.native_key_authorization_policy(process=owner.process, request=request), owner.fragment)
    _same(owner.policy.measured_configuration(process=owner.process, request=request), owner.measured)
    _same(owner.policy.endpoint_recipe_originals(process=owner.process, request=request), owner.recipe_originals)
    _same({**owner.policy.endpoint_deliveries(),
        **owner.policy.native_delivery_policy(process=owner.process, request=request)}, owner.delivery_policy)
    p.require(originals._boot() == owner.boot)
    now, epoch = c9._live(owner.window, owner.last), time.time_ns()
    p.require(owner.last_wall <= epoch)
    owner.last, owner.last_wall = now, epoch
    for role in ROLES:
        _verify_delivery(owner, role, now=now)
    # Public signature work must not carry a decision past either original
    # clock interval. Future roles need not be current before their own job.
    now, wall = c9._live(owner.window, now), time.time_ns()
    p.require(epoch <= wall)
    selected = {KEY_AUTHORIZATION_JOB_INFO[job.name][0]
        for job in KEY_AUTHORIZATION_JOBS[:owner.next]}
    if request.job in KEY_AUTHORIZATION_JOB_INFO:
        selected.add(KEY_AUTHORIZATION_JOB_INFO[request.job][0])
    for role in selected:
        row = owner.fragment[role]
        p.freshness(row["issuedAtUnixNanos"], row["expiresAtUnixNanos"], wall)
    owner.last, owner.last_wall = now, wall
    return now, wall


def _capture(owner, request):
    policy, process = owner.policy, owner.process
    owner.native_deliveries = native.require_deliveries(policy, process=process, request=request)
    p.fields(owner.native_deliveries, native.ROLES)
    _reserve(owner, sum(len(raw) for row in owner.native_deliveries.values() for raw in
        p.fields(row, ("deliveryOriginal", "runtimeOriginal")).values()))
    owner.fragment = profile.validate_policy(policy.native_key_authorization_policy(process=process, request=request))
    owner.measured = policy.measured_configuration(process=process, request=request)
    owner.recipe_originals = policy.endpoint_recipe_originals(process=process, request=request)
    owner.delivery_policy = {**policy.endpoint_deliveries(), **policy.native_delivery_policy(process=process, request=request)}
    p.fields(owner.delivery_policy, ROLES)
    owner.installed_raw = _approved(process, "endpoint-precreation", "install-precreation")
    installed = p.fields(p.document(owner.installed_raw, precreation.MAX_INPUT), precreation.FIELDS)
    p.require(installed["apiVersion"] == "catchplate.nativePilotPrecreationBundle/v1")
    _same(installed["nativeColdOriginals"], policy.precreation()["nativeColdOriginals"])
    owner.configuration_raw, _ = c9._original(installed["cohortConfigurationOriginal"], cohort.MAX_BYTES)
    owner.window_raw, signed = c9._original(installed["cohortPrecreationOriginal"], cohort.MAX_BYTES)
    p.fields(signed, ("apiVersion", "payload", "signatureBase64url"))
    p.require(signed["apiVersion"] == "catchplate.nativeShadowProofCohortPrecreation/v1")
    owner.window = p.fields(signed["payload"], cohort.WINDOW_FIELDS)
    owner.boot, owner.deadline = originals._boot(), p.ns(owner.window["startupDeadlineBoottimeNs"])
    phase = endpoints._phase(process, "service-originals")
    owner.phase_raw = p.canonical(phase)
    observed = p.fields(phase["payload"], endpoints._RESOURCE_FIELDS + ("driverGenerationRecipe",
        "endpointDeliveries", "endpointDeliveryResult", "ordinaryPreparationOriginal", "ordinaryInitialResourcesOriginal"))
    earlier = endpoints._phase(process, "endpoint-deliveries")
    owner.earlier_phase_raw = p.canonical(earlier)
    p.require(earlier["deadlineBoottimeNs"] == phase["deadlineBoottimeNs"])
    for name in endpoints._RESOURCE_FIELDS + ("driverGenerationRecipe",):
        _same(observed[name], earlier["payload"][name])
    owner.observation_raw, _ = c9._original(observed["cohortObservationOriginal"], cohort.MAX_BYTES)
    owner.activations = p.fields(observed["nativeActivations"], ROLES)
    for role in ROLES:
        owner.cold[role], _ = c9._original(installed["nativeColdOriginals"][role], 65536)
        phase_name, job = _delivery_phase(role), "native-delivery-" + role
        raw = _approved(process, phase_name, job)
        result = p.fields(process.prior_result(phase_name, job), ("original", "sha256", "pin"))
        signed_raw, _ = c9._original(result["original"], delivery.MAX_DELIVERY)
        result_raw = p.canonical(result)
        _reserve(owner, len(raw) + len(signed_raw) + len(result_raw) + len(owner.cold[role]))
        owner.delivery_inputs[role], owner.deliveries[role], owner.delivery_results[role] = raw, signed_raw, result_raw
        if role in native.ROLES:
            p.require(signed_raw == owner.native_deliveries[role]["deliveryOriginal"]
                and owner.delivery_policy[role]["runtimeOriginal"].encode("ascii")
                    == owner.native_deliveries[role]["runtimeOriginal"])
    _reserve(owner, sum(len(raw) for raw in (owner.installed_raw, owner.phase_raw, owner.earlier_phase_raw,
        owner.configuration_raw, owner.window_raw, owner.observation_raw))
        + sum(len(generation.canonical(value)) for value in
            (owner.fragment, owner.measured, owner.recipe_originals, owner.delivery_policy, owner.activations)))
    _current(owner, request)


def _prior(owner, *, now, epoch):
    for job in KEY_AUTHORIZATION_JOBS[:owner.next]:
        role, operation = KEY_AUTHORIZATION_JOB_INFO[job.name]
        raw = _approved(owner.process, "service-originals", job.name)
        p.require(raw == owner.inputs[job.name])
        result = owner.process.prior_result("service-originals", job.name)
        verified = checked_result(operation, role, raw, result, boot=owner.boot,
            now_boottime_ns=now, now_unix_ns=epoch)
        result_raw = p.canonical(result)
        if job.name not in owner.outputs:
            _reserve(owner, len(verified) + len(result_raw))
            owner.outputs[job.name], owner.results[job.name] = verified, result_raw
        else:
            p.require(owner.outputs[job.name] == verified and owner.results[job.name] == result_raw)
        if operation == "admission":
            first = "native-role-keys-" + role
            pair = profile.admitted_pair(role, owner.inputs[first], owner.outputs[first], raw, verified,
                boot=owner.boot, now_boottime_ns=now, now_unix_ns=epoch)
            p.fields(pair, ("authorization", "admissionAuthorization", "expectedScope", "authorityKeys", "trustCheckpoint"))


def compose(policy, *, process, request) -> bytes:
    """One complete approved signing input, never a signature or live verdict."""
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
        now, epoch = _current(owner, request)
        _prior(owner, now=now, epoch=epoch)
        now, epoch = _current(owner, request)
        role, operation = KEY_AUTHORIZATION_JOB_INFO[request.job]
        raw = profile.build(operation, role, fragment=owner.fragment, delivery_input_raw=owner.delivery_inputs[role],
            delivery_raw=owner.deliveries[role], measured=owner.measured, recipe_originals=owner.recipe_originals,
            boot=owner.boot, now_boottime_ns=now, now_unix_ns=epoch,
            role_key_raw=owner.outputs["native-role-keys-" + role] if operation == "admission" else None)
        p.require(type(raw) is bytes and 0 < len(raw) <= profile.MAX_INPUT)
        _current(owner, request)
        _reserve(owner, len(raw))
        owner.inputs[request.job] = raw
        owner.next += 1
        owner.inflight = None
        return raw
    except BaseException:
        owner.failed = True
        raise


def require_authorizations(policy, *, process, request) -> dict:
    """Verify ten literal pairs at the first native-service job, not configurations."""
    return _verified_authorizations(policy, process=process, request=request, first=True)


def recheck_authorizations(policy, *, process, request) -> dict:
    """Recheck the opened boundary through the fixed completed-owner scope."""
    return _verified_authorizations(policy, process=process, request=request, first=False)


def _verified_authorizations(policy, *, process, request, first):
    _owners(policy, process, request)
    owner = _LIVE
    p.require(owner is not None and owner.policy is policy and owner.process is process
        and not owner.failed and not owner.closed and owner.inflight is None
        and owner.next == len(KEY_AUTHORIZATION_JOBS) and installation.native_completed_boundary(request)
        and request.job_index >= NEXT_INDEX
        and (request.job_index == NEXT_INDEX and request.job == NEXT_JOB
             if first else owner.service_boundary_open))
    owner.inflight = request
    try:
        now, epoch = _current(owner, request)
        _prior(owner, now=now, epoch=epoch)
        _current(owner, request)
        p.require(tuple(owner.outputs) == tuple(job.name for job in KEY_AUTHORIZATION_JOBS))
        result = {role: {"roleKeyOriginal": owner.outputs["native-role-keys-" + role],
            "admissionOriginal": owner.outputs["native-key-admission-" + role]} for role in ROLES}
        owner.service_boundary_open = True
        owner.inflight = None
        return result
    except BaseException:
        owner.failed = True
        raise


def close(process):
    """Retire retained public data only after genuine terminal cleanup."""
    global _LIVE
    if _LIVE is None:
        return
    from catchplate.native_pilot_supervisor_process import AuthorityCoordinatorProcess
    owner = _LIVE
    p.require(type(process) is AuthorityCoordinatorProcess and owner.process is process and process._closed
        and not owner.close_attempted
        and process._result["status"] in ("not-started", "stopped-cleanup-complete", "failed-cleanup-complete"))
    owner.close_attempted = True
    owner.inputs.clear(); owner.outputs.clear(); owner.results.clear()
    owner.delivery_inputs.clear(); owner.deliveries.clear(); owner.delivery_results.clear(); owner.cold.clear()
    owner.closed = True
    _LIVE = None
