"""Five generation inputs from retained deliveries and measured scope originals.

Only the real pending ordinary-generation jobs and an independently admitted generation
policy enter composition. The first job opens the completed C9 boundary; every
later access rechecks its actual owners, original startup window and previous
signed results. No private key, signing, service receipt or renewed interval is
created. The fifth result is verified only at the actual next job's handoff.
"""
from __future__ import annotations

import time

from catchplate import custody_generation_grants as generation
from catchplate import native_pilot_ordinary_generation_profile as profile
from catchplate import native_pilot_ordinary_install as installation
from catchplate import native_pilot_precreation_install as precreation
from catchplate import native_pilot_publication as publication
from catchplate import native_pilot_service_authority as authority
from catchplate import native_pilot_supervisor_ordinary_deliveries as deliveries
from catchplate import native_shadow_nitro_originals as originals
from catchplate.native_pilot_phase_execution import JOBS, MAX_RETAINED_BYTES, job_index

p = generation.p
ROLES = generation.ROLES
FIRST_INDEX = job_index("service-originals", "ordinary-generation-" + ROLES[0])
NEXT_JOB = "native-delivery-generationInstall"
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
        and FIRST_INDEX <= request.job_index < FIRST_INDEX + len(ROLES))
    index = request.job_index - FIRST_INDEX
    p.require(request.job == "ordinary-generation-" + ROLES[index]
        and tuple(job.name for job in JOBS["service-originals"][FIRST_INDEX - 1:FIRST_INDEX - 1 + len(ROLES)])
        == tuple("ordinary-generation-" + role for role in ROLES))
    return index


def checked_result(role, input_raw, result, *, root_pin) -> bytes:
    """Pure signature/input/pin verification, not approval or live admission."""
    return profile.checked_result(role, input_raw, result, root_pin=root_pin)


class _Attempt:
    def __init__(self, policy, process):
        self.policy, self.process = policy, process
        self.next, self.retained_bytes = 0, 0
        self.inflight = None
        self.failed = self.closed = self.close_attempted = False
        self.native_boundary_open = False
        self.deliveries, self.delivery_inputs = {}, {}
        self.inputs, self.grants, self.results = {}, {}, {}
        self.fragment = self.initial_policy = self.measured = self.recipe_originals = None
        self.phase_raw = self.installed_raw = self.launch_raw = None
        self.bootstrap = self.bootstrap_input = self.bootstrap_result = None
        self.bootstrap_original = self.observation_original = self.scope = None
        self.driver_recipe = self.boot = self.deadline = self.lifetime = None
        self.cold = {}
        self.last = originals._clock()


def _reserve(owner, count):
    p.integer(count, minimum=0, maximum=MAX_RETAINED_BYTES)
    p.require(owner.retained_bytes + count <= MAX_RETAINED_BYTES)
    owner.retained_bytes += count


def _approved(process, phase, job):
    raw = process.approved_input_original(phase, job)
    p.require(p.sha(raw) == process.approved_input_sha256(phase, job))
    return raw


def _bootstrap(owner):
    """Bind the genuine prior result to the exact sent policy bootstrap input."""
    process, policy = owner.process, owner.policy
    approved = policy.bootstrap_originals()
    p.require(approved == owner.bootstrap == process.bootstrap_originals())
    raw = _approved(process, "bootstrap-admission", "driver-bootstrap")
    p.require(raw == owner.bootstrap_input == policy.bootstrap_input_original())
    value = p.fields(p.document(raw, 24 * 1024 * 1024), ("apiVersion", "operation", "controlOriginal",
        "configurationOriginal", "windowOriginal", "deliveryConfigurationOriginal", "payloadOriginal", "observationOriginal"))
    p.require(value["apiVersion"] == "catchplate.nativePilotDriverAuthorityInput/v1" and value["operation"] == "bootstrap")
    for name, original in approved.items():
        p.require(value[name + "Original"] == original.decode("ascii"))
    phase = process.conductor_request("bootstrap-admission")
    p.fields(phase["payload"], ("bootstrapObservationOriginal", "admissionPayloadOriginal"))
    p.require(phase["payload"]["bootstrapObservationOriginal"] == value["observationOriginal"]
        == owner.observation_original.decode("ascii")
        and phase["payload"]["admissionPayloadOriginal"] == value["payloadOriginal"]
        and p.ns(phase["deadlineBoottimeNs"]) == owner.deadline)
    result = p.fields(process.prior_result("bootstrap-admission", "driver-bootstrap"), ("original", "sha256", "pin"))
    p.require(generation.canonical(result) == owner.bootstrap_result)
    signed_raw = authority._original(result["original"], 8192)
    signed = p.fields(generation.document(signed_raw, 8192), ("payload", "signature"))
    p.require(signed_raw == owner.bootstrap_original and p.sha(signed_raw) == p.digest(result["sha256"])
        and generation.canonical(signed["payload"]).decode("ascii") == value["payloadOriginal"])
    _same(result["pin"], {"path": publication.DESTINATIONS["driver-bootstrap-admission"], "sha256": p.sha(signed_raw)})


def _scope(owner, epoch):
    # Signature/trust validation and the real receiver's hash recipe live in
    # the pure profile. These arguments originate only in checked live owners.
    return profile.derive_scope(owner.fragment, measured=owner.measured,
        recipe_originals=owner.recipe_originals, driver_generation_recipe=owner.driver_recipe,
        bootstrap_original=owner.bootstrap_original, driver_observation_original=owner.observation_original,
        bootstrap_configuration_original=owner.bootstrap["configuration"], now_unix_ns=epoch)


def _current(owner, request):
    _owners(owner.policy, owner.process, request)
    p.require(_LIVE is owner and not owner.failed and not owner.closed)
    actual = deliveries.recheck_deliveries(owner.policy, process=owner.process, request=request)
    p.require(actual == owner.deliveries)
    phase = owner.process.conductor_request("service-originals")
    p.require(p.canonical(phase) == owner.phase_raw and p.sha(owner.phase_raw) == request.value["conductorRequestSha256"]
        and p.ns(phase["deadlineBoottimeNs"]) == request.deadline_boottime_ns == owner.deadline)
    for role in ROLES:
        p.require(_approved(owner.process, "service-originals", "ordinary-delivery-" + role) == owner.delivery_inputs[role])
    p.require(_approved(owner.process, "endpoint-precreation", "install-precreation") == owner.installed_raw)
    _same(owner.policy.ordinary_generation_policy(process=owner.process, request=request), owner.fragment)
    _same(owner.policy.ordinary_initial_policy(process=owner.process, request=request), owner.initial_policy)
    _same(owner.policy.measured_configuration(process=owner.process, request=request), owner.measured)
    _same(owner.policy.endpoint_recipe_originals(process=owner.process, request=request), owner.recipe_originals)
    _bootstrap(owner)
    _same(_scope(owner, time.time_ns()), owner.scope)
    now = originals._clock()
    p.require(originals._boot() == owner.boot and owner.last <= now < owner.deadline <= owner.lifetime)
    owner.last = now
    return now


def _capture(owner, request):
    policy, process = owner.policy, owner.process
    selected = deliveries.require_deliveries(policy, process=process, request=request)
    p.fields(selected, ROLES)
    _reserve(owner, sum(len(raw) for row in selected.values() for raw in
        p.fields(row, ("deliveryOriginal", "runtimeOriginal", "historyOriginal")).values()))
    owner.deliveries = selected
    owner.fragment = profile.validate_policy(policy.ordinary_generation_policy(process=process, request=request))
    owner.initial_policy = policy.ordinary_initial_policy(process=process, request=request)
    owner.measured = policy.measured_configuration(process=process, request=request)
    owner.recipe_originals = policy.endpoint_recipe_originals(process=process, request=request)
    phase = process.conductor_request("service-originals")
    owner.phase_raw = p.canonical(phase)
    owner.driver_recipe = phase["payload"]["driverGenerationRecipe"]
    owner.installed_raw = _approved(process, "endpoint-precreation", "install-precreation")
    installed = p.fields(p.document(owner.installed_raw, precreation.MAX_INPUT), precreation.FIELDS)
    owner.launch_raw = authority._original(installed["ordinaryLaunchOriginal"], 65536)
    owner.observation_original = authority._original(installed["driverObservationOriginal"], 65536)
    owner.bootstrap = policy.bootstrap_originals()
    owner.bootstrap_input = _approved(process, "bootstrap-admission", "driver-bootstrap")
    result = p.fields(process.prior_result("bootstrap-admission", "driver-bootstrap"), ("original", "sha256", "pin"))
    owner.bootstrap_result = generation.canonical(result)
    owner.bootstrap_original = authority._original(result["original"], 8192)
    owner.boot = originals._boot()
    _, owner.deadline, owner.lifetime = authority._launch(owner.launch_raw, owner.boot, originals._clock())
    for role in ROLES:
        raw = _approved(process, "service-originals", "ordinary-delivery-" + role)
        value, _, cold_raw, _, _, startup, lifetime = deliveries._input(role, raw)
        p.require(value["launchOriginal"] == owner.launch_raw.decode("ascii")
            and value["configurationOriginal"] == installed["ordinaryColdOriginals"][role]
            and value["runtimeOriginal"] == selected[role]["runtimeOriginal"].decode("ascii")
            and startup == owner.deadline and lifetime == owner.lifetime)
        _reserve(owner, len(raw) + len(cold_raw))
        owner.delivery_inputs[role], owner.cold[role] = raw, cold_raw
    _reserve(owner, sum(len(raw) for raw in (owner.phase_raw, owner.installed_raw, owner.launch_raw,
        owner.observation_original, owner.bootstrap_input, owner.bootstrap_result, owner.bootstrap_original,
        *owner.bootstrap.values())) + sum(len(generation.canonical(value)) for value in
        (owner.fragment, owner.initial_policy, owner.measured, owner.recipe_originals, owner.driver_recipe)))
    _bootstrap(owner)
    owner.scope = _scope(owner, time.time_ns())
    _reserve(owner, len(generation.canonical(owner.scope)))
    _current(owner, request)


def _root_pin(owner, role):
    root = owner.initial_policy["services"][role]["authorities"]["root"]
    return {name: root[name] for name in ("keyId", "keySpkiSha256")}


def _prior(owner):
    for role in ROLES[:owner.next]:
        job = "ordinary-generation-" + role
        raw = _approved(owner.process, "service-originals", job)
        p.require(raw == owner.inputs[role])
        result = owner.process.prior_result("service-originals", job)
        verified = checked_result(role, raw, result, root_pin=_root_pin(owner, role))
        result_raw = generation.canonical(result)
        if role not in owner.grants:
            _reserve(owner, len(verified) + len(result_raw))
            owner.grants[role], owner.results[role] = verified, result_raw
        else:
            p.require(owner.grants[role] == verified and owner.results[role] == result_raw)


def compose(policy, *, process, request) -> bytes:
    """Return one complete existing input; the independent authority signs it."""
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
        issued = _current(owner, request)
        role = ROLES[index]
        row = owner.deliveries[role]
        raw = profile.build(role, launch_raw=owner.launch_raw, configuration_raw=owner.cold[role],
            delivery_raw=row["deliveryOriginal"], runtime_raw=row["runtimeOriginal"], history_raw=row["historyOriginal"],
            scope=owner.scope, issued_boottime_ns=issued, expires_boottime_ns=owner.lifetime)
        p.require(type(raw) is bytes and 0 < len(raw) <= authority.MAX_INPUT_BYTES)
        _current(owner, request)
        _reserve(owner, len(raw))
        owner.inputs[role] = raw
        owner.next += 1
        owner.inflight = None
        return raw
    except BaseException:
        owner.failed = True
        raise


def require_generations(policy, *, process, request) -> dict:
    """Verify five grants at the first native delivery; no approval is implied."""
    return _verified_generations(policy, process=process, request=request, first=True)


def recheck_generations(policy, *, process, request) -> dict:
    """Recheck the opened boundary through the fixed completed-owner scope."""
    return _verified_generations(policy, process=process, request=request, first=False)


def _verified_generations(policy, *, process, request, first):
    _owners(policy, process, request)
    owner = _LIVE
    p.require(owner is not None and owner.policy is policy and owner.process is process
        and not owner.failed and not owner.closed and owner.inflight is None and owner.next == len(ROLES)
        and installation.native_completed_boundary(request)
        and (request.job_index == NEXT_INDEX and request.job == NEXT_JOB
             if first else owner.native_boundary_open))
    owner.inflight = request
    try:
        _current(owner, request)
        _prior(owner)
        _current(owner, request)
        p.require(tuple(owner.grants) == ROLES)
        result = {role: {**owner.deliveries[role], "generationGrantOriginal": owner.grants[role]} for role in ROLES}
        owner.native_boundary_open = True
        owner.inflight = None
        return result
    except BaseException:
        owner.failed = True
        raise


def close(process):
    """Discard retained public data only after genuine process cleanup."""
    global _LIVE
    if _LIVE is None:
        return
    from catchplate.native_pilot_supervisor_process import AuthorityCoordinatorProcess
    owner = _LIVE
    p.require(type(process) is AuthorityCoordinatorProcess and owner.process is process and process._closed
        and not owner.close_attempted
        and process._result["status"] in ("not-started", "stopped-cleanup-complete", "failed-cleanup-complete"))
    owner.close_attempted = True
    owner.inputs.clear(); owner.grants.clear(); owner.results.clear()
    owner.deliveries.clear(); owner.delivery_inputs.clear(); owner.cold.clear()
    owner.closed = True
    _LIVE = None
