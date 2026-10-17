"""Five C9 inputs from actual retained initial histories and public resources.

Only an admitted delivery policy and the real pending request enter composition.
The first job derives five runtimes once and retains their fixed installer;
later jobs recheck those originals and every prior approved result. No signing,
secret read, process-identity prediction, new window or live-admission claim is
made here. A failed attempt retains its owners until genuine process cleanup.
"""
from __future__ import annotations

import copy

from catchplate import custody_generation_grants as generation
from catchplate import native_pilot_ordinary_install as installation
from catchplate import native_pilot_ordinary_key_authority as history
from catchplate import native_pilot_ordinary_runtime_profile as runtime_profile
from catchplate import native_pilot_precreation_install as precreation
from catchplate import native_pilot_publication as publication
from catchplate import native_pilot_service_authority as authority
from catchplate import native_pilot_supervisor_endpoint_deliveries as endpoints
from catchplate import native_pilot_supervisor_initial_history as initial_history
from catchplate import native_pilot_supervisor_helper_initial_profile as helper
from catchplate import native_pilot_window_authority as window_authority
from catchplate import native_shadow_driver_bootstrap as driver
from catchplate import native_shadow_nitro_originals as originals
from catchplate import native_shadow_retrieval_artifacts as retrieval
from catchplate.native_pilot_phase_execution import (
    HELPER_INITIAL_JOB_INFO, INITIAL_JOB_INFO,
    JOBS, MAX_RETAINED_BYTES, job_index,
)
from catchplate.native_shadow_proof_cohort_control import _Original

p = generation.p
ROLES = generation.ROLES
FIRST_INDEX = job_index("service-originals", "ordinary-delivery-" + ROLES[0])
INPUT_API = "catchplate.nativePilotServiceAuthorityInput/v1"
INPUT_FIELDS = ("apiVersion", "operation", "serviceRole", "launchOriginal", "payloadOriginal",
    "configurationOriginal", "configurationSha256", "runtimeOriginal", "activation")
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
    p.require(request.job == "ordinary-delivery-" + ROLES[index]
        and tuple(job.name for job in JOBS["service-originals"][FIRST_INDEX - 1:FIRST_INDEX + 4])
        == tuple("ordinary-delivery-" + role for role in ROLES))
    return index


def _input(role, input_raw, *, adopted=False):
    """Pure complete-input bindings; not retained-file or currentness evidence."""
    p.require(role in ROLES)
    value = p.fields(generation.document(input_raw, generation.MAX_BYTES) if adopted
        else p.document(input_raw, authority.MAX_INPUT_BYTES), INPUT_FIELDS)
    p.require(value["apiVersion"] == (authority.ADOPTED_INPUT_API if adopted else INPUT_API)
        and value["operation"] == "delivery" and value["serviceRole"] == role)
    launch_raw = authority._original(value["launchOriginal"], 65536)
    payload_raw = authority._original(value["payloadOriginal"], 65536)
    payload = generation.document(payload_raw, 65536)
    launch = generation.document(launch_raw, 65536)
    boot = tuple(launch[name] for name in ("bootIdBase64url", "timeNamespaceDevice", "timeNamespaceInode"))
    issued = p.ns(payload["issuedAtBoottimeNs"])
    launch, startup, lifetime = authority._launch(launch_raw, boot, issued, adopted=adopted)
    cold_raw, cold_sha, _ = authority._cold(value, role, launch)
    runtime_raw = authority._original(value["runtimeOriginal"], generation.MAX_BYTES)
    runtime_profile.validate_runtime(role, runtime_raw, adopted=adopted)
    authority._runtime(runtime_raw, role, adopted=adopted)
    _same(payload["runtimeConfig"], {"path": installation.RUNTIME_PATHS[role], "sha256": p.sha(runtime_raw)})
    p.require(payload["invocationId"] == launch["invocationId"])
    generation._delivery_values(cold_raw=cold_raw, cold_sha=cold_sha, role=role, payload_raw=payload_raw,
        activation=value["activation"], boot=boot, startup=startup, lifetime=lifetime, now=issued,
        **authority._flags(role, adopted=adopted))
    return value, payload, cold_raw, cold_sha, boot, startup, lifetime


def checked_result(role, input_raw, result, *, adopted=False) -> bytes:
    """Authenticate the returned C9 bytes, not the input's approval provenance."""
    value, payload, cold_raw, cold_sha, boot, startup, lifetime = _input(role, input_raw, adopted=adopted)
    p.fields(result, ("original", "sha256", "pin"))
    raw, signed = history._original(result["original"], 65536)
    p.require(p.sha(raw) == p.digest(result["sha256"]))
    _same(result["pin"], {"path": publication.DESTINATIONS["ordinary-delivery-" + role], "sha256": p.sha(raw)})
    _same(signed["payload"], payload)
    generation._admit_delivery(signed_raw=raw, cold_raw=cold_raw, cold_sha=cold_sha, role=role,
        activation=value["activation"], boot=boot, startup=startup, lifetime=lifetime,
        now=p.ns(payload["issuedAtBoottimeNs"]), **authority._flags(role, adopted=adopted))
    return raw


class _Attempt:
    def __init__(self, policy, process):
        self.policy, self.process = policy, process
        self.next = 0
        self.inflight = self.peer = self.installer = None
        self.failed = self.closed = self.close_attempted = False
        self.generation_boundary_open = False
        self.inputs, self.initial, self.histories, self.runtimes = {}, {}, {}, {}
        self.helper_histories = self.helper_fragment = self.initial_fragment = None
        self.deliveries, self.delivery_results = {}, {}
        self.retained_bytes = 0
        self.phase_raw = self.fragment = self.installed_raw = self.endpoint_raw = None
        self.bootstrap = self.configuration = self.window = self.boot = None
        self.launch_raw = self.preparation_raw = self.resources_raw = None
        self.cold, self.activations = {}, {}
        self.last = originals._clock()


def _reserve(owner, count):
    p.integer(count, minimum=0, maximum=MAX_RETAINED_BYTES)
    p.require(owner.retained_bytes + count <= MAX_RETAINED_BYTES)
    owner.retained_bytes += count


def _current(owner, request):
    _owners(owner.policy, owner.process, request)
    p.require(_LIVE is owner and not owner.failed and not owner.closed)
    phase = endpoints._phase(owner.process, "service-originals")
    p.require(p.canonical(phase) == owner.phase_raw and p.sha(owner.phase_raw) == request.value["conductorRequestSha256"]
        and phase["deadlineBoottimeNs"] == owner.window["startupDeadlineBoottimeNs"]
        and request.deadline_boottime_ns == p.ns(owner.window["startupDeadlineBoottimeNs"]))
    _same(owner.policy.ordinary_delivery_policy(process=owner.process, request=request), owner.fragment)
    _same(owner.policy.helper_initial_policy(process=owner.process, request=request), owner.helper_fragment)
    _same(owner.policy.ordinary_initial_policy(process=owner.process, request=request), owner.initial_fragment)
    p.require(owner.policy.bootstrap_originals() == owner.bootstrap == owner.process.bootstrap_originals())
    for phase_name, job, expected in (("endpoint-precreation", "install-precreation", owner.installed_raw),
            ("endpoint-inputs", "endpoint-inputs", owner.endpoint_raw)):
        p.require(owner.process.approved_input_original(phase_name, job) == expected
            and owner.process.approved_input_sha256(phase_name, job) == p.sha(expected))
    now = originals._clock()
    p.require(originals._boot() == owner.boot and owner.last <= now < request.deadline_boottime_ns)
    window_authority.validate_window(owner.window, owner.bootstrap["configuration"], owner.configuration,
        boot=owner.boot, now=now)
    owner.last = now
    if owner.peer is not None:
        owner.peer.check()
    if owner.installer is not None:
        owner.installer.check(owner.policy, owner.process, request)
    return now


def _capture(owner, request):
    # This is the only entry into the initial owner's first-delivery boundary.
    handoff = initial_history.require_all_histories(owner.policy, process=owner.process, request=request)
    results = handoff["histories"]
    p.fields(results, ROLES)
    histories = {role: history._original(results[role]["original"], generation.MAX_BYTES)[0] for role in ROLES}
    _reserve(owner, sum(len(raw) for raw in histories.values()))
    owner.histories = histories
    owner.helper_histories = handoff["helperHistories"]
    if owner.helper_histories is not None:
        _reserve(owner, sum(len(raw) for raw in owner.helper_histories.values()))
    owner.helper_fragment = owner.policy.helper_initial_policy(process=owner.process, request=request)
    owner.initial_fragment = owner.policy.ordinary_initial_policy(process=owner.process, request=request)
    for job in initial_history.CEREMONY_JOBS:
        raw = owner.process.approved_input_original("service-originals", job.name)
        result_raw = generation.canonical(owner.process.prior_result("service-originals", job.name))
        p.require(p.sha(raw) == owner.process.approved_input_sha256("service-originals", job.name))
        _reserve(owner, len(raw) + len(result_raw))
        owner.initial[job.name] = (raw, result_raw)
    owner.fragment = owner.policy.ordinary_delivery_policy(process=owner.process, request=request)
    owner.phase_raw = p.canonical(endpoints._phase(owner.process, "service-originals"))
    observed = p.document(owner.phase_raw, 32 * 1024 * 1024)["payload"]
    owner.preparation_raw = authority._original(observed["ordinaryPreparationOriginal"], 65536)
    owner.resources_raw = authority._original(observed["ordinaryInitialResourcesOriginal"], 65536)
    owner.activations = copy.deepcopy(p.fields(observed["ordinaryActivations"], ROLES))
    owner.installed_raw = owner.process.approved_input_original("endpoint-precreation", "install-precreation")
    installed = p.fields(p.document(owner.installed_raw, precreation.MAX_INPUT), precreation.FIELDS)
    owner.launch_raw = authority._original(installed["ordinaryLaunchOriginal"], 65536)
    owner.cold = {role: authority._original(installed["ordinaryColdOriginals"][role], 65536) for role in ROLES}
    _same(installed["ordinaryColdOriginals"], owner.policy.precreation()["ordinaryColdOriginals"])
    owner.bootstrap = owner.policy.bootstrap_originals()
    owner.configuration = window_authority.validate_configuration(owner.bootstrap["configuration"])
    signed = p.fields(p.document(owner.bootstrap["window"], 32768), ("apiVersion", "payload", "signatureBase64url"))
    p.require(signed["apiVersion"] == "catchplate.nativeShadowDriverBootstrapWindow/v1")
    owner.window, owner.boot = signed["payload"], originals._boot()
    driver._key(owner.configuration["bootstrapAuthority"]).verify(p.decoded(signed["signatureBase64url"], size=64),
        driver.WINDOW_DOMAIN + p.canonical(owner.window))
    for name in ("configuration", "window"):
        p.require(installed["driver" + name.title() + "Original"] == owner.bootstrap[name].decode("ascii"))
    owner.endpoint_raw = owner.process.approved_input_original("endpoint-inputs", "endpoint-inputs")
    endpoint = p.fields(p.document(owner.endpoint_raw, 65536),
        ("coldOriginals", "peer", "proofScope", "retrievalManifest", "objectDirectory", "assignment", "production"))
    pin = p.fields(endpoint["peer"], ("path", "sha256"))
    p.require(pin["path"] == publication.DESTINATIONS["endpoint-peer"])
    # Count retained copies conservatively even where immutable bytes share a
    # backing object with the genuine process. No aggregate limit is enlarged.
    _reserve(owner, sum(len(raw) for raw in (owner.phase_raw, owner.installed_raw, owner.endpoint_raw,
        owner.launch_raw, owner.preparation_raw, owner.resources_raw, *owner.bootstrap.values(), *owner.cold.values()))
        + len(generation.canonical(owner.fragment)) + len(generation.canonical(owner.activations))
        + len(generation.canonical(owner.helper_fragment)) + len(generation.canonical(owner.initial_fragment)))
    _current(owner, request)
    owner.peer = _Original(pin["path"], 4096, p.digest(pin["sha256"]), mode=0o400)
    _reserve(owner, len(owner.peer.raw))
    peer = retrieval._peer(owner.peer.raw)
    runtime_profile.validate_policy(owner.fragment, ordinary_cold_originals=installed["ordinaryColdOriginals"],
        initial_policy=owner.initial_fragment)
    for role in ROLES:
        _current(owner, request)
        raw = runtime_profile.build(role, fragment=owner.fragment, history_originals=owner.histories,
            preparation_raw=owner.preparation_raw, resources_raw=owner.resources_raw, launch_raw=owner.launch_raw,
            configuration_raw=owner.cold[role], peer=peer, helper_history_originals=owner.helper_histories)
        p.require(type(raw) is bytes and 0 < len(raw) <= generation.MAX_BYTES)
        _reserve(owner, len(raw))
        owner.runtimes[role] = raw
    _current(owner, request)


def prepared_runtime_originals(policy, *, process, request) -> dict:
    """Installer-only data seam bound to this actual in-flight first request."""
    _owners(policy, process, request)
    owner = _LIVE
    p.require(owner is not None and owner.policy is policy and owner.process is process
        and owner.inflight is request and owner.next == 0 and _slot(request) == 0
        and tuple(owner.runtimes) == ROLES)
    _current(owner, request)
    return dict(owner.runtimes)


def _prior(owner):
    supplementary = {}
    for job in initial_history.CEREMONY_JOBS:
        expected, result_raw = owner.initial[job.name]
        raw = owner.process.approved_input_original("service-originals", job.name)
        result = owner.process.prior_result("service-originals", job.name)
        p.require(raw == expected and p.sha(raw) == owner.process.approved_input_sha256("service-originals", job.name)
            and generation.canonical(result) == result_raw)
        if job.name in INITIAL_JOB_INFO:
            role, operation = INITIAL_JOB_INFO[job.name]
            verified = initial_history.checked_result(role, operation, raw, result)
            if operation == "assemble":
                p.require(verified == owner.histories[role])
        else:
            slot, operation = HELPER_INITIAL_JOB_INFO[job.name]
            verified = helper.checked_result(slot, operation, raw, result,
                fragment=owner.helper_fragment, initial_policy=owner.initial_fragment)
            if operation == "assemble":
                supplementary[slot] = verified
    if owner.helper_fragment is not None:
        members = helper.authenticate_histories(owner.histories[helper.HELPER], supplementary,
            fragment=owner.helper_fragment, initial_policy=owner.initial_fragment)
        p.require(members == owner.helper_histories)
    for role in ROLES[:owner.next]:
        job = "ordinary-delivery-" + role
        raw = owner.process.approved_input_original("service-originals", job)
        p.require(raw == owner.inputs[role] and owner.process.approved_input_sha256("service-originals", job) == p.sha(raw))
        result = owner.process.prior_result("service-originals", job)
        verified = checked_result(role, raw, result)
        result_raw = generation.canonical(result)
        if role not in owner.deliveries:
            _reserve(owner, len(verified) + len(result_raw))
            owner.deliveries[role], owner.delivery_results[role] = verified, result_raw
        else:
            p.require(owner.deliveries[role] == verified and owner.delivery_results[role] == result_raw)


def compose(policy, *, process, request) -> bytes:
    """Return one complete existing input; no approval or signature is emitted."""
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
    owner.inflight = request  # Claim before the first read or possible publication.
    try:
        if index == 0:
            _capture(owner, request)
            # The installer separately caps all retained public bytes at 32 MiB;
            # reserve that whole bound before it acquires any destination.
            _reserve(owner, installation.MAX_TOTAL_BYTES)
            owner.installer = installation.prepare(policy, process=process, request=request)
        _current(owner, request)
        _prior(owner)
        issued = _current(owner, request)
        role = ROLES[index]
        selected = p.fields(owner.installer.inputs(role), ("runtimeConfig", "historyCredential", "inspectionCredential"))
        credentials = copy.deepcopy(owner.fragment["services"][role]["credentials"])
        credentials.extend((selected["historyCredential"], selected["inspectionCredential"]))
        cold_sha = p.sha(owner.cold[role])
        cold = generation.configuration(owner.cold[role], cold_sha, role)
        launch = generation.document(owner.launch_raw, 65536)
        payload = {"configurationSha256": cold_sha, "authorityKeyId": cold["authority"]["keyId"],
            **{name: cold[name] for name in ("serviceRole", "uid", "gid")},
            **{name: launch[name] for name in ("bootIdBase64url", "timeNamespaceDevice", "timeNamespaceInode",
                "startupDeadlineBoottimeNs", "lifetimeDeadlineBoottimeNs", "invocationId")},
            "issuedAtBoottimeNs": str(issued), "runtimeConfig": selected["runtimeConfig"],
            "credentials": credentials, "activation": owner.activations[role]}
        value = {"apiVersion": INPUT_API, "operation": "delivery", "serviceRole": role,
            "launchOriginal": owner.launch_raw.decode("ascii"), "payloadOriginal": generation.canonical(payload).decode("ascii"),
            "configurationOriginal": owner.cold[role].decode("ascii"), "configurationSha256": cold_sha,
            "runtimeOriginal": owner.runtimes[role].decode("ascii"), "activation": owner.activations[role]}
        raw = p.canonical(value)
        p.require(len(raw) <= authority.MAX_INPUT_BYTES)
        _input(role, raw)
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
    """Five verified originals at the first generation, not a future grant."""
    return _verified_deliveries(policy, process=process, request=request, first=True)


def recheck_deliveries(policy, *, process, request) -> dict:
    """Recheck the opened boundary during fixed generations and their handoff."""
    return _verified_deliveries(policy, process=process, request=request, first=False)


def _verified_deliveries(policy, *, process, request, first):
    _owners(policy, process, request)
    owner = _LIVE
    p.require(owner is not None and owner.policy is policy and owner.process is process
        and owner.next == len(ROLES) and owner.inflight is None and not owner.failed and not owner.closed
        and request.phase == "service-originals" and type(request.job_index) is int)
    offset = request.job_index - FIRST_INDEX - len(ROLES)
    generation_job = (0 <= offset < len(ROLES)
        and request.job == "ordinary-generation-" + ROLES[offset])
    p.require((offset == 0 and generation_job if first else
        owner.generation_boundary_open and (generation_job or installation.native_completed_boundary(request)))
        and JOBS["service-originals"][request.job_index - 1].name == request.job)
    owner.inflight = request
    try:
        _current(owner, request)
        _prior(owner)  # The fifth signature first exists in this real request.
        _current(owner, request)
        p.require(tuple(owner.deliveries) == ROLES)
        result = {role: {"deliveryOriginal": owner.deliveries[role], "runtimeOriginal": owner.runtimes[role],
            "historyOriginal": owner.histories[role]} for role in ROLES}
        owner.generation_boundary_open = True
        owner.inflight = None
        return result
    except BaseException:
        owner.failed = True
        raise


def close(process):
    """Release retained originals only after real process cleanup is known."""
    global _LIVE
    if _LIVE is None:
        return
    from catchplate.native_pilot_supervisor_process import AuthorityCoordinatorProcess
    owner = _LIVE
    p.require(type(process) is AuthorityCoordinatorProcess and owner.process is process and process._closed
        and not owner.close_attempted
        and process._result["status"] in ("not-started", "stopped-cleanup-complete", "failed-cleanup-complete"))
    owner.close_attempted = True
    installation.close(process)
    if owner.peer is not None:
        owner.peer.close(); owner.peer = None
    owner.closed = True
    owner.initial.clear(); owner.inputs.clear(); owner.histories.clear(); owner.runtimes.clear()
    if owner.helper_histories is not None:
        owner.helper_histories.clear()
    owner.deliveries.clear(); owner.delivery_results.clear()
    _LIVE = None
