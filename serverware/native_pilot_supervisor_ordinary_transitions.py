"""Five ordinary transition inputs after the actual eleven native grants.

The originating process owns every prerequisite and pending request. Complete
inputs and genuine signed results are retained without recomposition; failures
consume the attempt. No key, file, activation resource, service receipt, clock
window or running service is created by this composer. The next authorization
job can only read the completed handoff; this module never performs a launch.
"""
from __future__ import annotations

import time

from serverware import custody_generation_grants as generation
from serverware import native_pilot_native_service_authority as native_authority
from serverware import native_pilot_ordinary_generation_profile as generation_profile
from serverware import native_pilot_ordinary_install as installation
from serverware import native_pilot_ordinary_transition_profile as profile
from serverware import native_pilot_precreation_install as precreation
from serverware import native_pilot_publication as publication
from serverware import native_pilot_service_authority as authority
from serverware import native_pilot_supervisor_endpoint_deliveries as endpoints
from serverware import native_pilot_supervisor_native_services as native
from serverware import native_shadow_nitro_originals as originals
from serverware.native_pilot_phase_execution import JOBS, MAX_RETAINED_BYTES, job_index

p = generation.p
TRANSITIONS = profile.JOBS
NEXT_JOB = "native-closure-retrieval"
JOB_NAMES = tuple("ordinary-" + operation + ("-" + role if operation == "dispatch" else "")
    for operation, role in TRANSITIONS)
FIRST_INDEX = job_index("service-originals", JOB_NAMES[0])
NEXT_INDEX = job_index("service-originals", NEXT_JOB)
_AUTHORIZATION_LAST_INDEX = job_index("service-originals", "service-material")
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
        and FIRST_INDEX <= request.job_index < FIRST_INDEX + len(TRANSITIONS))
    index = request.job_index - FIRST_INDEX
    p.require(request.job == JOB_NAMES[index]
        and tuple(job.name for job in JOBS["service-originals"][FIRST_INDEX - 1:
            FIRST_INDEX - 1 + len(TRANSITIONS)]) == JOB_NAMES)
    return index


def checked_result(operation, role, input_raw, result, *, boot, now_boottime_ns, now_unix_ns):
    """Pure result signature plus its exact fixed publication pin, not an owner."""
    p.require((operation, role) in TRANSITIONS)
    p.fields(result, ("original", "sha256", "pin"))
    raw = profile.checked_result(operation, role, input_raw,
        {name: result[name] for name in ("original", "sha256")}, boot=boot,
        now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    purpose = JOB_NAMES[TRANSITIONS.index((operation, role))]
    _same(result["pin"], {"path": publication.DESTINATIONS[purpose], "sha256": p.sha(raw)})
    return raw


class _Attempt:
    def __init__(self, policy, process):
        self.policy, self.process = policy, process
        self.next = self.retained_bytes = 0
        self.inflight = None
        self.failed = self.closed = self.close_attempted = False
        self.authorization_boundary_open = False
        self.inputs, self.outputs, self.results = {}, {}, {}
        self.generation_inputs, self.generation_results = {}, {}
        self.native_context = self.ordinary_context = self.ordinary_context_sha = self.fragment = None
        self.phase_raw = self.installed_raw = self.launch_raw = None
        self.boot = self.deadline = self.startup = self.lifetime = None
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
    # This real completed owner recursively authenticates all earlier literal
    # grants, histories, C9s, key pairs and the once-derived measured recipe.
    p.require(native.recheck_services(owner.policy, process=owner.process, request=request) == owner.native_context)
    phase = endpoints._phase(owner.process, "service-originals")
    p.require(p.canonical(phase) == owner.phase_raw
        and p.sha(owner.phase_raw) == request.value["conductorRequestSha256"]
        and request.deadline_boottime_ns == owner.deadline == p.ns(phase["deadlineBoottimeNs"]))
    p.require(_approved(owner.process, "endpoint-precreation", "install-precreation") == owner.installed_raw)
    p.require(p.sha(generation.canonical(owner.ordinary_context)) == owner.ordinary_context_sha)
    for role, raw in owner.generation_inputs.items():
        job = "ordinary-generation-" + role
        p.require(_approved(owner.process, "service-originals", job) == raw
            and generation.canonical(owner.process.prior_result("service-originals", job)) == owner.generation_results[role])
    _same(owner.policy.ordinary_transition_policy(process=owner.process, request=request), owner.fragment)
    now, epoch = originals._clock(), time.time_ns()
    p.require(originals._boot() == owner.boot and owner.last <= now < owner.deadline
        and owner.last_wall <= epoch)
    _, startup, lifetime = authority._launch(owner.launch_raw, owner.boot, now)
    p.require(startup == owner.startup and lifetime == owner.lifetime)
    # Ordinary and native launches retain their own original invocations and
    # windows. Their actual owners enforce each; none are forced equal here.
    owner.last, owner.last_wall = now, epoch
    return now, epoch


def _capture(owner, request):
    owner.native_context = native.require_services(owner.policy, process=owner.process, request=request)
    p.fields(owner.native_context, native.OPERATIONS)
    for value in owner.native_context.values():
        p.fields(value, ("inputOriginal", "grantOriginal"))
        p.require(all(type(raw) is bytes and raw for raw in value.values()))
        _reserve(owner, sum(len(raw) for raw in value.values()))
    owner.fragment = profile.validate_policy(owner.policy.ordinary_transition_policy(process=owner.process, request=request))
    phase = endpoints._phase(owner.process, "service-originals")
    owner.phase_raw, owner.deadline = p.canonical(phase), p.ns(phase["deadlineBoottimeNs"])
    owner.installed_raw = _approved(owner.process, "endpoint-precreation", "install-precreation")
    installed = p.fields(p.document(owner.installed_raw, precreation.MAX_INPUT), precreation.FIELDS)
    owner.launch_raw = authority._original(installed["ordinaryLaunchOriginal"], 65536)
    owner.boot, now = originals._boot(), originals._clock()
    _, owner.startup, owner.lifetime = authority._launch(owner.launch_raw, owner.boot, now)
    source = p.document(owner.native_context["commitRequest"]["inputOriginal"], native_authority.MAX_INPUT)
    p.require(source["apiVersion"] == native_authority.HISTORY_INPUT_API and source["operation"] == "commitRequest"
        and source["ordinaryLaunchOriginal"] == owner.launch_raw.decode("ascii"))
    services = p.fields(source["services"], generation.ROLES)
    for role in generation.ROLES:
        job = "ordinary-generation-" + role
        raw = _approved(owner.process, "service-originals", job)
        value = p.fields(p.document(raw, authority.MAX_INPUT_BYTES), generation_profile.INPUT_FIELDS)
        p.require(value["operation"] == "generation" and value["serviceRole"] == role
            and value["launchOriginal"] == owner.launch_raw.decode("ascii"))
        row = p.fields(p.fields(value["services"], (role,))[role], generation_profile.SERVICE_FIELDS)
        p.require(row["configurationOriginal"] == installed["ordinaryColdOriginals"][role])
        result = p.fields(owner.process.prior_result("service-originals", job), ("original", "sha256", "pin"))
        grant_raw = authority._original(result["original"], 65536)
        p.require(p.sha(grant_raw) == p.digest(result["sha256"]))
        _same(result["pin"], {"path": publication.DESTINATIONS[job], "sha256": p.sha(grant_raw)})
        _same(services[role], {**row, "generationGrantOriginal": result["original"]})
        result_raw = generation.canonical(result)
        _reserve(owner, len(raw) + len(result_raw))
        owner.generation_inputs[role], owner.generation_results[role] = raw, result_raw
    owner.ordinary_context = {"launchOriginal": owner.launch_raw.decode("ascii"), "services": services}
    context_raw = generation.canonical(owner.ordinary_context)
    owner.ordinary_context_sha = p.sha(context_raw)
    _reserve(owner, sum(len(raw) for raw in (owner.phase_raw, owner.installed_raw, owner.launch_raw))
        + len(generation.canonical(owner.fragment)) + len(context_raw))
    _current(owner, request)


def _prior(owner, *, now, epoch):
    for (operation, role), job in zip(TRANSITIONS[:owner.next], JOB_NAMES[:owner.next], strict=True):
        raw = _approved(owner.process, "service-originals", job)
        p.require(raw == owner.inputs[job])
        result = owner.process.prior_result("service-originals", job)
        verified = checked_result(operation, role, raw, result, boot=owner.boot,
            now_boottime_ns=now, now_unix_ns=epoch)
        result_raw = generation.canonical(result)
        if job not in owner.outputs:
            _reserve(owner, len(verified) + len(result_raw))
            owner.outputs[job], owner.results[job] = verified, result_raw
        else:
            p.require(owner.outputs[job] == verified and owner.results[job] == result_raw)


def compose(policy, *, process, request) -> bytes:
    """Compose exactly one existing authority input from the real pending job."""
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
        operation, role = TRANSITIONS[index]
        previous = ("head", "cleanup") if operation == "current" else ("head",) if operation == "cleanup" else ()
        raw = profile.build(operation, role, fragment=owner.fragment, ordinary_context=owner.ordinary_context,
            native_context=owner.native_context,
            prior_transition_originals={name: owner.outputs["ordinary-" + name] for name in previous},
            boot=owner.boot, now_boottime_ns=now, now_unix_ns=epoch)
        p.require(type(raw) is bytes and 0 < len(raw) <= JOBS["service-originals"][request.job_index - 1].maximum)
        _current(owner, request)
        _reserve(owner, len(raw))
        owner.inputs[request.job] = raw
        owner.next += 1
        owner.inflight = None
        return raw
    except BaseException:
        owner.failed = True
        raise


def require_transitions(policy, *, process, request) -> dict:
    """Read-only five-result first handoff at actual native-closure-retrieval79."""
    return _verified_transitions(policy, process=process, request=request, first=True)


def recheck_transitions(policy, *, process, request) -> dict:
    """Recheck the opened boundary through late authorizations and service material."""
    return _verified_transitions(policy, process=process, request=request, first=False)


def _verified_transitions(policy, *, process, request, first):
    _owners(policy, process, request)
    owner = _LIVE
    p.require(owner is not None and owner.policy is policy and owner.process is process
        and not owner.failed and not owner.closed and owner.inflight is None and owner.next == len(TRANSITIONS)
        and installation.native_completed_boundary(request)
        and NEXT_INDEX <= request.job_index <= _AUTHORIZATION_LAST_INDEX
        and (request.job_index == NEXT_INDEX and request.job == NEXT_JOB
             if first else owner.authorization_boundary_open))
    owner.inflight = request
    try:
        now, epoch = _current(owner, request)
        _prior(owner, now=now, epoch=epoch)
        _current(owner, request)
        p.require(tuple(owner.outputs) == JOB_NAMES)
        result = {job: {"inputOriginal": owner.inputs[job], "grantOriginal": owner.outputs[job]} for job in JOB_NAMES}
        owner.authorization_boundary_open = True
        owner.inflight = None
        return result
    except BaseException:
        owner.failed = True
        raise


def close(process):
    """Discard public data only after known cleanup of the actual process."""
    global _LIVE
    if _LIVE is None:
        return
    from serverware.native_pilot_supervisor_process import AuthorityCoordinatorProcess
    owner = _LIVE
    p.require(type(process) is AuthorityCoordinatorProcess and owner.process is process and process._closed
        and not owner.close_attempted
        and process._result["status"] in ("not-started", "stopped-cleanup-complete", "failed-cleanup-complete"))
    owner.close_attempted = True
    owner.inputs.clear(); owner.outputs.clear(); owner.results.clear()
    owner.generation_inputs.clear(); owner.generation_results.clear()
    if owner.native_context is not None:
        owner.native_context.clear()
    owner.closed = True
    _LIVE = None
