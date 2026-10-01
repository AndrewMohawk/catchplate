"""Thirty-one fixed late authorizations from genuine completed owners.

Only the originating process's actual key inputs/results and retained approved
policy reach the purpose-specific builders. This owner neither signs nor
publishes files, allocates resources, performs KMS operations or launches a
guest. A failed attempt is retained until genuine terminal process cleanup.
"""
from __future__ import annotations

import time

from serverware import custody_generation_grants as generation
from serverware import native_pilot_key_profile as key_profile
from serverware import native_pilot_launch_authorization_profile as profile
from serverware import native_pilot_ordinary_install as installation
from serverware import native_pilot_supervisor_endpoint_deliveries as endpoints
from serverware import native_pilot_supervisor_key_authorizations as keys
from serverware import native_pilot_supervisor_ordinary_transitions as transitions
from serverware import native_shadow_nitro_originals as originals
from serverware.native_pilot_phase_execution import JOBS, LAUNCH_AUTHORIZATION_JOBS, MAX_RETAINED_BYTES, job_index

p = key_profile.p
AUTHORIZATIONS = profile.JOBS
NEXT_JOB = "install-launch-retrieval"
JOB_NAMES = tuple(profile.job_name(operation, role) for operation, role in AUTHORIZATIONS)
FIRST_INDEX = job_index("service-originals", JOB_NAMES[0])
NEXT_INDEX = job_index("service-originals", NEXT_JOB)
_LAUNCH_LAST_INDEX = job_index("service-originals", "service-material")
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
    p.require(request.phase == "service-originals" and type(request.job_index) is int
        and FIRST_INDEX <= request.job_index < FIRST_INDEX + len(AUTHORIZATIONS))
    index = request.job_index - FIRST_INDEX
    p.require(request.job == JOB_NAMES[index]
        and tuple(job.name for job in LAUNCH_AUTHORIZATION_JOBS) == JOB_NAMES
        and tuple(job.name for job in JOBS["service-originals"][FIRST_INDEX - 1:
            FIRST_INDEX - 1 + len(AUTHORIZATIONS)]) == JOB_NAMES)
    return index


class _Attempt:
    def __init__(self, policy, process):
        self.policy, self.process = policy, process
        self.next = self.retained_bytes = 0
        self.inflight = None
        self.failed = self.closed = self.close_attempted = False
        self.launch_boundary_open = False
        self.inputs, self.outputs, self.results = {}, {}, {}
        self.key_inputs, self.key_results, self.pair_contexts, self.pair_digests = {}, {}, {}, {}
        self.transitions = self.fragment = self.phase_raw = None
        self.boot = self.window = self.deadline = None
        self.last, self.last_wall = originals._clock(), time.time_ns()


def _reserve(owner, count):
    p.integer(count, minimum=0, maximum=MAX_RETAINED_BYTES)
    p.require(owner.retained_bytes + count <= MAX_RETAINED_BYTES)
    owner.retained_bytes += count


def _approved(process, job):
    raw = process.approved_input_original("service-originals", job)
    p.require(p.sha(raw) == process.approved_input_sha256("service-originals", job))
    return raw


def _current(owner, request):
    _owners(owner.policy, owner.process, request)
    p.require(_LIVE is owner and not owner.failed and not owner.closed)
    # The originating completed chain reauthenticates all five transitions,
    # eleven native grants, ten key pairs and the original commissioning data.
    p.require(transitions.recheck_transitions(owner.policy, process=owner.process, request=request)
        == owner.transitions)
    phase = endpoints._phase(owner.process, "service-originals")
    p.require(p.canonical(phase) == owner.phase_raw
        and p.sha(owner.phase_raw) == request.value["conductorRequestSha256"]
        and request.deadline_boottime_ns == owner.deadline == p.ns(phase["deadlineBoottimeNs"]))
    for job, raw in owner.key_inputs.items():
        p.require(_approved(owner.process, job) == raw
            and p.canonical(owner.process.prior_result("service-originals", job)) == owner.key_results[job])
    for role, pair in owner.pair_contexts.items():
        p.require(p.sha(p.canonical(pair)) == owner.pair_digests[role])
    _same(owner.policy.launch_authorization_policy(process=owner.process, request=request), owner.fragment)
    now, epoch = key_profile.c9._live(owner.window, owner.last), time.time_ns()
    p.require(originals._boot() == owner.boot and now < owner.deadline and owner.last_wall <= epoch)
    owner.last, owner.last_wall = now, epoch
    return now, epoch


def _capture(owner, request):
    owner.transitions = transitions.require_transitions(owner.policy, process=owner.process, request=request)
    p.fields(owner.transitions, transitions.JOB_NAMES)
    for value in owner.transitions.values():
        p.fields(value, ("inputOriginal", "grantOriginal"))
        p.require(all(type(raw) is bytes and raw for raw in value.values()))
        _reserve(owner, sum(len(raw) for raw in value.values()))
    pair_originals = keys.recheck_authorizations(owner.policy, process=owner.process, request=request)
    p.fields(pair_originals, key_profile.ROLES)
    owner.fragment = profile.validate_policy(owner.policy.launch_authorization_policy(process=owner.process, request=request))
    phase = endpoints._phase(owner.process, "service-originals")
    owner.phase_raw, owner.deadline = p.canonical(phase), p.ns(phase["deadlineBoottimeNs"])
    owner.boot, now, epoch = originals._boot(), originals._clock(), time.time_ns()
    for role in key_profile.ROLES:
        first_job, second_job = "native-role-keys-" + role, "native-key-admission-" + role
        first, second = _approved(owner.process, first_job), _approved(owner.process, second_job)
        pair = p.fields(pair_originals[role], ("roleKeyOriginal", "admissionOriginal"))
        p.require(all(type(raw) is bytes and raw for raw in pair.values()))
        for job, input_raw, output_raw in ((first_job, first, pair["roleKeyOriginal"]),
                (second_job, second, pair["admissionOriginal"])):
            result = p.fields(owner.process.prior_result("service-originals", job), ("original", "sha256"))
            p.require(result["original"] == output_raw.decode("ascii") and p.digest(result["sha256"]) == p.sha(output_raw))
            result_raw = p.canonical(result)
            _reserve(owner, len(input_raw) + len(result_raw))
            owner.key_inputs[job], owner.key_results[job] = input_raw, result_raw
        context = {"roleKeyInputOriginal": first.decode("ascii"), "roleKeyOriginal": pair["roleKeyOriginal"].decode("ascii"),
            "admissionInputOriginal": second.decode("ascii"), "admissionOriginal": pair["admissionOriginal"].decode("ascii")}
        key_profile.admitted_pair(role, first, pair["roleKeyOriginal"], second, pair["admissionOriginal"],
            boot=owner.boot, now_boottime_ns=now, now_unix_ns=epoch)
        checked = key_profile.prepare_input("admission", role, second,
            boot=owner.boot, now_boottime_ns=now, now_unix_ns=epoch)
        if owner.window is None:
            owner.window = checked["window"]
        else:
            _same(owner.window, checked["window"])
        context_raw = p.canonical(context)
        _reserve(owner, len(context_raw))
        owner.pair_contexts[role], owner.pair_digests[role] = context, p.sha(context_raw)
    _reserve(owner, len(owner.phase_raw) + len(generation.canonical(owner.fragment)))
    _current(owner, request)


def _prior(owner, *, now, epoch):
    for (operation, role), job in zip(AUTHORIZATIONS[:owner.next], JOB_NAMES[:owner.next], strict=True):
        raw = _approved(owner.process, job)
        p.require(raw == owner.inputs[job])
        result = owner.process.prior_result("service-originals", job)
        verified = profile.checked_result(operation, role, raw, result,
            boot=owner.boot, now_boottime_ns=now, now_unix_ns=epoch)
        result_raw = p.canonical(result)
        if job not in owner.outputs:
            _reserve(owner, len(verified) + len(result_raw))
            owner.outputs[job], owner.results[job] = verified, result_raw
        else:
            p.require(owner.outputs[job] == verified and owner.results[job] == result_raw)


def compose(policy, *, process, request) -> bytes:
    """Compose one source-fixed input from the actual pending request token."""
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
        operation, role = AUTHORIZATIONS[index]
        previous = ({"request-commitment": owner.outputs[profile.job_name("request-commitment", role)]}
            if (operation, role) == ("encrypted-delivery", "commitRequest") else {})
        raw = profile.build(operation, role, fragment=owner.fragment, pair_context=owner.pair_contexts[role],
            prior_authorization_originals=previous, boot=owner.boot, now_boottime_ns=now, now_unix_ns=epoch)
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


def require_authorizations(policy, *, process, request) -> dict:
    """Read-only actual thirty-one-result handoff at the first endpoint launch."""
    return _verified_authorizations(policy, process=process, request=request, first=True)


def recheck_authorizations(policy, *, process, request) -> dict:
    """Recheck the opened boundary through fixed launches and service material."""
    return _verified_authorizations(policy, process=process, request=request, first=False)


def _verified_authorizations(policy, *, process, request, first):
    _owners(policy, process, request)
    owner = _LIVE
    p.require(owner is not None and owner.policy is policy and owner.process is process
        and not owner.failed and not owner.closed and owner.inflight is None and owner.next == len(AUTHORIZATIONS)
        and installation.native_completed_boundary(request)
        and NEXT_INDEX <= request.job_index <= _LAUNCH_LAST_INDEX
        and (request.job_index == NEXT_INDEX and request.job == NEXT_JOB
             if first else owner.launch_boundary_open))
    owner.inflight = request
    try:
        now, epoch = _current(owner, request)
        _prior(owner, now=now, epoch=epoch)
        _current(owner, request)
        p.require(tuple(owner.outputs) == JOB_NAMES)
        result = {job: {"inputOriginal": owner.inputs[job], "authorizationOriginal": owner.outputs[job]} for job in JOB_NAMES}
        owner.launch_boundary_open = True
        owner.inflight = None
        return result
    except BaseException:
        owner.failed = True
        raise


def close(process):
    """Release only after the originating process reports known cleanup."""
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
    owner.key_inputs.clear(); owner.key_results.clear(); owner.pair_contexts.clear(); owner.pair_digests.clear()
    if owner.transitions is not None:
        owner.transitions.clear()
    owner.closed = True
    _LIVE = None
