"""Ten fixed endpoint launch bundles from actual completed commissioning owners.

The existing installer performs publication only after the independently
approved bundle is returned through the real pending request. This composer
retains actual signed prerequisites and installation results; it does not
sign, publish, launch, attest a guest or renew any original time interval.
"""
from __future__ import annotations

import time

from serverware import native_pilot_endpoint_launch_profile as profile
from serverware import native_pilot_key_profile as key_profile
from serverware import native_pilot_launch_publication as launch
from serverware import native_pilot_supervisor_endpoint_deliveries as endpoints
from serverware import native_pilot_supervisor_launch_authorizations as authorizations
from serverware import native_pilot_supervisor_native_services as services
from serverware import native_shadow_nitro_originals as originals
from serverware.native_pilot_phase_execution import JOBS, MAX_RETAINED_BYTES, job_index

p = key_profile.p
ROLES = profile.ROLES
NEXT_JOB = "service-material"
JOB_NAMES = tuple("install-launch-" + role for role in ROLES)
FIRST_INDEX = job_index("service-originals", JOB_NAMES[0])
NEXT_INDEX = job_index("service-originals", NEXT_JOB)
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


def _slot(request):
    p.require(request.phase == "service-originals" and type(request.job_index) is int
        and FIRST_INDEX <= request.job_index < FIRST_INDEX + len(ROLES))
    index = request.job_index - FIRST_INDEX
    p.require(request.job == JOB_NAMES[index]
        and tuple(job.name for job in JOBS["service-originals"][FIRST_INDEX - 1:
            FIRST_INDEX - 1 + len(ROLES)]) == JOB_NAMES)
    return index


class _Attempt:
    def __init__(self, policy, process):
        self.policy, self.process = policy, process
        self.next = self.retained_bytes = 0
        self.inflight = None
        self.failed = self.closed = self.close_attempted = False
        self.material_boundary_open = False
        self.inputs, self.results = {}, {}
        self.key_inputs, self.key_results, self.pairs, self.pair_digests = {}, {}, {}, {}
        self.authorizations = self.services = self.fragment = self.phase_raw = None
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


def _service_context(owner, role):
    operation = launch.LAUNCHES[role][2] or "generationInstall"
    return {**owner.services[operation], "commitRequestOriginal":
        owner.services["commitRequest"]["grantOriginal"] if role == "commitRequest" else None}


def _authorization_context(owner, role):
    return {operation: owner.authorizations[name] for (operation, selected), name in
        zip(authorizations.AUTHORIZATIONS, authorizations.JOB_NAMES, strict=True) if selected == role}


def _current(owner, request):
    _owners(owner.policy, owner.process, request)
    p.require(_LIVE is owner and not owner.failed and not owner.closed)
    p.require(authorizations.recheck_authorizations(owner.policy, process=owner.process, request=request)
        == owner.authorizations)
    p.require(services.recheck_services(owner.policy, process=owner.process, request=request) == owner.services)
    phase = endpoints._phase(owner.process, "service-originals")
    p.require(p.canonical(phase) == owner.phase_raw
        and p.sha(owner.phase_raw) == request.value["conductorRequestSha256"]
        and request.deadline_boottime_ns == owner.deadline == p.ns(phase["deadlineBoottimeNs"]))
    for job, raw in owner.key_inputs.items():
        p.require(_approved(owner.process, job) == raw
            and p.canonical(owner.process.prior_result("service-originals", job)) == owner.key_results[job])
    for role, pair in owner.pairs.items():
        p.require(p.sha(p.canonical(pair)) == owner.pair_digests[role])
    _same(owner.policy.endpoint_launch_policy(process=owner.process, request=request), owner.fragment)
    now, epoch = key_profile.c9._live(owner.window, owner.last), time.time_ns()
    p.require(originals._boot() == owner.boot and now < owner.deadline and owner.last_wall <= epoch)
    owner.last, owner.last_wall = now, epoch
    return now, epoch


def _capture(owner, request):
    owner.authorizations = authorizations.require_authorizations(owner.policy, process=owner.process, request=request)
    owner.services = services.recheck_services(owner.policy, process=owner.process, request=request)
    for values, names, fields in ((owner.authorizations, authorizations.JOB_NAMES, ("inputOriginal", "authorizationOriginal")),
            (owner.services, services.OPERATIONS, ("inputOriginal", "grantOriginal"))):
        p.fields(values, names)
        for row in values.values():
            p.fields(row, fields)
            p.require(all(type(raw) is bytes and raw for raw in row.values()))
            _reserve(owner, sum(len(raw) for raw in row.values()))
    owner.fragment = profile.validate_policy(owner.policy.endpoint_launch_policy(process=owner.process, request=request))
    phase = endpoints._phase(owner.process, "service-originals")
    owner.phase_raw, owner.deadline = p.canonical(phase), p.ns(phase["deadlineBoottimeNs"])
    owner.boot, now, epoch = originals._boot(), originals._clock(), time.time_ns()
    for role in ROLES:
        first_job, second_job = "native-role-keys-" + role, "native-key-admission-" + role
        first, second = _approved(owner.process, first_job), _approved(owner.process, second_job)
        outputs = []
        for job, raw in ((first_job, first), (second_job, second)):
            result = p.fields(owner.process.prior_result("service-originals", job), ("original", "sha256"))
            output, _ = key_profile.c9._original(result["original"], key_profile.MAX_OUTPUT)
            p.require(p.sha(output) == p.digest(result["sha256"]))
            result_raw = p.canonical(result)
            _reserve(owner, len(raw) + len(result_raw))
            owner.key_inputs[job], owner.key_results[job] = raw, result_raw
            outputs.append(output)
        pair = {"roleKeyInputOriginal": first.decode("ascii"), "roleKeyOriginal": outputs[0].decode("ascii"),
            "admissionInputOriginal": second.decode("ascii"), "admissionOriginal": outputs[1].decode("ascii")}
        key_profile.admitted_pair(role, first, outputs[0], second, outputs[1],
            boot=owner.boot, now_boottime_ns=now, now_unix_ns=epoch)
        checked = key_profile.prepare_input("admission", role, second,
            boot=owner.boot, now_boottime_ns=now, now_unix_ns=epoch)
        if owner.window is None:
            owner.window = checked["window"]
        else:
            _same(owner.window, checked["window"])
        pair_raw = p.canonical(pair)
        _reserve(owner, len(pair_raw))
        owner.pairs[role], owner.pair_digests[role] = pair, p.sha(pair_raw)
    _reserve(owner, len(owner.phase_raw) + len(p.canonical(owner.fragment)))
    _current(owner, request)


def _build(owner, role, *, now, epoch):
    return profile.build(role, fragment=owner.fragment, pair_context=owner.pairs[role],
        authorizations=_authorization_context(owner, role), service_context=_service_context(owner, role),
        boot=owner.boot, now_boottime_ns=now, now_unix_ns=epoch)


def _prior(owner, *, now, epoch):
    for role, job in zip(ROLES[:owner.next], JOB_NAMES[:owner.next], strict=True):
        raw = _approved(owner.process, job)
        p.require(raw == owner.inputs[role] == _build(owner, role, now=now, epoch=epoch))
        result = owner.process.prior_result("service-originals", job)
        checked = profile.checked_result(role, raw, result, pair_context=owner.pairs[role],
            service_context=_service_context(owner, role), boot=owner.boot,
            now_boottime_ns=now, now_unix_ns=epoch)
        result_raw = p.canonical(checked)
        _same(checked, result)
        if role not in owner.results:
            _reserve(owner, len(result_raw))
            owner.results[role] = result_raw
        else:
            p.require(owner.results[role] == result_raw)


def compose(policy, *, process, request) -> bytes:
    """Return one complete fixed launch bundle, never an installation verdict."""
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
        role = ROLES[index]
        raw = _build(owner, role, now=now, epoch=epoch)
        p.require(type(raw) is bytes and 0 < len(raw) <= JOBS["service-originals"][request.job_index - 1].maximum)
        _current(owner, request)
        _reserve(owner, len(raw))
        owner.inputs[role] = raw
        owner.next += 1
        owner.inflight = None
        return raw
    except BaseException:
        owner.failed = True
        raise


def require_launches(policy, *, process, request) -> dict:
    """Read-only actual installation handoff at the service-material job."""
    return _verified_launches(policy, process=process, request=request, first=True)


def recheck_launches(policy, *, process, request) -> dict:
    """Recheck the opened handoff at that same service-material job only."""
    return _verified_launches(policy, process=process, request=request, first=False)


def _verified_launches(policy, *, process, request, first):
    _owners(policy, process, request)
    owner = _LIVE
    p.require(owner is not None and owner.policy is policy and owner.process is process
        and not owner.failed and not owner.closed and owner.inflight is None and owner.next == len(ROLES)
        and request.phase == "service-originals" and request.job_index == NEXT_INDEX
        and request.job == NEXT_JOB and JOBS["service-originals"][request.job_index - 1].name == NEXT_JOB
        and (first or owner.material_boundary_open))
    owner.inflight = request
    try:
        now, epoch = _current(owner, request)
        _prior(owner, now=now, epoch=epoch)
        _current(owner, request)
        p.require(tuple(owner.results) == ROLES)
        result = {role: {"inputOriginal": owner.inputs[role], "result": p.document(owner.results[role], 32768)}
            for role in ROLES}
        owner.material_boundary_open = True
        owner.inflight = None
        return result
    except BaseException:
        owner.failed = True
        raise


def close(process):
    """Forget public data only after known cleanup of the originating process."""
    global _LIVE
    if _LIVE is None:
        return
    from serverware.native_pilot_supervisor_process import AuthorityCoordinatorProcess
    owner = _LIVE
    p.require(type(process) is AuthorityCoordinatorProcess and owner.process is process and process._closed
        and not owner.close_attempted
        and process._result["status"] in ("not-started", "stopped-cleanup-complete", "failed-cleanup-complete"))
    owner.close_attempted = True
    owner.inputs.clear(); owner.results.clear()
    owner.key_inputs.clear(); owner.key_results.clear(); owner.pairs.clear(); owner.pair_digests.clear()
    for values in (owner.authorizations, owner.services):
        if values is not None:
            values.clear()
    owner.closed = True
    _LIVE = None
