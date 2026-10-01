"""One retained, protected late intake for eight independent currentness decisions.

Only the genuine pending coordinator request and actual approved predecessors
enter acquisition. Public observations never authorize currentness. Complete
input and approval bytes arrive separately through protected, independently
pinned FDs; this owner neither creates an approval nor signs or publishes.
Failures consume the attempt and retain partial handles until real cleanup.
"""
from __future__ import annotations

import copy
import fcntl
import os
import time

from scripts.authority import native_pilot_authority_io as io
from serverware import custody_generation_grants as generation
from serverware import native_pilot_approval_install as approvals
from serverware import native_pilot_ordinary_generation_profile as grants
from serverware import native_pilot_ordinary_initial_profile as initial
from serverware import native_pilot_precreation_install as precreation
from serverware import native_pilot_service_authority as service
from serverware import native_pilot_service_material as material_profile
from serverware import native_pilot_supervisor_current_head_profile as profile
from serverware import native_pilot_supervisor_endpoint_deliveries as endpoints
from serverware import native_pilot_supervisor_service_material as material
from serverware import native_shadow_nitro_originals as originals
from serverware.native_pilot_phase_execution import (
    CURRENT_HEAD_JOBS, CURRENT_HEAD_JOB_INFO, HELPER_INITIAL_JOBS, HELPER_INITIAL_JOB_INFO,
    JOBS, MAX_APPROVAL, MAX_RETAINED_BYTES, job_index,
)

p = generation.p
PHASE = "bridge-runtime"
NEXT_JOB = "install-bridge-runtime"
JOB_NAMES = tuple(job.name for job in CURRENT_HEAD_JOBS)
FIRST_INDEX = job_index(PHASE, JOB_NAMES[0])
NEXT_INDEX = job_index(PHASE, NEXT_JOB)
_TOKEN = object()
_LIVE = None
_USED = False


def _owners(policy, process, request):
    from serverware.native_pilot_supervisor_policy import SupervisorPolicy
    from serverware.native_pilot_supervisor_process import AuthorityCoordinatorProcess, JobRequest
    p.require(type(policy) is SupervisorPolicy and type(process) is AuthorityCoordinatorProcess
        and type(request) is JobRequest)
    policy.check(process); process.check_request(request)


def _slot(request):
    p.require(JOB_NAMES == profile.JOB_NAMES
        and tuple(CURRENT_HEAD_JOB_INFO[name] for name in JOB_NAMES) == profile.TARGETS)
    p.require(request.phase == PHASE and type(request.job_index) is int
        and FIRST_INDEX <= request.job_index < NEXT_INDEX
        and NEXT_INDEX == FIRST_INDEX + len(JOB_NAMES))
    index = request.job_index - FIRST_INDEX
    p.require(request.job == JOB_NAMES[index]
        and tuple(job.name for job in JOBS[PHASE][:len(JOB_NAMES)]) == JOB_NAMES)
    return index


def _same(first, second):
    p.require(generation.canonical(first) == generation.canonical(second))


def _public_size(value):
    """Conservatively count retained public copies, including byte originals."""
    pending, total, count = [value], 0, 0
    while pending:
        item = pending.pop(); count += 1
        p.require(count <= 65536 and total <= MAX_RETAINED_BYTES)
        if type(item) is dict:
            pending.extend(item.keys()); pending.extend(item.values())
        elif type(item) in (list, tuple):
            pending.extend(item)
        elif type(item) in (str, bytes):
            total += len(item)
        else:
            total += len(generation.canonical(item))
    p.require(total <= MAX_RETAINED_BYTES)
    return total


class CurrentHeadIntake:
    def __init__(self, token, policy, process):
        p.require(token is _TOKEN)
        self._policy, self._process = policy, process
        self._pid, self._boot = os.getpid(), originals._boot()
        self._request = self._context = self._observed = None
        self._fragment = self._initial_policy = self._bootstrap = None
        self._phase_raw = self._service_phase_raw = self._bootstrap_phase_raw = self._material = None
        self._deadline = self._epoch_limit = None
        self._sources, self._source_results, self._inputs, self._outputs, self._results = {}, {}, {}, {}, {}
        self._fds, self._observations = [], {}
        self._index = self._next = self._retained_bytes = 0
        self._attempted = set()
        self._failed = self._closed = self._close_attempted = False
        self._runtime_handoff_attempted = False
        self._adopted = False
        self._last, self._last_wall = originals._clock(), time.time_ns()

    def _reserve(self, count):
        p.integer(count, minimum=0, maximum=MAX_RETAINED_BYTES)
        p.require(self._retained_bytes + count <= MAX_RETAINED_BYTES)
        self._retained_bytes += count

    def _remember(self, phase, job, *, result=False):
        slot = (phase, job)
        raw = self._process.approved_input_original(phase, job)
        p.require(type(raw) is bytes and p.sha(raw) == self._process.approved_input_sha256(phase, job))
        self._reserve(len(raw)); self._sources[slot] = raw
        if result:
            value = self._process.prior_result(phase, job)
            encoded = p.canonical(value)
            self._reserve(len(encoded)); self._source_results[slot] = encoded
            return raw, value
        return raw

    def _capture(self):
        policy, process, request = self._policy, self._process, self._request
        # This is the sole call into the prior live material owner. Everything
        # subsequently retained is its actual immutable checked handoff.
        self._material = material.require_material(policy, process=process, request=request)
        p.fields(self._material, ("inputOriginal", "result"))
        material_raw, material_result = self._remember("service-originals", "service-material", result=True)
        p.require(material_raw == self._material["inputOriginal"])
        _same(material_result, self._material["result"])
        self._fragment = profile.validate_policy(policy.current_head_policy(process=process, request=request))
        self._initial_policy = policy.ordinary_initial_policy(process=process, request=request)
        self._bootstrap = policy.bootstrap_originals()
        p.require(self._bootstrap == process.bootstrap_originals())
        self._phase_raw = p.canonical(endpoints._phase(process, PHASE))
        self._service_phase_raw = p.canonical(endpoints._phase(process, "service-originals"))
        self._bootstrap_phase_raw = p.canonical(endpoints._phase(process, "bootstrap-admission"))
        phase = p.document(self._phase_raw, 32 * 1024 * 1024)
        observed = p.document(self._service_phase_raw, 32 * 1024 * 1024)["payload"]
        bootstrap_observed = p.document(self._bootstrap_phase_raw, 32 * 1024 * 1024)["payload"]
        bridge_raw = phase["payload"]["bridgePreparationOriginal"].encode("ascii")
        from serverware import native_pilot_bridge_preparation as bridge_profile
        bridge = bridge_profile.shape(bridge_raw)
        self._adopted = bridge["apiVersion"] == bridge_profile.ADOPTED_API
        now, wall = originals._clock(), time.time_ns()
        admitted = material_profile.prepare_bundle(material_raw, boot=self._boot,
            now_boottime_ns=now, now_unix_ns=wall, adopted=self._adopted)
        self._deadline, self._epoch_limit = admitted["deadline"], admitted["epochLimit"]
        p.require(bridge["driverObservationSha256"]
            == p.sha(bootstrap_observed["bootstrapObservationOriginal"].encode("ascii")))
        grant_pins = p.fields(phase["payload"]["ordinaryGenerationGrants"], generation.ROLES)
        installed_raw = self._remember("endpoint-precreation", "install-precreation")
        installed = p.fields(p.document(installed_raw, precreation.MAX_INPUT), precreation.FIELDS)
        p.require(installed["driverConfigurationOriginal"] == self._bootstrap["configuration"].decode("ascii")
            and installed["driverWindowOriginal"] == self._bootstrap["window"].decode("ascii"))
        ordinary, primary = {}, {}
        for role in generation.ROLES:
            raw, result = self._remember("service-originals", "ordinary-generation-" + role, result=True)
            value = p.fields(p.document(raw, service.MAX_INPUT_BYTES), grants.INPUT_FIELDS)
            p.require(value["apiVersion"] == (service.ADOPTED_INPUT_API if self._adopted
                else "serverware.nativePilotServiceAuthorityInput/v1") and value["operation"] == "generation"
                and value["serviceRole"] == role and value["launchOriginal"] == installed["ordinaryLaunchOriginal"])
            row = copy.deepcopy(p.fields(p.fields(value["services"], (role,))[role], grants.SERVICE_FIELDS))
            p.require(row["configurationOriginal"] == installed["ordinaryColdOriginals"][role])
            p.fields(result, ("original", "sha256", "pin"))
            p.require(p.sha(result["original"].encode("ascii")) == p.digest(result["sha256"])
                == p.digest(grant_pins[role]))
            row["generationGrantOriginal"] = result["original"]
            ordinary[role] = row
            _, result = self._remember("service-originals", "ordinary-initial-assemble-" + role, result=True)
            p.fields(result, ("original", "sha256", "pin"))
            primary[role] = result["original"].encode("ascii")
            p.require(p.sha(primary[role]) == p.digest(result["sha256"]) and row["historyOriginal"] == result["original"])
        helper_runtime = generation.document(ordinary[generation.ROLES[-1]]["runtimeOriginal"].encode("ascii"), generation.MAX_BYTES)
        members = p.fields(helper_runtime["initialEndpointHistories"], initial.HELPER_ENDPOINT_ROLES)
        seen = set()
        for raw in (primary[generation.ROLES[-1]], *self._supplemental()):
            wrapper = generation.document(raw, initial.MAX_HELPER_HISTORY)
            endpoint_role = wrapper["initialCheckpoint"]["payload"]["endpointRole"]
            p.require(endpoint_role in members and endpoint_role not in seen and members[endpoint_role] == raw.decode("ascii"))
            seen.add(endpoint_role)
        p.require(seen == set(initial.HELPER_ENDPOINT_ROLES))
        kwargs = dict(fragment=self._fragment,
            bridge_preparation_raw=bridge_raw,
            driver_configuration_raw=self._bootstrap["configuration"], driver_window_raw=self._bootstrap["window"],
            launch_raw=installed["ordinaryLaunchOriginal"].encode("ascii"),
            preparation_raw=observed["ordinaryPreparationOriginal"].encode("ascii"),
            resources_raw=observed["ordinaryInitialResourcesOriginal"].encode("ascii"),
            ordinary_context=ordinary, initial_policy=self._initial_policy)
        self._context = profile.prepare_context(**kwargs, boot=self._boot, now_boottime_ns=originals._clock())
        self._deadline = min(self._deadline, self._context["deadline"], request.deadline_boottime_ns)
        self._reserve(_public_size(self._context) + _public_size(self._material)
            + sum(len(raw) for raw in self._bootstrap.values())
            + len(self._phase_raw) + len(self._service_phase_raw) + len(self._bootstrap_phase_raw)
            + sum(len(generation.canonical(value)) for value in (self._fragment, self._initial_policy))
        )

    def _supplemental(self):
        values = []
        for job in HELPER_INITIAL_JOBS:
            _, operation = HELPER_INITIAL_JOB_INFO[job.name]
            if operation == "assemble":
                _, result = self._remember("service-originals", job.name, result=True)
                p.fields(result, ("original", "sha256"))
                raw = result["original"].encode("ascii")
                p.require(p.sha(raw) == p.digest(result["sha256"]))
                values.append(raw)
        return values

    def _clock(self):
        p.require(os.getpid() == self._pid and originals._boot() == self._boot)
        now, wall = originals._clock(), time.time_ns()
        p.require(self._last <= now < min(self._deadline, self._request.deadline_boottime_ns)
            and self._last_wall <= wall and (self._epoch_limit is None or wall < self._epoch_limit))
        self._last, self._last_wall = now, wall
        return now

    def _prior(self, count):
        for name in JOB_NAMES[:count]:
            raw = self._process.approved_input_original(PHASE, name)
            p.require(raw == self._inputs[name] and p.sha(raw) == self._process.approved_input_sha256(PHASE, name))
            result = self._process.prior_result(PHASE, name)
            result_raw = p.canonical(result)
            now = self._clock()
            if name not in self._outputs:
                verified = profile.checked_result(name, raw, result, context=self._context,
                    boot=self._boot, now_boottime_ns=now)
                self._reserve(len(verified) + len(result_raw))
                self._outputs[name], self._results[name] = verified, result_raw
            else:
                # Reuse only the first authenticated result for this immutable
                # context. check() rechecks every source literal and original
                # clock bound; a different statement or signature is refused.
                p.require(self._results[name] == result_raw
                    and self._outputs[name] == result["original"].encode("ascii"))

    def check(self):
        try:
            p.require(_LIVE is self and not self._failed and not self._closed and self._request is not None)
            _owners(self._policy, self._process, self._request)
            self._clock()
            p.require(p.canonical(endpoints._phase(self._process, PHASE)) == self._phase_raw
                and p.sha(self._phase_raw) == self._request.value["conductorRequestSha256"]
                and p.canonical(endpoints._phase(self._process, "service-originals")) == self._service_phase_raw
                and p.canonical(endpoints._phase(self._process, "bootstrap-admission")) == self._bootstrap_phase_raw)
            _same(self._policy.current_head_policy(process=self._process, request=self._request), self._fragment)
            _same(self._policy.ordinary_initial_policy(process=self._process, request=self._request), self._initial_policy)
            p.require(self._policy.bootstrap_originals() == self._bootstrap == self._process.bootstrap_originals())
            for (phase, job), raw in self._sources.items():
                p.require(self._process.approved_input_original(phase, job) == raw
                    and self._process.approved_input_sha256(phase, job) == p.sha(raw))
                if (phase, job) in self._source_results:
                    p.require(p.canonical(self._process.prior_result(phase, job)) == self._source_results[phase, job])
            for fd, identity, raw, maximum in self._fds:
                p.require(io._input(fd, maximum) == identity and io.read_public(fd, maximum) == raw)
            self._prior(self._index)
            _owners(self._policy, self._process, self._request); self._clock()
        except BaseException:
            self._failed = True
            raise

    def observed_original(self):
        self.check()
        p.require(self._request.job in JOB_NAMES and self._observed is not None)
        p.require(profile.observed_original(self._request.job, self._context) == self._observed)
        self.check()
        return self._observed

    def _read(self, fd, digest, maximum):
        identity = io._input(fd, maximum)
        held = fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, 3)
        record = [held, identity, None, maximum]
        self._fds.append(record)  # Retain a duplicate even if the next check fails.
        p.require(io._input(held, maximum) == identity)
        self._reserve(identity[6])
        raw = io.read_public(held, maximum)
        record[2] = raw
        p.require(len(raw) == identity[6] and p.sha(raw) == p.digest(digest)
            and io._input(fd, maximum) == identity)
        return raw

    def admit(self, *, input_fd, input_sha256, approval_fd, approval_sha256):
        try:
            name = self._request.job
            p.require(name not in self._attempted and name in JOB_NAMES and self._index == self._next)
            self._attempted.add(name)  # Consume before checks, reads or validation.
            self.check()
            p.require(type(input_fd) is int and type(approval_fd) is int and input_fd != approval_fd)
            raw = self._read(input_fd, input_sha256, profile.MAX_INPUT)
            approval = self._read(approval_fd, approval_sha256, MAX_APPROVAL)
            prepared = profile.prepare_input(name, raw, context=self._context,
                boot=self._boot, now_boottime_ns=self._clock())
            p.require(prepared["deadline"] >= self._deadline)
            approvals._prepare(self._request.raw, approval, raw, approval_sha256, input_sha256)
            self.check()
            self._inputs[name] = raw
            self._next += 1
            return raw, approval
        except BaseException:
            self._failed = True
            raise


def claim(policy, *, process, request):
    """Claim only this process's next actual current-head request, once."""
    global _LIVE, _USED
    _owners(policy, process, request)
    index = _slot(request)
    if _LIVE is None:
        p.require(not _USED and index == 0)
        _USED = True
        _LIVE = CurrentHeadIntake(_TOKEN, policy, process)
    owner = _LIVE
    try:
        p.require(owner._policy is policy and owner._process is process and not owner._failed and not owner._closed
            and index == owner._next and (owner._request is None or request is not owner._request))
        owner._request, owner._index = request, index
        if index == 0:
            owner._capture()
        owner.check()
        observed = profile.observed_original(request.job, owner._context)
        p.require(type(observed) is bytes and 0 < len(observed) <= profile.MAX_OBSERVED)
        owner._reserve(len(observed))
        owner._observed = observed
        owner._observations[request.job] = observed
        owner.check()
        return owner
    except BaseException:
        owner._failed = True
        raise


def require_heads(policy, *, process, request):
    """Return verified literal results only at the actual runtime-install job."""
    _owners(policy, process, request)
    owner = _LIVE
    p.require(owner is not None)
    try:
        p.require(owner._policy is policy and owner._process is process and not owner._failed and not owner._closed
            and owner._next == len(JOB_NAMES) and request.phase == PHASE
            and request.job == NEXT_JOB and request.job_index == NEXT_INDEX)
        owner._request, owner._index = request, len(JOB_NAMES)
        owner.check()
        return {name: {"inputOriginal": owner._inputs[name], "headOriginal": owner._outputs[name]} for name in JOB_NAMES}
    except BaseException:
        owner._failed = True
        raise


def require_runtime_context(policy, *, process, request):
    """Transfer verified immutable data once, only at runtime installation.

    The receiving owner retains these originals and their actual process joins;
    this does not reopen completed material/service owners or authorize writes.
    """
    _owners(policy, process, request)
    owner = _LIVE
    p.require(owner is not None and not owner._runtime_handoff_attempted)
    owner._runtime_handoff_attempted = True
    try:
        heads = require_heads(policy, process=process, request=request)
        return {"context": copy.deepcopy(owner._context), "heads": heads,
            "material": copy.deepcopy(owner._material), "bootstrapOriginals": owner._bootstrap.copy(),
            "sourceInputs": owner._sources | {(PHASE, name): owner._inputs[name] for name in JOB_NAMES},
            "sourceResults": owner._source_results | {(PHASE, name): owner._results[name] for name in JOB_NAMES},
            "conductorOriginals": {PHASE: owner._phase_raw, "service-originals": owner._service_phase_raw,
                "bootstrap-admission": owner._bootstrap_phase_raw},
            "deadline": owner._deadline, "epochLimit": owner._epoch_limit}
    except BaseException:
        owner._failed = True
        raise


def close(process):
    """Keep partial FDs until this genuine process's terminal cleanup is known."""
    global _LIVE
    if _LIVE is None:
        return
    from serverware.native_pilot_supervisor_process import AuthorityCoordinatorProcess
    owner = _LIVE
    p.require(type(process) is AuthorityCoordinatorProcess and owner._process is process and process._closed
        and not owner._close_attempted and os.getpid() == owner._pid
        and process._result["status"] in ("not-started", "stopped-cleanup-complete", "failed-cleanup-complete"))
    owner._close_attempted = True
    for fd, _, _, _ in reversed(owner._fds):
        os.close(fd)
    owner._fds.clear(); owner._sources.clear(); owner._source_results.clear()
    owner._inputs.clear(); owner._outputs.clear(); owner._results.clear(); owner._observations.clear()
    owner._context = owner._observed = owner._material = None
    owner._closed = True
    _LIVE = None
