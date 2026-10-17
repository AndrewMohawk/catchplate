"""Actual selected supervisor with protected, independently supplied approvals.

There is deliberately no automatic policy-fragment compositor here. The
operator sees each real pending request, retains the full public transcript,
and supplies a complete input plus independent Approval2. Typed source checks
precede exclusive publication and a reply to that same live request. No dict
can construct the real process, received core, or approval-channel owner.
"""
from __future__ import annotations

import fcntl
import os
import time

from scripts.authority import native_pilot_authority_io as io
from catchplate import native_pilot_adopted_phase_profile as profile
from catchplate import native_pilot_approval_install as installation
from catchplate import native_pilot_genesis_parent_control_io as ownership
from catchplate import native_shadow_nitro_originals as originals
from catchplate.native_pilot_adopted_supervisor_policy import AdoptedSupervisorPolicy
from catchplate.native_pilot_supervisor_process import AuthorityCoordinatorProcess

p = profile.p
SUPPORTED_JOBS = tuple((phase, job.name) for phase, jobs in profile.JOBS.items() for job in jobs)
_TOKEN, _USED, _LIVE = object(), False, None


def require_complete_coverage():
    # This is implemented typed-intake coverage, not preprovisioned approvals
    # or proof of deployment. The separate executor owns every actual action.
    p.require(len(SUPPORTED_JOBS) == len(set(SUPPORTED_JOBS)) == len(profile.BY_NAME)
        and tuple(profile.BY_NAME) == tuple(name for _, name in SUPPORTED_JOBS)
        and callable(profile.prepare_input) and callable(profile.checked_result))
    from catchplate.native_pilot_adopted_phase_execution import require_complete_coverage as executable_coverage
    executable_coverage()


class SupervisorError(ValueError):
    def __init__(self, owner):
        super().__init__("adopted commissioning refused; actual supervisor owner retained")
        self.owner = owner


class _Protected:
    def __init__(self, fd, maximum, sha, retained):
        self.fd = None
        self.maximum, self.sha = maximum, p.digest(sha)
        retained.append(self)  # Before any duplicated capability is acquired.
        with ownership.owning():
            self.identity = io._input(fd, maximum)
            self.fd = fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, 3)
        p.require(io._input(self.fd, maximum) == self.identity)
        self.raw = io.read_public(self.fd, maximum)
        self.check()

    def check(self):
        self.check_identity()
        p.require(io.read_public(self.fd, self.maximum) == self.raw and p.sha(self.raw) == self.sha)
        self.check_identity()

    def check_identity(self):
        p.require(self.fd is not None and not os.get_inheritable(self.fd)
            and io._input(self.fd, self.maximum) == self.identity)

    def close(self):
        with ownership.owning():
            fd, self.fd = self.fd, None
            if fd is not None:
                os.close(fd)


class AdoptedCommissioningSupervisor:
    def __init__(self, token, policy, process):
        p.require(token is _TOKEN)
        self._policy, self._process = policy, process
        self._pid, self._start, self._boot = os.getpid(), originals._start(), originals._boot()
        self._index, self._bytes = 0, 0
        self._pending = None
        self._retained, self._installations = [], []
        self._prior, self._observations = {}, {}
        self._stop_admission = None
        self._started = self._closed = self._failed = False

    @classmethod
    def prepare(cls, *, policy, process, measured_recipe=None):
        global _USED, _LIVE
        p.require(cls is AdoptedCommissioningSupervisor and not _USED
            and type(policy) is AdoptedSupervisorPolicy and type(process) is AuthorityCoordinatorProcess
            and process.adoption_selected())
        _USED = True
        owner = cls(_TOKEN, policy, process)
        _LIVE = owner
        try:
            policy.retain_measured_recipe(measured_recipe)
            process.prepare_bootstrap()
            policy.bind(process)
            owner._check()
            return owner
        except BaseException as error:
            owner._failed = True
            raise SupervisorError(owner) from error

    def _origin(self):
        p.require(type(self) is AdoptedCommissioningSupervisor and _LIVE is self and not self._closed
            and (self._pid, self._start, self._boot) == (os.getpid(), originals._start(), originals._boot()))

    def _check(self):
        self._origin()
        p.require(not self._failed)
        self._policy.check(self._process)

    def start(self):
        self._check()
        p.require(not self._started and self._index == 0)
        self._failed = True
        try:
            require_complete_coverage()
            self._policy.require_final_scope(self._process)
            self._process.start()
            self._started = True
            self._policy.check(self._process)
            self._failed = False
        except BaseException as error:
            raise SupervisorError(self) from error

    def step(self):
        self._check()
        p.require(self._started and self._pending is None and self._index < len(SUPPORTED_JOBS))
        self._failed = True
        try:
            request = self._process.receive()
            self._process.check_request(request)
            p.require((request.phase, request.job) == SUPPORTED_JOBS[self._index]
                and request.sequence == self._index + 1)
            if self._index:
                phase, name = SUPPORTED_JOBS[self._index - 1]
                raw = self._process.approved_input_original(phase, name)
                p.require(p.sha(raw) == self._process.approved_input_sha256(phase, name))
                result = self._process.prior_result(phase, name)
                profile.checked_result(name, raw, result, phase=phase, prior=self._prior,
                    observations=self._observations, boot=self._boot, now_boottime_ns=originals._clock(),
                    now_unix_ns=time.time_ns())
                self._prior[name] = {"input": raw, "result": result}
            conductor = self._process.conductor_request(request.phase)
            p.require(p.sha(p.canonical(conductor)) == request.value["conductorRequestSha256"])
            self._observations[request.phase] = conductor["payload"]
            if (request.phase, request.job) == ("endpoint-precreation", "cohort-precreation"):
                self._policy.derive_measured(process=self._process, request=request)
            self._pending = request
            observation = self._policy.observation(process=self._process, request=request)
            self._process.check_request(request)
            self._policy.check(self._process)
            self._failed = False
            return {"phase": request.phase, "job": request.job, "sequence": request.sequence,
                "status": "awaiting-independent-job-approval", "requestOriginal": request.raw.decode("ascii"),
                "requestSha256": p.sha(request.raw), "observationOriginal": observation.decode("ascii"),
                "observationSha256": p.sha(observation)}
        except BaseException as error:
            raise SupervisorError(self) from error

    def submit(self, *, input_fd, input_sha256, approval_fd, approval_sha256):
        self._check()
        p.require(self._started and self._pending is not None and input_fd != approval_fd)
        self._failed = True
        request, lower, wall = self._pending, originals._clock(), time.time_ns()
        try:
            job = profile.JOBS[request.phase][request.job_index - 1]
            inp = _Protected(input_fd, job.maximum, input_sha256, self._retained)
            approval = _Protected(approval_fd, profile.MAX_APPROVAL, approval_sha256, self._retained)
            p.require(inp.identity[:2] != approval.identity[:2]
                and self._bytes + len(inp.raw) + len(approval.raw) <= profile.MAX_RETAINED_BYTES)
            self._bytes += len(inp.raw) + len(approval.raw)
            installation._prepare_adopted(request.raw, approval.raw, inp.raw, approval.sha, inp.sha)
            self._policy.check(self._process); self._process.check_request(request)
            self._policy.require_input(inp.raw, process=self._process, request=request)
            admission_clocks = dict(boot=self._boot, now_boottime_ns=originals._clock(), now_unix_ns=time.time_ns())
            checked = profile.prepare_input(job.name, inp.raw, phase=request.phase, prior=self._prior,
                observations=self._observations, **admission_clocks)
            deadline = request.deadline_boottime_ns if checked.get("deadline") is None else min(
                request.deadline_boottime_ns, checked["deadline"])
            expiry = p.ns(request.value["expiresAtUnixNanos"])
            if checked.get("epochLimit") is not None:
                expiry = min(expiry, checked["epochLimit"])

            def current():
                nonlocal lower, wall
                self._origin(); self._policy.check(self._process); self._process.check_request(request)
                inp.check_identity(); approval.check_identity()
                now, epoch = originals._clock(), time.time_ns()
                p.require(lower <= now < deadline and wall <= epoch < expiry)
                lower, wall = now, epoch

            inp.check(); approval.check(); current()
            try:
                reply = installation.install_adopted(request.raw, approval.raw, inp.raw,
                    approval_sha256=approval.sha, input_sha256=inp.sha, check=current)
            except installation.AdoptedInstallationError as error:
                self._installations.append(error.owner)
                raise
            inp.check(); approval.check(); current()
            # The channel's positive-write transaction retains its own exact
            # originals. Signal masking keeps local one-use bookkeeping joined.
            with ownership.owning():
                self._process.reply(request, reply)
                if job.name == "stop":
                    p.require(request.phase == "shutdown" and self._stop_admission is None)
                    self._stop_admission = (inp, admission_clocks)
                self._index += 1
                self._pending = None
            self._policy.check(self._process)
            p.require(lower <= originals._clock() < deadline and wall <= time.time_ns() < expiry)
            self._failed = False
            return {"phase": request.phase, "job": request.job, "sequence": request.sequence,
                "inputSha256": inp.sha, "approvalSha256": approval.sha,
                "status": "approval-installed-and-replied"}
        except BaseException as error:
            raise SupervisorError(self) from error

    def close(self, *, cancel=False):
        self._origin()
        self._failed = True
        result = self._process.close(cancel=cancel)
        if result["status"] == "cleanup-unknown-owner-retained":
            return result
        p.require(result["status"] in ("not-started", "stopped-cleanup-complete", "failed-cleanup-complete"))
        transcript_success = result["status"] == "stopped-cleanup-complete" and not cancel
        if transcript_success:
            p.require(self._index == len(SUPPORTED_JOBS) and self._pending is None
                and self._stop_admission is not None)
            source, admitted = self._stop_admission
            source.check()
            terminal = p.document(self._process.completion_original(), 4096)
            final = terminal["finalResult"]
            p.require(final["inputSha256"] == source.sha)
            actual = p.document(final["resultOriginal"].encode("ascii"), profile.BY_NAME["stop"][1].maximum)
            # Replay the exact full public admission at its recorded actual
            # clocks. Re-admitting now would wrongly demand now < an already
            # ended interactive stop time. Current terminal caps/interval facts
            # are separately enforced by the actual process completion owner.
            profile.checked_result("stop", source.raw, actual, phase="shutdown", prior=self._prior,
                observations=self._observations, **admitted)
            self._prior["stop"] = {"input": source.raw, "result": actual}
            self._process.completion_original()  # Final current original-clock check.
        for owner in self._installations:
            owner.close()
        for original in self._retained:
            original.close()
        self._policy.close()
        self._closed = True
        if transcript_success: self._process.completion_original()
        return result
