"""Install an independently approved fixed job's literal input/approval pair.

The request is observation data, not a live process owner or approval. The
independent supervisor must supply the complete approval and authenticated byte
pins after the actual prior result exists. This module makes no approval,
signature, key, service, parent directory or new deadline. It publishes the
input first and approval last, then returns the existing bound reply. Partial
files remain on failure; neither rollback nor another attempt is authorized.
"""
from __future__ import annotations

import os
import stat
import time

from scripts.authority import native_pilot_authority_io as io
from catchplate import native_pilot_publication as publication
from catchplate import native_shadow_nitro_originals as originals
from catchplate import native_shadow_nitro_profile as p
from catchplate.native_pilot_genesis_parent_control_io import owning
from catchplate.native_pilot_operator_channel import MAX_FRAME, STAGES
from catchplate.native_pilot_phase_execution import APPROVAL_ROOT, JOBS, MAX_APPROVAL, MAX_RETAINED_BYTES
from catchplate.native_shadow_proof_cohort_control import _Original

MAX_REQUEST = MAX_FRAME - 1
MAX_INPUT = max(job.maximum for jobs in JOBS.values() for job in jobs)
_ORDER = tuple((phase, job) for phase in STAGES for job in JOBS[phase])
_ATTEMPTED = set()
_BYTES = 0
_FAILED = False


def _same(first, second):
    p.require(p.canonical(first) == p.canonical(second))


def _prepare(request_raw, approval_raw, input_raw, approval_sha256, input_sha256):
    request = p.fields(p.document(request_raw, MAX_REQUEST), (
        "apiVersion", "sequence", "conductorSequence", "conductorRequestSha256", "phase",
        "jobIndex", "job", "deadlineBoottimeNs", "conductorRequest", "previousResult"))
    p.require(request["apiVersion"] == "catchplate.nativePilotAuthorityJobRequest/v1"
        and tuple(JOBS) == STAGES and type(request["phase"]) is str and request["phase"] in JOBS)
    phase = request["phase"]
    phase_index = STAGES.index(phase)
    p.require(p.integer(request["conductorSequence"], maximum=len(STAGES)) == phase_index + 1)
    job_index = p.integer(request["jobIndex"], maximum=len(JOBS[phase])) - 1
    job = JOBS[phase][job_index]
    sequence = sum(len(JOBS[name]) for name in STAGES[:phase_index]) + job_index + 1
    p.require(p.integer(request["sequence"], maximum=len(_ORDER)) == sequence
        and request["job"] == job.name)
    p.digest(request["conductorRequestSha256"])
    deadline = p.ns(request["deadlineBoottimeNs"])
    if job_index == 0:
        conductor = p.fields(request["conductorRequest"],
            ("apiVersion", "sequence", "phase", "payload", "deadlineBoottimeNs"))
        p.require(conductor["apiVersion"] == "catchplate.nativePilotOperatorRequest/v1"
            and type(conductor["payload"]) is dict
            and p.sha(p.canonical(conductor)) == request["conductorRequestSha256"])
        for target, source in (("sequence", "conductorSequence"), ("phase", "phase"),
                               ("deadlineBoottimeNs", "deadlineBoottimeNs")):
            _same(conductor[target], request[source])
    else:
        p.require(request["conductorRequest"] is None)
    if sequence == 1:
        p.require(request["previousResult"] is None)
    else:
        previous = p.fields(request["previousResult"], ("phase", "job", "result"))
        prior_phase, prior_job = _ORDER[sequence - 2]
        p.require(previous["phase"] == prior_phase and previous["job"] == prior_job.name
            and type(previous["result"]) is dict)
    p.document(input_raw, job.maximum)
    approval = p.fields(p.document(approval_raw, MAX_APPROVAL), ("apiVersion", "conductorSequence",
        "conductorRequestSha256", "phase", "jobIndex", "job", "deadlineBoottimeNs", "inputSha256"))
    p.require(approval["apiVersion"] == "catchplate.nativePilotAuthorityJobApproval/v1"
        and p.sha(approval_raw) == p.digest(approval_sha256)
        and p.sha(input_raw) == p.digest(input_sha256)
        and approval["inputSha256"] == input_sha256)
    for name in ("conductorSequence", "conductorRequestSha256", "phase", "jobIndex", "job", "deadlineBoottimeNs"):
        _same(approval[name], request[name])
    p.require(originals._clock() < deadline)
    return request, job, deadline


class _Pair:
    """Only the two fixed names, with actual retained parents and originals."""

    def __init__(self, phase, deadline):
        self._pid, self._boot = os.getpid(), originals._boot()
        self._deadline, self._previous = deadline, originals._clock()
        self._paths = ("/", "/etc", "/etc/catchplate", APPROVAL_ROOT, APPROVAL_ROOT + "/" + phase)
        self._roots, self._files, self._pending = {}, [], []

    def open(self):
        io._process()
        for path in self._paths:
            with owning():
                if path == "/":
                    fd = os.open(path, publication._FLAGS | os.O_DIRECTORY)
                else:
                    parent, name = path.rsplit("/", 1)
                    fd = os.open(name, publication._FLAGS | os.O_DIRECTORY,
                        dir_fd=self._roots[parent or "/"][0])
                self._pending.append(fd)
                info = os.fstat(fd)
                publication._protected(info)
                self._roots[path] = (fd, publication._structural(info))
                self._pending.remove(fd)
        self.check()

    def check(self):
        io._process()
        now = originals._clock()
        p.require(os.getpid() == self._pid and originals._boot() == self._boot
            and self._previous <= now < self._deadline)
        self._previous = now
        for path, (fd, expected) in self._roots.items():
            actual = os.fstat(fd)
            publication._protected(actual)
            if path == "/":
                named = os.stat(path, follow_symlinks=False)
            else:
                parent, name = path.rsplit("/", 1)
                named = os.stat(name, dir_fd=self._roots[parent or "/"][0], follow_symlinks=False)
            p.require(publication._structural(actual) == expected == publication._structural(named)
                and not os.get_inheritable(fd))
        for original in self._files:
            original.check()

    def require_absent(self, job):
        self.check()
        for suffix in (".input.json", ".approval.json"):
            try:
                os.stat(job.name + suffix, dir_fd=self._roots[self._paths[-1]][0], follow_symlinks=False)
            except FileNotFoundError:
                continue
            raise ValueError("native pilot job destination already exists")
        self.check()

    def publish(self, name, raw, maximum, digest):
        self.check()
        parent = self._roots[self._paths[-1]][0]
        with owning():
            fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                0o400, dir_fd=parent)
            self._pending.append(fd)
        info = os.fstat(fd)
        p.require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0
            and info.st_nlink == 1 and info.st_size == 0)
        os.fchmod(fd, 0o400)  # Only the new exclusive file, never a parent or existing original.
        offset = 0
        while offset < len(raw):
            self.check()
            count = os.pwrite(fd, raw[offset:offset + 65536], offset)
            p.require(count > 0)
            offset += count
        os.fsync(fd)
        self.check()
        p.require(os.pread(fd, maximum + 1, 0) == raw)
        written = os.fstat(fd)
        p.require(stat.S_IMODE(written.st_mode) == 0o400 and written.st_nlink == 1
            and written.st_size == len(raw) and publication._file_identity(written)
            == publication._file_identity(os.stat(name, dir_fd=parent, follow_symlinks=False)))
        with owning():
            self._pending.remove(fd)
            os.close(fd)
        os.fsync(parent)
        with owning():
            original = _Original(self._paths[-1] + "/" + name, maximum, digest, mode=0o400)
            self._files.append(original)
        p.require(original.raw == raw and publication._file_identity(os.fstat(original.fd))
            == publication._file_identity(written))
        self.check()

    def close(self):
        # This owner holds no child/resource lifetime. Keep all names/partials;
        # the real coordinator independently acquires its own retained originals.
        for original in reversed(self._files):
            original.close()
        for fd in reversed(self._pending):
            os.close(fd)
        for fd, _ in reversed(tuple(self._roots.values())):
            os.close(fd)


def install(request_original: bytes, approval_original: bytes, input_original: bytes, *,
            approval_sha256: str, input_sha256: str) -> dict:
    """Return the existing reply only after actual input-first pair publication.

    Pins must be independently authenticated by the supervisor. Matching hashes,
    protected files, and this reply do not supply an independent decision or
    prove a live pending request. The actual channel/executor checks that join.
    """
    global _FAILED, _BYTES
    p.require(not _FAILED)
    _FAILED = True  # Any refused or partial call permanently fences this process.
    io._process()
    request, job, deadline = _prepare(request_original, approval_original, input_original,
        approval_sha256, input_sha256)
    slot = (request["phase"], job.name)
    p.require(slot not in _ATTEMPTED and len(_ATTEMPTED) < len(_ORDER)
        and _BYTES + len(approval_original) + len(input_original) <= MAX_RETAINED_BYTES)
    _ATTEMPTED.add(slot)
    _BYTES += len(approval_original) + len(input_original)
    owner = _Pair(request["phase"], deadline)
    try:
        owner.open()
        owner.require_absent(job)
        owner.publish(job.name + ".input.json", input_original, job.maximum, input_sha256)
        owner.publish(job.name + ".approval.json", approval_original, MAX_APPROVAL, approval_sha256)
        owner.check()
        reply = {"apiVersion": "catchplate.nativePilotAuthorityJobReply/v1",
            **{name: request[name] for name in ("sequence", "conductorSequence", "conductorRequestSha256",
                                               "phase", "jobIndex", "job")},
            "requestSha256": p.sha(request_original), "approvalSha256": approval_sha256,
            "inputSha256": input_sha256}
    finally:
        owner.close()
    _FAILED = False
    return reply


# Separate namespace/state: legacy Approval1 never selects this catalogue.
_ADOPTED_ATTEMPTED, _ADOPTED_OWNERS = set(), []
_ADOPTED_BYTES = 0
_ADOPTED_FAILED = False


def _prepare_adopted(request_raw, approval_raw, input_raw, approval_sha256, input_sha256,
                     *, now_boottime_ns=None, now_unix_ns=None):
    from catchplate import native_pilot_adopted_phase_profile as selected
    request = p.fields(p.document(request_raw, MAX_REQUEST), selected.REQUEST_FIELDS)
    p.require(request["apiVersion"] == selected.API and request["phase"] in selected.JOBS)
    phases, phase = tuple(selected.JOBS), request["phase"]
    phase_index = phases.index(phase)
    index = p.integer(request["jobIndex"], maximum=len(selected.JOBS[phase])) - 1
    job = selected.JOBS[phase][index]
    sequence = sum(len(selected.JOBS[name]) for name in phases[:phase_index]) + index + 1
    p.require(request["conductorSequence"] == phase_index + 1
        and type(request["sequence"]) is int and request["sequence"] == sequence
        and request["job"] == job.name)
    p.digest(request["conductorRequestSha256"])
    deadline, expiry = p.ns(request["deadlineBoottimeNs"]), p.ns(request["expiresAtUnixNanos"])
    p.integer(expiry, maximum=p.MAX_I64)
    if index == 0:
        conductor = p.fields(request["conductorRequest"], ("apiVersion", "sequence", "phase", "payload",
            "deadlineBoottimeNs", "expiresAtUnixNanos"))
        p.require(conductor["apiVersion"] == "catchplate.nativePilotOperatorRequest/v2"
            and type(conductor["payload"]) is dict and p.sha(p.canonical(conductor)) == request["conductorRequestSha256"])
        for target, source in (("sequence", "conductorSequence"), ("phase", "phase"),
                ("deadlineBoottimeNs", "deadlineBoottimeNs"), ("expiresAtUnixNanos", "expiresAtUnixNanos")):
            _same(conductor[target], request[source])
    else:
        p.require(request["conductorRequest"] is None)
    if sequence == 1:
        p.require(request["previousResult"] is None)
    else:
        order = tuple((name, row.name) for name, rows in selected.JOBS.items() for row in rows)
        previous = p.fields(request["previousResult"], ("phase", "job", "result"))
        p.require((previous["phase"], previous["job"]) == order[sequence - 2]
            and type(previous["result"]) is dict)
    p.document(input_raw, job.maximum)
    approval = p.fields(p.document(approval_raw, selected.MAX_APPROVAL), selected.APPROVAL_FIELDS)
    p.require(approval["apiVersion"] == selected.APPROVAL_API
        and p.sha(approval_raw) == p.digest(approval_sha256)
        and p.sha(input_raw) == p.digest(input_sha256) == approval["inputSha256"])
    for name in selected.APPROVAL_FIELDS[1:-1]:
        _same(approval[name], request[name])
    now = originals._clock() if now_boottime_ns is None else now_boottime_ns
    epoch = time.time_ns() if now_unix_ns is None else now_unix_ns
    p.require(now < deadline and epoch < expiry)
    return request, job, deadline, expiry


class AdoptedInstallationError(ValueError):
    def __init__(self, owner):
        super().__init__("adopted approval installation refused; partial public files retained")
        self.owner = owner


class _AdoptedPair(_Pair):
    def __init__(self, phase, deadline, expiry, check):
        from catchplate import native_pilot_adopted_phase_profile as selected
        super().__init__(phase, deadline)
        self._paths = ("/", "/etc", "/etc/catchplate", selected.APPROVAL_ROOT,
            selected.APPROVAL_ROOT + "/" + phase)
        self._expiry, self._wall, self._outer = expiry, time.time_ns(), check
        self._closed = False

    def check(self):
        p.require(not self._closed)
        self._outer()
        super().check()
        now, epoch = originals._clock(), time.time_ns()
        p.require(self._previous <= now < self._deadline and self._wall <= epoch < self._expiry)
        self._previous, self._wall = now, epoch

    def close(self):
        from catchplate.native_pilot_genesis_parent_control_io import owning
        p.require(os.getpid() == self._pid and originals._boot() == self._boot)
        if self._closed:
            return
        with owning():
            while self._files:
                original = self._files.pop()
                while original.fds:
                    os.close(original.fds.pop())
                original.fd = -1
            while self._pending:
                os.close(self._pending.pop())
            while self._roots:
                path = next(reversed(self._roots))
                os.close(self._roots.pop(path)[0])
            self._closed = True


def install_adopted(request_original, approval_original, input_original, *,
                    approval_sha256, input_sha256, check):
    """Only install supplied independent Approval2; this never makes one."""
    from catchplate import native_pilot_adopted_phase_profile as selected
    global _ADOPTED_BYTES, _ADOPTED_FAILED
    p.require(not _ADOPTED_FAILED and callable(check))
    _ADOPTED_FAILED = True
    io._process(); check()
    request, job, deadline, expiry = _prepare_adopted(request_original, approval_original,
        input_original, approval_sha256, input_sha256)
    slot = (request["phase"], job.name)
    p.require(slot not in _ADOPTED_ATTEMPTED
        and _ADOPTED_BYTES + len(input_original) + len(approval_original) <= selected.MAX_RETAINED_BYTES)
    _ADOPTED_ATTEMPTED.add(slot)
    _ADOPTED_BYTES += len(input_original) + len(approval_original)
    owner = _AdoptedPair(request["phase"], deadline, expiry, check)
    _ADOPTED_OWNERS.append(owner)
    try:
        owner.open(); owner.require_absent(job)
        owner.publish(job.name + ".input.json", input_original, job.maximum, input_sha256)
        owner.publish(job.name + ".approval.json", approval_original, selected.MAX_APPROVAL, approval_sha256)
        owner.check()
        reply = {"apiVersion": selected.REPLY_API, **{name: request[name] for name in
            ("sequence", "conductorSequence", "conductorRequestSha256", "phase", "jobIndex", "job")},
            "requestSha256": p.sha(request_original), "approvalSha256": approval_sha256,
            "inputSha256": input_sha256}
        owner.close(); check()
        p.require(originals._clock() < deadline and time.time_ns() < expiry)
        _ADOPTED_FAILED = False
        return reply
    except BaseException as error:
        raise AdoptedInstallationError(owner) from error
