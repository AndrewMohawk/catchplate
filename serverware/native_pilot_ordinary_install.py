"""Fixed public ordinary-service files from a genuine prepared supervisor owner.

Only the retained composer's deterministic runtime originals and the actual
initial-history results may reach this writer. Private credentials are never
opened, copied or created. All fifteen destinations are absent before writes;
partial files/descriptors remain retained until actual process cleanup. This
is public-input preparation, not approval, native admission or live readiness.
Blocking filesystem calls still require the independent process watchdog.
"""
from __future__ import annotations

import copy
import os
import stat
import threading

from serverware import custody_generation_grants as g
from serverware import custody_generation_originals as files
from serverware import native_pilot_ordinary_initial_profile as initial
from serverware import native_pilot_ordinary_runtime_profile as runtime_profile
from serverware.native_pilot_ordinary_runtime_recipe import INSPECTION_PATHS, RUNTIME_PATHS
from serverware import native_pilot_precreation_install as precreation
from serverware import native_pilot_supervisor_initial_history as histories
from serverware import native_shadow_nitro_originals as originals
from serverware.native_pilot_phase_execution import INITIAL_JOBS, JOBS, KEY_AUTHORIZATION_JOBS
from serverware.native_shadow_proof_cohort_assignment import ENDPOINT_ROLES

p = g.p
MAX_RUNTIME = MAX_HISTORY = g.MAX_BYTES
MAX_INSPECTION = 4096
MAX_TOTAL_BYTES = 32 * 1024 * 1024
INITIAL_CREDENTIAL_PATHS = initial.INITIAL_CREDENTIAL_PATHS
_ROOTS = ("/", "/etc", "/etc/serverware")
_FLAGS = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
_TOKEN = object()
_USED = False
_LIVE = None
_NATIVE_FIRST_INDEX = len(INITIAL_JOBS) + 2 * len(g.ROLES) + 1
_NATIVE_COMPLETED_JOBS = tuple("native-delivery-" + role for role in ENDPOINT_ROLES
    if role not in ("retrieval", "persistence", "trustedTime")) + tuple(
        job.name for job in KEY_AUTHORIZATION_JOBS) + tuple("native-service-" + operation for operation in
            ("commitRequest", "ingress", "ledger", "terminal", "dispatchBarrier", "activeEffectBarrier",
             "activeEffectCommit", "retrieval", "persistence", "trustedTime")) + (
                "native-generation-install-grant", "ordinary-dispatch-durable-recovery-store",
                "ordinary-dispatch-current-signature-authority", "ordinary-head", "ordinary-cleanup",
                "ordinary-current", "install-launch-retrieval")


def native_completed_boundary(request):
    """Fixed read-only continuation predicate; never an owner or approval."""
    if request.phase != "service-originals" or type(request.job_index) is not int:
        return False
    index = request.job_index - _NATIVE_FIRST_INDEX
    return (0 <= index < len(_NATIVE_COMPLETED_JOBS)
        and request.job == _NATIVE_COMPLETED_JOBS[index]
        and tuple(job.name for job in JOBS["service-originals"][_NATIVE_FIRST_INDEX - 1:
            _NATIVE_FIRST_INDEX - 1 + len(_NATIVE_COMPLETED_JOBS)]) == _NATIVE_COMPLETED_JOBS)


def plan(*, runtime_originals, history_originals, cold_originals, launch_original):
    """Pure fifteen-file plan; no input dictionary establishes a live owner."""
    for values in (runtime_originals, history_originals, cold_originals):
        p.fields(values, g.ROLES)
    launch = p.fields(g.document(launch_original, 65536), ("apiVersion", "bootIdBase64url",
        "timeNamespaceDevice", "timeNamespaceInode", "startupDeadlineBoottimeNs",
        "lifetimeDeadlineBoottimeNs", "invocationId", "services"))
    p.require(launch["apiVersion"] == "serverware.custodyFiveServiceLaunch/v6")
    p.fields(launch["services"], g.ROLES)
    planned = []
    for role in g.ROLES:
        runtime_raw, history_raw, cold_raw = runtime_originals[role], history_originals[role], cold_originals[role]
        p.require(type(runtime_raw) is bytes and 0 < len(runtime_raw) <= MAX_RUNTIME
            and type(history_raw) is bytes and 0 < len(history_raw) <= MAX_HISTORY)
        cold = g.configuration(cold_raw, launch["services"][role]["deliveryConfiguration"]["sha256"], role)
        runtime = runtime_profile.validate_runtime(role, runtime_raw)
        header = runtime["runtime"]
        p.require(header["authorityHistoryManifestCredential"] == "authority-history")
        wrapper = p.fields(g.document(history_raw, MAX_HISTORY), initial.WRAPPER_FIELDS)
        p.require(wrapper["apiVersion"] == initial.WRAPPER_API)
        history = initial.manifest(history_raw, role=role, root_pin={
            "keyId": header["authorityHistoryRootKeyId"],
            "keySpkiSha256": header["authorityHistoryRootKeySpkiSha256"]})
        state = wrapper["initialState"]
        identity = history["firstRetainedEpoch"]["retainedEpoch"]["endpointProcessIdentity"]
        p.require((identity["endpointUid"], identity["endpointGid"]) == (cold["uid"], cold["gid"])
            and state["launchSha256"] == p.sha(launch_original)
            and header["authorityHistoryManifestSha256"] == history["manifestSha256"]
            and header["serviceRestartEpoch"] == state["serviceGeneration"]
            and header["operationGeneration"] == state["operationGeneration"]
            and header["deploymentGenerationSha256"] == state["deploymentGenerationSha256"]
            and header["activationDirectoryIdentities"]
                == {name: item["identity"] for name, item in state["directories"].items()})
        for name in ("bootIdBase64url", "timeNamespaceDevice", "timeNamespaceInode",
                "startupDeadlineBoottimeNs", "lifetimeDeadlineBoottimeNs", "invocationId"):
            p.require(state[name] == launch[name])
        inspection = g.canonical({"apiVersion": "serverware.custodyOrdinaryPeerInspection/v1",
            "purpose": "ordinary-service-peer-inspection", "runtimeConfigurationSha256": p.sha(runtime_raw),
            "serviceRole": role, "uid": cold["uid"], "gid": cold["gid"],
            "startupDeadlineBoottimeNs": launch["startupDeadlineBoottimeNs"],
            "lifetimeDeadlineBoottimeNs": launch["lifetimeDeadlineBoottimeNs"]})
        p.require(len(inspection) <= MAX_INSPECTION)
        for kind, path, raw, uid, gid in (
                ("runtime", RUNTIME_PATHS[role], runtime_raw, 0, 0),
                ("history", INITIAL_CREDENTIAL_PATHS[role], history_raw, cold["uid"], cold["gid"]),
                ("inspection", INSPECTION_PATHS[role], inspection, cold["uid"], cold["gid"])):
            planned.append(dict(role=role, kind=kind, path=path, raw=raw, uid=uid, gid=gid, mode=0o400))
    p.require(len(planned) == len({item["path"] for item in planned}) == 15
        and sum(len(item["raw"]) for item in planned) <= MAX_TOTAL_BYTES)
    return tuple(planned)


def _types(policy, process, request):
    from serverware.native_pilot_supervisor_policy import SupervisorPolicy
    from serverware.native_pilot_supervisor_process import AuthorityCoordinatorProcess, JobRequest
    p.require(type(policy) is SupervisorPolicy and type(process) is AuthorityCoordinatorProcess
        and type(request) is JobRequest)


def _protected(info):
    p.require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0
        and not info.st_mode & 0o022 and info.st_mode & 0o001)


class _Installation:
    def __init__(self, token, policy, process, request):
        p.require(token is _TOKEN)
        self.policy, self.process, self.request = policy, process, request
        self.pid, self.boot = os.getpid(), originals._boot()
        self.deadline = request.deadline_boottime_ns
        self.phase_sha = request.value["conductorRequestSha256"]
        self.previous = 0
        self.roots, self.opened, self.pending, self.files = {}, [], [], {}
        self.planned, self.metadata = (), {}
        self.complete = self.failed = self.closed = self.close_attempted = False

    def check(self, policy, process, request):
        _types(policy, process, request)
        p.require(_LIVE is self and self.policy is policy and self.process is process
            and not self.failed and not self.closed and os.getpid() == self.pid
            and threading.current_thread() is threading.main_thread()
            and os.getresuid() == (0, 0, 0) and os.getresgid() == (0, 0, 0)
            and originals._boot() == self.boot)
        policy.check(process); process.check_request(request)
        offset = request.job_index - len(INITIAL_JOBS) - 1
        delivery = (0 <= offset < len(g.ROLES)
            and request.job == "ordinary-delivery-" + g.ROLES[offset])
        generation_offset = offset - len(g.ROLES)
        generation_job = (0 <= generation_offset < len(g.ROLES)
            and request.job == "ordinary-generation-" + g.ROLES[generation_offset])
        completed_boundary = self.complete and (generation_job or native_completed_boundary(request))
        p.require(request.phase == "service-originals" and (delivery or completed_boundary)
            and JOBS[request.phase][request.job_index - 1].name == request.job
            and request.deadline_boottime_ns == self.deadline
            and request.value["conductorRequestSha256"] == self.phase_sha)
        now = originals._clock()
        p.require(self.previous <= now < self.deadline)
        self.previous, self.request = now, request
        for path, (fd, expected) in self.roots.items():
            actual = os.fstat(fd); _protected(actual)
            parent, name = path.rsplit("/", 1)
            named = os.stat(path, follow_symlinks=False) if path == "/" else os.stat(
                name, dir_fd=self.roots[parent or "/"][0], follow_symlinks=False)
            p.require(files.structural(actual) == expected == files.structural(named)
                and not os.get_inheritable(fd))
        for path, original in self.files.items():
            original.check()
            p.require(files.identity(os.stat(path.rsplit("/", 1)[1],
                dir_fd=self.roots["/etc/serverware"][0], follow_symlinks=False)) == original.expected)

    def inputs(self, role):
        self.check(self.policy, self.process, self.request)
        p.require(self.complete and role in g.ROLES)
        return copy.deepcopy(self.metadata[role])

    def _preflight(self):
        self.check(self.policy, self.process, self.request)
        for path in _ROOTS:
            parent, name = path.rsplit("/", 1)
            fd = os.open(path, _FLAGS | os.O_DIRECTORY) if path == "/" else os.open(
                name, _FLAGS | os.O_DIRECTORY, dir_fd=self.roots[parent or "/"][0])
            self.opened.append(fd)
            info = os.fstat(fd); _protected(info)
            self.roots[path] = fd, files.structural(info)
        self.check(self.policy, self.process, self.request)
        for item in self.planned:
            try:
                os.stat(item["path"].rsplit("/", 1)[1],
                    dir_fd=self.roots["/etc/serverware"][0], follow_symlinks=False)
            except FileNotFoundError:
                continue
            raise ValueError("ordinary public input destination already exists")
        self.check(self.policy, self.process, self.request)

    def _publish(self, item):
        self.check(self.policy, self.process, self.request)
        parent = self.roots["/etc/serverware"][0]
        path, raw = item["path"], item["raw"]
        name = path.rsplit("/", 1)[1]
        fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
            | os.O_NOFOLLOW | os.O_NONBLOCK, 0o400, dir_fd=parent)
        self.pending.append(fd)
        info = os.fstat(fd)
        p.require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0
            and info.st_nlink == 1 and info.st_size == 0)
        offset = 0
        while offset < len(raw):
            self.check(self.policy, self.process, self.request)
            count = os.pwrite(fd, raw[offset:offset + 65536], offset)
            p.require(count > 0); offset += count
        p.require(files.identity(os.stat(name, dir_fd=parent, follow_symlinks=False))
            == files.identity(os.fstat(fd)))
        # Ownership changes apply only to this newly/exclusively created inode.
        os.fchown(fd, item["uid"], item["gid"])
        os.fchmod(fd, item["mode"])
        os.fsync(fd); os.fsync(parent)
        written = files.identity(os.fstat(fd))
        original = files.Original(path, len(raw), uid=item["uid"], gid=item["gid"])
        self.files[path] = original  # Retain before content read or hash work.
        original.sha = p.sha(raw)
        p.require(original.expected == written and original.read() == raw)
        self.check(self.policy, self.process, self.request)
        os.close(fd); self.pending.remove(fd)
        pin = {"path": path, "sha256": original.sha}
        row = self.metadata.setdefault(item["role"], {})
        if item["kind"] == "runtime":
            row["runtimeConfig"] = pin
        else:
            name = "authority-history" if item["kind"] == "history" else "peer-inspection-policy"
            row[item["kind"] + "Credential"] = dict(name=name, original=pin, length=len(raw), signing=None)


def prepare(policy, *, process, request):
    """One fixed installation at the genuine first ordinary-delivery request."""
    global _USED, _LIVE
    _types(policy, process, request)
    p.require(not _USED and _LIVE is None and request.phase == "service-originals"
        and request.job_index == len(INITIAL_JOBS) + 1
        and request.job == "ordinary-delivery-" + g.ROLES[0])
    _USED = True
    owner = _Installation(_TOKEN, policy, process, request)
    _LIVE = owner  # Keep the real owner even if acquisition or a partial write fails.
    try:
        owner.check(policy, process, request)
        # Only this getter's actual retained composer can supply deterministic
        # runtime originals. A caller cannot hand a dictionary to the writer.
        from serverware import native_pilot_supervisor_ordinary_deliveries as composer
        runtime_originals = composer.prepared_runtime_originals(policy, process=process, request=request)
        result = histories.require_histories(policy, process=process, request=request)
        history_originals = {role: result[role]["original"].encode("ascii") for role in g.ROLES}
        installed_raw = process.approved_input_original("endpoint-precreation", "install-precreation")
        p.require(p.sha(installed_raw) == process.approved_input_sha256("endpoint-precreation", "install-precreation"))
        installed = p.fields(p.document(installed_raw, precreation.MAX_INPUT), precreation.FIELDS)
        cold_originals = {role: installed["ordinaryColdOriginals"][role].encode("ascii") for role in g.ROLES}
        owner.planned = plan(runtime_originals=runtime_originals, history_originals=history_originals,
            cold_originals=cold_originals, launch_original=installed["ordinaryLaunchOriginal"].encode("ascii"))
        owner._preflight()
        for item in owner.planned:
            owner._publish(item)
        owner.check(policy, process, request)
        p.require(len(owner.files) == 15)
        for row in owner.metadata.values():
            p.fields(row, ("runtimeConfig", "historyCredential", "inspectionCredential"))
        owner.complete = True
        return owner
    except BaseException:
        owner.failed = True
        raise


def close(process):
    """Descriptor retirement only after actual terminal cleanup; no file removal."""
    global _LIVE
    if _LIVE is None:
        return
    from serverware.native_pilot_supervisor_process import AuthorityCoordinatorProcess
    owner = _LIVE
    p.require(type(process) is AuthorityCoordinatorProcess and owner.process is process
        and os.getpid() == owner.pid and process._closed and not owner.close_attempted
        and process._result["status"] in ("not-started", "stopped-cleanup-complete", "failed-cleanup-complete"))
    owner.close_attempted = True
    for original in reversed(tuple(owner.files.values())):
        original.close()
    while owner.pending:
        os.close(owner.pending[-1]); owner.pending.pop()
    while owner.opened:
        os.close(owner.opened[-1]); owner.opened.pop()
    owner.closed = True
    owner.planned, owner.metadata = (), {}
    _LIVE = None
