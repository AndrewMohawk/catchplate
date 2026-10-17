"""Commission fixed endpoint inputs from the actual retained supervisor owners.

The admitted policy supplies the empty directory and peer expectations; the
retained measured recipe supplies the signed assignment and run-specific scope.
Only actual process-owned observations supply peer process/executable facts.
This freezes an already provisioned empty directory and publishes four public
originals. It creates no receipts, genesis, keys, grant, approval or live owner.
Partial state and descriptors remain retained until actual process cleanup.
"""
from __future__ import annotations

import copy
import fcntl
import os
import stat
import time

from catchplate import custody_generation_grants as generation
from catchplate import native_pilot_assignment as assignment_profile
from catchplate import native_pilot_delivery_authority as c9
from catchplate import native_pilot_driver_authority as driver_authority
from catchplate import native_pilot_precreation_install as installation
from catchplate import native_pilot_publication as publication
from catchplate import native_pilot_scope_authority as scope
from catchplate import native_pilot_supervisor_precreation as precreation
from catchplate import native_shadow_constructed_driver as admission
from catchplate import native_shadow_endpoint_driver as external_driver
from catchplate import native_shadow_nitro_originals as originals
from catchplate import native_shadow_proof_cohort_assignment as cohort
from catchplate import native_shadow_retrieval_artifacts as retrieval
from catchplate import native_shadow_retrieval_store as store
from catchplate.native_pilot_service_inputs import ENDPOINT_INPUT_ROLES
from catchplate.native_shadow_proof_cohort_control import _Original

p = c9.p
PURPOSES = ("endpoint-peer", "endpoint-proof-scope", "endpoint-retrieval-manifest", "endpoint-assignment")
INPUT_FIELDS = ("coldOriginals", "peer", "proofScope", "retrievalManifest", "objectDirectory", "assignment", "production")
OBSERVATION_FIELDS = ("cohortObservationOriginal", "ordinaryParked", "ordinaryActivations", "ordinaryDirectories",
    "nativeActivations", "bridgeJournal")
_USED = False
_LIVE = None


def _same(first, second):
    p.require(p.canonical(first) == p.canonical(second))


def _actual(policy, process, request):
    from catchplate.native_pilot_supervisor_policy import SupervisorPolicy
    from catchplate.native_pilot_supervisor_process import AuthorityCoordinatorProcess, JobRequest
    p.require(type(policy) is SupervisorPolicy and type(process) is AuthorityCoordinatorProcess and type(request) is JobRequest)
    policy.check(process); process.check_request(request)


def _phase(process, name):
    value = p.fields(process.conductor_request(name),
        ("apiVersion", "sequence", "phase", "payload", "deadlineBoottimeNs"))
    p.require(value["apiVersion"] == "catchplate.nativePilotOperatorRequest/v1" and value["phase"] == name)
    p.ns(value["deadlineBoottimeNs"])
    return value


def _prior(policy, process):
    """Authenticate prior complete approved bytes and their actual results."""
    raw = process.approved_input_original("endpoint-precreation", "install-precreation")
    digest = process.approved_input_sha256("endpoint-precreation", "install-precreation")
    planned, window, ordinary = installation._prepare(raw, digest)
    bundle = p.document(raw, installation.MAX_INPUT)
    bootstrap = policy.bootstrap_originals()
    retained = process.bootstrap_originals()
    p.require(all(retained[name] == original for name, original in bootstrap.items()))
    for name in ("configuration", "window"):
        p.require(bundle["driver" + name.title() + "Original"] == bootstrap[name].decode("ascii"))
    early = _phase(process, "bootstrap-admission")
    early_payload = p.fields(early["payload"], ("bootstrapObservationOriginal", "admissionPayloadOriginal"))
    p.require(bundle["driverObservationOriginal"] == early_payload["bootstrapObservationOriginal"])
    observed_raw, _ = scope._original(bundle["driverObservationOriginal"], 65536)
    control = p.document(bootstrap["control"], 4096)
    driver_config = p.document(bootstrap["configuration"], 65536)
    observed = driver_authority._observation(observed_raw, control, driver_config, window, originals._clock())
    approved_bootstrap = process.approved_input_original("bootstrap-admission", "driver-bootstrap")
    p.require(approved_bootstrap == policy.bootstrap_input_original())
    expected_bootstrap = {"apiVersion": "catchplate.nativePilotDriverAuthorityInput/v1", "operation": "bootstrap",
        **{name + "Original": original.decode("ascii") for name, original in bootstrap.items()},
        "observationOriginal": observed_raw.decode("ascii"), "payloadOriginal": early_payload["admissionPayloadOriginal"]}
    p.require(approved_bootstrap == p.canonical(expected_bootstrap))
    prior_bootstrap = p.fields(process.prior_result("bootstrap-admission", "driver-bootstrap"), ("original", "sha256", "pin"))
    signed_raw, signed = scope._original(prior_bootstrap["original"], 8192)
    p.require(p.sha(signed_raw) == p.digest(prior_bootstrap["sha256"]))
    _same(prior_bootstrap["pin"], {"path": publication.DESTINATIONS["driver-bootstrap-admission"], "sha256": p.sha(signed_raw)})
    p.fields(signed, ("payload", "signature"))
    payload_raw, _ = scope._original(early_payload["admissionPayloadOriginal"], 8192)
    p.require(p.canonical(signed["payload"]) == payload_raw)
    authority = driver_config["lifecycle"]["constructedAdmissionAuthority"]
    admission.authority(authority).verify(p.decoded(signed["signature"], size=64),
        p.preimage(admission.BOOTSTRAP_DOMAIN, signed["payload"]))
    driver_authority._bootstrap(signed["payload"], observed_raw, control, window, authority)
    p.freshness(signed["payload"]["issuedAtUnixNanos"], signed["payload"]["expiresAtUnixNanos"], time.time_ns(), 30_000_000_000)
    previous = _phase(process, "endpoint-precreation")
    previous_payload = p.fields(previous["payload"],
        ("bootstrapObservationOriginal", "bootstrapAdmissionOriginal", "gateBindingOriginal"))
    p.require(previous_payload["bootstrapObservationOriginal"] == observed_raw.decode("ascii")
        and previous_payload["bootstrapAdmissionOriginal"] == signed_raw.decode("ascii")
        and early["deadlineBoottimeNs"] == previous["deadlineBoottimeNs"] == window["startupDeadlineBoottimeNs"])
    precreation._gate(previous_payload["gateBindingOriginal"], control, driver_config, window, observed_raw, signed["payload"])
    fragment = policy.precreation()
    config_raw, config = precreation._configuration(fragment, control, observed_raw)
    p.require(bundle["cohortConfigurationOriginal"] == config_raw.decode("ascii"))
    _same(bundle["nativeColdOriginals"], fragment["nativeColdOriginals"])
    _same(bundle["ordinaryColdOriginals"], fragment["ordinaryColdOriginals"])
    for role in generation.ROLES:
        p.require(ordinary["services"][role]["executableSha256"] == fragment["ordinaryExecutableSha256"][role])
    for name in c9.WINDOW_FIELDS:
        if name != "issuedAtBoottimeNs":
            _same(ordinary[name], window[name])
    cohort_control = p.document(bundle["cohortControlOriginal"].encode("ascii"), 4096)
    p.require(cohort_control["cohortExecutableSha256"] == fragment["cohortExecutableSha256"])
    signing_raw, _ = precreation._signing_input(fragment, config_raw, config, window)
    p.require(process.approved_input_original("endpoint-precreation", "cohort-precreation") == signing_raw)
    precreated = p.fields(process.prior_result("endpoint-precreation", "cohort-precreation"), ("original", "sha256"))
    p.require(precreated["original"] == bundle["cohortPrecreationOriginal"]
        and p.digest(precreated["sha256"]) == p.sha(bundle["cohortPrecreationOriginal"].encode("ascii")))
    result = p.fields(process.prior_result("endpoint-precreation", "install-precreation"),
        ("apiVersion", "bundleSha256", "startupDeadlineBoottimeNs", "pins"))
    expected_pins = {purpose: {"path": publication.DESTINATIONS[purpose], "sha256": p.sha(original)}
        for purpose, original in planned}
    _same(result, {"apiVersion": "catchplate.nativePilotPrecreationPublication/v1", "bundleSha256": digest,
        "startupDeadlineBoottimeNs": str(min(p.ns(window["startupDeadlineBoottimeNs"]),
            p.ns(ordinary["startupDeadlineBoottimeNs"]))), "pins": expected_pins})
    return planned, window, ordinary, bundle, config_raw, config, observed, signed["payload"]


def _peer(policy, process, request, bundle, config_raw, config, driver_observed, bootstrap):
    current = _phase(process, "endpoint-inputs")
    p.require(p.sha(p.canonical(current)) == request.value["conductorRequestSha256"]
        and p.ns(current["deadlineBoottimeNs"]) == request.deadline_boottime_ns)
    payload = p.fields(current["payload"], OBSERVATION_FIELDS)
    observed_raw, observed = scope._original(payload["cohortObservationOriginal"], cohort.MAX_BYTES)
    cold_raw = bundle["nativeColdOriginals"]["retrieval"].encode("ascii")
    cold = c9.delivery.configuration(cold_raw, p.sha(cold_raw))
    signed_raw, signed = scope._original(bundle["cohortPrecreationOriginal"], cohort.MAX_BYTES)
    c9._endpoint_owner("retrieval", cold, cold_raw, config_raw, signed_raw, signed, observed)
    external = external_driver.original(observed["externalDriver"], config["externalDriver"])
    packet = p.canonical({"apiVersion": "catchplate.nativeShadowEndpointDriverBinding/v1",
        "configurationOriginal": bundle["driverConfigurationOriginal"], "windowOriginal": bundle["driverWindowOriginal"],
        "observationOriginal": bundle["driverObservationOriginal"]})
    p.require(external["bindingSha256"] == p.sha(packet))
    kernel = driver_observed["driver"]
    child, supervisor, executable = external["driver"], external["supervisor"], external["executable"]
    p.require(child["processId"] == driver_observed["processId"] and child["startTimeTicks"] == kernel["processStartTimeTicks"])
    for name in external_driver.PROCESS_FIELDS:
        p.require(supervisor[name] == bootstrap["parent"][name])
    descriptor = driver_observed["descriptors"][1]
    p.require(executable["device"] == descriptor["device"] and executable["inode"] == descriptor["inode"]
        and executable["sha256"] == kernel["driverExecutableSha256"])
    fragment = policy.endpoint_policy()
    peer = {"uid": driver_observed["uid"], "gid": driver_observed["gid"], "pid": child["processId"],
        "startTimeTicks": child["startTimeTicks"], "executableDevice": executable["device"],
        "executableInode": executable["inode"], "executableLength": executable["length"],
        "executableSha256": executable["sha256"], "cgroupMountId": kernel["cgroupMountId"],
        "cgroupInode": kernel["cgroupInode"], **fragment["peerExpectations"]}
    # The proc-original digest is NOT the cgroup-path digest. These three
    # expectations come only from the independently admitted static policy.
    parts = [peer[name].to_bytes(4, "big") for name in ("uid", "gid", "pid")]
    parts.extend(peer[name].to_bytes(8, "big") for name in
        ("startTimeTicks", "executableDevice", "executableInode", "executableLength"))
    parts.extend((p.raw_digest(peer["executableSha256"]), peer["cgroupPathSha256"].encode("ascii"),
        peer["cgroupMountId"].to_bytes(8, "big"), peer["cgroupInode"].to_bytes(8, "big"),
        peer["securityLabelSha256"].encode("ascii"), peer["configurationGenerationSha256"].encode("ascii")))
    peer["processIdentitySha256"] = p.framed(b"catchplate.policyCustodyPeerProcessIdentity/v4", parts)
    raw = p.canonical(peer)
    retrieval._peer(raw)
    return raw, observed_raw, fragment


class _Directory:
    """Retain the existing path, without competing with the installer's flock."""
    def __init__(self, path):
        self.path, self.fds, self.links = path, [], []
        self.identity = None

    def open(self):
        parts = self.path.split("/")[1:]
        p.require(self.path.startswith("/") and self.path.isascii() and len(self.path) <= 4096
            and 3 <= len(parts) <= 32 and all(part not in ("", ".", "..") and "\0" not in part
                and len(part) <= 255 for part in parts))
        fd = os.open("/", store.READ_FLAGS | os.O_DIRECTORY)
        self.fds.append(fd)
        for part in parts:
            info = os.fstat(fd)
            p.require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and info.st_mode & 0o022 == 0)
            child = os.open(part, store.READ_FLAGS | os.O_DIRECTORY, dir_fd=fd)
            self.fds.append(child)
            self.links.append((fd, part, child))
            fd = child
        self.identity = store._identity(os.fstat(fd))
        self.check(0o700)

    def check(self, mode):
        p.require(self.identity is not None)
        for fd in self.fds:
            info = os.fstat(fd)
            flags = fcntl.fcntl(fd, fcntl.F_GETFL)
            p.require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and info.st_mode & 0o022 == 0
                and flags & os.O_ACCMODE == os.O_RDONLY and flags & os.O_PATH == 0
                and fcntl.fcntl(fd, fcntl.F_GETFD) & fcntl.FD_CLOEXEC)
        for parent, name, child in self.links:
            p.require(store._identity(os.fstat(child))
                == store._identity(os.stat(name, dir_fd=parent, follow_symlinks=False)))
        actual = os.fstat(self.fds[-1])
        p.require(store._identity(actual) == self.identity and actual.st_uid == actual.st_gid == 0
            and stat.S_IMODE(actual.st_mode) == mode and store._names(self.fds[-1]) == [])

    def installed(self, result_raw, manifest_sha256):
        actual = store._identity(os.fstat(self.fds[-1]))
        # Only chmod/ctime may have changed on this same empty retained inode.
        p.require(all(actual[index] == self.identity[index] for index in (0, 1, 3, 4, 5, 6, 7)))
        self.identity = actual
        self.check(0o555)
        expected = {"apiVersion": "catchplate.nativeShadowRetrievalStoreInstalled/v2",
            "manifestSha256": manifest_sha256, "releaseAuthority": False, "serviceReady": False,
            "directoryDevice": actual[0], "directoryInode": actual[1], "directoryMode": 0o555,
            "objects": [], "initialization": retrieval.FRESH_INITIALIZATION}
        p.require(result_raw == p.canonical(expected))

    def close(self):
        while self.fds:
            os.close(self.fds[-1])
            self.fds.pop()


class _Publication:
    def __init__(self, policy, process):
        self.policy, self.process = policy, process
        self.originals, self.publisher, self.directory = [], None, None
        self.window = self.ordinary = self.observed = self.input = self.bootstrap = None
        self.measured = self.recipe = self.installation = None
        self.wall, self.previous = time.time_ns(), 0
        self.closed = self.failed = False

    def _check(self, request):
        p.require(not self.closed and not self.failed)
        _actual(self.policy, self.process, request)
        self.previous = installation._check(self.window, self.ordinary, self.previous)
        p.require(request.deadline_boottime_ns == min(p.ns(self.window["startupDeadlineBoottimeNs"]),
            p.ns(self.ordinary["startupDeadlineBoottimeNs"])))
        wall = time.time_ns()
        p.require(self.wall <= wall)
        self.wall = wall
        p.freshness(self.bootstrap["issuedAtUnixNanos"], self.bootstrap["expiresAtUnixNanos"], wall, 30_000_000_000)
        for original in self.originals:
            original.check()
        if self.publisher is not None:
            self.publisher.check()
        if self.directory is not None:
            self.directory.check(0o700 if self.installation is None else 0o555)


def compose(policy, *, process, request) -> bytes:
    """Apply the admitted fixed preparation, then return the exact input7.

    Publication is explicitly authorized by that policy, before the separate
    input approval job. No approval8 or resource-admission result is generated.
    """
    global _USED, _LIVE
    p.require(not _USED)
    _USED = True
    _actual(policy, process, request)
    p.require(request.phase == request.job == "endpoint-inputs" and request.job_index == 1)
    owner = _Publication(policy, process); _LIVE = owner
    try:
        planned, window, ordinary, bundle, config_raw, config, driver_observed, bootstrap = _prior(policy, process)
        peer_raw, observed_raw, fragment = _peer(policy, process, request, bundle, config_raw, config, driver_observed, bootstrap)
        owner.window, owner.ordinary, owner.observed, owner.bootstrap = window, ordinary, observed_raw, bootstrap
        measured = policy.measured_configuration(process=process, request=request)
        recipe = policy.endpoint_recipe_originals(process=process, request=request)
        p.fields(measured, ("apiVersion", "recipeSha256", "configurationBindingOriginal", "configurationBindingSha256",
            "proofScopeOriginal", "production"))
        p.require(measured["apiVersion"] == "catchplate.nativePilotMeasuredConfiguration/v2"
            and fragment["initialization"] == retrieval.FRESH_INITIALIZATION)
        p.fields(recipe, ("assignmentOriginal", "trustOriginal", "trustSha256", "closureSetOriginal"))
        proof_raw, proof = scope._original(measured["proofScopeOriginal"], 16384)
        retrieval.scope_original(proof_raw)
        assignment_raw, assignment = scope._original(recipe["assignmentOriginal"], assignment_profile.MAX_BYTES)
        assignment_profile.shape(assignment)
        retrieval.require_assignment_scope(proof, p.canonical(assignment["payload"]))
        p.require(proof["production_configuration_binding_sha256"] == measured["configurationBindingSha256"]
            == measured["production"]["expectedConfigurationBindingSha256"])
        manifest_raw = retrieval.fresh_ledger_manifest_original(proof_raw)
        owner.measured, owner.recipe = measured, recipe
        for purpose, raw in planned:
            original = _Original(publication.DESTINATIONS[purpose], publication.LIMITS[purpose], p.sha(raw), mode=0o400)
            owner.originals.append(original)
            p.require(original.raw == raw)
        originals_to_publish = (peer_raw, proof_raw, manifest_raw, assignment_raw)
        p.require(sum(len(raw) for raw in originals_to_publish) <= publication.MAX_PUBLIC_BYTES)
        for purpose, raw in zip(PURPOSES, originals_to_publish, strict=True):
            publication._shape(purpose, raw)
        owner._check(request)
        owner.publisher = publication.PublicPublisher.open()
        owner.publisher.require_absent(PURPOSES)  # Before freezing the unused object directory.
        owner.directory = _Directory(fragment["objectDirectory"])
        owner.directory.open()  # Read-only retention, no flock, mkdir or mode change.
        owner._check(request)
        installed = store.install(target_directory=fragment["objectDirectory"],
            manifest_original=manifest_raw, manifest_sha256=p.sha(manifest_raw))
        owner.directory.installed(installed, p.sha(manifest_raw))
        owner.installation = installed
        owner._check(request)
        pins = {}
        for purpose, raw in zip(PURPOSES, originals_to_publish, strict=True):
            owner._check(request)
            pins[purpose] = owner.publisher.publish(purpose=purpose, raw=raw, expected_sha256=p.sha(raw))
            owner._check(request)
        value = {"coldOriginals": {role: copy.deepcopy(config[role + "Configuration"]) for role in ENDPOINT_INPUT_ROLES},
            "peer": pins[PURPOSES[0]], "proofScope": pins[PURPOSES[1]], "retrievalManifest": pins[PURPOSES[2]],
            "objectDirectory": fragment["objectDirectory"], "assignment": pins[PURPOSES[3]],
            "production": copy.deepcopy(measured["production"])}
        raw = p.canonical(value)
        p.fields(p.document(raw, 65536), INPUT_FIELDS)
        owner._check(request)
        owner.input = raw
        return raw
    except BaseException:
        owner.failed = True
        raise


def _service_boundary(request):
    from catchplate.native_pilot_phase_execution import JOBS, job_index
    last = job_index("service-originals", "ordinary-delivery-" + generation.ROLES[0])
    return (request.phase == "service-originals" and type(request.job_index) is int
        and 1 <= request.job_index <= last
        and request.job == JOBS["service-originals"][request.job_index - 1].name)


def require_endpoint_inputs(policy, *, process, request) -> dict:
    """Recheck actual prior publication/open report, not endpoint readiness."""
    owner = _LIVE
    p.require(owner is not None and owner.policy is policy and owner.process is process and owner.input is not None)
    try:
        _actual(policy, process, request)
        delivery = (request.phase == "endpoint-deliveries" and request.job_index in (1, 2, 3)
            and request.job == "native-delivery-" + ENDPOINT_INPUT_ROLES[request.job_index - 1])
        service = _service_boundary(request)
        p.require(delivery or service)
        owner._check(request)
        p.require(process.approved_input_original("endpoint-inputs", "endpoint-inputs") == owner.input
            and process.approved_input_sha256("endpoint-inputs", "endpoint-inputs") == p.sha(owner.input))
        result = p.fields(process.prior_result("endpoint-inputs", "endpoint-inputs"), ("publicPinsOpened",))
        p.require(result["publicPinsOpened"] is True)
        current = _phase(process, "endpoint-deliveries")
        p.require(current["payload"]["cohortObservationOriginal"].encode("ascii") == owner.observed)
        _same(policy.measured_configuration(process=process, request=request), owner.measured)
        _same(policy.endpoint_recipe_originals(process=process, request=request), owner.recipe)
        owner._check(request)
        return p.document(owner.input, 65536)
    except BaseException:
        owner.failed = True
        raise


def close(process):
    """Release retained handles only after the actual coordinator retires."""
    global _LIVE
    if _LIVE is None:
        return
    owner = _LIVE
    p.require(owner.process is process and os.getpid() == process._pid and originals._boot() == process._boot
        and process._closed and process._result["status"] in
        ("not-started", "stopped-cleanup-complete", "failed-cleanup-complete"))
    if owner.publisher is not None:
        owner.publisher.close()
    if owner.directory is not None:
        owner.directory.close()
    while owner.originals:
        owner.originals[-1].close()
        owner.originals.pop()
    owner.closed = True; _LIVE = None
