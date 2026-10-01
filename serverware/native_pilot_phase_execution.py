"""Execute the fixed pilot's separately approved authority jobs, once each.

The independent supervisor approves every complete input after any prerequisite
signature exists and installs the two protected fixed job files. An approval
hash received on a root pipe is not independently authenticated provenance by
itself. Provisioning that supervisor and its installation/key capabilities is
mandatory. Child observations are never approval, and no future signed input
is assembled from placeholders. The actual conductor retains its live owners.

Only existing purpose producers/installers are called. No commands, arbitrary
destinations, keys, windows, journals or success pins are generated. Partial
publications remain on failure; the entire attempt is fenced without retry.
"""
from __future__ import annotations

import copy
import fcntl
import os
import time
from typing import NamedTuple

from scripts.authority import native_pilot_authority_io as io
from serverware import custody_commitment_inputs as commitment
from serverware import custody_generation_grants as generation
from serverware import custody_generation_originals as generation_originals
from serverware import custody_spool_inputs as spool
from serverware import native_pilot_bridge_authority as bridge_authority
from serverware import native_pilot_bridge_authorization_profile as bridge_authorization_profile
from serverware import native_pilot_bridge_install as bridge_install
from serverware import native_pilot_bridge_launch_publication as bridge_launch
from serverware import native_pilot_bridge_runtime as bridge_runtime
from serverware import native_pilot_closure_authority as closure_authority
from serverware import native_pilot_current_head_authority as current_head_authority
from serverware import native_pilot_delivery_authority as delivery_authority
from serverware import native_pilot_driver_authority as driver_authority
from serverware import native_pilot_encrypted_authority as encrypted_authority
from serverware import native_pilot_generation_install_authority as generation_authority
from serverware import native_pilot_key_authority as key_authority
from serverware import native_pilot_launch_publication as launch_install
from serverware import native_pilot_native_service_authority as native_authority
from serverware import native_pilot_ordinary_initial_authority as initial_authority
from serverware import native_pilot_ordinary_initial_profile as initial_profile
from serverware import native_pilot_phase_two_publication as phase_two
from serverware import native_pilot_precreation_install as precreation_install
from serverware import native_pilot_scope_authority as scope_authority
from serverware import native_pilot_service_authority as service_authority
from serverware import native_pilot_service_material as service_material
from serverware import native_pilot_verifier_authority as verifier_authority
from serverware import native_shadow_nitro_originals as originals
from serverware import native_shadow_nitro_profile as p
from serverware import native_shadow_proof_cohort_assignment as cohort
from serverware import native_shadow_retrieval_artifacts as retrieval
from serverware.native_pilot_coordinator_channel import Request
from serverware.native_pilot_coordinator_process import ConductorProcess
from serverware.native_pilot_operator_channel import STAGES
from serverware.native_pilot_public_inputs import PublicInputs
from serverware.native_pilot_publication import PublicPublisher
from serverware.native_pilot_service_inputs import ENDPOINT_INPUT_ROLES
from serverware.native_shadow_generation_install_inputs import MAX_RECORD, MAX_RECORDS
from serverware.native_shadow_proof_cohort_control import _Original

APPROVAL_ROOT = "/etc/serverware/native-pilot-authority"
MAX_RETAINED_BYTES = 128 * 1024 * 1024
MAX_APPROVAL = 8192
_TOKEN = object()
_LIVE = None
_USED = False
_NATIVE_ENDPOINT = {"ingress": "ingressAdmission", "ledger": "commitRequest", "terminal": "terminalAppend",
    "dispatchBarrier": "dispatchBarrier", "activeEffectBarrier": "activeEffectBarrier",
    "activeEffectCommit": "activeEffectCommit", "retrieval": "retrieval", "persistence": "persistence",
    "trustedTime": "trustedTime", "commitRequest": "commitRequest"}
_GRANT_FOR_ENDPOINT = {role: operation for operation, role in _NATIVE_ENDPOINT.items() if operation != "commitRequest"}
_COHORT_ARGUMENTS = ("retrieval_configuration_raw", "persistence_configuration_raw", "trusted_time_configuration_raw",
    "generation_install_configuration_raw", "commit_request_configuration_raw", "ingress_admission_configuration_raw",
    "terminal_append_configuration_raw", "dispatch_barrier_configuration_raw",
    "active_effect_barrier_configuration_raw", "active_effect_commit_configuration_raw")


class _Job(NamedTuple):
    name: str
    family: str
    role: str | None
    maximum: int
    purpose: str | None
    key: str | None


def _signed(name, family, role, maximum, purpose=None):
    return _Job(name, family, role, maximum, purpose, name)


def _plain(name, family, maximum, role=None):
    return _Job(name, family, role, maximum, None, None)


INITIAL_JOBS = tuple(_Job(
    "ordinary-initial-" + operation + "-" + role, "ordinary-initial", role, initial_authority.MAX_INPUT,
    "ordinary-initial-history-" + role if operation == "assemble" else None,
    None if operation == "assemble" else "ordinary-initial-" + (
        "checkpoint" if operation == "checkpoint" else operation.removesuffix("-anchor")) + "-" + role)
    for role in generation.ROLES for operation in initial_authority.OPERATIONS)
INITIAL_JOB_INFO = {job.name: (role, operation) for job, (role, operation) in zip(INITIAL_JOBS,
    ((role, operation) for role in generation.ROLES for operation in initial_authority.OPERATIONS), strict=True)}

# The approved primary helper role remains one of INITIAL_JOBS. Three explicit
# supplemental slots cover its native-ordered complement, with the same keys.
# These assembly results stay retained; they do not create publication slots.
HELPER_INITIAL_JOBS = tuple(_Job(
    "ordinary-helper-initial-" + operation + "-slot" + str(slot), "helper-initial", generation.ROLES[-1],
    initial_authority.MAX_INPUT, None,
    None if operation == "assemble" else "ordinary-initial-" + (
        "checkpoint" if operation == "checkpoint" else operation.removesuffix("-anchor")) + "-" + generation.ROLES[-1])
    for slot in range(1, 4) for operation in initial_authority.OPERATIONS)
HELPER_INITIAL_JOB_INFO = {job.name: selected for job, selected in zip(HELPER_INITIAL_JOBS,
    ((slot, operation) for slot in range(1, 4) for operation in initial_authority.OPERATIONS), strict=True)}

_CURRENT_HEAD_TARGETS = tuple((role, None) for role in generation.ROLES[:-1]) + tuple(
    (generation.ROLES[-1], endpoint_role) for endpoint_role in initial_profile.HELPER_ENDPOINT_ROLES)
CURRENT_HEAD_JOBS = tuple(_Job("current-head-" + role + ("-" + endpoint_role if endpoint_role else ""),
    "current-head", role, current_head_authority.MAX_INPUT, None,
    "ordinary-initial-checkpoint-" + role) for role, endpoint_role in _CURRENT_HEAD_TARGETS)
CURRENT_HEAD_JOB_INFO = {job.name: selected for job, selected in
    zip(CURRENT_HEAD_JOBS, _CURRENT_HEAD_TARGETS, strict=True)}

KEY_AUTHORIZATION_JOBS = tuple(_signed(
    ("native-role-keys-" if operation == "role-keys" else "native-key-admission-") + role,
    "native-key", role, key_authority.MAX_INPUT)
    for role in cohort.ENDPOINT_ROLES for operation in ("role-keys", "admission"))
KEY_AUTHORIZATION_JOB_INFO = {job.name: (role, operation) for job, (role, operation) in zip(
    KEY_AUTHORIZATION_JOBS,
    ((role, operation) for role in cohort.ENDPOINT_ROLES for operation in ("role-keys", "admission")), strict=True)}

_LAUNCH_AUTHORIZATION_ORDER = tuple((role, operation) for role in cohort.ENDPOINT_ROLES
    for operation in (("closure", "request-commitment", "encrypted-delivery", "verifier-transport")
        if role == "commitRequest" else ("closure", "encrypted-delivery", "verifier-transport")))
LAUNCH_AUTHORIZATION_JOBS = tuple(_signed("native-" + operation + "-" + role,
    "native-launch-authorization", role,
    closure_authority.MAX_INPUT if operation == "closure" else
    verifier_authority.MAX_INPUT if operation == "verifier-transport" else encrypted_authority.MAX_INPUT)
    for role, operation in _LAUNCH_AUTHORIZATION_ORDER)
LAUNCH_AUTHORIZATION_JOB_INFO = {job.name: selected for job, selected in
    zip(LAUNCH_AUTHORIZATION_JOBS, _LAUNCH_AUTHORIZATION_ORDER, strict=True)}

BRIDGE_AUTHORIZATION_JOBS = tuple(_signed(
    ("native-key-admission-bridge" if operation == "admission" else "native-" + operation + "-bridge"),
    "bridge-authorization", "bridge",
    closure_authority.MAX_BRIDGE_INPUT if operation == "closure" else bridge_authority.MAX_INPUT)
    for operation in bridge_authorization_profile.OPERATIONS)
BRIDGE_AUTHORIZATION_JOB_INFO = {job.name: operation for job, operation in
    zip(BRIDGE_AUTHORIZATION_JOBS, bridge_authorization_profile.OPERATIONS, strict=True)}


# No user-controlled operation list. Dependencies intentionally precede later
# approval requests; every later producer receives its complete approved bytes.
JOBS = {
    "bootstrap-admission": (_signed("driver-bootstrap", "driver", "bootstrap", driver_authority.MAX_INPUT,
                                   "driver-bootstrap-admission"),),
    "endpoint-precreation": (_signed("cohort-precreation", "cohort", "precreation", 2 * 1024 * 1024),
        _plain("install-precreation", "precreation", precreation_install.MAX_INPUT)),
    "endpoint-inputs": (_plain("endpoint-inputs", "endpoint-inputs", 65536),),
    "endpoint-deliveries": tuple(_signed("native-delivery-" + role, "delivery", role,
        delivery_authority.MAX_INPUT, "native-delivery-" + role) for role in ENDPOINT_INPUT_ROLES),
    "service-originals": (
        *INITIAL_JOBS,
        *HELPER_INITIAL_JOBS,
        *(_signed("ordinary-delivery-" + role, "ordinary-delivery", role, service_authority.MAX_INPUT_BYTES,
                  "ordinary-delivery-" + role) for role in generation.ROLES),
        *(_signed("ordinary-generation-" + role, "ordinary-generation", role, service_authority.MAX_INPUT_BYTES,
                  "ordinary-generation-" + role) for role in generation.ROLES),
        *(_signed("native-delivery-" + role, "delivery", role, delivery_authority.MAX_INPUT,
                  "native-delivery-" + role) for role in cohort.ENDPOINT_ROLES if role not in ENDPOINT_INPUT_ROLES),
        *KEY_AUTHORIZATION_JOBS,
        _signed("native-service-commitRequest", "native", "commitRequest", native_authority.MAX_INPUT,
                "native-service-commitRequest"),
        *(_signed("native-service-" + operation, "native", operation, native_authority.MAX_INPUT,
                  "native-service-" + operation) for operation in native_authority.OPERATIONS if operation != "commitRequest"),
        _signed("native-generation-install-grant", "generation-install", None,
                generation_authority.MAX_INPUT_BYTES, "native-generation-install-grant"),
        *(_signed("ordinary-dispatch-" + role, "ordinary-dispatch", role, service_authority.MAX_INPUT_BYTES,
                  "ordinary-dispatch-" + role) for role in commitment.ROLES),
        *(_signed("ordinary-" + operation, "ordinary-" + operation, role, service_authority.MAX_INPUT_BYTES,
                  "ordinary-" + operation) for operation, role in zip(("head", "cleanup", "current"), spool.EFFECT_ROLES, strict=True)),
        *LAUNCH_AUTHORIZATION_JOBS,
        *(_plain("install-launch-" + role, "launch", launch_install.MAX_INPUT, role) for role in cohort.ENDPOINT_ROLES),
        _plain("service-material", "service-material", service_material.MAX_INPUT),
    ),
    "bridge-runtime": (*CURRENT_HEAD_JOBS,
        _plain("install-bridge-runtime", "bridge-runtime", bridge_install.MAX_BRIDGE_INPUT)),
    "bridge-delivery": (_signed("native-delivery-bridge", "delivery", "bridge", delivery_authority.MAX_BRIDGE_INPUT,
                                "native-delivery-bridge"),
        *BRIDGE_AUTHORIZATION_JOBS,
        _plain("install-launch-bridge", "launch", launch_install.MAX_INPUT, "bridge")),
    "release": (_signed("cohort-release", "cohort", "release", 2 * 1024 * 1024, "cohort-release"),
        _signed("driver-scope", "scope", None, scope_authority.MAX_BRIDGE_INPUT, "driver-scope"),
        _plain("phase-two-public", "phase-two-public", phase_two.MAX_INPUT)),
    "constructed-admission": (_signed("driver-constructed", "driver", "constructed", driver_authority.MAX_INPUT,
                                      "driver-constructed-admission"),),
    "generation-origin": (_plain("observe-generation-origin", "origin", 1024),),
    "shutdown": (_plain("stop", "stop", 1024),),
}
KEY_PURPOSES = tuple(sorted({job.key for jobs in JOBS.values() for job in jobs if job.key is not None}))


def job_index(phase, name):
    """One-based index of a unique source-fixed job, never a caller job list."""
    p.require(type(phase) is str and phase in JOBS and type(name) is str)
    indices = [index for index, job in enumerate(JOBS[phase], 1) if job.name == name]
    p.require(len(indices) == 1)
    return indices[0]


def _same(first, second):
    p.require(p.canonical(first) == p.canonical(second))


def _raw(value, maximum):
    p.require(type(value) is str and value.isascii())
    raw = value.encode("ascii")
    p.document(raw, maximum)
    return raw


class PhaseExecution:
    """Actual pending child request plus separately retained authority inputs."""

    def __init__(self, token, process):
        p.require(token is _TOKEN)
        self._process = process
        self._pid, self._boot = os.getpid(), originals._boot()
        self._held, self._keys = [], {}
        self._publisher = self._public = None
        self._bytes = self._exchange = self._phase_index = self._job_index = 0
        self._request = self._ticket = None
        self._failed = self._closed = self._keys_attempted = False
        self._outputs, self._pins, self._installations, self._observations = {}, {}, {}, {}
        self._inputs = {}  # References to the same bounded, retained original bytes.
        self._previous = None
        self._material = self._endpoint_inputs = self._public_bundle_pin = self._scope_bundle = None

    @classmethod
    def open(cls, process):
        global _USED, _LIVE
        p.require(cls is PhaseExecution and not _USED and type(process) is ConductorProcess)
        process._origin()
        p.require(not process._started and tuple(JOBS) == STAGES)
        _USED = True
        owner = cls(_TOKEN, process)
        _LIVE = owner
        return owner  # Caller retains this before any key/file/publication work.

    def prepare_keys(self, declared):
        self._check()
        p.require(not self._keys_attempted and not self._process._started)
        self._keys_attempted = True
        try:
            p.fields(declared, KEY_PURPOSES)
            for purpose in KEY_PURPOSES:
                source = declared[purpose]
                identity = io._input(source, 32, private=True)
                p.require(identity[6] == 32)
                held = fcntl.fcntl(source, fcntl.F_DUPFD_CLOEXEC, 3)
                self._keys[purpose] = (held, identity)
                p.require(io._input(held, 32, private=True) == identity)
            # Explicit transferred capability FDs are consumed. Only the
            # retained CLOEXEC copies remain; conductor Popen uses close_fds.
            for fd in set(declared.values()):
                os.close(fd)
            self._publisher = PublicPublisher.open()
            self._public = PublicInputs.open()
            self._check()
        except BaseException:
            self._failed = True
            raise

    def _check(self, *, pending=False):
        p.require(_LIVE is self and not self._closed and not self._failed and os.getpid() == self._pid
            and originals._boot() == self._boot)
        self._process._origin()
        if pending:
            p.require(type(self._request) is Request and self._process._channel._pending is self._request)
            self._process._io_check(self._request.deadline_boottime_ns)
        for original in self._held:
            original.check()
        if self._publisher is not None:
            self._publisher.check()
        if self._public is not None:
            self._public.check()

    def begin(self, request):
        self._check()
        p.require(self._keys_attempted and self._public is not None and self._request is None
            and type(request) is Request and self._process._channel._pending is request
            and self._phase_index < len(STAGES) and request.phase == STAGES[self._phase_index]
            and request.sequence == self._phase_index + 1)
        self._request, self._job_index = request, 0
        self._observations[request.phase] = request.payload
        self._check(pending=True)

    def has_job(self):
        self._check(pending=True)
        return self._job_index < len(JOBS[self._request.phase])

    def job_request(self):
        self._check(pending=True)
        p.require(self.has_job() and self._ticket is None)
        request = self._request
        job = JOBS[request.phase][self._job_index]
        value = {"apiVersion": "serverware.nativePilotAuthorityJobRequest/v1", "sequence": self._exchange + 1,
            "conductorSequence": request.sequence, "conductorRequestSha256": p.sha(request.raw),
            "phase": request.phase, "jobIndex": self._job_index + 1, "job": job.name,
            "deadlineBoottimeNs": str(request.deadline_boottime_ns),
            "conductorRequest": p.document(request.raw, 32 * 1024 * 1024) if self._job_index == 0 else None,
            "previousResult": copy.deepcopy(self._previous)}
        self._ticket = p.canonical(value)
        return value

    def _retain(self, path, digest, maximum):
        p.require(self._bytes < MAX_RETAINED_BYTES)
        original = _Original(path, min(maximum, MAX_RETAINED_BYTES - self._bytes), digest, mode=0o400)
        self._held.append(original)
        self._bytes += len(original.raw)
        p.require(self._bytes <= MAX_RETAINED_BYTES)
        return original.raw

    def execute(self, reply):
        """Consume one job before input validation, signing or filesystem writes."""
        self._check(pending=True)
        p.require(self._ticket is not None and self.has_job())
        request = self._request
        job = JOBS[request.phase][self._job_index]
        self._failed = True  # Only definite completion releases this attempt fence.
        ticket = p.document(self._ticket, 32 * 1024 * 1024)
        p.fields(reply, ("apiVersion", "sequence", "conductorSequence", "conductorRequestSha256", "phase",
            "jobIndex", "job", "requestSha256", "approvalSha256", "inputSha256"))
        p.require(reply["apiVersion"] == "serverware.nativePilotAuthorityJobReply/v1"
            and reply["requestSha256"] == p.sha(self._ticket))
        for field in ("sequence", "conductorSequence", "conductorRequestSha256", "phase", "jobIndex", "job"):
            _same(reply[field], ticket[field])
        stem = APPROVAL_ROOT + "/" + request.phase + "/" + job.name
        approval_raw = self._retain(stem + ".approval.json", p.digest(reply["approvalSha256"]), MAX_APPROVAL)
        approval = p.fields(p.document(approval_raw, MAX_APPROVAL), ("apiVersion", "conductorSequence",
            "conductorRequestSha256", "phase", "jobIndex", "job", "deadlineBoottimeNs", "inputSha256"))
        p.require(approval["apiVersion"] == "serverware.nativePilotAuthorityJobApproval/v1")
        for field in ("conductorSequence", "conductorRequestSha256", "phase", "jobIndex", "job", "deadlineBoottimeNs"):
            _same(approval[field], ticket[field])
        p.require(p.digest(approval["inputSha256"]) == p.digest(reply["inputSha256"]))
        raw = self._retain(stem + ".input.json", approval["inputSha256"], job.maximum)
        self._inputs[job.name] = raw
        value = p.document(raw, job.maximum)
        self._process._io_check(request.deadline_boottime_ns)
        self._bind(job, value)
        key = None
        if job.key is not None:
            fd, identity = self._keys[job.key]
            p.require(io._input(fd, 32, private=True) == identity)
            key = io.signing_key(fd)
        result = self._perform(job, raw, value, key)
        del key  # Not a hardware/non-exportable or guaranteed-zeroization claim.
        if job.key is not None:
            p.require(io._input(fd, 32, private=True) == identity)
        for original in self._held:
            original.check()
        self._process._io_check(request.deadline_boottime_ns)
        self._publisher.check(); self._public.check()
        self._previous = {"phase": request.phase, "job": job.name, "result": result}
        self._job_index += 1
        self._exchange += 1
        self._ticket = None
        self._failed = False

    def _known(self, field, value, output):
        p.require(_raw(value[field], 131072) == self._outputs[output])

    def _known_native(self, field, value, operation):
        raw = _raw(value[field], native_authority.MAX_OUTPUT)
        native_authority.grant_original(operation, raw)
        p.require(raw == self._outputs["native-service-" + operation])

    def _native_histories(self, value):
        """Bind the new grant bundle to all five actual earlier approved jobs."""
        for role, service in p.fields(value["services"], generation.ROLES).items():
            prior = generation.document(self._inputs["ordinary-generation-" + role],
                service_authority.MAX_INPUT_BYTES)
            _same(value["ordinaryLaunchOriginal"], prior["launchOriginal"])
            _same(service, {**prior["services"][role], "generationGrantOriginal":
                self._outputs["ordinary-generation-" + role].decode("ascii")})
            p.require(service_authority._original(service["historyOriginal"], generation.MAX_BYTES)
                == self._outputs["ordinary-initial-assemble-" + role])
            self._known("deliveryOriginal", service, "ordinary-delivery-" + role)

    def _key_configuration(self, role, original):
        """Downstream verifier settings must retain this attempt's two outputs."""
        value = p.document(_raw(original, p.MAX_CONFIG), p.MAX_CONFIG)
        p.require(p.canonical(value["authorization"]) == self._outputs["native-role-keys-" + role]
            and p.canonical(value["admissionAuthorization"]) == self._outputs["native-key-admission-" + role])

    def _bind_launch_authorization(self, job, value):
        """Bind complete inputs to this attempt's actual C9/key/pair originals."""
        role, operation = LAUNCH_AUTHORIZATION_JOB_INFO[job.name]
        p.require(role == job.role)
        if operation == "closure":
            p.require(value["apiVersion"] == "serverware.nativePilotClosureAuthorityInput/v2"
                and value["guestRole"] == role)
            prior = p.document(self._inputs["native-delivery-" + role], delivery_authority.MAX_INPUT)
            for target, source in (("configurationOriginal", "ownerConfigurationOriginal"),
                    ("windowOriginal", "windowOriginal"), ("observationOriginal", "observationOriginal"),
                    ("deliveryConfigurationOriginal", "configurationOriginal"), ("runtimeOriginal", "runtimeOriginal")):
                _same(value[target], prior[source])
            self._known("deliveryOriginal", value, "native-delivery-" + role)
            approved = p.document(self._inputs["native-role-keys-" + role], key_authority.MAX_INPUT)
            for field in ("trustOriginal", "trustSha256", "assignmentOriginal", "closureSetOriginal"):
                _same(value[field], approved["recipeOriginals"][field])
        else:
            p.require(value["role"] == role)
            if operation != "verifier-transport":
                p.require(value["operation"] == ("delivery" if operation == "encrypted-delivery" else operation))
            for field, previous in (("roleKeyInputOriginal", "native-role-keys-" + role),
                    ("admissionInputOriginal", "native-key-admission-" + role)):
                p.require(_raw(value[field], key_authority.MAX_INPUT) == self._inputs[previous])
            self._known("roleKeyOriginal", value, "native-role-keys-" + role)
            self._known("admissionOriginal", value, "native-key-admission-" + role)
            if operation == "encrypted-delivery" and role == "commitRequest":
                self._known("requestCommitmentOriginal", value, "native-request-commitment-commitRequest")

    def _bridge_pair(self):
        """Literal actual results, never a reconstructed early live owner."""
        return {"roleKeyInputOriginal": self._inputs["native-role-keys-bridge"].decode("ascii"),
            "roleKeyOriginal": self._outputs["native-role-keys-bridge"].decode("ascii"),
            "admissionInputOriginal": self._inputs["native-key-admission-bridge"].decode("ascii"),
            "admissionOriginal": self._outputs["native-key-admission-bridge"].decode("ascii")}

    def _bind_bridge_authorization(self, job, value):
        """Associate complete approved bytes before opening this job's key."""
        operation = BRIDGE_AUTHORIZATION_JOB_INFO[job.name]
        p.require(job.role == "bridge")
        prior = delivery_authority.input_document(self._inputs["native-delivery-bridge"])
        bootstrap = p.document(self._inputs["driver-bootstrap"], driver_authority.MAX_INPUT)
        retrieval_keys = p.document(self._inputs["native-role-keys-retrieval"], key_authority.MAX_INPUT)
        if operation in bridge_authority.keys.OPERATIONS:
            p.require(value["operation"] == operation)
            _same(value["controlOriginal"], bootstrap["controlOriginal"])
            p.require(_raw(value["deliveryInputOriginal"], delivery_authority.MAX_BRIDGE_INPUT)
                == self._inputs["native-delivery-bridge"])
            self._known("deliveryOriginal", value, "native-delivery-bridge")
            for field in ("recipeOriginals", "measured"):
                _same(value[field], retrieval_keys[field])
            if operation == "admission":
                self._known("roleKeyOriginal", value, "native-role-keys-bridge")
                first = p.document(self._inputs["native-role-keys-bridge"], bridge_authority.MAX_INPUT)
                for field in bridge_authority.keys.INPUT_FIELDS:
                    if field != "operation":
                        _same(value[field], first[field])
        elif operation == "closure":
            p.require(value["apiVersion"] == "serverware.nativePilotClosureAuthorityInput/v2"
                and value["guestRole"] == "bridge")
            _same(value["controlOriginal"], bootstrap["controlOriginal"])
            for target, source in (("configurationOriginal", "ownerConfigurationOriginal"),
                    ("windowOriginal", "windowOriginal"), ("observationOriginal", "observationOriginal"),
                    ("deliveryConfigurationOriginal", "configurationOriginal"), ("runtimeOriginal", "runtimeOriginal")):
                _same(value[target], prior[source])
            self._known("deliveryOriginal", value, "native-delivery-bridge")
            for field in ("trustOriginal", "trustSha256", "assignmentOriginal", "closureSetOriginal"):
                _same(value[field], retrieval_keys["recipeOriginals"][field])
        else:
            p.require(value["operation"] == operation)
            for field, literal in self._bridge_pair().items():
                _same(value[field], literal)
        prepared = bridge_authorization_profile.prepare_input(operation, p.canonical(value),
            boot=self._boot, now_boottime_ns=originals._clock(), now_unix_ns=time.time_ns())
        if operation == "closure":
            # Closure has no embedded pair fields. Its actual signed authority
            # context still must be this attempt's preceding bridge pair.
            pair = self._bridge_pair()
            admitted = bridge_authority.keys.admitted_pair(*(pair[name].encode("ascii")
                for name in bridge_authority.PAIR_FIELDS), boot=self._boot,
                now_boottime_ns=originals._clock(), now_unix_ns=time.time_ns())
            scope = admitted["expectedScope"]
            for field in ("assignmentId", "assignmentPayloadSha256", "assignmentRevision", "guest"):
                _same(prepared["payload"][field], scope[field])
        self._process._io_check(prepared["deadline"])

    def _bind_initial(self, job, value):
        supplemental = job.family == "helper-initial"
        if supplemental:
            slot, operation = HELPER_INITIAL_JOB_INFO[job.name]
            role = generation.ROLES[-1]
            stem, suffix = "ordinary-helper-initial-", "-slot" + str(slot)
        else:
            role, operation = INITIAL_JOB_INFO[job.name]
            stem, suffix = "ordinary-initial-", "-" + role
        extra = () if operation == "checkpoint" else ("initialCheckpointOriginal",)
        if operation == "assemble":
            extra += ("anchorSignatures",)
        p.fields(value, initial_authority.COMMON_FIELDS + extra)
        p.require(value["apiVersion"] == initial_authority.INPUT_API and value["operation"] == operation
            and role == job.role)
        _, state = initial_authority._original(value["initialStateOriginal"], initial_profile.MAX_STATE)
        p.require(state["serviceRole"] == role)
        observed = self._request.payload
        _same(value["preparationOriginal"], observed["ordinaryPreparationOriginal"])
        _same(value["resourcesOriginal"], observed["ordinaryInitialResourcesOriginal"])
        installed = p.document(self._inputs["install-precreation"], precreation_install.MAX_INPUT)
        p.require("install-precreation" in self._installations)
        for field in ("driverConfigurationOriginal", "driverWindowOriginal"):
            _same(value[field], installed[field])
        _same(value["launchOriginal"], installed["ordinaryLaunchOriginal"])
        _same(value["configurationOriginal"], installed["ordinaryColdOriginals"][role])
        checkpoint_job = stem + "checkpoint" + suffix
        if supplemental:
            # A later ceremony changes only the protocol-role identity. It must
            # use the actual retained primary facts, not a new owner/window.
            primary_name = "ordinary-initial-checkpoint-" + role
            primary = p.document(self._inputs[primary_name], initial_authority.MAX_INPUT)
            _, primary_state = initial_authority._original(primary["initialStateOriginal"], initial_profile.MAX_STATE)
            _, primary_payload = initial_authority._original(primary["payloadOriginal"], initial_authority.MAX_CHECKPOINT)
            remaining = tuple(name for name in initial_profile.HELPER_ENDPOINT_ROLES
                if name != primary_payload["endpointRole"])
            p.require(len(remaining) == 3)
            _, payload = initial_authority._original(value["payloadOriginal"], initial_authority.MAX_CHECKPOINT)
            p.require(payload["endpointRole"] == remaining[slot - 1])
            for field in initial_profile.STATE_FIELDS:
                if field != "endpointProcessIdentitySha256":
                    p.require(generation.canonical(state[field]) == generation.canonical(primary_state[field]))
            for field in initial_authority.COMMON_FIELDS:
                if field not in ("operation", "initialStateOriginal", "payloadOriginal"):
                    _same(value[field], primary[field])
            for field in primary_payload:
                if field not in ("endpointRole", "endpointProcessIdentitySha256", "predecessorCheckpointSha256"):
                    p.require(generation.canonical(payload[field]) == generation.canonical(primary_payload[field]))
        if operation != "checkpoint":
            approved = p.document(self._inputs[checkpoint_job], initial_authority.MAX_INPUT)
            # Literal originals and all independently selected public keys are
            # unchanged throughout this role's one ceremony; only operation
            # and actual prerequisite outputs may differ.
            for field in initial_authority.COMMON_FIELDS:
                if field != "operation":
                    _same(value[field], approved[field])
            checkpoint, _ = initial_authority._original(value["initialCheckpointOriginal"],
                initial_authority.MAX_CHECKPOINT)
            p.require(checkpoint == self._outputs[checkpoint_job])
        if operation == "assemble":
            for signer, original in p.fields(value["anchorSignatures"], initial_authority.KEY_NAMES).items():
                raw, _ = initial_authority._original(original, initial_authority.MAX_SIGNATURE)
                p.require(raw == self._outputs[stem + signer + "-anchor" + suffix])

    def _bind_initial_delivery(self, role, value):
        output = "ordinary-initial-assemble-" + role
        history_raw = self._outputs[output]
        runtime_raw = service_authority._original(value["runtimeOriginal"], generation.MAX_BYTES)
        header = service_authority._runtime(runtime_raw, role)
        payload = generation.document(service_authority._original(value["payloadOriginal"], 65536), 65536)
        p.require(type(payload["credentials"]) is list and 1 <= len(payload["credentials"]) <= 64)
        selected = [item for item in payload["credentials"]
            if item["name"] == header["authorityHistoryManifestCredential"]]
        p.require(len(selected) == 1)
        credential = p.fields(selected[0], ("name", "original", "length", "signing"))
        p.require(self._pins[output]["sha256"] == p.sha(history_raw))
        _same(credential["original"], {"path": initial_profile.INITIAL_CREDENTIAL_PATHS[role],
            "sha256": self._pins[output]["sha256"]})
        p.require(type(credential["length"]) is int and credential["length"] == len(history_raw)
            and credential["signing"] is None)
        installed = p.document(self._inputs["install-precreation"], precreation_install.MAX_INPUT)
        cold_raw = service_authority._original(installed["ordinaryColdOriginals"][role], 65536)
        cold = generation.configuration(cold_raw, p.sha(cold_raw), role)
        # The root-published result is not a service-owned C9 credential. A
        # separate fixed installer must supply this literal public copy; no
        # copying, chown, adoption or relaxed generic owner check occurs here.
        original = generation_originals.Original(credential["original"]["path"], len(history_raw),
            uid=cold["uid"], gid=cold["gid"])
        self._held.append(original)
        original.sha = p.digest(credential["original"]["sha256"])
        p.require(original.read() == history_raw)
        # The independently approved runtime supplies the authority pin; never
        # promote a key declared by the wrapper to its own trust anchor.
        history = initial_profile.manifest(history_raw, role=role, root_pin={
            "keyId": header["authorityHistoryRootKeyId"],
            "keySpkiSha256": header["authorityHistoryRootKeySpkiSha256"]})
        p.require(header["authorityHistoryManifestSha256"] == history["manifestSha256"])
        if role == generation.ROLES[-1] and header["apiVersion"] == initial_profile.HELPER_RUNTIME_API:
            runtime = generation.document(runtime_raw, generation.MAX_BYTES)
            expected = {}
            for name in (output,) + tuple("ordinary-helper-initial-assemble-slot" + str(slot) for slot in range(1, 4)):
                raw = self._outputs[name]
                wrapper = generation.document(raw, initial_profile.MAX_HELPER_HISTORY)
                endpoint_role = wrapper["initialCheckpoint"]["payload"]["endpointRole"]
                p.require(endpoint_role not in expected)
                expected[endpoint_role] = raw.decode("ascii")
            _same(runtime["initialEndpointHistories"], expected)
            initial_profile.helper_endpoint_histories(history_raw, runtime=runtime)

    def _bind_current_head(self, job, value):
        """Bind the independently approved decision to this attempt's real request."""
        from serverware import native_pilot_bridge_preparation as preparation

        role, endpoint_role = CURRENT_HEAD_JOB_INFO[job.name]
        bootstrap = p.document(self._inputs["driver-bootstrap"], driver_authority.MAX_INPUT)
        prior = p.document(self._inputs["ordinary-generation-" + role], service_authority.MAX_INPUT_BYTES)
        service = prior["services"][role]
        observed = self._observations["service-originals"]
        bridge = self._request.payload
        prep = preparation.shape(_raw(bridge["bridgePreparationOriginal"], preparation.MAX_BYTES))
        requests, _ = preparation._parts(prep)
        p.require(prep["apiVersion"] == preparation.HELPER_API and value["serviceRole"] == role)
        rows = [(endpoint, row) for selected, endpoint, row in preparation.requests_profile.iter_requests(requests)
            if selected == role and (endpoint_role is None or endpoint == endpoint_role)]
        p.require(len(rows) == 1)
        selected_endpoint, row = rows[0]
        expected = {"driverConfigurationOriginal": bootstrap["configurationOriginal"],
            "driverWindowOriginal": bootstrap["windowOriginal"], "launchOriginal": prior["launchOriginal"],
            "configurationOriginal": service["configurationOriginal"],
            "preparationOriginal": observed["ordinaryPreparationOriginal"],
            "resourcesOriginal": observed["ordinaryInitialResourcesOriginal"],
            "initialHistoryOriginal": service["historyOriginal"], "requestOriginal": row["requestOriginal"]}
        for field, original in expected.items():
            _same(value[field], original)
        p.require(requests["launchSha256"] == p.sha(_raw(value["launchOriginal"], 65536))
            and requests["preparationSha256"] == p.sha(_raw(value["preparationOriginal"], 65536))
            and requests["resourcesSha256"] == p.sha(_raw(value["resourcesOriginal"], 65536))
            and prep["driverObservationSha256"] == p.sha(_raw(
                self._observations["bootstrap-admission"]["bootstrapObservationOriginal"], 65536)))
        runtime_raw = _raw(service["runtimeOriginal"], generation.MAX_BYTES)
        runtime = generation.document(runtime_raw, generation.MAX_BYTES)
        header = runtime["runtime"]
        _same(value["rootAuthority"], {"keyId": header["authorityHistoryRootKeyId"],
            "keySpkiSha256": header["authorityHistoryRootKeySpkiSha256"]})
        history_raw = _raw(service["historyOriginal"], generation.MAX_BYTES)
        p.require(history_raw == self._outputs["ordinary-initial-assemble-" + role]
            and row["runtimeConfigurationSha256"] == p.sha(runtime_raw))
        if endpoint_role is not None:
            p.require(value["apiVersion"] == current_head_authority.profile.HELPER_API
                and value["endpointRole"] == endpoint_role)
            _same(value["runtimeOriginal"], service["runtimeOriginal"])
            members = initial_profile.helper_endpoint_histories(history_raw, runtime=runtime)
            history_raw = members[endpoint_role]["original"]
            actual = {self._outputs[name] for name in ("ordinary-initial-assemble-" + role,) + tuple(
                "ordinary-helper-initial-assemble-slot" + str(slot) for slot in range(1, 4))}
            p.require({item["original"] for item in members.values()} == actual)
        else:
            p.require(value["apiVersion"] == current_head_authority.profile.API)
        p.require(row["initialHistorySha256"] == p.sha(history_raw))
        checked = current_head_authority.profile.prepare_input(p.canonical(value),
            boot=self._boot, now_boottime_ns=originals._clock())
        p.require(checked["statement"]["endpointRole"] == selected_endpoint
            and checked["statement"]["requestSha256"] == row["requestSha256"]
            and checked["statement"]["checkpointSha256"] == row["checkpointSha256"])

    def _bind_bridge_heads(self, runtime):
        """The runtime must use these eight actual signatures, not substitutes."""
        from serverware import native_pilot_service_handshakes as handshakes

        p.require(bridge_runtime.version(runtime) == 11)
        jobs = {target: name for name, target in CURRENT_HEAD_JOB_INFO.items()}
        seen = set()
        for session in runtime["serviceSessions"]:
            role = session["serviceRole"]
            for item in session["handshakes"]:
                target = (role, item["endpointRole"] if role == generation.ROLES[-1] else None)
                p.require(target in jobs and jobs[target] not in seen)
                name = jobs[target]
                seen.add(name)
                signed = self._outputs[name]
                expected = handshakes.build(self._inputs[name],
                    {"original": signed.decode("ascii"), "sha256": p.sha(signed)},
                    boot=self._boot, now_boottime_ns=originals._clock(),
                    client_process_identity_sha256=runtime["expectedDriverProcessIdentitySha256"],
                    client_configuration_generation_sha256=runtime["expectedDriverConfigurationGenerationSha256"])
                p.require(p.canonical(item["request"]) == expected)
        p.require(seen == set(CURRENT_HEAD_JOB_INFO))

    def _bind(self, job, value):
        """Join approved input originals to this actual request and prior outputs."""
        observed = self._request.payload
        if job.family == "driver":
            if job.role == "bootstrap":
                _same(value["observationOriginal"], observed["bootstrapObservationOriginal"])
                _same(value["payloadOriginal"], observed["admissionPayloadOriginal"])
            else:
                for field, original in observed.items():
                    _same(value[field], original)
                self._known("bootstrapAdmissionOriginal", value, "driver-bootstrap")
        elif job.family == "cohort":
            if job.role == "precreation":
                config = p.document(_raw(value["configurationOriginal"], 32768), 32768)
                _same(config["externalDriver"]["observationSha256"],
                    p.sha(_raw(observed["bootstrapObservationOriginal"], 65536)))
            else:
                _same(value["observationsOriginal"], self._observations["service-originals"]["cohortObservationOriginal"])
                self._known("precreationOriginal", value, "cohort-precreation")
        elif job.family == "precreation":
            _same(value["driverObservationOriginal"], observed["bootstrapObservationOriginal"])
            self._known("cohortPrecreationOriginal", value, "cohort-precreation")
        elif job.family == "delivery":
            expected = observed["activation"] if job.role == "bridge" else observed["nativeActivations"][job.role]
            p.require(type(expected) is list)
            _same(self._array_original(value["activationOriginal"]), expected)
            _same(value["role"], job.role)
            _same(value["observationOriginal"], self._observations["bootstrap-admission"]["bootstrapObservationOriginal"]
                if job.role == "bridge" else observed["cohortObservationOriginal"])
            if job.role == "bridge":
                bootstrap = p.document(self._inputs["driver-bootstrap"], driver_authority.MAX_INPUT)
                for target, source in (("ownerConfigurationOriginal", "configurationOriginal"),
                        ("configurationOriginal", "deliveryConfigurationOriginal"), ("windowOriginal", "windowOriginal")):
                    _same(value[target], bootstrap[source])
                prior = p.document(self._inputs["install-bridge-runtime"], bridge_install.MAX_BRIDGE_INPUT)
                _same(value["runtimeOriginal"], prior["runtimeOriginal"])
                runtime_raw, runtime = bridge_runtime.original(value["runtimeOriginal"])
                p.require(bridge_runtime.version(runtime) in (10, 11) or len(p.canonical(value)) <= delivery_authority.MAX_INPUT)
                pin = self._installations["install-bridge-runtime"]["pins"]["bridge-runtime"]
                p.require(pin["sha256"] == p.sha(runtime_raw))
        elif job.family in ("ordinary-initial", "helper-initial"):
            self._bind_initial(job, value)
        elif job.family == "current-head":
            self._bind_current_head(job, value)
        elif job.family.startswith("ordinary-"):
            operation = job.family.removeprefix("ordinary-")
            _same(value["serviceRole"], job.role)
            if operation == "delivery":
                _same(value["activation"], observed["ordinaryActivations"][job.role])
                self._bind_initial_delivery(job.role, value)
            else:
                for role, service in value["services"].items():
                    p.require(service_authority._original(service["historyOriginal"], generation.MAX_BYTES)
                        == self._outputs["ordinary-initial-assemble-" + role])
                    self._known("deliveryOriginal", service, "ordinary-delivery-" + role)
                    if operation != "generation":
                        self._known("generationGrantOriginal", service, "ordinary-generation-" + role)
                if operation == "dispatch":
                    self._known_native("nativeGrantOriginal", value, "commitRequest")
                if operation in ("head", "cleanup", "current"):
                    for name in spool.EFFECT_NATIVE:
                        self._known_native(name, value["nativeOriginals"], name)
                    if operation != "head":
                        self._known("headGrantOriginal", value, "ordinary-head")
                    if operation == "current":
                        self._known("cleanupGrantOriginal", value, "ordinary-cleanup")
        elif job.family == "native-key":
            role, operation = KEY_AUTHORIZATION_JOB_INFO[job.name]
            p.require(value["role"] == role == job.role and value["operation"] == operation)
            delivery_job = "native-delivery-" + role
            self._known("deliveryOriginal", value, delivery_job)
            p.require(_raw(value["deliveryInputOriginal"], delivery_authority.MAX_INPUT) == self._inputs[delivery_job])
            if operation == "admission":
                self._known("roleKeyOriginal", value, "native-role-keys-" + role)
        elif job.family == "native-launch-authorization":
            self._bind_launch_authorization(job, value)
        elif job.family == "bridge-authorization":
            self._bind_bridge_authorization(job, value)
        elif job.family == "native":
            if value["apiVersion"] == "serverware.nativePilotNativeServiceAuthorityInput/v3":
                self._native_histories(value)
                if job.role == "commitRequest":
                    keys = p.document(self._inputs["native-role-keys-commitRequest"], key_authority.MAX_INPUT)
                    _same(value["assignmentOriginal"], keys["recipeOriginals"]["assignmentOriginal"])
            self._key_configuration(_NATIVE_ENDPOINT[job.role], value["configurationOriginal"])
            self._known("deliveryOriginal", value, "native-delivery-" + _NATIVE_ENDPOINT[job.role])
            _same(value["observationOriginal"], observed["cohortObservationOriginal"])
            if job.role == "ledger":
                self._known_native("companionOriginal", value, "commitRequest")
                _same(value["companionPin"], self._pins["native-service-commitRequest"])
            elif job.role == "retrieval":
                _same(p.document(_raw(value["endpointDeliveryResultOriginal"], 32768), 32768), observed["endpointDeliveryResult"])
                for name in native_authority.SIGNERS:
                    self._known_native(name, value["nativeGrantOriginals"], name)
        elif job.family == "generation-install":
            self._key_configuration("generationInstall", value["nativeConfigurationOriginal"])
            self._known("coordinatorDeliveryOriginal", value, "native-delivery-generationInstall")
            _same(value["observationOriginal"], observed["cohortObservationOriginal"])
            for role, service in p.fields(value["services"], generation.ROLES).items():
                self._known("deliveryOriginal", service, "ordinary-delivery-" + role)
                self._known("generationGrantOriginal", service, "ordinary-generation-" + role)
                prior = generation.document(self._inputs["ordinary-generation-" + role],
                    service_authority.MAX_INPUT_BYTES)
                _same(value["ordinaryLaunchOriginal"], prior["launchOriginal"])
                _same(service, {**prior["services"][role], "generationGrantOriginal":
                    self._outputs["ordinary-generation-" + role].decode("ascii")})
        elif job.family == "launch":
            _same(value["role"], job.role)
            if job.role == "bridge":
                prior_delivery = p.document(self._inputs["native-delivery-bridge"], delivery_authority.MAX_BRIDGE_INPUT)
                _same(value["runtimeOriginal"], prior_delivery["runtimeOriginal"])
                for target, source in (("ownerConfigurationSha256", "ownerConfigurationOriginal"), ("windowSha256", "windowOriginal")):
                    p.require(value[target] == p.sha(_raw(prior_delivery[source], 65536)))
                prior_key = p.document(self._inputs["native-role-keys-bridge"], bridge_authority.MAX_INPUT)
                for name in ("trust", "assignment"):
                    _same(value["originals"][name], prior_key["recipeOriginals"][name + "Original"])
                keys = p.document(_raw(value["originals"]["keys"], 65536), 65536)
                p.require(p.canonical(keys["authorization"]) == self._outputs["native-role-keys-bridge"])
                self._known("admission", value["originals"], "native-key-admission-bridge")
                p.require(_raw(value["originals"]["closure"], closure_authority.MAX_BYTES)
                    == self._outputs["native-closure-bridge"])
                self._known("encryptedKeys", value["originals"], "native-encrypted-delivery-bridge")
                self._known("verifierTransport", value["originals"], "native-verifier-transport-bridge")
                checked = bridge_launch.prepare_bridge_bundle(p.canonical(value), pair_context=self._bridge_pair(),
                    service_grant_original=self._outputs["native-service-trustedTime"],
                    boot=self._boot, now_boottime_ns=originals._clock(), now_unix_ns=time.time_ns())
                self._process._io_check(checked["deadline"])
            else:
                prior_key = p.document(self._inputs["native-role-keys-" + job.role], key_authority.MAX_INPUT)
                prior_delivery = p.document(_raw(prior_key["deliveryInputOriginal"], delivery_authority.MAX_INPUT),
                    delivery_authority.MAX_INPUT)
                for target, source in (("ownerConfigurationSha256", "ownerConfigurationOriginal"),
                        ("windowSha256", "windowOriginal")):
                    p.require(value[target] == p.sha(_raw(prior_delivery[source], 32768)))
                for name in ("runtimeOriginal", "observationOriginal"):
                    _same(value[name], prior_delivery[name])
                for name in ("trust", "assignment"):
                    _same(value["originals"][name], prior_key["recipeOriginals"][name + "Original"])
                if job.role == "trustedTime":
                    service_input = p.document(self._inputs["native-service-trustedTime"], native_authority.MAX_INPUT)
                    _same(value["originals"]["timeBootstrap"], service_input["bootstrapOriginal"])
                keys = p.document(_raw(value["originals"]["keys"], 65536), 65536)
                p.require(p.canonical(keys["authorization"]) == self._outputs["native-role-keys-" + job.role])
                self._known("admission", value["originals"], "native-key-admission-" + job.role)
                p.require(_raw(value["originals"]["closure"], closure_authority.MAX_BYTES)
                    == self._outputs["native-closure-" + job.role])
                self._known("encryptedKeys", value["originals"], "native-encrypted-delivery-" + job.role)
                self._known("verifierTransport", value["originals"], "native-verifier-transport-" + job.role)
            _same(value["keyAdmission"]["delivery"], self._pins["native-delivery-" + job.role])
            key = "native-generation-install-grant" if job.role == "generationInstall" else "native-service-" + (
                "trustedTime" if job.role == "bridge" else _GRANT_FOR_ENDPOINT[job.role])
            _same(value["serviceGrant"], self._pins[key])
            _same(value["observationOriginal"], self._observations["bootstrap-admission"]["bootstrapObservationOriginal"]
                if job.role == "bridge" else observed["cohortObservationOriginal"])
        elif job.family == "service-material" and value.get("apiVersion") == service_material.API:
            p.fields(value, ("apiVersion", "serviceContexts", "endpointLaunches"))
            p.fields(value["serviceContexts"], ("persistence", "generationInstall"))
            p.fields(value["endpointLaunches"], ("persistence", "generationInstall"))
            for role in ("persistence", "generationInstall"):
                previous = "native-generation-install-grant" if role == "generationInstall" else "native-service-persistence"
                row = p.fields(value["serviceContexts"][role], ("inputOriginal", "grantOriginal"))
                p.require(_raw(row["inputOriginal"], native_authority.MAX_INPUT) == self._inputs[previous])
                p.require(_raw(row["grantOriginal"], native_authority.MAX_OUTPUT) == self._outputs[previous])
                _same(value["endpointLaunches"][role], self._installations["install-launch-" + role]["launch"])
        elif job.family == "bridge-runtime":
            _same(value["driverObservationOriginal"], self._observations["bootstrap-admission"]["bootstrapObservationOriginal"])
            runtime_raw, runtime = bridge_runtime.original(value["runtimeOriginal"])
            self._bind_bridge_heads(runtime)
            if "bridgePreparationOriginal" in observed:
                from serverware import native_pilot_bridge_preparation as preparation
                ids = {"ordinary-services": {}, "native-endpoints": {}, "gate": {}}
                for role in generation.ROLES:
                    guest = generation.document(self._outputs["ordinary-generation-" + role], 65536)["payload"]["guest"]
                    ids["ordinary-services"][role] = {field: guest[field] for field in ("uid", "gid")}
                for role in cohort.ENDPOINT_ROLES:
                    guest = p.document(self._outputs["native-delivery-" + role], delivery_authority.MAX_DELIVERY)["payload"]
                    ids["native-endpoints"][role] = {field: guest[field] for field in ("uid", "gid")}
                gate_raw = _raw(self._observations["endpoint-precreation"]["gateBindingOriginal"], 8192)
                gate = p.document(gate_raw, 8192)["binding"]
                ids["gate"]["gate"] = {field: gate[field] for field in ("uid", "gid")}
                prep_raw = _raw(observed["bridgePreparationOriginal"], preparation.MAX_BYTES)
                prep = preparation.shape(prep_raw)
                initial_requests, prepared_peers = preparation._parts(prep)
                prior_observed = self._observations["service-originals"]
                p.require(initial_requests["preparationSha256"] == p.sha(
                    _raw(prior_observed["ordinaryPreparationOriginal"], 65536))
                    and initial_requests["resourcesSha256"] == p.sha(
                    _raw(prior_observed["ordinaryInitialResourcesOriginal"], 65536)))
                gate_peer = prepared_peers["gate"]["peers"]["gate"]
                p.require(prepared_peers["gate"]["sourceOriginalSha256"] == p.sha(gate_raw)
                    and (gate_peer["processId"], gate_peer["startTimeTicks"])
                        == (gate["gateProcessId"], gate["gateStartTimeTicks"]))
                helper_histories = None
                for role, endpoint_role, row in preparation.requests_profile.iter_requests(initial_requests):
                    prior = p.document(self._inputs["ordinary-generation-" + role], service_authority.MAX_INPUT_BYTES)
                    original = _raw(prior["services"][role]["historyOriginal"], generation.MAX_BYTES)
                    if role == generation.ROLES[-1] and initial_requests["apiVersion"] == preparation.requests_profile.HELPER_API:
                        if helper_histories is None:
                            from serverware import native_pilot_ordinary_initial_profile as initial
                            helper_runtime = generation.document(_raw(prior["services"][role]["runtimeOriginal"],
                                generation.MAX_BYTES), generation.MAX_BYTES)
                            helper_histories = initial.helper_endpoint_histories(original, runtime=helper_runtime)
                        original = helper_histories[endpoint_role]["original"]
                    p.require(initial_requests["launchSha256"] == p.sha(_raw(prior["launchOriginal"], 65536))
                        and row["initialHistorySha256"] == p.sha(original))
                preparation.require_runtime(prep_raw,
                    runtime_raw, driver_observation_raw=_raw(value["driverObservationOriginal"], 65536),
                    cohort_observation_raw=_raw(observed["cohortObservationOriginal"], cohort.MAX_BYTES), peer_ids=ids)
            p.require(bridge_runtime.version(runtime) in (10, 11) or len(p.canonical(value)) <= bridge_install.MAX_INPUT)
            _same(runtime["generationAdmission"]["grants"], observed["ordinaryGenerationGrants"])
            _same(observed["ordinaryGenerationGrants"], {role: self._pins["ordinary-generation-" + role]["sha256"]
                for role in generation.ROLES})
            _same(runtime["journalDirectoryIdentity"], observed["bridgeJournal"])
            for role in commitment.ROLES:
                p.require(_raw(runtime["commitRequest"]["serviceGrantOriginals"][role], 65536)
                    == self._outputs["ordinary-dispatch-" + role])
            for field, output in (("headGrantOriginal", "ordinary-head"), ("cleanupGrantOriginal", "ordinary-cleanup"),
                                  ("currentGrantOriginal", "ordinary-current")):
                self._known(field, runtime["spool"], output)
            if bridge_runtime.version(runtime) in (10, 11):
                for role, row in runtime["ordinaryInitialHistories"].items():
                    prior = p.document(self._inputs["ordinary-generation-" + role], service_authority.MAX_INPUT_BYTES)
                    _same(row["runtimeOriginal"], prior["services"][role]["runtimeOriginal"])
                    p.require(_raw(row["generationGrantOriginal"], 65536) == self._outputs["ordinary-generation-" + role])
        elif job.family == "scope":
            _same(value["operationOriginal"], observed["operationOriginal"])
            self._known("bootstrapAdmissionOriginal", value, "driver-bootstrap")
            p.require(_raw(value["launchOriginal"], 32768) == self._public.read(
                self._installations["install-launch-bridge"]["launch"], maximum=32768))
            self._scope_bundle = _raw(value["publicBundleOriginal"], bridge_runtime.MAX_BRIDGE_INPUT)
            bundle = p.document(self._scope_bundle, bridge_runtime.MAX_BRIDGE_INPUT)
            _, runtime = bridge_runtime.original(bundle["runtimeOriginal"])
            p.require(bridge_runtime.version(runtime) in (10, 11) or len(self._scope_bundle) <= 1024 * 1024)
            prior = p.document(self._inputs["native-delivery-bridge"], delivery_authority.MAX_BRIDGE_INPUT)
            _same(bundle["runtimeOriginal"], prior["runtimeOriginal"])
            self._known("deliveryOriginal", bundle, "native-delivery-bridge")
            for role, original in p.fields(bundle["generationOriginals"], generation.ROLES).items():
                p.require(scope_authority._generation_original(original)[0] == self._outputs["ordinary-generation-" + role])
        elif job.family == "phase-two-public":
            if value.get("apiVersion") == phase_two.API:
                p.require(phase_two.prepare_input(p.canonical(value)) == self._scope_bundle)
            else:
                p.require(len(p.canonical(value)) <= 1024)
                p.fields(value, ("phaseTwoPublic",))

    @staticmethod
    def _array_original(value):
        # Activation is an existing canonical array, not p.document's object.
        import json
        p.require(type(value) is str and value.isascii() and 0 < len(value) <= 65536)
        decoded = json.loads(value, object_pairs_hook=p._pairs, parse_float=p._reject, parse_constant=p._reject)
        p.require(type(decoded) is list and p.canonical(decoded) == value.encode("ascii"))
        return decoded

    def _cohort_sign(self, operation, value, key):
        fields = ("apiVersion", "operation", "configurationOriginal", "configurationSha256", "coldOriginals", "payloadOriginal")
        p.fields(value, fields + (("precreationOriginal", "observationsOriginal") if operation == "release" else ()))
        p.require(value["apiVersion"] == "serverware.nativePilotCohortAuthorityInput/v1" and value["operation"] == operation)
        raw = _raw(value["configurationOriginal"], cohort.MAX_BYTES)
        digest = p.digest(value["configurationSha256"])
        config = cohort.configuration(raw)
        p.require(config["apiVersion"] == "serverware.nativeShadowProofCohortConfiguration/v7"
            and cohort.roles(config) == cohort.ENDPOINT_ROLES and p.sha(raw) == digest)
        cold = p.fields(value["coldOriginals"], cohort.ENDPOINT_ROLES)
        kwargs = {name: _raw(cold[role], 65536) for role, name in zip(cohort.ENDPOINT_ROLES, _COHORT_ARGUMENTS, strict=True)}
        if operation == "release":
            kwargs["precreation_raw"] = _raw(value["precreationOriginal"], cohort.MAX_BYTES)
            kwargs["observations_raw"] = _raw(value["observationsOriginal"], cohort.MAX_BYTES)
            producer = cohort.sign_release
        else:
            producer = cohort.sign_precreation
        return producer(configuration_raw=raw, configuration_sha256=digest, bridge_configuration_raw=None,
            payload_raw=_raw(value["payloadOriginal"], cohort.MAX_BYTES), boot=originals._boot(),
            now=originals._clock(), signing_key=key, **kwargs)

    def _perform(self, job, raw, value, key):
        signed = None
        deadline = self._request.deadline_boottime_ns
        if job.family == "driver":
            signed = driver_authority.sign(job.role, raw, key)
        elif job.family == "cohort":
            signed = self._cohort_sign(job.role, value, key)
        elif job.family == "delivery":
            signed = delivery_authority.sign(raw, key)
        elif job.family == "native-key":
            role, operation = KEY_AUTHORIZATION_JOB_INFO[job.name]
            signed, original_deadline = key_authority.sign(operation, role, raw, key)
            deadline = min(deadline, original_deadline)
            self._process._io_check(deadline)
        elif job.family == "native-launch-authorization":
            role, operation = LAUNCH_AUTHORIZATION_JOB_INFO[job.name]
            if operation == "closure":
                signed, original_deadline = closure_authority.sign(input_original=raw, signing_key=key)
            elif operation == "verifier-transport":
                signed, original_deadline = verifier_authority.sign(role, raw, key)
            else:
                signed, original_deadline = encrypted_authority.sign(
                    "delivery" if operation == "encrypted-delivery" else operation, role, raw, key)
            deadline = min(deadline, original_deadline)
            self._process._io_check(deadline)
        elif job.family == "bridge-authorization":
            operation = BRIDGE_AUTHORIZATION_JOB_INFO[job.name]
            if operation == "closure":
                signed, original_deadline = closure_authority.sign(input_original=raw, signing_key=key)
            else:
                signed, original_deadline = bridge_authority.sign(operation, raw, key)
            deadline = min(deadline, original_deadline)
            self._process._io_check(deadline)
        elif job.family == "native":
            signed = native_authority.sign(job.role, raw, key)
        elif job.family == "current-head":
            signed, original_deadline = current_head_authority.sign(input_original=raw, signing_key=key)
            deadline = min(deadline, original_deadline)
            self._process._io_check(deadline)
        elif job.family == "generation-install":
            signed, _ = generation_authority.sign(input_original=raw, signing_key=key)
        elif job.family in ("ordinary-initial", "helper-initial"):
            _, operation = (INITIAL_JOB_INFO if job.family == "ordinary-initial" else HELPER_INITIAL_JOB_INFO)[job.name]
            if operation == "assemble":
                p.require(key is None)
                signed, initial_deadline = initial_authority.assemble(input_original=raw)
            else:
                signed, initial_deadline = initial_authority.sign(operation, input_original=raw, signing_key=key)
            deadline = min(deadline, initial_deadline)
            self._process._io_check(deadline)
        elif job.family.startswith("ordinary-"):
            signed, _ = service_authority.sign(operation=job.family.removeprefix("ordinary-"), role=job.role,
                input_original=raw, signing_key=key)
        elif job.family == "scope":
            signed = scope_authority.sign(raw, key)
        if signed is not None:
            self._outputs[job.name] = signed  # Retain even if publication fails.
            self._bytes += len(signed)
            p.require(self._bytes <= MAX_RETAINED_BYTES)
            result = {"original": signed.decode("ascii"), "sha256": p.sha(signed)}
            if job.purpose is not None:
                self._process._io_check(deadline)
                pin = self._publisher.publish(purpose=job.purpose, raw=signed, expected_sha256=p.sha(signed))
                self._pins[job.name] = pin
                result["pin"] = pin  # Measured output of this approved job, not a new approval.
                self._process._io_check(deadline)
            return result
        if job.family == "precreation":
            result = precreation_install.install(raw, expected_sha256=p.sha(raw))
        elif job.family == "bridge-runtime":
            result = bridge_install.install(raw, expected_sha256=p.sha(raw))
        elif job.family == "launch":
            result = launch_install.install(raw, expected_sha256=p.sha(raw))
            _same(result["role"], job.role)
        elif job.family == "endpoint-inputs":
            p.fields(value, ("coldOriginals", "peer", "proofScope", "retrievalManifest", "objectDirectory", "assignment", "production"))
            for pin in p.fields(value["coldOriginals"], ENDPOINT_INPUT_ROLES).values():
                self._public.read(pin, maximum=p.MAX_CONFIG)
            for name, maximum in (("peer", 16384), ("proofScope", 16384), ("retrievalManifest", retrieval.MAX_MANIFEST),
                                  ("assignment", 4 * 1024 * 1024)):
                self._public.read(value[name], maximum=maximum)
            p.fields(value["production"], scope_authority.PRODUCTION_FIELDS)
            # The actual conductor alone opens/owns this separately provisioned
            # object store. A path here is not reconstructed resource evidence.
            p.require(type(value["objectDirectory"]) is str and value["objectDirectory"].startswith("/")
                and len(value["objectDirectory"]) <= 4096 and "\0" not in value["objectDirectory"])
            self._endpoint_inputs = copy.deepcopy(value)
            result = {"publicPinsOpened": True}
        elif job.family == "service-material":
            if value.get("apiVersion") == service_material.API:
                result = service_material.install(raw, expected_sha256=p.sha(raw))
                material = result["material"]
            else:
                # Original separately supplied pin-only protocol remains
                # bounded and does not acquire publication authority.
                p.require(len(raw) <= 32768)
                material = value
                result = {"publicPinsOpened": True}
            p.fields(material, ("persistence", "generationJournal"))
            persistence = p.fields(material["persistence"], ("configuration", "genesis", "journal"))
            for name, maximum in (("configuration", p.MAX_CONFIG), ("genesis", 16384), ("journal", 1024)):
                self._public.read(persistence[name], maximum=maximum)
            journal = p.fields(material["generationJournal"], ("genesis", "records"))
            self._public.read(journal["genesis"], maximum=MAX_RECORD)
            p.require(type(journal["records"]) is list and len(journal["records"]) <= MAX_RECORDS)
            for pin in journal["records"]:
                self._public.read(pin, maximum=MAX_RECORD)
            self._material = copy.deepcopy(material)
        elif job.family == "phase-two-public":
            if value.get("apiVersion") == phase_two.API:
                selected = phase_two.prepare_input(raw)
                p.require(selected == self._scope_bundle)
                self._process._io_check(deadline)
                pin = self._publisher.publish(purpose=phase_two.PURPOSE, raw=selected, expected_sha256=p.sha(selected))
                self._process._io_check(deadline)
                value = {"phaseTwoPublic": pin}
            else:
                p.require(len(raw) <= 1024)
                p.fields(value, ("phaseTwoPublic",))
            bundle = p.document(self._scope_bundle, bridge_runtime.MAX_BRIDGE_INPUT)
            _, runtime = bridge_runtime.original(bundle["runtimeOriginal"])
            maximum = bridge_runtime.MAX_BRIDGE_INPUT if bridge_runtime.version(runtime) in (10, 11) else 1024 * 1024
            p.require(self._public.read(value["phaseTwoPublic"], maximum=maximum) == self._scope_bundle)
            self._public_bundle_pin = copy.deepcopy(value["phaseTwoPublic"])
            result = {"pin": self._public_bundle_pin}
        else:
            p.require(job.family in ("origin", "stop"))
            p.fields(value, ("action",))
            p.require(value["action"] == ("observe-installed-generation" if job.family == "origin" else "stop"))
            result = dict(value)  # A requested action, never an installed verdict.
        self._installations[job.name] = result
        return result

    def complete(self):
        self._check(pending=True)
        p.require(not self.has_job() and self._ticket is None)
        phase = self._request.phase
        if phase == "bootstrap-admission":
            reply = {"bootstrapAdmission": self._pins["driver-bootstrap"]}
        elif phase in ("endpoint-precreation", "bridge-runtime"):
            reply = {}
        elif phase == "endpoint-inputs":
            reply = self._endpoint_inputs
        elif phase == "endpoint-deliveries":
            reply = {"endpointDeliveries": {role: self._pins["native-delivery-" + role] for role in ENDPOINT_INPUT_ROLES}}
        elif phase == "service-originals":
            reply = {"ordinaryDeliveries": {role: self._pins["ordinary-delivery-" + role] for role in generation.ROLES},
                "ordinaryGrants": {role: self._pins["ordinary-generation-" + role] for role in generation.ROLES},
                "dispatchGrants": {role: self._pins["ordinary-dispatch-" + role] for role in commitment.ROLES},
                "dispatchNativeGrant": self._pins["native-service-commitRequest"],
                "spoolGrants": {role: self._pins["ordinary-" + name] for name, role in
                    zip(("head", "cleanup", "current"), spool.EFFECT_ROLES, strict=True)},
                "nativeSpoolGrants": {name: self._pins["native-service-" + name] for name in spool.EFFECT_NATIVE},
                "endpointLaunches": {role: self._installations["install-launch-" + role]["launch"] for role in cohort.ENDPOINT_ROLES},
                **self._material}
        elif phase == "bridge-delivery":
            reply = {"launch": self._installations["install-launch-bridge"]["launch"]}
        elif phase == "release":
            reply = {"endpointRelease": self._pins["cohort-release"], "phaseTwoScope": self._pins["driver-scope"],
                "phaseTwoPublic": self._public_bundle_pin}
        elif phase == "constructed-admission":
            reply = {"constructedAdmission": self._pins["driver-constructed"]}
        else:
            reply = {"action": "observe-installed-generation" if phase == "generation-origin" else "stop"}
        self._failed = True
        self._process.reply(self._request, copy.deepcopy(reply))
        self._request = None
        self._phase_index += 1
        self._failed = False

    def close(self):
        """Release only after actual child cleanup, never retry any job or unlink."""
        global _LIVE
        if self._closed:
            return
        p.require(_LIVE is self and os.getpid() == self._pid and self._process._closed)
        p.require(self._process._result["status"] in ("not-started", "stopped-cleanup-complete", "failed-cleanup-complete"))
        for original in reversed(self._held):
            original.close()
        for fd, _ in self._keys.values():
            os.close(fd)
        if self._public is not None:
            self._public.close()
        if self._publisher is not None:
            self._publisher.close()
        self._closed = True
        _LIVE = None
