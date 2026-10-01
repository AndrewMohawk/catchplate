"""Eleven fixed service grants from actual completed commissioning owners.

Composition retains the ten authenticated key pairs, five ordinary services,
fixed public peer/manifest files and the same original conductor request. It
does not sign, allocate service resources, attest an empty store or renew a
window. Any failure consumes this attempt; public originals and descriptors
remain owned until the originating process reports genuine terminal cleanup.
"""
from __future__ import annotations

import time

from serverware import custody_generation_grants as generation
from serverware import native_pilot_delivery_authority as c9
from serverware import native_pilot_key_profile as key_profile
from serverware import native_pilot_native_service_authority as authority
from serverware import native_pilot_native_service_profile as profile
from serverware import native_pilot_ordinary_generation_profile as ordinary_profile
from serverware import native_pilot_ordinary_install as installation
from serverware import native_pilot_precreation_install as precreation
from serverware import native_pilot_publication as publication
from serverware import native_pilot_service_authority as ordinary_authority
from serverware import native_pilot_supervisor_endpoint_deliveries as endpoints
from serverware import native_pilot_supervisor_key_authorizations as keys
from serverware import native_pilot_supervisor_ordinary_generations as generations
from serverware import native_shadow_nitro_originals as originals
from serverware import native_shadow_proof_cohort_assignment as cohort
from serverware.native_pilot_phase_execution import JOBS, MAX_RETAINED_BYTES
from serverware.native_shadow_proof_cohort_control import _Original

p = generation.p
OPERATIONS = profile.OPERATIONS
FIRST_INDEX = 63
NEXT_JOB = "ordinary-dispatch-durable-recovery-store"
_TRANSITION_LAST_INDEX = 79
JOB_NAMES = tuple("native-generation-install-grant" if operation == "generationInstall"
    else "native-service-" + operation for operation in OPERATIONS)
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
        and FIRST_INDEX <= request.job_index < FIRST_INDEX + len(OPERATIONS))
    index = request.job_index - FIRST_INDEX
    p.require(request.job == JOB_NAMES[index]
        and tuple(job.name for job in JOBS["service-originals"][FIRST_INDEX - 1:
            FIRST_INDEX - 1 + len(OPERATIONS)]) == JOB_NAMES)
    return index


def checked_result(operation, input_raw, result, *, boot, now_boottime_ns, now_unix_ns):
    """Verify the actual fixed output pin and the profile's complete signature."""
    p.require(operation in OPERATIONS)
    p.fields(result, ("original", "sha256", "pin"))
    raw = profile.checked_result(operation, input_raw,
        {name: result[name] for name in ("original", "sha256")}, boot=boot,
        now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    purpose = JOB_NAMES[OPERATIONS.index(operation)]
    _same(result["pin"], {"path": publication.DESTINATIONS[purpose], "sha256": p.sha(raw)})
    return raw


class _Attempt:
    def __init__(self, policy, process):
        self.policy, self.process = policy, process
        self.next = self.retained_bytes = 0
        self.inflight = self.peer = self.manifest = None
        self.failed = self.closed = self.close_attempted = False
        self.transition_boundary_open = False
        self.inputs, self.outputs, self.results = {}, {}, {}
        self.pairs, self.pair_contexts, self.key_inputs = {}, {}, {}
        self.ordinary_inputs, self.ordinary_results = {}, {}
        self.ordinary_context = self.fragment = None
        self.phase_raw = self.installed_raw = self.endpoint_raw = None
        self.endpoint_delivery_raw = self.window = self.boot = self.deadline = None
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
    # This originating predecessor recursively rechecks the actual native C9,
    # ordinary generation/delivery, initial-history and recipe owners. Its
    # first boundary was opened only by _capture at the real job63.
    p.require(keys.recheck_authorizations(owner.policy, process=owner.process, request=request) == owner.pairs)
    phase = endpoints._phase(owner.process, "service-originals")
    p.require(p.canonical(phase) == owner.phase_raw
        and p.sha(owner.phase_raw) == request.value["conductorRequestSha256"]
        and request.deadline_boottime_ns == owner.deadline == p.ns(phase["deadlineBoottimeNs"]))
    p.require(_approved(owner.process, "endpoint-precreation", "install-precreation") == owner.installed_raw
        and _approved(owner.process, "endpoint-inputs", "endpoint-inputs") == owner.endpoint_raw)
    result = p.fields(owner.process.prior_result("endpoint-inputs", "endpoint-inputs"), ("publicPinsOpened",))
    p.require(result["publicPinsOpened"] is True)
    for job, raw in owner.key_inputs.items():
        p.require(_approved(owner.process, "service-originals", job) == raw)
    for role, raw in owner.ordinary_inputs.items():
        job = "ordinary-generation-" + role
        p.require(_approved(owner.process, "service-originals", job) == raw
            and generation.canonical(owner.process.prior_result("service-originals", job))
                == owner.ordinary_results[role])
    _same(owner.policy.native_service_policy(process=owner.process, request=request), owner.fragment)
    for original in (owner.peer, owner.manifest):
        if original is not None:
            original.check()
    p.require(originals._boot() == owner.boot)
    now, epoch = c9._live(owner.window, owner.last), time.time_ns()
    p.require(owner.last_wall <= epoch)
    owner.last, owner.last_wall = now, epoch
    # Only already composed operations (and the current operation) have to be
    # current. Their approved UNIX intervals are retained literally, not reset.
    count = owner.next + (1 if request.job in JOB_NAMES and owner.next < len(OPERATIONS) else 0)
    for operation in OPERATIONS[:count]:
        row = owner.fragment["operationWindows"][operation]
        p.freshness(row["issuedAtUnixNanos"], row["expiresAtUnixNanos"], epoch)
    return now, epoch


def _capture_pairs(owner, installed, observed):
    for role in keys.ROLES:
        first_job, second_job = "native-role-keys-" + role, "native-key-admission-" + role
        first = _approved(owner.process, "service-originals", first_job)
        second = _approved(owner.process, "service-originals", second_job)
        value = p.fields(p.document(first, key_profile.MAX_INPUT), key_profile.INPUT_FIELDS)
        p.require(value["role"] == role and value["operation"] == "role-keys")
        _, c9_input = c9._original(value["deliveryInputOriginal"], c9.MAX_INPUT)
        p.fields(c9_input, c9.INPUT_FIELDS)
        p.require(c9_input["configurationOriginal"] == installed["nativeColdOriginals"][role]
            and c9_input["ownerConfigurationOriginal"] == installed["cohortConfigurationOriginal"]
            and c9_input["windowOriginal"] == installed["cohortPrecreationOriginal"]
            and c9_input["observationOriginal"] == observed["cohortObservationOriginal"]
            and c9_input["activationOriginal"] == p.canonical(observed["nativeActivations"][role]).decode("ascii"))
        pair = p.fields(owner.pairs[role], ("roleKeyOriginal", "admissionOriginal"))
        context = {"roleKeyInputOriginal": first.decode("ascii"), "roleKeyOriginal": pair["roleKeyOriginal"].decode("ascii"),
            "admissionInputOriginal": second.decode("ascii"), "admissionOriginal": pair["admissionOriginal"].decode("ascii")}
        _reserve(owner, len(first) + len(second) + sum(len(raw) for raw in pair.values())
            + len(generation.canonical(context)))
        owner.key_inputs[first_job], owner.key_inputs[second_job] = first, second
        owner.pair_contexts[role] = context


def _capture_ordinary(owner, installed, request):
    actual = generations.recheck_generations(owner.policy, process=owner.process, request=request)
    p.fields(actual, generation.ROLES)
    services = {}
    for role in generation.ROLES:
        job = "ordinary-generation-" + role
        raw = _approved(owner.process, "service-originals", job)
        value = p.fields(p.document(raw, ordinary_authority.MAX_INPUT_BYTES), ordinary_profile.INPUT_FIELDS)
        p.require(value["operation"] == "generation" and value["serviceRole"] == role
            and value["launchOriginal"] == installed["ordinaryLaunchOriginal"])
        row = p.fields(p.fields(value["services"], (role,))[role], ordinary_profile.SERVICE_FIELDS)
        p.require(row["configurationOriginal"] == installed["ordinaryColdOriginals"][role]
            and row["configurationSha256"] == p.sha(row["configurationOriginal"].encode("ascii")))
        selected = p.fields(actual[role], ("deliveryOriginal", "runtimeOriginal", "historyOriginal", "generationGrantOriginal"))
        for name in ("deliveryOriginal", "runtimeOriginal", "historyOriginal"):
            p.require(row[name].encode("ascii") == selected[name])
        result = owner.process.prior_result("service-originals", job)
        p.require(result["original"].encode("ascii") == selected["generationGrantOriginal"])
        result_raw = generation.canonical(result)
        services[role] = {**row, "generationGrantOriginal": selected["generationGrantOriginal"].decode("ascii")}
        _reserve(owner, len(raw) + len(result_raw))
        owner.ordinary_inputs[role], owner.ordinary_results[role] = raw, result_raw
    owner.ordinary_context = {"launchOriginal": installed["ordinaryLaunchOriginal"], "services": services}
    _reserve(owner, len(generation.canonical(owner.ordinary_context)))


def _capture(owner, request):
    owner.pairs = keys.require_authorizations(owner.policy, process=owner.process, request=request)
    p.fields(owner.pairs, keys.ROLES)
    owner.fragment = profile.validate_policy(owner.policy.native_service_policy(process=owner.process, request=request))
    owner.phase_raw = p.canonical(endpoints._phase(owner.process, "service-originals"))
    observed = p.document(owner.phase_raw, 32 * 1024 * 1024)["payload"]
    owner.endpoint_delivery_raw = generation.canonical(observed["endpointDeliveryResult"])
    owner.installed_raw = _approved(owner.process, "endpoint-precreation", "install-precreation")
    installed = p.fields(p.document(owner.installed_raw, precreation.MAX_INPUT), precreation.FIELDS)
    window_raw, signed = c9._original(installed["cohortPrecreationOriginal"], cohort.MAX_BYTES)
    p.fields(signed, ("apiVersion", "payload", "signatureBase64url"))
    p.require(signed["apiVersion"] == "serverware.nativeShadowProofCohortPrecreation/v1")
    owner.window = p.fields(signed["payload"], cohort.WINDOW_FIELDS)
    owner.boot, owner.deadline = originals._boot(), p.ns(owner.window["startupDeadlineBoottimeNs"])
    owner.endpoint_raw = _approved(owner.process, "endpoint-inputs", "endpoint-inputs")
    endpoint = p.fields(p.document(owner.endpoint_raw, 65536),
        ("coldOriginals", "peer", "proofScope", "retrievalManifest", "objectDirectory", "assignment", "production"))
    _reserve(owner, sum(len(raw) for raw in (owner.phase_raw, owner.endpoint_delivery_raw, owner.installed_raw,
        owner.endpoint_raw, window_raw)) + len(generation.canonical(owner.fragment)))
    _capture_pairs(owner, installed, observed)
    _capture_ordinary(owner, installed, request)
    _current(owner, request)
    # Read only fixed, already published public originals. No directory,
    # credential, activation descriptor or new file is created by this owner.
    for field, purpose, attribute in (("peer", "endpoint-peer", "peer"),
            ("retrievalManifest", "endpoint-retrieval-manifest", "manifest")):
        pin = p.fields(endpoint[field], ("path", "sha256"))
        p.require(pin["path"] == publication.DESTINATIONS[purpose])
        retained = _Original(pin["path"], publication.LIMITS[purpose], p.digest(pin["sha256"]), mode=0o400)
        setattr(owner, attribute, retained)  # Retain immediately, even if the next check refuses.
        _reserve(owner, len(retained.raw))
        _current(owner, request)


def _prior(owner, *, now, epoch):
    for operation, job in zip(OPERATIONS[:owner.next], JOB_NAMES[:owner.next], strict=True):
        raw = _approved(owner.process, "service-originals", job)
        p.require(raw == owner.inputs[operation])
        result = owner.process.prior_result("service-originals", job)
        verified = checked_result(operation, raw, result, boot=owner.boot,
            now_boottime_ns=now, now_unix_ns=epoch)
        result_raw = generation.canonical(result)
        if operation not in owner.outputs:
            _reserve(owner, len(verified) + len(result_raw))
            owner.outputs[operation], owner.results[operation] = verified, result_raw
        else:
            p.require(owner.outputs[operation] == verified and owner.results[operation] == result_raw)


def compose(policy, *, process, request) -> bytes:
    """One complete existing authority input from the originating live owners."""
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
        operation = OPERATIONS[index]
        previous = ("commitRequest",) if operation == "ledger" else authority.SIGNERS if operation == "retrieval" else ()
        raw = profile.build(operation, fragment=owner.fragment,
            pair_context=owner.pair_contexts[profile.ENDPOINT_ROLES[operation]], ordinary_context=owner.ordinary_context,
            peer_raw=owner.peer.raw, retrieval_manifest_raw=owner.manifest.raw,
            endpoint_delivery_result_raw=owner.endpoint_delivery_raw,
            prior_native_originals={name: owner.outputs[name] for name in previous}, boot=owner.boot,
            now_boottime_ns=now, now_unix_ns=epoch)
        p.require(type(raw) is bytes and 0 < len(raw) <= JOBS["service-originals"][request.job_index - 1].maximum)
        _current(owner, request)
        _reserve(owner, len(raw))
        owner.inputs[operation] = raw
        owner.next += 1
        owner.inflight = None
        return raw
    except BaseException:
        owner.failed = True
        raise


def require_services(policy, *, process, request) -> dict:
    """Verified literal input/grant pairs only at the actual next fixed job74."""
    return _verified_services(policy, process=process, request=request, first=True)


def recheck_services(policy, *, process, request) -> dict:
    """Recheck an opened boundary through fixed transition jobs and handoff79."""
    return _verified_services(policy, process=process, request=request, first=False)


def _verified_services(policy, *, process, request, first):
    _owners(policy, process, request)
    owner = _LIVE
    p.require(owner is not None and owner.policy is policy and owner.process is process
        and not owner.failed and not owner.closed and owner.inflight is None and owner.next == len(OPERATIONS)
        and installation.native_completed_boundary(request)
        and FIRST_INDEX + len(OPERATIONS) <= request.job_index <= _TRANSITION_LAST_INDEX
        and (request.job_index == FIRST_INDEX + len(OPERATIONS) and request.job == NEXT_JOB
             if first else owner.transition_boundary_open))
    owner.inflight = request
    try:
        now, epoch = _current(owner, request)
        _prior(owner, now=now, epoch=epoch)
        _current(owner, request)
        p.require(tuple(owner.outputs) == OPERATIONS)
        result = {operation: {"inputOriginal": owner.inputs[operation], "grantOriginal": owner.outputs[operation]}
            for operation in OPERATIONS}
        owner.transition_boundary_open = True
        owner.inflight = None
        return result
    except BaseException:
        owner.failed = True
        raise


def close(process):
    """Release only after real originating-process cleanup; never reset/retry."""
    global _LIVE
    if _LIVE is None:
        return
    from serverware.native_pilot_supervisor_process import AuthorityCoordinatorProcess
    owner = _LIVE
    p.require(type(process) is AuthorityCoordinatorProcess and owner.process is process and process._closed
        and not owner.close_attempted
        and process._result["status"] in ("not-started", "stopped-cleanup-complete", "failed-cleanup-complete"))
    owner.close_attempted = True
    for original in (owner.manifest, owner.peer):
        if original is not None:
            original.close()
    owner.inputs.clear(); owner.outputs.clear(); owner.results.clear()
    owner.key_inputs.clear(); owner.pair_contexts.clear(); owner.pairs.clear()
    owner.ordinary_inputs.clear(); owner.ordinary_results.clear()
    owner.closed = True
    _LIVE = None
