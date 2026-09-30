"""Twenty-five fixed initial-history inputs from one real retained request.

The independently admitted policy selects public authorities, generations and
revocation facts. Only actual preparation/resource originals supply process,
directory and time facts. Each later input uses verified prior public results;
nothing signs, publishes, opens secrets, invents history or renews a window.
Failed composition fences the retained attempt until genuine process cleanup.
"""
from __future__ import annotations

import copy

from serverware import custody_generation_grants as generation
from serverware import native_pilot_ordinary_initial_authority as issuer
from serverware import native_pilot_ordinary_initial_profile as initial
from serverware import native_pilot_ordinary_key_authority as history
from serverware import native_pilot_ordinary_key_profile as key
from serverware import native_pilot_precreation_install as precreation
from serverware import native_pilot_publication as publication
from serverware import native_pilot_service_authority as service
from serverware import native_pilot_supervisor_endpoint_deliveries as endpoints
from serverware import native_pilot_window_authority as window_authority
from serverware import native_shadow_driver_bootstrap as driver
from serverware import native_shadow_nitro_originals as originals
from serverware.native_pilot_phase_execution import INITIAL_JOBS, INITIAL_JOB_INFO

p = generation.p
POLICY_API = "serverware.nativePilotSupervisorOrdinaryInitialPolicy/v1"
VALIDITY = "observed-initial-resources-through-original-lifetime"
ROLE_FIELDS = ("authorities", "endpointRole", "endpointGeneration", "serviceGeneration", "operationGeneration",
    "durableEpoch", "deploymentGenerationSha256", "revocationGenerationHighWater", "revocationRootSha256", "validity")
GENERATIONS = ("endpointGeneration", "serviceGeneration", "operationGeneration", "durableEpoch")
_LIVE = None
_USED = False


def _same(first, second):
    p.require(generation.canonical(first) == generation.canonical(second))


def _keys(value):
    p.fields(value, issuer.KEY_NAMES)
    selected = {name: history._key(value[name]) for name in issuer.KEY_NAMES}
    p.require(len({item["keyId"] for item in value.values()}) == 3
        and len({item["keySpkiSha256"] for item in value.values()}) == 3
        and len({history._raw_key(item) for item in selected.values()}) == 3)
    return selected


def validate_policy(fragment, *, ordinary_cold_originals, driver_configuration) -> dict:
    """Pure static delegation grammar; not independent approval by itself."""
    p.fields(fragment, ("apiVersion", "services"))
    p.require(fragment["apiVersion"] == POLICY_API)
    rows = p.fields(fragment["services"], generation.ROLES)
    cold = p.fields(ordinary_cold_originals, generation.ROLES)
    excluded = [driver_configuration["bootstrapAuthority"], driver_configuration["phaseTwoAuthority"],
        driver_configuration["lifecycle"]["constructedAdmissionAuthority"]]
    for role in generation.ROLES:
        raw, _ = history._original(cold[role], 65536)
        excluded.append(generation.configuration(raw, p.sha(raw), role)["authority"])
    for value in excluded:
        driver._key(value)
    for role, row in rows.items():
        p.fields(row, ROLE_FIELDS)
        p.require(row["endpointRole"] in key.ENDPOINT_ROLES and row["validity"] == VALIDITY
            and (role != generation.ROLES[0] or row["endpointRole"] == "settlement-store"))
        for name in GENERATIONS + ("revocationGenerationHighWater",):
            p.integer(row[name], maximum=p.MAX_U64)
        for name in ("deploymentGenerationSha256", "revocationRootSha256"):
            p.digest(row[name])
        for name, public in _keys(row["authorities"]).items():
            for blocked in excluded:
                p.require(history._raw_key(public) != p.decoded(blocked["publicKeyBase64url"], size=32)
                    and row["authorities"][name]["keyId"] != blocked["keyId"])
    # Across-role reuse is allowed only because every row is explicitly pinned.
    return copy.deepcopy(fragment)


def _result_context(role, operation, input_raw):
    """Pure prior-result transcript check, not host/approval authentication."""
    p.require(role in generation.ROLES and operation in issuer.OPERATIONS)
    extra = () if operation == "checkpoint" else ("initialCheckpointOriginal",)
    if operation == "assemble":
        extra += ("anchorSignatures",)
    value = p.fields(p.document(input_raw, issuer.MAX_INPUT), issuer.COMMON_FIELDS + extra)
    p.require(value["apiVersion"] == issuer.INPUT_API and value["operation"] == operation)
    _, state = history._original(value["initialStateOriginal"], initial.MAX_STATE)
    initial.validate_state(state)
    p.require(state["serviceRole"] == role)
    authorities = value["authorities"]
    keys = _keys(authorities)
    _, payload = history._original(value["payloadOriginal"], issuer.MAX_CHECKPOINT)
    key.validate_payload_shape(payload)
    issuer._initial_payload(state, payload, authorities)
    p.require(payload["validFromBoottime"]["absoluteBoottimeNanos"] == p.ns(state["issuedAtBoottimeNs"])
        and payload["validUntilBoottime"]["absoluteBoottimeNanos"] == p.ns(state["lifetimeDeadlineBoottimeNs"]))
    preparation_raw, _ = history._original(value["preparationOriginal"], key.MAX_PREPARATION)
    resources_raw, _ = history._original(value["resourcesOriginal"], initial.MAX_STATE)
    launch_raw, _ = history._original(value["launchOriginal"], 65536)
    _, configuration = history._original(value["configurationOriginal"], 65536)
    _, signed_window = history._original(value["driverWindowOriginal"], 32768)
    identity = initial.prepared_state(state, preparation_raw=preparation_raw, resources_raw=resources_raw,
        launch_raw=launch_raw, configuration=configuration, window=signed_window["payload"],
        endpoint_role=payload["endpointRole"], now=p.ns(state["issuedAtBoottimeNs"]))
    return value, state, identity, payload, authorities, keys


def checked_result(role, operation, input_raw, result) -> bytes:
    """Verify a public result; the caller separately proves input/owner origin."""
    value, state, identity, payload, authorities, keys = _result_context(role, operation, input_raw)
    p.fields(result, ("original", "sha256", "pin") if operation == "assemble" else ("original", "sha256"))
    bound = issuer.MAX_OUTPUT if operation == "assemble" else issuer.MAX_CHECKPOINT if operation == "checkpoint" else issuer.MAX_SIGNATURE
    raw, output = history._original(result["original"], bound)
    p.require(p.sha(raw) == p.digest(result["sha256"]))
    if operation == "checkpoint":
        initial.validate_checkpoint(state, output, checkpoint_authority=authorities["checkpoint"], service_key=authorities["service"])
        _same(output["payload"], payload)
        return raw
    checkpoint = issuer._checkpoint(value, state, payload, authorities)
    anchor, anchor_raw, message = issuer._anchor(state, identity, authorities, checkpoint)
    if operation != "assemble":
        name = operation.removesuffix("-anchor")
        p.fields(output, issuer.SIGNATURE_FIELDS)
        p.require(output["apiVersion"] == issuer.SIGNATURE_API and output["signer"] == name
            and output["anchorPayloadSha256"] == p.sha(anchor_raw)
            and output["keyId"] == authorities[name]["keyId"]
            and output["keySpkiSha256"] == authorities[name]["keySpkiSha256"])
        keys[name].verify(p.decoded(output["signatureBase64"], size=64), message)
        return raw
    p.fields(output, initial.WRAPPER_FIELDS)
    p.require(output["apiVersion"] == initial.WRAPPER_API)
    _same(output["initialState"], state); _same(output["initialCheckpoint"], checkpoint)
    p.fields(value["anchorSignatures"], issuer.KEY_NAMES)
    for name, field in zip(issuer.KEY_NAMES, issuer.ANCHOR_SIGNATURE_FIELDS, strict=True):
        _, record = history._original(value["anchorSignatures"][name], issuer.MAX_SIGNATURE)
        p.fields(record, issuer.SIGNATURE_FIELDS)
        p.require(record["apiVersion"] == issuer.SIGNATURE_API and record["signer"] == name
            and record["anchorPayloadSha256"] == p.sha(anchor_raw)
            and record["keyId"] == authorities[name]["keyId"]
            and record["keySpkiSha256"] == authorities[name]["keySpkiSha256"])
        keys[name].verify(p.decoded(record["signatureBase64"], size=64), message)
        anchor[field] = record["signatureBase64"]
    anchor["retainedAnchorSha256"] = p.framed(history.ANCHOR_DIGEST_DOMAIN,
        (anchor_raw, *(anchor[name].encode("ascii") for name in issuer.ANCHOR_SIGNATURE_FIELDS)))
    verified = initial.manifest(raw, role=role,
        root_pin={name: authorities["root"][name] for name in ("keyId", "keySpkiSha256")})
    _same(verified["rootAuthority"], authorities["root"])
    _same(verified["firstRetainedEpoch"], anchor)
    _same(result["pin"], {"path": publication.DESTINATIONS["ordinary-initial-history-" + role], "sha256": p.sha(raw)})
    return raw


def _owners(policy, process, request):
    from serverware.native_pilot_supervisor_policy import SupervisorPolicy
    from serverware.native_pilot_supervisor_process import AuthorityCoordinatorProcess, JobRequest

    p.require(type(policy) is SupervisorPolicy and type(process) is AuthorityCoordinatorProcess and type(request) is JobRequest)
    policy.check(process); process.check_request(request)


class _Attempt:
    def __init__(self, policy, process):
        self.policy, self.process = policy, process
        self.inputs = {}
        self.phase_raw = self.fragment = None
        self.next = 0
        self.failed = self.closed = False


def _attempt(policy, process, request):
    global _LIVE, _USED
    _owners(policy, process, request)
    if _LIVE is None:
        p.require(not _USED and request.phase == "service-originals" and request.job_index == 1
            and request.job == INITIAL_JOBS[0].name)
        _USED = True
        _LIVE = _Attempt(policy, process)
    p.require(_LIVE.policy is policy and _LIVE.process is process and not _LIVE.closed and not _LIVE.failed)
    return _LIVE


def _context(owner, request):
    policy, process = owner.policy, owner.process
    endpoints.require_deliveries(policy, process=process, request=request)
    fragment = policy.ordinary_initial_policy(process=process, request=request)
    phase = endpoints._phase(process, "service-originals")
    phase_raw = p.canonical(phase)
    p.require(p.sha(phase_raw) == request.value["conductorRequestSha256"]
        and request.deadline_boottime_ns == p.ns(phase["deadlineBoottimeNs"]))
    if owner.phase_raw is None:
        owner.phase_raw, owner.fragment = phase_raw, copy.deepcopy(fragment)
    p.require(owner.phase_raw == phase_raw); _same(owner.fragment, fragment)
    approved = policy.bootstrap_originals()
    retained = process.bootstrap_originals()
    p.require(all(type(raw) is bytes and raw == retained[name] for name, raw in approved.items()))
    config = window_authority.validate_configuration(approved["configuration"])
    signed = p.fields(p.document(approved["window"], 32768), ("apiVersion", "payload", "signatureBase64url"))
    p.require(signed["apiVersion"] == "serverware.nativeShadowDriverBootstrapWindow/v1")
    window = signed["payload"]
    driver._key(config["bootstrapAuthority"]).verify(p.decoded(signed["signatureBase64url"], size=64),
        driver.WINDOW_DOMAIN + p.canonical(window))
    before, boot = originals._clock(), originals._boot()
    window_authority.validate_window(window, approved["configuration"], config, boot=boot, now=before)
    p.require(before < request.deadline_boottime_ns <= p.ns(window["startupDeadlineBoottimeNs"]))
    installed_raw = process.approved_input_original("endpoint-precreation", "install-precreation")
    p.require(p.sha(installed_raw) == process.approved_input_sha256("endpoint-precreation", "install-precreation"))
    installed = p.fields(p.document(installed_raw, precreation.MAX_INPUT), precreation.FIELDS)
    p.require(installed["driverConfigurationOriginal"] == approved["configuration"].decode("ascii")
        and installed["driverWindowOriginal"] == approved["window"].decode("ascii"))
    _same(installed["ordinaryColdOriginals"], policy.precreation()["ordinaryColdOriginals"])
    validate_policy(fragment, ordinary_cold_originals=installed["ordinaryColdOriginals"], driver_configuration=config)
    bindings = process.policy_bindings()["keyBindings"]
    for role, row in fragment["services"].items():
        for name, public in _keys(row["authorities"]).items():
            p.require(bindings["ordinary-initial-" + name + "-" + role] == p.sha(history._raw_key(public)))
    launch_raw, _ = history._original(installed["ordinaryLaunchOriginal"], 65536)
    launch, startup, lifetime = service._launch(launch_raw, boot, before)
    p.require(startup == p.ns(window["startupDeadlineBoottimeNs"])
        and lifetime == p.ns(window["lifetimeDeadlineBoottimeNs"]) and launch["invocationId"] == window["invocationId"])
    observed = phase["payload"]
    preparation_raw, _ = history._original(observed["ordinaryPreparationOriginal"], key.MAX_PREPARATION)
    measured = key.preparation(preparation_raw)
    resources_raw, _ = history._original(observed["ordinaryInitialResourcesOriginal"], initial.MAX_STATE)
    resources = initial.resources(resources_raw)
    result = {}
    for role, row in fragment["services"].items():
        cold_raw, _ = history._original(installed["ordinaryColdOriginals"][role], 65536)
        cold = generation.configuration(cold_raw, launch["services"][role]["deliveryConfiguration"]["sha256"], role)
        identity = key.prepared_identity(measured, role=role, endpoint_role=row["endpointRole"],
            launch=launch, configuration=cold, window=window, now=before)
        state = {"apiVersion": initial.STATE_API, "serviceRole": role,
            "preparationSha256": p.sha(preparation_raw), "resourcesSha256": p.sha(resources_raw),
            "launchSha256": p.sha(launch_raw), "endpointProcessIdentitySha256": identity["identitySha256"],
            **{name: measured[name] for name in ("bootIdBase64url", "timeNamespaceDevice", "timeNamespaceInode",
                "startupDeadlineBoottimeNs", "lifetimeDeadlineBoottimeNs", "invocationId")},
            "issuedAtBoottimeNs": resources["issuedAtBoottimeNs"], "deploymentGenerationSha256": row["deploymentGenerationSha256"],
            **{name: row[name] for name in GENERATIONS}, "directories": resources["services"][role]["directories"]}
        initial.prepared_state(state, preparation_raw=preparation_raw, resources_raw=resources_raw,
            launch_raw=launch_raw, configuration=cold, window=window, endpoint_role=row["endpointRole"], now=before)
        domain = key._boot(state)
        payload = {"apiVersion": key.KEY_API, "endpointRole": row["endpointRole"],
            "endpointProcessIdentitySha256": identity["identitySha256"], "exactEndpointGeneration": row["endpointGeneration"],
            "authorizedSigningKeyId": row["authorities"]["service"]["keyId"],
            "authorizedSigningKeySpkiSha256": row["authorities"]["service"]["keySpkiSha256"], "checkpointSequence": 1,
            "predecessorCheckpointSha256": initial.commitments(state)["predecessorCheckpointSha256"],
            "revocationGenerationHighWater": row["revocationGenerationHighWater"], "revocationRootSha256": row["revocationRootSha256"],
            "revocationStatus": "authorized-and-not-revoked", "rollbackFloorCheckpointSequence": 1,
            "rollbackFloorEndpointGeneration": row["endpointGeneration"], "rollbackFloorConsumerSequence": 1,
            "validFromBoottime": {"domain": domain, "absoluteBoottimeNanos": p.ns(state["issuedAtBoottimeNs"])},
            "validUntilBoottime": {"domain": domain, "absoluteBoottimeNanos": lifetime}}
        key.validate_payload(payload, identity=identity, window=window, now=before)
        result[role] = {"apiVersion": issuer.INPUT_API, "driverConfigurationOriginal": approved["configuration"].decode("ascii"),
            "driverWindowOriginal": approved["window"].decode("ascii"), "launchOriginal": launch_raw.decode("ascii"),
            "configurationOriginal": cold_raw.decode("ascii"), "preparationOriginal": preparation_raw.decode("ascii"),
            "resourcesOriginal": resources_raw.decode("ascii"), "initialStateOriginal": generation.canonical(state).decode("ascii"),
            "authorities": copy.deepcopy(row["authorities"]), "payloadOriginal": generation.canonical(payload).decode("ascii")}
    p.require(originals._boot() == boot and before <= originals._clock() < request.deadline_boottime_ns)
    _owners(policy, process, request)
    return result


def _previous(owner, count):
    outputs = {}
    for job in INITIAL_JOBS[:count]:
        expected = owner.inputs[job.name]
        raw = owner.process.approved_input_original("service-originals", job.name)
        p.require(raw == expected and p.sha(raw) == owner.process.approved_input_sha256("service-originals", job.name))
        result = owner.process.prior_result("service-originals", job.name)
        role, operation = INITIAL_JOB_INFO[job.name]
        outputs[job.name] = (checked_result(role, operation, raw, result), copy.deepcopy(result))
    return outputs


def compose(policy, *, process, request) -> bytes:
    owner = _attempt(policy, process, request)
    p.require(request.phase == "service-originals" and request.job in INITIAL_JOB_INFO
        and request.job_index == owner.next + 1 and INITIAL_JOBS[owner.next].name == request.job)
    owner.failed = True
    bases = _context(owner, request)
    outputs = _previous(owner, owner.next)
    role, operation = INITIAL_JOB_INFO[request.job]
    value = {**bases[role], "operation": operation}
    if operation != "checkpoint":
        value["initialCheckpointOriginal"] = outputs["ordinary-initial-checkpoint-" + role][0].decode("ascii")
    if operation == "assemble":
        value["anchorSignatures"] = {name: outputs["ordinary-initial-" + name + "-anchor-" + role][0].decode("ascii")
            for name in issuer.KEY_NAMES}
    raw = p.canonical(value)
    p.require(len(raw) <= issuer.MAX_INPUT)
    _result_context(role, operation, raw)
    _owners(policy, process, request)
    owner.inputs[request.job] = raw
    owner.next += 1
    owner.failed = False
    return raw


def require_histories(policy, *, process, request) -> dict:
    """Actual five final wrapper results at the first ordinary delivery only."""
    owner = _attempt(policy, process, request)
    p.require(request.phase == "service-originals" and request.job_index == len(INITIAL_JOBS) + 1
        and request.job == "ordinary-delivery-" + generation.ROLES[0] and owner.next == len(INITIAL_JOBS))
    owner.failed = True
    _context(owner, request)
    outputs = _previous(owner, len(INITIAL_JOBS))
    result = {role: outputs["ordinary-initial-assemble-" + role][1] for role in generation.ROLES}
    _owners(policy, process, request)
    owner.failed = False
    return result


def close(process):
    """Keep public attempt state until its actual process cleanup is known."""
    global _LIVE
    if _LIVE is None:
        return
    from serverware.native_pilot_supervisor_process import AuthorityCoordinatorProcess
    p.require(type(process) is AuthorityCoordinatorProcess and _LIVE.process is process and process._closed
        and process._result["status"] in ("not-started", "stopped-cleanup-complete", "failed-cleanup-complete"))
    _LIVE.closed = True
    _LIVE.inputs.clear()
    _LIVE = None
