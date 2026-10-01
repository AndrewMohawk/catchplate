"""Source-fixed adopted jobs and literal predecessor joins, not live owners.

Every input still needs separate independent approval. Public source validation
does not mint that approval or reconstruct the conductor, core, or services.
The old phase catalogue and its key capabilities are deliberately unchanged.
"""
from __future__ import annotations

from serverware import native_pilot_phase_execution as legacy
from serverware import native_pilot_adopted_commands as commands
from serverware import native_pilot_adopted_cohort_authority as cohort_authority
from serverware import native_pilot_adopted_delivery as delivery
from serverware import native_pilot_ordinary_publication_authority as publication
from serverware import native_pilot_publication_adoption_profile as adoption
from serverware import native_pilot_interactive as interactive

p, g = legacy.p, legacy.generation
API = "serverware.nativePilotAuthorityJobRequest/v2"
REPLY_API = "serverware.nativePilotAuthorityJobReply/v2"
APPROVAL_API = "serverware.nativePilotAuthorityJobApproval/v2"
APPROVAL_ROOT = "/etc/serverware/native-pilot-adopted-authority"
MAX_APPROVAL = legacy.MAX_APPROVAL
MAX_RETAINED_BYTES = legacy.MAX_RETAINED_BYTES
MAX_FRAME = 32 * 1024 * 1024
ADOPTION_INPUT_API = "serverware.nativePilotAdoptionJobInput/v1"
INSTALLATION_API = "serverware.nativePilotAdoptedOrdinaryInstallationInput/v1"
ENDPOINTS = delivery.ROLES
COMPOSITE = ("retrieval", "persistence", "trustedTime", "publicationReconciliation")
PUBLICATION_ROLES = (g.ROLES[0], g.ROLES[3])
REQUEST_FIELDS = ("apiVersion", "sequence", "conductorSequence", "conductorRequestSha256", "phase",
    "jobIndex", "job", "deadlineBoottimeNs", "expiresAtUnixNanos", "conductorRequest", "previousResult")
APPROVAL_FIELDS = ("apiVersion", "conductorSequence", "conductorRequestSha256", "phase", "jobIndex", "job",
    "deadlineBoottimeNs", "expiresAtUnixNanos", "inputSha256")
REPLY_FIELDS = ("apiVersion", "sequence", "conductorSequence", "conductorRequestSha256", "phase", "jobIndex",
    "job", "requestSha256", "approvalSha256", "inputSha256")
_signed, _plain = legacy._signed, legacy._plain
KEY_INFO = {("native-role-keys-" if op == "role-keys" else "native-key-admission-") + role: (role, op)
    for role in ENDPOINTS for op in ("role-keys", "admission")}
AUTH_INFO = {"native-" + op + "-" + role: (role, op) for role in ENDPOINTS
    for op in (("closure", "request-commitment", "encrypted-delivery", "verifier-transport")
        if role == "commitRequest" else ("closure", "encrypted-delivery", "verifier-transport"))}
NATIVE_ENDPOINT = {**legacy._NATIVE_ENDPOINT, "publication": "publicationReconciliation"}
GRANT_FOR_ENDPOINT = {role: op for op, role in NATIVE_ENDPOINT.items() if op != "commitRequest"}
# All six historical signers precede retrieval; publication also precedes it.
_NATIVE_ORDER = tuple(op for op in legacy.native_authority.OPERATIONS if op not in ("commitRequest", "retrieval"))
JOBS = {
    "bootstrap-admission": legacy.JOBS["bootstrap-admission"],
    "endpoint-precreation": (
        _signed("cohort-precreation", "cohort", "precreation", cohort_authority.MAX_INPUT),
        _plain("install-precreation", "precreation", legacy.precreation_install.MAX_INPUT)),
    "endpoint-inputs": (*legacy.INITIAL_JOBS, *legacy.HELPER_INITIAL_JOBS,
        _plain("install-ordinary-runtime", "ordinary-installation", MAX_FRAME),
        *(_signed("ordinary-delivery-" + role, "ordinary-delivery", role,
            legacy.service_authority.MAX_INPUT_BYTES, "ordinary-delivery-" + role) for role in g.ROLES),
        _signed("publication-adoption", "adoption", None, MAX_FRAME, "publication-adoption"),
        _plain("endpoint-inputs", "endpoint-inputs", 65536)),
    "endpoint-deliveries": tuple(_signed("native-delivery-" + role, "delivery", role,
        delivery.MAX_INPUT, "native-delivery-" + role) for role in COMPOSITE),
    "service-originals": (
        *(_signed("ordinary-generation-" + role, "ordinary-generation", role,
            legacy.service_authority.MAX_INPUT_BYTES, "ordinary-generation-" + role) for role in g.ROLES),
        *(_signed("native-delivery-" + role, "delivery", role, delivery.MAX_INPUT,
            "native-delivery-" + role) for role in ENDPOINTS if role not in COMPOSITE),
        *(_signed(name, "native-key", role, legacy.key_authority.MAX_INPUT) for name, (role, _) in KEY_INFO.items()),
        _signed("native-service-commitRequest", "native", "commitRequest", commands.MAX_INPUT,
            "native-service-commitRequest"),
        *(_signed("native-service-" + op, "native", op, commands.MAX_INPUT, "native-service-" + op)
            for op in (*_NATIVE_ORDER, "publication", "retrieval")),
        _signed("native-generation-install-grant", "generation-install", None,
            legacy.generation_authority.MAX_INPUT_BYTES, "native-generation-install-grant"),
        *(_signed("ordinary-dispatch-" + role, "ordinary-dispatch", role,
            legacy.service_authority.MAX_INPUT_BYTES, "ordinary-dispatch-" + role) for role in legacy.commitment.ROLES),
        *(_signed("ordinary-" + op, "ordinary-" + op, role, legacy.service_authority.MAX_INPUT_BYTES,
            "ordinary-" + op) for op, role in zip(("head", "cleanup", "current"), legacy.spool.EFFECT_ROLES, strict=True)),
        *(_signed("ordinary-publication-" + role, "ordinary-publication", role,
            publication.MAX_INPUT, "ordinary-publication-" + role) for role in PUBLICATION_ROLES),
        *(_signed(name, "native-launch-authorization", role, commands.MAX_INPUT)
            for name, (role, _) in AUTH_INFO.items()),
        *(_plain("install-launch-" + role, "launch", legacy.launch_install.MAX_INPUT, role) for role in ENDPOINTS),
        _plain("service-material", "service-material", legacy.service_material.MAX_INPUT)),
    "bridge-runtime": legacy.JOBS["bridge-runtime"],
    "bridge-delivery": legacy.JOBS["bridge-delivery"],
    "release": (_signed("cohort-release", "cohort", "release", cohort_authority.MAX_INPUT, "cohort-release"),
        *legacy.JOBS["release"][1:]),
    "constructed-admission": legacy.JOBS["constructed-admission"],
    "generation-origin": legacy.JOBS["generation-origin"],
    "shutdown": legacy.JOBS["shutdown"],
}
KEY_PURPOSES = tuple(sorted({job.key for rows in JOBS.values() for job in rows if job.key is not None}))
BY_NAME = {job.name: (phase, job) for phase, rows in JOBS.items() for job in rows}


def job_index(phase, name):
    p.require(type(phase) is str and phase in JOBS and name in BY_NAME and BY_NAME[name][0] == phase)
    return tuple(job.name for job in JOBS[phase]).index(name) + 1


def _same(a, b):
    p.require(g.canonical(a) == g.canonical(b))


def _raw(value, maximum=MAX_FRAME):
    p.require(type(value) is str and value.isascii())
    raw = value.encode("ascii")
    p.document(raw, maximum)
    return raw


def _result(prior, name):
    row = p.fields(prior[name], ("input", "result"))
    p.require(type(row["input"]) is bytes and type(row["result"]) is dict)
    return row["result"]


def _output(prior, name):
    result = _result(prior, name)
    raw = _raw(result["original"])
    p.require(p.sha(raw) == p.digest(result["sha256"]))
    return raw


def _input(prior, name):
    _result(prior, name)
    return p.document(prior[name]["input"], BY_NAME[name][1].maximum)


def _literal(value, field, prior, name, *, output=True):
    p.require(_raw(value[field]) == (_output(prior, name) if output else prior[name]["input"]))


def _pair(prior, role):
    return {"roleKeyInputOriginal": prior["native-role-keys-" + role]["input"].decode("ascii"),
        "roleKeyOriginal": _output(prior, "native-role-keys-" + role).decode("ascii"),
        "admissionInputOriginal": prior["native-key-admission-" + role]["input"].decode("ascii"),
        "admissionOriginal": _output(prior, "native-key-admission-" + role).decode("ascii")}


def _prefix(name, phase, prior, observations):
    p.require(name in BY_NAME and BY_NAME[name][0] == phase)
    names = tuple(BY_NAME)
    p.require(type(prior) is dict and set(prior) == set(names[:names.index(name)]))
    phases = tuple(JOBS)
    p.require(type(observations) is dict and set(observations) == set(phases[:phases.index(phase) + 1]))
    for entry in prior:
        _result(prior, entry)
    return BY_NAME[name][1]


def _initial(job, value, prior, observed):
    supplemental = job.family == "helper-initial"
    if supplemental:
        slot, operation = legacy.HELPER_INITIAL_JOB_INFO[job.name]
        role, stem, suffix = g.ROLES[-1], "ordinary-helper-initial-", "-slot" + str(slot)
    else:
        role, operation = legacy.INITIAL_JOB_INFO[job.name]
        stem, suffix = "ordinary-initial-", "-" + role
    installed = _input(prior, "install-precreation")
    for target, source in (("launchOriginal", "ordinaryLaunchOriginal"),
            ("driverConfigurationOriginal", "driverConfigurationOriginal"),
            ("driverWindowOriginal", "driverWindowOriginal")):
        _same(value[target], installed[source])
    _same(value["configurationOriginal"], installed["ordinaryColdOriginals"][role])
    for target, source in (("preparationOriginal", "ordinaryPreparationOriginal"),
            ("resourcesOriginal", "ordinaryInitialResourcesOriginal")):
        _same(value[target], observed[source])
    if supplemental:
        primary = _input(prior, "ordinary-initial-checkpoint-" + role)
        state = g.document(_raw(value["initialStateOriginal"]), g.MAX_BYTES)
        primary_state = g.document(_raw(primary["initialStateOriginal"]), g.MAX_BYTES)
        checkpoint = g.document(_raw(primary["payloadOriginal"]), g.MAX_BYTES)
        payload = g.document(_raw(value["payloadOriginal"]), g.MAX_BYTES)
        remaining = tuple(name for name in legacy.initial_profile.HELPER_ENDPOINT_ROLES
            if name != checkpoint["endpointRole"])
        p.require(len(remaining) == 3 and payload["endpointRole"] == remaining[slot - 1])
        for field in legacy.initial_authority.COMMON_FIELDS:
            if field not in ("operation", "initialStateOriginal", "payloadOriginal"):
                _same(value[field], primary[field])
        for field in state:
            if field != "endpointProcessIdentitySha256":
                _same(state[field], primary_state[field])
        for field in checkpoint:
            if field not in ("endpointRole", "endpointProcessIdentitySha256", "predecessorCheckpointSha256"):
                _same(payload[field], checkpoint[field])
    if operation != "checkpoint":
        first = stem + "checkpoint" + suffix
        approved = _input(prior, first)
        for field in legacy.initial_authority.COMMON_FIELDS:
            if field != "operation":
                _same(value[field], approved[field])
        _literal(value, "initialCheckpointOriginal", prior, first)
    if operation == "assemble":
        for signer, original in p.fields(value["anchorSignatures"], legacy.initial_authority.KEY_NAMES).items():
            p.require(_raw(original) == _output(prior, stem + signer + "-anchor" + suffix))
    return operation


def _ordinary_rows(value, prior, *, granted, launch_field="launchOriginal"):
    installed = _input(prior, "install-ordinary-runtime")
    _same(value[launch_field], installed["launchOriginal"])
    for role, row in value["services"].items():
        p.require(role in g.ROLES)
        for field, source in (("configurationOriginal", "coldOriginals"), ("runtimeOriginal", "runtimeOriginals"),
                ("historyOriginal", "historyOriginals")):
            _same(row[field], installed[source][role])
        _literal(row, "deliveryOriginal", prior, "ordinary-delivery-" + role)
        if granted:
            _literal(row, "generationGrantOriginal", prior, "ordinary-generation-" + role)


def _installation(value, prior, observed):
    p.fields(value, ("apiVersion", "launchOriginal", "preparationOriginal", "resourcesOriginal",
        "driverConfigurationOriginal", "driverWindowOriginal", "coldOriginals", "historyOriginals", "runtimeOriginals"))
    p.require(value["apiVersion"] == INSTALLATION_API)
    first = _input(prior, "install-precreation")
    _same(value["launchOriginal"], first["ordinaryLaunchOriginal"])
    _same(value["coldOriginals"], first["ordinaryColdOriginals"])
    for field in ("driverConfigurationOriginal", "driverWindowOriginal"):
        _same(value[field], first[field])
    _same(value["preparationOriginal"], observed["ordinaryPreparationOriginal"])
    _same(value["resourcesOriginal"], observed["ordinaryInitialResourcesOriginal"])
    for role, original in p.fields(value["historyOriginals"], g.ROLES).items():
        p.require(_raw(original) == _output(prior, "ordinary-initial-assemble-" + role))
    p.fields(value["runtimeOriginals"], g.ROLES)
    runtime = g.document(_raw(value["runtimeOriginals"][g.ROLES[-1]]), g.MAX_BYTES)
    expected = {}
    for name in ("ordinary-initial-assemble-" + g.ROLES[-1],) + tuple(
            "ordinary-helper-initial-assemble-slot" + str(slot) for slot in range(1, 4)):
        raw = _output(prior, name)
        wrapper = g.document(raw, g.MAX_BYTES)
        endpoint = wrapper["initialCheckpoint"]["payload"]["endpointRole"]
        p.require(endpoint not in expected)
        expected[endpoint] = raw.decode("ascii")
    _same(runtime["initialEndpointHistories"], expected)


def _delivery(job, value, prior, observations, observed):
    role = job.role
    expected = observed["activation"] if role == "bridge" else observed["nativeActivations"][role]
    _same(legacy.PhaseExecution._array_original(value["activationOriginal"]), expected)
    p.require(value["role"] == role)
    if role == "bridge":
        p.require(value["apiVersion"] == "serverware.nativePilotDeliverySigningInput/v3")
        bootstrap = _input(prior, "driver-bootstrap")
        for target, source in (("ownerConfigurationOriginal", "configurationOriginal"),
                ("configurationOriginal", "deliveryConfigurationOriginal"), ("windowOriginal", "windowOriginal")):
            _same(value[target], bootstrap[source])
        _same(value["runtimeOriginal"], _input(prior, "install-bridge-runtime")["runtimeOriginal"])
        _same(value["observationOriginal"], observations["bootstrap-admission"]["bootstrapObservationOriginal"])
    else:
        selected = _input(prior, "install-precreation")
        _same(value["ownerConfigurationOriginal"], selected["cohortConfigurationOriginal"])
        _literal(value, "windowOriginal", prior, "cohort-precreation")
        _same(value["observationOriginal"], observed["cohortObservationOriginal"])
        if role == "retrieval":
            core = observations["endpoint-inputs"]["adoptedCore"]
            _same(value["coreObservationOriginal"], core["observationOriginal"])
            _same(value["coreBundleOriginal"], core["bundleOriginal"])


def _authorization(role, operation, value, prior):
    if operation == "closure":
        _literal(value, "deliveryInputOriginal", prior, "native-delivery-" + role, output=False)
        _literal(value, "deliveryOriginal", prior, "native-delivery-" + role)
        keys = _input(prior, "native-role-keys-" + role)
        for field in ("trustOriginal", "trustSha256", "assignmentOriginal", "closureSetOriginal"):
            _same(value[field], keys["recipeOriginals"][field])
    else:
        for field, literal in _pair(prior, role).items():
            _same(value[field], literal)
        if operation == "encrypted-delivery" and role == "commitRequest":
            _literal(value, "requestCommitmentOriginal", prior, "native-request-commitment-commitRequest")


def adoption_input(raw, *, observations, prior, boot, now_boottime_ns, now_unix_ns):
    value = p.fields(p.document(raw, MAX_FRAME), ("apiVersion", "controlOriginal", "validationInputOriginal"))
    p.require(value["apiVersion"] == ADOPTION_INPUT_API)
    control = p.fields(p.document(_raw(value["controlOriginal"]), 4096),
        ("apiVersion", "validatorExecutableSha256", "inputSha256"))
    p.require(control["apiVersion"] == adoption.CONTROL_API)
    p.digest(control["validatorExecutableSha256"])
    validation_raw = _raw(value["validationInputOriginal"], adoption.MAX_INPUT)
    p.require(p.sha(validation_raw) == p.digest(control["inputSha256"]))
    checked = adoption.prepare_input(validation_raw, expected_input_sha256=p.sha(validation_raw),
        boot=boot, now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    native = p.document(validation_raw, adoption.MAX_INPUT)
    p.require(native["apiVersion"] == "serverware.nativePublicationAdoptionValidationInput/v2")
    payload = p.document(_raw(native["payloadOriginal"]), adoption.MAX_AUTHORIZATION)
    _same(payload["coldBundleOriginal"], observations["endpoint-inputs"]["adoptedCore"]["bundleOriginal"])
    installation = _input(prior, "install-ordinary-runtime")
    targets = {row["serviceRole"]: row for row in native["targetHistories"]}
    p.fields(targets, PUBLICATION_ROLES)
    for role, row in targets.items():
        _same(row["runtimeOriginal"], installation["runtimeOriginals"][role])
        _same(row["historyOriginal"], installation["historyOriginals"][role])
    return checked


def _native(job, value, prior, observed):
    op = "generationInstall" if job.family == "generation-install" else job.role
    role = "generationInstall" if op == "generationInstall" else NATIVE_ENDPOINT[op]
    _literal(value, "deliveryInputOriginal", prior, "native-delivery-" + role, output=False)
    delivery_field = "coordinatorDeliveryOriginal" if op == "generationInstall" else "deliveryOriginal"
    _literal(value, delivery_field, prior, "native-delivery-" + role)
    if "pair" in value:
        _same(value["pair"], _pair(prior, role))
    if op in ("publication", "retrieval", "persistence"):
        _literal(value, "adoptionAuthorizationOriginal", prior, "publication-adoption")
        _same(value["adoptionValidationInputOriginal"], _input(prior, "publication-adoption")["validationInputOriginal"])
        if op == "publication":
            _literal(value, "retrievalDeliveryInputOriginal", prior, "native-delivery-retrieval", output=False)
            _literal(value, "retrievalDeliveryOriginal", prior, "native-delivery-retrieval")
            for member, row in p.fields(value["ordinaryServices"], g.ROLES).items():
                source = _input(prior, "ordinary-generation-" + member)["services"][member]
                for field in ("runtimeOriginal", "historyOriginal"):
                    _same(row[field], source[field])
                _literal(row, "generationGrantOriginal", prior, "ordinary-generation-" + member)
    else:
        _same(value["observationOriginal"], observed["cohortObservationOriginal"])
    if "services" in value:
        _ordinary_rows(value, prior, granted=True, launch_field="ordinaryLaunchOriginal")
    if op == "ledger":
        _literal(value, "companionOriginal", prior, "native-service-commitRequest")
        _same(value["companionPin"], _result(prior, "native-service-commitRequest")["pin"])
    if op == "retrieval":
        _literal(value, "publicationGrantOriginal", prior, "native-service-publication")
        _same(p.document(_raw(value["endpointDeliveryResultOriginal"]), 32768), observed["endpointDeliveryResult"])
        for name in legacy.native_authority.SIGNERS:
            _literal(value["nativeGrantOriginals"], name, prior, "native-service-" + name)


def _current_head(job, value, prior, observations, clocks):
    from serverware import native_pilot_bridge_preparation as preparation
    role, endpoint_role = legacy.CURRENT_HEAD_JOB_INFO[job.name]
    bootstrap = _input(prior, "driver-bootstrap")
    generation = _input(prior, "ordinary-generation-" + role)
    service = generation["services"][role]
    early = observations["endpoint-inputs"]
    prep = preparation.shape(_raw(observations["bridge-runtime"]["bridgePreparationOriginal"]))
    requests, _ = preparation._parts(prep)
    rows = [(endpoint, row) for selected, endpoint, row in preparation.requests_profile.iter_requests(requests)
        if selected == role and (endpoint_role is None or endpoint == endpoint_role)]
    p.require(len(rows) == 1 and value["serviceRole"] == role)
    selected, row = rows[0]
    for field, expected in {"driverConfigurationOriginal": bootstrap["configurationOriginal"],
            "driverWindowOriginal": bootstrap["windowOriginal"], "launchOriginal": generation["launchOriginal"],
            "configurationOriginal": service["configurationOriginal"], "runtimeOriginal": service["runtimeOriginal"],
            "preparationOriginal": early["ordinaryPreparationOriginal"], "resourcesOriginal": early["ordinaryInitialResourcesOriginal"],
            "initialHistoryOriginal": service["historyOriginal"], "requestOriginal": row["requestOriginal"]}.items():
        _same(value[field], expected)
    p.require(value["endpointRole"] == selected)
    checked = legacy.current_head_authority.profile.prepare_input(g.canonical(value),
        boot=clocks["boot"], now_boottime_ns=clocks["now_boottime_ns"], adopted=True)
    p.require(checked["statement"]["requestSha256"] == row["requestSha256"]
        and checked["statement"]["checkpointSha256"] == row["checkpointSha256"])
    return checked


def _bridge_runtime(value, prior, observations, clocks):
    from serverware import native_pilot_bridge_preparation as preparation
    from serverware import native_pilot_service_handshakes as handshakes
    raw, runtime = legacy.bridge_runtime.original(value["runtimeOriginal"])
    p.require(value["apiVersion"] == "serverware.nativePilotBridgeRuntimeBundle/v2"
        and legacy.bridge_runtime.version(runtime) == 14)
    legacy.bridge_install.shape("bridge-runtime", raw)
    legacy.bridge_install.shape("bridge-outgoing", _raw(value["outgoingOriginal"]))
    _same(value["driverObservationOriginal"], observations["bootstrap-admission"]["bootstrapObservationOriginal"])
    observed = observations["bridge-runtime"]
    _same(runtime["journalDirectoryIdentity"], observed["bridgeJournal"])
    _same(runtime["generationAdmission"]["grants"], observed["ordinaryGenerationGrants"])
    _same(observed["ordinaryGenerationGrants"], {role: p.sha(_output(prior, "ordinary-generation-" + role)) for role in g.ROLES})
    for role in legacy.commitment.ROLES:
        _literal(runtime["commitRequest"]["serviceGrantOriginals"], role, prior, "ordinary-dispatch-" + role)
    for name, output in (("headGrantOriginal", "ordinary-head"), ("cleanupGrantOriginal", "ordinary-cleanup"),
            ("currentGrantOriginal", "ordinary-current")):
        _literal(runtime["spool"], name, prior, output)
    for name, role in zip(("durableGrantOriginal", "currentGrantOriginal"), PUBLICATION_ROLES, strict=True):
        _literal(runtime["publication"], name, prior, "ordinary-publication-" + role)
    for role, row in p.fields(runtime["ordinaryInitialHistories"], g.ROLES).items():
        source = _input(prior, "ordinary-generation-" + role)["services"][role]
        for field in ("runtimeOriginal", "historyOriginal"):
            _same(row[field], source[field])
        _literal(row, "generationGrantOriginal", prior, "ordinary-generation-" + role)
    names = {target: name for name, target in legacy.CURRENT_HEAD_JOB_INFO.items()}
    seen = set()
    for session in runtime["serviceSessions"]:
        role = session["serviceRole"]
        for row in session["handshakes"]:
            target = role, row["endpointRole"] if role == g.ROLES[-1] else None
            p.require(target in names and names[target] not in seen)
            name = names[target]; seen.add(name)
            head_raw = _output(prior, name)
            legacy.current_head_authority.profile.checked_result(prior[name]["input"],
                {"original": head_raw.decode("ascii"), "sha256": p.sha(head_raw)},
                boot=clocks["boot"], now_boottime_ns=clocks["now_boottime_ns"], adopted=True)
            expected = handshakes.frame(service_role=role,
                trust_request_original=_raw(_input(prior, name)["requestOriginal"]),
                signed_current_head=p.document(head_raw, 65536),
                client_process_identity_sha256=runtime["expectedDriverProcessIdentitySha256"],
                client_configuration_generation_sha256=runtime["expectedDriverConfigurationGenerationSha256"])
            p.require(p.canonical(row["request"]) == expected)
    p.require(seen == set(names.values()))
    ids = {"ordinary-services": {}, "native-endpoints": {}, "gate": {}}
    for role in g.ROLES:
        guest = p.document(_output(prior, "ordinary-generation-" + role), 65536)["payload"]["guest"]
        ids["ordinary-services"][role] = {field: guest[field] for field in ("uid", "gid")}
    for role in ENDPOINTS:
        payload = p.document(_output(prior, "native-delivery-" + role), 65536)["payload"]
        ids["native-endpoints"][role] = {field: payload[field] for field in ("uid", "gid")}
    gate = p.document(_raw(observations["endpoint-precreation"]["gateBindingOriginal"]), 8192)["binding"]
    ids["gate"]["gate"] = {field: gate[field] for field in ("uid", "gid")}
    preparation.require_runtime(_raw(observed["bridgePreparationOriginal"]), raw,
        driver_observation_raw=_raw(value["driverObservationOriginal"]),
        cohort_observation_raw=_raw(observations["service-originals"]["cohortObservationOriginal"]), peer_ids=ids)


def interactive_deadline(installed, production, *, boot):
    """Original lifetime arithmetic, not admission of supplied public sources.

    The real caller supplies its already checked, retained precreation input.
    Startup is not re-admitted or renewed after generation-origin handoff.
    """
    configuration = p.document(_raw(installed["driverConfigurationOriginal"]), 65536)
    driver = p.document(_raw(installed["driverWindowOriginal"]), 32768)
    cohort = p.document(_raw(installed["cohortPrecreationOriginal"]), legacy.cohort.MAX_BYTES)
    ordinary = g.document(_raw(installed["ordinaryLaunchOriginal"]), 65536)
    p.require(configuration["apiVersion"] == "serverware.nativeShadowDriverBootstrapConfiguration/v4"
        and driver["apiVersion"] == "serverware.nativeShadowDriverBootstrapWindow/v1"
        and cohort["apiVersion"] == "serverware.nativeShadowProofCohortPrecreation/v1"
        and ordinary["apiVersion"] == "serverware.custodyFiveServiceLaunch/v7")
    windows = (driver["payload"], cohort["payload"], ordinary)
    for window in windows:
        p.require(tuple(window[field] for field in ("bootIdBase64url", "timeNamespaceDevice", "timeNamespaceInode")) == boot
            and p.ns(window["issuedAtBoottimeNs"]) < p.ns(window["startupDeadlineBoottimeNs"])
            <= p.ns(window["lifetimeDeadlineBoottimeNs"]))
    p.fields(production, legacy.scope_authority.PRODUCTION_FIELDS)
    reserve = max(p.integer(configuration["lifecycle"]["cleanupReserveNanos"],
        minimum=1_000_000, maximum=5_000_000_000),
        p.integer(production["cleanupReserveNanos"], maximum=5_000_000_000))
    deadline = min(min(p.ns(window["lifetimeDeadlineBoottimeNs"]) for window in windows) - reserve,
        p.ns(cohort["payload"]["lifetimeDeadlineBoottimeNs"]) - interactive.COHORT_REAP_RESERVE_NS)
    p.require(deadline > 0)
    return deadline


def _interactive_input(value, *, prior, observations, boot, now_boottime_ns, now_unix_ns):
    """Check the full action; the retained Policy2 separately decides scope."""
    action = interactive.validate_action(value, origin_handoff=observations["shutdown"]["originHandoff"])
    deadline = interactive_deadline(_input(prior, "install-precreation"),
        _input(prior, "endpoint-inputs")["production"], boot=boot)
    # These are the actual prior signed outputs authenticated by the executor
    # and supervisor, not new admissions or caller-supplied success objects.
    adoption_payload = p.document(_output(prior, "publication-adoption"), adoption.MAX_AUTHORIZATION)["payload"]
    p.require(p.integer(adoption_payload["issuedAtBoottimeNanos"], maximum=p.MAX_U64) <= now_boottime_ns)
    deadline = min(deadline, p.integer(adoption_payload["expiresAtBoottimeNanos"], maximum=p.MAX_U64))
    signed = [adoption_payload, *(p.document(_output(prior, name), 16384)["payload"]
        for name in ("driver-bootstrap", "driver-constructed"))]
    for payload in signed:
        p.require(p.integer(payload["issuedAtUnixNanos"]) <= now_unix_ns < p.integer(payload["expiresAtUnixNanos"]))
    expiry = min(payload["expiresAtUnixNanos"] for payload in signed)
    for role in g.ROLES:
        payload = g.document(_output(prior, "ordinary-generation-" + role), g.MAX_BYTES)["payload"]
        p.require(payload["serviceRole"] == role
            and p.integer(payload["issuedAtBoottimeNanos"], maximum=p.MAX_U64) <= now_boottime_ns)
        deadline = min(deadline, p.integer(payload["expiresAtBoottimeNanos"], maximum=p.MAX_U64))
        p.require(p.integer(payload["scope"]["installationIssuedAtUnixNanos"]) <= now_unix_ns)
        expiry = min(expiry, p.integer(payload["scope"]["installationExpiresAtUnixNanos"]))
    stop, selected_expiry = action["stopAtBoottimeNanos"], action["expiresAtUnixNanos"]
    p.require(now_boottime_ns < stop < deadline and now_unix_ns < selected_expiry <= expiry
        and stop - now_boottime_ns < selected_expiry - now_unix_ns)
    # Approval installation and forwarding must finish before the selected
    # interval ends. Actual process waits retain their original request's
    # lifetime/cleanup cap; this delivery cap is not a new serving deadline.
    return {"deadline": stop, "epochLimit": selected_expiry}


def prepare_input(name, raw, *, phase, prior, observations, boot, now_boottime_ns, now_unix_ns):
    """Validate the fixed full input before key reads or publication side effects."""
    job = _prefix(name, phase, prior, observations)
    p.require(type(raw) is bytes and 0 < len(raw) <= job.maximum)
    value = p.document(raw, job.maximum)
    clocks = dict(boot=boot, now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    observed, context = observations[phase], None
    family = job.family
    if family == "driver":
        if job.role == "bootstrap":
            for field in ("observationOriginal", "payloadOriginal"):
                _same(value[field], observed["bootstrapObservationOriginal" if field == "observationOriginal" else "admissionPayloadOriginal"])
        else:
            for field, literal in observed.items(): _same(value[field], literal)
            _literal(value, "bootstrapAdmissionOriginal", prior, "driver-bootstrap")
        context = legacy.driver_authority.prepare_input(job.role, raw, **clocks, adopted=True)
    elif family == "cohort":
        if job.role == "precreation":
            config = p.document(_raw(value["configurationOriginal"]), legacy.cohort.MAX_BYTES)
            p.require(config["externalDriver"]["observationSha256"] == p.sha(_raw(observed["bootstrapObservationOriginal"])))
        else:
            _same(value["observationsOriginal"], observations["service-originals"]["cohortObservationOriginal"])
            _literal(value, "precreationOriginal", prior, "cohort-precreation")
            first = _input(prior, "cohort-precreation")
            for field in ("configurationOriginal", "configurationSha256", "coldOriginals"):
                _same(value[field], first[field])
        context = cohort_authority.prepare_input(job.role, raw, **clocks)
    elif family == "precreation":
        p.fields(value, legacy.precreation_install.FIELDS)
        p.require(value["apiVersion"] == "serverware.nativePilotPrecreationBundle/v2")
        first = _input(prior, "driver-bootstrap")
        for target, source in (("driverConfigurationOriginal", "configurationOriginal"), ("driverWindowOriginal", "windowOriginal")):
            _same(value[target], first[source])
        _same(value["driverObservationOriginal"], observed["bootstrapObservationOriginal"])
        _literal(value, "cohortPrecreationOriginal", prior, "cohort-precreation")
        selected = _input(prior, "cohort-precreation")
        _same(value["cohortConfigurationOriginal"], selected["configurationOriginal"])
        _same(value["nativeColdOriginals"], selected["coldOriginals"])
        # The actual installer performs its full fixed-path shape/authentication
        # check before writing. No key is read by this installation job.
        context = cohort_authority.prepare_input("precreation", prior["cohort-precreation"]["input"], **clocks)
    elif family in ("ordinary-initial", "helper-initial"):
        operation = _initial(job, value, prior, observed)
        context = legacy.initial_authority.prepare_input(operation, raw, **clocks, adopted=True)
    elif family == "ordinary-installation":
        from serverware import native_pilot_adopted_ordinary_install as install
        _installation(value, prior, observed)
        context = install.prepare_input(raw, **clocks)
    elif family == "adoption":
        context = adoption_input(raw, observations=observations, prior=prior, **clocks)
    elif family == "delivery":
        _delivery(job, value, prior, observations, observed)
        if job.role == "bridge":
            # Pure bridge delivery public admission shares the actual signer
            # recipe validator, without loading a private key.
            from serverware import native_pilot_bridge_delivery_profile as c9
            context = c9.prepare_signing_input(raw, boot=boot, now_boottime_ns=now_boottime_ns)
        else:
            context = commands.prepare_input(job.role, "delivery", raw, **clocks)
    elif family == "ordinary-publication":
        _ordinary_rows(value, prior, granted=True)
        for label, operation in (("Publication", "publication"), ("Retrieval", "retrieval")):
            _literal(value, "native" + label + "InputOriginal", prior, "native-service-" + operation, output=False)
            _literal(value, "native" + label + "GrantOriginal", prior, "native-service-" + operation)
        context = publication.prepare_input(job.role, raw, **clocks)
    elif family.startswith("ordinary-"):
        operation = family.removeprefix("ordinary-")
        if operation == "delivery":
            selected = _input(prior, "install-ordinary-runtime")
            for target, source in (("launchOriginal", "launchOriginal"),): _same(value[target], selected[source])
            for field, mapping in (("configurationOriginal", "coldOriginals"), ("runtimeOriginal", "runtimeOriginals")):
                _same(value[field], selected[mapping][job.role])
            _same(value["activation"], observed["ordinaryActivations"][job.role])
            payload = p.document(_raw(value["payloadOriginal"]), 65536)
            metadata = _result(prior, "install-ordinary-runtime")["services"][job.role]
            _same(payload["runtimeConfig"], metadata["runtimeConfig"])
            for field in ("historyCredential", "inspectionCredential"):
                expected = metadata[field]
                selected_rows = [row for row in payload["credentials"] if row["name"] == expected["name"]]
                p.require(len(selected_rows) == 1)
                _same(selected_rows[0], expected)
        else:
            _ordinary_rows(value, prior, granted=operation != "generation")
            if operation == "generation":
                from serverware import native_pilot_ordinary_generation_profile as generation_profile
                payload = p.document(_raw(value["payloadOriginal"]), 65536)
                recipe = p.fields(observed["driverGenerationRecipe"], generation_profile.RECIPE_FIELDS)
                for field in generation_profile.RECIPE_FIELDS[:-1]:
                    _same(payload["scope"][field], recipe[field])
            elif operation == "dispatch":
                _literal(value, "nativeGrantOriginal", prior, "native-service-commitRequest")
            else:
                for op in legacy.spool.EFFECT_NATIVE: _literal(value["nativeOriginals"], op, prior, "native-service-" + op)
                if operation != "head": _literal(value, "headGrantOriginal", prior, "ordinary-head")
                if operation == "current": _literal(value, "cleanupGrantOriginal", prior, "ordinary-cleanup")
        context = legacy.service_authority.prepare_input(operation, job.role, raw, **clocks, adopted=True)
    elif family == "native-key":
        role, operation = KEY_INFO[name]
        _literal(value, "deliveryInputOriginal", prior, "native-delivery-" + role, output=False)
        _literal(value, "deliveryOriginal", prior, "native-delivery-" + role)
        selected_adoption = p.document(_raw(_input(prior, "publication-adoption")["validationInputOriginal"]), adoption.MAX_INPUT)
        for target, source in (("trustOriginal", "currentTrustOriginal"), ("trustSha256", "currentTrustSha256"),
                ("assignmentOriginal", "currentAssignmentOriginal"), ("closureSetOriginal", "currentClosureSetOriginal")):
            _same(value["recipeOriginals"][target], selected_adoption[source])
        _same(value["measured"]["configurationBindingSha256"], selected_adoption["currentConfigurationBindingSha256"])
        _same(value["measured"]["proofScopeOriginal"], selected_adoption["currentProofScopeOriginal"])
        if operation == "admission": _literal(value, "roleKeyOriginal", prior, "native-role-keys-" + role)
        context = commands.prepare_input(role, operation, raw, **clocks)
    elif family == "native-launch-authorization":
        role, operation = AUTH_INFO[name]
        _authorization(role, operation, value, prior)
        context = commands.prepare_input(role, "verifier" if operation == "verifier-transport" else operation, raw, **clocks)
    elif family in ("native", "generation-install"):
        from serverware import native_pilot_native_service_profile as native
        _native(job, value, prior, observed)
        context = native.prepare_adopted_input("generationInstall" if family == "generation-install" else job.role, raw, **clocks)
    elif family == "launch":
        if job.role == "bridge":
            from serverware import native_pilot_bridge_launch_profile as launch
            p.require(value["apiVersion"] == launch.ADOPTED_INPUT_API)
            _literal(value, "deliveryInputOriginal", prior, "native-delivery-bridge", output=False)
            _literal(value, "deliveryOriginal", prior, "native-delivery-bridge")
            for operation, row in value["authorizations"].items():
                output = "native-key-admission-bridge" if operation == "admission" else "native-" + operation + "-bridge"
                _literal(row, "inputOriginal", prior, output, output=False)
                _literal(row, "authorizationOriginal", prior, output)
            _literal(value["serviceContext"], "inputOriginal", prior, "native-service-trustedTime", output=False)
            _literal(value["serviceContext"], "grantOriginal", prior, "native-service-trustedTime")
            context = launch.prepare_input(raw, **clocks)
        else:
            from serverware import native_pilot_adopted_launch_profile as launch
            p.require(value["apiVersion"] == launch.ALL_API)
            _same(value["pair"], _pair(prior, job.role))
            for operation, row in value["authorizations"].items():
                output = "native-" + operation + "-" + job.role
                _literal(row, "inputOriginal", prior, output, output=False)
                _literal(row, "original", prior, output)
            output = "native-generation-install-grant" if job.role == "generationInstall" else "native-service-" + GRANT_FOR_ENDPOINT[job.role]
            _literal(value, "serviceInputOriginal", prior, output, output=False)
            _literal(value, "serviceGrantOriginal", prior, output)
            if job.role == "commitRequest":
                _literal(value, "companionInputOriginal", prior, "native-service-commitRequest", output=False)
                _literal(value, "companionGrantOriginal", prior, "native-service-commitRequest")
            context = launch.prepare_input(job.role, raw, **clocks)
    elif family == "service-material":
        for role in ("persistence", "generationInstall"):
            output = "native-generation-install-grant" if role == "generationInstall" else "native-service-" + role
            _literal(value["serviceContexts"][role], "inputOriginal", prior, output, output=False)
            _literal(value["serviceContexts"][role], "grantOriginal", prior, output)
            _same(value["endpointLaunches"][role], _result(prior, "install-launch-" + role)["launch"])
        context = legacy.service_material.prepare_bundle(raw, **clocks, adopted=True)
    elif family == "current-head":
        context = _current_head(job, value, prior, observations, clocks)
    elif family == "bridge-runtime":
        _bridge_runtime(value, prior, observations, clocks)
    elif family == "bridge-authorization":
        operation = legacy.BRIDGE_AUTHORIZATION_JOB_INFO[name]
        if operation in ("role-keys", "admission"):
            _literal(value, "deliveryInputOriginal", prior, "native-delivery-bridge", output=False)
            _literal(value, "deliveryOriginal", prior, "native-delivery-bridge")
            _same(value["controlOriginal"], _input(prior, "driver-bootstrap")["controlOriginal"])
            earlier = _input(prior, "native-role-keys-retrieval")
            for field in ("recipeOriginals", "measured"): _same(value[field], earlier[field])
            if operation == "admission": _literal(value, "roleKeyOriginal", prior, "native-role-keys-bridge")
            p.require(value["apiVersion"] == legacy.bridge_authority.keys.ADOPTED_API)
        else:
            _authorization("bridge", operation, value, prior)
        context = legacy.bridge_authorization_profile.prepare_input(operation, raw, **clocks)
    elif family == "scope":
        _same(value["operationOriginal"], observed["operationOriginal"])
        _literal(value, "bootstrapAdmissionOriginal", prior, "driver-bootstrap")
        p.require(p.sha(_raw(value["launchOriginal"])) == _result(prior, "install-launch-bridge")["launch"]["sha256"])
        bundle = p.document(_raw(value["publicBundleOriginal"]), legacy.bridge_runtime.MAX_BRIDGE_INPUT)
        _same(bundle["runtimeOriginal"], _input(prior, "install-bridge-runtime")["runtimeOriginal"])
        _literal(bundle, "deliveryOriginal", prior, "native-delivery-bridge")
        for role, literal in p.fields(bundle["generationOriginals"], g.ROLES).items():
            p.require(_raw(literal) == _output(prior, "ordinary-generation-" + role))
        context = legacy.scope_authority.prepare_input(raw, **clocks, adopted=True)
    elif family == "phase-two-public":
        selected = legacy.phase_two.prepare_input(raw, adopted=True)
        p.require(selected == _raw(_input(prior, "driver-scope")["publicBundleOriginal"]))
    elif family == "endpoint-inputs":
        p.fields(value, ("coldOriginals", "peer", "proofScope", "retrievalManifest", "objectDirectory", "assignment", "production", "adoptionAuthorization"))
        p.fields(value["coldOriginals"], COMPOSITE)
        _same(value["adoptionAuthorization"], _result(prior, "publication-adoption")["pin"])
        native = p.document(_raw(_input(prior, "publication-adoption")["validationInputOriginal"]), adoption.MAX_INPUT)
        for field, source in (("proofScope", "currentProofScopeOriginal"), ("assignment", "currentAssignmentOriginal")):
            p.require(value[field]["sha256"] == p.sha(_raw(native[source])))
        p.fields(value["production"], legacy.scope_authority.PRODUCTION_FIELDS)
    else:
        p.require(family in ("origin", "stop"))
        if family == "stop" and value.get("action") == "run-interactive":
            context = _interactive_input(value, prior=prior, observations=observations, **clocks)
        else:
            p.fields(value, ("action",))
            p.require(value["action"] == ("observe-installed-generation" if family == "origin" else "stop"))
    result = {"deadline": None, "epochLimit": None} if context is None else dict(context)
    result.setdefault("deadline", None); result.setdefault("epochLimit", None)
    if result["deadline"] is not None: p.require(now_boottime_ns < result["deadline"])
    if result["epochLimit"] is not None: p.require(now_unix_ns < result["epochLimit"])
    return result


def _adoption_result(raw, prepared):
    envelope = p.fields(p.document(raw, adoption.MAX_AUTHORIZATION), ("payload", "signature"))
    p.require(p.canonical(envelope["payload"]) == prepared["payloadOriginal"])
    adoption.authority(prepared["payload"]["authority"]).verify(
        p.decoded(envelope["signature"], size=64), adoption.message(prepared))
    return raw


def checked_result(name, input_raw, result, *, phase, prior, observations, boot, now_boottime_ns, now_unix_ns):
    """Authenticate public results; measured installation provenance is external."""
    clocks = dict(boot=boot, now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    prepared = prepare_input(name, input_raw, phase=phase, prior=prior, observations=observations, **clocks)
    job = BY_NAME[name][1]
    value = p.document(input_raw, job.maximum)
    signed = job.key is not None or job.family in ("ordinary-initial", "helper-initial")
    if not signed:
        p.require(type(result) is dict)
        if job.family == "service-material":
            legacy.service_material.checked_result(input_raw, result, **clocks, adopted=True)
        elif job.family == "endpoint-inputs": _same(result, {"publicPinsOpened": True})
        elif job.family in ("origin", "stop"): _same(result, value)
        elif job.family == "phase-two-public": legacy.phase_two.checked_result(input_raw, result, adopted=True)
        elif job.family == "ordinary-installation":
            from serverware import native_pilot_adopted_ordinary_install as install
            p.require(result["apiVersion"] == install.RESULT_API and result["inputSha256"] == p.sha(input_raw))
            p.fields(result, ("apiVersion", "inputSha256", "pins", "services"))
            p.fields(result["services"], g.ROLES)
            expected = {row["path"]: {"path": row["path"], "sha256": p.sha(row["raw"])} for row in prepared["planned"]}
            _same(result["pins"], expected)
        elif job.family == "launch":
            p.require(result["role"] == job.role and result["launch"] == prepared["pins"]["native-launch-" + job.role])
        else:
            p.require(job.family in ("precreation", "bridge-runtime"))
            p.require(result["bundleSha256"] == p.sha(input_raw) and type(result["pins"]) is dict)
        return result
    p.fields(result, ("original", "sha256") + (("pin",) if job.purpose is not None else ()))
    raw = _raw(result["original"])
    p.require(p.digest(result["sha256"]) == p.sha(raw))
    pair = {"original": result["original"], "sha256": result["sha256"]}
    if job.purpose is not None:
        from serverware import native_pilot_adopted_publication as published
        destinations = published.DESTINATIONS if job.purpose in published.DESTINATIONS else (
            legacy.launch_install.ADOPTED_DESTINATIONS if job.purpose in legacy.launch_install.ADOPTED_DESTINATIONS
            else legacy.launch_install.publication.DESTINATIONS)
        _same(result["pin"], {"path": destinations[job.purpose], "sha256": p.sha(raw)})
    family = job.family
    if family == "driver": legacy.driver_authority.checked_result(job.role, input_raw, pair, **clocks, adopted=True)
    elif family == "current-head":
        legacy.current_head_authority.profile.checked_result(input_raw, pair, boot=boot,
            now_boottime_ns=now_boottime_ns, adopted=True)
    elif family == "ordinary-publication": publication.checked_result(job.role, input_raw, raw, **clocks)
    elif family in ("ordinary-delivery", "ordinary-generation", "ordinary-dispatch", "ordinary-head", "ordinary-cleanup", "ordinary-current"):
        envelope = p.fields(p.document(raw, prepared["maximum"]), ("apiVersion", "payload", "signatureBase64url")
            if family == "ordinary-delivery" else ("payload", "signatureBase64url"))
        p.require(p.canonical(envelope["payload"]) == prepared["payloadOriginal"])
        prepared["root"].verify(p.decoded(envelope["signatureBase64url"], size=64), prepared["message"])
    elif family == "delivery":
        if job.role != "bridge": delivery.verify_delivery(input_raw, raw, **clocks)
        else:
            cold_raw = _raw(value["configurationOriginal"])
            cold = legacy.delivery_authority.delivery.configuration(cold_raw, p.sha(cold_raw))
            envelope = p.fields(p.document(raw, 65536), ("apiVersion", "payload", "signatureBase64url"))
            p.require(envelope["apiVersion"] == "serverware.policyCustodyGuestDelivery/v1"
                and p.canonical(envelope["payload"]) == _raw(value["payloadOriginal"]))
            legacy.delivery_authority.driver._key(cold["authority"]).verify(p.decoded(envelope["signatureBase64url"], size=64),
                legacy.delivery_authority.delivery.DOMAIN + _raw(value["payloadOriginal"]))
    elif family == "native-key":
        role, operation = KEY_INFO[name]
        legacy.key_authority.profile.checked_result(operation, role, input_raw, pair, **clocks)
    elif family == "native-launch-authorization":
        role, operation = AUTH_INFO[name]
        if operation == "closure": legacy.closure_authority.checked_result(input_raw, pair, **clocks)
        elif operation == "verifier-transport": legacy.verifier_authority.checked_result(role, input_raw, pair, **clocks)
        else: legacy.encrypted_authority.checked_result("delivery" if operation == "encrypted-delivery" else operation,
            role, input_raw, pair, **clocks)
    elif family == "bridge-authorization":
        legacy.bridge_authorization_profile.checked_result(legacy.BRIDGE_AUTHORIZATION_JOB_INFO[name], input_raw, pair, **clocks)
    elif family in ("native", "generation-install"):
        from serverware import native_pilot_native_service_profile as native
        native.checked_adopted_result("generationInstall" if family == "generation-install" else job.role, input_raw, pair, **clocks)
    elif family == "scope": legacy.scope_authority.checked_result(input_raw, pair, **clocks, adopted=True)
    elif family == "adoption":
        _adoption_result(raw, prepared)
    elif family == "cohort":
        envelope = p.fields(p.document(raw, legacy.cohort.MAX_BYTES), ("apiVersion", "payload", "signatureBase64url"))
        p.require(p.canonical(envelope["payload"]) == _raw(value["payloadOriginal"]))
        config = legacy.cohort.configuration(_raw(value["configurationOriginal"]))
        domain = legacy.cohort.PRECREATE_DOMAIN if job.role == "precreation" else legacy.cohort.release_domain(config)
        legacy.delivery_authority.driver._key(config["authority"]).verify(p.decoded(envelope["signatureBase64url"], size=64),
            domain + p.canonical(envelope["payload"]))
    else:
        p.require(family in ("ordinary-initial", "helper-initial"))
        operation = (legacy.INITIAL_JOB_INFO if family == "ordinary-initial" else legacy.HELPER_INITIAL_JOB_INFO)[name][1]
        authority = legacy.initial_authority
        _, state, identity, payload, authorities, keys, _, _ = authority._context(operation, input_raw,
            adopted=True, clocks=(boot, now_boottime_ns))
        if operation == "checkpoint":
            checkpoint = p.document(raw, authority.MAX_CHECKPOINT)
            legacy.initial_profile.validate_checkpoint(state, checkpoint, checkpoint_authority=authorities["checkpoint"],
                service_key=authorities["service"], adopted=True)
            _same(checkpoint["payload"], payload)
        elif operation == "assemble":
            wrapper = p.document(raw, authority.MAX_OUTPUT)
            _same(wrapper["initialState"], state)
            p.require(p.canonical(wrapper["initialCheckpoint"]) == _raw(value["initialCheckpointOriginal"]))
            history = legacy.initial_profile.manifest(raw, role=state["serviceRole"],
                root_pin={field: authorities["root"][field] for field in ("keyId", "keySpkiSha256")}, adopted=True)
            for key_name, field in zip(authority.KEY_NAMES, authority.ANCHOR_SIGNATURE_FIELDS, strict=True):
                record = p.document(_raw(value["anchorSignatures"][key_name]), authority.MAX_SIGNATURE)
                p.require(history["firstRetainedEpoch"][field] == record["signatureBase64"])
        else:
            checkpoint = authority._checkpoint(value, state, payload, authorities, adopted=True)
            _, anchor, message = authority._anchor(state, identity, authorities, checkpoint, adopted=True)
            selected = operation.removesuffix("-anchor")
            record = p.fields(p.document(raw, authority.MAX_SIGNATURE), authority.SIGNATURE_FIELDS)
            p.require(record["signer"] == selected and record["anchorPayloadSha256"] == p.sha(anchor))
            for field in ("keyId", "keySpkiSha256"): _same(record[field], authorities[selected][field])
            keys[selected].verify(p.decoded(record["signatureBase64"], size=64), message)
    return raw
