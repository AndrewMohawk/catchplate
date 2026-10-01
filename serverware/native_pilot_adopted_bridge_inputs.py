"""Pure candidates for the existing adopted late bridge jobs.

All originals come from the caller's retained, separately authenticated job
prefix and actual phase observations. This module has no process, publication,
key or approval capability. In particular, a currentness decision and an
interactive action are independent selections, never inferred from history.
The facade additionally pins the supervisor observation to its retained policy
and recipe and enforces that policy's stop/interactive selection.
"""
from __future__ import annotations

import copy

from serverware import native_pilot_adopted_phase_profile as profile
from serverware import native_pilot_bridge_authorization_profile as authorizations
from serverware import native_pilot_bridge_delivery_profile as delivery
from serverware import native_pilot_bridge_launch_profile as launch
from serverware import native_pilot_bridge_launch_publication as launch_publication
from serverware import native_pilot_bridge_preparation as preparation
from serverware import native_pilot_bridge_runtime_profile as runtime
from serverware import native_pilot_current_head_profile as head
from serverware import native_pilot_ordinary_runtime_profile as ordinary_runtime
from serverware import native_pilot_phase_two_publication as phase_two
from serverware import native_pilot_supervisor_current_head_profile as current_heads

p, g = profile.p, profile.g
OBSERVATION_API = "serverware.nativePilotAdoptedSupervisorObservation/v1"
OBSERVATION_FIELDS = ("apiVersion", "policySha256", "catalogueSha256", "intakeConfigurationSha256",
    "conductorRequestOriginal", "measuredConfiguration", "recipeOriginals")
_FIELDS = {"current-head": ("currentness",), "bridge-runtime": ("runtimePolicy", "initialPolicy"),
    "bridge-authorization": ("commissioningPolicy",), "scope": (), "phase-two-public": (),
    "origin": (), "stop": ("action",)}


def selection_fields(selected):
    """The actual catalogue object is required; a lookalike is not a job."""
    p.require(type(selected) is type(next(iter(profile.BY_NAME.values()))[1])
        and selected.name in profile.BY_NAME and profile.BY_NAME[selected.name][1] is selected)
    if selected.family in ("delivery", "launch"):
        p.require(selected.role == "bridge")
        return ("commissioningPolicy",)
    p.require(selected.family in _FIELDS)
    return _FIELDS[selected.family]


def _text(raw):
    p.require(type(raw) is bytes and raw.isascii() and 0 < len(raw) <= profile.MAX_FRAME)
    return raw.decode("ascii")


def _raw(text):
    return profile._raw(text)


def _source_observation(value):
    p.fields(value, OBSERVATION_FIELDS)
    p.require(value["apiVersion"] == OBSERVATION_API)
    for name in ("policySha256", "catalogueSha256", "intakeConfigurationSha256"):
        p.digest(value[name])
    _raw(value["conductorRequestOriginal"])
    return value


def _sources(value):
    # The outer facade proves the observation's actual source and policy pins.
    # Lower builders independently authenticate these complete public objects.
    p.require(type(value["measuredConfiguration"]) is dict and type(value["recipeOriginals"]) is dict)
    return dict(measured=copy.deepcopy(value["measuredConfiguration"]),
        recipe_originals=copy.deepcopy(value["recipeOriginals"]))


def _bootstrap(prior):
    source = profile._input(prior, "driver-bootstrap")
    return {name: _raw(source[name + "Original"])
        for name in ("control", "configuration", "window", "deliveryConfiguration")}


def _records(prior, names, output):
    return {name: {"inputOriginal": prior[job]["input"], output: profile._output(prior, job)}
        for name, job in names.items()}


def _ordinary(prior):
    result = {}
    for role in g.ROLES:
        name = "ordinary-generation-" + role
        row = copy.deepcopy(profile._input(prior, name)["services"][role])
        row["generationGrantOriginal"] = _text(profile._output(prior, name))
        result[role] = row
    return result


def _current_head(selected, selection, prior, observations):
    role, endpoint = profile.legacy.CURRENT_HEAD_JOB_INFO[selected.name]
    source = profile._input(prior, "ordinary-generation-" + role)
    service = source["services"][role]
    bootstrap = profile._input(prior, "driver-bootstrap")
    early = observations["endpoint-inputs"]
    prepared = preparation.shape(_raw(observations["bridge-runtime"]["bridgePreparationOriginal"]))
    requests, _ = preparation._parts(prepared)
    rows = [(target, row) for actual, target, row in preparation.requests_profile.iter_requests(requests)
        if actual == role and (endpoint is None or endpoint == target)]
    p.require(len(rows) == 1)
    target, request = rows[0]
    header = ordinary_runtime.validate_runtime(role, _raw(service["runtimeOriginal"]), adopted=True)["runtime"]
    return p.canonical({"apiVersion": head.ADOPTED_API, "serviceRole": role, "endpointRole": target,
        "driverConfigurationOriginal": bootstrap["configurationOriginal"],
        "driverWindowOriginal": bootstrap["windowOriginal"], "launchOriginal": source["launchOriginal"],
        "configurationOriginal": service["configurationOriginal"], "runtimeOriginal": service["runtimeOriginal"],
        "preparationOriginal": early["ordinaryPreparationOriginal"],
        "resourcesOriginal": early["ordinaryInitialResourcesOriginal"],
        "initialHistoryOriginal": service["historyOriginal"],
        "rootAuthority": {"keyId": header["authorityHistoryRootKeyId"],
            "keySpkiSha256": header["authorityHistoryRootKeySpkiSha256"]},
        "requestOriginal": request["requestOriginal"], "currentness": selection["currentness"]})


def _runtime(selection, prior, observations, clocks):
    bootstrap = _bootstrap(prior)
    ordinary = _ordinary(prior)
    early, observed = observations["endpoint-inputs"], observations["bridge-runtime"]
    current = current_heads.prepare_context(
        fragment={"apiVersion": current_heads.API, "targets": list(current_heads.JOB_NAMES)},
        bridge_preparation_raw=_raw(observed["bridgePreparationOriginal"]),
        driver_configuration_raw=bootstrap["configuration"], driver_window_raw=bootstrap["window"],
        launch_raw=_raw(profile._input(prior, "ordinary-generation-" + g.ROLES[0])["launchOriginal"]),
        preparation_raw=_raw(early["ordinaryPreparationOriginal"]),
        resources_raw=_raw(early["ordinaryInitialResourcesOriginal"]), ordinary_context=ordinary,
        initial_policy=selection["initialPolicy"],
        **{name: clocks[name] for name in ("boot", "now_boottime_ns")})
    native = {operation: ("native-generation-install-grant" if operation == "generationInstall"
        else "native-service-" + operation) for operation in runtime.native_profile.OPERATIONS + ("publication",)}
    return runtime.build(fragment=selection["runtimePolicy"], current_context=current,
        heads=_records(prior, {name: name for name in current_heads.JOB_NAMES}, "headOriginal"),
        bootstrap_originals=bootstrap,
        driver_observation_raw=_raw(observations["bootstrap-admission"]["bootstrapObservationOriginal"]),
        cohort_observation_raw=_raw(observations["service-originals"]["cohortObservationOriginal"]),
        gate_binding_raw=_raw(observations["endpoint-precreation"]["gateBindingOriginal"]),
        bridge_journal=observed["bridgeJournal"],
        transition_context=_records(prior, {name: name for name in runtime.TRANSITION_JOBS}, "grantOriginal"),
        native_context=_records(prior, native, "grantOriginal"),
        native_delivery_context=_records(prior, {role: "native-delivery-" + role
            for role in profile.ENDPOINTS}, "deliveryOriginal"),
        publication_context=_records(prior, {role: "ordinary-publication-" + role
            for role in profile.PUBLICATION_ROLES}, "grantOriginal"), **clocks)


def _delivery(selection, prior, observations, supervisor_observation, clocks):
    return delivery.build(fragment=selection["commissioningPolicy"],
        runtime_bundle_raw=prior["install-bridge-runtime"]["input"],
        runtime_result=profile._result(prior, "install-bridge-runtime"), bootstrap_originals=_bootstrap(prior),
        activation=observations["bridge-delivery"]["activation"],
        history_originals={role: _raw(profile._input(prior, "ordinary-generation-" + role)
            ["services"][role]["historyOriginal"]) for role in g.ROLES},
        **_sources(supervisor_observation), **clocks)


def _authorization_names():
    return {operation: name for name, operation in profile.legacy.BRIDGE_AUTHORIZATION_JOB_INFO.items()}


def _authorizations(prior, operations):
    names = _authorization_names()
    return _records(prior, {operation: names[operation] for operation in operations}, "authorizationOriginal")


def _common(selection, prior, supervisor_observation):
    return dict(fragment=selection["commissioningPolicy"], control_original=_bootstrap(prior)["control"],
        delivery_input_raw=prior["native-delivery-bridge"]["input"],
        delivery_raw=profile._output(prior, "native-delivery-bridge"), **_sources(supervisor_observation))


def _launch(selection, prior, supervisor_observation):
    common = _common(selection, prior, supervisor_observation)
    return p.canonical({"apiVersion": launch.ADOPTED_INPUT_API, "fragment": common["fragment"],
        "controlOriginal": _text(common["control_original"]),
        "deliveryInputOriginal": _text(common["delivery_input_raw"]),
        "deliveryOriginal": _text(common["delivery_raw"]), "recipeOriginals": common["recipe_originals"],
        "measured": common["measured"], "authorizations": {operation: {field: _text(raw)
            for field, raw in row.items()} for operation, row in _authorizations(prior, authorizations.OPERATIONS).items()},
        "serviceContext": {"inputOriginal": _text(prior["native-service-trustedTime"]["input"]),
            "grantOriginal": _text(profile._output(prior, "native-service-trustedTime"))}})


def _scope(prior, observations, clocks):
    installed = prior["install-launch-bridge"]
    source = launch.input_document(installed["input"])
    checked = launch.prepare_input(installed["input"], **clocks)
    records = {operation: {field: _raw(text) for field, text in row.items()}
        for operation, row in source["authorizations"].items()}
    launch_publication.checked_bridge_result(checked["bundleOriginal"], installed["result"],
        pair_context=authorizations._pair_context(records),
        service_grant_original=_raw(source["serviceContext"]["grantOriginal"]), **clocks)
    bootstrap = _bootstrap(prior)
    public = p.canonical({"runtimeOriginal": profile._input(prior, "install-bridge-runtime")["runtimeOriginal"],
        "deliveryOriginal": _text(profile._output(prior, "native-delivery-bridge")),
        "generationOriginals": {role: _text(profile._output(prior, "ordinary-generation-" + role))
            for role in g.ROLES}})
    return p.canonical({"apiVersion": "serverware.nativePilotScopeSigningInput/v1",
        "configurationOriginal": _text(bootstrap["configuration"]), "windowOriginal": _text(bootstrap["window"]),
        "deliveryConfigurationOriginal": _text(bootstrap["deliveryConfiguration"]),
        "observationOriginal": observations["bootstrap-admission"]["bootstrapObservationOriginal"],
        "operationOriginal": observations["release"]["operationOriginal"],
        "publicBundleOriginal": _text(public), "launchOriginal": _text(checked["prepared"]["native-launch-bridge"]),
        "bootstrapAdmissionOriginal": _text(profile._output(prior, "driver-bootstrap"))})


def compose(selected, selection, *, prior, observations, supervisor_observation,
            boot, now_boottime_ns, now_unix_ns):
    """Return the existing complete job input, never an approval or result."""
    p.fields(selection, selection_fields(selected))
    phase = profile.BY_NAME[selected.name][0]
    p.require(profile._prefix(selected.name, phase, prior, observations) is selected)
    _source_observation(supervisor_observation)
    clocks = dict(boot=boot, now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    family = selected.family
    if family == "current-head": raw = _current_head(selected, selection, prior, observations)
    elif family == "bridge-runtime": raw = _runtime(selection, prior, observations, clocks)
    elif family == "delivery": raw = _delivery(selection, prior, observations, supervisor_observation, clocks)
    elif family == "bridge-authorization":
        operation = profile.legacy.BRIDGE_AUTHORIZATION_JOB_INFO[selected.name]
        before = authorizations.OPERATIONS[:authorizations.OPERATIONS.index(operation)]
        raw = authorizations.build(operation, prior_authorizations=_authorizations(prior, before),
            **_common(selection, prior, supervisor_observation), **clocks)
    elif family == "launch": raw = _launch(selection, prior, supervisor_observation)
    elif family == "scope": raw = _scope(prior, observations, clocks)
    elif family == "phase-two-public":
        raw = phase_two.build(_raw(profile._input(prior, "driver-scope")["publicBundleOriginal"]), adopted=True)
    elif family == "origin": raw = p.canonical({"action": "observe-installed-generation"})
    else:
        p.require(family == "stop")
        raw = p.canonical(selection["action"])
    p.require(len(raw) <= selected.maximum)
    profile.prepare_input(selected.name, raw, phase=phase, prior=prior, observations=observations, **clocks)
    return raw
