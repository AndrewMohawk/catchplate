"""Fixed release/scope inputs from a genuine owner's immutable public handoff.

The caller retains provenance and first-verification of earlier job results.
This pure layer rechecks literal associations, the original bootstrap/C9 and
cohort signatures, and the authenticated measured closure set. Endpoint image
paths are independently approved references, never discovered or provisioned.
It creates no process, release receipt, currentness decision or renewed window.
"""
from __future__ import annotations

import copy

from serverware import custody_generation_grants as generation
from serverware import native_pilot_bridge_delivery_profile as bridge_delivery
from serverware import native_pilot_bridge_runtime as bridge_runtime
from serverware import native_pilot_bridge_runtime_profile as runtime_builder
from serverware import native_pilot_closure_set as closure_set
from serverware import native_pilot_delivery_authority as c9
from serverware import native_pilot_launch_publication as launch
from serverware import native_pilot_precreation_install as precreation
from serverware import native_pilot_publication as publication
from serverware import native_pilot_scope_authority as scope
from serverware import native_pilot_service_authority as service
from serverware import native_shadow_guest_delivery as delivery
from serverware import native_shadow_proof_cohort_assignment as cohort

p = scope.p
JOBS = ("cohort-release", "driver-scope")
MAX_INPUT = scope.MAX_BRIDGE_INPUT
MAX_RELEASE_INPUT = 2 * 1024 * 1024
COHORT_FIELDS = ("apiVersion", "operation", "configurationOriginal", "configurationSha256",
    "coldOriginals", "payloadOriginal")
COHORT_ARGUMENTS = ("retrieval_configuration_raw", "persistence_configuration_raw",
    "trusted_time_configuration_raw", "generation_install_configuration_raw", "commit_request_configuration_raw",
    "ingress_admission_configuration_raw", "terminal_append_configuration_raw",
    "dispatch_barrier_configuration_raw", "active_effect_barrier_configuration_raw", "active_effect_commit_configuration_raw")
HANDOFF_FIELDS = ("runtime", "records", "sourceInputs", "sourceResults", "conductorOriginals", "deadline", "epochLimit")
RUNTIME_FIELDS = ("inputOriginal", "result", "bootstrapOriginals", "recipeOriginals", "measured",
    "historyOriginals", "trustedTime", "sourceInputs", "sourceResults", "conductorOriginals", "window", "deadline", "epochLimit")
BRIDGE_JOBS = ("native-delivery-bridge", "native-role-keys-bridge", "native-key-admission-bridge",
    "native-closure-bridge", "native-encrypted-delivery-bridge", "native-verifier-transport-bridge", "install-launch-bridge")


def _same(first, second):
    p.require(generation.canonical(first) == generation.canonical(second))


def _bytes(raw, maximum):
    p.require(type(raw) is bytes and 0 < len(raw) <= maximum)
    return raw


def _record(context, phase, job, maximum):
    slot = (phase, job)
    p.require(slot in context["sourceInputs"] and slot in context["sourceResults"])
    raw = _bytes(context["sourceInputs"][slot], maximum)
    result = p.document(_bytes(context["sourceResults"][slot], 32 * 1024 * 1024), 32 * 1024 * 1024)
    return raw, result


def _signed(result, maximum, purpose=None):
    p.fields(result, ("original", "sha256") + (("pin",) if purpose is not None else ()))
    raw, value = (scope._generation_original(result["original"])
        if purpose is not None and purpose.startswith("ordinary-generation-")
        else scope._original(result["original"], maximum))
    p.require(p.sha(raw) == p.digest(result["sha256"]))
    if purpose is not None:
        _same(result["pin"], {"path": publication.DESTINATIONS[purpose], "sha256": p.sha(raw)})
    return raw, value


def _phase(context, name):
    p.require(name in context["conductorOriginals"])
    value = p.fields(p.document(_bytes(context["conductorOriginals"][name], 32 * 1024 * 1024),
        32 * 1024 * 1024), ("apiVersion", "sequence", "phase", "payload", "deadlineBoottimeNs"))
    p.require(value["apiVersion"] == "serverware.nativePilotOperatorRequest/v1" and value["phase"] == name)
    return value


def _installed_launch(role, raw, result, window):
    """Exact previous publication projection, not new installation evidence."""
    value = p.fields(p.document(_bytes(raw, launch.MAX_INPUT), launch.MAX_INPUT), launch.FIELDS)
    p.require(value["apiVersion"] == "serverware.nativePilotLaunchBundle/v1" and value["role"] == role)
    launch._inner(value["keyAdmission"], role)
    runtime_raw, _ = bridge_runtime.original(value["runtimeOriginal"]) if role == "bridge" else scope._original(
        value["runtimeOriginal"], 65536)
    # Bridge runtime was published by the preceding runtime job, not by this
    # launch installer. Endpoints publish their runtime as the tenth file.
    pins = {}
    if role != "bridge":
        purpose = "native-runtime-" + role
        pins[purpose] = {"path": publication.DESTINATIONS[purpose], "sha256": p.sha(runtime_raw)}
    p.fields(value["originals"], launch.COMPONENTS)
    for name, (suffix, maximum) in launch.COMPONENTS.items():
        original, _ = scope._original(value["originals"][name], maximum)
        purpose = "native-" + role + "-" + suffix
        launch.shape(purpose, original)
        pin = {"path": publication.DESTINATIONS[purpose], "sha256": p.sha(original)}
        _same(value["keyAdmission"][name], pin)
        pins[purpose] = pin
    api, field, _ = launch.LAUNCHES[role]
    api = bridge_runtime.launch_for_runtime(runtime_raw) if role == "bridge" else "serverware." + api
    original = p.canonical({"apiVersion": api, "keyAdmission": value["keyAdmission"], field: value["serviceGrant"]})
    purpose = "native-launch-" + role
    launch.shape(purpose, original)
    pins[purpose] = {"path": publication.DESTINATIONS[purpose], "sha256": p.sha(original)}
    expected = launch._installation_result(role, p.sha(raw), window, pins)
    p.fields(result, tuple(expected)); _same(result, expected)
    return original, value


def prepare_release_input(input_raw, *, boot, now_boottime_ns):
    """Public validation shared with the unchanged native cohort release signer."""
    value = p.fields(p.document(_bytes(input_raw, MAX_RELEASE_INPUT), MAX_RELEASE_INPUT),
        COHORT_FIELDS + ("precreationOriginal", "observationsOriginal"))
    p.require(value["apiVersion"] == "serverware.nativePilotCohortAuthorityInput/v1" and value["operation"] == "release")
    config_raw, config = scope._original(value["configurationOriginal"], cohort.MAX_BYTES)
    p.require(config["apiVersion"] == "serverware.nativeShadowProofCohortConfiguration/v7")
    cold = p.fields(value["coldOriginals"], cohort.ENDPOINT_ROLES)
    kwargs = {argument: scope._original(cold[role], 65536)[0]
        for role, argument in zip(cohort.ENDPOINT_ROLES, COHORT_ARGUMENTS, strict=True)}
    return cohort.prepare_release(configuration_raw=config_raw, configuration_sha256=value["configurationSha256"],
        bridge_configuration_raw=None, precreation_raw=scope._original(value["precreationOriginal"], cohort.MAX_BYTES)[0],
        observations_raw=scope._original(value["observationsOriginal"], cohort.MAX_BYTES)[0],
        payload_raw=scope._original(value["payloadOriginal"], cohort.MAX_BYTES)[0],
        boot=boot, now=now_boottime_ns, **kwargs)


def _project(context, endpoint_images, operation_raw, clocks):
    p.fields(context, HANDOFF_FIELDS)
    retained = p.fields(context["runtime"], RUNTIME_FIELDS)
    p.fields(context["records"], BRIDGE_JOBS)
    for job, record in context["records"].items():
        p.fields(record, ("inputOriginal", "result"))
        actual_raw, actual_result = _record(context, "bridge-delivery", job, MAX_INPUT * 2)
        p.require(record["inputOriginal"] == actual_raw)
        _same(record["result"], actual_result)
    bootstrap = p.fields(retained["bootstrapOriginals"], ("control", "configuration", "window", "deliveryConfiguration"))
    early_raw, early_result = _record(context, "bootstrap-admission", "driver-bootstrap", MAX_INPUT)
    early_input = p.document(early_raw, MAX_INPUT)
    for name, raw in bootstrap.items():
        p.require(early_input[name + "Original"] == raw.decode("ascii"))
    early_signed, _ = _signed(early_result, 8192, "driver-bootstrap-admission")
    observed_raw = scope._original(early_input["observationOriginal"], 65536)[0]
    p.require(_phase(context, "bootstrap-admission")["payload"]["bootstrapObservationOriginal"]
        == observed_raw.decode("ascii"))
    before_raw, before_result = _record(context, "endpoint-precreation", "cohort-precreation", MAX_RELEASE_INPUT)
    before = p.fields(p.document(before_raw, MAX_RELEASE_INPUT), COHORT_FIELDS)
    p.require(before["apiVersion"] == "serverware.nativePilotCohortAuthorityInput/v1" and before["operation"] == "precreation")
    before_signed, precreated = _signed(before_result, cohort.MAX_BYTES)
    p.require(p.canonical(precreated["payload"]).decode("ascii") == before["payloadOriginal"])
    installed_raw, _ = _record(context, "endpoint-precreation", "install-precreation", precreation.MAX_INPUT)
    installed = p.fields(p.document(installed_raw, precreation.MAX_INPUT), precreation.FIELDS)
    for name in ("configuration", "window"):
        p.require(installed["driver" + name.title() + "Original"] == bootstrap[name].decode("ascii"))
    p.require(installed["driverObservationOriginal"] == observed_raw.decode("ascii")
        and installed["cohortConfigurationOriginal"] == before["configurationOriginal"]
        and installed["cohortPrecreationOriginal"] == before_signed.decode("ascii"))
    _same(installed["nativeColdOriginals"], before["coldOriginals"])
    cohort_raw, config = scope._original(before["configurationOriginal"], cohort.MAX_BYTES)
    p.require(config["apiVersion"] == "serverware.nativeShadowProofCohortConfiguration/v7"
        and before["configurationSha256"] == p.sha(cohort_raw))
    control = p.document(bootstrap["control"], 4096)
    _same(config["externalDriver"], {"configurationSha256": p.sha(bootstrap["configuration"]),
        "windowSha256": p.sha(bootstrap["window"]), "observationSha256": p.sha(observed_raw),
        "supervisorExecutableSha256": control["supervisorExecutableSha256"]})
    service_observation = _phase(context, "service-originals")["payload"]
    observation_raw, observation = scope._original(service_observation["cohortObservationOriginal"], cohort.MAX_BYTES)
    p.require(_phase(context, "bridge-runtime")["payload"]["cohortObservationOriginal"]
        == service_observation["cohortObservationOriginal"])

    runtime_input = p.document(_bytes(retained["inputOriginal"], MAX_INPUT), MAX_INPUT)
    runtime_raw, operational = bridge_runtime.original(runtime_input["runtimeOriginal"])
    p.require(bridge_runtime.version(operational) == 11)
    runtime_record, runtime_result = _record(context, "bridge-runtime", "install-bridge-runtime", MAX_INPUT)
    p.require(runtime_record == retained["inputOriginal"]); _same(runtime_result, retained["result"])
    bridge_c9 = context["records"][BRIDGE_JOBS[0]]
    c9_input = c9.input_document(bridge_c9["inputOriginal"])
    p.require(c9_input["role"] == "bridge" and c9_input["runtimeOriginal"] == runtime_input["runtimeOriginal"]
        and c9_input["ownerConfigurationOriginal"] == bootstrap["configuration"].decode("ascii")
        and c9_input["configurationOriginal"] == bootstrap["deliveryConfiguration"].decode("ascii")
        and c9_input["windowOriginal"] == bootstrap["window"].decode("ascii")
        and c9_input["observationOriginal"] == observed_raw.decode("ascii"))
    bridge_delivery_raw, bridge_signed = _signed(bridge_c9["result"], delivery.MAX_DELIVERY, "native-delivery-bridge")
    p.require(c9_input["payloadOriginal"] == p.canonical(bridge_signed["payload"]).decode("ascii"))
    window = p.document(bootstrap["window"], 32768)["payload"]
    for name in c9.WINDOW_FIELDS:
        _same(precreated["payload"][name], window[name])
    bridge_launch = context["records"]["install-launch-bridge"]
    launch_raw, launch_bundle = _installed_launch("bridge", bridge_launch["inputOriginal"], bridge_launch["result"], window)
    p.require(launch_bundle["runtimeOriginal"] == runtime_input["runtimeOriginal"])
    operation = p.document(_bytes(operation_raw, 65536), 65536)
    _same(operation["launch"], bridge_launch["result"]["launch"])
    _same(operation["production"], retained["measured"]["production"])
    grants = {}
    for role in generation.ROLES:
        grant_input, grant_result = _record(context, "service-originals", "ordinary-generation-" + role, service.MAX_INPUT_BYTES)
        grant_raw, _ = _signed(grant_result, 65536, "ordinary-generation-" + role)
        original = p.document(grant_input, service.MAX_INPUT_BYTES)
        p.require(original["services"][role]["runtimeOriginal"] == operational["ordinaryInitialHistories"][role]["runtimeOriginal"]
            and operational["ordinaryInitialHistories"][role]["generationGrantOriginal"] == grant_raw.decode("ascii")
            and operational["generationAdmission"]["grants"][role] == p.sha(grant_raw))
        grants[role] = grant_raw.decode("ascii")
    bundle = p.canonical({"runtimeOriginal": runtime_raw.decode("ascii"),
        "deliveryOriginal": bridge_delivery_raw.decode("ascii"), "generationOriginals": grants})
    scope_raw = p.canonical({"apiVersion": "serverware.nativePilotScopeSigningInput/v1",
        "configurationOriginal": bootstrap["configuration"].decode("ascii"),
        "windowOriginal": bootstrap["window"].decode("ascii"), "observationOriginal": observed_raw.decode("ascii"),
        "operationOriginal": operation_raw.decode("ascii"), "publicBundleOriginal": bundle.decode("ascii"),
        "deliveryConfigurationOriginal": bootstrap["deliveryConfiguration"].decode("ascii"),
        "launchOriginal": launch_raw.decode("ascii"), "bootstrapAdmissionOriginal": early_signed.decode("ascii")})
    prepared_scope = scope.prepare_input(scope_raw, **clocks)
    _, expiry = bridge_delivery._assignment(retained["recipeOriginals"], retained["measured"],
        p.document(bootstrap["configuration"], 65536), p.document(observed_raw, 65536), window, clocks["now_unix_ns"])
    selected = closure_set.validate(retained["recipeOriginals"]["closureSetOriginal"].encode("ascii"))
    p.fields(endpoint_images, cohort.ENDPOINT_ROLES)
    payload = {"apiVersion": cohort.release_api(config), "configurationSha256": p.sha(cohort_raw),
        "precreationSha256": p.sha(before_signed), "observationSha256": p.sha(observation_raw),
        "invocationId": observation["invocationId"], "signingKeyId": config["authority"]["keyId"],
        "externalDriverSha256": cohort.external_driver_sha256(config, observation)}
    for role in cohort.ENDPOINT_ROLES:
        image = endpoint_images[role]; delivery._pin(image)
        manifest = selected["members"][closure_set.ROLES.index(role)]["manifest"]
        p.require(image["sha256"] == manifest["imageSha256"])
        input_raw, result = _record(context, "service-originals", "install-launch-" + role, launch.MAX_INPUT)
        _, endpoint_bundle = _installed_launch(role, input_raw, result, precreated["payload"])
        p.require(endpoint_bundle["ownerConfigurationSha256"] == p.sha(cohort_raw)
            and endpoint_bundle["windowSha256"] == p.sha(before_signed)
            and endpoint_bundle["observationOriginal"] == observation_raw.decode("ascii"))
        _same(endpoint_bundle["keyAdmission"]["deliveryConfiguration"], config[role + "Configuration"])
        closure = p.document(endpoint_bundle["originals"]["closure"].encode("ascii"), 1024 * 1024)
        _same(closure["manifest"], manifest)
        p.require(p.canonical(closure["closureSet"]).decode("ascii") == retained["recipeOriginals"]["closureSetOriginal"])
        payload[role] = {"launch": copy.deepcopy(result["launch"]), "image": copy.deepcopy(image)}
    release_raw = p.canonical({**before, "operation": "release", "payloadOriginal": p.canonical(payload).decode("ascii"),
        "precreationOriginal": before_signed.decode("ascii"), "observationsOriginal": observation_raw.decode("ascii")})
    prepared_release = prepare_release_input(release_raw, boot=clocks["boot"], now_boottime_ns=clocks["now_boottime_ns"])
    deadline = min(p.integer(context["deadline"], maximum=p.MAX_U64), p.integer(retained["deadline"], maximum=p.MAX_U64),
        prepared_scope["deadline"], prepared_release["deadline"])
    epoch = min(p.integer(context["epochLimit"]), p.integer(retained["epochLimit"]), prepared_scope["epochLimit"], expiry)
    p.require(clocks["now_boottime_ns"] < deadline and clocks["now_unix_ns"] < epoch)
    return release_raw, scope_raw, window, deadline, epoch


def prepare(job, *, commissioning_context, endpoint_images, operation_raw, boot, now_boottime_ns, now_unix_ns):
    p.require(type(job) is str and job in JOBS)
    runtime_builder._size((commissioning_context, endpoint_images, operation_raw))
    first, second, window, deadline, epoch = _project(commissioning_context, endpoint_images, operation_raw,
        dict(boot=boot, now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns))
    raw = first if job == JOBS[0] else second
    _bytes(raw, MAX_RELEASE_INPUT if job == JOBS[0] else MAX_INPUT)
    return {"inputOriginal": raw, "window": copy.deepcopy(window), "deadline": deadline, "epochLimit": epoch}


def build(job, **kwargs):
    return prepare(job, **kwargs)["inputOriginal"]


def checked_result(job, input_raw, result, **kwargs):
    expected = prepare(job, **kwargs)
    p.require(type(input_raw) is bytes and input_raw == expected["inputOriginal"])
    clocks = {name: kwargs[name] for name in ("boot", "now_boottime_ns", "now_unix_ns")}
    if job == "driver-scope":
        return scope.checked_result(input_raw, result, **clocks)
    prepared = prepare_release_input(input_raw, boot=clocks["boot"], now_boottime_ns=clocks["now_boottime_ns"])
    raw, signed = _signed(result, cohort.MAX_BYTES)
    p.fields(signed, ("payload", "signatureBase64url")); _same(signed["payload"], prepared["payload"])
    prepared["key"].verify(p.decoded(signed["signatureBase64url"], size=64), prepared["message"])
    return raw
