"""Closed adopted ordinary candidates from literal retained public transcripts.

Selections contain independent public policy, never identity overrides or
approvals. Preparation, resources, installed metadata and signed predecessor
originals remain byte-bound to the existing 176-job profile. This pure compiler
does not observe processes, sign, install, acquire owners or renew a window.
The independently observed peer original is still required: the early cohort
observation does not contain its complete cgroup/label identity.
"""
from __future__ import annotations

import copy

from serverware import custody_generation_grants as g
from serverware import native_pilot_adopted_phase_profile as profile
from serverware import native_pilot_adopted_ordinary_install as installation
from serverware import native_pilot_ordinary_delivery_profile as delivery
from serverware import native_pilot_ordinary_generation_profile as generation
from serverware import native_pilot_ordinary_initial_authority as initial_authority
from serverware import native_pilot_ordinary_initial_profile as initial
from serverware import native_pilot_ordinary_key_profile as key
from serverware import native_pilot_ordinary_publication_authority as publication
from serverware import native_pilot_ordinary_runtime_profile as runtime
from serverware import native_pilot_ordinary_transition_profile as transition
from serverware import native_pilot_publication as public_paths
from serverware import native_pilot_service_authority as service
from serverware import native_pilot_supervisor_initial_history as initial_policy
from serverware import native_shadow_endpoint_driver as endpoint_driver
from serverware import native_shadow_proof_cohort_assignment as cohort
from serverware import native_shadow_retrieval_artifacts as retrieval

p = g.p
FAMILIES = ("ordinary-initial", "helper-initial", "ordinary-installation", "ordinary-delivery",
    "ordinary-generation", "ordinary-dispatch", "ordinary-head", "ordinary-cleanup", "ordinary-current",
    "ordinary-publication")
WINDOW = ("issuedAtBoottimeNanos", "expiresAtBoottimeNanos")
BOOT_FIELDS = ("bootIdBase64url", "timeNamespaceDevice", "timeNamespaceInode",
    "startupDeadlineBoottimeNs", "lifetimeDeadlineBoottimeNs", "invocationId")


def _job(selected):
    p.require(type(selected) is profile.legacy._Job and selected.name in profile.BY_NAME
        and selected == profile.BY_NAME[selected.name][1] and selected.family in FAMILIES)
    return selected


def selection_fields(selected):
    selected = _job(selected)
    if selected.family == "ordinary-initial":
        return initial_policy.ROLE_FIELDS if profile.legacy.INITIAL_JOB_INFO[selected.name][1] == "checkpoint" else ()
    if selected.family == "helper-initial":
        return ()
    if selected.family == "ordinary-installation":
        return ("runtimePolicy", "peerOriginal", "peerSha256")
    if selected.family == "ordinary-delivery":
        return ("credentials",)
    if selected.family == "ordinary-generation":
        return ("generationPolicy", "window") if selected.role == g.ROLES[0] else ()
    if selected.family == "ordinary-publication":
        return ("initialTransitionHeadSha256",)
    return ("transitionPolicy",)


def _raw(text, bound=g.MAX_BYTES):
    return service._original(text, bound)


def _same(first, second):
    p.require(g.canonical(first) == g.canonical(second))


def _checkpoint_policy(value):
    state = g.document(_raw(value["initialStateOriginal"]), 65536)
    payload = g.document(_raw(value["payloadOriginal"]), 65536)
    return {"authorities": copy.deepcopy(value["authorities"]), "endpointRole": payload["endpointRole"],
        **{name: state[name] for name in initial_policy.GENERATIONS + ("deploymentGenerationSha256",)},
        **{name: payload[name] for name in ("revocationGenerationHighWater", "revocationRootSha256")},
        "validity": initial_policy.VALIDITY}


def _initial(selected, selection, prior, observed, now):
    helper = selected.family == "helper-initial"
    if helper:
        slot, operation = profile.legacy.HELPER_INITIAL_JOB_INFO[selected.name]
        role, stem, suffix = g.ROLES[-1], "ordinary-helper-initial-", "-slot" + str(slot)
    else:
        role, operation = profile.legacy.INITIAL_JOB_INFO[selected.name]
        stem, suffix = "ordinary-initial-", "-" + role
    if operation != "checkpoint":
        first = stem + "checkpoint" + suffix
        value = copy.deepcopy(profile._input(prior, first))
        value.update(operation=operation, initialCheckpointOriginal=profile._output(prior, first).decode("ascii"))
        if operation == "assemble":
            value["anchorSignatures"] = {name: profile._output(prior, stem + name + "-anchor" + suffix).decode("ascii")
                for name in initial_authority.KEY_NAMES}
        return p.canonical(value)
    first = profile._input(prior, "install-precreation")
    row = copy.deepcopy(selection)
    if helper:
        primary = profile._input(prior, "ordinary-initial-checkpoint-" + role)
        row = _checkpoint_policy(primary)
        remaining = tuple(name for name in initial.HELPER_ENDPOINT_ROLES if name != row["endpointRole"])
        p.require(len(remaining) == 3)
        row["endpointRole"] = remaining[slot - 1]
    p.fields(row, initial_policy.ROLE_FIELDS)
    p.require(row["validity"] == initial_policy.VALIDITY and row["endpointRole"] in key.ENDPOINT_ROLES
        and (role != g.ROLES[0] or row["endpointRole"] == "settlement-store"))
    launch_raw = _raw(first["ordinaryLaunchOriginal"], 65536)
    launch = g.document(launch_raw, 65536)
    cold_raw = _raw(first["ordinaryColdOriginals"][role], 65536)
    cold = g.configuration(cold_raw, launch["services"][role]["deliveryConfiguration"]["sha256"], role)
    preparation_raw = _raw(observed["ordinaryPreparationOriginal"], key.MAX_PREPARATION)
    resources_raw = _raw(observed["ordinaryInitialResourcesOriginal"], 65536)
    prepared, resources = key.preparation(preparation_raw), initial.resources(resources_raw, adopted=True)
    window = g.document(_raw(first["driverWindowOriginal"], 32768), 32768)["payload"]
    identity = key.prepared_identity(prepared, role=role, endpoint_role=row["endpointRole"],
        launch=launch, configuration=cold, window=window, now=now)
    state = {"apiVersion": initial.ADOPTED_STATE_API if role in initial.ADOPTED_ROLES else initial.STATE_API,
        "serviceRole": role, "preparationSha256": p.sha(preparation_raw), "resourcesSha256": p.sha(resources_raw),
        "launchSha256": p.sha(launch_raw), "endpointProcessIdentitySha256": identity["identitySha256"],
        **{name: prepared[name] for name in BOOT_FIELDS}, "issuedAtBoottimeNs": resources["issuedAtBoottimeNs"],
        **{name: row[name] for name in initial_policy.GENERATIONS + ("deploymentGenerationSha256",)},
        "directories": resources["services"][role]["directories"]}
    initial.prepared_state(state, preparation_raw=preparation_raw, resources_raw=resources_raw, launch_raw=launch_raw,
        configuration=cold, window=window, endpoint_role=row["endpointRole"], now=now, adopted=True)
    domain = key._boot(state)
    payload = {"apiVersion": key.KEY_API, "endpointRole": row["endpointRole"],
        "endpointProcessIdentitySha256": identity["identitySha256"], "exactEndpointGeneration": row["endpointGeneration"],
        "authorizedSigningKeyId": row["authorities"]["service"]["keyId"],
        "authorizedSigningKeySpkiSha256": row["authorities"]["service"]["keySpkiSha256"], "checkpointSequence": 1,
        "predecessorCheckpointSha256": initial.commitments(state, adopted=True)["predecessorCheckpointSha256"],
        "revocationGenerationHighWater": row["revocationGenerationHighWater"], "revocationRootSha256": row["revocationRootSha256"],
        "revocationStatus": "authorized-and-not-revoked", "rollbackFloorCheckpointSequence": 1,
        "rollbackFloorEndpointGeneration": row["endpointGeneration"], "rollbackFloorConsumerSequence": 1,
        "validFromBoottime": {"domain": domain, "absoluteBoottimeNanos": p.ns(state["issuedAtBoottimeNs"])},
        "validUntilBoottime": {"domain": domain, "absoluteBoottimeNanos": p.ns(state["lifetimeDeadlineBoottimeNs"])}}
    return p.canonical({"apiVersion": initial_authority.ADOPTED_INPUT_API, "operation": operation,
        "driverConfigurationOriginal": first["driverConfigurationOriginal"], "driverWindowOriginal": first["driverWindowOriginal"],
        "launchOriginal": first["ordinaryLaunchOriginal"], "configurationOriginal": first["ordinaryColdOriginals"][role],
        "preparationOriginal": observed["ordinaryPreparationOriginal"], "resourcesOriginal": observed["ordinaryInitialResourcesOriginal"],
        "initialStateOriginal": g.canonical(state).decode("ascii"), "authorities": row["authorities"],
        "payloadOriginal": g.canonical(payload).decode("ascii")})


def _peer(selection, first, observed, observations):
    raw = _raw(selection["peerOriginal"], 4096)
    peer = retrieval._peer(raw)
    p.require(raw == g.canonical(peer) and p.sha(raw) == p.digest(selection["peerSha256"]))
    config = cohort.configuration(_raw(first["cohortConfigurationOriginal"], cohort.MAX_BYTES))
    p.require(cohort.adoption_selected(config))
    cohort_raw = _raw(observed["cohortObservationOriginal"], cohort.MAX_BYTES)
    original = p.fields(p.document(cohort_raw, cohort.MAX_BYTES), cohort.originals_fields(config))
    p.require(original["apiVersion"] == cohort.originals_api(config)
        and original["configurationSha256"] == p.sha(_raw(first["cohortConfigurationOriginal"], cohort.MAX_BYTES))
        and original["precreationSha256"] == p.sha(_raw(first["cohortPrecreationOriginal"], cohort.MAX_BYTES)))
    external = endpoint_driver.original(original["externalDriver"], config["externalDriver"])
    bootstrap_raw = _raw(observations["bootstrap-admission"]["bootstrapObservationOriginal"], 65536)
    bootstrap = p.document(bootstrap_raw, 65536)
    p.require(external["observationSha256"] == p.sha(bootstrap_raw)
        and external["configurationSha256"] == p.sha(_raw(first["driverConfigurationOriginal"], 65536))
        and external["windowSha256"] == p.sha(_raw(first["driverWindowOriginal"], 32768))
        and (peer["uid"], peer["gid"]) == (bootstrap["uid"], bootstrap["gid"])
        and (peer["pid"], peer["startTimeTicks"]) == (external["driver"]["processId"], external["driver"]["startTimeTicks"]))
    for target, source in (("executableDevice", "device"), ("executableInode", "inode"),
            ("executableLength", "length"), ("executableSha256", "sha256")):
        p.require(peer[target] == external["executable"][source])
    p.require(peer["executableSha256"] == bootstrap["driver"]["driverExecutableSha256"])
    return peer


def _installation(selection, prior, observed, observations):
    first = profile._input(prior, "install-precreation")
    fragment = selection["runtimePolicy"]
    p.require(fragment["apiVersion"] == runtime.HELPER_API)
    policy = {"apiVersion": initial_policy.POLICY_API, "services": {
        role: _checkpoint_policy(profile._input(prior, "ordinary-initial-checkpoint-" + role)) for role in g.ROLES}}
    runtime.validate_policy(fragment, ordinary_cold_originals=first["ordinaryColdOriginals"], initial_policy=policy)
    peer = _peer(selection, first, observed, observations)
    histories = {role: profile._output(prior, "ordinary-initial-assemble-" + role) for role in g.ROLES}
    helpers = {}
    for raw in (histories[g.ROLES[-1]], *(profile._output(prior, "ordinary-helper-initial-assemble-slot" + str(n)) for n in range(1, 4))):
        endpoint = g.document(raw, g.MAX_BYTES)["initialCheckpoint"]["payload"]["endpointRole"]
        p.require(endpoint not in helpers)
        helpers[endpoint] = raw
    values = {role: runtime.build(role, fragment=fragment, history_originals=histories,
        preparation_raw=_raw(observed["ordinaryPreparationOriginal"], key.MAX_PREPARATION),
        resources_raw=_raw(observed["ordinaryInitialResourcesOriginal"], 65536),
        launch_raw=_raw(first["ordinaryLaunchOriginal"], 65536), configuration_raw=_raw(first["ordinaryColdOriginals"][role], 65536),
        peer=peer, helper_history_originals=helpers, adopted=True).decode("ascii") for role in g.ROLES}
    return p.canonical({"apiVersion": installation.API, "launchOriginal": first["ordinaryLaunchOriginal"],
        "preparationOriginal": observed["ordinaryPreparationOriginal"], "resourcesOriginal": observed["ordinaryInitialResourcesOriginal"],
        **{field: first[field] for field in ("driverConfigurationOriginal", "driverWindowOriginal")},
        "coldOriginals": first["ordinaryColdOriginals"], "historyOriginals": {role: raw.decode("ascii") for role, raw in histories.items()},
        "runtimeOriginals": values})


def _delivery(role, selection, prior, observed):
    first = profile._input(prior, "install-ordinary-runtime")
    launch_raw, cold_raw = _raw(first["launchOriginal"], 65536), _raw(first["coldOriginals"][role], 65536)
    launch, cold = g.document(launch_raw, 65536), g.document(cold_raw, 65536)
    metadata = p.fields(profile._result(prior, "install-ordinary-runtime")["services"][role],
        ("runtimeConfig", "historyCredential", "inspectionCredential"))
    credentials = copy.deepcopy(selection["credentials"])
    p.require(type(credentials) is list)
    credentials.extend(copy.deepcopy([metadata["historyCredential"], metadata["inspectionCredential"]]))
    resources = initial.resources(_raw(first["resourcesOriginal"], 65536), adopted=True)
    payload = {"configurationSha256": p.sha(cold_raw), "authorityKeyId": cold["authority"]["keyId"],
        **{name: cold[name] for name in ("serviceRole", "uid", "gid")}, **{name: launch[name] for name in BOOT_FIELDS},
        "issuedAtBoottimeNs": resources["issuedAtBoottimeNs"], "runtimeConfig": metadata["runtimeConfig"],
        "credentials": credentials, "activation": observed["ordinaryActivations"][role]}
    return delivery.build(role, launch_raw=launch_raw, configuration_raw=cold_raw,
        runtime_raw=_raw(first["runtimeOriginals"][role]), payload_raw=p.canonical(payload), activation=payload["activation"], adopted=True)


def _generation(role, selection, prior, observed, supervisor, clocks):
    first = profile._input(prior, "install-ordinary-runtime")
    _installed_peer(first, prior)
    if role == g.ROLES[0]:
        policy, window = selection["generationPolicy"], p.fields(selection["window"], WINDOW)
    else:
        payload = p.document(_raw(profile._input(prior, "ordinary-generation-" + g.ROLES[0])["payloadOriginal"], 65536), 65536)
        policy = {"apiVersion": generation.API, **{name: payload["scope"][name] for name in generation.POLICY_FIELDS[1:]}}
        window = {name: payload[name] for name in WINDOW}
    bootstrap = profile._input(prior, "driver-bootstrap")
    p.require(bootstrap["windowOriginal"] == first["driverWindowOriginal"]
        and bootstrap["configurationOriginal"] == first["driverConfigurationOriginal"])
    original_window = g.document(_raw(bootstrap["windowOriginal"], 32768), 32768)["payload"]
    original_admission = p.document(profile._output(prior, "driver-bootstrap"), 8192)["payload"]
    p.require(p.ns(original_window["issuedAtBoottimeNs"]) <= p.integer(window[WINDOW[0]], maximum=p.MAX_U64)
        < p.integer(window[WINDOW[1]], maximum=p.MAX_U64)
        <= min(p.ns(original_window["lifetimeDeadlineBoottimeNs"]), p.ns(original_admission["lifetimeDeadlineBoottimeNs"])))
    scope = generation.derive_scope(policy, measured=supervisor["measuredConfiguration"],
        recipe_originals=supervisor["recipeOriginals"], driver_generation_recipe=observed["driverGenerationRecipe"],
        bootstrap_original=profile._output(prior, "driver-bootstrap"),
        bootstrap_configuration_original=_raw(bootstrap["configurationOriginal"], 65536),
        driver_observation_original=_raw(bootstrap["observationOriginal"], 65536),
        now_unix_ns=clocks["now_unix_ns"], adopted=True)
    if role != g.ROLES[0]:
        _same(scope, payload["scope"])
    return generation.build(role, launch_raw=_raw(first["launchOriginal"], 65536),
        configuration_raw=_raw(first["coldOriginals"][role], 65536), delivery_raw=profile._output(prior, "ordinary-delivery-" + role),
        runtime_raw=_raw(first["runtimeOriginals"][role]), history_raw=_raw(first["historyOriginals"][role]), scope=scope,
        issued_boottime_ns=window[WINDOW[0]], expires_boottime_ns=window[WINDOW[1]], adopted=True)


def _installed_peer(first, prior):
    """The later protected endpoint pin must be the very same selected peer."""
    pin = p.fields(profile._input(prior, "endpoint-inputs")["peer"], ("path", "sha256"))
    p.require(pin["path"] == public_paths.DESTINATIONS["endpoint-peer"])
    for role in g.ROLES:
        peer = service._runtime(_raw(first["runtimeOriginals"][role]), role, adopted=True)["expectedPeer"]
        p.require(p.sha(g.canonical(peer)) == p.digest(pin["sha256"]))


def _services(prior):
    first = profile._input(prior, "install-ordinary-runtime")
    _installed_peer(first, prior)
    rows = {}
    for role in g.ROLES:
        value = profile._input(prior, "ordinary-generation-" + role)
        p.require(value["launchOriginal"] == first["launchOriginal"])
        rows[role] = {**copy.deepcopy(value["services"][role]),
            "generationGrantOriginal": profile._output(prior, "ordinary-generation-" + role).decode("ascii")}
    return {"launchOriginal": first["launchOriginal"], "services": rows}


def _transition(selected, selection, prior, clocks):
    operation = selected.family.removeprefix("ordinary-")
    native = {}
    for name in transition.native.OPERATIONS + ("publication",):
        job = "native-generation-install-grant" if name == "generationInstall" else "native-service-" + name
        native[name] = {"inputOriginal": prior[job]["input"], "grantOriginal": profile._output(prior, job)}
    earlier = ("head", "cleanup") if operation == "current" else ("head",) if operation == "cleanup" else ()
    return transition.build(operation, selected.role, fragment=selection["transitionPolicy"],
        ordinary_context=_services(prior), native_context=native,
        prior_transition_originals={name: profile._output(prior, "ordinary-" + name) for name in earlier}, **clocks, adopted=True)


def _publication(role, selection, prior, clocks):
    context = _services(prior)
    launch, startup, lifetime = service._launch(_raw(context["launchOriginal"], 65536), clocks["boot"], clocks["now_boottime_ns"], adopted=True)
    rows = {name: context["services"][name] for name in profile.PUBLICATION_ROLES}
    items = {name: service._service(row, name, launch, clocks["boot"], startup, lifetime,
        clocks["now_boottime_ns"], granted=True, adopted=True) for name, row in rows.items()}
    originals = {}
    for label, operation in (("Publication", "publication"), ("Retrieval", "retrieval")):
        job = "native-service-" + operation
        originals["native" + label + "InputOriginal"] = prior[job]["input"].decode("ascii")
        originals["native" + label + "GrantOriginal"] = profile._output(prior, job).decode("ascii")
    _, pub_raw, pub = publication._native("publication", originals["nativePublicationInputOriginal"], originals["nativePublicationGrantOriginal"], clocks)
    _, ret_raw, _ = publication._native("retrieval", originals["nativeRetrievalInputOriginal"], originals["nativeRetrievalGrantOriginal"], clocks)
    admission = pub["payload"]["admission"]
    authorization = admission["adoption"]["payload"]
    item, durable = items[role], items[profile.PUBLICATION_ROLES[0]]
    head = p.digest(selection["initialTransitionHeadSha256"])
    durable_head = head
    if role != profile.PUBLICATION_ROLES[0]:
        job = "ordinary-publication-" + profile.PUBLICATION_ROLES[0]
        earlier = publication.checked_result(profile.PUBLICATION_ROLES[0], prior[job]["input"], profile._output(prior, job), **clocks)
        durable_head = p.document(earlier, publication.MAX_OUTPUT)["payload"]["initialTransitionHeadSha256"]
    payload = {"apiVersion": publication.GRANT_API, "purpose": "native-policy-publication-state", "serviceRole": role,
        "guest": item["guest"], "runtimeConfigurationSha256": p.sha(item["runtime_raw"]),
        "authorityHistoryManifestSha256": item["history"]["manifestSha256"], "admission": admission,
        "native": {"role": publication.native.LOCAL_ROLES["publication"], **authorization["native"], "grantSha256": p.sha(pub_raw)},
        "retrieval": {"role": publication.native.LOCAL_ROLES["retrieval"], **authorization["retrieval"], "grantSha256": p.sha(ret_raw)},
        "initialTransitionHeadSha256": head, "initialDurableTransitionHeadSha256": durable_head,
        "durableAuthorityEpoch": publication.adopted.epoch_reference(durable["epoch"]),
        "durablePublicKeyBase64url": p.encoded(service._public(publication.history_keys._key(durable["epoch"]["serviceSigningKey"])))}
    return p.canonical({"apiVersion": publication.API, "serviceRole": role, **context, "services": rows,
        "payloadOriginal": p.canonical(payload).decode("ascii"), **originals})


def compose(selected, selection, *, prior, observations, supervisor_observation, boot, now_boottime_ns, now_unix_ns):
    """Produce one existing full input, then run its exact adopted admission."""
    selected = _job(selected)
    p.fields(selection, selection_fields(selected))
    phase = profile.BY_NAME[selected.name][0]
    profile._prefix(selected.name, phase, prior, observations)
    p.require(type(supervisor_observation) is dict
        and supervisor_observation.get("apiVersion") == "serverware.nativePilotAdoptedSupervisorObservation/v1")
    clocks = dict(boot=boot, now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    observed = observations[phase]
    if selected.family in ("ordinary-initial", "helper-initial"):
        raw = _initial(selected, selection, prior, observed, now_boottime_ns)
    elif selected.family == "ordinary-installation":
        raw = _installation(selection, prior, observed, observations)
    elif selected.family == "ordinary-delivery":
        raw = _delivery(selected.role, selection, prior, observed)
    elif selected.family == "ordinary-generation":
        raw = _generation(selected.role, selection, prior, observed, supervisor_observation, clocks)
    elif selected.family == "ordinary-publication":
        raw = _publication(selected.role, selection, prior, clocks)
    else:
        raw = _transition(selected, selection, prior, clocks)
    p.require(type(raw) is bytes and 0 < len(raw) <= selected.maximum)
    profile.prepare_input(selected.name, raw, phase=phase, prior=prior, observations=observations, **clocks)
    return raw
