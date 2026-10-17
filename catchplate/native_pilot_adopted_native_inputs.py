"""Typed adopted endpoint candidates from exact prior public originals.

No signature, approval, process, installation or resource is created here.
Initialization values below are explicit unsigned initialization requests;
only the retained receiver can admit its actual fresh store. Current measured
configuration and source originals are supplied by the selected supervisor
observation and joined to the independently approved adoption input.
"""
from __future__ import annotations

import copy

from catchplate import native_pilot_adopted_phase_profile as phase
from catchplate import native_pilot_adopted_endpoint_authority as endpoints
from catchplate import native_pilot_adopted_launch_profile as launches
from catchplate import native_pilot_adopted_service_authority as adopted_service
from catchplate import native_pilot_key_profile as keys
from catchplate import native_pilot_native_delivery_profile as deliveries
from catchplate import native_pilot_native_service_profile as services
from catchplate import native_pilot_launch_publication as publication
from catchplate import native_pilot_service_material as material

p, g = phase.p, phase.g
FAMILIES = ("delivery", "native-key", "native", "generation-install", "native-launch-authorization", "launch", "service-material")
UNIX = ("issuedAtUnixNanos", "expiresAtUnixNanos")


def _selected(selected):
    p.require(type(selected) is phase.legacy._Job and selected.name in phase.BY_NAME
        and phase.BY_NAME[selected.name][1] == selected and selected.family in FAMILIES
        and selected.role != "bridge")


def selection_fields(selected):
    _selected(selected)
    if selected.family == "delivery": return ("credentials",)
    if selected.family == "native-key":
        return keys.POLICY_FIELDS if phase.KEY_INFO[selected.name][1] == "role-keys" else ()
    if selected.family == "native-launch-authorization":
        operation = phase.AUTH_INFO[selected.name][1]
        return UNIX + {"closure": (), "request-commitment": ("requestCommitmentOriginal",),
            "encrypted-delivery": ("transportOriginal",), "verifier-transport": ("parentPort",)}[operation]
    if selected.family == "launch": return ("timeBootstrap",)
    if selected.family == "service-material": return ("policy",)
    operation = "generationInstall" if selected.family == "generation-install" else selected.role
    return ("verifierSettings", *UNIX, *{"commitRequest": ("runtimeEvidence",),
        "ingress": ("generationId", "originVerifier"), "persistence": ("initialization",),
        "trustedTime": ("timeBootstrap",), "publication": ("firstIngressSequence", "lastIngressSequence"),
        "generationInstall": ("initialization",)}.get(operation, ()))


def _text(raw):
    p.require(type(raw) is bytes and raw.isascii())
    return raw.decode("ascii")


def _sources(prior, supervisor_observation):
    """Full retained measured/source projection, never a partial hash DTO."""
    recipe = copy.deepcopy(p.fields(supervisor_observation["recipeOriginals"], deliveries.RECIPE_FIELDS))
    measured = copy.deepcopy(p.fields(supervisor_observation["measuredConfiguration"], deliveries.MEASURED_FIELDS))
    validation = p.document(phase._raw(phase._input(prior, "publication-adoption")["validationInputOriginal"],
        phase.adoption.MAX_INPUT), phase.adoption.MAX_INPUT)
    for target, source in (("trustOriginal", "currentTrustOriginal"), ("trustSha256", "currentTrustSha256"),
            ("assignmentOriginal", "currentAssignmentOriginal"), ("closureSetOriginal", "currentClosureSetOriginal")):
        phase._same(recipe[target], validation[source])
    phase._same(measured["configurationBindingSha256"], validation["currentConfigurationBindingSha256"])
    phase._same(measured["proofScopeOriginal"], validation["currentProofScopeOriginal"])
    return recipe, measured


def _delivery(selected, selection, prior, observations, clocks):
    role = selected.role
    installed = phase._input(prior, "install-precreation")
    observed = observations[phase.BY_NAME[selected.name][0]]
    cold_raw = phase._raw(installed["nativeColdOriginals"][role], 65536)
    cold = g.c9.configuration(cold_raw, p.sha(cold_raw))
    window_raw = phase._output(prior, "cohort-precreation")
    window = g.document(window_raw, 32768)["payload"]
    runtime_raw = g.canonical({"apiVersion": "catchplate.nativePilotEndpointRuntime/v1", "role": role})
    activation = copy.deepcopy(observed["nativeActivations"][role])
    payload = {"configurationSha256": p.sha(cold_raw), "authorityKeyId": cold["authority"]["keyId"],
        **{name: cold[name] for name in ("serviceRole", "uid", "gid")},
        **{name: window[name] for name in phase.delivery.base.WINDOW_FIELDS},
        "runtimeConfig": {"path": publication.ADOPTED_DESTINATIONS["native-runtime-" + role], "sha256": p.sha(runtime_raw)},
        "credentials": copy.deepcopy(selection["credentials"]), "activation": activation}
    extra = {}
    if role == "retrieval":
        core = observations["endpoint-inputs"]["adoptedCore"]
        extra = {"core_observation_raw": phase._raw(core["observationOriginal"], phase.delivery.core.MAX_OBSERVATION),
            "core_bundle_raw": phase._raw(core["bundleOriginal"], phase.delivery.core.MAX_BUNDLE)}
    return deliveries.build_adopted(role, configuration_raw=cold_raw,
        owner_configuration_raw=phase._raw(installed["cohortConfigurationOriginal"]), window_raw=window_raw,
        observation_raw=phase._raw(observed["cohortObservationOriginal"]), runtime_raw=runtime_raw,
        payload_raw=g.canonical(payload), activation=activation, **clocks, **extra)


def _key(selected, selection, prior, supervisor_observation):
    role, operation = phase.KEY_INFO[selected.name]
    recipe, measured = _sources(prior, supervisor_observation)
    policy = selection if operation == "role-keys" else phase._input(prior, "native-role-keys-" + role)["policy"]
    value = {"apiVersion": keys.ADOPTED_API, "operation": operation, "role": role,
        "deliveryInputOriginal": _text(prior["native-delivery-" + role]["input"]),
        "deliveryOriginal": _text(phase._output(prior, "native-delivery-" + role)),
        "recipeOriginals": recipe, "measured": measured, "policy": copy.deepcopy(policy)}
    if operation == "admission": value["roleKeyOriginal"] = _text(phase._output(prior, "native-role-keys-" + role))
    return value


def _context(role, selection, prior, supervisor_observation, clocks):
    raw_pair = phase._pair(prior, role)
    pair = keys.admitted_adopted_pair(role, *(raw_pair[name].encode("ascii") for name in endpoints.PAIR_FIELDS), **clocks)
    first = phase._input(prior, "native-role-keys-" + role)
    recipe, measured = _sources(prior, supervisor_observation)
    phase._same(first["recipeOriginals"], recipe); phase._same(first["measured"], measured)
    guest = pair["expectedScope"]["guest"]
    settings = copy.deepcopy(selection["verifierSettings"])
    services._verifier(settings, now=clocks["now_unix_ns"])
    p.require(settings["uid"] != guest["uid"] and settings["gid"] != guest["gid"])
    operation = {name: guest[name] for name in ("bootIdBase64url", "timeNamespaceDevice", "timeNamespaceInode", "issuedAtBoottimeNs")}
    operation["deadlineBoottimeNs"] = guest["startupDeadlineBoottimeNs"]
    config = {"apiVersion": "catchplate.nativeShadowNitroVerifierConfiguration/v2", **settings, "operation": operation, **pair}
    config_raw = p.canonical(config)
    envelope = p.document(phase._raw(recipe["assignmentOriginal"]), p.MAX_CONFIG)
    source = endpoints.context(role, pair=raw_pair,
        delivery_input_original=prior["native-delivery-" + role]["input"],
        delivery_original=phase._output(prior, "native-delivery-" + role),
        configuration_original=config_raw, configuration_sha256=p.sha(config_raw),
        assignment_payload_original=p.canonical(envelope["payload"]), **clocks)
    endpoints.require_interval(source, *(selection[name] for name in UNIX), now_unix_ns=clocks["now_unix_ns"])
    common = services.commitment._common(config, source["admitted"], source["keys"],
        *(selection[name] for name in UNIX), clocks["now_unix_ns"])
    delivered_input = phase._input(prior, "native-delivery-" + role)
    return {"selected": source, "raw_pair": raw_pair, "config": config, "config_raw": config_raw,
        "guest": guest, "common": common, "delivery": delivered_input,
        "delivery_original": first["deliveryOriginal"], "recipe": recipe, "measured": measured,
        "assignment": envelope["payload"], "assignment_raw": phase._raw(recipe["assignmentOriginal"]),
        "admitted": source["admitted"], "keys": source["keys"],
        "proof_raw": phase._raw(measured["proofScopeOriginal"], 16384),
        "proof": services.retrieval.scope_original(phase._raw(measured["proofScopeOriginal"], 16384))}


def _ordinary(prior, context, clocks):
    """Authenticate the five actual prior generations before deriving scope."""
    first = phase._input(prior, "ordinary-generation-" + g.ROLES[0])
    original = {"launchOriginal": first["launchOriginal"], "services": {}}
    launch, startup, lifetime = services.ordinary._launch(phase._raw(first["launchOriginal"], 65536),
        clocks["boot"], clocks["now_boottime_ns"], adopted=True)
    rows, scopes, peers, floors, ceilings = {}, [], [], [p.ns(context["guest"]["issuedAtBoottimeNs"])], [p.ns(context["guest"]["lifetimeDeadlineBoottimeNs"])]
    for role in g.ROLES:
        supplied = phase._input(prior, "ordinary-generation-" + role)
        phase._same(supplied["launchOriginal"], first["launchOriginal"])
        row = copy.deepcopy(supplied["services"][role])
        row["generationGrantOriginal"] = _text(phase._output(prior, "ordinary-generation-" + role))
        item = services.ordinary._service(row, role, launch, clocks["boot"], startup, lifetime,
            clocks["now_boottime_ns"], granted=True, adopted=True)
        endpoints.require_generation_scope(context["selected"], item["generation"]["scope"])
        original["services"][role] = row
        root = item["history"]["rootAuthority"]
        rows[role] = {"grantOriginal": row["generationGrantOriginal"], "runtimeOriginal": row["runtimeOriginal"],
            "historyOriginal": row["historyOriginal"], "rootKeyId": root["keyId"], "rootKeySpkiSha256": root["keySpkiSha256"]}
        scopes.append(item["generation"]["scope"]); peers.append(item["header"]["expectedPeer"])
        floors.append(item["generation"]["issuedAtBoottimeNanos"]); ceilings.append(item["generation"]["expiresAtBoottimeNanos"])
    for scope, peer in zip(scopes[1:], peers[1:], strict=True):
        phase._same(scope, scopes[0]); phase._same(peer, peers[0])
    common = scopes[0]
    scope = {"productionConfigurationBindingSha256": common["successorConfigurationBindingSha256"],
        **{name: common[name] for name in ("kernelDriverIdentitySha256", "retainedDescriptorSetSha256",
            "driverGenerationReceiptSha256", "assignmentPayloadSha256", "assignmentRevision")},
        "issuedAtBoottimeNanos": max(floors), "expiresAtBoottimeNanos": min(ceilings)}
    p.require(scope["issuedAtBoottimeNanos"] <= clocks["now_boottime_ns"] < scope["expiresAtBoottimeNanos"])
    return original, rows, scope, copy.deepcopy(peers[0])


def _native(selected, selection, prior, observations, supervisor_observation, clocks):
    operation = "generationInstall" if selected.family == "generation-install" else selected.role
    role = "generationInstall" if operation == "generationInstall" else phase.NATIVE_ENDPOINT[operation]
    context = _context(role, selection, prior, supervisor_observation, clocks)
    ordinary, rows, scope, peer = _ordinary(prior, context, clocks)
    peer_raw = p.canonical(peer)
    actual_inputs = phase._input(prior, "endpoint-inputs")
    p.require(actual_inputs["peer"]["sha256"] == p.sha(peer_raw)
        and actual_inputs["proofScope"]["sha256"] == p.sha(context["proof_raw"]))
    if operation == "generationInstall":
        p.require(selection["initialization"] == "fresh-generation")
        value = services._generation(context, ordinary, rows, peer,
            {"generationInstall": {"keyHistory": {"currentKeyEpoch": 1, "predecessors": []}, "recordOriginals": []}})
        value.update(apiVersion=services.installation.ADOPTED_INPUT_API,
            deliveryInputOriginal=_text(prior["native-delivery-" + role]["input"]), pair=context["raw_pair"])
        return value
    if operation in adopted_service.PROFILES:
        value = {"apiVersion": adopted_service.INPUT_API, "operation": operation,
            "configurationOriginal": _text(context["config_raw"]), "configurationSha256": p.sha(context["config_raw"]),
            "deliveryInputOriginal": _text(prior["native-delivery-" + role]["input"]),
            "deliveryOriginal": _text(phase._output(prior, "native-delivery-" + role)),
            "adoptionValidationInputOriginal": phase._input(prior, "publication-adoption")["validationInputOriginal"],
            "adoptionAuthorizationOriginal": _text(phase._output(prior, "publication-adoption")),
            "peerOriginal": _text(peer_raw), "peerSha256": p.sha(peer_raw), **{name: selection[name] for name in UNIX}}
    else:
        value = services._base(operation, context, peer_raw)
        value.update(apiVersion=services.authority.ADOPTED_INPUT_API,
            deliveryInputOriginal=_text(prior["native-delivery-" + role]["input"]), pair=context["raw_pair"])
        if operation in services.authority.HISTORY_OPERATIONS:
            value.update(ordinaryLaunchOriginal=ordinary["launchOriginal"], services=ordinary["services"])
    if operation == "commitRequest":
        runtime = services.evidence.runtime(selection["runtimeEvidence"], assignment_original=context["assignment_raw"],
            issued_at_unix_ns=selection[UNIX[0]], expires_at_unix_ns=selection[UNIX[1]], now_unix_ns=clocks["now_unix_ns"])
        observation = context["assignment"]["observationWindow"]
        scope.update(runtime=runtime, **{name: observation[name] for name in ("requestCommitmentKeyId", "requestCommitmentKeyEpoch")})
        value.update(commitmentScopeOriginal=_text(p.canonical(scope)), runtimeEvidence=copy.deepcopy(selection["runtimeEvidence"]),
            assignmentOriginal=_text(context["assignment_raw"]))
    elif operation in services.authority.SIGNERS or operation in ("publication", "retrieval"):
        if operation == "ingress":
            scope.update(generationId=p.digest(selection["generationId"]), proofScopeSha256=p.sha(context["proof_raw"]),
                retrievalNamespaceSha256=context["proof"]["retrieval_namespace_sha256"])
            origin = copy.deepcopy(selection["originVerifier"])
        else:
            ingress = phase._input(prior, "native-service-ingress")
            supplied = p.document(phase._raw(ingress["spoolScopeOriginal"], 16384), 16384)
            for name in scope: phase._same(scope[name], supplied[name])
            scope = supplied
            origin = p.document(phase._raw(ingress["originVerifierOriginal"], 4096), 4096)
        value["spoolScopeOriginal"] = _text(p.canonical(scope))
        if operation in services.authority.SIGNERS:
            value.update(proofScopeOriginal=_text(context["proof_raw"]), originVerifierOriginal=_text(p.canonical(origin)))
            if operation == "ledger":
                value.update(companionOriginal=_text(phase._output(prior, "native-service-commitRequest")),
                    companionPin=copy.deepcopy(phase._result(prior, "native-service-commitRequest")["pin"]))
        elif operation == "publication":
            value.update(retrievalDeliveryInputOriginal=_text(prior["native-delivery-retrieval"]["input"]),
                retrievalDeliveryOriginal=_text(phase._output(prior, "native-delivery-retrieval")),
                ordinaryServices={member: {"generationGrantOriginal": row["grantOriginal"],
                    **{name: row[name] for name in adopted_service.ordinary.MEMBER_FIELDS if name != "generationGrantOriginal"}}
                    for member, row in rows.items()}, **{name: selection[name] for name in ("firstIngressSequence", "lastIngressSequence")})
        else:
            value.update(endpointDeliveryResultOriginal=_text(g.canonical(observations["service-originals"]["endpointDeliveryResult"])),
                publicationGrantOriginal=_text(phase._output(prior, "native-service-publication")),
                nativeGrantOriginals={name: _text(phase._output(prior, "native-service-" + name)) for name in services.authority.SIGNERS})
    elif operation == "persistence":
        p.require(selection["initialization"] == "fresh-persistence")
        genesis = p.canonical({"apiVersion": "catchplate.nativeShadowPersistenceGenesis/v1",
            "proofScopeSha256": context["proof"]["binding_sha256"], "guest": context["guest"]})
        value.update(genesisOriginal=_text(genesis), journalOriginal=_text(p.canonical({"genesisSha256": p.sha(genesis),
            "headSequence": 0, "headSha256": p.sha(genesis)})), permissions=list(adopted_service.PERMISSIONS))
    else:
        p.require(operation == "trustedTime")
        p.fields(selection["timeBootstrap"], ("parentPort", "maximumBracketNanos", "timestampErrorNanos", "maximumClockRateErrorPpm"))
        trust = p.document(phase._raw(context["recipe"]["trustOriginal"], 1024 * 1024), 1024 * 1024)
        value["bootstrapOriginal"] = _text(p.canonical({"apiVersion": "catchplate.nativeShadowGuestTimeBootstrap/v1",
            "guest": context["guest"], "signingKeyId": trust["timeKey"]["keyId"], **copy.deepcopy(selection["timeBootstrap"])}))
    return value


def _authorization(selected, selection, prior, clocks):
    role, operation = phase.AUTH_INFO[selected.name]
    pair = phase._pair(prior, role)
    if operation == "closure":
        authenticated = keys.admitted_adopted_pair(role, *(pair[name].encode("ascii") for name in endpoints.PAIR_FIELDS), **clocks)
        first = phase._input(prior, "native-role-keys-" + role)
        delivered = phase._input(prior, "native-delivery-" + role)
        context = keys.prepare_input("admission", role, prior["native-key-admission-" + role]["input"], **clocks)
        recipe = first["recipeOriginals"]
        envelope = p.document(phase._raw(recipe["assignmentOriginal"]), p.MAX_CONFIG)
        leaf = keys.assignments.closure_binding(envelope, phase._raw(recipe["closureSetOriginal"]), role,
            set_api_version=keys.closure_set.PUBLICATION_API)
        checkpoint, supervisor = context["trustCheckpoint"], context["authorityKeys"][-1]
        payload = {"apiVersion": "catchplate.nativeCustodyClosureAssignment/v5", "purpose": "shadow-custody-closure-set-member",
            "profile": phase.commands.closure.ADOPTED_PROFILE, "guestRole": role,
            "assignmentId": envelope["payload"]["assignmentId"], "assignmentPayloadSha256": envelope["payloadSha256"],
            "assignmentRevision": envelope["payload"]["assignmentRevision"], "manifestSha256": context["manifest"]["manifestSha256"],
            "guest": authenticated["expectedScope"]["guest"], **{name: checkpoint[name] for name in ("revocationGeneration", "revocationRootSha256")},
            "trustCheckpointId": checkpoint["checkpointId"], **copy.deepcopy(selection),
            "signingKeyId": supervisor["keyId"], "signingKeySpkiSha256": supervisor["keySpkiSha256"],
            **{name: leaf[name] for name in ("setRootSha256", "seccompSetRootSha256", "leafSha256")}}
        return {"apiVersion": phase.commands.closure.ADOPTED_API, "guestRole": role,
            "deliveryInputOriginal": first["deliveryInputOriginal"], "deliveryOriginal": first["deliveryOriginal"],
            "configurationOriginal": delivered["ownerConfigurationOriginal"], "deliveryConfigurationOriginal": delivered["configurationOriginal"],
            **{name: delivered[name] for name in ("windowOriginal", "observationOriginal", "runtimeOriginal")}, **recipe,
            "manifestOriginal": _text(p.canonical(context["manifest"])), "payloadOriginal": _text(p.canonical(payload))}
    verifier = operation == "verifier-transport"
    value = {"apiVersion": phase.commands.verifier.ADOPTED_API if verifier else phase.commands.encrypted.ADOPTED_API,
        "role": role, **pair, **copy.deepcopy(selection)}
    if not verifier:
        value["operation"] = "delivery" if operation == "encrypted-delivery" else operation
        if operation == "encrypted-delivery" and role == "commitRequest":
            value["requestCommitmentOriginal"] = _text(phase._output(prior, "native-request-commitment-commitRequest"))
    return value


def _launch(selected, selection, prior):
    role = selected.role
    operation = phase.GRANT_FOR_ENDPOINT.get(role)
    source = "native-generation-install-grant" if role == "generationInstall" else "native-service-" + operation
    names = launches.AUTHORIZATIONS + (("request-commitment",) if role == "commitRequest" else ())
    value = {"apiVersion": launches.ALL_API, "role": role, "pair": phase._pair(prior, role),
        "authorizations": {name: {"inputOriginal": _text(prior["native-" + name + "-" + role]["input"]),
            "original": _text(phase._output(prior, "native-" + name + "-" + role))} for name in names},
        "serviceInputOriginal": _text(prior[source]["input"]), "serviceGrantOriginal": _text(phase._output(prior, source)),
        "timeBootstrap": copy.deepcopy(selection["timeBootstrap"])}
    if role == "commitRequest":
        value.update(companionInputOriginal=_text(prior["native-service-commitRequest"]["input"]),
            companionGrantOriginal=_text(phase._output(prior, "native-service-commitRequest")))
    return value


def compose(selected, selection, *, prior, observations, supervisor_observation, boot, now_boottime_ns, now_unix_ns):
    """Return a typed candidate only; the facade separately binds the request."""
    _selected(selected); p.fields(selection, selection_fields(selected))
    clocks = dict(boot=boot, now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    family, role = selected.family, selected.role
    if family == "delivery": raw = _delivery(selected, selection, prior, observations, clocks)
    elif family == "service-material":
        contexts, pins = {}, {}
        for member in material.ROLES:
            source = "native-generation-install-grant" if member == "generationInstall" else "native-service-" + member
            contexts[member] = {"inputOriginal": prior[source]["input"], "grantOriginal": phase._output(prior, source)}
            pins[member] = copy.deepcopy(phase._result(prior, "install-launch-" + member)["launch"])
        return material.build(fragment=selection["policy"], service_contexts=contexts, endpoint_launches=pins, adopted=True, **clocks)
    else:
        if family == "native-key": value = _key(selected, selection, prior, supervisor_observation)
        elif family in ("native", "generation-install"): value = _native(selected, selection, prior, observations, supervisor_observation, clocks)
        elif family == "native-launch-authorization": value = _authorization(selected, selection, prior, clocks)
        else: value = _launch(selected, selection, prior)
        raw = p.canonical(value)
    p.require(0 < len(raw) <= selected.maximum)
    if family in ("native", "generation-install"):
        operation = "generationInstall" if family == "generation-install" else role
        context = services.prepare_adopted_input(operation, raw, **clocks)
    else:
        operation = "delivery" if family == "delivery" else "launch" if family == "launch" else (
            phase.KEY_INFO[selected.name][1] if family == "native-key" else phase.AUTH_INFO[selected.name][1])
        context = phase.commands.prepare_input(role, "verifier" if operation == "verifier-transport" else operation, raw, **clocks)
    p.require(now_boottime_ns < context["deadline"] and (context.get("epochLimit") is None or now_unix_ns < context["epochLimit"]))
    return raw
