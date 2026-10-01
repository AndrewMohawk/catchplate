"""Fixed cold-native candidate composition from literal retained transcripts.

The caller supplies the actual executor's cumulative observations and prior
input/result bytes. Parsing that transcript establishes neither ownership nor
approval. Only closed, purpose-specific static fragments are accepted; keys,
ciphertext, trust, private credentials and independent decisions are not made
here. The facade still checks the complete job prefix and request before an
independent provider authorizes the candidate. No filesystem or signing IO.
"""
from __future__ import annotations

import copy

from serverware import native_pilot_genesis_jobs as jobs
from serverware import native_pilot_genesis_launch_install as installation

p, g = jobs.p, jobs.g
FAMILIES = ("delivery", "role-keys", "admission", "closure", "encrypted-delivery",
    "verifier-transport", "service", "launch", "endpoint-release")
UNIX_FIELDS = ("issuedAtUnixNanos", "expiresAtUnixNanos")


def selection_fields(selected):
    """An exhaustive source-fixed fragment inventory, not a template grammar."""
    _selected(selected)
    if selected.family == "delivery":
        return ("credentials", "image") if selected.role == jobs.COORDINATOR else ("configurationOriginal", "credentials")
    return {"role-keys": jobs.keys.profile.POLICY_FIELDS, "admission": (), "closure": UNIX_FIELDS,
        "encrypted-delivery": ("transportOriginal", "encryptedInventoryOriginal", *UNIX_FIELDS),
        "verifier-transport": ("parentPort", *UNIX_FIELDS), "service": UNIX_FIELDS,
        "launch": ("timeBootstrap", "trustPath"), "endpoint-release": ()}[selected.family]


def _selected(selected):
    p.require(type(selected) is jobs.Job and jobs.BY_NAME.get(selected.name) == selected
        and selected.family in FAMILIES)


def _prior(prior, name, field="result"):
    return jobs._record(prior, name, field)


def _observed(observations, name):
    return jobs._observed(observations, name)


def _parents(observations):
    return {field: _observed(observations, name).decode("ascii") for field, name in jobs.PARENTS.items()}


def _binding(prior):
    raw = _prior(prior, "cold-binding", "input")
    return {"coldBindingInputOriginal": raw.decode("ascii"), "coldBindingInputSha256": p.sha(raw)}


def _source(role, prior):
    name = "native-delivery-" + role
    return {"deliveryInputOriginal": _prior(prior, name, "input").decode("ascii"),
        "deliveryOriginal": _prior(prior, name).decode("ascii"), **_binding(prior)}


def _pair(role, prior):
    result = {}
    for operation, prefix in (("role-keys", "roleKey"), ("admission", "admission")):
        name = "native-" + operation + "-" + role
        result[prefix + "InputOriginal"] = _prior(prior, name, "input").decode("ascii")
        result[prefix + "Original"] = _prior(prior, name).decode("ascii")
    return result


def _delivery(role, selection, observations, clocks):
    parents = _parents(observations)
    parent = jobs.parent.validate_precreation(parents[jobs.delivery.PARENTS[2]].encode("ascii"),
        configuration_raw=parents[jobs.delivery.PARENTS[0]].encode("ascii"),
        delivery_configuration_raw=parents[jobs.delivery.PARENTS[1]].encode("ascii"),
        boot=clocks["boot"], now_boottime_ns=clocks["now_boottime_ns"])
    if role == jobs.COORDINATOR:
        cold_raw = parents[jobs.delivery.PARENTS[1]].encode("ascii")
        runtime_raw = _observed(observations, "coordinator.runtime")
        activation_raw = _observed(observations, "coordinator.activation")
        image, extra = selection["image"], {}
    else:
        cold_raw = jobs.delivery.original(selection["configurationOriginal"], jobs.delivery.MAX_OUTPUT)
        runtime_raw = g.canonical({"apiVersion": "serverware.nativePilotEndpointRuntime/v1", "role": role})
        activation_raw = _observed(observations, "endpoints.activation." + role)
        extra = {field: _observed(observations, name).decode("ascii") for field, name in (
            ("ownerConfigurationOriginal", "endpoints.configuration"),
            ("preparationOriginal", "endpoints.preparation"), ("resourcesOriginal", "endpoints.resources"))}
        owner = jobs.delivery.endpoints.configuration(extra["ownerConfigurationOriginal"].encode("ascii"))
        image = owner["services"][role]["image"]
    cold = g.c9.configuration(cold_raw, p.sha(cold_raw))
    activation = jobs.delivery._activation(activation_raw)
    payload = {"configurationSha256": p.sha(cold_raw), "authorityKeyId": cold["authority"]["keyId"],
        **{name: cold[name] for name in ("serviceRole", "uid", "gid")},
        **{name: parent["window"][name] for name in jobs.delivery.endpoints.WINDOW},
        "runtimeConfig": {"path": installation.DESTINATIONS[role]["runtime"], "sha256": p.sha(runtime_raw)},
        "credentials": copy.deepcopy(selection["credentials"]), "activation": activation}
    # The actual fixed launch installer will later publish this one original.
    # The caller must have provisioned its ciphertext; no placeholder is made.
    encrypted = [row for row in payload["credentials"] if row["name"] == jobs.encrypted.CREDENTIAL]
    p.require(len(encrypted) == 1 and encrypted[0]["original"]["path"]
        == installation.DESTINATIONS[role]["encryptedInventory"])
    return {"apiVersion": jobs.delivery.API, "role": role, "parentOriginals": parents,
        "configurationOriginal": cold_raw.decode("ascii"), "runtimeOriginal": runtime_raw.decode("ascii"),
        "payloadOriginal": g.canonical(payload).decode("ascii"), "activationOriginal": activation_raw.decode("ascii"),
        "image": copy.deepcopy(image), **extra}


def _key(selected, selection, prior):
    role, operation = selected.role, selected.family
    if operation == "admission":
        first = jobs.keys.input_document(_prior(prior, "native-role-keys-" + role, "input"))
        return {"apiVersion": jobs.keys.profile.API, "operation": operation, "role": role,
            **{name: copy.deepcopy(first[name]) for name in (*jobs.keys.profile.SOURCE_FIELDS, "policy")},
            "roleKeyOriginal": _prior(prior, "native-role-keys-" + role).decode("ascii")}
    return {"apiVersion": jobs.keys.profile.API, "operation": operation, "role": role,
        **_source(role, prior), "policy": copy.deepcopy(selection)}


def _service(operation, selection, prior, observations):
    # This is the actual earlier complete runtime input, not newly assembled
    # histories, peer facts or an owner reconstructed from public data.
    current = jobs.ordinary.input_document(_prior(prior, "ordinary-runtime-" + jobs.ORDINARY[0], "input"))
    value = {"apiVersion": jobs.service.API, "operation": operation, **_binding(prior),
        "ordinary": {name: copy.deepcopy(current[name]) for name in ("runtimePolicy", "historyOriginals", "source")},
        **{name: copy.deepcopy(current[name]) for name in ("coordinatorPeerPreparationOriginal", "expectedPeer")},
        "endpointPairs": {role: _pair(role, prior) for role in jobs.service.ENDPOINTS},
        "window": copy.deepcopy(selection)}
    if operation == "retrieval":
        value.update(nativePublicationOriginal=_prior(prior, "native-publication-grant").decode("ascii"),
            retrievalStoreObservationOriginal=_observed(observations, "endpoints.store").decode("ascii"))
    return value


def _launch(role, selection, prior, clocks):
    module = jobs.launch
    operation = module.SELECTORS[role][1]
    value = {"apiVersion": module.API, "role": role, "pairContext": _pair(role, prior),
        "authorizations": {name: {
            "inputOriginal": _prior(prior, "native-" + name + "-" + role, "input").decode("ascii"),
            "authorizationOriginal": _prior(prior, "native-" + name + "-" + role).decode("ascii")}
            for name in module.AUTHORIZATIONS}, "timeBootstrap": copy.deepcopy(selection["timeBootstrap"]),
        "serviceContexts": {name: {
            "inputOriginal": _prior(prior, "native-" + name + "-grant", "input").decode("ascii"),
            "grantOriginal": _prior(prior, "native-" + name + "-grant").decode("ascii")}
            for name in ((operation,) if operation else jobs.service.OPERATIONS)}}
    module._clock_settings(value["timeBootstrap"])
    pair, _, pair_raw = module._pair(value, role, clocks)
    source = pair["source"]
    supplied = jobs.delivery.input_document(source["deliveryInputOriginal"])
    approved = jobs.binding.input_document(source["coldBindingInputOriginal"])
    trust_raw = jobs.keys.profile.original(approved["trustOriginal"], 1024 * 1024)
    trust = g.document(trust_raw, 1024 * 1024)
    encrypted_input = jobs.encrypted.input_document(_prior(prior, "native-encrypted-delivery-" + role, "input"))
    public = {"deliveryConfiguration": supplied["configurationOriginal"].encode("ascii"),
        "delivery": source["deliveryOriginal"], "runtime": source["delivery"]["runtime_raw"], "trust": trust_raw,
        "timeBootstrap": g.canonical({"apiVersion": "serverware.nativeShadowGuestTimeBootstrap/v1",
            "guest": pair["expectedScope"]["guest"], "signingKeyId": trust["timeKey"]["keyId"], **value["timeBootstrap"]}),
        "assignment": approved["assignmentOriginal"].encode("ascii"),
        "closure": _prior(prior, "native-closure-" + role),
        "keys": g.canonical({"apiVersion": "serverware.nativeShadowRoleKeys/v2", "authorization": pair["authorization"]}),
        "encryptedKeys": _prior(prior, "native-encrypted-delivery-" + role),
        "admission": pair_raw["admissionOriginal"], "verifierTransport": _prior(prior, "native-verifier-transport-" + role),
        "encryptedInventory": jobs.keys.profile.original(encrypted_input["encryptedInventoryOriginal"], 32768)}
    if operation:
        public["serviceGrant"] = _prior(prior, "native-" + operation + "-grant")
    pins = {name: {"path": installation.DESTINATIONS[role][name], "sha256": p.sha(raw)}
        for name, raw in public.items() if name not in installation.PREREQUISITES}
    if role == jobs.COORDINATOR:
        owner = g.document(supplied["parentOriginals"]["parentConfigurationOriginal"].encode("ascii"), 65536)
        cold_pin = owner["deliveryConfiguration"]
    else:
        owner = jobs.delivery.endpoints.configuration(supplied["ownerConfigurationOriginal"].encode("ascii"))
        cold_pin = owner["services"][role]["deliveryConfiguration"]
    pins.update(deliveryConfiguration=copy.deepcopy(cold_pin), trust={"path": selection["trustPath"], "sha256": p.sha(trust_raw)})
    native = {"apiVersion": module.SELECTORS[role][0], "keyAdmission": {
        "apiVersion": "serverware.nativeShadowGuestLaunch/v1", **{name: pins[name] for name in module.INNER}}}
    if operation:
        native[operation] = pins["serviceGrant"]
    pins["launch"] = {"path": installation.DESTINATIONS[role]["launch"], "sha256": p.sha(g.canonical(native))}
    value["pins"] = pins
    return value


def _endpoint_release(prior, observations):
    services = {}
    for role in jobs.endpoint_release.ROLES:
        bundle = p.document(_prior(prior, "native-launch-" + role), jobs.launch.MAX_OUTPUT)
        services[role] = {"launch": copy.deepcopy(bundle["launchPin"]), "launchOriginal": bundle["launchOriginal"],
            "closureInputOriginal": _prior(prior, "native-closure-" + role, "input").decode("ascii"),
            "closureOriginal": _prior(prior, "native-closure-" + role).decode("ascii")}
    return {"apiVersion": jobs.endpoint_release.API, "parentOriginals": _parents(observations),
        **{field: _observed(observations, name).decode("ascii") for field, name in (
            ("configurationOriginal", "endpoints.configuration"), ("preparationOriginal", "endpoints.preparation"),
            ("resourcesOriginal", "endpoints.resources"))}, "services": services}


def compose(selected, selection, *, prior, observations, boot, now_boottime_ns, now_unix_ns):
    """Compose and validate one existing cold-native issuer input, unsigned."""
    _selected(selected)
    p.fields(selection, selection_fields(selected))
    p.require(type(prior) is dict and type(observations) is dict)
    clocks = dict(boot=boot, now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    mono = dict(boot=boot, now_boottime_ns=now_boottime_ns)
    family, role = selected.family, selected.role
    if family == "delivery": value = _delivery(role, selection, observations, clocks)
    elif family in ("role-keys", "admission"): value = _key(selected, selection, prior)
    elif family == "closure":
        value = {"apiVersion": jobs.closure.API, "role": role, **_source(role, prior), "policy": copy.deepcopy(selection)}
    elif family in ("encrypted-delivery", "verifier-transport"):
        module = jobs.encrypted if family == "encrypted-delivery" else jobs.verifier
        value = {"apiVersion": module.API, "role": role, **_pair(role, prior), **copy.deepcopy(selection)}
    elif family == "service": value = _service(selected.operation, selection, prior, observations)
    elif family == "launch": value = _launch(role, selection, prior, clocks)
    else:
        p.require(family == "endpoint-release")
        value = _endpoint_release(prior, observations)
    raw = g.canonical(value)
    p.require(0 < len(raw) <= selected.maximum)
    jobs.associate(selected, value, prior=prior, observations=observations)
    if family == "delivery": prepared = jobs.delivery.prepare_input(role, raw, **mono)
    elif family in ("role-keys", "admission"): prepared = jobs.keys.prepare_input(family, role, raw, **clocks)
    elif family in ("closure", "encrypted-delivery", "verifier-transport", "launch"):
        module = {"closure": jobs.closure, "encrypted-delivery": jobs.encrypted,
            "verifier-transport": jobs.verifier, "launch": jobs.launch}[family]
        prepared = module.prepare_input(role, raw, **clocks)
    elif family == "service": prepared = jobs.service.prepare_input(selected.operation, raw, **clocks)
    else: prepared = jobs.endpoint_release.prepare_input(raw, **clocks)
    p.require(now_boottime_ns < prepared["deadline"]
        and (prepared.get("epochLimit") is None or now_unix_ns < prepared["epochLimit"]))
    return raw
