"""Typed cold ordinary candidate composition, never approval or observation.

Selections contain only explicit public policy/configuration facts. Actual
observations and completed input/result originals come from the caller's
retained dialogue. No owner, signature, authority, clock or path is created.
The facade separately enforces the complete prefix and authentic request; the
existing issuers authenticate these same full inputs before any key access.
"""
from __future__ import annotations

import copy

from serverware import native_pilot_genesis_jobs as jobs

g, p = jobs.g, jobs.p
initial, ordinary, runtime = jobs.initial, jobs.ordinary, jobs.runtime
COUNTERS = ("deploymentGenerationSha256", "endpointGeneration", "serviceGeneration", "operationGeneration", "durableEpoch")
CHECKPOINT_POLICY = ("revocationGenerationHighWater", "revocationRootSha256", "revocationStatus",
    "validFromBoottimeNanos", "validUntilBoottimeNanos")
PEER_POLICY = ("securityLabelSha256", "configurationGenerationSha256")


def selection_fields(selected):
    """Exact public fragments for the existing ordinary job selections."""
    p.require(type(selected) is jobs.Job and jobs.BY_NAME.get(selected.name) == selected
        and selected.family in ("initial", "ordinary-runtime", "ordinary"))
    if selected.family == "initial":
        return ("configurationOriginal", "endpointRole", "counters", "authorities", "checkpointPolicy") if (
            selected.operation == "checkpoint") else ()
    if selected.family == "ordinary-runtime":
        return ("runtimePolicy", "peerPolicy") if selected.role == jobs.ORDINARY[0] else ()
    return ("initialTransitionHeadSha256",) if selected.operation == "grant" else ()


def _text(raw):
    p.require(type(raw) is bytes and raw.isascii() and len(raw) > 0)
    return raw.decode("ascii")


def _source(observations):
    return {**{name: _text(jobs._observed(observations, observed)) for name, observed in jobs.PARENTS.items()},
        **{name: _text(jobs._observed(observations, observed)) for name, observed in (
            ("launchOriginal", "ordinary.configuration"), ("preparationOriginal", "ordinary.preparation"),
            ("resourcesOriginal", "ordinary.resources"))}}


def _initial(selected, selection, prior, observations, mono):
    role, operation = selected.role, selected.operation
    if operation != "checkpoint":
        p.fields(selection, ())
        name = "initial-checkpoint-" + role
        value = copy.deepcopy(initial.input_document(jobs._record(prior, name, "input")))
        p.require(value["serviceRole"] == role and value["operation"] == "checkpoint")
        value.update(operation=operation, initialCheckpointOriginal=_text(jobs._record(prior, name)))
        if operation == "assemble":
            value["anchorSignatures"] = {signer: _text(jobs._record(prior, "initial-" + signer + "-anchor-" + role))
                for signer in initial.KEY_NAMES}
        return value
    p.fields(selection, ("configurationOriginal", "endpointRole", "counters", "authorities", "checkpointPolicy"))
    counters = p.fields(selection["counters"], COUNTERS)
    authorities = p.fields(selection["authorities"], initial.KEY_NAMES)
    policy = p.fields(selection["checkpointPolicy"], CHECKPOINT_POLICY)
    source = _source(observations) | {"configurationOriginal": selection["configurationOriginal"]}
    arguments = {argument: initial._original(source[name], maximum)[0]
        for name, (argument, maximum) in initial.SOURCE_FIELDS.items()}
    state_raw = initial.state_original(role=role, endpoint_role=selection["endpointRole"],
        counters=counters, **arguments, **mono)
    state = g.document(state_raw, initial.profile.MAX_STATE)
    roots, domain = initial.profile.commitments(state), initial.key._boot(state)
    payload = {"apiVersion": initial.key.KEY_API, "endpointRole": selection["endpointRole"],
        "endpointProcessIdentitySha256": state["endpointProcessIdentitySha256"],
        "exactEndpointGeneration": state["endpointGeneration"],
        "authorizedSigningKeyId": authorities["service"]["keyId"],
        "authorizedSigningKeySpkiSha256": authorities["service"]["keySpkiSha256"],
        "checkpointSequence": 1, "predecessorCheckpointSha256": roots["predecessorCheckpointSha256"],
        **{name: policy[name] for name in CHECKPOINT_POLICY[:3]},
        "rollbackFloorCheckpointSequence": 1, "rollbackFloorEndpointGeneration": state["endpointGeneration"],
        "rollbackFloorConsumerSequence": 1,
        "validFromBoottime": {"domain": domain, "absoluteBoottimeNanos": policy["validFromBoottimeNanos"]},
        "validUntilBoottime": {"domain": domain, "absoluteBoottimeNanos": policy["validUntilBoottimeNanos"]}}
    return {"apiVersion": initial.INPUT_API, "operation": operation, "serviceRole": role, **source,
        "initialStateOriginal": _text(state_raw), "authorities": copy.deepcopy(authorities),
        "payloadOriginal": _text(g.canonical(payload))}


def _peer(source, observation_raw, selected, mono):
    """Measured fields from the observation; labels remain independent policy."""
    p.fields(selected, PEER_POLICY)
    for value in selected.values():
        p.digest(value)
    arguments = runtime.source_arguments(source, jobs.ORDINARY[0])
    args = dict(observation_raw=arguments["parent_observation_raw"],
        configuration_raw=arguments["parent_configuration_raw"], precreation_raw=arguments["parent_precreation_raw"],
        delivery_configuration_raw=arguments["parent_delivery_configuration_raw"], **mono)
    observed = runtime.coordinator.validate(observation_raw, **args)
    _, cold = initial.parent.validate_configuration(arguments["parent_configuration_raw"],
        arguments["parent_delivery_configuration_raw"])
    row = observed["peers"][runtime.coordinator.ROLE]
    value = {"uid": cold["uid"], "gid": cold["gid"], "pid": row["processId"], "startTimeTicks": row["startTimeTicks"],
        **{"executable" + name[0].upper() + name[1:]: row["targetExecutable"][name]
            for name in ("device", "inode", "length", "sha256")},
        "cgroupPathSha256": row["cgroup"]["pathSha256"], "cgroupMountId": row["cgroup"]["mountId"],
        "cgroupInode": row["cgroup"]["inode"], **copy.deepcopy(selected)}
    value["processIdentitySha256"] = runtime.peers.peer_identity(value)
    return runtime.coordinator.expected_peer(observation_raw, approved=value, **args)


def _common(selected, selection, prior, observations, mono):
    role = selected.role
    if role != jobs.ORDINARY[0]:
        p.fields(selection, ())
        first = ordinary.input_document(jobs._record(prior, "ordinary-runtime-" + jobs.ORDINARY[0], "input"))
        p.require(first["operation"] == "delivery" and first["serviceRole"] == jobs.ORDINARY[0])
        return {**{name: copy.deepcopy(first[name]) for name in ordinary.COMMON}, "serviceRole": role}
    p.fields(selection, ("runtimePolicy", "peerPolicy"))
    configurations = {}
    for name in jobs.ORDINARY:
        checkpoint = initial.input_document(jobs._record(prior, "initial-checkpoint-" + name, "input"))
        p.require(checkpoint["operation"] == "checkpoint" and checkpoint["serviceRole"] == name)
        configurations[name] = checkpoint["configurationOriginal"]
    source = _source(observations) | {"configurationOriginals": configurations}
    peer_raw = jobs._observed(observations, "parent.peer")
    return {"apiVersion": ordinary.API, "operation": "delivery", "serviceRole": role,
        "source": source, "runtimePolicy": runtime.validate_policy(selection["runtimePolicy"]),
        "historyOriginals": {name: _text(jobs._record(prior, "initial-assemble-" + name)) for name in jobs.ORDINARY},
        "coordinatorPeerPreparationOriginal": _text(peer_raw),
        "expectedPeer": _peer(source, peer_raw, selection["peerPolicy"], mono)}


def _runtime(selected, selection, prior, observations, mono):
    role = selected.role
    value = _common(selected, selection, prior, observations, mono)
    histories = {name: text.encode("ascii") for name, text in value["historyOriginals"].items()}
    held, peer = runtime.contexts(fragment=value["runtimePolicy"], history_originals=histories,
        source=value["source"], peer_preparation_raw=value["coordinatorPeerPreparationOriginal"].encode("ascii"),
        approved_peer=value["expectedPeer"], **mono)
    runtime_raw = runtime._compose(role, value["runtimePolicy"], held, peer)
    header = runtime.validate_runtime(role, runtime_raw)["runtime"]
    actual_inputs = g.document(jobs._observed(observations, "ordinary.runtime-inputs." + role), 65536)
    p.fields(actual_inputs, ("listenerSocketPath", "activationDirectoryIdentities"))
    jobs._same(actual_inputs, {name: header[name] for name in actual_inputs})
    item = held[role]
    cold, state = item["observed"]["cold"], item["state"]
    activation = jobs.delivery._activation(jobs._observed(observations, "ordinary.activation." + role))
    credentials = copy.deepcopy(value["runtimePolicy"]["services"][role]["credentials"])
    inspection_raw = runtime.inspection_original(role, runtime_raw, cold, state)
    prefix = "/etc/serverware/custody-" + role + "-"
    for name, suffix, raw in ((runtime.recipe.HISTORY_NAME, "initial-history", histories[role]),
            (runtime.recipe.INSPECTION_NAME, "peer-inspection", inspection_raw)):
        credentials.append({"name": name, "original": {"path": prefix + suffix + ".json", "sha256": p.sha(raw)},
            "length": len(raw), "signing": None})
    payload = {"configurationSha256": p.sha(runtime.source_arguments(value["source"], role)["configuration_raw"]),
        "authorityKeyId": cold["authority"]["keyId"], **{name: cold[name] for name in ("serviceRole", "uid", "gid")},
        **{name: state[name] for name in initial.parent.WINDOW_FIELDS[2:]},
        "runtimeConfig": {"path": prefix + "runtime.json", "sha256": p.sha(runtime_raw)},
        "credentials": credentials, "activation": activation}
    return value | {"payloadOriginal": _text(g.canonical(payload)), "activation": activation}


def _grant(selected, selection, prior, observations):
    p.fields(selection, ("initialTransitionHeadSha256",))
    p.digest(selection["initialTransitionHeadSha256"])
    original = ordinary.input_document(jobs._record(prior, "ordinary-delivery-" + selected.role, "input"))
    p.require(original["operation"] == "delivery" and original["serviceRole"] == selected.role)
    cold_raw = jobs._record(prior, "cold-binding", "input")
    return {**{name: copy.deepcopy(original[name]) for name in ordinary.COMMON}, "operation": "grant",
        "deliveryOriginals": {role: _text(jobs._record(prior, "ordinary-delivery-" + role)) for role in jobs.ORDINARY},
        "activation": {role: jobs.delivery._activation(jobs._observed(observations, "ordinary.activation." + role))
            for role in jobs.ORDINARY}, "coldBindingInputOriginal": _text(cold_raw), "coldBindingInputSha256": p.sha(cold_raw),
        "nativePublicationOriginal": _text(jobs._record(prior, "native-publication-grant")),
        "nativeRetrievalOriginal": _text(jobs._record(prior, "native-retrieval-grant")), **copy.deepcopy(selection)}


def compose(selected, selection, *, prior, observations, boot, now_boottime_ns, now_unix_ns):
    """Compose one existing full input from a closed operation selection.

    Initial checkpoint: configurationOriginal, endpointRole, counters5,
    authorities3, checkpointPolicy5. First runtime: runtimePolicy + peerPolicy2
    independent labels. Grant: initialTransitionHeadSha256. Every other selected
    operation requires an empty selection and retains predecessor policy bytes.
    Initial roots/sequences follow persisted State/v2 semantics, not caller
    roots or an assertion that an empty directory establishes durable state.
    """
    p.fields(selection, selection_fields(selected))
    p.require(type(prior) is dict and type(observations) is dict)
    p.integer(now_boottime_ns, maximum=p.MAX_U64); p.integer(now_unix_ns, maximum=p.MAX_I64)
    mono = dict(boot=boot, now_boottime_ns=now_boottime_ns)
    if selected.family == "initial":
        value = _initial(selected, selection, prior, observations, mono)
        raw = g.canonical(value)
        initial.prepare_input(selected.operation, raw, **mono)
    else:
        if selected.family == "ordinary-runtime":
            value = _runtime(selected, selection, prior, observations, mono)
            raw = g.canonical(value)
        elif selected.operation == "delivery":
            p.fields(selection, ())
            raw = jobs._record(prior, "ordinary-runtime-" + selected.role, "input")
            value = ordinary.input_document(raw)
        else:
            value = _grant(selected, selection, prior, observations)
            raw = g.canonical(value)
        ordinary.prepare_input(selected.operation, raw, **mono, now_unix_ns=now_unix_ns)
    p.require(len(raw) <= selected.maximum)
    jobs.associate(selected, value, prior=prior, observations=observations)
    return raw
