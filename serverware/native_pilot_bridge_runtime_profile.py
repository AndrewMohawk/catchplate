"""Compose explicit v11/v12 bridges from actual prior public originals.

Independent policy supplies only final peer expectations, credential names,
external endpoints and bounded startup configuration. All observations and
signed transitions come from the caller's retained conductor. These pure
checks establish cryptographic/byte associations, not live ownership, installed
credentials, currentness decisions, service readiness or permission to publish.
"""
from __future__ import annotations

import copy
import stat

from serverware import custody_generation_grants as g
from serverware import custody_spool_inputs as spool
from serverware import native_pilot_bridge_install as install
from serverware import native_pilot_bridge_preparation as preparation
from serverware import native_pilot_bridge_runtime_policy as policy
from serverware import native_pilot_current_head_profile as head
from serverware import native_pilot_delivery_authority as c9
from serverware import native_pilot_helper_bootstrap_profile as helper
from serverware import native_pilot_native_service_authority as native_authority
from serverware import native_pilot_native_service_profile as native_profile
from serverware import native_pilot_ordinary_initial_profile as initial
from serverware import native_pilot_ordinary_runtime_profile as ordinary_runtime
from serverware import native_pilot_ordinary_transition_profile as transitions
from serverware import native_pilot_peer_preparation as peers
from serverware import native_pilot_publication as publication
from serverware import native_pilot_service_authority as service
from serverware import native_pilot_service_handshakes as handshakes
from serverware import native_pilot_supervisor_current_head_profile as current_heads
from serverware import native_pilot_window_authority as windows
from serverware import native_shadow_driver_outgoing as outgoing
from serverware import native_shadow_driver_resources as resources
from serverware import native_shadow_guest_delivery as delivery
from serverware import native_shadow_key_admission_profile as admission

p = g.p
API = "serverware.nativePilotBridgeRuntimeBundle/v1"
MAX_INPUT = install.MAX_BRIDGE_INPUT
MAX_CONTEXT = 128 * 1024 * 1024
TRANSITION_JOBS = tuple("ordinary-" + operation + ("-" + role if operation == "dispatch" else "")
    for operation, role in transitions.JOBS)
SERVICE_ACTIVATIONS = {role: "service-" + role for role in g.ROLES}
SIGNER_ACTIVATIONS = {role: "signer-" + role for role in sorted(outgoing._SIGNERS)}
PROOF_ACTIVATIONS = {role: "proof-" + role for role in outgoing._PROOFS}
_OPERATION = {"retrieval": "retrieval", "persistence": "persistence", "trustedTime": "trustedTime",
    "generationInstall": "generationInstall", "commitRequest": "ledger", "ingressAdmission": "ingress",
    "terminalAppend": "terminal", "dispatchBarrier": "dispatchBarrier", "activeEffectBarrier": "activeEffectBarrier",
    "activeEffectCommit": "activeEffectCommit"}
_KEY_ROLE = {role: ("custody-result-envelope" if role == "generationInstall"
    else native_authority._LOCAL_ROLE[operation]) for role, operation in _OPERATION.items()}


def _same(first, second):
    p.require(g.canonical(first) == g.canonical(second))


def _result(raw):
    return {"original": raw.decode("ascii"), "sha256": p.sha(raw)}


def _records(value, names, output_name, input_maximum, output_maximum):
    p.fields(value, names)
    for row in value.values():
        p.fields(row, ("inputOriginal", output_name))
        for name, maximum in (("inputOriginal", input_maximum), (output_name, output_maximum)):
            p.require(type(row[name]) is bytes and 0 < len(row[name]) <= maximum)


def _size(value):
    """Bound public retained work without encoding bytes or narrowing u64."""
    pending, total, nodes = [value], 0, 0
    while pending:
        item = pending.pop(); nodes += 1
        p.require(nodes <= 262144)
        if type(item) is dict:
            pending.extend(item.values()); total += sum(len(name) for name in item)
        elif type(item) in (list, tuple):
            pending.extend(item)
        elif type(item) in (str, bytes):
            total += len(item)
        else:
            total += len(g.canonical(item))
        p.require(total <= MAX_CONTEXT)


def _bootstrap(originals, observation_raw, *, boot, now):
    p.fields(originals, ("control", "configuration", "window", "deliveryConfiguration"))
    control = p.fields(p.document(originals["control"], 4096),
        ("apiVersion", "supervisorExecutableSha256", "configurationSha256", "windowSha256"))
    p.require(control["apiVersion"] == "serverware.nativeShadowDriverBootstrapControl/v1"
        and p.digest(control["configurationSha256"]) == p.sha(originals["configuration"])
        and p.digest(control["windowSha256"]) == p.sha(originals["window"]))
    p.digest(control["supervisorExecutableSha256"])
    config = windows.validate_configuration(originals["configuration"])
    cold = windows.validate_delivery(config, originals["deliveryConfiguration"])
    signed = p.document(originals["window"], 32768)
    observed = p.document(observation_raw, 65536)
    window = c9.bridge_owner(cold, originals["deliveryConfiguration"], originals["configuration"],
        originals["window"], signed, observed, boot=boot, now=now)
    windows.validate_window(window, originals["configuration"], config, boot=boot, now=now)
    return config, cold, window, observed


def _gate(raw, config, window, observation_raw, observed, *, now):
    notice = p.fields(p.document(raw, 8192), ("apiVersion", "configurationSha256", "windowSha256",
        "bootstrapObservationSha256", "gateExecutableSha256", "binding"))
    binding = p.fields(notice["binding"], ("apiVersion", "preparedSha256", "gateProcessId", "gateStartTimeTicks",
        "uid", "gid", "observedAtBoottimeNs"))
    p.require(notice["apiVersion"] == "serverware.nativeShadowDriverGateBound/v1"
        and notice["configurationSha256"] == window["configurationSha256"]
        and notice["bootstrapObservationSha256"] == p.sha(observation_raw)
        and notice["gateExecutableSha256"] == config["lifecycle"]["gate"]["executableSha256"]
        and binding["apiVersion"] == "serverware.nativeShadowDriverLifecycleBound/v1"
        and binding["gateProcessId"] == observed["processId"]
        and binding["gateStartTimeTicks"] == observed["startTimeTicks"]
        and observed["targetExecutable"]["sha256"] == notice["gateExecutableSha256"]
        and p.ns(window["issuedAtBoottimeNs"]) <= p.ns(binding["observedAtBoottimeNs"]) <= now)
    p.digest(binding["preparedSha256"])
    ids = {name: binding[name] for name in ("uid", "gid")}
    p.require(ids == {name: config["lifecycle"]["gate"][name] for name in ids})
    return ids, notice


def _signing_digest(role, item):
    runtime = ordinary_runtime.validate_runtime(role, item["runtime_raw"])
    name = runtime["serviceSigningKeyCredential" if role == g.ROLES[3] else "signingKeyCredential"]
    credentials = p.document(item["delivery_raw"], 65536)["payload"]["credentials"]
    matches = [row for row in credentials if row["name"] == name]
    p.require(len(matches) == 1 and matches[0]["signing"] is not None)
    # This is the credential ORIGINAL's byte digest, not its public-key SPKI.
    return p.digest(matches[0]["original"]["sha256"])


def _project(fragment, *, current_context, heads, ordinary, native, transition_originals,
             bootstrap_originals, driver_observation_raw, cohort_observation_raw, gate_binding_raw,
             bridge_journal, boot, now_boottime_ns):
    """Internal deterministic projection, called only after full prepare admission.

    The item dictionaries are prechecked PUBLIC data, never authority-bearing
    owners. Calling this internal projection alone proves neither their source
    nor native/transition signatures; prepare/build are the complete entrypoints.
    """
    fragment = policy.validate_policy(fragment)
    p.fields(ordinary, g.ROLES); p.fields(native, peers.NATIVE_ROLES)
    p.fields(transition_originals, TRANSITION_JOBS)
    _records(heads, current_heads.JOB_NAMES, "headOriginal", head.MAX_INPUT, head.MAX_OUTPUT)
    config, cold, window, driver_observed = _bootstrap(bootstrap_originals, driver_observation_raw,
        boot=boot, now=now_boottime_ns)
    sources = current_context["sources"]
    p.require(sources["driver_configuration_raw"] == bootstrap_originals["configuration"]
        and sources["driver_window_raw"] == bootstrap_originals["window"])
    observed = preparation.shape(sources["bridge_preparation_raw"])
    _, peer_rows = preparation._parts(observed)
    p.require(observed["apiVersion"] == preparation.HELPER_API
        and observed["driverObservationSha256"] == p.sha(driver_observation_raw)
        and peer_rows["native-endpoints"]["sourceOriginalSha256"] == p.sha(cohort_observation_raw))
    cohort = p.document(cohort_observation_raw, 32768)
    peer = ordinary[g.ROLES[0]]["header"]["expectedPeer"]
    policy._peer(peer)
    p.require((peer["uid"], peer["gid"]) == (cold["uid"], cold["gid"])
        and peer["pid"] == driver_observed["processId"]
        and peer["startTimeTicks"] == driver_observed["driver"]["processStartTimeTicks"]
        and peer["executableSha256"] == driver_observed["driver"]["driverExecutableSha256"]
        and peer["cgroupMountId"] == driver_observed["driver"]["cgroupMountId"]
        and peer["cgroupInode"] == driver_observed["driver"]["cgroupInode"])
    external = cohort["externalDriver"]
    p.require(external["driver"]["processId"] == peer["pid"]
        and external["driver"]["startTimeTicks"] == peer["startTimeTicks"])
    for target, source in (("executableDevice", "device"), ("executableInode", "inode"),
            ("executableLength", "length"), ("executableSha256", "sha256")):
        p.require(peer[target] == external["executable"][source])
    gate_ids, gate = _gate(gate_binding_raw, config, window, driver_observation_raw,
        peer_rows["gate"]["peers"]["gate"], now=now_boottime_ns)
    p.require(gate["windowSha256"] == p.sha(bootstrap_originals["window"]))
    ids = {"gate": {"gate": gate_ids}, "ordinary-services": {}, "native-endpoints": {}}
    expected = {kind: {} for kind in ids}
    common_fields = ("operationGeneration", "sharedConfigurationSha256", "productionDispatchProtocolSetSha256",
        "maximumDurabilityWorkerNanos")
    common = {name: ordinary[g.ROLES[0]]["header"][name] for name in common_fields}
    for role, item in ordinary.items():
        _same(item["header"]["expectedPeer"], peer)
        _same({name: item["header"][name] for name in common_fields}, common)
        ids["ordinary-services"][role] = {name: item["guest"][name] for name in ("uid", "gid")}
    for role, item in native.items():
        p.fields(item, ("guest", "key", "expectedPeer"))
        _same(item["expectedPeer"], peer)
        ids["native-endpoints"][role] = {name: item["guest"][name] for name in ("uid", "gid")}
        child, measured = cohort[role], peer_rows["native-endpoints"]["peers"][role]
        p.require(child["processId"] == measured["processId"] and child["startTimeTicks"] == measured["startTimeTicks"]
            and child["executable"] == measured["targetExecutable"])
    for kind, selected in ids.items():
        for role, identity in selected.items():
            expected[kind][role] = policy.build_peer(peer_rows[kind]["peers"][role], identity,
                fragment["peerExpectations"][kind][role])
    p.fields(bridge_journal, initial.IDENTITY_FIELDS)
    for name in initial.IDENTITY_FIELDS:
        p.integer(bridge_journal[name], minimum=0 if name in ("deviceMajor", "deviceMinor") else 1,
            maximum=(1 << (32 if name in ("deviceMajor", "deviceMinor", "uid", "gid", "mode") else 64)) - 1)
    p.require(bridge_journal["mode"] == stat.S_IFDIR | 0o700
        and (bridge_journal["uid"], bridge_journal["gid"]) == (cold["uid"], cold["gid"]))
    sessions = []
    for role in g.ROLES:
        selected = []
        for job, (target, endpoint_role) in zip(current_heads.JOB_NAMES, current_heads.TARGETS, strict=True):
            if role != target:
                continue
            row = heads[job]
            value = p.document(row["inputOriginal"], head.MAX_INPUT)
            actual = current_context["targets"][job]
            p.require(value["serviceRole"] == role and value["requestOriginal"] == actual["request"]["requestOriginal"])
            request_raw = handshakes.build(row["inputOriginal"], _result(row["headOriginal"]), boot=boot,
                now_boottime_ns=now_boottime_ns, client_process_identity_sha256=peer["processIdentitySha256"],
                client_configuration_generation_sha256=peer["configurationGenerationSha256"])
            selected.append({"endpointRole": actual["endpointRole"], "request": p.document(request_raw, handshakes.MAX_BYTES)})
        sessions.append({"serviceRole": role, "activationFdName": SERVICE_ACTIVATIONS[role],
            "expectedSocketPath": ordinary_runtime.listener(role), "expectedPeer": expected["ordinary-services"][role],
            "handshakes": selected})
    endpoints = {}
    for field, discriminator, mapping, activations in (
            ("parentSignerEndpoints", "signerRole", preparation.NATIVE_SIGNERS, SIGNER_ACTIVATIONS),
            ("proofEndpoints", "endpointKind", preparation.NATIVE_PROOFS, PROOF_ACTIVATIONS)):
        rows = []
        for name in activations:
            binding = fragment["authorityBindings"][name]
            if name in mapping:
                role = mapping[name]
                public = native[role]["key"]
                p.public_key(public)
                p.require(public["role"] == _KEY_ROLE[role]
                    and binding["authorityKeyId"] == public["keyId"]
                    and binding["authorityKeySpkiSha256"] == public["keySpkiSha256"])
                socket = (outgoing._NATIVE_SIGNERS if field == "parentSignerEndpoints" else outgoing._PROOFS)[name][0]
                selected_peer = expected["native-endpoints"][role]
            else:
                selected = fragment["externalSignerEndpoints"][name]
                socket, selected_peer = selected["expectedSocketPath"], selected["expectedPeer"]
            p.require(all(binding[key] != p.sha(b"") for key in ("authorityKeyId", "authorityKeySpkiSha256")))
            rows.append({discriminator: name, **binding, "activationFdName": activations[name],
                "expectedSocketPath": socket, "expectedPeer": copy.deepcopy(selected_peer)})
        endpoints[field] = rows
    histories = [{"serviceRole": role, "manifestCredential": fragment["historyCredentials"][role],
        "manifestSha256": item["header"]["authorityHistoryManifestSha256"],
        "rootKeyId": item["header"]["authorityHistoryRootKeyId"],
        "rootKeySpkiSha256": item["header"]["authorityHistoryRootKeySpkiSha256"]} for role, item in ordinary.items()]
    helper_deadline = min((row["request"]["deadline"] for row in sessions[-1]["handshakes"]),
        key=lambda value: value["absoluteBoottimeNanos"])
    terminal = fragment["apiVersion"] == policy.TERMINAL_API
    launch_api = "serverware.nativeProofBridgeLaunch/v8" if terminal else "serverware.nativeProofBridgeLaunch/v7"
    runtime = {"apiVersion": "serverware.policyCustodyProductionRpcRuntime/v12" if terminal else "serverware.policyCustodyProductionRpcRuntime/v11",
        "startupTimeoutMillis": fragment["startupTimeoutMillis"], "listenerSocketPath": resources.LISTENER_PATH,
        "expectedFacadePeer": expected["gate"]["gate"], "journalDirectoryIdentity": copy.deepcopy(bridge_journal),
        "expectedHelperEndpointRoles": list(helper.ROLES), "expectedDriverProcessIdentitySha256": peer["processIdentitySha256"],
        "expectedDriverConfigurationGenerationSha256": peer["configurationGenerationSha256"],
        "expectedOperationGeneration": common["operationGeneration"],
        "expectedSharedConfigurationSha256": common["sharedConfigurationSha256"],
        "expectedServiceConfigurationSha256": {role: p.sha(item["runtime_raw"]) for role, item in ordinary.items()},
        "expectedServiceSigningCredentialSha256": {role: _signing_digest(role, item) for role, item in ordinary.items()},
        "expectedServiceRestartEpoch": {role: item["header"]["serviceRestartEpoch"] for role, item in ordinary.items()},
        "expectedServiceReadinessEpoch": {role: item["header"]["readinessEpoch"] for role, item in ordinary.items()},
        "expectedServiceAuthorityHistoryManifestSha256": {role: item["header"]["authorityHistoryManifestSha256"] for role, item in ordinary.items()},
        "expectedProductionDispatchProtocolSetSha256": common["productionDispatchProtocolSetSha256"],
        "expectedMaximumDurabilityWorkerNanos": common["maximumDurabilityWorkerNanos"],
        "serviceSessions": sessions, "histories": histories, **endpoints,
        "generationAdmission": {"apiVersion": "serverware.custodyGenerationServices/v1",
            "grants": {role: p.sha(item["grant_raw"]) for role, item in ordinary.items()}},
        "commitRequest": {"apiVersion": "serverware.nativeCommitRequestServices/v1", "serviceGrantOriginals": {
            role: transition_originals["ordinary-dispatch-" + role].decode("ascii") for role in (g.ROLES[0], g.ROLES[3])}},
        "spool": {"apiVersion": "serverware.nativeSpoolServices/v3", "originFdName": "generation-origin",
            **{field: transition_originals[job].decode("ascii") for field, job in (
                ("headGrantOriginal", "ordinary-head"), ("cleanupGrantOriginal", "ordinary-cleanup"),
                ("currentGrantOriginal", "ordinary-current"))}},
        "ordinaryInitialHistories": {role: {"runtimeOriginal": item["runtime_raw"].decode("ascii"),
            "generationGrantOriginal": item["grant_raw"].decode("ascii"),
            **({"historyOriginal": item["history_raw"].decode("ascii")} if terminal else {})} for role, item in ordinary.items()},
        "helperBootstrap": helper.shape(helper.build(ordinary[g.ROLES[-1]]["runtime_raw"], deadline=helper_deadline))}
    runtime_raw = p.canonical(runtime)
    install.shape("bridge-runtime", runtime_raw)
    outgoing._selection(runtime_raw, launch_api, cold["uid"])
    outgoing._peer(runtime["expectedFacadePeer"], cold["uid"])
    preparation.require_runtime(sources["bridge_preparation_raw"], runtime_raw,
        driver_observation_raw=driver_observation_raw, cohort_observation_raw=cohort_observation_raw, peer_ids=ids)
    selected = {"apiVersion": "serverware.nativeShadowDriverOutgoingInputs/v1",
        "driverConfigurationSha256": p.sha(bootstrap_originals["configuration"]),
        "driverWindowSha256": p.sha(bootstrap_originals["window"]), "driverObservationSha256": p.sha(driver_observation_raw),
        "invocationId": window["invocationId"], "deliveryConfiguration": config["deliveryConfiguration"],
        "runtime": {"path": install.RUNTIME_DESTINATION, "sha256": p.sha(runtime_raw)},
        "bridgeLaunchVersion": launch_api}
    outgoing_raw = p.canonical(selected)
    install.shape("bridge-outgoing", outgoing_raw)
    bundle = p.canonical({"apiVersion": API, "driverControlSha256": p.sha(bootstrap_originals["control"]),
        "driverObservationOriginal": driver_observation_raw.decode("ascii"), "runtimeOriginal": runtime_raw.decode("ascii"),
        "outgoingOriginal": outgoing_raw.decode("ascii")})
    p.require(len(bundle) <= MAX_INPUT)
    return bundle


def _native_delivery(role, row, value, *, cohort_observation_raw):
    original = c9.input_document(row["inputOriginal"])
    p.require(original["role"] == role and role in peers.NATIVE_ROLES)
    generation = role == "generationInstall"
    fields = {"configurationOriginal": "coordinatorConfigurationOriginal" if generation else "coldConfigurationOriginal",
        "ownerConfigurationOriginal": "cohortConfigurationOriginal", "windowOriginal": "precreationOriginal",
        "observationOriginal": "observationOriginal",
        "runtimeOriginal": "coordinatorRuntimeOriginal" if generation else "runtimeOriginal"}
    for field, source in fields.items():
        p.require(original[field] == value[source])
    p.require(original["observationOriginal"].encode("ascii") == cohort_observation_raw
        and row["deliveryOriginal"].decode("ascii") == value["coordinatorDeliveryOriginal" if generation else "deliveryOriginal"])
    signed = p.document(row["deliveryOriginal"], 65536)
    p.require(p.canonical(signed["payload"]) == original["payloadOriginal"].encode("ascii"))
    _, activation = c9._original(original["activationOriginal"], 32768, array=True)
    _same(activation, signed["payload"]["activation"])


def prepare(*, fragment, current_context, heads, bootstrap_originals, driver_observation_raw,
            cohort_observation_raw, gate_binding_raw, bridge_journal, transition_context,
            native_context, native_delivery_context, boot, now_boottime_ns, now_unix_ns):
    """Authenticate the complete literal source graph before public projection."""
    fragment = policy.validate_policy(fragment)
    _size((fragment, current_context, heads, bootstrap_originals, driver_observation_raw,
        cohort_observation_raw, gate_binding_raw, bridge_journal, transition_context, native_context, native_delivery_context))
    clocks = dict(boot=boot, now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    checked = current_heads._refresh(current_context, boot=boot, now_boottime_ns=now_boottime_ns)
    _records(heads, current_heads.JOB_NAMES, "headOriginal", head.MAX_INPUT, head.MAX_OUTPUT)
    for job, row in heads.items():
        current_heads._prepared_input(job, row["inputOriginal"],
            context=checked, boot=boot, now_boottime_ns=now_boottime_ns)
        head.checked_result(row["inputOriginal"], _result(row["headOriginal"]),
            boot=boot, now_boottime_ns=now_boottime_ns)
    _records(native_context, native_profile.OPERATIONS, "grantOriginal", native_profile.MAX_INPUT, native_profile.MAX_OUTPUT)
    _records(native_delivery_context, peers.NATIVE_ROLES, "deliveryOriginal", c9.MAX_INPUT, 65536)
    _records(transition_context, TRANSITION_JOBS, "grantOriginal", transitions.MAX_INPUT, 131072)
    native_inputs, payloads, native, deadline, epoch_limit = {}, {}, {}, checked["deadline"], (1 << 63) - 1
    authority_context = None
    for operation in native_profile.OPERATIONS:
        row = native_context[operation]
        prepared = native_profile.prepare_input(operation, row["inputOriginal"], **clocks)
        native_profile.checked_result(operation, row["inputOriginal"], _result(row["grantOriginal"]), **clocks)
        value = p.document(row["inputOriginal"], native_profile.MAX_INPUT)
        native_inputs[operation], payloads[operation] = value, prepared["payload"]
        deadline, epoch_limit = min(deadline, prepared["deadline"]), min(epoch_limit, prepared["epochLimit"])
        role = native_profile.ENDPOINT_ROLES[operation]
        _native_delivery(role, native_delivery_context[role], value, cohort_observation_raw=cohort_observation_raw)
        config_field = "nativeConfigurationOriginal" if operation == "generationInstall" else "configurationOriginal"
        config = p.document(value[config_field].encode("ascii"), p.MAX_CONFIG)
        admitted, keys = admission.authorization(config, now_unix_ns)
        selected_authority = {name: admitted[name] for name in (
            "assignmentId", "assignmentPayloadSha256", "assignmentRevision", "fullKeySetRootSha256")}
        selected_authority["trustCheckpoint"] = config["trustCheckpoint"]
        if authority_context is None:
            authority_context = selected_authority
        else:
            _same(authority_context, selected_authority)
        if operation != _OPERATION[role]:
            continue
        native[role] = {"guest": admitted["guest"], "key": keys[p.ROLES.index(_KEY_ROLE[role])],
            "expectedPeer": prepared["payload"]["expectedPeer"]}
    expected_persistence = native_profile.authority.persistence.COMPLETED_GRANT_API if fragment["apiVersion"] == policy.TERMINAL_API else native_profile.authority.PROFILES["persistence"][0]
    p.require(payloads["persistence"]["apiVersion"] == expected_persistence)
    sources = checked["sources"]
    ordinary_context = {"launchOriginal": sources["launch_raw"].decode("ascii"), "services": sources["ordinary_context"]}
    ordinary = transitions._services(ordinary_context, native_inputs, payloads, clocks)
    generation_scope = ordinary[g.ROLES[0]]["generation"]["scope"]
    for name in ("assignmentId", "assignmentPayloadSha256", "assignmentRevision"):
        p.require(authority_context[name] == generation_scope[name])
    for target, source in (("trustedTimeCheckpointSha256", "checkpointId"),
            ("trustedTimeRevocationGeneration", "revocationGeneration"),
            ("trustedTimeRevocationRootSha256", "revocationRootSha256")):
        p.require(generation_scope[target] == authority_context["trustCheckpoint"][source])
    transition_originals = {}
    for job, (operation, role) in zip(TRANSITION_JOBS, transitions.JOBS, strict=True):
        row = transition_context[job]
        value = p.document(row["inputOriginal"], transitions.MAX_INPUT)
        p.require(value["launchOriginal"] == ordinary_context["launchOriginal"])
        for name, entry in value["services"].items():
            p.require(entry == ordinary_context["services"][name])
        if operation == "dispatch":
            p.require(value["nativeGrantOriginal"] == native_context["commitRequest"]["grantOriginal"].decode("ascii")
                and value["nativeConfigurationOriginal"] == native_inputs["commitRequest"]["configurationOriginal"])
        else:
            for name in spool.EFFECT_NATIVE:
                p.require(value["nativeOriginals"][name] == native_context[name]["grantOriginal"].decode("ascii"))
            if operation != "head":
                p.require(value["headGrantOriginal"] == transition_originals["ordinary-head"].decode("ascii"))
            if operation == "current":
                p.require(value["cleanupGrantOriginal"] == transition_originals["ordinary-cleanup"].decode("ascii"))
        transition_originals[job] = transitions.checked_result(operation, role, row["inputOriginal"],
            _result(row["grantOriginal"]), **clocks)
        prepared = service.prepare_input(operation, role, row["inputOriginal"], **clocks)
        deadline = min(deadline, prepared["deadline"])
    p.require(now_boottime_ns < deadline and now_unix_ns < epoch_limit)
    bundle = _project(fragment, current_context=checked, heads=heads, ordinary=ordinary, native=native,
        transition_originals=transition_originals, bootstrap_originals=bootstrap_originals,
        driver_observation_raw=driver_observation_raw, cohort_observation_raw=cohort_observation_raw,
        gate_binding_raw=gate_binding_raw, bridge_journal=bridge_journal, boot=boot, now_boottime_ns=now_boottime_ns)
    return {"bundleOriginal": bundle, "window": copy.deepcopy(checked["window"]), "deadline": deadline, "epochLimit": epoch_limit}


def build(**kwargs):
    return prepare(**kwargs)["bundleOriginal"]


def checked_result(bundle_raw, result, **kwargs):
    """Check an actual install result; provenance still belongs to its caller."""
    prepared = prepare(**kwargs)
    p.require(type(bundle_raw) is bytes and bundle_raw == prepared["bundleOriginal"])
    bundle = p.fields(p.document(bundle_raw, MAX_INPUT), install.FIELDS)
    bootstrap, window = kwargs["bootstrap_originals"], prepared["window"]
    expected = {"apiVersion": "serverware.nativePilotBridgeRuntimeInstallation/v1", "bundleSha256": p.sha(bundle_raw),
        "configurationSha256": p.sha(bootstrap["configuration"]), "windowSha256": p.sha(bootstrap["window"]),
        "observationSha256": p.sha(kwargs["driver_observation_raw"]), "invocationId": window["invocationId"],
        "startupDeadlineBoottimeNs": window["startupDeadlineBoottimeNs"],
        "lifetimeDeadlineBoottimeNs": window["lifetimeDeadlineBoottimeNs"],
        "pins": {purpose: {"path": publication.DESTINATIONS[purpose], "sha256": p.sha(bundle[field].encode("ascii"))}
            for purpose, field in (("bridge-runtime", "runtimeOriginal"), ("bridge-outgoing", "outgoingOriginal"))}}
    p.fields(result, tuple(expected))
    p.require(p.canonical(result) == p.canonical(expected))
    return copy.deepcopy(result)
