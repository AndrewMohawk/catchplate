"""Explicit cold two-service runtime composition from authenticated originals.

No hot generation admission, driver receipt, process owner or prior publication
receipt is constructed. Public observations require independent complete-input
approval; the actual native owners still measure descriptors and executed peers.
"""
from __future__ import annotations

import copy

from catchplate import custody_generation_grants as g
from catchplate import native_pilot_bridge_preparation as peers
from catchplate import native_pilot_genesis_coordinator_peer as coordinator
from catchplate import native_pilot_genesis_ordinary_initial_authority as initial_authority
from catchplate import native_pilot_genesis_ordinary_initial_profile as initial
from catchplate import native_pilot_ordinary_key_profile as key
from catchplate import native_pilot_ordinary_runtime_profile as ordinary
from catchplate import native_pilot_ordinary_runtime_recipe as recipe

p = g.p
API = "catchplate.nativePilotGenesisOrdinaryRuntimePolicy/v1"
MAX_POLICY = MAX_RUNTIME = g.MAX_BYTES
ROLES = initial.ROLES
DRS, CURRENT = ROLES
HEADER = tuple(name for name in ordinary.HEADER if name != "generationAdmission") + ("publicationGenesisAdmission",)
FIELDS = {role: ordinary.FIELDS[role] for role in ROLES}
SOURCE_FIELDS = tuple(name for name in initial_authority.SOURCE_FIELDS if name != "configurationOriginal") + ("configurationOriginals",)
ACTIVATION_NAMES = {DRS: ("listener", "journal", "publication-genesis-journal", "publication-genesis-grant"),
    CURRENT: ("listener", "publication-genesis-journal", "publication-genesis-grant")}


def listener(role):
    p.require(role in ROLES)
    return "/run/catchplate-custody-genesis/" + role + "/listener.sock"


def _pin_shape(value):
    p.fields(value, ordinary.PIN_FIELDS)
    recipe.pin({name: value[name] for name in recipe.PIN})
    p.require(value["declaredSocketPath"] in {listener(role) for role in ROLES})
    identity = key.validate_identity(value["endpointProcessIdentity"])
    checkpoint = key.validate_checkpoint(value["signedCurrentKeyAuthorization"])
    p.require(checkpoint["payload"]["endpointRole"] == identity["endpointRole"]
        and checkpoint["payload"]["endpointProcessIdentitySha256"] == identity["identitySha256"])
    key._uint(value["consumeHeadObservedAtBoottimeNanos"])
    return identity


def _pin(selection, target, contexts, forbidden):
    value = ordinary._pin(selection, target, contexts, forbidden)
    value["declaredSocketPath"] = listener(target)
    return value


def validate_peer(value):
    p.fields(value, ("processIdentitySha256", "uid", "gid", "pid", "startTimeTicks", "executableDevice",
        "executableInode", "executableLength", "executableSha256", "cgroupPathSha256", "cgroupMountId",
        "cgroupInode", "securityLabelSha256", "configurationGenerationSha256"))
    p.require(value["processIdentitySha256"] == peers.peer_identity(
        {name: item for name, item in value.items() if name != "processIdentitySha256"}))
    p.integer(value["pid"], minimum=2, maximum=(1 << 31) - 1)
    for name in ("uid", "gid"):
        p.integer(value[name], maximum=(1 << 32) - 2)
    for name in value:
        if name.endswith("Sha256"):
            recipe.digest(value[name])
    return value


def validate_policy(fragment):
    p.fields(fragment, ("apiVersion", "services"))
    p.require(fragment["apiVersion"] == API)
    rows = p.fields(fragment["services"], ROLES)
    for role, row in rows.items():
        p.fields(row, ("runtimeHeader", "service", "credentials"))
        header = p.fields(row["runtimeHeader"], recipe.HEADER)
        p.integer(header["startupTimeoutMillis"], maximum=30000)
        key._uint(header["readinessEpoch"])
        p.integer(header["maximumDurabilityWorkerNanos"], maximum=1_000_000_000)
        for field in recipe.HEADER[3:]:
            recipe.digest(header[field])
        recipe.credentials(row["credentials"])
        service = p.fields(row["service"], recipe.SERVICE[role])
        for field in recipe.SERVICE[role]:
            if field.endswith("Credential"):
                recipe.name(service[field])
        if role == DRS:
            p.require(service["ownershipSeed"] == [] and service["recoveryMaterialSeed"] == [])
        else:
            recipe.pin(service["serviceSigningPin"])
            subjects, seen = service["currentSubjects"], set()
            p.require(type(subjects) is list and 1 <= len(subjects) <= 64)
            for item in subjects:
                p.fields(item, ("subject", "serviceRole", "pin"))
                p.require(item["serviceRole"] in ROLES)
                tag = item["subject"]["authority"], recipe.subject(item["subject"])
                p.require(tag not in seen); seen.add(tag)
                recipe.pin(item["pin"])
    p.require(len(g.canonical(fragment)) <= MAX_POLICY)
    return copy.deepcopy(fragment)


def validate_runtime(role, raw):
    p.require(role in ROLES)
    value = p.fields(g.document(raw, MAX_RUNTIME), ("runtime",) + FIELDS[role])
    header = p.fields(value["runtime"], HEADER)
    p.require(header["apiVersion"] == initial.RUNTIME_API
        and header["publicationGenesisAdmission"] == {"grantFdName": "publication-genesis-grant"}
        and header["authorityHistoryManifestCredential"] == recipe.HISTORY_NAME
        and header["listenerSocketPath"] == listener(role))
    p.integer(header["startupTimeoutMillis"], maximum=30000)
    p.integer(header["maximumDurabilityWorkerNanos"], maximum=1_000_000_000)
    p.integer(header["durabilityWorkerQueueDepth"], minimum=8, maximum=8)
    for name in ("operationGeneration", "serviceRestartEpoch", "readinessEpoch"):
        key._uint(header[name])
    p.require(header["readinessEpoch"] >= header["serviceRestartEpoch"])
    for name in HEADER:
        if name.endswith("Sha256") or name == "authorityHistoryRootKeyId":
            recipe.digest(header[name])
    validate_peer(header["expectedPeer"])
    initial.directories({name: {"identity": identity, "entryCount": 0}
        for name, identity in header["activationDirectoryIdentities"].items()}, role)
    for name in FIELDS[role]:
        if name.endswith("Credential"):
            recipe.name(value[name])
        elif name.endswith("Sha256") or name.endswith("KeyId"):
            recipe.digest(value[name])
    if role == DRS:
        for name in ("endpointGeneration", "checkpointSequence", "revocationGeneration"):
            key._uint(value[name])
        p.require(value["checkpointSequence"] == 1 and value["ownershipSeed"] == [] and value["recoveryMaterialSeed"] == [])
        p.require(key.validate_identity(value["endpointProcessIdentity"])["endpointRole"] == "settlement-store")
    else:
        _pin_shape(value["serviceSigningPin"])
        subjects, seen = value["currentSubjects"], set()
        p.require(type(subjects) is list and 1 <= len(subjects) <= 64)
        for item in subjects:
            p.fields(item, ("subject", "pin"))
            endpoint = recipe.subject(item["subject"])
            tag = item["subject"]["authority"], endpoint
            p.require(tag not in seen and _pin_shape(item["pin"])["endpointRole"] == endpoint)
            seen.add(tag)
    return value


def source_arguments(source, role):
    p.fields(source, SOURCE_FIELDS)
    configurations = p.fields(source["configurationOriginals"], ROLES)
    result = {argument: initial_authority._original(source[name], maximum)[0]
        for name, (argument, maximum) in initial_authority.SOURCE_FIELDS.items() if name != "configurationOriginal"}
    result["configuration_raw"] = initial_authority._original(configurations[role], 65536)[0]
    return result


def contexts(*, fragment, history_originals, source, peer_preparation_raw, approved_peer, boot, now_boottime_ns):
    rows = validate_policy(fragment)["services"]
    p.fields(history_originals, ROLES)
    result = {}
    for role in ROLES:
        header = rows[role]["runtimeHeader"]
        item = initial.require_window(history_originals[role], role=role, root_pin={
            "keyId": header["authorityHistoryRootKeyId"], "keySpkiSha256": header["authorityHistoryRootKeySpkiSha256"]},
            boot=boot, now_boottime_ns=now_boottime_ns)
        args = source_arguments(source, role)
        observed = initial_authority.source_context(**args, role=role, endpoint_role=item["identity"]["endpointRole"],
            boot=boot, now_boottime_ns=now_boottime_ns)
        state = item["state"]
        for field, argument in (("preparationSha256", "preparation_raw"), ("resourcesSha256", "resources_raw"), ("launchSha256", "launch_raw")):
            p.require(state[field] == p.sha(args[argument]))
        initial.same(item["identity"], observed["identity"])
        initial.same(state["directories"], observed["resources"]["services"][role]["directories"])
        for field in initial_authority.parent.WINDOW_FIELDS[2:]:
            initial.same(state[field], observed["window"][field])
        p.require(header["readinessEpoch"] >= state["serviceGeneration"])
        result[role] = {**item, "epoch": item["history"]["firstRetainedEpoch"]["retainedEpoch"], "observed": observed}
    args = source_arguments(source, DRS)
    peer = coordinator.expected_peer(peer_preparation_raw, approved=approved_peer,
        observation_raw=args["parent_observation_raw"], configuration_raw=args["parent_configuration_raw"],
        precreation_raw=args["parent_precreation_raw"], delivery_configuration_raw=args["parent_delivery_configuration_raw"],
        boot=boot, now_boottime_ns=now_boottime_ns)
    authorities = {role: {"root": item["history"]["rootAuthority"], "checkpoint": item["epoch"]["checkpointAuthority"],
        "service": item["epoch"]["serviceSigningKey"]} for role, item in result.items()}
    endpoints = {role: item["identity"]["endpointRole"] for role, item in result.items()}
    materials = [record["keySpkiSha256"] for selected in authorities.values() for record in selected.values()]
    p.require(len(set(materials)) == 6)
    for role in ROLES:
        recipe.bind_keys(role, rows[role], authorities, endpoints)
        cold = result[role]["observed"]["cold"]
        p.require(peer["uid"] != cold["uid"] and peer["gid"] != cold["gid"])
        for row in rows[role]["credentials"]:
            if row["signing"] is not None:
                p.require(row["signing"]["keyId"] != cold["authority"]["keyId"]
                    and row["signing"]["publicKeyBase64url"] != cold["authority"]["publicKeyBase64url"])
    return result, peer


def build(role, *, fragment, history_originals, source, peer_preparation_raw, approved_peer, boot, now_boottime_ns):
    p.require(role in ROLES)
    held, peer = contexts(fragment=fragment, history_originals=history_originals, source=source,
        peer_preparation_raw=peer_preparation_raw, approved_peer=approved_peer, boot=boot, now_boottime_ns=now_boottime_ns)
    return _compose(role, fragment, held, peer)


def _compose(role, fragment, held, peer):
    """Same-call projection; callers must authenticate contexts at their clock."""
    row, item = fragment["services"][role], held[role]
    state, checkpoint = item["state"], item["checkpoint"]
    header = {**row["runtimeHeader"], "apiVersion": initial.RUNTIME_API,
        "operationGeneration": state["operationGeneration"], "serviceRestartEpoch": state["serviceGeneration"],
        "durabilityWorkerQueueDepth": 8, "authorityHistoryManifestSha256": item["history"]["manifestSha256"],
        "authorityHistoryManifestCredential": recipe.HISTORY_NAME, "deploymentGenerationSha256": state["deploymentGenerationSha256"],
        "listenerSocketPath": listener(role), "expectedPeer": peer,
        "activationDirectoryIdentities": {name: value["identity"] for name, value in state["directories"].items()},
        "publicationGenesisAdmission": {"grantFdName": "publication-genesis-grant"}}
    service = copy.deepcopy(row["service"])
    if role == DRS:
        payload = checkpoint["payload"]
        service.update(endpointProcessIdentity=item["identity"], signingKeyId=payload["authorizedSigningKeyId"],
            endpointGeneration=payload["exactEndpointGeneration"], checkpointSequence=payload["checkpointSequence"],
            currentKeyAuthorizationCheckpointSha256=checkpoint["checkpointSha256"],
            revocationGeneration=payload["revocationGenerationHighWater"], revocationRootSha256=payload["revocationRootSha256"],
            currentHeadAuthorityKeyId=checkpoint["authorityKeyId"])
    else:
        forbidden = {digest for member in held.values() for digest in initial.commitments(member["state"]).values()}
        service["serviceSigningPin"] = _pin(service["serviceSigningPin"], role, held, forbidden)
        service["currentSubjects"] = [{"subject": entry["subject"],
            "pin": _pin(entry["pin"], entry["serviceRole"], held, forbidden)} for entry in service["currentSubjects"]]
    raw = g.canonical({"runtime": header, **service})
    validate_runtime(role, raw)
    return raw


def inspection_original(role, runtime_raw, cold, window):
    validate_runtime(role, runtime_raw)
    return g.canonical({"apiVersion": "catchplate.custodyOrdinaryPeerInspection/v1",
        "purpose": "ordinary-service-peer-inspection", "runtimeConfigurationSha256": p.sha(runtime_raw),
        "serviceRole": role, "uid": cold["uid"], "gid": cold["gid"],
        "startupDeadlineBoottimeNs": window["startupDeadlineBoottimeNs"],
        "lifetimeDeadlineBoottimeNs": window["lifetimeDeadlineBoottimeNs"]})
