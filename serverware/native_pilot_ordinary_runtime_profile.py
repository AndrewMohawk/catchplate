"""Pure fresh-five runtime assembly from approved recipes and genuine originals.

The caller retains and authenticates the observation/approval process and its
original deadline. This module verifies their byte/signature joins; it cannot
observe a live process, claim a listener exists or renew a window. The initial
empty-resource observation supplies a fresh 0/1 consume cursor's observation
time, never evidence of an earlier receipt. Historical seeds are unsupported.
"""
from __future__ import annotations

import copy

from serverware import custody_generation_grants as g
from serverware import native_pilot_ordinary_initial_profile as initial
from serverware import native_pilot_ordinary_key_profile as key
from serverware import native_pilot_ordinary_runtime_recipe as recipe
from serverware import native_shadow_retrieval_artifacts as retrieval

p = g.p
MAX_POLICY = recipe.MAX_POLICY
API = recipe.API
DRS, CLEANUP, RECOVERY, CURRENT, HELPER = g.ROLES
HISTORY_NAME, INSPECTION_NAME = recipe.HISTORY_NAME, recipe.INSPECTION_NAME
HEADER = recipe.HEADER + ("apiVersion", "operationGeneration", "serviceRestartEpoch", "durabilityWorkerQueueDepth",
    "authorityHistoryManifestSha256", "authorityHistoryManifestCredential", "deploymentGenerationSha256",
    "listenerSocketPath", "expectedPeer", "activationDirectoryIdentities", "generationAdmission")
IDENTITY = ("signingKeyId", "endpointGeneration", "checkpointSequence",
    "currentKeyAuthorizationCheckpointSha256", "revocationGeneration", "revocationRootSha256")
HEAD = ("currentHeadAuthorityVerifyingKeyCredential", "currentHeadAuthorityKeyId")
FIELDS = {
    DRS: ("signingKeyCredential", "endpointProcessIdentity", "ownershipSeed", "recoveryMaterialSeed") + IDENTITY + HEAD,
    CLEANUP: ("signingKeyCredential", "endpointProcessIdentity", "minimumCheckpointSequence", "minimumRevocationGeneration",
        "cleanupAuthorityVerifyingKeyCredential", "cleanupAuthorityKeyId", "cleanupAuthorityCurrentKeyAuthorizationCheckpointSha256",
        "cleanupAuthorityRevocationGeneration", "cleanupAuthorityRevocationRootSha256", "genesisPredecessorReceiptSha256") + IDENTITY + HEAD,
    RECOVERY: ("signingKeyCredential", "serviceSigningPin", "maximumRegistrations", "lineageAuthorityKeyId",
        "lineageAuthorityKeySpkiSha256", "lineageAuthorityVerifyingKeyCredential", "durableReapLineageProofs"),
    CURRENT: ("serviceSigningKeyCredential", "serviceSigningPin", "currentSubjects"),
    HELPER: ("signingKeyCredential", "endpointProcessIdentitySha256", "helperGeneration") + IDENTITY + HEAD,
}
PIN_FIELDS = recipe.PIN + ("declaredSocketPath", "endpointProcessIdentity",
    "signedCurrentKeyAuthorization", "consumeHeadObservedAtBoottimeNanos")
WINDOW = ("bootIdBase64url", "timeNamespaceDevice", "timeNamespaceInode", "invocationId",
    "startupDeadlineBoottimeNs", "lifetimeDeadlineBoottimeNs")


def listener(role):
    p.require(role in g.ROLES)
    return "/run/serverware-custody-business/" + role + "/listener.sock"


def validate_policy(fragment, *, ordinary_cold_originals, initial_policy):
    recipe.validate_policy(fragment, ordinary_cold_originals=ordinary_cold_originals, initial_policy=initial_policy)
    return copy.deepcopy(fragment)


def _selections(role):
    result = {"generationAdmission": {"grantFdName": "generation-grant"}}
    if role in (DRS, CURRENT):
        result["dispatchAdmission"] = {"grantFdName": "dispatch-grant"}
    field, grant = {DRS: ("spoolHead", "spool-head"), CLEANUP: ("spoolCleanup", "active-effect-cleanup"),
        CURRENT: ("spoolCurrent", "spool-current")}.get(role, (None, None))
    if field is not None:
        result[field] = {"grantFdName": grant + "-grant"}
    return result


def _pin_shape(value):
    p.fields(value, PIN_FIELDS)
    recipe.pin({name: value[name] for name in recipe.PIN})
    p.require(value["declaredSocketPath"] in {listener(role) for role in g.ROLES})
    identity = key.validate_identity(value["endpointProcessIdentity"])
    checkpoint = key.validate_checkpoint(value["signedCurrentKeyAuthorization"])
    p.require(checkpoint["payload"]["endpointRole"] == identity["endpointRole"]
        and checkpoint["payload"]["endpointProcessIdentitySha256"] == identity["identitySha256"])
    key._uint(value["consumeHeadObservedAtBoottimeNanos"])
    return identity


def validate_runtime(role, raw):
    """Closed native runtime shape only; not source or signature authority."""
    p.require(role in g.ROLES)
    value = p.fields(g.document(raw, g.MAX_BYTES), ("runtime",) + FIELDS[role])
    selections = _selections(role)
    header = p.fields(value["runtime"], HEADER + tuple(name for name in selections if name != "generationAdmission"))
    expected_version = "8" if role in (DRS, CLEANUP, CURRENT) else "5"
    p.require(header["apiVersion"] == "serverware.policyCustodyServiceRuntimeConfig/v" + expected_version
        and header["authorityHistoryManifestCredential"] == HISTORY_NAME and header["listenerSocketPath"] == listener(role))
    for name, selected in selections.items():
        p.require(header[name] == selected)
    p.integer(header["startupTimeoutMillis"], maximum=30_000)
    p.integer(header["maximumDurabilityWorkerNanos"], maximum=1_000_000_000)
    p.integer(header["durabilityWorkerQueueDepth"], minimum=8, maximum=8)
    for name in ("operationGeneration", "serviceRestartEpoch", "readinessEpoch"):
        key._uint(header[name])
    p.require(header["readinessEpoch"] >= header["serviceRestartEpoch"])
    for name in HEADER:
        if name.endswith("Sha256") or name == "authorityHistoryRootKeyId":
            recipe.digest(header[name])
    retrieval._peer(g.canonical(header["expectedPeer"]))
    initial._directories({name: {"identity": identity, "entryCount": 0}
        for name, identity in header["activationDirectoryIdentities"].items()}, role)
    for name in FIELDS[role]:
        if name.endswith("Credential"):
            recipe.name(value[name])
        elif name.endswith("Sha256") or name.endswith("KeyId"):
            recipe.digest(value[name])
    if role in (DRS, CLEANUP, HELPER):
        for name in ("endpointGeneration", "checkpointSequence", "revocationGeneration"):
            key._uint(value[name])
        p.require(value["checkpointSequence"] == 1)
        if role != HELPER:
            identity = key.validate_identity(value["endpointProcessIdentity"])
            p.require(role != DRS or identity["endpointRole"] == "settlement-store")
    if role == DRS:
        p.require(value["ownershipSeed"] == [] and value["recoveryMaterialSeed"] == [])
    elif role == CLEANUP:
        p.integer(value["minimumCheckpointSequence"], maximum=1)
        key._uint(value["minimumRevocationGeneration"]); key._uint(value["cleanupAuthorityRevocationGeneration"])
        p.require(value["minimumRevocationGeneration"] <= value["revocationGeneration"])
    elif role == HELPER:
        key._uint(value["helperGeneration"])
    else:
        _pin_shape(value["serviceSigningPin"])
        if role == RECOVERY:
            p.integer(value["maximumRegistrations"], maximum=1024)
            p.require(value["durableReapLineageProofs"] == [])
        else:
            subjects, seen = value["currentSubjects"], set()
            p.require(type(subjects) is list and 1 <= len(subjects) <= 64)
            for item in subjects:
                p.fields(item, ("subject", "pin"))
                endpoint_role = recipe.subject(item["subject"])
                tag = (item["subject"]["authority"], endpoint_role)
                p.require(tag not in seen and _pin_shape(item["pin"])["endpointRole"] == endpoint_role)
                seen.add(tag)
    return value


def _histories(rows, originals, preparation_raw, resources_raw, launch_raw):
    p.fields(originals, g.ROLES)
    prepared, resources = key.preparation(preparation_raw), initial.resources(resources_raw)
    launch = p.fields(g.document(launch_raw, 65536), key._LAUNCH_FIELDS)
    p.require(launch["apiVersion"] == "serverware.custodyFiveServiceLaunch/v6"
        and prepared["configurationSha256"] == p.sha(launch_raw)
        and resources["preparationSha256"] == p.sha(preparation_raw))
    p.fields(launch["services"], g.ROLES)
    contexts = {}
    for role in g.ROLES:
        header = rows[role]["runtimeHeader"]
        wrapper = p.fields(g.document(originals[role], g.MAX_BYTES), initial.WRAPPER_FIELDS)
        p.require(wrapper["apiVersion"] == initial.WRAPPER_API)
        history = initial.manifest(originals[role], role=role, root_pin={
            "keyId": header["authorityHistoryRootKeyId"], "keySpkiSha256": header["authorityHistoryRootKeySpkiSha256"]})
        state, checkpoint = wrapper["initialState"], wrapper["initialCheckpoint"]
        epoch = history["firstRetainedEpoch"]["retainedEpoch"]
        item, identity = prepared["services"][role], epoch["endpointProcessIdentity"]
        spec = p.fields(launch["services"][role], ("executableSha256", "deliveryConfiguration"))
        g.c9._pin(spec["deliveryConfiguration"])
        p.require(state["preparationSha256"] == p.sha(preparation_raw) and state["resourcesSha256"] == p.sha(resources_raw)
            and state["launchSha256"] == p.sha(launch_raw) and state["issuedAtBoottimeNs"] == resources["issuedAtBoottimeNs"]
            and state["directories"] == resources["services"][role]["directories"]
            and spec["executableSha256"] == item["targetExecutable"]["sha256"]
            and spec["deliveryConfiguration"]["sha256"] == item["configurationSha256"]
            and header["readinessEpoch"] >= state["serviceGeneration"]
            and p.ns(prepared["issuedAtBoottimeNs"]) <= p.ns(state["issuedAtBoottimeNs"]))
        for name in WINDOW:
            p.require(state[name] == prepared[name] == launch[name])
        target, pidfd = item["targetExecutable"], item["pidfdStat"]
        expected = (identity["endpointRole"], item["plannedUid"], item["plannedGid"], item["processId"],
            item["startTimeTicks"], pidfd["inode"], pidfd["sha256"], target["device"], target["inode"],
            target["length"], target["sha256"], target["imaSha256"], target["fsVeritySha256"])
        p.require(tuple(identity[name] for name in key.IDENTITY_FIELDS[:-1]) == expected)
        for record in state["directories"].values():
            p.require((record["identity"]["uid"], record["identity"]["gid"]) == (item["plannedUid"], item["plannedGid"]))
        contexts[role] = dict(state=state, checkpoint=checkpoint, history=history, identity=identity, epoch=epoch)
    return contexts, prepared, launch


def _pin(selection, target, contexts, forbidden):
    context = contexts[target]
    cursor = selection["consumeCursor"]
    p.require(cursor["expectedPredecessorReceiptSha256"] not in forbidden)
    return {**copy.deepcopy(selection), "declaredSocketPath": listener(target),
        "endpointProcessIdentity": copy.deepcopy(context["identity"]),
        "signedCurrentKeyAuthorization": copy.deepcopy(context["checkpoint"]),
        "consumeHeadObservedAtBoottimeNanos": p.ns(context["state"]["issuedAtBoottimeNs"])}


def build(role, *, fragment, history_originals, preparation_raw, resources_raw, launch_raw, configuration_raw, peer):
    """Build one deterministic flat native config; never sample a new clock."""
    p.require(role in g.ROLES)
    rows = recipe.shape(fragment)
    contexts, prepared, launch = _histories(rows, history_originals, preparation_raw, resources_raw, launch_raw)
    cold = g.configuration(configuration_raw, launch["services"][role]["deliveryConfiguration"]["sha256"], role)
    observed = prepared["services"][role]
    p.require((cold["uid"], cold["gid"]) == (observed["plannedUid"], observed["plannedGid"]))
    peer = retrieval._peer(g.canonical(peer))
    p.require(peer["uid"] != cold["uid"] and peer["gid"] != cold["gid"])
    authorities = {name: {"root": item["history"]["rootAuthority"], "checkpoint": item["epoch"]["checkpointAuthority"],
        "service": item["epoch"]["serviceSigningKey"]} for name, item in contexts.items()}
    roles = {name: item["identity"]["endpointRole"] for name, item in contexts.items()}
    for name in g.ROLES:
        recipe.bind_keys(name, rows[name], authorities, roles)
    forbidden = {digest for item in contexts.values() for digest in initial.commitments(item["state"]).values()}
    row, context = rows[role], contexts[role]
    state, checkpoint, service = context["state"], context["checkpoint"], copy.deepcopy(row["service"])
    payload = checkpoint["payload"]
    header = {**copy.deepcopy(row["runtimeHeader"]), "apiVersion": "serverware.policyCustodyServiceRuntimeConfig/v" +
        ("8" if role in (DRS, CLEANUP, CURRENT) else "5"), "operationGeneration": state["operationGeneration"],
        "serviceRestartEpoch": state["serviceGeneration"], "durabilityWorkerQueueDepth": 8,
        "authorityHistoryManifestSha256": context["history"]["manifestSha256"],
        "authorityHistoryManifestCredential": HISTORY_NAME, "deploymentGenerationSha256": state["deploymentGenerationSha256"],
        "listenerSocketPath": listener(role), "expectedPeer": copy.deepcopy(peer),
        "activationDirectoryIdentities": {name: record["identity"] for name, record in state["directories"].items()},
        **_selections(role)}
    if role in (DRS, CLEANUP, HELPER):
        service.update(signingKeyId=payload["authorizedSigningKeyId"], endpointGeneration=payload["exactEndpointGeneration"],
            checkpointSequence=payload["checkpointSequence"], currentKeyAuthorizationCheckpointSha256=checkpoint["checkpointSha256"],
            revocationGeneration=payload["revocationGenerationHighWater"], revocationRootSha256=payload["revocationRootSha256"],
            currentHeadAuthorityKeyId=checkpoint["authorityKeyId"])
        service["endpointProcessIdentitySha256" if role == HELPER else "endpointProcessIdentity"] = (
            context["identity"]["identitySha256"] if role == HELPER else context["identity"])
    if role == CLEANUP:
        selected = service.pop("cleanupAuthority")
        target = contexts[selected["serviceRole"]]["checkpoint"]
        p.require(service["genesisPredecessorReceiptSha256"] not in forbidden)
        service.update(cleanupAuthorityVerifyingKeyCredential=selected["verifyingKeyCredential"],
            cleanupAuthorityKeyId=target["payload"]["authorizedSigningKeyId"],
            cleanupAuthorityCurrentKeyAuthorizationCheckpointSha256=target["checkpointSha256"],
            cleanupAuthorityRevocationGeneration=target["payload"]["revocationGenerationHighWater"],
            cleanupAuthorityRevocationRootSha256=target["payload"]["revocationRootSha256"])
    elif role in (RECOVERY, CURRENT):
        service["serviceSigningPin"] = _pin(service["serviceSigningPin"], role, contexts, forbidden)
        if role == RECOVERY:
            lineage = service.pop("lineageAuthority")
            service.update(lineageAuthorityKeyId=lineage["keyId"], lineageAuthorityKeySpkiSha256=lineage["keySpkiSha256"])
        else:
            service["currentSubjects"] = [{"subject": item["subject"],
                "pin": _pin(item["pin"], item["serviceRole"], contexts, forbidden)} for item in service["currentSubjects"]]
    p.require(sum(item["length"] for item in row["credentials"]) + len(history_originals[role]) + 4096 <= 16 * 1024 * 1024)
    raw = g.canonical({"runtime": header, **service})
    validate_runtime(role, raw)
    return raw
