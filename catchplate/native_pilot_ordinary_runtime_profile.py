"""Pure fresh-five runtime assembly from approved recipes and genuine originals.

The caller retains and authenticates the observation/approval process and its
original deadline. This module verifies their byte/signature joins; it cannot
observe a live process, claim a listener exists or renew a window. The initial
empty-resource observation supplies a fresh 0/1 consume cursor's observation
time, never evidence of an earlier receipt. Historical seeds are unsupported.
"""
from __future__ import annotations

import copy

from catchplate import custody_generation_grants as g
from catchplate import native_pilot_ordinary_initial_profile as initial
from catchplate import native_pilot_ordinary_key_profile as key
from catchplate import native_pilot_ordinary_runtime_recipe as recipe
from catchplate import native_shadow_retrieval_artifacts as retrieval

p = g.p
MAX_POLICY = recipe.MAX_POLICY
API = recipe.API
HELPER_API = recipe.HELPER_API
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
    return "/run/catchplate-custody-business/" + role + "/listener.sock"


def validate_policy(fragment, *, ordinary_cold_originals, initial_policy):
    recipe.validate_policy(fragment, ordinary_cold_originals=ordinary_cold_originals, initial_policy=initial_policy)
    return copy.deepcopy(fragment)


def _selections(role, *, adopted=False):
    result = {"generationAdmission": {"grantFdName": "generation-grant"}}
    if role in (DRS, CURRENT):
        result["dispatchAdmission"] = {"grantFdName": "dispatch-grant"}
        if adopted:
            result["publicationAdmission"] = {"grantFdName": "publication-grant"}
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


def validate_runtime(role, raw, *, adopted=False):
    """Closed runtime and authenticated helper-member joins, not owner/approval."""
    p.require(role in g.ROLES and type(adopted) is bool)
    value = g.document(raw, g.MAX_BYTES)
    helper = role == HELPER and value.get("runtime", {}).get("apiVersion") == initial.HELPER_RUNTIME_API
    p.fields(value, ("runtime",) + FIELDS[role] + (("initialEndpointHistories", "initialEndpointPins") if helper else ()))
    selections = _selections(role, adopted=adopted)
    header = p.fields(value["runtime"], HEADER + tuple(name for name in selections if name != "generationAdmission"))
    expected_version = "12" if adopted and role in (DRS, CURRENT) else "9" if helper else "8" if role in (DRS, CLEANUP, CURRENT) else "5"
    p.require(header["apiVersion"] == "catchplate.policyCustodyServiceRuntimeConfig/v" + expected_version
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
        for name, identity in header["activationDirectoryIdentities"].items()}, role, adopted=adopted)
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
        if helper:
            members = p.fields(value["initialEndpointHistories"], initial.HELPER_ENDPOINT_ROLES)
            matches = []
            for text in members.values():
                p.require(type(text) is str and text.isascii() and 0 < len(text) <= initial.MAX_HELPER_HISTORY)
                wrapper = p.fields(g.document(text.encode("ascii"), initial.MAX_HELPER_HISTORY), initial.WRAPPER_FIELDS)
                if wrapper["history"]["manifestSha256"] == header["authorityHistoryManifestSha256"]:
                    matches.append(text.encode("ascii"))
            p.require(len(matches) == 1)
            contexts = initial.helper_endpoint_histories(matches[0], runtime=value)
            forbidden = {digest for item in contexts.values() for digest in initial.commitments(item["state"]).values()}
            for endpoint_role, pin in p.fields(value["initialEndpointPins"], initial.HELPER_ENDPOINT_ROLES).items():
                item = contexts[endpoint_role]
                p.require(_pin_shape(pin) == item["identity"]
                    and pin["signedCurrentKeyAuthorization"] == item["checkpoint"]
                    and pin["declaredSocketPath"] == listener(HELPER)
                    and pin["consumeHeadObservedAtBoottimeNanos"] == p.ns(item["state"]["issuedAtBoottimeNs"])
                    and pin["consumeCursor"]["expectedPredecessorReceiptSha256"] not in forbidden)
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


def _histories(rows, originals, preparation_raw, resources_raw, launch_raw, *, adopted=False):
    p.fields(originals, g.ROLES)
    prepared, resources = key.preparation(preparation_raw), initial.resources(resources_raw, adopted=adopted)
    launch = p.fields(g.document(launch_raw, 65536), key._LAUNCH_FIELDS)
    p.require(launch["apiVersion"] == "catchplate.custodyFiveServiceLaunch/v" + ("7" if adopted else "6")
        and prepared["configurationSha256"] == p.sha(launch_raw)
        and resources["preparationSha256"] == p.sha(preparation_raw))
    p.fields(launch["services"], g.ROLES)
    contexts = {}
    for role in g.ROLES:
        header = rows[role]["runtimeHeader"]
        wrapper = p.fields(g.document(originals[role], g.MAX_BYTES), initial.WRAPPER_FIELDS)
        p.require(wrapper["apiVersion"] == (initial.ADOPTED_WRAPPER_API if adopted and role in initial.ADOPTED_ROLES else initial.WRAPPER_API))
        history = initial.manifest(originals[role], role=role, root_pin={
            "keyId": header["authorityHistoryRootKeyId"], "keySpkiSha256": header["authorityHistoryRootKeySpkiSha256"]}, adopted=adopted)
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


def _pin(selection, target, contexts, forbidden, endpoint_role=None):
    context = contexts[target]
    if target == HELPER and "endpointHistories" in context and endpoint_role is not None:
        p.require(endpoint_role in initial.HELPER_ENDPOINT_ROLES)
        context = context["endpointHistories"][endpoint_role]
    cursor = selection["consumeCursor"]
    p.require(cursor["expectedPredecessorReceiptSha256"] not in forbidden)
    return {**copy.deepcopy(selection), "declaredSocketPath": listener(target),
        "endpointProcessIdentity": copy.deepcopy(context["identity"]),
        "signedCurrentKeyAuthorization": copy.deepcopy(context["checkpoint"]),
        "consumeHeadObservedAtBoottimeNanos": p.ns(context["state"]["issuedAtBoottimeNs"])}


def build(role, *, fragment, history_originals, preparation_raw, resources_raw, launch_raw, configuration_raw, peer,
          helper_history_originals=None, adopted=False):
    """Build one deterministic flat native config; never sample a new clock."""
    p.require(role in g.ROLES and type(adopted) is bool)
    rows = recipe.shape(fragment)
    contexts, prepared, launch = _histories(rows, history_originals, preparation_raw, resources_raw, launch_raw, adopted=adopted)
    helper = fragment["apiVersion"] == HELPER_API
    p.require((type(helper_history_originals) is dict) if helper else helper_history_originals is None)
    if helper:
        p.fields(helper_history_originals, initial.HELPER_ENDPOINT_ROLES)
        p.require(all(type(raw) is bytes for raw in helper_history_originals.values()))
        header = rows[HELPER]["runtimeHeader"]
        contexts[HELPER]["endpointHistories"] = initial.helper_histories(history_originals[HELPER],
            {name: raw.decode("ascii") for name, raw in helper_history_originals.items()}, root_pin={
                "keyId": header["authorityHistoryRootKeyId"], "keySpkiSha256": header["authorityHistoryRootKeySpkiSha256"]})
    cold = g.configuration(configuration_raw, launch["services"][role]["deliveryConfiguration"]["sha256"], role)
    observed = prepared["services"][role]
    p.require((cold["uid"], cold["gid"]) == (observed["plannedUid"], observed["plannedGid"]))
    peer = retrieval._peer(g.canonical(peer))
    p.require(peer["uid"] != cold["uid"] and peer["gid"] != cold["gid"])
    authorities = {name: {"root": item["history"]["rootAuthority"], "checkpoint": item["epoch"]["checkpointAuthority"],
        "service": item["epoch"]["serviceSigningKey"]} for name, item in contexts.items()}
    roles = {name: item["identity"]["endpointRole"] for name, item in contexts.items()}
    if helper:
        roles[HELPER] = initial.HELPER_ENDPOINT_ROLES
    for name in g.ROLES:
        recipe.bind_keys(name, rows[name], authorities, roles)
    forbidden = {digest for item in contexts.values() for digest in initial.commitments(item["state"], adopted=adopted).values()}
    if helper:
        forbidden.update(digest for item in contexts[HELPER]["endpointHistories"].values()
            for digest in initial.commitments(item["state"]).values())
    row, context = rows[role], contexts[role]
    state, checkpoint, service = context["state"], context["checkpoint"], copy.deepcopy(row["service"])
    payload = checkpoint["payload"]
    header = {**copy.deepcopy(row["runtimeHeader"]), "apiVersion": "catchplate.policyCustodyServiceRuntimeConfig/v" +
        ("12" if adopted and role in (DRS, CURRENT) else "9" if helper and role == HELPER else "8" if role in (DRS, CLEANUP, CURRENT) else "5"),
        "operationGeneration": state["operationGeneration"],
        "serviceRestartEpoch": state["serviceGeneration"], "durabilityWorkerQueueDepth": 8,
        "authorityHistoryManifestSha256": context["history"]["manifestSha256"],
        "authorityHistoryManifestCredential": HISTORY_NAME, "deploymentGenerationSha256": state["deploymentGenerationSha256"],
        "listenerSocketPath": listener(role), "expectedPeer": copy.deepcopy(peer),
        "activationDirectoryIdentities": {name: record["identity"] for name, record in state["directories"].items()},
        **_selections(role, adopted=adopted)}
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
                "pin": _pin(item["pin"], item["serviceRole"], contexts, forbidden,
                    endpoint_role=recipe.subject(item["subject"]))} for item in service["currentSubjects"]]
    if helper and role == HELPER:
        p.require(service.pop("initialEndpointRoles") == list(initial.HELPER_ENDPOINT_ROLES))
        service["initialEndpointPins"] = {name: _pin(service["initialEndpointPins"][name], HELPER,
            contexts, forbidden, endpoint_role=name) for name in initial.HELPER_ENDPOINT_ROLES}
        service["initialEndpointHistories"] = {name: helper_history_originals[name].decode("ascii")
            for name in initial.HELPER_ENDPOINT_ROLES}
    p.require(sum(item["length"] for item in row["credentials"]) + len(history_originals[role]) + 4096 <= 16 * 1024 * 1024)
    raw = g.canonical({"runtime": header, **service})
    validate_runtime(role, raw, adopted=adopted)
    return raw
