"""Explicit initial-state commitments, not fabricated historic receipts.

Pure wire joins cannot establish that a directory is empty or a process is
running. The actual retained preparation supplies these observations; the
native receiver independently checks the held capabilities before any gate
writes. Separate signed checkpoint and three-party anchor bind this contract.
Legacy raw history remains unchanged and is never interpreted as initial state.
"""
from __future__ import annotations

import copy
import stat

from serverware import custody_generation_grants as g
from serverware import native_pilot_ordinary_key_profile as key
from serverware.custody_generation_initial_state import DIRECTORIES, IDENTITY_FIELDS

p = g.p
MAX_STATE = 65536
STATE_API = "serverware.custodyOrdinaryInitialState/v1"
WRAPPER_API = "serverware.custodyOrdinaryInitialHistory/v1"
INITIAL_CREDENTIAL_PATHS = {role: "/etc/serverware/custody-" + role + "-initial-history.json"
    for role in g.ROLES}
STATE_FIELDS = ("apiVersion", "serviceRole", "preparationSha256", "resourcesSha256", "launchSha256",
    "endpointProcessIdentitySha256", "bootIdBase64url", "timeNamespaceDevice", "timeNamespaceInode",
    "issuedAtBoottimeNs", "startupDeadlineBoottimeNs", "lifetimeDeadlineBoottimeNs", "invocationId",
    "deploymentGenerationSha256", "endpointGeneration", "serviceGeneration", "operationGeneration",
    "durableEpoch", "directories")
WRAPPER_FIELDS = ("apiVersion", "initialState", "initialCheckpoint", "history")
DOMAINS = {
    "predecessorCheckpointSha256": b"serverware.custodyOrdinaryInitialCheckpointPredecessor/v1",
    "prunedHistoryRootSha256": b"serverware.custodyOrdinaryInitialHistoryRoot/v1",
    "durableEpochHeadSha256": b"serverware.custodyOrdinaryInitialDurableHead/v1",
}


def _directories(value, role):
    p.fields(value, DIRECTORIES[role])
    seen, owners = set(), set()
    for record in value.values():
        p.fields(record, ("identity", "entryCount"))
        p.integer(record["entryCount"], minimum=0, maximum=0)
        identity = p.fields(record["identity"], IDENTITY_FIELDS)
        for name in IDENTITY_FIELDS:
            key._uint(identity[name], 32 if name in ("deviceMajor", "deviceMinor", "uid", "gid", "mode") else 64,
                minimum=0 if name in ("deviceMajor", "deviceMinor") else 1)
        p.require(identity["mode"] == stat.S_IFDIR | 0o700)
        pair = (identity["deviceMajor"], identity["deviceMinor"], identity["inode"])
        p.require(pair not in seen)
        seen.add(pair); owners.add((identity["uid"], identity["gid"]))
    p.require(len(owners) == 1)
    return seen


def resources(raw):
    """Closed observation shape only; no filesystem or approval claim."""
    value = p.fields(g.document(raw, MAX_STATE),
        ("apiVersion", "preparationSha256", "issuedAtBoottimeNs", "services"))
    p.require(value["apiVersion"] == "serverware.custodyFiveServiceInitialResources/v1")
    p.digest(value["preparationSha256"]); p.ns(value["issuedAtBoottimeNs"])
    p.fields(value["services"], g.ROLES)
    seen = set()
    for role, item in value["services"].items():
        p.fields(item, ("directories",))
        current = _directories(item["directories"], role)
        p.require(not current & seen)
        seen.update(current)
    p.require(len(seen) == 15)
    return value


def validate_state(value):
    p.fields(value, STATE_FIELDS)
    p.require(value["apiVersion"] == STATE_API and value["serviceRole"] in g.ROLES)
    for name in ("preparationSha256", "resourcesSha256", "launchSha256",
                 "endpointProcessIdentitySha256", "deploymentGenerationSha256"):
        p.require(p.digest(value[name]) != p.sha(b""))
    key._boot(value); key._invocation(value["invocationId"])
    issued, startup, lifetime = (p.ns(value[name]) for name in
        ("issuedAtBoottimeNs", "startupDeadlineBoottimeNs", "lifetimeDeadlineBoottimeNs"))
    p.require(issued < startup <= lifetime and startup - issued <= 30_000_000_000)
    for name in ("endpointGeneration", "serviceGeneration", "operationGeneration", "durableEpoch"):
        key._uint(value[name])
    _directories(value["directories"], value["serviceRole"])
    p.require(len(g.canonical(value)) <= MAX_STATE)
    return copy.deepcopy(value)


def commitments(state):
    raw = g.canonical(validate_state(state))
    return {name: p.framed(domain, (raw,)) for name, domain in DOMAINS.items()}


def prepared_state(state, *, preparation_raw, resources_raw, launch_raw, configuration,
                   window, endpoint_role, now):
    state = validate_state(state)
    observation, observed = key.preparation(preparation_raw), resources(resources_raw)
    launch = g.document(launch_raw, 65536)
    role = state["serviceRole"]
    identity = key.prepared_identity(observation, role=role, endpoint_role=endpoint_role,
        launch=launch, configuration=configuration, window=window, now=now)
    p.require(state["preparationSha256"] == observed["preparationSha256"] == p.sha(preparation_raw)
        and state["resourcesSha256"] == p.sha(resources_raw)
        and state["launchSha256"] == p.sha(launch_raw)
        and state["endpointProcessIdentitySha256"] == identity["identitySha256"]
        and state["directories"] == observed["services"][role]["directories"]
        and state["issuedAtBoottimeNs"] == observed["issuedAtBoottimeNs"]
        and p.ns(observation["issuedAtBoottimeNs"]) <= p.ns(state["issuedAtBoottimeNs"]) <= now)
    for name in ("bootIdBase64url", "timeNamespaceDevice", "timeNamespaceInode",
                 "startupDeadlineBoottimeNs", "lifetimeDeadlineBoottimeNs", "invocationId"):
        p.require(state[name] == observation[name])
    for service_role in g.ROLES:
        measured = observation["services"][service_role]
        for item in observed["services"][service_role]["directories"].values():
            p.require((item["identity"]["uid"], item["identity"]["gid"])
                == (measured["plannedUid"], measured["plannedGid"]))
    return identity


def validate_checkpoint(state, checkpoint, *, checkpoint_authority, service_key):
    from serverware import native_pilot_ordinary_key_authority as authority

    state = validate_state(state)
    checked = key.validate_checkpoint(checkpoint)
    payload = checked["payload"]
    public = authority._key(checkpoint_authority)
    authority._key(service_key)
    p.require(checked["authorityKeyId"] == checkpoint_authority["keyId"]
        and checked["authorityKeySpkiSha256"] == checkpoint_authority["keySpkiSha256"]
        and payload["authorizedSigningKeyId"] == service_key["keyId"]
        and payload["authorizedSigningKeySpkiSha256"] == service_key["keySpkiSha256"]
        and payload["endpointProcessIdentitySha256"] == state["endpointProcessIdentitySha256"]
        and payload["exactEndpointGeneration"] == state["endpointGeneration"]
        and payload["checkpointSequence"] == payload["rollbackFloorCheckpointSequence"] == 1
        and payload["rollbackFloorEndpointGeneration"] == state["endpointGeneration"]
        and payload["rollbackFloorConsumerSequence"] == 1
        and payload["predecessorCheckpointSha256"] == commitments(state)["predecessorCheckpointSha256"])
    start, end = payload["validFromBoottime"], payload["validUntilBoottime"]
    p.require(start["domain"] == end["domain"] == key._boot(state)
        and p.ns(state["issuedAtBoottimeNs"]) <= start["absoluteBoottimeNanos"]
        < end["absoluteBoottimeNanos"] <= p.ns(state["lifetimeDeadlineBoottimeNs"]))
    public.verify(p.decoded(checked["authoritySignatureBase64"], size=64),
        key.signature_preimage(payload, checked["authorityKeyId"], checked["authorityKeySpkiSha256"]))
    return checked


def _wrapper(value, *, role, root_pin):
    from serverware import native_pilot_ordinary_key_authority as authority

    p.fields(value, WRAPPER_FIELDS)
    p.require(value["apiVersion"] == WRAPPER_API)
    state = validate_state(value["initialState"])
    p.require(state["serviceRole"] == role)
    history = p.fields(value["history"], g.HISTORY)
    epoch, _ = authority._history(g.canonical(history), role=role, root_pin=root_pin)
    checkpoint = validate_checkpoint(state, value["initialCheckpoint"],
        checkpoint_authority=epoch["checkpointAuthority"], service_key=epoch["serviceSigningKey"])
    identity = epoch["endpointProcessIdentity"]
    p.require(epoch["checkpointSequence"] == 1 and epoch["checkpointSha256"] == checkpoint["checkpointSha256"]
        and epoch["endpointProcessIdentitySha256"] == state["endpointProcessIdentitySha256"]
        and checkpoint["payload"]["endpointRole"] == identity["endpointRole"]
        and (role != g.ROLES[0] or identity["endpointRole"] == "settlement-store"))
    for name in ("endpointGeneration", "serviceGeneration", "operationGeneration", "durableEpoch",
                 "deploymentGenerationSha256"):
        p.require(epoch[name] == state[name])
    for item in state["directories"].values():
        p.require((item["identity"]["uid"], item["identity"]["gid"])
            == (identity["endpointUid"], identity["endpointGid"]))
    roots = commitments(state)
    p.require(epoch["durableEpochHeadSha256"] == roots["durableEpochHeadSha256"]
        and history["firstRetainedEpoch"]["prunedHistoryRootSha256"] == roots["prunedHistoryRootSha256"])
    retention = history["retention"]
    for name in ("oldestReplayableRecordSequence", "currentRecordSequence",
                 "oldestRetainedCompactionSequence", "currentCompactionSequence"):
        p.require(retention[name] == 0)
    for name in ("maximumRetainedEpochs", "maximumCompactionAnchors", "maximumReplayTombstones"):
        p.require(retention[name] == 1)
    return history


def manifest(raw, *, role, root_pin):
    """Opt-in authenticated initial wrapper or unchanged legacy shape.

    Preserve the original outer bytes for C9 byte-digest admission. Returning
    the inner manifest does not assert a live empty-directory observation.
    """
    value = g.document(raw, g.MAX_BYTES)
    if value.get("apiVersion") == WRAPPER_API:
        return _wrapper(value, role=role, root_pin=root_pin)
    return p.fields(value, g.HISTORY)


def runtime_manifest(raw, *, runtime, guest):
    history = manifest(raw, role=guest["serviceRole"], root_pin={
        "keyId": runtime["authorityHistoryRootKeyId"],
        "keySpkiSha256": runtime["authorityHistoryRootKeySpkiSha256"]})
    value = g.document(raw, g.MAX_BYTES)
    if value.get("apiVersion") != WRAPPER_API:
        return history
    state = value["initialState"]
    for name in ("bootIdBase64url", "timeNamespaceDevice", "timeNamespaceInode", "invocationId",
                 "startupDeadlineBoottimeNs", "lifetimeDeadlineBoottimeNs"):
        p.require(state[name] == guest[name])
    p.require(p.ns(state["issuedAtBoottimeNs"]) <= p.ns(guest["issuedAtBoottimeNs"])
        and state["operationGeneration"] == runtime["operationGeneration"]
        and state["serviceGeneration"] == runtime["serviceRestartEpoch"]
        and state["deploymentGenerationSha256"] == runtime["deploymentGenerationSha256"]
        and {name: item["identity"] for name, item in state["directories"].items()}
            == runtime["activationDirectoryIdentities"])
    identity = history["firstRetainedEpoch"]["retainedEpoch"]["endpointProcessIdentity"]
    p.require((identity["endpointUid"], identity["endpointGid"]) == (guest["uid"], guest["gid"]))
    return history
