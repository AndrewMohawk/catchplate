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

from catchplate import custody_generation_grants as g
from catchplate import native_pilot_ordinary_key_profile as key
from catchplate.custody_generation_initial_state import DIRECTORIES, IDENTITY_FIELDS

p = g.p
MAX_STATE = 65536
STATE_API = "catchplate.custodyOrdinaryInitialState/v1"
WRAPPER_API = "catchplate.custodyOrdinaryInitialHistory/v1"
ADOPTED_STATE_API = "catchplate.custodyOrdinaryInitialState/v3"
ADOPTED_WRAPPER_API = "catchplate.custodyOrdinaryInitialHistory/v3"
ADOPTED_ROLES = (g.ROLES[0], g.ROLES[3])
HELPER_RUNTIME_API = "catchplate.policyCustodyServiceRuntimeConfig/v9"
MAX_HELPER_HISTORY = 1024 * 1024
HELPER_ENDPOINT_ROLES = ("settlement-store", "fence-authority", "cgroup-executor", "termination-ledger")
INITIAL_CREDENTIAL_PATHS = {role: "/etc/catchplate/custody-" + role + "-initial-history.json"
    for role in g.ROLES}
STATE_FIELDS = ("apiVersion", "serviceRole", "preparationSha256", "resourcesSha256", "launchSha256",
    "endpointProcessIdentitySha256", "bootIdBase64url", "timeNamespaceDevice", "timeNamespaceInode",
    "issuedAtBoottimeNs", "startupDeadlineBoottimeNs", "lifetimeDeadlineBoottimeNs", "invocationId",
    "deploymentGenerationSha256", "endpointGeneration", "serviceGeneration", "operationGeneration",
    "durableEpoch", "directories")
WRAPPER_FIELDS = ("apiVersion", "initialState", "initialCheckpoint", "history")
DOMAINS = {
    "predecessorCheckpointSha256": b"catchplate.custodyOrdinaryInitialCheckpointPredecessor/v1",
    "prunedHistoryRootSha256": b"catchplate.custodyOrdinaryInitialHistoryRoot/v1",
    "durableEpochHeadSha256": b"catchplate.custodyOrdinaryInitialDurableHead/v1",
}


def _directories(value, role, *, adopted=False):
    p.require(type(adopted) is bool)
    p.fields(value, DIRECTORIES[role] + (("publication-journal",) if adopted and role in ADOPTED_ROLES else ()))
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


def resources(raw, *, adopted=False):
    """Closed observation shape only; no filesystem or approval claim."""
    value = p.fields(g.document(raw, MAX_STATE),
        ("apiVersion", "preparationSha256", "issuedAtBoottimeNs", "services"))
    p.require(type(adopted) is bool and value["apiVersion"] == "catchplate.custodyFiveServiceInitialResources/v" + ("2" if adopted else "1"))
    p.digest(value["preparationSha256"]); p.ns(value["issuedAtBoottimeNs"])
    p.fields(value["services"], g.ROLES)
    seen = set()
    for role, item in value["services"].items():
        p.fields(item, ("directories",))
        current = _directories(item["directories"], role, adopted=adopted)
        p.require(not current & seen)
        seen.update(current)
    p.require(len(seen) == (17 if adopted else 15))
    return value


def validate_state(value, *, adopted=False):
    p.fields(value, STATE_FIELDS)
    p.require(type(adopted) is bool and value["serviceRole"] in g.ROLES)
    selected = adopted and value["serviceRole"] in ADOPTED_ROLES
    p.require(value["apiVersion"] == (ADOPTED_STATE_API if selected else STATE_API))
    for name in ("preparationSha256", "resourcesSha256", "launchSha256",
                 "endpointProcessIdentitySha256", "deploymentGenerationSha256"):
        p.require(p.digest(value[name]) != p.sha(b""))
    key._boot(value); key._invocation(value["invocationId"])
    issued, startup, lifetime = (p.ns(value[name]) for name in
        ("issuedAtBoottimeNs", "startupDeadlineBoottimeNs", "lifetimeDeadlineBoottimeNs"))
    p.require(issued < startup <= lifetime and startup - issued <= 30_000_000_000)
    for name in ("endpointGeneration", "serviceGeneration", "operationGeneration", "durableEpoch"):
        key._uint(value[name])
    _directories(value["directories"], value["serviceRole"], adopted=adopted)
    p.require(len(g.canonical(value)) <= MAX_STATE)
    return copy.deepcopy(value)


def commitments(state, *, adopted=False):
    raw = g.canonical(validate_state(state, adopted=adopted))
    return {name: p.framed(domain, (raw,)) for name, domain in DOMAINS.items()}


def prepared_state(state, *, preparation_raw, resources_raw, launch_raw, configuration,
                   window, endpoint_role, now, adopted=False):
    state = validate_state(state, adopted=adopted)
    observation, observed = key.preparation(preparation_raw), resources(resources_raw, adopted=adopted)
    launch = g.document(launch_raw, 65536)
    role = state["serviceRole"]
    identity = key.prepared_identity(observation, role=role, endpoint_role=endpoint_role,
        launch=launch, configuration=configuration, window=window, now=now, adopted=adopted)
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


def validate_checkpoint(state, checkpoint, *, checkpoint_authority, service_key, adopted=False):
    from catchplate import native_pilot_ordinary_key_authority as authority

    state = validate_state(state, adopted=adopted)
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
        and payload["predecessorCheckpointSha256"] == commitments(state, adopted=adopted)["predecessorCheckpointSha256"])
    start, end = payload["validFromBoottime"], payload["validUntilBoottime"]
    p.require(start["domain"] == end["domain"] == key._boot(state)
        and p.ns(state["issuedAtBoottimeNs"]) <= start["absoluteBoottimeNanos"]
        < end["absoluteBoottimeNanos"] <= p.ns(state["lifetimeDeadlineBoottimeNs"]))
    public.verify(p.decoded(checked["authoritySignatureBase64"], size=64),
        key.signature_preimage(payload, checked["authorityKeyId"], checked["authorityKeySpkiSha256"]))
    return checked


def _wrapper(value, *, role, root_pin, adopted=False):
    from catchplate import native_pilot_ordinary_key_authority as authority

    p.fields(value, WRAPPER_FIELDS)
    p.require(value["apiVersion"] == (ADOPTED_WRAPPER_API if adopted and role in ADOPTED_ROLES else WRAPPER_API))
    state = validate_state(value["initialState"], adopted=adopted)
    p.require(state["serviceRole"] == role)
    history = p.fields(value["history"], g.HISTORY)
    epoch, _ = authority._history(g.canonical(history), role=role, root_pin=root_pin)
    checkpoint = validate_checkpoint(state, value["initialCheckpoint"],
        checkpoint_authority=epoch["checkpointAuthority"], service_key=epoch["serviceSigningKey"], adopted=adopted)
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
    roots = commitments(state, adopted=adopted)
    p.require(epoch["durableEpochHeadSha256"] == roots["durableEpochHeadSha256"]
        and history["firstRetainedEpoch"]["prunedHistoryRootSha256"] == roots["prunedHistoryRootSha256"])
    retention = history["retention"]
    for name in ("oldestReplayableRecordSequence", "currentRecordSequence",
                 "oldestRetainedCompactionSequence", "currentCompactionSequence"):
        p.require(retention[name] == 0)
    for name in ("maximumRetainedEpochs", "maximumCompactionAnchors", "maximumReplayTombstones"):
        p.require(retention[name] == 1)
    return history


def manifest(raw, *, role, root_pin, adopted=False):
    """Opt-in authenticated initial wrapper or unchanged legacy shape.

    Preserve the original outer bytes for C9 byte-digest admission. Returning
    the inner manifest does not assert a live empty-directory observation.
    """
    value = g.document(raw, g.MAX_BYTES)
    p.require(type(adopted) is bool)
    selected = ADOPTED_WRAPPER_API if adopted and role in ADOPTED_ROLES else WRAPPER_API
    if value.get("apiVersion") == selected:
        return _wrapper(value, role=role, root_pin=root_pin, adopted=adopted)
    p.require(not adopted or role not in ADOPTED_ROLES)
    return p.fields(value, g.HISTORY)


def runtime_manifest(raw, *, runtime, guest):
    adopted = runtime["apiVersion"] == "catchplate.policyCustodyServiceRuntimeConfig/v12"
    history = manifest(raw, role=guest["serviceRole"], root_pin={
        "keyId": runtime["authorityHistoryRootKeyId"],
        "keySpkiSha256": runtime["authorityHistoryRootKeySpkiSha256"]}, adopted=adopted)
    value = g.document(raw, g.MAX_BYTES)
    if adopted:
        p.require(value.get("apiVersion") == "catchplate.custodyOrdinaryInitialHistory/v3"
            and guest["serviceRole"] in (g.ROLES[0], g.ROLES[3]))
    elif value.get("apiVersion") != WRAPPER_API:
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


def helper_histories(primary_raw, members, *, root_pin):
    """Authenticate four real role-specific wrappers, never relabel a checkpoint.

    Every member uses the existing initial ceremony and independent root pin.
    Common facts name one prepared helper; only role-bound hashes/signatures
    differ. This public check is neither acquisition nor a currentness decision.
    """
    p.fields(members, HELPER_ENDPOINT_ROLES)
    p.require(type(primary_raw) is bytes and 0 < len(primary_raw) <= MAX_HELPER_HISTORY)
    result, primary = {}, None
    for endpoint_role in HELPER_ENDPOINT_ROLES:
        text = members[endpoint_role]
        p.require(type(text) is str and text.isascii() and 0 < len(text) <= MAX_HELPER_HISTORY)
        raw = text.encode("ascii")
        wrapper = p.fields(g.document(raw, MAX_HELPER_HISTORY), WRAPPER_FIELDS)
        p.require(wrapper["apiVersion"] == WRAPPER_API)
        history = _wrapper(wrapper, role=g.ROLES[-1], root_pin=root_pin)
        epoch = history["firstRetainedEpoch"]["retainedEpoch"]
        identity, checkpoint = epoch["endpointProcessIdentity"], wrapper["initialCheckpoint"]
        p.require(identity["endpointRole"] == checkpoint["payload"]["endpointRole"] == endpoint_role)
        result[endpoint_role] = dict(original=raw, wrapper=wrapper, history=history,
            state=wrapper["initialState"], checkpoint=checkpoint, epoch=epoch, identity=identity)
        if raw == primary_raw:
            p.require(primary is None)
            primary = result[endpoint_role]
    p.require(primary is not None)
    for item in result.values():
        for name in STATE_FIELDS:
            if name != "endpointProcessIdentitySha256":
                p.require(item["state"][name] == primary["state"][name])
        for name in key.IDENTITY_FIELDS:
            if name not in ("endpointRole", "identitySha256"):
                p.require(item["identity"][name] == primary["identity"][name])
        for name in key.PAYLOAD_FIELDS:
            if name not in ("endpointRole", "endpointProcessIdentitySha256", "predecessorCheckpointSha256"):
                p.require(item["checkpoint"]["payload"][name] == primary["checkpoint"]["payload"][name])
        for name, value in item["epoch"].items():
            if name not in ("endpointProcessIdentity", "endpointProcessIdentitySha256", "checkpointSha256",
                            "durableEpochHeadSha256", "epochSha256"):
                p.require(value == primary["epoch"][name])
        p.require(item["history"]["rootAuthority"] == primary["history"]["rootAuthority"])
    p.require(len({row["identity"]["identitySha256"] for row in result.values()}) == len(HELPER_ENDPOINT_ROLES)
        and len({row["checkpoint"]["checkpointSha256"] for row in result.values()}) == len(HELPER_ENDPOINT_ROLES))
    return copy.deepcopy(result)


def helper_endpoint_histories(primary_raw, *, runtime):
    """Bind authenticated members to the explicit helper runtime successor."""
    header = runtime["runtime"]
    p.require(header["apiVersion"] == HELPER_RUNTIME_API)
    result = helper_histories(primary_raw, runtime["initialEndpointHistories"], root_pin={
        "keyId": header["authorityHistoryRootKeyId"], "keySpkiSha256": header["authorityHistoryRootKeySpkiSha256"]})
    primary = next(row for row in result.values() if row["original"] == primary_raw)
    state, checkpoint = primary["state"], primary["checkpoint"]
    payload = checkpoint["payload"]
    p.require(header["authorityHistoryManifestSha256"] == primary["history"]["manifestSha256"]
        and header["operationGeneration"] == state["operationGeneration"]
        and header["serviceRestartEpoch"] == state["serviceGeneration"]
        and header["deploymentGenerationSha256"] == state["deploymentGenerationSha256"]
        and header["activationDirectoryIdentities"] == {name: item["identity"]
            for name, item in state["directories"].items()}
        and runtime["endpointProcessIdentitySha256"] == primary["identity"]["identitySha256"]
        and runtime["currentHeadAuthorityKeyId"] == checkpoint["authorityKeyId"]
        and runtime["currentKeyAuthorizationCheckpointSha256"] == checkpoint["checkpointSha256"])
    for target, source in (("signingKeyId", "authorizedSigningKeyId"), ("endpointGeneration", "exactEndpointGeneration"),
            ("checkpointSequence", "checkpointSequence"), ("revocationGeneration", "revocationGenerationHighWater"),
            ("revocationRootSha256", "revocationRootSha256")):
        p.require(runtime[target] == payload[source])
    return result


def helper_public_keys(runtime, contexts, credentials):
    """Select only exact C9 public verification originals, never signing seeds."""
    from catchplate import native_pilot_ordinary_key_authority as authority

    p.fields(contexts, HELPER_ENDPOINT_ROLES)
    pins = p.fields(runtime["initialEndpointPins"], HELPER_ENDPOINT_ROLES)
    p.require(type(credentials) is list)
    selected = {}
    for endpoint_role in HELPER_ENDPOINT_ROLES:
        epoch = contexts[endpoint_role]["epoch"]
        for field, public in (("endpointVerifyingKeyCredential", epoch["serviceSigningKey"]),
                ("checkpointAuthorityVerifyingKeyCredential", epoch["checkpointAuthority"])):
            name = pins[endpoint_role][field]
            records = [item for item in credentials if item["name"] == name]
            p.require(len(records) == 1)
            raw = authority._raw_key(authority._key(public))
            record = records[0]
            p.require(record["length"] == 32 and record["signing"] is None
                and record["original"]["sha256"] == p.sha(raw))
            p.require(name not in selected or selected[name] == raw)
            selected[name] = raw
    return selected
