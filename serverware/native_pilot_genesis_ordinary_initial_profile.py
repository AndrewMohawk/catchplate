"""Explicit cold DRS/CSA State/Wrapper v2 authentication, never a live owner.

Initial commitments describe the signed initial boundary. They are not prior
receipts, proof of currentness, proof of a durable genesis write or permission
to initialize directories. Native startup still measures the actual executed
process and retained empty directories before its first journal write.
"""
from __future__ import annotations

import copy
import stat

from serverware import custody_generation_grants as g
from serverware import native_pilot_ordinary_initial_profile as ordinary
from serverware import native_pilot_ordinary_key_authority as history_authority
from serverware import native_pilot_ordinary_key_profile as key

p = g.p
STATE_API = "serverware.custodyOrdinaryInitialState/v2"
WRAPPER_API = "serverware.custodyOrdinaryInitialHistory/v2"
RUNTIME_API = "serverware.policyCustodyServiceRuntimeConfig/v11"
ROLES = ("durable-recovery-store", "current-signature-authority")
DIRECTORIES = {ROLES[0]: ("journal", "publication-genesis-journal"), ROLES[1]: ("publication-genesis-journal",)}
MAX_STATE = 65536
MAX_HISTORY = g.MAX_BYTES
STATE_FIELDS = ordinary.STATE_FIELDS
WRAPPER_FIELDS = ordinary.WRAPPER_FIELDS
IDENTITY_FIELDS = ("mountId", "deviceMajor", "deviceMinor", "inode", "uid", "gid", "mode")
DOMAINS = ordinary.DOMAINS


def same(first, second):
    p.require(g.canonical(first) == g.canonical(second))


def directories(value, role):
    p.require(role in ROLES)
    p.fields(value, DIRECTORIES[role])
    seen, owners = set(), set()
    for row in value.values():
        p.fields(row, ("identity", "entryCount"))
        key._uint(row["entryCount"], minimum=0)
        p.require(row["entryCount"] == 0)
        identity = p.fields(row["identity"], IDENTITY_FIELDS)
        for name in IDENTITY_FIELDS:
            key._uint(identity[name], 32 if name in ("deviceMajor", "deviceMinor", "uid", "gid", "mode") else 64,
                minimum=0 if name in ("deviceMajor", "deviceMinor") else 1)
        p.require(identity["mode"] == stat.S_IFDIR | 0o700)
        pair = identity["deviceMajor"], identity["deviceMinor"], identity["inode"]
        p.require(pair not in seen)
        seen.add(pair); owners.add((identity["uid"], identity["gid"]))
    p.require(len(owners) == 1)
    return seen


def validate_state(value):
    p.fields(value, STATE_FIELDS)
    p.require(value["apiVersion"] == STATE_API and value["serviceRole"] in ROLES)
    for name in ("preparationSha256", "resourcesSha256", "launchSha256", "endpointProcessIdentitySha256",
            "deploymentGenerationSha256"):
        p.require(p.digest(value[name]) != p.sha(b""))
    key._boot(value); key._invocation(value["invocationId"])
    issued, startup, lifetime = (p.ns(value[name]) for name in
        ("issuedAtBoottimeNs", "startupDeadlineBoottimeNs", "lifetimeDeadlineBoottimeNs"))
    p.require(issued < startup <= lifetime and startup - issued <= 30_000_000_000)
    for name in ("endpointGeneration", "serviceGeneration", "operationGeneration", "durableEpoch"):
        key._uint(value[name])
    directories(value["directories"], value["serviceRole"])
    p.require(len(g.canonical(value)) <= MAX_STATE)
    return copy.deepcopy(value)


def commitments(state):
    raw = g.canonical(validate_state(state))
    return {name: p.framed(domain, (raw,)) for name, domain in DOMAINS.items()}


def validate_checkpoint(state, checkpoint, *, checkpoint_authority, service_key):
    state = validate_state(state)
    checked = key.validate_checkpoint(checkpoint)
    payload = checked["payload"]
    public = history_authority._key(checkpoint_authority)
    history_authority._key(service_key)
    p.require(checked["authorityKeyId"] == checkpoint_authority["keyId"]
        and checked["authorityKeySpkiSha256"] == checkpoint_authority["keySpkiSha256"]
        and payload["authorizedSigningKeyId"] == service_key["keyId"]
        and payload["authorizedSigningKeySpkiSha256"] == service_key["keySpkiSha256"]
        and payload["endpointProcessIdentitySha256"] == state["endpointProcessIdentitySha256"]
        and payload["exactEndpointGeneration"] == payload["rollbackFloorEndpointGeneration"] == state["endpointGeneration"]
        and payload["checkpointSequence"] == payload["rollbackFloorCheckpointSequence"] == 1
        and payload["rollbackFloorConsumerSequence"] == 1
        and payload["predecessorCheckpointSha256"] == commitments(state)["predecessorCheckpointSha256"]
        and (state["serviceRole"] != ROLES[0] or payload["endpointRole"] == "settlement-store"))
    start, end = payload["validFromBoottime"], payload["validUntilBoottime"]
    same(start["domain"], key._boot(state)); same(end["domain"], start["domain"])
    p.require(p.ns(state["issuedAtBoottimeNs"]) <= start["absoluteBoottimeNanos"]
        < end["absoluteBoottimeNanos"] <= p.ns(state["lifetimeDeadlineBoottimeNs"]))
    public.verify(p.decoded(checked["authoritySignatureBase64"], size=64),
        key.signature_preimage(payload, checked["authorityKeyId"], checked["authorityKeySpkiSha256"]))
    return checked


def _wrapper(raw, *, role, root_pin):
    p.require(role in ROLES)
    value = p.fields(g.document(raw, MAX_HISTORY), WRAPPER_FIELDS)
    p.require(value["apiVersion"] == WRAPPER_API)
    state = validate_state(value["initialState"])
    p.require(state["serviceRole"] == role)
    history = p.fields(value["history"], g.HISTORY)
    epoch, _ = history_authority._history(g.canonical(history), role=role, root_pin=root_pin)
    checkpoint = validate_checkpoint(state, value["initialCheckpoint"],
        checkpoint_authority=epoch["checkpointAuthority"], service_key=epoch["serviceSigningKey"])
    identity = epoch["endpointProcessIdentity"]
    p.require(epoch["checkpointSequence"] == 1 and epoch["checkpointSha256"] == checkpoint["checkpointSha256"]
        and epoch["endpointProcessIdentitySha256"] == state["endpointProcessIdentitySha256"]
        and checkpoint["payload"]["endpointRole"] == identity["endpointRole"])
    for name in ("endpointGeneration", "serviceGeneration", "operationGeneration", "durableEpoch", "deploymentGenerationSha256"):
        same(epoch[name], state[name])
    for row in state["directories"].values():
        p.require((row["identity"]["uid"], row["identity"]["gid"]) == (identity["endpointUid"], identity["endpointGid"]))
    roots = commitments(state)
    p.require(epoch["durableEpochHeadSha256"] == roots["durableEpochHeadSha256"]
        and history["firstRetainedEpoch"]["prunedHistoryRootSha256"] == roots["prunedHistoryRootSha256"])
    for name in ("oldestReplayableRecordSequence", "currentRecordSequence", "oldestRetainedCompactionSequence", "currentCompactionSequence"):
        p.require(history["retention"][name] == 0)
    for name in ("maximumRetainedEpochs", "maximumCompactionAnchors", "maximumReplayTombstones"):
        p.require(history["retention"][name] == 1)
    return {"state": state, "checkpoint": checkpoint, "history": history, "identity": identity}


def manifest(raw, *, role, root_pin):
    """Authenticate only the explicitly selected v2 wrapper; no legacy fallback."""
    return _wrapper(raw, role=role, root_pin=root_pin)["history"]


def require_window(raw, *, role, root_pin, boot, now_boottime_ns, issued=None, expires=None, startup=True):
    """Public authentication at explicit clocks; never new startup authority."""
    p.require(type(startup) is bool and type(boot) is tuple and len(boot) == 3)
    context = _wrapper(raw, role=role, root_pin=root_pin)
    state, checkpoint = context["state"], context["checkpoint"]["payload"]
    same(list(boot), [state[name] for name in ("bootIdBase64url", "timeNamespaceDevice", "timeNamespaceInode")])
    now = key._uint(now_boottime_ns)
    low = checkpoint["validFromBoottime"]["absoluteBoottimeNanos"]
    high = min(checkpoint["validUntilBoottime"]["absoluteBoottimeNanos"], p.ns(state["lifetimeDeadlineBoottimeNs"]))
    deadline = min(high, p.ns(state["startupDeadlineBoottimeNs"])) if startup else high
    p.require(low <= now < deadline and (issued is None) == (expires is None))
    if issued is not None:
        p.require(low <= key._uint(issued) < key._uint(expires) <= high)
    return {**context, "deadline": deadline}


def runtime_manifest(raw, *, runtime, guest):
    """Authenticate cold history and exact supplied guest/header associations."""
    p.require(runtime["apiVersion"] == RUNTIME_API)
    p.fields(guest, p.GUEST_FIELDS)
    context = _wrapper(raw, role=guest["serviceRole"], root_pin={"keyId": runtime["authorityHistoryRootKeyId"],
        "keySpkiSha256": runtime["authorityHistoryRootKeySpkiSha256"]})
    state, history, identity = context["state"], context["history"], context["identity"]
    p.require(runtime["authorityHistoryManifestSha256"] == history["manifestSha256"])
    for name in ("bootIdBase64url", "timeNamespaceDevice", "timeNamespaceInode", "invocationId",
            "startupDeadlineBoottimeNs", "lifetimeDeadlineBoottimeNs"):
        same(state[name], guest[name])
    p.require(p.ns(state["issuedAtBoottimeNs"]) <= p.ns(guest["issuedAtBoottimeNs"]))
    for target, source in (("operationGeneration", "operationGeneration"), ("serviceRestartEpoch", "serviceGeneration"),
            ("deploymentGenerationSha256", "deploymentGenerationSha256")):
        same(runtime[target], state[source])
    same({name: row["identity"] for name, row in state["directories"].items()}, runtime["activationDirectoryIdentities"])
    same([identity["endpointUid"], identity["endpointGid"]], [guest["uid"], guest["gid"]])
    return history
