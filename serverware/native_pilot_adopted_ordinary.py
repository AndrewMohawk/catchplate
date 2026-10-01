"""Authenticate supplied adopted ordinary histories; never construct an owner.

The explicit v3 initial wrapper is checked in its own domain. No old wrapper is
retagged, no empty directory or generation receipt is inferred, and no clock is
renewed. These public checks precede native admission of the actual resources.
"""
from __future__ import annotations

import stat

from cryptography.hazmat.primitives import serialization

from serverware import custody_generation_grants as g
from serverware import native_pilot_ordinary_initial_profile as initial
from serverware import native_pilot_ordinary_key_authority as authority
from serverware import native_pilot_ordinary_key_profile as key

p = g.p
ROLES = (g.ROLES[0], g.ROLES[3])
RUNTIME_API = "serverware.policyCustodyServiceRuntimeConfig/v12"
WRAPPER_API = "serverware.custodyOrdinaryInitialHistory/v3"
STATE_API = "serverware.custodyOrdinaryInitialState/v3"
MEMBER_FIELDS = ("generationGrantOriginal", "runtimeOriginal", "historyOriginal", "rootKeyId", "rootKeySpkiSha256")
DIRECTORIES = {role: initial.DIRECTORIES[role] + ("publication-journal",) for role in ROLES}


def original(value, maximum=1024 * 1024):
    p.require(type(value) is str and value.isascii() and 0 < len(value) <= maximum)
    raw = value.encode("ascii")
    return raw, g.document(raw, maximum)


def _state(value, role):
    p.fields(value, initial.STATE_FIELDS)
    p.require(value["apiVersion"] == STATE_API and value["serviceRole"] == role and role in ROLES)
    for name in ("preparationSha256", "resourcesSha256", "launchSha256", "endpointProcessIdentitySha256", "deploymentGenerationSha256"):
        p.require(p.digest(value[name]) not in {p.sha(b""), "sha256:" + "0" * 64})
    key._boot(value); key._invocation(value["invocationId"])
    issued, startup, lifetime = (p.ns(value[name]) for name in
        ("issuedAtBoottimeNs", "startupDeadlineBoottimeNs", "lifetimeDeadlineBoottimeNs"))
    p.require(issued < startup <= lifetime and startup - issued <= 30_000_000_000)
    for name in ("endpointGeneration", "serviceGeneration", "operationGeneration", "durableEpoch"):
        key._uint(value[name])
    owners, identities = set(), set()
    for row in p.fields(value["directories"], DIRECTORIES[role]).values():
        p.fields(row, ("identity", "entryCount")); p.require(type(row["entryCount"]) is int and row["entryCount"] == 0)
        identity = p.fields(row["identity"], initial.IDENTITY_FIELDS)
        for name in initial.IDENTITY_FIELDS:
            key._uint(identity[name], 32 if name in ("deviceMajor", "deviceMinor", "uid", "gid", "mode") else 64,
                minimum=0 if name in ("deviceMajor", "deviceMinor") else 1)
        p.require(identity["mode"] == stat.S_IFDIR | 0o700)
        item = tuple(identity[name] for name in ("deviceMajor", "deviceMinor", "inode"))
        p.require(item not in identities); identities.add(item); owners.add((identity["uid"], identity["gid"]))
    p.require(len(owners) == 1 and len(g.canonical(value)) <= initial.MAX_STATE)
    return value


def history(raw, *, role, header, boot, issued, expires):
    """Exact signed initial target, including both original window bounds."""
    wrapper = p.fields(g.document(raw, 1024 * 1024), initial.WRAPPER_FIELDS)
    p.require(wrapper["apiVersion"] == WRAPPER_API and header["apiVersion"] == RUNTIME_API)
    state = _state(wrapper["initialState"], role)
    p.require((state["bootIdBase64url"], state["timeNamespaceDevice"], state["timeNamespaceInode"]) == boot
        and p.ns(state["issuedAtBoottimeNs"]) <= issued < expires <= p.ns(state["lifetimeDeadlineBoottimeNs"]))
    manifest = p.fields(wrapper["history"], g.HISTORY)
    root_pin = {"keyId": header["authorityHistoryRootKeyId"], "keySpkiSha256": header["authorityHistoryRootKeySpkiSha256"]}
    epoch, checkpoint_key = authority._history(g.canonical(manifest), role=role, root_pin=root_pin)
    checkpoint = key.validate_checkpoint(wrapper["initialCheckpoint"])
    payload = checkpoint["payload"]
    commitments = {name: p.framed(domain, (g.canonical(state),)) for name, domain in initial.DOMAINS.items()}
    p.require(checkpoint["authorityKeyId"] == epoch["checkpointAuthority"]["keyId"]
        and checkpoint["authorityKeySpkiSha256"] == epoch["checkpointAuthority"]["keySpkiSha256"]
        and payload["authorizedSigningKeyId"] == epoch["serviceSigningKey"]["keyId"]
        and payload["authorizedSigningKeySpkiSha256"] == epoch["serviceSigningKey"]["keySpkiSha256"]
        and payload["endpointProcessIdentitySha256"] == state["endpointProcessIdentitySha256"]
        and payload["exactEndpointGeneration"] == payload["rollbackFloorEndpointGeneration"] == state["endpointGeneration"]
        and payload["checkpointSequence"] == payload["rollbackFloorCheckpointSequence"] == payload["rollbackFloorConsumerSequence"] == 1
        and payload["predecessorCheckpointSha256"] == commitments["predecessorCheckpointSha256"])
    start, end = payload["validFromBoottime"], payload["validUntilBoottime"]
    p.require(start["domain"] == end["domain"] == key._boot(state)
        and p.ns(state["issuedAtBoottimeNs"]) <= start["absoluteBoottimeNanos"] <= issued
        < expires <= end["absoluteBoottimeNanos"] <= p.ns(state["lifetimeDeadlineBoottimeNs"]))
    checkpoint_key.verify(p.decoded(checkpoint["authoritySignatureBase64"], size=64),
        key.signature_preimage(payload, checkpoint["authorityKeyId"], checkpoint["authorityKeySpkiSha256"]))
    identity = epoch["endpointProcessIdentity"]
    p.require(epoch["checkpointSequence"] == 1 and epoch["checkpointSha256"] == checkpoint["checkpointSha256"]
        and epoch["endpointProcessIdentitySha256"] == state["endpointProcessIdentitySha256"]
        and payload["endpointRole"] == identity["endpointRole"]
        and (role != ROLES[0] or identity["endpointRole"] == "settlement-store"))
    for name in ("endpointGeneration", "serviceGeneration", "operationGeneration", "durableEpoch", "deploymentGenerationSha256"):
        p.require(epoch[name] == state[name])
    p.require(epoch["durableEpochHeadSha256"] == commitments["durableEpochHeadSha256"]
        and manifest["firstRetainedEpoch"]["prunedHistoryRootSha256"] == commitments["prunedHistoryRootSha256"]
        and manifest["manifestSha256"] == header["authorityHistoryManifestSha256"]
        and header["operationGeneration"] == state["operationGeneration"]
        and header["serviceRestartEpoch"] == state["serviceGeneration"]
        and header["deploymentGenerationSha256"] == state["deploymentGenerationSha256"]
        and header["activationDirectoryIdentities"] == {name: row["identity"] for name, row in state["directories"].items()}
        and header["publicationAdmission"] == {"grantFdName": "publication-grant"}
        and header["generationAdmission"] == {"grantFdName": "generation-grant"}
        and header["dispatchAdmission"] == {"grantFdName": "dispatch-grant"})
    field, name = ("spoolHead", "spool-head-grant") if role == ROLES[0] else ("spoolCurrent", "spool-current-grant")
    p.require(header[field] == {"grantFdName": name}
        and all(other not in header for other in ("spoolHead", "spoolCurrent", "spoolCleanup") if other != field))
    for row in state["directories"].values():
        p.require((row["identity"]["uid"], row["identity"]["gid"]) == (identity["endpointUid"], identity["endpointGid"]))
    for name in ("oldestReplayableRecordSequence", "currentRecordSequence", "oldestRetainedCompactionSequence", "currentCompactionSequence"):
        p.require(manifest["retention"][name] == 0)
    for name in ("maximumRetainedEpochs", "maximumCompactionAnchors", "maximumReplayTombstones"):
        p.require(manifest["retention"][name] == 1)
    return {"history": manifest, "epoch": epoch, "state": state, "deadline": end["absoluteBoottimeNanos"]}


def epoch_reference(epoch):
    fields = ("apiVersion", "authorityRole", "authorityEpochSequence", "checkpointSequence", "checkpointSha256",
        "endpointProcessIdentitySha256", "endpointGeneration", "serviceGeneration", "operationGeneration", "durableEpoch", "durableEpochHeadSha256",
        "deploymentGenerationSha256")
    return {name: epoch[name] for name in fields} | {
        "authorityEpochSha256": epoch["epochSha256"],
        "checkpointAuthorityKeyId": epoch["checkpointAuthority"]["keyId"],
        "checkpointAuthorityKeySpkiSha256": epoch["checkpointAuthority"]["keySpkiSha256"],
        "serviceSigningKeyId": epoch["serviceSigningKey"]["keyId"],
        "serviceSigningKeySpkiSha256": epoch["serviceSigningKey"]["keySpkiSha256"]}


def targets(rows, payload, *, boot):
    p.require(type(rows) is list and len(rows) == 2)
    result = {}
    selected = {row["serviceRole"]: row for row in payload["targetHistories"]}
    p.require(len(selected) == 2 and set(selected) == set(ROLES))
    for row in rows:
        p.fields(row, ("serviceRole", "runtimeOriginal", "historyOriginal", "rootKeyId", "rootKeySpkiSha256"))
        role = row["serviceRole"]; p.require(role in ROLES and role not in result)
        runtime_raw, runtime = original(row["runtimeOriginal"])
        history_raw, _ = original(row["historyOriginal"])
        header = runtime["runtime"]
        p.require(header["authorityHistoryRootKeyId"] == row["rootKeyId"]
            and header["authorityHistoryRootKeySpkiSha256"] == row["rootKeySpkiSha256"])
        held = history(history_raw, role=role, header=header, boot=boot,
            issued=payload["issuedAtBoottimeNanos"], expires=payload["expiresAtBoottimeNanos"])
        target = selected[role]
        root = held["history"]["rootAuthority"]
        root_key = authority._key(root); service_key = authority._key(held["epoch"]["serviceSigningKey"])
        p.require(target == {"serviceRole": role, "historyManifestSha256": held["history"]["manifestSha256"],
            "rootKeySpkiSha256": root["keySpkiSha256"],
            "rootPublicKeyBase64url": p.encoded(root_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)),
            "authorityEpoch": epoch_reference(held["epoch"]),
            "publicKeyBase64url": p.encoded(service_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))})
        result[role] = held | {"runtime_raw": runtime_raw, "history_raw": history_raw, "header": header}
    return result


def members(rows, *, targets, scope, peer, assignment, checkpoint, boot, now_boottime_ns, issued_at, expires_at):
    """Authenticate the exact native five-member generation/history bundle."""
    p.fields(rows, g.ROLES)
    uids, gids, common = set(), set(), None
    deadline, epoch_limit = scope["expiresAtBoottimeNanos"], expires_at
    for role, row in rows.items():
        p.fields(row, MEMBER_FIELDS)
        runtime_raw, runtime = original(row["runtimeOriginal"], g.MAX_BYTES)
        history_raw, _ = original(row["historyOriginal"])
        grant_raw, signed = original(row["generationGrantOriginal"], 65536)
        p.fields(signed, ("payload", "signatureBase64url"))
        grant = p.fields(signed["payload"], g.GRANT)
        header, guest = runtime["runtime"], grant["guest"]
        p.guest(guest)
        p.require(grant["apiVersion"] == "serverware.custodyServiceGenerationGrant/v1"
            and grant["purpose"] == "cold-service-generation-admission" and grant["serviceRole"] == role == guest["serviceRole"]
            and p.sha(runtime_raw) == guest["runtimeConfigurationSha256"] == grant["runtimeConfigurationSha256"]
            and header["expectedPeer"] == peer
            and (guest["bootIdBase64url"], guest["timeNamespaceDevice"], guest["timeNamespaceInode"]) == boot
            and guest["uid"] != peer["uid"] and guest["gid"] != peer["gid"]
            and guest["uid"] not in uids and guest["gid"] not in gids)
        uids.add(guest["uid"]); gids.add(guest["gid"])
        if role in ROLES:
            target = targets[role]
            p.require(runtime_raw == target["runtime_raw"] and history_raw == target["history_raw"])
            manifest, state = target["history"], target["state"]
            for name in ("bootIdBase64url", "timeNamespaceDevice", "timeNamespaceInode", "invocationId",
                    "startupDeadlineBoottimeNs", "lifetimeDeadlineBoottimeNs"):
                p.require(state[name] == guest[name])
            identity = target["epoch"]["endpointProcessIdentity"]
            p.require((identity["endpointUid"], identity["endpointGid"]) == (guest["uid"], guest["gid"]))
            p.require(p.ns(state["issuedAtBoottimeNs"]) <= p.ns(guest["issuedAtBoottimeNs"]))
            deadline = min(deadline, target["deadline"])
        else:
            manifest = initial.runtime_manifest(history_raw, runtime=header, guest=guest)
            p.require(header["apiVersion"] == "serverware.policyCustodyServiceRuntimeConfig/v" +
                ("8" if role == g.ROLES[1] else "9" if role == g.ROLES[-1] else "5"))
            authority._history(g.canonical(manifest), role=role,
                root_pin={"keyId": row["rootKeyId"], "keySpkiSha256": row["rootKeySpkiSha256"]})
            if role == g.ROLES[-1]:
                initial.helper_endpoint_histories(history_raw, runtime=runtime)
        root = manifest["rootAuthority"]
        p.require(row["rootKeyId"] == header["authorityHistoryRootKeyId"] == root["keyId"]
            and row["rootKeySpkiSha256"] == header["authorityHistoryRootKeySpkiSha256"] == root["keySpkiSha256"]
            and manifest["manifestSha256"] == header["authorityHistoryManifestSha256"] == grant["authorityHistoryManifestSha256"])
        authority._key(root).verify(p.decoded(signed["signatureBase64url"], size=64), g._grant_message(g.canonical(grant)))
        selected = p.fields(grant["scope"], g.SCOPE)
        if common is None: common = selected
        else: p.require(selected == common)
        p.require(selected["previousConfigurationBindingSha256"] is None
            and selected["assignmentId"] == assignment["assignmentId"]
            and selected["assignmentPayloadSha256"] == scope["assignmentPayloadSha256"]
            and selected["assignmentRevision"] == scope["assignmentRevision"]
            and selected["successorConfigurationBindingSha256"] == scope["productionConfigurationBindingSha256"])
        for name in ("kernelDriverIdentitySha256", "retainedDescriptorSetSha256", "driverGenerationReceiptSha256"):
            p.require(selected[name] == scope[name])
        for target, source in (("trustedTimeCheckpointSha256", "checkpointId"), ("trustedTimeRevocationGeneration", "revocationGeneration"),
                ("trustedTimeRevocationRootSha256", "revocationRootSha256")):
            p.require(selected[target] == checkpoint[source])
        p.require(p.ns(guest["issuedAtBoottimeNs"]) <= grant["issuedAtBoottimeNanos"] <= scope["issuedAtBoottimeNanos"]
            <= now_boottime_ns < scope["expiresAtBoottimeNanos"] <= grant["expiresAtBoottimeNanos"]
            <= p.ns(guest["lifetimeDeadlineBoottimeNs"])
            and selected["installationIssuedAtUnixNanos"] <= issued_at < expires_at <= selected["installationExpiresAtUnixNanos"])
        deadline = min(deadline, grant["expiresAtBoottimeNanos"])
        epoch_limit = min(epoch_limit, selected["installationExpiresAtUnixNanos"])
    p.require(len(g.canonical(rows)) <= 4 * 1024 * 1024)
    return rows, deadline, epoch_limit
