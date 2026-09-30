"""Independent initial-install GenerationInstall authority, existing wire only.

The complete input and matching supervisor key must be independently approved.
No owner, peer, key epoch, genesis, journal record, history or deadline is made
here. The initial profile requires SUPPLIED epoch 1/empty predecessors and an
empty supplied journal, plus five authenticated initial-generation grants.
Historical installation/recovery authoring is deliberately unsupported; the
existing native historical verifier and all full-project gates are unchanged.

Checks below authenticate public originals and their associations, not live
descriptors, Nitro evidence, historical-chain currentness or installed effects.
Those remain the actual native receivers' duties. An external watchdog must
bound blocking original-file/cryptographic work in the command-line caller.
"""
from __future__ import annotations

import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from serverware import custody_generation_grants as g
from serverware import native_pilot_delivery_authority as c9
from serverware import native_pilot_service_authority as ordinary
from serverware import native_shadow_guest_delivery as delivery
from serverware import native_shadow_key_admission_profile as admission
from serverware import native_shadow_nitro_originals as originals
from serverware import native_shadow_retrieval_artifacts as retrieval

p = g.p
MAX_INPUT_BYTES = 32 * 1024 * 1024
MAX_BYTES = 65536
DOMAIN = "serverware.nativeGenerationCoordinatorAssignment.signature/v1"
PAYLOAD_FIELDS = ("apiVersion", "purpose", "guest", "assignmentPayloadSha256",
    "keyAuthorizationSha256", "services", "keyHistory", "journal", "expectedPeer",
    "trustCheckpointId", "revocationGeneration", "revocationRootSha256",
    "issuedAtUnixNanos", "expiresAtUnixNanos", "signingKeyId", "signingKeySpkiSha256")
INPUT_FIELDS = ("apiVersion", "payloadOriginal", "nativeConfigurationOriginal",
    "nativeConfigurationSha256", "assignmentPayloadOriginal", "cohortConfigurationOriginal",
    "precreationOriginal", "observationOriginal", "coordinatorConfigurationOriginal",
    "coordinatorDeliveryOriginal", "coordinatorRuntimeOriginal", "ordinaryLaunchOriginal",
    "services", "genesisOriginal", "recordOriginals")


def _same(first, second):
    p.require(g.canonical(first) == g.canonical(second))


def _coordinator(value):
    cold_raw = ordinary._original(value["coordinatorConfigurationOriginal"], MAX_BYTES)
    cold = delivery.configuration(cold_raw, p.sha(cold_raw))
    config_raw = ordinary._original(value["cohortConfigurationOriginal"], 32768)
    window_raw = ordinary._original(value["precreationOriginal"], 32768)
    observed_raw = ordinary._original(value["observationOriginal"], 32768)
    observed = p.document(observed_raw, 32768)
    window = c9._endpoint_owner("generationInstall", cold, cold_raw, config_raw, window_raw,
        p.document(window_raw, 32768), observed)
    signed_raw = ordinary._original(value["coordinatorDeliveryOriginal"], MAX_BYTES)
    signed = p.fields(p.document(signed_raw, MAX_BYTES), ("apiVersion", "payload", "signatureBase64url"))
    p.require(signed["apiVersion"] == "serverware.policyCustodyGuestDelivery/v1")
    payload = p.fields(signed["payload"], delivery.FIELDS)
    p.require(payload["configurationSha256"] == p.sha(cold_raw)
        and payload["authorityKeyId"] == cold["authority"]["keyId"])
    for name in ("serviceRole", "uid", "gid"):
        _same(payload[name], cold[name])
    for name in c9.WINDOW_FIELDS:
        _same(payload[name], window[name])
    delivery._pin(payload["runtimeConfig"])
    runtime = ordinary._original(value["coordinatorRuntimeOriginal"], MAX_BYTES)
    p.require(payload["runtimeConfig"]["sha256"] == p.sha(runtime))
    c9._activation(payload["activation"], c9.ENDPOINTS["generationInstall"])
    c9._credentials(payload["credentials"], cold["authority"])
    key = Ed25519PublicKey.from_public_bytes(p.decoded(cold["authority"]["publicKeyBase64url"], size=32))
    key.verify(p.decoded(signed["signatureBase64url"], size=64), delivery.DOMAIN + p.canonical(payload))
    return delivery._delivery_guest(payload, signed_raw), window, observed


def _peer(payload, observed, guest):
    peer = retrieval._peer(p.canonical(payload["expectedPeer"]))
    external = observed["externalDriver"]
    process, executable = external["driver"], external["executable"]
    p.require(peer["uid"] != guest["uid"] and peer["pid"] == process["processId"]
        and peer["startTimeTicks"] == process["startTimeTicks"])
    for target, source in (("executableDevice", "device"), ("executableInode", "inode"),
                           ("executableLength", "length"), ("executableSha256", "sha256")):
        _same(peer[target], executable[source])
    return peer


def _journal(value, payload, guest):
    # No restored effect record is silently treated as an initial installation.
    p.require(type(value["recordOriginals"]) is list and value["recordOriginals"] == [])
    history = p.fields(payload["keyHistory"], ("currentKeyEpoch", "predecessors"))
    p.require(type(history["currentKeyEpoch"]) is int and history["currentKeyEpoch"] == 1
        and type(history["predecessors"]) is list and history["predecessors"] == [])
    raw = ordinary._original(value["genesisOriginal"], 512 * 1024)
    genesis = p.fields(p.document(raw, 512 * 1024),
        ("apiVersion", "guest", "assignmentPayloadSha256", "servicesSha256"))
    p.require(genesis["apiVersion"] == "serverware.nativeGenerationCoordinatorGenesis/v1"
        and genesis["assignmentPayloadSha256"] == payload["assignmentPayloadSha256"]
        and genesis["servicesSha256"] == p.sha(p.canonical(payload["services"])))
    _same(genesis["guest"], guest)
    journal = p.fields(payload["journal"], ("genesisSha256", "sequence", "headSha256"))
    p.require(type(journal["sequence"]) is int and journal["sequence"] == 0
        and journal["headSha256"] == journal["genesisSha256"] == p.sha(raw))


def _live(window, payload, *, deadline, epoch_limit, previous_boot, previous_wall):
    now = c9._live(window, previous_boot)
    wall = time.time_ns()
    p.require(now < deadline and previous_wall <= wall < epoch_limit)
    p.freshness(payload["issuedAtUnixNanos"], payload["expiresAtUnixNanos"], wall)
    return now, wall


def sign(*, input_original: bytes, signing_key):
    """Return (unchanged existing signed-envelope bytes, original deadline).

    INPUT_FIELDS is the closed input object for
    serverware.nativePilotGenerationInstallAuthorityInput/v1. All *Original
    values are literal canonical ASCII strings. services is the fixed-five map
    of the existing ordinary authority's checked service bundles, including
    generationGrantOriginal. recordOriginals MUST be an explicitly supplied [];
    keyHistory and journal MUST be the supplied initial values, never defaults.
    No caller-selected clock, output payload construction or alternate domain.
    """
    p.require(isinstance(signing_key, Ed25519PrivateKey))
    value = p.fields(p.document(input_original, MAX_INPUT_BYTES), INPUT_FIELDS)
    p.require(value["apiVersion"] == "serverware.nativePilotGenerationInstallAuthorityInput/v1")
    payload_raw = ordinary._original(value["payloadOriginal"], MAX_BYTES)
    payload = p.fields(p.document(payload_raw, MAX_BYTES), PAYLOAD_FIELDS)
    p.require(payload["apiVersion"] == "serverware.nativeGenerationCoordinatorAssignment/v1"
        and payload["purpose"] == "native-generation-installation")
    guest, window, observed = _coordinator(value)
    _same(payload["guest"], guest)
    boot, now, wall = originals._boot(), originals._clock(), time.time_ns()
    native_raw = ordinary._original(value["nativeConfigurationOriginal"], p.MAX_CONFIG)
    p.require(p.sha(native_raw) == p.digest(value["nativeConfigurationSha256"]))
    native = p.document(native_raw, p.MAX_CONFIG)
    admitted, keys = admission.authorization(native, wall)
    _same(admitted["guest"], guest)
    p.require("custody-result-envelope" in native["authorization"]["payload"]["localRoles"])
    assignment_raw = ordinary._original(value["assignmentPayloadOriginal"], g.MAX_BYTES)
    assignment = g.document(assignment_raw, g.MAX_BYTES)
    p.integer(assignment["assignmentRevision"], maximum=p.MAX_U64)
    p.require(p.sha(assignment_raw) == admitted["assignmentPayloadSha256"]
        and assignment["assignmentId"] == admitted["assignmentId"]
        and assignment["assignmentRevision"] == admitted["assignmentRevision"]
        and payload["assignmentPayloadSha256"] == admitted["assignmentPayloadSha256"]
        and payload["keyAuthorizationSha256"] == admitted["keyAuthorizationSha256"])
    supervisor = keys[p.ROLES.index("custody-supervisor-capability")]
    public = signing_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    p.require(p.encoded(public) == supervisor["publicKeyBase64url"]
        and payload["signingKeyId"] == supervisor["keyId"]
        and payload["signingKeySpkiSha256"] == supervisor["keySpkiSha256"])
    checkpoint = native["trustCheckpoint"]
    for field, source in (("trustCheckpointId", "checkpointId"),
                          ("revocationGeneration", "revocationGeneration"), ("revocationRootSha256", "revocationRootSha256")):
        _same(payload[field], checkpoint[source])
    p.freshness(payload["issuedAtUnixNanos"], payload["expiresAtUnixNanos"], wall)
    epoch_limit = min(native[name]["payload"]["expiresAtUnixNanos"]
                      for name in ("authorization", "admissionAuthorization"))
    p.require(payload["expiresAtUnixNanos"] <= epoch_limit)
    peer = _peer(payload, observed, guest)
    launch_raw = ordinary._original(value["ordinaryLaunchOriginal"], MAX_BYTES)
    launch, startup, lifetime = ordinary._launch(launch_raw, boot, now)
    contexts = p.fields(value["services"], g.ROLES)
    members = p.fields(payload["services"], g.ROLES)
    deadline = min(startup, p.ns(window["startupDeadlineBoottimeNs"]))
    scopes, uids, gids = [], {guest["uid"], peer["uid"]}, {guest["gid"], peer["gid"]}
    for role in g.ROLES:
        item = ordinary._service(contexts[role], role, launch, boot, startup, lifetime, now, granted=True)
        member = p.fields(members[role], ("grantOriginal", "historyOriginal", "rootKeyId", "rootKeySpkiSha256"))
        p.require(member["grantOriginal"] == item["grant_raw"].decode("ascii")
            and member["historyOriginal"] == item["history_raw"].decode("ascii")
            and len(item["history_raw"]) <= 1024 * 1024)
        root = g.document(item["history_raw"], g.MAX_BYTES)["rootAuthority"]
        p.require(member["rootKeyId"] == root["keyId"] and member["rootKeySpkiSha256"] == root["keySpkiSha256"])
        _same(item["header"]["expectedPeer"], peer)
        p.require(item["guest"]["uid"] not in uids and item["guest"]["gid"] not in gids)
        uids.add(item["guest"]["uid"]); gids.add(item["guest"]["gid"])
        scope = item["generation"]["scope"]
        p.require(scope["previousConfigurationBindingSha256"] is None
            and scope["assignmentId"] == admitted["assignmentId"]
            and scope["assignmentPayloadSha256"] == admitted["assignmentPayloadSha256"]
            and scope["assignmentRevision"] == admitted["assignmentRevision"])
        scopes.append(scope)
        deadline = min(deadline, item["generation"]["expiresAtBoottimeNanos"])
    for scope in scopes[1:]:
        _same(scope, scopes[0])
    scope = scopes[0]
    p.freshness(scope["installationIssuedAtUnixNanos"], scope["installationExpiresAtUnixNanos"], wall)
    epoch_limit = min(epoch_limit, scope["installationExpiresAtUnixNanos"])
    p.require(payload["expiresAtUnixNanos"] <= epoch_limit)
    _journal(value, payload, guest)
    before_boot, before_wall = _live(window, payload, deadline=deadline, epoch_limit=epoch_limit,
                                    previous_boot=now, previous_wall=wall)
    message = p.preimage(DOMAIN, payload)
    signature = signing_key.sign(message)
    p.public_key(supervisor).verify(signature, message)
    raw = p.canonical({"payload": payload, "signature": p.encoded(signature)})
    p.require(len(raw) <= MAX_BYTES and originals._boot() == boot)
    _live(window, payload, deadline=deadline, epoch_limit=epoch_limit,
          previous_boot=before_boot, previous_wall=before_wall)
    return raw, deadline
