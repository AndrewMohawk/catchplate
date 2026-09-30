"""Independent initial-install GenerationInstall authority, existing wire only.

The complete input and matching supervisor key must be independently approved.
No owner, peer, key epoch, genesis, journal record, history or deadline is made
here. The initial profile requires SUPPLIED epoch 1/empty predecessors and an
empty supplied journal, plus five authenticated initial-generation grants.
Explicit input/output v2 additionally signs each actual ordinary runtime
original beside its history; the native receiver uses that retained runtime's
history adapter. Legacy v1 keeps four-field members and its 64-KiB output cap.
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
from serverware import native_pilot_ordinary_initial_profile as initial
from serverware import native_pilot_service_authority as ordinary
from serverware import native_shadow_guest_delivery as delivery
from serverware import native_shadow_key_admission_profile as admission
from serverware import native_shadow_nitro_originals as originals
from serverware import native_shadow_retrieval_artifacts as retrieval

p = g.p
MAX_INPUT_BYTES = 32 * 1024 * 1024
MAX_LEGACY_BYTES = 65536
MAX_BYTES = 4 * 1024 * 1024
DOMAIN = "serverware.nativeGenerationCoordinatorAssignment.signature/v1"
HISTORY_DOMAIN = "serverware.nativeGenerationCoordinatorAssignment.signature/v2"
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


def grant_shape(payload):
    p.fields(payload, PAYLOAD_FIELDS)
    history = payload["apiVersion"] == "serverware.nativeGenerationCoordinatorAssignment/v2"
    p.require(payload["apiVersion"] == "serverware.nativeGenerationCoordinatorAssignment/v" + ("2" if history else "1")
        and payload["purpose"] == "native-generation-installation")
    for row in p.fields(payload["services"], g.ROLES).values():
        p.fields(row, ("grantOriginal", "historyOriginal", "rootKeyId", "rootKeySpkiSha256")
            + (("runtimeOriginal",) if history else ()))
        ordinary._original(row["grantOriginal"], MAX_LEGACY_BYTES)
        ordinary._original(row["historyOriginal"], 1024 * 1024)
        p.digest(row["rootKeyId"]); p.digest(row["rootKeySpkiSha256"])
        if history:
            ordinary._original(row["runtimeOriginal"], g.MAX_BYTES)
    return HISTORY_DOMAIN if history else DOMAIN


def grant_original(raw):
    signed = p.fields(p.document(raw, MAX_BYTES), ("payload", "signature"))
    domain = grant_shape(signed["payload"])
    p.require(domain == HISTORY_DOMAIN or len(raw) <= MAX_LEGACY_BYTES)
    p.decoded(signed["signature"], size=64)
    return signed


def _coordinator(value, *, boot, now):
    cold_raw = ordinary._original(value["coordinatorConfigurationOriginal"], MAX_LEGACY_BYTES)
    cold = delivery.configuration(cold_raw, p.sha(cold_raw))
    config_raw = ordinary._original(value["cohortConfigurationOriginal"], 32768)
    window_raw = ordinary._original(value["precreationOriginal"], 32768)
    observed_raw = ordinary._original(value["observationOriginal"], 32768)
    observed = p.document(observed_raw, 32768)
    window = c9.endpoint_owner("generationInstall", cold, cold_raw, config_raw, window_raw,
        p.document(window_raw, 32768), observed, boot=boot, now=now)
    signed_raw = ordinary._original(value["coordinatorDeliveryOriginal"], MAX_LEGACY_BYTES)
    signed = p.fields(p.document(signed_raw, MAX_LEGACY_BYTES), ("apiVersion", "payload", "signatureBase64url"))
    p.require(signed["apiVersion"] == "serverware.policyCustodyGuestDelivery/v1")
    payload = p.fields(signed["payload"], delivery.FIELDS)
    p.require(payload["configurationSha256"] == p.sha(cold_raw)
        and payload["authorityKeyId"] == cold["authority"]["keyId"])
    for name in ("serviceRole", "uid", "gid"):
        _same(payload[name], cold[name])
    for name in c9.WINDOW_FIELDS:
        _same(payload[name], window[name])
    delivery._pin(payload["runtimeConfig"])
    runtime = ordinary._original(value["coordinatorRuntimeOriginal"], MAX_LEGACY_BYTES)
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


def prepare_input(input_original: bytes, *, boot, now_boottime_ns, now_unix_ns):
    """Pure verification of complete public originals at explicit caller clocks.

    This does not establish their kernel provenance or authorize a signature.
    The live signer below supplies its actual clocks and independently held key.
    """
    now, wall = now_boottime_ns, now_unix_ns
    p.integer(now, maximum=p.MAX_U64); p.integer(wall)
    value = p.fields(p.document(input_original, MAX_INPUT_BYTES), INPUT_FIELDS)
    history = value["apiVersion"] == "serverware.nativePilotGenerationInstallAuthorityInput/v2"
    p.require(value["apiVersion"] == "serverware.nativePilotGenerationInstallAuthorityInput/v" + ("2" if history else "1"))
    payload_raw = ordinary._original(value["payloadOriginal"], MAX_BYTES)
    payload = p.fields(p.document(payload_raw, MAX_BYTES), PAYLOAD_FIELDS)
    domain = grant_shape(payload)
    p.require(history == (domain == HISTORY_DOMAIN) and (history or len(payload_raw) <= MAX_LEGACY_BYTES))
    guest, window, observed = _coordinator(value, boot=boot, now=now)
    _same(payload["guest"], guest)
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
    p.require(payload["signingKeyId"] == supervisor["keyId"]
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
    launch_raw = ordinary._original(value["ordinaryLaunchOriginal"], MAX_LEGACY_BYTES)
    launch, startup, lifetime = ordinary._launch(launch_raw, boot, now)
    contexts = p.fields(value["services"], g.ROLES)
    members = p.fields(payload["services"], g.ROLES)
    deadline = min(startup, p.ns(window["startupDeadlineBoottimeNs"]))
    scopes, uids, gids = [], {guest["uid"], peer["uid"]}, {guest["gid"], peer["gid"]}
    for role in g.ROLES:
        item = ordinary._service(contexts[role], role, launch, boot, startup, lifetime, now, granted=True)
        member = members[role]
        p.require(member["grantOriginal"] == item["grant_raw"].decode("ascii")
            and member["historyOriginal"] == item["history_raw"].decode("ascii")
            and len(item["history_raw"]) <= 1024 * 1024)
        if history:
            p.require(member["runtimeOriginal"] == item["runtime_raw"].decode("ascii"))
        root = initial.runtime_manifest(item["history_raw"], runtime=item["header"],
            guest=item["guest"])["rootAuthority"]
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
    p.require(now < deadline and wall < epoch_limit)
    return {"payload": payload, "supervisor": supervisor, "window": window,
        "deadline": deadline, "epochLimit": epoch_limit, "domain": domain}


def sign(*, input_original: bytes, signing_key):
    """Sign one independently approved existing input; return its original bound.

    services retains all five real service bundles. Explicit initial keyHistory,
    genesisOriginal and empty recordOriginals are required, never defaulted.
    No caller clock, signing domain, owner or private key is synthesized.
    """
    p.require(isinstance(signing_key, Ed25519PrivateKey))
    boot, now, wall = originals._boot(), originals._clock(), time.time_ns()
    prepared = prepare_input(input_original, boot=boot, now_boottime_ns=now, now_unix_ns=wall)
    payload, supervisor, window = (prepared[name] for name in ("payload", "supervisor", "window"))
    deadline, epoch_limit = prepared["deadline"], prepared["epochLimit"]
    public = signing_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    p.require(p.encoded(public) == supervisor["publicKeyBase64url"] and originals._boot() == boot)
    before_boot, before_wall = _live(window, payload, deadline=deadline, epoch_limit=epoch_limit,
                                    previous_boot=now, previous_wall=wall)
    message = p.preimage(prepared["domain"], payload)
    signature = signing_key.sign(message)
    p.public_key(supervisor).verify(signature, message)
    raw = p.canonical({"payload": payload, "signature": p.encoded(signature)})
    grant_original(raw)
    p.require(originals._boot() == boot)
    _live(window, payload, deadline=deadline, epoch_limit=epoch_limit,
          previous_boot=before_boot, previous_wall=before_wall)
    return raw, deadline
