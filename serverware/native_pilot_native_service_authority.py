"""Closed native pilot operational-grant commands over approved originals.

The whole canonical input and matching supervisor key must be independently
approved. This module reuses existing grant producers; it does not reconstruct
owners, approve observations, verify hardware, create keys/history/genesis, or
renew a deadline. Native consumers still authenticate actual retained resources,
assignment/trust currentness, proof ownership and operational permissions.

Common exact fields are INPUT_FIELDS. All *Original values are literal canonical
ASCII strings. Operation-specific fields are EXTRA_FIELDS. Retrieval requires
the complete real endpointDeliveryResult original from the conductor's prior
endpoint-deliveries intake. Its spoolJournal is consumed, never calculated or
replaced by caller-provided genesis parameters. Independent approval of that
original's provenance remains mandatory; JSON parsing does not establish it.
Explicit Input/v2 is retrieval-only and additionally retains the approved
fresh-ledger manifest. Legacy Input/v1 keeps its existing grant versions.
Input/v3 is the seven retained-history signing endpoints only. Its actual
ordinary C9/runtime/history/generation bundles produce signed ordinaryServices;
CommitRequest additionally verifies an independently approved genuine fleet
startup receipt and its pinned generation trust, never an invented evidence hash.
Retrieval Input/v4 keeps the fresh-ledger output wire, but requires all six new
history-bearing grants and permits their bounded 32-MiB aggregate input.
Input/v5 is persistence-only: it explicitly authorizes the v2 grant's completed
invocation verification permission, under the unchanged 4-MiB input bound.
"""
from __future__ import annotations

import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from serverware import native_pilot_delivery_authority as c9
from serverware import native_pilot_scope_authority as originals
from serverware import native_shadow_nitro_originals as host_originals
from serverware import native_shadow_driver_bootstrap as driver
from serverware import native_shadow_guest_delivery as delivery
from serverware import native_shadow_key_admission_profile as admission
from serverware import native_shadow_commitment_artifacts as commitment
from serverware import native_shadow_persistence_artifacts as persistence
from serverware import native_shadow_retrieval_artifacts as retrieval
from serverware import native_shadow_spool_artifacts as spool
from serverware import native_shadow_trusted_time_inputs as trusted_time
from serverware import custody_spool_inputs as spool_values
from serverware import custody_commitment_inputs as ordinary_commitment
from serverware import custody_generation_grants as generation
from serverware import native_pilot_service_authority as ordinary
from serverware import native_pilot_ordinary_initial_profile as initial

p = delivery.p
MAX_LEGACY_INPUT = 4 * 1024 * 1024
MAX_INPUT = 32 * 1024 * 1024
MAX_LEGACY_OUTPUT = 65536
MAX_OUTPUT = 4 * 1024 * 1024
OPERATIONS = ("ingress", "ledger", "terminal", "dispatchBarrier", "activeEffectBarrier",
    "activeEffectCommit", "retrieval", "commitRequest", "persistence", "trustedTime")
SIGNERS = OPERATIONS[:6]
HISTORY_OPERATIONS = ("commitRequest",) + SIGNERS
HISTORY_INPUT_API = "serverware.nativePilotNativeServiceAuthorityInput/v3"
HISTORY_INPUT_FIELDS = ("ordinaryLaunchOriginal", "services")
EVIDENCE_INPUT_FIELDS = ("runtimeEvidence", "assignmentOriginal")
HISTORY_ROW_FIELDS = ("generationGrantOriginal", "runtimeOriginal", "historyOriginal", "rootKeyId", "rootKeySpkiSha256")
INPUT_FIELDS = ("apiVersion", "operation", "configurationOriginal", "configurationSha256",
    "assignmentPayloadOriginal", "cohortConfigurationOriginal", "precreationOriginal", "observationOriginal",
    "coldConfigurationOriginal", "deliveryOriginal", "runtimeOriginal", "peerOriginal", "peerSha256",
    "issuedAtUnixNanos", "expiresAtUnixNanos")
EXTRA_FIELDS = {
    **{name: ("spoolScopeOriginal", "proofScopeOriginal", "originVerifierOriginal") for name in SIGNERS},
    "ledger": ("spoolScopeOriginal", "proofScopeOriginal", "originVerifierOriginal", "companionPin", "companionOriginal"),
    "retrieval": ("spoolScopeOriginal", "proofScopeOriginal", "endpointDeliveryResultOriginal", "nativeGrantOriginals"),
    "commitRequest": ("commitmentScopeOriginal",),
    "persistence": ("proofScopeOriginal", "genesisOriginal", "journalOriginal", "permissions"),
    "trustedTime": ("bootstrapOriginal",),
}
# Existing payload API, purpose, signature domain. No caller selects a domain.
PROFILES = {
    "ingress": ("serverware.nativeShadowIngressServiceAssignment/v1", "native-first-ingress", "serverware.nativeShadowIngressServiceAssignment.signature/v1"),
    "ledger": ("serverware.nativeShadowLedgerSpoolServiceAssignment/v2", "native-ledger-spool-and-sampling-with-unavailability", "serverware.nativeShadowLedgerSpoolServiceAssignment.signature/v2"),
    "terminal": ("serverware.nativeShadowTerminalSpoolServiceAssignment/v1", "native-terminal-slot-append", "serverware.nativeShadowTerminalSpoolServiceAssignment.signature/v1"),
    "dispatchBarrier": ("serverware.nativeShadowDispatchBarrierServiceAssignment/v1", "native-dispatch-barrier", "serverware.nativeShadowDispatchBarrierServiceAssignment.signature/v1"),
    "activeEffectBarrier": ("serverware.nativeShadowActiveEffectBarrierServiceAssignment/v1", "native-active-effect-barrier", "serverware.nativeShadowActiveEffectBarrierServiceAssignment.signature/v1"),
    "activeEffectCommit": ("serverware.nativeShadowActiveEffectCommitServiceAssignment/v1", "native-active-effect-commit", "serverware.nativeShadowActiveEffectCommitServiceAssignment.signature/v1"),
    "retrieval": ("serverware.nativeLedgerSpoolRetrievalGrant/v3", "native-ledger-spool-retrieval", "serverware.nativeLedgerSpoolRetrievalGrant.signature/v3"),
    "commitRequest": ("serverware.nativeShadowCommitRequestServiceAssignment/v1", "native-shadow-ledger-commit-request", commitment.NATIVE_DOMAIN),
    "persistence": ("serverware.nativeShadowPersistenceServiceAssignment/v1", "native-shadow-receipt-persistence", persistence.GRANT_DOMAIN),
    "trustedTime": ("serverware.nativeShadowTrustedTimeServiceAssignment/v1", "native-shadow-trusted-time-response", trusted_time.GRANT_DOMAIN),
}
HISTORY_PROFILES = {name: (api.rsplit("/v", 1)[0] + "/v" + str(int(api.rsplit("/v", 1)[1]) + 1),
    purpose, domain.rsplit("/v", 1)[0] + "/v" + str(int(domain.rsplit("/v", 1)[1]) + 1))
    for name, (api, purpose, domain) in PROFILES.items() if name in HISTORY_OPERATIONS}
_COMMON_PAYLOAD = tuple(name for name in commitment.HMAC_FIELDS if name != "requestCommitment")
PAYLOAD_FIELDS = {
    **{name: _COMMON_PAYLOAD + ("scope", "proofScopeOriginal", "originVerifier", "expectedPeer", "commitRequest") for name in SIGNERS},
    "retrieval": _COMMON_PAYLOAD + ("proofScopeOriginalBase64url", "expectedPeer", "spoolScope", "ingress", "ledger", "store", "terminal", "effects"),
    "commitRequest": commitment.NATIVE_FIELDS,
    "persistence": _COMMON_PAYLOAD + ("permissions", "proofScopeOriginalBase64url", "journal", "expectedPeer"),
    "trustedTime": _COMMON_PAYLOAD + ("clockBootstrapSha256", "expectedPeer"),
}
FRESH_INPUT_API = "serverware.nativePilotNativeServiceAuthorityInput/v2"
HISTORY_RETRIEVAL_INPUT_API = "serverware.nativePilotNativeServiceAuthorityInput/v4"
COMPLETED_PERSISTENCE_INPUT_API = "serverware.nativePilotNativeServiceAuthorityInput/v5"
FRESH_RETRIEVAL_PROFILE = ("serverware.nativeLedgerSpoolRetrievalGrant/v4",
    "native-ledger-spool-retrieval", "serverware.nativeLedgerSpoolRetrievalGrant.signature/v4")
_ENDPOINT = {"ingress": "ingressAdmission", "ledger": "commitRequest", "terminal": "terminalAppend",
    **{name: name for name in OPERATIONS[3:]}}
_LOCAL_ROLE = {name: spool_values.EFFECT_NATIVE[name][0] for name in SIGNERS + ("retrieval",)}
_LOCAL_ROLE.update(commitRequest="custody-ledger-append", persistence="custody-store-response", trustedTime="custody-trusted-time-response")
_original = originals._original
_same = originals._same


def input_shape(operation, input_original):
    """Select the explicit approved-input profile, without signing or I/O."""
    p.require(operation in OPERATIONS)
    value = p.document(input_original, MAX_INPUT)
    p.require(type(value) is dict)
    history_retrieval = value.get("apiVersion") == HISTORY_RETRIEVAL_INPUT_API
    fresh = history_retrieval or value.get("apiVersion") == FRESH_INPUT_API
    history = value.get("apiVersion") == HISTORY_INPUT_API
    completed = value.get("apiVersion") == COMPLETED_PERSISTENCE_INPUT_API
    p.require(history or history_retrieval or len(input_original) <= MAX_LEGACY_INPUT)
    p.require(not history or operation in HISTORY_OPERATIONS)
    p.require(not fresh or operation == "retrieval")
    p.require(not completed or operation == "persistence")
    p.fields(value, INPUT_FIELDS + EXTRA_FIELDS[operation] + (("retrievalManifestOriginal",) if fresh else ())
        + (HISTORY_INPUT_FIELDS if history else ())
        + (EVIDENCE_INPUT_FIELDS if history and operation == "commitRequest" else ()))
    p.require(value["apiVersion"] == (HISTORY_INPUT_API if history else HISTORY_RETRIEVAL_INPUT_API if history_retrieval
        else FRESH_INPUT_API if fresh else COMPLETED_PERSISTENCE_INPUT_API if completed
        else "serverware.nativePilotNativeServiceAuthorityInput/v1")
        and value["operation"] == operation)
    if fresh:
        manifest_raw, manifest = _original(value["retrievalManifestOriginal"], retrieval.MAX_MANIFEST)
        p.require(retrieval.manifest_initialization(manifest_raw, p.sha(manifest_raw)) == retrieval.FRESH_INITIALIZATION)
        proof_raw, _ = _original(value["proofScopeOriginal"], 16384)
        p.require(p.decoded(manifest["proofScopeOriginalBase64url"], maximum=16384) == proof_raw)
    return value, fresh


def grant_shape(operation, payload):
    """Closed fields and signature domain; never a signature/admission verdict."""
    p.require(operation in OPERATIONS and type(payload) is dict)
    fresh = operation == "retrieval" and payload.get("apiVersion") == FRESH_RETRIEVAL_PROFILE[0]
    history = operation in HISTORY_PROFILES and payload.get("apiVersion") == HISTORY_PROFILES[operation][0]
    completed = operation == "persistence" and payload.get("apiVersion") == persistence.COMPLETED_GRANT_API
    p.fields(payload, PAYLOAD_FIELDS[operation] + (("initialization",) if fresh else ())
        + (("ordinaryServices",) if history else ()))
    api, purpose, domain = (persistence.COMPLETED_GRANT_API, PROFILES[operation][1], persistence.COMPLETED_GRANT_DOMAIN) if completed else (
        HISTORY_PROFILES[operation] if history else FRESH_RETRIEVAL_PROFILE if fresh else PROFILES[operation])
    p.require(payload["apiVersion"] == api and payload["purpose"] == purpose)
    if operation == "persistence":
        persistence.require_permissions(payload["permissions"], completed_invocations=completed)
    if history:
        for row in p.fields(payload["ordinaryServices"], generation.ROLES).values():
            p.fields(row, HISTORY_ROW_FIELDS)
            for name, limit in (("generationGrantOriginal", 65536), ("runtimeOriginal", generation.MAX_BYTES),
                                ("historyOriginal", 1024 * 1024)):
                ordinary._original(row[name], limit)
            p.digest(row["rootKeyId"]); p.digest(row["rootKeySpkiSha256"])
    if fresh:
        proof = retrieval.scope_original(p.decoded(payload["proofScopeOriginalBase64url"], maximum=16384))
        store = p.fields(payload["store"], ("genesisSha256", "sequence", "headSha256"))
        p.digest(store["genesisSha256"])
        p.require(payload["initialization"] == retrieval.FRESH_INITIALIZATION
            and proof.get("api_version") == retrieval.SCOPE_SET_API
            and type(store["sequence"]) is int and store["sequence"] == 0
            and store["headSha256"] == store["genesisSha256"])
        p.fields(payload["effects"], spool_values.EFFECT_KEYS)
        p.require(type(payload["terminal"]) is dict)
    return domain


def grant_original(operation, raw):
    """Closed version-specific bytes/fields only; callers verify authority."""
    signed = p.fields(p.document(raw, MAX_OUTPUT), ("payload", "signature"))
    grant_shape(operation, signed["payload"])
    history = operation in HISTORY_PROFILES and signed["payload"]["apiVersion"] == HISTORY_PROFILES[operation][0]
    p.require(history or len(raw) <= MAX_LEGACY_OUTPUT)
    p.decoded(signed["signature"], size=64)
    return signed


def require_ordinary_member(payload, role, *, runtime_raw, history_raw, generation_raw):
    """Join a successor's signed public member to actual retained originals."""
    if "ordinaryServices" not in payload:
        return
    row = p.fields(p.fields(payload["ordinaryServices"], generation.ROLES)[role], HISTORY_ROW_FIELDS)
    p.require(row["runtimeOriginal"] == runtime_raw.decode("ascii")
        and row["historyOriginal"] == history_raw.decode("ascii")
        and row["generationGrantOriginal"] == generation_raw.decode("ascii"))
    header = generation.document(runtime_raw, generation.MAX_BYTES)["runtime"]
    p.require(row["rootKeyId"] == header["authorityHistoryRootKeyId"]
        and row["rootKeySpkiSha256"] == header["authorityHistoryRootKeySpkiSha256"])


def _endpoint(value, operation, *, boot=None, now_boottime_ns=None):
    """Verify existing C9/window originals, not the observations' provenance."""
    cold_raw, _ = _original(value["coldConfigurationOriginal"], 65536)
    cold = delivery.configuration(cold_raw, p.sha(cold_raw))
    config_raw, _ = _original(value["cohortConfigurationOriginal"], 32768)
    window_raw, signed = _original(value["precreationOriginal"], 32768)
    _, observed = _original(value["observationOriginal"], 32768)
    role = _ENDPOINT[operation]
    if boot is None:
        p.require(now_boottime_ns is None)
        window = c9._endpoint_owner(role, cold, cold_raw, config_raw, window_raw, signed, observed)
    else:
        window = c9.endpoint_owner(role, cold, cold_raw, config_raw, window_raw, signed, observed,
            boot=boot, now=now_boottime_ns)
    _same(cold["authority"], p.document(config_raw, 32768)["authority"])
    delivery_raw, signed = _original(value["deliveryOriginal"], 65536)
    p.fields(signed, ("apiVersion", "payload", "signatureBase64url"))
    p.require(signed["apiVersion"] == "serverware.policyCustodyGuestDelivery/v1")
    payload = p.fields(signed["payload"], delivery.FIELDS)
    p.require(payload["configurationSha256"] == p.sha(cold_raw)
        and payload["authorityKeyId"] == cold["authority"]["keyId"])
    for name in ("serviceRole", "uid", "gid"):
        _same(payload[name], cold[name])
    for name in c9.WINDOW_FIELDS:
        _same(payload[name], window[name])
    runtime_raw, _ = _original(value["runtimeOriginal"], 65536)
    delivery._pin(payload["runtimeConfig"])
    p.require(payload["runtimeConfig"]["sha256"] == p.sha(runtime_raw))
    c9._activation(payload["activation"], c9.ENDPOINTS[role])
    c9._credentials(payload["credentials"], cold["authority"])
    driver._key(cold["authority"]).verify(p.decoded(signed["signatureBase64url"], size=64),
        delivery.DOMAIN + p.canonical(payload))
    return delivery._delivery_guest(payload, delivery_raw), window, observed


def _peer(value, observed, guest):
    raw, _ = _original(value["peerOriginal"], 4096)
    p.require(p.sha(raw) == p.digest(value["peerSha256"]))
    peer = retrieval._peer(raw)
    external = observed["externalDriver"]
    process, executable = external["driver"], external["executable"]
    p.require(peer["uid"] != guest["uid"] and peer["pid"] == process["processId"]
        and peer["startTimeTicks"] == process["startTimeTicks"])
    for target, source in (("executableDevice", "device"), ("executableInode", "inode"),
                           ("executableLength", "length"), ("executableSha256", "sha256")):
        _same(peer[target], executable[source])
    return raw, peer


def _verified_grant(raw, operation, keys, admitted, checkpoint, now, *, fresh_ledger=False,
                    boot=None, now_boottime_ns=None):
    signed = grant_original(operation, raw)
    payload = signed["payload"]
    domain = grant_shape(operation, payload)
    p.require(type(fresh_ledger) is bool and (not fresh_ledger or operation == "retrieval")
        and (payload["apiVersion"] == FRESH_RETRIEVAL_PROFILE[0]) == fresh_ledger)
    supervisor = keys[-1]
    p.require(payload["signingKeyId"] == supervisor["keyId"]
        and payload["signingKeySpkiSha256"] == supervisor["keySpkiSha256"]
        and payload["assignmentPayloadSha256"] == admitted["assignmentPayloadSha256"])
    p.public_key(supervisor).verify(p.decoded(signed["signature"], size=64), p.preimage(domain, payload))
    for target, source in (("trustCheckpointId", "checkpointId"), ("revocationGeneration", "revocationGeneration"),
                           ("revocationRootSha256", "revocationRootSha256")):
        _same(payload[target], checkpoint[source])
    p.freshness(payload["issuedAtUnixNanos"], payload["expiresAtUnixNanos"], now)
    p.guest(payload["guest"])
    if boot is None:
        p.require(now_boottime_ns is None)
        c9._live(payload["guest"])
    else:
        guest = payload["guest"]
        p.require(tuple(guest[name] for name in ("bootIdBase64url", "timeNamespaceDevice", "timeNamespaceInode")) == boot)
        p.require(p.ns(guest["issuedAtBoottimeNs"]) <= now_boottime_ns
            < p.ns(guest["startupDeadlineBoottimeNs"]) < p.ns(guest["lifetimeDeadlineBoottimeNs"]))
    return payload


def _companion(value, keys, admitted, checkpoint, peer, scope, now, *, boot=None, now_boottime_ns=None):
    raw, _ = _original(value["companionOriginal"], MAX_OUTPUT)
    pin = value["companionPin"]
    delivery._pin(pin)
    p.require(pin["sha256"] == p.sha(raw))
    payload = _verified_grant(raw, "commitRequest", keys, admitted, checkpoint, now,
        boot=boot, now_boottime_ns=now_boottime_ns)
    p.require((value["apiVersion"] == HISTORY_INPUT_API)
        == (payload["apiVersion"] == HISTORY_PROFILES["commitRequest"][0]))
    for name in ("guest", "keyAuthorizationSha256"):
        _same(payload[name], admitted[name])
    _same(payload["expectedPeer"], peer)
    companion_scope = commitment.scope_original(p.canonical(payload["scope"]))
    for name in spool_values.SCOPE:
        if name in commitment.SCOPE and name not in ("issuedAtBoottimeNanos", "expiresAtBoottimeNanos"):
            _same(companion_scope[name], scope[name])
    p.require(companion_scope["issuedAtBoottimeNanos"] <= scope["issuedAtBoottimeNanos"]
        < scope["expiresAtBoottimeNanos"] <= companion_scope["expiresAtBoottimeNanos"])
    return pin, payload["expiresAtUnixNanos"]


def ordinary_services(value, scope, peer, guest, *, assignment_id, boot, now_boottime_ns, now_unix_ns):
    """Verify five actual C9/runtime/history/generation chains, not root DTOs."""
    launch_raw = ordinary._original(value["ordinaryLaunchOriginal"], 65536)
    launch, startup, lifetime = ordinary._launch(launch_raw, boot, now_boottime_ns)
    contexts = p.fields(value["services"], generation.ROLES)
    rows, common = {}, None
    uids, gids = {guest["uid"], peer["uid"]}, {guest["gid"], peer["gid"]}
    epoch_limit = (1 << 63) - 1
    for role in generation.ROLES:
        item = ordinary._service(contexts[role], role, launch, boot, startup, lifetime, now_boottime_ns, granted=True)
        p.require(len(item["history_raw"]) <= 1024 * 1024)
        grant, header = item["generation"], item["header"]
        ordinary_commitment._scope_join(scope, grant["scope"])
        p.require(grant["scope"]["previousConfigurationBindingSha256"] is None
            and grant["scope"]["assignmentId"] == assignment_id)
        if common is None:
            common = grant["scope"]
        else:
            _same(common, grant["scope"])
        p.require(grant["issuedAtBoottimeNanos"] <= scope["issuedAtBoottimeNanos"]
            <= now_boottime_ns < scope["expiresAtBoottimeNanos"] <= grant["expiresAtBoottimeNanos"])
        p.freshness(common["installationIssuedAtUnixNanos"], common["installationExpiresAtUnixNanos"], now_unix_ns)
        p.require(common["installationIssuedAtUnixNanos"] <= value["issuedAtUnixNanos"]
            < value["expiresAtUnixNanos"] <= common["installationExpiresAtUnixNanos"])
        epoch_limit = min(epoch_limit, common["installationExpiresAtUnixNanos"])
        _same(header["expectedPeer"], peer)
        p.require(item["guest"]["uid"] not in uids and item["guest"]["gid"] not in gids)
        uids.add(item["guest"]["uid"]); gids.add(item["guest"]["gid"])
        root = initial.runtime_manifest(item["history_raw"], runtime=header, guest=item["guest"])["rootAuthority"]
        rows[role] = {"generationGrantOriginal": item["grant_raw"].decode("ascii"),
            "runtimeOriginal": item["runtime_raw"].decode("ascii"), "historyOriginal": item["history_raw"].decode("ascii"),
            "rootKeyId": root["keyId"], "rootKeySpkiSha256": root["keySpkiSha256"]}
    return rows, startup, epoch_limit


def prepare_service_input(operation, input_original, *, boot, now_boottime_ns, now_unix_ns):
    """Pure purpose-fixed payload for the seven signing endpoints.

    Both legacy and explicit retained-history successors use this same recipe.
    Clocks are supplied by the actual live issuer or a separately retained owner.
    """
    p.require(operation in HISTORY_OPERATIONS)
    p.integer(now_boottime_ns, maximum=p.MAX_U64); p.integer(now_unix_ns)
    value, fresh = input_shape(operation, input_original)
    p.require(not fresh)
    guest, window, observed = _endpoint(value, operation, boot=boot, now_boottime_ns=now_boottime_ns)
    config_raw, config = _original(value["configurationOriginal"], p.MAX_CONFIG)
    p.require(p.sha(config_raw) == p.digest(value["configurationSha256"]))
    admitted, keys = admission.authorization(config, now_unix_ns)
    _same(admitted["guest"], guest)
    p.require(config["authorization"]["payload"]["localRoles"] == [_LOCAL_ROLE[operation]])
    assignment_raw, assignment = _original(value["assignmentPayloadOriginal"], p.MAX_CONFIG)
    p.require(p.sha(assignment_raw) == admitted["assignmentPayloadSha256"]
        and assignment["assignmentRevision"] == admitted["assignmentRevision"])
    _, peer = _peer(value, observed, guest)
    issued, expires = value["issuedAtUnixNanos"], value["expiresAtUnixNanos"]
    payload = commitment._common(config, admitted, keys, issued, expires, now_unix_ns)
    history = value["apiVersion"] == HISTORY_INPUT_API
    api, purpose, domain = HISTORY_PROFILES[operation] if history else PROFILES[operation]
    payload.update(apiVersion=api, purpose=purpose, expectedPeer=peer)
    if operation == "commitRequest":
        scope_raw, _ = _original(value["commitmentScopeOriginal"], 32768)
        scope = commitment.scope_original(scope_raw)
        p.require(scope["assignmentPayloadSha256"] == admitted["assignmentPayloadSha256"]
            and scope["assignmentRevision"] == admitted["assignmentRevision"]
            and scope["requestCommitmentKeyId"] == assignment["observationWindow"]["requestCommitmentKeyId"]
            and scope["requestCommitmentKeyEpoch"] == assignment["observationWindow"]["requestCommitmentKeyEpoch"]
            and p.ns(guest["issuedAtBoottimeNs"]) <= scope["issuedAtBoottimeNanos"]
            and scope["expiresAtBoottimeNanos"] <= p.ns(guest["lifetimeDeadlineBoottimeNs"]))
        payload["scope"] = scope
        if history:
            from serverware import native_pilot_runtime_evidence as evidence
            signed_assignment_raw, signed_assignment = _original(value["assignmentOriginal"], p.MAX_CONFIG)
            _same(signed_assignment["payload"], assignment)
            runtime = evidence.runtime(value["runtimeEvidence"], assignment_original=signed_assignment_raw,
                issued_at_unix_ns=issued, expires_at_unix_ns=expires, now_unix_ns=now_unix_ns)
            _same(scope["runtime"], runtime)
    else:
        scope_raw, _ = _original(value["spoolScopeOriginal"], 16384)
        proof_raw, _ = _original(value["proofScopeOriginal"], 16384)
        scope = spool._scope(scope_raw, proof_raw, admitted, guest, assignment_payload_original=assignment_raw)
        _, origin = _original(value["originVerifierOriginal"], 4096)
        spool.key_live(origin, now_unix_ns)
        p.require(origin["keyId"] not in {key["keyId"] for key in keys} and expires <= origin["notAfterUnixNanos"])
        companion = None
        if operation == "ledger":
            companion, until = _companion(value, keys, admitted, config["trustCheckpoint"], peer, scope, now_unix_ns,
                boot=boot, now_boottime_ns=now_boottime_ns)
            p.require(expires <= until)
        payload.update(scope=scope, proofScopeOriginal=proof_raw.decode("ascii"), originVerifier=origin, commitRequest=companion)
    deadline, epoch_limit = p.ns(window["startupDeadlineBoottimeNs"]), expires
    if history:
        rows, startup, until = ordinary_services(value, scope, peer, guest,
            assignment_id=admitted["assignmentId"], boot=boot,
            now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
        payload["ordinaryServices"] = rows
        if operation == "ledger":
            companion_raw, _ = _original(value["companionOriginal"], MAX_OUTPUT)
            _same(grant_original("commitRequest", companion_raw)["payload"]["ordinaryServices"], rows)
        deadline, epoch_limit = min(deadline, startup), min(epoch_limit, until)
    p.require(now_boottime_ns < deadline and now_unix_ns < epoch_limit)
    p.require(grant_shape(operation, payload) == domain)
    p.require(len(p.canonical(payload)) <= (MAX_OUTPUT if history else MAX_LEGACY_OUTPUT))
    return {"payload": payload, "supervisor": keys[-1], "window": window,
        "deadline": deadline, "epochLimit": epoch_limit, "domain": domain}


def _retrieval_inputs(value, guest, keys, admitted, checkpoint, scope_raw, proof_raw, peer, now,
                      *, boot=None, now_boottime_ns=None):
    _, result = _original(value["endpointDeliveryResultOriginal"], 65536)
    p.fields(result, ("guests", "spoolJournal"))
    guests = p.fields(result["guests"], ("retrieval", "persistence", "trustedTime"))
    for item in guests.values():
        p.guest(item)
        for name in c9.WINDOW_FIELDS:
            _same(item[name], guest[name])
    _same(guests["retrieval"], guest)
    store = p.fields(result["spoolJournal"], ("genesisSha256", "sequence", "headSha256"))
    p.digest(store["genesisSha256"])
    p.require(type(store["sequence"]) is int and store["sequence"] == 0
        and store["headSha256"] == store["genesisSha256"])
    # Consume the actual intake result verbatim. Never compute a genesis from
    # predicted C9 bytes or accept a separate caller-selected store admission.
    scope = p.document(scope_raw, 16384)
    raw_grants = p.fields(value["nativeGrantOriginals"], SIGNERS)
    roles, expiries, history_bundle = {}, [], None
    for operation in SIGNERS:
        raw, _ = _original(raw_grants[operation], MAX_OUTPUT)
        grant = _verified_grant(raw, operation, keys, admitted, checkpoint, now,
            boot=boot, now_boottime_ns=now_boottime_ns)
        expected_api = (HISTORY_PROFILES if value["apiVersion"] == HISTORY_RETRIEVAL_INPUT_API else PROFILES)[operation][0]
        p.require(grant["apiVersion"] == expected_api)
        if value["apiVersion"] == HISTORY_RETRIEVAL_INPUT_API:
            if history_bundle is None:
                history_bundle = grant["ordinaryServices"]
            else:
                _same(history_bundle, grant["ordinaryServices"])
        _same(grant["scope"], scope)
        p.require(grant["proofScopeOriginal"] == proof_raw.decode("ascii"))
        _same(grant["expectedPeer"], peer)
        for name in c9.WINDOW_FIELDS:
            _same(grant["guest"][name], guest[name])
        key = keys[p.ROLES.index(_LOCAL_ROLE[operation])]
        roles[operation] = {name: key[name] for name in ("role", "keyId", "keySpkiSha256", "publicKeyBase64url")}
        roles[operation]["grantSha256"] = p.sha(raw)
        expiries.append(grant["expiresAtUnixNanos"])
    return store, roles, min(expiries)


def prepare_input(operation, input_original, *, boot, now_boottime_ns, now_unix_ns):
    """Pure fixed-operation preparation over complete approved public originals.

    Shares the real issuers' validation, not a second payload implementation.
    Supplied clocks are data; the caller must establish provenance and current
    owner lifetime. This creates no receipt, state, signing or approval owner.
    """
    p.require(operation in OPERATIONS)
    if operation in HISTORY_OPERATIONS:
        return prepare_service_input(operation, input_original, boot=boot,
            now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    p.integer(now_boottime_ns, maximum=p.MAX_U64); p.integer(now_unix_ns)
    value, fresh_ledger = input_shape(operation, input_original)
    guest, window, observed = _endpoint(value, operation, boot=boot, now_boottime_ns=now_boottime_ns)
    now = now_unix_ns
    config_raw, config = _original(value["configurationOriginal"], p.MAX_CONFIG)
    p.require(p.sha(config_raw) == p.digest(value["configurationSha256"]))
    admitted, keys = admission.authorization(config, now)
    checkpoint = config["trustCheckpoint"]
    _same(admitted["guest"], guest)
    p.require(_LOCAL_ROLE[operation] in config["authorization"]["payload"]["localRoles"])
    assignment_raw, assignment = _original(value["assignmentPayloadOriginal"], p.MAX_CONFIG)
    p.require(p.sha(assignment_raw) == admitted["assignmentPayloadSha256"]
        and assignment["assignmentRevision"] == admitted["assignmentRevision"])
    peer_raw, peer = _peer(value, observed, guest)
    issued, expires = value["issuedAtUnixNanos"], value["expiresAtUnixNanos"]
    p.freshness(issued, expires, now)
    p.require(config["authorization"]["payload"]["issuedAtUnixNanos"] <= issued)

    if operation == "retrieval":
        scope_raw, _ = _original(value["spoolScopeOriginal"], 16384)
        proof_raw, _ = _original(value["proofScopeOriginal"], 16384)
        store, role_keys, grant_expiry = _retrieval_inputs(value, guest, keys, admitted, checkpoint,
            scope_raw, proof_raw, peer, now, boot=boot, now_boottime_ns=now_boottime_ns)
        p.require(expires <= grant_expiry)
        payload, supervisor, domain = spool._retrieval_service_payload(configuration_original=config_raw,
            configuration_sha256=value["configurationSha256"], assignment_payload_original=assignment_raw,
            scope_original=scope_raw, proof_scope_original=proof_raw, peer_original=peer_raw,
            ingress_key=role_keys["ingress"], ledger_key=role_keys["ledger"], terminal_key=role_keys["terminal"],
            effects={name: role_keys[name] for name in spool_values.EFFECT_KEYS}, store_admission=store,
            issued_at=issued, expires_at=expires, now=now, completion=True, fresh_ledger=fresh_ledger)
    elif operation == "persistence":
        proof_raw, _ = _original(value["proofScopeOriginal"], 16384)
        genesis_raw, _ = _original(value["genesisOriginal"], 16384)
        journal_raw, _ = _original(value["journalOriginal"], 1024)
        persistence.fresh_originals(genesis_original=genesis_raw, genesis_sha256=p.sha(genesis_raw),
            journal_original=journal_raw, journal_sha256=p.sha(journal_raw), scope_original=proof_raw, guest=guest)
        payload, supervisor = persistence._service_grant_payload(configuration_original=config_raw,
            configuration_sha256=value["configurationSha256"], scope_original=proof_raw, scope_sha256=p.sha(proof_raw),
            peer_original=peer_raw, peer_sha256=value["peerSha256"], guest=guest,
            journal_original=journal_raw, journal_sha256=p.sha(journal_raw), permissions=value["permissions"],
            issued_at=issued, expires_at=expires, now=now,
            assignment_payload_original=assignment_raw,
            completed_invocations=value["apiVersion"] == COMPLETED_PERSISTENCE_INPUT_API)
        domain = persistence.COMPLETED_GRANT_DOMAIN if value["apiVersion"] == COMPLETED_PERSISTENCE_INPUT_API else persistence.GRANT_DOMAIN
    else:
        p.require(operation == "trustedTime")
        bootstrap_raw, _ = _original(value["bootstrapOriginal"], 65536)
        payload, supervisor = trusted_time._service_grant_payload(configuration_original=config_raw,
            configuration_sha256=value["configurationSha256"], bootstrap_original=bootstrap_raw,
            bootstrap_sha256=p.sha(bootstrap_raw), peer_original=peer_raw, peer_sha256=value["peerSha256"],
            issued_at=issued, expires_at=expires, now=now)
        domain = trusted_time.GRANT_DOMAIN

    _same(supervisor, keys[-1]); _same(payload["guest"], guest)
    deadline = p.ns(window["startupDeadlineBoottimeNs"])
    p.require(now_boottime_ns < deadline and now < expires
        and grant_shape(operation, payload) == domain
        and len(p.canonical(payload)) <= MAX_LEGACY_OUTPUT)
    return {"payload": payload, "supervisor": supervisor, "window": window,
        "deadline": deadline, "epochLimit": expires, "domain": domain}


def sign(operation: str, input_original: bytes, signing_key: Ed25519PrivateKey) -> bytes:
    """Sign exactly one selected existing envelope with live pre/post checks."""
    p.require(operation in OPERATIONS and isinstance(signing_key, Ed25519PrivateKey))
    boot, before, now = host_originals._boot(), host_originals._clock(), time.time_ns()
    prepared = prepare_input(operation, input_original, boot=boot,
        now_boottime_ns=before, now_unix_ns=now)
    value, fresh_ledger = input_shape(operation, input_original)
    config_raw, config = _original(value["configurationOriginal"], p.MAX_CONFIG)
    p.require(p.sha(config_raw) == p.digest(value["configurationSha256"]))
    admitted, keys = admission.authorization(config, now)
    _same(prepared["supervisor"], keys[-1])
    public = signing_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    p.require(p.encoded(public) == prepared["supervisor"]["publicKeyBase64url"])
    window, payload = prepared["window"], prepared["payload"]
    latest = time.time_ns()
    p.require(host_originals._boot() == boot and now <= latest < prepared["epochLimit"]
        and c9._live(window, before) < prepared["deadline"])
    admission.authorization(config, latest)
    signature = signing_key.sign(p.preimage(prepared["domain"], payload))
    raw = p.canonical({"payload": payload, "signature": p.encoded(signature)})
    grant_original(operation, raw)

    after = time.time_ns()
    p.require(latest <= after < prepared["epochLimit"] and host_originals._boot() == boot
        and c9._live(window, before) < prepared["deadline"])
    admission.authorization(config, after)
    signed = _verified_grant(raw, operation, keys, admitted, config["trustCheckpoint"], after, fresh_ledger=fresh_ledger)
    _same(signed, payload)
    final_wall = time.time_ns()
    p.require(after <= final_wall < prepared["epochLimit"])
    p.freshness(payload["issuedAtUnixNanos"], payload["expiresAtUnixNanos"], final_wall)
    p.require(c9._live(window, before) < prepared["deadline"])
    return raw
