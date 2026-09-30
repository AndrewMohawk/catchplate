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
"""
from __future__ import annotations

import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from serverware import native_pilot_delivery_authority as c9
from serverware import native_pilot_scope_authority as originals
from serverware import native_shadow_driver_bootstrap as driver
from serverware import native_shadow_guest_delivery as delivery
from serverware import native_shadow_key_admission_profile as admission
from serverware import native_shadow_commitment_artifacts as commitment
from serverware import native_shadow_persistence_artifacts as persistence
from serverware import native_shadow_retrieval_artifacts as retrieval
from serverware import native_shadow_spool_artifacts as spool
from serverware import native_shadow_trusted_time_inputs as trusted_time
from serverware import custody_spool_inputs as spool_values

p = delivery.p
MAX_INPUT = 4 * 1024 * 1024
MAX_OUTPUT = 65536
OPERATIONS = ("ingress", "ledger", "terminal", "dispatchBarrier", "activeEffectBarrier",
    "activeEffectCommit", "retrieval", "commitRequest", "persistence", "trustedTime")
SIGNERS = OPERATIONS[:6]
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
_COMMON_PAYLOAD = tuple(name for name in commitment.HMAC_FIELDS if name != "requestCommitment")
PAYLOAD_FIELDS = {
    **{name: _COMMON_PAYLOAD + ("scope", "proofScopeOriginal", "originVerifier", "expectedPeer", "commitRequest") for name in SIGNERS},
    "retrieval": _COMMON_PAYLOAD + ("proofScopeOriginalBase64url", "expectedPeer", "spoolScope", "ingress", "ledger", "store", "terminal", "effects"),
    "commitRequest": commitment.NATIVE_FIELDS,
    "persistence": _COMMON_PAYLOAD + ("permissions", "proofScopeOriginalBase64url", "journal", "expectedPeer"),
    "trustedTime": _COMMON_PAYLOAD + ("clockBootstrapSha256", "expectedPeer"),
}
_ENDPOINT = {"ingress": "ingressAdmission", "ledger": "commitRequest", "terminal": "terminalAppend",
    **{name: name for name in OPERATIONS[3:]}}
_LOCAL_ROLE = {name: spool_values.EFFECT_NATIVE[name][0] for name in SIGNERS + ("retrieval",)}
_LOCAL_ROLE.update(commitRequest="custody-ledger-append", persistence="custody-store-response", trustedTime="custody-trusted-time-response")
_original = originals._original
_same = originals._same


def _endpoint(value, operation):
    """Verify existing C9/window originals, not the observations' provenance."""
    cold_raw, _ = _original(value["coldConfigurationOriginal"], 65536)
    cold = delivery.configuration(cold_raw, p.sha(cold_raw))
    config_raw, _ = _original(value["cohortConfigurationOriginal"], 32768)
    window_raw, signed = _original(value["precreationOriginal"], 32768)
    _, observed = _original(value["observationOriginal"], 32768)
    role = _ENDPOINT[operation]
    window = c9._endpoint_owner(role, cold, cold_raw, config_raw, window_raw, signed, observed)
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


def _verified_grant(raw, operation, keys, admitted, checkpoint, now):
    signed = p.fields(p.document(raw, MAX_OUTPUT), ("payload", "signature"))
    payload = p.fields(signed["payload"], PAYLOAD_FIELDS[operation])
    api, purpose, domain = PROFILES[operation]
    supervisor = keys[-1]
    p.require(payload["apiVersion"] == api and payload["purpose"] == purpose
        and payload["signingKeyId"] == supervisor["keyId"]
        and payload["signingKeySpkiSha256"] == supervisor["keySpkiSha256"]
        and payload["assignmentPayloadSha256"] == admitted["assignmentPayloadSha256"])
    p.public_key(supervisor).verify(p.decoded(signed["signature"], size=64), p.preimage(domain, payload))
    for target, source in (("trustCheckpointId", "checkpointId"), ("revocationGeneration", "revocationGeneration"),
                           ("revocationRootSha256", "revocationRootSha256")):
        _same(payload[target], checkpoint[source])
    p.freshness(payload["issuedAtUnixNanos"], payload["expiresAtUnixNanos"], now)
    p.guest(payload["guest"])
    c9._live(payload["guest"])
    return payload


def _companion(value, keys, admitted, checkpoint, peer, scope, now):
    raw, _ = _original(value["companionOriginal"], MAX_OUTPUT)
    pin = value["companionPin"]
    delivery._pin(pin)
    p.require(pin["sha256"] == p.sha(raw))
    payload = _verified_grant(raw, "commitRequest", keys, admitted, checkpoint, now)
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


def _retrieval_inputs(value, guest, keys, admitted, checkpoint, scope_raw, proof_raw, peer, now):
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
    roles, expiries = {}, []
    for operation in SIGNERS:
        raw, _ = _original(raw_grants[operation], MAX_OUTPUT)
        grant = _verified_grant(raw, operation, keys, admitted, checkpoint, now)
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


def sign(operation: str, input_original: bytes, signing_key: Ed25519PrivateKey) -> bytes:
    """Sign exactly one selected existing native service envelope."""
    p.require(operation in OPERATIONS and isinstance(signing_key, Ed25519PrivateKey))
    value = p.fields(p.document(input_original, MAX_INPUT), INPUT_FIELDS + EXTRA_FIELDS[operation])
    p.require(value["apiVersion"] == "serverware.nativePilotNativeServiceAuthorityInput/v1"
        and value["operation"] == operation)
    guest, window, observed = _endpoint(value, operation)
    before = c9._live(window)
    now = time.time_ns()
    config_raw, config = _original(value["configurationOriginal"], p.MAX_CONFIG)
    p.require(p.sha(config_raw) == p.digest(value["configurationSha256"]))
    admitted, keys = admission.authorization(config, now)
    checkpoint = config["trustCheckpoint"]
    _same(admitted["guest"], guest)
    p.require(_LOCAL_ROLE[operation] in config["authorization"]["payload"]["localRoles"])
    public = signing_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    p.require(p.encoded(public) == keys[-1]["publicKeyBase64url"])
    assignment_raw, assignment = _original(value["assignmentPayloadOriginal"], p.MAX_CONFIG)
    p.require(p.sha(assignment_raw) == admitted["assignmentPayloadSha256"]
        and assignment["assignmentRevision"] == admitted["assignmentRevision"])
    peer_raw, peer = _peer(value, observed, guest)
    issued, expires = value["issuedAtUnixNanos"], value["expiresAtUnixNanos"]
    p.freshness(issued, expires, now)
    p.require(config["authorization"]["payload"]["issuedAtUnixNanos"] <= issued)

    if operation in SIGNERS:
        scope_raw, _ = _original(value["spoolScopeOriginal"], 16384)
        proof_raw, _ = _original(value["proofScopeOriginal"], 16384)
        _, origin = _original(value["originVerifierOriginal"], 4096)
        actual_scope = spool._scope(scope_raw, proof_raw, admitted, guest, assignment_payload_original=assignment_raw)
        p.require(expires <= p.integer(origin["notAfterUnixNanos"]))
        if operation == "ledger":
            pin, companion_expiry = _companion(value, keys, admitted, checkpoint, peer, actual_scope, now)
            p.require(expires <= companion_expiry)
            raw = spool.sign_completion_ledger_service(configuration_original=config_raw,
                configuration_sha256=value["configurationSha256"], assignment_payload_original=assignment_raw,
                scope_original=scope_raw, proof_scope_original=proof_raw, origin_verifier=origin,
                peer_original=peer_raw, companion_pin=pin, issued_at=issued, expires_at=expires,
                now=now, signing_key=signing_key)
        else:
            producer = {"ingress": spool.sign_ingress_service, "terminal": spool.sign_terminal_service,
                "dispatchBarrier": spool.sign_dispatch_barrier_service,
                "activeEffectBarrier": spool.sign_active_effect_barrier_service,
                "activeEffectCommit": spool.sign_active_effect_commit_service}[operation]
            raw = producer(configuration_original=config_raw, configuration_sha256=value["configurationSha256"],
                assignment_payload_original=assignment_raw, scope_original=scope_raw, proof_scope_original=proof_raw,
                origin_verifier=origin, peer_original=peer_raw, issued_at=issued, expires_at=expires,
                now=now, signing_key=signing_key)
    elif operation == "retrieval":
        scope_raw, _ = _original(value["spoolScopeOriginal"], 16384)
        proof_raw, _ = _original(value["proofScopeOriginal"], 16384)
        store, role_keys, grant_expiry = _retrieval_inputs(value, guest, keys, admitted, checkpoint, scope_raw, proof_raw, peer, now)
        p.require(expires <= grant_expiry)
        raw = spool.sign_effects_retrieval_service(configuration_original=config_raw,
            configuration_sha256=value["configurationSha256"], assignment_payload_original=assignment_raw,
            scope_original=scope_raw, proof_scope_original=proof_raw, peer_original=peer_raw,
            ingress_key=role_keys["ingress"], ledger_key=role_keys["ledger"], terminal_key=role_keys["terminal"],
            effects={name: role_keys[name] for name in spool_values.EFFECT_KEYS}, store_admission=store,
            issued_at=issued, expires_at=expires, now=now, signing_key=signing_key)
    elif operation == "commitRequest":
        scope_raw, _ = _original(value["commitmentScopeOriginal"], 32768)
        raw = commitment.sign_native_service(configuration_original=config_raw,
            configuration_sha256=value["configurationSha256"], assignment_payload_original=assignment_raw,
            scope_original_bytes=scope_raw, scope_sha256=p.sha(scope_raw), peer_original=peer_raw,
            peer_sha256=value["peerSha256"], issued_at=issued, expires_at=expires, now=now, signing_key=signing_key)
    elif operation == "persistence":
        proof_raw, _ = _original(value["proofScopeOriginal"], 16384)
        genesis_raw, _ = _original(value["genesisOriginal"], 16384)
        journal_raw, _ = _original(value["journalOriginal"], 1024)
        persistence.fresh_originals(genesis_original=genesis_raw, genesis_sha256=p.sha(genesis_raw),
            journal_original=journal_raw, journal_sha256=p.sha(journal_raw), scope_original=proof_raw, guest=guest)
        raw = persistence.sign_service_grant(configuration_original=config_raw,
            configuration_sha256=value["configurationSha256"], scope_original=proof_raw, scope_sha256=p.sha(proof_raw),
            peer_original=peer_raw, peer_sha256=value["peerSha256"], guest=guest,
            journal_original=journal_raw, journal_sha256=p.sha(journal_raw), permissions=value["permissions"],
            issued_at=issued, expires_at=expires, now=now, signing_key=signing_key,
            assignment_payload_original=assignment_raw)
    else:
        p.require(operation == "trustedTime")
        bootstrap_raw, _ = _original(value["bootstrapOriginal"], 65536)
        raw = trusted_time.sign_service_grant(configuration_original=config_raw,
            configuration_sha256=value["configurationSha256"], bootstrap_original=bootstrap_raw,
            bootstrap_sha256=p.sha(bootstrap_raw), peer_original=peer_raw, peer_sha256=value["peerSha256"],
            issued_at=issued, expires_at=expires, now=now, signing_key=signing_key)

    after = time.time_ns()
    p.require(now <= after)
    c9._live(window, before)
    admission.authorization(config, after)
    signed = _verified_grant(raw, operation, keys, admitted, checkpoint, after)
    _same(signed["guest"], guest)
    p.require(signed["issuedAtUnixNanos"] == issued and signed["expiresAtUnixNanos"] == expires)
    return raw
