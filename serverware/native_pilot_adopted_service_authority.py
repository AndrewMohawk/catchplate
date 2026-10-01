"""Explicit operational grants under an independently signed cold adoption.

The supervisor's exact adoption signature is authority, not a caller's validator
result. Its current assignment, trust, histories, C9 originals and all retained
intervals are joined before selecting the signing key. Native consumers still
validate the complete cold chain and actual resources. This module neither
creates a baseline nor re-signs it under current keys.
"""
from __future__ import annotations

import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from serverware import custody_generation_grants as g
from serverware import native_pilot_adopted_ordinary as ordinary
from serverware import native_pilot_adopted_delivery as adopted_c9
from serverware import native_pilot_assignment as assignments
from serverware import native_pilot_closure_set as closure_set
from serverware import native_pilot_delivery_authority as c9
from serverware import native_pilot_measured_configuration as measured
from serverware import native_pilot_publication_adoption_profile as adoption_profile
from serverware import native_shadow_key_admission_profile as admission
from serverware import native_shadow_nitro_originals as host
from serverware import native_shadow_nitro_profile as p
from serverware import native_shadow_persistence_artifacts as persistence
from serverware import native_shadow_retrieval_artifacts as retrieval
from serverware import native_shadow_spool_artifacts as spool

INPUT_API = "serverware.nativePilotNativeServiceAuthorityInput/v6"
MAX_INPUT = 32 * 1024 * 1024
PROFILES = {
    "publication": ("serverware.nativePublicationServiceAssignment/v2", "native-policy-publication-reconciliation",
        "serverware.nativePublicationServiceAssignment.signature/v2", 4 * 1024 * 1024),
    "retrieval": ("serverware.nativeLedgerSpoolRetrievalGrant/v6", "native-ledger-spool-retrieval",
        "serverware.nativeLedgerSpoolRetrievalGrant.signature/v6", 3 * 1024 * 1024),
    "persistence": ("serverware.nativeShadowPersistenceServiceAssignment/v4", "native-shadow-receipt-persistence",
        "serverware.nativeShadowPersistenceServiceAssignment.signature/v4", 3 * 1024 * 1024),
}
ROLES = {"publication": "publicationReconciliation", "retrieval": "retrieval", "persistence": "persistence"}
LOCAL_ROLES = {"publication": "custody-publication-reconciliation", "retrieval": "custody-retrieval-response", "persistence": "custody-store-response"}
COMMON = ("apiVersion", "operation", "configurationOriginal", "configurationSha256", "deliveryInputOriginal", "deliveryOriginal",
    "adoptionValidationInputOriginal", "adoptionAuthorizationOriginal", "peerOriginal", "peerSha256", "issuedAtUnixNanos", "expiresAtUnixNanos")
EXTRA = {
    "publication": ("retrievalDeliveryInputOriginal", "retrievalDeliveryOriginal", "spoolScopeOriginal", "firstIngressSequence", "lastIngressSequence", "ordinaryServices"),
    "retrieval": ("spoolScopeOriginal", "endpointDeliveryResultOriginal", "nativeGrantOriginals", "publicationGrantOriginal"),
    "persistence": ("genesisOriginal", "journalOriginal", "permissions"),
}
BASE = ("apiVersion", "purpose", "guest", "assignmentPayloadSha256", "keyAuthorizationSha256", "expectedPeer",
    "trustCheckpointId", "revocationGeneration", "revocationRootSha256", "issuedAtUnixNanos", "expiresAtUnixNanos", "signingKeyId", "signingKeySpkiSha256")
PAYLOAD = {
    "publication": BASE + ("admission", "retrieval", "retrievalGuest", "ordinaryServices"),
    "retrieval": BASE + ("proofScopeOriginalBase64url", "spoolScope", "ingress", "ledger", "store", "terminal", "effects", "initialization", "publication"),
    "persistence": BASE + ("permissions", "proofScopeOriginalBase64url", "journal", "adoption"),
}
PERMISSIONS = ["store-dispatch-original", "verify-persistence", "verify-completed-invocation", "verify-publication-invocation"]
MAX_AGE = 300_000_000_000


def original(value, maximum):
    p.require(type(value) is str and value.isascii() and 0 < len(value) <= maximum)
    raw = value.encode("ascii")
    # Literal C9 and unsigned source JSON preserve native u64 metadata. Larger
    # wrappers contain those originals as strings; signed payloads are still
    # checked with the native signed-i64 canonicalizer before key selection.
    return raw, g.document(raw, min(maximum, g.MAX_BYTES)) if len(raw) <= g.MAX_BYTES else p.document(raw, maximum)


def input_document(operation, raw):
    p.require(operation in PROFILES)
    value = p.fields(p.document(raw, MAX_INPUT), COMMON + EXTRA[operation])
    p.require(value["apiVersion"] == INPUT_API and value["operation"] == operation)
    return value


def _public(value):
    return {name: value[name] for name in ("keyId", "keySpkiSha256", "publicKeyBase64url")}


def _authority(value, config, *, boot, now_boottime_ns, now_unix_ns):
    validation_raw, validation = original(value["adoptionValidationInputOriginal"], adoption_profile.MAX_INPUT)
    context = adoption_profile.prepare_input(validation_raw, expected_input_sha256=p.sha(validation_raw), boot=boot,
        now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    authorization_raw, authorization = original(value["adoptionAuthorizationOriginal"], adoption_profile.MAX_AUTHORIZATION)
    p.fields(authorization, ("payload", "signature"))
    p.require(p.canonical(authorization["payload"]) == context["payloadOriginal"])
    trust_raw, trust = original(validation["currentTrustOriginal"], 1024 * 1024)
    assignment_raw, envelope = original(validation["currentAssignmentOriginal"], 1024 * 1024)
    # Authenticate the independently pinned trust and its signed assignment;
    # never bless config.authorityKeys as a self-described trust root.
    checked, bindings, _ = measured._assignment({"apiVersion": "serverware.nativePilotMeasuredConfigurationRecipe/v2",
        "trustOriginal": validation["currentTrustOriginal"], "trustSha256": validation["currentTrustSha256"],
        "assignmentOriginal": validation["currentAssignmentOriginal"]}, now_unix_ns)
    p.require(checked == envelope and p.sha(trust_raw) == validation["currentTrustSha256"])
    admitted, keys = admission.authorization(config, now_unix_ns)
    a, assignment = authorization["payload"], envelope["payload"]
    records = {row["role"]: row["key"] for row in trust["roleKeys"]}
    for key in keys:
        p.require({name: key[name] for name in ("role", "keyId", "keySpkiSha256", "keyMaterialSha256")} == bindings[key["role"]]
            and _public(key) == _public(records[key["role"]]))
    supervisor = keys[-1]
    p.require(a["authority"] == _public(supervisor)
        and a["native"] == _public(keys[p.ROLES.index(LOCAL_ROLES["publication"])])
        and a["retrieval"] == _public(keys[p.ROLES.index(LOCAL_ROLES["retrieval"])])
        and a["assignmentPayloadSha256"] == envelope["payloadSha256"] == admitted["assignmentPayloadSha256"]
        and a["assignmentRevision"] == assignment["assignmentRevision"] == admitted["assignmentRevision"]
        and admitted["assignmentId"] == assignment["assignmentId"]
        and config["trustCheckpoint"] == trust["checkpoint"])
    for name in ("trustCheckpointId", "revocationGeneration", "revocationRootSha256"):
        field = "checkpointId" if name == "trustCheckpointId" else name
        p.require(a[name] == trust["checkpoint"][field])
    p.public_key(supervisor).verify(p.decoded(authorization["signature"], size=64), adoption_profile.message(context))
    set_raw, _ = original(validation["currentClosureSetOriginal"], closure_set.MAX_BYTES)
    selected = closure_set.validate(set_raw, api_version=closure_set.PUBLICATION_API)
    leaf = assignments.closure_binding(envelope, set_raw, ROLES[value["operation"]], set_api_version=closure_set.PUBLICATION_API)
    manifest = next(row["manifest"] for row in selected["members"] if row["role"] == ROLES[value["operation"]])
    p.require(admitted["executionClosureManifestSha256"] == leaf["manifestSha256"] == manifest["manifestSha256"]
        and admitted["structurallyVerifiedSeccompPolicySha256"] == manifest["seccompPolicy"]["structurallyVerifiedPolicySha256"]
        and admitted["workerExecutableSha256"] == manifest["workerExecutableSha256"])
    proof_raw, proof = original(a["proofScopeOriginal"], 16384)
    retrieval.require_admitted_scope(retrieval.scope_original(proof_raw), admitted,
        assignment_payload_original=p.canonical(assignment))
    p.require(a["productionConfigurationBindingSha256"] == proof["production_configuration_binding_sha256"]
        and a["retrievalNamespaceSha256"] == proof["retrieval_namespace_sha256"])
    targets = ordinary.targets(validation["targetHistories"], a, boot=boot)
    originals = [trust, assignment, a,
        config["authorization"]["payload"], config["admissionAuthorization"]["payload"]]
    floors = [row["issuedAtUnixNanos"] for row in originals]
    ceilings = [min(row["expiresAtUnixNanos"], row["issuedAtUnixNanos"] + MAX_AGE + 1) for row in originals]
    for record in (trust["assignmentKey"], trust["timeKey"], *(records[role] for role in p.ROLES)):
        floors.append(record["notBeforeUnixNanos"]); ceilings.append(record["notAfterUnixNanos"])
    floors.append(trust["checkpoint"]["asOfUnixNanos"])
    ceilings.append(trust["checkpoint"]["asOfUnixNanos"] + MAX_AGE)
    p.require(max(floors) <= value["issuedAtUnixNanos"] < value["expiresAtUnixNanos"] <= min(ceilings))
    p.freshness(value["issuedAtUnixNanos"], value["expiresAtUnixNanos"], now_unix_ns)
    return {"authorization": authorization, "authorization_raw": authorization_raw, "payload": a, "context": context,
        "validation": validation, "admitted": admitted, "keys": keys, "supervisor": supervisor, "assignment": assignment,
        "proof_raw": proof_raw, "proof": proof, "targets": targets, "manifest": manifest,
        "epochLimit": min(ceilings + [value["expiresAtUnixNanos"], value["issuedAtUnixNanos"] + MAX_AGE + 1])}


def _guest(guest, a, *, boot):
    p.guest(guest)
    p.require((guest["bootIdBase64url"], guest["timeNamespaceDevice"], guest["timeNamespaceInode"]) == boot
        and p.ns(guest["issuedAtBoottimeNs"]) <= a["issuedAtBoottimeNanos"]
        < a["expiresAtBoottimeNanos"] <= p.ns(guest["lifetimeDeadlineBoottimeNs"]))


def _scope(value, held, guest):
    raw, _ = original(value["spoolScopeOriginal"], 16384)
    scope = spool._scope(raw, held["proof_raw"], held["admitted"], guest,
        assignment_payload_original=p.canonical(held["assignment"]))
    a = held["payload"]
    p.require(a["issuedAtBoottimeNanos"] <= scope["issuedAtBoottimeNanos"]
        < scope["expiresAtBoottimeNanos"] <= a["expiresAtBoottimeNanos"])
    return scope


def _signed(operation, raw, held, peer, *, now):
    if operation in PROFILES:
        signed = grant_original(operation, raw); domain = PROFILES[operation][2]
    else:
        from serverware import native_pilot_native_service_authority as legacy
        signed = legacy.grant_original(operation, raw); domain = legacy.grant_shape(operation, signed["payload"])
        p.require(signed["payload"]["apiVersion"] == legacy.HISTORY_PROFILES[operation][0])
    value = signed["payload"]
    p.require(value["assignmentPayloadSha256"] == held["payload"]["assignmentPayloadSha256"]
        and value["signingKeyId"] == held["supervisor"]["keyId"]
        and value["signingKeySpkiSha256"] == held["supervisor"]["keySpkiSha256"]
        and value["expectedPeer"] == peer)
    for name in ("trustCheckpointId", "revocationGeneration", "revocationRootSha256"):
        p.require(value[name] == held["payload"][name])
    p.public_key(held["supervisor"]).verify(p.decoded(signed["signature"], size=64), p.preimage(domain, value))
    p.freshness(value["issuedAtUnixNanos"], value["expiresAtUnixNanos"], now)
    return value


def prepare_input(operation, input_original, *, boot, now_boottime_ns, now_unix_ns):
    value = input_document(operation, input_original)
    config_raw, config = original(value["configurationOriginal"], p.MAX_CONFIG)
    p.require(p.sha(config_raw) == p.digest(value["configurationSha256"]))
    held = _authority(value, config, boot=boot, now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    delivery_input, _ = original(value["deliveryInputOriginal"], adopted_c9.MAX_INPUT)
    delivery_raw, _ = original(value["deliveryOriginal"], 65536)
    endpoint = c9.verify_adopted_delivery(delivery_input, delivery_raw, boot=boot,
        now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    guest, a = endpoint["guest"], held["payload"]
    p.require(endpoint["role"] == ROLES[operation] and guest == held["admitted"]["guest"]
        and config["authorization"]["payload"]["localRoles"] == [LOCAL_ROLES[operation]]
        and p.sha(endpoint["runtime_raw"]) == held["manifest"]["runtimeConfigurationSha256"]
        and endpoint["observed"][ROLES[operation]]["executable"]["sha256"] == held["manifest"]["workerExecutableSha256"])
    _guest(guest, a, boot=boot)
    from serverware import native_pilot_native_service_authority as legacy
    peer_raw, peer = legacy._peer(value, endpoint["observed"], guest)
    api, purpose, domain, _ = PROFILES[operation]
    payload = {"apiVersion": api, "purpose": purpose, "guest": guest,
        "assignmentPayloadSha256": a["assignmentPayloadSha256"], "keyAuthorizationSha256": held["admitted"]["keyAuthorizationSha256"],
        "expectedPeer": peer, **{name: a[name] for name in ("trustCheckpointId", "revocationGeneration", "revocationRootSha256")},
        "issuedAtUnixNanos": value["issuedAtUnixNanos"], "expiresAtUnixNanos": value["expiresAtUnixNanos"],
        "signingKeyId": held["supervisor"]["keyId"], "signingKeySpkiSha256": held["supervisor"]["keySpkiSha256"]}
    deadline = min(p.ns(endpoint["window"]["startupDeadlineBoottimeNs"]), a["expiresAtBoottimeNanos"])
    epoch_limit = held["epochLimit"]
    if operation == "publication":
        other_input, _ = original(value["retrievalDeliveryInputOriginal"], adopted_c9.MAX_INPUT)
        other_raw, _ = original(value["retrievalDeliveryOriginal"], 65536)
        other = c9.verify_adopted_delivery(other_input, other_raw, boot=boot,
            now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
        p.require(other["role"] == "retrieval" and other["window"] == endpoint["window"]
            and other["observed"] == endpoint["observed"] and other["guest"]["uid"] not in (guest["uid"], peer["uid"]))
        _guest(other["guest"], a, boot=boot)
        scope = _scope(value, held, guest)
        first, last = (p.integer(value[name], maximum=p.MAX_U64 - 1) for name in ("firstIngressSequence", "lastIngressSequence"))
        p.require(first <= last)
        bundle = p.document(a["coldBundleOriginal"].encode("ascii"), adoption_profile.MAX_AUTHORIZATION)
        prior = bundle["completion"]["receiptOriginal"]
        original(prior, 65536)
        rows, history_deadline, history_epoch = ordinary.members(value["ordinaryServices"], targets=held["targets"], scope=scope,
            peer=peer, assignment=held["assignment"], checkpoint=config["trustCheckpoint"], boot=boot,
            now_boottime_ns=now_boottime_ns, issued_at=value["issuedAtUnixNanos"], expires_at=value["expiresAtUnixNanos"])
        payload.update(admission={"scope": scope, "proofScopeOriginal": held["proof_raw"].decode("ascii"), "priorReceiptOriginal": prior,
            "firstIngressSequence": first, "lastIngressSequence": last, "adoption": held["authorization"]},
            retrieval=a["retrieval"], retrievalGuest=other["guest"], ordinaryServices=rows)
        deadline = min(deadline, history_deadline); epoch_limit = min(epoch_limit, history_epoch)
    elif operation == "retrieval":
        scope = _scope(value, held, guest)
        _, result = original(value["endpointDeliveryResultOriginal"], 65536)
        p.fields(result, ("guests", "spoolJournal"))
        guests = p.fields(result["guests"], ("retrieval", "persistence", "trustedTime", "publicationReconciliation"))
        p.require(guests["retrieval"] == guest)
        for other in guests.values():
            _guest(other, a, boot=boot)
            for name in c9.WINDOW_FIELDS: p.require(other[name] == guest[name])
        store = p.fields(result["spoolJournal"], ("genesisSha256", "sequence", "headSha256"))
        p.require(type(store["sequence"]) is int and store["sequence"] == 0 and store["headSha256"] == p.digest(store["genesisSha256"]))
        grant_raw, _ = original(value["publicationGrantOriginal"], PROFILES["publication"][3])
        published = _signed("publication", grant_raw, held, peer, now=now_unix_ns)
        p.require(published["admission"]["adoption"] == held["authorization"] and published["admission"]["scope"] == scope
            and published["admission"]["proofScopeOriginal"].encode("ascii") == held["proof_raw"]
            and published["retrieval"] == a["retrieval"] and published["retrievalGuest"] == guest
            and published["guest"] == guests["publicationReconciliation"])
        p.require(endpoint["core_bundle_raw"].decode("ascii") == a["coldBundleOriginal"])
        native = {"role": LOCAL_ROLES["publication"], **a["native"], "grantSha256": p.sha(grant_raw)}
        durable = next(row for row in a["targetHistories"] if row["serviceRole"] == ordinary.ROLES[0])
        selected = {}; raw_grants = p.fields(value["nativeGrantOriginals"], legacy.SIGNERS)
        for name, text in raw_grants.items():
            raw, _ = original(text, legacy.MAX_OUTPUT)
            prior = _signed(name, raw, held, peer, now=now_unix_ns)
            p.require(prior["scope"] == scope and prior["proofScopeOriginal"].encode("ascii") == held["proof_raw"]
                and prior["ordinaryServices"] == published["ordinaryServices"])
            for field in c9.WINDOW_FIELDS: p.require(prior["guest"][field] == guest[field])
            key_value = held["keys"][p.ROLES.index(legacy._LOCAL_ROLE[name])]
            selected[name] = {"role": key_value["role"], **_public(key_value), "grantSha256": p.sha(raw)}
            epoch_limit = min(epoch_limit, prior["expiresAtUnixNanos"], prior["issuedAtUnixNanos"] + MAX_AGE + 1)
        epoch_limit = min(epoch_limit, published["expiresAtUnixNanos"], published["issuedAtUnixNanos"] + MAX_AGE + 1)
        p.require(value["expiresAtUnixNanos"] <= epoch_limit)
        payload.update(proofScopeOriginalBase64url=p.encoded(held["proof_raw"]), spoolScope=scope, store=store,
            ingress=selected["ingress"], ledger=selected["ledger"], terminal=selected["terminal"],
            effects={name: selected[name] for name in ("dispatchBarrier", "activeEffectBarrier", "activeEffectCommit")},
            initialization="fresh-ledger-with-adopted-cold-publication",
            publication={"admission": published["admission"], "native": native,
                "drsAuthorityEpoch": durable["authorityEpoch"], "drsPublicKeyBase64url": durable["publicKeyBase64url"]})
    else:
        genesis_raw, _ = original(value["genesisOriginal"], 16384)
        journal_raw, journal = original(value["journalOriginal"], 1024)
        p.require(value["permissions"] == PERMISSIONS)
        persistence.fresh_originals(genesis_original=genesis_raw, genesis_sha256=p.sha(genesis_raw), journal_original=journal_raw,
            journal_sha256=p.sha(journal_raw), scope_original=held["proof_raw"], guest=guest)
        payload.update(permissions=list(PERMISSIONS), proofScopeOriginalBase64url=p.encoded(held["proof_raw"]), journal=journal, adoption=held["authorization"])
    grant_shape(operation, payload)
    p.require(now_boottime_ns < deadline and now_unix_ns < epoch_limit)
    return {"payload": payload, "supervisor": held["supervisor"], "window": endpoint["window"],
        "deadline": deadline, "epochLimit": epoch_limit, "domain": domain}


def grant_shape(operation, payload):
    p.require(operation in PROFILES)
    api, purpose, domain, maximum = PROFILES[operation]
    p.fields(payload, PAYLOAD[operation])
    p.require(payload["apiVersion"] == api and payload["purpose"] == purpose and len(p.canonical(payload)) + 128 <= maximum)
    if operation == "persistence":
        p.require(payload["permissions"] == PERMISSIONS)
    elif operation == "publication":
        p.fields(payload["ordinaryServices"], g.ROLES)
    else:
        p.require(payload["initialization"] == "fresh-ledger-with-adopted-cold-publication")
        p.fields(payload["publication"], ("admission", "native", "drsAuthorityEpoch", "drsPublicKeyBase64url"))
    selection = payload["adoption"] if operation == "persistence" else payload["admission"]["adoption"] if operation == "publication" else payload["publication"]["admission"]["adoption"]
    p.fields(selection, ("payload", "signature")); p.decoded(selection["signature"], size=64)
    p.require(selection["payload"]["apiVersion"] in tuple(profile[1] for profile in adoption_profile.PROFILES.values()))
    return domain


def grant_original(operation, raw):
    p.require(operation in PROFILES)
    signed = p.fields(p.document(raw, PROFILES[operation][3]), ("payload", "signature"))
    grant_shape(operation, signed["payload"]); p.decoded(signed["signature"], size=64)
    return signed


def require_adopted_grant(operation, raw, *, adoption_original, guest, proof_scope_original, store=None):
    """Owner association only; this is not a substitute for signature admission."""
    payload = grant_original(operation, raw)["payload"]
    authorization = p.fields(p.document(adoption_original, adoption_profile.MAX_AUTHORIZATION), ("payload", "signature"))
    selection = payload["adoption"] if operation == "persistence" else payload["admission"]["adoption"] if operation == "publication" else payload["publication"]["admission"]["adoption"]
    proof = payload["admission"]["proofScopeOriginal"].encode("ascii") if operation == "publication" else p.decoded(payload["proofScopeOriginalBase64url"], maximum=16384)
    p.require(selection == authorization and payload["guest"] == guest and proof == proof_scope_original
        and authorization["payload"]["proofScopeOriginal"].encode("ascii") == proof_scope_original)
    if operation == "retrieval": p.require(store is not None and payload["store"] == store)
    else: p.require(store is None)
    return payload


def sign(operation, input_original, signing_key):
    p.require(isinstance(signing_key, Ed25519PrivateKey))
    boot, before, wall = host._boot(), host._clock(), time.time_ns()
    prepared = prepare_input(operation, input_original, boot=boot, now_boottime_ns=before, now_unix_ns=wall)
    public = signing_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    p.require(p.encoded(public) == prepared["supervisor"]["publicKeyBase64url"])
    p.require(host._boot() == boot)
    now, epoch = host._clock(), time.time_ns()
    p.require(before <= now < prepared["deadline"] and wall <= epoch < prepared["epochLimit"])
    signature = signing_key.sign(p.preimage(prepared["domain"], prepared["payload"]))
    signing_key.public_key().verify(signature, p.preimage(prepared["domain"], prepared["payload"]))
    raw = p.canonical({"payload": prepared["payload"], "signature": p.encoded(signature)})
    grant_original(operation, raw)
    p.require(host._boot() == boot)
    final, final_epoch = host._clock(), time.time_ns()
    p.require(now <= final < prepared["deadline"] and epoch <= final_epoch < prepared["epochLimit"])
    return raw
