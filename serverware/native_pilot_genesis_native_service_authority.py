"""Separate cold native Publication-first/Retrieval-second service issuer.

Complete inputs need independent approval. Authentic key assignments, actual
C9/source observations and ordinary initial histories are required; parsing
their public originals does not create an owner or prove native admission.
Publication never references a future Retrieval grant. Retrieval requires the
exact prior signed Publication original and actual retained store observation.
No hot driver, policy load, prior business receipt or store genesis is made up.
"""
from __future__ import annotations

import copy
import os
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from serverware import custody_generation_grants as g
from serverware import native_pilot_genesis_ordinary_authority as ordinary
from serverware import native_pilot_genesis_ordinary_initial_profile as history
from serverware import native_pilot_genesis_ordinary_runtime as runtime
from serverware import native_pilot_ordinary_key_authority as history_keys
from serverware import native_pilot_publication_cold_binding as binding
from serverware import native_shadow_nitro_originals as originals

p = g.p
API = "serverware.nativePilotGenesisNativeServiceAuthorityInput/v1"
OPERATIONS = ("publication", "retrieval")
ENDPOINTS = ("publicationGenesis", "publicationGenesisRetrieval")
LOCAL_ROLES = dict(zip(ENDPOINTS, ("custody-publication-reconciliation", "custody-retrieval-response"), strict=True))
PROFILES = {
    "publication": ("serverware.nativePublicationGenesisAssignment/v1", "native-policy-publication-genesis",
        "serverware.nativePublicationGenesisAssignment.signature/v1"),
    "retrieval": ("serverware.nativePublicationGenesisRetrievalGrant/v1", "native-policy-publication-genesis-retrieval",
        "serverware.nativePublicationGenesisRetrievalGrant.signature/v1"),
}
MAX_INPUT = g.MAX_BYTES
MAX_OUTPUT = {"publication": g.MAX_BYTES, "retrieval": 65536}
PAIR_FIELDS = ("roleKeyInputOriginal", "roleKeyOriginal", "admissionInputOriginal", "admissionOriginal")
PARENT_FIELDS = ("parentConfigurationOriginal", "parentDeliveryConfigurationOriginal", "parentPrecreationOriginal", "parentObservationOriginal")
FIELDS = ("apiVersion", "operation", "coldBindingInputOriginal", "coldBindingInputSha256", "ordinary",
    "coordinatorPeerPreparationOriginal", "expectedPeer", "endpointPairs", "window")
PAYLOAD_FIELDS = ("apiVersion", "purpose", "authorization", "scope", "durableAuthority", "currentAuthority", "expectedPeer")


def _original(value, maximum=MAX_INPUT):
    return ordinary._original(value, maximum)


def _same(first, second):
    history.same(first, second)


def _public(key):
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def input_document(raw):
    value = g.document(raw, MAX_INPUT)
    p.require(value.get("apiVersion") == API and value.get("operation") in OPERATIONS)
    p.fields(value, FIELDS + (("nativePublicationOriginal", "retrievalStoreObservationOriginal") if value["operation"] == "retrieval" else ()))
    p.fields(value["ordinary"], ("runtimePolicy", "historyOriginals", "source"))
    p.fields(value["endpointPairs"], ENDPOINTS)
    for row in value["endpointPairs"].values(): p.fields(row, PAIR_FIELDS)
    _window_shape(value["window"])
    return value


def _window_shape(window):
    p.fields(window, ("issuedAtUnixNanos", "expiresAtUnixNanos"))
    issued, expires = (p.integer(window[field]) for field in ("issuedAtUnixNanos", "expiresAtUnixNanos"))
    p.require(issued < expires and expires - issued <= binding.MAX_AGE)
    return issued, expires


def _context(value, *, boot, now_boottime_ns, now_unix_ns):
    # Import the explicit successor, never route through a hot key profile.
    from serverware import native_pilot_genesis_key_profile as keys_profile
    binding_raw = _original(value["coldBindingInputOriginal"], binding.MAX_INPUT)
    approved = binding.input_document(binding_raw)
    bound = binding.result_document(binding.prepare(binding_raw, expected_input_sha256=value["coldBindingInputSha256"],
        boot=boot, now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns))
    _, assignment, trust, keys, _ = binding._authorities(approved, now_unix_ns)
    scope = g.document(bound["genesisScopeOriginal"].encode("ascii"), 16384)
    selected = next(row for row in keys if row["role"] == "custody-supervisor-capability")
    supervisor = p.public_key(selected)
    ordinary_input = value["ordinary"]
    histories = {role: _original(raw, history.MAX_HISTORY) for role, raw in
        p.fields(ordinary_input["historyOriginals"], history.ROLES).items()}
    contexts, peer = runtime.contexts(fragment=ordinary_input["runtimePolicy"], history_originals=histories,
        source=ordinary_input["source"], peer_preparation_raw=_original(value["coordinatorPeerPreparationOriginal"], 65536),
        approved_peer=value["expectedPeer"], boot=boot, now_boottime_ns=now_boottime_ns)
    authority = {}
    deadlines = [scope["expiresAtBoottimeNanos"]]
    epoch_limits = [bound["expiresAtUnixNanos"], trust["issuedAtUnixNanos"] + binding.MAX_AGE + 1,
        assignment["payload"]["issuedAtUnixNanos"] + binding.MAX_AGE + 1]
    floors = [bound["issuedAtUnixNanos"]]
    for name, role in (("durableAuthority", history.ROLES[0]), ("currentAuthority", history.ROLES[1])):
        item = contexts[role]
        state = item["state"]
        checked = history.require_window(histories[role], role=role, root_pin={
            "keyId": item["history"]["rootAuthority"]["keyId"],
            "keySpkiSha256": item["history"]["rootAuthority"]["keySpkiSha256"]},
            boot=boot, now_boottime_ns=now_boottime_ns, issued=scope["issuedAtBoottimeNanos"], expires=scope["expiresAtBoottimeNanos"])
        p.require(p.ns(state["issuedAtBoottimeNs"]) <= scope["issuedAtBoottimeNanos"]
            and scope["expiresAtBoottimeNanos"] <= p.ns(state["lifetimeDeadlineBoottimeNs"]))
        authority[name] = {"epoch": ordinary.epoch_reference(item["history"]),
            "publicKeyBase64url": p.encoded(_public(history_keys._key(item["epoch"]["serviceSigningKey"])))}
        deadlines.extend((checked["deadline"], item["deadline"], item["observed"]["deadline"]))
    pairs = {}
    for role in ENDPOINTS:
        row = value["endpointPairs"][role]
        pair_raw = {field: _original(row[field], min(MAX_INPUT, keys_profile.MAX_INPUT if "Input" in field else keys_profile.MAX_OUTPUT))
            for field in PAIR_FIELDS}
        pair = keys_profile.admitted_pair(role, pair_raw["roleKeyInputOriginal"], pair_raw["roleKeyOriginal"],
            pair_raw["admissionInputOriginal"], pair_raw["admissionOriginal"], boot=boot,
            now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
        source = pair["source"]
        p.require(source["coldBindingInputOriginal"] == binding_raw
            and source["coldBindingInputSha256"] == value["coldBindingInputSha256"])
        _same(source["coldBinding"], bound); _same(source["assignment"], assignment)
        _same(pair["authorityKeys"], keys); _same(pair["trustCheckpoint"], trust["checkpoint"])
        expected = pair["expectedScope"]
        p.require(expected["assignmentPayloadSha256"] == scope["assignmentPayloadSha256"]
            and expected["assignmentRevision"] == scope["assignmentRevision"])
        assigned = next(key for key in keys if key["role"] == LOCAL_ROLES[role])
        _same(expected["localKeys"], [assigned])
        guest = ordinary._guest(expected["guest"], scope=scope)
        p.require(guest["serviceRole"] == "production-bridge")
        _same(guest, source["delivery"]["guest"])
        # The source adapter authenticates these exact retained parent originals;
        # do not infer a common commissioning from a matching digest alone.
        parents = p.fields(source["delivery"]["parentOriginals"], PARENT_FIELDS)
        for field in PARENT_FIELDS:
            p.require(parents[field] == ordinary_input["source"][field])
        for field in ("authorization", "admissionAuthorization"):
            payload = pair[field]["payload"]
            floors.append(payload["issuedAtUnixNanos"])
            epoch_limits.extend((payload["expiresAtUnixNanos"], payload["issuedAtUnixNanos"] + binding.MAX_AGE + 1))
        p.require(type(pair["deadline"]) is int and type(pair["epochLimit"]) is int)
        deadlines.append(pair["deadline"]); epoch_limits.append(pair["epochLimit"])
        pairs[role] = pair
    material = [row["publicKeyBase64url"] for row in authority.values()]
    material.extend(next(row for row in keys if row["role"] == LOCAL_ROLES[role])["publicKeyBase64url"] for role in ENDPOINTS)
    p.require(len(set(material)) == 4)
    for item in contexts.values():
        p.require(p.encoded(_public(history_keys._key(item["history"]["rootAuthority"]))) not in material)
    ids = [(contexts[role]["identity"]["endpointUid"], contexts[role]["identity"]["endpointGid"]) for role in history.ROLES]
    ids.extend((pairs[role]["expectedScope"]["guest"]["uid"], pairs[role]["expectedScope"]["guest"]["gid"]) for role in ENDPOINTS)
    ids.append((peer["uid"], peer["gid"]))
    p.require(len({uid for uid, _ in ids}) == len(ids) and len({gid for _, gid in ids}) == len(ids))
    return dict(scope=scope, authority=authority, pairs=pairs, peer=peer, selected=selected, key=supervisor,
        keys=keys, checkpoint=trust["checkpoint"], deadline=min(deadlines), epochLimit=min(epoch_limits),
        issuedFloor=max(floors), now=now_boottime_ns, epoch=now_unix_ns)


def _window(window, context):
    issued, expires = _window_shape(window)
    p.freshness(issued, expires, context["epoch"], binding.MAX_AGE)
    p.require(context["issuedFloor"] <= issued < expires <= context["epochLimit"])
    return issued, expires


def _payload(operation, context, window):
    issued, expires = _window(window, context)
    role = ENDPOINTS[OPERATIONS.index(operation)]
    pair = context["pairs"][role]
    selected, checkpoint = context["selected"], context["checkpoint"]
    authorization = {"guest": pair["expectedScope"]["guest"],
        "assignmentPayloadSha256": context["scope"]["assignmentPayloadSha256"],
        "keyAuthorizationSha256": pair["expectedScope"]["keyAuthorizationSha256"],
        "trustCheckpointId": checkpoint["checkpointId"], "revocationGeneration": checkpoint["revocationGeneration"],
        "revocationRootSha256": checkpoint["revocationRootSha256"], "issuedAtUnixNanos": issued, "expiresAtUnixNanos": expires,
        "signingKeyId": selected["keyId"], "signingKeySpkiSha256": selected["keySpkiSha256"]}
    api, purpose, _ = PROFILES[operation]
    payload = {"apiVersion": api, "purpose": purpose, "authorization": authorization, "scope": context["scope"],
        **context["authority"], "expectedPeer": context["peer"]}
    if operation == "publication":
        assigned = next(row for row in context["keys"] if row["role"] == LOCAL_ROLES[ENDPOINTS[1]])
        payload.update(retrieval={field: assigned[field] for field in ("keyId", "keySpkiSha256", "publicKeyBase64url")},
            retrievalGuest=context["pairs"][ENDPOINTS[1]]["expectedScope"]["guest"])
    return payload


def _prior_publication(raw, context):
    envelope = p.fields(g.document(raw, MAX_OUTPUT["publication"]), ("payload", "signature"))
    payload = p.fields(envelope["payload"], PAYLOAD_FIELDS + ("retrieval", "retrievalGuest"))
    authorization = p.fields(payload["authorization"], ordinary.AUTHORIZATION_FIELDS)
    selected_window = {field: authorization[field] for field in ("issuedAtUnixNanos", "expiresAtUnixNanos")}
    _same(payload, _payload("publication", context, selected_window))
    context["key"].verify(p.decoded(envelope["signature"], size=64), ordinary.native_message(PROFILES["publication"][2], payload))
    return payload


def prepare_input(operation, input_original, *, boot, now_boottime_ns, now_unix_ns):
    value = input_document(input_original)
    p.require(operation in OPERATIONS and value["operation"] == operation)
    context = _context(value, boot=boot, now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    payload = _payload(operation, context, value["window"])
    if operation == "retrieval":
        native_raw = _original(value["nativePublicationOriginal"], MAX_OUTPUT["publication"])
        prior = _prior_publication(native_raw, context)
        p.require(value["window"]["issuedAtUnixNanos"] >= prior["authorization"]["issuedAtUnixNanos"]
            and value["window"]["expiresAtUnixNanos"] <= prior["authorization"]["expiresAtUnixNanos"])
        # Actual store-observation validation is provided by the resource owner
        # module, not by a caller-selected head digest or absent-file inference.
        from serverware import native_pilot_genesis_endpoint_profile as resources
        source = context["pairs"][ENDPOINTS[1]]["source"]
        store = resources.store_observation(_original(value["retrievalStoreObservationOriginal"], 65536),
            resources_raw=source["delivery"]["resources_raw"], delivery_raw=source["deliveryOriginal"],
            proof_scope_raw=context["scope"]["proofScopeOriginal"].encode("ascii"))
        assigned = next(row for row in context["keys"] if row["role"] == LOCAL_ROLES[ENDPOINTS[0]])
        payload.update(native={"role": assigned["role"], **{field: assigned[field] for field in
            ("keyId", "keySpkiSha256", "publicKeyBase64url")}, "grantSha256": p.sha(native_raw)}, store=store)
    deadline = context["deadline"]
    epoch_limit = min(context["epochLimit"], value["window"]["expiresAtUnixNanos"])
    p.require(now_boottime_ns < deadline and now_unix_ns < epoch_limit)
    raw = g.canonical(payload)
    p.require(len(raw) < MAX_OUTPUT[operation] - 256)
    return dict(payload=copy.deepcopy(payload), message=ordinary.native_message(PROFILES[operation][2], payload),
        key=context["key"], deadline=deadline, epochLimit=epoch_limit, operation=operation)


def checked_result(operation, input_original, result, *, boot, now_boottime_ns, now_unix_ns):
    prepared = prepare_input(operation, input_original, boot=boot, now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    p.fields(result, ("original", "sha256"))
    raw = _original(result["original"], MAX_OUTPUT[operation])
    p.require(p.sha(raw) == result["sha256"])
    envelope = p.fields(g.document(raw, MAX_OUTPUT[operation]), ("payload", "signature"))
    _same(envelope["payload"], prepared["payload"])
    prepared["key"].verify(p.decoded(envelope["signature"], size=64), prepared["message"])
    return raw


def sign(operation, *, input_original, signing_key):
    p.require(operation in OPERATIONS and isinstance(signing_key, Ed25519PrivateKey))
    owner = os.getpid(), originals._start(), originals._boot()
    now, epoch = originals._clock(), time.time_ns()
    prepared = prepare_input(operation, input_original, boot=owner[2], now_boottime_ns=now, now_unix_ns=epoch)
    p.require(_public(signing_key.public_key()) == _public(prepared["key"]))
    def check(previous, prior_epoch):
        p.require((os.getpid(), originals._start(), originals._boot()) == owner)
        current, wall = originals._clock(), time.time_ns()
        p.require(previous <= current < prepared["deadline"] and prior_epoch <= wall < prepared["epochLimit"])
        return current, wall
    before, before_epoch = check(now, epoch)
    signature = signing_key.sign(prepared["message"])
    prepared["key"].verify(signature, prepared["message"])
    raw = g.canonical({"payload": prepared["payload"], "signature": p.encoded(signature)})
    after, after_epoch = check(before, before_epoch)
    checked_result(operation, input_original, {"original": raw.decode("ascii"), "sha256": p.sha(raw)},
        boot=owner[2], now_boottime_ns=after, now_unix_ns=after_epoch)
    check(after, after_epoch)
    return raw
