"""Purpose-fixed public authoring for the explicit native spool successor.

Callers supply independently provisioned opaque authority keys and actual
approved originals. This module performs no key generation, launch, contact,
NSM, KMS, storage initialization, or readiness assertion.
"""
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from serverware import native_shadow_commitment_artifacts as old
from serverware import native_shadow_key_admission_profile as admission
from serverware import native_shadow_key_contract as delivery
from serverware import native_shadow_retrieval_artifacts as retrieval
from serverware import native_shadow_nitro_profile as p
from serverware import custody_spool_inputs as inputs
from serverware.native_shadow_time_profile import key_live


def sign_sampling_assignment(*, configuration_original, configuration_sha256, assignment_payload_original,
                             secret_sha256, issued_at, expires_at, now, signing_key):
    config, admitted, keys, assignment = old._inputs(configuration_original, configuration_sha256,
        assignment_payload_original, now, signing_key)
    window = assignment["observationWindow"]
    descriptor = delivery.commitment({"keyId": window["requestCommitmentKeyId"],
        "keyEpoch": window["requestCommitmentKeyEpoch"], "secretSha256": p.digest(secret_sha256)})
    p.require(descriptor["keyId"] not in {key["keyId"] for key in keys})
    value = old._common(config, admitted, keys, issued_at, expires_at, now)
    value.update(apiVersion="serverware.nativeShadowRequestCommitmentAssignment/v2",
        purpose="native-shadow-request-and-ingress-commitments", requestCommitment=descriptor)
    return old._signed(value, "serverware.nativeShadowRequestCommitmentAssignment.signature/v2", signing_key)


def sign_sampling_delivery(**values):
    """Explicit v2 HMAC authorization; old encrypted author keeps v1 strict."""
    return old._sign_encrypted_delivery(**values, sampling=True)


def sign_commit_service_grant(**values):
    """Old CommitRequest permission on separately selected service runtime/v7.

    This does not grant shared-head/append permission; its independently
    signed spool grant is separately mandatory at the actual effect owner.
    """
    return old._sign_service_transition_grant(**values, spool=True, effects=False)


def sign_effects_transition_grant(**values):
    """Existing two-role CommitRequest authority on explicit ordinary v8."""
    return old._sign_service_transition_grant(**values, spool=True, effects=True)


def _scope(raw, proof_raw, admitted, guest, *, assignment_payload_original=None):
    value = p.fields(p.document(raw, 16384), inputs.SCOPE)
    for name in inputs.SCOPE:
        if name in ("assignmentRevision", "issuedAtBoottimeNanos", "expiresAtBoottimeNanos"):
            p.integer(value[name], maximum=p.MAX_U64)
        else:
            p.digest(value[name])
    proof = retrieval.scope_original(proof_raw)
    if proof.get("api_version") == retrieval.SCOPE_SET_API:
        retrieval.require_admitted_scope(proof, admitted, assignment_payload_original=assignment_payload_original)
    p.require(value["assignmentPayloadSha256"] == admitted["assignmentPayloadSha256"]
        and value["assignmentRevision"] == admitted["assignmentRevision"]
        and value["proofScopeSha256"] == p.sha(proof_raw)
        and value["productionConfigurationBindingSha256"] == proof["production_configuration_binding_sha256"]
        and value["retrievalNamespaceSha256"] == proof["retrieval_namespace_sha256"]
        and p.ns(guest["issuedAtBoottimeNs"]) <= value["issuedAtBoottimeNanos"] < value["expiresAtBoottimeNanos"]
        <= p.ns(guest["lifetimeDeadlineBoottimeNs"]))
    return value


def _input(configuration_original, configuration_sha256, assignment_payload_original, role, now, signing_key):
    p.require(p.sha(configuration_original) == p.digest(configuration_sha256))
    config = p.document(configuration_original, p.MAX_CONFIG)
    admitted, keys = admission.authorization(config, now)
    assignment = p.document(assignment_payload_original, p.MAX_CONFIG)
    p.require(config["authorization"]["payload"]["localRoles"] == [role]
        and p.sha(assignment_payload_original) == admitted["assignmentPayloadSha256"]
        and assignment["assignmentRevision"] == admitted["assignmentRevision"]
        and isinstance(signing_key, Ed25519PrivateKey))
    public = signing_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    p.require(p.encoded(public) == keys[-1]["publicKeyBase64url"])
    return config, admitted, keys


def _sign_signer(*, configuration_original, configuration_sha256, assignment_payload_original, scope_original,
                 proof_scope_original, origin_verifier, peer_original, companion_pin, issued_at, expires_at, now, signing_key,
                 ingress, completion=False, terminal=False, effect=None):
    p.require(not (ingress and completion) and (not terminal or completion and not ingress)
        and (effect is None or effect in inputs.EFFECT_KEYS and not ingress and not completion and not terminal and companion_pin is None))
    effect_profiles = {"dispatchBarrier": ("DispatchBarrier", "custody-dispatch-barrier", "native-dispatch-barrier"),
        "activeEffectBarrier": ("ActiveEffectBarrier", "custody-active-effect-barrier", "native-active-effect-barrier"),
        "activeEffectCommit": ("ActiveEffectCommit", "custody-active-effect-commit", "native-active-effect-commit")}
    role = effect_profiles[effect][1] if effect is not None else "custody-terminal-append" if terminal else "custody-ingress-admission" if ingress else "custody-ledger-append"
    config, admitted, keys = _input(configuration_original, configuration_sha256, assignment_payload_original, role, now, signing_key)
    scope = _scope(scope_original, proof_scope_original, admitted, admitted["guest"],
        assignment_payload_original=assignment_payload_original)
    key_live(origin_verifier, now)
    p.require(origin_verifier["keyId"] not in {key["keyId"] for key in keys})
    if ingress or terminal or effect is not None:
        p.require(companion_pin is None)
    else:
        from serverware.native_shadow_guest_delivery import _pin
        _pin(companion_pin)
    peer = retrieval._peer(peer_original)
    p.require(peer["uid"] != admitted["guest"]["uid"])
    value = old._common(config, admitted, keys, issued_at, expires_at, now)
    stem = effect_profiles[effect][0] if effect is not None else "TerminalSpool" if terminal else "Ingress" if ingress else "LedgerSpool"
    version = "2" if completion and not terminal else "1"
    purpose = (effect_profiles[effect][2] if effect is not None else "native-terminal-slot-append" if terminal else "native-first-ingress" if ingress else
        "native-ledger-spool-and-sampling-with-unavailability" if completion else "native-ledger-spool-and-sampling")
    value.update(apiVersion="serverware.nativeShadow" + stem + "ServiceAssignment/v" + version,
        purpose=purpose, scope=scope,
        proofScopeOriginal=proof_scope_original.decode("ascii"), originVerifier=origin_verifier, expectedPeer=peer, commitRequest=companion_pin)
    domain = "serverware.nativeShadow" + stem + "ServiceAssignment.signature/v" + version
    return old._signed(value, domain, signing_key)


def sign_ingress_service(**values):
    return _sign_signer(**values, companion_pin=None, ingress=True, completion=False, terminal=False, effect=None)


def sign_ledger_service(**values):
    return _sign_signer(**values, ingress=False, completion=False, terminal=False, effect=None)


def sign_completion_ledger_service(**values):
    return _sign_signer(**values, ingress=False, completion=True, terminal=False, effect=None)


def sign_terminal_service(**values):
    return _sign_signer(**values, companion_pin=None, ingress=False, completion=True, terminal=True, effect=None)


def sign_dispatch_barrier_service(**values):
    return _sign_signer(**values, companion_pin=None, ingress=False, effect="dispatchBarrier")


def sign_active_effect_barrier_service(**values):
    return _sign_signer(**values, companion_pin=None, ingress=False, effect="activeEffectBarrier")


def sign_active_effect_commit_service(**values):
    return _sign_signer(**values, companion_pin=None, ingress=False, effect="activeEffectCommit")


def _sign_retrieval_service(*, configuration_original, configuration_sha256, assignment_payload_original, scope_original,
                           proof_scope_original, peer_original, ingress_key, ledger_key, store_admission,
                           issued_at, expires_at, now, signing_key, terminal_key=None, completion=False, effects=None):
    config, admitted, keys = _input(configuration_original, configuration_sha256, assignment_payload_original,
        "custody-retrieval-response", now, signing_key)
    scope = _scope(scope_original, proof_scope_original, admitted, admitted["guest"],
        assignment_payload_original=assignment_payload_original)
    p.require(completion == (terminal_key is not None) and (effects is None or completion))
    role_keys = ((ingress_key, "custody-ingress-admission"), (ledger_key, "custody-ledger-append"))
    if completion:
        role_keys += ((terminal_key, "custody-terminal-append"),)
    if effects is not None:
        p.fields(effects, inputs.EFFECT_KEYS)
        role_keys += tuple((effects[name], inputs.EFFECT_NATIVE[name][0]) for name in inputs.EFFECT_KEYS)
    for value, role in role_keys:
        p.fields(value, ("role", "keyId", "keySpkiSha256", "publicKeyBase64url", "grantSha256"))
        actual = keys[p.ROLES.index(role)]
        p.require(value["role"] == role and all(value[name] == actual[name] for name in ("keyId", "keySpkiSha256", "publicKeyBase64url")))
        p.digest(value["grantSha256"])
    store = p.fields(store_admission, ("genesisSha256", "sequence", "headSha256"))
    p.digest(store["genesisSha256"]); p.digest(store["headSha256"])
    p.integer(store["sequence"], minimum=0, maximum=128)
    p.require(store["sequence"] != 0 or store["headSha256"] == store["genesisSha256"])
    peer = retrieval._peer(peer_original); p.require(peer["uid"] != admitted["guest"]["uid"])
    value = old._common(config, admitted, keys, issued_at, expires_at, now)
    version = "3" if effects is not None else "2" if completion else "1"
    value.update(apiVersion="serverware.nativeLedgerSpoolRetrievalGrant/v" + version, purpose="native-ledger-spool-retrieval",
        proofScopeOriginalBase64url=p.encoded(proof_scope_original), expectedPeer=peer, spoolScope=scope,
        ingress=ingress_key, ledger=ledger_key, store=store)
    if completion:
        value["terminal"] = terminal_key
    if effects is not None:
        value["effects"] = dict(effects)
    return old._signed(value, "serverware.nativeLedgerSpoolRetrievalGrant.signature/v" + version, signing_key)


def sign_retrieval_service(**values):
    return _sign_retrieval_service(**values, terminal_key=None, completion=False, effects=None)


def sign_completion_retrieval_service(**values):
    return _sign_retrieval_service(**values, completion=True, effects=None)


def sign_effects_retrieval_service(**values):
    """Fixed v3 retrieval scope; terminal and all three effect RoleKeys required."""
    p.require("effects" in values and values["effects"] is not None)
    return _sign_retrieval_service(**values, completion=True)


def _sign_and_seal_service_grant(*, owner, role, approved_payload_original, native_originals, history_root_authority, completion, effects=False):
    """Actual root key and actual retained runtime/history/C9/grant writer."""
    from serverware.custody_generation_inputs import GenerationInputs
    p.require(type(owner) is GenerationInputs and owner._spool and owner._effects == effects
        and (not effects or completion) and role in (inputs.EFFECT_ROLES if effects else inputs.ROLES) and not owner._taken)
    owner.check()
    writer = owner._spools[role]; writer.check()
    item = owner._roles[role]; root, semantic = inputs._root(item)
    p.require(isinstance(history_root_authority, Ed25519PrivateKey)
        and history_root_authority.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            == root.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
    head = role == inputs.ROLES[0]
    cleanup = effects and role == inputs.EFFECT_ROLES[1]
    fields = inputs.HEAD + (("completion",) if completion else ()) + (("effects",) if effects else ()) if head else inputs.CURRENT
    value = p.fields(p.document(approved_payload_original, 131072), fields)
    p.require(value["guest"] == item["guest"] and value["runtimeConfigurationSha256"] == item["runtime"].sha
        and value["authorityHistoryManifestSha256"] == semantic)
    profile = "nativeActiveEffectCleanupGrant" if cleanup else "nativeSpool" + ("Head" if head else "Current") + "Grant"
    version = "1" if cleanup else "3" if effects else "2" if completion else "1"
    p.require(value["apiVersion"] == "serverware." + profile + "/v" + version
        and value["purpose"] == ("native-shared-spool-head" if head else "native-active-effect-cleanup" if cleanup else "native-spool-current-signature"))
    domain = ("serverware." + profile + ".signature/v" + version).encode("ascii")
    message = b"serverware-signature-v1\0" + len(domain).to_bytes(8, "big") + domain
    message += len(approved_payload_original).to_bytes(8, "big") + approved_payload_original
    raw = p.canonical({"payload": value, "signatureBase64url": p.encoded(history_root_authority.sign(message))})
    # The actual writer verifies complete current scope, native originals,
    # independent root and exact C9/runtime joins before sealing the memfd.
    owner.seal_spool_grant(role, approved_grant_original=raw, native_originals=native_originals)
    return raw


def sign_and_seal_service_grant(**values):
    return _sign_and_seal_service_grant(**values, completion=False, effects=False)


def sign_and_seal_completion_service_grant(**values):
    return _sign_and_seal_service_grant(**values, completion=True, effects=False)


def sign_and_seal_effects_service_grant(**values):
    """Only DRS, Cleanup and Current on the real retained effects owner.

    Sign the independently approved exact payload using that actual role's
    pinned history-root key; the retained writer validates and seals its real
    preallocated descriptor. No key generation or arbitrary signing purpose.
    """
    return _sign_and_seal_service_grant(**values, completion=True, effects=True)
