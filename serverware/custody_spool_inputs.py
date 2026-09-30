"""Real fixed DRS/current owners plus the explicit three-role effects successor.

Only supplied independently signed grants are admitted. This module creates no
key, head, native signature, generation, or successful effect observation.
Effects adds only Cleanup's own grant/journal, not dispatch or HMAC resources.
Allocate before C9; seal Head, Cleanup, Current after actual C9 originals exist;
retain all owners through the existing one-shot eleven-child release/cleanup.
"""
import fcntl
import os
import threading

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from serverware import custody_generation_grants as g
from serverware import custody_generation_originals as o
from serverware import custody_commitment_inputs as commitment

p = g.p
ROLES = commitment.ROLES
EFFECT_ROLES = (g.ROLES[0], g.ROLES[1], g.ROLES[3])
HEAD = ("apiVersion", "purpose", "guest", "runtimeConfigurationSha256", "authorityHistoryManifestSha256", "scope",
        "originVerifier", "ingress", "ledger", "retrieval", "proofScopeOriginal", "initialTransitionHeadSha256")
CURRENT = ("apiVersion", "purpose", "guest", "runtimeConfigurationSha256", "authorityHistoryManifestSha256",
           "headGrantOriginal", "durableAuthorityEpoch", "durablePublicKeyBase64url", "initialTransitionHeadSha256")
SCOPE = ("productionConfigurationBindingSha256", "kernelDriverIdentitySha256", "retainedDescriptorSetSha256",
         "driverGenerationReceiptSha256", "assignmentPayloadSha256", "assignmentRevision", "generationId",
         "proofScopeSha256", "retrievalNamespaceSha256", "issuedAtBoottimeNanos", "expiresAtBoottimeNanos")
NATIVE = {"ingress": ("custody-ingress-admission", "serverware.nativeShadowIngressServiceAssignment/v1"),
          "ledger": ("custody-ledger-append", "serverware.nativeShadowLedgerSpoolServiceAssignment/v1"),
          "retrieval": ("custody-retrieval-response", "serverware.nativeLedgerSpoolRetrievalGrant/v1")}
COMPLETION_NATIVE = {**NATIVE,
    "ledger": ("custody-ledger-append", "serverware.nativeShadowLedgerSpoolServiceAssignment/v2"),
    "retrieval": ("custody-retrieval-response", "serverware.nativeLedgerSpoolRetrievalGrant/v2"),
    "terminal": ("custody-terminal-append", "serverware.nativeShadowTerminalSpoolServiceAssignment/v1")}
EFFECT_KEYS = ("dispatchBarrier", "activeEffectBarrier", "activeEffectCommit")
EFFECTS = EFFECT_KEYS + ("cleanupAuthorityEpoch", "cleanupPublicKeyBase64url", "cleanupInitialTransitionHeadSha256")
EFFECT_NATIVE = {**COMPLETION_NATIVE,
    "retrieval": ("custody-retrieval-response", "serverware.nativeLedgerSpoolRetrievalGrant/v3"),
    "dispatchBarrier": ("custody-dispatch-barrier", "serverware.nativeShadowDispatchBarrierServiceAssignment/v1"),
    "activeEffectBarrier": ("custody-active-effect-barrier", "serverware.nativeShadowActiveEffectBarrierServiceAssignment/v1"),
    "activeEffectCommit": ("custody-active-effect-commit", "serverware.nativeShadowActiveEffectCommitServiceAssignment/v1")}


def _require_retrieval_profile(payload, *, expected_api, effects, proof_scope_original):
    """Join the selected profile without replacing signed grant-hash bindings."""
    if payload.get("apiVersion") != "serverware.nativeLedgerSpoolRetrievalGrant/v4":
        p.require(payload["apiVersion"] == expected_api and "initialization" not in payload)
        return
    from serverware import native_shadow_retrieval_artifacts as retrieval
    p.require(effects is True and expected_api == EFFECT_NATIVE["retrieval"][1]
        and payload["purpose"] == "native-ledger-spool-retrieval"
        and payload["initialization"] == "fresh-ledger"
        and type(proof_scope_original) is str and proof_scope_original.isascii()
        and 0 < len(proof_scope_original) <= 16384)
    proof_raw = proof_scope_original.encode("ascii")
    proof = retrieval.scope_original(proof_raw)
    p.require(proof.get("api_version") == retrieval.SCOPE_SET_API
        and p.decoded(payload["proofScopeOriginalBase64url"], maximum=16384) == proof_raw)
    store = p.fields(payload["store"], ("genesisSha256", "sequence", "headSha256"))
    p.digest(store["genesisSha256"])
    p.require(type(store["sequence"]) is int and store["sequence"] == 0
        and store["headSha256"] == store["genesisSha256"])


def sign_delivery(**values):
    p.require(values["role"] in ROLES)
    return g._sign_delivery(**values, commitment=True, spool=True, effects=False)


def sign_generation_grant(**values):
    p.require(values["guest"]["serviceRole"] in ROLES)
    return g._sign_grant(**values, commitment=True, spool=True, effects=False)


def sign_effects_delivery(**values):
    p.require(values["role"] in EFFECT_ROLES)
    return g._sign_delivery(**values, commitment=values["role"] in ROLES, spool=True, effects=True)


def sign_effects_generation_grant(**values):
    role = values["guest"]["serviceRole"]
    p.require(role in EFFECT_ROLES)
    return g._sign_grant(**values, commitment=role in ROLES, spool=True, effects=True)


def _signing_public(item, encoded):
    """Consistency with retained signed C9; full history remains a receiver check."""
    key = p.decoded(encoded, size=32)
    p.require(key != bytes(32))
    delivery = g.document(item["delivery_raw"], 65536)["payload"]
    signing = [entry["signing"]["publicKeyBase64url"] for entry in delivery["credentials"] if entry["signing"] is not None]
    p.require(encoded in signing)
    return p.sha(bytes.fromhex("302a300506032b6570032100") + key)


def _epoch_key(epoch, role, encoded, item):
    # The complete epoch is pinned by the independent signed grant; no unsigned
    # projection here is promoted into verified authority-history currentness.
    p.require(epoch["authorityRole"] == {"authorityKind": "isolated-service", "role": role}
        and epoch["serviceSigningKeySpkiSha256"] == _signing_public(item, encoded))


def _root(item):
    header = g.document(item["runtime_raw"], g.MAX_BYTES)["runtime"]
    from serverware import native_pilot_ordinary_initial_profile as initial
    history = initial.runtime_manifest(item["history_raw"], runtime=header, guest=item["guest"])
    semantic = p.framed(b"serverware.policyCustodyAuthorityHistoryManifest/v3", (g.canonical([history[k] for k in g.HISTORY[:-1]]),))
    p.require(history["manifestSha256"] == semantic == header["authorityHistoryManifestSha256"])
    root = p.fields(history["rootAuthority"], ("keyId", "keySpkiSha256", "publicKeySpkiBase64"))
    der = p.decoded(root["publicKeySpkiBase64"], size=44)
    key = serialization.load_der_public_key(der)
    p.require(isinstance(key, Ed25519PublicKey) and p.sha(der) == root["keySpkiSha256"] == header["authorityHistoryRootKeySpkiSha256"]
        and root["keyId"] == header["authorityHistoryRootKeyId"])
    return key, semantic


class RoleInputs:
    @classmethod
    def prepare(cls, owner, role, parent, cold):
        from serverware.custody_generation_inputs import GenerationInputs, _persistent
        p.require(cls is RoleInputs and type(owner) is GenerationInputs and owner._spool
            and role in (EFFECT_ROLES if owner._effects else ROLES))
        value = cls()
        value._owner, value._role, value._parent = owner, role, parent
        value._prefix = "spool-head" if role == ROLES[0] else "active-effect-cleanup" if role == EFFECT_ROLES[1] else "spool-current"
        value._raw = value._native = value._payload = None
        value._attempted = False
        os.mkdir(value._prefix + "-journal", 0o700, dir_fd=parent)
        fd = os.open(value._prefix + "-journal", o.FLAGS | os.O_DIRECTORY, dir_fd=parent)
        owner._fds.append(fd); value._directory = fd
        os.fchown(fd, cold["uid"], cold["gid"]); os.fchmod(fd, 0o700)
        _persistent(fd); p.require(o.names(fd) == ())
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB); os.fsync(fd); os.fsync(parent)
        fd = os.memfd_create(value._prefix + "-grant", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        owner._fds.append(fd); value._grant = fd
        os.fchown(fd, cold["uid"], cold["gid"]); os.fchmod(fd, 0o600)
        value._directory_identity = o.structural(os.fstat(value._directory))
        value._grant_identity = o.structural(os.fstat(value._grant))
        value.check(); return value

    def descriptors(self):
        return ((self._prefix + "-journal", self._directory), (self._prefix + "-grant", self._grant))

    def check(self):
        p.require(not self._owner._closed and threading.current_thread() is threading.main_thread())
        p.require(o.structural(os.fstat(self._directory)) == self._directory_identity
            == o.structural(os.stat(self._prefix + "-journal", dir_fd=self._parent, follow_symlinks=False))
            and o.structural(os.fstat(self._grant)) == self._grant_identity and os.fstat(self._grant).st_nlink == 0)
        for _, fd in self.descriptors():
            p.require(not os.get_inheritable(fd))
        if not self._owner._released:
            p.require(o.names(self._directory) == ())
        if self._raw is None:
            p.require(os.fstat(self._grant).st_size == 0 and fcntl.fcntl(self._grant, fcntl.F_GET_SEALS) == 0)
        else:
            p.require(fcntl.fcntl(self._grant, fcntl.F_GET_SEALS) == o.SEALS and o.read(self._grant, 131072) == self._raw)

    def original(self):
        self.check(); p.require(self._raw is not None); return self._raw

    def seal(self, raw, native_originals):
        self.check(); p.require(not self._attempted); self._attempted = True
        item = self._owner._roles[self._role]
        p.require(item["grant_raw"] is not None and item["delivery_raw"] is not None)
        signed = p.fields(g.document(raw, 131072), ("payload", "signatureBase64url"))
        head = self._role == ROLES[0]
        effects = self._owner._effects
        cleanup = effects and self._role == EFFECT_ROLES[1]
        stem, purpose = (("Head", "native-shared-spool-head") if head else
            ("Cleanup", "native-active-effect-cleanup") if cleanup else ("Current", "native-spool-current-signature"))
        completion = effects or signed["payload"].get("apiVersion") == "serverware.nativeSpool" + stem + "Grant/v2"
        fields = HEAD + (("completion",) if completion else ()) + (("effects",) if effects else ()) if head else CURRENT
        value = p.fields(signed["payload"], fields)
        version = "1" if cleanup else "3" if effects else "2" if completion else "1"
        profile = "nativeActiveEffectCleanupGrant" if cleanup else "nativeSpool" + stem + "Grant"
        root, semantic = _root(item)
        p.require(value["apiVersion"] == "serverware." + profile + "/v" + version and value["purpose"] == purpose
            and value["guest"] == item["guest"] and value["runtimeConfigurationSha256"] == item["runtime"].sha
            and value["authorityHistoryManifestSha256"] == semantic and p.digest(value["initialTransitionHeadSha256"]) != p.sha(b""))
        payload_raw = g.canonical(value)
        domain = ("serverware." + profile + ".signature/v" + version).encode("ascii")
        message = b"serverware-signature-v1\0" + len(domain).to_bytes(8, "big") + domain + len(payload_raw).to_bytes(8, "big") + payload_raw
        root.verify(p.decoded(signed["signatureBase64url"], size=64), message)
        header = g.document(item["runtime_raw"], g.MAX_BYTES)["runtime"]
        own = "spoolHead" if head else "spoolCleanup" if cleanup else "spoolCurrent"
        p.require(header["apiVersion"] == ("serverware.policyCustodyServiceRuntimeConfig/v8" if effects else "serverware.policyCustodyServiceRuntimeConfig/v7")
            and header[own] == {"grantFdName": self._prefix + "-grant"}
            and all(other not in header for other in ("spoolHead", "spoolCurrent", "spoolCleanup") if other != own)
            and (not cleanup or header.get("dispatchAdmission") is None))
        native_roles = EFFECT_NATIVE if effects else COMPLETION_NATIVE if completion else NATIVE
        p.fields(native_originals, native_roles)
        if head:
            p.require(len(raw) <= 65536)
            scope = p.fields(value["scope"], SCOPE)
            commitment._scope_join(scope, g.document(item["grant_raw"], 65536)["payload"]["scope"])
            if completion:
                selected = p.fields(value["completion"], ("terminal", "regularAppendCapacity"))
                p.integer(selected["regularAppendCapacity"], minimum=1, maximum=32)
            if effects:
                selected = p.fields(value["effects"], EFFECTS)
                cleanup_item = self._owner._roles[EFFECT_ROLES[1]]
                p.require(cleanup_item["delivery_raw"] is not None)
                _epoch_key(selected["cleanupAuthorityEpoch"], EFFECT_ROLES[1], selected["cleanupPublicKeyBase64url"], cleanup_item)
                p.require(p.digest(selected["cleanupInitialTransitionHeadSha256"]) != p.sha(b""))
            public_keys = []
            for name, (role, api) in native_roles.items():
                public = p.fields(value["completion"]["terminal"] if name == "terminal" else
                    value["effects"][name] if name in EFFECT_KEYS else value[name],
                    ("role", "keyId", "keySpkiSha256", "publicKeyBase64url", "grantSha256"))
                key = p.decoded(public["publicKeyBase64url"], size=32)
                p.require(public["role"] == role and public["grantSha256"] == p.sha(native_originals[name])
                    and p.sha(bytes.fromhex("302a300506032b6570032100") + key) == public["keySpkiSha256"])
                public_keys.append(key)
                native = p.fields(g.document(native_originals[name], 65536), ("payload", "signature"))
                if name == "retrieval":
                    _require_retrieval_profile(native["payload"], expected_api=api, effects=effects,
                        proof_scope_original=value["proofScopeOriginal"])
                else:
                    p.require(native["payload"]["apiVersion"] == api)
                p.require(native["payload"]["assignmentPayloadSha256"] == scope["assignmentPayloadSha256"]
                    and native["payload"]["expectedPeer"] == header["expectedPeer"])
                p.decoded(native["signature"], size=64)
                p.require(native["payload"]["spoolScope" if name == "retrieval" else "scope"] == scope)
                if name in EFFECT_KEYS:
                    p.require(native["payload"]["commitRequest"] is None)
            if effects:
                cleanup_public = p.decoded(value["effects"]["cleanupPublicKeyBase64url"], size=32)
                p.require(len(set(public_keys + [cleanup_public])) == len(public_keys) + 1
                    and root.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw) not in public_keys + [cleanup_public])
                retrieved = g.document(native_originals["retrieval"], 65536)["payload"]
                p.require(p.fields(retrieved["effects"], EFFECT_KEYS) == {name: value["effects"][name] for name in EFFECT_KEYS})
            p.require(type(value["proofScopeOriginal"]) is str and value["proofScopeOriginal"].isascii()
                and len(value["proofScopeOriginal"]) <= 16384 and p.sha(value["proofScopeOriginal"].encode("ascii")) == scope["proofScopeSha256"])
        else:
            first = self._owner._spools[ROLES[0]]
            p.require(value["headGrantOriginal"] == first.original().decode("ascii") and native_originals == first._native)
            p.require(first._payload["apiVersion"] == "serverware.nativeSpoolHeadGrant/v" + ("3" if effects else version))
            scope = first._payload["scope"]
            if effects:
                durable = self._owner._roles[ROLES[0]]
                _epoch_key(value["durableAuthorityEpoch"], ROLES[0], value["durablePublicKeyBase64url"], durable)
                if cleanup:
                    p.require(value["initialTransitionHeadSha256"] == first._payload["effects"]["cleanupInitialTransitionHeadSha256"])
                else:
                    sealed_cleanup = self._owner._spools[EFFECT_ROLES[1]]
                    sealed_cleanup.original()
                    p.require(value["durableAuthorityEpoch"] == sealed_cleanup._payload["durableAuthorityEpoch"]
                        and value["durablePublicKeyBase64url"] == sealed_cleanup._payload["durablePublicKeyBase64url"])
        p.require(p.ns(item["guest"]["issuedAtBoottimeNs"]) <= scope["issuedAtBoottimeNanos"] <= o.clock()
            < scope["expiresAtBoottimeNanos"] <= self._owner._launcher._lifetime and o.clock() < self._owner._launcher._startup)
        offset = 0
        while offset < len(raw):
            count = os.pwrite(self._grant, raw[offset:], offset); p.require(count > 0); offset += count
        fcntl.fcntl(self._grant, fcntl.F_ADD_SEALS, o.SEALS)
        p.require(o.read(self._grant, 131072) == raw)
        self._raw, self._payload, self._native = bytes(raw), value, {k: bytes(v) for k, v in native_originals.items()}
        self.check()


def _release_current(owner):
    from serverware.custody_generation_inputs import GenerationInputs
    p.require(type(owner) is GenerationInputs and owner._spool
        and tuple(owner._spools) == (EFFECT_ROLES if owner._effects else ROLES))
    for value in owner._spools.values():
        value.original()
    first = owner._spools[ROLES[0]]
    p.require(owner._spools[ROLES[1]]._payload["headGrantOriginal"] == first.original().decode("ascii")
        and o.clock() < first._payload["scope"]["expiresAtBoottimeNanos"])
    if owner._effects:
        p.require(owner._spools[EFFECT_ROLES[1]]._payload["headGrantOriginal"] == first.original().decode("ascii")
            and first._payload["apiVersion"] == "serverware.nativeSpoolHeadGrant/v3")


def bridge_selection(owner):
    _release_current(owner)
    version = "3" if owner._effects else "2" if owner._spools[ROLES[0]]._payload["apiVersion"] == "serverware.nativeSpoolHeadGrant/v2" else "1"
    result = {"apiVersion": "serverware.nativeSpoolServices/v" + version, "headGrantOriginal": owner._spools[ROLES[0]].original().decode("ascii"),
        "currentGrantOriginal": owner._spools[ROLES[1]].original().decode("ascii"), "originFdName": "generation-origin"}
    if owner._effects:
        result["cleanupGrantOriginal"] = owner._spools[EFFECT_ROLES[1]].original().decode("ascii")
    return result


def _require_native_release(launcher, cohort, transfers):
    p.require(not cohort.endpoint_driver_selected())
    return _require_release(launcher, cohort, transfers, inputs=None)


def _require_endpoint_release(launcher, cohort, driver, inputs, transfers):
    from serverware.native_shadow_driver_inputs import OperationalInputs
    p.require(cohort.endpoint_driver_selected() and type(inputs) is OperationalInputs
        and cohort._external_driver.driver is driver and inputs._driver is driver
        and driver._prepared_inputs is inputs and not inputs._begun)
    inputs.check(); driver.check()
    return _require_release(launcher, cohort, transfers, inputs=inputs)


def _require_release(launcher, cohort, transfers, *, inputs):
    from serverware.native_shadow_proof_cohort_control import ParkedProofCohort, RetainedActivationFds
    p.require(type(cohort) is ParkedProofCohort and cohort.spool_selected() and type(transfers) is dict)
    terminal = cohort.terminal_selected()
    effects = cohort.effects_selected()
    roles = {"retrieval", "persistence", "trustedTime", "generationInstall", "bridge", "commitRequest", "ingressAdmission"}
    if inputs is not None:
        p.require(effects and cohort.endpoint_driver_selected())
        roles.remove("bridge")
    p.require((not effects or terminal) and set(transfers) == (roles | ({"terminalAppend"} if terminal else set())
        | (set(EFFECT_KEYS) if effects else set())))
    owner = launcher._input_owner; _release_current(owner)
    p.require(owner._released and launcher._spool and owner._effects == effects == launcher._effects)
    expected = bridge_selection(owner)
    p.require(expected["apiVersion"] == ("serverware.nativeSpoolServices/v3" if effects else "serverware.nativeSpoolServices/v2" if terminal else "serverware.nativeSpoolServices/v1"))
    native_roles = (("ingress", "ingressAdmission"), ("ledger", "commitRequest"), ("retrieval", "retrieval"))
    selected_native = native_roles + ((("terminal", "terminalAppend"),) if terminal else ())
    if effects:
        selected_native += tuple((name, name) for name in EFFECT_KEYS)
    for name, role in selected_native:
        value = transfers[role]
        p.require(type(value) is RetainedActivationFds and value._cohort is cohort and value._role == role)
        value.check(); p.require(value._grant_bytes == owner._spools[ROLES[0]]._native[name])
    if inputs is None:
        bridge = transfers["bridge"]
        p.require(type(bridge) is RetainedActivationFds and bridge._cohort is cohort and bridge._role == "bridge")
        bridge.check()
    ledger = g.document(transfers["commitRequest"]._grant_bytes, 65536)["payload"]
    pin = ledger["commitRequest"]; g.c9._pin(pin)
    companion = o.Original(pin["path"], 65536, sha=pin["sha256"]); owner._originals.append(companion)
    p.require(companion.read() == owner._commitments[ROLES[0]]._native == owner._commitments[ROLES[1]]._native)
    scopes = [g.document(owner._roles[role]["grant_raw"], 65536)["payload"]["scope"] for role in g.ROLES]
    p.require(all(scope == scopes[0] for scope in scopes)); commitment._same_cohort(owner, scopes[0])
    expected_commitment = {"apiVersion": "serverware.nativeCommitRequestServices/v1",
        "serviceGrantOriginals": {role: owner._commitments[role].original().decode("ascii") for role in ROLES}}
    if inputs is None:
        pin = g.document(bridge._delivery_bytes, 65536)["payload"]["runtimeConfig"]
        original = o.Original(pin["path"], g.MAX_BYTES, sha=pin["sha256"]); owner._originals.append(original)
        runtime = g.document(original.read(), g.MAX_BYTES)
    else:
        # This raw original and these descriptors belong to the actual
        # already-verified OperationalInputs, not a fake bridge transfer.
        inputs.check()
        runtime = g.document(inputs._runtime_raw, g.MAX_BYTES)
    p.require(runtime["apiVersion"] == ("serverware.policyCustodyProductionRpcRuntime/v9" if effects else "serverware.policyCustodyProductionRpcRuntime/v8" if terminal else "serverware.policyCustodyProductionRpcRuntime/v7") and runtime["spool"] == expected
        and runtime["commitRequest"] == expected_commitment)
    from serverware.native_shadow_spool_inputs import SpoolInputs
    p.require(type(cohort._spool_resources) is SpoolInputs)
    if inputs is None:
        cohort._spool_resources.require_release(transfers, owner._spools[ROLES[0]].original())
    else:
        cohort._spool_resources.require_endpoint_release(transfers, owner._spools[ROLES[0]].original(), inputs)
