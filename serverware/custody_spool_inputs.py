"""Real fixed DRS/current journal and sealed-grant owners for spool/v7.

Only supplied independently signed grants are admitted. This module creates no
key, head, native signature, generation, or successful effect observation.
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


def sign_delivery(**values):
    p.require(values["role"] in ROLES)
    return g._sign_delivery(**values, commitment=True, spool=True)


def sign_generation_grant(**values):
    p.require(values["guest"]["serviceRole"] in ROLES)
    return g._sign_grant(**values, commitment=True, spool=True)


def _root(item):
    history = p.fields(g.document(item["history_raw"], g.MAX_BYTES), g.HISTORY)
    header = g.document(item["runtime_raw"], g.MAX_BYTES)["runtime"]
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
        p.require(cls is RoleInputs and type(owner) is GenerationInputs and owner._spool and role in ROLES)
        value = cls()
        value._owner, value._role, value._parent = owner, role, parent
        value._prefix = "spool-head" if role == ROLES[0] else "spool-current"
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
        value = p.fields(signed["payload"], HEAD if head else CURRENT)
        stem, purpose = ("Head", "native-shared-spool-head") if head else ("Current", "native-spool-current-signature")
        root, semantic = _root(item)
        p.require(value["apiVersion"] == "serverware.nativeSpool" + stem + "Grant/v1" and value["purpose"] == purpose
            and value["guest"] == item["guest"] and value["runtimeConfigurationSha256"] == item["runtime"].sha
            and value["authorityHistoryManifestSha256"] == semantic and p.digest(value["initialTransitionHeadSha256"]) != p.sha(b""))
        payload_raw = g.canonical(value)
        domain = ("serverware.nativeSpool" + stem + "Grant.signature/v1").encode("ascii")
        message = b"serverware-signature-v1\0" + len(domain).to_bytes(8, "big") + domain + len(payload_raw).to_bytes(8, "big") + payload_raw
        root.verify(p.decoded(signed["signatureBase64url"], size=64), message)
        header = g.document(item["runtime_raw"], g.MAX_BYTES)["runtime"]
        own, other = ("spoolHead", "spoolCurrent") if head else ("spoolCurrent", "spoolHead")
        p.require(header["apiVersion"] == "serverware.policyCustodyServiceRuntimeConfig/v7"
            and header[own] == {"grantFdName": self._prefix + "-grant"} and other not in header)
        p.fields(native_originals, NATIVE)
        if head:
            p.require(len(raw) <= 65536)
            scope = p.fields(value["scope"], SCOPE)
            commitment._scope_join(scope, g.document(item["grant_raw"], 65536)["payload"]["scope"])
            for name, (role, api) in NATIVE.items():
                public = p.fields(value[name], ("role", "keyId", "keySpkiSha256", "publicKeyBase64url", "grantSha256"))
                key = p.decoded(public["publicKeyBase64url"], size=32)
                p.require(public["role"] == role and public["grantSha256"] == p.sha(native_originals[name])
                    and p.sha(bytes.fromhex("302a300506032b6570032100") + key) == public["keySpkiSha256"])
                native = p.fields(g.document(native_originals[name], 65536), ("payload", "signature"))
                p.require(native["payload"]["apiVersion"] == api and native["payload"]["assignmentPayloadSha256"] == scope["assignmentPayloadSha256"]
                    and native["payload"]["expectedPeer"] == header["expectedPeer"])
                p.decoded(native["signature"], size=64)
                p.require(native["payload"]["spoolScope" if name == "retrieval" else "scope"] == scope)
            p.require(type(value["proofScopeOriginal"]) is str and value["proofScopeOriginal"].isascii()
                and len(value["proofScopeOriginal"]) <= 16384 and p.sha(value["proofScopeOriginal"].encode("ascii")) == scope["proofScopeSha256"])
        else:
            first = self._owner._spools[ROLES[0]]
            p.require(value["headGrantOriginal"] == first.original().decode("ascii") and native_originals == first._native)
            scope = first._payload["scope"]
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
    p.require(type(owner) is GenerationInputs and owner._spool and tuple(owner._spools) == ROLES)
    for value in owner._spools.values():
        value.original()
    first = owner._spools[ROLES[0]]
    p.require(owner._spools[ROLES[1]]._payload["headGrantOriginal"] == first.original().decode("ascii")
        and o.clock() < first._payload["scope"]["expiresAtBoottimeNanos"])


def bridge_selection(owner):
    _release_current(owner)
    return {"apiVersion": "serverware.nativeSpoolServices/v1", "headGrantOriginal": owner._spools[ROLES[0]].original().decode("ascii"),
        "currentGrantOriginal": owner._spools[ROLES[1]].original().decode("ascii"), "originFdName": "generation-origin"}


def _require_native_release(launcher, cohort, transfers):
    from serverware.native_shadow_proof_cohort_control import ParkedProofCohort, RetainedActivationFds
    p.require(type(cohort) is ParkedProofCohort and cohort.spool_selected() and type(transfers) is dict
        and set(transfers) == {"retrieval", "persistence", "trustedTime", "generationInstall", "bridge", "commitRequest", "ingressAdmission"})
    owner = launcher._input_owner; _release_current(owner)
    p.require(owner._released and launcher._spool)
    expected = bridge_selection(owner)
    for name, role in (("ingress", "ingressAdmission"), ("ledger", "commitRequest"), ("retrieval", "retrieval")):
        value = transfers[role]
        p.require(type(value) is RetainedActivationFds and value._cohort is cohort and value._role == role)
        value.check(); p.require(value._grant_bytes == owner._spools[ROLES[0]]._native[name])
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
    pin = g.document(bridge._delivery_bytes, 65536)["payload"]["runtimeConfig"]
    original = o.Original(pin["path"], g.MAX_BYTES, sha=pin["sha256"]); owner._originals.append(original)
    runtime = g.document(original.read(), g.MAX_BYTES)
    p.require(runtime["apiVersion"] == "serverware.policyCustodyProductionRpcRuntime/v7" and runtime["spool"] == expected
        and runtime["commitRequest"] == expected_commitment)
    from serverware.native_shadow_spool_inputs import SpoolInputs
    p.require(type(cohort._spool_resources) is SpoolInputs)
    cohort._spool_resources.require_release(transfers, owner._spools[ROLES[0]].original())
