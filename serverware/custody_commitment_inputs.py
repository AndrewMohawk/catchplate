"""Closed two-role commitment resources on the genuine ordinary five owner.

Public signed originals are consumed, never promoted from unsigned payloads.
Native quote/key admission and service history/currentness remain their actual
receivers' duties. This producer grants no dispatch permission by itself.
"""
import fcntl
import os
import threading

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from serverware import custody_generation_grants as g
from serverware import custody_generation_originals as o
from serverware import native_shadow_commitment_artifacts as a

p = g.p
_TOKEN = object()
ROLES = (g.ROLES[0], g.ROLES[3])


def prepare(launcher, *, business_descriptors):
    from serverware.custody_generation_business import BusinessResources
    from serverware.custody_generation_launch import FiveServiceLaunch
    from serverware.custody_generation_inputs import GenerationInputs
    p.require(type(launcher) is FiveServiceLaunch and launcher._commitment
        and type(launcher._business_resources) is BusinessResources)
    resources = launcher._business_resources
    resources.check()
    expected = {role: {"listener": resources._roles[role]["listener"].fileno(),
        **resources._roles[role]["directories"]} for role in g.ROLES}
    p.require(business_descriptors == expected)
    return GenerationInputs._prepare(launcher, business_descriptors=business_descriptors)


class _RoleInputs:
    def __init__(self, token, owner, role):
        p.require(token is _TOKEN)
        self._owner, self._role = owner, role
        self._attempted = False
        self._raw = self._native = self._payload = None

    @classmethod
    def prepare(cls, owner, role, parent, cold):
        from serverware.custody_generation_inputs import GenerationInputs, _persistent
        p.require(cls is _RoleInputs and type(owner) is GenerationInputs
            and owner._commitment and role in ROLES)
        selected = cls(_TOKEN, owner, role)
        # O_EXCL-like mkdir refusal: no adoption, repair or fabricated records.
        os.mkdir("dispatch-journal", 0o700, dir_fd=parent)
        directory = os.open("dispatch-journal", o.FLAGS | os.O_DIRECTORY, dir_fd=parent)
        owner._fds.append(directory)
        os.fchown(directory, cold["uid"], cold["gid"]); os.fchmod(directory, 0o700)
        _persistent(directory); p.require(o.names(directory) == ())
        fcntl.flock(directory, fcntl.LOCK_EX | fcntl.LOCK_NB)
        os.fsync(directory); os.fsync(parent)
        grant = os.memfd_create("custody-commit-request-" + role, os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        owner._fds.append(grant)
        os.fchown(grant, cold["uid"], cold["gid"]); os.fchmod(grant, 0o600)
        p.require(os.fstat(grant).st_size == 0 and os.fstat(grant).st_nlink == 0
            and fcntl.fcntl(grant, fcntl.F_GET_SEALS) == 0)
        selected._parent, selected._directory, selected._grant = parent, directory, grant
        selected._directory_identity = o.structural(os.fstat(directory))
        selected._grant_identity = o.structural(os.fstat(grant))
        return selected

    def descriptors(self):
        return (("dispatch-journal", self._directory), ("dispatch-grant", self._grant))

    def check(self):
        p.require(not self._owner._closed
            and o.structural(os.fstat(self._directory)) == self._directory_identity
            and o.structural(os.stat("dispatch-journal", dir_fd=self._parent, follow_symlinks=False))
                == self._directory_identity
            and o.structural(os.fstat(self._grant)) == self._grant_identity
            and os.fstat(self._grant).st_nlink == 0)
        for _, fd in self.descriptors():
            p.require(not os.get_inheritable(fd))
        if not self._owner._released:
            p.require(o.names(self._directory) == ())
        if self._raw is None:
            p.require(os.fstat(self._grant).st_size == 0 and fcntl.fcntl(self._grant, fcntl.F_GET_SEALS) == 0)
        else:
            p.require(fcntl.fcntl(self._grant, fcntl.F_GET_SEALS) == o.SEALS
                and o.read(self._grant, 65536) == self._raw)

    def original(self):
        self.check(); p.require(self._raw is not None)
        return self._raw

    def seal(self, raw, native_raw):
        self.check()
        p.require(not self._attempted and threading.current_thread() is threading.main_thread())
        self._attempted = True  # before parsing or first possible persistent write
        item = self._owner._roles[self._role]
        p.require(item["delivery"] is not None and item["grant_raw"] is not None)
        signed = p.fields(g.document(raw, 65536), ("payload", "signatureBase64url"))
        value = p.fields(signed["payload"], a.SERVICE_FIELDS)
        runtime = g.document(item["runtime_raw"], g.MAX_BYTES)["runtime"]
        history = p.fields(g.document(item["history_raw"], g.MAX_BYTES), g.HISTORY)
        c9 = g.document(item["delivery_raw"], 65536)["payload"]
        scope = a.scope_original(g.canonical(value["scope"]))
        p.require(value["apiVersion"] == "serverware.custodyCommitRequestServiceGrant/v1"
            and value["purpose"] == "commit-request-service-transition" and value["serviceRole"] == self._role
            and value["guest"] == item["guest"]
            and value["runtimeConfigurationSha256"] == item["runtime"].sha
            and runtime["apiVersion"] == ("serverware.policyCustodyServiceRuntimeConfig/v7" if self._owner._spool else "serverware.policyCustodyServiceRuntimeConfig/v6")
            and runtime["generationAdmission"] == {"grantFdName": "generation-grant"}
            and runtime["dispatchAdmission"] == {"grantFdName": "dispatch-grant"})
        semantic = p.framed(b"serverware.policyCustodyAuthorityHistoryManifest/v3",
            (g.canonical([history[field] for field in g.HISTORY[:-1]]),))
        p.require(history["apiVersion"] == "serverware.policyCustodyAuthorityHistory/v3"
            and history["authorityRole"] == {"authorityKind": "isolated-service", "role": self._role}
            and history["manifestSha256"] == semantic == runtime["authorityHistoryManifestSha256"]
                == value["authorityHistoryManifestSha256"])
        retained = [entry for entry in c9["credentials"] if entry["name"] == runtime["authorityHistoryManifestCredential"]]
        p.require(len(retained) == 1 and retained[0]["signing"] is None
            and retained[0]["original"]["sha256"] == p.sha(item["history_raw"])
            and retained[0]["length"] == len(item["history_raw"]))
        root = p.fields(history["rootAuthority"], ("keyId", "keySpkiSha256", "publicKeySpkiBase64"))
        der = p.decoded(root["publicKeySpkiBase64"], size=44)
        key = serialization.load_der_public_key(der)
        p.require(isinstance(key, Ed25519PublicKey)
            and der == key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
            and p.sha(der) == root["keySpkiSha256"] == runtime["authorityHistoryRootKeySpkiSha256"]
            and p.digest(root["keyId"]) == runtime["authorityHistoryRootKeyId"])
        ledger = p.decoded(value["nativeLedgerPublicKeyBase64url"], size=32)
        p.require(ledger != bytes(32) and p.digest(value["nativeLedgerKeyId"]) != p.sha(b"")
            and p.sha(bytes.fromhex("302a300506032b6570032100") + ledger) == value["nativeLedgerKeySpkiSha256"]
            and ledger != key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            and p.digest(value["initialHeadSha256"]) != p.sha(b""))
        signing = [entry["signing"]["publicKeyBase64url"] for entry in c9["credentials"] if entry["signing"] is not None]
        p.require(p.encoded(ledger) not in signing
            and p.encoded(key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)) not in signing)
        payload_raw = g.canonical(value)
        message = b"serverware-signature-v1\0" + len(a.SERVICE_DOMAIN).to_bytes(8, "big") + a.SERVICE_DOMAIN
        message += len(payload_raw).to_bytes(8, "big") + payload_raw
        key.verify(p.decoded(signed["signatureBase64url"], size=64), message)
        # This exact public native original is bound by the independently
        # verified service-root signature. Its own supervisor/quote/currentness
        # checks are still performed by the actual native receiver, not inferred
        # from the envelope's shape or a local wall-clock timestamp here.
        native = p.fields(g.document(native_raw, 65536), ("payload", "signature"))
        np = p.fields(native["payload"], a.NATIVE_FIELDS)
        p.decoded(native["signature"], size=64); p.guest(np["guest"])
        p.require(value["nativeGrantSha256"] == p.sha(native_raw) and np["scope"] == scope
            and np["apiVersion"] == "serverware.nativeShadowCommitRequestServiceAssignment/v1"
            and np["purpose"] == "native-shadow-ledger-commit-request"
            and np["expectedPeer"] == runtime["expectedPeer"])
        generation = g.document(item["grant_raw"], 65536)["payload"]
        _scope_join(scope, generation["scope"])
        now = o.clock()
        p.require(p.ns(item["guest"]["issuedAtBoottimeNs"]) <= generation["issuedAtBoottimeNanos"]
            <= scope["issuedAtBoottimeNanos"] <= now < scope["expiresAtBoottimeNanos"]
            <= generation["expiresAtBoottimeNanos"] <= self._owner._launcher._lifetime
            and now < self._owner._launcher._startup)
        offset = 0
        while offset < len(raw):
            count = os.pwrite(self._grant, raw[offset:], offset); p.require(count > 0); offset += count
        fcntl.fcntl(self._grant, fcntl.F_ADD_SEALS, o.SEALS)
        p.require(o.read(self._grant, 65536) == raw and fcntl.fcntl(self._grant, fcntl.F_GET_SEALS) == o.SEALS)
        self._raw, self._native, self._payload = bytes(raw), bytes(native_raw), value
        self.check()


def _scope_join(dispatch, generation):
    for destination, source in (
        ("productionConfigurationBindingSha256", "successorConfigurationBindingSha256"),
        ("kernelDriverIdentitySha256", "kernelDriverIdentitySha256"),
        ("retainedDescriptorSetSha256", "retainedDescriptorSetSha256"),
        ("driverGenerationReceiptSha256", "driverGenerationReceiptSha256"),
        ("assignmentPayloadSha256", "assignmentPayloadSha256"),
        ("assignmentRevision", "assignmentRevision"),
    ):
        p.require(dispatch[destination] == generation[source])


def _same_cohort(owner, generation_scope):
    p.require(owner._commitment and tuple(owner._commitments) == ROLES)
    values = [owner._commitments[role] for role in ROLES]
    for value in values:
        value.original(); _scope_join(value._payload["scope"], generation_scope)
        p.require(o.clock() < value._payload["scope"]["expiresAtBoottimeNanos"])
    for field in ("scope", "nativeGrantSha256", "nativeLedgerKeyId",
                  "nativeLedgerKeySpkiSha256", "nativeLedgerPublicKeyBase64url"):
        p.require(values[0]._payload[field] == values[1]._payload[field])
    p.require(values[0]._native == values[1]._native)


def bridge_selection(owner):
    """Exact retained public originals for independently approved bridge input."""
    from serverware.custody_generation_inputs import GenerationInputs
    p.require(type(owner) is GenerationInputs and owner._launcher._input_owner is owner)
    owner.check()
    p.require(owner._commitment and not owner._taken)
    scopes = [g.document(owner._roles[role]["grant_raw"], 65536)["payload"]["scope"] for role in g.ROLES]
    p.require(all(scope == scopes[0] for scope in scopes)); _same_cohort(owner, scopes[0])
    return {"apiVersion": "serverware.nativeCommitRequestServices/v1",
        "serviceGrantOriginals": {role: owner._commitments[role].original().decode("ascii") for role in ROLES}}


def _require_native_release(launcher, cohort, transfers):
    from serverware.native_shadow_proof_cohort_control import ParkedProofCohort, RetainedActivationFds
    p.require(type(cohort) is ParkedProofCohort and cohort.commitment_selected() and type(transfers) is dict
        and set(transfers) == {"retrieval", "persistence", "trustedTime", "generationInstall", "bridge", "commitRequest"})
    owner = launcher._input_owner
    p.require(owner is not None and owner._commitment and owner._released)
    expected = {"apiVersion": "serverware.nativeCommitRequestServices/v1",
        "serviceGrantOriginals": {role: owner._commitments[role].original().decode("ascii") for role in ROLES}}
    for role in ("bridge", "commitRequest"):
        transfer = transfers[role]
        p.require(type(transfer) is RetainedActivationFds and transfer._cohort is cohort and transfer._role == role)
        transfer.check()
    p.require(transfers["commitRequest"]._grant_bytes == owner._commitments[ROLES[0]]._native)
    signed = g.document(transfers["bridge"]._delivery_bytes, 65536)
    pin = signed["payload"]["runtimeConfig"]; g.c9._pin(pin)
    original = o.Original(pin["path"], g.MAX_BYTES, sha=pin["sha256"])
    owner._originals.append(original)
    runtime = g.document(original.read(), g.MAX_BYTES)
    p.require(runtime["apiVersion"] == "serverware.policyCustodyProductionRpcRuntime/v6"
        and runtime["commitRequest"] == expected)
    _release_current(owner)


def _release_current(owner):
    from serverware.custody_generation_inputs import GenerationInputs
    p.require(type(owner) is GenerationInputs and owner._launcher._input_owner is owner)
    owner.check()
    scopes = [g.document(owner._roles[role]["grant_raw"], 65536)["payload"]["scope"] for role in g.ROLES]
    p.require(all(scope == scopes[0] for scope in scopes)); _same_cohort(owner, scopes[0])
