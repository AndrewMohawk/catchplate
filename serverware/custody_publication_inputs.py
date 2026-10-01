"""Actual adopted DRS/CSA publication capabilities, allocated before C9.

An independently signed ordinary root grant authorizes exact public originals.
The native receivers still authenticate adoption, assigned keys and history.
This owner never creates a baseline, writes a journal record or reads a seed.
"""
import fcntl
import os
import threading
import time

from cryptography.hazmat.primitives import serialization

from serverware import custody_generation_grants as g
from serverware import custody_generation_originals as o
from serverware import custody_commitment_inputs as commitment
from serverware import custody_spool_inputs as spool
from serverware import native_pilot_adopted_service_authority as native
from serverware import native_pilot_adopted_ordinary as ordinary

p = g.p
ROLES = (g.ROLES[0], g.ROLES[3])
MAX_GRANT = 3 * 1024 * 1024
API = "serverware.nativePublicationServiceGrant/v2"
DOMAIN = b"serverware.nativePublicationServiceGrant.signature/v2"
FIELDS = ("apiVersion", "purpose", "serviceRole", "guest", "runtimeConfigurationSha256",
    "authorityHistoryManifestSha256", "admission", "native", "retrieval", "initialTransitionHeadSha256",
    "initialDurableTransitionHeadSha256", "durableAuthorityEpoch", "durablePublicKeyBase64url")
ADMISSION_FIELDS = ("scope", "proofScopeOriginal", "priorReceiptOriginal", "firstIngressSequence", "lastIngressSequence", "adoption")
KEY_FIELDS = ("role", "keyId", "keySpkiSha256", "publicKeyBase64url", "grantSha256")
_TOKEN = object()


def _key(value, role, raw):
    p.fields(value, KEY_FIELDS)
    public = p.decoded(value["publicKeyBase64url"], size=32)
    p.require(value["role"] == role and public != bytes(32)
        and p.digest(value["keyId"]) != p.sha(b"") and value["grantSha256"] == p.sha(raw)
        and value["keySpkiSha256"] == p.sha(bytes.fromhex("302a300506032b6570032100") + public))
    return public


def grant_values(raw, *, role, item, durable_item, native_original, retrieval_original, now, now_unix):
    """Root signature and retained-original association; not native admission."""
    p.require(role in ROLES)
    signed = p.fields(g.document(raw, MAX_GRANT), ("payload", "signatureBase64url"))
    value = p.fields(signed["payload"], FIELDS)
    header = g.document(item["runtime_raw"], g.MAX_BYTES)["runtime"]
    root, semantic = spool._root(item)
    p.require(value["apiVersion"] == API and value["purpose"] == "native-policy-publication-state"
        and value["serviceRole"] == role == item["guest"]["serviceRole"]
        and value["guest"] == item["guest"]
        and value["runtimeConfigurationSha256"] == item["guest"]["runtimeConfigurationSha256"] == p.sha(item["runtime_raw"])
        and value["authorityHistoryManifestSha256"] == semantic
        and header["apiVersion"] == ordinary.RUNTIME_API
        and header["publicationAdmission"] == {"grantFdName": "publication-grant"})
    # Native signed service payloads use policy-shadow's signed-i64 codec.
    # The broader original reader is not authority to emit another preimage.
    payload_raw = p.canonical(value)
    message = b"serverware-signature-v1\0" + len(DOMAIN).to_bytes(8, "big") + DOMAIN + len(payload_raw).to_bytes(8, "big") + payload_raw
    root.verify(p.decoded(signed["signatureBase64url"], size=64), message)
    admission = p.fields(value["admission"], ADMISSION_FIELDS)
    scope = p.fields(admission["scope"], spool.SCOPE)
    commitment._scope_join(scope, g.document(item["grant_raw"], 65536)["payload"]["scope"])
    native_payload = native.grant_original("publication", native_original)["payload"]
    retrieval = native.grant_original("retrieval", retrieval_original)["payload"]
    p.require(native_payload["admission"] == admission == retrieval["publication"]["admission"]
        and retrieval["publication"]["native"] == value["native"]
        and native_payload["retrieval"] == {name: value["retrieval"][name]
            for name in ("keyId", "keySpkiSha256", "publicKeyBase64url")}
        and native_payload["retrievalGuest"] == retrieval["guest"]
        and native_payload["expectedPeer"] == retrieval["expectedPeer"] == header["expectedPeer"]
        and retrieval["spoolScope"] == scope)
    native_key = _key(value["native"], "custody-publication-reconciliation", native_original)
    retrieval_key = _key(value["retrieval"], "custody-retrieval-response", retrieval_original)
    durable_header = g.document(durable_item["runtime_raw"], g.MAX_BYTES)["runtime"]
    from serverware import native_pilot_ordinary_initial_profile as initial
    durable_history = initial.runtime_manifest(durable_item["history_raw"], runtime=durable_header, guest=durable_item["guest"])
    epoch = durable_history["firstRetainedEpoch"]["retainedEpoch"]
    spool._epoch_key(value["durableAuthorityEpoch"], ROLES[0], value["durablePublicKeyBase64url"], durable_item)
    p.require(value["durableAuthorityEpoch"] == ordinary.epoch_reference(epoch)
        and retrieval["publication"]["drsAuthorityEpoch"] == value["durableAuthorityEpoch"]
        and retrieval["publication"]["drsPublicKeyBase64url"] == value["durablePublicKeyBase64url"])
    durable_key = p.decoded(value["durablePublicKeyBase64url"], size=32)
    root_raw = root.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    p.require(len({native_key, retrieval_key, durable_key, root_raw}) == 4)
    for name in ("initialTransitionHeadSha256", "initialDurableTransitionHeadSha256"):
        p.require(p.digest(value[name]) != p.sha(b""))
    if role == ROLES[0]:
        p.require(value["initialTransitionHeadSha256"] == value["initialDurableTransitionHeadSha256"])
    p.require(p.ns(item["guest"]["issuedAtBoottimeNs"]) <= scope["issuedAtBoottimeNanos"] <= now
        < scope["expiresAtBoottimeNanos"] <= p.ns(item["guest"]["lifetimeDeadlineBoottimeNs"]))
    expiry = min(native_payload["expiresAtUnixNanos"], retrieval["expiresAtUnixNanos"],
        g.document(item["grant_raw"], 65536)["payload"]["scope"]["installationExpiresAtUnixNanos"])
    p.require(max(native_payload["issuedAtUnixNanos"], retrieval["issuedAtUnixNanos"]) <= now_unix < expiry)
    return value, expiry


class RoleInputs:
    def __init__(self, token, owner, role, parent):
        p.require(token is _TOKEN)
        self._owner, self._role, self._parent = owner, role, parent
        self._raw = self._payload = self._native = self._retrieval = self._expiry = None
        self._previous_boot = self._previous_wall = None
        self._attempted = False

    @classmethod
    def prepare(cls, owner, role, parent, cold):
        from serverware.custody_generation_inputs import GenerationInputs, _persistent
        p.require(cls is RoleInputs and type(owner) is GenerationInputs and owner._adoption
            and role in ROLES and owner._effects and not owner._released)
        value = cls(_TOKEN, owner, role, parent)
        os.mkdir("publication-journal", 0o700, dir_fd=parent)
        fd = os.open("publication-journal", o.FLAGS | os.O_DIRECTORY, dir_fd=parent)
        owner._fds.append(fd); value._directory = fd
        os.fchown(fd, cold["uid"], cold["gid"]); os.fchmod(fd, 0o700)
        _persistent(fd); p.require(o.names(fd) == ())
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB); os.fsync(fd); os.fsync(parent)
        fd = os.memfd_create("publication-grant", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        owner._fds.append(fd); value._grant = fd
        os.fchown(fd, cold["uid"], cold["gid"]); os.fchmod(fd, 0o600)
        value._directory_identity = o.structural(os.fstat(value._directory))
        value._grant_identity = o.structural(os.fstat(value._grant))
        value.check(); return value

    def descriptors(self):
        return (("publication-journal", self._directory), ("publication-grant", self._grant))

    def check(self):
        p.require(not self._owner._closed and threading.current_thread() is threading.main_thread())
        p.require(o.structural(os.fstat(self._directory)) == self._directory_identity
            == o.structural(os.stat("publication-journal", dir_fd=self._parent, follow_symlinks=False))
            and o.structural(os.fstat(self._grant)) == self._grant_identity and os.fstat(self._grant).st_nlink == 0)
        p.require(all(not os.get_inheritable(fd) for _, fd in self.descriptors()))
        if not self._owner._released:
            p.require(o.names(self._directory) == ())
        if self._raw is None:
            p.require(os.fstat(self._grant).st_size == 0 and fcntl.fcntl(self._grant, fcntl.F_GET_SEALS) == 0)
        else:
            p.require(fcntl.fcntl(self._grant, fcntl.F_GET_SEALS) == o.SEALS
                and o.read(self._grant, MAX_GRANT) == self._raw)
            before = o.clock(); wall = time.time_ns(); after = o.clock()
            p.require(self._previous_boot <= before <= after < self._payload["admission"]["scope"]["expiresAtBoottimeNanos"]
                and self._previous_wall <= wall < self._expiry)
            self._previous_boot, self._previous_wall = after, wall

    def original(self):
        self.check(); p.require(self._raw is not None); return self._raw

    def seal(self, raw, native_original, retrieval_original):
        self.check(); p.require(not self._attempted); self._attempted = True
        self._owner.check()
        item = self._owner._roles[self._role]
        self._owner._spools[self._role].original()
        p.require(retrieval_original == self._owner._spools[ROLES[0]]._native["retrieval"])
        from serverware import native_pilot_native_service_authority as assigned
        native_payload = native.grant_original("publication", native_original)["payload"]
        for role, member in self._owner._roles.items():
            assigned.require_ordinary_member(native_payload, role, runtime_raw=member["runtime_raw"],
                history_raw=member["history_raw"], generation_raw=member["grant_raw"])
        checked_boot, checked_wall = o.clock(), time.time_ns()
        value, expiry = grant_values(raw, role=self._role, item=item,
            durable_item=self._owner._roles[ROLES[0]], native_original=native_original,
            retrieval_original=retrieval_original, now=checked_boot, now_unix=checked_wall)
        if self._role == ROLES[1]:
            durable = self._owner._publications[ROLES[0]]; durable.original()
            p.require(value["initialDurableTransitionHeadSha256"] == durable._payload["initialTransitionHeadSha256"]
                and value["admission"] == durable._payload["admission"]
                and native_original == durable._native and retrieval_original == durable._retrieval)
        self._owner.check()
        offset = 0
        while offset < len(raw):
            count = os.pwrite(self._grant, raw[offset:], offset); p.require(count > 0); offset += count
        fcntl.fcntl(self._grant, fcntl.F_ADD_SEALS, o.SEALS)
        p.require(o.read(self._grant, MAX_GRANT) == raw)
        self._raw, self._payload, self._expiry = bytes(raw), value, expiry
        self._previous_boot, self._previous_wall = checked_boot, checked_wall
        self._native, self._retrieval = bytes(native_original), bytes(retrieval_original)
        self._owner.check(); self.check()


def release_current(owner):
    from serverware.custody_generation_inputs import GenerationInputs
    p.require(type(owner) is GenerationInputs and owner._adoption and tuple(owner._publications) == ROLES)
    for value in owner._publications.values():
        value.original()
    first, second = (owner._publications[role] for role in ROLES)
    p.require(first._payload["admission"] == second._payload["admission"]
        and first._native == second._native and first._retrieval == second._retrieval
        and first._payload["initialTransitionHeadSha256"] == second._payload["initialDurableTransitionHeadSha256"])


def bridge_selection(owner):
    release_current(owner)
    return {"apiVersion": "serverware.nativePublicationServices/v2",
        "durableGrantOriginal": owner._publications[ROLES[0]].original().decode("ascii"),
        "currentGrantOriginal": owner._publications[ROLES[1]].original().decode("ascii")}
