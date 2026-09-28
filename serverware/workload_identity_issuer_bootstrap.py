"""Independent cold authority for the fixed local workload certificate issuer.

Only public originals are admitted here. The launcher owns descriptor checks
and the CA private key; a signed packet or CSR never confers issuance authority.
All validation uses the caller's original work and dual-clock processing window.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
import re
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from serverware import authority_contract as authority
from serverware import authority_webauthn_evidence_plan_clock as clock
from serverware import authority_successor_execution_window as windows
from serverware_agent_trust import _workload_signed_packet as packets
from serverware_agent_trust import workload_identity_originals as originals


SCHEMA = "serverware.signedWorkloadIdentityIssuerBootstrap/v1"
PAYLOAD_SCHEMA = "serverware.workloadIdentityIssuerBootstrap/v1"
MAX_BYTES = 128 * 1024
SERVICE_UID = SERVICE_GID = 65492
PROCESS_MODE = "workload-identity-issuer"
PEER_UID = PEER_GID = 65532
LISTENER_PATH = "/run/serverware/workload-identity-issuer/issuer.sock"
INHERITED_DESCRIPTORS = (198, 199, 200, 201, 202)
_MAX_TIMEOUT_NS = 30_000_000_000
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_PAYLOAD_FIELDS = frozenset({
    "schema", "sourceRevision", "purpose", "trustMode", "serviceUid", "serviceGid",
    "processMode", "configurationDigest", "journalNamespace", "issuerCertificate",
    "packetSigningKey", "authorizationKey", "policyHash", "runtimeManifestDigest",
    "caPrivateKey", "journal", "launch", "issuedAtEpochNs", "expiresAtEpochNs",
})
_LAUNCH_FIELDS = frozenset({
    "rootPublicKeyFd", "bootstrapFd", "listenerFd", "caPrivateKeyFd", "journalFd",
    "inheritedFileDescriptors", "listenerPath", "listenerDevice", "listenerInode",
    "listenerPathDevice", "listenerPathInode", "listenerUid", "listenerGid",
    "listenerMode", "peerUid", "peerGid", "requestTimeoutNs",
})


class WorkloadIdentityIssuerBootstrapError(ValueError):
    pass


def _fail():
    raise WorkloadIdentityIssuerBootstrapError("workload issuer original authority is invalid")


def _object(value, fields):
    if type(value) is not dict or set(value) != fields:
        _fail()
    return value


def _integer(value, maximum=(1 << 63) - 1, minimum=0):
    if type(value) is not int or not minimum <= value <= maximum:
        _fail()
    return value


def _digest(value):
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        _fail()
    return value


def _identifier(value):
    if type(value) is not str or _IDENTIFIER.fullmatch(value) is None:
        _fail()
    return value


def _construction_on_work(work):
    before, epoch, after = clock._sample_on_work(work)
    window = clock._validate((epoch, before, after, epoch + _MAX_TIMEOUT_NS,
        before + _MAX_TIMEOUT_NS, _MAX_TIMEOUT_NS, 0))
    return window, window[4]


def _guard_on_work(current, work):
    """Compose a metered ancestor without treating it as an unmetered native call."""
    clock.evidence.capture._SharedLedger(work)
    limits, before = work.limits, work.metrics
    ceiling = (limits.max_hashes, limits.max_input_bytes, limits.max_json_nodes)
    try:
        return current()
    finally:
        after = work.metrics
        if (work.limits is not limits
                or ceiling != (limits.max_hashes, limits.max_input_bytes, limits.max_json_nodes)
                or after.hash_work < before.hash_work or after.input_bytes < before.input_bytes
                or after.json_nodes < before.json_nodes):
            _fail()
        clock.evidence.capture._SharedLedger(work)


class _Budget:
    """Adapter, not a new allowance, timeout or clock authority."""

    def __init__(self, work, window, bound, ancestor):
        clock.evidence.capture._SharedLedger(work)
        self.work = work
        self.window = clock._validate(window)
        self.bound = _integer(bound, window[4], 1)
        self.ancestor = ancestor
        self.epoch = window[0]
        self.monotonic = window[2]
        self.intervals = []
        self.check()

    def current(self):
        clock.evidence.capture._SharedLedger(self.work)
        if self.ancestor is not None:
            ancestor_epoch = _guard_on_work(self.ancestor, self.work)
            _integer(ancestor_epoch, minimum=1)
            if ancestor_epoch < self.epoch:
                _fail()
            self.epoch = ancestor_epoch
        now = clock._check_on_work(self.window, work=self.work)
        mono = clock.evidence.production._callback(self.work, time.monotonic_ns)
        if now < self.epoch or mono < self.monotonic or mono >= self.bound:
            _fail()
        if any(not issued <= now < expires for issued, expires in self.intervals):
            _fail()
        self.epoch, self.monotonic = now, mono
        return now

    def check(self):
        self.current()

    def charge(self, **amounts):
        self.check()
        self.work.charge(**amounts)
        self.check()

    def interval(self, issued, expires):
        _integer(issued, minimum=1)
        _integer(expires, minimum=issued + 1)
        self.intervals.append((issued, expires))
        self.window = windows._narrow(self.window, deadline_epoch_ns=expires,
            maximum_lifetime_ns=self.window[5], maximum_clock_skew_ns=self.window[6])
        self.bound = min(self.bound, self.window[4])
        self.check()


def _raw(value, maximum):
    if type(value) is not bytes or not 1 <= len(value) <= maximum:
        _fail()
    return value


def _decode(raw, maximum, budget):
    _raw(raw, maximum)
    value = packets._parse_packet(raw, budget)
    if packets._canonical(value, maximum, budget) != raw:
        _fail()
    return value


def _spki(key, budget):
    budget.check()
    raw = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    budget.charge(input_bytes=len(raw))
    return raw


def _signed(raw, schema, payload_schema, public_key, maximum, budget):
    if not isinstance(public_key, ed25519.Ed25519PublicKey):
        _fail()
    value = _decode(raw, maximum, budget)
    _object(value, {"schema", "payload", "signature"})
    if value["schema"] != schema or type(value["payload"]) is not dict:
        _fail()
    payload = value["payload"]
    if payload.get("schema") != payload_schema or payload.get("sourceRevision") != authority.SOURCE_REVISION:
        _fail()
    encoded = value["signature"]
    if type(encoded) is not str or not encoded.startswith("ed25519:") or len(encoded) != 94:
        _fail()
    spelling = encoded[8:]
    signature = base64.b64decode(spelling + "==", altchars=b"-_", validate=True)
    if len(signature) != 64 or base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=") != spelling:
        _fail()
    message = payload_schema.encode("ascii") + b"\x00" + packets._canonical(payload, maximum, budget)
    budget.charge(hashes=1, input_bytes=len(message))
    public_key.verify(signature, message)
    budget.check()
    return payload


def _produce(payload_bytes, schema, payload_schema, private, public, maximum, budget):
    payload = _decode(payload_bytes, maximum, budget)
    if (not isinstance(private, ed25519.Ed25519PrivateKey)
            or not isinstance(public, ed25519.Ed25519PublicKey)
            or _spki(private.public_key(), budget) != _spki(public, budget)):
        _fail()
    message = payload_schema.encode("ascii") + b"\x00" + payload_bytes
    budget.charge(hashes=1, input_bytes=len(message))
    signature = private.sign(message)
    budget.check()
    return packets._canonical({"schema": schema, "payload": payload,
        "signature": "ed25519:" + base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")},
        maximum, budget)


def _wrapped(value, maximum, budget):
    _object(value, {"base64Url", "byteCount", "bytesDigest"})
    size = _integer(value["byteCount"], maximum, 1)
    spelling = value["base64Url"]
    if type(spelling) is not str or len(spelling) != (size * 8 + 5) // 6:
        _fail()
    budget.charge(input_bytes=size)
    raw = base64.b64decode(spelling + "=" * (-len(spelling) % 4), altchars=b"-_", validate=True)
    if (len(raw) != size or base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") != spelling
            or packets._digest(raw, budget) != _digest(value["bytesDigest"])):
        _fail()
    return raw


@dataclass(frozen=True, slots=True, repr=False)
class _IssuerMaterial:
    bootstrap_bytes: bytes
    bootstrap_digest: str
    configuration_digest: str
    issuer_certificate_bytes: bytes
    issuer_certificate: object
    packet_signing_key_bytes: bytes
    authorization_key_bytes: bytes
    authorization_public_key: object
    ca_private_key_byte_count: int
    ca_spki_digest: str
    policy_hash: str
    runtime_manifest_digest: str
    journal_namespace: str
    journal_device: int
    journal_inode: int
    journal_uid: int
    journal_gid: int
    journal_quota_bytes: int
    journal_maximum_records: int
    journal_checkpoint: tuple
    listener_device: int
    listener_inode: int
    listener_path_device: int
    listener_path_inode: int
    listener_uid: int
    listener_gid: int
    listener_mode: int
    request_timeout_ns: int
    attestation_interval: tuple
    window: tuple
    deadline_ns: int
    live: object


def _verify_on_work(*, bootstrap_bytes, root_public_key, live_window,
        transport_deadline_ns, work, _current=None):
    budget = _Budget(work, live_window, transport_deadline_ns, _current)
    p = _signed(bootstrap_bytes, SCHEMA, PAYLOAD_SCHEMA, root_public_key, MAX_BYTES, budget)
    _object(p, _PAYLOAD_FIELDS)
    for name, expected in (("purpose", "workload-identity-issuance"),
            ("trustMode", "trusted-host-local"), ("serviceUid", SERVICE_UID),
            ("serviceGid", SERVICE_GID), ("processMode", PROCESS_MODE)):
        if type(p[name]) is not type(expected) or p[name] != expected:
            _fail()
    budget.interval(p["issuedAtEpochNs"], p["expiresAtEpochNs"])
    certificate_bytes = _wrapped(p["issuerCertificate"], originals.MAX_CERTIFICATE_BYTES, budget)
    issuer = originals._issuer(certificate_bytes, budget)
    packet_key_bytes = _wrapped(p["packetSigningKey"], 1024, budget)
    authorization_key_bytes = _wrapped(p["authorizationKey"], 1024, budget)
    packet_key = packets._public_key(packet_key_bytes, budget)
    authorization_key = packets._public_key(authorization_key_bytes, budget)
    root_spki, packet_spki = _spki(root_public_key, budget), _spki(packet_key, budget)
    authorizer_spki = _spki(authorization_key, budget)
    if (authorizer_spki in (root_spki, packet_spki, issuer.spki_der)
            or issuer.spki_der in (root_spki, packet_spki)):
        _fail()
    key = _object(p["caPrivateKey"], {"byteCount", "spkiSha256"})
    key_size = _integer(key["byteCount"], 64 * 1024, 1)
    ca_digest = _digest(key["spkiSha256"])
    if packets._digest(issuer.spki_der, budget) != ca_digest:
        _fail()
    journal = _object(p["journal"], {"device", "inode", "uid", "gid", "quotaBytes",
        "maximumRecords", "checkpoint"})
    for name in ("device", "inode"):
        _integer(journal[name], minimum=1)
    if journal["uid"] != SERVICE_UID or journal["gid"] != SERVICE_GID:
        _fail()
    quota = _integer(journal["quotaBytes"], 64 * 1024 * 1024, 4096)
    records = _integer(journal["maximumRecords"], 1024, 2)
    if records % 2:
        _fail()
    checkpoint = _object(journal["checkpoint"], {"recordCount", "headDigest"})
    count = _integer(checkpoint["recordCount"], records)
    head = checkpoint["headDigest"]
    if count == 0:
        if head is not None:
            _fail()
    else:
        _digest(head)
    launch = _object(p["launch"], _LAUNCH_FIELDS)
    fixed = {"rootPublicKeyFd": 198, "bootstrapFd": 199, "listenerFd": 200,
        "caPrivateKeyFd": 201, "journalFd": 202,
        "inheritedFileDescriptors": list(INHERITED_DESCRIPTORS), "listenerPath": LISTENER_PATH,
        "listenerUid": SERVICE_UID, "listenerGid": PEER_GID, "listenerMode": 0o660,
        "peerUid": PEER_UID, "peerGid": PEER_GID}
    if any(type(launch[name]) is not type(value) or launch[name] != value for name, value in fixed.items()):
        _fail()
    for name in ("listenerDevice", "listenerInode", "listenerPathDevice", "listenerPathInode"):
        _integer(launch[name], minimum=1)
    timeout = _integer(launch["requestTimeoutNs"], _MAX_TIMEOUT_NS, 1)
    budget.window = windows._narrow(budget.window, deadline_epoch_ns=budget.window[3],
        maximum_lifetime_ns=timeout, maximum_clock_skew_ns=budget.window[6])
    budget.bound = min(budget.bound, budget.window[4])
    budget.interval(int(issuer.certificate.not_valid_before_utc.timestamp()) * 1_000_000_000,
        int(issuer.certificate.not_valid_after_utc.timestamp()) * 1_000_000_000)
    result = _IssuerMaterial(bootstrap_bytes, packets._digest(bootstrap_bytes, budget),
        _digest(p["configurationDigest"]), certificate_bytes, issuer, packet_key_bytes,
        authorization_key_bytes, authorization_key, key_size, ca_digest,
        _digest(p["policyHash"]), _digest(p["runtimeManifestDigest"]), _identifier(p["journalNamespace"]),
        journal["device"], journal["inode"], SERVICE_UID, SERVICE_GID, quota, records, (count, head),
        launch["listenerDevice"], launch["listenerInode"], launch["listenerPathDevice"],
        launch["listenerPathInode"], SERVICE_UID, PEER_GID, 0o660, timeout,
        (p["issuedAtEpochNs"], p["expiresAtEpochNs"]), budget.window, budget.bound, budget.current)
    result.live()
    return result


def _produce_on_work(*, payload_bytes, root_private_key, root_public_key,
        live_window, transport_deadline_ns, work, _current=None):
    budget = _Budget(work, live_window, transport_deadline_ns, _current)
    raw = _produce(payload_bytes, SCHEMA, PAYLOAD_SCHEMA, root_private_key, root_public_key, MAX_BYTES, budget)
    admitted = _verify_on_work(bootstrap_bytes=raw, root_public_key=root_public_key,
        live_window=budget.window, transport_deadline_ns=budget.bound, work=work, _current=budget.current)
    admitted.live()
    return raw
