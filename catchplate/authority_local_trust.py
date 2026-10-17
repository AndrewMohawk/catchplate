"""Issue only initial local artifact key documents under an already pinned root.

Public keys and initial trust are independently provisioned originals. This
issuer creates neither keys nor trust high-water. Empty-log anchors are explicit
genesis identities tied to an observed empty local directory, not prior signed
checkpoints. Existing package/installer and witness admission remain mandatory.
"""
from __future__ import annotations

from datetime import datetime, timezone
import fcntl
import os
import stat
import time

from cryptography.hazmat.primitives import serialization
from scripts.authority import native_pilot_authority_io as io
from catchplate import authority_artifact_spec as spec
from catchplate.authority_local_artifacts import document, sha
from catchplate.authority_local_snapshot import _boot

APPROVAL_SCHEMA = "catchplate.authorityTrustedHostLocalInitialTrustApproval/v1"
PURPOSE = "issue-first-local-artifact-key-documents"
EMPTY_WITNESS_CONVENTION = "catchplate.authorityTrustedHostLocalEmptyWitness/v1"
EMPTY_CHECKPOINT_DOMAIN = "catchplate.authorityTrustedHostLocalEmptyWitnessCheckpoint/v1"
EMPTY_ROOT_DOMAIN = "catchplate.authorityTrustedHostLocalEmptyWitnessRoot/v1"
ROOT_PURPOSE = "trust-document"
PURPOSES = tuple(sorted(spec.KEY_PURPOSES))
MAX_ORIGINAL = 65536
MAX_OPERATION_NS = 300_000_000_000
MAX_VALIDITY_NS = 7 * 86400 * 1_000_000_000
LOCAL_TRUST_MODE = dict(mode="trusted-host-local", hardwareBacked=False,
    externalWitnessRequired=False, teeQuoteRequired=False, imaAppraisalRequired=False)


def require(value):
    if not value: raise ValueError("initial local artifact trust issuance refused")


def key_id(purpose):
    require(purpose in PURPOSES)
    return "local-" + purpose + "-v1"


def public_roster(raw):
    value = document(raw, MAX_ORIGINAL)
    require(set(value) == set(PURPOSES))
    decoded = [spec.strict_base64url_decode(value[purpose], name="selected public key", decoded_size=32)
        for purpose in PURPOSES]
    require(len(set(decoded)) == len(PURPOSES))
    return value


def key_entries(roster, *, not_before, not_after):
    """Public-only candidate rows; this helper confers no signing authority."""
    public_roster(spec.canonical_json_bytes(roster))
    start = spec._require_timestamp(not_before, name="key notBefore")
    end = spec._require_timestamp(not_after, name="key notAfter")
    require(0 < (end - start).total_seconds() * 1_000_000_000 <= MAX_VALIDITY_NS)
    result = []
    for purpose in PURPOSES:
        raw = spec.strict_base64url_decode(roster[purpose], name="selected public key", decoded_size=32)
        entry = dict(keyId=key_id(purpose), purposes=[purpose], publicKeyBase64Url=roster[purpose],
            keyFile=dict(path="keys/artifact/" + purpose + ".pub", sha256=sha(raw), size=32, mode=0o400, uid=0, gid=0),
            notBefore=not_before, notAfter=not_after)
        entry["authorizationDigest"] = spec.domain_digest("catchplate.authorityKeyAuthorizationEntry/v1",
            spec.canonical_json_bytes(entry))
        result.append(entry)
    return tuple(result)


def external_key(entry):
    """Projection into the existing external trust row, not a trust install."""
    return {**{name: entry[name] for name in ("keyId", "purposes", "publicKeyBase64Url",
        "authorizationDigest", "notBefore", "notAfter")}, "keyFileSha256": entry["keyFile"]["sha256"]}


def empty_witness_anchors(directory, *, identity, key_id, key_file_sha256):
    require(type(directory) is dict and set(directory) == {"device", "inode"})
    for name, minimum in (("device", 0), ("inode", 1)):
        require(type(directory[name]) is int and minimum <= directory[name] < 2**64)
    spec._require_identifier(identity, name="empty witness identity")
    spec._require_identifier(key_id, name="empty witness key")
    spec._require_digest(key_file_sha256, name="empty witness public key")
    raw = spec.canonical_json_bytes(dict(schema=EMPTY_WITNESS_CONVENTION, directory=directory,
        identity=identity, keyId=key_id, keyFileSha256=key_file_sha256))
    return dict(currentCheckpointDigest=spec.domain_digest(EMPTY_CHECKPOINT_DOMAIN, raw),
        currentRootDigest=spec.domain_digest(EMPTY_ROOT_DOMAIN, raw))


def _timestamp(ns):
    return datetime.fromtimestamp(ns // 10**9, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def prepare(approval_raw, trust_raw, public_raw, *, boot, now_boottime_ns, now_unix_ns):
    selected = document(approval_raw, MAX_ORIGINAL)
    require(set(selected) == {"schema", "purpose", "trustSha256", "publicKeysSha256", "signerKeyId",
        "generation", "initialRevocations", "initialWitness", "bootIdDigest", "issuedAtBoottimeNs",
        "deadlineBoottimeNs", "issuedAtUnixNanos", "expiresAtUnixNanos"}
        and selected["schema"] == APPROVAL_SCHEMA and selected["purpose"] == PURPOSE
        and selected["trustSha256"] == sha(trust_raw) and selected["publicKeysSha256"] == sha(public_raw)
        and selected["signerKeyId"] == key_id(ROOT_PURPOSE) and selected["bootIdDigest"] == boot)
    for field in ("trustSha256", "publicKeysSha256", "bootIdDigest"):
        spec._require_digest(selected[field], name=field)
    for start, end, now in (("issuedAtBoottimeNs", "deadlineBoottimeNs", now_boottime_ns),
                            ("issuedAtUnixNanos", "expiresAtUnixNanos", now_unix_ns)):
        require(type(now) is int and type(selected[start]) is type(selected[end]) is int
            and 0 < selected[start] <= now < selected[end] < 2**63
            and selected[end] - selected[start] <= MAX_OPERATION_NS)
    generation = selected["generation"]
    require(type(generation) is dict and set(generation) == {"sequence", "predecessorDigest", "minimumRollbackSequence",
        "validFrom", "validUntil", "stageZeroContract", "trustMode"}
        and type(generation["sequence"]) is int and generation["sequence"] == 0
        and generation["predecessorDigest"] is None
        and type(generation["minimumRollbackSequence"]) is int and generation["minimumRollbackSequence"] == 0
        and generation["stageZeroContract"] == spec.LOCAL_STAGE_ZERO_INTERFACE_SCHEMA
        and generation["trustMode"] == LOCAL_TRUST_MODE)
    spec._validate_trust_mode(generation["trustMode"])
    require(selected["initialRevocations"] == {"state": "explicit-empty-initial-history", "revocationHighWater": 0, "revocations": []}
        and type(selected["initialRevocations"]["revocationHighWater"]) is int)
    roster = public_roster(public_raw)
    entries = key_entries(roster, not_before=generation["validFrom"], not_after=generation["validUntil"])
    require(generation["validFrom"] <= _timestamp(now_unix_ns) <= generation["validUntil"]
        and selected["expiresAtUnixNanos"] <= int(spec._require_timestamp(generation["validUntil"], name="key expiry").timestamp()) * 10**9)
    trust_value = document(trust_raw, MAX_ORIGINAL)
    trust = spec.validate_trust_state(trust_value)
    require(trust["currentSequence"] == -1 and trust["minimumRollbackSequence"] == 0
        and not trust["acceptedPackageDigests"] and not trust["acceptedGenerationDigests"]
        and not trust["acceptedEvidenceDigests"] and not trust["revokedKeyIds"])
    root = next(entry for entry in entries if entry["purposes"] == [ROOT_PURPOSE])
    operational = tuple(entry for entry in entries if entry is not root)
    require(trust_value["rootKeys"] == [external_key(root)]
        and trust_value["currentKeys"] == [external_key(entry) for entry in operational])
    initial = selected["initialWitness"]
    require(type(initial) is dict and set(initial) == {"convention", "identity", "directory"}
        and initial["convention"] == EMPTY_WITNESS_CONVENTION)
    witness_key = next(entry for entry in entries if entry["purposes"] == ["witness-checkpoint"])
    expected = dict(identity=initial["identity"], keyId=witness_key["keyId"], publicKeyBase64Url=witness_key["publicKeyBase64Url"],
        keyFileSha256=witness_key["keyFile"]["sha256"], authorizationDigest=witness_key["authorizationDigest"],
        currentSequence=-1, currentTreeSize=0,
        **empty_witness_anchors(initial["directory"], identity=initial["identity"], key_id=witness_key["keyId"],
            key_file_sha256=witness_key["keyFile"]["sha256"]))
    require(trust_value["witness"] == expected)
    return dict(value=selected, trust=trust, entries=operational, root=root)


def sign_documents(context, private, *, validation_time):
    """Pure existing-envelope signing; never a claim of actual file admission."""
    root = context["root"]
    public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    require(spec.strict_base64url_encode(public) == root["publicKeyBase64Url"]
        and root["notBefore"] <= validation_time <= root["notAfter"])
    material = {}
    for name, schema, domain, payload in (
        ("keyAuthorizations", spec.KEY_AUTHORIZATION_SCHEMA, spec.KEY_AUTHORIZATION_SIGNATURE_DOMAIN,
         dict(schema="catchplate.authorityKeyAuthorizationPayload/v1", generationSequence=0,
              predecessorGenerationDigest=None, keys=list(context["entries"]))),
        ("keyRevocations", spec.KEY_REVOCATION_SCHEMA, spec.KEY_REVOCATION_SIGNATURE_DOMAIN,
         dict(schema="catchplate.authorityKeyRevocationPayload/v1", generationSequence=0,
              predecessorGenerationDigest=None, revocationHighWater=0, revocations=[]))):
        signature = private.sign(spec._signature_message(domain, payload))
        material[name] = dict(schema=schema, payload=payload, signerKeyId=root["keyId"], algorithm="Ed25519",
            signatureBase64Url=spec.strict_base64url_encode(signature))
    files = [dict(entry["keyFile"], kind="configuration") for entry in context["entries"]]
    generation = dict(sequence=0, predecessorDigest=None,
        keyAuthorizationsDigest=spec.trust_document_digest(material["keyAuthorizations"]),
        keyRevocationsDigest=spec.trust_document_digest(material["keyRevocations"]))
    # The actual downstream trust-document consumer checks both signatures,
    # exact canonical entry digests and all existing key-file associations.
    keys, revoked = spec._verify_key_documents(material, bundle={"files": files}, generation=generation,
        trust_state=context["trust"], validation_time=validation_time)
    require(not revoked and tuple(keys) == tuple(entry["keyId"] for entry in context["entries"]))
    return spec.canonical_json_bytes(material)


def empty_directory(fd):
    require(type(fd) is int and fd >= 3)
    info = os.fstat(fd)
    require(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700
        and info.st_uid == info.st_gid == 0 and info.st_nlink > 0
        and fcntl.fcntl(fd, fcntl.F_GETFL) & (os.O_ACCMODE | os.O_PATH) == os.O_RDONLY)
    with os.scandir(fd) as entries:
        require(next(entries, None) is None)
    require(io._identity(os.fstat(fd)) == io._identity(info))
    return dict(device=info.st_dev, inode=info.st_ino)


class LocalTrustIssuer:
    """One-shot borrowed-descriptor issuer, with no filesystem mutation."""

    def __init__(self, *, approval_fd, approval_sha256, trust_fd, trust_sha256,
                 public_keys_fd, public_keys_sha256, witness_directory_fd, signing_key_fd):
        io._process()
        self.fds = (approval_fd, trust_fd, public_keys_fd, witness_directory_fd, signing_key_fd)
        require(all(type(fd) is int and 3 <= fd < 2**31 for fd in self.fds) and len(set(self.fds)) == len(self.fds))
        self.identities = {fd: io._identity(os.fstat(fd)) for fd in self.fds}
        require(len({entry[:2] for entry in self.identities.values()}) == len(self.fds))
        self.originals = {}
        for fd, pin in ((approval_fd, approval_sha256), (trust_fd, trust_sha256), (public_keys_fd, public_keys_sha256)):
            spec._require_digest(pin, name="selected original pin")
            raw = io.read_public(fd, MAX_ORIGINAL); require(sha(raw) == pin)
            self.originals[fd] = raw
        self.context = prepare(*(self.originals[fd] for fd in (approval_fd, trust_fd, public_keys_fd)),
            boot=_boot(), now_boottime_ns=time.clock_gettime_ns(time.CLOCK_BOOTTIME), now_unix_ns=time.time_ns())
        self.selected = self.context["value"]
        self.witness_directory_fd, self.signing_key_fd = witness_directory_fd, signing_key_fd
        self.pid, self.environment = os.getpid(), tuple(sorted(os.environ.items()))
        self.previous_boot, self.previous_unix = self.selected["issuedAtBoottimeNs"], self.selected["issuedAtUnixNanos"]
        self.used = False
        self.check()

    def check(self):
        io._process()
        require(os.getpid() == self.pid and tuple(sorted(os.environ.items())) == self.environment
            and _boot() == self.selected["bootIdDigest"])
        for fd, original in self.identities.items():
            require(io._identity(os.fstat(fd)) == original)
        for fd, original in self.originals.items():
            require(io.read_public(fd, MAX_ORIGINAL) == original)
        require(empty_directory(self.witness_directory_fd) == self.selected["initialWitness"]["directory"])
        boot, unix = time.clock_gettime_ns(time.CLOCK_BOOTTIME), time.time_ns()
        require(self.previous_boot <= boot < self.selected["deadlineBoottimeNs"]
            and self.previous_unix <= unix < self.selected["expiresAtUnixNanos"])
        self.previous_boot, self.previous_unix = boot, unix

    def issue(self):
        require(not self.used)
        self.used = True
        self.check()
        private = io.signing_key(self.signing_key_fd)
        try:
            self.check()
            raw = sign_documents(self.context, private, validation_time=_timestamp(self.previous_unix))
        finally: del private
        self.check()
        return raw

    def publish(self):
        raw = self.issue()
        io.write_public(raw, deadline_boottime_ns=self.selected["deadlineBoottimeNs"], check=self.check)
        self.check()
