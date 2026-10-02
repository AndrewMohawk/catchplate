"""Persistent co-located artifact witness, not a runtime replay witness.

The protected approval selects a literal generation core and independently held
trust high-water. A successful call appends the existing signed checkpoint and
generation formats to a locked local chain. It does not advance artifact trust,
verify the package's other evidence, or promise off-host/hostile-root rollback
resistance. Partial effects are preserved; no retry, repair or reset is offered.
"""
from __future__ import annotations

import contextlib
import ctypes
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
import signal
import stat
import time

from cryptography.hazmat.primitives import serialization
from scripts.authority import native_pilot_authority_io as io
from scripts.authority.generate_artifact_bundle import _verification_key
from serverware import authority_artifact_spec as spec
from serverware.authority_local_limits import LOCAL_SETUP_MAX_NS

APPROVAL_SCHEMA = "serverware.authorityTrustedHostLocalArtifactWitnessApproval/v1"
APPROVAL_SCHEMA_V2 = "serverware.authorityTrustedHostLocalArtifactWitnessApproval/v2"
HEAD_SCHEMA = "serverware.authorityTrustedHostLocalArtifactWitnessHead/v1"
LOCK_NAME, BASE_NAME, HEAD_NAME = "lock", "base-trust.json", "head.json"
MAX_RECORDS, MAX_TOTAL = 4096, 128 * 1024 * 1024
MAX_OPERATION_NS = LOCAL_SETUP_MAX_NS
_READ = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
_LIBC = ctypes.CDLL(None, use_errno=True)
_LIBC.renameat2.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                          ctypes.c_char_p, ctypes.c_uint)


class LocalArtifactWitnessError(RuntimeError):
    def __init__(self, owner):
        super().__init__("local artifact witness refused; partial state retained; no retry authorized")
        self.owner = owner


def _require(value):
    if not value:
        raise ValueError("local artifact witness refused")


def sha(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def document(raw, maximum=io.MAX_PUBLIC):
    def pairs(rows):
        value = {}
        for key, item in rows:
            _require(key not in value)
            value[key] = item
        return value
    def invalid(_):
        raise ValueError("noninteger JSON refused")
    _require(type(raw) is bytes and 0 < len(raw) <= maximum)
    value = json.loads(raw, object_pairs_hook=pairs, parse_float=invalid, parse_constant=invalid)
    _require(type(value) is dict and spec.canonical_json_bytes(value) == raw)
    return value


def approval(raw):
    value = document(raw, 8192)
    fields = {"schema", "action", "directory", "trustSha256", "coreSha256",
        "expectedHeadSha256", "signerKeyId", "bootIdDigest", "issuedAtBoottimeNs",
        "deadlineBoottimeNs", "issuedAtUnixNanos", "expiresAtUnixNanos"}
    selected_v2 = value.get("schema") == APPROVAL_SCHEMA_V2
    if selected_v2:
        fields.add("emptyWitnessConvention")
    _require(set(value) == fields and value["schema"] in {APPROVAL_SCHEMA, APPROVAL_SCHEMA_V2}
        and value["action"] in {"initialize-and-append", "append"})
    if selected_v2:
        from serverware.authority_local_trust import EMPTY_WITNESS_CONVENTION
        _require(value["action"] == "initialize-and-append"
            and value["emptyWitnessConvention"] == EMPTY_WITNESS_CONVENTION)
    for field in ("trustSha256", "coreSha256", "bootIdDigest"):
        spec._require_digest(value[field], name=field)
    spec._require_identifier(value["signerKeyId"], name="witness signer")
    if value["action"] == "initialize-and-append":
        _require(value["expectedHeadSha256"] is None)
    else:
        spec._require_digest(value["expectedHeadSha256"], name="expected witness head")
    directory = value["directory"]
    _require(type(directory) is dict and set(directory) == {"device", "inode"})
    for field, minimum in (("device", 0), ("inode", 1)):
        _require(type(directory[field]) is int and minimum <= directory[field] < 2**64)
    for field in ("issuedAtBoottimeNs", "deadlineBoottimeNs", "issuedAtUnixNanos", "expiresAtUnixNanos"):
        _require(type(value[field]) is int and 0 < value[field] < 2**63)
    for start, end in (("issuedAtBoottimeNs", "deadlineBoottimeNs"), ("issuedAtUnixNanos", "expiresAtUnixNanos")):
        _require(0 < value[end] - value[start] <= MAX_OPERATION_NS)
    return value


def _boot():
    with open("/proc/sys/kernel/random/boot_id", "rb") as stream:
        raw = stream.read(128).strip()
    _require(len(raw) == 36)
    return spec.domain_digest("serverware.policyAuthorityBootIdentity/v1", raw)


def _stamp(info):
    return io._identity(info)


def _directory(info):
    _require(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700
        and info.st_uid == info.st_gid == 0 and info.st_nlink > 0)
    # Adding a record changes nlink/mtime, not the selected directory identity.
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)


def _name(sequence):
    _require(type(sequence) is int and 0 <= sequence < MAX_RECORDS)
    return f"generation-{sequence:020d}.json"


def _head(base_raw, generation_raw):
    value = document(generation_raw)
    spec.validate_generation_statement(value)
    checkpoint = value["witnessCheckpoint"]
    return dict(schema=HEAD_SCHEMA, baseTrustSha256=sha(base_raw), sequence=value["sequence"],
        generationSha256=sha(generation_raw), generationDigest=spec.generation_statement_digest(value),
        checkpointDigest=spec.witness_checkpoint_digest(checkpoint),
        rootDigest=checkpoint["payload"]["rootDigest"], treeSize=checkpoint["payload"]["treeSize"],
        minimumRollbackSequence=value["minimumRollbackSequence"])


def _witness_identity(trust):
    value = trust["witness"]
    return tuple(value[name] for name in ("identity", "keyId", "publicKeyBase64Url",
                                         "keyFileSha256", "authorizationDigest"))


def _local_core(core):
    spec.validate_generation_core(core)
    _require(core["trustMode"]["mode"] == "trusted-host-local"
        and core["stageZeroContract"] == spec.LOCAL_STAGE_ZERO_INTERFACE_SCHEMA)


def _verify_record(value, previous, witness, *, now):
    """Verify an actual persisted record, never a reconstructed prior result."""
    spec.validate_generation_statement(value)
    _local_core({key: item for key, item in value.items() if key != "witnessCheckpoint"})
    checkpoint, payload = value["witnessCheckpoint"], value["witnessCheckpoint"]["payload"]
    _require(value["sequence"] == previous["sequence"] + 1
        and value["predecessorDigest"] == previous["generationDigest"]
        and value["minimumRollbackSequence"] >= previous["minimumRollbackSequence"]
        and checkpoint["signerKeyId"] == witness["keyId"] and payload["identity"] == witness["identity"]
        and payload["previousCheckpointDigest"] == previous["checkpointDigest"]
        and payload["previousRootDigest"] == previous["rootDigest"]
        and payload["previousTreeSize"] == previous["treeSize"]
        and value["validFrom"] <= payload["issuedAt"] < value["validUntil"]
        and previous["issuedAt"] <= payload["issuedAt"] <= now)
    spec.verify_ed25519_signature(witness["publicKey"], checkpoint["signatureBase64Url"],
        spec.domain_digest(spec.WITNESS_CHECKPOINT_SIGNATURE_DOMAIN,
                           spec.canonical_json_bytes(payload)).encode("ascii"), name="artifact witness checkpoint")


@contextlib.contextmanager
def _owning():
    old = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM, signal.SIGHUP})
    try:
        yield
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, old)


class LocalArtifactWitness:
    """One invocation; actual FD/lock ownership remains reachable on failure."""

    @classmethod
    def open(cls, *, approval_fd, approval_sha256, trust_fd, trust_sha256,
             core_fd, core_sha256, directory_fd, signing_key_fd):
        owner = cls.__new__(cls)
        owner._fds, owner._identities, owner._records = [], {}, {}
        owner._uncertain, owner._closed, owner._used = False, False, False
        owner._pid, owner.stage, owner.committed = os.getpid(), "opening", False
        owner._selected = None
        try:
            io._process()
            fds = (approval_fd, trust_fd, core_fd, directory_fd, signing_key_fd)
            _require(all(type(fd) is int and 3 <= fd < 2**31 for fd in fds) and len(set(fds)) == len(fds))
            with _owning():
                owner._fds.extend(fds)  # Transfer custody before the first fallible inspection.
                owner._directory_fd, owner._key_fd = directory_fd, signing_key_fd
                for fd in fds:
                    os.set_inheritable(fd, False)
                    owner._identities[fd] = _stamp(os.fstat(fd))
            _require(len({stamp[:2] for stamp in owner._identities.values()}) == len(fds))
            owner._directory_identity = _directory(os.fstat(directory_fd))
            _require(fcntl.fcntl(directory_fd, fcntl.F_GETFL) & (os.O_ACCMODE | os.O_PATH) == os.O_RDONLY)
            raw = [io.read_public(fd, limit) for fd, limit in
                   ((approval_fd, 8192), (trust_fd, io.MAX_PUBLIC), (core_fd, io.MAX_PUBLIC))]
            for original, pin in zip(raw, (approval_sha256, trust_sha256, core_sha256)):
                spec._require_digest(pin, name="public input pin")
                _require(sha(original) == pin)
            owner._originals = dict(zip((approval_fd, trust_fd, core_fd), raw))
            owner._selected = selected = approval(raw[0])
            _require(selected["trustSha256"] == trust_sha256 and selected["coreSha256"] == core_sha256
                and selected["directory"] == dict(zip(("device", "inode"), owner._directory_identity[:2])))
            owner._trust_raw, owner._core_raw = raw[1:]
            owner._trust = spec.validate_trust_state(document(raw[1]))
            owner._core = document(raw[2]); _local_core(owner._core)
            owner._epoch_limit = min(selected["expiresAtUnixNanos"],
                int(spec._require_timestamp(owner._core["validUntil"], name="generation expiry").timestamp()) * 10**9)
            _require(io._input(signing_key_fd, 32, private=True)[6] == 32)
            owner._previous_boot = selected["issuedAtBoottimeNs"]
            owner._previous_unix = selected["issuedAtUnixNanos"]
            owner.check()
            owner.stage = "prepared"
            return owner
        except BaseException as exc:
            raise LocalArtifactWitnessError(owner) from exc

    def _origin(self):
        io._process()
        _require(os.getpid() == self._pid and not self._uncertain)

    def check_clock(self):
        self._origin()
        value = self._selected
        _require(value is not None and _boot() == value["bootIdDigest"])
        boot, unix = time.clock_gettime_ns(time.CLOCK_BOOTTIME), time.time_ns()
        _require(self._previous_boot <= boot < value["deadlineBoottimeNs"]
            and self._previous_unix <= unix < self._epoch_limit)
        self._previous_boot, self._previous_unix = boot, unix

    def check(self):
        self.check_clock()
        _require(not self._closed)
        for fd, original in self._identities.items():
            if fd == self._directory_fd:
                _require(_directory(os.fstat(fd)) == self._directory_identity)
            else:
                _require(_stamp(os.fstat(fd)) == original)
        for name, original in self._records.items():
            _require(_stamp(os.stat(name, dir_fd=self._directory_fd, follow_symlinks=False)) == original)

    def _hold(self, fd):
        self._fds.append(fd)
        self._identities[fd] = _stamp(os.fstat(fd))
        return fd

    def _drop(self, fd):
        self._uncertain = True
        os.close(fd)
        self._fds.remove(fd)
        self._identities.pop(fd, None)
        self._uncertain = False

    def _read(self, name, maximum=io.MAX_PUBLIC):
        self.check_clock()
        with _owning():
            fd = self._hold(os.open(name, _READ, dir_fd=self._directory_fd))
        raw = io.read_public(fd, maximum)
        original = _stamp(os.fstat(fd))
        _require(original[5] == 1 and _stamp(os.stat(name, dir_fd=self._directory_fd,
            follow_symlinks=False)) == original)
        self._records[name] = original
        with _owning():
            self._drop(fd)
        self.check_clock()
        return raw

    def _publish(self, name, raw, *, replace=False):
        self.check()
        pending = ".pending-" + name
        with _owning():
            fd = self._hold(os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
                | os.O_NOFOLLOW, 0o600, dir_fd=self._directory_fd))
        offset = 0
        while offset < len(raw):
            self.check_clock()
            count = os.write(fd, memoryview(raw)[offset:offset+65536])
            _require(count > 0); offset += count
        os.fchmod(fd, 0o400)
        os.fsync(fd)
        self._identities[fd] = _stamp(os.fstat(fd))
        self.check()
        if replace:
            _require(name == HEAD_NAME and name in self._records)
            os.replace(pending, name, src_dir_fd=self._directory_fd, dst_dir_fd=self._directory_fd)
            del self._records[name]
        else:
            result = _LIBC.renameat2(self._directory_fd, os.fsencode(pending),
                self._directory_fd, os.fsencode(name), 1)
            if result != 0:
                error = ctypes.get_errno()
                raise OSError(error, "no-replace witness publication refused")
        self._identities[fd] = _stamp(os.fstat(fd))
        os.fsync(self._directory_fd)
        with _owning():
            self._drop(fd)
        _require(self._read(name) == raw)
        self.check()

    def _lock(self, initialize):
        self.check()
        if initialize:
            _require(os.listdir(self._directory_fd) == [])
        flags = os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
        if initialize:
            flags |= os.O_CREAT | os.O_EXCL
        with _owning():
            fd = self._hold(os.open(LOCK_NAME, flags, 0o600, dir_fd=self._directory_fd))
        info = os.fstat(fd)
        _require(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600
            and info.st_uid == info.st_gid == 0 and info.st_nlink == 1 and info.st_size == 0)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self._records[LOCK_NAME] = _stamp(info)
        if initialize:
            os.fsync(fd); os.fsync(self._directory_fd)
            _require(os.listdir(self._directory_fd) == [LOCK_NAME])
        self.check()

    def _audit(self, initialize):
        trust = self._trust
        if initialize:
            _require(trust["currentSequence"] == -1)
            base_raw = self._trust_raw
        else:
            base_raw = self._read(BASE_NAME)
        base = spec.validate_trust_state(document(base_raw))
        _require(base["currentSequence"] == -1 and _witness_identity(base) == _witness_identity(trust))
        witness = base["witness"]
        previous = dict(sequence=-1, generationDigest=None, minimumRollbackSequence=base["minimumRollbackSequence"],
            checkpointDigest=witness["currentCheckpointDigest"], rootDigest=witness["currentRootDigest"],
            treeSize=0, issuedAt="0001-01-01T00:00:00Z")
        total, latest = len(base_raw), None
        sequence = trust["currentSequence"]
        _require(-1 <= sequence < MAX_RECORDS - 1)
        if not initialize:
            head_raw = self._read(HEAD_NAME, 8192)
            _require(sha(head_raw) == self._selected["expectedHeadSha256"])
            expected_names = {LOCK_NAME, BASE_NAME, HEAD_NAME} | {_name(index) for index in range(sequence+1)}
            _require(set(os.listdir(self._directory_fd)) == expected_names)
            for index in range(sequence+1):
                raw = self._read(_name(index))
                total += len(raw); _require(total <= MAX_TOTAL)
                value = document(raw)
                _verify_record(value, previous, witness, now=self._timestamp())
                latest = _head(base_raw, raw)
                previous = {**latest, "issuedAt": value["witnessCheckpoint"]["payload"]["issuedAt"]}
            _require(latest is not None and document(head_raw, 8192) == latest
                and trust["currentGenerationDigest"] == previous["generationDigest"]
                and trust["minimumRollbackSequence"] >= previous["minimumRollbackSequence"])
        current = trust["witness"]
        _require(current["currentSequence"] == previous["sequence"]
            and current["currentCheckpointDigest"] == previous["checkpointDigest"]
            and current["currentRootDigest"] == previous["rootDigest"]
            and current["currentTreeSize"] == previous["treeSize"]
            and self._core["sequence"] == sequence + 1
            and self._core["predecessorDigest"] == previous["generationDigest"]
            and self._core["minimumRollbackSequence"] >= max(trust["minimumRollbackSequence"], previous["minimumRollbackSequence"])
            and total + len(self._core_raw) + 4096 <= MAX_TOTAL)
        self.check()
        return base_raw, previous

    def _timestamp(self):
        return datetime.fromtimestamp(self._previous_unix // 10**9, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    def _check_empty_genesis(self):
        """Selected v2 only, before acquiring/creating any persistent object."""
        from serverware.authority_local_trust import empty_directory, empty_witness_anchors
        self.check()
        directory = empty_directory(self._directory_fd)
        _require(directory == self._selected["directory"])
        trust, witness = self._trust, self._trust["witness"]
        _require(trust["currentSequence"] == -1 and witness["currentSequence"] == -1
            and witness["currentTreeSize"] == 0)
        anchors = empty_witness_anchors(directory, identity=witness["identity"], key_id=witness["keyId"],
            key_file_sha256=witness["keyFileSha256"])
        _require(all(witness[name] == value for name, value in anchors.items()))
        self.check()

    def run(self):
        try:
            _require(not self._used and not self._closed)
            self._used = True
            initialize = self._selected["action"] == "initialize-and-append"
            if self._selected["schema"] == APPROVAL_SCHEMA_V2:
                self._check_empty_genesis()
            self._lock(initialize)
            self.stage = "auditing"
            base_raw, previous = self._audit(initialize)
            self.check()
            now, core = self._timestamp(), self._core
            _require(core["validFrom"] <= now < core["validUntil"])
            key = _verification_key(self._trust, key_id=self._selected["signerKeyId"],
                purpose="witness-checkpoint", validation_time=now)
            witness = self._trust["witness"]
            _require(key.key_id == witness["keyId"] and key.public_key == witness["publicKey"]
                and key.authorization_digest == witness["authorizationDigest"]
                and core["validUntil"] <= key.not_after)
            for fd, raw in self._originals.items():
                _require(io.read_public(fd, io.MAX_PUBLIC) == raw)
            self.check()
            core_digest = spec.domain_digest(spec.GENERATION_CORE_DIGEST_DOMAIN, self._core_raw)
            leaf = spec.domain_digest(spec.WITNESS_LEAF_DIGEST_DOMAIN, core_digest.encode("ascii"))
            size = previous["treeSize"] + 1
            payload = dict(schema="serverware.authorityWitnessCheckpointPayload/v1", identity=witness["identity"],
                sequence=core["sequence"], previousCheckpointDigest=previous["checkpointDigest"],
                previousRootDigest=previous["rootDigest"], previousTreeSize=previous["treeSize"], treeSize=size,
                generationCoreDigest=core_digest, leafDigest=leaf,
                rootDigest=spec.domain_digest(spec.WITNESS_CHAIN_ROOT_DOMAIN, previous["rootDigest"].encode("ascii"),
                    str(size).encode("ascii"), leaf.encode("ascii")), issuedAt=now, coLocated=True, hardwareBacked=False)
            private = io.signing_key(self._key_fd)
            try:
                _require(private.public_key().public_bytes(serialization.Encoding.Raw,
                    serialization.PublicFormat.Raw) == key.public_key)
                self.check()
                signature = private.sign(spec.domain_digest(spec.WITNESS_CHECKPOINT_SIGNATURE_DOMAIN,
                    spec.canonical_json_bytes(payload)).encode("ascii"))
            finally:
                del private
            checkpoint = dict(schema="serverware.signedAuthorityWitnessCheckpoint/v1", payload=payload,
                signerKeyId=key.key_id, algorithm="Ed25519", signatureBase64Url=spec.strict_base64url_encode(signature))
            generation = dict(core, witnessCheckpoint=checkpoint)
            _verify_record(generation, previous, witness, now=now)
            raw = spec.canonical_json_bytes(generation)
            self.stage = "appending"
            if initialize:
                self._publish(BASE_NAME, base_raw)
            self._publish(_name(core["sequence"]), raw)
            self._publish(HEAD_NAME, spec.canonical_json_bytes(_head(base_raw, raw)), replace=not initialize)
            self.check()
            self.committed = True
            self.stage = "committed"
            output = spec.canonical_json_bytes(checkpoint)
            self.close()
            self.check_clock()
            return output
        except BaseException as exc:
            raise LocalArtifactWitnessError(self) from exc

    def close(self):
        try:
            self._origin()  # Cleanup has no authority deadline or peer-liveness requirement.
            if self._closed:
                return
            with _owning():
                for fd in reversed(tuple(self._fds)):
                    original = self._identities.get(fd)
                    if original is not None:
                        if fd == getattr(self, "_directory_fd", None):
                            if hasattr(self, "_directory_identity"):
                                _require(_directory(os.fstat(fd)) == self._directory_identity)
                            else:
                                _require(_stamp(os.fstat(fd))[:2] == original[:2])
                        else:
                            # A partial write can legitimately change size/mtime; identity
                            # still binds the exact open handle before known-close.
                            _require(_stamp(os.fstat(fd))[:2] == original[:2])
                    self._drop(fd)
            self._closed = True
        except BaseException as exc:
            raise LocalArtifactWitnessError(self) from exc
