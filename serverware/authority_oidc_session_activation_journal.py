"""Private encrypted activation originals, not plan or execution authority.

Only an independently provisioned private directory and two distinct supplied
keys are accepted. The journal key encrypts the exact closed original document;
the delivery key is held solely for the owning caller's configuration join and
is never serialized here. Original signatures, roots, currentness and operation
permission still require the actual downstream replay. No directory, key,
budget, authority window, retry or rollback anchor is created by this module.
"""
from __future__ import annotations

import fcntl
import hashlib
import os
import stat

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from serverware import authority_oidc_session_activation_plan_contract as contract
from serverware import authority_current_root_head as head
from serverware import authority_current_root_vector as vector
from serverware import oidc_session_activation_delivery as delivery
from serverware.authority_witness_journal import WitnessJournalIO


authority, shape, evidence = contract.authority, contract.shape, contract.evidence
registration = delivery.registration
SCHEMA = "serverware.oidcSessionActivationPrivateOriginals/v2"
DOMAIN = b"serverware.oidcSessionActivationJournal/v2\x00"
MAGIC = b"SWOAJ002"
MAX_ORIGINAL_BYTES = authority.MAX_RESULT_BYTES
MAX_SCOPE_BYTES = 4096
MAX_RECORD_BYTES = MAX_ORIGINAL_BYTES + MAX_SCOPE_BYTES + 46
MAX_RECORDS = 1024
MAX_QUOTA_BYTES = 8 * 1024 * 1024 * 1024
MAX_NODES = shape.MAX_JSON_NODES
MAX_DEPTH = shape.MAX_JSON_DEPTH
_READ_CHUNK = 64 * 1024
_HEX = frozenset("0123456789abcdef")
SCOPE_FIELDS = frozenset({"sourceRevision", "configurationDigest", "requestDigest", "planDigest"})
ORIGINAL_FIELDS = frozenset({"schema", "sourceRevision", "request", "scope", "databaseNow",
    "assertionBase64Url", "oldTokenBase64Url", "newTokenBase64Url", "deliveryEnvelopeBase64Url",
    "readInputs", "writeProofBase64Url", "planEnvelopeBase64Url", "stateEnrollmentBase64Url",
    "completeRootVectorBase64Url", "headQueryBase64Url", "headObservationBase64Url"})
READ_INPUT_FIELDS = frozenset({"schema", "selectedRows", "beforeProofs", "readHeads",
    "queryFrontiers", "queryReads", "businessBeforeRoots", "authorizationBeforeRoots", "countedBeforeHeads"})
# This is the closed private plan scope, not a new caller-selected authority.
# Keep the storage grammar independent of the plan owner to avoid an import cycle.
PLAN_SCOPE_FIELDS = frozenset({"userId", "sessionId", "credentialId", "credentialRecordId", "challengeId",
    "rpId", "origin", "authenticationPolicy", "trustPolicy", "configurationDigest",
    "plannerIdentity", "plannerSpkiDigest", "maximumPlanAgeNs", "maximumClockSkewNs", "deadlineEpochNs"})
_ARGUMENT_FIELDS = frozenset({"session_id", "user_id", "credential_id", "credential_record_id",
    "challenge_id", "old_token_digest", "new_token_digest", "assertion_digest", "delivery_ttl_seconds",
    "businessIntent"})


class ActivationOriginalJournalError(RuntimeError):
    pass


def _fail(message):
    raise ActivationOriginalJournalError(message)


def _scope(value):
    """Capture only exact immutable scalars, before native callbacks."""
    shape._object(value, SCOPE_FIELDS, "activation journal scope")
    held = {}
    for field, item in value.items():
        if type(item) is not str or not 1 <= len(item) <= 256:
            _fail("activation journal scope is not bounded immutable text")
        held[field] = item
    shape._literal(held["sourceRevision"], authority.SOURCE_REVISION)
    for field in SCOPE_FIELDS - {"sourceRevision"}:
        shape._digest(held[field])
    return held


class _Capture(evidence.capture._JSONCapture):
    def visit(self, value, depth=0, ancestors=frozenset()):
        if depth > MAX_DEPTH or self.nodes >= MAX_NODES:
            _fail("activation private originals exceed their structure bound")
        result = super().visit(value, depth, ancestors)
        if self.nodes > MAX_NODES:
            _fail("activation private originals exceed their node bound")
        return result


def _original(value, scope, work):
    """Own a closed storage document; this does not authenticate its proofs."""
    owned = _Capture(evidence.capture._SharedLedger(work), maximum_bytes=MAX_ORIGINAL_BYTES).visit(value)
    shape._object(owned, ORIGINAL_FIELDS, "activation private originals")
    shape._literal(owned["schema"], SCHEMA)
    shape._literal(owned["sourceRevision"], scope["sourceRevision"])
    request, expected, reads = owned["request"], owned["scope"], owned["readInputs"]
    shape._object(request, shape.TYPED_REQUEST_FIELDS, "retained activation typed request")
    shape._literal(request["schema"], shape.TYPED_REQUEST_SCHEMA)
    shape._literal(request["operation"], contract.OPERATION)
    shape._literal(request["handler"], "finalize_oidc_browser_session_activation")
    shape._literal(request["operationManifestDigest"], authority.OPERATION_MANIFEST_DIGEST)
    shape._object(request["arguments"], _ARGUMENT_FIELDS, "retained activation arguments")
    shape._digest(request["operationId"])
    shape._literal(request["requestDigest"], scope["requestDigest"])
    shape._object(expected, PLAN_SCOPE_FIELDS, "retained activation plan scope")
    shape._literal(expected["configurationDigest"], scope["configurationDigest"])
    shape._object(reads, READ_INPUT_FIELDS, "retained activation read inputs")
    shape._literal(reads["schema"], contract.PROOF_DOMAIN)
    database_now = registration._utc(owned["databaseNow"], "retained activation database time", work)
    if database_now.isoformat() != owned["databaseNow"]:
        _fail("retained activation database time is not a canonical UTC original")
    registration._encoded_original(owned["assertionBase64Url"], 128 * 1024, work)
    for field in ("oldTokenBase64Url", "newTokenBase64Url"):
        delivery._token(registration._encoded_original(owned[field], delivery.TOKEN_BYTES,
            work, minimum=delivery.TOKEN_BYTES), work)
    delivery._envelope(registration._encoded_original(owned["deliveryEnvelopeBase64Url"],
        delivery.ENVELOPE_BYTES, work, minimum=delivery.ENVELOPE_BYTES), work)
    # Opaque proof originals and bounded graphs require the actual downstream
    # verifier; neither this codec nor AEAD authenticates their alleged meaning.
    registration._encoded_original(owned["writeProofBase64Url"], MAX_ORIGINAL_BYTES, work)
    for field, maximum in (("stateEnrollmentBase64Url", head.authorization.MAX_ENROLLMENT_BYTES),
            ("completeRootVectorBase64Url", vector.MAX_BYTES),
            ("headQueryBase64Url", head.MAX_QUERY_BYTES), ("headObservationBase64Url", head.MAX_BYTES)):
        registration._encoded_original(owned[field], maximum, work)
    plan_bytes = registration._encoded_original(owned["planEnvelopeBase64Url"], contract.MAX_BYTES, work)
    plan = contract._decode_on_work(plan_bytes, envelope=True, work=work)
    shape._literal(plan["payload"]["requestDigest"], scope["requestDigest"])
    shape._literal(plan["payload"]["operationId"], request["operationId"])
    shape._literal(plan["payload"]["configurationDigest"], scope["configurationDigest"])
    digest = evidence.plan._frame(contract.IDENTITY_DOMAIN, (plan_bytes,), work)
    shape._literal(digest, scope["planDigest"])
    return owned


def _encode_original_on_work(value, *, scope, work):
    """Canonical private bytes only; caller retains its current processing guard."""
    held = _scope(scope)
    owned = _original(value, held, work)
    return evidence.capability._wire(owned, evidence.capture._SharedLedger(work), MAX_ORIGINAL_BYTES, MAX_NODES)


def _decode_original_on_work(original_bytes, *, scope, work):
    """Return owned ordinary data, never a successful replay or proof token."""
    held = _scope(scope)
    if type(original_bytes) is not bytes or not 2 <= len(original_bytes) <= MAX_ORIGINAL_BYTES:
        _fail("activation private original bytes exceed their exact bound")
    value = evidence.wire._decode_object(original_bytes, work=work, maximum_bytes=MAX_ORIGINAL_BYTES,
        maximum_nodes=MAX_NODES, maximum_depth=MAX_DEPTH)
    owned = _original(value, held, work)
    evidence.capability._canonical(original_bytes, owned, evidence.capture._SharedLedger(work),
        MAX_ORIGINAL_BYTES, MAX_NODES)
    return owned


def _identity(metadata):
    return (metadata.st_dev, metadata.st_ino, metadata.st_uid, metadata.st_gid,
        metadata.st_mode, metadata.st_nlink, metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns)


def _name(plan_digest):
    return "activation-" + plan_digest[7:]


def _scope_tuple(scope):
    return tuple(scope[field] for field in sorted(SCOPE_FIELDS))


def _native(work, current, callback):
    current()
    work.charge(input_bytes=1)
    try:
        return evidence.production._callback(work, callback)
    finally:
        current()


def _open(work, current, callback):
    """An expired post-open check must still close its newly owned descriptor."""
    current()
    work.charge(input_bytes=1)
    descriptor = evidence.production._callback(work, callback)
    try:
        current()
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


class ActivationOriginalJournal:
    """PID-bound local first-original custody; not an anti-rollback anchor."""

    __slots__ = ("_pid", "_configuration", "_binding", "_closed", "_directory_fd",
        "_directory_stamp", "_io", "_entries", "_used_bytes")

    def __init__(self, *, directory_fd, expected_device, expected_inode, expected_uid, expected_gid,
            maximum_records, quota_bytes, configuration_digest, journal_key, delivery_key,
            live_window, work, transport_deadline_ns=None):
        for value, minimum, maximum in ((directory_fd, 0, 2**31 - 1),
                (expected_device, 0, 2**64 - 1), (expected_inode, 1, 2**64 - 1),
                (expected_uid, 1, 2**32 - 2), (expected_gid, 0, 2**32 - 2),
                (maximum_records, 1, MAX_RECORDS), (quota_bytes, 1, MAX_QUOTA_BYTES)):
            shape._integer(value, maximum, minimum=minimum)
        shape._digest(configuration_digest)
        if (type(journal_key) is not bytes or len(journal_key) != 32
                or type(delivery_key) is not bytes or len(delivery_key) != 32
                or journal_key == delivery_key):
            _fail("activation journal requires two independent distinct exact 32-byte keys")
        self._pid = os.getpid()
        self._binding = (expected_device, expected_inode, expected_uid, expected_gid)
        self._configuration = (authority.SOURCE_REVISION, configuration_digest, journal_key,
            delivery_key, self._binding, maximum_records, quota_bytes)
        self._closed, self._directory_fd, self._directory_stamp, self._io = False, None, None, None
        self._entries, self._used_bytes = {}, 0
        _window_value, current = delivery._window(live_window, transport_deadline_ns, work)
        current()
        self._require_process()
        self._directory_metadata(directory_fd, work, current)
        try:
            # dup() shares flock state; '.' opens an independently owned lease.
            self._directory_fd = _open(work, current, lambda: os.open(".",
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=directory_fd))
            self._directory_metadata(self._directory_fd, work, current)
            _native(work, current, lambda: fcntl.flock(self._directory_fd, fcntl.LOCK_EX | fcntl.LOCK_NB))
            self._io = _native(work, current, lambda: WitnessJournalIO(self._directory_fd,
                maximum_record_bytes=MAX_RECORD_BYTES))
            self._directory_stamp = self._stamp(work, current)

            def scan():
                before = self._stamp(work, current)
                if before != self._directory_stamp:
                    _fail("activation journal changed before original recovery")
                inventory = self._inventory(work, current)
                for name, identity in inventory.items():
                    raw, observed = self._read_file(name, work, current, synchronize=True)
                    if observed != identity:
                        _fail("activation journal changed during original recovery")
                    scope, _original_bytes = self._unseal(raw, work, current)
                    if name != _name(scope["planDigest"]):
                        _fail("activation original differs from its plan locator")
                    self._entries[name] = (_scope_tuple(scope), self._digest(raw, work, current), observed)
                    self._used_bytes += len(raw)
                if self._stamp(work, current) != before:
                    _fail("activation journal changed during its original scan")
                return before

            # This fixed scan itself consumes supplied work. Do not wrap it in
            # the no-work-mutation native callback used for individual syscalls.
            work.charge(input_bytes=1)
            try:
                self._directory_stamp = self._io.recover(scan)
            finally:
                current()
        except BaseException:
            self._closed = True
            if self._io is not None:
                self._io.poison()
            if self._directory_fd is not None:
                os.close(self._directory_fd)
                self._directory_fd = None
            raise

    def _require_process(self):
        if os.getpid() != self._pid:
            _fail("forked process cannot use the activation journal")
        if self._closed:
            _fail("activation journal is closed")
        if (os.geteuid(), os.getegid()) != self._binding[2:]:
            if self._io is not None:
                self._io.poison()
            _fail("activation journal process differs from its provisioned owner")

    def _snapshot_configuration(self):
        """Private held configuration only; no unmetered filesystem scan."""
        self._require_process()
        with self._io.ready():
            self._require_process()
            return self._configuration

    def _directory_metadata(self, descriptor, work, current):
        metadata = _native(work, current, lambda: os.fstat(descriptor))
        if (not stat.S_ISDIR(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o700
                or metadata.st_nlink < 1
                or (metadata.st_dev, metadata.st_ino, metadata.st_uid, metadata.st_gid) != self._binding):
            _fail("activation journal directory differs from its pinned private identity")
        return metadata

    def _stamp(self, work, current):
        metadata = self._directory_metadata(self._directory_fd, work, current)
        return (metadata.st_dev, metadata.st_ino, metadata.st_mtime_ns, metadata.st_ctime_ns)

    def _file_identity(self, metadata):
        if (not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o400
                or metadata.st_nlink != 1 or metadata.st_dev != self._binding[0]
                or (metadata.st_uid, metadata.st_gid) != self._binding[2:]
                or not 50 <= metadata.st_size <= MAX_RECORD_BYTES):
            _fail("activation journal record is not bounded private immutable material")
        return _identity(metadata)

    def _inventory(self, work, current):
        """Bound count and sizes before allocating or reading any record body."""
        names, total = {}, 0
        current()
        work.charge(input_bytes=1)
        iterator = evidence.production._callback(work, lambda: os.scandir(self._directory_fd))
        with iterator:
            current()
            while True:
                entry = _native(work, current, lambda: next(iterator, None))
                if entry is None:
                    break
                if len(names) >= self._configuration[5]:
                    _fail("activation journal exceeds its configured record count")
                name = entry.name
                if (type(name) is not str or len(name) != 75 or not name.startswith("activation-")
                        or any(point not in _HEX for point in name[11:]) or name in names):
                    _fail("activation journal contains an unknown or temporary entry")
                work.charge(input_bytes=len(name))
                metadata = _native(work, current, lambda: os.stat(name,
                    dir_fd=self._directory_fd, follow_symlinks=False))
                identity = self._file_identity(metadata)
                total += metadata.st_size
                if total > self._configuration[6]:
                    _fail("activation journal exceeds its configured byte quota")
                names[name] = identity
        current()
        return names

    def _continuity(self, work, current):
        self._require_process()
        self._io.require_ready()
        if self._stamp(work, current) != self._directory_stamp:
            _fail("activation journal directory changed outside this owner")
        actual = self._inventory(work, current)
        if len(actual) != len(self._entries):
            _fail("activation journal lost or acquired an original")
        for name, identity in actual.items():
            if name not in self._entries or identity != self._entries[name][2]:
                _fail("activation journal original identity changed outside this owner")
        if self._stamp(work, current) != self._directory_stamp:
            _fail("activation journal directory changed during continuity checks")

    def _read_file(self, name, work, current, *, synchronize=False):
        descriptor = _open(work, current, lambda: os.open(name,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self._directory_fd))
        try:
            before = _native(work, current, lambda: os.fstat(descriptor))
            identity = self._file_identity(before)
            work.charge(input_bytes=2 * before.st_size)
            value = bytearray()
            while len(value) < before.st_size:
                raw = _native(work, current, lambda: os.read(descriptor,
                    min(_READ_CHUNK, before.st_size - len(value))))
                if not raw:
                    _fail("activation journal original was truncated")
                value.extend(raw)
            if _native(work, current, lambda: os.read(descriptor, 1)):
                _fail("activation journal original grew during its read")
            if synchronize:
                _native(work, current, lambda: os.fsync(descriptor))
            after = _native(work, current, lambda: os.fstat(descriptor))
            named = _native(work, current, lambda: os.stat(name,
                dir_fd=self._directory_fd, follow_symlinks=False))
            if identity != _identity(after) or identity != _identity(named):
                _fail("activation journal original changed during its stable read")
            return bytes(value), identity
        finally:
            # Cleanup must close an owned descriptor even after expiry.
            os.close(descriptor)

    def _digest(self, raw, work, current):
        work.charge(hashes=1, input_bytes=len(raw))
        return _native(work, current, lambda: "sha256:" + hashlib.sha256(raw).hexdigest())

    def _unseal(self, raw, work, current):
        if type(raw) is not bytes or not 50 <= len(raw) <= MAX_RECORD_BYTES or raw[:8] != MAGIC:
            _fail("activation journal original has an unknown encrypted frame")
        scope_size, original_size = int.from_bytes(raw[8:10], "big"), int.from_bytes(raw[10:18], "big")
        if (not 2 <= scope_size <= MAX_SCOPE_BYTES or not 2 <= original_size <= MAX_ORIGINAL_BYTES
                or len(raw) != 30 + scope_size + original_size + 16):
            _fail("activation journal encrypted frame has a malformed length vector")
        work.charge(input_bytes=len(raw) + original_size + len(DOMAIN))
        scope_bytes, nonce, ciphertext = raw[30:30 + scope_size], raw[18:30], raw[30 + scope_size:]
        value = evidence.wire._decode_object(scope_bytes, work=work, maximum_bytes=MAX_SCOPE_BYTES,
            maximum_nodes=32, maximum_depth=2)
        scope = _scope(value)
        if scope["configurationDigest"] != self._configuration[1]:
            _fail("activation journal original belongs to a different configuration")
        evidence.capability._canonical(scope_bytes, scope, evidence.capture._SharedLedger(work), MAX_SCOPE_BYTES, 32)
        aad = DOMAIN + raw[:18] + scope_bytes
        try:
            original = _native(work, current, lambda: AESGCM(self._configuration[2]).decrypt(nonce, ciphertext, aad))
        except (InvalidTag, ValueError) as exc:
            raise ActivationOriginalJournalError("activation journal original did not authenticate") from exc
        if type(original) is not bytes or len(original) != original_size:
            _fail("activation journal plaintext length differs from its original frame")
        current()
        _decode_original_on_work(original, scope=scope, work=work)
        current()
        return scope, original

    def _seal(self, scope, original, work, current):
        raw_scope = evidence.capability._wire(scope, evidence.capture._SharedLedger(work), MAX_SCOPE_BYTES, 32)
        header = MAGIC + len(raw_scope).to_bytes(2, "big") + len(original).to_bytes(8, "big")
        work.charge(input_bytes=2 * len(original) + len(raw_scope) * 2 + len(DOMAIN) + 64)
        nonce = _native(work, current, lambda: os.urandom(12))
        if type(nonce) is not bytes or len(nonce) != 12:
            _fail("activation journal randomness has the wrong exact length")
        ciphertext = _native(work, current, lambda: AESGCM(self._configuration[2]).encrypt(
            nonce, original, DOMAIN + header + raw_scope))
        if type(ciphertext) is not bytes or len(ciphertext) != len(original) + 16:
            _fail("activation journal ciphertext has the wrong exact length")
        raw = header + nonce + raw_scope + ciphertext
        _opened_scope, opened = self._unseal(raw, work, current)
        work.charge(input_bytes=2 * len(original))
        if opened != original:
            _fail("activation journal seal did not reopen its exact original")
        return raw

    def append(self, *, scope, original_bytes, live_window, work, transport_deadline_ns=None):
        """Durably retain the first exact private original; return ciphertext ID."""
        held = _scope(scope)
        if type(original_bytes) is not bytes or not 2 <= len(original_bytes) <= MAX_ORIGINAL_BYTES:
            _fail("activation journal append requires bounded immutable original bytes")
        self._require_process()
        _window_value, current = delivery._window(live_window, transport_deadline_ns, work)
        with self._io.ready():
            try:
                self._require_process()
                current()
                if held["configurationDigest"] != self._configuration[1]:
                    _fail("activation journal append configuration differs")
                _decode_original_on_work(original_bytes, scope=held, work=work)
                current()
                self._continuity(work, current)
                name = _name(held["planDigest"])
                if name in self._entries:
                    previous = self._entries[name]
                    raw, identity = self._read_file(name, work, current)
                    old_scope, old = self._unseal(raw, work, current)
                    work.charge(input_bytes=2 * len(original_bytes))
                    if (previous[0] != _scope_tuple(held) or _scope_tuple(old_scope) != previous[0]
                            or identity != previous[2] or self._digest(raw, work, current) != previous[1]
                            or old != original_bytes):
                        _fail("activation journal refuses reassociation or changed first originals")
                    self._continuity(work, current)
                    current()
                    return previous[1]
                if len(self._entries) >= self._configuration[5]:
                    _fail("activation journal record count is exhausted")
                raw = self._seal(held, original_bytes, work, current)
                if len(raw) > self._configuration[6] - self._used_bytes:
                    _fail("activation journal byte quota is exhausted")
                digest = self._digest(raw, work, current)
                self._continuity(work, current)
                # A visible publication is never removed, including on a late
                # response/deadline failure. Only ciphertext enters file I/O.
                work.charge(input_bytes=len(raw))
                _native(work, current, lambda: self._io.publish("pending-" + held["planDigest"][7:], name, raw))
                observed, identity = self._read_file(name, work, current)
                work.charge(input_bytes=2 * len(raw))
                if observed != raw:
                    _fail("activation journal durable ciphertext differs from its publication")
                _observed_scope, original = self._unseal(observed, work, current)
                work.charge(input_bytes=2 * len(original_bytes))
                if original != original_bytes:
                    _fail("activation journal durable readback differs from its original")
                self._entries[name] = (_scope_tuple(held), digest, identity)
                self._used_bytes += len(raw)
                self._directory_stamp = self._stamp(work, current)
                self._continuity(work, current)
                current()
                return digest
            except BaseException:
                self._io.poison()
                raise

    def read(self, *, scope, live_window, work, transport_deadline_ns=None):
        """Read exact local plaintext privately; absence says nothing about SQL."""
        held = _scope(scope)
        self._require_process()
        _window_value, current = delivery._window(live_window, transport_deadline_ns, work)
        with self._io.ready():
            try:
                self._require_process()
                current()
                if held["configurationDigest"] != self._configuration[1]:
                    _fail("activation journal read configuration differs")
                self._continuity(work, current)
                name = _name(held["planDigest"])
                previous = self._entries.get(name)
                if previous is None:
                    current()
                    return None
                raw, identity = self._read_file(name, work, current)
                actual_scope, original = self._unseal(raw, work, current)
                if (previous[0] != _scope_tuple(held) or _scope_tuple(actual_scope) != previous[0]
                        or identity != previous[2] or self._digest(raw, work, current) != previous[1]):
                    _fail("activation journal read differs from its retained first original")
                self._continuity(work, current)
                current()
                return original
            except BaseException:
                self._io.poison()
                raise

    def close(self):
        if os.getpid() != self._pid:
            _fail("forked process cannot close the activation journal owner")
        if self._closed:
            return
        with self._io.lock:
            if self._closed:
                return
            self._closed = True
            self._io.poison()
            descriptor, self._directory_fd = self._directory_fd, None
            # Close only this independent description: never unlock a borrowed
            # descriptor, delete retained originals or claim key-memory erasure.
            os.close(descriptor)
