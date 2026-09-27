"""Private first-ciphertext retention, not activation execution authority.

This owner receives an independently provisioned directory, configuration and
bundle key. It authenticates storage integrity, never plan signatures, fresh
state, permission, one-use execution or a historical authority resolution.
"""
from __future__ import annotations

import fcntl
import hashlib
import os
import stat

from serverware import authority_oidc_session_activation_execution_bundle as bundle
from serverware import authority_oidc_session_activation_journal as journal
from serverware.authority_witness_journal import WitnessJournalIO


authority, shape, evidence = journal.authority, journal.shape, journal.evidence
contract, delivery = journal.contract, journal.delivery
MAGIC = b"SWOAS001"
SLOT_DOMAIN = "serverware.oidcSessionActivationExecutionStoreSlot/v1"
HEADER_BYTES = 24
MAX_RECORD_BYTES = authority.MAX_RESULT_BYTES
MAX_CONTEXT_BYTES = bundle.MAX_CONTEXT_BYTES
MAX_PLAN_BYTES = contract.MAX_BYTES
MAX_RECORDS, MAX_QUOTA_BYTES = journal.MAX_RECORDS, journal.MAX_QUOTA_BYTES
MIN_RECORD_BYTES = HEADER_BYTES + 4 + bundle.OVERHEAD_BYTES + 2
_PREFIX = "execution-"
_HEX = frozenset("0123456789abcdef")
_CONTEXT_ORDER = tuple(sorted(bundle.CONTEXT_FIELDS))
_native, _open, _identity = journal._native, journal._open, journal._identity


class ActivationExecutionStoreError(RuntimeError):
    pass


def _fail(message):
    raise ActivationExecutionStoreError(message)


def _capture(key, context, envelope_bytes, bundle_bytes=None):
    """Hold all external originals before clock, hashing or file callbacks."""
    _key, held, _scope = bundle._capture(key, context)
    if type(envelope_bytes) is not bytes or not 2 <= len(envelope_bytes) <= MAX_PLAN_BYTES:
        _fail("activation execution store requires a bounded original plan")
    if bundle_bytes is not None:
        bundle._bounded_frame(bundle_bytes)
        if HEADER_BYTES + 2 + len(envelope_bytes) + len(bundle_bytes) > MAX_RECORD_BYTES:
            _fail("activation execution record exceeds its whole-record bound")
    return held


def _context_tuple(context):
    return tuple(context[field] for field in _CONTEXT_ORDER)


def _context_bytes(context, work):
    return evidence.capability._wire(context, evidence.capture._SharedLedger(work),
        MAX_CONTEXT_BYTES, bundle.MAX_CONTEXT_NODES)


def _name(raw_context, work):
    digest = evidence.plan._frame(SLOT_DOMAIN, (raw_context,), work)
    return _PREFIX + digest[7:]


class ActivationExecutionBundleStore:
    """PID/UID/GID-bound no-replace storage; no directory or key provisioning."""

    __slots__ = ("_pid", "_configuration", "_binding", "_closed", "_directory_fd",
        "_directory_stamp", "_io", "_entries", "_used_bytes")

    def __init__(self, *, directory_fd, expected_device, expected_inode, expected_uid, expected_gid,
            maximum_records, quota_bytes, configuration_digest, bundle_key,
            live_window, work, transport_deadline_ns=None):
        for value, minimum, maximum in ((directory_fd, 0, 2**31 - 1),
                (expected_device, 0, 2**64 - 1), (expected_inode, 1, 2**64 - 1),
                (expected_uid, 1, 2**32 - 2), (expected_gid, 0, 2**32 - 2),
                (maximum_records, 1, MAX_RECORDS), (quota_bytes, 1, MAX_QUOTA_BYTES)):
            shape._integer(value, maximum, minimum=minimum)
        shape._digest(configuration_digest)
        if type(bundle_key) is not bytes or len(bundle_key) != bundle.KEY_BYTES:
            _fail("activation execution store requires an independent exact 32-byte bundle key")
        self._pid = os.getpid()
        self._binding = (expected_device, expected_inode, expected_uid, expected_gid)
        self._configuration = (authority.SOURCE_REVISION, configuration_digest, bundle_key,
            self._binding, maximum_records, quota_bytes)
        self._closed, self._directory_fd, self._directory_stamp, self._io = False, None, None, None
        self._entries, self._used_bytes = {}, 0
        window, bound, current = self._window(live_window, transport_deadline_ns, work)
        self._require_process()
        self._directory_metadata(directory_fd, work, current)
        try:
            # Opening '.' owns an independent flock lease; dup would share it.
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
                    _fail("activation execution store changed before recovery")
                for name, identity in self._inventory(work, current).items():
                    raw, observed = self._read_file(name, work, current, synchronize=True)
                    if observed != identity:
                        _fail("activation execution record changed during recovery")
                    context, raw_context, _plan, _cipher = self._decode(raw, window, bound, work, current)
                    if name != _name(raw_context, work):
                        _fail("activation execution record differs from its context slot")
                    self._entries[name] = (_context_tuple(context), self._digest(raw, work, current), observed)
                    self._used_bytes += len(raw)
                if self._stamp(work, current) != before:
                    _fail("activation execution store changed during recovery")
                current()
                return before

            # The genuine bounded scan itself consumes the same work ledger.
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

    @staticmethod
    def _window(live_window, transport_deadline_ns, work):
        window, current = delivery._window(live_window, transport_deadline_ns, work)
        bound = window[4] if transport_deadline_ns is None else min(window[4], transport_deadline_ns)
        current()
        return window, bound, current

    def _require_process(self):
        if type(self) is not ActivationExecutionBundleStore or os.getpid() != self._pid:
            _fail("activation execution store is not its original process owner")
        if self._closed:
            _fail("activation execution store is closed")
        if (os.geteuid(), os.getegid()) != self._binding[2:]:
            if self._io is not None:
                self._io.poison()
            _fail("activation execution store process differs from its provisioned owner")

    def _snapshot_configuration(self):
        self._require_process()
        with self._io.ready():
            self._require_process()
            return self._configuration

    def _directory_metadata(self, descriptor, work, current):
        metadata = _native(work, current, lambda: os.fstat(descriptor))
        if (not stat.S_ISDIR(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o700
                or metadata.st_nlink < 1
                or (metadata.st_dev, metadata.st_ino, metadata.st_uid, metadata.st_gid) != self._binding):
            _fail("activation execution directory differs from its pinned private identity")
        return metadata

    def _stamp(self, work, current):
        metadata = self._directory_metadata(self._directory_fd, work, current)
        return (metadata.st_dev, metadata.st_ino, metadata.st_mtime_ns, metadata.st_ctime_ns)

    def _file_identity(self, metadata):
        if (not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o400
                or metadata.st_nlink != 1 or metadata.st_dev != self._binding[0]
                or (metadata.st_uid, metadata.st_gid) != self._binding[2:]
                or not MIN_RECORD_BYTES <= metadata.st_size <= MAX_RECORD_BYTES):
            _fail("activation execution record is not bounded private immutable material")
        return _identity(metadata)

    def _inventory(self, work, current):
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
                if len(names) >= self._configuration[4]:
                    _fail("activation execution store exceeds its record count")
                name = entry.name
                if (type(name) is not str or len(name) != len(_PREFIX) + 64 or not name.startswith(_PREFIX)
                        or any(point not in _HEX for point in name[len(_PREFIX):]) or name in names):
                    _fail("activation execution store contains an unknown or temporary entry")
                work.charge(input_bytes=len(name))
                metadata = _native(work, current, lambda: os.stat(name,
                    dir_fd=self._directory_fd, follow_symlinks=False))
                identity = self._file_identity(metadata)
                total += metadata.st_size
                if total > self._configuration[5]:
                    _fail("activation execution store exceeds its byte quota")
                names[name] = identity
        current()
        return names

    def _continuity(self, work, current):
        self._require_process()
        self._io.require_ready()
        if self._stamp(work, current) != self._directory_stamp:
            _fail("activation execution directory changed outside this owner")
        actual = self._inventory(work, current)
        if len(actual) != len(self._entries):
            _fail("activation execution store lost or acquired a record")
        for name, identity in actual.items():
            if name not in self._entries or identity != self._entries[name][2]:
                _fail("activation execution record identity changed outside this owner")
        if self._stamp(work, current) != self._directory_stamp:
            _fail("activation execution directory changed during continuity checks")

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
                    min(journal._READ_CHUNK, before.st_size - len(value))))
                if not raw:
                    _fail("activation execution record was truncated")
                value.extend(raw)
            if _native(work, current, lambda: os.read(descriptor, 1)):
                _fail("activation execution record grew during read")
            if synchronize:
                _native(work, current, lambda: os.fsync(descriptor))
            after = _native(work, current, lambda: os.fstat(descriptor))
            named = _native(work, current, lambda: os.stat(name,
                dir_fd=self._directory_fd, follow_symlinks=False))
            if identity != _identity(after) or identity != _identity(named):
                _fail("activation execution record changed during stable read")
            return bytes(value), identity
        finally:
            os.close(descriptor)

    def _digest(self, raw, work, current):
        work.charge(hashes=1, input_bytes=len(raw))
        return _native(work, current, lambda: "sha256:" + hashlib.sha256(raw).hexdigest())

    def _plan(self, context, envelope, work, current):
        if context["configurationDigest"] != self._configuration[1]:
            _fail("activation execution record belongs to a different configuration")
        decoded = contract._decode_on_work(envelope, envelope=True, work=work)
        for field in ("sourceRevision", "configurationDigest", "requestDigest"):
            shape._literal(decoded["payload"][field], context[field])
        shape._literal(evidence.plan._frame(contract.IDENTITY_DOMAIN, (envelope,), work), context["planDigest"])
        current()

    def _validate(self, context, envelope, cipher, window, bound, work, current):
        self._plan(context, envelope, work, current)
        original = bundle._open_on_work(bundle_bytes=cipher, bundle_key=self._configuration[2],
            expected_context=context, live_window=window, transport_deadline_ns=bound, work=work)
        current()
        scope = {field: context[field] for field in journal.SCOPE_FIELDS}
        document = journal._decode_original_on_work(original, scope=scope, work=work)
        embedded = journal.registration._encoded_original(document["planEnvelopeBase64Url"], MAX_PLAN_BYTES, work)
        work.charge(input_bytes=len(embedded) + len(envelope))
        if embedded != envelope:
            _fail("activation execution bundle contains a different original plan")
        current()

    def _decode(self, raw, window, bound, work, current):
        if type(raw) is not bytes or not MIN_RECORD_BYTES <= len(raw) <= MAX_RECORD_BYTES or raw[:8] != MAGIC:
            _fail("activation execution record has an unknown bounded frame")
        work.charge(input_bytes=HEADER_BYTES)
        context_size = int.from_bytes(raw[8:12], "big")
        plan_size, bundle_size = int.from_bytes(raw[12:16], "big"), int.from_bytes(raw[16:24], "big")
        if (not 2 <= context_size <= MAX_CONTEXT_BYTES or not 2 <= plan_size <= MAX_PLAN_BYTES
                or not bundle.OVERHEAD_BYTES + 2 <= bundle_size <= bundle.MAX_BYTES
                or len(raw) != HEADER_BYTES + context_size + plan_size + bundle_size):
            _fail("activation execution record has a malformed length vector")
        work.charge(input_bytes=len(raw))
        plan_offset, bundle_offset = HEADER_BYTES + context_size, HEADER_BYTES + context_size + plan_size
        raw_context, envelope, cipher = raw[HEADER_BYTES:plan_offset], raw[plan_offset:bundle_offset], raw[bundle_offset:]
        value = evidence.wire._decode_object(raw_context, work=work, maximum_bytes=MAX_CONTEXT_BYTES,
            maximum_nodes=bundle.MAX_CONTEXT_NODES, maximum_depth=2)
        context = _capture(self._configuration[2], value, envelope, cipher)
        evidence.capability._canonical(raw_context, context, evidence.capture._SharedLedger(work),
            MAX_CONTEXT_BYTES, bundle.MAX_CONTEXT_NODES)
        self._validate(context, envelope, cipher, window, bound, work, current)
        return context, raw_context, envelope, cipher

    def _retained(self, name, held, envelope, window, bound, work, current):
        previous = self._entries[name]
        raw, identity = self._read_file(name, work, current)
        if (previous[0] != _context_tuple(held) or identity != previous[2]
                or self._digest(raw, work, current) != previous[1]):
            _fail("activation execution record differs from its retained first identity")
        context, raw_context, old_plan, cipher = self._decode(raw, window, bound, work, current)
        work.charge(input_bytes=len(old_plan) + len(envelope))
        if _context_tuple(context) != previous[0] or name != _name(raw_context, work) or old_plan != envelope:
            _fail("activation execution record differs from its independent context or plan")
        return cipher

    def read(self, *, context, envelope_bytes, live_window, work, transport_deadline_ns):
        held = _capture(self._configuration[2], context, envelope_bytes)
        journal.registration._integer(transport_deadline_ns, "execution store inherited deadline", 1)
        self._require_process()
        window, bound, current = self._window(live_window, transport_deadline_ns, work)
        with self._io.ready():
            try:
                self._continuity(work, current)
                self._plan(held, envelope_bytes, work, current)
                name = _name(_context_bytes(held, work), work)
                result = None if name not in self._entries else self._retained(
                    name, held, envelope_bytes, window, bound, work, current)
                self._continuity(work, current)
                current()
                return result
            except BaseException:
                self._io.poison()
                raise

    def append(self, *, context, envelope_bytes, bundle_bytes, live_window, work, transport_deadline_ns):
        bundle._bounded_frame(bundle_bytes)
        held = _capture(self._configuration[2], context, envelope_bytes, bundle_bytes)
        journal.registration._integer(transport_deadline_ns, "execution store inherited deadline", 1)
        self._require_process()
        window, bound, current = self._window(live_window, transport_deadline_ns, work)
        with self._io.ready():
            try:
                self._continuity(work, current)
                raw_context = _context_bytes(held, work)
                name = _name(raw_context, work)
                if name in self._entries:
                    first = self._retained(name, held, envelope_bytes, window, bound, work, current)
                    work.charge(input_bytes=len(first) + len(bundle_bytes))
                    if first != bundle_bytes:
                        _fail("activation execution store refuses changed first ciphertext")
                    self._continuity(work, current)
                    current()
                    return first
                size = HEADER_BYTES + len(raw_context) + len(envelope_bytes) + len(bundle_bytes)
                if (size > MAX_RECORD_BYTES or len(self._entries) >= self._configuration[4]
                        or size > self._configuration[5] - self._used_bytes):
                    _fail("activation execution record count or byte quota is exhausted")
                self._validate(held, envelope_bytes, bundle_bytes, window, bound, work, current)
                work.charge(input_bytes=size + HEADER_BYTES)
                header = (MAGIC + len(raw_context).to_bytes(4, "big")
                    + len(envelope_bytes).to_bytes(4, "big") + len(bundle_bytes).to_bytes(8, "big"))
                raw = b"".join((header, raw_context, envelope_bytes, bundle_bytes))
                digest = self._digest(raw, work, current)
                self._continuity(work, current)
                work.charge(input_bytes=len(raw))
                _native(work, current, lambda: self._io.publish("pending-" + name[len(_PREFIX):], name, raw))
                observed, identity = self._read_file(name, work, current)
                work.charge(input_bytes=len(raw) + len(observed))
                if observed != raw:
                    _fail("activation execution durable record differs from publication")
                _context, _raw_context, _plan, cipher = self._decode(observed, window, bound, work, current)
                self._entries[name] = (_context_tuple(held), digest, identity)
                self._used_bytes += len(raw)
                self._directory_stamp = self._stamp(work, current)
                self._continuity(work, current)
                current()
                return cipher
            except BaseException:
                # A visible publication survives uncertainty; this owner never
                # deletes originals, clears a conflict or grants retry permission.
                self._io.poison()
                raise

    def close(self):
        if os.getpid() != self._pid:
            _fail("forked process cannot close the activation execution store")
        if self._closed:
            return
        with self._io.lock:
            if self._closed:
                return
            self._closed = True
            self._io.poison()
            descriptor, self._directory_fd = self._directory_fd, None
            os.close(descriptor)
