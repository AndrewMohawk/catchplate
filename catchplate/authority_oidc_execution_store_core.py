"""Private storage mechanics for two exact source-fixed ciphertext owners.

Only the actual activation and delivery-consume wrapper classes select their
own codecs and formats. No caller-selected profile, callback, subclass or
successful replay carrier is an admitted storage authority.
"""
from __future__ import annotations

import fcntl
import hashlib
import os
import stat

from catchplate import authority_oidc_session_activation_journal as journal
from catchplate.authority_witness_journal import WitnessJournalIO


authority, shape, evidence = journal.authority, journal.shape, journal.evidence
delivery = journal.delivery
HEADER_BYTES = 24
MAX_RECORD_BYTES = authority.MAX_RESULT_BYTES
MAX_RECORDS, MAX_QUOTA_BYTES = journal.MAX_RECORDS, journal.MAX_QUOTA_BYTES
_HEX = frozenset("0123456789abcdef")
_native, _open, _identity = journal._native, journal._open, journal._identity


class _ExecutionStoreError(RuntimeError):
    pass


def _profile(owner):
    """Resolve exact installed classes only; no profile argument or registry."""
    from catchplate import authority_oidc_session_activation_execution_store as activation
    from catchplate import authority_oidc_session_activation_delivery_execution_store as consume

    if type(owner) is activation.ActivationExecutionBundleStore:
        return activation
    if type(owner) is consume.DeliveryExecutionBundleStore:
        return consume
    raise _ExecutionStoreError("execution storage requires an exact source-fixed owner class")


def _capture(owner, key, context, envelope_bytes, bundle_bytes=None):
    """Hold all external originals before clock, hashing or file callbacks."""
    profile = _profile(owner)
    bundle = profile.bundle
    _key, held, _scope = bundle._capture(key, context)
    if type(envelope_bytes) is not bytes or not 2 <= len(envelope_bytes) <= profile.MAX_PLAN_BYTES:
        owner._fail("execution store requires a bounded original plan")
    if bundle_bytes is not None:
        bundle._bounded_frame(bundle_bytes)
        if HEADER_BYTES + 2 + len(envelope_bytes) + len(bundle_bytes) > MAX_RECORD_BYTES:
            owner._fail("execution record exceeds its whole-record bound")
    return held


def _context_tuple(owner, context):
    return tuple(context[field] for field in _profile(owner)._CONTEXT_ORDER)


def _context_bytes(owner, context, work):
    return _profile(owner)._context_bytes(context, work)


def _name(owner, raw_context, work):
    profile = _profile(owner)
    digest = evidence.plan._frame(profile.SLOT_DOMAIN, (raw_context,), work)
    return profile._PREFIX + digest[7:]


def _record_limit(owner, maximum):
    selected = MAX_RECORD_BYTES if maximum is None else maximum
    if type(selected) is not int or not 1 <= selected <= MAX_RECORD_BYTES:
        owner._fail("execution record limit must only tighten the source maximum")
    return selected


class _ExecutionBundleStore:
    """PID/UID/GID-bound no-replace storage; no directory or key provisioning."""

    __slots__ = ("_pid", "_configuration", "_binding", "_closed", "_directory_fd",
        "_directory_stamp", "_io", "_entries", "_used_bytes")

    def __init__(self, *, directory_fd, expected_device, expected_inode, expected_uid, expected_gid,
            maximum_records, quota_bytes, configuration_digest, bundle_key,
            live_window, work, transport_deadline_ns=None, maximum_record_bytes=None, _current=None):
        profile = _profile(self)
        record_limit = _record_limit(self, maximum_record_bytes)
        for value, minimum, maximum in ((directory_fd, 0, 2**31 - 1),
                (expected_device, 0, 2**64 - 1), (expected_inode, 1, 2**64 - 1),
                (expected_uid, 1, 2**32 - 2), (expected_gid, 0, 2**32 - 2),
                (maximum_records, 1, MAX_RECORDS), (quota_bytes, 1, MAX_QUOTA_BYTES)):
            shape._integer(value, maximum, minimum=minimum)
        shape._digest(configuration_digest)
        if type(bundle_key) is not bytes or len(bundle_key) != profile.bundle.KEY_BYTES:
            self._fail("execution store requires an independent exact 32-byte bundle key")
        self._pid = os.getpid()
        self._binding = (expected_device, expected_inode, expected_uid, expected_gid)
        self._configuration = (authority.SOURCE_REVISION, configuration_digest, bundle_key,
            self._binding, maximum_records, quota_bytes)
        self._closed, self._directory_fd, self._directory_stamp, self._io = False, None, None, None
        self._entries, self._used_bytes = {}, 0
        window, bound, current = self._window(live_window, transport_deadline_ns, work, _current)
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
                    self._fail("execution store changed before recovery")
                for name, identity in self._inventory(work, current).items():
                    raw, observed = self._read_file(name, work, current, synchronize=True,
                        maximum_record_bytes=record_limit)
                    if observed != identity:
                        self._fail("execution record changed during recovery")
                    context, raw_context, _plan, _cipher = self._decode(raw, window, bound, work, current,
                        _current=_current)
                    if name != _name(self, raw_context, work):
                        self._fail("execution record differs from its context slot")
                    self._entries[name] = (_context_tuple(self, context), self._digest(raw, work, current), observed)
                    self._used_bytes += len(raw)
                if self._stamp(work, current) != before:
                    self._fail("execution store changed during recovery")
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

    def _fail(self, message):
        raise _profile(self).StoreError(message)

    @staticmethod
    def _window(live_window, transport_deadline_ns, work, _current=None):
        window, current = delivery._window(live_window, transport_deadline_ns, work)
        current = delivery._join_current(current, _current, work)
        bound = window[4] if transport_deadline_ns is None else min(window[4], transport_deadline_ns)
        current()
        return window, bound, current

    def _require_process(self):
        _profile(self)
        if os.getpid() != self._pid:
            self._fail("execution store is not its original process owner")
        if self._closed:
            self._fail("execution store is closed")
        if (os.geteuid(), os.getegid()) != self._binding[2:]:
            if self._io is not None:
                self._io.poison()
            self._fail("execution store process differs from its provisioned owner")

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
            self._fail("execution directory differs from its pinned private identity")
        return metadata

    def _stamp(self, work, current):
        metadata = self._directory_metadata(self._directory_fd, work, current)
        return (metadata.st_dev, metadata.st_ino, metadata.st_mtime_ns, metadata.st_ctime_ns)

    def _file_identity(self, metadata):
        if (not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o400
                or metadata.st_nlink != 1 or metadata.st_dev != self._binding[0]
                or (metadata.st_uid, metadata.st_gid) != self._binding[2:]
                or not _profile(self).MIN_RECORD_BYTES <= metadata.st_size <= MAX_RECORD_BYTES):
            self._fail("execution record is not bounded private immutable material")
        return _identity(metadata)

    def _inventory(self, work, current):
        prefix = _profile(self)._PREFIX
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
                    self._fail("execution store exceeds its record count")
                name = entry.name
                if (type(name) is not str or len(name) != len(prefix) + 64 or not name.startswith(prefix)
                        or any(point not in _HEX for point in name[len(prefix):]) or name in names):
                    self._fail("execution store contains an unknown or temporary entry")
                work.charge(input_bytes=len(name))
                metadata = _native(work, current, lambda: os.stat(name,
                    dir_fd=self._directory_fd, follow_symlinks=False))
                identity = self._file_identity(metadata)
                total += metadata.st_size
                if total > self._configuration[5]:
                    self._fail("execution store exceeds its byte quota")
                names[name] = identity
        current()
        return names

    def _continuity(self, work, current):
        self._require_process()
        self._io.require_ready()
        if self._stamp(work, current) != self._directory_stamp:
            self._fail("execution directory changed outside this owner")
        actual = self._inventory(work, current)
        if len(actual) != len(self._entries):
            self._fail("execution store lost or acquired a record")
        for name, identity in actual.items():
            if name not in self._entries or identity != self._entries[name][2]:
                self._fail("execution record identity changed outside this owner")
        if self._stamp(work, current) != self._directory_stamp:
            self._fail("execution directory changed during continuity checks")

    def _read_file(self, name, work, current, *, synchronize=False, maximum_record_bytes=None):
        maximum = _record_limit(self, maximum_record_bytes)
        descriptor = _open(work, current, lambda: os.open(name,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self._directory_fd))
        try:
            before = _native(work, current, lambda: os.fstat(descriptor))
            identity = self._file_identity(before)
            if before.st_size > maximum:
                self._fail("execution record exceeds the remaining held inventory")
            work.charge(input_bytes=2 * before.st_size)
            value = bytearray()
            while len(value) < before.st_size:
                raw = _native(work, current, lambda: os.read(descriptor,
                    min(journal._READ_CHUNK, before.st_size - len(value))))
                if not raw:
                    self._fail("execution record was truncated")
                value.extend(raw)
            if _native(work, current, lambda: os.read(descriptor, 1)):
                self._fail("execution record grew during read")
            if synchronize:
                _native(work, current, lambda: os.fsync(descriptor))
            after = _native(work, current, lambda: os.fstat(descriptor))
            named = _native(work, current, lambda: os.stat(name,
                dir_fd=self._directory_fd, follow_symlinks=False))
            if identity != _identity(after) or identity != _identity(named):
                self._fail("execution record changed during stable read")
            return bytes(value), identity
        finally:
            os.close(descriptor)

    def _digest(self, raw, work, current):
        work.charge(hashes=1, input_bytes=len(raw))
        return _native(work, current, lambda: "sha256:" + hashlib.sha256(raw).hexdigest())

    def _plan(self, context, envelope, work, current):
        contract = _profile(self).contract
        if context["configurationDigest"] != self._configuration[1]:
            self._fail("execution record belongs to a different configuration")
        decoded = contract._decode_on_work(envelope, envelope=True, work=work)
        for field in ("sourceRevision", "configurationDigest", "requestDigest"):
            shape._literal(decoded["payload"][field], context[field])
        shape._literal(evidence.plan._frame(contract.IDENTITY_DOMAIN, (envelope,), work), context["planDigest"])
        current()

    def _validate(self, context, envelope, cipher, window, bound, work, current, *, _current=None):
        profile = _profile(self)
        bundle, original_journal = profile.bundle, profile.journal
        self._plan(context, envelope, work, current)
        if _current is None:
            original = bundle._open_on_work(bundle_bytes=cipher, bundle_key=self._configuration[2],
                expected_context=context, live_window=window, transport_deadline_ns=bound, work=work)
        else:
            from catchplate import authority_oidc_session_activation_delivery_execution_store as consume
            if profile is not consume:
                self._fail("explicit execution continuity is confined to the consume profile")
            original = bundle._open_on_work(bundle_bytes=cipher, bundle_key=self._configuration[2],
                expected_context=context, live_window=window, transport_deadline_ns=bound,
                work=work, _current=current)
        current()
        scope = {field: context[field] for field in original_journal.SCOPE_FIELDS}
        document = original_journal._decode_original_on_work(original, scope=scope, work=work)
        embedded = original_journal.registration._encoded_original(
            document["planEnvelopeBase64Url"], profile.MAX_PLAN_BYTES, work)
        work.charge(input_bytes=len(embedded) + len(envelope))
        if embedded != envelope:
            self._fail("execution bundle contains a different original plan")
        current()

    def _decode(self, raw, window, bound, work, current, *, _current=None):
        profile = _profile(self)
        bundle = profile.bundle
        if (type(raw) is not bytes or not profile.MIN_RECORD_BYTES <= len(raw) <= MAX_RECORD_BYTES
                or raw[:8] != profile.MAGIC):
            self._fail("execution record has an unknown bounded frame")
        work.charge(input_bytes=HEADER_BYTES)
        context_size = int.from_bytes(raw[8:12], "big")
        plan_size, bundle_size = int.from_bytes(raw[12:16], "big"), int.from_bytes(raw[16:24], "big")
        if (not 2 <= context_size <= profile.MAX_CONTEXT_BYTES or not 2 <= plan_size <= profile.MAX_PLAN_BYTES
                or not bundle.OVERHEAD_BYTES + 2 <= bundle_size <= bundle.MAX_BYTES
                or len(raw) != HEADER_BYTES + context_size + plan_size + bundle_size):
            self._fail("execution record has a malformed length vector")
        work.charge(input_bytes=len(raw))
        plan_offset, bundle_offset = HEADER_BYTES + context_size, HEADER_BYTES + context_size + plan_size
        raw_context, envelope, cipher = raw[HEADER_BYTES:plan_offset], raw[plan_offset:bundle_offset], raw[bundle_offset:]
        value = evidence.wire._decode_object(raw_context, work=work, maximum_bytes=profile.MAX_CONTEXT_BYTES,
            maximum_nodes=bundle.MAX_CONTEXT_NODES, maximum_depth=2)
        context = _capture(self, self._configuration[2], value, envelope, cipher)
        evidence.capability._canonical(raw_context, context, evidence.capture._SharedLedger(work),
            profile.MAX_CONTEXT_BYTES, bundle.MAX_CONTEXT_NODES)
        self._validate(context, envelope, cipher, window, bound, work, current, _current=_current)
        return context, raw_context, envelope, cipher

    def _retained(self, name, held, envelope, window, bound, work, current, *,
            maximum_record_bytes=None, _current=None):
        previous = self._entries[name]
        raw, identity = self._read_file(name, work, current, maximum_record_bytes=maximum_record_bytes)
        if (previous[0] != _context_tuple(self, held) or identity != previous[2]
                or self._digest(raw, work, current) != previous[1]):
            self._fail("execution record differs from its retained first identity")
        context, raw_context, old_plan, cipher = self._decode(raw, window, bound, work, current,
            _current=_current)
        work.charge(input_bytes=len(old_plan) + len(envelope))
        if (_context_tuple(self, context) != previous[0]
                or name != _name(self, raw_context, work) or old_plan != envelope):
            self._fail("execution record differs from its independent context or plan")
        return cipher

    def read(self, *, context, envelope_bytes, live_window, work, transport_deadline_ns,
            maximum_record_bytes=None, _current=None):
        maximum = _record_limit(self, maximum_record_bytes)
        held = _capture(self, self._configuration[2], context, envelope_bytes)
        journal.registration._integer(transport_deadline_ns, "execution store inherited deadline", 1)
        self._require_process()
        window, bound, current = self._window(live_window, transport_deadline_ns, work, _current)
        with self._io.ready():
            try:
                self._continuity(work, current)
                self._plan(held, envelope_bytes, work, current)
                name = _name(self, _context_bytes(self, held, work), work)
                result = None if name not in self._entries else self._retained(
                    name, held, envelope_bytes, window, bound, work, current,
                    maximum_record_bytes=maximum, _current=_current)
                self._continuity(work, current)
                current()
                return result
            except BaseException:
                self._io.poison()
                raise

    def append(self, *, context, envelope_bytes, bundle_bytes, live_window, work, transport_deadline_ns,
            maximum_record_bytes=None, _current=None):
        maximum = _record_limit(self, maximum_record_bytes)
        profile = _profile(self)
        profile.bundle._bounded_frame(bundle_bytes)
        held = _capture(self, self._configuration[2], context, envelope_bytes, bundle_bytes)
        journal.registration._integer(transport_deadline_ns, "execution store inherited deadline", 1)
        self._require_process()
        window, bound, current = self._window(live_window, transport_deadline_ns, work, _current)
        with self._io.ready():
            try:
                self._continuity(work, current)
                raw_context = _context_bytes(self, held, work)
                name = _name(self, raw_context, work)
                if name in self._entries:
                    first = self._retained(name, held, envelope_bytes, window, bound, work, current,
                        maximum_record_bytes=maximum, _current=_current)
                    work.charge(input_bytes=len(first) + len(bundle_bytes))
                    if first != bundle_bytes:
                        self._fail("execution store refuses changed first ciphertext")
                    self._continuity(work, current)
                    current()
                    return first
                size = HEADER_BYTES + len(raw_context) + len(envelope_bytes) + len(bundle_bytes)
                if (size > maximum or len(self._entries) >= self._configuration[4]
                        or size > self._configuration[5] - self._used_bytes):
                    self._fail("execution record count or byte quota is exhausted")
                self._validate(held, envelope_bytes, bundle_bytes, window, bound, work, current,
                    _current=_current)
                work.charge(input_bytes=size + HEADER_BYTES)
                header = (profile.MAGIC + len(raw_context).to_bytes(4, "big")
                    + len(envelope_bytes).to_bytes(4, "big") + len(bundle_bytes).to_bytes(8, "big"))
                raw = b"".join((header, raw_context, envelope_bytes, bundle_bytes))
                digest = self._digest(raw, work, current)
                self._continuity(work, current)
                work.charge(input_bytes=len(raw))
                _native(work, current, lambda: self._io.publish("pending-" + name[len(profile._PREFIX):], name, raw))
                observed, identity = self._read_file(name, work, current, maximum_record_bytes=maximum)
                work.charge(input_bytes=len(raw) + len(observed))
                if observed != raw:
                    self._fail("execution durable record differs from publication")
                _context, _raw_context, _plan, cipher = self._decode(observed, window, bound, work, current,
                    _current=_current)
                self._entries[name] = (_context_tuple(self, held), digest, identity)
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
        _profile(self)
        if os.getpid() != self._pid:
            self._fail("forked process cannot close the execution store")
        if self._closed:
            return
        with self._io.lock:
            if self._closed:
                return
            self._closed = True
            self._io.poison()
            descriptor, self._directory_fd = self._directory_fd, None
            os.close(descriptor)
