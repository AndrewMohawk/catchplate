"""One exact token-free release outcome in a separately authorized directory.

Storage authorization is current root-original authority, not record content.
The cold checkpoint is exact; it is not inferred from a directory scan. This
owner discloses no token and returns no release proof or recovery permission.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
import stat
import threading
import time

from serverware import authority_current_root_journal as storage
from serverware import oidc_session_activation_release_outcome as records
from serverware import oidc_session_activation_release_outcome_authorization as grants


authorization, capture, plan = grants.authorization, grants.capture, grants.plan
shape, production, keys = grants.shape, grants.production, grants.keys
SERVICE_UID, SERVICE_GID, PROCESS_MODE = grants.SERVICE_UID, grants.SERVICE_GID, grants.PROCESS_MODE
MAX_BYTES = records.MAX_BYTES
BINDING_FIELDS = grants.SCOPE_FIELDS - {"directory", "checkpoint"}
_PHYSICAL_RECORD_LIMIT = 2
_INVENTORY_BYTES = _PHYSICAL_RECORD_LIMIT * (255 + 9 * 8)
_LOCK_TYPE = type(threading.Lock())


class ReleaseOutcomeStoreError(ValueError):
    pass


def _fail(message):
    raise ReleaseOutcomeStoreError(message)


def _process():
    if (os.getresuid() != (SERVICE_UID,) * 3 or os.getresgid() != (SERVICE_GID,) * 3
            or os.getgroups() or os.environ.get("SERVERWARE_PROCESS_MODE") != PROCESS_MODE):
        _fail("release outcome storage requires its fixed isolated release process")


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _Configuration:
    source_revision: str
    authorization_bytes: bytes
    root_public_key: object
    root_spki_digest: str
    scope_bytes: bytes
    binding_bytes: bytes
    authorization_digest: str
    directory_binding: tuple


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _State:
    record_bytes: bytes | None
    outcome_digest: str | None
    metadata: storage.CurrentRootRecord | None


def _binding(value, work):
    owned = grants._capture(value, work)
    shape._object(owned, BINDING_FIELDS, "release outcome independent binding")
    for name in ("configurationDigest", "generationDigest", "runtimeClosureDigest", "releaseCustodyDigest"):
        shape._digest(owned[name])
    authorization._token(owned["databaseId"])
    shape.validate_identity_shape(owned["receiverIdentity"])
    grants.registration._text(owned["deliveryId"], "release outcome delivery identity",
        grants.delivery._SCOPE_LIMITS["deliveryId"], work)
    return owned


def _record_binding(record, work):
    value = {name: record["scope"][name] for name in (
        "configurationDigest", "databaseId", "generationDigest", "runtimeClosureDigest", "receiverIdentity")}
    value["deliveryId"] = record["releaseBinding"]["deliveryScope"]["deliveryId"]
    value["releaseCustodyDigest"] = record["evidenceBinding"]["releaseCustodyDigest"]
    return _binding(value, work)


def _same_bytes(actual, expected, work, label):
    work.charge(input_bytes=len(actual) + len(expected))
    if actual != expected:
        _fail(label + " differs")


@dataclass(frozen=True, slots=True, init=False, repr=False, eq=False)
class ReleaseOutcomeStore:
    _configured: _Configuration | None
    _seal: _Configuration | None
    _state: _State
    _state_seal: _State
    _journal: object
    _journal_seal: object
    _lifetime: tuple
    _lifetime_seal: tuple
    _pid: int
    _lock: object
    _closed: bool
    _ready: bool
    _last_epoch: int
    _last_monotonic: int

    def __init__(self, *, directory_fd, authorization_bytes, root_public_key,
            expected_scope, live_window, transport_deadline_ns, work):
        capture._SharedLedger(work)
        original = authorization._original(authorization_bytes, grants.MAX_BYTES, "release outcome storage authorization")
        root, descriptor = root_public_key, directory_fd
        authorization._public(root)
        shape._integer(descriptor, 2**31 - 1)
        window = grants.clock._validate(live_window)
        shape._integer(transport_deadline_ns, minimum=1)
        bound = min(window[4], transport_deadline_ns)
        scope = grants._scope(expected_scope, work)
        _process()
        admitted = grants._verify_on_work(authorization_bytes=original, root_public_key=root,
            expected_scope=scope, live_window=window, transport_deadline_ns=bound, work=work)
        admitted.live()
        scope_bytes = grants._wire(scope, work)
        binding = _binding({name: scope[name] for name in BINDING_FIELDS}, work)
        binding_bytes = grants._wire(binding, work)
        root_digest = keys._spki_on_work(root, work)
        admitted.live()
        directory = scope["directory"]
        configured = _Configuration(grants.authority.SOURCE_REVISION, original, root,
            root_digest, scope_bytes, binding_bytes, admitted.authorization_digest,
            tuple(directory[name] for name in ("device", "inode", "uid", "gid")))
        empty = _State(None, None, None)
        lifetime = (work, window, bound)
        for name, value in (("_configured", configured), ("_seal", configured),
                ("_state", empty), ("_state_seal", empty), ("_journal", None), ("_journal_seal", None),
                ("_lifetime", lifetime), ("_lifetime_seal", lifetime),
                ("_pid", os.getpid()), ("_lock", threading.Lock()), ("_closed", False), ("_ready", False),
                ("_last_epoch", window[0]), ("_last_monotonic", window[2])):
            object.__setattr__(self, name, value)
        current = self._guard(configured, admitted.live, window, bound, work)
        acquired = None
        try:
            current()

            def open_journal():
                nonlocal acquired
                acquired = storage.CurrentRootJournal(directory_fd=descriptor,
                    expected_device=directory["device"], expected_inode=directory["inode"],
                    expected_uid=directory["uid"], expected_gid=directory["gid"],
                    maximum_records=_PHYSICAL_RECORD_LIMIT)
                # Own the resource before the stable callback's suffix can fail.
                object.__setattr__(self, "_journal", acquired)
                object.__setattr__(self, "_journal_seal", acquired)
                return acquired

            production._callback(work, open_journal)
            current()
            self._preflight(work, current)
            recovered_raw = recovered_digest = None

            def recover_record(sequence, raw):
                nonlocal recovered_raw, recovered_digest
                current()
                if sequence != 1 or recovered_raw is not None:
                    _fail("release outcome protocol permits exactly zero or one record")
                observed = records._decode_on_work(raw, work)
                plan._same(_record_binding(observed, work), binding, work,
                    "release outcome recovered record differs from root storage binding")
                recovered_digest = records._digest_on_work(raw, work)
                recovered_raw = raw
                current()

            # Recovery legitimately charges the same work in its native reader
            # and semantic reducer. Never wrap the whole call in _callback.
            work.charge(input_bytes=_INVENTORY_BYTES)
            metadata = storage.CurrentRootJournal.recover(acquired, recover_record, work=work)
            current()
            checkpoint = scope["checkpoint"]
            plan._same(len(metadata), checkpoint["recordCount"], work, "release outcome exact cold record count")
            plan._same(recovered_digest, checkpoint["outcomeDigest"], work, "release outcome exact cold domain identity")
            if len(metadata) > 1 or metadata and metadata[0].sequence != 1:
                _fail("release outcome recovered an invalid physical sequence")
            state = _State(recovered_raw, recovered_digest, None if not metadata else metadata[0])
            object.__setattr__(self, "_state", state)
            object.__setattr__(self, "_state_seal", state)
            object.__setattr__(self, "_ready", True)
            self._continuity(work, current)
            current()
        except BaseException:
            self._poison_close()
            raise

    def _identity(self, configured):
        if (type(self) is not ReleaseOutcomeStore or self._closed or self._pid != os.getpid()
                or type(self._lock) is not _LOCK_TYPE or type(configured) is not _Configuration
                or self._configured is not configured or self._seal is not configured
                or configured.source_revision != grants.authority.SOURCE_REVISION
                or type(self._state) is not _State or self._state is not self._state_seal
                or type(self._lifetime) is not tuple or self._lifetime is not self._lifetime_seal
                or self._journal is not self._journal_seal
                or self._journal is not None and type(self._journal) is not storage.CurrentRootJournal):
            _fail("release outcome owner is closed, changed or belongs to another process")
        _process()

    def _snapshot_configuration(self):
        configured = self._configured
        self._identity(configured)
        if not self._ready or type(self._journal) is not storage.CurrentRootJournal:
            _fail("release outcome owner has not completed exact cold admission")
        return configured

    def _narrow_lifetime(self, work, window, bound):
        original_work, prior, prior_bound = self._lifetime
        if (work is not original_work or window[:3] != prior[:3] or bound > prior_bound
                or any(actual > previous for actual, previous in zip(window[3:], prior[3:]))):
            _fail("release outcome owner cannot renew its original processing allowance")
        lifetime = (work, window, bound)
        object.__setattr__(self, "_lifetime", lifetime)
        object.__setattr__(self, "_lifetime_seal", lifetime)

    def _guard(self, configured, grant_live, window, bound, work):
        _window, processing = grants.delivery._window(window, bound, work)

        def current():
            self._identity(configured)
            first = processing()
            enrolled = grant_live()
            finished = processing()
            monotonic = production._callback(work, time.monotonic_ns)
            shape._integer(monotonic, minimum=1)
            if (first < self._last_epoch or enrolled < first or finished < enrolled
                    or monotonic < self._last_monotonic or monotonic >= bound):
                _fail("release outcome current authority expired or clocks reversed")
            object.__setattr__(self, "_last_epoch", finished)
            object.__setattr__(self, "_last_monotonic", monotonic)
            self._identity(configured)
            return finished

        return current

    def _preflight(self, work, current):
        journal = self._journal

        def inspect():
            storage.CurrentRootJournal._require_process(journal)
            storage.CurrentRootJournal._directory_metadata(journal, journal._directory_fd)
            count = 0
            with os.scandir(journal._directory_fd) as entries:
                for entry in entries:
                    count += 1
                    sequence, _digest = storage._parse_name(entry.name)
                    if count > 1 or sequence != 1:
                        _fail("release outcome directory contains more than its one fixed slot")
                    info = os.stat(entry.name, dir_fd=journal._directory_fd, follow_symlinks=False)
                    if not stat.S_ISREG(info.st_mode) or not 2 <= info.st_size <= MAX_BYTES:
                        _fail("release outcome file exceeds the exact codec byte cap")

        current()
        work.charge(input_bytes=_INVENTORY_BYTES)
        production._callback(work, inspect)
        current()

    def _continuity(self, work, current):
        current()
        work.charge(input_bytes=_INVENTORY_BYTES)
        observed = production._callback(work,
            lambda: storage.CurrentRootJournal.records.fget(self._journal))
        expected = () if self._state.metadata is None else (self._state.metadata,)
        if observed != expected:
            _fail("release outcome journal differs from its first retained state")
        current()

    def _read_exact(self, metadata, original, work, current):
        current()
        # Actual stat size is charged by the native reader before allocation;
        # it closes normally before returning, including its fsync/readback.
        observed, returned, _identity = storage.CurrentRootJournal._read_record(self._journal,
            storage._name(metadata), metadata.sequence, metadata.digest, synchronize=True, work=work)
        current()
        if returned != metadata:
            _fail("release outcome durable metadata changed")
        _same_bytes(observed, original, work, "release outcome durable original")
        current()

    def retain_on_work(self, *, record_bytes, root_public_key, expected_binding,
            live_window, transport_deadline_ns, work):
        capture._SharedLedger(work)
        original = authorization._original(record_bytes, MAX_BYTES, "release outcome record")
        root = root_public_key
        authorization._public(root)
        window = grants.clock._validate(live_window)
        shape._integer(transport_deadline_ns, minimum=1)
        bound = min(window[4], transport_deadline_ns)
        configured = self._snapshot_configuration()
        lock = self._lock
        if not lock.acquire(blocking=False):
            _fail("release outcome owner is already in use")
        try:
            self._narrow_lifetime(work, window, bound)
            binding = _binding(expected_binding, work)
            actual_root = keys._spki_on_work(root, work)
            plan._same(actual_root, configured.root_spki_digest, work, "release outcome independently supplied root")
            plan._same(keys._spki_on_work(configured.root_public_key, work), configured.root_spki_digest,
                work, "release outcome held root")
            scope = grants.capability.wire._decode_object(configured.scope_bytes, work=work,
                maximum_bytes=grants.MAX_BYTES, maximum_nodes=grants.MAX_NODES, maximum_depth=grants.MAX_DEPTH)
            admitted = grants._verify_on_work(authorization_bytes=configured.authorization_bytes,
                root_public_key=root, expected_scope=scope, live_window=window,
                transport_deadline_ns=bound, work=work)
            current = self._guard(configured, admitted.live, window, bound, work)
            current()
            plan._same(admitted.authorization_digest, configured.authorization_digest, work,
                "release outcome held storage authorization")
            _same_bytes(grants._wire(binding, work), configured.binding_bytes, work,
                "release outcome independently supplied binding")
            plan._same({name: admitted.payload[name] for name in BINDING_FIELDS}, binding, work,
                "release outcome current root-authorized binding")
            record = records._decode_on_work(original, work)
            plan._same(_record_binding(record, work), binding, work, "release outcome actual record binding")
            outcome_digest = records._digest_on_work(original, work)
            current()
            self._continuity(work, current)
            prior = self._state
            if prior.record_bytes is not None:
                _same_bytes(original, prior.record_bytes, work, "release outcome first exact record")
                plan._same(outcome_digest, prior.outcome_digest, work, "release outcome first domain identity")
                self._read_exact(prior.metadata, original, work, current)
            else:
                # Raw hashing, publication and native readback are bounded
                # before entering the metrics-stable native append callback.
                work.charge(hashes=2, input_bytes=6 * len(original) + 1 + _INVENTORY_BYTES)
                metadata = production._callback(work,
                    lambda: storage.CurrentRootJournal.append(self._journal, original))
                current()
                if type(metadata) is not storage.CurrentRootRecord or metadata.sequence != 1:
                    _fail("release outcome publication did not occupy its one fixed slot")
                self._read_exact(metadata, original, work, current)
                state = _State(original, outcome_digest, metadata)
                object.__setattr__(self, "_state", state)
                object.__setattr__(self, "_state_seal", state)
                # The root checkpoint admitted the initial cold state. Own
                # publication advances held state; it does not reapply 0/null.
            self._continuity(work, current)
            current()
            return self._state.outcome_digest
        except BaseException:
            self._poison_close()
            raise
        finally:
            lock.release()

    def _poison_close(self):
        object.__setattr__(self, "_closed", True)
        object.__setattr__(self, "_ready", False)
        journal = self._journal
        if type(journal) is storage.CurrentRootJournal:
            try:
                storage.CurrentRootJournal.poison(journal)
            finally:
                storage.CurrentRootJournal.close(journal)

    def close(self):
        if type(self) is not ReleaseOutcomeStore or self._pid != os.getpid():
            _fail("release outcome close requires its actual process owner")
        if self._closed:
            return
        lock = self._lock
        if not lock.acquire(blocking=False):
            _fail("release outcome cannot close during another operation")
        try:
            self._poison_close()
        finally:
            lock.release()
