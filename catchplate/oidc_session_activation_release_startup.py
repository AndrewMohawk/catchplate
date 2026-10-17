"""Construct one root-selected private release owner from actual cold resources.

The original construction work/window survives resource intake and permanent
drop, one owned accept and one original-only operation. Framing belongs to the
separate finite service; accepted sockets never widen the descriptor inventory.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
import select
import stat
import threading
import time

from catchplate import oidc_session_activation_release_bootstrap as bootstrap
from catchplate import oidc_session_activation_release_resources as resources
from catchplate import oidc_session_activation_release_connection as connections
from catchplate import authority_oidc_session_activation_release_custody as custody
from catchplate import authority_oidc_session_activation_release_recovery as recovery
from catchplate import authority_oidc_session_activation_release_outcome_store as stores
from catchplate.authority_query_read_work import _ValidationWork


authorization, shape, clock = bootstrap.authorization, bootstrap.shape, bootstrap.clock
production, plan, delivery = bootstrap.production, bootstrap.plan, bootstrap.delivery
records = stores.records
_INHERITED = tuple(range(198, 203))
_IDENTITY_FIELDS = tuple(sorted(custody.bootstrap.planner_bootstrap._IDENTITY_FIELDS))
_LOCK_TYPE = type(threading.Lock())
_PID, _STATE = os.getpid(), "new"
_STATE_LOCK = threading.Lock()


class ReleaseStartupError(RuntimeError):
    pass


def _fail(message):
    raise ReleaseStartupError(message)


def _begin():
    global _STATE
    with _STATE_LOCK:
        if os.getpid() != _PID or _STATE != "new":
            _fail("release startup cannot restart or cross a process boundary")
        _STATE = "constructing"


def _state(value):
    global _STATE
    with _STATE_LOCK:
        _STATE = value


def _close_owned(owner, store, resource_owner):
    """Close only actual acquired owners; never remove or replace records."""
    failed = False
    for item, kind in ((owner, type(owner)), (store, stores.ReleaseOutcomeStore),
            (resource_owner, resources._Resources)):
        if item is None:
            continue
        try:
            if kind is custody.OidcSessionActivationReleaseCustody:
                custody.OidcSessionActivationReleaseCustody.close(item)
            elif kind is recovery.OidcSessionActivationReleaseRecovery:
                recovery.OidcSessionActivationReleaseRecovery.close(item)
            elif kind is stores.ReleaseOutcomeStore:
                stores.ReleaseOutcomeStore.close(item)
            elif kind is resources._Resources:
                resources._Resources.close(item)
            else:
                failed = True
        except BaseException:
            failed = True
    return not failed


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _Configuration:
    source_revision: str
    resources: resources._Resources
    resource_configuration: object
    root_public_key: object
    profile: str
    store: stores.ReleaseOutcomeStore
    store_configuration: object
    owner: object
    owner_configuration: object
    role_live: object
    release_bytes: bytes
    producer_id: str
    producer_identity: tuple
    caller_id: str
    state_receipt_digest: str
    journal: object
    journal_fd: int
    directory: tuple
    listener_fd: int


def _owner_configuration(owner, profile):
    if profile == bootstrap.LIVE_PROFILE and type(owner) is custody.OidcSessionActivationReleaseCustody:
        return custody.OidcSessionActivationReleaseCustody._snapshot_configuration(owner)
    if profile == bootstrap.RECOVERY_PROFILE and type(owner) is recovery.OidcSessionActivationReleaseRecovery:
        return recovery.OidcSessionActivationReleaseRecovery._snapshot_configuration(owner)
    _fail("release startup selected owner differs from its root profile")


def _directory(configured, connection):
    journal = configured.journal
    if (type(journal) is not stores.storage.CurrentRootJournal
            or configured.store._journal is not journal
            or journal._directory_fd != configured.journal_fd
            or journal._io.directory_descriptor != configured.journal_fd):
        _fail("release startup owned journal descriptor changed")
    value = os.fstat(configured.journal_fd)
    if (not stat.S_ISDIR(value.st_mode) or stat.S_IMODE(value.st_mode) != 0o700
            or (value.st_dev, value.st_ino, value.st_uid, value.st_gid) != configured.directory
            or os.get_inheritable(configured.journal_fd)):
        _fail("release startup owned journal no longer matches root pins")
    expected = (*_INHERITED, configured.journal_fd)
    if connection is not None:
        if type(connection) is not connections._AcceptedConnection:
            _fail("release startup requires its actual accepted connection owner")
        accepted = connections._AcceptedConnection._check(connection)
        if accepted.descriptor in expected:
            _fail("release accepted connection overlaps an inherited resource")
        expected = (*expected, accepted.descriptor)
    connections._require_inventory(expected)


def _hold_originals(*, proof_bytes, proof_enrollment_bytes, intent_bytes,
        intent_enrollment_bytes, old_token_bytes, envelope_bytes, record_bytes, work):
    proof = authorization._original(proof_bytes, custody.release_proof.MAX_BYTES, "release proof original")
    proof_enrollment = authorization._original(proof_enrollment_bytes,
        custody.proof_enrollment.MAX_BYTES, "release proof enrollment original")
    intent = authorization._original(intent_bytes, custody.release_intent.MAX_BYTES, "release intent original")
    intent_enrollment = authorization._original(intent_enrollment_bytes,
        custody.intent_enrollment.MAX_BYTES, "release intent enrollment original")
    token = delivery._token(old_token_bytes, work)
    envelope = delivery._envelope(envelope_bytes, work)
    record = None if record_bytes is None else authorization._original(
        record_bytes, records.MAX_BYTES, "retained release outcome original")
    held = (proof, proof_enrollment, intent, intent_enrollment, token, envelope, record)
    total = sum(len(value) for value in held if value is not None)
    if total > recovery.MAX_ORIGINAL_BYTES:
        _fail("release startup operation exceeds the fixed original byte bound")
    work.charge(input_bytes=total)
    return held


@dataclass(frozen=True, slots=True, init=False, repr=False, eq=False)
class _StartedRelease:
    _configured: _Configuration | None
    _seal: _Configuration | None
    _lifetime: tuple
    _lifetime_seal: tuple
    _pid: int
    _lock: object
    _closed: bool
    _spent: bool
    _accept_spent: bool
    _connection: connections._AcceptedConnection | None
    _connection_seal: connections._AcceptedConnection | None
    _cleanup_failed: bool
    _last_epoch: int
    _last_monotonic: int

    def __init__(self):
        _fail("release startup requires actual original resource construction")

    def _identity(self):
        configured = self._configured
        if (type(self) is not _StartedRelease or self._closed or self._pid != os.getpid()
                or type(self._lock) is not _LOCK_TYPE or type(configured) is not _Configuration
                or configured is not self._seal or configured.source_revision != bootstrap.authority.SOURCE_REVISION
                or self._connection is not self._connection_seal
                or type(self._lifetime) is not tuple or self._lifetime is not self._lifetime_seal):
            _fail("release startup is closed, changed or belongs to another process")
        if (resources._Resources._snapshot_configuration(configured.resources) is not configured.resource_configuration
                or stores.ReleaseOutcomeStore._snapshot_configuration(configured.store) is not configured.store_configuration
                or _owner_configuration(configured.owner, configured.profile) is not configured.owner_configuration):
            _fail("release startup resource or owner configuration changed")
        return configured

    def _epoch(self, value):
        shape._integer(value, minimum=1)
        if value < self._last_epoch:
            _fail("release startup clock reversed across an actual guard")
        object.__setattr__(self, "_last_epoch", value)

    def _current(self):
        configured = self._identity()
        work, window, bound = self._lifetime
        self._epoch(resources._Resources._check_on_work(configured.resources, work=work))
        self._epoch(configured.role_live())
        work.charge(input_bytes=4096)
        production._callback(work, lambda: _directory(configured, self._connection))
        self._epoch(clock._check_on_work(window, work=work))
        monotonic = production._callback(work, time.monotonic_ns)
        shape._integer(monotonic, minimum=1)
        if monotonic < self._last_monotonic or monotonic >= bound:
            _fail("release startup original monotonic allowance expired or reversed")
        object.__setattr__(self, "_last_monotonic", monotonic)
        self._identity()
        return self._last_epoch

    def _narrow_from_actual(self, lifetime):
        work, prior, prior_bound = self._lifetime
        if type(lifetime) is not tuple or len(lifetime) != 3 or lifetime[0] is not work:
            _fail("release startup owner changed the original cumulative work")
        actual = clock._validate(lifetime[1])
        shape._integer(lifetime[2], minimum=1)
        if actual[:3] != prior[:3]:
            _fail("release startup owner changed the original clock bracket")
        narrowed = clock._validate(prior[:3] + tuple(min(left, right)
            for left, right in zip(prior[3:], actual[3:])))
        held = (work, narrowed, min(prior_bound, lifetime[2], narrowed[4]))
        object.__setattr__(self, "_lifetime", held)
        object.__setattr__(self, "_lifetime_seal", held)

    def _after_operation(self, token):
        configured = self._identity()
        if type(token) is not bytes or len(token) != delivery.TOKEN_BYTES:
            _fail("release startup operation did not return the exact private token")
        # These are private fields of the exact owners just invoked, not a
        # received success DTO. The store can legitimately precede the custody
        # owner's final sample; compare both to the pre-operation observations.
        epochs = (configured.owner._last_epoch, configured.store._last_epoch)
        monotonic = (configured.owner._last_monotonic, configured.store._last_monotonic)
        for value in (*epochs, *monotonic):
            shape._integer(value, minimum=1)
        if min(epochs) < self._last_epoch or min(monotonic) < self._last_monotonic:
            _fail("release startup clock reversed across the actual operation")
        object.__setattr__(self, "_last_epoch", max(epochs))
        object.__setattr__(self, "_last_monotonic", max(monotonic))
        self._narrow_from_actual(configured.store._lifetime)
        if configured.profile == bootstrap.RECOVERY_PROFILE:
            self._narrow_from_actual(configured.owner._lifetime)
        self._current()
        return token

    def _poison_close(self):
        configured = self._configured
        connection = self._connection
        failed = self._cleanup_failed
        object.__setattr__(self, "_closed", True)
        object.__setattr__(self, "_spent", True)
        object.__setattr__(self, "_accept_spent", True)
        object.__setattr__(self, "_connection", None)
        object.__setattr__(self, "_connection_seal", None)
        object.__setattr__(self, "_configured", None)
        object.__setattr__(self, "_seal", None)
        _state("closed")
        if connection is not None:
            try:
                connections._AcceptedConnection.close(connection)
            except BaseException:
                failed = True
        if type(configured) is _Configuration:
            failed = not _close_owned(configured.owner, configured.store, configured.resources) or failed
        object.__setattr__(self, "_cleanup_failed", failed)
        return not failed

    def request_profile(self):
        """Return the genuinely root-selected grammar under the current guard."""
        self.processing_context()
        return self._identity().profile

    def accept_on_work(self):
        """Wait and own exactly one native connection before any request I/O."""
        lock = self._lock
        if type(lock) is not _LOCK_TYPE or not lock.acquire(blocking=False):
            _fail("release startup is already in use")
        try:
            self._current()
            if self._accept_spent or self._spent or self._connection is not None:
                _fail("release startup cannot accept a second exchange")
            object.__setattr__(self, "_accept_spent", True)
            configured = self._identity()
            work = self._lifetime[0]
            while True:
                self._current()
                remaining = (self._lifetime[2] - self._last_monotonic) / 1_000_000_000
                if remaining <= 0:
                    _fail("release startup original accept allowance expired")
                work.charge(input_bytes=64)
                ready, _writable, _exceptional = production._callback(work,
                    lambda: select.select((configured.listener_fd,), (), (), min(remaining, 0.1)))
                self._current()
                if ready:
                    break

            def acquire():
                connection = connections._accept(configured.listener_fd)
                # Claim inside the native callback, before any suffix can fail.
                object.__setattr__(self, "_connection", connection)
                object.__setattr__(self, "_connection_seal", connection)

            work.charge(input_bytes=4096)
            self._current()
            production._callback(work, acquire)
            self._current()
            return self._connection._configured.connection
        except BaseException:
            self._poison_close()
            raise
        finally:
            lock.release()

    def close_connection(self):
        """Close only the real owned connection, then restore the exact inventory."""
        lock = self._lock
        if type(lock) is not _LOCK_TYPE or not lock.acquire(blocking=False):
            _fail("release startup cannot close a connection during another operation")
        try:
            self._current()
            connection = self._connection
            if type(connection) is not connections._AcceptedConnection:
                _fail("release startup has no accepted connection to close")
            work = self._lifetime[0]

            def close_owned():
                try:
                    connections._AcceptedConnection.close(connection)
                except BaseException:
                    object.__setattr__(self, "_cleanup_failed", True)
                    raise
                finally:
                    object.__setattr__(self, "_connection", None)
                    object.__setattr__(self, "_connection_seal", None)

            production._callback(work, close_owned)
            self._current()
        except BaseException:
            self._poison_close()
            raise
        finally:
            lock.release()

    def processing_context(self):
        """Checked original allowance, never a replacement request window."""
        lock = self._lock
        if type(lock) is not _LOCK_TYPE or not lock.acquire(blocking=False):
            _fail("release startup is already in use")
        try:
            self._current()
            return self._lifetime
        except BaseException:
            self._poison_close()
            raise
        finally:
            lock.release()

    def open_committed_on_work(self, *, proof_bytes, proof_enrollment_bytes,
            intent_bytes, intent_enrollment_bytes, old_token_bytes, envelope_bytes):
        """One live-profile original call; no caller policy, store or allowance."""
        configured = self._identity()
        work = self._lifetime[0]
        held = _hold_originals(proof_bytes=proof_bytes, proof_enrollment_bytes=proof_enrollment_bytes,
            intent_bytes=intent_bytes, intent_enrollment_bytes=intent_enrollment_bytes,
            old_token_bytes=old_token_bytes, envelope_bytes=envelope_bytes, record_bytes=None, work=work)
        lock = self._lock
        if not lock.acquire(blocking=False):
            _fail("release startup is already in use")
        try:
            if self._spent or configured.profile != bootstrap.LIVE_PROFILE:
                _fail("release startup does not admit another live operation")
            object.__setattr__(self, "_spent", True)
            self._current()
            expected = records.capability.wire._decode_object(configured.release_bytes, work=work,
                maximum_bytes=records.MAX_BYTES, maximum_nodes=records.MAX_NODES, maximum_depth=records.MAX_DEPTH)
            self._current()
            _work, window, bound = self._lifetime
            token = custody.OidcSessionActivationReleaseCustody.open_committed_on_work(configured.owner,
                proof_bytes=held[0], proof_enrollment_bytes=held[1], intent_bytes=held[2],
                intent_enrollment_bytes=held[3], old_token_bytes=held[4], envelope_bytes=held[5],
                expected_producer_id=configured.producer_id,
                expected_producer_identity=dict(zip(_IDENTITY_FIELDS, configured.producer_identity)),
                expected_caller_id=configured.caller_id, expected_consume_binding=expected["consumeBinding"],
                expected_state_receipt_digest=configured.state_receipt_digest,
                outcome_store=configured.store, live_window=window, transport_deadline_ns=bound, work=work)
            return self._after_operation(token)
        except BaseException:
            self._poison_close()
            raise
        finally:
            lock.release()

    def recover_on_work(self, *, record_bytes, proof_bytes, proof_enrollment_bytes,
            intent_bytes, intent_enrollment_bytes, old_token_bytes, envelope_bytes):
        """One recovery-profile call of the actual unchanged-outcome owner."""
        configured = self._identity()
        work = self._lifetime[0]
        held = _hold_originals(proof_bytes=proof_bytes, proof_enrollment_bytes=proof_enrollment_bytes,
            intent_bytes=intent_bytes, intent_enrollment_bytes=intent_enrollment_bytes,
            old_token_bytes=old_token_bytes, envelope_bytes=envelope_bytes, record_bytes=record_bytes, work=work)
        lock = self._lock
        if not lock.acquire(blocking=False):
            _fail("release startup is already in use")
        try:
            if self._spent or configured.profile != bootstrap.RECOVERY_PROFILE or held[6] is None:
                _fail("release startup does not admit another recovery operation")
            object.__setattr__(self, "_spent", True)
            self._current()
            record = records._decode_on_work(held[6], work)
            expected = records.capability.wire._decode_object(configured.release_bytes, work=work,
                maximum_bytes=records.MAX_BYTES, maximum_nodes=records.MAX_NODES, maximum_depth=records.MAX_DEPTH)
            for actual, pinned in ((record["scope"]["producerId"], configured.producer_id),
                    (record["scope"]["producerIdentity"], dict(zip(_IDENTITY_FIELDS, configured.producer_identity))),
                    (record["evidenceBinding"]["stateReceiptDigest"], configured.state_receipt_digest),
                    (record["callerId"], configured.caller_id), (record["releaseBinding"], expected)):
                plan._same(actual, pinned, work, "release recovery record differs from independent cold pins")
            self._current()
            _work, window, bound = self._lifetime
            token = recovery.OidcSessionActivationReleaseRecovery.recover_on_work(configured.owner,
                record_bytes=held[6], proof_bytes=held[0], proof_enrollment_bytes=held[1],
                intent_bytes=held[2], intent_enrollment_bytes=held[3], old_token_bytes=held[4],
                envelope_bytes=held[5], live_window=window, transport_deadline_ns=bound, work=work)
            return self._after_operation(token)
        except BaseException:
            self._poison_close()
            raise
        finally:
            lock.release()

    def close(self):
        if type(self) is not _StartedRelease or self._pid != os.getpid():
            _fail("release startup close belongs to another process")
        if self._closed:
            if self._cleanup_failed:
                _fail("release startup cleanup remained uncertain; no retry is permitted")
            return
        lock = self._lock
        if type(lock) is not _LOCK_TYPE or not lock.acquire(blocking=False):
            _fail("release startup cannot close during another operation")
        try:
            if not self._poison_close():
                _fail("release startup resource cleanup is not established")
        finally:
            lock.release()


def _construct(resource_owner):
    store = owner = None
    try:
        if type(resource_owner) is not resources._Resources:
            _fail("release startup requires the actual cold resource owner")
        acquired = resources._Resources._snapshot_configuration(resource_owner)
        work, window = acquired.work, clock._validate(acquired.live_window)
        if type(work) is not _ValidationWork:
            _fail("release startup requires actual original cumulative work")
        shape._integer(acquired.deadline_ns, minimum=1)
        bound = min(acquired.deadline_ns, window[4])
        last_epoch, last_monotonic = window[0], window[2]
        role_live = None

        def base_current():
            nonlocal last_epoch, last_monotonic
            if resources._Resources._snapshot_configuration(resource_owner) is not acquired:
                _fail("release startup resource configuration changed during construction")
            epoch = resources._Resources._check_on_work(resource_owner, work=work)
            shape._integer(epoch, minimum=1)
            if epoch < last_epoch:
                _fail("release startup construction clock reversed across admission")
            last_epoch = epoch
            now = clock._check_on_work(window, work=work)
            monotonic = production._callback(work, time.monotonic_ns)
            shape._integer(monotonic, minimum=1)
            if now < last_epoch or monotonic < last_monotonic or monotonic >= bound:
                _fail("release startup original construction allowance expired or reversed")
            last_epoch, last_monotonic = now, monotonic
            return now

        def current():
            nonlocal last_epoch
            base_current()
            if role_live is not None:
                epoch = role_live()
                shape._integer(epoch, minimum=1)
                if epoch < last_epoch:
                    _fail("release startup role admission reversed the original clock")
                last_epoch = epoch
            return base_current()

        current()
        material = bootstrap._verify_on_work(bootstrap_bytes=acquired.bootstrap_bytes,
            root_public_key=acquired.root_public_key, live_window=window,
            transport_deadline_ns=bound, work=work,
            _continuity=custody.bootstrap._continuity(base_current, work))
        if type(material) is not bootstrap._ReleaseMaterial:
            _fail("release startup requires actual original bootstrap admission")
        narrowed = clock._validate(material.live_window)
        if narrowed[:3] != window[:3] or any(new > old for new, old in zip(narrowed[3:], window[3:])):
            _fail("release startup bootstrap renewed the construction window")
        shape._integer(material.deadline_ns, minimum=1)
        window, bound = narrowed, min(bound, material.deadline_ns, narrowed[4])
        role_live = material.live
        current()
        launch = material.launch
        if (tuple(launch[name] for name in ("rootPublicKeyFd", "bootstrapFd", "deliveryKeyFd",
                "outcomeDirectoryFd", "listenerFd")) != _INHERITED
                or tuple(launch["inheritedFileDescriptors"]) != _INHERITED
                or acquired.directory_fd != 201 or acquired.listener_fd != 202):
            _fail("release startup original resource inventory differs")
        store = stores.ReleaseOutcomeStore(directory_fd=acquired.directory_fd,
            authorization_bytes=material.storage_authorization_bytes, root_public_key=acquired.root_public_key,
            expected_scope=material.storage_scope, live_window=window, transport_deadline_ns=bound, work=work,
            _continuity=custody.bootstrap._continuity(current, work)
                if material.profile == bootstrap.RECOVERY_PROFILE else None)
        if store._last_epoch < last_epoch or store._last_monotonic < last_monotonic:
            _fail("release startup clock reversed across actual store construction")
        last_epoch, last_monotonic = store._last_epoch, store._last_monotonic
        current()
        if material.profile == bootstrap.LIVE_PROFILE:
            owner = custody.OidcSessionActivationReleaseCustody(custody_bytes=material.custody_bytes,
                root_public_key=acquired.root_public_key, expected_receiver_identity=material.receiver_identity,
                delivery_custody_key=acquired.delivery_key, live_window=window,
                transport_deadline_ns=bound, work=work)
        elif material.profile == bootstrap.RECOVERY_PROFILE:
            owner = recovery.OidcSessionActivationReleaseRecovery(
                recovery_authorization_bytes=material.recovery_authorization_bytes,
                custody_bytes=material.custody_bytes, root_public_key=acquired.root_public_key,
                expected_scope=material.recovery_scope, delivery_custody_key=acquired.delivery_key,
                outcome_store=store, live_window=window, transport_deadline_ns=bound, work=work,
                _continuity=custody.bootstrap._continuity(current, work))
        else:
            _fail("release startup has an unknown root-selected profile")
        if owner._last_epoch < last_epoch or owner._last_monotonic < last_monotonic:
            _fail("release startup clock reversed across actual owner construction")
        last_epoch, last_monotonic = owner._last_epoch, owner._last_monotonic
        current()
        release_bytes = records.capability._wire(material.expected_release,
            records.capture._SharedLedger(work), records.MAX_BYTES, records.MAX_NODES)
        current()
        journal = store._journal
        if type(journal) is not stores.storage.CurrentRootJournal or journal._directory_fd in _INHERITED:
            _fail("release startup journal is not a distinct actual owned descriptor")
        directory = material.storage_scope["directory"]
        configured = _Configuration(bootstrap.authority.SOURCE_REVISION, resource_owner, acquired,
            acquired.root_public_key, material.profile, store, stores.ReleaseOutcomeStore._snapshot_configuration(store),
            owner, _owner_configuration(owner, material.profile), role_live, release_bytes,
            material.producer_id, tuple(material.producer_identity[name] for name in _IDENTITY_FIELDS),
            material.caller_id, material.state_receipt_digest, journal, journal._directory_fd,
            tuple(directory[name] for name in ("device", "inode", "uid", "gid")), acquired.listener_fd)
        started = object.__new__(_StartedRelease)
        lifetime = (work, window, bound)
        for name, value in (("_configured", configured), ("_seal", configured),
                ("_lifetime", lifetime), ("_lifetime_seal", lifetime), ("_pid", os.getpid()),
                ("_lock", threading.Lock()), ("_closed", False), ("_spent", False),
                ("_accept_spent", False), ("_connection", None), ("_connection_seal", None),
                ("_cleanup_failed", False),
                ("_last_epoch", last_epoch), ("_last_monotonic", last_monotonic)):
            object.__setattr__(started, name, value)
        started._narrow_from_actual(store._lifetime)
        if material.profile == bootstrap.RECOVERY_PROFILE:
            started._narrow_from_actual(owner._lifetime)
        started._current()
        _state("started")
        return started
    except BaseException:
        _close_owned(owner, store, resource_owner if type(resource_owner) is resources._Resources else None)
        _state("failed")
        raise


def start_from_resources(resource_owner):
    """Internal exact-owner join; no successful bootstrap DTO is accepted."""
    _begin()
    return _construct(resource_owner)


def start_on_work(*, work, live_window, transport_deadline_ns):
    """Consume the real inherited resources and original root I/O allowance."""
    _begin()
    try:
        resource_owner = resources._intake_on_work(work=work, live_window=live_window,
            transport_deadline_ns=transport_deadline_ns)
        return _construct(resource_owner)
    except BaseException:
        _state("failed")
        raise
