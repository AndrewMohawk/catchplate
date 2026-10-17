"""Durable original registration reserve/snapshot delivery, never SQL authority.

This owner takes a separate actual journal and an independently current exact
local checkpoint. It authenticates original computation controls and their
snapshot, and stores them before any reserve exchange. The grant-record ID is
only a local lookup association: neither this storage nor a computation signature
replaces genuine grant/plan replay, current state admission or caller permission.

One unresolved request blocks new requests. Explicit delivery sends only the
retained original, verifies the exact state acknowledgment, then durably stores
it before returning. Network or verification uncertainty retains pending state;
local publication uncertainty poisons the owner. There is no background retry,
replacement signature, pending clear, expiry reset, lookup-peer widening or SQL.

After expiry an explicit unchanged redelivery can retrieve a previously accepted
historical receipt, never authorize a previously unaccepted expired request.
Even a durable acknowledgment is not a fresh current-head checkpoint or execution
permission. Native I/O needs an external watchdog; a late failure can follow
durable publication. Original lifetimes are never extended by a retrieval window.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
import threading
import time

from catchplate import authority_current_root_authorization as authorization
from catchplate import authority_current_root_journal as storage
from catchplate import authority_current_root_transport as transport
from catchplate import authority_registration_reservation_records as records
from catchplate import authority_webauthn_evidence as evidence
from catchplate import authority_webauthn_evidence_plan_clock as clock
from catchplate.authority_query_read_work import QueryReadValidationLimits, _ValidationWork


class RegistrationReservationDeliveryError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class RegistrationReservationObservation:
    """Unsigned local state, not state-service currentness or SQL permission."""

    sequence: int
    head_digest: str
    pending_request_digest: str | None
    acknowledged_count: int


@dataclass(frozen=True, slots=True)
class RegistrationReservationOriginals:
    """Original recovery data only; downstream consumers must authenticate it."""

    execution_record_digest: str
    request_bytes: bytes
    snapshot_bytes: bytes
    receipt_bytes: bytes | None


def _cold_work():
    return _ValidationWork(QueryReadValidationLimits())


def _live_guard(live_window, inherited, work):
    window = clock._validate(live_window)
    if inherited is not None:
        authorization.shape._integer(inherited, minimum=1)
    bound = window[4] if inherited is None else min(window[4], inherited)
    last_epoch, last_monotonic = window[0], window[2]

    def live():
        nonlocal last_epoch, last_monotonic
        now = clock._check_on_work(window, work=work)
        monotonic = evidence.production._callback(work, time.monotonic_ns)
        authorization.shape._integer(monotonic, minimum=1)
        if now < last_epoch or monotonic < last_monotonic or monotonic >= bound:
            raise RegistrationReservationDeliveryError("reservation delivery window expired or clock reversed")
        last_epoch, last_monotonic = now, monotonic
        return now

    return live, bound


def _owner_profile(owner):
    """Select only exact source-owned classes, never a supplied codec/factory."""
    if type(owner) is RegistrationReservationDelivery:
        return 0
    from catchplate import authority_registration_finalization_reservation_delivery as finalization

    if type(owner) is finalization.FinalizationReservationDelivery:
        return 1
    from catchplate import authority_oidc_session_activation_reservation_delivery as activation

    if type(owner) is activation.OidcSessionActivationReservationDelivery:
        return 2
    from catchplate import authority_oidc_session_activation_delivery_reservation_delivery as consume

    if type(owner) is consume.OidcSessionActivationDeliveryReservationDelivery:
        return 3
    raise RegistrationReservationDeliveryError("reservation delivery owner type is not source fixed")


def _record_codec(owner):
    selected = _owner_profile(owner)
    if type(owner._record_profile) is not int or selected != owner._record_profile:
        raise RegistrationReservationDeliveryError("reservation delivery profile changed after construction")
    if selected == 0:
        return records
    if selected == 1:
        from catchplate import authority_registration_finalization_reservation_records as finalization

        return finalization
    if selected == 2:
        from catchplate import authority_oidc_session_activation_reservation_records as activation

        return activation
    from catchplate import authority_oidc_session_activation_delivery_reservation_records as consume

    return consume


def _delivery_guard(owner, live_window, inherited, work):
    if _owner_profile(owner) in (2, 3):
        # Activation and consume cannot replace their original allowance.
        authorization.shape._integer(inherited, minimum=1)
    return _live_guard(live_window, inherited, work)


class _RegistrationReservationDeliveryBase:
    """Shared mechanics for four exact fixed-operation durable owner types.

    Journal ownership transfers at construction, including failure cleanup. Its
    preprovisioned directory must be separate from state/completion/SQL-attempt
    journals. At sequence zero the independent local head is the enrollment
    digest; later heads are framed reservation-record identities. Recovery of a
    valid prefix does not establish that prefix's currentness.
    """

    __slots__ = ("_journal", "_pid", "_closed", "_lock", "_sequence", "_head_digest",
        "_enrollment_bytes", "_root_public_key", "_enrollment_digest", "_age", "_skew",
        "_maximum_records", "_pending", "_history", "_operations", "_capabilities",
        "_predecessor_heads", "_last_reserved_sequence", "_last_fence", "_acknowledged_count",
        "_record_profile")

    def __init__(self, *, journal, enrollment_bytes, root_public_key,
            expected_local_sequence, expected_local_head_digest):
        self._initialize(journal=journal, enrollment_bytes=enrollment_bytes,
            root_public_key=root_public_key, expected_local_sequence=expected_local_sequence,
            expected_local_head_digest=expected_local_head_digest)

    def _initialize(self, *, journal, enrollment_bytes, root_public_key,
            expected_local_sequence, expected_local_head_digest, live_window=None,
            work=None, transport_deadline_ns=None):
        self._record_profile = _owner_profile(self)
        if type(journal) is not storage.CurrentRootJournal:
            raise RegistrationReservationDeliveryError("reservation delivery requires its actual separate journal")
        self._journal = journal
        self._pid, self._closed = os.getpid(), False
        self._lock = threading.RLock()
        self._sequence = self._acknowledged_count = self._last_fence = 0
        self._last_reserved_sequence = -1
        self._pending = None
        self._history, self._operations, self._capabilities, self._predecessor_heads = {}, set(), set(), set()
        try:
            original = authorization._original(enrollment_bytes,
                authorization.MAX_ENROLLMENT_BYTES, "reservation delivery enrollment")
            held_root = root_public_key
            authorization._public(held_root)
            authorization.shape._integer(expected_local_sequence, storage.MAX_RECORDS)
            authorization.shape._digest(expected_local_head_digest)
            expected = expected_local_sequence, expected_local_head_digest
            live = None
            if self._record_profile in (2, 3):
                evidence.capture._SharedLedger(work)
                live, _bound = _delivery_guard(self, live_window, transport_deadline_ns, work)
                live()
                admission_work = work
            else:
                if live_window is not None or work is not None or transport_deadline_ns is not None:
                    raise RegistrationReservationDeliveryError("legacy reservation cold allowance is fixed")
                admission_work = _cold_work()
            material = authorization._admit_enrollment_on_work(enrollment_bytes=original,
                root_public_key=held_root, work=admission_work)
            if live is not None:
                live()
            self._enrollment_bytes, self._root_public_key = original, held_root
            self._enrollment_digest = self._head_digest = material.enrollment_digest
            self._age, self._skew = material.payload["maxControlAgeNs"], material.payload["maxClockSkewNs"]
            self._maximum_records = journal.maximum_records
            if self._maximum_records != material.payload["maxRecords"]:
                raise RegistrationReservationDeliveryError("reservation journal capacity differs from enrollment")
            if live is None:
                storage.CurrentRootJournal.recover(journal, self._recover_record)
            else:
                def recover_record(sequence, record_bytes):
                    live()
                    self._recover_record_on_work(sequence, record_bytes, work)
                    live()

                evidence.production._callback(work,
                    lambda: storage.CurrentRootJournal.recover(journal, recover_record))
                live()
            if (self._sequence, self._head_digest) != expected:
                raise RegistrationReservationDeliveryError("reservation history differs from independently current checkpoint")
            self._require_ready()
            if live is not None:
                live()
        except BaseException:
            self._poison_and_close()
            raise

    def _require_process(self):
        _record_codec(self)
        if os.getpid() != self._pid:
            raise RegistrationReservationDeliveryError("reservation delivery requires its actual process-bound owner")
        if self._closed:
            raise RegistrationReservationDeliveryError("reservation delivery owner is closed")

    def _require_ready(self):
        self._require_process()
        try:
            if self._journal.count != self._sequence:
                raise RegistrationReservationDeliveryError("reservation journal changed outside its owner")
        except BaseException:
            self._poison_and_close()
            raise

    def _poison_and_close(self):
        self._closed = True
        try:
            storage.CurrentRootJournal.poison(self._journal)
        except BaseException:
            pass
        try:
            storage.CurrentRootJournal.close(self._journal)
        except BaseException:
            pass

    def _check_record(self, record, work):
        previous = None if self._sequence == 0 else self._head_digest
        if (record.enrollment_digest != self._enrollment_digest
                or record.sequence != self._sequence + 1 or record.previous_record_digest != previous):
            raise RegistrationReservationDeliveryError("reservation record differs from its exact local chain")
        if record.kind == "request":
            if self._pending is not None or self._sequence + 2 > self._maximum_records:
                raise RegistrationReservationDeliveryError("reservation pending or acknowledgment capacity unavailable")
            if (record.request_digest in self._history
                    or record.request_payload["operationId"] in self._operations
                    or record.request_payload["capabilityDigest"] in self._capabilities
                    or record.predecessor_head_digest in self._predecessor_heads
                    or record.predecessor_sequence <= self._last_reserved_sequence
                    or record.fence <= self._last_fence):
                raise RegistrationReservationDeliveryError("reservation repeats consumed identity or state ancestry")
        elif record.kind == "ack":
            pending = self._pending
            if pending is None:
                raise RegistrationReservationDeliveryError("reservation acknowledgment has no retained request")
            work.charge(input_bytes=len(record.request_bytes) + len(pending.request_bytes)
                + len(record.snapshot_bytes) + len(pending.snapshot_bytes))
            if (record.request_bytes != pending.request_bytes or record.snapshot_bytes != pending.snapshot_bytes
                    or record.execution_record_digest != pending.execution_record_digest
                    or record.request_digest != pending.request_digest
                    or record.predecessor_sequence != pending.predecessor_sequence
                    or record.predecessor_head_digest != pending.predecessor_head_digest
                    or record.fence != pending.fence):
                raise RegistrationReservationDeliveryError("reservation acknowledgment changes retained scope")
        else:
            raise RegistrationReservationDeliveryError("reservation record kind is not fixed")

    def _install_record(self, record):
        # Only same-call genuine codec output passing _check_record reaches here.
        self._history[record.request_digest] = record
        if record.kind == "request":
            self._pending = record
            self._operations.add(record.request_payload["operationId"])
            self._capabilities.add(record.request_payload["capabilityDigest"])
            self._predecessor_heads.add(record.predecessor_head_digest)
            self._last_fence = record.fence
        else:
            self._pending = None
            self._acknowledged_count += 1
            self._last_reserved_sequence = record.receipt_payload["sequence"]
        self._sequence, self._head_digest = record.sequence, record.record_digest

    def _recover_record(self, sequence, original):
        self._recover_record_on_work(sequence, original, _cold_work())

    def _recover_record_on_work(self, sequence, original, work):
        record = _record_codec(self)._decode_on_work(original, enrollment_bytes=self._enrollment_bytes,
            root_public_key=self._root_public_key, work=work)
        if record.sequence != sequence:
            raise RegistrationReservationDeliveryError("reservation filename and record sequence differ")
        self._check_record(record, work)
        self._install_record(record)

    def _append(self, original, record, work):
        self._check_record(record, work)
        work.charge(hashes=1, input_bytes=len(original))
        raw_digest = "sha256:" + hashlib.sha256(original).hexdigest()
        try:
            metadata = evidence.production._callback(work,
                lambda: storage.CurrentRootJournal.append(self._journal, original))
            if (type(metadata) is not storage.CurrentRootRecord
                    or metadata.sequence != record.sequence or metadata.digest != raw_digest
                    or metadata.byte_count != len(original)):
                raise RegistrationReservationDeliveryError("reservation publication differs from its original")
            self._install_record(record)
            self._require_ready()
        except BaseException:
            self._poison_and_close()
            raise

    def enqueue(self, request_bytes, *, snapshot_bytes, execution_record_digest,
            expected_predecessor_sequence, expected_predecessor_head_digest, expected_fence,
            live_window, work, transport_deadline_ns=None):
        """Retain a fresh signed reserve plus exact snapshot before any send.

        The predecessor/fence and local grant locator must come from the actual
        coordinator, not an incoming request's purported authority. Re-enqueue
        of identical retained originals/scope is idempotent and never renews it.
        """
        evidence.capture._SharedLedger(work)
        codec = _record_codec(self)
        original = authorization._original(request_bytes, codec.MAX_REQUEST_BYTES, "reservation request")
        snapshot = authorization._original(snapshot_bytes, codec.MAX_SNAPSHOT_BYTES, "reservation snapshot")
        authorization.shape._digest(execution_record_digest)
        scope = codec._predecessor_scope(expected_predecessor_sequence,
            expected_predecessor_head_digest, expected_fence)
        locator = execution_record_digest
        live, _bound = _delivery_guard(self, live_window, transport_deadline_ns, work)
        self._require_process()
        with self._lock:
            self._require_ready()
            live()
            identity = authorization.plan._frame(authorization.REQUEST_IDENTITY_DOMAIN, (original,), work)
            prior = self._history.get(identity)
            if prior is not None:
                work.charge(input_bytes=len(original) + len(prior.request_bytes)
                    + len(snapshot) + len(prior.snapshot_bytes))
                if (original != prior.request_bytes or snapshot != prior.snapshot_bytes
                        or locator != prior.execution_record_digest
                        or scope != (prior.predecessor_sequence, prior.predecessor_head_digest, prior.fence)):
                    raise RegistrationReservationDeliveryError("reservation identity has different original scope")
                live()
                return identity
            if self._pending is not None or self._sequence + 2 > self._maximum_records:
                raise RegistrationReservationDeliveryError("reservation pending or acknowledgment capacity unavailable")
            encoded, record = codec._prepare_request_on_work(sequence=self._sequence + 1,
                previous_record_digest=None if self._sequence == 0 else self._head_digest,
                expected_predecessor_sequence=scope[0], expected_predecessor_head_digest=scope[1],
                expected_fence=scope[2], execution_record_digest=locator,
                request_bytes=original, snapshot_bytes=snapshot, enrollment_bytes=self._enrollment_bytes,
                root_public_key=self._root_public_key, work=work)
            authorization.plan._same(record.request_digest, identity, work, "reservation original identity changed")
            evidence._fresh(record.request_payload, live(), self._age, self._skew)
            self._append(encoded, record, work)
            evidence._fresh(record.request_payload, live(), self._age, self._skew)
            return identity

    def deliver(self, request_digest, *, client, live_window, work, transport_deadline_ns=None):
        """Explicitly send one retained reserve and persist its genuine ack.

        Failures never clear pending state. A later explicit same-original call
        may recover acceptance; there is no automatic retry or SQL invocation.
        Already durable receipts are returned unchanged, not refreshed.
        """
        evidence.capture._SharedLedger(work)
        codec = _record_codec(self)
        authorization.shape._digest(request_digest)
        identity = request_digest
        configured = transport.CurrentRootDecisionClient._snapshot_configuration(client)
        live, bound = _delivery_guard(self, live_window, transport_deadline_ns, work)
        self._require_process()
        with self._lock:
            self._require_ready()
            live()
            retained = self._history.get(identity)
            if retained is None:
                raise RegistrationReservationDeliveryError("reservation original is not durably retained")
            if retained.kind == "ack":
                live()
                return retained.receipt_bytes
            if retained is not self._pending:
                raise RegistrationReservationDeliveryError("reservation original is not the local pending request")
            receipt = evidence.production._callback(work, lambda: transport._exchange_on_configuration(
                configured, action="reserve", request_bytes=retained.request_bytes, deadline_ns=bound))
            live()
            encoded, record = codec._prepare_ack_on_work(sequence=self._sequence + 1,
                previous_record_digest=self._head_digest,
                expected_predecessor_sequence=retained.predecessor_sequence,
                expected_predecessor_head_digest=retained.predecessor_head_digest,
                expected_fence=retained.fence, execution_record_digest=retained.execution_record_digest,
                request_bytes=retained.request_bytes, snapshot_bytes=retained.snapshot_bytes,
                receipt_bytes=receipt, enrollment_bytes=self._enrollment_bytes,
                root_public_key=self._root_public_key, work=work)
            live()
            self._append(encoded, record, work)
            live()
            return record.receipt_bytes

    def _original_for_execution_on_work(self, execution_record_digest, *,
            expected_predecessor_sequence, expected_predecessor_head_digest, expected_fence,
            work) -> RegistrationReservationOriginals | None:
        """Find retained originals by an actual local execution-record digest.

        The caller must derive this locator from its exact incoming originals
        and supply the independently admitted predecessor scope. A match is
        recovery data only, including after expiry; it is not renewed grant
        authority, current state or permission to bypass delivery's live guard.
        """
        evidence.capture._SharedLedger(work)
        authorization.shape._digest(execution_record_digest)
        locator = execution_record_digest
        scope = _record_codec(self)._predecessor_scope(expected_predecessor_sequence,
            expected_predecessor_head_digest, expected_fence)
        self._require_process()
        with self._lock:
            self._require_ready()
            count = len(self._history)
            if count > self._maximum_records:
                raise RegistrationReservationDeliveryError("reservation history exceeds its enrolled bound")
            # The record objects contain bytes, not a JSON graph: reserve the
            # bounded entry traversal, then charge each exact scalar comparison.
            work.charge(json_nodes=count)
            selected = None
            for retained in self._history.values():
                work.prepare_comparison(locator, retained.execution_record_digest)
                if locator == retained.execution_record_digest:
                    if selected is not None:
                        raise RegistrationReservationDeliveryError("reservation execution locator is ambiguous")
                    selected = retained
            if selected is None:
                self._require_ready()
                return None
            retained_scope = (selected.predecessor_sequence, selected.predecessor_head_digest, selected.fence)
            work.prepare_comparison(scope, retained_scope)
            if scope != retained_scope:
                raise RegistrationReservationDeliveryError("reservation execution locator has different predecessor scope")
            self._require_ready()
            return RegistrationReservationOriginals(selected.execution_record_digest,
                selected.request_bytes, selected.snapshot_bytes, selected.receipt_bytes)

    def originals(self, request_digest):
        """Read held originals, even after expiry, without claiming currentness."""
        authorization.shape._digest(request_digest)
        self._require_process()
        with self._lock:
            self._require_ready()
            retained = self._history.get(request_digest)
            if retained is None:
                raise RegistrationReservationDeliveryError("reservation original is not durably retained")
            return RegistrationReservationOriginals(retained.execution_record_digest,
                retained.request_bytes, retained.snapshot_bytes, retained.receipt_bytes)

    def inspect(self):
        self._require_process()
        with self._lock:
            self._require_ready()
            return RegistrationReservationObservation(self._sequence, self._head_digest,
                None if self._pending is None else self._pending.request_digest, self._acknowledged_count)

    def close(self):
        if os.getpid() != self._pid:
            raise RegistrationReservationDeliveryError("forked process cannot close reservation delivery")
        with self._lock:
            if not self._closed:
                self._closed = True
                storage.CurrentRootJournal.close(self._journal)


class RegistrationReservationDelivery(_RegistrationReservationDeliveryBase):
    """Original fixed evidence-admission owner; wire, API and domains unchanged."""

    __slots__ = ()
