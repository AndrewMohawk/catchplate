"""Durable exact-original completion delivery, never database re-execution.

This owner takes a SEPARATE actual private journal and an independently current
exact local checkpoint. Local delivery sequence/head are not the state owner's
pending sequence/head. A valid older local prefix cannot declare itself current.
Cold directory/configuration/key and checkpoint provenance remain external.

Enqueue authenticates and durably retains a fresh original complete control
before any network operation. Explicit delivery sends only those retained bytes,
authenticates the original state acknowledgment against the retained independent
pending scope, and durably appends the acknowledgment before returning it.
No successful replay/observation carrier or transport callback is accepted.

An uncertain exchange leaves the exact pending record intact. Explicit repeated
delivery may retrieve the state owner's original historical receipt, including
after request expiry; it does not renew the control or retry SQL. An expired
request which was never accepted cannot be replaced/reset here. Reconciliation
queries the real owner with a fresh nonce and authenticates a signed observation;
an accepted original acknowledgment is retained without another mutation send.
A not-recorded result grants no database noncommit, replacement or retry right.
There is no loop, signer, database access, listener, cancellation record or
implicit checkpoint. The state owner's independently current cold checkpoint
remains required: nonce freshness is not host rollback resistance.

Public operations spend the caller's original work/window. Cold replay defaults
to one fixed allowance per source-bounded record; an explicitly supplied complete
current allowance is instead shared cumulatively through recovery. Physical
journal/transport work is not JSON/hash accounting and is not interruptible by
a Python clock check; late failures never undo completed durability barriers.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import os
import threading
import time

from serverware import authority_current_root_authorization as authorization
from serverware import authority_current_root_delivery_records as records
from serverware import authority_current_root_journal as storage
from serverware import authority_current_root_lookup as lookup
from serverware import authority_current_root_transport as transport
from serverware import authority_webauthn_evidence as evidence
from serverware import authority_webauthn_evidence_plan_clock as clock
from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork


class CurrentRootDeliveryError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class CurrentRootDeliveryObservation:
    """Unsigned local inspection, not checkpoint/currentness/delivery authority."""

    sequence: int
    head_digest: str
    pending_request_digest: str | None
    completed_count: int


@dataclass(frozen=True, slots=True)
class CurrentRootDeliveryReconciliation:
    """Authenticated lookup observations, never replacement/execution authority.

    acknowledged includes a durable original receipt. pendingUnaccepted means
    notRecorded at the retained pending position, not database noncommit.
    stateChanged reports another observed position without releasing anything.
    The state sequence/head describe the fresh lookup, not the local journal.
    """

    status: str
    request_digest: str
    state_sequence: int
    state_head_digest: str
    receipt_bytes: bytes | None


def _cold_work():
    return _ValidationWork(QueryReadValidationLimits())


def _window(live_window, transport_deadline_ns):
    window = clock._validate(live_window)
    if transport_deadline_ns is not None:
        authorization.shape._integer(transport_deadline_ns, minimum=1)
    bound = window[4] if transport_deadline_ns is None else min(window[4], transport_deadline_ns)
    return window, bound


class CurrentRootCompletionDelivery:
    """One pending original completion, with durable request/ack pairs.

    Construction takes ownership of a fresh unrecovered CurrentRootJournal in
    its own independently provisioned directory, including failure closure.
    Sequence zero's expected local head is the original enrollment digest;
    later local heads are framed original delivery-record identities, not raw
    filename hashes or state-receipt identities. No directory is created here.
    """

    def __init__(self, *, journal, enrollment_bytes, root_public_key,
            expected_local_sequence, expected_local_head_digest,
            live_window=None, work=None, transport_deadline_ns=None):
        if type(journal) is not storage.CurrentRootJournal:
            raise CurrentRootDeliveryError("completion delivery requires its actual separate journal")
        self._journal = journal
        self._pid, self._closed = os.getpid(), False
        self._lock = threading.RLock()
        self._sequence = self._completed_count = self._last_state_sequence = 0
        self._pending = None
        self._history, self._pending_heads = {}, set()
        self._pending_requests = {}
        try:
            original = authorization._original(enrollment_bytes,
                authorization.MAX_ENROLLMENT_BYTES, "completion delivery enrollment")
            held_root = root_public_key
            authorization._public(held_root)
            authorization.shape._integer(expected_local_sequence, storage.MAX_RECORDS)
            authorization.shape._digest(expected_local_head_digest)
            expected = expected_local_sequence, expected_local_head_digest
            inherited = (live_window, work, transport_deadline_ns)
            live = None
            if any(value is not None for value in inherited):
                if any(value is None for value in inherited):
                    raise CurrentRootDeliveryError("completion cold allowance must be supplied completely")
                evidence.capture._SharedLedger(work)
                window = clock._validate(live_window)
                authorization.shape._integer(transport_deadline_ns, minimum=1)
                bound = min(window[4], transport_deadline_ns)
                last_epoch, last_monotonic = window[0], window[2]

                def live():
                    nonlocal last_epoch, last_monotonic
                    self._require_process()
                    now = clock._check_on_work(window, work=work)
                    monotonic = evidence.production._callback(work, time.monotonic_ns)
                    authorization.shape._integer(monotonic, minimum=1)
                    if now < last_epoch or monotonic < last_monotonic or monotonic >= bound:
                        raise CurrentRootDeliveryError("completion cold original interval expired or reversed")
                    last_epoch, last_monotonic = now, monotonic

                live()
            material = authorization._admit_enrollment_on_work(enrollment_bytes=original,
                root_public_key=held_root, work=_cold_work() if live is None else work)
            self._enrollment_bytes, self._root_public_key = original, held_root
            self._enrollment_digest = self._head_digest = material.enrollment_digest
            self._age = material.payload["maxControlAgeNs"]
            self._skew = material.payload["maxClockSkewNs"]
            self._maximum_records = journal.maximum_records
            if self._maximum_records != material.payload["maxRecords"]:
                raise CurrentRootDeliveryError("delivery journal limit differs from its enrolled generation")
            # Only this owner's fixed original-byte replay reducer reaches I/O.
            if live is None:
                storage.CurrentRootJournal.recover(journal, self._recover_record)
            else:
                def recover_record(sequence, original):
                    live()
                    self._recover_record_on_work(sequence, original, work)
                    live()

                live()
                evidence.production._callback(work,
                    lambda: storage.CurrentRootJournal.recover(journal, recover_record))
                live()
            if (self._sequence, self._head_digest) != expected:
                raise CurrentRootDeliveryError("delivery journal differs from independently current local checkpoint")
            self._require_ready()
            if live is not None:
                live()
        except BaseException:
            self._poison_and_close()
            raise

    def _require_process(self):
        if os.getpid() != self._pid:
            raise CurrentRootDeliveryError("forked process cannot use completion delivery")
        if self._closed:
            raise CurrentRootDeliveryError("completion delivery owner is closed")

    def _require_ready(self):
        self._require_process()
        if self._journal.count != self._sequence:
            self._journal.poison()
            raise CurrentRootDeliveryError("delivery journal changed outside its owner")

    def _poison_and_close(self):
        self._closed = True
        # Preserve the first publication/recovery failure even during cleanup.
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
                or record.sequence != self._sequence + 1
                or record.previous_record_digest != previous):
            raise CurrentRootDeliveryError("delivery record differs from its exact local chain")
        if record.kind == "request":
            if self._pending is not None:
                raise CurrentRootDeliveryError("completion delivery already has an unresolved original")
            if self._sequence + 2 > self._maximum_records:
                raise CurrentRootDeliveryError("completion delivery cannot reserve acknowledgment capacity")
            if (record.request_digest in self._history or record.pending_head_digest in self._pending_heads
                    or record.pending_sequence <= self._last_state_sequence):
                raise CurrentRootDeliveryError("completion delivery repeats an already consumed state position")
        elif record.kind == "ack":
            pending = self._pending
            if pending is None:
                raise CurrentRootDeliveryError("delivery acknowledgment has no retained original request")
            work.charge(input_bytes=len(record.request_bytes) + len(pending.request_bytes))
            if (record.request_bytes != pending.request_bytes
                    or record.request_digest != pending.request_digest
                    or record.pending_sequence != pending.pending_sequence
                    or record.pending_head_digest != pending.pending_head_digest):
                raise CurrentRootDeliveryError("delivery acknowledgment differs from retained original scope")
        else:
            raise CurrentRootDeliveryError("delivery record kind is not source fixed")

    def _install_record(self, record):
        # Only a genuine same-call decode/prepare which passed _check_record
        # reaches this continuation; no public API accepts such a carrier.
        self._history[record.request_digest] = record
        self._pending_requests[record.pending_head_digest] = record.request_digest
        if record.kind == "request":
            self._pending = record
            self._pending_heads.add(record.pending_head_digest)
        else:
            self._pending = None
            self._completed_count += 1
            self._last_state_sequence = record.receipt_payload["sequence"]
        self._sequence, self._head_digest = record.sequence, record.record_digest

    def _recover_record(self, sequence, original):
        self._recover_record_on_work(sequence, original, _cold_work())

    def _recover_record_on_work(self, sequence, original, work):
        record = records._decode_on_work(original, enrollment_bytes=self._enrollment_bytes,
            root_public_key=self._root_public_key, work=work)
        if record.sequence != sequence:
            raise CurrentRootDeliveryError("delivery filename and authenticated record sequence differ")
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
                raise CurrentRootDeliveryError("delivery publication metadata differs from its exact original")
            self._install_record(record)
            self._require_ready()
        except BaseException:
            self._poison_and_close()
            raise

    def enqueue(self, request_bytes, *, expected_pending_sequence, expected_pending_head_digest,
            live_window, work, transport_deadline_ns=None):
        """Durably retain one fresh complete control; perform no network send.

        Returns its original signed-byte digest as a lookup ID, not a receipt.
        Re-enqueue of the same retained bytes/scope is idempotent even if old;
        a different completion cannot replace an unresolved pending original.
        """
        evidence.capture._SharedLedger(work)
        original = records._original(request_bytes, records.MAX_REQUEST_BYTES, "delivery request")
        pending_sequence, pending_head = records._pending_scope(expected_pending_sequence,
            expected_pending_head_digest)
        window, bound = _window(live_window, transport_deadline_ns)
        self._require_process()
        with self._lock:
            self._require_ready()
            last_epoch = window[0]

            def live(payload=None):
                nonlocal last_epoch
                now = clock._check_on_work(window, work=work)
                monotonic = evidence.production._callback(work, time.monotonic_ns)
                authorization.shape._integer(monotonic, minimum=1)
                if now < last_epoch or monotonic >= bound:
                    raise CurrentRootDeliveryError("delivery enqueue original window expired or clock reversed")
                last_epoch = now
                if payload is not None:
                    evidence._fresh(payload, now, self._age, self._skew)

            live()
            identity = authorization.plan._frame(authorization.REQUEST_IDENTITY_DOMAIN, (original,), work)
            prior = self._history.get(identity)
            if prior is not None:
                work.charge(input_bytes=len(original) + len(prior.request_bytes))
                if (original != prior.request_bytes or pending_sequence != prior.pending_sequence
                        or pending_head != prior.pending_head_digest):
                    raise CurrentRootDeliveryError("retained completion identity has different bytes or pending scope")
                live()
                return identity
            if self._pending is not None or self._sequence + 2 > self._maximum_records:
                raise CurrentRootDeliveryError("completion delivery is pending or lacks acknowledgment capacity")
            encoded, record = records._prepare_request_on_work(sequence=self._sequence + 1,
                previous_record_digest=None if self._sequence == 0 else self._head_digest,
                expected_pending_sequence=pending_sequence, expected_pending_head_digest=pending_head,
                request_bytes=original, enrollment_bytes=self._enrollment_bytes,
                root_public_key=self._root_public_key, work=work)
            authorization.plan._same(record.request_digest, identity, work,
                "delivery original complete identity changed during admission")
            live(record.request_payload)
            self._append(encoded, record, work)
            live(record.request_payload)
            return identity

    def deliver(self, request_digest, *, client, live_window, work, transport_deadline_ns=None):
        """Explicitly exchange one retained original, then durably retain its ack.

        There is no automatic retry. Network/verification failure leaves the
        pending request intact. An already durable acknowledgment is returned
        unchanged without another exchange; it is not a fresh state assertion.
        """
        evidence.capture._SharedLedger(work)
        authorization.shape._digest(request_digest)
        identity = request_digest
        configured = transport.CurrentRootDecisionClient._snapshot_configuration(client)
        window, bound = _window(live_window, transport_deadline_ns)
        self._require_process()
        with self._lock:
            self._require_ready()
            last_epoch = window[0]

            def live():
                nonlocal last_epoch
                now = clock._check_on_work(window, work=work)
                monotonic = evidence.production._callback(work, time.monotonic_ns)
                authorization.shape._integer(monotonic, minimum=1)
                if now < last_epoch or monotonic >= bound:
                    raise CurrentRootDeliveryError("delivery original exchange window expired or clock reversed")
                last_epoch = now

            live()
            retained = self._history.get(identity)
            if retained is None:
                raise CurrentRootDeliveryError("completion original is not durably retained")
            if retained.kind == "ack":
                live()
                return retained.receipt_bytes
            if retained is not self._pending:
                raise CurrentRootDeliveryError("completion original is not the current local pending request")
            receipt = evidence.production._callback(work, lambda: transport._exchange_on_configuration(
                configured, action="complete", request_bytes=retained.request_bytes, deadline_ns=bound))
            live()
            encoded, record = records._prepare_ack_on_work(sequence=self._sequence + 1,
                previous_record_digest=self._head_digest,
                expected_pending_sequence=retained.pending_sequence,
                expected_pending_head_digest=retained.pending_head_digest,
                request_bytes=retained.request_bytes, receipt_bytes=receipt,
                enrollment_bytes=self._enrollment_bytes, root_public_key=self._root_public_key, work=work)
            live()
            self._append(encoded, record, work)
            live()
            return record.receipt_bytes

    def reconcile(self, request_digest, *, client, live_window, work, transport_deadline_ns=None):
        """Query fresh state and recover only the exact retained original ack.

        Always performs a nonce-bound read, including for an already durable
        acknowledgment. No complete control is sent. Contradictory history or
        a state behind the retained checkpoint denies; a missing request never
        clears the pending record. Another in-flight delivery can still commit.
        A late failure can follow local acknowledgment durability.
        """
        evidence.capture._SharedLedger(work)
        authorization.shape._digest(request_digest)
        identity = request_digest
        configured = transport.CurrentRootDecisionClient._snapshot_configuration(client)
        window, bound = _window(live_window, transport_deadline_ns)
        self._require_process()
        with self._lock:
            self._require_ready()
            last_epoch = window[0]

            def live(payload=None):
                nonlocal last_epoch
                now = clock._check_on_work(window, work=work)
                monotonic = evidence.production._callback(work, time.monotonic_ns)
                authorization.shape._integer(monotonic, minimum=1)
                if now < last_epoch or monotonic >= bound:
                    raise CurrentRootDeliveryError("delivery lookup original window expired or clock reversed")
                last_epoch = now
                if payload is not None:
                    evidence._fresh(payload, now, self._age, self._skew)
                return now

            live()
            retained = self._history.get(identity)
            if retained is None:
                raise CurrentRootDeliveryError("completion original is not durably retained")
            if retained.kind != "ack" and retained is not self._pending:
                raise CurrentRootDeliveryError("completion original is not the current local pending request")
            nonce = evidence.production._callback(work, lambda: os.urandom(32))
            if type(nonce) is not bytes or len(nonce) != 32:
                raise CurrentRootDeliveryError("delivery lookup nonce is not exactly 32 random bytes")
            work.charge(input_bytes=32 + 64)
            query = lookup._encode_query_on_work(enrollment_digest=self._enrollment_digest,
                request_digest=identity, challenge=nonce.hex(), work=work)
            live()
            original = evidence.production._callback(work, lambda: transport._lookup_on_configuration(
                configured, query_bytes=query, deadline_ns=bound))
            payload, receipt = lookup._verify_on_work(observation_bytes=original, query_bytes=query,
                enrollment_bytes=self._enrollment_bytes, root_public_key=self._root_public_key,
                now_epoch_ns=live(), work=work)
            live(payload)
            self._require_ready()
            if self._history.get(identity) is not retained:
                raise CurrentRootDeliveryError("retained original changed during state lookup")
            observed_sequence, observed_head = payload["sequence"], payload["headDigest"]
            minimum_sequence, minimum_head = retained.pending_sequence, retained.pending_head_digest
            if retained.kind == "ack":
                minimum_sequence = retained.receipt_payload["sequence"]
                minimum_head = retained.receipt_digest
            if (observed_sequence < minimum_sequence
                    or observed_sequence == minimum_sequence and observed_head != minimum_head):
                raise CurrentRootDeliveryError("observed state is behind or conflicts with retained checkpoint")
            if payload["requestStatus"] == "accepted":
                if retained.kind == "ack":
                    work.charge(input_bytes=len(receipt) + len(retained.receipt_bytes))
                    if receipt != retained.receipt_bytes:
                        raise CurrentRootDeliveryError("state lookup changed the durable original acknowledgment")
                    acknowledged = retained.receipt_bytes
                else:
                    if retained is not self._pending:
                        raise CurrentRootDeliveryError("local pending completion changed during state lookup")
                    encoded, record = records._prepare_ack_on_work(sequence=self._sequence + 1,
                        previous_record_digest=self._head_digest,
                        expected_pending_sequence=retained.pending_sequence,
                        expected_pending_head_digest=retained.pending_head_digest,
                        request_bytes=retained.request_bytes, receipt_bytes=receipt,
                        enrollment_bytes=self._enrollment_bytes, root_public_key=self._root_public_key, work=work)
                    live(payload)
                    self._append(encoded, record, work)
                    acknowledged = record.receipt_bytes
                live(payload)
                return CurrentRootDeliveryReconciliation("acknowledged", identity,
                    observed_sequence, observed_head, acknowledged)
            if retained.kind == "ack":
                raise CurrentRootDeliveryError("state lookup contradicts a durable original acknowledgment")
            unchanged = (observed_sequence == retained.pending_sequence
                and observed_head == retained.pending_head_digest
                and payload["pendingRequestDigest"] == retained.request_payload["pendingRequestDigest"]
                and payload["pendingDecisionDigest"] == retained.pending_head_digest)
            live(payload)
            return CurrentRootDeliveryReconciliation("pendingUnaccepted" if unchanged else "stateChanged",
                identity, observed_sequence, observed_head, None)

    @contextmanager
    def _recovery_scope(self):
        """Serialize fixed recovery through retention/delivery, not proof input."""
        self._require_process()
        with self._lock:
            self._require_ready()
            yield
            self._require_ready()

    def _original_for_pending_on_work(self, *, expected_pending_sequence,
            expected_pending_head_digest, work):
        """Locate exact retained bytes, never enroll a pending checkpoint.

        Recovery uses this before producing a completion: existing originals
        cannot be replaced or renewed. A returned pair is only a locator/raw
        original, not a fresh state statement or caller-supplied proof token.
        An unresolved other original or exhausted journal denies new work.
        """
        evidence.capture._SharedLedger(work)
        sequence, head = records._pending_scope(expected_pending_sequence, expected_pending_head_digest)
        self._require_process()
        with self._lock:
            self._require_ready()
            identity = self._pending_requests.get(head)
            if identity is not None:
                retained = self._history[identity]
                if retained.pending_sequence != sequence:
                    raise CurrentRootDeliveryError("retained completion has another pending sequence")
                return identity, retained.request_bytes
            if (self._pending is not None or sequence <= self._last_state_sequence
                    or self._sequence + 2 > self._maximum_records):
                raise CurrentRootDeliveryError("completion recovery cannot replace pending or consumed local scope")
            return None

    def inspect(self):
        self._require_process()
        with self._lock:
            self._require_ready()
            return CurrentRootDeliveryObservation(self._sequence, self._head_digest,
                None if self._pending is None else self._pending.request_digest, self._completed_count)

    def close(self):
        if os.getpid() != self._pid:
            raise CurrentRootDeliveryError("forked process cannot close completion delivery")
        with self._lock:
            if not self._closed:
                self._closed = True
                storage.CurrentRootJournal.close(self._journal)
