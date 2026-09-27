"""Durable one-attempt storage, separate from the database rollback domain.

An independently provisioned private journal and an independently current EXACT
local sequence/head are mandatory. Recovery authenticates no request and cannot
declare its own latest checkpoint. This unsigned source-bound chain is protected
by its separate directory/lease/checkpoint owner, not by a database commit marker
or a claim of hostile-host antirollback. No directory or checkpoint is created.

The actual executor consumes an attempt before connecting to the database. Each
pending-decision identity AND each packet identity is usable at most once, even
after SQL abort, timeout, process restart or byte-identical resubmission. Records
are never removed, reset, expired or retried. A late failure may already have
burned the attempt; an ambiguous publication poisons and closes this owner.

Claim spends only the caller's original validation work and unchanged live
window. Legacy cold recovery has one fixed work allowance per source-bounded
record; an explicitly supplied cold allowance stays cumulative through recovery.
Physical journal calls are not interrupted by a hard watchdog. Returned local
inspection data, and a claim returning None, are not authorization/proof tokens.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
import threading
import time

from serverware import authority_contract as authority
from serverware import authority_current_root_journal as storage
from serverware import authority_revocation_capability as codec
from serverware import authority_revocation_proof_bundle as encoding
from serverware import authority_webauthn_evidence as evidence
from serverware import authority_webauthn_evidence_plan_clock as clock
from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork


SCHEMA = "serverware.policyAuthoritySuccessorExecutionAttempt/v1"
GENESIS_DOMAIN = "serverware.policyAuthoritySuccessorExecutionAttemptGenesis/v1"
IDENTITY_DOMAIN = "serverware.policyAuthoritySuccessorExecutionAttemptIdentity/v1"
MAX_BYTES = 4096
MAX_NODES = 64
MAX_DEPTH = 2
FIELDS = frozenset({"schema", "sourceRevision", "structureManifestDigest", "sequence",
    "previousRecordDigest", "pendingDecisionDigest", "packetDigest"})


class SuccessorExecutionAttemptsError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class SuccessorExecutionAttemptsObservation:
    """Unsigned local metadata; never an independently current checkpoint."""

    sequence: int
    head_digest: str
    attempted_count: int


def _cold_work():
    return _ValidationWork(QueryReadValidationLimits())


def _genesis_on_work(structure_manifest_digest, work):
    codec.capture._SharedLedger(work)
    codec.shape._digest(structure_manifest_digest)
    return codec.plan._frame(GENESIS_DOMAIN,
        (codec.plan._ascii(authority.SOURCE_REVISION, work),
            codec.plan._ascii(structure_manifest_digest, work)), work)


def _shape(document):
    codec.shape._object(document, FIELDS, "successor execution attempt")
    codec.shape._literal(document["schema"], SCHEMA)
    codec.shape._literal(document["sourceRevision"], authority.SOURCE_REVISION)
    for name in ("structureManifestDigest", "pendingDecisionDigest", "packetDigest"):
        codec.shape._digest(document[name])
    codec.shape._integer(document["sequence"], storage.MAX_RECORDS, minimum=1)
    previous = document["previousRecordDigest"]
    if document["sequence"] == 1:
        if previous is not None:
            raise SuccessorExecutionAttemptsError("first attempt must have a null local predecessor")
    else:
        codec.shape._digest(previous)


def _encode_on_work(document, work):
    # The closed seven-field graph contains only exact immutable scalars.
    _shape(document)
    return encoding._bounded_wire(document, codec.capture._SharedLedger(work),
        maximum_bytes=MAX_BYTES, maximum_nodes=MAX_NODES)


def _decode_on_work(original, work):
    if type(original) is not bytes or not 2 <= len(original) <= MAX_BYTES:
        raise SuccessorExecutionAttemptsError("attempt original exceeds its byte bound")
    document = codec.wire._decode_object(original, work=work, maximum_bytes=MAX_BYTES,
        maximum_nodes=MAX_NODES, maximum_depth=MAX_DEPTH)
    encoded = _encode_on_work(document, work)
    work.charge(input_bytes=len(original) + len(encoded))
    if encoded != original:
        raise SuccessorExecutionAttemptsError("attempt original is not canonical")
    return document


class SuccessorExecutionAttempts:
    """PID-bound serialized owner of an independently current attempt chain.

    Ownership transfers only for an exact fresh CurrentRootJournal, including
    failure closure. Its genuine one-shot recover rejects an already recovered
    journal. Sequence zero's explicitly supplied head must match the source and
    structure-manifest genesis; later heads identify framed original records.
    Neither an empty directory nor a valid old prefix supplies this checkpoint.
    """

    __slots__ = ("_journal", "_pid", "_closed", "_lock", "_sequence", "_head_digest",
        "_structure_manifest_digest", "_maximum_records", "_pending_digests", "_packet_digests")

    def __init__(self, *, journal, expected_structure_manifest_digest,
            expected_local_sequence, expected_local_head_digest,
            live_window=None, work=None, transport_deadline_ns=None):
        if type(journal) is not storage.CurrentRootJournal:
            raise SuccessorExecutionAttemptsError("attempt owner requires its actual separate journal")
        self._journal = journal
        self._pid, self._closed = os.getpid(), False
        self._lock = threading.RLock()
        self._sequence = 0
        self._pending_digests, self._packet_digests = set(), set()
        try:
            codec.shape._digest(expected_structure_manifest_digest)
            codec.shape._integer(expected_local_sequence, storage.MAX_RECORDS)
            codec.shape._digest(expected_local_head_digest)
            expected = expected_local_sequence, expected_local_head_digest
            self._structure_manifest_digest = expected_structure_manifest_digest
            self._maximum_records = storage.CurrentRootJournal.maximum_records.fget(journal)
            if expected_local_sequence > self._maximum_records:
                raise SuccessorExecutionAttemptsError("attempt checkpoint exceeds the provisioned record limit")
            inherited = (live_window, work, transport_deadline_ns)
            live = None
            if any(value is not None for value in inherited):
                if any(value is None for value in inherited):
                    raise SuccessorExecutionAttemptsError("attempt cold allowance must be supplied completely")
                codec.capture._SharedLedger(work)
                window = clock._validate(live_window)
                codec.shape._integer(transport_deadline_ns, minimum=1)
                bound = min(window[4], transport_deadline_ns)
                last_epoch, last_monotonic = window[0], window[2]

                def live():
                    nonlocal last_epoch, last_monotonic
                    self._require_process()
                    now = clock._check_on_work(window, work=work)
                    monotonic = evidence.production._callback(work, time.monotonic_ns)
                    codec.shape._integer(monotonic, minimum=1)
                    if now < last_epoch or monotonic < last_monotonic or monotonic >= bound:
                        raise SuccessorExecutionAttemptsError("attempt cold original interval expired or reversed")
                    last_epoch, last_monotonic = now, monotonic

                live()
            self._head_digest = _genesis_on_work(self._structure_manifest_digest,
                _cold_work() if live is None else work)
            if live is None:
                storage.CurrentRootJournal.recover(journal, self._recover_record)
            else:
                def recover_record(sequence, original):
                    live()
                    self._recover_record_on_work(sequence, original, work)
                    live()

                live()
                # The genuine record consumer charges the inherited ledger.
                # A metrics-constant native callback around the whole recovery
                # would reject those required charges after the first record.
                storage.CurrentRootJournal.recover(journal, recover_record)
                live()
            if (self._sequence, self._head_digest) != expected:
                raise SuccessorExecutionAttemptsError("attempt journal differs from independently current checkpoint")
            self._require_ready()
            if live is not None:
                live()
        except BaseException:
            self._poison_and_close()
            raise

    def _require_process(self):
        if os.getpid() != self._pid:
            raise SuccessorExecutionAttemptsError("forked process cannot use successor attempts")
        if self._closed:
            raise SuccessorExecutionAttemptsError("successor attempt owner is closed")

    def _require_ready(self):
        self._require_process()
        try:
            if (storage.CurrentRootJournal.count.fget(self._journal) != self._sequence
                    or len(self._pending_digests) != self._sequence
                    or len(self._packet_digests) != self._sequence):
                raise SuccessorExecutionAttemptsError("attempt journal changed outside its owner")
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

    def _check_record(self, document):
        previous = None if self._sequence == 0 else self._head_digest
        if (document["structureManifestDigest"] != self._structure_manifest_digest
                or document["sequence"] != self._sequence + 1
                or document["sequence"] > self._maximum_records
                or document["previousRecordDigest"] != previous):
            raise SuccessorExecutionAttemptsError("attempt record differs from the exact local chain")
        if (document["pendingDecisionDigest"] in self._pending_digests
                or document["packetDigest"] in self._packet_digests):
            raise SuccessorExecutionAttemptsError("successor pending decision or packet was already attempted")

    def _install_record(self, document, identity):
        self._pending_digests.add(document["pendingDecisionDigest"])
        self._packet_digests.add(document["packetDigest"])
        self._sequence, self._head_digest = document["sequence"], identity

    def _recover_record(self, sequence, original):
        self._recover_record_on_work(sequence, original, _cold_work())

    def _recover_record_on_work(self, sequence, original, work):
        document = _decode_on_work(original, work)
        if document["sequence"] != sequence:
            raise SuccessorExecutionAttemptsError("attempt filename and original sequence differ")
        self._check_record(document)
        identity = codec.plan._frame(IDENTITY_DOMAIN, (original,), work)
        self._install_record(document, identity)

    @property
    def structure_manifest_digest(self):
        self._require_process()
        with self._lock:
            self._require_ready()
            return self._structure_manifest_digest

    def _claim_on_work(self, *, pending_decision_digest, packet_digest, live_window,
            work, transport_deadline_ns=None):
        """Durably burn one attempt before any SQL; never authorize its use.

        Any repeated pending identity OR packet identity is rejected, including
        identical bytes. On every error the caller must treat execution as
        denied; a late error may follow a fully durable attempt publication.
        """
        codec.capture._SharedLedger(work)
        codec.shape._digest(pending_decision_digest)
        codec.shape._digest(packet_digest)
        pending, packet = pending_decision_digest, packet_digest
        window = clock._validate(live_window)
        if transport_deadline_ns is not None:
            codec.shape._integer(transport_deadline_ns, minimum=1)
        bound = window[4] if transport_deadline_ns is None else min(window[4], transport_deadline_ns)
        self._require_process()
        with self._lock:
            self._require_ready()
            position = self._sequence, self._head_digest
            last_epoch, last_monotonic = window[0], window[2]

            def live():
                nonlocal last_epoch, last_monotonic
                self._require_ready()
                now = clock._check_on_work(window, work=work)
                monotonic = evidence.production._callback(work, time.monotonic_ns)
                codec.shape._integer(monotonic, minimum=1)
                self._require_ready()
                if (now < last_epoch or monotonic < last_monotonic or monotonic >= bound
                        or (self._sequence, self._head_digest) != position):
                    raise SuccessorExecutionAttemptsError("attempt original window or local position changed")
                last_epoch, last_monotonic = now, monotonic

            live()
            if self._sequence >= self._maximum_records:
                raise SuccessorExecutionAttemptsError("successor attempt journal capacity is exhausted")
            document = {"schema": SCHEMA, "sourceRevision": authority.SOURCE_REVISION,
                "structureManifestDigest": self._structure_manifest_digest,
                "sequence": self._sequence + 1,
                "previousRecordDigest": None if self._sequence == 0 else self._head_digest,
                "pendingDecisionDigest": pending, "packetDigest": packet}
            self._check_record(document)
            original = _encode_on_work(document, work)
            identity = codec.plan._frame(IDENTITY_DOMAIN, (original,), work)
            work.charge(hashes=1, input_bytes=len(original))
            raw_digest = "sha256:" + hashlib.sha256(original).hexdigest()
            live()
            try:
                metadata = evidence.production._callback(work,
                    lambda: storage.CurrentRootJournal.append(self._journal, original))
                if (type(metadata) is not storage.CurrentRootRecord
                        or metadata.sequence != document["sequence"] or metadata.digest != raw_digest
                        or metadata.byte_count != len(original)):
                    raise SuccessorExecutionAttemptsError("attempt publication differs from its exact original")
                self._install_record(document, identity)
                self._require_ready()
            except BaseException:
                self._poison_and_close()
                raise
            position = self._sequence, self._head_digest
            # Failure here never removes the now-durable attempt or permits SQL.
            live()

    def inspect(self):
        self._require_process()
        with self._lock:
            self._require_ready()
            return SuccessorExecutionAttemptsObservation(self._sequence, self._head_digest,
                len(self._pending_digests))

    def close(self):
        if os.getpid() != self._pid:
            raise SuccessorExecutionAttemptsError("forked process cannot close successor attempts")
        with self._lock:
            if not self._closed:
                self._closed = True
                storage.CurrentRootJournal.close(self._journal)
