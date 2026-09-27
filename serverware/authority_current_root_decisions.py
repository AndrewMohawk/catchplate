"""Durable one-pending current-root decisions, without deployment authority.

The cold owner must independently admit the root key, exact latest checkpoint,
state signer and private directory. Neither the local journal nor a valid old
signature can supply that latest checkpoint. This owner genuinely verifies the
root-signed enrollment and every purpose-specific original request/receipt;
ordinary caller data cannot replace those signature checks.

An enrolled computation producer must actually prove the proposed mutation and
complete roots; delta compatibility alone does not do so. An enrolled completion
producer must attest the exact protected postcommit receipt after confirmed SQL
commit. These producer implementations, cold admission, transport and atomic SQL
integration remain separate prerequisites. No legacy gate is enabled here.

Reserve publishes a signed pending decision before returning it. One completion
slot is retained. Expiry never releases pending state; there is no abort/reset,
generation rollover or automatic execution. Exact replay returns the original
historical receipt without minting a new fence. Challenge-bound lookup signs
only this serialized owner's observed state; it supplies no independent latest
checkpoint, hostile-host antirollback or permission to retry execution.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
import os
import threading
import time

from serverware import authority_current_root_authorization as authorization
from serverware import authority_current_root_journal as storage
from serverware import authority_current_root_lookup as lookup_wire
from serverware import authority_current_root_vector as vector
from serverware import authority_webauthn_evidence as evidence
from serverware import authority_webauthn_evidence_plan_clock as clock
from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork


RECORD_SCHEMA = "serverware.policyAuthorityCurrentRootJournalRecord/v1"
RECEIPT_SCHEMA = "serverware.policyAuthorityCurrentRootReceipt/v1"
MAX_REQUEST_BYTES = 256 * 1024
MAX_RECEIPT_BYTES = 16 * 1024
_RECORD_FIELDS = frozenset({"schema", "enrollmentDigest", "sequence",
    "requestBase64Url", "receiptBase64Url"})


class CurrentRootDecisionError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class CurrentRootObservation:
    """Unsigned local inspection only; not a fresh currentness statement."""

    sequence: int
    head_digest: str
    vector_digest: str
    fence: int
    pending_request_digest: str | None


def _work():
    return _ValidationWork(QueryReadValidationLimits())


def _encode_raw(raw, maximum, work):
    if type(raw) is not bytes or not 2 <= len(raw) <= maximum:
        raise CurrentRootDecisionError("current-root record original exceeds its byte bound")
    encoded_size = 4 * ((len(raw) + 2) // 3)
    work.charge(input_bytes=len(raw) + 3 * encoded_size)
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _decode_raw(value, maximum, work):
    if (type(value) is not str or not 1 <= len(value) <= 4 * ((maximum + 2) // 3)
            or any(character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
                for character in value)):
        raise CurrentRootDecisionError("current-root record original is not bounded base64url")
    work.prepare_utf8(value)
    work.charge(input_bytes=3 * (len(value) + 3))
    try:
        raw = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except ValueError as exc:
        raise CurrentRootDecisionError("current-root record original is not base64url") from exc
    if _encode_raw(raw, maximum, work) != value:
        raise CurrentRootDecisionError("current-root record original is not canonical base64url")
    return raw


def _record(enrollment_digest, sequence, request_bytes, receipt_bytes, work):
    document = {"schema": RECORD_SCHEMA, "enrollmentDigest": enrollment_digest,
        "sequence": sequence,
        "requestBase64Url": _encode_raw(request_bytes, MAX_REQUEST_BYTES, work),
        "receiptBase64Url": _encode_raw(receipt_bytes, MAX_RECEIPT_BYTES, work)}
    return vector.encoding._bounded_wire(document, vector.capture._SharedLedger(work),
        maximum_bytes=storage.MAX_RECORD_BYTES, maximum_nodes=32)


def _read_record(raw, enrollment_digest, sequence, work):
    if type(raw) is not bytes or not 2 <= len(raw) <= storage.MAX_RECORD_BYTES:
        raise CurrentRootDecisionError("current-root journal record exceeds its bound")
    document = vector.wire._decode_object(raw, work=work,
        maximum_bytes=storage.MAX_RECORD_BYTES, maximum_nodes=32, maximum_depth=2)
    vector._closed(document, _RECORD_FIELDS, "current-root journal record")
    if (document["schema"] != RECORD_SCHEMA or document["enrollmentDigest"] != enrollment_digest
            or type(document["sequence"]) is not int or document["sequence"] != sequence):
        raise CurrentRootDecisionError("current-root record scope/sequence differs")
    request = _decode_raw(document["requestBase64Url"], MAX_REQUEST_BYTES, work)
    receipt = _decode_raw(document["receiptBase64Url"], MAX_RECEIPT_BYTES, work)
    canonical = _record(enrollment_digest, sequence, request, receipt, work)
    work.charge(input_bytes=len(raw) + len(canonical))
    if raw != canonical:
        raise CurrentRootDecisionError("current-root journal record is not canonical")
    return request, receipt


class CurrentRootDecisionOwner:
    """Source-fixed signing/replay owner over one actual durable journal.

    Construction takes ownership of the journal, including failure closure.
    Expected sequence/head must be independently current, not read from this
    journal or guessed from an empty directory. Zero explicitly selects the
    root-signed enrollment's initial vector and enrollment digest as its head.
    Historical records each receive one source-fixed validation allowance;
    the journal's fixed record/byte limits bound the complete cold replay.
    Each new request uses one allowance throughout admission and publication.
    """

    def __init__(self, *, journal, enrollment_bytes, root_public_key,
            state_private_key, expected_sequence, expected_head_digest):
        if type(journal) is not storage.CurrentRootJournal:
            raise CurrentRootDecisionError("current-root decisions require the actual journal owner")
        self._journal = journal
        self._pid, self._lock, self._closed = os.getpid(), threading.RLock(), False
        self._enrollment_bytes = enrollment_bytes
        self._root_public_key, self._state_private_key = root_public_key, state_private_key
        self._history, self._operations, self._capabilities = {}, set(), set()
        self._pending = None
        try:
            work = _work()
            if type(expected_sequence) is not int or not 0 <= expected_sequence <= storage.MAX_RECORDS:
                raise CurrentRootDecisionError("current-root expected checkpoint sequence is invalid")
            evidence.plan.contract._digest(expected_head_digest)
            expected_head = expected_head_digest
            material = authorization._admit_enrollment_on_work(enrollment_bytes=enrollment_bytes,
                root_public_key=root_public_key, work=work)
            if not isinstance(state_private_key, evidence.keys.Ed25519PrivateKey):
                raise CurrentRootDecisionError("current-root state signer is not Ed25519")
            evidence.keys._pair_on_work(state_private_key, material.state_public_key, work)
            if journal.maximum_records != material.payload["maxRecords"]:
                raise CurrentRootDecisionError("current-root journal capacity differs from enrollment")
            self._material = material
            self._vector_bytes = vector._encode_on_work(material.payload["initialVector"], work=work)
            self._vector_digest = vector._digest_on_work(self._vector_bytes, work=work)
            self._sequence, self._fence = 0, 0
            self._head_digest = material.enrollment_digest
            # Only this actual source-owned replay callback reaches the I/O
            # layer; no request provides a reducer or verification registry.
            journal.recover(self._recover_record)
            if (self._sequence, self._head_digest) != (expected_sequence, expected_head):
                raise CurrentRootDecisionError("current-root journal differs from independently current checkpoint")
            if journal.count != self._sequence:
                raise CurrentRootDecisionError("current-root recovered record inventory differs")
        except BaseException:
            self._closed = True
            journal.poison()
            journal.close()
            raise

    def _require_ready(self):
        if os.getpid() != self._pid:
            raise CurrentRootDecisionError("forked process cannot use current-root decisions")
        if self._closed:
            raise CurrentRootDecisionError("current-root decision owner is closed")
        if self._journal.count != self._sequence:
            self._journal.poison()
            raise CurrentRootDecisionError("current-root journal changed outside its decision owner")

    def _proposal(self, request, request_digest, work):
        """Derive a receipt candidate from this invocation's genuine admission."""
        material = self._material
        if request_digest in self._history:
            raise CurrentRootDecisionError("current-root journal repeats a request identity")
        if request["action"] == "reserve":
            if self._pending is not None:
                raise CurrentRootDecisionError("current-root enrollment already has a pending decision")
            if self._sequence + 2 > material.payload["maxRecords"]:
                raise CurrentRootDecisionError("current-root cannot reserve completion capacity")
            if (request["operationId"] in self._operations
                    or request["capabilityDigest"] in self._capabilities):
                raise CurrentRootDecisionError("current-root operation or capability is already consumed")
            if (request["predecessorSequence"], request["predecessorHeadDigest"], request["fence"]) != (
                    self._sequence, self._head_digest, self._fence + 1):
                raise CurrentRootDecisionError("current-root reservation predecessor or fence differs")
            before = vector._encode_on_work(request["beforeVector"], work=work)
            work.charge(input_bytes=len(before) + len(self._vector_bytes))
            if before != self._vector_bytes:
                raise CurrentRootDecisionError("current-root reservation does not use the complete current vector")
            after = vector._encode_on_work(request["afterVector"], work=work)
            before_digest, after_digest = self._vector_digest, vector._digest_on_work(after, work=work)
            pending_request = request_digest
        elif request["action"] == "complete":
            pending = self._pending
            if pending is None:
                raise CurrentRootDecisionError("current-root completion has no pending decision")
            original, pending_request, pending_decision, after, before_digest, after_digest = pending
            if (request["operation"], request["pendingRequestDigest"], request["pendingDecisionDigest"],
                    request["fence"], request["snapshotDigest"], request["beforeVectorDigest"],
                    request["afterVectorDigest"]) != (original["operation"], pending_request,
                    pending_decision, original["fence"], original["snapshotDigest"],
                    before_digest, after_digest):
                raise CurrentRootDecisionError("current-root completion differs from the exact pending decision")
            if self._sequence + 1 > material.payload["maxRecords"]:
                raise CurrentRootDecisionError("current-root completion capacity is unavailable")
        else:
            raise CurrentRootDecisionError("current-root action is not source fixed")
        receipt = {"schema": RECEIPT_SCHEMA, "sourceRevision": vector.authority.SOURCE_REVISION,
            "action": request["action"], "enrollmentDigest": material.enrollment_digest,
            "databaseId": material.payload["databaseId"], "generationDigest": material.payload["generationDigest"],
            "producerMeasurementDigest": material.payload["state"]["measurementDigest"],
            "requestDigest": request_digest, "sequence": self._sequence + 1,
            "previousHeadDigest": self._head_digest, "fence": request["fence"],
            "beforeVectorDigest": before_digest, "afterVectorDigest": after_digest,
            "pendingRequestDigest": pending_request,
            "issuedAtEpochNs": request["issuedAtEpochNs"], "expiresAtEpochNs": request["expiresAtEpochNs"]}
        return receipt, after

    def _accept(self, request, request_digest, request_bytes, receipt_bytes, receipt_digest, receipt, after):
        if request["action"] == "reserve":
            self._pending = (request, request_digest, receipt_digest, after,
                receipt["beforeVectorDigest"], receipt["afterVectorDigest"])
            self._operations.add(request["operationId"])
            self._capabilities.add(request["capabilityDigest"])
        else:
            self._vector_bytes, self._vector_digest = after, receipt["afterVectorDigest"]
            self._pending = None
        self._sequence, self._head_digest, self._fence = receipt["sequence"], receipt_digest, receipt["fence"]
        self._history[request_digest] = (request_bytes, receipt_bytes)

    def _recover_record(self, sequence, raw):
        work = _work()
        request_bytes, receipt_bytes = _read_record(raw, self._material.enrollment_digest, sequence, work)
        material, request, request_digest = authorization._verify_historical_request_on_work(
            request_bytes=request_bytes, enrollment_bytes=self._enrollment_bytes,
            root_public_key=self._root_public_key, work=work)
        if material.enrollment_digest != self._material.enrollment_digest:
            raise CurrentRootDecisionError("current-root recovered enrollment changed")
        receipt = authorization._verify_receipt_on_work(receipt_bytes=receipt_bytes,
            enrollment_bytes=self._enrollment_bytes, root_public_key=self._root_public_key, work=work)
        expected, after = self._proposal(request, request_digest, work)
        evidence.plan._same(receipt, expected, work, "current-root signed record does not replay")
        if sequence != receipt["sequence"]:
            raise CurrentRootDecisionError("current-root record and receipt sequences differ")
        receipt_digest = authorization._receipt_digest_on_work(receipt_bytes, work)
        self._accept(request, request_digest, request_bytes, receipt_bytes, receipt_digest, receipt, after)

    def apply(self, request_bytes, *, transport_deadline_ns=None, expected_action=None,
            expected_operation=None):
        """Durably reserve/complete once, or return the exact historical receipt.

        An exception after publication can leave a pending or completed record.
        It never proves absence or allows execution, reset or a new reservation.
        """
        if type(request_bytes) is not bytes or not 2 <= len(request_bytes) <= MAX_REQUEST_BYTES:
            raise CurrentRootDecisionError("current-root request is not bounded original bytes")
        if os.getpid() != self._pid:
            raise CurrentRootDecisionError("forked process cannot use current-root decisions")
        # A purpose-admitted serving edge may only restrict the signed action;
        # it cannot choose a parser verdict or add authority to the request.
        if expected_action is not None:
            authorization._action(expected_action)
        if expected_operation is not None and (type(expected_operation) is not str
                or expected_operation not in authorization.OPERATIONS):
            raise CurrentRootDecisionError("current-root transport operation restriction is invalid")
        original, inherited, purpose = request_bytes, transport_deadline_ns, expected_action
        operation = expected_operation
        work = _work()
        if inherited is not None:
            evidence.plan.contract._integer(inherited, minimum=1)
        with self._lock:
            self._require_ready()
            policy = self._material.payload
            now = evidence.production._callback(work, time.time_ns)
            window = clock._open_on_work(deadline_epoch_ns=now + policy["maxControlAgeNs"],
                maximum_lifetime_ns=policy["maxControlAgeNs"],
                maximum_clock_skew_ns=policy["maxClockSkewNs"], work=work)
            bound = window[4] if inherited is None else min(window[4], inherited)

            def live(request=None):
                instant = clock._check_on_work(window, work=work)
                monotonic = evidence.production._callback(work, time.monotonic_ns)
                if monotonic >= bound:
                    raise CurrentRootDecisionError("current-root original transport window expired")
                if request is not None:
                    evidence._fresh(request, instant, policy["maxControlAgeNs"], policy["maxClockSkewNs"])
                self._require_ready()

            live()
            material, request, request_digest = authorization._verify_historical_request_on_work(
                request_bytes=original, enrollment_bytes=self._enrollment_bytes,
                root_public_key=self._root_public_key, work=work)
            if material.enrollment_digest != self._material.enrollment_digest:
                raise CurrentRootDecisionError("current-root request enrollment changed")
            if purpose is not None and request["action"] != purpose:
                raise CurrentRootDecisionError("current-root signed action differs from its admitted transport purpose")
            if operation is not None and request["operation"] != operation:
                raise CurrentRootDecisionError("current-root signed operation differs from its admitted peer")
            prior = self._history.get(request_digest)
            if prior is not None:
                work.charge(input_bytes=len(original) + len(prior[0]))
                if prior[0] != original:
                    raise CurrentRootDecisionError("current-root request identity has conflicting originals")
                live()
                return prior[1]
            live(request)
            receipt, after = self._proposal(request, request_digest, work)
            encoded = authorization._produce_receipt_on_work(payload=receipt,
                enrollment_bytes=self._enrollment_bytes, root_public_key=self._root_public_key,
                state_private_key=self._state_private_key, work=work)
            receipt_digest = authorization._receipt_digest_on_work(encoded, work)
            record = _record(material.enrollment_digest, receipt["sequence"], original, encoded, work)
            live(request)
            try:
                observed = self._journal.append(record)
                if observed.sequence != receipt["sequence"]:
                    raise CurrentRootDecisionError("current-root publication sequence differs")
                self._accept(request, request_digest, original, encoded, receipt_digest, receipt, after)
            except BaseException:
                self._journal.poison()
                raise
            # A late error retains the durable decision. It is not a rollback
            # or a reason to reset a pending fence; exact readback stays separate.
            live(request)
            return encoded

    def lookup(self, query_bytes, *, transport_deadline_ns=None):
        """Sign a fresh observation without changing the journal or decisions.

        An accepted request returns its exact historical receipt, even when that
        receipt expired. The observation cannot renew its execution authority.
        notRecorded describes only this locked history, not SQL noncommit or
        permission to clear pending state, retry or choose an older checkpoint.
        """
        if type(self) is not CurrentRootDecisionOwner:
            raise CurrentRootDecisionError("current-root lookup requires the actual decision owner")
        if type(query_bytes) is not bytes or not 2 <= len(query_bytes) <= lookup_wire.MAX_QUERY_BYTES:
            raise CurrentRootDecisionError("current-root lookup query exceeds its original-byte bound")
        if os.getpid() != self._pid:
            raise CurrentRootDecisionError("forked process cannot query current-root decisions")
        original, inherited = query_bytes, transport_deadline_ns
        work = _work()
        if inherited is not None:
            evidence.plan.contract._integer(inherited, minimum=1)
        with self._lock:
            CurrentRootDecisionOwner._require_ready(self)
            material, pending, history = self._material, self._pending, self._history
            enrollment, root_key, state_key = (
                self._enrollment_bytes, self._root_public_key, self._state_private_key)
            policy = material.payload
            pins = (material.enrollment_digest, policy["databaseId"], policy["generationDigest"],
                policy["state"]["measurementDigest"], policy["maxControlAgeNs"], policy["maxClockSkewNs"])
            state = (self._sequence, self._head_digest, self._vector_digest, self._fence)
            pending_request = None if pending is None else pending[1]
            pending_decision = None if pending is None else pending[2]
            # Own the actual immutable state/key/policy scalars before native
            # clock or signing callbacks. The existing lock serializes apply.
            now = evidence.production._callback(work, time.time_ns)
            window = clock._open_on_work(deadline_epoch_ns=now + pins[4],
                maximum_lifetime_ns=pins[4], maximum_clock_skew_ns=pins[5], work=work)
            if inherited is not None and inherited < window[4]:
                # Shorten the original opening bracket, never open another one.
                expires = window[0] + inherited - window[1]
                window = clock._validate((window[0], window[1], window[2], expires,
                    inherited, window[5], window[6]))
            last_epoch, last_monotonic = window[0], window[2]

            def live():
                nonlocal last_epoch, last_monotonic
                instant = clock._check_on_work(window, work=work)
                monotonic = evidence.production._callback(work, time.monotonic_ns)
                evidence.plan.contract._integer(monotonic, minimum=1)
                if (instant < last_epoch or monotonic < last_monotonic
                        or monotonic >= window[4]):
                    raise CurrentRootDecisionError("current-root lookup original window expired or clock reversed")
                last_epoch, last_monotonic = instant, monotonic
                CurrentRootDecisionOwner._require_ready(self)
                if (self._material is not material or self._pending is not pending
                        or self._history is not history or self._enrollment_bytes is not enrollment
                        or self._root_public_key is not root_key or self._state_private_key is not state_key
                        or (self._sequence, self._head_digest, self._vector_digest, self._fence) != state):
                    raise CurrentRootDecisionError("current-root lookup owner state changed during observation")
                return instant

            live()
            query = lookup_wire._decode_query_on_work(original, work=work)
            queried, challenge = query["requestDigest"], query["challenge"]
            evidence.plan._same(query["enrollmentDigest"], pins[0], work,
                "current-root lookup query names another enrollment")
            query_digest = lookup_wire._query_digest_on_work(original, work)
            prior = history.get(queried)
            receipt_wire, receipt_count, receipt_digest = None, 0, None
            if prior is not None:
                receipt = prior[1]
                receipt_wire = _encode_raw(receipt, MAX_RECEIPT_BYTES, work)
                receipt_count = len(receipt)
                work.charge(hashes=1, input_bytes=receipt_count)
                receipt_digest = "sha256:" + hashlib.sha256(receipt).hexdigest()
            payload = {"schema": lookup_wire.PAYLOAD_SCHEMA,
                "sourceRevision": vector.authority.SOURCE_REVISION,
                "enrollmentDigest": pins[0], "databaseId": pins[1], "generationDigest": pins[2],
                "producerMeasurementDigest": pins[3], "queryDigest": query_digest,
                "challenge": challenge, "requestedRequestDigest": queried,
                "issuedAtEpochNs": window[0], "expiresAtEpochNs": window[3],
                "sequence": state[0], "headDigest": state[1], "vectorDigest": state[2], "fence": state[3],
                "pendingRequestDigest": pending_request, "pendingDecisionDigest": pending_decision,
                "requestStatus": "notRecorded" if prior is None else "accepted",
                "receiptBase64Url": receipt_wire, "receiptByteCount": receipt_count,
                "receiptBytesDigest": receipt_digest}
            encoded = lookup_wire._sign_on_work(payload=payload, enrollment_bytes=enrollment,
                root_public_key=root_key, state_private_key=state_key,
                now_epoch_ns=live(), work=work)
            live()
            if history.get(queried) is not prior:
                raise CurrentRootDecisionError("current-root queried history changed during observation")
            return encoded

    def inspect(self):
        if os.getpid() != self._pid:
            raise CurrentRootDecisionError("forked process cannot inspect current-root decisions")
        with self._lock:
            self._require_ready()
            return CurrentRootObservation(self._sequence, self._head_digest, self._vector_digest,
                self._fence, None if self._pending is None else self._pending[1])

    def close(self):
        if os.getpid() != self._pid:
            raise CurrentRootDecisionError("forked process cannot close current-root decisions")
        with self._lock:
            if not self._closed:
                self._closed = True
                self._state_private_key = None
                self._journal.close()
