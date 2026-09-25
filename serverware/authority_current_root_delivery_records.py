"""Canonical local delivery records with original current-root signatures.

The local record chain is distinct from the state owner's sequence and head.
Its genesis predecessor is null; its separately admitted checkpoint begins at
the genuinely admitted enrollment digest, then uses framed original record
identities. Neither a canonical record nor the journal's raw file SHA supplies
that checkpoint or proves that a request was delivered.

Every request/acknowledgment path authenticates original enrollment and signed
control bytes on the supplied work. Historical verification permits retained
replay only: the owner must enforce freshness before a new enqueue. An ack
joins an actual state signature to the original complete request and the
independently admitted pending sequence/head retained in the request record.
The owner must also enforce local request/ack ordering and publish each record
before reporting its corresponding durable state.

Returned frozen containers contain ordinary owned observations, not admission
tokens. No verifier accepts them as a substitute for originals. There is no
clock, new work allowance, signing, I/O, retry, execution or key enrollment
apart from verification of the explicitly supplied original root enrollment.
"""
from __future__ import annotations

from dataclasses import dataclass

from serverware import authority_current_root_authorization as authorization
from serverware import authority_current_root_journal as journal
from serverware.authority_current_root_decisions import MAX_RECEIPT_BYTES


RECORD_SCHEMA = "serverware.policyAuthorityCurrentRootDeliveryRecord/v1"
RECORD_IDENTITY_DOMAIN = "serverware.policyAuthorityCurrentRootDeliveryRecordIdentity/v1"
MAX_BYTES = journal.MAX_RECORD_BYTES
MAX_REQUEST_BYTES = authorization.MAX_BYTES
MAX_NODES = 32
MAX_DEPTH = 2
REQUEST_FIELDS = frozenset({"schema", "kind", "enrollmentDigest", "sequence",
    "previousRecordDigest", "pendingSequence", "pendingHeadDigest", "requestBase64Url"})
ACK_FIELDS = REQUEST_FIELDS | frozenset({"receiptBase64Url"})
_ACK_JOINS = ("action", "enrollmentDigest", "databaseId", "generationDigest",
    "pendingRequestDigest", "fence", "beforeVectorDigest", "afterVectorDigest",
    "issuedAtEpochNs", "expiresAtEpochNs")


class CurrentRootDeliveryRecordError(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _VerifiedRequest:
    payload: dict
    request_digest: str


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _VerifiedAcknowledgment:
    request_payload: dict
    request_digest: str
    receipt_payload: dict
    receipt_digest: str


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _DeliveryRecord:
    kind: str
    enrollment_digest: str
    sequence: int
    previous_record_digest: str | None
    pending_sequence: int
    pending_head_digest: str
    request_bytes: bytes
    receipt_bytes: bytes | None
    request_payload: dict
    request_digest: str
    receipt_payload: dict | None
    receipt_digest: str | None
    record_digest: str


def _original(value, maximum, label):
    if type(value) is not bytes or not 2 <= len(value) <= maximum:
        raise CurrentRootDeliveryRecordError(label + " exceeds its original byte bound")
    return value


def _pending_scope(sequence, head):
    authorization.shape._integer(sequence, authorization.MAX_RECORDS - 1, minimum=1)
    authorization.shape._digest(head)
    return sequence, head


def _local_scope(sequence, previous):
    authorization.shape._integer(sequence, journal.MAX_RECORDS, minimum=1)
    if sequence == 1:
        if previous is not None:
            raise CurrentRootDeliveryRecordError("first local delivery record must have a null predecessor")
    else:
        authorization.shape._digest(previous)
    return sequence, previous


def _verify_request_on_work(*, request_bytes, enrollment_bytes, root_public_key,
        expected_pending_sequence, expected_pending_head_digest, work):
    """Authenticate the original complete control, without a live-time claim."""
    held_request = _original(request_bytes, MAX_REQUEST_BYTES, "delivery request")
    held_enrollment = _original(enrollment_bytes, authorization.MAX_ENROLLMENT_BYTES,
        "delivery enrollment")
    held_key = root_public_key
    pending_sequence, pending_head = _pending_scope(expected_pending_sequence,
        expected_pending_head_digest)
    authorization._public(held_key)
    material, payload, digest = authorization._verify_historical_request_on_work(
        request_bytes=held_request, enrollment_bytes=held_enrollment,
        root_public_key=held_key, work=work)
    if payload["action"] != "complete":
        raise CurrentRootDeliveryRecordError("delivery accepts only an original complete control")
    if pending_sequence >= material.payload["maxRecords"]:
        raise CurrentRootDeliveryRecordError("delivery pending sequence leaves no enrolled completion capacity")
    authorization.plan._same(payload["pendingDecisionDigest"], pending_head, work,
        "delivery independently admitted pending head")
    return _VerifiedRequest(payload, digest)


def _verify_ack_on_work(*, request_bytes, receipt_bytes, enrollment_bytes,
        root_public_key, expected_pending_sequence, expected_pending_head_digest, work):
    """Verify both originals and exact response/independent ancestry joins."""
    # Hold every original, key and scope scalar before any verification callback.
    held_request = _original(request_bytes, MAX_REQUEST_BYTES, "delivery request")
    held_receipt = _original(receipt_bytes, MAX_RECEIPT_BYTES, "delivery receipt")
    held_enrollment = _original(enrollment_bytes, authorization.MAX_ENROLLMENT_BYTES,
        "delivery enrollment")
    held_key = root_public_key
    pending_sequence, pending_head = _pending_scope(expected_pending_sequence,
        expected_pending_head_digest)
    authorization._public(held_key)
    request = _verify_request_on_work(request_bytes=held_request,
        enrollment_bytes=held_enrollment, root_public_key=held_key,
        expected_pending_sequence=pending_sequence,
        expected_pending_head_digest=pending_head, work=work)
    receipt = authorization._verify_receipt_on_work(receipt_bytes=held_receipt,
        enrollment_bytes=held_enrollment, root_public_key=held_key, work=work)
    for name in _ACK_JOINS:
        authorization.plan._same(receipt[name], request.payload[name], work,
            "delivery receipt " + name)
    authorization.plan._same(receipt["requestDigest"], request.request_digest, work,
        "delivery receipt original request identity")
    authorization.plan._same(receipt["sequence"], pending_sequence + 1, work,
        "delivery receipt independently admitted next state sequence")
    authorization.plan._same(receipt["previousHeadDigest"], pending_head, work,
        "delivery receipt independently admitted previous state head")
    # Signature/canonical admission above already covered these exact originals.
    receipt_digest = authorization.plan._frame(authorization.RECEIPT_IDENTITY_DOMAIN,
        (held_receipt,), work)
    return _VerifiedAcknowledgment(request.payload, request.request_digest,
        receipt, receipt_digest)


def _base64_count(value, maximum):
    if type(value) is not str or not 3 <= len(value) <= (4 * maximum + 2) // 3:
        raise CurrentRootDeliveryRecordError("delivery original transport exceeds its encoded bound")
    count = 3 * len(value) // 4
    authorization.transport._transport_shape(value, count, maximum)
    return count


def _shape(document):
    if type(document) is not dict or len(document) not in (len(REQUEST_FIELDS), len(ACK_FIELDS)):
        raise CurrentRootDeliveryRecordError("delivery record is not a closed object")
    kind = document.get("kind")
    if type(kind) is not str or kind not in ("request", "ack"):
        raise CurrentRootDeliveryRecordError("delivery record kind is not source fixed")
    authorization.shape._object(document, REQUEST_FIELDS if kind == "request" else ACK_FIELDS,
        "current-root delivery record")
    authorization.shape._literal(document["schema"], RECORD_SCHEMA)
    authorization.shape._digest(document["enrollmentDigest"])
    _local_scope(document["sequence"], document["previousRecordDigest"])
    _pending_scope(document["pendingSequence"], document["pendingHeadDigest"])
    _base64_count(document["requestBase64Url"], MAX_REQUEST_BYTES)
    if kind == "ack":
        _base64_count(document["receiptBase64Url"], MAX_RECEIPT_BYTES)


def _read(record_bytes, work):
    held = _original(record_bytes, MAX_BYTES, "delivery record")
    # Decoder allocates a bounded detached flat object on the supplied ledger.
    document = authorization.wire._decode_object(held, work=work,
        maximum_bytes=MAX_BYTES, maximum_nodes=MAX_NODES, maximum_depth=MAX_DEPTH)
    _shape(document)
    authorization.capability._canonical(held, document,
        authorization.capture._SharedLedger(work), MAX_BYTES, MAX_NODES)
    request = authorization.transport._decode(document["requestBase64Url"],
        _base64_count(document["requestBase64Url"], MAX_REQUEST_BYTES), MAX_REQUEST_BYTES, work)
    receipt = None
    if document["kind"] == "ack":
        receipt = authorization.transport._decode(document["receiptBase64Url"],
            _base64_count(document["receiptBase64Url"], MAX_RECEIPT_BYTES), MAX_RECEIPT_BYTES, work)
    return document, request, receipt


def _record_digest_on_work(original, work):
    """Framed canonical original identity only, not signature/checkpoint admission."""
    held = _original(original, MAX_BYTES, "delivery record")
    _read(held, work)
    return authorization.plan._frame(RECORD_IDENTITY_DOMAIN, (held,), work)


def _record(document, original, request_bytes, receipt_bytes,
        request_payload, request_digest, receipt_payload, receipt_digest, work):
    return _DeliveryRecord(document["kind"], document["enrollmentDigest"], document["sequence"],
        document["previousRecordDigest"], document["pendingSequence"], document["pendingHeadDigest"],
        request_bytes, receipt_bytes, request_payload, request_digest, receipt_payload, receipt_digest,
        authorization.plan._frame(RECORD_IDENTITY_DOMAIN, (original,), work))


def _decode_on_work(record_bytes, *, enrollment_bytes, root_public_key, work):
    """Decode and genuinely authenticate originals; owner checks the local chain."""
    held_record = _original(record_bytes, MAX_BYTES, "delivery record")
    held_enrollment = _original(enrollment_bytes, authorization.MAX_ENROLLMENT_BYTES,
        "delivery enrollment")
    held_key = root_public_key
    authorization._public(held_key)
    document, request_bytes, receipt_bytes = _read(held_record, work)
    scope = {"request_bytes": request_bytes, "enrollment_bytes": held_enrollment,
        "root_public_key": held_key, "expected_pending_sequence": document["pendingSequence"],
        "expected_pending_head_digest": document["pendingHeadDigest"], "work": work}
    if document["kind"] == "request":
        verified = _verify_request_on_work(**scope)
        payload, digest = verified.payload, verified.request_digest
        receipt_payload, receipt_digest = None, None
    else:
        verified = _verify_ack_on_work(receipt_bytes=receipt_bytes, **scope)
        payload, digest = verified.request_payload, verified.request_digest
        receipt_payload, receipt_digest = verified.receipt_payload, verified.receipt_digest
    authorization.plan._same(document["enrollmentDigest"], payload["enrollmentDigest"], work,
        "delivery record original enrollment")
    return _record(document, held_record, request_bytes, receipt_bytes, payload, digest,
        receipt_payload, receipt_digest, work)


def _prepare(*, kind, sequence, previous_record_digest, expected_pending_sequence,
        expected_pending_head_digest, request_bytes, receipt_bytes, enrollment_bytes,
        root_public_key, work):
    local_sequence, previous = _local_scope(sequence, previous_record_digest)
    pending_sequence, pending_head = _pending_scope(expected_pending_sequence,
        expected_pending_head_digest)
    held_request = _original(request_bytes, MAX_REQUEST_BYTES, "delivery request")
    held_enrollment = _original(enrollment_bytes, authorization.MAX_ENROLLMENT_BYTES,
        "delivery enrollment")
    held_receipt = None if kind == "request" else _original(receipt_bytes,
        MAX_RECEIPT_BYTES, "delivery receipt")
    held_key = root_public_key
    authorization._public(held_key)
    scope = {"request_bytes": held_request, "enrollment_bytes": held_enrollment,
        "root_public_key": held_key, "expected_pending_sequence": pending_sequence,
        "expected_pending_head_digest": pending_head, "work": work}
    if kind == "request":
        verified = _verify_request_on_work(**scope)
        payload, digest = verified.payload, verified.request_digest
        receipt_payload, receipt_digest = None, None
    else:
        verified = _verify_ack_on_work(receipt_bytes=held_receipt, **scope)
        payload, digest = verified.request_payload, verified.request_digest
        receipt_payload, receipt_digest = verified.receipt_payload, verified.receipt_digest
    document = {"schema": RECORD_SCHEMA, "kind": kind,
        "enrollmentDigest": payload["enrollmentDigest"], "sequence": local_sequence,
        "previousRecordDigest": previous, "pendingSequence": pending_sequence,
        "pendingHeadDigest": pending_head,
        "requestBase64Url": authorization.transport._encode(held_request, work)}
    if kind == "ack":
        document["receiptBase64Url"] = authorization.transport._encode(held_receipt, work)
    _shape(document)
    original = authorization.capability._wire(document,
        authorization.capture._SharedLedger(work), MAX_BYTES, MAX_NODES)
    return original, _record(document, original, held_request, held_receipt,
        payload, digest, receipt_payload, receipt_digest, work)


def _prepare_request_on_work(*, sequence, previous_record_digest, expected_pending_sequence,
        expected_pending_head_digest, request_bytes, enrollment_bytes, root_public_key, work):
    """Authenticate once and return canonical bytes plus same-call observations."""
    return _prepare(kind="request", sequence=sequence, previous_record_digest=previous_record_digest,
        expected_pending_sequence=expected_pending_sequence,
        expected_pending_head_digest=expected_pending_head_digest, request_bytes=request_bytes,
        receipt_bytes=None, enrollment_bytes=enrollment_bytes, root_public_key=root_public_key, work=work)


def _prepare_ack_on_work(*, sequence, previous_record_digest, expected_pending_sequence,
        expected_pending_head_digest, request_bytes, receipt_bytes, enrollment_bytes,
        root_public_key, work):
    """Authenticate both originals once; owner publishes before delivered return."""
    return _prepare(kind="ack", sequence=sequence, previous_record_digest=previous_record_digest,
        expected_pending_sequence=expected_pending_sequence,
        expected_pending_head_digest=expected_pending_head_digest, request_bytes=request_bytes,
        receipt_bytes=receipt_bytes, enrollment_bytes=enrollment_bytes, root_public_key=root_public_key,
        work=work)


def _encode_request_on_work(*, sequence, previous_record_digest, expected_pending_sequence,
        expected_pending_head_digest, request_bytes, enrollment_bytes, root_public_key, work):
    return _prepare_request_on_work(sequence=sequence, previous_record_digest=previous_record_digest,
        expected_pending_sequence=expected_pending_sequence,
        expected_pending_head_digest=expected_pending_head_digest, request_bytes=request_bytes,
        enrollment_bytes=enrollment_bytes, root_public_key=root_public_key, work=work)[0]


def _encode_ack_on_work(*, sequence, previous_record_digest, expected_pending_sequence,
        expected_pending_head_digest, request_bytes, receipt_bytes, enrollment_bytes,
        root_public_key, work):
    return _prepare_ack_on_work(sequence=sequence, previous_record_digest=previous_record_digest,
        expected_pending_sequence=expected_pending_sequence,
        expected_pending_head_digest=expected_pending_head_digest, request_bytes=request_bytes,
        receipt_bytes=receipt_bytes, enrollment_bytes=enrollment_bytes, root_public_key=root_public_key,
        work=work)[0]
