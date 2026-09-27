"""Canonical local originals for one fixed registration reserve operation.

The local chain and its independently admitted checkpoint are separate from
the state owner's predecessor sequence/head. This codec authenticates enrolled
historical reserve signatures, their exact canonical computation snapshots and
original state acknowledgments. It does not establish freshness, currentness,
grant provenance, delivery, reservation ownership or execution permission.

executionRecordDigest is only a local locator. No original grant is supplied
here: matching the signed reserve/snapshot capability commitment cannot replace
the caller's genuine grant replay. Request and acknowledgment observations are
ordinary same-call data, never accepted as substitutes for original bytes.
The owner checks local ordering and publishes before reporting durable state.
There is no I/O, clock, signing, new work allowance or retry in this module.
"""
from __future__ import annotations

from dataclasses import dataclass

from serverware import authority_current_root_authorization as authorization
from serverware import authority_current_root_computation as computation
from serverware import authority_current_root_journal as journal
from serverware.authority_current_root_decisions import MAX_RECEIPT_BYTES


OPERATION = "webauthn.registration.evidence.admit"
RECORD_SCHEMA = "serverware.registrationExecutionReservationRecord/v1"
RECORD_IDENTITY_DOMAIN = "serverware.registrationExecutionReservationRecordIdentity/v1"
_FINALIZATION_OPERATION = "webauthn.registration.finalize"
_FINALIZATION_SCHEMA = "serverware.registrationFinalizationReservationRecord/v1"
_FINALIZATION_IDENTITY_DOMAIN = "serverware.registrationFinalizationReservationRecordIdentity/v1"
MAX_REQUEST_BYTES = authorization.MAX_BYTES
MAX_SNAPSHOT_BYTES = computation.MAX_SNAPSHOT_BYTES
MAX_BYTES = journal.MAX_RECORD_BYTES
MAX_NODES = 32
MAX_DEPTH = 2
REQUEST_FIELDS = frozenset({"schema", "kind", "enrollmentDigest", "sequence",
    "previousRecordDigest", "predecessorSequence", "predecessorHeadDigest", "fence",
    "executionRecordDigest", "requestBase64Url", "snapshotBase64Url"})
ACK_FIELDS = REQUEST_FIELDS | frozenset({"receiptBase64Url"})
_SNAPSHOT_JOINS = ("sourceRevision", "enrollmentDigest", "databaseId", "generationDigest",
    "producerMeasurementDigest", "operation", "requestDigest", "operationId", "capabilityDigest")
_ACK_JOINS = ("sourceRevision", "action", "enrollmentDigest", "databaseId", "generationDigest",
    "fence", "issuedAtEpochNs", "expiresAtEpochNs")


class RegistrationReservationRecordError(ValueError):
    pass


def _profile(profile):
    """Only two source-fixed private profiles; never a supplied codec/operation."""
    if type(profile) is not int or profile not in (0, 1):
        raise RegistrationReservationRecordError("reservation record profile is not source fixed")
    return ((OPERATION, RECORD_SCHEMA, RECORD_IDENTITY_DOMAIN) if profile == 0 else
        (_FINALIZATION_OPERATION, _FINALIZATION_SCHEMA, _FINALIZATION_IDENTITY_DOMAIN))


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _ReservationRecord:
    kind: str
    enrollment_digest: str
    sequence: int
    previous_record_digest: str | None
    predecessor_sequence: int
    predecessor_head_digest: str
    fence: int
    execution_record_digest: str
    request_bytes: bytes
    snapshot_bytes: bytes
    receipt_bytes: bytes | None
    request_payload: dict
    request_digest: str
    receipt_payload: dict | None
    receipt_digest: str | None
    record_digest: str


def _original(value, maximum, label):
    return authorization._original(value, maximum, label)


def _predecessor_scope(sequence, head, fence):
    # A reserve must leave space for both its pending decision and completion.
    authorization.shape._integer(sequence, authorization.MAX_RECORDS - 2, minimum=0)
    authorization.shape._digest(head)
    authorization.shape._integer(fence, minimum=1)
    return sequence, head, fence


def _local_scope(sequence, previous):
    authorization.shape._integer(sequence, journal.MAX_RECORDS, minimum=1)
    if sequence == 1:
        if previous is not None:
            raise RegistrationReservationRecordError("first reservation record must have a null predecessor")
    else:
        authorization.shape._digest(previous)
    return sequence, previous


def _verify_on_work(*, request_bytes, snapshot_bytes, receipt_bytes, enrollment_bytes,
        root_public_key, expected_predecessor_sequence, expected_predecessor_head_digest,
        expected_fence, work):
    return _verify_profile_on_work(0, request_bytes=request_bytes, snapshot_bytes=snapshot_bytes,
        receipt_bytes=receipt_bytes, enrollment_bytes=enrollment_bytes, root_public_key=root_public_key,
        expected_predecessor_sequence=expected_predecessor_sequence,
        expected_predecessor_head_digest=expected_predecessor_head_digest, expected_fence=expected_fence,
        work=work)


def _verify_profile_on_work(profile, *, request_bytes, snapshot_bytes, receipt_bytes, enrollment_bytes,
        root_public_key, expected_predecessor_sequence, expected_predecessor_head_digest,
        expected_fence, work):
    """Authenticate owned originals, without supplying a current-state claim."""
    operation, _schema, _domain = _profile(profile)
    held_request = _original(request_bytes, MAX_REQUEST_BYTES, "reservation request")
    held_snapshot = _original(snapshot_bytes, MAX_SNAPSHOT_BYTES, "reservation snapshot")
    held_receipt = None if receipt_bytes is None else _original(
        receipt_bytes, MAX_RECEIPT_BYTES, "reservation receipt")
    held_enrollment = _original(enrollment_bytes, authorization.MAX_ENROLLMENT_BYTES,
        "reservation enrollment")
    held_key = root_public_key
    predecessor, head, fence = _predecessor_scope(expected_predecessor_sequence,
        expected_predecessor_head_digest, expected_fence)
    authorization._public(held_key)
    material, request, request_digest = authorization._verify_historical_request_on_work(
        request_bytes=held_request, enrollment_bytes=held_enrollment,
        root_public_key=held_key, work=work)
    if request["action"] != "reserve" or request["operation"] != operation:
        raise RegistrationReservationRecordError("reservation record requires the fixed registration reserve")
    if predecessor + 2 > material.payload["maxRecords"]:
        raise RegistrationReservationRecordError("reservation predecessor leaves no enrolled completion capacity")
    for name, expected in (("predecessorSequence", predecessor),
            ("predecessorHeadDigest", head), ("fence", fence)):
        authorization.plan._same(request[name], expected, work,
            "reservation independently admitted " + name)

    snapshot = computation._decode_snapshot_on_work(held_snapshot, work=work)
    # The actual decoder established canonical originals; frame those bytes
    # using the producer's domain rather than decoding or reserializing again.
    snapshot_digest = authorization.plan._frame(computation.SNAPSHOT_DOMAIN, (held_snapshot,), work)
    authorization.plan._same(request["snapshotDigest"], snapshot_digest, work,
        "reservation original computation snapshot")
    for name in _SNAPSHOT_JOINS:
        authorization.plan._same(snapshot[name], request[name], work,
            "reservation snapshot " + name)
    vector_digests = {}
    for name in ("beforeVector", "afterVector"):
        original_vector = authorization.vector._encode_on_work(request[name], work=work)
        actual = authorization.vector._digest_on_work(original_vector, work=work)
        vector_digests[name + "Digest"] = actual
        authorization.plan._same(snapshot[name + "Digest"], actual, work,
            "reservation snapshot " + name)
    if (request["issuedAtEpochNs"] < snapshot["originalIssuedAtEpochNs"]
            or request["expiresAtEpochNs"] > snapshot["originalExpiresAtEpochNs"]):
        raise RegistrationReservationRecordError("reservation interval exceeds the original plan interval")

    if held_receipt is None:
        return request, request_digest, None, None
    receipt = authorization._verify_receipt_on_work(receipt_bytes=held_receipt,
        enrollment_bytes=held_enrollment, root_public_key=held_key, work=work)
    for name in _ACK_JOINS:
        authorization.plan._same(receipt[name], request[name], work,
            "reservation receipt " + name)
    for name, expected in (("requestDigest", request_digest),
            ("pendingRequestDigest", request_digest), ("sequence", predecessor + 1),
            ("previousHeadDigest", head), *vector_digests.items()):
        authorization.plan._same(receipt[name], expected, work,
            "reservation receipt original " + name)
    receipt_digest = authorization.plan._frame(authorization.RECEIPT_IDENTITY_DOMAIN,
        (held_receipt,), work)
    return request, request_digest, receipt, receipt_digest


def _base64_count(value, maximum):
    if type(value) is not str or not 3 <= len(value) <= (4 * maximum + 2) // 3:
        raise RegistrationReservationRecordError("reservation original transport exceeds its encoded bound")
    count = 3 * len(value) // 4
    authorization.transport._transport_shape(value, count, maximum)
    return count


def _shape(document, *, profile=0):
    _operation, schema, _domain = _profile(profile)
    if type(document) is not dict or len(document) not in (len(REQUEST_FIELDS), len(ACK_FIELDS)):
        raise RegistrationReservationRecordError("reservation record is not a closed object")
    kind = document.get("kind")
    if type(kind) is not str or kind not in ("request", "ack"):
        raise RegistrationReservationRecordError("reservation record kind is not source fixed")
    authorization.shape._object(document, REQUEST_FIELDS if kind == "request" else ACK_FIELDS,
        "registration reservation record")
    authorization.shape._literal(document["schema"], schema)
    authorization.shape._digest(document["enrollmentDigest"])
    authorization.shape._digest(document["executionRecordDigest"])
    _local_scope(document["sequence"], document["previousRecordDigest"])
    _predecessor_scope(document["predecessorSequence"], document["predecessorHeadDigest"], document["fence"])
    _base64_count(document["requestBase64Url"], MAX_REQUEST_BYTES)
    _base64_count(document["snapshotBase64Url"], MAX_SNAPSHOT_BYTES)
    if kind == "ack":
        _base64_count(document["receiptBase64Url"], MAX_RECEIPT_BYTES)


def _read(record_bytes, work, *, profile=0):
    held = _original(record_bytes, MAX_BYTES, "reservation record")
    document = authorization.wire._decode_object(held, work=work,
        maximum_bytes=MAX_BYTES, maximum_nodes=MAX_NODES, maximum_depth=MAX_DEPTH)
    _shape(document, profile=profile)
    authorization.capability._canonical(held, document,
        authorization.capture._SharedLedger(work), MAX_BYTES, MAX_NODES)
    request = authorization.transport._decode(document["requestBase64Url"],
        _base64_count(document["requestBase64Url"], MAX_REQUEST_BYTES), MAX_REQUEST_BYTES, work)
    snapshot = authorization.transport._decode(document["snapshotBase64Url"],
        _base64_count(document["snapshotBase64Url"], MAX_SNAPSHOT_BYTES), MAX_SNAPSHOT_BYTES, work)
    receipt = None
    if document["kind"] == "ack":
        receipt = authorization.transport._decode(document["receiptBase64Url"],
            _base64_count(document["receiptBase64Url"], MAX_RECEIPT_BYTES), MAX_RECEIPT_BYTES, work)
    return document, request, snapshot, receipt


def _record(document, original, request_bytes, snapshot_bytes, receipt_bytes,
        request_payload, request_digest, receipt_payload, receipt_digest, work, *, profile=0):
    _operation, _schema, domain = _profile(profile)
    return _ReservationRecord(document["kind"], document["enrollmentDigest"], document["sequence"],
        document["previousRecordDigest"], document["predecessorSequence"], document["predecessorHeadDigest"],
        document["fence"], document["executionRecordDigest"], request_bytes, snapshot_bytes, receipt_bytes,
        request_payload, request_digest, receipt_payload, receipt_digest,
        authorization.plan._frame(domain, (original,), work))


def _decode_on_work(record_bytes, *, enrollment_bytes, root_public_key, work):
    return _decode_profile_on_work(0, record_bytes, enrollment_bytes=enrollment_bytes,
        root_public_key=root_public_key, work=work)


def _decode_profile_on_work(profile, record_bytes, *, enrollment_bytes, root_public_key, work):
    """Authenticate originals; the owner separately admits the local chain."""
    _profile(profile)
    held_record = _original(record_bytes, MAX_BYTES, "reservation record")
    held_enrollment = _original(enrollment_bytes, authorization.MAX_ENROLLMENT_BYTES,
        "reservation enrollment")
    held_key = root_public_key
    authorization._public(held_key)
    document, request, snapshot, receipt = _read(held_record, work, profile=profile)
    payload, digest, receipt_payload, receipt_digest = _verify_profile_on_work(profile,
        request_bytes=request, snapshot_bytes=snapshot, receipt_bytes=receipt,
        enrollment_bytes=held_enrollment, root_public_key=held_key,
        expected_predecessor_sequence=document["predecessorSequence"],
        expected_predecessor_head_digest=document["predecessorHeadDigest"],
        expected_fence=document["fence"], work=work)
    authorization.plan._same(document["enrollmentDigest"], payload["enrollmentDigest"], work,
        "reservation record original enrollment")
    return _record(document, held_record, request, snapshot, receipt, payload, digest,
        receipt_payload, receipt_digest, work, profile=profile)


def _prepare(*, kind, sequence, previous_record_digest, expected_predecessor_sequence,
        expected_predecessor_head_digest, expected_fence, execution_record_digest,
        request_bytes, snapshot_bytes, receipt_bytes, enrollment_bytes, root_public_key, work, _profile_id=0):
    _operation, schema, _domain = _profile(_profile_id)
    local_sequence, previous = _local_scope(sequence, previous_record_digest)
    predecessor, head, fence = _predecessor_scope(expected_predecessor_sequence,
        expected_predecessor_head_digest, expected_fence)
    authorization.shape._digest(execution_record_digest)
    local_execution = execution_record_digest
    request = _original(request_bytes, MAX_REQUEST_BYTES, "reservation request")
    snapshot = _original(snapshot_bytes, MAX_SNAPSHOT_BYTES, "reservation snapshot")
    receipt = None if kind == "request" else _original(receipt_bytes,
        MAX_RECEIPT_BYTES, "reservation receipt")
    enrollment = _original(enrollment_bytes, authorization.MAX_ENROLLMENT_BYTES,
        "reservation enrollment")
    held_key = root_public_key
    payload, digest, receipt_payload, receipt_digest = _verify_profile_on_work(_profile_id,
        request_bytes=request, snapshot_bytes=snapshot, receipt_bytes=receipt,
        enrollment_bytes=enrollment, root_public_key=held_key,
        expected_predecessor_sequence=predecessor, expected_predecessor_head_digest=head,
        expected_fence=fence, work=work)
    document = {"schema": schema, "kind": kind,
        "enrollmentDigest": payload["enrollmentDigest"], "sequence": local_sequence,
        "previousRecordDigest": previous, "predecessorSequence": predecessor,
        "predecessorHeadDigest": head, "fence": fence, "executionRecordDigest": local_execution,
        "requestBase64Url": authorization.transport._encode(request, work),
        "snapshotBase64Url": authorization.transport._encode(snapshot, work)}
    if kind == "ack":
        document["receiptBase64Url"] = authorization.transport._encode(receipt, work)
    _shape(document, profile=_profile_id)
    original = authorization.capability._wire(document,
        authorization.capture._SharedLedger(work), MAX_BYTES, MAX_NODES)
    return original, _record(document, original, request, snapshot, receipt,
        payload, digest, receipt_payload, receipt_digest, work, profile=_profile_id)


def _prepare_request_on_work(*, sequence, previous_record_digest, expected_predecessor_sequence,
        expected_predecessor_head_digest, expected_fence, execution_record_digest,
        request_bytes, snapshot_bytes, enrollment_bytes, root_public_key, work):
    """Return canonical request bytes and observations for durable enqueue."""
    return _prepare(kind="request", sequence=sequence, previous_record_digest=previous_record_digest,
        expected_predecessor_sequence=expected_predecessor_sequence,
        expected_predecessor_head_digest=expected_predecessor_head_digest,
        expected_fence=expected_fence, execution_record_digest=execution_record_digest,
        request_bytes=request_bytes, snapshot_bytes=snapshot_bytes, receipt_bytes=None,
        enrollment_bytes=enrollment_bytes, root_public_key=root_public_key, work=work)


def _prepare_ack_on_work(*, sequence, previous_record_digest, expected_predecessor_sequence,
        expected_predecessor_head_digest, expected_fence, execution_record_digest,
        request_bytes, snapshot_bytes, receipt_bytes, enrollment_bytes, root_public_key, work):
    """Return authenticated acknowledgment originals; publication is separate."""
    return _prepare(kind="ack", sequence=sequence, previous_record_digest=previous_record_digest,
        expected_predecessor_sequence=expected_predecessor_sequence,
        expected_predecessor_head_digest=expected_predecessor_head_digest,
        expected_fence=expected_fence, execution_record_digest=execution_record_digest,
        request_bytes=request_bytes, snapshot_bytes=snapshot_bytes, receipt_bytes=receipt_bytes,
        enrollment_bytes=enrollment_bytes, root_public_key=root_public_key, work=work)
