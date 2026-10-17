"""Fixed activation-only original reserve/snapshot/ack local record profile.

The actual shared codec verifies original enrolled reserve and receipt
signatures, canonical snapshots and independently supplied predecessor scope.
This third source-fixed schema/domain does not admit a caller-selected operation.
It receives no encrypted bundle, AES key or grant original: executionRecordDigest
is only an opaque local association, never grant, custody or currentness proof.
No clock, signing, I/O or new work allowance is introduced here.
"""
from __future__ import annotations

from catchplate import authority_registration_reservation_records as shared


OPERATION = "oidc.session.activate"
RECORD_SCHEMA = "catchplate.oidcSessionActivationReservationRecord/v1"
RECORD_IDENTITY_DOMAIN = "catchplate.oidcSessionActivationReservationRecordIdentity/v1"
MAX_REQUEST_BYTES = shared.MAX_REQUEST_BYTES
MAX_SNAPSHOT_BYTES = shared.MAX_SNAPSHOT_BYTES
MAX_RECEIPT_BYTES = shared.MAX_RECEIPT_BYTES
MAX_BYTES, MAX_NODES, MAX_DEPTH = shared.MAX_BYTES, shared.MAX_NODES, shared.MAX_DEPTH
REQUEST_FIELDS, ACK_FIELDS = shared.REQUEST_FIELDS, shared.ACK_FIELDS
OidcSessionActivationReservationRecordError = shared.RegistrationReservationRecordError
_predecessor_scope = shared._predecessor_scope


def _verify_on_work(*, request_bytes, snapshot_bytes, receipt_bytes, enrollment_bytes,
        root_public_key, expected_predecessor_sequence, expected_predecessor_head_digest,
        expected_fence, work):
    return shared._verify_profile_on_work(2, request_bytes=request_bytes, snapshot_bytes=snapshot_bytes,
        receipt_bytes=receipt_bytes, enrollment_bytes=enrollment_bytes, root_public_key=root_public_key,
        expected_predecessor_sequence=expected_predecessor_sequence,
        expected_predecessor_head_digest=expected_predecessor_head_digest,
        expected_fence=expected_fence, work=work)


def _decode_on_work(record_bytes, *, enrollment_bytes, root_public_key, work):
    return shared._decode_profile_on_work(2, record_bytes, enrollment_bytes=enrollment_bytes,
        root_public_key=root_public_key, work=work)


def _prepare_request_on_work(*, sequence, previous_record_digest, expected_predecessor_sequence,
        expected_predecessor_head_digest, expected_fence, execution_record_digest,
        request_bytes, snapshot_bytes, enrollment_bytes, root_public_key, work):
    return shared._prepare(_profile_id=2, kind="request", sequence=sequence,
        previous_record_digest=previous_record_digest,
        expected_predecessor_sequence=expected_predecessor_sequence,
        expected_predecessor_head_digest=expected_predecessor_head_digest,
        expected_fence=expected_fence, execution_record_digest=execution_record_digest,
        request_bytes=request_bytes, snapshot_bytes=snapshot_bytes, receipt_bytes=None,
        enrollment_bytes=enrollment_bytes, root_public_key=root_public_key, work=work)


def _prepare_ack_on_work(*, sequence, previous_record_digest, expected_predecessor_sequence,
        expected_predecessor_head_digest, expected_fence, execution_record_digest,
        request_bytes, snapshot_bytes, receipt_bytes, enrollment_bytes, root_public_key, work):
    return shared._prepare(_profile_id=2, kind="ack", sequence=sequence,
        previous_record_digest=previous_record_digest,
        expected_predecessor_sequence=expected_predecessor_sequence,
        expected_predecessor_head_digest=expected_predecessor_head_digest,
        expected_fence=expected_fence, execution_record_digest=execution_record_digest,
        request_bytes=request_bytes, snapshot_bytes=snapshot_bytes, receipt_bytes=receipt_bytes,
        enrollment_bytes=enrollment_bytes, root_public_key=root_public_key, work=work)
