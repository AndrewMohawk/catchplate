"""Fixed consume-only fourth durable reserve/snapshot/ACK record profile.

Authenticates originals and their local associations, never current pending
state, caller permission or the private consume proofs. No keys or plaintext
tokens are serialized. The dedicated delivery owner supplies durable ordering.
"""
from __future__ import annotations

from catchplate import authority_registration_reservation_records as shared


OPERATION = "oidc.session.activation-delivery.consume"
RECORD_SCHEMA = "catchplate.oidcSessionActivationDeliveryReservationRecord/v1"
RECORD_IDENTITY_DOMAIN = "catchplate.oidcSessionActivationDeliveryReservationRecordIdentity/v1"
MAX_REQUEST_BYTES = shared.MAX_REQUEST_BYTES
MAX_SNAPSHOT_BYTES = shared.MAX_SNAPSHOT_BYTES
MAX_RECEIPT_BYTES = shared.MAX_RECEIPT_BYTES
MAX_BYTES, MAX_NODES, MAX_DEPTH = shared.MAX_BYTES, shared.MAX_NODES, shared.MAX_DEPTH
REQUEST_FIELDS, ACK_FIELDS = shared.REQUEST_FIELDS, shared.ACK_FIELDS
OidcSessionActivationDeliveryReservationRecordError = shared.RegistrationReservationRecordError
_predecessor_scope = shared._predecessor_scope


def _verify_on_work(*, request_bytes, snapshot_bytes, receipt_bytes, enrollment_bytes,
        root_public_key, expected_predecessor_sequence, expected_predecessor_head_digest,
        expected_fence, work):
    return shared._verify_profile_on_work(3, request_bytes=request_bytes, snapshot_bytes=snapshot_bytes,
        receipt_bytes=receipt_bytes, enrollment_bytes=enrollment_bytes, root_public_key=root_public_key,
        expected_predecessor_sequence=expected_predecessor_sequence,
        expected_predecessor_head_digest=expected_predecessor_head_digest,
        expected_fence=expected_fence, work=work)


def _decode_on_work(record_bytes, *, enrollment_bytes, root_public_key, work):
    return shared._decode_profile_on_work(3, record_bytes, enrollment_bytes=enrollment_bytes,
        root_public_key=root_public_key, work=work)


def _prepare_request_on_work(*, sequence, previous_record_digest, expected_predecessor_sequence,
        expected_predecessor_head_digest, expected_fence, execution_record_digest,
        request_bytes, snapshot_bytes, enrollment_bytes, root_public_key, work):
    return shared._prepare(_profile_id=3, kind="request", sequence=sequence,
        previous_record_digest=previous_record_digest,
        expected_predecessor_sequence=expected_predecessor_sequence,
        expected_predecessor_head_digest=expected_predecessor_head_digest,
        expected_fence=expected_fence, execution_record_digest=execution_record_digest,
        request_bytes=request_bytes, snapshot_bytes=snapshot_bytes, receipt_bytes=None,
        enrollment_bytes=enrollment_bytes, root_public_key=root_public_key, work=work)


def _prepare_ack_on_work(*, sequence, previous_record_digest, expected_predecessor_sequence,
        expected_predecessor_head_digest, expected_fence, execution_record_digest,
        request_bytes, snapshot_bytes, receipt_bytes, enrollment_bytes, root_public_key, work):
    return shared._prepare(_profile_id=3, kind="ack", sequence=sequence,
        previous_record_digest=previous_record_digest,
        expected_predecessor_sequence=expected_predecessor_sequence,
        expected_predecessor_head_digest=expected_predecessor_head_digest,
        expected_fence=expected_fence, execution_record_digest=execution_record_digest,
        request_bytes=request_bytes, snapshot_bytes=snapshot_bytes, receipt_bytes=receipt_bytes,
        enrollment_bytes=enrollment_bytes, root_public_key=root_public_key, work=work)
