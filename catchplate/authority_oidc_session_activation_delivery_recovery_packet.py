"""Consume-only original packet decoding, never historical admission.

Independently expected packet and pending IDs are held before decoding. The
neutral outer schema retains a distinct closed nine-field consume inventory.
All raw frame bounds precede decoded-body allocation. No signatures, clocks,
decryption, SQL, permission, commit or successful-result authority are supplied.
"""
from __future__ import annotations

from dataclasses import dataclass

from catchplate import authority_oidc_session_activation_delivery_execution_packet as producer
from catchplate import authority_successor_execution_recovery_packet as neutral


authority, authorization, vector = neutral.authority, neutral.authorization, neutral.vector
SCHEMA, IDENTITY_DOMAIN = neutral.SCHEMA, neutral.IDENTITY_DOMAIN
MAX_BYTES, MAX_NODES, MAX_DEPTH = neutral.MAX_BYTES, neutral.MAX_NODES, neutral.MAX_DEPTH
OPERATION = "oidc.session.activation-delivery.consume"
ORIGINAL_FIELDS = frozenset({"currentRootEnrollment", "grantEnrollment", "grant",
    "reserveRequest", "reserveReceipt", "computationSnapshot", "callerEnrollment",
    "callerAuthorization", "plan"})
_CONTROL_FIELDS = ("currentRootEnrollment", "grantEnrollment", "grant", "reserveRequest",
    "reserveReceipt", "computationSnapshot", "callerEnrollment", "callerAuthorization")


class DeliveryRecoveryPacketError(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _RecoveryDeliveryPacket:
    """Detached ordinary data and original bytes, not a proof carrier."""

    payload: dict
    originals: tuple[bytes, ...]
    enrollment_bytes: bytes
    grant_enrollment_bytes: bytes
    grant_bytes: bytes
    reserve_request_bytes: bytes
    reserve_receipt_bytes: bytes
    snapshot_bytes: bytes
    authorization_enrollment_bytes: bytes
    authorization_bytes: bytes


def _packet_shape(payload, expected_pending, work):
    if (producer.OPERATION != OPERATION or producer.ORIGINAL_FIELDS != ORIGINAL_FIELDS
            or tuple(name for name, _maximum in producer.CONTROL_MAXIMA) != _CONTROL_FIELDS
            or len(producer.grants.FRAME_MAXIMA) != 2 or MAX_BYTES != producer.MAX_BYTES
            or MAX_BYTES != 64 * 1024 * 1024):
        raise DeliveryRecoveryPacketError("consume recovery source inventory changed")
    vector._closed(payload, producer.packet.PACKET_FIELDS, "consume recovery packet")
    authorization.shape._literal(payload["schema"], SCHEMA)
    authorization.shape._literal(payload["sourceRevision"], authority.SOURCE_REVISION)
    authorization.shape._literal(payload["operation"], OPERATION)
    spec = authority.operation_spec(OPERATION)
    for name in ("authorizationDigest", "requestDigest", "operationId"):
        authorization.shape._digest(payload[name])
    for name in ("issuedAtEpochNs", "expiresAtEpochNs"):
        authorization.shape._integer(payload[name], minimum=1)
    if payload["expiresAtEpochNs"] <= payload["issuedAtEpochNs"]:
        raise DeliveryRecoveryPacketError("consume recovery original interval is empty")
    neutral._effect_shape(payload["selectedRows"], payload["mutations"], payload["workUnits"], spec=spec)
    neutral._bound(payload["selectedRows"], authority.MAX_PLAN_SELECTED_BYTES, MAX_NODES, work)
    neutral._bound(payload["mutations"], authority.MAX_RESULT_BYTES, MAX_NODES, work)
    neutral._bound(payload["result"], authority.MAX_RESULT_BYTES, MAX_NODES, work)
    for name in ("beforeVector", "afterVector"):
        vector._shape(payload[name])
        neutral._bound(payload[name], vector.MAX_BYTES, vector.MAX_NODES, work)
    marker = payload["marker"]
    vector._closed(marker, frozenset(authority.CURRENT_ROOT_COMMIT_MARKER_COLUMNS), "consume recovery marker")
    authorization.shape._literal(marker["source_revision"], authority.SOURCE_REVISION)
    authorization._token(marker["database_id"])
    for name in neutral._MARKER_DIGESTS:
        authorization.shape._digest(marker[name])
    authorization.shape._integer(marker["pending_sequence"], authorization.MAX_RECORDS - 1, minimum=1)
    authorization.shape._integer(marker["predecessor_sequence"], authorization.MAX_RECORDS - 2)
    authorization.shape._integer(marker["fence"], minimum=1)
    if marker["pending_sequence"] != marker["predecessor_sequence"] + 1:
        raise DeliveryRecoveryPacketError("consume recovery predecessor is not adjacent")
    for actual, expected in ((marker["pending_decision_digest"], expected_pending),
            (marker["operation"], OPERATION), (marker["request_digest"], payload["requestDigest"]),
            (marker["operation_id"], payload["operationId"])):
        neutral._same(actual, expected, work, "consume recovery marker differs from held packet scope")
    neutral._bound(marker, 4096, 64, work)
    inventory = payload["originals"]
    vector._closed(inventory, ORIGINAL_FIELDS, "consume recovery originals")
    plans = inventory["plan"]
    if type(plans) is not list or len(plans) != 2:
        raise DeliveryRecoveryPacketError("consume recovery requires exactly plan and ciphertext")
    # The entire original inventory is checked before allocating any decoded
    # control or plan body. Each real codec also reserves its decoding work.
    total = 0
    for name, maximum in producer.CONTROL_MAXIMA:
        neutral._frame_shape(inventory[name], maximum)
        total += inventory[name]["byteCount"]
    for frame, maximum in zip(plans, producer.grants.FRAME_MAXIMA):
        neutral._frame_shape(frame, maximum)
        total += frame["byteCount"]
    if (plans[1]["byteCount"] < producer.grants.bundle.OVERHEAD_BYTES + 2
            or total > MAX_BYTES):
        raise DeliveryRecoveryPacketError("consume recovery original inventory exceeds fixed bounds")


def _decode_on_work(packet_bytes, *, expected_packet_digest, expected_pending_decision_digest, work):
    """Decode independently identified data on the caller's existing work."""
    ledger = vector.capture._SharedLedger(work)
    original = authorization._original(packet_bytes, MAX_BYTES, "retained consume custody packet")
    held_digest, held_pending = expected_packet_digest, expected_pending_decision_digest
    authorization.shape._digest(held_digest)
    authorization.shape._digest(held_pending)
    actual_digest = vector.framing._frame(IDENTITY_DOMAIN, (original,), work)
    neutral._same(actual_digest, held_digest, work, "consume recovery packet differs from independent identity")
    payload = vector.wire._decode_object(original, work=work,
        maximum_bytes=MAX_BYTES, maximum_nodes=MAX_NODES, maximum_depth=MAX_DEPTH)
    authorization.capability._canonical(original, payload, ledger, MAX_BYTES, MAX_NODES)
    _packet_shape(payload, held_pending, work)
    inventory = payload["originals"]
    controls = tuple(neutral._decode_frame(inventory[name], maximum, work)
        for name, maximum in producer.CONTROL_MAXIMA)
    originals = tuple(neutral._decode_frame(frame, maximum, work)
        for frame, maximum in zip(inventory["plan"], producer.grants.FRAME_MAXIMA))
    producer.grants.bundle._bounded_frame(originals[1])
    return _RecoveryDeliveryPacket(payload, originals, *controls)
