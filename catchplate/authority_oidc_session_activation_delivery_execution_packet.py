"""Fixed consume packet from genuine caller/grant/current-pending replay.

Only original-input admission reaches the private encoding suffix. The neutral
protected packet schema is retained, with a closed consume-specific original
inventory including its caller controls. Private raw2 contains signed plan and
ciphertext only; SQL never opens the bundle or receives plaintext tokens/keys.
This module does no I/O and accepts no successful candidate as authority.
"""
from __future__ import annotations

from dataclasses import dataclass

from catchplate import authority_oidc_session_activation_delivery_pending_admission as admission
from catchplate import authority_oidc_session_activation_delivery_computation as computation
from catchplate import authority_oidc_session_activation_delivery_execution_authorization as caller
from catchplate import authority_oidc_session_activation_delivery_execution_enrollment as enrollments
from catchplate import authority_oidc_session_activation_delivery_execution_grant as grants
from catchplate import authority_successor_execution_packet as packet


OPERATION = grants.OPERATION
MAX_BYTES = packet.MAX_BYTES
ORIGINAL_FIELDS = packet.ORIGINAL_FIELDS | frozenset({"callerEnrollment", "callerAuthorization"})
CONTROL_MAXIMA = (
    ("currentRootEnrollment", packet.authorization.MAX_ENROLLMENT_BYTES),
    ("grantEnrollment", enrollments.MAX_ENROLLMENT_BYTES),
    ("grant", grants.MAX_GRANT_BYTES),
    ("reserveRequest", packet.authorization.MAX_BYTES),
    ("reserveReceipt", admission.reservation.records.MAX_RECEIPT_BYTES),
    ("computationSnapshot", computation.MAX_SNAPSHOT_BYTES),
    ("callerEnrollment", caller.MAX_ENROLLMENT_BYTES),
    ("callerAuthorization", caller.MAX_AUTHORIZATION_BYTES),
)


class DeliveryExecutionPacketError(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _PreparedDelivery:
    packet_bytes: bytes
    packet_digest: str
    pending_decision_digest: str
    issued_at_epoch_ns: int
    expires_at_epoch_ns: int
    marker_expectation: dict
    live_window: tuple
    deadline_ns: int
    live: object


def _prepare_on_work(*, originals, expectations, before_vector_bytes, authorization_bytes,
        grant_bytes, response_originals, authorization_enrollment_bytes, grant_enrollment_bytes,
        current_root_enrollment_bytes, root_public_key, planner_public_key,
        operation_public_key, configuration_digest, expected_predecessor_sequence,
        expected_predecessor_head_digest, expected_database_id, expected_generation_digest,
        expected_pending_sequence, expected_pending_head_digest, expected_fence,
        receiving_custody, live_window, transport_deadline_ns, work):
    """Replay actual consume originals once, then encode only this invocation."""
    admitted = admission._admit_full_on_work(originals=originals, expectations=expectations,
        before_vector_bytes=before_vector_bytes, authorization_bytes=authorization_bytes,
        grant_bytes=grant_bytes, response_originals=response_originals,
        authorization_enrollment_bytes=authorization_enrollment_bytes,
        grant_enrollment_bytes=grant_enrollment_bytes,
        current_root_enrollment_bytes=current_root_enrollment_bytes, root_public_key=root_public_key,
        planner_public_key=planner_public_key, operation_public_key=operation_public_key,
        configuration_digest=configuration_digest, expected_predecessor_sequence=expected_predecessor_sequence,
        expected_predecessor_head_digest=expected_predecessor_head_digest,
        expected_database_id=expected_database_id, expected_generation_digest=expected_generation_digest,
        expected_pending_sequence=expected_pending_sequence, expected_pending_head_digest=expected_pending_head_digest,
        expected_fence=expected_fence, receiving_custody=receiving_custody,
        live_window=live_window, transport_deadline_ns=transport_deadline_ns, work=work)
    admitted.live()
    candidate = admitted.candidate
    spec = packet.authority.operation_spec(OPERATION)
    if (type(candidate) is not packet.pending._ExecutionCandidate or candidate.operation != OPERATION
            or type(candidate.selected_rows) is not tuple
            or len(candidate.selected_rows) > spec["maximumQueryRows"]
            or type(candidate.mutations) is not tuple
            or len(candidate.mutations) > spec["maximumMutations"]
            or len(admitted.control_originals) != len(CONTROL_MAXIMA)
            or len(admitted.plan_originals) != len(grants.FRAME_MAXIMA)):
        raise DeliveryExecutionPacketError("consume packet differs from its genuine fixed inventory")
    packet.authorization.shape._integer(candidate.work_units, spec["maximumWorkUnits"], minimum=1)
    work.prepare_copy(candidate.selected_rows)
    work.prepare_copy(candidate.mutations)
    owned = packet.vector.capture._JSONCapture(packet.vector.capture._SharedLedger(work),
        maximum_bytes=MAX_BYTES).visit({"selectedRows": list(candidate.selected_rows),
            "mutations": list(candidate.mutations), "result": candidate.result, "marker": candidate.marker})
    packet.vector._closed(owned["marker"], frozenset(packet.authority.CURRENT_ROOT_COMMIT_MARKER_COLUMNS),
        "consume custody marker")
    request_digest, operation_id = candidate.request["requestDigest"], candidate.request["operationId"]
    for name, expected in (("operation", OPERATION), ("request_digest", request_digest),
            ("operation_id", operation_id)):
        packet.vector.framing._same(owned["marker"][name], expected, work,
            "consume custody marker differs from actual replay")
    for value, maximum, nodes in ((owned["selectedRows"], packet.authority.MAX_PLAN_SELECTED_BYTES, packet.MAX_NODES),
            (owned["mutations"], MAX_BYTES, packet.MAX_NODES), (owned["result"], MAX_BYTES, packet.MAX_NODES),
            (owned["marker"], 4096, 64)):
        packet._component(value, maximum, nodes, work)
    before = packet.vector._decode_on_work(candidate.before_vector_bytes, work=work)
    after = packet.vector._decode_on_work(candidate.after_vector_bytes, work=work)
    controls = {name: packet._raw_frame(raw, maximum, work)
        for (name, maximum), raw in zip(CONTROL_MAXIMA, admitted.control_originals)}
    controls["plan"] = [packet._raw_frame(raw, maximum, work)
        for raw, maximum in zip(admitted.plan_originals, grants.FRAME_MAXIMA)]
    packet.vector._closed(controls, ORIGINAL_FIELDS, "consume custody originals")
    issued, expires = candidate.original_interval
    document = {"schema": packet.SCHEMA, "sourceRevision": packet.authority.SOURCE_REVISION,
        "authorizationDigest": admitted.authorization_digest, "operation": OPERATION,
        "requestDigest": request_digest, "operationId": operation_id,
        "issuedAtEpochNs": issued, "expiresAtEpochNs": expires,
        "selectedRows": owned["selectedRows"], "mutations": owned["mutations"],
        "workUnits": candidate.work_units, "result": owned["result"],
        "beforeVector": before, "afterVector": after, "marker": owned["marker"], "originals": controls}
    packet.vector._closed(document, packet.PACKET_FIELDS, "consume custody packet")
    admitted.live()
    encoded = packet.vector.encoding._bounded_wire(document, packet.vector.capture._SharedLedger(work),
        maximum_bytes=MAX_BYTES, maximum_nodes=packet.MAX_NODES)
    digest = packet.vector.framing._frame(packet.IDENTITY_DOMAIN, (encoded,), work)
    admitted.live()
    work.prepare_copy(owned["marker"])
    result = _PreparedDelivery(encoded, digest, owned["marker"]["pending_decision_digest"],
        issued, expires, owned["marker"].copy(), admitted.live_window, admitted.deadline_ns, admitted.live)
    admitted.live()
    return result
