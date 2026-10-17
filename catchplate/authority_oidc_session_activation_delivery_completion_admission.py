"""Consume originals into non-executable, independently scoped completion facts.

Original execution intervals are historical data, never current clock samples.
The dedicated completion custodian authenticates caller/grant/private consume
history once. This adapter joins actual reserve/ACK, reconstructed computation,
effects and marker to independent pending pins. No successful carrier is an
accepted input, and no executable rows or token bytes leave this entrypoint.
"""
from __future__ import annotations

from dataclasses import dataclass

from catchplate import authority_current_root_execution_admission as pending
from catchplate import authority_oidc_session_activation_delivery_computation as computation
from catchplate import authority_oidc_session_activation_delivery_execution_authorization as caller
from catchplate import authority_oidc_session_activation_delivery_execution_enrollment as enrollments
from catchplate import authority_oidc_session_activation_delivery_execution_expectations as expectations_wire
from catchplate import authority_oidc_session_activation_delivery_execution_grant as grants
from catchplate import authority_oidc_session_activation_delivery_history_exchange as exchange
from catchplate import authority_oidc_session_activation_delivery_reservation_records as records
from catchplate import authority_successor_execution_recovery_packet as recovery
from catchplate import oidc_session_activation_delivery as delivery


authorization, vector, evidence, clock = pending.authorization, pending.vector, pending.evidence, pending.clock
OPERATION = computation.OPERATION
MAX_ORIGINAL_BYTES = grants.MAX_ORIGINAL_BYTES
_SNAPSHOT_JOINS = ("sourceRevision", "databaseId", "generationDigest", "operation",
    "requestDigest", "operationId", "retainedRecordDigest", "planDigest", "beforeVectorDigest",
    "afterVectorDigest", "resultDigest", "originalFrames", "originalIssuedAtEpochNs", "originalExpiresAtEpochNs")


class DeliveryCompletionAdmissionError(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _AdmittedCompletion:
    """Same-call private suffix; no API accepts this object as authority."""

    candidate: pending._PendingCompletion
    effects_digest: str
    authorization_digest: str
    live: object
    activation_request_digest: str
    activation_delivery_id: str
    activation_delivery_scope_digest: str
    activation_delivery_envelope_digest: str


def _admit_on_work(*, originals, expectations, planner_public_key,
        operation_public_key, enrollment_bytes, root_public_key, reserve_request_bytes,
        reserve_receipt_bytes, snapshot_bytes, expected_database_id, expected_generation_digest,
        expected_pending_sequence, expected_pending_head_digest, expected_fence,
        authorization_bytes, authorization_enrollment_bytes, grant_bytes,
        grant_enrollment_bytes, configuration_digest, historical_custody,
        live_window, transport_deadline_ns, work):
    """Authenticate genuine history once; return only pending facts/effects ID."""
    from catchplate import authority_oidc_session_activation_delivery_completion_custody as custody

    evidence.capture._SharedLedger(work)
    owner_type = custody.OidcSessionActivationDeliveryCompletionCustody
    owner = historical_custody
    if type(owner) is not owner_type:
        raise DeliveryCompletionAdmissionError("consume completion requires its actual historical custodian")
    if type(originals) is not tuple or len(originals) != 2:
        raise DeliveryCompletionAdmissionError("consume completion requires original plan/ciphertext raw2")
    raw2 = tuple(authorization._original(raw, maximum, "historical consume plan original")
        for raw, maximum in zip(originals, grants.FRAME_MAXIMA))
    enrollment = authorization._original(enrollment_bytes, authorization.MAX_ENROLLMENT_BYTES,
        "historical consume state enrollment")
    reserve = authorization._original(reserve_request_bytes, records.MAX_REQUEST_BYTES, "historical consume reserve")
    receipt_raw = authorization._original(reserve_receipt_bytes, records.MAX_RECEIPT_BYTES, "historical consume ACK")
    snapshot_raw = authorization._original(snapshot_bytes, computation.MAX_SNAPSHOT_BYTES, "historical consume snapshot")
    caller_raw = authorization._original(authorization_bytes, caller.MAX_AUTHORIZATION_BYTES, "historical consume caller")
    caller_enrollment = authorization._original(authorization_enrollment_bytes,
        caller.MAX_ENROLLMENT_BYTES, "historical consume caller enrollment")
    grant_raw = authorization._original(grant_bytes, grants.MAX_GRANT_BYTES, "historical consume grant")
    grant_enrollment = authorization._original(grant_enrollment_bytes,
        enrollments.MAX_ENROLLMENT_BYTES, "historical consume grant enrollment")
    if sum(map(len, (*raw2, enrollment, reserve, receipt_raw, snapshot_raw, caller_raw,
            caller_enrollment, grant_raw, grant_enrollment))) > MAX_ORIGINAL_BYTES:
        raise DeliveryCompletionAdmissionError("consume completion original aggregate exceeds source bound")
    root, planner, operation_key, config = root_public_key, planner_public_key, operation_public_key, configuration_digest
    for key in (root, planner, operation_key):
        authorization._public(key)
    authorization.shape._digest(config)
    authorization.shape._integer(transport_deadline_ns, minimum=1)
    scope = pending._scope(expected_database_id=expected_database_id,
        expected_generation_digest=expected_generation_digest, expected_pending_sequence=expected_pending_sequence,
        expected_pending_head_digest=expected_pending_head_digest, expected_fence=expected_fence,
        live_window=live_window, transport_deadline_ns=transport_deadline_ns)
    window, inherited = scope[5:]
    bound = min(window[4], inherited)
    expected = expectations_wire._capture_on_work(expectations, work=work)
    evidence.plan._same(expected["scope"]["configurationDigest"], config, work,
        "consume completion independent configuration")
    _window, processing = delivery._window(window, bound, work)
    verified = None

    def live():
        first = processing()
        if verified is not None:
            joined = verified.live()
            finished = processing()
            if not first <= joined <= finished:
                raise DeliveryCompletionAdmissionError("consume completion processing reversed across history")
            return finished
        return first

    live()
    owner_type.require_completion_on_work(owner, work=work)
    owner_type.bind_context_on_work(owner, root_public_key=root,
        current_root_enrollment_bytes=enrollment, work=work)
    live()
    material, request, request_digest = authorization._verify_historical_request_on_work(
        request_bytes=reserve, enrollment_bytes=enrollment, root_public_key=root, work=work)
    for actual, wanted in ((request["action"], "reserve"), (request["operation"], OPERATION)):
        evidence.plan._same(actual, wanted, work, "consume historical reserve purpose")
    live()
    receipt = authorization._verify_receipt_on_work(receipt_bytes=receipt_raw,
        enrollment_bytes=enrollment, root_public_key=root, work=work)
    receipt_digest = authorization._receipt_digest_on_work(receipt_raw, work)
    pending._pending(material, request, request_digest, receipt, receipt_digest, scope, work)
    before = vector._encode_on_work(request["beforeVector"], work=work)
    live()
    verified = owner_type.verify_exchange_on_work(owner, originals=raw2,
        expectations=expected, before_vector_bytes=before, authorization_bytes=caller_raw,
        grant_bytes=grant_raw, authorization_enrollment_bytes=caller_enrollment,
        grant_enrollment_bytes=grant_enrollment, current_root_enrollment_bytes=enrollment,
        root_public_key=root, planner_public_key=planner, operation_public_key=operation_key,
        configuration_digest=config, live_window=window, transport_deadline_ns=bound, work=work)
    if type(verified) is not exchange._HistoricalExchange:
        raise DeliveryCompletionAdmissionError("consume completion requires actual same-call historical exchange")
    live()
    replayed = verified.replayed
    for actual, wanted in ((verified.database_id, scope[0]), (verified.generation_digest, scope[1]),
            (replayed.operation, OPERATION), (request["capabilityDigest"], verified.grant_digest)):
        evidence.plan._same(actual, wanted, work, "consume completion independent original scope")
    for field in ("operation", "requestDigest", "operationId"):
        evidence.plan._same(request[field], replayed.request[field], work,
            "consume historical reserve differs from genuine typed request")
    if (request["issuedAtEpochNs"] != replayed.original_interval[0]
            or request["expiresAtEpochNs"] > replayed.original_interval[1]):
        raise DeliveryCompletionAdmissionError("consume reserve retimes or renews its original plan")
    snapshot = computation._snapshot(replayed, material, verified.grant_digest, work)
    expected_snapshot = computation._snapshot_wire(snapshot, work)
    work.charge(input_bytes=len(expected_snapshot) + len(snapshot_raw))
    if expected_snapshot != snapshot_raw:
        raise DeliveryCompletionAdmissionError("consume snapshot differs from genuine historical replay")
    snapshot_digest = computation._snapshot_digest_on_work(snapshot_raw, work=work)
    evidence.plan._same(snapshot_digest, request["snapshotDigest"], work, "consume reserve snapshot identity")
    after = vector._encode_on_work(request["afterVector"], work=work)
    work.charge(input_bytes=len(before) + len(replayed.before_vector_bytes)
        + len(after) + len(replayed.after_vector_bytes))
    if before != replayed.before_vector_bytes or after != replayed.after_vector_bytes:
        raise DeliveryCompletionAdmissionError("consume historical reserve differs from actual complete roots")
    for field in ("beforeVectorDigest", "afterVectorDigest"):
        evidence.plan._same(receipt[field], snapshot[field], work, "consume ACK actual complete roots")
    live()
    # Already authenticated original control; this is bounded claim decoding,
    # not another signature/replay or a fabricated live clock.
    grant = grants._read_on_work(grant_raw, work)["payload"]
    evidence.plan._same(grant["currentRootEnrollmentDigest"], snapshot["enrollmentDigest"], work,
        "consume historical grant and computation enrollment")
    for field in _SNAPSHOT_JOINS:
        evidence.plan._same(grant[field], snapshot[field], work, "consume historical grant computation " + field)
    if (request["issuedAtEpochNs"] != grant["issuedAtEpochNs"]
            or request["expiresAtEpochNs"] > grant["expiresAtEpochNs"]):
        raise DeliveryCompletionAdmissionError("consume reserve extends original caller/grant authority")
    marker = pending._marker(material, request, request_digest, receipt, receipt_digest, snapshot, work)
    live()
    effects_digest = recovery._effects_digest_on_work(selected_rows=replayed.selected_rows,
        mutations=replayed.mutations, result=replayed.result, work_units=replayed.work_units, work=work)
    live()
    candidate = pending._PendingCompletion(OPERATION, marker, replayed.after_vector_bytes,
        reserve, receipt_raw, snapshot_raw, (request["issuedAtEpochNs"], request["expiresAtEpochNs"]))
    # These scalar identities come only from the same genuine historical
    # replay, never from a caller-supplied success object or truncated UUID.
    result = _AdmittedCompletion(candidate, effects_digest, verified.authorization_digest, live,
        replayed.activation_request_digest, replayed.activation_delivery_id,
        replayed.activation_delivery_scope_digest, replayed.activation_delivery_envelope_digest)
    live()
    return result
