"""Live consume reservation admission against independent current pending pins.

The genuine state ACK is checked against an independently supplied checkpoint,
never used to manufacture one. All caller/grant/plan/private originals are
replayed through the separately root-admitted SQL-issuer receiving owner. The
raw3 API remains unchanged. A private original-input suffix retains the actual
same-call candidate for dedicated protected custody insertion; no API accepts
that output as proof, SQL permission, retry or historical-expiry bypass.
"""
from __future__ import annotations

from dataclasses import dataclass

from catchplate import authority_current_root_execution_admission as pending
from catchplate import authority_oidc_session_activation_delivery_execution_custody as custody
from catchplate import authority_oidc_session_activation_delivery_reservation as reservation


OPERATION = custody.bootstrap.OPERATION


class DeliveryPendingAdmissionError(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _AdmittedDelivery:
    """Private same-call output; never accepted instead of original replay."""

    originals: tuple
    plan_originals: tuple
    control_originals: tuple
    authorization_digest: str
    candidate: object
    live_window: tuple
    deadline_ns: int
    live: object


def _admit_full_on_work(*, originals, expectations, before_vector_bytes, authorization_bytes,
        grant_bytes, response_originals, authorization_enrollment_bytes, grant_enrollment_bytes,
        current_root_enrollment_bytes, root_public_key, planner_public_key,
        operation_public_key, configuration_digest, expected_predecessor_sequence,
        expected_predecessor_head_digest, expected_database_id, expected_generation_digest,
        expected_pending_sequence, expected_pending_head_digest, expected_fence,
        receiving_custody, live_window, transport_deadline_ns, work):
    """Derive the genuine consume candidate once from independently pinned originals."""
    try:
        # All independent scalar expectations are exact immutable values held
        # before the reservation path captures graphs or invokes any callback.
        pending.evidence.capture._SharedLedger(work)
        pending.authorization.shape._integer(transport_deadline_ns, minimum=1)
        sequence, head, fence = reservation.records._predecessor_scope(
            expected_predecessor_sequence, expected_predecessor_head_digest, expected_fence)
        scope = pending._scope(expected_database_id=expected_database_id,
            expected_generation_digest=expected_generation_digest,
            expected_pending_sequence=expected_pending_sequence,
            expected_pending_head_digest=expected_pending_head_digest, expected_fence=fence,
            live_window=live_window, transport_deadline_ns=transport_deadline_ns)
        if scope[2] != sequence + 1:
            raise DeliveryPendingAdmissionError("consume predecessor and independent pending sequence disagree")
        returned = reservation._response_originals(response_originals)
        owner = receiving_custody
        pair, before, caller, grant, caller_enrollment, grant_enrollment, enrollment, total = (
            reservation._hold_originals(originals, before_vector_bytes, authorization_bytes,
                grant_bytes, authorization_enrollment_bytes, grant_enrollment_bytes,
                current_root_enrollment_bytes, owner))
        if total + sum(map(len, returned)) > reservation.grants.wire.MAX_ORIGINAL_BYTES:
            raise DeliveryPendingAdmissionError("consume pending originals exceed the aggregate source bound")
        owner_type = custody.OidcSessionActivationDeliveryExecutionCustody
        if type(owner) is not owner_type:
            raise DeliveryPendingAdmissionError("consume pending needs the actual SQL-issuer receiving owner")
        owner_type.require_consumer_role_on_work(owner,
            consumer_role=custody.bootstrap.SQL_ISSUER_CONSUMER_ROLE, work=work)

        # This original-only path meters the raw3 with caller/grant/raw2 and
        # receiver originals before caller hashes, authenticates controls before
        # private opening, and genuinely replays the consume plan exactly once.
        actual = reservation._verify_full_on_work(originals=pair, expectations=expectations,
            before_vector_bytes=before, authorization_bytes=caller,
            grant_bytes=grant, response_originals=returned,
            authorization_enrollment_bytes=caller_enrollment,
            grant_enrollment_bytes=grant_enrollment,
            current_root_enrollment_bytes=enrollment, root_public_key=root_public_key,
            planner_public_key=planner_public_key, operation_public_key=operation_public_key,
            configuration_digest=configuration_digest, expected_predecessor_sequence=sequence,
            expected_predecessor_head_digest=head, expected_fence=fence, receiving_custody=owner,
            live_window=scope[5], transport_deadline_ns=scope[6], work=work,
            required_consumer_role=custody.bootstrap.SQL_ISSUER_CONSUMER_ROLE)
        if type(actual) is not reservation._VerifiedReservation or actual.receipt is None:
            raise DeliveryPendingAdmissionError("consume pending admission lacks its genuine original ACK")
        actual.live()
        pending.evidence.plan._same(actual.request["operation"], OPERATION, work,
            "consume pending operation differs from its fixed purpose")
        pending._pending(actual.material, actual.request, actual.request_digest,
            actual.receipt, actual.receipt_digest, scope, work)
        # The comparison includes actual signed ACK identity/sequence, exact
        # enrollment/database/generation, reserve identity, predecessor/fence,
        # unchanged reserve interval and independently reserved completion room.
        actual.live()
        owner_type.require_consumer_role_on_work(owner,
            consumer_role=custody.bootstrap.SQL_ISSUER_CONSUMER_ROLE, work=work)
        actual.live()
        replayed = actual.replayed
        marker = pending._marker(actual.material, actual.request, actual.request_digest,
            actual.receipt, actual.receipt_digest, actual.snapshot, work)
        candidate = pending._ExecutionCandidate(OPERATION, replayed.request, replayed.selected_rows,
            replayed.mutations, replayed.result, replayed.before_vector_bytes, replayed.after_vector_bytes,
            marker, (actual.request["issuedAtEpochNs"], actual.request["expiresAtEpochNs"]),
            returned[0], returned[2], returned[1], replayed.work_units)
        caller_wire = reservation.grants.admission.caller
        authorization_digest = pending.evidence.plan._frame(caller_wire.REQUEST_IDENTITY_DOMAIN,
            (caller,), work)

        def live():
            epoch, _monotonic = actual.live()
            owner_type.require_consumer_role_on_work(owner,
                consumer_role=custody.bootstrap.SQL_ISSUER_CONSUMER_ROLE, work=work)
            final_epoch, _final_monotonic = actual.live()
            if final_epoch < epoch:
                raise DeliveryPendingAdmissionError("consume pending clock reversed through its continuation")
            return final_epoch

        controls = (enrollment, grant_enrollment, grant, returned[0], returned[2], returned[1],
            caller_enrollment, caller)
        live()
        result = _AdmittedDelivery(returned, pair, controls, authorization_digest, candidate,
            actual.window, actual.deadline_ns, live)
        live()
        return result
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError, RecursionError) as exc:
        if isinstance(exc, DeliveryPendingAdmissionError):
            raise
        raise DeliveryPendingAdmissionError("consume pending original admission failed") from exc


def _admit_on_work(*, originals, expectations, before_vector_bytes, authorization_bytes,
        grant_bytes, response_originals, authorization_enrollment_bytes, grant_enrollment_bytes,
        current_root_enrollment_bytes, root_public_key, planner_public_key,
        operation_public_key, configuration_digest, expected_predecessor_sequence,
        expected_predecessor_head_digest, expected_database_id, expected_generation_digest,
        expected_pending_sequence, expected_pending_head_digest, expected_fence,
        receiving_custody, live_window, transport_deadline_ns, work):
    """Preserve the original raw3 API; no successful suffix can be supplied."""
    admitted = _admit_full_on_work(originals=originals, expectations=expectations,
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
    return admitted.originals
