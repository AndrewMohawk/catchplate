"""Live activation raw3 admission against independently held current pending pins.

An authenticated reservation ACK is not its own current-head authority. Every
entry takes the full original caller/grant/private plan again; no previously
successful reserve or admission carrier is accepted. The unchanged originals
returned here cannot replace genuine downstream issuer replay.
"""
from __future__ import annotations

from dataclasses import dataclass

from catchplate import authority_oidc_session_activation_reservation as reservation
from catchplate import authority_successor_execution_admission as successor


OPERATION = reservation.OPERATION


class OidcSessionActivationPendingAdmissionError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class _AdmittedSqlInputs:
    """Private same-invocation suffix; no entrypoint accepts this as proof."""

    originals: tuple
    issue_arguments: dict
    marker_expectation: dict
    live_window: tuple
    deadline_ns: int
    live: object


def _admit_for_sql_on_work(*, originals, expectations, before_vector_bytes, authorization_bytes,
        grant_bytes, response_originals, authorization_enrollment_bytes, grant_enrollment_bytes,
        current_root_enrollment_bytes, root_public_key, planner_public_key,
        operation_public_key, configuration_digest, expected_predecessor_sequence,
        expected_predecessor_head_digest, expected_database_id, expected_generation_digest,
        expected_pending_sequence, expected_pending_head_digest, expected_fence,
        activation_custody, live_window, transport_deadline_ns, work):
    """Derive original issuer arguments after actual pending admission once."""
    returned = reservation._response_originals(response_originals)
    sequence, head, fence = reservation.records._predecessor_scope(expected_predecessor_sequence,
        expected_predecessor_head_digest, expected_fence)
    scope = successor.pending._scope(expected_database_id=expected_database_id,
        expected_generation_digest=expected_generation_digest, expected_pending_sequence=expected_pending_sequence,
        expected_pending_head_digest=expected_pending_head_digest, expected_fence=fence,
        live_window=live_window, transport_deadline_ns=transport_deadline_ns)
    if scope[2] != sequence + 1:
        raise OidcSessionActivationPendingAdmissionError("independent activation predecessor/pending scopes disagree")
    owner = activation_custody
    held, grant, authorized, payload, live = reservation._authorize_on_work(originals=originals,
        expectations=expectations, before_vector_bytes=before_vector_bytes, authorization_bytes=authorization_bytes,
        grant_bytes=grant_bytes, authorization_enrollment_bytes=authorization_enrollment_bytes,
        grant_enrollment_bytes=grant_enrollment_bytes, current_root_enrollment_bytes=current_root_enrollment_bytes,
        root_public_key=root_public_key, planner_public_key=planner_public_key,
        operation_public_key=operation_public_key, configuration_digest=configuration_digest,
        activation_custody=owner, live_window=scope[5], transport_deadline_ns=scope[6],
        work=work, consumer_role="sql-issuer", extra_originals=returned)
    live()
    issue_arguments = {"operation": OPERATION, "originals": held.originals,
        "expectations": held.expectations, "planner_public_key": held.planner,
        "operation_public_key": held.operation_key, "enrollment_bytes": held.current_enrollment,
        "root_public_key": held.root, "reserve_request_bytes": returned[0],
        "snapshot_bytes": returned[1], "reserve_receipt_bytes": returned[2],
        "grant_bytes": grant, "grant_enrollment_bytes": held.grant_enrollment,
        "expected_authorization_digest": authorized.authorization_digest,
        "expected_database_id": scope[0], "expected_generation_digest": scope[1],
        "expected_pending_sequence": scope[2], "expected_pending_head_digest": scope[3],
        "expected_fence": scope[4], "activation_custody": owner}
    candidate = successor._admit_on_work(**issue_arguments, live_window=authorized.window,
        work=work, transport_deadline_ns=authorized.deadline_ns)
    for field, expected in (("predecessor_sequence", sequence), ("predecessor_head_digest", head),
            ("operation", OPERATION), ("request_digest", authorized.request_digest),
            ("operation_id", authorized.operation_id)):
        reservation.plan._same(candidate.marker[field], expected, work,
            "activation pending computation differs from independent original scope")
    reservation._same_bytes(candidate.before_vector_bytes, held.before, work,
        "activation pending before vector differs from independently held original")
    issued, expires = candidate.original_interval
    if issued != payload["issuedAtEpochNs"] or expires > min(payload["expiresAtEpochNs"], authorized.window[3]):
        raise OidcSessionActivationPendingAdmissionError("activation pending interval renews original authority")
    window = reservation.clock._validate((authorized.window[0], authorized.window[1],
        authorized.window[2], expires, min(authorized.window[4],
            authorized.window[1] + expires - authorized.window[0]),
        authorized.window[5], authorized.window[6]))
    bound = min(authorized.deadline_ns, window[4])

    def pending_live():
        now, monotonic = live()
        if now >= expires or monotonic >= bound:
            raise OidcSessionActivationPendingAdmissionError("activation pending original interval expired")
        return now

    pending_live()
    work.prepare_copy(candidate.marker)
    marker = candidate.marker.copy()
    result = _AdmittedSqlInputs(returned, issue_arguments, marker, window, bound, pending_live)
    pending_live()
    return result


def _admit_on_work(*, originals, expectations, before_vector_bytes, authorization_bytes,
        grant_bytes, response_originals, authorization_enrollment_bytes, grant_enrollment_bytes,
        current_root_enrollment_bytes, root_public_key, planner_public_key,
        operation_public_key, configuration_digest, expected_predecessor_sequence,
        expected_predecessor_head_digest, expected_database_id, expected_generation_digest,
        expected_pending_sequence, expected_pending_head_digest, expected_fence,
        activation_custody, live_window, transport_deadline_ns, work):
    """Return unchanged raw3; no suffix result can be supplied as authority."""
    result = _admit_for_sql_on_work(originals=originals, expectations=expectations,
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
        expected_fence=expected_fence, activation_custody=activation_custody,
        live_window=live_window, transport_deadline_ns=transport_deadline_ns, work=work)
    result.live()
    return result.originals
