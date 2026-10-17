"""Live activation originals into a reserve, or an authenticated original ACK.

Independent predecessor pins never come from a returned receipt. The private
same-call caller check is not a proof accepted by another entrypoint. Full
private plan replay remains in the actual generic grant/preparation path.
"""
from __future__ import annotations

from catchplate import authority_current_root_authorization as current_root
from catchplate import authority_current_root_computation as computation
from catchplate import authority_oidc_session_activation_execution_authorization as caller
from catchplate import authority_oidc_session_activation_execution_custody as custody
from catchplate import authority_oidc_session_activation_reservation_records as records
from catchplate import authority_successor_execution_preparation as preparation


OPERATION = caller.OPERATION
grants, plan, clock = caller.grants, caller.plan, caller.clock


class OidcSessionActivationReservationError(ValueError):
    pass


def _same_bytes(actual, expected, work, message):
    work.charge(input_bytes=len(actual) + len(expected))
    if actual != expected:
        raise OidcSessionActivationReservationError(message)


def _response_originals(values, *, allow_pending=False):
    if type(values) not in (tuple, list) or len(values) != 3:
        raise OidcSessionActivationReservationError("activation reservation response requires exact raw3")
    return tuple(None if position == 2 and allow_pending and raw is None else
        current_root._original(raw, cap, "activation reservation response original")
        for position, (raw, cap) in enumerate(zip(values, (records.MAX_REQUEST_BYTES,
            records.MAX_SNAPSHOT_BYTES, records.MAX_RECEIPT_BYTES))))


def _authorize_on_work(*, originals, expectations, before_vector_bytes, authorization_bytes,
        grant_bytes, authorization_enrollment_bytes, grant_enrollment_bytes,
        current_root_enrollment_bytes, root_public_key, planner_public_key,
        operation_public_key, configuration_digest, activation_custody,
        live_window, transport_deadline_ns, work, consumer_role, extra_originals=()):
    """Own all originals before callbacks; return facts only to this invocation."""
    original = current_root._original(authorization_bytes, caller.MAX_AUTHORIZATION_BYTES,
        "activation execution authorization")
    grant = current_root._original(grant_bytes, grants.MAX_GRANT_BYTES, "activation execution grant")
    owner = activation_custody
    if type(owner) is not custody.OidcSessionActivationExecutionCustody:
        raise OidcSessionActivationReservationError("activation requires actual private receiving custody")
    held = caller._capture_on_work(originals=originals, expectations=expectations,
        before_vector_bytes=before_vector_bytes, authorization_enrollment_bytes=authorization_enrollment_bytes,
        grant_enrollment_bytes=grant_enrollment_bytes, current_root_enrollment_bytes=current_root_enrollment_bytes,
        root_public_key=root_public_key, planner_public_key=planner_public_key,
        operation_public_key=operation_public_key, configuration_digest=configuration_digest,
        live_window=live_window, transport_deadline_ns=transport_deadline_ns, work=work,
        extra_originals=(original, grant, *extra_originals))
    configured = custody.OidcSessionActivationExecutionCustody._snapshot_configuration(owner)
    if configured.consumer_role != consumer_role:
        raise OidcSessionActivationReservationError("activation receiving custody has another fixed purpose")
    grants.replay._activation_context_on_work(OPERATION, owner, root_public_key=held.root,
        current_root_enrollment_bytes=held.current_enrollment, work=work)
    authorized = caller._verify_on_work(authorization_bytes=original,
        authorization_enrollment_bytes=held.caller_enrollment,
        current_root_enrollment_bytes=held.current_enrollment, grant_enrollment_bytes=held.grant_enrollment,
        root_public_key=held.root, configuration_digest=held.configuration_digest,
        planner_public_key=held.planner, operation_public_key=held.operation_key,
        originals=held.originals, expectations=held.expectations, before_vector_bytes=held.before,
        live_window=held.window, transport_deadline_ns=held.deadline_ns, work=work)
    # Signature/control admission is small; the later genuine generic consumer
    # performs the full original plan replay once. Check the post-plan caller's
    # interval, rather than treating its digest alone as execution permission.
    payload, _grant_digest = grants._verify_control_on_work(grant_bytes=grant,
        grant_enrollment_bytes=held.grant_enrollment, current_root_enrollment_bytes=held.current_enrollment,
        root_public_key=held.root, planner_public_key=held.planner, operation_public_key=held.operation_key,
        expected_authorization_digest=authorized.authorization_digest,
        now_epoch_ns=authorized.live()[0], work=work)
    for field, expected in (("operation", OPERATION), ("requestDigest", authorized.request_digest),
            ("operationId", authorized.operation_id), ("planDigest", authorized.plan_digest),
            ("retainedRecordDigest", authorized.retained_record_digest),
            ("beforeVectorDigest", authorized.before_vector_digest)):
        plan._same(payload[field], expected, work, "activation grant differs from original caller authority")
    if not (payload["issuedAtEpochNs"] <= authorized.issued_at_epoch_ns
            < authorized.expires_at_epoch_ns <= payload["originalExpiresAtEpochNs"]
            and payload["expiresAtEpochNs"] <= authorized.expires_at_epoch_ns):
        raise OidcSessionActivationReservationError("activation grant renews its post-plan caller authority")
    grant_bound = min(authorized.deadline_ns,
        authorized.window[1] + payload["expiresAtEpochNs"] - authorized.window[0])

    def live():
        now, monotonic = authorized.live()
        if now >= payload["expiresAtEpochNs"] or monotonic >= grant_bound:
            raise OidcSessionActivationReservationError("activation original execution grant expired")
        if custody.OidcSessionActivationExecutionCustody._snapshot_configuration(owner) is not configured:
            raise OidcSessionActivationReservationError("activation receiving custody configuration changed")
        # The process check is a native operation too; retain the actual caller
        # closure's rollback/expiry observations after it, not just before it.
        final_now, final_monotonic = authorized.live()
        if (final_now < now or final_monotonic < monotonic
                or final_now >= payload["expiresAtEpochNs"] or final_monotonic >= grant_bound):
            raise OidcSessionActivationReservationError("activation original execution interval expired or reversed")
        return final_now, final_monotonic

    live()
    return held, grant, authorized, payload, live


def _produce_on_work(*, originals, expectations, before_vector_bytes, authorization_bytes,
        grant_bytes, authorization_enrollment_bytes, grant_enrollment_bytes,
        current_root_enrollment_bytes, root_public_key, planner_public_key,
        operation_public_key, configuration_digest, computation_private_key,
        expected_predecessor_sequence, expected_predecessor_head_digest, expected_fence,
        activation_custody, live_window, transport_deadline_ns, work):
    """Return actual signed request/snapshot bytes, without publishing state."""
    sequence, head, fence = records._predecessor_scope(expected_predecessor_sequence,
        expected_predecessor_head_digest, expected_fence)
    signer, owner = computation_private_key, activation_custody
    current_root._private(signer)
    held, grant, authorized, _payload, live = _authorize_on_work(originals=originals,
        expectations=expectations, before_vector_bytes=before_vector_bytes, authorization_bytes=authorization_bytes,
        grant_bytes=grant_bytes, authorization_enrollment_bytes=authorization_enrollment_bytes,
        grant_enrollment_bytes=grant_enrollment_bytes, current_root_enrollment_bytes=current_root_enrollment_bytes,
        root_public_key=root_public_key, planner_public_key=planner_public_key,
        operation_public_key=operation_public_key, configuration_digest=configuration_digest,
        activation_custody=owner, live_window=live_window, transport_deadline_ns=transport_deadline_ns,
        work=work, consumer_role="reserve")
    live()
    result = preparation._produce_reserve_on_work(operation=OPERATION, originals=held.originals,
        expectations=held.expectations, planner_public_key=held.planner, operation_public_key=held.operation_key,
        before_vector_bytes=held.before, enrollment_bytes=held.current_enrollment, root_public_key=held.root,
        computation_private_key=signer, grant_bytes=grant, grant_enrollment_bytes=held.grant_enrollment,
        expected_authorization_digest=authorized.authorization_digest, predecessor_sequence=sequence,
        predecessor_head_digest=head, fence=fence, deadline_epoch_ns=authorized.window[3], work=work,
        transport_deadline_ns=authorized.deadline_ns, live_window=authorized.window, activation_custody=owner)
    material, request, _identity = current_root._verify_request_on_work(request_bytes=result.request_bytes,
        enrollment_bytes=held.current_enrollment, root_public_key=held.root, now_epoch_ns=live()[0], work=work)
    now, monotonic = live()
    current_root._fresh(request, material, now)
    if monotonic >= min(authorized.deadline_ns,
            authorized.window[1] + request["expiresAtEpochNs"] - authorized.window[0]):
        raise OidcSessionActivationReservationError("activation signed reserve expired before return")
    return result


def _verify_retained_on_work(*, originals, expectations, before_vector_bytes, authorization_bytes,
        grant_bytes, response_originals, authorization_enrollment_bytes, grant_enrollment_bytes,
        current_root_enrollment_bytes, root_public_key, planner_public_key,
        operation_public_key, configuration_digest, expected_predecessor_sequence,
        expected_predecessor_head_digest, expected_fence, activation_custody,
        live_window, transport_deadline_ns, work):
    """Re-admit original request/snapshot and optional ACK, without re-signing."""
    returned = _response_originals(response_originals, allow_pending=True)
    sequence, head, fence = records._predecessor_scope(expected_predecessor_sequence,
        expected_predecessor_head_digest, expected_fence)
    owner = activation_custody
    held, grant, authorized, _payload, live = _authorize_on_work(originals=originals,
        expectations=expectations, before_vector_bytes=before_vector_bytes, authorization_bytes=authorization_bytes,
        grant_bytes=grant_bytes, authorization_enrollment_bytes=authorization_enrollment_bytes,
        grant_enrollment_bytes=grant_enrollment_bytes, current_root_enrollment_bytes=current_root_enrollment_bytes,
        root_public_key=root_public_key, planner_public_key=planner_public_key,
        operation_public_key=operation_public_key, configuration_digest=configuration_digest,
        activation_custody=owner, live_window=live_window, transport_deadline_ns=transport_deadline_ns,
        work=work, consumer_role="reserve", extra_originals=tuple(raw for raw in returned if raw is not None))
    verified = grants._verify_on_work(grant_bytes=grant, grant_enrollment_bytes=held.grant_enrollment,
        current_root_enrollment_bytes=held.current_enrollment, root_public_key=held.root, operation=OPERATION,
        originals=held.originals, expectations=held.expectations, planner_public_key=held.planner,
        operation_public_key=held.operation_key, before_vector_bytes=held.before,
        expected_authorization_digest=authorized.authorization_digest, now_epoch_ns=live()[0], work=work,
        activation_custody=owner, live_window=authorized.window, transport_deadline_ns=authorized.deadline_ns)
    material, request, request_digest = current_root._verify_request_on_work(request_bytes=returned[0],
        enrollment_bytes=held.current_enrollment, root_public_key=held.root, now_epoch_ns=live()[0], work=work)
    for field, expected in (("action", "reserve"), ("operation", OPERATION),
            ("requestDigest", authorized.request_digest), ("operationId", authorized.operation_id),
            ("capabilityDigest", verified.grant_digest), ("predecessorSequence", sequence),
            ("predecessorHeadDigest", head), ("fence", fence)):
        plan._same(request[field], expected, work, "activation reserve differs from independent original scope")
    plan._same(material.enrollment_digest, verified.payload["currentRootEnrollmentDigest"], work,
        "activation reserve and grant current-root enrollments differ")
    if (request["issuedAtEpochNs"] != verified.payload["issuedAtEpochNs"]
            or request["issuedAtEpochNs"] != verified.replayed.original_interval[0]
            or request["expiresAtEpochNs"] > min(authorized.window[3],
                verified.payload["expiresAtEpochNs"], verified.replayed.original_interval[1])):
        raise OidcSessionActivationReservationError("activation reserve renews or retimes original authority")
    deadline = request["expiresAtEpochNs"]
    bound = min(authorized.deadline_ns, authorized.window[1] + deadline - authorized.window[0])

    def reserve_live():
        now, monotonic = live()
        if now >= deadline or monotonic >= bound:
            raise OidcSessionActivationReservationError("activation reservation response original interval expired")
        current_root._fresh(request, material, now)

    reserve_live()
    before = current_root.vector._encode_on_work(request["beforeVector"], work=work)
    after = current_root.vector._encode_on_work(request["afterVector"], work=work)
    _same_bytes(before, held.before, work, "activation reserve differs from independently held before vector")
    _same_bytes(before, verified.replayed.before_vector_bytes, work, "activation reserve before vector differs from replay")
    _same_bytes(after, verified.replayed.after_vector_bytes, work, "activation reserve after vector differs from replay")
    expected_snapshot = computation._snapshot_wire(
        computation._snapshot(verified.replayed, material, verified.grant_digest, work), work)
    _same_bytes(returned[1], expected_snapshot, work, "activation reserve snapshot differs from genuine replay")
    reserve_live()
    _request, retained_digest, receipt, _receipt_digest = records._verify_on_work(
        request_bytes=returned[0], snapshot_bytes=returned[1], receipt_bytes=returned[2],
        enrollment_bytes=held.current_enrollment, root_public_key=held.root,
        expected_predecessor_sequence=sequence, expected_predecessor_head_digest=head,
        expected_fence=fence, work=work)
    plan._same(retained_digest, request_digest, work, "activation ACK differs from the live original reserve")
    if returned[2] is not None and receipt is None:
        raise OidcSessionActivationReservationError("activation reservation has no original state ACK")
    reserve_live()
    return returned


def _verify_response_on_work(*, originals, expectations, before_vector_bytes, authorization_bytes,
        grant_bytes, response_originals, authorization_enrollment_bytes, grant_enrollment_bytes,
        current_root_enrollment_bytes, root_public_key, planner_public_key,
        operation_public_key, configuration_digest, expected_predecessor_sequence,
        expected_predecessor_head_digest, expected_fence, activation_custody,
        live_window, transport_deadline_ns, work):
    """Return unchanged exact raw3 after live replay/ACK joins, not currentness."""
    returned = _response_originals(response_originals)
    return _verify_retained_on_work(originals=originals, expectations=expectations,
        before_vector_bytes=before_vector_bytes, authorization_bytes=authorization_bytes,
        grant_bytes=grant_bytes, response_originals=returned,
        authorization_enrollment_bytes=authorization_enrollment_bytes,
        grant_enrollment_bytes=grant_enrollment_bytes, current_root_enrollment_bytes=current_root_enrollment_bytes,
        root_public_key=root_public_key, planner_public_key=planner_public_key,
        operation_public_key=operation_public_key, configuration_digest=configuration_digest,
        expected_predecessor_sequence=expected_predecessor_sequence,
        expected_predecessor_head_digest=expected_predecessor_head_digest, expected_fence=expected_fence,
        activation_custody=activation_custody, live_window=live_window,
        transport_deadline_ns=transport_deadline_ns, work=work)
