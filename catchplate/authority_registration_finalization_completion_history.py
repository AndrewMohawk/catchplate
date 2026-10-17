"""Historical finalization completion admission from complete original bytes.

The same independently admitted finalization configuration and enrollments
authenticate raw10 history before actual reserve/plan/grant/completion replay.
Expected pending sequence/head/fence are captured caller pins, never selected
by a response or journal. No packet identity is asserted by the response wire.

This retains the caller's current work/window/deadline, not an old execution
interval. It performs no SQL, signing, transport, storage or retry and supplies
no present-user recovery permission, session activation or current-head proof.
"""
from __future__ import annotations

import time

from catchplate import authority_registration_finalization_history_exchange as history_exchange
from catchplate import authority_registration_finalization_completion_response as completion


caller, grants, authorization = history_exchange.caller, history_exchange.grants, history_exchange.authorization
evidence, clock, shape = history_exchange.evidence, history_exchange.clock, history_exchange.shape
reservation_wire, measured, wire = (
    history_exchange.reservation_wire, history_exchange.measured, history_exchange.wire)
MAX_ORIGINAL_BYTES = history_exchange.MAX_ORIGINAL_BYTES


class RegistrationFinalizationCompletionHistoryError(ValueError):
    pass


def _verify_on_configuration(*, payload, configuration_digest, generation,
        runtime_role_identities, originals, reservation_originals, response_originals,
        authorization_enrollment_bytes, grant_enrollment_bytes, current_root_enrollment_bytes,
        root_public_key, expected_pending_sequence, expected_pending_head_digest,
        expected_fence, live_window, work, transport_deadline_ns=None):
    """Return the genuine receiving verifier's original completion/state facts.

    Orders are finalization raw10, reserve raw3, completion raw4. Neither a
    successful carrier nor a response-appointed expected scope is accepted.
    """
    ledger = evidence.capture._SharedLedger(work)
    held = reservation_wire._originals(originals, response=False)
    reserved = reservation_wire._originals(reservation_originals, response=True)
    returned = completion.transport._originals(response_originals, response=True)
    caller_enrollment = authorization._original(authorization_enrollment_bytes,
        caller.MAX_ENROLLMENT_BYTES, "historical finalization completion caller enrollment")
    grant_enrollment = authorization._original(grant_enrollment_bytes,
        grants.MAX_ENROLLMENT_BYTES, "historical finalization completion grant enrollment")
    current_enrollment = authorization._original(current_root_enrollment_bytes,
        authorization.MAX_ENROLLMENT_BYTES, "historical finalization completion current-root enrollment")
    if sum(len(raw) for raw in (*held, *reserved, *returned, caller_enrollment,
            grant_enrollment, current_enrollment)) > MAX_ORIGINAL_BYTES:
        raise RegistrationFinalizationCompletionHistoryError("historical finalization completion originals exceed their bound")
    digest, sequence, head, fence = (configuration_digest, expected_pending_sequence,
        expected_pending_head_digest, expected_fence)
    shape._digest(digest)
    shape._integer(sequence, authorization.MAX_RECORDS, minimum=1)
    shape._digest(head)
    shape._integer(fence, minimum=1)
    root = root_public_key
    authorization._public(root)
    window = clock._validate(live_window)
    inherited = transport_deadline_ns
    if inherited is not None:
        shape._integer(inherited, minimum=1)
    bound = window[4] if inherited is None else min(window[4], inherited)
    if type(payload) is not dict or type(generation) is not dict:
        raise RegistrationFinalizationCompletionHistoryError("historical completion configuration is not exact data")
    shape._bounded_object(generation, 24, "historical finalization completion launch context")
    owned_payload = measured._ConfigurationCapture(ledger,
        maximum_bytes=wire.authority.MAX_REQUEST_BYTES).visit(payload)
    owned_generation = evidence.capture._JSONCapture(ledger).visit(
        {name: generation[name] for name in measured._GENERATION_FIELDS})
    owned_runtime = evidence.capture._JSONCapture(ledger,
        maximum_bytes=8192).visit(runtime_role_identities)
    if returned[0] == b"uncertain":
        raise completion.FinalizationCompletionUncertainError("finalization completion outcome is not established")
    last_epoch, last_monotonic = window[0], window[2]

    def current():
        nonlocal last_epoch, last_monotonic
        now = clock._check_on_work(window, work=work)
        monotonic = evidence.production._callback(work, time.monotonic_ns)
        shape._integer(monotonic, minimum=1)
        if now < last_epoch or monotonic < last_monotonic or monotonic >= bound:
            raise RegistrationFinalizationCompletionHistoryError("historical completion processing expired or clocks reversed")
        last_epoch, last_monotonic = now, monotonic

    current()
    historical = history_exchange._verify_on_configuration(payload=owned_payload,
        configuration_digest=digest, generation=owned_generation, runtime_role_identities=owned_runtime,
        originals=held, authorization_enrollment_bytes=caller_enrollment,
        grant_enrollment_bytes=grant_enrollment, current_root_enrollment_bytes=current_enrollment,
        root_public_key=root, live_window=window, work=work, transport_deadline_ns=bound)
    current()
    result = completion._verify_on_work(response_originals=returned,
        plan_originals=historical.raw4, reserve_request_bytes=reserved[0],
        reserve_receipt_bytes=reserved[2], snapshot_bytes=reserved[1],
        enrollment_bytes=current_enrollment, grant_bytes=held[9], grant_enrollment_bytes=grant_enrollment,
        expectations=historical.expectations, planner_public_key=historical.planner_public_key,
        operation_public_key=historical.operation_public_key, root_public_key=root,
        expected_authorization_digest=historical.authorization_digest,
        expected_database_id=historical.database_id, expected_generation_digest=historical.generation_digest,
        expected_pending_sequence=sequence, expected_pending_head_digest=head, expected_fence=fence,
        live_window=window, work=work, transport_deadline_ns=bound)
    current()
    return result
