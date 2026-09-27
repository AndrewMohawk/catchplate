"""Authenticate historical registration completion from complete originals.

Independent cold configuration/enrollments and expected pending scope precede
all admission. Genuine verifier/planner controls bind historical request and
response bytes; full plan replay derives bounded history, not database-clock
truth. Caller authorization and grant signatures retain their ORIGINAL scope
and intervals. Completion/state originals are then genuinely replayed and
authenticated under those same facts.

The caller supplies its existing current processing window and work. Expired
execution controls are never revived, no clock is synthesized from an original
timestamp, and no execution or public recovery permission is returned. This
module performs no SQL, transport, signing, storage, retry or finalization.
"""
from __future__ import annotations

import time

from serverware import authority_registration_execution_exchange as exchange
from serverware import authority_registration_reservation_transport as reservation_wire
from serverware import authority_registration_completion_response as completion
from serverware import authority_registration_history_exchange as history_exchange


authorization, grants, evidence, clock = (
    exchange.authorization, exchange.grants, exchange.evidence, exchange.clock)
current_root = grants.authorization


class RegistrationCompletionHistoryError(ValueError):
    pass


def _verify_on_configuration(*, payload, configuration_digest, generation,
        runtime_role_identities, originals, reservation_originals, response_originals,
        authorization_enrollment_bytes, grant_enrollment_bytes, current_root_enrollment_bytes,
        root_public_key, expected_pending_sequence, expected_pending_head_digest,
        expected_fence, live_window, work, transport_deadline_ns=None):
    """Return only authenticated completion/state originals and their IDs.

    Input orders remain actual grant raw10, reserve raw3 and completion raw4.
    Original enrollments/configuration and expected pending scope must come
    from independent admission, never the returned acknowledgment. This call
    does not authenticate the present human/workload or authorize recovery.
    """
    ledger = evidence.capture._SharedLedger(work)
    held = reservation_wire._originals(originals, response=False)
    reserved = reservation_wire._originals(reservation_originals, response=True)
    returned = completion.transport._originals(response_originals, response=True)
    caller_enrollment = current_root._original(authorization_enrollment_bytes,
        authorization.MAX_ENROLLMENT_BYTES, "historical completion caller enrollment")
    grant_enrollment = current_root._original(grant_enrollment_bytes,
        grants.MAX_ENROLLMENT_BYTES, "historical completion grant enrollment")
    current_enrollment = current_root._original(current_root_enrollment_bytes,
        current_root.MAX_ENROLLMENT_BYTES, "historical completion current-root enrollment")
    if sum(len(raw) for raw in (*held, *reserved, *returned, caller_enrollment,
            grant_enrollment, current_enrollment)) > exchange.MAX_ORIGINAL_BYTES:
        raise RegistrationCompletionHistoryError("historical completion originals exceed their complete bound")
    shape = current_root.shape
    shape._digest(configuration_digest)
    shape._integer(expected_pending_sequence, current_root.MAX_RECORDS, minimum=1)
    shape._digest(expected_pending_head_digest)
    shape._integer(expected_fence, minimum=1)
    digest, sequence, head, fence = (configuration_digest, expected_pending_sequence,
        expected_pending_head_digest, expected_fence)
    root = root_public_key
    current_root._public(root)
    window = clock._validate(live_window)
    inherited = transport_deadline_ns
    if inherited is not None:
        shape._integer(inherited, minimum=1)
    bound = window[4] if inherited is None else min(window[4], inherited)
    if type(payload) is not dict or type(generation) is not dict:
        raise RegistrationCompletionHistoryError("historical completion configuration is not exact data")
    shape._bounded_object(generation, 24, "historical completion launch context")
    owned_payload = exchange.measured._ConfigurationCapture(ledger,
        maximum_bytes=exchange.wire.authority.MAX_REQUEST_BYTES).visit(payload)
    owned_generation = evidence.capture._JSONCapture(ledger).visit(
        {name: generation[name] for name in exchange.measured._GENERATION_FIELDS})
    owned_runtime = evidence.capture._JSONCapture(ledger,
        maximum_bytes=8192).visit(runtime_role_identities)
    if returned[0] == b"uncertain":
        raise completion.RegistrationCompletionUncertainError("registration completion outcome is not established")
    last_epoch, last_monotonic = window[0], window[2]

    def current():
        nonlocal last_epoch, last_monotonic
        now = clock._check_on_work(window, work=work)
        monotonic = evidence.production._callback(work, time.monotonic_ns)
        shape._integer(monotonic, minimum=1)
        if now < last_epoch or monotonic < last_monotonic or monotonic >= bound:
            raise RegistrationCompletionHistoryError("historical completion processing expired or its clocks reversed")
        last_epoch, last_monotonic = now, monotonic
        return now

    current()
    historical = history_exchange._verify_on_configuration(
        payload=owned_payload, configuration_digest=digest, generation=owned_generation,
        runtime_role_identities=owned_runtime, originals=held,
        authorization_enrollment_bytes=caller_enrollment,
        current_root_enrollment_bytes=current_enrollment, grant_enrollment_bytes=grant_enrollment,
        root_public_key=root,
        live_window=window, work=work, transport_deadline_ns=bound)
    current()
    # Replays actual original pending/plan/grant state, not any returned
    # successful-verification object; independently expected sequence/head/fence
    # remain caller-held. The returned wire contains no packet locator.
    result = completion._verify_on_work(response_originals=returned,
        plan_originals=held[5:8], reserve_request_bytes=reserved[0],
        reserve_receipt_bytes=reserved[2], snapshot_bytes=reserved[1],
        enrollment_bytes=current_enrollment, grant_bytes=held[9], grant_enrollment_bytes=grant_enrollment,
        expectations=historical.expectations, planner_public_key=historical.planner_public_key,
        evidence_public_key=historical.evidence_public_key,
        root_public_key=root, expected_authorization_digest=historical.authorization_digest,
        expected_database_id=historical.database_id, expected_generation_digest=historical.generation_digest,
        expected_pending_sequence=sequence, expected_pending_head_digest=head, expected_fence=fence,
        live_window=window, work=work, transport_deadline_ns=bound)
    current()
    return result
