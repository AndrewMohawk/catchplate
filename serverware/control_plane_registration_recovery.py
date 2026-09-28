"""Explicit authorized historical completion recovery; never SQL retry.

The public handler admits the present caller and recovery purpose. This actual
cold-owner continuation repeats genuine retained-subject replay and historical
grant/pending admission before any completion-service request. Returned/stored
completion originals are genuinely verified before their separate durable
association. Original uncertainty and the irreversible SQL claim are immutable.
No old expiry is renewed, no finalization is performed and no automatic retry
is authorized. Current owner admission does not prove an off-host current head.
"""
from __future__ import annotations

from serverware import control_plane_registration_recovery_subject as subjects
from serverware import control_plane_registration_handoff as handoff
from serverware import authority_registration_history_exchange as history
from serverware import authority_registration_completion_history as completion_history
from serverware import authority_registration_completion_response as completion


evidence, clock, startup = subjects.evidence, subjects.clock, subjects.startup
custody_client, journal, wire = handoff.custody_client, handoff.journal, completion.transport


class RegistrationRecoveryOutcomeError(ValueError):
    """Selector only; no result, rollback, currentness or SQL retry permission."""

    def __init__(self, local_digest):
        super().__init__("registration completion recovery outcome is not established")
        self.local_digest = journal._digest(local_digest)


def _recover_on_owner(owner, *, local_digest, expected_user_id, expected_session_id,
        live_window, work, transport_deadline_ns=None):
    digest = journal._digest(local_digest)
    user_id, session_id = handoff._expected_subject(expected_user_id, expected_session_id)
    common, endpoint, window, bound, live = subjects._scope_on_owner(owner,
        live_window=live_window, work=work, transport_deadline_ns=transport_deadline_ns)
    # One bounded read holds the pair and every retained outcome together.
    # Historical authority is resolved and genuinely replayed on this same work;
    # the current owner still supplies transport and present-purpose authority.
    replayed = subjects._replay_material_on_owner(owner, digest,
        live_window=window, work=work, transport_deadline_ns=bound,
        _include_outcomes=True)
    custody, binding = owner._custody, owner._binding
    common, window = replayed.common, replayed.window
    bound = min(bound, replayed.deadline_ns)
    pending, packet = replayed.current_pending, replayed.completion_packet_digest
    observed = replayed.observed
    if observed is None or observed.sql_attempt is None or observed.reservation is None:
        raise RegistrationRecoveryOutcomeError(digest)
    held = handoff.reserve_wire._originals(replayed.originals, response=False)
    reserved = handoff.reserve_wire._originals(observed.reservation.originals, response=True)
    subject, original_bytes = replayed.subject, replayed.original_bytes
    if original_bytes > completion.MAX_ORIGINAL_BYTES:
        raise RegistrationRecoveryOutcomeError(digest)

    def current():
        live()
        replayed.current()
        if (owner._custody is not custody or owner._binding is not binding
                or evidence.production._callback(work,
                    lambda: custody_client._snapshot(custody)) is not binding):
            raise RegistrationRecoveryOutcomeError(digest)
        evidence.production._callback(work, lambda: wire._check_deadline(bound))
        replayed.current()
        live()

    current()
    evidence.plan._same(subject["userId"], user_id, work,
        "registration recovery differs from the independently authenticated user")
    evidence.plan._same(subject["sessionId"], session_id, work,
        "registration recovery differs from the independently authenticated session")
    current()
    # This genuine exchange supplies only THIS call's historical pending
    # expectations. No incoming successful-verification carrier can skip it.
    exchanged = history._verify_on_configuration(**common, originals=held,
        live_window=window, work=work, transport_deadline_ns=bound)
    current()
    candidate = completion.pending._admit_for_completion_on_work(
        operation=completion.OPERATION, originals=held[5:8], expectations=exchanged.expectations,
        planner_public_key=exchanged.planner_public_key, operation_public_key=exchanged.evidence_public_key,
        enrollment_bytes=common["current_root_enrollment_bytes"], root_public_key=common["root_public_key"],
        reserve_request_bytes=reserved[0], reserve_receipt_bytes=reserved[2], snapshot_bytes=reserved[1],
        expected_database_id=exchanged.database_id, expected_generation_digest=exchanged.generation_digest,
        expected_pending_sequence=pending[0], expected_pending_head_digest=pending[1], expected_fence=pending[2],
        live_window=window, work=work, transport_deadline_ns=bound)
    completion.completion._verify_grant_on_work(candidate=candidate, grant_raw=held[9],
        grant_enrollment=common["grant_enrollment_bytes"], enrollment=common["current_root_enrollment_bytes"],
        root_public_key=common["root_public_key"], planner_public_key=exchanged.planner_public_key,
        operation_public_key=exchanged.evidence_public_key,
        authorization_digest=exchanged.authorization_digest, work=work)
    current()
    retained = observed.completion_reconciled or observed.completion_outcome
    if retained is not None and retained.originals[0] == b"acknowledged":
        returned = retained.originals
    else:
        # The independent cold packet pin is NEVER taken from unsigned SQL or
        # returned completion data. One explicitly authorized recovery exchange
        # can retrieve/complete existing committed evidence; it sends no SQL.
        request = wire._originals((wire.PURPOSE, packet.encode("ascii")), response=False)
        returned = evidence.production._callback(work,
            lambda: wire._socket_request(endpoint, originals=request, deadline_ns=bound))
    current()
    returned = wire._originals(returned, response=True)
    if original_bytes + sum(len(raw) for raw in returned) > completion.MAX_ORIGINAL_BYTES:
        raise RegistrationRecoveryOutcomeError(digest)
    completion_history._verify_on_configuration(**common, originals=held,
        reservation_originals=reserved, response_originals=returned,
        expected_pending_sequence=pending[0], expected_pending_head_digest=pending[1], expected_fence=pending[2],
        live_window=window, work=work, transport_deadline_ns=bound)
    current()
    # Reconciliation never overwrites an uncertain original. The journal's
    # separate single slot is immutable, quota-bounded and fsynced; storage by
    # itself authenticates nothing. Every reused result is replayed above.
    if observed.completion_outcome is not None and observed.completion_outcome.originals[0] == b"uncertain":
        append = custody_client.ControlPlaneCustodyClient.append_registration_completion_reconciliation
    else:
        append = custody_client.ControlPlaneCustodyClient.append_registration_completion_outcome
    evidence.production._callback(work, lambda: append(custody, digest, returned))
    current()
    return returned


def recover_retained_registration_completion(local_digest, *, expected_user_id, expected_session_id):
    """Present-purpose facade returning authenticated original raw4 plus local ID."""
    from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork

    digest = journal._digest(local_digest)
    user_id, session_id = handoff._expected_subject(expected_user_id, expected_session_id)
    work = _ValidationWork(QueryReadValidationLimits())
    owner, material, binding, window = subjects._open_on_work(work)
    callback = evidence.production._callback
    try:
        returned = startup._EnrollmentOwner._recover_retained_registration_completion(owner,
            local_digest=digest, expected_user_id=user_id, expected_session_id=session_id,
            live_window=window, work=work, transport_deadline_ns=window[4])
        if (callback(work, startup.require_started) is not owner or owner._material is not material
                or owner._binding is not binding
                or callback(work, subjects.custody_startup.require_started) is not owner._custody):
            raise RegistrationRecoveryOutcomeError(digest)
        now = clock._check_on_work(window, work=work)
        archived = material.registration_history
        if (archived is not None
                and not archived.valid_from_epoch_ns <= now < archived.valid_until_epoch_ns):
            raise RegistrationRecoveryOutcomeError(digest)
    except Exception as exc:
        raise RegistrationRecoveryOutcomeError(digest) from exc
    return digest, returned
