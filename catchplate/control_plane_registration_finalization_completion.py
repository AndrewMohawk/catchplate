"""Explicit retained finalization completion and uncertainty recovery.

The actual application must FIRST admit the present user/session and the
separate complete or recover purpose. Fixed public handlers own those checks;
these private facades are not HTTP routes and accept no public proof dictionary.
Each call repeats genuine historical retained ownership and pending/grant replay
under the actual cold owner's lock; no inspected subject object is accepted.

One independently pinned packet request may reach the completion service. No
SQL is sent or retried. A bounded first response is retained as opaque original
data before semantic acceptance under the original window. Every acknowledged result is genuinely
reverified; only explicitly requested recovery may fetch after uncertainty and
append a distinct authenticated reconciliation. Earlier uncertainty stays put.
Neither outcome nor error activates a session or proves action-time currentness.
"""
from __future__ import annotations

from dataclasses import dataclass

from catchplate import authority_registration_finalization_completion_history as admission
from catchplate import control_plane_registration_finalization_completion_subject as subjects


startup, evidence, clock = subjects.startup, subjects.evidence, subjects.clock
custody_client, journal, wire = subjects.custody_client, subjects.journal, subjects.wire
_PERSISTENCE_RESERVATION_BYTES = journal.FINALIZATION_COMPLETION_APPEND_BYTES


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _CompletionReturn:
    """Same-call originals and final cleanup guard, never accepted as authority."""

    originals: tuple[bytes, ...]
    current: object


class RetainedFinalizationCompletionOutcomeError(ValueError):
    """Submitted locator only; no result, durability, noncommit or retry claim."""

    __slots__ = ("local_digest",)

    def __init__(self, local_digest):
        self.local_digest = journal._digest(local_digest)
        super().__init__("finalization completion outcome is not established; automatic retry is not allowed")


def _complete_on_owner(owner, *, local_digest, expected_user_id, expected_session_id,
        recovery, live_window, transport_deadline_ns, work):
    """Replay actual ownership before at most one fixed completion exchange."""
    digest = journal._digest(local_digest)
    user_id, session_id = subjects.handoff._expected_subject(expected_user_id, expected_session_id)
    if type(recovery) is not bool:
        raise RetainedFinalizationCompletionOutcomeError(digest)
    selected = subjects._inspect_material_on_owner(owner, digest, live_window=live_window,
        transport_deadline_ns=transport_deadline_ns, work=work,
        _additional_original_bytes=_PERSISTENCE_RESERVATION_BYTES)
    subject, held, reserved, observed = (selected.subject, selected.originals,
        selected.reservation_originals, selected.observed)
    common, endpoint = selected.common, selected.endpoint
    window, bound, current = selected.window, selected.deadline_ns, selected.current
    original_bytes = selected.original_bytes
    evidence.plan._same(subject["userId"], user_id, work,
        "finalization completion differs from the independently authenticated current user")
    evidence.plan._same(subject["sessionId"], session_id, work,
        "finalization completion differs from the independently authenticated current session")
    current()
    custody = owner._custody
    pending = selected.current_pending
    if not original_bytes <= selected.original_reservation_bytes <= subjects.completion.MAX_ORIGINAL_BYTES:
        raise RetainedFinalizationCompletionOutcomeError(digest)
    previous = observed.completion_reconciled or observed.completion_outcome
    uncertain = previous is not None and previous.originals[0] == b"uncertain"
    if uncertain and not recovery:
        # Initial completion never implicitly converts into a recovery action.
        raise RetainedFinalizationCompletionOutcomeError(digest)
    if previous is not None and not uncertain:
        returned = wire._originals(previous.originals, response=True)
    else:
        # Packet selection is root-admitted. Neither an unsigned SQL packet ID
        # nor a completion response supplies the expected request locator.
        request = wire._originals((wire.PURPOSE,
            selected.completion_packet_digest.encode("ascii")), response=False)
        # Fixed wire maxima were reserved before the first history body. Charge
        # the bounded request/response framing once on the original work; the
        # transport itself keeps the original deadline through normal close.
        work.charge(input_bytes=2 * (wire.MAX_REQUEST_BYTES + wire.MAX_RESPONSE_BYTES)
            + 4 * (len(wire.REQUEST_MAGIC) + 8 * len(wire.REQUEST_LIMITS))
            + 3 * (len(wire.RESPONSE_MAGIC) + 8 * len(wire.RESPONSE_LIMITS)))
        current()
        returned = evidence.production._callback(work,
            lambda: wire._socket_request(endpoint, originals=request, deadline_ns=bound))
        returned = wire._originals(returned, response=True)
        current()
        if previous is None:
            # Retain DATA before semantic admission, while the actual owner and
            # original window still hold. A failed/late publication stays
            # uncertain; neither a missing record nor an error permits SQL retry.
            custody_client.ControlPlaneCustodyClient.append_registration_finalization_completion_outcome(
                custody, digest, returned, work=work, current=current,
                maximum_original_bytes=_PERSISTENCE_RESERVATION_BYTES)
    current()
    if original_bytes + sum(len(raw) for raw in returned) > subjects.completion.MAX_ORIGINAL_BYTES:
        raise RetainedFinalizationCompletionOutcomeError(digest)
    # The wrapper actually authenticates historical original controls, full
    # vectors, completion and state signatures. No raw4 status is authority.
    admission._verify_on_configuration(**common, originals=held,
        reservation_originals=reserved, response_originals=returned,
        expected_pending_sequence=pending[0], expected_pending_head_digest=pending[1],
        expected_fence=pending[2], live_window=window, work=work, transport_deadline_ns=bound)
    current()
    if uncertain:
        custody_client.ControlPlaneCustodyClient.append_registration_finalization_completion_reconciliation(
            custody, digest, returned, work=work, current=current,
            maximum_original_bytes=_PERSISTENCE_RESERVATION_BYTES)
        current()
    return _CompletionReturn(returned, current)


def _run(local_digest, *, expected_user_id, expected_session_id, recovery):
    from catchplate.authority_query_read_work import QueryReadValidationLimits, _ValidationWork

    digest = journal._digest(local_digest)
    user_id, session_id = subjects.handoff._expected_subject(expected_user_id, expected_session_id)
    work = _ValidationWork(QueryReadValidationLimits())
    callback = evidence.production._callback
    try:
        owner, material, binding, window = subjects._open_on_work(work)
        custody = owner._custody
        # The concrete owner method holds its actual lock and repeats original
        # ownership. A previously inspected eight-field subject is never input.
        method = (startup._EnrollmentOwner._recover_retained_registration_finalization_completion
            if recovery else startup._EnrollmentOwner._request_retained_registration_finalization_completion)
        completed = method(owner, local_digest=digest,
            expected_user_id=user_id, expected_session_id=session_id,
            live_window=window, transport_deadline_ns=window[4], work=work)
        # The actual owner method has now released its lock normally. Retain
        # the very same selected archive/resource/time guard through this
        # boundary; no new historical selection or processing window is opened.
        if type(completed) is not _CompletionReturn or not callable(completed.current):
            raise RetainedFinalizationCompletionOutcomeError(digest)
        completed.current()
        if (owner._material is not material or owner._binding is not binding
                or owner._custody is not custody or callback(work, startup.require_started) is not owner
                or callback(work, subjects.custody_startup.require_started) is not custody):
            raise RetainedFinalizationCompletionOutcomeError(digest)
        clock._check_on_work(window, work=work)
        returned = wire._originals(completed.originals, response=True)
        completed.current()
    except Exception as exc:
        raise RetainedFinalizationCompletionOutcomeError(digest) from exc
    return digest, returned


def request_retained_registration_finalization_completion(local_digest, *, expected_user_id, expected_session_id):
    """Return (same local ID, authenticated raw4) after separate complete permission."""
    return _run(local_digest, expected_user_id=expected_user_id,
        expected_session_id=expected_session_id, recovery=False)


def recover_retained_registration_finalization_completion(local_digest, *, expected_user_id, expected_session_id):
    """Return (same local ID, authenticated raw4) after separate recovery permission."""
    return _run(local_digest, expected_user_id=expected_user_id,
        expected_session_id=expected_session_id, recovery=True)
