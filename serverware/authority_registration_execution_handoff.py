"""Original-input preflight for private registration SQL/completion callers.

SQL preflight genuinely admits live caller/plan controls and replays the full
pending/grant scope before any caller sends. Unsigned SQL responses are checked
only against the same-call marker; packet locators never become authority.

The completion adapter is explicitly LIVE-only: existing planning exchange,
caller authorization and grant controls must remain valid. It is not historical
recovery, does not bypass expiry and cannot reconstruct independent history from
a receipt. No network, SQL, signing, storage, new work or public caller exists
here. Private returned observations are not accepted as admission tokens.
"""
from __future__ import annotations

from dataclasses import dataclass
import time

from serverware import authority_registration_execution_sql_admission as admission
from serverware import authority_registration_execution_sql_transport as sql_transport
from serverware import authority_registration_completion_response as completion_response
from serverware import authority_successor_execution_admission as execution
from serverware import authority_successor_execution_owner as owners


evidence, clock, authorization = admission.evidence, admission.clock, admission.current_root
OPERATION = admission.authorization.OPERATION


class RegistrationExecutionHandoffError(ValueError):
    pass


class RegistrationExecutionHandoffUncertainError(RegistrationExecutionHandoffError):
    """No established outcome, receipt, authority or automatic retry permission."""


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _AdmittedSqlHandoff:
    """Same-call original arguments and replay marker, never a public token."""

    issue_arguments: dict
    live_window: tuple
    deadline_ns: int
    live: object
    marker: dict


def _marker_on_work(marker, work):
    ledger = evidence.capture._SharedLedger(work)
    owned = evidence.capture._JSONCapture(ledger, maximum_bytes=4096).visit(marker)
    shape = authorization.shape
    shape._object(owned, frozenset(execution.pending._MARKER_COLUMNS),
        "registration handoff marker")
    shape._literal(owned["source_revision"], authorization.authority.SOURCE_REVISION)
    shape._literal(owned["operation"], OPERATION)
    shape._digest(owned["pending_decision_digest"])
    return owned


def _admit_sql_on_configuration(*, payload, configuration_digest, generation,
        runtime_role_identities, originals, reservation_originals,
        authorization_enrollment_bytes, grant_enrollment_bytes, current_root_enrollment_bytes,
        root_public_key, expected_pending_sequence, expected_pending_head_digest,
        expected_fence, deadline_epoch_ns, transport_deadline_ns, work):
    """Perform genuine live original admission before a private SQL send."""
    admitted = admission._admit_on_configuration(payload=payload,
        configuration_digest=configuration_digest, generation=generation,
        runtime_role_identities=runtime_role_identities, originals=originals,
        reservation_originals=reservation_originals,
        authorization_enrollment_bytes=authorization_enrollment_bytes,
        grant_enrollment_bytes=grant_enrollment_bytes,
        current_root_enrollment_bytes=current_root_enrollment_bytes, root_public_key=root_public_key,
        expected_pending_sequence=expected_pending_sequence,
        expected_pending_head_digest=expected_pending_head_digest, expected_fence=expected_fence,
        deadline_epoch_ns=deadline_epoch_ns, transport_deadline_ns=transport_deadline_ns, work=work)
    admitted.live()
    candidate = execution._admit_on_work(**admitted.issue_arguments,
        live_window=admitted.live_window, work=work, transport_deadline_ns=admitted.deadline_ns)
    checked_now = admitted.live()
    marker = _marker_on_work(candidate.marker, work)
    # A reserve may expire before its grant. Keep the original opening bracket
    # and make the caller's retained live guard enforce that narrower bound.
    original_window = admitted.live_window
    expires = min(original_window[3], candidate.original_interval[1])
    window = clock._validate((original_window[0], original_window[1], original_window[2],
        expires, original_window[1] + expires - original_window[0],
        original_window[5], original_window[6]))
    bound = min(admitted.deadline_ns, window[4])
    last_epoch, last_monotonic = checked_now, window[2]

    def live():
        nonlocal last_epoch, last_monotonic
        authorized_now = admitted.live()
        now = clock._check_on_work(window, work=work)
        monotonic = evidence.production._callback(work, time.monotonic_ns)
        authorization.shape._integer(monotonic, minimum=1)
        if (now < authorized_now or now < last_epoch or monotonic < last_monotonic
                or monotonic >= bound):
            raise RegistrationExecutionHandoffError("registration SQL handoff expired or its clocks reversed")
        last_epoch, last_monotonic = now, monotonic
        return now

    live()
    return _AdmittedSqlHandoff(admitted.issue_arguments, window, bound, live, marker)


def _verify_sql_response_on_work(*, response_originals, expected_marker, work):
    """Check an unsigned response only against this caller's same-call marker.

    This private equality check accepts no successful SQL carrier. The caller
    must supply its genuine preflight marker and bracket the exchange and this
    check with the retained live guard. No packet-ID authenticity is inferred.
    """
    evidence.capture._SharedLedger(work)
    returned = sql_transport._originals(response_originals, response=True)
    marker = _marker_on_work(expected_marker, work)
    if returned[0] == b"uncertain":
        raise RegistrationExecutionHandoffUncertainError("registration SQL outcome is not established")
    work.charge(input_bytes=len(returned[1]) + len(returned[3]))
    pending_digest = returned[1].decode("ascii")
    try:
        marker_text = returned[3].decode("ascii")
    except UnicodeDecodeError:
        raise RegistrationExecutionHandoffError("registration SQL marker is not canonical ASCII") from None
    evidence.plan._same(pending_digest, marker["pending_decision_digest"], work,
        "registration SQL locator differs from the genuine pending marker")
    # Reuse the actual owner's source-fixed scalar/source/sequence validation
    # and canonical parser, then compare every field to the held replay marker.
    original = owners._marker_on_work(marker_text, pending_digest, work)
    authorization.capability._canonical(original, marker,
        evidence.capture._SharedLedger(work), 4096, 64)
    return returned


def _verify_live_completion_on_configuration(*, payload, configuration_digest, generation,
        runtime_role_identities, originals, reservation_originals, response_originals,
        authorization_enrollment_bytes, grant_enrollment_bytes, current_root_enrollment_bytes,
        root_public_key, expected_pending_sequence, expected_pending_head_digest,
        expected_fence, deadline_epoch_ns, transport_deadline_ns, work):
    """Verify completion only while original planning/caller/grant gates live.

    This is deliberately not historical recovery. Authenticating expired
    planning exchange/caller originals requires a separate genuine historical
    path; this function never labels a live verifier as such a path.
    """
    evidence.capture._SharedLedger(work)
    held = admission.transport._originals(originals, response=False)
    reserved = admission.transport._originals(reservation_originals, response=True)
    returned = completion_response.transport._originals(response_originals, response=True)
    caller_enrollment = authorization._original(authorization_enrollment_bytes,
        admission.authorization.MAX_ENROLLMENT_BYTES, "completion handoff caller enrollment")
    grant_enrollment = authorization._original(grant_enrollment_bytes,
        admission.grants.MAX_ENROLLMENT_BYTES, "completion handoff grant enrollment")
    current_enrollment = authorization._original(current_root_enrollment_bytes,
        authorization.MAX_ENROLLMENT_BYTES, "completion handoff current-root enrollment")
    if sum(len(raw) for raw in (*held, *reserved, *returned, caller_enrollment,
            grant_enrollment, current_enrollment)) > admission.exchange.MAX_ORIGINAL_BYTES:
        raise RegistrationExecutionHandoffError("completion handoff originals exceed the aggregate source bound")
    admitted = admission._admit_on_configuration(payload=payload,
        configuration_digest=configuration_digest, generation=generation,
        runtime_role_identities=runtime_role_identities, originals=held,
        reservation_originals=reserved, authorization_enrollment_bytes=caller_enrollment,
        grant_enrollment_bytes=grant_enrollment, current_root_enrollment_bytes=current_enrollment,
        root_public_key=root_public_key, expected_pending_sequence=expected_pending_sequence,
        expected_pending_head_digest=expected_pending_head_digest, expected_fence=expected_fence,
        deadline_epoch_ns=deadline_epoch_ns, transport_deadline_ns=transport_deadline_ns, work=work)
    admitted.live()
    args = admitted.issue_arguments
    # The response verifier performs the one heavy historical plan replay.
    # Existing live exchange/caller/grant checks supplement that replay and
    # remain mandatory on both sides; no SQL admission carrier is passed in.
    result = completion_response._verify_on_work(response_originals=returned,
        plan_originals=args["originals"], reserve_request_bytes=args["reserve_request_bytes"],
        reserve_receipt_bytes=args["reserve_receipt_bytes"], snapshot_bytes=args["snapshot_bytes"],
        enrollment_bytes=args["enrollment_bytes"], grant_bytes=args["grant_bytes"],
        grant_enrollment_bytes=args["grant_enrollment_bytes"], expectations=args["expectations"],
        planner_public_key=args["planner_public_key"], evidence_public_key=args["operation_public_key"],
        root_public_key=args["root_public_key"], expected_authorization_digest=args["expected_authorization_digest"],
        expected_database_id=args["expected_database_id"],
        expected_generation_digest=args["expected_generation_digest"],
        expected_pending_sequence=args["expected_pending_sequence"],
        expected_pending_head_digest=args["expected_pending_head_digest"], expected_fence=args["expected_fence"],
        live_window=admitted.live_window, work=work, transport_deadline_ns=admitted.deadline_ns)
    admitted.live()
    return result
