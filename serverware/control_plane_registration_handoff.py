"""Private retained-original SQL dispatch and live completion handoff.

Separate present-actor and purpose authorization must precede either action.
Local record IDs supply only selectors. Actual cold owners provide endpoints,
enrollments and independent pending/packet pins. Explicit public handlers admit
their present caller and action permission first. Neither action finalizes a
credential or activates a session.

The durable local claim precedes the single SQL send and is never cleared.
SQL responses are retained as unsigned observations before semantic admission.
Only genuinely authenticated completion originals are retained as completion
outcomes. Every call keeps its original work/deadline; no automatic retry,
signing, checkpoint advancement or historical-expiry bypass is provided.
"""
from __future__ import annotations

from serverware import control_plane_registration_execution as execution
from serverware import control_plane_custody_client as custody_client
from serverware import control_plane_custody_journal as journal
from serverware import authority_registration_execution_handoff as admission
from serverware import authority_registration_execution_sql_admission as control_admission
from serverware import authority_registration_execution_sql_transport as sql_wire
from serverware import authority_registration_completion_transport as completion_wire
from serverware import authority_registration_reservation_transport as reserve_wire


evidence, clock, startup = execution.evidence, execution.clock, execution.startup


class RegistrationHandoffOutcomeError(ValueError):
    """Submitted local selector only; no retention, remote outcome or retry proof."""

    def __init__(self, local_digest):
        super().__init__("registration handoff outcome is not established; automatic retry is not allowed")
        self.local_digest = journal._digest(local_digest)


def _retained(owner, digest, work, live):
    custody = owner._custody
    if type(custody) is not custody_client.ControlPlaneCustodyClient:
        raise startup.EnrollmentStartupError("registration handoff requires actual custody")
    callback = evidence.production._callback
    binding = callback(work, lambda: custody_client._snapshot(custody))
    if binding is not owner._binding:
        raise startup.EnrollmentStartupError("registration handoff cold owners differ")
    pair = callback(work, lambda: custody_client.ControlPlaneCustodyClient.load_registration_preparation(
        custody, digest))
    observed = callback(work, lambda: custody_client.ControlPlaneCustodyClient.load_registration_outcomes(
        custody, digest))
    if observed.reservation is None:
        raise startup.EnrollmentStartupError("registration handoff lacks retained reservation originals")
    held = reserve_wire._originals(pair[0].originals, response=False)
    reserved = reserve_wire._originals(observed.reservation.originals, response=True)
    # Same-call storage observations never substitute for original replay.
    # Preserve all byte bounds before creating the combined transport tuple.
    if sum(len(raw) for raw in (*held, *reserved)) > sql_wire.MAX_REQUEST_BYTES:
        raise startup.EnrollmentStartupError("registration handoff originals exceed their aggregate bound")

    def current():
        live()
        if (owner._custody is not custody or owner._binding is not binding
                or callback(work, lambda: custody_client._snapshot(custody)) is not binding):
            raise startup.EnrollmentStartupError("registration handoff custody changed")
        live()

    current()
    return custody, held, reserved, observed, current


def _arguments(common, held, reserved, pending, deadline, bound, work):
    return dict(common, originals=held, reservation_originals=reserved,
        expected_pending_sequence=pending[0], expected_pending_head_digest=pending[1],
        expected_fence=pending[2], deadline_epoch_ns=deadline,
        transport_deadline_ns=bound, work=work)


def _expected_subject(user_id, session_id):
    from serverware import control_plane_registration_execution_intent as intent

    intent._text(user_id, 4096)
    if session_id is not None:
        intent._text(session_id, 4096)
    return user_id, session_id


def _subject_scope(owner, digest, expected_user_id, expected_session_id, deadline, bound, work):
    from serverware import control_plane_registration_handoff_subject as subjects

    subject = subjects._inspect_on_owner(owner, local_digest=digest,
        deadline_epoch_ns=deadline, deadline_ns=bound, work=work)
    evidence.plan._same(subject["userId"], expected_user_id, work,
        "registration handoff differs from the independently authenticated user")
    evidence.plan._same(subject["sessionId"], expected_session_id, work,
        "registration handoff differs from the independently authenticated session")


def _execute_on_owner(owner, *, local_digest, expected_user_id, expected_session_id,
        deadline_epoch_ns, deadline_ns, work):
    digest = journal._digest(local_digest)
    expected_user_id, expected_session_id = _expected_subject(expected_user_id, expected_session_id)
    common, endpoint, _key, deadline, bound, live = execution._scope(owner,
        deadline_epoch_ns=deadline_epoch_ns, deadline_ns=deadline_ns,
        work=work, _endpoint_kind="sql")
    pending = owner._material.execution.current_pending
    custody, held, reserved, observed, current = _retained(owner, digest, work, live)
    if observed.sql_attempt is not None:
        raise RegistrationHandoffOutcomeError(digest)
    checked = admission._admit_sql_on_configuration(
        **_arguments(common, held, reserved, pending, deadline, bound, work))
    _subject_scope(owner, digest, expected_user_id, expected_session_id,
        deadline, min(bound, checked.deadline_ns), work)
    current()
    checked.live()
    callback = evidence.production._callback
    # The actual journal performs the indivisible duplicate check and durable
    # publication. Neither a failure nor a missing response releases this claim.
    callback(work, lambda: custody_client.ControlPlaneCustodyClient.claim_registration_sql_attempt(
        custody, digest))
    current()
    checked.live()
    work.charge(input_bytes=sum(len(raw) for raw in (*held, *reserved)))
    returned = callback(work, lambda: sql_wire._socket_request(endpoint,
        originals=held + reserved, deadline_ns=min(bound, checked.deadline_ns)))
    # Retain even an uncertain response as opaque observation. Publication is
    # not semantic verification and does not renew the original authority.
    callback(work, lambda: custody_client.ControlPlaneCustodyClient.append_registration_sql_outcome(
        custody, digest, returned))
    current()
    checked.live()
    result = admission._verify_sql_response_on_work(response_originals=returned,
        expected_marker=checked.marker, work=work)
    current()
    checked.live()
    return result


def _complete_on_owner(owner, *, local_digest, expected_user_id, expected_session_id,
        deadline_epoch_ns, deadline_ns, work):
    digest = journal._digest(local_digest)
    expected_user_id, expected_session_id = _expected_subject(expected_user_id, expected_session_id)
    common, endpoint, _key, deadline, bound, live = execution._scope(owner,
        deadline_epoch_ns=deadline_epoch_ns, deadline_ns=deadline_ns,
        work=work, _endpoint_kind="completion")
    configured = owner._material.execution
    pending, packet = configured.current_pending, configured.completion_packet_digest
    custody, held, reserved, observed, current = _retained(owner, digest, work, live)
    if observed.sql_attempt is None:
        raise startup.EnrollmentStartupError("registration completion has no retained SQL dispatch claim")
    arguments = _arguments(common, held, reserved, pending, deadline, bound, work)
    # Authenticate live caller/grant/control/history before contacting a
    # side-effecting completion service. Full pending replay follows on the
    # returned originals; the service independently admits its fixed packet.
    admitted = control_admission._admit_on_configuration(**arguments)
    _subject_scope(owner, digest, expected_user_id, expected_session_id,
        deadline, min(bound, admitted.deadline_ns), work)
    current()
    admitted.live()
    if observed.completion_outcome is None:
        # Never use the unsigned SQL packet ID or a returned receipt as scope.
        request = completion_wire._originals((completion_wire.PURPOSE, packet.encode("ascii")), response=False)
        returned = evidence.production._callback(work, lambda: completion_wire._socket_request(
            endpoint, originals=request, deadline_ns=min(bound, admitted.deadline_ns)))
    else:
        # Retained genuine originals are reverified; they do not authorize a
        # new network request or refresh the original grant's lifetime.
        returned = observed.completion_outcome.originals
    current()
    admitted.live()
    admission._verify_live_completion_on_configuration(**arguments, response_originals=returned)
    current()
    admitted.live()
    evidence.production._callback(work,
        lambda: custody_client.ControlPlaneCustodyClient.append_registration_completion_outcome(
            custody, digest, returned))
    current()
    admitted.live()
    return returned


def _action(local_digest, *, expected_user_id, expected_session_id, completion):
    from serverware import control_plane_custody_startup as custody_startup
    from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork

    digest = journal._digest(local_digest)
    user_id, session_id = _expected_subject(expected_user_id, expected_session_id)
    work = _ValidationWork(QueryReadValidationLimits())
    callback = evidence.production._callback
    owner = callback(work, startup.require_started)
    if (type(owner) is not startup._EnrollmentOwner
            or not callback(work, lambda: owner.sql_handoff_enabled)
            or callback(work, custody_startup.require_started) is not owner._custody):
        raise startup.EnrollmentStartupError("registration handoff is not cold-enabled")
    material, binding = owner._material, owner._binding
    endpoint = material.execution.completion_endpoint if completion else material.execution.sql_endpoint
    window = clock._open_on_work(deadline_epoch_ns=binding.attestation_interval[1],
        maximum_lifetime_ns=min(binding.maximum_deadline_ns, int(endpoint[1] * 1_000_000_000),
            evidence.authority.VERIFIER_RESPONSE_MAX_AGE_NS),
        maximum_clock_skew_ns=material.issuer_policy["maximumClockSkewNs"], work=work)
    try:
        if (owner._material is not material or owner._binding is not binding
                or callback(work, startup.require_started) is not owner
                or callback(work, custody_startup.require_started) is not owner._custody):
            raise startup.EnrollmentStartupError("registration handoff cold owners changed before dispatch")
        clock._check_on_work(window, work=work)
        call = (startup._EnrollmentOwner._request_retained_registration_completion if completion
            else startup._EnrollmentOwner._execute_retained_registration)
        result = call(owner, local_digest=digest, expected_user_id=user_id,
            expected_session_id=session_id, deadline_epoch_ns=window[3],
            deadline_ns=window[4], work=work)
        if (callback(work, startup.require_started) is not owner or owner._material is not material
                or owner._binding is not binding or callback(work, custody_startup.require_started) is not owner._custody):
            raise startup.EnrollmentStartupError("registration handoff cold owners changed")
        clock._check_on_work(window, work=work)
    except Exception as exc:
        # A known-shaped selector is still not proof that retention or any
        # particular remote effect succeeded. Cancellation propagates.
        raise RegistrationHandoffOutcomeError(digest) from exc
    return digest, result


def execute_retained_registration(local_digest, *, expected_user_id, expected_session_id):
    """Private present-purpose action; returns only unsigned SQL raw4 and ID."""
    return _action(local_digest, expected_user_id=expected_user_id,
        expected_session_id=expected_session_id, completion=False)


def request_retained_registration_completion(local_digest, *, expected_user_id, expected_session_id):
    """Private LIVE-original action; returns authenticated raw4 and local ID."""
    return _action(local_digest, expected_user_id=expected_user_id,
        expected_session_id=expected_session_id, completion=True)
