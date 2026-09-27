"""Explicit retained-registration finalization PREPARATION, never success.

Present finalization-purpose permission must be admitted separately by the
real application before this facade. A local execution/evidence-admission ID
is only a locator. Actual cold owners, joined live signer/grant replay and
genuine stored acknowledged completion are required before the existing LIVE
finalization planner/custody path can prepare and durably retain raw7.

No recovery, completion-service request, evidence SQL dispatch, signing,
transition forwarding or finalization execution is performed. Returned IDs
locate original preparations; they do not assert a registered credential,
active session, current root, one-use effect or permission to retry.
This path does not issue the dedicated finalization execution authorization.
That authorization must precede a production plan's issue time; a later fresh
authorization cannot make this prepared-only raw7 executable retroactively.
"""
from __future__ import annotations

from serverware import control_plane_registration_handoff as handoff
from serverware import control_plane_registration_handoff_subject as subjects
from serverware import control_plane_registration_preparation as preparation


execution, custody_client, journal = handoff.execution, handoff.custody_client, handoff.journal
startup, evidence, clock = execution.startup, execution.evidence, execution.clock


class RetainedRegistrationFinalizationError(preparation.RegistrationPreparationError):
    pass


def _prepare_on_owner(owner, digest, *, expected_user_id, expected_session_id,
        live_window, work):
    """Continue only under the actual owner's lock and the same current work."""
    window = clock._validate(live_window)
    common, _endpoint, _key, deadline, bound, owner_live = execution._scope(owner,
        deadline_epoch_ns=window[3], deadline_ns=window[4], work=work, _endpoint_kind="completion")
    # Preserve the original opening bracket even when the actual cold scope
    # supplies an earlier bound; do not open a window from completion times.
    expiry = min(window[3], deadline)
    window = clock._validate((window[0], window[1], window[2], expiry,
        window[1] + expiry - window[0], window[5], window[6]))
    bound = min(bound, window[4])
    custody, binding, material = owner._custody, owner._binding, owner._material
    pending = material.execution.current_pending
    callback = evidence.production._callback

    def current():
        owner_live()
        if (owner._material is not material or owner._binding is not binding
                or owner._custody is not custody
                or callback(work, startup.require_started) is not owner
                or callback(work, subjects.custody_startup.require_started) is not custody
                or callback(work, lambda: custody_client._snapshot(custody)) is not binding):
            raise RetainedRegistrationFinalizationError("retained finalization cold owners changed")
        clock._check_on_work(window, work=work)
        callback(work, lambda: subjects.signer_wire._check_deadline(bound))
        owner_live()

    current()
    pair = callback(work, lambda: custody_client.ControlPlaneCustodyClient.load_registration_preparation(
        custody, digest))
    observed = callback(work, lambda: custody_client.ControlPlaneCustodyClient.load_registration_outcomes(
        custody, digest))
    if (type(pair) is not tuple or len(pair) != 2
            or any(type(record) is not subjects.records.PreparedRecord for record in pair)):
        raise RetainedRegistrationFinalizationError("retained finalization requires the actual associated pair")
    execution_record, signer_record = pair
    if (execution_record.digest != digest
            or (execution_record.family, execution_record.selector)
                != (subjects.execution_records.FAMILY, subjects.execution_records.OPERATION)
            or (signer_record.family, signer_record.selector)
                != (subjects.signer_records.FAMILY, subjects.signer_records.OPERATION)
            or execution_record.source_revision != evidence.authority.SOURCE_REVISION
            or signer_record.source_revision != execution_record.source_revision
            or observed.source_revision != execution_record.source_revision):
        raise RetainedRegistrationFinalizationError("retained finalization association has another source or family")
    if observed.reservation is None or observed.sql_attempt is None:
        raise RetainedRegistrationFinalizationError("retained finalization lacks reservation or dispatch originals")
    completed = observed.completion_reconciled or observed.completion_outcome
    if completed is None:
        raise RetainedRegistrationFinalizationError("retained finalization requires stored acknowledged completion")
    held = subjects.reservation_wire._originals(execution_record.originals, response=False)
    signer = subjects.signer_wire._request_originals(signer_record.originals)
    reserved = subjects.reservation_wire._originals(observed.reservation.originals, response=True)
    returned = handoff.completion_wire._originals(completed.originals, response=True)
    if returned[0] != b"acknowledged":
        raise RetainedRegistrationFinalizationError("uncertain completion cannot prepare registration finalization")
    enrollments = (common["authorization_enrollment_bytes"], common["grant_enrollment_bytes"],
        common["current_root_enrollment_bytes"])
    maxima = (execution.authorization.MAX_ENROLLMENT_BYTES, execution.receiving.grants.MAX_ENROLLMENT_BYTES,
        execution.receiving.grants.authorization.MAX_ENROLLMENT_BYTES)
    if any(type(raw) is not bytes or not 2 <= len(raw) <= maximum
            for raw, maximum in zip(enrollments, maxima)):
        raise RetainedRegistrationFinalizationError("retained finalization enrollments are not bounded originals")
    if sum(len(raw) for raw in (*held, *signer, *reserved, *returned, *enrollments)) > evidence.authority.MAX_RESULT_BYTES:
        raise RetainedRegistrationFinalizationError("retained finalization originals exceed their aggregate bound")
    current()
    # The local association is not user ownership or a grant/signature join.
    # This actual LIVE replay reconstructs the signer request and authenticates
    # the retained planning/grant exchange before comparing present caller IDs.
    subject = subjects._inspect_on_owner(owner, local_digest=digest,
        deadline_epoch_ns=window[3], deadline_ns=bound, work=work)
    evidence.plan._same(subject["userId"], expected_user_id, work,
        "retained finalization differs from the independently authenticated current user")
    evidence.plan._same(subject["sessionId"], expected_session_id, work,
        "retained finalization differs from the independently authenticated current session")
    current()
    # Stored state labels/IDs never authenticate completion. Use the genuine
    # original receiver with independent cold pending pins, not response heads.
    # This remains live-only for caller/plan/grant scope even if the stored
    # acknowledged result came from a separately authorized reconciliation.
    handoff.admission._verify_live_completion_on_configuration(**common,
        originals=held, reservation_originals=reserved, response_originals=returned,
        expected_pending_sequence=pending[0], expected_pending_head_digest=pending[1], expected_fence=pending[2],
        deadline_epoch_ns=window[3], transport_deadline_ns=bound, work=work)
    current()
    finalization_digest = preparation._prepare_registration_finalization_on_work(
        request_originals=signer[:8], response_originals=signer[8:], live_window=window,
        transport_deadline_ns=bound, work=work)
    # The unchanged preparation tail may finish its opaque durable append
    # after the processing window. That is retention, never renewed authority.
    return digest, journal._digest(finalization_digest)


def prepare_retained_registration_finalization(local_digest, *, expected_user_id, expected_session_id):
    """Return (input execution/evidence-admission ID, retained finalization ID).

    There is no manufactured legacy raw6 evidence record. Both outputs are
    local locators only; the second is the actual appended transition raw7.
    """
    from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork

    startup._require_pid()
    digest = journal._digest(local_digest)
    user_id, session_id = handoff._expected_subject(expected_user_id, expected_session_id)
    work = _ValidationWork(QueryReadValidationLimits())
    callback = evidence.production._callback
    owner = callback(work, startup.require_started)
    if (type(owner) is not startup._EnrollmentOwner
            or not callback(work, lambda: owner.sql_handoff_enabled)
            or callback(work, subjects.custody_startup.require_started) is not owner._custody):
        raise RetainedRegistrationFinalizationError("retained finalization requires both cold-enabled owners")
    material, binding = owner._material, owner._binding
    window = clock._open_on_work(deadline_epoch_ns=binding.attestation_interval[1],
        maximum_lifetime_ns=min(binding.maximum_deadline_ns, evidence.authority.VERIFIER_RESPONSE_MAX_AGE_NS),
        maximum_clock_skew_ns=material.issuer_policy["maximumClockSkewNs"], work=work)
    startup._require_pid()
    with startup._LOCK:
        if owner._material is not material or owner._binding is not binding:
            raise RetainedRegistrationFinalizationError("retained finalization startup changed before preparation")
        clock._check_on_work(window, work=work)
        return _prepare_on_owner(owner, digest, expected_user_id=user_id,
            expected_session_id=session_id, live_window=window, work=work)
