"""Explicit live reservation of a retained finalization grant, never SQL.

A local finalization association locates originals, not their owner or an
execution permission. Inspection authenticates the complete finalization grant
and plan, the associated signer/evidence exchange and acknowledged completion,
then compares the entire finalization request regenerated from THAT signer.
Only its already-proven sibling inventory is reused as reconstruction hints.

The actual application must admit the separate present reservation purpose.
Dispatch repeats inspection under the cold owner lock and compares independent
current-user/session scalars, without accepting an earlier subject dictionary.
One work/window spans replay, one actual exchange and genuine returned raw3
admission. Opaque durable retention cannot renew it. No preparation, signing,
automatic retry/recovery, SQL, completion or session activation occurs here.
"""
from __future__ import annotations

from serverware import authority_registration_finalization_execution_admission as admission
from serverware import authority_registration_finalization_reservation_transport as transport
from serverware import authority_webauthn_registration_signer_response as signer_response
from serverware import control_plane_registration_finalization as retained
from serverware import control_plane_registration_finalization_execution as caller
from serverware import control_plane_registration_finalization_records as finalization_records


startup, evidence, clock = caller.startup, caller.evidence, caller.clock
subjects, handoff = retained.subjects, retained.handoff
custody_client, journal = retained.custody_client, retained.journal


class RetainedFinalizationReservationError(ValueError):
    """Failure may follow remote or local durability; it grants no retry."""


def _inspect_on_owner(owner, local_digest, *, live_window, transport_deadline_ns, work):
    """Return private same-call subject/originals/bounds, never an input token."""
    startup._require_pid()
    digest = journal._digest(local_digest)
    callback = evidence.production._callback
    if (type(owner) is not startup._EnrollmentOwner
            or not callback(work, lambda: owner.finalization_reservation_enabled)
            or not callback(work, lambda: owner.sql_handoff_enabled)):
        raise RetainedFinalizationReservationError("finalization reservation is not cold-enabled")
    material, binding, custody = owner._material, owner._binding, owner._custody
    common, _private, window, bound, owner_live = caller._scope(owner,
        live_window=live_window, transport_deadline_ns=transport_deadline_ns, work=work)
    admitted, retained_live, signer_limits = None, None, None

    def current():
        now = owner_live()
        if (owner._material is not material or owner._binding is not binding
                or owner._custody is not custody
                or not callback(work, lambda: owner.finalization_reservation_enabled)):
            raise RetainedFinalizationReservationError("finalization reservation cold scope changed")
        if retained_live is not None:
            retained_live()
        if admitted is not None:
            admitted.live()
        now = clock._check_on_work(window, work=work)
        callback(work, lambda: transport._check_deadline(bound))
        if signer_limits is not None and (now >= signer_limits[0] or now < signer_limits[2]):
            raise RetainedFinalizationReservationError("finalization signer originals expired or clocks reversed")
        owner_live()
        return now

    current()
    association = callback(work,
        lambda: custody_client.ControlPlaneCustodyClient.load_registration_finalization_preparation(
            custody, digest))
    if (type(association) is not tuple or len(association) != 3
            or type(association[0]) is not subjects.records.PreparedRecord
            or type(association[2]) is not tuple or len(association[2]) != 2
            or any(type(record) is not subjects.records.PreparedRecord for record in association[2])):
        raise RetainedFinalizationReservationError("finalization reservation requires actual retained originals")
    final_record, evidence_digest, pair = association
    evidence_record, signer_record = pair
    evidence_digest = journal._digest(evidence_digest)
    if (final_record.digest != digest or evidence_record.digest != evidence_digest
            or (final_record.family, final_record.selector)
                != (finalization_records.FAMILY, finalization_records.OPERATION)
            or (evidence_record.family, evidence_record.selector)
                != (subjects.execution_records.FAMILY, subjects.execution_records.OPERATION)
            or (signer_record.family, signer_record.selector)
                != (subjects.signer_records.FAMILY, subjects.signer_records.OPERATION)
            or final_record.source_revision != evidence.authority.SOURCE_REVISION
            or evidence_record.source_revision != final_record.source_revision
            or signer_record.source_revision != final_record.source_revision
            or len({digest, evidence_digest, signer_record.digest}) != 3):
        raise RetainedFinalizationReservationError("finalization association source or family differs")
    held = transport._originals(final_record.originals, response=False)
    evidence_originals = subjects.reservation_wire._originals(evidence_record.originals, response=False)
    signer = subjects.signer_wire._request_originals(signer_record.originals)
    observed = callback(work,
        lambda: custody_client.ControlPlaneCustodyClient.load_registration_outcomes(custody, evidence_digest))
    completed = observed.completion_reconciled or observed.completion_outcome
    if (observed.source_revision != final_record.source_revision
            or observed.reservation is None or observed.sql_attempt is None or completed is None):
        raise RetainedFinalizationReservationError("finalization lacks retained evidence completion")
    reserved = subjects.reservation_wire._originals(observed.reservation.originals, response=True)
    completion = handoff.completion_wire._originals(completed.originals, response=True)
    if completion[0] != b"acknowledged":
        raise RetainedFinalizationReservationError("uncertain evidence completion cannot reserve finalization")
    final_enrollments = tuple(common[name] for name in (
        "authorization_enrollment_bytes", "grant_enrollment_bytes", "current_root_enrollment_bytes"))
    evidence_enrollments = (material.execution.authorization_enrollment_bytes,
        material.execution.grant_enrollment_bytes, material.execution.current_root_enrollment_bytes)
    maxima = (admission.caller.MAX_ENROLLMENT_BYTES, admission.grants.MAX_ENROLLMENT_BYTES,
        admission.authorization.MAX_ENROLLMENT_BYTES,
        retained.execution.authorization.MAX_ENROLLMENT_BYTES,
        admission.grants.MAX_ENROLLMENT_BYTES, admission.authorization.MAX_ENROLLMENT_BYTES)
    if any(type(raw) is not bytes or not 2 <= len(raw) <= maximum
            for raw, maximum in zip((*final_enrollments, *evidence_enrollments), maxima)):
        raise RetainedFinalizationReservationError("finalization enrollment inventory is not bounded")
    if sum(len(raw) for raw in (*held, *evidence_originals, *signer, *reserved, *completion,
            *final_enrollments, *evidence_enrollments)) > evidence.authority.MAX_RESULT_BYTES:
        raise RetainedFinalizationReservationError("finalization retained inventory exceeds its aggregate bound")
    current()
    admitted = admission._admit_on_configuration(**common, originals=held[1:8],
        authorization_bytes=held[0], before_vector_bytes=held[8], grant_bytes=held[9],
        live_window=window, transport_deadline_ns=bound, work=work)
    window, bound = admitted.window, min(bound, admitted.deadline_ns)
    # These are copied ONLY from the actual complete original replay above.
    # They are not an accepted actor or successful request carrier.
    actual_request = evidence.capture._JSONCapture(evidence.capture._SharedLedger(work),
        maximum_bytes=evidence.authority.MAX_REQUEST_BYTES).visit(admitted.verified_grant.replayed.request)
    arguments = actual_request["arguments"]
    intent = arguments["semantic_intent"]
    expected_user, expected_session = handoff._expected_subject(intent["userId"], arguments["oidc_session_id"])
    current()
    actual_signer, retained_window, retained_bound, retained_live, retained_bytes = retained._retained_on_owner(
        owner, evidence_digest, expected_user_id=expected_user, expected_session_id=expected_session,
        live_window=window, work=work)
    original_bytes = sum(len(raw) for raw in (*held, *final_enrollments)) + retained_bytes
    if original_bytes > evidence.authority.MAX_RESULT_BYTES:
        raise RetainedFinalizationReservationError("finalization complete replay inventory exceeds its bound")
    work.charge(input_bytes=sum(len(raw) for raw in (*actual_signer, *signer)))
    if actual_signer != signer:
        raise RetainedFinalizationReservationError("finalization association changed its actual signer originals")
    window, bound = retained_window, min(bound, retained_bound)
    current()
    config = {name: common[name] for name in (
        "payload", "configuration_digest", "generation", "runtime_role_identities")}
    regenerated = signer_response._verify_finalization_execution_request_on_configuration(**config,
        request_originals=signer[:8], response_originals=signer[8:],
        sibling_challenge_ids=arguments["sibling_challenge_ids"], work=work)
    evidence.plan._same(regenerated.request, actual_request, work,
        "finalization grant differs from its associated signer's complete typed request")
    # The genuine signer finalization replay itself uses this source encoder;
    # finalization has no caller-supplied inputs. Compare the exact original.
    inputs = signer_response.registration_replay._encode_inputs_on_work(work=work)
    work.charge(input_bytes=len(inputs) + len(admitted.raw4[2]))
    if inputs != admitted.raw4[2]:
        raise RetainedFinalizationReservationError("finalization input original differs from signer replay")
    signer_limits = regenerated.expires_at_epoch_ns, regenerated.deadline_ns, regenerated.last_epoch_ns
    expiry = min(window[3], signer_limits[0])
    window = clock._validate((window[0], window[1], window[2], expiry,
        min(window[4], window[1] + expiry - window[0]), window[5], window[6]))
    bound = min(bound, window[4], signer_limits[1])
    current()
    regenerated_arguments = regenerated.request["arguments"]
    regenerated_intent = regenerated_arguments["semantic_intent"]
    result = {"localDigest": digest, "userId": regenerated_intent["userId"],
        "challengeId": regenerated_intent["challengeId"],
        "sessionId": regenerated_arguments["oidc_session_id"],
        "mode": regenerated_intent["authorizationMode"],
        "requestDigest": regenerated.request["requestDigest"],
        "operationId": regenerated.request["operationId"]}
    return result, held, window, bound, current, original_bytes


def _run(local_digest, *, expected_user_id=None, expected_session_id=None, dispatch):
    from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork

    startup._require_pid()
    digest = journal._digest(local_digest)
    if type(dispatch) is not bool:
        raise RetainedFinalizationReservationError("finalization reservation mode is not source selected")
    if dispatch:
        expected_user_id, expected_session_id = handoff._expected_subject(expected_user_id, expected_session_id)
    work = _ValidationWork(QueryReadValidationLimits())
    callback = evidence.production._callback
    owner = callback(work, startup.require_started)
    if (type(owner) is not startup._EnrollmentOwner
            or not callback(work, lambda: owner.finalization_reservation_enabled)
            or not callback(work, lambda: owner.sql_handoff_enabled)
            or callback(work, subjects.custody_startup.require_started) is not owner._custody):
        raise RetainedFinalizationReservationError("finalization reservation requires actual enabled cold owners")
    material, binding, custody = owner._material, owner._binding, owner._custody
    endpoint = material.finalization.reservation_endpoint
    window = clock._open_on_work(deadline_epoch_ns=binding.attestation_interval[1],
        maximum_lifetime_ns=min(binding.maximum_deadline_ns, endpoint[1] * 1_000_000_000,
            evidence.authority.VERIFIER_RESPONSE_MAX_AGE_NS),
        maximum_clock_skew_ns=material.issuer_policy["maximumClockSkewNs"], work=work)
    startup._require_pid()
    with startup._LOCK:
        if (owner._material is not material or owner._binding is not binding or owner._custody is not custody):
            raise RetainedFinalizationReservationError("finalization reservation owners changed before inspection")
        subject, held, window, bound, current, original_bytes = _inspect_on_owner(owner, digest,
            live_window=window, transport_deadline_ns=window[4], work=work)
        if not dispatch:
            current()
            return subject
        evidence.plan._same(subject["userId"], expected_user_id, work,
            "finalization reservation differs from the independently authenticated current user")
        evidence.plan._same(subject["sessionId"], expected_session_id, work,
            "finalization reservation differs from the independently authenticated current session")
        existing = callback(work,
            lambda: custody_client.ControlPlaneCustodyClient.load_registration_finalization_reservation(
                custody, digest))
        if existing is not None:
            raise RetainedFinalizationReservationError("finalization reservation is already retained; no implicit redispatch")
        current()
        # The real owner independently admits raw10 and authenticates raw3;
        # this same-call subject is never passed as an authority token.
        response = startup._EnrollmentOwner._request_registration_finalization_reservation(owner,
            originals=held, live_window=window, transport_deadline_ns=bound, work=work)
        response = transport._originals(response, response=True)
        if original_bytes + sum(len(raw) for raw in response) > evidence.authority.MAX_RESULT_BYTES:
            raise RetainedFinalizationReservationError("finalization response exceeds the complete retained inventory bound")
        current()
        custody_client.ControlPlaneCustodyClient.append_registration_finalization_reservation(
            custody, digest, response)
        current()
        return digest, response


def inspect_retained_finalization_subject(local_digest):
    """Return seven genuine same-call subject scalars, not present permission."""
    return _run(local_digest, dispatch=False)


def reserve_retained_registration_finalization(local_digest, *, expected_user_id, expected_session_id):
    """Return (input finalization grant ID, verified raw3) after durable append."""
    return _run(local_digest, expected_user_id=expected_user_id,
        expected_session_id=expected_session_id, dispatch=True)
