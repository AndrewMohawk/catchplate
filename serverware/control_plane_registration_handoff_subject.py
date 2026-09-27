"""Live original-replay ownership inspection for retained registration handoff.

A local digest and signer/grant association are locators, not subject proof.
This helper loads both originals from the actual cold custody owner, genuinely
replays the signer exchange, verifies the complete execution grant/planning
exchange, and joins their actual request commitments on one work allowance.
The returned seven-field dictionary is ordinary bounded data, never a token
accepted by a side-effect API. Present user/session/role, CSRF and new-purpose
authorization remain the caller's responsibility; dispatch must repeat this
inspection with its original work/deadline and compare current-caller scalars.

Only still-live originals are supported. No historical expiry exception,
transport, signing, SQL, checkpoint advancement or credential finalization is
performed. There are no supplied keys, successful verification carriers, actor
selectors or fallback owners.
"""
from __future__ import annotations

from serverware import control_plane_registration_execution as execution
from serverware import control_plane_custody_client as custody_client
from serverware import control_plane_custody_startup as custody_startup
from serverware import control_plane_custody_journal as journal
from serverware import control_plane_custody_records as records
from serverware import control_plane_registration_execution_records as execution_records
from serverware import control_plane_registration_signer_records as signer_records
from serverware import authority_registration_reservation_transport as reservation_wire
from serverware import authority_webauthn_registration_custody_caller as signer_wire
from serverware import authority_webauthn_registration_signer_response as signer_response


evidence, clock, startup = execution.evidence, execution.clock, execution.startup


class RegistrationHandoffSubjectError(ValueError):
    pass


def _inspect_on_owner(owner, local_digest, deadline_epoch_ns, deadline_ns, work):
    """Recheck actual retained ownership on the caller's unchanged allowance.

    The actual enrollment owner dispatch holds its existing lock. The separate
    convenience wrapper below acquires that same lock after the PID check.
    Nothing accepts an earlier returned subject dictionary as admission.
    """
    startup._require_pid()
    evidence.capture._SharedLedger(work)
    digest = journal._digest(local_digest)
    if type(owner) is not startup._EnrollmentOwner:
        raise RegistrationHandoffSubjectError("registration subject requires the actual cold owner")
    custody, binding, material = owner._custody, owner._binding, owner._material
    if type(custody) is not custody_client.ControlPlaneCustodyClient:
        raise RegistrationHandoffSubjectError("registration subject requires actual retained custody")
    callback = evidence.production._callback
    common, _endpoint, _private, deadline, bound, owner_live = execution._scope(owner,
        deadline_epoch_ns=deadline_epoch_ns, deadline_ns=deadline_ns,
        work=work, _endpoint_kind="sql")

    def current():
        owner_live()
        if (owner._material is not material or owner._binding is not binding
                or owner._custody is not custody
                or callback(work, startup.require_started) is not owner
                or callback(work, custody_startup.require_started) is not custody
                or callback(work, lambda: custody_client._snapshot(custody)) is not binding):
            raise RegistrationHandoffSubjectError("registration subject cold owners changed")
        owner_live()

    current()
    pair = callback(work, lambda: custody_client.ControlPlaneCustodyClient.load_registration_preparation(
        custody, digest))
    if (type(pair) is not tuple or len(pair) != 2
            or any(type(record) is not records.PreparedRecord for record in pair)):
        raise RegistrationHandoffSubjectError("registration subject association is not an exact retained pair")
    execution_record, signer_record = pair
    if (execution_record.digest != digest
            or execution_record.family != execution_records.FAMILY
            or execution_record.selector != execution_records.OPERATION
            or signer_record.family != signer_records.FAMILY
            or signer_record.selector != signer_records.OPERATION
            or execution_record.source_revision != signer_response.authority.SOURCE_REVISION
            or signer_record.source_revision != execution_record.source_revision):
        raise RegistrationHandoffSubjectError("registration subject association has another family or source")
    # Capture immutable inventories and admit every original/group before the
    # next native clock/key/hash callback. The journal already authenticates the
    # local content locators and association, not their cryptographic meaning.
    held = reservation_wire._originals(execution_record.originals, response=False)
    signer = signer_wire._request_originals(signer_record.originals)
    enrollments = (common["authorization_enrollment_bytes"],
        common["grant_enrollment_bytes"], common["current_root_enrollment_bytes"])
    maxima = (execution.authorization.MAX_ENROLLMENT_BYTES,
        execution.receiving.grants.MAX_ENROLLMENT_BYTES,
        execution.receiving.grants.authorization.MAX_ENROLLMENT_BYTES)
    if any(type(raw) is not bytes or not 2 <= len(raw) <= maximum
            for raw, maximum in zip(enrollments, maxima)):
        raise RegistrationHandoffSubjectError("registration subject enrollment originals are not bounded")
    if sum(len(raw) for raw in (*held, *signer, *enrollments)) > signer_response.authority.MAX_RESULT_BYTES:
        raise RegistrationHandoffSubjectError("registration subject originals exceed their aggregate bound")
    current()
    subject, signer_expiry, signer_deadline, signer_live = (
        signer_response._verify_handoff_subject_on_configuration(
            payload=common["payload"], configuration_digest=common["configuration_digest"],
            generation=common["generation"], runtime_role_identities=common["runtime_role_identities"],
            request_originals=signer[:8], response_originals=signer[8:], work=work))
    deadline, bound = min(deadline, signer_expiry), min(bound, signer_deadline)
    # Copy just authenticated scalars before any further verifier callback.
    result = {"localDigest": digest, "userId": subject["userId"],
        "challengeId": subject["challengeId"], "sessionId": subject["sessionId"],
        "mode": subject["mode"], "requestDigest": subject["requestDigest"],
        "operationId": subject["operationId"]}
    last_epoch, last_monotonic = 0, 0

    def live():
        nonlocal last_epoch, last_monotonic
        current()
        signer_now = signer_live()
        before, now, after = clock._sample_on_work(work)
        if (now < signer_now or now < last_epoch or before < last_monotonic
                or now >= deadline or after >= bound):
            raise RegistrationHandoffSubjectError("registration subject original window expired or reversed")
        last_epoch, last_monotonic = now, after
        return now

    live()
    original_grant = execution.receiving._verify_on_configuration(**common,
        request_originals=held[1:4], response_originals=held[4:8],
        before_vector_bytes=held[8], authorization_bytes=held[0], grant_bytes=held[9],
        deadline_epoch_ns=deadline, transport_deadline_ns=bound, work=work)
    if type(original_grant) is not bytes:
        raise RegistrationHandoffSubjectError("registration subject grant original changed")
    work.charge(input_bytes=len(original_grant) + len(held[9]))
    if original_grant != held[9]:
        raise RegistrationHandoffSubjectError("registration subject grant original changed")
    live()
    # Decode ONLY the same-call genuinely verified immutable grant. This read
    # is not a signature verifier: the call above already joined every grant
    # claim to full original plan/vector replay and the dedicated caller's
    # signature. Its authenticated request identity must match THIS signer's
    # reconstructed request, even if a valid local marker associates the two.
    granted = execution.receiving.grants._read(original_grant,
        enrollment=False, work=work)["payload"]
    for name, expected in (("operation", execution_records.OPERATION),
            ("requestDigest", result["requestDigest"]), ("operationId", result["operationId"])):
        evidence.plan._same(granted[name], expected, work,
            "retained execution grant differs from the replayed registration subject")
    if live() >= granted["expiresAtEpochNs"]:
        raise RegistrationHandoffSubjectError("registration subject grant expired during inspection")
    return result


def inspect_retained_registration_subject(local_digest):
    """Return exact seven-field live-replayed subject data, not permission."""
    from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork

    startup._require_pid()
    digest = journal._digest(local_digest)
    work = _ValidationWork(QueryReadValidationLimits())
    callback = evidence.production._callback
    owner = callback(work, startup.require_started)
    if (type(owner) is not startup._EnrollmentOwner
            or not callback(work, lambda: owner.sql_handoff_enabled)
            or callback(work, custody_startup.require_started) is not owner._custody):
        raise RegistrationHandoffSubjectError("registration subject handoff is not cold-enabled")
    material, binding = owner._material, owner._binding
    endpoints = (material.execution.sql_endpoint, material.execution.completion_endpoint)
    window = clock._open_on_work(deadline_epoch_ns=binding.attestation_interval[1],
        maximum_lifetime_ns=min(binding.maximum_deadline_ns,
            *(int(endpoint[1] * 1_000_000_000) for endpoint in endpoints),
            evidence.authority.VERIFIER_RESPONSE_MAX_AGE_NS),
        maximum_clock_skew_ns=material.issuer_policy["maximumClockSkewNs"], work=work)
    startup._require_pid()
    with startup._LOCK:
        clock._check_on_work(window, work=work)
        if owner._material is not material or owner._binding is not binding:
            raise RegistrationHandoffSubjectError("registration subject startup changed before inspection")
        result = _inspect_on_owner(owner, digest, window[3], window[4], work)
        clock._check_on_work(window, work=work)
        return result
