"""Genuine retained-subject replay for separately authorized history recovery.

Historical signer and planning/grant originals prove their original subject,
not a present actor's permission. The fixed HTTP handler must authenticate that
actor and admit the separate recovery purpose. Dispatch repeats this replay
against actual cold-owner custody, then compares independently admitted caller
scalars. No public successful subject object can replace that replay.

Current processing is bounded by cold-owner attestation and one work/window.
No historical issue time is a clock and no original expiry is renewed. This
module does not dispatch, sign, execute SQL or finalize credentials.
"""
from __future__ import annotations

import time

from serverware import control_plane_registration_handoff_subject as live_subject
from serverware import authority_webauthn_registration_signer_history as signer_history
from serverware import authority_registration_history_exchange as history


execution, custody_client, custody_startup = (
    live_subject.execution, live_subject.custody_client, live_subject.custody_startup)
startup, evidence, clock = execution.startup, execution.evidence, execution.clock


class RegistrationRecoverySubjectError(ValueError):
    pass


def _open_on_work(work):
    """Open only present processing from actual independently cold-admitted scope."""
    startup._require_pid()
    callback = evidence.production._callback
    owner = callback(work, startup.require_started)
    if (type(owner) is not startup._EnrollmentOwner
            or not callback(work, lambda: owner.sql_handoff_enabled)
            or callback(work, custody_startup.require_started) is not owner._custody):
        raise RegistrationRecoverySubjectError("registration recovery is not cold-enabled")
    material, binding = owner._material, owner._binding
    endpoint = material.execution.completion_endpoint
    window = clock._open_on_work(deadline_epoch_ns=binding.attestation_interval[1],
        maximum_lifetime_ns=min(binding.maximum_deadline_ns, int(endpoint[1] * 1_000_000_000),
            evidence.authority.VERIFIER_RESPONSE_MAX_AGE_NS),
        maximum_clock_skew_ns=material.issuer_policy["maximumClockSkewNs"], work=work)
    if (owner._material is not material or owner._binding is not binding
            or callback(work, startup.require_started) is not owner
            or callback(work, custody_startup.require_started) is not owner._custody):
        raise RegistrationRecoverySubjectError("registration recovery startup changed")
    clock._check_on_work(window, work=work)
    return owner, material, binding, window


def _scope_on_owner(owner, *, live_window, work, transport_deadline_ns=None):
    """Preserve the caller window while rechecking the actual cold owner."""
    startup._require_pid()
    evidence.capture._SharedLedger(work)
    window = clock._validate(live_window)
    shape = evidence.plan.contract
    if transport_deadline_ns is not None:
        shape._integer(transport_deadline_ns, minimum=1)
    inherited = window[4] if transport_deadline_ns is None else min(window[4], transport_deadline_ns)
    if type(owner) is not startup._EnrollmentOwner:
        raise RegistrationRecoverySubjectError("registration recovery requires the actual cold owner")
    custody, binding, material = owner._custody, owner._binding, owner._material
    if type(custody) is not custody_client.ControlPlaneCustodyClient:
        raise RegistrationRecoverySubjectError("registration recovery requires actual retained custody")
    common, endpoint, _private, deadline, bound, owner_live = execution._scope(owner,
        deadline_epoch_ns=window[3], deadline_ns=inherited,
        work=work, _endpoint_kind="completion")
    last_epoch, last_monotonic = window[0], window[2]
    callback = evidence.production._callback

    def current():
        nonlocal last_epoch, last_monotonic
        owner_live()
        if (owner._material is not material or owner._binding is not binding
                or owner._custody is not custody
                or callback(work, startup.require_started) is not owner
                or callback(work, custody_startup.require_started) is not custody
                or callback(work, lambda: custody_client._snapshot(custody)) is not binding):
            raise RegistrationRecoverySubjectError("registration recovery cold owners changed")
        now = clock._check_on_work(window, work=work)
        monotonic = callback(work, time.monotonic_ns)
        shape._integer(monotonic, minimum=1)
        if now < last_epoch or monotonic < last_monotonic or now >= deadline or monotonic >= bound:
            raise RegistrationRecoverySubjectError("registration recovery processing expired or reversed")
        last_epoch, last_monotonic = now, monotonic
        owner_live()
        return now

    current()
    return common, endpoint, window, bound, current


def _replay_on_owner(owner, local_digest, *, live_window, work, transport_deadline_ns=None):
    """Return subject scalars and original inventory size from this actual replay."""
    digest = live_subject.journal._digest(local_digest)
    common, _endpoint, window, bound, current = _scope_on_owner(owner,
        live_window=live_window, work=work, transport_deadline_ns=transport_deadline_ns)
    custody = owner._custody
    pair = evidence.production._callback(work,
        lambda: custody_client.ControlPlaneCustodyClient.load_registration_preparation(custody, digest))
    if (type(pair) is not tuple or len(pair) != 2
            or any(type(record) is not live_subject.records.PreparedRecord for record in pair)):
        raise RegistrationRecoverySubjectError("registration recovery association is not an exact retained pair")
    execution_record, signer_record = pair
    if (execution_record.digest != digest
            or execution_record.family != live_subject.execution_records.FAMILY
            or execution_record.selector != live_subject.execution_records.OPERATION
            or signer_record.family != live_subject.signer_records.FAMILY
            or signer_record.selector != live_subject.signer_records.OPERATION
            or execution_record.source_revision != live_subject.signer_response.authority.SOURCE_REVISION
            or signer_record.source_revision != execution_record.source_revision):
        raise RegistrationRecoverySubjectError("registration recovery association has another source or family")
    held = live_subject.reservation_wire._originals(execution_record.originals, response=False)
    signer = live_subject.signer_wire._request_originals(signer_record.originals)
    enrollments = (common["authorization_enrollment_bytes"], common["grant_enrollment_bytes"],
        common["current_root_enrollment_bytes"])
    maxima = (execution.authorization.MAX_ENROLLMENT_BYTES,
        execution.receiving.grants.MAX_ENROLLMENT_BYTES,
        execution.receiving.grants.authorization.MAX_ENROLLMENT_BYTES)
    if any(type(raw) is not bytes or not 2 <= len(raw) <= maximum
            for raw, maximum in zip(enrollments, maxima)):
        raise RegistrationRecoverySubjectError("registration recovery enrollments are not bounded originals")
    original_bytes = sum(len(raw) for raw in (*held, *signer, *enrollments))
    if original_bytes > live_subject.signer_response.authority.MAX_RESULT_BYTES:
        raise RegistrationRecoverySubjectError("registration recovery subject originals exceed their aggregate bound")
    current()
    subject = signer_history._verify_subject_on_configuration(payload=common["payload"],
        configuration_digest=common["configuration_digest"], generation=common["generation"],
        runtime_role_identities=common["runtime_role_identities"],
        request_originals=signer[:8], response_originals=signer[8:],
        live_window=window, work=work, transport_deadline_ns=bound)
    result = {"localDigest": digest, "userId": subject["userId"],
        "challengeId": subject["challengeId"], "sessionId": subject["sessionId"],
        "mode": subject["mode"], "requestDigest": subject["requestDigest"],
        "operationId": subject["operationId"]}
    current()
    exchanged = history._verify_on_configuration(**common, originals=held,
        live_window=window, work=work, transport_deadline_ns=bound)
    evidence.plan._same(exchanged.request_digest, result["requestDigest"], work,
        "historical execution exchange differs from the replayed signer request")
    evidence.plan._same(exchanged.operation_id, result["operationId"], work,
        "historical execution exchange differs from the replayed signer operation")
    current()
    return result, original_bytes


def _inspect_on_owner(owner, local_digest, *, live_window, work, transport_deadline_ns=None):
    """Return the seven subject scalars, never an admission token."""
    result, _original_bytes = _replay_on_owner(owner, local_digest,
        live_window=live_window, work=work, transport_deadline_ns=transport_deadline_ns)
    return result


def inspect_retained_registration_recovery_subject(local_digest):
    """Public-handler lookup; authenticates original subject, not present permission."""
    from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork

    digest = live_subject.journal._digest(local_digest)
    work = _ValidationWork(QueryReadValidationLimits())
    owner, material, binding, window = _open_on_work(work)
    startup._require_pid()
    with startup._LOCK:
        if owner._material is not material or owner._binding is not binding:
            raise RegistrationRecoverySubjectError("registration recovery startup changed before inspection")
        result = _inspect_on_owner(owner, digest, live_window=window,
            work=work, transport_deadline_ns=window[4])
        clock._check_on_work(window, work=work)
        return result
