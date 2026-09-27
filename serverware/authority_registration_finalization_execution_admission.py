"""Admit finalization raw7 and an original operation-specific execution grant.

The real custody signatures authenticate raw4 and separate historical bytes;
the independently configured transition verifier and full-vector grant replay
then check their actual semantics. A separately root-enrolled finalization
caller signs the exact request/operation commitment. Retention controls or an
evidence-admission grant cannot replace that original authorization.

The original verifier returns unchanged raw7. A private same-call continuation
also retains genuinely derived facts and the original live guard; no entrypoint
accepts that record as proof. This supplies no present actor, cold
purpose owner, grant signing, reserve, pending/currentness, SQL, one-use claim,
completion or session activation. The same caller work/window is retained.
"""
from __future__ import annotations

import time
from dataclasses import dataclass

from serverware import authority_registration_finalization_authorization as caller
from serverware import authority_webauthn_transition_custody_actions as custody


grants, authorization, shape = caller.grants, caller.authorization, caller.shape
evidence, clock, wire = custody.evidence, custody.wire.clock, custody.wire
OPERATION = caller.OPERATION


class RegistrationFinalizationExecutionAdmissionError(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _AdmittedFinalization:
    """Internal results of THIS original replay, never an authority input."""

    originals: tuple
    raw4: tuple
    before: bytes
    authorization: bytes
    authorization_enrollment: bytes
    grant: bytes
    grant_enrollment: bytes
    current_enrollment: bytes
    root: object
    configured: object
    authorized: object
    verified_grant: object
    history: dict
    window: tuple
    deadline_epoch_ns: int
    deadline_ns: int
    live: object


def _verify_on_configuration(*, payload, configuration_digest, generation,
        runtime_role_identities, originals, before_vector_bytes, authorization_bytes,
        authorization_enrollment_bytes, grant_bytes, grant_enrollment_bytes,
        current_root_enrollment_bytes, root_public_key, live_window, work,
        transport_deadline_ns=None):
    """Return the exact raw7 only after genuine original authorization/replay."""
    admitted = _admit_on_configuration(payload=payload, configuration_digest=configuration_digest,
        generation=generation, runtime_role_identities=runtime_role_identities,
        originals=originals, before_vector_bytes=before_vector_bytes,
        authorization_bytes=authorization_bytes, authorization_enrollment_bytes=authorization_enrollment_bytes,
        grant_bytes=grant_bytes, grant_enrollment_bytes=grant_enrollment_bytes,
        current_root_enrollment_bytes=current_root_enrollment_bytes, root_public_key=root_public_key,
        live_window=live_window, work=work, transport_deadline_ns=transport_deadline_ns)
    return admitted.originals


def _admit_on_configuration(*, payload, configuration_digest, generation,
        runtime_role_identities, originals, before_vector_bytes, authorization_bytes,
        authorization_enrollment_bytes, grant_bytes, grant_enrollment_bytes,
        current_root_enrollment_bytes, root_public_key, live_window, work,
        transport_deadline_ns=None):
    """Fully replay originals and preserve private same-call facts and clocks."""
    ledger = evidence.capture._SharedLedger(work)
    if type(originals) is not tuple or len(originals) != 7:
        raise RegistrationFinalizationExecutionAdmissionError("finalization admission requires exact original raw7")
    held = custody.transport._validate_originals(intent_bytes=originals[0], relay_bytes=originals[1],
        envelope_bytes=originals[2], proof_bytes=originals[3], inputs_bytes=originals[4],
        context_bytes=originals[5], historical_expectations_bytes=originals[6])
    raw4, before = grants.replay._originals(OPERATION, held[2:6], before_vector_bytes)
    request = authorization._original(authorization_bytes, caller.MAX_AUTHORIZATION_BYTES,
        "finalization request authorization")
    caller_enrollment = authorization._original(authorization_enrollment_bytes, caller.MAX_ENROLLMENT_BYTES,
        "finalization caller enrollment")
    grant = authorization._original(grant_bytes, grants.MAX_GRANT_BYTES, "finalization execution grant")
    grant_enrollment = authorization._original(grant_enrollment_bytes,
        grants.MAX_ENROLLMENT_BYTES, "finalization grant enrollment")
    current_enrollment = authorization._original(current_root_enrollment_bytes,
        authorization.MAX_ENROLLMENT_BYTES, "finalization current-root enrollment")
    if sum(len(raw) for raw in (*held, before, request, caller_enrollment, grant,
            grant_enrollment, current_enrollment)) > grants.replay.MAX_ORIGINAL_BYTES:
        raise RegistrationFinalizationExecutionAdmissionError("finalization admission originals exceed their aggregate bound")
    shape._digest(configuration_digest)
    digest, root = configuration_digest, root_public_key
    authorization._public(root)
    window = clock._validate(live_window)
    inherited = transport_deadline_ns
    if inherited is not None:
        shape._integer(inherited, minimum=1)
    bound = window[4] if inherited is None else min(window[4], inherited)
    measured = custody.configuration.configuration
    if type(payload) is not dict or type(generation) is not dict:
        raise RegistrationFinalizationExecutionAdmissionError("finalization configuration is not exact data")
    shape._bounded_object(generation, 24, "finalization launch context")
    owned_payload = measured._ConfigurationCapture(ledger,
        maximum_bytes=wire.authority.MAX_REQUEST_BYTES).visit(payload)
    owned_generation = evidence.capture._JSONCapture(ledger).visit(
        {name: generation[name] for name in measured._GENERATION_FIELDS})
    owned_runtime = evidence.capture._JSONCapture(ledger,
        maximum_bytes=8192).visit(runtime_role_identities)
    last_epoch, last_monotonic = window[0], window[2]
    authorized, verified_custody, plan_payload, expected, verified_grant = (None,) * 5

    def current():
        nonlocal last_epoch, last_monotonic
        now = clock._check_on_work(window, work=work)
        monotonic = evidence.production._callback(work, time.monotonic_ns)
        shape._integer(monotonic, minimum=1)
        if now < last_epoch or monotonic < last_monotonic or monotonic >= bound:
            raise RegistrationFinalizationExecutionAdmissionError("finalization processing expired or clocks reversed")
        last_epoch, last_monotonic = now, monotonic
        if authorized is not None and (now >= authorized.expires_at_epoch_ns
                or authorized.issued_at_epoch_ns > now + authorized.maximum_clock_skew_ns
                or now - authorized.issued_at_epoch_ns > authorized.maximum_age_ns):
            raise RegistrationFinalizationExecutionAdmissionError("finalization caller authority is no longer live")
        if verified_custody is not None:
            for issued, expires in (verified_custody.intent_times, verified_custody.relay_times):
                if (issued > now + configured.pins[6][1] or now >= expires
                        or now - issued > configured.maximum_control_age_ns):
                    raise RegistrationFinalizationExecutionAdmissionError("finalization custody controls are no longer live")
        if plan_payload is not None:
            wire.retention.plan._fresh(plan_payload, expected, now)
        if verified_grant is not None and now >= verified_grant.payload["expiresAtEpochNs"]:
            raise RegistrationFinalizationExecutionAdmissionError("finalization execution grant expired during admission")
        return now

    current()
    configured = custody.configuration._capture_on_work(operation=OPERATION,
        payload=owned_payload, configuration_digest=digest, generation=owned_generation,
        runtime_role_identities=owned_runtime, work=work)
    current()
    authorized = caller._verify_on_work(authorization_bytes=request,
        authorization_enrollment_bytes=caller_enrollment, current_root_enrollment_bytes=current_enrollment,
        grant_enrollment_bytes=grant_enrollment, root_public_key=root, configuration_digest=digest,
        planner_public_key=configured.pins[1], evidence_public_key=configured.pins[4],
        live_window=window, work=work, transport_deadline_ns=bound)
    if (authorized.last_epoch_ns < last_epoch
            or authorized.last_monotonic_ns < last_monotonic):
        raise RegistrationFinalizationExecutionAdmissionError("finalization authorization reversed the caller clocks")
    last_epoch, last_monotonic = authorized.last_epoch_ns, authorized.last_monotonic_ns
    bound = min(bound, window[1] + authorized.expires_at_epoch_ns - window[0])
    evidence.plan._same(authorized.generation_digest, configured.generation_digest, work,
        "finalization authorization differs from the independently configured generation")
    current()
    verified_custody = custody.relay._verify_on_work(intent_bytes=held[0], relay_bytes=held[1],
        envelope_bytes=raw4[0], proof_bytes=raw4[1], inputs_bytes=raw4[2], context_bytes=raw4[3],
        historical_expectations_bytes=held[6], pins=configured.pins,
        generation_sequence=configured.generation_sequence, generation_digest=configured.generation_digest,
        verifier_public_key=configured.verifier_public_key,
        maximum_control_age_ns=configured.maximum_control_age_ns, work=work)
    bound = min(bound, verified_custody.intent_window[4], verified_custody.relay_window[4])
    current()
    # The real signed intent/relay admitted this separate history before it is
    # decoded here. It is still joined to independently configured policy.
    historical = custody.intent.context_wire._decode_on_work(held[6], work=work)
    expected = custody.intent.admission._capture_expectations_on_work(configured.pins, historical, work)
    plan_payload = custody.intent._payload_on_work(raw4[0], work)
    before_grant = current()
    verified_grant = grants._verify_on_work(grant_bytes=grant, grant_enrollment_bytes=grant_enrollment,
        current_root_enrollment_bytes=current_enrollment, root_public_key=root, operation=OPERATION,
        originals=raw4, expectations=expected, planner_public_key=configured.pins[1],
        operation_public_key=configured.pins[4], before_vector_bytes=before,
        expected_authorization_digest=authorized.authorization_digest,
        now_epoch_ns=before_grant, work=work)
    actual = verified_grant.payload
    for name, value in (("operation", OPERATION), ("requestDigest", authorized.request_digest),
            ("operationId", authorized.operation_id), ("databaseId", authorized.database_id),
            ("generationDigest", authorized.generation_digest),
            ("currentRootEnrollmentDigest", authorized.current_root_enrollment_digest),
            ("grantEnrollmentDigest", authorized.grant_enrollment_digest),
            ("retainedRecordDigest", verified_custody.retained_record_digest)):
        evidence.plan._same(actual[name], value, work, "finalization grant differs from admitted original scope " + name)
    if (actual["issuedAtEpochNs"] < authorized.issued_at_epoch_ns
            or actual["expiresAtEpochNs"] > authorized.expires_at_epoch_ns):
        raise RegistrationFinalizationExecutionAdmissionError("finalization grant escapes its original caller authority")
    bound = min(bound, window[1] + actual["expiresAtEpochNs"] - window[0])
    deadline = min(window[3], authorized.expires_at_epoch_ns,
        verified_custody.intent_times[1], verified_custody.relay_times[1],
        plan_payload["expiresAtEpochNs"], actual["expiresAtEpochNs"])
    window = clock._validate((window[0], window[1], window[2], deadline,
        min(window[4], window[1] + deadline - window[0]), window[5], window[6]))
    bound = min(bound, window[4])
    current()
    return _AdmittedFinalization(held, raw4, before, request, caller_enrollment,
        grant, grant_enrollment, current_enrollment, root, configured, authorized,
        verified_grant, expected, window, deadline, bound, current)
