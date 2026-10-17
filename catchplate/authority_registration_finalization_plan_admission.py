"""Authenticate new finalization custody under an original caller delegation.

The supplied processing window/work and independently admitted configuration
remain prerequisites. Actual finalization authorization precedes genuine raw7
custody replay. Original plan history never becomes caller authority, and a
past preparation cannot acquire permission by changing its issue instant.
Only unchanged raw7 is exposed; private same-call facts serve grant production.
There is no new work allowance, signing, transport, SQL or session activation.
"""
from __future__ import annotations

from dataclasses import dataclass
import time

from catchplate import authority_registration_finalization_authorization as caller
from catchplate import authority_webauthn_transition_custody_actions as custody


grants, authorization, shape = caller.grants, caller.authorization, caller.shape
evidence, clock, wire = custody.evidence, custody.wire.clock, custody.wire
OPERATION = caller.OPERATION


class RegistrationFinalizationPlanAdmissionError(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _AdmittedPlan:
    """Private same-call facts; no entrypoint accepts this as authority."""

    originals: tuple
    expectations: dict
    configured: object
    authorized: object
    retained_record_digest: str
    window: tuple
    deadline_ns: int
    check: object


def _verify_on_configuration(*, payload, configuration_digest, generation,
        runtime_role_identities, originals, authorization_bytes,
        authorization_enrollment_bytes, grant_enrollment_bytes,
        current_root_enrollment_bytes, root_public_key, live_window, work,
        transport_deadline_ns=None):
    """Return unchanged raw7, never a successful-verification carrier."""
    admitted = _admit_on_configuration(payload=payload, configuration_digest=configuration_digest,
        generation=generation, runtime_role_identities=runtime_role_identities,
        originals=originals, authorization_bytes=authorization_bytes,
        authorization_enrollment_bytes=authorization_enrollment_bytes,
        grant_enrollment_bytes=grant_enrollment_bytes,
        current_root_enrollment_bytes=current_root_enrollment_bytes,
        root_public_key=root_public_key, live_window=live_window, work=work,
        transport_deadline_ns=transport_deadline_ns)
    admitted.check()
    return admitted.originals


def _admit_on_configuration(*, payload, configuration_digest, generation,
        runtime_role_identities, originals, authorization_bytes,
        authorization_enrollment_bytes, grant_enrollment_bytes,
        current_root_enrollment_bytes, root_public_key, live_window, work,
        transport_deadline_ns=None):
    """Sibling-only raw composition, not a reusable admission-result input."""
    ledger = evidence.capture._SharedLedger(work)
    if type(originals) is not tuple or len(originals) != 7:
        raise RegistrationFinalizationPlanAdmissionError("finalization requires exact original raw7")
    held = custody.transport._validate_originals(intent_bytes=originals[0], relay_bytes=originals[1],
        envelope_bytes=originals[2], proof_bytes=originals[3], inputs_bytes=originals[4],
        context_bytes=originals[5], historical_expectations_bytes=originals[6])
    request = authorization._original(authorization_bytes, caller.MAX_AUTHORIZATION_BYTES,
        "finalization request authorization")
    caller_enrollment = authorization._original(authorization_enrollment_bytes,
        caller.MAX_ENROLLMENT_BYTES, "finalization caller enrollment")
    grant_enrollment = authorization._original(grant_enrollment_bytes,
        grants.MAX_ENROLLMENT_BYTES, "finalization grant enrollment")
    current_enrollment = authorization._original(current_root_enrollment_bytes,
        authorization.MAX_ENROLLMENT_BYTES, "finalization current-root enrollment")
    if sum(len(raw) for raw in (*held, request, caller_enrollment,
            grant_enrollment, current_enrollment)) > grants.replay.MAX_ORIGINAL_BYTES:
        raise RegistrationFinalizationPlanAdmissionError("finalization originals exceed their aggregate bound")
    digest, root = configuration_digest, root_public_key
    shape._digest(digest)
    authorization._public(root)
    window = clock._validate(live_window)
    inherited = transport_deadline_ns
    if inherited is not None:
        shape._integer(inherited, minimum=1)
    bound = window[4] if inherited is None else min(window[4], inherited)
    measured = custody.configuration.configuration
    if type(payload) is not dict or type(generation) is not dict:
        raise RegistrationFinalizationPlanAdmissionError("finalization configuration is not exact data")
    shape._bounded_object(generation, 24, "finalization launch context")
    owned_payload = measured._ConfigurationCapture(ledger,
        maximum_bytes=wire.authority.MAX_REQUEST_BYTES).visit(payload)
    owned_generation = evidence.capture._JSONCapture(ledger).visit(
        {name: generation[name] for name in measured._GENERATION_FIELDS})
    owned_runtime = evidence.capture._JSONCapture(ledger,
        maximum_bytes=8192).visit(runtime_role_identities)
    last_epoch, last_monotonic = window[0], window[2]
    authorized, verified_custody, plan_payload, expected = (None,) * 4

    def current():
        nonlocal last_epoch, last_monotonic
        now = clock._check_on_work(window, work=work)
        monotonic = evidence.production._callback(work, time.monotonic_ns)
        shape._integer(monotonic, minimum=1)
        if now < last_epoch or monotonic < last_monotonic or monotonic >= bound:
            raise RegistrationFinalizationPlanAdmissionError("finalization processing expired or clocks reversed")
        last_epoch, last_monotonic = now, monotonic
        if authorized is not None and (now >= authorized.expires_at_epoch_ns
                or authorized.issued_at_epoch_ns > now + authorized.maximum_clock_skew_ns
                or now - authorized.issued_at_epoch_ns > authorized.maximum_age_ns):
            raise RegistrationFinalizationPlanAdmissionError("finalization caller authority is no longer live")
        if verified_custody is not None:
            for issued, expires in (verified_custody.intent_times, verified_custody.relay_times):
                if (issued > now + configured.pins[6][1] or now >= expires
                        or now - issued > configured.maximum_control_age_ns):
                    raise RegistrationFinalizationPlanAdmissionError("finalization custody is no longer live")
        if plan_payload is not None:
            wire.retention.plan._fresh(plan_payload, expected, now)
        return now, monotonic

    current()
    configured = custody.configuration._capture_on_work(operation=OPERATION,
        payload=owned_payload, configuration_digest=digest, generation=owned_generation,
        runtime_role_identities=owned_runtime, work=work)
    current()
    # Original purpose-specific root/caller authority is admitted BEFORE plan
    # or custody replay. No authorization digest is adopted from the plan.
    authorized = caller._verify_on_work(authorization_bytes=request,
        authorization_enrollment_bytes=caller_enrollment,
        current_root_enrollment_bytes=current_enrollment, grant_enrollment_bytes=grant_enrollment,
        root_public_key=root, configuration_digest=digest, planner_public_key=configured.pins[1],
        evidence_public_key=configured.pins[4], live_window=window, work=work,
        transport_deadline_ns=bound)
    if (authorized.last_epoch_ns < last_epoch or authorized.last_monotonic_ns < last_monotonic):
        raise RegistrationFinalizationPlanAdmissionError("finalization authorization reversed processing clocks")
    last_epoch, last_monotonic = authorized.last_epoch_ns, authorized.last_monotonic_ns
    bound = min(bound, window[1] + authorized.expires_at_epoch_ns - window[0])
    evidence.plan._same(authorized.generation_digest, configured.generation_digest, work,
        "finalization authorization differs from the configured generation")
    current()
    verified_custody = custody.relay._verify_on_work(intent_bytes=held[0], relay_bytes=held[1],
        envelope_bytes=held[2], proof_bytes=held[3], inputs_bytes=held[4], context_bytes=held[5],
        historical_expectations_bytes=held[6], pins=configured.pins,
        generation_sequence=configured.generation_sequence, generation_digest=configured.generation_digest,
        verifier_public_key=configured.verifier_public_key,
        maximum_control_age_ns=configured.maximum_control_age_ns, work=work)
    bound = min(bound, verified_custody.intent_window[4], verified_custody.relay_window[4])
    current()
    # The genuine signed custody verifier already authenticated all raw5 byte
    # commitments, compared the complete history and replayed the actual raw4.
    historical = custody.intent.context_wire._decode_on_work(held[6], work=work)
    expected = custody.intent.admission._capture_expectations_on_work(configured.pins, historical, work)
    plan_payload = custody.intent._payload_on_work(held[2], work)
    actual_request = expected["proofExpectations"]["request"]
    request_digest = authorization.commitment._typed_request_digest(actual_request, work=work)
    operation_id = evidence.plan._frame("catchplate.policyAuthorityOperation/v2",
        (OPERATION.encode("ascii"), request_digest.encode("ascii")), work)
    for actual, value, label in ((actual_request["operation"], OPERATION, "operation"),
            (actual_request["requestDigest"], request_digest, "typed request commitment"),
            (actual_request["operationId"], operation_id, "typed operation commitment"),
            (request_digest, authorized.request_digest, "authorized request"),
            (operation_id, authorized.operation_id, "authorized operation")):
        evidence.plan._same(actual, value, work, "finalization plan differs from " + label)
    if (plan_payload["issuedAtEpochNs"] < authorized.issued_at_epoch_ns
            or plan_payload["expiresAtEpochNs"] > authorized.expires_at_epoch_ns):
        raise RegistrationFinalizationPlanAdmissionError("finalization plan escapes its prior caller authorization")
    # Preserve the original opening bracket, narrowing every later phase to
    # the original caller, custody and plan intervals. No verifier reopens it.
    lifetime = min(window[5], authorized.maximum_age_ns, configured.maximum_control_age_ns)
    skew = min(window[6], authorized.maximum_clock_skew_ns, configured.pins[6][1])
    expires = min(window[3], window[0] + lifetime, authorized.expires_at_epoch_ns,
        plan_payload["expiresAtEpochNs"], expected["proofExpectations"]["policy"]["deadlineEpochNs"],
        *(value[1] for value in (verified_custody.intent_times, verified_custody.relay_times)))
    window = clock._validate((window[0], window[1], window[2], expires,
        window[1] + expires - window[0], lifetime, skew))
    bound = min(bound, window[4])
    current()
    return _AdmittedPlan(held, expected, configured, authorized,
        verified_custody.retained_record_digest, window, bound, current)
