"""Authenticate a complete live planning exchange before registration grants.

The cold service supplies root-admitted configuration, active generation and
runtime role identities, the root key and its separately enrolled authorizer
key. This module checks their consistency; it cannot establish that provenance.
No submitted expectations, decoded historical context or successful replay
carrier is accepted. The original verifier-signed request supplies the request,
roots and inputs; the planner-signed response binds that request and exact raw3.
Only genuine live replay admits its three bounded planner time observations.

The dedicated caller authorization is separately verified by the actual grant
producer and joined to the replayed request before signing. Its original issue
and expiry remain intact. All phases share the caller's cumulative work and
original deadlines. The complete before vector is checked by genuine downstream
replay, not promoted to current-root authority. No socket, DSN, SQL, reservation,
one-use store, deployment, trusted clock or new work allowance is supplied here.
"""
from __future__ import annotations

import time

from serverware import authority_registration_execution_authorization as authorization
from serverware import authority_registration_execution_grant_production as producing
from serverware import authority_revocation_configuration as measured
from serverware import authority_webauthn_evidence_custody_configuration as configuration
from serverware import authority_webauthn_evidence_plan_live as live_plan
from serverware import authority_webauthn_evidence_plan_request as request_wire
from serverware import authority_webauthn_evidence_plan_response as response_wire
from serverware import authority_webauthn_evidence_plan_transport as transport


evidence, wire, clock = live_plan.evidence, live_plan.wire, live_plan.clock
grants = producing.production.grants
MAX_ORIGINAL_BYTES = grants.replay.MAX_ORIGINAL_BYTES


class RegistrationExecutionExchangeError(ValueError):
    pass


def _produce_on_configuration(*, payload, configuration_digest, generation,
        runtime_role_identities, request_originals, response_originals,
        before_vector_bytes, authorization_bytes, authorization_enrollment_bytes,
        grant_enrollment_bytes, current_root_enrollment_bytes, root_public_key,
        authorizer_private_key, deadline_epoch_ns, work, transport_deadline_ns=None):
    """Return one signed grant only after original exchange and request replay.

    The request tuple is (control, context, inputs); the response tuple is
    (control, plan envelope, inputs, evaluation context). The cold owner retains
    all independent pins. The returned bytes are a grant, not execution success.
    """
    ledger = evidence.capture._SharedLedger(work)
    if type(request_originals) is not tuple or len(request_originals) != 3:
        raise RegistrationExecutionExchangeError("planning request is not an exact original three-tuple")
    if type(response_originals) is not tuple or len(response_originals) != 4:
        raise RegistrationExecutionExchangeError("planning response is not an exact original four-tuple")
    request_raw = transport._validate_request(control_bytes=request_originals[0],
        context_bytes=request_originals[1], inputs_bytes=request_originals[2])
    response_raw = transport._validate_response(*response_originals)
    raw3, before_raw = grants.replay._originals(authorization.OPERATION,
        response_raw[1:], before_vector_bytes)
    caller_raw = grants.authorization._original(authorization_bytes,
        authorization.MAX_AUTHORIZATION_BYTES, "registration request authorization")
    caller_enrollment = grants.authorization._original(authorization_enrollment_bytes,
        authorization.MAX_ENROLLMENT_BYTES, "registration request authorization enrollment")
    grant_enrollment = grants.authorization._original(grant_enrollment_bytes,
        grants.MAX_ENROLLMENT_BYTES, "successor grant enrollment")
    current_enrollment = grants.authorization._original(current_root_enrollment_bytes,
        grants.authorization.MAX_ENROLLMENT_BYTES, "current-root enrollment")
    # Count both transmitted input occurrences in the source inventory, even
    # though their byte equality is mandatory after response authentication.
    if sum(len(raw) for raw in (*request_raw, *response_raw, before_raw, caller_raw,
            caller_enrollment, grant_enrollment, current_enrollment)) > MAX_ORIGINAL_BYTES:
        raise RegistrationExecutionExchangeError("registration execution originals exceed the source aggregate")
    root, signer, digest = root_public_key, authorizer_private_key, configuration_digest
    grants.authorization._public(root)
    grants.authorization._private(signer)
    shape = evidence.plan.contract
    shape._digest(digest)
    shape._integer(deadline_epoch_ns, minimum=1)
    if transport_deadline_ns is not None:
        shape._integer(transport_deadline_ns, minimum=1)
    deadline, inherited = deadline_epoch_ns, transport_deadline_ns
    # Detach every caller-owned graph before configuration's actual key
    # callbacks. Generation/cohort consistency never substitutes for admission.
    if type(payload) is not dict or type(generation) is not dict:
        raise RegistrationExecutionExchangeError("registration configuration is not exact local data")
    measured.capability.shape._bounded_object(generation, 24, "registration execution launch context")
    owned_payload = measured._ConfigurationCapture(ledger,
        maximum_bytes=wire.authority.MAX_REQUEST_BYTES).visit(payload)
    owned_generation = evidence.capture._JSONCapture(ledger).visit(
        {name: generation[name] for name in measured._GENERATION_FIELDS})
    owned_runtime = evidence.capture._JSONCapture(ledger,
        maximum_bytes=8192).visit(runtime_role_identities)
    if inherited is not None:
        evidence.production._callback(work, lambda: transport._check_deadline(inherited))
    configured = configuration._capture_on_work(purpose="registration", payload=owned_payload,
        configuration_digest=digest, generation=owned_generation,
        runtime_role_identities=owned_runtime, work=work)
    verified = request_wire._verify_on_work(control_bytes=request_raw[0],
        context_bytes=request_raw[1], inputs_bytes=request_raw[2], pins=configured.pins,
        generation_sequence=configured.generation_sequence, generation_digest=configured.generation_digest,
        verifier_public_key=configured.verifier_public_key,
        maximum_control_age_ns=configured.maximum_control_age_ns, work=work)
    context = verified.context
    issued, expires = verified.issued_at_epoch_ns, verified.expires_at_epoch_ns
    original_window = clock._validate(verified.window)
    effective_expiry = min(deadline, expires, original_window[3])
    window = clock._validate((original_window[0], original_window[1], original_window[2],
        effective_expiry, original_window[1] + effective_expiry - original_window[0],
        original_window[5], original_window[6]))
    bound = window[4] if inherited is None else min(window[4], inherited)
    timing = {"issuedAtEpochNs": issued, "expiresAtEpochNs": expires}
    last_epoch, last_monotonic = window[0], window[2]

    def live():
        nonlocal last_epoch, last_monotonic
        now = wire._fresh_on_work(timing, window=window,
            maximum_age_ns=configured.maximum_control_age_ns,
            maximum_clock_skew_ns=configured.pins[9], work=work)
        monotonic = evidence.production._callback(work, time.monotonic_ns)
        shape._integer(monotonic, minimum=1)
        if now < last_epoch or monotonic < last_monotonic or monotonic >= bound:
            raise RegistrationExecutionExchangeError("registration exchange expired or its original clocks reversed")
        last_epoch, last_monotonic = now, monotonic

    live()
    # A verified request alone does not authenticate returned historical bytes.
    # This genuine planner signature binds the request control and complete raw3
    # before the evaluation context may be decoded as bounded observations.
    response_wire._verify_on_work(control_bytes=response_raw[0],
        request_control_bytes=request_raw[0], envelope_bytes=raw3[0], inputs_bytes=raw3[1],
        evaluation_context_bytes=raw3[2], pins=configured.pins,
        generation_sequence=configured.generation_sequence, generation_digest=configured.generation_digest,
        verifier_public_key=configured.verifier_public_key, request_issued_at_epoch_ns=issued,
        request_expires_at_epoch_ns=expires, request_window=window,
        maximum_control_age_ns=configured.maximum_control_age_ns, work=work)
    work.charge(input_bytes=len(request_raw[2]) + len(raw3[1]))
    if request_raw[2] != raw3[1]:
        raise RegistrationExecutionExchangeError("planning response changed the authenticated original inputs")
    live()
    history = live_plan._admit_history_on_work(envelope_bytes=raw3[0], inputs_bytes=raw3[1],
        evaluation_context_bytes=raw3[2], request_context=context,
        request_issued_at_epoch_ns=issued, request_expires_at_epoch_ns=expires,
        request_window=window, pins=configured.pins,
        maximum_control_age_ns=configured.maximum_control_age_ns, work=work)
    live()
    enrollment = grants._admit_enrollment_on_work(grant_enrollment_bytes=grant_enrollment,
        current_root_enrollment_bytes=current_enrollment, root_public_key=root, work=work)
    evidence.plan._same(enrollment.payload["generationDigest"], configured.generation_digest,
        work, "registration grant enrollment differs from the active planning generation")
    live()
    # This raw-original composition repeats genuine plan/vector replay and
    # verifies the dedicated caller request before joining its exact request
    # and operation IDs. No same-call successful carrier replaces those gates.
    result = producing._produce_on_work(originals=raw3, expectations=history,
        planner_public_key=configured.pins[1], evidence_public_key=configured.pins[4],
        before_vector_bytes=before_raw, authorization_bytes=caller_raw,
        authorization_enrollment_bytes=caller_enrollment, grant_enrollment_bytes=grant_enrollment,
        current_root_enrollment_bytes=current_enrollment, root_public_key=root,
        authorizer_private_key=signer, configuration_digest=digest,
        deadline_epoch_ns=effective_expiry, work=work, transport_deadline_ns=bound)
    live()
    return result
