"""Configured, authenticated live planning without implicit custody or execution.

The verifier signs independently admitted request/original-input data and real
root observations. The planner authenticates those originals before opening
its actual producer, and signs a response binding the request and exact raw3.
The receiving verifier authenticates that binding before genuine live replay.
Planner cutoff/time observations stay observations, not independent database
clock truth. The dedicated private preparation exchange explicitly admits
bounded live-origin history after the same genuine authentication and replay;
the original exchange return remains unchanged. No retained-record write,
reservation, execution or retry follows. All ownership, authentication, I/O
guards and replay use the original work.
"""
from __future__ import annotations

from catchplate import authority_query_reads as reads
from catchplate import authority_revocation_configuration as measured
from catchplate import authority_webauthn_evidence_custody_configuration as configuration
from catchplate import authority_webauthn_evidence_custody_wire as wire
from catchplate import authority_webauthn_evidence_plan_configuration as producer_configuration
from catchplate import authority_webauthn_evidence_plan_live as live
from catchplate import authority_webauthn_evidence_plan_owner as producing
from catchplate import authority_webauthn_evidence_plan_request as request_wire
from catchplate import authority_webauthn_evidence_plan_response as response_wire
from catchplate import authority_webauthn_evidence_plan_transport as transport


evidence = wire.evidence
_OPERATIONS = {"registration": "webauthn.registration.evidence.admit",
    "installation": "webauthn.trust.installation.admit"}


class WebAuthnEvidencePlanActionError(ValueError):
    pass


def _operation(purpose):
    if type(purpose) is not str or purpose not in _OPERATIONS:
        raise WebAuthnEvidencePlanActionError("evidence planning purpose is not source fixed")
    return _OPERATIONS[purpose]


def _fresh(timing, window, configured, work, transport_deadline_ns=None):
    now = wire._fresh_on_work(timing, window=window,
        maximum_age_ns=configured.maximum_control_age_ns,
        maximum_clock_skew_ns=configured.pins[9], work=work)
    if transport_deadline_ns is not None:
        evidence.production._callback(work, lambda: transport._check_deadline(transport_deadline_ns))
    return now


def _produce_request_on_configuration(*, purpose, payload, configuration_digest, generation,
        runtime_role_identities,
        request, business_before_roots, authorization_before_roots, inputs_bytes,
        deadline_epoch_ns, verifier_private_key, work):
    _operation(purpose)
    request_wire.inputs_wire._raw(inputs_bytes, 2, request_wire.MAX_INPUT_BYTES)
    original_inputs, private_key = inputs_bytes, verifier_private_key
    if not isinstance(private_key, wire.retention.plan.Ed25519PrivateKey):
        raise WebAuthnEvidencePlanActionError("evidence planning requires the real verifier signer")
    owned = reads._CopyBudget(work).copy({"request": request,
        "businessBeforeRoots": business_before_roots,
        "authorizationBeforeRoots": authorization_before_roots,
        "deadlineEpochNs": deadline_epoch_ns})
    configured = configuration._capture_on_work(purpose=purpose, payload=payload,
        configuration_digest=configuration_digest, generation=generation,
        runtime_role_identities=runtime_role_identities, work=work)
    return request_wire._produce_on_work(request=owned["request"],
        business_before_roots=owned["businessBeforeRoots"],
        authorization_before_roots=owned["authorizationBeforeRoots"], inputs_bytes=original_inputs,
        deadline_epoch_ns=owned["deadlineEpochNs"], pins=configured.pins,
        generation_sequence=configured.generation_sequence, generation_digest=configured.generation_digest,
        verifier_private_key=private_key, verifier_public_key=configured.verifier_public_key,
        maximum_control_age_ns=configured.maximum_control_age_ns, work=work)


def _produce_plan_on_configuration(*, purpose, payload, configuration_digest, generation,
        runtime_role_identities,
        control_bytes, context_bytes, inputs_bytes, read_dsn, planner_private_key, work):
    _operation(purpose)
    originals = transport._validate_request(control_bytes=control_bytes,
        context_bytes=context_bytes, inputs_bytes=inputs_bytes)
    private_key, dsn, digest = planner_private_key, read_dsn, configuration_digest
    if not isinstance(private_key, wire.retention.plan.Ed25519PrivateKey):
        raise WebAuthnEvidencePlanActionError("evidence planning requires the real planner signer")
    if (type(dsn) is not str or not 1 <= len(dsn) <= 65536
            or any(character in dsn for character in ("\x00", "\r", "\n"))):
        raise WebAuthnEvidencePlanActionError("evidence planning requires one protected read DSN")
    # Both fixed mappers must consume the same held graph, even after the
    # first mapper's key callbacks. Never reread caller configuration or DSN.
    ledger = evidence.capture._SharedLedger(work)
    evidence.plan.contract._digest(digest)
    if type(payload) is not dict or type(generation) is not dict:
        raise WebAuthnEvidencePlanActionError("evidence planning configuration is not closed data")
    measured.capability.shape._bounded_object(generation, 24, "evidence planning launch context")
    owned_payload = measured._ConfigurationCapture(
        ledger, maximum_bytes=wire.authority.MAX_REQUEST_BYTES).visit(payload)
    owned_runtime_identities = evidence.capture._JSONCapture(ledger, maximum_bytes=8192).visit(runtime_role_identities)
    held_generation = evidence.capture._JSONCapture(ledger).visit(
        {name: generation[name] for name in measured._GENERATION_FIELDS})
    configured = configuration._capture_on_work(purpose=purpose, payload=owned_payload,
        configuration_digest=digest, generation=held_generation,
        runtime_role_identities=owned_runtime_identities, work=work)
    verified = request_wire._verify_on_work(control_bytes=originals[0], context_bytes=originals[1],
        inputs_bytes=originals[2], pins=configured.pins,
        generation_sequence=configured.generation_sequence, generation_digest=configured.generation_digest,
        verifier_public_key=configured.verifier_public_key,
        maximum_control_age_ns=configured.maximum_control_age_ns, work=work)
    context, window = verified.context, verified.window
    issued, expires = verified.issued_at_epoch_ns, verified.expires_at_epoch_ns
    timing = {"issuedAtEpochNs": issued, "expiresAtEpochNs": expires}
    _fresh(timing, window, configured, work)
    producer = producer_configuration._producer_from_configuration_on_work(purpose=purpose,
        payload=owned_payload, configuration_digest=digest, generation=held_generation,
        runtime_role_identities=owned_runtime_identities,
        read_dsn=dsn, planner_private_key=private_key, work=work)
    _fresh(timing, window, configured, work)
    result = producing.EvidenceAdmissionPlanOwner.produce_originals(producer,
        request=context["request"], business_before_roots=context["businessBeforeRoots"],
        authorization_before_roots=context["authorizationBeforeRoots"], inputs_bytes=originals[2],
        deadline_epoch_ns=expires, work=work)
    _fresh(timing, window, configured, work)
    raw3 = result.envelope_bytes, result.inputs_bytes, result.evaluation_context_bytes
    live._verify_live_on_work(envelope_bytes=raw3[0], inputs_bytes=raw3[1],
        evaluation_context_bytes=raw3[2], request_context=context,
        request_issued_at_epoch_ns=issued, request_expires_at_epoch_ns=expires, request_window=window,
        pins=configured.pins, maximum_control_age_ns=configured.maximum_control_age_ns, work=work)
    response = response_wire._produce_on_work(request_control_bytes=originals[0],
        envelope_bytes=raw3[0], inputs_bytes=raw3[1], evaluation_context_bytes=raw3[2],
        pins=configured.pins, generation_sequence=configured.generation_sequence,
        generation_digest=configured.generation_digest, planner_private_key=private_key,
        verifier_public_key=configured.verifier_public_key, request_issued_at_epoch_ns=issued,
        request_expires_at_epoch_ns=expires, request_window=window,
        maximum_control_age_ns=configured.maximum_control_age_ns, work=work)
    _fresh(timing, window, configured, work)
    return transport._validate_response(response, *raw3)


def _request_plan_on_configuration_core(*, admit_history, purpose, payload, configuration_digest, generation,
        runtime_role_identities,
        control_bytes, context_bytes, inputs_bytes, work, transport_deadline_ns=None):
    if type(admit_history) is not bool:
        raise WebAuthnEvidencePlanActionError("evidence planning exchange action is not source fixed")
    _operation(purpose)
    inherited_deadline = transport_deadline_ns
    if inherited_deadline is not None:
        evidence.plan.contract._integer(inherited_deadline, minimum=1)
    originals = transport._validate_request(control_bytes=control_bytes,
        context_bytes=context_bytes, inputs_bytes=inputs_bytes)
    configured = configuration._capture_on_work(purpose=purpose, payload=payload,
        configuration_digest=configuration_digest, generation=generation,
        runtime_role_identities=runtime_role_identities, work=work)
    verified = request_wire._verify_on_work(control_bytes=originals[0], context_bytes=originals[1],
        inputs_bytes=originals[2], pins=configured.pins,
        generation_sequence=configured.generation_sequence, generation_digest=configured.generation_digest,
        verifier_public_key=configured.verifier_public_key,
        maximum_control_age_ns=configured.maximum_control_age_ns, work=work)
    context, window = verified.context, verified.window
    effective_deadline = None if inherited_deadline is None else min(inherited_deadline, window[4])
    issued, expires = verified.issued_at_epoch_ns, verified.expires_at_epoch_ns
    timing = {"issuedAtEpochNs": issued, "expiresAtEpochNs": expires}
    endpoint = configured.planner_endpoint
    _fresh(timing, window, configured, work, effective_deadline)
    received = evidence.production._callback(work, lambda: transport._socket_request(endpoint,
        purpose=purpose, control_bytes=originals[0], context_bytes=originals[1], inputs_bytes=originals[2],
        deadline_ns=effective_deadline))
    if type(received) is not tuple or len(received) != 4:
        raise WebAuthnEvidencePlanActionError("evidence planning response is not an exact four-tuple")
    returned = transport._validate_response(*received)
    _fresh(timing, window, configured, work, effective_deadline)
    # Authenticate exact context bytes and every other original before any
    # returned context is decoded or used even as claimed planner observations.
    response_wire._verify_on_work(control_bytes=returned[0], request_control_bytes=originals[0],
        envelope_bytes=returned[1], inputs_bytes=returned[2], evaluation_context_bytes=returned[3],
        pins=configured.pins, generation_sequence=configured.generation_sequence,
        generation_digest=configured.generation_digest, verifier_public_key=configured.verifier_public_key,
        request_issued_at_epoch_ns=issued, request_expires_at_epoch_ns=expires, request_window=window,
        maximum_control_age_ns=configured.maximum_control_age_ns, work=work)
    work.charge(input_bytes=len(originals[2]) + len(returned[2]))
    if originals[2] != returned[2]:
        raise WebAuthnEvidencePlanActionError("evidence planning response changed the original inputs")
    if admit_history:
        history = live._admit_history_on_work(envelope_bytes=returned[1], inputs_bytes=returned[2],
            evaluation_context_bytes=returned[3], request_context=context,
            request_issued_at_epoch_ns=issued, request_expires_at_epoch_ns=expires, request_window=window,
            pins=configured.pins, maximum_control_age_ns=configured.maximum_control_age_ns, work=work)
    else:
        live._verify_live_on_work(envelope_bytes=returned[1], inputs_bytes=returned[2],
            evaluation_context_bytes=returned[3], request_context=context,
            request_issued_at_epoch_ns=issued, request_expires_at_epoch_ns=expires, request_window=window,
            pins=configured.pins, maximum_control_age_ns=configured.maximum_control_age_ns, work=work)
    _fresh(timing, window, configured, work, effective_deadline)
    # Preserve the old return unchanged. The separate fixed preparation path
    # may receive newly admitted live-origin history, never a reusable proof DTO.
    return (returned, history) if admit_history else returned


def _request_plan_on_configuration(*, purpose, payload, configuration_digest, generation,
        runtime_role_identities, control_bytes, context_bytes, inputs_bytes, work, transport_deadline_ns=None):
    return _request_plan_on_configuration_core(admit_history=False, purpose=purpose,
        payload=payload, configuration_digest=configuration_digest, generation=generation,
        runtime_role_identities=runtime_role_identities, control_bytes=control_bytes,
        context_bytes=context_bytes, inputs_bytes=inputs_bytes, work=work,
        transport_deadline_ns=transport_deadline_ns)


def _request_plan_and_admit_history_on_configuration(*, purpose, payload, configuration_digest, generation,
        runtime_role_identities, control_bytes, context_bytes, inputs_bytes, work, transport_deadline_ns=None):
    """Authenticate both original controls, replay raw3, then admit live history.

    This is the source-owned observation-admission path for private preparation,
    not a generic stored-context adapter or upstream typed-request authorization.
    """
    return _request_plan_on_configuration_core(admit_history=True, purpose=purpose,
        payload=payload, configuration_digest=configuration_digest, generation=generation,
        runtime_role_identities=runtime_role_identities, control_bytes=control_bytes,
        context_bytes=context_bytes, inputs_bytes=inputs_bytes, work=work,
        transport_deadline_ns=transport_deadline_ns)
