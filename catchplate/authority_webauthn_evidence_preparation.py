"""Private live-origin preparation of exact journal-ready evidence raw6.

The actual verifier's typed-request and original-input admission is an upstream
precondition. This composition is not a public authorization boundary. It uses
real root acquisition, authenticated planning, explicit bounded live-history
admission, another actual root comparison, genuine custody-intent production
and planner relay preparation. Every phase spends the same caller work.

The returned history records verifier-admitted bounded planner observations,
not independent database-clock truth, currently reserved roots or execution
authority. No writer is contacted, no journal is modified, and no delivery or
retry occurs. The caller must durably retain the exact raw6 before separately
claiming its one potentially committing forward attempt.
"""
from __future__ import annotations

from catchplate import authority_historical_archive as archive
from catchplate import authority_launch_guard as launch
from catchplate import authority_revocation_configuration as measured_configuration
from catchplate import authority_webauthn_evidence_custody_configuration as configuration
from catchplate import authority_webauthn_evidence_custody_transport as custody_transport
from catchplate import authority_webauthn_evidence_custody_wire as wire
from catchplate import authority_webauthn_evidence_plan_actions as actions
from catchplate import authority_webauthn_evidence_plan_request as request_wire
from catchplate import authority_webauthn_evidence_plan_transport as plan_transport


evidence, retention, clock = wire.evidence, wire.retention, wire.clock


class WebAuthnEvidencePreparationError(ValueError):
    pass


def _interval(issued, expires, validity):
    if not validity[0] <= issued < expires <= validity[1]:
        raise WebAuthnEvidencePreparationError("prepared original interval exceeds the current admitted archive")


def _current(process, measured, held_archive, digest, generation, runtime, window, validity, work,
        transport_deadline_ns=None):
    if transport_deadline_ns is not None:
        evidence.production._callback(work, lambda: plan_transport._check_deadline(transport_deadline_ns))
    if (process.configuration is not measured or measured.history_archive is not held_archive
            or measured.digest != digest or process.role_name != "verifier"
            or process.process_mode != "policy-authority-verifier"):
        raise WebAuthnEvidencePreparationError("evidence preparation changed its actual verifier scope")
    evidence.production._callback(work, lambda: launch.require_active("verifier"))
    actual_generation = evidence.production._callback(work, lambda: dict(launch.generation()))
    evidence.plan._same(tuple(generation[name] for name in measured_configuration._GENERATION_FIELDS),
        tuple(actual_generation[name] for name in measured_configuration._GENERATION_FIELDS), work,
        "evidence preparation generation changed")
    evidence.plan._same(measured.runtime_role_identities, runtime, work,
        "evidence preparation admitted runtime cohort changed")
    now = clock._check_on_work(window, work=work)
    if not validity[0] <= now < validity[1]:
        raise WebAuthnEvidencePreparationError("evidence preparation archive authorization expired")
    if (process.configuration is not measured or measured.history_archive is not held_archive
            or measured.digest != digest):
        raise WebAuthnEvidencePreparationError("evidence preparation current configuration changed during callbacks")
    if transport_deadline_ns is not None:
        evidence.production._callback(work, lambda: plan_transport._check_deadline(transport_deadline_ns))


def _plan_interval(envelope_bytes, validity, work):
    contract = retention.plan.contract
    ledger = evidence.capture._SharedLedger(work)
    envelope = evidence.wire._decode_object(envelope_bytes, work=work,
        maximum_bytes=contract.MAX_BYTES, maximum_nodes=contract.MAX_NODES, maximum_depth=contract.MAX_DEPTH)
    contract.validate_envelope_shape(envelope)
    evidence.capability._canonical(envelope_bytes, envelope, ledger, contract.MAX_BYTES, contract.MAX_NODES)
    payload = envelope["payload"]
    _interval(payload["issuedAtEpochNs"], payload["expiresAtEpochNs"], validity)


def _prepare_on_work(process, *, purpose, request, inputs_bytes, deadline_epoch_ns, work,
        transport_deadline_ns=None):
    """Prepare raw6; upstream must already admit the typed request and inputs."""
    from catchplate import authority_service as service

    ledger = evidence.capture._SharedLedger(work)
    operation = service._webauthn_evidence_custody_purpose(purpose)
    request_wire.inputs_wire._raw(inputs_bytes, 2, request_wire.MAX_INPUT_BYTES)
    original_inputs, deadline, inherited_deadline = inputs_bytes, deadline_epoch_ns, transport_deadline_ns
    evidence.plan.contract._integer(deadline, minimum=1)
    if inherited_deadline is not None:
        evidence.plan.contract._integer(inherited_deadline, minimum=1)
    owned_request = evidence.capture._JSONCapture(ledger,
        maximum_bytes=request_wire.MAX_CONTEXT_BYTES).visit(request)
    retention.plan.contract._request(owned_request, operation, retention.plan.contract._SPECS[operation])
    if (type(process) is not service.AuthorityProcess or process.role_name != "verifier"
            or process.process_mode != "policy-authority-verifier"):
        raise WebAuthnEvidencePreparationError("evidence preparation requires the actual verifier process")
    measured = process.configuration
    if type(measured) is not service.MeasuredConfiguration:
        raise WebAuthnEvidencePreparationError("evidence preparation measured configuration is unavailable")
    held_archive, digest = measured.history_archive, measured.digest
    snapshots = archive._capture_on_work(held_archive, work=work)
    validity = snapshots.valid_from_epoch_ns, snapshots.valid_until_epoch_ns
    # This real continuation owns complete configuration/runtime graphs before
    # its native active-launch calls and captures admitted generation last.
    payload, captured_digest, generation, _dsn, _signer, runtime = service._webauthn_evidence_custody_context(
        process, role_name="verifier", signing=False, work=work)
    evidence.plan._same(captured_digest, digest, work, "evidence preparation configuration changed")
    held_generation = evidence.capture._JSONCapture(ledger).visit(
        {name: generation[name] for name in measured_configuration._GENERATION_FIELDS})
    configured = configuration._capture_on_work(purpose=purpose, payload=payload,
        configuration_digest=digest, generation=held_generation,
        runtime_role_identities=runtime, work=work)
    window = clock._open_on_work(deadline_epoch_ns=min(deadline, validity[1]),
        maximum_lifetime_ns=configured.maximum_control_age_ns,
        maximum_clock_skew_ns=configured.pins[9], work=work)
    # The inherited clock bound only narrows ongoing work and I/O. It never
    # rewrites original signed-control times or renews this opening window.
    effective_deadline = None if inherited_deadline is None else min(inherited_deadline, window[4])
    _current(process, measured, held_archive, digest, held_generation, runtime, window, validity, work,
        effective_deadline)

    planned_request = service.AuthorityProcess._produce_webauthn_evidence_plan_request(process,
        purpose=purpose, request=owned_request, inputs_bytes=original_inputs,
        deadline_epoch_ns=deadline, work=work)
    request_originals = plan_transport._validate_request(control_bytes=planned_request.control_bytes,
        context_bytes=planned_request.context_bytes, inputs_bytes=planned_request.inputs_bytes)
    request_control, _signature, _unsigned = request_wire._read_control(request_originals[0], work)
    _interval(request_control["issuedAtEpochNs"], request_control["expiresAtEpochNs"], validity)
    _current(process, measured, held_archive, digest, held_generation, runtime, window, validity, work,
        effective_deadline)

    response, history = actions._request_plan_and_admit_history_on_configuration(purpose=purpose,
        payload=payload, configuration_digest=digest, generation=held_generation,
        runtime_role_identities=runtime, control_bytes=request_originals[0],
        context_bytes=request_originals[1], inputs_bytes=request_originals[2], work=work,
        transport_deadline_ns=effective_deadline)
    response = plan_transport._validate_response(*response)
    _plan_interval(response[1], validity, work)
    for original_time in (history["nowEpochNs"], history["databaseCutoffUs"] * 1000):
        if not validity[0] <= original_time < validity[1]:
            raise WebAuthnEvidencePreparationError("live-origin evidence observations lie outside the current archive")
    _current(process, measured, held_archive, digest, held_generation, runtime, window, validity, work,
        effective_deadline)

    # History comes only from the real authenticated exchange's dedicated
    # live-origin admission, never from a decoded returned context or DTO.
    produced_intent = service.AuthorityProcess._produce_webauthn_evidence_custody_intent(process,
        purpose=purpose, envelope_bytes=response[1], inputs_bytes=response[2],
        evaluation_context_bytes=response[3], expectations=history, work=work)
    intent_bytes, historical_bytes = produced_intent.intent_bytes, produced_intent.historical_expectations_bytes
    intent, _signature, _unsigned = wire._read_control(intent_bytes, relay=False, work=work)
    _interval(intent["issuedAtEpochNs"], intent["expiresAtEpochNs"], validity)
    _current(process, measured, held_archive, digest, held_generation, runtime, window, validity, work,
        effective_deadline)

    relay_bytes = service.AuthorityProcess._request_webauthn_evidence_custody_relay(process,
        purpose=purpose, intent_bytes=intent_bytes, envelope_bytes=response[1], inputs_bytes=response[2],
        evaluation_context_bytes=response[3], historical_expectations_bytes=historical_bytes, work=work,
        transport_deadline_ns=effective_deadline)
    relay, _signature, _unsigned = wire._read_control(relay_bytes, relay=True, work=work)
    _interval(relay["issuedAtEpochNs"], relay["expiresAtEpochNs"], validity)
    originals = custody_transport._validate_originals(intent_bytes=intent_bytes, relay_bytes=relay_bytes,
        envelope_bytes=response[1], inputs_bytes=response[2], evaluation_context_bytes=response[3],
        historical_expectations_bytes=historical_bytes)
    _current(process, measured, held_archive, digest, held_generation, runtime, window, validity, work,
        effective_deadline)
    return originals
