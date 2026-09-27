"""Prepare original transition custody bytes from one admitted live invocation.

The upstream owner must admit the typed request, original inputs and evaluation
instant, and the stage capability or completion committed-stage history. This
private composition does not infer that provenance from their JSON. The real
verifier independently reads roots and signs the request; the real planner
exchange authenticates both controls and replays raw4 before admitting derived
live history. Only its bounded cutoff is a planner-observed historical fact.

One work allowance, current measured configuration/generation/archive and one
nonrenewable local window span request, plan, intent and relay preparation.
All signed intervals must fit the held current archive authorization. The
result is raw7 for a caller journal, not a durable receipt, authorization to
execute, or evidence that a caller journal has actually retained it. There is
no writer contact, automatic forwarding, retry or replacement allowance.
"""
from __future__ import annotations

from serverware import authority_webauthn_custody_history as history
from serverware import authority_webauthn_transition_actions as actions
from serverware import authority_webauthn_transition_custody_transport as transport
from serverware import authority_webauthn_transition_custody_wire as wire
from serverware import authority_webauthn_transition_service as transition


evidence, clock, plan = wire.evidence, wire.clock, wire.retention.plan


class WebAuthnTransitionPreparationError(ValueError):
    pass


def _same_owner(process, measured, archive):
    if (process.configuration is not measured or measured.history_archive is not archive
            or process.role_name != "verifier" or process.process_mode != "policy-authority-verifier"):
        raise WebAuthnTransitionPreparationError("transition preparation admission changed during this call")


def _interval(value, snapshots):
    # Capture ordinary immutable scalars before any subsequent native work.
    issued, expires = value["issuedAtEpochNs"], value["expiresAtEpochNs"]
    plan.contract.shape._integer(issued, minimum=1)
    plan.contract.shape._integer(expires, minimum=1)
    if (issued >= expires or issued < snapshots.valid_from_epoch_ns
            or expires > snapshots.valid_until_epoch_ns):
        raise WebAuthnTransitionPreparationError("transition signed interval exceeds current archive admission")
    return issued, expires


def _current_on_work(process, measured, archive, snapshots, generation, window, controls, work,
        transport_deadline_ns=None):
    if transport_deadline_ns is not None:
        evidence.production._callback(work, lambda: transport._check_deadline(transport_deadline_ns))
    _same_owner(process, measured, archive)
    transition._require_generation_on_work("verifier", generation, work)
    _same_owner(process, measured, archive)
    now = clock._check_on_work(window, work=work)
    if not snapshots.valid_from_epoch_ns <= now < snapshots.valid_until_epoch_ns:
        raise WebAuthnTransitionPreparationError("transition preparation archive is no longer current")
    for issued, expires in controls:
        if issued > now + window[6] or now >= expires:
            raise WebAuthnTransitionPreparationError("transition preparation original control is no longer live")
    _same_owner(process, measured, archive)
    if transport_deadline_ns is not None:
        evidence.production._callback(work, lambda: transport._check_deadline(transport_deadline_ns))
    return now


def _prepare_on_work(process, *, operation, request, inputs_bytes,
        now_epoch_ns, deadline_epoch_ns, invocation, work, transport_deadline_ns=None):
    """Return raw7 only after real request/response, plan, intent and relay work.

    Registration invocation is empty; stage capabilityId and completion
    committedStage still require independent admission by the upstream owner.
    Neither an existing context nor a successful-proof carrier is accepted.
    """
    return _prepare_core(process, operation=operation, request=request, inputs_bytes=inputs_bytes,
        now_epoch_ns=now_epoch_ns, deadline_epoch_ns=deadline_epoch_ns, invocation=invocation,
        work=work, transport_deadline_ns=transport_deadline_ns, complete_before=False,
        original_window=None)


def _prepare_finalization_execution_on_work(process, *, request, inputs_bytes,
        now_epoch_ns, deadline_epoch_ns, invocation, live_window, work, transport_deadline_ns):
    """Return custody raw7 and the SAME actual vector used to sign its request."""
    return _prepare_core(process, operation=transition.root_contract.registration.OPERATION,
        request=request, inputs_bytes=inputs_bytes, now_epoch_ns=now_epoch_ns,
        deadline_epoch_ns=deadline_epoch_ns, invocation=invocation, work=work,
        transport_deadline_ns=transport_deadline_ns, complete_before=True,
        original_window=live_window)


def _prepare_core(process, *, operation, request, inputs_bytes, now_epoch_ns,
        deadline_epoch_ns, invocation, work, transport_deadline_ns, complete_before, original_window):
    from serverware import authority_service as service

    ledger = evidence.capture._SharedLedger(work)
    if (type(process) is not service.AuthorityProcess or process.role_name != "verifier"
            or process.process_mode != service.PROCESS_MODES["verifier"]):
        raise WebAuthnTransitionPreparationError("transition preparation requires the actual verifier")
    measured = process.configuration
    if type(measured) is not service.MeasuredConfiguration:
        raise WebAuthnTransitionPreparationError("transition preparation requires measured configuration")
    archive = measured.history_archive
    operation = transition._operation(operation)
    if type(complete_before) is not bool or (complete_before
            and operation != transition.root_contract.registration.OPERATION):
        raise WebAuthnTransitionPreparationError("complete-before preparation is not fixed finalization")
    plan.proof.wire._raw(inputs_bytes, 2, plan.proof.wire.MAX_BYTES)
    original_inputs, inherited_deadline = inputs_bytes, transport_deadline_ns
    if inherited_deadline is not None:
        plan.contract.shape._integer(inherited_deadline, minimum=1)
    owned = evidence.capture._JSONCapture(ledger, maximum_bytes=plan.contract.MAX_BYTES).visit(
        {"request": request, "nowEpochNs": now_epoch_ns,
            "deadlineEpochNs": deadline_epoch_ns, "invocation": invocation})
    owned_request = transition.root_contract._capture_request_on_work(
        request=owned["request"], operation=operation, work=work)
    for name in ("nowEpochNs", "deadlineEpochNs"):
        plan.contract.shape._integer(owned[name], minimum=1)
    if owned["nowEpochNs"] >= owned["deadlineEpochNs"]:
        raise WebAuthnTransitionPreparationError("transition invocation has no positive original lifetime")

    # Own all configuration/runtime and caller graphs before clock, launch or
    # key callbacks. The exact current object remains pinned for later real
    # AuthorityProcess methods, which independently read their own admission.
    payload, digest, runtime = measured.payload, measured.digest, measured.runtime_role_identities
    plan.contract.shape._digest(digest)
    payload = transition.configuration._ConfigurationCapture(
        ledger, maximum_bytes=wire.authority.MAX_REQUEST_BYTES).visit(payload)
    runtime = evidence.capture._JSONCapture(ledger, maximum_bytes=8192).visit(runtime)
    snapshots = history.archive._capture_on_work(archive, work=work)
    if not snapshots.valid_from_epoch_ns <= owned["nowEpochNs"] < snapshots.valid_until_epoch_ns:
        raise WebAuthnTransitionPreparationError("original transition evaluation is outside current archive admission")
    if complete_before:
        supplied = clock._validate(original_window)
        end = min(supplied[3], owned["deadlineEpochNs"], snapshots.valid_until_epoch_ns)
        window = clock._validate((supplied[0], supplied[1], supplied[2], end,
            min(supplied[4], supplied[1] + end - supplied[0]), supplied[5], supplied[6]))
    else:
        window = clock._open_on_work(
            deadline_epoch_ns=min(owned["deadlineEpochNs"], snapshots.valid_until_epoch_ns),
            maximum_lifetime_ns=wire.authority.VERIFIER_RESPONSE_MAX_AGE_NS,
            maximum_clock_skew_ns=wire.authority.VERIFIER_MAX_CLOCK_SKEW_NS, work=work)
    if not snapshots.valid_from_epoch_ns <= window[0] < snapshots.valid_until_epoch_ns:
        raise WebAuthnTransitionPreparationError("transition preparation archive is not current")
    _same_owner(process, measured, archive)
    evidence.production._callback(work, lambda: service.authority_launch_guard.require_active("verifier"))
    generation = evidence.production._callback(
        work, lambda: dict(service.authority_launch_guard.generation()))
    generation = transition._generation_on_work(generation, work)
    configured = actions.configuration._capture_on_work(operation=operation, payload=payload,
        configuration_digest=digest, generation=generation,
        runtime_role_identities=runtime, work=work)
    # Narrow the SAME opening bracket after the real mapper provides policy.
    # No later epoch or monotonic sample becomes a fresh lifetime origin.
    start, before, after = window[:3]
    end = min(window[3], start + configured.maximum_control_age_ns)
    window = clock._validate((start, before, after, end, before + end - start,
        min(window[5], configured.maximum_control_age_ns) if complete_before
            else configured.maximum_control_age_ns,
        min(window[6], configured.pins[6][1]) if complete_before else configured.pins[6][1]))
    # An inherited absolute transport bound can only narrow this same original
    # opening. It never rewrites signed control times or starts a new window.
    effective_deadline = None if inherited_deadline is None else min(inherited_deadline, window[4])
    if complete_before:
        effective_deadline = window[4] if effective_deadline is None else effective_deadline
    controls = ()
    _current_on_work(process, measured, archive, snapshots, generation, window, controls, work,
        effective_deadline)

    before = None
    if complete_before:
        requested, before = transition._produce_finalization_execution_request_on_work(process,
            request=owned_request, inputs_bytes=original_inputs,
            now_epoch_ns=owned["nowEpochNs"], deadline_epoch_ns=window[3],
            invocation=owned["invocation"], work=work, transport_deadline_ns=effective_deadline)
    else:
        requested = service.AuthorityProcess._produce_webauthn_transition_plan_request(process,
            operation=operation, request=owned_request, inputs_bytes=original_inputs,
            now_epoch_ns=owned["nowEpochNs"], deadline_epoch_ns=owned["deadlineEpochNs"],
            invocation=owned["invocation"], work=work)
    originals = actions.transport._validate_request(
        requested.control_bytes, requested.context_bytes, requested.inputs_bytes)
    value, _signature, _unsigned = actions.request_wire._read_control(originals[0], work)
    controls = (_interval(value, snapshots),)
    _current_on_work(process, measured, archive, snapshots, generation, window, controls, work,
        effective_deadline)
    response, expected = actions._request_plan_and_admit_history_on_configuration(
        operation=operation, payload=payload, configuration_digest=digest, generation=generation,
        runtime_role_identities=runtime, control_bytes=originals[0],
        context_bytes=originals[1], inputs_bytes=originals[2], work=work,
        transport_deadline_ns=effective_deadline)
    now = _current_on_work(process, measured, archive, snapshots, generation, window, controls, work,
        effective_deadline)
    response = actions.transport._validate_response(*response)
    raw4 = response[1:]
    # Actual exchange/replay has authenticated raw4 before this timing-only
    # projection. No returned plan/context supplies a request or history pin.
    envelope = evidence.wire._decode_object(raw4[0], work=work,
        maximum_bytes=plan.contract.MAX_BYTES, maximum_nodes=plan.contract.MAX_NODES,
        maximum_depth=plan.contract.MAX_DEPTH)
    plan.contract.validate_envelope_shape(envelope)
    evidence.capability._canonical(raw4[0], envelope, ledger,
        plan.contract.MAX_BYTES, plan.contract.MAX_NODES)
    plan_payload = envelope["payload"]
    _interval(plan_payload, snapshots)
    proof = expected["proofExpectations"]
    for instant in (proof["policy"]["nowEpochNs"], proof["databaseCutoffUs"] * 1000):
        if not snapshots.valid_from_epoch_ns <= instant < snapshots.valid_until_epoch_ns:
            raise WebAuthnTransitionPreparationError("admitted live transition history exceeds the archive interval")
    plan._fresh(plan_payload, expected, now)
    historical = plan.context._encode_on_work(expectations=expected, work=work)
    now = _current_on_work(process, measured, archive, snapshots, generation, window, controls, work,
        effective_deadline)
    plan._fresh(plan_payload, expected, now)

    produced = service.AuthorityProcess._produce_webauthn_transition_custody_intent(process,
        operation=operation, envelope_bytes=raw4[0], proof_bytes=raw4[1],
        inputs_bytes=raw4[2], context_bytes=raw4[3], expectations=expected, work=work)
    intent_bytes, history_bytes = produced.intent_bytes, produced.historical_expectations_bytes
    wire._raw5(*raw4, history_bytes)
    work.charge(input_bytes=len(historical) + len(history_bytes))
    if historical != history_bytes:
        raise WebAuthnTransitionPreparationError("custody intent changed the source-admitted live history")
    value, _signature, _unsigned = wire._read_control(intent_bytes, relay=False, work=work)
    controls += (_interval(value, snapshots),)
    now = _current_on_work(process, measured, archive, snapshots, generation, window, controls, work,
        effective_deadline)
    plan._fresh(plan_payload, expected, now)
    relay_bytes = service.AuthorityProcess._request_webauthn_transition_custody_relay(process,
        operation=operation, intent_bytes=intent_bytes, envelope_bytes=raw4[0],
        proof_bytes=raw4[1], inputs_bytes=raw4[2], context_bytes=raw4[3],
        historical_expectations_bytes=history_bytes, work=work,
        transport_deadline_ns=effective_deadline)
    value, _signature, _unsigned = wire._read_control(relay_bytes, relay=True, work=work)
    controls += (_interval(value, snapshots),)
    result = transport._validate_originals(intent_bytes=intent_bytes, relay_bytes=relay_bytes,
        envelope_bytes=raw4[0], proof_bytes=raw4[1], inputs_bytes=raw4[2],
        context_bytes=raw4[3], historical_expectations_bytes=history_bytes)
    now = _current_on_work(process, measured, archive, snapshots, generation, window, controls, work,
        effective_deadline)
    plan._fresh(plan_payload, expected, now)
    return (*result, before) if complete_before else result
