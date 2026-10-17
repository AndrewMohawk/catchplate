"""Authenticated original-byte planning for three fixed successor operations.

The verifier signs independently admitted invocation data and source-complete
root observations. The planner authenticates that request before constructing
its configured original-input producer. Its real acquisition and single proof
replay precede plan signing; a separate response signature binds raw4 to the
original request control. The client authenticates that response before using
bounded planner observations and performing genuine live raw4 replay.

One original work allowance and unchanged request window span all phases.
No copied context supplies independent historical authority. A dedicated live
exchange admits reconstructed history only after its actual original controls
and full replay, recording the bounded planner cutoff as an observation. The
existing client still returns only original raw5. No custody, reservation,
execution, retry or public business invocation follows here.
"""
from __future__ import annotations

from catchplate import authority_query_reads as reads
from catchplate import authority_revocation_configuration as measured
from catchplate import authority_webauthn_transition_configuration as producing_configuration
from catchplate import authority_webauthn_transition_exchange_configuration as configuration
from catchplate import authority_webauthn_transition_live as live
from catchplate import authority_webauthn_transition_plan_owner as producing
from catchplate import authority_webauthn_transition_request as request_wire
from catchplate import authority_webauthn_transition_response as response_wire
from catchplate import authority_webauthn_transition_transport as transport


evidence, wire = request_wire.evidence, request_wire.wire


class WebAuthnTransitionActionError(ValueError):
    pass


def _operation(operation):
    if type(operation) is not str or operation not in request_wire.plan.contract.OPERATIONS:
        raise WebAuthnTransitionActionError("transition planning operation is not source fixed")
    return operation


def _fresh(timing, window, configured, work, transport_deadline_ns=None):
    now = wire._fresh_on_work(timing, window=window,
        maximum_age_ns=configured.maximum_control_age_ns,
        maximum_clock_skew_ns=configured.pins[6][1], work=work)
    if transport_deadline_ns is not None:
        evidence.production._callback(work, lambda: transport._check_deadline(transport_deadline_ns))
    return now


def _verify_request(originals, configured, work):
    return request_wire._verify_on_work(control_bytes=originals[0], context_bytes=originals[1],
        inputs_bytes=originals[2], pins=configured.pins,
        generation_sequence=configured.generation_sequence, generation_digest=configured.generation_digest,
        verifier_public_key=configured.verifier_public_key,
        maximum_control_age_ns=configured.maximum_control_age_ns, work=work)


def _produce_request_on_configuration(*, operation, payload, configuration_digest, generation,
        runtime_role_identities,
        request, business_before_roots, authorization_before_roots, counted_before_heads,
        inputs_bytes, now_epoch_ns, deadline_epoch_ns, invocation, verifier_private_key, work):
    operation = _operation(operation)
    request_wire.inputs_wire.wire._raw(inputs_bytes, 2, request_wire.MAX_INPUT_BYTES)
    original, private = inputs_bytes, verifier_private_key
    if not isinstance(private, request_wire.plan.Ed25519PrivateKey):
        raise WebAuthnTransitionActionError("transition request requires the real verifier signer")
    # CopyBudget owns actual tuple projections as well as JSON request data;
    # the request producer performs its charged root tuple-to-list conversion.
    owned = reads._CopyBudget(work).copy({"request": request,
        "businessBeforeRoots": business_before_roots, "authorizationBeforeRoots": authorization_before_roots,
        "countedBeforeHeads": counted_before_heads, "nowEpochNs": now_epoch_ns,
        "deadlineEpochNs": deadline_epoch_ns, "invocation": invocation})
    configured = configuration._capture_on_work(operation=operation, payload=payload,
        configuration_digest=configuration_digest, generation=generation,
        runtime_role_identities=runtime_role_identities, work=work)
    return request_wire._produce_on_work(request=owned["request"],
        business_before_roots=owned["businessBeforeRoots"],
        authorization_before_roots=owned["authorizationBeforeRoots"],
        counted_before_heads=owned["countedBeforeHeads"], inputs_bytes=original,
        now_epoch_ns=owned["nowEpochNs"], deadline_epoch_ns=owned["deadlineEpochNs"],
        invocation=owned["invocation"], pins=configured.pins,
        generation_sequence=configured.generation_sequence, generation_digest=configured.generation_digest,
        verifier_private_key=private, verifier_public_key=configured.verifier_public_key,
        maximum_control_age_ns=configured.maximum_control_age_ns, work=work)


def _produce_plan_on_configuration(*, operation, payload, configuration_digest, generation,
        runtime_role_identities,
        control_bytes, context_bytes, inputs_bytes, read_dsn, planner_private_key, work):
    operation = _operation(operation)
    originals = transport._validate_request(control_bytes, context_bytes, inputs_bytes)
    private, dsn, digest = planner_private_key, read_dsn, configuration_digest
    if not isinstance(private, request_wire.plan.Ed25519PrivateKey):
        raise WebAuthnTransitionActionError("transition plan requires the real planner signer")
    if (type(dsn) is not str or not 1 <= len(dsn) <= 65536
            or any(character in dsn for character in ("\x00", "\r", "\n"))):
        raise WebAuthnTransitionActionError("transition planning requires one protected read DSN")
    ledger = evidence.capture._SharedLedger(work)
    evidence.plan.contract._digest(digest)
    if type(payload) is not dict or type(generation) is not dict:
        raise WebAuthnTransitionActionError("transition configuration is not closed data")
    measured.capability.shape._bounded_object(generation, 24, "transition planning launch context")
    # Both actual mappers consume these same owned snapshots. Native work in
    # the exchange mapper cannot cause a later reread of caller configuration.
    owned_payload = measured._ConfigurationCapture(
        ledger, maximum_bytes=wire.authority.MAX_REQUEST_BYTES).visit(payload)
    owned_runtime_identities = evidence.capture._JSONCapture(ledger, maximum_bytes=8192).visit(runtime_role_identities)
    held_generation = evidence.capture._JSONCapture(ledger).visit(
        {name: generation[name] for name in measured._GENERATION_FIELDS})
    configured = configuration._capture_on_work(operation=operation, payload=owned_payload,
        configuration_digest=digest, generation=held_generation,
        runtime_role_identities=owned_runtime_identities, work=work)
    verified = _verify_request(originals, configured, work)
    context, window = verified.context, verified.window
    issued, expires = verified.issued_at_epoch_ns, verified.expires_at_epoch_ns
    timing = {"issuedAtEpochNs": issued, "expiresAtEpochNs": expires}
    _fresh(timing, window, configured, work)
    # Only genuine control authentication unlocks construction of the actual
    # configured producer. It opens its own fixed read owner, never a caller DB.
    producer = producing_configuration._producer_from_configuration_on_work(operation=operation,
        payload=owned_payload, configuration_digest=digest, generation=held_generation,
        runtime_role_identities=owned_runtime_identities,
        read_dsn=dsn, planner_private_key=private, work=work)
    _fresh(timing, window, configured, work)
    work.prepare_copy(context["countedBeforeHeads"])
    heads = tuple(context["countedBeforeHeads"])
    produced = producing.TransitionPlanOwner.produce_originals(producer,
        request=context["request"], business_before_roots=context["businessBeforeRoots"],
        authorization_before_roots=context["authorizationBeforeRoots"], expected_counted_heads=heads,
        inputs_bytes=originals[2], now_epoch_ns=context["nowEpochNs"],
        deadline_epoch_ns=context["deadlineEpochNs"], invocation=context["invocation"],
        live_deadline_epoch_ns=expires, work=work)
    raw4 = produced.envelope_bytes, produced.proof_bytes, produced.inputs_bytes, produced.context_bytes
    _fresh(timing, window, configured, work)
    work.charge(input_bytes=len(originals[2]) + len(raw4[2]))
    if originals[2] != raw4[2]:
        raise WebAuthnTransitionActionError("transition producer changed the original input bytes")
    response = response_wire._produce_on_work(request_control_bytes=originals[0],
        envelope_bytes=raw4[0], proof_bytes=raw4[1], inputs_bytes=raw4[2], context_bytes=raw4[3],
        pins=configured.pins, generation_sequence=configured.generation_sequence,
        generation_digest=configured.generation_digest, planner_private_key=private,
        verifier_public_key=configured.verifier_public_key, request_issued_at_epoch_ns=issued,
        request_expires_at_epoch_ns=expires, request_window=window,
        maximum_control_age_ns=configured.maximum_control_age_ns, work=work)
    _fresh(timing, window, configured, work)
    return transport._validate_response(response, *raw4)


def _request_plan_on_configuration(*, operation, payload, configuration_digest, generation,
        runtime_role_identities,
        control_bytes, context_bytes, inputs_bytes, work, transport_deadline_ns=None):
    returned, _history = _request_plan_and_admit_history_on_configuration(operation=operation,
        payload=payload, configuration_digest=configuration_digest, generation=generation,
        runtime_role_identities=runtime_role_identities, control_bytes=control_bytes,
        context_bytes=context_bytes, inputs_bytes=inputs_bytes, work=work,
        transport_deadline_ns=transport_deadline_ns)
    return returned


def _request_plan_and_admit_history_on_configuration(*, operation, payload, configuration_digest,
        generation, runtime_role_identities, control_bytes, context_bytes, inputs_bytes, work,
        transport_deadline_ns=None):
    """Exchange real originals and admit only the reconstructed live history.

    This path performs the request/response signature checks itself; neither a
    successful DTO nor a caller-provided response or history bypasses replay.
    """
    operation = _operation(operation)
    inherited_deadline = transport_deadline_ns
    if inherited_deadline is not None:
        evidence.plan.contract._integer(inherited_deadline, minimum=1)
    originals = transport._validate_request(control_bytes, context_bytes, inputs_bytes)
    configured = configuration._capture_on_work(operation=operation, payload=payload,
        configuration_digest=configuration_digest, generation=generation,
        runtime_role_identities=runtime_role_identities, work=work)
    verified = _verify_request(originals, configured, work)
    context, window = verified.context, verified.window
    effective_deadline = None if inherited_deadline is None else min(inherited_deadline, window[4])
    issued, expires = verified.issued_at_epoch_ns, verified.expires_at_epoch_ns
    timing = {"issuedAtEpochNs": issued, "expiresAtEpochNs": expires}
    endpoint = configured.planner_endpoint
    _fresh(timing, window, configured, work, effective_deadline)
    received = evidence.production._callback(work, lambda: transport._socket_request(endpoint,
        operation=operation, control_bytes=originals[0], context_bytes=originals[1], inputs_bytes=originals[2],
        deadline_ns=effective_deadline))
    if type(received) is not tuple or len(received) != 5:
        raise WebAuthnTransitionActionError("transition plan response is not an exact five-tuple")
    returned = transport._validate_response(*received)
    _fresh(timing, window, configured, work, effective_deadline)
    # Authenticate every returned original, including the context, before it
    # is decoded even as a claimed planner observation for bounded live replay.
    response_wire._verify_on_work(control_bytes=returned[0], request_control_bytes=originals[0],
        envelope_bytes=returned[1], proof_bytes=returned[2], inputs_bytes=returned[3], context_bytes=returned[4],
        pins=configured.pins, generation_sequence=configured.generation_sequence,
        generation_digest=configured.generation_digest, verifier_public_key=configured.verifier_public_key,
        request_issued_at_epoch_ns=issued, request_expires_at_epoch_ns=expires, request_window=window,
        maximum_control_age_ns=configured.maximum_control_age_ns, work=work)
    work.charge(input_bytes=len(originals[2]) + len(returned[3]))
    if originals[2] != returned[3]:
        raise WebAuthnTransitionActionError("transition response changed the original input bytes")
    admitted = live._admit_history_on_work(envelope_bytes=returned[1], proof_bytes=returned[2],
        inputs_bytes=returned[3], context_bytes=returned[4], request_context=context,
        request_issued_at_epoch_ns=issued, request_expires_at_epoch_ns=expires, request_window=window,
        pins=configured.pins, maximum_control_age_ns=configured.maximum_control_age_ns, work=work)
    _fresh(timing, window, configured, work, effective_deadline)
    # The original response and ordinary derived history remain separate.
    # Neither is a successful execution or custody carrier.
    return returned, admitted
