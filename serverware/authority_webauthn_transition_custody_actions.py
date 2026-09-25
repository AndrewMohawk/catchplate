"""Explicit configured actions for authenticated successor-plan custody.

Original controls, raw4 and independently admitted history are owned before
configuration callbacks. Every receiver genuinely authenticates and replays
them on the same caller work. Relay preparation, explicit forwarding and
potentially committing writer delivery are separate calls; none retries,
resigns or automatically invokes the next step.

The fixed digest/time peer response is unsigned informational data, not a
durable signed receipt, execution capability or rollback proof. An immutable
first-retained time may predate this invocation. No original control window
is renewed by transport or later authentication, and no returned context is
promoted to independently admitted historical authority.
"""
from __future__ import annotations

from serverware import authority_webauthn_transition_custody_configuration as configuration
from serverware import authority_webauthn_transition_custody_intent as intent
from serverware import authority_webauthn_transition_custody_persistence as persistence
from serverware import authority_webauthn_transition_custody_relay as relay
from serverware import authority_webauthn_transition_custody_transport as transport
from serverware import authority_webauthn_transition_custody_wire as wire


evidence = wire.evidence


class WebAuthnTransitionCustodyActionError(ValueError):
    pass


def _operation(operation):
    if type(operation) is not str or operation not in wire.retention.plan.contract.OPERATIONS:
        raise WebAuthnTransitionCustodyActionError("transition custody operation is not source fixed")
    return operation


def _produce_intent_on_configuration(*, operation, payload, configuration_digest, generation,
        runtime_role_identities,
        envelope_bytes, proof_bytes, inputs_bytes, context_bytes, expectations, verifier_private_key, work):
    ledger = evidence.capture._SharedLedger(work)
    operation = _operation(operation)
    originals = wire.retention._raw4(envelope_bytes, proof_bytes, inputs_bytes, context_bytes)
    private = verifier_private_key
    if not isinstance(private, wire.retention.plan.Ed25519PrivateKey):
        raise WebAuthnTransitionCustodyActionError("transition custody intent requires the real verifier signer")
    plan = wire.retention.plan
    plan.contract.shape._object(expectations, plan.contract.EXPECTATION_FIELDS,
        "independent configured transition custody history")
    owned = evidence.capture._JSONCapture(ledger).visit(expectations)
    expected_operation = plan.contract._validate_expectations(owned)
    evidence.plan._same(expected_operation, operation, work,
        "transition custody history differs from the selected operation")
    configured = configuration._capture_on_work(operation=operation, payload=payload,
        configuration_digest=configuration_digest, generation=generation,
        runtime_role_identities=runtime_role_identities, work=work)
    return intent._produce_on_work(envelope_bytes=originals[0], proof_bytes=originals[1],
        inputs_bytes=originals[2], context_bytes=originals[3], expectations=owned, pins=configured.pins,
        generation_sequence=configured.generation_sequence, generation_digest=configured.generation_digest,
        verifier_private_key=private, verifier_public_key=configured.verifier_public_key,
        maximum_control_age_ns=configured.maximum_control_age_ns, work=work)


def _produce_relay_on_configuration(*, operation, payload, configuration_digest, generation,
        runtime_role_identities,
        intent_bytes, envelope_bytes, proof_bytes, inputs_bytes, context_bytes,
        historical_expectations_bytes, planner_private_key, work):
    evidence.capture._SharedLedger(work)
    operation = _operation(operation)
    originals = transport._validate_relay_originals(intent_bytes=intent_bytes,
        envelope_bytes=envelope_bytes, proof_bytes=proof_bytes, inputs_bytes=inputs_bytes,
        context_bytes=context_bytes, historical_expectations_bytes=historical_expectations_bytes)
    private = planner_private_key
    if not isinstance(private, wire.retention.plan.Ed25519PrivateKey):
        raise WebAuthnTransitionCustodyActionError("transition custody relay requires the real planner signer")
    configured = configuration._capture_on_work(operation=operation, payload=payload,
        configuration_digest=configuration_digest, generation=generation,
        runtime_role_identities=runtime_role_identities, work=work)
    return relay._produce_on_work(intent_bytes=originals[0], envelope_bytes=originals[1],
        proof_bytes=originals[2], inputs_bytes=originals[3], context_bytes=originals[4],
        historical_expectations_bytes=originals[5], pins=configured.pins,
        generation_sequence=configured.generation_sequence, generation_digest=configured.generation_digest,
        verifier_public_key=configured.verifier_public_key, planner_private_key=private,
        maximum_control_age_ns=configured.maximum_control_age_ns, work=work)


def _persist_on_configuration(*, operation, payload, configuration_digest, generation,
        runtime_role_identities,
        intent_bytes, relay_bytes, envelope_bytes, proof_bytes, inputs_bytes, context_bytes,
        historical_expectations_bytes, writer_dsn, work):
    evidence.capture._SharedLedger(work)
    operation = _operation(operation)
    originals = transport._validate_originals(intent_bytes=intent_bytes, relay_bytes=relay_bytes,
        envelope_bytes=envelope_bytes, proof_bytes=proof_bytes, inputs_bytes=inputs_bytes,
        context_bytes=context_bytes, historical_expectations_bytes=historical_expectations_bytes)
    configured = configuration._capture_on_work(operation=operation, payload=payload,
        configuration_digest=configuration_digest, generation=generation,
        runtime_role_identities=runtime_role_identities, writer_dsn=writer_dsn, work=work)
    owner = configured.writer_configuration
    if owner is None:
        raise WebAuthnTransitionCustodyActionError("transition custody requires protected writer configuration")
    return persistence._persist_on_configuration(owner, intent_bytes=originals[0], relay_bytes=originals[1],
        envelope_bytes=originals[2], proof_bytes=originals[3], inputs_bytes=originals[4],
        context_bytes=originals[5], historical_expectations_bytes=originals[6],
        generation_sequence=configured.generation_sequence, generation_digest=configured.generation_digest,
        verifier_public_key=configured.verifier_public_key,
        maximum_control_age_ns=configured.maximum_control_age_ns, work=work)


def _request_relay_on_configuration(*, operation, payload, configuration_digest, generation,
        runtime_role_identities,
        intent_bytes, envelope_bytes, proof_bytes, inputs_bytes, context_bytes,
        historical_expectations_bytes, work, transport_deadline_ns=None):
    evidence.capture._SharedLedger(work)
    operation = _operation(operation)
    inherited_deadline = transport_deadline_ns
    if inherited_deadline is not None:
        evidence.plan.contract._integer(inherited_deadline, minimum=1)
    originals = transport._validate_relay_originals(intent_bytes=intent_bytes,
        envelope_bytes=envelope_bytes, proof_bytes=proof_bytes, inputs_bytes=inputs_bytes,
        context_bytes=context_bytes, historical_expectations_bytes=historical_expectations_bytes)
    configured = configuration._capture_on_work(operation=operation, payload=payload,
        configuration_digest=configuration_digest, generation=generation,
        runtime_role_identities=runtime_role_identities, work=work)
    pins, public = configured.pins, configured.verifier_public_key
    sequence, digest = configured.generation_sequence, configured.generation_digest
    age, skew = configured.maximum_control_age_ns, pins[6][1]
    path, timeout, peer_uid, peer_gid = configured.planner_endpoint
    verified = intent._verify_on_work(intent_bytes=originals[0], envelope_bytes=originals[1],
        proof_bytes=originals[2], inputs_bytes=originals[3], context_bytes=originals[4],
        historical_expectations_bytes=originals[5], pins=pins, generation_sequence=sequence,
        generation_digest=digest, verifier_public_key=public, maximum_control_age_ns=age, work=work)
    window = verified.window
    effective_deadline = None if inherited_deadline is None else min(inherited_deadline, window[4])
    timing = {"issuedAtEpochNs": verified.issued_at_epoch_ns, "expiresAtEpochNs": verified.expires_at_epoch_ns}
    wire._fresh_on_work(timing, window=window, maximum_age_ns=age, maximum_clock_skew_ns=skew, work=work)
    if effective_deadline is not None:
        evidence.production._callback(work, lambda: transport._check_deadline(effective_deadline))
    original_relay = evidence.production._callback(work, lambda: transport._socket_relay_request(
        path, operation=operation, intent_bytes=originals[0], envelope_bytes=originals[1],
        proof_bytes=originals[2], inputs_bytes=originals[3], context_bytes=originals[4],
        historical_expectations_bytes=originals[5], timeout_seconds=timeout,
        expected_peer_uid=peer_uid, expected_peer_gid=peer_gid, deadline_ns=effective_deadline))
    wire._fresh_on_work(timing, window=window, maximum_age_ns=age, maximum_clock_skew_ns=skew, work=work)
    relay._verify_on_work(intent_bytes=originals[0], relay_bytes=original_relay, envelope_bytes=originals[1],
        proof_bytes=originals[2], inputs_bytes=originals[3], context_bytes=originals[4],
        historical_expectations_bytes=originals[5], pins=pins, generation_sequence=sequence,
        generation_digest=digest, verifier_public_key=public, maximum_control_age_ns=age, work=work)
    # Keep the first intent window too; response authentication cannot renew
    # the elapsed lifetime spent on this actual transport and genuine replay.
    wire._fresh_on_work(timing, window=window, maximum_age_ns=age, maximum_clock_skew_ns=skew, work=work)
    if effective_deadline is not None:
        evidence.production._callback(work, lambda: transport._check_deadline(effective_deadline))
    return original_relay


def _send_originals_on_configuration(*, forward, operation, payload, configuration_digest, generation,
        runtime_role_identities,
        intent_bytes, relay_bytes, envelope_bytes, proof_bytes, inputs_bytes, context_bytes,
        historical_expectations_bytes, work):
    evidence.capture._SharedLedger(work)
    if type(forward) is not bool:
        raise WebAuthnTransitionCustodyActionError("transition custody delivery action is not fixed")
    operation = _operation(operation)
    originals = transport._validate_originals(intent_bytes=intent_bytes, relay_bytes=relay_bytes,
        envelope_bytes=envelope_bytes, proof_bytes=proof_bytes, inputs_bytes=inputs_bytes,
        context_bytes=context_bytes, historical_expectations_bytes=historical_expectations_bytes)
    configured = configuration._capture_on_work(operation=operation, payload=payload,
        configuration_digest=configuration_digest, generation=generation,
        runtime_role_identities=runtime_role_identities, work=work)
    pins, public = configured.pins, configured.verifier_public_key
    sequence, digest = configured.generation_sequence, configured.generation_digest
    age, skew = configured.maximum_control_age_ns, pins[6][1]
    path, timeout, peer_uid, peer_gid = (configured.planner_endpoint if forward else configured.writer_endpoint)
    verified = relay._verify_on_work(intent_bytes=originals[0], relay_bytes=originals[1],
        envelope_bytes=originals[2], proof_bytes=originals[3], inputs_bytes=originals[4], context_bytes=originals[5],
        historical_expectations_bytes=originals[6], pins=pins, generation_sequence=sequence,
        generation_digest=digest, verifier_public_key=public, maximum_control_age_ns=age, work=work)
    record_digest = verified.retained_record_digest
    timing = {"intent_window": verified.intent_window, "relay_window": verified.relay_window,
        "intent_times": verified.intent_times, "relay_times": verified.relay_times,
        "maximum_control_age_ns": age, "maximum_clock_skew_ns": skew}
    persistence._fresh_controls_on_work(**timing, work=work)
    observation = evidence.production._callback(work,
        lambda: (transport._socket_forward_request if forward else transport._socket_request)(
            path, operation=operation, intent_bytes=originals[0], relay_bytes=originals[1],
            envelope_bytes=originals[2], proof_bytes=originals[3], inputs_bytes=originals[4], context_bytes=originals[5],
            historical_expectations_bytes=originals[6], timeout_seconds=timeout,
            expected_peer_uid=peer_uid, expected_peer_gid=peer_gid))
    persistence._fresh_controls_on_work(**timing, work=work)
    if type(observation) is not tuple or len(observation) != 2:
        raise WebAuthnTransitionCustodyActionError("transition custody peer observation is not an exact pair")
    retained_record_digest, retained_at_epoch_ns = observation
    evidence.plan.contract._digest(retained_record_digest)
    evidence.plan.contract._integer(retained_at_epoch_ns, minimum=1)
    evidence.plan._same(retained_record_digest, record_digest, work,
        "transition custody peer observation differs from the genuinely replayed record")
    now = persistence._fresh_controls_on_work(**timing, work=work)
    if retained_at_epoch_ns > now + skew:
        raise WebAuthnTransitionCustodyActionError("transition custody peer observation has a future retention time")
    # The immutable first-retained timestamp may precede these new controls.
    return retained_record_digest, retained_at_epoch_ns


def _send_on_configuration(*, operation, payload, configuration_digest, generation,
        runtime_role_identities,
        intent_bytes, relay_bytes, envelope_bytes, proof_bytes, inputs_bytes, context_bytes,
        historical_expectations_bytes, work):
    return _send_originals_on_configuration(forward=False, operation=operation, payload=payload,
        configuration_digest=configuration_digest, generation=generation,
        runtime_role_identities=runtime_role_identities, intent_bytes=intent_bytes,
        relay_bytes=relay_bytes, envelope_bytes=envelope_bytes, proof_bytes=proof_bytes,
        inputs_bytes=inputs_bytes, context_bytes=context_bytes,
        historical_expectations_bytes=historical_expectations_bytes, work=work)


def _forward_on_configuration(*, operation, payload, configuration_digest, generation,
        runtime_role_identities,
        intent_bytes, relay_bytes, envelope_bytes, proof_bytes, inputs_bytes, context_bytes,
        historical_expectations_bytes, work):
    return _send_originals_on_configuration(forward=True, operation=operation, payload=payload,
        configuration_digest=configuration_digest, generation=generation,
        runtime_role_identities=runtime_role_identities, intent_bytes=intent_bytes,
        relay_bytes=relay_bytes, envelope_bytes=envelope_bytes, proof_bytes=proof_bytes,
        inputs_bytes=inputs_bytes, context_bytes=context_bytes,
        historical_expectations_bytes=historical_expectations_bytes, work=work)
