"""Fixed configured actions for original evidence-plan custody controls.

The actual service independently admits configuration, launch generation and
role ownership. These workers own originals and independent history before
configuration/key callbacks, then invoke the real retain-only intent, relay
and persistence paths on the existing caller work. Returned verification
observations are never accepted as substitutes for original-byte replay.

Relay preparation and potentially committing delivery are separate explicit
calls. Nothing regenerates a control, automatically forwards or retries.
Peer responses are unsigned local custody observations, not signed receipts,
execution permission or rollback evidence. Caller-owned durable retention and
uncertain-outcome recovery remain separate responsibilities. No registry gate,
operation allowlist, configuration policy or work allowance is broadened.
"""
from __future__ import annotations

from serverware import authority_webauthn_evidence_custody_configuration as configuration
from serverware import authority_webauthn_evidence_custody_intent as intent
from serverware import authority_webauthn_evidence_custody_persistence as persistence
from serverware import authority_webauthn_evidence_custody_relay as relay
from serverware import authority_webauthn_evidence_custody_transport as transport
from serverware import authority_webauthn_evidence_custody_wire as wire


evidence = wire.evidence
_OPERATIONS = {"registration": "webauthn.registration.evidence.admit",
    "installation": "webauthn.trust.installation.admit"}


class WebAuthnEvidenceCustodyActionError(ValueError):
    pass


def _operation(purpose):
    if type(purpose) is not str or purpose not in _OPERATIONS:
        raise WebAuthnEvidenceCustodyActionError("evidence custody purpose is not source fixed")
    return _OPERATIONS[purpose]


def _fresh_controls_on_work(*, intent_window, relay_window, intent_times, relay_times,
        maximum_age_ns, maximum_clock_skew_ns, work):
    """Check both held original windows and return the last actual epoch sample."""
    now = None
    for window, times in ((intent_window, intent_times), (relay_window, relay_times)):
        if type(times) is not tuple or len(times) != 2:
            raise WebAuthnEvidenceCustodyActionError("evidence custody timing pair is not exact")
        now = wire._fresh_on_work({"issuedAtEpochNs": times[0], "expiresAtEpochNs": times[1]},
            window=window, maximum_age_ns=maximum_age_ns,
            maximum_clock_skew_ns=maximum_clock_skew_ns, work=work)
    return now


def _produce_intent_on_configuration(*, purpose, payload, configuration_digest, generation,
        runtime_role_identities,
        envelope_bytes, inputs_bytes, evaluation_context_bytes, expectations,
        verifier_private_key, work):
    ledger = evidence.capture._SharedLedger(work)
    operation = _operation(purpose)
    originals = intent._raw3(envelope_bytes, inputs_bytes, evaluation_context_bytes)
    private_key = verifier_private_key
    if not isinstance(private_key, wire.retention.plan.Ed25519PrivateKey):
        raise WebAuthnEvidenceCustodyActionError("evidence custody intent requires the real verifier signer")
    evidence.plan.contract._object(expectations, wire.retention.plan._EXPECTATION_FIELDS,
        "independent configured evidence custody history")
    owned = evidence.capture._JSONCapture(ledger).visit(expectations)
    wire.retention.plan._validate_expectations(owned, operation)
    configured = configuration._capture_on_work(purpose=purpose, payload=payload,
        configuration_digest=configuration_digest, generation=generation,
        runtime_role_identities=runtime_role_identities, work=work)
    return intent._produce_on_work(envelope_bytes=originals[0], inputs_bytes=originals[1],
        evaluation_context_bytes=originals[2], expectations=owned, pins=configured.pins,
        generation_sequence=configured.generation_sequence, generation_digest=configured.generation_digest,
        verifier_private_key=private_key, verifier_public_key=configured.verifier_public_key,
        maximum_control_age_ns=configured.maximum_control_age_ns, work=work)


def _produce_relay_on_configuration(*, purpose, payload, configuration_digest, generation,
        runtime_role_identities,
        intent_bytes, envelope_bytes, inputs_bytes, evaluation_context_bytes,
        historical_expectations_bytes, planner_private_key, work):
    evidence.capture._SharedLedger(work)
    _operation(purpose)
    original_intent = intent_bytes
    relay._raw_control(original_intent)
    originals = wire._raw4(envelope_bytes, inputs_bytes, evaluation_context_bytes, historical_expectations_bytes)
    private_key = planner_private_key
    if not isinstance(private_key, wire.retention.plan.Ed25519PrivateKey):
        raise WebAuthnEvidenceCustodyActionError("evidence custody relay requires the real planner signer")
    configured = configuration._capture_on_work(purpose=purpose, payload=payload,
        configuration_digest=configuration_digest, generation=generation,
        runtime_role_identities=runtime_role_identities, work=work)
    return relay._produce_on_work(intent_bytes=original_intent, envelope_bytes=originals[0],
        inputs_bytes=originals[1], evaluation_context_bytes=originals[2],
        historical_expectations_bytes=originals[3], pins=configured.pins,
        generation_sequence=configured.generation_sequence, generation_digest=configured.generation_digest,
        verifier_public_key=configured.verifier_public_key, planner_private_key=private_key,
        maximum_control_age_ns=configured.maximum_control_age_ns, work=work)


def _persist_on_configuration(*, purpose, payload, configuration_digest, generation,
        runtime_role_identities,
        intent_bytes, relay_bytes, envelope_bytes, inputs_bytes, evaluation_context_bytes,
        historical_expectations_bytes, writer_dsn, work):
    evidence.capture._SharedLedger(work)
    _operation(purpose)
    controls = intent_bytes, relay_bytes
    for raw in controls:
        relay._raw_control(raw)
    originals = wire._raw4(envelope_bytes, inputs_bytes, evaluation_context_bytes, historical_expectations_bytes)
    configured = configuration._capture_on_work(purpose=purpose, payload=payload,
        configuration_digest=configuration_digest, generation=generation,
        runtime_role_identities=runtime_role_identities, writer_dsn=writer_dsn, work=work)
    writer_configuration = configured.writer_configuration
    if writer_configuration is None:
        raise WebAuthnEvidenceCustodyActionError("evidence custody persistence requires protected writer configuration")
    return persistence._persist_on_configuration(writer_configuration,
        intent_bytes=controls[0], relay_bytes=controls[1], envelope_bytes=originals[0], inputs_bytes=originals[1],
        evaluation_context_bytes=originals[2], historical_expectations_bytes=originals[3],
        generation_sequence=configured.generation_sequence, generation_digest=configured.generation_digest,
        verifier_public_key=configured.verifier_public_key,
        maximum_control_age_ns=configured.maximum_control_age_ns, work=work)


def _request_relay_on_configuration(*, purpose, payload, configuration_digest, generation,
        runtime_role_identities,
        intent_bytes, envelope_bytes, inputs_bytes, evaluation_context_bytes,
        historical_expectations_bytes, work):
    evidence.capture._SharedLedger(work)
    _operation(purpose)
    originals = transport._validate_relay_originals(intent_bytes=intent_bytes,
        envelope_bytes=envelope_bytes, inputs_bytes=inputs_bytes, evaluation_context_bytes=evaluation_context_bytes,
        historical_expectations_bytes=historical_expectations_bytes)
    configured = configuration._capture_on_work(purpose=purpose, payload=payload,
        configuration_digest=configuration_digest, generation=generation,
        runtime_role_identities=runtime_role_identities, work=work)
    pins, public_key = configured.pins, configured.verifier_public_key
    sequence, digest = configured.generation_sequence, configured.generation_digest
    age, skew = configured.maximum_control_age_ns, pins[9]
    path, timeout, peer_uid, peer_gid = configured.planner_endpoint
    verified = intent._verify_on_work(intent_bytes=originals[0], envelope_bytes=originals[1],
        inputs_bytes=originals[2], evaluation_context_bytes=originals[3], historical_expectations_bytes=originals[4],
        pins=pins, generation_sequence=sequence, generation_digest=digest,
        verifier_public_key=public_key, maximum_control_age_ns=age, work=work)
    window = verified.window
    timing = {"issuedAtEpochNs": verified.issued_at_epoch_ns, "expiresAtEpochNs": verified.expires_at_epoch_ns}
    wire._fresh_on_work(timing, window=window, maximum_age_ns=age, maximum_clock_skew_ns=skew, work=work)
    original_relay = evidence.production._callback(work, lambda: transport._socket_relay_request(
        path, purpose=purpose, intent_bytes=originals[0], envelope_bytes=originals[1], inputs_bytes=originals[2],
        evaluation_context_bytes=originals[3], historical_expectations_bytes=originals[4],
        timeout_seconds=timeout, expected_peer_uid=peer_uid, expected_peer_gid=peer_gid))
    wire._fresh_on_work(timing, window=window, maximum_age_ns=age, maximum_clock_skew_ns=skew, work=work)
    relay._verify_on_work(intent_bytes=originals[0], relay_bytes=original_relay, envelope_bytes=originals[1],
        inputs_bytes=originals[2], evaluation_context_bytes=originals[3], historical_expectations_bytes=originals[4],
        pins=pins, generation_sequence=sequence, generation_digest=digest,
        verifier_public_key=public_key, maximum_control_age_ns=age, work=work)
    # Keep the first intent window as well as the receiver's later windows:
    # returning from transport and re-verifying cannot renew spent lifetime.
    wire._fresh_on_work(timing, window=window, maximum_age_ns=age, maximum_clock_skew_ns=skew, work=work)
    return original_relay


def _send_originals_on_configuration(*, forward, purpose, payload, configuration_digest, generation,
        runtime_role_identities,
        intent_bytes, relay_bytes, envelope_bytes, inputs_bytes, evaluation_context_bytes,
        historical_expectations_bytes, work):
    evidence.capture._SharedLedger(work)
    if type(forward) is not bool:
        raise WebAuthnEvidenceCustodyActionError("evidence custody delivery action is not fixed")
    _operation(purpose)
    originals = transport._validate_originals(intent_bytes=intent_bytes, relay_bytes=relay_bytes,
        envelope_bytes=envelope_bytes, inputs_bytes=inputs_bytes, evaluation_context_bytes=evaluation_context_bytes,
        historical_expectations_bytes=historical_expectations_bytes)
    configured = configuration._capture_on_work(purpose=purpose, payload=payload,
        configuration_digest=configuration_digest, generation=generation,
        runtime_role_identities=runtime_role_identities, work=work)
    pins, public_key = configured.pins, configured.verifier_public_key
    sequence, digest = configured.generation_sequence, configured.generation_digest
    age, skew = configured.maximum_control_age_ns, pins[9]
    path, timeout, peer_uid, peer_gid = (configured.planner_endpoint if forward else configured.writer_endpoint)
    verified = relay._verify_on_work(intent_bytes=originals[0], relay_bytes=originals[1],
        envelope_bytes=originals[2], inputs_bytes=originals[3], evaluation_context_bytes=originals[4],
        historical_expectations_bytes=originals[5], pins=pins,
        generation_sequence=sequence, generation_digest=digest, verifier_public_key=public_key,
        maximum_control_age_ns=age, work=work)
    record_digest = verified.retained_record_digest
    timing = {"intent_window": verified.intent_window, "relay_window": verified.relay_window,
        "intent_times": verified.intent_times, "relay_times": verified.relay_times,
        "maximum_age_ns": age, "maximum_clock_skew_ns": skew}
    _fresh_controls_on_work(**timing, work=work)
    observation = evidence.production._callback(work,
        lambda: (transport._socket_forward_request if forward else transport._socket_request)(
            path, purpose=purpose, intent_bytes=originals[0], relay_bytes=originals[1],
            envelope_bytes=originals[2], inputs_bytes=originals[3], evaluation_context_bytes=originals[4],
            historical_expectations_bytes=originals[5], timeout_seconds=timeout,
            expected_peer_uid=peer_uid, expected_peer_gid=peer_gid))
    _fresh_controls_on_work(**timing, work=work)
    if type(observation) is not tuple or len(observation) != 2:
        raise WebAuthnEvidenceCustodyActionError("evidence custody peer observation is not an exact pair")
    retained_record_digest, retained_at_epoch_ns = observation
    evidence.plan.contract._digest(retained_record_digest)
    evidence.plan.contract._integer(retained_at_epoch_ns, minimum=1)
    evidence.plan._same(retained_record_digest, record_digest, work,
        "evidence custody peer observation differs from the genuinely replayed record")
    now = _fresh_controls_on_work(**timing, work=work)
    if retained_at_epoch_ns > now + skew:
        raise WebAuthnEvidenceCustodyActionError("evidence custody peer observation has a future retention time")
    # An identical retry can report an earlier immutable first-retained time.
    # The timestamp is not required to follow this invocation's controls.
    return retained_record_digest, retained_at_epoch_ns


def _send_on_configuration(*, purpose, payload, configuration_digest, generation,
        runtime_role_identities,
        intent_bytes, relay_bytes, envelope_bytes, inputs_bytes, evaluation_context_bytes,
        historical_expectations_bytes, work):
    return _send_originals_on_configuration(forward=False, purpose=purpose, payload=payload,
        configuration_digest=configuration_digest, generation=generation,
        runtime_role_identities=runtime_role_identities, intent_bytes=intent_bytes,
        relay_bytes=relay_bytes, envelope_bytes=envelope_bytes, inputs_bytes=inputs_bytes,
        evaluation_context_bytes=evaluation_context_bytes, historical_expectations_bytes=historical_expectations_bytes,
        work=work)


def _forward_on_configuration(*, purpose, payload, configuration_digest, generation,
        runtime_role_identities,
        intent_bytes, relay_bytes, envelope_bytes, inputs_bytes, evaluation_context_bytes,
        historical_expectations_bytes, work):
    return _send_originals_on_configuration(forward=True, purpose=purpose, payload=payload,
        configuration_digest=configuration_digest, generation=generation,
        runtime_role_identities=runtime_role_identities, intent_bytes=intent_bytes,
        relay_bytes=relay_bytes, envelope_bytes=envelope_bytes, inputs_bytes=inputs_bytes,
        evaluation_context_bytes=evaluation_context_bytes, historical_expectations_bytes=historical_expectations_bytes,
        work=work)
