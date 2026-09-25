"""Genuine planner relay of original successor-transition custody controls.

The verifier intent, independent historical bytes and raw4 are authenticated
and genuinely replayed on the same caller work at both entrypoints. No prior
verification carrier can replace those originals. Configuration, generation
and purpose-specific keys retain their independent admission obligations.

Signing uses the original intent window, never a renewed deadline. Verification
authenticates the exact relay and intent commitment before historical replay,
then checks both original controls through its final clock samples. Returned
observations are not a transaction outcome, custody receipt or execution grant.
There is no SQL, transport, automatic retry or replacement work allowance.
"""
from __future__ import annotations

from dataclasses import dataclass

from serverware import authority_webauthn_transition_custody_intent as intent
from serverware import authority_webauthn_transition_custody_wire as wire
from serverware import authority_webauthn_transition_plan_admission as admission


class WebAuthnTransitionCustodyRelayError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class _VerifiedCustody:
    retained_record_digest: str
    intent_window: tuple[int, ...]
    relay_window: tuple[int, ...]
    intent_times: tuple[int, int]
    relay_times: tuple[int, int]


def _raw_control(raw):
    if type(raw) is not bytes or not 2 <= len(raw) <= wire.MAX_CONTROL_BYTES:
        raise WebAuthnTransitionCustodyRelayError("transition custody requires a bounded original control")


def _aggregate(controls, originals):
    for raw in controls:
        _raw_control(raw)
    wire._raw5(*originals)
    if sum(len(raw) for raw in (*controls, *originals)) > wire.retention.MAX_ORIGINAL_BYTES:
        raise WebAuthnTransitionCustodyRelayError("transition custody originals exceed the aggregate bound")


def _hold_on_work(controls, originals, pins, generation_sequence, generation_digest,
        verifier_public_key, maximum_control_age_ns, work):
    """Hold exact immutable originals and scalar/key pins before callbacks."""
    wire.evidence.capture._SharedLedger(work)
    _aggregate(controls, originals)
    pins = admission._validate_pins(pins)
    wire._pins(pins[5], generation_sequence, generation_digest, pins[0])
    wire.evidence.plan.contract._integer(maximum_control_age_ns,
        wire.authority.VERIFIER_RESPONSE_MAX_AGE_NS, minimum=1)
    if not isinstance(verifier_public_key, wire.retention.plan.Ed25519PublicKey):
        raise WebAuthnTransitionCustodyRelayError("transition custody requires an independently held verifier key")
    return pins


def _times(issued, expires):
    return {"issuedAtEpochNs": issued, "expiresAtEpochNs": expires}


def _produce_on_work(*, intent_bytes, envelope_bytes, proof_bytes, inputs_bytes,
        context_bytes, historical_expectations_bytes, pins, generation_sequence,
        generation_digest, verifier_public_key, planner_private_key, maximum_control_age_ns, work):
    originals = envelope_bytes, proof_bytes, inputs_bytes, context_bytes, historical_expectations_bytes
    original_intent, private, public = intent_bytes, planner_private_key, verifier_public_key
    pins = _hold_on_work((original_intent,), originals, pins, generation_sequence,
        generation_digest, public, maximum_control_age_ns, work)
    planner_key, operation, configuration_digest, skew = pins[1], pins[0], pins[5], pins[6][1]
    if not isinstance(private, wire.retention.plan.Ed25519PrivateKey):
        raise WebAuthnTransitionCustodyRelayError("transition custody relay requires the actual planner private key")
    # No successful-verification object is accepted instead of this real
    # original intent, detached history and full raw4 proof/semantic replay.
    verified = intent._verify_on_work(intent_bytes=original_intent,
        envelope_bytes=originals[0], proof_bytes=originals[1], inputs_bytes=originals[2],
        context_bytes=originals[3], historical_expectations_bytes=originals[4], pins=pins,
        generation_sequence=generation_sequence, generation_digest=generation_digest,
        verifier_public_key=public, maximum_control_age_ns=maximum_control_age_ns, work=work)
    record_digest, window = verified.retained_record_digest, verified.window
    intent_timing = _times(verified.issued_at_epoch_ns, verified.expires_at_epoch_ns)
    wire.evidence.keys._pair_on_work(private, planner_key, work)
    intent_digest = wire.retention._bytes_digest(original_intent, work)
    issued = wire._fresh_on_work(intent_timing, window=window,
        maximum_age_ns=maximum_control_age_ns, maximum_clock_skew_ns=skew, work=work)
    expires = min(intent_timing["expiresAtEpochNs"], wire.clock._deadline_epoch_ns(window))
    unsigned = {"schema": wire.RELAY_SCHEMA, "sourceRevision": wire.authority.SOURCE_REVISION,
        "purpose": wire.RELAY_PURPOSE, "configurationDigest": configuration_digest,
        "generationSequence": generation_sequence, "generationDigest": generation_digest,
        "operation": operation, "retainedRecordDigest": record_digest,
        "intentBytesDigest": intent_digest, "intentByteCount": len(original_intent),
        "issuedAtEpochNs": issued, "expiresAtEpochNs": expires}
    relay_timing = _times(issued, expires)
    wire._fresh_on_work(relay_timing, window=window, maximum_age_ns=maximum_control_age_ns,
        maximum_clock_skew_ns=skew, work=work)
    result = wire._sign_control(unsigned, relay=True, private_key=private, public_key=planner_key, work=work)
    _aggregate((original_intent, result), originals)
    # Pairing, real signing, signature verification and final encoding all
    # spent this same original intent window; none reissues its lifetime.
    wire._fresh_on_work(intent_timing, window=window, maximum_age_ns=maximum_control_age_ns,
        maximum_clock_skew_ns=skew, work=work)
    wire._fresh_on_work(relay_timing, window=window, maximum_age_ns=maximum_control_age_ns,
        maximum_clock_skew_ns=skew, work=work)
    return result


def _verify_on_work(*, intent_bytes, relay_bytes, envelope_bytes, proof_bytes,
        inputs_bytes, context_bytes, historical_expectations_bytes, pins,
        generation_sequence, generation_digest, verifier_public_key, maximum_control_age_ns, work):
    originals = envelope_bytes, proof_bytes, inputs_bytes, context_bytes, historical_expectations_bytes
    original_intent, original_relay, public = intent_bytes, relay_bytes, verifier_public_key
    pins = _hold_on_work((original_intent, original_relay), originals, pins, generation_sequence,
        generation_digest, public, maximum_control_age_ns, work)
    planner_key, operation, configuration_digest, skew = pins[1], pins[0], pins[5], pins[6][1]
    value, signature, unsigned_wire = wire._read_control(original_relay, relay=True, work=work)
    wire._signature(signature, unsigned_wire, relay=True, public_key=planner_key, work=work)
    wire.evidence.capability._canonical(original_relay, value,
        wire.evidence.capture._SharedLedger(work), wire.MAX_CONTROL_BYTES, wire.MAX_CONTROL_NODES)
    wire._bind_control(value, configuration_digest=configuration_digest,
        generation_sequence=generation_sequence, generation_digest=generation_digest,
        operation=operation, work=work)
    record_commitment = value["retainedRecordDigest"]
    relay_times = value["issuedAtEpochNs"], value["expiresAtEpochNs"]
    # Reject a substituted intent before interpreting any detached history.
    wire.evidence.plan._same((wire.retention._bytes_digest(original_intent, work), len(original_intent)),
        (value["intentBytesDigest"], value["intentByteCount"]), work,
        "transition custody relay differs from the original intent bytes")
    relay_timing = _times(*relay_times)
    relay_window = wire._open_control_window_on_work(relay_timing,
        maximum_age_ns=maximum_control_age_ns, maximum_clock_skew_ns=skew, work=work)
    verified = intent._verify_on_work(intent_bytes=original_intent,
        envelope_bytes=originals[0], proof_bytes=originals[1], inputs_bytes=originals[2],
        context_bytes=originals[3], historical_expectations_bytes=originals[4], pins=pins,
        generation_sequence=generation_sequence, generation_digest=generation_digest,
        verifier_public_key=public, maximum_control_age_ns=maximum_control_age_ns, work=work)
    record_digest, intent_window = verified.retained_record_digest, verified.window
    intent_times = verified.issued_at_epoch_ns, verified.expires_at_epoch_ns
    wire.evidence.plan._same(record_digest, record_commitment, work,
        "transition custody relay differs from the genuinely replayed retained record")
    if relay_times[1] > intent_times[1] or relay_times[0] < intent_times[0] - skew:
        raise WebAuthnTransitionCustodyRelayError("transition custody relay widens or predates its authenticated intent")
    wire._fresh_on_work(_times(*intent_times), window=intent_window,
        maximum_age_ns=maximum_control_age_ns, maximum_clock_skew_ns=skew, work=work)
    wire._fresh_on_work(relay_timing, window=relay_window,
        maximum_age_ns=maximum_control_age_ns, maximum_clock_skew_ns=skew, work=work)
    return _VerifiedCustody(record_digest, intent_window, relay_window, intent_times, relay_times)
