"""Genuine planner relay of an independently authenticated custody intent.

Both entrypoints replay the original verifier intent, detached historical
expectations and all three retained plan originals on the caller's work. A
returned observation is ordinary same-call data, not an accepted proof token,
transaction outcome, execution grant or durable acknowledgment. Configuration,
generation and role keys require independent admission by the owning caller.

Relay signing keeps the original verified intent's live window and cannot
renew its expiry. Verification checks both controls through its final clock
samples. No SQL, transport, automatic retry or legacy envelope is introduced.
"""
from __future__ import annotations

from dataclasses import dataclass

from serverware import authority_webauthn_evidence_custody_intent as intent
from serverware import authority_webauthn_evidence_custody_wire as wire
from serverware import authority_webauthn_evidence_plan_admission as admission


class WebAuthnEvidenceCustodyRelayError(ValueError):
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
        raise WebAuthnEvidenceCustodyRelayError("evidence custody requires a bounded original control")


def _hold_on_work(intent_bytes, originals, pins, generation_sequence,
        generation_digest, verifier_public_key, maximum_control_age_ns, work):
    """Validate immutable input references before any clock or key callback."""
    wire.evidence.capture._SharedLedger(work)
    _raw_control(intent_bytes)
    wire._raw4(*originals)
    pins = admission._validate_pins(pins)
    wire._pins(pins[7], generation_sequence, generation_digest, pins[0])
    wire.evidence.plan.contract._integer(maximum_control_age_ns,
        wire.authority.VERIFIER_RESPONSE_MAX_AGE_NS, minimum=1)
    if not isinstance(verifier_public_key, wire.retention.plan.Ed25519PublicKey):
        raise WebAuthnEvidenceCustodyRelayError("evidence custody requires an independently held verifier key")
    return pins


def _times(issued, expires):
    return {"issuedAtEpochNs": issued, "expiresAtEpochNs": expires}


def _produce_on_work(*, intent_bytes, envelope_bytes, inputs_bytes,
        evaluation_context_bytes, historical_expectations_bytes, pins,
        generation_sequence, generation_digest, verifier_public_key,
        planner_private_key, maximum_control_age_ns, work):
    originals = (envelope_bytes, inputs_bytes, evaluation_context_bytes,
        historical_expectations_bytes)
    pins = _hold_on_work(intent_bytes, originals, pins, generation_sequence,
        generation_digest, verifier_public_key, maximum_control_age_ns, work)
    planner_public_key, operation, configuration_digest, skew = pins[1], pins[0], pins[7], pins[9]
    if not isinstance(planner_private_key, wire.retention.plan.Ed25519PrivateKey):
        raise WebAuthnEvidenceCustodyRelayError("evidence custody relay requires the actual planner private key")
    # No incoming successful verification observation can skip this replay.
    verified = intent._verify_on_work(intent_bytes=intent_bytes,
        envelope_bytes=originals[0], inputs_bytes=originals[1],
        evaluation_context_bytes=originals[2], historical_expectations_bytes=originals[3],
        pins=pins, generation_sequence=generation_sequence, generation_digest=generation_digest,
        verifier_public_key=verifier_public_key, maximum_control_age_ns=maximum_control_age_ns, work=work)
    record_digest, window = verified.retained_record_digest, verified.window
    intent_times = _times(verified.issued_at_epoch_ns, verified.expires_at_epoch_ns)
    wire.evidence.keys._pair_on_work(planner_private_key, planner_public_key, work)
    intent_digest = wire.retention._bytes_digest(intent_bytes, work)
    issued = wire._fresh_on_work(intent_times, window=window,
        maximum_age_ns=maximum_control_age_ns, maximum_clock_skew_ns=skew, work=work)
    expires = min(intent_times["expiresAtEpochNs"], wire.clock._deadline_epoch_ns(window))
    unsigned = {"schema": wire.RELAY_SCHEMA, "sourceRevision": wire.authority.SOURCE_REVISION,
        "purpose": wire.RELAY_PURPOSE, "configurationDigest": configuration_digest,
        "generationSequence": generation_sequence, "generationDigest": generation_digest,
        "operation": operation, "retainedRecordDigest": record_digest,
        "intentBytesDigest": intent_digest, "intentByteCount": len(intent_bytes),
        "issuedAtEpochNs": issued, "expiresAtEpochNs": expires}
    relay_times = _times(issued, expires)
    wire._fresh_on_work(relay_times, window=window, maximum_age_ns=maximum_control_age_ns,
        maximum_clock_skew_ns=skew, work=work)
    result = wire._sign_control(unsigned, relay=True, private_key=planner_private_key,
        public_key=planner_public_key, work=work)
    # This is the same intent window, including time spent pairing, signing,
    # verifying the new signature and encoding the final original envelope.
    wire._fresh_on_work(intent_times, window=window, maximum_age_ns=maximum_control_age_ns,
        maximum_clock_skew_ns=skew, work=work)
    wire._fresh_on_work(relay_times, window=window, maximum_age_ns=maximum_control_age_ns,
        maximum_clock_skew_ns=skew, work=work)
    return result


def _verify_on_work(*, intent_bytes, relay_bytes, envelope_bytes, inputs_bytes,
        evaluation_context_bytes, historical_expectations_bytes, pins,
        generation_sequence, generation_digest, verifier_public_key,
        maximum_control_age_ns, work):
    originals = (envelope_bytes, inputs_bytes, evaluation_context_bytes,
        historical_expectations_bytes)
    _raw_control(relay_bytes)
    pins = _hold_on_work(intent_bytes, originals, pins, generation_sequence,
        generation_digest, verifier_public_key, maximum_control_age_ns, work)
    planner_public_key, operation, configuration_digest, skew = pins[1], pins[0], pins[7], pins[9]
    value, signature, unsigned_wire = wire._read_control(relay_bytes, relay=True, work=work)
    wire._bind_control(value, configuration_digest=configuration_digest,
        generation_sequence=generation_sequence, generation_digest=generation_digest,
        operation=operation, work=work)
    wire._signature(signature, unsigned_wire, relay=True, public_key=planner_public_key, work=work)
    # Recheck the complete original after the actual public-key callback before
    # using any decoded fields as authenticated control commitments.
    wire.evidence.capability._canonical(relay_bytes, value,
        wire.evidence.capture._SharedLedger(work), wire.MAX_CONTROL_BYTES, wire.MAX_CONTROL_NODES)
    committed = (value["intentBytesDigest"], value["intentByteCount"], value["retainedRecordDigest"])
    relay_times = (value["issuedAtEpochNs"], value["expiresAtEpochNs"])
    relay_timing = _times(*relay_times)
    relay_window = wire._open_control_window_on_work(relay_timing,
        maximum_age_ns=maximum_control_age_ns, maximum_clock_skew_ns=skew, work=work)
    verified = intent._verify_on_work(intent_bytes=intent_bytes,
        envelope_bytes=originals[0], inputs_bytes=originals[1],
        evaluation_context_bytes=originals[2], historical_expectations_bytes=originals[3],
        pins=pins, generation_sequence=generation_sequence, generation_digest=generation_digest,
        verifier_public_key=verifier_public_key, maximum_control_age_ns=maximum_control_age_ns, work=work)
    record_digest, intent_window = verified.retained_record_digest, verified.window
    intent_times = (verified.issued_at_epoch_ns, verified.expires_at_epoch_ns)
    wire.evidence.plan._same((wire.retention._bytes_digest(intent_bytes, work),
        len(intent_bytes), record_digest), committed, work,
        "evidence custody relay differs from the original intent or genuinely replayed record")
    if (relay_times[1] > intent_times[1]
            or relay_times[0] < intent_times[0] - skew):
        raise WebAuthnEvidenceCustodyRelayError("evidence custody relay widens or predates its authenticated intent")
    wire._fresh_on_work(_times(*intent_times), window=intent_window,
        maximum_age_ns=maximum_control_age_ns, maximum_clock_skew_ns=skew, work=work)
    wire._fresh_on_work(relay_timing, window=relay_window,
        maximum_age_ns=maximum_control_age_ns, maximum_clock_skew_ns=skew, work=work)
    return _VerifiedCustody(record_digest, intent_window, relay_window, intent_times, relay_times)
