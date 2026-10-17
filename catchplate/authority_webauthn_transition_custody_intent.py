"""Verifier-signed retention intents over genuine transition plan originals.

The producer owns independent history, genuinely replays raw4, and signs its
record identity plus every raw5 byte commitment. The receiver authenticates
the dedicated control, current scope and all originals before decoding the
separate historical expectations, joining configured pins and replaying again.
No successful-verification DTO can replace either actual computation.

Original policy deadline, signed plan issue/expiry and one actual dual-clock
window remain mandatory through signing and return. Neither configuration nor
an incoming context enrolls historical authority. There is no SQL, transport,
execution permission, durable acknowledgment, retry or replacement allowance.
"""
from __future__ import annotations

from dataclasses import dataclass

from catchplate import authority_webauthn_transition_custody_wire as wire
from catchplate import authority_webauthn_transition_plan_admission as admission
from catchplate import authority_webauthn_transition_plan_context as context_wire


evidence, authority, retention, clock = wire.evidence, wire.authority, wire.retention, wire.clock
_BODY_FIELDS = ("envelopeBytesDigest", "envelopeByteCount", "proofBytesDigest", "proofByteCount",
    "inputsBytesDigest", "inputsByteCount", "contextBytesDigest", "contextByteCount",
    "historyBytesDigest", "historyByteCount")


class WebAuthnTransitionCustodyIntentError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class _ProducedIntent:
    intent_bytes: bytes
    historical_expectations_bytes: bytes


@dataclass(frozen=True, slots=True)
class _VerifiedIntent:
    """Same-call scalar observations, never accepted as a verification input."""

    retained_record_digest: str
    issued_at_epoch_ns: int
    expires_at_epoch_ns: int
    window: tuple


def _payload_on_work(envelope_bytes, work):
    """Decode the same genuinely verified original, not a verification DTO."""
    ledger = evidence.capture._SharedLedger(work)
    contract = retention.plan.contract
    envelope = evidence.wire._decode_object(envelope_bytes, work=work,
        maximum_bytes=contract.MAX_BYTES, maximum_nodes=contract.MAX_NODES,
        maximum_depth=contract.MAX_DEPTH)
    contract.validate_envelope_shape(envelope)
    evidence.capability._canonical(envelope_bytes, envelope, ledger, contract.MAX_BYTES, contract.MAX_NODES)
    return envelope["payload"]


def _current_on_work(payload, expected, timing, *, window, maximum_control_age_ns, skew, work):
    now = wire._fresh_on_work(timing, window=window, maximum_age_ns=maximum_control_age_ns,
        maximum_clock_skew_ns=skew, work=work)
    # Historical plan replay alone checks freshness at historical policy.now.
    # This genuine current-time join also rejects future issue or expired plan
    # without changing its policy, cutoff, issue, expiry or original deadline.
    retention.plan._fresh(payload, expected, now)
    return now


def _produce_on_work(*, envelope_bytes, proof_bytes, inputs_bytes, context_bytes,
        expectations, pins, generation_sequence, generation_digest, verifier_private_key,
        verifier_public_key, maximum_control_age_ns, work):
    ledger = evidence.capture._SharedLedger(work)
    pins = admission._validate_pins(pins)
    originals = retention._raw4(envelope_bytes, proof_bytes, inputs_bytes, context_bytes)
    scope = wire._pins(pins[5], generation_sequence, generation_digest, pins[0])
    private_key, public_key, skew = verifier_private_key, verifier_public_key, pins[6][1]
    if (not isinstance(private_key, retention.plan.Ed25519PrivateKey)
            or not isinstance(public_key, retention.plan.Ed25519PublicKey)):
        raise WebAuthnTransitionCustodyIntentError("transition custody intent signer is not Ed25519")
    shape = retention.plan.contract.shape
    shape._integer(maximum_control_age_ns, authority.VERIFIER_RESPONSE_MAX_AGE_NS, minimum=1)
    shape._object(expectations, retention.plan.contract.EXPECTATION_FIELDS, "independent transition custody history")
    owned = evidence.capture._JSONCapture(ledger).visit(expectations)
    retention.plan.contract._validate_expectations(owned)
    # Serialize independently owned history, never history adopted from the
    # plan's context. Complete raw5 bounds precede the first key callback.
    historical = context_wire._encode_on_work(expectations=owned, work=work)
    wire._raw5(*originals, historical)
    owned = admission._capture_expectations_on_work(pins, owned, work)
    deadline = owned["proofExpectations"]["policy"]["deadlineEpochNs"]
    window = clock._open_on_work(deadline_epoch_ns=deadline,
        maximum_lifetime_ns=maximum_control_age_ns, maximum_clock_skew_ns=skew, work=work)
    retained = retention._verify_record_on_work(envelope_bytes=originals[0], proof_bytes=originals[1],
        inputs_bytes=originals[2], context_bytes=originals[3], expectations=owned,
        planner_public_key=pins[1], operation_public_key=pins[4], work=work)
    record_digest = retained.record_digest
    payload = _payload_on_work(originals[0], work)
    issued, expires = window[0], min(clock._deadline_epoch_ns(window), payload["expiresAtEpochNs"])
    wire._distinct_keys(pins[1], public_key, work)
    evidence.keys._pair_on_work(private_key, public_key, work)
    commitments = wire._body_commitments_on_work(envelope_bytes=originals[0], proof_bytes=originals[1],
        inputs_bytes=originals[2], context_bytes=originals[3], historical_expectations_bytes=historical, work=work)
    unsigned = {"schema": wire.INTENT_SCHEMA, "sourceRevision": authority.SOURCE_REVISION,
        "purpose": wire.INTENT_PURPOSE, "configurationDigest": scope[0],
        "generationSequence": scope[1], "generationDigest": scope[2], "operation": scope[3],
        "retainedRecordDigest": record_digest, **commitments,
        "issuedAtEpochNs": issued, "expiresAtEpochNs": expires}
    timing = {"issuedAtEpochNs": issued, "expiresAtEpochNs": expires}
    _current_on_work(payload, owned, timing, window=window,
        maximum_control_age_ns=maximum_control_age_ns, skew=skew, work=work)
    original = wire._sign_control(unsigned, relay=False, private_key=private_key, public_key=public_key, work=work)
    _current_on_work(payload, owned, timing, window=window,
        maximum_control_age_ns=maximum_control_age_ns, skew=skew, work=work)
    return _ProducedIntent(original, historical)


def _verify_on_work(*, intent_bytes, envelope_bytes, proof_bytes, inputs_bytes, context_bytes,
        historical_expectations_bytes, pins, generation_sequence, generation_digest,
        verifier_public_key, maximum_control_age_ns, work):
    ledger = evidence.capture._SharedLedger(work)
    pins = admission._validate_pins(pins)
    originals = wire._raw5(envelope_bytes, proof_bytes, inputs_bytes, context_bytes, historical_expectations_bytes)
    scope = wire._pins(pins[5], generation_sequence, generation_digest, pins[0])
    public_key, skew = verifier_public_key, pins[6][1]
    if not isinstance(public_key, retention.plan.Ed25519PublicKey):
        raise WebAuthnTransitionCustodyIntentError("transition custody intent verifier is not Ed25519")
    retention.plan.contract.shape._integer(maximum_control_age_ns, authority.VERIFIER_RESPONSE_MAX_AGE_NS, minimum=1)
    value, signature, unsigned_wire = wire._read_control(intent_bytes, relay=False, work=work)
    record_digest = value["retainedRecordDigest"]
    issued, expires = value["issuedAtEpochNs"], value["expiresAtEpochNs"]
    signed_bodies = {name: value[name] for name in _BODY_FIELDS}
    timing = {"issuedAtEpochNs": issued, "expiresAtEpochNs": expires}
    wire._signature(signature, unsigned_wire, relay=False, public_key=public_key, work=work)
    evidence.capability._canonical(intent_bytes, value, ledger, wire.MAX_CONTROL_BYTES, wire.MAX_CONTROL_NODES)
    wire._bind_control(value, configuration_digest=scope[0], generation_sequence=scope[1],
        generation_digest=scope[2], operation=scope[3], work=work)
    wire._distinct_keys(pins[1], public_key, work)
    window = wire._open_control_window_on_work(timing, maximum_age_ns=maximum_control_age_ns,
        maximum_clock_skew_ns=skew, work=work)
    actual_bodies = wire._body_commitments_on_work(envelope_bytes=originals[0], proof_bytes=originals[1],
        inputs_bytes=originals[2], context_bytes=originals[3], historical_expectations_bytes=originals[4], work=work)
    evidence.plan._same(actual_bodies, signed_bodies, work,
        "transition custody intent differs from its complete original-byte commitments")
    # Only the authenticated verifier's separately committed history is used;
    # it still must match the current independently admitted configuration.
    historical = context_wire._decode_on_work(originals[4], work=work)
    owned = admission._capture_expectations_on_work(pins, historical, work)
    if expires > owned["proofExpectations"]["policy"]["deadlineEpochNs"]:
        raise WebAuthnTransitionCustodyIntentError("transition custody intent extends its historical deadline")
    retained = retention._verify_record_on_work(envelope_bytes=originals[0], proof_bytes=originals[1],
        inputs_bytes=originals[2], context_bytes=originals[3], expectations=owned,
        planner_public_key=pins[1], operation_public_key=pins[4], work=work)
    evidence.plan._same(retained.record_digest, record_digest, work,
        "transition custody intent differs from the genuinely replayed retained record")
    payload = _payload_on_work(originals[0], work)
    if expires > payload["expiresAtEpochNs"]:
        raise WebAuthnTransitionCustodyIntentError("transition custody intent extends its original signed plan")
    _current_on_work(payload, owned, timing, window=window,
        maximum_control_age_ns=maximum_control_age_ns, skew=skew, work=work)
    return _VerifiedIntent(record_digest, issued, expires, window)
