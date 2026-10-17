"""Verifier-signed retain-only intents over genuine original evidence plans.

The producer owns independently admitted history, genuinely replays the three
originals, then signs their complete byte commitments and the resulting record
identity. The receiver authenticates that control and its configured scope
before decoding the committed history, and repeats the real retained replay.
No received successful-verification object can substitute for either replay.

Freshness uses one nonrenewable actual dual-clock window per invocation and
cannot extend the original plan or historical deadline. Historical roots,
configuration, signer keys and generation still need independent admission.
The returned observations confer no execution permission, reservation, fence,
durable receipt or rollback guarantee. There is no SQL, transport, automatic
retry, registry activation or replacement work allowance here.
"""
from __future__ import annotations

from dataclasses import dataclass

from catchplate import authority_webauthn_evidence_custody_wire as wire
from catchplate import authority_webauthn_evidence_plan_admission as admission
from catchplate import authority_webauthn_evidence_plan_context as context_wire
from catchplate import authority_webauthn_evidence_plan_verifier as verifier


evidence, authority, retention, clock = wire.evidence, wire.authority, wire.retention, wire.clock
_BODY_FIELDS = ("envelopeBytesDigest", "envelopeByteCount", "inputsBytesDigest", "inputsByteCount",
    "contextBytesDigest", "contextByteCount", "historyBytesDigest", "historyByteCount")


class WebAuthnEvidenceCustodyIntentError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class _ProducedIntent:
    intent_bytes: bytes
    historical_expectations_bytes: bytes


@dataclass(frozen=True, slots=True)
class _VerifiedIntent:
    """Local scalar observations, never accepted as plan-verification input."""

    retained_record_digest: str
    issued_at_epoch_ns: int
    expires_at_epoch_ns: int
    window: tuple


def _raw3(envelope_bytes, inputs_bytes, evaluation_context_bytes):
    originals = envelope_bytes, inputs_bytes, evaluation_context_bytes
    for raw, maximum in zip(originals, (retention.plan.contract.MAX_BYTES,
            retention.plan.inputs_wire.MAX_BYTES, context_wire.MAX_BYTES)):
        if type(raw) is not bytes or not 2 <= len(raw) <= maximum:
            raise WebAuthnEvidenceCustodyIntentError("evidence custody intent requires bounded original bytes")
    return originals


def _plan_expiry_on_work(payload_bytes, work):
    """Decode the actual replay's canonical payload, not a caller proof DTO."""
    ledger = evidence.capture._SharedLedger(work)
    contract = retention.plan.contract
    payload = evidence.wire._decode_object(payload_bytes, work=work,
        maximum_bytes=contract.MAX_BYTES, maximum_nodes=contract.MAX_NODES,
        maximum_depth=contract.MAX_DEPTH)
    contract.validate_payload_shape(payload)
    evidence.capability._canonical(payload_bytes, payload, ledger, contract.MAX_BYTES, contract.MAX_NODES)
    return payload["expiresAtEpochNs"]


def _produce_on_work(*, envelope_bytes, inputs_bytes, evaluation_context_bytes,
        expectations, pins, generation_sequence, generation_digest, verifier_private_key,
        verifier_public_key, maximum_control_age_ns, work):
    ledger = evidence.capture._SharedLedger(work)
    pins = admission._validate_pins(pins)
    originals = _raw3(envelope_bytes, inputs_bytes, evaluation_context_bytes)
    scope = wire._pins(pins[7], generation_sequence, generation_digest, pins[0])
    private_key, public_key = verifier_private_key, verifier_public_key
    if (not isinstance(private_key, retention.plan.Ed25519PrivateKey)
            or not isinstance(public_key, retention.plan.Ed25519PublicKey)):
        raise WebAuthnEvidenceCustodyIntentError("evidence custody intent signer is not Ed25519")
    evidence.plan.contract._integer(maximum_control_age_ns, authority.VERIFIER_RESPONSE_MAX_AGE_NS, minimum=1)
    evidence.plan.contract._object(expectations, retention.plan._EXPECTATION_FIELDS,
        "independent evidence custody history")
    owned = evidence.capture._JSONCapture(ledger).visit(expectations)
    retention.plan._validate_expectations(owned, pins[0])
    # This separate original comes from independently owned history, never
    # from the evaluation context decoded out of the retained record.
    historical = context_wire._encode_on_work(expectations=owned, work=work)
    deadline = owned["deadlineEpochNs"]
    window = clock._open_on_work(deadline_epoch_ns=deadline,
        maximum_lifetime_ns=maximum_control_age_ns, maximum_clock_skew_ns=pins[9], work=work)
    owner = verifier.EvidencePlanVerifier(pins=pins)
    retained = verifier.EvidencePlanVerifier.verify(owner, envelope_bytes=originals[0],
        inputs_bytes=originals[1], evaluation_context_bytes=originals[2], expectations=owned, work=work)
    record_digest, payload_bytes = retained.record_digest, retained.verification.payload_bytes
    plan_expiry = _plan_expiry_on_work(payload_bytes, work)
    issued, expires = window[0], min(clock._deadline_epoch_ns(window), plan_expiry)
    wire._distinct_keys(pins[1], public_key, work)
    evidence.keys._pair_on_work(private_key, public_key, work)
    commitments = wire._body_commitments_on_work(envelope_bytes=originals[0], inputs_bytes=originals[1],
        evaluation_context_bytes=originals[2], historical_expectations_bytes=historical, work=work)
    unsigned = {"schema": wire.INTENT_SCHEMA, "sourceRevision": authority.SOURCE_REVISION,
        "purpose": "retain-evidence-plan", "configurationDigest": scope[0],
        "generationSequence": scope[1], "generationDigest": scope[2], "operation": scope[3],
        "retainedRecordDigest": record_digest, **commitments,
        "issuedAtEpochNs": issued, "expiresAtEpochNs": expires}
    timing = {"issuedAtEpochNs": issued, "expiresAtEpochNs": expires}
    wire._fresh_on_work(timing, window=window, maximum_age_ns=maximum_control_age_ns,
        maximum_clock_skew_ns=pins[9], work=work)
    original = wire._sign_control(unsigned, relay=False, private_key=private_key, public_key=public_key, work=work)
    wire._fresh_on_work(timing, window=window, maximum_age_ns=maximum_control_age_ns,
        maximum_clock_skew_ns=pins[9], work=work)
    return _ProducedIntent(original, historical)


def _verify_on_work(*, intent_bytes, envelope_bytes, inputs_bytes, evaluation_context_bytes,
        historical_expectations_bytes, pins, generation_sequence, generation_digest,
        verifier_public_key, maximum_control_age_ns, work):
    ledger = evidence.capture._SharedLedger(work)
    pins = admission._validate_pins(pins)
    originals = wire._raw4(envelope_bytes, inputs_bytes, evaluation_context_bytes, historical_expectations_bytes)
    scope = wire._pins(pins[7], generation_sequence, generation_digest, pins[0])
    public_key = verifier_public_key
    if not isinstance(public_key, retention.plan.Ed25519PublicKey):
        raise WebAuthnEvidenceCustodyIntentError("evidence custody intent verifier is not Ed25519")
    evidence.plan.contract._integer(maximum_control_age_ns, authority.VERIFIER_RESPONSE_MAX_AGE_NS, minimum=1)
    value, signature, unsigned_wire = wire._read_control(intent_bytes, relay=False, work=work)
    record_digest = value["retainedRecordDigest"]
    issued, expires = value["issuedAtEpochNs"], value["expiresAtEpochNs"]
    signed_bodies = {name: value[name] for name in _BODY_FIELDS}
    timing = {"issuedAtEpochNs": issued, "expiresAtEpochNs": expires}
    # Authenticate purpose/schema and independent scope before any historical
    # document is decoded or adopted as this signed control's expectation.
    wire._signature(signature, unsigned_wire, relay=False, public_key=public_key, work=work)
    evidence.capability._canonical(intent_bytes, value, ledger, wire.MAX_CONTROL_BYTES, wire.MAX_CONTROL_NODES)
    wire._bind_control(value, configuration_digest=scope[0], generation_sequence=scope[1],
        generation_digest=scope[2], operation=scope[3], work=work)
    wire._distinct_keys(pins[1], public_key, work)
    window = wire._open_control_window_on_work(timing, maximum_age_ns=maximum_control_age_ns,
        maximum_clock_skew_ns=pins[9], work=work)
    actual_bodies = wire._body_commitments_on_work(envelope_bytes=originals[0], inputs_bytes=originals[1],
        evaluation_context_bytes=originals[2], historical_expectations_bytes=originals[3], work=work)
    evidence.plan._same(actual_bodies, signed_bodies, work,
        "evidence custody intent differs from its complete original-byte commitments")
    historical = context_wire._decode_on_work(originals[3], work=work)
    historical_deadline = historical["deadlineEpochNs"]
    if expires > historical_deadline:
        raise WebAuthnEvidenceCustodyIntentError("evidence custody intent extends its historical deadline")
    owner = verifier.EvidencePlanVerifier(pins=pins)
    retained = verifier.EvidencePlanVerifier.verify(owner, envelope_bytes=originals[0],
        inputs_bytes=originals[1], evaluation_context_bytes=originals[2], expectations=historical, work=work)
    actual_record, payload_bytes = retained.record_digest, retained.verification.payload_bytes
    evidence.plan._same(actual_record, record_digest, work,
        "evidence custody intent differs from the genuinely replayed retained record")
    if expires > _plan_expiry_on_work(payload_bytes, work):
        raise WebAuthnEvidenceCustodyIntentError("evidence custody intent extends its original signed plan")
    wire._fresh_on_work(timing, window=window, maximum_age_ns=maximum_control_age_ns,
        maximum_clock_skew_ns=pins[9], work=work)
    return _VerifiedIntent(record_digest, issued, expires, window)
