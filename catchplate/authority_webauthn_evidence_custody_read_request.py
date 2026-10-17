"""Verifier-signed, lookup-only requests for retained evidence-plan originals.

The producer binds an independently held record identity and historical
expectations to current admitted configuration, generation and purpose pins.
A new bounded read window authorizes lookup even when the historical plan's
execution/retention deadline has expired; it never refreshes that old deadline.
The original request is forwarded unchanged, without a planner signature.

The receiver authenticates the exact control and history commitment before
decoding historical data and joining it to independently held configured pins.
No plan can be replayed before retrieval, and these ordinary scalar results do
not claim such replay, durable custody, execution or historical key enrollment.
Actual original-plan verification remains required after retrieval. No SQL,
socket, automatic retry, registry activation or new work allowance exists here.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass

from catchplate import authority_webauthn_evidence_custody_wire as wire
from catchplate import authority_webauthn_evidence_plan_admission as admission
from catchplate import authority_webauthn_evidence_plan_context as context_wire


evidence, authority, retention, clock = wire.evidence, wire.authority, wire.retention, wire.clock
SCHEMA = "catchplate.signedPolicyAuthorityWebAuthnEvidenceCustodyReadRequest/v1"
PURPOSE = "read-evidence-plan"
MAX_CONTROL_BYTES = wire.MAX_CONTROL_BYTES
MAX_CONTROL_NODES = wire.MAX_CONTROL_NODES
MAX_CONTROL_DEPTH = wire.MAX_CONTROL_DEPTH
_FIELDS = frozenset({"schema", "sourceRevision", "purpose", "configurationDigest",
    "generationSequence", "generationDigest", "operation", "retainedRecordDigest",
    "historyBytesDigest", "historyByteCount", "issuedAtEpochNs", "expiresAtEpochNs",
    "signatureBase64Url"})


class WebAuthnEvidenceCustodyReadRequestError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class _ProducedReadRequest:
    control_bytes: bytes
    historical_expectations_bytes: bytes


@dataclass(frozen=True, slots=True)
class _VerifiedReadRequest:
    """Local scalar observations, not accepted proof or plan-replay input."""

    retained_record_digest: str
    issued_at_epoch_ns: int
    expires_at_epoch_ns: int
    window: tuple


def _archive_validity(value):
    if type(value) is not tuple or len(value) != 2:
        raise WebAuthnEvidenceCustodyReadRequestError("evidence read archive validity is not an exact pair")
    lower, upper = value
    for instant in (lower, upper):
        evidence.plan.contract._integer(instant, minimum=1)
    if lower >= upper:
        raise WebAuthnEvidenceCustodyReadRequestError("evidence read archive validity is empty")
    return lower, upper


def _shape(value, *, signed=True):
    shape = evidence.plan.contract
    shape._object(value, _FIELDS if signed else _FIELDS - {"signatureBase64Url"},
        "evidence custody read control")
    shape._literal(value["schema"], SCHEMA)
    shape._literal(value["sourceRevision"], authority.SOURCE_REVISION)
    shape._literal(value["purpose"], PURPOSE)
    wire._pins(value["configurationDigest"], value["generationSequence"],
        value["generationDigest"], value["operation"])
    shape._digest(value["retainedRecordDigest"])
    shape._digest(value["historyBytesDigest"])
    shape._integer(value["historyByteCount"], context_wire.MAX_BYTES, minimum=2)
    for field in ("issuedAtEpochNs", "expiresAtEpochNs"):
        shape._integer(value[field], minimum=1)
    if value["issuedAtEpochNs"] >= value["expiresAtEpochNs"]:
        raise WebAuthnEvidenceCustodyReadRequestError("evidence read issuance does not precede expiry")
    if signed:
        shape._base64url(value["signatureBase64Url"], signature=True)


def _read_control(raw, work):
    ledger = evidence.capture._SharedLedger(work)
    value = evidence.wire._decode_object(raw, work=work, maximum_bytes=MAX_CONTROL_BYTES,
        maximum_nodes=MAX_CONTROL_NODES, maximum_depth=MAX_CONTROL_DEPTH)
    _shape(value)
    evidence.capability._canonical(raw, value, ledger, MAX_CONTROL_BYTES, MAX_CONTROL_NODES)
    work.prepare_copy(value)
    unsigned = value.copy()
    signature = unsigned.pop("signatureBase64Url")
    unsigned_wire = evidence.capability._wire(unsigned, ledger, MAX_CONTROL_BYTES, MAX_CONTROL_NODES)
    return value, signature, unsigned_wire


def _sign_control(unsigned, *, private_key, public_key, work):
    """Reserve actual output and sign only the dedicated read domain."""
    ledger = evidence.capture._SharedLedger(work)
    if (not isinstance(private_key, retention.plan.Ed25519PrivateKey)
            or not isinstance(public_key, retention.plan.Ed25519PublicKey)):
        raise WebAuthnEvidenceCustodyReadRequestError("evidence read signing requires real Ed25519 keys")
    _shape(unsigned, signed=False)
    owned = evidence.capture._JSONCapture(ledger, maximum_bytes=MAX_CONTROL_BYTES).visit(unsigned)
    envelope = {**owned, "signatureBase64Url": "A" * 86}
    _shape(envelope)
    unsigned_size, unsigned_nodes = work.measure(owned)
    envelope_size, envelope_nodes = work.measure(envelope)
    if (max(unsigned_size, envelope_size) > MAX_CONTROL_BYTES
            or max(unsigned_nodes, envelope_nodes) > MAX_CONTROL_NODES
            or envelope_size + owned["historyByteCount"] > authority.MAX_RESULT_BYTES):
        raise WebAuthnEvidenceCustodyReadRequestError("evidence read signed output exceeds its control bound")
    # Prepay both actual encodings, the post-callback full comparison, final
    # envelope and signature transport before the native signing callback.
    work.charge(input_bytes=4 * unsigned_size + envelope_size + evidence.production._SIGNATURE_TRANSPORT_BYTES,
        json_nodes=2 * unsigned_nodes + envelope_nodes)
    frame_bytes = 2 * len(SCHEMA) + 9 + unsigned_size + 2 * 71
    if (work.limits.max_hashes - work.hash_work < 1
            or work.limits.max_input_bytes - work.input_bytes < frame_bytes + unsigned_size
            or work.limits.max_json_nodes - work.json_nodes < 4 + unsigned_nodes):
        raise WebAuthnEvidenceCustodyReadRequestError("evidence read cannot reserve its complete signature output")
    original = evidence.plan.core.canonical_bytes(owned)
    if len(original) != unsigned_size:
        raise WebAuthnEvidenceCustodyReadRequestError("evidence read unsigned bytes changed after measurement")
    message = evidence.plan._ascii(evidence.plan._frame(SCHEMA, (original,), work), work)
    signature = evidence.production._sign_and_verify(private_key, public_key, message, work)
    if work.measure(owned) != (unsigned_size, unsigned_nodes):
        raise WebAuthnEvidenceCustodyReadRequestError("evidence read graph changed during signing")
    if evidence.plan.core.canonical_bytes(owned) != original:
        raise WebAuthnEvidenceCustodyReadRequestError("evidence read unsigned bytes changed during signing")
    encoded = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
    evidence.plan.contract._base64url(encoded, signature=True)
    result = evidence.plan.core.canonical_bytes({**owned, "signatureBase64Url": encoded})
    if len(result) != envelope_size:
        raise WebAuthnEvidenceCustodyReadRequestError("evidence read final output changed after measurement")
    return result


def _produce_on_work(*, retained_record_digest, expectations, pins, historical_pins,
        generation_sequence, generation_digest, verifier_private_key, verifier_public_key,
        maximum_control_age_ns, archive_validity, work):
    evidence.capture._SharedLedger(work)
    archive_from, archive_until = _archive_validity(archive_validity)
    pins = admission._validate_pins(pins)
    historical_pins = admission._validate_pins(historical_pins)
    evidence.plan._same(pins[0], historical_pins[0], work,
        "evidence lookup and historical replay operations differ")
    shape = evidence.plan.contract
    shape._digest(retained_record_digest)
    record_digest = retained_record_digest
    scope = wire._pins(pins[7], generation_sequence, generation_digest, pins[0])
    private_key, public_key = verifier_private_key, verifier_public_key
    if (not isinstance(private_key, retention.plan.Ed25519PrivateKey)
            or not isinstance(public_key, retention.plan.Ed25519PublicKey)):
        raise WebAuthnEvidenceCustodyReadRequestError("evidence read signer is not Ed25519")
    shape._integer(maximum_control_age_ns, authority.VERIFIER_RESPONSE_MAX_AGE_NS, minimum=1)
    # Independent history is fully owned before the first real key callback.
    # These joins use the separately admitted historical configuration, not
    # current control pins and not a missing stored plan.
    owned = admission._capture_expectations_on_work(historical_pins, expectations, work)
    historical = context_wire._encode_on_work(expectations=owned, work=work)
    wire._distinct_keys(pins[1], public_key, work)
    evidence.keys._pair_on_work(private_key, public_key, work)
    history_digest = retention._bytes_digest(historical, work)
    # The current archive, not an old plan deadline, bounds this new lookup.
    window = clock._open_on_work(deadline_epoch_ns=archive_until,
        maximum_lifetime_ns=maximum_control_age_ns, maximum_clock_skew_ns=pins[9], work=work)
    issued, expires = window[0], clock._deadline_epoch_ns(window)
    if issued < archive_from or expires > archive_until:
        raise WebAuthnEvidenceCustodyReadRequestError("evidence read lifetime exceeds the admitted archive")
    timing = {"issuedAtEpochNs": issued, "expiresAtEpochNs": expires}
    unsigned = {"schema": SCHEMA, "sourceRevision": authority.SOURCE_REVISION,
        "purpose": PURPOSE, "configurationDigest": scope[0], "generationSequence": scope[1],
        "generationDigest": scope[2], "operation": scope[3], "retainedRecordDigest": record_digest,
        "historyBytesDigest": history_digest, "historyByteCount": len(historical),
        "issuedAtEpochNs": issued, "expiresAtEpochNs": expires}
    wire._fresh_on_work(timing, window=window, maximum_age_ns=maximum_control_age_ns,
        maximum_clock_skew_ns=pins[9], work=work)
    original = _sign_control(unsigned, private_key=private_key, public_key=public_key, work=work)
    wire._fresh_on_work(timing, window=window, maximum_age_ns=maximum_control_age_ns,
        maximum_clock_skew_ns=pins[9], work=work)
    return _ProducedReadRequest(original, historical)


def _authenticate_on_work(*, control_bytes, historical_expectations_bytes, pins,
        generation_sequence, generation_digest, verifier_public_key, maximum_control_age_ns,
        archive_validity, work):
    """Authenticate current lookup and original history bytes, without decoding history."""
    ledger = evidence.capture._SharedLedger(work)
    archive_from, archive_until = _archive_validity(archive_validity)
    pins = admission._validate_pins(pins)
    for raw, maximum in ((control_bytes, MAX_CONTROL_BYTES),
            (historical_expectations_bytes, context_wire.MAX_BYTES)):
        if type(raw) is not bytes or not 2 <= len(raw) <= maximum:
            raise WebAuthnEvidenceCustodyReadRequestError("evidence read requires bounded immutable originals")
    original, historical = control_bytes, historical_expectations_bytes
    if len(original) + len(historical) > authority.MAX_RESULT_BYTES:
        raise WebAuthnEvidenceCustodyReadRequestError("evidence read originals exceed their aggregate bound")
    scope = wire._pins(pins[7], generation_sequence, generation_digest, pins[0])
    public_key = verifier_public_key
    if not isinstance(public_key, retention.plan.Ed25519PublicKey):
        raise WebAuthnEvidenceCustodyReadRequestError("evidence read verifier is not Ed25519")
    evidence.plan.contract._integer(maximum_control_age_ns, authority.VERIFIER_RESPONSE_MAX_AGE_NS, minimum=1)
    value, signature, unsigned_wire = _read_control(original, work)
    record_digest = value["retainedRecordDigest"]
    issued, expires = value["issuedAtEpochNs"], value["expiresAtEpochNs"]
    if issued < archive_from or expires > archive_until:
        raise WebAuthnEvidenceCustodyReadRequestError("evidence read lifetime exceeds the admitted archive")
    history_commitment = value["historyBytesDigest"], value["historyByteCount"]
    timing = {"issuedAtEpochNs": issued, "expiresAtEpochNs": expires}
    evidence.capability._signature(public_key, signature, SCHEMA, unsigned_wire, ledger)
    evidence.capability._canonical(original, value, ledger, MAX_CONTROL_BYTES, MAX_CONTROL_NODES)
    evidence.plan._same((value["configurationDigest"], value["generationSequence"],
            value["generationDigest"], value["operation"]), scope, work,
        "evidence read differs from independently held configuration, generation or operation")
    wire._distinct_keys(pins[1], public_key, work)
    window = wire._open_control_window_on_work(timing, maximum_age_ns=maximum_control_age_ns,
        maximum_clock_skew_ns=pins[9], work=work)
    evidence.plan._same((retention._bytes_digest(historical, work), len(historical)),
        history_commitment, work, "evidence read differs from its complete historical-byte commitment")
    wire._fresh_on_work(timing, window=window, maximum_age_ns=maximum_control_age_ns,
        maximum_clock_skew_ns=pins[9], work=work)
    return _VerifiedReadRequest(record_digest, issued, expires, window)


def _verify_on_work(*, control_bytes, historical_expectations_bytes, pins, historical_pins,
        generation_sequence, generation_digest, verifier_public_key, maximum_control_age_ns,
        archive_validity, work):
    """Authenticate once, then join only independently admitted historical pins."""
    held_validity = _archive_validity(archive_validity)
    pins = admission._validate_pins(pins)
    historical_pins = admission._validate_pins(historical_pins)
    original, historical = control_bytes, historical_expectations_bytes
    evidence.plan._same(pins[0], historical_pins[0], work,
        "evidence lookup and historical replay operations differ")
    verified = _authenticate_on_work(control_bytes=original, historical_expectations_bytes=historical,
        pins=pins, generation_sequence=generation_sequence, generation_digest=generation_digest,
        verifier_public_key=verifier_public_key, maximum_control_age_ns=maximum_control_age_ns,
        archive_validity=held_validity, work=work)
    window = verified.window
    timing = {"issuedAtEpochNs": verified.issued_at_epoch_ns, "expiresAtEpochNs": verified.expires_at_epoch_ns}
    decoded = context_wire._decode_on_work(historical, work=work)
    admission._capture_expectations_on_work(historical_pins, decoded, work)
    wire._fresh_on_work(timing, window=window, maximum_age_ns=maximum_control_age_ns,
        maximum_clock_skew_ns=pins[9], work=work)
    return verified
