"""Verifier-signed lookup requests for retained transition-plan originals.

The dedicated control binds an independently held record identity and complete
historical expectations to the current admitted configuration and generation.
Its new bounded read window may outlive the historical plan. It does not renew
that plan's issue, expiry, evidence, invocation time or retention deadline.

The receiver authenticates the original signature, current scope and entire
history commitment before decoding history and joining actual configured pins.
No plan replay is possible before retrieval. Returned scalar observations are
not a response signature, historical enrollment, custody receipt or execution
permission. There is no SQL, transport, retry or replacement work allowance.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass

from serverware import authority_webauthn_transition_custody_wire as wire
from serverware import authority_webauthn_transition_plan_admission as admission
from serverware import authority_webauthn_transition_plan_context as context_wire


evidence, authority, retention, clock = wire.evidence, wire.authority, wire.retention, wire.clock
SCHEMA = "serverware.signedPolicyAuthorityWebAuthnTransitionCustodyReadRequest/v1"
PURPOSE = "read-transition-plan"
MAX_CONTROL_BYTES = wire.MAX_CONTROL_BYTES
MAX_CONTROL_NODES = wire.MAX_CONTROL_NODES
MAX_CONTROL_DEPTH = wire.MAX_CONTROL_DEPTH
MAX_HISTORY_BYTES = context_wire.MAX_BYTES
MAX_REQUEST_BYTES = authority.MAX_RESULT_BYTES
_FIELDS = frozenset({"schema", "sourceRevision", "purpose", "configurationDigest",
    "generationSequence", "generationDigest", "operation", "retainedRecordDigest",
    "historyBytesDigest", "historyByteCount", "issuedAtEpochNs", "expiresAtEpochNs",
    "signatureBase64Url"})


class WebAuthnTransitionCustodyReadRequestError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class _ProducedReadRequest:
    control_bytes: bytes
    historical_expectations_bytes: bytes


@dataclass(frozen=True, slots=True)
class _VerifiedReadRequest:
    """Same-call scalar observations, never accepted as plan-replay input."""

    retained_record_digest: str
    issued_at_epoch_ns: int
    expires_at_epoch_ns: int
    window: tuple


def _raw2(control_bytes, historical_expectations_bytes):
    originals = control_bytes, historical_expectations_bytes
    for raw, maximum in zip(originals, (MAX_CONTROL_BYTES, MAX_HISTORY_BYTES)):
        if type(raw) is not bytes or not 2 <= len(raw) <= maximum:
            raise WebAuthnTransitionCustodyReadRequestError("transition read requires bounded immutable originals")
    if sum(len(raw) for raw in originals) > MAX_REQUEST_BYTES:
        raise WebAuthnTransitionCustodyReadRequestError("transition read originals exceed their aggregate bound")
    return originals


def _shape(value, *, signed=True):
    shape = retention.plan.contract.shape
    shape._object(value, _FIELDS if signed else _FIELDS - {"signatureBase64Url"},
        "transition custody read control")
    shape._literal(value["schema"], SCHEMA)
    shape._literal(value["sourceRevision"], authority.SOURCE_REVISION)
    shape._literal(value["purpose"], PURPOSE)
    wire._pins(value["configurationDigest"], value["generationSequence"],
        value["generationDigest"], value["operation"])
    shape._digest(value["retainedRecordDigest"])
    shape._digest(value["historyBytesDigest"])
    shape._integer(value["historyByteCount"], MAX_HISTORY_BYTES, minimum=2)
    for name in ("issuedAtEpochNs", "expiresAtEpochNs"):
        shape._integer(value[name], minimum=1)
    if not 0 < value["expiresAtEpochNs"] - value["issuedAtEpochNs"] <= authority.VERIFIER_RESPONSE_MAX_AGE_NS:
        raise WebAuthnTransitionCustodyReadRequestError("transition read lifetime exceeds its source bound")
    if signed:
        shape._base64url(value["signatureBase64Url"], signature=True)


def _read_control(raw, work):
    ledger = evidence.capture._SharedLedger(work)
    if type(raw) is not bytes or not 2 <= len(raw) <= MAX_CONTROL_BYTES:
        raise WebAuthnTransitionCustodyReadRequestError("transition read control exceeds its byte bound")
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
    """Reserve actual read-control output before dedicated-domain signing."""
    ledger = evidence.capture._SharedLedger(work)
    if (not isinstance(private_key, retention.plan.Ed25519PrivateKey)
            or not isinstance(public_key, retention.plan.Ed25519PublicKey)):
        raise WebAuthnTransitionCustodyReadRequestError("transition read signing requires actual Ed25519 keys")
    _shape(unsigned, signed=False)
    owned = evidence.capture._JSONCapture(ledger, maximum_bytes=MAX_CONTROL_BYTES).visit(unsigned)
    envelope = {**owned, "signatureBase64Url": "A" * 86}
    _shape(envelope)
    unsigned_size, unsigned_nodes = work.measure(owned)
    envelope_size, envelope_nodes = work.measure(envelope)
    if (max(unsigned_size, envelope_size) > MAX_CONTROL_BYTES
            or max(unsigned_nodes, envelope_nodes) > MAX_CONTROL_NODES
            or envelope_size + owned["historyByteCount"] > MAX_REQUEST_BYTES):
        raise WebAuthnTransitionCustodyReadRequestError("transition read signed originals exceed their bounds")
    # Actual encodings, post-callback equality, final output and signature
    # transport are prepaid before the first native signing callback.
    work.charge(input_bytes=4 * unsigned_size + envelope_size + evidence.production._SIGNATURE_TRANSPORT_BYTES,
        json_nodes=2 * unsigned_nodes + envelope_nodes)
    frame_bytes = 2 * len(SCHEMA) + 9 + unsigned_size + 2 * 71
    if (work.limits.max_hashes - work.hash_work < 1
            or work.limits.max_input_bytes - work.input_bytes < frame_bytes + unsigned_size
            or work.limits.max_json_nodes - work.json_nodes < 4 + unsigned_nodes):
        raise WebAuthnTransitionCustodyReadRequestError("transition read cannot reserve its signature output")
    original = evidence.plan.core.canonical_bytes(owned)
    if len(original) != unsigned_size:
        raise WebAuthnTransitionCustodyReadRequestError("transition read unsigned bytes changed after measurement")
    message = evidence.plan._ascii(evidence.plan._frame(SCHEMA, (original,), work), work)
    signature = evidence.production._sign_and_verify(private_key, public_key, message, work)
    if work.measure(owned) != (unsigned_size, unsigned_nodes):
        raise WebAuthnTransitionCustodyReadRequestError("transition read control changed during signing")
    if evidence.plan.core.canonical_bytes(owned) != original:
        raise WebAuthnTransitionCustodyReadRequestError("transition read unsigned bytes changed during signing")
    encoded = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
    retention.plan.contract.shape._base64url(encoded, signature=True)
    result = evidence.plan.core.canonical_bytes({**owned, "signatureBase64Url": encoded})
    if len(result) != envelope_size:
        raise WebAuthnTransitionCustodyReadRequestError("transition read output changed after measurement")
    return result


def _produce_on_work(*, retained_record_digest, expectations, pins,
        generation_sequence, generation_digest, verifier_private_key, verifier_public_key,
        maximum_control_age_ns, work):
    evidence.capture._SharedLedger(work)
    pins = admission._validate_pins(pins)
    shape = retention.plan.contract.shape
    shape._digest(retained_record_digest)
    record_digest = retained_record_digest
    scope = wire._pins(pins[5], generation_sequence, generation_digest, pins[0])
    private_key, public_key, skew = verifier_private_key, verifier_public_key, pins[6][1]
    if (not isinstance(private_key, retention.plan.Ed25519PrivateKey)
            or not isinstance(public_key, retention.plan.Ed25519PublicKey)):
        raise WebAuthnTransitionCustodyReadRequestError("transition read signer is not Ed25519")
    shape._integer(maximum_control_age_ns, authority.VERIFIER_RESPONSE_MAX_AGE_NS, minimum=1)
    # This actual helper captures all independent5 before key callbacks, then
    # checks their full configured policy/key bindings. It cannot verify a
    # missing retained plan or enroll history from the record digest.
    owned = admission._capture_expectations_on_work(pins, expectations, work)
    historical = context_wire._encode_on_work(expectations=owned, work=work)
    if len(historical) + 2 > MAX_REQUEST_BYTES:
        raise WebAuthnTransitionCustodyReadRequestError("transition read history cannot fit its aggregate bound")
    wire._distinct_keys(pins[1], public_key, work)
    evidence.keys._pair_on_work(private_key, public_key, work)
    history_digest = retention._bytes_digest(historical, work)
    # A fresh lookup is not constrained by an expired historical plan. The
    # real clock clips this integer ceiling to the current configured lifetime.
    window = clock._open_on_work(deadline_epoch_ns=shape.I64_MAX,
        maximum_lifetime_ns=maximum_control_age_ns, maximum_clock_skew_ns=skew, work=work)
    issued, expires = window[0], clock._deadline_epoch_ns(window)
    timing = {"issuedAtEpochNs": issued, "expiresAtEpochNs": expires}
    unsigned = {"schema": SCHEMA, "sourceRevision": authority.SOURCE_REVISION,
        "purpose": PURPOSE, "configurationDigest": scope[0], "generationSequence": scope[1],
        "generationDigest": scope[2], "operation": scope[3], "retainedRecordDigest": record_digest,
        "historyBytesDigest": history_digest, "historyByteCount": len(historical),
        "issuedAtEpochNs": issued, "expiresAtEpochNs": expires}
    wire._fresh_on_work(timing, window=window, maximum_age_ns=maximum_control_age_ns,
        maximum_clock_skew_ns=skew, work=work)
    original = _sign_control(unsigned, private_key=private_key, public_key=public_key, work=work)
    wire._fresh_on_work(timing, window=window, maximum_age_ns=maximum_control_age_ns,
        maximum_clock_skew_ns=skew, work=work)
    _raw2(original, historical)
    return _ProducedReadRequest(original, historical)


def _verify_on_work(*, control_bytes, historical_expectations_bytes, pins,
        generation_sequence, generation_digest, verifier_public_key, maximum_control_age_ns, work):
    ledger = evidence.capture._SharedLedger(work)
    original, historical = _raw2(control_bytes, historical_expectations_bytes)
    pins = admission._validate_pins(pins)
    scope = wire._pins(pins[5], generation_sequence, generation_digest, pins[0])
    public_key, skew = verifier_public_key, pins[6][1]
    if not isinstance(public_key, retention.plan.Ed25519PublicKey):
        raise WebAuthnTransitionCustodyReadRequestError("transition read verifier is not Ed25519")
    retention.plan.contract.shape._integer(maximum_control_age_ns, authority.VERIFIER_RESPONSE_MAX_AGE_NS, minimum=1)
    value, signature, unsigned_wire = _read_control(original, work)
    record_digest = value["retainedRecordDigest"]
    issued, expires = value["issuedAtEpochNs"], value["expiresAtEpochNs"]
    history_commitment = value["historyBytesDigest"], value["historyByteCount"]
    timing = {"issuedAtEpochNs": issued, "expiresAtEpochNs": expires}
    evidence.capability._signature(public_key, signature, SCHEMA, unsigned_wire, ledger)
    evidence.capability._canonical(original, value, ledger, MAX_CONTROL_BYTES, MAX_CONTROL_NODES)
    evidence.plan._same((value["configurationDigest"], value["generationSequence"],
            value["generationDigest"], value["operation"]), scope, work,
        "transition read differs from independent configuration, generation or operation")
    wire._distinct_keys(pins[1], public_key, work)
    window = wire._open_control_window_on_work(timing, maximum_age_ns=maximum_control_age_ns,
        maximum_clock_skew_ns=skew, work=work)
    evidence.plan._same((retention._bytes_digest(historical, work), len(historical)),
        history_commitment, work, "transition read differs from its complete historical-byte commitment")
    # Signature, scope and complete byte commitment precede history decoding.
    # Current pins must match; neither key rollover nor provenance is inferred.
    decoded = context_wire._decode_on_work(historical, work=work)
    admission._capture_expectations_on_work(pins, decoded, work)
    wire._fresh_on_work(timing, window=window, maximum_age_ns=maximum_control_age_ns,
        maximum_clock_skew_ns=skew, work=work)
    return _VerifiedReadRequest(record_digest, issued, expires, window)
