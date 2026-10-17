"""Planner-signed exact-original responses to live evidence-plan requests.

This separate response binds the original authenticated request control and
all three produced originals, including the exact evaluation-context bytes.
The fixed caller must perform genuine planning and original-plan replay before
signing; this helper signs byte bindings, not a standalone semantic-proof DTO.
On receipt these bindings must pass before adopting any returned context.

Configured purpose keys and the original authenticated request timing/window
are independently held caller prerequisites. The response keeps that request's
expiry and its existing dual-clock window; it never renews the planning call.
All crypto, original-byte commitments and output accounting use the existing
work. No SQL, transport, execution, registry change or new allowance exists.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass

from catchplate import authority_webauthn_evidence_custody_wire as wire
from catchplate import authority_webauthn_evidence_plan_admission as admission


evidence, authority, retention, clock = wire.evidence, wire.authority, wire.retention, wire.clock
plan = retention.plan
SCHEMA = "catchplate.signedPolicyAuthorityWebAuthnEvidencePlanResponse/v1"
PURPOSE = "produced-evidence-plan"
MAX_CONTROL_BYTES = wire.MAX_CONTROL_BYTES
MAX_CONTROL_NODES = wire.MAX_CONTROL_NODES
MAX_CONTROL_DEPTH = wire.MAX_CONTROL_DEPTH
MAX_RESPONSE_BYTES = authority.MAX_RESULT_BYTES
_BODY_NAMES = ("request", "envelope", "inputs", "context")
_BODY_LIMITS = (MAX_CONTROL_BYTES, plan.contract.MAX_BYTES,
    plan.inputs_wire.MAX_BYTES, retention.context_wire.MAX_BYTES)
_FIELDS = frozenset({"schema", "sourceRevision", "purpose", "configurationDigest",
    "generationSequence", "generationDigest", "operation", "requestBytesDigest",
    "requestByteCount", "envelopeBytesDigest", "envelopeByteCount", "inputsBytesDigest",
    "inputsByteCount", "contextBytesDigest", "contextByteCount", "issuedAtEpochNs",
    "expiresAtEpochNs", "signatureBase64Url"})


class WebAuthnEvidencePlanResponseError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class _VerifiedPlanResponse:
    """Authenticated response timing observations, not plan semantics."""

    issued_at_epoch_ns: int
    expires_at_epoch_ns: int
    window: tuple


def _originals(request_control_bytes, envelope_bytes, inputs_bytes, evaluation_context_bytes):
    originals = request_control_bytes, envelope_bytes, inputs_bytes, evaluation_context_bytes
    for raw, maximum in zip(originals, _BODY_LIMITS):
        if type(raw) is not bytes or not 2 <= len(raw) <= maximum:
            raise WebAuthnEvidencePlanResponseError("evidence planning response requires bounded immutable originals")
    if sum(len(raw) for raw in originals[1:]) + 2 > MAX_RESPONSE_BYTES:
        raise WebAuthnEvidencePlanResponseError("evidence planning response originals exceed the aggregate bound")
    return originals


def _shape(value, *, signed=True):
    shape = evidence.plan.contract
    shape._object(value, _FIELDS if signed else _FIELDS - {"signatureBase64Url"},
        "evidence planning response")
    shape._literal(value["schema"], SCHEMA)
    shape._literal(value["sourceRevision"], authority.SOURCE_REVISION)
    shape._literal(value["purpose"], PURPOSE)
    wire._pins(value["configurationDigest"], value["generationSequence"],
        value["generationDigest"], value["operation"])
    for name, maximum in zip(_BODY_NAMES, _BODY_LIMITS):
        shape._digest(value[name + "BytesDigest"])
        shape._integer(value[name + "ByteCount"], maximum, minimum=2)
    for name in ("issuedAtEpochNs", "expiresAtEpochNs"):
        shape._integer(value[name], minimum=1)
    if not 0 < value["expiresAtEpochNs"] - value["issuedAtEpochNs"] <= authority.VERIFIER_RESPONSE_MAX_AGE_NS:
        raise WebAuthnEvidencePlanResponseError("evidence planning response lifetime exceeds its source bound")
    if signed:
        shape._base64url(value["signatureBase64Url"], signature=True)


def _request_timing(issued, expires, window, maximum_age_ns, maximum_clock_skew_ns):
    timing = {"issuedAtEpochNs": issued, "expiresAtEpochNs": expires}
    wire._time_pins(timing, maximum_age_ns, maximum_clock_skew_ns)
    held = clock._validate(window)
    if (held[3] > expires or held[5] > maximum_age_ns or held[6] > maximum_clock_skew_ns):
        raise WebAuthnEvidencePlanResponseError("evidence planning response widens the original request window")
    return timing, held


def _fresh_response(timing, request_timing, *, window, maximum_age_ns, maximum_clock_skew_ns, work):
    issued, expires = wire._time_pins(timing, maximum_age_ns, maximum_clock_skew_ns)
    request_issued, request_expires = wire._time_pins(request_timing,
        maximum_age_ns, maximum_clock_skew_ns)
    evidence.plan._same(expires, request_expires, work,
        "evidence planning response changed the original request expiry")
    if issued < request_issued - maximum_clock_skew_ns:
        raise WebAuthnEvidencePlanResponseError("evidence planning response predates its request")
    now = wire._fresh_on_work(request_timing, window=window, maximum_age_ns=maximum_age_ns,
        maximum_clock_skew_ns=maximum_clock_skew_ns, work=work)
    if issued > now + maximum_clock_skew_ns or now - issued > maximum_age_ns or now >= expires:
        raise WebAuthnEvidencePlanResponseError("evidence planning response is stale, future-issued or expired")
    return now


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


def _sign_control(unsigned, *, private_key, public_key, detached_size, work):
    ledger = evidence.capture._SharedLedger(work)
    if (not isinstance(private_key, plan.Ed25519PrivateKey)
            or not isinstance(public_key, plan.Ed25519PublicKey)):
        raise WebAuthnEvidencePlanResponseError("evidence planning response signer is not Ed25519")
    evidence.plan.contract._integer(detached_size, MAX_RESPONSE_BYTES, minimum=6)
    _shape(unsigned, signed=False)
    owned = evidence.capture._JSONCapture(ledger, maximum_bytes=MAX_CONTROL_BYTES).visit(unsigned)
    envelope = {**owned, "signatureBase64Url": "A" * 86}
    _shape(envelope)
    unsigned_size, unsigned_nodes = work.measure(owned)
    envelope_size, envelope_nodes = work.measure(envelope)
    if (max(unsigned_size, envelope_size) > MAX_CONTROL_BYTES
            or max(unsigned_nodes, envelope_nodes) > MAX_CONTROL_NODES
            or detached_size + envelope_size > MAX_RESPONSE_BYTES):
        raise WebAuthnEvidencePlanResponseError("evidence planning signed response exceeds its bounds")
    work.charge(input_bytes=4 * unsigned_size + envelope_size + evidence.production._SIGNATURE_TRANSPORT_BYTES,
        json_nodes=2 * unsigned_nodes + envelope_nodes)
    frame_bytes = 2 * len(SCHEMA) + 9 + unsigned_size + 2 * 71
    if (work.limits.max_hashes - work.hash_work < 1
            or work.limits.max_input_bytes - work.input_bytes < frame_bytes + unsigned_size
            or work.limits.max_json_nodes - work.json_nodes < 4 + unsigned_nodes):
        raise WebAuthnEvidencePlanResponseError("evidence planning response cannot reserve its complete signature output")
    original = evidence.plan.core.canonical_bytes(owned)
    if len(original) != unsigned_size:
        raise WebAuthnEvidencePlanResponseError("evidence planning response size changed after measurement")
    message = evidence.plan._ascii(evidence.plan._frame(SCHEMA, (original,), work), work)
    signature = evidence.production._sign_and_verify(private_key, public_key, message, work)
    if work.measure(owned) != (unsigned_size, unsigned_nodes):
        raise WebAuthnEvidencePlanResponseError("evidence planning response graph changed during signing")
    if evidence.plan.core.canonical_bytes(owned) != original:
        raise WebAuthnEvidencePlanResponseError("evidence planning response unsigned bytes changed during signing")
    encoded = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
    evidence.plan.contract._base64url(encoded, signature=True)
    result = evidence.plan.core.canonical_bytes({**owned, "signatureBase64Url": encoded})
    if len(result) != envelope_size:
        raise WebAuthnEvidencePlanResponseError("evidence planning response output changed after measurement")
    return result


def _produce_on_work(*, request_control_bytes, envelope_bytes, inputs_bytes,
        evaluation_context_bytes, pins, generation_sequence, generation_digest,
        planner_private_key, verifier_public_key, request_issued_at_epoch_ns,
        request_expires_at_epoch_ns, request_window, maximum_control_age_ns, work):
    evidence.capture._SharedLedger(work)
    originals = _originals(request_control_bytes, envelope_bytes, inputs_bytes, evaluation_context_bytes)
    pins = admission._validate_pins(pins)
    scope = wire._pins(pins[7], generation_sequence, generation_digest, pins[0])
    private_key, planner_key, verifier_key = planner_private_key, pins[1], verifier_public_key
    if (not isinstance(private_key, plan.Ed25519PrivateKey)
            or not isinstance(verifier_key, plan.Ed25519PublicKey)):
        raise WebAuthnEvidencePlanResponseError("evidence planning response requires actual role keys")
    request_timing, window = _request_timing(request_issued_at_epoch_ns,
        request_expires_at_epoch_ns, request_window, maximum_control_age_ns, pins[9])
    wire._fresh_on_work(request_timing, window=window, maximum_age_ns=maximum_control_age_ns,
        maximum_clock_skew_ns=pins[9], work=work)
    evidence.keys._public_binding(planner_key, pins[3], work)
    wire._distinct_keys(planner_key, verifier_key, work)
    evidence.keys._pair_on_work(private_key, planner_key, work)
    body = {}
    for name, raw in zip(_BODY_NAMES, originals):
        body[name + "BytesDigest"] = retention._bytes_digest(raw, work)
        body[name + "ByteCount"] = len(raw)
    issued = wire._fresh_on_work(request_timing, window=window,
        maximum_age_ns=maximum_control_age_ns, maximum_clock_skew_ns=pins[9], work=work)
    expires = request_expires_at_epoch_ns
    timing = {"issuedAtEpochNs": issued, "expiresAtEpochNs": expires}
    unsigned = {"schema": SCHEMA, "sourceRevision": authority.SOURCE_REVISION,
        "purpose": PURPOSE, "configurationDigest": scope[0], "generationSequence": scope[1],
        "generationDigest": scope[2], "operation": scope[3], **body,
        "issuedAtEpochNs": issued, "expiresAtEpochNs": expires}
    _fresh_response(timing, request_timing, window=window, maximum_age_ns=maximum_control_age_ns,
        maximum_clock_skew_ns=pins[9], work=work)
    control = _sign_control(unsigned, private_key=private_key, public_key=planner_key,
        detached_size=sum(len(raw) for raw in originals[1:]), work=work)
    _fresh_response(timing, request_timing, window=window, maximum_age_ns=maximum_control_age_ns,
        maximum_clock_skew_ns=pins[9], work=work)
    return control


def _verify_on_work(*, control_bytes, request_control_bytes, envelope_bytes, inputs_bytes,
        evaluation_context_bytes, pins, generation_sequence, generation_digest,
        verifier_public_key, request_issued_at_epoch_ns, request_expires_at_epoch_ns,
        request_window, maximum_control_age_ns, work):
    ledger = evidence.capture._SharedLedger(work)
    originals = _originals(request_control_bytes, envelope_bytes, inputs_bytes, evaluation_context_bytes)
    if (type(control_bytes) is not bytes or not 2 <= len(control_bytes) <= MAX_CONTROL_BYTES
            or len(control_bytes) + sum(len(raw) for raw in originals[1:]) > MAX_RESPONSE_BYTES):
        raise WebAuthnEvidencePlanResponseError("evidence planning response control exceeds its aggregate bound")
    original = control_bytes
    pins = admission._validate_pins(pins)
    scope = wire._pins(pins[7], generation_sequence, generation_digest, pins[0])
    planner_key, verifier_key = pins[1], verifier_public_key
    if not isinstance(verifier_key, plan.Ed25519PublicKey):
        raise WebAuthnEvidencePlanResponseError("evidence planning response requires an actual verifier key")
    request_timing, window = _request_timing(request_issued_at_epoch_ns,
        request_expires_at_epoch_ns, request_window, maximum_control_age_ns, pins[9])
    wire._fresh_on_work(request_timing, window=window, maximum_age_ns=maximum_control_age_ns,
        maximum_clock_skew_ns=pins[9], work=work)
    value, signature, unsigned_wire = _read_control(original, work)
    issued, expires = value["issuedAtEpochNs"], value["expiresAtEpochNs"]
    expected_body = tuple((value[name + "BytesDigest"], value[name + "ByteCount"]) for name in _BODY_NAMES)
    timing = {"issuedAtEpochNs": issued, "expiresAtEpochNs": expires}
    evidence.keys._public_binding(planner_key, pins[3], work)
    evidence.capability._signature(planner_key, signature, SCHEMA, unsigned_wire, ledger)
    evidence.capability._canonical(original, value, ledger, MAX_CONTROL_BYTES, MAX_CONTROL_NODES)
    evidence.plan._same((value["configurationDigest"], value["generationSequence"],
            value["generationDigest"], value["operation"]), scope, work,
        "evidence planning response differs from independent configuration, generation or operation")
    wire._distinct_keys(planner_key, verifier_key, work)
    actual_body = tuple((retention._bytes_digest(raw, work), len(raw)) for raw in originals)
    evidence.plan._same(actual_body, expected_body, work,
        "evidence planning response differs from the original request or produced bytes")
    _fresh_response(timing, request_timing, window=window, maximum_age_ns=maximum_control_age_ns,
        maximum_clock_skew_ns=pins[9], work=work)
    return _VerifiedPlanResponse(issued, expires, window)
