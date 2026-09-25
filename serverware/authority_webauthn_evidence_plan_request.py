"""Verifier-signed original-input requests for live evidence planning.

The dedicated control authenticates the complete detached request context and
original input bytes under current independently admitted configuration and
generation pins. Its context contains the caller's typed request, before-root
observations, input commitment and deadline, not retained-plan history or a
successful semantic/proof result. Request/root/input provenance remains the
caller's admission responsibility; genuine planner computation follows.

All variable input graphs are owned before key or clock callbacks. Original
canonical bytes, request and operation commitments, real Ed25519 signatures,
distinct role keys and one bounded epoch/monotonic window use the same work.
There is no SQL, transport, execution capability, registry change or retry.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass

from serverware import authority_request_commitment as commitment
from serverware import authority_webauthn_evidence_custody_wire as wire
from serverware import authority_webauthn_evidence_input_wire as inputs_wire
from serverware import authority_webauthn_evidence_plan_admission as admission


evidence, authority, retention, clock = wire.evidence, wire.authority, wire.retention, wire.clock
plan = retention.plan
SCHEMA = "serverware.signedPolicyAuthorityWebAuthnEvidencePlanRequest/v1"
CONTEXT_SCHEMA = "serverware.policyAuthorityWebAuthnEvidencePlanRequestContext/v1"
PURPOSE = "produce-evidence-plan"
MAX_CONTROL_BYTES = wire.MAX_CONTROL_BYTES
MAX_CONTROL_NODES = wire.MAX_CONTROL_NODES
MAX_CONTROL_DEPTH = wire.MAX_CONTROL_DEPTH
MAX_CONTEXT_BYTES = plan.contract.MAX_BYTES
MAX_CONTEXT_NODES = plan.contract.MAX_NODES
MAX_CONTEXT_DEPTH = plan.contract.MAX_DEPTH
MAX_INPUT_BYTES = inputs_wire.MAX_BYTES
MAX_REQUEST_BYTES = authority.MAX_RESULT_BYTES
_FIELDS = frozenset({"schema", "sourceRevision", "purpose", "configurationDigest",
    "generationSequence", "generationDigest", "operation", "contextBytesDigest",
    "contextByteCount", "inputsBytesDigest", "inputsByteCount", "issuedAtEpochNs",
    "expiresAtEpochNs", "signatureBase64Url"})
_CONTEXT_FIELDS = frozenset({"schema", "sourceRevision", "operation", "request",
    "businessBeforeRoots", "authorizationBeforeRoots", "inputsDigest", "deadlineEpochNs"})


class WebAuthnEvidencePlanRequestError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class _ProducedPlanRequest:
    control_bytes: bytes
    context_bytes: bytes
    inputs_bytes: bytes


@dataclass(frozen=True, slots=True)
class _VerifiedPlanRequest:
    """Owned request data and local timings, never proof of planner semantics."""

    context: dict
    issued_at_epoch_ns: int
    expires_at_epoch_ns: int
    window: tuple


def _raw3(control_bytes, context_bytes, inputs_bytes):
    originals = control_bytes, context_bytes, inputs_bytes
    for raw, maximum in zip(originals, (MAX_CONTROL_BYTES, MAX_CONTEXT_BYTES, MAX_INPUT_BYTES)):
        if type(raw) is not bytes or not 2 <= len(raw) <= maximum:
            raise WebAuthnEvidencePlanRequestError("evidence planning requires bounded immutable originals")
    if sum(len(raw) for raw in originals) > MAX_REQUEST_BYTES:
        raise WebAuthnEvidencePlanRequestError("evidence planning originals exceed the aggregate bound")
    return originals


def _shape(value, *, signed=True):
    shape = evidence.plan.contract
    shape._object(value, _FIELDS if signed else _FIELDS - {"signatureBase64Url"},
        "evidence planning control")
    shape._literal(value["schema"], SCHEMA)
    shape._literal(value["sourceRevision"], authority.SOURCE_REVISION)
    shape._literal(value["purpose"], PURPOSE)
    wire._pins(value["configurationDigest"], value["generationSequence"],
        value["generationDigest"], value["operation"])
    for name, maximum in (("context", MAX_CONTEXT_BYTES), ("inputs", MAX_INPUT_BYTES)):
        shape._digest(value[name + "BytesDigest"])
        shape._integer(value[name + "ByteCount"], maximum, minimum=2)
    for name in ("issuedAtEpochNs", "expiresAtEpochNs"):
        shape._integer(value[name], minimum=1)
    if not 0 < value["expiresAtEpochNs"] - value["issuedAtEpochNs"] <= authority.VERIFIER_RESPONSE_MAX_AGE_NS:
        raise WebAuthnEvidencePlanRequestError("evidence planning control lifetime exceeds its source bound")
    if signed:
        shape._base64url(value["signatureBase64Url"], signature=True)


def _context_shape(value, operation):
    shape, contract = evidence.plan.contract, plan.contract
    shape._object(value, _CONTEXT_FIELDS, "evidence planning request context")
    shape._literal(value["schema"], CONTEXT_SCHEMA)
    shape._literal(value["sourceRevision"], authority.SOURCE_REVISION)
    shape._literal(value["operation"], operation)
    if type(operation) is not str or operation not in contract.OPERATIONS:
        raise WebAuthnEvidencePlanRequestError("evidence planning operation is not source fixed")
    contract._request(value["request"], operation, contract._SPECS[operation])
    contract._roots(value["businessBeforeRoots"], contract._BUSINESS_TABLES[operation])
    contract._roots(value["authorizationBeforeRoots"], contract._AUTHORIZATION_TABLES[operation])
    shape._digest(value["inputsDigest"])
    shape._integer(value["deadlineEpochNs"], minimum=1)


def _request_commitments(value, work):
    request, operation = value["request"], value["operation"]
    digest = commitment._typed_request_digest(request, work=work)
    if commitment._request_different(digest, request["requestDigest"], work=work):
        raise WebAuthnEvidencePlanRequestError("evidence planning typed request commitment changed")
    work.prepare_utf8(operation)
    work.prepare_utf8(digest)
    work.charge(hashes=1)
    if commitment._request_different(commitment.operation_id(operation, digest), request["operationId"], work=work):
        raise WebAuthnEvidencePlanRequestError("evidence planning operation commitment changed")


def _root_list(values, tables, work):
    if type(values) not in (list, tuple) or len(values) != len(tables):
        raise WebAuthnEvidencePlanRequestError("evidence planning roots differ from the source inventory")
    if type(values) is tuple:
        work.prepare_copy(values)
        return list(values)
    return values


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
    """Prepay the complete original output before its genuine paired sign."""
    ledger = evidence.capture._SharedLedger(work)
    if (not isinstance(private_key, plan.Ed25519PrivateKey)
            or not isinstance(public_key, plan.Ed25519PublicKey)):
        raise WebAuthnEvidencePlanRequestError("evidence planning signer is not Ed25519")
    evidence.plan.contract._integer(detached_size, MAX_REQUEST_BYTES, minimum=4)
    _shape(unsigned, signed=False)
    owned = evidence.capture._JSONCapture(ledger, maximum_bytes=MAX_CONTROL_BYTES).visit(unsigned)
    envelope = {**owned, "signatureBase64Url": "A" * 86}
    _shape(envelope)
    unsigned_size, unsigned_nodes = work.measure(owned)
    envelope_size, envelope_nodes = work.measure(envelope)
    if (max(unsigned_size, envelope_size) > MAX_CONTROL_BYTES
            or max(unsigned_nodes, envelope_nodes) > MAX_CONTROL_NODES
            or detached_size + envelope_size > MAX_REQUEST_BYTES):
        raise WebAuthnEvidencePlanRequestError("evidence planning signed originals exceed their bounds")
    work.charge(input_bytes=4 * unsigned_size + envelope_size + evidence.production._SIGNATURE_TRANSPORT_BYTES,
        json_nodes=2 * unsigned_nodes + envelope_nodes)
    frame_bytes = 2 * len(SCHEMA) + 9 + unsigned_size + 2 * 71
    if (work.limits.max_hashes - work.hash_work < 1
            or work.limits.max_input_bytes - work.input_bytes < frame_bytes + unsigned_size
            or work.limits.max_json_nodes - work.json_nodes < 4 + unsigned_nodes):
        raise WebAuthnEvidencePlanRequestError("evidence planning cannot reserve its complete signature output")
    original = evidence.plan.core.canonical_bytes(owned)
    if len(original) != unsigned_size:
        raise WebAuthnEvidencePlanRequestError("evidence planning unsigned size changed after measurement")
    message = evidence.plan._ascii(evidence.plan._frame(SCHEMA, (original,), work), work)
    signature = evidence.production._sign_and_verify(private_key, public_key, message, work)
    if work.measure(owned) != (unsigned_size, unsigned_nodes):
        raise WebAuthnEvidencePlanRequestError("evidence planning control changed during signing")
    if evidence.plan.core.canonical_bytes(owned) != original:
        raise WebAuthnEvidencePlanRequestError("evidence planning unsigned bytes changed during signing")
    encoded = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
    evidence.plan.contract._base64url(encoded, signature=True)
    result = evidence.plan.core.canonical_bytes({**owned, "signatureBase64Url": encoded})
    if len(result) != envelope_size:
        raise WebAuthnEvidencePlanRequestError("evidence planning output changed after measurement")
    return result


def _produce_on_work(*, request, business_before_roots, authorization_before_roots,
        inputs_bytes, deadline_epoch_ns, pins, generation_sequence, generation_digest,
        verifier_private_key, verifier_public_key, maximum_control_age_ns, work):
    ledger = evidence.capture._SharedLedger(work)
    pins = admission._validate_pins(pins)
    inputs_wire._raw(inputs_bytes, 2, MAX_INPUT_BYTES)
    original_inputs = inputs_bytes
    scope = wire._pins(pins[7], generation_sequence, generation_digest, pins[0])
    private_key, public_key = verifier_private_key, verifier_public_key
    if (not isinstance(private_key, plan.Ed25519PrivateKey)
            or not isinstance(public_key, plan.Ed25519PublicKey)):
        raise WebAuthnEvidencePlanRequestError("evidence planning requires actual verifier Ed25519 keys")
    evidence.plan.contract._integer(deadline_epoch_ns, minimum=1)
    evidence.plan.contract._integer(maximum_control_age_ns, authority.VERIFIER_RESPONSE_MAX_AGE_NS, minimum=1)
    document = {"schema": CONTEXT_SCHEMA, "sourceRevision": authority.SOURCE_REVISION,
        "operation": scope[3], "request": request,
        "businessBeforeRoots": _root_list(business_before_roots, plan.contract._BUSINESS_TABLES[scope[3]], work),
        "authorizationBeforeRoots": _root_list(authorization_before_roots,
            plan.contract._AUTHORIZATION_TABLES[scope[3]], work),
        "inputsDigest": inputs_wire._digest_on_work(original_inputs, work),
        "deadlineEpochNs": deadline_epoch_ns}
    owned = evidence.capture._JSONCapture(ledger, maximum_bytes=MAX_CONTEXT_BYTES).visit(document)
    _context_shape(owned, scope[3])
    _request_commitments(owned, work)
    deadline = owned["deadlineEpochNs"]
    context_bytes = evidence.capability._wire(owned, ledger, MAX_CONTEXT_BYTES, MAX_CONTEXT_NODES)
    if len(context_bytes) + len(original_inputs) + 2 > MAX_REQUEST_BYTES:
        raise WebAuthnEvidencePlanRequestError("evidence planning detached originals exceed the aggregate bound")
    # Only immutable bytes/scalars are used after the first key callback.
    context_digest = retention._bytes_digest(context_bytes, work)
    inputs_digest = retention._bytes_digest(original_inputs, work)
    wire._distinct_keys(pins[1], public_key, work)
    evidence.keys._pair_on_work(private_key, public_key, work)
    window = clock._open_on_work(deadline_epoch_ns=deadline,
        maximum_lifetime_ns=maximum_control_age_ns, maximum_clock_skew_ns=pins[9], work=work)
    issued, expires = window[0], clock._deadline_epoch_ns(window)
    timing = {"issuedAtEpochNs": issued, "expiresAtEpochNs": expires}
    unsigned = {"schema": SCHEMA, "sourceRevision": authority.SOURCE_REVISION,
        "purpose": PURPOSE, "configurationDigest": scope[0], "generationSequence": scope[1],
        "generationDigest": scope[2], "operation": scope[3],
        "contextBytesDigest": context_digest, "contextByteCount": len(context_bytes),
        "inputsBytesDigest": inputs_digest, "inputsByteCount": len(original_inputs),
        "issuedAtEpochNs": issued, "expiresAtEpochNs": expires}
    wire._fresh_on_work(timing, window=window, maximum_age_ns=maximum_control_age_ns,
        maximum_clock_skew_ns=pins[9], work=work)
    control = _sign_control(unsigned, private_key=private_key, public_key=public_key,
        detached_size=len(context_bytes) + len(original_inputs), work=work)
    wire._fresh_on_work(timing, window=window, maximum_age_ns=maximum_control_age_ns,
        maximum_clock_skew_ns=pins[9], work=work)
    _raw3(control, context_bytes, original_inputs)
    return _ProducedPlanRequest(control, context_bytes, original_inputs)


def _verify_on_work(*, control_bytes, context_bytes, inputs_bytes, pins,
        generation_sequence, generation_digest, verifier_public_key, maximum_control_age_ns, work):
    ledger = evidence.capture._SharedLedger(work)
    original, original_context, original_inputs = _raw3(control_bytes, context_bytes, inputs_bytes)
    pins = admission._validate_pins(pins)
    scope = wire._pins(pins[7], generation_sequence, generation_digest, pins[0])
    public_key = verifier_public_key
    if not isinstance(public_key, plan.Ed25519PublicKey):
        raise WebAuthnEvidencePlanRequestError("evidence planning verifier is not Ed25519")
    evidence.plan.contract._integer(maximum_control_age_ns, authority.VERIFIER_RESPONSE_MAX_AGE_NS, minimum=1)
    value, signature, unsigned_wire = _read_control(original, work)
    issued, expires = value["issuedAtEpochNs"], value["expiresAtEpochNs"]
    body_commitment = (value["contextBytesDigest"], value["contextByteCount"],
        value["inputsBytesDigest"], value["inputsByteCount"])
    timing = {"issuedAtEpochNs": issued, "expiresAtEpochNs": expires}
    evidence.capability._signature(public_key, signature, SCHEMA, unsigned_wire, ledger)
    evidence.capability._canonical(original, value, ledger, MAX_CONTROL_BYTES, MAX_CONTROL_NODES)
    evidence.plan._same((value["configurationDigest"], value["generationSequence"],
            value["generationDigest"], value["operation"]), scope, work,
        "evidence planning control differs from independent configuration, generation or operation")
    wire._distinct_keys(pins[1], public_key, work)
    window = wire._open_control_window_on_work(timing, maximum_age_ns=maximum_control_age_ns,
        maximum_clock_skew_ns=pins[9], work=work)
    evidence.plan._same((retention._bytes_digest(original_context, work), len(original_context),
            retention._bytes_digest(original_inputs, work), len(original_inputs)), body_commitment, work,
        "evidence planning control differs from its complete original-byte commitments")
    # No request context is decoded until its signature and both byte bindings
    # have genuinely passed. Decoding does not establish planner semantics.
    decoded = evidence.wire._decode_object(original_context, work=work,
        maximum_bytes=MAX_CONTEXT_BYTES, maximum_nodes=MAX_CONTEXT_NODES, maximum_depth=MAX_CONTEXT_DEPTH)
    owned = evidence.capture._JSONCapture(ledger, maximum_bytes=MAX_CONTEXT_BYTES).visit(decoded)
    _context_shape(owned, scope[3])
    evidence.capability._canonical(original_context, owned, ledger, MAX_CONTEXT_BYTES, MAX_CONTEXT_NODES)
    evidence.plan._same(inputs_wire._digest_on_work(original_inputs, work), owned["inputsDigest"], work,
        "evidence planning context differs from the original input identity")
    _request_commitments(owned, work)
    if expires > owned["deadlineEpochNs"]:
        raise WebAuthnEvidencePlanRequestError("evidence planning control exceeds its admitted context deadline")
    wire._fresh_on_work(timing, window=window, maximum_age_ns=maximum_control_age_ns,
        maximum_clock_skew_ns=pins[9], work=work)
    # A clock callback must not retarget the owned graph returned to the fixed
    # planner. Full original canonical equality remains metered on this work.
    evidence.capability._canonical(original_context, owned, ledger, MAX_CONTEXT_BYTES, MAX_CONTEXT_NODES)
    return _VerifiedPlanRequest(owned, issued, expires, window)
