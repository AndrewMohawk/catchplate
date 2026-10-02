"""Authenticated original-input requests for the three successor planners.

The dedicated verifier control binds the exact typed request, complete primary
and potential counted-root inventories, original input identity, invocation
pins and unchanged caller times. None is a database cutoff, successful proof
or execution permission. Their independent admission precedes this protocol;
the fixed planner must still run its genuine acquisition and semantic work.

All mutable invocation data is owned before key or clock callbacks. The same
work pays for canonical originals, commitments, signatures and the unchanged
live request window. No evidence-admission protocol is widened here.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass

from serverware import authority_webauthn_evidence_custody_wire as wire
from serverware import authority_webauthn_transition_inputs as inputs_wire
from serverware import authority_webauthn_transition_plan as plan
from serverware import authority_webauthn_transition_plan_admission as admission
from serverware import authority_webauthn_transition_roots_contract as roots_contract


evidence, authority, retention, clock = wire.evidence, wire.authority, wire.retention, wire.clock
SCHEMA = "serverware.signedPolicyAuthorityWebAuthnTransitionPlanRequest/v1"
CONTEXT_SCHEMA = "serverware.policyAuthorityWebAuthnTransitionPlanRequestContext/v1"
PURPOSE = "produce-webauthn-transition-plan"
MAX_CONTROL_BYTES = wire.MAX_CONTROL_BYTES
MAX_CONTROL_NODES = wire.MAX_CONTROL_NODES
MAX_CONTROL_DEPTH = wire.MAX_CONTROL_DEPTH
MAX_CONTEXT_BYTES = plan.contract.MAX_BYTES
MAX_CONTEXT_NODES = plan.contract.MAX_NODES
MAX_CONTEXT_DEPTH = plan.contract.MAX_DEPTH
MAX_INPUT_BYTES = inputs_wire.wire.MAX_BYTES
MAX_REQUEST_BYTES = authority.MAX_RESULT_BYTES
_FIELDS = frozenset({"schema", "sourceRevision", "purpose", "configurationDigest",
    "generationSequence", "generationDigest", "operation", "contextBytesDigest",
    "contextByteCount", "inputsBytesDigest", "inputsByteCount", "issuedAtEpochNs",
    "expiresAtEpochNs", "signatureBase64Url"})
_CONTEXT_FIELDS = frozenset({"schema", "sourceRevision", "operation", "request",
    "businessBeforeRoots", "authorizationBeforeRoots", "countedBeforeHeads", "inputsDigest",
    "nowEpochNs", "deadlineEpochNs", "invocation"})


class WebAuthnTransitionRequestError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class _ProducedPlanRequest:
    control_bytes: bytes
    context_bytes: bytes
    inputs_bytes: bytes


@dataclass(frozen=True, slots=True)
class _VerifiedPlanRequest:
    """Owned request and local timing observations, never a proof token."""

    context: dict
    issued_at_epoch_ns: int
    expires_at_epoch_ns: int
    window: tuple


def _pins(configuration_digest, generation_sequence, generation_digest, operation):
    shape = plan.contract.shape
    shape._digest(configuration_digest)
    # This is artifact-sequence syntax, not configuration/launch admission.
    # The configured caller retains the native/local generation policy, and
    # verification below requires the exact independent generation scope.
    shape._integer(generation_sequence, minimum=0)
    shape._digest(generation_digest)
    if type(operation) is not str or operation not in plan.contract.OPERATIONS:
        raise WebAuthnTransitionRequestError("transition request operation is not source fixed")
    return configuration_digest, generation_sequence, generation_digest, operation


def _raw3(control_bytes, context_bytes, inputs_bytes):
    originals = control_bytes, context_bytes, inputs_bytes
    for raw, maximum in zip(originals, (MAX_CONTROL_BYTES, MAX_CONTEXT_BYTES, MAX_INPUT_BYTES)):
        if type(raw) is not bytes or not 2 <= len(raw) <= maximum:
            raise WebAuthnTransitionRequestError("transition request requires bounded immutable originals")
    if sum(len(raw) for raw in originals) > MAX_REQUEST_BYTES:
        raise WebAuthnTransitionRequestError("transition request originals exceed the aggregate bound")
    return originals


def _shape(value, *, signed=True):
    shape = plan.contract.shape
    shape._object(value, _FIELDS if signed else _FIELDS - {"signatureBase64Url"},
        "transition planning control")
    shape._literal(value["schema"], SCHEMA)
    shape._literal(value["sourceRevision"], authority.SOURCE_REVISION)
    shape._literal(value["purpose"], PURPOSE)
    _pins(value["configurationDigest"], value["generationSequence"],
        value["generationDigest"], value["operation"])
    for name, maximum in (("context", MAX_CONTEXT_BYTES), ("inputs", MAX_INPUT_BYTES)):
        shape._digest(value[name + "BytesDigest"])
        shape._integer(value[name + "ByteCount"], maximum, minimum=2)
    for name in ("issuedAtEpochNs", "expiresAtEpochNs"):
        shape._integer(value[name], minimum=1)
    if not 0 < value["expiresAtEpochNs"] - value["issuedAtEpochNs"] <= authority.VERIFIER_RESPONSE_MAX_AGE_NS:
        raise WebAuthnTransitionRequestError("transition request lifetime exceeds its source bound")
    if signed:
        shape._base64url(value["signatureBase64Url"], signature=True)


def _context_shape(value, operation):
    shape, contract = plan.contract.shape, plan.proof.contract
    if type(operation) is not str or operation not in contract.OPERATIONS:
        raise WebAuthnTransitionRequestError("transition context operation is not source fixed")
    shape._object(value, _CONTEXT_FIELDS, "transition planning request context")
    shape._literal(value["schema"], CONTEXT_SCHEMA)
    shape._literal(value["sourceRevision"], authority.SOURCE_REVISION)
    shape._literal(value["operation"], operation)
    contract._request(value["request"], operation)
    contract._roots(value["businessBeforeRoots"], contract.BUSINESS_TABLES[operation])
    contract._roots(value["authorizationBeforeRoots"], contract.AUTHORIZATION_TABLES[operation])
    contract._heads(value["countedBeforeHeads"], contract._head_ids(operation, value["request"]["arguments"]))
    shape._digest(value["inputsDigest"])
    for name in ("nowEpochNs", "deadlineEpochNs"):
        shape._integer(value[name], minimum=1)
    if value["nowEpochNs"] >= value["deadlineEpochNs"]:
        raise WebAuthnTransitionRequestError("transition invocation deadline is not after its original time")
    invocation = value["invocation"]
    if operation == "webauthn.registration.finalize":
        shape._object(invocation, frozenset(), "registration planning invocation")
    elif operation == "webauthn.trust.stage":
        shape._object(invocation, frozenset({"capabilityId"}), "trust-stage planning invocation")
        shape._digest(invocation["capabilityId"])
    else:
        shape._object(invocation, frozenset({"committedStage"}), "trust-completion planning invocation")
        stage = invocation["committedStage"]
        fields = plan.proof.completion.completion._STAGE_FIELDS
        shape._object(stage, fields, "independently admitted committed stage")
        for name in fields - {"witnessSequence"}:
            shape._digest(stage[name])
        shape._integer(stage["witnessSequence"], minimum=1)


def _request_commitments(value, work):
    # This actual source worker owns and validates family arguments, typed
    # request/business intent, requestDigest and operationId without a cutoff.
    roots_contract._capture_request_on_work(request=value["request"],
        operation=value["operation"], work=work)


def _root_list(values, maximum, work):
    if type(values) not in (list, tuple) or not 0 <= len(values) <= maximum:
        raise WebAuthnTransitionRequestError("transition roots are not a bounded source inventory")
    if type(values) is tuple:
        work.prepare_copy(values)
        return list(values)
    return values


def _read_control(raw, work):
    inputs_wire.wire._raw(raw, 2, MAX_CONTROL_BYTES)
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
    """Reserve the actual canonical output before genuine paired signing."""
    ledger = evidence.capture._SharedLedger(work)
    if (not isinstance(private_key, plan.Ed25519PrivateKey)
            or not isinstance(public_key, plan.Ed25519PublicKey)):
        raise WebAuthnTransitionRequestError("transition request signer is not Ed25519")
    plan.contract.shape._integer(detached_size, MAX_REQUEST_BYTES, minimum=4)
    _shape(unsigned, signed=False)
    owned = evidence.capture._JSONCapture(ledger, maximum_bytes=MAX_CONTROL_BYTES).visit(unsigned)
    envelope = {**owned, "signatureBase64Url": "A" * 86}
    _shape(envelope)
    unsigned_size, unsigned_nodes = work.measure(owned)
    envelope_size, envelope_nodes = work.measure(envelope)
    if (max(unsigned_size, envelope_size) > MAX_CONTROL_BYTES
            or max(unsigned_nodes, envelope_nodes) > MAX_CONTROL_NODES
            or detached_size + envelope_size > MAX_REQUEST_BYTES):
        raise WebAuthnTransitionRequestError("signed transition request exceeds its bounded output")
    work.charge(input_bytes=4 * unsigned_size + envelope_size + evidence.production._SIGNATURE_TRANSPORT_BYTES,
        json_nodes=2 * unsigned_nodes + envelope_nodes)
    frame_bytes = 2 * len(SCHEMA) + 9 + unsigned_size + 2 * 71
    if (work.limits.max_hashes - work.hash_work < 1
            or work.limits.max_input_bytes - work.input_bytes < frame_bytes + unsigned_size
            or work.limits.max_json_nodes - work.json_nodes < 4 + unsigned_nodes):
        raise WebAuthnTransitionRequestError("transition request cannot reserve its signature output")
    original = evidence.plan.core.canonical_bytes(owned)
    if len(original) != unsigned_size:
        raise WebAuthnTransitionRequestError("transition request unsigned size changed after measurement")
    message = evidence.plan._ascii(evidence.plan._frame(SCHEMA, (original,), work), work)
    signature = evidence.production._sign_and_verify(private_key, public_key, message, work)
    if work.measure(owned) != (unsigned_size, unsigned_nodes):
        raise WebAuthnTransitionRequestError("transition control changed during signing")
    if evidence.plan.core.canonical_bytes(owned) != original:
        raise WebAuthnTransitionRequestError("transition unsigned bytes changed during signing")
    encoded = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
    plan.contract.shape._base64url(encoded, signature=True)
    result = evidence.plan.core.canonical_bytes({**owned, "signatureBase64Url": encoded})
    if len(result) != envelope_size:
        raise WebAuthnTransitionRequestError("transition signed output changed after measurement")
    return result


def _produce_on_work(*, request, business_before_roots, authorization_before_roots,
        counted_before_heads, inputs_bytes, now_epoch_ns, deadline_epoch_ns, invocation,
        pins, generation_sequence, generation_digest, verifier_private_key,
        verifier_public_key, maximum_control_age_ns, work):
    ledger = evidence.capture._SharedLedger(work)
    pins = admission._validate_pins(pins)
    inputs_wire.wire._raw(inputs_bytes, 2, MAX_INPUT_BYTES)
    original_inputs = inputs_bytes
    scope = _pins(pins[5], generation_sequence, generation_digest, pins[0])
    private_key, public_key = verifier_private_key, verifier_public_key
    if (not isinstance(private_key, plan.Ed25519PrivateKey)
            or not isinstance(public_key, plan.Ed25519PublicKey)):
        raise WebAuthnTransitionRequestError("transition request requires actual verifier Ed25519 keys")
    plan.contract.shape._integer(maximum_control_age_ns, authority.VERIFIER_RESPONSE_MAX_AGE_NS, minimum=1)
    contract = plan.proof.contract
    document = {"schema": CONTEXT_SCHEMA, "sourceRevision": authority.SOURCE_REVISION,
        "operation": scope[3], "request": request,
        "businessBeforeRoots": _root_list(business_before_roots, len(contract.BUSINESS_TABLES[scope[3]]), work),
        "authorizationBeforeRoots": _root_list(authorization_before_roots,
            len(contract.AUTHORIZATION_TABLES[scope[3]]), work),
        "countedBeforeHeads": _root_list(counted_before_heads, roots_contract.heads.MAX_HEADS, work),
        "inputsDigest": None,
        "nowEpochNs": now_epoch_ns, "deadlineEpochNs": deadline_epoch_ns, "invocation": invocation}
    owned = evidence.capture._JSONCapture(ledger, maximum_bytes=MAX_CONTEXT_BYTES).visit(document)
    # Detach every caller graph before even hashing the immutable originals;
    # the temporary null never leaves this local construction or passes shape.
    owned["inputsDigest"] = inputs_wire._digest_on_work(original_inputs, work)
    _context_shape(owned, scope[3])
    _request_commitments(owned, work)
    original_now, deadline, skew = owned["nowEpochNs"], owned["deadlineEpochNs"], pins[6][1]
    context_bytes = evidence.capability._wire(owned, ledger, MAX_CONTEXT_BYTES, MAX_CONTEXT_NODES)
    if len(context_bytes) + len(original_inputs) + 2 > MAX_REQUEST_BYTES:
        raise WebAuthnTransitionRequestError("transition detached originals exceed their aggregate bound")
    context_digest = retention._bytes_digest(context_bytes, work)
    inputs_digest = retention._bytes_digest(original_inputs, work)
    # No mutable caller graph is consulted after the first actual key callback.
    evidence.keys._public_binding(pins[1], pins[3], work)
    evidence.keys._public_binding(pins[4], pins[6][4], work)
    wire._distinct_keys(pins[1], public_key, work)
    evidence.keys._pair_on_work(private_key, public_key, work)
    window = clock._open_on_work(deadline_epoch_ns=deadline,
        maximum_lifetime_ns=maximum_control_age_ns, maximum_clock_skew_ns=skew, work=work)
    issued, expires = window[0], clock._deadline_epoch_ns(window)
    if abs(original_now - issued) > skew:
        raise WebAuthnTransitionRequestError("original transition time differs from the actual request window")
    timing = {"issuedAtEpochNs": issued, "expiresAtEpochNs": expires}
    unsigned = {"schema": SCHEMA, "sourceRevision": authority.SOURCE_REVISION,
        "purpose": PURPOSE, "configurationDigest": scope[0], "generationSequence": scope[1],
        "generationDigest": scope[2], "operation": scope[3],
        "contextBytesDigest": context_digest, "contextByteCount": len(context_bytes),
        "inputsBytesDigest": inputs_digest, "inputsByteCount": len(original_inputs),
        "issuedAtEpochNs": issued, "expiresAtEpochNs": expires}
    wire._fresh_on_work(timing, window=window, maximum_age_ns=maximum_control_age_ns,
        maximum_clock_skew_ns=skew, work=work)
    control = _sign_control(unsigned, private_key=private_key, public_key=public_key,
        detached_size=len(context_bytes) + len(original_inputs), work=work)
    wire._fresh_on_work(timing, window=window, maximum_age_ns=maximum_control_age_ns,
        maximum_clock_skew_ns=skew, work=work)
    _raw3(control, context_bytes, original_inputs)
    return _ProducedPlanRequest(control, context_bytes, original_inputs)


def _verify_on_work(*, control_bytes, context_bytes, inputs_bytes, pins,
        generation_sequence, generation_digest, verifier_public_key, maximum_control_age_ns, work):
    ledger = evidence.capture._SharedLedger(work)
    original, original_context, original_inputs = _raw3(control_bytes, context_bytes, inputs_bytes)
    pins = admission._validate_pins(pins)
    scope = _pins(pins[5], generation_sequence, generation_digest, pins[0])
    public_key, skew = verifier_public_key, pins[6][1]
    if not isinstance(public_key, plan.Ed25519PublicKey):
        raise WebAuthnTransitionRequestError("transition request verifier is not Ed25519")
    plan.contract.shape._integer(maximum_control_age_ns, authority.VERIFIER_RESPONSE_MAX_AGE_NS, minimum=1)
    value, signature, unsigned_wire = _read_control(original, work)
    issued, expires = value["issuedAtEpochNs"], value["expiresAtEpochNs"]
    body_commitment = (value["contextBytesDigest"], value["contextByteCount"],
        value["inputsBytesDigest"], value["inputsByteCount"])
    timing = {"issuedAtEpochNs": issued, "expiresAtEpochNs": expires}
    evidence.capability._signature(public_key, signature, SCHEMA, unsigned_wire, ledger)
    evidence.capability._canonical(original, value, ledger, MAX_CONTROL_BYTES, MAX_CONTROL_NODES)
    evidence.plan._same((value["configurationDigest"], value["generationSequence"],
            value["generationDigest"], value["operation"]), scope, work,
        "transition control differs from independent configuration, generation or operation")
    wire._distinct_keys(pins[1], public_key, work)
    window = wire._open_control_window_on_work(timing, maximum_age_ns=maximum_control_age_ns,
        maximum_clock_skew_ns=skew, work=work)
    evidence.plan._same((retention._bytes_digest(original_context, work), len(original_context),
            retention._bytes_digest(original_inputs, work), len(original_inputs)), body_commitment, work,
        "transition control differs from its complete original-byte commitments")
    # Authenticate both originals before decoding any request/root/invocation
    # graph. The decoded context is not independent history or proof authority.
    decoded = evidence.wire._decode_object(original_context, work=work,
        maximum_bytes=MAX_CONTEXT_BYTES, maximum_nodes=MAX_CONTEXT_NODES, maximum_depth=MAX_CONTEXT_DEPTH)
    owned = evidence.capture._JSONCapture(ledger, maximum_bytes=MAX_CONTEXT_BYTES).visit(decoded)
    _context_shape(owned, scope[3])
    evidence.capability._canonical(original_context, owned, ledger, MAX_CONTEXT_BYTES, MAX_CONTEXT_NODES)
    evidence.plan._same(inputs_wire._digest_on_work(original_inputs, work), owned["inputsDigest"], work,
        "transition request differs from its original input identity")
    _request_commitments(owned, work)
    if expires > owned["deadlineEpochNs"] or abs(owned["nowEpochNs"] - issued) > skew:
        raise WebAuthnTransitionRequestError("transition request window differs from its original invocation times")
    evidence.keys._public_binding(pins[1], pins[3], work)
    evidence.keys._public_binding(pins[4], pins[6][4], work)
    wire._fresh_on_work(timing, window=window, maximum_age_ns=maximum_control_age_ns,
        maximum_clock_skew_ns=skew, work=work)
    evidence.capability._canonical(original_context, owned, ledger, MAX_CONTEXT_BYTES, MAX_CONTEXT_NODES)
    return _VerifiedPlanRequest(owned, issued, expires, window)
