"""Verifier-signed requests for fixed registration pre-signing source reads.

The exact detached context contains independently admitted selectors, the full
existing before-root inventory and the original deadline. It is not an evidence
envelope, business request, enrollment grant or proof of row/root provenance.
The actual reader and membership replay remain mandatory downstream.

All caller graphs are owned before native key/hash/clock callbacks. Dedicated
control framing, original-byte commitments and one bounded epoch/monotonic
window use the supplied work, with no replacement allowance or renewed expiry.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass

from serverware import authority_webauthn_evidence_custody_wire as wire
from serverware import authority_webauthn_evidence_plan_admission as admission


evidence, authority, retention, clock = wire.evidence, wire.authority, wire.retention, wire.clock
plan = retention.plan
OPERATION = "webauthn.registration.evidence.admit"
SCHEMA = "serverware.signedPolicyAuthorityWebAuthnRegistrationSourceRequest/v1"
CONTEXT_SCHEMA = "serverware.policyAuthorityWebAuthnRegistrationSourceRequestContext/v1"
PURPOSE = "read-registration-source"
MAX_CONTROL_BYTES = wire.MAX_CONTROL_BYTES
MAX_CONTROL_NODES = wire.MAX_CONTROL_NODES
MAX_CONTROL_DEPTH = wire.MAX_CONTROL_DEPTH
MAX_CONTEXT_BYTES = plan.contract.MAX_BYTES
MAX_CONTEXT_NODES = plan.contract.MAX_NODES
MAX_CONTEXT_DEPTH = plan.contract.MAX_DEPTH
MAX_REQUEST_BYTES = authority.MAX_RESULT_BYTES
_FIELDS = frozenset({"schema", "sourceRevision", "purpose", "configurationDigest",
    "generationSequence", "generationDigest", "operation", "contextBytesDigest",
    "contextByteCount", "issuedAtEpochNs", "expiresAtEpochNs", "signatureBase64Url"})
_CONTEXT_FIELDS = frozenset({"schema", "sourceRevision", "operation",
    "registrationChallengeId", "publishedPublicationId", "oidcSessionId",
    "businessBeforeRoots", "authorizationBeforeRoots", "deadlineEpochNs"})


class WebAuthnRegistrationSourceRequestError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class _ProducedSourceRequest:
    control_bytes: bytes
    context_bytes: bytes


@dataclass(frozen=True, slots=True)
class _VerifiedSourceRequest:
    """Authenticated request data and local timing, not source membership."""

    context: dict
    issued_at_epoch_ns: int
    expires_at_epoch_ns: int
    window: tuple


def _raw2(control_bytes, context_bytes):
    originals = control_bytes, context_bytes
    for raw, maximum in zip(originals, (MAX_CONTROL_BYTES, MAX_CONTEXT_BYTES)):
        if type(raw) is not bytes or not 2 <= len(raw) <= maximum:
            raise WebAuthnRegistrationSourceRequestError("source read requires bounded immutable originals")
    if sum(len(raw) for raw in originals) > MAX_REQUEST_BYTES:
        raise WebAuthnRegistrationSourceRequestError("source request exceeds its existing aggregate bound")
    return originals


def _scope(pins, generation_sequence, generation_digest):
    held = admission._validate_pins(pins)
    evidence.plan.contract._literal(held[0], OPERATION)
    return held, wire._pins(held[7], generation_sequence, generation_digest, OPERATION)


def _shape(value, *, signed=True):
    shape = evidence.plan.contract
    shape._object(value, _FIELDS if signed else _FIELDS - {"signatureBase64Url"},
        "registration source request control")
    shape._literal(value["schema"], SCHEMA)
    shape._literal(value["sourceRevision"], authority.SOURCE_REVISION)
    shape._literal(value["purpose"], PURPOSE)
    shape._literal(value["operation"], OPERATION)
    wire._pins(value["configurationDigest"], value["generationSequence"],
        value["generationDigest"], value["operation"])
    shape._digest(value["contextBytesDigest"])
    shape._integer(value["contextByteCount"], MAX_CONTEXT_BYTES, minimum=2)
    for name in ("issuedAtEpochNs", "expiresAtEpochNs"):
        shape._integer(value[name], minimum=1)
    if not 0 < value["expiresAtEpochNs"] - value["issuedAtEpochNs"] <= authority.VERIFIER_RESPONSE_MAX_AGE_NS:
        raise WebAuthnRegistrationSourceRequestError("source request lifetime exceeds its source bound")
    if signed:
        shape._base64url(value["signatureBase64Url"], signature=True)


def _context_shape(value, operation=OPERATION):
    shape = evidence.plan.contract
    shape._literal(operation, OPERATION)
    shape._object(value, _CONTEXT_FIELDS, "registration source request context")
    shape._literal(value["schema"], CONTEXT_SCHEMA)
    shape._literal(value["sourceRevision"], authority.SOURCE_REVISION)
    shape._literal(value["operation"], OPERATION)
    for name in ("registrationChallengeId", "publishedPublicationId"):
        shape._text(value[name], 4096)
    if value["oidcSessionId"] is not None:
        shape._text(value["oidcSessionId"], 4096)
    plan.contract._roots(value["businessBeforeRoots"], plan.contract._BUSINESS_TABLES[OPERATION])
    plan.contract._roots(value["authorizationBeforeRoots"], plan.contract._AUTHORIZATION_TABLES[OPERATION])
    shape._integer(value["deadlineEpochNs"], minimum=1)


def _root_list(values, tables, work):
    if type(values) not in (list, tuple) or len(values) != len(tables):
        raise WebAuthnRegistrationSourceRequestError("source request roots differ from the full source inventory")
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
    """Reserve exact output costs before the genuine guarded sign/paired verify."""
    ledger = evidence.capture._SharedLedger(work)
    if (not isinstance(private_key, plan.Ed25519PrivateKey)
            or not isinstance(public_key, plan.Ed25519PublicKey)):
        raise WebAuthnRegistrationSourceRequestError("source request signer is not Ed25519")
    evidence.plan.contract._integer(detached_size, MAX_REQUEST_BYTES, minimum=2)
    _shape(unsigned, signed=False)
    owned = evidence.capture._JSONCapture(ledger, maximum_bytes=MAX_CONTROL_BYTES).visit(unsigned)
    envelope = {**owned, "signatureBase64Url": "A" * 86}
    _shape(envelope)
    unsigned_size, unsigned_nodes = work.measure(owned)
    envelope_size, envelope_nodes = work.measure(envelope)
    if (max(unsigned_size, envelope_size) > MAX_CONTROL_BYTES
            or max(unsigned_nodes, envelope_nodes) > MAX_CONTROL_NODES
            or detached_size + envelope_size > MAX_REQUEST_BYTES):
        raise WebAuthnRegistrationSourceRequestError("signed source request exceeds its existing bounds")
    work.charge(input_bytes=4 * unsigned_size + envelope_size + evidence.production._SIGNATURE_TRANSPORT_BYTES,
        json_nodes=2 * unsigned_nodes + envelope_nodes)
    frame_bytes = 2 * len(SCHEMA) + 9 + unsigned_size + 2 * 71
    if (work.limits.max_hashes - work.hash_work < 1
            or work.limits.max_input_bytes - work.input_bytes < frame_bytes + unsigned_size
            or work.limits.max_json_nodes - work.json_nodes < 4 + unsigned_nodes):
        raise WebAuthnRegistrationSourceRequestError("source request cannot reserve its signature output")
    original = evidence.plan.core.canonical_bytes(owned)
    if len(original) != unsigned_size:
        raise WebAuthnRegistrationSourceRequestError("source request size changed after measurement")
    message = evidence.plan._ascii(evidence.plan._frame(SCHEMA, (original,), work), work)
    signature = evidence.production._sign_and_verify(private_key, public_key, message, work)
    if work.measure(owned) != (unsigned_size, unsigned_nodes):
        raise WebAuthnRegistrationSourceRequestError("source request graph changed during signing")
    if evidence.plan.core.canonical_bytes(owned) != original:
        raise WebAuthnRegistrationSourceRequestError("source request unsigned bytes changed during signing")
    encoded = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
    evidence.plan.contract._base64url(encoded, signature=True)
    result = evidence.plan.core.canonical_bytes({**owned, "signatureBase64Url": encoded})
    if len(result) != envelope_size:
        raise WebAuthnRegistrationSourceRequestError("source request output changed after measurement")
    return result


def _produce_on_work(*, registration_challenge_id, published_publication_id,
        oidc_session_id, business_before_roots, authorization_before_roots,
        deadline_epoch_ns, pins, generation_sequence, generation_digest,
        verifier_private_key, verifier_public_key, maximum_control_age_ns, work):
    ledger = evidence.capture._SharedLedger(work)
    pins, scope = _scope(pins, generation_sequence, generation_digest)
    private_key, public_key = verifier_private_key, verifier_public_key
    if (not isinstance(private_key, plan.Ed25519PrivateKey)
            or not isinstance(public_key, plan.Ed25519PublicKey)):
        raise WebAuthnRegistrationSourceRequestError("source request requires real verifier Ed25519 keys")
    evidence.plan.contract._integer(deadline_epoch_ns, minimum=1)
    evidence.plan.contract._integer(maximum_control_age_ns, authority.VERIFIER_RESPONSE_MAX_AGE_NS, minimum=1)
    # Detach all selectors/roots/deadline before canonical hashing, key work or
    # clocks; never reopen caller graphs after those callbacks.
    owned = evidence.capture._JSONCapture(ledger, maximum_bytes=MAX_CONTEXT_BYTES).visit({
        "schema": CONTEXT_SCHEMA, "sourceRevision": authority.SOURCE_REVISION, "operation": OPERATION,
        "registrationChallengeId": registration_challenge_id, "publishedPublicationId": published_publication_id,
        "oidcSessionId": oidc_session_id,
        "businessBeforeRoots": _root_list(business_before_roots, plan.contract._BUSINESS_TABLES[OPERATION], work),
        "authorizationBeforeRoots": _root_list(authorization_before_roots,
            plan.contract._AUTHORIZATION_TABLES[OPERATION], work),
        "deadlineEpochNs": deadline_epoch_ns})
    _context_shape(owned)
    deadline = owned["deadlineEpochNs"]
    context_bytes = evidence.capability._wire(owned, ledger, MAX_CONTEXT_BYTES, MAX_CONTEXT_NODES)
    if len(context_bytes) + 2 > MAX_REQUEST_BYTES:
        raise WebAuthnRegistrationSourceRequestError("source request context exceeds its aggregate bound")
    context_digest = retention._bytes_digest(context_bytes, work)
    evidence.keys._public_binding(pins[1], pins[3], work)
    wire._distinct_keys(pins[1], public_key, work)
    evidence.keys._pair_on_work(private_key, public_key, work)
    window = clock._open_on_work(deadline_epoch_ns=deadline,
        maximum_lifetime_ns=maximum_control_age_ns, maximum_clock_skew_ns=pins[9], work=work)
    issued, expires = window[0], clock._deadline_epoch_ns(window)
    timing = {"issuedAtEpochNs": issued, "expiresAtEpochNs": expires}
    unsigned = {"schema": SCHEMA, "sourceRevision": authority.SOURCE_REVISION,
        "purpose": PURPOSE, "configurationDigest": scope[0], "generationSequence": scope[1],
        "generationDigest": scope[2], "operation": OPERATION,
        "contextBytesDigest": context_digest, "contextByteCount": len(context_bytes),
        "issuedAtEpochNs": issued, "expiresAtEpochNs": expires}
    wire._fresh_on_work(timing, window=window, maximum_age_ns=maximum_control_age_ns,
        maximum_clock_skew_ns=pins[9], work=work)
    control = _sign_control(unsigned, private_key=private_key, public_key=public_key,
        detached_size=len(context_bytes), work=work)
    wire._fresh_on_work(timing, window=window, maximum_age_ns=maximum_control_age_ns,
        maximum_clock_skew_ns=pins[9], work=work)
    _raw2(control, context_bytes)
    return _ProducedSourceRequest(control, context_bytes)


def _verify_on_work(*, control_bytes, context_bytes, pins, generation_sequence,
        generation_digest, verifier_public_key, maximum_control_age_ns, work):
    ledger = evidence.capture._SharedLedger(work)
    original, original_context = _raw2(control_bytes, context_bytes)
    pins, scope = _scope(pins, generation_sequence, generation_digest)
    public_key = verifier_public_key
    if not isinstance(public_key, plan.Ed25519PublicKey):
        raise WebAuthnRegistrationSourceRequestError("source request verifier key is not Ed25519")
    evidence.plan.contract._integer(maximum_control_age_ns, authority.VERIFIER_RESPONSE_MAX_AGE_NS, minimum=1)
    value, signature, unsigned_wire = _read_control(original, work)
    issued, expires = value["issuedAtEpochNs"], value["expiresAtEpochNs"]
    body_commitment = value["contextBytesDigest"], value["contextByteCount"]
    timing = {"issuedAtEpochNs": issued, "expiresAtEpochNs": expires}
    evidence.capability._signature(public_key, signature, SCHEMA, unsigned_wire, ledger)
    evidence.capability._canonical(original, value, ledger, MAX_CONTROL_BYTES, MAX_CONTROL_NODES)
    evidence.plan._same((value["configurationDigest"], value["generationSequence"],
        value["generationDigest"], value["operation"]), scope, work,
        "source request differs from independent configuration/generation/operation")
    evidence.keys._public_binding(pins[1], pins[3], work)
    wire._distinct_keys(pins[1], public_key, work)
    window = wire._open_control_window_on_work(timing, maximum_age_ns=maximum_control_age_ns,
        maximum_clock_skew_ns=pins[9], work=work)
    evidence.plan._same((retention._bytes_digest(original_context, work), len(original_context)),
        body_commitment, work, "source request differs from its complete original context bytes")
    # The detached graph is decoded only after actual signature/scope/byte
    # authentication. Its root provenance is still an upstream precondition.
    decoded = evidence.wire._decode_object(original_context, work=work,
        maximum_bytes=MAX_CONTEXT_BYTES, maximum_nodes=MAX_CONTEXT_NODES, maximum_depth=MAX_CONTEXT_DEPTH)
    owned = evidence.capture._JSONCapture(ledger, maximum_bytes=MAX_CONTEXT_BYTES).visit(decoded)
    _context_shape(owned)
    evidence.capability._canonical(original_context, owned, ledger, MAX_CONTEXT_BYTES, MAX_CONTEXT_NODES)
    if expires > owned["deadlineEpochNs"]:
        raise WebAuthnRegistrationSourceRequestError("source request exceeds its admitted context deadline")
    wire._fresh_on_work(timing, window=window, maximum_age_ns=maximum_control_age_ns,
        maximum_clock_skew_ns=pins[9], work=work)
    evidence.capability._canonical(original_context, owned, ledger, MAX_CONTEXT_BYTES, MAX_CONTEXT_NODES)
    return _VerifiedSourceRequest(owned, issued, expires, window)
