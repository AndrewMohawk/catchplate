"""Canonical token-free committed-release proof originals in one fixed domain.

Wire parsing is not committed-consumption admission or release permission.
Actual production must admit originals and independent scope; the receiver
must authenticate the original proof and its enrolled, separated producer key.
No nonce, one-use claim, plaintext or tokenReleased flag is accepted.
"""
from __future__ import annotations

import base64

from catchplate import oidc_session_activation_release_custody_bootstrap as bootstrap
from catchplate import oidc_session_activation_release_proof_enrollment as enrollments
from catchplate.authority_query_read_work import QueryReadWorkError


authorization, plan, shape = bootstrap.authorization, bootstrap.plan, bootstrap.shape
clock, production, capture = bootstrap.clock, bootstrap.production, bootstrap.capture
delivery, authority, capability = bootstrap.delivery, bootstrap.authority, bootstrap.capability
keys = bootstrap.planner_bootstrap.keys
PURPOSE = "prove-oidc-session-activation-committed-release"
SCHEMA = "catchplate.signedOidcSessionActivationReleaseProof/v1"
PAYLOAD_SCHEMA = "catchplate.oidcSessionActivationReleaseProof/v1"
SIGNATURE_DOMAIN = SCHEMA
IDENTITY_DOMAIN = "catchplate.oidcSessionActivationReleaseProofIdentity/v1"
CUSTODY_IDENTITY_DOMAIN = "catchplate.oidcSessionActivationReleaseProofCustodyIdentity/v1"
MAX_BYTES = 64 * 1024
MAX_NODES, MAX_DEPTH = 256, 4
_ENVELOPE_FIELDS = frozenset({"schema", "payload", "signatureBase64Url"})
SCOPE_FIELDS = enrollments.SCOPE_FIELDS
RELEASE_FIELDS = frozenset({"activationRequestDigest", "activationOperationId",
    "consumeRequestDigest", "deliveryEnvelopeDigest", "deliveryScope", "consumeBinding"})
CONSUME_BINDING_FIELDS = frozenset({"packetDigest", "pendingDecisionDigest",
    "completionRequestDigest", "effectsDigest", "afterVectorDigest"})
PAYLOAD_FIELDS = SCOPE_FIELDS | RELEASE_FIELDS | frozenset({"schema", "sourceRevision",
    "purpose", "enrollmentDigest", "producerMeasurementDigest", "releaseCustodyDigest",
    "releaseIntentDigest", "stateReceiptDigest", "issuedAtEpochNs", "expiresAtEpochNs"})
_DIGEST_FIELDS = ("enrollmentDigest", "producerMeasurementDigest", "activationRequestDigest",
    "activationOperationId", "consumeRequestDigest", "deliveryEnvelopeDigest",
    "releaseCustodyDigest", "releaseIntentDigest", "stateReceiptDigest")


class OidcSessionActivationReleaseProofError(ValueError):
    pass


def _fail(message):
    raise OidcSessionActivationReleaseProofError(message)


class _Capture(capture._JSONCapture):
    def visit(self, value, depth=0, ancestors=frozenset()):
        if depth > MAX_DEPTH or self.nodes >= MAX_NODES:
            _fail("release proof exceeds its fixed structure bounds")
        result = super().visit(value, depth, ancestors)
        if self.nodes > MAX_NODES:
            _fail("release proof exceeds its fixed node bound")
        return result


def _capture(value, work):
    return _Capture(capture._SharedLedger(work), maximum_bytes=MAX_BYTES).visit(value)


def _wire(value, work):
    return capability._wire(value, capture._SharedLedger(work), MAX_BYTES, MAX_NODES)


def _canonical(original, value, work):
    return capability._canonical(original, value, capture._SharedLedger(work), MAX_BYTES, MAX_NODES)


def _payload_shape(payload, work):
    shape._object(payload, PAYLOAD_FIELDS, "activation committed-release proof")
    for field, expected in (("schema", PAYLOAD_SCHEMA), ("sourceRevision", authority.SOURCE_REVISION),
            ("purpose", PURPOSE)):
        shape._literal(payload[field], expected)
    enrollments._scope_shape({name: payload[name] for name in SCOPE_FIELDS})
    for field in _DIGEST_FIELDS:
        shape._digest(payload[field])
    if payload["producerMeasurementDigest"] != payload["producerIdentity"]["measurementDigest"]:
        _fail("release proof measurement differs from its producer identity")
    binding = payload["consumeBinding"]
    shape._object(binding, CONSUME_BINDING_FIELDS, "release proof committed-consumption binding")
    for field in CONSUME_BINDING_FIELDS:
        shape._digest(binding[field])
    authorization._interval(payload, authority.VERIFIER_RESPONSE_MAX_AGE_NS)
    _created, delivery_expiry = bootstrap._scope(payload["deliveryScope"], work)
    if payload["expiresAtEpochNs"] > delivery_expiry:
        _fail("release proof extends the original delivery expiry")


def _envelope_shape(envelope, work):
    shape._object(envelope, _ENVELOPE_FIELDS, "signed activation committed-release proof")
    shape._literal(envelope["schema"], SCHEMA)
    shape._base64url(envelope["signatureBase64Url"], signature=True)
    _payload_shape(envelope["payload"], work)


def _read(original, work):
    """Own canonical bounded envelope data; this does not authenticate it."""
    raw = authorization._original(original, MAX_BYTES, "activation committed-release proof")
    decoded = capability.wire._decode_object(raw, work=work, maximum_bytes=MAX_BYTES,
        maximum_nodes=MAX_NODES, maximum_depth=MAX_DEPTH)
    owned = _capture(decoded, work)
    _envelope_shape(owned, work)
    _canonical(raw, owned, work)
    return owned


def _digest(original, work):
    """Identity of the exact canonical original, not signature or admission."""
    raw = authorization._original(original, MAX_BYTES, "activation committed-release proof")
    _read(raw, work)
    return plan._frame(IDENTITY_DOMAIN, (raw,), work)


def _signature(envelope, public_key, work):
    """Authenticate only this fixed signature domain, not enrollment or time."""
    public = public_key
    authorization._public(public)
    owned = _capture(envelope, work)
    _envelope_shape(owned, work)
    envelope_original = _wire(owned, work)
    unsigned = _wire(owned["payload"], work)
    capability._signature(public, owned["signatureBase64Url"], SIGNATURE_DOMAIN,
        unsigned, capture._SharedLedger(work))
    _canonical(envelope_original, _capture(envelope, work), work)
    _canonical(envelope_original, owned, work)


def _sign(payload, *, private_key, public_key, work):
    """Private proof-only signing primitive, never a payload-signing endpoint."""
    private, public = private_key, public_key
    authorization._private(private)
    authorization._public(public)
    owned = _capture(payload, work)
    _payload_shape(owned, work)
    keys._pair_on_work(private, public, work)
    envelope = {"schema": SCHEMA, "payload": owned, "signatureBase64Url": "A" * 86}
    unsigned_size, unsigned_nodes = work.measure(owned)
    envelope_size, envelope_nodes = work.measure(envelope)
    if max(unsigned_size, envelope_size) > MAX_BYTES or max(unsigned_nodes, envelope_nodes) > MAX_NODES:
        _fail("release proof signature exceeds its fixed output bounds")
    work.charge(input_bytes=4 * unsigned_size + envelope_size + production._SIGNATURE_TRANSPORT_BYTES,
        json_nodes=2 * unsigned_nodes + envelope_nodes)
    frame_bytes = 2 * len(SIGNATURE_DOMAIN) + 9 + unsigned_size + 2 * 71
    if (work.limits.max_hashes - work.hash_work < 1
            or work.limits.max_input_bytes - work.input_bytes < frame_bytes + unsigned_size
            or work.limits.max_json_nodes - work.json_nodes < 4 + unsigned_nodes):
        raise QueryReadWorkError("release proof cannot reserve its complete signature output")
    unsigned = plan.core.canonical_bytes(owned)
    if len(unsigned) != unsigned_size:
        _fail("release proof changed after measurement")
    message = plan._ascii(plan._frame(SIGNATURE_DOMAIN, (unsigned,), work), work)
    signature = production._sign_and_verify(private, public, message, work)
    if work.measure(owned) != (unsigned_size, unsigned_nodes) or plan.core.canonical_bytes(owned) != unsigned:
        _fail("release proof changed during signing")
    encoded = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
    shape._base64url(encoded, signature=True)
    original = plan.core.canonical_bytes({"schema": SCHEMA,
        "payload": owned, "signatureBase64Url": encoded})
    if len(original) != envelope_size:
        _fail("release proof output changed after reservation")
    checked = _read(original, work)
    plan._same(checked["payload"], owned, work, "release proof signed output payload differs")
    return original
