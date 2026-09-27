"""Canonical private release-intent originals, not consumption or release proof.

The fixed signature domain binds ordinary token-free claims. Enrollment,
fresh caller permission, independently expected scope and actual committed
consumption belong to their original-admitting consumers. No registry operation,
key delivery, plaintext opening or successful authority carrier is exposed here.
"""
from __future__ import annotations

import base64

from serverware import oidc_session_activation_release_custody_bootstrap as bootstrap
from serverware.authority_query_read_work import QueryReadWorkError


authorization, plan, shape = bootstrap.authorization, bootstrap.plan, bootstrap.shape
clock, production, capture = bootstrap.clock, bootstrap.production, bootstrap.capture
delivery, authority, capability = bootstrap.delivery, bootstrap.authority, bootstrap.capability
keys = bootstrap.planner_bootstrap.keys
PURPOSE = "authorize-oidc-session-activation-token-release"
SCHEMA = "serverware.signedOidcSessionActivationReleaseIntent/v1"
PAYLOAD_SCHEMA = "serverware.oidcSessionActivationReleaseIntent/v1"
SIGNATURE_DOMAIN = SCHEMA
IDENTITY_DOMAIN = "serverware.oidcSessionActivationReleaseIntentIdentity/v1"
MAX_BYTES = 64 * 1024
MAX_NODES, MAX_DEPTH = 256, 4
NONCE_BYTES = 32
_ENVELOPE_FIELDS = frozenset({"schema", "payload", "signatureBase64Url"})
PAYLOAD_FIELDS = frozenset({"schema", "sourceRevision", "purpose", "enrollmentDigest",
    "callerId", "callerMeasurementDigest", "receiverIdentity", "configurationDigest",
    "databaseId", "generationDigest", "runtimeClosureDigest", "activationRequestDigest",
    "activationOperationId", "consumeRequestDigest", "deliveryEnvelopeDigest", "deliveryScope",
    "consumeBinding", "intentNonce", "issuedAtEpochNs", "expiresAtEpochNs"})
CONSUME_BINDING_FIELDS = frozenset({"packetDigest", "pendingDecisionDigest",
    "completionRequestDigest", "effectsDigest", "afterVectorDigest"})
_DIGEST_FIELDS = ("enrollmentDigest", "callerMeasurementDigest", "configurationDigest",
    "generationDigest", "runtimeClosureDigest", "activationRequestDigest", "activationOperationId",
    "consumeRequestDigest", "deliveryEnvelopeDigest")


class OidcSessionActivationReleaseIntentError(ValueError):
    pass


def _fail(message):
    raise OidcSessionActivationReleaseIntentError(message)


class _Capture(capture._JSONCapture):
    def visit(self, value, depth=0, ancestors=frozenset()):
        if depth > MAX_DEPTH or self.nodes >= MAX_NODES:
            _fail("release intent exceeds its fixed structure bounds")
        result = super().visit(value, depth, ancestors)
        if self.nodes > MAX_NODES:
            _fail("release intent exceeds its fixed node bound")
        return result


def _capture(value, work):
    return _Capture(capture._SharedLedger(work), maximum_bytes=MAX_BYTES).visit(value)


def _wire(value, work):
    return capability._wire(value, capture._SharedLedger(work), MAX_BYTES, MAX_NODES)


def _canonical(original, value, work):
    return capability._canonical(original, value, capture._SharedLedger(work), MAX_BYTES, MAX_NODES)


def _payload_shape(payload, work):
    shape._object(payload, PAYLOAD_FIELDS, "activation token-release intent")
    for field, expected in (("schema", PAYLOAD_SCHEMA), ("sourceRevision", authority.SOURCE_REVISION),
            ("purpose", PURPOSE)):
        shape._literal(payload[field], expected)
    for field in _DIGEST_FIELDS:
        shape._digest(payload[field])
    for field in ("callerId", "databaseId"):
        authorization._token(payload[field])
    shape.validate_identity_shape(payload["receiverIdentity"])
    binding = payload["consumeBinding"]
    shape._object(binding, CONSUME_BINDING_FIELDS, "release intent committed-consumption binding")
    for field in CONSUME_BINDING_FIELDS:
        shape._digest(binding[field])
    # Exactly 43 canonical unpadded characters encode exactly 32 bytes. The
    # wire checks this grammar; only the actual producer generates the nonce.
    shape._text(payload["intentNonce"], 43, minimum=43)
    shape._base64url(payload["intentNonce"])
    if payload["intentNonce"] == "A" * 43:
        _fail("release intent nonce is zero")
    authorization._interval(payload, authority.VERIFIER_RESPONSE_MAX_AGE_NS)
    _created, delivery_expiry = bootstrap._scope(payload["deliveryScope"], work)
    if payload["expiresAtEpochNs"] > delivery_expiry:
        _fail("release intent extends the original delivery expiry")


def _envelope_shape(envelope, work):
    shape._object(envelope, _ENVELOPE_FIELDS, "signed activation token-release intent")
    shape._literal(envelope["schema"], SCHEMA)
    shape._base64url(envelope["signatureBase64Url"], signature=True)
    _payload_shape(envelope["payload"], work)


def _read(original, work):
    """Own canonical bounded envelope data; this does not authenticate it."""
    raw = authorization._original(original, MAX_BYTES, "activation token-release intent")
    decoded = capability.wire._decode_object(raw, work=work, maximum_bytes=MAX_BYTES,
        maximum_nodes=MAX_NODES, maximum_depth=MAX_DEPTH)
    owned = _capture(decoded, work)
    _envelope_shape(owned, work)
    _canonical(raw, owned, work)
    return owned


def _digest(original, work):
    """Identity of the exact canonical original, not a signature/admission claim."""
    raw = authorization._original(original, MAX_BYTES, "activation token-release intent")
    _read(raw, work)
    return plan._frame(IDENTITY_DOMAIN, (raw,), work)


def _signature(envelope, public_key, work):
    """Verify the one fixed intent domain; no enrollment or freshness admission."""
    public = public_key
    authorization._public(public)
    owned = _capture(envelope, work)
    _envelope_shape(owned, work)
    envelope_original = _wire(owned, work)
    unsigned = _wire(owned["payload"], work)
    capability._signature(public, owned["signatureBase64Url"], SIGNATURE_DOMAIN,
        unsigned, capture._SharedLedger(work))
    # A key callback cannot turn a checked envelope into different caller data.
    _canonical(envelope_original, _capture(envelope, work), work)
    _canonical(envelope_original, owned, work)


def _sign(payload, *, private_key, public_key, work):
    """Private intent-only signing primitive, never a payload-signing endpoint."""
    private, public = private_key, public_key
    authorization._private(private)
    authorization._public(public)
    owned = _capture(payload, work)
    _payload_shape(owned, work)
    # Capture all ordinary input before any external key callback.
    keys._pair_on_work(private, public, work)
    envelope = {"schema": SCHEMA, "payload": owned, "signatureBase64Url": "A" * 86}
    unsigned_size, unsigned_nodes = work.measure(owned)
    envelope_size, envelope_nodes = work.measure(envelope)
    if max(unsigned_size, envelope_size) > MAX_BYTES or max(unsigned_nodes, envelope_nodes) > MAX_NODES:
        _fail("release intent signature exceeds its fixed output bounds")
    work.charge(input_bytes=4 * unsigned_size + envelope_size + production._SIGNATURE_TRANSPORT_BYTES,
        json_nodes=2 * unsigned_nodes + envelope_nodes)
    frame_bytes = 2 * len(SIGNATURE_DOMAIN) + 9 + unsigned_size + 2 * 71
    if (work.limits.max_hashes - work.hash_work < 1
            or work.limits.max_input_bytes - work.input_bytes < frame_bytes + unsigned_size
            or work.limits.max_json_nodes - work.json_nodes < 4 + unsigned_nodes):
        raise QueryReadWorkError("release intent cannot reserve its complete signature output")
    unsigned = plan.core.canonical_bytes(owned)
    if len(unsigned) != unsigned_size:
        _fail("release intent changed after measurement")
    message = plan._ascii(plan._frame(SIGNATURE_DOMAIN, (unsigned,), work), work)
    signature = production._sign_and_verify(private, public, message, work)
    if work.measure(owned) != (unsigned_size, unsigned_nodes) or plan.core.canonical_bytes(owned) != unsigned:
        _fail("release intent changed during signing")
    encoded = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
    shape._base64url(encoded, signature=True)
    original = plan.core.canonical_bytes({"schema": SCHEMA,
        "payload": owned, "signatureBase64Url": encoded})
    if len(original) != envelope_size:
        _fail("release intent output changed after reservation")
    checked = _read(original, work)
    plan._same(checked["payload"], owned, work, "release intent signed output payload differs")
    return original
