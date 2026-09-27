"""Closed consume-only grant bytes and private signing primitives.

Signature validity is not role enrollment, caller permission, currentness or
original-proof replay. The actual producer/receiver must join those originals
under its existing allowance before using these token-free commitments. This
module does not widen generic successor grants or expose a signing endpoint.
"""
from __future__ import annotations

import base64

from serverware import authority_current_root_authorization as authorization
from serverware import authority_oidc_session_activation_delivery_execution_bundle as bundle
from serverware import authority_oidc_session_activation_delivery_plan_contract as contract
from serverware.authority_query_read_work import QueryReadWorkError


authority, shape, capture, wire = (
    authorization.authority, authorization.shape, authorization.capture, authorization.wire)
plan, keys, production = authorization.plan, authorization.keys, authorization.production
OPERATION = contract.OPERATION
GRANT_SCHEMA = "serverware.signedOidcSessionActivationDeliveryExecutionGrant/v1"
GRANT_PAYLOAD_SCHEMA = "serverware.oidcSessionActivationDeliveryExecutionGrant/v1"
SIGNATURE_DOMAIN = "serverware.oidcSessionActivationDeliveryExecutionGrantSignature/v1"
GRANT_IDENTITY_DOMAIN = "serverware.oidcSessionActivationDeliveryExecutionGrantIdentity/v1"
IDENTITY_DOMAIN = GRANT_IDENTITY_DOMAIN
MAX_GRANT_BYTES = MAX_BYTES = 64 * 1024
MAX_ORIGINAL_BYTES = authority.MAX_RESULT_BYTES
MAX_NODES, MAX_DEPTH = 128, 4
FRAME_MAXIMA = (contract.MAX_BYTES, bundle.MAX_BYTES)
_FRAME_MINIMA = (2, bundle.OVERHEAD_BYTES + 2)
_ENVELOPE_FIELDS = frozenset({"schema", "payload", "signatureBase64Url"})
_FRAME_FIELDS = frozenset({"position", "bytesDigest", "byteCount"})
GRANT_FIELDS = frozenset({"schema", "sourceRevision", "grantEnrollmentDigest",
    "currentRootEnrollmentDigest", "configurationDigest", "databaseId", "generationDigest",
    "authorizerMeasurementDigest", "operation", "requestDigest", "operationId",
    "requestAuthorizationDigest", "journalDigest", "retainedRecordDigest", "planDigest",
    "beforeVectorDigest", "afterVectorDigest", "resultDigest", "originalFrames",
    "originalIssuedAtEpochNs", "originalExpiresAtEpochNs", "issuedAtEpochNs", "expiresAtEpochNs"})
_DIGEST_FIELDS = ("grantEnrollmentDigest", "currentRootEnrollmentDigest", "configurationDigest",
    "generationDigest", "authorizerMeasurementDigest", "requestDigest", "operationId",
    "requestAuthorizationDigest", "journalDigest", "retainedRecordDigest", "planDigest",
    "beforeVectorDigest", "afterVectorDigest", "resultDigest")


class DeliveryExecutionGrantError(ValueError):
    pass


def _fail(message):
    raise DeliveryExecutionGrantError(message)


class _Capture(capture._JSONCapture):
    def visit(self, value, depth=0, ancestors=frozenset()):
        if depth > MAX_DEPTH or self.nodes >= MAX_NODES:
            _fail("consume grant exceeds its fixed structure bounds")
        result = super().visit(value, depth, ancestors)
        if self.nodes > MAX_NODES:
            _fail("consume grant exceeds its fixed node bound")
        return result


def _shape(payload):
    shape._object(payload, GRANT_FIELDS, "consume execution grant")
    shape._literal(payload["schema"], GRANT_PAYLOAD_SCHEMA)
    shape._literal(payload["sourceRevision"], authority.SOURCE_REVISION)
    shape._literal(payload["operation"], OPERATION)
    for field in _DIGEST_FIELDS:
        shape._digest(payload[field])
    authorization._token(payload["databaseId"])
    for field in ("originalIssuedAtEpochNs", "originalExpiresAtEpochNs", "issuedAtEpochNs", "expiresAtEpochNs"):
        shape._integer(payload[field], minimum=1)
    original_issue, original_expiry = payload["originalIssuedAtEpochNs"], payload["originalExpiresAtEpochNs"]
    issued, expires = payload["issuedAtEpochNs"], payload["expiresAtEpochNs"]
    if not 0 < original_expiry - original_issue <= authority.VERIFIER_RESPONSE_MAX_AGE_NS:
        _fail("consume grant original interval exceeds its source plan lifetime")
    if issued != original_issue or not issued < expires <= original_expiry:
        _fail("consume grant renews or escapes its original plan interval")
    frames = payload["originalFrames"]
    if type(frames) is not list or len(frames) != 2:
        _fail("consume grant requires exactly the original plan and encrypted bundle")
    total = 0
    for position, frame in enumerate(frames):
        shape._object(frame, _FRAME_FIELDS, "consume grant original frame")
        shape._integer(frame["position"], 1)
        if frame["position"] != position:
            _fail("consume grant original frame order changed")
        shape._digest(frame["bytesDigest"])
        shape._integer(frame["byteCount"], FRAME_MAXIMA[position], minimum=_FRAME_MINIMA[position])
        total += frame["byteCount"]
    if total > MAX_ORIGINAL_BYTES:
        _fail("consume grant originals exceed the source aggregate bound")


def _read_on_work(raw, work):
    """Return owned canonical envelope data, without a signature/admission claim."""
    original = authorization._original(raw, MAX_GRANT_BYTES, "consume execution grant")
    value = wire._decode_object(original, work=work, maximum_bytes=MAX_GRANT_BYTES,
        maximum_nodes=MAX_NODES, maximum_depth=MAX_DEPTH)
    shape._object(value, _ENVELOPE_FIELDS, "signed consume execution grant")
    shape._literal(value["schema"], GRANT_SCHEMA)
    shape._base64url(value["signatureBase64Url"], signature=True)
    _shape(value["payload"])
    owned = _Capture(capture._SharedLedger(work), maximum_bytes=MAX_GRANT_BYTES).visit(value)
    authorization.capability._canonical(original, owned,
        capture._SharedLedger(work), MAX_GRANT_BYTES, MAX_NODES)
    return owned


def _verify_signature_on_work(raw, public_key, work):
    """Verify the fixed signature domain; return ordinary payload and identity."""
    original = authorization._original(raw, MAX_GRANT_BYTES, "consume execution grant")
    public = public_key
    authorization._public(public)
    envelope = _read_on_work(original, work)
    unsigned = authorization.capability._wire(envelope["payload"], capture._SharedLedger(work),
        MAX_GRANT_BYTES, MAX_NODES)
    authorization.capability._signature(public, envelope["signatureBase64Url"],
        SIGNATURE_DOMAIN, unsigned, capture._SharedLedger(work))
    authorization.capability._canonical(original, envelope,
        capture._SharedLedger(work), MAX_GRANT_BYTES, MAX_NODES)
    identity = plan._frame(GRANT_IDENTITY_DOMAIN, (original,), work)
    return envelope["payload"], identity


def _sign_on_work(payload, private_key, public_key, work):
    """Private fixed-domain primitive; no payload DTO establishes authority."""
    private, public = private_key, public_key
    authorization._private(private)
    authorization._public(public)
    owned = _Capture(capture._SharedLedger(work), maximum_bytes=MAX_GRANT_BYTES).visit(payload)
    _shape(owned)
    # Own the complete graph before any key or cryptographic callback.
    keys._pair_on_work(private, public, work)
    envelope = {"schema": GRANT_SCHEMA, "payload": owned, "signatureBase64Url": "A" * 86}
    unsigned_size, unsigned_nodes = work.measure(owned)
    envelope_size, envelope_nodes = work.measure(envelope)
    if max(unsigned_size, envelope_size) > MAX_GRANT_BYTES or max(unsigned_nodes, envelope_nodes) > MAX_NODES:
        _fail("consume grant signature exceeds its fixed output bounds")
    work.charge(input_bytes=4 * unsigned_size + envelope_size + production._SIGNATURE_TRANSPORT_BYTES,
        json_nodes=2 * unsigned_nodes + envelope_nodes)
    frame_bytes = 2 * len(SIGNATURE_DOMAIN) + 9 + unsigned_size + 2 * 71
    if (work.limits.max_hashes - work.hash_work < 1
            or work.limits.max_input_bytes - work.input_bytes < frame_bytes + unsigned_size
            or work.limits.max_json_nodes - work.json_nodes < 4 + unsigned_nodes):
        raise QueryReadWorkError("consume grant cannot reserve its complete signature output")
    unsigned = plan.core.canonical_bytes(owned)
    if len(unsigned) != unsigned_size:
        _fail("consume grant changed after measurement")
    message = plan._ascii(plan._frame(SIGNATURE_DOMAIN, (unsigned,), work), work)
    signature = production._sign_and_verify(private, public, message, work)
    if work.measure(owned) != (unsigned_size, unsigned_nodes) or plan.core.canonical_bytes(owned) != unsigned:
        _fail("consume grant changed during signing")
    encoded = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
    shape._base64url(encoded, signature=True)
    result = plan.core.canonical_bytes({"schema": GRANT_SCHEMA,
        "payload": owned, "signatureBase64Url": encoded})
    if len(result) != envelope_size:
        _fail("consume grant output changed after reservation")
    checked = _read_on_work(result, work)
    plan._same(checked["payload"], owned, work, "consume grant signed output payload differs")
    return result
