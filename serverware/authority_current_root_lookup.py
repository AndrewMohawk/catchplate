"""Bounded nonce-bound current-root lookup and signed state observations.

The unsigned query is a locator, not mutation authority. Its caller must use
a fresh unpredictable 32-byte nonce, encoded as exactly 64 lower-case hex
characters. Signature verification joins the exact original query, challenge,
root enrollment and state key at an independently supplied current instant.

Only the actual state owner derives a producer payload under its existing
lock from admitted state/history. This private signing primitive supplies no
independent latest-head, journal durability or caller-selected state admission.
An accepted receipt retains its original interval; it is not renewed by the
fresh observation. The delivery owner must still authenticate/join that
receipt to its original complete request and independent pending checkpoint.
Not-recorded is a signed observation, never permission to retry, abort, reset,
release a reservation or claim that a database write did not happen.

All graphs/originals are held before callbacks on the supplied work. No clock,
I/O, new allowance, mutation, nonce generation or successful authority token
is provided here.
"""
from __future__ import annotations

import base64
import hashlib

from serverware import authority_current_root_authorization as authorization
from serverware.authority_query_read_work import QueryReadWorkError


QUERY_SCHEMA = "serverware.policyAuthorityCurrentRootLookup/v1"
QUERY_IDENTITY_DOMAIN = "serverware.policyAuthorityCurrentRootLookupIdentity/v1"
OBSERVATION_SCHEMA = "serverware.signedPolicyAuthorityCurrentRootStateObservation/v1"
PAYLOAD_SCHEMA = "serverware.policyAuthorityCurrentRootStateObservation/v1"
MAX_QUERY_BYTES = 4 * 1024
MAX_QUERY_NODES = 64
MAX_QUERY_DEPTH = 2
MAX_BYTES = 32 * 1024
MAX_NODES = 256
MAX_DEPTH = 4
# Same original receipt ceiling as CurrentRootDecisionOwner and its transport.
# Do not import the owner here: it imports this fixed lookup protocol.
MAX_RECEIPT_BYTES = 16 * 1024
QUERY_FIELDS = frozenset({"schema", "sourceRevision", "enrollmentDigest", "requestDigest", "challenge"})
PAYLOAD_FIELDS = frozenset({"schema", "sourceRevision", "enrollmentDigest", "databaseId",
    "generationDigest", "producerMeasurementDigest", "queryDigest", "challenge",
    "requestedRequestDigest", "issuedAtEpochNs", "expiresAtEpochNs", "sequence",
    "headDigest", "vectorDigest", "fence", "pendingRequestDigest", "pendingDecisionDigest",
    "requestStatus", "receiptBase64Url", "receiptByteCount", "receiptBytesDigest"})
_ENVELOPE_FIELDS = frozenset({"schema", "payload", "signatureBase64Url"})


class CurrentRootLookupError(ValueError):
    pass


class _Capture(authorization.capture._JSONCapture):
    def visit(self, value, depth=0, ancestors=frozenset()):
        if depth > MAX_DEPTH or self.nodes >= MAX_NODES:
            raise CurrentRootLookupError("current-root lookup exceeds its structure bound")
        result = super().visit(value, depth, ancestors)
        if self.nodes > MAX_NODES:
            raise CurrentRootLookupError("current-root lookup exceeds its node bound")
        return result


def _challenge(value):
    if (type(value) is not str or len(value) != 64
            or any(character not in "0123456789abcdef" for character in value)):
        raise CurrentRootLookupError("lookup challenge must encode exactly 32 nonce bytes as lower-case hex")


def _query_shape(value):
    authorization.shape._object(value, QUERY_FIELDS, "current-root lookup query")
    authorization.shape._literal(value["schema"], QUERY_SCHEMA)
    authorization.shape._literal(value["sourceRevision"], authorization.authority.SOURCE_REVISION)
    authorization.shape._digest(value["enrollmentDigest"])
    authorization.shape._digest(value["requestDigest"])
    _challenge(value["challenge"])


def _encode_query_on_work(*, enrollment_digest, request_digest, challenge, work):
    """Encode held scalar selectors; nonce unpredictability is the caller's duty."""
    document = {"schema": QUERY_SCHEMA, "sourceRevision": authorization.authority.SOURCE_REVISION,
        "enrollmentDigest": enrollment_digest, "requestDigest": request_digest, "challenge": challenge}
    _query_shape(document)
    return authorization.capability._wire(document, authorization.capture._SharedLedger(work),
        MAX_QUERY_BYTES, MAX_QUERY_NODES)


def _decode_query_on_work(query_bytes, *, work):
    original = authorization._original(query_bytes, MAX_QUERY_BYTES, "current-root lookup query")
    document = authorization.wire._decode_object(original, work=work,
        maximum_bytes=MAX_QUERY_BYTES, maximum_nodes=MAX_QUERY_NODES, maximum_depth=MAX_QUERY_DEPTH)
    _query_shape(document)
    authorization.capability._canonical(original, document,
        authorization.capture._SharedLedger(work), MAX_QUERY_BYTES, MAX_QUERY_NODES)
    return document


def _query_digest_on_work(query_bytes, work):
    """Identity of canonical unsigned query originals, not query authority."""
    original = authorization._original(query_bytes, MAX_QUERY_BYTES, "current-root lookup query")
    _decode_query_on_work(original, work=work)
    return authorization.plan._frame(QUERY_IDENTITY_DOMAIN, (original,), work)


def _payload_shape(payload):
    authorization.shape._object(payload, PAYLOAD_FIELDS, "current-root state observation")
    authorization._source(payload, PAYLOAD_SCHEMA)
    for name in ("enrollmentDigest", "producerMeasurementDigest", "queryDigest",
            "requestedRequestDigest", "headDigest", "vectorDigest"):
        authorization.shape._digest(payload[name])
    _challenge(payload["challenge"])
    authorization._interval(payload, authorization.authority.VERIFIER_RESPONSE_MAX_AGE_NS)
    sequence, fence = payload["sequence"], payload["fence"]
    authorization.shape._integer(sequence, authorization.MAX_RECORDS)
    authorization.shape._integer(fence, authorization.MAX_RECORDS)
    if fence > sequence or sequence > 0 and fence == 0:
        raise CurrentRootLookupError("observed state sequence/fence are inconsistent")
    pending_request, pending_decision = payload["pendingRequestDigest"], payload["pendingDecisionDigest"]
    if pending_request is None:
        if pending_decision is not None:
            raise CurrentRootLookupError("observed pending identities must both be null or both present")
    else:
        authorization.shape._digest(pending_request)
        authorization.shape._digest(pending_decision)
        if sequence == 0 or fence == 0 or pending_decision != payload["headDigest"]:
            raise CurrentRootLookupError("observed pending decision is not the positive current head")
    if sequence == 0 and (fence != 0 or pending_request is not None
            or payload["headDigest"] != payload["enrollmentDigest"]):
        raise CurrentRootLookupError("observed genesis differs from its enrolled head and empty pending state")
    status = payload["requestStatus"]
    if type(status) is not str or status not in ("accepted", "notRecorded"):
        raise CurrentRootLookupError("lookup request status is not source fixed")
    if status == "accepted":
        authorization.transport._transport_shape(payload["receiptBase64Url"],
            payload["receiptByteCount"], MAX_RECEIPT_BYTES)
        authorization.shape._digest(payload["receiptBytesDigest"])
    elif (payload["receiptBase64Url"] is not None or type(payload["receiptByteCount"]) is not int
            or payload["receiptByteCount"] != 0 or payload["receiptBytesDigest"] is not None):
        raise CurrentRootLookupError("not-recorded observation must not contain receipt material")


def _envelope_shape(envelope):
    authorization.shape._object(envelope, _ENVELOPE_FIELDS, "signed current-root observation")
    authorization.shape._literal(envelope["schema"], OBSERVATION_SCHEMA)
    authorization.shape._base64url(envelope["signatureBase64Url"], signature=True)
    _payload_shape(envelope["payload"])


def _read_observation(original, work):
    envelope = authorization.wire._decode_object(original, work=work,
        maximum_bytes=MAX_BYTES, maximum_nodes=MAX_NODES, maximum_depth=MAX_DEPTH)
    _envelope_shape(envelope)
    owned = _Capture(authorization.capture._SharedLedger(work), maximum_bytes=MAX_BYTES).visit(envelope)
    authorization.capability._canonical(original, owned,
        authorization.capture._SharedLedger(work), MAX_BYTES, MAX_NODES)
    return owned


def _scope(payload, material, now_epoch_ns, work):
    authorization._scope(payload, material, "state", work)
    if payload["sequence"] > material.payload["maxRecords"]:
        raise CurrentRootLookupError("observed sequence exceeds the original enrolled record limit")
    authorization._fresh(payload, material, now_epoch_ns)


def _receipt_on_work(payload, material, work):
    """Join retained signed receipt without renewing its original interval."""
    if payload["requestStatus"] == "notRecorded":
        return None
    raw = authorization.transport._decode(payload["receiptBase64Url"],
        payload["receiptByteCount"], MAX_RECEIPT_BYTES, work)
    work.charge(hashes=1, input_bytes=len(raw))
    actual = "sha256:" + hashlib.sha256(raw).hexdigest()
    authorization.plan._same(actual, payload["receiptBytesDigest"], work,
        "observed original receipt raw SHA256")
    envelope = authorization._read(raw, authorization.RECEIPT_SCHEMA, MAX_RECEIPT_BYTES, work)
    receipt = envelope["payload"]
    authorization._scope(receipt, material, "state", work)
    authorization._verify_signature(envelope, authorization.RECEIPT_SCHEMA,
        material.state_public_key, MAX_RECEIPT_BYTES, work)
    authorization._unchanged(raw, envelope, MAX_RECEIPT_BYTES, work)
    authorization.plan._same(receipt["requestDigest"], payload["requestedRequestDigest"], work,
        "observed receipt requested original identity")
    if receipt["sequence"] > payload["sequence"]:
        raise CurrentRootLookupError("observed receipt is ahead of the asserted state sequence")
    if receipt["sequence"] == payload["sequence"]:
        identity = authorization.plan._frame(authorization.RECEIPT_IDENTITY_DOMAIN, (raw,), work)
        authorization.plan._same(identity, payload["headDigest"], work,
            "observed same-sequence original receipt head")
    return raw


def _verify_on_work(*, observation_bytes, query_bytes, enrollment_bytes,
        root_public_key, now_epoch_ns, work):
    """Authenticate exact originals against independent enrollment/current time."""
    original = authorization._original(observation_bytes, MAX_BYTES, "current-root observation")
    original_query = authorization._original(query_bytes, MAX_QUERY_BYTES, "current-root lookup query")
    original_enrollment = authorization._original(enrollment_bytes,
        authorization.MAX_ENROLLMENT_BYTES, "current-root enrollment")
    held_key, held_now = root_public_key, now_epoch_ns
    authorization._public(held_key)
    authorization.shape._integer(held_now, minimum=1)
    # Both received graphs are closed and detached before root/key callbacks.
    query = _decode_query_on_work(original_query, work=work)
    envelope = _read_observation(original, work)
    material = authorization._admit_enrollment_on_work(enrollment_bytes=original_enrollment,
        root_public_key=held_key, work=work)
    payload = envelope["payload"]
    _scope(payload, material, held_now, work)
    authorization._verify_signature(envelope, OBSERVATION_SCHEMA,
        material.state_public_key, MAX_BYTES, work)
    authorization.plan._same(query["enrollmentDigest"], material.enrollment_digest, work,
        "lookup query original enrollment")
    query_digest = authorization.plan._frame(QUERY_IDENTITY_DOMAIN, (original_query,), work)
    for name, expected in (("queryDigest", query_digest), ("challenge", query["challenge"]),
            ("requestedRequestDigest", query["requestDigest"])):
        authorization.plan._same(payload[name], expected, work, "observation original query " + name)
    # Complete outer signature/scope/query commitments precede receipt decoding.
    receipt = _receipt_on_work(payload, material, work)
    authorization.capability._canonical(original, envelope,
        authorization.capture._SharedLedger(work), MAX_BYTES, MAX_NODES)
    authorization._fresh(payload, material, held_now)
    return payload, receipt


def _sign_on_work(*, payload, enrollment_bytes, root_public_key,
        state_private_key, now_epoch_ns, work):
    """Sign actual owner's same-call state; this function does not derive it."""
    original_enrollment = authorization._original(enrollment_bytes,
        authorization.MAX_ENROLLMENT_BYTES, "current-root enrollment")
    held_root, held_private, held_now = root_public_key, state_private_key, now_epoch_ns
    authorization._public(held_root)
    authorization._private(held_private)
    authorization.shape._integer(held_now, minimum=1)
    _payload_shape(payload)
    owned = _Capture(authorization.capture._SharedLedger(work), maximum_bytes=MAX_BYTES).visit(payload)
    material = authorization._admit_enrollment_on_work(enrollment_bytes=original_enrollment,
        root_public_key=held_root, work=work)
    _scope(owned, material, held_now, work)
    _receipt_on_work(owned, material, work)
    public_key = material.state_public_key
    authorization.keys._pair_on_work(held_private, public_key, work)
    envelope = {"schema": OBSERVATION_SCHEMA, "payload": owned, "signatureBase64Url": "A" * 86}
    _envelope_shape(envelope)
    unsigned_size, unsigned_nodes = work.measure(owned)
    envelope_size, envelope_nodes = work.measure(envelope)
    if max(unsigned_size, envelope_size) > MAX_BYTES or max(unsigned_nodes, envelope_nodes) > MAX_NODES:
        raise CurrentRootLookupError("current-root observation exceeds its signed output bound")
    work.charge(input_bytes=4 * unsigned_size + envelope_size
        + authorization.production._SIGNATURE_TRANSPORT_BYTES,
        json_nodes=2 * unsigned_nodes + envelope_nodes)
    frame_bytes = 2 * len(OBSERVATION_SCHEMA) + 9 + unsigned_size + 2 * 71
    if (work.limits.max_hashes - work.hash_work < 1
            or work.limits.max_input_bytes - work.input_bytes < frame_bytes + unsigned_size
            or work.limits.max_json_nodes - work.json_nodes < 4 + unsigned_nodes):
        raise QueryReadWorkError("current-root lookup cannot reserve its complete signature output")
    unsigned = authorization.plan.core.canonical_bytes(owned)
    if len(unsigned) != unsigned_size:
        raise CurrentRootLookupError("current-root observation changed after measurement")
    message = authorization.plan._ascii(authorization.plan._frame(OBSERVATION_SCHEMA, (unsigned,), work), work)
    signature = authorization.production._sign_and_verify(held_private, public_key, message, work)
    if (work.measure(owned) != (unsigned_size, unsigned_nodes)
            or authorization.plan.core.canonical_bytes(owned) != unsigned):
        raise CurrentRootLookupError("current-root observation changed during signing")
    encoded = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
    authorization.shape._base64url(encoded, signature=True)
    result = authorization.plan.core.canonical_bytes({"schema": OBSERVATION_SCHEMA,
        "payload": owned, "signatureBase64Url": encoded})
    if len(result) != envelope_size:
        raise CurrentRootLookupError("current-root signed observation changed after measurement")
    authorization._fresh(owned, material, held_now)
    return result
