"""Separate original-byte latest-head observations for fixed planning purposes.

The unsigned query binds a caller-generated fresh unpredictable nonce, context
and expected complete-vector identity. Only the real locked decision owner
derives the signed state. This protocol returns no receipt or lookup status,
and does not turn a pending state into permission to plan, execute or retry.

Verification authenticates the enrolled local owner's observation at the
independently supplied instant. It does not prove off-host antirollback,
future freshness, SQL effects or execution authority. The returned dict is
ordinary data, not a reusable admission capability. The separate historical
entrypoint uses real clocks only for its supplied current processing window
and future-issue rejection; it never calls live verification at an old issue
time. No I/O, random generation, new allowance or mutation is performed here.
The default profile remains activation-only. A distinct delivery wrapper opts
into consume-specific schemas, operation and signature/query domains; older
activation and historical entrypoints do not infer that purpose from input.
"""
from __future__ import annotations

import base64
import time

from serverware import authority_current_root_authorization as authorization
from serverware import authority_webauthn_evidence_plan_clock as clock
from serverware.authority_query_read_work import QueryReadWorkError


OPERATION = "oidc.session.activate"
QUERY_SCHEMA = "serverware.policyAuthorityCurrentRootHeadQuery/v1"
QUERY_IDENTITY_DOMAIN = "serverware.policyAuthorityCurrentRootHeadQueryIdentity/v1"
OBSERVATION_SCHEMA = "serverware.signedPolicyAuthorityCurrentRootHeadObservation/v1"
PAYLOAD_SCHEMA = "serverware.policyAuthorityCurrentRootHeadObservation/v1"
MAX_QUERY_BYTES = 4 * 1024
MAX_QUERY_NODES = 32
MAX_QUERY_DEPTH = 2
MAX_BYTES = 8 * 1024
MAX_NODES = 128
MAX_DEPTH = 4
QUERY_FIELDS = frozenset({"schema", "sourceRevision", "enrollmentDigest", "operation",
    "challenge", "contextDigest", "expectedVectorDigest"})
PAYLOAD_FIELDS = frozenset({"schema", "sourceRevision", "enrollmentDigest", "databaseId",
    "generationDigest", "producerMeasurementDigest", "operation", "queryDigest", "challenge",
    "contextDigest", "issuedAtEpochNs", "expiresAtEpochNs", "sequence", "headDigest",
    "vectorDigest", "fence", "pendingRequestDigest", "pendingDecisionDigest"})
_ENVELOPE_FIELDS = frozenset({"schema", "payload", "signatureBase64Url"})
DELIVERY_OPERATION = "oidc.session.activation-delivery.consume"
_DELIVERY_PROFILE = (
    "serverware.policyAuthorityCurrentRootDeliveryHeadQuery/v1",
    "serverware.policyAuthorityCurrentRootDeliveryHeadQueryIdentity/v1",
    "serverware.signedPolicyAuthorityCurrentRootDeliveryHeadObservation/v1",
    "serverware.policyAuthorityCurrentRootDeliveryHeadObservation/v1",
)


def _profile(operation):
    # Callers select one source-fixed protocol, never a schema from the wire.
    # All existing entrypoints remain activation-only unless the separate
    # delivery wrapper explicitly selects its independently admitted purpose.
    if type(operation) is str and operation == OPERATION:
        return QUERY_SCHEMA, QUERY_IDENTITY_DOMAIN, OBSERVATION_SCHEMA, PAYLOAD_SCHEMA
    if type(operation) is str and operation == DELIVERY_OPERATION:
        return _DELIVERY_PROFILE
    raise CurrentRootHeadError("current-root head operation is not source fixed")


class CurrentRootHeadError(ValueError):
    pass


class _Capture(authorization.capture._JSONCapture):
    def visit(self, value, depth=0, ancestors=frozenset()):
        if depth > MAX_DEPTH or self.nodes >= MAX_NODES:
            raise CurrentRootHeadError("current-root head observation exceeds its structure bound")
        result = super().visit(value, depth, ancestors)
        if self.nodes > MAX_NODES:
            raise CurrentRootHeadError("current-root head observation exceeds its node bound")
        return result


def _challenge(value):
    if (type(value) is not str or len(value) != 64
            or any(character not in "0123456789abcdef" for character in value)):
        raise CurrentRootHeadError("head challenge must encode exactly 32 bytes as lower-case hex")


def _query_shape(value, *, operation=OPERATION):
    query_schema = _profile(operation)[0]
    authorization.shape._object(value, QUERY_FIELDS, "current-root head query")
    authorization.shape._literal(value["schema"], query_schema)
    authorization.shape._literal(value["sourceRevision"], authorization.authority.SOURCE_REVISION)
    authorization.shape._literal(value["operation"], operation)
    for name in ("enrollmentDigest", "contextDigest", "expectedVectorDigest"):
        authorization.shape._digest(value[name])
    _challenge(value["challenge"])


def _encode_query_on_work(*, enrollment_digest, context_digest, expected_vector_digest, challenge, work,
        operation=OPERATION):
    """Encode exact scalar originals; fresh randomness is the caller's duty."""
    query_schema = _profile(operation)[0]
    document = {"schema": query_schema, "sourceRevision": authorization.authority.SOURCE_REVISION,
        "enrollmentDigest": enrollment_digest, "operation": operation, "challenge": challenge,
        "contextDigest": context_digest, "expectedVectorDigest": expected_vector_digest}
    _query_shape(document, operation=operation)
    return authorization.capability._wire(document, authorization.capture._SharedLedger(work),
        MAX_QUERY_BYTES, MAX_QUERY_NODES)


def _decode_query_on_work(raw, *, work, operation=OPERATION):
    original = authorization._original(raw, MAX_QUERY_BYTES, "current-root head query")
    document = authorization.wire._decode_object(original, work=work,
        maximum_bytes=MAX_QUERY_BYTES, maximum_nodes=MAX_QUERY_NODES, maximum_depth=MAX_QUERY_DEPTH)
    _query_shape(document, operation=operation)
    authorization.capability._canonical(original, document,
        authorization.capture._SharedLedger(work), MAX_QUERY_BYTES, MAX_QUERY_NODES)
    return document


def _query_digest_on_work(raw, work, *, operation=OPERATION):
    original = authorization._original(raw, MAX_QUERY_BYTES, "current-root head query")
    _decode_query_on_work(original, work=work, operation=operation)
    return authorization.plan._frame(_profile(operation)[1], (original,), work)


def _payload_shape(payload, *, operation=OPERATION):
    authorization.shape._object(payload, PAYLOAD_FIELDS, "current-root head observation")
    authorization._source(payload, _profile(operation)[3])
    authorization.shape._literal(payload["operation"], operation)
    for name in ("enrollmentDigest", "producerMeasurementDigest", "queryDigest", "contextDigest",
            "headDigest", "vectorDigest"):
        authorization.shape._digest(payload[name])
    _challenge(payload["challenge"])
    authorization._interval(payload, authorization.authority.VERIFIER_RESPONSE_MAX_AGE_NS)
    sequence, fence = payload["sequence"], payload["fence"]
    authorization.shape._integer(sequence, authorization.MAX_RECORDS)
    authorization.shape._integer(fence, authorization.MAX_RECORDS)
    if fence > sequence or sequence > 0 and fence == 0:
        raise CurrentRootHeadError("observed head sequence/fence are inconsistent")
    pending_request, pending_decision = payload["pendingRequestDigest"], payload["pendingDecisionDigest"]
    if pending_request is None:
        if pending_decision is not None:
            raise CurrentRootHeadError("head pending identities must both be null or both present")
    else:
        authorization.shape._digest(pending_request)
        authorization.shape._digest(pending_decision)
        if sequence == 0 or fence == 0 or pending_decision != payload["headDigest"]:
            raise CurrentRootHeadError("observed pending decision is not the positive current head")
    if sequence == 0 and (fence != 0 or pending_request is not None
            or payload["headDigest"] != payload["enrollmentDigest"]):
        raise CurrentRootHeadError("observed genesis differs from its enrollment and empty pending state")


def _envelope_shape(envelope, *, operation=OPERATION):
    authorization.shape._object(envelope, _ENVELOPE_FIELDS, "signed current-root head observation")
    authorization.shape._literal(envelope["schema"], _profile(operation)[2])
    authorization.shape._base64url(envelope["signatureBase64Url"], signature=True)
    _payload_shape(envelope["payload"], operation=operation)


def _read_observation(original, work, *, operation=OPERATION):
    envelope = authorization.wire._decode_object(original, work=work,
        maximum_bytes=MAX_BYTES, maximum_nodes=MAX_NODES, maximum_depth=MAX_DEPTH)
    _envelope_shape(envelope, operation=operation)
    owned = _Capture(authorization.capture._SharedLedger(work), maximum_bytes=MAX_BYTES).visit(envelope)
    authorization.capability._canonical(original, owned,
        authorization.capture._SharedLedger(work), MAX_BYTES, MAX_NODES)
    return owned


def _original_scope(payload, material, work):
    authorization._scope(payload, material, "state", work)
    if payload["sequence"] > material.payload["maxRecords"]:
        raise CurrentRootHeadError("observed head sequence exceeds original enrolled capacity")
    if payload["sequence"] == 0:
        raw = authorization.vector._encode_on_work(material.payload["initialVector"], work=work)
        digest = authorization.vector._digest_on_work(raw, work=work)
        authorization.plan._same(payload["vectorDigest"], digest, work,
            "observed genesis vector differs from its actual enrolled original")


def _scope(payload, material, now_epoch_ns, work):
    _original_scope(payload, material, work)
    authorization._fresh(payload, material, now_epoch_ns)


def _verify_on_work(*, observation_bytes, query_bytes, enrollment_bytes,
        root_public_key, now_epoch_ns, work, operation=OPERATION):
    """Authenticate originals; pending rejection and live continuity are caller duties."""
    original = authorization._original(observation_bytes, MAX_BYTES, "current-root head observation")
    original_query = authorization._original(query_bytes, MAX_QUERY_BYTES, "current-root head query")
    original_enrollment = authorization._original(enrollment_bytes,
        authorization.MAX_ENROLLMENT_BYTES, "current-root enrollment")
    held_key, held_now = root_public_key, now_epoch_ns
    authorization._public(held_key)
    authorization.shape._integer(held_now, minimum=1)
    # Capture both graphs and all scalar/original inputs before key callbacks.
    profile = _profile(operation)
    query = _decode_query_on_work(original_query, work=work, operation=operation)
    envelope = _read_observation(original, work, operation=operation)
    material = authorization._admit_enrollment_on_work(enrollment_bytes=original_enrollment,
        root_public_key=held_key, work=work)
    payload = envelope["payload"]
    _scope(payload, material, held_now, work)
    authorization._verify_signature(envelope, profile[2],
        material.state_public_key, MAX_BYTES, work)
    authorization.plan._same(query["enrollmentDigest"], material.enrollment_digest, work,
        "head query original enrollment")
    query_digest = authorization.plan._frame(profile[1], (original_query,), work)
    for name, expected in (("queryDigest", query_digest), ("challenge", query["challenge"]),
            ("contextDigest", query["contextDigest"]), ("vectorDigest", query["expectedVectorDigest"]),
            ("operation", query["operation"])):
        authorization.plan._same(payload[name], expected, work, "head observation original query " + name)
    authorization.capability._canonical(original, envelope,
        authorization.capture._SharedLedger(work), MAX_BYTES, MAX_NODES)
    authorization._fresh(payload, material, held_now)
    return payload


def _verify_historical_with_enrollment_on_work(*, observation_bytes, query_bytes,
        enrollment_bytes, root_public_key, live_window, transport_deadline_ns, work):
    """Private same-call original facts, never accepted as another API's proof.

    Enrollment and observation intervals are checked algebraically, while
    future issuance and processing liveness use the actual current clock.
    Expiry of the observation does not renew it or constrain this new, already
    supplied processing window. No caller clock or successful carrier enters.
    """
    authorization.capture._SharedLedger(work)
    original = authorization._original(observation_bytes, MAX_BYTES, "historical current-root head observation")
    original_query = authorization._original(query_bytes, MAX_QUERY_BYTES, "historical current-root head query")
    original_enrollment = authorization._original(enrollment_bytes,
        authorization.MAX_ENROLLMENT_BYTES, "historical current-root enrollment")
    held_key = root_public_key
    authorization._public(held_key)
    window = clock._validate(live_window)
    authorization.shape._integer(transport_deadline_ns, minimum=1)
    bound = min(window[4], transport_deadline_ns)
    # Own both original graphs before key or clock callbacks; all later
    # comparisons refer only to these captured immutable-original inputs.
    query = _decode_query_on_work(original_query, work=work)
    envelope = _read_observation(original, work)
    last_epoch, last_monotonic = window[0], window[2]

    def current():
        nonlocal last_epoch, last_monotonic
        now = clock._check_on_work(window, work=work)
        monotonic = authorization.production._callback(work, time.monotonic_ns)
        authorization.shape._integer(monotonic, minimum=1)
        if now < last_epoch or monotonic < last_monotonic or monotonic >= bound:
            raise CurrentRootHeadError("historical head processing expired or its clocks reversed")
        last_epoch, last_monotonic = now, monotonic
        return now

    current()
    material = authorization._admit_enrollment_on_work(enrollment_bytes=original_enrollment,
        root_public_key=held_key, work=work)
    current()
    payload = envelope["payload"]
    # The same enrolled role, generation, positive bounded original interval,
    # capacity and true genesis checks as live admission, without _fresh().
    _original_scope(payload, material, work)
    authorization._verify_signature(envelope, OBSERVATION_SCHEMA,
        material.state_public_key, MAX_BYTES, work)
    if payload["issuedAtEpochNs"] > current() + material.payload["maxClockSkewNs"]:
        raise CurrentRootHeadError("historical head observation is issued in the current future")
    authorization.plan._same(query["enrollmentDigest"], material.enrollment_digest, work,
        "historical head query original enrollment")
    query_digest = authorization.plan._frame(QUERY_IDENTITY_DOMAIN, (original_query,), work)
    for name, expected in (("queryDigest", query_digest), ("challenge", query["challenge"]),
            ("contextDigest", query["contextDigest"]), ("vectorDigest", query["expectedVectorDigest"]),
            ("operation", query["operation"])):
        authorization.plan._same(payload[name], expected, work,
            "historical head observation original query " + name)
    authorization.capability._canonical(original, envelope,
        authorization.capture._SharedLedger(work), MAX_BYTES, MAX_NODES)
    if payload["issuedAtEpochNs"] > current() + material.payload["maxClockSkewNs"]:
        raise CurrentRootHeadError("historical head observation future issue changed at return")
    return payload, material


def _verify_historical_on_work(*, observation_bytes, query_bytes, enrollment_bytes,
        root_public_key, live_window, transport_deadline_ns, work):
    """Authenticate original history only; return ordinary observation data."""
    payload, _material = _verify_historical_with_enrollment_on_work(observation_bytes=observation_bytes,
        query_bytes=query_bytes, enrollment_bytes=enrollment_bytes, root_public_key=root_public_key,
        live_window=live_window, transport_deadline_ns=transport_deadline_ns, work=work)
    return payload


def _sign_on_work(*, payload, enrollment_bytes, root_public_key,
        state_private_key, now_epoch_ns, work, operation=OPERATION):
    """Sign the actual owner's held state; never derive or admit posted state."""
    original_enrollment = authorization._original(enrollment_bytes,
        authorization.MAX_ENROLLMENT_BYTES, "current-root enrollment")
    held_root, held_private, held_now = root_public_key, state_private_key, now_epoch_ns
    authorization._public(held_root)
    authorization._private(held_private)
    authorization.shape._integer(held_now, minimum=1)
    observation_schema = _profile(operation)[2]
    _payload_shape(payload, operation=operation)
    owned = _Capture(authorization.capture._SharedLedger(work), maximum_bytes=MAX_BYTES).visit(payload)
    material = authorization._admit_enrollment_on_work(enrollment_bytes=original_enrollment,
        root_public_key=held_root, work=work)
    _scope(owned, material, held_now, work)
    public_key = material.state_public_key
    authorization.keys._pair_on_work(held_private, public_key, work)
    envelope = {"schema": observation_schema, "payload": owned, "signatureBase64Url": "A" * 86}
    _envelope_shape(envelope, operation=operation)
    unsigned_size, unsigned_nodes = work.measure(owned)
    envelope_size, envelope_nodes = work.measure(envelope)
    if max(unsigned_size, envelope_size) > MAX_BYTES or max(unsigned_nodes, envelope_nodes) > MAX_NODES:
        raise CurrentRootHeadError("current-root head observation exceeds its signed output bound")
    work.charge(input_bytes=4 * unsigned_size + envelope_size
        + authorization.production._SIGNATURE_TRANSPORT_BYTES,
        json_nodes=2 * unsigned_nodes + envelope_nodes)
    frame_bytes = 2 * len(observation_schema) + 9 + unsigned_size + 2 * 71
    if (work.limits.max_hashes - work.hash_work < 1
            or work.limits.max_input_bytes - work.input_bytes < frame_bytes + unsigned_size
            or work.limits.max_json_nodes - work.json_nodes < 4 + unsigned_nodes):
        raise QueryReadWorkError("current-root head cannot reserve its complete signature output")
    unsigned = authorization.plan.core.canonical_bytes(owned)
    if len(unsigned) != unsigned_size:
        raise CurrentRootHeadError("current-root head observation changed after measurement")
    message = authorization.plan._ascii(authorization.plan._frame(observation_schema, (unsigned,), work), work)
    signature = authorization.production._sign_and_verify(held_private, public_key, message, work)
    if (work.measure(owned) != (unsigned_size, unsigned_nodes)
            or authorization.plan.core.canonical_bytes(owned) != unsigned):
        raise CurrentRootHeadError("current-root head observation changed during signing")
    encoded = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
    authorization.shape._base64url(encoded, signature=True)
    result = authorization.plan.core.canonical_bytes({"schema": observation_schema,
        "payload": owned, "signatureBase64Url": encoded})
    if len(result) != envelope_size:
        raise CurrentRootHeadError("current-root signed head observation changed after measurement")
    authorization._fresh(owned, material, held_now)
    return result
