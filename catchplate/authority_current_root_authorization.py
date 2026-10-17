"""Original-byte current-root enrollment, requests and state receipts.

The independently pinned root signs a database/generation enrollment and three
separate role keys. Computation and completion signatures are assertions by
those enrolled producers, not mutation proofs or hardware attestations. Full
reserve vectors undergo the actual source-vector and necessary delta checks.

Every verifier admits original enrollment bytes itself on the caller's work.
Returned dictionaries/material are ordinary data, never substitute authority.
Historical request verification authenticates the original interval without
sampling a clock, renewing it or claiming currentness. Receipt verification
does not establish publication: the durable owner must join exact request,
pending decision, ancestry and interval, and publish before acknowledging.

No I/O, clock, allowance, key provisioning, latest-head admission, expiration
release, abort, reset, generation rollover or execution is provided here.
"""
from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_public_key

from catchplate import authority_contract as authority
from catchplate import authority_current_root_delta as delta
from catchplate import authority_current_root_vector as vector
from catchplate import authority_request_commitment as commitment
from catchplate import authority_revocation_capability as capability
from catchplate import authority_revocation_capability_production as production
from catchplate import authority_revocation_invocation as transport
from catchplate import authority_revocation_writer_acknowledgment as keys
from catchplate.authority_query_read_work import QueryReadWorkError


plan, wire, capture, shape = capability.plan, capability.wire, capability.capture, capability.shape
ENROLLMENT_SCHEMA = "catchplate.signedPolicyAuthorityCurrentRootEnrollment/v1"
ENROLLMENT_PAYLOAD_SCHEMA = "catchplate.policyAuthorityCurrentRootEnrollment/v1"
REQUEST_SCHEMA = "catchplate.signedPolicyAuthorityCurrentRootRequest/v1"
REQUEST_PAYLOAD_SCHEMA = "catchplate.policyAuthorityCurrentRootRequest/v1"
RECEIPT_SCHEMA = "catchplate.signedPolicyAuthorityCurrentRootReceipt/v1"
RECEIPT_PAYLOAD_SCHEMA = "catchplate.policyAuthorityCurrentRootReceipt/v1"
ENROLLMENT_IDENTITY_DOMAIN = "catchplate.policyAuthorityCurrentRootEnrollmentIdentity/v1"
REQUEST_IDENTITY_DOMAIN = "catchplate.policyAuthorityCurrentRootRequestIdentity/v1"
RECEIPT_IDENTITY_DOMAIN = "catchplate.policyAuthorityCurrentRootReceiptIdentity/v1"
MAX_ENROLLMENT_BYTES = 128 * 1024
MAX_BYTES = 256 * 1024
MAX_WRITER_RECEIPT_BYTES = 64 * 1024
MAX_PEM_BYTES = 4096
MAX_NODES = 16384
MAX_DEPTH = 8
MAX_RECORDS = 1024
OPERATIONS = delta.OPERATIONS
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_ENVELOPE_FIELDS = frozenset({"schema", "payload", "signatureBase64Url"})
_ROLE_FIELDS = frozenset({"publicKeyPem", "spkiDigest", "measurementDigest"})
_ROLES = ("computation", "completion", "state")
ENROLLMENT_FIELDS = frozenset({"schema", "sourceRevision", "databaseId", "generationDigest",
    "initialVector", "computation", "completion", "state", "maxControlAgeNs",
    "maxClockSkewNs", "maxRecords"})
_REQUEST_COMMON = frozenset({"schema", "sourceRevision", "action", "enrollmentDigest",
    "databaseId", "generationDigest", "producerMeasurementDigest", "issuedAtEpochNs",
    "expiresAtEpochNs"})
RESERVE_FIELDS = _REQUEST_COMMON | frozenset({"operation", "requestDigest", "operationId",
    "capabilityDigest", "snapshotDigest", "predecessorSequence", "predecessorHeadDigest",
    "fence", "beforeVector", "afterVector"})
COMPLETE_FIELDS = _REQUEST_COMMON | frozenset({"operation", "pendingRequestDigest",
    "pendingDecisionDigest", "fence", "writerReceiptBase64Url", "writerReceiptBytesDigest",
    "writerReceiptByteCount", "snapshotDigest", "resultDigest", "beforeVectorDigest",
    "afterVectorDigest"})
RECEIPT_FIELDS = frozenset({"schema", "sourceRevision", "action", "enrollmentDigest",
    "databaseId", "generationDigest", "producerMeasurementDigest", "requestDigest",
    "sequence", "previousHeadDigest", "fence", "beforeVectorDigest", "afterVectorDigest",
    "pendingRequestDigest", "issuedAtEpochNs", "expiresAtEpochNs"})


class CurrentRootAuthorizationError(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _EnrollmentMaterial:
    """Same-call owned observations; no verifier accepts this as an input."""

    enrollment_bytes: bytes
    payload: dict
    enrollment_digest: str
    computation_public_key: object
    completion_public_key: object
    state_public_key: object


class _Capture(capture._JSONCapture):
    def visit(self, value, depth=0, ancestors=frozenset()):
        if depth > MAX_DEPTH or self.nodes >= MAX_NODES:
            raise CurrentRootAuthorizationError("current-root document exceeds its structure bound")
        result = super().visit(value, depth, ancestors)
        if self.nodes > MAX_NODES:
            raise CurrentRootAuthorizationError("current-root document exceeds its node bound")
        return result


def _token(value):
    if type(value) is not str or not 1 <= len(value) <= 128 or _TOKEN.fullmatch(value) is None:
        raise CurrentRootAuthorizationError("current-root database identity is not a bounded ASCII token")


def _original(raw, maximum, label):
    if type(raw) is not bytes or not 2 <= len(raw) <= maximum:
        raise CurrentRootAuthorizationError(label + " requires bounded original bytes")
    return raw


def _public(key):
    if not isinstance(key, Ed25519PublicKey):
        raise CurrentRootAuthorizationError("current-root verification requires an actual Ed25519 key")


def _private(key):
    if not isinstance(key, Ed25519PrivateKey):
        raise CurrentRootAuthorizationError("current-root signing requires an actual Ed25519 key")


def _source(value, expected_schema):
    shape._literal(value["schema"], expected_schema)
    shape._literal(value["sourceRevision"], authority.SOURCE_REVISION)
    _token(value["databaseId"])
    shape._digest(value["generationDigest"])


def _interval(value, maximum):
    issued, expires = value["issuedAtEpochNs"], value["expiresAtEpochNs"]
    shape._integer(issued, minimum=1)
    shape._integer(expires, minimum=1)
    if not 0 < expires - issued <= maximum:
        raise CurrentRootAuthorizationError("current-root original control interval exceeds its enrolled age")


def _enrollment_shape(value):
    shape._object(value, ENROLLMENT_FIELDS, "current-root enrollment")
    _source(value, ENROLLMENT_PAYLOAD_SCHEMA)
    shape._integer(value["maxControlAgeNs"], authority.VERIFIER_RESPONSE_MAX_AGE_NS, minimum=1)
    shape._integer(value["maxClockSkewNs"], authority.VERIFIER_MAX_CLOCK_SKEW_NS)
    # A reservation always leaves capacity for its completion record.
    shape._integer(value["maxRecords"], MAX_RECORDS, minimum=2)
    vector._shape(value["initialVector"])
    for role in _ROLES:
        record = value[role]
        shape._object(record, _ROLE_FIELDS, "current-root role")
        pem = record["publicKeyPem"]
        if type(pem) is not str or not 1 <= len(pem) <= MAX_PEM_BYTES or not pem.isascii() or "\x00" in pem:
            raise CurrentRootAuthorizationError("current-root role PEM is not bounded ASCII")
        shape._digest(record["spkiDigest"])
        shape._digest(record["measurementDigest"])
    if len({value[role]["spkiDigest"] for role in _ROLES}) != len(_ROLES):
        raise CurrentRootAuthorizationError("current-root producer and state keys must be separate")


def _action(value):
    if type(value) is not str or value not in ("reserve", "complete"):
        raise CurrentRootAuthorizationError("current-root action is not reserve or complete")
    return value


def _request_shape(value):
    if type(value) is not dict or not 1 <= len(value) <= len(COMPLETE_FIELDS):
        raise CurrentRootAuthorizationError("current-root request is not a bounded object")
    action = _action(value.get("action"))
    shape._object(value, RESERVE_FIELDS if action == "reserve" else COMPLETE_FIELDS,
        "current-root request")
    _source(value, REQUEST_PAYLOAD_SCHEMA)
    for name in ("enrollmentDigest", "producerMeasurementDigest", "snapshotDigest"):
        shape._digest(value[name])
    _interval(value, authority.VERIFIER_RESPONSE_MAX_AGE_NS)
    shape._integer(value["fence"], minimum=1)
    delta._source(value["operation"])
    if action == "reserve":
        for name in ("requestDigest", "operationId", "capabilityDigest", "predecessorHeadDigest"):
            shape._digest(value[name])
        shape._integer(value["predecessorSequence"])
        vector._shape(value["beforeVector"])
        vector._shape(value["afterVector"])
    else:
        for name in ("pendingRequestDigest", "pendingDecisionDigest", "writerReceiptBytesDigest",
                "resultDigest", "beforeVectorDigest", "afterVectorDigest"):
            shape._digest(value[name])
        transport._transport_shape(value["writerReceiptBase64Url"],
            value["writerReceiptByteCount"], MAX_WRITER_RECEIPT_BYTES)


def _receipt_shape(value):
    shape._object(value, RECEIPT_FIELDS, "current-root receipt")
    _source(value, RECEIPT_PAYLOAD_SCHEMA)
    action = _action(value["action"])
    for name in ("enrollmentDigest", "producerMeasurementDigest", "requestDigest",
            "previousHeadDigest", "beforeVectorDigest", "afterVectorDigest", "pendingRequestDigest"):
        shape._digest(value[name])
    for name in ("sequence", "fence"):
        shape._integer(value[name], minimum=1)
    _interval(value, authority.VERIFIER_RESPONSE_MAX_AGE_NS)
    if action == "reserve" and value["pendingRequestDigest"] != value["requestDigest"]:
        raise CurrentRootAuthorizationError("reserve receipt pending identity differs from its original request")


def _payload_shape(payload, schema):
    if schema == ENROLLMENT_SCHEMA:
        _enrollment_shape(payload)
    elif schema == REQUEST_SCHEMA:
        _request_shape(payload)
    elif schema == RECEIPT_SCHEMA:
        _receipt_shape(payload)
    else:
        raise CurrentRootAuthorizationError("current-root envelope schema is not source-selected")


def _envelope_shape(value, schema):
    shape._object(value, _ENVELOPE_FIELDS, "current-root signed envelope")
    shape._literal(value["schema"], schema)
    shape._base64url(value["signatureBase64Url"], signature=True)
    _payload_shape(value["payload"], schema)


def _capture_payload(payload, schema, maximum, work):
    ledger = capture._SharedLedger(work)
    _payload_shape(payload, schema)
    return _Capture(ledger, maximum_bytes=maximum).visit(payload)


def _read(raw, schema, maximum, work):
    _original(raw, maximum, "current-root envelope")
    decoded = wire._decode_object(raw, work=work, maximum_bytes=maximum,
        maximum_nodes=MAX_NODES, maximum_depth=MAX_DEPTH)
    _envelope_shape(decoded, schema)
    ledger = capture._SharedLedger(work)
    owned = _Capture(ledger, maximum_bytes=maximum).visit(decoded)
    capability._canonical(raw, owned, ledger, maximum, MAX_NODES)
    return owned


def _unchanged(raw, envelope, maximum, work):
    capability._canonical(raw, envelope, capture._SharedLedger(work), maximum, MAX_NODES)


def _verify_signature(envelope, schema, public_key, maximum, work):
    _public(public_key)
    ledger = capture._SharedLedger(work)
    unsigned = capability._wire(envelope["payload"], ledger, maximum, MAX_NODES)
    try:
        capability._signature(public_key, envelope["signatureBase64Url"], schema, unsigned, ledger)
    except InvalidSignature as exc:
        raise CurrentRootAuthorizationError("current-root original signature is invalid") from exc


def _role_key(record, work):
    pem = record["publicKeyPem"]
    size = work.prepare_utf8(pem)
    # The exact already-owned ASCII PEM is the sole parser input.
    raw = pem.encode("ascii")
    if len(raw) != size:
        raise CurrentRootAuthorizationError("current-root role PEM changed after measurement")
    public_key = production._callback(work, lambda: load_pem_public_key(raw))
    _public(public_key)
    actual = keys._spki_on_work(public_key, work)
    plan._same(actual, record["spkiDigest"], work, "current-root role SPKI")
    # Reject alternate PEM spellings after actual Ed25519 parsing/binding.
    work.charge(input_bytes=MAX_PEM_BYTES)
    canonical = production._callback(work,
        lambda: public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))
    if type(canonical) is not bytes or not 1 <= len(canonical) <= MAX_PEM_BYTES:
        raise CurrentRootAuthorizationError("current-root role export is not bounded PEM")
    work.charge(input_bytes=len(canonical) + len(raw))
    if canonical != raw:
        raise CurrentRootAuthorizationError("current-root role PEM is not canonical SPKI")
    return public_key


def _enrollment_content(payload, work):
    # Source vectors and all three closed key records were owned before the
    # first callback. A root signature enrolls this vector; vector shape alone
    # would never establish genesis, population or currentness.
    vector._encode_on_work(payload["initialVector"], work=work)
    return tuple(_role_key(payload[role], work) for role in _ROLES)


def _admit_enrollment_on_work(*, enrollment_bytes, root_public_key, work):
    """Authenticate original root enrollment; the root pin is independent."""
    held_raw = _original(enrollment_bytes, MAX_ENROLLMENT_BYTES, "current-root enrollment")
    held_key = root_public_key
    _public(held_key)
    envelope = _read(held_raw, ENROLLMENT_SCHEMA, MAX_ENROLLMENT_BYTES, work)
    _verify_signature(envelope, ENROLLMENT_SCHEMA, held_key, MAX_ENROLLMENT_BYTES, work)
    admitted_keys = _enrollment_content(envelope["payload"], work)
    _unchanged(held_raw, envelope, MAX_ENROLLMENT_BYTES, work)
    digest = plan._frame(ENROLLMENT_IDENTITY_DOMAIN, (held_raw,), work)
    return _EnrollmentMaterial(held_raw, envelope["payload"], digest, *admitted_keys)


def _scope(payload, material, role, work):
    enrolled = material.payload
    for name, expected in (("enrollmentDigest", material.enrollment_digest),
            ("databaseId", enrolled["databaseId"]), ("generationDigest", enrolled["generationDigest"]),
            ("producerMeasurementDigest", enrolled[role]["measurementDigest"])):
        plan._same(payload[name], expected, work, "current-root " + name)
    _interval(payload, enrolled["maxControlAgeNs"])


def _fresh(payload, material, now_epoch_ns):
    shape._integer(now_epoch_ns, minimum=1)
    issued, expires = payload["issuedAtEpochNs"], payload["expiresAtEpochNs"]
    if (issued > now_epoch_ns + material.payload["maxClockSkewNs"]
            or now_epoch_ns - issued > material.payload["maxControlAgeNs"]
            or now_epoch_ns >= expires):
        raise CurrentRootAuthorizationError("current-root original control is not live at the supplied instant")


def _request_content(payload, work):
    if payload["action"] == "reserve":
        # Use the actual operation identity recipe, not a second hash domain.
        operation, request_digest = payload["operation"], payload["requestDigest"]
        operation_size = work.prepare_utf8(operation)
        request_size = work.prepare_utf8(request_digest)
        work.charge(hashes=1, input_bytes=len("catchplate.policyAuthorityOperation/v2")
            + 17 + operation_size + request_size)
        actual = production._callback(work, lambda: commitment.operation_id(operation, request_digest))
        plan._same(payload["operationId"], actual, work, "current-root operation identity")
        # Canonicalize the already-owned closed vectors, then the genuine delta
        # consumer independently validates both complete source inventories.
        ledger = capture._SharedLedger(work)
        before = capability._wire(payload["beforeVector"], ledger, vector.MAX_BYTES, vector.MAX_NODES)
        after = capability._wire(payload["afterVector"], ledger, vector.MAX_BYTES, vector.MAX_NODES)
        if operation == "webauthn.challenge.maintain":
            # Source-fixed six-phase compatibility only. Each phase retains
            # its original proof/mutation caps; execution still needs genuine
            # raw-page replay and its protected single-commit stream owner.
            from catchplate import authority_challenge_current_root as maintenance_delta

            maintenance_delta.validate_necessary_delta(before_vector_bytes=before,
                after_vector_bytes=after, work=work)
        else:
            delta._validate_on_work(operation=operation, before_vector_bytes=before,
                after_vector_bytes=after, work=work)
    else:
        original = transport._decode(payload["writerReceiptBase64Url"],
            payload["writerReceiptByteCount"], MAX_WRITER_RECEIPT_BYTES, work)
        work.charge(hashes=1, input_bytes=len(original))
        actual = "sha256:" + hashlib.sha256(original).hexdigest()
        plan._same(actual, payload["writerReceiptBytesDigest"], work, "current-root writer original bytes")
        # These exact opaque writer bytes are a completion-role assertion.
        # Independent writer semantics/authorization are not inferred here.


def _verify_request(*, request_bytes, enrollment_bytes, root_public_key, now_epoch_ns, work):
    held_request = _original(request_bytes, MAX_BYTES, "current-root request")
    held_enrollment = _original(enrollment_bytes, MAX_ENROLLMENT_BYTES, "current-root enrollment")
    held_key, held_now = root_public_key, now_epoch_ns
    _public(held_key)
    if held_now is not None:
        shape._integer(held_now, minimum=1)
    # Own the entire request before enrollment/key callbacks; no successful
    # caller-supplied enrollment or request carrier is accepted.
    envelope = _read(held_request, REQUEST_SCHEMA, MAX_BYTES, work)
    material = _admit_enrollment_on_work(enrollment_bytes=held_enrollment,
        root_public_key=held_key, work=work)
    payload = envelope["payload"]
    reserve = payload["action"] == "reserve"
    _scope(payload, material, "computation" if reserve else "completion", work)
    key = material.computation_public_key if reserve else material.completion_public_key
    _verify_signature(envelope, REQUEST_SCHEMA, key, MAX_BYTES, work)
    _request_content(payload, work)
    if held_now is not None:
        _fresh(payload, material, held_now)
    _unchanged(held_request, envelope, MAX_BYTES, work)
    return material, payload, plan._frame(REQUEST_IDENTITY_DOMAIN, (held_request,), work)


def _verify_request_on_work(*, request_bytes, enrollment_bytes, root_public_key, now_epoch_ns, work):
    """Authenticate originals and require freshness at an independent instant."""
    shape._integer(now_epoch_ns, minimum=1)
    return _verify_request(request_bytes=request_bytes, enrollment_bytes=enrollment_bytes,
        root_public_key=root_public_key, now_epoch_ns=now_epoch_ns, work=work)


def _verify_historical_request_on_work(*, request_bytes, enrollment_bytes, root_public_key, work):
    """Authenticate original intervals for recovery, without a live-time claim.

    Signatures, exact scope, complete reserve vectors/deltas and opaque writer
    receipt commitments are all checked. This neither renews an expired
    control nor authorizes a fresh reservation/completion or latest-head use.
    """
    return _verify_request(request_bytes=request_bytes, enrollment_bytes=enrollment_bytes,
        root_public_key=root_public_key, now_epoch_ns=None, work=work)


def _sign(payload, schema, maximum, private_key, public_key, work):
    _private(private_key)
    _public(public_key)
    keys._pair_on_work(private_key, public_key, work)
    envelope = {"schema": schema, "payload": payload, "signatureBase64Url": "A" * 86}
    _envelope_shape(envelope, schema)
    unsigned_size, unsigned_nodes = work.measure(payload)
    envelope_size, envelope_nodes = work.measure(envelope)
    if max(unsigned_size, envelope_size) > maximum or max(unsigned_nodes, envelope_nodes) > MAX_NODES:
        raise CurrentRootAuthorizationError("current-root signature output exceeds its bound")
    work.charge(input_bytes=4 * unsigned_size + envelope_size + production._SIGNATURE_TRANSPORT_BYTES,
        json_nodes=2 * unsigned_nodes + envelope_nodes)
    frame_bytes = 2 * len(schema) + 9 + unsigned_size + 2 * 71
    if (work.limits.max_hashes - work.hash_work < 1
            or work.limits.max_input_bytes - work.input_bytes < frame_bytes + unsigned_size
            or work.limits.max_json_nodes - work.json_nodes < 4 + unsigned_nodes):
        raise QueryReadWorkError("current-root production cannot reserve its complete signature output")
    unsigned = plan.core.canonical_bytes(payload)
    if len(unsigned) != unsigned_size:
        raise CurrentRootAuthorizationError("current-root payload changed after measurement")
    message = plan._ascii(plan._frame(schema, (unsigned,), work), work)
    signature = production._sign_and_verify(private_key, public_key, message, work)
    if work.measure(payload) != (unsigned_size, unsigned_nodes) or plan.core.canonical_bytes(payload) != unsigned:
        raise CurrentRootAuthorizationError("current-root payload changed during signing")
    encoded = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
    shape._base64url(encoded, signature=True)
    result = plan.core.canonical_bytes({"schema": schema, "payload": payload,
        "signatureBase64Url": encoded})
    if len(result) != envelope_size:
        raise CurrentRootAuthorizationError("current-root signed envelope changed after measurement")
    return result


def _produce_enrollment_on_work(*, payload, root_private_key, root_public_key, work):
    """Sign a complete explicit enrollment; no initial vector is synthesized."""
    held_private, held_public = root_private_key, root_public_key
    _private(held_private)
    _public(held_public)
    owned = _capture_payload(payload, ENROLLMENT_SCHEMA, MAX_ENROLLMENT_BYTES, work)
    _enrollment_content(owned, work)
    return _sign(owned, ENROLLMENT_SCHEMA, MAX_ENROLLMENT_BYTES, held_private, held_public, work)


def _produce_request_on_work(*, payload, enrollment_bytes, root_public_key,
        producer_private_key, now_epoch_ns, work):
    """Sign a source-closed live request with its genuinely enrolled role key."""
    held_enrollment = _original(enrollment_bytes, MAX_ENROLLMENT_BYTES, "current-root enrollment")
    held_root, held_private, held_now = root_public_key, producer_private_key, now_epoch_ns
    _public(held_root)
    _private(held_private)
    shape._integer(held_now, minimum=1)
    owned = _capture_payload(payload, REQUEST_SCHEMA, MAX_BYTES, work)
    material = _admit_enrollment_on_work(enrollment_bytes=held_enrollment,
        root_public_key=held_root, work=work)
    reserve = owned["action"] == "reserve"
    _scope(owned, material, "computation" if reserve else "completion", work)
    _request_content(owned, work)
    _fresh(owned, material, held_now)
    public_key = material.computation_public_key if reserve else material.completion_public_key
    return _sign(owned, REQUEST_SCHEMA, MAX_BYTES, held_private, public_key, work)


def _produce_receipt_on_work(*, payload, enrollment_bytes, root_public_key, state_private_key, work):
    """Sign an original-interval state assertion, not proof of publication."""
    held_enrollment = _original(enrollment_bytes, MAX_ENROLLMENT_BYTES, "current-root enrollment")
    held_root, held_private = root_public_key, state_private_key
    _public(held_root)
    _private(held_private)
    owned = _capture_payload(payload, RECEIPT_SCHEMA, MAX_BYTES, work)
    material = _admit_enrollment_on_work(enrollment_bytes=held_enrollment,
        root_public_key=held_root, work=work)
    _scope(owned, material, "state", work)
    return _sign(owned, RECEIPT_SCHEMA, MAX_BYTES, held_private, material.state_public_key, work)


def _verify_receipt_on_work(*, receipt_bytes, enrollment_bytes, root_public_key, work):
    """Verify a historical state signature; owner must join request/ancestry."""
    held_receipt = _original(receipt_bytes, MAX_BYTES, "current-root receipt")
    held_enrollment = _original(enrollment_bytes, MAX_ENROLLMENT_BYTES, "current-root enrollment")
    held_key = root_public_key
    _public(held_key)
    envelope = _read(held_receipt, RECEIPT_SCHEMA, MAX_BYTES, work)
    material = _admit_enrollment_on_work(enrollment_bytes=held_enrollment,
        root_public_key=held_key, work=work)
    _scope(envelope["payload"], material, "state", work)
    _verify_signature(envelope, RECEIPT_SCHEMA, material.state_public_key, MAX_BYTES, work)
    _unchanged(held_receipt, envelope, MAX_BYTES, work)
    return envelope["payload"]


def _receipt_digest_on_work(receipt_bytes, work):
    """Identity of bounded canonical originals, not signature verification."""
    held = _original(receipt_bytes, MAX_BYTES, "current-root receipt")
    _read(held, RECEIPT_SCHEMA, MAX_BYTES, work)
    return plan._frame(RECEIPT_IDENTITY_DOMAIN, (held,), work)
