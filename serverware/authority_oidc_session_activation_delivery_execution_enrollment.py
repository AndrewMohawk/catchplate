"""Root-original delegation for a distinct consume-only grant authorizer.

This is enrollment, not a grant producer or replay-success interface. The
root-signed scope is derived from the actual current-root original, with a
separate fixed purpose and key. Generic successor delegations cannot acquire
consume authority by adding an operation to their array. Cold custody, caller
permission, full consume-original replay and issuance remain separate work.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass

from serverware import authority_current_root_authorization as authorization
from serverware import authority_oidc_session_activation_delivery_plan_contract as consume
from serverware.authority_query_read_work import QueryReadWorkError


authority, shape, capture, wire = (
    authorization.authority, authorization.shape, authorization.capture, authorization.wire)
plan, keys, production = authorization.plan, authorization.keys, authorization.production
OPERATION = consume.OPERATION
ENROLLMENT_SCHEMA = "serverware.signedOidcSessionActivationDeliveryExecutionGrantEnrollment/v1"
ENROLLMENT_PAYLOAD_SCHEMA = "serverware.oidcSessionActivationDeliveryExecutionGrantEnrollment/v1"
ENROLLMENT_IDENTITY_DOMAIN = "serverware.oidcSessionActivationDeliveryExecutionGrantEnrollmentIdentity/v1"
MAX_ENROLLMENT_BYTES = 16 * 1024
MAX_NODES, MAX_DEPTH = 4096, 6
_ENVELOPE_FIELDS = frozenset({"schema", "payload", "signatureBase64Url"})
_KEY_FIELDS = frozenset({"publicKeyPem", "spkiDigest", "measurementDigest"})
ENROLLMENT_FIELDS = frozenset({"schema", "sourceRevision", "operation",
    "currentRootEnrollmentDigest", "databaseId", "generationDigest", "authorizer",
    "maximumGrantAgeNs", "maximumClockSkewNs"})


class DeliveryExecutionEnrollmentError(ValueError):
    pass


def _fail(message):
    raise DeliveryExecutionEnrollmentError(message)


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _Enrollment:
    """Same-call original observations; not accepted in place of signed bytes."""

    payload: dict
    enrollment_digest: str
    authorizer_public_key: object


class _Capture(capture._JSONCapture):
    def visit(self, value, depth=0, ancestors=frozenset()):
        if depth > MAX_DEPTH or self.nodes >= MAX_NODES:
            _fail("consume delegation exceeds its fixed structure bounds")
        result = super().visit(value, depth, ancestors)
        if self.nodes > MAX_NODES:
            _fail("consume delegation exceeds its fixed node bound")
        return result


def _shape(payload):
    shape._object(payload, ENROLLMENT_FIELDS, "consume-only grant enrollment")
    shape._literal(payload["schema"], ENROLLMENT_PAYLOAD_SCHEMA)
    shape._literal(payload["sourceRevision"], authority.SOURCE_REVISION)
    shape._literal(payload["operation"], OPERATION)
    for name in ("currentRootEnrollmentDigest", "generationDigest"):
        shape._digest(payload[name])
    authorization._token(payload["databaseId"])
    record = payload["authorizer"]
    shape._object(record, _KEY_FIELDS, "consume grant authorizer key")
    for name in ("spkiDigest", "measurementDigest"):
        shape._digest(record[name])
    pem = record["publicKeyPem"]
    if (type(pem) is not str or not 1 <= len(pem) <= authorization.MAX_PEM_BYTES
            or not pem.isascii() or "\x00" in pem):
        _fail("consume grant authorizer PEM is not bounded original ASCII")
    shape._integer(payload["maximumGrantAgeNs"], authority.VERIFIER_RESPONSE_MAX_AGE_NS, minimum=1)
    shape._integer(payload["maximumClockSkewNs"], authority.VERIFIER_MAX_CLOCK_SKEW_NS)


def _read(raw, work):
    original = authorization._original(raw, MAX_ENROLLMENT_BYTES, "consume grant enrollment")
    value = wire._decode_object(original, work=work, maximum_bytes=MAX_ENROLLMENT_BYTES,
        maximum_nodes=MAX_NODES, maximum_depth=MAX_DEPTH)
    shape._object(value, _ENVELOPE_FIELDS, "signed consume grant enrollment")
    shape._literal(value["schema"], ENROLLMENT_SCHEMA)
    shape._base64url(value["signatureBase64Url"], signature=True)
    _shape(value["payload"])
    owned = _Capture(capture._SharedLedger(work), maximum_bytes=MAX_ENROLLMENT_BYTES).visit(value)
    authorization.capability._canonical(original, owned,
        capture._SharedLedger(work), MAX_ENROLLMENT_BYTES, MAX_NODES)
    return owned


def _separate(authorizer, current, root, work):
    actual = keys._spki_on_work(authorizer, work)
    for other in (root, current.computation_public_key, current.completion_public_key,
            current.state_public_key):
        forbidden = keys._spki_on_work(other, work)
        work.prepare_comparison(actual, forbidden)
        if actual == forbidden:
            _fail("consume authorizer must differ from root and state producers")
    return actual


def _admit_enrollment_on_work(*, grant_enrollment_bytes, current_root_enrollment_bytes,
        root_public_key, work):
    """Genuinely authenticate both original enrollments on existing work."""
    capture._SharedLedger(work)
    raw = authorization._original(grant_enrollment_bytes, MAX_ENROLLMENT_BYTES, "consume grant enrollment")
    current_raw = authorization._original(current_root_enrollment_bytes,
        authorization.MAX_ENROLLMENT_BYTES, "current-root enrollment")
    root = root_public_key
    authorization._public(root)
    envelope = _read(raw, work)
    payload = envelope["payload"]
    unsigned = authorization.capability._wire(payload, capture._SharedLedger(work),
        MAX_ENROLLMENT_BYTES, MAX_NODES)
    authorization.capability._signature(root, envelope["signatureBase64Url"],
        ENROLLMENT_SCHEMA, unsigned, capture._SharedLedger(work))
    current = authorization._admit_enrollment_on_work(enrollment_bytes=current_raw,
        root_public_key=root, work=work)
    for name, expected in (("currentRootEnrollmentDigest", current.enrollment_digest),
            ("databaseId", current.payload["databaseId"]), ("generationDigest", current.payload["generationDigest"])):
        plan._same(payload[name], expected, work, "consume grant enrollment " + name)
    authorizer = authorization._role_key(payload["authorizer"], work)
    _separate(authorizer, current, root, work)
    authorization.capability._canonical(raw, envelope,
        capture._SharedLedger(work), MAX_ENROLLMENT_BYTES, MAX_NODES)
    identity = plan._frame(ENROLLMENT_IDENTITY_DOMAIN, (raw,), work)
    return _Enrollment(payload, identity, authorizer)


def _sign(payload, private_key, public_key, work):
    """Single fixed root-enrollment domain; no arbitrary signing purpose."""
    private, public = private_key, public_key
    authorization._private(private)
    authorization._public(public)
    owned = _Capture(capture._SharedLedger(work), maximum_bytes=MAX_ENROLLMENT_BYTES).visit(payload)
    _shape(owned)
    keys._pair_on_work(private, public, work)
    envelope = {"schema": ENROLLMENT_SCHEMA, "payload": owned, "signatureBase64Url": "A" * 86}
    unsigned_size, unsigned_nodes = work.measure(owned)
    envelope_size, envelope_nodes = work.measure(envelope)
    if (max(unsigned_size, envelope_size) > MAX_ENROLLMENT_BYTES
            or max(unsigned_nodes, envelope_nodes) > MAX_NODES):
        _fail("consume enrollment signature exceeds its output bounds")
    work.charge(input_bytes=4 * unsigned_size + envelope_size + production._SIGNATURE_TRANSPORT_BYTES,
        json_nodes=2 * unsigned_nodes + envelope_nodes)
    frame_bytes = 2 * len(ENROLLMENT_SCHEMA) + 9 + unsigned_size + 2 * 71
    if (work.limits.max_hashes - work.hash_work < 1
            or work.limits.max_input_bytes - work.input_bytes < frame_bytes + unsigned_size
            or work.limits.max_json_nodes - work.json_nodes < 4 + unsigned_nodes):
        raise QueryReadWorkError("consume enrollment cannot reserve its complete signature output")
    unsigned = plan.core.canonical_bytes(owned)
    if len(unsigned) != unsigned_size:
        _fail("consume enrollment changed after measurement")
    message = plan._ascii(plan._frame(ENROLLMENT_SCHEMA, (unsigned,), work), work)
    signature = production._sign_and_verify(private, public, message, work)
    if (work.measure(owned) != (unsigned_size, unsigned_nodes)
            or plan.core.canonical_bytes(owned) != unsigned):
        _fail("consume enrollment changed during signing")
    encoded = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
    shape._base64url(encoded, signature=True)
    result = plan.core.canonical_bytes({"schema": ENROLLMENT_SCHEMA,
        "payload": owned, "signatureBase64Url": encoded})
    if len(result) != envelope_size:
        _fail("consume enrollment signed output changed after reservation")
    return result


def _produce_on_work(*, current_root_enrollment_bytes, root_private_key,
        root_public_key, authorizer_public_key, authorizer_measurement_digest,
        maximum_grant_age_ns, maximum_clock_skew_ns, work):
    """Derive fixed delegation claims from originals, never a scope carrier."""
    original = authorization._original(current_root_enrollment_bytes,
        authorization.MAX_ENROLLMENT_BYTES, "current-root enrollment")
    private, root, authorizer = root_private_key, root_public_key, authorizer_public_key
    measurement, age, skew = authorizer_measurement_digest, maximum_grant_age_ns, maximum_clock_skew_ns
    authorization._private(private)
    authorization._public(root)
    authorization._public(authorizer)
    shape._digest(measurement)
    shape._integer(age, authority.VERIFIER_RESPONSE_MAX_AGE_NS, minimum=1)
    shape._integer(skew, authority.VERIFIER_MAX_CLOCK_SKEW_NS)
    capture._SharedLedger(work)
    current = authorization._admit_enrollment_on_work(enrollment_bytes=original,
        root_public_key=root, work=work)
    enrollment_digest, database_id, generation_digest = (
        current.enrollment_digest, current.payload["databaseId"], current.payload["generationDigest"])
    spki = _separate(authorizer, current, root, work)
    work.charge(input_bytes=authorization.MAX_PEM_BYTES)
    pem = production._callback(work, lambda: authorizer.public_bytes(
        authorization.Encoding.PEM, authorization.PublicFormat.SubjectPublicKeyInfo))
    if (type(pem) is not bytes or not 1 <= len(pem) <= authorization.MAX_PEM_BYTES
            or not pem.isascii()):
        _fail("consume authorizer did not export bounded canonical PEM")
    work.charge(input_bytes=len(pem))
    payload = {"schema": ENROLLMENT_PAYLOAD_SCHEMA, "sourceRevision": authority.SOURCE_REVISION,
        "operation": OPERATION, "currentRootEnrollmentDigest": enrollment_digest,
        "databaseId": database_id, "generationDigest": generation_digest,
        "authorizer": {"publicKeyPem": pem.decode("ascii"), "spkiDigest": spki,
            "measurementDigest": measurement}, "maximumGrantAgeNs": age, "maximumClockSkewNs": skew}
    _shape(payload)
    authorization._role_key(payload["authorizer"], work)
    original_enrollment = _sign(payload, private, root, work)
    _admit_enrollment_on_work(grant_enrollment_bytes=original_enrollment,
        current_root_enrollment_bytes=original, root_public_key=root, work=work)
    return original_enrollment
