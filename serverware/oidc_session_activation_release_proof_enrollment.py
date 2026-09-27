"""Root-original enrollment of a separate committed-release proof signer.

This fixed purpose authenticates a producer key and independently held scope.
It is not a committed-consumption proof, measured-runtime assertion, token
release permission, key-delivery mechanism or successful admission input.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature

from serverware import authority_current_root_authorization as authorization
from serverware import authority_webauthn_evidence_plan_clock as clock
from serverware.authority_query_read_work import QueryReadWorkError


authority, shape, capture, wire = (
    authorization.authority, authorization.shape, authorization.capture, authorization.wire)
plan, keys, production = authorization.plan, authorization.keys, authorization.production
capability = authorization.capability
PURPOSE = "enroll-oidc-session-activation-committed-release-producer"
SCHEMA = "serverware.signedOidcSessionActivationReleaseProofEnrollment/v1"
PAYLOAD_SCHEMA = "serverware.oidcSessionActivationReleaseProofEnrollment/v1"
IDENTITY_DOMAIN = "serverware.oidcSessionActivationReleaseProofEnrollmentIdentity/v1"
SIGNATURE_DOMAIN = SCHEMA
MAX_BYTES = 16 * 1024
MAX_NODES, MAX_DEPTH = 256, 4
MAX_FORBIDDEN_PUBLIC_KEYS = 16
_ENVELOPE_FIELDS = frozenset({"schema", "payload", "signatureBase64Url"})
_KEY_FIELDS = frozenset({"publicKeyPem", "spkiDigest", "measurementDigest"})
SCOPE_FIELDS = frozenset({"configurationDigest", "databaseId", "generationDigest",
    "runtimeClosureDigest", "producerId", "producerIdentity", "receiverIdentity"})
PAYLOAD_FIELDS = SCOPE_FIELDS | frozenset({"schema", "sourceRevision", "purpose",
    "proofKey", "maximumAgeNs", "maximumClockSkewNs"})


class OidcSessionActivationReleaseProofEnrollmentError(ValueError):
    pass


def _fail(message):
    raise OidcSessionActivationReleaseProofEnrollmentError(message)


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _Enrollment:
    """Same-call observations; no API accepts this result as authority."""

    payload: dict
    enrollment_digest: str
    proof_public_key: object


class _Capture(capture._JSONCapture):
    def visit(self, value, depth=0, ancestors=frozenset()):
        if depth > MAX_DEPTH or self.nodes >= MAX_NODES:
            _fail("release proof enrollment exceeds its fixed structure bounds")
        result = super().visit(value, depth, ancestors)
        if self.nodes > MAX_NODES:
            _fail("release proof enrollment exceeds its fixed node bound")
        return result


def _capture(value, work):
    return _Capture(capture._SharedLedger(work), maximum_bytes=MAX_BYTES).visit(value)


def _scope_shape(value):
    shape._object(value, SCOPE_FIELDS, "release proof enrollment scope")
    for name in ("configurationDigest", "generationDigest", "runtimeClosureDigest"):
        shape._digest(value[name])
    for name in ("databaseId", "producerId"):
        authorization._token(value[name])
    for name in ("producerIdentity", "receiverIdentity"):
        shape.validate_identity_shape(value[name])


def _scope(value, work):
    """Own exactly seven independently supplied scope fields, not proof."""
    owned = _capture(value, work)
    _scope_shape(owned)
    return owned


def _payload_shape(payload):
    shape._object(payload, PAYLOAD_FIELDS, "committed-release proof enrollment")
    shape._literal(payload["schema"], PAYLOAD_SCHEMA)
    shape._literal(payload["sourceRevision"], authority.SOURCE_REVISION)
    shape._literal(payload["purpose"], PURPOSE)
    _scope_shape({name: payload[name] for name in SCOPE_FIELDS})
    record = payload["proofKey"]
    shape._object(record, _KEY_FIELDS, "committed-release proof key")
    for name in ("spkiDigest", "measurementDigest"):
        shape._digest(record[name])
    if record["measurementDigest"] != payload["producerIdentity"]["measurementDigest"]:
        _fail("release proof key measurement differs from the independent producer identity")
    pem = record["publicKeyPem"]
    if (type(pem) is not str or not 1 <= len(pem) <= authorization.MAX_PEM_BYTES
            or not pem.isascii() or "\x00" in pem):
        _fail("release proof PEM is not bounded original ASCII")
    shape._integer(payload["maximumAgeNs"], authority.VERIFIER_RESPONSE_MAX_AGE_NS, minimum=1)
    shape._integer(payload["maximumClockSkewNs"], authority.VERIFIER_MAX_CLOCK_SKEW_NS)


def _forbidden(values):
    if type(values) is not tuple or not 1 <= len(values) <= MAX_FORBIDDEN_PUBLIC_KEYS:
        _fail("release proof requires a bounded exact tuple of independent role keys")
    for key in values:
        authorization._public(key)
    return values


def _separate(proof_key, root, forbidden, work):
    actual = keys._spki_on_work(proof_key, work)
    root_digest = keys._spki_on_work(root, work)
    work.prepare_comparison(actual, root_digest)
    if actual == root_digest:
        _fail("release proof signer reuses the root key")
    seen = []
    for key in forbidden:
        digest = keys._spki_on_work(key, work)
        for previous in seen:
            work.prepare_comparison(digest, previous)
            if digest == previous:
                _fail("release proof forbidden role keys contain a duplicate SPKI")
        seen.append(digest)
        work.prepare_comparison(actual, digest)
        if actual == digest:
            _fail("release proof signer reuses an independently supplied role key")


def _read(raw, work):
    original = authorization._original(raw, MAX_BYTES, "release proof enrollment")
    decoded = wire._decode_object(original, work=work, maximum_bytes=MAX_BYTES,
        maximum_nodes=MAX_NODES, maximum_depth=MAX_DEPTH)
    owned = _capture(decoded, work)
    shape._object(owned, _ENVELOPE_FIELDS, "signed release proof enrollment")
    shape._literal(owned["schema"], SCHEMA)
    shape._base64url(owned["signatureBase64Url"], signature=True)
    _payload_shape(owned["payload"])
    capability._canonical(original, owned, capture._SharedLedger(work), MAX_BYTES, MAX_NODES)
    return owned


def _admit_on_work(*, enrollment_bytes, root_public_key, expected_scope,
        forbidden_public_keys, work):
    """Authenticate original root enrollment against independent held scope."""
    capture._SharedLedger(work)
    raw = authorization._original(enrollment_bytes, MAX_BYTES, "release proof enrollment")
    root, forbidden = root_public_key, _forbidden(forbidden_public_keys)
    authorization._public(root)
    expected = _scope(expected_scope, work)
    # Own ordinary scope and retain actual key references before native calls.
    envelope = _read(raw, work)
    payload = envelope["payload"]
    unsigned = capability._wire(payload, capture._SharedLedger(work), MAX_BYTES, MAX_NODES)
    try:
        capability._signature(root, envelope["signatureBase64Url"], SIGNATURE_DOMAIN,
            unsigned, capture._SharedLedger(work))
    except InvalidSignature as exc:
        raise OidcSessionActivationReleaseProofEnrollmentError(
            "release proof enrollment root signature is invalid") from exc
    for name in SCOPE_FIELDS:
        plan._same(payload[name], expected[name], work, "release proof enrollment " + name)
    proof_key = authorization._role_key(payload["proofKey"], work)
    _separate(proof_key, root, forbidden, work)
    capability._canonical(raw, envelope, capture._SharedLedger(work), MAX_BYTES, MAX_NODES)
    identity = plan._frame(IDENTITY_DOMAIN, (raw,), work)
    return _Enrollment(payload, identity, proof_key)


def _produce_on_work(*, payload, root_private_key, root_public_key,
        forbidden_public_keys, work):
    """Sign this enrollment only, then genuinely admit the exact output."""
    capture._SharedLedger(work)
    private, root = root_private_key, root_public_key
    forbidden = _forbidden(forbidden_public_keys)
    authorization._private(private)
    authorization._public(root)
    owned = _capture(payload, work)
    _payload_shape(owned)
    expected = _scope({name: owned[name] for name in SCOPE_FIELDS}, work)
    proof_key = authorization._role_key(owned["proofKey"], work)
    _separate(proof_key, root, forbidden, work)
    keys._pair_on_work(private, root, work)
    envelope = {"schema": SCHEMA, "payload": owned, "signatureBase64Url": "A" * 86}
    unsigned_size, unsigned_nodes = work.measure(owned)
    envelope_size, envelope_nodes = work.measure(envelope)
    if max(unsigned_size, envelope_size) > MAX_BYTES or max(unsigned_nodes, envelope_nodes) > MAX_NODES:
        _fail("release proof enrollment signature exceeds its output bounds")
    work.charge(input_bytes=4 * unsigned_size + envelope_size + production._SIGNATURE_TRANSPORT_BYTES,
        json_nodes=2 * unsigned_nodes + envelope_nodes)
    frame_bytes = 2 * len(SIGNATURE_DOMAIN) + 9 + unsigned_size + 2 * 71
    if (work.limits.max_hashes - work.hash_work < 1
            or work.limits.max_input_bytes - work.input_bytes < frame_bytes + unsigned_size
            or work.limits.max_json_nodes - work.json_nodes < 4 + unsigned_nodes):
        raise QueryReadWorkError("release proof enrollment cannot reserve its complete signature output")
    unsigned = plan.core.canonical_bytes(owned)
    if len(unsigned) != unsigned_size:
        _fail("release proof enrollment changed after measurement")
    message = plan._ascii(plan._frame(SIGNATURE_DOMAIN, (unsigned,), work), work)
    signature = production._sign_and_verify(private, root, message, work)
    if work.measure(owned) != (unsigned_size, unsigned_nodes) or plan.core.canonical_bytes(owned) != unsigned:
        _fail("release proof enrollment changed during signing")
    encoded = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
    shape._base64url(encoded, signature=True)
    original = plan.core.canonical_bytes({"schema": SCHEMA,
        "payload": owned, "signatureBase64Url": encoded})
    if len(original) != envelope_size:
        _fail("release proof enrollment signed output changed after reservation")
    verified = _admit_on_work(enrollment_bytes=original, root_public_key=root,
        expected_scope=expected, forbidden_public_keys=forbidden, work=work)
    plan._same(verified.payload, owned, work, "release proof enrollment signed payload differs")
    return original
