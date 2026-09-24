"""Private clock-free signatures over the writer's scalar request commitment.

The owning transaction supplies the freshly matched immutable request fields
after both real replays. These pure functions do not establish that provenance,
commit, currentness, execution or launch admission. They accept no proof DTO,
read no clock, open no database and release no response. Stable identities omit
key/configuration epochs; historical key resolution remains an external duty.
Every actual copy, codec, hash and key callback uses the existing caller work.
"""
from __future__ import annotations

import base64
import hashlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from serverware import authority_contract as authority
from serverware import authority_revocation_capability as capability
from serverware import authority_revocation_capability_production as production
from serverware import authority_revocation_retention as retention
from serverware.authority_query_read_work import QueryReadWorkError


plan, wire, capture = retention.plan, retention.wire, retention.capture
ACK_SCHEMA = "serverware.policyAuthorityRevocationWriterAcknowledgment/v1"
ACK_ID_DOMAIN = "serverware.policyAuthorityRevocationWriterAcknowledgmentIdentity/v1"
PURPOSE = "acknowledge-revocation-writer-custody"
CUSTODY_STATE = "retained-and-reserved"
MAX_ACK_BYTES = 16384
MAX_ACK_NODES = 256
MAX_ACK_DEPTH = 2
REQUEST_FIELDS = frozenset({
    "intent_envelope_id", "relay_envelope_id", "execution_envelope_id", "planner_transaction_id",
    "plan_protocol", "retained_record_digest", "configuration_digest", "generation_sequence",
    "generation_digest", "exact_intent_bytes_digest", "exact_intent_byte_count",
    "exact_relay_bytes_digest", "exact_relay_byte_count", "historical_expectations_bytes_digest",
    "historical_expectations_byte_count", "planner_key_digest", "verifier_key_digest",
    "planned_at_epoch_ns", "source_revision",
})
_COUNT_LIMITS = {"exact_intent_byte_count": authority.MAX_REQUEST_BYTES,
    "exact_relay_byte_count": authority.MAX_REQUEST_BYTES,
    "historical_expectations_byte_count": capture.MAX_TOTAL_INPUT_BYTES}
_NON_DIGESTS = frozenset({"plan_protocol", "source_revision", "generation_sequence",
    "planned_at_epoch_ns", *_COUNT_LIMITS})
_ENVELOPE_FIELDS = frozenset({"schema", "acknowledgmentId", "purpose", "custodyState",
    "writerResponseSpkiDigest", "request", "signatureBase64Url"})
_SPKI_PREFIX = b"\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00"
_FAILURES = (AttributeError, KeyError, TypeError, ValueError, OverflowError, RecursionError, InvalidSignature)


class RevocationWriterAcknowledgmentError(ValueError):
    pass


def _request_shape(value):
    plan.contract._object(value, REQUEST_FIELDS, "writer acknowledgment request")
    for name in REQUEST_FIELDS - _NON_DIGESTS:
        plan.contract._digest(value[name])
    plan.contract._literal(value["plan_protocol"], retention.PLAN_PROTOCOL)
    plan.contract._literal(value["source_revision"], authority.SOURCE_REVISION)
    for name in ("generation_sequence", "planned_at_epoch_ns"):
        plan.contract._integer(value[name], minimum=1)
    for name, maximum in _COUNT_LIMITS.items():
        plan.contract._integer(value[name], maximum, minimum=2)


def _capture_request(request_fields, ledger):
    # A closed scalar object is checked before the copy, not an unbounded row
    # with three potentially huge original-body transports. Its actual place
    # in the signed envelope is depth one and every child is depth two.
    _request_shape(request_fields)
    owned = capture._JSONCapture(ledger, maximum_bytes=MAX_ACK_BYTES)
    result = owned.visit(request_fields, depth=1)
    if owned.nodes > MAX_ACK_NODES:
        raise RevocationWriterAcknowledgmentError("writer acknowledgment request exceeds its node bound")
    return result


def _ack_id_on_work(intent_envelope_id, work):
    capture._SharedLedger(work)
    plan.contract._digest(intent_envelope_id)
    return plan._frame(ACK_ID_DOMAIN, (plan._ascii(intent_envelope_id, work),), work)


def _spki_on_work(key, work):
    if not isinstance(key, Ed25519PublicKey):
        raise RevocationWriterAcknowledgmentError("writer acknowledgment requires an Ed25519 public key")
    work.charge(input_bytes=44)
    der = production._callback(work,
        lambda: key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo))
    if type(der) is not bytes or len(der) != 44 or not der.startswith(_SPKI_PREFIX):
        raise RevocationWriterAcknowledgmentError("writer acknowledgment SPKI is not canonical Ed25519")
    work.charge(hashes=1, input_bytes=44)
    return "sha256:" + hashlib.sha256(der).hexdigest()


def _public_binding(key, pin, work):
    plan.contract._digest(pin)
    observed = _spki_on_work(key, work)
    plan._same(observed, pin, work, "writer acknowledgment key differs from its independent response pin")
    return observed


def _bind_signer_on_work(*, writer_private_key, launch_public_key,
        expected_writer_spki_digest, other_response_spki_digests, work):
    """Bind actual writer/launch handles to immutable independently owned pins.

    Exact four-role pin shapes/membership are fixed bounded admission, outside
    H/B/N. Two actual DER exports/hashes, the canonical pin equality and full
    launch inequality comparison are metered. No signature is produced here.
    """
    try:
        capture._SharedLedger(work)
        plan.contract._digest(expected_writer_spki_digest)
        if type(other_response_spki_digests) is not tuple or len(other_response_spki_digests) != 4:
            raise RevocationWriterAcknowledgmentError("writer acknowledgment requires four other role pins")
        for value in other_response_spki_digests:
            plan.contract._digest(value)
        if expected_writer_spki_digest in other_response_spki_digests:
            raise RevocationWriterAcknowledgmentError("writer acknowledgment signer reuses another role key")
        if (not isinstance(writer_private_key, Ed25519PrivateKey)
                or not isinstance(launch_public_key, Ed25519PublicKey)):
            raise RevocationWriterAcknowledgmentError("writer acknowledgment signer handles are not Ed25519")
        public = production._callback(work, lambda: writer_private_key.public_key())
        observed = _public_binding(public, expected_writer_spki_digest, work)
        launch = _spki_on_work(launch_public_key, work)
        work.prepare_comparison(observed, launch)
        if observed == launch:
            raise RevocationWriterAcknowledgmentError("writer acknowledgment signer reuses the launch identity")
        return public
    except _FAILURES as exc:
        if isinstance(exc, RevocationWriterAcknowledgmentError):
            raise
        raise RevocationWriterAcknowledgmentError("writer acknowledgment signer binding failed") from exc


def _pair_on_work(private_key, public_key, work):
    work.charge(input_bytes=128)
    derived = production._callback(work, lambda: private_key.public_key())
    if not isinstance(derived, Ed25519PublicKey):
        raise RevocationWriterAcknowledgmentError("writer acknowledgment signer did not derive Ed25519")
    actual = production._callback(work, lambda: derived.public_bytes(Encoding.Raw, PublicFormat.Raw))
    expected = production._callback(work, lambda: public_key.public_bytes(Encoding.Raw, PublicFormat.Raw))
    if (any(type(value) is not bytes or len(value) != 32 for value in (actual, expected))
            or actual != expected):
        raise RevocationWriterAcknowledgmentError("writer acknowledgment private/public keys differ")


def _unsigned(request, pin, work):
    return {"schema": ACK_SCHEMA,
        "acknowledgmentId": _ack_id_on_work(request["intent_envelope_id"], work),
        "purpose": PURPOSE, "custodyState": CUSTODY_STATE,
        "writerResponseSpkiDigest": pin, "request": request}


def _shape(value):
    plan.contract._object(value, _ENVELOPE_FIELDS, "writer acknowledgment")
    for name, expected in (("schema", ACK_SCHEMA), ("purpose", PURPOSE), ("custodyState", CUSTODY_STATE)):
        plan.contract._literal(value[name], expected)
    for name in ("acknowledgmentId", "writerResponseSpkiDigest"):
        plan.contract._digest(value[name])
    _request_shape(value["request"])
    plan.contract._base64url(value["signatureBase64Url"], signature=True)


def _signed_wire(unsigned, private_key, public_key, work):
    envelope = {**unsigned, "signatureBase64Url": "A" * 86}
    _shape(envelope)
    unsigned_size, unsigned_nodes = work.measure(unsigned)
    envelope_size, envelope_nodes = work.measure(envelope)
    if (max(unsigned_size, envelope_size) > MAX_ACK_BYTES
            or max(unsigned_nodes, envelope_nodes) > MAX_ACK_NODES):
        raise RevocationWriterAcknowledgmentError("writer acknowledgment exceeds its output bound")
    work.charge(input_bytes=4 * unsigned_size + envelope_size + production._SIGNATURE_TRANSPORT_BYTES,
        json_nodes=2 * unsigned_nodes + envelope_nodes)
    frame_bytes = 2 * len(ACK_SCHEMA) + 9 + unsigned_size + 2 * 71
    if (work.limits.max_hashes - work.hash_work < 1
            or work.limits.max_input_bytes - work.input_bytes < frame_bytes + unsigned_size
            or work.limits.max_json_nodes - work.json_nodes < 4 + unsigned_nodes):
        raise QueryReadWorkError("writer acknowledgment cannot reserve its complete signed output")
    original = plan.core.canonical_bytes(unsigned)
    if len(original) != unsigned_size:
        raise RevocationWriterAcknowledgmentError("writer acknowledgment unsigned measurement changed")
    message = plan._ascii(plan._frame(ACK_SCHEMA, (original,), work), work)
    signature = production._sign_and_verify(private_key, public_key, message, work)
    if work.measure(unsigned) != (unsigned_size, unsigned_nodes):
        raise RevocationWriterAcknowledgmentError("writer acknowledgment unsigned graph changed during signing")
    if plan.core.canonical_bytes(unsigned) != original:
        raise RevocationWriterAcknowledgmentError("writer acknowledgment unsigned bytes changed during signing")
    encoded = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
    plan.contract._base64url(encoded, signature=True)
    result = plan.core.canonical_bytes({**unsigned, "signatureBase64Url": encoded})
    if len(result) != envelope_size:
        raise RevocationWriterAcknowledgmentError("writer acknowledgment final envelope changed")
    return result


def _sign_on_work(*, request_fields, writer_private_key, writer_public_key,
        expected_writer_spki_digest, work):
    """Sign only owned scalar claims; the caller still owes custody provenance."""
    try:
        ledger = capture._SharedLedger(work)
        plan.contract._digest(expected_writer_spki_digest)
        if not isinstance(writer_private_key, Ed25519PrivateKey):
            raise RevocationWriterAcknowledgmentError("writer acknowledgment signer is not Ed25519")
        request = _capture_request(request_fields, ledger)
        _public_binding(writer_public_key, expected_writer_spki_digest, work)
        _pair_on_work(writer_private_key, writer_public_key, work)
        return _signed_wire(_unsigned(request, expected_writer_spki_digest, work),
            writer_private_key, writer_public_key, work)
    except _FAILURES as exc:
        if isinstance(exc, RevocationWriterAcknowledgmentError):
            raise
        raise RevocationWriterAcknowledgmentError("writer acknowledgment signing failed") from exc


def _verify_on_work(*, acknowledgment_bytes, request_fields, writer_public_key,
        expected_writer_spki_digest, work):
    """Verify exact stored bytes against external pins/fields; return no token."""
    try:
        ledger = capture._SharedLedger(work)
        if type(acknowledgment_bytes) is not bytes or not 2 <= len(acknowledgment_bytes) <= MAX_ACK_BYTES:
            raise RevocationWriterAcknowledgmentError("writer acknowledgment requires bounded original bytes")
        plan.contract._digest(expected_writer_spki_digest)
        request = _capture_request(request_fields, ledger)
        envelope = wire._decode_object(acknowledgment_bytes, work=work,
            maximum_bytes=MAX_ACK_BYTES, maximum_nodes=MAX_ACK_NODES, maximum_depth=MAX_ACK_DEPTH)
        _shape(envelope)
        capability._canonical(acknowledgment_bytes, envelope, ledger, MAX_ACK_BYTES, MAX_ACK_NODES)
        work.prepare_copy(envelope)
        unsigned = envelope.copy()
        encoded = unsigned.pop("signatureBase64Url")
        unsigned_wire = capability._wire(unsigned, ledger, MAX_ACK_BYTES, MAX_ACK_NODES)
        _public_binding(writer_public_key, expected_writer_spki_digest, work)
        capability._signature(writer_public_key, encoded, ACK_SCHEMA, unsigned_wire, ledger)
        # Recheck the exact graph whose bytes were signed after the callback,
        # including its shallow copy's scalar fields, before comparing it to
        # independent expectations. Never publish parsed data.
        capability._canonical(unsigned_wire, unsigned, ledger, MAX_ACK_BYTES, MAX_ACK_NODES)
        plan._same(unsigned, _unsigned(request, expected_writer_spki_digest, work), work,
            "writer acknowledgment differs from the independent request or response pin")
    except _FAILURES as exc:
        if isinstance(exc, RevocationWriterAcknowledgmentError):
            raise
        raise RevocationWriterAcknowledgmentError("writer acknowledgment verification failed") from exc
