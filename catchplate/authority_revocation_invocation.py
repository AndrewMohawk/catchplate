"""Private original-byte authenticated revocation issuance invocation.

The existing internal-envelope/v3 domain and eleven fields are unchanged; the
new fixed purpose is not registered with legacy service dispatch. A verifier
signature authenticates historical sender claims, not current roots, truthful
clock acquisition or post-plan witness authority. The configured issuer must
still genuinely verify the original capability, witness and retained plan.

No clock, SQL, registry, fresh work allowance or successful-proof input exists
here. Keys/configuration/generation and current clocks are independent inputs.
The full wrapper keeps the existing 4 MiB request ceiling. Historical request
arguments may contain nested audit JSON, so depth is bounded at the existing
128 ceiling, including the wrapper, rather than assuming a shallow payload.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from catchplate import authority_revocation_capability as capability
from catchplate import authority_revocation_capability_production as production
from catchplate.authority_query_read_work import QueryReadValidationMetrics, QueryReadWorkError, _ValidationWork


SCHEMA = "catchplate.policyAuthorityRevocationIssuanceInvocation/v1"
PURPOSE = "issue-revocation-capability"
ENVELOPE_SCHEMA = capability.authority.INTERNAL_ENVELOPE_SCHEMA
MAX_ENVELOPE_BYTES = capability.authority.MAX_REQUEST_BYTES
MAX_JSON_NODES = capability.MAX_JSON_NODES
MAX_JSON_DEPTH = capability.shape.MAX_JSON_DEPTH
ENVELOPE_FIELDS = frozenset({"schema", "envelopeId", "parentEnvelopeId", "purpose",
    "configurationDigest", "issuedAtEpochNs", "issuedMonotonicNs", "deadlineMonotonicNs",
    "fence", "payload", "signature"})
PAYLOAD_FIELDS = frozenset({"schema", "sourceRevision", "generationSequence", "generationDigest",
    "executionEnvelopeId", "witnessReceiptDigest", "capabilityBase64Url", "capabilityByteCount",
    "witnessRequestBase64Url", "witnessRequestByteCount", "historicalExpectations"})
_HISTORICAL_PAIRS = (("expectedRequest", "expected_request"),
    *(pair for pair in capability.retention._CONTEXT_PAIRS
      if pair[0] not in {"expectedPlannerIdentity", "expectedVerifierIdentity"}))
HISTORICAL_FIELDS = frozenset({"databaseCutoffUs", *(name for name, _ in _HISTORICAL_PAIRS)})
_CALL_FIELDS = frozenset({"database_now", *(name for _, name in _HISTORICAL_PAIRS)})
_POSITIVE_HISTORY = ("expectedFence", "reservedAtEpochNs", "deadlineEpochNs", "deadlineMonotonicNs",
    "nowEpochNs", "nowMonotonicNs", "maximumAssertionAgeNs", "maximumPlanAgeNs", "databaseCutoffUs")
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"


class RevocationInvocationError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class InvocationProductionMetrics:
    capture: QueryReadValidationMetrics
    transport: QueryReadValidationMetrics
    key_binding: QueryReadValidationMetrics
    signing: QueryReadValidationMetrics
    signing_attempts: int
    signature_verifications: int
    total_hashes: int
    total_input_bytes: int
    total_json_nodes: int


@dataclass(frozen=True, slots=True)
class InvocationVerificationMetrics:
    transport: QueryReadValidationMetrics
    authentication: QueryReadValidationMetrics
    bindings: QueryReadValidationMetrics
    signature_attempts: int
    total_hashes: int
    total_input_bytes: int
    total_json_nodes: int


@dataclass(frozen=True, slots=True)
class _ProducedInvocation:
    envelope_bytes: bytes
    metrics: InvocationProductionMetrics


@dataclass(frozen=True, slots=True)
class _AuthenticatedInvocation:
    """Ordinary owned claims; no API accepts this object as authority."""

    envelope: dict
    envelope_bytes: bytes
    capability_bytes: bytes
    witness_request_bytes: bytes
    execution_envelope_id: str
    witness_receipt_digest: str
    historical_expectations: dict
    metrics: InvocationVerificationMetrics


def _history_shape(value):
    shape = capability.shape
    shape._object(value, HISTORICAL_FIELDS, "invocation history")
    for name in _POSITIVE_HISTORY:
        shape._integer(value[name], minimum=1)
    shape._integer(value["maximumClockSkewNs"])
    for name in ("expectedCapabilityId", "expectedPlannerTransactionId"):
        shape._digest(value[name])
    if value["expectedApproverPolicyDigest"] is not None:
        shape._digest(value["expectedApproverPolicyDigest"])
    shape._request(value["expectedRequest"])
    capability.plan.semantics._expected_before(value["expectedBefore"])
    # Integer timedelta arithmetic is lossless; never use a float timestamp.
    cutoff = value["databaseCutoffUs"]
    instant = _EPOCH + timedelta(microseconds=cutoff)
    if capability.plan.semantics.complete.cutoff_microseconds(instant) != cutoff:
        raise RevocationInvocationError("invocation database cutoff did not round-trip")
    return instant


def _capture_history(expectations, ledger):
    capability.shape._object(expectations, _CALL_FIELDS, "invocation caller expectations")
    instant = expectations["database_now"]
    if type(instant) is not datetime or instant.tzinfo is not timezone.utc:
        raise RevocationInvocationError("invocation requires the original exact UTC database instant")
    document = {name: expectations[argument] for name, argument in _HISTORICAL_PAIRS}
    document["databaseCutoffUs"] = capability.plan.semantics.complete.cutoff_microseconds(instant)
    # Historical claims are at depth two in the actual envelope. This owns
    # mutable caller graphs before any external key callback, on existing work.
    owned = capability.capture._JSONCapture(ledger).visit(document, depth=2)
    _history_shape(owned)
    return owned


def _raw(value, maximum):
    if type(value) is not bytes or not 2 <= len(value) <= maximum:
        raise RevocationInvocationError("invocation transport is not exact bounded original bytes")


def _encode(raw, work):
    padded = 4 * ((len(raw) + 2) // 3)
    length = padded - ((3 - len(raw) % 3) % 3)
    # Input, padded output, URL translation, strip and ASCII decode.
    work.charge(input_bytes=len(raw) + 3 * padded + length)
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _transport_shape(value, count, maximum):
    if (type(count) is not int or not 2 <= count <= maximum
            or type(value) is not str or len(value) != (4 * count + 2) // 3):
        raise RevocationInvocationError("invocation base64 or byte count exceeds its exact bound")


def _decode(value, count, maximum, work):
    _transport_shape(value, count, maximum)
    length = len(value)
    padded = length + (-length % 4)
    decoded = 3 * (padded // 4)
    reencoded = 4 * ((decoded + 2) // 3)
    # Same bounded codec passes as durable raw retention, without importing
    # its database-bound error factory. Reserve before scanning/allocating.
    work.charge(input_bytes=2 * length + 4 * padded + 2 * decoded + 5 * reencoded)
    if any(character not in _ALPHABET for character in value):
        raise RevocationInvocationError("invocation base64 alphabet is invalid")
    raw = base64.b64decode(value + "=" * (-length % 4), altchars=b"-_", validate=True)
    if len(raw) != count or base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") != value:
        raise RevocationInvocationError("invocation base64 is not canonical original transport")
    return raw


def _shape(envelope):
    shape = capability.shape
    shape._object(envelope, ENVELOPE_FIELDS, "issuance invocation envelope")
    shape._literal(envelope["schema"], ENVELOPE_SCHEMA)
    shape._literal(envelope["purpose"], PURPOSE)
    for name in ("envelopeId", "parentEnvelopeId", "configurationDigest"):
        shape._digest(envelope[name])
    for name in ("issuedAtEpochNs", "issuedMonotonicNs", "deadlineMonotonicNs", "fence"):
        shape._integer(envelope[name], minimum=1)
    if envelope["issuedMonotonicNs"] >= envelope["deadlineMonotonicNs"]:
        raise RevocationInvocationError("invocation issuance is not before its deadline")
    shape._base64url(envelope["signature"], signature=True)
    payload = envelope["payload"]
    shape._object(payload, PAYLOAD_FIELDS, "issuance invocation payload")
    shape._literal(payload["schema"], SCHEMA)
    shape._literal(payload["sourceRevision"], capability.authority.SOURCE_REVISION)
    shape._integer(payload["generationSequence"], minimum=1)
    for name in ("generationDigest", "executionEnvelopeId", "witnessReceiptDigest"):
        shape._digest(payload[name])
    _transport_shape(payload["capabilityBase64Url"], payload["capabilityByteCount"], capability.MAX_CAPABILITY_BYTES)
    _transport_shape(payload["witnessRequestBase64Url"], payload["witnessRequestByteCount"], capability.MAX_WITNESS_REQUEST_BYTES)
    return _history_shape(payload["historicalExpectations"])


def _bind(envelope, configuration, sequence, generation, work):
    payload, historical = envelope["payload"], envelope["payload"]["historicalExpectations"]
    capability.plan._same((envelope["configurationDigest"], payload["generationSequence"], payload["generationDigest"],
        envelope["envelopeId"], envelope["parentEnvelopeId"], envelope["fence"], envelope["deadlineMonotonicNs"]),
        (configuration, sequence, generation, historical["expectedCapabilityId"], historical["expectedPlannerTransactionId"],
         historical["expectedFence"], historical["deadlineMonotonicNs"]), work,
        "invocation header differs from independent pins or signed historical bindings")


def _fresh(envelope, now_epoch, now_monotonic, age, skew):
    remaining_mono = envelope["deadlineMonotonicNs"] - now_monotonic
    remaining_epoch = envelope["payload"]["historicalExpectations"]["deadlineEpochNs"] - now_epoch
    if (envelope["issuedMonotonicNs"] > now_monotonic
            or now_monotonic - envelope["issuedMonotonicNs"] > age
            or envelope["issuedAtEpochNs"] > now_epoch + skew
            or now_epoch - envelope["issuedAtEpochNs"] > age
            or remaining_mono <= 0 or remaining_epoch <= 0
            or remaining_mono > age or remaining_epoch > age + skew
            or abs(remaining_epoch - remaining_mono) > skew):
        raise RevocationInvocationError("invocation current clocks or deadline are not fresh and consistent")


def _sign_wire(unsigned, private_key, public_key, work):
    envelope = {**unsigned, "signature": "A" * 86}
    _shape(envelope)
    unsigned_size, unsigned_nodes = work.measure(unsigned)
    envelope_size, envelope_nodes = work.measure(envelope)
    if (max(unsigned_size, envelope_size) > MAX_ENVELOPE_BYTES
            or max(unsigned_nodes, envelope_nodes) > MAX_JSON_NODES):
        raise RevocationInvocationError("invocation output exceeds its full-wrapper bound")
    work.charge(input_bytes=4 * unsigned_size + envelope_size + production._SIGNATURE_TRANSPORT_BYTES,
                json_nodes=2 * unsigned_nodes + envelope_nodes)
    frame_bytes = 2 * len(ENVELOPE_SCHEMA) + 9 + unsigned_size + 2 * 71
    if (work.limits.max_hashes - work.hash_work < 1
            or work.limits.max_input_bytes - work.input_bytes < frame_bytes + unsigned_size
            or work.limits.max_json_nodes - work.json_nodes < 4 + unsigned_nodes):
        raise QueryReadWorkError("invocation cannot reserve its complete signed output")
    unsigned_wire = capability.plan.core.canonical_bytes(unsigned)
    if len(unsigned_wire) != unsigned_size:
        raise RevocationInvocationError("invocation unsigned graph changed after measurement")
    message = capability.plan._ascii(capability.plan._frame(ENVELOPE_SCHEMA, (unsigned_wire,), work), work)
    signature = production._sign_and_verify(private_key, public_key, message, work)
    current_size, current_nodes = work.measure(unsigned)
    if (current_size, current_nodes) != (unsigned_size, unsigned_nodes):
        raise RevocationInvocationError("invocation unsigned graph changed during signing")
    current_wire = capability.plan.core.canonical_bytes(unsigned)
    if current_wire != unsigned_wire:
        raise RevocationInvocationError("invocation unsigned graph changed during signing")
    encoded = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
    capability.shape._base64url(encoded, signature=True)
    encoded_envelope = capability.plan.core.canonical_bytes({**unsigned, "signature": encoded})
    if len(encoded_envelope) != envelope_size:
        raise RevocationInvocationError("invocation final envelope changed after measurement")
    return encoded_envelope


def _produce_invocation_on_work(*, capability_bytes, witness_request_bytes, execution_envelope_id,
        witness_receipt_digest, historical_expectations, signer_private_key, signer_public_key,
        configuration_digest, generation_sequence, generation_digest, issued_at_epoch_ns,
        issued_monotonic_ns, work: _ValidationWork) -> _ProducedInvocation:
    """Sign owned sender claims; never manufacture independent replay inputs."""
    try:
        ledger = capability.capture._SharedLedger(work)
        if not isinstance(signer_private_key, Ed25519PrivateKey) or not isinstance(signer_public_key, Ed25519PublicKey):
            raise RevocationInvocationError("invocation producer requires actual independently pinned Ed25519 keys")
        _raw(capability_bytes, capability.MAX_CAPABILITY_BYTES)
        _raw(witness_request_bytes, capability.MAX_WITNESS_REQUEST_BYTES)
        for digest in (execution_envelope_id, witness_receipt_digest, configuration_digest, generation_digest):
            capability.shape._digest(digest)
        for integer in (generation_sequence, issued_at_epoch_ns, issued_monotonic_ns):
            capability.shape._integer(integer, minimum=1)
        before = work.metrics
        historical = _capture_history(historical_expectations, ledger)
        captured = capability.plan.mixed._delta(before, work.metrics)
        before = work.metrics
        payload = {"schema": SCHEMA, "sourceRevision": capability.authority.SOURCE_REVISION,
            "generationSequence": generation_sequence, "generationDigest": generation_digest,
            "executionEnvelopeId": execution_envelope_id, "witnessReceiptDigest": witness_receipt_digest,
            "capabilityBase64Url": _encode(capability_bytes, work), "capabilityByteCount": len(capability_bytes),
            "witnessRequestBase64Url": _encode(witness_request_bytes, work), "witnessRequestByteCount": len(witness_request_bytes),
            "historicalExpectations": historical}
        unsigned = {"schema": ENVELOPE_SCHEMA, "envelopeId": historical["expectedCapabilityId"],
            "parentEnvelopeId": historical["expectedPlannerTransactionId"], "purpose": PURPOSE,
            "configurationDigest": configuration_digest, "issuedAtEpochNs": issued_at_epoch_ns,
            "issuedMonotonicNs": issued_monotonic_ns, "deadlineMonotonicNs": historical["deadlineMonotonicNs"],
            "fence": historical["expectedFence"], "payload": payload}
        transported = capability.plan.mixed._delta(before, work.metrics)
        before = work.metrics
        # Two actual raw32 outputs and their full comparison, before callbacks.
        work.charge(input_bytes=2 * 32 + 2 * 32)
        derived = production._callback(work, lambda: signer_private_key.public_key())
        if not isinstance(derived, Ed25519PublicKey):
            raise RevocationInvocationError("invocation private key did not derive an Ed25519 public key")
        actual = production._callback(work, lambda: derived.public_bytes(Encoding.Raw, PublicFormat.Raw))
        expected = production._callback(work, lambda: signer_public_key.public_bytes(Encoding.Raw, PublicFormat.Raw))
        if any(type(raw) is not bytes or len(raw) != 32 for raw in (actual, expected)) or actual != expected:
            raise RevocationInvocationError("invocation signing key differs from its independent public pin")
        bound = capability.plan.mixed._delta(before, work.metrics)
        before = work.metrics
        raw = _sign_wire(unsigned, signer_private_key, signer_public_key, work)
        signed = capability.plan.mixed._delta(before, work.metrics)
        return _ProducedInvocation(raw, InvocationProductionMetrics(captured, transported, bound, signed,
            1, 1, work.hash_work, work.input_bytes, work.json_nodes))
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError, RecursionError, InvalidSignature) as exc:
        if isinstance(exc, RevocationInvocationError):
            raise
        raise RevocationInvocationError("revocation invocation production failed") from exc


def _verify_invocation_on_work(*, envelope_bytes, verifier_public_key, expected_configuration_digest,
        expected_generation_sequence, expected_generation_digest, now_epoch_ns, now_monotonic_ns,
        maximum_age_ns, maximum_clock_skew_ns, work: _ValidationWork) -> _AuthenticatedInvocation:
    """Authenticate original bytes and retain the complete bound outer header.

    The supplied current clock/policy inputs never replace signed historical
    clocks. Returned graphs are local observations, not accepted authority.
    """
    try:
        ledger = capability.capture._SharedLedger(work)
        if not isinstance(verifier_public_key, Ed25519PublicKey):
            raise RevocationInvocationError("invocation verifier key is not independently pinned Ed25519")
        for digest in (expected_configuration_digest, expected_generation_digest):
            capability.shape._digest(digest)
        for integer in (expected_generation_sequence, now_epoch_ns, now_monotonic_ns, maximum_age_ns):
            capability.shape._integer(integer, minimum=1)
        capability.shape._integer(maximum_clock_skew_ns)
        before = work.metrics
        envelope = capability.wire._decode_object(envelope_bytes, work=work,
            maximum_bytes=MAX_ENVELOPE_BYTES, maximum_nodes=MAX_JSON_NODES, maximum_depth=MAX_JSON_DEPTH)
        database_now = _shape(envelope)
        capability._canonical(envelope_bytes, envelope, ledger, MAX_ENVELOPE_BYTES, MAX_JSON_NODES)
        work.prepare_copy(envelope)
        unsigned = envelope.copy()
        signature = unsigned.pop("signature")
        unsigned_wire = capability._wire(unsigned, ledger, MAX_ENVELOPE_BYTES, MAX_JSON_NODES)
        transported = capability.plan.mixed._delta(before, work.metrics)
        before = work.metrics
        capability._signature(verifier_public_key, signature, ENVELOPE_SCHEMA, unsigned_wire, ledger)
        authenticated = capability.plan.mixed._delta(before, work.metrics)
        before = work.metrics
        _bind(envelope, expected_configuration_digest, expected_generation_sequence, expected_generation_digest, work)
        _fresh(envelope, now_epoch_ns, now_monotonic_ns, maximum_age_ns, maximum_clock_skew_ns)
        payload = envelope["payload"]
        original_capability = _decode(payload["capabilityBase64Url"], payload["capabilityByteCount"],
            capability.MAX_CAPABILITY_BYTES, work)
        original_request = _decode(payload["witnessRequestBase64Url"], payload["witnessRequestByteCount"],
            capability.MAX_WITNESS_REQUEST_BYTES, work)
        historical = {argument: payload["historicalExpectations"][name] for name, argument in _HISTORICAL_PAIRS}
        historical["database_now"] = database_now
        bound = capability.plan.mixed._delta(before, work.metrics)
        return _AuthenticatedInvocation(envelope, envelope_bytes, original_capability, original_request,
            payload["executionEnvelopeId"], payload["witnessReceiptDigest"], historical,
            InvocationVerificationMetrics(transported, authenticated, bound, 1,
                work.hash_work, work.input_bytes, work.json_nodes))
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError, RecursionError, InvalidSignature) as exc:
        if isinstance(exc, RevocationInvocationError):
            raise
        raise RevocationInvocationError("revocation invocation authentication failed") from exc
