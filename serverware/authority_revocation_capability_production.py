"""Private original-byte capability/v4 production on existing work.

The verifier-owned signer authenticates a preliminary witness reservation and
genuinely replays the original retained plan before signing a capability. The
caller must independently admit keys, identities, original expectations and
the exact execution reservation. No SQL, clock, enrollment, issuance, post-plan
witness bind or execution authority is supplied by this module or its output.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from serverware import authority_revocation_capability as capability
from serverware.authority_query_read_work import QueryReadValidationMetrics, QueryReadWorkError, _ValidationWork


MAX_CAPABILITY_BYTES = capability.MAX_CAPABILITY_BYTES
MAX_WITNESS_REQUEST_BYTES = capability.MAX_WITNESS_REQUEST_BYTES
MAX_WITNESS_RECEIPT_BYTES = 64 * 1024
MAX_JSON_NODES = capability.MAX_JSON_NODES
MAX_JSON_DEPTH = capability.MAX_JSON_DEPTH
_SIGNATURE_PLACEHOLDER = "A" * 86
# Signature64 output + encoder input64 + padded output88 + URL translation88
# + ASCII decode88 + rstrip88 + final canonical-alphabet scan86.
_SIGNATURE_TRANSPORT_BYTES = 2 * 64 + 4 * 88 + 86


@dataclass(frozen=True, slots=True)
class RevocationCapabilityProductionMetrics:
    capture: QueryReadValidationMetrics
    transport: QueryReadValidationMetrics
    key_binding: QueryReadValidationMetrics
    witness_verification: QueryReadValidationMetrics
    retained_verification: QueryReadValidationMetrics
    bindings: QueryReadValidationMetrics
    signing: QueryReadValidationMetrics
    request_signature_attempts: int
    witness_signature_attempts: int
    signing_attempts: int
    signature_verifications: int
    total_hashes: int
    total_input_bytes: int
    total_json_nodes: int


@dataclass(frozen=True, slots=True)
class _ProducedCapability:
    """Immutable original transports, freely constructible and never authority."""

    envelope_bytes: bytes
    payload_bytes: bytes
    retained_envelope_bytes: bytes
    evaluation_context_bytes: bytes
    execution_request_bytes: bytes
    witness_request_bytes: bytes
    witness_receipt_bytes: bytes
    capability_digest: str
    metrics: RevocationCapabilityProductionMetrics


def _callback(work, callback):
    limits, metrics = work.limits, work.metrics
    values = (limits.max_hashes, limits.max_input_bytes, limits.max_json_nodes)
    result = callback()
    capability.capture._SharedLedger(work)
    if (work.limits is not limits or work.metrics != metrics
            or (work.limits.max_hashes, work.limits.max_input_bytes, work.limits.max_json_nodes) != values):
        raise capability.RevocationCapabilityError("revocation capability production work changed during key callback")
    return result


def _key_binding(private_key, public_key, witness_key, work):
    # Three actual raw32 outputs and two full byte comparisons. Native key
    # internals are excluded, but every external key operation is guarded.
    work.charge(input_bytes=3 * 32 + 2 * 64)
    derived = _callback(work, lambda: private_key.public_key())
    if not isinstance(derived, Ed25519PublicKey):
        raise capability.RevocationCapabilityError("revocation capability signer did not derive an Ed25519 public key")
    actual = _callback(work, lambda: derived.public_bytes(Encoding.Raw, PublicFormat.Raw))
    expected = _callback(work, lambda: public_key.public_bytes(Encoding.Raw, PublicFormat.Raw))
    witness = _callback(work, lambda: witness_key.public_bytes(Encoding.Raw, PublicFormat.Raw))
    if any(type(raw) is not bytes or len(raw) != 32 for raw in (actual, expected, witness)):
        raise capability.RevocationCapabilityError("revocation capability signing keys are not exact raw32")
    if actual != expected:
        raise capability.RevocationCapabilityError("revocation capability signing key differs from its independent public pin")
    if expected == witness:
        raise capability.RevocationCapabilityError("revocation capability signer and witness keys are not separate")


def _sign_and_verify(private_key, public_key, message, work):
    signature = _callback(work, lambda: private_key.sign(message))
    if type(signature) is not bytes or len(signature) != 64:
        raise capability.RevocationCapabilityError("revocation capability signer returned a noncanonical signature")
    try:
        _callback(work, lambda: public_key.verify(signature, message))
    except InvalidSignature as exc:
        raise capability.RevocationCapabilityError("revocation capability signature differs from its independent public pin") from exc
    return signature


def _sign_wire(payload, identity, private_key, public_key, work):
    plan = capability.plan
    unsigned = {"schema": capability.SIGNED_SCHEMA, "sourceRevision": capability.authority.SOURCE_REVISION,
                "signerIdentity": identity, "payload": payload}
    envelope = {**unsigned, "signatureBase64Url": _SIGNATURE_PLACEHOLDER}
    # This source-owned envelope has fixed depth: every nested receipt and
    # identity is a closed scalar object. Check its actual full shape before
    # measuring/reserving either final encoder or invoking the signer.
    capability._shape(envelope)
    unsigned_size, unsigned_nodes = work.measure(unsigned)
    envelope_size, envelope_nodes = work.measure(envelope)
    if (max(unsigned_size, envelope_size) > MAX_CAPABILITY_BYTES
            or max(unsigned_nodes, envelope_nodes) > MAX_JSON_NODES):
        raise capability.RevocationCapabilityError("revocation capability production exceeds its output bound")
    work.charge(input_bytes=4 * unsigned_size + envelope_size + _SIGNATURE_TRANSPORT_BYTES,
                json_nodes=2 * unsigned_nodes + envelope_nodes)
    frame_bytes = 2 * len(capability.SIGNED_SCHEMA) + 9 + unsigned_size + 2 * 71
    if (work.limits.max_hashes - work.hash_work < 1
            or work.limits.max_input_bytes - work.input_bytes < frame_bytes + unsigned_size
            or work.limits.max_json_nodes - work.json_nodes < 4 + unsigned_nodes):
        raise QueryReadWorkError("revocation capability production cannot reserve its complete signature output")
    unsigned_wire = plan.core.canonical_bytes(unsigned)
    if len(unsigned_wire) != unsigned_size:
        raise capability.RevocationCapabilityError("revocation capability unsigned bytes changed after measurement")
    message = plan._ascii(plan._frame(capability.SIGNED_SCHEMA, (unsigned_wire,), work), work)
    signature = _sign_and_verify(private_key, public_key, message, work)
    current_size, current_nodes = work.measure(unsigned)
    if (current_size, current_nodes) != (unsigned_size, unsigned_nodes):
        raise capability.RevocationCapabilityError("revocation capability unsigned graph changed during signing")
    current_wire = plan.core.canonical_bytes(unsigned)
    if current_wire != unsigned_wire:
        raise capability.RevocationCapabilityError("revocation capability unsigned graph changed during signing")
    encoded = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
    capability.shape._base64url(encoded, signature=True)
    # Rebuild only fixed field scaffolding after the checked callback; never
    # reuse a mutable placeholder envelope as if it were signed evidence.
    envelope = {**unsigned, "signatureBase64Url": encoded}
    envelope_wire = plan.core.canonical_bytes(envelope)
    if len(envelope_wire) != envelope_size:
        raise capability.RevocationCapabilityError("revocation capability envelope changed after measurement")
    return envelope_wire


def _produce_signed_capability_on_work(*, work: _ValidationWork,
        retained_envelope_bytes: bytes, evaluation_context_bytes: bytes, execution_request_bytes: bytes,
        witness_request_bytes: bytes, witness_receipt_bytes: bytes, signer_private_key: Ed25519PrivateKey,
        signer_public_key: Ed25519PublicKey, witness_public_key: Ed25519PublicKey,
        expected_signer_identity, expected_issuer_session_identity_digest: str,
        expected_execution_envelope_id: str, expected_witness_receipt_digest: str,
        expected_witness_identity_digest: str, expected_configuration_digest: str,
        expected_generation_sequence: int, expected_generation_digest: str,
        retention_expectations: dict) -> _ProducedCapability:
    """Authenticate original bytes and derive one capability before signing.

    The exact execution reservation is independently supplied, not proved to
    exist by a matching JSON wrapper. Every external expectation is owned
    before key callbacks. Witness request and receipt verification, followed
    by one genuine retained replay and the exact wrapper binding, precede any
    signing. The private key must match its independently admitted public pin
    and differ from the witness key. All work stays on the supplied meter;
    failure refunds nothing. Fixed field scaffolding and native cryptographic
    internals are excluded from H/B/N; signature attempts are explicit.
    """
    cap, plan = capability, capability.plan
    try:
        ledger = cap.capture._SharedLedger(work)
        if (not isinstance(signer_private_key, Ed25519PrivateKey)
                or not isinstance(signer_public_key, Ed25519PublicKey)
                or not isinstance(witness_public_key, Ed25519PublicKey)):
            raise cap.RevocationCapabilityError("revocation capability production requires actual Ed25519 keys")
        cap.shape._object(retention_expectations, cap.wire._EXPECTATIONS, "retention expectations")
        handles = {field: retention_expectations[field] for field in cap._HANDLE_FIELDS}
        plan._verification_types(**handles)
        for raw, maximum in ((retained_envelope_bytes, cap.shape.MAX_PAYLOAD_BYTES),
                (evaluation_context_bytes, cap.retention.MAX_CONTEXT_BYTES),
                (execution_request_bytes, cap.authority.MAX_REQUEST_BYTES),
                (witness_request_bytes, MAX_WITNESS_REQUEST_BYTES),
                (witness_receipt_bytes, MAX_WITNESS_RECEIPT_BYTES)):
            if type(raw) is not bytes or not 2 <= len(raw) <= maximum:
                raise cap.RevocationCapabilityError("revocation capability production requires bounded original bytes")
        before = work.metrics
        owned = cap._capture_expectations(ledger, retention_expectations,
            expected_signer_identity=expected_signer_identity,
            expected_issuer_session_identity_digest=expected_issuer_session_identity_digest,
            expected_execution_envelope_id=expected_execution_envelope_id,
            expected_witness_receipt_digest=expected_witness_receipt_digest,
            expected_witness_identity_digest=expected_witness_identity_digest,
            expected_configuration_digest=expected_configuration_digest,
            expected_generation_sequence=expected_generation_sequence,
            expected_generation_digest=expected_generation_digest)
        captured = plan.mixed._delta(before, work.metrics)
        before = work.metrics
        request = cap.wire._decode_object(witness_request_bytes, work=work,
            maximum_bytes=MAX_WITNESS_REQUEST_BYTES, maximum_nodes=MAX_JSON_NODES, maximum_depth=MAX_JSON_DEPTH)
        receipt = cap.wire._decode_object(witness_receipt_bytes, work=work,
            maximum_bytes=MAX_WITNESS_RECEIPT_BYTES, maximum_nodes=MAX_JSON_NODES, maximum_depth=MAX_JSON_DEPTH)
        execution = cap.wire._decode_object(execution_request_bytes, work=work,
            maximum_bytes=cap.authority.MAX_REQUEST_BYTES)
        cap._witness_shape(request, request=True)
        cap._witness_shape(receipt, request=False)
        cap._canonical(witness_request_bytes, request, ledger, MAX_WITNESS_REQUEST_BYTES, MAX_JSON_NODES)
        cap._canonical(witness_receipt_bytes, receipt, ledger, MAX_WITNESS_RECEIPT_BYTES, MAX_JSON_NODES)
        cap._canonical(execution_request_bytes, execution, ledger, cap.authority.MAX_REQUEST_BYTES, cap.shape.MAX_JSON_NODES)
        transported = plan.mixed._delta(before, work.metrics)
        before = work.metrics
        # Serialize all key pins before any proof-derived payload exists.
        # The only later private-key callback receives immutable message bytes
        # and is surrounded by the full unsigned-graph equality check.
        _key_binding(signer_private_key, signer_public_key, witness_public_key, work)
        keys = plan.mixed._delta(before, work.metrics)
        before = work.metrics
        witness_digest = cap._witness(request, receipt, owned, signer_public_key, witness_public_key, ledger)
        witnessed = plan.mixed._delta(before, work.metrics)
        before = work.metrics
        record = cap.retention._verify_record_on_work(envelope_bytes=retained_envelope_bytes,
            evaluation_context_bytes=evaluation_context_bytes, work=work, **owned["retention"], **handles)
        replayed = plan.mixed._delta(before, work.metrics)
        before = work.metrics
        payload = cap._expected_payload(record, execution, execution_request_bytes, receipt,
                                        witness_digest, owned, ledger)
        payload_bytes = cap._wire(payload, ledger, MAX_CAPABILITY_BYTES, MAX_JSON_NODES)
        capability_digest = plan._frame(cap.CAPABILITY_SCHEMA, (payload_bytes,), work)
        bound = plan.mixed._delta(before, work.metrics)
        before = work.metrics
        envelope_bytes = _sign_wire(payload, owned["expectedSignerIdentity"], signer_private_key,
                                    signer_public_key, work)
        signed = plan.mixed._delta(before, work.metrics)
        cap.capture._SharedLedger(work)
        return _ProducedCapability(envelope_bytes, payload_bytes, retained_envelope_bytes,
            evaluation_context_bytes, execution_request_bytes, witness_request_bytes, witness_receipt_bytes,
            capability_digest, RevocationCapabilityProductionMetrics(captured, transported, keys,
                witnessed, replayed, bound, signed, 1, 1, 1, 1, work.hash_work, work.input_bytes, work.json_nodes))
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError, RecursionError, InvalidSignature) as exc:
        if isinstance(exc, capability.RevocationCapabilityError):
            raise
        raise capability.RevocationCapabilityError("revocation capability production failed") from exc
