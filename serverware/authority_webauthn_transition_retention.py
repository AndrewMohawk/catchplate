"""Genuine raw-four verification and content identity for transition custody.

The signed envelope, original proof, original inputs and full evaluation
context remain separate immutable byte strings. Independently admitted five
expectations and actual planner/operation keys are owned before callbacks.
Stored context never supplies those expectations or historical provenance.

The existing plan verifier authenticates every original commitment, compares
the entire canonical context to independent expectations, and performs actual
primary/count/query, semantic and write-root replay. Only then are real raw
key and byte hashes committed in the dedicated eighteen-field record header.
The returned carrier is locally computed data, never accepted as proof input.

No clock, signing, SQL, persistence, capability, reservation, current-root
admission, business execution or replacement work allowance is provided here.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from serverware import authority_webauthn_transition_plan as plan
from serverware import authority_webauthn_transition_plan_context as context_wire
from serverware.authority_query_read_work import QueryReadValidationMetrics


evidence = plan.evidence
RECORD_SCHEMA = "serverware.policyAuthorityWebAuthnTransitionRetainedPlan/v1"
PLAN_PROTOCOL = "webauthn-transition-v1"
MAX_ORIGINAL_BYTES = evidence.authority.MAX_RESULT_BYTES


class WebAuthnTransitionRetentionError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class _RetainedTransitionPlan:
    """Actual local verification observations, not a durable custody receipt."""

    envelope_bytes: bytes
    proof_bytes: bytes
    inputs_bytes: bytes
    context_bytes: bytes
    header: dict
    record_digest: str
    verification: plan._VerifiedTransitionPlan
    metrics: QueryReadValidationMetrics


def _raw4(envelope_bytes, proof_bytes, inputs_bytes, context_bytes):
    originals = envelope_bytes, proof_bytes, inputs_bytes, context_bytes
    limits = (plan.contract.MAX_BYTES, plan.proof.contract.MAX_BYTES,
        plan.proof.wire.MAX_BYTES, context_wire.MAX_BYTES)
    for raw, maximum in zip(originals, limits):
        if type(raw) is not bytes or not 2 <= len(raw) <= maximum:
            raise WebAuthnTransitionRetentionError("transition custody requires bounded immutable originals")
    if sum(len(raw) for raw in originals) > MAX_ORIGINAL_BYTES:
        raise WebAuthnTransitionRetentionError("transition custody originals exceed their aggregate bound")
    return originals


def _bytes_digest(raw, work):
    work.charge(hashes=1, input_bytes=len(raw))
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _key_digest(key, work):
    # Prepay the real raw export. Both getter and invocation remain inside
    # the actual finally guard; no stored key digest substitutes for this key.
    work.charge(input_bytes=32)
    raw = evidence.production._callback(work,
        lambda: key.public_bytes(Encoding.Raw, PublicFormat.Raw))
    if type(raw) is not bytes or len(raw) != 32:
        raise WebAuthnTransitionRetentionError("transition custody key is not exact raw32")
    return _bytes_digest(raw, work)


def _verify_record_on_work(*, envelope_bytes, proof_bytes, inputs_bytes, context_bytes,
        expectations, planner_public_key, operation_public_key, work):
    """Replay original raw4 against independently owned historical context.

    Returned metrics include all earlier work on this same invocation. There
    is no currentness refresh, successful-record input or retry allowance.
    Fixed scaffolding is not a whole-process or native-allocation bound.
    """
    try:
        ledger = evidence.capture._SharedLedger(work)
        envelope, proof, inputs, context = _raw4(
            envelope_bytes, proof_bytes, inputs_bytes, context_bytes)
        planner_key, operation_key = planner_public_key, operation_public_key
        if (not isinstance(planner_key, plan.Ed25519PublicKey)
                or not isinstance(operation_key, plan.Ed25519PublicKey)):
            raise WebAuthnTransitionRetentionError("transition custody needs independently pinned Ed25519 keys")
        plan.contract.shape._object(expectations, plan.contract.EXPECTATION_FIELDS,
            "independent retained transition expectations")
        owned = evidence.capture._JSONCapture(ledger).visit(expectations)
        operation = plan.contract._validate_expectations(owned)
        request = owned["proofExpectations"]["request"]
        operation_id, request_digest = request["operationId"], request["requestDigest"]
        configuration_digest = owned["configurationDigest"]
        # This real verifier owns independent5 again, authenticates all four
        # originals before context/proof use, and performs full genuine replay.
        # Never replace its expectations with decoded retained context.
        verification = plan._verify_on_work(envelope_bytes=envelope, proof_bytes=proof,
            inputs_bytes=inputs, context_bytes=context, expectations=owned,
            planner_public_key=planner_key, public_key=operation_key, work=work)
        planner_digest = _key_digest(planner_key, work)
        operation_digest = _key_digest(operation_key, work)
        envelope_digest = _bytes_digest(envelope, work)
        proof_digest = _bytes_digest(proof, work)
        inputs_digest = _bytes_digest(inputs, work)
        context_digest = _bytes_digest(context, work)
        header = {"schema": RECORD_SCHEMA, "sourceRevision": evidence.authority.SOURCE_REVISION,
            "planProtocol": PLAN_PROTOCOL, "operation": operation,
            "operationId": operation_id, "requestDigest": request_digest,
            "configurationDigest": configuration_digest,
            "plannerKeyDigest": planner_digest, "operationKeyDigest": operation_digest,
            "planDigest": verification.plan_digest,
            "envelopeBytesDigest": envelope_digest, "envelopeByteCount": len(envelope),
            "proofBytesDigest": proof_digest, "proofByteCount": len(proof),
            "inputsBytesDigest": inputs_digest, "inputsByteCount": len(inputs),
            "contextBytesDigest": context_digest, "contextByteCount": len(context)}
        record_digest = evidence.plan._json_digest(RECORD_SCHEMA, header, ledger)
        return _RetainedTransitionPlan(envelope, proof, inputs, context, header,
            record_digest, verification, work.metrics)
    except evidence.keys._FAILURES as exc:
        if isinstance(exc, WebAuthnTransitionRetentionError):
            raise
        raise WebAuthnTransitionRetentionError("retained transition plan verification failed") from exc
