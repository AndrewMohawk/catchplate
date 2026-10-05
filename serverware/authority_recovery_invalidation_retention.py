"""Original-four framing and genuine invalidation-plan replay.

The envelope, typed request, proof and canonical context remain separate
immutable originals. Independently held expectations and the actual planner
key are captured before callbacks; stored context never selects those pins.
The real plan verifier authenticates the signature and replays primary,
terminal and counted-write proofs before any retained record is returned.

This is live verification within the unchanged original interval, not a
historical-expiry exception. Framing and hashing remain inside that interval
and on the same cumulative work. No persistence, recovery-witness custody,
current-root authority, execution permission or registry activation is given.
Returned observations are local data, never accepted as verification inputs.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from serverware import authority_recovery_invalidation_plan as plan
from serverware.authority_query_read_work import QueryReadValidationMetrics


evidence = plan.evidence
RECORD_SCHEMA = "serverware.policyAuthorityRecoveryInvalidationRetainedPlan/v1"
PLAN_PROTOCOL = "recovery-invalidation-v1"
_ORIGINAL_LIMITS = (plan.MAX_PARENT_BYTES, plan.proof.contract.MAX_REQUEST_BYTES,
    plan.proof.MAX_INPUT_BYTES, plan.MAX_CONTEXT_BYTES)
MAX_ORIGINAL_BYTES = sum(_ORIGINAL_LIMITS)


class RecoveryInvalidationRetentionError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class _RetainedInvalidationPlan:
    """Locally replayed originals, not a durable receipt or authority token."""

    envelope_bytes: bytes
    request_bytes: bytes
    proof_bytes: bytes
    context_bytes: bytes
    request: dict
    context: dict
    payload: dict
    header: dict
    record_digest: str
    verification: plan.VerifiedRecoveryInvalidationPlan
    original_interval: tuple[int, int]
    original_deadline_ns: int
    metrics: QueryReadValidationMetrics


def _raw4(envelope_bytes, request_bytes, proof_bytes, context_bytes):
    originals = envelope_bytes, request_bytes, proof_bytes, context_bytes
    for raw, maximum in zip(originals, _ORIGINAL_LIMITS):
        if type(raw) is not bytes or not 2 <= len(raw) <= maximum:
            raise RecoveryInvalidationRetentionError(
                "invalidation retention requires bounded immutable originals")
    return originals


def _bytes_digest(raw, work):
    work.charge(hashes=1, input_bytes=len(raw))
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _key_digest(key, work):
    # Export the independently held key actually used by the verifier. A
    # stored key digest never substitutes for this guarded native operation.
    work.charge(input_bytes=32)
    raw = evidence.production._callback(work,
        lambda: key.public_bytes(Encoding.Raw, PublicFormat.Raw))
    if type(raw) is not bytes or len(raw) != 32:
        raise RecoveryInvalidationRetentionError("invalidation planner key is not exact raw32")
    return _bytes_digest(raw, work)


def _verify_record_on_work(*, envelope_bytes, request_bytes, proof_bytes, context_bytes,
        expectations, planner_public_key, live_window, check, work):
    """Verify raw4 against independent pins, preserving original live bounds.

    This accepts neither a prior verification carrier nor a retained header.
    The entire context original must equal the canonical independent context;
    request/configuration/root/retention-policy pins are never read back from
    storage as expectations. Failure grants no replacement work or interval.
    Returned metrics include earlier work on this same invocation.
    """
    live = None
    try:
        ledger = evidence.capture._SharedLedger(work)
        envelope, request_raw, proof_raw, context_raw = _raw4(
            envelope_bytes, request_bytes, proof_bytes, context_bytes)
        planner_key = planner_public_key
        if not isinstance(planner_key, plan.Ed25519PublicKey):
            raise RecoveryInvalidationRetentionError(
                "invalidation retention needs the independently pinned Ed25519 key")
        # The genuine source helper owns expectations and validates the exact
        # typed request before any external clock/key/owner callback. It derives
        # canonical context from independent pins, never from retained bytes.
        owned, request, expected_context = plan._originals(
            request_raw, proof_raw, expectations, work)
        work.charge(input_bytes=len(context_raw) + len(expected_context))
        if context_raw != expected_context:
            raise RecoveryInvalidationRetentionError(
                "retained invalidation context differs from independent expectations")
        document = plan._decode(envelope, plan.MAX_PARENT_BYTES, work, nodes=2048, depth=8)
        plan._object(document, {"schema", "payload", "signatureBase64Url"})
        plan._require(document["schema"] == plan.ENVELOPE_SCHEMA)
        payload = document["payload"]
        plan._bind(payload, owned, request, request_raw, proof_raw, context_raw, work)
        # This interval is not trusted merely because it decoded. It can only
        # refuse before signature verification; the actual verifier below must
        # authenticate the same immutable envelope and replay all raw proofs.
        live = plan._Live(owned, payload, live_window, check, work)
        live.checked()
        verification = plan.verify_originals(envelope_bytes=envelope,
            request_bytes=request_raw, proof_bytes=proof_raw, expectations=owned,
            planner_public_key=planner_key, live_window=live.window,
            check=live.checked, work=work)
        live.checked()
        planner_digest = _key_digest(planner_key, work)
        live.checked()
        envelope_digest = _bytes_digest(envelope, work)
        request_digest = _bytes_digest(request_raw, work)
        proof_digest = _bytes_digest(proof_raw, work)
        context_digest = _bytes_digest(context_raw, work)
        # Fixed header/result scaffolding; canonical encoding and hashing are
        # additionally metered below, not replaced by this reservation.
        work.charge(input_bytes=8192, json_nodes=256)
        issued, expires = payload["issuedAtEpochNs"], payload["expiresAtEpochNs"]
        deadline = payload["originalDeadlineNs"]
        header = {"schema": RECORD_SCHEMA, "sourceRevision": plan.proof.contract.SOURCE_REVISION,
            "planProtocol": PLAN_PROTOCOL, "operation": plan.OPERATION,
            "operationId": request["operationId"], "requestDigest": request["requestDigest"],
            "configurationDigest": owned["configurationDigest"],
            "plannerKeyDigest": planner_digest, "planDigest": verification.plan_digest,
            "envelopeBytesDigest": envelope_digest, "envelopeByteCount": len(envelope),
            "requestBytesDigest": request_digest, "requestByteCount": len(request_raw),
            "proofBytesDigest": proof_digest, "proofByteCount": len(proof_raw),
            "contextBytesDigest": context_digest, "contextByteCount": len(context_raw),
            "issuedAtEpochNs": issued, "expiresAtEpochNs": expires,
            "originalDeadlineNs": deadline}
        record_digest = evidence.plan._json_digest(RECORD_SCHEMA, header, ledger)
        live.checked()
        return _RetainedInvalidationPlan(envelope, request_raw, proof_raw, context_raw,
            request, owned["context"], payload, header, record_digest, verification,
            (issued, expires), deadline, work.metrics)
    except BaseException as exc:
        if live is not None:
            live.failed = True
        if isinstance(exc, evidence.keys._FAILURES) and not isinstance(
                exc, RecoveryInvalidationRetentionError):
            raise RecoveryInvalidationRetentionError(
                "retained invalidation plan verification failed") from exc
        raise
