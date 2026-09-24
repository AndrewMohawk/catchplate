"""Original-envelope/context verification for versioned durable retention.

Raw immutable bytes and independently admitted expectations are mandatory.
Returned records are ordinary local observations, never caller-granted proof.
Historical verification establishes no current-state or execution authority.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from serverware import authority_complete_query_batch as capture
from serverware import authority_contract
from serverware import authority_revocation_plan as plan
from serverware import authority_revocation_plan_production as production
from serverware import authority_revocation_wire as wire
from serverware.authority_query_read_work import QueryReadValidationMetrics, _ValidationWork


CONTEXT_SCHEMA = "serverware.policyAuthorityRevocationEvaluationContext/v1"
RECORD_SCHEMA = "serverware.policyAuthorityRevocationRetainedPlan/v1"
PLAN_PROTOCOL = "revocation-v4"
MAX_CONTEXT_BYTES = 512 * 1024
MAX_CONTEXT_NODES = 4096
MAX_CONTEXT_DEPTH = 8
_CONTEXT_PAIRS = (
    ("expectedPlannerIdentity", "expected_planner_identity"),
    ("expectedVerifierIdentity", "expected_verifier_identity"),
    ("expectedCapabilityId", "expected_capability_id"),
    ("expectedPlannerTransactionId", "expected_planner_transaction_id"),
    ("expectedFence", "expected_fence"),
    ("reservedAtEpochNs", "reserved_at_epoch_ns"),
    ("deadlineEpochNs", "deadline_epoch_ns"),
    ("deadlineMonotonicNs", "deadline_monotonic_ns"),
    ("nowEpochNs", "now_epoch_ns"),
    ("nowMonotonicNs", "now_monotonic_ns"),
    ("maximumAssertionAgeNs", "maximum_assertion_age_ns"),
    ("maximumPlanAgeNs", "maximum_plan_age_ns"),
    ("maximumClockSkewNs", "maximum_clock_skew_ns"),
    ("expectedBefore", "expected_before"),
    ("expectedApproverPolicyDigest", "expected_approver_policy_digest"),
)
_CONTEXT_FIELDS = frozenset({"schema", "sourceRevision", "databaseCutoffUs",
                           *(name for name, _ in _CONTEXT_PAIRS)})


class RevocationRetentionError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class _RetainedRevocationRecord:
    """Actual locally verified data, not an accepted persistence API input."""

    envelope_bytes: bytes
    context_bytes: bytes
    payload_bytes: bytes
    payload: dict
    context: dict
    planner_key_digest: str
    verifier_key_digest: str
    envelope_digest: str
    context_digest: str
    payload_digest: str
    header: dict
    record_digest: str
    verification: plan.RevocationPlanObservation
    metrics: QueryReadValidationMetrics


def _encode_context_on_work(context: dict, *, database_now: datetime,
                            work: _ValidationWork) -> bytes:
    """Encode the producer's already-owned historical context before signing.

    No authority or ownership is inferred from this private helper's inputs.
    The producer must supply its invocation-owned context and original UTC
    database instant. The closed scalar/identity/root/head shapes have maximum
    scalar depth four, below the context depth-eight decoder ceiling. Actual
    bounded measurement and encoding cost 0H/2L/2N on existing work; there is
    no parse, clock sample, signature, new allowance or copied proof result.
    """
    try:
        ledger = capture._SharedLedger(work)
        if type(database_now) is not datetime or database_now.tzinfo is not timezone.utc:
            raise RevocationRetentionError("producer context requires its original exact UTC instant")
        production._validate_context(context, work)
        # These are the only unconstrained strings in the closed context.
        # Shape admission already bounds each to 128 characters and limits
        # the root/head inventory. The raw reader rejects NUL, so do not emit
        # bytes that cannot be read back under that same transport contract.
        for field, name in (("businessBeforeRoots", "table"),
                            ("authorizationBeforeRoots", "table"),
                            ("indexBeforeHeads", "indexId")):
            for entry in context["expectedBefore"][field]:
                if "\x00" in entry[name]:
                    raise RevocationRetentionError("producer context identifier contains NUL")
        document = {"schema": CONTEXT_SCHEMA, "sourceRevision": authority_contract.SOURCE_REVISION,
            "databaseCutoffUs": plan.semantics.complete.cutoff_microseconds(database_now),
            **{name: context[name] for name, _ in _CONTEXT_PAIRS}}
        return plan.retained._bounded_wire(document, ledger,
            maximum_bytes=MAX_CONTEXT_BYTES, maximum_nodes=MAX_CONTEXT_NODES)
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError, RecursionError,
            plan.core.TransitionKernelError) as exc:
        if isinstance(exc, RevocationRetentionError):
            raise
        raise RevocationRetentionError("producer evaluation context encoding failed") from exc


def _bytes_digest(raw: bytes, work: _ValidationWork) -> str:
    work.charge(hashes=1, input_bytes=len(raw))
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _key_digest(key, work: _ValidationWork) -> str:
    # Reserve actual raw32 output before the key callback. Its input was
    # independently admitted and already used by genuine signature replay.
    work.charge(input_bytes=32)
    limits, metrics = work.limits, work.metrics
    values = (limits.max_hashes, limits.max_input_bytes, limits.max_json_nodes)
    raw = key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    capture._SharedLedger(work)
    if (work.limits is not limits or work.metrics != metrics
            or (work.limits.max_hashes, work.limits.max_input_bytes, work.limits.max_json_nodes) != values
            or type(raw) is not bytes or len(raw) != 32):
        raise RevocationRetentionError("retained key serialization changed its work or raw32 binding")
    return _bytes_digest(raw, work)


def _verify_record_on_work(*, envelope_bytes: bytes, evaluation_context_bytes: bytes,
                           work: _ValidationWork, **expectations) -> _RetainedRevocationRecord:
    """Genuinely verify a raw retained record without trusting stored context.

    The caller supplies every original expectation independently. Capture them
    together before key callbacks; decode both original documents with one
    remaining allowance; compare canonical historical context to that capture;
    genuinely verify the original signed envelope; derive key/byte/header
    commitments. No clock is sampled and no claim becomes current authority.

    Returned totals are cumulative, including earlier work. Fixed bounded
    metadata dictionaries and hash-output scaffolding are not process-memory
    accounting. Failure aborts the enclosing persistence/read transaction.
    """
    try:
        if len(expectations) != len(wire._EXPECTATIONS) or set(expectations) != wire._EXPECTATIONS:
            raise RevocationRetentionError("retained revocation expectations are not closed")
        ledger = capture._SharedLedger(work)
        planner_key, verifier_key = expectations["planner_public_key"], expectations["verifier_public_key"]
        database_now = expectations["database_now"]
        plan._verification_types(planner_key, verifier_key, database_now)
        expected_context = {
            "schema": CONTEXT_SCHEMA, "sourceRevision": authority_contract.SOURCE_REVISION,
            "databaseCutoffUs": plan.semantics.complete.cutoff_microseconds(database_now),
            **{name: expectations[argument] for name, argument in _CONTEXT_PAIRS},
        }
        owned = capture._JSONCapture(ledger).visit({
            "expectedRequest": expectations["expected_request"], "context": expected_context,
        }, depth=-1)
        production._validate_context({name: owned["context"][name] for name, _ in _CONTEXT_PAIRS}, work)
        context = wire._decode_object(evaluation_context_bytes, work=work,
            maximum_bytes=MAX_CONTEXT_BYTES, maximum_nodes=MAX_CONTEXT_NODES,
            maximum_depth=MAX_CONTEXT_DEPTH)
        plan.contract._object(context, _CONTEXT_FIELDS, "retained evaluation context")
        context_wire = plan.retained._bounded_wire(context, ledger,
            maximum_bytes=MAX_CONTEXT_BYTES, maximum_nodes=MAX_CONTEXT_NODES)
        work.charge(input_bytes=2 * len(evaluation_context_bytes))
        if context_wire != evaluation_context_bytes:
            raise RevocationRetentionError("retained evaluation context bytes are not canonical")
        plan._same(context, owned["context"], work,
            "retained context differs from independently supplied historical expectations")
        envelope = wire._decode_envelope(envelope_bytes, work=work)
        supplied = {argument: owned["context"][name] for name, argument in _CONTEXT_PAIRS}
        verification = plan._verify_signed_revocation_plan_on_work(
            envelope=envelope, original_envelope_bytes=envelope_bytes, work=work,
            expected_request=owned["expectedRequest"], planner_public_key=planner_key,
            verifier_public_key=verifier_key, database_now=database_now, **supplied)
        planner_key_digest, verifier_key_digest = _key_digest(planner_key, work), _key_digest(verifier_key, work)
        envelope_digest = _bytes_digest(envelope_bytes, work)
        context_digest = _bytes_digest(evaluation_context_bytes, work)
        payload_digest = _bytes_digest(verification.payload_bytes, work)
        measured = envelope["payload"]["measuredPlan"]
        header = {
            "schema": RECORD_SCHEMA, "sourceRevision": authority_contract.SOURCE_REVISION,
            "planProtocol": PLAN_PROTOCOL,
            "plannerTransactionId": measured["plannerTransactionId"],
            "operationId": measured["operationId"], "requestDigest": measured["requestDigest"],
            "capabilityId": measured["capabilityId"],
            "plannerKeyDigest": planner_key_digest, "verifierKeyDigest": verifier_key_digest,
            "envelopeDigest": envelope_digest, "envelopeByteCount": len(envelope_bytes),
            "contextDigest": context_digest, "contextByteCount": len(evaluation_context_bytes),
        }
        record_digest = plan._json_digest(RECORD_SCHEMA, header, ledger)
        return _RetainedRevocationRecord(envelope_bytes, evaluation_context_bytes,
            verification.payload_bytes, envelope["payload"], context, planner_key_digest,
            verifier_key_digest, envelope_digest, context_digest, payload_digest, header,
            record_digest, verification, work.metrics)
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError, RecursionError,
            plan.core.TransitionKernelError) as exc:
        if isinstance(exc, RevocationRetentionError):
            raise
        raise RevocationRetentionError("retained revocation record verification failed") from exc
