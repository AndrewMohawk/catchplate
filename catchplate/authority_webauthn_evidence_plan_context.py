"""Canonical historical expectations for original evidence-plan retention.

The closed context preserves the exact eighteen independently admitted plan
expectations. Encoding and decoding authenticate none of them: a retained
record verifier must compare the complete context with separately owned,
independently admitted history before genuine signature/proof/semantic replay.
Stored configuration, identity, SPKI, root or input commitments do not enroll
trust, and an old context's time is not a current-clock claim.

There are no keys, clocks, signatures, SQL or replacement allowances here. The
existing plan byte/node/depth ceilings and cumulative caller work apply; the
transport ceiling is not a promise that a maximum-sized record can be replayed.
"""
from __future__ import annotations

from catchplate import authority_webauthn_evidence_plan as plan


SCHEMA = "catchplate.policyAuthorityWebAuthnEvidencePlanEvaluationContext/v1"
MAX_BYTES = plan.contract.MAX_BYTES
MAX_NODES = plan.contract.MAX_NODES
MAX_DEPTH = plan.contract.MAX_DEPTH
_FIELDS = frozenset({"schema", "sourceRevision", *plan._EXPECTATION_FIELDS})


class WebAuthnEvidencePlanContextError(ValueError):
    pass


def _operation(expected):
    if type(expected) is not dict or type(expected.get("request")) is not dict:
        raise WebAuthnEvidencePlanContextError("evidence plan context requires an exact typed request")
    operation = expected["request"].get("operation")
    if type(operation) is not str or operation not in plan.contract.OPERATIONS:
        raise WebAuthnEvidencePlanContextError("evidence plan context operation is not source fixed")
    return operation


def _encode_on_work(*, expectations, work):
    """Own and encode historical data without establishing its provenance."""
    ledger = plan.evidence.capture._SharedLedger(work)
    expected = plan.evidence.capture._JSONCapture(ledger, maximum_bytes=MAX_BYTES).visit(expectations)
    plan._validate_expectations(expected, _operation(expected))
    document = {"schema": SCHEMA, "sourceRevision": plan.evidence.authority.SOURCE_REVISION, **expected}
    return plan.evidence.capability._wire(document, ledger, MAX_BYTES, MAX_NODES)


def _decode_on_work(raw, *, work):
    """Return ordinary exact expectations, never admitted historical authority."""
    ledger = plan.evidence.capture._SharedLedger(work)
    document = plan.evidence.wire._decode_object(raw, work=work,
        maximum_bytes=MAX_BYTES, maximum_nodes=MAX_NODES, maximum_depth=MAX_DEPTH)
    shape = plan.evidence.plan.contract
    shape._object(document, _FIELDS, "retained evidence plan context")
    shape._literal(document["schema"], SCHEMA)
    shape._literal(document["sourceRevision"], plan.evidence.authority.SOURCE_REVISION)
    owned = plan.evidence.capture._JSONCapture(ledger, maximum_bytes=MAX_BYTES).visit(document)
    expected = {field: owned[field] for field in plan._EXPECTATION_FIELDS}
    plan._validate_expectations(expected, _operation(expected))
    # The actual bounded encoder and both complete byte scans are charged on
    # this same work; equivalent parsed JSON is not an accepted original wire.
    plan.evidence.capability._canonical(raw, owned, ledger, MAX_BYTES, MAX_NODES)
    return expected
