"""Canonical independent expectations for detached successor transition plans.

The exact five expectations are retained beneath a schema/source header.
Decoding, canonical equality and a framed byte identity do not establish
historical or current admission: a real plan verifier must compare the whole
context with separately owned expectations and invoke genuine replay.
No keys, signatures, clocks, database, registry or replacement budget exists
here. Existing byte/node/depth and original cumulative work limits apply.
"""
from __future__ import annotations

from serverware import authority_webauthn_transition_plan_contract as contract


proof = contract.proof
evidence = proof.evidence
SCHEMA = "serverware.policyAuthorityWebAuthnTransitionPlanEvaluationContext/v1"
IDENTITY_DOMAIN = "serverware.policyAuthorityWebAuthnTransitionPlanEvaluationContextIdentity/v1"
MAX_BYTES, MAX_NODES, MAX_DEPTH = contract.MAX_BYTES, contract.MAX_NODES, contract.MAX_DEPTH
FIELDS = frozenset({"schema", "sourceRevision", *contract.EXPECTATION_FIELDS})


def _encode_on_work(*, expectations, work):
    """Capture and encode the full context without admitting its authority."""
    ledger = evidence.capture._SharedLedger(work)
    expected = evidence.capture._JSONCapture(ledger, maximum_bytes=MAX_BYTES).visit(expectations)
    contract._validate_expectations(expected)
    document = {"schema": SCHEMA, "sourceRevision": contract.authority.SOURCE_REVISION, **expected}
    return evidence.capability._wire(document, ledger, MAX_BYTES, MAX_NODES)


def _decode_on_work(raw, *, work):
    """Return ordinary owned five-field data only after exact canonical replay."""
    ledger = evidence.capture._SharedLedger(work)
    document = evidence.wire._decode_object(raw, work=work,
        maximum_bytes=MAX_BYTES, maximum_nodes=MAX_NODES, maximum_depth=MAX_DEPTH)
    contract.shape._object(document, FIELDS, "successor transition plan evaluation context")
    contract.shape._literal(document["schema"], SCHEMA)
    contract.shape._literal(document["sourceRevision"], contract.authority.SOURCE_REVISION)
    owned = evidence.capture._JSONCapture(ledger, maximum_bytes=MAX_BYTES).visit(document)
    expected = {field: owned[field] for field in contract.EXPECTATION_FIELDS}
    contract._validate_expectations(expected)
    evidence.capability._canonical(raw, owned, ledger, MAX_BYTES, MAX_NODES)
    return expected


def _digest_on_work(raw, work):
    """Hash bounded original context bytes; a digest alone does not validate it."""
    evidence.capture._SharedLedger(work)
    proof.wire._raw(raw, 2, MAX_BYTES)
    return evidence.plan._frame(IDENTITY_DOMAIN, (raw,), work)
