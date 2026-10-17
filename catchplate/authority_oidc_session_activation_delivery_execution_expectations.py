"""Closed consume execution expectation data, never permission or proof.

This owns the caller's independent request/scope/journal expectations and checks
typed commitments only. It admits no key, custody object, clock or replay result.
Current policy and original lifetime admission belong to the actual consumer.
"""
from __future__ import annotations

from catchplate import authority_oidc_session_activation_delivery_plan as plan


assertion, registration, evidence = plan.assertion, plan.registration, plan.evidence
OPERATION = plan.contract.OPERATION
EXPECTATION_FIELDS = frozenset({"request", "scope", "journalDigest"})
MAX_BYTES = assertion.MAX_CONTEXT_BYTES
MAX_NODES = assertion.MAX_CONTEXT_NODES


class DeliveryExecutionExpectationsError(ValueError):
    pass


def _shape(value):
    registration._closed(value, EXPECTATION_FIELDS, "consume execution expectations")
    registration._closed(value["request"], plan.contract.shape.TYPED_REQUEST_FIELDS,
        "consume execution expected request")
    registration._closed(value["scope"], plan.state.SCOPE_FIELDS,
        "consume execution expected scope")
    if type(value["request"]["operation"]) is not str or value["request"]["operation"] != OPERATION:
        raise DeliveryExecutionExpectationsError("consume expectations require the fixed operation")


def _capture_on_work(value, *, work):
    """Detach the entire bounded graph before hashing its typed commitments."""
    ledger = evidence.capture._SharedLedger(work)
    _shape(value)
    owned = assertion._Capture(ledger, maximum_bytes=MAX_BYTES).visit(value)
    _shape(owned)
    registration._digest(owned["journalDigest"])
    request = owned["request"]
    digest = plan.commitment._typed_request_digest(request, work=work)
    registration._same(request["requestDigest"], digest, work, "consume expected request")
    operation_id = evidence.plan._frame("catchplate.policyAuthorityOperation/v2",
        (evidence.plan._ascii(OPERATION, work), evidence.plan._ascii(digest, work)), work)
    registration._same(request["operationId"], operation_id, work, "consume expected operation")
    return owned
