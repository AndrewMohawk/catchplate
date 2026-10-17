"""Closed activation execution expectation data, never replay authority.

The caller independently admits these expectations. Capturing and checking
their typed commitments does not authenticate signatures, policy, custody,
current state or a live interval. No private key or clock window is accepted.
"""
from __future__ import annotations

from catchplate import authority_oidc_session_activation_plan as plan


assertion, registration, evidence = plan.assertion, plan.registration, plan.evidence
OPERATION = plan.contract.OPERATION
EXPECTATION_FIELDS = frozenset({"request", "scope", "journalDigest"})
MAX_BYTES = assertion.MAX_CONTEXT_BYTES
MAX_NODES = assertion.MAX_CONTEXT_NODES


class ActivationExecutionExpectationsError(ValueError):
    pass


def _shape(value):
    """Reject unknown fields before traversing any received nested graph."""
    registration._closed(value, EXPECTATION_FIELDS, "activation execution expectations")
    registration._closed(value["request"], plan.contract.shape.TYPED_REQUEST_FIELDS,
        "activation execution expected request")
    registration._closed(value["scope"], plan._SCOPE_FIELDS, "activation execution expected scope")
    operation = value["request"]["operation"]
    if type(operation) is not str or operation != OPERATION:
        raise ActivationExecutionExpectationsError("activation expectations require the fixed operation")


def _capture_on_work(value, *, work):
    """Own bounded JSON data and check actual request commitments only.

    Original assertion/policy/subject semantics and live processing remain the
    actual receiving replay's responsibility under independently admitted scope.
    """
    ledger = evidence.capture._SharedLedger(work)
    _shape(value)
    owned = assertion._Capture(ledger, maximum_bytes=MAX_BYTES).visit(value)
    # Recheck the owned graph; the received graph is never consulted afterward.
    _shape(owned)
    request = owned["request"]
    registration._digest(owned["journalDigest"])
    digest = plan.commitment._typed_request_digest(request, work=work)
    registration._same(request["requestDigest"], digest, work, "activation execution expected request")
    operation_id = evidence.plan._frame("catchplate.policyAuthorityOperation/v2",
        (evidence.plan._ascii(OPERATION, work), evidence.plan._ascii(digest, work)), work)
    registration._same(request["operationId"], operation_id, work, "activation execution expected operation")
    return owned
