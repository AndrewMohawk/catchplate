"""Private writer-action ownership and measured-policy consistency.

These inert helpers admit bounded data shapes, not configuration provenance,
authenticated callers, clock truth, current roots or successful plan proofs.
The real service owns all invocation graphs and its full measured payload
before launch, descriptor or key callbacks. It compares policy against that
same payload, then calls the genuine configured atomic persistence owner.
No original envelope is decoded, reconstructed or signed here, and neither
an ordinary returned dictionary nor a prior receipt is an authority token.
"""
from __future__ import annotations

from datetime import datetime, timezone

from catchplate import authority_contract as authority
from catchplate import authority_revocation_retention as retention


_EXTERNAL_FIELDS = retention.wire._EXPECTATIONS - {
    "planner_public_key", "verifier_public_key",
    "expected_planner_identity", "expected_verifier_identity",
}
_AGE_FIELDS = ("maximum_assertion_age_ns", "maximum_plan_age_ns", "maximum_clock_skew_ns")


class RevocationWriterActionError(ValueError):
    pass


def _capture_action_inputs(*, envelope_bytes, evaluation_context_bytes,
        planned_at_epoch_ns, envelope_id, planner_transaction_id, work, **expectations):
    """Return ordinary fixed arguments and fifteen owned external expectations.

    Immutable original bytes and the exact UTC datetime retain their identity.
    The other fourteen fields receive one real bounded JSON ownership pass
    (0H/1L/1N), followed by source shape checks. The canonical independent
    planner-ID comparison adds 0H/438B/4N. This is an additional service boundary:
    the configured atomic owner still repeats its own capture, ID comparison
    and both genuine replays on the same remaining work. No callback occurs.
    """
    try:
        ledger = retention.capture._SharedLedger(work)
        for raw, maximum in ((envelope_bytes, retention.plan.contract.MAX_PAYLOAD_BYTES),
                             (evaluation_context_bytes, retention.MAX_CONTEXT_BYTES)):
            if type(raw) is not bytes or not 2 <= len(raw) <= maximum:
                raise RevocationWriterActionError("revocation writer action requires bounded original bytes")
        retention.plan.contract._integer(planned_at_epoch_ns, minimum=1)
        retention.plan.contract._digest(envelope_id)
        retention.plan.contract._digest(planner_transaction_id)
        if (type(expectations) is not dict or len(expectations) != len(_EXTERNAL_FIELDS)
                or any(type(name) is not str for name in expectations)
                or set(expectations) != _EXTERNAL_FIELDS):
            raise RevocationWriterActionError("revocation writer action requires exactly fifteen external expectations")
        database_now = expectations["database_now"]
        if type(database_now) is not datetime or database_now.tzinfo is not timezone.utc:
            raise RevocationWriterActionError("revocation writer action requires its original exact UTC instant")
        retention.plan.contract._digest(expectations["expected_planner_transaction_id"])
        owned = retention.capture._JSONCapture(ledger).visit({
            name: value for name, value in expectations.items() if name != "database_now"})
        owned["database_now"] = database_now
        retention.plan.contract._request(owned["expected_request"])
        for name in ("expected_capability_id", "expected_planner_transaction_id"):
            retention.plan.contract._digest(owned[name])
        if owned["expected_approver_policy_digest"] is not None:
            retention.plan.contract._digest(owned["expected_approver_policy_digest"])
        for name in ("expected_fence", "reserved_at_epoch_ns", "deadline_epoch_ns",
                     "deadline_monotonic_ns", "now_epoch_ns", "now_monotonic_ns",
                     "maximum_assertion_age_ns", "maximum_plan_age_ns"):
            retention.plan.contract._integer(owned[name], minimum=1)
        retention.plan.contract._integer(owned["maximum_clock_skew_ns"])
        retention.plan.semantics._expected_before(owned["expected_before"])
        retention.plan._same(planner_transaction_id, owned["expected_planner_transaction_id"], work,
            "revocation writer action planner ID differs from its independent expectation")
        arguments = {"envelope_bytes": envelope_bytes,
            "evaluation_context_bytes": evaluation_context_bytes,
            "planned_at_epoch_ns": planned_at_epoch_ns, "envelope_id": envelope_id,
            "planner_transaction_id": planner_transaction_id}
        return arguments, owned
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError, RecursionError) as exc:
        if isinstance(exc, RevocationWriterActionError):
            raise
        raise RevocationWriterActionError("revocation writer action input capture failed") from exc


def _assert_policy_on_work(payload, expectations, work):
    """Compare owned policy without recapturing configuration or overwriting it.

    The service passes the very same full owned payload to the real mapper.
    Assertion age is its measured WebAuthn challenge age, without a thirty-
    second cap. Plan age is min(measured verifier age, source thirty seconds);
    skew is the unchanged source five seconds. This actual canonical tuple
    comparison costs 0H plus 3L/2N for each operand. Shape checks are not proof.
    """
    try:
        retention.capture._SharedLedger(work)
        if (type(payload) is not dict or type(payload.get("roles")) is not dict
                or type(payload["roles"].get("verifier")) is not dict
                or type(payload.get("webauthn")) is not dict
                or type(expectations) is not dict):
            raise RevocationWriterActionError("revocation writer action policy is not exact data")
        assertion_age = payload["webauthn"]["maximumChallengeAgeNs"]
        verifier_age = payload["roles"]["verifier"]["maximumInternalAgeNs"]
        retention.plan.contract._integer(assertion_age, minimum=1)
        retention.plan.contract._integer(verifier_age, minimum=1)
        supplied = tuple(expectations[name] for name in _AGE_FIELDS)
        for value in supplied[:2]:
            retention.plan.contract._integer(value, minimum=1)
        retention.plan.contract._integer(supplied[2])
        measured = (assertion_age, min(verifier_age, authority.VERIFIER_RESPONSE_MAX_AGE_NS),
            authority.VERIFIER_MAX_CLOCK_SKEW_NS)
        retention.plan._same(supplied, measured, work,
            "revocation writer action policy differs from its measured configuration")
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError, RecursionError) as exc:
        if isinstance(exc, RevocationWriterActionError):
            raise
        raise RevocationWriterActionError("revocation writer action policy check failed") from exc
