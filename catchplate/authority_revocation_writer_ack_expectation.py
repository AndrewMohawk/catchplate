"""Derive independent ACK contents by verifying the original writer request.

Configured identities, keys, policy, generation and current clocks are fixed
caller preconditions, not provenance established by this inert helper. No
received ACK or successful observation is accepted as an input. Both original
role signatures and one genuine retained-plan replay precede the fresh scalar
request expectation. Historical verification is not current-root, database,
custody, commit or execution authority; the writer still owes its own checks.
All work, including the genuine remaining-clamped proof child, uses the caller's
existing allowance. The ordinary output is not a reusable admission token.
"""
from __future__ import annotations

from catchplate import authority_contract as authority
from catchplate import authority_revocation_retention as retention
from catchplate import authority_revocation_writer_acknowledgment as acknowledgment
from catchplate import authority_revocation_writer_commitment as commitment


plan, capture = retention.plan, retention.capture
_AGE_FIELDS = ("maximum_assertion_age_ns", "maximum_plan_age_ns", "maximum_clock_skew_ns")


class RevocationWriterAckExpectationError(ValueError):
    pass


def _expected_ack_request_and_freshness_on_work(*, intent_bytes, relay_bytes, envelope_bytes,
        evaluation_context_bytes, historical_expectations_bytes,
        planner_public_key, verifier_public_key,
        expected_planner_identity, expected_verifier_identity,
        expected_configuration_digest, expected_generation_sequence,
        expected_generation_digest, now_epoch_ns, now_monotonic_ns,
        maximum_age_ns, maximum_clock_skew_ns, maximum_assertion_age_ns,
        maximum_plan_age_ns, work):
    """Return request19 and fixed authenticated clocks from original bytes.

    The only initial graph copy is the two independent identity dictionaries
    (actual JSONCapture, 0H/1L/1N), before any key callback. The real receiver
    owns its historical fifteen fields; their age tuple must match configured
    policy before original plan/context replay. Current clocks go only to the
    receiver: they never overwrite signed historical verification times.

    The fixed six-scalar clock tuple is captured before retention callbacks;
    later current-time checks cannot read a mutable authenticated carrier.
    It is local data for those checks, not a proof token or new authority.
    Three additional hashes cover original intent, relay and history. Stable
    IDs were genuinely derived and checked by the receiver, while record/key
    digests come only from this call's genuine retention result. Fixed scalar
    scaffolding/shape admission is not a variable copy or encoder charge.
    """
    try:
        ledger = capture._SharedLedger(work)
        commitment._raw(intent_bytes, commitment.MAX_CONTROL_BYTES)
        commitment._raw(relay_bytes, commitment.MAX_CONTROL_BYTES)
        commitment._body_bounds(envelope_bytes, evaluation_context_bytes, historical_expectations_bytes)
        commitment._pins(expected_configuration_digest, expected_generation_sequence,
            expected_generation_digest)
        commitment._current(now_epoch_ns, now_monotonic_ns, maximum_age_ns, maximum_clock_skew_ns)
        commitment._public_keys(planner_public_key, verifier_public_key)
        plan.contract.validate_identity_shape(expected_planner_identity)
        plan.contract.validate_identity_shape(expected_verifier_identity)
        plan.contract._integer(maximum_assertion_age_ns, minimum=1)
        plan.contract._integer(maximum_plan_age_ns, authority.VERIFIER_RESPONSE_MAX_AGE_NS, minimum=1)
        identities = capture._JSONCapture(ledger).visit({
            "expectedPlannerIdentity": expected_planner_identity,
            "expectedVerifierIdentity": expected_verifier_identity,
        })
        received = commitment._verify_commitments_on_work(
            intent_bytes=intent_bytes, relay_bytes=relay_bytes, envelope_bytes=envelope_bytes,
            evaluation_context_bytes=evaluation_context_bytes,
            historical_expectations_bytes=historical_expectations_bytes,
            planner_public_key=planner_public_key, verifier_public_key=verifier_public_key,
            expected_configuration_digest=expected_configuration_digest,
            expected_generation_sequence=expected_generation_sequence,
            expected_generation_digest=expected_generation_digest,
            now_epoch_ns=now_epoch_ns, now_monotonic_ns=now_monotonic_ns,
            maximum_age_ns=maximum_age_ns, maximum_clock_skew_ns=maximum_clock_skew_ns,
            work=work)
        # Hold the checked immutable scalar links before retention's next key
        # callbacks. The ordinary receiver graphs are not reusable authority.
        freshness_pins = (
            received.intent_envelope["issuedAtEpochNs"],
            received.intent_envelope["issuedMonotonicNs"],
            received.relay_envelope["issuedAtEpochNs"],
            received.relay_envelope["issuedMonotonicNs"],
            received.expectations["deadline_epoch_ns"],
            received.expectations["deadline_monotonic_ns"],
        )
        intent_id, relay_id = (received.intent_envelope["envelopeId"],
            received.relay_envelope["envelopeId"])
        execution_id, planner_id, planned_at = (received.arguments[name]
            for name in ("envelope_id", "planner_transaction_id", "planned_at_epoch_ns"))
        plan._same(tuple(received.expectations[name] for name in _AGE_FIELDS),
            (maximum_assertion_age_ns, maximum_plan_age_ns, maximum_clock_skew_ns), work,
            "writer ACK history policy differs from independently configured policy")
        record = retention._verify_record_on_work(
            envelope_bytes=envelope_bytes, evaluation_context_bytes=evaluation_context_bytes,
            planner_public_key=planner_public_key, verifier_public_key=verifier_public_key,
            expected_planner_identity=identities["expectedPlannerIdentity"],
            expected_verifier_identity=identities["expectedVerifierIdentity"],
            work=work, **received.expectations)
        request = {
            "intent_envelope_id": intent_id,
            "relay_envelope_id": relay_id,
            "execution_envelope_id": execution_id,
            "planner_transaction_id": planner_id,
            "plan_protocol": retention.PLAN_PROTOCOL,
            "retained_record_digest": record.record_digest,
            "configuration_digest": expected_configuration_digest,
            "generation_sequence": expected_generation_sequence,
            "generation_digest": expected_generation_digest,
            "planner_key_digest": record.planner_key_digest,
            "verifier_key_digest": record.verifier_key_digest,
            "planned_at_epoch_ns": planned_at,
            "source_revision": authority.SOURCE_REVISION,
        }
        for name, raw in (("exact_intent", intent_bytes), ("exact_relay", relay_bytes),
                         ("historical_expectations", historical_expectations_bytes)):
            request[name + "_bytes_digest"] = retention._bytes_digest(raw, work)
            request[name + "_byte_count"] = len(raw)
        acknowledgment._request_shape(request)
        return request, freshness_pins
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError, RecursionError) as exc:
        if isinstance(exc, RevocationWriterAckExpectationError):
            raise
        raise RevocationWriterAckExpectationError("writer ACK expectation derivation failed") from exc


def _expected_ack_request_on_work(*, intent_bytes, relay_bytes, envelope_bytes,
        evaluation_context_bytes, historical_expectations_bytes,
        planner_public_key, verifier_public_key,
        expected_planner_identity, expected_verifier_identity,
        expected_configuration_digest, expected_generation_sequence,
        expected_generation_digest, now_epoch_ns, now_monotonic_ns,
        maximum_age_ns, maximum_clock_skew_ns, maximum_assertion_age_ns,
        maximum_plan_age_ns, work):
    """Compatibility surface returning only the independently derived row19."""
    request, _freshness_pins = _expected_ack_request_and_freshness_on_work(
        intent_bytes=intent_bytes, relay_bytes=relay_bytes, envelope_bytes=envelope_bytes,
        evaluation_context_bytes=evaluation_context_bytes,
        historical_expectations_bytes=historical_expectations_bytes,
        planner_public_key=planner_public_key, verifier_public_key=verifier_public_key,
        expected_planner_identity=expected_planner_identity,
        expected_verifier_identity=expected_verifier_identity,
        expected_configuration_digest=expected_configuration_digest,
        expected_generation_sequence=expected_generation_sequence,
        expected_generation_digest=expected_generation_digest,
        now_epoch_ns=now_epoch_ns, now_monotonic_ns=now_monotonic_ns,
        maximum_age_ns=maximum_age_ns, maximum_clock_skew_ns=maximum_clock_skew_ns,
        maximum_assertion_age_ns=maximum_assertion_age_ns,
        maximum_plan_age_ns=maximum_plan_age_ns, work=work)
    return request
