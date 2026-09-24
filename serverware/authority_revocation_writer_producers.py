"""Configured verifier intent and planner relay production, without transport.

The service must supply its admitted measured configuration, active generation,
held role signer and independently admitted invocation. For intent production
it also obtains the full inventory from its own genuine root reader. This
inert module reowns those graphs, but cannot manufacture that provenance.

Every intent performs a fresh configured handoff verification in the same call.
Only its locally authenticated context and cutoff become historical claims.
Neither producer accepts a successful observation, caller current clocks or selected
public keys. Outputs are original bytes, not proof tokens, custody, ACKs or
current execution authority. Relay generation is separate from sending: an
uncertain retry must retain originals, not silently generate new controls.
"""
from __future__ import annotations

import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from serverware import authority_contract as authority
from serverware import authority_revocation_configuration as configuration
from serverware import authority_revocation_verifier as verifier
from serverware import authority_revocation_writer_commitment as commitment


plan, capture = commitment.plan, commitment.capture
_FAILURES = (AttributeError, KeyError, TypeError, ValueError, OverflowError, RecursionError)


class RevocationWriterProducerError(ValueError):
    pass


def _capture_intent_call_inputs(*, envelope_bytes, evaluation_context_bytes,
        expected_request, context, planned_at_epoch_ns, envelope_id,
        planner_transaction_id, work):
    """Own request/context9 before the service's first external callback.

    Raw bytes and original scalar arguments are exact immutable values. The
    genuine CopyBudget owns the joint graph; the canonical planner-ID join is
    charged on the same allowance. No key, clock, reader or launch is invoked.
    The configured producer repeats this boundary, not a returned admission.
    """
    try:
        capture._SharedLedger(work)
        commitment._raw(envelope_bytes, plan.contract.MAX_PAYLOAD_BYTES)
        commitment._raw(evaluation_context_bytes, commitment.retention.MAX_CONTEXT_BYTES)
        plan.contract._integer(planned_at_epoch_ns, minimum=1)
        plan.contract._digest(envelope_id)
        plan.contract._digest(planner_transaction_id)
        if type(expected_request) is not dict:
            raise RevocationWriterProducerError("writer intent requires an exact independent request")
        plan.contract._object(context, verifier._CALL_CONTEXT_FIELDS, "writer intent historical context")
        owned = verifier.handoff.observed.reads._CopyBudget(work).copy(
            {"expectedRequest": expected_request, "context": context})
        request, historical = owned["expectedRequest"], owned["context"]
        plan.contract._request(request)
        for name in ("expectedCapabilityId", "expectedPlannerTransactionId"):
            plan.contract._digest(historical[name])
        if historical["expectedApproverPolicyDigest"] is not None:
            plan.contract._digest(historical["expectedApproverPolicyDigest"])
        for name in ("expectedFence", "reservedAtEpochNs", "deadlineEpochNs", "deadlineMonotonicNs",
                     "nowEpochNs", "nowMonotonicNs"):
            plan.contract._integer(historical[name], minimum=1)
        plan._same(planner_transaction_id, historical["expectedPlannerTransactionId"], work,
            "writer intent planner ID differs from its independent expectation")
        return request, historical
    except _FAILURES as exc:
        if isinstance(exc, RevocationWriterProducerError):
            raise
        raise RevocationWriterProducerError("writer intent input capture failed") from exc


def _capture_payload(payload, role_names, work):
    """Hold complete configuration and fixed role-age scalars before keys."""
    if type(payload) is not dict:
        raise RevocationWriterProducerError("writer producer configuration is not an exact object")
    owned = configuration._ConfigurationCapture(capture._SharedLedger(work),
        maximum_bytes=authority.MAX_REQUEST_BYTES).visit(payload)
    roles = owned["roles"]
    if type(roles) is not dict:
        raise RevocationWriterProducerError("writer producer roles are not an exact object")
    ages = []
    for name in role_names:
        role = roles[name]
        if type(role) is not dict:
            raise RevocationWriterProducerError("writer producer role is not an exact object")
        plan.contract._literal(role["processMode"], "policy-authority-" + name)
        plan.contract._integer(role["maximumInternalAgeNs"], minimum=1)
        ages.append(role["maximumInternalAgeNs"])
    return owned, min(ages)


def _produce_intent_on_configuration(*, payload, configuration_digest, generation,
        envelope_bytes, evaluation_context_bytes, expected_request, context, root_inventory,
        planned_at_epoch_ns, envelope_id, planner_transaction_id, verifier_private_key, work):
    """Replay originals with independent roots, then sign newly owned history.

    Ownership precedes every key callback. The real verifier mapper and owner
    retain their existing captures and proof accounting, including the genuine
    remaining-clamped child. Derived external15 receives a real JSON capture
    before post-replay clock callbacks. Current samples check historical
    freshness; they never replace historical times, cutoff or plannedAt.
    The pure producer performs its own charged capture and genuine paired
    signing. No replacement allowance or prior-proof input is available.
    """
    try:
        capture._SharedLedger(work)
        if not isinstance(verifier_private_key, Ed25519PrivateKey):
            raise RevocationWriterProducerError("writer intent requires its configured verifier signer")
        request, historical = _capture_intent_call_inputs(envelope_bytes=envelope_bytes,
            evaluation_context_bytes=evaluation_context_bytes, expected_request=expected_request,
            context=context, planned_at_epoch_ns=planned_at_epoch_ns, envelope_id=envelope_id,
            planner_transaction_id=planner_transaction_id, work=work)
        inventory = verifier.handoff.observed._capture_root_inventory(root_inventory, work=work)
        owned_payload, maximum_age = _capture_payload(payload, ("verifier", "planner", "planner-writer"), work)
        owner = verifier._verifier_from_configuration_on_work(payload=owned_payload,
            configuration_digest=configuration_digest, generation=generation, work=work)
        fixed = owner._snapshot_configuration()
        verified = owner.verify_handoff(envelope_bytes=envelope_bytes,
            evaluation_context_bytes=evaluation_context_bytes, expected_request=request,
            context=historical, root_inventory=inventory, work=work)
        expectations = {argument: verified.expected_context[name]
            for name, argument in commitment.retention._CONTEXT_PAIRS
            if argument not in ("expected_planner_identity", "expected_verifier_identity")}
        arguments, owned = commitment.action._capture_action_inputs(envelope_bytes=envelope_bytes,
            evaluation_context_bytes=evaluation_context_bytes, planned_at_epoch_ns=planned_at_epoch_ns,
            envelope_id=envelope_id, planner_transaction_id=planner_transaction_id,
            expected_request=request, database_now=verified.database_now, work=work, **expectations)
        now_monotonic = configuration.production._callback(work, time.monotonic_ns)
        now_epoch = configuration.production._callback(work, time.time_ns)
        commitment._current(now_epoch, now_monotonic, maximum_age, fixed[6])
        commitment._fresh({"issuedAtEpochNs": owned["now_epoch_ns"],
            "issuedMonotonicNs": owned["now_monotonic_ns"],
            "deadlineMonotonicNs": owned["deadline_monotonic_ns"]}, owned,
            now_epoch, now_monotonic, maximum_age, fixed[6])
        produced = commitment._produce_intent_on_work(**arguments,
            verifier_private_key=verifier_private_key, verifier_public_key=fixed[1],
            planner_public_key=fixed[0], configuration_digest=fixed[7],
            generation_sequence=fixed[8], generation_digest=fixed[9],
            issued_at_epoch_ns=now_epoch, issued_monotonic_ns=now_monotonic, work=work, **owned)
        return produced.intent_bytes, produced.historical_expectations_bytes
    except _FAILURES as exc:
        if isinstance(exc, RevocationWriterProducerError):
            raise
        raise RevocationWriterProducerError("configured writer intent production failed") from exc


def _produce_relay_on_configuration(*, payload, configuration_digest, generation,
        intent_bytes, envelope_bytes, evaluation_context_bytes, historical_expectations_bytes,
        planner_private_key, work):
    """Authenticate the original intent, then return a separate original relay.

    This is not a semantic replay, send, retry or custody operation. The real
    mapper binds both public keys and scope; the pure producer checks actual
    private/public pairing, verifier signature, all original bodies and fresh
    current clocks before signing. Caller current clocks and public keys are absent.
    """
    try:
        capture._SharedLedger(work)
        commitment._raw(intent_bytes, commitment.MAX_CONTROL_BYTES)
        commitment._body_bounds(envelope_bytes, evaluation_context_bytes, historical_expectations_bytes)
        if not isinstance(planner_private_key, Ed25519PrivateKey):
            raise RevocationWriterProducerError("writer relay requires its configured planner signer")
        owned_payload, maximum_age = _capture_payload(payload, ("planner", "planner-writer"), work)
        owner = verifier._verifier_from_configuration_on_work(payload=owned_payload,
            configuration_digest=configuration_digest, generation=generation, work=work)
        fixed = owner._snapshot_configuration()
        now_monotonic = configuration.production._callback(work, time.monotonic_ns)
        now_epoch = configuration.production._callback(work, time.time_ns)
        produced = commitment._produce_relay_on_work(intent_bytes=intent_bytes,
            envelope_bytes=envelope_bytes, evaluation_context_bytes=evaluation_context_bytes,
            historical_expectations_bytes=historical_expectations_bytes,
            planner_private_key=planner_private_key, planner_public_key=fixed[0], verifier_public_key=fixed[1],
            expected_configuration_digest=fixed[7], expected_generation_sequence=fixed[8],
            expected_generation_digest=fixed[9], now_epoch_ns=now_epoch,
            now_monotonic_ns=now_monotonic, maximum_age_ns=maximum_age,
            maximum_clock_skew_ns=fixed[6], work=work)
        return produced.relay_bytes
    except _FAILURES as exc:
        if isinstance(exc, RevocationWriterProducerError):
            raise
        raise RevocationWriterProducerError("configured writer relay production failed") from exc
