"""Measured private service boundaries for authenticated transition custody.

Intent production requires independently admitted historical expectations;
received planning context cannot supply that authority. Relay preparation and
possibly committing delivery are explicit separate calls. The caller must
durably retain all seven exact originals before forwarding. No successful
return establishes a signed writer receipt, execution permission or recovery
authority, and a late error can follow an actual writer commit.

All methods retain the caller's original work and own input references before
measured configuration, key or launch callbacks. Fixed roles and protected
descriptors preserve verifier -> planner -> planner-writer peer topology.
"""
from __future__ import annotations

from serverware import authority_webauthn_transition_service as service
from serverware import authority_webauthn_transition_custody_actions as actions
from serverware import authority_webauthn_transition_custody_transport as transport


def _context_on_work(process, *, role, signing, work):
    descriptor = ("SERVERWARE_POLICY_AUTHORITY_PLANNER_WRITER_POSTGRES_DSN"
        if role == "planner-writer" else None)
    payload, digest, generation, dsn, private = service._measured_context_on_work(
        process, role=role, signing=signing, read_descriptor=descriptor, work=work)
    return payload, digest, service._generation_on_work(generation, work), dsn, private


def _produce_intent_on_work(process, *, operation, envelope_bytes, proof_bytes,
        inputs_bytes, context_bytes, expectations, work):
    """Sign a retain-only intent without sending it or admitting its history."""
    operation = service._operation(operation)
    originals = service.retention._raw4(envelope_bytes, proof_bytes, inputs_bytes, context_bytes)
    owned = service._history_on_work(operation, expectations, work)
    payload, digest, generation, _dsn, private = _context_on_work(
        process, role="verifier", signing=True, work=work)
    result = actions._produce_intent_on_configuration(operation=operation,
        payload=payload, configuration_digest=digest, generation=generation,
        envelope_bytes=originals[0], proof_bytes=originals[1], inputs_bytes=originals[2],
        context_bytes=originals[3], expectations=owned, verifier_private_key=private, work=work)
    service._require_generation_on_work("verifier", generation, work)
    return result


def _relay_on_work(process, *, operation, intent_bytes, envelope_bytes, proof_bytes,
        inputs_bytes, context_bytes, historical_expectations_bytes, producing, work):
    """Fixed local signing or remote preparation; neither path contacts a writer."""
    if type(producing) is not bool:
        raise ValueError("transition custody relay action is not source fixed")
    operation = service._operation(operation)
    originals = transport._validate_relay_originals(intent_bytes=intent_bytes,
        envelope_bytes=envelope_bytes, proof_bytes=proof_bytes, inputs_bytes=inputs_bytes,
        context_bytes=context_bytes, historical_expectations_bytes=historical_expectations_bytes)
    role = "planner" if producing else "verifier"
    payload, digest, generation, _dsn, private = _context_on_work(
        process, role=role, signing=producing, work=work)
    arguments = {"operation": operation, "payload": payload,
        "configuration_digest": digest, "generation": generation,
        "intent_bytes": originals[0], "envelope_bytes": originals[1],
        "proof_bytes": originals[2], "inputs_bytes": originals[3],
        "context_bytes": originals[4], "historical_expectations_bytes": originals[5], "work": work}
    if producing:
        result = actions._produce_relay_on_configuration(**arguments, planner_private_key=private)
    else:
        result = actions._request_relay_on_configuration(**arguments)
    service._require_generation_on_work(role, generation, work)
    return result


def _produce_relay_on_work(process, *, operation, intent_bytes, envelope_bytes,
        proof_bytes, inputs_bytes, context_bytes, historical_expectations_bytes, work):
    return _relay_on_work(process, operation=operation, intent_bytes=intent_bytes,
        envelope_bytes=envelope_bytes, proof_bytes=proof_bytes, inputs_bytes=inputs_bytes,
        context_bytes=context_bytes, historical_expectations_bytes=historical_expectations_bytes,
        producing=True, work=work)


def _request_relay_on_work(process, *, operation, intent_bytes, envelope_bytes,
        proof_bytes, inputs_bytes, context_bytes, historical_expectations_bytes, work):
    return _relay_on_work(process, operation=operation, intent_bytes=intent_bytes,
        envelope_bytes=envelope_bytes, proof_bytes=proof_bytes, inputs_bytes=inputs_bytes,
        context_bytes=context_bytes, historical_expectations_bytes=historical_expectations_bytes,
        producing=False, work=work)


def _delivery_on_work(process, *, operation, intent_bytes, relay_bytes, envelope_bytes,
        proof_bytes, inputs_bytes, context_bytes, historical_expectations_bytes, kind, work):
    """One source-selected delivery edge, with no retries or generic callback."""
    if type(kind) is not str or kind not in ("forward", "send", "persist"):
        raise ValueError("transition custody delivery action is not source fixed")
    operation = service._operation(operation)
    originals = transport._validate_originals(intent_bytes=intent_bytes, relay_bytes=relay_bytes,
        envelope_bytes=envelope_bytes, proof_bytes=proof_bytes, inputs_bytes=inputs_bytes,
        context_bytes=context_bytes, historical_expectations_bytes=historical_expectations_bytes)
    role = {"forward": "verifier", "send": "planner", "persist": "planner-writer"}[kind]
    payload, digest, generation, dsn, _private = _context_on_work(
        process, role=role, signing=False, work=work)
    arguments = {"operation": operation, "payload": payload,
        "configuration_digest": digest, "generation": generation,
        "intent_bytes": originals[0], "relay_bytes": originals[1],
        "envelope_bytes": originals[2], "proof_bytes": originals[3], "inputs_bytes": originals[4],
        "context_bytes": originals[5], "historical_expectations_bytes": originals[6], "work": work}
    if kind == "persist":
        result = actions._persist_on_configuration(**arguments, writer_dsn=dsn)
    elif kind == "send":
        result = actions._send_on_configuration(**arguments)
    else:
        result = actions._forward_on_configuration(**arguments)
    # The writer may already have committed. Failure here is not rollback
    # evidence and must not authorize regeneration or automatic forwarding.
    service._require_generation_on_work(role, generation, work)
    return result


def _forward_on_work(process, *, operation, intent_bytes, relay_bytes, envelope_bytes,
        proof_bytes, inputs_bytes, context_bytes, historical_expectations_bytes, work):
    return _delivery_on_work(process, operation=operation, intent_bytes=intent_bytes,
        relay_bytes=relay_bytes, envelope_bytes=envelope_bytes, proof_bytes=proof_bytes,
        inputs_bytes=inputs_bytes, context_bytes=context_bytes,
        historical_expectations_bytes=historical_expectations_bytes, kind="forward", work=work)


def _send_on_work(process, *, operation, intent_bytes, relay_bytes, envelope_bytes,
        proof_bytes, inputs_bytes, context_bytes, historical_expectations_bytes, work):
    return _delivery_on_work(process, operation=operation, intent_bytes=intent_bytes,
        relay_bytes=relay_bytes, envelope_bytes=envelope_bytes, proof_bytes=proof_bytes,
        inputs_bytes=inputs_bytes, context_bytes=context_bytes,
        historical_expectations_bytes=historical_expectations_bytes, kind="send", work=work)


def _persist_on_work(process, *, operation, intent_bytes, relay_bytes, envelope_bytes,
        proof_bytes, inputs_bytes, context_bytes, historical_expectations_bytes, work):
    return _delivery_on_work(process, operation=operation, intent_bytes=intent_bytes,
        relay_bytes=relay_bytes, envelope_bytes=envelope_bytes, proof_bytes=proof_bytes,
        inputs_bytes=inputs_bytes, context_bytes=context_bytes,
        historical_expectations_bytes=historical_expectations_bytes, kind="persist", work=work)
