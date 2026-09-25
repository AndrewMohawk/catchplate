"""Configured authenticated retrieval of original successor-plan custody.

A fresh verifier control binds one retained identity and independent historical
expectations. No proof replay is claimed before the original raw4 is available.
The writer invokes its actual fixed read owner and returns only after normal
transaction/connection exit; both receiving clients genuinely replay returned
originals against the authenticated history and configured purpose pins.

The current lookup window never renews historical plan, input or root authority.
Historical retention time is checked against the original signed plan, not the
current clock. Peer metadata remains unsigned information, not a signed custody,
execution, rollback or absence receipt. No write, retry, new allowance or public
operation callback is introduced.
"""
from __future__ import annotations

from serverware import authority_webauthn_transition_custody_configuration as configuration
from serverware import authority_webauthn_transition_custody_read_request as request
from serverware import authority_webauthn_transition_custody_read_transport as transport
from serverware import authority_webauthn_transition_custody_wire as wire
from serverware import authority_webauthn_transition_persistence as persistence
from serverware import authority_webauthn_transition_plan_admission as admission


evidence, retention = wire.evidence, wire.retention
_OBSERVATION_FIELDS = frozenset({"envelope_bytes", "proof_bytes", "inputs_bytes", "context_bytes",
    "retained_record_digest", "retained_at_epoch_ns"})


class WebAuthnTransitionCustodyReadActionError(ValueError):
    pass


def _operation(operation):
    if type(operation) is not str or operation not in retention.plan.contract.OPERATIONS:
        raise WebAuthnTransitionCustodyReadActionError("transition custody read operation is not source fixed")
    return operation


def _historical_retention_on_work(envelope_bytes, expectations, retained_at_epoch_ns, work):
    """Check the original envelope at historical retention time, never now."""
    ledger = evidence.capture._SharedLedger(work)
    contract = retention.plan.contract
    envelope = evidence.wire._decode_object(envelope_bytes, work=work,
        maximum_bytes=contract.MAX_BYTES, maximum_nodes=contract.MAX_NODES,
        maximum_depth=contract.MAX_DEPTH)
    contract.validate_envelope_shape(envelope)
    evidence.capability._canonical(envelope_bytes, envelope, ledger, contract.MAX_BYTES, contract.MAX_NODES)
    retention.plan._fresh(envelope["payload"], expectations, retained_at_epoch_ns)


def _produce_on_configuration(*, operation, payload, configuration_digest, generation,
        retained_record_digest, expectations, verifier_private_key, work):
    ledger = evidence.capture._SharedLedger(work)
    operation = _operation(operation)
    record_digest, private = retained_record_digest, verifier_private_key
    evidence.plan.contract._digest(record_digest)
    if not isinstance(private, retention.plan.Ed25519PrivateKey):
        raise WebAuthnTransitionCustodyReadActionError("transition custody read requires the real verifier signer")
    retention.plan.contract.shape._object(expectations, retention.plan.contract.EXPECTATION_FIELDS,
        "independent transition custody read history")
    owned = evidence.capture._JSONCapture(ledger).visit(expectations)
    expected_operation = retention.plan.contract._validate_expectations(owned)
    evidence.plan._same(expected_operation, operation, work,
        "transition custody read history differs from its selected operation")
    configured = configuration._capture_on_work(operation=operation, payload=payload,
        configuration_digest=configuration_digest, generation=generation, work=work)
    return request._produce_on_work(retained_record_digest=record_digest, expectations=owned,
        pins=configured.pins, generation_sequence=configured.generation_sequence,
        generation_digest=configured.generation_digest, verifier_private_key=private,
        verifier_public_key=configured.verifier_public_key,
        maximum_control_age_ns=configured.maximum_control_age_ns, work=work)


def _read_on_configuration(*, operation, payload, configuration_digest, generation,
        control_bytes, historical_expectations_bytes, writer_dsn, work):
    evidence.capture._SharedLedger(work)
    operation = _operation(operation)
    originals = transport._validate_request(control_bytes=control_bytes,
        historical_expectations_bytes=historical_expectations_bytes)
    configured = configuration._capture_on_work(operation=operation, payload=payload,
        configuration_digest=configuration_digest, generation=generation, writer_dsn=writer_dsn, work=work)
    owner = configured.writer_configuration
    if owner is None:
        raise WebAuthnTransitionCustodyReadActionError("transition custody read requires protected writer configuration")
    # Keep the actual owner's immutable database/policy tuple through all
    # request/key callbacks, rather than rereading its original mutable slots.
    fixed = persistence._snapshot(owner)
    held_owner = persistence.TransitionPlanPersistence(writer_dsn=fixed[0],
        connect_timeout_seconds=fixed[1], database_identity=fixed[2], pins=fixed[3:])
    pins, public = configured.pins, configured.verifier_public_key
    sequence, digest = configured.generation_sequence, configured.generation_digest
    age, skew = configured.maximum_control_age_ns, pins[6][1]
    verified = request._verify_on_work(control_bytes=originals[0], historical_expectations_bytes=originals[1],
        pins=pins, generation_sequence=sequence, generation_digest=digest,
        verifier_public_key=public, maximum_control_age_ns=age, work=work)
    record_digest, window = verified.retained_record_digest, verified.window
    timing = {"issuedAtEpochNs": verified.issued_at_epoch_ns, "expiresAtEpochNs": verified.expires_at_epoch_ns}
    # Decode only the authenticated original history, never a graph from a
    # successful verification carrier or an unverified stored plan context.
    historical = retention.context_wire._decode_on_work(originals[1], work=work)
    owned = admission._capture_expectations_on_work(pins, historical, work)
    wire._fresh_on_work(timing, window=window, maximum_age_ns=age, maximum_clock_skew_ns=skew, work=work)
    result = persistence.TransitionPlanPersistence.read(held_owner,
        retained_record_digest=record_digest, expectations=owned, work=work)
    evidence.plan.contract._object(result, _OBSERVATION_FIELDS, "transition custody store observation")
    returned = transport._validate_response((result["envelope_bytes"], result["proof_bytes"],
        result["inputs_bytes"], result["context_bytes"],
        result["retained_record_digest"], result["retained_at_epoch_ns"]))
    evidence.plan._same(returned[4], record_digest, work,
        "transition custody read differs from the authenticated requested record")
    now = wire._fresh_on_work(timing, window=window, maximum_age_ns=age, maximum_clock_skew_ns=skew, work=work)
    if returned[5] > now + skew:
        raise WebAuthnTransitionCustodyReadActionError("transition custody read returned a future retention time")
    # The real owner already replayed the original record and checked its
    # historical timestamp, then normally closed every database scope. Keep
    # immutable output refs held across the final real lookup-window check.
    wire._fresh_on_work(timing, window=window, maximum_age_ns=age, maximum_clock_skew_ns=skew, work=work)
    return {"envelope_bytes": returned[0], "proof_bytes": returned[1], "inputs_bytes": returned[2],
        "context_bytes": returned[3], "retained_record_digest": returned[4], "retained_at_epoch_ns": returned[5]}


def _request_originals_on_configuration(*, forward, operation, payload, configuration_digest, generation,
        control_bytes, historical_expectations_bytes, work):
    evidence.capture._SharedLedger(work)
    if type(forward) is not bool:
        raise WebAuthnTransitionCustodyReadActionError("transition custody read hop is not fixed")
    operation = _operation(operation)
    originals = transport._validate_request(control_bytes=control_bytes,
        historical_expectations_bytes=historical_expectations_bytes)
    configured = configuration._capture_on_work(operation=operation, payload=payload,
        configuration_digest=configuration_digest, generation=generation, work=work)
    pins, public = configured.pins, configured.verifier_public_key
    sequence, digest = configured.generation_sequence, configured.generation_digest
    age, skew = configured.maximum_control_age_ns, pins[6][1]
    path, timeout, peer_uid, peer_gid = (configured.writer_endpoint if forward else configured.planner_endpoint)
    verified = request._verify_on_work(control_bytes=originals[0], historical_expectations_bytes=originals[1],
        pins=pins, generation_sequence=sequence, generation_digest=digest,
        verifier_public_key=public, maximum_control_age_ns=age, work=work)
    record_digest, window = verified.retained_record_digest, verified.window
    timing = {"issuedAtEpochNs": verified.issued_at_epoch_ns, "expiresAtEpochNs": verified.expires_at_epoch_ns}
    wire._fresh_on_work(timing, window=window, maximum_age_ns=age, maximum_clock_skew_ns=skew, work=work)
    response = evidence.production._callback(work,
        lambda: (transport._socket_forward_request if forward else transport._socket_request)(
            path, operation=operation, control_bytes=originals[0], historical_expectations_bytes=originals[1],
            timeout_seconds=timeout, expected_peer_uid=peer_uid, expected_peer_gid=peer_gid))
    returned = transport._validate_response(response)
    wire._fresh_on_work(timing, window=window, maximum_age_ns=age, maximum_clock_skew_ns=skew, work=work)
    historical = retention.context_wire._decode_on_work(originals[1], work=work)
    owned = admission._capture_expectations_on_work(pins, historical, work)
    retained = retention._verify_record_on_work(envelope_bytes=returned[0], proof_bytes=returned[1],
        inputs_bytes=returned[2], context_bytes=returned[3], expectations=owned,
        planner_public_key=pins[1], operation_public_key=pins[4], work=work)
    evidence.plan._same((retained.record_digest, returned[4]), (record_digest, record_digest), work,
        "transition custody response differs from the requested and genuinely replayed record")
    _historical_retention_on_work(returned[0], owned, returned[5], work)
    now = wire._fresh_on_work(timing, window=window, maximum_age_ns=age, maximum_clock_skew_ns=skew, work=work)
    if returned[5] > now + skew:
        raise WebAuthnTransitionCustodyReadActionError("transition custody peer returned a future retention time")
    return returned


def _request_on_configuration(*, operation, payload, configuration_digest, generation,
        control_bytes, historical_expectations_bytes, work):
    return _request_originals_on_configuration(forward=False, operation=operation, payload=payload,
        configuration_digest=configuration_digest, generation=generation, control_bytes=control_bytes,
        historical_expectations_bytes=historical_expectations_bytes, work=work)


def _forward_on_configuration(*, operation, payload, configuration_digest, generation,
        control_bytes, historical_expectations_bytes, work):
    return _request_originals_on_configuration(forward=True, operation=operation, payload=payload,
        configuration_digest=configuration_digest, generation=generation, control_bytes=control_bytes,
        historical_expectations_bytes=historical_expectations_bytes, work=work)
