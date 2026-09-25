"""Configured authenticated retrieval of original evidence-plan custody.

A fresh verifier-signed read request binds the requested record and independent
historical expectations. It does not claim plan replay before the originals
are available. The writer uses the existing real read owner; each receiving
client genuinely replays returned raw3 against the authenticated history and
configured purpose pins on the same caller work.

The current read window never refreshes the historical plan, evidence or
evaluation cutoff. Current configuration consistency does not establish old
root/key authority. Peer metadata is informational, not a signed durability,
execution, rollback or absence receipt. No mutation, automatic retry, signer
substitution, registry bypass or replacement allowance is introduced.
"""
from __future__ import annotations

from serverware import authority_webauthn_evidence_custody_configuration as configuration
from serverware import authority_webauthn_evidence_custody_read_request as request
from serverware import authority_webauthn_evidence_custody_read_transport as transport
from serverware import authority_webauthn_evidence_custody_wire as wire
from serverware import authority_webauthn_evidence_plan_persistence as persistence
from serverware import authority_webauthn_evidence_plan_verifier as verifier


evidence, retention = wire.evidence, wire.retention
_OPERATIONS = {"registration": "webauthn.registration.evidence.admit",
    "installation": "webauthn.trust.installation.admit"}
_OBSERVATION_FIELDS = frozenset({"envelope_bytes", "inputs_bytes", "evaluation_context_bytes",
    "retained_record_digest", "retained_at_epoch_ns"})


class WebAuthnEvidenceCustodyReadActionError(ValueError):
    pass


def _operation(purpose):
    if type(purpose) is not str or purpose not in _OPERATIONS:
        raise WebAuthnEvidenceCustodyReadActionError("evidence custody read purpose is not source fixed")
    return _OPERATIONS[purpose]


def _historical_retention_on_work(payload_bytes, historical_times, retained_at_epoch_ns, work):
    """Check a returned timestamp against the actual replayed original plan."""
    ledger = evidence.capture._SharedLedger(work)
    contract = retention.plan.contract
    payload = evidence.wire._decode_object(payload_bytes, work=work,
        maximum_bytes=contract.MAX_BYTES, maximum_nodes=contract.MAX_NODES,
        maximum_depth=contract.MAX_DEPTH)
    contract.validate_payload_shape(payload)
    evidence.capability._canonical(payload_bytes, payload, ledger, contract.MAX_BYTES, contract.MAX_NODES)
    # These are the held original history scalars, not a current-time rewrite
    # or an independently accepted successful verification object.
    retention.plan._fresh(payload, historical_times, retained_at_epoch_ns)


def _produce_on_configuration(*, purpose, payload, configuration_digest, generation,
        retained_record_digest, expectations, verifier_private_key, work):
    ledger = evidence.capture._SharedLedger(work)
    operation = _operation(purpose)
    record_digest, private_key = retained_record_digest, verifier_private_key
    evidence.plan.contract._digest(record_digest)
    if not isinstance(private_key, retention.plan.Ed25519PrivateKey):
        raise WebAuthnEvidenceCustodyReadActionError("evidence custody read requires the real verifier signer")
    evidence.plan.contract._object(expectations, retention.plan._EXPECTATION_FIELDS,
        "independent evidence custody read history")
    owned = evidence.capture._JSONCapture(ledger).visit(expectations)
    retention.plan._validate_expectations(owned, operation)
    configured = configuration._capture_on_work(purpose=purpose, payload=payload,
        configuration_digest=configuration_digest, generation=generation, work=work)
    return request._produce_on_work(retained_record_digest=record_digest, expectations=owned,
        pins=configured.pins, generation_sequence=configured.generation_sequence,
        generation_digest=configured.generation_digest, verifier_private_key=private_key,
        verifier_public_key=configured.verifier_public_key,
        maximum_control_age_ns=configured.maximum_control_age_ns, work=work)


def _read_on_configuration(*, purpose, payload, configuration_digest, generation,
        control_bytes, historical_expectations_bytes, writer_dsn, work):
    evidence.capture._SharedLedger(work)
    _operation(purpose)
    originals = transport._validate_request(control_bytes=control_bytes,
        historical_expectations_bytes=historical_expectations_bytes)
    configured = configuration._capture_on_work(purpose=purpose, payload=payload,
        configuration_digest=configuration_digest, generation=generation, writer_dsn=writer_dsn, work=work)
    writer_configuration = configured.writer_configuration
    if writer_configuration is None:
        raise WebAuthnEvidenceCustodyReadActionError("evidence custody read requires protected writer configuration")
    pins, public_key = configured.pins, configured.verifier_public_key
    sequence, generation_digest = configured.generation_sequence, configured.generation_digest
    age, skew = configured.maximum_control_age_ns, pins[9]
    verified = request._verify_on_work(control_bytes=originals[0], historical_expectations_bytes=originals[1],
        pins=pins, generation_sequence=sequence, generation_digest=generation_digest,
        verifier_public_key=public_key, maximum_control_age_ns=age, work=work)
    record_digest, window = verified.retained_record_digest, verified.window
    timing = {"issuedAtEpochNs": verified.issued_at_epoch_ns, "expiresAtEpochNs": verified.expires_at_epoch_ns}
    # Reconstruct history from the authenticated original, not from a returned
    # verification carrier. The real configured joins repeat before the owner.
    historical = retention.context_wire._decode_on_work(originals[1], work=work)
    owned = persistence._capture(writer_configuration, historical, work)
    wire._fresh_on_work(timing, window=window, maximum_age_ns=age, maximum_clock_skew_ns=skew, work=work)
    result = persistence._run(writer_configuration, {"retained_record_digest": record_digest}, owned,
        persist=False, work=work)
    now = wire._fresh_on_work(timing, window=window, maximum_age_ns=age, maximum_clock_skew_ns=skew, work=work)
    if (type(result) is not dict or len(result) != len(_OBSERVATION_FIELDS)
            or set(result) != _OBSERVATION_FIELDS):
        raise WebAuthnEvidenceCustodyReadActionError("evidence custody store observation is not exact")
    evidence.plan.contract._integer(result["retained_at_epoch_ns"], minimum=1)
    evidence.plan._same(result["retained_record_digest"], record_digest, work,
        "evidence custody read differs from the authenticated requested record")
    if result["retained_at_epoch_ns"] > now + skew:
        raise WebAuthnEvidenceCustodyReadActionError("evidence custody read returned a future retention time")
    # The actual read owner has normally exited its transaction and connection.
    # Missing/incomplete custody still raises; it is never an absence proof.
    wire._fresh_on_work(timing, window=window, maximum_age_ns=age, maximum_clock_skew_ns=skew, work=work)
    return result


def _request_originals_on_configuration(*, forward, purpose, payload, configuration_digest, generation,
        control_bytes, historical_expectations_bytes, work):
    evidence.capture._SharedLedger(work)
    if type(forward) is not bool:
        raise WebAuthnEvidenceCustodyReadActionError("evidence custody read hop is not fixed")
    _operation(purpose)
    originals = transport._validate_request(control_bytes=control_bytes,
        historical_expectations_bytes=historical_expectations_bytes)
    configured = configuration._capture_on_work(purpose=purpose, payload=payload,
        configuration_digest=configuration_digest, generation=generation, work=work)
    pins, public_key = configured.pins, configured.verifier_public_key
    sequence, generation_digest = configured.generation_sequence, configured.generation_digest
    age, skew = configured.maximum_control_age_ns, pins[9]
    path, timeout, peer_uid, peer_gid = (configured.writer_endpoint if forward else configured.planner_endpoint)
    verified = request._verify_on_work(control_bytes=originals[0], historical_expectations_bytes=originals[1],
        pins=pins, generation_sequence=sequence, generation_digest=generation_digest,
        verifier_public_key=public_key, maximum_control_age_ns=age, work=work)
    record_digest, window = verified.retained_record_digest, verified.window
    timing = {"issuedAtEpochNs": verified.issued_at_epoch_ns, "expiresAtEpochNs": verified.expires_at_epoch_ns}
    wire._fresh_on_work(timing, window=window, maximum_age_ns=age, maximum_clock_skew_ns=skew, work=work)
    response = evidence.production._callback(work,
        lambda: (transport._socket_forward_request if forward else transport._socket_request)(
            path, purpose=purpose, control_bytes=originals[0], historical_expectations_bytes=originals[1],
            timeout_seconds=timeout, expected_peer_uid=peer_uid, expected_peer_gid=peer_gid))
    returned = transport._validate_response(response)
    wire._fresh_on_work(timing, window=window, maximum_age_ns=age, maximum_clock_skew_ns=skew, work=work)
    historical = retention.context_wire._decode_on_work(originals[1], work=work)
    historical_times = {"deadlineEpochNs": historical["deadlineEpochNs"],
        "maximumPlanAgeNs": historical["maximumPlanAgeNs"],
        "maximumClockSkewNs": historical["maximumClockSkewNs"]}
    owner = verifier.EvidencePlanVerifier(pins=pins)
    retained = verifier.EvidencePlanVerifier.verify(owner, envelope_bytes=returned[0],
        inputs_bytes=returned[1], evaluation_context_bytes=returned[2], expectations=historical, work=work)
    actual_record, payload_bytes = retained.record_digest, retained.verification.payload_bytes
    evidence.plan._same((actual_record, returned[3]), (record_digest, record_digest), work,
        "evidence custody response differs from the original requested and genuinely replayed record")
    _historical_retention_on_work(payload_bytes, historical_times, returned[4], work)
    now = wire._fresh_on_work(timing, window=window, maximum_age_ns=age, maximum_clock_skew_ns=skew, work=work)
    if returned[4] > now + skew:
        raise WebAuthnEvidenceCustodyReadActionError("evidence custody peer returned a future retention time")
    return returned


def _request_on_configuration(*, purpose, payload, configuration_digest, generation,
        control_bytes, historical_expectations_bytes, work):
    return _request_originals_on_configuration(forward=False, purpose=purpose, payload=payload,
        configuration_digest=configuration_digest, generation=generation, control_bytes=control_bytes,
        historical_expectations_bytes=historical_expectations_bytes, work=work)


def _forward_on_configuration(*, purpose, payload, configuration_digest, generation,
        control_bytes, historical_expectations_bytes, work):
    return _request_originals_on_configuration(forward=True, purpose=purpose, payload=payload,
        configuration_digest=configuration_digest, generation=generation, control_bytes=control_bytes,
        historical_expectations_bytes=historical_expectations_bytes, work=work)
