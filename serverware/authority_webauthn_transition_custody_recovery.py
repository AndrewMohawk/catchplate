"""Authenticate original transition custody before a fresh read-only lookup.

An original intent locates only an already root-admitted historical verifier
key. Its genuine signature and every original-body commitment are checked
before historical expectations are decoded. Those authenticated expectations
then select the actual planner/evaluation snapshot; the original relay and
raw-four plan undergo genuine signature, policy and proof/semantic replay.

Historical controls retain their original intervals and are never subjected
to a new live control window. A separate current, archive-bounded window spans
this recovery and the existing signed lookup. Exact returned originals and
record identity must match. Neither an unsigned timestamp nor a missing or
late response proves durability, absence, rollback or permission to retry.
There is no persistence, execution, cross-source enrollment or new allowance.
"""
from __future__ import annotations

from serverware import authority_webauthn_custody_history as history
from serverware import authority_webauthn_transition_custody_configuration as configuration
from serverware import authority_webauthn_transition_custody_intent as intent
from serverware import authority_webauthn_transition_custody_read_request as read_request
from serverware import authority_webauthn_transition_custody_read_transport as read_transport
from serverware import authority_webauthn_transition_custody_service as custody
from serverware import authority_webauthn_transition_custody_transport as transport
from serverware import authority_webauthn_transition_custody_wire as wire
from serverware import authority_webauthn_transition_plan_admission as admission


evidence, retention = wire.evidence, wire.retention


class WebAuthnTransitionCustodyRecoveryError(ValueError):
    pass


def _same_owner(process, measured, archive):
    if process.configuration is not measured or measured.history_archive is not archive:
        raise WebAuthnTransitionCustodyRecoveryError("transition recovery admission changed during this call")


def _archive_time(snapshots, now):
    if not snapshots.valid_from_epoch_ns <= now < snapshots.valid_until_epoch_ns:
        raise WebAuthnTransitionCustodyRecoveryError("transition recovery archive authorization is not current")


def _current_on_work(process, measured, archive, snapshots, window, work):
    _same_owner(process, measured, archive)
    now = wire.clock._check_on_work(window, work=work)
    _archive_time(snapshots, now)
    _same_owner(process, measured, archive)


def _configuration_on_work(snapshot, operation, work):
    # All graphs originate in this call's detached, root-admitted archive
    # selection. The real mapper owns them before its native key callbacks.
    return configuration._capture_on_work(operation=operation, payload=snapshot.payload,
        configuration_digest=snapshot.configuration_digest, generation=snapshot.generation,
        runtime_role_identities=snapshot.runtime_role_identities, work=work)


def _historical_times(timing, snapshot, configured):
    value = {"issuedAtEpochNs": timing[0], "expiresAtEpochNs": timing[1]}
    issued, expires = wire._time_pins(value, configured.maximum_control_age_ns,
        configured.pins[6][1])
    if issued < snapshot.valid_from_epoch_ns or expires > snapshot.valid_until_epoch_ns:
        raise WebAuthnTransitionCustodyRecoveryError("original transition control exceeds its admitted historical interval")
    return issued, expires


def _equal_original(left, right, work, label):
    # Raw bytes are not JSON equality inputs. Prepay the full actual scan.
    work.charge(input_bytes=len(left) + len(right))
    if left != right:
        raise WebAuthnTransitionCustodyRecoveryError(label)


def _recover_on_work(process, *, operation, originals: tuple, work):
    """Resolve original raw7 to the existing read response raw4/digest/time."""
    from serverware import authority_service as service

    ledger = evidence.capture._SharedLedger(work)
    if (type(process) is not service.AuthorityProcess or process.role_name != "verifier"
            or process.process_mode != service.PROCESS_MODES["verifier"]):
        raise WebAuthnTransitionCustodyRecoveryError("transition recovery requires the actual verifier process")
    measured = process.configuration
    if type(measured) is not service.MeasuredConfiguration:
        raise WebAuthnTransitionCustodyRecoveryError("transition recovery requires measured current configuration")
    held_archive = measured.history_archive
    operation = custody.service._operation(operation)
    if type(originals) is not tuple or len(originals) != 7:
        raise WebAuthnTransitionCustodyRecoveryError("transition recovery requires the exact original raw7 tuple")
    originals = transport._validate_originals(intent_bytes=originals[0], relay_bytes=originals[1],
        envelope_bytes=originals[2], proof_bytes=originals[3], inputs_bytes=originals[4],
        context_bytes=originals[5], historical_expectations_bytes=originals[6])
    snapshots = history.archive._capture_on_work(held_archive, work=work)
    # Check current archive authority before any configuration/key/launch
    # callback. This clock observes only current admission, not old controls.
    _archive_time(snapshots, wire.clock._sample_on_work(work)[1])
    _same_owner(process, measured, held_archive)
    payload, digest, generation, _dsn, _private, runtime = custody._context_on_work(
        process, role="verifier", signing=False, work=work)
    current = configuration._capture_on_work(operation=operation, payload=payload,
        configuration_digest=digest, generation=generation,
        runtime_role_identities=runtime, work=work)
    window = wire.clock._open_on_work(deadline_epoch_ns=snapshots.valid_until_epoch_ns,
        maximum_lifetime_ns=current.maximum_control_age_ns,
        maximum_clock_skew_ns=current.pins[6][1], work=work)
    _current_on_work(process, measured, held_archive, snapshots, window, work)

    value, signature, unsigned = wire._read_control(originals[0], relay=False, work=work)
    intent_scope = (value["configurationDigest"], value["generationSequence"],
        value["generationDigest"], value["operation"])
    intent_times = value["issuedAtEpochNs"], value["expiresAtEpochNs"]
    record_digest = value["retainedRecordDigest"]
    signed_bodies = tuple((name, value[name]) for name in intent._BODY_FIELDS)
    evidence.plan._same(intent_scope[3], operation, work,
        "original transition intent differs from the fixed recovery operation")
    # Unauthenticated locators can only choose an already root-admitted key.
    # No history or plan context has been decoded at this point.
    located = history.archive._lookup_control_on_work(snapshots,
        configuration_digest=intent_scope[0], generation_digest=intent_scope[2],
        issued_at_epoch_ns=intent_times[0], work=work)
    bootstrap = _configuration_on_work(located, operation, work)
    bootstrap_key = bootstrap.verifier_public_key
    wire._signature(signature, unsigned, relay=False, public_key=bootstrap_key, work=work)
    evidence.capability._canonical(originals[0], value, ledger,
        wire.MAX_CONTROL_BYTES, wire.MAX_CONTROL_NODES)
    wire._bind_control(value, configuration_digest=bootstrap.pins[5],
        generation_sequence=bootstrap.generation_sequence, generation_digest=bootstrap.generation_digest,
        operation=operation, work=work)
    actual_bodies = wire._body_commitments_on_work(envelope_bytes=originals[2],
        proof_bytes=originals[3], inputs_bytes=originals[4], context_bytes=originals[5],
        historical_expectations_bytes=originals[6], work=work)
    evidence.plan._same(actual_bodies, dict(signed_bodies), work,
        "original transition intent differs from its complete raw5 commitments")
    bootstrap_key_digest = retention._key_digest(bootstrap_key, work)
    _current_on_work(process, measured, held_archive, snapshots, window, work)

    # Only authenticated original verifier history supplies these selectors.
    # Root-admitted archive membership, not the locator or plan, supplies trust.
    historical = retention.context_wire._decode_on_work(originals[6], work=work)
    actual_operation = retention.plan.contract._validate_expectations(historical)
    evidence.plan._same(actual_operation, operation, work,
        "authenticated transition history differs from the fixed recovery operation")
    snapshot = history.archive._lookup_on_work(snapshots,
        configuration_digest=historical["configurationDigest"],
        planner_attestation_receipt_digest=historical["plannerIdentity"]["attestationReceiptDigest"],
        evaluation_epoch_ns=historical["proofExpectations"]["policy"]["nowEpochNs"], work=work)
    configured = _configuration_on_work(snapshot, operation, work)
    pins = configured.pins
    _equal_original(originals[6],
        retention.context_wire._encode_on_work(expectations=historical, work=work), work,
        "authenticated transition history changed during historical key mapping")
    owned = admission._capture_expectations_on_work(pins, historical, work)
    evidence.plan._same(bootstrap_key_digest, retention._key_digest(configured.verifier_public_key, work),
        work, "transition intent locator and actual historical verifier key differ")
    # Rejoin the original control after all historical mapper/key callbacks.
    # Subsequent timing and identity decisions use the pre-callback scalars.
    evidence.capability._canonical(originals[0], value, ledger,
        wire.MAX_CONTROL_BYTES, wire.MAX_CONTROL_NODES)
    wire._bind_control(value, configuration_digest=pins[5],
        generation_sequence=configured.generation_sequence, generation_digest=configured.generation_digest,
        operation=operation, work=work)
    intent_times = _historical_times(intent_times, snapshot, configured)

    relay, relay_signature, relay_unsigned = wire._read_control(originals[1], relay=True, work=work)
    relay_times = relay["issuedAtEpochNs"], relay["expiresAtEpochNs"]
    relay_record_digest = relay["retainedRecordDigest"]
    relay_intent_commitment = relay["intentBytesDigest"], relay["intentByteCount"]
    wire._signature(relay_signature, relay_unsigned, relay=True, public_key=pins[1], work=work)
    actual_intent_commitment = retention._bytes_digest(originals[0], work), len(originals[0])
    evidence.capability._canonical(originals[1], relay, ledger,
        wire.MAX_CONTROL_BYTES, wire.MAX_CONTROL_NODES)
    wire._bind_control(relay, configuration_digest=pins[5],
        generation_sequence=configured.generation_sequence, generation_digest=configured.generation_digest,
        operation=operation, work=work)
    evidence.plan._same(actual_intent_commitment, relay_intent_commitment, work,
        "original transition relay differs from the exact original intent")
    evidence.plan._same(relay_record_digest, record_digest, work,
        "original transition controls name different retained records")
    relay_times = _historical_times(relay_times, snapshot, configured)
    if relay_times[1] > intent_times[1] or relay_times[0] < intent_times[0] - pins[6][1]:
        raise WebAuthnTransitionCustodyRecoveryError("original transition relay widens or predates its intent")
    _current_on_work(process, measured, held_archive, snapshots, window, work)

    retained = retention._verify_record_on_work(envelope_bytes=originals[2], proof_bytes=originals[3],
        inputs_bytes=originals[4], context_bytes=originals[5], expectations=owned,
        planner_public_key=pins[1], operation_public_key=pins[4], work=work)
    evidence.plan._same(retained.record_digest, record_digest, work,
        "original transition controls differ from genuine raw4 historical replay")
    plan_payload = intent._payload_on_work(originals[2], work)
    for issued, expires in (intent_times, relay_times):
        if (expires > plan_payload["expiresAtEpochNs"]
                or expires > owned["proofExpectations"]["policy"]["deadlineEpochNs"]):
            raise WebAuthnTransitionCustodyRecoveryError("original transition control extends its plan or invocation deadline")
        retention.plan._fresh(plan_payload, owned, issued)
        retention.plan._fresh(plan_payload, owned, expires - 1)
    _current_on_work(process, measured, held_archive, snapshots, window, work)
    custody.service._require_generation_on_work("verifier", generation, work)
    _current_on_work(process, measured, held_archive, snapshots, window, work)

    # Only now invoke the real current verifier's read-only signed lookup.
    # Its existing client genuinely verifies the returned originals again;
    # no successful replay carrier or stored context replaces those bytes.
    produced = service.AuthorityProcess._produce_webauthn_transition_custody_read_request(
        process, operation=operation, retained_record_digest=record_digest,
        expectations=owned, work=work)
    if type(produced) is not read_request._ProducedReadRequest:
        raise WebAuthnTransitionCustodyRecoveryError("transition recovery did not produce the actual lookup originals")
    control, lookup_history = read_request._raw2(produced.control_bytes, produced.historical_expectations_bytes)
    _equal_original(originals[6], lookup_history, work,
        "transition recovery lookup changed the authenticated original history")
    _current_on_work(process, measured, held_archive, snapshots, window, work)
    response = service.AuthorityProcess._request_webauthn_transition_custody_read(
        process, operation=operation, control_bytes=control,
        historical_expectations_bytes=lookup_history, work=work)
    returned = read_transport._validate_response(response)
    _current_on_work(process, measured, held_archive, snapshots, window, work)
    evidence.plan._same(returned[4], record_digest, work,
        "transition recovery response differs from its authenticated original record")
    for original, received in zip(originals[2:6], returned[:4]):
        _equal_original(original, received, work, "transition recovery returned different original plan bytes")
    custody.service._require_generation_on_work("verifier", generation, work)
    _current_on_work(process, measured, held_archive, snapshots, window, work)
    return returned
