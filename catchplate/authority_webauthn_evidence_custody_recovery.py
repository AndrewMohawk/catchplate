"""Authenticate original evidence custody before an explicit read-only lookup.

An original intent header locates only an already root-admitted historical
verifier key. Its real signature, scope and all byte commitments precede any
history decoding. The authenticated history then selects its actual planner
cohort and original evaluation interval; real relay authentication and retained
raw3 replay follow. No successful observation supplied by a caller is accepted.

Old controls are checked at their original times without opening live windows
for them. A separate, unchanged current archive window bounds this whole call.
The genuine current verifier signs a fresh read request and uses the existing
read-only custody path. Returned originals must equal the attempted originals.
No custody write, resend, signing of old controls, clock renewal, new allowance,
execution authority, absence proof or durable receipt is introduced here.
"""
from __future__ import annotations

from catchplate import authority_historical_archive as archive
from catchplate import authority_webauthn_evidence_custody_configuration as configuration
from catchplate import authority_webauthn_evidence_custody_transport as custody_transport
from catchplate import authority_webauthn_evidence_custody_read_transport as read_transport
from catchplate import authority_webauthn_evidence_custody_wire as wire
from catchplate import authority_webauthn_evidence_plan_admission as admission
from catchplate import authority_webauthn_evidence_plan_verifier as verifier


evidence, retention, clock = wire.evidence, wire.retention, wire.clock
_BODY_FIELDS = ("envelopeBytesDigest", "envelopeByteCount", "inputsBytesDigest", "inputsByteCount",
    "contextBytesDigest", "contextByteCount", "historyBytesDigest", "historyByteCount")


class WebAuthnEvidenceCustodyRecoveryError(ValueError):
    pass


def _same_bytes(left, right, work, label):
    if type(left) is not bytes or type(right) is not bytes:
        raise WebAuthnEvidenceCustodyRecoveryError(label)
    work.charge(input_bytes=len(left) + len(right))
    if left != right:
        raise WebAuthnEvidenceCustodyRecoveryError(label)


def _configured_snapshot(purpose, snapshot, work):
    # Selected graphs are detached by the real archive on the same work. The
    # actual mapper captures them before its first native key callback.
    return configuration._capture_on_work(purpose=purpose,
        payload=snapshot.payload, configuration_digest=snapshot.configuration_digest,
        generation=snapshot.generation, runtime_role_identities=snapshot.runtime_role_identities,
        work=work)


def _scope(configured):
    return (configured.pins[7], configured.generation_sequence,
        configured.generation_digest, configured.pins[0])


def _bind(value, scope, work):
    wire._bind_control(value, configuration_digest=scope[0], generation_sequence=scope[1],
        generation_digest=scope[2], operation=scope[3], work=work)


def _interval(times, interval, maximum_age_ns, skew):
    # Pure historical policy checks: never sample now or renew either control.
    issued, expires = wire._time_pins({"issuedAtEpochNs": times[0], "expiresAtEpochNs": times[1]},
        maximum_age_ns, skew)
    if issued < interval[0] or expires > interval[1]:
        raise WebAuthnEvidenceCustodyRecoveryError("original control lies outside its admitted historical snapshot")
    return issued, expires


def _archive_current(process, measured, held_archive, configuration_digest, window, validity, work):
    if (process.configuration is not measured or measured.history_archive is not held_archive
            or measured.digest != configuration_digest
            or process.role_name != "verifier" or process.process_mode != "policy-authority-verifier"):
        raise WebAuthnEvidenceCustodyRecoveryError("recovery process changed its admitted current scope")
    now = clock._check_on_work(window, work=work)
    if not validity[0] <= now < validity[1]:
        raise WebAuthnEvidenceCustodyRecoveryError("current historical archive authorization expired")
    if (process.configuration is not measured or measured.history_archive is not held_archive
            or measured.digest != configuration_digest):
        raise WebAuthnEvidenceCustodyRecoveryError("recovery configuration changed during a clock callback")


def _recover_on_work(process, *, purpose, originals, work):
    """Return exact raw3/digest/time only through genuine current custody read."""
    from catchplate import authority_service as service

    ledger = evidence.capture._SharedLedger(work)
    operation = service._webauthn_evidence_custody_purpose(purpose)
    if type(originals) is not tuple or len(originals) != 6:
        raise WebAuthnEvidenceCustodyRecoveryError("evidence recovery needs the exact original six-tuple")
    originals = custody_transport._validate_originals(intent_bytes=originals[0], relay_bytes=originals[1],
        envelope_bytes=originals[2], inputs_bytes=originals[3],
        evaluation_context_bytes=originals[4], historical_expectations_bytes=originals[5])
    if (type(process) is not service.AuthorityProcess or process.role_name != "verifier"
            or process.process_mode != "policy-authority-verifier"):
        raise WebAuthnEvidenceCustodyRecoveryError("evidence recovery requires the real verifier process")
    measured = process.configuration
    if type(measured) is not service.MeasuredConfiguration:
        raise WebAuthnEvidenceCustodyRecoveryError("evidence recovery current configuration is unavailable")
    held_archive, current_digest = measured.history_archive, measured.digest
    snapshots = archive._capture_on_work(held_archive, work=work)
    validity = snapshots.valid_from_epoch_ns, snapshots.valid_until_epoch_ns
    # The genuine service continuation owns current payload/runtime graphs
    # before active-launch callbacks and obtains the admitted generation last.
    payload, digest, generation, _dsn, _signer, runtime = service._webauthn_evidence_custody_context(
        process, role_name="verifier", signing=False, work=work)
    evidence.plan._same(digest, current_digest, work, "evidence recovery changed current configuration")
    current = configuration._capture_on_work(purpose=purpose, payload=payload,
        configuration_digest=digest, generation=generation, runtime_role_identities=runtime, work=work)
    window = clock._open_on_work(deadline_epoch_ns=validity[1],
        maximum_lifetime_ns=current.maximum_control_age_ns,
        maximum_clock_skew_ns=current.pins[9], work=work)
    _archive_current(process, measured, held_archive, current_digest, window, validity, work)

    value, signature, unsigned = wire._read_control(originals[0], relay=False, work=work)
    locator = value["configurationDigest"], value["generationDigest"], value["issuedAtEpochNs"]
    intent_times = value["issuedAtEpochNs"], value["expiresAtEpochNs"]
    record_digest = value["retainedRecordDigest"]
    signed_bodies = {name: value[name] for name in _BODY_FIELDS}
    bootstrap_snapshot = archive._lookup_control_on_work(snapshots,
        configuration_digest=locator[0], generation_digest=locator[1],
        issued_at_epoch_ns=locator[2], work=work)
    bootstrap = _configured_snapshot(purpose, bootstrap_snapshot, work)
    bootstrap_scope = _scope(bootstrap)
    bootstrap_key = bootstrap.verifier_public_key
    _archive_current(process, measured, held_archive, current_digest, window, validity, work)
    wire._signature(signature, unsigned, relay=False, public_key=bootstrap_key, work=work)
    evidence.capability._canonical(originals[0], value, ledger, wire.MAX_CONTROL_BYTES, wire.MAX_CONTROL_NODES)
    _bind(value, bootstrap_scope, work)
    actual_bodies = wire._body_commitments_on_work(envelope_bytes=originals[2],
        inputs_bytes=originals[3], evaluation_context_bytes=originals[4],
        historical_expectations_bytes=originals[5], work=work)
    evidence.plan._same(actual_bodies, signed_bodies, work,
        "original evidence intent does not commit every recovery body")
    bootstrap_key_digest = retention._key_digest(bootstrap_key, work)
    _archive_current(process, measured, held_archive, current_digest, window, validity, work)

    # Only the authenticated original history selects the actual cohort.
    historical = retention.context_wire._decode_on_work(originals[5], work=work)
    retention.plan._validate_expectations(historical, operation)
    selected = archive._lookup_on_work(snapshots,
        configuration_digest=historical["configurationDigest"],
        planner_attestation_receipt_digest=historical["plannerIdentity"]["attestationReceiptDigest"],
        evaluation_epoch_ns=historical["nowEpochNs"], work=work)
    selected_interval = selected.valid_from_epoch_ns, selected.valid_until_epoch_ns
    configured = _configured_snapshot(purpose, selected, work)
    pins, scope = configured.pins, _scope(configured)
    age, skew = configured.maximum_control_age_ns, pins[9]
    evidence.plan._same(retention._key_digest(configured.verifier_public_key, work),
        bootstrap_key_digest, work, "historical recovery verifier key differs from authenticated intent key")
    evidence.capability._canonical(originals[0], value, ledger, wire.MAX_CONTROL_BYTES, wire.MAX_CONTROL_NODES)
    _bind(value, scope, work)
    _interval(intent_times, selected_interval, age, skew)
    # Reject mutation of decoded history during configuration/key callbacks;
    # the immutable, authenticated original remains the comparison authority.
    encoded_history = retention.context_wire._encode_on_work(expectations=historical, work=work)
    _same_bytes(encoded_history, originals[5], work, "authenticated evidence recovery history changed")
    owned = admission._capture_expectations_on_work(pins, historical, work)
    historical_times = {"deadlineEpochNs": owned["deadlineEpochNs"],
        "maximumPlanAgeNs": owned["maximumPlanAgeNs"], "maximumClockSkewNs": owned["maximumClockSkewNs"]}
    _archive_current(process, measured, held_archive, current_digest, window, validity, work)

    relay, relay_signature, relay_unsigned = wire._read_control(originals[1], relay=True, work=work)
    relay_times = relay["issuedAtEpochNs"], relay["expiresAtEpochNs"]
    relay_commitment = relay["intentBytesDigest"], relay["intentByteCount"], relay["retainedRecordDigest"]
    wire._signature(relay_signature, relay_unsigned, relay=True, public_key=pins[1], work=work)
    evidence.capability._canonical(originals[1], relay, ledger, wire.MAX_CONTROL_BYTES, wire.MAX_CONTROL_NODES)
    _bind(relay, scope, work)
    evidence.plan._same((retention._bytes_digest(originals[0], work), len(originals[0]), record_digest),
        relay_commitment, work, "original planner relay differs from the authenticated intent and record")
    _interval(relay_times, selected_interval, age, skew)
    if relay_times[1] > intent_times[1] or relay_times[0] < intent_times[0] - skew:
        raise WebAuthnEvidenceCustodyRecoveryError("original relay widens or predates its intent")
    _archive_current(process, measured, held_archive, current_digest, window, validity, work)

    owner = verifier.EvidencePlanVerifier(pins=pins)
    retained = verifier.EvidencePlanVerifier.verify(owner, envelope_bytes=originals[2],
        inputs_bytes=originals[3], evaluation_context_bytes=originals[4], expectations=owned, work=work)
    actual_record, payload_bytes = retained.record_digest, retained.verification.payload_bytes
    evidence.plan._same(actual_record, record_digest, work,
        "original controls differ from genuinely replayed evidence custody")
    contract = retention.plan.contract
    plan_payload = evidence.wire._decode_object(payload_bytes, work=work,
        maximum_bytes=contract.MAX_BYTES, maximum_nodes=contract.MAX_NODES, maximum_depth=contract.MAX_DEPTH)
    contract.validate_payload_shape(plan_payload)
    evidence.capability._canonical(payload_bytes, plan_payload, ledger, contract.MAX_BYTES, contract.MAX_NODES)
    for issued, expires in (intent_times, relay_times):
        retention.plan._fresh(plan_payload, historical_times, issued)
        if expires > min(plan_payload["expiresAtEpochNs"], historical_times["deadlineEpochNs"]):
            raise WebAuthnEvidenceCustodyRecoveryError("original control extends its plan or invocation interval")
    _archive_current(process, measured, held_archive, current_digest, window, validity, work)

    # Authenticate current read authority afresh through its actual fixed
    # service methods. Neither method receives a successful historical DTO.
    request = service.AuthorityProcess._produce_webauthn_evidence_custody_read_request(process,
        purpose=purpose, retained_record_digest=actual_record, expectations=owned, work=work)
    control_bytes, historical_bytes = request.control_bytes, request.historical_expectations_bytes
    _same_bytes(historical_bytes, originals[5], work, "current lookup changed authenticated original history")
    _archive_current(process, measured, held_archive, current_digest, window, validity, work)
    returned = service.AuthorityProcess._request_webauthn_evidence_custody_read(process,
        purpose=purpose, control_bytes=control_bytes, historical_expectations_bytes=historical_bytes, work=work)
    returned = read_transport._validate_response(returned)
    _archive_current(process, measured, held_archive, current_digest, window, validity, work)
    for actual, original in zip(returned[:3], originals[2:5]):
        _same_bytes(actual, original, work, "reconciled custody differs from the exact attempted originals")
    evidence.plan._same(returned[3], actual_record, work,
        "reconciled custody record differs from the genuinely replayed attempted record")
    _archive_current(process, measured, held_archive, current_digest, window, validity, work)
    return returned
