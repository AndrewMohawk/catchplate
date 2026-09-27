"""Actual verifier preparation of a complete registration planning exchange.

The private caller supplies original signer request8/response2, never browser
roots, a typed successful request or historical expectations. Genuine signer
replay derives the request and preserves its original interval. The actual
configured verifier then reads one source-complete root vector through its
protected PostgreSQL read owner and signs planning roots projected from THAT
vector. The configured planner's original response is authenticated and its
plan genuinely replayed before all seven exchange originals plus the vector
return. No second independent root read invents a common snapshot.

The root observation is not latest-head authority or a reservation. This path
does not issue caller authorization, contact the execution-grant service,
write custody, execute SQL mutations or report registration success. Existing
raw6 custody preparation is unchanged. All reads, replay, signing and transport
use the caller's same work and original epoch/monotonic bounds; blocking driver
calls still require an external watchdog for hard termination guarantees.
"""
from __future__ import annotations

import time

from serverware import authority_current_root_reader as complete_reader
from serverware import authority_current_root_vector as vector
from serverware import authority_historical_archive as archive
from serverware import authority_revocation_configuration as measured_configuration
from serverware import authority_webauthn_evidence_custody_configuration as configuration
from serverware import authority_webauthn_evidence_plan_actions as actions
from serverware import authority_webauthn_evidence_plan_request as request_wire
from serverware import authority_webauthn_evidence_plan_transport as transport
from serverware import authority_webauthn_evidence_preparation as preparation
from serverware import authority_webauthn_evidence_root_configuration as root_configuration
from serverware import authority_webauthn_evidence_root_reader as purpose_reader
from serverware import authority_webauthn_evidence_roots as purpose_roots
from serverware import authority_webauthn_registration_signer_response as signer_response


evidence, clock = request_wire.evidence, request_wire.clock
OPERATION = "webauthn.registration.evidence.admit"
MAX_ORIGINAL_BYTES = request_wire.authority.MAX_RESULT_BYTES


class RegistrationExecutionPreparationError(ValueError):
    pass


def _receipt_interval(receipt):
    if type(receipt) is not dict or type(receipt.get("payload")) is not dict:
        raise RegistrationExecutionPreparationError("registration verifier original receipt is missing")
    issued, expires = receipt["payload"].get("issuedAtEpochNs"), receipt["payload"].get("expiresAtEpochNs")
    evidence.plan.contract._integer(issued, minimum=1)
    evidence.plan.contract._integer(expires, minimum=1)
    if issued >= expires:
        raise RegistrationExecutionPreparationError("registration verifier original receipt interval is invalid")
    return issued, expires


def _project_before_on_work(original, work):
    """Project source-ordered operation roots from the same genuine vector."""
    document = vector._decode_on_work(original, work=work)
    business_tables, authorization_tables = purpose_roots._source(OPERATION)
    work.prepare_scan(document)
    primary = {row["table"]: row for row in document["primaryRoots"]}
    work.charge(json_nodes=2 + len(business_tables) + len(authorization_tables))
    selected = {"business": [primary[table] for table in business_tables],
        "authorization": [primary[table] for table in authorization_tables]}
    owned = evidence.capture._JSONCapture(evidence.capture._SharedLedger(work),
        maximum_bytes=vector.MAX_BYTES).visit(selected)
    contract = request_wire.plan.contract
    contract._roots(owned["business"], contract._BUSINESS_TABLES[OPERATION])
    contract._roots(owned["authorization"], contract._AUTHORIZATION_TABLES[OPERATION])
    return owned["business"], owned["authorization"]


def _prepare_on_work(process, *, request_originals, response_originals,
        deadline_epoch_ns, work, transport_deadline_ns=None):
    """Return planning request3 + response4 + complete vector, all original bytes."""
    from serverware import authority_service as service

    ledger = evidence.capture._SharedLedger(work)
    request_raw = signer_response.wire._request_originals(request_originals)
    response_raw = signer_response.wire._response_originals(response_originals)
    if sum(len(raw) for raw in (*request_raw, *response_raw)) > MAX_ORIGINAL_BYTES:
        raise RegistrationExecutionPreparationError("registration signer originals exceed the source aggregate")
    evidence.plan.contract._integer(deadline_epoch_ns, minimum=1)
    if transport_deadline_ns is not None:
        evidence.plan.contract._integer(transport_deadline_ns, minimum=1)
    deadline, inherited = deadline_epoch_ns, transport_deadline_ns
    if (type(process) is not service.AuthorityProcess or process.role_name != "verifier"
            or process.process_mode != "policy-authority-verifier"
            or type(process.configuration) is not service.MeasuredConfiguration):
        raise RegistrationExecutionPreparationError("registration execution preparation requires the actual verifier")
    measured = process.configuration
    held_archive, digest, receipt = measured.history_archive, measured.digest, measured.attestation_evidence
    receipt_interval = _receipt_interval(receipt)
    snapshots = archive._capture_on_work(held_archive, work=work)
    validity = snapshots.valid_from_epoch_ns, snapshots.valid_until_epoch_ns
    if inherited is not None:
        evidence.production._callback(work, lambda: transport._check_deadline(inherited))
    payload, captured_digest, generation, read_dsn, signer, runtime = service._webauthn_evidence_custody_context(
        process, role_name="verifier", signing=True, read_roots=True, work=work)
    evidence.plan._same(captured_digest, digest, work, "registration preparation configuration changed")
    held_generation = evidence.capture._JSONCapture(ledger).visit(
        {name: generation[name] for name in measured_configuration._GENERATION_FIELDS})
    configured = configuration._capture_on_work(purpose="registration", payload=payload,
        configuration_digest=digest, generation=held_generation,
        runtime_role_identities=runtime, work=work)
    window = clock._open_on_work(deadline_epoch_ns=min(deadline, validity[1], receipt_interval[1]),
        maximum_lifetime_ns=configured.maximum_control_age_ns,
        maximum_clock_skew_ns=configured.pins[9], work=work)
    bound = window[4] if inherited is None else min(window[4], inherited)
    last_epoch, last_monotonic = window[0], window[2]

    def current():
        nonlocal last_epoch, last_monotonic
        preparation._current(process, measured, held_archive, digest, held_generation,
            runtime, window, validity, work, bound)
        if (process.signing_key is not signer or measured.attestation_evidence is not receipt
                or _receipt_interval(receipt) != receipt_interval):
            raise RegistrationExecutionPreparationError("registration verifier signer or receipt changed")
        now = clock._check_on_work(window, work=work)
        monotonic = evidence.production._callback(work, time.monotonic_ns)
        evidence.plan.contract._integer(monotonic, minimum=1)
        if (now < last_epoch or monotonic < last_monotonic or monotonic >= bound
                or not receipt_interval[0] <= now < receipt_interval[1]):
            raise RegistrationExecutionPreparationError("registration preparation expired or its original clocks reversed")
        last_epoch, last_monotonic = now, monotonic

    current()
    replayed = signer_response._verify_execution_request_on_configuration(payload=payload,
        configuration_digest=digest, generation=held_generation,
        runtime_role_identities=runtime, request_originals=request_raw,
        response_originals=response_raw, work=work)
    # The response input bytes were reproduced and compared by genuine replay.
    # Its new request is ordinary same-call data, not an accepted input token.
    request = evidence.capture._JSONCapture(ledger,
        maximum_bytes=request_wire.MAX_CONTEXT_BYTES).visit(replayed.request)
    inputs = response_raw[1]
    effective_expiry = min(window[3], replayed.expires_at_epoch_ns)
    window = clock._validate((window[0], window[1], window[2], effective_expiry,
        window[1] + effective_expiry - window[0], window[5], window[6]))
    bound = min(bound, window[4], replayed.deadline_ns)
    last_epoch = max(last_epoch, replayed.last_epoch_ns)
    current()

    # Reuse the existing admitted verifier-policy mapper, without invoking its
    # operation-only read. Both real owners share the exact seven DB/TLS pins.
    selected_reader = root_configuration._reader_from_configuration_on_work(purpose="registration",
        payload=payload, configuration_digest=digest, generation=held_generation,
        runtime_role_identities=runtime, read_dsn=read_dsn, work=work)
    root_pins = purpose_reader.EvidenceRootReader._snapshot_configuration(selected_reader)
    evidence.plan._same(root_pins[0], OPERATION, work, "registration root reader operation changed")
    full_reader = complete_reader.CurrentRootReader(dsn=root_pins[1],
        connect_timeout_seconds=root_pins[2], database_role=root_pins[3],
        tls_client_dn=root_pins[4], tls_client_serial=root_pins[5],
        tls_issuer_dn=root_pins[6], query_manifest_digest=root_pins[7])
    current()
    before = complete_reader.CurrentRootReader.read(full_reader, work=work)
    current()
    business, authorization = _project_before_on_work(before, work)
    current()
    planned = actions._produce_request_on_configuration(purpose="registration", payload=payload,
        configuration_digest=digest, generation=held_generation, runtime_role_identities=runtime,
        request=request, business_before_roots=business, authorization_before_roots=authorization,
        inputs_bytes=inputs, deadline_epoch_ns=window[3], verifier_private_key=signer, work=work)
    planned_originals = transport._validate_request(control_bytes=planned.control_bytes,
        context_bytes=planned.context_bytes, inputs_bytes=planned.inputs_bytes)
    request_control, _signature, _unsigned = request_wire._read_control(planned_originals[0], work)
    preparation._interval(request_control["issuedAtEpochNs"], request_control["expiresAtEpochNs"], validity)
    current()
    response = actions._request_plan_on_configuration(purpose="registration", payload=payload,
        configuration_digest=digest, generation=held_generation, runtime_role_identities=runtime,
        control_bytes=planned_originals[0], context_bytes=planned_originals[1],
        inputs_bytes=planned_originals[2], work=work, transport_deadline_ns=bound)
    response = transport._validate_response(*response)
    preparation._plan_interval(response[1], validity, work)
    originals = (*planned_originals, *response, before)
    if sum(len(raw) for raw in originals) > MAX_ORIGINAL_BYTES:
        raise RegistrationExecutionPreparationError("prepared registration originals exceed the source aggregate")
    current()
    return originals
