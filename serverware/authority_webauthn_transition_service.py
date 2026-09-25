"""Private measured-service boundaries for successor planning and custody.

The actual service configuration loader, protected descriptors and active
launch guard supply admission. A caller-created configuration or returned
owner does not. Fixed factory callers select only a planner reader, signed
producer, verifier, verifier-root reader or custody owner for three source operations;
no request chooses keys,
policy, descriptor names, callbacks or a replacement work allowance.

The factories do not open SQL or enable public operations. The explicit root
read performs only its separately admitted read-only acquisition. Dedicated
live exchange methods authenticate and replay original planning bytes, with no
custody, reservation, business execution or automatic retry. Historical
handoff and custody expectations are owned before all launch/key callbacks and
must be independently admitted upstream, never adopted from received context
bytes. Explicit custody calls are separate from planning and return only after
the actual writer transaction and connection exit; an uncertain error cannot
prove rollback or authorize another attempt.
"""
from __future__ import annotations

from serverware import authority_contract as authority
from serverware import authority_revocation_configuration as configuration
from serverware import authority_webauthn_transition_plan as plan
from serverware import authority_webauthn_transition_configuration as mapping
from serverware import authority_webauthn_transition_plan_verifier as verifying
from serverware import authority_webauthn_transition_root_configuration as root_mapping
from serverware import authority_webauthn_transition_root_reader as root_reader
from serverware import authority_webauthn_transition_roots_contract as root_contract
from serverware import authority_webauthn_transition_retention as retention
from serverware import authority_webauthn_transition_persistence as persistence
from serverware import authority_webauthn_transition_writer_configuration as writer_mapping


def _operation(value):
    if type(value) is not str or value not in plan.contract.OPERATIONS:
        raise ValueError("measured transition operation is not source fixed")
    return value


def _measured_context_on_work(process, *, role, signing, read_descriptor, work):
    """Hold measured inputs for one fixed local role before any callbacks."""
    # The service imports these private boundaries lazily after its genuine
    # classes exist; this fixed reverse import does not create a startup cycle.
    from serverware import authority_service as service

    planner_dsn = "SERVERWARE_POLICY_AUTHORITY_PLANNER_READ_POSTGRES_DSN"
    verifier_dsn = "SERVERWARE_POLICY_AUTHORITY_VERIFIER_READ_POSTGRES_DSN"
    writer_dsn = "SERVERWARE_POLICY_AUTHORITY_PLANNER_WRITER_POSTGRES_DSN"
    if (type(role) is not str or type(signing) is not bool
            or type(read_descriptor) not in (str, type(None))
            or (role, signing, read_descriptor) not in (
                ("planner", False, planner_dsn), ("planner", True, planner_dsn),
                ("verifier", False, None), ("verifier", False, verifier_dsn),
                ("verifier", True, verifier_dsn), ("planner-writer", False, writer_dsn))):
        raise service.AuthorityServiceError("transition service context is not source fixed")
    if (type(process) is not service.AuthorityProcess or process.role_name != role
            or process.process_mode != "policy-authority-" + role):
        raise service.AuthorityServiceError("transition service process is not configured")
    measured = process.configuration
    if type(measured) is not service.MeasuredConfiguration:
        raise service.AuthorityServiceError("transition measured configuration is unavailable")
    payload, digest = measured.payload, measured.digest
    private = process.signing_key if signing else None
    if signing and not isinstance(private, service.Ed25519PrivateKey):
        raise service.AuthorityServiceError("transition service signer is unavailable")
    ledger = configuration.capability.capture._SharedLedger(work)
    configuration.capability.shape._digest(digest)
    if type(payload) is not dict:
        raise service.AuthorityServiceError("transition configuration is not closed data")
    owned = configuration._ConfigurationCapture(
        ledger, maximum_bytes=authority.MAX_REQUEST_BYTES).visit(payload)
    configuration.production._callback(work, lambda: service.authority_launch_guard.require_active(role))
    dsn = (None if read_descriptor is None else configuration.production._callback(work,
        lambda: service._read_dsn_descriptor(read_descriptor)))
    # No process/configuration/descriptor lookup follows this final snapshot.
    # The fixed selected mapper immediately owns and checks its seven bindings.
    generation = configuration.production._callback(
        work, lambda: dict(service.authority_launch_guard.generation()))
    return owned, digest, generation, dsn, private


def _context_on_work(process, *, operation, kind, work):
    """Own one actual measured configuration before real admission callbacks."""
    operation = _operation(operation)
    if type(kind) is not str or kind not in ("reader", "producer", "verifier", "roots", "persistence"):
        raise ValueError("transition service factory is not source fixed")
    role = ("planner-writer" if kind == "persistence" else
        "verifier" if kind in ("verifier", "roots") else "planner")
    descriptor = (None if kind == "verifier" else
        "SERVERWARE_POLICY_AUTHORITY_PLANNER_WRITER_POSTGRES_DSN" if kind == "persistence" else
        "SERVERWARE_POLICY_AUTHORITY_VERIFIER_READ_POSTGRES_DSN" if kind == "roots"
        else "SERVERWARE_POLICY_AUTHORITY_PLANNER_READ_POSTGRES_DSN")
    mapper = {
        "reader": mapping._planner_from_configuration_on_work,
        "producer": mapping._producer_from_configuration_on_work,
        "verifier": mapping._verifier_from_configuration_on_work,
        "roots": root_mapping._reader_from_configuration_on_work,
        "persistence": writer_mapping._persistence_from_configuration_on_work,
    }[kind]
    owned, digest, generation, dsn, private = _measured_context_on_work(process,
        role=role, signing=kind == "producer", read_descriptor=descriptor, work=work)
    arguments = {"operation": operation, "payload": owned, "configuration_digest": digest,
        "generation": generation, "work": work}
    if kind == "persistence":
        arguments["writer_dsn"] = dsn
    elif kind != "verifier":
        arguments["read_dsn"] = dsn
    if kind == "producer":
        arguments["planner_private_key"] = private
    return mapper, arguments


def _configured_on_work(process, *, operation, kind, work):
    mapper, arguments = _context_on_work(process, operation=operation, kind=kind, work=work)
    return mapper(**arguments)


def _planner_on_work(process, *, operation, work):
    return _configured_on_work(process, operation=operation, kind="reader", work=work)


def _producer_on_work(process, *, operation, work):
    return _configured_on_work(process, operation=operation, kind="producer", work=work)


def _verifier_on_work(process, *, operation, work):
    return _configured_on_work(process, operation=operation, kind="verifier", work=work)


def _root_reader_on_work(process, *, operation, work):
    return _configured_on_work(process, operation=operation, kind="roots", work=work)


def _persistence_on_work(process, *, operation, work):
    return _configured_on_work(process, operation=operation, kind="persistence", work=work)


def _generation_on_work(value, work):
    ledger = configuration.capability.capture._SharedLedger(work)
    configuration.capability.shape._bounded_object(value, 20, "transition root launch context")
    return configuration.capability.capture._JSONCapture(ledger).visit(
        {name: value[name] for name in configuration._GENERATION_FIELDS})


def _require_generation_on_work(role, generation, work):
    from serverware import authority_service as service

    configuration.production._callback(work, lambda: service.authority_launch_guard.require_active(role))
    final = configuration.production._callback(work, lambda: dict(service.authority_launch_guard.generation()))
    configuration.capability.plan._same(generation, _generation_on_work(final, work), work,
        "transition service generation changed")


def _history_on_work(operation, expectations, work):
    """Own independently admitted history without parsing a retained context."""
    ledger = plan.evidence.capture._SharedLedger(work)
    owned = plan.evidence.capture._JSONCapture(
        ledger, maximum_bytes=plan.contract.MAX_BYTES).visit(expectations)
    expected_operation = plan.contract._validate_expectations(owned)
    plan.evidence.plan._same(expected_operation, operation, work,
        "transition history differs from its independently selected operation")
    return owned


def _custody_owner_on_work(process, operation, work):
    mapper, arguments = _context_on_work(process, operation=operation, kind="persistence", work=work)
    generation = _generation_on_work(arguments["generation"], work)
    arguments["generation"] = generation
    return mapper(**arguments), generation


def _persist_plan_on_work(process, *, operation, envelope_bytes, proof_bytes,
        inputs_bytes, context_bytes, expectations, work):
    """Retain raw4 under independent history, not the preceding live response.

    A failure after the actual outer commit, including final generation
    rejection, does not establish that custody was rolled back. No retry or
    business execution follows this private call.
    """
    operation = _operation(operation)
    originals = retention._raw4(envelope_bytes, proof_bytes, inputs_bytes, context_bytes)
    owned = _history_on_work(operation, expectations, work)
    owner, generation = _custody_owner_on_work(process, operation, work)
    result = persistence.TransitionPlanPersistence.persist(owner,
        envelope_bytes=originals[0], proof_bytes=originals[1], inputs_bytes=originals[2],
        context_bytes=originals[3], expectations=owned, work=work)
    _require_generation_on_work("planner-writer", generation, work)
    return result


def _read_plan_on_work(process, *, operation, retained_record_digest, expectations, work):
    """Read and replay historical originals without renewing plan lifetime."""
    operation = _operation(operation)
    plan.contract.shape._digest(retained_record_digest)
    digest = retained_record_digest
    owned = _history_on_work(operation, expectations, work)
    owner, generation = _custody_owner_on_work(process, operation, work)
    result = persistence.TransitionPlanPersistence.read(owner,
        retained_record_digest=digest, expectations=owned, work=work)
    _require_generation_on_work("planner-writer", generation, work)
    return result


def _produce_request_on_work(process, *, operation, request, inputs_bytes,
        now_epoch_ns, deadline_epoch_ns, invocation, work):
    """Sign admitted original inputs and genuine independent root observations.

    This private preparation does not send anything. Upstream must admit the
    request, original evaluation instant, capability or committed-stage history;
    possession of a JSON object cannot supply that provenance.
    """
    from serverware import authority_webauthn_transition_actions as actions

    operation = _operation(operation)
    original_inputs = inputs_bytes
    plan.proof.wire._raw(original_inputs, 2, plan.proof.wire.MAX_BYTES)
    owned = configuration.capability.capture._JSONCapture(
        configuration.capability.capture._SharedLedger(work),
        maximum_bytes=plan.contract.MAX_BYTES).visit({"request": request,
            "nowEpochNs": now_epoch_ns, "deadlineEpochNs": deadline_epoch_ns,
            "invocation": invocation})
    request_owned = root_contract._capture_request_on_work(
        request=owned["request"], operation=operation, work=work)
    for name in ("nowEpochNs", "deadlineEpochNs"):
        configuration.capability.shape._integer(owned[name], minimum=1)
    if owned["nowEpochNs"] >= owned["deadlineEpochNs"]:
        raise ValueError("transition planning invocation has no positive lifetime")
    payload, digest, generation, dsn, private = _measured_context_on_work(process,
        role="verifier", signing=True,
        read_descriptor="SERVERWARE_POLICY_AUTHORITY_VERIFIER_READ_POSTGRES_DSN", work=work)
    held_generation = _generation_on_work(generation, work)
    reader = root_mapping._reader_from_configuration_on_work(operation=operation,
        payload=payload, configuration_digest=digest, generation=held_generation, read_dsn=dsn, work=work)
    inventory = root_reader.TransitionRootReader.read(reader, request=request_owned, work=work)
    business, authorization, heads = root_contract._project_on_work(
        inventory, operation=operation, request=request_owned, work=work)
    _require_generation_on_work("verifier", held_generation, work)
    result = actions._produce_request_on_configuration(operation=operation,
        payload=payload, configuration_digest=digest, generation=held_generation,
        request=request_owned, business_before_roots=business,
        authorization_before_roots=authorization, counted_before_heads=heads,
        inputs_bytes=original_inputs, now_epoch_ns=owned["nowEpochNs"],
        deadline_epoch_ns=owned["deadlineEpochNs"], invocation=owned["invocation"],
        verifier_private_key=private, work=work)
    _require_generation_on_work("verifier", held_generation, work)
    return result


def _request_plan_on_work(process, *, operation, control_bytes, context_bytes, inputs_bytes, work):
    """Send original request bytes and replay the authenticated raw-four reply."""
    from serverware import authority_webauthn_transition_actions as actions
    from serverware import authority_webauthn_transition_transport as transport

    operation = _operation(operation)
    originals = transport._validate_request(control_bytes=control_bytes,
        context_bytes=context_bytes, inputs_bytes=inputs_bytes)
    payload, digest, generation, _dsn, _private = _measured_context_on_work(process,
        role="verifier", signing=False, read_descriptor=None, work=work)
    held_generation = _generation_on_work(generation, work)
    result = actions._request_plan_on_configuration(operation=operation,
        payload=payload, configuration_digest=digest, generation=held_generation,
        control_bytes=originals[0], context_bytes=originals[1], inputs_bytes=originals[2], work=work)
    _require_generation_on_work("verifier", held_generation, work)
    return result


def _produce_plan_on_work(process, *, operation, control_bytes, context_bytes, inputs_bytes, work):
    """Authenticate a request before actual configured read, replay and signing."""
    from serverware import authority_webauthn_transition_actions as actions
    from serverware import authority_webauthn_transition_transport as transport

    operation = _operation(operation)
    originals = transport._validate_request(control_bytes=control_bytes,
        context_bytes=context_bytes, inputs_bytes=inputs_bytes)
    payload, digest, generation, dsn, private = _measured_context_on_work(process,
        role="planner", signing=True,
        read_descriptor="SERVERWARE_POLICY_AUTHORITY_PLANNER_READ_POSTGRES_DSN", work=work)
    held_generation = _generation_on_work(generation, work)
    result = actions._produce_plan_on_configuration(operation=operation,
        payload=payload, configuration_digest=digest, generation=held_generation,
        control_bytes=originals[0], context_bytes=originals[1], inputs_bytes=originals[2],
        read_dsn=dsn, planner_private_key=private, work=work)
    _require_generation_on_work("planner", held_generation, work)
    return result


def _read_roots_on_work(process, *, operation, request, work):
    """Read independent primary/count roots, then check the held generation.

    No received plan/context supplies the roots. Completion of the read and
    generation checks neither reserves those roots nor holds them current for
    a later planner or writer. The inventory remains an ordinary observation.
    """
    from serverware import authority_service as service

    operation = _operation(operation)
    owned = root_contract._capture_request_on_work(request=request, operation=operation, work=work)
    mapper, arguments = _context_on_work(process, operation=operation, kind="roots", work=work)
    generation = _generation_on_work(arguments["generation"], work)
    reader = mapper(**arguments)
    inventory = root_reader.TransitionRootReader.read(reader, request=owned, work=work)
    configuration.production._callback(work, lambda: service.authority_launch_guard.require_active("verifier"))
    final = configuration.production._callback(work, lambda: dict(service.authority_launch_guard.generation()))
    configuration.capability.plan._same(generation, _generation_on_work(final, work), work,
        "transition verifier root read generation changed")
    return inventory


def _verify_handoff_on_work(process, *, operation, envelope_bytes, proof_bytes,
        inputs_bytes, context_bytes, expectations, work):
    """Verify raw-four against owned independent history without a new clock."""
    operation = _operation(operation)
    originals = envelope_bytes, proof_bytes, inputs_bytes, context_bytes
    plan.proof.wire._raw(originals[0], 2, plan.contract.MAX_BYTES)
    plan._originals(originals[1], originals[2], originals[3])
    owned = _history_on_work(operation, expectations, work)
    # Only now may active-launch and real key constructors run. Configuration
    # pins can constrain supplied history but never establish its provenance.
    verifier = _verifier_on_work(process, operation=operation, work=work)
    return verifying.TransitionPlanVerifier.verify(verifier, envelope_bytes=originals[0],
        proof_bytes=originals[1], inputs_bytes=originals[2], context_bytes=originals[3],
        expectations=owned, work=work)
