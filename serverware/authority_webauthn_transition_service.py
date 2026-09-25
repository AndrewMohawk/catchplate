"""Private measured-service boundaries for configured successor planning.

The actual service configuration loader, protected descriptors and active
launch guard supply admission. A caller-created configuration or returned
owner does not. Fixed factory callers select only a reader, signed producer
or verifier for one of the three source operations; no request chooses keys,
policy, descriptor names, callbacks or a replacement work allowance.

These factories do not open SQL or enable public operations. Historical
handoff expectations are owned before all launch/key callbacks and must be
independently admitted upstream, never adopted from received context bytes.
"""
from __future__ import annotations

from serverware import authority_contract as authority
from serverware import authority_revocation_configuration as configuration
from serverware import authority_webauthn_transition_plan as plan
from serverware import authority_webauthn_transition_configuration as mapping
from serverware import authority_webauthn_transition_plan_verifier as verifying


def _operation(value):
    if type(value) is not str or value not in plan.contract.OPERATIONS:
        raise ValueError("measured transition operation is not source fixed")
    return value


def _configured_on_work(process, *, operation, kind, work):
    """Own one actual measured configuration before real admission callbacks."""
    # The service imports these private boundaries lazily after its genuine
    # classes exist; this fixed reverse import does not create a startup cycle.
    from serverware import authority_service as service

    operation = _operation(operation)
    if type(kind) is not str or kind not in ("reader", "producer", "verifier"):
        raise service.AuthorityServiceError("transition service factory is not source fixed")
    role = "verifier" if kind == "verifier" else "planner"
    if (type(process) is not service.AuthorityProcess or process.role_name != role
            or process.process_mode != "policy-authority-" + role):
        raise service.AuthorityServiceError("transition service process is not configured")
    measured = process.configuration
    if type(measured) is not service.MeasuredConfiguration:
        raise service.AuthorityServiceError("transition measured configuration is unavailable")
    payload, digest = measured.payload, measured.digest
    private = process.signing_key if kind == "producer" else None
    if kind == "producer" and not isinstance(private, service.Ed25519PrivateKey):
        raise service.AuthorityServiceError("transition planner signer is unavailable")
    mapper = {
        "reader": mapping._planner_from_configuration_on_work,
        "producer": mapping._producer_from_configuration_on_work,
        "verifier": mapping._verifier_from_configuration_on_work,
    }[kind]
    ledger = configuration.capability.capture._SharedLedger(work)
    configuration.capability.shape._digest(digest)
    if type(payload) is not dict:
        raise service.AuthorityServiceError("transition configuration is not closed data")
    owned = configuration._ConfigurationCapture(
        ledger, maximum_bytes=authority.MAX_REQUEST_BYTES).visit(payload)
    configuration.production._callback(work, lambda: service.authority_launch_guard.require_active(role))
    arguments = {"operation": operation, "payload": owned, "configuration_digest": digest, "work": work}
    if kind != "verifier":
        arguments["read_dsn"] = configuration.production._callback(work,
            lambda: service._read_dsn_descriptor("SERVERWARE_POLICY_AUTHORITY_PLANNER_READ_POSTGRES_DSN"))
    if kind == "producer":
        arguments["planner_private_key"] = private
    # No process/configuration/descriptor lookup follows this final snapshot.
    # The fixed selected mapper immediately owns and checks its seven bindings.
    arguments["generation"] = configuration.production._callback(
        work, lambda: dict(service.authority_launch_guard.generation()))
    return mapper(**arguments)


def _planner_on_work(process, *, operation, work):
    return _configured_on_work(process, operation=operation, kind="reader", work=work)


def _producer_on_work(process, *, operation, work):
    return _configured_on_work(process, operation=operation, kind="producer", work=work)


def _verifier_on_work(process, *, operation, work):
    return _configured_on_work(process, operation=operation, kind="verifier", work=work)


def _verify_handoff_on_work(process, *, operation, envelope_bytes, proof_bytes,
        inputs_bytes, context_bytes, expectations, work):
    """Verify raw-four against owned independent history without a new clock."""
    operation = _operation(operation)
    originals = envelope_bytes, proof_bytes, inputs_bytes, context_bytes
    plan.proof.wire._raw(originals[0], 2, plan.contract.MAX_BYTES)
    plan._originals(originals[1], originals[2], originals[3])
    ledger = plan.evidence.capture._SharedLedger(work)
    owned = plan.evidence.capture._JSONCapture(
        ledger, maximum_bytes=plan.contract.MAX_BYTES).visit(expectations)
    expected_operation = plan.contract._validate_expectations(owned)
    plan.evidence.plan._same(expected_operation, operation, work,
        "transition handoff differs from its independently selected operation")
    # Only now may active-launch and real key constructors run. Configuration
    # pins can constrain supplied history but never establish its provenance.
    verifier = _verifier_on_work(process, operation=operation, work=work)
    return verifying.TransitionPlanVerifier.verify(verifier, envelope_bytes=originals[0],
        proof_bytes=originals[1], inputs_bytes=originals[2], context_bytes=originals[3],
        expectations=owned, work=work)
