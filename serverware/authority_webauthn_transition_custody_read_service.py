"""Measured private lookup of retained successor-transition originals.

The signer owns an independently admitted content identity and historical
expectations before measured callbacks. A fresh signed lookup window does not
renew any historical plan deadline. The same original request travels through
the fixed verifier -> planner -> planner-writer topology without resigning.

These private methods retain the existing work, protected descriptor and active
generation boundaries. Returned original plans still require genuine replay;
peer metadata and missing responses supply no durability, absence, rollback,
automatic retry, reconciliation or business execution authority.
"""
from __future__ import annotations

from serverware import authority_webauthn_transition_service as service
from serverware import authority_webauthn_transition_custody_service as custody
from serverware import authority_webauthn_transition_custody_read_actions as actions
from serverware import authority_webauthn_transition_custody_read_transport as transport


def _history_archive(process):
    """Hold the startup-immutable archive before any measured callbacks."""
    from serverware import authority_service as authority_service

    if type(process) is not authority_service.AuthorityProcess:
        raise authority_service.AuthorityServiceError("transition custody read process is not configured")
    measured = process.configuration
    if type(measured) is not authority_service.MeasuredConfiguration:
        raise authority_service.AuthorityServiceError("transition custody read configuration is unavailable")
    return measured.history_archive


def _produce_on_work(process, *, operation, retained_record_digest, expectations, work):
    """Prepare a lookup-only request without reading or reviving the old plan."""
    operation = service._operation(operation)
    service.plan.contract.shape._digest(retained_record_digest)
    record_digest = retained_record_digest
    owned = service._history_on_work(operation, expectations, work)
    held_archive = _history_archive(process)
    payload, digest, generation, _dsn, private, runtime_role_identities = custody._context_on_work(
        process, role="verifier", signing=True, work=work)
    result = actions._produce_on_configuration(operation=operation,
        payload=payload, configuration_digest=digest, generation=generation,
        runtime_role_identities=runtime_role_identities, history_archive=held_archive,
        retained_record_digest=record_digest, expectations=owned,
        verifier_private_key=private, work=work)
    service._require_generation_on_work("verifier", generation, work)
    return result


def _lookup_on_work(process, *, operation, control_bytes, historical_expectations_bytes, kind, work):
    """Select only one fixed read edge, never a caller callback or SQL command."""
    if type(kind) is not str or kind not in ("request", "forward", "read"):
        raise ValueError("transition custody lookup action is not source fixed")
    operation = service._operation(operation)
    originals = transport._validate_request(control_bytes=control_bytes,
        historical_expectations_bytes=historical_expectations_bytes)
    held_archive = _history_archive(process)
    role = {"request": "verifier", "forward": "planner", "read": "planner-writer"}[kind]
    payload, digest, generation, dsn, _private, runtime_role_identities = custody._context_on_work(
        process, role=role, signing=False, work=work)
    arguments = {"operation": operation, "payload": payload,
        "configuration_digest": digest, "generation": generation,
        "runtime_role_identities": runtime_role_identities, "history_archive": held_archive,
        "control_bytes": originals[0], "historical_expectations_bytes": originals[1], "work": work}
    if kind == "read":
        result = actions._read_on_configuration(**arguments, writer_dsn=dsn)
    elif kind == "forward":
        result = actions._forward_on_configuration(**arguments)
    else:
        result = actions._request_on_configuration(**arguments)
    service._require_generation_on_work(role, generation, work)
    return result


def _read_on_work(process, *, operation, control_bytes, historical_expectations_bytes, work):
    return _lookup_on_work(process, operation=operation, control_bytes=control_bytes,
        historical_expectations_bytes=historical_expectations_bytes, kind="read", work=work)


def _request_on_work(process, *, operation, control_bytes, historical_expectations_bytes, work):
    return _lookup_on_work(process, operation=operation, control_bytes=control_bytes,
        historical_expectations_bytes=historical_expectations_bytes, kind="request", work=work)


def _forward_on_work(process, *, operation, control_bytes, historical_expectations_bytes, work):
    return _lookup_on_work(process, operation=operation, control_bytes=control_bytes,
        historical_expectations_bytes=historical_expectations_bytes, kind="forward", work=work)
