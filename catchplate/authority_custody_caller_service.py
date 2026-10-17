"""Fixed opaque caller-custody handlers behind the real peer-checked routers.

The runtime relay does not admit history or controls. The verifier invokes its
actual custody forwarding or read-only reconciliation path on one existing
work allowance. Reconciliation returns original retained bodies with unsigned
metadata, not write permission. An unsigned response is not a remote durability
receipt; a late failure after forwarding may follow commit and never authorizes
retry.
"""
from __future__ import annotations

import os
import time

from catchplate import authority_custody_caller_transport as transport
from catchplate import authority_custody_reconcile_transport as reconcile_transport


def _send_pair(connection, result, *, deadline_ns):
    if type(result) is not tuple or len(result) != 2:
        raise ValueError("caller custody result is not the fixed observation pair")
    transport._check_deadline(deadline_ns)
    transport._send_response(connection, result[0], result[1], deadline_ns=deadline_ns)


def _relay_deadline(interval, deadline_ns):
    """Keep the admitted receipt's original lifetime and only shorten I/O."""
    from catchplate import authority_service as service

    transport._check_deadline(deadline_ns)
    # Sampling monotonic first makes conversion conservative across the wall
    # sample. A later sample can shorten this deadline, never renew it.
    monotonic_ns = time.monotonic_ns()
    now_epoch_ns = time.time_ns()
    if (
        type(monotonic_ns) is not int
        or monotonic_ns < 0
        or type(now_epoch_ns) is not int
        or not interval[0] <= now_epoch_ns < interval[1]
    ):
        raise service.AuthorityServiceError("caller custody runtime attestation is not current")
    clipped = min(deadline_ns, monotonic_ns + interval[1] - now_epoch_ns)
    transport._check_deadline(clipped)
    return clipped


def _serve_verifier(process, connection, *, deadline_ns, prefix, reconciling=False):
    """Receive all originals and EOF before allocating the sole verifier work."""
    # The outer service imports this module lazily after its actual classes
    # exist. No registry, synthetic owner or caller-selected callback is used.
    from catchplate import authority_service as service
    from catchplate.authority_query_read_work import QueryReadValidationLimits, _ValidationWork

    if type(reconciling) is not bool:
        raise service.AuthorityServiceError("caller custody reconciliation mode is not exact")
    wire = reconcile_transport if reconciling else transport
    if (
        type(process) is not service.AuthorityProcess
        or process.role_name != "verifier"
        or process.process_mode != service.PROCESS_MODES["verifier"]
    ):
        raise service.AuthorityServiceError("caller custody requires the actual verifier process")
    configuration = process.configuration
    if type(configuration) is not service.MeasuredConfiguration:
        raise service.AuthorityServiceError("caller custody requires the actual measured configuration")
    configuration_digest = transport._configuration_digest(configuration.digest)
    transport._check_deadline(deadline_ns)
    received_configuration, family, selector, originals = wire._recv_request(
        connection, deadline_ns=deadline_ns, prefix=prefix,
    )
    if received_configuration != configuration_digest:
        raise service.AuthorityServiceError("caller custody scope differs from the verifier configuration")
    # _recv_request validates the fixed family, complete length vector,
    # immutable originals and exact EOF. It does not create proof work.
    work = _ValidationWork(QueryReadValidationLimits())
    transport._check_deadline(deadline_ns)
    if process.configuration is not configuration:
        raise service.AuthorityServiceError("caller custody configuration changed during reception")
    if reconciling:
        if family == "evidence":
            from catchplate import authority_webauthn_evidence_custody_recovery as recovery

            result = recovery._recover_on_work(process, purpose=selector, originals=originals, work=work)
        elif family == "transition":
            from catchplate import authority_webauthn_transition_custody_recovery as recovery

            result = recovery._recover_on_work(process, operation=selector, originals=originals, work=work)
        else:
            raise service.AuthorityServiceError("caller custody reconciliation family is not source fixed")
    elif family == "evidence":
        result = service.AuthorityProcess._forward_webauthn_evidence_custody(
            process, purpose=selector, intent_bytes=originals[0],
            relay_bytes=originals[1], envelope_bytes=originals[2],
            inputs_bytes=originals[3], evaluation_context_bytes=originals[4],
            historical_expectations_bytes=originals[5], work=work,
        )
    elif family == "transition":
        result = service.AuthorityProcess._forward_webauthn_transition_custody(
            process, operation=selector, intent_bytes=originals[0],
            relay_bytes=originals[1], envelope_bytes=originals[2],
            proof_bytes=originals[3], inputs_bytes=originals[4],
            context_bytes=originals[5], historical_expectations_bytes=originals[6],
            work=work,
        )
    else:
        raise service.AuthorityServiceError("caller custody family is not source fixed")
    if process.configuration is not configuration:
        # Forwarding may already have committed; this is not rollback or
        # permission to repeat a journal attempt.
        raise service.AuthorityServiceError("caller custody configuration changed during forwarding")
    if reconciling:
        wire._check_deadline(deadline_ns)
        wire._send_response(connection, family=family, selector=selector,
            response=result, deadline_ns=deadline_ns)
    else:
        _send_pair(connection, result, deadline_ns=deadline_ns)


def _serve_relay(trust, connection, *, deadline_ns, prefix, reconciling=False):
    """Forward unchanged originals without extending the incoming deadline."""
    from catchplate import authority_service as service
    from catchplate import authority_launch_guard as guard

    if type(reconciling) is not bool:
        raise service.AuthorityServiceError("caller custody reconciliation mode is not exact")
    wire = reconcile_transport if reconciling else transport
    if type(trust) is not service.AuthorityRuntimeClient:
        raise service.AuthorityServiceError("caller custody relay trust is not the actual runtime client")
    # These fields come from the already admitted hot-runtime trust object.
    # Hold them before guard, socket or other native I/O callbacks.
    verifier_path = trust.verifier_socket_path
    verifier_uid, verifier_gid = trust.verifier_uid, trust.verifier_gid
    relay_uid, relay_gid = trust.server_uid, trust.server_gid
    configuration_digest = transport._configuration_digest(trust.configuration_digest)
    attestation = trust.attestation_evidence
    if type(attestation) is not dict or type(attestation.get("payload")) is not dict:
        raise service.AuthorityServiceError("caller custody runtime attestation payload is missing")
    attestation_payload = attestation["payload"]
    interval = (attestation_payload.get("issuedAtEpochNs"),
        attestation_payload.get("expiresAtEpochNs"))
    if (any(type(value) is not int or not 1 <= value <= (1 << 63) - 1 for value in interval)
            or interval[0] >= interval[1]):
        raise service.AuthorityServiceError("caller custody runtime attestation interval is invalid")
    if (
        type(verifier_path) is not str
        or any(type(value) is not int for value in (verifier_uid, verifier_gid, relay_uid, relay_gid))
        or os.environ.get("CATCHPLATE_PROCESS_MODE", "").strip() != service.RUNTIME_RELAY_PROCESS_MODE
        or (os.geteuid(), os.getegid()) != (relay_uid, relay_gid)
    ):
        raise service.AuthorityServiceError("caller custody relay is not the admitted hot runtime")
    deadline_ns = _relay_deadline(interval, deadline_ns)
    guard.require_active("runtime")
    transport._check_deadline(deadline_ns)
    received_configuration, family, selector, originals = wire._recv_request(
        connection, deadline_ns=deadline_ns, prefix=prefix,
    )
    if received_configuration != configuration_digest:
        raise service.AuthorityServiceError("caller custody scope differs from the admitted runtime trust")
    deadline_ns = _relay_deadline(interval, deadline_ns)
    result = wire._socket_request(
        verifier_path, configuration_digest=configuration_digest,
        family=family, selector=selector, originals=originals,
        deadline_ns=deadline_ns, expected_peer_uid=verifier_uid,
        expected_peer_gid=verifier_gid,
    )
    deadline_ns = _relay_deadline(interval, deadline_ns)
    if reconciling:
        wire._check_deadline(deadline_ns)
        wire._send_response(connection, family=family, selector=selector,
            response=result, deadline_ns=deadline_ns)
    else:
        _send_pair(connection, result, deadline_ns=deadline_ns)
    # Even a final expiry is uncertain after forwarding; it is not rollback
    # evidence and cannot release a caller journal's attempt barrier.
    _relay_deadline(interval, deadline_ns)
