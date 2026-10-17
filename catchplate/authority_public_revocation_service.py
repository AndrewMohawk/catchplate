"""Closed public-revocation dispatch through actual measured serving owners.

Outer servers authenticate their fixed peer before reading any frame. The
runtime remains an opaque relay. Only the selected measured verifier performs
preparation/computation; the independent issuer and executor own their real
terminal effects. An error closes this exchange, never another protocol or a
second execution attempt. Every phase inherits the caller's absolute expiry.
"""
from __future__ import annotations

import os

from catchplate import authority_public_revocation_transport as wire
from catchplate import authority_public_revocation_terminal as terminal
from catchplate import authority_public_revocation_execution as execution
from catchplate import authority_public_revocation_preparation as preparation
from catchplate import authority_webauthn_registration_custody_caller as registration
from catchplate import authority_custody_caller_service as custody
from catchplate import authority_launch_guard as launch


def serve_relay(trust, connection, *, deadline_ns, prefix):
    from catchplate import authority_service as service
    if type(trust) is not service.AuthorityRuntimeClient:
        raise wire.AuthorityTransportError("public revocation requires actual runtime trust")
    original = (trust.verifier_socket_path, trust.verifier_uid, trust.verifier_gid,
        trust.server_uid, trust.server_gid, trust.configuration_digest)
    path, uid, gid, runtime_uid, runtime_gid, digest = original
    receipt = trust.attestation_evidence
    interval = registration._receipt_interval(receipt)
    if (os.environ.get("CATCHPLATE_PROCESS_MODE", "").strip() != service.RUNTIME_RELAY_PROCESS_MODE
            or (os.geteuid(), os.getegid()) != (runtime_uid, runtime_gid)):
        raise wire.AuthorityTransportError("public revocation actual relay identity differs")
    launch.require_active("runtime")
    generation = dict(launch.generation())
    deadline_ns = custody._relay_deadline(interval, deadline_ns)

    def current():
        launch.require_active("runtime")
        if (dict(launch.generation()) != generation or trust.attestation_evidence is not receipt
                or registration._receipt_interval(receipt) != interval
                or (trust.verifier_socket_path, trust.verifier_uid, trust.verifier_gid,
                    trust.server_uid, trust.server_gid, trust.configuration_digest) != original):
            raise wire.AuthorityTransportError("public revocation actual relay scope changed")
        return custody._relay_deadline(interval, deadline_ns)

    kind, received, epoch, raw = wire.recv_request(connection, deadline_ns=current(), prefix=prefix)
    if received != digest:
        raise wire.AuthorityTransportError("public revocation differs from runtime configuration")
    response = wire.exchange(path, kind=kind, configuration_digest=digest,
        deadline_epoch_ns=epoch, raw=raw, deadline_ns=current(), expected_peer_uid=uid, expected_peer_gid=gid)
    wire.send_response(connection, kind, response, deadline_ns=current())


def serve_process(process, connection, *, deadline_ns, prefix):
    from catchplate.authority_query_read_work import QueryReadValidationLimits, _ValidationWork
    owner = terminal.require_started(process)
    work = _ValidationWork(QueryReadValidationLimits())
    with owner.lock:
        owner.check(work=work)
        configuration = process.configuration
        receipt = configuration.attestation_evidence
        interval = registration._receipt_interval(receipt)
        deadline_ns = min(custody._relay_deadline(interval, deadline_ns), owner.window[4])
        kind, digest, epoch, raw = wire.recv_request(connection, deadline_ns=deadline_ns, prefix=prefix)
        if digest != owner.configuration_digest or process.configuration is not configuration:
            raise wire.AuthorityTransportError("public revocation differs from actual cold configuration")
        owner.require_originals(raw[:3], work=work)
        window = preparation.clock._open_on_work(deadline_epoch_ns=epoch,
            maximum_lifetime_ns=30_000_000_000, maximum_clock_skew_ns=0, work=work)
        deadline_ns = min(deadline_ns, window[4])
        owner.check(work=work)
        target = wire.profile(kind)[5]
        if owner.role == "verifier" and target != "verifier":
            # Endpoints and Unix identities come only from this actual signed
            # configuration. The original authority bytes are never relabeled.
            role = configuration.payload["roles"][target]
            response = wire.exchange(role["socketPath"], kind=kind, configuration_digest=digest,
                deadline_epoch_ns=epoch, raw=raw, deadline_ns=deadline_ns,
                expected_peer_uid=role["serviceUid"], expected_peer_gid=role["serviceGid"])
        else:
            owner.require_role(target)
            arguments = dict(live_window=window, transport_deadline_ns=deadline_ns, work=work)
            if kind == "approval":
                from catchplate import authority_public_revocation_approval_owner
                response = authority_public_revocation_approval_owner.execute_on_process(process, raw=raw, **arguments)
            elif kind == "prepare":
                response = preparation.prepare_on_process(process, originals=raw, **arguments)
            elif kind == "compute":
                response = execution.compute_on_process(process, raw=raw, **arguments)
            elif kind == "grant":
                response = execution.grant_on_process(process, raw=raw, **arguments)
            elif kind == "reserve":
                response = execution.reserve_on_process(process, raw=raw, **arguments)
            elif kind == "issue":
                response = execution.issue_on_process(process, raw=raw, **arguments)
            elif kind == "execute":
                response = execution.execute_on_process(process, raw=raw, **arguments)
            elif kind in ("complete", "recover"):
                response = execution.complete_on_process(process, kind=kind, raw=raw, **arguments)
            else:
                raise wire.AuthorityTransportError("public revocation phase has no fixed serving owner")
        owner.check(work=work)
        if (configuration.attestation_evidence is not receipt
                or registration._receipt_interval(receipt) != interval):
            raise wire.AuthorityTransportError("public revocation actual serving receipt changed")
        deadline_ns = min(deadline_ns, custody._relay_deadline(interval, deadline_ns))
        preparation._current(window, deadline_ns, work)
        wire.send_response(connection, kind, response, deadline_ns=deadline_ns)
