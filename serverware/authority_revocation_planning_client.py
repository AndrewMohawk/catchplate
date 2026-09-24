"""Configured verifier-to-planner exchange with genuine original-plan replay.

The actual verifier service supplies its independently admitted request,
reservation context and genuinely acquired full inventory. Configuration and
launch admission remain upstream prerequisites. No response field chooses an
expected request, identity, root, policy, key or clock. This client returns
original plan/context bytes only after genuine replay and a final freshness
check; it grants neither persistence nor current execution authority.
"""
from __future__ import annotations

import math
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from serverware import authority_contract as authority
from serverware import authority_revocation_configuration as configuration
from serverware import authority_revocation_planning_request as request_wire
from serverware import authority_revocation_planning_transport as transport
from serverware import authority_revocation_verifier as verifier


plan, capture = request_wire.plan, request_wire.capture


class RevocationPlanningClientError(ValueError):
    pass


def _endpoint(payload, work):
    """Hold measured endpoint/age scalars before any key or socket callback."""
    roles = payload["roles"]
    if type(roles) is not dict:
        raise RevocationPlanningClientError("planning client roles are not exact objects")
    source, target = roles["verifier"], roles["planner"]
    for name, role in (("verifier", source), ("planner", target)):
        if type(role) is not dict:
            raise RevocationPlanningClientError("planning client role is not an exact object")
        plan.contract._literal(role["processMode"], "policy-authority-" + name)
        for field in ("serviceUid", "serviceGid"):
            plan.contract._integer(role[field], 0xFFFFFFFF, minimum=1)
        plan.contract._integer(role["maximumInternalAgeNs"], minimum=1)
        timeout = role["requestTimeoutSeconds"]
        if (type(timeout) not in (int, float) or not math.isfinite(timeout)
                or not 0.05 <= timeout <= 30):
            raise RevocationPlanningClientError("planning client timeout is outside its source interval")
    request_wire._require_enabled_operation(target, work)
    for field in ("peerUid", "peerGid"):
        plan.contract._integer(target[field], 0xFFFFFFFF, minimum=1)
    plan._same((target["peerUid"], target["peerGid"]),
        (source["serviceUid"], source["serviceGid"]), work,
        "planning client peer topology differs from its measured verifier")
    path = target["socketPath"]
    if (type(path) is not str or not 1 <= len(path) <= 107 or not path.startswith("/")
            or "\x00" in path or len(path.encode("utf-8")) > 107):
        raise RevocationPlanningClientError("planning client socket path is not bounded and absolute")
    return (path, target["serviceUid"], target["serviceGid"],
        min(source["requestTimeoutSeconds"], target["requestTimeoutSeconds"]),
        min(source["maximumInternalAgeNs"], target["maximumInternalAgeNs"]))


def _current(context, age, skew, work):
    monotonic = configuration.production._callback(work, time.monotonic_ns)
    epoch = configuration.production._callback(work, time.time_ns)
    request_wire._require_current_context(context, now_epoch_ns=epoch,
        now_monotonic_ns=monotonic, maximum_age_ns=age, maximum_clock_skew_ns=skew)
    return epoch, monotonic


def _request_on_configuration(*, payload, configuration_digest, generation,
        request, evidence, context, root_inventory, verifier_private_key, work):
    """Sign one request, exchange originals and genuinely replay its response.

    Own invocation graphs, complete roots and the full measured payload before
    callbacks. The actual verifier mapper owns launch bindings and admits both
    configured public keys on the same remaining work. Transport is guarded
    against changing that work, but does not perform cryptographic verification.
    Final current-clock checks cover synchronous replay as well as socket I/O;
    they never replace the original historical context or authorize execution.
    """
    try:
        ledger = capture._SharedLedger(work)
        if not isinstance(verifier_private_key, Ed25519PrivateKey):
            raise RevocationPlanningClientError("planning client requires its configured verifier signer")
        owned = request_wire._capture_call_graphs(
            request=request, evidence=evidence, context=context, work=work)
        inventory = request_wire.observed._capture_root_inventory(root_inventory, work=work)
        plan.contract._digest(configuration_digest)
        if type(payload) is not dict:
            raise RevocationPlanningClientError("planning client configuration is not an exact object")
        owned_payload = configuration._ConfigurationCapture(
            ledger, maximum_bytes=authority.MAX_REQUEST_BYTES).visit(payload)
        path, peer_uid, peer_gid, timeout, age = _endpoint(owned_payload, work)
        owner = verifier._verifier_from_configuration_on_work(payload=owned_payload,
            configuration_digest=configuration_digest, generation=generation, work=work)
        fixed = owner._snapshot_configuration()
        age = min(age, fixed[5])
        epoch, monotonic = _current(owned["context"], age, fixed[6], work)
        originals = request_wire._produce_request_on_work(request=owned["request"],
            evidence=owned["evidence"], context=owned["context"], root_inventory=inventory,
            verifier_private_key=verifier_private_key, verifier_public_key=fixed[1],
            planner_public_key=fixed[0], configuration_digest=fixed[7],
            generation_sequence=fixed[8], generation_digest=fixed[9],
            issued_at_epoch_ns=epoch, issued_monotonic_ns=monotonic, work=work)
        # Key/sign callbacks may consume real time. Reject expired history
        # before opening the socket, then check it again after actual replay.
        _current(owned["context"], age, fixed[6], work)
        response = configuration.production._callback(work, lambda: transport._socket_request(
            path, control_bytes=originals[0], request_bytes=originals[1], evidence_bytes=originals[2],
            context_bytes=originals[3], root_inventory_bytes=originals[4], timeout_seconds=timeout,
            expected_peer_uid=peer_uid, expected_peer_gid=peer_gid))
        if (type(response) is not tuple or len(response) != 2
                or any(type(raw) is not bytes for raw in response)):
            raise RevocationPlanningClientError("planning client response is not an original byte pair")
        transport._validate_response_lengths(tuple(len(raw) for raw in response))
        if owner._snapshot_configuration() is not fixed:
            raise RevocationPlanningClientError("planning client verifier configuration changed")
        owner.verify_handoff(envelope_bytes=response[0], evaluation_context_bytes=response[1],
            expected_request=owned["request"], context=owned["context"], root_inventory=inventory, work=work)
        _current(owned["context"], age, fixed[6], work)
        return response
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError, RecursionError) as exc:
        if isinstance(exc, RevocationPlanningClientError):
            raise
        raise RevocationPlanningClientError("configured planning exchange failed") from exc
