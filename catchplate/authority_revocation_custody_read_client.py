"""Configured read-only retrieval of unverified original custody bytes.

The actual service supplies admitted configuration and its active generation.
Only the existing verifier -> planner -> writer peer topology is supported.
Locators select custody; they are not bearer credentials or execution authority.
The result is ordinary raw6, not an authenticated historical proof. No key or
policy is learned from it, and no missing response permits retry or re-signing.
"""
from __future__ import annotations

import math

from catchplate import authority_revocation_configuration as configuration
from catchplate import authority_revocation_custody_read_transport as transport


class RevocationCustodyReadClientError(ValueError):
    pass


def _endpoint(payload, source_name, target_name, work):
    if (source_name, target_name) not in (("verifier", "planner"), ("planner", "planner-writer")):
        raise RevocationCustodyReadClientError("custody read peer route is not supported")
    shape = configuration.capability.shape
    roles = payload["roles"]
    if type(roles) is not dict:
        raise RevocationCustodyReadClientError("custody read roles are not exact objects")
    source, target = roles[source_name], roles[target_name]
    for name, role in ((source_name, source), (target_name, target)):
        if type(role) is not dict:
            raise RevocationCustodyReadClientError("custody read role is not an exact object")
        shape._literal(role["processMode"], "policy-authority-" + name)
        for field in ("serviceUid", "serviceGid"):
            shape._integer(role[field], 0xFFFFFFFF, minimum=1)
        timeout = role["requestTimeoutSeconds"]
        if (type(timeout) not in (int, float) or not math.isfinite(timeout)
                or not 0.05 <= timeout <= 30):
            raise RevocationCustodyReadClientError("custody read timeout is outside its source interval")
    for field in ("peerUid", "peerGid"):
        shape._integer(target[field], 0xFFFFFFFF, minimum=1)
    configuration.capability.plan._same((target["peerUid"], target["peerGid"]),
        (source["serviceUid"], source["serviceGid"]), work,
        "custody read peer topology differs from its measured caller")
    path = target["socketPath"]
    if (type(path) is not str or not 1 <= len(path) <= 107 or not path.startswith("/")
            or "\x00" in path or len(path.encode("utf-8")) > 107):
        raise RevocationCustodyReadClientError("custody read socket path is not bounded and absolute")
    return (path, target["serviceUid"], target["serviceGid"],
        min(source["requestTimeoutSeconds"], target["requestTimeoutSeconds"]))


def _read(*, payload, configuration_digest, generation, execution_envelope_id,
        planner_transaction_id, source_name, target_name, work):
    try:
        transport._validate_ids(execution_envelope_id, planner_transaction_id)
        owned, _launch = configuration._capture_configuration_on_work(
            payload=payload, configuration_digest=configuration_digest, generation=generation, work=work)
        path, uid, gid, timeout = _endpoint(owned, source_name, target_name, work)
        originals = configuration.production._callback(work, lambda: transport._socket_request(
            path, execution_envelope_id=execution_envelope_id, planner_transaction_id=planner_transaction_id,
            timeout_seconds=timeout, expected_peer_uid=uid, expected_peer_gid=gid))
        if (type(originals) is not tuple or len(originals) != 6
                or any(type(raw) is not bytes for raw in originals)):
            raise RevocationCustodyReadClientError("custody read response is not original raw6")
        transport._validate_response_lengths(tuple(len(raw) for raw in originals))
        return originals
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError, RecursionError) as exc:
        if isinstance(exc, RevocationCustodyReadClientError):
            raise
        raise RevocationCustodyReadClientError("configured custody read is unresolved") from exc


def _read_from_planner_on_configuration(*, payload, configuration_digest, generation,
        execution_envelope_id, planner_transaction_id, work):
    """Verifier retrieval, without a writer socket or database credential."""
    return _read(payload=payload, configuration_digest=configuration_digest, generation=generation,
        execution_envelope_id=execution_envelope_id, planner_transaction_id=planner_transaction_id,
        source_name="verifier", target_name="planner", work=work)


def _read_from_writer_on_configuration(*, payload, configuration_digest, generation,
        execution_envelope_id, planner_transaction_id, work):
    """Planner retrieval, without signing, persistence, or authentication claims."""
    return _read(payload=payload, configuration_digest=configuration_digest, generation=generation,
        execution_envelope_id=execution_envelope_id, planner_transaction_id=planner_transaction_id,
        source_name="planner", target_name="planner-writer", work=work)
