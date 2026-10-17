"""One-use, in-process proof of actual workload approval verification.

This receipt is never serialized or accepted over HTTP. It bridges the genuine
fresh assertion verifier to the existing locked approval transaction, without
re-verifying an already consumed challenge or treating metadata as authority.
"""
from __future__ import annotations

import os
import threading
import time


_ACTION = "workload.identity.issue"
_PID = os.getpid()
_CONSTRUCTION = object()
_LOCK = threading.RLock()
_LIVE = {}
_ROW_FIELDS = ("id", "action", "resource_id", "payload_digest", "requester_id", "expires_at")
_FIELDS = ("method", "user_id", "credential_id", "credential_record_id",
    "authenticator_class", "aaguid", "attestation_trusted", "attestation_enrollment_trusted",
    "attestation_trust_reason", "effective_authenticator_class", "current_trust_bundle_digest",
    "current_trust_bundle_sequence", "attestation_root_sha256", "user_present", "user_verified",
    "sign_count", "challenge_id", "control_plane_action", "resource_id", "payload_digest",
    "control_plane_approval_id", "approval_requester_id", "approval_expires_at", "decision")
_ATTRS = ("request", "scope", "headers", "identity", "policy", "row", "evidence", "deadline_ns")


class WorkloadApprovalError(ValueError):
    pass


def _fail():
    raise WorkloadApprovalError("workload approval lacks its live one-use verification receipt")


def _policy():
    from catchplate import app as application

    policy = application._control_plane_mutation_authn_policy()
    return (policy.get("userVerification"), tuple(policy.get("allowedAuthenticatorClasses", ())),
        policy.get("requireHardwareAttestation", False))


class _VerifiedWorkloadApproval:
    __slots__ = (*_ATTRS, "_seal")

    def __init__(self, construction, *, request, identity, policy, row, evidence, deadline_ns):
        if construction is not _CONSTRUCTION:
            _fail()
        self.request, self.scope, self.headers = request, request.scope, tuple(request.scope["headers"])
        self.identity, self.policy, self.row = identity, policy, row
        self.evidence, self.deadline_ns = evidence, deadline_ns
        self._seal = tuple(getattr(self, name) for name in _ATTRS)


def _registered(value, state):
    if (os.getpid() != _PID or type(value) is not _VerifiedWorkloadApproval
            or _LIVE.get(value) != state
            or any(getattr(value, name) is not saved for name, saved in zip(_ATTRS, value._seal))
            or len(value._seal) != len(_ATTRS)):
        _fail()


def _current(value, state):
    from catchplate import control_plane_workload_identity_routes as routes

    with _LOCK:
        _registered(value, state)
    if (time.monotonic_ns() >= value.deadline_ns or value.request.scope is not value.scope
            or tuple(value.scope["headers"]) != value.headers or _policy() != value.policy
            or value.scope.get("method") != "POST" or value.scope.get("query_string", b"") != b""
            or value.scope.get("path") != "/api/control-plane/approvals/" + value.row[0] + "/approve"):
        _fail()
    try:
        current = routes._cookie_identity(value.request, approver=True)
    except Exception:
        _fail()
    if current != value.identity or time.monotonic_ns() >= value.deadline_ns:
        _fail()
    with _LOCK:
        _registered(value, state)


def _verify_on_request(request, *, approval, mfa):
    from catchplate import control_plane_workload_identity_routes as routes

    deadline = time.monotonic_ns() + 30_000_000_000
    if sum(len(k) + len(v) for k, v in request.scope["headers"]) > 8 * 1024:
        _fail()
    row = tuple(approval[name] for name in _ROW_FIELDS)
    if (any(type(value) is not str or not 1 <= len(value) <= 4096 for value in row)
            or row[1] != _ACTION or approval["status"] != "pending"):
        _fail()
    identity = routes._cookie_identity(request, approver=True)
    if row[4] == identity.user_id:
        _fail()
    policy = _policy()
    # Only this invocation can manufacture the private receipt. Posted success
    # dictionaries, raw authn metadata and challenge IDs cannot select it.
    genuine = routes._fresh_assertion(identity=identity, resource_id=row[2],
        payload_digest=row[3], mfa=mfa, approval_context=approval)
    if (type(genuine) is not dict or set(genuine) != set(_FIELDS)
            or genuine["method"] != "webauthn" or genuine["user_verified"] is not True
            or genuine["user_present"] is not True):
        _fail()
    evidence = tuple(genuine[name] for name in _FIELDS)
    if any(value is not None and (type(value) not in (str, int, bool)
            or type(value) is str and len(value) > 4096
            or type(value) is int and not 0 <= value < 1 << 64) for value in evidence):
        _fail()
    result = _VerifiedWorkloadApproval(_CONSTRUCTION, request=request, identity=identity,
        policy=policy, row=row, evidence=evidence, deadline_ns=deadline)
    with _LOCK:
        _LIVE[result] = "fresh"
    try:
        _current(result, "fresh")
        return identity, result
    except BaseException:
        _discard(result)
        raise


def _consume_on_row(receipt, *, row, actor_id):
    # Spend before any live/row check: uncertainty never makes a receipt reusable.
    with _LOCK:
        _registered(receipt, "fresh")
        _LIVE[receipt] = "consumed"
    _current(receipt, "consumed")
    actual = tuple(row[name] for name in _ROW_FIELDS)
    if (actual != receipt.row or actual[1] != _ACTION or actor_id != receipt.identity.user_id
            or row["status"] != "pending" or actual[4] == actor_id):
        _fail()
    evidence = dict(zip(_FIELDS, receipt.evidence))
    expected = {"method": "webauthn", "user_id": actor_id, "control_plane_action": _ACTION,
        "resource_id": actual[2], "payload_digest": actual[3], "control_plane_approval_id": actual[0],
        "approval_requester_id": actual[4], "approval_expires_at": actual[5], "decision": "approve"}
    if any(evidence[name] != value for name, value in expected.items()):
        _fail()
    return evidence


def _current_on_consumed(receipt):
    _current(receipt, "consumed")


def _discard(receipt):
    if type(receipt) is not _VerifiedWorkloadApproval:
        return
    with _LOCK:
        _LIVE.pop(receipt, None)
        receipt.request, receipt.scope, receipt.headers, receipt.evidence = None, None, (), ()
        receipt._seal = ()
