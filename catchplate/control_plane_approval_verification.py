"""Request-held, one-use proof of genuine generic approval verification.

Only the direct fresh WebAuthn verifier can mint this in-process receipt. It is
not an HTTP shape, a challenge authority, or a replacement for the locked row
and active credential checks. The separate workload approval path is unchanged.
"""
from __future__ import annotations

from datetime import datetime, timezone
import os
import threading
import time

from fastapi import HTTPException, Request


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
_ATTRS = ("request", "scope", "request_pin", "identity", "policy", "row", "evidence",
    "credential_pin", "deadline_ns", "expires_ns")
_MAX_AGE_NS = 30_000_000_000


class ApprovalVerificationError(ValueError):
    pass


def _fail():
    raise ApprovalVerificationError("approval lacks its live one-use verification receipt")


def _row(value):
    result = tuple(value[name] for name in _ROW_FIELDS)
    if (any((item is not None or index != 2)
            and (type(item) is not str or not 1 <= len(item) <= 4096)
            for index, item in enumerate(result))
            or result[1] == "workload.identity.issue"):
        _fail()
    return result


def _epoch_ns(value):
    if type(value) is not str or len(value) > 128:
        _fail()
    try:
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            _fail()
        delta = parsed.astimezone(timezone.utc) - datetime(1970, 1, 1, tzinfo=timezone.utc)
        result = ((delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds) * 1000
    except (ValueError, OverflowError):
        _fail()
    if result <= 0:
        _fail()
    return result


def _request_pin(request):
    scope = request.scope
    headers = scope.get("headers")
    if (type(headers) not in (list, tuple) or len(headers) > 256
            or any(type(pair) not in (list, tuple) or len(pair) != 2
                or any(type(part) is not bytes for part in pair) for pair in headers)
            or sum(len(key) + len(value) for key, value in headers) > 128 * 1024):
        _fail()
    return (scope.get("type"), scope.get("method"), scope.get("path"), scope.get("raw_path"),
        scope.get("root_path"), scope.get("query_string"), scope.get("scheme"),
        tuple(scope.get("client") or ()), tuple(scope.get("server") or ()),
        tuple((key, value) for key, value in headers))


def _policy(action):
    from catchplate import app as application

    policy = application._control_plane_mutation_authn_policy()
    roles = tuple(sorted(application._control_plane_approval_roles(action)))
    if (application._control_plane_mutation_webauthn_required(action) is not True
            or policy.get("userVerification") != "required" or not roles):
        _fail()
    return (policy["userVerification"], tuple(policy.get("allowedAuthenticatorClasses", ())),
        policy.get("requireHardwareAttestation", False), roles)


def _authn_policy(policy):
    return {"userVerification": policy[0], "allowedAuthenticatorClasses": list(policy[1]),
        "requireHardwareAttestation": policy[2]}


def _identity(request, row, policy):
    from catchplate import auth

    # A new Request has no per-request OIDC/session cache. The exact source
    # scope remains pinned; this preserves require_admin's header/bearer/cookie
    # precedence while re-reading current session and authoritative role state.
    current_request = Request(request.scope)
    identity = auth.require_admin(current_request,
        x_catchplate_admin_token=current_request.headers.get("X-Catchplate-Admin-Token"))
    auth.validate_csrf_request(current_request)
    if (type(identity) is not auth.AdminIdentity or identity.user_id == row[4]
            or not identity.has_any_role(set(policy[3]))):
        _fail()
    return identity


def _credential_pin(credential):
    if (type(credential) is not dict or credential.get("revoked_at") is not None
            or any(type(credential.get(name)) is not str
                or not 1 <= len(credential[name]) <= 16 * 1024
                for name in ("id", "credential_id", "user_id", "public_key_cose"))):
        _fail()
    return tuple(credential[name] for name in ("id", "credential_id", "user_id", "public_key_cose"))


class _VerifiedApproval:
    __slots__ = (*_ATTRS, "_seal")

    def __init__(self, construction, **fields):
        if construction is not _CONSTRUCTION or set(fields) != set(_ATTRS):
            _fail()
        for name in _ATTRS:
            setattr(self, name, fields[name])
        self._seal = tuple(getattr(self, name) for name in _ATTRS)


def _registered(receipt, state):
    if os.getpid() != _PID or type(receipt) is not _VerifiedApproval:
        _fail()
    entry = _LIVE.get(receipt)
    if (entry is None or entry[0] != state
            or len(receipt._seal) != len(_ATTRS)
            or any(getattr(receipt, name) is not saved
                for name, saved in zip(_ATTRS, receipt._seal))):
        _fail()
    return entry


def _sample(receipt, state):
    with _LOCK:
        _, last_epoch, last_mono = _registered(receipt, state)
        epoch, mono = time.time_ns(), time.monotonic_ns()
        if (epoch < last_epoch or mono < last_mono or epoch >= receipt.expires_ns
                or mono >= receipt.deadline_ns):
            _LIVE.pop(receipt, None)
            _fail()
        _LIVE[receipt] = (state, epoch, mono)


def _current(receipt, state):
    from catchplate import db, webauthn

    _sample(receipt, state)
    try:
        if (receipt.request.scope is not receipt.scope
                or _request_pin(receipt.request) != receipt.request_pin
                or _policy(receipt.row[1]) != receipt.policy
                or _identity(receipt.request, receipt.row, receipt.policy) != receipt.identity):
            _fail()
        credential = db.get_webauthn_credential_by_record_id(receipt.credential_pin[0])
        if _credential_pin(credential) != receipt.credential_pin:
            _fail()
        trust = webauthn._allowed_authenticator(credential, _authn_policy(receipt.policy))
        evidence = dict(zip(_FIELDS, receipt.evidence))
        expected = {"attestation_trusted": trust["currently_trusted"],
            "attestation_enrollment_trusted": trust["enrollment_trusted"],
            "attestation_trust_reason": trust["reason"],
            "effective_authenticator_class": trust["effective_authenticator_class"],
            "current_trust_bundle_digest": trust.get("current_trust_bundle_digest"),
            "current_trust_bundle_sequence": trust.get("current_trust_bundle_sequence"),
            "authenticator_class": credential["authenticator_class"],
            "aaguid": credential.get("aaguid"),
            "attestation_root_sha256": credential.get("attestation_root_sha256")}
        if any(evidence[name] != value for name, value in expected.items()):
            _fail()
    except Exception:
        _fail()
    _sample(receipt, state)


def _verify_on_request(request, *, approval, mfa):
    from catchplate import db, webauthn

    started_epoch, started_mono = time.time_ns(), time.monotonic_ns()
    if type(request) is not Request:
        _fail()
    row = _row(approval)
    actual = db.get_control_plane_approval(row[0])
    if actual is None or _row(actual) != row or actual["status"] != "pending":
        _fail()
    pin = _request_pin(request)
    if pin[0] != "http" or pin[1] != "POST" or pin[2] != "/api/control-plane/approvals/" + row[0] + "/approve":
        _fail()
    policy = _policy(row[1])
    identity = _identity(request, row, policy)
    assertion = mfa.get("assertion") if type(mfa) is dict else None
    if not assertion:
        raise HTTPException(status_code=412, detail={"error": "control_plane_webauthn_required",
            "message": "WebAuthn assertion required for control-plane mutation", "action": row[1],
            "resourceId": row[2], "payloadDigest": row[3], "approvalId": row[0]})
    if type(assertion) is not dict or type(assertion.get("response")) is not dict:
        _fail()
    try:
        client_data, _ = webauthn._parse_client_data(assertion["response"].get("clientDataJSON"), "webauthn.get")
        challenge = db.get_unused_webauthn_challenge(client_data["challenge"],
            challenge_type="control-plane-mutation", user_id=identity.user_id)
        if challenge is None:
            _fail()
        expires = min(_epoch_ns(row[5]), _epoch_ns(challenge["expires_at"]))
        deadline = started_mono + min(_MAX_AGE_NS, expires - started_epoch)
        credential = db.get_webauthn_credential(assertion.get("id") or assertion.get("rawId"))
        credential_pin = _credential_pin(credential)
        if credential_pin[2] != identity.user_id or time.monotonic_ns() >= deadline:
            _fail()
        # This direct invocation consumes the genuine challenge and advances
        # its registered credential counter. Neither metadata nor authority
        # challenge hints can manufacture the result or choose a verifier.
        genuine = webauthn.verify_control_plane_mutation_assertion(user_id=identity.user_id,
            action=row[1], resource_id=row[2], payload_digest=row[3],
            authn_policy=_authn_policy(policy), assertion=assertion, approval_context=actual)
    except webauthn.WebAuthnError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    if (type(genuine) is not dict or set(genuine) != set(_FIELDS)
            or genuine["method"] != "webauthn" or genuine["user_present"] is not True
            or genuine["user_verified"] is not True or genuine["challenge_id"] != challenge["id"]
            or genuine["credential_record_id"] != credential_pin[0]
            or genuine["credential_id"] != credential_pin[1]):
        _fail()
    for hint, name in (("authorityChallengeId", "challenge_id"), ("credentialRecordId", "credential_record_id")):
        if hint in mfa and mfa[hint] != genuine[name]:
            _fail()
    evidence = tuple(genuine[name] for name in _FIELDS)
    if any(value is not None and (type(value) not in (str, int, bool)
            or type(value) is str and len(value) > 16 * 1024
            or type(value) is int and not 0 <= value < 1 << 64) for value in evidence):
        _fail()
    result = _VerifiedApproval(_CONSTRUCTION, request=request, scope=request.scope,
        request_pin=pin, identity=identity, policy=policy, row=row, evidence=evidence,
        credential_pin=credential_pin, deadline_ns=deadline, expires_ns=expires)
    with _LOCK:
        _LIVE[result] = ("fresh", started_epoch, started_mono)
    try:
        _current(result, "fresh")
        return identity, result
    except BaseException:
        _discard(result)
        raise


def _consume_on_row(receipt, *, row, actor_id):
    # Irreversible before current/row checks; uncertainty cannot restore reuse.
    with _LOCK:
        _, epoch, mono = _registered(receipt, "fresh")
        _LIVE[receipt] = ("consumed", epoch, mono)
    _current(receipt, "consumed")
    actual = _row(row)
    if (actual != receipt.row or row["status"] != "pending"
            or actor_id != receipt.identity.user_id or actor_id == actual[4]):
        _fail()
    evidence = dict(zip(_FIELDS, receipt.evidence))
    expected = {"method": "webauthn", "user_id": actor_id, "control_plane_action": actual[1],
        "resource_id": actual[2], "payload_digest": actual[3], "control_plane_approval_id": actual[0],
        "approval_requester_id": actual[4], "approval_expires_at": actual[5], "decision": "approve"}
    if any(evidence[name] != value for name, value in expected.items()):
        _fail()
    return evidence


def _current_on_consumed(receipt):
    _current(receipt, "consumed")


def _discard(receipt):
    if type(receipt) is not _VerifiedApproval:
        return
    with _LOCK:
        _LIVE.pop(receipt, None)
        receipt.request, receipt.scope, receipt.request_pin, receipt.evidence = None, None, (), ()
        receipt._seal = ()
