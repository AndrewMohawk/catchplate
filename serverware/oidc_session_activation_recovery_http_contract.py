"""Closed recovery request and locator data, never actor or retry authority.

Options and a future separately authorized recovery dispatch share only a
bounded locator/MFA carrier. There is no planning assertion, browser root
original, token, success projection or route in this module.
"""
from __future__ import annotations

from serverware import control_plane_oidc_session_activation_permission_http as permission
from serverware.setup_receipts import ReceiptVerificationError, parse_strict_json_object


MAX_REQUEST_BYTES = 64 * 1024
REQUEST_SCHEMA = "serverware.oidcSessionActivationRecoveryRequest/v1"
INTENT_SCHEMA = "serverware.oidcSessionActivationRecoveryIntent/v1"
OPTIONS_SCHEMA = "serverware.oidcSessionActivationRecoveryOptions/v1"
RESPONSE_SCHEMA = "serverware.oidcSessionActivationRecoveryFailure/v1"
PURPOSE = "recover-oidc-session-activation"
ACTION = "webauthn.oidc-session.activation.recover"
_FIELDS = frozenset({"schema", "purpose", "localDigest"})


def parse_request(raw_bytes, *, options=False):
    """Own strict bounded DATA; options never consume an assertion."""
    if type(options) is not bool:
        raise ValueError("recovery request mode must be source selected")
    if type(raw_bytes) is not bytes or not 2 <= len(raw_bytes) <= MAX_REQUEST_BYTES:
        raise ValueError("recovery request requires bounded immutable JSON bytes")
    try:
        value = permission.framing._owned(parse_strict_json_object(
            raw_bytes, limits=permission.framing._JSON_LIMITS))
    except (ReceiptVerificationError, ValueError, RecursionError):
        raise ValueError("recovery request requires bounded strict JSON") from None
    allowed = _FIELDS if options else _FIELDS | {"mfa"}
    if (type(value) is not dict or not _FIELDS <= value.keys() or not value.keys() <= allowed
            or type(value["schema"]) is not str or value["schema"] != REQUEST_SCHEMA
            or type(value["purpose"]) is not str or value["purpose"] != PURPOSE):
        raise ValueError("recovery request fields, schema or purpose differ")
    value["localDigest"] = permission.framing._local_digest(value["localDigest"])
    if "mfa" in value:
        mfa = value["mfa"]
        if type(mfa) is not dict or not mfa.keys() <= {"assertion", "approvalId"}:
            raise ValueError("recovery MFA carrier fields differ")
        if "assertion" in mfa and type(mfa["assertion"]) is not dict:
            raise ValueError("recovery assertion must be a bounded object")
        if "approvalId" in mfa:
            approval = mfa["approvalId"]
            if (type(approval) is not str or not 1 <= len(approval) <= 4096
                    or "\x00" in approval
                    or any(0xD800 <= ord(point) <= 0xDFFF for point in approval)):
                raise ValueError("recovery approval ID is invalid")
    return value


def request_binding(subject, *, activation_authorization_digest, old_token_digest):
    """Project independently replayed subject8 plus two exact binding digests.

    The activation authorization digest is a retained-record locator, not proof
    of execution. Only genuine historical intent/possession admission supplies
    the old-token digest. Shape checks cannot authenticate incoming dictionaries.
    """
    binding = permission.request_binding(subject)
    authorization = permission.framing._local_digest(activation_authorization_digest)
    token = permission.framing._local_digest(old_token_digest)
    return {**binding, "schema": INTENT_SCHEMA, "purpose": PURPOSE, "action": ACTION,
        "activationAuthorizationDigest": authorization, "oldTokenDigest": token}


def unavailable(local_digest=None):
    """Ordinary uncertainty; no nonexecution, success or permission to retry."""
    digest = None if local_digest is None else permission.framing._local_digest(local_digest)
    return {"schema": RESPONSE_SCHEMA, "purpose": PURPOSE, "localDigest": digest,
        "status": "recovery-unavailable", "dispatchState": "unknown",
        "sessionState": "unknown", "automaticRetryAllowed": False}
