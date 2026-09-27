"""Closed activation-permission carriers and target projection, not authority.

Only the options carrier is exposed by this slice. The private permission
carrier is for a future combined permission-and-dispatch call, never a reusable
successful permission object. Target projection accepts ordinary data and does
not itself authenticate retained finalization, the actor or the credential.
"""
from __future__ import annotations

from serverware import control_plane_registration_handoff_http as framing
from serverware import control_plane_registration_finalization_completion_http as subjects
from serverware.setup_receipts import ReceiptVerificationError, parse_strict_json_object


MAX_REQUEST_BYTES = 64 * 1024
PURPOSE = "authorize-oidc-session-activation"
ACTION = "webauthn.oidc-session.activation.authorize"
INTENT_SCHEMA = "serverware.oidcSessionActivationPermissionIntent/v1"
OPTIONS_SCHEMA = "serverware.oidcSessionActivationPermissionOptions/v1"


def parse_request(raw_bytes, *, options):
    """Detach bounded strict JSON; authenticate no caller or permission."""
    if type(options) is not bool:
        raise ValueError("activation permission carrier mode must be source selected")
    if type(raw_bytes) is not bytes or not 2 <= len(raw_bytes) <= MAX_REQUEST_BYTES:
        raise ValueError("activation permission requires bounded original JSON bytes")
    try:
        value = framing._owned(parse_strict_json_object(raw_bytes, limits=framing._JSON_LIMITS))
    except (ReceiptVerificationError, ValueError, RecursionError):
        raise ValueError("activation permission requires bounded strict JSON") from None
    required = {"purpose", "localDigest"}
    allowed = required if options else required | {"mfa"}
    if (type(value) is not dict or not required <= value.keys()
            or not value.keys() <= allowed
            or type(value["purpose"]) is not str or value["purpose"] != PURPOSE):
        raise ValueError("activation permission fields or purpose differ")
    value["localDigest"] = framing._local_digest(value["localDigest"])
    mfa = value.get("mfa")
    if mfa is not None:
        if type(mfa) is not dict or not mfa.keys() <= {"assertion", "approvalId"}:
            raise ValueError("activation permission MFA carrier fields differ")
        assertion, approval = mfa.get("assertion"), mfa.get("approvalId")
        if assertion is not None and type(assertion) is not dict:
            raise ValueError("activation permission assertion carrier is invalid")
        if approval is not None and (type(approval) is not str or not 1 <= len(approval) <= 4096):
            raise ValueError("activation permission approval carrier is invalid")
    return value


def request_binding(subject):
    """Project the genuine same-call retained subject, never posted targets.

    The neutral predecessor projection checks the exact eight-field shape and
    canonical credential identifier. Its old action is not retained: this
    binding has a distinct fixed activation purpose, action and schema.
    """
    binding = subjects.request_binding(subject, recovery=False)
    if (binding["mode"] != "oidc-session-first-enrollment"
            or type(binding["sessionId"]) is not str or not binding["sessionId"]):
        raise ValueError("activation permission requires its exact pending-session target")
    return {**binding, "schema": INTENT_SCHEMA, "purpose": PURPOSE, "action": ACTION}


def unavailable():
    """A local failure is not permission, an activation result or a retry grant."""
    return {"error": "oidc_session_activation_permission_unavailable",
        "purpose": PURPOSE, "activationExecuted": False, "sessionActivated": False,
        "tokenReleased": False, "automaticRetryAllowed": False}
