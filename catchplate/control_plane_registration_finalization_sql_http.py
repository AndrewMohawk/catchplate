"""Closed finalization execution carriers, never actor or original admission.

Only the actual authorized facade result may feed the public success projection.
Bounded raw4 checks do not authenticate an observation or establish currentness.
"""
from __future__ import annotations

from catchplate import authority_registration_finalization_sql_transport as transport
from catchplate import control_plane_registration_handoff_http as handoff
from catchplate.setup_receipts import ReceiptVerificationError, parse_strict_json_object


MAX_REQUEST_BYTES = 64 * 1024
PURPOSE = "execute-registration-finalization"
ACTION = "webauthn.registration.finalization.execute"
OPERATION = "webauthn.registration.finalize"
INTENT_SCHEMA = "catchplate.webAuthnRegistrationFinalizationExecutionIntent/v1"
RESPONSE_SCHEMA = "catchplate.webAuthnRegistrationFinalizationExecution/v1"


def parse_request(raw_bytes):
    try:
        value = handoff._owned(parse_strict_json_object(raw_bytes, limits=handoff._JSON_LIMITS))
    except (ReceiptVerificationError, ValueError, RecursionError):
        raise ValueError("finalization execution requires bounded strict JSON") from None
    if (type(value) is not dict or not {"purpose", "localDigest"} <= value.keys()
            or not value.keys() <= {"purpose", "localDigest", "bootstrapToken", "mfa"}
            or type(value["purpose"]) is not str or value["purpose"] != PURPOSE):
        raise ValueError("finalization execution fields or purpose differ")
    value["localDigest"] = handoff._local_digest(value["localDigest"])
    token = value.get("bootstrapToken")
    if token is not None and (type(token) is not str or len(token) > 1024):
        raise ValueError("finalization execution bootstrap carrier is invalid")
    mfa = value.get("mfa")
    if mfa is not None:
        if type(mfa) is not dict or not mfa.keys() <= {"assertion", "approvalId"}:
            raise ValueError("finalization execution MFA carrier differs")
        assertion, approval = mfa.get("assertion"), mfa.get("approvalId")
        if assertion is not None and type(assertion) is not dict:
            raise ValueError("finalization execution assertion carrier is invalid")
        if approval is not None and (type(approval) is not str or not 1 <= len(approval) <= 4096):
            raise ValueError("finalization execution approval carrier is invalid")
    return value


def request_binding(subject):
    """Project this call's genuine inspected subject, never a posted subject."""
    binding = handoff.request_binding(subject, completion=True)
    return {**binding, "schema": INTENT_SCHEMA, "purpose": PURPOSE, "action": ACTION}


def accepted(local_digest, response_originals):
    """Project an actual successful facade observation; carrier checks are not proof."""
    digest = handoff._local_digest(local_digest)
    try:
        held = transport._originals(response_originals, response=True)
    except transport.AuthorityTransportError:
        raise ValueError("finalization execution response is not bounded raw4") from None
    if held[0] != b"observed-commit":
        raise ValueError("finalization execution has no accepted observation carrier")
    return {"schema": RESPONSE_SCHEMA, "status": "observed-commit", "purpose": PURPOSE,
        "localDigest": digest, "observationAuthenticated": False,
        "registrationCompleted": False, "sessionActivated": False,
        "currentnessEstablished": False, "automaticRetryAllowed": False}


def unavailable(local_digest=None):
    """Redacted uncertainty, never an assertion that SQL did not execute."""
    result = {"error": "registration_finalization_execution_unavailable",
        "registrationCompleted": False, "sessionActivated": False,
        "currentnessEstablished": False, "automaticRetryAllowed": False, "remoteState": "unknown"}
    if local_digest is not None:
        result["localDigest"] = handoff._local_digest(local_digest)
    return result
