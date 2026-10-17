"""Closed public finalization-reservation shapes, not original admission."""
from __future__ import annotations

from catchplate import control_plane_registration_handoff_http as handoff
from catchplate.setup_receipts import ReceiptVerificationError, parse_strict_json_object


MAX_REQUEST_BYTES = 64 * 1024
PURPOSE = "reserve-registration-finalization"
ACTION = "webauthn.registration.finalization.reserve"
OPERATION = "webauthn.registration.finalize"
INTENT_SCHEMA = "catchplate.webAuthnRegistrationFinalizationReservationIntent/v1"
RESPONSE_SCHEMA = "catchplate.webAuthnRegistrationFinalizationReservation/v1"


def parse_request(raw_bytes):
    try:
        value = handoff._owned(parse_strict_json_object(raw_bytes, limits=handoff._JSON_LIMITS))
    except (ReceiptVerificationError, ValueError, RecursionError):
        raise ValueError("finalization reservation requires bounded strict JSON") from None
    if (type(value) is not dict or not {"purpose", "localDigest"} <= value.keys()
            or not value.keys() <= {"purpose", "localDigest", "bootstrapToken", "mfa"}
            or type(value["purpose"]) is not str or value["purpose"] != PURPOSE):
        raise ValueError("finalization reservation fields or purpose differ")
    value["localDigest"] = handoff._local_digest(value["localDigest"])
    token = value.get("bootstrapToken")
    if token is not None and (type(token) is not str or len(token) > 1024):
        raise ValueError("finalization reservation bootstrap carrier is invalid")
    mfa = value.get("mfa")
    if mfa is not None:
        if type(mfa) is not dict or not mfa.keys() <= {"assertion", "approvalId"}:
            raise ValueError("finalization reservation MFA carrier differs")
        assertion, approval = mfa.get("assertion"), mfa.get("approvalId")
        if assertion is not None and type(assertion) is not dict:
            raise ValueError("finalization reservation assertion carrier is invalid")
        if approval is not None and (type(approval) is not str or not 1 <= len(approval) <= 4096):
            raise ValueError("finalization reservation approval carrier is invalid")
    return value


def request_binding(subject):
    """Bind this handler's actual inspection, never a client-supplied subject."""
    binding = handoff.request_binding(subject, completion=True)
    return {**binding, "schema": INTENT_SCHEMA, "purpose": PURPOSE, "action": ACTION}


def accepted(local_digest):
    """Project only a genuinely verified and durably retained facade result."""
    return {"schema": RESPONSE_SCHEMA, "status": "reservation-recorded", "purpose": PURPOSE,
        "localDigest": handoff._local_digest(local_digest), "operation": OPERATION,
        "reservationRecorded": True, "finalizationExecuted": False,
        "registrationCompleted": False, "currentnessEstablished": False, "automaticRetryAllowed": False}


def unavailable(local_digest=None):
    result = {"error": "registration_finalization_reservation_unavailable",
        "finalizationExecuted": False, "registrationCompleted": False,
        "currentnessEstablished": False, "automaticRetryAllowed": False, "remoteState": "unknown"}
    if local_digest is not None:
        result["localDigest"] = handoff._local_digest(local_digest)
    return result
