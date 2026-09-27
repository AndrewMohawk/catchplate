"""Closed preparation shapes; no credential or execution authority is returned."""
from __future__ import annotations

from serverware import control_plane_registration_handoff_http as handoff
from serverware.setup_receipts import ReceiptVerificationError, parse_strict_json_object


MAX_REQUEST_BYTES = 64 * 1024
PURPOSE = "prepare-retained-registration-finalization"
ACTION = "webauthn.registration.finalization.prepare"
OPERATION = "webauthn.registration.finalize"
INTENT_SCHEMA = "serverware.webAuthnRegistrationFinalizationPreparationIntent/v1"
RESPONSE_SCHEMA = "serverware.webAuthnRegistrationFinalizationPreparation/v1"


def parse_request(raw_bytes):
    try:
        value = handoff._owned(parse_strict_json_object(raw_bytes, limits=handoff._JSON_LIMITS))
    except (ReceiptVerificationError, ValueError, RecursionError):
        raise ValueError("registration finalization preparation requires bounded strict JSON") from None
    if (type(value) is not dict or not {"purpose", "localDigest"} <= value.keys()
            or not value.keys() <= {"purpose", "localDigest", "bootstrapToken", "mfa"}
            or type(value["purpose"]) is not str or value["purpose"] != PURPOSE):
        raise ValueError("registration finalization preparation fields or purpose differ")
    value["localDigest"] = handoff._local_digest(value["localDigest"])
    token = value.get("bootstrapToken")
    if token is not None and (type(token) is not str or len(token) > 1024):
        raise ValueError("registration finalization bootstrap carrier is invalid")
    mfa = value.get("mfa")
    if mfa is not None:
        if type(mfa) is not dict or not mfa.keys() <= {"assertion", "approvalId"}:
            raise ValueError("registration finalization MFA carrier differs")
        assertion, approval = mfa.get("assertion"), mfa.get("approvalId")
        if assertion is not None and type(assertion) is not dict:
            raise ValueError("registration finalization assertion carrier is invalid")
        if approval is not None and (type(approval) is not str or not 1 <= len(approval) <= 4096):
            raise ValueError("registration finalization approval carrier is invalid")
    return value


def request_binding(subject):
    """Project only the fixed handler's genuine live-retained subject inspection."""
    binding = handoff.request_binding(subject, completion=True)
    return {**binding, "schema": INTENT_SCHEMA, "purpose": PURPOSE, "action": ACTION}


def accepted(local_digest, finalization_local_digest):
    """Project only actual durable preparation; a digest is not execution proof."""
    return {"schema": RESPONSE_SCHEMA, "status": "finalization-prepared", "purpose": PURPOSE,
        "localDigest": handoff._local_digest(local_digest),
        "finalizationLocalDigest": handoff._local_digest(finalization_local_digest),
        "operation": OPERATION, "finalizationExecuted": False, "registrationCompleted": False,
        "currentnessEstablished": False, "automaticRetryAllowed": False}


def unavailable(local_digest=None):
    result = {"error": "registration_finalization_preparation_unavailable",
        "finalizationExecuted": False, "registrationCompleted": False,
        "currentnessEstablished": False, "automaticRetryAllowed": False, "remoteState": "unknown"}
    if local_digest is not None:
        result["localDigest"] = handoff._local_digest(local_digest)
    return result
