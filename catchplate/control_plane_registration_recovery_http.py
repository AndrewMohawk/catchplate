"""Closed public historical-completion shapes, not verification authority.

The fixed handler admits the present actor and recovery purpose. Only the
actual historical subject/facade may supply projection inputs; bounded shape
checks cannot replace original authentication. No SQL or finalization action
is selected, and no signed original, packet locator or secret is exposed.
"""
from __future__ import annotations

from catchplate import authority_registration_completion_transport as transport
from catchplate import control_plane_registration_handoff_http as handoff
from catchplate.setup_receipts import ReceiptVerificationError, parse_strict_json_object


MAX_REQUEST_BYTES = 64 * 1024
PURPOSE = "recover-registration-evidence-completion"
ACTION = "webauthn.registration.execution.recover"
INTENT_SCHEMA = "catchplate.webAuthnRegistrationCompletionRecoveryIntent/v1"
RESPONSE_SCHEMA = "catchplate.webAuthnRegistrationCompletionRecovery/v1"


def parse_request(raw_bytes):
    """Own the closed HTTP request; establish no actor or original authority."""
    try:
        value = handoff._owned(parse_strict_json_object(raw_bytes, limits=handoff._JSON_LIMITS))
    except (ReceiptVerificationError, ValueError, RecursionError):
        raise ValueError("registration recovery request is not bounded strict JSON") from None
    if (type(value) is not dict or not {"purpose", "localDigest"} <= value.keys()
            or not value.keys() <= {"purpose", "localDigest", "bootstrapToken", "mfa"}
            or type(value["purpose"]) is not str or value["purpose"] != PURPOSE):
        raise ValueError("registration recovery request fields or purpose differ")
    value["purpose"] = PURPOSE
    value["localDigest"] = handoff._local_digest(value["localDigest"])
    token = value.get("bootstrapToken")
    if token is not None and (type(token) is not str or len(token) > 1024):
        raise ValueError("registration recovery bootstrap carrier is invalid")
    mfa = value.get("mfa")
    if mfa is not None:
        if type(mfa) is not dict or not mfa.keys() <= {"assertion", "approvalId"}:
            raise ValueError("registration recovery MFA carrier fields differ")
        assertion, approval = mfa.get("assertion"), mfa.get("approvalId")
        if assertion is not None and type(assertion) is not dict:
            raise ValueError("registration recovery assertion carrier is invalid")
        if approval is not None and (type(approval) is not str or not 1 <= len(approval) <= 4096):
            raise ValueError("registration recovery approval carrier is invalid")
    return value


def request_binding(subject):
    """Bind only the actual same-call seven-field historical subject.

    Reuse the exact subject bounds and immutable-scalar projection, then select
    this distinct source-fixed purpose/domain. Historical mode is not fresh
    recovery permission, and no incoming subject DTO is accepted by a route.
    """
    binding = handoff.request_binding(subject, completion=True)
    return {**binding, "schema": INTENT_SCHEMA, "purpose": PURPOSE, "action": ACTION}


def accepted(local_digest, response_originals):
    """Project only the actual authenticated historical-recovery facade result."""
    digest = handoff._local_digest(local_digest)
    try:
        held = transport._originals(response_originals, response=True)
    except transport.AuthorityTransportError:
        raise ValueError("registration recovery response is not its bounded raw4") from None
    if held[0] != b"acknowledged":
        raise ValueError("registration recovery has no acknowledged response carrier")
    return {"schema": RESPONSE_SCHEMA, "status": "completion-recovered",
        "purpose": PURPOSE, "localDigest": digest, "observationAuthenticated": True,
        "registrationCompleted": False, "currentnessEstablished": False,
        "automaticRetryAllowed": False}


def unavailable(local_digest=None):
    """Fixed uncertainty, without remote outcome or exception-text inference."""
    digest = None if local_digest is None else handoff._local_digest(local_digest)
    result = {"error": "registration_completion_recovery_unavailable",
        "registrationCompleted": False, "currentnessEstablished": False,
        "automaticRetryAllowed": False, "remoteState": "unknown"}
    if digest is not None:
        result["localDigest"] = digest
    return result
