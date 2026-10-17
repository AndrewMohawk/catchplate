"""Closed finalization completion/recovery HTTP shapes, never authority.

Only genuine same-call subject inspection may feed request binding, and only
the authorized facade's authenticated result may feed accepted(). Structural
carrier checks cannot replace original verification or present permission.
"""
from __future__ import annotations

import base64
import binascii

from catchplate import authority_registration_finalization_completion_transport as transport
from catchplate import control_plane_registration_handoff_http as handoff
from catchplate.setup_receipts import ReceiptVerificationError, parse_strict_json_object


MAX_REQUEST_BYTES = 64 * 1024
COMPLETE_PURPOSE = "complete-registration-finalization"
RECOVER_PURPOSE = "recover-registration-finalization-completion"
COMPLETE_ACTION = "webauthn.registration.finalization.complete"
RECOVER_ACTION = "webauthn.registration.finalization.recover"
COMPLETE_SCHEMA = "catchplate.webAuthnRegistrationFinalizationCompletion/v1"
RECOVER_SCHEMA = "catchplate.webAuthnRegistrationFinalizationCompletionRecovery/v1"
INTENT_SCHEMA = "catchplate.webAuthnRegistrationFinalizationCompletionIntent/v1"
OPTIONS_SCHEMA = "catchplate.webAuthnRegistrationFinalizationPermissionOptions/v1"
_SUBJECT_FIELDS = handoff._SUBJECT_FIELDS | frozenset({"credentialId"})
_BASE64URL = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")


def _mode(recovery):
    if type(recovery) is not bool:
        raise ValueError("finalization completion mode must be source selected")
    return ((RECOVER_PURPOSE, RECOVER_ACTION, RECOVER_SCHEMA, "finalization-completion-recovered")
        if recovery else (COMPLETE_PURPOSE, COMPLETE_ACTION, COMPLETE_SCHEMA,
            "finalization-completion-acknowledged"))


def parse_request(raw_bytes, *, recovery, options=False):
    """Own bounded strict JSON without authenticating its actor or purpose."""
    purpose, _, _, _ = _mode(recovery)
    if type(options) is not bool:
        raise ValueError("finalization completion options mode must be source selected")
    if type(raw_bytes) is not bytes or not 2 <= len(raw_bytes) <= MAX_REQUEST_BYTES:
        raise ValueError("finalization completion requires bounded original JSON bytes")
    try:
        value = handoff._owned(parse_strict_json_object(raw_bytes, limits=handoff._JSON_LIMITS))
    except (ReceiptVerificationError, ValueError, RecursionError):
        raise ValueError("finalization completion requires bounded strict JSON") from None
    allowed = {"purpose", "localDigest"} if options else {"purpose", "localDigest", "bootstrapToken", "mfa"}
    if (type(value) is not dict or not {"purpose", "localDigest"} <= value.keys()
            or not value.keys() <= allowed
            or type(value["purpose"]) is not str or value["purpose"] != purpose):
        raise ValueError("finalization completion fields or purpose differ")
    value["localDigest"] = handoff._local_digest(value["localDigest"])
    token = value.get("bootstrapToken")
    if token is not None and (type(token) is not str or len(token) > 1024):
        raise ValueError("finalization completion bootstrap carrier is invalid")
    mfa = value.get("mfa")
    if mfa is not None:
        if type(mfa) is not dict or not mfa.keys() <= {"assertion", "approvalId"}:
            raise ValueError("finalization completion MFA carrier fields differ")
        assertion, approval = mfa.get("assertion"), mfa.get("approvalId")
        if assertion is not None and type(assertion) is not dict:
            raise ValueError("finalization completion assertion carrier is invalid")
        if approval is not None and (type(approval) is not str or not 1 <= len(approval) <= 4096):
            raise ValueError("finalization completion approval carrier is invalid")
    return value


def _credential(value):
    # Match the genuinely replayed finalization kernel, not the broader signer
    # front door: unpadded text <=1366 and original credential bytes 1..1024.
    if (type(value) is not str or not 1 <= len(value) <= 1366
            or any(character not in _BASE64URL for character in value)):
        raise ValueError("finalization completion credential is not bounded base64url")
    try:
        raw = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except (ValueError, binascii.Error):
        raise ValueError("finalization completion credential is not canonical base64url") from None
    if (not 1 <= len(raw) <= 1024
            or base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") != value):
        raise ValueError("finalization completion credential is not canonical base64url")
    return value


def request_binding(subject, *, recovery):
    """Bind the actual eight-field replayed subject, never a posted dictionary."""
    purpose, action, _, _ = _mode(recovery)
    if type(subject) is not dict or set(subject) != _SUBJECT_FIELDS:
        raise ValueError("finalization completion subject fields differ")
    # Preserve the existing generic seven-field contract unchanged. This new
    # exact projection alone includes the original finalization credential.
    credential = subject["credentialId"]
    original = {name: subject[name] for name in handoff._SUBJECT_FIELDS}
    binding = handoff.request_binding(original, completion=True)
    return {**binding, "schema": INTENT_SCHEMA, "purpose": purpose, "action": action,
        "credentialId": _credential(credential)}


def accepted(local_digest, response_originals, *, recovery):
    """Project only the genuine facade's authenticated completion result."""
    purpose, _, schema, status = _mode(recovery)
    digest = handoff._local_digest(local_digest)
    try:
        held = transport._originals(response_originals, response=True)
    except transport.AuthorityTransportError:
        raise ValueError("finalization completion response is not bounded raw4") from None
    if held[0] != b"acknowledged":
        raise ValueError("finalization completion has no authenticated acknowledgment carrier")
    return {"schema": schema, "status": status, "purpose": purpose, "localDigest": digest,
        "observationAuthenticated": True, "finalizationAcknowledged": True,
        "sessionActivated": False, "currentnessEstablished": False, "automaticRetryAllowed": False}


def unavailable(local_digest=None, *, recovery):
    """Static uncertainty; never infer noncommit, denial or permission to retry."""
    _mode(recovery)
    result = {"error": ("registration_finalization_completion_recovery_unavailable" if recovery
        else "registration_finalization_completion_unavailable"),
        "sessionActivated": False, "currentnessEstablished": False,
        "automaticRetryAllowed": False, "remoteState": "unknown"}
    if local_digest is not None:
        result["localDigest"] = handoff._local_digest(local_digest)
    return result
