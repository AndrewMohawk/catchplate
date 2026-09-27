"""Closed HTTP shapes for actual retained registration handoffs, not authority.

Parsing authenticates no actor, purpose or original. Response projections may
be used only after the handler's real authorization and successful private
facade; carrier checks cannot substitute for that verification. No raw response,
packet identity, bootstrap token or MFA original appears in a public result.
"""
from __future__ import annotations

from collections.abc import Mapping

from serverware import authority_registration_execution_sql_transport as sql
from serverware import authority_registration_completion_transport as completion_transport
from serverware.setup_receipts import (
    JsonLimits,
    ReceiptVerificationError,
    parse_strict_json_object,
)


MAX_REQUEST_BYTES = 64 * 1024
EXECUTE_PURPOSE = "execute-registration-evidence"
COMPLETE_PURPOSE = "complete-registration-evidence"
EXECUTE_ACTION = "webauthn.registration.execution.execute"
COMPLETE_ACTION = "webauthn.registration.execution.complete"
EXECUTE_SCHEMA = "serverware.webAuthnRegistrationExecutionHandoff/v1"
COMPLETE_SCHEMA = "serverware.webAuthnRegistrationCompletion/v1"
INTENT_SCHEMA = "serverware.webAuthnRegistrationHandoffIntent/v1"
_HEX = frozenset("0123456789abcdef")
_SUBJECT_FIELDS = frozenset({"localDigest", "userId", "challengeId", "sessionId", "mode",
    "requestDigest", "operationId"})
_SUBJECT_MODES = frozenset({"bootstrap-token", "development-bootstrap", "existing-webauthn",
    "oidc-session-first-enrollment"})
_JSON_LIMITS = JsonLimits(max_bytes=MAX_REQUEST_BYTES, max_depth=16,
    max_object_keys=64, max_total_keys=512, max_array_items=128,
    max_total_nodes=4096, max_string_bytes=MAX_REQUEST_BYTES)


def _mode(completion):
    if type(completion) is not bool:
        raise ValueError("registration handoff mode must be source selected")
    return (COMPLETE_PURPOSE, COMPLETE_ACTION, COMPLETE_SCHEMA) if completion else (
        EXECUTE_PURPOSE, EXECUTE_ACTION, EXECUTE_SCHEMA)


def _local_digest(value):
    if (type(value) is not str or len(value) != 71 or not value.startswith("sha256:")
            or any(character not in _HEX for character in value[7:])):
        raise ValueError("registration handoff local ID is not canonical SHA256")
    return value


def _owned(value):
    # Called only on the already bounded, recursively frozen strict parser
    # output. No externally supplied Mapping or object method is traversed.
    if isinstance(value, Mapping):
        return {key: _owned(item) for key, item in value.items()}
    if type(value) is tuple:
        return [_owned(item) for item in value]
    return value


def parse_request(raw_bytes, *, completion):
    """Parse a bounded closed request into a newly owned ordinary dictionary.

    HTTP framing, actor/session authentication, CSRF, current credential state,
    bootstrap/assertion/approval verification and handler deadline ownership
    remain outside this pure shape parser.
    """
    purpose, _, _ = _mode(completion)
    try:
        value = _owned(parse_strict_json_object(raw_bytes, limits=_JSON_LIMITS))
    except (ReceiptVerificationError, ValueError, RecursionError):
        raise ValueError("registration handoff request is not bounded strict JSON") from None
    if (type(value) is not dict or not {"purpose", "localDigest"} <= value.keys()
            or not value.keys() <= {"purpose", "localDigest", "bootstrapToken", "mfa"}
            or type(value["purpose"]) is not str or value["purpose"] != purpose):
        raise ValueError("registration handoff request fields or purpose differ")
    value["purpose"] = purpose
    value["localDigest"] = _local_digest(value["localDigest"])
    token = value.get("bootstrapToken")
    if token is not None and (type(token) is not str or len(token) > 1024):
        raise ValueError("registration handoff bootstrap carrier is invalid")
    mfa = value.get("mfa")
    if mfa is not None:
        if type(mfa) is not dict or not mfa.keys() <= {"assertion", "approvalId"}:
            raise ValueError("registration handoff MFA carrier fields differ")
        assertion, approval = mfa.get("assertion"), mfa.get("approvalId")
        if assertion is not None and type(assertion) is not dict:
            raise ValueError("registration handoff assertion carrier is invalid")
        if approval is not None and (type(approval) is not str or not 1 <= len(approval) <= 4096):
            raise ValueError("registration handoff approval carrier is invalid")
    return value


def _subject_text(value):
    if type(value) is not str or not 1 <= len(value) <= 4096:
        raise ValueError("registration handoff subject text is invalid or oversized")
    try:
        size = len(value.encode("utf-8"))
    except UnicodeEncodeError:
        raise ValueError("registration handoff subject text is invalid UTF8") from None
    if size > 4096:
        raise ValueError("registration handoff subject text is invalid or oversized")
    return value


def request_binding(subject, *, completion):
    """Project the genuine same-call retained subject for MFA/approval binding.

    Only the actual inspect_retained_registration_subject result belongs here.
    This checks its bounded shape, not the authenticity of an incoming dict;
    the handler must perform genuine inspection and current caller admission.
    Historical enrollment mode never replaces this new action's authorization.
    """
    purpose, action, _ = _mode(completion)
    if type(subject) is not dict or set(subject) != _SUBJECT_FIELDS:
        raise ValueError("registration handoff subject fields differ")
    # Hold every scalar before validation and return a distinct owned graph.
    local, user, challenge, session, mode, request, operation = (
        subject["localDigest"], subject["userId"], subject["challengeId"],
        subject["sessionId"], subject["mode"], subject["requestDigest"], subject["operationId"])
    _local_digest(local)
    _local_digest(request)
    _local_digest(operation)
    _subject_text(user)
    _subject_text(challenge)
    if type(mode) is not str or mode not in _SUBJECT_MODES:
        raise ValueError("registration handoff subject mode differs")
    if mode == "oidc-session-first-enrollment":
        _subject_text(session)
    elif session is not None:
        raise ValueError("registration handoff subject session scope differs")
    return {"schema": INTENT_SCHEMA, "purpose": purpose, "action": action,
        "localDigest": local, "userId": user, "challengeId": challenge,
        "sessionId": session, "mode": mode, "requestDigest": request,
        "operationId": operation}


def accepted(local_digest, response_originals, *, completion=False):
    """Project only a successful actual facade call, never authenticate raw4.

    SQL observed-commit remains an unsigned observation. Completion's true
    observationAuthenticated label relies on the actual facade having verified
    the originals; callers must never use this function on an arbitrary raw4.
    Neither branch establishes a current head or finalizes a credential.
    """
    purpose, _, schema = _mode(completion)
    digest = _local_digest(local_digest)
    transport = completion_transport if completion else sql
    try:
        held = transport._originals(response_originals, response=True)
    except sql.AuthorityTransportError:
        raise ValueError("registration handoff response is not its bounded raw4") from None
    if held[0] != (b"acknowledged" if completion else b"observed-commit"):
        raise ValueError("registration handoff does not have an accepted response carrier")
    return {"schema": schema,
        "status": "completion-acknowledged" if completion else "observed-commit",
        "purpose": purpose, "localDigest": digest,
        "observationAuthenticated": completion,
        "registrationCompleted": False, "currentnessEstablished": False,
        "automaticRetryAllowed": False}


def unavailable(local_digest=None, *, completion=False):
    """Fixed redacted uncertainty; no exception text or execution-denial claim."""
    _mode(completion)
    digest = None if local_digest is None else _local_digest(local_digest)
    result = {"error": ("registration_completion_unavailable" if completion
        else "registration_execution_unavailable"), "registrationCompleted": False,
        "currentnessEstablished": False, "automaticRetryAllowed": False,
        "remoteState": "unknown"}
    if digest is not None:
        result["localDigest"] = digest
    return result
