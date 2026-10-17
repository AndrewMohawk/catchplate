"""Read-only, cookie-only observation of one genuinely retained session target.

This is neither permission nor delivery evidence. It never contacts an effect
service, reconciles history, changes a cookie or accepts a bearer/token target.
"""
from __future__ import annotations

import re

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from catchplate import auth, webauthn
from catchplate import control_plane_registration_activation_subject as subjects
from catchplate import control_plane_registration_finalization_completion_pending as pending
from catchplate import control_plane_oidc_session_activation_permission as permission
from catchplate.authority_query_read_work import QueryReadValidationLimits, _ValidationWork
from catchplate.setup_receipts import JsonLimits, parse_strict_json_object


router = APIRouter()
POST_PATH = "/api/auth/session/activation/confirmation"
ORIGINAL_STATE_NAME = "oidc_session_activation_confirmation_bytes"
MAX_REQUEST_BYTES = 1024
REQUEST_SCHEMA = "catchplate.oidcSessionActivationConfirmationRequest/v1"
RESPONSE_SCHEMA = "catchplate.oidcSessionActivationConfirmationResponse/v1"
PURPOSE = "confirm-current-oidc-session"
HEADERS = {"Cache-Control": "no-store", "Pragma": "no-cache",
    "X-Content-Type-Options": "nosniff"}
_LIMITS = JsonLimits(max_bytes=MAX_REQUEST_BYTES, max_depth=2, max_object_keys=3,
    max_total_keys=3, max_array_items=1, max_total_nodes=8, max_string_bytes=256)
_AUTH_BYTES = 256 * 1024


def _response(status_code, digest=None, *, active=False):
    return JSONResponse(status_code=status_code, headers=HEADERS, content={
        "schema": RESPONSE_SCHEMA, "purpose": PURPOSE, "localDigest": digest,
        "status": "current-target-active" if active else "unknown",
        "sessionState": "active" if active else "unknown", "automaticRetryAllowed": False})


def error(status_code=503):
    code = status_code if type(status_code) is int and status_code in (400, 401, 403, 405, 409, 413, 415, 503) else 503
    return _response(code)


async def _frame_request(request):
    if not isinstance(request, Request) or request.scope.get("path") != POST_PATH:
        return error(400)
    if request.method != "POST":
        return error(405)
    lengths = request.headers.getlist("content-length")
    if (len(lengths) != 1 or re.fullmatch(r"[1-9][0-9]{0,3}", lengths[0]) is None
            or request.headers.getlist("transfer-encoding") or request.headers.getlist("content-encoding")
            or request.scope.get("query_string", b"") != b""):
        return error(400)
    if request.headers.getlist("content-type") != ["application/json"]:
        return error(415)
    size = int(lengths[0])
    if not 2 <= size <= MAX_REQUEST_BYTES:
        return error(413 if size > MAX_REQUEST_BYTES else 400)
    body = bytearray()
    try:
        async for chunk in request.stream():
            if type(chunk) is not bytes or len(chunk) > size - len(body):
                return error(400)
            body.extend(chunk)
    except Exception:
        return error(400)
    if len(body) != size:
        return error(400)
    original = bytes(body)
    request._body, request._stream_consumed = original, False
    setattr(request.state, ORIGINAL_STATE_NAME, original)
    return None


def _confirm(request, original):
    from catchplate import app as application

    digest = None
    try:
        if (type(request) is not Request or type(original) is not bytes
                or not 2 <= len(original) <= MAX_REQUEST_BYTES
                or getattr(request.state, ORIGINAL_STATE_NAME, None) is not original
                or request.method != "POST" or request.scope.get("path") != POST_PATH
                or request.scope.get("query_string", b"") != b""
                or request.headers.getlist("authorization")
                or request.headers.getlist("x-catchplate-admin-token")):
            return error(400)
        # The submitted digest is only a locator. No submitted subject or
        # successful actor/permission object can supply expected ownership.
        work = _ValidationWork(QueryReadValidationLimits())
        source = subjects.completion_subject
        with_lock = subjects.startup._LOCK
        if with_lock.acquire(blocking=False) is not True:
            return error(409)
        try:
            owner, material, binding, window = source._open_on_work(work)
            work.charge(input_bytes=4 * len(original) + 2 * _AUTH_BYTES, json_nodes=4096, hashes=2)
            payload = parse_strict_json_object(original, limits=_LIMITS)
            if (type(payload) is not dict or set(payload) != {"schema", "purpose", "localDigest"}
                    or payload["schema"] != REQUEST_SCHEMA or payload["purpose"] != PURPOSE):
                return error(400)
            digest = subjects.journal._digest(payload["localDigest"])
            _common, _endpoint, selected_window, bound, current = source._scope_on_owner(
                owner, live_window=window, transport_deadline_ns=window[4], work=work)
            native = lambda call: permission._native(current, work, call)
            native(lambda: application._require_registration_execution_session_csrf(request))
            if (type(webauthn.WEBAUTHN_ORIGIN) is not str
                    or not webauthn.WEBAUTHN_ORIGIN or webauthn.WEBAUTHN_ORIGIN == "null"
                    or request.headers.getlist("origin") != [webauthn.WEBAUTHN_ORIGIN]):
                return error(403)
            token = request.cookies.get(auth.OIDC_SESSION_COOKIE_NAME)
            if not auth.oidc_session_token_is_well_formed(token):
                return error(401)

            def fresh():
                # Deliberately bypass the Request's authentication cache.
                session = native(lambda: application.oidc_browser_session_from_token(token))
                if (type(session) is not dict or session.get("status") != "active"
                        or session.get("revoked_at") is not None
                        or any(type(session.get(name)) is not str or not 1 <= len(session[name]) <= 4096
                            for name in ("id", "user_id", "bound_webauthn_credential_id"))):
                    raise ValueError("current cookie is not an active bound session")
                identity = native(lambda: application.oidc_identity_from_browser_session(session))
                if (type(identity) is not application.AdminIdentity or identity.auth_method != "oidc-session"
                        or identity.user_id != session["user_id"]):
                    raise ValueError("current cookie identity differs")
                return session, identity

            with application.trust_bundle_lock(exclusive=False):
                first, first_identity = fresh()
                # The existing genuine target inspector's underlying combined
                # loader reserves the held auth/request lane before body one.
                inspected = source._inspect_on_owner(owner, digest, live_window=selected_window,
                    transport_deadline_ns=bound, work=work,
                    _additional_original_bytes=2 * _AUTH_BYTES + 4 * len(original))
                subject, held, reserved, observed, common, _endpoint, admitted_window, admitted_bound, live, _size = inspected
                if type(subject) is not dict or set(subject) != subjects._SUBJECT_FIELDS:
                    raise ValueError("retained target shape differs")
                subjects.evidence.plan._same((subject["localDigest"], subject["userId"], subject["sessionId"], subject["mode"]),
                    (digest, first["user_id"], first["id"], "oidc-session-first-enrollment"), work,
                    "current cookie differs from retained target")
                record, kind = observed.completion_reconciled, "completion-reconciled"
                if record is None:
                    record, kind = observed.completion_outcome, "completion-outcome"
                if (type(record) is not subjects.records.FinalizationOutcomeRecord
                        or record.finalization_digest != digest or record.source_revision != observed.source_revision
                        or record.kind != kind):
                    raise ValueError("retained target lacks its original completion")
                returned = subjects.wire._originals(record.originals, response=True)
                if returned[0] != b"acknowledged":
                    raise ValueError("retained target completion is unavailable")
                current()
                live()
                configured = material.finalization.current_pending
                subjects.admission._verify_on_configuration(**common, originals=held,
                    reservation_originals=reserved, response_originals=returned,
                    expected_pending_sequence=configured[0], expected_pending_head_digest=configured[1],
                    expected_fence=configured[2], live_window=admitted_window, work=work,
                    transport_deadline_ns=admitted_bound)
                live()
                credential = native(lambda: pending._history(application, subject["userId"], subject["credentialId"]))
                second, second_identity = fresh()
                if (credential is None or second["id"] != first["id"]
                        or second["user_id"] != subject["userId"]
                        or first["bound_webauthn_credential_id"] != credential[0]
                        or second["bound_webauthn_credential_id"] != credential[0]
                        or second_identity.roles != first_identity.roles):
                    raise ValueError("current session or retained credential changed")
                bound_credential = pending._credential(second.get("_bound_credential"),
                    subject["userId"], subject["credentialId"])
                if bound_credential[:2] != credential[:2] or bound_credential[2] < credential[2]:
                    raise ValueError("current bound credential differs")
                current()
                live()
                response = _response(200, digest, active=True)
                live()
                current()
            if (owner._material is not material or owner._binding is not binding):
                raise ValueError("confirmation owner changed")
            current()
        finally:
            with_lock.release()
        # Only normal read-only owner/trust cleanup reaches this observation.
        # It describes this check, never a future grant or proof of delivery.
        return response
    except Exception:
        return _response(503, digest)


@router.post(POST_PATH)
def confirm(request: Request):
    return _confirm(request, getattr(request.state, ORIGINAL_STATE_NAME, None))
