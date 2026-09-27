"""Fresh exact retained-target permission, never an activation success token.

Only options are public. The actual pending cookie, CSRF, current role and
sole retained credential are checked against genuine local completion replay.
No operator/bootstrap branch, posted subject, activation dispatch or token
release is accepted here.
"""
from __future__ import annotations

from fastapi import HTTPException, Request

from serverware import control_plane_enrollment_startup as startup
from serverware import control_plane_registration_activation_subject as subjects
from serverware import control_plane_registration_finalization_completion_pending as pending
from serverware import control_plane_oidc_session_activation_permission_http as contract
from serverware import authority_oidc_session_activation as activation


evidence, clock = subjects.evidence, subjects.clock


def _deny(message, status=409):
    raise HTTPException(status_code=status, detail=message)


def _request_original(request, permission_bytes, work):
    if type(request) is not Request:
        _deny("activation permission requires the actual HTTP request", 400)
    if type(permission_bytes) is not bytes or not 2 <= len(permission_bytes) <= contract.MAX_REQUEST_BYTES:
        _deny("activation permission requires bounded original request bytes", 400)
    work.charge(input_bytes=len(permission_bytes))
    return permission_bytes


def _native(current, work, call):
    """Keep the original allowance around fixed application admission calls."""
    current()
    try:
        return evidence.production._callback(work, call)
    finally:
        current()


def _session_deadline(session, work):
    """The genuine current row can only shorten the existing allowance."""
    return min(activation._time(session[name], name, work)
        for name in ("provider_expires_at", "expires_at", "pending_expires_at"))


def _target_on_owner(owner, *, request, payload, live_window, transport_deadline_ns,
        work, current):
    """Same-call source composition; no returned subject is accepted publicly."""
    from serverware import app as application

    _native(current, work, lambda: application._require_registration_execution_session_csrf(request))
    session, identity, session_scope = _native(current, work,
        lambda: pending._session(application, request))
    subject = subjects._inspect_on_owner(owner, local_digest=payload["localDigest"],
        expected_user_id=session["user_id"], expected_session_id=session["id"],
        live_window=live_window, transport_deadline_ns=transport_deadline_ns, work=work)
    current()
    binding = contract.request_binding(subject)
    work.prepare_scan(binding)
    credential = _native(current, work, lambda: pending._history(application,
        binding["userId"], binding["credentialId"]))
    if credential is None:
        _deny("activation permission requires the sole committed retained credential")
    _native(current, work, lambda: pending._recheck(application, request, binding,
        session_scope, credential, credential[2]))
    work.prepare_encoding(binding)
    work.charge(hashes=1)
    digest = _native(current, work, lambda: application._control_plane_payload_digest(binding))
    return application, session, identity, session_scope, binding, credential, digest


def _options(request, *, permission_bytes):
    """Issue target-bound options only, without consuming an assertion."""
    from serverware import app as application
    from serverware import control_plane_oidc_session_activation_execution as execution
    from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork

    work = _ValidationWork(QueryReadValidationLimits())
    original = _request_original(request, permission_bytes, work)
    # The strict decoder owns the sole external graph before owner/key/hash
    # callbacks. The private body permits MFA; this public body does not.
    payload = contract.parse_request(original, options=True)
    work.prepare_scan(payload)
    with startup._LOCK:
        owner, window = execution._open_on_work(work)
        scope = execution._scope_on_owner(owner, live_window=window,
            transport_deadline_ns=window[4], work=work)
        with application.trust_bundle_lock(exclusive=False):
            _app, session, _identity, session_scope, binding, credential, digest = _target_on_owner(
                owner, request=request, payload=payload, live_window=scope.window,
                transport_deadline_ns=scope.deadline_ns, work=work, current=scope.current)
            session_deadline = _session_deadline(session, work)
            if scope.current() >= session_deadline:
                _deny("activation permission pending session expired")
            work.charge(hashes=3)
            result = _native(scope.current, work,
                lambda: pending._options(application, binding, digest))
            _native(scope.current, work, lambda: pending._recheck(application, request,
                binding, session_scope, credential, credential[2]))
            if type(result) is not dict or result.get("schema") != pending.OPTIONS_SCHEMA:
                _deny("activation permission options result shape differs", 503)
            work.prepare_copy(result)
            result = {**result, "schema": contract.OPTIONS_SCHEMA}
            if scope.current() >= session_deadline:
                _deny("activation permission pending session expired")
            return result
