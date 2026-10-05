"""Final current-auth and single cookie emission on the original live call.

Only this source-owned boundary receives the token. A cookie is staged before
normal permission cleanup and emitted only after the genuine receiver guards
survive cleanup and signed-response buffering on the same process/thread.
"""
from __future__ import annotations

from datetime import datetime, timezone
import os
import threading
import time

from fastapi.responses import JSONResponse

from serverware import auth
from serverware import control_plane_oidc_session_activation_execution as execution
from serverware import control_plane_oidc_session_activation_permission as permission_source
from serverware import control_plane_registration_finalization_completion_pending as pending
from serverware import oidc_session_activation_http_contract as contract
from serverware.operator_oidc import oidc_session_cookie_attributes


POST_PATH = "/api/auth/session/activation"
_SCOPE_KEY = "serverware.oidc-session-activation.final-delivery"
_HEADERS = {"Cache-Control": "no-store", "Pragma": "no-cache", "X-Content-Type-Options": "nosniff"}
_SUCCESS = {"ok": True, "authenticated": True}
_AUTH_RESERVATION = 256 * 1024


def _fail():
    raise execution.startup.EnrollmentStartupError("activation current-session delivery is unavailable")


class _StagedResponse:
    """Actual same-call finishing owner; no public API accepts this as proof."""

    __slots__ = ("_permission", "_owner", "_request", "_asgi", "_work", "_scope", "_target",
        "_parent", "_binding", "_custody", "_pid", "_thread", "_seal", "_limits", "_ceilings", "_metrics",
        "_window", "_bound", "_epoch", "_monotonic", "_intervals", "_session_expiry",
        "_parent_continuity", "_receiver", "_phase", "_response", "_body", "_cookie", "_local_digest",
        "_user_id", "_session_id", "_credential_id", "_credential", "_count", "_session_scope")

    def __init__(self):
        _fail()

    def _identity(self):
        p = self._permission
        if (os.getpid() != self._pid or threading.get_ident() != self._thread
                or self._seal != (p, self._owner, self._request, self._asgi, self._work, self._scope,
                    self._target, self._parent, self._binding, self._custody, self._pid, self._thread)
                or p._owner is not self._owner or p._request is not self._request or p._work is not self._work
                or self._request.scope is not self._asgi or self._owner._material is not self._parent
                or self._owner._binding is not self._binding or self._owner._custody is not self._custody
                or self._target[2]["localDigest"] != self._local_digest
                or self._target[2]["userId"] != self._user_id
                or self._target[2]["sessionId"] != self._session_id
                or self._target[2]["credentialId"] != self._credential_id
                or self._target[3] is not self._credential or self._target[4] != self._count
                or self._target[1] is not self._session_scope):
            _fail()
        if p._state == "active":
            if (self._phase not in ("acquiring", "staged") or p._target is not self._target
                    or p._scope is not self._scope or self._owner._activation_permission is not p):
                _fail()
        elif (p._state != "closed" or p._normal_exit is not True or p._locked is not False
                or p._trust is not None or p._scope is not None or p._target is not None
                or p._dispatch_phase != "closed" or self._owner._activation_permission is not None
                or self._phase not in ("staged", "finished")):
            _fail()

    def _ledger(self):
        execution.capture._SharedLedger(self._work)
        limits, metrics = self._work.limits, self._work.metrics
        if (limits is not self._limits
                or self._ceilings != (limits.max_hashes, limits.max_input_bytes, limits.max_json_nodes)
                or metrics.hash_work < self._metrics.hash_work
                or metrics.input_bytes < self._metrics.input_bytes
                or metrics.json_nodes < self._metrics.json_nodes):
            _fail()
        self._metrics = metrics

    def _floors(self, epoch, monotonic):
        if (type(epoch) is not int or type(monotonic) is not int
                or epoch < self._epoch or monotonic < self._monotonic
                or epoch >= self._window[3] or monotonic >= self._bound):
            _fail()
        self._epoch, self._monotonic = epoch, monotonic

    def _bounds(self, window, bound):
        candidate = execution.clock._validate(window)
        execution.shape._integer(bound, minimum=1)
        if (candidate[:3] != self._window[:3] or bound > self._bound
                or bound > candidate[4] or any(new > old for new, old in zip(candidate[3:], self._window[3:]))):
            _fail()
        self._window, self._bound = candidate, bound
        self._floors(self._epoch, self._monotonic)

    def _receiving_on_permission(self, permission, parent_continuity):
        self._identity()
        if (permission is not self._permission or self._phase != "acquiring"
                or self._parent_continuity is not None or not callable(parent_continuity)):
            _fail()
        self._parent_continuity = parent_continuity
        window, bound = permission._planning_bounds
        self._bounds(window, bound)
        return self._continuity, self._retain_receiver

    def _continuity(self, epoch, monotonic):
        self._identity()
        self._ledger()
        if type(epoch) is not int or type(monotonic) is not int or min(epoch, monotonic) < 1:
            _fail()
        self._floors(max(self._epoch, epoch), max(self._monotonic, monotonic))
        if self._permission._state == "active":
            if not callable(self._parent_continuity):
                _fail()
            observed = self._parent_continuity(self._epoch, self._monotonic)
            if type(observed) is not tuple or len(observed) != 2:
                _fail()
            self._floors(*observed)
        else:
            # The exact old scope checks actual owner/key/receipt resources but
            # does not reactivate or invoke the revoked permission. The final
            # signed receiver bounds below remain the stricter last check.
            self._floors(*self._scope.continuity(self._epoch, self._monotonic))
            if self._intervals is not None:
                from serverware import oidc_session_activation_delivery_planner_bootstrap as consume

                for interval, opening in self._intervals:
                    observed = consume.shared._fresh(interval, self._work, opening=opening)
                    if observed[0] < self._monotonic or observed[1] < self._epoch:
                        _fail()
                    self._floors(observed[1], observed[2])
                    self._floors(*self._scope.continuity(self._epoch, self._monotonic))
        now = execution.clock._check_on_work(self._window, work=self._work)
        sampled = execution.production._callback(self._work, time.monotonic_ns)
        self._floors(now, sampled)
        if self._session_expiry is not None and now >= self._session_expiry:
            _fail()
        self._ledger()
        self._identity()
        return self._epoch, self._monotonic

    def _retain_receiver(self, current, window, bound):
        self._identity()
        if self._phase != "acquiring" or self._receiver is not None or not callable(current):
            _fail()
        self._bounds(window, bound)
        self._receiver = current

    def _current(self):
        self._identity()
        if not callable(self._receiver):
            _fail()
        self._ledger()
        now = self._receiver()
        if type(now) is not int or now < self._epoch or now >= self._window[3]:
            _fail()
        self._epoch = now
        self._ledger()
        self._identity()
        return now

    def finish(self):
        if (self._phase != "staged" or self._permission._normal_exit is not True
                or self._permission._state != "closed" or type(self._response) is not JSONResponse):
            _fail()
        self._current()
        self._parent_continuity = None
        self._phase = "finished"
        return self._response

    def _before_send(self, scope, status_code, headers, body):
        if (scope is not self._asgi or scope.get(_SCOPE_KEY) is not self or self._phase != "finished"
                or type(status_code) is not int or status_code != 200 or body != self._body
                or [(name, value) for name, value in headers if name.lower() == b"set-cookie"]
                    != [(b"set-cookie", self._cookie)]):
            _fail()
        self._current()
        # Claim before actual send. A later send failure is terminal, never a
        # second cookie or a replacement response after headers may escape.
        self._phase = "sending"

    def _discard(self):
        self._phase = "closed"
        self._response = self._body = self._cookie = None
        self._receiver = self._parent_continuity = None
        if self._asgi.get(_SCOPE_KEY) is self:
            del self._asgi[_SCOPE_KEY]


def _response_on_permission(permission):
    from serverware import app as application
    from serverware import authority_oidc_session_activation_release_response as receiving

    if type(permission) is not execution._ActivationPermission:
        _fail()
    permission._identity()
    if (permission._state != "active" or permission._dispatch_phase != "release-proof-verified"
            or permission._release_handoff_spent is not False or permission._normal_exit is not False
            or type(permission._scope) is not execution._Scope or type(permission._target) is not tuple):
        _fail()
    owner, request, work, scope, target = (permission._owner, permission._request,
        permission._work, permission._scope, permission._target)
    if target[0] is not application or request.scope.get(_SCOPE_KEY) is not None:
        _fail()
    window, bound = permission._planning_bounds
    observed = permission._planning_observed
    staged = object.__new__(_StagedResponse)
    staged._permission, staged._owner, staged._request = permission, owner, request
    staged._asgi, staged._work, staged._scope, staged._target = request.scope, work, scope, target
    staged._parent, staged._binding, staged._custody = owner._material, owner._binding, owner._custody
    staged._pid, staged._thread = os.getpid(), threading.get_ident()
    staged._seal = (permission, owner, request, request.scope, work, scope, target,
        staged._parent, staged._binding, staged._custody, staged._pid, staged._thread)
    staged._limits, staged._metrics = work.limits, work.metrics
    staged._ceilings = (work.limits.max_hashes, work.limits.max_input_bytes, work.limits.max_json_nodes)
    staged._window, staged._bound = execution.clock._validate(window), bound
    staged._epoch, staged._monotonic = observed
    staged._intervals, staged._session_expiry = permission._consume_lifetimes, permission._session_expiry
    staged._parent_continuity = staged._receiver = staged._response = staged._body = staged._cookie = None
    staged._phase, staged._local_digest = "acquiring", target[2]["localDigest"]
    staged._user_id, staged._session_id, staged._credential_id = (
        target[2]["userId"], target[2]["sessionId"], target[2]["credentialId"])
    staged._credential, staged._count, staged._session_scope = target[3], target[4], target[1]
    # The source-owned terminal continuation reaches the real receiver. No
    # posted token or successful result object can enter this helper.
    token = permission.acquire_and_release_token(_delivery=staged)
    if type(token) is not bytes or len(token) != receiving.delivery.TOKEN_BYTES:
        _fail()
    staged._current()
    work.charge(input_bytes=_AUTH_RESERVATION + len(token), hashes=1, json_nodes=2048)
    active_token = token.decode("ascii")
    del token
    if not auth.oidc_session_token_is_well_formed(active_token):
        _fail()
    active_session = permission_source._native(staged._current, work,
        lambda: application.oidc_browser_session_from_token(active_token))
    credential, count = staged._credential, staged._count
    if (type(active_session) is not dict or active_session.get("status") != "active"
            or active_session.get("id") != staged._session_id
            or active_session.get("user_id") != staged._user_id
            or active_session.get("bound_webauthn_credential_id") != credential[0]
            or active_session.get("revoked_at") is not None):
        _fail()
    fresh_credential = pending._credential(active_session.get("_bound_credential"),
        staged._user_id, staged._credential_id)
    if fresh_credential[:2] != credential[:2] or fresh_credential[2] < count:
        _fail()
    active_identity = permission_source._native(staged._current, work,
        lambda: application.oidc_identity_from_browser_session(active_session))
    if (type(active_identity) is not application.AdminIdentity
            or active_identity.auth_method != "oidc-session"
            or active_identity.user_id != staged._user_id or active_identity.roles != staged._session_scope[1]):
        _fail()
    snapshot = staged._session_scope[0]
    for name in ("expires_at", "provider_expires_at"):
        expected = snapshot[pending._SESSION_FIELDS.index(name)]
        if pending._hold(active_session.get(name)) != expected:
            _fail()
    expiry = min(permission_source.activation._time(active_session[name], name, work)
        for name in ("expires_at", "provider_expires_at"))
    staged._session_expiry = min(staged._session_expiry, expiry)
    now = staged._current()
    max_age = (expiry - now) // 1_000_000_000
    if max_age < 1:
        _fail()
    work.charge(input_bytes=2048, json_nodes=8)
    response = permission_source._native(staged._current, work,
        lambda: JSONResponse(status_code=200, headers=_HEADERS, content=dict(_SUCCESS)))
    permission_source._native(staged._current, work, lambda: response.set_cookie(
        application.OIDC_SESSION_COOKIE_NAME, active_token,
        **oidc_session_cookie_attributes(
            expires_at=datetime.fromtimestamp(staged._session_expiry // 1_000_000_000, tz=timezone.utc),
            max_age=max_age), httponly=True,
        secure=request.url.scheme == "https", samesite="strict", path="/"))
    del active_token
    cookies = [value for name, value in response.raw_headers if name.lower() == b"set-cookie"]
    if len(cookies) != 1:
        _fail()
    staged._response, staged._body, staged._cookie = response, response.body, cookies[0]
    staged._current()
    staged._phase = "staged"
    request.scope[_SCOPE_KEY] = staged
    return staged


def _unknown_response():
    return JSONResponse(status_code=503, headers=_HEADERS, content=contract.outcome_unknown())


def _discard_scope(scope):
    staged = scope.get(_SCOPE_KEY)
    if type(staged) is _StagedResponse:
        staged._discard()


async def _send_response(scope, receive, send, response, *, before_dispatch=False, downstream_failed=False):
    """The signed outer ASGI owner calls this at the actual emission boundary."""
    if scope.get("path") == POST_PATH and before_dispatch:
        await JSONResponse(status_code=400, headers=_HEADERS,
            content=contract.rejected_before_dispatch())(scope, receive, send)
        return
    if scope.get("path") == POST_PATH and downstream_failed:
        await _unknown_response()(scope, receive, send)
        return
    staged = scope.get(_SCOPE_KEY)
    if staged is None:
        # No other path may manufacture a successful activation cookie.
        if (scope.get("path") == POST_PATH and (response.status_code == 200
                or any(name.lower() == b"set-cookie" for name, _value in response.raw_headers))):
            await _unknown_response()(scope, receive, send)
        else:
            await response(scope, receive, send)
        return
    if type(staged) is not _StagedResponse:
        await _unknown_response()(scope, receive, send)
        return
    started = False

    class _BeforeSendFailure(Exception):
        pass

    async def guarded_send(message):
        nonlocal started
        if message["type"] == "http.response.start":
            if started:
                _fail()
            try:
                staged._before_send(scope, message["status"], message.get("headers", []), response.body)
            except Exception:
                raise _BeforeSendFailure() from None
            started = True
        await send(message)

    try:
        try:
            await response(scope, receive, guarded_send)
        except _BeforeSendFailure:
            if started:
                raise
            # The stale success proof/header set is discarded with its cookie.
            # This fixed unknown response is intentionally not re-signed under
            # a renewed activation allowance and never requests a replay.
            await _unknown_response()(scope, receive, send)
    finally:
        staged._discard()
