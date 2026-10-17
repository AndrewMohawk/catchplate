"""Genuine recovery receiving through normal cleanup and one signed send.

Only this same-call terminal can retain the receiver past actor cleanup. Its
ancestor is selected before derivation; ordinary closed actor/acquisition
guards remain unusable. No public input accepts a token or successful carrier.
"""
from __future__ import annotations

from datetime import datetime, timezone
import os
import threading
import time

from fastapi.responses import JSONResponse

from catchplate import auth
from catchplate import control_plane_oidc_session_activation_recovery_acquisition as acquisition
from catchplate import oidc_session_activation_recovery_http_contract as contract
from catchplate.operator_oidc import oidc_session_cookie_attributes


actor, execution = acquisition.actor, acquisition.execution
permission, pending = actor.permission, actor.pending
POST_PATH = "/api/auth/session/activation/recovery"
_SCOPE_KEY = "catchplate.oidc-session-activation.recovery-final-delivery"
_HEADERS = {"Cache-Control": "no-store", "Pragma": "no-cache", "X-Content-Type-Options": "nosniff"}
_SUCCESS = {"schema": contract.SUCCESS_SCHEMA, "purpose": contract.PURPOSE,
    "status": "recovered", "sessionState": "active", "automaticRetryAllowed": False}
_AUTH_RESERVATION = 256 * 1024


def _fail():
    raise execution.startup.EnrollmentStartupError("recovery current-session delivery is unavailable")


class _StagedRecoveryResponse:
    """Source-owned terminal, never a reusable permission or token carrier."""

    __slots__ = ("_active", "_actor", "_application", "_owner", "_owner_scope",
        "_source_current", "_target", "_request", "_asgi", "_original", "_payload",
        "_parent", "_binding", "_custody", "_config", "_config_pin", "_root", "_work",
        "_parent_lifetime", "_selected", "_selected_pin", "_originals", "_result", "_capacity",
        "_old", "_pid", "_thread", "_seal", "_pins", "_limits", "_ceilings", "_metrics",
        "_window", "_bound", "_epoch", "_monotonic", "_parent_continuity", "_receiver",
        "_phase", "_response", "_body", "_cookie", "_local_digest", "_session_expiry")

    def __init__(self):
        _fail()

    def _identity(self):
        """Identity only: never call the receiver or a descendant guard here."""
        active, scope, owner = self._active, self._actor, self._owner
        references = (active, scope, self._application, owner, self._owner_scope,
            self._source_current, self._target, self._request, self._asgi, self._original,
            self._payload, self._parent, self._binding, self._custody, self._config,
            self._root, self._work, self._parent_lifetime, self._selected, self._selected_pin,
            self._originals, self._result, self._capacity, self._old)
        if (type(active) is not acquisition._RecoveryAcquisition
                or type(scope) is not actor._ActorScope
                or os.getpid() != self._pid or threading.get_ident() != self._thread
                or type(self._seal) is not tuple or len(self._seal) != len(references)
                or any(value is not held for value, held in zip(references, self._seal))
                or execution.startup._owner is not owner
                or owner._material is not self._parent or owner._binding is not self._binding
                or owner._custody is not self._custody or owner._activation_permission is not None
                or self._parent.release_recovery_grant_acquisition is not self._config
                or self._binding.runtime_root_public_key is not self._root
                or self._request.scope is not self._asgi
                or getattr(self._request.state, actor.ORIGINAL_STATE_NAME, None) is not self._original
                or scope._application is not self._application or scope._owner is not owner
                or scope._request is not self._request or scope._original is not self._original
                or scope._payload is not self._payload or scope._work is not self._work
                or scope._owner_scope is not self._owner_scope or scope._target is not self._target
                or scope._source_current is not self._source_current
                or active._owner is not owner or active._work is not self._work
                or active._parent is not self._parent or active._binding is not self._binding
                or active._custody is not self._custody or active._config is not self._config
                or active._root is not self._root or active._lifetime is not self._parent_lifetime
                or active._delivery is not self or active._delivery_seal is not self
                or active._stage_spent is not True or active._staged is not True
                or active._exchange_spent is not True):
            _fail()
        config = self._config
        observed = (config.endpoint, config.issuer_policy_bytes, config.release_custody_bytes,
            config.proof_enrollment_bytes, config.intent_enrollment_bytes)
        if any(value is not held for value, held in zip(observed, self._config_pin)):
            _fail()
        pins = (scope._policy_pin, scope._request_pin, scope._target_pin, scope._binding_pin,
            scope._payload_digest, scope._credential, scope._count, scope._roles,
            scope._rbac_pin, scope._session_pin, scope._trust_pin)
        if pins != self._pins:
            _fail()
        for record, pin in zip(self._selected[1:], self._selected_pin):
            if (record.kind, record.digest) != pin[:2] or record.originals is not pin[2]:
                _fail()
        result = self._result
        if any(value is not held for value, held in zip((result.client_authorization_bytes,
                result.server_bootstrap_bytes, result.outcome_bytes), self._originals)):
            _fail()
        if active._closed is False:
            if (self._phase not in ("acquiring", "staged") or acquisition._ACTIVE is not active
                    or actor._ACTIVE is not scope or scope._active is not True
                    or scope._authorized is not True or scope._normal_exit is not False
                    or active._normal_exit is not False or active._exchange_failed is not False
                    or scope._recovery_acquisition_spent is not True or scope._old_token is not self._old
                    or active._scope is not scope or active._scope_seal is not scope
                    or active._lifetime_seal is not self._parent_lifetime
                    or active._selected is not self._selected or active._selected_pin is not self._selected_pin
                    or active._originals is not self._originals or active._result is not result
                    or active._capacity is not self._capacity or active._capacity_seal is not self._capacity
                    or active._receiving_current is not active._receiving_seal
                    or active._token is not active._token_seal):
                _fail()
        elif (active._closed is not True or active._normal_exit is not True
                or scope._normal_exit is not True or scope._active is not False
                or scope._authorized is not False or scope._old_token is not None
                or acquisition._ACTIVE is not None or actor._ACTIVE is not None
                or active._scope is not None or active._scope_seal is not None
                or active._lifetime_seal is not None or active._selected is not None
                or active._selected_pin is not None or active._originals is not None
                or active._result is not None or active._capacity is not None
                or active._capacity_seal is not None or active._receiving_current is not None
                or active._receiving_seal is not None or active._token is not None
                or active._token_seal is not None or active._exchange_in_progress is not False
                or active._exchange_complete is not False or active._exchange_failed is not True
                or self._parent_lifetime.guards or self._phase not in ("staged", "finished")):
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
        if (candidate[:3] != self._window[:3] or bound > self._bound or bound > candidate[4]
                or any(new > old for new, old in zip(candidate[3:], self._window[3:]))):
            _fail()
        self._window, self._bound = candidate, bound
        self._floors(self._epoch, self._monotonic)

    def _exchange_on_active(self, active, original_parent_continuity):
        self._identity()
        if (active is not self._active or active._exchange_in_progress is not True
                or self._phase != "acquiring" or self._parent_continuity is not None
                or not callable(original_parent_continuity)):
            _fail()
        self._parent_continuity = original_parent_continuity
        self._bounds(self._parent_lifetime.window, self._parent_lifetime.bound)
        return self._continuity

    def _request_policy(self):
        application, scope, target, work = self._application, self._actor, self._target, self._work
        _policy, policy_pin = actor._policy(application, work)
        request_pin = (tuple(self._request.headers.getlist("origin")),
            tuple(self._request.headers.getlist(application.CSRF_HEADER_NAME)),
            self._request.cookies.get(application.CSRF_COOKIE_NAME),
            self._request.cookies.get(application.OIDC_SESSION_COOKIE_NAME),
            self._request.method, self._request.scope.get("path"),
            self._request.scope.get("query_string", b""))
        if (policy_pin != self._pins[0] or request_pin != self._pins[1]
                or actor._snapshot(scope._policy, work) != self._pins[0][0]
                or actor._snapshot(scope._binding, work) != self._pins[3]
                or actor._target_snapshot(target, work) != self._pins[2]):
            _fail()

    def _continuity(self, epoch, monotonic):
        self._identity()
        self._ledger()
        if type(epoch) is not int or type(monotonic) is not int or min(epoch, monotonic) < 1:
            _fail()
        self._floors(max(self._epoch, epoch), max(self._monotonic, monotonic))
        self._request_policy()
        if self._active._closed is False:
            if not callable(self._parent_continuity):
                _fail()
            observed = self._parent_continuity(self._epoch, self._monotonic)
            if type(observed) is not tuple or len(observed) != 2:
                _fail()
            self._floors(*observed)
            self._bounds(self._parent_lifetime.window, self._parent_lifetime.bound)
        else:
            # These are captured original ancestors, not a closed actor's
            # current(), a resumed acquisition, or the response child itself.
            self._floors(*self._owner_scope.continuity(self._epoch, self._monotonic))
            for guard in (self._source_current, self._target.live):
                now = guard()
                sampled = execution.production._callback(self._work, time.monotonic_ns)
                self._floors(now, sampled)
            self._floors(*self._owner_scope.continuity(self._epoch, self._monotonic))
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
        # The exact same genuine child guards live token access and survives
        # only in this terminal. It is never attached to its ancestor lifetime.
        acquisition._RecoveryAcquisition._retain_receiving_current(self._active, current, window, bound)
        self._receiver = current

    def _current(self):
        self._identity()
        self._ledger()
        if not callable(self._receiver):
            _fail()
        now = self._receiver()
        if type(now) is not int or now < self._epoch or now >= self._window[3]:
            _fail()
        self._epoch = now
        self._ledger()
        self._identity()
        return now

    def _check_actor(self):
        """Fresh exact target/RBAC/sole-credential/trust checks, not token proof."""
        application, work, subject = self._application, self._work, self._target.subject
        work.charge(input_bytes=_AUTH_RESERVATION, json_nodes=2048)
        native = lambda call: permission._native(self._current, work, call)
        rbac = native(lambda: application.db.get_rbac_role_binding(subject["userId"]))
        if (type(rbac) is not dict or rbac.get("subject_id") != subject["userId"]
                or rbac.get("status") != "active" or actor._snapshot(rbac, work) != self._pins[8]):
            _fail()
        credential = native(lambda: pending._history(application, subject["userId"], subject["credentialId"]))
        if credential != (self._pins[5][0], self._pins[5][1], self._pins[6]):
            _fail()
        row = native(lambda: application.db.get_webauthn_credential(subject["credentialId"]))
        if pending._credential(row, subject["userId"], subject["credentialId"]) != credential:
            _fail()
        trust = native(lambda: actor.webauthn._allowed_authenticator(row, self._actor._policy))
        if actor._snapshot(trust, work) != self._pins[10]:
            _fail()
        session = native(lambda: application.db.get_oidc_browser_session_recovery_target(
            user_id=subject["userId"], session_id=subject["sessionId"]))
        if (type(session) is not dict or session.get("status") != "active"
                or session.get("id") != subject["sessionId"] or session.get("user_id") != subject["userId"]
                or session.get("token_digest") != self._target.delivery_scope["newTokenDigest"]
                or session.get("revoked_at") is not None
                or session.get("bound_webauthn_credential_id") != credential[0]
                or actor._snapshot(session, work) != self._pins[9]):
            _fail()
        identity = native(lambda: application.oidc_identity_from_browser_session(session))
        if (type(identity) is not application.AdminIdentity or identity.auth_method != "oidc-session"
                or identity.user_id != subject["userId"] or identity.roles != self._pins[7]):
            _fail()
        self._current()

    def finish(self):
        if (self._phase != "staged" or self._active._normal_exit is not True
                or self._actor._normal_exit is not True or type(self._response) is not JSONResponse):
            _fail()
        self._current()
        self._check_actor()
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
        self._check_actor()
        self._phase = "sending"

    def _discard(self):
        self._phase = "closed"
        self._response = self._body = self._cookie = None
        self._receiver = self._parent_continuity = None
        self._old = None
        self._seal = ()
        if self._asgi.get(_SCOPE_KEY) is self:
            del self._asgi[_SCOPE_KEY]


def _response_on_active(active):
    from catchplate import app as application
    from catchplate import authority_oidc_session_activation_release_response as receiving

    if type(active) is not acquisition._RecoveryAcquisition or acquisition._ACTIVE is not active:
        _fail()
    active.current()
    scope = active._scope
    if (type(scope) is not actor._ActorScope or actor._ACTIVE is not scope
            or scope._application is not application or scope._authorized is not True
            or scope._normal_exit is not False or active._normal_exit is not False
            or active._closed is not False or active._staged is not True
            or active._exchange_spent is not False or active._delivery is not None
            or type(scope._owner_scope) is not execution._Scope
            or type(scope._target) is not actor.history._RecoveryTarget
            or scope._request.method != "POST" or scope._request.scope.get("path") != POST_PATH
            or scope._request.scope.get("query_string", b"") != b""
            or scope._request.scope.get(_SCOPE_KEY) is not None):
        _fail()
    staged = object.__new__(_StagedRecoveryResponse)
    staged._active, staged._actor, staged._application = active, scope, application
    staged._owner, staged._owner_scope = active._owner, scope._owner_scope
    staged._source_current, staged._target = scope._source_current, scope._target
    staged._request, staged._asgi = scope._request, scope._request.scope
    staged._original, staged._payload = scope._original, scope._payload
    staged._parent, staged._binding, staged._custody = active._parent, active._binding, active._custody
    staged._config, staged._config_pin, staged._root = active._config, active._config_pin, active._root
    staged._work, staged._parent_lifetime = active._work, active._lifetime
    staged._selected, staged._selected_pin = active._selected, active._selected_pin
    staged._originals, staged._result, staged._capacity = active._originals, active._result, active._capacity
    staged._old = scope._old_token
    staged._pid, staged._thread = os.getpid(), threading.get_ident()
    staged._seal = (active, scope, application, staged._owner, staged._owner_scope,
        staged._source_current, staged._target, staged._request, staged._asgi, staged._original,
        staged._payload, staged._parent, staged._binding, staged._custody, staged._config,
        staged._root, staged._work, staged._parent_lifetime, staged._selected, staged._selected_pin,
        staged._originals, staged._result, staged._capacity, staged._old)
    staged._pins = (scope._policy_pin, scope._request_pin, scope._target_pin, scope._binding_pin,
        scope._payload_digest, scope._credential, scope._count, scope._roles,
        scope._rbac_pin, scope._session_pin, scope._trust_pin)
    work, lifetime = staged._work, staged._parent_lifetime
    staged._limits, staged._metrics = work.limits, work.metrics
    staged._ceilings = (work.limits.max_hashes, work.limits.max_input_bytes, work.limits.max_json_nodes)
    staged._window, staged._bound = execution.clock._validate(lifetime.window), lifetime.bound
    staged._epoch, staged._monotonic = lifetime.epoch, lifetime.monotonic
    staged._parent_continuity = staged._receiver = None
    staged._response = staged._body = staged._cookie = None
    staged._phase, staged._local_digest = "acquiring", scope._target.subject["localDigest"]
    staged._session_expiry = None
    try:
        # A binds this exact terminal before root chooses its derivation
        # ancestor. The ordinary None/private exchange remains live-only.
        active.exchange_token(_delivery=staged)
        token = active.token_bytes
        if type(token) is not bytes or len(token) != receiving.delivery.TOKEN_BYTES:
            _fail()
        staged._current()
        work.charge(input_bytes=_AUTH_RESERVATION + len(token), hashes=1, json_nodes=2048)
        active_token = token.decode("ascii")
        del token
        if not auth.oidc_session_token_is_well_formed(active_token):
            _fail()
        session = permission._native(staged._current, work,
            lambda: application.oidc_browser_session_from_token(active_token))
        subject, delivery = staged._target.subject, staged._target.delivery_scope
        if (type(session) is not dict or session.get("status") != "active"
                or session.get("id") != subject["sessionId"] or session.get("user_id") != subject["userId"]
                or session.get("revoked_at") is not None
                or session.get("token_digest") != delivery["newTokenDigest"]
                or session.get("bound_webauthn_credential_id") != scope._credential[0]):
            _fail()
        credential = pending._credential(session.get("_bound_credential"), subject["userId"], subject["credentialId"])
        if credential != (scope._credential[0], scope._credential[1], scope._count):
            _fail()
        identity = permission._native(staged._current, work,
            lambda: application.oidc_identity_from_browser_session(session))
        if (type(identity) is not application.AdminIdentity or identity.auth_method != "oidc-session"
                or identity.user_id != subject["userId"] or identity.roles != scope._roles):
            _fail()
        session_pin = dict(scope._session_pin)
        for name in pending._SESSION_FIELDS:
            if pending._hold(session.get(name)) != session_pin.get(name):
                _fail()
        expiry = min(permission.activation._time(session[name], name, work)
            for name in ("expires_at", "provider_expires_at"))
        staged._session_expiry = expiry
        staged._check_actor()
        now = staged._current()
        max_age = (staged._session_expiry - now) // 1_000_000_000
        if max_age < 1:
            _fail()
        work.charge(input_bytes=2048, json_nodes=16)
        response = permission._native(staged._current, work,
            lambda: JSONResponse(status_code=200, headers=_HEADERS, content=dict(_SUCCESS)))
        permission._native(staged._current, work, lambda: response.set_cookie(
            application.OIDC_SESSION_COOKIE_NAME, active_token,
            **oidc_session_cookie_attributes(
                expires_at=datetime.fromtimestamp(staged._session_expiry // 1_000_000_000, tz=timezone.utc),
                max_age=max_age), httponly=True,
            secure=staged._request.url.scheme == "https", samesite="strict", path="/"))
        del active_token
        cookies = [value for name, value in response.raw_headers if name.lower() == b"set-cookie"]
        if len(cookies) != 1:
            _fail()
        staged._response, staged._body, staged._cookie = response, response.body, cookies[0]
        staged._current()
        staged._phase = "staged"
        staged._asgi[_SCOPE_KEY] = staged
        return staged
    except BaseException:
        staged._discard()
        raise


def _unknown_response():
    return JSONResponse(status_code=503, headers=_HEADERS, content=contract.outcome_unknown())


def _discard_scope(scope):
    staged = scope.get(_SCOPE_KEY)
    if type(staged) is _StagedRecoveryResponse:
        staged._discard()


async def _send_response(scope, receive, send, response, *, before_dispatch=False, downstream_failed=False):
    """Called after signing, immediately around the actual ASGI emission."""
    if scope.get("path") == POST_PATH and before_dispatch:
        _discard_scope(scope)
        await JSONResponse(status_code=400, headers=_HEADERS,
            content=contract.rejected_before_dispatch())(scope, receive, send)
        return
    if scope.get("path") == POST_PATH and downstream_failed:
        _discard_scope(scope)
        await _unknown_response()(scope, receive, send)
        return
    staged = scope.get(_SCOPE_KEY)
    if staged is None:
        if (scope.get("path") == POST_PATH and (response.status_code == 200
                or any(name.lower() == b"set-cookie" for name, _value in response.raw_headers))):
            await _unknown_response()(scope, receive, send)
        else:
            await response(scope, receive, send)
        return
    if type(staged) is not _StagedRecoveryResponse:
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
            # Discard the signed stale success, including its cookie/proof.
            # No second signature, allowance, contact or automatic retry.
            await _unknown_response()(scope, receive, send)
    finally:
        staged._discard()
