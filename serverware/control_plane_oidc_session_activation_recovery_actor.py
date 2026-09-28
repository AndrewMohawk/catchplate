"""Fresh target-key recovery actor admission, never stale-cookie identity.

Options disclose only a genuine target-bound challenge. The private authorizer
is a live context manager, not a successful permission carrier: its caller must
stay inside the original work, clocks, owner and trust locks. Neither path
executes activation SQL, retries dispatch, opens a token or delivers a session.
"""
from __future__ import annotations

from contextlib import contextmanager
import math
import os
import threading
import time

from fastapi import HTTPException, Request

from serverware import auth as authentication
from serverware import control_plane_enrollment_startup as startup
from serverware import control_plane_oidc_session_activation_execution as execution
from serverware import control_plane_oidc_session_activation_permission as permission
from serverware import control_plane_oidc_session_activation_recovery_history as history
from serverware import control_plane_registration_finalization_completion_pending as pending
from serverware import oidc_session_activation_recovery_http_contract as contract
from serverware import webauthn


ORIGINAL_STATE_NAME = "oidc_session_activation_recovery_bytes"
_CONSTRUCTION = object()
_ACTIVE = None


def _deny(message, status=409):
    raise HTTPException(status_code=status, detail=message)


@contextmanager
def _startup_scope():
    lock = startup._LOCK
    if lock.acquire(blocking=False) is not True:
        _deny("recovery owner is busy", 409)
    try:
        yield
    finally:
        lock.release()


def _snapshot(value, work):
    if type(value) is not dict or not 1 <= len(value) <= 64:
        _deny("recovery current row is not bounded")
    work.prepare_scan(value)
    if any(type(key) is not str for key in value):
        _deny("recovery current row keys differ")
    return tuple((key, pending._hold(value[key])) for key in sorted(value))


def _policy(application, work):
    policy = application._control_plane_mutation_authn_policy()
    if policy.get("userVerification") != "required":
        _deny("recovery requires user-verified WebAuthn", 503)
    origin = webauthn.WEBAUTHN_ORIGIN
    if type(origin) is not str or not 1 <= len(origin) <= 4096 or origin == "null":
        _deny("recovery origin is not configured", 503)
    required = application.CONTROL_PLANE_TWO_PERSON_REQUIRED
    actions = application.CONTROL_PLANE_TWO_PERSON_ACTIONS
    ttl = application.CONTROL_PLANE_TWO_PERSON_TTL_SECONDS
    if (type(required) is not bool or type(actions) is not tuple
            or any(type(action) is not str for action in actions)
            or type(ttl) is not int or ttl <= 0):
        _deny("recovery approval policy is not configured", 503)
    if required and "*" not in actions and contract.ACTION not in actions:
        _deny("recovery action is missing from required approval policy", 503)
    return policy, (_snapshot(policy, work), origin, required, actions, ttl)


def _request(request, original):
    if (type(request) is not Request or type(original) is not bytes
            or not 2 <= len(original) <= contract.MAX_REQUEST_BYTES
            or getattr(request.state, ORIGINAL_STATE_NAME, None) is not original):
        _deny("recovery requires the actual bounded HTTP request", 400)


def _owned_capture_bytes(graphs, work):
    """Measure a fixed source-selected graph table without copying or serialization."""
    total, nodes = 0, 0

    def visit(value, depth=0):
        nonlocal total, nodes
        nodes += 1
        if depth > 12 or nodes > 8192:
            execution._fail("recovery held graphs exceed their source bound")
        work.charge(json_nodes=1)
        if value is None or type(value) is bool:
            size = 5
        elif type(value) is int:
            if not -(1 << 63) <= value < (1 << 64):
                execution._fail("recovery held integer exceeds its source bound")
            size = 32
        elif type(value) is float and math.isfinite(value):
            size = 32
        elif type(value) is str:
            size = 4 * len(value)
        elif type(value) is bytes:
            size = len(value)
        elif type(value) in (tuple, list, frozenset, dict):
            if len(value) > 8192:
                execution._fail("recovery held collection exceeds its source bound")
            size = 2 + 16 * len(value)
        else:
            execution._fail("recovery held graph has an unexpected source type")
        total += size
        if total > history.MAX_ORIGINAL_BYTES // 4:
            execution._fail("recovery held graphs exhaust original capacity")
        work.charge(input_bytes=size)
        if type(value) is dict:
            for key, item in value.items():
                if type(key) is not str:
                    execution._fail("recovery held graph keys differ")
                visit(key, depth + 1)
                visit(item, depth + 1)
        elif type(value) in (tuple, list, frozenset):
            for item in value:
                visit(item, depth + 1)

    # This is deliberately not an arbitrary owner, Request or key traversal.
    for graph in graphs:
        visit(graph)
    return total


class _ActorScope:
    """Source-constructed, thread-bound scope; never accepted as input proof."""

    __slots__ = ("_application", "_owner", "_request", "_original", "_payload",
        "_work", "_source_current", "_owner_scope", "_target", "_policy",
        "_policy_pin", "_request_pin", "_old_token", "_target_pin", "_binding",
        "_binding_pin", "_payload_digest", "_credential", "_count", "_roles",
        "_rbac_pin", "_session_pin", "_trust_pin", "_window", "_bound", "_epoch", "_monotonic",
        "_pid", "_thread", "_active", "_authorized", "_recovery_acquisition_spent", "_normal_exit")

    def __init__(self, construction, *, application, owner, request, original,
            payload, work, current, owner_scope, target, policy, policy_pin,
            request_pin, old_token):
        if construction is not _CONSTRUCTION:
            _deny("recovery scope is privately constructed", 503)
        self._application, self._owner, self._request = application, owner, request
        self._original, self._payload, self._work = original, payload, work
        self._source_current, self._owner_scope, self._target = current, owner_scope, target
        self._policy, self._policy_pin, self._request_pin = policy, policy_pin, request_pin
        self._old_token = old_token
        self._target_pin = (_snapshot(target.subject, work),
            _snapshot(target.delivery_scope, work), target.activation_authorization_digest,
            target.old_token_digest, target.intent_bytes, target.intent_digest)
        self._binding = contract.request_binding(target.subject,
            activation_authorization_digest=target.activation_authorization_digest,
            old_token_digest=target.old_token_digest)
        self._binding_pin = _snapshot(self._binding, work)
        self._payload_digest = None
        self._credential, self._count, self._roles = None, None, None
        self._rbac_pin, self._session_pin, self._trust_pin = None, None, None
        self._window = target.live_window
        self._bound = min(target.deadline_ns, owner_scope.deadline_ns)
        self._epoch, self._monotonic = self._window[0], self._window[2]
        self._pid, self._thread = os.getpid(), threading.get_ident()
        self._active, self._authorized = True, False
        self._recovery_acquisition_spent = False
        self._normal_exit = False

    @property
    def binding(self):
        self.current()
        self._work.prepare_copy(self._binding)
        return dict(self._binding)

    @property
    def window(self):
        self.current()
        return self._window

    @property
    def deadline_ns(self):
        self.current()
        return self._bound

    def _guard(self):
        work, application, target = self._work, self._application, self._target
        execution.capture._SharedLedger(work)
        if (self._active is not True or os.getpid() != self._pid
                or threading.get_ident() != self._thread
                or _ACTIVE is not self or self._owner._activation_permission is not None
                or startup._owner is not self._owner
                or getattr(self._request.state, ORIGINAL_STATE_NAME, None) is not self._original):
            _deny("recovery actor context is no longer live", 503)
        self._source_current()
        self._owner_scope.current()
        epoch = target.live()
        monotonic = execution.production._callback(work, time.monotonic_ns)
        if (type(epoch) is not int or type(monotonic) is not int
                or epoch < self._epoch or monotonic < self._monotonic
                or epoch >= self._window[3] or monotonic >= self._bound):
            _deny("recovery original allowance expired or reversed", 503)
        self._epoch, self._monotonic = epoch, monotonic
        _policy_value, policy_pin = _policy(application, work)
        request_pin = (tuple(self._request.headers.getlist("origin")),
            tuple(self._request.headers.getlist(application.CSRF_HEADER_NAME)),
            self._request.cookies.get(application.CSRF_COOKIE_NAME),
            self._request.cookies.get(application.OIDC_SESSION_COOKIE_NAME),
            self._request.method, self._request.scope.get("path"),
            self._request.scope.get("query_string", b""))
        if policy_pin != self._policy_pin or request_pin != self._request_pin:
            _deny("recovery request or current policy changed", 403)
        if (_snapshot(target.subject, work), _snapshot(target.delivery_scope, work),
                target.activation_authorization_digest, target.old_token_digest,
                target.intent_bytes, target.intent_digest) != self._target_pin:
            _deny("recovery historical target changed", 503)
        if (_snapshot(self._binding, work) != self._binding_pin
                or _snapshot(self._policy, work) != self._policy_pin[0]):
            _deny("recovery held policy or action binding changed", 503)
        return epoch

    def _native(self, call):
        return permission._native(self._guard, self._work, call)

    def _current_target(self):
        delivery = self._target.delivery_scope
        return (self._target.subject, delivery["credentialRecordId"],
            delivery["oldTokenDigest"], delivery["newTokenDigest"])

    def _read_current(self):
        application, work = self._application, self._work
        subject, credential_record_id, old_token_digest, new_token_digest = self._current_target()
        rbac = self._native(lambda: application.db.get_rbac_role_binding(subject["userId"]))
        if (type(rbac) is not dict or rbac.get("subject_id") != subject["userId"]
                or rbac.get("status") != "active" or type(rbac.get("roles")) is not list
                or not set(rbac["roles"]).intersection({"admin", "approver"})):
            _deny("recovery requires explicit current actor roles", 403)
        rbac_pin = _snapshot(rbac, work)
        credential = self._native(lambda: pending._history(application,
            subject["userId"], subject["credentialId"]))
        if credential is None or credential[0] != credential_record_id:
            _deny("recovery requires the sole original credential", 403)
        credential_row = self._native(lambda: application.db.get_webauthn_credential(
            subject["credentialId"]))
        if pending._credential(credential_row, subject["userId"], subject["credentialId"]) != credential:
            _deny("recovery target credential changed", 403)
        trust = self._native(lambda: webauthn._allowed_authenticator(credential_row, self._policy))
        trust_pin = _snapshot(trust, work)
        session = self._native(lambda: application.db.get_oidc_browser_session_recovery_target(
            user_id=subject["userId"], session_id=subject["sessionId"]))
        if (type(session) is not dict or session.get("id") != subject["sessionId"]
                or session.get("user_id") != subject["userId"]
                or session.get("revoked_at") is not None
                or session.get("roles") != rbac["roles"]):
            _deny("recovery original session is unavailable", 403)
        status = session.get("status")
        if status == "pending_webauthn":
            if (session.get("token_digest") != old_token_digest
                    or any(session.get(name) is not None for name in pending._UNBOUND_FIELDS)):
                _deny("recovery pending target binding changed", 403)
        elif status == "active":
            if (session.get("token_digest") != new_token_digest
                    or session.get("bound_webauthn_credential_id") != credential[0]):
                _deny("recovery active target binding changed", 403)
            # A current row check is not actor authentication. It only rejects
            # changed target credential/trust/roles before the fresh assertion.
            identity = self._native(lambda: application.oidc_identity_from_browser_session(session))
            if (identity is None or identity.user_id != subject["userId"]
                    or identity.roles != frozenset(rbac["roles"])):
                _deny("recovery active target trust changed", 403)
        else:
            _deny("recovery target status is unavailable", 403)
        deadlines = [permission.activation._time(session[name], name, work)
            for name in ("provider_expires_at", "expires_at")]
        if status == "pending_webauthn":
            deadlines.append(permission.activation._time(session["pending_expires_at"],
                "pending_expires_at", work))
        self._window = execution.caller.window_policy._narrow(self._window,
            deadline_epoch_ns=min(deadlines), maximum_lifetime_ns=self._window[5],
            maximum_clock_skew_ns=self._window[6])
        self._bound = min(self._bound, self._window[4])
        self._guard()
        return rbac_pin, _snapshot(session, work), credential, frozenset(rbac["roles"]), trust_pin

    def current(self):
        self._guard()
        rbac_pin, session_pin, credential, roles, trust_pin = self._read_current()
        if (rbac_pin != self._rbac_pin or session_pin != self._session_pin
                or credential != (self._credential[0], self._credential[1], self._count)
                or roles != self._roles or trust_pin != self._trust_pin):
            _deny("recovery actor or exact target changed", 403)
        return self._guard()

    def _close(self):
        global _ACTIVE

        self._normal_exit = False
        self._active, self._authorized = False, False
        self._old_token = None
        if _ACTIVE is self:
            _ACTIVE = None


def _prepare_on_owner(owner, *, request, recovery_bytes, options, live_window,
        transport_deadline_ns, work, current):
    global _ACTIVE

    from serverware import app as application

    _request(request, recovery_bytes)
    if _ACTIVE is not None or owner._activation_permission is not None:
        _deny("recovery requires a non-overlapping fresh actor scope", 409)
    current()
    work.charge(input_bytes=4 * len(recovery_bytes),
        json_nodes=4 * contract.permission.framing._JSON_LIMITS.max_total_nodes)
    try:
        payload = contract.parse_request(recovery_bytes, options=options)
    except (ValueError, RecursionError):
        _deny("recovery request is not closed bounded data", 400)
    work.prepare_scan(payload)
    owner_scope = execution._scope_on_owner(owner, live_window=live_window,
        transport_deadline_ns=transport_deadline_ns, work=work)

    def base_current():
        current()
        return owner_scope.current()

    policy, policy_pin = _policy(application, work)
    if request.headers.getlist("origin") != [policy_pin[1]]:
        _deny("recovery requires the configured exact origin", 403)
    permission._native(base_current, work,
        lambda: application._require_registration_execution_session_csrf(request))
    token = request.cookies.get(application.OIDC_SESSION_COOKIE_NAME)
    if type(token) is not str or not authentication.oidc_session_token_is_well_formed(token):
        _deny("recovery requires original old-token possession", 401)
    old_token = token.encode("ascii")
    if len(old_token) != 64:
        _deny("recovery requires original old-token possession", 401)
    request_pin = (tuple(request.headers.getlist("origin")),
        tuple(request.headers.getlist(application.CSRF_HEADER_NAME)),
        request.cookies.get(application.CSRF_COOKIE_NAME), token,
        request.method, request.scope.get("path"), request.scope.get("query_string", b""))
    # The historical loader must see already-held request and configuration
    # representations before its first body read, not only in a later sum.
    scope_originals = tuple(owner_scope.common[name] for name in (
        "authorization_enrollment_bytes", "current_root_enrollment_bytes",
        "grant_enrollment_bytes", "configuration_digest"))
    held_request_bytes = 4 * _owned_capture_bytes((recovery_bytes, payload,
        policy, policy_pin, request_pin, old_token, scope_originals), work)
    # Reserve the fixed key representations without inspecting key objects.
    held_request_bytes += 8 * (3 * 32 + startup.MAX_PRIVATE_KEY_BYTES)
    target = history._inspect_on_owner(owner, local_digest=payload["localDigest"],
        old_token_bytes=old_token, live_window=owner_scope.window,
        transport_deadline_ns=owner_scope.deadline_ns, work=work, current=base_current,
        _additional_original_bytes=held_request_bytes)
    if type(target) is not history._RecoveryTarget:
        _deny("recovery historical target is unavailable", 503)
    execution.clock._validate(target.live_window)
    if (target.live_window[:3] != owner_scope.window[:3]
            or target.live_window[3] > owner_scope.window[3]
            or target.live_window[4] > owner_scope.window[4]
            or target.live_window[5] > owner_scope.window[5]
            or target.live_window[6] > owner_scope.window[6]
            or type(target.deadline_ns) is not int
            or not 0 < target.deadline_ns <= owner_scope.deadline_ns):
        _deny("recovery historical allowance widened", 503)
    scope = _ActorScope(_CONSTRUCTION, application=application, owner=owner,
        request=request, original=recovery_bytes, payload=payload, work=work,
        current=current, owner_scope=owner_scope, target=target, policy=policy,
        policy_pin=policy_pin, request_pin=request_pin, old_token=old_token)
    _ACTIVE = scope
    try:
        rbac_pin, session_pin, credential, roles, trust_pin = scope._read_current()
        scope._rbac_pin, scope._session_pin, scope._trust_pin = rbac_pin, session_pin, trust_pin
        scope._credential, scope._count, scope._roles = credential, credential[2], roles
        work.prepare_encoding(scope._binding)
        work.charge(hashes=1)
        scope._payload_digest = scope._native(
            lambda: application._control_plane_payload_digest(scope._binding))
        scope.current()
        return scope
    except BaseException:
        scope._close()
        raise


def _options(request, *, recovery_bytes):
    """Fresh target and current policy checks; no assertion or permission."""
    from serverware import app as application
    from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork

    _request(request, recovery_bytes)
    work = _ValidationWork(QueryReadValidationLimits())
    with _startup_scope():
        owner, window = execution._open_on_work(work)
        opening = execution._scope_on_owner(owner, live_window=window,
            transport_deadline_ns=window[4], work=work)
        scope = None
        try:
            with application.trust_bundle_lock(exclusive=False):
                scope = _prepare_on_owner(owner, request=request, recovery_bytes=recovery_bytes,
                    options=True, live_window=opening.window, transport_deadline_ns=opening.deadline_ns,
                    work=work, current=opening.current)
                scope.current()
                work.charge(hashes=3)
                result = scope._native(lambda: pending._options(application,
                    scope._binding, scope._payload_digest))
                if type(result) is not dict or result.get("schema") != pending.OPTIONS_SCHEMA:
                    _deny("recovery options shape changed", 503)
                work.prepare_copy(result)
                result = {**result, "schema": contract.OPTIONS_SCHEMA}
                scope.current()
            # Trust-lock cleanup does not discard the narrower target/session
            # deadlines. No new DB/trust read or historical admission occurs.
            scope._guard()
        finally:
            if scope is not None:
                scope._close()
        return result


@contextmanager
def _authorize_on_owner(owner, *, request, recovery_bytes, live_window,
        transport_deadline_ns, work, current):
    """Private recovery acquisition consumes this live context, never its result.

    Its source-owned one-use latch is never reset, including on failure or exit.
    A separately selected source-owned terminal may retain genuine originals;
    this actor itself never remains live after cleanup or carries a token out.
    A fresh assertion can claim a challenge and advance its authenticator CAS;
    rejection is not a claim that those permission-side effects were absent.
    """
    from serverware import app as application

    _request(request, recovery_bytes)
    current()
    scope = None
    completed = False
    with _startup_scope():
        try:
            with application.trust_bundle_lock(exclusive=False):
                scope = _prepare_on_owner(owner, request=request, recovery_bytes=recovery_bytes,
                    options=False, live_window=live_window, transport_deadline_ns=transport_deadline_ns,
                    work=work, current=current)
                scope.current()
                work.charge(hashes=4)
                scope._count = scope._native(lambda: pending._assertion(application,
                    scope._payload, scope._binding, scope._credential, scope._payload_digest))
                scope.current()
                identity = application.AdminIdentity(scope._binding["userId"],
                    scope._roles, "webauthn-recovery")
                scope._native(lambda: application._require_control_plane_two_person(
                    action=contract.ACTION, resource_id=scope._binding["challengeId"],
                    payload_digest=scope._payload_digest, mfa=scope._payload.get("mfa"),
                    identity=identity, request=scope._binding))
                scope.current()
                scope._authorized = True
                yield scope
                scope.current()
                completed = True
            scope._guard()
        finally:
            if scope is not None:
                scope._close()
    # Reaching this point proves normal trust-context exit, the final guard,
    # actor cleanup and startup-lock release. A finally-closed actor alone
    # never proves any of those successful suffixes.
    if scope is None or completed is not True:
        _deny("recovery actor lacks its completed original context", 503)
    scope._normal_exit = True
