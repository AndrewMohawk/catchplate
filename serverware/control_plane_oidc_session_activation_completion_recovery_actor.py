"""Fresh pre-intent actor under independently selected completion-only scope.

Historical target proof and current user permission are different checks. This
context supplies neither a completion result nor permission to execute SQL,
recover a token, resume a spent attempt or set a browser cookie. The ordinary
intent-stage actor and its exact-type acquisition entrypoint stay unchanged.
"""
from __future__ import annotations

from contextlib import contextmanager
import os
import threading
import time

from serverware import control_plane_oidc_session_activation_recovery_actor as actor
from serverware import control_plane_oidc_session_activation_completion_recovery_bootstrap as configured
from serverware import control_plane_oidc_session_activation_completion_recovery_history as history


execution, startup, permission = actor.execution, actor.startup, actor.permission
contract, pending = actor.contract, actor.pending
_CONSTRUCTION = object()
_ACTIVE = None
INTENT_SCHEMA = "serverware.oidcSessionActivationCompletionRecoveryIntent/v1"
OPTIONS_SCHEMA = "serverware.oidcSessionActivationCompletionRecoveryOptions/v1"


def _configuration(owner, profile):
    parent = owner._material
    recovery = None if parent is None else parent.completion_recovery
    if (type(profile) is not str or profile not in ("activation", "consume")
            or type(recovery) is not configured._CompletionRecoveryMaterial):
        actor._deny("completion recovery is not independently configured", 503)
    selected = recovery.activation if profile == "activation" else recovery.consume
    if type(selected) is not configured._CompletionRecoveryScope:
        actor._deny("completion recovery profile is disabled", 503)
    return parent, recovery, selected


def _configuration_pin(profile, scope):
    return (profile, scope.endpoint, scope.packet_digest, scope.authorization_digest,
        scope.current_pending)


def _target_pin(target, work):
    return (actor._snapshot(target.subject, work), target.activation_authorization_digest,
        target.old_token_digest, target.new_token_digest, target.credential_record_id,
        target.challenge_id, target.original_bytes, target.original_reservation_bytes)


class _CompletionActorScope(actor._ActorScope):
    """Distinct exact type; existing token acquisition cannot accept it."""

    __slots__ = ("_profile", "_parent", "_recovery", "_configuration", "_configuration_pin",
        "_target_seal", "_completion_recovery_spent", "_completion_receiving_current")

    def __init__(self, construction, *, application, owner, request, original,
            payload, work, current, owner_scope, target, policy, policy_pin,
            request_pin, old_token, profile, parent, recovery, configuration):
        if (construction is not _CONSTRUCTION
                or type(target) is not history._CompletionRecoveryTarget):
            actor._deny("completion recovery scope is privately constructed", 503)
        self._application, self._owner, self._request = application, owner, request
        self._original, self._payload, self._work = original, payload, work
        self._source_current, self._owner_scope = current, owner_scope
        self._target = self._target_seal = target
        self._policy, self._policy_pin, self._request_pin = policy, policy_pin, request_pin
        self._old_token = old_token
        self._profile, self._parent, self._recovery = profile, parent, recovery
        self._configuration = configuration
        self._configuration_pin = _configuration_pin(profile, configuration)
        self._target_pin = _target_pin(target, work)
        # Shape projection is not evidence: the inspector above genuinely
        # admitted both historical signatures and the actual old possession.
        binding = contract.request_binding(target.subject,
            activation_authorization_digest=target.activation_authorization_digest,
            old_token_digest=target.old_token_digest)
        sequence, head, fence = configuration.current_pending
        self._binding = {**binding, "schema": INTENT_SCHEMA,
            "completionProfile": profile, "activationChallengeId": target.challenge_id,
            "completionAuthorizationDigest": configuration.authorization_digest,
            "completionPacketDigest": configuration.packet_digest,
            "completionPendingSequence": sequence, "completionPendingHeadDigest": head,
            "completionFence": fence}
        self._binding_pin = actor._snapshot(self._binding, work)
        self._payload_digest = None
        self._credential, self._count, self._roles = None, None, None
        self._rbac_pin, self._session_pin, self._trust_pin = None, None, None
        self._window = target.live_window
        self._bound = min(target.deadline_ns, owner_scope.deadline_ns)
        self._epoch, self._monotonic = self._window[0], self._window[2]
        self._pid, self._thread = os.getpid(), threading.get_ident()
        self._active, self._authorized, self._normal_exit = True, False, False
        # Never become an intent-stage acquisition, including by inheritance.
        self._recovery_acquisition_spent = True
        self._completion_recovery_spent = False
        self._completion_receiving_current = None

    def _current_target(self):
        target = self._target
        return (target.subject, target.credential_record_id,
            target.old_token_digest, target.new_token_digest)

    def _guard(self):
        work, application, target = self._work, self._application, self._target
        execution.capture._SharedLedger(work)
        if (type(self) is not _CompletionActorScope or self._active is not True
                or os.getpid() != self._pid or threading.get_ident() != self._thread
                or _ACTIVE is not self or actor._ACTIVE is not None
                or self._owner._activation_permission is not None
                or startup._owner is not self._owner or target is not self._target_seal
                or getattr(self._request.state, actor.ORIGINAL_STATE_NAME, None) is not self._original):
            actor._deny("completion recovery actor is no longer live", 503)
        parent, recovery, selected = _configuration(self._owner, self._profile)
        if (parent is not self._parent or recovery is not self._recovery
                or selected is not self._configuration
                or _configuration_pin(self._profile, selected) != self._configuration_pin):
            actor._deny("completion recovery original configuration changed", 503)
        self._source_current()
        self._owner_scope.current()
        epoch = target.live()
        monotonic = execution.production._callback(work, time.monotonic_ns)
        if (type(epoch) is not int or type(monotonic) is not int
                or epoch < self._epoch or monotonic < self._monotonic
                or epoch >= self._window[3] or monotonic >= self._bound):
            actor._deny("completion recovery original allowance expired or reversed", 503)
        self._epoch, self._monotonic = epoch, monotonic
        _policy, policy_pin = actor._policy(application, work)
        request_pin = (tuple(self._request.headers.getlist("origin")),
            tuple(self._request.headers.getlist(application.CSRF_HEADER_NAME)),
            self._request.cookies.get(application.CSRF_COOKIE_NAME),
            self._request.cookies.get(application.OIDC_SESSION_COOKIE_NAME),
            self._request.method, self._request.scope.get("path"),
            self._request.scope.get("query_string", b""))
        if (policy_pin != self._policy_pin or request_pin != self._request_pin
                or _target_pin(target, work) != self._target_pin
                or actor._snapshot(self._binding, work) != self._binding_pin
                or actor._snapshot(self._policy, work) != self._policy_pin[0]):
            actor._deny("completion recovery original target, request or policy changed", 403)
        return epoch

    def _close(self):
        global _ACTIVE

        self._normal_exit = False
        self._active, self._authorized = False, False
        self._old_token = None
        self._completion_receiving_current = None
        if _ACTIVE is self:
            _ACTIVE = None


def _prepare_on_owner(owner, *, profile, request, recovery_bytes, options,
        live_window, transport_deadline_ns, work, current):
    global _ACTIVE

    from serverware import app as application

    actor._request(request, recovery_bytes)
    if (type(owner) is not startup._EnrollmentOwner or _ACTIVE is not None
            or actor._ACTIVE is not None or owner._activation_permission is not None):
        actor._deny("completion recovery requires a non-overlapping actual owner", 409)
    current()
    parent, recovery, configuration = _configuration(owner, profile)
    configuration_pin = _configuration_pin(profile, configuration)
    work.charge(input_bytes=4 * len(recovery_bytes),
        json_nodes=4 * contract.permission.framing._JSON_LIMITS.max_total_nodes)
    try:
        payload = contract.parse_request(recovery_bytes, options=options)
    except (ValueError, RecursionError):
        actor._deny("completion recovery request is not closed bounded data", 400)
    work.prepare_scan(payload)
    owner_scope = execution._scope_on_owner(owner, live_window=live_window,
        transport_deadline_ns=transport_deadline_ns, work=work)

    def base_current():
        current()
        observed_parent, observed_recovery, observed_configuration = _configuration(owner, profile)
        if (observed_parent is not parent or observed_recovery is not recovery
                or observed_configuration is not configuration
                or _configuration_pin(profile, configuration) != configuration_pin):
            actor._deny("completion recovery configuration changed during target admission", 503)
        return owner_scope.current()

    policy, policy_pin = actor._policy(application, work)
    if request.headers.getlist("origin") != [policy_pin[1]]:
        actor._deny("completion recovery requires the configured exact origin", 403)
    permission._native(base_current, work,
        lambda: application._require_registration_execution_session_csrf(request))
    token = request.cookies.get(application.OIDC_SESSION_COOKIE_NAME)
    if type(token) is not str or not actor.authentication.oidc_session_token_is_well_formed(token):
        actor._deny("completion recovery requires original old-token possession", 401)
    old_token = token.encode("ascii")
    if len(old_token) != 64:
        actor._deny("completion recovery requires original old-token possession", 401)
    request_pin = (tuple(request.headers.getlist("origin")),
        tuple(request.headers.getlist(application.CSRF_HEADER_NAME)),
        request.cookies.get(application.CSRF_COOKIE_NAME), token, request.method,
        request.scope.get("path"), request.scope.get("query_string", b""))
    scope_originals = tuple(owner_scope.common[name] for name in (
        "authorization_enrollment_bytes", "current_root_enrollment_bytes",
        "grant_enrollment_bytes", "configuration_digest"))
    held_bytes = 4 * actor._owned_capture_bytes((recovery_bytes, payload, policy,
        policy_pin, request_pin, old_token, scope_originals, configuration_pin), work)
    held_bytes += 8 * (3 * 32 + startup.MAX_PRIVATE_KEY_BYTES)
    target = history._inspect_on_owner(owner, local_digest=payload["localDigest"],
        old_token_bytes=old_token, live_window=owner_scope.window,
        transport_deadline_ns=owner_scope.deadline_ns, work=work, current=base_current,
        _additional_original_bytes=held_bytes)
    if type(target) is not history._CompletionRecoveryTarget:
        actor._deny("completion recovery original target is unavailable", 503)
    window = execution.clock._validate(target.live_window)
    if (window[:3] != owner_scope.window[:3]
            or any(new > old for new, old in zip(window[3:], owner_scope.window[3:]))
            or type(target.deadline_ns) is not int
            or not 0 < target.deadline_ns <= owner_scope.deadline_ns):
        actor._deny("completion recovery historical allowance widened", 503)
    if profile == "activation" and target.activation_authorization_digest != configuration.authorization_digest:
        actor._deny("completion recovery target differs from independent activation authorization", 403)
    scope = _CompletionActorScope(_CONSTRUCTION, application=application, owner=owner,
        request=request, original=recovery_bytes, payload=payload, work=work,
        current=current, owner_scope=owner_scope, target=target, policy=policy,
        policy_pin=policy_pin, request_pin=request_pin, old_token=old_token,
        profile=profile, parent=parent, recovery=recovery, configuration=configuration)
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


def _options_on_owner(owner, *, profile, request, recovery_bytes, live_window,
        transport_deadline_ns, work, current):
    """Actual bounded challenge only; no completion or assertion authority."""
    from serverware import app as application

    scope = None
    with actor._startup_scope():
        try:
            with application.trust_bundle_lock(exclusive=False):
                scope = _prepare_on_owner(owner, profile=profile, request=request,
                    recovery_bytes=recovery_bytes, options=True, live_window=live_window,
                    transport_deadline_ns=transport_deadline_ns, work=work, current=current)
                scope.current()
                work.charge(hashes=3)
                result = scope._native(lambda: pending._options(application,
                    scope._binding, scope._payload_digest))
                if type(result) is not dict or result.get("schema") != pending.OPTIONS_SCHEMA:
                    actor._deny("completion recovery options shape changed", 503)
                work.prepare_copy(result)
                result = {**result, "schema": OPTIONS_SCHEMA, "completionProfile": profile}
                scope.current()
            scope._guard()
        finally:
            if scope is not None:
                scope._close()
    return result


@contextmanager
def _authorize_on_owner(owner, *, profile, request, recovery_bytes, live_window,
        transport_deadline_ns, work, current):
    """One fresh actor; original control admission must precede future effects."""
    from serverware import app as application

    actor._request(request, recovery_bytes)
    current()
    scope, completed = None, False
    with actor._startup_scope():
        try:
            with application.trust_bundle_lock(exclusive=False):
                scope = _prepare_on_owner(owner, profile=profile, request=request,
                    recovery_bytes=recovery_bytes, options=False, live_window=live_window,
                    transport_deadline_ns=transport_deadline_ns, work=work, current=current)
                scope.current()
                work.charge(hashes=4)
                scope._count = scope._native(lambda: pending._assertion(application,
                    scope._payload, scope._binding, scope._credential, scope._payload_digest))
                scope.current()
                identity = application.AdminIdentity(scope._binding["userId"],
                    scope._roles, "webauthn-completion-recovery")
                scope._native(lambda: application._require_control_plane_two_person(
                    action=contract.ACTION, resource_id=scope._binding["challengeId"],
                    payload_digest=scope._payload_digest, mfa=scope._payload.get("mfa"),
                    identity=identity, request=scope._binding))
                scope.current()
                scope._authorized = True
                yield scope
                scope.current()
                if scope._completion_receiving_current is not None:
                    scope._completion_receiving_current()
                completed = True
            scope._guard()
            # A genuine receiving child is checked separately, never from
            # current()/the ancestor it calls. Keep it through normal trust
            # cleanup without creating an actor/receiver guard cycle.
            if scope._completion_receiving_current is not None:
                scope._completion_receiving_current()
        finally:
            if scope is not None:
                scope._close()
    if scope is None or completed is not True:
        actor._deny("completion recovery lacks its completed original cleanup", 503)
    scope._normal_exit = True
