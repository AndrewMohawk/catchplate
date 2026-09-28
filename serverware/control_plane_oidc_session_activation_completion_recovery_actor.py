"""Fresh purpose-bound actor under independently selected completion scope.

Historical target proof and current user permission are different checks. This
context alone supplies no completion result, release grant, SQL permission,
token, retry or browser cookie. A release action requires its own fresh purpose,
not a broadened preparation permission or closed actor. The ordinary
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
from serverware import control_plane_oidc_session_activation_completion_recovery_consume_selection as consume_selection


execution, startup, permission = actor.execution, actor.startup, actor.permission
contract, pending = actor.contract, actor.pending
_CONSTRUCTION = object()
_ACTIVE = None
INTENT_SCHEMA = "serverware.oidcSessionActivationCompletionRecoveryIntent/v1"
OPTIONS_SCHEMA = "serverware.oidcSessionActivationCompletionRecoveryOptions/v1"
RELEASE_INTENT_SCHEMA = "serverware.oidcSessionActivationCompletionRecoveryReleaseIntent/v1"
RELEASE_OPTIONS_SCHEMA = "serverware.oidcSessionActivationCompletionRecoveryReleaseOptions/v1"
RELEASE_PATH = "/api/auth/session/activation/consume/completion/recovery/release-proof"
DELIVERY_SCHEMA = "serverware.oidcSessionActivationCompletionRecoveryDeliveryIntent/v1"
DELIVERY_OPTIONS_SCHEMA = "serverware.oidcSessionActivationCompletionRecoveryDeliveryOptions/v1"
DELIVERY_PATH = "/api/auth/session/activation/consume/completion/recovery/release"
RETAINED_DELIVERY_SCHEMA = "serverware.oidcSessionActivationCompletionRecoveryRetainedDeliveryIntent/v1"
RETAINED_DELIVERY_OPTIONS_SCHEMA = "serverware.oidcSessionActivationCompletionRecoveryRetainedDeliveryOptions/v1"
RETAINED_DELIVERY_PATH = "/api/auth/session/activation/consume/completion/recovery/retained-release"
CONSUME_SCHEMA = "serverware.oidcSessionActivationCompletionRecoveryConsumeIntent/v1"
CONSUME_OPTIONS_SCHEMA = "serverware.oidcSessionActivationCompletionRecoveryConsumeOptions/v1"
CONSUME_PATH = "/api/auth/session/activation/completion/recovery/consume"
# These two purposes authenticate retained consume originals under independently
# selected authority. Selection is evidence, not permission to release a token.
_CONSUME_SELECTION_PURPOSES = frozenset({"completion", "release-intent-proof"})


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


def _historical_configuration(target, profile, selected_consume=None):
    authority = target.authority
    if type(authority) is not history.historical._SelectedActivationHistory:
        actor._deny("completion recovery lacks its genuine historical authority", 503)
    if selected_consume is not None:
        if (profile != "consume" or type(selected_consume) is not consume_selection._ConsumeRecoverySelection
                or selected_consume.target is not target):
            actor._deny("consume completion changed its independent original selection", 503)
        authority = selected_consume.authority
    recovery = authority.completion_recovery
    if type(recovery) is not configured._CompletionRecoveryMaterial:
        actor._deny("completion recovery lacks independently archived completion pins", 503)
    selected = recovery.activation if profile == "activation" else recovery.consume
    if type(selected) is not configured._CompletionRecoveryScope:
        actor._deny("completion recovery historical profile is disabled", 503)
    return selected


def _selected_configuration(target, profile, current, selected_consume=None):
    """Historical expectations with only the currently enabled transport.

    These are the existing cold scope fields, not proof of an outcome. The
    target retains genuine archive admission; later controls re-admit actual
    signatures before any durable claim or network exchange.
    """
    target.live()
    selected = _historical_configuration(target, profile, selected_consume)
    if selected is current:
        # Preserve exact identity for the unchanged no-history live lane.
        return current
    return configured._CompletionRecoveryScope(current.endpoint, selected.packet_digest,
        selected.authorization_digest, selected.current_pending)


def _current_effect_authority(owner, parent, target):
    """Exact cold current selection, never coincident keys or matching fields."""
    selected = target.authority
    return (type(selected) is history.historical._SelectedActivationHistory
            and selected.configuration_payload is parent.configuration_payload
            and selected.configuration_digest == parent.configuration_digest
            and selected.root_public_key is owner._binding.runtime_root_public_key
            and all(getattr(selected, name) is getattr(parent, name) for name in (
                "activation_execution", "activation_planning", "consume_execution",
                "release_intent", "completion_recovery")))


def _require_current_effect_authority(owner, parent, target):
    """Proof preparation history cannot authorize grant or credential release."""
    if not _current_effect_authority(owner, parent, target):
        actor._deny("historical completion does not authorize a current effect continuation", 503)


def _require_proof_effect_authority(owner, parent, target, selected_consume, work):
    """Require the explicit current-root bridge before a historical ceremony.

    This cold configuration check is not proof issuance. The actual input,
    producer and receiver paths still authenticate all R0/R1/R2 originals and
    preserve the original delivery key, state and expiry before any output.
    """
    from serverware import control_plane_oidc_session_activation_release_proof_acquisition_bootstrap as acquisition

    consume_selection._require_selection(selected_consume, owner=owner, target=target, work=work)
    selected = selected_consume.authority
    if (_current_effect_authority(owner, parent, target)
            and selected.configuration_payload is parent.configuration_payload
            and selected.root_public_key is owner._binding.runtime_root_public_key
            and selected.consume_execution is parent.consume_execution
            and selected.completion_recovery is parent.completion_recovery):
        return
    setup, planning = parent.release_proof_acquisition, parent.activation_planning
    if (type(setup) is not acquisition._ReleaseProofAcquisitionMaterial
            or planning is None or type(setup.current_activation_planner_bytes) is not bytes):
        actor._deny("historical proof preparation requires its explicit current-root bridge", 503)
    history.bookkeeping._same_bytes(setup.current_activation_planner_bytes,
        planning.planner_bootstrap_bytes, work, "historical proof exact current planner")


def _consume_effect_configuration(owner, parent, target, now):
    """Select admitted cold data; the real caller must reverify originals.

    Only fresh consumption has a versioned old/current bridge. This helper is
    not permission for proof, grant or credential-release recovery.
    """
    from serverware import control_plane_oidc_session_activation_consume_input_acquisition as acquisition

    if (owner._material is not parent or parent.consume_execution is None
            or parent.activation_execution is None or parent.activation_planning is None):
        actor._deny("fresh consume requires actual current execution configuration", 503)
    config, original = acquisition._configuration_on_target(owner, target)
    interval = config.bridge_interval
    if config.historical_scope is not None and (
            type(interval) is not tuple or len(interval) != 2
            or any(type(value) is not int or value <= 0 for value in interval)
            or not interval[0] < interval[1]
            or interval[0] > now + target.live_window[6] or now >= interval[1]):
        actor._deny("fresh consume historical bridge is not currently authorized", 503)
    return config, original, (config.endpoint, config.issuer_policy_bytes,
        config.historical_scope, interval)


def _target_pin(target, work):
    return (actor._snapshot(target.subject, work), target.activation_authorization_digest,
        target.old_token_digest, target.new_token_digest, target.credential_record_id,
        target.challenge_id, target.original_bytes, target.original_reservation_bytes,
        target.authority)


class _CompletionActorScope(actor._ActorScope):
    """Distinct exact type; existing token acquisition cannot accept it."""

    __slots__ = ("_profile", "_parent", "_recovery", "_configuration", "_configuration_pin",
        "_target_seal", "_completion_recovery_spent", "_completion_receiving_current",
        "_purpose", "_purpose_pin", "_future_original_bytes", "_future_original_bytes_pin",
        "_current_configuration", "_current_configuration_pin", "_configuration_seal",
        "_consume_configuration", "_consume_planner_original", "_consume_configuration_pin",
        "_consume_recovery_selection", "_consume_recovery_selection_pin")

    def __init__(self, construction, *, application, owner, request, original,
            payload, work, current, owner_scope, target, policy, policy_pin,
            request_pin, old_token, profile, parent, recovery, configuration,
            current_configuration, purpose, future_original_bytes, selected_consume):
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
        self._purpose = self._purpose_pin = purpose
        self._future_original_bytes = self._future_original_bytes_pin = future_original_bytes
        self._current_configuration = current_configuration
        self._current_configuration_pin = _configuration_pin(profile, current_configuration)
        self._configuration = self._configuration_seal = configuration
        self._configuration_pin = _configuration_pin(profile, configuration)
        if profile == "consume" and purpose in _CONSUME_SELECTION_PURPOSES:
            consume_selection._require_selection(selected_consume, owner=owner, target=target, work=work)
        elif selected_consume is not None:
            actor._deny("consume history selection cannot authorize another effect purpose", 503)
        self._consume_recovery_selection = self._consume_recovery_selection_pin = selected_consume
        self._consume_configuration = self._consume_planner_original = self._consume_configuration_pin = None
        if purpose == "consume":
            (self._consume_configuration, self._consume_planner_original,
                self._consume_configuration_pin) = _consume_effect_configuration(owner, parent, target, target.live())
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
        if purpose == "release-intent-proof":
            # Distinct WebAuthn/approval payload: completion-only permission
            # must never authorize a fresh signature or private proof request.
            self._binding["schema"] = RELEASE_INTENT_SCHEMA
            self._binding["recoveryPurpose"] = purpose
        elif purpose == "release":
            # A separate fresh assertion and approval select release. Neither
            # completion nor intent/proof preparation can authorize this use.
            self._binding["schema"] = DELIVERY_SCHEMA
            self._binding["recoveryPurpose"] = purpose
        elif purpose == "retained-release":
            # Retained-outcome authority is a separate fresh action, never a
            # fallback selected by a LIVE failure or preparation permission.
            self._binding["schema"] = RETAINED_DELIVERY_SCHEMA
            self._binding["recoveryPurpose"] = purpose
        elif purpose == "consume":
            # Fresh consume continuation from acknowledged activation is not
            # activation execution permission or a completion-only assertion.
            self._binding["schema"] = CONSUME_SCHEMA
            self._binding["recoveryPurpose"] = purpose
        self._binding_pin = actor._snapshot(self._binding, work)
        self._payload_digest = None
        self._credential, self._count, self._roles = None, None, None
        self._rbac_pin, self._session_pin, self._trust_pin = None, None, None
        self._window = target.live_window if selected_consume is None else selected_consume.window
        self._bound = min(target.deadline_ns, owner_scope.deadline_ns, self._window[4],
            target.deadline_ns if selected_consume is None else selected_consume.deadline_ns)
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
                or self._purpose is not self._purpose_pin
                or self._future_original_bytes is not self._future_original_bytes_pin
                or self._consume_recovery_selection is not self._consume_recovery_selection_pin
                or getattr(self._request.state, actor.ORIGINAL_STATE_NAME, None) is not self._original):
            actor._deny("completion recovery actor is no longer live", 503)
        parent, recovery, current_configuration = _configuration(self._owner, self._profile)
        selected_consume = self._consume_recovery_selection
        if selected_consume is not None:
            consume_selection._require_selection(selected_consume,
                owner=self._owner, target=target, work=work)
        historical = _historical_configuration(target, self._profile, selected_consume)
        expected = (self._profile, current_configuration.endpoint, historical.packet_digest,
            historical.authorization_digest, historical.current_pending)
        if (parent is not self._parent or recovery is not self._recovery
                or current_configuration is not self._current_configuration
                or _configuration_pin(self._profile, current_configuration) != self._current_configuration_pin
                or self._configuration is not self._configuration_seal
                or _configuration_pin(self._profile, self._configuration) != self._configuration_pin
                or expected != self._configuration_pin):
            actor._deny("completion recovery original configuration changed", 503)
        self._source_current()
        self._owner_scope.current()
        epoch = target.live()
        if selected_consume is not None:
            selected_epoch = selected_consume.live()
            if type(selected_epoch) is not int or selected_epoch < epoch:
                actor._deny("consume completion selection clocks reversed", 503)
            epoch = selected_epoch
        monotonic = execution.production._callback(work, time.monotonic_ns)
        if (type(epoch) is not int or type(monotonic) is not int
                or epoch < self._epoch or monotonic < self._monotonic
                or epoch >= self._window[3] or monotonic >= self._bound):
            actor._deny("completion recovery original allowance expired or reversed", 503)
        self._epoch, self._monotonic = epoch, monotonic
        if self._purpose == "consume":
            config, original, pin = _consume_effect_configuration(self._owner, parent, target, epoch)
            if (config is not self._consume_configuration or original is not self._consume_planner_original
                    or pin != self._consume_configuration_pin):
                actor._deny("fresh consume changed its independently selected input authority", 503)
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
        live_window, transport_deadline_ns, work, current, _purpose="completion",
        _additional_original_bytes=0):
    global _ACTIVE

    from serverware import app as application

    actor._request(request, recovery_bytes)
    if (type(_purpose) is not str
            or _purpose not in ("completion", "release-intent-proof", "release", "retained-release", "consume")
            or type(_additional_original_bytes) is not int
            or not 0 <= _additional_original_bytes < history.MAX_ORIGINAL_BYTES):
        actor._deny("completion recovery purpose or held capacity differs", 503)
    if _purpose in ("release-intent-proof", "release", "retained-release"):
        if _purpose == "release-intent-proof":
            action_path = RELEASE_PATH
        elif _purpose == "release":
            action_path = DELIVERY_PATH
        else:
            action_path = RETAINED_DELIVERY_PATH
        path = action_path + "/options" if options else action_path
        if (profile != "consume" or request.method != "POST"
                or request.scope.get("path") != path
                or request.scope.get("query_string", b"") != b""):
            actor._deny("completion recovery purpose requires its distinct fixed action", 400)
    elif _purpose == "consume":
        path = CONSUME_PATH + "/options" if options else CONSUME_PATH
        if (profile != "activation" or request.method != "POST"
                or request.scope.get("path") != path
                or request.scope.get("query_string", b"") != b""):
            actor._deny("fresh consume requires its fixed activation-profile action", 400)
    if (type(owner) is not startup._EnrollmentOwner or _ACTIVE is not None
            or actor._ACTIVE is not None or owner._activation_permission is not None):
        actor._deny("completion recovery requires a non-overlapping actual owner", 409)
    current()
    parent, recovery, current_configuration = _configuration(owner, profile)
    if (_purpose in ("release-intent-proof", "release", "retained-release")
            and (parent.release_intent is None or parent.release_proof is None)):
        actor._deny("completion release purpose lacks independent cold intent/proof configuration", 503)
    current_configuration_pin = _configuration_pin(profile, current_configuration)
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
                or observed_configuration is not current_configuration
                or _configuration_pin(profile, current_configuration) != current_configuration_pin):
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
        policy_pin, request_pin, old_token, scope_originals, current_configuration_pin), work)
    # The effective historical pin tuple and current endpoint are retained
    # separately. Reserve their bounded metadata before historical body one.
    held_bytes += 8 * (3 * 32 + startup.MAX_PRIVATE_KEY_BYTES) + 16 * 1024
    target = history._inspect_on_owner(owner, local_digest=payload["localDigest"],
        old_token_bytes=old_token, live_window=owner_scope.window,
        transport_deadline_ns=owner_scope.deadline_ns, work=work, current=base_current,
        _additional_original_bytes=held_bytes + _additional_original_bytes)
    if type(target) is not history._CompletionRecoveryTarget:
        actor._deny("completion recovery original target is unavailable", 503)
    selected_consume = None
    if profile == "consume" and _purpose in _CONSUME_SELECTION_PURPOSES:
        # The target proves R0 activation/possession. Independently authenticate
        # retained R1 consume controls before binding the new human ceremony.
        # Target accounting already includes held actor and future captures.
        selected_consume = consume_selection._select_on_owner(owner, target=target,
            live_window=target.live_window, transport_deadline_ns=target.deadline_ns,
            work=work, current=base_current, _additional_original_bytes=0)
        consume_selection._require_selection(selected_consume, owner=owner, target=target, work=work)
        selected_window = execution.clock._validate(selected_consume.window)
        if (selected_window[:3] != target.live_window[:3]
                or any(new > old for new, old in zip(selected_window[3:], target.live_window[3:]))
                or type(selected_consume.deadline_ns) is not int
                or not 0 < selected_consume.deadline_ns <= min(target.deadline_ns, selected_window[4])):
            actor._deny("consume completion selection widened the target allowance", 503)
    configuration = _selected_configuration(target, profile, current_configuration, selected_consume)
    if _purpose == "release-intent-proof":
        _require_proof_effect_authority(owner, parent, target, selected_consume, work)
    elif _purpose not in ("completion", "consume"):
        _require_current_effect_authority(owner, parent, target)
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
        profile=profile, parent=parent, recovery=recovery, configuration=configuration,
        current_configuration=current_configuration, purpose=_purpose,
        future_original_bytes=_additional_original_bytes, selected_consume=selected_consume)
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
        transport_deadline_ns, work, current, _purpose="completion"):
    """Actual bounded challenge only; no completion or assertion authority."""
    from serverware import app as application

    scope = None
    with actor._startup_scope():
        try:
            with application.trust_bundle_lock(exclusive=False):
                scope = _prepare_on_owner(owner, profile=profile, request=request,
                    recovery_bytes=recovery_bytes, options=True, live_window=live_window,
                    transport_deadline_ns=transport_deadline_ns, work=work, current=current,
                    _purpose=_purpose)
                scope.current()
                work.charge(hashes=3)
                result = scope._native(lambda: pending._options(application,
                    scope._binding, scope._payload_digest))
                if type(result) is not dict or result.get("schema") != pending.OPTIONS_SCHEMA:
                    actor._deny("completion recovery options shape changed", 503)
                work.prepare_copy(result)
                result = {**result, "schema": OPTIONS_SCHEMA, "completionProfile": profile}
                if _purpose == "release-intent-proof":
                    result["schema"] = RELEASE_OPTIONS_SCHEMA
                    result["recoveryPurpose"] = _purpose
                elif _purpose == "release":
                    result["schema"] = DELIVERY_OPTIONS_SCHEMA
                    result["recoveryPurpose"] = _purpose
                elif _purpose == "retained-release":
                    result["schema"] = RETAINED_DELIVERY_OPTIONS_SCHEMA
                    result["recoveryPurpose"] = _purpose
                elif _purpose == "consume":
                    result["schema"] = CONSUME_OPTIONS_SCHEMA
                    result["recoveryPurpose"] = _purpose
                scope.current()
            scope._guard()
        finally:
            if scope is not None:
                scope._close()
    return result


@contextmanager
def _authorize_on_owner(owner, *, profile, request, recovery_bytes, live_window,
        transport_deadline_ns, work, current, _purpose="completion",
        _additional_original_bytes=0):
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
                    transport_deadline_ns=transport_deadline_ns, work=work, current=current,
                    _purpose=_purpose, _additional_original_bytes=_additional_original_bytes)
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
