"""Fixed LIVE or RECOVERY receiving through current authentication and send.

This source-owned terminal is selected before final admission, not after a token
is returned. Only successful normal actor/owner cleanup permits its receiver to
continue against captured original ancestors. Preparation permission and closed
ordinary actor, input, proof and exchange guards are never reused.
"""
from __future__ import annotations

from datetime import datetime, timezone
import os
import threading
import time

from fastapi.responses import JSONResponse

from catchplate import auth
from catchplate import control_plane_oidc_session_activation_completion_recovery_actor as actors
from catchplate import control_plane_oidc_session_activation_completion_recovery_controls as controls_source
from catchplate import control_plane_oidc_session_activation_completion_recovery_intent_inputs as inputs_source
from catchplate import control_plane_oidc_session_activation_completion_recovery_intent as intent_source
from catchplate import control_plane_oidc_session_activation_completion_recovery_proof as proof_source
from catchplate import control_plane_oidc_session_activation_release_recovery_grant_acquisition_bootstrap as recovery_config
from catchplate import oidc_session_activation_release_recovery_grant_admission as recovery_grants
from catchplate.operator_oidc import oidc_session_cookie_attributes


actor, execution = actors.actor, actors.execution
permission, pending = actor.permission, actor.pending
POST_PATH = actors.DELIVERY_PATH
RETAINED_POST_PATH = actors.RETAINED_DELIVERY_PATH
POST_PATHS = frozenset({POST_PATH, RETAINED_POST_PATH})
RESPONSE_SCHEMA = "catchplate.oidcSessionActivationCompletionRecoveryDeliveryResponse/v1"
RETAINED_RESPONSE_SCHEMA = "catchplate.oidcSessionActivationCompletionRecoveryRetainedDeliveryResponse/v1"
PURPOSE = "release"
RETAINED_PURPOSE = "retained-release"
_SCOPE_KEY = "catchplate.oidc-session-activation.completion-recovery-final-delivery"
_HEADERS = {"Cache-Control": "no-store", "Pragma": "no-cache", "X-Content-Type-Options": "nosniff"}
_AUTH_RESERVATION = 256 * 1024
_PUBLIC_FIELDS = ("actor", "controls", "response", "inputs", "intent", "proof", "grants",
    "reconciliation_digest")


def _fail():
    raise execution.startup.EnrollmentStartupError("completion recovery release delivery is unavailable")


def _action(purpose):
    if type(purpose) is str and purpose == PURPOSE:
        return POST_PATH, RESPONSE_SCHEMA, "released"
    if type(purpose) is str and purpose == RETAINED_PURPOSE:
        return RETAINED_POST_PATH, RETAINED_RESPONSE_SCHEMA, "recovered"
    _fail()


class _StagedRecoveryResponse:
    """Same-call terminal only; no incoming token or success carrier API."""

    __slots__ = ("_active", "_actor", "_application", "_owner", "_owner_scope",
        "_source_current", "_target", "_request", "_asgi", "_original", "_payload",
        "_parent", "_binding", "_custody", "_config", "_config_pin", "_root", "_work",
        "_parent_lifetime", "_public", "_evidence_refs_pin", "_evidence_values_pin", "_cold_pin",
        "_old", "_pid", "_thread", "_seal", "_pins", "_limits", "_ceilings", "_metrics",
        "_window", "_bound", "_epoch", "_monotonic", "_parent_continuity", "_receiver",
        "_phase", "_response", "_body", "_cookie", "_session_expiry",
        "_purpose", "_path", "_schema", "_success_status", "_recovery_pin",
        "_current_config", "_current_config_pin", "_historical_config", "_historical_config_pin",
        "_consume_selection", "_consume_selection_seal")

    def __init__(self):
        _fail()

    def _evidence_refs(self):
        _scope, controls, _response, inputs, selected_intent, proof, _grants, _digest = self._public
        return (controls._seal, *(getattr(controls, name) for name in controls_source._SEALED_FIELDS),
            inputs._seal, *(getattr(inputs, name) for name in inputs_source._SEALED_FIELDS),
            selected_intent._seal, selected_intent.inputs, selected_intent.intent_bytes,
            selected_intent.intent_digest, selected_intent._interval, selected_intent._lifetime,
            selected_intent._records, selected_intent._key_identity,
            proof._seal, proof.intent, proof._lifetime, proof._originals)

    def _evidence_values(self):
        controls, inputs = self._public[1], self._public[3]
        if (type(controls.marker) is not dict
                or tuple(controls.marker) != controls_source.pending._MARKER_COLUMNS):
            _fail()
        return (tuple(controls.marker[name] for name in controls_source.pending._MARKER_COLUMNS),
            inputs_source._scope_pin(inputs.intent_scope, proof=False),
            inputs_source._scope_pin(inputs.proof_scope, proof=True),
            inputs_source._release_pin(inputs.expected_release))

    def _cold_refs(self):
        parent = self._parent
        inputs = self._public[3]
        intent_policy, proof_policy, setup = inputs.intent_policy, inputs.proof_policy, inputs.setup_policy
        consume = self._public[1].consume_authority
        evidence = (None,)
        if consume is not None:
            policy = consume.consume_execution
            evidence = (consume, consume.root_public_key, consume.configuration_payload,
                consume.configuration_digest, consume.generation, consume.runtime_role_identities,
                consume.authority_interval, consume.completion_recovery, policy,
                policy.current_root_enrollment_bytes, policy.authorization_enrollment_bytes,
                policy.grant_enrollment_bytes, policy.planner_public_key,
                policy.operation_public_key, policy.caller_public_key)
        if self._purpose == PURPOSE:
            handoff = parent.release_handoff
            selected = (handoff, handoff.client_id, handoff.client_identity_bytes, handoff.endpoint_bytes,
                parent.release_grant_acquisition, parent.release_grant_acquisition.endpoint)
        else:
            configured = parent.release_recovery_grant_acquisition
            if type(configured) is not recovery_config._RecoveryGrantAcquisitionMaterial:
                _fail()
            selected = (configured, configured.endpoint, configured.issuer_policy_bytes,
                configured.release_custody_bytes, configured.proof_enrollment_bytes,
                configured.intent_enrollment_bytes)
        return (*selected, *evidence,
            parent.release_intent, parent.release_proof, parent.release_proof_acquisition,
            intent_policy.enrollment_bytes, intent_policy.enrollment_digest, intent_policy.expected_scope_bytes,
            intent_policy.caller_public_key, intent_policy.forbidden_public_keys,
            proof_policy.enrollment_bytes, proof_policy.enrollment_digest, proof_policy.expected_scope_bytes,
            proof_policy.proof_public_key, proof_policy.forbidden_public_keys, proof_policy.endpoint,
            None if setup is None else setup.issuer_policy_bytes, None if setup is None else setup.endpoint,
            parent.activation_planning, parent.activation_planning.planner_bootstrap_bytes,
            self._owner._response_path, self._owner._response_pin)

    def _recovery_refs(self):
        active = self._active
        result = active._recovery_result
        if self._purpose == PURPOSE:
            if (result is not None or active._recovery_result_seal is not None
                    or active._stage_spent is not False or active._staged is not False):
                _fail()
            return (None, None, False, False)
        if (type(result) is not recovery_grants._RecoveryGrantMaterial
                or result is not active._recovery_result_seal
                or active._stage_spent is not True or active._staged is not True
                or any(raw is not held for raw, held in zip(active.grants,
                    (result.client_authorization_bytes, result.server_bootstrap_bytes, result.outcome_bytes)))):
            _fail()
        # The old admission guard belongs to acquisition/staging. Retain its
        # exact evidence identity, but never invoke it after actor cleanup.
        return (result, active._recovery_result_seal, True, True,
            result.client_authorization_bytes, result.server_bootstrap_bytes, result.outcome_bytes,
            result.client_material, result.issuer_policy_material, result.live_window,
            result.deadline_ns, result.live)

    def _identity(self):
        """Identity only: never call a receiving child or closed private guard."""
        from catchplate import control_plane_oidc_session_activation_completion_recovery_delivery as source

        active, scope, owner = self._active, self._actor, self._owner
        references = (active, scope, self._application, owner, self._owner_scope,
            self._source_current, self._target, self._request, self._asgi, self._original,
            self._payload, self._parent, self._binding, self._custody, self._config,
            self._root, self._work, self._parent_lifetime, self._public, self._old,
            self._purpose, self._path, self._schema, self._success_status,
            self._current_config, self._historical_config, self._consume_selection, self._consume_selection_seal)
        if (type(active) is not source._DeliveryAttempt or type(scope) is not actors._CompletionActorScope
                or os.getpid() != self._pid or threading.get_ident() != self._thread
                or type(self._seal) is not tuple or len(self._seal) != len(references)
                or any(value is not held for value, held in zip(references, self._seal))
                or execution.startup._owner is not owner
                or owner._material is not self._parent or owner._binding is not self._binding
                or owner._custody is not self._custody or owner._activation_permission is not None
                or self._parent.completion_recovery is not scope._recovery
                or self._parent.completion_recovery.consume is not self._current_config
                or scope._current_configuration is not self._current_config
                or scope._configuration_seal is not self._config
                or scope._consume_recovery_selection is not self._consume_selection
                or scope._consume_recovery_selection_pin is not self._consume_selection
                or self._binding.runtime_root_public_key is not self._root
                or self._request.scope is not self._asgi
                or getattr(self._request.state, actor.ORIGINAL_STATE_NAME, None) is not self._original
                or scope._application is not self._application or scope._owner is not owner
                or scope._request is not self._request or scope._original is not self._original
                or scope._payload is not self._payload or scope._work is not self._work
                or scope._owner_scope is not self._owner_scope or scope._target is not self._target
                or scope._target_seal is not self._target or scope._source_current is not self._source_current
                or scope._purpose is not self._purpose or scope._purpose is not scope._purpose_pin
                or active._purpose is not self._purpose or active._purpose is not active._purpose_pin
                or _action(self._purpose) != (self._path, self._schema, self._success_status)
                or self._asgi.get("path") != self._path
                or scope._profile != "consume" or scope._configuration is not self._config
                or active._owner is not owner or active._work is not self._work
                or active._parent is not self._parent or active._binding is not self._binding
                or active._custody is not self._custody or active._root is not self._root
                or active._lifetime is not self._parent_lifetime
                or active._delivery is not self or active._delivery_seal is not self
                or active._exchange_spent is not True
                or any(getattr(active, name) is not held for name, held in zip(_PUBLIC_FIELDS, self._public))
                or actors._configuration_pin("consume", self._config) != self._config_pin
                or actors._configuration_pin("consume", self._current_config) != self._current_config_pin
                or scope._current_configuration_pin != self._current_config_pin
                or actors._configuration_pin("consume", self._historical_config) != self._historical_config_pin):
            _fail()
        selection = self._consume_selection
        if self._purpose == PURPOSE:
            actors.consume_selection._identity(selection)
            if (selection._seal is not self._consume_selection_seal
                    or selection.owner is not owner or selection.target is not self._target
                    or selection.work is not self._work
                    or self._public[1].consume_authority is not selection.authority):
                _fail()
        elif selection is not None or self._consume_selection_seal is not None:
            _fail()
        historical = actors._historical_configuration(self._target, "consume", selection)
        if (historical is not self._historical_config
                or self._config_pin != ("consume", self._current_config.endpoint,
                    historical.packet_digest, historical.authorization_digest, historical.current_pending)):
            _fail()
        pins = (scope._policy_pin, scope._request_pin, scope._target_pin, scope._binding_pin,
            scope._payload_digest, scope._credential, scope._count, scope._roles,
            scope._rbac_pin, scope._session_pin, scope._trust_pin,
            scope._future_original_bytes, scope._future_original_bytes_pin)
        if pins != self._pins:
            _fail()
        refs, cold, recovery = self._evidence_refs(), self._cold_refs(), self._recovery_refs()
        if (len(refs) != len(self._evidence_refs_pin) or len(cold) != len(self._cold_pin)
                or len(recovery) != len(self._recovery_pin)
                or any(actual is not held for actual, held in zip(refs, self._evidence_refs_pin))
                or any(actual is not held for actual, held in zip(cold, self._cold_pin))
                or any(actual is not held for actual, held in zip(recovery, self._recovery_pin))
                or self._evidence_values() != self._evidence_values_pin):
            _fail()
        if active._closed is False:
            if (self._phase not in ("acquiring", "staged") or source._ACTIVE is not active
                    or actors._ACTIVE is not scope or actor._ACTIVE is not None
                    or scope._active is not True or scope._authorized is not True
                    or scope._normal_exit is not False or active._normal_exit is not False
                    or active._exchange_failed is not False or scope._completion_recovery_spent is not True
                    or scope._recovery_acquisition_spent is not True or scope._old_token is not self._old
                    or active._receiving_current is not active._receiving_seal
                    or active._token is not active._token_seal):
                _fail()
        elif (active._closed is not True or active._normal_exit is not True
                or scope._normal_exit is not True or scope._active is not False
                or scope._authorized is not False or scope._old_token is not None
                or source._ACTIVE is not None or actors._ACTIVE is not None or actor._ACTIVE is not None
                or scope._completion_receiving_current is not None
                or active._receiving_current is not None or active._receiving_seal is not None
                or active._token is not None or active._token_seal is not None
                or active._exchange_in_progress is not False or active._exchange_complete is not False
                or active._exchange_failed is not True or self._parent_lifetime.guards
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
        application, scope, work = self._application, self._actor, self._work
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
                or actors._target_pin(self._target, work) != self._pins[2]):
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
            # Genuine original ancestors survive normal cleanup; ordinary
            # actor/input/proof/current methods do not and are never called.
            self._floors(*self._owner_scope.continuity(self._epoch, self._monotonic))
            guards = (self._source_current, self._target.live)
            if self._consume_selection is not None:
                # This is the original base-only selection guard. Never call
                # a closed actor, controls, input, proof or exchange descendant.
                guards += (self._consume_selection.live,)
            for guard in guards:
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
        from catchplate import control_plane_oidc_session_activation_completion_recovery_delivery as source

        self._identity()
        if self._phase != "acquiring" or self._receiver is not None or not callable(current):
            _fail()
        self._bounds(window, bound)
        source._DeliveryAttempt._retain_receiving_current(self._active, current, window, bound)
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
        """Fresh exact current target, roles, credential and trust admission."""
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
                or session.get("token_digest") != self._target.new_token_digest
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
                or scope.get("path") != self._path
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
    from catchplate import control_plane_oidc_session_activation_completion_recovery_delivery as source

    if type(active) is not source._DeliveryAttempt or source._ACTIVE is not active:
        _fail()
    active._parent_current()
    scope = active.actor
    path, schema, success_status = _action(scope._purpose)
    if (type(scope) is not actors._CompletionActorScope or actors._ACTIVE is not scope
            or actor._ACTIVE is not None or scope._application is not application
            or scope._purpose is not scope._purpose_pin or scope._profile != "consume"
            or active._purpose is not scope._purpose or active._purpose is not active._purpose_pin
            or scope._authorized is not True or scope._normal_exit is not False
            or active._normal_exit is not False or active._closed is not False
            or active._exchange_spent is not False or active._delivery is not None
            or active._delivery_seal is not None or active._receiving_current is not None
            or active._receiving_seal is not None or active._token is not None or active._token_seal is not None
            or type(scope._owner_scope) is not execution._Scope
            or type(scope._target) is not actors.history._CompletionRecoveryTarget
            or type(active.controls) is not controls_source._CompletionControls
            or type(active.inputs) is not inputs_source._IntentInputs or active.inputs._purpose != scope._purpose
            or type(active.intent) is not intent_source._IntentContinuation
            or type(active.proof) is not proof_source._ProofContinuation
            or active.inputs.actor is not scope or active.inputs.controls is not active.controls
            or active.intent.inputs is not active.inputs or active.proof.intent is not active.intent
            or active.response is not active.inputs.response_originals
            or active.reconciliation_digest is not active.inputs.reconciliation_digest
            or type(active.grants) is not tuple
            or len(active.grants) != (2 if scope._purpose == PURPOSE else 3)
            or any(type(raw) is not bytes or len(raw) < 2 for raw in active.grants)
            or scope._request.method != "POST" or scope._request.scope.get("path") != path
            or scope._request.scope.get("query_string", b"") != b""
            or scope._request.scope.get(_SCOPE_KEY) is not None):
        _fail()
    staged = object.__new__(_StagedRecoveryResponse)
    staged._purpose, staged._path, staged._schema = scope._purpose, path, schema
    staged._success_status = success_status
    staged._active, staged._actor, staged._application = active, scope, application
    staged._owner, staged._owner_scope = active._owner, scope._owner_scope
    staged._source_current, staged._target = scope._source_current, scope._target
    staged._request, staged._asgi = scope._request, scope._request.scope
    staged._original, staged._payload = scope._original, scope._payload
    staged._parent, staged._binding, staged._custody = active._parent, active._binding, active._custody
    staged._config, staged._root = scope._configuration, active._root
    staged._config_pin = actors._configuration_pin("consume", staged._config)
    staged._current_config = scope._current_configuration
    staged._current_config_pin = actors._configuration_pin("consume", staged._current_config)
    staged._consume_selection = scope._consume_recovery_selection
    staged._consume_selection_seal = (None if staged._consume_selection is None
        else staged._consume_selection._seal)
    staged._historical_config = actors._historical_configuration(
        scope._target, "consume", staged._consume_selection)
    staged._historical_config_pin = actors._configuration_pin("consume", staged._historical_config)
    staged._work, staged._parent_lifetime = active._work, active._lifetime
    staged._public = tuple(getattr(active, name) for name in _PUBLIC_FIELDS)
    staged._old = scope._old_token
    staged._pid, staged._thread = os.getpid(), threading.get_ident()
    staged._seal = (active, scope, application, staged._owner, staged._owner_scope,
        staged._source_current, staged._target, staged._request, staged._asgi, staged._original,
        staged._payload, staged._parent, staged._binding, staged._custody, staged._config,
        staged._root, staged._work, staged._parent_lifetime, staged._public, staged._old,
        staged._purpose, staged._path, staged._schema, staged._success_status,
        staged._current_config, staged._historical_config, staged._consume_selection, staged._consume_selection_seal)
    staged._pins = (scope._policy_pin, scope._request_pin, scope._target_pin, scope._binding_pin,
        scope._payload_digest, scope._credential, scope._count, scope._roles,
        scope._rbac_pin, scope._session_pin, scope._trust_pin,
        scope._future_original_bytes, scope._future_original_bytes_pin)
    staged._evidence_refs_pin, staged._evidence_values_pin = staged._evidence_refs(), staged._evidence_values()
    staged._cold_pin = staged._cold_refs()
    staged._recovery_pin = staged._recovery_refs()
    work, lifetime = staged._work, staged._parent_lifetime
    staged._limits, staged._metrics = work.limits, work.metrics
    staged._ceilings = (work.limits.max_hashes, work.limits.max_input_bytes, work.limits.max_json_nodes)
    staged._window, staged._bound = execution.clock._validate(lifetime.window), lifetime.bound
    staged._epoch, staged._monotonic = lifetime.epoch, lifetime.monotonic
    staged._parent_continuity = staged._receiver = None
    staged._response = staged._body = staged._cookie = None
    staged._phase, staged._session_expiry = "acquiring", None
    try:
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
        subject = staged._target.subject
        if (type(session) is not dict or session.get("status") != "active"
                or session.get("id") != subject["sessionId"] or session.get("user_id") != subject["userId"]
                or session.get("revoked_at") is not None
                or session.get("token_digest") != staged._target.new_token_digest
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
        staged._session_expiry = min(permission.activation._time(session[name], name, work)
            for name in ("expires_at", "provider_expires_at"))
        staged._check_actor()
        now = staged._current()
        max_age = (staged._session_expiry - now) // 1_000_000_000
        if max_age < 1:
            _fail()
        work.charge(input_bytes=2048, json_nodes=16)
        response = permission._native(staged._current, work,
            lambda: JSONResponse(status_code=200, headers=_HEADERS, content={
                "schema": staged._schema, "purpose": staged._purpose, "status": staged._success_status,
                "sessionState": "active", "automaticRetryAllowed": False}))
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
    return JSONResponse(status_code=503, headers=_HEADERS, content={"schema": RESPONSE_SCHEMA,
        "purpose": PURPOSE, "status": "release-outcome-unknown", "dispatchState": "unknown",
        "sessionState": "unknown", "automaticRetryAllowed": False})


def _retained_unknown_response():
    return JSONResponse(status_code=503, headers=_HEADERS, content={"schema": RETAINED_RESPONSE_SCHEMA,
        "purpose": RETAINED_PURPOSE, "status": "release-outcome-unknown", "dispatchState": "unknown",
        "sessionState": "unknown", "automaticRetryAllowed": False})


def _rejected_response(*, status_code=400):
    if type(status_code) is not int or status_code not in (400, 401, 403, 405, 409, 413, 415, 422, 429, 503):
        _fail()
    return JSONResponse(status_code=status_code, headers=_HEADERS, content={"schema": RESPONSE_SCHEMA,
        "purpose": PURPOSE, "status": "release-rejected-before-dispatch", "dispatchState": "not-started",
        "sessionState": "unknown", "automaticRetryAllowed": False})


def _retained_rejected_response(*, status_code=400):
    if type(status_code) is not int or status_code not in (400, 401, 403, 405, 409, 413, 415, 422, 429, 503):
        _fail()
    return JSONResponse(status_code=status_code, headers=_HEADERS, content={"schema": RETAINED_RESPONSE_SCHEMA,
        "purpose": RETAINED_PURPOSE, "status": "release-rejected-before-dispatch", "dispatchState": "not-started",
        "sessionState": "unknown", "automaticRetryAllowed": False})


def _discard_scope(scope):
    staged = scope.get(_SCOPE_KEY)
    if type(staged) is _StagedRecoveryResponse:
        staged._discard()


async def _send_response(scope, receive, send, response, *, before_dispatch=False, downstream_failed=False):
    """Guard the actual response start after buffering/signing on this thread."""
    path = scope.get("path")
    rejected = _retained_rejected_response if path == RETAINED_POST_PATH else _rejected_response
    unknown = _retained_unknown_response if path == RETAINED_POST_PATH else _unknown_response
    if path in POST_PATHS and before_dispatch:
        _discard_scope(scope)
        await rejected()(scope, receive, send)
        return
    if path in POST_PATHS and downstream_failed:
        _discard_scope(scope)
        await unknown()(scope, receive, send)
        return
    staged = scope.get(_SCOPE_KEY)
    if staged is None:
        if (path in POST_PATHS and (response.status_code == 200
                or any(name.lower() == b"set-cookie" for name, _value in response.raw_headers))):
            await unknown()(scope, receive, send)
        else:
            await response(scope, receive, send)
        return
    if type(staged) is not _StagedRecoveryResponse:
        await unknown()(scope, receive, send)
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
            # Discard the stale success/cookie/signature; never send a second
            # header set or re-sign, retry contact, or renew the allowance.
            await unknown()(scope, receive, send)
    finally:
        staged._discard()
