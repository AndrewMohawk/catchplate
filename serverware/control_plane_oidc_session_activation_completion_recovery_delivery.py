"""Fresh purpose-bound ownership after retained completion/intent/proof.

First release and retained recovery are separate literal actions, never a
fallback choice. Independent originals must authorize the selected checkpoint;
missing local records say nothing about the private outcome store. Each lost
attempt is terminal. Preparation, SQL and completion are never repeated here.
"""
from __future__ import annotations

from contextlib import contextmanager

from serverware import authority_oidc_session_activation_release_grant_transport as grants_transport
from serverware import authority_oidc_session_activation_release_hints as hints
from serverware import control_plane_oidc_session_activation_completion_recovery_release as preparation
from serverware import control_plane_oidc_session_activation_completion_recovery_delivery_exchange as live
from serverware import control_plane_oidc_session_activation_release_grant_acquisition_bootstrap as grant_config
from serverware import control_plane_oidc_session_activation_release_handoff_bootstrap as handoff_config
from serverware import control_plane_oidc_session_activation_release_recovery_grant_acquisition_bootstrap as recovery_config


completion, inputs, intent, proof = preparation.completion, preparation.inputs, preparation.intent, preparation.proof
actors, controls, exchange, execution = completion.actors, completion.controls, completion.exchange, completion.execution
bookkeeping = inputs.bookkeeping
planning = inputs.controls_source.history.planning
_ACTIVE = None
_CONSTRUCTION = object()


class _DeliveryAttempt:
    """One actual call association, not an accepted authority carrier."""

    __slots__ = ("_construction", "actor", "controls", "response", "completion_current",
        "reconciliation_digest", "inputs", "intent", "proof", "grants",
        "inputs_spent", "intent_spent", "proof_spent", "_owner", "_work", "_parent",
        "_binding", "_custody", "_root", "_config", "_issuer", "_cold_seal",
        "_config_pin", "_continuation_seal", "_grants_seal", "_lifetime", "_lifetime_seal",
        "_window_pin", "_bound_pin", "_delivery", "_delivery_seal", "_receiving_current",
        "_receiving_seal", "_token", "_token_seal", "_exchange_spent", "_exchange_in_progress",
        "_exchange_complete", "_exchange_failed", "_closed", "_normal_exit",
        "_purpose", "_purpose_pin", "_recovery_result", "_recovery_result_seal",
        "_stage_spent", "_staged")

    def __init__(self, construction, actor, selected):
        if construction is not _CONSTRUCTION:
            execution._fail("completion delivery is privately constructed")
        self._construction, self.actor, self.controls = construction, actor, selected
        self.response = self.completion_current = self.reconciliation_digest = None
        self.inputs = self.intent = self.proof = self.grants = None
        self.inputs_spent = self.intent_spent = self.proof_spent = False
        self._owner, self._work = actor._owner, selected.work
        self._parent, self._binding, self._custody = self._owner._material, self._owner._binding, self._owner._custody
        self._root = self._binding.runtime_root_public_key
        self._purpose = self._purpose_pin = actor._purpose
        if self._purpose == "release":
            self._config, self._issuer = self._parent.release_handoff, self._parent.release_grant_acquisition
            if (type(self._config) is not handoff_config._ReleaseHandoffMaterial
                    or type(self._issuer) is not grant_config._ReleaseGrantAcquisitionMaterial):
                execution._fail("completion delivery lacks independent LIVE caller configuration")
        elif self._purpose == "retained-release":
            self._config = self._issuer = self._parent.release_recovery_grant_acquisition
            if type(self._config) is not recovery_config._RecoveryGrantAcquisitionMaterial:
                execution._fail("completion delivery lacks independent RECOVERY configuration")
        else:
            execution._fail("completion delivery purpose is not a fixed release action")
        if ((self._binding.caller_uid, self._binding.caller_gid)
                != (handoff_config.client.CLIENT_UID, handoff_config.client.CLIENT_GID)):
            execution._fail("completion delivery lacks its independent caller identity")
        self._cold_seal = (actor, selected, self._owner, self._work, self._parent,
            self._binding, self._custody, self._root, self._config, self._issuer)
        self._config_pin = self._cold_configuration()
        self._continuation_seal = self._grants_seal = None
        self._lifetime = self._lifetime_seal = self._window_pin = self._bound_pin = None
        self._delivery = self._delivery_seal = self._receiving_current = self._receiving_seal = None
        self._token = self._token_seal = None
        self._exchange_spent = self._exchange_in_progress = self._exchange_complete = False
        self._exchange_failed = self._closed = self._normal_exit = False
        self._recovery_result = self._recovery_result_seal = None
        self._stage_spent = self._staged = False

    def _cold_configuration(self):
        if self._purpose == "release":
            if (self._parent.release_handoff is not self._config
                    or self._parent.release_grant_acquisition is not self._issuer):
                execution._fail("completion LIVE configuration changed")
            return (self._config.client_id, self._config.client_identity_bytes,
                self._config.endpoint_bytes, self._issuer.endpoint)
        if (self._purpose != "retained-release" or self._config is not self._issuer
                or self._parent.release_recovery_grant_acquisition is not self._config):
            execution._fail("completion RECOVERY configuration changed")
        return (self._config.endpoint, self._config.issuer_policy_bytes,
            self._config.release_custody_bytes, self._config.proof_enrollment_bytes,
            self._config.intent_enrollment_bytes)

    def _identity(self):
        observed = (self.actor, self.controls, self._owner, self._work, self._parent,
            self._binding, self._custody, self._root, self._config, self._issuer)
        if (type(self) is not _DeliveryAttempt or self._construction is not _CONSTRUCTION
                or _ACTIVE is not self or self._closed is not False
                or any(actual is not held for actual, held in zip(observed, self._cold_seal))
                or self._owner._material is not self._parent or self._owner._binding is not self._binding
                or self._owner._custody is not self._custody
                or self._binding.runtime_root_public_key is not self._root
                or self._purpose is not self._purpose_pin
                or self._cold_configuration() != self._config_pin
                or self.actor._purpose != self._purpose or self.actor._profile != "consume"
                or actors._ACTIVE is not self.actor or self.actor._authorized is not True
                or self.actor._completion_recovery_spent is not True
                or self.controls._actor is not self.actor):
            execution._fail("completion delivery lost its actual fresh actor or cold originals")
        if self._continuation_seal is not None:
            references = (self.inputs, self.intent, self.proof, self.response, self.completion_current)
            if any(actual is not held for actual, held in zip(references, self._continuation_seal)):
                execution._fail("completion delivery changed its retained continuation")
        if self.grants is not self._grants_seal:
            execution._fail("completion delivery changed its retained grant originals")
        if (self._recovery_result is not self._recovery_result_seal
                or type(self._stage_spent) is not bool or type(self._staged) is not bool
                or self._staged and not self._stage_spent
                or self._purpose == "release" and (self._recovery_result is not None
                    or self._stage_spent or self._staged)):
            execution._fail("completion delivery changed its recovery admission or staging")
        if self._lifetime is not None:
            lifetime = self._lifetime
            if lifetime is not self._lifetime_seal or lifetime.work is not self._work:
                execution._fail("completion delivery replaced its original lifetime")
            window, bound = execution.clock._validate(lifetime.window), lifetime.bound
            if (window[:3] != self._window_pin[:3] or bound > self._bound_pin
                    or bound > window[4] or any(new > old for new, old in zip(window[3:], self._window_pin[3:]))):
                execution._fail("completion delivery widened its inherited allowance")
            self._window_pin, self._bound_pin = window, bound

    def _proof_continuity(self, epoch, monotonic):
        self._identity()
        proof._require_proof(self.proof)
        observed = self.proof._lifetime.continuity(epoch, monotonic)
        self.proof.current()
        return self.proof._lifetime.continuity(*observed)

    def _parent_current(self):
        self._identity()
        if self._lifetime is None:
            execution._fail("completion delivery has no original proof lifetime")
        now = self._lifetime.current()
        self._identity()
        return now

    def _parent_continuity(self, epoch, monotonic):
        self._identity()
        observed = self._lifetime.continuity(epoch, monotonic)
        self._identity()
        return observed

    def _retain_receiving_current(self, current, window, bound):
        self._identity()
        if (self._exchange_in_progress is not True or self._receiving_current is not None
                or not callable(current)):
            execution._fail("completion delivery cannot replace its genuine receiver")
        self._lifetime.adopt(window, bound)
        self._receiving_current = self._receiving_seal = current

    def exchange_token(self, *, _delivery=None):
        self._parent_current()
        if (self._exchange_spent is not False or self.grants is None
                or self._delivery is not None or self._token is not None):
            execution._fail("completion delivery protected exchange is already spent")
        if _delivery is not None:
            from serverware import control_plane_oidc_session_activation_completion_recovery_delivery_response as terminal

            if type(_delivery) is not terminal._StagedRecoveryResponse or _delivery._active is not self:
                execution._fail("completion delivery terminal is not its source-owned association")
        self._delivery = self._delivery_seal = _delivery
        self._exchange_spent = self._exchange_in_progress = True
        try:
            if self._purpose == "release":
                token = live._exchange_on_active(self, _delivery=_delivery)
            else:
                from serverware import control_plane_oidc_session_activation_completion_recovery_retained_exchange as retained

                if self._stage_spent is not True or self._staged is not True:
                    execution._fail("completion recovery has no same-call staged original")
                token = retained._exchange_on_active(self, _delivery=_delivery)
            if (type(token) is not bytes or len(token) != handoff_config.client.delivery.TOKEN_BYTES
                    or not callable(self._receiving_current)
                    or self._receiving_current is not self._receiving_seal):
                execution._fail("completion delivery lacks its genuine token receiver")
            self._receiving_current()
            self._token = self._token_seal = token
            self._exchange_complete = True
        except BaseException:
            self._exchange_failed = True
            self._token = self._token_seal = None
            raise
        finally:
            self._exchange_in_progress = False

    @property
    def token_bytes(self):
        self._parent_current()
        if (self._exchange_complete is not True or self._exchange_failed is not False
                or self._token is not self._token_seal or not callable(self._receiving_current)
                or self._receiving_current is not self._receiving_seal):
            execution._fail("completion delivery token is not live in this source call")
        self._receiving_current()
        return self._token

    def _close(self):
        self._closed = True
        self._exchange_in_progress = self._exchange_complete = False
        self._exchange_failed = True
        self._token = self._token_seal = None
        self._receiving_current = self._receiving_seal = None
        if self._lifetime is not None:
            self._lifetime.guards.clear()
        if self._normal_exit is not True and self._delivery is not None:
            self._delivery._discard()


def _active():
    active = _ACTIVE
    if (type(active) is not _DeliveryAttempt or completion._ACTIVE is not None
            or preparation._ACTIVE is not None):
        execution._fail("completion delivery is not its actual source call")
    active._identity()
    controls._require_controls(active.controls)
    return active


def _require_inputs_call(selected, response_originals, receiving_current):
    active = _active()
    if (active.controls is not selected or active.response is not response_originals
            or active.completion_current is not receiving_current or active.inputs_spent is not False):
        execution._fail("completion delivery inputs changed their actual receiving call")
    active.inputs_spent = True
    receiving_current()
    return active.reconciliation_digest


def _require_intent_call(selected):
    active = _active()
    if active.inputs is not selected or active.inputs_spent is not True or active.intent_spent is not False:
        execution._fail("completion delivery intent is not its sole readmission call")
    active.intent_spent = True
    selected.current()


def _require_proof_call(selected):
    active = _active()
    if active.intent is not selected or active.intent_spent is not True or active.proof_spent is not False:
        execution._fail("completion delivery proof is not its sole readmission call")
    active.proof_spent = True
    selected.current()


def _acquire_grants(active):
    """Claim the same target slot before contact; retain raw2 before admission."""
    active._parent_current()
    if active._purpose != "release":
        execution._fail("LIVE acquisition cannot accept retained recovery permission")
    selected, work = active.inputs, active._work
    wire = grants_transport
    kwargs = intent._persistence(selected, active._parent_current, live._GRANT_IO_BYTES)
    local = execution.custody.ControlPlaneCustodyClient
    claim, prior = local.load_oidc_session_activation_completion_recovery_release_grants(active._custody, **kwargs)
    active._parent_current()
    if claim is not None or prior is not None:
        execution._fail("completion delivery grant acquisition was already attempted; no retry is permitted")
    packet, effects, envelope, created, expires = hints._decode_on_work(active.response[4:], work=work)
    expected = selected.expected_release
    for actual, value, label in (
            (packet, expected["consumeBinding"]["packetDigest"], "packet"),
            (effects, expected["consumeBinding"]["effectsDigest"], "effects"),
            (created, expected["deliveryScope"]["createdAt"], "created"),
            (expires, expected["deliveryScope"]["expiresAt"], "expiry"),
            (planning.assertion._digest(envelope, work), expected["deliveryEnvelopeDigest"], "envelope")):
        inputs.plan._same(actual, value, work, "completion delivery original hint " + label)
    raw = active.proof._originals
    request = wire._originals((wire.PURPOSE, wire.release.LIVE_PURPOSE, raw[2], raw[3],
        active.intent.intent_bytes, selected.intent_policy.enrollment_bytes,
        selected.old_token_bytes, envelope), response=False)
    # This acquisition's temporary reads/wire copies share, not extend, the
    # pre-reserved delivery lane. The response cap is checked before its body.
    temporary = (live._GRANT_IO_BYTES + 4 * sum(map(len, request))
        + 4 * live.MAX_GRANT_RESPONSE_BYTES + 4 * (wire.REQUEST_HEADER_BYTES + wire.RESPONSE_HEADER_BYTES))
    if (temporary > live.EXCHANGE_RESERVATION_BYTES
            or selected.original_reservation_bytes > controls.MAX_ORIGINAL_BYTES):
        execution._fail("completion delivery acquisition exceeds its reserved inventory")
    active._parent_current()
    digest = local.claim_oidc_session_activation_completion_recovery_release_grants_attempt(active._custody, **kwargs)
    execution.shape._digest(digest)
    active._parent_current()
    returned = wire._socket_request_on_work(active._issuer.endpoint, originals=request,
        deadline_ns=active._lifetime.bound, work=work, current=active._parent_current,
        maximum_response_bytes=live.MAX_GRANT_RESPONSE_BYTES)
    active._parent_current()
    returned = wire._originals(returned, response=True)
    digest = local.append_oidc_session_activation_completion_recovery_release_grants(
        active._custody, originals=returned, **kwargs)
    execution.shape._digest(digest)
    active._parent_current()
    active.grants = active._grants_seal = returned


@contextmanager
def _acquire_on_owner(owner, *, request, recovery_bytes, live_window,
        transport_deadline_ns, work, current, _purpose="release"):
    """Retained originals plus fresh release permission; never preparation."""
    global _ACTIVE

    if _ACTIVE is not None or completion._ACTIVE is not None or preparation._ACTIVE is not None:
        execution._fail("completion delivery cannot overlap another source call")
    if _purpose == "release":
        release_reservation = live.EXCHANGE_RESERVATION_BYTES
    elif _purpose == "retained-release":
        from serverware import control_plane_oidc_session_activation_completion_recovery_retained_acquisition as retained_acquisition

        release_reservation = retained_acquisition._reservation_on_owner(owner)
    else:
        execution._fail("completion delivery purpose is not a fixed source action")
    future = (inputs.INPUT_RESERVATION_BYTES + intent._additional_original_bytes(owner)
        + exchange._exchange_reservation("consume") + preparation._RECONCILIATION_IO_BYTES
        + completion._CONFIGURATION_RESERVATION + release_reservation)
    if type(future) is not int or not 0 < future < controls.MAX_ORIGINAL_BYTES:
        execution._fail("completion delivery future inventory exceeds its original allowance")
    active, scope = None, None
    try:
        with actors._authorize_on_owner(owner, profile="consume", request=request,
                recovery_bytes=recovery_bytes, live_window=live_window,
                transport_deadline_ns=transport_deadline_ns, work=work, current=current,
                _purpose=_purpose, _additional_original_bytes=future) as scope:
            scope.current()
            if (scope._purpose != _purpose or scope._authorized is not True
                    or scope._completion_recovery_spent is not False):
                execution._fail("completion delivery requires its fresh release-purpose actor")
            scope._completion_recovery_spent = True
            selected = controls._admit_on_actor(scope, _additional_original_bytes=0)
            active = _DeliveryAttempt(_CONSTRUCTION, scope, selected)
            _ACTIVE = active
            pins = {"finalization_digest": selected.finalization_digest, "phase": "consume",
                "authorization_digest": selected.authorization_digest, "packet_digest": selected.packet_digest,
                "recovery_configuration_digest": completion._configuration_digest(scope)}
            selected.current()
            retained = execution.custody.ControlPlaneCustodyClient.load_oidc_session_activation_completion_recovery_records(
                owner._custody, selected.finalization_digest, phase="consume", work=work,
                current=selected.current, maximum_original_bytes=preparation._RECONCILIATION_IO_BYTES)
            selected.current()
            if retained is not None:
                response = completion._retained_response(selected, retained, pins)
                active.reconciliation_digest = retained.response.digest
            else:
                response = selected.prior_response
            if type(response) is not tuple or len(response) != 6 or response[0] != b"acknowledged":
                execution._fail("completion delivery has no acknowledged retained consume response")
            receiving_current = exchange._verify_on_controls(selected, response_originals=response)
            receiving_current()
            active.response, active.completion_current = response, receiving_current
            scope._completion_receiving_current = receiving_current
            if _purpose == "release":
                active.inputs = inputs._admit_for_release_on_controls(selected,
                    response_originals=response, receiving_current=receiving_current)
            else:
                active.inputs = inputs._admit_for_retained_release_on_controls(selected,
                    response_originals=response, receiving_current=receiving_current)
            active.intent = intent._readmit_on_inputs(active.inputs)
            active.proof = proof._readmit_on_intent(active.intent)
            proof._require_proof(active.proof)
            if (active.inputs.controls is not selected or active.intent.inputs is not active.inputs
                    or active.proof.intent is not active.intent or active.proof_spent is not True):
                execution._fail("completion delivery changed its actual retained source chain")
            active._continuation_seal = (active.inputs, active.intent, active.proof,
                active.response, active.completion_current)
            parent_lifetime = active.proof._lifetime
            active._lifetime = active._lifetime_seal = bookkeeping._Lifetime(
                parent_lifetime.window, parent_lifetime.bound, work, active._proof_continuity)
            active._window_pin, active._bound_pin = parent_lifetime.window, parent_lifetime.bound
            if _purpose == "release":
                _acquire_grants(active)
            else:
                retained_acquisition._acquire_and_stage(active)
            yield active
            active._parent_current()
            if active._exchange_complete is not True or active._exchange_failed is not False:
                execution._fail("completion delivery did not complete its sole protected exchange")
            scope._completion_receiving_current = active._receiving_current
            scope._completion_receiving_current()
        if scope._normal_exit is not True:
            execution._fail("completion delivery lacks normal fresh-actor cleanup")
        active._normal_exit = True
    finally:
        if active is not None:
            active._close()
        if _ACTIVE is active:
            _ACTIVE = None


def _recover_on_owner(owner, *, request, recovery_bytes, live_window,
        transport_deadline_ns, work, current):
    """Separate fresh retained-release action; never a first-release fallback."""
    return _acquire_on_owner(owner, request=request, recovery_bytes=recovery_bytes,
        live_window=live_window, transport_deadline_ns=transport_deadline_ns,
        work=work, current=current, _purpose="retained-release")
