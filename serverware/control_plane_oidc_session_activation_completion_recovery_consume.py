"""Private fresh consume continuation after acknowledged activation completion.

The fresh consume purpose authorizes the eventual same-call continuation, not
reuse of the expired activation permission. This source slice stops at private
prepare/export; no public route, SQL dispatch, completion or cookie is enabled.
Opaque responses are durably retained before genuine original admission.
"""
from __future__ import annotations

from contextlib import contextmanager
import time

from serverware import control_plane_oidc_session_activation_completion_recovery as completion
from serverware import control_plane_oidc_session_activation_completion_recovery_consume_inputs as inputs
from serverware import control_plane_oidc_session_activation_completion_recovery_consume_planning as planning
from serverware import control_plane_oidc_session_activation_consume_input_acquisition as acquisition


actors, controls, exchange, execution = completion.actors, completion.controls, completion.exchange, completion.execution
issuer, receiving, transport = acquisition.issuer, acquisition.receiving, acquisition.transport
bookkeeping, configured = acquisition.producer, acquisition.configured
MAX_ORIGINAL_BYTES = controls.MAX_ORIGINAL_BYTES
_RECONCILIATION_IO_BYTES = 1024 * 1024
_ACTIVE = None
_CONSTRUCTION = object()


def _configuration(config, activation_original):
    if (type(config) is not configured._ConsumeInputAcquisitionMaterial
            or type(config.issuer_policy_bytes) is not bytes
            or not 2 <= len(config.issuer_policy_bytes) <= issuer.MAX_BYTES
            or type(activation_original) is not bytes
            or not 2 <= len(activation_original) <= issuer.MAX_ACTIVATION_PLANNER_BOOTSTRAP_BYTES):
        execution._fail("fresh consume lacks bounded independent input configuration")
    transport._endpoint(config.endpoint)


def _acquisition_capture_bytes(original_lengths, config, activation_original, grant_lengths):
    """Length-only allowance retained through planning, excluding reclaimed IO."""
    _configuration(config, activation_original)
    transport._response_lengths(grant_lengths)
    return (bookkeeping._derivation_reservation(original_lengths,
        len(config.issuer_policy_bytes), len(activation_original)) + 24 * sum(grant_lengths))


class _ConsumeAttempt:
    """Actual private call association; never an external authority carrier."""

    __slots__ = ("_construction", "actor", "controls", "response", "completion_current",
        "reconciliation_digest", "_owner", "_parent", "_binding", "_custody", "_work", "_root",
        "_config", "_cold_seal", "_config_pin", "_response_seal", "_lifetime", "_lifetime_seal",
        "_window_pin", "_bound_pin", "_phase", "_closed", "_normal_exit", "_inputs_spent",
        "_planning_spent", "_originals", "_originals_seal", "_input_grants", "_input_grants_seal",
        "_input_material", "_input_material_seal", "_consume_slot", "_consume_slot_seal", "_plan")

    def __init__(self, construction, actor, selected, response, receiving_current, reconciliation):
        if construction is not _CONSTRUCTION:
            execution._fail("fresh consume ownership is privately constructed")
        self._construction, self.actor, self.controls = construction, actor, selected
        self.response, self.completion_current, self.reconciliation_digest = response, receiving_current, reconciliation
        self._owner, self._work = actor._owner, selected.work
        self._parent, self._binding, self._custody = self._owner._material, self._owner._binding, self._owner._custody
        self._root = self._binding.runtime_root_public_key
        self._config = self._parent.consume_input_acquisition
        _configuration(self._config, self._parent.activation_planning.planner_bootstrap_bytes)
        self._cold_seal = (actor, selected, self._owner, self._work, self._parent, self._binding,
            self._custody, self._root, self._config)
        self._config_pin = self._cold_configuration()
        self._response_seal = (response, receiving_current, reconciliation)
        self._phase = "inputs"
        self._closed = self._normal_exit = self._inputs_spent = self._planning_spent = False
        self._originals = self._originals_seal = self._input_grants = self._input_grants_seal = None
        self._input_material = self._input_material_seal = self._consume_slot = self._consume_slot_seal = None
        self._plan = None
        self._window_pin, self._bound_pin = selected.window, selected.deadline_ns
        self._lifetime = self._lifetime_seal = bookkeeping._Lifetime(
            selected.window, selected.deadline_ns, self._work, self._ancestor)

    def _cold_configuration(self):
        return (self._config.endpoint, self._config.issuer_policy_bytes,
            self._parent.activation_planning.planner_bootstrap_bytes,
            self._parent.configuration_digest)

    def _identity(self):
        observed = (self.actor, self.controls, self._owner, self._work, self._parent,
            self._binding, self._custody, self._root, self._config)
        if (type(self) is not _ConsumeAttempt or self._construction is not _CONSTRUCTION
                or _ACTIVE is not self or self._closed is not False
                or any(actual is not held for actual, held in zip(observed, self._cold_seal))
                or self._owner._material is not self._parent or self._owner._binding is not self._binding
                or self._owner._custody is not self._custody
                or self._binding.runtime_root_public_key is not self._root
                or self._parent.consume_input_acquisition is not self._config
                or self._cold_configuration() != self._config_pin
                or actors._ACTIVE is not self.actor or self.actor._purpose != "consume"
                or self.actor._profile != "activation" or self.actor._authorized is not True
                or self.actor._completion_recovery_spent is not True
                or self.controls._actor is not self.actor
                or any(actual is not held for actual, held in zip((self.response,
                    self.completion_current, self.reconciliation_digest), self._response_seal))
                or self._originals is not self._originals_seal
                or self._input_grants is not self._input_grants_seal
                or self._input_material is not self._input_material_seal
                or self._consume_slot is not self._consume_slot_seal
                or self._phase not in ("inputs", "planning", "prepared")):
            execution._fail("fresh consume lost its exact owner, originals or purpose")
        lifetime = self._lifetime
        if lifetime is not self._lifetime_seal or lifetime.work is not self._work:
            execution._fail("fresh consume replaced its original lifetime")
        window, bound = execution.clock._validate(lifetime.window), lifetime.bound
        if (window[:3] != self._window_pin[:3] or bound > self._bound_pin or bound > window[4]
                or any(new > old for new, old in zip(window[3:], self._window_pin[3:]))):
            execution._fail("fresh consume widened its inherited allowance")
        self._window_pin, self._bound_pin = window, bound
        controls._identity(self.controls)

    def _ancestor(self, epoch, monotonic):
        self._identity()
        self.controls.current()
        observed = self.completion_current()
        sampled = bookkeeping.production._callback(self._work, time.monotonic_ns)
        if (type(observed) is not int or observed < epoch
                or type(sampled) is not int or sampled < monotonic):
            execution._fail("fresh consume historical receiver reversed its clocks")
        self._identity()
        return observed, sampled

    def _current(self):
        # Parent guards only. Never call the child plan from this ancestor.
        self._identity()
        epoch = self._lifetime.current()
        self._identity()
        return epoch

    def _continuity(self, epoch, monotonic):
        self._identity()
        observed = self._lifetime.continuity(epoch, monotonic)
        self._identity()
        return observed

    def _close(self):
        self._closed = True
        self._lifetime.guards.clear()
        self._originals = self._originals_seal = None
        self._input_grants = self._input_grants_seal = None
        self._input_material = self._input_material_seal = None
        self._plan = None


def _require_inputs_call(active):
    if (type(active) is not _ConsumeAttempt or _ACTIVE is not active
            or active._phase != "inputs" or active._inputs_spent is not False
            or active._originals is not None):
        execution._fail("fresh consume extraction is not its sole source call")
    active._current()
    active._inputs_spent = True


def _require_planning_call(active):
    if (type(active) is not _ConsumeAttempt or _ACTIVE is not active
            or active._phase != "planning" or active._inputs_spent is not True
            or active._planning_spent is not False or active._input_material is None
            or active._input_grants is None or active._consume_slot is None):
        execution._fail("fresh consume planning lacks its sole admitted input call")
    active._current()
    execution.shape._digest(active._consume_slot)
    active._planning_spent = True


def _persistence(active):
    return {"finalization_digest": active.controls.finalization_digest,
        "activation_authorization_digest": active.controls.authorization_digest,
        "activation_completion_originals": active.response,
        "reconciliation_digest": active.reconciliation_digest,
        "work": active._work, "current": active._current,
        "maximum_original_bytes": planning._IO_BYTES}


def _acquire(active):
    active._current()
    active._originals = active._originals_seal = inputs._originals_on_active(active)
    raw, config, work = active._originals, active._config, active._work
    activation_original = active._parent.activation_planning.planner_bootstrap_bytes
    held = active.controls.original_reservation_bytes - planning.PLANNING_RESERVATION_BYTES
    # The transport caps the combined raw2 body, not each role separately.
    # Only their sum affects the capture multiplier; no original is fabricated.
    ceilings = (planning.MAX_INPUT_RESPONSE_BYTES, 0)
    captures = _acquisition_capture_bytes(tuple(map(len, raw)), config, activation_original, ceilings)
    wire_bytes = (planning._IO_BYTES + 4 * (len(transport.PURPOSE) + sum(map(len, raw)))
        + 4 * planning.MAX_INPUT_RESPONSE_BYTES
        + 4 * (transport.REQUEST_HEADER_BYTES + transport.RESPONSE_HEADER_BYTES))
    if (held < 0 or active.controls.original_reservation_bytes > MAX_ORIGINAL_BYTES
            or max(captures + planning._IO_BYTES, wire_bytes) > planning.PLANNING_RESERVATION_BYTES):
        execution._fail("fresh consume acquisition exceeds its pre-reserved lane")
    lifetime = active._lifetime
    policy = issuer._verify_on_work(policy_bytes=config.issuer_policy_bytes,
        activation_planner_bootstrap_bytes=activation_original, root_public_key=active._root,
        live_window=lifetime.window, transport_deadline_ns=lifetime.bound, work=work,
        _continuity=active._continuity)
    if type(policy) is not issuer._IssuerPolicyMaterial:
        execution._fail("fresh consume requires genuine independent input policy admission")
    lifetime.attach(policy.live)
    lifetime.adopt(policy.live_window, policy.deadline_ns)
    kwargs, local = _persistence(active), execution.custody.ControlPlaneCustodyClient
    active._current()
    slot = local.claim_oidc_session_activation_completion_recovery_consume_attempt(active._custody, **kwargs)
    execution.shape._digest(slot)
    active._consume_slot = active._consume_slot_seal = slot
    active._current()
    returned = transport._socket_request_on_work(config.endpoint,
        originals=transport._originals((transport.PURPOSE, *raw), response=False),
        deadline_ns=lifetime.bound, work=work, current=active._current,
        maximum_response_bytes=planning.MAX_INPUT_RESPONSE_BYTES)
    active._current()
    returned = transport._originals(returned, response=True)
    if sum(map(len, returned)) > planning.MAX_INPUT_RESPONSE_BYTES:
        execution._fail("fresh consume input response exceeded its pre-body bound")
    digest = local.append_oidc_session_activation_completion_recovery_consume_inputs(
        active._custody, originals=returned, **kwargs)
    execution.shape._digest(digest)
    active._input_grants = active._input_grants_seal = returned
    active._current()
    admitted = receiving._verify_on_work(response_originals=returned, request_originals=raw,
        issuer_policy_bytes=config.issuer_policy_bytes, activation_planner_bootstrap_bytes=activation_original,
        root_public_key=active._root, live_window=lifetime.window,
        transport_deadline_ns=lifetime.bound, work=work, _continuity=active._continuity,
        _additional_original_bytes=held)
    if (type(admitted) is not receiving._InputMaterial
            or admitted.planner_bootstrap_bytes is not returned[0]
            or admitted.history_custody_bytes is not returned[1]):
        execution._fail("fresh consume requires independently admitted actual raw2")
    execution.plan._same(admitted.issuer_policy_material.policy_digest, policy.policy_digest,
        work, "fresh consume unchanged independent issuer policy")
    lifetime.attach(admitted.live)
    lifetime.adopt(admitted.live_window, admitted.deadline_ns)
    active._input_material = active._input_material_seal = admitted
    active._current()


@contextmanager
def _prepare_on_owner(owner, *, request, recovery_bytes, live_window,
        transport_deadline_ns, work, current):
    """Private preparation only; no public result or old permission revival."""
    global _ACTIVE

    if _ACTIVE is not None or completion._ACTIVE is not None:
        execution._fail("fresh consume cannot overlap another source call")
    if type(owner) is not execution.startup._EnrollmentOwner:
        execution._fail("fresh consume requires its actual cold owner")
    config, activation_original = owner._material.consume_input_acquisition, owner._material.activation_planning.planner_bootstrap_bytes
    _configuration(config, activation_original)
    cold = (16 * len(activation_original) + 8 * len(config.issuer_policy_bytes)
        + 8 * bookkeeping.history.MAX_CONSUME_REQUEST_BYTES
        + 8 * bookkeeping.state.vector.MAX_BYTES + 64 * 1024 + planning._IO_BYTES
        + 24 * planning.MAX_INPUT_RESPONSE_BYTES)
    if cold >= planning.PLANNING_RESERVATION_BYTES:
        execution._fail("fresh consume cold originals leave no bounded acquisition lane")
    future = (planning.PLANNING_RESERVATION_BYTES + inputs.INPUT_RESERVATION_BYTES
        + exchange._exchange_reservation("activation") + _RECONCILIATION_IO_BYTES
        + completion._CONFIGURATION_RESERVATION)
    if not 0 < future < MAX_ORIGINAL_BYTES:
        execution._fail("fresh consume future inventory exceeds the original allowance")
    active = scope = None
    try:
        with actors._authorize_on_owner(owner, profile="activation", request=request,
                recovery_bytes=recovery_bytes, live_window=live_window,
                transport_deadline_ns=transport_deadline_ns, work=work, current=current,
                _purpose="consume", _additional_original_bytes=future) as scope:
            scope.current()
            if (scope._purpose != "consume" or scope._authorized is not True
                    or scope._completion_recovery_spent is not False):
                execution._fail("fresh consume lacks its unspent purpose-bound actor")
            scope._completion_recovery_spent = True
            selected = controls._admit_on_actor(scope)
            pins = {"finalization_digest": selected.finalization_digest, "phase": "activation",
                "authorization_digest": selected.authorization_digest, "packet_digest": selected.packet_digest,
                "recovery_configuration_digest": completion._configuration_digest(scope)}
            retained = execution.custody.ControlPlaneCustodyClient.load_oidc_session_activation_completion_recovery_records(
                owner._custody, selected.finalization_digest, phase="activation", work=work,
                current=selected.current, maximum_original_bytes=_RECONCILIATION_IO_BYTES)
            selected.current()
            response = completion._retained_response(selected, retained, pins) if retained is not None else selected.prior_response
            reconciliation = retained.response.digest if retained is not None else None
            if type(response) is not tuple or len(response) != 4 or response[0] != b"acknowledged":
                execution._fail("fresh consume requires acknowledged original activation completion")
            receiving_current = exchange._verify_on_controls(selected, response_originals=response)
            receiving_current()
            scope._completion_receiving_current = receiving_current
            active = _ConsumeAttempt(_CONSTRUCTION, scope, selected, response, receiving_current, reconciliation)
            _ACTIVE = active
            _acquire(active)
            active._phase = "planning"
            active._plan = planning._prepare_on_active(active)
            planning._require_plan(active._plan)
            active._phase = "prepared"
            yield active
            active._current()
            planning._require_plan(active._plan)
            scope._completion_receiving_current = active._plan.current
        if scope._normal_exit is not True:
            execution._fail("fresh consume lacks normal fresh-actor cleanup")
        active._normal_exit = True
    finally:
        if active is not None:
            active._close()
        _ACTIVE = None
