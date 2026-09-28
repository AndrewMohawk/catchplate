"""One consume completion on the same fresh private execution continuation.

The live dispatch already owns genuine caller/grant/reserve admission. Only its
exact sealed source continuation can enter here; stored records or successful
external objects cannot replace it. Returned state/ACK controls are independently
verified after opaque durable retention. Hints never authorize token release.
"""
from __future__ import annotations

from dataclasses import dataclass

from serverware import authority_oidc_session_activation_consume_input_production as bookkeeping
from serverware import control_plane_oidc_session_activation_consume_completion as shared
from serverware import control_plane_oidc_session_activation_completion_recovery_consume_dispatch as dispatching


execution, caller, planning = shared.execution, shared.caller, shared.planning
state, plan, acknowledgments = shared.state, shared.plan, shared.acknowledgments
COMPLETION_RESERVATION_BYTES = 4 * 1024 * 1024
MAX_RESPONSE_BYTES = 64 * 1024
_IO_BYTES = 2 * 1024 * 1024
_CONSTRUCTION = object()


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _ConsumeCompletion:
    _construction: object
    _active: object
    response: tuple
    hints: tuple | None
    after: bytes
    original_reservation_bytes: int
    _lifetime: object
    _live: object
    _seal: tuple | None = None

    @property
    def acknowledged(self):
        self.current()
        return self.response[0] == b"acknowledged"

    @property
    def window(self):
        self.current()
        return self._lifetime.window

    @property
    def deadline_ns(self):
        self.current()
        return self._lifetime.bound

    def current(self):
        if (type(self) is not _ConsumeCompletion or self._construction is not _CONSTRUCTION
                or type(self._seal) is not tuple or len(self._seal) != len(_FIELDS)
                or any(getattr(self, name) is not held for name, held in zip(_FIELDS, self._seal))):
            execution._fail("fresh consume completion lost its private originals")
        return self._live()


_FIELDS = ("_active", "response", "hints", "after", "original_reservation_bytes", "_lifetime", "_live")


def _require_completion(value):
    if type(value) is not _ConsumeCompletion:
        execution._fail("fresh consume completion is not the actual source result")
    value.current()
    return value


def _complete_on_active(active):
    from serverware import control_plane_oidc_session_activation_completion_recovery_consume as source

    source._require_completion_call(active)
    previous = dispatching._require_dispatch(active._dispatch)
    if previous._active is not active:
        execution._fail("fresh consume completion changed its dispatch owner")
    owner, parent, binding, custody, work = active._owner, active._parent, active._binding, active._custody, active._work
    policy = parent.consume_execution
    if (type(policy) is not shared.configured._ConsumeExecutionMaterial
            or policy.completion_endpoint is None or type(policy.release_hints) is not bool):
        execution._fail("fresh consume completion lacks its independent cold profile")
    release_hints = policy.release_hints
    wire = shared.release_transport if release_hints else shared.transport
    endpoint = wire._endpoint(policy.completion_endpoint)
    predecessor = shared.reservations._predecessor_scope(*policy.reservation_predecessor)
    originals, held, authorized = previous.sql_originals, previous.held, previous.authorized
    grant, grant_digest, before = previous.grant_payload, previous.grant_digest, previous.before
    if (type(originals) is not tuple or len(originals) != 8
            or any(type(raw) is not bytes for raw in originals)
            or held.root is not binding.runtime_root_public_key
            or held.current_enrollment is not policy.current_root_enrollment_bytes):
        execution._fail("fresh consume completion lost its actual admitted original controls")
    # No new caller capture is accepted: this is the actual same-call genuine
    # dispatch, kept live below. Reserve re-admission and the new receiver have
    # their own bounded captures; the completion cap is checked before body1.
    request = wire._originals((wire.PURPOSE, originals[0]), response=False)
    footprint = (_IO_BYTES + 8 * sum(map(len, originals[5:]))
        + 4 * len(held.current_enrollment) + 4 * len(before)
        + 4 * state.vector.MAX_BYTES + 4 * shared.observations.MAX_OBSERVATION_BYTES
        + 8 * MAX_RESPONSE_BYTES + 4 * sum(map(len, request))
        + 4 * (wire.REQUEST_HEADER_BYTES + wire.RESPONSE_HEADER_BYTES) + 64 * 1024)
    base = source._execution_held_bytes(active)
    if (footprint > COMPLETION_RESERVATION_BYTES
            or previous.original_reservation_bytes + footprint > base + source.EXECUTION_RESERVATION_BYTES
            or base + source.EXECUTION_RESERVATION_BYTES > source.MAX_ORIGINAL_BYTES):
        execution._fail("fresh consume completion exceeds its pre-reserved execution lane")
    pins = (owner, parent, binding, custody, work, previous, policy, originals, held, authorized, grant)
    state_material = reserve = marker = after = receipt_digest = None
    completed_material = complete = complete_pin = None
    lifetime = None

    def identity():
        if (type(active) is not source._ConsumeAttempt or source._ACTIVE is not active
                or active._closed is not False or active._phase not in ("completing", "completion-observed")
                or active._completion_spent is not True
                or any(actual is not pinned for actual, pinned in zip((active._owner, active._parent,
                    active._binding, active._custody, active._work, active._dispatch, parent.consume_execution,
                    previous.sql_originals, previous.held, previous.authorized, previous.grant_payload), pins))
                or owner._material is not parent or owner._binding is not binding or owner._custody is not custody
                or policy.release_hints is not release_hints or policy.completion_endpoint != endpoint
                or policy.reservation_predecessor != predecessor):
            execution._fail("fresh consume completion outlived its original execution")

    def ancestor(epoch, monotonic):
        identity()
        previous.current()
        observed = previous.continuity(epoch, monotonic)
        previous.current()
        identity()
        return previous.continuity(*observed)

    lifetime = bookkeeping._Lifetime(previous.window, previous.deadline_ns, work, ancestor)
    window_pin, bound_pin = lifetime.window, lifetime.bound

    def current():
        nonlocal window_pin, bound_pin
        identity()
        window = execution.clock._validate(lifetime.window)
        if (window[:3] != window_pin[:3] or lifetime.bound > bound_pin or lifetime.bound > window[4]
                or any(new > old for new, old in zip(window[3:], window_pin[3:]))):
            execution._fail("fresh consume completion widened its inherited allowance")
        window_pin, bound_pin = window, lifetime.bound
        now = lifetime.current()
        if reserve is not None:
            state._fresh(reserve, state_material, now)
        if complete is not None:
            planning._same_bytes(caller.registration._wire(complete, work), complete_pin, work,
                "fresh consume complete payload seal")
            state._fresh(complete, completed_material, now)
        identity()
        return now

    current()
    state_material, reserve, marker, after, receipt_digest = shared._controls(originals,
        held, authorized, grant, grant_digest, predecessor, current, work)
    plan._same(receipt_digest, previous.pending_digest, work, "fresh consume original pending identity")
    age = state_material.payload["maxControlAgeNs"]
    lifetime.narrow(min(reserve["expiresAtEpochNs"], reserve["issuedAtEpochNs"] + age),
        age, state_material.payload["maxClockSkewNs"])
    current()
    returned = wire._socket_request_on_work(endpoint, originals=request, deadline_ns=lifetime.bound,
        work=work, current=current, maximum_response_bytes=MAX_RESPONSE_BYTES)
    current()
    returned = wire._originals(returned, response=True)
    if sum(map(len, returned)) > MAX_RESPONSE_BYTES:
        execution._fail("fresh consume completion exceeded its pre-body response bound")
    response, hints = returned[:4], returned[4:] if release_hints else None
    kwargs = source._persistence(active)
    kwargs.update(current=current, maximum_original_bytes=_IO_BYTES)
    local = execution.custody.ControlPlaneCustodyClient
    digest = local.append_oidc_session_activation_completion_recovery_consume_completion_outcome(
        custody, originals=response, **kwargs)
    execution.shape._digest(digest)
    if hints is not None:
        digest = local.append_oidc_session_activation_completion_recovery_consume_completion_hints(
            custody, originals=hints, **kwargs)
        execution.shape._digest(digest)
    current()
    # Unsigned status/hints do not establish completion. The actual ACK and
    # signed writer observation must match these independently admitted controls.
    if response[0] == b"acknowledged":
        completed_material, complete, complete_digest = state._verify_request_on_work(
            request_bytes=response[2], enrollment_bytes=held.current_enrollment,
            root_public_key=held.root, now_epoch_ns=current(), work=work)
        complete_pin = caller.registration._wire(complete, work)
        acknowledged = acknowledgments._verify_ack_on_work(request_bytes=response[2], receipt_bytes=response[3],
            enrollment_bytes=held.current_enrollment, root_public_key=held.root,
            expected_pending_sequence=predecessor[0] + 1,
            expected_pending_head_digest=receipt_digest, work=work)
        plan._same(acknowledged.request_payload, complete, work, "fresh consume completed state readback")
        plan._same(acknowledged.request_digest, complete_digest, work, "fresh consume complete identity")
        planning._same_bytes(response[1], complete_digest.encode("ascii"), work, "fresh consume response identity")
        plan._same(complete["action"], "complete", work, "fresh consume completion action")
        for field, column in shared.neutral._REQUEST_MARKER_JOINS:
            plan._same(complete[field], marker[column], work, "fresh consume original completion marker " + field)
        shared._observation(complete, marker, after, work)
        age = completed_material.payload["maxControlAgeNs"]
        lifetime.narrow(min(complete["expiresAtEpochNs"], complete["issuedAtEpochNs"] + age),
            age, completed_material.payload["maxClockSkewNs"])
    current()
    result = _ConsumeCompletion(_CONSTRUCTION, active, response, hints, after,
        previous.original_reservation_bytes + footprint, lifetime, current)
    object.__setattr__(result, "_seal", tuple(getattr(result, name) for name in _FIELDS))
    return _require_completion(result)
