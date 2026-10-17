"""One private fresh-consume grant, reserve and claimed SQL exchange.

Original caller and downstream signatures are genuinely admitted. Opaque
responses are durable before interpretation; unsigned SQL observations never
prove commit, completion, token release or permission to retry.
"""
from __future__ import annotations

from dataclasses import dataclass

from catchplate import control_plane_oidc_session_activation_consume_dispatch as shared
from catchplate import control_plane_oidc_session_activation_completion_recovery_consume_authorization as signing
from catchplate import control_plane_oidc_session_activation_completion_recovery_consume_planning as planning


caller, execution, configured = shared.caller, shared.execution, shared.configured
grant_io, reserve_io, sql_io = shared.grant_io, shared.reserve_io, shared.sql_io
state, reservations, plan = shared.state, shared.reservations, shared.plan
MAX_ORIGINAL_BYTES = caller.MAX_ORIGINAL_BYTES
MAX_RESERVATION_RESPONSE_BYTES = 64 * 1024
_IO_BYTES = 2 * 1024 * 1024
_COMPLETION_RESERVATION_BYTES = 4 * 1024 * 1024
_CONSTRUCTION = object()


def _fail(message):
    execution._fail(message)


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _ConsumeDispatch:
    """Same-owner original controls; no consumer accepts a fabricated result."""

    _construction: object
    _active: object
    sql_originals: tuple
    outcome: tuple
    before: bytes
    held: object
    authorized: object
    grant_payload: dict
    grant_digest: str
    grant_enrollment: object
    state_material: object
    reserve_request: dict
    pending_digest: str
    original_plan: dict
    original_reservation_bytes: int
    _lifetime: object
    _live: object
    _identity_guard: object
    _bounds: object
    _seal: tuple | None = None

    @property
    def window(self):
        self._bounds()
        return self._lifetime.window

    @property
    def deadline_ns(self):
        self._bounds()
        return self._lifetime.bound

    def current(self):
        _identity(self)
        observed = self._live()
        _identity(self)
        return observed

    def continuity(self, epoch, monotonic):
        _identity(self)
        observed = self._lifetime.continuity(epoch, monotonic)
        _identity(self)
        return observed

    def narrow(self, expiry, age, skew):
        self.current()
        self._lifetime.narrow(expiry, age, skew)
        self.current()


_FIELDS = ("_active", "sql_originals", "outcome", "before", "held", "authorized",
    "grant_payload", "grant_digest", "grant_enrollment", "state_material", "reserve_request",
    "pending_digest", "original_plan", "original_reservation_bytes", "_lifetime", "_live",
    "_identity_guard", "_bounds")


def _identity(value):
    if (type(value) is not _ConsumeDispatch or value._construction is not _CONSTRUCTION
            or type(value._seal) is not tuple or len(value._seal) != len(_FIELDS)
            or any(getattr(value, name) is not original for name, original in zip(_FIELDS, value._seal))):
        _fail("fresh consume dispatch lost its private construction or original seals")
    value._identity_guard()
    value._bounds()


def _require_dispatch(value):
    _identity(value)
    value.current()
    return value


def _dispatch_on_active(active):
    """Spend the actual owner's dispatch latch; accept no permission or DTO."""
    from catchplate import control_plane_oidc_session_activation_completion_recovery_consume as source

    source._require_dispatch_call(active)
    if type(active) is not source._ConsumeAttempt or source._ACTIVE is not active:
        _fail("fresh consume dispatch requires its actual source owner")
    selected = signing._require_authorization(active._authorization)
    prepared_plan = planning._require_plan(active._plan)
    actor, controls, response = active.actor, active.controls, active.response
    owner, work, root = active._owner, active._work, active._root
    parent, binding, custody = active._parent, active._binding, active._custody
    policy = parent.consume_execution
    authorization = selected.authorization_bytes
    prepared, exported, before = prepared_plan.prepared, prepared_plan.exported, prepared_plan.before
    if (selected._active is not active or prepared_plan._active is not active
            or selected is not active._authorization_seal or active._dispatch_spent is not True
            or active._phase != "dispatching" or actor._purpose != "consume" or actor._profile != "activation"
            or type(policy) is not configured._ConsumeExecutionMaterial
            or policy.reservation_endpoint is None or policy.reservation_predecessor is None
            or policy.sql_endpoint is None or policy.completion_endpoint is None
            or type(policy.release_hints) is not bool):
        _fail("fresh consume dispatch lacks its source-owned signed continuation")
    caller.authorization._original(authorization, caller.MAX_AUTHORIZATION_BYTES, "fresh consume caller original")
    grant_endpoint = grant_io._endpoint(policy.authorizer_endpoint)
    reserve_endpoint = reserve_io._endpoint(policy.reservation_endpoint)
    sql_endpoint = sql_io._endpoint(policy.sql_endpoint)
    predecessor = reservations._predecessor_scope(*policy.reservation_predecessor)
    release_hints = policy.release_hints
    common = {"authorization_enrollment_bytes": policy.authorization_enrollment_bytes,
        "current_root_enrollment_bytes": policy.current_root_enrollment_bytes,
        "grant_enrollment_bytes": policy.grant_enrollment_bytes,
        "root_public_key": root, "configuration_digest": parent.configuration_digest,
        "planner_public_key": policy.planner_public_key, "operation_public_key": policy.operation_public_key}
    common_pin = tuple(common.items())
    association = (actor, controls, response, owner, work, root, parent, binding, custody,
        selected, prepared_plan, active._lifetime, active.reconciliation_digest)

    def identity():
        observed = (active.actor, active.controls, active.response, active._owner, active._work,
            active._root, active._parent, active._binding, active._custody, active._authorization,
            active._plan, active._lifetime, active.reconciliation_digest)
        if (type(active) is not source._ConsumeAttempt or source._ACTIVE is not active
                or active._closed is not False or active._dispatch_spent is not True
                or active._phase not in ("dispatching", "dispatched", "completing", "completion-observed")
                or any(actual is not held for actual, held in zip(observed, association))
                or active._authorization_seal is not selected or selected.authorization_bytes is not authorization
                or prepared_plan.prepared is not prepared or prepared_plan.exported is not exported
                or prepared_plan.before is not before or parent.consume_execution is not policy
                or owner._material is not parent or owner._binding is not binding or owner._custody is not custody
                or binding.runtime_root_public_key is not root
                or policy.authorizer_endpoint != grant_endpoint or policy.reservation_endpoint != reserve_endpoint
                or policy.sql_endpoint != sql_endpoint or policy.reservation_predecessor != predecessor
                or policy.release_hints is not release_hints
                or actor._purpose != "consume" or actor._profile != "activation"):
            _fail("fresh consume dispatch changed its source owner, originals or cold pins")
        actual = (policy.authorization_enrollment_bytes, policy.current_root_enrollment_bytes,
            policy.grant_enrollment_bytes, root, parent.configuration_digest,
            policy.planner_public_key, policy.operation_public_key)
        if any(value is not held for value, (_, held) in zip(actual, common_pin)):
            _fail("fresh consume dispatch changed its independent original enrollment or key")

    def ancestor(epoch, monotonic):
        identity()
        selected.current()
        observed = selected.continuity(epoch, monotonic)
        selected.current()
        return selected.continuity(*observed)

    lifetime = planning.bookkeeping._Lifetime(selected.window, selected.deadline_ns, work, ancestor)
    previous_window, previous_bound = lifetime.window, lifetime.bound

    def bounds():
        nonlocal previous_window, previous_bound
        window = execution.clock._validate(lifetime.window)
        if (type(lifetime.bound) is not int or not 0 < lifetime.bound <= min(previous_bound, window[4])
                or window[:3] != previous_window[:3]
                or any(new > old for new, old in zip(window[3:], previous_window[3:]))):
            _fail("fresh consume dispatch widened its original clock allowance")
        previous_window, previous_bound = window, lifetime.bound

    graph_pins = []
    grant_payload = grant_enrollment = state_material = reserve_request = None

    def pin_graph(graph):
        graph_pins.append((graph, caller.registration._wire(graph, work)))

    def current():
        identity()
        bounds()
        now = lifetime.current()
        for graph, original in graph_pins:
            planning._same(caller.registration._wire(graph, work), original, work,
                "dispatch admitted graph changed")
        if grant_payload is not None:
            caller.evidence._fresh(grant_payload, now, grant_enrollment.payload["maximumGrantAgeNs"],
                min(lifetime.window[6], grant_enrollment.payload["maximumClockSkewNs"]))
        if reserve_request is not None:
            state._fresh(reserve_request, state_material, now)
        identity()
        return now

    base_bytes = source._execution_held_bytes(active)
    prior_bytes = selected.original_reservation_bytes
    if (type(prior_bytes) is not int or not base_bytes <= prior_bytes < MAX_ORIGINAL_BYTES
            or source.EXECUTION_RESERVATION_BYTES != 8 * 1024 * 1024):
        _fail("fresh consume dispatch lacks its original execution reservation")
    raw2 = exported[3], exported[4]
    # This phase reserves its actual caller captures before decoding. Bounded
    # replies cover retained originals, decoding, canonical pins and buffers.
    # Journal scratch is reclaimed before the later completion phase begins.
    capture_bytes = (8 * sum(map(len, (*raw2, prepared[1], prepared[2], prepared[5], before,
        authorization, policy.authorization_enrollment_bytes, policy.current_root_enrollment_bytes,
        policy.grant_enrollment_bytes))) + 64 * 1024)
    response_reserve = 8 * (grant_io.MAX_RESPONSE_BYTES + MAX_RESERVATION_RESPONSE_BYTES
        + sql_io.MAX_RESPONSE_BYTES)
    framing = 4 * sum(module.REQUEST_HEADER_BYTES + module.RESPONSE_HEADER_BYTES
        for module in (grant_io, reserve_io, sql_io))
    retained_bytes = prior_bytes + capture_bytes + response_reserve + framing
    future = max(_IO_BYTES, _COMPLETION_RESERVATION_BYTES)
    if (retained_bytes - base_bytes + future > source.EXECUTION_RESERVATION_BYTES
            or retained_bytes + future > MAX_ORIGINAL_BYTES):
        _fail("fresh consume dispatch and completion exceed their pre-body execution lane")
    current()
    request = shared.planning.activation._object(prepared[1],
        shared.planning.bootstrap.history.MAX_CONSUME_REQUEST_BYTES, work)
    scope = shared.planning.activation._object(prepared[2], caller.expectations_wire.MAX_BYTES, work)
    plan._same(scope, prepared_plan.scope, work, "fresh consume independently admitted scope")
    work.charge(input_bytes=len(prepared[5]))
    journal_digest = prepared[5].decode("ascii")
    expectations = caller.expectations_wire._capture_on_work(
        {"request": request, "scope": scope, "journalDigest": journal_digest}, work=work)
    # Signed bytes are re-admitted against the actual parent, not the successful
    # authorization result's held/verified fields or a restored permission.
    held = caller._capture_on_work(**common, originals=raw2, expectations=expectations,
        before_vector_bytes=before, live_window=lifetime.window,
        transport_deadline_ns=lifetime.bound, work=work, extra_originals=(authorization,))
    actual_clock = caller._clock(held, work, continuity=lifetime.continuity)
    authorized = caller._verify_held_on_work(held, authorization, work, current=actual_clock)
    original_plan = caller.contract._decode_on_work(held.originals[0], envelope=True, work=work)["payload"]
    canonical_expectations = caller.registration._wire(held.expectations, work)
    pin_graph(held.expectations)
    pin_graph(original_plan)

    def caller_current():
        observed = authorized.live()
        lifetime.continuity(*observed)
        return lifetime.base()

    lifetime.attach(caller_current)
    lifetime.adopt(authorized.window, min(lifetime.bound, authorized.deadline_ns))
    lifetime.narrow(authorized.expires_at_epoch_ns, policy.maximum_age_ns, policy.maximum_clock_skew_ns)
    current()
    grant_enrollment = caller.enrollments._admit_enrollment_on_work(
        grant_enrollment_bytes=held.grant_enrollment, current_root_enrollment_bytes=held.current_enrollment,
        root_public_key=held.root, work=work)
    caller.primitives._separate(grant_enrollment.authorizer_public_key,
        (held.planner, held.operation_key), work)
    pin_graph(grant_enrollment.payload)
    lifetime.narrow(lifetime.window[3], grant_enrollment.payload["maximumGrantAgeNs"],
        grant_enrollment.payload["maximumClockSkewNs"])
    grant_request = grant_io._originals((authorization, *held.originals, canonical_expectations), response=False)
    persistence = {"finalization_digest": controls.finalization_digest,
        "activation_authorization_digest": controls.authorization_digest,
        "activation_completion_originals": response, "reconciliation_digest": active.reconciliation_digest,
        "work": work, "current": current, "maximum_original_bytes": _IO_BYTES}
    client = execution.custody.ControlPlaneCustodyClient
    current()
    grant_original = grant_io._socket_request_on_work(grant_endpoint, originals=grant_request,
        deadline_ns=lifetime.bound, work=work, current=current)
    grant_original = grant_io._originals((grant_original,), response=True)[0]
    identity_digest = client.append_oidc_session_activation_completion_recovery_consume_grant(
        custody, **persistence, originals=(grant_original,))
    caller.shape._digest(identity_digest)
    current()
    grant_payload, grant_digest = shared._grant(grant_original, held, authorized, original_plan,
        grant_enrollment, current, lifetime.window, work)
    pin_graph(grant_payload)
    lifetime.narrow(grant_payload["expiresAtEpochNs"], lifetime.window[5], lifetime.window[6])
    current()
    reserved = reserve_io._socket_request_on_work(reserve_endpoint,
        originals=reserve_io._originals((*grant_request, grant_original), response=False),
        deadline_ns=lifetime.bound, work=work, current=current,
        maximum_response_bytes=MAX_RESERVATION_RESPONSE_BYTES)
    reserved = reserve_io._originals(reserved, response=True)
    if sum(map(len, reserved)) > MAX_RESERVATION_RESPONSE_BYTES:
        _fail("fresh consume reservation exceeded its pre-body response cap")
    identity_digest = client.append_oidc_session_activation_completion_recovery_consume_reservation(
        custody, **persistence, originals=reserved)
    caller.shape._digest(identity_digest)
    current()
    state_material, reserve_request, pending_digest = shared._reserve(reserved, held, authorized,
        grant_payload, grant_digest, predecessor, current, work)
    pin_graph(state_material.payload)
    pin_graph(reserve_request)
    lifetime.narrow(reserve_request["expiresAtEpochNs"], state_material.payload["maxControlAgeNs"],
        state_material.payload["maxClockSkewNs"])
    sql_originals = sql_io._originals((*grant_request, grant_original, *reserved), response=False)
    current()
    claim_digest = client.claim_oidc_session_activation_completion_recovery_consume_sql_attempt(
        custody, **persistence, release_hints=release_hints)
    caller.shape._digest(claim_digest)
    current()
    outcome = sql_io._socket_request_on_work(sql_endpoint, originals=sql_originals,
        deadline_ns=lifetime.bound, work=work, current=current)
    outcome = sql_io._originals(outcome, response=True)
    identity_digest = client.append_oidc_session_activation_completion_recovery_consume_sql_outcome(
        custody, **persistence, originals=outcome)
    caller.shape._digest(identity_digest)
    current()
    work.charge(input_bytes=71)
    if outcome[1] and outcome[1] != pending_digest.encode("ascii"):
        _fail("fresh consume SQL observation names another original pending decision")
    # The raw4 remains untrusted data even when its optional locator matches.
    # Future completion authenticates actual signed complete/state originals.
    result = _ConsumeDispatch(_CONSTRUCTION, active, sql_originals, outcome, before, held,
        authorized, grant_payload, grant_digest, grant_enrollment, state_material, reserve_request,
        pending_digest, original_plan, retained_bytes, lifetime, current, identity, bounds)
    object.__setattr__(result, "_seal", tuple(getattr(result, field) for field in _FIELDS))
    return _require_dispatch(result)
