"""One fresh consume caller signature on the actual private recovery owner.

Genuine original signing and receiving remain the existing caller's work. The
sealed result is a same-call continuation, never an incoming authority carrier,
an activation permission, private replay, SQL result or browser session.
"""
from __future__ import annotations

from dataclasses import dataclass

from serverware import authority_oidc_session_activation_consume_input_production as bookkeeping
from serverware import control_plane_oidc_session_activation_consume_authorization as shared
from serverware import control_plane_oidc_session_activation_completion_recovery_consume_planning as planning


caller, configured, execution = shared.caller, shared.configured, shared.execution
plan = caller.plan
MAX_ORIGINAL_BYTES = caller.MAX_ORIGINAL_BYTES
_COMPLETION_RESERVATION_BYTES = 4 * 1024 * 1024
_CONSTRUCTION = object()
_COMMON_FIELDS = ("authorization_enrollment_bytes", "current_root_enrollment_bytes",
    "grant_enrollment_bytes", "root_public_key", "configuration_digest",
    "planner_public_key", "operation_public_key")


def _fail(message):
    execution._fail("fresh consume authorization " + message)


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _ConsumeAuthorization:
    """Private same-owner result; downstream still admits original bytes."""

    _construction: object
    _active: object
    authorization_bytes: bytes
    common: dict
    expectations: dict
    before: bytes
    raw2: tuple
    held: object
    verified: object
    original_reservation_bytes: int
    _lifetime: object
    _identity_guard: object
    _bounds: object
    _seal: tuple | None = None

    @property
    def window(self):
        _identity(self)
        return self._lifetime.window

    @property
    def deadline_ns(self):
        _identity(self)
        return self._lifetime.bound

    def current(self):
        _identity(self)
        observed = self._lifetime.current()
        _identity(self)
        return observed

    def continuity(self, epoch, monotonic):
        # This base excludes our verified child. Later callers bracket it with
        # current(), never attach their full receiving guard to this ancestor.
        _identity(self)
        observed = self._lifetime.continuity(epoch, monotonic)
        _identity(self)
        return observed

    def narrow(self, expiry, age, skew):
        self.current()
        self._lifetime.narrow(expiry, age, skew)
        self.current()


_FIELDS = ("_active", "authorization_bytes", "common", "expectations", "before",
    "raw2", "held", "verified", "original_reservation_bytes", "_lifetime", "_identity_guard", "_bounds")


def _identity(value):
    if (type(value) is not _ConsumeAuthorization or value._construction is not _CONSTRUCTION
            or type(value._seal) is not tuple or len(value._seal) != len(_FIELDS)
            or any(getattr(value, name) is not held for name, held in zip(_FIELDS, value._seal))):
        _fail("lost its exact private construction or original fields")
    value._identity_guard()
    value._bounds()


def _require_authorization(value):
    _identity(value)
    value.current()
    return value


def _authorize_on_active(active):
    from serverware import control_plane_oidc_session_activation_completion_recovery_consume as source

    if type(active) is not source._ConsumeAttempt or source._ACTIVE is not active:
        _fail("requires its actual private owner")
    source._require_authorization_call(active)
    selected = planning._require_plan(active._plan)
    actor, owner, work = active.actor, active._owner, active._work
    parent, binding, custody, root = active._parent, active._binding, active._custody, active._root
    policy, activation_policy = parent.consume_execution, parent.activation_execution
    historical_activation_policy = active._activation_policy
    private, descriptor, descriptor_identity = owner._consume_key, owner._consume_key_fd, owner._consume_key_identity
    response_path, response_pin = owner._response_path, owner._response_pin
    prepared, exported, before = selected.prepared, selected.exported, selected.before
    if (selected._active is not active or active._phase != "authorizing"
            or actor._purpose != "consume" or actor._profile != "activation"
            or type(policy) is not configured._ConsumeExecutionMaterial or private is None
            or type(descriptor) is not int or descriptor != configured.CALLER_KEY_FD
            or descriptor != policy.caller_private_key_fd or descriptor_identity is None
            or (binding.caller_uid, binding.caller_gid) != (65532, 65532)
            or type(response_path) is not str or response_pin is None
            or type(prepared) is not tuple or len(prepared) != 6 or prepared[0] != b"prepared"
            or type(exported) is not tuple or len(exported) != 7 or exported[0] != b"exported"):
        _fail("lacks its admitted plan and dedicated cold caller key")
    raw2 = exported[3:5]
    common = {"authorization_enrollment_bytes": policy.authorization_enrollment_bytes,
        "current_root_enrollment_bytes": policy.current_root_enrollment_bytes,
        "grant_enrollment_bytes": policy.grant_enrollment_bytes,
        "root_public_key": root, "configuration_digest": parent.configuration_digest,
        "planner_public_key": policy.planner_public_key, "operation_public_key": policy.operation_public_key}
    common_pin = tuple(common[name] for name in _COMMON_FIELDS)
    key_refs = (policy.caller_public_key, activation_policy.caller_public_key,
        activation_policy.consume_planner_public_key, historical_activation_policy.caller_public_key)
    enrollment_originals = common_pin[:3]
    for original, maximum in zip(enrollment_originals, (caller.MAX_ENROLLMENT_BYTES,
            caller.authorization.MAX_ENROLLMENT_BYTES, caller.enrollments.MAX_ENROLLMENT_BYTES)):
        caller.authorization._original(original, maximum, "fresh consume enrollment original")
    base = source._execution_held_bytes(active)
    # Before decoding or signing: two caller admissions, known-plan/enrollment
    # captures, canonical/snapshot copies and the bounded signed output. Large
    # valid originals may fail this source representation bound; it is not RSS.
    capture_bytes = (16 * sum(map(len, (*raw2, prepared[1], prepared[2], prepared[5],
            before, *enrollment_originals))) + 8 * caller.MAX_AUTHORIZATION_BYTES + 64 * 1024)
    if (type(base) is not int or base < 0
            or source.EXECUTION_RESERVATION_BYTES != 8 * 1024 * 1024
            or capture_bytes + _COMPLETION_RESERVATION_BYTES >= source.EXECUTION_RESERVATION_BYTES
            or base + source.EXECUTION_RESERVATION_BYTES > MAX_ORIGINAL_BYTES):
        _fail("has insufficient shared capacity after reserving completion")
    reservation = base + capture_bytes
    caller.authorization._private(private)
    for key in (root, policy.caller_public_key, policy.planner_public_key, policy.operation_public_key):
        caller.authorization._public(key)
    expectations = expectation_pin = held = held_pin = None

    def identity():
        if (type(active) is not source._ConsumeAttempt or source._ACTIVE is not active
                or active._closed is not False or active.actor is not actor or active._plan is not selected
                or active._owner is not owner or active._work is not work
                or active._parent is not parent or active._binding is not binding
                or active._custody is not custody or active._root is not root
                or actor._purpose != "consume" or actor._purpose is not actor._purpose_pin
                or actor._profile != "activation" or actor._active is not True
                or actor._authorized is not True or owner._activation_permission is not None
                or owner._material is not parent or owner._binding is not binding or owner._custody is not custody
                or parent.consume_execution is not policy or parent.activation_execution is not activation_policy
                or active._activation_policy is not historical_activation_policy
                or owner._consume_key is not private or owner._consume_key_fd != descriptor
                or owner._consume_key_identity is not descriptor_identity
                or owner._response_path != response_path or owner._response_pin != response_pin
                or binding.runtime_root_public_key is not root
                or selected.prepared is not prepared or selected.exported is not exported or selected.before is not before
                or type(common) is not dict or tuple(common) != _COMMON_FIELDS
                or any(common[name] is not value for name, value in zip(_COMMON_FIELDS, common_pin))
                or any(getattr(policy, name) is not value for name, value in zip(_COMMON_FIELDS[:3], enrollment_originals))
                or parent.configuration_digest is not common_pin[4]
                or policy.planner_public_key is not common_pin[5] or policy.operation_public_key is not common_pin[6]
                or any(actual is not value for actual, value in zip((policy.caller_public_key,
                    activation_policy.caller_public_key, activation_policy.consume_planner_public_key,
                    historical_activation_policy.caller_public_key), key_refs))):
            _fail("changed its actor, dedicated signer, resources or original inputs")
        planning._identity(selected)
        if expectations is not None:
            planning._same(caller.registration._wire(expectations, work), expectation_pin, work,
                "authorization expectation snapshot")
        if held is not None:
            planning._same(caller.registration._wire(held.expectations, work), held_pin, work,
                "authorization captured expectation snapshot")

    def ancestor(epoch, monotonic):
        identity()
        # selected.current includes the genuine original startup descriptor and
        # HTTP-key checks. Pinning the signer above keeps FD206 non-substitutable.
        selected.current()
        observed = selected.continuity(epoch, monotonic)
        selected.current()
        identity()
        return selected.continuity(*observed)

    lifetime = bookkeeping._Lifetime(selected.window, selected.deadline_ns, work, ancestor)

    def bounds():
        identity()
        parent_window, parent_bound = selected.window, selected.deadline_ns
        if parent_window[:3] != lifetime.window[:3]:
            _fail("replaced its original planning clock")
        window = (*lifetime.window[:3], *(min(old, new)
            for old, new in zip(lifetime.window[3:], parent_window[3:])))
        bound = min(lifetime.bound, parent_bound, window[4])
        if window != lifetime.window or bound != lifetime.bound:
            lifetime.adopt(window, bound)

    def current():
        bounds()
        epoch = lifetime.current()
        identity()
        return epoch

    current()
    planning._same(common["current_root_enrollment_bytes"], activation_policy.current_root_enrollment_bytes,
        work, "consume caller independent current-root enrollment")
    plan._same(caller.keys._spki_on_work(policy.planner_public_key, work),
        caller.keys._spki_on_work(activation_policy.consume_planner_public_key, work), work,
        "fresh consume independently configured planner")
    signing_pin = caller.keys._spki_on_work(policy.caller_public_key, work)
    if (signing_pin == response_pin
            or signing_pin == caller.keys._spki_on_work(activation_policy.caller_public_key, work)
            or signing_pin == caller.keys._spki_on_work(historical_activation_policy.caller_public_key, work)):
        _fail("reuses the HTTP or activation caller signing key")
    caller.keys._pair_on_work(private, policy.caller_public_key, work)
    current()
    lifetime.narrow(lifetime.window[3], policy.maximum_age_ns, policy.maximum_clock_skew_ns)
    request = planning.activation._object(prepared[1], planning.bootstrap.history.MAX_CONSUME_REQUEST_BYTES, work)
    scope = planning.activation._object(prepared[2], caller.expectations_wire.MAX_BYTES, work)
    work.charge(input_bytes=len(prepared[5]))
    journal_digest = prepared[5].decode("ascii")
    caller.shape._digest(journal_digest)
    expectations = caller.expectations_wire._capture_on_work(
        {"request": request, "scope": scope, "journalDigest": journal_digest}, work=work)
    expectation_pin = caller.registration._wire(expectations, work)
    current()
    signed = caller._produce_on_work(**common, caller_private_key=private, originals=raw2,
        expectations=expectations, before_vector_bytes=before, live_window=lifetime.window,
        transport_deadline_ns=lifetime.bound, work=work, _continuity=lifetime.continuity)
    current()
    held = caller._capture_on_work(**common, originals=raw2, expectations=expectations,
        before_vector_bytes=before, live_window=lifetime.window, transport_deadline_ns=lifetime.bound,
        work=work, extra_originals=(signed,))
    held_pin = caller.registration._wire(held.expectations, work)
    checked_clock = caller._clock(held, work, continuity=lifetime.continuity)
    verified = caller._verify_held_on_work(held, signed, work, current=checked_clock)
    lifetime.adopt(verified.window, verified.deadline_ns)
    # The actual verifier child uses only lifetime.continuity (base), never
    # this aggregate current. It remains present through downstream cleanup.
    lifetime.attach(lambda: verified.live()[0])
    current()
    kwargs = source._persistence(active)
    kwargs["current"] = current
    identity_digest = execution.custody.ControlPlaneCustodyClient.append_oidc_session_activation_completion_recovery_consume_authorized(
        custody, originals=(signed,), **kwargs)
    caller.shape._digest(identity_digest)
    current()
    result = _ConsumeAuthorization(_CONSTRUCTION, active, signed, common, expectations,
        before, raw2, held, verified, reservation, lifetime, identity, bounds)
    object.__setattr__(result, "_seal", tuple(getattr(result, name) for name in _FIELDS))
    return _require_authorization(result)
