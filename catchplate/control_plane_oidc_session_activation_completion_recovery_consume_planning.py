"""Private prepare/export on the actual fresh consume recovery owner.

This is not an activation permission or an execution/result API. Root planner
and history originals are freshly admitted; opaque prepare/export replies are
durable before interpretation. No SQL, token opening or public success occurs.
"""
from __future__ import annotations

from dataclasses import dataclass

from catchplate import control_plane_oidc_session_activation_consume_planning as shared
from catchplate import control_plane_oidc_session_activation_completion_recovery_controls as controls_source
from catchplate import oidc_session_activation_consume_input_admission as input_admission
from catchplate import authority_oidc_session_activation_release_grant_production as bookkeeping


execution, configured, bootstrap = shared.execution, shared.configured, shared.bootstrap
consume, transport, activation = shared.consume, shared.transport, shared.activation
caller, plan, state = shared.caller, shared.plan, shared.state
assertion, registration, reservations = shared.assertion, shared.registration, shared.reservations
MAX_ORIGINAL_BYTES = consume.MAX_ORIGINAL_BYTES
PLANNING_RESERVATION_BYTES = 32 * 1024 * 1024
MAX_INPUT_RESPONSE_BYTES = 256 * 1024
_IO_BYTES = 2 * 1024 * 1024
_CONSTRUCTION = object()


def _fail(message):
    execution._fail(message)


def _same(actual, expected, work, label):
    shared._same_bytes(actual, expected, work, "fresh completion consume " + label)


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _ConsumePlan:
    """Private same-owner continuation; never an admission authority input."""

    _construction: object
    _active: object
    before: bytes
    prepared: tuple
    exported: tuple
    material: object
    signed: dict
    scope: dict
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

    def narrow(self, expiry, age, skew):
        self.current()
        self._lifetime.narrow(expiry, age, skew)
        self.current()

    def continuity(self, epoch, monotonic):
        # A later child must bracket this base with current(), not attach its
        # own full guard back into the source owner's ancestor.
        _identity(self)
        observed = self._lifetime.continuity(epoch, monotonic)
        _identity(self)
        return observed


_FIELDS = ("_active", "before", "prepared", "exported", "material", "signed", "scope",
    "original_reservation_bytes", "_lifetime", "_live", "_identity_guard", "_bounds")


def _identity(value):
    if (type(value) is not _ConsumePlan or value._construction is not _CONSTRUCTION
            or type(value._seal) is not tuple or len(value._seal) != len(_FIELDS)
            or any(getattr(value, name) is not held for name, held in zip(_FIELDS, value._seal))):
        _fail("completion consume plan lost its private construction or original seals")
    value._identity_guard()
    value._bounds()


def _require_plan(value):
    _identity(value)
    value.current()
    return value


def _prepare_on_active(active):
    """Only the actual claimed owner can prepare and export once."""
    from catchplate import control_plane_oidc_session_activation_completion_recovery_consume as source

    source._require_planning_call(active)
    if type(active) is not source._ConsumeAttempt or source._ACTIVE is not active:
        _fail("completion consume planning requires its exact source owner")
    source._ConsumeAttempt._current(active)
    actor, selected, response = active.actor, controls_source._require_controls(active.controls), active.response
    owner, work, root = active._owner, active._work, active._root
    parent, binding, custody = active._parent, active._binding, active._custody
    policy, historical_root = active._activation_policy, active._historical_root
    activation_original = active._activation_original
    originals, grants, acquired = active._originals, active._input_grants, active._input_material
    parent_lifetime, config, slot = active._lifetime, active._config, active._consume_slot
    if (actor._purpose != "consume" or actor._profile != "activation"
            or selected._actor is not actor or selected.profile != "activation" or selected.work is not work
            or selected.root_public_key is not historical_root or actor._owner is not owner
            or selected.authority.activation_execution is not policy
            or selected.authority.root_public_key is not historical_root
            or selected.authority.activation_planning.planner_bootstrap_bytes is not activation_original
            or owner._material is not parent or owner._binding is not binding or owner._custody is not custody
            or binding.runtime_root_public_key is not root
            or originals is not active._originals_seal or grants is not active._input_grants_seal
            or acquired is not active._input_material_seal
            or type(acquired) is not input_admission._InputMaterial
            or type(originals) is not tuple or len(originals) != 16
            or type(response) is not tuple or len(response) != 4 or response[0] != b"acknowledged"
            or type(selected.original_reservation_bytes) is not int
            or not PLANNING_RESERVATION_BYTES <= selected.original_reservation_bytes < MAX_ORIGINAL_BYTES):
        _fail("completion consume planning changed its fresh actor or admitted input association")
    caller.shape._digest(slot)
    originals = input_admission.transport._originals(
        (input_admission.transport.PURPOSE, *originals), response=False)[1:]
    # Shape validation does not replace the exact source-held tuple association.
    held_originals = active._originals
    if any(raw is not held for raw, held in zip(originals, held_originals)):
        _fail("completion consume input framing replaced an original")
    root_original, history_original = shared._inputs(*input_admission.transport._originals(grants, response=True))
    if (sum(map(len, grants)) > MAX_INPUT_RESPONSE_BYTES
            or acquired.planner_bootstrap_bytes is not root_original
            or acquired.history_custody_bytes is not history_original):
        _fail("completion consume planning lost its bounded genuinely admitted raw2")
    current_policy, current_consume = parent.activation_execution, parent.consume_execution
    if (current_policy.consume_planner_endpoint is None or current_policy.consume_planner_public_key is None
            or parent.activation_planning is None):
        _fail("completion consume planner is not independently configured")
    endpoint = transport._endpoint(current_policy.consume_planner_endpoint)
    raw = selected.originals
    expected_raw = (*response, raw[1], raw[2], raw[5], raw[7], raw[6], raw[0], raw[4],
        policy.authorization_enrollment_bytes, policy.grant_enrollment_bytes,
        raw[3], selected.before_bytes, actor._old_token)
    if any(actual is not held for actual, held in zip(originals, expected_raw)):
        _fail("completion consume raw16 differs from its genuine activation originals")
    activation_originals = originals[:13]
    expectations_original, activation_before, old = originals[13:]
    target = actor._target
    held = (actor, selected, response, owner, work, root, parent, binding, custody,
        held_originals, grants, acquired, parent_lifetime, config, slot, target,
        policy, historical_root, activation_original, current_policy, current_consume)

    def identity():
        observed = (active.actor, active.controls, active.response, active._owner, active._work,
            active._root, active._parent, active._binding, active._custody, active._originals,
            active._input_grants, active._input_material, active._lifetime, active._config,
            active._consume_slot, actor._target, active._activation_policy,
            active._historical_root, active._activation_original,
            parent.activation_execution, parent.consume_execution)
        if (type(active) is not source._ConsumeAttempt or source._ACTIVE is not active
                or actor._purpose != "consume" or actor._profile != "activation"
                or actor._old_token is not old or active._originals_seal is not held_originals
                or active._input_grants_seal is not grants or active._input_material_seal is not acquired
                or owner._material is not parent or owner._binding is not binding or owner._custody is not custody
                or selected.authority.activation_execution is not policy
                or selected.authority.root_public_key is not historical_root
                or selected.authority.activation_planning.planner_bootstrap_bytes is not activation_original
                or current_policy.consume_planner_endpoint != endpoint
                or any(actual is not original for actual, original in zip(observed, held))):
            _fail("completion consume planning outlived its original owner or source pins")

    def ancestor(epoch, monotonic):
        identity()
        source._ConsumeAttempt._current(active)
        observed = source._ConsumeAttempt._continuity(active, epoch, monotonic)
        source._ConsumeAttempt._current(active)
        return source._ConsumeAttempt._continuity(active, *observed)

    lifetime = bookkeeping._Lifetime(parent_lifetime.window, parent_lifetime.bound, work, ancestor)
    previous_window, previous_bound = lifetime.window, lifetime.bound

    def bounds():
        nonlocal previous_window, previous_bound
        window = execution.clock._validate(lifetime.window)
        if (window[:3] != previous_window[:3] or lifetime.bound > previous_bound
                or lifetime.bound > window[4]
                or any(new > prior for new, prior in zip(window[3:], previous_window[3:]))):
            _fail("completion consume planning widened its original window")
        previous_window, previous_bound = window, lifetime.bound

    material = signed = scope = None
    material_pin = signed_pin = scope_pin = None

    def current():
        identity()
        bounds()
        now = lifetime.current()
        if material_pin is not None:
            _same(bootstrap.configuration._configuration_wire(material.payload, execution.capture._SharedLedger(work)),
                material_pin, work, "root planner payload seal")
        if signed_pin is not None:
            _same(consume.contract._encode_on_work(signed, work=work), signed_pin, work, "signed plan seal")
            _same(registration._wire(scope, work), scope_pin, work, "independent consume scope seal")
            consume.evidence._fresh(signed, now, scope["maximumPlanAgeNs"], scope["maximumClockSkewNs"])
        identity()
        return now

    current()
    capture_bytes = source._acquisition_capture_bytes(tuple(map(len, originals)), config,
        activation_original, tuple(map(len, grants)))
    acquired_request = acquired.planner_material.consume_request_bytes
    if (type(acquired.planner_material) is not bootstrap._PlannerMaterial
            or type(acquired_request) is not bytes
            or not 2 <= len(acquired_request) <= bootstrap.history.MAX_CONSUME_REQUEST_BYTES):
        _fail("completion consume lacks its bounded already-held typed request")
    # These lengths reserve representations only, not request authority. The
    # new verifier still receives actual root originals, and the typed request
    # is byte-joined afterward. Scope is a fixed projection of that payload;
    # its extra field names/deadline fit the separate 4 KiB framing allowance.
    scope_bound = min(assertion.MAX_CONTEXT_BYTES, len(root_original) + 4096)
    owned_graph = {"configuration": parent.configuration_payload,
        "generation": {name: parent.generation[name]
            for name in activation.configured.configuration._GENERATION_FIELDS},
        "runtime": parent.runtime_role_identities}
    measured = bootstrap.configuration._ConfigurationCapture(execution.capture._SharedLedger(work),
        maximum_bytes=bootstrap.MAX_BYTES, retain=False)
    measured.visit(owned_graph)
    # Held input admission is not reclaimed. New planner/history decoding,
    # canonical pins, reservation/vector copies and all returned representations
    # must share the originally reserved lane with temporary journal I/O.
    planning_bytes = (16 * sum(map(len, grants)) + 8 * measured.bytes
        + 8 * len(policy.current_root_enrollment_bytes)
        + (0 if config.historical_scope is None else 8 * len(current_consume.current_root_enrollment_bytes))
        + 8 * (len(activation_before) + len(selected.after_bytes) + len(expectations_original))
        + 8 * len(acquired_request)
        + 8 * scope_bound + 8 * consume.contract.MAX_BYTES
        + 4 * (transport.BOUNDED_PREPARE_REQUEST_HEADER_BYTES + transport.RESPONSE_HEADER_BYTES
            + transport.EXPORT_REQUEST_HEADER_BYTES + transport.EXPORT_RESPONSE_HEADER_BYTES)
        + 4096)
    held_before_lane = selected.original_reservation_bytes - PLANNING_RESERVATION_BYTES
    fixed = capture_bytes + planning_bytes + _IO_BYTES
    if (MAX_ORIGINAL_BYTES != 64 * 1024 * 1024 or fixed >= PLANNING_RESERVATION_BYTES
            or held_before_lane + fixed >= MAX_ORIGINAL_BYTES):
        _fail("completion consume re-admission leaves no original prepare/export capacity")
    available = min(PLANNING_RESERVATION_BYTES, MAX_ORIGINAL_BYTES - held_before_lane) - fixed
    # Selected activation bodies are already represented by raw16; allow their
    # reread/copies and fixed claim/record headers in the same publication slice.
    # Prior consume stage bodies are not reloaded by these source-fixed methods.
    publication_held = 8 * sum(map(len, originals)) + 64 * 1024
    publication_cap = (_IO_BYTES - publication_held) // 3
    # Eight reply footprints retain framing, publication, decode and comparison
    # headroom; half the available reply lane is reserved for the later export.
    prepare_cap = min(transport.MAX_RESPONSE_BYTES, available // 16, publication_cap)
    if prepare_cap < len(transport.RESPONSE_LIMITS):
        _fail("completion consume preparation has no bounded reply capacity")
    current()
    owned = bootstrap.configuration._ConfigurationCapture(execution.capture._SharedLedger(work),
        maximum_bytes=bootstrap.MAX_BYTES).visit(owned_graph)
    admission = dict(planner_bootstrap_bytes=root_original,
        history_custody_bytes=history_original, configuration_payload=owned["configuration"],
        configuration_digest=parent.configuration_digest, generation=owned["generation"],
        runtime_role_identities=owned["runtime"], runtime_root_public_key=root,
        activation_execution=current_policy, live_window=lifetime.window,
        transport_deadline_ns=lifetime.bound, work=work)
    if config.historical_scope is None:
        material = configured._admit_on_work(**admission)
    else:
        material = configured._admit_bridge_on_work(**admission,
            consume_execution=current_consume, historical_activation_execution=policy,
            historical_root_public_key=historical_root,
            activation_planner_bootstrap_bytes=activation_original,
            issuer_policy_bytes=config.issuer_policy_bytes)
    if type(material) is not bootstrap._PlannerMaterial:
        _fail("completion consume planning requires genuine root planner/history admission")
    material_pin = bootstrap.configuration._configuration_wire(material.payload, execution.capture._SharedLedger(work))
    _same(material.consume_request_bytes, acquired_request, work, "re-admitted typed request footprint")
    _same(material.history_material.planner.bootstrap_bytes,
        activation_original, work, "original activation planner")
    for nested in (material, material.history_material):
        def launch_guard(nested=nested, previous=[nested.opening_sample]):
            lifetime.base()
            sample = bootstrap.shared._fresh(nested.attestation_interval, work, opening=nested.opening_sample)
            if sample[0] < previous[0][2] or sample[1] < previous[0][1]:
                _fail("completion consume original launch clocks reversed")
            previous[0] = sample
            lifetime.continuity(sample[1], sample[2])
            return lifetime.base()

        lifetime.attach(launch_guard)
        lifetime.narrow(nested.attestation_interval[1], material.payload["maximumPlanAgeNs"],
            material.payload["maximumClockSkewNs"])
    current()
    expected = caller.expectations_wire._capture_on_work(
        activation._object(expectations_original, caller.expectations_wire.MAX_BYTES, work), work=work)
    plan._same(material.payload["activationExpectations"], expected, work, "fresh consume activation expectations")
    authorization_digest = plan._frame(caller.REQUEST_IDENTITY_DOMAIN, (raw[0],), work)
    plan._same(authorization_digest, selected.authorization_digest, work, "fresh consume activation authorization")
    predecessor = reservations._predecessor_scope(*policy.reservation_predecessor)
    reserve, _reserve_digest, receipt, receipt_digest = reservations._verify_on_work(
        request_bytes=raw[5], snapshot_bytes=raw[6], receipt_bytes=raw[7],
        enrollment_bytes=policy.current_root_enrollment_bytes, root_public_key=historical_root,
        expected_predecessor_sequence=predecessor[0], expected_predecessor_head_digest=predecessor[1],
        expected_fence=predecessor[2], work=work)
    if receipt is None or receipt_digest is None:
        _fail("completion consume lacks its original activation reservation ACK")
    expected_activation = {"authorizationDigest": authorization_digest, "databaseId": reserve["databaseId"],
        "generationDigest": reserve["generationDigest"], "pendingSequence": predecessor[0] + 1,
        "pendingHeadDigest": receipt_digest, "fence": predecessor[2]}
    plan._same(material.payload["activationScope"], expected_activation, work, "fresh consume original pending scope")
    after = state.vector._encode_on_work(reserve["afterVector"], work=work)
    _same(after, selected.after_bytes, work, "genuine activation after-vector")
    _same(material.complete_root_vector_bytes, after, work, "root consume before-vector")
    consume_request = activation._object(material.consume_request_bytes, bootstrap.history.MAX_CONSUME_REQUEST_BYTES, work)
    arguments = consume.plan.transition._arguments(consume_request["arguments"], work)
    activation_arguments = expected["request"]["arguments"]
    for field in ("user_id", "session_id", "credential_id", "credential_record_id", "challenge_id",
            "old_token_digest", "new_token_digest", "assertion_digest"):
        plan._same(arguments[field], activation_arguments[field], work, "fresh consume original " + field)
    for field, name in (("user_id", "userId"), ("session_id", "sessionId"), ("credential_id", "credentialId")):
        plan._same(arguments[field], target.subject[name], work, "fresh consume actual target " + name)
    for actual, wanted, label in (
            (arguments["credential_record_id"], target.credential_record_id, "credential record"),
            (arguments["challenge_id"], target.challenge_id, "challenge"),
            (arguments["old_token_digest"], target.old_token_digest, "old token commitment"),
            (arguments["new_token_digest"], target.new_token_digest, "new token commitment")):
        plan._same(actual, wanted, work, "fresh consume actual target " + label)
    transition = caller.activation.plan.transition
    delivery_id = transition.core._deterministic_uuid(operation=caller.OPERATION,
        request_digest=expected["request"]["requestDigest"], purpose=transition.DELIVERY_PURPOSE, work=work)
    plan._same(arguments["delivery_id"], delivery_id, work, "fresh consume deterministic delivery")
    plan._same(assertion._digest(old, work), arguments["old_token_digest"], work, "fresh consume original possession")
    current()
    scope = shared._scope(material, lifetime.window[3], work)
    if len(registration._wire(scope, work)) > scope_bound:
        _fail("completion consume independent scope exceeds its reserved projection")
    kwargs = {"finalization_digest": selected.finalization_digest,
        "activation_authorization_digest": authorization_digest,
        "activation_completion_originals": response, "reconciliation_digest": active.reconciliation_digest,
        "work": work, "current": current, "maximum_original_bytes": _IO_BYTES}
    prepared = transport._socket_prepare_on_work(endpoint, old_token_bytes=old,
        activation_originals=activation_originals, live_window=lifetime.window, deadline_ns=lifetime.bound,
        work=work, current=current, maximum_response_bytes=prepare_cap)
    prepared = transport._originals(prepared, response=True)
    prepared_digest = execution.custody.ControlPlaneCustodyClient.append_oidc_session_activation_completion_recovery_consume_prepared(
        custody, originals=prepared, **kwargs)
    caller.shape._digest(prepared_digest)
    current()
    if prepared[0] != b"prepared":
        _fail("completion consume preparation is uncertain; original response retained")
    _same(prepared[1], material.consume_request_bytes, work, "root-bound typed consume request")
    if len(prepared[2]) > scope_bound:
        _fail("completion consume returned scope exceeds its reserved projection")
    returned_scope = activation._object(prepared[2], assertion.MAX_CONTEXT_BYTES, work)
    registration._closed(returned_scope, consume.state.SCOPE_FIELDS, "returned fresh consume scope")
    deadline = returned_scope["deadlineEpochNs"]
    registration._integer(deadline, "returned fresh consume deadline", 1)
    if deadline > lifetime.window[3] or current() >= deadline:
        _fail("completion consume scope widened or exhausted its original deadline")
    scope["deadlineEpochNs"] = deadline
    plan._same(returned_scope, scope, work, "fresh consume independently derived scope")
    lifetime.narrow(deadline, scope["maximumPlanAgeNs"], scope["maximumClockSkewNs"])
    consume._scope({"request": consume_request, "scope": scope}, lifetime.window, work)
    signed, plan_digest = consume._authenticate(prepared[3], consume_request, scope,
        material.planner_public_key, current, work)
    signed_pin, scope_pin = consume.contract._encode_on_work(signed, work=work), registration._wire(scope, work)
    if len(scope_pin) > scope_bound:
        _fail("completion consume final scope exceeds its reserved projection")
    _same(prepared[4], plan_digest.encode("ascii"), work, "genuine signed plan identity")
    work.charge(input_bytes=len(prepared[5]))
    journal_digest = prepared[5].decode("ascii")
    caller.shape._digest(journal_digest)
    # The private planner bounds signed expiry by the actual write/delivery
    # expiry. The public continuation adopts that bound; it never creates dates.
    lifetime.narrow(signed["expiresAtEpochNs"], scope["maximumPlanAgeNs"], scope["maximumClockSkewNs"])
    current()
    export_cap = min(transport.MAX_EXPORT_RESPONSE_BYTES, publication_cap,
        (available - 8 * sum(map(len, prepared)) - 4 * transport.MAX_EXPORT_REQUEST_BYTES) // 8)
    if export_cap < len(transport.EXPORT_RESPONSE_LIMITS):
        _fail("completion consume export has no remaining original response capacity")
    exported = transport._socket_export_retained_on_work(endpoint, envelope_bytes=prepared[3],
        expected_deadline_epoch_ns=deadline, expected_journal_digest=journal_digest,
        live_window=lifetime.window, deadline_ns=lifetime.bound, work=work, current=current,
        maximum_response_bytes=export_cap)
    exported = transport._originals(exported, response=True, export=True)
    exported_digest = execution.custody.ControlPlaneCustodyClient.append_oidc_session_activation_completion_recovery_consume_exported(
        custody, originals=exported, **kwargs)
    caller.shape._digest(exported_digest)
    current()
    if exported[0] != b"exported":
        _fail("completion consume export is uncertain; original response retained")
    for actual, expected_original in zip((exported[1], exported[2], exported[3], exported[5], exported[6]), prepared[1:]):
        _same(actual, expected_original, work, "retained prepare/export correspondence")
    if fixed + 8 * (sum(map(len, prepared)) + sum(map(len, exported))) > PLANNING_RESERVATION_BYTES:
        _fail("completion consume actual replies exceeded their preallocated lane")
    current()
    result = _ConsumePlan(_CONSTRUCTION, active, after, prepared, exported, material, signed, scope,
        selected.original_reservation_bytes, lifetime, current, identity, bounds)
    object.__setattr__(result, "_seal", tuple(getattr(result, name) for name in _FIELDS))
    return _require_plan(result)
