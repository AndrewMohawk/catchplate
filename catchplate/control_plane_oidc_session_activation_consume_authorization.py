"""One live consume authorization from this call's sealed planner originals.

The real parent owns the distinct caller key and original permission. No raw
response, restored record, window, callback or successful carrier is accepted
here. Public known-plan authentication is not private ciphertext replay, a
consume grant, SQL execution or token release.
"""
from __future__ import annotations

from catchplate import authority_oidc_session_activation_delivery_execution_authorization as caller
from catchplate import control_plane_oidc_session_activation_consume_execution_bootstrap as configured
from catchplate import control_plane_oidc_session_activation_consume_planning as planning
from catchplate import control_plane_oidc_session_activation_consume_records as retained
from catchplate import control_plane_oidc_session_activation_execution as execution


plan, production = caller.plan, caller.production


def _authorize_on_permission(permission):
    """Consume the source-owned active continuation, not externally held facts."""
    if type(permission) is not execution._ActivationPermission:
        execution._fail("consume signing requires the actual active permission")
    permission._identity()
    owner, work = permission._owner, permission._work
    parent, binding, custody = owner._material, owner._binding, owner._custody
    policy, activation_policy = parent.consume_execution, parent.activation_execution
    private, descriptor, descriptor_identity = owner._consume_key, owner._consume_key_fd, owner._consume_key_identity
    originals, context = permission._consume_originals, permission._consume_context
    raw_activation = permission._sql_originals
    response_path, response_pin = owner._response_path, owner._response_pin
    if (permission._state != "active" or permission._dispatch_phase != "consume-authorizing"
            or permission._consume_authorization_spent is not True
            or originals is not permission._consume_originals_seal or context is not permission._consume_context_seal
            or type(policy) is not configured._ConsumeExecutionMaterial or private is None
            or descriptor != configured.CALLER_KEY_FD or descriptor != policy.caller_private_key_fd
            or descriptor_identity is None or raw_activation is not permission._sql_seal
            or binding.caller_uid != 65532 or binding.caller_gid != 65532
            or type(response_path) is not str or response_pin is None):
        execution._fail("consume signing lacks its actual dedicated cold key and planning continuation")
    prepared, exported = originals
    before, guard, narrow, prior_bytes = context
    raw2 = exported[3], exported[4]
    finalization_digest = permission._target[2]["localDigest"]
    caller.shape._digest(finalization_digest)
    common = {"authorization_enrollment_bytes": policy.authorization_enrollment_bytes,
        "current_root_enrollment_bytes": policy.current_root_enrollment_bytes,
        "grant_enrollment_bytes": policy.grant_enrollment_bytes,
        "root_public_key": binding.runtime_root_public_key,
        "configuration_digest": parent.configuration_digest,
        "planner_public_key": policy.planner_public_key,
        "operation_public_key": policy.operation_public_key}
    enrollment_originals = tuple(common[name] for name in (
        "authorization_enrollment_bytes", "current_root_enrollment_bytes", "grant_enrollment_bytes"))
    for original, maximum in zip(enrollment_originals, (caller.MAX_ENROLLMENT_BYTES,
            caller.authorization.MAX_ENROLLMENT_BYTES, caller.enrollments.MAX_ENROLLMENT_BYTES)):
        caller.authorization._original(original, maximum, "configured consume enrollment original")
    if prior_bytes + sum(map(len, enrollment_originals)) + caller.MAX_AUTHORIZATION_BYTES > caller.MAX_ORIGINAL_BYTES:
        execution._fail("consume signing exceeds the held whole-call original bound")
    caller.authorization._private(private)
    for key in (common["root_public_key"], policy.caller_public_key,
            policy.planner_public_key, policy.operation_public_key):
        caller.authorization._public(key)
    permission._consume_signing = permission._consume_signing_seal = (
        policy, private, descriptor, descriptor_identity)

    def current():
        if (owner._material is not parent or owner._binding is not binding or owner._custody is not custody
                or parent.consume_execution is not policy or parent.activation_execution is not activation_policy
                or permission._consume_originals is not originals or permission._consume_context is not context
                or permission._sql_originals is not raw_activation
                or owner._response_path != response_path or owner._response_pin != response_pin):
            execution._fail("consume signing changed its held cold or original resources")
        return guard()

    def continuity(epoch_floor, monotonic_floor):
        # Both clocks retain each other's actual maxima. The producer also
        # rejects these floors against its own narrower interval before return.
        permission._continuity(epoch_floor, monotonic_floor)
        current()
        return permission._planning_observed

    current()
    planning._same_bytes(common["current_root_enrollment_bytes"],
        activation_policy.current_root_enrollment_bytes, work, "consume caller original current-root enrollment")
    plan._same(caller.keys._spki_on_work(policy.planner_public_key, work),
        caller.keys._spki_on_work(activation_policy.consume_planner_public_key, work), work,
        "consume caller configured planner")
    signing_pin = caller.keys._spki_on_work(policy.caller_public_key, work)
    if (signing_pin == response_pin
            or signing_pin == caller.keys._spki_on_work(activation_policy.caller_public_key, work)):
        execution._fail("consume caller reuses the actual HTTP or activation caller key")
    # The actual guard rechecks the provisioned HTTP pin and every original
    # owner/FD identity; this key is not used as the consume signer.
    current()
    window, _bound = permission._planning_bounds
    narrow(window[3], policy.maximum_age_ns, policy.maximum_clock_skew_ns)
    current()
    request = planning.activation._object(prepared[1], planning.bootstrap.history.MAX_CONSUME_REQUEST_BYTES, work)
    scope = planning.activation._object(prepared[2], caller.expectations_wire.MAX_BYTES, work)
    work.charge(input_bytes=len(prepared[5]))
    journal_digest = prepared[5].decode("ascii")
    caller.shape._digest(journal_digest)
    expectations = caller.expectations_wire._capture_on_work(
        {"request": request, "scope": scope, "journalDigest": journal_digest}, work=work)
    activation_authorization_digest = plan._frame(execution.caller.REQUEST_IDENTITY_DOMAIN,
        (raw_activation[0],), work)
    current()
    window, bound = permission._planning_bounds
    signed = caller._produce_on_work(**common, caller_private_key=private, originals=raw2,
        expectations=expectations, before_vector_bytes=before, live_window=window,
        transport_deadline_ns=bound, work=work, _continuity=continuity)
    current()
    # Admit the returned original through the real signature/fact verifier.
    # Its same-call result is not accepted as an input to this owner or a grant.
    held = caller._capture_on_work(**common, originals=raw2, expectations=expectations,
        before_vector_bytes=before, live_window=window, transport_deadline_ns=bound,
        work=work, extra_originals=(signed,))
    checked_clock = caller._clock(held, work, continuity=continuity)
    verified = caller._verify_held_on_work(held, signed, work, current=checked_clock)
    narrow(verified.expires_at_epoch_ns, policy.maximum_age_ns, policy.maximum_clock_skew_ns)

    def live():
        epoch, monotonic = verified.live()
        continuity(epoch, monotonic)

    live()
    result_originals = (signed,)
    work.charge(input_bytes=retained._append_io_bytes("authorized", result_originals))
    live()
    identity = production._callback(work,
        lambda: execution.custody.ControlPlaneCustodyClient.append_oidc_session_activation_consume_authorized(
            custody, finalization_digest=finalization_digest,
            activation_authorization_digest=activation_authorization_digest, originals=result_originals))
    caller.shape._digest(identity)
    live()
    return signed
