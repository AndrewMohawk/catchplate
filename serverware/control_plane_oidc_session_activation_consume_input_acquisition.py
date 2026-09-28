"""One original-bound consume-input acquisition on the active permission.

The shared durable consume claim precedes issuer contact; opaque raw2 is
retained before root/target admission. Possession-bearing request bytes are
ephemeral. Lost replies, journal history and successful material outputs cannot
restore this permission, create a new allowance or authorize an automatic retry.
"""
from __future__ import annotations

from serverware import authority_oidc_session_activation_consume_input_transport as transport
from serverware import control_plane_oidc_session_activation_consume_input_acquisition_bootstrap as configured
from serverware import control_plane_oidc_session_activation_consume_planning as planning
from serverware import oidc_session_activation_consume_input_admission as receiving


execution, caller, plan = planning.execution, planning.caller, planning.plan
producer, issuer = receiving.production, receiving.issuer


def _acquire_on_permission(permission):
    """No caller-selected originals, policy, target, endpoint or successful DTO."""
    if type(permission) is not execution._ActivationPermission:
        execution._fail("consume input acquisition requires the actual live permission")
    permission._identity()
    owner, work, request = permission._owner, permission._work, permission._request
    parent, binding, custody = owner._material, owner._binding, owner._custody
    policy, activation_policy = parent.consume_input_acquisition, parent.activation_planning
    execution_policy = parent.activation_execution
    target, raw, completed = permission._target, permission._sql_originals, permission._completion_originals
    context, scope = permission._completion_context, permission._scope
    if (permission._state != "active" or permission._dispatch_phase != "consume-planning"
            or permission._consume_spent is not True or permission._consume_claim is not None
            or type(policy) is not configured._ConsumeInputAcquisitionMaterial
            or raw is not permission._sql_seal or completed is not permission._completion_seal
            or context is not permission._completion_context_seal
            or type(context) is not tuple or len(context) != 3
            or type(completed) is not tuple or completed[0] != b"acknowledged"):
        execution._fail("consume input acquisition lacks its unspent completed continuation")
    endpoint = transport._endpoint(policy.endpoint)
    policy_original = issuer.authorization._original(policy.issuer_policy_bytes,
        issuer.MAX_BYTES, "parent consume issuer policy")
    activation_original = activation_policy.planner_bootstrap_bytes
    root = scope.common["root_public_key"]
    response_pin = owner._response_pin
    target_digest = target[2]["localDigest"]
    caller.shape._digest(target_digest)
    cookie_name = target[0].OIDC_SESSION_COOKIE_NAME
    cookie = request.cookies.get(cookie_name)
    prior_guard = context[1]
    claim = None

    def identity():
        permission._identity()
        if (permission._owner is not owner or permission._work is not work
                or permission._request is not request or permission._target is not target
                or target[2]["localDigest"] != target_digest or permission._scope is not scope
                or scope.common["root_public_key"] is not root
                or owner._material is not parent or owner._binding is not binding or owner._custody is not custody
                or owner._response_pin != response_pin
                or parent.consume_input_acquisition is not policy or policy.endpoint != endpoint
                or policy.issuer_policy_bytes is not policy_original
                or parent.activation_planning is not activation_policy
                or activation_policy.planner_bootstrap_bytes is not activation_original
                or parent.activation_execution is not execution_policy
                or permission._sql_originals is not raw or permission._completion_originals is not completed
                or permission._completion_context is not context
                or permission._dispatch_phase not in planning._CONTINUATION_PHASES
                or permission._consume_spent is not True
                or request.cookies.get(cookie_name) != cookie
                or target[0].OIDC_SESSION_COOKIE_NAME != cookie_name
                or claim is not None and permission._consume_claim is not claim):
            execution._fail("consume input acquisition replaced its original owner or possession")

    def continuity(epoch, monotonic):
        identity()
        observed = permission._continuity(epoch, monotonic)
        identity()
        return observed

    window, bound = permission._planning_bounds
    lifetime = producer._Lifetime(window, bound, work, continuity)
    lifetime.attach(prior_guard)

    def current():
        identity()
        now = lifetime.current()
        identity()
        return now

    current()
    suffix = planning.input_request._originals_on_permission(permission)
    current()
    packet = transport._originals((transport.PURPOSE, *suffix), response=False)
    # Cold parent admission proves static original consistency, not current
    # issuance authority. Authenticate that authority on THIS permission window.
    admitted_policy = issuer._verify_on_work(policy_bytes=policy_original,
        activation_planner_bootstrap_bytes=activation_original, root_public_key=root,
        live_window=lifetime.window, transport_deadline_ns=lifetime.bound,
        work=work, _continuity=lifetime.continuity)
    lifetime.attach(admitted_policy.live)
    lifetime.adopt(admitted_policy.live_window, admitted_policy.deadline_ns)
    permission._narrow_planning(lifetime.window, lifetime.bound)
    current()
    # Reserve the retained derivation graphs, response originals and transfer
    # alongside the existing direct planner's later inventory. This is only
    # restrictive accounting, not a new response or processing allowance.
    additional = (len(policy_original) + sum(map(len, packet))
        + transport.REQUEST_HEADER_BYTES + transport.RESPONSE_HEADER_BYTES
        + producer._OUTPUT_RESERVATION + 2 * len(activation_original)
        + len(admitted_policy.activation_planner.state_enrollment_bytes)
        + len(admitted_policy.activation_planner.complete_root_vector_bytes))
    original_hold = (sum(map(len, suffix)) + len(activation_original)
        + len(permission._original) + len(execution_policy.current_root_enrollment_bytes)
        + planning.activation.MAX_ASSERTION_BYTES)
    if original_hold + additional + transport.MAX_RESPONSE_BYTES >= receiving.MAX_ORIGINAL_BYTES:
        execution._fail("consume acquisition cannot reserve its complete remaining original inventory")
    authorization_digest = plan._frame(caller.REQUEST_IDENTITY_DOMAIN, (raw[0],), work)
    planning._claim_on_permission(permission, target_digest=target_digest,
        authorization_digest=authorization_digest, current=current)
    claim = permission._consume_claim
    current()
    response = transport._socket_request_on_work(endpoint, originals=packet,
        deadline_ns=lifetime.bound, work=work, current=current)
    response = transport._originals(response, response=True)
    # No nonempty check, status, JSON, signature or target interpretation may
    # precede this opaque retention. Neither request nor old token is written.
    work.charge(input_bytes=planning.retained._append_io_bytes("inputs", response))
    current()
    identity_digest = planning.production._callback(work,
        lambda: execution.custody.ControlPlaneCustodyClient.append_oidc_session_activation_consume_inputs(
            custody, finalization_digest=target_digest,
            activation_authorization_digest=authorization_digest, originals=response))
    current()
    caller.shape._digest(identity_digest)
    admitted = receiving._verify_on_work(response_originals=response, request_originals=suffix,
        issuer_policy_bytes=policy_original, activation_planner_bootstrap_bytes=activation_original,
        root_public_key=root, live_window=lifetime.window, transport_deadline_ns=lifetime.bound,
        work=work, _continuity=lifetime.continuity)
    lifetime.attach(admitted.live)
    lifetime.adopt(admitted.live_window, admitted.deadline_ns)
    permission._narrow_planning(lifetime.window, lifetime.bound)
    current()
    # The actual direct path re-admits the originals against its own parent
    # pins and target. It reuses only this same-call claim, never journal history.
    return planning._prepare_on_permission(permission,
        planner_bootstrap_bytes=response[0], history_custody_bytes=response[1],
        _current=current, _additional_original_bytes=additional)
