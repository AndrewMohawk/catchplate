"""Single-invocation request issuance on the genuine active permission owner."""
from __future__ import annotations

from serverware import authority_oidc_session_activation_request_issuance as issuer
from serverware import authority_oidc_session_activation_request_issuance_transport as transport
from serverware import control_plane_oidc_session_activation_request_issuance_bootstrap as configured


class _Continuation:
    """Private originals only; this object cannot be supplied to an entrypoint."""

    __slots__ = ("_permission", "_owner", "_parent", "_policy", "_work", "_limits",
        "_request", "_originals", "_pins", "_closed", "_predecessor", "_predecessor_seal",
        "_consume_predecessor", "_consume_predecessor_seal")

    def __init__(self, permission, policy, request, originals):
        self._permission, self._owner = permission, permission._owner
        self._parent, self._policy = permission._owner._material, policy
        self._work, self._limits = permission._work, permission._work.limits
        self._request, self._originals, self._closed = request, originals, False
        self._predecessor = self._predecessor_seal = None
        self._consume_predecessor = self._consume_predecessor_seal = None
        self._pins = (permission, self._owner, self._parent, policy, self._work,
            self._limits, request, originals)

    def _check(self, permission):
        from serverware import control_plane_oidc_session_activation_execution as execution
        if type(self) is not _Continuation or type(permission) is not execution._ActivationPermission:
            execution._fail("request issuance continuation requires its actual original owner")
        permission._identity()
        actual = (self._permission, self._owner, self._parent, self._policy, self._work,
            self._limits, self._request, self._originals)
        if (self._closed or len(self._pins) != len(actual)
                or any(value is not pin for value, pin in zip(actual, self._pins, strict=True))
                or permission is not self._permission or permission._owner is not self._owner
                or permission._owner._material is not self._parent
                or self._parent.activation_planning is not self._policy
                or permission._work is not self._work or self._work.limits is not self._limits
                or permission._request_issuance is not self
                or permission._request_issuance_spent is not True
                or self._predecessor is not self._predecessor_seal
                or self._consume_predecessor is not self._consume_predecessor_seal):
            execution._fail("request issuance continuation changed its original custody")
        return self._originals

    def _close(self):
        self._closed = True
        self._originals = self._request = self._pins = None
        self._predecessor = self._predecessor_seal = None
        self._consume_predecessor = self._consume_predecessor_seal = None


def _prepare_on_permission(permission, *, planner_originals, live_window, deadline_ns):
    from serverware import control_plane_oidc_session_activation_execution as execution
    if type(permission) is not execution._ActivationPermission:
        execution._fail("request issuance requires the actual permission owner")
    permission._identity()
    owner, work, scope = permission._owner, permission._work, permission._scope
    parent, binding = owner._material, owner._binding
    selected = parent.activation_planning
    if (type(selected) is not configured._RequestPlanningMaterial
            or permission._state != "active" or permission._planning_spent is not True
            or permission._spent is not False or permission._request_issuance_spent is not False
            or permission._request_issuance is not None):
        execution._fail("request issuance is not this active context's unused fixed phase")
    raw = issuer.planner_transport._originals(planner_originals, response=False)
    permission._narrow_planning(live_window, deadline_ns)
    permission._request_issuance_spent = True
    policy_raw, endpoint = selected.policy_bytes, selected.issuance_endpoint
    root, private = binding.runtime_root_public_key, scope.private

    def current():
        if (owner._material is not parent or owner._binding is not binding
                or parent.activation_planning is not selected
                or selected.policy_bytes is not policy_raw or selected.issuance_endpoint != endpoint
                or permission._scope is not scope or scope.private is not private
                or binding.runtime_root_public_key is not root):
            execution._fail("request issuance changed the actual parent/key/configuration")
        return permission._current()

    current()
    request = issuer._sign_request_on_work(policy_bytes=policy_raw, planner_originals=raw,
        caller_private_key=private, root_public_key=root, live_window=live_window,
        transport_deadline_ns=deadline_ns, work=work, _continuity=permission._continuity)
    # This exact original was just signed by the held caller and is independently
    # verified again below. Retain its shorter policy expiry in the actual owner,
    # including transport/final return; never restore the broader parent window.
    request_payload = issuer._read_request(request, work)["payload"]
    live_window = execution.caller.window_policy._narrow(live_window,
        deadline_epoch_ns=request_payload["expiresAtEpochNs"],
        maximum_lifetime_ns=live_window[5], maximum_clock_skew_ns=live_window[6])
    deadline_ns = min(deadline_ns, live_window[4])
    permission._narrow_planning(live_window, deadline_ns)
    current()
    returned = transport._socket_request_on_work(endpoint, request_bytes=request,
        deadline_ns=deadline_ns, work=work, current=current)
    current()
    originals = issuer._verify_planning_on_work(policy_bytes=policy_raw, request_bytes=request,
        originals=returned, root_public_key=root, live_window=live_window,
        transport_deadline_ns=deadline_ns, work=work, _continuity=permission._continuity)
    current()
    continuation = _Continuation(permission, selected, request, originals)
    permission._request_issuance = continuation
    current()
    continuation._check(permission)
    return originals[3], live_window, deadline_ns
