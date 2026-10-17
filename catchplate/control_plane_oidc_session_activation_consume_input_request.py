"""Extract consume-input originals from the actual same-call permission only.

The returned raw16 is ephemeral data, including old-token possession, not an
admission result or authority carrier. No socket, journal, clock allowance or
new operation latch is created here.
"""
from __future__ import annotations

from catchplate import authority_current_root_vector as vector
from catchplate import authority_oidc_session_activation_delivery_execution_replay as consume
from catchplate import authority_oidc_session_activation_execution_expectations as expectations
from catchplate import control_plane_oidc_session_activation_execution as execution


def _originals_on_permission(permission):
    """Return activation raw13, expectations, before-vector and old token."""
    if type(permission) is not execution._ActivationPermission:
        execution._fail("consume input extraction requires the actual active permission")
    permission._identity()
    owner, work, request, target = (permission._owner, permission._work,
        permission._request, permission._target)
    parent, binding, custody = owner._material, owner._binding, owner._custody
    policy = parent.activation_execution
    raw, completed, continuation = (permission._sql_originals,
        permission._completion_originals, permission._completion_context)
    if (permission._state != "active" or permission._dispatch_phase != "consume-planning"
            or permission._consume_spent is not True
            or raw is not permission._sql_seal or type(raw) is not tuple or len(raw) != 8
            or any(type(value) is not bytes for value in raw)
            or completed is not permission._completion_seal or type(completed) is not tuple
            or len(completed) != 4 or completed[0] != b"acknowledged"
            or any(type(value) is not bytes for value in completed)
            or continuation is not permission._completion_context_seal
            or type(continuation) is not tuple or len(continuation) != 3
            or not callable(continuation[1]) or not callable(continuation[2])
            or type(target) is not tuple or len(target) != 5):
        execution._fail("consume input extraction lost its sealed completed continuation")
    application = target[0]
    cookie_name = application.OIDC_SESSION_COOKIE_NAME
    cookie = request.cookies.get(cookie_name)
    if type(cookie) is not str or len(cookie) != 64 or any(ord(point) > 127 for point in cookie):
        execution._fail("consume input extraction requires the actual original cookie possession")
    before, guard, _narrow = continuation
    original_expectations = raw[3]
    if (type(before) is not bytes or not 2 <= len(before) <= vector.MAX_BYTES
            or not 2 <= len(original_expectations) <= expectations.MAX_BYTES):
        execution._fail("consume input extraction requires bounded original expectations and vector")
    # Hold all original references and possession before the existing guard can
    # invoke any native callback. A caller cannot supply a replacement guard.
    activation_originals = (*completed, raw[1], raw[2], raw[5], raw[7], raw[6], raw[0], raw[4],
        policy.authorization_enrollment_bytes, policy.grant_enrollment_bytes)

    def check():
        permission._identity()
        if (permission._state != "active" or permission._dispatch_phase != "consume-planning"
                or permission._consume_spent is not True or permission._owner is not owner
                or permission._work is not work or permission._request is not request
                or permission._target is not target or owner._material is not parent
                or owner._binding is not binding or owner._custody is not custody
                or parent.activation_execution is not policy
                or policy.authorization_enrollment_bytes is not activation_originals[11]
                or policy.grant_enrollment_bytes is not activation_originals[12]
                or permission._sql_originals is not raw or permission._sql_seal is not raw
                or permission._completion_originals is not completed or permission._completion_seal is not completed
                or permission._completion_context is not continuation
                or permission._completion_context_seal is not continuation
                or application.OIDC_SESSION_COOKIE_NAME != cookie_name
                or request.cookies.get(cookie_name) != cookie):
            execution._fail("consume input extraction replaced its original owner or possession")

    check()
    guard()
    check()
    old = consume.assertion._token(cookie.encode("ascii"), work)
    activation_originals = consume.plan._activation_originals(activation_originals, work)
    originals = (*activation_originals, original_expectations, before, old)
    if sum(map(len, originals)) > consume.MAX_ORIGINAL_BYTES:
        execution._fail("consume input originals exceed the existing whole-original bound")
    work.charge(input_bytes=len(original_expectations) + len(before))
    check()
    guard()
    check()
    return originals
