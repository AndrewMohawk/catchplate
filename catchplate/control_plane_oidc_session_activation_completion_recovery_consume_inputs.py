"""Ephemeral consume-input originals from the exact fresh consume owner.

Historical controls and the source-selected acknowledged activation receiver
precede this extraction. Raw16 is original DATA, including actual old-token
possession, never a new execution permission or an admitted authority carrier.
No journal read, private key, socket, SQL or clock/work allowance is created.
"""
from __future__ import annotations

from catchplate import authority_oidc_session_activation_consume_input_transport as transport
from catchplate import control_plane_oidc_session_activation_completion_recovery_actor as actors
from catchplate import control_plane_oidc_session_activation_completion_recovery_controls as controls_source
from catchplate import control_plane_oidc_session_activation_consume_input_request as existing
from catchplate import oidc_session_activation_delivery as delivery


execution = actors.execution
MAX_ORIGINAL_BYTES = existing.consume.MAX_ORIGINAL_BYTES
INPUT_RESERVATION_BYTES = 16 * 1024


def _fail(message):
    execution._fail("fresh consume input extraction " + message)


def _originals_on_active(active):
    """Return exact existing raw16 only inside its one-use source owner."""
    from catchplate import control_plane_oidc_session_activation_completion_recovery_consume as source

    if type(active) is not source._ConsumeAttempt or source._ACTIVE is not active:
        _fail("requires the actual private consume owner")
    # The source hook binds the actual acknowledged receiver and consumes its
    # extraction latch. It is not repeated by any ancestor/current callback.
    source._require_inputs_call(active)
    scope, selected = active.actor, active.controls
    owner, work = active._owner, active._work
    parent, binding, custody, root = active._parent, active._binding, active._custody, active._root
    lifetime = active._lifetime
    if (type(scope) is not actors._CompletionActorScope
            or type(selected) is not controls_source._CompletionControls):
        _fail("requires genuine actor and historical activation controls")
    request, target = scope._request, scope._target
    historical = target.authority
    if (type(historical) is not actors.history.historical._SelectedActivationHistory
            or selected.authority is not historical):
        _fail("requires the target's genuine historical activation authority")
    policy, historical_root = historical.activation_execution, historical.root_public_key
    if type(policy) is not execution.configured._ActivationExecutionMaterial:
        _fail("lacks its independently admitted original activation enrollments")
    raw, completed, receiving = selected.originals, active.response, active.completion_current
    reconciliation = active.reconciliation_digest
    before, old = selected.before_bytes, scope._old_token
    if type(raw) is not tuple or len(raw) != 8 or any(type(value) is not bytes for value in raw):
        _fail("lost its exact historical activation controls")
    expectation_bytes = raw[3]
    if (type(completed) is not tuple or len(completed) != 4
            or completed[0] != b"acknowledged" or any(type(value) is not bytes for value in completed)
            or not callable(receiving)
            or type(before) is not bytes or not 2 <= len(before) <= existing.vector.MAX_BYTES
            or not 2 <= len(expectation_bytes) <= existing.expectations.MAX_BYTES
            or type(old) is not bytes or len(old) != delivery.TOKEN_BYTES
            or type(selected.original_reservation_bytes) is not int
            or not INPUT_RESERVATION_BYTES <= selected.original_reservation_bytes <= MAX_ORIGINAL_BYTES
            or type(scope._future_original_bytes) is not int
            or not INPUT_RESERVATION_BYTES <= scope._future_original_bytes <= selected.original_reservation_bytes):
        _fail("lost bounded acknowledged originals, possession or its prior reservation")
    authorization_enrollment = policy.authorization_enrollment_bytes
    grant_enrollment = policy.grant_enrollment_bytes
    current_root_enrollment = policy.current_root_enrollment_bytes

    def check():
        if (type(active) is not source._ConsumeAttempt or source._ACTIVE is not active
                or active._closed is not False or active._phase != "inputs"
                or active._originals is not None or active._originals_seal is not None
                or active.actor is not scope or active.controls is not selected
                or active._owner is not owner or active._work is not work
                or active._parent is not parent or active._binding is not binding
                or active._custody is not custody or active._root is not root
                or active._lifetime is not lifetime or lifetime.work is not work
                or active.response is not completed or active.completion_current is not receiving
                or active.reconciliation_digest is not reconciliation
                or actors._ACTIVE is not scope or actors.actor._ACTIVE is not None
                or scope._active is not True or scope._authorized is not True
                or scope._normal_exit is not False or scope._completion_recovery_spent is not True
                or scope._purpose != "consume" or scope._purpose is not scope._purpose_pin
                or scope._profile != "activation" or scope._owner is not owner or scope._work is not work
                or scope._request is not request or scope._target is not target or scope._old_token is not old
                or scope._future_original_bytes is not scope._future_original_bytes_pin
                or request.method != "POST" or request.scope.get("path") != actors.CONSUME_PATH
                or request.scope.get("query_string", b"") != b""
                or owner._material is not parent or owner._binding is not binding
                or owner._custody is not custody or owner._activation_permission is not None
                or binding.runtime_root_public_key is not root
                or target.authority is not historical or selected.authority is not historical
                or historical.activation_execution is not policy
                or historical.root_public_key is not historical_root
                or policy.authorization_enrollment_bytes is not authorization_enrollment
                or policy.grant_enrollment_bytes is not grant_enrollment
                or policy.current_root_enrollment_bytes is not current_root_enrollment
                or selected._actor is not scope or selected.profile != "activation"
                or selected.work is not work or selected.root_public_key is not historical_root
                or selected.enrollment_bytes is not current_root_enrollment
                or selected.originals is not raw or selected.before_bytes is not before):
            _fail("changed its same-call owner, original evidence or possession")
        controls_source._identity(selected)

    def current():
        check()
        active._current()
        check()
        epoch = receiving()
        check()
        return epoch

    current()
    execution.capture._SharedLedger(work)
    # Only fixed reference/identity bookkeeping is added here. The complete
    # future lane was reserved before the actor's first historical body read.
    work.charge(input_bytes=INPUT_RESERVATION_BYTES)
    # Request grammar is unchanged. These two enrollments authenticate the
    # original activation, not a new consume issuer/caller. The active owner's
    # current root remains separate and cannot replace their historical root.
    activation = (*completed, raw[1], raw[2], raw[5], raw[7], raw[6], raw[0], raw[4],
        authorization_enrollment, grant_enrollment)
    originals = (*activation, expectation_bytes, before, old)
    if sum(map(len, originals)) > selected.original_reservation_bytes:
        _fail("exceeds its already reserved original inventory")
    transport._originals((transport.PURPOSE, *originals), response=False)
    existing.consume.plan._activation_originals(activation, work)
    delivery._token(old, work)
    execution.plan._same(delivery._token_digest(old, work, current), target.old_token_digest,
        work, "fresh consume actual old-token possession")
    work.charge(input_bytes=len(expectation_bytes) + len(before))
    current()
    # Preserve the exact historical expectation bytes. Genuine issuance still
    # checks canonical encoding and re-admits all originals independently.
    return originals
