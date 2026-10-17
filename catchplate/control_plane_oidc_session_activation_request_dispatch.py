"""Original-only joins for the actual request-bound activation permission.

The private continuation was made by this same permission after genuine issuer
verification. It is not an input carrier and never replaces the cold parent.
Each downstream authority still verifies its own original bytes. In particular,
the observed predecessor below is not a promise that the head remains current:
the actual reserver must perform its existing locked comparison and transition.
"""
from __future__ import annotations

from catchplate import authority_current_root_head as head
from catchplate import authority_current_root_delivery_records as acknowledgments
from catchplate import authority_oidc_session_activation_reservation_records as reservations
from catchplate import control_plane_oidc_session_activation_execution_bootstrap as activation
from catchplate import control_plane_oidc_session_activation_request_issuance as issued
from catchplate import control_plane_oidc_session_activation_request_issuance_bootstrap as configured


def _held(permission):
    from catchplate import control_plane_oidc_session_activation_execution as execution
    if type(permission) is not execution._ActivationPermission:
        execution._fail("request dispatch requires the actual active permission")
    permission._identity()
    parent = permission._owner._material
    continuation = permission._request_issuance
    if (permission._state != "active" or permission._planning_spent is not True
            or permission._planning_bounds is None
            or type(parent.activation_execution) is not activation._ActivationExecutionMaterial
            or parent.activation_execution.request_bound is not True
            or parent.activation_execution.reservation_predecessor is not None
            or type(parent.activation_planning) is not configured._RequestPlanningMaterial
            or type(continuation) is not issued._Continuation):
        execution._fail("request dispatch lost its actual resource profile or private continuation")
    originals = issued._Continuation._check(continuation, permission)
    if (type(originals) is not tuple or len(originals) != 7
            or any(type(raw) is not bytes for raw in originals)):
        execution._fail("request dispatch lost its retained exact raw7 originals")
    return continuation, originals


def _planner_original_on_permission(permission):
    """Private original accessor; never an admission or caller-supplied DTO."""
    from catchplate import control_plane_oidc_session_activation_execution as execution
    continuation, originals = _held(permission)
    permission._current()
    after, raw = _held(permission)
    if after is not continuation or raw is not originals:
        execution._fail("request planner original changed across live owner custody")
    return originals[3]


def _predecessor_on_permission(permission):
    from catchplate import control_plane_oidc_session_activation_execution as execution
    continuation, _originals = _held(permission)
    predecessor = continuation._predecessor
    if type(predecessor) is not tuple or len(predecessor) != 3:
        execution._fail("request predecessor was not derived by the actual prepare phase")
    reservations._predecessor_scope(*predecessor)
    permission._current()
    after, _raw = _held(permission)
    if after is not continuation or continuation._predecessor is not predecessor:
        execution._fail("request predecessor changed across live original custody")
    return predecessor


def _consume_predecessor_on_permission(permission):
    from catchplate import control_plane_oidc_session_activation_execution as execution
    continuation, _originals = _held(permission)
    predecessor = continuation._consume_predecessor
    if type(predecessor) is not tuple or len(predecessor) != 3:
        execution._fail("consume predecessor was not derived from this call's real completion")
    reservations._predecessor_scope(*predecessor)
    permission._current()
    after, _raw = _held(permission)
    if after is not continuation or continuation._consume_predecessor is not predecessor:
        execution._fail("consume predecessor changed across live original custody")
    return predecessor


def _consume_prepared_on_permission(permission, *, before_vector_bytes):
    """Derive only from the real completed activation; the next CAS still decides."""
    from catchplate import control_plane_oidc_session_activation_execution as execution
    continuation, _originals = _held(permission)
    parent, work = permission._owner._material, permission._work
    policy, consume = parent.activation_execution, parent.consume_execution
    raw, completed = permission._sql_originals, permission._completion_originals
    if (permission._dispatch_phase != "consume-dispatching"
            or permission._consume_dispatch_spent is not True
            or continuation._consume_predecessor is not None
            or consume.request_bound is not True or consume.reservation_predecessor is not None
            or raw is not permission._sql_seal or type(raw) is not tuple or len(raw) != 8
            or completed is not permission._completion_seal
            or type(completed) is not tuple or len(completed) != 4 or completed[0] != b"acknowledged"):
        execution._fail("consume predecessor requires the actual completed same-request activation")
    root = permission._owner._binding.runtime_root_public_key
    enrollment = policy.current_root_enrollment_bytes
    work.charge(input_bytes=len(enrollment) + len(consume.current_root_enrollment_bytes))
    if consume.current_root_enrollment_bytes != enrollment:
        execution._fail("consume predecessor changed the actual state enrollment")
    predecessor = _predecessor_on_permission(permission)
    reserve, reserve_digest, receipt, receipt_digest = reservations._verify_on_work(
        request_bytes=raw[5], snapshot_bytes=raw[6], receipt_bytes=raw[7],
        enrollment_bytes=enrollment, root_public_key=root,
        expected_predecessor_sequence=predecessor[0], expected_predecessor_head_digest=predecessor[1],
        expected_fence=predecessor[2], work=work)
    if receipt is None or receipt_digest is None:
        execution._fail("consume predecessor lacks this activation's signed reserve acknowledgment")
    checked = acknowledgments._verify_ack_on_work(request_bytes=completed[2], receipt_bytes=completed[3],
        enrollment_bytes=enrollment, root_public_key=root,
        expected_pending_sequence=predecessor[0] + 1, expected_pending_head_digest=receipt_digest, work=work)
    state, complete, complete_digest = head.authorization._verify_request_on_work(
        request_bytes=completed[2], enrollment_bytes=enrollment, root_public_key=root,
        now_epoch_ns=permission._current(), work=work)
    same = head.authorization.plan._same
    same(checked.request_digest, complete_digest, work, "consume predecessor exact completion original")
    same(complete["pendingRequestDigest"], reserve_digest, work, "consume predecessor exact activation reserve")
    same(complete["afterVectorDigest"], receipt["afterVectorDigest"], work,
        "consume predecessor activation complete vector")
    same(issued.issuer.planner.vector._digest_on_work(before_vector_bytes, work=work),
        complete["afterVectorDigest"], work, "consume predecessor actual prepared before vector")
    sequence = checked.receipt_payload["sequence"]
    if sequence + 2 > state.payload["maxRecords"]:
        execution._fail("consume predecessor lacks enrolled reserve and completion capacity")
    following = reservations._predecessor_scope(sequence, checked.receipt_digest,
        checked.receipt_payload["fence"] + 1)
    head.authorization._fresh(complete, state, permission._current())
    after, _raw = _held(permission)
    if (after is not continuation or permission._owner._material is not parent
            or parent.activation_execution is not policy or parent.consume_execution is not consume
            or permission._sql_originals is not raw or permission._completion_originals is not completed
            or permission._owner._binding.runtime_root_public_key is not root):
        execution._fail("consume predecessor changed its real completion custody")
    continuation._consume_predecessor = continuation._consume_predecessor_seal = following
    return following


def _predecessor_on_work(*, query_bytes, observation_bytes, enrollment_bytes,
        root_public_key, expected_context_digest, before_vector_bytes, now_epoch_ns, work):
    """Reauthenticate the real nonce-bound head; derive rather than accept a pin."""
    observed = head._verify_on_work(observation_bytes=observation_bytes,
        query_bytes=query_bytes, enrollment_bytes=enrollment_bytes,
        root_public_key=root_public_key, now_epoch_ns=now_epoch_ns, work=work)
    if observed["pendingRequestDigest"] is not None or observed["pendingDecisionDigest"] is not None:
        raise RuntimeError("request dispatch cannot reserve over an observed pending transition")
    state = head.authorization._admit_enrollment_on_work(
        enrollment_bytes=enrollment_bytes, root_public_key=root_public_key, work=work)
    head.authorization.plan._same(observed["contextDigest"], expected_context_digest,
        work, "request reservation head belongs to another exact issuance request")
    vector_digest = issued.issuer.planner.vector._digest_on_work(before_vector_bytes, work=work)
    head.authorization.plan._same(observed["vectorDigest"], vector_digest,
        work, "request reservation head differs from the genuine prepared before vector")
    if observed["sequence"] + 2 > state.payload["maxRecords"]:
        raise RuntimeError("request reservation lacks enrolled reserve and completion capacity")
    if observed["sequence"] == 0:
        head.authorization.plan._same(observed["headDigest"], state.enrollment_digest,
            work, "request reservation genesis differs from the actual enrollment")
    return reservations._predecessor_scope(observed["sequence"],
        observed["headDigest"], observed["fence"] + 1)


def _prepared_on_permission(permission, *, before_vector_bytes):
    """Only the real dispatch calls this after genuine preparation on this work."""
    from catchplate import control_plane_oidc_session_activation_execution as execution
    continuation, originals = _held(permission)
    if (permission._dispatch_phase not in ("preparing", "preparing-completion")
            or permission._spent is not True or continuation._predecessor is not None):
        execution._fail("request predecessor requires this actual prepared dispatch phase")
    parent, binding, work = permission._owner._material, permission._owner._binding, permission._work
    policy, root = parent.activation_execution, binding.runtime_root_public_key
    before = head.authorization._original(before_vector_bytes,
        issued.issuer.planner.vector.MAX_BYTES, "request dispatch prepared before vector")
    context = head.authorization.plan._frame(issued.issuer.REQUEST_IDENTITY_DOMAIN,
        (originals[0],), work)
    predecessor = _predecessor_on_work(query_bytes=originals[1], observation_bytes=originals[2],
        enrollment_bytes=policy.current_root_enrollment_bytes, root_public_key=root,
        expected_context_digest=context, before_vector_bytes=before,
        now_epoch_ns=permission._current(), work=work)
    # The verifier above uses the sampled instant, so sample again after all
    # signature/canonical work and retain the exact original head expiry too.
    payload = head._read_observation(originals[2], work)["payload"]
    now = permission._current()
    if not payload["issuedAtEpochNs"] <= now < payload["expiresAtEpochNs"]:
        execution._fail("request head expired during predecessor verification")
    after, raw = _held(permission)
    if (after is not continuation or raw is not originals
            or permission._owner._material is not parent or permission._owner._binding is not binding
            or parent.activation_execution is not policy or binding.runtime_root_public_key is not root):
        execution._fail("request predecessor changed its actual owner inputs")
    continuation._predecessor = continuation._predecessor_seal = predecessor
    return originals[3], predecessor
