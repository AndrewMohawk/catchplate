"""Same-call consume completion originals, without private replay authority.

The isolated completion owner authenticates its private packet/history and
normal-closed commit observation. This public caller authenticates signed
complete/state controls against its own admitted consume originals. Neither
the unsigned SQL outcome nor any returned carrier supplies packet authority.
"""
from __future__ import annotations

from serverware import authority_current_root_authorization as state
from serverware import authority_current_root_completion as observations
from serverware import authority_current_root_delivery_records as acknowledgments
from serverware import authority_current_root_execution_admission as pending
from serverware import authority_oidc_session_activation_delivery_completion_dispatch_transport as transport
from serverware import authority_registration_completion_response as neutral
from serverware import control_plane_oidc_session_activation_consume_dispatch as dispatch
from serverware import control_plane_oidc_session_activation_consume_execution_bootstrap as configured
from serverware import control_plane_oidc_session_activation_consume_records as retained
from serverware import control_plane_oidc_session_activation_execution as execution


caller, planning, computation, reservations = (
    dispatch.caller, dispatch.planning, dispatch.computation, dispatch.reservations)
plan, production = caller.plan, caller.production


def _observation(request, marker, after_bytes, work):
    """Decode only a signed statement; do not fabricate a replay candidate."""
    raw = state.transport._decode(request["writerReceiptBase64Url"],
        request["writerReceiptByteCount"], observations.MAX_OBSERVATION_BYTES, work)
    document = state.wire._decode_object(raw, work=work,
        maximum_bytes=observations.MAX_OBSERVATION_BYTES,
        maximum_nodes=observations.MAX_OBSERVATION_NODES, maximum_depth=3)
    state.shape._object(document, neutral._OBSERVATION_FIELDS, "consume completion observation")
    state.shape._literal(document["schema"], observations.OBSERVATION_SCHEMA)
    state.shape._literal(document["sourceRevision"], state.authority.SOURCE_REVISION)
    state.shape._object(document["marker"], frozenset(pending._MARKER_COLUMNS),
        "consume completion observation marker")
    plan._same(document["marker"], marker, work,
        "consume completion observation differs from original public controls")
    after_digest = state.vector._digest_on_work(after_bytes, work=work)
    for actual in (marker["after_vector_digest"], request["afterVectorDigest"], document["afterVectorDigest"]):
        plan._same(actual, after_digest, work, "consume completion signed full after-vector")
    observed = document["observedAtEpochNs"]
    state.shape._integer(observed, minimum=1)
    if not request["issuedAtEpochNs"] <= observed < request["expiresAtEpochNs"]:
        execution._fail("consume completion observation escapes its signed interval")
    expected = observations._observation_bytes(marker, after_digest, observed, work)
    planning._same_bytes(raw, expected, work, "canonical signed consume observation")


def _controls(originals, held, authorized, grant, grant_digest, predecessor, current, work):
    """Genuine public reserve/snapshot/ACK joins, not historical AES replay."""
    material, reserve, reserve_digest = state._verify_request_on_work(
        request_bytes=originals[5], enrollment_bytes=held.current_enrollment,
        root_public_key=held.root, now_epoch_ns=current(), work=work)
    for field, expected in (("action", "reserve"), ("operation", caller.OPERATION),
            ("requestDigest", authorized.request_digest), ("operationId", authorized.operation_id),
            ("capabilityDigest", grant_digest), ("predecessorSequence", predecessor[0]),
            ("predecessorHeadDigest", predecessor[1]), ("fence", predecessor[2]),
            ("enrollmentDigest", grant["currentRootEnrollmentDigest"]),
            ("databaseId", grant["databaseId"]), ("generationDigest", grant["generationDigest"])):
        plan._same(reserve[field], expected, work, "consume completion reserve " + field)
    if (reserve["issuedAtEpochNs"] != grant["issuedAtEpochNs"]
            or reserve["expiresAtEpochNs"] > min(grant["expiresAtEpochNs"], authorized.window[3])):
        execution._fail("consume completion reserve retimes or renews original authority")
    checked, checked_digest, receipt, receipt_digest = reservations._verify_on_work(
        request_bytes=originals[5], snapshot_bytes=originals[6], receipt_bytes=originals[7],
        enrollment_bytes=held.current_enrollment, root_public_key=held.root,
        expected_predecessor_sequence=predecessor[0], expected_predecessor_head_digest=predecessor[1],
        expected_fence=predecessor[2], work=work)
    plan._same(checked, reserve, work, "consume completion reserve original readback")
    plan._same(checked_digest, reserve_digest, work, "consume completion reserve original identity")
    if receipt is None or receipt_digest is None:
        execution._fail("consume completion lacks the original reserve state acknowledgment")
    snapshot = computation._decode_snapshot_on_work(originals[6], work=work)
    for field in ("sourceRevision", "databaseId", "generationDigest", "operation", "requestDigest",
            "operationId", "retainedRecordDigest", "planDigest", "beforeVectorDigest",
            "afterVectorDigest", "resultDigest", "originalFrames", "originalIssuedAtEpochNs", "originalExpiresAtEpochNs"):
        plan._same(snapshot[field], grant[field], work, "consume completion snapshot/grant " + field)
    plan._same(snapshot["capabilityDigest"], grant_digest, work, "consume completion exact snapshot grant")
    before = state.vector._encode_on_work(reserve["beforeVector"], work=work)
    planning._same_bytes(before, held.before, work, "consume completion independent before-vector")
    after = state.vector._encode_on_work(reserve["afterVector"], work=work)
    for field, raw in (("beforeVectorDigest", before), ("afterVectorDigest", after)):
        plan._same(state.vector._digest_on_work(raw, work=work), grant[field], work,
            "consume completion original full " + field)
    marker = pending._marker(material, reserve, reserve_digest, receipt, receipt_digest, snapshot, work)
    state._fresh(reserve, material, current())
    return material, reserve, marker, after, receipt_digest


def _complete_on_permission(permission):
    """No posted originals, successful carrier or renewed context enter here."""
    if type(permission) is not execution._ActivationPermission:
        execution._fail("consume completion requires the actual active permission")
    permission._identity()
    owner, work = permission._owner, permission._work
    parent, binding, custody = owner._material, owner._binding, owner._custody
    policy = parent.consume_execution
    originals, continuation = permission._consume_sql_originals, permission._consume_sql_context
    sql_outcome, activation_raw = permission._consume_sql_outcome, permission._sql_originals
    signing, authorization = permission._consume_signing, permission._consume_authorization
    if (permission._state != "active" or permission._dispatch_phase != "consume-completing"
            or permission._consume_completion_spent is not True
            or type(policy) is not configured._ConsumeExecutionMaterial or policy.completion_endpoint is None
            or originals is not permission._consume_sql_seal or continuation is not permission._consume_sql_context_seal
            or sql_outcome is not permission._consume_sql_outcome_seal or activation_raw is not permission._sql_seal
            or authorization is not permission._consume_authorization_seal or signing is not permission._consume_signing_seal):
        execution._fail("consume completion is not the configured one-use SQL continuation")
    before, guard, prior_narrow, prior_bytes = continuation
    endpoint = transport._endpoint(policy.completion_endpoint)
    predecessor = reservations._predecessor_scope(*policy.reservation_predecessor)
    selected = transport._originals((transport.PURPOSE, originals[0]), response=False)
    target = permission._target[2]["localDigest"]
    caller.shape._digest(target)
    root, planner, operation_key = binding.runtime_root_public_key, policy.planner_public_key, policy.operation_public_key
    common = {"authorization_enrollment_bytes": policy.authorization_enrollment_bytes,
        "current_root_enrollment_bytes": policy.current_root_enrollment_bytes,
        "grant_enrollment_bytes": policy.grant_enrollment_bytes,
        "root_public_key": root, "configuration_digest": parent.configuration_digest,
        "planner_public_key": planner, "operation_public_key": operation_key}
    reserved_bytes = (prior_bytes + len(transport.PURPOSE) + len(originals[0])
        + transport.REQUEST_HEADER_BYTES + transport.MAX_RESPONSE_BYTES + transport.RESPONSE_HEADER_BYTES)
    if reserved_bytes > caller.MAX_ORIGINAL_BYTES:
        execution._fail("consume completion whole-held originals and response exceed their aggregate bound")

    def base_current():
        if (owner._material is not parent or owner._binding is not binding or owner._custody is not custody
                or parent.consume_execution is not policy or policy.completion_endpoint != endpoint
                or policy.reservation_predecessor != predecessor or permission._consume_sql_originals is not originals
                or permission._consume_sql_context is not continuation or permission._consume_sql_outcome is not sql_outcome
                or permission._sql_originals is not activation_raw or permission._consume_signing is not signing
                or permission._consume_authorization is not authorization or permission._dispatch_phase not in (
                    "consume-completing", "consume-completion-observed")):
            execution._fail("consume completion changed its original authority or cold resources")
        return guard()

    def continuity(epoch, monotonic):
        permission._continuity(epoch, monotonic)
        base_current()
        return permission._planning_observed

    base_current()
    planning._same_bytes(originals[0], authorization, work, "consume completion signed caller")
    expected = planning.activation._object(originals[3], caller.expectations_wire.MAX_BYTES, work)
    expected = caller.expectations_wire._capture_on_work(expected, work=work)
    window, bound = permission._planning_bounds
    held = caller._capture_on_work(**common, originals=originals[1:3], expectations=expected,
        before_vector_bytes=before, live_window=window, transport_deadline_ns=bound,
        work=work, extra_originals=(authorization,))
    actual_clock = caller._clock(held, work, continuity=continuity)
    authorized = caller._verify_held_on_work(held, authorization, work, current=actual_clock)
    original_plan = caller.contract._decode_on_work(held.originals[0], envelope=True, work=work)["payload"]
    activation_digest = plan._frame(execution.caller.REQUEST_IDENTITY_DOMAIN, (activation_raw[0],), work)
    grant = grant_enrollment = state_material = reserve = completed_material = complete = None

    def current():
        base_current()
        epoch, monotonic = authorized.live()
        epoch, monotonic = continuity(epoch, monotonic)
        if epoch >= window[3] or monotonic >= bound:
            execution._fail("consume completion original authority expired")
        if grant is not None:
            caller.evidence._fresh(grant, epoch, grant_enrollment.payload["maximumGrantAgeNs"],
                min(window[6], grant_enrollment.payload["maximumClockSkewNs"]))
        if reserve is not None:
            state._fresh(reserve, state_material, epoch)
        if complete is not None:
            state._fresh(complete, completed_material, epoch)
        return epoch

    def narrow(expires, maximum_age, maximum_skew):
        nonlocal window, bound
        prior_narrow(expires, min(window[5], maximum_age), min(window[6], maximum_skew))
        selected_window, selected_bound = permission._planning_bounds
        if (selected_window[:3] != window[:3] or selected_bound > bound
                or any(selected_window[index] > window[index] for index in (3, 4, 5, 6))):
            execution._fail("consume completion replaced or widened the original allowance")
        window, bound = selected_window, selected_bound
        current()

    narrow(authorized.expires_at_epoch_ns, policy.maximum_age_ns, policy.maximum_clock_skew_ns)
    grant_enrollment = caller.enrollments._admit_enrollment_on_work(
        grant_enrollment_bytes=held.grant_enrollment, current_root_enrollment_bytes=held.current_enrollment,
        root_public_key=held.root, work=work)
    caller.primitives._separate(grant_enrollment.authorizer_public_key, (held.planner, held.operation_key), work)
    grant, grant_digest = dispatch._grant(originals[4], held, authorized, original_plan,
        grant_enrollment, current, window, work)
    grant_age = grant_enrollment.payload["maximumGrantAgeNs"]
    narrow(min(grant["expiresAtEpochNs"], grant["issuedAtEpochNs"] + grant_age),
        grant_age, grant_enrollment.payload["maximumClockSkewNs"])
    state_material, reserve, marker, after, receipt_digest = _controls(originals, held, authorized,
        grant, grant_digest, predecessor, current, work)
    reserve_age = state_material.payload["maxControlAgeNs"]
    narrow(min(reserve["expiresAtEpochNs"], reserve["issuedAtEpochNs"] + reserve_age),
        reserve_age, state_material.payload["maxClockSkewNs"])
    current()
    response = transport._socket_request_on_work(endpoint, originals=selected,
        deadline_ns=bound, work=work, current=current)
    current()
    response = transport._originals(response, response=True)
    work.charge(input_bytes=retained._append_io_bytes("completion-outcome", response))
    current()
    identity = production._callback(work, lambda:
        execution.custody.ControlPlaneCustodyClient.append_oidc_session_activation_consume_completion_outcome(
            custody, finalization_digest=target, activation_authorization_digest=activation_digest, originals=response))
    current()
    caller.shape._digest(identity)
    # Preserve the exact first response before interpreting even its selector.
    if response[0] == b"acknowledged":
        completed_material, complete, complete_digest = state._verify_request_on_work(
            request_bytes=response[2], enrollment_bytes=held.current_enrollment,
            root_public_key=held.root, now_epoch_ns=current(), work=work)
        acknowledged = acknowledgments._verify_ack_on_work(request_bytes=response[2], receipt_bytes=response[3],
            enrollment_bytes=held.current_enrollment, root_public_key=held.root,
            expected_pending_sequence=predecessor[0] + 1,
            expected_pending_head_digest=receipt_digest, work=work)
        plan._same(acknowledged.request_payload, complete, work, "consume completion control readback")
        plan._same(acknowledged.request_digest, complete_digest, work, "consume completion control identity")
        planning._same_bytes(response[1], complete_digest.encode("ascii"), work, "consume complete response identity")
        plan._same(complete["action"], "complete", work, "consume completion fixed action")
        for field, column in neutral._REQUEST_MARKER_JOINS:
            plan._same(complete[field], marker[column], work, "consume completion original marker " + field)
        _observation(complete, marker, after, work)
        maximum_age = completed_material.payload["maxControlAgeNs"]
        narrow(min(complete["expiresAtEpochNs"], complete["issuedAtEpochNs"] + maximum_age),
            maximum_age, completed_material.payload["maxClockSkewNs"])
    permission._consume_completion_originals = permission._consume_completion_seal = response
    permission._consume_completion_context = permission._consume_completion_context_seal = (
        after, current, narrow, reserved_bytes)
    permission._dispatch_phase = "consume-completion-observed"
    current()
    return response
