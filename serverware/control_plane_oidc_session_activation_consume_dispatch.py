"""One configured consume grant/reserve/SQL dispatch on live permission.

Only genuine public original controls are checked here; private consume replay
and AES custody stay in their isolated roles. The exact unsigned SQL response
is durably retained, never promoted to completion, release or current session.
"""
from __future__ import annotations

from serverware import authority_current_root_authorization as state
from serverware import authority_oidc_session_activation_delivery_computation as computation
from serverware import authority_oidc_session_activation_delivery_execution_authorization as caller
from serverware import authority_oidc_session_activation_delivery_execution_authorizer_transport as grant_io
from serverware import authority_oidc_session_activation_delivery_execution_grant as grants
from serverware import authority_oidc_session_activation_delivery_reservation_records as reservations
from serverware import authority_oidc_session_activation_delivery_reservation_transport as reserve_io
from serverware import authority_oidc_session_activation_delivery_sql_transport as sql_io
from serverware import control_plane_oidc_session_activation_consume_execution_bootstrap as configured
from serverware import control_plane_oidc_session_activation_consume_planning as planning
from serverware import control_plane_oidc_session_activation_consume_records as retained
from serverware import control_plane_oidc_session_activation_execution as execution


plan, production = caller.plan, caller.production


def _append(owner, target, activation_digest, kind, originals, work, current):
    methods = {
        "grant": execution.custody.ControlPlaneCustodyClient.append_oidc_session_activation_consume_grant,
        "reserved": execution.custody.ControlPlaneCustodyClient.append_oidc_session_activation_consume_reservation,
        "sql-outcome": execution.custody.ControlPlaneCustodyClient.append_oidc_session_activation_consume_sql_outcome,
    }
    method = methods[kind]
    work.charge(input_bytes=retained._append_io_bytes(kind, originals))
    current()
    identity = production._callback(work, lambda: method(owner,
        finalization_digest=target, activation_authorization_digest=activation_digest, originals=originals))
    current()
    caller.shape._digest(identity)


def _grant(original, held, authorized, original_plan, enrollment, current, window, work):
    """Authenticate consume signatures and controls without a replay carrier."""
    current()
    payload, digest = grants._verify_signature_on_work(original, enrollment.authorizer_public_key, work)
    policy = enrollment.payload
    bindings = {
        "grantEnrollmentDigest": enrollment.enrollment_digest,
        "currentRootEnrollmentDigest": policy["currentRootEnrollmentDigest"],
        "configurationDigest": held.configuration_digest,
        "databaseId": policy["databaseId"], "generationDigest": policy["generationDigest"],
        "authorizerMeasurementDigest": policy["authorizer"]["measurementDigest"],
        "operation": caller.OPERATION, "requestDigest": authorized.request_digest,
        "operationId": authorized.operation_id, "requestAuthorizationDigest": authorized.authorization_digest,
        "journalDigest": authorized.journal_digest, "retainedRecordDigest": authorized.retained_record_digest,
        "planDigest": authorized.plan_digest, "beforeVectorDigest": authorized.before_vector_digest,
        "originalIssuedAtEpochNs": original_plan["issuedAtEpochNs"],
        "originalExpiresAtEpochNs": original_plan["expiresAtEpochNs"],
    }
    for field, expected in bindings.items():
        plan._same(payload[field], expected, work, "consume grant original " + field)
    frames = [{"position": position, "bytesDigest": planning.assertion._digest(raw, work),
        "byteCount": len(raw)} for position, raw in enumerate(held.originals)]
    plan._same(payload["originalFrames"], frames, work, "consume grant exact original frames")
    if not (payload["issuedAtEpochNs"] == original_plan["issuedAtEpochNs"]
            <= authorized.issued_at_epoch_ns < authorized.expires_at_epoch_ns
            <= payload["originalExpiresAtEpochNs"]
            and payload["expiresAtEpochNs"] <= min(authorized.expires_at_epoch_ns, window[3])):
        execution._fail("consume grant renews or retimes original caller permission")
    caller.evidence._fresh(payload, current(), policy["maximumGrantAgeNs"],
        min(policy["maximumClockSkewNs"], window[6]))
    return payload, digest


def _reserve(originals, held, authorized, grant_payload, grant_digest, predecessor, current, work):
    """Admit signed consume reserve/snapshot/ACK controls, not private replay."""
    current()
    material, request, request_digest = state._verify_request_on_work(
        request_bytes=originals[0], enrollment_bytes=held.current_enrollment,
        root_public_key=held.root, now_epoch_ns=current(), work=work)
    for field, expected in (("action", "reserve"), ("operation", caller.OPERATION),
            ("requestDigest", authorized.request_digest), ("operationId", authorized.operation_id),
            ("capabilityDigest", grant_digest), ("predecessorSequence", predecessor[0]),
            ("predecessorHeadDigest", predecessor[1]), ("fence", predecessor[2]),
            ("enrollmentDigest", grant_payload["currentRootEnrollmentDigest"]),
            ("databaseId", grant_payload["databaseId"]), ("generationDigest", grant_payload["generationDigest"])):
        plan._same(request[field], expected, work, "consume reserve exact original " + field)
    if (request["issuedAtEpochNs"] != grant_payload["issuedAtEpochNs"]
            or request["expiresAtEpochNs"] > min(grant_payload["expiresAtEpochNs"], authorized.window[3])):
        execution._fail("consume reserve renews or retimes original authority")
    before = state.vector._encode_on_work(request["beforeVector"], work=work)
    planning._same_bytes(before, held.before, work, "consume reservation before-vector")
    after = state.vector._encode_on_work(request["afterVector"], work=work)
    for field, raw in (("beforeVectorDigest", before), ("afterVectorDigest", after)):
        plan._same(state.vector._digest_on_work(raw, work=work), grant_payload[field], work,
            "consume reserve/grant " + field)
    snapshot = computation._decode_snapshot_on_work(originals[1], work=work)
    for field in ("sourceRevision", "databaseId", "generationDigest", "operation", "requestDigest",
            "operationId", "retainedRecordDigest", "planDigest", "beforeVectorDigest", "afterVectorDigest",
            "resultDigest", "originalFrames", "originalIssuedAtEpochNs", "originalExpiresAtEpochNs"):
        plan._same(snapshot[field], grant_payload[field], work, "consume snapshot/grant " + field)
    plan._same(snapshot["capabilityDigest"], grant_digest, work, "consume snapshot actual grant identity")
    current()
    checked, checked_digest, receipt, receipt_digest = reservations._verify_on_work(
        request_bytes=originals[0], snapshot_bytes=originals[1], receipt_bytes=originals[2],
        enrollment_bytes=held.current_enrollment, root_public_key=held.root,
        expected_predecessor_sequence=predecessor[0], expected_predecessor_head_digest=predecessor[1],
        expected_fence=predecessor[2], work=work)
    plan._same(checked_digest, request_digest, work, "consume original reserve identity")
    plan._same(checked, request, work, "consume original reserve readback")
    if receipt is None or receipt_digest is None:
        execution._fail("consume reserve lacks an authenticated original state acknowledgment")
    state._fresh(request, material, current())
    return material, request, receipt_digest


def _dispatch_on_permission(permission):
    """No original/result ingress or restored context can enter this path."""
    if type(permission) is not execution._ActivationPermission:
        execution._fail("consume dispatch requires the actual active permission")
    permission._identity()
    owner, work = permission._owner, permission._work
    parent, binding, custody = owner._material, owner._binding, owner._custody
    policy = parent.consume_execution
    originals, continuation = permission._consume_originals, permission._consume_context
    authorization = permission._consume_authorization
    activation_raw = permission._sql_originals
    signing = permission._consume_signing
    if (permission._state != "active" or permission._dispatch_phase != "consume-dispatching"
            or permission._consume_dispatch_spent is not True
            or type(policy) is not configured._ConsumeExecutionMaterial
            or policy.reservation_endpoint is None or policy.reservation_predecessor is None or policy.sql_endpoint is None
            or originals is not permission._consume_originals_seal or continuation is not permission._consume_context_seal
            or authorization is not permission._consume_authorization_seal
            or activation_raw is not permission._sql_seal or signing is not permission._consume_signing_seal):
        execution._fail("consume downstream dispatch is not the configured one-use continuation")
    prepared, exported = originals
    before, guard, prior_narrow, prior_bytes = continuation
    grant_endpoint = grant_io._endpoint(policy.authorizer_endpoint)
    reserve_endpoint = reserve_io._endpoint(policy.reservation_endpoint)
    sql_endpoint = sql_io._endpoint(policy.sql_endpoint)
    predecessor = reservations._predecessor_scope(*policy.reservation_predecessor)
    target = permission._target[2]["localDigest"]
    caller.shape._digest(target)
    common = {"authorization_enrollment_bytes": policy.authorization_enrollment_bytes,
        "current_root_enrollment_bytes": policy.current_root_enrollment_bytes,
        "grant_enrollment_bytes": policy.grant_enrollment_bytes,
        "root_public_key": binding.runtime_root_public_key, "configuration_digest": parent.configuration_digest,
        "planner_public_key": policy.planner_public_key, "operation_public_key": policy.operation_public_key}
    raw2 = exported[3], exported[4]

    def base_current():
        if (owner._material is not parent or owner._binding is not binding or owner._custody is not custody
                or parent.consume_execution is not policy or permission._consume_originals is not originals
                or permission._consume_context is not continuation or permission._consume_authorization is not authorization
                or permission._sql_originals is not activation_raw or permission._consume_signing is not signing
                or policy.authorizer_endpoint != grant_endpoint or policy.reservation_endpoint != reserve_endpoint
                or policy.sql_endpoint != sql_endpoint or policy.reservation_predecessor != predecessor):
            execution._fail("consume dispatch changed its original authority or cold resources")
        return guard()

    def continuity(epoch, monotonic):
        permission._continuity(epoch, monotonic)
        base_current()
        return permission._planning_observed

    base_current()
    request = planning.activation._object(prepared[1], planning.bootstrap.history.MAX_CONSUME_REQUEST_BYTES, work)
    scope = planning.activation._object(prepared[2], caller.expectations_wire.MAX_BYTES, work)
    work.charge(input_bytes=len(prepared[5]))
    journal_digest = prepared[5].decode("ascii")
    expectations = caller.expectations_wire._capture_on_work(
        {"request": request, "scope": scope, "journalDigest": journal_digest}, work=work)
    activation_digest = plan._frame(execution.caller.REQUEST_IDENTITY_DOMAIN, (activation_raw[0],), work)
    window, bound = permission._planning_bounds
    held = caller._capture_on_work(**common, originals=raw2, expectations=expectations,
        before_vector_bytes=before, live_window=window, transport_deadline_ns=bound,
        work=work, extra_originals=(authorization,))
    actual_clock = caller._clock(held, work, continuity=continuity)
    authorized = caller._verify_held_on_work(held, authorization, work, current=actual_clock)
    original_plan = caller.contract._decode_on_work(held.originals[0], envelope=True, work=work)["payload"]
    canonical_expectations = caller.registration._wire(held.expectations, work)
    grant_request = grant_io._originals((authorization, *held.originals, canonical_expectations), response=False)
    grant_payload = grant_enrollment = state_material = reserve_request = None
    window, bound = permission._planning_bounds

    def current():
        base_current()
        now, monotonic = authorized.live()
        now, monotonic = continuity(now, monotonic)
        if now >= window[3] or monotonic >= bound:
            execution._fail("consume dispatch original authority expired")
        if grant_payload is not None:
            caller.evidence._fresh(grant_payload, now, grant_enrollment.payload["maximumGrantAgeNs"],
                min(window[6], grant_enrollment.payload["maximumClockSkewNs"]))
        if reserve_request is not None:
            state._fresh(reserve_request, state_material, now)
        return now

    def narrow(expires, maximum_age, maximum_skew):
        nonlocal window, bound
        prior_narrow(expires, min(window[5], maximum_age), min(window[6], maximum_skew))
        selected, selected_bound = permission._planning_bounds
        if selected[:3] != window[:3] or any(selected[index] > window[index] for index in (3, 4, 5, 6)):
            execution._fail("consume dispatch replaced or widened its original bracket")
        window, bound = selected, min(bound, selected_bound)
        current()

    narrow(authorized.expires_at_epoch_ns, policy.maximum_age_ns, policy.maximum_clock_skew_ns)
    grant_enrollment = caller.enrollments._admit_enrollment_on_work(
        grant_enrollment_bytes=held.grant_enrollment, current_root_enrollment_bytes=held.current_enrollment,
        root_public_key=held.root, work=work)
    caller.primitives._separate(grant_enrollment.authorizer_public_key, (held.planner, held.operation_key), work)
    narrow(window[3], grant_enrollment.payload["maximumGrantAgeNs"], grant_enrollment.payload["maximumClockSkewNs"])
    reserved_bytes = (prior_bytes + len(authorization) + len(canonical_expectations)
        + sum(map(len, (held.caller_enrollment, held.current_enrollment, held.grant_enrollment)))
        + sum(module.MAX_RESPONSE_BYTES + module.REQUEST_HEADER_BYTES + module.RESPONSE_HEADER_BYTES
            for module in (grant_io, reserve_io, sql_io)))
    if reserved_bytes > caller.MAX_ORIGINAL_BYTES:
        execution._fail("consume dispatch whole-held originals and responses exceed their aggregate bound")
    current()
    grant_original = grant_io._socket_request_on_work(grant_endpoint, originals=grant_request,
        deadline_ns=bound, work=work, current=current)
    grant_original = grant_io._originals((grant_original,), response=True)[0]
    _append(custody, target, activation_digest, "grant", (grant_original,), work, current)
    grant_payload, grant_digest = _grant(grant_original, held, authorized, original_plan,
        grant_enrollment, current, window, work)
    narrow(grant_payload["expiresAtEpochNs"], window[5], window[6])
    reserved = reserve_io._socket_request_on_work(reserve_endpoint,
        originals=reserve_io._originals((*grant_request, grant_original), response=False),
        deadline_ns=bound, work=work, current=current)
    reserved = reserve_io._originals(reserved, response=True)
    _append(custody, target, activation_digest, "reserved", reserved, work, current)
    state_material, reserve_request, pending_digest = _reserve(reserved, held, authorized,
        grant_payload, grant_digest, predecessor, current, work)
    narrow(reserve_request["expiresAtEpochNs"], state_material.payload["maxControlAgeNs"],
        state_material.payload["maxClockSkewNs"])
    sql_originals = sql_io._originals((*grant_request, grant_original, *reserved), response=False)
    work.charge(input_bytes=retained._append_io_bytes("sql-claimed", ()))
    current()
    production._callback(work, lambda: execution.custody.ControlPlaneCustodyClient.claim_oidc_session_activation_consume_sql_attempt(
        custody, finalization_digest=target, activation_authorization_digest=activation_digest))
    current()
    permission._consume_sql_originals = permission._consume_sql_seal = sql_originals
    permission._consume_sql_context = permission._consume_sql_context_seal = (before, current, narrow, reserved_bytes)
    permission._dispatch_phase = "consume-sql"
    response = sql_io._socket_request_on_work(sql_endpoint, originals=sql_originals,
        deadline_ns=bound, work=work, current=current)
    response = sql_io._originals(response, response=True)
    _append(custody, target, activation_digest, "sql-outcome", response, work, current)
    work.charge(input_bytes=71)
    if response[1] and response[1] != pending_digest.encode("ascii"):
        execution._fail("consume SQL observation names another original pending decision")
    current()
    permission._consume_sql_outcome = permission._consume_sql_outcome_seal = response
    permission._dispatch_phase = "consume-dispatched"
    return response
