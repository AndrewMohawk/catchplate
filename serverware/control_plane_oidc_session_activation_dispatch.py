"""One configured activation grant/reserve/SQL exchange on live permission.

Public original controls are authenticated here. Private business replay stays
inside the actual isolated receiving owners. An unsigned SQL observation is
never promoted to a commit, completion, current session or token release.
"""
from __future__ import annotations

from serverware import authority_oidc_session_activation_execution_authorizer_transport as grant_io
from serverware import authority_oidc_session_activation_reservation_transport as reserve_io
from serverware import authority_oidc_session_activation_sql_transport as sql_io
from serverware import authority_oidc_session_activation_reservation_records as reservations
from serverware import authority_current_root_authorization as state
from serverware import authority_current_root_computation as computation
from serverware import control_plane_oidc_session_activation_execution as execution
from serverware import control_plane_oidc_session_activation_planning as planning
from serverware import control_plane_oidc_session_activation_records as retained
from serverware import control_plane_oidc_session_activation_request_dispatch as request_dispatch
from serverware import control_plane_oidc_session_activation_request_issuance_bootstrap as request_planning


caller, production, plan = execution.caller, execution.production, execution.plan
grants = caller.grants


def _same_bytes(actual, expected, work, label):
    work.charge(input_bytes=len(actual) + len(expected))
    if actual != expected:
        execution._fail("activation dispatch original " + label + " differs")


def _append(owner, finalization_digest, kind, originals, work, current):
    """Only the closed activation journal facade; no generic forward family."""
    methods = {
        "prepared": execution.custody.ControlPlaneCustodyClient.append_oidc_session_activation_preparation,
        "grant": execution.custody.ControlPlaneCustodyClient.append_oidc_session_activation_grant,
        "reserved": execution.custody.ControlPlaneCustodyClient.append_oidc_session_activation_reservation,
        "sql-outcome": execution.custody.ControlPlaneCustodyClient.append_oidc_session_activation_sql_outcome,
    }
    method = methods[kind]
    work.charge(input_bytes=retained._append_io_bytes(kind, originals))
    current()
    result = production._callback(work, lambda: method(owner,
        finalization_digest=finalization_digest, originals=originals))
    current()
    caller.shape._digest(result)


def _grant(*, original, held, authorized, original_plan, enrollment, current, work):
    current()
    payload, digest = grants._verify_control_on_work(grant_bytes=original,
        grant_enrollment_bytes=held.grant_enrollment, current_root_enrollment_bytes=held.current_enrollment,
        root_public_key=held.root, planner_public_key=held.planner, operation_public_key=held.operation_key,
        expected_authorization_digest=authorized.authorization_digest, now_epoch_ns=current(), work=work)
    for field, expected in (("operation", caller.OPERATION), ("requestDigest", authorized.request_digest),
            ("operationId", authorized.operation_id), ("planDigest", authorized.plan_digest),
            ("retainedRecordDigest", authorized.retained_record_digest),
            ("beforeVectorDigest", authorized.before_vector_digest),
            ("grantEnrollmentDigest", enrollment.enrollment_digest),
            ("originalIssuedAtEpochNs", original_plan["issuedAtEpochNs"]),
            ("originalExpiresAtEpochNs", original_plan["expiresAtEpochNs"])):
        plan._same(payload[field], expected, work, "activation grant original " + field)
    frames = []
    for position, raw in enumerate(held.originals):
        frames.append({"position": position, "bytesDigest": planning.assertion._digest(raw, work),
            "byteCount": len(raw)})
    plan._same(payload["originalFrames"], frames, work, "activation grant exact original frames")
    if not (payload["issuedAtEpochNs"] <= authorized.issued_at_epoch_ns
            < authorized.expires_at_epoch_ns <= payload["originalExpiresAtEpochNs"]
            and payload["expiresAtEpochNs"] <= authorized.expires_at_epoch_ns):
        execution._fail("activation grant renews original caller permission")
    current()
    return payload, digest


def _reserve(*, originals, held, authorized, grant_payload, grant_digest,
        predecessor, current, work):
    """Authenticate public originals/ancestry, not private plan semantics."""
    current()
    material, request, request_digest = state._verify_request_on_work(
        request_bytes=originals[0], enrollment_bytes=held.current_enrollment,
        root_public_key=held.root, now_epoch_ns=current(), work=work)
    for field, expected in (("action", "reserve"), ("operation", caller.OPERATION),
            ("requestDigest", authorized.request_digest), ("operationId", authorized.operation_id),
            ("capabilityDigest", grant_digest), ("predecessorSequence", predecessor[0]),
            ("predecessorHeadDigest", predecessor[1]), ("fence", predecessor[2]),
            ("enrollmentDigest", grant_payload["currentRootEnrollmentDigest"]),
            ("databaseId", grant_payload["databaseId"]),
            ("generationDigest", grant_payload["generationDigest"])):
        plan._same(request[field], expected, work, "activation reserve exact original " + field)
    if (request["issuedAtEpochNs"] != grant_payload["issuedAtEpochNs"]
            or request["expiresAtEpochNs"] > min(grant_payload["expiresAtEpochNs"], authorized.window[3])):
        execution._fail("activation reserve renews or retimes original authority")
    before = state.vector._encode_on_work(request["beforeVector"], work=work)
    _same_bytes(before, held.before, work, "reservation before-vector")
    after = state.vector._encode_on_work(request["afterVector"], work=work)
    for field, raw in (("beforeVectorDigest", before), ("afterVectorDigest", after)):
        plan._same(state.vector._digest_on_work(raw, work=work), grant_payload[field],
            work, "activation reserve/grant " + field)
    snapshot = computation._decode_snapshot_on_work(originals[1], work=work)
    for field in ("sourceRevision", "databaseId", "generationDigest", "operation", "requestDigest",
            "operationId", "retainedRecordDigest", "planDigest", "beforeVectorDigest",
            "afterVectorDigest", "resultDigest", "originalFrames", "originalIssuedAtEpochNs",
            "originalExpiresAtEpochNs", "signedSnapshotDigest", "signedCapabilityId"):
        plan._same(snapshot[field], grant_payload[field], work, "activation snapshot/grant " + field)
    plan._same(snapshot["capabilityDigest"], grant_digest, work, "activation snapshot actual grant identity")
    current()
    checked, checked_digest, receipt, receipt_digest = reservations._verify_on_work(
        request_bytes=originals[0], snapshot_bytes=originals[1], receipt_bytes=originals[2],
        enrollment_bytes=held.current_enrollment, root_public_key=held.root,
        expected_predecessor_sequence=predecessor[0], expected_predecessor_head_digest=predecessor[1],
        expected_fence=predecessor[2], work=work)
    plan._same(checked_digest, request_digest, work, "activation original reserve identity")
    plan._same(checked, request, work, "activation original reserve readback")
    if receipt is None or receipt_digest is None:
        execution._fail("activation reserve has no authenticated original state acknowledgment")
    # The actual records verifier derives sequence=predecessor+1, joins the
    # exact request/vector/interval/fence and frames the signed ACK original.
    # This successor observation is not a newly asserted current-head pin.
    current()
    state._fresh(request, material, current())
    return material, request, receipt_digest


def _dispatch_on_permission(permission, *, assertion_bytes, expected_challenge_id):
    return _dispatch_fixed_on_permission(permission, assertion_bytes=assertion_bytes,
        expected_challenge_id=expected_challenge_id, include_completion=False)


def _dispatch_completion_on_permission(permission, *, assertion_bytes, expected_challenge_id):
    return _dispatch_fixed_on_permission(permission, assertion_bytes=assertion_bytes,
        expected_challenge_id=expected_challenge_id, include_completion=True)


def _dispatch_fixed_on_permission(permission, *, assertion_bytes, expected_challenge_id,
        include_completion):
    """Fixed live continuation; no external original/result carrier ingress."""
    if type(permission) is not execution._ActivationPermission:
        execution._fail("activation dispatch requires the actual active permission context")
    permission._identity()
    if permission._dispatch_phase != ("preparing-completion" if include_completion else "preparing"):
        execution._fail("activation dispatch is not the original one-use continuation")
    assertion_original, challenge_id = planning._planning_inputs(assertion_bytes, expected_challenge_id)
    owner, work = permission._owner, permission._work
    parent, binding, custody_owner = owner._material, owner._binding, owner._custody
    policy, planning_policy = parent.activation_execution, parent.activation_planning
    dynamic = policy.request_bound is True
    if (policy.reservation_endpoint is None or policy.sql_endpoint is None
            or dynamic and (policy.reservation_predecessor is not None
                or type(planning_policy) is not request_planning._RequestPlanningMaterial)
            or not dynamic and (policy.reservation_predecessor is None
                or type(planning_policy) is not planning.configured._PlanningMaterial)):
        execution._fail("activation downstream dispatch is not independently configured")
    grant_endpoint = grant_io._endpoint(policy.authorizer_endpoint)
    reserve_endpoint = reserve_io._endpoint(policy.reservation_endpoint)
    sql_endpoint = sql_io._endpoint(policy.sql_endpoint)
    completion_endpoint = None
    if include_completion:
        from serverware import authority_oidc_session_activation_completion_dispatch_transport as completion_io

        if policy.completion_endpoint is None:
            execution._fail("activation completion dispatch is not independently configured")
        completion_endpoint = completion_io._endpoint(policy.completion_endpoint)
    predecessor = (None if dynamic else
        reservations._predecessor_scope(*policy.reservation_predecessor))
    finalization_digest = permission._target[2]["localDigest"]
    caller.shape._digest(finalization_digest)
    permission._current()
    raw2, expectations, before, authorization = execution._ActivationPermission.prepare_authorization(
        permission, assertion_bytes=assertion_original, expected_challenge_id=challenge_id)
    if dynamic:
        planner_original, predecessor = request_dispatch._prepared_on_permission(
            permission, before_vector_bytes=before)
    else:
        planner_original = planning_policy.planner_bootstrap_bytes
    window, bound = permission._planning_bounds
    # The result above is genuine same-call output, but every control is still
    # admitted from its original bytes below, never accepted as proof by type.
    held = caller._capture_on_work(**permission._scope.common, originals=raw2,
        expectations=expectations, before_vector_bytes=before, live_window=window,
        transport_deadline_ns=bound, work=work,
        extra_originals=(authorization, assertion_original, permission._original,
            planner_original))
    clock = caller._clock(held, work, continuity=permission._continuity)
    authorized = caller._verify_held_on_work(held, authorization, work, current=clock)
    window, bound = authorized.window, authorized.deadline_ns
    original_plan = caller.activation.contract._decode_on_work(
        held.originals[0], envelope=True, work=work)["payload"]
    canonical_expectations = planning.registration._wire(held.expectations, work)
    prepared = (authorization, *held.originals, canonical_expectations, held.before)
    grant_request = grant_io._originals(prepared[:4], response=False)
    grant_payload = reserve_request = state_material = None
    grant_enrollment = None

    def current():
        if (owner._material is not parent or owner._binding is not binding
                or owner._custody is not custody_owner or parent.activation_execution is not policy
                or parent.activation_planning is not planning_policy
                or policy.authorizer_endpoint != grant_endpoint
                or policy.reservation_endpoint != reserve_endpoint
                or policy.sql_endpoint != sql_endpoint or policy.request_bound is not dynamic
                or policy.reservation_predecessor != (None if dynamic else predecessor)
                or include_completion and policy.completion_endpoint != completion_endpoint):
            execution._fail("activation dispatch changed its original cold configuration")
        if dynamic and request_dispatch._planner_original_on_permission(permission) is not planner_original:
            execution._fail("activation dispatch changed its same-request planner original")
        permission._narrow_planning(window, bound)
        now, monotonic = authorized.live()
        now, monotonic = permission._continuity(now, monotonic)
        if now >= window[3] or monotonic >= bound:
            execution._fail("activation dispatch original authority expired")
        if grant_payload is not None:
            grants.evidence._fresh(grant_payload, now,
                grant_enrollment.payload["maximumGrantAgeNs"],
                grant_enrollment.payload["maximumClockSkewNs"])
        if reserve_request is not None:
            state._fresh(reserve_request, state_material, now)
        return now

    def narrow_completion(expires, maximum_age, maximum_skew):
        # Only the fixed original-consuming completion suffix calls this;
        # values can tighten, never replace, the same signed-authority guard.
        nonlocal window, bound
        window = caller.window_policy._narrow(window, deadline_epoch_ns=expires,
            maximum_lifetime_ns=min(window[5], maximum_age),
            maximum_clock_skew_ns=min(window[6], maximum_skew))
        bound = min(bound, window[4])
        current()

    current()
    grant_enrollment = grants._admit_enrollment_on_work(
        grant_enrollment_bytes=held.grant_enrollment, current_root_enrollment_bytes=held.current_enrollment,
        root_public_key=held.root, work=work)
    window = caller.window_policy._narrow(window, deadline_epoch_ns=window[3],
        maximum_lifetime_ns=grant_enrollment.payload["maximumGrantAgeNs"],
        maximum_clock_skew_ns=grant_enrollment.payload["maximumClockSkewNs"])
    bound = min(bound, window[4])
    # Reserve every bounded later response and the complete held originals
    # before any new response body may be allocated by the fixed transports.
    base_bytes = sum(len(raw) for raw in (*prepared, held.caller_enrollment,
        held.current_enrollment, held.grant_enrollment, assertion_original,
        permission._original, planner_original))
    reserved_bytes = base_bytes + grant_io.MAX_RESPONSE_BYTES + reserve_io.MAX_RESPONSE_BYTES + sql_io.MAX_RESPONSE_BYTES
    reserved_bytes += sum(module.REQUEST_HEADER_BYTES + module.RESPONSE_HEADER_BYTES
        for module in (grant_io, reserve_io, sql_io))
    if include_completion:
        reserved_bytes += (len(completion_io.PURPOSE) + len(authorization)
            + completion_io.REQUEST_HEADER_BYTES + completion_io.RESPONSE_HEADER_BYTES
            + completion_io.MAX_RESPONSE_BYTES)
    if reserved_bytes > grants.replay.MAX_ORIGINAL_BYTES:
        execution._fail("activation complete dispatch originals exceed their aggregate bound")
    current()
    _append(custody_owner, finalization_digest, "prepared", prepared, work, current)
    grant_original = grant_io._socket_request_on_work(grant_endpoint, originals=grant_request,
        deadline_ns=bound, work=work, current=current)
    current()
    grant_original = grant_io._originals((grant_original,), response=True)[0]
    grant_payload, grant_digest = _grant(original=grant_original, held=held,
        authorized=authorized, original_plan=original_plan, enrollment=grant_enrollment,
        current=current, work=work)
    window = caller.window_policy._narrow(window, deadline_epoch_ns=grant_payload["expiresAtEpochNs"],
        maximum_lifetime_ns=window[5], maximum_clock_skew_ns=window[6])
    bound = min(bound, window[4])
    current()
    _append(custody_owner, finalization_digest, "grant", (grant_original,), work, current)
    reserve_originals = reserve_io._socket_request_on_work(reserve_endpoint,
        originals=reserve_io._originals((*grant_request, grant_original), response=False),
        deadline_ns=bound, work=work, current=current)
    current()
    reserve_originals = reserve_io._originals(reserve_originals, response=True)
    state_material, reserve_request, pending_digest = _reserve(originals=reserve_originals,
        held=held, authorized=authorized, grant_payload=grant_payload, grant_digest=grant_digest,
        predecessor=predecessor, current=current, work=work)
    window = caller.window_policy._narrow(window, deadline_epoch_ns=reserve_request["expiresAtEpochNs"],
        maximum_lifetime_ns=state_material.payload["maxControlAgeNs"],
        maximum_clock_skew_ns=state_material.payload["maxClockSkewNs"])
    bound = min(bound, window[4])
    current()
    _append(custody_owner, finalization_digest, "reserved", reserve_originals, work, current)
    sql_originals = sql_io._originals((*grant_request, grant_original, *reserve_originals), response=False)
    work.charge(input_bytes=retained._append_io_bytes("sql-claimed", ()))
    current()
    production._callback(work, lambda: execution.custody.ControlPlaneCustodyClient.claim_oidc_session_activation_sql_attempt(
        custody_owner, finalization_digest=finalization_digest))
    current()
    # This sole source-fixed transition follows genuine original admission,
    # durable exact retention/claim and the last pending-target check. No API
    # accepts a boolean phase, socket outcome or success DTO to reach it.
    permission._sql_originals = permission._sql_seal = sql_originals
    permission._dispatch_phase = "sql-completion" if include_completion else "sql"
    if dynamic:
        from serverware import authority_oidc_session_activation_execution_issuance_transport as issuance_io
        issuance_io._request_on_work(b"activation-sql", originals=sql_originals,
            deadline_ns=bound, work=work, current=current)
        current()
    response = sql_io._socket_request_on_work(sql_endpoint, originals=sql_originals,
        deadline_ns=bound, work=work, current=current)
    current()
    response = sql_io._originals(response, response=True)
    _append(custody_owner, finalization_digest, "sql-outcome", response, work, current)
    work.charge(input_bytes=71)
    if response[1] and response[1] != pending_digest.encode("ascii"):
        execution._fail("activation SQL observation names another original pending decision")
    current()
    if include_completion:
        from serverware import control_plane_oidc_session_activation_completion as completion

        if dynamic:
            issuance_io._request_on_work(b"activation-completion", originals=(*sql_originals, *response),
                deadline_ns=bound, work=work, current=current)
            current()

        complete_originals = completion._complete_on_permission(permission,
            before_vector_bytes=held.before, current=current, narrow=narrow_completion,
            deadline_ns=bound)
        if complete_originals[0] == b"acknowledged":
            # Only the actual original-verifying same-call suffix reaches this
            # branch. Public facades still cannot restore an escaped context.
            permission._completion_originals = permission._completion_seal = complete_originals
            permission._completion_context = permission._completion_context_seal = (held.before, current, narrow_completion)
            permission._dispatch_phase = "completed"
        return response, complete_originals
    # Exact unsigned raw4 only. The durable claim prevents automatic replay;
    # completion, recovery and token handoff require separate original authority.
    return response
