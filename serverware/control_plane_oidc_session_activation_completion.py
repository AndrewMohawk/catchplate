"""Original-only public completion controls inside the active SQL continuation.

The isolated completion service retains private history/commit replay. This
caller authenticates its returned signed controls and exact original marker
bindings, not independent SQL truth, packet identity, token release or latest
session state. No successful result carrier is accepted as authority.
"""
from __future__ import annotations

from serverware import authority_current_root_authorization as state
from serverware import authority_current_root_completion as observations
from serverware import authority_current_root_computation as computation
from serverware import authority_current_root_delivery_records as acknowledgments
from serverware import authority_current_root_execution_admission as pending
from serverware import authority_oidc_session_activation_completion_dispatch_transport as transport
from serverware import authority_oidc_session_activation_reservation_records as reservations
from serverware import authority_registration_completion_response as neutral
from serverware import control_plane_oidc_session_activation_execution as execution
from serverware import control_plane_oidc_session_activation_records as retained


caller, plan, production = execution.caller, execution.plan, execution.production


def _same_bytes(actual, expected, work, label):
    work.charge(input_bytes=len(actual) + len(expected))
    if actual != expected:
        execution._fail("activation completion original " + label + " differs")


def _observation(request, marker, after_bytes, work):
    """Canonical signed statement joined only to this call's original controls."""
    raw = state.transport._decode(request["writerReceiptBase64Url"],
        request["writerReceiptByteCount"], observations.MAX_OBSERVATION_BYTES, work)
    document = state.wire._decode_object(raw, work=work,
        maximum_bytes=observations.MAX_OBSERVATION_BYTES,
        maximum_nodes=observations.MAX_OBSERVATION_NODES, maximum_depth=3)
    state.shape._object(document, neutral._OBSERVATION_FIELDS, "activation completion observation")
    state.shape._literal(document["schema"], observations.OBSERVATION_SCHEMA)
    state.shape._literal(document["sourceRevision"], state.authority.SOURCE_REVISION)
    state.shape._object(document["marker"], frozenset(pending._MARKER_COLUMNS),
        "activation completion observation marker")
    plan._same(document["marker"], marker, work,
        "activation completion observation differs from original public controls")
    after_digest = state.vector._digest_on_work(after_bytes, work=work)
    for actual in (marker["after_vector_digest"], request["afterVectorDigest"], document["afterVectorDigest"]):
        plan._same(actual, after_digest, work, "activation completion signed full after-vector")
    observed = document["observedAtEpochNs"]
    state.shape._integer(observed, minimum=1)
    if not request["issuedAtEpochNs"] <= observed < request["expiresAtEpochNs"]:
        execution._fail("activation completion observation escapes its signed interval")
    expected = observations._observation_bytes(marker, after_digest, observed, work)
    _same_bytes(raw, expected, work, "canonical signed observation")


def _complete_on_permission(permission, *, before_vector_bytes, current, narrow, deadline_ns):
    """Fixed private dispatch suffix; callbacks are its actual closed guards.

    No API forwards a posted callback, phase, marker or previous verification
    result here. Every expected marker field comes from original signed bytes
    sealed by the same active context before SQL, never from its raw4 outcome.
    """
    if type(permission) is not execution._ActivationPermission:
        execution._fail("activation completion requires its actual active permission")
    owner, work, originals = permission._owner, permission._work, permission._sql_originals
    parent, binding, custody = owner._material, owner._binding, owner._custody
    policy = parent.activation_execution
    root, planner, operation_key = (permission._scope.common[name]
        for name in ("root_public_key", "planner_public_key", "operation_public_key"))
    enrollment, grant_enrollment = policy.current_root_enrollment_bytes, policy.grant_enrollment_bytes
    before = state._original(before_vector_bytes, state.vector.MAX_BYTES, "activation completion before-vector")
    if (permission._dispatch_phase != "sql-completion" or originals is not permission._sql_seal
            or type(originals) is not tuple or len(originals) != 8
            or any(type(raw) is not bytes for raw in originals) or policy.completion_endpoint is None):
        execution._fail("activation completion is not the sealed one-use SQL continuation")
    endpoint = transport._endpoint(policy.completion_endpoint)
    predecessor = reservations._predecessor_scope(*policy.reservation_predecessor)
    finalization_digest = permission._target[2]["localDigest"]
    selected = transport._originals((transport.PURPOSE, originals[0]), response=False)
    permission._identity()

    def live():
        if (permission._sql_originals is not originals or permission._sql_seal is not originals
                or permission._dispatch_phase != "sql-completion" or owner._material is not parent
                or owner._binding is not binding or owner._custody is not custody
                or parent.activation_execution is not policy or policy.completion_endpoint != endpoint):
            execution._fail("activation completion replaced its actual sealed continuation")
        return current()

    live()
    authorization_digest = plan._frame(caller.REQUEST_IDENTITY_DOMAIN, (originals[0],), work)
    grant, grant_digest = caller.grants._verify_control_on_work(grant_bytes=originals[4],
        grant_enrollment_bytes=grant_enrollment, current_root_enrollment_bytes=enrollment,
        root_public_key=root, planner_public_key=planner, operation_public_key=operation_key,
        expected_authorization_digest=authorization_digest, now_epoch_ns=live(), work=work)
    material, reserve, reserve_digest = state._verify_request_on_work(request_bytes=originals[5],
        enrollment_bytes=enrollment, root_public_key=root, now_epoch_ns=live(), work=work)
    checked, checked_digest, receipt, receipt_digest = reservations._verify_on_work(
        request_bytes=originals[5], snapshot_bytes=originals[6], receipt_bytes=originals[7],
        enrollment_bytes=enrollment, root_public_key=root,
        expected_predecessor_sequence=predecessor[0], expected_predecessor_head_digest=predecessor[1],
        expected_fence=predecessor[2], work=work)
    plan._same(checked, reserve, work, "activation completion original reserve readback")
    plan._same(checked_digest, reserve_digest, work, "activation completion original reserve identity")
    if receipt is None or receipt_digest is None:
        execution._fail("activation completion has no original reserve acknowledgment")
    plan._same(reserve["operation"], caller.OPERATION, work, "activation completion fixed operation")
    plan._same(reserve["capabilityDigest"], grant_digest, work, "activation completion exact grant")
    snapshot = computation._decode_snapshot_on_work(originals[6], work=work)
    for field in ("sourceRevision", "databaseId", "generationDigest", "operation", "requestDigest",
            "operationId", "retainedRecordDigest", "planDigest", "beforeVectorDigest",
            "afterVectorDigest", "resultDigest", "originalFrames", "originalIssuedAtEpochNs",
            "originalExpiresAtEpochNs", "signedSnapshotDigest", "signedCapabilityId"):
        plan._same(snapshot[field], grant[field], work, "activation completion snapshot/grant " + field)
    plan._same(snapshot["capabilityDigest"], grant_digest, work, "activation completion snapshot grant")
    actual_before = state.vector._encode_on_work(reserve["beforeVector"], work=work)
    _same_bytes(actual_before, before, work, "independent before-vector")
    after = state.vector._encode_on_work(reserve["afterVector"], work=work)
    marker = pending._marker(material, reserve, reserve_digest, receipt, receipt_digest, snapshot, work)
    live()
    response = transport._socket_request_on_work(endpoint, originals=selected,
        deadline_ns=deadline_ns, work=work, current=live)
    live()
    response = transport._originals(response, response=True)
    work.charge(input_bytes=retained._append_io_bytes("completion-outcome", response))
    live()
    production._callback(work, lambda: execution.custody.ControlPlaneCustodyClient.append_oidc_session_activation_completion_outcome(
        custody, finalization_digest=finalization_digest, originals=response))
    live()
    # Exact bytes survive before branch, identity or signature interpretation.
    if response[0] == b"uncertain":
        return response
    completed_material, complete, complete_digest = state._verify_request_on_work(
        request_bytes=response[2], enrollment_bytes=enrollment, root_public_key=root,
        now_epoch_ns=live(), work=work)
    acknowledged = acknowledgments._verify_ack_on_work(request_bytes=response[2], receipt_bytes=response[3],
        enrollment_bytes=enrollment, root_public_key=root,
        expected_pending_sequence=predecessor[0] + 1,
        expected_pending_head_digest=receipt_digest, work=work)
    plan._same(acknowledged.request_payload, complete, work, "activation completion control readback")
    plan._same(acknowledged.request_digest, complete_digest, work, "activation completion control identity")
    _same_bytes(response[1], complete_digest.encode("ascii"), work, "returned complete identity")
    plan._same(complete["action"], "complete", work, "activation completion action")
    for field, column in neutral._REQUEST_MARKER_JOINS:
        plan._same(complete[field], marker[column], work, "activation completion original marker " + field)
    _observation(complete, marker, after, work)
    state._fresh(complete, completed_material, live())
    policy_age = completed_material.payload["maxControlAgeNs"]
    narrow(min(complete["expiresAtEpochNs"], complete["issuedAtEpochNs"] + policy_age),
        policy_age, completed_material.payload["maxClockSkewNs"])
    state._fresh(complete, completed_material, live())
    # Originals only; the actual context exit retains the newly narrowed guard.
    return response
