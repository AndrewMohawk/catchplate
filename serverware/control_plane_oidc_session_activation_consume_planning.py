"""One public-original consume prepare/export on the still-live completion.

Per-request root originals arrive only after activation; their actual root
admission cannot be replaced by a returned planner DTO or old journal record.
Private history, state acquisition and AES export stay in the isolated planner.
This module neither consumes SQL state nor releases a token or public session.
"""
from __future__ import annotations

from serverware import authority_current_root_authorization as state
from serverware import authority_oidc_session_activation_delivery_execution_replay as consume
from serverware import authority_oidc_session_activation_delivery_planner_transport as transport
from serverware import authority_oidc_session_activation_reservation_records as reservations
from serverware import control_plane_oidc_session_activation_consume_bootstrap as configured
from serverware import control_plane_oidc_session_activation_consume_records as retained
from serverware import control_plane_oidc_session_activation_execution as execution
from serverware import control_plane_oidc_session_activation_planning as activation
from serverware import oidc_session_activation_delivery_planner_bootstrap as bootstrap


caller, plan, production = execution.caller, execution.plan, execution.production
assertion, registration = consume.assertion, consume.registration
_SUBJECT = (("delivery_id", "deliveryId"), ("user_id", "userId"), ("session_id", "sessionId"),
    ("credential_id", "credentialId"), ("credential_record_id", "credentialRecordId"), ("challenge_id", "challengeId"))


def _inputs(planner_bootstrap_bytes, history_custody_bytes):
    """Bound both immutable root originals before permission/native callbacks."""
    if (type(planner_bootstrap_bytes) is not bytes or not 2 <= len(planner_bootstrap_bytes) <= bootstrap.MAX_BYTES
            or type(history_custody_bytes) is not bytes or not 2 <= len(history_custody_bytes) <= bootstrap.history.MAX_BYTES):
        execution._fail("consume planning requires bounded original planner and history bootstraps")
    return planner_bootstrap_bytes, history_custody_bytes


def _same_bytes(actual, expected, work, label):
    work.charge(input_bytes=len(actual) + len(expected))
    if actual != expected:
        execution._fail("consume planning original " + label + " differs")


def _append(owner, target, authorization_digest, kind, originals, work, current):
    method = (execution.custody.ControlPlaneCustodyClient.append_oidc_session_activation_consume_prepared
        if kind == "prepared" else execution.custody.ControlPlaneCustodyClient.append_oidc_session_activation_consume_exported)
    work.charge(input_bytes=retained._append_io_bytes(kind, originals))
    current()
    identity = production._callback(work, lambda: method(owner, finalization_digest=target,
        activation_authorization_digest=authorization_digest, originals=originals))
    current()
    caller.shape._digest(identity)


def _scope(material, deadline, work):
    payload, arguments = material.payload, material.payload["consumeRequest"]["arguments"]
    return assertion._Capture(execution.capture._SharedLedger(work),
        maximum_bytes=assertion.MAX_CONTEXT_BYTES).visit({
        **{name: arguments[field] for field, name in _SUBJECT},
        "authenticationPolicy": payload["authenticationPolicy"], "trustPolicy": payload["trustPolicy"],
        "configurationDigest": payload["configurationDigest"], "plannerIdentity": payload["planner"]["identity"],
        "plannerSpkiDigest": payload["planner"]["spkiDigest"], "maximumPlanAgeNs": payload["maximumPlanAgeNs"],
        "maximumClockSkewNs": payload["maximumClockSkewNs"], "deadlineEpochNs": deadline})


def _prepare_on_permission(permission, *, planner_bootstrap_bytes, history_custody_bytes):
    """No independent entry/resumption: use the actual acknowledged context."""
    root_original, history_original = _inputs(planner_bootstrap_bytes, history_custody_bytes)
    if type(permission) is not execution._ActivationPermission:
        execution._fail("consume planning requires the actual active permission")
    owner, work, raw = permission._owner, permission._work, permission._sql_originals
    completed, continuation = permission._completion_originals, permission._completion_context
    parent, binding, custody = owner._material, owner._binding, owner._custody
    policy = parent.activation_execution
    if (permission._dispatch_phase != "consume-planning" or permission._consume_spent is not True
            or raw is not permission._sql_seal or completed is not permission._completion_seal
            or continuation is not permission._completion_context_seal
            or type(completed) is not tuple or len(completed) != 4 or completed[0] != b"acknowledged"
            or type(continuation) is not tuple or len(continuation) != 3
            or policy.consume_planner_endpoint is None or policy.consume_planner_public_key is None):
        execution._fail("consume planning is not the source-fixed completed continuation")
    before, guard, narrow = continuation
    endpoint = transport._endpoint(policy.consume_planner_endpoint)
    root = permission._scope.common["root_public_key"]
    application, _session_scope, target, _credential, _count = permission._target
    cookie = permission._request.cookies.get(application.OIDC_SESSION_COOKIE_NAME)
    if type(cookie) is not str or len(cookie) != 64 or any(ord(value) > 127 for value in cookie):
        execution._fail("consume planning requires the actual original cookie possession")
    old = assertion._token(cookie.encode("ascii"), work)
    # All remaining mutable caller graphs are copied together before root,
    # commitment, key, clock or native callbacks. Only configuration permits
    # its existing finite-float grammar; no returned object supplies authority.
    owned = activation.configured.configuration._ConfigurationCapture(execution.capture._SharedLedger(work),
        maximum_bytes=bootstrap.MAX_BYTES).visit({"configuration": parent.configuration_payload,
        "generation": {name: parent.generation[name]
            for name in activation.configured.configuration._GENERATION_FIELDS},
        "runtime": parent.runtime_role_identities, "target": target})
    target = owned["target"]
    activation_originals = (*completed, raw[1], raw[2], raw[5], raw[7], raw[6], raw[0], raw[4],
        policy.authorization_enrollment_bytes, policy.grant_enrollment_bytes)
    activation_originals = consume.plan._activation_originals(activation_originals, work)
    held_bytes = sum(map(len, (root_original, history_original, *activation_originals, old, before, raw[3],
        policy.current_root_enrollment_bytes, permission._original,
        parent.activation_planning.planner_bootstrap_bytes))) + activation.MAX_ASSERTION_BYTES
    if held_bytes >= consume.MAX_ORIGINAL_BYTES:
        execution._fail("consume planning original inventory exceeds its aggregate bound")
    material = signed = None
    permission._identity()

    def current():
        if (owner._material is not parent or owner._binding is not binding or owner._custody is not custody
                or parent.activation_execution is not policy or policy.consume_planner_endpoint != endpoint
                or permission._sql_originals is not raw or permission._completion_originals is not completed
                or permission._completion_context is not continuation
                or permission._dispatch_phase not in (
                    "consume-planning", "consume-planned", "consume-authorizing", "consume-authorized",
                    "consume-dispatching", "consume-sql", "consume-dispatched",
                    "consume-completing", "consume-completion-observed", "release-intent-signing", "release-intent-authorized",
                    "release-proof-requesting", "release-proof-verified", "release-handoff-requesting")
                or permission._request.cookies.get(application.OIDC_SESSION_COOKIE_NAME) != cookie):
            execution._fail("consume planning replaced its actual original context or possession")
        now = guard()
        if signed is not None:
            consume.evidence._fresh(signed, now, material.payload["maximumPlanAgeNs"],
                material.payload["maximumClockSkewNs"])
        return now

    current()
    window, bound = permission._planning_bounds
    material = configured._admit_on_work(planner_bootstrap_bytes=root_original,
        history_custody_bytes=history_original, configuration_payload=owned["configuration"],
        configuration_digest=parent.configuration_digest, generation=owned["generation"],
        runtime_role_identities=owned["runtime"], runtime_root_public_key=root,
        activation_execution=policy, live_window=window, transport_deadline_ns=bound, work=work)
    current()
    _same_bytes(material.history_material.planner.bootstrap_bytes,
        parent.activation_planning.planner_bootstrap_bytes, work,
        "consume history original activation planner bootstrap")
    lifetimes = ((material.attestation_interval, material.opening_sample),
        (material.history_material.attestation_interval, material.history_material.opening_sample))
    permission._consume_lifetimes = permission._consume_lifetimes_seal = lifetimes
    narrow(min(item[0][1] for item in lifetimes), material.payload["maximumPlanAgeNs"],
        material.payload["maximumClockSkewNs"])
    current()
    original_expectations = caller.expectations_wire._capture_on_work(
        activation._object(raw[3], caller.expectations_wire.MAX_BYTES, work), work=work)
    plan._same(material.payload["activationExpectations"], original_expectations, work,
        "consume root original activation expectations")
    authorization_digest = plan._frame(caller.REQUEST_IDENTITY_DOMAIN, (raw[0],), work)
    predecessor = reservations._predecessor_scope(*policy.reservation_predecessor)
    reserve, reserve_digest, receipt, receipt_digest = reservations._verify_on_work(
        request_bytes=raw[5], snapshot_bytes=raw[6], receipt_bytes=raw[7],
        enrollment_bytes=policy.current_root_enrollment_bytes, root_public_key=root,
        expected_predecessor_sequence=predecessor[0], expected_predecessor_head_digest=predecessor[1],
        expected_fence=predecessor[2], work=work)
    if receipt is None or receipt_digest is None:
        execution._fail("consume planning lacks original activation reservation acknowledgment")
    expected_activation = {"authorizationDigest": authorization_digest, "databaseId": reserve["databaseId"],
        "generationDigest": reserve["generationDigest"], "pendingSequence": predecessor[0] + 1,
        "pendingHeadDigest": receipt_digest, "fence": predecessor[2]}
    plan._same(material.payload["activationScope"], expected_activation, work,
        "consume root original activation pending scope")
    after = state.vector._encode_on_work(reserve["afterVector"], work=work)
    _same_bytes(material.complete_root_vector_bytes, after, work, "post-activation complete vector")
    held_bytes += len(material.complete_root_vector_bytes) + len(material.consume_request_bytes) + len(after)
    consume_request = activation._object(material.consume_request_bytes, bootstrap.history.MAX_CONSUME_REQUEST_BYTES, work)
    old_request = original_expectations["request"]
    arguments = consume.plan.transition._arguments(consume_request["arguments"], work)
    activation_arguments = old_request["arguments"]
    for field in ("user_id", "session_id", "credential_id", "credential_record_id", "challenge_id",
            "old_token_digest", "new_token_digest", "assertion_digest"):
        plan._same(arguments[field], activation_arguments[field], work, "consume original activation " + field)
    transition = caller.activation.plan.transition
    delivery_id = transition.core._deterministic_uuid(operation=caller.OPERATION,
        request_digest=old_request["requestDigest"], purpose=transition.DELIVERY_PURPOSE, work=work)
    plan._same(arguments["delivery_id"], delivery_id, work, "consume deterministic activation delivery")
    plan._same(assertion._digest(old, work), arguments["old_token_digest"], work,
        "consume possession of the original pre-activation token")
    current()
    window, bound = permission._planning_bounds
    expected_scope = _scope(material, window[3], work)
    response_cap = min(transport.MAX_RESPONSE_BYTES, consume.MAX_ORIGINAL_BYTES - held_bytes
        - transport.BOUNDED_PREPARE_REQUEST_HEADER_BYTES - transport.RESPONSE_HEADER_BYTES
        - len(transport.BOUNDED_PREPARE_PURPOSE) - transport.BOUNDED_PREPARE_REQUEST_LIMITS[-1])
    if response_cap < 1:
        execution._fail("consume preparation has no bounded original response capacity")
    work.charge(input_bytes=retained.MAX_CLAIM_IO_BYTES)
    current()
    slot = production._callback(work, lambda: execution.custody.ControlPlaneCustodyClient.claim_oidc_session_activation_consume_planning(
        custody, finalization_digest=target["localDigest"], activation_authorization_digest=authorization_digest,
        source_revision=state.authority.SOURCE_REVISION))
    caller.shape._digest(slot)
    current()
    prepared = transport._socket_prepare_on_work(endpoint, old_token_bytes=old,
        activation_originals=activation_originals, live_window=window, deadline_ns=bound,
        work=work, current=current, maximum_response_bytes=response_cap)
    prepared = transport._originals(prepared, response=True)
    _append(custody, target["localDigest"], authorization_digest, "prepared", prepared, work, current)
    if prepared[0] != b"prepared":
        execution._fail("consume preparation is not established; original outcome retained")
    _same_bytes(prepared[1], material.consume_request_bytes, work, "root-bound typed consume request")
    returned_scope = activation._object(prepared[2], assertion.MAX_CONTEXT_BYTES, work)
    registration._closed(returned_scope, consume.state.SCOPE_FIELDS, "returned consume scope")
    deadline = returned_scope["deadlineEpochNs"]
    registration._integer(deadline, "returned consume deadline", 1)
    if deadline > window[3] or current() >= deadline:
        execution._fail("consume planner scope widened or exhausted the original deadline")
    expected_scope["deadlineEpochNs"] = deadline
    plan._same(returned_scope, expected_scope, work, "independently derived consume scope")
    narrow(deadline, expected_scope["maximumPlanAgeNs"], expected_scope["maximumClockSkewNs"])
    window, bound = permission._planning_bounds
    consume._scope({"request": consume_request, "scope": expected_scope}, window, work)
    signed, plan_digest = consume._authenticate(prepared[3], consume_request, expected_scope,
        material.planner_public_key, current, work)
    _same_bytes(prepared[4], plan_digest.encode("ascii"), work, "known signed consume plan identity")
    # This is a durable exact response locator, not a signature or replay proof.
    work.charge(input_bytes=len(prepared[5]))
    journal_digest = prepared[5].decode("ascii")
    caller.shape._digest(journal_digest)
    narrow(signed["expiresAtEpochNs"], expected_scope["maximumPlanAgeNs"], expected_scope["maximumClockSkewNs"])
    current()
    window, bound = permission._planning_bounds
    export_cap = min(transport.MAX_EXPORT_RESPONSE_BYTES, consume.MAX_ORIGINAL_BYTES - held_bytes
        - sum(map(len, prepared)) - transport.MAX_EXPORT_REQUEST_BYTES
        - transport.EXPORT_REQUEST_HEADER_BYTES - transport.EXPORT_RESPONSE_HEADER_BYTES)
    if export_cap < 1:
        execution._fail("consume export has no bounded original response capacity")
    exported = transport._socket_export_retained_on_work(endpoint, envelope_bytes=prepared[3],
        expected_deadline_epoch_ns=deadline, expected_journal_digest=journal_digest,
        live_window=window, deadline_ns=bound, work=work, current=current,
        maximum_response_bytes=export_cap)
    exported = transport._originals(exported, response=True, export=True)
    _append(custody, target["localDigest"], authorization_digest, "exported", exported, work, current)
    if exported[0] != b"exported":
        execution._fail("consume export is not established; original outcome retained")
    for actual, expected in zip((exported[1], exported[2], exported[3], exported[5], exported[6]), prepared[1:]):
        _same_bytes(actual, expected, work, "retained prepare/export correspondence")
    # The source transport checked the distinct ciphertext frame. Only a
    # genuine private receiver can open/replay it; no public AES claim is made.
    current()
    originals = prepared, exported
    permission._consume_originals = permission._consume_originals_seal = originals
    permission._consume_context = permission._consume_context_seal = (
        after, current, narrow, held_bytes + sum(map(len, prepared)) + sum(map(len, exported)))
    permission._consume_possession = permission._consume_possession_seal = (
        application.OIDC_SESSION_COOKIE_NAME, cookie)
    return originals
