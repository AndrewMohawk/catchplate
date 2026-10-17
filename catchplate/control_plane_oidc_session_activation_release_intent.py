"""One retained release intent from the actual live completed consume call.

Public completion controls authenticate their own bindings. Packet/effects and
encrypted-delivery hints remain expected data, never private replay evidence.
Only later genuine committed-release proof admission can authenticate those
expectations; this component neither constructs that proof nor opens a token.
"""
from __future__ import annotations

from catchplate import authority_current_root_authorization as state
from catchplate import authority_current_root_delivery_records as acknowledgments
from catchplate import authority_oidc_session_activation_release_hints as hints_wire
from catchplate import authority_oidc_session_activation_release_intent as intent
from catchplate import authority_transition_oidc_session_activation as activation
from catchplate import authority_transition_oidc_session_activation_delivery as consumption
from catchplate import control_plane_oidc_session_activation_consume_completion as completion
from catchplate import control_plane_oidc_session_activation_consume_records as retained
from catchplate import control_plane_oidc_session_activation_execution as execution
from catchplate import control_plane_oidc_session_activation_release_intent_bootstrap as configured
from catchplate import control_plane_oidc_session_activation_request_dispatch as request_dispatch


planning, caller = completion.planning, completion.caller
plan, production = intent.plan, intent.production


def _authorize_on_permission(permission):
    """No target, token, result, key, callback or allowance is accepted here."""
    if type(permission) is not execution._ActivationPermission:
        execution._fail("release intent requires the actual active permission")
    permission._identity()
    owner, work = permission._owner, permission._work
    parent, binding, custody = owner._material, owner._binding, owner._custody
    policy, consume_policy = parent.release_intent, parent.consume_execution
    private, descriptor, descriptor_identity = owner._intent_key, owner._intent_key_fd, owner._intent_key_identity
    completed, context = permission._consume_completion_originals, permission._consume_completion_context
    hinted = permission._consume_completion_hints
    consume_raw, activation_raw = permission._consume_sql_originals, permission._sql_originals
    target_original, possession = permission._target, permission._consume_possession
    credential_original = target_original[3]
    credential_record_id = credential_original[0]
    response_path, response_pin = owner._response_path, owner._response_pin
    if (permission._state != "active" or permission._dispatch_phase != "release-intent-signing"
            or permission._release_intent_spent is not True
            or type(policy) is not configured._ReleaseIntentMaterial or private is None
            or descriptor != configured.CALLER_KEY_FD or descriptor != policy.caller_private_key_fd
            or descriptor_identity is None or consume_policy.release_hints is not True
            or completed is not permission._consume_completion_seal or completed[0] != b"acknowledged"
            or context is not permission._consume_completion_context_seal
            or hinted is not permission._consume_completion_hints_seal
            or consume_raw is not permission._consume_sql_seal or activation_raw is not permission._sql_seal
            or possession is not permission._consume_possession_seal
            or (binding.caller_uid, binding.caller_gid) != (65532, 65532)
            or type(response_path) is not str or response_pin is None):
        execution._fail("release intent lacks its actual completed target and dedicated cold key")
    after, guard, prior_narrow, prior_bytes = context
    enrollment, scope_original, forbidden = policy.enrollment_bytes, policy.expected_scope_bytes, policy.forbidden_public_keys
    root, configured_public = binding.runtime_root_public_key, policy.caller_public_key
    generation_original = parent.generation
    generation_digest, configuration_digest = generation_original["digest"], parent.configuration_digest
    target = execution.capture._JSONCapture(execution.capture._SharedLedger(work),
        maximum_bytes=execution.caller.MAX_AUTHORIZATION_BYTES).visit(target_original[2])
    target_digest = target["localDigest"]
    intent.shape._digest(target_digest)
    cookie = permission._request.cookies.get(possession[0])
    if cookie != possession[1] or type(cookie) is not str or len(cookie) != intent.delivery.TOKEN_BYTES:
        execution._fail("release intent lost original old-token possession")
    if any(ord(value) > 127 for value in cookie):
        execution._fail("release intent old token is not its exact ASCII original")
    work.charge(input_bytes=len(cookie))
    old = intent.delivery._token(cookie.encode("ascii"), work)
    state._original(enrollment, intent.enrollments.MAX_BYTES, "configured release intent enrollment")
    state._original(scope_original, intent.enrollments.MAX_BYTES, "configured release intent scope")
    total = prior_bytes + len(enrollment) + len(scope_original) + len(old) + intent.MAX_BYTES
    if total > caller.MAX_ORIGINAL_BYTES:
        execution._fail("release intent exceeds the original whole-call inventory")
    state._private(private)
    state._public(root)
    state._public(configured_public)
    permission._release_intent_signing = permission._release_intent_signing_seal = (
        policy, private, descriptor, descriptor_identity)
    admitted = None

    def base_current():
        if (owner._material is not parent or owner._binding is not binding or owner._custody is not custody
                or parent.release_intent is not policy or parent.consume_execution is not consume_policy
                or parent.configuration_digest != configuration_digest or parent.generation is not generation_original
                or generation_original["digest"] != generation_digest
                or policy.enrollment_bytes is not enrollment or policy.expected_scope_bytes is not scope_original
                or policy.forbidden_public_keys is not forbidden or policy.caller_public_key is not configured_public
                or binding.runtime_root_public_key is not root
                or permission._consume_completion_originals is not completed
                or permission._consume_completion_context is not context or permission._consume_completion_hints is not hinted
                or permission._consume_sql_originals is not consume_raw or permission._sql_originals is not activation_raw
                or permission._target is not target_original or target_original[2] != target
                or target_original[3] is not credential_original or credential_original[0] != credential_record_id
                or permission._consume_possession is not possession
                or permission._request.cookies.get(possession[0]) != cookie
                or owner._response_path != response_path or owner._response_pin != response_pin):
            execution._fail("release intent changed its original target, possession or cold resources")
        return guard()

    def continuity(epoch_floor, monotonic_floor):
        permission._continuity(epoch_floor, monotonic_floor)
        base_current()
        return permission._planning_observed

    def current():
        now = base_current()
        if admitted is not None:
            observed = admitted.live()
            now = base_current()
            if observed > now:
                execution._fail("release intent owner clocks reversed after signature admission")
        return now

    def narrow(expiry, age, skew):
        previous, previous_bound = permission._planning_bounds
        prior_narrow(expiry, min(previous[5], age), min(previous[6], skew))
        selected, selected_bound = permission._planning_bounds
        if (selected[:3] != previous[:3] or selected_bound > previous_bound
                or any(selected[index] > previous[index] for index in (3, 4, 5, 6))):
            execution._fail("release intent replaced or widened its original allowance")
        current()

    current()
    scope = configured._scope_on_work(scope_original, work)
    for field, expected in (("configurationDigest", configuration_digest), ("generationDigest", generation_digest)):
        plan._same(scope[field], expected, work, "release intent current parent " + field)
    enrolled = intent.enrollments._admit_on_work(enrollment_bytes=enrollment, root_public_key=root,
        expected_scope=scope, forbidden_public_keys=forbidden, work=work)
    current()
    plan._same(enrolled.enrollment_digest, policy.enrollment_digest, work, "release intent actual enrollment original")
    signing_pin = intent.enrollments.keys._spki_on_work(enrolled.caller_public_key, work)
    plan._same(signing_pin, intent.enrollments.keys._spki_on_work(configured_public, work), work,
        "release intent original cold public key")
    if signing_pin == response_pin:
        execution._fail("release intent reuses the actual HTTP response key")
    intent.enrollments.keys._pair_on_work(private, enrolled.caller_public_key, work)
    current()
    activation_expected = execution.caller.expectations_wire._capture_on_work(
        planning.activation._object(activation_raw[3], execution.caller.expectations_wire.MAX_BYTES, work), work=work)
    consume_expected = caller.expectations_wire._capture_on_work(
        planning.activation._object(consume_raw[3], caller.expectations_wire.MAX_BYTES, work), work=work)
    activated, consumed = activation_expected["request"], consume_expected["request"]
    activation_arguments = activation._arguments(activated["arguments"], work)
    arguments = consumption._arguments(consumed["arguments"], work)
    for field in ("user_id", "session_id", "credential_id", "credential_record_id", "challenge_id",
            "old_token_digest", "new_token_digest", "assertion_digest"):
        plan._same(arguments[field], activation_arguments[field], work, "release intent same activation/consume " + field)
    for field, column in (("user_id", "userId"), ("session_id", "sessionId"), ("credential_id", "credentialId")):
        plan._same(arguments[field], target[column], work, "release intent actual retained subject " + field)
    plan._same(arguments["credential_record_id"], credential_record_id, work,
        "release intent actual retained credential record")
    for expected in (activation_expected, consume_expected):
        plan._same(expected["scope"]["configurationDigest"], configuration_digest, work,
            "release intent original request configuration")
    packet_digest, effects_digest, envelope, created, expires = hints_wire._decode_on_work(hinted, work=work)
    delivery_scope = {"deliveryId": arguments["delivery_id"], "userId": arguments["user_id"],
        "sessionId": arguments["session_id"], "credentialId": arguments["credential_id"],
        "credentialRecordId": arguments["credential_record_id"], "challengeId": arguments["challenge_id"],
        "assertionDigest": arguments["assertion_digest"], "oldTokenDigest": arguments["old_token_digest"],
        "newTokenDigest": arguments["new_token_digest"], "createdAt": created, "expiresAt": expires}
    # Descriptor dates/ciphertext and packet/effects remain untrusted expected
    # data. Genuine private committed proof must independently match them.
    _created_epoch, delivery_expiry = intent.bootstrap._scope(delivery_scope, work)
    plan._same(intent.delivery._token_digest(old, work, current), arguments["old_token_digest"], work,
        "release intent current old-token possession")
    envelope_digest = planning.assertion._digest(envelope, work)
    predecessor = (request_dispatch._consume_predecessor_on_permission(permission) if consume_policy.request_bound
        else completion.reservations._predecessor_scope(*consume_policy.reservation_predecessor))
    reserve, reserve_digest, receipt, receipt_digest = completion.reservations._verify_on_work(
        request_bytes=consume_raw[5], snapshot_bytes=consume_raw[6], receipt_bytes=consume_raw[7],
        enrollment_bytes=consume_policy.current_root_enrollment_bytes, root_public_key=root,
        expected_predecessor_sequence=predecessor[0], expected_predecessor_head_digest=predecessor[1],
        expected_fence=predecessor[2], work=work)
    if receipt is None or receipt_digest is None:
        execution._fail("release intent lacks its original consume reserve acknowledgment")
    completed_material, complete, complete_digest = state._verify_request_on_work(
        request_bytes=completed[2], enrollment_bytes=consume_policy.current_root_enrollment_bytes,
        root_public_key=root, now_epoch_ns=current(), work=work)
    checked = acknowledgments._verify_ack_on_work(request_bytes=completed[2], receipt_bytes=completed[3],
        enrollment_bytes=consume_policy.current_root_enrollment_bytes, root_public_key=root,
        expected_pending_sequence=predecessor[0] + 1, expected_pending_head_digest=receipt_digest, work=work)
    plan._same(checked.request_digest, complete_digest, work, "release intent complete original identity")
    plan._same(checked.request_payload, complete, work, "release intent complete original readback")
    planning._same_bytes(completed[1], complete_digest.encode("ascii"), work, "release intent returned completion identity")
    for field, expected in (("action", "complete"), ("operation", consumption.OPERATION),
            ("pendingRequestDigest", reserve_digest), ("pendingDecisionDigest", receipt_digest),
            ("fence", predecessor[2]), ("databaseId", scope["databaseId"]), ("generationDigest", scope["generationDigest"])):
        plan._same(complete[field], expected, work, "release intent signed completion " + field)
    plan._same(reserve["requestDigest"], consumed["requestDigest"], work, "release intent typed consume target")
    after_digest = state.vector._digest_on_work(after, work=work)
    plan._same(complete["afterVectorDigest"], after_digest, work, "release intent complete full after-vector")
    expected_release = {"activationRequestDigest": activated["requestDigest"],
        "activationOperationId": activated["operationId"], "consumeRequestDigest": consumed["requestDigest"],
        "deliveryEnvelopeDigest": envelope_digest, "deliveryScope": delivery_scope,
        "consumeBinding": {"packetDigest": packet_digest, "pendingDecisionDigest": receipt_digest,
            "completionRequestDigest": complete_digest, "effectsDigest": effects_digest, "afterVectorDigest": after_digest}}
    scope, expected_release = intent._graphs(scope, expected_release)
    release_bytes = intent.contract._wire(expected_release, work)
    total += len(release_bytes)
    if total > caller.MAX_ORIGINAL_BYTES:
        execution._fail("release intent derived expectations exceed the whole-call inventory")
    age, skew = enrolled.payload["maximumAgeNs"], enrolled.payload["maximumClockSkewNs"]
    narrow(delivery_expiry, age, skew)
    activation_digest = plan._frame(execution.caller.REQUEST_IDENTITY_DOMAIN, (activation_raw[0],), work)
    work.charge(input_bytes=retained._append_io_bytes("release-intent-claimed", ()))
    current()
    production._callback(work, lambda:
        execution.custody.ControlPlaneCustodyClient.claim_oidc_session_activation_consume_release_intent_attempt(
            custody, finalization_digest=target_digest, activation_authorization_digest=activation_digest))
    current()
    window, bound = permission._planning_bounds
    original = intent._produce_on_work(enrollment_bytes=enrollment, root_public_key=root,
        forbidden_public_keys=forbidden, expected_scope=scope, expected_release=expected_release,
        old_token_bytes=old, caller_private_key=private, live_window=window,
        transport_deadline_ns=bound, work=work, _continuity=continuity)
    current()
    admitted = intent._verify_on_work(intent_bytes=original, enrollment_bytes=enrollment, root_public_key=root,
        forbidden_public_keys=forbidden, expected_scope=scope, expected_release=expected_release,
        old_token_bytes=old, live_window=window, transport_deadline_ns=bound, work=work, _continuity=continuity)
    if type(admitted) is not intent._AdmittedIntent:
        execution._fail("release intent requires its actual original signature admission")
    narrow(min(admitted.payload["expiresAtEpochNs"], admitted.payload["issuedAtEpochNs"] + age), age, skew)
    work.charge(input_bytes=retained._append_io_bytes("release-intent", (original,)))
    current()
    identity = production._callback(work, lambda:
        execution.custody.ControlPlaneCustodyClient.append_oidc_session_activation_consume_release_intent(
            custody, finalization_digest=target_digest, activation_authorization_digest=activation_digest, originals=(original,)))
    current()
    intent.shape._digest(identity)
    permission._release_intent_original = permission._release_intent_seal = original
    permission._release_intent_context = permission._release_intent_context_seal = (release_bytes, current, narrow, total)
    permission._dispatch_phase = "release-intent-authorized"
    current()
    return original
