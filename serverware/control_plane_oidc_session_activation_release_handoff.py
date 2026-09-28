"""Same-permission protected handoff from exact fresh public originals.

Only two grant originals enter this continuation. Target, possession, proof,
intent, completion and static client pins come from its actual live owner.
Grants are retained before admission; a separate irreversible grant claim
precedes the sole socket. The genuine receiver alone returns token bytes.
"""
from __future__ import annotations

from serverware import authority_current_root_authorization as state
from serverware import authority_current_root_delivery_records as acknowledgments
from serverware import authority_oidc_session_activation_release_hints as hints
from serverware import authority_oidc_session_activation_release_intent as intents
from serverware import authority_oidc_session_activation_release_proof as proofs
from serverware import authority_oidc_session_activation_release_response as receiving
from serverware import control_plane_oidc_session_activation_consume_completion as completion
from serverware import control_plane_oidc_session_activation_consume_records as retained
from serverware import control_plane_oidc_session_activation_execution as execution
from serverware import control_plane_oidc_session_activation_release_attempt as attempts
from serverware import control_plane_oidc_session_activation_release_handoff_bootstrap as configured
from serverware import control_plane_oidc_session_activation_release_intent_bootstrap as intent_config
from serverware import control_plane_oidc_session_activation_release_proof_bootstrap as proof_config
from serverware import oidc_session_activation_release_client_authorization as clients
from serverware import oidc_session_activation_release_outcome as outcomes
from serverware import oidc_session_activation_release_transport as transport


authorization, shape, plan = clients.authorization, clients.shape, clients.plan
capture, production, delivery = clients.capture, clients.production, clients.delivery
planning, reservations = completion.planning, completion.reservations


def _release_on_permission(permission, *, client_authorization_bytes, server_bootstrap_bytes):
    """No posted target, successful carrier, key, possession or allowance input."""
    if type(permission) is not execution._ActivationPermission:
        execution._fail("release handoff requires the actual active permission")
    # Hold both caller-supplied originals before any original-owner callback.
    client_raw = authorization._original(client_authorization_bytes, clients.MAX_BYTES,
        "same-permission release client authorization")
    server_raw = authorization._original(server_bootstrap_bytes, clients.MAX_SERVER_BOOTSTRAP_BYTES,
        "same-permission release server bootstrap")
    permission._identity()
    owner, work = permission._owner, permission._work
    parent, binding, custody = owner._material, owner._binding, owner._custody
    policy, proof_policy, intent_policy = parent.release_handoff, parent.release_proof, parent.release_intent
    consume_policy = parent.consume_execution
    proof_raw, context = permission._release_proof_originals, permission._release_proof_context
    intent_raw = permission._release_intent_original
    completed, completed_context = permission._consume_completion_originals, permission._consume_completion_context
    hint_raw, consume_raw = permission._consume_completion_hints, permission._consume_sql_originals
    activation_raw, target, possession = permission._sql_originals, permission._target, permission._consume_possession
    root, response_pin = binding.runtime_root_public_key, owner._response_pin
    if (permission._state != "active" or permission._dispatch_phase != "release-handoff-requesting"
            or permission._release_handoff_spent is not True
            or type(policy) is not configured._ReleaseHandoffMaterial
            or type(proof_policy) is not proof_config._ReleaseProofMaterial
            or type(intent_policy) is not intent_config._ReleaseIntentMaterial
            or proof_raw is not permission._release_proof_seal or proof_raw[0] != b"proved"
            or context is not permission._release_proof_context_seal
            or intent_raw is not permission._release_intent_seal
            or completed is not permission._consume_completion_seal or completed[0] != b"acknowledged"
            or completed_context is not permission._consume_completion_context_seal
            or hint_raw is not permission._consume_completion_hints_seal
            or consume_raw is not permission._consume_sql_seal or activation_raw is not permission._sql_seal
            or possession is not permission._consume_possession_seal
            or (binding.caller_uid, binding.caller_gid) != (clients.CLIENT_UID, clients.CLIENT_GID)):
        execution._fail("release handoff lacks its actual verified proof continuation")
    release_raw, prior_current, prior_narrow, prior_bytes = context
    after = completed_context[0]
    target_digest = target[2]["localDigest"]
    shape._digest(target_digest)
    client_id, identity_raw, endpoint_raw = policy.client_id, policy.client_identity_bytes, policy.endpoint_bytes
    proof_scope_raw, proof_enrollment = proof_policy.expected_scope_bytes, proof_policy.enrollment_bytes
    proof_forbidden, proof_key = proof_policy.forbidden_public_keys, proof_policy.proof_public_key
    intent_scope_raw, intent_enrollment = intent_policy.expected_scope_bytes, intent_policy.enrollment_bytes
    intent_forbidden = intent_policy.forbidden_public_keys
    state_enrollment = consume_policy.current_root_enrollment_bytes
    predecessor = consume_policy.reservation_predecessor
    activation_planner = parent.activation_planning
    planner_raw = activation_planner.planner_bootstrap_bytes
    cookie = permission._request.cookies.get(possession[0])
    if (cookie != possession[1] or type(cookie) is not str or len(cookie) != delivery.TOKEN_BYTES
            or any(ord(character) > 127 for character in cookie)):
        execution._fail("release handoff lost its same-call old-token possession")
    capture._SharedLedger(work)
    work.charge(input_bytes=len(cookie))
    old = delivery._token(cookie.encode("ascii"), work)
    request_bytes = (len(transport.LIVE_PURPOSE) + len(proof_raw[2]) + len(proof_raw[3])
        + len(intent_raw) + len(intent_enrollment) + len(old) + delivery.ENVELOPE_BYTES)
    total = (prior_bytes + len(client_raw) + len(server_raw) + len(identity_raw) + len(endpoint_raw)
        + clients.MAX_BYTES + outcomes.MAX_BYTES + request_bytes
        + transport.LIVE_REQUEST_HEADER_BYTES + transport.RESPONSE_HEADER_BYTES + transport.MAX_RESPONSE_BYTES)
    if total > receiving.MAX_ORIGINAL_BYTES:
        execution._fail("release handoff exceeds the whole original call inventory")
    work.charge(input_bytes=len(client_raw) + len(server_raw))
    guards = []
    complete_material = complete = None

    def base_current():
        if (owner._material is not parent or owner._binding is not binding or owner._custody is not custody
                or binding.runtime_root_public_key is not root or owner._response_pin != response_pin
                or parent.release_handoff is not policy or parent.release_proof is not proof_policy
                or parent.release_intent is not intent_policy or parent.consume_execution is not consume_policy
                or policy.client_id != client_id or policy.client_identity_bytes is not identity_raw
                or policy.endpoint_bytes is not endpoint_raw
                or proof_policy.expected_scope_bytes is not proof_scope_raw
                or proof_policy.enrollment_bytes is not proof_enrollment
                or proof_policy.forbidden_public_keys is not proof_forbidden or proof_policy.proof_public_key is not proof_key
                or intent_policy.expected_scope_bytes is not intent_scope_raw
                or intent_policy.enrollment_bytes is not intent_enrollment
                or intent_policy.forbidden_public_keys is not intent_forbidden
                or consume_policy.current_root_enrollment_bytes is not state_enrollment
                or consume_policy.reservation_predecessor is not predecessor
                or parent.activation_planning is not activation_planner
                or activation_planner.planner_bootstrap_bytes is not planner_raw
                or permission._release_proof_originals is not proof_raw or permission._release_proof_context is not context
                or permission._release_intent_original is not intent_raw
                or permission._consume_completion_originals is not completed
                or permission._consume_completion_context is not completed_context
                or permission._consume_completion_hints is not hint_raw or permission._consume_sql_originals is not consume_raw
                or permission._sql_originals is not activation_raw or permission._target is not target
                or target[2]["localDigest"] != target_digest or permission._consume_possession is not possession
                or permission._request.cookies.get(possession[0]) != cookie
                or permission._dispatch_phase != "release-handoff-requesting"
                or permission._release_handoff_spent is not True):
            execution._fail("release handoff changed its original owner, target or public pins")
        return prior_current()

    def continuity(epoch, monotonic):
        permission._continuity(epoch, monotonic)
        base_current()
        return permission._planning_observed

    def current():
        now = base_current()
        for guard in guards:
            observed = guard()
            now = base_current()
            if type(observed) is not int or observed < 1 or observed > now:
                execution._fail("release handoff clocks reversed across original admission")
        if complete is not None:
            state._fresh(complete, complete_material, now)
        return now

    def narrow(expiry, age, skew):
        previous, previous_bound = permission._planning_bounds
        prior_narrow(expiry, min(previous[5], age), min(previous[6], skew))
        selected, selected_bound = permission._planning_bounds
        if (selected[:3] != previous[:3] or selected_bound > previous_bound
                or any(new > old_limit for new, old_limit in zip(selected[3:], previous[3:]))):
            execution._fail("release handoff replaced or widened its original allowance")
        current()

    def receiving_continuity(epoch, monotonic):
        # Inner intent/proof guards use the base-only hook above. The final
        # receiver retains every newly admitted guard without calling itself.
        permission._continuity(epoch, monotonic)
        current()
        return permission._planning_observed

    current()
    activation_digest = plan._frame(execution.caller.REQUEST_IDENTITY_DOMAIN, (activation_raw[0],), work)
    current()
    # Raw2 is a durable original record, not an authenticated permission result.
    # It contains only the actual incoming grants, never request/response/token frames.
    grants = client_raw, server_raw
    work.charge(input_bytes=retained._append_io_bytes("release-grants", grants))
    current()
    retained_digest = production._callback(work, lambda:
        execution.custody.ControlPlaneCustodyClient.append_oidc_session_activation_consume_release_grants(
            custody, finalization_digest=target_digest, activation_authorization_digest=activation_digest,
            originals=grants))
    current()
    shape._digest(retained_digest)

    client_identity = configured._identity_on_work(identity_raw, work)
    endpoint_graph = configured._endpoint_on_work(endpoint_raw, work)
    endpoint = clients._endpoint(endpoint_graph, work)
    proof_scope = proof_config._scope_on_work(proof_scope_raw, work)
    intent_scope = intent_config._scope_on_work(intent_scope_raw, work)
    release = planning.activation._object(release_raw, intents.contract.MAX_BYTES, work)
    intent_scope, release = intents._graphs(intent_scope, release)
    for name in ("configurationDigest", "databaseId", "generationDigest", "runtimeClosureDigest", "receiverIdentity"):
        plan._same(proof_scope[name], intent_scope[name], work, "release handoff independently pinned " + name)
    plan._same(proof_scope["configurationDigest"], parent.configuration_digest, work,
        "release handoff actual parent configuration")
    planning._same_bytes(proof_raw[3], proof_enrollment, work, "release handoff original proof enrollment")
    current()
    enrolled = proofs.enrollments._admit_on_work(enrollment_bytes=proof_enrollment,
        root_public_key=root, expected_scope=proof_scope, forbidden_public_keys=proof_forbidden, work=work)
    current()
    plan._same(enrolled.enrollment_digest, proof_policy.enrollment_digest, work,
        "release handoff actual cold proof enrollment")
    proof_pin = proofs.enrollments.keys._spki_on_work(enrolled.proof_public_key, work)
    plan._same(proof_pin, proofs.enrollments.keys._spki_on_work(proof_key, work), work,
        "release handoff actual proof public key")
    if response_pin is None or proof_pin == response_pin:
        execution._fail("release handoff proof purpose lacks original response-key separation")

    # Re-admit the actual retained signed COMPLETE and state ACK; an unsigned
    # SQL response or the cached completion carrier never supplies this binding.
    checked_predecessor = reservations._predecessor_scope(*predecessor)
    reserve, reserve_digest, reserve_ack, pending_digest = reservations._verify_on_work(
        request_bytes=consume_raw[5], snapshot_bytes=consume_raw[6], receipt_bytes=consume_raw[7],
        enrollment_bytes=state_enrollment, root_public_key=root,
        expected_predecessor_sequence=checked_predecessor[0], expected_predecessor_head_digest=checked_predecessor[1],
        expected_fence=checked_predecessor[2], work=work)
    current()
    if reserve_ack is None or pending_digest is None:
        execution._fail("release handoff lacks actual retained reserve acknowledgment")
    complete_material, complete, complete_digest = state._verify_request_on_work(
        request_bytes=completed[2], enrollment_bytes=state_enrollment,
        root_public_key=root, now_epoch_ns=current(), work=work)
    current()
    acknowledged = acknowledgments._verify_ack_on_work(request_bytes=completed[2], receipt_bytes=completed[3],
        enrollment_bytes=state_enrollment, root_public_key=root,
        expected_pending_sequence=checked_predecessor[0] + 1, expected_pending_head_digest=pending_digest, work=work)
    current()
    plan._same(acknowledged.request_payload, complete, work, "release handoff original COMPLETE readback")
    plan._same(acknowledged.request_digest, complete_digest, work, "release handoff original COMPLETE identity")
    work.prepare_utf8(complete_digest)
    planning._same_bytes(completed[1], complete_digest.encode("ascii"), work,
        "release handoff original COMPLETE response identity")
    for field, expected in (("action", "complete"), ("operation", completion.caller.OPERATION),
            ("requestDigest", release["consumeRequestDigest"]), ("pendingRequestDigest", reserve_digest),
            ("pendingDecisionDigest", pending_digest), ("fence", checked_predecessor[2]),
            ("databaseId", proof_scope["databaseId"]), ("generationDigest", proof_scope["generationDigest"])):
        plan._same(complete[field], expected, work, "release handoff signed completion " + field)
    plan._same(reserve["requestDigest"], release["consumeRequestDigest"], work,
        "release handoff original consume reservation")
    for name, expected in (("pendingDecisionDigest", pending_digest),
            ("completionRequestDigest", complete_digest),
            ("afterVectorDigest", state.vector._digest_on_work(after, work=work))):
        plan._same(release["consumeBinding"][name], expected, work, "release handoff consume binding " + name)
    plan._same(complete["afterVectorDigest"], release["consumeBinding"]["afterVectorDigest"], work,
        "release handoff signed complete after-vector")
    complete_age = complete_material.payload["maxControlAgeNs"]
    narrow(min(complete["expiresAtEpochNs"], complete["issuedAtEpochNs"] + complete_age),
        complete_age, complete_material.payload["maxClockSkewNs"])

    window, bound = permission._planning_bounds
    admitted_intent = intents._verify_on_work(intent_bytes=intent_raw, enrollment_bytes=intent_enrollment,
        root_public_key=root, forbidden_public_keys=intent_forbidden, expected_scope=intent_scope,
        expected_release=release, old_token_bytes=old, live_window=window, transport_deadline_ns=bound,
        work=work, _continuity=continuity)
    if type(admitted_intent) is not intents._AdmittedIntent:
        execution._fail("release handoff requires genuine original intent and possession admission")
    guards.append(admitted_intent.live)
    intent_interval = admitted_intent.payload["issuedAtEpochNs"], admitted_intent.payload["expiresAtEpochNs"]
    age, skew = enrolled.payload["maximumAgeNs"], enrolled.payload["maximumClockSkewNs"]
    narrow(intent_interval[1], age, skew)
    window, bound = permission._planning_bounds
    root_custody = proofs.bootstrap._verify_on_work(custody_bytes=proof_raw[1], root_public_key=root,
        live_window=window, transport_deadline_ns=bound, work=work)
    current()
    guards.append(proofs.bootstrap.planner_bootstrap._launch_guard(root_custody.attestation_interval,
        root_custody.opening_sample, base_current, work))
    planning._same_bytes(root_custody.planner.bootstrap_bytes, planner_raw, work,
        "release handoff same original activation planner")
    for actual, expected, label in (
            (root_custody.release_intent_digest, admitted_intent.intent_digest, "intent"),
            (root_custody.activation_request_digest, release["activationRequestDigest"], "activation request"),
            (root_custody.activation_operation_id, release["activationOperationId"], "activation operation"),
            (root_custody.consume_request_digest, release["consumeRequestDigest"], "consume request"),
            (root_custody.delivery_envelope_digest, release["deliveryEnvelopeDigest"], "encrypted envelope"),
            (root_custody.delivery_scope, release["deliveryScope"], "delivery scope"),
            (root_custody.receiver_identity, proof_scope["receiverIdentity"], "receiver"),
            (root_custody.planner.configuration_digest, proof_scope["configurationDigest"], "configuration"),
            (root_custody.planner.generation["digest"], proof_scope["generationDigest"], "generation"),
            (root_custody.planner.runtime_closure_digest, proof_scope["runtimeClosureDigest"], "runtime closure")):
        plan._same(actual, expected, work, "release handoff independently authenticated custody " + label)
    narrow(root_custody.attestation_interval[1], root_custody.planner.maximum_plan_age_ns,
        root_custody.planner.maximum_clock_skew_ns)
    evidence = {"releaseCustodyDigest": plan._frame(proofs.contract.CUSTODY_IDENTITY_DOMAIN, (proof_raw[1],), work),
        "releaseIntentDigest": admitted_intent.intent_digest, "stateReceiptDigest": acknowledged.receipt_digest}
    window, bound = permission._planning_bounds
    admitted_proof = proofs._verify_on_work(proof_bytes=proof_raw[2], enrollment_bytes=proof_raw[3],
        root_public_key=root, forbidden_public_keys=proof_forbidden, expected_scope=proof_scope,
        expected_release=release, expected_evidence=evidence, expected_intent_interval=intent_interval,
        live_window=window, transport_deadline_ns=bound, work=work, _continuity=continuity)
    if type(admitted_proof) is not proofs._AdmittedProof:
        execution._fail("release handoff requires genuine original proof admission")
    guards.append(admitted_proof.live)
    narrow(min(admitted_proof.payload["expiresAtEpochNs"], admitted_proof.payload["issuedAtEpochNs"] + age), age, skew)

    packet_digest, effects_digest, envelope, created, expires = hints._decode_on_work(hint_raw, work=work)
    for actual, expected, label in ((packet_digest, release["consumeBinding"]["packetDigest"], "packet"),
            (effects_digest, release["consumeBinding"]["effectsDigest"], "effects"),
            (created, release["deliveryScope"]["createdAt"], "created"),
            (expires, release["deliveryScope"]["expiresAt"], "expires"),
            (planning.assertion._digest(envelope, work), release["deliveryEnvelopeDigest"], "ciphertext")):
        plan._same(actual, expected, work, "release handoff proof-bound original hint " + label)
    current()
    record = outcomes._encode_on_work(
        scope={name: admitted_proof.payload[name] for name in outcomes.SCOPE_FIELDS},
        release_binding={name: admitted_proof.payload[name] for name in outcomes.RELEASE_FIELDS},
        evidence_binding={**evidence, "releaseProofDigest": admitted_proof.proof_digest,
            "proofEnrollmentDigest": admitted_proof.payload["enrollmentDigest"],
            "intentEnrollmentDigest": admitted_intent.payload["enrollmentDigest"]},
        caller_id=admitted_intent.payload["callerId"], work=work)
    current()
    outcome_digest = outcomes._digest_on_work(record, work)
    request = transport._originals((transport.LIVE_PURPOSE, proof_raw[2], proof_raw[3],
        intent_raw, intent_enrollment, old, envelope), response=False, profile=clients.LIVE_PROFILE)
    window, bound = permission._planning_bounds
    request_identity = transport._request_identity_on_work(request, profile=clients.LIVE_PROFILE,
        deadline_ns=bound, work=work, current=current)
    current()
    scope = clients._scope({**proof_scope, "serverBootstrapDigest": clients._server_bootstrap_digest_on_work(server_raw, work),
        "profile": clients.LIVE_PROFILE, "requestIdentity": request_identity.decode("ascii"),
        "clientId": client_id, "clientIdentity": client_identity, "callerId": intent_scope["callerId"],
        "stateReceiptDigest": evidence["stateReceiptDigest"], "expectedRelease": release,
        "expectedOutcomeDigest": outcome_digest, "endpoint": endpoint_graph}, work)
    current()
    window, bound = permission._planning_bounds
    admitted_client = clients._verify_on_work(authorization_bytes=client_raw, server_bootstrap_bytes=server_raw,
        root_public_key=root, expected_scope=scope, live_window=window, transport_deadline_ns=bound, work=work)
    if type(admitted_client) is not clients._ClientAuthorization:
        execution._fail("release handoff requires genuine fresh client/server originals")
    guards.append(admitted_client.live)
    candidate = clients.clock._validate(admitted_client.live_window)
    shape._integer(admitted_client.deadline_ns, minimum=1)
    if (candidate[:3] != window[:3] or any(new > old_limit for new, old_limit in zip(candidate[3:], window[3:]))
            or admitted_client.deadline_ns > bound or admitted_client.deadline_ns > candidate[4]):
        execution._fail("release handoff fresh grants widened the inherited allowance")
    narrow(candidate[3], candidate[5], candidate[6])
    selected, selected_bound = permission._planning_bounds
    permission._narrow_planning(selected, min(selected_bound, admitted_client.deadline_ns))
    current()
    material = admitted_client.server_material
    if type(material) is not clients.server._ReleaseMaterial or material.profile != clients.LIVE_PROFILE:
        execution._fail("release handoff cannot select recovery or accept a server carrier")
    planning._same_bytes(material.custody_bytes, proof_raw[1], work,
        "release handoff exact server custody original from retained proof")
    plan._same(material.storage_scope["releaseCustodyDigest"], evidence["releaseCustodyDigest"], work,
        "release handoff actual storage custody binding")
    current()

    # Existing token-free durable one-use authorization identity is the only
    # dispatch claim. Neither response/token nor raw7 is appended to a journal.
    work.charge(input_bytes=attempts.MAX_CLAIM_IO_BYTES)
    current()
    production._callback(work, lambda:
        execution.custody.ControlPlaneCustodyClient.claim_oidc_session_activation_release(
            custody, client_authorization_digest=admitted_client.authorization_digest,
            request_identity=scope["requestIdentity"], profile=clients.LIVE_PROFILE,
            server_bootstrap_digest=scope["serverBootstrapDigest"], expected_outcome_digest=outcome_digest))
    current()
    window, bound = permission._planning_bounds
    returned = transport._socket_request(endpoint, profile=clients.LIVE_PROFILE, originals=request,
        deadline_ns=bound, work=work, current=current)
    current()
    window, bound = permission._planning_bounds
    # No weaker post-verification owner callback or success carrier follows.
    return receiving._verify_on_work(response_originals=returned, request_originals=request,
        client_authorization_bytes=client_raw, server_bootstrap_bytes=server_raw,
        root_public_key=root, expected_client_scope=scope, live_window=window,
        transport_deadline_ns=bound, work=work, _continuity=receiving_continuity)
