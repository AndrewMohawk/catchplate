"""Same-permission private proof exchange and original-only public admission.

Optional root-policy setup uses the same irreversible claim before worker I/O.
The worker performs private replay. This caller retains the exact replies before
authenticating its root custody and distinct proof against the actual intent,
completion and expected delivery. Neither path opens the new token here.
"""
from __future__ import annotations

from serverware import authority_current_root_authorization as state
from serverware import authority_oidc_session_activation_release_intent as intent
from serverware import authority_oidc_session_activation_release_proof as proof
from serverware import authority_oidc_session_activation_release_proof_transport as transport
from serverware import authority_oidc_session_activation_release_proof_input_transport as setup_transport
from serverware import control_plane_oidc_session_activation_consume_records as retained
from serverware import control_plane_oidc_session_activation_execution as execution
from serverware import control_plane_oidc_session_activation_release_intent_bootstrap as intent_config
from serverware import control_plane_oidc_session_activation_release_proof_bootstrap as configured
from serverware import control_plane_oidc_session_activation_release_proof_acquisition_bootstrap as acquisition
from serverware import control_plane_oidc_session_activation_consume_planning as planning
from serverware import oidc_session_activation_release_proof_bootstrap as worker_bootstrap


plan, production = intent.plan, intent.production


def _prove_on_permission(permission):
    """Accept no target, originals, possession, success carrier or new allowance."""
    if type(permission) is not execution._ActivationPermission:
        execution._fail("release proof requires the actual active permission")
    permission._identity()
    owner, work = permission._owner, permission._work
    parent, binding, custody = owner._material, owner._binding, owner._custody
    policy, intent_policy = parent.release_proof, parent.release_intent
    setup_policy = parent.release_proof_acquisition
    original, context = permission._release_intent_original, permission._release_intent_context
    completed, activation_raw = permission._consume_completion_originals, permission._sql_originals
    possession, target = permission._consume_possession, permission._target
    root = binding.runtime_root_public_key
    if (permission._state != "active" or permission._dispatch_phase != "release-proof-requesting"
            or permission._release_proof_spent is not True
            or type(policy) is not configured._ReleaseProofMaterial
            or type(intent_policy) is not intent_config._ReleaseIntentMaterial
            or original is not permission._release_intent_seal
            or context is not permission._release_intent_context_seal
            or completed is not permission._consume_completion_seal or completed[0] != b"acknowledged"
            or activation_raw is not permission._sql_seal or possession is not permission._consume_possession_seal
            or (binding.caller_uid, binding.caller_gid) != (65532, 65532)):
        execution._fail("release proof lacks its actual acknowledged intent continuation")
    release_original, guard, prior_narrow, prior_bytes = context
    scope_original, enrollment = policy.expected_scope_bytes, policy.enrollment_bytes
    forbidden, public_key = policy.forbidden_public_keys, policy.proof_public_key
    endpoint = transport._endpoint(policy.endpoint)
    if setup_policy is not None and type(setup_policy) is not acquisition._ReleaseProofAcquisitionMaterial:
        execution._fail("release proof setup requires actual cold acquisition configuration")
    setup_endpoint = setup_transport._endpoint(setup_policy.endpoint) if setup_policy is not None else None
    setup_original = setup_policy.issuer_policy_bytes if setup_policy is not None else None
    setup_planner_original = setup_policy.current_activation_planner_bytes if setup_policy is not None else None
    request_bound = setup_policy is not None and setup_policy.request_bound is True
    response_pin = owner._response_pin
    planning_material = parent.activation_planning
    resource_original = None
    if request_bound:
        from serverware import control_plane_oidc_session_activation_request_dispatch as requested
        from serverware import control_plane_oidc_session_activation_request_issuance_bootstrap as resource_config
        if type(planning_material) is not resource_config._RequestPlanningMaterial or setup_planner_original is not None:
            execution._fail("resource proof requires actual request planning without a future template")
        resource_original = planning_material.policy_bytes
        planner_original = requested._planner_original_on_permission(permission)
    else:
        planner_original = planning_material.planner_bootstrap_bytes
    intent_enrollment, intent_scope_original = intent_policy.enrollment_bytes, intent_policy.expected_scope_bytes
    intent_forbidden = intent_policy.forbidden_public_keys
    target_digest = target[2]["localDigest"]
    state.shape._digest(target_digest)
    cookie = permission._request.cookies.get(possession[0])
    if (cookie != possession[1] or type(cookie) is not str or len(cookie) != intent.delivery.TOKEN_BYTES
            or any(ord(character) > 127 for character in cookie)):
        execution._fail("release proof lost actual old-token possession")
    work.charge(input_bytes=len(cookie))
    old = intent.delivery._token(cookie.encode("ascii"), work)
    reserved = (prior_bytes + len(scope_original) + len(enrollment) + len(old)
        + transport.REQUEST_HEADER_BYTES + transport.MAX_REQUEST_BYTES
        + transport.RESPONSE_HEADER_BYTES + transport.MAX_RESPONSE_BYTES)
    if reserved > planning.consume.MAX_ORIGINAL_BYTES:
        execution._fail("release proof exceeds the original whole-call inventory")
    guards = []
    setup_material = None

    def base_current():
        if (owner._material is not parent or owner._binding is not binding or owner._custody is not custody
                or parent.release_proof is not policy or parent.release_intent is not intent_policy
                or parent.release_proof_acquisition is not setup_policy
                or (setup_policy is not None and (setup_policy.endpoint != setup_endpoint
                    or setup_policy.issuer_policy_bytes is not setup_original
                    or setup_policy.current_activation_planner_bytes is not setup_planner_original
                    or setup_policy.request_bound is not request_bound))
                or binding.runtime_root_public_key is not root or policy.endpoint != endpoint
                or policy.expected_scope_bytes is not scope_original or policy.enrollment_bytes is not enrollment
                or policy.forbidden_public_keys is not forbidden or policy.proof_public_key is not public_key
                or intent_policy.enrollment_bytes is not intent_enrollment
                or intent_policy.expected_scope_bytes is not intent_scope_original
                or intent_policy.forbidden_public_keys is not intent_forbidden
                or parent.activation_planning is not planning_material
                or (request_bound and (planning_material.policy_bytes is not resource_original
                    or requested._planner_original_on_permission(permission) is not planner_original))
                or (not request_bound and planning_material.planner_bootstrap_bytes is not planner_original)
                or owner._response_pin != response_pin
                or permission._release_intent_original is not original or permission._release_intent_context is not context
                or permission._consume_completion_originals is not completed or permission._sql_originals is not activation_raw
                or permission._target is not target or target[2]["localDigest"] != target_digest
                or permission._consume_possession is not possession
                or permission._request.cookies.get(possession[0]) != cookie):
            execution._fail("release proof changed its original context or cold resources")
        return guard()

    def continuity(epoch, monotonic):
        permission._continuity(epoch, monotonic)
        base_current()
        return permission._planning_observed

    def current():
        now = base_current()
        for check in guards:
            observed = check()
            now = base_current()
            if observed > now:
                execution._fail("release proof owner clocks reversed across admitted originals")
        return now

    def narrow(expiry, age, skew):
        previous, previous_bound = permission._planning_bounds
        prior_narrow(expiry, min(previous[5], age), min(previous[6], skew))
        selected, selected_bound = permission._planning_bounds
        if (selected[:3] != previous[:3] or selected_bound > previous_bound
                or any(selected[index] > previous[index] for index in (3, 4, 5, 6))):
            execution._fail("release proof replaced or widened its original allowance")
        current()

    current()
    scope = configured._scope_on_work(scope_original, work)
    intent_scope = intent_config._scope_on_work(intent_scope_original, work)
    release = planning.activation._object(release_original, intent.contract.MAX_BYTES, work)
    intent_scope, release = intent._graphs(intent_scope, release)
    for name in ("configurationDigest", "databaseId", "generationDigest", "runtimeClosureDigest", "receiverIdentity"):
        plan._same(scope[name], intent_scope[name], work, "release proof same intent scope " + name)
    enrolled = proof.enrollments._admit_on_work(enrollment_bytes=enrollment, root_public_key=root,
        expected_scope=scope, forbidden_public_keys=forbidden, work=work)
    current()
    plan._same(enrolled.enrollment_digest, policy.enrollment_digest, work, "release proof actual cold enrollment")
    proof_pin = proof.enrollments.keys._spki_on_work(enrolled.proof_public_key, work)
    plan._same(proof_pin, proof.enrollments.keys._spki_on_work(public_key, work), work,
        "release proof actual cold signer")
    if response_pin is None or proof_pin == response_pin:
        execution._fail("release proof signer reuses or lacks the actual response-key separation")
    window, bound = permission._planning_bounds
    admitted_intent = intent._verify_on_work(intent_bytes=original, enrollment_bytes=intent_enrollment,
        root_public_key=root, forbidden_public_keys=intent_forbidden, expected_scope=intent_scope,
        expected_release=release, old_token_bytes=old, live_window=window, transport_deadline_ns=bound,
        work=work, _continuity=continuity)
    if type(admitted_intent) is not intent._AdmittedIntent:
        execution._fail("release proof requires actual original intent admission")
    guards.append(admitted_intent.live)
    intent_interval = admitted_intent.payload["issuedAtEpochNs"], admitted_intent.payload["expiresAtEpochNs"]
    age, skew = enrolled.payload["maximumAgeNs"], enrolled.payload["maximumClockSkewNs"]
    narrow(intent_interval[1], age, skew)
    activation_digest = plan._frame(execution.caller.REQUEST_IDENTITY_DOMAIN, (activation_raw[0],), work)
    request = transport._originals((transport.PURPOSE, admitted_intent.intent_digest.encode("ascii"), old), response=False)
    setup_request, setup_budget = None, None
    if setup_policy is not None:
        current()
        policy_reservation = 0
        if request_bound:
            # Own the embedded static policy's repeated original graphs before
            # decoding, within the unchanged whole-call inventory ceiling.
            policy_reservation = 8 * (len(setup_original) + len(resource_original))
            reserved += policy_reservation
            if reserved >= planning.consume.MAX_ORIGINAL_BYTES:
                execution._fail("resource proof policy exceeds the original whole-call capacity")
        if setup_planner_original is not None:
            planning._same_bytes(setup_planner_original, planner_original, work,
                "release proof setup independently current planner")
            # The versioned original embeds a planner. Reserve its decode and
            # repeated policy captures before that first new body, not after.
            policy_reservation = 8 * (len(setup_original) + len(setup_planner_original))
            reserved += policy_reservation
            if reserved >= planning.consume.MAX_ORIGINAL_BYTES:
                execution._fail("versioned proof policy exceeds the original whole-call capacity")
        policy_window, policy_bound = permission._planning_bounds
        setup_payload = acquisition._policy_on_work(setup_original, release_intent=intent_policy,
            release_proof=policy, root_public_key=root, work=work,
            activation_planner_bytes=None if request_bound else planner_original,
            activation_policy_bytes=resource_original, current=current,
            live_window=policy_window if request_bound else None,
            transport_deadline_ns=policy_bound if request_bound else None,
            _continuity=continuity if request_bound else None)
        current()
        window, _bound = permission._planning_bounds
        interval = setup_payload["issuedAtEpochNs"], setup_payload["expiresAtEpochNs"]
        guards.append(worker_bootstrap.completion.primitives._launch_guard(interval,
            (window[1], window[0], window[2]), base_current, work))
        narrow(interval[1], age, skew)
        setup_request = setup_transport._originals(
            (setup_transport.PURPOSE, completed[2], completed[3], original), response=False)
        policy_size, _policy_nodes = work.measure(setup_payload)
        current()
        if request_bound:
            if 4 * len(setup_original) + 2 * policy_size + 8 * len(resource_original) > policy_reservation:
                execution._fail("resource proof policy exceeds its pre-decoding capture reservation")
        elif setup_planner_original is None:
            reserved += 4 * len(setup_original) + 2 * policy_size
        elif 4 * len(setup_original) + 2 * policy_size + 8 * len(setup_planner_original) > policy_reservation:
            execution._fail("versioned proof policy exceeds its pre-decoding capture reservation")
        reserved += (sum(map(len, setup_request)) + setup_transport.REQUEST_HEADER_BYTES
            + setup_transport.RESPONSE_HEADER_BYTES)
        # Reserve outer JSON, decoded originals and both independently admitted
        # nested material graphs before accepting any body. This conservative
        # fixed multiplier also covers simultaneous canonical readback copies.
        setup_budget = min(worker_bootstrap.MAX_BYTES,
            (planning.consume.MAX_ORIGINAL_BYTES - reserved) // 8)
        if setup_budget < 2:
            execution._fail("release proof setup has no bounded whole-call response capacity")
    work.charge(input_bytes=retained._append_io_bytes("release-proof-claimed", ()))
    current()
    production._callback(work, lambda:
        execution.custody.ControlPlaneCustodyClient.claim_oidc_session_activation_consume_release_proof_attempt(
            custody, finalization_digest=target_digest, activation_authorization_digest=activation_digest))
    current()
    window, bound = permission._planning_bounds
    if setup_request is not None:
        returned = setup_transport._socket_request_on_work(setup_endpoint, originals=setup_request,
            deadline_ns=bound, work=work, current=current, maximum_response_bytes=setup_budget)
        current()
        returned = setup_transport._originals(returned, response=True)
        if len(returned[0]) > setup_budget:
            execution._fail("release proof setup exceeded its original response reservation")
        work.charge(input_bytes=retained._append_io_bytes("release-proof-setup", returned))
        current()
        setup_digest = production._callback(work, lambda:
            execution.custody.ControlPlaneCustodyClient.append_oidc_session_activation_consume_release_proof_setup(
                custody, finalization_digest=target_digest, activation_authorization_digest=activation_digest,
                originals=returned))
        current()
        state.shape._digest(setup_digest)
        reserved += 8 * len(returned[0])
        setup_material = worker_bootstrap._verify_on_work(bootstrap_bytes=returned[0], root_public_key=root,
            live_window=window, transport_deadline_ns=bound, work=work, _current=base_current)
        if type(setup_material) is not worker_bootstrap._ProofMaterial:
            execution._fail("release proof setup lacks actual original bootstrap admission")
        guards.append(setup_material.live)
        current()
        if setup_planner_original is None:
            if (setup_material.current_activation_planner_bytes is not None
                    or setup_material.current_activation_planner is not None):
                execution._fail("legacy proof policy cannot select a versioned setup")
        else:
            planning._same_bytes(setup_material.current_activation_planner_bytes,
                setup_planner_original, work, "release proof setup exact current planner")
            if type(setup_material.current_activation_planner) is not worker_bootstrap.release_bootstrap.planner_bootstrap._PlannerMaterial:
                execution._fail("versioned proof setup lacks genuine current planner admission")
        plan._same(proof.enrollments.keys._spki_on_work(setup_material.completion_material.evidence_root_public_key, work),
            proof.enrollments.keys._spki_on_work(root, work), work,
            "ordinary release proof keeps its actual consume root")
        for actual, expected, label in (
                (setup_material.intent_bytes, original, "intent"),
                (setup_material.intent_enrollment_bytes, intent_enrollment, "intent enrollment"),
                (setup_material.proof_enrollment_bytes, enrollment, "proof enrollment"),
                (setup_material.completion_request_bytes, completed[2], "completion request"),
                (setup_material.state_receipt_bytes, completed[3], "state receipt")):
            planning._same_bytes(actual, expected, work, "release proof setup exact " + label)
        for actual, expected, label in (
                (setup_material.expected_proof_scope, scope, "proof scope"),
                (setup_material.expected_release, release, "release"),
                (setup_material.caller_id, intent_scope["callerId"], "caller")):
            plan._same(actual, expected, work, "release proof setup independent " + label)
        narrow(setup_material.live_window[3], setup_material.live_window[5], setup_material.live_window[6])
        window, bound = permission._planning_bounds
        issued = acquisition.issuer._verify_on_work(policy_bytes=setup_original,
            completion_bootstrap_bytes=setup_material.completion_bootstrap_bytes,
            proof_enrollment_bytes=enrollment, intent_enrollment_bytes=intent_enrollment,
            root_public_key=root, live_window=window, transport_deadline_ns=bound, work=work,
            _continuity=continuity)
        if type(issued) is not acquisition.issuer._IssuerPolicyMaterial:
            execution._fail("release proof setup requires genuine independent issuer policy admission")
        guards.append(issued.live)
        if setup_planner_original is None:
            if issued.current_activation_planner_bytes is not None or issued.current_activation_planner is not None:
                execution._fail("legacy proof issuer changed its planner profile")
        else:
            planning._same_bytes(issued.current_activation_planner_bytes,
                setup_planner_original, work, "release proof issuer exact current planner")
            planning._same_bytes(issued.current_activation_planner.bootstrap_bytes,
                setup_material.current_activation_planner.bootstrap_bytes, work,
                "release proof issuer and setup genuine current context")
        plan._same(setup_material.launch, issued.proof_launch, work, "release proof setup root launch")
        narrow(issued.live_window[3], issued.live_window[5], issued.live_window[6])
        window, bound = permission._planning_bounds
    response = transport._socket_request_on_work(endpoint, originals=request, deadline_ns=bound,
        work=work, current=current)
    current()
    response = transport._originals(response, response=True)
    work.charge(input_bytes=retained._append_io_bytes("release-proof", response))
    current()
    record_digest = production._callback(work, lambda:
        execution.custody.ControlPlaneCustodyClient.append_oidc_session_activation_consume_release_proof(
            custody, finalization_digest=target_digest, activation_authorization_digest=activation_digest,
            originals=response))
    current()
    state.shape._digest(record_digest)
    if response[0] != b"proved":
        execution._fail("release proof returned no successful original proof")
    if setup_material is not None:
        planning._same_bytes(response[1], setup_material.release_custody_bytes, work,
            "release proof response differs from the exact acquired root custody")
    planning._same_bytes(response[3], enrollment, work, "release proof exact independently enrolled signer")
    root_custody = proof.bootstrap._verify_on_work(custody_bytes=response[1], root_public_key=root,
        live_window=window, transport_deadline_ns=bound, work=work)
    current()
    guards.append(proof.bootstrap.planner_bootstrap._launch_guard(root_custody.attestation_interval,
        root_custody.opening_sample, base_current, work))
    planning._same_bytes(root_custody.planner.bootstrap_bytes, planner_original, work,
        "release proof same original activation planner")
    for actual, expected, label in (
            (root_custody.release_intent_digest, admitted_intent.intent_digest, "intent"),
            (root_custody.activation_request_digest, release["activationRequestDigest"], "activation request"),
            (root_custody.activation_operation_id, release["activationOperationId"], "activation operation"),
            (root_custody.consume_request_digest, release["consumeRequestDigest"], "consume request"),
            (root_custody.delivery_envelope_digest, release["deliveryEnvelopeDigest"], "encrypted envelope"),
            (root_custody.delivery_scope, release["deliveryScope"], "delivery scope"),
            (root_custody.receiver_identity, scope["receiverIdentity"], "receiver"),
            (root_custody.planner.configuration_digest, scope["configurationDigest"], "configuration"),
            (root_custody.planner.generation["digest"], scope["generationDigest"], "generation"),
            (root_custody.planner.runtime_closure_digest, scope["runtimeClosureDigest"], "runtime closure")):
        plan._same(actual, expected, work, "release proof independent root custody " + label)
    narrow(root_custody.attestation_interval[1], root_custody.planner.maximum_plan_age_ns,
        root_custody.planner.maximum_clock_skew_ns)
    evidence = {"releaseCustodyDigest": plan._frame(proof.contract.CUSTODY_IDENTITY_DOMAIN, (response[1],), work),
        "releaseIntentDigest": admitted_intent.intent_digest,
        "stateReceiptDigest": plan._frame(state.RECEIPT_IDENTITY_DOMAIN, (completed[3],), work)}
    window, bound = permission._planning_bounds
    admitted = proof._verify_on_work(proof_bytes=response[2], enrollment_bytes=response[3],
        root_public_key=root, forbidden_public_keys=forbidden, expected_scope=scope, expected_release=release,
        expected_evidence=evidence, expected_intent_interval=intent_interval, live_window=window,
        transport_deadline_ns=bound, work=work, _continuity=continuity)
    if type(admitted) is not proof._AdmittedProof:
        execution._fail("release proof requires actual signed-original admission")
    guards.append(admitted.live)
    narrow(min(admitted.payload["expiresAtEpochNs"], admitted.payload["issuedAtEpochNs"] + age), age, skew)
    permission._release_proof_originals = permission._release_proof_seal = response
    permission._release_proof_context = permission._release_proof_context_seal = (
        release_original, current, narrow, reserved)
    permission._dispatch_phase = "release-proof-verified"
    current()
    return response
