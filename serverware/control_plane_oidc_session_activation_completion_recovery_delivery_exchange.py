"""One independently authorized LIVE exchange on a fresh release-purpose actor.

Only the actual source owner supplies retained originals. Missing history never
selects a checkpoint; genuine root client/server originals must authorize LIVE
checkpoint zero. No SQL, signing, setup, store probing or recovery fallback.
"""
from __future__ import annotations

from serverware import control_plane_oidc_session_activation_release_handoff as shared
from serverware import control_plane_oidc_session_activation_completion_recovery_intent_inputs as inputs_source
from serverware import control_plane_oidc_session_activation_completion_recovery_intent as intent_source
from serverware import control_plane_oidc_session_activation_completion_recovery_proof as proof_source


clients, receiving, transport = shared.clients, shared.receiving, shared.transport
intents, proofs, outcomes, hints = shared.intents, shared.proofs, shared.outcomes, shared.hints
state, plan, configured = shared.state, shared.plan, shared.configured
execution, attempts, bookkeeping = shared.execution, shared.attempts, intent_source.bookkeeping
MAX_ORIGINAL_BYTES = receiving.MAX_ORIGINAL_BYTES
EXCHANGE_RESERVATION_BYTES = 8 * 1024 * 1024
MAX_GRANT_RESPONSE_BYTES = 128 * 1024
_GRANT_IO_BYTES = 2 * 1024 * 1024
_AUTH_RESERVATION = 256 * 1024
_CLAIM_IO_BYTES = attempts.MAX_CLAIM_IO_BYTES + shared.retained.COMPLETION_RECOVERY_METADATA_BYTES


def _fail(message):
    execution._fail(message)


def _same(actual, expected, work, label):
    bookkeeping._same_bytes(actual, expected, work, "completion release " + label)


def _exchange_on_active(active, *, _delivery=None):
    """A spent, in-progress source call only; the genuine receiver returns token64."""
    from serverware import control_plane_oidc_session_activation_completion_recovery_delivery as owner_call

    if (type(active) is not owner_call._DeliveryAttempt or owner_call._ACTIVE is not active
            or active._closed is not False or active._exchange_spent is not True
            or active._exchange_in_progress is not True or active._exchange_complete is not False
            or active._exchange_failed is not False or active._receiving_current is not None
            or active._receiving_seal is not None or active._token is not None
            or active._token_seal is not None
            or active._delivery is not _delivery or active._delivery_seal is not _delivery):
        _fail("completion release exchange requires its actual one-use active owner")
    owner_call._DeliveryAttempt._parent_current(active)
    inputs = inputs_source._require_inputs(active.inputs)
    selected_intent = intent_source._require_intent(active.intent)
    selected_proof = proof_source._require_proof(active.proof)
    actor, controls, response = active.actor, active.controls, active.response
    owner, work, root = active._owner, active._work, active._root
    parent, binding, custody, parent_lifetime = active._parent, active._binding, active._custody, active._lifetime
    grants = active.grants
    activation_authority, consume_authority = controls.authority, controls.consume_authority
    consume_selection = actor._consume_recovery_selection
    if (inputs._purpose != "release" or actor._purpose != "release"
            or inputs.actor is not actor or inputs.controls is not controls or inputs.work is not work
            or inputs.response_originals is not response or inputs.root_public_key is not root
            or selected_intent.inputs is not inputs or selected_proof.intent is not selected_intent
            or actor._owner is not owner or owner._material is not parent
            or owner._binding is not binding or owner._custody is not custody
            or binding.runtime_root_public_key is not root
            or activation_authority is not actor._target.authority
            or consume_authority is None or consume_selection is None
            or consume_selection.authority is not consume_authority
            or controls.root_public_key is not consume_authority.root_public_key
            or (binding.caller_uid, binding.caller_gid) != (clients.CLIENT_UID, clients.CLIENT_GID)
            or type(inputs.original_reservation_bytes) is not int
            or not EXCHANGE_RESERVATION_BYTES <= inputs.original_reservation_bytes < MAX_ORIGINAL_BYTES):
        _fail("completion release exchange changed its original release actor or reserve")
    client_raw, server_raw = shared.grant_transport._originals(grants, response=True)
    if sum(map(len, grants)) > MAX_GRANT_RESPONSE_BYTES:
        _fail("completion release grants exceed the original bounded acquisition lane")
    policy, proof_policy, intent_policy = parent.release_handoff, inputs.proof_policy, inputs.intent_policy
    if (type(policy) is not configured._ReleaseHandoffMaterial
            or parent.release_proof is not proof_policy or parent.release_intent is not intent_policy):
        _fail("completion release requires independent parent handoff pins")
    proof_raw, intent_raw, old = selected_proof._originals, selected_intent.intent_bytes, inputs.old_token_bytes
    if (type(proof_raw) is not tuple or len(proof_raw) != 4 or proof_raw[0] != b"proved"
            or type(response) is not tuple or len(response) != 6 or response[0] != b"acknowledged"
            or type(old) is not bytes or len(old) != clients.delivery.TOKEN_BYTES
            or actor._old_token is not old):
        _fail("completion release requires exact retained proof, completion and possession")
    identity_raw, endpoint_raw, client_id = policy.client_identity_bytes, policy.endpoint_bytes, policy.client_id
    proof_scope, intent_scope, release = inputs.proof_scope, inputs.intent_scope, inputs.expected_release
    intent_enrollment, proof_enrollment = intent_policy.enrollment_bytes, proof_policy.enrollment_bytes
    consume_root, consume_state = consume_authority.root_public_key, controls.enrollment_bytes
    held = (actor, controls, response, inputs, selected_intent, selected_proof, grants,
        owner, work, parent, binding, custody, root, parent_lifetime)

    def active_identity():
        observed = (active.actor, active.controls, active.response, active.inputs, active.intent,
            active.proof, active.grants, active._owner, active._work, active._parent,
            active._binding, active._custody, active._root, active._lifetime)
        if (type(active) is not owner_call._DeliveryAttempt or owner_call._ACTIVE is not active
                or active._closed is not False or active._exchange_spent is not True
                or active._exchange_failed is not False or actor._old_token is not old
                or actor._purpose != "release"
                or controls.authority is not activation_authority
                or controls.consume_authority is not consume_authority
                or actor._consume_recovery_selection is not consume_selection
                or consume_authority.root_public_key is not consume_root
                or controls.enrollment_bytes is not consume_state
                or any(actual is not original for actual, original in zip(observed, held))):
            _fail("completion release original owner changed or closed")

    def original_parent_continuity(epoch, monotonic):
        active_identity()
        return owner_call._DeliveryAttempt._parent_continuity(active, epoch, monotonic)

    identity, ancestor = active_identity, original_parent_continuity
    retain_current = active._retain_receiving_current
    if _delivery is not None:
        from serverware import control_plane_oidc_session_activation_completion_recovery_delivery_response as terminal

        if (type(_delivery) is not terminal._StagedRecoveryResponse
                or _delivery._active is not active or terminal._AUTH_RESERVATION != _AUTH_RESERVATION):
            _fail("completion release final delivery is not its exact source terminal")
        ancestor = terminal._StagedRecoveryResponse._exchange_on_active(
            _delivery, active, original_parent_continuity)
        identity = lambda: terminal._StagedRecoveryResponse._identity(_delivery)
        retain_current = _delivery._retain_receiver

    # Select the terminal BEFORE every new LIVE admission. A closed ordinary
    # actor/proof continuation is never revived by any descendant below.
    lifetime = bookkeeping._Lifetime(parent_lifetime.window, parent_lifetime.bound, work, ancestor)

    def current():
        identity()
        return lifetime.current()

    def receiving_continuity(epoch, monotonic):
        identity()
        lifetime._floors(max(lifetime.epoch, epoch), max(lifetime.monotonic, monotonic))
        current()
        return lifetime.epoch, lifetime.monotonic

    current()
    lengths = (len(transport.LIVE_PURPOSE), len(proof_raw[2]), len(proof_enrollment),
        len(intent_raw), len(intent_enrollment), len(old), clients.delivery.ENVELOPE_BYTES)
    fixed = (_AUTH_RESERVATION + _CLAIM_IO_BYTES + 8 * hints.MAX_DESCRIPTOR_BYTES
        + 8 * (len(identity_raw) + len(endpoint_raw)) + 4 * sum(map(len, grants))
        + 8 * (len(consume_state) + min(state.MAX_ENROLLMENT_BYTES, len(server_raw)))
        + 4 * (transport.LIVE_REQUEST_HEADER_BYTES + transport.RESPONSE_HEADER_BYTES))
    first = receiving._reservation_bytes(lengths, client_bytes=len(client_raw),
        bootstrap_bytes=len(server_raw))
    lane = receiving._reservation_bytes(lengths, client_bytes=len(client_raw),
        bootstrap_bytes=len(server_raw), additional_original_bytes=fixed + first)
    held_before_exchange = inputs.original_reservation_bytes - EXCHANGE_RESERVATION_BYTES
    if (MAX_ORIGINAL_BYTES != 64 * 1024 * 1024 or lane > EXCHANGE_RESERVATION_BYTES
            or held_before_exchange + lane > MAX_ORIGINAL_BYTES):
        _fail("completion release and both genuine admissions exceed the reserved lane")
    receiving_extra = held_before_exchange + fixed + first
    # No payload decode precedes this actual-length, double-admission bound.
    client_identity = configured._identity_on_work(identity_raw, work)
    endpoint_graph = configured._endpoint_on_work(endpoint_raw, work)
    endpoint = clients._endpoint(endpoint_graph, work)
    current()
    _same(proof_raw[3], proof_enrollment, work, "independent proof enrollment")
    enrolled_intent = intents.enrollments._admit_on_work(enrollment_bytes=intent_enrollment,
        root_public_key=root, expected_scope=intent_scope,
        forbidden_public_keys=intent_policy.forbidden_public_keys, work=work)
    current()
    enrolled_proof = proofs.enrollments._admit_on_work(enrollment_bytes=proof_enrollment,
        root_public_key=root, expected_scope=proof_scope,
        forbidden_public_keys=proof_policy.forbidden_public_keys, work=work)
    current()
    plan._same(enrolled_intent.enrollment_digest, intent_policy.enrollment_digest, work,
        "completion release actual intent enrollment")
    plan._same(enrolled_proof.enrollment_digest, proof_policy.enrollment_digest, work,
        "completion release actual proof enrollment")
    age = min(enrolled_intent.payload["maximumAgeNs"], enrolled_proof.payload["maximumAgeNs"])
    skew = min(enrolled_intent.payload["maximumClockSkewNs"], enrolled_proof.payload["maximumClockSkewNs"])
    lifetime.narrow(lifetime.window[3], age, skew)
    admitted_intent = intents._verify_on_work(intent_bytes=intent_raw,
        enrollment_bytes=intent_enrollment, root_public_key=root,
        forbidden_public_keys=intent_policy.forbidden_public_keys,
        expected_scope=intent_scope, expected_release=release, old_token_bytes=old,
        live_window=lifetime.window, transport_deadline_ns=lifetime.bound,
        work=work, _continuity=lifetime.continuity)
    if type(admitted_intent) is not intents._AdmittedIntent:
        _fail("completion release requires genuine current intent admission")
    lifetime.attach(admitted_intent.live)
    interval = admitted_intent.payload["issuedAtEpochNs"], admitted_intent.payload["expiresAtEpochNs"]
    lifetime.narrow(interval[1], age, skew)
    evidence = {"releaseCustodyDigest": plan._frame(proofs.contract.CUSTODY_IDENTITY_DOMAIN,
            (proof_raw[1],), work), "releaseIntentDigest": admitted_intent.intent_digest,
        "stateReceiptDigest": plan._frame(state.RECEIPT_IDENTITY_DOMAIN, (response[3],), work)}
    current()
    admitted_proof = proofs._verify_on_work(proof_bytes=proof_raw[2], enrollment_bytes=proof_enrollment,
        root_public_key=root, forbidden_public_keys=proof_policy.forbidden_public_keys,
        expected_scope=proof_scope, expected_release=release, expected_evidence=evidence,
        expected_intent_interval=interval, live_window=lifetime.window,
        transport_deadline_ns=lifetime.bound, work=work, _continuity=lifetime.continuity)
    if type(admitted_proof) is not proofs._AdmittedProof:
        _fail("completion release requires genuine current proof admission")
    lifetime.attach(admitted_proof.live)
    lifetime.narrow(min(admitted_proof.payload["expiresAtEpochNs"],
        admitted_proof.payload["issuedAtEpochNs"] + age), age, skew)
    packet, effects, envelope, created, expires = hints._decode_on_work(response[4:], work=work)
    for actual, expected, label in (
            (packet, release["consumeBinding"]["packetDigest"], "packet"),
            (effects, release["consumeBinding"]["effectsDigest"], "effects"),
            (created, release["deliveryScope"]["createdAt"], "created"),
            (expires, release["deliveryScope"]["expiresAt"], "expires"),
            (shared.planning.assertion._digest(envelope, work), release["deliveryEnvelopeDigest"], "envelope")):
        plan._same(actual, expected, work, "completion release signed hint " + label)
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
    request = transport._originals((transport.LIVE_PURPOSE, proof_raw[2], proof_enrollment,
        intent_raw, intent_enrollment, old, envelope), response=False, profile=clients.LIVE_PROFILE)
    request_identity = transport._request_identity_on_work(request, profile=clients.LIVE_PROFILE,
        deadline_ns=lifetime.bound, work=work, current=current)
    current()
    expected_scope = clients._scope({**proof_scope,
        "serverBootstrapDigest": clients._server_bootstrap_digest_on_work(server_raw, work),
        "profile": clients.LIVE_PROFILE, "requestIdentity": request_identity.decode("ascii"),
        "clientId": client_id, "clientIdentity": client_identity, "callerId": intent_scope["callerId"],
        "stateReceiptDigest": evidence["stateReceiptDigest"], "expectedRelease": release,
        "expectedOutcomeDigest": outcome_digest, "endpoint": endpoint_graph}, work)
    current()
    admitted = clients._verify_on_work(authorization_bytes=client_raw,
        server_bootstrap_bytes=server_raw, root_public_key=root, expected_scope=expected_scope,
        live_window=lifetime.window, transport_deadline_ns=lifetime.bound,
        work=work, _continuity=lifetime.continuity)
    if type(admitted) is not clients._ClientAuthorization or type(admitted.server_material) is not clients.server._ReleaseMaterial:
        _fail("completion release requires genuine current client/server originals")
    lifetime.attach(admitted.live)
    lifetime.adopt(admitted.live_window, admitted.deadline_ns)
    material = admitted.server_material
    if (material.profile != clients.LIVE_PROFILE or material.recovery_scope is not None
            or material.storage_scope["checkpoint"] != {"recordCount": 0, "outcomeDigest": None}):
        _fail("completion release requires independently root-authorized LIVE checkpoint zero")
    _same(material.custody_bytes, proof_raw[1], work, "root server exact retained proof custody")
    root_custody = material.custody_material
    _same(root_custody.planner.bootstrap_bytes, inputs.planner_original, work, "original activation planner")
    # R1 authenticates only the retained consume evidence. The independently
    # current R2 server must preserve its complete state contract, not merely
    # a database ID or generation. Both signatures are checked on this work;
    # no retired authority becomes a grant or a token-release signer.
    current_state = state._admit_enrollment_on_work(
        enrollment_bytes=root_custody.planner.state_enrollment_bytes,
        root_public_key=root, work=work)
    current()
    original_state = state._admit_enrollment_on_work(enrollment_bytes=consume_state,
        root_public_key=consume_root, work=work)
    current()
    plan._same(current_state.payload, original_state.payload, work,
        "completion release unchanged original/current complete state payload")
    for actual, expected, label in (
            (current_state.payload["databaseId"], proof_scope["databaseId"], "database"),
            (current_state.payload["generationDigest"], proof_scope["generationDigest"], "generation"),
            (material.delivery_key_digest, root_custody.delivery_key_digest, "custody delivery key"),
            (root_custody.delivery_key_digest, root_custody.planner.delivery_key_digest, "planner delivery key")):
        plan._same(actual, expected, work, "completion release original/current " + label)
    for actual, expected, label in (
            (root_custody.release_intent_digest, admitted_intent.intent_digest, "intent"),
            (root_custody.activation_request_digest, release["activationRequestDigest"], "activation request"),
            (root_custody.activation_operation_id, release["activationOperationId"], "activation operation"),
            (root_custody.consume_request_digest, release["consumeRequestDigest"], "consume request"),
            (root_custody.delivery_envelope_digest, release["deliveryEnvelopeDigest"], "envelope"),
            (root_custody.delivery_scope, release["deliveryScope"], "delivery scope"),
            (root_custody.receiver_identity, proof_scope["receiverIdentity"], "receiver"),
            (root_custody.planner.configuration_digest, proof_scope["configurationDigest"], "configuration"),
            (root_custody.planner.generation["digest"], proof_scope["generationDigest"], "generation"),
            (root_custody.planner.runtime_closure_digest, proof_scope["runtimeClosureDigest"], "runtime closure"),
            (material.storage_scope["releaseCustodyDigest"], evidence["releaseCustodyDigest"], "storage custody")):
        plan._same(actual, expected, work, "completion release independent custody " + label)
    lifetime.attach(proofs.bootstrap.planner_bootstrap._launch_guard(root_custody.attestation_interval,
        root_custody.opening_sample, lifetime.base, work))
    lifetime.narrow(root_custody.attestation_interval[1], root_custody.planner.maximum_plan_age_ns,
        root_custody.planner.maximum_clock_skew_ns)
    current()
    # Canonical outcome reconstruction binds this request, not store absence.
    # The directly metered same-global claim is terminal before any socket.
    claim = execution.custody.ControlPlaneCustodyClient.claim_oidc_session_activation_completion_recovery_release_attempt(
        custody, client_authorization_digest=admitted.authorization_digest,
        request_identity=expected_scope["requestIdentity"], profile=clients.LIVE_PROFILE,
        server_bootstrap_digest=expected_scope["serverBootstrapDigest"], expected_outcome_digest=outcome_digest,
        work=work, current=current, maximum_original_bytes=_CLAIM_IO_BYTES)
    current()
    plan._same(claim, admitted.authorization_digest, work, "completion release exact irreversible claim")
    returned = transport._socket_request(endpoint, profile=clients.LIVE_PROFILE,
        originals=request, deadline_ns=lifetime.bound, work=work, current=current)
    current()
    # Normal close precedes genuine response admission. The child stays separate
    # from every ancestor above, including the selected terminal continuation.
    return receiving._verify_on_work(response_originals=returned, request_originals=request,
        client_authorization_bytes=client_raw, server_bootstrap_bytes=server_raw,
        root_public_key=root, expected_client_scope=expected_scope,
        live_window=lifetime.window, transport_deadline_ns=lifetime.bound, work=work,
        _continuity=receiving_continuity, _retain_current=retain_current,
        _additional_original_bytes=receiving_extra)
