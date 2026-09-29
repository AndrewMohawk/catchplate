"""One independently authorized RECOVERY exchange on reconciled originals.

Only the actual retained-release owner supplies history and independent cold
policy. Canonical outcome reconstruction is a request binding, never a store
observation. This path neither signs, retries SQL, renews expiry nor falls back.
"""
from __future__ import annotations

from serverware import authority_oidc_session_activation_release_recovery_grant_production as derivation
from serverware import oidc_session_activation_release_recovery_grant_admission as grant_admission
from serverware import control_plane_oidc_session_activation_release_handoff as shared
from serverware import control_plane_oidc_session_activation_release_recovery_grant_acquisition_bootstrap as configured
from serverware import control_plane_oidc_session_activation_completion_recovery_intent_inputs as inputs_source
from serverware import control_plane_oidc_session_activation_completion_recovery_intent as intent_source
from serverware import control_plane_oidc_session_activation_completion_recovery_proof as proof_source


clients, server, transport = derivation.clients, derivation.server, derivation.transport
issuer, plan, outcomes = derivation.issuer, derivation.plan, derivation.outcomes
receiving, hints, state = shared.receiving, shared.hints, shared.state
execution, attempts = shared.execution, shared.attempts
MAX_ORIGINAL_BYTES = receiving.MAX_ORIGINAL_BYTES
EXCHANGE_RESERVATION_BYTES = 16 * 1024 * 1024
MAX_GRANT_RESPONSE_BYTES = 128 * 1024
_GRANT_IO_BYTES = 2 * 1024 * 1024
_AUTH_RESERVATION = 256 * 1024
_CLAIM_IO_BYTES = attempts.MAX_CLAIM_IO_BYTES + shared.retained.COMPLETION_RECOVERY_METADATA_BYTES


def _fail(message):
    execution._fail(message)


def _same(actual, expected, work, label):
    derivation.shared._same_bytes(actual, expected, work, "completion retained release " + label)


def _exchange_on_active(active, *, _delivery=None):
    """An actual staged, spent, in-progress source owner only; return token64."""
    from serverware import control_plane_oidc_session_activation_completion_recovery_delivery as owner_call
    from serverware import control_plane_oidc_session_activation_completion_recovery_retained_acquisition as acquisition

    if (type(active) is not owner_call._DeliveryAttempt or owner_call._ACTIVE is not active
            or active._purpose != "retained-release" or active._purpose is not active._purpose_pin
            or active._closed is not False or active._exchange_spent is not True
            or active._exchange_in_progress is not True or active._exchange_complete is not False
            or active._exchange_failed is not False or active._stage_spent is not True
            or active._staged is not True or active._receiving_current is not None
            or active._receiving_seal is not None or active._token is not None
            or active._token_seal is not None
            or active._delivery is not _delivery or active._delivery_seal is not _delivery):
        _fail("completion retained release requires its actual staged one-use owner")
    owner_call._DeliveryAttempt._parent_current(active)
    inputs = inputs_source._require_inputs(active.inputs)
    selected_intent = intent_source._require_intent(active.intent)
    selected_proof = proof_source._require_proof(active.proof)
    actor, controls, response = active.actor, active.controls, active.response
    owner, work, root = active._owner, active._work, active._root
    parent, binding, custody = active._parent, active._binding, active._custody
    parent_lifetime, config = active._lifetime, active._config
    grants, result = active.grants, active._recovery_result
    if (inputs._purpose != "retained-release" or actor._purpose != "retained-release"
            or inputs.actor is not actor or inputs.controls is not controls or inputs.work is not work
            or inputs.response_originals is not response
            or (not config.retained_authority and inputs.root_public_key is not root)
            or selected_intent.inputs is not inputs or selected_proof.intent is not selected_intent
            or actor._owner is not owner or owner._material is not parent
            or owner._binding is not binding or owner._custody is not custody
            or binding.runtime_root_public_key is not root
            or (binding.caller_uid, binding.caller_gid) != (clients.CLIENT_UID, clients.CLIENT_GID)
            or type(config) is not configured._RecoveryGrantAcquisitionMaterial
            or config is not active._issuer or config is not parent.release_recovery_grant_acquisition
            or parent_lifetime is not active._lifetime_seal
            or type(result) is not grant_admission._RecoveryGrantMaterial
            or result is not active._recovery_result_seal
            or grants is not active._grants_seal
            or type(inputs.original_reservation_bytes) is not int
            or not EXCHANGE_RESERVATION_BYTES <= inputs.original_reservation_bytes < MAX_ORIGINAL_BYTES):
        _fail("completion retained release changed its actual actor, cold originals or reserve")
    client_raw, server_raw, retained_outcome = grant_admission._originals(grants)
    if (sum(map(len, grants)) > MAX_GRANT_RESPONSE_BYTES
            or any(original is not held for original, held in zip(grants,
                (result.client_authorization_bytes, result.server_bootstrap_bytes, result.outcome_bytes)))):
        _fail("completion retained release lost its bounded genuinely admitted triple")
    proof_raw, intent_raw, old = selected_proof._originals, selected_intent.intent_bytes, inputs.old_token_bytes
    if (type(proof_raw) is not tuple or len(proof_raw) != 4 or proof_raw[0] != b"proved"
            or type(response) is not tuple or len(response) != 6 or response[0] != b"acknowledged"
            or type(old) is not bytes or len(old) != clients.delivery.TOKEN_BYTES
            or actor._old_token is not old
            or (not config.retained_authority and (parent.release_proof is not inputs.proof_policy
                or parent.release_intent is not inputs.intent_policy))):
        _fail("completion retained release requires exact existing proof, completion and possession")
    proof_scope, intent_scope, release = inputs.proof_scope, inputs.intent_scope, inputs.expected_release
    held = (actor, controls, response, inputs, selected_intent, selected_proof, grants, result,
        owner, work, parent, binding, custody, root, parent_lifetime, config)

    def active_identity():
        observed = (active.actor, active.controls, active.response, active.inputs, active.intent,
            active.proof, active.grants, active._recovery_result, active._owner, active._work,
            active._parent, active._binding, active._custody, active._root, active._lifetime, active._config)
        if (type(active) is not owner_call._DeliveryAttempt or owner_call._ACTIVE is not active
                or active._closed is not False or active._exchange_spent is not True
                or active._exchange_failed is not False or active._purpose != "retained-release"
                or active._purpose is not active._purpose_pin or actor._purpose != "retained-release"
                or actor._old_token is not old or active._stage_spent is not True or active._staged is not True
                or active._issuer is not config or active._recovery_result_seal is not result
                or active._grants_seal is not grants or active._lifetime_seal is not parent_lifetime
                or any(actual is not original for actual, original in zip(observed, held))):
            _fail("completion retained release original owner changed or closed")
        # The full receiver can outlive the in-progress phase while this owner
        # is still active. Only the exact terminal permits normal closed cleanup.

    def original_parent_continuity(epoch, monotonic):
        active_identity()
        return owner_call._DeliveryAttempt._parent_continuity(active, epoch, monotonic)

    identity, ancestor = active_identity, original_parent_continuity
    retain_current = active._retain_receiving_current
    if _delivery is not None:
        from serverware import control_plane_oidc_session_activation_completion_recovery_delivery_response as terminal

        if (type(_delivery) is not terminal._StagedRecoveryResponse
                or _delivery._active is not active or terminal._AUTH_RESERVATION != _AUTH_RESERVATION):
            _fail("completion retained release final delivery is not its exact source terminal")
        ancestor = terminal._StagedRecoveryResponse._exchange_on_active(
            _delivery, active, original_parent_continuity)
        identity = lambda: terminal._StagedRecoveryResponse._identity(_delivery)
        retain_current = _delivery._retain_receiver

    # Select the original terminal before ALL fresh derivation/admission below.
    # The prior acquisition result is an identity pin, never an attached child:
    # its ordinary actor ancestry is intentionally invalid after normal cleanup.
    identity()
    prefix_lengths = (len(transport.RECOVERY_PURPOSE), len(proof_raw[2]),
        len(config.proof_enrollment_bytes), len(intent_raw), len(config.intent_enrollment_bytes),
        len(old), clients.delivery.ENVELOPE_BYTES)
    capture_bytes = acquisition._acquisition_capture_bytes(prefix_lengths, config, tuple(map(len, grants)))
    fixed = (_AUTH_RESERVATION + _CLAIM_IO_BYTES + 8 * hints.MAX_DESCRIPTOR_BYTES
        + 4 * sum(map(len, grants))
        + 4 * (transport.RECOVERY_REQUEST_HEADER_BYTES + transport.RESPONSE_HEADER_BYTES))
    # This is the exact length-only form of the existing read-only derivation
    # reservation, including canonical outcome/raw8. No placeholder body exists.
    derived = (8 * len(config.release_custody_bytes)
        + 4 * (sum(prefix_lengths) + len(config.issuer_policy_bytes)
            + len(config.proof_enrollment_bytes) + len(config.intent_enrollment_bytes))
        + transport.RECOVERY_REQUEST_HEADER_BYTES + 3 * outcomes.MAX_BYTES)
    lengths = (*prefix_lengths, outcomes.MAX_BYTES)
    first = receiving._reservation_bytes(lengths, client_bytes=len(client_raw), bootstrap_bytes=len(server_raw))
    lane = receiving._reservation_bytes(lengths, client_bytes=len(client_raw), bootstrap_bytes=len(server_raw),
        additional_original_bytes=capture_bytes + fixed + derived + first)
    held_before_exchange = inputs.original_reservation_bytes - EXCHANGE_RESERVATION_BYTES
    if (MAX_ORIGINAL_BYTES != 64 * 1024 * 1024 or type(capture_bytes) is not int or capture_bytes < 0
            or lane > EXCHANGE_RESERVATION_BYTES or held_before_exchange + lane > MAX_ORIGINAL_BYTES):
        _fail("completion retained release acquisition and fresh admissions exceed the reserved lane")
    extra = held_before_exchange + capture_bytes + fixed
    receiving_extra = extra + derived + first
    # No hints or new authority are decoded before this combined preallocation.
    _same(proof_raw[3], config.proof_enrollment_bytes, work, "retained proof enrollment")
    _same(inputs.proof_policy.enrollment_bytes, config.proof_enrollment_bytes, work,
        "original actor proof enrollment")
    _same(inputs.intent_policy.enrollment_bytes, config.intent_enrollment_bytes, work,
        "original actor intent enrollment")
    identity()
    packet, effects, envelope, created, expires = hints._decode_on_work(response[4:], work=work)
    for actual, expected, label in (
            (packet, release["consumeBinding"]["packetDigest"], "packet"),
            (effects, release["consumeBinding"]["effectsDigest"], "effects"),
            (created, release["deliveryScope"]["createdAt"], "created"),
            (expires, release["deliveryScope"]["expiresAt"], "expires"),
            (shared.planning.assertion._digest(envelope, work), release["deliveryEnvelopeDigest"], "envelope")):
        plan._same(actual, expected, work, "completion retained release original hints " + label)
    prefix = derivation._request_originals((transport.RECOVERY_PURPOSE, proof_raw[2],
        config.proof_enrollment_bytes, intent_raw, config.intent_enrollment_bytes, old, envelope))
    if derived != (derivation._input_reservation(prefix, config.issuer_policy_bytes,
            config.release_custody_bytes, config.proof_enrollment_bytes, config.intent_enrollment_bytes)
            + 3 * outcomes.MAX_BYTES):
        _fail("completion retained release actual derivation inventory changed")
    identity()
    request, policy, record, storage_scope, recovery_scope, request_identity, lifetime = (
        derivation._derive_on_work(request_originals=prefix,
            issuer_policy_bytes=config.issuer_policy_bytes, release_custody_bytes=config.release_custody_bytes,
            proof_enrollment_bytes=config.proof_enrollment_bytes,
            intent_enrollment_bytes=config.intent_enrollment_bytes, root_public_key=root,
            live_window=parent_lifetime.window, transport_deadline_ns=parent_lifetime.bound,
            work=work, _continuity=ancestor, _additional_original_bytes=extra))
    if type(policy) is not issuer._IssuerPolicyMaterial:
        _fail("completion retained release requires genuine independent recovery derivation")

    def current():
        identity()
        return lifetime.current()

    def receiving_continuity(epoch, monotonic):
        identity()
        lifetime._floors(max(lifetime.epoch, epoch), max(lifetime.monotonic, monotonic))
        current()
        return lifetime.epoch, lifetime.monotonic

    current()
    acquisition._require_policy_inputs(policy, inputs, config, parent, root,
        proof_raw[1], work, current)
    _same(record, retained_outcome, work, "exact durably retained canonical outcome")
    payload = policy.payload
    evidence = {"releaseCustodyDigest": plan._frame(shared.proofs.contract.CUSTODY_IDENTITY_DOMAIN,
            (proof_raw[1],), work), "releaseIntentDigest": selected_intent.intent_digest,
        "stateReceiptDigest": plan._frame(state.RECEIPT_IDENTITY_DOMAIN, (response[3],), work)}
    for actual, expected, label in (
            (policy.policy_digest, result.issuer_policy_material.policy_digest, "acquired policy identity"),
            (payload["proofScope"], proof_scope, "original proof scope"),
            (payload["callerId"], intent_scope["callerId"], "original intent caller"),
            (payload["expectedRelease"], release, "original complete release binding"),
            (payload["expectedEvidence"], evidence, "original custody, intent and state receipt")):
        plan._same(actual, expected, work, "completion retained release " + label)
        current()
    _same(policy.custody_material.planner.bootstrap_bytes, inputs.planner_original, work,
        "original activation planner")
    expected_scope = clients._scope({**payload["proofScope"],
        "serverBootstrapDigest": clients._server_bootstrap_digest_on_work(server_raw, work),
        "profile": clients.RECOVERY_PROFILE, "requestIdentity": request_identity.decode("ascii"),
        "clientId": policy.client_id, "clientIdentity": policy.client_identity,
        "callerId": payload["callerId"], "stateReceiptDigest": evidence["stateReceiptDigest"],
        "expectedRelease": payload["expectedRelease"], "expectedOutcomeDigest": payload["expectedOutcomeDigest"],
        "endpoint": payload["endpoint"]}, work)
    current()
    admitted = clients._verify_on_work(authorization_bytes=client_raw,
        server_bootstrap_bytes=server_raw, root_public_key=root, expected_scope=expected_scope,
        live_window=lifetime.window, transport_deadline_ns=lifetime.bound, work=work,
        _continuity=lifetime.continuity)
    if (type(admitted) is not clients._ClientAuthorization
            or type(admitted.server_material) is not server._ReleaseMaterial):
        _fail("completion retained release requires genuine recovery client/server originals")
    lifetime.attach(admitted.live)
    lifetime.adopt(admitted.live_window, admitted.deadline_ns)
    material = admitted.server_material
    current()
    _same(material.custody_bytes, config.release_custody_bytes, work, "server independent custody original")
    if (material.profile != server.RECOVERY_PROFILE
            or material.storage_scope["checkpoint"] != {
                "recordCount": 1, "outcomeDigest": payload["expectedOutcomeDigest"]}
            or material.recovery_scope is None):
        _fail("completion retained release requires independently authorized RECOVERY checkpoint one")
    for actual, expected, label in (
            (material.storage_scope, storage_scope, "checkpoint-one storage scope"),
            (material.recovery_scope, recovery_scope, "fresh recovery scope"),
            (material.launch, policy.release_launch, "independent launch resources"),
            (material.expected_release, release, "original release binding")):
        plan._same(actual, expected, work, "completion retained release " + label)
        current()
    policy_interval = payload["issuedAtEpochNs"], payload["expiresAtEpochNs"]
    server._contains(material.attestation_interval, policy_interval)
    server._contains((admitted.payload["issuedAtEpochNs"], admitted.payload["expiresAtEpochNs"]), policy_interval)
    current()
    # This is the policy's protected RECOVERY endpoint, never the issuer socket,
    # a LIVE handoff pin, or a profile inferred from a missing journal entry.
    endpoint = policy.endpoint
    claim = execution.custody.ControlPlaneCustodyClient.claim_oidc_session_activation_completion_recovery_retained_release_attempt(
        custody, client_authorization_digest=admitted.authorization_digest,
        request_identity=expected_scope["requestIdentity"], profile=clients.RECOVERY_PROFILE,
        server_bootstrap_digest=expected_scope["serverBootstrapDigest"],
        expected_outcome_digest=payload["expectedOutcomeDigest"],
        work=work, current=current, maximum_original_bytes=_CLAIM_IO_BYTES)
    current()
    plan._same(claim, admitted.authorization_digest, work, "completion retained release exact irreversible claim")
    returned = transport._socket_request(endpoint, profile=clients.RECOVERY_PROFILE,
        originals=request, deadline_ns=lifetime.bound, work=work, current=current)
    current()
    # Normal close precedes genuine receiving. Keep the full child separately;
    # neither the parent nor selected terminal ancestor calls it recursively.
    return receiving._verify_on_work(response_originals=returned, request_originals=request,
        client_authorization_bytes=client_raw, server_bootstrap_bytes=server_raw,
        root_public_key=root, expected_client_scope=expected_scope,
        live_window=lifetime.window, transport_deadline_ns=lifetime.bound, work=work,
        _continuity=receiving_continuity, _retain_current=retain_current,
        _additional_original_bytes=receiving_extra)
