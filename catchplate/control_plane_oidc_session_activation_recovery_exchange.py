"""One protected recovery exchange inside the genuine live actor context.

All request originals come from its sealed selection and independent policy.
The existing irreversible release claim precedes the only socket; an exact
token is returned only by genuine response verification after normal close.
Neither this coordinator nor its claim appends an outcome, request or token.
"""
from __future__ import annotations

from catchplate import authority_oidc_session_activation_release_hints as hints
from catchplate import authority_oidc_session_activation_release_recovery_grant_production as derivation
from catchplate import authority_oidc_session_activation_release_response as receiving
from catchplate import control_plane_oidc_session_activation_recovery_acquisition as acquisition
from catchplate import control_plane_oidc_session_activation_release_attempt as attempts


clients, server, transport = derivation.clients, derivation.server, derivation.transport
issuer, plan, outcomes = derivation.issuer, derivation.plan, derivation.outcomes
production, custody = acquisition.execution.production, acquisition.custody
MAX_ORIGINAL_BYTES = derivation.MAX_ORIGINAL_BYTES


def _fail(message):
    acquisition._fail(message)


def _exchange_on_active(active, *, _delivery=None):
    """Only the source-owned spent/in-progress context can invoke this path.

    No caller target, successful material, raw request, token, scope or allowance
    is an argument. The private path retains its live-context-only guard.
    Public delivery selects one actual source-owned terminal before any fresh
    derivation, so its genuine verifier can survive only normal cleanup.
    """
    if (type(active) is not acquisition._RecoveryAcquisition
            or acquisition._ACTIVE is not active
            or active._staged is not True or active._stage_spent is not True
            or active._exchange_spent is not True or active._exchange_in_progress is not True
            or active._exchange_complete is not False or active._exchange_failed is not False
            or active._receiving_current is not None or active._token is not None):
        _fail("recovery exchange requires its actual one-use active context")
    acquisition._RecoveryAcquisition._parent_current(active)
    scope, parent_lifetime, work = active._scope, active._lifetime, active._work
    config, root, local_custody = active._config, active._root, active._custody
    selected, selected_pin = active._selected, active._selected_pin
    originals, result, capacity = active._originals, active._result, active._capacity
    old = scope._old_token
    if (scope is not active._scope_seal or parent_lifetime is not active._lifetime_seal
            or type(result) is not acquisition.client.receiving._RecoveryGrantMaterial
            or type(originals) is not tuple or len(originals) != 3
            or type(selected) is not tuple or len(selected) != 5
            or type(selected[0]) is not acquisition.consume.activation.ActivationDispatchAttemptRecord
            or any(type(record) is not acquisition.consume.ConsumeRecord for record in selected[1:])
            or type(capacity) is not tuple or len(capacity) != 2
            or capacity is not active._capacity_seal or capacity[1] is not originals
            or type(capacity[0]) is not int or not 0 <= capacity[0] < MAX_ORIGINAL_BYTES
            or type(old) is not bytes or len(old) != clients.delivery.TOKEN_BYTES):
        _fail("recovery exchange lost its actual retained originals or capacity")
    acquisition.client.receiving._originals(originals)
    held_references = (scope, parent_lifetime, work, config, root, local_custody,
        selected, selected_pin, originals, result, capacity)

    def active_identity():
        observed = (active._scope, active._lifetime, active._work, active._config,
            active._root, active._custody, active._selected, active._selected_pin,
            active._originals, active._result, active._capacity)
        if (type(active) is not acquisition._RecoveryAcquisition or acquisition._ACTIVE is not active
                or active._closed is not False or active._exchange_failed is not False
                or active._exchange_spent is not True or active._staged is not True
                or active._stage_spent is not True or scope._old_token is not old
                or active._scope_seal is not scope or active._lifetime_seal is not parent_lifetime
                or active._capacity_seal is not capacity
                or any(actual is not held for actual, held in zip(observed, held_references))
                or any(actual is not held for actual, held in zip(
                    (result.client_authorization_bytes, result.server_bootstrap_bytes, result.outcome_bytes),
                    originals))):
            _fail("recovery exchange original context changed or closed")
        # In-progress is required at entry, not forever: the full retained
        # response guard also checks the completed but still active context.

    def original_parent_continuity(epoch, monotonic):
        active_identity()
        # This parent contains original actor/grant guards only. It never calls
        # the response child retained separately by the acquisition context.
        return acquisition._RecoveryAcquisition._parent_continuity(active, epoch, monotonic)

    identity = active_identity
    ancestor = original_parent_continuity
    retain_current = active._retain_receiving_current
    delivery_reservation = 0
    if _delivery is not None:
        from catchplate import control_plane_oidc_session_activation_recovery_delivery as delivery

        if (type(_delivery) is not delivery._StagedRecoveryResponse
                or active._delivery is not _delivery or active._delivery_seal is not _delivery
                or _delivery._active is not active):
            _fail("recovery exchange terminal is not its actual source-owned association")
        active_identity()
        ancestor = delivery._StagedRecoveryResponse._exchange_on_active(
            _delivery, active, original_parent_continuity)
        identity = lambda: delivery._StagedRecoveryResponse._identity(_delivery)
        retain_current = _delivery._retain_receiver
        delivery_reservation = delivery._AUTH_RESERVATION

    identity()
    acquisition._RecoveryAcquisition._parent_current(active)
    _activation, claim, intent, proof, descriptor = selected
    if ((claim.kind, intent.kind, proof.kind, descriptor.kind)
            != ("claimed", "release-intent", "release-proof", "completion-hints")
            or claim.originals != ()
            or tuple(map(len, (intent.originals, proof.originals, descriptor.originals))) != (1, 4, 2)
            or proof.originals[0] != b"proved"):
        _fail("recovery exchange selected inventory differs from its fixed source records")
    client_raw, server_raw, retained_outcome = originals
    # Existing retained parent/actor/grant representations remain reserved.
    # Hint decoding and the token-free claim have fixed separate headroom.
    extra = (capacity[0] + delivery_reservation + 8 * hints.MAX_DESCRIPTOR_BYTES + attempts.MAX_CLAIM_IO_BYTES
        + 4 * (transport.RECOVERY_REQUEST_HEADER_BYTES + transport.RESPONSE_HEADER_BYTES)
        + 2 * transport.MAX_RESPONSE_BYTES)
    if MAX_ORIGINAL_BYTES != 64 * 1024 * 1024 or extra >= MAX_ORIGINAL_BYTES:
        _fail("recovery exchange has no remaining original representation capacity")
    derivation.shared._same_bytes(intent.originals[0], scope._target.intent_bytes, work,
        "recovery exchange freshly authorized historical intent")
    derivation.shared._same_bytes(proof.originals[1], config.release_custody_bytes, work,
        "recovery exchange independent custody original")
    derivation.shared._same_bytes(proof.originals[3], config.proof_enrollment_bytes, work,
        "recovery exchange independent proof enrollment")
    acquisition._RecoveryAcquisition._parent_current(active)
    _packet, _effects, envelope, _created, _expires = hints._decode_on_work(descriptor.originals, work=work)
    prefix = derivation._request_originals((transport.RECOVERY_PURPOSE, proof.originals[2],
        config.proof_enrollment_bytes, intent.originals[0], config.intent_enrollment_bytes,
        old, envelope))
    # Reserve the complete read-only derivation before it decodes originals.
    # The outcome ceiling is source fixed, not a candidate record or authority.
    derived_reserve = (extra + derivation._input_reservation(prefix, config.issuer_policy_bytes,
        config.release_custody_bytes, config.proof_enrollment_bytes, config.intent_enrollment_bytes)
        + 3 * outcomes.MAX_BYTES)
    lengths = (*tuple(map(len, prefix)), outcomes.MAX_BYTES)
    # One genuine client/server admission remains held during a second genuine
    # response admission. Reserve both, including full fixed reply buffers,
    # before derivation or any protected exchange socket can run.
    receiving_extra = receiving._reservation_bytes(lengths, client_bytes=len(client_raw),
        bootstrap_bytes=len(server_raw), additional_original_bytes=derived_reserve)
    total = receiving._reservation_bytes(lengths, client_bytes=len(client_raw),
        bootstrap_bytes=len(server_raw), additional_original_bytes=receiving_extra)
    if total > MAX_ORIGINAL_BYTES:
        _fail("recovery exchange and both genuine receiving paths exceed held capacity")
    acquisition._RecoveryAcquisition._parent_current(active)
    request, policy, record, storage_scope, recovery_scope, request_identity, lifetime = (
        derivation._derive_on_work(request_originals=prefix,
            issuer_policy_bytes=config.issuer_policy_bytes, release_custody_bytes=config.release_custody_bytes,
            proof_enrollment_bytes=config.proof_enrollment_bytes,
            intent_enrollment_bytes=config.intent_enrollment_bytes, root_public_key=root,
            live_window=parent_lifetime.window, transport_deadline_ns=parent_lifetime.bound,
            work=work, _continuity=ancestor, _additional_original_bytes=extra))
    if type(policy) is not issuer._IssuerPolicyMaterial:
        _fail("recovery exchange requires genuine independent original derivation")

    def current():
        identity()
        return lifetime.current()

    def receiving_continuity(epoch, monotonic):
        identity()
        lifetime._floors(max(lifetime.epoch, epoch), max(lifetime.monotonic, monotonic))
        current()
        return lifetime.epoch, lifetime.monotonic

    current()
    derivation.shared._same_bytes(record, retained_outcome, work,
        "recovery exchange exact durably retained canonical outcome")
    plan._same(policy.policy_digest, result.issuer_policy_material.policy_digest, work,
        "recovery exchange unchanged independently acquired policy")
    plan._same(policy.payload["expectedRelease"]["deliveryScope"], scope._target.delivery_scope,
        work, "recovery exchange fresh actor target")
    plan._same(policy.payload["expectedEvidence"]["releaseIntentDigest"], scope._target.intent_digest,
        work, "recovery exchange exact actor intent")
    current()
    payload = policy.payload
    expected_scope = clients._scope({**payload["proofScope"],
        "serverBootstrapDigest": clients._server_bootstrap_digest_on_work(server_raw, work),
        "profile": clients.RECOVERY_PROFILE, "requestIdentity": request_identity.decode("ascii"),
        "clientId": policy.client_id, "clientIdentity": policy.client_identity,
        "callerId": payload["callerId"],
        "stateReceiptDigest": payload["expectedEvidence"]["stateReceiptDigest"],
        "expectedRelease": payload["expectedRelease"],
        "expectedOutcomeDigest": payload["expectedOutcomeDigest"], "endpoint": payload["endpoint"]}, work)
    current()
    admitted = clients._verify_on_work(authorization_bytes=client_raw,
        server_bootstrap_bytes=server_raw, root_public_key=root, expected_scope=expected_scope,
        live_window=lifetime.window, transport_deadline_ns=lifetime.bound, work=work,
        _continuity=lifetime.continuity)
    if (type(admitted) is not clients._ClientAuthorization
            or type(admitted.server_material) is not server._ReleaseMaterial):
        _fail("recovery exchange requires genuine client and server originals")
    lifetime.attach(admitted.live)
    lifetime.adopt(admitted.live_window, admitted.deadline_ns)
    material = admitted.server_material
    current()
    derivation.shared._same_bytes(material.custody_bytes, config.release_custody_bytes, work,
        "recovery exchange server exact independent custody")
    for actual, expected, label in (
            (material.profile, server.RECOVERY_PROFILE, "profile"),
            (material.storage_scope, storage_scope, "checkpoint-one storage"),
            (material.recovery_scope, recovery_scope, "fresh recovery scope"),
            (material.launch, policy.release_launch, "independent launch"),
            (material.expected_release, payload["expectedRelease"], "independent release target")):
        plan._same(actual, expected, work, "recovery exchange " + label)
        current()
    policy_interval = payload["issuedAtEpochNs"], payload["expiresAtEpochNs"]
    server._contains(material.attestation_interval, policy_interval)
    server._contains((admitted.payload["issuedAtEpochNs"], admitted.payload["expiresAtEpochNs"]),
        policy_interval)
    current()
    # The source-derived endpoint, not the parent's issuer-acquisition endpoint
    # or an old LIVE release_client, selects this private RECOVERY socket.
    endpoint = policy.endpoint
    work.charge(input_bytes=attempts.MAX_CLAIM_IO_BYTES)
    current()
    production._callback(work, lambda:
        custody.ControlPlaneCustodyClient.claim_oidc_session_activation_release(local_custody,
            client_authorization_digest=admitted.authorization_digest,
            request_identity=expected_scope["requestIdentity"], profile=clients.RECOVERY_PROFILE,
            server_bootstrap_digest=expected_scope["serverBootstrapDigest"],
            expected_outcome_digest=payload["expectedOutcomeDigest"]))
    current()
    returned = transport._socket_request(endpoint, profile=clients.RECOVERY_PROFILE,
        originals=request, deadline_ns=lifetime.bound, work=work, current=current)
    current()
    # The transport returns only after normal close. Retain the genuine full
    # response guard separately in C; never attach it to any ancestor above.
    return receiving._verify_on_work(response_originals=returned, request_originals=request,
        client_authorization_bytes=client_raw, server_bootstrap_bytes=server_raw,
        root_public_key=root, expected_client_scope=expected_scope, live_window=lifetime.window,
        transport_deadline_ns=lifetime.bound, work=work, _continuity=receiving_continuity,
        _retain_current=retain_current, _additional_original_bytes=receiving_extra)
