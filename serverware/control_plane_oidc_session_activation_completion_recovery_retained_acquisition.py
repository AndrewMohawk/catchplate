"""Fresh retained-release grants and exact one-use worker staging.

The independently configured RECOVERY policy, not missing local data, selects
checkpoint one. A durable global policy claim precedes contact, and returned
raw3 is durably retained before semantic admission. Neither reconstructed
outcome bytes nor a staging ACK proves that the private outcome exists.
"""
from __future__ import annotations

from serverware import authority_oidc_session_activation_release_hints as hints
from serverware import authority_oidc_session_activation_release_recovery_delivery_transport as staging
from serverware import control_plane_oidc_session_activation_release_recovery_grant_acquisition as client
from serverware import control_plane_oidc_session_activation_release_recovery_grant_acquisition_bootstrap as configured
from serverware import control_plane_oidc_session_activation_completion_recovery_intent as intent_source


issuer, derivation, admission, wire = client.issuer, client.production, client.receiving, client.transport
execution, bookkeeping, plan = intent_source.execution, intent_source.bookkeeping, intent_source.plan
MAX_ORIGINAL_BYTES = admission.MAX_ORIGINAL_BYTES
EXCHANGE_RESERVATION_BYTES = 16 * 1024 * 1024
MAX_GRANT_RESPONSE_BYTES = 128 * 1024
_GRANT_IO_BYTES = 2 * 1024 * 1024


def _fail(message):
    execution._fail(message)


def _configuration(config):
    if (type(config) is not configured._RecoveryGrantAcquisitionMaterial
            or type(config.retained_authority) is not bool):
        _fail("retained release requires independently configured recovery originals")
    originals = (config.issuer_policy_bytes, config.release_custody_bytes,
        config.proof_enrollment_bytes, config.intent_enrollment_bytes)
    maxima = (issuer.MAX_BYTES, issuer.MAX_CUSTODY_BYTES,
        issuer.MAX_PROOF_ENROLLMENT_BYTES, issuer.MAX_INTENT_ENROLLMENT_BYTES)
    if any(type(raw) is not bytes or not 2 <= len(raw) <= bound
            for raw, bound in zip(originals, maxima)):
        _fail("retained release cold originals exceed their fixed bounds")
    return originals


def _require_policy_inputs(policy, selected, config, parent, root, evidence_custody, work, current):
    """Join fresh originals to the actual same-call RI and current cold owner."""
    history = derivation.retained
    material = policy.custody_material
    bridged = config.retained_authority
    if (bridged != (policy.payload["schema"] == issuer.V2_PAYLOAD_SCHEMA)
            or bridged != (material.intent_root_public_key is not None)
            or selected.retained_only and not bridged):
        _fail("recovery current policy and independently selected RI profiles differ")
    _same(history.custody_for(material), evidence_custody, work, "exact RI evidence custody")
    history.require_originals(material, selected.intent_policy.enrollment_bytes,
        selected.proof_policy.enrollment_bytes, work)
    plan._same(issuer.server.keys._spki_on_work(history.root_for(material, root), work),
        issuer.server.keys._spki_on_work(selected.root_public_key, work), work,
        "recovery independently selected RI root")
    if bridged:
        selection = selected._retained_intent_selection
        if selection is None or selection.authority is None or selection.prefix_pins is None:
            _fail("recovery current bridge requires actual retained RI selection")
        plan._same(material.intent_authority_interval, selection.authority.authority_interval,
            work, "recovery independently selected RI interval")
    _same(material.planner.bootstrap_bytes, selected.planner_original, work, "RI activation planner")
    current_planner = history.planner_for(material)
    _same(current_planner.bootstrap_bytes, parent.activation_planning.planner_bootstrap_bytes,
        work, "current activation planner")
    current()
    current_state = issuer.authorization._admit_enrollment_on_work(
        enrollment_bytes=current_planner.state_enrollment_bytes, root_public_key=root, work=work)
    current()
    original_state = issuer.authorization._admit_enrollment_on_work(
        enrollment_bytes=selected.controls.enrollment_bytes,
        root_public_key=selected.controls.root_public_key, work=work)
    current()
    plan._same(current_state.payload, original_state.payload, work,
        "recovery unchanged original/current complete state payload")
    plan._same(material.delivery_key_digest, current_planner.delivery_key_digest,
        work, "recovery unchanged current delivery key")
    current()


def _acquisition_capture_bytes(prefix_lengths, config, grant_lengths):
    """Length-only reserve for the still-held policy and genuine raw3 result.

    This is representation accounting, not authority or a Python heap guarantee.
    Temporary publication/staging buffers are accounted separately and reclaimed;
    the exchange must keep this allowance while admitting its new descendants.
    """
    policy, custody, proof, intent = _configuration(config)
    if (type(prefix_lengths) is not tuple or len(prefix_lengths) != 7
            or any(type(size) is not int or not 2 <= size <= limit
                for size, limit in zip(prefix_lengths, wire.release.RECOVERY_REQUEST_LIMITS[:7]))
            or prefix_lengths[0] != len(wire.release.RECOVERY_PURPOSE)
            or prefix_lengths[5:7] != wire.release.RECOVERY_REQUEST_LIMITS[5:7]
            or type(grant_lengths) is not tuple or len(grant_lengths) != 3
            or any(type(size) is not int or not 2 <= size <= limit
                for size, limit in zip(grant_lengths, wire.RESPONSE_LIMITS))):
        _fail("retained release capture reservation requires the fixed original lengths")
    return (16 * len(custody)
        + 8 * (sum(prefix_lengths) + len(policy) + len(proof) + len(intent))
        + 24 * sum(grant_lengths) + 16 * derivation.outcomes.MAX_BYTES + 64 * 1024)


def _response_ceilings():
    # Each frame is bounded by both its codec and the pre-body aggregate cap.
    # Summing individual ceilings deliberately over-reserves the actual triple.
    return tuple(min(limit, MAX_GRANT_RESPONSE_BYTES) for limit in wire.RESPONSE_LIMITS)


def _reservation_on_owner(owner):
    """Reserve once before target body1; inspect only existing cold lengths."""
    if type(owner) is not execution.startup._EnrollmentOwner:
        _fail("retained release requires the actual enrollment owner")
    config = owner._material.release_recovery_grant_acquisition
    _configuration(config)
    minimum = (len(wire.release.RECOVERY_PURPOSE), 2, len(config.proof_enrollment_bytes),
        2, len(config.intent_enrollment_bytes), *wire.release.RECOVERY_REQUEST_LIMITS[5:7])
    if (_acquisition_capture_bytes(minimum, config, _response_ceilings()) + _GRANT_IO_BYTES
            >= EXCHANGE_RESERVATION_BYTES):
        _fail("retained release cold originals leave no bounded recovery lane")
    return EXCHANGE_RESERVATION_BYTES


def _same(actual, expected, work, label):
    bookkeeping._same_bytes(actual, expected, work, "retained release " + label)


def _stage_bytes(bootstrap_bytes):
    return (2 * bootstrap_bytes + 4096 + len(staging.PURPOSE)
        + 4 * staging.REQUEST_HEADER_BYTES + 3 * staging.RESPONSE_HEADER_BYTES
        + 3 * staging.MAX_RESPONSE_BYTES + 2 * 71)


def _acquire_and_stage(active):
    from serverware import control_plane_oidc_session_activation_completion_recovery_delivery as source

    if (type(active) is not source._DeliveryAttempt or source._ACTIVE is not active
            or active._purpose != "retained-release" or active.grants is not None
            or active._recovery_result is not None or active._stage_spent is not False
            or active._staged is not False or active._exchange_spent is not False):
        _fail("retained release acquisition requires its exact unspent fresh owner")
    active._parent_current()
    selected, work, config = active.inputs, active._work, active._config
    raw, original = active.proof._originals, active.intent.intent_bytes
    if (selected._purpose != "retained-release" or active.actor._purpose != "retained-release"
            or active._issuer is not config or active._parent.release_recovery_grant_acquisition is not config
            or type(raw) is not tuple or len(raw) != 4 or raw[0] != b"proved"
            or type(active.response) is not tuple or len(active.response) != 6
            or active.response[0] != b"acknowledged"
            or type(selected.original_reservation_bytes) is not int
            or not EXCHANGE_RESERVATION_BYTES <= selected.original_reservation_bytes < MAX_ORIGINAL_BYTES):
        _fail("retained release changed its admitted completion and historical source chain")
    _configuration(config)
    prefix_lengths = (len(wire.release.RECOVERY_PURPOSE), len(raw[2]), len(config.proof_enrollment_bytes),
        len(original), len(config.intent_enrollment_bytes), len(selected.old_token_bytes),
        wire.release.RECOVERY_REQUEST_LIMITS[6])
    capture_bound = _acquisition_capture_bytes(prefix_lengths, config, _response_ceilings())
    fixed = (_GRANT_IO_BYTES + 8 * hints.MAX_DESCRIPTOR_BYTES
        + 4 * (wire.REQUEST_HEADER_BYTES + wire.RESPONSE_HEADER_BYTES)
        + _stage_bytes(min(staging.MAX_BOOTSTRAP_BYTES, MAX_GRANT_RESPONSE_BYTES)))
    held = selected.original_reservation_bytes - EXCHANGE_RESERVATION_BYTES
    if (MAX_ORIGINAL_BYTES != 64 * 1024 * 1024
            or capture_bound + fixed > EXCHANGE_RESERVATION_BYTES
            or held + capture_bound + fixed > MAX_ORIGINAL_BYTES):
        _fail("retained release acquisition exceeds its already reserved representation lane")
    # No payload decoding or socket contact precedes the actual-length bound.
    _same(raw[3], config.proof_enrollment_bytes, work, "independent proof enrollment")
    _same(selected.intent_policy.enrollment_bytes, config.intent_enrollment_bytes,
        work, "independent intent enrollment")
    packet, effects, envelope, created, expires = hints._decode_on_work(active.response[4:], work=work)
    expected = selected.expected_release
    for actual, value, label in (
            (packet, expected["consumeBinding"]["packetDigest"], "packet"),
            (effects, expected["consumeBinding"]["effectsDigest"], "effects"),
            (created, expected["deliveryScope"]["createdAt"], "created"),
            (expires, expected["deliveryScope"]["expiresAt"], "expiry"),
            (source.planning.assertion._digest(envelope, work), expected["deliveryEnvelopeDigest"], "envelope")):
        plan._same(actual, value, work, "retained release original hint " + label)
    request = derivation._request_originals((wire.release.RECOVERY_PURPOSE, raw[2],
        config.proof_enrollment_bytes, original, config.intent_enrollment_bytes,
        selected.old_token_bytes, envelope))
    lifetime = active._lifetime
    policy = issuer._verify_on_work(policy_bytes=config.issuer_policy_bytes,
        release_custody_bytes=config.release_custody_bytes,
        proof_enrollment_bytes=config.proof_enrollment_bytes,
        intent_enrollment_bytes=config.intent_enrollment_bytes, root_public_key=active._root,
        live_window=lifetime.window, transport_deadline_ns=lifetime.bound, work=work,
        _continuity=active._parent_continuity)
    if type(policy) is not issuer._IssuerPolicyMaterial:
        _fail("retained release requires genuine independent issuer policy admission")
    lifetime.attach(policy.live)
    lifetime.adopt(policy.live_window, policy.deadline_ns)
    _require_policy_inputs(policy, selected, config, active._parent, active._root,
        raw[1], work, lifetime.current)
    evidence = {"releaseCustodyDigest": plan._frame(derivation.proofs.contract.CUSTODY_IDENTITY_DOMAIN,
            (raw[1],), work), "releaseIntentDigest": active.intent.intent_digest,
        "stateReceiptDigest": plan._frame(intent_source.state.RECEIPT_IDENTITY_DOMAIN,
            (active.response[3],), work)}
    for actual, wanted, label in (
            (policy.payload["expectedRelease"], expected, "actual original release target"),
            (policy.payload["expectedEvidence"], evidence, "actual original evidence"),
            (policy.payload["proofScope"], selected.proof_scope, "independent proof scope"),
            (policy.payload["callerId"], selected.intent_scope["callerId"], "actual intent caller")):
        plan._same(actual, wanted, work, "retained release policy " + label)
    kwargs = intent_source._persistence(selected, active._parent_current, _GRANT_IO_BYTES)
    kwargs.update(release_intent_digest=active.intent.intent_digest,
        issuer_policy_digest=policy.policy_digest)
    local = execution.custody.ControlPlaneCustodyClient
    active._parent_current()
    prior = local.load_oidc_session_activation_completion_recovery_retained_grants(active._custody, **kwargs)
    active._parent_current()
    if prior is not None:
        _fail("retained release issuer policy slot was already attempted; no retry is permitted")
    slot = local.claim_oidc_session_activation_completion_recovery_retained_grant_attempt(active._custody, **kwargs)
    execution.shape._digest(slot)
    active._parent_current()
    returned = wire._socket_request_on_work(config.endpoint,
        originals=wire._originals((wire.PURPOSE, *request), response=False),
        deadline_ns=lifetime.bound, work=work, current=active._parent_current,
        maximum_response_bytes=MAX_GRANT_RESPONSE_BYTES)
    active._parent_current()
    returned = wire._originals(returned, response=True)
    if sum(map(len, returned)) > MAX_GRANT_RESPONSE_BYTES:
        _fail("retained release issuer exceeded its pre-body response bound")
    digest = local.append_oidc_session_activation_completion_recovery_retained_grants(
        active._custody, originals=returned, **kwargs)
    execution.shape._digest(digest)
    active._parent_current()
    # Opaque originals are now durable. They still supply no expectations.
    admitted = admission._verify_on_work(response_originals=returned, request_originals=request,
        issuer_policy_bytes=config.issuer_policy_bytes, release_custody_bytes=config.release_custody_bytes,
        proof_enrollment_bytes=config.proof_enrollment_bytes,
        intent_enrollment_bytes=config.intent_enrollment_bytes, root_public_key=active._root,
        live_window=lifetime.window, transport_deadline_ns=lifetime.bound, work=work,
        _continuity=active._parent_continuity, _additional_original_bytes=held + fixed)
    if (type(admitted) is not admission._RecoveryGrantMaterial
            or any(actual is not original for actual, original in zip((admitted.client_authorization_bytes,
                admitted.server_bootstrap_bytes, admitted.outcome_bytes), returned))):
        _fail("retained release requires actual independently admitted raw3")
    lifetime.attach(admitted.live)
    lifetime.adopt(admitted.live_window, admitted.deadline_ns)
    plan._same(admitted.issuer_policy_material.policy_digest, policy.policy_digest,
        work, "retained release unchanged independent policy")
    active.grants = active._grants_seal = returned
    active._recovery_result = active._recovery_result_seal = admitted
    del request, envelope
    active._parent_current()
    active._stage_spent = True
    if admitted.client_material.server_material.profile != staging.server.RECOVERY_PROFILE:
        _fail("retained release staging requires independently admitted recovery authority")
    endpoint = staging._endpoint((staging.LISTENER_PATH,
        admitted.issuer_policy_material.release_launch["requestTimeoutSeconds"],
        staging.EXPECTED_PEER_UID, staging.EXPECTED_PEER_GID))
    # The transport matches its ACK to these exact server bytes and closes
    # normally. This is not worker readiness or private-store existence proof.
    staging._socket_request_on_work(endpoint, originals=(staging.PURPOSE, returned[1]),
        deadline_ns=lifetime.bound, work=work, current=active._parent_current)
    active._parent_current()
    active._staged = True
